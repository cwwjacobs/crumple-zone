import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from crumple_zone.codex_chamber import CodexAssignment, CodexChamberRuntimeAdapter
from crumple_zone.codex_controller import BASELINE_TASK, CodexExerciseController
from crumple_zone.firecracker_runtime import LifecycleError, LifecycleLimits
from crumple_zone.model_proxy import CapabilityManager, HostModelProxy, MockResponsesProvider, ProxyLimits
from crumple_zone.scenario_binding import load_scenario_binding, runtime_manifest
from crumple_zone.scenario_controller import _bounded_hostile_task
from crumple_zone.trusted_events import TrustedTimeline
from crumple_zone.vsock_services import HostToolMediator


ROOT = Path(__file__).resolve().parents[1]


class GuestCodexChamberTests(unittest.TestCase):
    def runtime(self, temporary: Path) -> CodexChamberRuntimeAdapter:
        cache = ROOT / ".crumple/cache"
        return CodexChamberRuntimeAdapter(
            ROOT,
            cache / "firecracker/v1.16.1/firecracker-v1.16.1-x86_64",
            cache / "kernel/6.1.176/vmlinux-6.1.176",
            cache / "guest/rootfs-phase2.ext4",
            temporary / "runs",
            temporary / "evidence",
        )

    def test_real_independent_codex_baseline_is_mediated_and_torn_down(self):
        with tempfile.TemporaryDirectory(prefix="crumple-phase2-") as directory:
            temporary = Path(directory)
            runtime = self.runtime(temporary)
            provider = MockResponsesProvider()
            live_events = []
            run_directory_seen_live = []

            def watch(event):
                live_events.append(event)
                if event["code"] in {"CHAMBER_READY", "TOOL_SURFACE_PRESENTED"}:
                    run_directory_seen_live.append((temporary / "runs" / event["run_id"]).is_dir())

            request = {
                "schema_version": "run-request.v1",
                "scenario_uri": "fixture://poisoned-tool-surface-v1",
                "policy": "capability-bound",
                "limits": {
                    "vcpu_count": 1,
                    "memory_mib": 1024,
                    "wall_seconds": 90,
                    "output_bytes": 2_097_152,
                    "model_requests": 4,
                },
            }
            result = CodexExerciseController(runtime, provider).exercise_baseline(request, watch)
            lifecycle = result.lifecycle

            self.assertEqual(lifecycle.codex_exit_code, 0)
            self.assertFalse(lifecycle.guest_auth_file_reported)
            self.assertTrue(lifecycle.tool_surface_presented)
            self.assertEqual(lifecycle.model_requests_observed, 1)
            self.assertTrue(lifecycle.trace_completed)
            self.assertTrue(lifecycle.teardown_verified)
            self.assertTrue(lifecycle.process_gone and lifecycle.run_directory_gone and lifecycle.sockets_gone)
            self.assertEqual(list((temporary / "runs").iterdir()), [])
            self.assertTrue(run_directory_seen_live and all(run_directory_seen_live))
            self.assertEqual(live_events, list(lifecycle.events))
            self.assertIn("TOOL_SURFACE_PRESENTED", [event["code"] for event in live_events])
            self.assertIn("MODEL_PROXY_REQUEST_ACCEPTED", [event["code"] for event in live_events])
            self.assertEqual(provider.calls[0].provider_auth_owner, "HOST_PROXY")
            self.assertFalse(provider.calls[0].guest_authorization_forwarded)

            quarantine = temporary / "evidence" / lifecycle.run_id / "quarantine"
            self.assertTrue((quarantine / "codex.jsonl").is_file())
            self.assertTrue((quarantine / "codex.stderr").is_file())
            self.assertTrue((quarantine / "firecracker.log").is_file())
            trusted = json.dumps(lifecycle.events, sort_keys=True)
            scenario = json.loads((ROOT / "scenarios/poisoned-tool-surface-v1.json").read_text())
            for hostile in scenario["hostile_fixture_strings"]:
                self.assertNotIn(hostile, trusted)

    def test_invalid_capability_fails_before_launch(self):
        with tempfile.TemporaryDirectory(prefix="crumple-phase2-negative-") as directory:
            temporary = Path(directory)
            runtime = self.runtime(temporary)
            limits = ProxyLimits()
            capabilities = CapabilityManager(limits)
            proxy = HostModelProxy(MockResponsesProvider(), limits, capabilities)
            timeline = TrustedTimeline("run_12345678", "capability-bound-v1")
            assignment = CodexAssignment(
                run_id="run_12345678", canary="a" * 32, capability="not valid", policy_id="capability-bound-v1",
                task="bounded", scenario_hash="0" * 64, tool_surface_hash="0" * 64, runtime_manifest_hash="0" * 64,
            )
            with self.assertRaisesRegex(LifecycleError, "CAPABILITY_INVALID"):
                runtime.run_once(assignment, proxy, timeline, LifecycleLimits(memory_mib=1024))
            self.assertIsNone(runtime.last_process_pid)

    def test_mediator_exposes_real_tools_and_keeps_raw_results_out_of_timeline(self):
        with tempfile.TemporaryDirectory(prefix="crumple-phase2-mediator-") as directory:
            timeline = TrustedTimeline("run_12345678", "capability-bound-v1")
            mediator = HostToolMediator(Path(directory) / "mcp.sock", ROOT, timeline, "capability-bound-v1", "a" * 32)
            listed = mediator._dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
            names = [tool["name"] for tool in listed["result"]["tools"]]
            self.assertEqual(
                names,
                ["inspect_tool_surface", "inspect_fake_data", "package_lookup", "diagnostic_export", "record_injection_observation", "complete_synthetic_task"],
            )
            binding = load_scenario_binding(ROOT)
            manifest = runtime_manifest(binding, rootfs_sha256="0" * 64, guest_init="/sbin/crumple-phase2-init")
            self.assertEqual(listed["result"]["tools"], manifest["model_visible_tools"])
            result = mediator._dispatch({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "inspect_fake_data", "arguments": {"item": "package_metadata"}},
            })
            self.assertIn("crumple-demo", result["result"]["content"][0]["text"])
            trusted = json.dumps(timeline.snapshot(), sort_keys=True)
            self.assertNotIn("crumple-demo", trusted)
            self.assertEqual([event["authority"] for event in timeline.snapshot()], ["HOST_MEDIATED"] * 3)
            result_event = timeline.snapshot()[-1]
            self.assertEqual(result_event["code"], "TOOL_RESULT_RECORDED")
            self.assertTrue(result_event["result_projection"]["present"])
            self.assertGreater(result_event["result_projection"]["payload_bytes"], 0)
            self.assertNotEqual(result_event["result_projection"]["result_hash"], "0" * 64)

    def test_reusable_images_contain_no_bounded_task_text(self):
        cache = ROOT / ".crumple/cache/guest"
        scenario = json.loads((ROOT / "scenarios/poisoned-tool-surface-v1.json").read_text())
        hostile_task = _bounded_hostile_task(scenario["user_task"])
        for image in (cache / "rootfs-phase2.ext4", cache / "rootfs-phase3.ext4"):
            with self.subTest(image=image.name):
                self.assertFalse(self._contains(image, BASELINE_TASK.encode()))
                self.assertFalse(self._contains(image, hostile_task.encode()))
                self.assertFalse(self._contains(image, scenario["user_task"].encode()))

    def test_two_real_runs_receive_only_their_post_ready_task(self):
        with tempfile.TemporaryDirectory(prefix="crumple-task-isolation-") as directory:
            temporary = Path(directory)
            runtime = self.runtime(temporary)
            binding = load_scenario_binding(ROOT)
            _, manifest_hash = runtime.bind_scenario(binding)
            prompts = ["Return exactly TASK_ALPHA_COMPLETE.", "Return exactly TASK_BETA_COMPLETE."]
            captured = []
            for index, prompt in enumerate(prompts):
                limits = ProxyLimits(max_requests=2, ttl_seconds=90)
                capabilities = CapabilityManager(limits)
                token, _ = capabilities.issue(f"run_taskisolation{index:02d}")
                provider = MockResponsesProvider()
                timeline = TrustedTimeline(f"run_taskisolation{index:02d}", "observe-v1")
                result = runtime.run_once(
                    CodexAssignment(
                        run_id=f"run_taskisolation{index:02d}", canary=f"{index + 1:032x}", capability=token,
                        policy_id="observe-v1", task=prompt, scenario_hash=binding.scenario_hash,
                        tool_surface_hash=binding.tool_surface_hash, runtime_manifest_hash=manifest_hash,
                    ),
                    HostModelProxy(provider, limits, capabilities), timeline, LifecycleLimits(memory_mib=1024, wall_seconds=90),
                )
                self.assertEqual(result.run_status, "COMPLETED")
                captured.append(b"\n".join(call.payload for call in provider.calls))
            self.assertIn(prompts[0].encode(), captured[0])
            self.assertNotIn(prompts[1].encode(), captured[0])
            self.assertIn(prompts[1].encode(), captured[1])
            self.assertNotIn(prompts[0].encode(), captured[1])
            self.assertEqual(list((temporary / "runs").iterdir()), [])

    def test_process_stop_exception_still_attempts_all_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="crumple-stop-failure-") as directory:
            temporary = Path(directory)
            runtime = self.runtime(temporary)
            request = {
                "schema_version": "run-request.v1", "scenario_uri": "fixture://poisoned-tool-surface-v1",
                "policy": "observe", "limits": {"vcpu_count": 1, "memory_mib": 1024, "wall_seconds": 30, "output_bytes": 1048576, "model_requests": 4},
            }
            with patch("crumple_zone.codex_chamber._read_line", side_effect=LifecycleError("FORCED_HANDSHAKE_FAILURE")), patch(
                "crumple_zone.codex_chamber._stop_process", side_effect=RuntimeError("forced stop exception")
            ):
                result = CodexExerciseController(runtime, MockResponsesProvider()).exercise_baseline(request).lifecycle
            self.assertEqual(result.run_status, "RUN_FAILED")
            self.assertTrue(result.process_gone and result.run_directory_gone and result.sockets_gone)
            self.assertTrue(result.teardown_verified)
            self.assertEqual(list((temporary / "runs").iterdir()), [])

    @staticmethod
    def _contains(path: Path, needle: bytes) -> bool:
        overlap = b""
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                data = overlap + chunk
                if needle in data:
                    return True
                overlap = data[-max(len(needle) - 1, 0):]
        return False


if __name__ == "__main__":
    unittest.main()
