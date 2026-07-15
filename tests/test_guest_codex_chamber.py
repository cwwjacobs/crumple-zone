import json
import tempfile
import unittest
from pathlib import Path

from crumple_zone.codex_chamber import CodexAssignment, CodexChamberRuntimeAdapter
from crumple_zone.codex_controller import CodexExerciseController
from crumple_zone.firecracker_runtime import LifecycleError, LifecycleLimits
from crumple_zone.model_proxy import CapabilityManager, HostModelProxy, MockResponsesProvider, ProxyLimits
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
            assignment = CodexAssignment("run_12345678", "a" * 32, "not valid", "capability-bound-v1")
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
            result = mediator._dispatch({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "inspect_fake_data", "arguments": {"item": "package_metadata"}},
            })
            self.assertIn("crumple-demo", result["result"]["content"][0]["text"])
            trusted = json.dumps(timeline.snapshot(), sort_keys=True)
            self.assertNotIn("crumple-demo", trusted)
            self.assertEqual([event["authority"] for event in timeline.snapshot()], ["HOST_MEDIATED", "HOST_MEDIATED"])


if __name__ == "__main__":
    unittest.main()
