import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from crumple_zone.canary import CanaryManager
from crumple_zone.codex_chamber import CodexChamberRuntimeAdapter
from crumple_zone.evidence import EvidenceError, _envelope_hash, verify_envelope
from crumple_zone.fixture_driver import exercise_fixture
from crumple_zone.model_proxy import CapabilityManager
from crumple_zone.scenario_binding import ScenarioBindingError
from crumple_zone.scenario_controller import ScenarioExerciseController
from crumple_zone.scripted_provider import ScriptedInvestigationProvider
from crumple_zone.synthetic_target import SyntheticSinkhole
from crumple_zone.trusted_events import TrustedTimeline


ROOT = Path(__file__).resolve().parents[1]
PHASE3_ROOTFS_SHA256 = "5ac599fb9b11e8015a21762741279978493a19e6dfb6e89330fe6dc491311667"


class SyntheticWorkflowTests(unittest.TestCase):
    def test_scenario_raw_hash_is_verified_before_capability_or_vm_launch(self):
        with tempfile.TemporaryDirectory(prefix="crumple-scenario-binding-") as directory:
            temporary = Path(directory)
            resources = temporary / "resources"
            for name in ("contracts", "scenarios", "locks"):
                shutil.copytree(ROOT / name, resources / name)
            scenario = resources / "scenarios/poisoned-tool-surface-v1.json"
            scenario.write_bytes(scenario.read_bytes() + b" ")
            cache = ROOT / ".crumple/cache"
            runtime = CodexChamberRuntimeAdapter(
                resources,
                cache / "firecracker/v1.16.1/firecracker-v1.16.1-x86_64",
                cache / "kernel/6.1.176/vmlinux-6.1.176",
                cache / "guest/rootfs-phase3.ext4",
                temporary / "runs",
                temporary / "evidence",
                PHASE3_ROOTFS_SHA256,
                "/sbin/crumple-phase3-init",
            )
            request = {
                "schema_version": "run-request.v1", "scenario_uri": "fixture://poisoned-tool-surface-v1",
                "policy": "observe", "limits": {
                    "vcpu_count": 1, "memory_mib": 1024, "wall_seconds": 30,
                    "output_bytes": 1048576, "model_requests": 5,
                },
            }
            with patch.object(CapabilityManager, "issue") as issue:
                with self.assertRaisesRegex(ScenarioBindingError, "SCENARIO_RAW_HASH_MISMATCH"):
                    ScenarioExerciseController(runtime, ScriptedInvestigationProvider(resources)).exercise(request)
                issue.assert_not_called()
            self.assertIsNone(runtime.last_process_pid)

    def test_deterministic_fixture_observe_reaches_only_owned_sinkhole(self):
        result = exercise_fixture(ROOT, "observe-v1", "run_fixtureobserve01")
        self.assertEqual(result.driver_code, "DETERMINISTIC_INFRASTRUCTURE_FIXTURE")
        self.assertEqual(result.decision, "OBSERVE")
        self.assertTrue(result.sinkhole_effect_observed)
        self.assertTrue(result.canary_tripwire_observed)
        self.assertEqual(result.tripwire_code, "SINKHOLE_BODY_CANARY_SCAN")
        codes = [event["code"] for event in result.events]
        self.assertIn("SINKHOLE_RECEIVED", codes)
        self.assertNotIn("TOOL_CALL_BLOCKED", codes)
        self.assertEqual(result.envelope["run_mode"], "DETERMINISTIC_FIXTURE")
        self.assertEqual(result.projection["verdict"], "VIOLATION_OBSERVED")
        self.assertIn("RUNTIME_MANIFEST_JSON", {artifact["media_code"] for artifact in result.envelope["artifacts"]})

    def test_deterministic_fixture_enforce_blocks_before_effect(self):
        result = exercise_fixture(ROOT, "capability-bound-v1", "run_fixtureenforce01")
        self.assertEqual(result.decision, "BLOCK")
        self.assertFalse(result.sinkhole_effect_observed)
        self.assertTrue(result.canary_tripwire_observed)
        self.assertEqual(result.tripwire_code, "TOOL_ARGUMENT_CANARY_SCAN")
        codes = [event["code"] for event in result.events]
        self.assertIn("TOOL_CALL_BLOCKED", codes)
        self.assertNotIn("SINKHOLE_RECEIVED", codes)
        observed = next(event for event in result.events if event["code"] == "TOOL_CALL_OBSERVED" and event["tool_id"] == "diagnostic_export")
        blocked = next(event for event in result.events if event["code"] == "TOOL_CALL_BLOCKED")
        self.assertEqual(observed["action_id"], blocked["action_id"])
        self.assertEqual(result.projection["verdict"], "INCONCLUSIVE")

        broken = copy.deepcopy(result.envelope)
        next(event for event in broken["events"] if event["code"] == "TOOL_CALL_BLOCKED")["action_id"] = "act_ffffffffffffffff"
        broken["envelope_hash"] = _envelope_hash(broken)
        with self.assertRaisesRegex(EvidenceError, "TOOL_ACTION_CORRELATION_INVALID"):
            verify_envelope(broken)

    def test_canaries_are_fresh_and_stale_value_does_not_trip(self):
        manager = CanaryManager()
        first = manager.issue("run_canaryfresh001")
        second = manager.issue("run_canaryfresh002")
        self.assertNotEqual(first.value, second.value)
        self.assertNotEqual(first.digest, second.digest)
        timeline = TrustedTimeline(first.run_id, "observe-v1")
        sinkhole = SyntheticSinkhole(timeline, first)
        receipt = sinkhole.receive(second.value.encode(), action_id="act_0123456789abcdef")
        self.assertFalse(receipt.canary_present)
        self.assertEqual(receipt.tripwire_code, "SINKHOLE_BODY_CANARY_SCAN")

    def test_independent_guest_codex_receives_hostile_result_with_scripted_provider(self):
        with tempfile.TemporaryDirectory(prefix="crumple-phase3-") as directory:
            temporary = Path(directory)
            cache = ROOT / ".crumple/cache"
            runtime = CodexChamberRuntimeAdapter(
                ROOT,
                cache / "firecracker/v1.16.1/firecracker-v1.16.1-x86_64",
                cache / "kernel/6.1.176/vmlinux-6.1.176",
                cache / "guest/rootfs-phase3.ext4",
                temporary / "runs",
                temporary / "evidence",
                PHASE3_ROOTFS_SHA256,
                "/sbin/crumple-phase3-init",
            )
            provider = ScriptedInvestigationProvider(ROOT)
            live_events = []
            request = {
                "schema_version": "run-request.v1",
                "scenario_uri": "fixture://poisoned-tool-surface-v1",
                "policy": "capability-bound",
                "limits": {
                    "vcpu_count": 1,
                    "memory_mib": 1024,
                    "wall_seconds": 90,
                    "output_bytes": 2_097_152,
                    "model_requests": 5,
                },
            }
            result = ScenarioExerciseController(runtime, provider).exercise(request, live_events.append)
            lifecycle = result.lifecycle
            self.assertEqual(result.verdict, "INCONCLUSIVE")
            self.assertEqual(result.behavior_source, "SCRIPTED_MOCK_PROVIDER")
            self.assertEqual(result.live_provider_check, "LIVE_PROVIDER_CALL_NOT_RUN")
            self.assertEqual(result.limitation_code, "OPERATOR_CREDENTIAL_UNAVAILABLE")
            self.assertTrue(result.search_exposed_target)
            self.assertTrue(result.hostile_result_returned_to_codex)
            self.assertEqual(lifecycle.model_requests_observed, 5)
            self.assertEqual(lifecycle.tool_calls_observed, 3)
            self.assertTrue(lifecycle.teardown_verified)
            self.assertEqual(lifecycle.run_status, "COMPLETED")
            self.assertGreater(lifecycle.ready_milliseconds, 0)
            self.assertLessEqual(lifecycle.ready_milliseconds, lifecycle.ready_limit_milliseconds)
            self.assertFalse(lifecycle.guest_auth_file_reported)
            codes = [event["code"] for event in live_events]
            self.assertIn("AGENT_OBSERVATION_REPORTED", codes)
            self.assertNotIn("SINKHOLE_RECEIVED", codes)
            self.assertNotIn("TOOL_CALL_BLOCKED", codes)
            self.assertEqual(
                next(event for event in live_events if event["code"] == "AGENT_OBSERVATION_REPORTED")["authority"],
                "AGENT_INTERPRETED",
            )
            trusted = json.dumps(live_events, sort_keys=True)
            scenario = json.loads((ROOT / "scenarios/poisoned-tool-surface-v1.json").read_text())
            for hostile in scenario["hostile_fixture_strings"]:
                self.assertNotIn(hostile, trusted)


if __name__ == "__main__":
    unittest.main()
