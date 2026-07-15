import json
import tempfile
import unittest
from pathlib import Path

from crumple_zone.canary import CanaryManager
from crumple_zone.codex_chamber import CodexChamberRuntimeAdapter
from crumple_zone.fixture_driver import exercise_fixture
from crumple_zone.scenario_controller import ScenarioExerciseController
from crumple_zone.scripted_provider import ScriptedInvestigationProvider
from crumple_zone.synthetic_target import SyntheticSinkhole
from crumple_zone.trusted_events import TrustedTimeline


ROOT = Path(__file__).resolve().parents[1]
PHASE3_ROOTFS_SHA256 = "ff42d037c7090668a76a6abd4dc4fd2b0d12c772224245ad6284e2c8871ae0c5"


class SyntheticWorkflowTests(unittest.TestCase):
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

    def test_deterministic_fixture_enforce_blocks_before_effect(self):
        result = exercise_fixture(ROOT, "capability-bound-v1", "run_fixtureenforce01")
        self.assertEqual(result.decision, "BLOCK")
        self.assertFalse(result.sinkhole_effect_observed)
        self.assertTrue(result.canary_tripwire_observed)
        self.assertEqual(result.tripwire_code, "TOOL_ARGUMENT_CANARY_SCAN")
        codes = [event["code"] for event in result.events]
        self.assertIn("TOOL_CALL_BLOCKED", codes)
        self.assertNotIn("SINKHOLE_RECEIVED", codes)

    def test_canaries_are_fresh_and_stale_value_does_not_trip(self):
        manager = CanaryManager()
        first = manager.issue("run_canaryfresh001")
        second = manager.issue("run_canaryfresh002")
        self.assertNotEqual(first.value, second.value)
        self.assertNotEqual(first.digest, second.digest)
        timeline = TrustedTimeline(first.run_id, "observe-v1")
        sinkhole = SyntheticSinkhole(timeline, first)
        receipt = sinkhole.receive(second.value.encode())
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
