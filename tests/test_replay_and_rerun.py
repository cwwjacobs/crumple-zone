import copy
import tempfile
import unittest
from pathlib import Path

from crumple_zone.codex_chamber import CodexChamberRuntimeAdapter
from crumple_zone.evidence import EvidenceAssembler, rehash_envelope, verify_envelope
from crumple_zone.fixture_driver import exercise_fixture
from crumple_zone.replay import PolicyReplayEngine, ReplayError, bind_replay_to_envelope, verify_replay
from crumple_zone.rerun import RerunError, ScenarioRerunCoordinator, compare_envelopes, write_comparison
from crumple_zone.scenario_controller import ScenarioExerciseController
from crumple_zone.scripted_provider import ScriptedInvestigationProvider
from crumple_zone.trace_store import QuarantinedTraceStore


ROOT = Path(__file__).resolve().parents[1]
PHASE3_ROOTFS_SHA256 = "ff42d037c7090668a76a6abd4dc4fd2b0d12c772224245ad6284e2c8871ae0c5"


class ReplayAndRerunTests(unittest.TestCase):
    def test_policy_replay_is_deterministic_and_changes_diagnostic_decision(self):
        fixture = exercise_fixture(ROOT, "observe-v1", "run_replayfixture01")
        engine = PolicyReplayEngine()
        first = engine.replay_events(fixture.run_id, fixture.policy_id, "0" * 64, list(fixture.events), "capability-bound-v1")
        second = engine.replay_events(fixture.run_id, fixture.policy_id, "0" * 64, list(fixture.events), "capability-bound-v1")
        self.assertEqual(first, second)
        diagnostic = next(decision for decision in first["decisions"] if decision["tool_id"] == "diagnostic_export")
        self.assertEqual(diagnostic["recorded_decision"], "OBSERVE")
        self.assertEqual(diagnostic["replayed_decision"], "BLOCK")
        self.assertTrue(first["deterministic"])
        mutated = copy.deepcopy(first)
        mutated["decisions"][0]["replayed_decision"] = "BLOCK"
        with self.assertRaisesRegex(ReplayError, "POLICY_REPLAY_HASH_MISMATCH"):
            verify_replay(mutated)

    def test_fresh_scenario_rerun_is_comparable_distinct_and_torn_down(self):
        with tempfile.TemporaryDirectory(prefix="crumple-phase5-") as directory:
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
            original_request = self._request("observe")
            original_result = ScenarioExerciseController(runtime, ScriptedInvestigationProvider(ROOT)).exercise(original_request)
            store = QuarantinedTraceStore(temporary / "evidence")
            assembler = EvidenceAssembler(ROOT, store)
            original_envelope = assembler.assemble(original_result.lifecycle, "observe-v1")

            replay_engine = PolicyReplayEngine()
            replay = replay_engine.replay(original_envelope, "capability-bound-v1")
            replay_path = replay_engine.write(temporary / "evidence", replay)
            replay_bound = bind_replay_to_envelope(original_envelope, replay_path, replay)
            verify_envelope(replay_bound)
            self.assertEqual(replay_bound["previous_envelope_hash"], original_envelope["envelope_hash"])
            self.assertIn("POLICY_REPLAY", replay_bound["checks"]["executed"])

            rerun = ScenarioRerunCoordinator(ROOT, runtime).rerun(original_envelope, self._request("capability-bound"))
            comparison = rerun.comparison
            self.assertEqual(comparison["mode"], "FRESH_SCENARIO_RERUN_NONDETERMINISTIC")
            self.assertTrue(comparison["scenario_identity_equal"])
            self.assertTrue(comparison["fresh_run_identity"])
            self.assertTrue(comparison["policy_changed"])
            self.assertFalse(comparison["undeclared_drift"])
            self.assertEqual(comparison["model_divergence_code"], "NOT_CHECKED_LIVE_MODEL")
            self.assertNotEqual(original_result.lifecycle.run_id, rerun.lifecycle.run_id)
            self.assertNotEqual(original_result.lifecycle.canary_digest, rerun.lifecycle.canary_digest)
            self.assertTrue(original_result.lifecycle.teardown_verified and rerun.lifecycle.teardown_verified)
            self.assertTrue(original_result.lifecycle.process_gone and rerun.lifecycle.process_gone)
            self.assertIn("SCENARIO_RERUN", rerun.envelope["checks"]["executed"])
            self.assertEqual(list((temporary / "runs").iterdir()), [])
            self.assertTrue(write_comparison(temporary / "evidence", comparison).is_file())

            drifted = copy.deepcopy(rerun.envelope)
            drifted["scenario_hash"] = "f" * 64
            next(artifact for artifact in drifted["artifacts"] if artifact["media_code"] == "SCENARIO_JSON")["sha256"] = "f" * 64
            drifted = rehash_envelope(drifted)
            with self.assertRaisesRegex(RerunError, "SCENARIO_RERUN_UNDECLARED_DRIFT"):
                compare_envelopes(original_envelope, drifted)

    @staticmethod
    def _request(policy: str) -> dict:
        return {
            "schema_version": "run-request.v1",
            "scenario_uri": "fixture://poisoned-tool-surface-v1",
            "policy": policy,
            "limits": {
                "vcpu_count": 1,
                "memory_mib": 1024,
                "wall_seconds": 90,
                "output_bytes": 2_097_152,
                "model_requests": 5,
            },
        }


if __name__ == "__main__":
    unittest.main()
