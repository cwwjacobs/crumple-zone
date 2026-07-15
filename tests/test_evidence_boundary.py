import copy
import json
import tempfile
import unittest
from pathlib import Path

from crumple_zone.codex_chamber import CodexChamberRuntimeAdapter
from crumple_zone.evidence import EvidenceAssembler, EvidenceError, event_hash, verify_envelope
from crumple_zone.projector import project_trusted_result
from crumple_zone.scenario_controller import ScenarioExerciseController
from crumple_zone.scripted_provider import ScriptedInvestigationProvider
from crumple_zone.trace_store import QuarantinedTraceStore, TraceAccessError


ROOT = Path(__file__).resolve().parents[1]
PHASE3_ROOTFS_SHA256 = "ff42d037c7090668a76a6abd4dc4fd2b0d12c772224245ad6284e2c8871ae0c5"


class EvidenceBoundaryTests(unittest.TestCase):
    def test_real_run_evidence_projection_mutations_and_operator_trace_gate(self):
        with tempfile.TemporaryDirectory(prefix="crumple-phase4-") as directory:
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
            lifecycle = ScenarioExerciseController(runtime, ScriptedInvestigationProvider(ROOT)).exercise(request).lifecycle
            trace_store = QuarantinedTraceStore(temporary / "evidence")
            assembler = EvidenceAssembler(ROOT, trace_store)
            envelope = assembler.assemble(lifecycle, "capability-bound-v1")
            projection = project_trusted_result(envelope, lifecycle.teardown_verified)

            verify_envelope(envelope)
            self.assertEqual(projection["verdict"], "INCONCLUSIVE")
            self.assertTrue(projection["teardown_verified"])
            self.assertIn("OPERATOR_CREDENTIAL_UNAVAILABLE", projection["limitations"])
            self.assertIn("NO_GLOBAL_SAFETY_CLAIM", projection["limitations"])
            self.assertIn("NO_CAUSAL_ATTRIBUTION", projection["limitations"])
            self.assertEqual(event_hash(envelope["events"][0]), event_hash(copy.deepcopy(envelope["events"][0])))
            self.assertEqual([event["sequence"] for event in envelope["events"]], list(range(len(envelope["events"]))))
            self.assertTrue(all(artifact["quarantined"] for artifact in envelope["artifacts"] if artifact["media_code"].startswith(("GUEST_", "FIRECRACKER_"))))

            hostile_values = json.loads((ROOT / "scenarios/poisoned-tool-surface-v1.json").read_text())["hostile_fixture_strings"]
            surface = json.loads((ROOT / "scenarios/poisoned-tool-surface-v1.tools.json").read_text())
            hostile_values += [tool["description"] for tool in surface["tools"]]
            hostile_values += [tool["result_template"] for tool in surface["tools"]]
            encoded_projection = json.dumps(projection, sort_keys=True).encode()
            for hostile in hostile_values:
                self.assertNotIn(hostile.encode(), encoded_projection)

            with self.assertRaisesRegex(TraceAccessError, "OPERATOR_TRACE_OPT_IN_REQUIRED"):
                trace_store.read_operator(lifecycle.run_id, "codex-jsonl")
            raw = trace_store.read_operator(lifecycle.run_id, "codex-jsonl", operator_only=True)
            self.assertTrue(raw)
            self.assertNotIn(raw, encoded_projection)

            mutated_event = copy.deepcopy(envelope)
            mutated_event["events"][0]["decision"] = "ALLOW"
            with self.assertRaisesRegex(EvidenceError, "EVIDENCE_HASH_MISMATCH"):
                verify_envelope(mutated_event)
            reordered = copy.deepcopy(envelope)
            reordered["events"][0], reordered["events"][1] = reordered["events"][1], reordered["events"][0]
            with self.assertRaisesRegex(EvidenceError, "EVENT_ORDER_NONCANONICAL"):
                verify_envelope(reordered)
            mutated_artifact = copy.deepcopy(envelope)
            mutated_artifact["artifacts"][0]["size_bytes"] += 1
            with self.assertRaisesRegex(EvidenceError, "EVIDENCE_HASH_MISMATCH"):
                verify_envelope(mutated_artifact)

            path = assembler.write(envelope)
            self.assertTrue(path.is_file())
            with self.assertRaisesRegex(EvidenceError, "EVIDENCE_ENVELOPE_ALREADY_EXISTS"):
                assembler.write(envelope)


if __name__ == "__main__":
    unittest.main()
