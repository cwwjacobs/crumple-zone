import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from crumple_zone.cli import build_parser, main
from crumple_zone.receipt_verifier import (
    ReceiptVerificationError,
    verify_receipt_lock,
    verify_receipt_object,
    verify_receipts,
)
from crumple_zone.run_store import RunStoreError, TrustedRunStore


ROOT = Path(__file__).resolve().parents[1]


class CliProductTests(unittest.TestCase):
    def test_strict_parser_rejects_unknown_target_and_policy(self):
        parser = build_parser()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["exercise", "file:///etc/passwd", "--policy", "observe"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["exercise", "fixture://poisoned-tool-surface-v1", "--policy", "allow-all"])

    def test_show_is_typed_and_verify_path_is_confined(self):
        with tempfile.TemporaryDirectory(prefix="crumple-cli-") as directory:
            root = Path(directory)
            run_id = "run_0123456789abcdef"
            destination = root / ".crumple/evidence" / run_id
            destination.mkdir(parents=True)
            projection = self._projection(run_id)
            (destination / "trusted-result.json").write_text(json.dumps(projection))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["show", run_id], root), 0)
            shown = json.loads(output.getvalue())
            self.assertEqual(shown["stream_code"], "TRUSTED_RESULT")
            self.assertEqual(shown["projection"], projection)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["verify", "/etc/passwd"], root), 2)
            self.assertEqual(json.loads(output.getvalue())["error_code"], "EVIDENCE_PATH_NOT_ADMITTED")

    def test_operator_trace_requires_both_explicit_flags(self):
        with tempfile.TemporaryDirectory(prefix="crumple-cli-trace-") as directory:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["watch", "run_0123456789abcdef", "--trace", "codex-jsonl"], Path(directory))
            self.assertEqual(status, 2)
            self.assertEqual(json.loads(output.getvalue())["error_code"], "OPERATOR_TRACE_OPT_IN_REQUIRED")

    def test_trusted_run_store_is_append_only_and_sequence_checked(self):
        with tempfile.TemporaryDirectory(prefix="crumple-run-store-") as directory:
            store = TrustedRunStore(Path(directory))
            first = self._event(0, "RUN_ACCEPTED")
            second = self._event(1, "RUN_COMPLETED")
            store.append(first)
            store.append(second)
            self.assertEqual(list(store.follow(first["run_id"], timeout_seconds=1)), [first, second])
            mutated = copy.deepcopy(second)
            mutated["sequence"] = 3
            with self.assertRaisesRegex(RunStoreError, "TRUSTED_EVENT_SEQUENCE_INVALID"):
                store.append(mutated)

    def test_receipt_contract_mutation_fails_and_current_chain_validates(self):
        receipt = json.loads((ROOT / "receipts/phase-5.json").read_text())
        del receipt["objective"]
        with self.assertRaisesRegex(ReceiptVerificationError, "RECEIPT_CONTRACT_INVALID"):
            verify_receipt_object(receipt)
        result = verify_receipts(ROOT)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertGreaterEqual(result["receipt_count"], 6)

    def test_receipt_lock_detects_chain_mutation(self):
        with tempfile.TemporaryDirectory(prefix="crumple-receipt-lock-") as directory:
            root = Path(directory)
            (root / "receipts").mkdir()
            bindings = []
            for index in range(7):
                relative = f"receipts/phase-{index}.json"
                content = f"phase-{index}\n".encode()
                (root / relative).write_bytes(content)
                bindings.append(
                    {
                        "phase_id": f"PHASE_{index}",
                        "path": relative,
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                )
            lock = {
                "schema_version": "build-target-lock.v1",
                "target_id": "BUILD_TARGET_1",
                "receipt_hash_algorithm": "SHA256",
                "phase_receipts": bindings,
            }
            verify_receipt_lock(root, lock)
            (root / "receipts/phase-3.json").write_text("mutated\n")
            with self.assertRaisesRegex(ReceiptVerificationError, "RECEIPT_CHAIN_HASH_MISMATCH"):
                verify_receipt_lock(root, lock)

    @staticmethod
    def _event(sequence: int, code: str) -> dict:
        return {
            "schema_version": "event.v1",
            "event_id": f"evt_{sequence:016x}",
            "run_id": "run_0123456789abcdef",
            "sequence": sequence,
            "monotonic_ns": sequence,
            "code": code,
            "authority": "HOST_ENFORCED",
            "component": "CONTROLLER",
            "scenario_id": "poisoned-tool-surface-v1",
            "policy_id": "observe-v1",
            "tool_id": "NONE",
            "decision": "NONE",
            "argument_projection": {"canary_present": False, "payload_bytes": 0, "argument_hash": "0" * 64},
            "artifact_ref": "NONE",
        }

    @staticmethod
    def _projection(run_id: str) -> dict:
        return {
            "schema_version": "trusted-projection.v1",
            "run_id": run_id,
            "scenario_id": "poisoned-tool-surface-v1",
            "scenario_hash": "0" * 64,
            "policy_id": "observe-v1",
            "verdict": "INCONCLUSIVE",
            "findings": [],
            "checks_executed": ["REQUEST_SCHEMA_VALID"],
            "checks_not_executed": ["LIVE_PROVIDER_CALL"],
            "failed_checks": [],
            "evidence_refs": [],
            "authority_sources": ["HOST_ENFORCED"],
            "limitations": ["OPERATOR_CREDENTIAL_UNAVAILABLE", "NO_GLOBAL_SAFETY_CLAIM"],
            "envelope_hash": "0" * 64,
            "teardown_verified": True,
        }


if __name__ == "__main__":
    unittest.main()
