import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from crumple_zone.cli import build_parser, main
from crumple_zone.evidence import EvidenceAssembler
from crumple_zone.projector import project_trusted_result, write_trusted_projection
from crumple_zone.receipt_verifier import (
    ReceiptVerificationError,
    verify_receipt_lock,
    verify_receipt_object,
    verify_receipts,
    verify_build_receipt,
    _verify_current_artifact_locks,
    _verify_git_identity,
)
from crumple_zone.resources import production_layout
from crumple_zone.scenario_binding import load_scenario_binding, runtime_manifest
from crumple_zone.trace_store import QuarantinedTraceStore
from crumple_zone.trusted_events import TrustedTimeline
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
            binding = load_scenario_binding(ROOT)
            manifest = runtime_manifest(binding, rootfs_sha256="0" * 64, guest_init="/sbin/crumple-phase3-init")
            timeline = TrustedTimeline(run_id, "observe-v1")
            timeline.emit("RUN_ACCEPTED", "HOST_ENFORCED", "CONTROLLER")
            timeline.emit("SCENARIO_BOUND", "HOST_ENFORCED", "CONTROLLER")
            timeline.emit("RUN_COMPLETED", "HOST_ENFORCED", "CONTROLLER")
            assembler = EvidenceAssembler(ROOT, QuarantinedTraceStore(root / ".crumple/evidence"))
            envelope = assembler.assemble_fixture(run_id=run_id, policy_id="observe-v1", events=list(timeline.snapshot()), manifest=manifest)
            projection = project_trusted_result(envelope)
            assembler.write(envelope)
            write_trusted_projection(projection, envelope, root / ".crumple/evidence")
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

    def test_production_resources_ignore_exported_repository_authority(self):
        with tempfile.TemporaryDirectory(prefix="crumple-authority-") as directory:
            with patch.dict(os.environ, {"CRUMPLE_REPOSITORY": directory}):
                self.assertEqual(production_layout().resource_root, ROOT)
        setup = (ROOT / "scripts/setup.sh").read_text(encoding="utf-8")
        self.assertNotIn("CRUMPLE_REPOSITORY", setup)

    def test_teardown_script_checks_process_socket_and_run_directory_postconditions(self):
        run_directory = ROOT / ".crumple/runs/run_teardownregression"
        socket_path = run_directory / "orphan.sock"
        run_directory.mkdir(parents=True, exist_ok=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(socket_path))
        finally:
            listener.close()
        completed = subprocess.run(
            [str(ROOT / "scripts/teardown.sh")], cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("CRUMPLE_TEARDOWN_VERIFIED", completed.stdout)
        self.assertFalse(run_directory.exists())
        self.assertFalse(socket_path.exists())

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
        self.assertTrue(verify_build_receipt(ROOT))
        with self.assertRaisesRegex(ReceiptVerificationError, "INDEPENDENT_SOURCE_IDENTITY_REQUIRED"):
            verify_receipts(ROOT)

    def test_final_build_receipt_claim_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="crumple-build-receipt-") as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "receipts", root / "receipts")
            shutil.copytree(ROOT / "locks", root / "locks")
            path = root / "receipts/build-target-1.json"
            receipt = json.loads(path.read_text(encoding="utf-8"))
            receipt["live_provider_call_executed"] = True
            path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ReceiptVerificationError, "BUILD_RECEIPT_CLAIM_INVALID"):
                verify_build_receipt(root)

    def test_git_identity_rejects_uncommitted_merge_and_dirty_evidence(self):
        with tempfile.TemporaryDirectory(prefix="crumple-git-identity-") as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Crumple Test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            (root / "evidence.txt").write_text("bounded\n", encoding="utf-8")
            subprocess.run(["git", "add", "evidence.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip()
            (root / ".git/MERGE_HEAD").write_text(commit + "\n", encoding="ascii")
            with self.assertRaisesRegex(ReceiptVerificationError, "UNCOMMITTED_MERGE_EVIDENCE_REJECTED"):
                _verify_git_identity(root, commit, tree)
            (root / ".git/MERGE_HEAD").unlink()
            (root / "evidence.txt").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(ReceiptVerificationError, "UNCOMMITTED_SOURCE_EVIDENCE_REJECTED"):
                _verify_git_identity(root, commit, tree)

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

    def test_current_guest_artifact_locks_rehash_all_images_and_inits(self):
        self.assertEqual(_verify_current_artifact_locks(ROOT), 6)

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
            "action_id": "NONE",
            "argument_projection": {"canary_present": False, "payload_bytes": 0, "argument_hash": hashlib.sha256(b"").hexdigest()},
            "result_projection": {"present": False, "payload_bytes": 0, "result_hash": hashlib.sha256(b"").hexdigest(), "is_error": False},
            "artifact_ref": "NONE",
        }

    @staticmethod
    def _projection(run_id: str) -> dict:
        return {
            "schema_version": "trusted-projection.v1",
            "run_id": run_id,
            "run_status": "COMPLETED",
            "failure_code": "NONE",
            "scenario_id": "poisoned-tool-surface-v1",
            "scenario_hash": "0" * 64,
            "runtime_manifest_hash": "0" * 64,
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
            "time_to_ready_ms": 1,
            "time_to_ready_limit_ms": 1000,
            "teardown_verified": True,
        }


if __name__ == "__main__":
    unittest.main()
