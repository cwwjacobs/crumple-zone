"""Machine verifier for append-only phase receipts and retained artifact hashes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .contracts import ContractViolation, validate_contract


class ReceiptVerificationError(RuntimeError):
    pass


def verify_receipt_object(receipt: dict) -> None:
    try:
        validate_contract("phase_receipt", receipt)
    except ContractViolation as error:
        raise ReceiptVerificationError("RECEIPT_CONTRACT_INVALID") from error
    if receipt["repository_commit_before"] == "0" * 40:
        raise ReceiptVerificationError("RECEIPT_COMMIT_INVALID")


def verify_receipts(repository: Path, *, require_artifacts: bool = False) -> dict:
    root = repository.resolve()
    paths = sorted((root / "receipts").glob("phase-[0-6].json"))
    if not paths:
        raise ReceiptVerificationError("RECEIPTS_NOT_FOUND")
    phases = []
    checked_artifacts = 0
    missing_artifacts = 0
    superseded_artifacts = 0
    for path in paths:
        receipt = json.loads(path.read_text())
        verify_receipt_object(receipt)
        phases.append(receipt["phase_id"])
        for artifact in receipt["generated_artifacts"]:
            relative = Path(artifact["path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ReceiptVerificationError("RECEIPT_ARTIFACT_PATH_INVALID")
            candidate = root / relative
            if not candidate.is_file():
                missing_artifacts += 1
                if require_artifacts:
                    raise ReceiptVerificationError("RECEIPT_ARTIFACT_MISSING")
                continue
            if _sha256(candidate) != artifact["sha256"]:
                if _historically_mutable(relative):
                    superseded_artifacts += 1
                    continue
                raise ReceiptVerificationError("RECEIPT_ARTIFACT_HASH_MISMATCH")
            checked_artifacts += 1
    expected = [f"PHASE_{index}" for index in range(len(phases))]
    if phases != expected:
        raise ReceiptVerificationError("RECEIPT_PHASE_SEQUENCE_INVALID")
    lock_path = root / "locks/build-target-1.json"
    receipt_chain_locked = False
    if lock_path.is_file():
        verify_receipt_lock(root, json.loads(lock_path.read_text()))
        receipt_chain_locked = True
    return {
        "schema_version": "receipt-verification.v1",
        "status": "VERIFIED",
        "receipt_count": len(paths),
        "artifact_hashes_checked": checked_artifacts,
        "artifacts_not_present": missing_artifacts,
        "artifacts_superseded_by_later_phase": superseded_artifacts,
        "require_artifacts": require_artifacts,
        "receipt_chain_locked": receipt_chain_locked,
    }


def verify_receipt_lock(repository: Path, lock: dict) -> None:
    required = {"schema_version", "target_id", "receipt_hash_algorithm", "phase_receipts"}
    if not isinstance(lock, dict) or not required.issubset(lock):
        raise ReceiptVerificationError("RECEIPT_LOCK_INVALID")
    if lock["schema_version"] != "build-target-lock.v1" or lock["target_id"] != "BUILD_TARGET_1":
        raise ReceiptVerificationError("RECEIPT_LOCK_INVALID")
    if lock["receipt_hash_algorithm"] != "SHA256" or not isinstance(lock["phase_receipts"], list):
        raise ReceiptVerificationError("RECEIPT_LOCK_INVALID")
    if len(lock["phase_receipts"]) != 7:
        raise ReceiptVerificationError("RECEIPT_LOCK_PHASE_COUNT_INVALID")
    root = repository.resolve()
    for index, binding in enumerate(lock["phase_receipts"]):
        expected_path = f"receipts/phase-{index}.json"
        expected_phase = f"PHASE_{index}"
        if binding.get("phase_id") != expected_phase or binding.get("path") != expected_path:
            raise ReceiptVerificationError("RECEIPT_LOCK_SEQUENCE_INVALID")
        digest = binding.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ReceiptVerificationError("RECEIPT_LOCK_DIGEST_INVALID")
        candidate = root / expected_path
        if not candidate.is_file() or _sha256(candidate) != digest:
            raise ReceiptVerificationError("RECEIPT_CHAIN_HASH_MISMATCH")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _historically_mutable(relative: Path) -> bool:
    immutable_prefixes = {".crumple", "locks", "scenarios"}
    return relative.parts[0] not in immutable_prefixes and not relative.as_posix().startswith("guest/skills/")
