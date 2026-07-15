"""Machine verifier for append-only phase receipts and retained artifact hashes."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
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


def verify_receipts(
    repository: Path,
    *,
    require_artifacts: bool = False,
    source_commit: str | None = None,
    source_tree: str | None = None,
) -> dict:
    root = repository.resolve()
    if source_commit is None or source_tree is None:
        raise ReceiptVerificationError("INDEPENDENT_SOURCE_IDENTITY_REQUIRED")
    _verify_git_identity(root, source_commit, source_tree)
    paths = sorted((root / "receipts").glob("phase-[0-6].json"))
    if not paths:
        raise ReceiptVerificationError("RECEIPTS_NOT_FOUND")
    phases = []
    checked_artifacts = 0
    missing_artifacts = 0
    superseded_artifacts = 0
    current_locked_artifacts = _verify_current_artifact_locks(root) if require_artifacts else 0
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
    build_receipt = verify_build_receipt(root)
    return {
        "schema_version": "receipt-verification.v1",
        "status": "VERIFIED",
        "receipt_count": len(paths),
        "artifact_hashes_checked": checked_artifacts,
        "artifacts_not_present": missing_artifacts,
        "artifacts_superseded_by_later_phase": superseded_artifacts,
        "current_locked_artifacts_checked": current_locked_artifacts,
        "require_artifacts": require_artifacts,
        "receipt_chain_locked": receipt_chain_locked,
        "build_receipt_verified": build_receipt,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "integrity_is_safety": False,
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


def verify_build_receipt(repository: Path) -> bool:
    root = repository.resolve()
    path = root / "receipts/build-target-1.json"
    if not path.is_file():
        raise ReceiptVerificationError("BUILD_RECEIPT_MISSING")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptVerificationError("BUILD_RECEIPT_INVALID") from exc
    required = {
        "schema_version", "target_id", "completed_at", "build_status", "bounded_model_verdict",
        "build_lock", "phase_receipts", "final_acceptance", "checks_executed", "checks_not_executed",
        "failed_checks", "retained_evidence_refs", "limitations", "credential_created",
        "credential_crossed_guest_boundary", "live_provider_call_executed", "integrity_is_safety",
    }
    if set(receipt) != required or receipt["schema_version"] != "build-receipt.v1" or receipt["target_id"] != "BUILD_TARGET_1":
        raise ReceiptVerificationError("BUILD_RECEIPT_INVALID")
    if any(receipt[field] is not False for field in ("credential_created", "credential_crossed_guest_boundary", "live_provider_call_executed", "integrity_is_safety")):
        raise ReceiptVerificationError("BUILD_RECEIPT_CLAIM_INVALID")
    lock = receipt["build_lock"]
    if set(lock) != {"path", "sha256"} or lock["path"] != "locks/build-target-1.json":
        raise ReceiptVerificationError("BUILD_RECEIPT_LOCK_INVALID")
    if _sha256(root / lock["path"]) != lock["sha256"]:
        raise ReceiptVerificationError("BUILD_RECEIPT_LOCK_HASH_MISMATCH")
    build_lock = json.loads((root / lock["path"]).read_text(encoding="utf-8"))
    verify_receipt_lock(root, build_lock)
    _verify_build_lock_contents(root, build_lock)
    phase_records = receipt["phase_receipts"]
    if not isinstance(phase_records, list) or len(phase_records) != 7:
        raise ReceiptVerificationError("BUILD_RECEIPT_PHASES_INVALID")
    for index, binding in enumerate(phase_records):
        if set(binding) != {"phase_id", "verdict", "sha256"} or binding["phase_id"] != f"PHASE_{index}":
            raise ReceiptVerificationError("BUILD_RECEIPT_PHASES_INVALID")
        phase_path = root / f"receipts/phase-{index}.json"
        phase = json.loads(phase_path.read_text(encoding="utf-8"))
        if binding["sha256"] != _sha256(phase_path) or binding["verdict"] != phase["final_verdict"]:
            raise ReceiptVerificationError("BUILD_RECEIPT_PHASE_HASH_MISMATCH")
    if receipt["failed_checks"] != [] or "INTEGRITY_NOT_SAFETY" not in receipt["limitations"]:
        raise ReceiptVerificationError("BUILD_RECEIPT_CLAIM_INVALID")
    return True


def _verify_build_lock_contents(root: Path, lock: dict) -> None:
    contract_paths = {
        "scenario_sha256": "scenarios/poisoned-tool-surface-v1.json",
        "tool_surface_sha256": "scenarios/poisoned-tool-surface-v1.tools.json",
        "observation_skill_sha256": "guest/skills/prompt-injection-observer/SKILL.md",
        "runtime_lock_sha256": "locks/runtime-versions.json",
        "scenario_lock_sha256": "locks/poisoned-tool-surface-v1.json",
        "phase3_image_lock_sha256": "locks/phase3-guest-image.json",
        "event_contract_sha256": "contracts/event.schema.json",
        "evidence_contract_sha256": "contracts/evidence_envelope.schema.json",
        "projection_contract_sha256": "contracts/trusted_projection.schema.json",
        "runtime_manifest_contract_sha256": "contracts/runtime_manifest.schema.json",
        "policy_replay_contract_sha256": "contracts/policy_replay.schema.json",
    }
    bindings = lock.get("contract_bindings")
    if not isinstance(bindings, dict) or set(bindings) != set(contract_paths):
        raise ReceiptVerificationError("BUILD_LOCK_CONTRACT_BINDINGS_INVALID")
    for key, relative in contract_paths.items():
        if _sha256(root / relative) != bindings[key]:
            raise ReceiptVerificationError("BUILD_LOCK_CONTRACT_HASH_MISMATCH")

    retained = lock.get("retained_acceptance_evidence")
    required = {
        "source_run_id", "source_envelope_file_sha256", "source_trusted_result_file_sha256",
        "policy_replay_file_sha256", "rerun_id", "rerun_envelope_file_sha256",
        "rerun_comparison_file_sha256",
    }
    if not isinstance(retained, dict) or set(retained) != required:
        raise ReceiptVerificationError("BUILD_LOCK_RETAINED_EVIDENCE_INVALID")
    source = retained["source_run_id"]
    rerun = retained["rerun_id"]
    if re.fullmatch(r"run_[a-z0-9_]{8,64}", source or "") is None or re.fullmatch(r"run_[a-z0-9_]{8,64}", rerun or "") is None:
        raise ReceiptVerificationError("BUILD_LOCK_RETAINED_EVIDENCE_INVALID")
    retained_paths = {
        "source_envelope_file_sha256": f".crumple/evidence/{source}/evidence-envelope.json",
        "source_trusted_result_file_sha256": f".crumple/evidence/{source}/trusted-result.json",
        "policy_replay_file_sha256": f".crumple/evidence/{source}/policy-replay-capability-bound-v1.json",
        "rerun_envelope_file_sha256": f".crumple/evidence/{rerun}/evidence-envelope.json",
        "rerun_comparison_file_sha256": f".crumple/evidence/{rerun}/scenario-rerun-comparison.json",
    }
    for key, relative in retained_paths.items():
        path = root / relative
        if not path.is_file() or _sha256(path) != retained[key]:
            raise ReceiptVerificationError("BUILD_LOCK_RETAINED_EVIDENCE_HASH_MISMATCH")
    try:
        from .evidence import verify_envelope
        from .projector import verify_projection
        from .replay import verify_replay
        from .rerun import compare_envelopes

        source_root = root / f".crumple/evidence/{source}"
        rerun_root = root / f".crumple/evidence/{rerun}"
        source_envelope = json.loads((source_root / "evidence-envelope.json").read_text(encoding="utf-8"))
        source_projection = json.loads((source_root / "trusted-result.json").read_text(encoding="utf-8"))
        replay = json.loads((source_root / "policy-replay-capability-bound-v1.json").read_text(encoding="utf-8"))
        rerun_envelope = json.loads((rerun_root / "evidence-envelope.json").read_text(encoding="utf-8"))
        rerun_projection = json.loads((rerun_root / "trusted-result.json").read_text(encoding="utf-8"))
        comparison = json.loads((rerun_root / "scenario-rerun-comparison.json").read_text(encoding="utf-8"))
        verify_envelope(source_envelope, artifact_root=source_root, require_artifacts=True)
        verify_projection(source_projection, source_envelope)
        verify_replay(replay, source_envelope)
        verify_envelope(rerun_envelope, artifact_root=rerun_root, require_artifacts=True)
        verify_projection(rerun_projection, rerun_envelope)
        if comparison != compare_envelopes(source_envelope, rerun_envelope):
            raise ValueError("comparison mismatch")
    except Exception as exc:
        raise ReceiptVerificationError("BUILD_LOCK_RETAINED_EVIDENCE_SEMANTICS_INVALID") from exc
    bounded = lock.get("bounded_status")
    if (
        not isinstance(bounded, dict)
        or bounded.get("live_provider_call") != "NOT_RUN"
        or bounded.get("credential_created") is not False
        or bounded.get("global_safety_claim") is not False
        or bounded.get("causal_claim") is not False
        or bounded.get("integrity_is_safety") is not False
    ):
        raise ReceiptVerificationError("BUILD_LOCK_CLAIM_INVALID")


def _verify_git_identity(root: Path, source_commit: str, source_tree: str) -> None:
    if re.fullmatch(r"[a-f0-9]{40}", source_commit) is None or re.fullmatch(r"[a-f0-9]{40}", source_tree) is None:
        raise ReceiptVerificationError("SOURCE_IDENTITY_INVALID")
    if not (root / ".git").exists():
        raise ReceiptVerificationError("SOURCE_GIT_REPOSITORY_REQUIRED")
    if _git(root, "rev-parse", "HEAD") != source_commit:
        raise ReceiptVerificationError("SOURCE_COMMIT_MISMATCH")
    if _git(root, "rev-parse", f"{source_commit}^{{tree}}") != source_tree:
        raise ReceiptVerificationError("SOURCE_TREE_MISMATCH")
    merge = subprocess.run(
        ["git", "rev-parse", "--verify", "MERGE_HEAD"], cwd=root, capture_output=True, text=True, check=False,
    )
    if merge.returncode == 0:
        raise ReceiptVerificationError("UNCOMMITTED_MERGE_EVIDENCE_REJECTED")
    status = _git(root, "status", "--porcelain", "--untracked-files=all")
    if status:
        raise ReceiptVerificationError("UNCOMMITTED_SOURCE_EVIDENCE_REJECTED")


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(["git", *arguments], cwd=root, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise ReceiptVerificationError("SOURCE_GIT_IDENTITY_UNAVAILABLE")
    return completed.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _historically_mutable(relative: Path) -> bool:
    if relative.parts[:3] == (".crumple", "cache", "guest"):
        return True
    immutable_prefixes = {".crumple", "locks", "scenarios"}
    return relative.parts[0] not in immutable_prefixes and not relative.as_posix().startswith("guest/skills/")


def _verify_current_artifact_locks(root: Path) -> int:
    checked = 0
    for phase in (1, 2, 3):
        lock_path = root / f"locks/phase{phase}-guest-image.json"
        try:
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReceiptVerificationError("CURRENT_ARTIFACT_LOCK_INVALID") from exc
        bindings = [(lock.get("rootfs_artifact"), lock.get("rootfs_sha256"))]
        if phase == 1:
            bindings.append((".crumple/cache/guest/crumple-lifecycle-init", lock.get("init_binary_sha256")))
        else:
            bindings.append((f".crumple/cache/guest/crumple-phase{phase}-init", lock.get("init_binary_sha256")))
        for relative, digest in bindings:
            if not isinstance(relative, str) or re.fullmatch(r"[a-f0-9]{64}", digest or "") is None:
                raise ReceiptVerificationError("CURRENT_ARTIFACT_LOCK_INVALID")
            path = root / relative
            if not path.is_file():
                raise ReceiptVerificationError("CURRENT_LOCKED_ARTIFACT_MISSING")
            if _sha256(path) != digest:
                raise ReceiptVerificationError("CURRENT_LOCKED_ARTIFACT_HASH_MISMATCH")
            checked += 1
    return checked
