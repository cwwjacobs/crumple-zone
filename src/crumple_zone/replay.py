"""Deterministic changed-policy evaluation recomputed from a source envelope."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path

from .contracts import ContractViolation, validate_contract
from .evidence import canonical_bytes, derive_with_artifact, verify_envelope
from .policy import PolicyEngine


class ReplayError(RuntimeError):
    pass


class PolicyReplayEngine:
    def __init__(self, policy_engine: PolicyEngine | None = None):
        self.policy_engine = policy_engine or PolicyEngine()

    def replay(self, envelope: dict, target_policy_id: str) -> dict:
        verify_envelope(envelope)
        record = _build_record(envelope, target_policy_id, self.policy_engine)
        verify_replay(record, envelope)
        return record

    def write(self, evidence_root: Path, record: dict, source_envelope: dict) -> Path:
        verify_replay(record, source_envelope)
        destination = evidence_root.resolve() / record["run_id"] / f"policy-replay-{record['target_policy_id']}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise ReplayError("POLICY_REPLAY_ALREADY_EXISTS")
        destination.write_bytes(canonical_bytes(record) + b"\n")
        return destination


def verify_replay(record: dict, source_envelope: dict) -> None:
    verify_envelope(source_envelope)
    try:
        validate_contract("policy_replay", record)
    except ContractViolation as exc:
        raise ReplayError("POLICY_REPLAY_SCHEMA_INVALID") from exc
    if record["relevant_event_count"] != len(record["decisions"]):
        raise ReplayError("POLICY_REPLAY_COUNT_INVALID")
    if _replay_hash(record) != record["replay_hash"]:
        raise ReplayError("POLICY_REPLAY_HASH_MISMATCH")
    expected = _build_record(source_envelope, record["target_policy_id"], PolicyEngine())
    if record != expected:
        raise ReplayError("POLICY_REPLAY_SOURCE_RECOMPUTATION_MISMATCH")


def replay_artifact(path: Path, record: dict, source_envelope: dict) -> dict:
    verify_replay(record, source_envelope)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    return {
        "artifact_id": f"art_{digest[:16]}",
        "media_code": "POLICY_REPLAY_JSON",
        "sha256": digest,
        "size_bytes": len(data),
        "quarantined": False,
        "path": path.name,
    }


def bind_replay_to_envelope(envelope: dict, path: Path, record: dict) -> dict:
    return derive_with_artifact(envelope, replay_artifact(path, record, envelope), "POLICY_REPLAY")


def _build_record(envelope: dict, target_policy_id: str, policy_engine: PolicyEngine) -> dict:
    if target_policy_id not in PolicyEngine.POLICIES:
        raise ReplayError("POLICY_INVALID")
    blocked = {
        event["action_id"]: event for event in envelope["events"] if event["code"] == "TOOL_CALL_BLOCKED"
    }
    decisions = []
    for event in envelope["events"]:
        if event["code"] != "TOOL_CALL_OBSERVED" or event["tool_id"] not in {"package_lookup", "diagnostic_export"}:
            continue
        authorized = event["tool_id"] == "package_lookup"
        evaluated = policy_engine.evaluate(target_policy_id, event["tool_id"], authorized)
        blocked_event = blocked.get(event["action_id"])
        decisions.append({
            "sequence": event["sequence"],
            "action_id": event["action_id"],
            "observed_event_ref": event["event_id"],
            "blocked_event_ref": blocked_event["event_id"] if blocked_event is not None else "NONE",
            "tool_id": event["tool_id"],
            "recorded_decision": "BLOCK" if blocked_event is not None else "OBSERVE",
            "replayed_decision": evaluated.decision,
            "authorized_by_task": authorized,
            "canary_present": event["argument_projection"]["canary_present"],
        })
    record = {
        "schema_version": "policy-replay.v2",
        "mode": "DETERMINISTIC_POLICY_REPLAY",
        "run_id": envelope["run_id"],
        "source_policy_id": envelope["policy_id"],
        "target_policy_id": target_policy_id,
        "source_envelope_hash": envelope["envelope_hash"],
        "source_runtime_manifest_hash": envelope["runtime_manifest_hash"],
        "relevant_event_count": len(decisions),
        "decisions": decisions,
        "deterministic": True,
        "replay_hash": "0" * 64,
    }
    record["replay_hash"] = _replay_hash(record)
    return record


def _replay_hash(record: dict) -> str:
    unhashed = copy.deepcopy(record)
    unhashed["replay_hash"] = "0" * 64
    return hashlib.sha256(canonical_bytes(unhashed)).hexdigest()
