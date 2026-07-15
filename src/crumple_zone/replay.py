"""Deterministic changed-policy evaluation over recorded host-mediated events."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from .contracts import validate_contract
from .evidence import canonical_bytes, derive_with_artifact, verify_envelope
from .policy import PolicyEngine


class ReplayError(RuntimeError):
    pass


class PolicyReplayEngine:
    def __init__(self, policy_engine: PolicyEngine | None = None):
        self.policy_engine = policy_engine or PolicyEngine()

    def replay(self, envelope: dict, target_policy_id: str) -> dict:
        verify_envelope(envelope)
        return self.replay_events(
            envelope["run_id"], envelope["policy_id"], envelope["envelope_hash"], envelope["events"], target_policy_id,
        )

    def replay_events(
        self,
        run_id: str,
        source_policy_id: str,
        source_envelope_hash: str,
        events: list[dict],
        target_policy_id: str,
    ) -> dict:
        if source_policy_id not in PolicyEngine.POLICIES or target_policy_id not in PolicyEngine.POLICIES:
            raise ReplayError("POLICY_INVALID")
        decisions = []
        for event in events:
            validate_contract("event", event)
            if event["run_id"] != run_id or event["policy_id"] != source_policy_id:
                raise ReplayError("REPLAY_EVENT_SCOPE_INVALID")
            if event["code"] != "TOOL_CALL_OBSERVED" or event["tool_id"] == "NONE":
                continue
            authorized = event["tool_id"] == "package_lookup"
            evaluated = self.policy_engine.evaluate(target_policy_id, event["tool_id"], authorized)
            decisions.append({
                "sequence": event["sequence"],
                "event_ref": event["event_id"],
                "tool_id": event["tool_id"],
                "recorded_event_code": event["code"],
                "recorded_decision": event["decision"],
                "replayed_decision": evaluated.decision,
                "authorized_by_task": authorized,
                "canary_present": event["argument_projection"]["canary_present"],
            })
        record = {
            "schema_version": "policy-replay.v1",
            "mode": "DETERMINISTIC_POLICY_REPLAY",
            "run_id": run_id,
            "source_policy_id": source_policy_id,
            "target_policy_id": target_policy_id,
            "source_envelope_hash": source_envelope_hash,
            "relevant_event_count": len(decisions),
            "decisions": decisions,
            "deterministic": True,
            "replay_hash": "0" * 64,
        }
        record["replay_hash"] = _replay_hash(record)
        verify_replay(record)
        return record

    def write(self, evidence_root: Path, record: dict) -> Path:
        verify_replay(record)
        destination = evidence_root.resolve() / record["run_id"] / f"policy-replay-{record['target_policy_id']}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise ReplayError("POLICY_REPLAY_ALREADY_EXISTS")
        destination.write_bytes(canonical_bytes(record) + b"\n")
        return destination


def verify_replay(record: dict) -> None:
    required = {
        "schema_version", "mode", "run_id", "source_policy_id", "target_policy_id", "source_envelope_hash",
        "relevant_event_count", "decisions", "deterministic", "replay_hash",
    }
    if set(record) != required:
        raise ReplayError("POLICY_REPLAY_SCHEMA_INVALID")
    if record["schema_version"] != "policy-replay.v1" or record["mode"] != "DETERMINISTIC_POLICY_REPLAY" or record["deterministic"] is not True:
        raise ReplayError("POLICY_REPLAY_SCHEMA_INVALID")
    if record["source_policy_id"] not in PolicyEngine.POLICIES or record["target_policy_id"] not in PolicyEngine.POLICIES:
        raise ReplayError("POLICY_REPLAY_SCHEMA_INVALID")
    if record["relevant_event_count"] != len(record["decisions"]):
        raise ReplayError("POLICY_REPLAY_COUNT_INVALID")
    if _replay_hash(record) != record["replay_hash"]:
        raise ReplayError("POLICY_REPLAY_HASH_MISMATCH")


def replay_artifact(path: Path, record: dict) -> dict:
    verify_replay(record)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    return {
        "artifact_id": f"art_{digest[:16]}",
        "media_code": "POLICY_REPLAY_JSON",
        "sha256": digest,
        "size_bytes": len(data),
        "quarantined": False,
    }


def bind_replay_to_envelope(envelope: dict, path: Path, record: dict) -> dict:
    return derive_with_artifact(envelope, replay_artifact(path, record), "POLICY_REPLAY")


def _replay_hash(record: dict) -> str:
    unhashed = copy.deepcopy(record)
    unhashed["replay_hash"] = "0" * 64
    return hashlib.sha256(canonical_bytes(unhashed)).hexdigest()
