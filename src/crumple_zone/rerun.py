"""Fresh scenario rerun coordinator with explicit nondeterministic semantics."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .codex_chamber import CodexChamberResult, CodexChamberRuntimeAdapter
from .evidence import EvidenceAssembler, canonical_bytes, rehash_envelope, verify_envelope
from .projector import project_trusted_result
from .scenario_controller import ScenarioExerciseController
from .scripted_provider import ScriptedInvestigationProvider
from .trace_store import QuarantinedTraceStore


class RerunError(RuntimeError):
    pass


@dataclass(frozen=True)
class ScenarioRerunResult:
    lifecycle: CodexChamberResult
    envelope: dict
    projection: dict
    comparison: dict


class ScenarioRerunCoordinator:
    def __init__(self, repository: Path, runtime: CodexChamberRuntimeAdapter):
        self.repository = repository.resolve()
        self.runtime = runtime

    def rerun(self, original_envelope: dict, request: dict) -> ScenarioRerunResult:
        verify_envelope(original_envelope)
        provider = ScriptedInvestigationProvider(self.repository)
        exercised = ScenarioExerciseController(self.runtime, provider).exercise(request)
        policy_id = {"observe": "observe-v1", "capability-bound": "capability-bound-v1"}[request["policy"]]
        assembler = EvidenceAssembler(self.repository, QuarantinedTraceStore(self.runtime.evidence_root))
        envelope = assembler.assemble(exercised.lifecycle, policy_id)
        envelope["checks"]["not_executed"].remove("SCENARIO_RERUN")
        envelope["checks"]["executed"].append("SCENARIO_RERUN")
        envelope = rehash_envelope(envelope)
        projection = project_trusted_result(envelope, exercised.lifecycle.teardown_verified)
        comparison = compare_envelopes(original_envelope, envelope)
        return ScenarioRerunResult(exercised.lifecycle, envelope, projection, comparison)


def compare_envelopes(original: dict, rerun: dict) -> dict:
    verify_envelope(original)
    verify_envelope(rerun)
    core_equal = original["scenario_id"] == rerun["scenario_id"] and original["scenario_hash"] == rerun["scenario_hash"] and original["tool_surface_hash"] == rerun["tool_surface_hash"]
    run_distinct = original["run_id"] != rerun["run_id"]
    policy_changed = original["policy_id"] != rerun["policy_id"]
    undeclared_drift = not core_equal or not run_distinct
    comparison = {
        "schema_version": "scenario-rerun-comparison.v1",
        "mode": "FRESH_SCENARIO_RERUN_NONDETERMINISTIC",
        "original_run_id": original["run_id"],
        "rerun_run_id": rerun["run_id"],
        "original_envelope_hash": original["envelope_hash"],
        "rerun_envelope_hash": rerun["envelope_hash"],
        "scenario_identity_equal": core_equal,
        "fresh_run_identity": run_distinct,
        "original_policy_id": original["policy_id"],
        "rerun_policy_id": rerun["policy_id"],
        "policy_changed": policy_changed,
        "provider_mode": "SCRIPTED_MOCK_PROVIDER",
        "model_divergence_code": "NOT_CHECKED_LIVE_MODEL",
        "permitted_differences": [
            "RUN_ID", "CANARY", "CAPABILITY", "EVENT_ID", "MONOTONIC_TIME", "READY_TIME",
            "ARTIFACT_ID", "ARTIFACT_HASH", "MODEL_OUTPUT", "MODEL_ACTION_SEQUENCE", "VERDICT",
        ],
        "undeclared_drift": undeclared_drift,
        "comparison_hash": "0" * 64,
    }
    comparison["comparison_hash"] = _comparison_hash(comparison)
    if undeclared_drift:
        raise RerunError("SCENARIO_RERUN_UNDECLARED_DRIFT")
    return comparison


def write_comparison(evidence_root: Path, comparison: dict) -> Path:
    if _comparison_hash(comparison) != comparison["comparison_hash"]:
        raise RerunError("SCENARIO_RERUN_COMPARISON_HASH_MISMATCH")
    destination = evidence_root.resolve() / comparison["rerun_run_id"] / "scenario-rerun-comparison.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise RerunError("SCENARIO_RERUN_COMPARISON_ALREADY_EXISTS")
    destination.write_bytes(canonical_bytes(comparison) + b"\n")
    return destination


def _comparison_hash(comparison: dict) -> str:
    unhashed = copy.deepcopy(comparison)
    unhashed["comparison_hash"] = "0" * 64
    return hashlib.sha256(canonical_bytes(unhashed)).hexdigest()
