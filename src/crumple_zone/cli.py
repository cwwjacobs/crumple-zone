"""Crumple Zone Build Target 1 command line."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .codex_chamber import CodexChamberRuntimeAdapter
from .contracts import validate_contract
from .evidence import EvidenceAssembler, EvidenceError, verify_envelope
from .projector import project_trusted_result, verify_projection, write_trusted_projection
from .receipt_verifier import verify_receipts
from .replay import PolicyReplayEngine, verify_replay
from .rerun import compare_envelopes, write_comparison
from .resources import InstallLayout, _layout_for_tests, production_layout
from .run_store import TrustedRunStore
from .scenario_controller import ScenarioExerciseController
from .scripted_provider import ScriptedInvestigationProvider
from .trace_store import QuarantinedTraceStore


TARGET = "fixture://poisoned-tool-surface-v1"
POLICIES = {"observe": "observe-v1", "capability-bound": "capability-bound-v1"}


class CliError(RuntimeError):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="crumple")
    commands = parser.add_subparsers(dest="command", required=True)
    exercise = commands.add_parser("exercise")
    exercise.add_argument("target", choices=[TARGET])
    exercise.add_argument("--policy", choices=sorted(POLICIES), required=True)
    watch = commands.add_parser("watch")
    watch.add_argument("run_id")
    watch.add_argument("--operator-only", action="store_true")
    watch.add_argument("--trace", choices=sorted(QuarantinedTraceStore.STREAMS))
    show = commands.add_parser("show")
    show.add_argument("run_id")
    replay = commands.add_parser("replay-policy")
    replay.add_argument("run_id")
    replay.add_argument("--policy", choices=sorted(POLICIES), required=True)
    rerun = commands.add_parser("rerun")
    rerun.add_argument("run_id")
    rerun.add_argument("--policy", choices=sorted(POLICIES), required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("evidence_envelope")
    receipts = commands.add_parser("verify-receipts")
    receipts.add_argument("--require-artifacts", action="store_true")
    receipts.add_argument("--source-root", required=True)
    receipts.add_argument("--source-commit", required=True)
    receipts.add_argument("--source-tree", required=True)
    return parser


def main(argv: list[str] | None = None, _test_root: Path | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    layout = _layout_for_tests(_test_root) if _test_root is not None else production_layout()
    try:
        if args.command == "exercise":
            return _exercise(layout, args.policy)
        if args.command == "watch":
            return _watch(layout, args.run_id, args.operator_only, args.trace)
        if args.command == "show":
            return _show(layout, args.run_id)
        if args.command == "replay-policy":
            return _replay(layout, args.run_id, args.policy)
        if args.command == "rerun":
            return _rerun(layout, args.run_id, args.policy)
        if args.command == "verify":
            return _verify(layout, args.evidence_envelope)
        if args.command == "verify-receipts":
            return _verify_receipts(layout, args.require_artifacts, args.source_root, args.source_commit, args.source_tree)
        raise CliError("COMMAND_INVALID")
    except Exception as error:
        code = str(error) if re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", str(error)) else "COMMAND_FAILED"
        _print({"stream_code": "FIXED_ERROR", "error_code": code})
        return 2


def _exercise(layout: InstallLayout, policy: str) -> int:
    evidence_root = layout.state_root / "evidence"
    event_store = TrustedRunStore(evidence_root)

    def emit(event: dict) -> None:
        event_store.append(event)
        _print({"stream_code": "TRUSTED_EVENT", "event": event})

    runtime = _runtime(layout)
    provider = ScriptedInvestigationProvider(layout.resource_root)
    result = ScenarioExerciseController(runtime, provider).exercise(_request(policy), emit)
    trace_store = QuarantinedTraceStore(evidence_root)
    assembler = EvidenceAssembler(layout.resource_root, trace_store)
    envelope = assembler.assemble(result.lifecycle, POLICIES[policy])
    envelope_path = assembler.write(envelope)
    projection = project_trusted_result(envelope)
    write_trusted_projection(projection, envelope, evidence_root)
    (layout.state_root / "last-run-id").write_text(result.lifecycle.run_id + "\n")
    _print({
        "stream_code": "TRUSTED_RESULT",
        "provider_code": "SCRIPTED_MOCK_PROVIDER",
        "projection": projection,
        "evidence_file_code": "EVIDENCE_ENVELOPE_RETAINED",
        "envelope_hash": envelope["envelope_hash"],
    })
    if not envelope_path.is_file():
        raise CliError("EVIDENCE_WRITE_FAILED")
    return 0 if result.lifecycle.run_status == "COMPLETED" else 2


def _watch(layout: InstallLayout, run_id: str, operator_only: bool, trace: str | None) -> int:
    _validate_run_id(run_id)
    evidence_root = layout.state_root / "evidence"
    if trace is not None or operator_only:
        if trace is None or not operator_only:
            raise CliError("OPERATOR_TRACE_OPT_IN_REQUIRED")
        raw = QuarantinedTraceStore(evidence_root).read_operator(run_id, trace, operator_only=True)
        sys.stdout.buffer.write(raw)
        return 0
    for event in TrustedRunStore(evidence_root).follow(run_id):
        _print({"stream_code": "TRUSTED_EVENT", "event": event})
    return 0


def _show(layout: InstallLayout, run_id: str) -> int:
    _validate_run_id(run_id)
    run_root = layout.state_root / "evidence" / run_id
    projection = _load_json(run_root / "trusted-result.json", "TRUSTED_RESULT_NOT_FOUND")
    envelope = _load_json(run_root / "evidence-envelope.json", "EVIDENCE_ENVELOPE_NOT_FOUND")
    verify_envelope(envelope, artifact_root=run_root, require_artifacts=True)
    verify_projection(projection, envelope)
    _print({"stream_code": "TRUSTED_RESULT", "projection": projection})
    return 0


def _replay(layout: InstallLayout, run_id: str, policy: str) -> int:
    envelope = _load_envelope(layout, run_id)
    engine = PolicyReplayEngine()
    target = POLICIES[policy]
    path = layout.state_root / "evidence" / run_id / f"policy-replay-{target}.json"
    if path.exists():
        record = _load_json(path, "POLICY_REPLAY_NOT_FOUND")
        verify_replay(record, envelope)
        if record["source_envelope_hash"] != envelope["envelope_hash"] or record["target_policy_id"] != target:
            raise CliError("POLICY_REPLAY_SCOPE_MISMATCH")
    else:
        record = engine.replay(envelope, target)
        engine.write(layout.state_root / "evidence", record, envelope)
    _print({"stream_code": "POLICY_REPLAY_RESULT", "replay": record})
    return 0


def _rerun(layout: InstallLayout, run_id: str, policy: str) -> int:
    original = _load_envelope(layout, run_id)
    if POLICIES[policy] == original["policy_id"]:
        raise CliError("SAME_POLICY_RERUN_REJECTED")
    evidence_root = layout.state_root / "evidence"
    event_store = TrustedRunStore(evidence_root)

    def emit(event: dict) -> None:
        event_store.append(event)
        _print({"stream_code": "TRUSTED_EVENT", "event": event})

    runtime = _runtime(layout)
    provider = ScriptedInvestigationProvider(layout.resource_root)
    # The coordinator constructs its own fresh provider; callback streaming is retained by running the same strict controller path here.
    exercised = ScenarioExerciseController(runtime, provider).exercise(_request(policy), emit)
    assembler = EvidenceAssembler(layout.resource_root, QuarantinedTraceStore(evidence_root))
    envelope = assembler.assemble(exercised.lifecycle, POLICIES[policy], run_mode="FRESH_SCENARIO_RERUN")
    comparison = compare_envelopes(original, envelope)
    projection = project_trusted_result(envelope)
    assembler.write(envelope)
    write_trusted_projection(projection, envelope, evidence_root)
    write_comparison(evidence_root, comparison)
    _print({"stream_code": "SCENARIO_RERUN_RESULT", "comparison": comparison, "projection": projection})
    return 0


def _verify(layout: InstallLayout, supplied: str) -> int:
    evidence_root = (layout.state_root / "evidence").resolve()
    path = Path(supplied).expanduser().resolve()
    if not path.is_relative_to(evidence_root) or path.name != "evidence-envelope.json":
        raise CliError("EVIDENCE_PATH_NOT_ADMITTED")
    envelope = _load_json(path, "EVIDENCE_ENVELOPE_NOT_FOUND")
    verify_envelope(envelope, artifact_root=path.parent, require_artifacts=True)
    projection_path = path.parent / "trusted-result.json"
    if projection_path.is_file():
        verify_projection(_load_json(projection_path, "TRUSTED_RESULT_NOT_FOUND"), envelope)
    _print({
        "stream_code": "EVIDENCE_VERIFICATION",
        "status": "VERIFIED",
        "run_id": envelope["run_id"],
        "envelope_hash": envelope["envelope_hash"],
        "integrity_is_safety": False,
    })
    return 0


def _verify_receipts(
    layout: InstallLayout,
    require_artifacts: bool,
    source_root: str,
    source_commit: str,
    source_tree: str,
) -> int:
    root = Path(source_root).expanduser().resolve()
    if layout.source_root is not None and root != layout.source_root:
        raise CliError("SOURCE_ROOT_MISMATCH")
    _print({"stream_code": "RECEIPT_VERIFICATION", "result": verify_receipts(
        root,
        require_artifacts=require_artifacts,
        source_commit=source_commit,
        source_tree=source_tree,
    )})
    return 0


def _runtime(layout: InstallLayout) -> CodexChamberRuntimeAdapter:
    lock = _load_json(layout.resource_root / "locks/phase3-guest-image.json", "PHASE3_LOCK_NOT_FOUND")
    return CodexChamberRuntimeAdapter.for_hostile_layout(layout.resource_root, layout.state_root, lock["rootfs_sha256"])


def _request(policy: str) -> dict:
    return {
        "schema_version": "run-request.v1",
        "scenario_uri": TARGET,
        "policy": policy,
        "limits": {"vcpu_count": 1, "memory_mib": 1024, "wall_seconds": 90, "output_bytes": 2_097_152, "model_requests": 5},
    }


def _load_envelope(layout: InstallLayout, run_id: str) -> dict:
    _validate_run_id(run_id)
    root = layout.state_root / "evidence" / run_id
    envelope = _load_json(root / "evidence-envelope.json", "EVIDENCE_ENVELOPE_NOT_FOUND")
    verify_envelope(envelope, artifact_root=root, require_artifacts=True)
    return envelope


def _load_json(path: Path, missing_code: str) -> dict:
    if not path.is_file():
        raise CliError(missing_code)
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise CliError("JSON_ARTIFACT_INVALID") from error
    if not isinstance(value, dict):
        raise CliError("JSON_ARTIFACT_INVALID")
    return value


def _validate_run_id(run_id: str) -> None:
    if re.fullmatch(r"run_[a-z0-9_]{8,64}", run_id) is None:
        raise CliError("RUN_ID_INVALID")


def _print(value: dict) -> None:
    print(json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
