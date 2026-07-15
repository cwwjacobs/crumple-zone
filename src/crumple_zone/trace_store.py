"""Quarantined trace metadata and deliberately gated operator access."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .codex_chamber import CodexChamberResult


class TraceAccessError(RuntimeError):
    pass


class QuarantinedTraceStore:
    STREAMS = {
        "codex-jsonl": ("codex.jsonl", "GUEST_JSONL"),
        "codex-stderr": ("codex.stderr", "GUEST_STDERR"),
        "firecracker-log": ("firecracker.log", "FIRECRACKER_LOG"),
    }

    def __init__(self, evidence_root: Path):
        self.evidence_root = evidence_root.resolve()

    def describe(self, lifecycle: CodexChamberResult) -> list[dict]:
        identifiers = {
            "codex-jsonl": lifecycle.codex_trace_artifact_id,
            "codex-stderr": lifecycle.codex_stderr_artifact_id,
            "firecracker-log": lifecycle.firecracker_log_artifact_id,
        }
        expected_hashes = {
            "codex-jsonl": lifecycle.codex_trace_sha256,
            "codex-stderr": lifecycle.codex_stderr_sha256,
            "firecracker-log": lifecycle.firecracker_log_sha256,
        }
        records = []
        for stream, (filename, media_code) in self.STREAMS.items():
            path = self._path(lifecycle.run_id, filename)
            if not path.is_file():
                raise TraceAccessError("QUARANTINE_ARTIFACT_MISSING")
            actual_hash = _sha256(path)
            if actual_hash != expected_hashes[stream]:
                raise TraceAccessError("QUARANTINE_ARTIFACT_HASH_MISMATCH")
            records.append({
                "artifact_id": identifiers[stream],
                "media_code": media_code,
                "sha256": actual_hash,
                "size_bytes": path.stat().st_size,
                "quarantined": True,
                "path": f"quarantine/{filename}",
            })
        return records

    def read_operator(self, run_id: str, stream: str, *, operator_only: bool = False) -> bytes:
        if not operator_only:
            raise TraceAccessError("OPERATOR_TRACE_OPT_IN_REQUIRED")
        if stream not in self.STREAMS:
            raise TraceAccessError("TRACE_STREAM_INVALID")
        filename, _ = self.STREAMS[stream]
        path = self._path(run_id, filename)
        if not path.is_file():
            raise TraceAccessError("QUARANTINE_ARTIFACT_MISSING")
        return path.read_bytes()

    def _path(self, run_id: str, filename: str) -> Path:
        if re.fullmatch(r"run_[a-z0-9_]{8,64}", run_id) is None:
            raise TraceAccessError("RUN_ID_INVALID")
        return self.evidence_root / run_id / "quarantine" / filename


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
