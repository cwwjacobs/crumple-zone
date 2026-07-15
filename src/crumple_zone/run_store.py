"""Append-only trusted event stream persistence for live watch."""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

from .contracts import validate_contract


class RunStoreError(RuntimeError):
    pass


class TrustedRunStore:
    def __init__(self, evidence_root: Path):
        self.evidence_root = evidence_root.resolve()
        self._locks: dict[str, threading.Lock] = {}

    def append(self, event: dict) -> None:
        validate_contract("event", event)
        run_id = event["run_id"]
        lock = self._locks.setdefault(run_id, threading.Lock())
        with lock:
            path = self._path(run_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            existing = self.read(run_id) if path.exists() else []
            if event["sequence"] != len(existing):
                raise RunStoreError("TRUSTED_EVENT_SEQUENCE_INVALID")
            with path.open("ab") as output:
                output.write(json.dumps(event, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode() + b"\n")

    def read(self, run_id: str) -> list[dict]:
        path = self._path(run_id)
        if not path.is_file():
            raise RunStoreError("TRUSTED_TIMELINE_NOT_FOUND")
        events = []
        for expected_sequence, line in enumerate(path.read_bytes().splitlines()):
            try:
                event = json.loads(line)
                validate_contract("event", event)
            except Exception as error:
                raise RunStoreError("TRUSTED_TIMELINE_INVALID") from error
            if event["run_id"] != run_id or event["sequence"] != expected_sequence:
                raise RunStoreError("TRUSTED_EVENT_SEQUENCE_INVALID")
            events.append(event)
        return events

    def follow(self, run_id: str, timeout_seconds: int = 900):
        start = time.monotonic()
        emitted = 0
        while time.monotonic() - start < timeout_seconds:
            try:
                events = self.read(run_id)
            except RunStoreError as error:
                if str(error) != "TRUSTED_TIMELINE_NOT_FOUND":
                    raise
                events = []
            for event in events[emitted:]:
                yield event
                emitted += 1
                if event["code"] in {"RUN_COMPLETED", "RUN_FAILED"}:
                    return
            time.sleep(0.05)
        raise RunStoreError("WATCH_TIMEOUT")

    def _path(self, run_id: str) -> Path:
        if re.fullmatch(r"run_[a-z0-9_]{8,64}", run_id) is None:
            raise RunStoreError("RUN_ID_INVALID")
        return self.evidence_root / run_id / "trusted-events.jsonl"
