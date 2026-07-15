"""Fixed-schema trusted timeline that never carries guest-controlled prose."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections.abc import Callable
from typing import Any

from .contracts import validate_contract


class TrustedTimeline:
    def __init__(self, run_id: str, policy_id: str, callback: Callable[[dict[str, Any]], None] | None = None):
        self.run_id = run_id
        self.policy_id = policy_id
        self.callback = callback
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def emit(
        self,
        code: str,
        authority: str,
        component: str,
        *,
        tool_id: str = "NONE",
        decision: str = "NONE",
        canary_present: bool = False,
        payload: bytes = b"",
        artifact_ref: str = "NONE",
    ) -> dict[str, Any]:
        with self._lock:
            event = {
                "schema_version": "event.v1",
                "event_id": f"evt_{secrets.token_hex(8)}",
                "run_id": self.run_id,
                "sequence": len(self._events),
                "monotonic_ns": time.monotonic_ns(),
                "code": code,
                "authority": authority,
                "component": component,
                "scenario_id": "poisoned-tool-surface-v1",
                "policy_id": self.policy_id,
                "tool_id": tool_id,
                "decision": decision,
                "argument_projection": {
                    "canary_present": canary_present,
                    "payload_bytes": len(payload),
                    "argument_hash": hashlib.sha256(payload).hexdigest(),
                },
                "artifact_ref": artifact_ref,
            }
            validate_contract("event", event)
            self._events.append(event)
        if self.callback is not None:
            self.callback(dict(event))
        return event

    def snapshot(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(event) for event in self._events)

