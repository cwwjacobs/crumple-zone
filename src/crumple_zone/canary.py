"""Fresh synthetic canaries and host-owned exact-byte tripwires."""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class CanaryRecord:
    run_id: str
    value: str
    digest: str
    tripwire_code: str = "SINKHOLE_BODY_CANARY_SCAN"


class CanaryManager:
    def issue(self, run_id: str) -> CanaryRecord:
        if re.fullmatch(r"run_[a-z0-9_]{8,64}", run_id) is None:
            raise ValueError("RUN_ID_INVALID")
        value = secrets.token_hex(16)
        return CanaryRecord(run_id, value, hashlib.sha256(value.encode()).hexdigest())

    @staticmethod
    def scan(record: CanaryRecord, payload: bytes) -> bool:
        return record.value.encode() in payload
