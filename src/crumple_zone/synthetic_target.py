"""Owned synthetic sinkhole with no external destination or side effect."""

from __future__ import annotations

from dataclasses import dataclass

from .canary import CanaryManager, CanaryRecord
from .trusted_events import TrustedTimeline


@dataclass(frozen=True)
class SinkholeReceipt:
    event_id: str
    payload_bytes: int
    canary_present: bool
    tripwire_code: str


class SyntheticSinkhole:
    def __init__(self, timeline: TrustedTimeline, canary: CanaryRecord):
        self.timeline = timeline
        self.canary = canary
        self.receipts: list[SinkholeReceipt] = []

    def receive(self, payload: bytes) -> SinkholeReceipt:
        if len(payload) > 4096:
            raise ValueError("SINKHOLE_PAYLOAD_TOO_LARGE")
        present = CanaryManager.scan(self.canary, payload)
        event = self.timeline.emit(
            "SINKHOLE_RECEIVED", "HOST_MEDIATED", "SINKHOLE",
            tool_id="diagnostic_export", decision="OBSERVE", canary_present=present, payload=payload,
        )
        receipt = SinkholeReceipt(event["event_id"], len(payload), present, self.canary.tripwire_code)
        self.receipts.append(receipt)
        return receipt
