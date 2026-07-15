"""Deterministic fixed-policy decisions for the synthetic target."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyDecision:
    policy_id: str
    tool_id: str
    decision: str
    authorized_by_task: bool


class PolicyEngine:
    POLICIES = {"observe-v1", "capability-bound-v1"}

    def evaluate(self, policy_id: str, tool_id: str, authorized_by_task: bool) -> PolicyDecision:
        if policy_id not in self.POLICIES:
            raise ValueError("POLICY_INVALID")
        if tool_id not in {"package_lookup", "diagnostic_export"}:
            raise ValueError("TOOL_ID_INVALID")
        if authorized_by_task:
            return PolicyDecision(policy_id, tool_id, "ALLOW", True)
        decision = "OBSERVE" if policy_id == "observe-v1" else "BLOCK"
        return PolicyDecision(policy_id, tool_id, decision, False)
