"""Phase 3 orchestration with an explicitly bounded, inconclusive model result."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .canary import CanaryManager
from .codex_chamber import CodexAssignment, CodexChamberResult, CodexChamberRuntimeAdapter
from .contracts import validate_contract
from .firecracker_runtime import LifecycleLimits
from .model_proxy import CapabilityManager, HostModelProxy, ProxyLimits
from .scripted_provider import ScriptedInvestigationProvider
from .trusted_events import TrustedTimeline


@dataclass(frozen=True)
class ScenarioExerciseResult:
    interface_version: str
    verdict: str
    behavior_source: str
    live_provider_check: str
    limitation_code: str
    search_exposed_target: bool
    hostile_result_returned_to_codex: bool
    lifecycle: CodexChamberResult


class ScenarioExerciseController:
    def __init__(self, runtime: CodexChamberRuntimeAdapter, provider: ScriptedInvestigationProvider):
        self.runtime = runtime
        self.provider = provider

    def exercise(
        self,
        request: dict[str, Any],
        callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> ScenarioExerciseResult:
        validate_contract("run_request", request)
        limits = request["limits"]
        if limits["model_requests"] < 5:
            raise ValueError("SCRIPTED_PROVIDER_REQUIRES_FIVE_REQUESTS")
        policy_id = {"observe": "observe-v1", "capability-bound": "capability-bound-v1"}[request["policy"]]
        run_id = f"run_{secrets.token_hex(8)}"
        canary = CanaryManager().issue(run_id)
        timeline = TrustedTimeline(run_id, policy_id, callback)
        timeline.emit("RUN_ACCEPTED", "HOST_ENFORCED", "CONTROLLER")
        proxy_limits = ProxyLimits(max_requests=limits["model_requests"], ttl_seconds=min(limits["wall_seconds"] + 15, 300))
        capability_manager = CapabilityManager(proxy_limits)
        capability, _ = capability_manager.issue(run_id)
        timeline.emit("CAPABILITY_ISSUED", "HOST_ENFORCED", "MODEL_PROXY")
        timeline.emit("LIVE_PROVIDER_CALL_NOT_RUN", "HOST_ENFORCED", "MODEL_PROXY", decision="FAIL_CLOSED")
        try:
            lifecycle = self.runtime.run_once(
                CodexAssignment(run_id, canary.value, capability, policy_id, "hostile"),
                HostModelProxy(self.provider, proxy_limits, capability_manager),
                timeline,
                LifecycleLimits(
                    vcpu_count=limits["vcpu_count"],
                    memory_mib=limits["memory_mib"],
                    wall_seconds=limits["wall_seconds"],
                    output_bytes=limits["output_bytes"],
                    process_limit=128,
                ),
            )
        finally:
            capability_manager.revoke(capability)
        return ScenarioExerciseResult(
            interface_version="scenario-exercise.v1",
            verdict="INCONCLUSIVE",
            behavior_source="SCRIPTED_MOCK_PROVIDER",
            live_provider_check="LIVE_PROVIDER_CALL_NOT_RUN",
            limitation_code="OPERATOR_CREDENTIAL_UNAVAILABLE",
            search_exposed_target=self.provider.search_exposed_target,
            hostile_result_returned_to_codex=self.provider.hostile_result_returned_to_codex,
            lifecycle=lifecycle,
        )
