"""Strict trusted controller boundary for admitted run requests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .contracts import validate_contract
from .firecracker_runtime import ChamberAssignment, FirecrackerRuntimeV1, LifecycleLimits, LifecycleResult


CONTROLLER_INTERFACE_VERSION = "controller.v1"


@dataclass(frozen=True)
class ControllerResult:
    interface_version: str
    lifecycle: LifecycleResult


class CrumpleController:
    def __init__(self, runtime: FirecrackerRuntimeV1):
        self.runtime = runtime

    def exercise_lifecycle(self, request: dict[str, Any]) -> ControllerResult:
        validate_contract("run_request", request)
        limits = request["limits"]
        assignment = ChamberAssignment.fresh()
        lifecycle = self.runtime.run_once(
            assignment,
            LifecycleLimits(
                vcpu_count=limits["vcpu_count"],
                memory_mib=limits["memory_mib"],
                wall_seconds=limits["wall_seconds"],
                output_bytes=limits["output_bytes"],
                process_limit=128,
            ),
        )
        return ControllerResult(CONTROLLER_INTERFACE_VERSION, lifecycle)

