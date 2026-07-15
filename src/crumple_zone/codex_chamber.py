"""Versioned Firecracker chamber for one mock-backed, non-persistent guest Codex run."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .firecracker_runtime import (
    EXPECTED_FIRECRACKER_SHA256,
    EXPECTED_KERNEL_SHA256,
    LifecycleError,
    LifecycleLimits,
    _OutputCapture,
    _api_put,
    _apply_process_limits,
    _current_uid_task_count,
    _pid_exists,
    _read_line,
    _send_line,
    _sha256_file,
    _stop_process,
    _validate_limits,
    _wait_for_socket,
)
from .model_proxy import HostModelProxy
from .trusted_events import TrustedTimeline
from .vsock_services import HostToolMediator, ModelVsockService, ServiceError, TraceVsockService


CODEX_CHAMBER_INTERFACE_VERSION = "codex-chamber.v1"
CODEX_GUEST_PROTOCOL_VERSION = "guest-codex.v1"
EXPECTED_PHASE2_ROOTFS_SHA256 = "d7616a6795a7bf26ea8f6234199c10d08f6fd204506648ac6841280684658c4b"
LIFECYCLE_PORT = 5000


@dataclass(frozen=True)
class CodexAssignment:
    run_id: str
    canary: str
    capability: str
    policy_id: str
    task_mode: str = "baseline"


@dataclass(frozen=True)
class CodexChamberResult:
    interface_version: str
    run_id: str
    canary_digest: str
    challenge_digest: str
    ready_milliseconds: int
    codex_exit_code: int
    guest_auth_file_reported: bool
    tool_surface_presented: bool
    tool_calls_observed: int
    model_requests_observed: int
    trace_completed: bool
    trace_truncated: bool
    codex_trace_artifact_id: str
    codex_stderr_artifact_id: str
    firecracker_log_artifact_id: str
    codex_trace_sha256: str
    codex_stderr_sha256: str
    firecracker_log_sha256: str
    firecracker_pid: int
    firecracker_exit_code: int
    process_gone: bool
    run_directory_gone: bool
    sockets_gone: bool
    teardown_verified: bool
    events: tuple[dict, ...]


class CodexChamberRuntimeAdapter:
    """Owns the complete mutable namespace for one assigned Codex chamber."""

    def __init__(
        self,
        repository: Path,
        firecracker_binary: Path,
        kernel_image: Path,
        base_rootfs: Path,
        runtime_root: Path,
        evidence_root: Path,
        expected_rootfs_sha256: str = EXPECTED_PHASE2_ROOTFS_SHA256,
        guest_init: str = "/sbin/crumple-phase2-init",
    ):
        self.repository = repository.resolve()
        self.firecracker_binary = firecracker_binary.resolve()
        self.kernel_image = kernel_image.resolve()
        self.base_rootfs = base_rootfs.resolve()
        self.runtime_root = runtime_root.resolve()
        self.evidence_root = evidence_root.resolve()
        self.expected_rootfs_sha256 = expected_rootfs_sha256
        self.guest_init = guest_init
        self.last_process_pid: int | None = None
        self._validate_artifacts()

    @classmethod
    def from_repository(cls, repository: Path) -> "CodexChamberRuntimeAdapter":
        root = repository.resolve()
        cache = root / ".crumple/cache"
        return cls(
            root,
            cache / "firecracker/v1.16.1/firecracker-v1.16.1-x86_64",
            cache / "kernel/6.1.176/vmlinux-6.1.176",
            cache / "guest/rootfs-phase2.ext4",
            root / ".crumple/runs",
            root / ".crumple/evidence",
        )

    @classmethod
    def for_hostile_scenario(cls, repository: Path, rootfs_sha256: str) -> "CodexChamberRuntimeAdapter":
        root = repository.resolve()
        cache = root / ".crumple/cache"
        return cls(
            root,
            cache / "firecracker/v1.16.1/firecracker-v1.16.1-x86_64",
            cache / "kernel/6.1.176/vmlinux-6.1.176",
            cache / "guest/rootfs-phase3.ext4",
            root / ".crumple/runs",
            root / ".crumple/evidence",
            rootfs_sha256,
            "/sbin/crumple-phase3-init",
        )

    def run_once(
        self,
        assignment: CodexAssignment,
        proxy: HostModelProxy,
        timeline: TrustedTimeline,
        limits: LifecycleLimits,
    ) -> CodexChamberResult:
        _validate_codex_assignment(assignment)
        _validate_limits(limits)
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        run_directory = self.runtime_root / assignment.run_id
        if run_directory.exists():
            raise LifecycleError("RUN_DIRECTORY_ALREADY_EXISTS")
        run_directory.mkdir(mode=0o700)
        evidence_directory = self.evidence_root / assignment.run_id / "quarantine"
        evidence_directory.mkdir(parents=True, exist_ok=False)

        rootfs = run_directory / "rootfs.ext4"
        api_socket = run_directory / "firecracker.api.sock"
        vsock_prefix = run_directory / "v.sock"
        lifecycle_socket = Path(f"{vsock_prefix}_{LIFECYCLE_PORT}")
        model_socket = Path(f"{vsock_prefix}_5001")
        mcp_socket = Path(f"{vsock_prefix}_5002")
        trace_socket = Path(f"{vsock_prefix}_5003")
        socket_paths = (api_socket, lifecycle_socket, model_socket, mcp_socket, trace_socket, vsock_prefix)
        quarantined_log = evidence_directory / "firecracker.log"

        model_service = ModelVsockService(model_socket, proxy, timeline, assignment.canary)
        tool_service = HostToolMediator(mcp_socket, self.repository, timeline, assignment.policy_id, assignment.canary)
        trace_service = TraceVsockService(trace_socket, evidence_directory, timeline, limits.output_bytes)
        services = (model_service, tool_service, trace_service)
        listener: socket.socket | None = None
        process: subprocess.Popen[bytes] | None = None
        capture: _OutputCapture | None = None
        started = time.monotonic()
        deadline = started + limits.wall_seconds
        challenge = secrets.token_hex(16)
        ready_milliseconds = -1
        codex_exit_code = -1
        guest_auth_file_reported = True
        pid = -1
        firecracker_exit_code = -1
        process_gone = False
        run_directory_gone = False
        sockets_gone = False
        teardown_verified = False
        original_error: BaseException | None = None
        cleanup_error: BaseException | None = None

        try:
            shutil.copyfile(self.base_rootfs, rootfs)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(lifecycle_socket))
            os.chmod(lifecycle_socket, 0o600)
            listener.listen(1)
            listener.settimeout(limits.wall_seconds)
            for service in services:
                service.start()

            nproc_ceiling = _current_uid_task_count() + limits.process_limit
            process = subprocess.Popen(
                [str(self.firecracker_binary), "--api-sock", str(api_socket), "--id", f"fc{assignment.run_id.removeprefix('run_')}"],
                cwd=run_directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                preexec_fn=lambda: _apply_process_limits(limits, nproc_ceiling),
            )
            pid = process.pid
            self.last_process_pid = pid
            if process.stdout is None:
                raise LifecycleError("FIRECRACKER_OUTPUT_PIPE_MISSING")
            capture = _OutputCapture(process.stdout, quarantined_log, limits.output_bytes)
            capture.start()
            _wait_for_socket(api_socket, process, deadline)
            _configure_codex_vm(api_socket, self.kernel_image, rootfs, vsock_prefix, limits, self.guest_init)
            _api_put(api_socket, "/actions", {"action_type": "InstanceStart"})

            listener.settimeout(_remaining(deadline))
            channel, _ = listener.accept()
            with channel:
                channel.settimeout(_remaining(deadline))
                if _read_line(channel) != f"HELLO {CODEX_GUEST_PROTOCOL_VERSION}":
                    raise LifecycleError("HANDSHAKE_HELLO_INVALID")
                _send_line(channel, f"CHALLENGE {challenge}")
                ready = _read_line(channel).split(" ")
                if len(ready) != 3 or ready[0] != "READY" or ready[1] != challenge or ready[2] != "0":
                    raise LifecycleError("HANDSHAKE_NONCE_OR_STATE_INVALID")
                ready_milliseconds = int((time.monotonic() - started) * 1000)
                timeline.emit("CHAMBER_READY", "HOST_ENFORCED", "FIRECRACKER_RUNTIME")
                _send_line(
                    channel,
                    f"ASSIGN2 {assignment.run_id} {assignment.canary} {assignment.capability} {assignment.task_mode}",
                )
                if _read_line(channel) != f"ASSIGNED2 {assignment.run_id}":
                    raise LifecycleError("ASSIGNMENT_ACK_INVALID")
                channel.settimeout(_remaining(deadline))
                status = _read_line(channel).split(" ")
                if len(status) != 3 or status[0] != "CODEX_EXIT" or not all(item.isdigit() for item in status[1:]):
                    raise LifecycleError("GUEST_CODEX_STATUS_INVALID")
                codex_exit_code = int(status[1])
                guest_auth_file_reported = status[2] == "1"
                timeline.emit(
                    "GUEST_EVENT_REPORTED", "GUEST_REPORTED", "GUEST_SENSOR",
                    decision="OBSERVE", payload=(" ".join(status)).encode("ascii"),
                )
                _send_line(channel, "SHUTDOWN")
                if _read_line(channel) != f"BYE {assignment.run_id}":
                    raise LifecycleError("GUEST_SHUTDOWN_ACK_INVALID")

            try:
                firecracker_exit_code = process.wait(timeout=min(5.0, _remaining(deadline)))
            except subprocess.TimeoutExpired as exc:
                raise LifecycleError("GUEST_DID_NOT_TERMINATE") from exc
            if not trace_service.completed.wait(timeout=1):
                raise LifecycleError("GUEST_TRACE_INCOMPLETE")
            if codex_exit_code != 0:
                raise LifecycleError("GUEST_CODEX_FAILED")
            if guest_auth_file_reported:
                raise LifecycleError("GUEST_AUTH_STATE_PRESENT")
        except BaseException as error:
            original_error = error
        finally:
            if listener is not None:
                listener.close()
            if process is not None and process.poll() is None:
                _stop_process(process)
            if process is not None:
                firecracker_exit_code = process.poll() if process.poll() is not None else -1
            if capture is not None:
                try:
                    capture.join()
                except BaseException as error:
                    cleanup_error = cleanup_error or error
            if process is not None and process.stdout is not None:
                process.stdout.close()
            for service in reversed(services):
                try:
                    service.stop()
                except BaseException as error:
                    cleanup_error = cleanup_error or error
            process_gone = pid < 0 or not _pid_exists(pid)
            if process_gone:
                timeline.emit("CHAMBER_STOPPED", "HOST_ENFORCED", "FIRECRACKER_RUNTIME")
            try:
                shutil.rmtree(run_directory, ignore_errors=False)
            except BaseException as error:
                cleanup_error = cleanup_error or error
            run_directory_gone = not run_directory.exists()
            sockets_gone = all(not path.exists() for path in socket_paths)
            teardown_verified = process_gone and run_directory_gone and sockets_gone
            if teardown_verified:
                timeline.emit("TEARDOWN_VERIFIED", "HOST_ENFORCED", "FIRECRACKER_RUNTIME")

        success = original_error is None and cleanup_error is None and teardown_verified
        timeline.emit("RUN_COMPLETED" if success else "RUN_FAILED", "HOST_ENFORCED", "CONTROLLER")
        if original_error is not None:
            if isinstance(original_error, (LifecycleError, ServiceError)):
                raise LifecycleError(str(original_error)) from original_error
            if isinstance(original_error, socket.timeout):
                raise LifecycleError("WALL_CLOCK_LIMIT_EXCEEDED") from original_error
            raise LifecycleError("CODEX_CHAMBER_FAILED") from original_error
        if cleanup_error is not None:
            if isinstance(cleanup_error, (LifecycleError, ServiceError)):
                raise LifecycleError(str(cleanup_error)) from cleanup_error
            raise LifecycleError("CODEX_CHAMBER_CLEANUP_FAILED") from cleanup_error
        if not teardown_verified:
            raise LifecycleError("TEARDOWN_VERIFICATION_FAILED")

        firecracker_log_hash = _hash_or_zero(quarantined_log)
        return CodexChamberResult(
            interface_version=CODEX_CHAMBER_INTERFACE_VERSION,
            run_id=assignment.run_id,
            canary_digest=_digest_text(assignment.canary),
            challenge_digest=_digest_text(challenge),
            ready_milliseconds=ready_milliseconds,
            codex_exit_code=codex_exit_code,
            guest_auth_file_reported=guest_auth_file_reported,
            tool_surface_presented=tool_service.surface_presented,
            tool_calls_observed=tool_service.calls_observed,
            model_requests_observed=model_service.requests_observed,
            trace_completed=trace_service.completed.is_set(),
            trace_truncated=trace_service.truncated,
            codex_trace_artifact_id=trace_service.jsonl_artifact,
            codex_stderr_artifact_id=trace_service.stderr_artifact,
            firecracker_log_artifact_id=f"art_{firecracker_log_hash[:16]}",
            codex_trace_sha256=_hash_or_zero(trace_service.jsonl_path),
            codex_stderr_sha256=_hash_or_zero(trace_service.stderr_path),
            firecracker_log_sha256=firecracker_log_hash,
            firecracker_pid=pid,
            firecracker_exit_code=firecracker_exit_code,
            process_gone=process_gone,
            run_directory_gone=run_directory_gone,
            sockets_gone=sockets_gone,
            teardown_verified=teardown_verified,
            events=timeline.snapshot(),
        )

    def _validate_artifacts(self) -> None:
        for path, code, expected in (
            (self.firecracker_binary, "FIRECRACKER_BINARY", EXPECTED_FIRECRACKER_SHA256),
            (self.kernel_image, "GUEST_KERNEL", EXPECTED_KERNEL_SHA256),
            (self.base_rootfs, "GUEST_ROOTFS", self.expected_rootfs_sha256),
        ):
            if not path.is_file():
                raise LifecycleError(f"{code}_MISSING")
            if _sha256_file(path) != expected:
                raise LifecycleError(f"{code}_HASH_MISMATCH")


def _configure_codex_vm(
    api_socket: Path,
    kernel: Path,
    rootfs: Path,
    vsock_prefix: Path,
    limits: LifecycleLimits,
    guest_init: str,
) -> None:
    _api_put(api_socket, "/machine-config", {
        "vcpu_count": limits.vcpu_count,
        "mem_size_mib": limits.memory_mib,
        "smt": False,
        "track_dirty_pages": False,
    })
    _api_put(api_socket, "/boot-source", {
        "kernel_image_path": str(kernel),
        "boot_args": f"console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init={guest_init} random.trust_cpu=on",
    })
    _api_put(api_socket, "/drives/rootfs", {
        "drive_id": "rootfs",
        "path_on_host": str(rootfs),
        "is_root_device": True,
        "is_read_only": False,
        "cache_type": "Unsafe",
        "io_engine": "Sync",
    })
    _api_put(api_socket, "/vsock", {"guest_cid": 3, "uds_path": str(vsock_prefix)})


def _validate_codex_assignment(assignment: CodexAssignment) -> None:
    if re.fullmatch(r"run_[a-z0-9_]{8,64}", assignment.run_id) is None:
        raise LifecycleError("RUN_ID_INVALID")
    if re.fullmatch(r"[a-f0-9]{32}", assignment.canary) is None:
        raise LifecycleError("CANARY_INVALID")
    if re.fullmatch(r"[A-Za-z0-9_-]{32,128}", assignment.capability) is None:
        raise LifecycleError("CAPABILITY_INVALID")
    if assignment.policy_id not in {"observe-v1", "capability-bound-v1"}:
        raise LifecycleError("POLICY_INVALID")
    if assignment.task_mode not in {"baseline", "hostile"}:
        raise LifecycleError("TASK_MODE_INVALID")


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LifecycleError("WALL_CLOCK_LIMIT_EXCEEDED")
    return max(0.1, remaining)


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _hash_or_zero(path: Path) -> str:
    return _sha256_file(path) if path.exists() else "0" * 64
