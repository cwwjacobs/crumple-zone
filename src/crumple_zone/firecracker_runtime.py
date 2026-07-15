"""Versioned, single-use Firecracker runtime adapter."""

from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import secrets
import shutil
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol


FIRECRACKER_RUNTIME_INTERFACE_VERSION = "firecracker-runtime.v1"
LIFECYCLE_PROTOCOL_VERSION = "lifecycle.v1"
LIFECYCLE_PORT = 5000
EXPECTED_FIRECRACKER_SHA256 = "2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7"
EXPECTED_KERNEL_SHA256 = "b20af7585283b051f16f6ece46e7064165054efe112c4ab0e26a06ff8ebe9da4"
EXPECTED_PHASE1_ROOTFS_SHA256 = "3f77696fe97adc47ecd9c114b82d04f46994f028e4ca8b677cd0f1b39b2ab537"


class LifecycleError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class LifecycleLimits:
    vcpu_count: int = 1
    memory_mib: int = 256
    wall_seconds: int = 20
    output_bytes: int = 1_048_576
    process_limit: int = 128


@dataclass(frozen=True)
class ChamberAssignment:
    run_id: str
    canary: str

    @classmethod
    def fresh(cls) -> "ChamberAssignment":
        return cls(run_id=f"run_{secrets.token_hex(8)}", canary=secrets.token_hex(16))


@dataclass(frozen=True)
class LifecycleEvent:
    code: str
    authority: str
    monotonic_milliseconds: int


@dataclass(frozen=True)
class LifecycleResult:
    interface_version: str
    run_id: str
    canary: str
    challenge_nonce: str
    ready_milliseconds: int
    prior_state_present: bool
    assignment_acknowledged: bool
    graceful_guest_shutdown: bool
    firecracker_pid: int
    firecracker_exit_code: int
    output_truncated: bool
    quarantined_log_sha256: str
    process_gone: bool
    run_directory_gone: bool
    sockets_gone: bool
    teardown_verified: bool
    events: tuple[LifecycleEvent, ...]


class FirecrackerRuntimeV1(Protocol):
    def run_once(self, assignment: ChamberAssignment, limits: LifecycleLimits = LifecycleLimits()) -> LifecycleResult: ...


class _OutputCapture:
    def __init__(self, source: BinaryIO, destination: Path, limit: int):
        self.source = source
        self.destination = destination
        self.limit = limit
        self.truncated = False
        self._thread = threading.Thread(target=self._run, name="crumple-vmm-output", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def join(self) -> None:
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise LifecycleError("OUTPUT_HELPER_DID_NOT_STOP")

    def _run(self) -> None:
        written = 0
        with self.destination.open("wb") as output:
            while True:
                chunk = self.source.read(65536)
                if not chunk:
                    return
                remaining = self.limit - written
                if remaining > 0:
                    accepted = chunk[:remaining]
                    output.write(accepted)
                    written += len(accepted)
                if len(chunk) > max(remaining, 0):
                    self.truncated = True


class FirecrackerRuntimeAdapter:
    """One process, rootfs copy, socket namespace, and teardown per run."""

    def __init__(
        self,
        firecracker_binary: Path,
        kernel_image: Path,
        base_rootfs: Path,
        runtime_root: Path,
        evidence_root: Path,
    ):
        self.firecracker_binary = firecracker_binary.resolve()
        self.kernel_image = kernel_image.resolve()
        self.base_rootfs = base_rootfs.resolve()
        self.runtime_root = runtime_root.resolve()
        self.evidence_root = evidence_root.resolve()
        self.last_process_pid: int | None = None
        self._validate_artifacts()

    @classmethod
    def from_repository(cls, repository: Path) -> "FirecrackerRuntimeAdapter":
        root = repository.resolve()
        cache = root / ".crumple/cache"
        return cls(
            firecracker_binary=cache / "firecracker/v1.16.1/firecracker-v1.16.1-x86_64",
            kernel_image=cache / "kernel/6.1.176/vmlinux-6.1.176",
            base_rootfs=cache / "guest/rootfs-phase1.ext4",
            runtime_root=root / ".crumple/runs",
            evidence_root=root / ".crumple/evidence",
        )

    def run_once(self, assignment: ChamberAssignment, limits: LifecycleLimits = LifecycleLimits()) -> LifecycleResult:
        _validate_assignment(assignment)
        _validate_limits(limits)
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        run_directory = self.runtime_root / assignment.run_id
        if run_directory.exists():
            raise LifecycleError("RUN_DIRECTORY_ALREADY_EXISTS")
        run_directory.mkdir(mode=0o700)
        rootfs = run_directory / "rootfs.ext4"
        api_socket = run_directory / "firecracker.api.sock"
        vsock_prefix = run_directory / "v.sock"
        lifecycle_socket = Path(f"{vsock_prefix}_{LIFECYCLE_PORT}")
        evidence_directory = self.evidence_root / assignment.run_id / "quarantine"
        evidence_directory.mkdir(parents=True, exist_ok=False)
        quarantined_log = evidence_directory / "firecracker.log"
        challenge = secrets.token_hex(16)
        process: subprocess.Popen[bytes] | None = None
        listener: socket.socket | None = None
        capture: _OutputCapture | None = None
        started = time.monotonic()
        ready_milliseconds = -1
        prior_state = False
        acknowledged = False
        graceful = False
        exit_code = -1
        pid = -1
        original_error: BaseException | None = None
        cleanup_error: BaseException | None = None
        process_gone = False
        run_directory_gone = False
        sockets_gone = False
        events = [LifecycleEvent("RUN_ACCEPTED", "HOST_ENFORCED", 0)]
        try:
            shutil.copyfile(self.base_rootfs, rootfs)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(lifecycle_socket))
            os.chmod(lifecycle_socket, 0o600)
            listener.listen(1)
            listener.settimeout(limits.wall_seconds)

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
            deadline = started + limits.wall_seconds
            _wait_for_socket(api_socket, process, deadline)
            _configure_vm(api_socket, self.kernel_image, rootfs, vsock_prefix, limits)
            _api_put(api_socket, "/actions", {"action_type": "InstanceStart"})

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LifecycleError("WALL_CLOCK_LIMIT_EXCEEDED")
            listener.settimeout(remaining)
            channel, _ = listener.accept()
            with channel:
                channel.settimeout(max(0.1, deadline - time.monotonic()))
                prior_state = _handshake(channel, assignment, challenge)
                ready_milliseconds = int((time.monotonic() - started) * 1000)
                events.append(LifecycleEvent("CHAMBER_READY", "HOST_ENFORCED", ready_milliseconds))
                acknowledged = True
                _send_line(channel, "SHUTDOWN")
                goodbye = _read_line(channel)
                if goodbye != f"BYE {assignment.run_id}":
                    raise LifecycleError("GUEST_SHUTDOWN_ACK_INVALID")
                graceful = True

            remaining = max(0.1, min(5.0, deadline - time.monotonic()))
            try:
                exit_code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise LifecycleError("GUEST_DID_NOT_TERMINATE") from exc
        except BaseException as exc:
            original_error = exc
        finally:
            if listener is not None:
                try:
                    listener.close()
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
            if process is not None and process.poll() is None:
                try:
                    _stop_process(process)
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
                    try:
                        _force_kill_process(process)
                    except BaseException as force_exc:
                        cleanup_error = cleanup_error or force_exc
            if process is not None:
                exit_code = process.poll() if process.poll() is not None else -1
                if process.stdout is not None:
                    try:
                        process.stdout.close()
                    except BaseException as exc:
                        cleanup_error = cleanup_error or exc
            if capture is not None:
                try:
                    capture.join()
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
            process_gone = pid < 0 or not _pid_exists(pid)
            if process_gone:
                events.append(LifecycleEvent("CHAMBER_STOPPED", "HOST_ENFORCED", int((time.monotonic() - started) * 1000)))
            for path in (api_socket, lifecycle_socket, vsock_prefix):
                try:
                    path.unlink(missing_ok=True)
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
            try:
                shutil.rmtree(run_directory, ignore_errors=False)
            except BaseException as exc:
                cleanup_error = cleanup_error or exc
            run_directory_gone = not run_directory.exists()
            sockets_gone = not api_socket.exists() and not lifecycle_socket.exists() and not vsock_prefix.exists()

        log_hash = hashlib.sha256(quarantined_log.read_bytes()).hexdigest() if quarantined_log.exists() else "0" * 64
        teardown = process_gone and run_directory_gone and sockets_gone
        if teardown:
            events.append(LifecycleEvent("TEARDOWN_VERIFIED", "HOST_ENFORCED", int((time.monotonic() - started) * 1000)))
        if original_error is not None:
            if isinstance(original_error, LifecycleError):
                raise original_error
            if isinstance(original_error, socket.timeout):
                raise LifecycleError("WALL_CLOCK_LIMIT_EXCEEDED") from original_error
            raise LifecycleError("FIRECRACKER_LIFECYCLE_FAILED") from original_error
        if cleanup_error is not None:
            raise LifecycleError("FIRECRACKER_CLEANUP_FAILED") from cleanup_error
        if not teardown:
            raise LifecycleError("TEARDOWN_VERIFICATION_FAILED")
        return LifecycleResult(
            interface_version=FIRECRACKER_RUNTIME_INTERFACE_VERSION,
            run_id=assignment.run_id,
            canary=assignment.canary,
            challenge_nonce=challenge,
            ready_milliseconds=ready_milliseconds,
            prior_state_present=prior_state,
            assignment_acknowledged=acknowledged,
            graceful_guest_shutdown=graceful,
            firecracker_pid=pid,
            firecracker_exit_code=exit_code,
            output_truncated=capture.truncated if capture is not None else False,
            quarantined_log_sha256=log_hash,
            process_gone=process_gone,
            run_directory_gone=run_directory_gone,
            sockets_gone=sockets_gone,
            teardown_verified=teardown,
            events=tuple(events),
        )

    def _validate_artifacts(self) -> None:
        for path, code, expected_hash in (
            (self.firecracker_binary, "FIRECRACKER_BINARY_MISSING", EXPECTED_FIRECRACKER_SHA256),
            (self.kernel_image, "GUEST_KERNEL_MISSING", EXPECTED_KERNEL_SHA256),
            (self.base_rootfs, "BASE_ROOTFS_MISSING", EXPECTED_PHASE1_ROOTFS_SHA256),
        ):
            if not path.is_file():
                raise LifecycleError(code)
            if _sha256_file(path) != expected_hash:
                raise LifecycleError(code.removesuffix("_MISSING") + "_HASH_MISMATCH")


def _configure_vm(api_socket: Path, kernel: Path, rootfs: Path, vsock_prefix: Path, limits: LifecycleLimits) -> None:
    _api_put(api_socket, "/machine-config", {
        "vcpu_count": limits.vcpu_count,
        "mem_size_mib": limits.memory_mib,
        "smt": False,
        "track_dirty_pages": False,
    })
    _api_put(api_socket, "/boot-source", {
        "kernel_image_path": str(kernel),
        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/sbin/crumple-lifecycle-init random.trust_cpu=on",
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


def _api_put(api_socket: Path, path: str, payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    request = (
        f"PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(str(api_socket))
        client.sendall(request)
        response = bytearray()
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > 1_048_576:
                raise LifecycleError("FIRECRACKER_API_RESPONSE_TOO_LARGE")
            header_end = response.find(b"\r\n\r\n")
            if header_end >= 0:
                header = bytes(response[:header_end]).decode("ascii", errors="strict")
                content_length = 0
                for line in header.split("\r\n")[1:]:
                    if line.lower().startswith("content-length:"):
                        content_length = int(line.split(":", 1)[1].strip())
                        break
                if len(response) >= header_end + 4 + content_length:
                    break
    finally:
        client.close()
    match = re.match(rb"HTTP/1\.[01] ([0-9]{3}) ", response)
    if match is None:
        raise LifecycleError("FIRECRACKER_API_RESPONSE_INVALID")
    status = int(match.group(1))
    if status != 204:
        raise LifecycleError(f"FIRECRACKER_API_REJECTED_{status}")


def _handshake(channel: socket.socket, assignment: ChamberAssignment, challenge: str) -> bool:
    if _read_line(channel) != f"HELLO {LIFECYCLE_PROTOCOL_VERSION}":
        raise LifecycleError("HANDSHAKE_HELLO_INVALID")
    _send_line(channel, f"CHALLENGE {challenge}")
    ready = _read_line(channel).split(" ")
    if len(ready) != 3 or ready[0] != "READY" or ready[1] != challenge or ready[2] not in {"0", "1"}:
        raise LifecycleError("HANDSHAKE_NONCE_MISMATCH")
    _send_line(channel, f"ASSIGN {assignment.run_id} {assignment.canary}")
    if _read_line(channel) != f"ASSIGNED {assignment.run_id} {assignment.canary}":
        raise LifecycleError("ASSIGNMENT_ACK_INVALID")
    return ready[2] == "1"


def _read_line(channel: socket.socket) -> str:
    data = bytearray()
    while len(data) < 512:
        chunk = channel.recv(1)
        if not chunk:
            raise LifecycleError("CHANNEL_CLOSED")
        if chunk == b"\n":
            try:
                return data.decode("ascii")
            except UnicodeDecodeError as exc:
                raise LifecycleError("CHANNEL_NON_ASCII") from exc
        if chunk[0] < 0x20 or chunk[0] > 0x7E:
            raise LifecycleError("CHANNEL_CONTROL_BYTE")
        data.extend(chunk)
    raise LifecycleError("CHANNEL_LINE_TOO_LONG")


def _send_line(channel: socket.socket, line: str) -> None:
    channel.sendall(line.encode("ascii") + b"\n")


def _wait_for_socket(path: Path, process: subprocess.Popen[bytes], deadline: float) -> None:
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise LifecycleError("FIRECRACKER_EXITED_BEFORE_API_READY")
        time.sleep(0.005)
    raise LifecycleError("FIRECRACKER_API_TIMEOUT")


def _apply_process_limits(limits: LifecycleLimits, nproc_ceiling: int) -> None:
    os.setsid()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_NPROC, (nproc_ceiling, nproc_ceiling))
    resource.setrlimit(resource.RLIMIT_CPU, (limits.wall_seconds + 2, limits.wall_seconds + 2))


def _current_uid_task_count() -> int:
    uid = os.getuid()
    count = 0
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            status = (process / "status").read_text(encoding="ascii", errors="ignore")
            uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
            if int(uid_line.split()[1]) != uid:
                continue
            count += sum(1 for task in (process / "task").iterdir() if task.name.isdigit())
        except (FileNotFoundError, PermissionError, StopIteration, ValueError):
            continue
    return max(count, 1)


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=2)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)


def _force_kill_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _validate_assignment(assignment: ChamberAssignment) -> None:
    if re.fullmatch(r"run_[a-z0-9_]{8,64}", assignment.run_id) is None:
        raise LifecycleError("RUN_ID_INVALID")
    if re.fullmatch(r"[a-f0-9]{32}", assignment.canary) is None:
        raise LifecycleError("CANARY_INVALID")


def _validate_limits(limits: LifecycleLimits) -> None:
    if limits.vcpu_count not in {1, 2}:
        raise LifecycleError("VCPU_LIMIT_INVALID")
    if not 256 <= limits.memory_mib <= 2048:
        raise LifecycleError("MEMORY_LIMIT_INVALID")
    if not 2 <= limits.wall_seconds <= 900:
        raise LifecycleError("WALL_LIMIT_INVALID")
    if not 4096 <= limits.output_bytes <= 10_485_760:
        raise LifecycleError("OUTPUT_LIMIT_INVALID")
    if not 16 <= limits.process_limit <= 256:
        raise LifecycleError("PROCESS_LIMIT_INVALID")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
