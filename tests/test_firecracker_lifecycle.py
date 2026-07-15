import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from crumple_zone.controller import CrumpleController
from crumple_zone.firecracker_runtime import (
    ChamberAssignment,
    FirecrackerRuntimeAdapter,
    LifecycleError,
    LifecycleLimits,
    _handshake,
)


ROOT = Path(__file__).resolve().parents[1]


class FirecrackerLifecycleTests(unittest.TestCase):
    def runtime(self, temporary: Path) -> FirecrackerRuntimeAdapter:
        cache = ROOT / ".crumple/cache"
        return FirecrackerRuntimeAdapter(
            cache / "firecracker/v1.16.1/firecracker-v1.16.1-x86_64",
            cache / "kernel/6.1.176/vmlinux-6.1.176",
            cache / "guest/rootfs-phase1.ext4",
            temporary / "runs",
            temporary / "evidence",
        )

    def test_real_repeated_boot_assignment_and_teardown(self):
        with tempfile.TemporaryDirectory(prefix="crumple-phase1-") as directory:
            runtime = self.runtime(Path(directory))
            controller = CrumpleController(runtime)
            request = {
                "schema_version": "run-request.v1",
                "scenario_uri": "fixture://poisoned-tool-surface-v1",
                "policy": "observe",
                "limits": {"vcpu_count": 1, "memory_mib": 256, "wall_seconds": 20, "output_bytes": 1048576, "model_requests": 4},
            }
            first = controller.exercise_lifecycle(request).lifecycle
            second = controller.exercise_lifecycle(request).lifecycle

            self.assertNotEqual(first.run_id, second.run_id)
            self.assertNotEqual(first.canary, second.canary)
            self.assertNotEqual(first.challenge_nonce, second.challenge_nonce)
            self.assertFalse(first.prior_state_present)
            self.assertFalse(second.prior_state_present)
            self.assertTrue(first.assignment_acknowledged)
            self.assertTrue(second.assignment_acknowledged)
            self.assertTrue(first.teardown_verified)
            self.assertTrue(second.teardown_verified)
            self.assertTrue(first.process_gone and second.process_gone)
            self.assertTrue(first.run_directory_gone and second.run_directory_gone)
            self.assertTrue(first.sockets_gone and second.sockets_gone)
            self.assertEqual([event.code for event in first.events], ["RUN_ACCEPTED", "CHAMBER_READY", "CHAMBER_STOPPED", "TEARDOWN_VERIFIED"])
            self.assertEqual({event.authority for event in first.events}, {"HOST_ENFORCED"})
            self.assertGreater(first.ready_milliseconds, 0)
            self.assertGreater(second.ready_milliseconds, 0)
            self.assertEqual(list((Path(directory) / "runs").iterdir()), [])
            self.assertTrue((Path(directory) / "evidence" / first.run_id / "quarantine/firecracker.log").exists())

    def test_nonce_mismatch_fails(self):
        host, guest = socket.socketpair()
        assignment = ChamberAssignment.fresh()

        def fake_guest():
            with guest:
                guest.sendall(b"HELLO lifecycle.v1\n")
                challenge = self._line(guest)
                self.assertTrue(challenge.startswith("CHALLENGE "))
                guest.sendall(b"READY 00000000000000000000000000000000 0\n")

        thread = threading.Thread(target=fake_guest)
        thread.start()
        with host:
            with self.assertRaisesRegex(LifecycleError, "HANDSHAKE_NONCE_MISMATCH"):
                _handshake(host, assignment, "11111111111111111111111111111111")
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_invalid_limits_fail_before_launch(self):
        with tempfile.TemporaryDirectory(prefix="crumple-phase1-negative-") as directory:
            runtime = self.runtime(Path(directory))
            with self.assertRaisesRegex(LifecycleError, "MEMORY_LIMIT_INVALID"):
                runtime.run_once(ChamberAssignment.fresh(), LifecycleLimits(memory_mib=64))
            self.assertIsNone(runtime.last_process_pid)

    def test_wall_timeout_forces_teardown(self):
        with tempfile.TemporaryDirectory(prefix="crumple-phase1-timeout-") as directory:
            temporary = Path(directory)
            runtime = self.runtime(temporary)
            with patch("crumple_zone.firecracker_runtime.LIFECYCLE_PORT", 5001):
                with self.assertRaisesRegex(LifecycleError, "WALL_CLOCK_LIMIT_EXCEEDED"):
                    runtime.run_once(ChamberAssignment.fresh(), LifecycleLimits(wall_seconds=2))
            self.assertIsNotNone(runtime.last_process_pid)
            self.assertEqual(list((temporary / "runs").iterdir()), [])
            with self.assertRaises(ProcessLookupError):
                import os
                os.kill(runtime.last_process_pid, 0)

    @staticmethod
    def _line(sock: socket.socket) -> str:
        data = bytearray()
        while True:
            chunk = sock.recv(1)
            if chunk == b"\n":
                return data.decode()
            data.extend(chunk)


if __name__ == "__main__":
    unittest.main()
