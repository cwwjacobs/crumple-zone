# Phase 1 single-use lifecycle

## Boundary

`controller.v1` accepts only `run-request.v1`. It creates the run ID and canary after validation and passes a typed assignment to `firecracker-runtime.v1`. No request field can select a host path, command, VM argument, environment variable, or destination.

The runtime uses official Firecracker v1.16.1 with the pinned official Firecracker CI `vmlinux-6.1.176` kernel and a locally built, hash-pinned 64 MiB ext4 rootfs. The base rootfs contains one statically linked init, no shell, no SSH server, no model credential, no run identity, no canary, and no user data.

## Handshake and assignment

The guest initiates an AF_VSOCK connection to host CID 2, port 5000. Firecracker maps that connection to a unique host Unix socket inside the run directory.

```text
guest init                     host runtime
    | HELLO lifecycle.v1           |
    |------------------------------>|
    | CHALLENGE <fresh nonce>       |
    |<------------------------------|
    | READY <same nonce> <prior>    |
    |------------------------------>|
    | ASSIGN <run id> <canary>      |
    |<------------------------------|
    | ASSIGNED <run id> <canary>    |
    |------------------------------>|
    | SHUTDOWN / BYE / reboot       |
```

The challenge and assignment are generated after request admission and are never stored in the reusable kernel or rootfs. A rootfs copy is made per run. The guest reports whether a prior marker existed before it writes the current run marker; repeated real boots reported `false` for both runs.

## Limits

- vCPUs and guest memory are enforced by Firecracker machine configuration.
- wall time is enforced by the host controller and terminates the VMM process group on expiry.
- host child CPU time, open files, core dumps, and additional process allowance are enforced with rlimits.
- VMM/serial output is drained but only the first configured byte limit is retained in quarantine.
- writable storage is the bounded per-run rootfs copy plus an 8 MiB guest tmpfs.
- the Phase 1 guest image contains only PID 1 and cannot launch arbitrary guest commands.

The `RLIMIT_NPROC` mechanism is scoped by Linux to the real host UID. The adapter calculates the current UID task count and adds the chamber allowance; this is not represented as a per-chamber cgroup claim.

## Teardown evidence

The adapter verifies the Firecracker PID is gone, closes and removes all run sockets, removes the writable rootfs and run directory, joins the output helper thread, and retains only the bounded quarantined log outside mutable run state. Lifecycle codes are fixed and `HOST_ENFORCED`:

- `RUN_ACCEPTED`
- `CHAMBER_READY`
- `CHAMBER_STOPPED`
- `TEARDOWN_VERIFIED`

## Claim boundary

- `VERIFIED_FROM_SOURCE`: two sequential real microVM runs used distinct run IDs, canaries, and challenge nonces; both reported no prior writable state; both exited 0 and passed teardown checks.
- `VERIFIED_FROM_SOURCE`: a forced two-second timeout with a deliberately unmatched test port terminated the real Firecracker process and removed run state.
- `VERIFIED_FROM_SOURCE`: readiness for the retained two-run proof was 854 ms and 860 ms on this host. These are measurements, not an SLA.
- `INFERENCE`: destruction of the VMM process destroys guest helper execution because the helper exists only inside that VM; no separate host process claims to observe guest PID state.
- `REQUIRES_LOCAL_VERIFICATION`: the jailer is pinned but not used in this unprivileged slice; no production-hardening claim is made.
- `REQUIRES_LOCAL_VERIFICATION`: setup must complete before controller admission. Concurrent cache mutation and execution are not an admitted operation.
