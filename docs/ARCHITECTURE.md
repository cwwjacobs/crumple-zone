# Build Target 1 architecture

```text
Crumple CLI
  |
  v strict run-request.v1
Controller ---- fresh run ID/canary/capability ----+
  |                                                |
  v firecracker-runtime.v1                        v
Firecracker 1.16.1                           Host model proxy
  |  guest-codex.v1 handshake                 | endpoint/model/count/
  |                                           | bytes/TTL enforcement
  v                                           v
fresh writable rootfs + tmpfs CODEX_HOME   mock Responses provider
  |
  +-- independent Codex 0.144.4
  |      | HTTP loopback -> vsock -> host model proxy
  |      + MCP stdio -> vsock -> host tool mediator
  |                              | policy engine
  |                              + owned synthetic sinkhole
  |
  +-- prompt-injection observation skill
  +-- fresh fake credential file and canary

Host mediators/runtime
  +--> append-only fixed event timeline --> default CLI/watch/outer agent
  +--> raw guest streams -------------> quarantined operator trace
  +--> canonical envelope ------------> typed trusted projection
  +--> deterministic policy replay
  +--> fresh scenario rerun coordinator
```

## Component ownership

- CLI: parsing and fixed-code rendering only; no arbitrary host paths, commands, VM arguments, destinations, models, or environment variables.
- Controller: validates the request, assigns fresh state, issues/revokes the run capability, and selects fixed limits.
- Firecracker adapter: validates pinned artifacts, owns the per-run VMM/rootfs/socket namespace, enforces wall/process/output limits, and proves teardown.
- Guest bootstrap: creates tmpfs Codex home, installs the observation skill, injects fake data after assignment, runs Codex unprivileged, and frames raw telemetry.
- Model proxy: owns provider authentication and enforces endpoint/model/request/size/TTL bounds. The guest sees only its run capability.
- Tool mediator: supplies the exact tool surface, validates calls, hashes projections, and routes effects through host policy.
- Canary manager and sinkhole: create fresh fake canaries and provide named exact-byte tripwires with no external destination.
- Evidence/projector: canonicalize events, bind hashes/artifacts/findings, and emit schema-limited machine results.
- Trace store: permits raw reads only after explicit operator-only selection.
- Replay/rerun: keep deterministic policy evaluation separate from fresh execution.

## Runtime and trust boundaries

The host controller, mediators, artifact locks, evidence assembler, policy engine, and projector are trusted. The guest, inner Codex, model output, target descriptions/results, skill classifications, terminal output, and guest-generated artifacts are untrusted. No TAP interface is configured. No general guest syscall, file-read, process, or hidden-model-state sensor is claimed.

The versioned internal seams are `controller.v1`, `firecracker-runtime.v1`, `codex-controller.v1`, `codex-chamber.v1`, `guest-codex.v1`, `model-proxy.v1`, and `scenario-exercise.v1`.
