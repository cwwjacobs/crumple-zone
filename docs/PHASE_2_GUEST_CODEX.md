# Phase 2 guest Codex and observation boundary

## Runtime boundary

`codex-controller.v1` validates `run-request.v1`, chooses a fresh run ID and fake canary, issues a short-lived run capability, and invokes `codex-chamber.v1`. The guest receives the capability only after the nonce handshake and assignment. It never receives provider authentication.

The Phase 2 image pins the installed Codex CLI 0.144.4 native binary and runs:

- `codex exec --ephemeral --json --ignore-user-config --ignore-rules --strict-config`;
- a fresh tmpfs-backed `CODEX_HOME` created on each boot;
- no history persistence and no saved `auth.json`;
- a Responses-compatible provider at guest loopback only;
- a required stdio MCP server whose bytes are forwarded over vsock to the host mediator;
- read-only Codex sandbox selection, a 128-task guest ceiling, bounded file/output/CPU/wall limits, and a single-use writable rootfs copy.

The host model service accepts only `/v1/responses`, the pinned model, the run capability, and the configured request/response/count/TTL bounds. The Phase 2 test provider is deterministic and owns no credential. The live provider is not invoked.

## Data paths

```text
guest Codex --HTTP loopback--> static TCP/vsock bridge --AF_VSOCK--> host model proxy --> mock provider
guest Codex --MCP stdio------> static stdio/vsock bridge ---------> host tool mediator
guest init  --framed streams--------------------------------------> quarantined trace store
host controller <---------------fixed-code typed events------------ host mediators/runtime
```

Firecracker exposes no TAP device in this slice. The guest has no general external network route. Meaningful synthetic target calls can only use the declared MCP bridge. The host does not claim visibility into arbitrary guest file reads, syscalls, processes, or model reasoning.

## Prompt-injection observation skill

`guest/skills/prompt-injection-observer/SKILL.md` is copied from the immutable image into the fresh Codex home. It asks Codex to notice instruction overrides, provenance changes, undeclared authority, and disclosure suppression, then use a bounded mediated recording tool. It does not sanitize or rewrite the target, and any resulting classification is limited to `AGENT_INTERPRETED` authority.

## Evidence separation and claim boundary

The live trusted callback receives only values that validate as `event.v1`: fixed codes/enums, validated IDs, counts, booleans, hashes, and artifact references. Raw Codex JSONL, stderr, and Firecracker console bytes are stored under the run's `quarantine/` directory and never inserted into trusted events.

- `VERIFIED_FROM_SOURCE`: a real Firecracker guest ran the pinned independent Codex binary to exit 0 using one host-mock Responses request.
- `VERIFIED_FROM_SOURCE`: Codex initialized and listed the actual host-mediated six-tool MCP surface.
- `HOST_ENFORCED`: the controller supplied only a fresh run capability through the assignment channel and revoked it after the run.
- `HOST_MEDIATED`: model requests and tool-surface presentation necessarily crossed host-owned Unix/vsock services.
- `GUEST_REPORTED`: Codex structured output, stderr, its exit status report, and its report that no `auth.json` existed.
- `VERIFIED_FROM_SOURCE`: the reusable image has no `auth.json`; every run creates `CODEX_HOME` in fresh tmpfs and destroys the writable rootfs, sockets, and Firecracker process.
- `LIMITATION`: no live OpenAI call was made. The explicit check is `LIVE_PROVIDER_CALL_NOT_RUN` with Phase 0 reason `OPERATOR_CREDENTIAL_UNAVAILABLE`.
- `LIMITATION`: use of the observation skill and harmless mock completion does not establish resistance to prompt injection.
