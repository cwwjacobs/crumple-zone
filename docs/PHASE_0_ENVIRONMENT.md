# Phase 0 environment and contract lock

Status codes in this document are evidence labels, not product verdicts.

- `VERIFIED_FROM_SOURCE`: Linux x86-64 host; CPU virtualization flags and KVM modules are present; `/dev/kvm` is readable and writable under the admitted execution environment.
- `VERIFIED_FROM_SOURCE`: official Firecracker v1.16.1 x86-64 archive SHA-256 is `382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6`; its internal `SHA256SUMS` verifies; both `firecracker` and `jailer` report v1.16.1.
- `VERIFIED_FROM_SOURCE`: installed `codex-cli 0.144.4` exposes `codex exec --ephemeral --json`, `--ignore-user-config`, `--strict-config`, and command/config overrides.
- `VERIFIED_FROM_SOURCE`: official Codex configuration documentation defines custom model providers with `base_url`, `wire_api = "responses"`, and an environment or command-backed bearer-token seam.
- `PROPOSAL`: each guest run receives only `CRUMPLE_RUN_CAPABILITY`; that bearer token authenticates to the chamber host proxy and is never a provider credential.
- `PROPOSAL`: host live authentication is supplied only at runtime as `CRUMPLE_OPENAI_API_KEY`, is read only by `LiveResponsesProvider`, and is never serialized.
- `VERIFIED_FROM_SOURCE`: the mock provider and proxy tests prove endpoint, model, request-size, response-size, request-count, and TTL enforcement without a credential.
- `REQUIRES_LOCAL_VERIFICATION`: `LIVE_PROVIDER_CALL_NOT_RUN` with reason `OPERATOR_CREDENTIAL_UNAVAILABLE`.

Implementation is Python 3.14 standard library only. No Python dependency is admitted. Firecracker and Codex are pinned external runtime artifacts, not Python dependencies.

Hashes establish artifact identity and integrity. They do not establish artifact safety.
