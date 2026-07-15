# Limitations

- `LIVE_PROVIDER_CALL_NOT_RUN`: `OPERATOR_CREDENTIAL_UNAVAILABLE`. No live OpenAI model inference was attempted.
- The scripted mock provider proves Responses routing and real Codex/MCP execution, not prompt-injection susceptibility or resistance.
- Observe/enforce violation paths are proven by the separately labeled deterministic fixture, not by fabricated model behavior.
- The direct Firecracker binary is used without jailer, dedicated namespaces, or per-chamber cgroups; production hardening is not claimed.
- Host visibility covers configured lifecycle, proxy, tool, sinkhole, event, and teardown boundaries only. General guest syscalls, process activity, filesystem reads, and hidden model state are not observed.
- A guest report that no `auth.json` exists remains `GUEST_REPORTED`; the host-enforced claim is limited to pinned image content and assignment data supplied.
- Evidence uses SHA-256 canonical binding protected by the host filesystem. It is not a TPM-backed signature or transparency-log proof.
- Raw operator traces can contain hostile/model-controlled text. They must not be automatically forwarded to a privileged agent.
- No guest-generated file, patch, report, or recommendation is promoted to trusted status.
- Time-to-ready measurements are host-specific observations, not an SLA.
- Fresh scenario runs may diverge. Model behavior is never described as deterministic replay.
- No global safety, causal attribution, or absence-of-prompt-injection claim is made.
