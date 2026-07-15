# Crumple Zone — Build Target 1

Crumple Zone launches a real single-use Firecracker microVM containing an independent Codex process, fresh fake data/canaries, a bounded observation skill, and one owned poisoned package-tool workflow. All meaningful target actions and model requests cross host-owned mediators. Raw guest output is quarantined; the default CLI exposes only fixed-schema trusted events and results.

## Supported host

- Linux x86-64 with readable/writable `/dev/kvm`;
- Python 3.14;
- installed Codex CLI 0.144.4;
- `gcc`, `mke2fs`, `debugfs`, `e2fsck`, `curl`, and `tar`;
- official Firecracker 1.16.1 and official Firecracker CI kernel 6.1.176, downloaded and hash-checked by setup.

Setup never creates or copies an API key. Live OpenAI authentication is an operator-supplied runtime secret behind the host provider boundary and was not used for this build. The included demo uses the deterministic mock Responses provider and labels its result `INCONCLUSIVE`.
Setup installs a hash-manifested resource tree under `.crumple/resources`; the launcher does not export a checkout path as production authority.

```bash
./scripts/setup.sh
export PATH="$HOME/.local/bin:$PATH"
```

## Product commands

```bash
crumple exercise fixture://poisoned-tool-surface-v1 --policy observe
crumple watch <run-id>
crumple show <run-id>
crumple replay-policy <run-id> --policy capability-bound
crumple rerun <run-id> --policy capability-bound
crumple verify .crumple/evidence/<run-id>/evidence-envelope.json
```

`exercise` and `rerun` stream fixed-code trusted events as they occur. `watch` defaults to that trusted timeline. Raw trace access requires both an operator flag and a fixed stream:

```bash
crumple watch <run-id> --operator-only --trace codex-jsonl
```

## Demonstration and verification

```bash
./scripts/demo.sh
./scripts/test-fixture.sh
./scripts/verify-receipts.sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
./scripts/teardown.sh
```

`test-fixture.sh` deterministically proves observe/sinkhole and enforce/block infrastructure. It is not evidence that a real model followed prompt injection. `demo.sh` performs a real Firecracker/Codex exercise, trusted watch/show, deterministic policy replay, fresh scenario rerun, and evidence verification.
`verify-receipts.sh` supplies the current Git commit and tree independently, rejects dirty or uncommitted-merge evidence, rehashes the current locked guest artifacts, and verifies the final build receipt. SHA-256 establishes integrity, not safety.

See [architecture](docs/ARCHITECTURE.md), [claim boundaries](docs/CLAIM_BOUNDARIES.md), and [limitations](docs/LIMITATIONS.md).
