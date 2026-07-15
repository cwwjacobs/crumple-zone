# Phase 5 policy replay and scenario rerun

## Deterministic policy replay

`PolicyReplayEngine` reads a verified evidence envelope and selects only recorded `TOOL_CALL_OBSERVED` events with fixed target tool IDs. It does not inspect raw trace data and does not launch a VM. For each relevant event it retains the event reference, recorded fixed decision, task-authorization boolean, canary-presence boolean, and deterministic decision under the requested policy.

The replay record is canonical JSON with its own SHA-256. Replaying identical events under the same target policy yields byte-identical decisions and hash. The deterministic infrastructure fixture proves that an observed `diagnostic_export` changes from `OBSERVE` under `observe-v1` to `BLOCK` under `capability-bound-v1`.

Policy replay answers only how the changed policy treats the recorded action. It does not assert that a different policy would have changed prior model reasoning, and it does not re-execute any guest/model/tool effect.

## Fresh scenario rerun

`ScenarioRerunCoordinator` verifies the original envelope, creates a new run identity/canary/capability, launches a new Firecracker chamber and independent Codex process, assembles a new evidence envelope, and compares fixed fields.

The comparison is labeled `FRESH_SCENARIO_RERUN_NONDETERMINISTIC`. Required equalities are scenario ID/hash and tool-surface hash. The run ID must differ. The policy change is explicit. Permitted differences are limited to run identity, canary, capability, event IDs, monotonic/readiness timing, artifact IDs/hashes, model output/action sequence, and bounded verdict. Any other core drift raises `SCENARIO_RERUN_UNDECLARED_DRIFT`.

Current runs use `SCRIPTED_MOCK_PROVIDER`, so live-model divergence is `NOT_CHECKED_LIVE_MODEL`. The nondeterministic label preserves the correct product semantics for a later operator-supplied live provider; a fresh execution is never called deterministic replay.

## Repeated lifecycle proof

The retained Phase 5 source and rerun chambers had distinct run IDs and canary digests. Both Firecracker processes terminated, both mutable run directories/sockets were removed, both evidence directories remained verifiable, and the shared mutable run root was empty afterward. These checks supplement the repeated and timeout lifecycle tests from Phases 1–4.
