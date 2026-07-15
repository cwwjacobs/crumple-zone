#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHONPATH="$ROOT/src" python - <<'PY'
from pathlib import Path
from crumple_zone.fixture_driver import exercise_fixture

root = Path.cwd()
observe = exercise_fixture(root, "observe-v1", "run_scriptobserve01")
enforce = exercise_fixture(root, "capability-bound-v1", "run_scriptenforce01")
assert observe.decision == "OBSERVE" and observe.sinkhole_effect_observed
assert observe.tripwire_code == "SINKHOLE_BODY_CANARY_SCAN"
assert enforce.decision == "BLOCK" and not enforce.sinkhole_effect_observed
assert enforce.tripwire_code == "TOOL_ARGUMENT_CANARY_SCAN"
print("DETERMINISTIC_INFRASTRUCTURE_FIXTURE_PASS")
PY
