#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRUMPLE=(python -m crumple_zone.cli)
export PYTHONPATH="$ROOT/src"

"${CRUMPLE[@]}" exercise fixture://poisoned-tool-surface-v1 --policy observe
RUN_ID="$(tr -d '\n' < "$ROOT/.crumple/last-run-id")"
"${CRUMPLE[@]}" watch "$RUN_ID"
"${CRUMPLE[@]}" show "$RUN_ID"
"${CRUMPLE[@]}" replay-policy "$RUN_ID" --policy capability-bound
"${CRUMPLE[@]}" rerun "$RUN_ID" --policy capability-bound
"${CRUMPLE[@]}" verify "$ROOT/.crumple/evidence/$RUN_ID/evidence-envelope.json"
echo 'CRUMPLE_SYNTHETIC_DEMO_COMPLETE'
