#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
TREE="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
PYTHONPATH="$ROOT/src" python -m crumple_zone.cli verify-receipts --source-root "$ROOT" --source-commit "$COMMIT" --source-tree "$TREE" "$@"
