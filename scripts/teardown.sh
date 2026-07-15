#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ROOT="$ROOT/.crumple/runs"

for cmdline in /proc/[0-9]*/cmdline; do
  [[ -r "$cmdline" ]] || continue
  value="$(tr '\0' ' ' < "$cmdline")"
  if [[ "$value" == *firecracker* && "$value" == *"$RUN_ROOT/"* ]]; then
    echo 'ACTIVE_CRUMPLE_FIRECRACKER_PRESENT' >&2
    exit 2
  fi
done

if [[ -d "$RUN_ROOT" ]]; then
  find "$RUN_ROOT" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
fi
find "$ROOT/.crumple" -maxdepth 1 -type s -delete 2>/dev/null || true
echo 'CRUMPLE_TEARDOWN_VERIFIED'
