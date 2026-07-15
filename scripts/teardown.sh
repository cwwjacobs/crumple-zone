#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ROOT="$ROOT/.crumple/runs"

active_pids() {
  for cmdline in /proc/[0-9]*/cmdline; do
    [[ -r "$cmdline" ]] || continue
    value="$(tr '\0' ' ' < "$cmdline")"
    if [[ "$value" == *firecracker* && "$value" == *"$RUN_ROOT/"* ]]; then
      basename "$(dirname "$cmdline")"
    fi
  done
}

mapfile -t pids < <(active_pids)
if ((${#pids[@]})); then
  kill -TERM "${pids[@]}" 2>/dev/null || true
  for _ in {1..20}; do
    mapfile -t pids < <(active_pids)
    ((${#pids[@]} == 0)) && break
    sleep 0.1
  done
  ((${#pids[@]} == 0)) || kill -KILL "${pids[@]}" 2>/dev/null || true
fi

if [[ -d "$RUN_ROOT" ]]; then
  find "$RUN_ROOT" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
fi
find "$ROOT/.crumple" -type s -delete 2>/dev/null || true

mapfile -t pids < <(active_pids)
((${#pids[@]} == 0)) || { echo 'TEARDOWN_PROCESS_POSTCONDITION_FAILED' >&2; exit 2; }
if [[ -d "$RUN_ROOT" ]] && find "$RUN_ROOT" -mindepth 1 -print -quit | read -r _; then
  echo 'TEARDOWN_RUN_DIRECTORY_POSTCONDITION_FAILED' >&2
  exit 2
fi
if find "$ROOT/.crumple" -type s -print -quit | read -r _; then
  echo 'TEARDOWN_SOCKET_POSTCONDITION_FAILED' >&2
  exit 2
fi
echo 'CRUMPLE_TEARDOWN_VERIFIED'
