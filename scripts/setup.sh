#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ "$(uname -s)" == "Linux" ]] || { echo 'UNSUPPORTED_HOST_OS' >&2; exit 2; }
[[ "$(uname -m)" == "x86_64" ]] || { echo 'UNSUPPORTED_HOST_ARCHITECTURE' >&2; exit 2; }
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo 'KVM_ACCESS_UNAVAILABLE' >&2; exit 2; }
command -v codex >/dev/null || { echo 'CODEX_CLI_NOT_INSTALLED' >&2; exit 2; }
[[ "$(codex --version)" == "codex-cli 0.144.4" ]] || { echo 'CODEX_VERSION_MISMATCH' >&2; exit 2; }

"$ROOT/scripts/setup-phase1.sh"
"$ROOT/scripts/build-phase2-rootfs.sh"
"$ROOT/scripts/build-phase3-rootfs.sh"

printf '%s  %s\n' 'd7616a6795a7bf26ea8f6234199c10d08f6fd204506648ac6841280684658c4b' "$ROOT/.crumple/cache/guest/rootfs-phase2.ext4" | sha256sum --check
printf '%s  %s\n' 'ff42d037c7090668a76a6abd4dc4fd2b0d12c772224245ad6284e2c8871ae0c5' "$ROOT/.crumple/cache/guest/rootfs-phase3.ext4" | sha256sum --check
printf '%s  %s\n' '2b3edc9cdfd1717fba3dbc92817205a8a2c7511d459e456d4817eeff6f78ed7a' "$(cd "$(dirname "$(readlink -f "$(command -v codex)")")/.." && pwd)/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex" | sha256sum --check

python -m venv --clear "$ROOT/.crumple/venv"
"$ROOT/.crumple/venv/bin/python" -m pip install --no-deps --no-build-isolation "$ROOT"
install -d "$HOME/.local/bin"
rm -f "$HOME/.local/bin/crumple"
{
  printf '%s\n' '#!/usr/bin/env bash'
  printf 'export CRUMPLE_REPOSITORY=%q\n' "$ROOT"
  printf 'exec %q "$@"\n' "$ROOT/.crumple/venv/bin/crumple"
} > "$HOME/.local/bin/crumple"
chmod 0755 "$HOME/.local/bin/crumple"
echo 'CRUMPLE_SETUP_COMPLETE'
