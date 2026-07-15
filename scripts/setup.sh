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

printf '%s  %s\n' 'c66ff0975fc24950b4a372bc1644763a09bff726f021927340f01da92e2fbee4' "$ROOT/.crumple/cache/guest/rootfs-phase2.ext4" | sha256sum --check
printf '%s  %s\n' '5ac599fb9b11e8015a21762741279978493a19e6dfb6e89330fe6dc491311667' "$ROOT/.crumple/cache/guest/rootfs-phase3.ext4" | sha256sum --check
printf '%s  %s\n' '2b3edc9cdfd1717fba3dbc92817205a8a2c7511d459e456d4817eeff6f78ed7a' "$(cd "$(dirname "$(readlink -f "$(command -v codex)")")/.." && pwd)/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex" | sha256sum --check

python -m venv --clear "$ROOT/.crumple/venv"
"$ROOT/.crumple/venv/bin/python" -m pip install --no-deps --no-build-isolation "$ROOT"
rm -rf "$ROOT/.crumple/resources"
install -d "$ROOT/.crumple/resources"
cp -a "$ROOT/contracts" "$ROOT/scenarios" "$ROOT/locks" "$ROOT/receipts" "$ROOT/.crumple/resources/"
RESOURCE_ROOT="$ROOT/.crumple/resources" "$ROOT/.crumple/venv/bin/python" - <<'PY'
import hashlib
import json
import os
from pathlib import Path

root = Path(os.environ["RESOURCE_ROOT"])
files = []
for path in sorted(item for item in root.rglob("*") if item.is_file()):
    files.append({"path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
(root / "install-manifest.json").write_text(json.dumps({"schema_version": "install-manifest.v1", "files": files}, separators=(",", ":"), sort_keys=True) + "\n")
PY
install -d "$HOME/.local/bin"
rm -f "$HOME/.local/bin/crumple"
{
  printf '%s\n' '#!/usr/bin/env bash'
  printf 'exec %q "$@"\n' "$ROOT/.crumple/venv/bin/crumple"
} > "$HOME/.local/bin/crumple"
chmod 0755 "$HOME/.local/bin/crumple"
echo 'CRUMPLE_SETUP_COMPLETE'
