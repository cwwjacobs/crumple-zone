#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="$ROOT/.crumple/cache"
BUILD_DIR="$(mktemp -d /tmp/crumple-phase3-rootfs.XXXXXX)"
IMAGE_TMP="$(mktemp /tmp/crumple-phase3-image.XXXXXX)"
OUTPUT="$CACHE/guest/rootfs-phase3.ext4"
SOURCE_DATE_EPOCH=1784091600
CODEX_ENTRY="$(readlink -f "$(command -v codex)")"
CODEX_PACKAGE_ROOT="$(cd "$(dirname "$CODEX_ENTRY")/.." && pwd)"
CODEX_VENDOR="$CODEX_PACKAGE_ROOT/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl"

cleanup() {
  rm -rf "$BUILD_DIR"
  rm -f "$IMAGE_TMP"
}
trap cleanup EXIT

install -d "$CACHE/guest" "$BUILD_DIR/sbin" "$BUILD_DIR/proc" "$BUILD_DIR/sys" "$BUILD_DIR/dev" "$BUILD_DIR/run" "$BUILD_DIR/workspace" \
  "$BUILD_DIR/opt/codex/bin" "$BUILD_DIR/opt/codex/codex-resources" "$BUILD_DIR/opt/codex/codex-path" \
  "$BUILD_DIR/opt/crumple/skills/prompt-injection-observer"

gcc -Os -static -Wall -Wextra -Werror -o "$CACHE/guest/crumple-phase3-init" "$ROOT/guest/phase3_init.c"
gcc -Os -static -Wall -Wextra -Werror -o "$CACHE/guest/crumple-http-forwarder" "$ROOT/guest/http_vsock_forwarder.c"
gcc -Os -static -Wall -Wextra -Werror -o "$CACHE/guest/crumple-mcp-proxy" "$ROOT/guest/mcp_vsock_proxy.c"
install -m 0755 "$CACHE/guest/crumple-phase3-init" "$BUILD_DIR/sbin/crumple-phase3-init"
install -m 0755 "$CACHE/guest/crumple-http-forwarder" "$BUILD_DIR/sbin/crumple-http-forwarder"
install -m 0755 "$CACHE/guest/crumple-mcp-proxy" "$BUILD_DIR/sbin/crumple-mcp-proxy"
install -m 0755 "$CODEX_VENDOR/bin/codex" "$BUILD_DIR/opt/codex/bin/codex"
install -m 0755 "$CODEX_VENDOR/codex-resources/bwrap" "$BUILD_DIR/opt/codex/codex-resources/bwrap"
install -m 0755 "$CODEX_VENDOR/codex-path/rg" "$BUILD_DIR/opt/codex/codex-path/rg"
install -m 0644 "$ROOT/guest/skills/prompt-injection-observer/SKILL.md" "$BUILD_DIR/opt/crumple/skills/prompt-injection-observer/SKILL.md"
find "$BUILD_DIR" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

truncate -s 512M "$IMAGE_TMP"
E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH" mke2fs -q -t ext4 -F -d "$BUILD_DIR" \
  -L CRUMPLE_P3 -U 6372756d-706c-6500-0000-000000000003 \
  -E hash_seed=6372756d-706c-6500-0000-000000000003,lazy_itable_init=0,lazy_journal_init=0 \
  "$IMAGE_TMP"

for path in /dev /proc /run /sbin /sys /workspace /opt /opt/codex /opt/codex/bin /opt/codex/codex-resources /opt/codex/codex-path /opt/crumple /opt/crumple/skills /opt/crumple/skills/prompt-injection-observer \
  /sbin/crumple-phase3-init /sbin/crumple-http-forwarder /sbin/crumple-mcp-proxy /opt/codex/bin/codex /opt/codex/codex-resources/bwrap /opt/codex/codex-path/rg /opt/crumple/skills/prompt-injection-observer/SKILL.md; do
  debugfs -w -R "set_inode_field $path ctime 20260715050000" "$IMAGE_TMP" >/dev/null 2>&1
  debugfs -w -R "set_inode_field $path uid 0" "$IMAGE_TMP" >/dev/null 2>&1
  debugfs -w -R "set_inode_field $path gid 0" "$IMAGE_TMP" >/dev/null 2>&1
done

install -m 0600 "$IMAGE_TMP" "$OUTPUT"
e2fsck -fn "$OUTPUT"
sha256sum "$CACHE/guest/crumple-phase3-init" "$CACHE/guest/crumple-http-forwarder" "$CACHE/guest/crumple-mcp-proxy" "$OUTPUT"
