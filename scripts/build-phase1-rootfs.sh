#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="$ROOT/.crumple/cache"
BUILD_DIR="$(mktemp -d /tmp/crumple-rootfs.XXXXXX)"
OUTPUT="$CACHE/guest/rootfs-phase1.ext4"
INIT_BINARY="$CACHE/guest/crumple-lifecycle-init"
SOURCE_DATE_EPOCH=1784091600
IMAGE_TMP="$(mktemp /tmp/crumple-rootfs-image.XXXXXX)"

cleanup() {
  rm -rf "$BUILD_DIR"
  rm -f "$IMAGE_TMP"
}
trap cleanup EXIT

install -d "$CACHE/guest" "$BUILD_DIR/sbin" "$BUILD_DIR/proc" "$BUILD_DIR/sys" "$BUILD_DIR/dev" "$BUILD_DIR/run" "$BUILD_DIR/var/lib/crumple"
gcc -Os -static -Wall -Wextra -Werror -o "$INIT_BINARY" "$ROOT/guest/lifecycle_init.c"
install -m 0755 "$INIT_BINARY" "$BUILD_DIR/sbin/crumple-lifecycle-init"
find "$BUILD_DIR" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
truncate -s 64M "$IMAGE_TMP"
E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH" mke2fs -q -t ext4 -F -d "$BUILD_DIR" \
  -L CRUMPLE_ROOT -U 6372756d-706c-6500-0000-000000000001 \
  -E hash_seed=6372756d-706c-6500-0000-000000000001,lazy_itable_init=0,lazy_journal_init=0 \
  "$IMAGE_TMP"
for inode in 13 14 15 16 17 18 19 20 21; do
  debugfs -w -R "set_inode_field <$inode> ctime 20260715050000" "$IMAGE_TMP" >/dev/null 2>&1
  debugfs -w -R "set_inode_field <$inode> uid 0" "$IMAGE_TMP" >/dev/null 2>&1
  debugfs -w -R "set_inode_field <$inode> gid 0" "$IMAGE_TMP" >/dev/null 2>&1
done
install -m 0600 "$IMAGE_TMP" "$OUTPUT"
e2fsck -fn "$OUTPUT"
sha256sum "$INIT_BINARY" "$OUTPUT"
