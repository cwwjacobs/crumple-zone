#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="$ROOT/.crumple/cache"
FC_DIR="$CACHE/firecracker/v1.16.1"
KERNEL_DIR="$CACHE/kernel/6.1.176"
FC_ARCHIVE="$CACHE/downloads/firecracker-v1.16.1-x86_64.tgz"

install -d "$CACHE/downloads" "$FC_DIR" "$KERNEL_DIR"

curl --fail --silent --show-error --location --output "$FC_ARCHIVE" \
  "https://github.com/firecracker-microvm/firecracker/releases/download/v1.16.1/firecracker-v1.16.1-x86_64.tgz"
printf '%s  %s\n' "382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6" "$FC_ARCHIVE" | sha256sum --check
tar -xzf "$FC_ARCHIVE" -C "$FC_DIR" --strip-components=1

curl --fail --silent --show-error --location --output "$KERNEL_DIR/vmlinux-6.1.176" \
  "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260715-1faca2f70e7a-0/x86_64/vmlinux-6.1.176"
printf '%s  %s\n' "b20af7585283b051f16f6ece46e7064165054efe112c4ab0e26a06ff8ebe9da4" "$KERNEL_DIR/vmlinux-6.1.176" | sha256sum --check

curl --fail --silent --show-error --location --output "$KERNEL_DIR/vmlinux-6.1.176.config" \
  "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260715-1faca2f70e7a-0/x86_64/vmlinux-6.1.176.config"
printf '%s  %s\n' "d15b2004a8a46054bc55faed515578419f46a0e973f5d62fb8400d030ea6fa1f" "$KERNEL_DIR/vmlinux-6.1.176.config" | sha256sum --check

"$ROOT/scripts/build-phase1-rootfs.sh"
printf '%s  %s\n' "b7f9bd4ca18698355c86572fe3803aff22ecbe2cebecd02b9e53577211ba7e7f" "$CACHE/guest/crumple-lifecycle-init" | sha256sum --check
printf '%s  %s\n' "3f77696fe97adc47ecd9c114b82d04f46994f028e4ca8b677cd0f1b39b2ab537" "$CACHE/guest/rootfs-phase1.ext4" | sha256sum --check
