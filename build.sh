#!/bin/bash
# Build script for Nostalgia OS

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET_DIR="target"
RELEASE_DIR="$TARGET_DIR/release"

echo "Building Nostalgia OS..."

# Build bootloader
echo "[1/3] Building UEFI bootloader..."
cargo build --package uefi-loader --target x86_64-unknown-uefi --release

# Build kernel
echo "[2/3] Building kernel..."
cargo build --package kernel --target x86_64-unknown-none --release

# Convert kernel to flat binary
echo "[3/3] Creating kernel binary..."
objcopy -O binary \
    "$TARGET_DIR/x86_64-unknown-none/release/kernel" \
    "$TARGET_DIR/x86_64-unknown-none/release/kernel.bin"

echo ""
echo "Build complete!"
echo "  Bootloader: $TARGET_DIR/x86_64-unknown-uefi/release/uefi-loader.efi"
echo "  Kernel:     $TARGET_DIR/x86_64-unknown-none/release/kernel.bin"
