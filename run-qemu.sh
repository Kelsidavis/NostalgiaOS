#!/bin/bash
# Run Nostalgia OS in QEMU

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET_DIR="target"
ESP_DIR="$TARGET_DIR/esp"
# Try to find OVMF firmware
if [ -f "/usr/share/OVMF/OVMF_CODE_4M.snakeoil.fd" ]; then
    OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.snakeoil.fd"
    OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"
elif [ -f "/usr/share/ovmf/OVMF.fd" ]; then
    OVMF_CODE="/usr/share/ovmf/OVMF.fd"
    OVMF_VARS=""
elif [ -f "/usr/share/qemu/OVMF.fd" ]; then
    OVMF_CODE="/usr/share/qemu/OVMF.fd"
    OVMF_VARS=""
elif [ -f "/usr/share/OVMF/OVMF_CODE.fd" ]; then
    OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
    OVMF_VARS="/usr/share/OVMF/OVMF_VARS.fd"
else
    echo "OVMF not found. Install with: sudo apt install ovmf"
    exit 1
fi

# Build first
./build.sh

# Create ESP directory structure
echo "Setting up ESP..."
mkdir -p "$ESP_DIR/EFI/BOOT"
mkdir -p "$ESP_DIR/EFI/nostalgia"

# Copy bootloader (as default UEFI app)
cp "$TARGET_DIR/x86_64-unknown-uefi/release/uefi-loader.efi" \
   "$ESP_DIR/EFI/BOOT/BOOTX64.EFI"

# Copy kernel
cp "$TARGET_DIR/x86_64-unknown-none/release/kernel.bin" \
   "$ESP_DIR/EFI/nostalgia/kernel.bin"

echo ""
echo "Starting QEMU..."
echo ""

# Build QEMU args
# Use 'pc' machine with legacy ISA IDE controller for disk detection
QEMU_ARGS=(
    -machine pc,accel=tcg
    -m 256M
    -drive format=raw,file=fat:rw:"$ESP_DIR"
    -serial stdio
    -no-reboot
)

# Add test disk image if it exists (as IDE primary master on legacy ISA IDE)
if [ -f "disk.img" ]; then
    echo "Adding test disk: disk.img as IDE primary master"
    # Use ISA IDE controller at standard ports 0x1F0/0x170
    QEMU_ARGS+=(-drive file=disk.img,format=raw,if=ide,index=2,media=disk)
fi

# Handle different OVMF configurations
if [ -n "$OVMF_VARS" ]; then
    # Separate CODE and VARS files
    OVMF_VARS_COPY="$TARGET_DIR/OVMF_VARS.fd"
    if [ ! -f "$OVMF_VARS_COPY" ]; then
        cp "$OVMF_VARS" "$OVMF_VARS_COPY"
    fi
    QEMU_ARGS+=(
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE"
        -drive if=pflash,format=raw,file="$OVMF_VARS_COPY"
    )
else
    # Combined OVMF file
    QEMU_ARGS+=(-bios "$OVMF_CODE")
fi

# Run QEMU
qemu-system-x86_64 "${QEMU_ARGS[@]}" "$@"
