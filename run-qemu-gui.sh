#!/bin/bash
# Run Nostalgia OS in QEMU with graphical display

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET_DIR="target"
ESP_DIR="$TARGET_DIR/esp"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.snakeoil.fd"
OVMF_VARS_SRC="/usr/share/OVMF/OVMF_VARS_4M.fd"
OVMF_VARS_COPY="$TARGET_DIR/OVMF_VARS.fd"

# Check for OVMF firmware
if [ ! -f "$OVMF_CODE" ]; then
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

# Copy kernel (ELF format required by bootloader)
cp "$TARGET_DIR/x86_64-unknown-none/release/kernel" \
   "$ESP_DIR/EFI/nostalgia/kernel.bin"

# Create a fresh copy of OVMF_VARS (for UEFI variable storage)
if [ ! -f "$OVMF_VARS_COPY" ]; then
    echo "Creating OVMF variables file..."
    cp "$OVMF_VARS_SRC" "$OVMF_VARS_COPY"
fi

echo ""
echo "Starting QEMU with graphical display..."
echo "Serial output will appear in this terminal"
echo ""

# Run QEMU with graphical display
qemu-system-x86_64 \
    -machine q35 \
    -m 256M \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$OVMF_VARS_COPY" \
    -drive format=raw,file=fat:rw:"$ESP_DIR" \
    -serial stdio \
    -no-reboot \
    "$@"
