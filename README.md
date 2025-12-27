# Nostalgia OS

An x86_64 operating system kernel written in Rust.

## Features

### Core Subsystems

- **Memory Manager (MM)**: PFN database, pool allocator, virtual address descriptors, user-mode page tables
- **Object Manager (OB)**: Hierarchical namespace, handle tables, object types
- **Process Manager (PS)**: Process and thread management, CID table
- **I/O Manager (IO)**: IRP-based driver model, device and driver objects
- **Security Reference Monitor (SE)**: SIDs, ACLs, tokens, privileges, access checks
- **Configuration Manager (CM)**: Registry-style hives and keys
- **Kernel Executive (KE)**: Scheduler, timers, APCs, DPCs, synchronization primitives

### Hardware Support

- x86_64 architecture (GDT, IDT, TSS)
- UEFI bootloader
- LAPIC timer (1000 Hz)
- ATA/IDE disk driver
- Serial console (COM1)
- Framebuffer graphics

### File System

- FAT32 driver with full read/write support
- VFS layer with mount point manager
- File operations: create, read, write, delete, rename, truncate, stat, sync
- Directory operations: mkdir, rmdir, readdir

### Execution Model

- Ring 0 / Ring 3 separation
- SYSCALL/SYSRET for user mode transitions
- Priority-based preemptive scheduler (32 priority levels)
- Multi-object wait support (WaitForSingleObject, WaitForMultipleObjects)

## Building

### Prerequisites

- Rust nightly toolchain
- QEMU with OVMF (UEFI firmware)

```bash
# Install Rust nightly
rustup install nightly
rustup default nightly

# Install required components
rustup component add rust-src llvm-tools-preview

# Install QEMU and OVMF (Ubuntu/Debian)
sudo apt install qemu-system-x86 ovmf
```

### Build

```bash
./build.sh
```

### Run

```bash
./run-qemu.sh
```

## Project Structure

```
NostalgiaOS/
├── boot/
│   └── uefi-loader/       # UEFI bootloader
├── kernel/
│   └── src/
│       ├── arch/          # Architecture-specific code (x86_64)
│       ├── cm/            # Configuration Manager (registry)
│       ├── fs/            # File systems (FAT32, VFS)
│       ├── hal/           # Hardware Abstraction Layer (APIC, ATA)
│       ├── io/            # I/O Manager (IRP, devices, drivers)
│       ├── ke/            # Kernel Executive (scheduler, sync)
│       ├── mm/            # Memory Manager
│       ├── ob/            # Object Manager
│       ├── ps/            # Process Manager
│       ├── rtl/           # Runtime Library
│       └── se/            # Security Reference Monitor
├── build.sh               # Build script
└── run-qemu.sh            # QEMU launch script
```

## License

This project is for educational purposes.
