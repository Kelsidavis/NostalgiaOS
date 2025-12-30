//! PCI Bus Access
//!
//! Provides low-level PCI configuration space access functions.

extern crate alloc;

use x86_64::instructions::port::Port;

/// PCI configuration address port
pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
/// PCI configuration data port
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

/// PCI configuration registers
pub mod config {
    pub const VENDOR_ID: u8 = 0x00;
    pub const DEVICE_ID: u8 = 0x02;
    pub const COMMAND: u8 = 0x04;
    pub const STATUS: u8 = 0x06;
    pub const REVISION_ID: u8 = 0x08;
    pub const PROG_IF: u8 = 0x09;
    pub const SUBCLASS: u8 = 0x0A;
    pub const CLASS_CODE: u8 = 0x0B;
    pub const CACHE_LINE_SIZE: u8 = 0x0C;
    pub const LATENCY_TIMER: u8 = 0x0D;
    pub const HEADER_TYPE: u8 = 0x0E;
    pub const BIST: u8 = 0x0F;
    pub const BAR0: u8 = 0x10;
    pub const BAR1: u8 = 0x14;
    pub const BAR2: u8 = 0x18;
    pub const BAR3: u8 = 0x1C;
    pub const BAR4: u8 = 0x20;
    pub const BAR5: u8 = 0x24;
    pub const SUBSYSTEM_VENDOR_ID: u8 = 0x2C;
    pub const SUBSYSTEM_ID: u8 = 0x2E;
    pub const EXPANSION_ROM: u8 = 0x30;
    pub const CAPABILITIES_PTR: u8 = 0x34;
    pub const INTERRUPT_LINE: u8 = 0x3C;
    pub const INTERRUPT_PIN: u8 = 0x3D;
}

/// PCI command register bits
pub mod command {
    pub const IO_SPACE: u16 = 0x0001;
    pub const MEMORY_SPACE: u16 = 0x0002;
    pub const BUS_MASTER: u16 = 0x0004;
    pub const INTERRUPT_DISABLE: u16 = 0x0400;
}

/// PCI capability IDs
pub mod capability {
    pub const MSI: u8 = 0x05;
    pub const VENDOR_SPECIFIC: u8 = 0x09;
    pub const MSIX: u8 = 0x11;
}

/// VirtIO vendor ID
pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;

/// VirtIO device IDs (modern)
pub mod virtio_device {
    pub const NETWORK: u16 = 0x1041;
    pub const BLOCK: u16 = 0x1042;
    pub const CONSOLE: u16 = 0x1043;
    pub const ENTROPY: u16 = 0x1044;
    pub const BALLOON: u16 = 0x1045;
    pub const SCSI: u16 = 0x1048;
    pub const GPU: u16 = 0x1050;
    pub const INPUT: u16 = 0x1052;
}

/// VirtIO transitional device IDs (legacy)
pub mod virtio_legacy {
    pub const NETWORK: u16 = 0x1000;
    pub const BLOCK: u16 = 0x1001;
    pub const BALLOON: u16 = 0x1002;
    pub const CONSOLE: u16 = 0x1003;
    pub const SCSI: u16 = 0x1004;
    pub const ENTROPY: u16 = 0x1005;
    pub const GPU: u16 = 0x1040;
}

/// PCI device location
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciLocation {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciLocation {
    pub fn new(bus: u8, device: u8, function: u8) -> Self {
        Self { bus, device, function }
    }

    /// Generate configuration space address
    fn config_address(&self, offset: u8) -> u32 {
        0x80000000
            | ((self.bus as u32) << 16)
            | ((self.device as u32) << 11)
            | ((self.function as u32) << 8)
            | ((offset as u32) & 0xFC)
    }
}

/// Read 8-bit value from PCI config space
pub fn pci_read_config_u8(loc: PciLocation, offset: u8) -> u8 {
    let value = pci_read_config_u32(loc, offset & 0xFC);
    ((value >> ((offset & 3) * 8)) & 0xFF) as u8
}

/// Read 16-bit value from PCI config space
pub fn pci_read_config_u16(loc: PciLocation, offset: u8) -> u16 {
    let value = pci_read_config_u32(loc, offset & 0xFC);
    ((value >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

/// Read 32-bit value from PCI config space
pub fn pci_read_config_u32(loc: PciLocation, offset: u8) -> u32 {
    unsafe {
        let mut addr_port: Port<u32> = Port::new(PCI_CONFIG_ADDRESS);
        let mut data_port: Port<u32> = Port::new(PCI_CONFIG_DATA);
        addr_port.write(loc.config_address(offset));
        data_port.read()
    }
}

/// Write 8-bit value to PCI config space
pub fn pci_write_config_u8(loc: PciLocation, offset: u8, value: u8) {
    let old = pci_read_config_u32(loc, offset & 0xFC);
    let shift = (offset & 3) * 8;
    let mask = !(0xFF << shift);
    let new = (old & mask) | ((value as u32) << shift);
    pci_write_config_u32(loc, offset & 0xFC, new);
}

/// Write 16-bit value to PCI config space
pub fn pci_write_config_u16(loc: PciLocation, offset: u8, value: u16) {
    let old = pci_read_config_u32(loc, offset & 0xFC);
    let shift = (offset & 2) * 8;
    let mask = !(0xFFFF << shift);
    let new = (old & mask) | ((value as u32) << shift);
    pci_write_config_u32(loc, offset & 0xFC, new);
}

/// Write 32-bit value to PCI config space
pub fn pci_write_config_u32(loc: PciLocation, offset: u8, value: u32) {
    unsafe {
        let mut addr_port: Port<u32> = Port::new(PCI_CONFIG_ADDRESS);
        let mut data_port: Port<u32> = Port::new(PCI_CONFIG_DATA);
        addr_port.write(loc.config_address(offset));
        data_port.write(value);
    }
}

/// Enable bus mastering for a device
pub fn pci_enable_bus_master(loc: PciLocation) {
    let cmd = pci_read_config_u16(loc, config::COMMAND);
    pci_write_config_u16(loc, config::COMMAND, cmd | command::BUS_MASTER | command::MEMORY_SPACE);
}

/// Get BAR (Base Address Register) value
pub fn pci_get_bar(loc: PciLocation, bar: u8) -> Option<PciBar> {
    if bar > 5 {
        return None;
    }

    let offset = config::BAR0 + bar * 4;
    let value = pci_read_config_u32(loc, offset);

    if value == 0 {
        return None;
    }

    // Check if it's I/O or memory
    if value & 1 != 0 {
        // I/O BAR
        Some(PciBar::Io {
            port: (value & 0xFFFFFFFC) as u16,
        })
    } else {
        // Memory BAR
        let prefetchable = (value & 0x08) != 0;
        let bar_type = (value >> 1) & 0x03;

        // Get size by writing all 1s and reading back
        pci_write_config_u32(loc, offset, 0xFFFFFFFF);
        let size_mask = pci_read_config_u32(loc, offset);
        pci_write_config_u32(loc, offset, value); // Restore

        let size = if size_mask == 0 {
            0
        } else {
            !((size_mask & 0xFFFFFFF0) - 1) as u64 + 1
        };

        let address = if bar_type == 2 {
            // 64-bit BAR
            let high = pci_read_config_u32(loc, offset + 4);
            ((high as u64) << 32) | ((value & 0xFFFFFFF0) as u64)
        } else {
            (value & 0xFFFFFFF0) as u64
        };

        Some(PciBar::Memory {
            address,
            size,
            prefetchable,
            is_64bit: bar_type == 2,
        })
    }
}

/// PCI Base Address Register
#[derive(Debug, Clone, Copy)]
pub enum PciBar {
    Io { port: u16 },
    Memory { address: u64, size: u64, prefetchable: bool, is_64bit: bool },
}

impl PciBar {
    pub fn address(&self) -> u64 {
        match self {
            PciBar::Io { port } => *port as u64,
            PciBar::Memory { address, .. } => *address,
        }
    }
}

/// Find a PCI capability
pub fn pci_find_capability(loc: PciLocation, cap_id: u8) -> Option<u8> {
    // Check if device has capabilities
    let status = pci_read_config_u16(loc, config::STATUS);
    if (status & 0x10) == 0 {
        return None; // No capabilities list
    }

    let mut offset = pci_read_config_u8(loc, config::CAPABILITIES_PTR) & 0xFC;

    while offset != 0 {
        let id = pci_read_config_u8(loc, offset);
        if id == cap_id {
            return Some(offset);
        }
        offset = pci_read_config_u8(loc, offset + 1) & 0xFC;
    }

    None
}

/// Scan for VirtIO network devices
pub fn find_virtio_net_devices() -> alloc::vec::Vec<PciLocation> {
    let mut devices = alloc::vec::Vec::new();

    for bus in 0..=255u8 {
        for device in 0..32u8 {
            for function in 0..8u8 {
                let loc = PciLocation::new(bus, device, function);
                let vendor = pci_read_config_u16(loc, config::VENDOR_ID);

                if vendor == 0xFFFF {
                    continue;
                }

                if vendor == VIRTIO_VENDOR_ID {
                    let device_id = pci_read_config_u16(loc, config::DEVICE_ID);

                    // Check for network device (legacy or modern)
                    if device_id == virtio_legacy::NETWORK || device_id == virtio_device::NETWORK {
                        devices.push(loc);
                        crate::serial_println!(
                            "[PCI] Found VirtIO Network at {:02X}:{:02X}.{} (device_id={:#06X})",
                            bus, device, function, device_id
                        );
                    }
                }

                // Only check function 0 if not multifunction
                if function == 0 {
                    let header_type = pci_read_config_u8(loc, config::HEADER_TYPE);
                    if (header_type & 0x80) == 0 {
                        break; // Not multifunction, skip other functions
                    }
                }
            }
        }
    }

    devices
}

/// Initialize PCI subsystem
pub fn init() {
    crate::serial_println!("[PCI] PCI subsystem initialized");
}
