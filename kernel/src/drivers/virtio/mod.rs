//! VirtIO Drivers
//!
//! VirtIO is a standardized interface for virtual devices.
//! See: https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html

extern crate alloc;

pub mod virtqueue;
pub mod net;

use crate::hal::pci::{PciLocation, pci_read_config_u16, pci_read_config_u32, pci_write_config_u32, config};

/// VirtIO device status bits
pub mod device_status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const DEVICE_NEEDS_RESET: u8 = 64;
    pub const FAILED: u8 = 128;
}

/// VirtIO PCI capability types
pub mod pci_cap {
    pub const COMMON_CFG: u8 = 1;
    pub const NOTIFY_CFG: u8 = 2;
    pub const ISR_CFG: u8 = 3;
    pub const DEVICE_CFG: u8 = 4;
    pub const PCI_CFG: u8 = 5;
}

/// VirtIO network device feature bits
pub mod net_features {
    pub const CSUM: u64 = 1 << 0;          // Checksum offload
    pub const GUEST_CSUM: u64 = 1 << 1;    // Guest handles partial csum
    pub const MAC: u64 = 1 << 5;           // Device has MAC
    pub const GSO: u64 = 1 << 6;           // Generic segmentation offload
    pub const GUEST_TSO4: u64 = 1 << 7;    // Guest can receive TSOv4
    pub const GUEST_TSO6: u64 = 1 << 8;    // Guest can receive TSOv6
    pub const GUEST_ECN: u64 = 1 << 9;     // Guest can receive TSO with ECN
    pub const GUEST_UFO: u64 = 1 << 10;    // Guest can receive UFO
    pub const HOST_TSO4: u64 = 1 << 11;    // Device can receive TSOv4
    pub const HOST_TSO6: u64 = 1 << 12;    // Device can receive TSOv6
    pub const HOST_ECN: u64 = 1 << 13;     // Device can receive TSO with ECN
    pub const HOST_UFO: u64 = 1 << 14;     // Device can receive UFO
    pub const MRG_RXBUF: u64 = 1 << 15;    // Merge rx buffers
    pub const STATUS: u64 = 1 << 16;       // Configuration status
    pub const CTRL_VQ: u64 = 1 << 17;      // Control virtqueue
    pub const CTRL_RX: u64 = 1 << 18;      // Control RX mode
    pub const CTRL_VLAN: u64 = 1 << 19;    // Control VLAN filtering
    pub const CTRL_RX_EXTRA: u64 = 1 << 20;// Extra RX mode control
    pub const GUEST_ANNOUNCE: u64 = 1 << 21;// Guest can announce
    pub const MQ: u64 = 1 << 22;           // Multiqueue
    pub const CTRL_MAC_ADDR: u64 = 1 << 23;// MAC address control
}

/// VirtIO version 1 feature bits
pub mod virtio_features {
    pub const VERSION_1: u64 = 1 << 32;    // VirtIO 1.0 compliant
    pub const ACCESS_PLATFORM: u64 = 1 << 33;
    pub const RING_PACKED: u64 = 1 << 34;
    pub const IN_ORDER: u64 = 1 << 35;
    pub const ORDER_PLATFORM: u64 = 1 << 36;
    pub const SR_IOV: u64 = 1 << 37;
    pub const NOTIFICATION_DATA: u64 = 1 << 38;
}

/// VirtIO PCI capability header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtioPciCap {
    pub cap_vndr: u8,      // Generic PCI field: capability ID (0x09)
    pub cap_next: u8,      // Generic PCI field: next capability
    pub cap_len: u8,       // Length of this capability structure
    pub cfg_type: u8,      // Type of structure (pci_cap::*)
    pub bar: u8,           // BAR index
    pub padding: [u8; 3],
    pub offset: u32,       // Offset within BAR
    pub length: u32,       // Length of structure
}

/// VirtIO legacy I/O offsets
pub mod legacy_io {
    pub const DEVICE_FEATURES: u16 = 0;
    pub const GUEST_FEATURES: u16 = 4;
    pub const QUEUE_ADDRESS: u16 = 8;
    pub const QUEUE_SIZE: u16 = 12;
    pub const QUEUE_SELECT: u16 = 14;
    pub const QUEUE_NOTIFY: u16 = 16;
    pub const DEVICE_STATUS: u16 = 18;
    pub const ISR_STATUS: u16 = 19;
    // Network-specific (starts at 20)
    pub const NET_MAC: u16 = 20;
    pub const NET_STATUS: u16 = 26;
}

/// VirtIO device transport (legacy I/O based)
pub struct VirtioTransport {
    /// PCI location
    pub location: PciLocation,
    /// I/O port base
    pub io_base: u16,
    /// Device features
    pub device_features: u64,
    /// Negotiated features
    pub features: u64,
}

impl VirtioTransport {
    /// Create a new transport from PCI location
    pub fn new(loc: PciLocation) -> Option<Self> {
        // Get BAR0 for legacy devices
        let bar0 = pci_read_config_u32(loc, config::BAR0);

        // Legacy devices use I/O BAR
        if (bar0 & 1) == 0 {
            crate::serial_println!("[VIRTIO] BAR0 is not I/O space, modern device?");
            return None;
        }

        let io_base = (bar0 & 0xFFFFFFFC) as u16;
        crate::serial_println!("[VIRTIO] I/O base: {:#06X}", io_base);

        // Enable bus mastering
        crate::hal::pci::pci_enable_bus_master(loc);

        Some(Self {
            location: loc,
            io_base,
            device_features: 0,
            features: 0,
        })
    }

    /// Read device status
    pub fn read_status(&self) -> u8 {
        unsafe {
            x86_64::instructions::port::Port::new(self.io_base + legacy_io::DEVICE_STATUS).read()
        }
    }

    /// Write device status
    pub fn write_status(&self, status: u8) {
        unsafe {
            x86_64::instructions::port::Port::new(self.io_base + legacy_io::DEVICE_STATUS).write(status);
        }
    }

    /// Reset device
    pub fn reset(&mut self) {
        self.write_status(0);
        // Wait for reset to complete
        while self.read_status() != 0 {
            core::hint::spin_loop();
        }
    }

    /// Read device features
    pub fn read_device_features(&mut self) -> u64 {
        unsafe {
            let low: u32 = x86_64::instructions::port::Port::new(self.io_base + legacy_io::DEVICE_FEATURES).read();
            self.device_features = low as u64;
            low as u64
        }
    }

    /// Write guest features
    pub fn write_guest_features(&mut self, features: u64) {
        self.features = features;
        unsafe {
            x86_64::instructions::port::Port::new(self.io_base + legacy_io::GUEST_FEATURES)
                .write(features as u32);
        }
    }

    /// Select a virtqueue
    pub fn queue_select(&self, queue: u16) {
        unsafe {
            x86_64::instructions::port::Port::new(self.io_base + legacy_io::QUEUE_SELECT)
                .write(queue);
        }
    }

    /// Get queue size
    pub fn queue_size(&self) -> u16 {
        unsafe {
            x86_64::instructions::port::Port::new(self.io_base + legacy_io::QUEUE_SIZE).read()
        }
    }

    /// Set queue address (page frame number)
    pub fn queue_set_pfn(&self, pfn: u32) {
        unsafe {
            x86_64::instructions::port::Port::new(self.io_base + legacy_io::QUEUE_ADDRESS)
                .write(pfn);
        }
    }

    /// Notify device about available buffers
    pub fn queue_notify(&self, queue: u16) {
        unsafe {
            x86_64::instructions::port::Port::new(self.io_base + legacy_io::QUEUE_NOTIFY)
                .write(queue);
        }
    }

    /// Read ISR status
    pub fn read_isr(&self) -> u8 {
        unsafe {
            x86_64::instructions::port::Port::new(self.io_base + legacy_io::ISR_STATUS).read()
        }
    }

    /// Read MAC address (network devices)
    pub fn read_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        unsafe {
            for i in 0..6 {
                mac[i] = x86_64::instructions::port::Port::new(self.io_base + legacy_io::NET_MAC + i as u16).read();
            }
        }
        mac
    }

    /// Initialize device (perform feature negotiation and setup)
    pub fn init(&mut self) -> Result<(), &'static str> {
        // Reset device
        self.reset();

        // Acknowledge device
        self.write_status(device_status::ACKNOWLEDGE);

        // We're a driver
        self.write_status(device_status::ACKNOWLEDGE | device_status::DRIVER);

        // Read features
        let features = self.read_device_features();
        crate::serial_println!("[VIRTIO] Device features: {:#010X}", features);

        // Select simple features for now
        let our_features = net_features::MAC;
        self.write_guest_features(our_features);

        Ok(())
    }

    /// Complete initialization
    pub fn driver_ok(&self) {
        self.write_status(
            device_status::ACKNOWLEDGE |
            device_status::DRIVER |
            device_status::DRIVER_OK
        );
    }
}

/// Initialize VirtIO subsystem
pub fn init() {
    crate::serial_println!("[VIRTIO] VirtIO subsystem initialized");
}
