//! HAL Bus Interface Support
//!
//! Provides unified bus abstraction for device drivers:
//!
//! - **Bus Types**: PCI, ISA, USB, ACPI, etc.
//! - **Resource Query**: I/O ports, memory ranges, IRQs, DMA
//! - **Configuration**: Bus-specific configuration access
//! - **Slot Information**: Device location on bus
//!
//! # NT Functions
//!
//! - `HalGetBusData` - Read bus configuration
//! - `HalSetBusData` - Write bus configuration
//! - `HalTranslateBusAddress` - Translate bus to physical address
//! - `HalGetInterruptVector` - Get system interrupt for bus IRQ
//!
//! # Usage
//!
//! ```ignore
//! // Query PCI configuration
//! let data = hal_get_bus_data(
//!     BusType::Pci,
//!     bus_number,
//!     slot,
//!     offset,
//! );
//!
//! // Translate bus address
//! let phys = hal_translate_bus_address(
//!     BusType::Pci,
//!     bus_number,
//!     bus_address,
//! );
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;

/// Maximum buses per type
pub const MAX_BUSES: usize = 256;

/// Bus types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BusType {
    /// Internal/platform bus
    #[default]
    Internal = 0,
    /// ISA bus
    Isa = 1,
    /// EISA bus
    Eisa = 2,
    /// MicroChannel (MCA)
    MicroChannel = 3,
    /// TurboChannel
    TurboChannel = 4,
    /// PCI bus
    Pci = 5,
    /// VMEbus
    Vme = 6,
    /// NuBus
    NuBus = 7,
    /// PCMCIA
    Pcmcia = 8,
    /// C-Bus
    CBus = 9,
    /// MPI bus
    Mpi = 10,
    /// MPSA bus
    Mpsa = 11,
    /// Processor internal
    ProcessorInternal = 12,
    /// PnP ISA
    PnpIsa = 13,
    /// PnP bus
    PnpBus = 14,
    /// Maximum bus type
    MaxBus = 15,
}

impl BusType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Internal,
            1 => Self::Isa,
            2 => Self::Eisa,
            3 => Self::MicroChannel,
            4 => Self::TurboChannel,
            5 => Self::Pci,
            6 => Self::Vme,
            7 => Self::NuBus,
            8 => Self::Pcmcia,
            9 => Self::CBus,
            10 => Self::Mpi,
            11 => Self::Mpsa,
            12 => Self::ProcessorInternal,
            13 => Self::PnpIsa,
            14 => Self::PnpBus,
            _ => Self::MaxBus,
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Internal => "Internal",
            Self::Isa => "ISA",
            Self::Eisa => "EISA",
            Self::MicroChannel => "MicroChannel",
            Self::TurboChannel => "TurboChannel",
            Self::Pci => "PCI",
            Self::Vme => "VME",
            Self::NuBus => "NuBus",
            Self::Pcmcia => "PCMCIA",
            Self::CBus => "C-Bus",
            Self::Mpi => "MPI",
            Self::Mpsa => "MPSA",
            Self::ProcessorInternal => "ProcessorInternal",
            Self::PnpIsa => "PnP ISA",
            Self::PnpBus => "PnP Bus",
            Self::MaxBus => "Unknown",
        }
    }
}

/// Bus data type for configuration access
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BusDataType {
    /// PCI configuration space
    #[default]
    ConfigurationSpaceUndefined = 0,
    /// CMOS/RTC data
    Cmos = 1,
    /// EISA slot info
    EisaSlotInformation = 2,
    /// CMOS extended
    CmosAttrEntry = 3,
    /// PCI slot info
    PciSlotInformation = 4,
    /// SMBIOS data
    Smbios = 5,
    /// ACPI data
    Acpi = 6,
}

/// PCI slot number encoding
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PciSlotNumber {
    /// Device number (0-31)
    pub device_number: u8,
    /// Function number (0-7)
    pub function_number: u8,
    /// Reserved
    pub reserved: u16,
}

impl PciSlotNumber {
    pub const fn new(device: u8, function: u8) -> Self {
        Self {
            device_number: device,
            function_number: function,
            reserved: 0,
        }
    }

    /// Convert to u32 for compatibility
    pub fn as_u32(&self) -> u32 {
        (self.device_number as u32) | ((self.function_number as u32) << 8)
    }

    /// Create from u32
    pub fn from_u32(value: u32) -> Self {
        Self {
            device_number: (value & 0xFF) as u8,
            function_number: ((value >> 8) & 0xFF) as u8,
            reserved: 0,
        }
    }
}

/// Bus address (for translation)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BusAddress {
    /// Low 32 bits
    pub low_part: u32,
    /// High 32 bits
    pub high_part: u32,
}

impl BusAddress {
    pub const fn new(address: u64) -> Self {
        Self {
            low_part: address as u32,
            high_part: (address >> 32) as u32,
        }
    }

    pub fn as_u64(&self) -> u64 {
        (self.low_part as u64) | ((self.high_part as u64) << 32)
    }
}

/// Address space type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressSpace {
    /// Memory space
    #[default]
    Memory = 0,
    /// I/O port space
    Io = 1,
    /// Bus-specific space
    BusSpecific = 2,
}

/// Bus information
#[derive(Debug, Clone, Copy, Default)]
pub struct BusInfo {
    /// Bus type
    pub bus_type: BusType,
    /// Bus number
    pub bus_number: u32,
    /// Is bus present
    pub present: bool,
    /// Number of slots/devices
    pub slot_count: u32,
    /// Bus capabilities
    pub capabilities: u32,
}

/// Slot information
#[derive(Debug, Clone, Copy, Default)]
pub struct SlotInfo {
    /// Bus type
    pub bus_type: BusType,
    /// Bus number
    pub bus_number: u32,
    /// Slot number
    pub slot_number: u32,
    /// Device is present
    pub device_present: bool,
    /// Vendor ID (for PCI)
    pub vendor_id: u16,
    /// Device ID (for PCI)
    pub device_id: u16,
    /// Class code
    pub class_code: u32,
    /// Interrupt line
    pub interrupt_line: u8,
    /// Interrupt pin
    pub interrupt_pin: u8,
}

/// Resource descriptor
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceDescriptor {
    /// Resource type
    pub resource_type: ResourceType,
    /// Start address/port
    pub start: u64,
    /// Length
    pub length: u64,
    /// Flags
    pub flags: u32,
}

/// Resource types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourceType {
    #[default]
    Null = 0,
    Port = 1,
    Memory = 3,
    Interrupt = 2,
    Dma = 4,
    DeviceSpecific = 5,
    BusNumber = 6,
}

// ============================================================================
// Bus Registry
// ============================================================================

struct BusEntry {
    info: BusInfo,
    valid: bool,
}

impl Default for BusEntry {
    fn default() -> Self {
        Self {
            info: BusInfo::default(),
            valid: false,
        }
    }
}

static mut BUS_REGISTRY: [[BusEntry; MAX_BUSES]; 16] = {
    const INIT_ENTRY: BusEntry = BusEntry {
        info: BusInfo {
            bus_type: BusType::Internal,
            bus_number: 0,
            present: false,
            slot_count: 0,
            capabilities: 0,
        },
        valid: false,
    };
    const INIT_ARRAY: [BusEntry; MAX_BUSES] = [INIT_ENTRY; MAX_BUSES];
    [INIT_ARRAY; 16]
};

static BUS_LOCK: SpinLock<()> = SpinLock::new(());
static BUS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static BUS_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Bus Data Access
// ============================================================================

/// Read bus configuration data
///
/// Returns the number of bytes read
pub fn hal_get_bus_data(
    bus_type: BusType,
    bus_number: u32,
    slot_number: u32,
    buffer: &mut [u8],
    offset: u32,
) -> u32 {
    match bus_type {
        BusType::Pci => hal_get_pci_data(bus_number, slot_number, buffer, offset),
        BusType::Isa => hal_get_isa_data(bus_number, slot_number, buffer, offset),
        _ => 0,
    }
}

/// Write bus configuration data
///
/// Returns the number of bytes written
pub fn hal_set_bus_data(
    bus_type: BusType,
    bus_number: u32,
    slot_number: u32,
    buffer: &[u8],
    offset: u32,
) -> u32 {
    match bus_type {
        BusType::Pci => hal_set_pci_data(bus_number, slot_number, buffer, offset),
        _ => 0,
    }
}

/// Read PCI configuration data
fn hal_get_pci_data(
    bus: u32,
    slot: u32,
    buffer: &mut [u8],
    offset: u32,
) -> u32 {
    let slot_info = PciSlotNumber::from_u32(slot);
    let device = slot_info.device_number;
    let function = slot_info.function_number;

    let mut bytes_read = 0u32;

    for (i, byte) in buffer.iter_mut().enumerate() {
        let reg_offset = offset + i as u32;
        if reg_offset >= 256 {
            break;
        }

        *byte = pci_read_config_byte(bus as u8, device, function, reg_offset as u8);
        bytes_read += 1;
    }

    bytes_read
}

/// Write PCI configuration data
fn hal_set_pci_data(
    bus: u32,
    slot: u32,
    buffer: &[u8],
    offset: u32,
) -> u32 {
    let slot_info = PciSlotNumber::from_u32(slot);
    let device = slot_info.device_number;
    let function = slot_info.function_number;

    let mut bytes_written = 0u32;

    for (i, &byte) in buffer.iter().enumerate() {
        let reg_offset = offset + i as u32;
        if reg_offset >= 256 {
            break;
        }

        pci_write_config_byte(bus as u8, device, function, reg_offset as u8, byte);
        bytes_written += 1;
    }

    bytes_written
}

/// Read ISA data (placeholder)
fn hal_get_isa_data(
    _bus: u32,
    _slot: u32,
    _buffer: &mut [u8],
    _offset: u32,
) -> u32 {
    // ISA doesn't have configuration space like PCI
    0
}

// ============================================================================
// PCI Configuration Access
// ============================================================================

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// Build PCI configuration address
fn pci_config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    0x8000_0000
        | ((bus as u32) << 16)
        | (((device & 0x1F) as u32) << 11)
        | (((function & 0x07) as u32) << 8)
        | ((offset & 0xFC) as u32)
}

/// Read PCI config byte
fn pci_read_config_byte(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let address = pci_config_address(bus, device, function, offset);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        use core::arch::asm;
        let value: u32;

        // Write address
        asm!(
            "out dx, eax",
            in("dx") PCI_CONFIG_ADDRESS,
            in("eax") address,
            options(nostack, preserves_flags)
        );

        // Read data
        asm!(
            "in eax, dx",
            in("dx") PCI_CONFIG_DATA,
            out("eax") value,
            options(nostack, preserves_flags)
        );

        ((value >> ((offset & 3) * 8)) & 0xFF) as u8
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Write PCI config byte
fn pci_write_config_byte(bus: u8, device: u8, function: u8, offset: u8, value: u8) {
    let address = pci_config_address(bus, device, function, offset);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        use core::arch::asm;

        // Read current dword
        asm!(
            "out dx, eax",
            in("dx") PCI_CONFIG_ADDRESS,
            in("eax") address,
            options(nostack, preserves_flags)
        );

        let current: u32;
        asm!(
            "in eax, dx",
            in("dx") PCI_CONFIG_DATA,
            out("eax") current,
            options(nostack, preserves_flags)
        );

        // Modify byte
        let shift = (offset & 3) * 8;
        let mask = !(0xFFu32 << shift);
        let new_value = (current & mask) | ((value as u32) << shift);

        // Write back
        asm!(
            "out dx, eax",
            in("dx") PCI_CONFIG_ADDRESS,
            in("eax") address,
            options(nostack, preserves_flags)
        );

        asm!(
            "out dx, eax",
            in("dx") PCI_CONFIG_DATA,
            in("eax") new_value,
            options(nostack, preserves_flags)
        );
    }
}

/// Read PCI config word
pub fn pci_read_config_word(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let low = pci_read_config_byte(bus, device, function, offset) as u16;
    let high = pci_read_config_byte(bus, device, function, offset + 1) as u16;
    low | (high << 8)
}

/// Read PCI config dword
pub fn pci_read_config_dword(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address = pci_config_address(bus, device, function, offset);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        use core::arch::asm;
        let value: u32;

        asm!(
            "out dx, eax",
            in("dx") PCI_CONFIG_ADDRESS,
            in("eax") address,
            options(nostack, preserves_flags)
        );

        asm!(
            "in eax, dx",
            in("dx") PCI_CONFIG_DATA,
            out("eax") value,
            options(nostack, preserves_flags)
        );

        value
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

// ============================================================================
// Address Translation
// ============================================================================

/// Translate bus address to physical address
///
/// Returns (physical_address, address_space) or None if translation fails
pub fn hal_translate_bus_address(
    bus_type: BusType,
    bus_number: u32,
    bus_address: BusAddress,
    address_space: AddressSpace,
) -> Option<(u64, AddressSpace)> {
    match bus_type {
        BusType::Pci | BusType::Isa | BusType::Eisa => {
            // For x86, bus addresses are typically same as physical
            let _ = bus_number;
            Some((bus_address.as_u64(), address_space))
        }
        _ => None,
    }
}

// ============================================================================
// Interrupt Vector Mapping
// ============================================================================

/// Get system interrupt vector for bus IRQ
///
/// Returns (vector, irql) or None if mapping fails
pub fn hal_get_interrupt_vector(
    bus_type: BusType,
    _bus_number: u32,
    bus_interrupt_level: u32,
    _bus_interrupt_vector: u32,
) -> Option<(u32, u8)> {
    match bus_type {
        BusType::Pci => {
            // PCI interrupts are typically mapped to vectors 32+
            let vector = 32 + bus_interrupt_level;
            let irql = (bus_interrupt_level + 4).min(26) as u8; // Device IRQL range
            Some((vector, irql))
        }
        BusType::Isa => {
            // ISA IRQs 0-15 map to vectors 32-47
            if bus_interrupt_level < 16 {
                let vector = 32 + bus_interrupt_level;
                let irql = (bus_interrupt_level + 4).min(26) as u8;
                Some((vector, irql))
            } else {
                None
            }
        }
        _ => None,
    }
}

// ============================================================================
// Bus Registration
// ============================================================================

/// Register a bus
pub fn hal_register_bus(bus_type: BusType, bus_number: u32, info: &BusInfo) -> bool {
    let type_idx = bus_type as usize;
    if type_idx >= 16 || bus_number as usize >= MAX_BUSES {
        return false;
    }

    let _guard = BUS_LOCK.lock();

    unsafe {
        BUS_REGISTRY[type_idx][bus_number as usize] = BusEntry {
            info: *info,
            valid: true,
        };
    }

    BUS_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

/// Query bus information
pub fn hal_query_bus(bus_type: BusType, bus_number: u32) -> Option<BusInfo> {
    let type_idx = bus_type as usize;
    if type_idx >= 16 || bus_number as usize >= MAX_BUSES {
        return None;
    }

    unsafe {
        let entry = &BUS_REGISTRY[type_idx][bus_number as usize];
        if entry.valid {
            Some(entry.info)
        } else {
            None
        }
    }
}

/// Enumerate buses of a type
pub fn hal_enumerate_buses(bus_type: BusType) -> ([BusInfo; 16], usize) {
    let mut buses = [BusInfo::default(); 16];
    let mut count = 0;

    let type_idx = bus_type as usize;
    if type_idx >= 16 {
        return (buses, 0);
    }

    unsafe {
        for i in 0..MAX_BUSES {
            if count >= 16 {
                break;
            }
            let entry = &BUS_REGISTRY[type_idx][i];
            if entry.valid {
                buses[count] = entry.info;
                count += 1;
            }
        }
    }

    (buses, count)
}

// ============================================================================
// PCI Device Enumeration
// ============================================================================

/// Scan PCI bus for devices
pub fn hal_scan_pci_bus(bus: u8) -> ([SlotInfo; 32], usize) {
    let mut devices = [SlotInfo::default(); 32];
    let mut count = 0;

    for device in 0..32u8 {
        for function in 0..8u8 {
            let vendor = pci_read_config_word(bus, device, function, 0);

            if vendor == 0xFFFF {
                if function == 0 {
                    break; // No device, skip remaining functions
                }
                continue;
            }

            if count >= 32 {
                return (devices, count);
            }

            let device_id = pci_read_config_word(bus, device, function, 2);
            let class = pci_read_config_dword(bus, device, function, 8);
            let int_line = pci_read_config_byte(bus, device, function, 0x3C);
            let int_pin = pci_read_config_byte(bus, device, function, 0x3D);

            devices[count] = SlotInfo {
                bus_type: BusType::Pci,
                bus_number: bus as u32,
                slot_number: PciSlotNumber::new(device, function).as_u32(),
                device_present: true,
                vendor_id: vendor,
                device_id,
                class_code: class >> 8,
                interrupt_line: int_line,
                interrupt_pin: int_pin,
            };
            count += 1;

            // Check if multi-function device
            if function == 0 {
                let header = pci_read_config_byte(bus, device, function, 0x0E);
                if (header & 0x80) == 0 {
                    break; // Not multi-function
                }
            }
        }
    }

    (devices, count)
}

// ============================================================================
// Statistics
// ============================================================================

/// Bus statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct BusStats {
    pub registered_buses: u32,
    pub pci_buses: u32,
    pub isa_buses: u32,
}

/// Get bus statistics
pub fn hal_get_bus_stats() -> BusStats {
    let mut stats = BusStats::default();
    stats.registered_buses = BUS_COUNT.load(Ordering::Relaxed);

    unsafe {
        for i in 0..MAX_BUSES {
            if BUS_REGISTRY[BusType::Pci as usize][i].valid {
                stats.pci_buses += 1;
            }
            if BUS_REGISTRY[BusType::Isa as usize][i].valid {
                stats.isa_buses += 1;
            }
        }
    }

    stats
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize bus subsystem
pub fn init() {
    let _guard = BUS_LOCK.lock();

    // Clear registry
    unsafe {
        for type_buses in BUS_REGISTRY.iter_mut() {
            for entry in type_buses.iter_mut() {
                *entry = BusEntry::default();
            }
        }
    }

    BUS_COUNT.store(0, Ordering::Relaxed);

    // Register default buses
    // PCI bus 0
    hal_register_bus(BusType::Pci, 0, &BusInfo {
        bus_type: BusType::Pci,
        bus_number: 0,
        present: true,
        slot_count: 32,
        capabilities: 0,
    });

    // ISA bus (legacy)
    hal_register_bus(BusType::Isa, 0, &BusInfo {
        bus_type: BusType::Isa,
        bus_number: 0,
        present: true,
        slot_count: 0,
        capabilities: 0,
    });

    BUS_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[HAL] Bus subsystem initialized");
}

/// Check if bus subsystem is initialized
pub fn hal_is_bus_initialized() -> bool {
    BUS_INITIALIZED.load(Ordering::Acquire)
}
