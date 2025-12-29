//! ACPI (Advanced Configuration and Power Interface) Support
//!
//! This module implements ACPI table parsing for hardware discovery
//! and configuration, following the Windows NT HAL ACPI model.
//!
//! ## Supported Tables
//! - RSDP (Root System Description Pointer)
//! - RSDT/XSDT (Root/Extended System Description Table)
//! - MADT/APIC (Multiple APIC Description Table)
//! - FADT (Fixed ACPI Description Table)
//!
//! ## Usage
//! ```ignore
//! // Initialize ACPI from RSDP address (from bootloader)
//! acpi::init(rsdp_addr);
//!
//! // Get CPU information
//! let cpu_count = acpi::get_processor_count();
//! let local_apic_addr = acpi::get_local_apic_address();
//! ```

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// RSDP signature: "RSD PTR "
const RSDP_SIGNATURE: u64 = 0x2052545020445352;

/// Table signatures
const RSDT_SIGNATURE: u32 = 0x54445352; // "RSDT"
const XSDT_SIGNATURE: u32 = 0x54445358; // "XSDT"
const MADT_SIGNATURE: u32 = 0x43495041; // "APIC"
const FADT_SIGNATURE: u32 = 0x50434146; // "FACP"

/// MADT entry types
const MADT_LOCAL_APIC: u8 = 0;
const MADT_IO_APIC: u8 = 1;
const MADT_INTERRUPT_OVERRIDE: u8 = 2;
const MADT_NMI_SOURCE: u8 = 3;
const MADT_LOCAL_NMI: u8 = 4;
const MADT_LOCAL_APIC_OVERRIDE: u8 = 5;

/// Maximum number of processors supported
pub const MAX_PROCESSORS: usize = 64;

/// Maximum number of I/O APICs supported
pub const MAX_IO_APICS: usize = 8;

/// Root System Description Pointer (ACPI 2.0+)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Rsdp {
    /// Signature "RSD PTR "
    pub signature: u64,
    /// Checksum for first 20 bytes
    pub checksum: u8,
    /// OEM ID
    pub oem_id: [u8; 6],
    /// Revision: 0 = ACPI 1.0, 2 = ACPI 2.0+
    pub revision: u8,
    /// Physical address of RSDT (32-bit)
    pub rsdt_address: u32,
    // ACPI 2.0+ fields below
    /// Length of this table
    pub length: u32,
    /// Physical address of XSDT (64-bit)
    pub xsdt_address: u64,
    /// Extended checksum
    pub extended_checksum: u8,
    /// Reserved
    pub reserved: [u8; 3],
}

/// Generic ACPI table header (DESCRIPTION_HEADER)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AcpiHeader {
    /// Table signature
    pub signature: u32,
    /// Length of entire table including header
    pub length: u32,
    /// ACPI spec minor version
    pub revision: u8,
    /// Checksum (sum of all bytes should be 0)
    pub checksum: u8,
    /// OEM ID
    pub oem_id: [u8; 6],
    /// OEM table ID
    pub oem_table_id: [u8; 8],
    /// OEM revision
    pub oem_revision: u32,
    /// Creator ID
    pub creator_id: [u8; 4],
    /// Creator revision
    pub creator_revision: u32,
}

/// Generic Address Structure
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct GenericAddress {
    /// Address space ID
    pub address_space: u8,
    /// Bit width
    pub bit_width: u8,
    /// Bit offset
    pub bit_offset: u8,
    /// Access size
    pub access_size: u8,
    /// Address
    pub address: u64,
}

/// Fixed ACPI Description Table (FADT)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Fadt {
    pub header: AcpiHeader,
    /// Physical address of FACS
    pub facs_address: u32,
    /// Physical address of DSDT
    pub dsdt_address: u32,
    /// Interrupt model (0 = dual PIC, 1 = APIC)
    pub int_model: u8,
    /// Preferred power profile
    pub pm_profile: u8,
    /// SCI interrupt vector
    pub sci_interrupt: u16,
    /// SMI command port
    pub smi_command_port: u32,
    /// Value to enable ACPI
    pub acpi_enable: u8,
    /// Value to disable ACPI
    pub acpi_disable: u8,
    /// Value for S4BIOS
    pub s4bios_req: u8,
    /// P-state control
    pub pstate_control: u8,
    /// PM1a event block address
    pub pm1a_event_block: u32,
    /// PM1b event block address
    pub pm1b_event_block: u32,
    /// PM1a control block address
    pub pm1a_control_block: u32,
    /// PM1b control block address
    pub pm1b_control_block: u32,
    /// PM2 control block address
    pub pm2_control_block: u32,
    /// PM timer block address
    pub pm_timer_block: u32,
    /// GPE0 block address
    pub gpe0_block: u32,
    /// GPE1 block address
    pub gpe1_block: u32,
    /// PM1 event block length
    pub pm1_event_length: u8,
    /// PM1 control block length
    pub pm1_control_length: u8,
    /// PM2 control block length
    pub pm2_control_length: u8,
    /// PM timer block length
    pub pm_timer_length: u8,
    /// GPE0 block length
    pub gpe0_length: u8,
    /// GPE1 block length
    pub gpe1_length: u8,
    /// GPE1 base offset
    pub gpe1_base: u8,
    /// C-state control
    pub cstate_control: u8,
    /// C2 latency in microseconds
    pub c2_latency: u16,
    /// C3 latency in microseconds
    pub c3_latency: u16,
    /// Flush size for WBINVD
    pub flush_size: u16,
    /// Flush stride for WBINVD
    pub flush_stride: u16,
    /// Duty cycle offset
    pub duty_offset: u8,
    /// Duty cycle width
    pub duty_width: u8,
    /// RTC day alarm index
    pub day_alarm: u8,
    /// RTC month alarm index
    pub month_alarm: u8,
    /// RTC century index
    pub century: u8,
    /// Boot architecture flags
    pub boot_arch_flags: u16,
    /// Reserved
    pub reserved2: u8,
    /// Feature flags
    pub flags: u32,
    // ACPI 2.0+ extended fields follow...
}

/// Multiple APIC Description Table header (MADT/MAPIC)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Madt {
    pub header: AcpiHeader,
    /// Physical address of Local APIC
    pub local_apic_address: u32,
    /// Flags (bit 0 = dual 8259 present)
    pub flags: u32,
    // Variable-length entries follow
}

/// MADT entry header
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtEntry {
    pub entry_type: u8,
    pub length: u8,
}

/// Local APIC entry
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtLocalApic {
    pub header: MadtEntry,
    /// ACPI processor ID
    pub acpi_processor_id: u8,
    /// Local APIC ID
    pub apic_id: u8,
    /// Flags (bit 0 = enabled)
    pub flags: u32,
}

/// I/O APIC entry
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtIoApic {
    pub header: MadtEntry,
    /// I/O APIC ID
    pub io_apic_id: u8,
    /// Reserved
    pub reserved: u8,
    /// I/O APIC physical address
    pub io_apic_address: u32,
    /// Global system interrupt base
    pub gsi_base: u32,
}

/// Interrupt Source Override entry
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtInterruptOverride {
    pub header: MadtEntry,
    /// Bus (0 = ISA)
    pub bus: u8,
    /// Source IRQ
    pub source: u8,
    /// Global System Interrupt
    pub gsi: u32,
    /// Flags (polarity, trigger mode)
    pub flags: u16,
}

/// Local APIC NMI entry
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtLocalNmi {
    pub header: MadtEntry,
    /// ACPI processor ID (0xFF = all)
    pub acpi_processor_id: u8,
    /// Flags
    pub flags: u16,
    /// Local APIC LINT# (0 or 1)
    pub lint: u8,
}

/// Local APIC Address Override entry
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtLocalApicOverride {
    pub header: MadtEntry,
    /// Reserved
    pub reserved: u16,
    /// 64-bit Local APIC address
    pub local_apic_address: u64,
}

/// Processor information
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessorInfo {
    /// ACPI processor ID
    pub acpi_id: u8,
    /// Local APIC ID
    pub apic_id: u8,
    /// Is processor enabled?
    pub enabled: bool,
    /// Is this the bootstrap processor?
    pub is_bsp: bool,
}

/// I/O APIC information
#[derive(Debug, Clone, Copy, Default)]
pub struct IoApicInfo {
    /// I/O APIC ID
    pub id: u8,
    /// Physical address
    pub address: u64,
    /// Global System Interrupt base
    pub gsi_base: u32,
}

/// Interrupt override information
#[derive(Debug, Clone, Copy)]
pub struct InterruptOverride {
    /// Source IRQ (ISA)
    pub source: u8,
    /// Global System Interrupt
    pub gsi: u32,
    /// Polarity (0 = conforms, 1 = active high, 3 = active low)
    pub polarity: u8,
    /// Trigger mode (0 = conforms, 1 = edge, 3 = level)
    pub trigger: u8,
}

/// ACPI system information
pub struct AcpiInfo {
    /// Is ACPI initialized?
    pub initialized: bool,
    /// ACPI revision (0 = 1.0, 2 = 2.0+)
    pub revision: u8,
    /// Local APIC physical address
    pub local_apic_address: u64,
    /// Number of processors found
    pub processor_count: usize,
    /// Processor information
    pub processors: [ProcessorInfo; MAX_PROCESSORS],
    /// Number of I/O APICs found
    pub io_apic_count: usize,
    /// I/O APIC information
    pub io_apics: [IoApicInfo; MAX_IO_APICS],
    /// Interrupt overrides
    pub interrupt_overrides: [Option<InterruptOverride>; 24],
    /// FADT flags
    pub fadt_flags: u32,
    /// Does system have dual 8259 PICs?
    pub has_8259: bool,
}

impl Default for AcpiInfo {
    fn default() -> Self {
        Self {
            initialized: false,
            revision: 0,
            local_apic_address: 0xFEE0_0000, // Default Local APIC address
            processor_count: 0,
            processors: [ProcessorInfo::default(); MAX_PROCESSORS],
            io_apic_count: 0,
            io_apics: [IoApicInfo::default(); MAX_IO_APICS],
            interrupt_overrides: [None; 24],
            fadt_flags: 0,
            has_8259: true,
        }
    }
}

/// Global ACPI information
static ACPI_INFO: Mutex<AcpiInfo> = Mutex::new(AcpiInfo {
    initialized: false,
    revision: 0,
    local_apic_address: 0xFEE0_0000,
    processor_count: 0,
    processors: [ProcessorInfo {
        acpi_id: 0,
        apic_id: 0,
        enabled: false,
        is_bsp: false,
    }; MAX_PROCESSORS],
    io_apic_count: 0,
    io_apics: [IoApicInfo {
        id: 0,
        address: 0,
        gsi_base: 0,
    }; MAX_IO_APICS],
    interrupt_overrides: [None; 24],
    fadt_flags: 0,
    has_8259: true,
});

static ACPI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Validate ACPI table checksum
fn validate_checksum(addr: u64, len: usize) -> bool {
    let mut sum: u8 = 0;
    for i in 0..len {
        let byte = unsafe { ptr::read_volatile((addr + i as u64) as *const u8) };
        sum = sum.wrapping_add(byte);
    }
    sum == 0
}

/// Read a signature as a string (for debug output)
fn signature_to_str(sig: u32) -> [u8; 4] {
    [
        (sig & 0xFF) as u8,
        ((sig >> 8) & 0xFF) as u8,
        ((sig >> 16) & 0xFF) as u8,
        ((sig >> 24) & 0xFF) as u8,
    ]
}

/// Parse RSDP and return pointer to RSDT/XSDT
unsafe fn parse_rsdp(rsdp_addr: u64) -> Option<(u64, bool)> {
    let rsdp = &*(rsdp_addr as *const Rsdp);

    // Validate signature
    if rsdp.signature != RSDP_SIGNATURE {
        crate::serial_println!("[ACPI] Invalid RSDP signature");
        return None;
    }

    // Validate checksum for ACPI 1.0 portion (first 20 bytes)
    if !validate_checksum(rsdp_addr, 20) {
        crate::serial_println!("[ACPI] Invalid RSDP checksum");
        return None;
    }

    crate::serial_println!("[ACPI] Found RSDP at {:#x}, revision {}", rsdp_addr, rsdp.revision);

    // Use XSDT for ACPI 2.0+, RSDT for 1.0
    // Use read_unaligned for packed struct fields
    let xsdt_addr = ptr::read_unaligned(ptr::addr_of!(rsdp.xsdt_address));
    let rsdt_addr = ptr::read_unaligned(ptr::addr_of!(rsdp.rsdt_address));
    let length = ptr::read_unaligned(ptr::addr_of!(rsdp.length));

    if rsdp.revision >= 2 && xsdt_addr != 0 {
        // Validate extended checksum
        if !validate_checksum(rsdp_addr, length as usize) {
            crate::serial_println!("[ACPI] Invalid RSDP extended checksum");
            return None;
        }
        crate::serial_println!("[ACPI] Using XSDT at {:#x}", xsdt_addr);
        Some((xsdt_addr, true))
    } else {
        crate::serial_println!("[ACPI] Using RSDT at {:#x}", rsdt_addr);
        Some((rsdt_addr as u64, false))
    }
}

/// Find a specific ACPI table by signature
unsafe fn find_table(sdt_addr: u64, use_xsdt: bool, signature: u32) -> Option<u64> {
    let header = &*(sdt_addr as *const AcpiHeader);

    // Validate the SDT
    let expected_sig = if use_xsdt { XSDT_SIGNATURE } else { RSDT_SIGNATURE };
    if header.signature != expected_sig {
        crate::serial_println!("[ACPI] Invalid SDT signature");
        return None;
    }

    if !validate_checksum(sdt_addr, header.length as usize) {
        crate::serial_println!("[ACPI] Invalid SDT checksum");
        return None;
    }

    // Calculate number of entries
    let entry_size = if use_xsdt { 8 } else { 4 };
    let entries_start = sdt_addr + core::mem::size_of::<AcpiHeader>() as u64;
    let entries_len = header.length as usize - core::mem::size_of::<AcpiHeader>();
    let num_entries = entries_len / entry_size;

    // Search for the requested table
    for i in 0..num_entries {
        let entry_addr = entries_start + (i * entry_size) as u64;
        let table_addr = if use_xsdt {
            ptr::read_unaligned(entry_addr as *const u64)
        } else {
            ptr::read_unaligned(entry_addr as *const u32) as u64
        };

        if table_addr == 0 {
            continue;
        }

        let table_header = &*(table_addr as *const AcpiHeader);
        if table_header.signature == signature {
            let sig_str = signature_to_str(signature);
            crate::serial_println!(
                "[ACPI] Found {} table at {:#x}",
                core::str::from_utf8(&sig_str).unwrap_or("????"),
                table_addr
            );
            return Some(table_addr);
        }
    }

    None
}

/// Parse MADT (Multiple APIC Description Table)
unsafe fn parse_madt(madt_addr: u64, info: &mut AcpiInfo) {
    let madt = &*(madt_addr as *const Madt);

    if !validate_checksum(madt_addr, madt.header.length as usize) {
        crate::serial_println!("[ACPI] Invalid MADT checksum");
        return;
    }

    // Get Local APIC address
    info.local_apic_address = madt.local_apic_address as u64;
    info.has_8259 = (madt.flags & 1) != 0;

    crate::serial_println!(
        "[ACPI] MADT: Local APIC at {:#x}, has_8259={}",
        info.local_apic_address,
        info.has_8259
    );

    // Parse entries
    let entries_start = madt_addr + core::mem::size_of::<Madt>() as u64;
    let entries_end = madt_addr + madt.header.length as u64;
    let mut offset = entries_start;

    while offset < entries_end {
        let entry = &*(offset as *const MadtEntry);

        if entry.length == 0 {
            break;
        }

        match entry.entry_type {
            MADT_LOCAL_APIC => {
                let local_apic = &*(offset as *const MadtLocalApic);
                let enabled = (local_apic.flags & 1) != 0;

                if info.processor_count < MAX_PROCESSORS {
                    info.processors[info.processor_count] = ProcessorInfo {
                        acpi_id: local_apic.acpi_processor_id,
                        apic_id: local_apic.apic_id,
                        enabled,
                        is_bsp: info.processor_count == 0, // First one is BSP
                    };
                    info.processor_count += 1;

                    crate::serial_println!(
                        "[ACPI]   CPU {}: ACPI ID={}, APIC ID={}, enabled={}",
                        info.processor_count - 1,
                        local_apic.acpi_processor_id,
                        local_apic.apic_id,
                        enabled
                    );
                }
            }
            MADT_IO_APIC => {
                let io_apic = &*(offset as *const MadtIoApic);
                // Read unaligned fields
                let io_apic_addr = ptr::read_unaligned(ptr::addr_of!(io_apic.io_apic_address));
                let gsi_base = ptr::read_unaligned(ptr::addr_of!(io_apic.gsi_base));

                if info.io_apic_count < MAX_IO_APICS {
                    info.io_apics[info.io_apic_count] = IoApicInfo {
                        id: io_apic.io_apic_id,
                        address: io_apic_addr as u64,
                        gsi_base,
                    };
                    info.io_apic_count += 1;

                    crate::serial_println!(
                        "[ACPI]   I/O APIC {}: ID={}, addr={:#x}, GSI base={}",
                        info.io_apic_count - 1,
                        io_apic.io_apic_id,
                        io_apic_addr,
                        gsi_base
                    );
                }
            }
            MADT_INTERRUPT_OVERRIDE => {
                let override_entry = &*(offset as *const MadtInterruptOverride);
                let source = override_entry.source as usize;
                // Read unaligned fields
                let gsi = ptr::read_unaligned(ptr::addr_of!(override_entry.gsi));
                let flags = ptr::read_unaligned(ptr::addr_of!(override_entry.flags));

                if source < 24 {
                    info.interrupt_overrides[source] = Some(InterruptOverride {
                        source: override_entry.source,
                        gsi,
                        polarity: (flags & 0x3) as u8,
                        trigger: ((flags >> 2) & 0x3) as u8,
                    });

                    crate::serial_println!(
                        "[ACPI]   IRQ Override: source={} -> GSI={}, flags={:#x}",
                        override_entry.source,
                        gsi,
                        flags
                    );
                }
            }
            MADT_LOCAL_APIC_OVERRIDE => {
                let override_entry = &*(offset as *const MadtLocalApicOverride);
                // Read unaligned field
                let local_apic_addr = ptr::read_unaligned(ptr::addr_of!(override_entry.local_apic_address));
                info.local_apic_address = local_apic_addr;
                crate::serial_println!(
                    "[ACPI]   Local APIC Override: addr={:#x}",
                    local_apic_addr
                );
            }
            MADT_NMI_SOURCE => {
                crate::serial_println!("[ACPI]   NMI Source entry");
            }
            MADT_LOCAL_NMI => {
                let nmi = &*(offset as *const MadtLocalNmi);
                crate::serial_println!(
                    "[ACPI]   Local NMI: processor={}, LINT={}",
                    nmi.acpi_processor_id,
                    nmi.lint
                );
            }
            _ => {
                crate::serial_println!("[ACPI]   Unknown entry type: {}", entry.entry_type);
            }
        }

        offset += entry.length as u64;
    }
}

/// Parse FADT (Fixed ACPI Description Table)
unsafe fn parse_fadt(fadt_addr: u64, info: &mut AcpiInfo) {
    let fadt = &*(fadt_addr as *const Fadt);
    // Read unaligned fields
    let header_length = ptr::read_unaligned(ptr::addr_of!(fadt.header.length));

    if !validate_checksum(fadt_addr, header_length as usize) {
        crate::serial_println!("[ACPI] Invalid FADT checksum");
        return;
    }

    let flags = ptr::read_unaligned(ptr::addr_of!(fadt.flags));
    let sci_interrupt = ptr::read_unaligned(ptr::addr_of!(fadt.sci_interrupt));
    let pm1a_event_block = ptr::read_unaligned(ptr::addr_of!(fadt.pm1a_event_block));
    let pm1a_control_block = ptr::read_unaligned(ptr::addr_of!(fadt.pm1a_control_block));
    let pm_timer_block = ptr::read_unaligned(ptr::addr_of!(fadt.pm_timer_block));

    info.fadt_flags = flags;

    crate::serial_println!(
        "[ACPI] FADT: int_model={}, SCI={}, flags={:#x}",
        fadt.int_model,
        sci_interrupt,
        flags
    );
    crate::serial_println!(
        "[ACPI]   PM1a_evt={:#x}, PM1a_ctrl={:#x}, PM_tmr={:#x}",
        pm1a_event_block,
        pm1a_control_block,
        pm_timer_block
    );
}

/// Initialize ACPI subsystem
///
/// # Arguments
/// * `rsdp_addr` - Physical address of RSDP from bootloader
///
/// # Safety
/// Must be called with valid RSDP address. Should only be called once
/// during kernel initialization.
pub unsafe fn init(rsdp_addr: u64) {
    if rsdp_addr == 0 {
        crate::serial_println!("[ACPI] No RSDP address provided");
        return;
    }

    // Parse RSDP to get SDT address
    let (sdt_addr, use_xsdt) = match parse_rsdp(rsdp_addr) {
        Some(result) => result,
        None => return,
    };

    let mut info = ACPI_INFO.lock();
    info.revision = if use_xsdt { 2 } else { 0 };

    // Find and parse MADT
    if let Some(madt_addr) = find_table(sdt_addr, use_xsdt, MADT_SIGNATURE) {
        parse_madt(madt_addr, &mut info);
    } else {
        crate::serial_println!("[ACPI] MADT not found");
    }

    // Find and parse FADT
    if let Some(fadt_addr) = find_table(sdt_addr, use_xsdt, FADT_SIGNATURE) {
        parse_fadt(fadt_addr, &mut info);
    } else {
        crate::serial_println!("[ACPI] FADT not found");
    }

    info.initialized = true;
    ACPI_INITIALIZED.store(true, Ordering::SeqCst);

    crate::serial_println!(
        "[ACPI] Initialized: {} processor(s), {} I/O APIC(s)",
        info.processor_count,
        info.io_apic_count
    );
}

/// Check if ACPI is initialized
pub fn is_initialized() -> bool {
    ACPI_INITIALIZED.load(Ordering::SeqCst)
}

/// Get the number of processors detected
pub fn get_processor_count() -> usize {
    ACPI_INFO.lock().processor_count
}

/// Get processor information by index
pub fn get_processor(index: usize) -> Option<ProcessorInfo> {
    let info = ACPI_INFO.lock();
    if index < info.processor_count {
        Some(info.processors[index])
    } else {
        None
    }
}

/// Get the Local APIC physical address
pub fn get_local_apic_address() -> u64 {
    ACPI_INFO.lock().local_apic_address
}

/// Get the number of I/O APICs detected
pub fn get_io_apic_count() -> usize {
    ACPI_INFO.lock().io_apic_count
}

/// Get I/O APIC information by index
pub fn get_io_apic(index: usize) -> Option<IoApicInfo> {
    let info = ACPI_INFO.lock();
    if index < info.io_apic_count {
        Some(info.io_apics[index])
    } else {
        None
    }
}

/// Get interrupt override for a given ISA IRQ
pub fn get_interrupt_override(irq: u8) -> Option<InterruptOverride> {
    if irq < 24 {
        ACPI_INFO.lock().interrupt_overrides[irq as usize]
    } else {
        None
    }
}

/// Check if the system has legacy 8259 PICs
pub fn has_legacy_pics() -> bool {
    ACPI_INFO.lock().has_8259
}

/// Get ACPI revision (0 = 1.0, 2 = 2.0+)
pub fn get_revision() -> u8 {
    ACPI_INFO.lock().revision
}
