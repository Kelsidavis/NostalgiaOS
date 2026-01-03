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

    // Store PM control registers for power management
    store_fadt_pm_info(fadt_addr);

    // Update sleep state support from FADT flags
    {
        let mut sleep_info = SLEEP_STATES.lock();

        // FADT flags bit definitions for sleep states
        // Bit 10: S4_S5_LOW_POWER (S4BIOS_REQ supported)
        // For simplicity, assume S5 is always supported
        sleep_info.s5_supported = true;

        // Check if hardware reduced ACPI (no legacy mode)
        let hw_reduced = (flags & (1 << 20)) != 0;
        if hw_reduced {
            crate::serial_println!("[ACPI] Hardware-reduced ACPI mode");
        }

        // Check C-state latencies to estimate sleep state support
        let c2_latency = ptr::read_unaligned(ptr::addr_of!(fadt.c2_latency));
        let c3_latency = ptr::read_unaligned(ptr::addr_of!(fadt.c3_latency));

        if c2_latency < 100 {
            // C2 is reasonable, S1 might be supported
            sleep_info.s1_supported = true;
        }
        if c3_latency < 1000 {
            // C3 is reasonable, S3 might be supported
            sleep_info.s3_supported = true;
        }

        // Check for S4BIOS support
        if fadt.s4bios_req != 0 {
            sleep_info.s4_supported = true;
        }

        crate::serial_println!("[ACPI] Sleep states: S1={}, S2={}, S3={}, S4={}, S5={}",
            sleep_info.s1_supported, sleep_info.s2_supported,
            sleep_info.s3_supported, sleep_info.s4_supported,
            sleep_info.s5_supported);
    }
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

// ============================================================================
// ACPI Power Control
// ============================================================================

/// ACPI power control registers (from FADT)
static PM_CONTROL: Mutex<AcpiPmControl> = Mutex::new(AcpiPmControl {
    pm1a_event: 0,
    pm1b_event: 0,
    pm1a_control: 0,
    pm1b_control: 0,
    pm_timer: 0,
    pm1_event_len: 0,
    pm1_control_len: 0,
    gpe0_block: 0,
    gpe1_block: 0,
    sci_interrupt: 0,
    smi_command: 0,
    acpi_enable: 0,
    acpi_disable: 0,
    slp_typa: [0; 6],
    slp_typb: [0; 6],
});

/// ACPI PM control structure
#[derive(Debug, Clone, Copy)]
pub struct AcpiPmControl {
    /// PM1a Event block address
    pub pm1a_event: u32,
    /// PM1b Event block address
    pub pm1b_event: u32,
    /// PM1a Control block address
    pub pm1a_control: u32,
    /// PM1b Control block address
    pub pm1b_control: u32,
    /// PM Timer address
    pub pm_timer: u32,
    /// PM1 event block length
    pub pm1_event_len: u8,
    /// PM1 control block length
    pub pm1_control_len: u8,
    /// GPE0 block address
    pub gpe0_block: u32,
    /// GPE1 block address
    pub gpe1_block: u32,
    /// SCI interrupt number
    pub sci_interrupt: u16,
    /// SMI command port
    pub smi_command: u32,
    /// ACPI enable command
    pub acpi_enable: u8,
    /// ACPI disable command
    pub acpi_disable: u8,
    /// SLP_TYPa values for S0-S5
    pub slp_typa: [u8; 6],
    /// SLP_TYPb values for S0-S5
    pub slp_typb: [u8; 6],
}

/// Sleep state capabilities
static SLEEP_STATES: Mutex<SleepStateInfo> = Mutex::new(SleepStateInfo {
    s1_supported: false,
    s2_supported: false,
    s3_supported: false,
    s4_supported: false,
    s5_supported: true,
    reset_supported: false,
    reset_register: GenericAddress {
        address_space: 0,
        bit_width: 0,
        bit_offset: 0,
        access_size: 0,
        address: 0,
    },
    reset_value: 0,
});

/// Sleep state information
#[derive(Debug, Clone, Copy)]
pub struct SleepStateInfo {
    /// S1 (standby) supported
    pub s1_supported: bool,
    /// S2 supported
    pub s2_supported: bool,
    /// S3 (sleep) supported
    pub s3_supported: bool,
    /// S4 (hibernate) supported
    pub s4_supported: bool,
    /// S5 (soft off) supported
    pub s5_supported: bool,
    /// Reset via ACPI supported
    pub reset_supported: bool,
    /// Reset register (ACPI 2.0+)
    pub reset_register: GenericAddress,
    /// Reset value to write
    pub reset_value: u8,
}

/// PM1 Status register bits
pub mod pm1_status {
    /// Timer carry status
    pub const TMR_STS: u16 = 1 << 0;
    /// Bus master status
    pub const BM_STS: u16 = 1 << 4;
    /// Global status
    pub const GBL_STS: u16 = 1 << 5;
    /// Power button status
    pub const PWRBTN_STS: u16 = 1 << 8;
    /// Sleep button status
    pub const SLPBTN_STS: u16 = 1 << 9;
    /// RTC alarm status
    pub const RTC_STS: u16 = 1 << 10;
    /// Wakeup status
    pub const WAK_STS: u16 = 1 << 15;
}

/// PM1 Enable register bits
pub mod pm1_enable {
    /// Timer enable
    pub const TMR_EN: u16 = 1 << 0;
    /// Global enable
    pub const GBL_EN: u16 = 1 << 5;
    /// Power button enable
    pub const PWRBTN_EN: u16 = 1 << 8;
    /// Sleep button enable
    pub const SLPBTN_EN: u16 = 1 << 9;
    /// RTC alarm enable
    pub const RTC_EN: u16 = 1 << 10;
}

/// PM1 Control register bits
pub mod pm1_control {
    /// SCI enable (enables ACPI mode)
    pub const SCI_EN: u16 = 1 << 0;
    /// Bus master reload
    pub const BM_RLD: u16 = 1 << 1;
    /// Global lock release
    pub const GBL_RLS: u16 = 1 << 2;
    /// Sleep type (bits 10-12)
    pub const SLP_TYP_MASK: u16 = 0x1C00;
    pub const SLP_TYP_SHIFT: u16 = 10;
    /// Sleep enable
    pub const SLP_EN: u16 = 1 << 13;
}

/// Read PM1 status register
pub fn read_pm1_status() -> u16 {
    let pm = PM_CONTROL.lock();
    if pm.pm1a_event == 0 {
        return 0;
    }

    let mut status: u16 = 0;
    unsafe {
        // Read from PM1a
        core::arch::asm!(
            "in ax, dx",
            out("ax") status,
            in("dx") pm.pm1a_event as u16,
            options(nomem, nostack, preserves_flags)
        );

        // OR in PM1b if present
        if pm.pm1b_event != 0 {
            let mut status_b: u16;
            core::arch::asm!(
                "in ax, dx",
                out("ax") status_b,
                in("dx") pm.pm1b_event as u16,
                options(nomem, nostack, preserves_flags)
            );
            status |= status_b;
        }
    }
    status
}

/// Write PM1 status register (to clear bits)
pub fn write_pm1_status(value: u16) {
    let pm = PM_CONTROL.lock();
    if pm.pm1a_event == 0 {
        return;
    }

    unsafe {
        // Write to PM1a
        core::arch::asm!(
            "out dx, ax",
            in("dx") pm.pm1a_event as u16,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        );

        // Write to PM1b if present
        if pm.pm1b_event != 0 {
            core::arch::asm!(
                "out dx, ax",
                in("dx") pm.pm1b_event as u16,
                in("ax") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

/// Read PM1 enable register
pub fn read_pm1_enable() -> u16 {
    let pm = PM_CONTROL.lock();
    if pm.pm1a_event == 0 {
        return 0;
    }

    // Enable register is at offset pm1_event_len/2 from event block
    let offset = (pm.pm1_event_len / 2) as u32;
    let mut enable: u16 = 0;

    unsafe {
        core::arch::asm!(
            "in ax, dx",
            out("ax") enable,
            in("dx") (pm.pm1a_event + offset) as u16,
            options(nomem, nostack, preserves_flags)
        );

        if pm.pm1b_event != 0 {
            let mut enable_b: u16;
            core::arch::asm!(
                "in ax, dx",
                out("ax") enable_b,
                in("dx") (pm.pm1b_event + offset) as u16,
                options(nomem, nostack, preserves_flags)
            );
            enable |= enable_b;
        }
    }
    enable
}

/// Write PM1 enable register
pub fn write_pm1_enable(value: u16) {
    let pm = PM_CONTROL.lock();
    if pm.pm1a_event == 0 {
        return;
    }

    let offset = (pm.pm1_event_len / 2) as u32;

    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") (pm.pm1a_event + offset) as u16,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        );

        if pm.pm1b_event != 0 {
            core::arch::asm!(
                "out dx, ax",
                in("dx") (pm.pm1b_event + offset) as u16,
                in("ax") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

/// Read PM1 control register
pub fn read_pm1_control() -> u16 {
    let pm = PM_CONTROL.lock();
    if pm.pm1a_control == 0 {
        return 0;
    }

    let mut control: u16 = 0;
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            out("ax") control,
            in("dx") pm.pm1a_control as u16,
            options(nomem, nostack, preserves_flags)
        );
    }
    control
}

/// Write PM1 control register
fn write_pm1_control(value: u16) {
    let pm = PM_CONTROL.lock();
    if pm.pm1a_control == 0 {
        return;
    }

    unsafe {
        // Write to PM1a control
        core::arch::asm!(
            "out dx, ax",
            in("dx") pm.pm1a_control as u16,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        );

        // Write to PM1b control if present
        if pm.pm1b_control != 0 {
            core::arch::asm!(
                "out dx, ax",
                in("dx") pm.pm1b_control as u16,
                in("ax") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

/// Read ACPI PM timer (24 or 32 bit)
pub fn read_pm_timer() -> u32 {
    let pm = PM_CONTROL.lock();
    if pm.pm_timer == 0 {
        return 0;
    }

    let mut timer: u32 = 0;
    unsafe {
        core::arch::asm!(
            "in eax, dx",
            out("eax") timer,
            in("dx") pm.pm_timer as u16,
            options(nomem, nostack, preserves_flags)
        );
    }
    timer
}

/// Enable ACPI mode (switch from legacy APM)
pub fn enable_acpi() -> bool {
    // Get PM control info, then drop lock to avoid deadlock with read_pm1_control
    let (smi_command, acpi_enable) = {
        let pm = PM_CONTROL.lock();
        (pm.smi_command, pm.acpi_enable)
    };

    // Check if already in ACPI mode
    if (read_pm1_control() & pm1_control::SCI_EN) != 0 {
        crate::serial_println!("[ACPI] Already in ACPI mode");
        return true;
    }

    // Write ACPI enable to SMI command port
    if smi_command != 0 && acpi_enable != 0 {
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") smi_command as u16,
                in("al") acpi_enable,
                options(nomem, nostack, preserves_flags)
            );
        }

        // Wait for ACPI mode to be enabled (poll SCI_EN)
        for _ in 0..1000 {
            if (read_pm1_control() & pm1_control::SCI_EN) != 0 {
                crate::serial_println!("[ACPI] ACPI mode enabled");
                return true;
            }
            // Small delay
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }

        crate::serial_println!("[ACPI] Failed to enable ACPI mode");
        return false;
    }

    crate::serial_println!("[ACPI] No SMI command port available");
    false
}

/// Enter a sleep state (S1-S5)
///
/// # Safety
/// This will put the system to sleep or power it off.
/// Ensure all devices are properly quiesced before calling.
pub unsafe fn enter_sleep_state(state: u8) -> Result<(), &'static str> {
    if state > 5 {
        return Err("Invalid sleep state");
    }

    let sleep_info = SLEEP_STATES.lock();

    // Check if state is supported
    let supported = match state {
        0 => true, // S0 always supported
        1 => sleep_info.s1_supported,
        2 => sleep_info.s2_supported,
        3 => sleep_info.s3_supported,
        4 => sleep_info.s4_supported,
        5 => sleep_info.s5_supported,
        _ => false,
    };

    if !supported {
        return Err("Sleep state not supported");
    }

    let pm = PM_CONTROL.lock();

    if pm.pm1a_control == 0 {
        return Err("PM1 control block not available");
    }

    crate::serial_println!("[ACPI] Entering sleep state S{}", state);

    // Get SLP_TYP values
    let slp_typa = pm.slp_typa[state as usize];
    let slp_typb = pm.slp_typb[state as usize];

    // Disable interrupts
    core::arch::asm!("cli", options(nomem, nostack));

    // Clear wake status
    write_pm1_status(pm1_status::WAK_STS);

    // Build PM1 control value with SLP_TYP
    let pm1a_slp = ((slp_typa as u16) << pm1_control::SLP_TYP_SHIFT) | pm1_control::SLP_EN;
    let pm1b_slp = ((slp_typb as u16) << pm1_control::SLP_TYP_SHIFT) | pm1_control::SLP_EN;

    // Write to PM1a control
    core::arch::asm!(
        "out dx, ax",
        in("dx") pm.pm1a_control as u16,
        in("ax") pm1a_slp,
        options(nomem, nostack, preserves_flags)
    );

    // Write to PM1b control if present
    if pm.pm1b_control != 0 {
        core::arch::asm!(
            "out dx, ax",
            in("dx") pm.pm1b_control as u16,
            in("ax") pm1b_slp,
            options(nomem, nostack, preserves_flags)
        );
    }

    // If we're still executing (S1 or failed sleep), wait for wake
    if state == 1 {
        // For S1, wait for WAK_STS
        loop {
            if (read_pm1_status() & pm1_status::WAK_STS) != 0 {
                break;
            }
            core::arch::asm!("hlt", options(nomem, nostack));
        }

        // Clear wake status
        write_pm1_status(pm1_status::WAK_STS);

        // Re-enable interrupts
        core::arch::asm!("sti", options(nomem, nostack));

        crate::serial_println!("[ACPI] Resumed from S1");
    } else {
        // For deeper sleep states, we shouldn't reach here
        // If we do, the sleep failed
        core::arch::asm!("sti", options(nomem, nostack));
        return Err("Failed to enter sleep state");
    }

    Ok(())
}

/// Perform ACPI shutdown (S5)
///
/// # Safety
/// This will power off the system. Ensure all data is saved.
pub unsafe fn shutdown() -> ! {
    crate::serial_println!("[ACPI] Initiating system shutdown (S5)");

    // Try ACPI S5
    let _ = enter_sleep_state(5);

    // If that fails, try keyboard controller reset
    crate::serial_println!("[ACPI] ACPI S5 failed, trying keyboard controller");

    // Pulse CPU reset line via keyboard controller
    // 0x64 = keyboard controller command port
    // 0xFE = reset command
    for _ in 0..10 {
        // Wait for keyboard controller to be ready
        let mut status: u8;
        loop {
            core::arch::asm!(
                "in al, dx",
                out("al") status,
                in("dx") 0x64u16,
                options(nomem, nostack, preserves_flags)
            );
            if (status & 0x02) == 0 {
                break;
            }
        }

        // Send reset command
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x64u16,
            in("al") 0xFEu8,
            options(nomem, nostack, preserves_flags)
        );
    }

    // If reset failed, halt
    crate::serial_println!("[ACPI] Shutdown failed, halting");
    loop {
        core::arch::asm!("cli; hlt", options(nomem, nostack));
    }
}

/// Perform ACPI reset
///
/// # Safety
/// This will reset the system.
pub unsafe fn reset() -> ! {
    crate::serial_println!("[ACPI] Initiating system reset");

    let sleep_info = SLEEP_STATES.lock();

    // Try ACPI reset register first (ACPI 2.0+)
    if sleep_info.reset_supported {
        let reset_reg = sleep_info.reset_register;
        let reset_val = sleep_info.reset_value;

        match reset_reg.address_space {
            0 => {
                // System memory
                ptr::write_volatile(reset_reg.address as *mut u8, reset_val);
            }
            1 => {
                // I/O space
                core::arch::asm!(
                    "out dx, al",
                    in("dx") reset_reg.address as u16,
                    in("al") reset_val,
                    options(nomem, nostack, preserves_flags)
                );
            }
            2 => {
                // PCI config space (not commonly used)
                crate::serial_println!("[ACPI] PCI reset not implemented");
            }
            _ => {}
        }

        // Wait a bit
        for _ in 0..1000000 {
            core::hint::spin_loop();
        }
    }

    drop(sleep_info);

    // Fallback to keyboard controller reset
    crate::serial_println!("[ACPI] ACPI reset failed, trying keyboard controller");

    // Triple fault method: load invalid IDT and trigger interrupt
    // First try keyboard controller
    for _ in 0..10 {
        let mut status: u8;
        loop {
            core::arch::asm!(
                "in al, dx",
                out("al") status,
                in("dx") 0x64u16,
                options(nomem, nostack, preserves_flags)
            );
            if (status & 0x02) == 0 {
                break;
            }
        }

        core::arch::asm!(
            "out dx, al",
            in("dx") 0x64u16,
            in("al") 0xFEu8,
            options(nomem, nostack, preserves_flags)
        );
    }

    // Triple fault as last resort
    crate::serial_println!("[ACPI] Keyboard reset failed, triple faulting");

    // Load null IDT and trigger interrupt
    let null_idt: [u8; 6] = [0; 6];
    core::arch::asm!(
        "lidt [{}]",
        "int3",
        in(reg) null_idt.as_ptr(),
        options(nomem, nostack)
    );

    loop {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}

/// Store PM control registers from FADT
pub(crate) unsafe fn store_fadt_pm_info(fadt_addr: u64) {
    let fadt = &*(fadt_addr as *const Fadt);
    let mut pm = PM_CONTROL.lock();

    // Read unaligned fields
    pm.pm1a_event = ptr::read_unaligned(ptr::addr_of!(fadt.pm1a_event_block));
    pm.pm1b_event = ptr::read_unaligned(ptr::addr_of!(fadt.pm1b_event_block));
    pm.pm1a_control = ptr::read_unaligned(ptr::addr_of!(fadt.pm1a_control_block));
    pm.pm1b_control = ptr::read_unaligned(ptr::addr_of!(fadt.pm1b_control_block));
    pm.pm_timer = ptr::read_unaligned(ptr::addr_of!(fadt.pm_timer_block));
    pm.pm1_event_len = fadt.pm1_event_length;
    pm.pm1_control_len = fadt.pm1_control_length;
    pm.gpe0_block = ptr::read_unaligned(ptr::addr_of!(fadt.gpe0_block));
    pm.gpe1_block = ptr::read_unaligned(ptr::addr_of!(fadt.gpe1_block));
    pm.sci_interrupt = ptr::read_unaligned(ptr::addr_of!(fadt.sci_interrupt));
    pm.smi_command = ptr::read_unaligned(ptr::addr_of!(fadt.smi_command_port));
    pm.acpi_enable = fadt.acpi_enable;
    pm.acpi_disable = fadt.acpi_disable;

    crate::serial_println!("[ACPI] PM1a_evt={:#x}, PM1a_ctrl={:#x}, PM_tmr={:#x}",
        pm.pm1a_event, pm.pm1a_control, pm.pm_timer);
    crate::serial_println!("[ACPI] SCI={}, SMI_cmd={:#x}", pm.sci_interrupt, pm.smi_command);
}

/// Get sleep state capabilities
pub fn get_sleep_capabilities() -> SleepStateInfo {
    *SLEEP_STATES.lock()
}

/// Check if a specific sleep state is supported
pub fn is_sleep_state_supported(state: u8) -> bool {
    let info = SLEEP_STATES.lock();
    match state {
        0 => true,
        1 => info.s1_supported,
        2 => info.s2_supported,
        3 => info.s3_supported,
        4 => info.s4_supported,
        5 => info.s5_supported,
        _ => false,
    }
}

/// Get SCI interrupt number
pub fn get_sci_interrupt() -> u16 {
    PM_CONTROL.lock().sci_interrupt
}

/// Get PM control info for diagnostics
pub fn get_pm_control_info() -> AcpiPmControl {
    *PM_CONTROL.lock()
}
