//! VDM Control Operations
//!
//! Implements NtVdmControl and related VDM management functions.

extern crate alloc;

use super::{VdmServiceClass, V86Context};
use crate::ob::handle::Handle;

// ============================================================================
// VDM Control Structures
// ============================================================================

/// VDM initialization parameters
#[derive(Debug, Clone)]
#[repr(C)]
pub struct VdmInitParams {
    /// Size of this structure
    pub size: u32,
    /// Flags
    pub flags: u32,
    /// Conventional memory size (in KB)
    pub conventional_memory: u32,
    /// Extended memory size (in KB)
    pub extended_memory: u32,
    /// EMS memory size (in KB)
    pub ems_memory: u32,
    /// XMS memory size (in KB)
    pub xms_memory: u32,
}

impl Default for VdmInitParams {
    fn default() -> Self {
        Self {
            size: core::mem::size_of::<Self>() as u32,
            flags: 0,
            conventional_memory: 640,  // 640 KB
            extended_memory: 16384,    // 16 MB
            ems_memory: 0,             // No EMS
            xms_memory: 16384,         // 16 MB XMS
        }
    }
}

/// VDM execution state
#[derive(Debug, Clone)]
#[repr(C)]
pub struct VdmExecutionState {
    /// Current V86 context
    pub context: V86Context,
    /// Execution flags
    pub flags: u32,
    /// Last interrupt
    pub last_interrupt: u8,
    /// Exit reason
    pub exit_reason: VdmExitReason,
}

/// Reasons for VDM execution exit
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdmExitReason {
    /// Normal completion
    Normal = 0,
    /// Interrupt occurred
    Interrupt = 1,
    /// I/O instruction
    IoInstruction = 2,
    /// Invalid opcode
    InvalidOpcode = 3,
    /// General protection fault
    GeneralProtectionFault = 4,
    /// Page fault
    PageFault = 5,
    /// Halt instruction
    Halt = 6,
    /// Debug trap
    DebugTrap = 7,
    /// Task switch
    TaskSwitch = 8,
}

/// VDM query directory info (for DOS INT 21h, AH=4Eh/4Fh)
#[derive(Debug, Clone)]
#[repr(C)]
pub struct VdmQueryDirInfo {
    /// File handle
    pub file_handle: Handle,
    /// File information buffer
    pub file_info_ptr: usize,
    /// Buffer length
    pub length: u32,
    /// File name pattern
    pub file_name_ptr: usize,
    /// File index for restart
    pub file_index: u32,
}

/// VDM LDT entry
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VdmLdtEntry {
    /// Limit (low 16 bits)
    pub limit_low: u16,
    /// Base (low 16 bits)
    pub base_low: u16,
    /// Base (middle 8 bits)
    pub base_mid: u8,
    /// Access byte
    pub access: u8,
    /// Limit high (4 bits) + flags (4 bits)
    pub limit_high_flags: u8,
    /// Base (high 8 bits)
    pub base_high: u8,
}

impl VdmLdtEntry {
    /// Create a code segment descriptor
    pub fn code_segment(base: u32, limit: u32, dpl: u8) -> Self {
        Self::new(base, limit, 0x9A | ((dpl & 3) << 5), true)
    }

    /// Create a data segment descriptor
    pub fn data_segment(base: u32, limit: u32, dpl: u8) -> Self {
        Self::new(base, limit, 0x92 | ((dpl & 3) << 5), true)
    }

    /// Create a new LDT entry
    fn new(base: u32, limit: u32, access: u8, is_32bit: bool) -> Self {
        let granularity = if limit > 0xFFFFF { 0x80 } else { 0 };
        let db_bit = if is_32bit { 0x40 } else { 0 };
        let actual_limit = if granularity != 0 { limit >> 12 } else { limit };

        Self {
            limit_low: (actual_limit & 0xFFFF) as u16,
            base_low: (base & 0xFFFF) as u16,
            base_mid: ((base >> 16) & 0xFF) as u8,
            access,
            limit_high_flags: ((actual_limit >> 16) as u8 & 0xF) | granularity | db_bit,
            base_high: ((base >> 24) & 0xFF) as u8,
        }
    }

    /// Get the base address
    pub fn base(&self) -> u32 {
        (self.base_low as u32)
            | ((self.base_mid as u32) << 16)
            | ((self.base_high as u32) << 24)
    }

    /// Get the limit
    pub fn limit(&self) -> u32 {
        let limit = (self.limit_low as u32) | (((self.limit_high_flags & 0xF) as u32) << 16);
        if (self.limit_high_flags & 0x80) != 0 {
            (limit << 12) | 0xFFF
        } else {
            limit
        }
    }
}

// ============================================================================
// VDM Control Functions
// ============================================================================

/// Initialize the VDM control subsystem
pub fn init() {
    crate::serial_println!("[VDM] Control subsystem initialized");
}

/// Main VDM control entry point (NtVdmControl equivalent)
pub fn vdm_control(service: VdmServiceClass, service_data: usize) -> i32 {
    match service {
        VdmServiceClass::VdmStartExecution => {
            vdm_start_execution(service_data)
        }
        VdmServiceClass::VdmQueueInterrupt => {
            super::interrupt::vdm_queue_interrupt_from_user(service_data)
        }
        VdmServiceClass::VdmSetInt21Handler => {
            vdm_set_int21_handler(service_data)
        }
        VdmServiceClass::VdmQueryDir => {
            vdm_query_directory(service_data)
        }
        VdmServiceClass::VdmInitialize => {
            vdm_initialize(service_data)
        }
        VdmServiceClass::VdmFeatures => {
            vdm_query_features(service_data)
        }
        VdmServiceClass::VdmSetLdtEntries => {
            vdm_set_ldt_entries(service_data)
        }
        VdmServiceClass::VdmSetProcessLdtInfo => {
            vdm_set_process_ldt_info(service_data)
        }
        _ => {
            // Not implemented
            -1
        }
    }
}

/// Start VDM execution
pub fn vdm_start_execution(context_ptr: usize) -> i32 {
    // In a real implementation, this would:
    // 1. Switch to V86 mode or start CPU emulation
    // 2. Execute until an exit condition
    // 3. Return the exit reason and updated context

    // For now, return "not implemented" status
    crate::serial_println!("[VDM] Start execution called, context at 0x{:x}", context_ptr);
    0
}

/// Initialize VDM for the current process
pub fn vdm_initialize(params_ptr: usize) -> i32 {
    // Read initialization parameters
    if params_ptr == 0 {
        return -1;
    }

    crate::serial_println!("[VDM] Initialize called with params at 0x{:x}", params_ptr);

    // Create VDM state for current process
    let process_handle: Handle = 0xFFFFFFFF; // Current process pseudo-handle
    if let Some(vdm_id) = super::create_vdm(process_handle) {
        // Initialize default DOS environment
        let mut table = super::VDM_TABLE.lock();
        if let Some(state) = table.get_mut(&vdm_id) {
            // Set up interrupt vector table with default handlers
            for i in 0..256 {
                // Point to a default handler in low memory
                state.ivt[i] = 0x0000_0000 + (i as u32 * 4);
            }

            // Allow common I/O ports for DOS
            // Timer (ports 0x40-0x43)
            for port in 0x40..=0x43 {
                state.allow_port(port);
            }
            // Keyboard (port 0x60, 0x64)
            state.allow_port(0x60);
            state.allow_port(0x64);
            // PIC (ports 0x20-0x21, 0xA0-0xA1)
            state.allow_port(0x20);
            state.allow_port(0x21);
            state.allow_port(0xA0);
            state.allow_port(0xA1);
            // COM ports
            for port in 0x3F8..=0x3FF { state.allow_port(port); }
            for port in 0x2F8..=0x2FF { state.allow_port(port); }
        }
        vdm_id as i32
    } else {
        -1
    }
}

/// Set INT 21h handler
fn vdm_set_int21_handler(handler_ptr: usize) -> i32 {
    if handler_ptr == 0 {
        return -1;
    }

    // In a real implementation, this would register a custom
    // INT 21h (DOS services) handler
    crate::serial_println!("[VDM] Set INT 21h handler at 0x{:x}", handler_ptr);
    0
}

/// Query directory for DOS compatibility
fn vdm_query_directory(query_ptr: usize) -> i32 {
    if query_ptr == 0 {
        return -1;
    }

    // This provides FindFirst/FindNext functionality for DOS
    // using NT directory enumeration
    crate::serial_println!("[VDM] Query directory at 0x{:x}", query_ptr);
    0
}

/// Query VDM features
fn vdm_query_features(features_ptr: usize) -> i32 {
    if features_ptr == 0 {
        return -1;
    }

    // Return supported features bitmap
    let features: u32 = 0x0000_0001; // Basic VDM support

    // In real implementation, would write to features_ptr
    crate::serial_println!("[VDM] Query features, returning 0x{:x}", features);
    features as i32
}

/// Set LDT entries for protected mode DOS
fn vdm_set_ldt_entries(ldt_ptr: usize) -> i32 {
    if ldt_ptr == 0 {
        return -1;
    }

    // This allows DPMI applications to set up their own segments
    crate::serial_println!("[VDM] Set LDT entries at 0x{:x}", ldt_ptr);
    0
}

/// Set process LDT information
fn vdm_set_process_ldt_info(info_ptr: usize) -> i32 {
    if info_ptr == 0 {
        return -1;
    }

    // Configure per-process LDT settings
    crate::serial_println!("[VDM] Set process LDT info at 0x{:x}", info_ptr);
    0
}
