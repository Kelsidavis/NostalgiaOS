//! Virtual DOS Machine (VDM) Support
//!
//! NTVDM provides the infrastructure for running 16-bit DOS and Windows 3.x
//! applications on Windows NT. This module implements the kernel-side support
//! for VDM operations.
//!
//! # Architecture
//!
//! ```text
//! User Mode                          Kernel Mode
//! ┌─────────────────┐               ┌─────────────────┐
//! │   DOS App       │               │  VDM Support    │
//! │  (16-bit code)  │               │                 │
//! └────────┬────────┘               │ - I/O emulation │
//!          │                        │ - INT handling  │
//!          ▼                        │ - v86 mode      │
//! ┌─────────────────┐               └────────┬────────┘
//! │    NTVDM.EXE    │◄──────────────────────►│
//! │  (VDM process)  │    NtVdmControl()      │
//! └─────────────────┘                        │
//!          │                                 │
//!          ▼                                 ▼
//! ┌─────────────────┐               ┌─────────────────┐
//! │   WOW Layer     │               │  CPU Emulation  │
//! │ (Win16 support) │               │  (if no v86)    │
//! └─────────────────┘               └─────────────────┘
//! ```
//!
//! # Services
//!
//! - VdmStartExecution: Begin VDM execution
//! - VdmQueueInterrupt: Queue an interrupt for VDM
//! - VdmSetInt21Handler: Set DOS interrupt handler
//! - VdmQueryDir: Query directory for DOS
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `base/ntos/vdm/vdm.c` - VDM support

extern crate alloc;

pub mod control;
pub mod io;
pub mod interrupt;

use crate::ke::spinlock::SpinLock;
use crate::ob::handle::Handle;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

// ============================================================================
// VDM Constants
// ============================================================================

/// VDM service classes for NtVdmControl
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdmServiceClass {
    /// Start VDM execution
    VdmStartExecution = 0,
    /// Queue interrupt to VDM
    VdmQueueInterrupt = 1,
    /// Exchange interrupt state
    VdmExchangeInt21 = 2,
    /// Set Int21 handler
    VdmSetInt21Handler = 3,
    /// Query directory (DOS style)
    VdmQueryDir = 4,
    /// Printer direct access
    VdmPrinterDirectIoOpen = 5,
    VdmPrinterDirectIoClose = 6,
    /// Initialize VDM
    VdmInitialize = 7,
    /// Feature query
    VdmFeatures = 8,
    /// Set LDT entries
    VdmSetLdtEntries = 9,
    /// Set process LDT info
    VdmSetProcessLdtInfo = 10,
    /// Adapter info
    VdmAdapterInfo = 11,
}

/// VDM state flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VdmFlags: u32 {
        /// VDM is in virtual 8086 mode
        const V86_MODE = 1 << 0;
        /// VDM has pending interrupt
        const INTERRUPT_PENDING = 1 << 1;
        /// VDM is in protected mode
        const PROTECTED_MODE = 1 << 2;
        /// VDM trace mode enabled
        const TRACE_MODE = 1 << 3;
        /// VDM uses IOPL
        const IOPL_ENABLED = 1 << 4;
        /// VDM is 32-bit
        const VDM_32BIT = 1 << 5;
        /// VDM uses DPMI
        const DPMI_ENABLED = 1 << 6;
        /// VDM has virtual interrupts enabled
        const VIRTUAL_IF = 1 << 7;
    }
}

/// Virtual 8086 mode registers
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct V86Context {
    /// General purpose registers
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub eip: u32,
    pub eflags: u32,
    /// Segment registers
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
}

impl V86Context {
    /// Create a new V86 context with default DOS values
    pub fn new() -> Self {
        Self {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            esi: 0,
            edi: 0,
            ebp: 0,
            esp: 0xFFFE, // Top of conventional memory stack
            eip: 0x100,  // DOS program entry point
            eflags: 0x200, // Interrupts enabled
            cs: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
            ss: 0,
        }
    }

    /// Set segment:offset address for instruction pointer
    pub fn set_ip(&mut self, segment: u16, offset: u16) {
        self.cs = segment;
        self.eip = offset as u32;
    }

    /// Get linear address from segment:offset
    pub fn linear_address(segment: u16, offset: u16) -> u32 {
        ((segment as u32) << 4) + (offset as u32)
    }
}

/// DOS memory block information
#[derive(Debug, Clone)]
pub struct DosMemoryBlock {
    /// Segment address
    pub segment: u16,
    /// Size in paragraphs (16 bytes)
    pub size: u16,
    /// Owner PSP segment
    pub owner: u16,
    /// Block type (M = middle, Z = last)
    pub block_type: u8,
    /// Program name (8 chars)
    pub name: [u8; 8],
}

/// VDM process state
pub struct VdmState {
    /// Process handle
    pub process: Handle,
    /// VDM flags
    pub flags: VdmFlags,
    /// V86 context
    pub context: V86Context,
    /// Pending interrupts
    pub pending_interrupts: Vec<u8>,
    /// Interrupt vector table (256 entries)
    pub ivt: [u32; 256],
    /// I/O permission bitmap
    pub io_permission: [u8; 8192], // 65536 ports / 8
    /// DOS memory blocks
    pub memory_blocks: Vec<DosMemoryBlock>,
    /// Current PSP segment
    pub current_psp: u16,
    /// DOS version to report
    pub dos_version: (u8, u8),
    /// Drive mapping
    pub drive_map: [Option<alloc::string::String>; 26],
}

impl VdmState {
    /// Create a new VDM state
    pub fn new(process: Handle) -> Self {
        Self {
            process,
            flags: VdmFlags::empty(),
            context: V86Context::new(),
            pending_interrupts: Vec::new(),
            ivt: [0; 256],
            io_permission: [0xFF; 8192], // All ports denied by default
            memory_blocks: Vec::new(),
            current_psp: 0,
            dos_version: (5, 0), // DOS 5.0
            drive_map: Default::default(),
        }
    }

    /// Enable I/O port access for VDM
    pub fn allow_port(&mut self, port: u16) {
        let byte_index = (port / 8) as usize;
        let bit_index = port % 8;
        if byte_index < self.io_permission.len() {
            self.io_permission[byte_index] &= !(1 << bit_index);
        }
    }

    /// Deny I/O port access for VDM
    pub fn deny_port(&mut self, port: u16) {
        let byte_index = (port / 8) as usize;
        let bit_index = port % 8;
        if byte_index < self.io_permission.len() {
            self.io_permission[byte_index] |= 1 << bit_index;
        }
    }

    /// Check if port access is allowed
    pub fn is_port_allowed(&self, port: u16) -> bool {
        let byte_index = (port / 8) as usize;
        let bit_index = port % 8;
        if byte_index < self.io_permission.len() {
            (self.io_permission[byte_index] & (1 << bit_index)) == 0
        } else {
            false
        }
    }

    /// Queue an interrupt for VDM
    pub fn queue_interrupt(&mut self, vector: u8) {
        if !self.pending_interrupts.contains(&vector) {
            self.pending_interrupts.push(vector);
            self.flags.insert(VdmFlags::INTERRUPT_PENDING);
        }
    }

    /// Get next pending interrupt
    pub fn dequeue_interrupt(&mut self) -> Option<u8> {
        let result = self.pending_interrupts.pop();
        if self.pending_interrupts.is_empty() {
            self.flags.remove(VdmFlags::INTERRUPT_PENDING);
        }
        result
    }

    /// Set interrupt vector
    pub fn set_interrupt_vector(&mut self, vector: u8, segment: u16, offset: u16) {
        let linear = V86Context::linear_address(segment, offset);
        self.ivt[vector as usize] = linear;
    }

    /// Get interrupt vector
    pub fn get_interrupt_vector(&self, vector: u8) -> (u16, u16) {
        let linear = self.ivt[vector as usize];
        let segment = ((linear >> 4) & 0xFFFF) as u16;
        let offset = (linear & 0xF) as u16;
        (segment, offset)
    }
}

// ============================================================================
// VDM Table
// ============================================================================

static VDM_TABLE: SpinLock<BTreeMap<u32, VdmState>> = SpinLock::new(BTreeMap::new());
static NEXT_VDM_ID: SpinLock<u32> = SpinLock::new(1);

/// Initialize the VDM subsystem
pub fn init() {
    control::init();
    io::init();
    interrupt::init();
    crate::serial_println!("[VDM] Virtual DOS Machine subsystem initialized");
}

/// Create a new VDM for a process
pub fn create_vdm(process: Handle) -> Option<u32> {
    let mut id = NEXT_VDM_ID.lock();
    let vdm_id = *id;
    *id += 1;
    drop(id);

    let state = VdmState::new(process);
    let mut table = VDM_TABLE.lock();
    table.insert(vdm_id, state);

    Some(vdm_id)
}

/// Get VDM state by ID
pub fn get_vdm(vdm_id: u32) -> Option<VdmFlags> {
    let table = VDM_TABLE.lock();
    table.get(&vdm_id).map(|s| s.flags)
}

/// Destroy a VDM
pub fn destroy_vdm(vdm_id: u32) -> bool {
    let mut table = VDM_TABLE.lock();
    table.remove(&vdm_id).is_some()
}

// Re-exports
pub use control::{
    vdm_control,
    vdm_start_execution,
    vdm_initialize,
};

pub use io::{
    vdm_port_read,
    vdm_port_write,
};

pub use interrupt::{
    vdm_queue_interrupt,
    vdm_handle_interrupt,
};
