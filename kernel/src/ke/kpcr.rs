//! Kernel Processor Control Region (KPCR)
//!
//! The KPCR is a per-processor data structure that contains:
//! - Pointer to the KPRCB (processor control block)
//! - Per-processor IDT, GDT, and TSS pointers
//! - Current IRQL (Interrupt Request Level)
//! - Exception/interrupt handling state
//!
//! On x86_64, the KPCR is accessed via the GS segment register.
//! The GS base points to the KPCR, and the KPRCB is embedded/pointed to within it.
//!
//! This is NT 5.2 (Windows Server 2003) compatible.

use core::ptr;
use super::prcb::{KPrcb, KAffinity, MAX_CPUS};

// ============================================================================
// IRQL (Interrupt Request Level)
// ============================================================================

/// Interrupt Request Level type
pub type Kirql = u8;

/// IRQL levels (NT compatible)
pub mod irql {
    use super::Kirql;

    /// Passive level - normal thread execution, all interrupts enabled
    pub const PASSIVE_LEVEL: Kirql = 0;
    /// APC level - APCs are disabled
    pub const APC_LEVEL: Kirql = 1;
    /// Dispatch level - thread preemption disabled, DPCs run here
    pub const DISPATCH_LEVEL: Kirql = 2;
    /// Device IRQL base (3-26 on x86)
    pub const DEVICE_LEVEL_BASE: Kirql = 3;
    /// Clock interrupt level
    pub const CLOCK_LEVEL: Kirql = 28;
    /// Inter-processor interrupt level
    pub const IPI_LEVEL: Kirql = 29;
    /// Power fail level
    pub const POWER_LEVEL: Kirql = 30;
    /// Highest level - all interrupts disabled
    pub const HIGH_LEVEL: Kirql = 31;

    /// Synchronization level (same as DISPATCH on x86-64)
    pub const SYNCH_LEVEL: Kirql = DISPATCH_LEVEL;
}

// ============================================================================
// KPCR - Kernel Processor Control Region
// ============================================================================

/// Kernel Processor Control Region
///
/// This structure is the primary per-processor data structure in NT.
/// On x86_64, it's accessed via the GS segment base.
#[repr(C, align(64))]
pub struct KPcr {
    // ========================================================================
    // Self Reference (offset 0x00)
    // ========================================================================

    /// Self-referential pointer (for debugging and validation)
    pub self_pcr: *mut KPcr,

    /// Pointer to the current PRCB
    pub current_prcb: *mut KPrcb,

    // ========================================================================
    // Interrupt State (offset 0x10)
    // ========================================================================

    /// Current Interrupt Request Level
    pub irql: Kirql,

    /// Padding
    _pad0: [u8; 7],

    // ========================================================================
    // Per-Processor Tables (offset 0x18)
    // ========================================================================

    /// Interrupt Descriptor Table pointer
    pub idt: u64,

    /// Global Descriptor Table pointer
    pub gdt: u64,

    /// Task State Segment pointer
    pub tss: u64,

    // ========================================================================
    // Processor Identity (offset 0x30)
    // ========================================================================

    /// Processor number (0-based)
    pub number: u32,

    /// Padding
    _pad1: u32,

    /// Processor set member (affinity bit)
    pub set_member: KAffinity,

    // ========================================================================
    // Exception/Interrupt State (offset 0x40)
    // ========================================================================

    /// Interrupt count (nested interrupt tracking)
    pub interrupt_count: i32,

    /// Kernel debugger active flag
    pub debugger_active: u8,

    /// DPC routine active flag
    pub dpc_routine_active: u8,

    /// Padding
    _pad2: [u8; 2],

    // ========================================================================
    // Kernel Stack Info (offset 0x48)
    // ========================================================================

    /// NMI stack pointer
    pub nmi_stack: u64,

    /// Double fault stack pointer
    pub double_fault_stack: u64,

    /// Machine check stack pointer
    pub machine_check_stack: u64,

    // ========================================================================
    // Embedded PRCB (follows after KPCR header)
    // Note: In our implementation, we point to the PRCB array rather than embed
    // ========================================================================
}

impl KPcr {
    /// Create a new uninitialized KPCR
    pub const fn new() -> Self {
        Self {
            self_pcr: ptr::null_mut(),
            current_prcb: ptr::null_mut(),
            irql: irql::PASSIVE_LEVEL,
            _pad0: [0; 7],
            idt: 0,
            gdt: 0,
            tss: 0,
            number: 0,
            _pad1: 0,
            set_member: 0,
            interrupt_count: 0,
            debugger_active: 0,
            dpc_routine_active: 0,
            _pad2: [0; 2],
            nmi_stack: 0,
            double_fault_stack: 0,
            machine_check_stack: 0,
        }
    }

    /// Initialize the KPCR for a specific processor
    ///
    /// # Safety
    /// - Must be called once per processor during initialization
    /// - `prcb` must be a valid pointer to the processor's KPRCB
    pub unsafe fn init(&mut self, processor_number: u32, prcb: *mut KPrcb) {
        self.self_pcr = self as *mut KPcr;
        self.current_prcb = prcb;
        self.irql = irql::HIGH_LEVEL; // Start at HIGH_LEVEL during init
        self.number = processor_number;
        self.set_member = 1u64 << processor_number;
        self.interrupt_count = 0;
        self.debugger_active = 0;
        self.dpc_routine_active = 0;
    }

    /// Get a reference to the PRCB
    #[inline]
    pub fn prcb(&self) -> &KPrcb {
        unsafe { &*self.current_prcb }
    }

    /// Get a mutable reference to the PRCB
    ///
    /// # Safety
    /// Caller must ensure proper synchronization
    #[inline]
    pub unsafe fn prcb_mut(&mut self) -> &mut KPrcb {
        &mut *self.current_prcb
    }
}

impl Default for KPcr {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global KPCR Array
// ============================================================================

/// Array of KPCRs for all processors
static mut PCR_ARRAY: [KPcr; MAX_CPUS] = [const { KPcr::new() }; MAX_CPUS];

/// Initialize a specific processor's KPCR
///
/// # Safety
/// Must be called once per CPU during initialization, after KPRCB is initialized
pub unsafe fn init_kpcr(cpu_id: usize, prcb: *mut KPrcb) {
    if cpu_id < MAX_CPUS {
        PCR_ARRAY[cpu_id].init(cpu_id as u32, prcb);
    }
}

/// Get a reference to the current processor's KPCR
///
/// Note: In our implementation, we use GS to point directly to KPRCB
/// for efficiency, so this function constructs the KPCR reference from
/// the PRCB's processor number.
#[inline]
pub fn get_current_kpcr() -> &'static KPcr {
    let prcb = super::prcb::get_current_prcb();
    unsafe { &PCR_ARRAY[prcb.number as usize] }
}

/// Get a mutable reference to the current processor's KPCR
///
/// # Safety
/// Caller must ensure proper synchronization
#[inline]
pub unsafe fn get_current_kpcr_mut() -> &'static mut KPcr {
    let prcb = super::prcb::get_current_prcb();
    &mut PCR_ARRAY[prcb.number as usize]
}

/// Get a reference to a specific processor's KPCR
#[inline]
pub unsafe fn get_kpcr(cpu_id: usize) -> Option<&'static KPcr> {
    if cpu_id < MAX_CPUS {
        Some(&PCR_ARRAY[cpu_id])
    } else {
        None
    }
}

// ============================================================================
// IRQL Management Functions
// ============================================================================

/// Get the current IRQL
#[inline]
pub fn ke_get_current_irql() -> Kirql {
    get_current_kpcr().irql
}

/// Raise IRQL to a new level
///
/// # Safety
/// - New IRQL must be >= current IRQL
/// - Caller must restore IRQL properly
#[inline]
pub unsafe fn ke_raise_irql(new_irql: Kirql) -> Kirql {
    let pcr = get_current_kpcr_mut();
    let old_irql = pcr.irql;

    debug_assert!(
        new_irql >= old_irql,
        "ke_raise_irql: new IRQL {} < current IRQL {}",
        new_irql,
        old_irql
    );

    pcr.irql = new_irql;

    // If raising to DISPATCH_LEVEL or above, disable preemption
    if new_irql >= irql::DISPATCH_LEVEL && old_irql < irql::DISPATCH_LEVEL {
        // Disable interrupts for now (proper IRQL would mask specific interrupts)
        core::arch::asm!("cli", options(nomem, nostack));
    }

    old_irql
}

/// Lower IRQL to a previous level
///
/// # Safety
/// - New IRQL must be <= current IRQL
/// - Should be the value returned from ke_raise_irql
#[inline]
pub unsafe fn ke_lower_irql(new_irql: Kirql) {
    let pcr = get_current_kpcr_mut();
    let old_irql = pcr.irql;

    debug_assert!(
        new_irql <= old_irql,
        "ke_lower_irql: new IRQL {} > current IRQL {}",
        new_irql,
        old_irql
    );

    pcr.irql = new_irql;

    // If lowering below DISPATCH_LEVEL, may need to process DPCs/APCs
    if new_irql < irql::DISPATCH_LEVEL && old_irql >= irql::DISPATCH_LEVEL {
        // Check for pending DPCs
        let prcb = pcr.prcb();
        if prcb.dpc_pending {
            // Would call KiRetireDpcList here
        }

        // Re-enable interrupts
        core::arch::asm!("sti", options(nomem, nostack));
    }

    // If lowering to PASSIVE_LEVEL, check for APCs
    if new_irql == irql::PASSIVE_LEVEL && old_irql > irql::PASSIVE_LEVEL {
        // Would check for kernel APCs here
    }
}

/// Raise IRQL to DISPATCH_LEVEL (convenience function)
#[inline]
pub unsafe fn ke_raise_irql_to_dpc_level() -> Kirql {
    ke_raise_irql(irql::DISPATCH_LEVEL)
}

/// Raise IRQL to SYNCH_LEVEL (convenience function)
#[inline]
pub unsafe fn ke_raise_irql_to_synch_level() -> Kirql {
    ke_raise_irql(irql::SYNCH_LEVEL)
}

// ============================================================================
// Interrupt Management
// ============================================================================

/// Enter an interrupt handler
///
/// Increments the interrupt count and raises IRQL.
///
/// # Safety
/// Must be called at the start of an interrupt handler
#[inline]
pub unsafe fn ki_enter_interrupt(vector_irql: Kirql) -> Kirql {
    let pcr = get_current_kpcr_mut();
    pcr.interrupt_count += 1;
    ke_raise_irql(vector_irql)
}

/// Exit an interrupt handler
///
/// Decrements the interrupt count and lowers IRQL.
///
/// # Safety
/// Must be called at the end of an interrupt handler with the saved IRQL
#[inline]
pub unsafe fn ki_exit_interrupt(saved_irql: Kirql) {
    let pcr = get_current_kpcr_mut();
    pcr.interrupt_count -= 1;
    ke_lower_irql(saved_irql);
}

/// Check if currently in an interrupt context
#[inline]
pub fn ke_is_executing_interrupt() -> bool {
    get_current_kpcr().interrupt_count > 0
}

/// Check if DPC routine is active
#[inline]
pub fn ke_is_dpc_active() -> bool {
    get_current_kpcr().dpc_routine_active != 0
}
