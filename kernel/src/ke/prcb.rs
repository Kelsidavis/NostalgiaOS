//! Kernel Processor Control Block (KPRCB)
//!
//! The KPRCB contains per-processor state including:
//! - Current and next thread pointers
//! - Ready queues (32 priority levels)
//! - Idle thread pointer
//! - Ready summary bitmap for O(1) thread selection
//!
//! In a multiprocessor system, each CPU has its own KPRCB.

use core::ptr;
use super::list::ListEntry;
use super::thread::{KThread, constants::MAXIMUM_PRIORITY};

/// Maximum number of processors (from ACPI)
pub use crate::hal::acpi::MAX_PROCESSORS as MAX_CPUS;

/// Kernel Processor Control Block
///
/// This structure contains per-processor scheduling state.
/// Modeled after Windows NT's KPRCB structure.
#[repr(C)]
pub struct KPrcb {
    /// Processor number (0 for BSP)
    pub number: u32,

    /// Currently running thread
    pub current_thread: *mut KThread,

    /// Thread selected to run next (set by scheduler)
    pub next_thread: *mut KThread,

    /// Idle thread for this processor
    pub idle_thread: *mut KThread,

    /// Bitmap of non-empty ready queues
    /// Bit N is set if ready_queues[N] is non-empty
    /// Allows O(1) highest priority thread selection using BSR instruction
    pub ready_summary: u32,

    /// Ready queues (one per priority level 0-31)
    /// Higher index = higher priority
    pub ready_queues: [ListEntry; MAXIMUM_PRIORITY],

    /// DPC queue head (for deferred procedure calls)
    pub dpc_queue_head: ListEntry,

    /// Number of context switches on this processor
    pub context_switches: u64,

    /// Quantum end flag (set by timer, cleared by scheduler)
    pub quantum_end: bool,

    /// DPC pending flag
    pub dpc_pending: bool,
}

impl KPrcb {
    /// Create a new uninitialized PRCB
    pub const fn new() -> Self {
        const EMPTY_LIST: ListEntry = ListEntry::new();

        Self {
            number: 0,
            current_thread: ptr::null_mut(),
            next_thread: ptr::null_mut(),
            idle_thread: ptr::null_mut(),
            ready_summary: 0,
            ready_queues: [EMPTY_LIST; MAXIMUM_PRIORITY],
            dpc_queue_head: ListEntry::new(),
            context_switches: 0,
            quantum_end: false,
            dpc_pending: false,
        }
    }

    /// Initialize the PRCB
    pub fn init(&mut self, processor_number: u32) {
        self.number = processor_number;
        self.current_thread = ptr::null_mut();
        self.next_thread = ptr::null_mut();
        self.idle_thread = ptr::null_mut();
        self.ready_summary = 0;
        self.context_switches = 0;
        self.quantum_end = false;
        self.dpc_pending = false;

        // Initialize all ready queue heads
        for queue in self.ready_queues.iter_mut() {
            queue.init_head();
        }

        // Initialize DPC queue
        self.dpc_queue_head.init_head();
    }

    /// Find the highest priority non-empty ready queue
    ///
    /// Returns the priority level (0-31) or None if all queues are empty.
    /// Uses the ready_summary bitmap for O(1) lookup.
    #[inline]
    pub fn find_highest_ready_priority(&self) -> Option<usize> {
        if self.ready_summary == 0 {
            return None;
        }

        // Find highest set bit (highest priority with ready threads)
        // 31 - leading_zeros gives the index of the highest set bit
        let priority = 31 - self.ready_summary.leading_zeros();
        Some(priority as usize)
    }

    /// Check if any threads are ready to run
    #[inline]
    pub fn has_ready_threads(&self) -> bool {
        self.ready_summary != 0
    }

    /// Set the ready summary bit for a priority level
    #[inline]
    pub fn set_ready_bit(&mut self, priority: usize) {
        self.ready_summary |= 1 << priority;
    }

    /// Clear the ready summary bit for a priority level
    #[inline]
    pub fn clear_ready_bit(&mut self, priority: usize) {
        self.ready_summary &= !(1 << priority);
    }
}

impl Default for KPrcb {
    fn default() -> Self {
        Self::new()
    }
}

/// Array of PRCBs for all processors
static mut PRCB_ARRAY: [KPrcb; MAX_CPUS] = [const { KPrcb::new() }; MAX_CPUS];

/// Number of active CPUs (updated as APs start)
static mut ACTIVE_CPU_COUNT: usize = 1;

/// Initialize a specific processor's PRCB
///
/// # Safety
/// Must be called once per CPU during initialization
pub unsafe fn init_prcb(cpu_id: usize) {
    if cpu_id < MAX_CPUS {
        PRCB_ARRAY[cpu_id].init(cpu_id as u32);

        // Set GS base to point to this CPU's PRCB
        let prcb_addr = &PRCB_ARRAY[cpu_id] as *const KPrcb as u64;
        crate::arch::x86_64::percpu::set_gs_base(prcb_addr);
    }
}

/// Initialize the boot processor's PRCB
///
/// # Safety
/// Must be called exactly once during kernel initialization
pub unsafe fn init_bsp_prcb() {
    init_prcb(0);
}

/// Get a reference to the current processor's PRCB (via GS segment)
///
/// This reads the PRCB pointer from the GS segment base, allowing
/// fast per-CPU data access without locks.
pub fn get_current_prcb() -> &'static KPrcb {
    unsafe {
        let prcb_ptr = crate::arch::x86_64::percpu::get_gs_base() as *const KPrcb;
        if prcb_ptr.is_null() {
            // GS not initialized yet, fall back to BSP (during early boot)
            &PRCB_ARRAY[0]
        } else {
            &*prcb_ptr
        }
    }
}

/// Get a mutable reference to the current processor's PRCB (via GS segment)
///
/// # Safety
/// Caller must ensure proper synchronization (typically IRQL >= DISPATCH_LEVEL)
pub unsafe fn get_current_prcb_mut() -> &'static mut KPrcb {
    let prcb_ptr = crate::arch::x86_64::percpu::get_gs_base() as *mut KPrcb;
    if prcb_ptr.is_null() {
        // GS not initialized yet, fall back to BSP (during early boot)
        &mut PRCB_ARRAY[0]
    } else {
        &mut *prcb_ptr
    }
}

/// Get a reference to a specific CPU's PRCB by index
///
/// # Safety
/// Caller must ensure cpu_id is valid (< active CPU count)
pub unsafe fn get_prcb(cpu_id: usize) -> Option<&'static KPrcb> {
    if cpu_id < MAX_CPUS {
        Some(&PRCB_ARRAY[cpu_id])
    } else {
        None
    }
}

/// Get a mutable reference to a specific CPU's PRCB by index
///
/// # Safety
/// Caller must ensure cpu_id is valid and proper synchronization
pub unsafe fn get_prcb_mut(cpu_id: usize) -> Option<&'static mut KPrcb> {
    if cpu_id < MAX_CPUS {
        Some(&mut PRCB_ARRAY[cpu_id])
    } else {
        None
    }
}

/// Get the number of active CPUs
pub fn get_active_cpu_count() -> usize {
    unsafe { ACTIVE_CPU_COUNT }
}

/// Increment the active CPU count (called when an AP starts)
///
/// # Safety
/// Must be called with proper synchronization during AP startup
pub unsafe fn increment_active_cpu_count() {
    ACTIVE_CPU_COUNT += 1;
}

/// Get the currently running thread
#[inline]
pub fn get_current_thread() -> *mut KThread {
    get_current_prcb().current_thread
}

/// Set the currently running thread
///
/// # Safety
/// Must be called from scheduler context with proper synchronization
#[inline]
pub unsafe fn set_current_thread(thread: *mut KThread) {
    get_current_prcb_mut().current_thread = thread;
}
