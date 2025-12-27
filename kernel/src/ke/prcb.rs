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

/// The boot processor's PRCB (processor 0)
static mut BSP_PRCB: KPrcb = KPrcb::new();

/// Initialize the boot processor's PRCB
///
/// # Safety
/// Must be called exactly once during kernel initialization
pub unsafe fn init_bsp_prcb() {
    BSP_PRCB.init(0);
}

/// Get a reference to the current processor's PRCB
///
/// For now, this always returns the BSP's PRCB since we only support
/// single processor. In SMP, this would read from GS segment or similar.
pub fn get_current_prcb() -> &'static KPrcb {
    unsafe { &BSP_PRCB }
}

/// Get a mutable reference to the current processor's PRCB
///
/// # Safety
/// Caller must ensure proper synchronization (typically IRQL >= DISPATCH_LEVEL)
pub unsafe fn get_current_prcb_mut() -> &'static mut KPrcb {
    &mut BSP_PRCB
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
