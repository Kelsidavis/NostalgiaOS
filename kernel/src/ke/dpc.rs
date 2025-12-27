//! Deferred Procedure Call (DPC) Implementation
//!
//! DPCs allow code running at high IRQL (interrupt handlers) to defer
//! work to a lower IRQL (DISPATCH_LEVEL). This is essential because
//! interrupt handlers should complete quickly and not do extensive processing.
//!
//! # Usage
//! ```
//! static MY_DPC: KDpc = KDpc::new();
//!
//! // Initialize once
//! MY_DPC.init(my_dpc_routine);
//!
//! // Queue from interrupt handler
//! MY_DPC.queue(system_arg1, system_arg2);
//! ```
//!
//! # NT Compatibility
//! Equivalent to NT's KDPC / KeInitializeDpc / KeInsertQueueDpc

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use super::list::ListEntry;
use super::prcb::get_current_prcb_mut;
use crate::containing_record;

/// DPC routine function signature
///
/// # Arguments
/// * `dpc` - Pointer to the DPC object
/// * `deferred_context` - Context set during initialization
/// * `system_argument1` - First argument passed to queue
/// * `system_argument2` - Second argument passed to queue
pub type DpcRoutine = fn(
    dpc: *mut KDpc,
    deferred_context: usize,
    system_argument1: usize,
    system_argument2: usize,
);

/// DPC importance level
///
/// Determines where in the DPC queue the DPC is inserted
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpcImportance {
    /// Insert at tail of queue (default)
    Low = 0,
    /// Insert at tail of queue
    Medium = 1,
    /// Insert at head of queue
    High = 2,
}

/// Kernel Deferred Procedure Call object
///
/// Equivalent to NT's KDPC structure
#[repr(C)]
pub struct KDpc {
    /// Entry for linking into DPC queue
    dpc_list_entry: UnsafeCell<ListEntry>,

    /// The routine to call when DPC fires
    deferred_routine: UnsafeCell<Option<DpcRoutine>>,

    /// Context passed to routine (set during init)
    deferred_context: UnsafeCell<usize>,

    /// First system argument (set during queue)
    system_argument1: UnsafeCell<usize>,

    /// Second system argument (set during queue)
    system_argument2: UnsafeCell<usize>,

    /// Target processor number (0 = current, 0xFFFFFFFF = any)
    processor_number: UnsafeCell<u32>,

    /// DPC importance
    importance: UnsafeCell<DpcImportance>,

    /// Whether this DPC is currently queued
    inserted: AtomicBool,
}

// Safety: KDpc is designed for multi-threaded access with atomic operations
unsafe impl Sync for KDpc {}
unsafe impl Send for KDpc {}

impl KDpc {
    /// Create a new uninitialized DPC
    pub const fn new() -> Self {
        Self {
            dpc_list_entry: UnsafeCell::new(ListEntry::new()),
            deferred_routine: UnsafeCell::new(None),
            deferred_context: UnsafeCell::new(0),
            system_argument1: UnsafeCell::new(0),
            system_argument2: UnsafeCell::new(0),
            processor_number: UnsafeCell::new(0),
            importance: UnsafeCell::new(DpcImportance::Medium),
            inserted: AtomicBool::new(false),
        }
    }

    /// Initialize the DPC with a routine and context
    ///
    /// Equivalent to KeInitializeDpc
    ///
    /// # Arguments
    /// * `routine` - Function to call when DPC fires
    /// * `context` - Context passed to the routine
    pub fn init(&self, routine: DpcRoutine, context: usize) {
        unsafe {
            (*self.dpc_list_entry.get()).init_head();
            *self.deferred_routine.get() = Some(routine);
            *self.deferred_context.get() = context;
            *self.system_argument1.get() = 0;
            *self.system_argument2.get() = 0;
            *self.processor_number.get() = 0;
            *self.importance.get() = DpcImportance::Medium;
        }
        self.inserted.store(false, Ordering::Release);
    }

    /// Initialize with just a routine (no context)
    pub fn init_routine(&self, routine: DpcRoutine) {
        self.init(routine, 0);
    }

    /// Set the DPC importance
    pub fn set_importance(&self, importance: DpcImportance) {
        unsafe {
            *self.importance.get() = importance;
        }
    }

    /// Set the target processor for this DPC
    ///
    /// # Arguments
    /// * `processor` - Processor number, or 0xFFFFFFFF for any processor
    pub fn set_target_processor(&self, processor: u32) {
        unsafe {
            *self.processor_number.get() = processor;
        }
    }

    /// Queue the DPC for execution
    ///
    /// Equivalent to KeInsertQueueDpc
    ///
    /// # Arguments
    /// * `system_arg1` - First system argument
    /// * `system_arg2` - Second system argument
    ///
    /// # Returns
    /// true if the DPC was queued, false if it was already queued
    ///
    /// # Safety
    /// Can be called from any IRQL
    pub unsafe fn queue(&self, system_arg1: usize, system_arg2: usize) -> bool {
        // Check if already queued - atomic swap
        if self.inserted.swap(true, Ordering::AcqRel) {
            // Already queued
            return false;
        }

        // Set system arguments
        *self.system_argument1.get() = system_arg1;
        *self.system_argument2.get() = system_arg2;

        // Get PRCB and add to DPC queue
        let prcb = get_current_prcb_mut();
        let importance = *self.importance.get();

        // Insert based on importance
        let entry = &mut *self.dpc_list_entry.get();
        match importance {
            DpcImportance::High => {
                // Insert at head
                prcb.dpc_queue_head.insert_head(entry);
            }
            DpcImportance::Medium | DpcImportance::Low => {
                // Insert at tail
                prcb.dpc_queue_head.insert_tail(entry);
            }
        }

        // Set DPC pending flag
        prcb.dpc_pending = true;

        true
    }

    /// Queue the DPC with no arguments
    pub unsafe fn queue_no_args(&self) -> bool {
        self.queue(0, 0)
    }

    /// Check if this DPC is currently queued
    #[inline]
    pub fn is_queued(&self) -> bool {
        self.inserted.load(Ordering::Acquire)
    }

    /// Remove DPC from queue (cancel pending DPC)
    ///
    /// Equivalent to KeRemoveQueueDpc
    ///
    /// # Returns
    /// true if the DPC was removed, false if it wasn't queued
    pub unsafe fn remove(&self) -> bool {
        // Check if queued
        if !self.inserted.swap(false, Ordering::AcqRel) {
            return false;
        }

        // Remove from queue
        let entry = &mut *self.dpc_list_entry.get();
        entry.remove_entry();

        true
    }

    /// Execute this DPC
    ///
    /// # Safety
    /// Must be called at DISPATCH_LEVEL
    unsafe fn execute(&self) {
        // Clear inserted flag first
        self.inserted.store(false, Ordering::Release);

        // Get routine and arguments
        if let Some(routine) = *self.deferred_routine.get() {
            let context = *self.deferred_context.get();
            let arg1 = *self.system_argument1.get();
            let arg2 = *self.system_argument2.get();

            // Call the DPC routine
            routine(
                self as *const KDpc as *mut KDpc,
                context,
                arg1,
                arg2,
            );
        }
    }
}

impl Default for KDpc {
    fn default() -> Self {
        Self::new()
    }
}

/// Retire (execute) all pending DPCs on the current processor
///
/// Equivalent to KiRetireDpcList
///
/// # Safety
/// Must be called at DISPATCH_LEVEL (typically from timer interrupt)
pub unsafe fn ki_retire_dpc_list() {
    let prcb = get_current_prcb_mut();

    // Check if any DPCs pending
    if !prcb.dpc_pending {
        return;
    }

    // Clear pending flag (we'll set it again if new DPCs arrive during processing)
    prcb.dpc_pending = false;

    // Process all DPCs in the queue
    while !prcb.dpc_queue_head.is_empty() {
        // Remove first DPC from queue
        let entry = prcb.dpc_queue_head.remove_head();

        // Get the DPC structure
        let dpc = containing_record!(entry, KDpc, dpc_list_entry);

        // Execute the DPC
        (*dpc).execute();
    }
}

/// Check if there are pending DPCs on the current processor
#[inline]
pub fn ki_check_dpc_pending() -> bool {
    super::prcb::get_current_prcb().dpc_pending
}

/// Request a DPC interrupt
///
/// This sets the DPC pending flag and requests a software interrupt
/// to process DPCs. Used when queuing a DPC from below DISPATCH_LEVEL.
pub unsafe fn ki_request_software_interrupt() {
    let prcb = get_current_prcb_mut();
    prcb.dpc_pending = true;
    // In a full implementation, this would trigger a software interrupt
    // For now, DPCs are processed in the timer interrupt
}
