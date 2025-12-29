//! Kernel Queue Implementation (KQUEUE)
//!
//! Kernel queues are dispatcher objects that support thread-safe
//! insertion and removal of work items. They are the foundation for:
//! - I/O Completion Ports
//! - Executive Worker Threads
//! - System work queues
//!
//! # Features
//! - FIFO/LIFO insertion
//! - Automatic thread wakeup when entries are inserted
//! - Maximum concurrency limit (controls how many threads can process entries)
//! - Thread association (tracks which threads are working on this queue)
//!
//! # Windows Equivalent
//! This implements NT's KQUEUE from queueobj.c
//!
//! # Usage
//! ```
//! static WORK_QUEUE: KQueue = KQueue::new();
//!
//! // Initialize with max 4 concurrent threads
//! WORK_QUEUE.init(4);
//!
//! // Worker threads call:
//! let entry = WORK_QUEUE.remove(WaitMode::Kernel, None);
//!
//! // Producers insert work:
//! WORK_QUEUE.insert(&mut work_item.list_entry);
//! ```

use super::dispatcher::{DispatcherHeader, DispatcherType, KWaitBlock, WaitType};
use super::list::ListEntry;
use super::prcb::get_current_prcb_mut;
use super::scheduler;
use super::thread::{KThread, ThreadState};
use crate::containing_record;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;

/// Maximum number of threads that can concurrently process queue entries
pub const DEFAULT_MAXIMUM_COUNT: u32 = 1;

/// Wait mode for queue operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WaitMode {
    /// Wait in kernel mode
    Kernel = 0,
    /// Wait in user mode
    User = 1,
}

/// Wait reason for threads waiting on queues
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QueueWaitReason {
    /// Thread is waiting for work on a queue
    WrQueue = 14,
}

/// Kernel Queue Object
///
/// KQUEUE is a dispatcher object that supports multiple producers
/// inserting work items and multiple consumers waiting to process them.
///
/// Equivalent to NT's KQUEUE structure.
#[repr(C)]
pub struct KQueue {
    /// Dispatcher header (must be first for casting)
    /// SignalState = number of entries in the queue
    pub header: DispatcherHeader,

    /// List of queued entries (work items)
    entry_list_head: UnsafeCell<ListEntry>,

    /// List of threads associated with this queue
    thread_list_head: UnsafeCell<ListEntry>,

    /// Current number of threads actively processing entries
    current_count: UnsafeCell<u32>,

    /// Maximum number of threads that can process concurrently
    maximum_count: UnsafeCell<u32>,
}

// Safety: KQueue is designed for multi-threaded access
unsafe impl Sync for KQueue {}
unsafe impl Send for KQueue {}

impl KQueue {
    /// Create a new uninitialized queue
    pub const fn new() -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherType::Queue),
            entry_list_head: UnsafeCell::new(ListEntry::new()),
            thread_list_head: UnsafeCell::new(ListEntry::new()),
            current_count: UnsafeCell::new(0),
            maximum_count: UnsafeCell::new(DEFAULT_MAXIMUM_COUNT),
        }
    }

    /// Initialize the queue (KeInitializeQueue)
    ///
    /// # Arguments
    /// * `count` - Maximum number of concurrent threads. If 0, uses 1 (single processor default).
    pub fn init(&mut self, count: u32) {
        self.header.init(DispatcherType::Queue, 0);

        unsafe {
            (*self.entry_list_head.get()).init_head();
            (*self.thread_list_head.get()).init_head();
            *self.current_count.get() = 0;
            *self.maximum_count.get() = if count == 0 { DEFAULT_MAXIMUM_COUNT } else { count };
        }
    }

    /// Get the number of entries in the queue (KeReadStateQueue)
    #[inline]
    pub fn read_state(&self) -> i32 {
        self.header.signal_state()
    }

    /// Check if the queue has entries
    #[inline]
    pub fn has_entries(&self) -> bool {
        unsafe { !(*self.entry_list_head.get()).is_empty() }
    }

    /// Get current count of active threads
    #[inline]
    pub fn current_count(&self) -> u32 {
        unsafe { *self.current_count.get() }
    }

    /// Get maximum concurrent thread count
    #[inline]
    pub fn maximum_count(&self) -> u32 {
        unsafe { *self.maximum_count.get() }
    }

    /// Insert an entry at the tail of the queue (KeInsertQueue)
    ///
    /// FIFO discipline - entries are processed in order of insertion.
    /// If a thread is waiting and the concurrency limit allows, the thread is woken.
    ///
    /// # Arguments
    /// * `entry` - The list entry to insert (must be embedded in a work item)
    ///
    /// # Returns
    /// The previous signal state (number of entries before insertion)
    ///
    /// # Safety
    /// The entry must remain valid until removed from the queue.
    pub unsafe fn insert(&self, entry: *mut ListEntry) -> i32 {
        self.insert_internal(entry, false)
    }

    /// Insert an entry at the head of the queue (KeInsertHeadQueue)
    ///
    /// LIFO discipline for this entry - it will be processed next.
    ///
    /// # Arguments
    /// * `entry` - The list entry to insert
    ///
    /// # Returns
    /// The previous signal state (number of entries before insertion)
    pub unsafe fn insert_head(&self, entry: *mut ListEntry) -> i32 {
        self.insert_internal(entry, true)
    }

    /// Internal insert implementation
    unsafe fn insert_internal(&self, entry: *mut ListEntry, at_head: bool) -> i32 {
        let old_state = self.header.signal_state();

        // Try to wake a waiting thread if we can
        if self.header.has_waiters() && *self.current_count.get() < *self.maximum_count.get() {
            // Remove a waiting thread and give it this entry directly
            let wait_entry = self.header.wait_list().remove_tail();
            let wait_block = containing_record!(wait_entry, KWaitBlock, wait_list_entry);
            let thread = (*wait_block).thread;

            // Give the entry to the thread directly via wait status
            (*thread).wait_status = entry as isize;

            // Remove from wait list if present
            if !(*thread).wait_list_entry.is_empty() {
                (*thread).wait_list_entry.remove_entry();
            }

            // Increment active thread count
            *self.current_count.get() += 1;

            // Clear wait reason
            (*thread).wait_reason = 0;

            // Make thread ready
            (*thread).state = ThreadState::Ready;
            scheduler::ki_ready_thread(thread);
        } else {
            // No waiting thread available - add to queue
            self.header.set_signal_state(old_state + 1);

            let list = &mut *self.entry_list_head.get();
            if at_head {
                list.insert_head(entry);
            } else {
                list.insert_tail(entry);
            }
        }

        old_state
    }

    /// Remove an entry from the queue (KeRemoveQueue)
    ///
    /// If no entries are available, the thread waits until one is inserted.
    /// This is the main function called by worker threads to get work.
    ///
    /// # Arguments
    /// * `wait_mode` - Kernel or User mode wait
    /// * `timeout` - Optional timeout (None = infinite wait)
    ///
    /// # Returns
    /// Pointer to the removed entry, or:
    /// - STATUS_TIMEOUT as pointer if timed out
    /// - STATUS_USER_APC as pointer if user APC pending (user mode only)
    ///
    /// # Safety
    /// Must be called from thread context.
    pub unsafe fn remove(&self, wait_mode: WaitMode, timeout: Option<i64>) -> *mut ListEntry {
        let prcb = get_current_prcb_mut();
        let thread = prcb.current_thread;

        // Get old queue (if thread was associated with another queue)
        let old_queue = (*thread).queue as *mut KQueue;
        (*thread).queue = self as *const _ as *mut c_void;

        if !ptr::eq(self as *const _, old_queue) {
            // Thread is switching queues
            if !old_queue.is_null() {
                // Remove from old queue's thread list
                (*thread).queue_list_entry.remove_entry();
                // Try to activate a waiter on the old queue
                Self::activate_waiter_static(old_queue);
            }

            // Add to this queue's thread list
            (*self.thread_list_head.get()).insert_tail(&mut (*thread).queue_list_entry);
        } else {
            // Same queue - decrement current count (we're about to wait or get entry)
            *self.current_count.get() = (*self.current_count.get()).saturating_sub(1);
        }

        // Main wait loop
        loop {
            // Check if there's an entry available and we can process it
            let list = &mut *self.entry_list_head.get();
            if !list.is_empty() && *self.current_count.get() < *self.maximum_count.get() {
                // Get entry
                let old_state = self.header.signal_state();
                self.header.set_signal_state(old_state - 1);
                *self.current_count.get() += 1;

                let entry = list.remove_head();
                (*entry).init_head(); // Clear the entry's links
                return entry;
            }

            // Check for zero timeout (try without waiting)
            if let Some(t) = timeout {
                if t == 0 {
                    *self.current_count.get() += 1;
                    return STATUS_TIMEOUT as *mut ListEntry;
                }
            }

            // Check for user APC pending in user mode
            if wait_mode == WaitMode::User && (*thread).user_apc_pending {
                *self.current_count.get() += 1;
                return STATUS_USER_APC as *mut ListEntry;
            }

            // Must wait for an entry
            let mut wait_block = KWaitBlock::new();
            wait_block.init(
                thread,
                &self.header as *const _ as *mut DispatcherHeader,
                WaitType::WaitAny,
            );

            // Add to queue's wait list (at tail for FIFO wake order)
            self.header.wait_list().insert_tail(&mut wait_block.wait_list_entry);

            // Set thread state to waiting
            (*thread).state = ThreadState::Waiting;
            (*thread).wait_reason = QueueWaitReason::WrQueue as u8;

            // Yield to scheduler
            scheduler::ki_dispatch_interrupt();

            // Woken up - check why
            (*thread).wait_reason = 0;

            // If wait_status is a valid pointer, it's the entry given to us directly
            let wait_status = (*thread).wait_status;
            if wait_status > 0x1000 {
                // Valid pointer - return the entry
                return wait_status as *mut ListEntry;
            }

            // Otherwise check status codes
            if wait_status == STATUS_KERNEL_APC {
                // Kernel APC - loop and try again
                *self.current_count.get() = (*self.current_count.get()).saturating_sub(1);
                continue;
            }

            if wait_status == STATUS_TIMEOUT {
                return STATUS_TIMEOUT as *mut ListEntry;
            }

            if wait_status == STATUS_USER_APC {
                return STATUS_USER_APC as *mut ListEntry;
            }

            // Try to get entry from queue (may have been queued while we were waking)
            *self.current_count.get() = (*self.current_count.get()).saturating_sub(1);
        }
    }

    /// Try to remove an entry without waiting
    ///
    /// # Returns
    /// Some(entry) if an entry was available, None otherwise
    pub unsafe fn try_remove(&self) -> Option<*mut ListEntry> {
        let list = &mut *self.entry_list_head.get();

        if list.is_empty() || *self.current_count.get() >= *self.maximum_count.get() {
            return None;
        }

        let old_state = self.header.signal_state();
        self.header.set_signal_state(old_state - 1);
        *self.current_count.get() += 1;

        let entry = list.remove_head();
        (*entry).init_head();
        Some(entry)
    }

    /// Run down the queue (KeRundownQueue)
    ///
    /// Removes all entries and threads from the queue.
    /// Used when destroying the queue.
    ///
    /// # Returns
    /// Pointer to the first entry in the list, or None if empty.
    /// The returned list is detached from the queue.
    pub unsafe fn rundown(&mut self) -> Option<*mut ListEntry> {
        let list = &mut *self.entry_list_head.get();
        let thread_list = &mut *self.thread_list_head.get();

        // Get first entry if any
        let first_entry = if list.is_empty() {
            None
        } else {
            // Detach the list - get the first entry
            let first = list.flink;
            // The list is now detached, just return the first entry
            // Caller is responsible for walking the rest
            Some(first)
        };

        // Remove all threads from thread list
        while !thread_list.is_empty() {
            let entry = thread_list.remove_head();
            let thread = containing_record!(entry, KThread, queue_list_entry);
            (*thread).queue = ptr::null_mut();
        }

        // Clear the queue
        list.init_head();
        thread_list.init_head();
        self.header.set_signal_state(0);
        *self.current_count.get() = 0;

        first_entry
    }

    /// Internal: try to activate a waiter on a queue
    unsafe fn activate_waiter_static(queue: *mut KQueue) {
        if queue.is_null() {
            return;
        }

        let queue = &*queue;

        // Check if there are entries and waiters
        if !(*queue.entry_list_head.get()).is_empty() && queue.header.has_waiters() {
            // Wake a waiter
            let wait_entry = queue.header.wait_list().remove_tail();
            let wait_block = containing_record!(wait_entry, KWaitBlock, wait_list_entry);
            let thread = (*wait_block).thread;

            (*thread).state = ThreadState::Ready;
            scheduler::ki_ready_thread(thread);
        }
    }
}

impl Default for KQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Status code: wait timed out
const STATUS_TIMEOUT: isize = 0x00000102;

/// Status code: kernel APC delivered
const STATUS_KERNEL_APC: isize = 0x00000100;

/// Status code: user APC pending
const STATUS_USER_APC: isize = 0x000000C0;

// ============================================================================
// Public API Functions (NT-compatible naming)
// ============================================================================

/// Initialize a kernel queue object (KeInitializeQueue)
///
/// # Arguments
/// * `queue` - Queue to initialize
/// * `count` - Maximum concurrent threads (0 = use default)
pub fn ke_initialize_queue(queue: &mut KQueue, count: u32) {
    queue.init(count);
}

/// Read the state of a queue (KeReadStateQueue)
///
/// Returns the number of entries in the queue.
pub fn ke_read_state_queue(queue: &KQueue) -> i32 {
    queue.read_state()
}

/// Insert an entry at the tail of a queue (KeInsertQueue)
///
/// # Returns
/// Previous signal state (entry count)
///
/// # Safety
/// Entry must remain valid until removed.
pub unsafe fn ke_insert_queue(queue: &KQueue, entry: *mut ListEntry) -> i32 {
    queue.insert(entry)
}

/// Insert an entry at the head of a queue (KeInsertHeadQueue)
///
/// # Returns
/// Previous signal state (entry count)
///
/// # Safety
/// Entry must remain valid until removed.
pub unsafe fn ke_insert_head_queue(queue: &KQueue, entry: *mut ListEntry) -> i32 {
    queue.insert_head(entry)
}

/// Remove an entry from a queue, waiting if necessary (KeRemoveQueue)
///
/// # Returns
/// Pointer to removed entry, or status code as pointer if wait was interrupted.
///
/// # Safety
/// Must be called from thread context.
pub unsafe fn ke_remove_queue(
    queue: &KQueue,
    wait_mode: WaitMode,
    timeout: Option<i64>,
) -> *mut ListEntry {
    queue.remove(wait_mode, timeout)
}

/// Run down a queue (KeRundownQueue)
///
/// Removes all entries and threads, returns first entry or None.
///
/// # Safety
/// No threads should be waiting on the queue.
pub unsafe fn ke_rundown_queue(queue: &mut KQueue) -> Option<*mut ListEntry> {
    queue.rundown()
}
