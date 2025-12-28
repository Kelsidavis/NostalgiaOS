//! Executive Worker Thread Pool (System Work Queue)
//!
//! Provides a pool of system threads that can execute work items.
//! This allows drivers and kernel components to defer work to a
//! thread context without creating their own threads.
//!
//! # NT Semantics
//!
//! Three queues with different priorities:
//! - **CriticalWorkQueue**: Highest priority, time-critical work
//! - **DelayedWorkQueue**: Normal priority, general work
//! - **HyperCriticalWorkQueue**: Emergency work during low resources
//!
//! # Usage
//! ```
//! // Define a work routine
//! extern "C" fn my_work(context: *mut c_void) {
//!     // Do work...
//! }
//!
//! // Queue work
//! let mut item = WorkQueueItem::new(my_work, context_ptr);
//! ex_queue_work_item(&mut item, WorkQueueType::DelayedWorkQueue);
//! ```

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::ke::list::ListEntry;
use crate::ke::spinlock::SpinLock;
// KEvent and EventType reserved for future use with work queue signaling

/// Work queue types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WorkQueueType {
    /// Time-critical work, higher priority
    CriticalWorkQueue = 0,
    /// Normal work items
    DelayedWorkQueue = 1,
    /// Emergency work during resource exhaustion
    HyperCriticalWorkQueue = 2,
}

/// Work routine signature
pub type WorkerRoutine = extern "C" fn(context: *mut c_void);

/// Work queue item
///
/// Equivalent to NT's WORK_QUEUE_ITEM
#[repr(C)]
pub struct WorkQueueItem {
    /// List entry for queue management
    pub list_entry: ListEntry,
    /// Work routine to execute
    worker_routine: Option<WorkerRoutine>,
    /// Context parameter passed to worker
    parameter: *mut c_void,
    /// Flag indicating if item is queued
    queued: AtomicBool,
}

// Safety: WorkQueueItem is designed for cross-thread use
unsafe impl Send for WorkQueueItem {}
unsafe impl Sync for WorkQueueItem {}

impl WorkQueueItem {
    /// Create a new work queue item
    pub const fn new() -> Self {
        Self {
            list_entry: ListEntry::new(),
            worker_routine: None,
            parameter: ptr::null_mut(),
            queued: AtomicBool::new(false),
        }
    }

    /// Initialize a work queue item with a routine and context
    pub fn init(&mut self, routine: WorkerRoutine, context: *mut c_void) {
        self.worker_routine = Some(routine);
        self.parameter = context;
        self.queued.store(false, Ordering::Relaxed);
        self.list_entry.init_head();
    }

    /// Check if the item is currently queued
    #[inline]
    pub fn is_queued(&self) -> bool {
        self.queued.load(Ordering::Relaxed)
    }

    /// Execute the work item
    fn execute(&self) {
        if let Some(routine) = self.worker_routine {
            routine(self.parameter);
        }
    }
}

impl Default for WorkQueueItem {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal work queue structure
struct WorkQueue {
    /// Queue of pending work items
    list_head: ListEntry,
    /// Lock protecting the queue
    lock: SpinLock<()>,
    /// Event signaled when work is available
    semaphore_count: AtomicUsize,
    /// Number of items in queue
    item_count: AtomicUsize,
}

impl WorkQueue {
    const fn new() -> Self {
        Self {
            list_head: ListEntry::new(),
            lock: SpinLock::new(()),
            semaphore_count: AtomicUsize::new(0),
            item_count: AtomicUsize::new(0),
        }
    }

    fn init(&mut self) {
        self.list_head.init_head();
    }

    /// Insert a work item into the queue
    fn insert(&mut self, item: &mut WorkQueueItem) -> bool {
        let _guard = self.lock.lock();

        // Check if already queued
        if item.queued.swap(true, Ordering::AcqRel) {
            return false; // Already queued
        }

        // Insert at tail
        unsafe {
            self.list_head.insert_tail(&mut item.list_entry);
        }

        self.item_count.fetch_add(1, Ordering::Relaxed);
        self.semaphore_count.fetch_add(1, Ordering::Release);

        true
    }

    /// Remove and return a work item from the queue
    fn remove(&mut self) -> Option<*mut WorkQueueItem> {
        let _guard = self.lock.lock();

        if self.list_head.is_empty() {
            return None;
        }

        unsafe {
            let entry = self.list_head.remove_head();
            if entry.is_null() {
                return None;
            }

            // Get the containing WorkQueueItem
            let item = crate::containing_record!(entry, WorkQueueItem, list_entry);

            (*item).queued.store(false, Ordering::Release);
            self.item_count.fetch_sub(1, Ordering::Relaxed);

            Some(item)
        }
    }

    /// Get the number of queued items
    fn count(&self) -> usize {
        self.item_count.load(Ordering::Relaxed)
    }
}

/// Maximum number of worker threads per queue
const MAX_WORKERS_PER_QUEUE: usize = 4;

/// Global work queues
static mut WORK_QUEUES: [WorkQueue; 3] = [
    WorkQueue::new(),
    WorkQueue::new(),
    WorkQueue::new(),
];

/// Flag indicating if work queues are initialized
static WORK_QUEUES_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the executive work queue system
///
/// # Safety
/// Must be called once during system initialization
pub unsafe fn ex_initialize_worker_threads() {
    if WORK_QUEUES_INITIALIZED.swap(true, Ordering::AcqRel) {
        return; // Already initialized
    }

    for queue in WORK_QUEUES.iter_mut() {
        queue.init();
    }

    // In a real implementation, we would create worker threads here
    // For now, work items must be processed manually or by a polling mechanism
}

/// Queue a work item for execution
///
/// The work item will be executed by a worker thread at the specified
/// priority level.
///
/// # Safety
/// - The work item must remain valid until the work routine completes
/// - The work routine must be safe to call from a worker thread context
pub unsafe fn ex_queue_work_item(
    item: &mut WorkQueueItem,
    queue_type: WorkQueueType,
) -> bool {
    if !WORK_QUEUES_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let queue_index = queue_type as usize;
    if queue_index >= WORK_QUEUES.len() {
        return false;
    }

    WORK_QUEUES[queue_index].insert(item)
}

/// Process pending work items (for testing/polling)
///
/// This is a helper function that processes work items synchronously.
/// In a real implementation, worker threads would do this automatically.
///
/// # Safety
/// Must be called from a safe thread context
pub unsafe fn ex_process_work_items(queue_type: WorkQueueType, max_items: usize) -> usize {
    if !WORK_QUEUES_INITIALIZED.load(Ordering::Acquire) {
        return 0;
    }

    let queue_index = queue_type as usize;
    if queue_index >= WORK_QUEUES.len() {
        return 0;
    }

    let queue = &mut WORK_QUEUES[queue_index];
    let mut processed = 0;

    while processed < max_items {
        if let Some(item) = queue.remove() {
            (*item).execute();
            processed += 1;
        } else {
            break;
        }
    }

    processed
}

/// Get the number of pending items in a queue
pub fn ex_get_work_queue_depth(queue_type: WorkQueueType) -> usize {
    let queue_index = queue_type as usize;
    if queue_index >= 3 {
        return 0;
    }

    unsafe { WORK_QUEUES[queue_index].count() }
}

// NT API compatibility type alias
#[allow(non_camel_case_types)]
pub type WORK_QUEUE_ITEM = WorkQueueItem;

#[allow(non_camel_case_types)]
pub type WORK_QUEUE_TYPE = WorkQueueType;

/// IO Work item (for IO manager work items)
#[repr(C)]
pub struct IoWorkItem {
    /// Base work queue item
    pub work_item: WorkQueueItem,
    /// Associated device object
    pub device_object: *mut c_void,
    /// IO-specific work routine
    io_work_routine: Option<IoWorkerRoutine>,
    /// Context for IO work
    io_context: *mut c_void,
}

/// IO work routine signature
pub type IoWorkerRoutine = extern "C" fn(device: *mut c_void, context: *mut c_void);

impl IoWorkItem {
    /// Create a new IO work item
    pub const fn new() -> Self {
        Self {
            work_item: WorkQueueItem::new(),
            device_object: ptr::null_mut(),
            io_work_routine: None,
            io_context: ptr::null_mut(),
        }
    }

    /// Initialize for a specific device
    pub fn init(&mut self, device: *mut c_void) {
        self.device_object = device;
        self.io_work_routine = None;
        self.io_context = ptr::null_mut();
    }

    /// Queue the IO work item
    ///
    /// # Safety
    /// The work item and device must remain valid until work completes
    pub unsafe fn queue(
        &mut self,
        routine: IoWorkerRoutine,
        context: *mut c_void,
        queue_type: WorkQueueType,
    ) {
        self.io_work_routine = Some(routine);
        self.io_context = context;

        // Set up the wrapper routine
        extern "C" fn io_work_wrapper(ctx: *mut c_void) {
            let item = ctx as *mut IoWorkItem;
            unsafe {
                if let Some(routine) = (*item).io_work_routine {
                    routine((*item).device_object, (*item).io_context);
                }
            }
        }

        // Get raw pointer to self before borrowing work_item
        let self_ptr = self as *mut _ as *mut c_void;
        self.work_item.init(io_work_wrapper, self_ptr);
        ex_queue_work_item(&mut self.work_item, queue_type);
    }
}

impl Default for IoWorkItem {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: IoWorkItem is designed for cross-thread use
unsafe impl Send for IoWorkItem {}
unsafe impl Sync for IoWorkItem {}

#[allow(non_camel_case_types)]
pub type IO_WORKITEM = IoWorkItem;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_work_queue_item() {
        static mut CALLED: bool = false;

        extern "C" fn test_routine(_ctx: *mut c_void) {
            unsafe { CALLED = true; }
        }

        let mut item = WorkQueueItem::new();
        item.init(test_routine, ptr::null_mut());

        assert!(!item.is_queued());
        item.execute();
        assert!(unsafe { CALLED });
    }
}
