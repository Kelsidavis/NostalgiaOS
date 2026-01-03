//! Stack Overflow Worker Thread Support (FsRtl Stack Overflow)
//!
//! Provides worker threads for file systems to use when running low on
//! kernel stack space during paging I/O operations.
//!
//! # Background
//!
//! File system drivers often call recursively (filter drivers, nested I/O).
//! During paging I/O, stack overflow would be fatal (can't page in more stack).
//! This module provides dedicated worker threads with clean stacks for
//! completing I/O when the original thread is running low on stack.
//!
//! # Design
//!
//! - Two worker queues: normal I/O and paging file I/O
//! - Paging file queue has priority (must complete to free memory)
//! - File systems call FsRtlPostStackOverflow to queue work
//! - Worker thread executes the callback with fresh stack
//!
//! # NT Functions
//!
//! - `FsRtlPostStackOverflow` - Queue work item for stack overflow processing
//! - `FsRtlPostPagingFileStackOverflow` - Queue paging file work
//! - `FsRtlIsNtstatusExpected` - Check if status is expected stack overflow

use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use crate::ke::event::KEvent;
use crate::ke::spinlock::SpinLock;

/// Stack overflow work callback
pub type StackOverflowRoutine = fn(context: *mut u8, event: *mut KEvent);

/// Stack overflow work item
#[repr(C)]
pub struct StackOverflowItem {
    /// Link for queue
    pub queue_link: [usize; 2],
    /// Callback routine
    pub stack_overflow_routine: Option<StackOverflowRoutine>,
    /// Context for callback
    pub context: *mut u8,
    /// Event to signal on completion
    pub event: *mut KEvent,
}

impl Default for StackOverflowItem {
    fn default() -> Self {
        Self::new()
    }
}

impl StackOverflowItem {
    pub const fn new() -> Self {
        Self {
            queue_link: [0; 2],
            stack_overflow_routine: None,
            context: core::ptr::null_mut(),
            event: core::ptr::null_mut(),
        }
    }
}

/// Maximum items in the stack overflow pool
const MAX_STACK_OVERFLOW_ITEMS: usize = 32;

/// Pool of stack overflow items
static mut STACK_OVERFLOW_POOL: [StackOverflowItem; MAX_STACK_OVERFLOW_ITEMS] = {
    const INIT: StackOverflowItem = StackOverflowItem::new();
    [INIT; MAX_STACK_OVERFLOW_ITEMS]
};

/// Bitmap for allocated items
static mut STACK_OVERFLOW_BITMAP: u32 = 0;

/// Lock for item allocation
static STACK_OVERFLOW_LOCK: SpinLock<()> = SpinLock::new(());

/// Normal I/O overflow queue
static mut NORMAL_OVERFLOW_QUEUE: [StackOverflowItem; 16] = {
    const INIT: StackOverflowItem = StackOverflowItem::new();
    [INIT; 16]
};
static NORMAL_QUEUE_HEAD: AtomicU32 = AtomicU32::new(0);
static NORMAL_QUEUE_TAIL: AtomicU32 = AtomicU32::new(0);

/// Paging file overflow queue
static mut PAGING_OVERFLOW_QUEUE: [StackOverflowItem; 16] = {
    const INIT: StackOverflowItem = StackOverflowItem::new();
    [INIT; 16]
};
static PAGING_QUEUE_HEAD: AtomicU32 = AtomicU32::new(0);
static PAGING_QUEUE_TAIL: AtomicU32 = AtomicU32::new(0);

/// Worker thread running flags
static NORMAL_WORKER_RUNNING: AtomicBool = AtomicBool::new(false);
static PAGING_WORKER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct StackOverflowStats {
    /// Total posts to normal queue
    pub normal_posts: u64,
    /// Total posts to paging queue
    pub paging_posts: u64,
    /// Callbacks processed from normal queue
    pub normal_processed: u64,
    /// Callbacks processed from paging queue
    pub paging_processed: u64,
    /// Fallback items used (when pool exhausted)
    pub fallback_used: u64,
    /// Posts that failed
    pub post_failures: u64,
}

static mut STATS: StackOverflowStats = StackOverflowStats {
    normal_posts: 0,
    paging_posts: 0,
    normal_processed: 0,
    paging_processed: 0,
    fallback_used: 0,
    post_failures: 0,
};

/// Fallback item for when pool is exhausted
static mut FALLBACK_ITEM: StackOverflowItem = StackOverflowItem::new();
static FALLBACK_IN_USE: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Stack Remaining Check
// ============================================================================

/// Minimum stack required to continue processing
pub const STACK_OVERFLOW_READ_THRESHHOLD: usize = 0x1000; // 4KB

/// Kernel stack size
const KERNEL_STACK_SIZE: usize = 0x6000; // 24KB on AMD64

/// Approximate remaining stack space
///
/// # Safety
/// This reads the current stack pointer to estimate remaining space.
#[inline]
pub fn io_get_remaining_stack_size() -> usize {
    // Get approximate stack pointer using inline assembly or stack variable address
    let stack_var: usize = 0;
    let stack_ptr = &stack_var as *const usize as usize;

    // Stack grows down, estimate bottom of stack
    // This is a rough approximation
    let stack_bottom = stack_ptr & !(KERNEL_STACK_SIZE - 1);

    stack_ptr.saturating_sub(stack_bottom)
}

/// Check if there's enough stack remaining
#[inline]
pub fn io_check_stack_overflow() -> bool {
    io_get_remaining_stack_size() < STACK_OVERFLOW_READ_THRESHHOLD
}

// ============================================================================
// Stack Overflow Posting Functions
// ============================================================================

/// Post stack overflow work item for normal I/O (FsRtlPostStackOverflow)
///
/// Called by file systems when they detect low stack during normal I/O.
/// The callback will be executed on a worker thread with a fresh stack.
///
/// # Arguments
/// * `context` - Context passed to callback
/// * `event` - Event to wait on (will be signaled when done)
/// * `stack_overflow_routine` - Callback to execute
///
/// # Safety
/// The event and context must remain valid until the callback completes.
pub unsafe fn fsrtl_post_stack_overflow(
    context: *mut u8,
    event: *mut KEvent,
    stack_overflow_routine: StackOverflowRoutine,
) {
    fsrtl_post_stack_overflow_internal(context, event, stack_overflow_routine, false);
}

/// Post stack overflow work item for paging file I/O (FsRtlPostPagingFileStackOverflow)
///
/// Called by file systems when low stack during paging file I/O.
/// Has higher priority than normal overflow items.
pub unsafe fn fsrtl_post_paging_file_stack_overflow(
    context: *mut u8,
    event: *mut KEvent,
    stack_overflow_routine: StackOverflowRoutine,
) {
    fsrtl_post_stack_overflow_internal(context, event, stack_overflow_routine, true);
}

/// Internal post function
unsafe fn fsrtl_post_stack_overflow_internal(
    context: *mut u8,
    event: *mut KEvent,
    stack_overflow_routine: StackOverflowRoutine,
    paging_file: bool,
) {
    // Try to allocate an item from the pool
    let item = allocate_stack_overflow_item();

    if let Some(item_ptr) = item {
        (*item_ptr).context = context;
        (*item_ptr).event = event;
        (*item_ptr).stack_overflow_routine = Some(stack_overflow_routine);

        // Queue the item
        if paging_file {
            queue_paging_item(item_ptr);
            STATS.paging_posts += 1;
        } else {
            queue_normal_item(item_ptr);
            STATS.normal_posts += 1;
        }

        // Signal worker thread (if using events)
        // In a real implementation, this would wake the worker thread
    } else {
        // Use fallback item if pool exhausted
        if !FALLBACK_IN_USE.swap(true, Ordering::AcqRel) {
            FALLBACK_ITEM.context = context;
            FALLBACK_ITEM.event = event;
            FALLBACK_ITEM.stack_overflow_routine = Some(stack_overflow_routine);

            STATS.fallback_used += 1;

            // Execute immediately on fallback
            // In a real implementation, this would use the worker thread
            if let Some(routine) = FALLBACK_ITEM.stack_overflow_routine {
                routine(context, event);
            }

            FALLBACK_IN_USE.store(false, Ordering::Release);
        } else {
            // Both pool and fallback exhausted - this is bad
            STATS.post_failures += 1;
            crate::serial_println!("[FSRTL] CRITICAL: Stack overflow item allocation failed!");
        }
    }
}

/// Allocate a stack overflow item
unsafe fn allocate_stack_overflow_item() -> Option<*mut StackOverflowItem> {
    let _guard = STACK_OVERFLOW_LOCK.lock();

    for i in 0..MAX_STACK_OVERFLOW_ITEMS {
        if STACK_OVERFLOW_BITMAP & (1 << i) == 0 {
            STACK_OVERFLOW_BITMAP |= 1 << i;
            return Some(&mut STACK_OVERFLOW_POOL[i] as *mut StackOverflowItem);
        }
    }

    None
}

/// Free a stack overflow item
unsafe fn free_stack_overflow_item(item: *mut StackOverflowItem) {
    let _guard = STACK_OVERFLOW_LOCK.lock();

    let base = STACK_OVERFLOW_POOL.as_ptr() as usize;
    let item_addr = item as usize;
    let item_size = core::mem::size_of::<StackOverflowItem>();

    if item_addr >= base && item_addr < base + MAX_STACK_OVERFLOW_ITEMS * item_size {
        let index = (item_addr - base) / item_size;
        STACK_OVERFLOW_BITMAP &= !(1 << index);
    }
}

/// Queue item to normal queue
unsafe fn queue_normal_item(item: *mut StackOverflowItem) {
    let tail = NORMAL_QUEUE_TAIL.load(Ordering::Relaxed) as usize;
    let new_tail = (tail + 1) % 16;

    NORMAL_OVERFLOW_QUEUE[tail] = (*item).clone_item();
    NORMAL_QUEUE_TAIL.store(new_tail as u32, Ordering::Release);
}

/// Queue item to paging queue
unsafe fn queue_paging_item(item: *mut StackOverflowItem) {
    let tail = PAGING_QUEUE_TAIL.load(Ordering::Relaxed) as usize;
    let new_tail = (tail + 1) % 16;

    PAGING_OVERFLOW_QUEUE[tail] = (*item).clone_item();
    PAGING_QUEUE_TAIL.store(new_tail as u32, Ordering::Release);
}

impl StackOverflowItem {
    fn clone_item(&self) -> Self {
        Self {
            queue_link: self.queue_link,
            stack_overflow_routine: self.stack_overflow_routine,
            context: self.context,
            event: self.event,
        }
    }
}

// ============================================================================
// Worker Thread
// ============================================================================

/// Process pending stack overflow items
///
/// Called by the worker thread to process queued items.
pub unsafe fn fsrtl_stack_overflow_worker(paging_file: bool) {
    let (queue_head, queue_tail, queue, processed_counter) = if paging_file {
        (
            &PAGING_QUEUE_HEAD,
            &PAGING_QUEUE_TAIL,
            &mut PAGING_OVERFLOW_QUEUE,
            &mut STATS.paging_processed,
        )
    } else {
        (
            &NORMAL_QUEUE_HEAD,
            &NORMAL_QUEUE_TAIL,
            &mut NORMAL_OVERFLOW_QUEUE,
            &mut STATS.normal_processed,
        )
    };

    loop {
        let head = queue_head.load(Ordering::Acquire) as usize;
        let tail = queue_tail.load(Ordering::Acquire) as usize;

        if head == tail {
            // Queue empty
            break;
        }

        // Get item
        let item = &queue[head];

        // Execute callback
        if let Some(routine) = item.stack_overflow_routine {
            routine(item.context, item.event as *mut KEvent);
            *processed_counter += 1;
        }

        // Advance head
        let new_head = (head + 1) % 16;
        queue_head.store(new_head as u32, Ordering::Release);
    }
}

/// Worker thread entry point for normal I/O
pub fn fsrtl_worker_thread_normal() {
    if NORMAL_WORKER_RUNNING.swap(true, Ordering::AcqRel) {
        return; // Already running
    }

    unsafe {
        fsrtl_stack_overflow_worker(false);
    }

    NORMAL_WORKER_RUNNING.store(false, Ordering::Release);
}

/// Worker thread entry point for paging file I/O
pub fn fsrtl_worker_thread_paging() {
    if PAGING_WORKER_RUNNING.swap(true, Ordering::AcqRel) {
        return; // Already running
    }

    unsafe {
        fsrtl_stack_overflow_worker(true);
    }

    PAGING_WORKER_RUNNING.store(false, Ordering::Release);
}

// ============================================================================
// Status Checking
// ============================================================================

/// NTSTATUS codes that indicate expected stack overflow conditions
pub mod status {
    pub const STATUS_PENDING: i32 = 0x103;
    pub const STATUS_NO_MORE_FILES: i32 = -2147483642;
    pub const STATUS_NO_SUCH_FILE: i32 = -1073741773;
    pub const STATUS_OBJECT_NAME_NOT_FOUND: i32 = -1073741772;
    pub const STATUS_OBJECT_PATH_NOT_FOUND: i32 = -1073741766;
    pub const STATUS_DATATYPE_MISALIGNMENT: i32 = -2147483646;
    pub const STATUS_ACCESS_DENIED: i32 = -1073741790;
    pub const STATUS_SHARING_VIOLATION: i32 = -1073741757;
    pub const STATUS_FILE_LOCK_CONFLICT: i32 = -1073741740;
    pub const STATUS_LOCK_NOT_GRANTED: i32 = -1073741738;
    pub const STATUS_DELETE_PENDING: i32 = -1073741738;
    pub const STATUS_END_OF_FILE: i32 = -1073741788;
    pub const STATUS_INSUFFICIENT_RESOURCES: i32 = -1073741670;
    pub const STATUS_DISK_FULL: i32 = -1073741697;
    pub const STATUS_MEDIA_WRITE_PROTECTED: i32 = -1073741662;
    pub const STATUS_VOLUME_DISMOUNTED: i32 = -1073741738;
    pub const STATUS_FILE_DELETED: i32 = -1073741757;
    pub const STATUS_FILE_CLOSED: i32 = -1073741738;
}

/// Check if an NTSTATUS is expected (FsRtlIsNtstatusExpected)
///
/// Returns TRUE if the status is a "normal" failure that file systems
/// expect and handle gracefully.
pub fn fsrtl_is_ntstatus_expected(status: i32) -> bool {
    matches!(
        status,
        status::STATUS_PENDING
            | status::STATUS_NO_MORE_FILES
            | status::STATUS_NO_SUCH_FILE
            | status::STATUS_OBJECT_NAME_NOT_FOUND
            | status::STATUS_OBJECT_PATH_NOT_FOUND
            | status::STATUS_DATATYPE_MISALIGNMENT
            | status::STATUS_ACCESS_DENIED
            | status::STATUS_SHARING_VIOLATION
            | status::STATUS_FILE_LOCK_CONFLICT
            | status::STATUS_LOCK_NOT_GRANTED
            | status::STATUS_DELETE_PENDING
            | status::STATUS_END_OF_FILE
            | status::STATUS_INSUFFICIENT_RESOURCES
            | status::STATUS_DISK_FULL
            | status::STATUS_MEDIA_WRITE_PROTECTED
            | status::STATUS_VOLUME_DISMOUNTED
            | status::STATUS_FILE_DELETED
            | status::STATUS_FILE_CLOSED
    )
}

// ============================================================================
// Stack Check Helpers
// ============================================================================

/// Check if we need to post to stack overflow thread (IoIsOperationSynchronous check)
pub fn fsrtl_is_stack_overflow_read_possible() -> bool {
    io_check_stack_overflow()
}

/// Get current stack usage percentage (for diagnostics)
pub fn get_stack_usage_percent() -> u32 {
    let remaining = io_get_remaining_stack_size();
    let used = KERNEL_STACK_SIZE.saturating_sub(remaining);
    ((used * 100) / KERNEL_STACK_SIZE) as u32
}

// ============================================================================
// Statistics
// ============================================================================

/// Get stack overflow statistics
pub fn get_stats() -> StackOverflowStats {
    unsafe { STATS }
}

/// Reset statistics
pub fn reset_stats() {
    unsafe {
        STATS = StackOverflowStats::default();
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize stack overflow support
pub fn init() {
    unsafe {
        // Clear pool bitmap
        STACK_OVERFLOW_BITMAP = 0;

        // Clear queues
        NORMAL_QUEUE_HEAD.store(0, Ordering::Release);
        NORMAL_QUEUE_TAIL.store(0, Ordering::Release);
        PAGING_QUEUE_HEAD.store(0, Ordering::Release);
        PAGING_QUEUE_TAIL.store(0, Ordering::Release);

        // Clear stats
        STATS = StackOverflowStats::default();
    }

    FALLBACK_IN_USE.store(false, Ordering::Release);
    NORMAL_WORKER_RUNNING.store(false, Ordering::Release);
    PAGING_WORKER_RUNNING.store(false, Ordering::Release);

    crate::serial_println!("[FSRTL] Stack overflow support initialized");
}
