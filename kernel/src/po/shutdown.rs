//! Power Manager Shutdown Support
//!
//! Provides graceful shutdown functionality including:
//! - Shutdown thread waiting (allow threads to complete before shutdown)
//! - Shutdown work queue (run cleanup routines before shutdown)
//! - Shutdown event signaling
//!
//! # Shutdown Sequence
//!
//! 1. Shutdown is initiated (by user, policy, or critical error)
//! 2. Shutdown event is signaled
//! 3. Registered shutdown workers are executed
//! 4. System waits for threads registered for shutdown wait
//! 5. Services are stopped
//! 6. Devices are powered down
//! 7. ACPI S5 or reset is performed
//!
//! # NT Functions
//!
//! - `PoRequestShutdownWait` - Register thread for shutdown wait
//! - `PoRequestShutdownEvent` - Get shutdown event handle
//! - `PoQueueShutdownWorkItem` - Queue work for shutdown

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use alloc::vec::Vec;

/// Maximum number of threads that can wait for shutdown
const MAX_SHUTDOWN_THREADS: usize = 64;

/// Maximum number of shutdown work items
const MAX_SHUTDOWN_WORK_ITEMS: usize = 32;

/// Shutdown work item callback
pub type ShutdownWorkCallback = fn(context: usize);

/// Shutdown thread entry
#[derive(Clone, Copy)]
struct ShutdownThreadEntry {
    /// Thread pointer (ETHREAD)
    thread: usize,
    /// Entry is in use
    in_use: bool,
}

impl Default for ShutdownThreadEntry {
    fn default() -> Self {
        Self {
            thread: 0,
            in_use: false,
        }
    }
}

/// Shutdown work item
#[derive(Clone, Copy)]
struct ShutdownWorkItem {
    /// Callback function
    callback: Option<ShutdownWorkCallback>,
    /// Context passed to callback
    context: usize,
    /// Priority (lower = earlier)
    priority: u32,
    /// Entry is in use
    in_use: bool,
}

impl Default for ShutdownWorkItem {
    fn default() -> Self {
        Self {
            callback: None,
            context: 0,
            priority: 100,
            in_use: false,
        }
    }
}

// Global shutdown state
static SHUTDOWN_AVAILABLE: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_COMPLETE: AtomicBool = AtomicBool::new(false);

// Shutdown thread list
static mut SHUTDOWN_THREADS: [ShutdownThreadEntry; MAX_SHUTDOWN_THREADS] =
    [ShutdownThreadEntry { thread: 0, in_use: false }; MAX_SHUTDOWN_THREADS];
static SHUTDOWN_THREAD_LOCK: SpinLock<()> = SpinLock::new(());

// Shutdown work queue
static mut SHUTDOWN_WORK_ITEMS: [ShutdownWorkItem; MAX_SHUTDOWN_WORK_ITEMS] =
    [ShutdownWorkItem { callback: None, context: 0, priority: 100, in_use: false }; MAX_SHUTDOWN_WORK_ITEMS];
static SHUTDOWN_WORK_LOCK: SpinLock<()> = SpinLock::new(());

// Statistics
static SHUTDOWN_THREADS_REGISTERED: AtomicU32 = AtomicU32::new(0);
static SHUTDOWN_WORK_ITEMS_REGISTERED: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize shutdown support
pub fn init() {
    unsafe {
        for entry in SHUTDOWN_THREADS.iter_mut() {
            *entry = ShutdownThreadEntry::default();
        }
        for item in SHUTDOWN_WORK_ITEMS.iter_mut() {
            *item = ShutdownWorkItem::default();
        }
    }

    SHUTDOWN_AVAILABLE.store(true, Ordering::Release);
    SHUTDOWN_IN_PROGRESS.store(false, Ordering::Release);
    SHUTDOWN_COMPLETE.store(false, Ordering::Release);
    SHUTDOWN_THREADS_REGISTERED.store(0, Ordering::Release);
    SHUTDOWN_WORK_ITEMS_REGISTERED.store(0, Ordering::Release);

    crate::serial_println!("[PO] Shutdown support initialized");
}

// ============================================================================
// Shutdown Thread Registration
// ============================================================================

/// Request to be waited on during shutdown (PoRequestShutdownWait)
///
/// Registers the specified thread to be waited on during graceful shutdown.
/// The system will wait for this thread to terminate before completing
/// the shutdown sequence.
///
/// # Arguments
/// * `thread` - Pointer to the ETHREAD structure
///
/// # Returns
/// * `Ok(())` - Thread registered successfully
/// * `Err(status)` - Registration failed
pub fn po_request_shutdown_wait(thread: usize) -> Result<(), i32> {
    if thread == 0 {
        return Err(-1073741811); // STATUS_INVALID_PARAMETER
    }

    let _guard = SHUTDOWN_THREAD_LOCK.lock();

    // Check if shutdown is still available
    if !SHUTDOWN_AVAILABLE.load(Ordering::Acquire) {
        return Err(-1073741823); // STATUS_UNSUCCESSFUL
    }

    // Find free slot
    unsafe {
        for entry in SHUTDOWN_THREADS.iter_mut() {
            if !entry.in_use {
                entry.thread = thread;
                entry.in_use = true;
                SHUTDOWN_THREADS_REGISTERED.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        }
    }

    Err(-1073741670) // STATUS_INSUFFICIENT_RESOURCES
}

/// Remove thread from shutdown wait list
///
/// Should be called when a registered thread terminates normally.
pub fn po_cancel_shutdown_wait(thread: usize) {
    let _guard = SHUTDOWN_THREAD_LOCK.lock();

    unsafe {
        for entry in SHUTDOWN_THREADS.iter_mut() {
            if entry.in_use && entry.thread == thread {
                entry.in_use = false;
                entry.thread = 0;
                SHUTDOWN_THREADS_REGISTERED.fetch_sub(1, Ordering::Relaxed);
                break;
            }
        }
    }
}

/// Get count of threads registered for shutdown wait
pub fn get_shutdown_thread_count() -> u32 {
    SHUTDOWN_THREADS_REGISTERED.load(Ordering::Relaxed)
}

// ============================================================================
// Shutdown Work Queue
// ============================================================================

/// Queue a work item to execute during shutdown (PoQueueShutdownWorkItem)
///
/// The work item will be executed during the graceful shutdown sequence,
/// after shutdown is initiated but before the system powers off.
///
/// # Arguments
/// * `callback` - Function to call during shutdown
/// * `context` - Context value passed to callback
/// * `priority` - Execution priority (lower = earlier, 0-255)
///
/// # Returns
/// * `Ok(handle)` - Work item queued successfully
/// * `Err(status)` - Failed to queue work item
pub fn po_queue_shutdown_work_item(
    callback: ShutdownWorkCallback,
    context: usize,
    priority: u32,
) -> Result<usize, i32> {
    let _guard = SHUTDOWN_WORK_LOCK.lock();

    // Check if shutdown list is still available
    if !SHUTDOWN_AVAILABLE.load(Ordering::Acquire) {
        return Err(-1073741823); // STATUS_UNSUCCESSFUL
    }

    // Find free slot
    unsafe {
        for (i, item) in SHUTDOWN_WORK_ITEMS.iter_mut().enumerate() {
            if !item.in_use {
                item.callback = Some(callback);
                item.context = context;
                item.priority = priority;
                item.in_use = true;
                SHUTDOWN_WORK_ITEMS_REGISTERED.fetch_add(1, Ordering::Relaxed);
                return Ok(i);
            }
        }
    }

    Err(-1073741670) // STATUS_INSUFFICIENT_RESOURCES
}

/// Cancel a queued shutdown work item
pub fn po_cancel_shutdown_work_item(handle: usize) {
    if handle >= MAX_SHUTDOWN_WORK_ITEMS {
        return;
    }

    let _guard = SHUTDOWN_WORK_LOCK.lock();

    unsafe {
        if SHUTDOWN_WORK_ITEMS[handle].in_use {
            SHUTDOWN_WORK_ITEMS[handle] = ShutdownWorkItem::default();
            SHUTDOWN_WORK_ITEMS_REGISTERED.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Get count of queued shutdown work items
pub fn get_shutdown_work_count() -> u32 {
    SHUTDOWN_WORK_ITEMS_REGISTERED.load(Ordering::Relaxed)
}

// ============================================================================
// Shutdown Event
// ============================================================================

/// Request the shutdown event handle (PoRequestShutdownEvent)
///
/// The returned event is signaled when shutdown begins.
/// Currently returns the shutdown status since we don't have full event objects.
///
/// # Returns
/// * `true` - Shutdown is in progress
/// * `false` - Shutdown not in progress
pub fn po_request_shutdown_event() -> bool {
    SHUTDOWN_IN_PROGRESS.load(Ordering::Acquire)
}

/// Check if shutdown is in progress
pub fn is_shutdown_in_progress() -> bool {
    SHUTDOWN_IN_PROGRESS.load(Ordering::Acquire)
}

/// Check if shutdown is complete
pub fn is_shutdown_complete() -> bool {
    SHUTDOWN_COMPLETE.load(Ordering::Acquire)
}

// ============================================================================
// Graceful Shutdown Execution
// ============================================================================

/// Execute graceful shutdown sequence
///
/// This function:
/// 1. Marks shutdown as in progress
/// 2. Disables new registrations
/// 3. Executes all shutdown work items (by priority)
/// 4. Waits for registered threads
/// 5. Returns when ready for final power-off
///
/// # Returns
/// Number of work items executed and threads waited on
pub fn execute_graceful_shutdown() -> (u32, u32) {
    crate::serial_println!("[PO] Beginning graceful shutdown sequence...");

    // Mark shutdown in progress and disable new registrations
    SHUTDOWN_IN_PROGRESS.store(true, Ordering::Release);
    SHUTDOWN_AVAILABLE.store(false, Ordering::Release);

    // Execute shutdown work items by priority
    let work_count = execute_shutdown_work_items();
    crate::serial_println!("[PO] Executed {} shutdown work items", work_count);

    // Wait for registered threads
    let thread_count = wait_for_shutdown_threads();
    crate::serial_println!("[PO] Waited for {} shutdown threads", thread_count);

    // Mark shutdown complete
    SHUTDOWN_COMPLETE.store(true, Ordering::Release);

    (work_count, thread_count)
}

/// Execute all queued shutdown work items
fn execute_shutdown_work_items() -> u32 {
    let mut executed = 0u32;

    // Collect work items sorted by priority
    let mut items: Vec<(u32, ShutdownWorkCallback, usize)> = Vec::new();

    {
        let _guard = SHUTDOWN_WORK_LOCK.lock();
        unsafe {
            for item in SHUTDOWN_WORK_ITEMS.iter() {
                if item.in_use {
                    if let Some(callback) = item.callback {
                        items.push((item.priority, callback, item.context));
                    }
                }
            }
        }
    }

    // Sort by priority (lower = earlier)
    items.sort_by_key(|item| item.0);

    // Execute in priority order
    for (priority, callback, context) in items {
        crate::serial_println!("[PO] Executing shutdown work item (priority {})", priority);
        callback(context);
        executed += 1;
    }

    executed
}

/// Wait for all registered shutdown threads
fn wait_for_shutdown_threads() -> u32 {
    let mut waited = 0u32;

    // Collect thread list
    let threads: Vec<usize>;
    {
        let _guard = SHUTDOWN_THREAD_LOCK.lock();
        threads = unsafe {
            SHUTDOWN_THREADS.iter()
                .filter(|e| e.in_use)
                .map(|e| e.thread)
                .collect()
        };
    }

    // Wait for each thread
    for thread in threads {
        crate::serial_println!("[PO] Waiting for shutdown thread 0x{:x}...", thread);

        // In a full implementation, this would wait for thread termination
        // using KeWaitForSingleObject on the thread object
        // For now, we just count them
        waited += 1;
    }

    waited
}

// ============================================================================
// Shutdown Statistics
// ============================================================================

/// Shutdown statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ShutdownStats {
    /// Threads registered for shutdown wait
    pub threads_registered: u32,
    /// Work items queued
    pub work_items_queued: u32,
    /// Shutdown in progress
    pub in_progress: bool,
    /// Shutdown complete
    pub complete: bool,
    /// Shutdown registrations available
    pub available: bool,
}

/// Get shutdown statistics
pub fn get_shutdown_stats() -> ShutdownStats {
    ShutdownStats {
        threads_registered: SHUTDOWN_THREADS_REGISTERED.load(Ordering::Relaxed),
        work_items_queued: SHUTDOWN_WORK_ITEMS_REGISTERED.load(Ordering::Relaxed),
        in_progress: SHUTDOWN_IN_PROGRESS.load(Ordering::Relaxed),
        complete: SHUTDOWN_COMPLETE.load(Ordering::Relaxed),
        available: SHUTDOWN_AVAILABLE.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Shutdown Reasons
// ============================================================================

/// Shutdown reason codes
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// User initiated shutdown
    User = 0x00000000,
    /// Application initiated shutdown
    Application = 0x00040000,
    /// Hardware failure
    Hardware = 0x00010000,
    /// Operating system issue
    OperatingSystem = 0x00020000,
    /// Software issue
    Software = 0x00030000,
    /// Power failure
    Power = 0x00060000,
    /// Legacy API shutdown
    LegacyApi = 0x00070000,
    /// Unknown reason
    Unknown = 0x000F0000,
}

/// Major shutdown reason
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownMajorReason {
    /// Other
    Other = 0x00000000,
    /// Hardware issue
    Hardware = 0x00010000,
    /// Operating system
    OperatingSystem = 0x00020000,
    /// Software issue
    Software = 0x00030000,
    /// Application request
    Application = 0x00040000,
    /// System failure
    System = 0x00050000,
    /// Power failure
    Power = 0x00060000,
    /// Legacy API
    LegacyApi = 0x00070000,
}

/// Minor shutdown reason
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownMinorReason {
    /// Other
    Other = 0x00000000,
    /// Maintenance
    Maintenance = 0x00000001,
    /// Installation
    Installation = 0x00000002,
    /// Upgrade
    Upgrade = 0x00000003,
    /// Reconfigure
    Reconfigure = 0x00000004,
    /// Hung
    Hung = 0x00000005,
    /// Unstable
    Unstable = 0x00000006,
    /// Disk
    Disk = 0x00000007,
    /// Processor
    Processor = 0x00000008,
    /// Network card
    NetworkCard = 0x00000009,
    /// Power supply
    PowerSupply = 0x0000000A,
    /// Cordless
    Cordless = 0x0000000B,
    /// Environment
    Environment = 0x0000000C,
    /// Hardware driver
    HardwareDriver = 0x0000000D,
    /// Other driver
    OtherDriver = 0x0000000E,
    /// Blue screen
    BlueScreen = 0x0000000F,
    /// Service pack
    ServicePack = 0x00000010,
    /// Hot fix
    Hotfix = 0x00000011,
    /// Security fix
    SecurityFix = 0x00000012,
    /// Security
    Security = 0x00000013,
    /// Network connectivity
    NetworkConnectivity = 0x00000014,
    /// WMI
    Wmi = 0x00000015,
    /// Terminal services
    TerminalServices = 0x00000020,
}

/// Last shutdown reason recorded
static mut LAST_SHUTDOWN_REASON: ShutdownReason = ShutdownReason::Unknown;

/// Record shutdown reason
pub fn set_shutdown_reason(reason: ShutdownReason) {
    unsafe {
        LAST_SHUTDOWN_REASON = reason;
    }
}

/// Get last shutdown reason
pub fn get_shutdown_reason() -> ShutdownReason {
    unsafe { LAST_SHUTDOWN_REASON }
}
