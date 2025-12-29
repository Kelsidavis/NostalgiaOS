//! Kernel Timer Implementation (KTIMER)
//!
//! Timers are dispatcher objects that become signaled after a specified
//! time interval. They can optionally queue a DPC when they expire.
//!
//! # Usage
//! ```
//! static MY_TIMER: KTimer = KTimer::new();
//!
//! // Initialize timer
//! MY_TIMER.init();
//!
//! // Set timer to expire in 1000ms (one-shot)
//! MY_TIMER.set(1000, 0, None);
//!
//! // Set periodic timer every 500ms with DPC
//! MY_TIMER.set(500, 500, Some(&MY_DPC));
//! ```
//!
//! # NT Compatibility
//! Equivalent to NT's KTIMER / KeInitializeTimer / KeSetTimer

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use super::dispatcher::{DispatcherHeader, DispatcherType};
use super::dpc::KDpc;
use super::list::ListEntry;
use super::scheduler;
use super::thread::ThreadState;
use crate::hal::apic;
use crate::containing_record;

/// Timer type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerType {
    /// Notification timer - stays signaled until reset
    Notification = 0,
    /// Synchronization timer - auto-resets after satisfying one wait
    Synchronization = 1,
}

/// Kernel Timer object
///
/// Equivalent to NT's KTIMER
#[repr(C)]
pub struct KTimer {
    /// Dispatcher header (must be first for casting)
    pub header: DispatcherHeader,

    /// Absolute expiration time in ticks
    due_time: UnsafeCell<u64>,

    /// Entry in the global timer list
    timer_list_entry: UnsafeCell<ListEntry>,

    /// Optional DPC to queue when timer expires
    dpc: UnsafeCell<*mut KDpc>,

    /// Period for periodic timers (0 = one-shot)
    period: UnsafeCell<u32>,

    /// Timer type (notification or synchronization)
    timer_type: UnsafeCell<TimerType>,

    /// Whether timer is currently inserted in the timer list
    inserted: AtomicBool,
}

// Safety: KTimer is designed for multi-threaded access
unsafe impl Sync for KTimer {}
unsafe impl Send for KTimer {}

impl KTimer {
    /// Create a new uninitialized timer
    pub const fn new() -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherType::Timer),
            due_time: UnsafeCell::new(0),
            timer_list_entry: UnsafeCell::new(ListEntry::new()),
            dpc: UnsafeCell::new(core::ptr::null_mut()),
            period: UnsafeCell::new(0),
            timer_type: UnsafeCell::new(TimerType::Notification),
            inserted: AtomicBool::new(false),
        }
    }

    /// Initialize the timer
    ///
    /// Equivalent to KeInitializeTimer
    pub fn init(&self) {
        self.init_ex(TimerType::Notification);
    }

    /// Initialize the timer with a specific type
    ///
    /// Equivalent to KeInitializeTimerEx
    pub fn init_ex(&self, timer_type: TimerType) {
        unsafe {
            // Initialize dispatcher header (not signaled initially)
            let header = &self.header as *const _ as *mut DispatcherHeader;
            (*header).init(DispatcherType::Timer, 0);

            *self.due_time.get() = 0;
            (*self.timer_list_entry.get()).init_head();
            *self.dpc.get() = core::ptr::null_mut();
            *self.period.get() = 0;
            *self.timer_type.get() = timer_type;
        }
        self.inserted.store(false, Ordering::Release);
    }

    /// Set the timer to expire after a specified interval
    ///
    /// Equivalent to KeSetTimer / KeSetTimerEx
    ///
    /// # Arguments
    /// * `due_time_ms` - Time until expiration in milliseconds
    /// * `period_ms` - Period for periodic timer (0 = one-shot)
    /// * `dpc` - Optional DPC to queue on expiration
    ///
    /// # Returns
    /// true if the timer was already in the timer queue (was reset)
    ///
    /// # Safety
    /// Must be called with proper synchronization
    pub unsafe fn set(&self, due_time_ms: u32, period_ms: u32, dpc: Option<&KDpc>) -> bool {
        let was_inserted = self.cancel();

        // Calculate absolute expiration time
        let current_time = apic::get_tick_count();
        let due_time = current_time + due_time_ms as u64;

        *self.due_time.get() = due_time;
        *self.period.get() = period_ms;
        *self.dpc.get() = dpc.map(|d| d as *const _ as *mut KDpc).unwrap_or(core::ptr::null_mut());

        // Clear signaled state
        self.header.set_signal_state(0);

        // Insert into timer queue
        ki_insert_timer(self);

        was_inserted
    }

    /// Set timer with just due time (one-shot, no DPC)
    pub unsafe fn set_simple(&self, due_time_ms: u32) -> bool {
        self.set(due_time_ms, 0, None)
    }

    /// Cancel a pending timer
    ///
    /// Equivalent to KeCancelTimer
    ///
    /// # Returns
    /// true if the timer was in the queue and was removed
    pub unsafe fn cancel(&self) -> bool {
        if !self.inserted.swap(false, Ordering::AcqRel) {
            return false;
        }

        // Remove from timer queue
        let entry = &mut *self.timer_list_entry.get();
        entry.remove_entry();

        true
    }

    /// Check if the timer is currently set
    #[inline]
    pub fn is_set(&self) -> bool {
        self.inserted.load(Ordering::Acquire)
    }

    /// Check if the timer is signaled (expired)
    #[inline]
    pub fn is_signaled(&self) -> bool {
        self.header.is_signaled()
    }

    /// Clear the signaled state
    ///
    /// For periodic notification timers that are polled (not waited on),
    /// the polling code should call this after observing the signaled state
    /// to acknowledge the expiration and prepare for the next one.
    ///
    /// # Safety
    /// Must be called with proper synchronization
    #[inline]
    pub unsafe fn clear_signal(&self) {
        self.header.set_signal_state(0);
    }

    /// Get the due time
    #[inline]
    pub fn due_time(&self) -> u64 {
        unsafe { *self.due_time.get() }
    }

    /// Get the period
    #[inline]
    pub fn period(&self) -> u32 {
        unsafe { *self.period.get() }
    }

    /// Internal: Mark timer as expired and signal it
    unsafe fn expire(&self) {
        // Remove from timer queue
        self.inserted.store(false, Ordering::Release);
        let entry = &mut *self.timer_list_entry.get();
        entry.remove_entry();

        // Signal the timer
        self.header.set_signal_state(1);

        // Wake any waiting threads
        self.wake_waiters();

        // Queue associated DPC if any
        let dpc = *self.dpc.get();
        if !dpc.is_null() {
            (*dpc).queue(self as *const _ as usize, 0);
        }

        // For periodic timers, re-queue
        let period = *self.period.get();
        if period > 0 {
            let current_time = apic::get_tick_count();
            *self.due_time.get() = current_time + period as u64;

            // Note: We keep the signaled state for notification timers so that
            // polling threads can observe the expiration. The polling code should
            // call clear_signal() after observing the signaled state.
            // For synchronization timers, signal is cleared after waking one waiter.
            if *self.timer_type.get() == TimerType::Synchronization {
                self.header.set_signal_state(0);
            }

            ki_insert_timer(self);
        }
    }

    /// Wake threads waiting on this timer
    unsafe fn wake_waiters(&self) {
        while self.header.has_waiters() {
            let entry = self.header.wait_list().remove_head();
            let wait_block = containing_record!(entry, super::dispatcher::KWaitBlock, wait_list_entry);
            let thread = (*wait_block).thread;

            (*thread).state = ThreadState::Ready;
            scheduler::ki_ready_thread(thread);

            // For synchronization timers, only wake one
            if *self.timer_type.get() == TimerType::Synchronization {
                self.header.set_signal_state(0);
                break;
            }
        }
    }
}

impl Default for KTimer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Timer Queue
// ============================================================================

/// Wrapper to make ListEntry safe for static use
struct TimerListHead(UnsafeCell<ListEntry>);

// Safety: Access is protected by single-threaded kernel or interrupt disable
unsafe impl Sync for TimerListHead {}

impl TimerListHead {
    const fn new() -> Self {
        Self(UnsafeCell::new(ListEntry::new()))
    }

    unsafe fn get(&self) -> *mut ListEntry {
        self.0.get()
    }
}

/// Global timer list head
/// Timers are kept sorted by due time for efficient expiration checking
static TIMER_LIST_HEAD: TimerListHead = TimerListHead::new();

/// Flag indicating timer list is initialized
static TIMER_LIST_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Number of timers currently active
static ACTIVE_TIMER_COUNT: AtomicU64 = AtomicU64::new(0);

/// Initialize the timer subsystem
///
/// # Safety
/// Must be called once during kernel initialization
pub unsafe fn ki_init_timer_system() {
    if TIMER_LIST_INITIALIZED.swap(true, Ordering::AcqRel) {
        return; // Already initialized
    }

    // Initialize timer list head
    let head = TIMER_LIST_HEAD.get();
    (*head).init_head();

    crate::serial_println!("[TIMER] Timer subsystem initialized");
}

/// Insert a timer into the timer queue
///
/// Timers are inserted in sorted order by due time for efficient processing.
///
/// # Safety
/// Timer must be properly initialized
unsafe fn ki_insert_timer(timer: &KTimer) {
    // Mark as inserted
    timer.inserted.store(true, Ordering::Release);

    let due_time = timer.due_time();
    let new_entry = &mut *timer.timer_list_entry.get();
    let head = TIMER_LIST_HEAD.get();

    // Find insertion point (sorted by due time)
    let mut current = (*head).flink;
    while current != head {
        let current_timer = containing_record!(current, KTimer, timer_list_entry);
        if (*current_timer).due_time() > due_time {
            // Insert before this timer
            break;
        }
        current = (*current).flink;
    }

    // Insert before current (or at end if current == head)
    let prev = (*current).blink;
    new_entry.flink = current;
    new_entry.blink = prev;
    (*prev).flink = new_entry;
    (*current).blink = new_entry;

    ACTIVE_TIMER_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Process expired timers
///
/// Called from the timer interrupt to check and expire any due timers.
///
/// # Safety
/// Must be called from timer interrupt context
pub unsafe fn ki_expire_timers() {
    if !TIMER_LIST_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    let current_time = apic::get_tick_count();
    let head = TIMER_LIST_HEAD.get();

    // Process all expired timers (they're sorted, so stop at first non-expired)
    loop {
        if (*head).is_empty() {
            break;
        }

        let first = (*head).flink;
        let timer = containing_record!(first, KTimer, timer_list_entry);

        if (*timer).due_time() > current_time {
            // This timer hasn't expired yet, and neither have any after it
            break;
        }

        // Timer has expired - process it
        ACTIVE_TIMER_COUNT.fetch_sub(1, Ordering::Relaxed);
        (*timer).expire();
    }
}

/// Get the number of active timers
pub fn ki_get_active_timer_count() -> u64 {
    ACTIVE_TIMER_COUNT.load(Ordering::Relaxed)
}

/// Get the time until next timer expiration
///
/// Returns None if no timers are active
pub fn ki_get_next_timer_delta() -> Option<u64> {
    unsafe {
        if !TIMER_LIST_INITIALIZED.load(Ordering::Acquire) {
            return None;
        }

        let head = TIMER_LIST_HEAD.get();
        if (*head).is_empty() {
            return None;
        }

        let first = (*head).flink;
        let timer = containing_record!(first, KTimer, timer_list_entry);
        let current_time = apic::get_tick_count();
        let due_time = (*timer).due_time();

        if due_time <= current_time {
            Some(0) // Already expired
        } else {
            Some(due_time - current_time)
        }
    }
}

// ============================================================================
// Timer Queue Inspection (for debugging)
// ============================================================================

/// Snapshot of a timer for debugging
#[derive(Debug, Clone, Copy)]
pub struct TimerSnapshot {
    /// Timer address (for identification)
    pub address: u64,
    /// Due time (absolute tick count)
    pub due_time: u64,
    /// Period (0 = one-shot)
    pub period: u32,
    /// Timer type
    pub timer_type: TimerType,
    /// Whether timer is signaled
    pub signaled: bool,
    /// Whether timer has an associated DPC
    pub has_dpc: bool,
    /// DPC address (if any)
    pub dpc_address: u64,
}

/// Get timer queue statistics
#[derive(Debug, Clone, Copy)]
pub struct TimerQueueStats {
    /// Number of active timers
    pub active_count: u64,
    /// Number of periodic timers
    pub periodic_count: u64,
    /// Number of one-shot timers
    pub oneshot_count: u64,
    /// Number of signaled timers
    pub signaled_count: u64,
    /// Nearest timer expiration (ms from now)
    pub next_expiration_ms: Option<u64>,
    /// Current tick count
    pub current_time: u64,
}

/// Get timer queue statistics
pub fn ki_get_timer_stats() -> TimerQueueStats {
    unsafe {
        if !TIMER_LIST_INITIALIZED.load(Ordering::Acquire) {
            return TimerQueueStats {
                active_count: 0,
                periodic_count: 0,
                oneshot_count: 0,
                signaled_count: 0,
                next_expiration_ms: None,
                current_time: 0,
            };
        }

        let current_time = apic::get_tick_count();
        let head = TIMER_LIST_HEAD.get();

        let mut periodic_count = 0u64;
        let mut oneshot_count = 0u64;
        let mut signaled_count = 0u64;
        let mut next_exp: Option<u64> = None;

        // Walk the timer list
        let mut current = (*head).flink;
        while current != head {
            let timer = containing_record!(current, KTimer, timer_list_entry);

            if (*timer).period() > 0 {
                periodic_count += 1;
            } else {
                oneshot_count += 1;
            }

            if (*timer).is_signaled() {
                signaled_count += 1;
            }

            // First timer is the next to expire (list is sorted)
            if next_exp.is_none() {
                let due = (*timer).due_time();
                if due > current_time {
                    next_exp = Some(due - current_time);
                } else {
                    next_exp = Some(0);
                }
            }

            current = (*current).flink;
        }

        TimerQueueStats {
            active_count: ACTIVE_TIMER_COUNT.load(Ordering::Relaxed),
            periodic_count,
            oneshot_count,
            signaled_count,
            next_expiration_ms: next_exp,
            current_time,
        }
    }
}

/// Get a snapshot of timers in the queue
/// Returns up to `max_count` timer snapshots
pub fn ki_get_timer_snapshots(max_count: usize) -> ([TimerSnapshot; 32], usize) {
    let mut snapshots = [TimerSnapshot {
        address: 0,
        due_time: 0,
        period: 0,
        timer_type: TimerType::Notification,
        signaled: false,
        has_dpc: false,
        dpc_address: 0,
    }; 32];

    let max_count = max_count.min(32);
    let mut count = 0;

    unsafe {
        if !TIMER_LIST_INITIALIZED.load(Ordering::Acquire) {
            return (snapshots, 0);
        }

        let head = TIMER_LIST_HEAD.get();
        let mut current = (*head).flink;

        while current != head && count < max_count {
            let timer = containing_record!(current, KTimer, timer_list_entry);
            let dpc_ptr = *(*timer).dpc.get();

            snapshots[count] = TimerSnapshot {
                address: timer as u64,
                due_time: (*timer).due_time(),
                period: (*timer).period(),
                timer_type: *(*timer).timer_type.get(),
                signaled: (*timer).is_signaled(),
                has_dpc: !dpc_ptr.is_null(),
                dpc_address: dpc_ptr as u64,
            };

            count += 1;
            current = (*current).flink;
        }
    }

    (snapshots, count)
}

/// Get timer type name
pub fn timer_type_name(tt: TimerType) -> &'static str {
    match tt {
        TimerType::Notification => "Notification",
        TimerType::Synchronization => "Synchronization",
    }
}
