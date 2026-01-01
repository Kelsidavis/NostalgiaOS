//! USER Timer Subsystem
//!
//! Implementation of window timers following Windows NT architecture.
//! Timers generate WM_TIMER messages at specified intervals.
//!
//! # Functions
//!
//! - `SetTimer` - Create a timer for a window
//! - `KillTimer` - Destroy a timer
//! - `process_timers` - Check and fire expired timers
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/timer.c`

use super::super::{HWND, UserHandle};
use super::message::{self, WM_TIMER};
use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of USER timers
const MAX_TIMERS: usize = 256;

/// Minimum timer interval in milliseconds
pub const USER_TIMER_MINIMUM: u32 = 10;

/// Maximum timer interval in milliseconds
pub const USER_TIMER_MAXIMUM: u32 = 0x7FFFFFFF;

// ============================================================================
// Timer Structure
// ============================================================================

/// USER timer entry
#[derive(Clone, Copy)]
struct UserTimer {
    /// Window that receives WM_TIMER messages
    hwnd: HWND,

    /// Timer ID (unique per window)
    timer_id: usize,

    /// Interval in milliseconds
    interval_ms: u32,

    /// Next expiration time (system tick count)
    next_fire: u64,

    /// Timer callback function pointer (optional)
    callback: usize,

    /// Is this timer slot in use?
    in_use: bool,
}

impl UserTimer {
    const fn empty() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            timer_id: 0,
            interval_ms: 0,
            next_fire: 0,
            callback: 0,
            in_use: false,
        }
    }
}

// ============================================================================
// Timer Table
// ============================================================================

/// Timer table for managing active timers
struct TimerTable {
    timers: [UserTimer; MAX_TIMERS],
    count: usize,
}

impl TimerTable {
    const fn new() -> Self {
        Self {
            timers: [UserTimer::empty(); MAX_TIMERS],
            count: 0,
        }
    }
}

static TIMER_TABLE: SpinLock<TimerTable> = SpinLock::new(TimerTable::new());
static TIMER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_TIMER_ID: AtomicU32 = AtomicU32::new(1);

/// System tick counter (milliseconds since boot)
/// This should be updated by the system timer interrupt
static SYSTEM_TICK_COUNT: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the timer subsystem
pub fn init() {
    if TIMER_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[USER/Timer] Timer subsystem initialized");
    TIMER_INITIALIZED.store(true, Ordering::Release);
}

// ============================================================================
// System Tick Management
// ============================================================================

/// Get current system tick count in milliseconds
pub fn get_tick_count() -> u64 {
    SYSTEM_TICK_COUNT.load(Ordering::Relaxed)
}

/// Increment the system tick count (called by timer interrupt)
pub fn increment_tick_count(ms: u64) {
    SYSTEM_TICK_COUNT.fetch_add(ms, Ordering::Relaxed);
}

/// Set the system tick count
pub fn set_tick_count(ms: u64) {
    SYSTEM_TICK_COUNT.store(ms, Ordering::Relaxed);
}

// ============================================================================
// Timer API
// ============================================================================

/// Create a timer for a window
///
/// # Arguments
/// * `hwnd` - Window to receive WM_TIMER messages (NULL for thread timer)
/// * `timer_id` - Timer identifier
/// * `interval` - Interval in milliseconds
/// * `callback` - Optional timer callback function (0 for WM_TIMER only)
///
/// # Returns
/// Timer ID on success, 0 on failure
pub fn set_timer(hwnd: HWND, timer_id: usize, interval: u32, callback: usize) -> usize {
    // Clamp interval to valid range
    let interval = interval.clamp(USER_TIMER_MINIMUM, USER_TIMER_MAXIMUM);

    let mut table = TIMER_TABLE.lock();

    // Check if this timer already exists (for modification)
    for timer in table.timers.iter_mut() {
        if timer.in_use && timer.hwnd == hwnd && timer.timer_id == timer_id {
            // Modify existing timer
            timer.interval_ms = interval;
            timer.next_fire = get_tick_count() + interval as u64;
            timer.callback = callback;
            return timer_id;
        }
    }

    // Find an empty slot for new timer
    for timer in table.timers.iter_mut() {
        if !timer.in_use {
            let id = if timer_id == 0 {
                NEXT_TIMER_ID.fetch_add(1, Ordering::Relaxed) as usize
            } else {
                timer_id
            };

            timer.hwnd = hwnd;
            timer.timer_id = id;
            timer.interval_ms = interval;
            timer.next_fire = get_tick_count() + interval as u64;
            timer.callback = callback;
            timer.in_use = true;
            table.count += 1;

            crate::serial_println!("[USER/Timer] Timer {} created for hwnd {:x}, interval={}ms",
                id, hwnd.raw(), interval);

            return id;
        }
    }

    // No free timer slots
    crate::serial_println!("[USER/Timer] ERROR: No free timer slots");
    0
}

/// Destroy a timer
///
/// # Arguments
/// * `hwnd` - Window that owns the timer
/// * `timer_id` - Timer identifier
///
/// # Returns
/// true on success, false if timer not found
pub fn kill_timer(hwnd: HWND, timer_id: usize) -> bool {
    let mut table = TIMER_TABLE.lock();

    for timer in table.timers.iter_mut() {
        if timer.in_use && timer.hwnd == hwnd && timer.timer_id == timer_id {
            timer.in_use = false;
            table.count -= 1;

            crate::serial_println!("[USER/Timer] Timer {} destroyed", timer_id);
            return true;
        }
    }

    false
}

/// Kill all timers for a window (called when window is destroyed)
pub fn kill_window_timers(hwnd: HWND) {
    let mut table = TIMER_TABLE.lock();

    let mut killed = 0usize;
    for timer in table.timers.iter_mut() {
        if timer.in_use && timer.hwnd == hwnd {
            timer.in_use = false;
            killed += 1;
        }
    }
    table.count = table.count.saturating_sub(killed);
}

/// Process expired timers and post WM_TIMER messages
///
/// Should be called periodically from the message loop or timer interrupt
pub fn process_timers() {
    let current_tick = get_tick_count();

    let mut table = TIMER_TABLE.lock();

    for timer in table.timers.iter_mut() {
        if timer.in_use && current_tick >= timer.next_fire {
            // Timer has expired

            if timer.callback != 0 {
                // Call the timer callback
                // Note: In a real implementation, this would be a function pointer
                // For now, we just post a message
                message::post_message(timer.hwnd, WM_TIMER, timer.timer_id, timer.callback as isize);
            } else {
                // Post WM_TIMER message
                message::post_message(timer.hwnd, WM_TIMER, timer.timer_id, 0);
            }

            // Schedule next fire time
            timer.next_fire = current_tick + timer.interval_ms as u64;
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Timer statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct TimerStats {
    pub active_timers: usize,
    pub system_tick_count: u64,
}

/// Get timer statistics
pub fn get_stats() -> TimerStats {
    let table = TIMER_TABLE.lock();
    TimerStats {
        active_timers: table.count,
        system_tick_count: get_tick_count(),
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if any timers are pending for a window
pub fn has_pending_timers(hwnd: HWND) -> bool {
    let current_tick = get_tick_count();
    let table = TIMER_TABLE.lock();

    for timer in table.timers.iter() {
        if timer.in_use && timer.hwnd == hwnd && current_tick >= timer.next_fire {
            return true;
        }
    }

    false
}

/// Get the next timer expiration time (for sleep optimization)
pub fn get_next_timer_expiration() -> Option<u64> {
    let table = TIMER_TABLE.lock();

    let mut min_time: Option<u64> = None;

    for timer in table.timers.iter() {
        if timer.in_use {
            match min_time {
                None => min_time = Some(timer.next_fire),
                Some(t) if timer.next_fire < t => min_time = Some(timer.next_fire),
                _ => {}
            }
        }
    }

    min_time
}
