//! Executive Delay Execution Service
//!
//! Provides the NtDelayExecution system call which delays the calling
//! thread for a specified interval. The delay can be specified as either
//! an absolute time or a relative interval.
//!
//! # Time Format
//!
//! - Positive values: Absolute time (100ns intervals since Jan 1, 1601)
//! - Negative values: Relative time (100ns intervals from now)
//!
//! # Alertable Waits
//!
//! If `alertable` is true, the delay can be interrupted by:
//! - Kernel APCs (always, regardless of alertable flag)
//! - User APCs (only when alertable=true)
//! - Alert signals (only when alertable=true)
//!
//! # NT Functions
//!
//! - `NtDelayExecution` - Delay thread execution

use core::sync::atomic::{AtomicU64, Ordering};

/// Statistics for delay execution
#[derive(Debug, Clone, Copy, Default)]
pub struct DelayStats {
    /// Total delay calls
    pub total_delays: u64,
    /// Alertable delays
    pub alertable_delays: u64,
    /// Delays interrupted by APC
    pub interrupted_delays: u64,
    /// Total time delayed (100ns units)
    pub total_delay_time: u64,
}

static TOTAL_DELAYS: AtomicU64 = AtomicU64::new(0);
static ALERTABLE_DELAYS: AtomicU64 = AtomicU64::new(0);
static INTERRUPTED_DELAYS: AtomicU64 = AtomicU64::new(0);
static TOTAL_DELAY_TIME: AtomicU64 = AtomicU64::new(0);

/// Convert 100ns intervals to milliseconds
#[inline]
fn intervals_to_ms(intervals: i64) -> u64 {
    // 10,000 100ns intervals = 1 millisecond
    (intervals.unsigned_abs() / 10_000) as u64
}

/// Delay execution of the current thread (NtDelayExecution)
///
/// Delays the current thread for the specified interval.
///
/// # Arguments
/// * `alertable` - If true, the delay can be interrupted by user APCs
/// * `delay_interval` - Time to delay:
///   - Negative: Relative delay (intervals from now)
///   - Positive: Absolute time (intervals since Jan 1, 1601)
///
/// # Returns
/// * `STATUS_SUCCESS` (0) - Delay completed normally
/// * `STATUS_ALERTED` - Thread was alerted (alertable only)
/// * `STATUS_USER_APC` - Delay interrupted by user APC (alertable only)
pub fn nt_delay_execution(alertable: bool, delay_interval: i64) -> i32 {
    TOTAL_DELAYS.fetch_add(1, Ordering::Relaxed);

    if alertable {
        ALERTABLE_DELAYS.fetch_add(1, Ordering::Relaxed);
    }

    // Handle the delay based on interval type
    let delay_ms = if delay_interval < 0 {
        // Negative = relative delay
        intervals_to_ms(delay_interval)
    } else if delay_interval == 0 {
        // Zero delay = yield
        0
    } else {
        // Positive = absolute time
        // Calculate relative delay from current time
        let current_time = crate::rtl::rtl_get_system_time();
        let target_time = delay_interval;

        if target_time <= current_time {
            0 // Already past
        } else {
            ((target_time - current_time) / 10_000) as u64 // Convert to ms
        }
    };

    // Track total delay time
    TOTAL_DELAY_TIME.fetch_add(delay_ms * 10_000, Ordering::Relaxed);

    // Perform the delay
    let completed = if delay_ms == 0 {
        // Just yield
        unsafe { crate::ke::scheduler::ki_yield(); }
        true
    } else {
        // Use kernel delay function
        unsafe { crate::ke::wait::ke_delay_execution_alertable(delay_ms, alertable) }
    };

    if completed {
        0 // STATUS_SUCCESS
    } else {
        INTERRUPTED_DELAYS.fetch_add(1, Ordering::Relaxed);
        -1073741849 // STATUS_USER_APC
    }
}

/// Kernel mode delay execution (KeDelayExecutionThread)
///
/// This is the kernel-mode implementation called by NtDelayExecution.
///
/// # Arguments
/// * `wait_mode` - Processor mode (0=Kernel, 1=User)
/// * `alertable` - If true, delay can be interrupted
/// * `interval` - Delay interval (100ns units, negative=relative)
pub fn ke_delay_execution_thread(wait_mode: u8, alertable: bool, interval: i64) -> i32 {
    // For kernel mode, just use the same implementation
    let _ = wait_mode;
    nt_delay_execution(alertable, interval)
}

/// Sleep for specified milliseconds (convenience function)
///
/// Sleeps the current thread for the specified number of milliseconds.
/// This is a simple wrapper around nt_delay_execution.
pub fn ex_sleep(milliseconds: u32) {
    // Convert to 100ns intervals (negative for relative)
    let intervals = -(milliseconds as i64 * 10_000);
    nt_delay_execution(false, intervals);
}

/// Sleep for specified milliseconds, alertable
pub fn ex_sleep_alertable(milliseconds: u32) -> bool {
    let intervals = -(milliseconds as i64 * 10_000);
    nt_delay_execution(true, intervals) == 0
}

/// Yield execution without delay
///
/// Gives other threads a chance to run without actually delaying.
#[inline]
pub fn ex_yield() {
    nt_delay_execution(false, 0);
}

/// Get delay statistics
pub fn get_delay_stats() -> DelayStats {
    DelayStats {
        total_delays: TOTAL_DELAYS.load(Ordering::Relaxed),
        alertable_delays: ALERTABLE_DELAYS.load(Ordering::Relaxed),
        interrupted_delays: INTERRUPTED_DELAYS.load(Ordering::Relaxed),
        total_delay_time: TOTAL_DELAY_TIME.load(Ordering::Relaxed),
    }
}

/// Reset delay statistics
pub fn reset_delay_stats() {
    TOTAL_DELAYS.store(0, Ordering::Relaxed);
    ALERTABLE_DELAYS.store(0, Ordering::Relaxed);
    INTERRUPTED_DELAYS.store(0, Ordering::Relaxed);
    TOTAL_DELAY_TIME.store(0, Ordering::Relaxed);
}

// ============================================================================
// Time Conversion Helpers
// ============================================================================

/// Convert milliseconds to 100ns intervals
#[inline]
pub const fn ms_to_intervals(ms: u32) -> i64 {
    -(ms as i64 * 10_000)
}

/// Convert seconds to 100ns intervals
#[inline]
pub const fn seconds_to_intervals(seconds: u32) -> i64 {
    -(seconds as i64 * 10_000_000)
}

/// Convert microseconds to 100ns intervals
#[inline]
pub const fn us_to_intervals(us: u64) -> i64 {
    -(us as i64 * 10)
}

/// Infinite timeout value
pub const INFINITE: i64 = i64::MIN;

// ============================================================================
// Initialization
// ============================================================================

/// Initialize delay execution support
pub fn init() {
    TOTAL_DELAYS.store(0, Ordering::Release);
    ALERTABLE_DELAYS.store(0, Ordering::Release);
    INTERRUPTED_DELAYS.store(0, Ordering::Release);
    TOTAL_DELAY_TIME.store(0, Ordering::Release);

    crate::serial_println!("[EX] Delay execution support initialized");
}
