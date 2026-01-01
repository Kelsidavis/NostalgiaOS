//! Time Zone Support
//!
//! Provides system time to local time conversion and time zone management.
//!
//! # NT Functions
//!
//! - `ExSystemTimeToLocalTime` - Convert system time to local time
//! - `ExLocalTimeToSystemTime` - Convert local time to system time
//! - `RtlQueryTimeZoneInformation` - Query current time zone
//! - `RtlSetTimeZoneInformation` - Set time zone (requires privilege)
//!
//! # Time Zones
//!
//! Time zones in NT are defined by:
//! - Bias: Minutes west of UTC (negative = east)
//! - Standard time offset
//! - Daylight saving time offset
//! - Rules for DST transitions

use core::sync::atomic::{AtomicI32, AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;

/// Minutes per hour
const MINUTES_PER_HOUR: i32 = 60;

/// Minutes per day
const MINUTES_PER_DAY: i32 = 24 * 60;

/// 100ns intervals per minute
const INTERVALS_PER_MINUTE: i64 = 60 * 10_000_000;

/// Time zone name length
pub const TIME_ZONE_NAME_LENGTH: usize = 32;

/// System time structure (same as LARGE_INTEGER)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SystemTime {
    /// Time in 100ns intervals since Jan 1, 1601
    pub quad_part: i64,
}

impl SystemTime {
    pub const fn new(time: i64) -> Self {
        Self { quad_part: time }
    }

    pub const fn zero() -> Self {
        Self { quad_part: 0 }
    }
}

/// Time zone information
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TimeZoneInformation {
    /// Bias from UTC in minutes (positive = west of Greenwich)
    pub bias: i32,
    /// Standard time name (null-terminated UTF-16)
    pub standard_name: [u16; TIME_ZONE_NAME_LENGTH],
    /// Standard date (transition from DST to standard)
    pub standard_date: SystemTime,
    /// Standard time bias (additional minutes)
    pub standard_bias: i32,
    /// Daylight time name (null-terminated UTF-16)
    pub daylight_name: [u16; TIME_ZONE_NAME_LENGTH],
    /// Daylight date (transition from standard to DST)
    pub daylight_date: SystemTime,
    /// Daylight time bias (additional minutes)
    pub daylight_bias: i32,
}

impl Default for TimeZoneInformation {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeZoneInformation {
    /// Create a new time zone with zero bias (UTC)
    pub const fn new() -> Self {
        Self {
            bias: 0,
            standard_name: [0; TIME_ZONE_NAME_LENGTH],
            standard_date: SystemTime::zero(),
            standard_bias: 0,
            daylight_name: [0; TIME_ZONE_NAME_LENGTH],
            daylight_date: SystemTime::zero(),
            daylight_bias: 0,
        }
    }

    /// Create UTC time zone
    pub fn utc() -> Self {
        let mut tz = Self::new();
        // Set name to "UTC"
        tz.standard_name[0] = 'U' as u16;
        tz.standard_name[1] = 'T' as u16;
        tz.standard_name[2] = 'C' as u16;
        tz
    }

    /// Create a time zone with simple bias (no DST)
    pub fn with_bias(bias_minutes: i32) -> Self {
        let mut tz = Self::new();
        tz.bias = bias_minutes;
        tz
    }

    /// Get total bias in minutes for current time
    ///
    /// This considers DST if applicable
    pub fn get_current_bias(&self) -> i32 {
        // For now, just return the base bias
        // Full implementation would check if current time is in DST
        self.bias + self.standard_bias
    }

    /// Check if DST is currently active
    pub fn is_daylight_time(&self, _system_time: i64) -> bool {
        // Simplified: check if daylight date is set
        if self.daylight_date.quad_part == 0 {
            return false;
        }

        // TODO: Implement proper DST check based on dates
        false
    }
}

/// Dynamic time zone information (Vista+)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DynamicTimeZoneInformation {
    /// Base time zone info
    pub base: TimeZoneInformation,
    /// Key name in registry
    pub time_zone_key_name: [u16; 128],
    /// Disable dynamic DST
    pub dynamic_daylight_time_disabled: bool,
}

impl Default for DynamicTimeZoneInformation {
    fn default() -> Self {
        Self {
            base: TimeZoneInformation::new(),
            time_zone_key_name: [0; 128],
            dynamic_daylight_time_disabled: false,
        }
    }
}

// ============================================================================
// Global Time Zone State
// ============================================================================

/// Current time zone bias in minutes
static CURRENT_BIAS: AtomicI32 = AtomicI32::new(0);

/// Standard time bias
static STANDARD_BIAS: AtomicI32 = AtomicI32::new(0);

/// Daylight time bias
static DAYLIGHT_BIAS: AtomicI32 = AtomicI32::new(-60); // Typical DST is UTC+1

/// Whether DST is currently active
static DST_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Time zone initialized flag
static TIMEZONE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Full time zone information
static mut CURRENT_TIMEZONE: TimeZoneInformation = TimeZoneInformation {
    bias: 0,
    standard_name: [0; TIME_ZONE_NAME_LENGTH],
    standard_date: SystemTime { quad_part: 0 },
    standard_bias: 0,
    daylight_name: [0; TIME_ZONE_NAME_LENGTH],
    daylight_date: SystemTime { quad_part: 0 },
    daylight_bias: 0,
};

static TIMEZONE_LOCK: SpinLock<()> = SpinLock::new(());

// ============================================================================
// Time Conversion Functions
// ============================================================================

/// Convert system time (UTC) to local time (ExSystemTimeToLocalTime)
///
/// # Arguments
/// * `system_time` - UTC time in 100ns intervals
/// * `local_time` - Output local time in 100ns intervals
///
/// # Safety
/// The local_time pointer must be valid
#[inline]
pub unsafe fn ex_system_time_to_local_time(system_time: i64, local_time: *mut i64) {
    if local_time.is_null() {
        return;
    }

    let bias_minutes = get_current_bias();
    let bias_intervals = (bias_minutes as i64) * INTERVALS_PER_MINUTE;

    // Local time = System time - bias (bias is positive west of Greenwich)
    *local_time = system_time - bias_intervals;
}

/// Convert local time to system time (UTC) (ExLocalTimeToSystemTime)
///
/// # Arguments
/// * `local_time` - Local time in 100ns intervals
/// * `system_time` - Output UTC time in 100ns intervals
///
/// # Safety
/// The system_time pointer must be valid
#[inline]
pub unsafe fn ex_local_time_to_system_time(local_time: i64, system_time: *mut i64) {
    if system_time.is_null() {
        return;
    }

    let bias_minutes = get_current_bias();
    let bias_intervals = (bias_minutes as i64) * INTERVALS_PER_MINUTE;

    // System time = Local time + bias
    *system_time = local_time + bias_intervals;
}

/// Get current time zone bias in minutes
#[inline]
pub fn get_current_bias() -> i32 {
    let base_bias = CURRENT_BIAS.load(Ordering::Relaxed);
    let extra_bias = if DST_ACTIVE.load(Ordering::Relaxed) {
        DAYLIGHT_BIAS.load(Ordering::Relaxed)
    } else {
        STANDARD_BIAS.load(Ordering::Relaxed)
    };
    base_bias + extra_bias
}

/// Set time zone bias
pub fn set_time_zone_bias(bias_minutes: i32) {
    CURRENT_BIAS.store(bias_minutes, Ordering::Release);
}

/// Set DST state
pub fn set_dst_active(active: bool) {
    DST_ACTIVE.store(active, Ordering::Release);
}

/// Check if DST is active
pub fn is_dst_active() -> bool {
    DST_ACTIVE.load(Ordering::Relaxed)
}

// ============================================================================
// Time Zone Information Query/Set
// ============================================================================

/// Query current time zone information (RtlQueryTimeZoneInformation)
pub fn rtl_query_time_zone_information() -> TimeZoneInformation {
    let _guard = TIMEZONE_LOCK.lock();
    unsafe { CURRENT_TIMEZONE }
}

/// Set time zone information (RtlSetTimeZoneInformation)
///
/// # Arguments
/// * `tz_info` - New time zone information
///
/// # Returns
/// Ok(()) on success, Err(NTSTATUS) on failure
pub fn rtl_set_time_zone_information(tz_info: &TimeZoneInformation) -> Result<(), i32> {
    let _guard = TIMEZONE_LOCK.lock();

    unsafe {
        CURRENT_TIMEZONE = *tz_info;
    }

    // Update cached values
    CURRENT_BIAS.store(tz_info.bias, Ordering::Release);
    STANDARD_BIAS.store(tz_info.standard_bias, Ordering::Release);
    DAYLIGHT_BIAS.store(tz_info.daylight_bias, Ordering::Release);

    Ok(())
}

/// Query dynamic time zone information
pub fn rtl_query_dynamic_time_zone_information() -> DynamicTimeZoneInformation {
    let _guard = TIMEZONE_LOCK.lock();

    DynamicTimeZoneInformation {
        base: unsafe { CURRENT_TIMEZONE },
        time_zone_key_name: [0; 128],
        dynamic_daylight_time_disabled: false,
    }
}

// ============================================================================
// Common Time Zones
// ============================================================================

/// Create Pacific Standard Time zone (UTC-8, DST UTC-7)
pub fn pst_timezone() -> TimeZoneInformation {
    let mut tz = TimeZoneInformation::new();
    tz.bias = 8 * MINUTES_PER_HOUR; // UTC-8
    tz.standard_bias = 0;
    tz.daylight_bias = -MINUTES_PER_HOUR; // UTC-7 during DST

    // Set names
    let pst_name = ['P' as u16, 'a' as u16, 'c' as u16, 'i' as u16, 'f' as u16,
                   'i' as u16, 'c' as u16, ' ' as u16, 'S' as u16, 't' as u16,
                   'a' as u16, 'n' as u16, 'd' as u16, 'a' as u16, 'r' as u16,
                   'd' as u16, ' ' as u16, 'T' as u16, 'i' as u16, 'm' as u16,
                   'e' as u16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    tz.standard_name = pst_name;

    tz
}

/// Create Eastern Standard Time zone (UTC-5, DST UTC-4)
pub fn est_timezone() -> TimeZoneInformation {
    let mut tz = TimeZoneInformation::new();
    tz.bias = 5 * MINUTES_PER_HOUR; // UTC-5
    tz.standard_bias = 0;
    tz.daylight_bias = -MINUTES_PER_HOUR; // UTC-4 during DST

    tz
}

/// Create Central European Time zone (UTC+1, DST UTC+2)
pub fn cet_timezone() -> TimeZoneInformation {
    let mut tz = TimeZoneInformation::new();
    tz.bias = -1 * MINUTES_PER_HOUR; // UTC+1
    tz.standard_bias = 0;
    tz.daylight_bias = -MINUTES_PER_HOUR; // UTC+2 during DST

    tz
}

/// Create Japan Standard Time zone (UTC+9, no DST)
pub fn jst_timezone() -> TimeZoneInformation {
    let mut tz = TimeZoneInformation::new();
    tz.bias = -9 * MINUTES_PER_HOUR; // UTC+9
    tz.standard_bias = 0;
    tz.daylight_bias = 0; // No DST

    tz
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize time zone support
pub fn init() {
    // Default to UTC
    let utc = TimeZoneInformation::utc();
    let _ = rtl_set_time_zone_information(&utc);

    TIMEZONE_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[EX] Time zone support initialized (UTC)");
}

/// Initialize with specific time zone
pub fn init_with_timezone(tz: &TimeZoneInformation) {
    let _ = rtl_set_time_zone_information(tz);
    TIMEZONE_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[EX] Time zone support initialized (bias: {} minutes)", tz.bias);
}

// ============================================================================
// Statistics
// ============================================================================

/// Time zone statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeZoneStats {
    /// Current bias in minutes
    pub current_bias: i32,
    /// Standard bias
    pub standard_bias: i32,
    /// Daylight bias
    pub daylight_bias: i32,
    /// DST is active
    pub dst_active: bool,
    /// Time zone initialized
    pub initialized: bool,
}

/// Get time zone statistics
pub fn get_timezone_stats() -> TimeZoneStats {
    TimeZoneStats {
        current_bias: get_current_bias(),
        standard_bias: STANDARD_BIAS.load(Ordering::Relaxed),
        daylight_bias: DAYLIGHT_BIAS.load(Ordering::Relaxed),
        dst_active: DST_ACTIVE.load(Ordering::Relaxed),
        initialized: TIMEZONE_INITIALIZED.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert bias in minutes to hours and minutes string representation
pub fn bias_to_string(bias: i32) -> (i32, i32, char) {
    let sign = if bias >= 0 { '-' } else { '+' };
    let abs_bias = bias.abs();
    let hours = abs_bias / 60;
    let minutes = abs_bias % 60;
    (hours, minutes, sign)
}

/// Parse a UTC offset string like "+05:30" or "-08:00"
pub fn parse_utc_offset(offset: &str) -> Option<i32> {
    let bytes = offset.as_bytes();
    if bytes.len() < 5 {
        return None;
    }

    let sign = match bytes[0] {
        b'+' => -1, // East of UTC = negative bias
        b'-' => 1,  // West of UTC = positive bias
        _ => return None,
    };

    // Parse hours and minutes
    let hours: i32 = offset.get(1..3)?.parse().ok()?;
    let minutes: i32 = if bytes.len() >= 6 && bytes[3] == b':' {
        offset.get(4..6)?.parse().ok()?
    } else {
        0
    };

    Some(sign * (hours * 60 + minutes))
}
