//! RTL Time Functions
//!
//! Time conversion and manipulation functions following NT conventions.
//!
//! NT uses 64-bit timestamps representing 100-nanosecond intervals
//! since January 1, 1601 (the FILETIME epoch).
//!
//! # Key Types
//! - `LargeInteger`: 64-bit time value in 100ns units
//! - `TimeFields`: Broken-down time (year, month, day, etc.)

/// Time fields structure (broken-down time)
///
/// This is the NT equivalent of struct tm in C.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeFields {
    /// Year (1601-30827)
    pub year: i16,
    /// Month (1-12)
    pub month: i16,
    /// Day of month (1-31)
    pub day: i16,
    /// Hour (0-23)
    pub hour: i16,
    /// Minute (0-59)
    pub minute: i16,
    /// Second (0-59)
    pub second: i16,
    /// Milliseconds (0-999)
    pub milliseconds: i16,
    /// Day of week (0-6, Sunday=0)
    pub weekday: i16,
}

impl TimeFields {
    /// Create a new TimeFields with all zeros
    pub const fn new() -> Self {
        Self {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0,
            milliseconds: 0,
            weekday: 0,
        }
    }
}

/// Number of 100-nanosecond intervals per millisecond
pub const TICKS_PER_MILLISECOND: i64 = 10_000;

/// Number of 100-nanosecond intervals per second
pub const TICKS_PER_SECOND: i64 = 10_000_000;

/// Number of 100-nanosecond intervals per minute
pub const TICKS_PER_MINUTE: i64 = TICKS_PER_SECOND * 60;

/// Number of 100-nanosecond intervals per hour
pub const TICKS_PER_HOUR: i64 = TICKS_PER_MINUTE * 60;

/// Number of 100-nanosecond intervals per day
pub const TICKS_PER_DAY: i64 = TICKS_PER_HOUR * 24;

/// Days from 1601 to 1970 (Unix epoch)
const DAYS_FROM_1601_TO_1970: i64 = 134774;

/// Ticks from 1601 to 1970
pub const TICKS_1601_TO_1970: i64 = DAYS_FROM_1601_TO_1970 * TICKS_PER_DAY;

/// Days in each month (non-leap year)
const DAYS_IN_MONTH: [i16; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Days before each month (cumulative, non-leap year)
const DAYS_BEFORE_MONTH: [i16; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

/// Check if a year is a leap year
#[inline]
pub fn is_leap_year(year: i16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Get days in a specific month
pub fn days_in_month(year: i16, month: i16) -> i16 {
    if month < 1 || month > 12 {
        return 0;
    }
    let days = DAYS_IN_MONTH[(month - 1) as usize];
    if month == 2 && is_leap_year(year) {
        days + 1
    } else {
        days
    }
}

/// Convert NT time (100ns intervals since 1601) to TimeFields
///
/// # Arguments
/// * `time` - 64-bit NT timestamp
/// * `time_fields` - Output TimeFields structure
///
/// # Safety
/// `time_fields` must be a valid pointer
pub unsafe fn rtl_time_to_time_fields(time: i64, time_fields: *mut TimeFields) {
    if time_fields.is_null() {
        return;
    }

    let tf = &mut *time_fields;

    // Handle negative time
    if time < 0 {
        *tf = TimeFields::new();
        return;
    }

    // Calculate total days and remaining ticks
    let mut total_days = (time / TICKS_PER_DAY) as i32;
    let mut remaining_ticks = time % TICKS_PER_DAY;

    // Calculate time of day
    tf.hour = (remaining_ticks / TICKS_PER_HOUR) as i16;
    remaining_ticks %= TICKS_PER_HOUR;

    tf.minute = (remaining_ticks / TICKS_PER_MINUTE) as i16;
    remaining_ticks %= TICKS_PER_MINUTE;

    tf.second = (remaining_ticks / TICKS_PER_SECOND) as i16;
    remaining_ticks %= TICKS_PER_SECOND;

    tf.milliseconds = (remaining_ticks / TICKS_PER_MILLISECOND) as i16;

    // Calculate day of week (January 1, 1601 was a Monday)
    tf.weekday = ((total_days + 1) % 7) as i16;

    // Calculate year
    // Start from 1601 and work forward
    let mut year: i32 = 1601;

    loop {
        let days_in_year = if is_leap_year(year as i16) { 366 } else { 365 };
        if total_days < days_in_year {
            break;
        }
        total_days -= days_in_year;
        year += 1;
    }

    tf.year = year as i16;

    // Calculate month and day
    let leap = is_leap_year(tf.year);
    let mut month = 1i16;

    for m in 1..=12 {
        let days = if m == 2 && leap {
            29
        } else {
            DAYS_IN_MONTH[(m - 1) as usize] as i32
        };

        if total_days < days {
            month = m as i16;
            break;
        }
        total_days -= days;
    }

    tf.month = month;
    tf.day = (total_days + 1) as i16;
}

/// Convert TimeFields to NT time (100ns intervals since 1601)
///
/// # Arguments
/// * `time_fields` - Input TimeFields structure
/// * `time` - Output 64-bit NT timestamp
///
/// # Returns
/// true if conversion succeeded, false if fields are invalid
///
/// # Safety
/// Both pointers must be valid
pub unsafe fn rtl_time_fields_to_time(time_fields: *const TimeFields, time: *mut i64) -> bool {
    if time_fields.is_null() || time.is_null() {
        return false;
    }

    let tf = &*time_fields;

    // Validate fields
    if tf.year < 1601 || tf.year > 30827 {
        return false;
    }
    if tf.month < 1 || tf.month > 12 {
        return false;
    }
    if tf.day < 1 || tf.day > days_in_month(tf.year, tf.month) {
        return false;
    }
    if tf.hour < 0 || tf.hour > 23 {
        return false;
    }
    if tf.minute < 0 || tf.minute > 59 {
        return false;
    }
    if tf.second < 0 || tf.second > 59 {
        return false;
    }
    if tf.milliseconds < 0 || tf.milliseconds > 999 {
        return false;
    }

    // Calculate days from 1601 to the start of the year
    let mut total_days: i64 = 0;
    for y in 1601..tf.year {
        total_days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Add days for months in current year
    let leap = is_leap_year(tf.year);
    for m in 1..tf.month {
        total_days += if m == 2 && leap {
            29
        } else {
            DAYS_IN_MONTH[(m - 1) as usize] as i64
        };
    }

    // Add days in current month
    total_days += (tf.day - 1) as i64;

    // Calculate total ticks
    let mut total_ticks = total_days * TICKS_PER_DAY;
    total_ticks += tf.hour as i64 * TICKS_PER_HOUR;
    total_ticks += tf.minute as i64 * TICKS_PER_MINUTE;
    total_ticks += tf.second as i64 * TICKS_PER_SECOND;
    total_ticks += tf.milliseconds as i64 * TICKS_PER_MILLISECOND;

    *time = total_ticks;
    true
}

/// Convert Unix timestamp to NT time
///
/// Unix time: seconds since January 1, 1970
/// NT time: 100ns intervals since January 1, 1601
#[inline]
pub fn unix_time_to_nt_time(unix_time: i64) -> i64 {
    TICKS_1601_TO_1970 + (unix_time * TICKS_PER_SECOND)
}

/// Convert NT time to Unix timestamp
///
/// Returns seconds since January 1, 1970
#[inline]
pub fn nt_time_to_unix_time(nt_time: i64) -> i64 {
    (nt_time - TICKS_1601_TO_1970) / TICKS_PER_SECOND
}

/// Get current system time in NT format (FILETIME - 100ns intervals since 1601)
///
/// Reads from the hardware RTC via the HAL and returns the current time
/// in Windows FILETIME format.
pub fn rtl_get_system_time() -> i64 {
    // Get current time from the hardware RTC
    crate::hal::rtc::get_system_time() as i64
}

/// Get local time in NT format
///
/// Currently returns the same as system time (no timezone adjustment).
/// In a full implementation, this would apply timezone offset.
pub fn rtl_get_local_time() -> i64 {
    // TODO: Apply timezone offset
    // For now, return UTC time
    rtl_get_system_time()
}

/// Query system time and return it in a TimeFields structure
pub fn rtl_query_system_time(time_fields: &mut TimeFields) {
    let time = rtl_get_system_time();
    unsafe {
        rtl_time_to_time_fields(time, time_fields);
    }
}

// ============================================================================
// NT-style aliases
// ============================================================================

/// Alias for rtl_time_to_time_fields (NT naming)
#[inline]
pub unsafe fn RtlTimeToTimeFields(time: i64, time_fields: *mut TimeFields) {
    rtl_time_to_time_fields(time, time_fields)
}

/// Alias for rtl_time_fields_to_time (NT naming)
#[inline]
pub unsafe fn RtlTimeFieldsToTime(time_fields: *const TimeFields, time: *mut i64) -> bool {
    rtl_time_fields_to_time(time_fields, time)
}

/// Alias for rtl_get_system_time (NT naming)
#[inline]
pub fn RtlGetSystemTime() -> i64 {
    rtl_get_system_time()
}

// ============================================================================
// Display formatting
// ============================================================================

impl core::fmt::Display for TimeFields {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            self.year, self.month, self.day,
            self.hour, self.minute, self.second, self.milliseconds
        )
    }
}
