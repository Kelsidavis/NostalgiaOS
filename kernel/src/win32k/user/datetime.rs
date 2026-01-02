//! Date/Time Dialog
//!
//! Provides date and time settings dialog following Windows
//! timedate.cpl patterns.
//!
//! # References
//!
//! - Windows Server 2003 Date and Time control panel
//! - Time zone API

use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum name length
pub const MAX_NAME: usize = 64;

/// Days per month (non-leap year)
pub const DAYS_PER_MONTH: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Day names
pub const DAY_NAMES: [&[u8]; 7] = [
    b"Sunday", b"Monday", b"Tuesday", b"Wednesday",
    b"Thursday", b"Friday", b"Saturday"
];

/// Day abbreviations
pub const DAY_ABBREV: [&[u8]; 7] = [
    b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"
];

/// Month names
pub const MONTH_NAMES: [&[u8]; 12] = [
    b"January", b"February", b"March", b"April",
    b"May", b"June", b"July", b"August",
    b"September", b"October", b"November", b"December"
];

/// Month abbreviations
pub const MONTH_ABBREV: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun",
    b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"
];

// ============================================================================
// Structures
// ============================================================================

/// System time structure
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTime {
    /// Year (e.g., 2003)
    pub year: u16,
    /// Month (1-12)
    pub month: u16,
    /// Day of week (0-6, 0 = Sunday)
    pub day_of_week: u16,
    /// Day of month (1-31)
    pub day: u16,
    /// Hour (0-23)
    pub hour: u16,
    /// Minute (0-59)
    pub minute: u16,
    /// Second (0-59)
    pub second: u16,
    /// Milliseconds (0-999)
    pub milliseconds: u16,
}

impl SystemTime {
    pub const fn new() -> Self {
        Self {
            year: 2003,
            month: 1,
            day_of_week: 0,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            milliseconds: 0,
        }
    }
}

/// Time zone information
#[derive(Clone, Copy)]
pub struct TimeZoneInfo {
    /// Bias from UTC in minutes
    pub bias: i32,
    /// Standard name length
    pub standard_name_len: u8,
    /// Standard name
    pub standard_name: [u8; MAX_NAME],
    /// Standard date/time
    pub standard_date: SystemTime,
    /// Standard bias
    pub standard_bias: i32,
    /// Daylight name length
    pub daylight_name_len: u8,
    /// Daylight name
    pub daylight_name: [u8; MAX_NAME],
    /// Daylight date/time
    pub daylight_date: SystemTime,
    /// Daylight bias
    pub daylight_bias: i32,
}

impl TimeZoneInfo {
    const fn new() -> Self {
        Self {
            bias: 0,
            standard_name_len: 0,
            standard_name: [0; MAX_NAME],
            standard_date: SystemTime::new(),
            standard_bias: 0,
            daylight_name_len: 0,
            daylight_name: [0; MAX_NAME],
            daylight_date: SystemTime::new(),
            daylight_bias: 0,
        }
    }

    /// Set standard name
    pub fn set_standard_name(&mut self, name: &[u8]) {
        self.standard_name_len = name.len().min(MAX_NAME) as u8;
        let len = self.standard_name_len as usize;
        self.standard_name[..len].copy_from_slice(&name[..len]);
    }

    /// Set daylight name
    pub fn set_daylight_name(&mut self, name: &[u8]) {
        self.daylight_name_len = name.len().min(MAX_NAME) as u8;
        let len = self.daylight_name_len as usize;
        self.daylight_name[..len].copy_from_slice(&name[..len]);
    }
}

/// Time zone entry
#[derive(Clone, Copy)]
pub struct TimeZoneEntry {
    /// Entry is valid
    pub valid: bool,
    /// Display name length
    pub display_name_len: u8,
    /// Display name
    pub display_name: [u8; 128],
    /// UTC offset in minutes
    pub utc_offset: i16,
    /// Has daylight saving
    pub has_dst: bool,
    /// Time zone info
    pub info: TimeZoneInfo,
}

impl TimeZoneEntry {
    const fn new() -> Self {
        Self {
            valid: false,
            display_name_len: 0,
            display_name: [0; 128],
            utc_offset: 0,
            has_dst: false,
            info: TimeZoneInfo::new(),
        }
    }
}

/// Date/time dialog state
#[derive(Clone, Copy)]
pub struct DateTimeDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Current tab (0=date/time, 1=time zone, 2=internet time)
    pub current_tab: u8,
    /// Pending time
    pub pending_time: SystemTime,
    /// Pending time zone index
    pub pending_tz: u8,
    /// Changes pending
    pub changes_pending: bool,
}

impl DateTimeDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            current_tab: 0,
            pending_time: SystemTime::new(),
            pending_tz: 0,
            changes_pending: false,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static DATETIME_INITIALIZED: AtomicBool = AtomicBool::new(false);
static DATETIME_LOCK: SpinLock<()> = SpinLock::new(());

// Current time (would be updated by RTC)
static CURRENT_TIME: SpinLock<SystemTime> = SpinLock::new(SystemTime::new());
static CURRENT_TZ: SpinLock<TimeZoneInfo> = SpinLock::new(TimeZoneInfo::new());

// Time zones
const MAX_TIMEZONES: usize = 32;
static TIMEZONES: SpinLock<[TimeZoneEntry; MAX_TIMEZONES]> =
    SpinLock::new([const { TimeZoneEntry::new() }; MAX_TIMEZONES]);

// Dialog state
static DIALOG_STATE: SpinLock<DateTimeDialogState> = SpinLock::new(DateTimeDialogState::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize date/time subsystem
pub fn init() {
    let _guard = DATETIME_LOCK.lock();

    if DATETIME_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[DATETIME] Initializing date/time...");

    // Initialize time zones
    init_timezones();

    // Set default time zone (UTC)
    let mut tz = CURRENT_TZ.lock();
    tz.bias = 0;
    tz.set_standard_name(b"Coordinated Universal Time");

    // Set initial time
    let mut time = CURRENT_TIME.lock();
    time.year = 2003;
    time.month = 1;
    time.day = 1;
    time.hour = 0;
    time.minute = 0;
    time.second = 0;

    DATETIME_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[DATETIME] Date/time initialized");
}

/// Initialize time zones
fn init_timezones() {
    let zones: &[(&[u8], i16, bool)] = &[
        (b"(GMT-12:00) International Date Line West", -720, false),
        (b"(GMT-11:00) Midway Island, Samoa", -660, false),
        (b"(GMT-10:00) Hawaii", -600, false),
        (b"(GMT-09:00) Alaska", -540, true),
        (b"(GMT-08:00) Pacific Time (US & Canada)", -480, true),
        (b"(GMT-07:00) Mountain Time (US & Canada)", -420, true),
        (b"(GMT-06:00) Central Time (US & Canada)", -360, true),
        (b"(GMT-05:00) Eastern Time (US & Canada)", -300, true),
        (b"(GMT-04:00) Atlantic Time (Canada)", -240, true),
        (b"(GMT-03:00) Brasilia", -180, true),
        (b"(GMT-02:00) Mid-Atlantic", -120, true),
        (b"(GMT-01:00) Azores", -60, true),
        (b"(GMT) Greenwich Mean Time", 0, true),
        (b"(GMT+01:00) Central European Time", 60, true),
        (b"(GMT+02:00) Eastern European Time", 120, true),
        (b"(GMT+03:00) Moscow, St. Petersburg", 180, true),
        (b"(GMT+04:00) Abu Dhabi, Muscat", 240, false),
        (b"(GMT+05:00) Islamabad, Karachi", 300, false),
        (b"(GMT+05:30) Chennai, Kolkata, Mumbai", 330, false),
        (b"(GMT+06:00) Astana, Dhaka", 360, false),
        (b"(GMT+07:00) Bangkok, Hanoi, Jakarta", 420, false),
        (b"(GMT+08:00) Beijing, Hong Kong, Singapore", 480, false),
        (b"(GMT+09:00) Tokyo, Seoul", 540, false),
        (b"(GMT+10:00) Sydney, Melbourne", 600, true),
        (b"(GMT+11:00) Solomon Islands", 660, false),
        (b"(GMT+12:00) Auckland, Wellington", 720, true),
    ];

    let mut timezones = TIMEZONES.lock();

    for (i, (name, offset, has_dst)) in zones.iter().enumerate() {
        if i >= MAX_TIMEZONES {
            break;
        }

        let tz = &mut timezones[i];
        tz.valid = true;
        tz.display_name_len = name.len().min(128) as u8;
        tz.display_name[..tz.display_name_len as usize]
            .copy_from_slice(&name[..tz.display_name_len as usize]);
        tz.utc_offset = *offset;
        tz.has_dst = *has_dst;
        tz.info.bias = *offset as i32;
    }
}

// ============================================================================
// Date/Time API
// ============================================================================

/// Get system time
pub fn get_system_time() -> SystemTime {
    *CURRENT_TIME.lock()
}

/// Set system time
pub fn set_system_time(time: &SystemTime) -> bool {
    if !validate_time(time) {
        return false;
    }

    let mut current = CURRENT_TIME.lock();
    *current = *time;

    // Recalculate day of week
    current.day_of_week = calculate_day_of_week(time.year, time.month as u8, time.day as u8);

    // Would update RTC
    true
}

/// Get local time (adjusted for time zone)
pub fn get_local_time() -> SystemTime {
    let time = *CURRENT_TIME.lock();
    let tz = CURRENT_TZ.lock();

    adjust_time_for_timezone(&time, tz.bias)
}

/// Set local time
pub fn set_local_time(time: &SystemTime) -> bool {
    let tz = CURRENT_TZ.lock();
    let utc_time = adjust_time_for_timezone(time, -tz.bias);
    drop(tz);

    set_system_time(&utc_time)
}

/// Validate time values
fn validate_time(time: &SystemTime) -> bool {
    if time.month < 1 || time.month > 12 {
        return false;
    }
    if time.day < 1 || time.day > days_in_month(time.year, time.month as u8) as u16 {
        return false;
    }
    if time.hour > 23 || time.minute > 59 || time.second > 59 {
        return false;
    }
    true
}

/// Adjust time for timezone
fn adjust_time_for_timezone(time: &SystemTime, bias_minutes: i32) -> SystemTime {
    let mut result = *time;

    // Simple adjustment - would need proper date arithmetic
    let total_minutes = result.hour as i32 * 60 + result.minute as i32 - bias_minutes;

    let mut hours = total_minutes / 60;
    let mut minutes = total_minutes % 60;

    if minutes < 0 {
        minutes += 60;
        hours -= 1;
    }

    // Handle day overflow
    while hours >= 24 {
        hours -= 24;
        // Would increment day
    }
    while hours < 0 {
        hours += 24;
        // Would decrement day
    }

    result.hour = hours as u16;
    result.minute = minutes as u16;

    result
}

// ============================================================================
// Time Zone API
// ============================================================================

/// Get current time zone
pub fn get_timezone() -> TimeZoneInfo {
    *CURRENT_TZ.lock()
}

/// Set time zone
pub fn set_timezone(info: &TimeZoneInfo) -> bool {
    let mut tz = CURRENT_TZ.lock();
    *tz = *info;
    true
}

/// Get time zone by index
pub fn get_timezone_entry(index: usize) -> Option<TimeZoneEntry> {
    let timezones = TIMEZONES.lock();

    if index < MAX_TIMEZONES && timezones[index].valid {
        Some(timezones[index])
    } else {
        None
    }
}

/// Get time zone count
pub fn get_timezone_count() -> usize {
    let timezones = TIMEZONES.lock();
    timezones.iter().filter(|tz| tz.valid).count()
}

/// Set time zone by index
pub fn set_timezone_by_index(index: usize) -> bool {
    let timezones = TIMEZONES.lock();

    if index >= MAX_TIMEZONES || !timezones[index].valid {
        return false;
    }

    let info = timezones[index].info;
    drop(timezones);

    set_timezone(&info)
}

// ============================================================================
// Date/Time Dialog
// ============================================================================

/// Show date/time dialog
pub fn show_datetime_dialog(hwnd_owner: HWND, tab: u8) -> bool {
    if !DATETIME_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = DIALOG_STATE.lock();

    if state.active {
        return false;
    }

    state.current_tab = tab;
    state.pending_time = get_local_time();
    state.changes_pending = false;

    // Create dialog
    let hwnd = create_datetime_dialog(hwnd_owner);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    // Run dialog
    let result = run_datetime_dialog(hwnd);

    // Apply if OK
    if result {
        apply_datetime_changes();
    }

    // Clean up
    let mut state = DIALOG_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

/// Close date/time dialog
pub fn close_datetime_dialog() {
    let mut state = DIALOG_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }

        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Apply pending changes
fn apply_datetime_changes() {
    let state = DIALOG_STATE.lock();

    if !state.changes_pending {
        return;
    }

    let time = state.pending_time;
    let tz_idx = state.pending_tz;

    drop(state);

    set_local_time(&time);
    set_timezone_by_index(tz_idx as usize);
}

// ============================================================================
// Dialog Creation
// ============================================================================

/// Create date/time dialog
fn create_datetime_dialog(_owner: HWND) -> HWND {
    UserHandle::NULL
}

/// Run date/time dialog
fn run_datetime_dialog(_hwnd: HWND) -> bool {
    true
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Date/time dialog procedure
pub fn datetime_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_datetime_command(hwnd, wparam as u32)
        }
        super::message::WM_CLOSE => {
            close_datetime_dialog();
            0
        }
        _ => 0,
    }
}

/// Handle dialog commands
fn handle_datetime_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        1 => {
            // OK
            let state = DIALOG_STATE.lock();
            if state.active && state.hwnd == hwnd {
                drop(state);
                apply_datetime_changes();
                close_datetime_dialog();
            }
            0
        }
        2 => {
            // Cancel
            close_datetime_dialog();
            0
        }
        3 => {
            // Apply
            apply_datetime_changes();
            0
        }
        100 => {
            // Month combo changed
            let mut state = DIALOG_STATE.lock();
            let month = ((command >> 16) & 0xFF) as u16;
            if month >= 1 && month <= 12 {
                state.pending_time.month = month;
                state.changes_pending = true;
            }
            0
        }
        101 => {
            // Year spinner changed
            let mut state = DIALOG_STATE.lock();
            state.pending_time.year = ((command >> 16) & 0xFFFF) as u16;
            state.changes_pending = true;
            0
        }
        102 => {
            // Day calendar selection
            let mut state = DIALOG_STATE.lock();
            let day = ((command >> 16) & 0xFF) as u16;
            if day >= 1 && day <= 31 {
                state.pending_time.day = day;
                state.changes_pending = true;
            }
            0
        }
        103 => {
            // Time zone combo changed
            let mut state = DIALOG_STATE.lock();
            state.pending_tz = ((command >> 16) & 0xFF) as u8;
            state.changes_pending = true;
            0
        }
        _ => 0,
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Check if year is leap year
pub fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Get days in month
pub fn days_in_month(year: u16, month: u8) -> u8 {
    if month < 1 || month > 12 {
        return 0;
    }

    if month == 2 && is_leap_year(year) {
        29
    } else {
        DAYS_PER_MONTH[month as usize - 1]
    }
}

/// Calculate day of week (0=Sunday)
pub fn calculate_day_of_week(year: u16, month: u8, day: u8) -> u16 {
    // Zeller's congruence (simplified)
    let mut y = year as i32;
    let mut m = month as i32;

    if m < 3 {
        m += 12;
        y -= 1;
    }

    let q = day as i32;
    let k = y % 100;
    let j = y / 100;

    let h = (q + (13 * (m + 1)) / 5 + k + k / 4 + j / 4 - 2 * j) % 7;
    let dow = ((h + 6) % 7) as u16; // Convert to Sunday=0

    dow
}

/// Format time as string (HH:MM:SS)
pub fn format_time(time: &SystemTime, buffer: &mut [u8]) -> usize {
    let mut pos = 0;

    // Hours
    pos += format_two_digit(time.hour as u8, &mut buffer[pos..]);

    if pos < buffer.len() {
        buffer[pos] = b':';
        pos += 1;
    }

    // Minutes
    pos += format_two_digit(time.minute as u8, &mut buffer[pos..]);

    if pos < buffer.len() {
        buffer[pos] = b':';
        pos += 1;
    }

    // Seconds
    pos += format_two_digit(time.second as u8, &mut buffer[pos..]);

    pos
}

/// Format date as string (MM/DD/YYYY)
pub fn format_date(time: &SystemTime, buffer: &mut [u8]) -> usize {
    let mut pos = 0;

    // Month
    pos += format_two_digit(time.month as u8, &mut buffer[pos..]);

    if pos < buffer.len() {
        buffer[pos] = b'/';
        pos += 1;
    }

    // Day
    pos += format_two_digit(time.day as u8, &mut buffer[pos..]);

    if pos < buffer.len() {
        buffer[pos] = b'/';
        pos += 1;
    }

    // Year
    pos += format_number(time.year as u64, &mut buffer[pos..]);

    pos
}

/// Format two-digit number with leading zero
fn format_two_digit(n: u8, buffer: &mut [u8]) -> usize {
    if buffer.len() < 2 {
        return 0;
    }

    buffer[0] = b'0' + (n / 10);
    buffer[1] = b'0' + (n % 10);
    2
}

/// Format number
fn format_number(mut n: u64, buffer: &mut [u8]) -> usize {
    if n == 0 {
        if !buffer.is_empty() {
            buffer[0] = b'0';
            return 1;
        }
        return 0;
    }

    let mut temp = [0u8; 20];
    let mut len = 0;

    while n > 0 && len < 20 {
        temp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }

    let copy_len = len.min(buffer.len());
    for i in 0..copy_len {
        buffer[i] = temp[len - 1 - i];
    }

    copy_len
}
