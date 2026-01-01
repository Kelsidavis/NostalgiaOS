//! DateTime Picker Control Implementation
//!
//! Windows Date and Time Picker control for date/time selection.
//! Based on Windows Server 2003 commctrl.h and SysDateTimePick32.
//!
//! # Features
//!
//! - Date selection with dropdown calendar or spin control
//! - Time selection mode
//! - Custom date/time formats
//! - Date range limits
//! - "None" selection option
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - DTM_* messages, DTS_* styles

use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Rect};
use super::monthcal::SystemTime;

// ============================================================================
// DateTime Picker Styles (DTS_*)
// ============================================================================

/// Use up-down control instead of dropdown calendar
pub const DTS_UPDOWN: u32 = 0x0001;

/// Allow "none" selection (checkbox)
pub const DTS_SHOWNONE: u32 = 0x0002;

/// Short date format (default)
pub const DTS_SHORTDATEFORMAT: u32 = 0x0000;

/// Long date format
pub const DTS_LONGDATEFORMAT: u32 = 0x0004;

/// Short date format with century
pub const DTS_SHORTDATECENTURYFORMAT: u32 = 0x000C;

/// Time format
pub const DTS_TIMEFORMAT: u32 = 0x0009;

/// Allow user-entered strings
pub const DTS_APPCANPARSE: u32 = 0x0010;

/// Right-align dropdown
pub const DTS_RIGHTALIGN: u32 = 0x0020;

// ============================================================================
// DateTime Picker Messages
// ============================================================================

/// Message base for DateTime Picker
pub const DTM_FIRST: u32 = 0x1000;

/// Get the current date/time
/// Returns: GDT_VALID or GDT_NONE
pub const DTM_GETSYSTEMTIME: u32 = DTM_FIRST + 1;

/// Set the current date/time
/// wParam: GDT_VALID or GDT_NONE
pub const DTM_SETSYSTEMTIME: u32 = DTM_FIRST + 2;

/// Get the min/max range
pub const DTM_GETRANGE: u32 = DTM_FIRST + 3;

/// Set the min/max range
pub const DTM_SETRANGE: u32 = DTM_FIRST + 4;

/// Set the display format (ANSI)
pub const DTM_SETFORMATA: u32 = DTM_FIRST + 5;

/// Set month calendar color
pub const DTM_SETMCCOLOR: u32 = DTM_FIRST + 6;

/// Get month calendar color
pub const DTM_GETMCCOLOR: u32 = DTM_FIRST + 7;

/// Get month calendar handle
pub const DTM_GETMONTHCAL: u32 = DTM_FIRST + 8;

/// Set month calendar font
pub const DTM_SETMCFONT: u32 = DTM_FIRST + 9;

/// Get month calendar font
pub const DTM_GETMCFONT: u32 = DTM_FIRST + 10;

/// Set the display format (Unicode)
pub const DTM_SETFORMATW: u32 = DTM_FIRST + 50;

/// Alias for DTM_SETFORMATA
pub const DTM_SETFORMAT: u32 = DTM_SETFORMATA;

// ============================================================================
// Get Date Time Result
// ============================================================================

/// Date/time is valid
pub const GDT_VALID: u32 = 0;

/// Date/time is "none" (not selected)
pub const GDT_NONE: u32 = 1;

/// Error
pub const GDT_ERROR: u32 = u32::MAX;

// ============================================================================
// Range Flags (GDTR_*)
// ============================================================================

/// Minimum date is set
pub const GDTR_MIN: u32 = 0x0001;

/// Maximum date is set
pub const GDTR_MAX: u32 = 0x0002;

// ============================================================================
// Notifications (DTN_*)
// ============================================================================

/// First DTN notification code
pub const DTN_FIRST: u32 = 0u32.wrapping_sub(760);

/// Date/time changed
pub const DTN_DATETIMECHANGE: u32 = DTN_FIRST;

/// User entered a string (DTS_APPCANPARSE)
pub const DTN_USERSTRINGA: u32 = DTN_FIRST.wrapping_sub(1);

/// User entered a string (Unicode)
pub const DTN_USERSTRINGW: u32 = DTN_FIRST.wrapping_sub(15);

/// Want keyboard input
pub const DTN_WMKEYDOWNA: u32 = DTN_FIRST.wrapping_sub(2);

/// Want keyboard input (Unicode)
pub const DTN_WMKEYDOWNW: u32 = DTN_FIRST.wrapping_sub(16);

/// Format callback (ANSI)
pub const DTN_FORMATA: u32 = DTN_FIRST.wrapping_sub(3);

/// Format callback (Unicode)
pub const DTN_FORMATW: u32 = DTN_FIRST.wrapping_sub(17);

/// Format query callback (ANSI)
pub const DTN_FORMATQUERYA: u32 = DTN_FIRST.wrapping_sub(4);

/// Format query callback (Unicode)
pub const DTN_FORMATQUERYW: u32 = DTN_FIRST.wrapping_sub(18);

/// Dropdown calendar showing
pub const DTN_DROPDOWN: u32 = DTN_FIRST.wrapping_sub(5);

/// Dropdown calendar closing
pub const DTN_CLOSEUP: u32 = DTN_FIRST.wrapping_sub(6);

// ============================================================================
// Format Mode
// ============================================================================

/// Display format mode
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FormatMode {
    /// Short date format (M/d/yyyy)
    ShortDate,
    /// Long date format (dddd, MMMM dd, yyyy)
    LongDate,
    /// Time format (h:mm:ss tt)
    Time,
    /// Custom format
    Custom,
}

impl Default for FormatMode {
    fn default() -> Self {
        Self::ShortDate
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of DateTime Picker controls
pub const MAX_DATETIMEPICK_CONTROLS: usize = 64;

/// DateTime Picker class name
pub const DATETIMEPICK_CLASS: &str = "SysDateTimePick32";

/// Maximum format string length
pub const MAX_FORMAT_LEN: usize = 64;

// ============================================================================
// DateTime Picker Control Structure
// ============================================================================

/// DateTime Picker control state
#[derive(Clone)]
pub struct DateTimePickControl {
    /// Control handle
    pub hwnd: HWND,
    /// Is this slot in use
    pub in_use: bool,
    /// Control style flags
    pub style: u32,
    /// Display rectangle
    pub rect: Rect,

    // Selection
    /// Current date/time
    pub date_time: SystemTime,
    /// Is date selected (for DTS_SHOWNONE)
    pub selected: bool,

    // Range limits
    /// Minimum date
    pub min_date: SystemTime,
    /// Maximum date
    pub max_date: SystemTime,
    /// Has minimum limit
    pub has_min: bool,
    /// Has maximum limit
    pub has_max: bool,

    // Display
    /// Format mode
    pub format_mode: FormatMode,
    /// Custom format string
    pub format_string: [u8; MAX_FORMAT_LEN],
    pub format_len: usize,

    // State
    /// Is dropdown open
    pub dropdown_open: bool,
    /// Currently editing field (for time/updown mode)
    pub edit_field: u8,

    // Month calendar colors (same as MCSC_* values)
    pub mc_background: u32,
    pub mc_text: u32,
    pub mc_titlebk: u32,
    pub mc_titletext: u32,
    pub mc_monthbk: u32,
    pub mc_trailingtext: u32,
}

impl DateTimePickControl {
    /// Create a new DateTime Picker control
    pub const fn new() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            in_use: false,
            style: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            date_time: SystemTime::new(),
            selected: true,
            min_date: SystemTime::new(),
            max_date: SystemTime::new(),
            has_min: false,
            has_max: false,
            format_mode: FormatMode::ShortDate,
            format_string: [0u8; MAX_FORMAT_LEN],
            format_len: 0,
            dropdown_open: false,
            edit_field: 0,
            mc_background: 0xFFFFFF,
            mc_text: 0x000000,
            mc_titlebk: 0x808080,
            mc_titletext: 0xFFFFFF,
            mc_monthbk: 0xFFFFFF,
            mc_trailingtext: 0x808080,
        }
    }

    /// Reset control to default state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Get system time
    pub fn get_system_time(&self) -> (u32, SystemTime) {
        if self.selected {
            (GDT_VALID, self.date_time)
        } else {
            (GDT_NONE, SystemTime::new())
        }
    }

    /// Set system time
    pub fn set_system_time(&mut self, flag: u32, date: &SystemTime) -> bool {
        if flag == GDT_NONE {
            if self.style & DTS_SHOWNONE != 0 {
                self.selected = false;
                return true;
            }
            return false;
        }

        // Validate against range
        if self.has_min && date.is_before(&self.min_date) {
            return false;
        }
        if self.has_max && self.max_date.is_before(date) {
            return false;
        }

        self.date_time = *date;
        self.selected = true;
        true
    }

    /// Set range limits
    pub fn set_range(&mut self, flags: u32, min: &SystemTime, max: &SystemTime) -> bool {
        if flags & GDTR_MIN != 0 {
            self.min_date = *min;
            self.has_min = true;
        }
        if flags & GDTR_MAX != 0 {
            self.max_date = *max;
            self.has_max = true;
        }
        true
    }

    /// Get range limits
    pub fn get_range(&self) -> (u32, SystemTime, SystemTime) {
        let mut flags = 0;
        if self.has_min {
            flags |= GDTR_MIN;
        }
        if self.has_max {
            flags |= GDTR_MAX;
        }
        (flags, self.min_date, self.max_date)
    }

    /// Set month calendar color
    pub fn set_mc_color(&mut self, index: u32, color: u32) -> u32 {
        let old = match index {
            0 => { let o = self.mc_background; self.mc_background = color; o }
            1 => { let o = self.mc_text; self.mc_text = color; o }
            2 => { let o = self.mc_titlebk; self.mc_titlebk = color; o }
            3 => { let o = self.mc_titletext; self.mc_titletext = color; o }
            4 => { let o = self.mc_monthbk; self.mc_monthbk = color; o }
            5 => { let o = self.mc_trailingtext; self.mc_trailingtext = color; o }
            _ => 0xFFFFFFFF,
        };
        old
    }

    /// Get month calendar color
    pub fn get_mc_color(&self, index: u32) -> u32 {
        match index {
            0 => self.mc_background,
            1 => self.mc_text,
            2 => self.mc_titlebk,
            3 => self.mc_titletext,
            4 => self.mc_monthbk,
            5 => self.mc_trailingtext,
            _ => 0xFFFFFFFF,
        }
    }

    /// Set format string
    pub fn set_format(&mut self, format: &[u8]) {
        let len = core::cmp::min(format.len(), MAX_FORMAT_LEN);
        self.format_string[..len].copy_from_slice(&format[..len]);
        self.format_len = len;
        self.format_mode = FormatMode::Custom;
    }

    /// Get display text
    pub fn get_display_text(&self, buffer: &mut [u8]) -> usize {
        if !self.selected {
            let text = b"(none)";
            let len = core::cmp::min(text.len(), buffer.len());
            buffer[..len].copy_from_slice(&text[..len]);
            return len;
        }

        let mut pos = 0;

        match self.format_mode {
            FormatMode::ShortDate => {
                // M/d/yyyy
                pos += write_num(self.date_time.month as u32, &mut buffer[pos..]);
                if pos < buffer.len() {
                    buffer[pos] = b'/';
                    pos += 1;
                }
                pos += write_num(self.date_time.day as u32, &mut buffer[pos..]);
                if pos < buffer.len() {
                    buffer[pos] = b'/';
                    pos += 1;
                }
                pos += write_num(self.date_time.year as u32, &mut buffer[pos..]);
            }
            FormatMode::LongDate => {
                // dddd, MMMM dd, yyyy
                let day_name = day_of_week_name(self.date_time.day_of_week);
                let len = core::cmp::min(day_name.len(), buffer.len() - pos);
                buffer[pos..pos + len].copy_from_slice(&day_name.as_bytes()[..len]);
                pos += len;

                let sep = b", ";
                let len = core::cmp::min(sep.len(), buffer.len() - pos);
                buffer[pos..pos + len].copy_from_slice(&sep[..len]);
                pos += len;

                let month_name = month_name(self.date_time.month);
                let len = core::cmp::min(month_name.len(), buffer.len() - pos);
                buffer[pos..pos + len].copy_from_slice(&month_name.as_bytes()[..len]);
                pos += len;

                if pos < buffer.len() {
                    buffer[pos] = b' ';
                    pos += 1;
                }

                pos += write_num_padded(self.date_time.day as u32, 2, &mut buffer[pos..]);

                let sep = b", ";
                let len = core::cmp::min(sep.len(), buffer.len() - pos);
                buffer[pos..pos + len].copy_from_slice(&sep[..len]);
                pos += len;

                pos += write_num(self.date_time.year as u32, &mut buffer[pos..]);
            }
            FormatMode::Time => {
                // h:mm:ss tt
                let hour_12 = if self.date_time.hour == 0 {
                    12
                } else if self.date_time.hour > 12 {
                    self.date_time.hour - 12
                } else {
                    self.date_time.hour
                };

                pos += write_num(hour_12 as u32, &mut buffer[pos..]);
                if pos < buffer.len() {
                    buffer[pos] = b':';
                    pos += 1;
                }
                pos += write_num_padded(self.date_time.minute as u32, 2, &mut buffer[pos..]);
                if pos < buffer.len() {
                    buffer[pos] = b':';
                    pos += 1;
                }
                pos += write_num_padded(self.date_time.second as u32, 2, &mut buffer[pos..]);
                if pos < buffer.len() {
                    buffer[pos] = b' ';
                    pos += 1;
                }
                let ampm = if self.date_time.hour < 12 { b"AM" } else { b"PM" };
                let len = core::cmp::min(ampm.len(), buffer.len() - pos);
                buffer[pos..pos + len].copy_from_slice(&ampm[..len]);
                pos += len;
            }
            FormatMode::Custom => {
                // For custom, just copy the format for now
                // A real implementation would parse and substitute
                let len = core::cmp::min(self.format_len, buffer.len());
                buffer[..len].copy_from_slice(&self.format_string[..len]);
                pos = len;
            }
        }

        pos
    }

    /// Increment the current edit field
    pub fn increment_field(&mut self) {
        match self.edit_field {
            0 => { // Month
                if self.date_time.month < 12 {
                    self.date_time.month += 1;
                } else {
                    self.date_time.month = 1;
                }
            }
            1 => { // Day
                let max = super::monthcal::days_in_month(self.date_time.year, self.date_time.month);
                if self.date_time.day < max {
                    self.date_time.day += 1;
                } else {
                    self.date_time.day = 1;
                }
            }
            2 => { // Year
                self.date_time.year = self.date_time.year.saturating_add(1);
            }
            3 => { // Hour
                if self.date_time.hour < 23 {
                    self.date_time.hour += 1;
                } else {
                    self.date_time.hour = 0;
                }
            }
            4 => { // Minute
                if self.date_time.minute < 59 {
                    self.date_time.minute += 1;
                } else {
                    self.date_time.minute = 0;
                }
            }
            5 => { // Second
                if self.date_time.second < 59 {
                    self.date_time.second += 1;
                } else {
                    self.date_time.second = 0;
                }
            }
            _ => {}
        }
    }

    /// Decrement the current edit field
    pub fn decrement_field(&mut self) {
        match self.edit_field {
            0 => { // Month
                if self.date_time.month > 1 {
                    self.date_time.month -= 1;
                } else {
                    self.date_time.month = 12;
                }
            }
            1 => { // Day
                if self.date_time.day > 1 {
                    self.date_time.day -= 1;
                } else {
                    self.date_time.day = super::monthcal::days_in_month(self.date_time.year, self.date_time.month);
                }
            }
            2 => { // Year
                self.date_time.year = self.date_time.year.saturating_sub(1);
            }
            3 => { // Hour
                if self.date_time.hour > 0 {
                    self.date_time.hour -= 1;
                } else {
                    self.date_time.hour = 23;
                }
            }
            4 => { // Minute
                if self.date_time.minute > 0 {
                    self.date_time.minute -= 1;
                } else {
                    self.date_time.minute = 59;
                }
            }
            5 => { // Second
                if self.date_time.second > 0 {
                    self.date_time.second -= 1;
                } else {
                    self.date_time.second = 59;
                }
            }
            _ => {}
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Write a number to buffer
fn write_num(n: u32, buffer: &mut [u8]) -> usize {
    if buffer.is_empty() {
        return 0;
    }

    if n == 0 {
        buffer[0] = b'0';
        return 1;
    }

    let mut temp = [0u8; 10];
    let mut pos = 0;
    let mut val = n;

    while val > 0 && pos < temp.len() {
        temp[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        pos += 1;
    }

    let len = core::cmp::min(pos, buffer.len());
    for i in 0..len {
        buffer[i] = temp[pos - 1 - i];
    }
    len
}

/// Write a number with zero padding
fn write_num_padded(n: u32, width: usize, buffer: &mut [u8]) -> usize {
    if buffer.len() < width {
        return write_num(n, buffer);
    }

    let mut temp = [b'0'; 10];
    let mut pos = 0;
    let mut val = n;

    while val > 0 && pos < temp.len() {
        temp[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        pos += 1;
    }

    let actual_width = core::cmp::max(pos, width);
    let len = core::cmp::min(actual_width, buffer.len());

    // Fill with zeros
    for i in 0..len - pos {
        buffer[i] = b'0';
    }
    // Write digits
    for i in 0..pos {
        buffer[len - 1 - i] = temp[i];
    }

    len
}

/// Get day of week name
fn day_of_week_name(dow: u16) -> &'static str {
    match dow {
        0 => "Sunday",
        1 => "Monday",
        2 => "Tuesday",
        3 => "Wednesday",
        4 => "Thursday",
        5 => "Friday",
        6 => "Saturday",
        _ => "Unknown",
    }
}

/// Get month name
fn month_name(month: u16) -> &'static str {
    match month {
        1 => "January",
        2 => "February",
        3 => "March",
        4 => "April",
        5 => "May",
        6 => "June",
        7 => "July",
        8 => "August",
        9 => "September",
        10 => "October",
        11 => "November",
        12 => "December",
        _ => "Unknown",
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global DateTime Picker control storage
static DATETIMEPICK_CONTROLS: SpinLock<[DateTimePickControl; MAX_DATETIMEPICK_CONTROLS]> =
    SpinLock::new([const { DateTimePickControl::new() }; MAX_DATETIMEPICK_CONTROLS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize DateTime Picker control subsystem
pub fn init() {
    crate::serial_println!("[USER] DateTimePick control initialized");
}

/// Create a DateTime Picker control
pub fn create_datetimepick(hwnd: HWND, style: u32, rect: &Rect) -> Option<usize> {
    let mut controls = DATETIMEPICK_CONTROLS.lock();

    for (i, control) in controls.iter_mut().enumerate() {
        if !control.in_use {
            control.reset();
            control.hwnd = hwnd;
            control.in_use = true;
            control.style = style;
            control.rect = *rect;

            // Set format mode based on style
            if style & DTS_TIMEFORMAT == DTS_TIMEFORMAT {
                control.format_mode = FormatMode::Time;
            } else if style & DTS_LONGDATEFORMAT != 0 {
                control.format_mode = FormatMode::LongDate;
            } else {
                control.format_mode = FormatMode::ShortDate;
            }

            return Some(i);
        }
    }

    None
}

/// Destroy a DateTime Picker control
pub fn destroy_datetimepick(index: usize) -> bool {
    let mut controls = DATETIMEPICK_CONTROLS.lock();

    if index >= MAX_DATETIMEPICK_CONTROLS {
        return false;
    }

    if controls[index].in_use {
        controls[index].reset();
        true
    } else {
        false
    }
}

/// Get system time
pub fn get_system_time(index: usize) -> (u32, SystemTime) {
    let controls = DATETIMEPICK_CONTROLS.lock();

    if index >= MAX_DATETIMEPICK_CONTROLS || !controls[index].in_use {
        return (GDT_ERROR, SystemTime::new());
    }

    controls[index].get_system_time()
}

/// Set system time
pub fn set_system_time(index: usize, flag: u32, date: &SystemTime) -> bool {
    let mut controls = DATETIMEPICK_CONTROLS.lock();

    if index >= MAX_DATETIMEPICK_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].set_system_time(flag, date)
}

/// Set range
pub fn set_range(index: usize, flags: u32, min: &SystemTime, max: &SystemTime) -> bool {
    let mut controls = DATETIMEPICK_CONTROLS.lock();

    if index >= MAX_DATETIMEPICK_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].set_range(flags, min, max)
}

/// Get range
pub fn get_range(index: usize) -> (u32, SystemTime, SystemTime) {
    let controls = DATETIMEPICK_CONTROLS.lock();

    if index >= MAX_DATETIMEPICK_CONTROLS || !controls[index].in_use {
        return (0, SystemTime::new(), SystemTime::new());
    }

    controls[index].get_range()
}

/// Set month calendar color
pub fn set_mc_color(index: usize, color_index: u32, color: u32) -> u32 {
    let mut controls = DATETIMEPICK_CONTROLS.lock();

    if index >= MAX_DATETIMEPICK_CONTROLS || !controls[index].in_use {
        return 0xFFFFFFFF;
    }

    controls[index].set_mc_color(color_index, color)
}

/// Get month calendar color
pub fn get_mc_color(index: usize, color_index: u32) -> u32 {
    let controls = DATETIMEPICK_CONTROLS.lock();

    if index >= MAX_DATETIMEPICK_CONTROLS || !controls[index].in_use {
        return 0xFFFFFFFF;
    }

    controls[index].get_mc_color(color_index)
}

/// Set format string
pub fn set_format(index: usize, format: &[u8]) -> bool {
    let mut controls = DATETIMEPICK_CONTROLS.lock();

    if index >= MAX_DATETIMEPICK_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].set_format(format);
    true
}

/// Get display text
pub fn get_display_text(index: usize, buffer: &mut [u8]) -> usize {
    let controls = DATETIMEPICK_CONTROLS.lock();

    if index >= MAX_DATETIMEPICK_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].get_display_text(buffer)
}

/// Process DateTime Picker control message
pub fn process_message(index: usize, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        DTM_GETSYSTEMTIME => {
            let (result, _date) = get_system_time(index);
            // In real implementation, write date to lparam
            result as isize
        }
        DTM_SETSYSTEMTIME => {
            // In real implementation, read date from lparam
            let date = SystemTime::new();
            if set_system_time(index, wparam as u32, &date) { 1 } else { 0 }
        }
        DTM_GETRANGE => {
            let (flags, _min, _max) = get_range(index);
            // In real implementation, write dates to lparam
            flags as isize
        }
        DTM_SETRANGE => {
            // In real implementation, read dates from lparam
            let min = SystemTime::new();
            let max = SystemTime::new();
            if set_range(index, wparam as u32, &min, &max) { 1 } else { 0 }
        }
        DTM_SETMCCOLOR => {
            set_mc_color(index, wparam as u32, lparam as u32) as isize
        }
        DTM_GETMCCOLOR => {
            get_mc_color(index, wparam as u32) as isize
        }
        DTM_SETFORMATA | DTM_SETFORMATW => {
            // In real implementation, read format from lparam
            let format = b"";
            if set_format(index, format) { 1 } else { 0 }
        }
        DTM_GETMONTHCAL => {
            // Return 0 as we don't maintain a separate month calendar handle
            0
        }
        _ => 0,
    }
}

/// Get statistics
pub fn get_stats() -> DateTimePickStats {
    let controls = DATETIMEPICK_CONTROLS.lock();

    let mut active_count = 0;
    for control in controls.iter() {
        if control.in_use {
            active_count += 1;
        }
    }

    DateTimePickStats {
        max_controls: MAX_DATETIMEPICK_CONTROLS,
        active_controls: active_count,
    }
}

/// DateTime Picker statistics
#[derive(Debug, Clone, Copy)]
pub struct DateTimePickStats {
    pub max_controls: usize,
    pub active_controls: usize,
}
