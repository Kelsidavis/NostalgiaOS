//! Month Calendar Control Implementation
//!
//! Windows Month Calendar control for date selection.
//! Based on Windows Server 2003 commctrl.h and SysMonthCal32.
//!
//! # Features
//!
//! - Single and multi-select date modes
//! - Day state highlighting
//! - First day of week configuration
//! - Date range limits
//! - Today indicator
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - MCM_* messages, MCS_* styles

use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Rect, Point};

// ============================================================================
// Month Calendar Styles (MCS_*)
// ============================================================================

/// Display day state (bolding) for each day
pub const MCS_DAYSTATE: u32 = 0x0001;

/// Allow multi-select (date range)
pub const MCS_MULTISELECT: u32 = 0x0002;

/// Show week numbers
pub const MCS_WEEKNUMBERS: u32 = 0x0004;

/// Don't circle today's date
pub const MCS_NOTODAYCIRCLE: u32 = 0x0008;

/// Don't show "today" string
pub const MCS_NOTODAY: u32 = 0x0010;

// ============================================================================
// Month Calendar Messages
// ============================================================================

/// Message base for Month Calendar
pub const MCM_FIRST: u32 = 0x1000;

/// Get currently selected date
pub const MCM_GETCURSEL: u32 = MCM_FIRST + 1;

/// Set currently selected date
pub const MCM_SETCURSEL: u32 = MCM_FIRST + 2;

/// Get maximum selection count
pub const MCM_GETMAXSELCOUNT: u32 = MCM_FIRST + 3;

/// Set maximum selection count
pub const MCM_SETMAXSELCOUNT: u32 = MCM_FIRST + 4;

/// Get selected date range
pub const MCM_GETSELRANGE: u32 = MCM_FIRST + 5;

/// Set selected date range
pub const MCM_SETSELRANGE: u32 = MCM_FIRST + 6;

/// Get month range being displayed
pub const MCM_GETMONTHRANGE: u32 = MCM_FIRST + 7;

/// Set day state (bold days)
pub const MCM_SETDAYSTATE: u32 = MCM_FIRST + 8;

/// Get minimum required rectangle
pub const MCM_GETMINREQRECT: u32 = MCM_FIRST + 9;

/// Set calendar color
pub const MCM_SETCOLOR: u32 = MCM_FIRST + 10;

/// Get calendar color
pub const MCM_GETCOLOR: u32 = MCM_FIRST + 11;

/// Set today's date
pub const MCM_SETTODAY: u32 = MCM_FIRST + 12;

/// Get today's date
pub const MCM_GETTODAY: u32 = MCM_FIRST + 13;

/// Hit test
pub const MCM_HITTEST: u32 = MCM_FIRST + 14;

/// Set first day of week
pub const MCM_SETFIRSTDAYOFWEEK: u32 = MCM_FIRST + 15;

/// Get first day of week
pub const MCM_GETFIRSTDAYOFWEEK: u32 = MCM_FIRST + 16;

/// Get date range limits
pub const MCM_GETRANGE: u32 = MCM_FIRST + 17;

/// Set date range limits
pub const MCM_SETRANGE: u32 = MCM_FIRST + 18;

/// Get month scroll delta
pub const MCM_GETMONTHDELTA: u32 = MCM_FIRST + 19;

/// Set month scroll delta
pub const MCM_SETMONTHDELTA: u32 = MCM_FIRST + 20;

/// Get width of "today" string
pub const MCM_GETMAXTODAYWIDTH: u32 = MCM_FIRST + 21;

// ============================================================================
// Calendar Colors (MCSC_*)
// ============================================================================

/// Background color between months
pub const MCSC_BACKGROUND: u32 = 0;

/// Text color for days
pub const MCSC_TEXT: u32 = 1;

/// Title background color
pub const MCSC_TITLEBK: u32 = 2;

/// Title text color
pub const MCSC_TITLETEXT: u32 = 3;

/// Month background color
pub const MCSC_MONTHBK: u32 = 4;

/// Trailing text color (prev/next month days)
pub const MCSC_TRAILINGTEXT: u32 = 5;

// ============================================================================
// Hit Test Results (MCHT_*)
// ============================================================================

/// Outside calendar area
pub const MCHT_NOWHERE: u32 = 0x00000000;

/// On the title
pub const MCHT_TITLE: u32 = 0x00010000;

/// On calendar area
pub const MCHT_CALENDAR: u32 = 0x00020000;

/// On "today" link
pub const MCHT_TODAYLINK: u32 = 0x00030000;

/// On previous month button
pub const MCHT_TITLEBTNPREV: u32 = MCHT_TITLE | 0x0001;

/// On next month button
pub const MCHT_TITLEBTNNEXT: u32 = MCHT_TITLE | 0x0002;

/// On month title
pub const MCHT_TITLEMONTH: u32 = MCHT_TITLE | 0x0003;

/// On year title
pub const MCHT_TITLEYEAR: u32 = MCHT_TITLE | 0x0004;

/// On a day number
pub const MCHT_CALENDARDAY: u32 = MCHT_CALENDAR | 0x0001;

/// On week number
pub const MCHT_CALENDARWEEKNUM: u32 = MCHT_CALENDAR | 0x0002;

/// On a date
pub const MCHT_CALENDARDATE: u32 = MCHT_CALENDAR | 0x0003;

// ============================================================================
// Notifications (MCN_*)
// ============================================================================

/// First MCN notification code
pub const MCN_FIRST: u32 = 0u32.wrapping_sub(750);

/// Selection changed
pub const MCN_SELCHANGE: u32 = MCN_FIRST;

/// Request for day state
pub const MCN_GETDAYSTATE: u32 = MCN_FIRST.wrapping_sub(1);

/// Selection complete
pub const MCN_SELECT: u32 = MCN_FIRST.wrapping_sub(2);

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of Month Calendar controls
pub const MAX_MONTHCAL_CONTROLS: usize = 32;

/// Month Calendar class name
pub const MONTHCAL_CLASS: &str = "SysMonthCal32";

/// Days per week
pub const DAYS_PER_WEEK: usize = 7;

/// Maximum weeks displayed
pub const MAX_WEEKS: usize = 6;

// ============================================================================
// System Time Structure
// ============================================================================

/// SYSTEMTIME equivalent for date/time storage
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemTime {
    pub year: u16,
    pub month: u16,       // 1-12
    pub day_of_week: u16, // 0 = Sunday
    pub day: u16,         // 1-31
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
}

impl SystemTime {
    /// Create a new system time
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

    /// Check if this date is before another
    pub fn is_before(&self, other: &SystemTime) -> bool {
        if self.year != other.year {
            return self.year < other.year;
        }
        if self.month != other.month {
            return self.month < other.month;
        }
        self.day < other.day
    }

    /// Check if this date equals another (date only)
    pub fn same_date(&self, other: &SystemTime) -> bool {
        self.year == other.year && self.month == other.month && self.day == other.day
    }

    /// Get days in month
    pub fn days_in_month(&self) -> u16 {
        days_in_month(self.year, self.month)
    }

    /// Advance to next day
    pub fn next_day(&mut self) {
        self.day += 1;
        if self.day > self.days_in_month() {
            self.day = 1;
            self.month += 1;
            if self.month > 12 {
                self.month = 1;
                self.year += 1;
            }
        }
        self.day_of_week = (self.day_of_week + 1) % 7;
    }

    /// Go to previous day
    pub fn prev_day(&mut self) {
        if self.day == 1 {
            if self.month == 1 {
                self.year -= 1;
                self.month = 12;
            } else {
                self.month -= 1;
            }
            self.day = days_in_month(self.year, self.month);
        } else {
            self.day -= 1;
        }
        self.day_of_week = if self.day_of_week == 0 { 6 } else { self.day_of_week - 1 };
    }
}

/// Get days in a month
pub fn days_in_month(year: u16, month: u16) -> u16 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) { 29 } else { 28 }
        }
        _ => 0,
    }
}

/// Check if year is a leap year
pub fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Calculate day of week for a date (Zeller's formula simplified)
pub fn day_of_week(year: u16, month: u16, day: u16) -> u16 {
    let y = if month < 3 { year - 1 } else { year } as i32;
    let m = if month < 3 { month + 12 } else { month } as i32;
    let d = day as i32;

    let dow = (d + (13 * (m + 1)) / 5 + y + y / 4 - y / 100 + y / 400) % 7;
    // Convert to 0=Sunday
    let result = (dow + 6) % 7;
    result as u16
}

// ============================================================================
// Month Calendar Control Structure
// ============================================================================

/// Month Calendar control state
#[derive(Clone)]
pub struct MonthCalControl {
    /// Control handle
    pub hwnd: HWND,
    /// Is this slot in use
    pub in_use: bool,
    /// Control style flags
    pub style: u32,
    /// Display rectangle
    pub rect: Rect,

    // Selection
    /// Currently selected date (single select)
    pub cur_sel: SystemTime,
    /// Range selection start
    pub sel_start: SystemTime,
    /// Range selection end
    pub sel_end: SystemTime,
    /// Maximum days in selection range
    pub max_sel_count: u32,

    // Display
    /// Currently displayed month
    pub display_month: u16,
    /// Currently displayed year
    pub display_year: u16,
    /// First day of week (0=Sunday, 1=Monday, etc.)
    pub first_day_of_week: u8,
    /// Month scroll delta
    pub month_delta: i32,

    // Today
    /// Today's date
    pub today: SystemTime,
    /// Show today circle
    pub show_today_circle: bool,
    /// Show today string
    pub show_today: bool,

    // Range limits
    /// Minimum allowed date (if has_min_range)
    pub min_date: SystemTime,
    /// Maximum allowed date (if has_max_range)
    pub max_date: SystemTime,
    /// Has minimum date limit
    pub has_min_range: bool,
    /// Has maximum date limit
    pub has_max_range: bool,

    // Colors
    pub background_color: u32,
    pub text_color: u32,
    pub title_bk_color: u32,
    pub title_text_color: u32,
    pub month_bk_color: u32,
    pub trailing_text_color: u32,

    // Day state bitmask (for MCS_DAYSTATE)
    /// Bold day state per month (3 months: prev, current, next)
    pub day_state: [u32; 3],
}

impl MonthCalControl {
    /// Create a new Month Calendar control
    pub const fn new() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            in_use: false,
            style: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            cur_sel: SystemTime::new(),
            sel_start: SystemTime::new(),
            sel_end: SystemTime::new(),
            max_sel_count: 7,
            display_month: 1,
            display_year: 2003,
            first_day_of_week: 0, // Sunday
            month_delta: 1,
            today: SystemTime::new(),
            show_today_circle: true,
            show_today: true,
            min_date: SystemTime::new(),
            max_date: SystemTime::new(),
            has_min_range: false,
            has_max_range: false,
            background_color: 0xFFFFFF,
            text_color: 0x000000,
            title_bk_color: 0x808080,
            title_text_color: 0xFFFFFF,
            month_bk_color: 0xFFFFFF,
            trailing_text_color: 0x808080,
            day_state: [0; 3],
        }
    }

    /// Reset control to default state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Set current selection (single date)
    pub fn set_cur_sel(&mut self, date: &SystemTime) -> bool {
        if self.style & MCS_MULTISELECT != 0 {
            return false;
        }

        // Check range limits
        if self.has_min_range && date.is_before(&self.min_date) {
            return false;
        }
        if self.has_max_range && self.max_date.is_before(date) {
            return false;
        }

        self.cur_sel = *date;
        self.display_month = date.month;
        self.display_year = date.year;
        true
    }

    /// Get current selection
    pub fn get_cur_sel(&self) -> SystemTime {
        self.cur_sel
    }

    /// Set selection range (for MCS_MULTISELECT)
    pub fn set_sel_range(&mut self, start: &SystemTime, end: &SystemTime) -> bool {
        if self.style & MCS_MULTISELECT == 0 {
            return false;
        }

        self.sel_start = *start;
        self.sel_end = *end;
        self.display_month = start.month;
        self.display_year = start.year;
        true
    }

    /// Set a color
    pub fn set_color(&mut self, color_type: u32, color: u32) -> u32 {
        let old = match color_type {
            MCSC_BACKGROUND => {
                let old = self.background_color;
                self.background_color = color;
                old
            }
            MCSC_TEXT => {
                let old = self.text_color;
                self.text_color = color;
                old
            }
            MCSC_TITLEBK => {
                let old = self.title_bk_color;
                self.title_bk_color = color;
                old
            }
            MCSC_TITLETEXT => {
                let old = self.title_text_color;
                self.title_text_color = color;
                old
            }
            MCSC_MONTHBK => {
                let old = self.month_bk_color;
                self.month_bk_color = color;
                old
            }
            MCSC_TRAILINGTEXT => {
                let old = self.trailing_text_color;
                self.trailing_text_color = color;
                old
            }
            _ => 0xFFFFFFFF,
        };
        old
    }

    /// Get a color
    pub fn get_color(&self, color_type: u32) -> u32 {
        match color_type {
            MCSC_BACKGROUND => self.background_color,
            MCSC_TEXT => self.text_color,
            MCSC_TITLEBK => self.title_bk_color,
            MCSC_TITLETEXT => self.title_text_color,
            MCSC_MONTHBK => self.month_bk_color,
            MCSC_TRAILINGTEXT => self.trailing_text_color,
            _ => 0xFFFFFFFF,
        }
    }

    /// Navigate to previous month
    pub fn prev_month(&mut self) {
        for _ in 0..self.month_delta.abs() {
            if self.display_month == 1 {
                self.display_month = 12;
                self.display_year = self.display_year.saturating_sub(1);
            } else {
                self.display_month -= 1;
            }
        }
    }

    /// Navigate to next month
    pub fn next_month(&mut self) {
        for _ in 0..self.month_delta.abs() {
            if self.display_month == 12 {
                self.display_month = 1;
                self.display_year = self.display_year.saturating_add(1);
            } else {
                self.display_month += 1;
            }
        }
    }

    /// Hit test at a point
    pub fn hit_test(&self, pt: &Point) -> (u32, SystemTime) {
        let width = self.rect.right - self.rect.left;
        let height = self.rect.bottom - self.rect.top;

        // Title area is top 20% approximately
        let title_height = height / 5;

        if pt.y < self.rect.top + title_height {
            // In title area
            let third = width / 3;
            if pt.x < self.rect.left + third {
                return (MCHT_TITLEBTNPREV, SystemTime::new());
            } else if pt.x > self.rect.right - third {
                return (MCHT_TITLEBTNNEXT, SystemTime::new());
            } else {
                return (MCHT_TITLEMONTH, SystemTime::new());
            }
        }

        // Today link area at bottom
        if pt.y > self.rect.bottom - 20 && self.show_today {
            return (MCHT_TODAYLINK, self.today);
        }

        // Calendar area
        let cal_top = self.rect.top + title_height + 20; // Day header height
        let cal_height = self.rect.bottom - 20 - cal_top;
        let cell_height = cal_height / (MAX_WEEKS as i32);
        let cell_width = width / (DAYS_PER_WEEK as i32);

        if pt.y >= cal_top && pt.y < self.rect.bottom - 20 {
            let col = (pt.x - self.rect.left) / cell_width;
            let row = (pt.y - cal_top) / cell_height;

            if col >= 0 && col < DAYS_PER_WEEK as i32 && row >= 0 && row < MAX_WEEKS as i32 {
                // Calculate which day this cell represents
                let first_day = day_of_week(self.display_year, self.display_month, 1);
                let adjusted_first = ((first_day as i32 - self.first_day_of_week as i32) + 7) % 7;
                let day_offset = row * (DAYS_PER_WEEK as i32) + col - adjusted_first;

                if day_offset >= 0 && day_offset < days_in_month(self.display_year, self.display_month) as i32 {
                    let mut date = SystemTime::new();
                    date.year = self.display_year;
                    date.month = self.display_month;
                    date.day = (day_offset + 1) as u16;
                    date.day_of_week = ((first_day as i32 + day_offset) % 7) as u16;
                    return (MCHT_CALENDARDATE, date);
                }
            }
        }

        (MCHT_NOWHERE, SystemTime::new())
    }

    /// Check if a day is bold (for MCS_DAYSTATE)
    pub fn is_day_bold(&self, month_offset: usize, day: u16) -> bool {
        if month_offset > 2 || day == 0 || day > 31 {
            return false;
        }
        (self.day_state[month_offset] & (1 << (day - 1))) != 0
    }

    /// Set day state
    pub fn set_day_state(&mut self, states: &[u32]) {
        for (i, &state) in states.iter().take(3).enumerate() {
            self.day_state[i] = state;
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global Month Calendar control storage
static MONTHCAL_CONTROLS: SpinLock<[MonthCalControl; MAX_MONTHCAL_CONTROLS]> =
    SpinLock::new([const { MonthCalControl::new() }; MAX_MONTHCAL_CONTROLS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize Month Calendar control subsystem
pub fn init() {
    crate::serial_println!("[USER] MonthCal control initialized");
}

/// Create a Month Calendar control
pub fn create_monthcal(hwnd: HWND, style: u32, rect: &Rect) -> Option<usize> {
    let mut controls = MONTHCAL_CONTROLS.lock();

    for (i, control) in controls.iter_mut().enumerate() {
        if !control.in_use {
            control.reset();
            control.hwnd = hwnd;
            control.in_use = true;
            control.style = style;
            control.rect = *rect;

            // Apply style-based settings
            control.show_today_circle = (style & MCS_NOTODAYCIRCLE) == 0;
            control.show_today = (style & MCS_NOTODAY) == 0;

            return Some(i);
        }
    }

    None
}

/// Destroy a Month Calendar control
pub fn destroy_monthcal(index: usize) -> bool {
    let mut controls = MONTHCAL_CONTROLS.lock();

    if index >= MAX_MONTHCAL_CONTROLS {
        return false;
    }

    if controls[index].in_use {
        controls[index].reset();
        true
    } else {
        false
    }
}

/// Get current selection
pub fn get_cur_sel(index: usize) -> Option<SystemTime> {
    let controls = MONTHCAL_CONTROLS.lock();

    if index >= MAX_MONTHCAL_CONTROLS || !controls[index].in_use {
        return None;
    }

    Some(controls[index].cur_sel)
}

/// Set current selection
pub fn set_cur_sel(index: usize, date: &SystemTime) -> bool {
    let mut controls = MONTHCAL_CONTROLS.lock();

    if index >= MAX_MONTHCAL_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].set_cur_sel(date)
}

/// Set color
pub fn set_color(index: usize, color_type: u32, color: u32) -> u32 {
    let mut controls = MONTHCAL_CONTROLS.lock();

    if index >= MAX_MONTHCAL_CONTROLS || !controls[index].in_use {
        return 0xFFFFFFFF;
    }

    controls[index].set_color(color_type, color)
}

/// Get color
pub fn get_color(index: usize, color_type: u32) -> u32 {
    let controls = MONTHCAL_CONTROLS.lock();

    if index >= MAX_MONTHCAL_CONTROLS || !controls[index].in_use {
        return 0xFFFFFFFF;
    }

    controls[index].get_color(color_type)
}

/// Navigate to previous month
pub fn prev_month(index: usize) -> bool {
    let mut controls = MONTHCAL_CONTROLS.lock();

    if index >= MAX_MONTHCAL_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].prev_month();
    true
}

/// Navigate to next month
pub fn next_month(index: usize) -> bool {
    let mut controls = MONTHCAL_CONTROLS.lock();

    if index >= MAX_MONTHCAL_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].next_month();
    true
}

/// Hit test
pub fn hit_test(index: usize, pt: &Point) -> (u32, SystemTime) {
    let controls = MONTHCAL_CONTROLS.lock();

    if index >= MAX_MONTHCAL_CONTROLS || !controls[index].in_use {
        return (MCHT_NOWHERE, SystemTime::new());
    }

    controls[index].hit_test(pt)
}

/// Set first day of week
pub fn set_first_day_of_week(index: usize, day: u8) -> u32 {
    let mut controls = MONTHCAL_CONTROLS.lock();

    if index >= MAX_MONTHCAL_CONTROLS || !controls[index].in_use {
        return 0xFFFFFFFF;
    }

    let old = controls[index].first_day_of_week;
    controls[index].first_day_of_week = day % 7;
    old as u32
}

/// Get first day of week
pub fn get_first_day_of_week(index: usize) -> u32 {
    let controls = MONTHCAL_CONTROLS.lock();

    if index >= MAX_MONTHCAL_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].first_day_of_week as u32
}

/// Set today's date
pub fn set_today(index: usize, date: &SystemTime) -> bool {
    let mut controls = MONTHCAL_CONTROLS.lock();

    if index >= MAX_MONTHCAL_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].today = *date;
    true
}

/// Get today's date
pub fn get_today(index: usize) -> Option<SystemTime> {
    let controls = MONTHCAL_CONTROLS.lock();

    if index >= MAX_MONTHCAL_CONTROLS || !controls[index].in_use {
        return None;
    }

    Some(controls[index].today)
}

/// Process Month Calendar control message
pub fn process_message(index: usize, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        MCM_GETCURSEL => {
            if let Some(_date) = get_cur_sel(index) {
                // In a real implementation, we'd write to lparam
                1
            } else {
                0
            }
        }
        MCM_SETCURSEL => {
            // In a real implementation, we'd read from lparam
            let date = SystemTime::new();
            if set_cur_sel(index, &date) { 1 } else { 0 }
        }
        MCM_GETMAXSELCOUNT => {
            let controls = MONTHCAL_CONTROLS.lock();
            if index < MAX_MONTHCAL_CONTROLS && controls[index].in_use {
                controls[index].max_sel_count as isize
            } else {
                0
            }
        }
        MCM_SETMAXSELCOUNT => {
            let mut controls = MONTHCAL_CONTROLS.lock();
            if index < MAX_MONTHCAL_CONTROLS && controls[index].in_use {
                controls[index].max_sel_count = wparam as u32;
                1
            } else {
                0
            }
        }
        MCM_SETCOLOR => {
            set_color(index, wparam as u32, lparam as u32) as isize
        }
        MCM_GETCOLOR => {
            get_color(index, wparam as u32) as isize
        }
        MCM_SETFIRSTDAYOFWEEK => {
            set_first_day_of_week(index, lparam as u8) as isize
        }
        MCM_GETFIRSTDAYOFWEEK => {
            get_first_day_of_week(index) as isize
        }
        MCM_GETMONTHDELTA => {
            let controls = MONTHCAL_CONTROLS.lock();
            if index < MAX_MONTHCAL_CONTROLS && controls[index].in_use {
                controls[index].month_delta as isize
            } else {
                0
            }
        }
        MCM_SETMONTHDELTA => {
            let mut controls = MONTHCAL_CONTROLS.lock();
            if index < MAX_MONTHCAL_CONTROLS && controls[index].in_use {
                let old = controls[index].month_delta;
                controls[index].month_delta = wparam as i32;
                old as isize
            } else {
                0
            }
        }
        _ => 0,
    }
}

/// Get statistics
pub fn get_stats() -> MonthCalStats {
    let controls = MONTHCAL_CONTROLS.lock();

    let mut active_count = 0;
    for control in controls.iter() {
        if control.in_use {
            active_count += 1;
        }
    }

    MonthCalStats {
        max_controls: MAX_MONTHCAL_CONTROLS,
        active_controls: active_count,
    }
}

/// Month Calendar statistics
#[derive(Debug, Clone, Copy)]
pub struct MonthCalStats {
    pub max_controls: usize,
    pub active_controls: usize,
}
