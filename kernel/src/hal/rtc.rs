//! Real-Time Clock (RTC) / CMOS Support
//!
//! This module provides access to the PC's Real-Time Clock (RTC) which
//! maintains the current date and time even when the system is powered off.
//!
//! The RTC is accessed through CMOS ports 0x70 (index) and 0x71 (data).
//!
//! ## Registers
//! - 0x00: Seconds (0-59)
//! - 0x02: Minutes (0-59)
//! - 0x04: Hours (0-23 or 1-12 with AM/PM)
//! - 0x06: Day of Week (1-7, Sunday = 1)
//! - 0x07: Day of Month (1-31)
//! - 0x08: Month (1-12)
//! - 0x09: Year (0-99)
//! - 0x0A: Status Register A
//! - 0x0B: Status Register B
//! - 0x0C: Status Register C
//! - 0x0D: Status Register D
//! - 0x32: Century (19-20) - not always present
//!
//! ## Time Format
//! Values can be in BCD or binary format depending on Status Register B.
//! Most systems use BCD format.

use crate::arch::io::{inb, outb};
use core::sync::atomic::{AtomicU64, Ordering};

/// CMOS address port
const CMOS_ADDR: u16 = 0x70;
/// CMOS data port
const CMOS_DATA: u16 = 0x71;

/// RTC register indices
mod reg {
    pub const SECONDS: u8 = 0x00;
    pub const MINUTES: u8 = 0x02;
    pub const HOURS: u8 = 0x04;
    pub const DAY_OF_WEEK: u8 = 0x06;
    pub const DAY_OF_MONTH: u8 = 0x07;
    pub const MONTH: u8 = 0x08;
    pub const YEAR: u8 = 0x09;
    pub const STATUS_A: u8 = 0x0A;
    pub const STATUS_B: u8 = 0x0B;
    pub const STATUS_C: u8 = 0x0C;
    pub const STATUS_D: u8 = 0x0D;
    pub const CENTURY: u8 = 0x32;
}

/// Status Register B flags
mod status_b {
    /// 24-hour mode (1) or 12-hour mode (0)
    pub const HOUR_24: u8 = 0x02;
    /// Binary mode (1) or BCD mode (0)
    pub const BINARY: u8 = 0x04;
}

/// Date/time structure
#[derive(Debug, Clone, Copy, Default)]
pub struct DateTime {
    pub year: u16,      // Full year (e.g., 2025)
    pub month: u8,      // 1-12
    pub day: u8,        // 1-31
    pub hour: u8,       // 0-23
    pub minute: u8,     // 0-59
    pub second: u8,     // 0-59
    pub day_of_week: u8, // 1-7 (Sunday = 1)
}

/// System time in 100-nanosecond intervals since January 1, 1601
/// (Windows FILETIME format)
static SYSTEM_TIME: AtomicU64 = AtomicU64::new(0);

/// Boot time (snapshot of RTC at boot)
static BOOT_TIME: AtomicU64 = AtomicU64::new(0);

/// Read a CMOS register
///
/// # Safety
/// Disables NMI while reading to prevent corruption.
#[inline]
unsafe fn cmos_read(reg: u8) -> u8 {
    // Select register (bit 7 disables NMI)
    outb(CMOS_ADDR, reg | 0x80);
    // Small delay for I/O
    core::hint::spin_loop();
    // Read value
    inb(CMOS_DATA)
}

/// Write a CMOS register
///
/// # Safety
/// Disables NMI while writing to prevent corruption.
#[inline]
#[allow(dead_code)]
unsafe fn cmos_write(reg: u8, value: u8) {
    // Select register (bit 7 disables NMI)
    outb(CMOS_ADDR, reg | 0x80);
    core::hint::spin_loop();
    // Write value
    outb(CMOS_DATA, value);
}

/// Check if RTC update is in progress
#[inline]
unsafe fn is_update_in_progress() -> bool {
    (cmos_read(reg::STATUS_A) & 0x80) != 0
}

/// Convert BCD to binary
#[inline]
fn bcd_to_binary(bcd: u8) -> u8 {
    ((bcd >> 4) * 10) + (bcd & 0x0F)
}

/// Convert binary to BCD
#[inline]
#[allow(dead_code)]
fn binary_to_bcd(bin: u8) -> u8 {
    ((bin / 10) << 4) | (bin % 10)
}

/// Read current date/time from RTC
///
/// This function waits for any in-progress update to complete,
/// then reads all time values atomically.
pub fn read_datetime() -> DateTime {
    unsafe {
        // Wait for any update to complete
        while is_update_in_progress() {
            core::hint::spin_loop();
        }

        // Read all values
        let mut seconds = cmos_read(reg::SECONDS);
        let mut minutes = cmos_read(reg::MINUTES);
        let mut hours = cmos_read(reg::HOURS);
        let day_of_week = cmos_read(reg::DAY_OF_WEEK);
        let mut day = cmos_read(reg::DAY_OF_MONTH);
        let mut month = cmos_read(reg::MONTH);
        let mut year = cmos_read(reg::YEAR);
        let mut century = cmos_read(reg::CENTURY);

        // Read again to ensure consistency (RTC may have updated mid-read)
        while is_update_in_progress() {
            core::hint::spin_loop();
        }

        let seconds2 = cmos_read(reg::SECONDS);
        if seconds != seconds2 {
            // Values changed, re-read everything
            seconds = cmos_read(reg::SECONDS);
            minutes = cmos_read(reg::MINUTES);
            hours = cmos_read(reg::HOURS);
            day = cmos_read(reg::DAY_OF_MONTH);
            month = cmos_read(reg::MONTH);
            year = cmos_read(reg::YEAR);
            century = cmos_read(reg::CENTURY);
        }

        // Check format
        let status_b = cmos_read(reg::STATUS_B);
        let is_binary = (status_b & status_b::BINARY) != 0;
        let is_24hour = (status_b & status_b::HOUR_24) != 0;

        // Convert from BCD if necessary
        if !is_binary {
            seconds = bcd_to_binary(seconds);
            minutes = bcd_to_binary(minutes);
            // Handle hours specially for 12-hour mode
            let pm = hours & 0x80;
            hours = bcd_to_binary(hours & 0x7F);
            if pm != 0 {
                hours |= 0x80;
            }
            day = bcd_to_binary(day);
            month = bcd_to_binary(month);
            year = bcd_to_binary(year);
            century = bcd_to_binary(century);
        }

        // Convert 12-hour to 24-hour if necessary
        if !is_24hour {
            let pm = (hours & 0x80) != 0;
            hours &= 0x7F;
            if hours == 12 {
                hours = if pm { 12 } else { 0 };
            } else if pm {
                hours += 12;
            }
        }

        // Calculate full year
        let full_year = if century == 0 || century == 0xFF {
            // Century register not supported, assume 2000s
            2000 + year as u16
        } else {
            (century as u16 * 100) + year as u16
        };

        DateTime {
            year: full_year,
            month,
            day,
            hour: hours,
            minute: minutes,
            second: seconds,
            day_of_week,
        }
    }
}

/// Convert DateTime to Windows FILETIME (100-ns intervals since 1601-01-01)
pub fn datetime_to_filetime(dt: &DateTime) -> u64 {
    // Days from year 1601 to the given year
    let year = dt.year as i64;
    let month = dt.month as i64;
    let day = dt.day as i64;

    // Calculate days since 1601-01-01
    // Using a simplified algorithm
    let mut total_days: i64 = 0;

    // Years from 1601 to year-1
    for y in 1601..year {
        total_days += if is_leap_year(y as u16) { 366 } else { 365 };
    }

    // Days in months before current month
    let days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        total_days += days_in_month[m as usize] as i64;
        if m == 2 && is_leap_year(dt.year) {
            total_days += 1;
        }
    }

    // Add current day (minus 1 because day 1 = 0 days past)
    total_days += day - 1;

    // Convert to 100-nanosecond intervals
    let seconds = total_days * 86400 + dt.hour as i64 * 3600
        + dt.minute as i64 * 60 + dt.second as i64;

    (seconds as u64) * 10_000_000
}

/// Check if year is a leap year
fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Initialize RTC subsystem
pub fn init() {
    // Read current time and store as boot time
    let dt = read_datetime();
    let filetime = datetime_to_filetime(&dt);

    BOOT_TIME.store(filetime, Ordering::SeqCst);
    SYSTEM_TIME.store(filetime, Ordering::SeqCst);

    crate::serial_println!(
        "[RTC] Initialized: {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second
    );
}

/// Get current system time as Windows FILETIME
pub fn get_system_time() -> u64 {
    // In a real implementation, we'd track elapsed ticks since boot
    // and add to boot time. For now, just re-read the RTC.
    let dt = read_datetime();
    datetime_to_filetime(&dt)
}

/// Get boot time as Windows FILETIME
pub fn get_boot_time() -> u64 {
    BOOT_TIME.load(Ordering::SeqCst)
}

/// Get current date/time
pub fn get_datetime() -> DateTime {
    read_datetime()
}

/// Get uptime in seconds (approximate)
pub fn get_uptime_seconds() -> u64 {
    let current = get_system_time();
    let boot = get_boot_time();
    if current > boot {
        (current - boot) / 10_000_000
    } else {
        0
    }
}
