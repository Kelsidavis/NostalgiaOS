//! CMOS/NVRAM Access
//!
//! Provides access to the CMOS real-time clock and NVRAM storage:
//!
//! - **RTC**: Real-time clock date/time access
//! - **NVRAM**: Non-volatile RAM storage (114 bytes)
//! - **Checksum**: CMOS data integrity verification
//! - **Battery**: Battery status monitoring
//!
//! # CMOS Memory Map
//!
//! Standard CMOS layout (128 bytes):
//! - 0x00-0x0D: Real-time clock registers
//! - 0x0E-0x0F: Status registers
//! - 0x10-0x3F: BIOS configuration data
//! - 0x40-0x7F: Extended CMOS (if present)
//!
//! # RTC Registers
//!
//! - 0x00: Seconds
//! - 0x02: Minutes
//! - 0x04: Hours
//! - 0x06: Day of Week
//! - 0x07: Day of Month
//! - 0x08: Month
//! - 0x09: Year
//! - 0x0A: Status Register A
//! - 0x0B: Status Register B
//! - 0x0C: Status Register C
//! - 0x0D: Status Register D
//!
//! # NT Functions
//!
//! - `HalReadCmosData` - Read CMOS bytes
//! - `HalWriteCmosData` - Write CMOS bytes
//! - `HalGetEnvironmentVariable` - Read NVRAM variable
//! - `HalSetEnvironmentVariable` - Write NVRAM variable
//!
//! # Usage
//!
//! ```ignore
//! // Read current time
//! let time = cmos_read_rtc();
//!
//! // Read CMOS byte
//! let value = cmos_read(0x10);
//!
//! // Write CMOS byte
//! cmos_write(0x10, 0x42);
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;

// ============================================================================
// Constants
// ============================================================================

/// CMOS address port
const CMOS_ADDRESS: u16 = 0x70;
/// CMOS data port
const CMOS_DATA: u16 = 0x71;

/// NMI disable bit (set in address port)
const NMI_DISABLE_BIT: u8 = 0x80;

/// Standard CMOS size (bytes)
pub const CMOS_SIZE: usize = 128;

/// Extended CMOS size (if available)
pub const EXTENDED_CMOS_SIZE: usize = 256;

/// NVRAM start offset (after RTC and status)
pub const NVRAM_START: u8 = 0x10;

/// NVRAM end offset
pub const NVRAM_END: u8 = 0x7F;

// ============================================================================
// CMOS Register Offsets
// ============================================================================

pub mod registers {
    /// Seconds (0-59)
    pub const RTC_SECONDS: u8 = 0x00;
    /// Seconds alarm
    pub const RTC_SECONDS_ALARM: u8 = 0x01;
    /// Minutes (0-59)
    pub const RTC_MINUTES: u8 = 0x02;
    /// Minutes alarm
    pub const RTC_MINUTES_ALARM: u8 = 0x03;
    /// Hours (0-23 or 1-12)
    pub const RTC_HOURS: u8 = 0x04;
    /// Hours alarm
    pub const RTC_HOURS_ALARM: u8 = 0x05;
    /// Day of week (1-7)
    pub const RTC_DAY_OF_WEEK: u8 = 0x06;
    /// Day of month (1-31)
    pub const RTC_DAY_OF_MONTH: u8 = 0x07;
    /// Month (1-12)
    pub const RTC_MONTH: u8 = 0x08;
    /// Year (0-99)
    pub const RTC_YEAR: u8 = 0x09;

    /// Status register A
    pub const STATUS_A: u8 = 0x0A;
    /// Status register B
    pub const STATUS_B: u8 = 0x0B;
    /// Status register C
    pub const STATUS_C: u8 = 0x0C;
    /// Status register D
    pub const STATUS_D: u8 = 0x0D;

    /// Diagnostic status
    pub const DIAGNOSTIC: u8 = 0x0E;
    /// Shutdown status
    pub const SHUTDOWN: u8 = 0x0F;

    /// Floppy drive types
    pub const FLOPPY_TYPES: u8 = 0x10;
    /// Hard disk types
    pub const HARD_DISK_TYPES: u8 = 0x12;
    /// Equipment byte
    pub const EQUIPMENT: u8 = 0x14;
    /// Base memory low byte
    pub const BASE_MEM_LOW: u8 = 0x15;
    /// Base memory high byte
    pub const BASE_MEM_HIGH: u8 = 0x16;
    /// Extended memory low byte
    pub const EXT_MEM_LOW: u8 = 0x17;
    /// Extended memory high byte
    pub const EXT_MEM_HIGH: u8 = 0x18;

    /// Century register (may vary by BIOS)
    pub const CENTURY: u8 = 0x32;

    /// CMOS checksum high byte
    pub const CHECKSUM_HIGH: u8 = 0x2E;
    /// CMOS checksum low byte
    pub const CHECKSUM_LOW: u8 = 0x2F;
}

// ============================================================================
// Status Register Bits
// ============================================================================

/// Status Register A bits
pub mod status_a {
    /// Update in progress (read-only)
    pub const UIP: u8 = 0x80;
    /// Divider select (bits 4-6)
    pub const DV_MASK: u8 = 0x70;
    /// Rate select (bits 0-3)
    pub const RS_MASK: u8 = 0x0F;
}

/// Status Register B bits
pub mod status_b {
    /// Daylight saving enable
    pub const DSE: u8 = 0x01;
    /// 24-hour mode
    pub const HOUR_24: u8 = 0x02;
    /// Binary mode (vs BCD)
    pub const DM: u8 = 0x04;
    /// Square wave enable
    pub const SQWE: u8 = 0x08;
    /// Update ended interrupt enable
    pub const UIE: u8 = 0x10;
    /// Alarm interrupt enable
    pub const AIE: u8 = 0x20;
    /// Periodic interrupt enable
    pub const PIE: u8 = 0x40;
    /// Update inhibit (set to modify time)
    pub const SET: u8 = 0x80;
}

/// Status Register C bits (read-only, cleared on read)
pub mod status_c {
    /// Update ended interrupt flag
    pub const UF: u8 = 0x10;
    /// Alarm interrupt flag
    pub const AF: u8 = 0x20;
    /// Periodic interrupt flag
    pub const PF: u8 = 0x40;
    /// Interrupt request flag
    pub const IRQF: u8 = 0x80;
}

/// Status Register D bits
pub mod status_d {
    /// Valid RAM and time (battery good)
    pub const VRT: u8 = 0x80;
}

// ============================================================================
// Types
// ============================================================================

/// RTC time structure
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RtcTime {
    pub seconds: u8,
    pub minutes: u8,
    pub hours: u8,
    pub day_of_week: u8,
    pub day: u8,
    pub month: u8,
    pub year: u8,
    pub century: u8,
}

impl RtcTime {
    /// Get full 4-digit year
    pub fn full_year(&self) -> u16 {
        (self.century as u16) * 100 + (self.year as u16)
    }

    /// Check if time is valid
    pub fn is_valid(&self) -> bool {
        self.seconds < 60
            && self.minutes < 60
            && self.hours < 24
            && self.day >= 1
            && self.day <= 31
            && self.month >= 1
            && self.month <= 12
    }
}

/// CMOS status
#[derive(Debug, Clone, Copy, Default)]
pub struct CmosStatus {
    /// Battery is good
    pub battery_good: bool,
    /// Update in progress
    pub update_in_progress: bool,
    /// 24-hour mode enabled
    pub hour_24_mode: bool,
    /// Binary mode (vs BCD)
    pub binary_mode: bool,
    /// Alarm interrupt enabled
    pub alarm_enabled: bool,
    /// Periodic interrupt enabled
    pub periodic_enabled: bool,
}

// ============================================================================
// Global State
// ============================================================================

static CMOS_LOCK: SpinLock<()> = SpinLock::new(());
static CMOS_READS: AtomicU64 = AtomicU64::new(0);
static CMOS_WRITES: AtomicU64 = AtomicU64::new(0);
static NMI_DISABLED: AtomicBool = AtomicBool::new(false);
static CMOS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static CENTURY_REGISTER: AtomicU32 = AtomicU32::new(registers::CENTURY as u32);

// ============================================================================
// Low-Level I/O
// ============================================================================

/// Read from CMOS port (without NMI handling)
#[inline]
unsafe fn cmos_port_read(addr: u8) -> u8 {
    use super::port::{read_port_u8, write_port_u8};

    // Write address (preserve NMI state)
    let nmi_mask = if NMI_DISABLED.load(Ordering::Relaxed) {
        NMI_DISABLE_BIT
    } else {
        0
    };
    write_port_u8(CMOS_ADDRESS, addr | nmi_mask);

    // Small delay for slow CMOS
    super::port::io_delay();

    read_port_u8(CMOS_DATA)
}

/// Write to CMOS port (without NMI handling)
#[inline]
unsafe fn cmos_port_write(addr: u8, value: u8) {
    use super::port::{write_port_u8};

    // Write address (preserve NMI state)
    let nmi_mask = if NMI_DISABLED.load(Ordering::Relaxed) {
        NMI_DISABLE_BIT
    } else {
        0
    };
    write_port_u8(CMOS_ADDRESS, addr | nmi_mask);

    // Small delay for slow CMOS
    super::port::io_delay();

    write_port_u8(CMOS_DATA, value)
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize CMOS subsystem
pub fn init() {
    // Detect century register from ACPI if available
    // For now, use standard location
    CENTURY_REGISTER.store(registers::CENTURY as u32, Ordering::Relaxed);
    CMOS_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[HAL] CMOS initialized");
}

/// Read a byte from CMOS
pub fn cmos_read(addr: u8) -> u8 {
    if addr >= CMOS_SIZE as u8 {
        return 0;
    }

    let _guard = CMOS_LOCK.lock();
    CMOS_READS.fetch_add(1, Ordering::Relaxed);

    unsafe { cmos_port_read(addr) }
}

/// Write a byte to CMOS
pub fn cmos_write(addr: u8, value: u8) {
    if addr >= CMOS_SIZE as u8 {
        return;
    }

    // Don't allow writing to RTC seconds-alarm through hours-alarm
    // or status registers without proper handling
    if addr < NVRAM_START && addr != registers::STATUS_A {
        return;
    }

    let _guard = CMOS_LOCK.lock();
    CMOS_WRITES.fetch_add(1, Ordering::Relaxed);

    unsafe { cmos_port_write(addr, value) }
}

/// Read multiple bytes from CMOS
pub fn cmos_read_buffer(start: u8, buffer: &mut [u8]) {
    let _guard = CMOS_LOCK.lock();

    for (i, byte) in buffer.iter_mut().enumerate() {
        let addr = start.wrapping_add(i as u8);
        if addr < CMOS_SIZE as u8 {
            *byte = unsafe { cmos_port_read(addr) };
        } else {
            *byte = 0;
        }
    }

    CMOS_READS.fetch_add(buffer.len() as u64, Ordering::Relaxed);
}

/// Write multiple bytes to CMOS (NVRAM region only)
pub fn cmos_write_buffer(start: u8, buffer: &[u8]) {
    // Only allow writing to NVRAM region
    if start < NVRAM_START {
        return;
    }

    let _guard = CMOS_LOCK.lock();

    for (i, &byte) in buffer.iter().enumerate() {
        let addr = start.wrapping_add(i as u8);
        if addr >= NVRAM_START && addr <= NVRAM_END {
            unsafe { cmos_port_write(addr, byte) };
        }
    }

    CMOS_WRITES.fetch_add(buffer.len() as u64, Ordering::Relaxed);
}

// ============================================================================
// RTC Functions
// ============================================================================

/// Convert BCD to binary
#[inline]
fn bcd_to_binary(value: u8) -> u8 {
    (value & 0x0F) + ((value >> 4) * 10)
}

/// Convert binary to BCD
#[inline]
fn binary_to_bcd(value: u8) -> u8 {
    ((value / 10) << 4) | (value % 10)
}

/// Wait for RTC update to complete
fn wait_for_update_complete() {
    // Wait for update-in-progress to clear
    let mut timeout = 10000u32;
    while timeout > 0 {
        let status = unsafe { cmos_port_read(registers::STATUS_A) };
        if (status & status_a::UIP) == 0 {
            break;
        }
        timeout -= 1;
        // Small delay
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }
}

/// Read RTC time
pub fn cmos_read_rtc() -> RtcTime {
    let _guard = CMOS_LOCK.lock();

    // Wait for any update to complete
    wait_for_update_complete();

    unsafe {
        let status_b = cmos_port_read(registers::STATUS_B);
        let is_binary = (status_b & status_b::DM) != 0;
        let is_24h = (status_b & status_b::HOUR_24) != 0;

        let seconds = cmos_port_read(registers::RTC_SECONDS);
        let minutes = cmos_port_read(registers::RTC_MINUTES);
        let mut hours = cmos_port_read(registers::RTC_HOURS);
        let day_of_week = cmos_port_read(registers::RTC_DAY_OF_WEEK);
        let day = cmos_port_read(registers::RTC_DAY_OF_MONTH);
        let month = cmos_port_read(registers::RTC_MONTH);
        let year = cmos_port_read(registers::RTC_YEAR);
        let century_reg = CENTURY_REGISTER.load(Ordering::Relaxed) as u8;
        let century = cmos_port_read(century_reg);

        // Handle 12-hour mode
        let pm = if !is_24h {
            (hours & 0x80) != 0
        } else {
            false
        };
        hours &= 0x7F;

        // Convert from BCD if needed
        let (seconds, minutes, hours, day, month, year, century) = if is_binary {
            (seconds, minutes, hours, day, month, year, century)
        } else {
            (
                bcd_to_binary(seconds),
                bcd_to_binary(minutes),
                bcd_to_binary(hours),
                bcd_to_binary(day),
                bcd_to_binary(month),
                bcd_to_binary(year),
                bcd_to_binary(century),
            )
        };

        // Handle 12-hour to 24-hour conversion
        let hours = if !is_24h {
            if hours == 12 {
                if pm { 12 } else { 0 }
            } else if pm {
                hours + 12
            } else {
                hours
            }
        } else {
            hours
        };

        CMOS_READS.fetch_add(8, Ordering::Relaxed);

        RtcTime {
            seconds,
            minutes,
            hours,
            day_of_week,
            day,
            month,
            year,
            century,
        }
    }
}

/// Write RTC time
pub fn cmos_write_rtc(time: &RtcTime) {
    if !time.is_valid() {
        return;
    }

    let _guard = CMOS_LOCK.lock();

    unsafe {
        let status_b = cmos_port_read(registers::STATUS_B);
        let is_binary = (status_b & status_b::DM) != 0;

        // Disable updates while setting time
        cmos_port_write(registers::STATUS_B, status_b | status_b::SET);

        // Convert to BCD if needed
        let (seconds, minutes, hours, day, month, year, century) = if is_binary {
            (
                time.seconds,
                time.minutes,
                time.hours,
                time.day,
                time.month,
                time.year,
                time.century,
            )
        } else {
            (
                binary_to_bcd(time.seconds),
                binary_to_bcd(time.minutes),
                binary_to_bcd(time.hours),
                binary_to_bcd(time.day),
                binary_to_bcd(time.month),
                binary_to_bcd(time.year),
                binary_to_bcd(time.century),
            )
        };

        cmos_port_write(registers::RTC_SECONDS, seconds);
        cmos_port_write(registers::RTC_MINUTES, minutes);
        cmos_port_write(registers::RTC_HOURS, hours);
        cmos_port_write(registers::RTC_DAY_OF_WEEK, time.day_of_week);
        cmos_port_write(registers::RTC_DAY_OF_MONTH, day);
        cmos_port_write(registers::RTC_MONTH, month);
        cmos_port_write(registers::RTC_YEAR, year);

        let century_reg = CENTURY_REGISTER.load(Ordering::Relaxed) as u8;
        cmos_port_write(century_reg, century);

        // Re-enable updates
        cmos_port_write(registers::STATUS_B, status_b & !status_b::SET);

        CMOS_WRITES.fetch_add(8, Ordering::Relaxed);
    }
}

// ============================================================================
// Status Functions
// ============================================================================

/// Get CMOS status
pub fn cmos_get_status() -> CmosStatus {
    let _guard = CMOS_LOCK.lock();

    unsafe {
        let status_a = cmos_port_read(registers::STATUS_A);
        let status_b = cmos_port_read(registers::STATUS_B);
        let status_d = cmos_port_read(registers::STATUS_D);

        CmosStatus {
            battery_good: (status_d & status_d::VRT) != 0,
            update_in_progress: (status_a & status_a::UIP) != 0,
            hour_24_mode: (status_b & status_b::HOUR_24) != 0,
            binary_mode: (status_b & status_b::DM) != 0,
            alarm_enabled: (status_b & status_b::AIE) != 0,
            periodic_enabled: (status_b & status_b::PIE) != 0,
        }
    }
}

/// Check if battery is good
pub fn cmos_battery_good() -> bool {
    let _guard = CMOS_LOCK.lock();
    unsafe {
        let status_d = cmos_port_read(registers::STATUS_D);
        (status_d & status_d::VRT) != 0
    }
}

// ============================================================================
// NMI Control
// ============================================================================

/// Disable NMI (Non-Maskable Interrupt)
pub fn cmos_disable_nmi() {
    NMI_DISABLED.store(true, Ordering::SeqCst);

    // Update CMOS address port to reflect new NMI state
    #[cfg(target_arch = "x86_64")]
    unsafe {
        super::port::write_port_u8(CMOS_ADDRESS, NMI_DISABLE_BIT);
    }
}

/// Enable NMI
pub fn cmos_enable_nmi() {
    NMI_DISABLED.store(false, Ordering::SeqCst);

    // Update CMOS address port to reflect new NMI state
    #[cfg(target_arch = "x86_64")]
    unsafe {
        super::port::write_port_u8(CMOS_ADDRESS, 0);
    }
}

/// Check if NMI is disabled
pub fn cmos_is_nmi_disabled() -> bool {
    NMI_DISABLED.load(Ordering::Relaxed)
}

// ============================================================================
// Checksum Functions
// ============================================================================

/// Calculate CMOS checksum
pub fn cmos_calculate_checksum() -> u16 {
    let _guard = CMOS_LOCK.lock();

    let mut sum: u16 = 0;

    // Standard checksum covers bytes 0x10-0x2D
    for addr in 0x10u8..=0x2D {
        unsafe {
            sum = sum.wrapping_add(cmos_port_read(addr) as u16);
        }
    }

    sum
}

/// Get stored CMOS checksum
pub fn cmos_get_stored_checksum() -> u16 {
    let _guard = CMOS_LOCK.lock();

    unsafe {
        let high = cmos_port_read(registers::CHECKSUM_HIGH) as u16;
        let low = cmos_port_read(registers::CHECKSUM_LOW) as u16;
        (high << 8) | low
    }
}

/// Verify CMOS checksum
pub fn cmos_verify_checksum() -> bool {
    let calculated = cmos_calculate_checksum();
    let stored = cmos_get_stored_checksum();
    calculated == stored
}

/// Update CMOS checksum
pub fn cmos_update_checksum() {
    let checksum = cmos_calculate_checksum();

    let _guard = CMOS_LOCK.lock();

    unsafe {
        cmos_port_write(registers::CHECKSUM_HIGH, (checksum >> 8) as u8);
        cmos_port_write(registers::CHECKSUM_LOW, checksum as u8);
    }

    CMOS_WRITES.fetch_add(2, Ordering::Relaxed);
}

// ============================================================================
// Memory Size Functions
// ============================================================================

/// Get base memory size (KB, typically 640)
pub fn cmos_get_base_memory() -> u16 {
    let _guard = CMOS_LOCK.lock();

    unsafe {
        let low = cmos_port_read(registers::BASE_MEM_LOW) as u16;
        let high = cmos_port_read(registers::BASE_MEM_HIGH) as u16;
        (high << 8) | low
    }
}

/// Get extended memory size (KB above 1MB)
pub fn cmos_get_extended_memory() -> u16 {
    let _guard = CMOS_LOCK.lock();

    unsafe {
        let low = cmos_port_read(registers::EXT_MEM_LOW) as u16;
        let high = cmos_port_read(registers::EXT_MEM_HIGH) as u16;
        (high << 8) | low
    }
}

// ============================================================================
// NT Compatibility
// ============================================================================

/// HalReadCmosData equivalent
pub fn hal_read_cmos_data(slot: u32, offset: u32, buffer: &mut [u8]) -> u32 {
    // Slot 0 = standard CMOS, slot 1 = extended CMOS
    let base = if slot == 0 { 0 } else { 0x80 };
    let start = base + offset as u8;

    cmos_read_buffer(start, buffer);
    buffer.len() as u32
}

/// HalWriteCmosData equivalent
pub fn hal_write_cmos_data(slot: u32, offset: u32, buffer: &[u8]) -> u32 {
    let base = if slot == 0 { 0 } else { 0x80 };
    let start = base + offset as u8;

    cmos_write_buffer(start, buffer);
    buffer.len() as u32
}

// ============================================================================
// Statistics
// ============================================================================

/// CMOS statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct CmosStats {
    pub initialized: bool,
    pub reads: u64,
    pub writes: u64,
    pub nmi_disabled: bool,
    pub battery_good: bool,
    pub checksum_valid: bool,
}

/// Get CMOS statistics
pub fn cmos_get_stats() -> CmosStats {
    CmosStats {
        initialized: CMOS_INITIALIZED.load(Ordering::Relaxed),
        reads: CMOS_READS.load(Ordering::Relaxed),
        writes: CMOS_WRITES.load(Ordering::Relaxed),
        nmi_disabled: NMI_DISABLED.load(Ordering::Relaxed),
        battery_good: cmos_battery_good(),
        checksum_valid: cmos_verify_checksum(),
    }
}

/// Check if CMOS is initialized
pub fn cmos_is_initialized() -> bool {
    CMOS_INITIALIZED.load(Ordering::Acquire)
}
