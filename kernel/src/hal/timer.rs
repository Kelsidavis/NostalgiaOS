//! HAL Timer Support
//!
//! Provides hardware timer abstraction for the kernel:
//!
//! - **Performance Counter**: High-resolution timing via TSC/HPET
//! - **System Time**: Wall-clock time management
//! - **Timer Interrupts**: Periodic interrupt support
//! - **Timer Calibration**: TSC/APIC timer frequency detection
//!
//! # Timer Sources
//!
//! The HAL supports multiple timer sources:
//! - TSC (Time Stamp Counter): Highest resolution, per-CPU
//! - HPET (High Precision Event Timer): System-wide, consistent
//! - APIC Timer: Per-CPU, used for scheduling
//! - PIT (8254): Legacy timer, fallback only
//!
//! # NT Functions
//!
//! - `KeQueryPerformanceCounter` - High resolution counter
//! - `KeQuerySystemTime` - Current system time (100ns units)
//! - `KeQueryTickCount` - System tick count
//! - `HalCalibratePerformanceCounter` - Timer calibration
//!
//! # Usage
//!
//! ```ignore
//! // Get high-resolution timestamp
//! let counter = hal_query_performance_counter();
//! let freq = hal_query_performance_frequency();
//!
//! // Calculate elapsed time
//! let elapsed_ns = (counter * 1_000_000_000) / freq;
//! ```

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;

/// Timer resolution in 100-nanosecond units (NT standard)
pub const TIME_INCREMENT: u64 = 156250; // ~15.625ms default

/// Nanoseconds per second
pub const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// Nanoseconds per 100ns unit
pub const NANOSECONDS_PER_TIME_UNIT: u64 = 100;

/// Timer source types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimerSource {
    /// Unknown/not calibrated
    #[default]
    Unknown = 0,
    /// Time Stamp Counter (RDTSC)
    Tsc = 1,
    /// High Precision Event Timer
    Hpet = 2,
    /// Local APIC Timer
    ApicTimer = 3,
    /// 8254 Programmable Interval Timer
    Pit = 4,
}

/// System time epoch
/// NT epoch: January 1, 1601
/// Unix epoch: January 1, 1970
/// Difference: 11644473600 seconds = 116444736000000000 100ns units
pub const NT_UNIX_EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// Timer calibration data
#[derive(Debug, Clone, Copy)]
pub struct TimerCalibration {
    /// TSC frequency in Hz
    pub tsc_frequency: u64,
    /// APIC timer frequency in Hz
    pub apic_frequency: u64,
    /// Performance counter frequency
    pub performance_frequency: u64,
    /// Timer source being used
    pub timer_source: TimerSource,
    /// TSC is invariant (constant rate)
    pub tsc_invariant: bool,
    /// Calibration complete
    pub calibrated: bool,
}

impl Default for TimerCalibration {
    fn default() -> Self {
        Self {
            tsc_frequency: 0,
            apic_frequency: 0,
            performance_frequency: 0,
            timer_source: TimerSource::Unknown,
            tsc_invariant: false,
            calibrated: false,
        }
    }
}

/// System time state
#[derive(Debug)]
struct SystemTimeState {
    /// Current system time in 100ns units since NT epoch
    system_time: AtomicU64,
    /// Boot time in 100ns units since NT epoch
    boot_time: AtomicU64,
    /// Tick count since boot
    tick_count: AtomicU64,
    /// Time zone bias in 100ns units
    time_zone_bias: AtomicU64,
    /// Last TSC value for time updates
    last_tsc: AtomicU64,
}

impl SystemTimeState {
    const fn new() -> Self {
        Self {
            system_time: AtomicU64::new(0),
            boot_time: AtomicU64::new(0),
            tick_count: AtomicU64::new(0),
            time_zone_bias: AtomicU64::new(0),
            last_tsc: AtomicU64::new(0),
        }
    }
}

/// Timer interrupt state
struct TimerInterruptState {
    /// Timer interrupt enabled
    enabled: AtomicBool,
    /// Timer interrupt interval in 100ns units
    interval: AtomicU64,
    /// Timer interrupt count
    interrupt_count: AtomicU64,
    /// Last timer interrupt TSC
    last_interrupt_tsc: AtomicU64,
}

impl TimerInterruptState {
    const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            interval: AtomicU64::new(TIME_INCREMENT),
            interrupt_count: AtomicU64::new(0),
            last_interrupt_tsc: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Global Timer State
// ============================================================================

static mut CALIBRATION: TimerCalibration = TimerCalibration {
    tsc_frequency: 0,
    apic_frequency: 0,
    performance_frequency: 0,
    timer_source: TimerSource::Unknown,
    tsc_invariant: false,
    calibrated: false,
};

static TIME_STATE: SystemTimeState = SystemTimeState::new();
static INTERRUPT_STATE: TimerInterruptState = TimerInterruptState::new();
static TIMER_LOCK: SpinLock<()> = SpinLock::new(());
static TIMER_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// TSC Functions
// ============================================================================

/// Read Time Stamp Counter
#[inline]
pub fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Read TSC with serializing fence (more accurate)
#[inline]
pub fn read_tsc_serialized() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // LFENCE to serialize
        core::arch::x86_64::_mm_lfence();
        let tsc = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        tsc
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Check if TSC is invariant (constant rate)
pub fn is_tsc_invariant() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Check CPUID.80000007H:EDX[8] = Invariant TSC
        let result: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 0x80000007",
            "cpuid",
            "pop rbx",
            out("edx") result,
            out("eax") _,
            out("ecx") _,
            options(preserves_flags)
        );
        (result & (1 << 8)) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Get TSC frequency from CPUID (if available)
pub fn get_tsc_frequency_cpuid() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Try CPUID.15H for TSC frequency
        let (eax, ebx_val, ecx): (u32, u32, u32);
        core::arch::asm!(
            "push rbx",
            "mov eax, 0x15",
            "xor ecx, ecx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx_val,
            out("eax") eax,
            out("ecx") ecx,
            out("edx") _,
            options(preserves_flags)
        );

        if eax != 0 && ebx_val != 0 && ecx != 0 {
            // TSC frequency = ecx * ebx / eax
            let freq = (ecx as u64 * ebx_val as u64) / eax as u64;
            if freq > 0 {
                return Some(freq);
            }
        }

        // Try CPUID.16H for processor frequency (approximate)
        let base_freq: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 0x16",
            "cpuid",
            "pop rbx",
            out("eax") base_freq,
            out("ecx") _,
            out("edx") _,
            options(preserves_flags)
        );

        if base_freq > 0 {
            // Base frequency is in MHz, convert to Hz
            return Some(base_freq as u64 * 1_000_000);
        }

        None
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

// ============================================================================
// Performance Counter API
// ============================================================================

/// Query performance counter (high resolution)
///
/// Returns the current value of the performance counter.
/// Use with `hal_query_performance_frequency()` to calculate elapsed time.
#[inline]
pub fn hal_query_performance_counter() -> u64 {
    read_tsc()
}

/// Query performance counter frequency
///
/// Returns the frequency of the performance counter in Hz.
#[inline]
pub fn hal_query_performance_frequency() -> u64 {
    unsafe { CALIBRATION.performance_frequency }
}

/// Query performance counter with frequency
///
/// Returns both the counter value and frequency for atomic access.
pub fn hal_query_performance_counter_ex() -> (u64, u64) {
    let counter = read_tsc();
    let freq = unsafe { CALIBRATION.performance_frequency };
    (counter, freq)
}

/// Convert performance counter ticks to nanoseconds
pub fn ticks_to_nanoseconds(ticks: u64) -> u64 {
    let freq = unsafe { CALIBRATION.performance_frequency };
    if freq == 0 {
        return 0;
    }
    (ticks * NANOSECONDS_PER_SECOND) / freq
}

/// Convert nanoseconds to performance counter ticks
pub fn nanoseconds_to_ticks(ns: u64) -> u64 {
    let freq = unsafe { CALIBRATION.performance_frequency };
    (ns * freq) / NANOSECONDS_PER_SECOND
}

// ============================================================================
// System Time API
// ============================================================================

/// Query system time in 100ns units since NT epoch (January 1, 1601)
pub fn hal_query_system_time() -> u64 {
    TIME_STATE.system_time.load(Ordering::Acquire)
}

/// Query local time (system time adjusted for timezone)
pub fn hal_query_local_time() -> u64 {
    let system = TIME_STATE.system_time.load(Ordering::Acquire);
    let bias = TIME_STATE.time_zone_bias.load(Ordering::Relaxed);
    system.saturating_sub(bias)
}

/// Set system time
///
/// # Safety
/// This should only be called during initialization or by privileged code.
pub unsafe fn hal_set_system_time(time: u64) {
    TIME_STATE.system_time.store(time, Ordering::Release);
}

/// Query boot time
pub fn hal_query_boot_time() -> u64 {
    TIME_STATE.boot_time.load(Ordering::Acquire)
}

/// Query uptime in 100ns units
pub fn hal_query_uptime() -> u64 {
    let now = TIME_STATE.system_time.load(Ordering::Acquire);
    let boot = TIME_STATE.boot_time.load(Ordering::Acquire);
    now.saturating_sub(boot)
}

/// Query uptime in seconds
pub fn hal_query_uptime_seconds() -> u64 {
    hal_query_uptime() / 10_000_000 // 100ns to seconds
}

/// Query tick count (timer interrupts since boot)
pub fn hal_query_tick_count() -> u64 {
    TIME_STATE.tick_count.load(Ordering::Relaxed)
}

/// Get current time zone bias in 100ns units
pub fn hal_get_time_zone_bias() -> u64 {
    TIME_STATE.time_zone_bias.load(Ordering::Relaxed)
}

/// Set time zone bias in 100ns units
pub fn hal_set_time_zone_bias(bias: u64) {
    TIME_STATE.time_zone_bias.store(bias, Ordering::Relaxed);
}

/// Get tick count (NT API compatibility)
pub fn ke_query_tick_count() -> u64 {
    hal_query_tick_count()
}

/// Get time increment (100ns units per tick)
pub fn ke_query_time_increment() -> u64 {
    TIME_INCREMENT
}

// ============================================================================
// Timer Interrupt Support
// ============================================================================

/// Timer interrupt handler
///
/// Called by the timer interrupt to update system time and tick count.
pub fn hal_timer_interrupt() {
    // Update interrupt count
    INTERRUPT_STATE.interrupt_count.fetch_add(1, Ordering::Relaxed);
    INTERRUPT_STATE.last_interrupt_tsc.store(read_tsc(), Ordering::Relaxed);

    // Update tick count
    TIME_STATE.tick_count.fetch_add(1, Ordering::Relaxed);

    // Update system time based on interval
    let interval = INTERRUPT_STATE.interval.load(Ordering::Relaxed);
    TIME_STATE.system_time.fetch_add(interval, Ordering::Release);
}

/// Set timer interrupt interval
///
/// # Arguments
/// * `interval` - Interval in 100ns units
pub fn hal_set_timer_interval(interval: u64) {
    INTERRUPT_STATE.interval.store(interval, Ordering::Release);
}

/// Get timer interrupt interval
pub fn hal_get_timer_interval() -> u64 {
    INTERRUPT_STATE.interval.load(Ordering::Relaxed)
}

/// Enable timer interrupts
pub fn hal_enable_timer_interrupt() {
    INTERRUPT_STATE.enabled.store(true, Ordering::Release);
}

/// Disable timer interrupts
pub fn hal_disable_timer_interrupt() {
    INTERRUPT_STATE.enabled.store(false, Ordering::Release);
}

/// Check if timer interrupts are enabled
pub fn hal_is_timer_interrupt_enabled() -> bool {
    INTERRUPT_STATE.enabled.load(Ordering::Acquire)
}

/// Get timer interrupt count
pub fn hal_get_timer_interrupt_count() -> u64 {
    INTERRUPT_STATE.interrupt_count.load(Ordering::Relaxed)
}

// ============================================================================
// Calibration
// ============================================================================

/// Calibrate timers
///
/// Determines TSC and APIC timer frequencies for accurate timing.
pub fn hal_calibrate_timers() {
    let _guard = unsafe { TIMER_LOCK.lock() };

    unsafe {
        // Check for invariant TSC
        CALIBRATION.tsc_invariant = is_tsc_invariant();

        // Try to get TSC frequency from CPUID first
        if let Some(freq) = get_tsc_frequency_cpuid() {
            CALIBRATION.tsc_frequency = freq;
            CALIBRATION.performance_frequency = freq;
            CALIBRATION.timer_source = TimerSource::Tsc;
            CALIBRATION.calibrated = true;
            crate::serial_println!("[HAL] TSC frequency from CPUID: {} Hz", freq);
            return;
        }

        // Fallback: estimate using PIT
        // This is a simplified calibration - real implementation would use PIT
        // For now, assume a reasonable default (2.5 GHz)
        let estimated_freq = 2_500_000_000u64;
        CALIBRATION.tsc_frequency = estimated_freq;
        CALIBRATION.performance_frequency = estimated_freq;
        CALIBRATION.timer_source = TimerSource::Tsc;
        CALIBRATION.calibrated = true;

        crate::serial_println!("[HAL] TSC frequency estimated: {} Hz", estimated_freq);
    }
}

/// Get calibration data
pub fn hal_get_calibration() -> TimerCalibration {
    unsafe { CALIBRATION }
}

/// Check if timers are calibrated
pub fn hal_is_calibrated() -> bool {
    unsafe { CALIBRATION.calibrated }
}

// ============================================================================
// Stall/Delay Functions
// ============================================================================

/// Busy-wait for a number of microseconds
pub fn hal_stall_execution(microseconds: u32) {
    let freq = unsafe { CALIBRATION.performance_frequency };
    if freq == 0 {
        // Fallback: simple loop-based delay
        for _ in 0..microseconds * 100 {
            core::hint::spin_loop();
        }
        return;
    }

    let ticks = (microseconds as u64 * freq) / 1_000_000;
    let start = read_tsc();

    while read_tsc().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

/// Busy-wait for a number of nanoseconds
pub fn hal_stall_execution_ns(nanoseconds: u64) {
    let freq = unsafe { CALIBRATION.performance_frequency };
    if freq == 0 {
        return;
    }

    let ticks = (nanoseconds * freq) / NANOSECONDS_PER_SECOND;
    let start = read_tsc();

    while read_tsc().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

// ============================================================================
// Timer Statistics
// ============================================================================

/// Timer statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct TimerStats {
    /// Timer source in use
    pub timer_source: TimerSource,
    /// TSC frequency in Hz
    pub tsc_frequency: u64,
    /// Performance counter frequency
    pub performance_frequency: u64,
    /// Is TSC invariant
    pub tsc_invariant: bool,
    /// Is calibrated
    pub calibrated: bool,
    /// Current tick count
    pub tick_count: u64,
    /// Timer interrupt count
    pub interrupt_count: u64,
    /// Current system time (100ns units)
    pub system_time: u64,
    /// Uptime (100ns units)
    pub uptime: u64,
}

/// Get timer statistics
pub fn hal_get_timer_stats() -> TimerStats {
    let cal = hal_get_calibration();

    TimerStats {
        timer_source: cal.timer_source,
        tsc_frequency: cal.tsc_frequency,
        performance_frequency: cal.performance_frequency,
        tsc_invariant: cal.tsc_invariant,
        calibrated: cal.calibrated,
        tick_count: hal_query_tick_count(),
        interrupt_count: hal_get_timer_interrupt_count(),
        system_time: hal_query_system_time(),
        uptime: hal_query_uptime(),
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize HAL timer subsystem
pub fn init() {
    unsafe {
        // Initialize calibration
        CALIBRATION = TimerCalibration::default();

        // Set initial boot time (would be read from RTC in real implementation)
        // For now, use a placeholder representing a date
        // This represents 2024-01-01 00:00:00 in NT time
        let initial_time = NT_UNIX_EPOCH_DIFF + (54 * 365 + 13) * 24 * 60 * 60 * 10_000_000u64;
        TIME_STATE.boot_time.store(initial_time, Ordering::Release);
        TIME_STATE.system_time.store(initial_time, Ordering::Release);
        TIME_STATE.tick_count.store(0, Ordering::Release);

        // Set default timezone bias (0 = UTC)
        TIME_STATE.time_zone_bias.store(0, Ordering::Release);

        // Calibrate timers
        hal_calibrate_timers();

        // Enable timer interrupts
        hal_enable_timer_interrupt();

        TIMER_INITIALIZED.store(true, Ordering::Release);
    }

    crate::serial_println!("[HAL] Timer subsystem initialized");
}

/// Check if timer subsystem is initialized
pub fn hal_is_timer_initialized() -> bool {
    TIMER_INITIALIZED.load(Ordering::Acquire)
}
