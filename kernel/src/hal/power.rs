//! Power State Management
//!
//! Provides ACPI power state control:
//!
//! - **S-States**: System sleep states (S0-S5)
//! - **G-States**: Global states (G0-G3)
//! - **Wake**: Wake source configuration
//! - **Shutdown**: System shutdown/restart
//!
//! # Power States
//!
//! - S0: Working (fully on)
//! - S1: Standby (CPU stops, RAM refreshed)
//! - S2: Standby (CPU off, RAM refreshed)
//! - S3: Suspend to RAM (STR/Sleep)
//! - S4: Suspend to Disk (STD/Hibernate)
//! - S5: Soft Off (power off, needs button)
//!
//! # Wake Sources
//!
//! - Power button
//! - Keyboard/Mouse
//! - Network (Wake-on-LAN)
//! - RTC alarm
//! - USB
//!
//! # NT Functions
//!
//! - `HalSystemShutdown` - Shutdown or restart
//! - `HalReturnToFirmware` - Reboot to BIOS/UEFI
//! - `NtSetSystemPowerState` - Set power state
//!
//! # Usage
//!
//! ```ignore
//! // Check sleep support
//! if power_is_s3_supported() {
//!     power_enter_sleep_state(SleepState::S3);
//! }
//!
//! // Shutdown
//! power_shutdown(false);  // false = power off, true = restart
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;

// ============================================================================
// Constants
// ============================================================================

/// ACPI PM1a control port (placeholder, set from FADT)
const PM1A_CNT_DEFAULT: u16 = 0x0;

/// ACPI PM1b control port
const PM1B_CNT_DEFAULT: u16 = 0x0;

/// SLP_EN bit in PM1 control register
const SLP_EN: u16 = 1 << 13;

/// SLP_TYP shift (bits 10-12)
const SLP_TYP_SHIFT: u16 = 10;

// ============================================================================
// Types
// ============================================================================

/// System sleep state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SleepState {
    #[default]
    S0 = 0,  // Working
    S1 = 1,  // Standby (power to CPU)
    S2 = 2,  // Standby (no power to CPU)
    S3 = 3,  // Suspend to RAM
    S4 = 4,  // Suspend to Disk
    S5 = 5,  // Soft Off
}

/// Global state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GlobalState {
    #[default]
    G0 = 0,  // Working
    G1 = 1,  // Sleeping
    G2 = 2,  // Soft Off (S5)
    G3 = 3,  // Mechanical Off
}

/// Wake source
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeSource {
    Unknown = 0,
    PowerButton = 1,
    SleepButton = 2,
    RtcAlarm = 3,
    Keyboard = 4,
    Mouse = 5,
    Lan = 6,
    Usb = 7,
    Pci = 8,
}

/// Shutdown action
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownAction {
    PowerOff = 0,
    Restart = 1,
    Hibernate = 2,
    Sleep = 3,
}

/// Sleep state support flags
#[derive(Debug, Clone, Copy, Default)]
pub struct SleepSupport {
    pub s1_supported: bool,
    pub s2_supported: bool,
    pub s3_supported: bool,
    pub s4_supported: bool,
    pub s5_supported: bool,
}

/// Power state info
#[derive(Debug, Clone, Copy, Default)]
pub struct PowerStateInfo {
    pub current_state: SleepState,
    pub target_state: SleepState,
    pub transition_in_progress: bool,
    pub last_wake_source: Option<WakeSource>,
    pub last_sleep_time: u64,
    pub last_wake_time: u64,
}

// ============================================================================
// ACPI Register Addresses
// ============================================================================

/// ACPI FADT information
#[derive(Debug, Clone, Copy, Default)]
pub struct AcpiFadt {
    pub pm1a_evt_blk: u16,
    pub pm1b_evt_blk: u16,
    pub pm1a_cnt_blk: u16,
    pub pm1b_cnt_blk: u16,
    pub pm2_cnt_blk: u16,
    pub pm_tmr_blk: u16,
    pub gpe0_blk: u16,
    pub gpe1_blk: u16,
    pub pm1_evt_len: u8,
    pub pm1_cnt_len: u8,
    pub pm2_cnt_len: u8,
    pub pm_tmr_len: u8,
    pub gpe0_blk_len: u8,
    pub gpe1_blk_len: u8,
    pub s4bios_req: bool,
    pub reset_reg_supported: bool,
    pub reset_reg: u64,
    pub reset_value: u8,
}

/// Sleep type values (from DSDT/SSDT _Sx methods)
#[derive(Debug, Clone, Copy, Default)]
pub struct SleepTypeValues {
    pub s1_typ_a: u8,
    pub s1_typ_b: u8,
    pub s2_typ_a: u8,
    pub s2_typ_b: u8,
    pub s3_typ_a: u8,
    pub s3_typ_b: u8,
    pub s4_typ_a: u8,
    pub s4_typ_b: u8,
    pub s5_typ_a: u8,
    pub s5_typ_b: u8,
}

// ============================================================================
// Global State
// ============================================================================

static POWER_LOCK: SpinLock<()> = SpinLock::new(());
static POWER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static ACPI_AVAILABLE: AtomicBool = AtomicBool::new(false);

static CURRENT_STATE: AtomicU32 = AtomicU32::new(SleepState::S0 as u32);
static TRANSITION_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

static LAST_WAKE_SOURCE: AtomicU32 = AtomicU32::new(WakeSource::Unknown as u32);
static LAST_SLEEP_TIME: AtomicU64 = AtomicU64::new(0);
static LAST_WAKE_TIME: AtomicU64 = AtomicU64::new(0);

static SLEEP_COUNT: AtomicU64 = AtomicU64::new(0);
static WAKE_COUNT: AtomicU64 = AtomicU64::new(0);
static SHUTDOWN_COUNT: AtomicU64 = AtomicU64::new(0);

/// ACPI port addresses
static PM1A_CNT_BLK: AtomicU32 = AtomicU32::new(PM1A_CNT_DEFAULT as u32);
static PM1B_CNT_BLK: AtomicU32 = AtomicU32::new(PM1B_CNT_DEFAULT as u32);

/// Sleep type values
static S5_TYP_A: AtomicU32 = AtomicU32::new(0);
static S5_TYP_B: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Port Access
// ============================================================================

/// Read from PM control register
#[inline]
unsafe fn read_pm1_cnt() -> u16 {
    let port = PM1A_CNT_BLK.load(Ordering::Relaxed) as u16;
    if port != 0 {
        super::port::read_port_u16(port)
    } else {
        0
    }
}

/// Write to PM control register
#[inline]
unsafe fn write_pm1_cnt(value: u16) {
    let port_a = PM1A_CNT_BLK.load(Ordering::Relaxed) as u16;
    if port_a != 0 {
        super::port::write_port_u16(port_a, value);
    }

    let port_b = PM1B_CNT_BLK.load(Ordering::Relaxed) as u16;
    if port_b != 0 {
        super::port::write_port_u16(port_b, value);
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize power management
pub fn init() {
    let _guard = POWER_LOCK.lock();

    // Would parse ACPI tables here to get PM control block addresses
    // For now, assume S5 is available with common values

    POWER_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[Power] Initialized");
}

/// Set ACPI FADT information
pub fn power_set_fadt(fadt: &AcpiFadt) {
    let _guard = POWER_LOCK.lock();

    PM1A_CNT_BLK.store(fadt.pm1a_cnt_blk as u32, Ordering::Relaxed);
    PM1B_CNT_BLK.store(fadt.pm1b_cnt_blk as u32, Ordering::Relaxed);

    ACPI_AVAILABLE.store(true, Ordering::Release);

    crate::serial_println!(
        "[Power] ACPI FADT: PM1a=0x{:X}, PM1b=0x{:X}",
        fadt.pm1a_cnt_blk, fadt.pm1b_cnt_blk
    );
}

/// Set sleep type values (from DSDT parsing)
pub fn power_set_sleep_types(types: &SleepTypeValues) {
    S5_TYP_A.store(types.s5_typ_a as u32, Ordering::Relaxed);
    S5_TYP_B.store(types.s5_typ_b as u32, Ordering::Relaxed);
}

// ============================================================================
// Sleep State Support
// ============================================================================

/// Get supported sleep states
pub fn power_get_sleep_support() -> SleepSupport {
    // Would query ACPI tables for actual support
    SleepSupport {
        s1_supported: false,
        s2_supported: false,
        s3_supported: false,
        s4_supported: false,
        s5_supported: ACPI_AVAILABLE.load(Ordering::Relaxed),
    }
}

/// Check if S3 (sleep) is supported
pub fn power_is_s3_supported() -> bool {
    power_get_sleep_support().s3_supported
}

/// Check if S4 (hibernate) is supported
pub fn power_is_s4_supported() -> bool {
    power_get_sleep_support().s4_supported
}

/// Check if S5 (soft off) is supported
pub fn power_is_s5_supported() -> bool {
    power_get_sleep_support().s5_supported
}

// ============================================================================
// Power State Transitions
// ============================================================================

/// Enter a sleep state
pub fn power_enter_sleep_state(state: SleepState) -> bool {
    let _guard = POWER_LOCK.lock();

    if !POWER_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    if TRANSITION_IN_PROGRESS.load(Ordering::Relaxed) {
        return false;
    }

    TRANSITION_IN_PROGRESS.store(true, Ordering::Release);

    crate::serial_println!("[Power] Entering {:?}", state);

    let result = match state {
        SleepState::S0 => {
            // Already in S0, nothing to do
            true
        }
        SleepState::S1 | SleepState::S2 | SleepState::S3 => {
            // Would save system state and enter sleep
            // For now, just record the transition
            LAST_SLEEP_TIME.store(read_tsc(), Ordering::Relaxed);
            SLEEP_COUNT.fetch_add(1, Ordering::Relaxed);
            CURRENT_STATE.store(state as u32, Ordering::Relaxed);
            true
        }
        SleepState::S4 => {
            // Hibernate - would write RAM to disk
            LAST_SLEEP_TIME.store(read_tsc(), Ordering::Relaxed);
            SLEEP_COUNT.fetch_add(1, Ordering::Relaxed);
            true
        }
        SleepState::S5 => {
            // Soft off - this doesn't return
            power_acpi_shutdown();
            false  // Should not reach here
        }
    };

    TRANSITION_IN_PROGRESS.store(false, Ordering::Release);
    result
}

/// Exit sleep state (wake up)
pub fn power_exit_sleep_state(wake_source: WakeSource) {
    let _guard = POWER_LOCK.lock();

    LAST_WAKE_TIME.store(read_tsc(), Ordering::Relaxed);
    LAST_WAKE_SOURCE.store(wake_source as u32, Ordering::Relaxed);
    WAKE_COUNT.fetch_add(1, Ordering::Relaxed);
    CURRENT_STATE.store(SleepState::S0 as u32, Ordering::Relaxed);

    crate::serial_println!("[Power] Woke from sleep, source: {:?}", wake_source);
}

/// Get current power state
pub fn power_get_current_state() -> SleepState {
    match CURRENT_STATE.load(Ordering::Relaxed) {
        0 => SleepState::S0,
        1 => SleepState::S1,
        2 => SleepState::S2,
        3 => SleepState::S3,
        4 => SleepState::S4,
        5 => SleepState::S5,
        _ => SleepState::S0,
    }
}

// ============================================================================
// Shutdown/Restart
// ============================================================================

/// Shutdown or restart the system
pub fn power_shutdown(restart: bool) -> ! {
    let _guard = POWER_LOCK.lock();

    SHUTDOWN_COUNT.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[Power] {} system", if restart { "Restarting" } else { "Shutting down" });

    if restart {
        power_restart();
    } else {
        power_acpi_shutdown();
    }

    // If we get here, something went wrong
    // Fall back to triple fault
    crate::serial_println!("[Power] Shutdown failed, triple faulting");
    power_triple_fault();
}

/// ACPI shutdown (S5)
fn power_acpi_shutdown() -> ! {
    // Try ACPI shutdown
    if ACPI_AVAILABLE.load(Ordering::Relaxed) {
        let slp_typ_a = S5_TYP_A.load(Ordering::Relaxed) as u16;

        unsafe {
            let current = read_pm1_cnt();
            let value = (current & !0x3C00) | (slp_typ_a << SLP_TYP_SHIFT) | SLP_EN;
            write_pm1_cnt(value);
        }

        // Give it time to work
        for _ in 0..10000000 {
            core::hint::spin_loop();
        }
    }

    // If ACPI failed, try keyboard controller
    power_keyboard_shutdown();

    // Final fallback
    power_triple_fault();
}

/// Restart via keyboard controller
fn power_restart() -> ! {
    // Try keyboard controller reset
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Wait for keyboard controller
        let mut timeout = 100000u32;
        while timeout > 0 {
            if (super::port::read_port_u8(0x64) & 0x02) == 0 {
                break;
            }
            timeout -= 1;
        }

        // Send reset command
        super::port::write_port_u8(0x64, 0xFE);
    }

    // Give it time to work
    for _ in 0..10000000 {
        core::hint::spin_loop();
    }

    // If keyboard reset failed, try triple fault
    power_triple_fault();
}

/// Shutdown via keyboard controller
fn power_keyboard_shutdown() {
    // Some systems support shutdown via keyboard controller
    #[cfg(target_arch = "x86_64")]
    unsafe {
        super::port::write_port_u8(0x64, 0xFE);
    }
}

/// Triple fault to force reset
fn power_triple_fault() -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Load empty IDT
        let null_idt: [u8; 6] = [0; 6];
        core::arch::asm!(
            "lidt [{}]",
            in(reg) null_idt.as_ptr(),
            options(nostack)
        );

        // Trigger interrupt - will triple fault with no handlers
        core::arch::asm!("int3", options(nostack));
    }

    // Should never reach here
    loop {
        core::hint::spin_loop();
    }
}

/// Read TSC for timestamps
#[inline]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

// ============================================================================
// Wake Sources
// ============================================================================

/// Enable wake from RTC alarm
pub fn power_enable_rtc_wake(_hour: u8, _minute: u8, _second: u8) -> bool {
    // Would configure CMOS alarm and enable wake
    false
}

/// Disable RTC wake
pub fn power_disable_rtc_wake() {
    // Would disable CMOS alarm wake
}

/// Get last wake source
pub fn power_get_last_wake_source() -> Option<WakeSource> {
    match LAST_WAKE_SOURCE.load(Ordering::Relaxed) {
        0 => None,
        1 => Some(WakeSource::PowerButton),
        2 => Some(WakeSource::SleepButton),
        3 => Some(WakeSource::RtcAlarm),
        4 => Some(WakeSource::Keyboard),
        5 => Some(WakeSource::Mouse),
        6 => Some(WakeSource::Lan),
        7 => Some(WakeSource::Usb),
        8 => Some(WakeSource::Pci),
        _ => Some(WakeSource::Unknown),
    }
}

// ============================================================================
// Query Functions
// ============================================================================

/// Get power state information
pub fn power_get_state_info() -> PowerStateInfo {
    PowerStateInfo {
        current_state: power_get_current_state(),
        target_state: power_get_current_state(),
        transition_in_progress: TRANSITION_IN_PROGRESS.load(Ordering::Relaxed),
        last_wake_source: power_get_last_wake_source(),
        last_sleep_time: LAST_SLEEP_TIME.load(Ordering::Relaxed),
        last_wake_time: LAST_WAKE_TIME.load(Ordering::Relaxed),
    }
}

/// Check if power management is initialized
pub fn power_is_initialized() -> bool {
    POWER_INITIALIZED.load(Ordering::Acquire)
}

/// Check if ACPI is available
pub fn power_is_acpi_available() -> bool {
    ACPI_AVAILABLE.load(Ordering::Relaxed)
}

// ============================================================================
// Statistics
// ============================================================================

/// Power statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct PowerStats {
    pub initialized: bool,
    pub acpi_available: bool,
    pub current_state: SleepState,
    pub sleep_support: SleepSupport,
    pub sleep_count: u64,
    pub wake_count: u64,
    pub shutdown_count: u64,
    pub last_sleep_time: u64,
    pub last_wake_time: u64,
}

/// Get power statistics
pub fn power_get_stats() -> PowerStats {
    PowerStats {
        initialized: POWER_INITIALIZED.load(Ordering::Relaxed),
        acpi_available: ACPI_AVAILABLE.load(Ordering::Relaxed),
        current_state: power_get_current_state(),
        sleep_support: power_get_sleep_support(),
        sleep_count: SLEEP_COUNT.load(Ordering::Relaxed),
        wake_count: WAKE_COUNT.load(Ordering::Relaxed),
        shutdown_count: SHUTDOWN_COUNT.load(Ordering::Relaxed),
        last_sleep_time: LAST_SLEEP_TIME.load(Ordering::Relaxed),
        last_wake_time: LAST_WAKE_TIME.load(Ordering::Relaxed),
    }
}

// ============================================================================
// NT Compatibility
// ============================================================================

/// HalSystemShutdown equivalent
pub fn hal_system_shutdown(restart: bool) -> ! {
    power_shutdown(restart)
}

/// HalReturnToFirmware equivalent
pub fn hal_return_to_firmware(action: u32) -> ! {
    match action {
        0 => power_shutdown(false),  // Power off
        1 => power_shutdown(true),   // Restart
        2 => power_shutdown(true),   // Reboot to firmware (restart for now)
        _ => power_shutdown(false),
    }
}

/// NtSetSystemPowerState equivalent
pub fn nt_set_system_power_state(state: u32) -> bool {
    let sleep_state = match state {
        0 => SleepState::S0,
        1 => SleepState::S1,
        2 => SleepState::S2,
        3 => SleepState::S3,
        4 => SleepState::S4,
        5 => SleepState::S5,
        _ => return false,
    };

    power_enter_sleep_state(sleep_state)
}
