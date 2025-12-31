//! Driver Verifier Subsystem
//!
//! The Driver Verifier is a tool for finding bugs in kernel-mode drivers.
//! It monitors driver behavior and detects:
//! - Invalid IRP handling
//! - Pool allocation issues (leaks, corruptions)
//! - Deadlock scenarios
//! - IRQL violations
//! - DMA verification
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Driver Verifier                         │
//! ├─────────────┬─────────────┬─────────────┬─────────────────┤
//! │  Settings   │ IRP Verify  │ Pool Verify │ Deadlock Detect │
//! ├─────────────┼─────────────┼─────────────┼─────────────────┤
//! │   Options   │  Track IRPs │ Track Alloc │ Lock Graph      │
//! │   Flags     │  Validate   │ Guard Pages │ Cycle Detect    │
//! └─────────────┴─────────────┴─────────────┴─────────────────┘
//! ```
//!
//! Based on Windows Server 2003 base/ntos/verifier/

pub mod deadlock;
pub mod irp;
pub mod pnp;
pub mod pool;
pub mod power;
pub mod settings;
pub mod stack;

pub use deadlock::*;
pub use irp::*;
pub use pnp::*;
pub use pool::*;
pub use power::*;
pub use settings::*;
pub use stack::*;

use crate::ke::SpinLock;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

extern crate alloc;

/// Verifier initialized flag
static VERIFIER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Verifier enabled flag
static VERIFIER_ENABLED: AtomicBool = AtomicBool::new(false);

/// Global fault injection counter
static FAULT_INJECTION_COUNT: AtomicU64 = AtomicU64::new(0);

/// Driver Verifier global state
pub struct VerifierState {
    /// Current verifier settings
    settings: SpinLock<VerifierSettings>,
    /// List of drivers being verified
    verified_drivers: SpinLock<BTreeSet<String>>,
    /// Deadlock detection state
    deadlock_state: SpinLock<DeadlockState>,
    /// Pool tracking state
    pool_state: SpinLock<PoolVerifierState>,
    /// IRP tracking state
    irp_state: SpinLock<IrpVerifierState>,
    /// Statistics
    statistics: SpinLock<VerifierStatistics>,
}

impl VerifierState {
    pub const fn new() -> Self {
        Self {
            settings: SpinLock::new(VerifierSettings::new()),
            verified_drivers: SpinLock::new(BTreeSet::new()),
            deadlock_state: SpinLock::new(DeadlockState::new()),
            pool_state: SpinLock::new(PoolVerifierState::new()),
            irp_state: SpinLock::new(IrpVerifierState::new()),
            statistics: SpinLock::new(VerifierStatistics::new()),
        }
    }
}

static mut VERIFIER_STATE: Option<VerifierState> = None;

fn get_verifier_state() -> &'static VerifierState {
    unsafe { VERIFIER_STATE.as_ref().expect("Verifier not initialized") }
}

/// Initialize the Driver Verifier subsystem
pub fn vf_initialize(flags: VerifierFlags) -> bool {
    if VERIFIER_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return true; // Already initialized
    }

    unsafe {
        VERIFIER_STATE = Some(VerifierState::new());
    }

    let state = get_verifier_state();

    // Apply initial settings based on flags
    {
        let mut settings = state.settings.lock();
        settings.flags = flags;

        // Set default values
        settings.irp_deferral_time_us = 300;
        settings.irps_to_log_per_device = 20;

        // Enable options based on flags
        if flags.contains(VerifierFlags::IO_CHECKING) {
            settings.options |= VerifierOptions::TRACK_IRPS;
            settings.options |= VerifierOptions::MONITOR_IRP_ALLOCS;
            settings.options |= VerifierOptions::POLICE_IRPS;
            settings.options |= VerifierOptions::MONITOR_MAJORS;
        }

        if flags.contains(VerifierFlags::ENHANCED_IO_CHECKING) {
            settings.options |= VerifierOptions::MONITOR_PENDING_IO;
            settings.options |= VerifierOptions::MONITOR_REMOVES;
            settings.options |= VerifierOptions::SEED_STACK;
        }

        if flags.contains(VerifierFlags::DEADLOCK_DETECTION) {
            settings.options |= VerifierOptions::DETECT_DEADLOCKS;
        }

        if flags.contains(VerifierFlags::DMA_CHECKING) {
            settings.options |= VerifierOptions::VERIFY_DMA;
            settings.options |= VerifierOptions::DOUBLE_BUFFER_DMA;
        }

        if flags.contains(VerifierFlags::SPECIAL_POOL) {
            settings.options |= VerifierOptions::SPECIAL_POOL;
        }

        if flags.contains(VerifierFlags::POOL_TRACKING) {
            settings.options |= VerifierOptions::TRACK_POOL;
        }
    }

    // Initialize sub-components
    vf_irp_init();
    vf_pool_init();
    vf_deadlock_init();
    vf_pnp_init();
    vf_power_init();
    vf_stack_init();

    VERIFIER_ENABLED.store(flags.bits() != 0, Ordering::SeqCst);

    crate::serial_println!(
        "[VERIFIER] Driver Verifier initialized, flags={:?}",
        flags
    );

    true
}

/// Check if verifier is enabled
#[inline]
pub fn vf_is_enabled() -> bool {
    VERIFIER_ENABLED.load(Ordering::Relaxed)
}

/// Check if a specific option is enabled
pub fn vf_is_option_enabled(option: VerifierOptions) -> bool {
    if !vf_is_enabled() {
        return false;
    }

    let state = get_verifier_state();
    let settings = state.settings.lock();
    settings.options.contains(option)
}

/// Add a driver to the verification list
pub fn vf_add_driver(driver_name: &str) -> bool {
    if !VERIFIER_INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }

    let state = get_verifier_state();
    let mut drivers = state.verified_drivers.lock();
    let inserted = drivers.insert(String::from(driver_name));

    if inserted {
        crate::serial_println!("[VERIFIER] Added driver '{}' to verification", driver_name);
    }

    inserted
}

/// Remove a driver from the verification list
pub fn vf_remove_driver(driver_name: &str) -> bool {
    if !VERIFIER_INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }

    let state = get_verifier_state();
    let mut drivers = state.verified_drivers.lock();
    drivers.remove(driver_name)
}

/// Check if a driver is being verified
pub fn vf_is_driver_verified(driver_name: &str) -> bool {
    if !vf_is_enabled() {
        return false;
    }

    let state = get_verifier_state();
    let drivers = state.verified_drivers.lock();

    // If no specific drivers, verify all
    if drivers.is_empty() {
        return true;
    }

    drivers.contains(driver_name)
}

/// Get verification statistics
pub fn vf_get_statistics() -> VerifierStatistics {
    if !VERIFIER_INITIALIZED.load(Ordering::SeqCst) {
        return VerifierStatistics::new();
    }

    let state = get_verifier_state();
    state.statistics.lock().clone()
}

/// Increment a statistic counter
pub fn vf_increment_stat(stat: VerifierStat) {
    if !vf_is_enabled() {
        return;
    }

    let state = get_verifier_state();
    let mut stats = state.statistics.lock();

    match stat {
        VerifierStat::IrpsTracked => stats.irps_tracked += 1,
        VerifierStat::IrpsCompleted => stats.irps_completed += 1,
        VerifierStat::IrpViolations => stats.irp_violations += 1,
        VerifierStat::PoolAllocations => stats.pool_allocations += 1,
        VerifierStat::PoolFrees => stats.pool_frees += 1,
        VerifierStat::PoolViolations => stats.pool_violations += 1,
        VerifierStat::DeadlockChecks => stats.deadlock_checks += 1,
        VerifierStat::DeadlockDetections => stats.deadlock_detections += 1,
        VerifierStat::FaultInjections => stats.fault_injections += 1,
    }
}

/// Verifier statistics
#[derive(Debug, Clone, Default)]
pub struct VerifierStatistics {
    /// Number of IRPs tracked
    pub irps_tracked: u64,
    /// Number of IRPs completed
    pub irps_completed: u64,
    /// Number of IRP violations detected
    pub irp_violations: u64,
    /// Number of pool allocations tracked
    pub pool_allocations: u64,
    /// Number of pool frees tracked
    pub pool_frees: u64,
    /// Number of pool violations detected
    pub pool_violations: u64,
    /// Number of deadlock checks performed
    pub deadlock_checks: u64,
    /// Number of deadlocks detected
    pub deadlock_detections: u64,
    /// Number of fault injections performed
    pub fault_injections: u64,
}

impl VerifierStatistics {
    pub const fn new() -> Self {
        Self {
            irps_tracked: 0,
            irps_completed: 0,
            irp_violations: 0,
            pool_allocations: 0,
            pool_frees: 0,
            pool_violations: 0,
            deadlock_checks: 0,
            deadlock_detections: 0,
            fault_injections: 0,
        }
    }
}

/// Statistics to increment
#[derive(Debug, Clone, Copy)]
pub enum VerifierStat {
    IrpsTracked,
    IrpsCompleted,
    IrpViolations,
    PoolAllocations,
    PoolFrees,
    PoolViolations,
    DeadlockChecks,
    DeadlockDetections,
    FaultInjections,
}

/// Verifier bugcheck codes
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierBugcheck {
    /// Driver accessed freed pool
    DriverAccessedFreedPool = 0x000000C1,
    /// Driver overran stack buffer
    DriverOverranStackBuffer = 0x000000F7,
    /// Driver caught modifying freed pool
    DriverCaughtModifyingFreedPool = 0x000000C6,
    /// IRP completion routine returned at wrong IRQL
    IrqlNotLessOrEqual = 0x0000000A,
    /// Driver verifier detected violation
    DriverVerifierDetectedViolation = 0x000000C4,
    /// Driver unloaded without cancelling pending operations
    DriverUnloadedWithoutCancellingPendingOperations = 0x000000CE,
    /// Deadlock detected
    DeadlockDetected = 0x000000EF,
    /// Timer or DPC invalid
    TimerOrDpcInvalid = 0x000000C7,
}

/// Report a verifier violation (may bugcheck)
pub fn vf_report_violation(
    bugcheck: VerifierBugcheck,
    driver_name: &str,
    param1: usize,
    param2: usize,
    param3: usize,
    param4: usize,
) {
    crate::serial_println!(
        "[VERIFIER] VIOLATION: {:?} in driver '{}'\n\
         Parameters: {:#x}, {:#x}, {:#x}, {:#x}",
        bugcheck,
        driver_name,
        param1,
        param2,
        param3,
        param4
    );

    // In a real implementation, this would trigger a bugcheck
    // For now, we log and continue (could be configured)

    vf_increment_stat(match bugcheck {
        VerifierBugcheck::DriverAccessedFreedPool
        | VerifierBugcheck::DriverCaughtModifyingFreedPool => VerifierStat::PoolViolations,
        VerifierBugcheck::DeadlockDetected => VerifierStat::DeadlockDetections,
        _ => VerifierStat::IrpViolations,
    });
}

/// Fault injection - randomly fail allocations for stress testing
pub fn vf_should_fail_allocation() -> bool {
    if !vf_is_option_enabled(VerifierOptions::FAULT_INJECTION) {
        return false;
    }

    let state = get_verifier_state();
    let settings = state.settings.lock();

    if settings.fault_injection_probability == 0 {
        return false;
    }

    // Simple pseudo-random based on counter
    let count = FAULT_INJECTION_COUNT.fetch_add(1, Ordering::Relaxed);
    let should_fail = (count % 100) < settings.fault_injection_probability as u64;

    if should_fail {
        vf_increment_stat(VerifierStat::FaultInjections);
    }

    should_fail
}

/// Get list of verified drivers
pub fn vf_get_verified_drivers() -> Vec<String> {
    if !VERIFIER_INITIALIZED.load(Ordering::SeqCst) {
        return Vec::new();
    }

    let state = get_verifier_state();
    let drivers = state.verified_drivers.lock();
    drivers.iter().cloned().collect()
}

/// Set verifier option at runtime
pub fn vf_set_option(option: VerifierOptions, enabled: bool) {
    if !VERIFIER_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }

    let state = get_verifier_state();
    let mut settings = state.settings.lock();

    if enabled {
        settings.options |= option;
    } else {
        settings.options.remove(option);
    }
}
