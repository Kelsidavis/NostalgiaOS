//! Power IRP Verification
//!
//! Verifies Power IRP handling by drivers to detect common errors:
//! - Invalid initial IRP status
//! - Incorrect power state transitions
//! - Missing PoStartNextPowerIrp calls
//!
//! Based on Windows Server 2003 base/ntos/verifier/vfpower.c

use super::{vf_increment_stat, vf_is_option_enabled, vf_report_violation, VerifierBugcheck, VerifierOptions, VerifierStat};
use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

extern crate alloc;

// Power IRP minor function codes
pub const IRP_MN_WAIT_WAKE: u8 = 0x00;
pub const IRP_MN_POWER_SEQUENCE: u8 = 0x01;
pub const IRP_MN_SET_POWER: u8 = 0x02;
pub const IRP_MN_QUERY_POWER: u8 = 0x03;

/// Get Power IRP minor function name
pub fn power_irp_name(minor_function: u8) -> &'static str {
    match minor_function {
        IRP_MN_WAIT_WAKE => "IRP_MN_WAIT_WAKE",
        IRP_MN_POWER_SEQUENCE => "IRP_MN_POWER_SEQUENCE",
        IRP_MN_SET_POWER => "IRP_MN_SET_POWER",
        IRP_MN_QUERY_POWER => "IRP_MN_QUERY_POWER",
        _ => "UNKNOWN_POWER_IRP",
    }
}

/// System power states
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemPowerState {
    Unspecified = 0,
    Working = 1,    // S0
    Sleeping1 = 2,  // S1
    Sleeping2 = 3,  // S2
    Sleeping3 = 4,  // S3
    Hibernate = 5,  // S4
    Shutdown = 6,   // S5
}

impl SystemPowerState {
    pub fn name(self) -> &'static str {
        match self {
            SystemPowerState::Unspecified => "PowerSystemUnspecified",
            SystemPowerState::Working => "PowerSystemWorking.S0",
            SystemPowerState::Sleeping1 => "PowerSystemSleeping1.S1",
            SystemPowerState::Sleeping2 => "PowerSystemSleeping2.S2",
            SystemPowerState::Sleeping3 => "PowerSystemSleeping3.S3",
            SystemPowerState::Hibernate => "PowerSystemHibernate.S4",
            SystemPowerState::Shutdown => "PowerSystemShutdown.S5",
        }
    }

    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(SystemPowerState::Unspecified),
            1 => Some(SystemPowerState::Working),
            2 => Some(SystemPowerState::Sleeping1),
            3 => Some(SystemPowerState::Sleeping2),
            4 => Some(SystemPowerState::Sleeping3),
            5 => Some(SystemPowerState::Hibernate),
            6 => Some(SystemPowerState::Shutdown),
            _ => None,
        }
    }
}

/// Device power states
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DevicePowerState {
    Unspecified = 0,
    D0 = 1, // Full power
    D1 = 2, // Light sleep
    D2 = 3, // Medium sleep
    D3 = 4, // Off
}

impl DevicePowerState {
    pub fn name(self) -> &'static str {
        match self {
            DevicePowerState::Unspecified => "PowerDeviceUnspecified",
            DevicePowerState::D0 => "PowerDeviceD0",
            DevicePowerState::D1 => "PowerDeviceD1",
            DevicePowerState::D2 => "PowerDeviceD2",
            DevicePowerState::D3 => "PowerDeviceD3",
        }
    }

    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(DevicePowerState::Unspecified),
            1 => Some(DevicePowerState::D0),
            2 => Some(DevicePowerState::D1),
            3 => Some(DevicePowerState::D2),
            4 => Some(DevicePowerState::D3),
            _ => None,
        }
    }
}

/// Power action types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerAction {
    None = 0,
    Reserved = 1,
    Sleep = 2,
    Hibernate = 3,
    Shutdown = 4,
    ShutdownReset = 5,
    ShutdownOff = 6,
    WarmEject = 7,
}

impl PowerAction {
    pub fn name(self) -> &'static str {
        match self {
            PowerAction::None => "PowerActionNone",
            PowerAction::Reserved => "PowerActionReserved",
            PowerAction::Sleep => "PowerActionSleep",
            PowerAction::Hibernate => "PowerActionHibernate",
            PowerAction::Shutdown => "PowerActionShutdown",
            PowerAction::ShutdownReset => "PowerActionShutdownReset",
            PowerAction::ShutdownOff => "PowerActionShutdownOff",
            PowerAction::WarmEject => "PowerActionWarmEject",
        }
    }
}

/// Power IRP tracking entry
#[derive(Debug, Clone)]
pub struct TrackedPowerIrp {
    /// IRP address
    pub irp_address: usize,
    /// Device object address
    pub device_object: usize,
    /// Minor function
    pub minor_function: u8,
    /// Is system power IRP
    pub is_system_power: bool,
    /// Target power state
    pub target_state: u32,
    /// Initial status
    pub initial_status: i32,
    /// Final status
    pub final_status: i32,
    /// Timestamp
    pub timestamp: u64,
    /// PoStartNextPowerIrp was called
    pub start_next_called: bool,
    /// Completed
    pub completed: bool,
}

/// Power verifier state
#[derive(Debug)]
pub struct PowerVerifierState {
    /// Device power states by device object address
    device_states: BTreeMap<usize, DevicePowerState>,
    /// System power state
    system_state: SystemPowerState,
    /// Tracked Power IRPs
    tracked_irps: Vec<TrackedPowerIrp>,
    /// Maximum IRPs to track
    max_tracked_irps: usize,
    /// Total Power IRPs verified
    pub total_irps: u64,
    /// Violations detected
    pub violations: u64,
    /// Missing PoStartNextPowerIrp calls
    pub missing_start_next: u64,
}

impl PowerVerifierState {
    pub const fn new() -> Self {
        Self {
            device_states: BTreeMap::new(),
            system_state: SystemPowerState::Working,
            tracked_irps: Vec::new(),
            max_tracked_irps: 128,
            total_irps: 0,
            violations: 0,
            missing_start_next: 0,
        }
    }
}

/// Global Power verifier state
static mut POWER_VERIFIER_STATE: Option<SpinLock<PowerVerifierState>> = None;

fn get_power_state() -> &'static SpinLock<PowerVerifierState> {
    unsafe {
        POWER_VERIFIER_STATE
            .as_ref()
            .expect("Power verifier not initialized")
    }
}

/// Initialize Power verification
pub fn vf_power_init() {
    unsafe {
        POWER_VERIFIER_STATE = Some(SpinLock::new(PowerVerifierState::new()));
    }
    crate::serial_println!("[VERIFIER] Power verification initialized");
}

/// Verify a new Power IRP
pub fn vf_power_verify_new_request(
    irp_address: usize,
    device_object: usize,
    minor_function: u8,
    is_system_power: bool,
    target_state: u32,
    initial_status: i32,
    driver_name: &str,
) {
    if !vf_is_option_enabled(VerifierOptions::MONITOR_MAJORS) {
        return;
    }

    let state = get_power_state();
    let mut guard = state.lock();

    guard.total_irps += 1;

    // STATUS_NOT_SUPPORTED is the correct initial status for Power IRPs
    const STATUS_NOT_SUPPORTED: i32 = -1073741637i32;

    // Check initial status
    if initial_status != STATUS_NOT_SUPPORTED {
        guard.violations += 1;
        vf_report_violation(
            VerifierBugcheck::DriverVerifierDetectedViolation,
            driver_name,
            irp_address,
            device_object,
            minor_function as usize,
            0x4001, // Power IRP bad initial status
        );
    }

    // Track the IRP
    let tracked = TrackedPowerIrp {
        irp_address,
        device_object,
        minor_function,
        is_system_power,
        target_state,
        initial_status,
        final_status: initial_status,
        timestamp: unsafe { core::arch::x86_64::_rdtsc() },
        start_next_called: false,
        completed: false,
    };

    if guard.tracked_irps.len() >= guard.max_tracked_irps {
        guard.tracked_irps.remove(0);
    }
    guard.tracked_irps.push(tracked);
}

/// Verify Power IRP completion
pub fn vf_power_verify_completion(
    irp_address: usize,
    device_object: usize,
    minor_function: u8,
    is_system_power: bool,
    target_state: u32,
    final_status: i32,
    driver_name: &str,
) {
    if !vf_is_option_enabled(VerifierOptions::MONITOR_MAJORS) {
        return;
    }

    let state = get_power_state();
    let mut guard = state.lock();

    // Update power states on successful SET_POWER
    if minor_function == IRP_MN_SET_POWER && final_status >= 0 {
        if is_system_power {
            if let Some(new_state) = SystemPowerState::from_u32(target_state) {
                guard.system_state = new_state;
            }
        } else {
            if let Some(new_state) = DevicePowerState::from_u32(target_state) {
                guard.device_states.insert(device_object, new_state);
            }
        }
    }

    // Update tracked IRP
    for irp in &mut guard.tracked_irps {
        if irp.irp_address == irp_address && !irp.completed {
            irp.final_status = final_status;
            irp.completed = true;

            // Check if PoStartNextPowerIrp was called
            if !irp.start_next_called {
                guard.missing_start_next += 1;
                crate::serial_println!(
                    "[VERIFIER] Warning: Power IRP completed without PoStartNextPowerIrp in {}",
                    driver_name
                );
            }
            break;
        }
    }
}

/// Record PoStartNextPowerIrp call
pub fn vf_power_start_next_called(irp_address: usize) {
    let state = get_power_state();
    let mut guard = state.lock();

    for irp in &mut guard.tracked_irps {
        if irp.irp_address == irp_address && !irp.completed {
            irp.start_next_called = true;
            break;
        }
    }
}

/// Get device power state
pub fn vf_power_get_device_state(device_object: usize) -> DevicePowerState {
    let state = get_power_state();
    let guard = state.lock();

    guard.device_states.get(&device_object).copied().unwrap_or(DevicePowerState::D0)
}

/// Get system power state
pub fn vf_power_get_system_state() -> SystemPowerState {
    let state = get_power_state();
    let guard = state.lock();

    guard.system_state
}

/// Get Power verification statistics
pub fn vf_power_get_stats() -> (u64, u64, u64) {
    let state = get_power_state();
    let guard = state.lock();

    (guard.total_irps, guard.violations, guard.missing_start_next)
}

/// Validate power state transition
pub fn vf_power_validate_transition(
    device_object: usize,
    is_system: bool,
    current_state: u32,
    new_state: u32,
    driver_name: &str,
) -> bool {
    // For system power: transitions should be from Working to lower, or back to Working
    // For device power: similar constraints, with D0 being fully on

    if is_system {
        let from = SystemPowerState::from_u32(current_state);
        let to = SystemPowerState::from_u32(new_state);

        if let (Some(from), Some(to)) = (from, to) {
            // Can always go to Working (wake)
            if matches!(to, SystemPowerState::Working) {
                return true;
            }
            // From Working can go anywhere
            if matches!(from, SystemPowerState::Working) {
                return true;
            }
            // Otherwise should be transitioning through states
            crate::serial_println!(
                "[VERIFIER] Unusual system power transition: {} -> {} in {}",
                from.name(),
                to.name(),
                driver_name
            );
        }
    } else {
        let from = DevicePowerState::from_u32(current_state);
        let to = DevicePowerState::from_u32(new_state);

        if let (Some(from), Some(to)) = (from, to) {
            // Can always go to D0 (power up) or D3 (power down)
            if matches!(to, DevicePowerState::D0 | DevicePowerState::D3) {
                return true;
            }
            // From D0 can go anywhere
            if matches!(from, DevicePowerState::D0) {
                return true;
            }
        }
    }

    true // Default to allowing the transition
}
