//! PnP IRP Verification
//!
//! Verifies Plug and Play IRP handling by drivers to detect common errors:
//! - Invalid initial IRP status
//! - Incorrect handling of device states
//! - Missing or improper handling of required PnP IRPs
//!
//! Based on Windows Server 2003 base/ntos/verifier/vfpnp.c

use super::{vf_increment_stat, vf_is_option_enabled, vf_report_violation, VerifierBugcheck, VerifierOptions, VerifierStat};
use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

extern crate alloc;

// PnP IRP minor function codes
pub const IRP_MN_START_DEVICE: u8 = 0x00;
pub const IRP_MN_QUERY_REMOVE_DEVICE: u8 = 0x01;
pub const IRP_MN_REMOVE_DEVICE: u8 = 0x02;
pub const IRP_MN_CANCEL_REMOVE_DEVICE: u8 = 0x03;
pub const IRP_MN_STOP_DEVICE: u8 = 0x04;
pub const IRP_MN_QUERY_STOP_DEVICE: u8 = 0x05;
pub const IRP_MN_CANCEL_STOP_DEVICE: u8 = 0x06;
pub const IRP_MN_QUERY_DEVICE_RELATIONS: u8 = 0x07;
pub const IRP_MN_QUERY_INTERFACE: u8 = 0x08;
pub const IRP_MN_QUERY_CAPABILITIES: u8 = 0x09;
pub const IRP_MN_QUERY_RESOURCES: u8 = 0x0A;
pub const IRP_MN_QUERY_RESOURCE_REQUIREMENTS: u8 = 0x0B;
pub const IRP_MN_QUERY_DEVICE_TEXT: u8 = 0x0C;
pub const IRP_MN_FILTER_RESOURCE_REQUIREMENTS: u8 = 0x0D;
pub const IRP_MN_READ_CONFIG: u8 = 0x0F;
pub const IRP_MN_WRITE_CONFIG: u8 = 0x10;
pub const IRP_MN_EJECT: u8 = 0x11;
pub const IRP_MN_SET_LOCK: u8 = 0x12;
pub const IRP_MN_QUERY_ID: u8 = 0x13;
pub const IRP_MN_QUERY_PNP_DEVICE_STATE: u8 = 0x14;
pub const IRP_MN_QUERY_BUS_INFORMATION: u8 = 0x15;
pub const IRP_MN_DEVICE_USAGE_NOTIFICATION: u8 = 0x16;
pub const IRP_MN_SURPRISE_REMOVAL: u8 = 0x17;
pub const IRP_MN_QUERY_LEGACY_BUS_INFORMATION: u8 = 0x18;

/// Get PnP IRP minor function name
pub fn pnp_irp_name(minor_function: u8) -> &'static str {
    match minor_function {
        IRP_MN_START_DEVICE => "IRP_MN_START_DEVICE",
        IRP_MN_QUERY_REMOVE_DEVICE => "IRP_MN_QUERY_REMOVE_DEVICE",
        IRP_MN_REMOVE_DEVICE => "IRP_MN_REMOVE_DEVICE",
        IRP_MN_CANCEL_REMOVE_DEVICE => "IRP_MN_CANCEL_REMOVE_DEVICE",
        IRP_MN_STOP_DEVICE => "IRP_MN_STOP_DEVICE",
        IRP_MN_QUERY_STOP_DEVICE => "IRP_MN_QUERY_STOP_DEVICE",
        IRP_MN_CANCEL_STOP_DEVICE => "IRP_MN_CANCEL_STOP_DEVICE",
        IRP_MN_QUERY_DEVICE_RELATIONS => "IRP_MN_QUERY_DEVICE_RELATIONS",
        IRP_MN_QUERY_INTERFACE => "IRP_MN_QUERY_INTERFACE",
        IRP_MN_QUERY_CAPABILITIES => "IRP_MN_QUERY_CAPABILITIES",
        IRP_MN_QUERY_RESOURCES => "IRP_MN_QUERY_RESOURCES",
        IRP_MN_QUERY_RESOURCE_REQUIREMENTS => "IRP_MN_QUERY_RESOURCE_REQUIREMENTS",
        IRP_MN_QUERY_DEVICE_TEXT => "IRP_MN_QUERY_DEVICE_TEXT",
        IRP_MN_FILTER_RESOURCE_REQUIREMENTS => "IRP_MN_FILTER_RESOURCE_REQUIREMENTS",
        IRP_MN_READ_CONFIG => "IRP_MN_READ_CONFIG",
        IRP_MN_WRITE_CONFIG => "IRP_MN_WRITE_CONFIG",
        IRP_MN_EJECT => "IRP_MN_EJECT",
        IRP_MN_SET_LOCK => "IRP_MN_SET_LOCK",
        IRP_MN_QUERY_ID => "IRP_MN_QUERY_ID",
        IRP_MN_QUERY_PNP_DEVICE_STATE => "IRP_MN_QUERY_PNP_DEVICE_STATE",
        IRP_MN_QUERY_BUS_INFORMATION => "IRP_MN_QUERY_BUS_INFORMATION",
        IRP_MN_DEVICE_USAGE_NOTIFICATION => "IRP_MN_DEVICE_USAGE_NOTIFICATION",
        IRP_MN_SURPRISE_REMOVAL => "IRP_MN_SURPRISE_REMOVAL",
        IRP_MN_QUERY_LEGACY_BUS_INFORMATION => "IRP_MN_QUERY_LEGACY_BUS_INFORMATION",
        _ => "UNKNOWN_PNP_IRP",
    }
}

/// PnP device state for verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnpDeviceState {
    /// Device not started
    NotStarted,
    /// Start pending
    StartPending,
    /// Device started
    Started,
    /// Stop pending
    StopPending,
    /// Device stopped
    Stopped,
    /// Remove pending
    RemovePending,
    /// Surprise removal occurred
    SurpriseRemoved,
    /// Device removed
    Removed,
}

impl Default for PnpDeviceState {
    fn default() -> Self {
        Self::NotStarted
    }
}

/// PnP IRP tracking entry
#[derive(Debug, Clone)]
pub struct TrackedPnpIrp {
    /// IRP address
    pub irp_address: usize,
    /// Device object address
    pub device_object: usize,
    /// Minor function
    pub minor_function: u8,
    /// Initial status
    pub initial_status: i32,
    /// Final status
    pub final_status: i32,
    /// Timestamp
    pub timestamp: u64,
    /// Was properly forwarded
    pub was_forwarded: bool,
    /// Completion state
    pub completed: bool,
}

/// PnP verifier state
#[derive(Debug)]
pub struct PnpVerifierState {
    /// Device states by device object address
    device_states: BTreeMap<usize, PnpDeviceState>,
    /// Tracked PnP IRPs
    tracked_irps: Vec<TrackedPnpIrp>,
    /// Maximum IRPs to track
    max_tracked_irps: usize,
    /// Total PnP IRPs verified
    pub total_irps: u64,
    /// Violations detected
    pub violations: u64,
}

impl PnpVerifierState {
    pub const fn new() -> Self {
        Self {
            device_states: BTreeMap::new(),
            tracked_irps: Vec::new(),
            max_tracked_irps: 256,
            total_irps: 0,
            violations: 0,
        }
    }
}

/// Global PnP verifier state
static mut PNP_VERIFIER_STATE: Option<SpinLock<PnpVerifierState>> = None;

fn get_pnp_state() -> &'static SpinLock<PnpVerifierState> {
    unsafe {
        PNP_VERIFIER_STATE
            .as_ref()
            .expect("PnP verifier not initialized")
    }
}

/// Initialize PnP verification
pub fn vf_pnp_init() {
    unsafe {
        PNP_VERIFIER_STATE = Some(SpinLock::new(PnpVerifierState::new()));
    }
    crate::serial_println!("[VERIFIER] PnP verification initialized");
}

/// Verify a new PnP IRP
pub fn vf_pnp_verify_new_request(
    irp_address: usize,
    device_object: usize,
    minor_function: u8,
    initial_status: i32,
    driver_name: &str,
) {
    if !vf_is_option_enabled(VerifierOptions::MONITOR_MAJORS) {
        return;
    }

    let state = get_pnp_state();
    let mut guard = state.lock();

    guard.total_irps += 1;

    // STATUS_NOT_SUPPORTED is the correct initial status for PnP IRPs
    const STATUS_NOT_SUPPORTED: i32 = -1073741637i32; // 0xC00000BB

    // Check initial status
    if initial_status != STATUS_NOT_SUPPORTED {
        // IRP_MN_FILTER_RESOURCE_REQUIREMENTS is an exception
        if minor_function != IRP_MN_FILTER_RESOURCE_REQUIREMENTS {
            guard.violations += 1;
            vf_report_violation(
                VerifierBugcheck::DriverVerifierDetectedViolation,
                driver_name,
                irp_address,
                device_object,
                minor_function as usize,
                0x3001, // PnP IRP bad initial status
            );
        }
    }

    // Track the IRP
    let tracked = TrackedPnpIrp {
        irp_address,
        device_object,
        minor_function,
        initial_status,
        final_status: initial_status,
        timestamp: unsafe { core::arch::x86_64::_rdtsc() },
        was_forwarded: false,
        completed: false,
    };

    if guard.tracked_irps.len() >= guard.max_tracked_irps {
        guard.tracked_irps.remove(0);
    }
    guard.tracked_irps.push(tracked);
}

/// Verify PnP IRP completion
pub fn vf_pnp_verify_completion(
    irp_address: usize,
    device_object: usize,
    minor_function: u8,
    final_status: i32,
    driver_name: &str,
) {
    if !vf_is_option_enabled(VerifierOptions::MONITOR_MAJORS) {
        return;
    }

    let state = get_pnp_state();
    let mut guard = state.lock();

    // Update device state based on completed IRP
    match minor_function {
        IRP_MN_START_DEVICE => {
            if final_status >= 0 { // NT_SUCCESS
                guard.device_states.insert(device_object, PnpDeviceState::Started);
            }
        }
        IRP_MN_STOP_DEVICE => {
            guard.device_states.insert(device_object, PnpDeviceState::Stopped);
        }
        IRP_MN_REMOVE_DEVICE => {
            guard.device_states.insert(device_object, PnpDeviceState::Removed);
        }
        IRP_MN_SURPRISE_REMOVAL => {
            guard.device_states.insert(device_object, PnpDeviceState::SurpriseRemoved);
        }
        IRP_MN_QUERY_REMOVE_DEVICE => {
            if final_status >= 0 {
                guard.device_states.insert(device_object, PnpDeviceState::RemovePending);
            }
        }
        IRP_MN_CANCEL_REMOVE_DEVICE => {
            // Should return to started state
            guard.device_states.insert(device_object, PnpDeviceState::Started);
        }
        IRP_MN_QUERY_STOP_DEVICE => {
            if final_status >= 0 {
                guard.device_states.insert(device_object, PnpDeviceState::StopPending);
            }
        }
        IRP_MN_CANCEL_STOP_DEVICE => {
            // Should return to started state
            guard.device_states.insert(device_object, PnpDeviceState::Started);
        }
        _ => {}
    }

    // Update tracked IRP
    for irp in &mut guard.tracked_irps {
        if irp.irp_address == irp_address && !irp.completed {
            irp.final_status = final_status;
            irp.completed = true;
            break;
        }
    }
}

/// Get device PnP state
pub fn vf_pnp_get_device_state(device_object: usize) -> PnpDeviceState {
    let state = get_pnp_state();
    let guard = state.lock();

    guard.device_states.get(&device_object).copied().unwrap_or_default()
}

/// Get PnP verification statistics
pub fn vf_pnp_get_stats() -> (u64, u64, usize) {
    let state = get_pnp_state();
    let guard = state.lock();

    (guard.total_irps, guard.violations, guard.device_states.len())
}

/// Check if device is in valid state for IRP
pub fn vf_pnp_validate_irp_for_state(
    device_object: usize,
    minor_function: u8,
    driver_name: &str,
) -> bool {
    let state = get_pnp_state();
    let guard = state.lock();

    let device_state = guard.device_states.get(&device_object).copied().unwrap_or_default();

    let valid = match minor_function {
        IRP_MN_START_DEVICE => {
            // Must be NotStarted or Stopped
            matches!(device_state, PnpDeviceState::NotStarted | PnpDeviceState::Stopped)
        }
        IRP_MN_REMOVE_DEVICE => {
            // Should not be already removed
            !matches!(device_state, PnpDeviceState::Removed)
        }
        IRP_MN_STOP_DEVICE => {
            // Must be in StopPending state
            matches!(device_state, PnpDeviceState::StopPending)
        }
        IRP_MN_CANCEL_REMOVE_DEVICE => {
            // Must be in RemovePending state
            matches!(device_state, PnpDeviceState::RemovePending)
        }
        IRP_MN_CANCEL_STOP_DEVICE => {
            // Must be in StopPending state
            matches!(device_state, PnpDeviceState::StopPending)
        }
        _ => true, // Other IRPs can be sent in various states
    };

    if !valid {
        crate::serial_println!(
            "[VERIFIER] PnP state violation: {} sent to device in {:?} state",
            pnp_irp_name(minor_function),
            device_state
        );
    }

    valid
}
