//! IRP Verification
//!
//! Tracks and validates IRP handling by drivers.

use super::{vf_increment_stat, vf_is_option_enabled, vf_report_violation, VerifierBugcheck, VerifierOptions, VerifierStat};
use crate::etw::Guid;
use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

extern crate alloc;

/// IRP tracking entry
#[derive(Debug, Clone)]
pub struct TrackedIrp {
    /// IRP address
    pub irp_address: usize,
    /// Allocator address (return address)
    pub allocator: usize,
    /// Current owner device object
    pub current_device: usize,
    /// Major function code
    pub major_function: u8,
    /// Minor function code
    pub minor_function: u8,
    /// IRP flags
    pub irp_flags: u32,
    /// Stack location count
    pub stack_count: u8,
    /// Current stack location
    pub current_location: u8,
    /// Allocation timestamp (TSC)
    pub alloc_time: u64,
    /// IRP state
    pub state: IrpState,
    /// Call stack at allocation
    pub alloc_stack: [usize; 8],
    /// History of operations
    pub history: Vec<IrpHistoryEntry>,
}

impl TrackedIrp {
    pub fn new(irp_address: usize, stack_count: u8, allocator: usize) -> Self {
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        Self {
            irp_address,
            allocator,
            current_device: 0,
            major_function: 0,
            minor_function: 0,
            irp_flags: 0,
            stack_count,
            current_location: stack_count,
            alloc_time: tsc,
            state: IrpState::Allocated,
            alloc_stack: [0; 8],
            history: Vec::new(),
        }
    }
}

/// IRP state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrpState {
    /// Just allocated
    Allocated,
    /// Dispatched to driver
    Dispatched,
    /// Pending (IoMarkIrpPending called)
    Pending,
    /// Being completed
    Completing,
    /// Completed
    Completed,
    /// Freed
    Freed,
}

/// IRP history entry
#[derive(Debug, Clone)]
pub struct IrpHistoryEntry {
    /// Operation type
    pub operation: IrpOperation,
    /// Device object
    pub device_object: usize,
    /// Timestamp (TSC)
    pub timestamp: u64,
    /// IRQL at operation
    pub irql: u8,
    /// Additional info
    pub info: u64,
}

/// IRP operations to track
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrpOperation {
    /// IoAllocateIrp
    Allocate,
    /// IoCallDriver
    Call,
    /// IoCompleteRequest
    Complete,
    /// IoMarkIrpPending
    MarkPending,
    /// IoCopyCurrentIrpStackLocationToNext
    CopyStack,
    /// IoSkipCurrentIrpStackLocation
    SkipStack,
    /// IoSetCompletionRoutine
    SetCompletion,
    /// IoFreeIrp
    Free,
}

/// IRP verifier state
#[derive(Debug)]
pub struct IrpVerifierState {
    /// Tracked IRPs by address
    irps: BTreeMap<usize, TrackedIrp>,
    /// IRP allocation counter
    alloc_count: u64,
    /// IRP free counter
    free_count: u64,
    /// Maximum tracked IRPs
    max_tracked: usize,
}

impl IrpVerifierState {
    pub const fn new() -> Self {
        Self {
            irps: BTreeMap::new(),
            alloc_count: 0,
            free_count: 0,
            max_tracked: 65536,
        }
    }
}

/// Global IRP verifier state
static mut IRP_VERIFIER_STATE: Option<SpinLock<IrpVerifierState>> = None;

fn get_irp_state() -> &'static SpinLock<IrpVerifierState> {
    unsafe {
        IRP_VERIFIER_STATE
            .as_ref()
            .expect("IRP verifier not initialized")
    }
}

/// Initialize IRP verification
pub fn vf_irp_init() {
    unsafe {
        IRP_VERIFIER_STATE = Some(SpinLock::new(IrpVerifierState::new()));
    }
    crate::serial_println!("[VERIFIER] IRP verification initialized");
}

/// Track an IRP allocation
pub fn vf_irp_allocate(irp_address: usize, stack_count: u8, allocator: usize) {
    if !vf_is_option_enabled(VerifierOptions::TRACK_IRPS) {
        return;
    }

    let state = get_irp_state();
    let mut guard = state.lock();

    if guard.irps.len() >= guard.max_tracked {
        // Trim old entries if at limit
        return;
    }

    let mut tracked = TrackedIrp::new(irp_address, stack_count, allocator);

    // Record initial history
    tracked.history.push(IrpHistoryEntry {
        operation: IrpOperation::Allocate,
        device_object: 0,
        timestamp: tracked.alloc_time,
        irql: 0, // Would get actual IRQL
        info: 0,
    });

    guard.irps.insert(irp_address, tracked);
    guard.alloc_count += 1;

    vf_increment_stat(VerifierStat::IrpsTracked);
}

/// Track IoCallDriver
pub fn vf_irp_call_driver(irp_address: usize, device_object: usize, major: u8, minor: u8) {
    if !vf_is_option_enabled(VerifierOptions::TRACK_IRPS) {
        return;
    }

    let state = get_irp_state();
    let mut guard = state.lock();

    if let Some(tracked) = guard.irps.get_mut(&irp_address) {
        // Validate state transition
        match tracked.state {
            IrpState::Allocated | IrpState::Pending | IrpState::Dispatched => {
                // Valid transitions
            }
            IrpState::Completed | IrpState::Freed => {
                // Invalid: calling driver on completed/freed IRP
                vf_report_violation(
                    VerifierBugcheck::DriverVerifierDetectedViolation,
                    "unknown",
                    irp_address,
                    device_object,
                    tracked.state as usize,
                    0x1001, // Call on completed IRP
                );
                return;
            }
            _ => {}
        }

        tracked.state = IrpState::Dispatched;
        tracked.current_device = device_object;
        tracked.major_function = major;
        tracked.minor_function = minor;

        if tracked.current_location > 0 {
            tracked.current_location -= 1;
        }

        tracked.history.push(IrpHistoryEntry {
            operation: IrpOperation::Call,
            device_object,
            timestamp: unsafe { core::arch::x86_64::_rdtsc() },
            irql: 0,
            info: ((major as u64) << 8) | (minor as u64),
        });
    }
}

/// Track IoMarkIrpPending
pub fn vf_irp_mark_pending(irp_address: usize) {
    if !vf_is_option_enabled(VerifierOptions::TRACK_IRPS) {
        return;
    }

    let state = get_irp_state();
    let mut guard = state.lock();

    if let Some(tracked) = guard.irps.get_mut(&irp_address) {
        tracked.state = IrpState::Pending;
        tracked.irp_flags |= 0x01; // IRP_PENDING_RETURNED

        tracked.history.push(IrpHistoryEntry {
            operation: IrpOperation::MarkPending,
            device_object: tracked.current_device,
            timestamp: unsafe { core::arch::x86_64::_rdtsc() },
            irql: 0,
            info: 0,
        });
    }
}

/// Track IoCompleteRequest
pub fn vf_irp_complete(irp_address: usize, status: i32, priority_boost: u8) {
    if !vf_is_option_enabled(VerifierOptions::TRACK_IRPS) {
        return;
    }

    let state = get_irp_state();
    let mut guard = state.lock();

    if let Some(tracked) = guard.irps.get_mut(&irp_address) {
        // Validate state
        match tracked.state {
            IrpState::Freed => {
                vf_report_violation(
                    VerifierBugcheck::DriverVerifierDetectedViolation,
                    "unknown",
                    irp_address,
                    status as usize,
                    tracked.state as usize,
                    0x1002, // Complete on freed IRP
                );
                return;
            }
            IrpState::Completed => {
                vf_report_violation(
                    VerifierBugcheck::DriverVerifierDetectedViolation,
                    "unknown",
                    irp_address,
                    status as usize,
                    tracked.state as usize,
                    0x1003, // Double completion
                );
                return;
            }
            _ => {}
        }

        tracked.state = IrpState::Completed;

        tracked.history.push(IrpHistoryEntry {
            operation: IrpOperation::Complete,
            device_object: tracked.current_device,
            timestamp: unsafe { core::arch::x86_64::_rdtsc() },
            irql: 0,
            info: ((status as u64) << 8) | (priority_boost as u64),
        });

        vf_increment_stat(VerifierStat::IrpsCompleted);
    }
}

/// Track IoFreeIrp
pub fn vf_irp_free(irp_address: usize) {
    if !vf_is_option_enabled(VerifierOptions::TRACK_IRPS) {
        return;
    }

    let state = get_irp_state();
    let mut guard = state.lock();

    if let Some(tracked) = guard.irps.get_mut(&irp_address) {
        // Check if IRP was properly completed
        if tracked.state == IrpState::Dispatched {
            vf_report_violation(
                VerifierBugcheck::DriverVerifierDetectedViolation,
                "unknown",
                irp_address,
                tracked.current_device,
                tracked.state as usize,
                0x1004, // Free without completion
            );
        }

        tracked.state = IrpState::Freed;

        tracked.history.push(IrpHistoryEntry {
            operation: IrpOperation::Free,
            device_object: 0,
            timestamp: unsafe { core::arch::x86_64::_rdtsc() },
            irql: 0,
            info: 0,
        });

        guard.free_count += 1;
    }

    // Remove from tracking
    guard.irps.remove(&irp_address);
}

/// Check for IRP leaks (IRPs allocated but never freed)
pub fn vf_irp_check_leaks() -> Vec<TrackedIrp> {
    let state = get_irp_state();
    let guard = state.lock();

    guard
        .irps
        .values()
        .filter(|irp| irp.state != IrpState::Freed)
        .cloned()
        .collect()
}

/// Get IRP tracking statistics
pub fn vf_irp_get_stats() -> (u64, u64, usize) {
    let state = get_irp_state();
    let guard = state.lock();

    (guard.alloc_count, guard.free_count, guard.irps.len())
}

/// Validate IRP before dispatch
pub fn vf_irp_validate_before_call(
    irp_address: usize,
    device_object: usize,
    major: u8,
) -> Result<(), IrpValidationError> {
    if !vf_is_option_enabled(VerifierOptions::POLICE_IRPS) {
        return Ok(());
    }

    let state = get_irp_state();
    let guard = state.lock();

    if let Some(tracked) = guard.irps.get(&irp_address) {
        // Check for valid state
        if tracked.state == IrpState::Freed {
            return Err(IrpValidationError::UseAfterFree);
        }

        // Check stack location
        if tracked.current_location == 0 {
            return Err(IrpValidationError::StackOverflow);
        }
    }

    Ok(())
}

/// IRP validation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrpValidationError {
    /// IRP used after free
    UseAfterFree,
    /// IRP stack overflow
    StackOverflow,
    /// Invalid state transition
    InvalidStateTransition,
    /// Invalid major function
    InvalidMajorFunction,
    /// Wrong IRQL
    WrongIrql,
}

/// IRP major function codes for validation
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrpMajorFunction {
    Create = 0x00,
    CreateNamedPipe = 0x01,
    Close = 0x02,
    Read = 0x03,
    Write = 0x04,
    QueryInformation = 0x05,
    SetInformation = 0x06,
    QueryEa = 0x07,
    SetEa = 0x08,
    FlushBuffers = 0x09,
    QueryVolumeInformation = 0x0a,
    SetVolumeInformation = 0x0b,
    DirectoryControl = 0x0c,
    FileSystemControl = 0x0d,
    DeviceControl = 0x0e,
    InternalDeviceControl = 0x0f,
    Shutdown = 0x10,
    LockControl = 0x11,
    Cleanup = 0x12,
    CreateMailslot = 0x13,
    QuerySecurity = 0x14,
    SetSecurity = 0x15,
    Power = 0x16,
    SystemControl = 0x17,
    DeviceChange = 0x18,
    QueryQuota = 0x19,
    SetQuota = 0x1a,
    Pnp = 0x1b,
    MaximumFunction = 0x1c,
}

/// Get readable name for major function
pub fn vf_irp_major_name(major: u8) -> &'static str {
    match major {
        0x00 => "IRP_MJ_CREATE",
        0x01 => "IRP_MJ_CREATE_NAMED_PIPE",
        0x02 => "IRP_MJ_CLOSE",
        0x03 => "IRP_MJ_READ",
        0x04 => "IRP_MJ_WRITE",
        0x05 => "IRP_MJ_QUERY_INFORMATION",
        0x06 => "IRP_MJ_SET_INFORMATION",
        0x07 => "IRP_MJ_QUERY_EA",
        0x08 => "IRP_MJ_SET_EA",
        0x09 => "IRP_MJ_FLUSH_BUFFERS",
        0x0a => "IRP_MJ_QUERY_VOLUME_INFORMATION",
        0x0b => "IRP_MJ_SET_VOLUME_INFORMATION",
        0x0c => "IRP_MJ_DIRECTORY_CONTROL",
        0x0d => "IRP_MJ_FILE_SYSTEM_CONTROL",
        0x0e => "IRP_MJ_DEVICE_CONTROL",
        0x0f => "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        0x10 => "IRP_MJ_SHUTDOWN",
        0x11 => "IRP_MJ_LOCK_CONTROL",
        0x12 => "IRP_MJ_CLEANUP",
        0x13 => "IRP_MJ_CREATE_MAILSLOT",
        0x14 => "IRP_MJ_QUERY_SECURITY",
        0x15 => "IRP_MJ_SET_SECURITY",
        0x16 => "IRP_MJ_POWER",
        0x17 => "IRP_MJ_SYSTEM_CONTROL",
        0x18 => "IRP_MJ_DEVICE_CHANGE",
        0x19 => "IRP_MJ_QUERY_QUOTA",
        0x1a => "IRP_MJ_SET_QUOTA",
        0x1b => "IRP_MJ_PNP",
        _ => "IRP_MJ_UNKNOWN",
    }
}
