//! Executive Exception Raising
//!
//! Provides functions to raise common exception types. These functions
//! are primarily used by the probe macros to report errors when probing
//! user-mode pointers.
//!
//! # NT Functions
//!
//! - `ExRaiseStatus` - Raise an exception with a status code
//! - `ExRaiseAccessViolation` - Raise STATUS_ACCESS_VIOLATION
//! - `ExRaiseDatatypeMisalignment` - Raise STATUS_DATATYPE_MISALIGNMENT

use core::sync::atomic::{AtomicU64, Ordering};

// NTSTATUS values
const STATUS_ACCESS_VIOLATION: i32 = -1073741819i32;       // 0xC0000005
const STATUS_DATATYPE_MISALIGNMENT: i32 = -2147483646i32;  // 0x80000002

/// Exception raised count for debugging
static EXCEPTION_RAISED_COUNT: AtomicU64 = AtomicU64::new(0);
static ACCESS_VIOLATION_COUNT: AtomicU64 = AtomicU64::new(0);
static MISALIGNMENT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Raise an exception with the given status (ExRaiseStatus)
///
/// This function raises an exception with the specified NTSTATUS code.
/// The exception can be caught by a structured exception handler.
///
/// # Arguments
/// * `status` - NTSTATUS code to raise
///
/// # Panics
/// In the current implementation, this will panic as we don't have
/// full SEH support. In a complete implementation, this would
/// unwind to an exception handler.
#[cold]
#[track_caller]
pub fn ex_raise_status(status: i32) -> ! {
    EXCEPTION_RAISED_COUNT.fetch_add(1, Ordering::Relaxed);

    // In real Windows, this would:
    // 1. Build an exception record
    // 2. Call RtlRaiseException to dispatch it
    // 3. If no handler catches it, the process/kernel terminates

    // For now, log and panic
    crate::serial_println!(
        "[EX] ExRaiseStatus: 0x{:08x} at {}",
        status as u32,
        core::panic::Location::caller()
    );

    panic!("ExRaiseStatus(0x{:08x})", status as u32);
}

/// Raise an access violation exception (ExRaiseAccessViolation)
///
/// This function is typically called by probe macros when a pointer
/// is invalid or not accessible.
#[cold]
#[track_caller]
pub fn ex_raise_access_violation() -> ! {
    ACCESS_VIOLATION_COUNT.fetch_add(1, Ordering::Relaxed);
    ex_raise_status(STATUS_ACCESS_VIOLATION);
}

/// Raise a datatype misalignment exception (ExRaiseDatatypeMisalignment)
///
/// This function is typically called by probe macros when a pointer
/// is not properly aligned for the data type being accessed.
#[cold]
#[track_caller]
pub fn ex_raise_datatype_misalignment() -> ! {
    MISALIGNMENT_COUNT.fetch_add(1, Ordering::Relaxed);
    ex_raise_status(STATUS_DATATYPE_MISALIGNMENT);
}

// ============================================================================
// Non-panicking versions (return status instead)
// ============================================================================

/// Result of attempting to raise an exception
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaiseResult {
    /// Would have raised (for testing/non-fatal paths)
    WouldRaise(i32),
    /// Actually raised (unreachable in non-panicking version)
    Raised,
}

/// Try to "raise" an exception without actually panicking
///
/// This is useful for paths where we want to report an error
/// but continue execution.
pub fn ex_try_raise_status(status: i32) -> RaiseResult {
    EXCEPTION_RAISED_COUNT.fetch_add(1, Ordering::Relaxed);
    RaiseResult::WouldRaise(status)
}

/// Non-panicking access violation (returns error status)
pub fn ex_report_access_violation() -> i32 {
    ACCESS_VIOLATION_COUNT.fetch_add(1, Ordering::Relaxed);
    STATUS_ACCESS_VIOLATION
}

/// Non-panicking misalignment (returns error status)
pub fn ex_report_datatype_misalignment() -> i32 {
    MISALIGNMENT_COUNT.fetch_add(1, Ordering::Relaxed);
    STATUS_DATATYPE_MISALIGNMENT
}

// ============================================================================
// Status Code Constants (commonly raised)
// ============================================================================

/// STATUS_ACCESS_VIOLATION - Invalid memory access
pub const EX_STATUS_ACCESS_VIOLATION: i32 = STATUS_ACCESS_VIOLATION;

/// STATUS_DATATYPE_MISALIGNMENT - Unaligned data access
pub const EX_STATUS_DATATYPE_MISALIGNMENT: i32 = STATUS_DATATYPE_MISALIGNMENT;

/// STATUS_INVALID_PARAMETER - Invalid parameter
pub const EX_STATUS_INVALID_PARAMETER: i32 = -1073741811i32; // 0xC000000D

/// STATUS_INTEGER_OVERFLOW - Arithmetic overflow
pub const EX_STATUS_INTEGER_OVERFLOW: i32 = -1073741476i32; // 0xC0000095

/// STATUS_INTEGER_DIVIDE_BY_ZERO - Division by zero
pub const EX_STATUS_INTEGER_DIVIDE_BY_ZERO: i32 = -1073741676i32; // 0xC0000094

/// STATUS_FLOAT_DIVIDE_BY_ZERO - Floating point division by zero
pub const EX_STATUS_FLOAT_DIVIDE_BY_ZERO: i32 = -1073741683i32;

/// STATUS_PRIVILEGED_INSTRUCTION - Privileged instruction
pub const EX_STATUS_PRIVILEGED_INSTRUCTION: i32 = -1073741674i32;

/// STATUS_ILLEGAL_INSTRUCTION - Illegal instruction
pub const EX_STATUS_ILLEGAL_INSTRUCTION: i32 = -1073741795i32;

/// STATUS_STACK_OVERFLOW - Stack overflow
pub const EX_STATUS_STACK_OVERFLOW: i32 = -1073741571i32;

/// STATUS_IN_PAGE_ERROR - Page fault could not be resolved
pub const EX_STATUS_IN_PAGE_ERROR: i32 = -1073741818i32;

// ============================================================================
// Statistics
// ============================================================================

/// Exception raising statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ExceptionStats {
    /// Total exceptions raised
    pub total_raised: u64,
    /// Access violations
    pub access_violations: u64,
    /// Datatype misalignments
    pub misalignments: u64,
}

/// Get exception raising statistics
pub fn get_exception_stats() -> ExceptionStats {
    ExceptionStats {
        total_raised: EXCEPTION_RAISED_COUNT.load(Ordering::Relaxed),
        access_violations: ACCESS_VIOLATION_COUNT.load(Ordering::Relaxed),
        misalignments: MISALIGNMENT_COUNT.load(Ordering::Relaxed),
    }
}

/// Reset exception statistics
pub fn reset_exception_stats() {
    EXCEPTION_RAISED_COUNT.store(0, Ordering::Relaxed);
    ACCESS_VIOLATION_COUNT.store(0, Ordering::Relaxed);
    MISALIGNMENT_COUNT.store(0, Ordering::Relaxed);
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize exception raising support
pub fn init() {
    EXCEPTION_RAISED_COUNT.store(0, Ordering::Release);
    ACCESS_VIOLATION_COUNT.store(0, Ordering::Release);
    MISALIGNMENT_COUNT.store(0, Ordering::Release);

    crate::serial_println!("[EX] Exception raising support initialized");
}
