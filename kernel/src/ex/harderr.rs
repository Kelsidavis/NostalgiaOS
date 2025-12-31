//! Executive Hard Error Handling
//!
//! Provides hard error handling for critical system errors that may
//! require user interaction or system shutdown:
//! - Hard error response options (Ok, Cancel, Abort, Retry, etc.)
//! - Error port registration for user-mode handlers
//! - System error handler for unhandled errors
//! - NtRaiseHardError and ExRaiseHardError APIs
//!
//! Based on Windows Server 2003 base/ntos/ex/harderr.c

use crate::ke::SpinLock;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

extern crate alloc;

/// Maximum number of parameters in a hard error
pub const MAXIMUM_HARDERROR_PARAMETERS: usize = 5;

/// Hard error override flag (in NTSTATUS)
pub const HARDERROR_OVERRIDE_ERRORMODE: u32 = 0x10000000;

/// Hard error response options
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardErrorResponseOption {
    /// Abort/Retry/Ignore buttons
    AbortRetryIgnore = 0,
    /// OK button only
    Ok = 1,
    /// OK/Cancel buttons
    OkCancel = 2,
    /// Retry/Cancel buttons
    RetryCancel = 3,
    /// Yes/No buttons
    YesNo = 4,
    /// Yes/No/Cancel buttons
    YesNoCancel = 5,
    /// Shutdown system (requires privilege)
    ShutdownSystem = 6,
    /// OK button, no wait
    OkNoWait = 7,
    /// Cancel/Try Again/Continue buttons
    CancelTryContinue = 8,
}

impl TryFrom<u32> for HardErrorResponseOption {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::AbortRetryIgnore),
            1 => Ok(Self::Ok),
            2 => Ok(Self::OkCancel),
            3 => Ok(Self::RetryCancel),
            4 => Ok(Self::YesNo),
            5 => Ok(Self::YesNoCancel),
            6 => Ok(Self::ShutdownSystem),
            7 => Ok(Self::OkNoWait),
            8 => Ok(Self::CancelTryContinue),
            _ => Err(()),
        }
    }
}

/// Hard error response values
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HardErrorResponse {
    /// Return to caller without handling
    #[default]
    ReturnToCaller = 0,
    /// Error was not handled
    NotHandled = 1,
    /// Abort operation
    Abort = 2,
    /// Cancel operation
    Cancel = 3,
    /// Ignore error
    Ignore = 4,
    /// No response
    No = 5,
    /// OK response
    Ok = 6,
    /// Retry operation
    Retry = 7,
    /// Yes response
    Yes = 8,
    /// Try again
    TryAgain = 9,
    /// Continue operation
    Continue = 10,
}

impl From<u32> for HardErrorResponse {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::ReturnToCaller,
            1 => Self::NotHandled,
            2 => Self::Abort,
            3 => Self::Cancel,
            4 => Self::Ignore,
            5 => Self::No,
            6 => Self::Ok,
            7 => Self::Retry,
            8 => Self::Yes,
            9 => Self::TryAgain,
            10 => Self::Continue,
            _ => Self::ReturnToCaller,
        }
    }
}

/// Hard error state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardErrorState {
    /// System is starting, no handler installed
    Starting,
    /// Handler is installed and running
    Started,
    /// System is shutting down
    Shutdown,
}

/// Hard error message for LPC communication
#[derive(Debug, Clone)]
pub struct HardErrorMessage {
    /// Error status code
    pub status: i32,
    /// Valid response options
    pub valid_response_options: HardErrorResponseOption,
    /// Unicode string parameter mask (which params are strings)
    pub unicode_string_parameter_mask: u32,
    /// Number of parameters
    pub number_of_parameters: u32,
    /// Parameters (up to 5)
    pub parameters: [usize; MAXIMUM_HARDERROR_PARAMETERS],
    /// Error timestamp
    pub error_time: u64,
    /// Response from handler
    pub response: HardErrorResponse,
}

impl HardErrorMessage {
    pub fn new(
        status: i32,
        options: HardErrorResponseOption,
        string_mask: u32,
        num_params: u32,
        params: &[usize],
    ) -> Self {
        let mut parameters = [0usize; MAXIMUM_HARDERROR_PARAMETERS];
        let count = params.len().min(MAXIMUM_HARDERROR_PARAMETERS);
        parameters[..count].copy_from_slice(&params[..count]);

        Self {
            status,
            valid_response_options: options,
            unicode_string_parameter_mask: string_mask,
            number_of_parameters: num_params,
            parameters,
            error_time: crate::hal::rtc::get_system_time(),
            response: HardErrorResponse::ReturnToCaller,
        }
    }
}

/// Hard error handler callback type
pub type HardErrorHandler = fn(&HardErrorMessage) -> HardErrorResponse;

/// Pending hard error entry
#[derive(Clone)]
struct PendingHardError {
    /// Error message
    message: HardErrorMessage,
    /// Process ID that raised the error
    process_id: u64,
    /// Thread ID that raised the error
    thread_id: u64,
    /// Description (for display)
    description: String,
}

/// Hard error subsystem state
struct HardErrorSubsystem {
    /// Current state
    state: HardErrorState,
    /// Ready to receive errors
    ready_for_errors: bool,
    /// Too late for errors (shutdown in progress)
    too_late_for_errors: bool,
    /// Default error handler
    default_handler: Option<HardErrorHandler>,
    /// Default error port process ID
    default_error_port_process: u64,
    /// Pending errors queue
    pending_errors: VecDeque<PendingHardError>,
    /// Error log (recent errors)
    error_log: VecDeque<PendingHardError>,
}

impl HardErrorSubsystem {
    pub const fn new() -> Self {
        Self {
            state: HardErrorState::Starting,
            ready_for_errors: false,
            too_late_for_errors: false,
            default_handler: None,
            default_error_port_process: 0,
            pending_errors: VecDeque::new(),
            error_log: VecDeque::new(),
        }
    }
}

/// Global hard error state
static mut HARDERR_STATE: Option<SpinLock<HardErrorSubsystem>> = None;

/// Statistics
static ERRORS_RAISED: AtomicU64 = AtomicU64::new(0);
static ERRORS_HANDLED: AtomicU64 = AtomicU64::new(0);
static ERRORS_IGNORED: AtomicU64 = AtomicU64::new(0);
static SYSTEM_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Maximum pending errors
const MAX_PENDING_ERRORS: usize = 64;

/// Maximum error log size
const MAX_ERROR_LOG: usize = 256;

fn get_harderr_state() -> &'static SpinLock<HardErrorSubsystem> {
    unsafe {
        HARDERR_STATE
            .as_ref()
            .expect("Hard error subsystem not initialized")
    }
}

/// Initialize hard error subsystem
pub fn exp_harderr_init() {
    unsafe {
        HARDERR_STATE = Some(SpinLock::new(HardErrorSubsystem::new()));
    }

    crate::serial_println!("[EX] Hard error subsystem initialized");
}

/// Get NTSTATUS severity
fn ntstatus_severity(status: i32) -> u32 {
    ((status as u32) >> 30) & 0x3
}

/// Check if NTSTATUS is an error
fn nt_error(status: i32) -> bool {
    ntstatus_severity(status) == 3
}

/// Check if NTSTATUS is a warning
fn nt_warning(status: i32) -> bool {
    ntstatus_severity(status) == 2
}

/// System error handler - called when no handler is installed
fn exp_system_error_handler(
    error_status: i32,
    number_of_parameters: u32,
    parameters: &[usize],
    call_shutdown: bool,
) {
    SYSTEM_ERRORS.fetch_add(1, Ordering::Relaxed);

    // Format the error message
    crate::serial_println!("\n*** STOP: 0x{:08X}", error_status as u32);

    if number_of_parameters > 0 {
        crate::serial_print!("    Parameters: ");
        for i in 0..(number_of_parameters as usize).min(MAXIMUM_HARDERROR_PARAMETERS) {
            crate::serial_print!("0x{:X} ", parameters[i]);
        }
        crate::serial_println!("");
    }

    if call_shutdown {
        crate::serial_println!("*** System shutdown requested ***");
        // In a real implementation, this would trigger PoShutdownBugCheck
        // or KeBugCheckEx
    }
}

/// Internal raise hard error implementation
fn exp_raise_hard_error(
    error_status: i32,
    number_of_parameters: u32,
    unicode_string_parameter_mask: u32,
    parameters: &[usize],
    valid_response_options: HardErrorResponseOption,
) -> Result<HardErrorResponse, i32> {
    ERRORS_RAISED.fetch_add(1, Ordering::Relaxed);

    let state = get_harderr_state();
    let mut guard = state.lock();

    // Check if system is shutting down
    if valid_response_options == HardErrorResponseOption::ShutdownSystem {
        guard.ready_for_errors = false;
        guard.state = HardErrorState::Shutdown;
    }

    // If no handler installed and this is a hard error, call system handler
    if guard.state == HardErrorState::Starting && nt_error(error_status) {
        drop(guard);
        exp_system_error_handler(
            error_status,
            number_of_parameters,
            parameters,
            false,
        );
        return Ok(HardErrorResponse::ReturnToCaller);
    }

    // If too late for errors, just return
    if guard.too_late_for_errors {
        ERRORS_IGNORED.fetch_add(1, Ordering::Relaxed);
        return Ok(HardErrorResponse::NotHandled);
    }

    // Check if we have a default handler
    if let Some(handler) = guard.default_handler {
        let message = HardErrorMessage::new(
            error_status,
            valid_response_options,
            unicode_string_parameter_mask,
            number_of_parameters,
            parameters,
        );

        drop(guard);
        let response = handler(&message);
        ERRORS_HANDLED.fetch_add(1, Ordering::Relaxed);
        return Ok(response);
    }

    // Queue the error if ready for errors
    if guard.ready_for_errors {
        let error = PendingHardError {
            message: HardErrorMessage::new(
                error_status,
                valid_response_options,
                unicode_string_parameter_mask,
                number_of_parameters,
                parameters,
            ),
            process_id: 0, // Would get from PsGetCurrentProcessId
            thread_id: 0,  // Would get from PsGetCurrentThreadId
            description: format_error_description(error_status),
        };

        // Add to pending queue
        if guard.pending_errors.len() < MAX_PENDING_ERRORS {
            guard.pending_errors.push_back(error.clone());
        }

        // Add to error log
        if guard.error_log.len() >= MAX_ERROR_LOG {
            guard.error_log.pop_front();
        }
        guard.error_log.push_back(error);

        return Ok(HardErrorResponse::ReturnToCaller);
    }

    // No handler available
    ERRORS_IGNORED.fetch_add(1, Ordering::Relaxed);
    Ok(HardErrorResponse::ReturnToCaller)
}

/// Format error description from status code
fn format_error_description(status: i32) -> String {
    // Common NTSTATUS codes
    match status as u32 {
        0xC0000001 => String::from("STATUS_UNSUCCESSFUL"),
        0xC0000002 => String::from("STATUS_NOT_IMPLEMENTED"),
        0xC0000005 => String::from("STATUS_ACCESS_VIOLATION"),
        0xC0000008 => String::from("STATUS_INVALID_HANDLE"),
        0xC000000D => String::from("STATUS_INVALID_PARAMETER"),
        0xC0000017 => String::from("STATUS_NO_MEMORY"),
        0xC0000022 => String::from("STATUS_ACCESS_DENIED"),
        0xC0000034 => String::from("STATUS_OBJECT_NAME_NOT_FOUND"),
        0xC000003A => String::from("STATUS_OBJECT_PATH_NOT_FOUND"),
        0xC0000043 => String::from("STATUS_SHARING_VIOLATION"),
        0xC0000061 => String::from("STATUS_PRIVILEGE_NOT_HELD"),
        0xC00000BB => String::from("STATUS_NOT_SUPPORTED"),
        0xC00000E5 => String::from("STATUS_INTERNAL_ERROR"),
        0xC0000135 => String::from("STATUS_DLL_NOT_FOUND"),
        0xC0000139 => String::from("STATUS_ENTRYPOINT_NOT_FOUND"),
        0xC0000142 => String::from("STATUS_DLL_INIT_FAILED"),
        0xC0000221 => String::from("STATUS_IMAGE_CHECKSUM_MISMATCH"),
        _ => alloc::format!("NTSTATUS 0x{:08X}", status as u32),
    }
}

/// Raise a hard error (kernel mode API)
pub fn ex_raise_hard_error(
    error_status: i32,
    number_of_parameters: u32,
    unicode_string_parameter_mask: u32,
    parameters: &[usize],
    valid_response_options: HardErrorResponseOption,
) -> Result<HardErrorResponse, i32> {
    // Validate parameters
    if number_of_parameters as usize > MAXIMUM_HARDERROR_PARAMETERS {
        return Err(-1073741811); // STATUS_INVALID_PARAMETER
    }

    exp_raise_hard_error(
        error_status,
        number_of_parameters,
        unicode_string_parameter_mask,
        parameters,
        valid_response_options,
    )
}

/// Raise a hard error (NT syscall API)
pub fn nt_raise_hard_error(
    error_status: i32,
    number_of_parameters: u32,
    unicode_string_parameter_mask: u32,
    parameters: &[usize],
    valid_response_options: u32,
) -> Result<HardErrorResponse, i32> {
    // Validate response options
    let options = HardErrorResponseOption::try_from(valid_response_options)
        .map_err(|_| -1073741811i32)?; // STATUS_INVALID_PARAMETER

    // Check shutdown privilege if needed
    if options == HardErrorResponseOption::ShutdownSystem {
        // Would check SeSinglePrivilegeCheck(SeShutdownPrivilege)
        // For now, allow it
    }

    ex_raise_hard_error(
        error_status,
        number_of_parameters,
        unicode_string_parameter_mask,
        parameters,
        options,
    )
}

/// Set the default hard error port/handler
pub fn nt_set_default_hard_error_port(handler: HardErrorHandler) -> Result<(), i32> {
    let state = get_harderr_state();
    let mut guard = state.lock();

    // Can only set once
    if guard.state == HardErrorState::Started {
        return Err(-1073741823); // STATUS_UNSUCCESSFUL
    }

    guard.default_handler = Some(handler);
    guard.ready_for_errors = true;
    guard.state = HardErrorState::Started;
    guard.default_error_port_process = 0; // Would get from PsGetCurrentProcess

    crate::serial_println!("[EX] Default hard error handler installed");

    Ok(())
}

/// Get next pending hard error
pub fn exp_get_pending_error() -> Option<HardErrorMessage> {
    let state = get_harderr_state();
    let mut guard = state.lock();
    guard.pending_errors.pop_front().map(|e| e.message)
}

/// Get pending error count
pub fn exp_pending_error_count() -> usize {
    let state = get_harderr_state();
    let guard = state.lock();
    guard.pending_errors.len()
}

/// Respond to a pending error
pub fn exp_respond_to_error(response: HardErrorResponse) {
    ERRORS_HANDLED.fetch_add(1, Ordering::Relaxed);
    // In a real implementation, this would unblock the waiting thread
    crate::serial_println!("[EX] Hard error response: {:?}", response);
}

/// Mark system as too late for errors (shutdown starting)
pub fn exp_too_late_for_errors() {
    let state = get_harderr_state();
    let mut guard = state.lock();
    guard.too_late_for_errors = true;
    guard.state = HardErrorState::Shutdown;
}

/// Check if system is ready for errors
pub fn exp_ready_for_errors() -> bool {
    let state = get_harderr_state();
    let guard = state.lock();
    guard.ready_for_errors
}

/// Get error log (recent errors)
pub fn exp_get_error_log() -> Vec<(i32, String, u64)> {
    let state = get_harderr_state();
    let guard = state.lock();

    guard.error_log
        .iter()
        .map(|e| (e.message.status, e.description.clone(), e.message.error_time))
        .collect()
}

/// Clear error log
pub fn exp_clear_error_log() {
    let state = get_harderr_state();
    let mut guard = state.lock();
    guard.error_log.clear();
}

/// Get hard error statistics
pub fn exp_harderr_get_stats() -> HardErrorStats {
    let state = get_harderr_state();
    let guard = state.lock();

    HardErrorStats {
        errors_raised: ERRORS_RAISED.load(Ordering::Relaxed),
        errors_handled: ERRORS_HANDLED.load(Ordering::Relaxed),
        errors_ignored: ERRORS_IGNORED.load(Ordering::Relaxed),
        system_errors: SYSTEM_ERRORS.load(Ordering::Relaxed),
        pending_count: guard.pending_errors.len(),
        log_count: guard.error_log.len(),
        is_ready: guard.ready_for_errors,
        is_shutdown: guard.state == HardErrorState::Shutdown,
    }
}

/// Hard error statistics
#[derive(Debug, Clone)]
pub struct HardErrorStats {
    /// Total errors raised
    pub errors_raised: u64,
    /// Errors handled by handler
    pub errors_handled: u64,
    /// Errors ignored (no handler)
    pub errors_ignored: u64,
    /// System errors (critical)
    pub system_errors: u64,
    /// Pending error count
    pub pending_count: usize,
    /// Error log count
    pub log_count: usize,
    /// Ready for errors
    pub is_ready: bool,
    /// System shutting down
    pub is_shutdown: bool,
}

/// Convenience function to raise a simple error
pub fn ex_raise_error(status: i32) -> HardErrorResponse {
    ex_raise_hard_error(status, 0, 0, &[], HardErrorResponseOption::Ok)
        .unwrap_or(HardErrorResponse::NotHandled)
}

/// Convenience function to raise an error with one parameter
pub fn ex_raise_error_with_param(status: i32, param: usize) -> HardErrorResponse {
    ex_raise_hard_error(
        status,
        1,
        0,
        &[param],
        HardErrorResponseOption::Ok,
    )
    .unwrap_or(HardErrorResponse::NotHandled)
}

/// Convenience function to raise a Yes/No error
pub fn ex_raise_yesno_error(status: i32) -> HardErrorResponse {
    ex_raise_hard_error(status, 0, 0, &[], HardErrorResponseOption::YesNo)
        .unwrap_or(HardErrorResponse::NotHandled)
}

/// Convenience function to raise an Abort/Retry/Ignore error
pub fn ex_raise_ari_error(status: i32) -> HardErrorResponse {
    ex_raise_hard_error(status, 0, 0, &[], HardErrorResponseOption::AbortRetryIgnore)
        .unwrap_or(HardErrorResponse::NotHandled)
}

/// Default console hard error handler (for shell)
pub fn exp_console_error_handler(message: &HardErrorMessage) -> HardErrorResponse {
    crate::kprintln!("\n*** Hard Error ***");
    crate::kprintln!("Status: 0x{:08X}", message.status as u32);
    crate::kprintln!("Description: {}", format_error_description(message.status));

    if message.number_of_parameters > 0 {
        crate::kprint!("Parameters: ");
        for i in 0..(message.number_of_parameters as usize).min(MAXIMUM_HARDERROR_PARAMETERS) {
            crate::kprint!("0x{:X} ", message.parameters[i]);
        }
        crate::kprintln!("");
    }

    // Show valid responses based on options
    match message.valid_response_options {
        HardErrorResponseOption::Ok => {
            crate::kprintln!("Press any key to continue...");
            HardErrorResponse::Ok
        }
        HardErrorResponseOption::OkCancel => {
            crate::kprintln!("[O]k / [C]ancel");
            HardErrorResponse::Ok
        }
        HardErrorResponseOption::YesNo => {
            crate::kprintln!("[Y]es / [N]o");
            HardErrorResponse::Yes
        }
        HardErrorResponseOption::YesNoCancel => {
            crate::kprintln!("[Y]es / [N]o / [C]ancel");
            HardErrorResponse::Yes
        }
        HardErrorResponseOption::AbortRetryIgnore => {
            crate::kprintln!("[A]bort / [R]etry / [I]gnore");
            HardErrorResponse::Ignore
        }
        HardErrorResponseOption::RetryCancel => {
            crate::kprintln!("[R]etry / [C]ancel");
            HardErrorResponse::Cancel
        }
        HardErrorResponseOption::CancelTryContinue => {
            crate::kprintln!("[C]ancel / [T]ry Again / Conti[n]ue");
            HardErrorResponse::Continue
        }
        _ => HardErrorResponse::ReturnToCaller,
    }
}
