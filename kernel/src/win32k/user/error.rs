//! Error Reporting UI
//!
//! Implements Windows Error Reporting (WER) and application error dialogs
//! following wer.h and the Dr. Watson API.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/werapi.h` - WER API definitions
//! - `admin/wmi/wbem/tools/drwatson/` - Dr. Watson implementation
//! - `shell/appcompat/shim/error/` - Error handling

use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::HWND;

// ============================================================================
// Constants
// ============================================================================

/// Maximum error message length
const MAX_ERROR_MESSAGE: usize = 1024;

/// Maximum error reports stored
const MAX_ERROR_REPORTS: usize = 64;

/// Maximum module name length
const MAX_MODULE_NAME: usize = 260;

/// Maximum application name length
const MAX_APP_NAME: usize = 260;

/// Maximum signature parameters
const MAX_SIGNATURE_PARAMS: usize = 10;

/// Maximum file path length
const MAX_FILE_PATH: usize = 260;

/// Maximum files per report
const MAX_REPORT_FILES: usize = 16;

// ============================================================================
// WER Constants
// ============================================================================

/// WER result codes
pub mod result {
    pub const S_OK: i32 = 0;
    pub const E_FAIL: i32 = -2147467259; // 0x80004005
    pub const E_INVALIDARG: i32 = -2147024809; // 0x80070057
    pub const E_OUTOFMEMORY: i32 = -2147024882; // 0x8007000E
    pub const WER_E_NOT_INITIALIZED: i32 = -2145845247;
    pub const WER_E_ALREADY_REPORTING: i32 = -2145845246;
    pub const WER_E_REPORT_NOT_FOUND: i32 = -2145845245;
    pub const WER_E_INSUFFICIENT_BUFFER: i32 = -2145845244;
}

/// WER consent values
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WerConsent {
    #[default]
    NotAsked = 1,
    Approved = 2,
    Denied = 3,
    AlwaysPrompt = 4,
}

/// WER report types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WerReportType {
    #[default]
    NonCritical = 0,
    Critical = 1,
    ApplicationCrash = 2,
    ApplicationHang = 3,
    Kernel = 4,
    Invalid = 5,
}

/// WER submission result
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WerSubmitResult {
    #[default]
    ReportQueued = 1,
    ReportUploaded = 2,
    ReportFailed = 3,
    ReportDebug = 4,
    ReportAsync = 5,
    CustomAction = 6,
    Disabled = 7,
    DisabledQueue = 8,
}

// ============================================================================
// WER Flags
// ============================================================================

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct WerReportFlags: u32 {
        /// Queue report for later submission
        const QUEUE = 0x00000004;
        /// Disable archive
        const DISABLE_ARCHIVE = 0x00000008;
        /// Report immediately
        const START_MINIMIZED = 0x00000020;
        /// Disable restart
        const DISABLE_RESTART = 0x00000100;
        /// Show debug button
        const SHOW_DEBUG = 0x00000002;
        /// Add dump file
        const ADD_DUMP = 0x00000001;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct WerDumpFlags: u32 {
        /// Include heap
        const HEAP = 0x00000001;
        /// Include thread info
        const THREAD_INFO = 0x00000002;
        /// Include modules
        const MODULES = 0x00000004;
        /// Include module headers
        const MODULE_HEADERS = 0x00000008;
        /// Include data segments
        const DATA_SEGS = 0x00000010;
        /// Include stack
        const STACK = 0x00000020;
        /// Include all memory
        const ALL_MEMORY = 0x00000040;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct WerFileFlags: u32 {
        /// Delete file when done
        const DELETE_WHEN_DONE = 0x00000001;
        /// Anonymous data
        const ANONYMOUS_DATA = 0x00000002;
    }
}

// ============================================================================
// Report File Types
// ============================================================================

/// Types of files that can be added to a report
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WerFileType {
    #[default]
    MiniDump = 1,
    Heap = 2,
    UserDocument = 3,
    Other = 4,
    Triagedump = 5,
}

// ============================================================================
// Error Report Structure
// ============================================================================

/// Error report signature parameter
#[derive(Debug, Clone)]
pub struct SignatureParam {
    pub name: [u8; 64],
    pub value: [u8; 256],
}

impl SignatureParam {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 64],
            value: [0u8; 256],
        }
    }
}

impl Default for SignatureParam {
    fn default() -> Self {
        Self::new()
    }
}

/// File attached to error report
#[derive(Debug, Clone)]
pub struct ReportFile {
    pub in_use: bool,
    pub file_type: WerFileType,
    pub path: [u8; MAX_FILE_PATH],
    pub flags: WerFileFlags,
}

impl ReportFile {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            file_type: WerFileType::Other,
            path: [0u8; MAX_FILE_PATH],
            flags: WerFileFlags::empty(),
        }
    }
}

impl Default for ReportFile {
    fn default() -> Self {
        Self::new()
    }
}

/// Error report information
#[derive(Debug)]
pub struct WerReportInfo {
    pub in_use: bool,
    pub report_handle: u32,
    pub report_type: WerReportType,
    pub event_type: [u8; 64],
    pub app_name: [u8; MAX_APP_NAME],
    pub app_path: [u8; MAX_FILE_PATH],
    pub description: [u8; MAX_ERROR_MESSAGE],
    pub signature_params: [SignatureParam; MAX_SIGNATURE_PARAMS],
    pub signature_count: usize,
    pub files: [ReportFile; MAX_REPORT_FILES],
    pub file_count: usize,
    pub flags: WerReportFlags,
    pub consent: WerConsent,
    pub submitted: bool,
}

impl WerReportInfo {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            report_handle: 0,
            report_type: WerReportType::NonCritical,
            event_type: [0u8; 64],
            app_name: [0u8; MAX_APP_NAME],
            app_path: [0u8; MAX_FILE_PATH],
            description: [0u8; MAX_ERROR_MESSAGE],
            signature_params: [const { SignatureParam::new() }; MAX_SIGNATURE_PARAMS],
            signature_count: 0,
            files: [const { ReportFile::new() }; MAX_REPORT_FILES],
            file_count: 0,
            flags: WerReportFlags::empty(),
            consent: WerConsent::NotAsked,
            submitted: false,
        }
    }
}

// ============================================================================
// Exception Information
// ============================================================================

/// Exception record
#[derive(Debug, Clone, Copy, Default)]
pub struct ExceptionRecord {
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_address: usize,
    pub number_parameters: u32,
    pub exception_info: [usize; 4],
}

/// Context record (simplified)
#[derive(Debug, Clone, Copy, Default)]
pub struct ContextRecord {
    pub context_flags: u32,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rip: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
}

/// Exception pointers
#[derive(Debug, Clone, Copy, Default)]
pub struct ExceptionPointers {
    pub exception_record: ExceptionRecord,
    pub context_record: ContextRecord,
}

// ============================================================================
// Application Error Dialog
// ============================================================================

/// Application error info
#[derive(Debug, Clone)]
pub struct AppErrorInfo {
    pub app_name: [u8; MAX_APP_NAME],
    pub module_name: [u8; MAX_MODULE_NAME],
    pub exception_code: u32,
    pub exception_address: usize,
    pub message: [u8; MAX_ERROR_MESSAGE],
}

impl AppErrorInfo {
    pub const fn new() -> Self {
        Self {
            app_name: [0u8; MAX_APP_NAME],
            module_name: [0u8; MAX_MODULE_NAME],
            exception_code: 0,
            exception_address: 0,
            message: [0u8; MAX_ERROR_MESSAGE],
        }
    }

    pub fn set_app_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_APP_NAME - 1);
        self.app_name[..len].copy_from_slice(&name[..len]);
        self.app_name[len] = 0;
    }

    pub fn set_module_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_MODULE_NAME - 1);
        self.module_name[..len].copy_from_slice(&name[..len]);
        self.module_name[len] = 0;
    }

    pub fn set_message(&mut self, msg: &[u8]) {
        let len = msg.len().min(MAX_ERROR_MESSAGE - 1);
        self.message[..len].copy_from_slice(&msg[..len]);
        self.message[len] = 0;
    }
}

impl Default for AppErrorInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Dialog result for application error
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppErrorResult {
    #[default]
    Close = 0,
    Debug = 1,
    SendReport = 2,
    DontSend = 3,
    Restart = 4,
}

// ============================================================================
// State
// ============================================================================

static ERROR_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_REPORT_HANDLE: AtomicU32 = AtomicU32::new(1);
static REPORTING_ENABLED: AtomicBool = AtomicBool::new(true);
static ERROR_REPORTS: SpinLock<[WerReportInfo; MAX_ERROR_REPORTS]> = SpinLock::new(
    [const { WerReportInfo::new() }; MAX_ERROR_REPORTS]
);
static GLOBAL_CONSENT: SpinLock<WerConsent> = SpinLock::new(WerConsent::NotAsked);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize error reporting subsystem
pub fn init() {
    if ERROR_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[ERROR] Initializing error reporting...");
    crate::serial_println!("[ERROR] Error reporting initialized");
}

// ============================================================================
// WER Report Functions
// ============================================================================

/// Create a new error report
pub fn wer_report_create(
    event_type: &[u8],
    report_type: WerReportType,
) -> Result<u32, i32> {
    if !REPORTING_ENABLED.load(Ordering::Relaxed) {
        return Err(result::WER_E_NOT_INITIALIZED);
    }

    let mut reports = ERROR_REPORTS.lock();

    // Find free slot
    let slot_idx = reports.iter().position(|r| !r.in_use);
    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(result::E_OUTOFMEMORY),
    };

    let handle = NEXT_REPORT_HANDLE.fetch_add(1, Ordering::SeqCst);

    let report = &mut reports[idx];
    *report = WerReportInfo::new();
    report.in_use = true;
    report.report_handle = handle;
    report.report_type = report_type;

    let len = event_type.len().min(63);
    report.event_type[..len].copy_from_slice(&event_type[..len]);
    report.event_type[len] = 0;

    Ok(handle)
}

/// Set report signature parameter
pub fn wer_report_set_parameter(
    report_handle: u32,
    param_index: usize,
    name: &[u8],
    value: &[u8],
) -> i32 {
    let mut reports = ERROR_REPORTS.lock();

    let report = match reports.iter_mut().find(|r| r.in_use && r.report_handle == report_handle) {
        Some(r) => r,
        None => return result::WER_E_REPORT_NOT_FOUND,
    };

    if param_index >= MAX_SIGNATURE_PARAMS {
        return result::E_INVALIDARG;
    }

    let param = &mut report.signature_params[param_index];

    let name_len = name.len().min(63);
    param.name[..name_len].copy_from_slice(&name[..name_len]);
    param.name[name_len] = 0;

    let value_len = value.len().min(255);
    param.value[..value_len].copy_from_slice(&value[..value_len]);
    param.value[value_len] = 0;

    if param_index >= report.signature_count {
        report.signature_count = param_index + 1;
    }

    result::S_OK
}

/// Add a file to the report
pub fn wer_report_add_file(
    report_handle: u32,
    path: &[u8],
    file_type: WerFileType,
    flags: WerFileFlags,
) -> i32 {
    let mut reports = ERROR_REPORTS.lock();

    let report = match reports.iter_mut().find(|r| r.in_use && r.report_handle == report_handle) {
        Some(r) => r,
        None => return result::WER_E_REPORT_NOT_FOUND,
    };

    if report.file_count >= MAX_REPORT_FILES {
        return result::E_OUTOFMEMORY;
    }

    let file = &mut report.files[report.file_count];
    file.in_use = true;
    file.file_type = file_type;
    file.flags = flags;

    let len = path.len().min(MAX_FILE_PATH - 1);
    file.path[..len].copy_from_slice(&path[..len]);
    file.path[len] = 0;

    report.file_count += 1;

    result::S_OK
}

/// Add dump to report
pub fn wer_report_add_dump(
    report_handle: u32,
    exception_pointers: Option<&ExceptionPointers>,
    dump_flags: WerDumpFlags,
) -> i32 {
    let _ = (exception_pointers, dump_flags);

    let mut reports = ERROR_REPORTS.lock();

    let report = match reports.iter_mut().find(|r| r.in_use && r.report_handle == report_handle) {
        Some(r) => r,
        None => return result::WER_E_REPORT_NOT_FOUND,
    };

    report.flags |= WerReportFlags::ADD_DUMP;

    result::S_OK
}

/// Set UI option for report
pub fn wer_report_set_ui_option(
    report_handle: u32,
    option: u32,
    value: &[u8],
) -> i32 {
    let _ = (option, value);

    let reports = ERROR_REPORTS.lock();

    if !reports.iter().any(|r| r.in_use && r.report_handle == report_handle) {
        return result::WER_E_REPORT_NOT_FOUND;
    }

    result::S_OK
}

/// Submit the error report
pub fn wer_report_submit(
    report_handle: u32,
    consent: WerConsent,
    flags: WerReportFlags,
) -> (i32, WerSubmitResult) {
    let mut reports = ERROR_REPORTS.lock();

    let report = match reports.iter_mut().find(|r| r.in_use && r.report_handle == report_handle) {
        Some(r) => r,
        None => return (result::WER_E_REPORT_NOT_FOUND, WerSubmitResult::ReportFailed),
    };

    report.consent = consent;
    report.flags |= flags;
    report.submitted = true;

    crate::serial_println!("[ERROR] Report {} submitted", report_handle);

    // In a real implementation, this would queue the report for upload
    if flags.contains(WerReportFlags::QUEUE) {
        (result::S_OK, WerSubmitResult::ReportQueued)
    } else {
        (result::S_OK, WerSubmitResult::ReportAsync)
    }
}

/// Close the error report
pub fn wer_report_close(report_handle: u32) -> i32 {
    let mut reports = ERROR_REPORTS.lock();

    for report in reports.iter_mut() {
        if report.in_use && report.report_handle == report_handle {
            report.in_use = false;
            return result::S_OK;
        }
    }

    result::WER_E_REPORT_NOT_FOUND
}

// ============================================================================
// WER Registration Functions
// ============================================================================

/// Register memory block for crash collection
pub fn wer_register_memory_block(address: usize, size: usize) -> i32 {
    let _ = (address, size);
    // Would register memory block for inclusion in crash dumps
    result::S_OK
}

/// Unregister memory block
pub fn wer_unregister_memory_block(address: usize) -> i32 {
    let _ = address;
    result::S_OK
}

/// Register file for crash collection
pub fn wer_register_file(path: &[u8], file_type: WerFileType, flags: WerFileFlags) -> i32 {
    let _ = (path, file_type, flags);
    result::S_OK
}

/// Unregister file
pub fn wer_unregister_file(path: &[u8]) -> i32 {
    let _ = path;
    result::S_OK
}

/// Register runtime exception module
pub fn wer_register_runtime_exception_module(
    module_path: &[u8],
    context: usize,
) -> i32 {
    let _ = (module_path, context);
    result::S_OK
}

/// Unregister runtime exception module
pub fn wer_unregister_runtime_exception_module(
    module_path: &[u8],
    context: usize,
) -> i32 {
    let _ = (module_path, context);
    result::S_OK
}

// ============================================================================
// WER Configuration
// ============================================================================

/// Set default consent
pub fn wer_set_default_consent(consent: WerConsent) {
    *GLOBAL_CONSENT.lock() = consent;
}

/// Get default consent
pub fn wer_get_default_consent() -> WerConsent {
    *GLOBAL_CONSENT.lock()
}

/// Enable or disable reporting
pub fn wer_enable_reporting(enable: bool) {
    REPORTING_ENABLED.store(enable, Ordering::Relaxed);
}

/// Check if reporting is enabled
pub fn wer_is_reporting_enabled() -> bool {
    REPORTING_ENABLED.load(Ordering::Relaxed)
}

// ============================================================================
// Application Error Dialog Functions
// ============================================================================

/// Display application error dialog
pub fn show_app_error_dialog(
    hwnd_parent: HWND,
    info: &AppErrorInfo,
) -> AppErrorResult {
    let _ = hwnd_parent;

    crate::serial_println!(
        "[ERROR] Application error dialog: exception 0x{:08X} at 0x{:X}",
        info.exception_code,
        info.exception_address
    );

    // Would display error dialog
    AppErrorResult::Close
}

/// Display crash dialog
pub fn show_crash_dialog(
    hwnd_parent: HWND,
    app_name: &[u8],
    exception: &ExceptionPointers,
) -> AppErrorResult {
    let _ = (hwnd_parent, app_name);

    crate::serial_println!(
        "[ERROR] Crash dialog: exception 0x{:08X} at 0x{:X}",
        exception.exception_record.exception_code,
        exception.exception_record.exception_address
    );

    // Would display crash dialog
    AppErrorResult::SendReport
}

/// Display hang dialog
pub fn show_hang_dialog(
    hwnd_parent: HWND,
    app_name: &[u8],
    hwnd_hung: HWND,
) -> AppErrorResult {
    let _ = (hwnd_parent, app_name, hwnd_hung);

    crate::serial_println!("[ERROR] Hang dialog requested");

    // Would display hang dialog
    AppErrorResult::Close
}

// ============================================================================
// Exception Codes
// ============================================================================

/// Common exception codes
pub mod exception {
    pub const ACCESS_VIOLATION: u32 = 0xC0000005;
    pub const ARRAY_BOUNDS_EXCEEDED: u32 = 0xC000008C;
    pub const BREAKPOINT: u32 = 0x80000003;
    pub const DATATYPE_MISALIGNMENT: u32 = 0x80000002;
    pub const FLT_DENORMAL_OPERAND: u32 = 0xC000008D;
    pub const FLT_DIVIDE_BY_ZERO: u32 = 0xC000008E;
    pub const FLT_INEXACT_RESULT: u32 = 0xC000008F;
    pub const FLT_INVALID_OPERATION: u32 = 0xC0000090;
    pub const FLT_OVERFLOW: u32 = 0xC0000091;
    pub const FLT_STACK_CHECK: u32 = 0xC0000092;
    pub const FLT_UNDERFLOW: u32 = 0xC0000093;
    pub const GUARD_PAGE: u32 = 0x80000001;
    pub const ILLEGAL_INSTRUCTION: u32 = 0xC000001D;
    pub const IN_PAGE_ERROR: u32 = 0xC0000006;
    pub const INT_DIVIDE_BY_ZERO: u32 = 0xC0000094;
    pub const INT_OVERFLOW: u32 = 0xC0000095;
    pub const INVALID_DISPOSITION: u32 = 0xC0000026;
    pub const INVALID_HANDLE: u32 = 0xC0000008;
    pub const NONCONTINUABLE: u32 = 0xC0000025;
    pub const PRIV_INSTRUCTION: u32 = 0xC0000096;
    pub const SINGLE_STEP: u32 = 0x80000004;
    pub const STACK_OVERFLOW: u32 = 0xC00000FD;
    pub const STATUS_UNWIND: u32 = 0xC0000027;
}

/// Get exception code description
pub fn get_exception_description(code: u32) -> &'static [u8] {
    match code {
        exception::ACCESS_VIOLATION => b"Access Violation",
        exception::ARRAY_BOUNDS_EXCEEDED => b"Array Bounds Exceeded",
        exception::BREAKPOINT => b"Breakpoint",
        exception::DATATYPE_MISALIGNMENT => b"Data Type Misalignment",
        exception::FLT_DIVIDE_BY_ZERO => b"Floating Point Divide by Zero",
        exception::FLT_INVALID_OPERATION => b"Floating Point Invalid Operation",
        exception::FLT_OVERFLOW => b"Floating Point Overflow",
        exception::FLT_UNDERFLOW => b"Floating Point Underflow",
        exception::ILLEGAL_INSTRUCTION => b"Illegal Instruction",
        exception::INT_DIVIDE_BY_ZERO => b"Integer Divide by Zero",
        exception::INT_OVERFLOW => b"Integer Overflow",
        exception::INVALID_HANDLE => b"Invalid Handle",
        exception::PRIV_INSTRUCTION => b"Privileged Instruction",
        exception::STACK_OVERFLOW => b"Stack Overflow",
        _ => b"Unknown Exception",
    }
}

// ============================================================================
// Fatal Application Exit
// ============================================================================

/// Report fatal application exit
pub fn fatal_app_exit(action: u32, message: &[u8]) {
    let _ = action;

    crate::serial_println!("[ERROR] Fatal application exit requested");

    // Display the message
    let msg_len = str_len(message);
    if msg_len > 0 {
        // Would display fatal error dialog
    }
}

/// Report a fault
pub fn report_fault(
    exception_pointers: &ExceptionPointers,
    mode: u32,
) -> bool {
    let _ = mode;

    crate::serial_println!(
        "[ERROR] Fault reported: 0x{:08X} at 0x{:X}",
        exception_pointers.exception_record.exception_code,
        exception_pointers.exception_record.exception_address
    );

    // Create and submit WER report
    if let Ok(handle) = wer_report_create(b"Application Crash", WerReportType::ApplicationCrash) {
        wer_report_add_dump(handle, Some(exception_pointers), WerDumpFlags::STACK);
        let _ = wer_report_submit(handle, WerConsent::Approved, WerReportFlags::QUEUE);
        let _ = wer_report_close(handle);
    }

    true
}

// ============================================================================
// Unhandled Exception Filter
// ============================================================================

/// Unhandled exception filter result
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnhandledExceptionResult {
    ContinueExecution = -1,
    ContinueSearch = 0,
    ExecuteHandler = 1,
}

/// Default unhandled exception filter
pub fn unhandled_exception_filter(
    exception_pointers: &ExceptionPointers,
) -> UnhandledExceptionResult {
    // Report the fault
    let _ = report_fault(exception_pointers, 0);

    // Show crash dialog
    let _ = show_crash_dialog(
        super::UserHandle::NULL,
        b"Application",
        exception_pointers,
    );

    UnhandledExceptionResult::ExecuteHandler
}

/// Set unhandled exception filter callback
pub fn set_unhandled_exception_filter(
    filter: Option<fn(&ExceptionPointers) -> UnhandledExceptionResult>,
) -> Option<fn(&ExceptionPointers) -> UnhandledExceptionResult> {
    let _ = filter;
    // Would store and return previous filter
    None
}

// ============================================================================
// Helper Functions
// ============================================================================

fn str_len(s: &[u8]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

// ============================================================================
// Statistics
// ============================================================================

/// Error reporting statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ErrorStats {
    pub initialized: bool,
    pub reporting_enabled: bool,
    pub active_reports: u32,
    pub submitted_reports: u32,
}

/// Get error reporting statistics
pub fn get_stats() -> ErrorStats {
    let reports = ERROR_REPORTS.lock();

    let mut active = 0u32;
    let mut submitted = 0u32;

    for report in reports.iter() {
        if report.in_use {
            active += 1;
            if report.submitted {
                submitted += 1;
            }
        }
    }

    ErrorStats {
        initialized: ERROR_INITIALIZED.load(Ordering::Relaxed),
        reporting_enabled: REPORTING_ENABLED.load(Ordering::Relaxed),
        active_reports: active,
        submitted_reports: submitted,
    }
}
