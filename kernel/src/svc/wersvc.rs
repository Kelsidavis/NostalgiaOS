//! Windows Error Reporting Service (WerSvc)
//!
//! The Windows Error Reporting service collects crash dumps, handles
//! unhandled exceptions, and manages error reports that can be submitted
//! to Microsoft for analysis.
//!
//! # Features
//!
//! - **Crash Handling**: Capture unhandled exceptions and crashes
//! - **Dump Collection**: Create minidumps and full dumps
//! - **Report Generation**: Generate error reports with system info
//! - **Report Queuing**: Queue reports for later submission
//! - **Privacy**: Allow user control over report submission
//!
//! # Report Types
//!
//! - Application crashes (unhandled exceptions)
//! - Kernel crashes (bugchecks/BSODs)
//! - Hangs (application not responding)
//! - Generic reports (custom application reports)
//!
//! # Dump Types
//!
//! - Minidump: Small dump with essential info
//! - Heap dump: Includes process heap
//! - Full dump: Complete process memory

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum queued reports
const MAX_REPORTS: usize = 64;

/// Maximum report name length
const MAX_REPORT_NAME: usize = 128;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Maximum application name length
const MAX_APP_NAME: usize = 64;

/// Maximum module name length
const MAX_MODULE_NAME: usize = 64;

/// Report type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportType {
    /// Application crash
    AppCrash = 0,
    /// Kernel crash (BSOD)
    KernelCrash = 1,
    /// Application hang
    AppHang = 2,
    /// Generic application report
    Generic = 3,
    /// Non-critical error
    NonCritical = 4,
}

impl ReportType {
    const fn empty() -> Self {
        ReportType::Generic
    }
}

/// Report status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportStatus {
    /// Report is queued
    Queued = 0,
    /// Report is being processed
    Processing = 1,
    /// Report is ready to submit
    Ready = 2,
    /// Report was submitted
    Submitted = 3,
    /// Report submission failed
    Failed = 4,
    /// User declined submission
    Declined = 5,
}

impl ReportStatus {
    const fn empty() -> Self {
        ReportStatus::Queued
    }
}

/// Dump type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpType {
    /// No dump
    None = 0,
    /// Minidump (small)
    Mini = 1,
    /// Minidump with heap
    MiniWithHeap = 2,
    /// Full dump
    Full = 3,
}

impl DumpType {
    const fn empty() -> Self {
        DumpType::None
    }
}

/// Exception information
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExceptionInfo {
    /// Exception code
    pub code: u32,
    /// Exception flags
    pub flags: u32,
    /// Exception address
    pub address: u64,
    /// Number of parameters
    pub num_params: u32,
    /// Exception parameters
    pub params: [u64; 4],
}

impl ExceptionInfo {
    const fn empty() -> Self {
        ExceptionInfo {
            code: 0,
            flags: 0,
            address: 0,
            num_params: 0,
            params: [0; 4],
        }
    }
}

/// Error report
#[repr(C)]
#[derive(Clone)]
pub struct ErrorReport {
    /// Report ID
    pub report_id: u64,
    /// Report type
    pub report_type: ReportType,
    /// Status
    pub status: ReportStatus,
    /// Application name
    pub app_name: [u8; MAX_APP_NAME],
    /// Application version
    pub app_version: u32,
    /// Module name (faulting)
    pub module_name: [u8; MAX_MODULE_NAME],
    /// Module version
    pub module_version: u32,
    /// Exception info
    pub exception: ExceptionInfo,
    /// Process ID
    pub process_id: u32,
    /// Thread ID
    pub thread_id: u32,
    /// Dump file path
    pub dump_path: [u8; MAX_PATH],
    /// Dump type
    pub dump_type: DumpType,
    /// Timestamp
    pub timestamp: i64,
    /// User consent given
    pub consent: bool,
    /// Entry is valid
    pub valid: bool,
}

impl ErrorReport {
    const fn empty() -> Self {
        ErrorReport {
            report_id: 0,
            report_type: ReportType::empty(),
            status: ReportStatus::empty(),
            app_name: [0; MAX_APP_NAME],
            app_version: 0,
            module_name: [0; MAX_MODULE_NAME],
            module_version: 0,
            exception: ExceptionInfo::empty(),
            process_id: 0,
            thread_id: 0,
            dump_path: [0; MAX_PATH],
            dump_type: DumpType::empty(),
            timestamp: 0,
            consent: false,
            valid: false,
        }
    }
}

/// Consent mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentMode {
    /// Always ask
    Ask = 0,
    /// Always send
    AlwaysSend = 1,
    /// Never send
    NeverSend = 2,
    /// Send parameters only
    SendParameters = 3,
}

/// WER configuration
#[repr(C)]
#[derive(Clone)]
pub struct WerConfig {
    /// Error reporting enabled
    pub enabled: bool,
    /// Consent mode
    pub consent_mode: ConsentMode,
    /// Create dumps
    pub create_dumps: bool,
    /// Default dump type
    pub dump_type: DumpType,
    /// Max reports to queue
    pub max_queue_size: usize,
    /// Queue path
    pub queue_path: [u8; MAX_PATH],
    /// Archive submitted reports
    pub archive_reports: bool,
    /// Notification timeout (seconds)
    pub notify_timeout: u32,
}

impl WerConfig {
    const fn default() -> Self {
        WerConfig {
            enabled: true,
            consent_mode: ConsentMode::Ask,
            create_dumps: true,
            dump_type: DumpType::Mini,
            max_queue_size: MAX_REPORTS,
            queue_path: [0; MAX_PATH],
            archive_reports: false,
            notify_timeout: 30,
        }
    }
}

/// WER service state
pub struct WerState {
    /// Service is running
    pub running: bool,
    /// Configuration
    pub config: WerConfig,
    /// Queued reports
    pub reports: [ErrorReport; MAX_REPORTS],
    /// Report count
    pub report_count: usize,
    /// Next report ID
    pub next_report_id: u64,
    /// Service start time
    pub start_time: i64,
}

impl WerState {
    const fn new() -> Self {
        WerState {
            running: false,
            config: WerConfig::default(),
            reports: [const { ErrorReport::empty() }; MAX_REPORTS],
            report_count: 0,
            next_report_id: 1,
            start_time: 0,
        }
    }
}

/// Global state
static WER_STATE: Mutex<WerState> = Mutex::new(WerState::new());

/// Statistics
static TOTAL_CRASHES: AtomicU64 = AtomicU64::new(0);
static REPORTS_CREATED: AtomicU64 = AtomicU64::new(0);
static REPORTS_SUBMITTED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize WER service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = WER_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Set default queue path
    let queue_path = b"C:\\Windows\\WER\\ReportQueue";
    state.config.queue_path[..queue_path.len()].copy_from_slice(queue_path);

    crate::serial_println!("[WERSVC] Windows Error Reporting service initialized");
}

/// Report an application crash
pub fn report_crash(
    app_name: &[u8],
    app_version: u32,
    module_name: &[u8],
    module_version: u32,
    exception: &ExceptionInfo,
    process_id: u32,
    thread_id: u32,
) -> Result<u64, u32> {
    report_error(
        ReportType::AppCrash,
        app_name,
        app_version,
        module_name,
        module_version,
        exception,
        process_id,
        thread_id,
    )
}

/// Report an application hang
pub fn report_hang(
    app_name: &[u8],
    app_version: u32,
    process_id: u32,
    thread_id: u32,
) -> Result<u64, u32> {
    report_error(
        ReportType::AppHang,
        app_name,
        app_version,
        b"",
        0,
        &ExceptionInfo::empty(),
        process_id,
        thread_id,
    )
}

/// Report a kernel crash
pub fn report_kernel_crash(
    bugcheck_code: u32,
    params: &[u64],
) -> Result<u64, u32> {
    let mut exception = ExceptionInfo::empty();
    exception.code = bugcheck_code;
    exception.num_params = params.len().min(4) as u32;
    for (i, &p) in params.iter().take(4).enumerate() {
        exception.params[i] = p;
    }

    report_error(
        ReportType::KernelCrash,
        b"ntoskrnl.exe",
        0,
        b"ntoskrnl.exe",
        0,
        &exception,
        0,
        0,
    )
}

/// Report a generic error
fn report_error(
    report_type: ReportType,
    app_name: &[u8],
    app_version: u32,
    module_name: &[u8],
    module_version: u32,
    exception: &ExceptionInfo,
    process_id: u32,
    thread_id: u32,
) -> Result<u64, u32> {
    let mut state = WER_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if !state.config.enabled {
        return Err(0x80070005); // Access denied (reporting disabled)
    }

    // Find free report slot
    let slot = state.reports.iter().position(|r| !r.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let report_id = state.next_report_id;
    state.next_report_id += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    let config_dump_type = state.config.dump_type;
    let auto_consent = state.config.consent_mode == ConsentMode::AlwaysSend;

    let report = &mut state.reports[slot];
    report.report_id = report_id;
    report.report_type = report_type;
    report.status = ReportStatus::Queued;

    let app_len = app_name.len().min(MAX_APP_NAME);
    report.app_name[..app_len].copy_from_slice(&app_name[..app_len]);
    report.app_version = app_version;

    let mod_len = module_name.len().min(MAX_MODULE_NAME);
    report.module_name[..mod_len].copy_from_slice(&module_name[..mod_len]);
    report.module_version = module_version;

    report.exception = *exception;
    report.process_id = process_id;
    report.thread_id = thread_id;
    report.dump_type = config_dump_type;
    report.timestamp = now;
    report.consent = auto_consent;
    report.valid = true;

    state.report_count += 1;

    if report_type == ReportType::AppCrash || report_type == ReportType::KernelCrash {
        TOTAL_CRASHES.fetch_add(1, Ordering::SeqCst);
    }
    REPORTS_CREATED.fetch_add(1, Ordering::SeqCst);

    Ok(report_id)
}

/// Get report status
pub fn get_report_status(report_id: u64) -> Option<ReportStatus> {
    let state = WER_STATE.lock();

    state.reports.iter()
        .find(|r| r.valid && r.report_id == report_id)
        .map(|r| r.status)
}

/// Set user consent for report
pub fn set_report_consent(report_id: u64, consent: bool) -> Result<(), u32> {
    let mut state = WER_STATE.lock();

    let report = state.reports.iter_mut()
        .find(|r| r.valid && r.report_id == report_id);

    match report {
        Some(r) => {
            r.consent = consent;
            if consent {
                r.status = ReportStatus::Ready;
            } else {
                r.status = ReportStatus::Declined;
            }
            Ok(())
        }
        None => Err(0x80070057),
    }
}

/// Submit a report
pub fn submit_report(report_id: u64) -> Result<(), u32> {
    let mut state = WER_STATE.lock();

    let report = state.reports.iter_mut()
        .find(|r| r.valid && r.report_id == report_id);

    let report = match report {
        Some(r) => r,
        None => return Err(0x80070057),
    };

    if !report.consent {
        return Err(0x80070005); // Access denied (no consent)
    }

    report.status = ReportStatus::Processing;

    // Simulate submission (in real impl would send to server)
    report.status = ReportStatus::Submitted;
    REPORTS_SUBMITTED.fetch_add(1, Ordering::SeqCst);

    Ok(())
}

/// Delete a report
pub fn delete_report(report_id: u64) -> Result<(), u32> {
    let mut state = WER_STATE.lock();

    let idx = state.reports.iter().position(|r| r.valid && r.report_id == report_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.reports[idx].valid = false;
    state.report_count = state.report_count.saturating_sub(1);

    Ok(())
}

/// Enumerate reports
pub fn enum_reports() -> ([ErrorReport; MAX_REPORTS], usize) {
    let state = WER_STATE.lock();
    let mut result = [const { ErrorReport::empty() }; MAX_REPORTS];
    let mut count = 0;

    for report in state.reports.iter() {
        if report.valid && count < MAX_REPORTS {
            result[count] = report.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get pending report count
pub fn get_pending_count() -> usize {
    let state = WER_STATE.lock();
    state.reports.iter()
        .filter(|r| r.valid && r.status == ReportStatus::Queued)
        .count()
}

/// Get configuration
pub fn get_config() -> WerConfig {
    let state = WER_STATE.lock();
    state.config.clone()
}

/// Set configuration
pub fn set_config(config: &WerConfig) {
    let mut state = WER_STATE.lock();
    state.config = config.clone();
}

/// Enable/disable error reporting
pub fn set_enabled(enabled: bool) {
    let mut state = WER_STATE.lock();
    state.config.enabled = enabled;
}

/// Set consent mode
pub fn set_consent_mode(mode: ConsentMode) {
    let mut state = WER_STATE.lock();
    state.config.consent_mode = mode;
}

/// Set dump type
pub fn set_dump_type(dump_type: DumpType) {
    let mut state = WER_STATE.lock();
    state.config.dump_type = dump_type;
}

/// Create exception info from bugcheck
pub fn create_exception_from_bugcheck(code: u32, p1: u64, p2: u64, p3: u64, p4: u64) -> ExceptionInfo {
    ExceptionInfo {
        code,
        flags: 0,
        address: 0,
        num_params: 4,
        params: [p1, p2, p3, p4],
    }
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64) {
    (
        TOTAL_CRASHES.load(Ordering::SeqCst),
        REPORTS_CREATED.load(Ordering::SeqCst),
        REPORTS_SUBMITTED.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = WER_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = WER_STATE.lock();
    state.running = false;
    crate::serial_println!("[WERSVC] Windows Error Reporting service stopped");
}
