//! Windows Error Reporting (WER)
//!
//! WER provides crash reporting and error collection functionality:
//!
//! - **Crash Dump Collection**: Captures minidump/full dump on crashes
//! - **Application Errors**: Reports application crashes and hangs
//! - **Kernel Errors**: Reports BSOD and kernel crashes
//! - **Problem Reports**: Queues reports for upload to Microsoft
//! - **Consent Management**: User consent for report submission
//!
//! # Report Types
//!
//! - Non-Critical: Application crashes, hangs
//! - Critical: Kernel crash, BSOD
//! - Generic: User-submitted reports
//!
//! # Registry Location
//!
//! `HKLM\Software\Microsoft\Windows\Windows Error Reporting`

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;
use alloc::vec::Vec;

// ============================================================================
// WER Constants
// ============================================================================

/// Maximum queued reports
pub const MAX_REPORTS: usize = 64;

/// Maximum parameters per report
pub const MAX_PARAMETERS: usize = 10;

/// Maximum parameter name length
pub const MAX_PARAM_NAME: usize = 64;

/// Maximum parameter value length
pub const MAX_PARAM_VALUE: usize = 256;

/// Maximum report description length
pub const MAX_DESCRIPTION: usize = 256;

/// Maximum bucket ID length (for grouping similar crashes)
pub const MAX_BUCKET_ID: usize = 64;

/// Maximum application name length
pub const MAX_APP_NAME: usize = 128;

/// Maximum module name length
pub const MAX_MODULE_NAME: usize = 128;

/// Maximum files per report
pub const MAX_FILES_PER_REPORT: usize = 8;

/// Maximum file path length
pub const MAX_FILE_PATH: usize = 260;

// ============================================================================
// Report Type
// ============================================================================

/// Type of error report
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum WerReportType {
    /// Non-critical application crash
    #[default]
    NonCritical = 0,
    /// Critical kernel error (BSOD)
    Critical = 1,
    /// Application hang
    ApplicationHang = 2,
    /// Kernel hang
    KernelHang = 3,
    /// Generic user-submitted report
    Generic = 4,
    /// Service crash
    ServiceCrash = 5,
    /// Driver crash
    DriverCrash = 6,
}

impl WerReportType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => WerReportType::NonCritical,
            1 => WerReportType::Critical,
            2 => WerReportType::ApplicationHang,
            3 => WerReportType::KernelHang,
            4 => WerReportType::Generic,
            5 => WerReportType::ServiceCrash,
            6 => WerReportType::DriverCrash,
            _ => WerReportType::NonCritical,
        }
    }

    /// Get severity level (0-3, 3 being most severe)
    pub fn severity(&self) -> u32 {
        match self {
            WerReportType::Generic => 0,
            WerReportType::NonCritical => 1,
            WerReportType::ApplicationHang | WerReportType::ServiceCrash => 2,
            WerReportType::Critical | WerReportType::KernelHang | WerReportType::DriverCrash => 3,
        }
    }
}

// ============================================================================
// Report Status
// ============================================================================

/// Status of an error report
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum WerReportStatus {
    /// Report queued for processing
    #[default]
    Queued = 0,
    /// Report is being collected
    Collecting = 1,
    /// Report ready for submission
    Ready = 2,
    /// Report submitted, awaiting response
    Submitted = 3,
    /// Report completed (response received)
    Completed = 4,
    /// Report failed
    Failed = 5,
    /// Report cancelled
    Cancelled = 6,
}

impl WerReportStatus {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => WerReportStatus::Queued,
            1 => WerReportStatus::Collecting,
            2 => WerReportStatus::Ready,
            3 => WerReportStatus::Submitted,
            4 => WerReportStatus::Completed,
            5 => WerReportStatus::Failed,
            6 => WerReportStatus::Cancelled,
            _ => WerReportStatus::Queued,
        }
    }
}

// ============================================================================
// Consent Type
// ============================================================================

/// User consent for error reporting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum WerConsent {
    /// Not yet determined
    #[default]
    NotAsked = 0,
    /// User denied reporting
    Denied = 1,
    /// User approved this report
    ApprovedThisTime = 2,
    /// User approved all reports (this type)
    ApprovedAlways = 3,
    /// System disabled (group policy)
    Disabled = 4,
}

// ============================================================================
// Dump Type
// ============================================================================

/// Type of crash dump to collect
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum WerDumpType {
    /// No dump
    None = 0,
    /// Minidump (small, stack + partial heap)
    #[default]
    MiniDump = 1,
    /// Heap dump (minidump + full heap)
    HeapDump = 2,
    /// Full dump (complete memory)
    FullDump = 3,
    /// Triage dump (minimal for triage)
    TriageDump = 4,
}

// ============================================================================
// Error Codes
// ============================================================================

/// WER error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WerError {
    /// Success
    Success = 0,
    /// Invalid parameter
    InvalidParameter = 0x80070057,
    /// Not enough memory
    OutOfMemory = 0x8007000E,
    /// Maximum reports reached
    MaxReportsReached = 0x8007000F,
    /// Report not found
    ReportNotFound = 0x80070002,
    /// Operation cancelled
    Cancelled = 0x800704C7,
    /// Consent denied
    ConsentDenied = 0x80070005,
    /// Reporting disabled
    Disabled = 0x80070422,
    /// Network error
    NetworkError = 0x800700EA,
    /// Invalid state
    InvalidState = 0x80070013,
}

// ============================================================================
// Report Parameter
// ============================================================================

/// Single parameter in a WER report
#[repr(C)]
pub struct WerParameter {
    /// Parameter name
    pub name: [u8; MAX_PARAM_NAME],
    /// Parameter value
    pub value: [u8; MAX_PARAM_VALUE],
    /// Parameter in use
    pub valid: bool,
}

impl WerParameter {
    pub const fn empty() -> Self {
        Self {
            name: [0; MAX_PARAM_NAME],
            value: [0; MAX_PARAM_VALUE],
            valid: false,
        }
    }

    pub fn set(&mut self, name: &str, value: &str) {
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(MAX_PARAM_NAME - 1);
        self.name[..name_len].copy_from_slice(&name_bytes[..name_len]);
        self.name[name_len] = 0;

        let value_bytes = value.as_bytes();
        let value_len = value_bytes.len().min(MAX_PARAM_VALUE - 1);
        self.value[..value_len].copy_from_slice(&value_bytes[..value_len]);
        self.value[value_len] = 0;

        self.valid = true;
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_PARAM_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn value_str(&self) -> &str {
        let len = self.value.iter().position(|&b| b == 0).unwrap_or(MAX_PARAM_VALUE);
        core::str::from_utf8(&self.value[..len]).unwrap_or("")
    }
}

// ============================================================================
// Report File
// ============================================================================

/// File attached to a WER report
#[repr(C)]
pub struct WerReportFile {
    /// File path
    pub path: [u8; MAX_FILE_PATH],
    /// File type (log, dump, etc.)
    pub file_type: WerFileType,
    /// File flags
    pub flags: u32,
    /// File valid
    pub valid: bool,
}

impl WerReportFile {
    pub const fn empty() -> Self {
        Self {
            path: [0; MAX_FILE_PATH],
            file_type: WerFileType::Other,
            flags: 0,
            valid: false,
        }
    }

    pub fn set_path(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_FILE_PATH - 1);
        self.path[..len].copy_from_slice(&bytes[..len]);
        self.path[len] = 0;
    }

    pub fn path_str(&self) -> &str {
        let len = self.path.iter().position(|&b| b == 0).unwrap_or(MAX_FILE_PATH);
        core::str::from_utf8(&self.path[..len]).unwrap_or("")
    }
}

/// Type of file in report
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum WerFileType {
    /// Minidump file
    MiniDump = 1,
    /// Heap dump file
    HeapDump = 2,
    /// User document
    UserDocument = 3,
    /// Other file
    #[default]
    Other = 4,
}

// ============================================================================
// Exception Info
// ============================================================================

/// Exception information for crash reports
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WerExceptionInfo {
    /// Exception code
    pub exception_code: u32,
    /// Exception flags
    pub exception_flags: u32,
    /// Faulting address
    pub exception_address: u64,
    /// Thread ID
    pub thread_id: u32,
    /// Process ID
    pub process_id: u32,
    /// Number of parameters
    pub number_parameters: u32,
    /// Exception parameters
    pub exception_information: [u64; 4],
}

impl WerExceptionInfo {
    pub const fn new() -> Self {
        Self {
            exception_code: 0,
            exception_flags: 0,
            exception_address: 0,
            thread_id: 0,
            process_id: 0,
            number_parameters: 0,
            exception_information: [0; 4],
        }
    }
}

// ============================================================================
// Report
// ============================================================================

/// WER Report
#[repr(C)]
pub struct WerReport {
    /// Report ID (unique)
    pub report_id: u64,
    /// Report type
    pub report_type: WerReportType,
    /// Current status
    pub status: AtomicU32,
    /// Consent status
    pub consent: WerConsent,

    /// Application name
    pub app_name: [u8; MAX_APP_NAME],
    /// Module name (faulting)
    pub module_name: [u8; MAX_MODULE_NAME],
    /// Description
    pub description: [u8; MAX_DESCRIPTION],
    /// Bucket ID (for grouping)
    pub bucket_id: [u8; MAX_BUCKET_ID],

    /// Report parameters
    pub parameters: [WerParameter; MAX_PARAMETERS],
    /// Parameter count
    pub param_count: usize,

    /// Attached files
    pub files: [WerReportFile; MAX_FILES_PER_REPORT],
    /// File count
    pub file_count: usize,

    /// Exception information
    pub exception_info: WerExceptionInfo,
    /// Has exception info
    pub has_exception: bool,

    /// Dump type requested
    pub dump_type: WerDumpType,
    /// Dump collected
    pub dump_collected: bool,

    /// Creation time
    pub creation_time: u64,
    /// Submission time
    pub submission_time: u64,

    /// Report valid
    pub valid: bool,
}

impl WerReport {
    pub const fn empty() -> Self {
        Self {
            report_id: 0,
            report_type: WerReportType::NonCritical,
            status: AtomicU32::new(WerReportStatus::Queued as u32),
            consent: WerConsent::NotAsked,
            app_name: [0; MAX_APP_NAME],
            module_name: [0; MAX_MODULE_NAME],
            description: [0; MAX_DESCRIPTION],
            bucket_id: [0; MAX_BUCKET_ID],
            parameters: [const { WerParameter::empty() }; MAX_PARAMETERS],
            param_count: 0,
            files: [const { WerReportFile::empty() }; MAX_FILES_PER_REPORT],
            file_count: 0,
            exception_info: WerExceptionInfo::new(),
            has_exception: false,
            dump_type: WerDumpType::MiniDump,
            dump_collected: false,
            creation_time: 0,
            submission_time: 0,
            valid: false,
        }
    }

    /// Get status
    pub fn get_status(&self) -> WerReportStatus {
        WerReportStatus::from_u32(self.status.load(Ordering::SeqCst))
    }

    /// Set status
    pub fn set_status(&self, status: WerReportStatus) {
        self.status.store(status as u32, Ordering::SeqCst);
    }

    /// Set application name
    pub fn set_app_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_APP_NAME - 1);
        self.app_name[..len].copy_from_slice(&bytes[..len]);
        self.app_name[len] = 0;
    }

    pub fn app_name_str(&self) -> &str {
        let len = self.app_name.iter().position(|&b| b == 0).unwrap_or(MAX_APP_NAME);
        core::str::from_utf8(&self.app_name[..len]).unwrap_or("")
    }

    /// Set module name
    pub fn set_module_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_MODULE_NAME - 1);
        self.module_name[..len].copy_from_slice(&bytes[..len]);
        self.module_name[len] = 0;
    }

    pub fn module_name_str(&self) -> &str {
        let len = self.module_name.iter().position(|&b| b == 0).unwrap_or(MAX_MODULE_NAME);
        core::str::from_utf8(&self.module_name[..len]).unwrap_or("")
    }

    /// Set description
    pub fn set_description(&mut self, desc: &str) {
        let bytes = desc.as_bytes();
        let len = bytes.len().min(MAX_DESCRIPTION - 1);
        self.description[..len].copy_from_slice(&bytes[..len]);
        self.description[len] = 0;
    }

    /// Add parameter
    pub fn add_parameter(&mut self, name: &str, value: &str) -> Result<(), WerError> {
        if self.param_count >= MAX_PARAMETERS {
            return Err(WerError::MaxReportsReached);
        }

        self.parameters[self.param_count].set(name, value);
        self.param_count += 1;
        Ok(())
    }

    /// Add file to report
    pub fn add_file(&mut self, path: &str, file_type: WerFileType) -> Result<(), WerError> {
        if self.file_count >= MAX_FILES_PER_REPORT {
            return Err(WerError::MaxReportsReached);
        }

        let file = &mut self.files[self.file_count];
        file.set_path(path);
        file.file_type = file_type;
        file.valid = true;
        self.file_count += 1;
        Ok(())
    }

    /// Set exception info
    pub fn set_exception(&mut self, info: WerExceptionInfo) {
        self.exception_info = info;
        self.has_exception = true;
    }

    /// Generate bucket ID from crash parameters
    pub fn generate_bucket_id(&mut self) {
        // Simple bucket ID: AppName_ExceptionCode_ModuleName
        let app = self.app_name_str();
        let module = self.module_name_str();
        let code = if self.has_exception {
            self.exception_info.exception_code
        } else {
            0
        };

        let bucket = if !app.is_empty() && !module.is_empty() {
            // Format: first 16 chars of app + code + first 16 of module
            let app_part = if app.len() > 16 { &app[..16] } else { app };
            let mod_part = if module.len() > 16 { &module[..16] } else { module };

            let mut bucket_str = [0u8; MAX_BUCKET_ID];
            let mut pos = 0;

            for b in app_part.bytes() {
                if pos < MAX_BUCKET_ID - 1 {
                    bucket_str[pos] = b;
                    pos += 1;
                }
            }
            if pos < MAX_BUCKET_ID - 1 {
                bucket_str[pos] = b'_';
                pos += 1;
            }

            // Add exception code as hex
            let hex_chars = b"0123456789ABCDEF";
            for i in (0..8).rev() {
                if pos < MAX_BUCKET_ID - 1 {
                    bucket_str[pos] = hex_chars[((code >> (i * 4)) & 0xF) as usize];
                    pos += 1;
                }
            }

            if pos < MAX_BUCKET_ID - 1 {
                bucket_str[pos] = b'_';
                pos += 1;
            }

            for b in mod_part.bytes() {
                if pos < MAX_BUCKET_ID - 1 {
                    bucket_str[pos] = b;
                    pos += 1;
                }
            }

            bucket_str
        } else {
            [0u8; MAX_BUCKET_ID]
        };

        self.bucket_id = bucket;
    }
}

// ============================================================================
// WER Configuration
// ============================================================================

/// WER configuration
#[repr(C)]
pub struct WerConfig {
    /// Enable error reporting
    pub enabled: bool,
    /// Auto-submit reports (no UI)
    pub auto_submit: bool,
    /// Default consent level
    pub default_consent: WerConsent,
    /// Collect full dumps
    pub collect_full_dump: bool,
    /// Maximum dump size (MB)
    pub max_dump_size_mb: u32,
    /// Queue max size
    pub max_queue_size: u32,
    /// Disable Windows Error Reporting service
    pub disabled_by_policy: bool,
    /// Log events to event log
    pub log_to_event_log: bool,
}

impl WerConfig {
    pub const fn new() -> Self {
        Self {
            enabled: true,
            auto_submit: false,
            default_consent: WerConsent::NotAsked,
            collect_full_dump: false,
            max_dump_size_mb: 256,
            max_queue_size: MAX_REPORTS as u32,
            disabled_by_policy: false,
            log_to_event_log: true,
        }
    }
}

// ============================================================================
// WER State
// ============================================================================

/// WER service state
#[repr(C)]
pub struct WerState {
    /// Configuration
    pub config: WerConfig,
    /// Report queue
    pub reports: [WerReport; MAX_REPORTS],
    /// Report count
    pub report_count: usize,
    /// Next report ID
    pub next_report_id: u64,
    /// Service initialized
    pub initialized: bool,
}

impl WerState {
    pub const fn new() -> Self {
        Self {
            config: WerConfig::new(),
            reports: [const { WerReport::empty() }; MAX_REPORTS],
            report_count: 0,
            next_report_id: 1,
            initialized: false,
        }
    }
}

/// Global WER state
static WER_STATE: SpinLock<WerState> = SpinLock::new(WerState::new());

/// WER statistics
pub struct WerStats {
    /// Total reports created
    pub reports_created: AtomicU64,
    /// Reports submitted
    pub reports_submitted: AtomicU64,
    /// Reports completed
    pub reports_completed: AtomicU64,
    /// Reports failed
    pub reports_failed: AtomicU64,
    /// Reports cancelled
    pub reports_cancelled: AtomicU64,
    /// Consent denied
    pub consent_denied: AtomicU64,
    /// Dumps collected
    pub dumps_collected: AtomicU64,
    /// Critical reports
    pub critical_reports: AtomicU64,
}

impl WerStats {
    pub const fn new() -> Self {
        Self {
            reports_created: AtomicU64::new(0),
            reports_submitted: AtomicU64::new(0),
            reports_completed: AtomicU64::new(0),
            reports_failed: AtomicU64::new(0),
            reports_cancelled: AtomicU64::new(0),
            consent_denied: AtomicU64::new(0),
            dumps_collected: AtomicU64::new(0),
            critical_reports: AtomicU64::new(0),
        }
    }
}

static WER_STATS: WerStats = WerStats::new();

// ============================================================================
// WER API
// ============================================================================

/// Create a new error report
pub fn create_report(
    report_type: WerReportType,
    app_name: &str,
) -> Result<u64, WerError> {
    let mut state = WER_STATE.lock();

    if !state.initialized {
        return Err(WerError::Disabled);
    }

    if state.config.disabled_by_policy {
        return Err(WerError::Disabled);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_REPORTS {
        if !state.reports[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(WerError::MaxReportsReached),
    };

    // Create report
    let report_id = state.next_report_id;
    state.next_report_id += 1;

    let current_time = crate::hal::apic::get_tick_count();
    let default_consent = state.config.default_consent;
    let default_dump = if state.config.collect_full_dump {
        WerDumpType::FullDump
    } else {
        WerDumpType::MiniDump
    };

    let report = &mut state.reports[slot];
    *report = WerReport::empty();
    report.report_id = report_id;
    report.report_type = report_type;
    report.set_app_name(app_name);
    report.consent = default_consent;
    report.dump_type = default_dump;
    report.creation_time = current_time;
    report.valid = true;

    state.report_count += 1;

    WER_STATS.reports_created.fetch_add(1, Ordering::Relaxed);

    if report_type.severity() >= 3 {
        WER_STATS.critical_reports.fetch_add(1, Ordering::Relaxed);
    }

    crate::serial_println!("[WER] Created report {} for '{}' (type={:?})",
        report_id, app_name, report_type);

    Ok(report_id)
}

/// Add exception info to report
pub fn set_report_exception(report_id: u64, info: WerExceptionInfo) -> Result<(), WerError> {
    let mut state = WER_STATE.lock();

    let report = find_report_mut(&mut state, report_id)?;

    if report.get_status() != WerReportStatus::Queued {
        return Err(WerError::InvalidState);
    }

    report.set_exception(info);

    crate::serial_println!("[WER] Report {}: Exception code 0x{:08X} at 0x{:016X}",
        report_id, info.exception_code, info.exception_address);

    Ok(())
}

/// Add parameter to report
pub fn add_report_parameter(
    report_id: u64,
    name: &str,
    value: &str,
) -> Result<(), WerError> {
    let mut state = WER_STATE.lock();

    let report = find_report_mut(&mut state, report_id)?;

    if report.get_status() != WerReportStatus::Queued {
        return Err(WerError::InvalidState);
    }

    report.add_parameter(name, value)
}

/// Add file to report
pub fn add_report_file(
    report_id: u64,
    path: &str,
    file_type: WerFileType,
) -> Result<(), WerError> {
    let mut state = WER_STATE.lock();

    let report = find_report_mut(&mut state, report_id)?;

    if report.get_status() != WerReportStatus::Queued &&
       report.get_status() != WerReportStatus::Collecting {
        return Err(WerError::InvalidState);
    }

    report.add_file(path, file_type)
}

/// Submit report for processing
pub fn submit_report(report_id: u64, consent: WerConsent) -> Result<(), WerError> {
    let mut state = WER_STATE.lock();

    let report = find_report_mut(&mut state, report_id)?;

    let current_status = report.get_status();
    if current_status != WerReportStatus::Queued &&
       current_status != WerReportStatus::Ready {
        return Err(WerError::InvalidState);
    }

    // Check consent
    if consent == WerConsent::Denied {
        report.set_status(WerReportStatus::Cancelled);
        WER_STATS.consent_denied.fetch_add(1, Ordering::Relaxed);
        return Err(WerError::ConsentDenied);
    }

    report.consent = consent;
    report.generate_bucket_id();

    let current_time = crate::hal::apic::get_tick_count();
    report.submission_time = current_time;
    report.set_status(WerReportStatus::Submitted);

    WER_STATS.reports_submitted.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[WER] Report {} submitted (bucket: {})",
        report_id,
        core::str::from_utf8(&report.bucket_id)
            .unwrap_or("")
            .trim_end_matches('\0'));

    Ok(())
}

/// Cancel a report
pub fn cancel_report(report_id: u64) -> Result<(), WerError> {
    let mut state = WER_STATE.lock();

    let report = find_report_mut(&mut state, report_id)?;

    report.set_status(WerReportStatus::Cancelled);
    report.valid = false;
    state.report_count = state.report_count.saturating_sub(1);

    WER_STATS.reports_cancelled.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[WER] Report {} cancelled", report_id);

    Ok(())
}

/// Get report status
pub fn get_report_status(report_id: u64) -> Result<WerReportStatus, WerError> {
    let state = WER_STATE.lock();

    for i in 0..MAX_REPORTS {
        if state.reports[i].valid && state.reports[i].report_id == report_id {
            return Ok(state.reports[i].get_status());
        }
    }

    Err(WerError::ReportNotFound)
}

/// Enumerate pending reports
pub fn enumerate_reports() -> Vec<u64> {
    let state = WER_STATE.lock();
    let mut result = Vec::new();

    for i in 0..MAX_REPORTS {
        if state.reports[i].valid {
            result.push(state.reports[i].report_id);
        }
    }

    result
}

// ============================================================================
// Crash Dump Collection
// ============================================================================

/// Collect crash dump for report
pub fn collect_dump(report_id: u64, dump_type: WerDumpType) -> Result<(), WerError> {
    let mut state = WER_STATE.lock();

    let report = find_report_mut(&mut state, report_id)?;

    if report.get_status() != WerReportStatus::Queued &&
       report.get_status() != WerReportStatus::Collecting {
        return Err(WerError::InvalidState);
    }

    report.set_status(WerReportStatus::Collecting);
    report.dump_type = dump_type;

    // In a real implementation, this would:
    // 1. Suspend the target process
    // 2. Create a minidump/full dump file
    // 3. Add it to the report files

    let dump_path = "\\SystemRoot\\Temp\\crash.dmp";
    let _ = report.add_file(dump_path, WerFileType::MiniDump);

    report.dump_collected = true;
    report.set_status(WerReportStatus::Ready);

    WER_STATS.dumps_collected.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[WER] Report {}: Collected {:?} dump", report_id, dump_type);

    Ok(())
}

// ============================================================================
// Process Reports
// ============================================================================

/// Process pending reports (called periodically)
pub fn process_reports() {
    let mut state = WER_STATE.lock();

    if !state.initialized {
        return;
    }

    for i in 0..MAX_REPORTS {
        if !state.reports[i].valid {
            continue;
        }

        let status = state.reports[i].get_status();

        match status {
            WerReportStatus::Submitted => {
                // Simulate server response
                // In real implementation, this would send to Watson server
                state.reports[i].set_status(WerReportStatus::Completed);
                WER_STATS.reports_completed.fetch_add(1, Ordering::Relaxed);

                let report_id = state.reports[i].report_id;
                crate::serial_println!("[WER] Report {} completed", report_id);
            }
            WerReportStatus::Completed | WerReportStatus::Failed | WerReportStatus::Cancelled => {
                // Clean up old reports (after some time)
                // For now, just mark as invalid
                state.reports[i].valid = false;
                state.report_count = state.report_count.saturating_sub(1);
            }
            _ => {}
        }
    }
}

// ============================================================================
// Application Crash Reporting
// ============================================================================

/// Report application crash (high-level API)
pub fn report_application_crash(
    app_name: &str,
    module_name: &str,
    exception_code: u32,
    exception_address: u64,
    process_id: u32,
    thread_id: u32,
) -> Result<u64, WerError> {
    // Create report
    let report_id = create_report(WerReportType::NonCritical, app_name)?;

    // Set module
    {
        let mut state = WER_STATE.lock();
        if let Ok(report) = find_report_mut(&mut state, report_id) {
            report.set_module_name(module_name);
            report.set_description("Application has stopped working");
        }
    }

    // Set exception
    let exception = WerExceptionInfo {
        exception_code,
        exception_flags: 0,
        exception_address,
        thread_id,
        process_id,
        number_parameters: 0,
        exception_information: [0; 4],
    };
    set_report_exception(report_id, exception)?;

    // Add standard parameters
    add_report_parameter(report_id, "Application", app_name)?;
    add_report_parameter(report_id, "Module", module_name)?;

    // Collect dump
    collect_dump(report_id, WerDumpType::MiniDump)?;

    Ok(report_id)
}

/// Report kernel crash (BSOD)
pub fn report_kernel_crash(
    bug_check_code: u32,
    params: [u64; 4],
) -> Result<u64, WerError> {
    let report_id = create_report(WerReportType::Critical, "ntoskrnl.exe")?;

    {
        let mut state = WER_STATE.lock();
        if let Ok(report) = find_report_mut(&mut state, report_id) {
            report.set_module_name("ntoskrnl.exe");
            report.set_description("System crash (Blue Screen)");
        }
    }

    let exception = WerExceptionInfo {
        exception_code: bug_check_code,
        exception_flags: 0,
        exception_address: 0,
        thread_id: 0,
        process_id: 0,
        number_parameters: 4,
        exception_information: params,
    };
    set_report_exception(report_id, exception)?;

    // Add bugcheck parameters
    let hex_buf = format_hex(bug_check_code as u64);
    let hex_str = core::str::from_utf8(&hex_buf).unwrap_or("0x00000000");
    let _ = add_report_parameter(report_id, "BugCheckCode", hex_str);

    // Add parameter 1-4
    let param_names = ["Parameter1", "Parameter2", "Parameter3", "Parameter4"];
    for i in 0..4 {
        let hex_buf = format_hex(params[i]);
        let hex_str = core::str::from_utf8(&hex_buf).unwrap_or("0x00000000");
        let _ = add_report_parameter(report_id, param_names[i], hex_str);
    }

    // Collect full dump for kernel crashes
    collect_dump(report_id, WerDumpType::FullDump)?;

    // Auto-submit critical reports
    submit_report(report_id, WerConsent::ApprovedAlways)?;

    Ok(report_id)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Find report by ID (mutable)
fn find_report_mut(state: &mut WerState, report_id: u64) -> Result<&mut WerReport, WerError> {
    for i in 0..MAX_REPORTS {
        if state.reports[i].valid && state.reports[i].report_id == report_id {
            return Ok(&mut state.reports[i]);
        }
    }
    Err(WerError::ReportNotFound)
}

/// Format u64 as hex string (simple version)
fn format_hex(value: u64) -> [u8; 18] {
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';

    let hex_chars = b"0123456789ABCDEF";
    for i in 0..16 {
        buf[2 + i] = hex_chars[((value >> ((15 - i) * 4)) & 0xF) as usize];
    }

    buf
}

/// Format helper that returns string
fn format_hex_str(value: u64) -> &'static str {
    // This is a simplified version - in real implementation would use proper formatting
    "0x00000000"
}

/// Get WER statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        WER_STATS.reports_created.load(Ordering::Relaxed),
        WER_STATS.reports_submitted.load(Ordering::Relaxed),
        WER_STATS.reports_completed.load(Ordering::Relaxed),
        WER_STATS.reports_failed.load(Ordering::Relaxed),
        WER_STATS.reports_cancelled.load(Ordering::Relaxed),
        WER_STATS.consent_denied.load(Ordering::Relaxed),
        WER_STATS.dumps_collected.load(Ordering::Relaxed),
        WER_STATS.critical_reports.load(Ordering::Relaxed),
    )
}

/// Get pending report count
pub fn get_report_count() -> usize {
    let state = WER_STATE.lock();
    state.report_count
}

/// Check if WER is enabled
pub fn is_enabled() -> bool {
    let state = WER_STATE.lock();
    state.initialized && state.config.enabled && !state.config.disabled_by_policy
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize WER service
pub fn init() {
    crate::serial_println!("[WER] Initializing Windows Error Reporting...");

    let mut state = WER_STATE.lock();
    state.initialized = true;

    crate::serial_println!("[WER] WER initialized (max {} reports)",
        state.config.max_queue_size);
}

/// Shutdown WER service
pub fn shutdown() {
    crate::serial_println!("[WER] Shutting down WER...");

    let mut state = WER_STATE.lock();

    // Cancel pending reports
    for i in 0..MAX_REPORTS {
        if state.reports[i].valid {
            state.reports[i].set_status(WerReportStatus::Cancelled);
        }
    }

    state.initialized = false;

    let (created, submitted, completed, _, _, _, dumps, critical) = get_statistics();
    crate::serial_println!("[WER] Stats: {} created, {} submitted, {} completed, {} dumps, {} critical",
        created, submitted, completed, dumps, critical);
}
