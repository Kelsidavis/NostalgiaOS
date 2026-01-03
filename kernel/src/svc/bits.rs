//! Background Intelligent Transfer Service (BITS)
//!
//! BITS provides reliable, asynchronous file transfer between machines using idle
//! network bandwidth. Key features:
//!
//! - **Background Transfer**: Uses only idle network bandwidth
//! - **Resume Support**: Transfers resume after disconnect/reboot
//! - **Priority Levels**: Foreground, high, normal, low
//! - **Job Management**: Create, suspend, resume, cancel, complete
//! - **Error Recovery**: Automatic retry with exponential backoff
//! - **Cost Awareness**: Can restrict transfers on metered networks
//!
//! # Architecture
//!
//! BITS manages transfer jobs, each containing one or more files:
//! - Jobs are persisted to survive reboots
//! - Files are transferred using HTTP/HTTPS GET (download) or POST (upload)
//! - Range requests enable resume from partial transfers
//!
//! # Registry Location
//!
//! `HKLM\Software\Microsoft\Windows\CurrentVersion\BITS`

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;
use alloc::vec::Vec;

// ============================================================================
// BITS Constants
// ============================================================================

/// Maximum concurrent jobs
pub const MAX_BITS_JOBS: usize = 64;

/// Maximum files per job
pub const MAX_FILES_PER_JOB: usize = 16;

/// Maximum URL length
pub const MAX_URL_LENGTH: usize = 256;

/// Maximum local path length
pub const MAX_PATH_LENGTH: usize = 260;

/// Maximum job name length
pub const MAX_JOB_NAME: usize = 64;

/// Maximum error description length
pub const MAX_ERROR_DESC: usize = 128;

/// Default chunk size for transfers (256KB)
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Minimum retry delay (seconds)
pub const MIN_RETRY_DELAY: u32 = 60;

/// Maximum retry delay (seconds)
pub const MAX_RETRY_DELAY: u32 = 3600;

/// Maximum retry count before job fails
pub const MAX_RETRY_COUNT: u32 = 80;

// ============================================================================
// Job Priority
// ============================================================================

/// BITS job priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum BitsJobPriority {
    /// Use all available bandwidth (immediate user request)
    Foreground = 0,
    /// High priority background transfer
    High = 1,
    /// Normal priority background transfer
    #[default]
    Normal = 2,
    /// Low priority (use minimal bandwidth)
    Low = 3,
}

impl BitsJobPriority {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => BitsJobPriority::Foreground,
            1 => BitsJobPriority::High,
            2 => BitsJobPriority::Normal,
            3 => BitsJobPriority::Low,
            _ => BitsJobPriority::Normal,
        }
    }

    /// Get bandwidth allocation percentage
    pub fn bandwidth_percent(&self) -> u32 {
        match self {
            BitsJobPriority::Foreground => 100,
            BitsJobPriority::High => 75,
            BitsJobPriority::Normal => 50,
            BitsJobPriority::Low => 25,
        }
    }
}

// ============================================================================
// Job State
// ============================================================================

/// BITS job state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum BitsJobState {
    /// Job is queued but not transferring
    #[default]
    Queued = 0,
    /// Job is connecting to server
    Connecting = 1,
    /// Job is actively transferring
    Transferring = 2,
    /// Job is suspended by user
    Suspended = 3,
    /// Job has a transient error (will retry)
    TransientError = 4,
    /// Job has a fatal error
    Error = 5,
    /// Job transfer completed, waiting for acknowledge
    Transferred = 6,
    /// Job was acknowledged/completed
    Acknowledged = 7,
    /// Job was cancelled
    Cancelled = 8,
}

impl BitsJobState {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => BitsJobState::Queued,
            1 => BitsJobState::Connecting,
            2 => BitsJobState::Transferring,
            3 => BitsJobState::Suspended,
            4 => BitsJobState::TransientError,
            5 => BitsJobState::Error,
            6 => BitsJobState::Transferred,
            7 => BitsJobState::Acknowledged,
            8 => BitsJobState::Cancelled,
            _ => BitsJobState::Queued,
        }
    }

    /// Check if job can be modified
    pub fn is_modifiable(&self) -> bool {
        matches!(self,
            BitsJobState::Queued |
            BitsJobState::Suspended |
            BitsJobState::TransientError |
            BitsJobState::Error
        )
    }

    /// Check if job is active
    pub fn is_active(&self) -> bool {
        matches!(self,
            BitsJobState::Queued |
            BitsJobState::Connecting |
            BitsJobState::Transferring
        )
    }
}

// ============================================================================
// Job Type
// ============================================================================

/// BITS job type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum BitsJobType {
    /// Download files from server
    #[default]
    Download = 0,
    /// Upload files to server
    Upload = 1,
    /// Upload with reply from server
    UploadReply = 2,
}

impl BitsJobType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => BitsJobType::Download,
            1 => BitsJobType::Upload,
            2 => BitsJobType::UploadReply,
            _ => BitsJobType::Download,
        }
    }
}

// ============================================================================
// Error Codes
// ============================================================================

/// BITS error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BitsError {
    /// Success
    Success = 0,
    /// Job not found
    JobNotFound = 0x80200001,
    /// Invalid parameter
    InvalidParameter = 0x80200002,
    /// Out of memory
    OutOfMemory = 0x80200003,
    /// Job already exists
    JobAlreadyExists = 0x80200004,
    /// File not found on server
    FileNotFound = 0x80200005,
    /// Access denied
    AccessDenied = 0x80200006,
    /// Network error
    NetworkError = 0x80200007,
    /// Server error (5xx)
    ServerError = 0x80200008,
    /// Invalid state for operation
    InvalidState = 0x80200009,
    /// Maximum jobs reached
    MaxJobsReached = 0x8020000A,
    /// Maximum files reached
    MaxFilesReached = 0x8020000B,
    /// Transfer cancelled
    Cancelled = 0x8020000C,
    /// Session error
    SessionError = 0x8020000D,
    /// Invalid URL
    InvalidUrl = 0x8020000E,
    /// Proxy error
    ProxyError = 0x8020000F,
    /// Authentication required
    AuthRequired = 0x80200010,
    /// Disk full
    DiskFull = 0x80200011,
    /// File in use
    FileInUse = 0x80200012,
    /// Operation timed out
    Timeout = 0x80200013,
}

// ============================================================================
// File Info
// ============================================================================

/// BITS file transfer information
#[repr(C)]
pub struct BitsFileInfo {
    /// Remote URL
    pub remote_url: [u8; MAX_URL_LENGTH],
    /// Local file path
    pub local_path: [u8; MAX_PATH_LENGTH],
    /// Total file size (0 if unknown)
    pub total_size: u64,
    /// Bytes transferred
    pub bytes_transferred: u64,
    /// File completed flag
    pub completed: bool,
    /// Valid entry flag
    pub valid: bool,
}

impl BitsFileInfo {
    pub const fn empty() -> Self {
        Self {
            remote_url: [0; MAX_URL_LENGTH],
            local_path: [0; MAX_PATH_LENGTH],
            total_size: 0,
            bytes_transferred: 0,
            completed: false,
            valid: false,
        }
    }

    /// Get remote URL as string
    pub fn remote_url_str(&self) -> &str {
        let len = self.remote_url.iter().position(|&b| b == 0).unwrap_or(MAX_URL_LENGTH);
        core::str::from_utf8(&self.remote_url[..len]).unwrap_or("")
    }

    /// Set remote URL
    pub fn set_remote_url(&mut self, url: &str) {
        let bytes = url.as_bytes();
        let len = bytes.len().min(MAX_URL_LENGTH - 1);
        self.remote_url[..len].copy_from_slice(&bytes[..len]);
        self.remote_url[len] = 0;
    }

    /// Get local path as string
    pub fn local_path_str(&self) -> &str {
        let len = self.local_path.iter().position(|&b| b == 0).unwrap_or(MAX_PATH_LENGTH);
        core::str::from_utf8(&self.local_path[..len]).unwrap_or("")
    }

    /// Set local path
    pub fn set_local_path(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_PATH_LENGTH - 1);
        self.local_path[..len].copy_from_slice(&bytes[..len]);
        self.local_path[len] = 0;
    }

    /// Get transfer progress (0-100)
    pub fn progress(&self) -> u32 {
        if self.total_size == 0 {
            return 0;
        }
        ((self.bytes_transferred * 100) / self.total_size) as u32
    }
}

// ============================================================================
// Job Progress
// ============================================================================

/// BITS job progress information
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BitsJobProgress {
    /// Total bytes to transfer (all files)
    pub bytes_total: u64,
    /// Bytes transferred so far
    pub bytes_transferred: u64,
    /// Total number of files
    pub files_total: u32,
    /// Files transferred
    pub files_transferred: u32,
}

impl BitsJobProgress {
    pub const fn new() -> Self {
        Self {
            bytes_total: 0,
            bytes_transferred: 0,
            files_total: 0,
            files_transferred: 0,
        }
    }

    /// Get overall progress percentage (0-100)
    pub fn percent(&self) -> u32 {
        if self.bytes_total == 0 {
            return 0;
        }
        ((self.bytes_transferred * 100) / self.bytes_total) as u32
    }
}

// ============================================================================
// Job Times
// ============================================================================

/// BITS job time information
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BitsJobTimes {
    /// Job creation time
    pub creation_time: u64,
    /// Job modification time
    pub modification_time: u64,
    /// Transfer completion time
    pub transfer_completion_time: u64,
}

impl BitsJobTimes {
    pub const fn new() -> Self {
        Self {
            creation_time: 0,
            modification_time: 0,
            transfer_completion_time: 0,
        }
    }
}

// ============================================================================
// Job
// ============================================================================

/// BITS job
#[repr(C)]
pub struct BitsJob {
    /// Job ID (GUID-like unique identifier)
    pub job_id: u64,
    /// Job name
    pub name: [u8; MAX_JOB_NAME],
    /// Job type
    pub job_type: BitsJobType,
    /// Current state
    pub state: AtomicU32,
    /// Priority
    pub priority: BitsJobPriority,
    /// Owner SID (simplified as u32)
    pub owner_sid: u32,

    /// Files in this job
    pub files: [BitsFileInfo; MAX_FILES_PER_JOB],
    /// Number of files
    pub file_count: usize,

    /// Job times
    pub times: BitsJobTimes,
    /// Job progress
    pub progress: BitsJobProgress,

    /// Error code (if in error state)
    pub error_code: u32,
    /// Error description
    pub error_desc: [u8; MAX_ERROR_DESC],
    /// Error context (file index or -1)
    pub error_context: i32,

    /// Retry count for current error
    pub retry_count: u32,
    /// Next retry time (tick count)
    pub next_retry_time: u64,
    /// Current retry delay (seconds)
    pub retry_delay: u32,

    /// Notification flags
    pub notify_flags: u32,
    /// Callback command line (for notification)
    pub notify_cmdline: [u8; MAX_PATH_LENGTH],

    /// Proxy settings
    pub proxy_usage: ProxyUsage,

    /// Cost flags (for metered connections)
    pub cost_flags: u32,

    /// Valid entry
    pub valid: bool,
}

impl BitsJob {
    pub const fn empty() -> Self {
        Self {
            job_id: 0,
            name: [0; MAX_JOB_NAME],
            job_type: BitsJobType::Download,
            state: AtomicU32::new(BitsJobState::Queued as u32),
            priority: BitsJobPriority::Normal,
            owner_sid: 0,
            files: [const { BitsFileInfo::empty() }; MAX_FILES_PER_JOB],
            file_count: 0,
            times: BitsJobTimes::new(),
            progress: BitsJobProgress::new(),
            error_code: 0,
            error_desc: [0; MAX_ERROR_DESC],
            error_context: -1,
            retry_count: 0,
            next_retry_time: 0,
            retry_delay: MIN_RETRY_DELAY,
            notify_flags: 0,
            notify_cmdline: [0; MAX_PATH_LENGTH],
            proxy_usage: ProxyUsage::Preconfig,
            cost_flags: 0,
            valid: false,
        }
    }

    /// Get job name as string
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_JOB_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    /// Set job name
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_JOB_NAME - 1);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0;
    }

    /// Get current state
    pub fn get_state(&self) -> BitsJobState {
        BitsJobState::from_u32(self.state.load(Ordering::SeqCst))
    }

    /// Set state
    pub fn set_state(&self, state: BitsJobState) {
        self.state.store(state as u32, Ordering::SeqCst);
    }

    /// Add a file to the job
    pub fn add_file(&mut self, remote_url: &str, local_path: &str) -> Result<(), BitsError> {
        if self.file_count >= MAX_FILES_PER_JOB {
            return Err(BitsError::MaxFilesReached);
        }

        let file = &mut self.files[self.file_count];
        file.set_remote_url(remote_url);
        file.set_local_path(local_path);
        file.valid = true;
        file.total_size = 0;
        file.bytes_transferred = 0;
        file.completed = false;

        self.file_count += 1;
        self.progress.files_total += 1;

        Ok(())
    }

    /// Set error state
    pub fn set_error(&mut self, error: BitsError, context: i32, desc: &str) {
        self.error_code = error as u32;
        self.error_context = context;

        let bytes = desc.as_bytes();
        let len = bytes.len().min(MAX_ERROR_DESC - 1);
        self.error_desc[..len].copy_from_slice(&bytes[..len]);
        self.error_desc[len] = 0;

        // Determine if transient or fatal
        let transient = matches!(error,
            BitsError::NetworkError |
            BitsError::ServerError |
            BitsError::Timeout
        );

        if transient && self.retry_count < MAX_RETRY_COUNT {
            self.set_state(BitsJobState::TransientError);
        } else {
            self.set_state(BitsJobState::Error);
        }
    }

    /// Schedule retry with exponential backoff
    pub fn schedule_retry(&mut self, current_time: u64) {
        self.retry_count += 1;

        // Exponential backoff: delay * 2^retry (capped)
        let new_delay = self.retry_delay.saturating_mul(2).min(MAX_RETRY_DELAY);
        self.retry_delay = new_delay;

        // Schedule next retry
        self.next_retry_time = current_time + (new_delay as u64 * 1000);
    }

    /// Reset retry state
    pub fn reset_retry(&mut self) {
        self.retry_count = 0;
        self.retry_delay = MIN_RETRY_DELAY;
        self.next_retry_time = 0;
        self.error_code = 0;
        self.error_context = -1;
        self.error_desc[0] = 0;
    }

    /// Update progress from files
    pub fn update_progress(&mut self) {
        let mut total: u64 = 0;
        let mut transferred: u64 = 0;
        let mut completed: u32 = 0;

        for i in 0..self.file_count {
            if self.files[i].valid {
                total += self.files[i].total_size;
                transferred += self.files[i].bytes_transferred;
                if self.files[i].completed {
                    completed += 1;
                }
            }
        }

        self.progress.bytes_total = total;
        self.progress.bytes_transferred = transferred;
        self.progress.files_transferred = completed;
    }
}

// ============================================================================
// Proxy Usage
// ============================================================================

/// Proxy usage settings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum ProxyUsage {
    /// Use system proxy settings (IE/WinHTTP)
    #[default]
    Preconfig = 0,
    /// No proxy
    NoProxy = 1,
    /// Override with specific proxy
    Override = 2,
    /// Auto-detect proxy
    AutoDetect = 3,
}

// ============================================================================
// Notification Flags
// ============================================================================

/// Notification callback flags
pub mod notify_flags {
    /// Notify when job transfers to Transferred state
    pub const JOB_TRANSFERRED: u32 = 0x0001;
    /// Notify on job error
    pub const JOB_ERROR: u32 = 0x0002;
    /// Disable notifications
    pub const DISABLE: u32 = 0x0004;
    /// Notify on file transfer complete
    pub const FILE_TRANSFERRED: u32 = 0x0008;
}

// ============================================================================
// Cost Flags
// ============================================================================

/// Network cost flags
pub mod cost_flags {
    /// Transfer on metered networks
    pub const TRANSFER_IF_METERED: u32 = 0x0001;
    /// Transfer when roaming
    pub const TRANSFER_IF_ROAMING: u32 = 0x0002;
    /// Transfer on expensive networks
    pub const TRANSFER_IF_EXPENSIVE: u32 = 0x0004;
    /// No cost restrictions (always transfer)
    pub const NO_RESTRICTIONS: u32 = 0x0008;
}

// ============================================================================
// BITS State
// ============================================================================

/// BITS service configuration
#[repr(C)]
pub struct BitsConfig {
    /// Maximum concurrent transfers
    pub max_concurrent: u32,
    /// Default priority for new jobs
    pub default_priority: BitsJobPriority,
    /// Enable background downloads
    pub background_enabled: bool,
    /// Maximum bandwidth percentage (1-100)
    pub max_bandwidth_percent: u32,
    /// Transfer on battery power
    pub transfer_on_battery: bool,
    /// Use BITS cache
    pub use_cache: bool,
}

impl BitsConfig {
    pub const fn new() -> Self {
        Self {
            max_concurrent: 4,
            default_priority: BitsJobPriority::Normal,
            background_enabled: true,
            max_bandwidth_percent: 100,
            transfer_on_battery: true,
            use_cache: true,
        }
    }
}

/// BITS service state
#[repr(C)]
pub struct BitsState {
    /// Service configuration
    pub config: BitsConfig,
    /// Active jobs
    pub jobs: [BitsJob; MAX_BITS_JOBS],
    /// Number of active jobs
    pub job_count: usize,
    /// Next job ID
    pub next_job_id: u64,
    /// Service running flag
    pub running: bool,
}

impl BitsState {
    pub const fn new() -> Self {
        Self {
            config: BitsConfig::new(),
            jobs: [const { BitsJob::empty() }; MAX_BITS_JOBS],
            job_count: 0,
            next_job_id: 1,
            running: false,
        }
    }
}

/// Global BITS state
static BITS_STATE: SpinLock<BitsState> = SpinLock::new(BitsState::new());

/// BITS statistics
static BITS_STATS: BitsStats = BitsStats::new();

/// BITS statistics
pub struct BitsStats {
    /// Total jobs created
    pub jobs_created: AtomicU64,
    /// Total jobs completed
    pub jobs_completed: AtomicU64,
    /// Total jobs failed
    pub jobs_failed: AtomicU64,
    /// Total jobs cancelled
    pub jobs_cancelled: AtomicU64,
    /// Total bytes downloaded
    pub bytes_downloaded: AtomicU64,
    /// Total bytes uploaded
    pub bytes_uploaded: AtomicU64,
    /// Total files transferred
    pub files_transferred: AtomicU64,
    /// Total transfer errors
    pub transfer_errors: AtomicU64,
    /// Total retries
    pub retry_count: AtomicU64,
}

impl BitsStats {
    pub const fn new() -> Self {
        Self {
            jobs_created: AtomicU64::new(0),
            jobs_completed: AtomicU64::new(0),
            jobs_failed: AtomicU64::new(0),
            jobs_cancelled: AtomicU64::new(0),
            bytes_downloaded: AtomicU64::new(0),
            bytes_uploaded: AtomicU64::new(0),
            files_transferred: AtomicU64::new(0),
            transfer_errors: AtomicU64::new(0),
            retry_count: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// BITS API
// ============================================================================

/// Create a new BITS job
pub fn create_job(
    name: &str,
    job_type: BitsJobType,
    owner_sid: u32,
) -> Result<u64, BitsError> {
    let mut state = BITS_STATE.lock();

    if !state.running {
        return Err(BitsError::SessionError);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_BITS_JOBS {
        if !state.jobs[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(BitsError::MaxJobsReached),
    };

    // Create job
    let job_id = state.next_job_id;
    state.next_job_id += 1;

    let current_time = crate::hal::apic::get_tick_count();
    let default_priority = state.config.default_priority;

    let job = &mut state.jobs[slot];
    *job = BitsJob::empty();
    job.job_id = job_id;
    job.set_name(name);
    job.job_type = job_type;
    job.owner_sid = owner_sid;
    job.priority = default_priority;
    job.times.creation_time = current_time;
    job.times.modification_time = current_time;
    job.valid = true;

    state.job_count += 1;

    BITS_STATS.jobs_created.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[BITS] Created job {} '{}' type={:?}",
        job_id, name, job_type);

    Ok(job_id)
}

/// Add file to job
pub fn add_file_to_job(
    job_id: u64,
    remote_url: &str,
    local_path: &str,
) -> Result<(), BitsError> {
    let mut state = BITS_STATE.lock();

    // Find job
    let job_idx = find_job_index(&state, job_id)?;

    // Check state
    if !state.jobs[job_idx].get_state().is_modifiable() {
        return Err(BitsError::InvalidState);
    }

    state.jobs[job_idx].add_file(remote_url, local_path)?;

    let current_time = crate::hal::apic::get_tick_count();
    state.jobs[job_idx].times.modification_time = current_time;

    crate::serial_println!("[BITS] Job {}: Added file {} -> {}",
        job_id, remote_url, local_path);

    Ok(())
}

/// Resume a job (start/continue transfer)
pub fn resume_job(job_id: u64) -> Result<(), BitsError> {
    let state = BITS_STATE.lock();

    let job_idx = find_job_index(&state, job_id)?;

    let current_state = state.jobs[job_idx].get_state();

    match current_state {
        BitsJobState::Queued |
        BitsJobState::Suspended |
        BitsJobState::TransientError => {
            state.jobs[job_idx].set_state(BitsJobState::Queued);
            crate::serial_println!("[BITS] Job {} resumed", job_id);
            Ok(())
        }
        _ => Err(BitsError::InvalidState),
    }
}

/// Suspend a job
pub fn suspend_job(job_id: u64) -> Result<(), BitsError> {
    let mut state = BITS_STATE.lock();

    let job_idx = find_job_index(&state, job_id)?;

    let current_state = state.jobs[job_idx].get_state();

    if current_state.is_active() {
        state.jobs[job_idx].set_state(BitsJobState::Suspended);

        let current_time = crate::hal::apic::get_tick_count();
        state.jobs[job_idx].times.modification_time = current_time;

        crate::serial_println!("[BITS] Job {} suspended", job_id);
        Ok(())
    } else {
        Err(BitsError::InvalidState)
    }
}

/// Cancel a job
pub fn cancel_job(job_id: u64) -> Result<(), BitsError> {
    let mut state = BITS_STATE.lock();

    let job_idx = find_job_index(&state, job_id)?;

    state.jobs[job_idx].set_state(BitsJobState::Cancelled);
    state.jobs[job_idx].valid = false;
    state.job_count = state.job_count.saturating_sub(1);

    BITS_STATS.jobs_cancelled.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[BITS] Job {} cancelled", job_id);

    Ok(())
}

/// Complete/acknowledge a finished job
pub fn complete_job(job_id: u64) -> Result<(), BitsError> {
    let mut state = BITS_STATE.lock();

    let job_idx = find_job_index(&state, job_id)?;

    let current_state = state.jobs[job_idx].get_state();

    if current_state != BitsJobState::Transferred {
        return Err(BitsError::InvalidState);
    }

    state.jobs[job_idx].set_state(BitsJobState::Acknowledged);
    state.jobs[job_idx].valid = false;
    state.job_count = state.job_count.saturating_sub(1);

    BITS_STATS.jobs_completed.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[BITS] Job {} completed and acknowledged", job_id);

    Ok(())
}

/// Set job priority
pub fn set_job_priority(job_id: u64, priority: BitsJobPriority) -> Result<(), BitsError> {
    let mut state = BITS_STATE.lock();

    let job_idx = find_job_index(&state, job_id)?;

    state.jobs[job_idx].priority = priority;

    let current_time = crate::hal::apic::get_tick_count();
    state.jobs[job_idx].times.modification_time = current_time;

    crate::serial_println!("[BITS] Job {} priority set to {:?}", job_id, priority);

    Ok(())
}

/// Get job state
pub fn get_job_state(job_id: u64) -> Result<BitsJobState, BitsError> {
    let state = BITS_STATE.lock();
    let job_idx = find_job_index(&state, job_id)?;
    Ok(state.jobs[job_idx].get_state())
}

/// Get job progress
pub fn get_job_progress(job_id: u64) -> Result<BitsJobProgress, BitsError> {
    let state = BITS_STATE.lock();
    let job_idx = find_job_index(&state, job_id)?;
    Ok(state.jobs[job_idx].progress)
}

/// Get job error info
pub fn get_job_error(job_id: u64) -> Result<(u32, i32), BitsError> {
    let state = BITS_STATE.lock();
    let job_idx = find_job_index(&state, job_id)?;
    Ok((state.jobs[job_idx].error_code, state.jobs[job_idx].error_context))
}

/// Enumerate all jobs for an owner
pub fn enumerate_jobs(owner_sid: u32) -> Vec<u64> {
    let state = BITS_STATE.lock();
    let mut result = Vec::new();

    for i in 0..MAX_BITS_JOBS {
        if state.jobs[i].valid && state.jobs[i].owner_sid == owner_sid {
            result.push(state.jobs[i].job_id);
        }
    }

    result
}

/// Set notification flags
pub fn set_notify_flags(job_id: u64, flags: u32) -> Result<(), BitsError> {
    let mut state = BITS_STATE.lock();

    let job_idx = find_job_index(&state, job_id)?;

    state.jobs[job_idx].notify_flags = flags;

    Ok(())
}

/// Set notification command line
pub fn set_notify_cmdline(job_id: u64, cmdline: &str) -> Result<(), BitsError> {
    let mut state = BITS_STATE.lock();

    let job_idx = find_job_index(&state, job_id)?;

    let bytes = cmdline.as_bytes();
    let len = bytes.len().min(MAX_PATH_LENGTH - 1);
    state.jobs[job_idx].notify_cmdline[..len].copy_from_slice(&bytes[..len]);
    state.jobs[job_idx].notify_cmdline[len] = 0;

    Ok(())
}

// ============================================================================
// Transfer Engine
// ============================================================================

/// Process pending transfers (called periodically)
pub fn process_transfers() {
    let state = BITS_STATE.lock();

    if !state.running {
        return;
    }

    let current_time = crate::hal::apic::get_tick_count();

    // Count active transfers
    let mut active_count = 0;
    for i in 0..MAX_BITS_JOBS {
        if state.jobs[i].valid {
            let job_state = state.jobs[i].get_state();
            if matches!(job_state, BitsJobState::Connecting | BitsJobState::Transferring) {
                active_count += 1;
            }
        }
    }

    let max_concurrent = state.config.max_concurrent;

    // Process jobs by priority
    for priority in [BitsJobPriority::Foreground, BitsJobPriority::High,
                     BitsJobPriority::Normal, BitsJobPriority::Low] {
        if active_count >= max_concurrent {
            break;
        }

        for i in 0..MAX_BITS_JOBS {
            if !state.jobs[i].valid {
                continue;
            }

            if state.jobs[i].priority != priority {
                continue;
            }

            let job_state = state.jobs[i].get_state();

            match job_state {
                BitsJobState::Queued => {
                    if active_count < max_concurrent {
                        // Start transfer
                        state.jobs[i].set_state(BitsJobState::Connecting);
                        active_count += 1;
                        crate::serial_println!("[BITS] Starting job {}", state.jobs[i].job_id);
                    }
                }
                BitsJobState::TransientError => {
                    // Check if retry time reached
                    let next_retry = state.jobs[i].next_retry_time;
                    if next_retry > 0 && current_time >= next_retry {
                        if active_count < max_concurrent {
                            state.jobs[i].set_state(BitsJobState::Connecting);
                            active_count += 1;
                            BITS_STATS.retry_count.fetch_add(1, Ordering::Relaxed);
                            crate::serial_println!("[BITS] Retrying job {} (attempt {})",
                                state.jobs[i].job_id, state.jobs[i].retry_count);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Simulate transfer progress (for testing)
pub fn simulate_transfer_progress(job_id: u64, bytes: u64) -> Result<(), BitsError> {
    let mut state = BITS_STATE.lock();

    let job_idx = find_job_index(&state, job_id)?;

    let job_state = state.jobs[job_idx].get_state();
    if job_state != BitsJobState::Transferring && job_state != BitsJobState::Connecting {
        return Err(BitsError::InvalidState);
    }

    // Set to transferring
    state.jobs[job_idx].set_state(BitsJobState::Transferring);

    // Find current file being transferred
    for i in 0..state.jobs[job_idx].file_count {
        if state.jobs[job_idx].files[i].valid && !state.jobs[job_idx].files[i].completed {
            let file = &mut state.jobs[job_idx].files[i];
            file.bytes_transferred += bytes;

            // Check if file complete
            if file.total_size > 0 && file.bytes_transferred >= file.total_size {
                file.completed = true;
                BITS_STATS.files_transferred.fetch_add(1, Ordering::Relaxed);
            }
            break;
        }
    }

    // Update job progress
    state.jobs[job_idx].update_progress();

    // Check if all files complete
    let mut all_complete = true;
    let file_count = state.jobs[job_idx].file_count;
    for i in 0..file_count {
        if state.jobs[job_idx].files[i].valid && !state.jobs[job_idx].files[i].completed {
            all_complete = false;
            break;
        }
    }

    if all_complete && file_count > 0 {
        let current_time = crate::hal::apic::get_tick_count();
        state.jobs[job_idx].times.transfer_completion_time = current_time;
        state.jobs[job_idx].set_state(BitsJobState::Transferred);

        crate::serial_println!("[BITS] Job {} transfer complete", job_id);

        // Track bytes by type
        let total_bytes = state.jobs[job_idx].progress.bytes_transferred;
        match state.jobs[job_idx].job_type {
            BitsJobType::Download => {
                BITS_STATS.bytes_downloaded.fetch_add(total_bytes, Ordering::Relaxed);
            }
            BitsJobType::Upload | BitsJobType::UploadReply => {
                BITS_STATS.bytes_uploaded.fetch_add(total_bytes, Ordering::Relaxed);
            }
        }
    }

    Ok(())
}

/// Set file size (normally determined by HTTP Content-Length)
pub fn set_file_size(job_id: u64, file_index: usize, size: u64) -> Result<(), BitsError> {
    let mut state = BITS_STATE.lock();

    let job_idx = find_job_index(&state, job_id)?;

    if file_index >= state.jobs[job_idx].file_count {
        return Err(BitsError::InvalidParameter);
    }

    state.jobs[job_idx].files[file_index].total_size = size;
    state.jobs[job_idx].update_progress();

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Find job index by ID
fn find_job_index(state: &BitsState, job_id: u64) -> Result<usize, BitsError> {
    for i in 0..MAX_BITS_JOBS {
        if state.jobs[i].valid && state.jobs[i].job_id == job_id {
            return Ok(i);
        }
    }
    Err(BitsError::JobNotFound)
}

/// Get BITS statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        BITS_STATS.jobs_created.load(Ordering::Relaxed),
        BITS_STATS.jobs_completed.load(Ordering::Relaxed),
        BITS_STATS.jobs_failed.load(Ordering::Relaxed),
        BITS_STATS.jobs_cancelled.load(Ordering::Relaxed),
        BITS_STATS.bytes_downloaded.load(Ordering::Relaxed),
        BITS_STATS.bytes_uploaded.load(Ordering::Relaxed),
        BITS_STATS.files_transferred.load(Ordering::Relaxed),
        BITS_STATS.transfer_errors.load(Ordering::Relaxed),
        BITS_STATS.retry_count.load(Ordering::Relaxed),
    )
}

/// Check if BITS is running
pub fn is_running() -> bool {
    let state = BITS_STATE.lock();
    state.running
}

/// Get active job count
pub fn get_job_count() -> usize {
    let state = BITS_STATE.lock();
    state.job_count
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize BITS service
pub fn init() {
    crate::serial_println!("[BITS] Initializing Background Intelligent Transfer Service...");

    let mut state = BITS_STATE.lock();
    state.running = true;

    crate::serial_println!("[BITS] BITS initialized (max {} concurrent transfers)",
        state.config.max_concurrent);
}

/// Shutdown BITS service
pub fn shutdown() {
    crate::serial_println!("[BITS] Shutting down BITS...");

    let mut state = BITS_STATE.lock();

    // Suspend all active jobs
    for i in 0..MAX_BITS_JOBS {
        if state.jobs[i].valid {
            let job_state = state.jobs[i].get_state();
            if job_state.is_active() {
                state.jobs[i].set_state(BitsJobState::Suspended);
            }
        }
    }

    state.running = false;

    let (created, completed, failed, cancelled, _, _, _, _, _) = get_statistics();
    crate::serial_println!("[BITS] Stats: {} created, {} completed, {} failed, {} cancelled",
        created, completed, failed, cancelled);
}
