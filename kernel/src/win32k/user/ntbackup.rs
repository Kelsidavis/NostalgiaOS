//! Backup Utility
//!
//! Implements the Windows Backup utility following Windows Server 2003.
//! Provides file backup, restore, and scheduling capabilities.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - ntbackup.exe - Windows Backup Utility
//! - Backup Wizard, Restore Wizard, Scheduled Jobs
//! - System State backup

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum backup jobs
const MAX_JOBS: usize = 32;

/// Maximum backup sets
const MAX_SETS: usize = 64;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Maximum name length
const MAX_NAME: usize = 128;

// ============================================================================
// Backup Type
// ============================================================================

/// Backup type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackupType {
    /// Normal (Full) - backs up all selected files, clears archive bit
    #[default]
    Normal = 0,
    /// Copy - backs up all selected files, does not clear archive bit
    Copy = 1,
    /// Incremental - backs up files with archive bit set, clears archive bit
    Incremental = 2,
    /// Differential - backs up files with archive bit set, does not clear
    Differential = 3,
    /// Daily - backs up files modified today, does not clear archive bit
    Daily = 4,
}

impl BackupType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BackupType::Normal => "Normal",
            BackupType::Copy => "Copy",
            BackupType::Incremental => "Incremental",
            BackupType::Differential => "Differential",
            BackupType::Daily => "Daily",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            BackupType::Normal => "Backs up all selected files and marks each as backed up",
            BackupType::Copy => "Backs up all selected files but does not mark them as backed up",
            BackupType::Incremental => "Backs up only files created or changed since last backup",
            BackupType::Differential => "Backs up files changed since last normal backup",
            BackupType::Daily => "Backs up only files modified today",
        }
    }
}

// ============================================================================
// Backup Status
// ============================================================================

/// Backup job status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackupStatus {
    /// Pending
    #[default]
    Pending = 0,
    /// Running
    Running = 1,
    /// Completed successfully
    Completed = 2,
    /// Completed with warnings
    CompletedWarnings = 3,
    /// Failed
    Failed = 4,
    /// Cancelled
    Cancelled = 5,
}

impl BackupStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            BackupStatus::Pending => "Pending",
            BackupStatus::Running => "Running",
            BackupStatus::Completed => "Completed",
            BackupStatus::CompletedWarnings => "Completed with warnings",
            BackupStatus::Failed => "Failed",
            BackupStatus::Cancelled => "Cancelled",
        }
    }
}

// ============================================================================
// Restore Options
// ============================================================================

/// Restore location option
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestoreLocation {
    /// Original location
    #[default]
    OriginalLocation = 0,
    /// Alternate location
    AlternateLocation = 1,
    /// Single folder
    SingleFolder = 2,
}

/// File replacement option
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReplaceOption {
    /// Leave existing files
    #[default]
    LeaveExisting = 0,
    /// Replace if backup is newer
    ReplaceIfNewer = 1,
    /// Always replace
    AlwaysReplace = 2,
}

// ============================================================================
// Backup Selection
// ============================================================================

/// What to back up
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackupSelection {
    /// All files on this computer
    #[default]
    AllFiles = 0,
    /// Selected files, folders, or drives
    SelectedItems = 1,
    /// System State only
    SystemStateOnly = 2,
}

// ============================================================================
// System State Components
// ============================================================================

bitflags::bitflags! {
    /// System State backup components
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SystemStateFlags: u32 {
        const BOOT_FILES = 0x0001;
        const COM_DATABASE = 0x0002;
        const REGISTRY = 0x0004;
        const SYSVOL = 0x0008;
        const ACTIVE_DIRECTORY = 0x0010;
        const CERTIFICATE_SERVICES = 0x0020;
        const CLUSTER_DATABASE = 0x0040;
        const IIS_METABASE = 0x0080;

        const DEFAULT = Self::BOOT_FILES.bits() | Self::REGISTRY.bits();
    }
}

// ============================================================================
// Backup Set
// ============================================================================

/// Backup set (catalog entry)
#[derive(Debug, Clone, Copy)]
pub struct BackupSet {
    /// Set ID
    pub set_id: u32,
    /// Backup label
    pub label: [u8; MAX_NAME],
    /// Label length
    pub label_len: usize,
    /// Backup type
    pub backup_type: BackupType,
    /// Backup date/time
    pub backup_time: u64,
    /// Media name
    pub media_name: [u8; 64],
    /// Media name length
    pub media_len: usize,
    /// Total files
    pub total_files: u32,
    /// Total bytes
    pub total_bytes: u64,
    /// Includes System State
    pub has_system_state: bool,
    /// System state components
    pub system_state: SystemStateFlags,
}

impl BackupSet {
    pub const fn new() -> Self {
        Self {
            set_id: 0,
            label: [0u8; MAX_NAME],
            label_len: 0,
            backup_type: BackupType::Normal,
            backup_time: 0,
            media_name: [0u8; 64],
            media_len: 0,
            total_files: 0,
            total_bytes: 0,
            has_system_state: false,
            system_state: SystemStateFlags::empty(),
        }
    }

    pub fn set_label(&mut self, label: &[u8]) {
        let len = label.len().min(MAX_NAME);
        self.label[..len].copy_from_slice(&label[..len]);
        self.label_len = len;
    }

    pub fn set_media(&mut self, media: &[u8]) {
        let len = media.len().min(64);
        self.media_name[..len].copy_from_slice(&media[..len]);
        self.media_len = len;
    }
}

impl Default for BackupSet {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Backup Job
// ============================================================================

/// Backup job
#[derive(Debug, Clone, Copy)]
pub struct BackupJob {
    /// Job ID
    pub job_id: u32,
    /// Job name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Backup selection
    pub selection: BackupSelection,
    /// Backup type
    pub backup_type: BackupType,
    /// Destination path
    pub destination: [u8; MAX_PATH],
    /// Destination length
    pub dest_len: usize,
    /// Include System State
    pub include_system_state: bool,
    /// System state components
    pub system_state: SystemStateFlags,
    /// Verify after backup
    pub verify_after: bool,
    /// Use hardware compression
    pub hardware_compression: bool,
    /// Disable volume shadow copy
    pub disable_vss: bool,
    /// Status
    pub status: BackupStatus,
    /// Last run time
    pub last_run: u64,
    /// Next run time (scheduled)
    pub next_run: u64,
    /// Progress (0-100)
    pub progress: u8,
    /// Files processed
    pub files_processed: u32,
    /// Bytes processed
    pub bytes_processed: u64,
    /// Schedule enabled
    pub scheduled: bool,
}

impl BackupJob {
    pub const fn new() -> Self {
        Self {
            job_id: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            selection: BackupSelection::AllFiles,
            backup_type: BackupType::Normal,
            destination: [0u8; MAX_PATH],
            dest_len: 0,
            include_system_state: true,
            system_state: SystemStateFlags::DEFAULT,
            verify_after: true,
            hardware_compression: false,
            disable_vss: false,
            status: BackupStatus::Pending,
            last_run: 0,
            next_run: 0,
            progress: 0,
            files_processed: 0,
            bytes_processed: 0,
            scheduled: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_destination(&mut self, dest: &[u8]) {
        let len = dest.len().min(MAX_PATH);
        self.destination[..len].copy_from_slice(&dest[..len]);
        self.dest_len = len;
    }
}

impl Default for BackupJob {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Restore Job
// ============================================================================

/// Restore job
#[derive(Debug, Clone, Copy)]
pub struct RestoreJob {
    /// Job ID
    pub job_id: u32,
    /// Source backup set ID
    pub backup_set_id: u32,
    /// Restore location option
    pub location: RestoreLocation,
    /// Alternate path (if applicable)
    pub alternate_path: [u8; MAX_PATH],
    /// Alternate path length
    pub alt_path_len: usize,
    /// Replace option
    pub replace_option: ReplaceOption,
    /// Restore security settings
    pub restore_security: bool,
    /// Restore junction points
    pub restore_junctions: bool,
    /// Restore System State
    pub restore_system_state: bool,
    /// Status
    pub status: BackupStatus,
    /// Progress (0-100)
    pub progress: u8,
    /// Files restored
    pub files_restored: u32,
}

impl RestoreJob {
    pub const fn new() -> Self {
        Self {
            job_id: 0,
            backup_set_id: 0,
            location: RestoreLocation::OriginalLocation,
            alternate_path: [0u8; MAX_PATH],
            alt_path_len: 0,
            replace_option: ReplaceOption::LeaveExisting,
            restore_security: true,
            restore_junctions: false,
            restore_system_state: false,
            status: BackupStatus::Pending,
            progress: 0,
            files_restored: 0,
        }
    }
}

impl Default for RestoreJob {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Backup State
// ============================================================================

/// Backup utility state
struct BackupState {
    /// Backup jobs
    jobs: [BackupJob; MAX_JOBS],
    /// Job count
    job_count: usize,
    /// Next job ID
    next_job_id: u32,
    /// Backup catalog (sets)
    catalog: [BackupSet; MAX_SETS],
    /// Catalog count
    catalog_count: usize,
    /// Next set ID
    next_set_id: u32,
    /// Current restore job
    restore_job: RestoreJob,
    /// Restore in progress
    restoring: bool,
    /// Active backup job index
    active_job: Option<usize>,
    /// Default backup type
    default_type: BackupType,
    /// Log file path
    log_path: [u8; MAX_PATH],
    /// Log path length
    log_path_len: usize,
}

impl BackupState {
    pub const fn new() -> Self {
        Self {
            jobs: [const { BackupJob::new() }; MAX_JOBS],
            job_count: 0,
            next_job_id: 1,
            catalog: [const { BackupSet::new() }; MAX_SETS],
            catalog_count: 0,
            next_set_id: 1,
            restore_job: RestoreJob::new(),
            restoring: false,
            active_job: None,
            default_type: BackupType::Normal,
            log_path: [0u8; MAX_PATH],
            log_path_len: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static BACKUP_INITIALIZED: AtomicBool = AtomicBool::new(false);
static BACKUP_STATE: SpinLock<BackupState> = SpinLock::new(BackupState::new());

// Statistics
static BACKUPS_COMPLETED: AtomicU32 = AtomicU32::new(0);
static RESTORES_COMPLETED: AtomicU32 = AtomicU32::new(0);
static TOTAL_BYTES_BACKED: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Backup Utility
pub fn init() {
    if BACKUP_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = BACKUP_STATE.lock();

    // Add sample backup catalog
    add_sample_catalog(&mut state);

    // Set default log path
    let log = b"C:\\Documents and Settings\\All Users\\Application Data\\Microsoft\\Windows NT\\NTBackup\\data\\backup.log";
    let len = log.len().min(MAX_PATH);
    state.log_path[..len].copy_from_slice(&log[..len]);
    state.log_path_len = len;

    crate::serial_println!("[WIN32K] Backup Utility initialized");
}

/// Add sample backup catalog
fn add_sample_catalog(state: &mut BackupState) {
    let sets: [(&[u8], BackupType, u64, u32, u64); 3] = [
        (b"System State Backup", BackupType::Normal, 1104537600, 1250, 524_288_000),
        (b"Full Server Backup", BackupType::Normal, 1104624000, 15420, 10_737_418_240),
        (b"Incremental Backup", BackupType::Incremental, 1104710400, 342, 104_857_600),
    ];

    for (label, btype, time, files, bytes) in sets.iter() {
        if state.catalog_count >= MAX_SETS {
            break;
        }

        let mut set = BackupSet::new();
        set.set_id = state.next_set_id;
        state.next_set_id += 1;
        set.set_label(label);
        set.backup_type = *btype;
        set.backup_time = *time;
        set.set_media(b"Backup001.bkf");
        set.total_files = *files;
        set.total_bytes = *bytes;
        set.has_system_state = true;
        set.system_state = SystemStateFlags::DEFAULT;

        let idx = state.catalog_count;
        state.catalog[idx] = set;
        state.catalog_count += 1;
    }
}

// ============================================================================
// Backup Job Management
// ============================================================================

/// Create backup job
pub fn create_job(name: &[u8], backup_type: BackupType, destination: &[u8]) -> Option<u32> {
    let mut state = BACKUP_STATE.lock();
    if state.job_count >= MAX_JOBS {
        return None;
    }

    let job_id = state.next_job_id;
    state.next_job_id += 1;

    let mut job = BackupJob::new();
    job.job_id = job_id;
    job.set_name(name);
    job.backup_type = backup_type;
    job.set_destination(destination);

    let idx = state.job_count;
    state.jobs[idx] = job;
    state.job_count += 1;

    Some(job_id)
}

/// Get backup job count
pub fn get_job_count() -> usize {
    BACKUP_STATE.lock().job_count
}

/// Get backup job by index
pub fn get_job(index: usize) -> Option<BackupJob> {
    let state = BACKUP_STATE.lock();
    if index < state.job_count {
        Some(state.jobs[index])
    } else {
        None
    }
}

/// Get backup job by ID
pub fn get_job_by_id(job_id: u32) -> Option<BackupJob> {
    let state = BACKUP_STATE.lock();
    for i in 0..state.job_count {
        if state.jobs[i].job_id == job_id {
            return Some(state.jobs[i]);
        }
    }
    None
}

/// Delete backup job
pub fn delete_job(job_id: u32) -> bool {
    let mut state = BACKUP_STATE.lock();

    let mut found_index = None;
    for i in 0..state.job_count {
        if state.jobs[i].job_id == job_id {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..state.job_count - 1 {
            state.jobs[i] = state.jobs[i + 1];
        }
        state.job_count -= 1;
        true
    } else {
        false
    }
}

// ============================================================================
// Backup Operations
// ============================================================================

/// Start backup job
pub fn start_backup(job_id: u32) -> bool {
    let mut state = BACKUP_STATE.lock();

    if state.active_job.is_some() {
        return false; // Already running
    }

    for i in 0..state.job_count {
        if state.jobs[i].job_id == job_id {
            state.jobs[i].status = BackupStatus::Running;
            state.jobs[i].progress = 0;
            state.jobs[i].files_processed = 0;
            state.jobs[i].bytes_processed = 0;
            state.active_job = Some(i);
            return true;
        }
    }
    false
}

/// Cancel running backup
pub fn cancel_backup() -> bool {
    let mut state = BACKUP_STATE.lock();

    if let Some(idx) = state.active_job {
        state.jobs[idx].status = BackupStatus::Cancelled;
        state.active_job = None;
        true
    } else {
        false
    }
}

/// Update backup progress (would be called during actual backup)
pub fn update_progress(progress: u8, files: u32, bytes: u64) {
    let mut state = BACKUP_STATE.lock();

    if let Some(idx) = state.active_job {
        state.jobs[idx].progress = progress.min(100);
        state.jobs[idx].files_processed = files;
        state.jobs[idx].bytes_processed = bytes;

        if progress >= 100 {
            state.jobs[idx].status = BackupStatus::Completed;
            state.jobs[idx].last_run = 0; // Would be current timestamp

            // Add to catalog
            if state.catalog_count < MAX_SETS {
                let mut set = BackupSet::new();
                set.set_id = state.next_set_id;
                state.next_set_id += 1;
                let name_len = state.jobs[idx].name_len;
                set.label[..name_len].copy_from_slice(&state.jobs[idx].name[..name_len]);
                set.label_len = name_len;
                set.backup_type = state.jobs[idx].backup_type;
                set.total_files = files;
                set.total_bytes = bytes;
                set.has_system_state = state.jobs[idx].include_system_state;

                let cidx = state.catalog_count;
                state.catalog[cidx] = set;
                state.catalog_count += 1;
            }

            state.active_job = None;
            BACKUPS_COMPLETED.fetch_add(1, Ordering::Relaxed);
            TOTAL_BYTES_BACKED.fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

/// Is backup running
pub fn is_backup_running() -> bool {
    BACKUP_STATE.lock().active_job.is_some()
}

// ============================================================================
// Backup Catalog
// ============================================================================

/// Get catalog size
pub fn get_catalog_count() -> usize {
    BACKUP_STATE.lock().catalog_count
}

/// Get backup set by index
pub fn get_backup_set(index: usize) -> Option<BackupSet> {
    let state = BACKUP_STATE.lock();
    if index < state.catalog_count {
        Some(state.catalog[index])
    } else {
        None
    }
}

/// Get backup set by ID
pub fn get_backup_set_by_id(set_id: u32) -> Option<BackupSet> {
    let state = BACKUP_STATE.lock();
    for i in 0..state.catalog_count {
        if state.catalog[i].set_id == set_id {
            return Some(state.catalog[i]);
        }
    }
    None
}

// ============================================================================
// Restore Operations
// ============================================================================

/// Start restore from backup set
pub fn start_restore(set_id: u32, location: RestoreLocation, replace: ReplaceOption) -> bool {
    let mut state = BACKUP_STATE.lock();

    if state.restoring {
        return false;
    }

    // Find backup set
    let mut found = false;
    for i in 0..state.catalog_count {
        if state.catalog[i].set_id == set_id {
            found = true;
            break;
        }
    }

    if !found {
        return false;
    }

    state.restore_job = RestoreJob::new();
    state.restore_job.job_id = 1;
    state.restore_job.backup_set_id = set_id;
    state.restore_job.location = location;
    state.restore_job.replace_option = replace;
    state.restore_job.status = BackupStatus::Running;
    state.restoring = true;

    true
}

/// Cancel restore
pub fn cancel_restore() -> bool {
    let mut state = BACKUP_STATE.lock();

    if state.restoring {
        state.restore_job.status = BackupStatus::Cancelled;
        state.restoring = false;
        true
    } else {
        false
    }
}

/// Update restore progress
pub fn update_restore_progress(progress: u8, files: u32) {
    let mut state = BACKUP_STATE.lock();

    if state.restoring {
        state.restore_job.progress = progress.min(100);
        state.restore_job.files_restored = files;

        if progress >= 100 {
            state.restore_job.status = BackupStatus::Completed;
            state.restoring = false;
            RESTORES_COMPLETED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Is restore running
pub fn is_restore_running() -> bool {
    BACKUP_STATE.lock().restoring
}

/// Get current restore job
pub fn get_restore_job() -> Option<RestoreJob> {
    let state = BACKUP_STATE.lock();
    if state.restoring || state.restore_job.job_id > 0 {
        Some(state.restore_job)
    } else {
        None
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Backup utility statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct BackupStats {
    pub initialized: bool,
    pub job_count: usize,
    pub catalog_count: usize,
    pub backup_running: bool,
    pub restore_running: bool,
    pub backups_completed: u32,
    pub restores_completed: u32,
    pub total_bytes_backed: u64,
}

/// Get backup statistics
pub fn get_stats() -> BackupStats {
    let state = BACKUP_STATE.lock();
    BackupStats {
        initialized: BACKUP_INITIALIZED.load(Ordering::Relaxed),
        job_count: state.job_count,
        catalog_count: state.catalog_count,
        backup_running: state.active_job.is_some(),
        restore_running: state.restoring,
        backups_completed: BACKUPS_COMPLETED.load(Ordering::Relaxed),
        restores_completed: RESTORES_COMPLETED.load(Ordering::Relaxed),
        total_bytes_backed: TOTAL_BYTES_BACKED.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Backup dialog handle
pub type HBACKUPDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Backup dialog
pub fn create_backup_dialog(_parent: super::super::HWND) -> HBACKUPDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
