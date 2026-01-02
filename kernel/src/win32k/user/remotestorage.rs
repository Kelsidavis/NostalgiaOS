//! Remote Storage Service (RSS) Management Console
//!
//! This module implements the Win32k USER subsystem support for the
//! Remote Storage Service management snap-in. RSS provides hierarchical
//! storage management (HSM) capabilities for Windows Server 2003.
//!
//! # Windows Server 2003 Reference
//!
//! Remote Storage allows automatic migration of infrequently used files
//! from local volumes to secondary storage media (typically tape), while
//! maintaining transparent access through reparse points.
//!
//! Key components:
//! - Managed volumes with storage policies
//! - Media management (tapes, optical media)
//! - File selection criteria (age, size, access patterns)
//! - Recall operations for migrated files

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Type alias for window handles in this module
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of managed volumes
const MAX_MANAGED_VOLUMES: usize = 32;

/// Maximum number of media items
const MAX_MEDIA_ITEMS: usize = 256;

/// Maximum number of file rules
const MAX_FILE_RULES: usize = 64;

/// Maximum number of recall tasks
const MAX_RECALL_TASKS: usize = 128;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Maximum media label length
const MAX_LABEL_LEN: usize = 64;

// ============================================================================
// Enumerations
// ============================================================================

/// Volume management status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VolumeStatus {
    /// Volume not managed
    NotManaged = 0,
    /// Volume is being set up
    Initializing = 1,
    /// Volume is actively managed
    Active = 2,
    /// Volume management paused
    Paused = 3,
    /// Volume has errors
    Error = 4,
    /// Volume is full, waiting for migration
    WaitingForMigration = 5,
    /// Migration in progress
    Migrating = 6,
}

impl Default for VolumeStatus {
    fn default() -> Self {
        Self::NotManaged
    }
}

/// Media type for secondary storage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MediaType {
    /// Unknown media type
    Unknown = 0,
    /// 4mm DAT tape
    Dat4mm = 1,
    /// 8mm tape
    Tape8mm = 2,
    /// DLT tape
    Dlt = 3,
    /// LTO Ultrium tape
    Lto = 4,
    /// AIT tape
    Ait = 5,
    /// Optical disc
    Optical = 6,
    /// DVD-RAM
    DvdRam = 7,
    /// Removable disk
    RemovableDisk = 8,
}

impl Default for MediaType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Media status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MediaStatus {
    /// Media offline/not present
    Offline = 0,
    /// Media online and ready
    Online = 1,
    /// Media being mounted
    Mounting = 2,
    /// Media being dismounted
    Dismounting = 3,
    /// Media is full
    Full = 4,
    /// Media has errors
    Error = 5,
    /// Media is read-only
    ReadOnly = 6,
    /// Media is being formatted
    Formatting = 7,
}

impl Default for MediaStatus {
    fn default() -> Self {
        Self::Offline
    }
}

/// File selection criteria type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CriteriaType {
    /// Select by file age (days since last access)
    FileAge = 0,
    /// Select by file size
    FileSize = 1,
    /// Select by file extension
    FileExtension = 2,
    /// Select by path pattern
    PathPattern = 3,
    /// Select by owner
    FileOwner = 4,
    /// Exclude specific paths
    ExcludePath = 5,
}

impl Default for CriteriaType {
    fn default() -> Self {
        Self::FileAge
    }
}

/// Recall task status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RecallStatus {
    /// Recall queued
    Queued = 0,
    /// Waiting for media
    WaitingForMedia = 1,
    /// Recall in progress
    InProgress = 2,
    /// Recall completed
    Completed = 3,
    /// Recall failed
    Failed = 4,
    /// Recall cancelled
    Cancelled = 5,
}

impl Default for RecallStatus {
    fn default() -> Self {
        Self::Queued
    }
}

/// Recall priority
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RecallPriority {
    /// Low priority (batch processing)
    Low = 0,
    /// Normal priority (user initiated)
    Normal = 1,
    /// High priority (application demand)
    High = 2,
    /// Critical (system requirement)
    Critical = 3,
}

impl Default for RecallPriority {
    fn default() -> Self {
        Self::Normal
    }
}

// ============================================================================
// Structures
// ============================================================================

/// Managed volume configuration
#[derive(Debug)]
pub struct ManagedVolume {
    /// Volume ID
    pub id: u32,
    /// Volume active
    pub active: bool,
    /// Volume letter (e.g., 'D')
    pub drive_letter: u8,
    /// Volume GUID path
    pub guid_path: [u8; MAX_PATH_LEN],
    /// GUID path length
    pub guid_path_len: usize,
    /// Volume label
    pub label: [u8; MAX_LABEL_LEN],
    /// Label length
    pub label_len: usize,
    /// Total volume size in bytes
    pub total_size: u64,
    /// Free space in bytes
    pub free_space: u64,
    /// Remote storage used in bytes
    pub remote_used: u64,
    /// Desired free space percentage (0-100)
    pub desired_free_percent: u8,
    /// Minimum file size for migration (bytes)
    pub min_file_size: u64,
    /// Minimum file age for migration (days)
    pub min_file_age_days: u32,
    /// Current status
    pub status: VolumeStatus,
    /// Files migrated count
    pub files_migrated: u64,
    /// Bytes migrated
    pub bytes_migrated: u64,
    /// Last migration time
    pub last_migration: u64,
    /// Associated UI window handle
    pub hwnd: HWND,
}

impl ManagedVolume {
    /// Create a new managed volume
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            drive_letter: 0,
            guid_path: [0u8; MAX_PATH_LEN],
            guid_path_len: 0,
            label: [0u8; MAX_LABEL_LEN],
            label_len: 0,
            total_size: 0,
            free_space: 0,
            remote_used: 0,
            desired_free_percent: 10,
            min_file_size: 65536,
            min_file_age_days: 30,
            status: VolumeStatus::NotManaged,
            files_migrated: 0,
            bytes_migrated: 0,
            last_migration: 0,
            hwnd: UserHandle::NULL,
        }
    }
}

/// Secondary storage media
#[derive(Debug)]
pub struct StorageMedia {
    /// Media ID
    pub id: u32,
    /// Media active
    pub active: bool,
    /// Media type
    pub media_type: MediaType,
    /// Media label
    pub label: [u8; MAX_LABEL_LEN],
    /// Label length
    pub label_len: usize,
    /// Media barcode/identifier
    pub barcode: [u8; 32],
    /// Barcode length
    pub barcode_len: usize,
    /// Total capacity in bytes
    pub capacity: u64,
    /// Used space in bytes
    pub used: u64,
    /// Current status
    pub status: MediaStatus,
    /// Media pool name
    pub pool_name: [u8; MAX_LABEL_LEN],
    /// Pool name length
    pub pool_name_len: usize,
    /// Location (slot number or description)
    pub location: u32,
    /// Last mount time
    pub last_mount: u64,
    /// Mount count
    pub mount_count: u32,
    /// Error count
    pub error_count: u32,
    /// Associated window
    pub hwnd: HWND,
}

impl StorageMedia {
    /// Create new storage media
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            media_type: MediaType::Unknown,
            label: [0u8; MAX_LABEL_LEN],
            label_len: 0,
            barcode: [0u8; 32],
            barcode_len: 0,
            capacity: 0,
            used: 0,
            status: MediaStatus::Offline,
            pool_name: [0u8; MAX_LABEL_LEN],
            pool_name_len: 0,
            location: 0,
            last_mount: 0,
            mount_count: 0,
            error_count: 0,
            hwnd: UserHandle::NULL,
        }
    }
}

/// File selection rule for migration
#[derive(Debug)]
pub struct FileSelectionRule {
    /// Rule ID
    pub id: u32,
    /// Rule active
    pub active: bool,
    /// Rule enabled
    pub enabled: bool,
    /// Rule name
    pub name: [u8; MAX_LABEL_LEN],
    /// Name length
    pub name_len: usize,
    /// Criteria type
    pub criteria: CriteriaType,
    /// Numeric value (size in bytes, age in days)
    pub numeric_value: u64,
    /// String pattern (extension, path pattern)
    pub pattern: [u8; MAX_PATH_LEN],
    /// Pattern length
    pub pattern_len: usize,
    /// Include (true) or exclude (false) matching files
    pub include: bool,
    /// Priority (higher = processed first)
    pub priority: u32,
    /// Volume ID this rule applies to (0 = all volumes)
    pub volume_id: u32,
}

impl FileSelectionRule {
    /// Create a new file selection rule
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            enabled: true,
            name: [0u8; MAX_LABEL_LEN],
            name_len: 0,
            criteria: CriteriaType::FileAge,
            numeric_value: 0,
            pattern: [0u8; MAX_PATH_LEN],
            pattern_len: 0,
            include: true,
            priority: 0,
            volume_id: 0,
        }
    }
}

/// File recall task
#[derive(Debug)]
pub struct RecallTask {
    /// Task ID
    pub id: u32,
    /// Task active
    pub active: bool,
    /// File path
    pub file_path: [u8; MAX_PATH_LEN],
    /// Path length
    pub path_len: usize,
    /// File size
    pub file_size: u64,
    /// Source media ID
    pub media_id: u32,
    /// Source volume ID
    pub volume_id: u32,
    /// Task status
    pub status: RecallStatus,
    /// Task priority
    pub priority: RecallPriority,
    /// Bytes recalled so far
    pub bytes_recalled: u64,
    /// Request time
    pub request_time: u64,
    /// Start time (0 if not started)
    pub start_time: u64,
    /// Completion time (0 if not completed)
    pub completion_time: u64,
    /// Error code (0 = no error)
    pub error_code: u32,
    /// Requesting process ID
    pub process_id: u32,
}

impl RecallTask {
    /// Create a new recall task
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            file_path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            file_size: 0,
            media_id: 0,
            volume_id: 0,
            status: RecallStatus::Queued,
            priority: RecallPriority::Normal,
            bytes_recalled: 0,
            request_time: 0,
            start_time: 0,
            completion_time: 0,
            error_code: 0,
            process_id: 0,
        }
    }
}

/// Remote Storage service configuration
#[derive(Debug)]
pub struct ServiceConfig {
    /// Service enabled
    pub enabled: bool,
    /// Auto-start with system
    pub auto_start: bool,
    /// Maximum concurrent recalls
    pub max_concurrent_recalls: u32,
    /// Maximum recall queue size
    pub max_recall_queue: u32,
    /// Migration schedule start hour (0-23)
    pub schedule_start_hour: u8,
    /// Migration schedule end hour (0-23)
    pub schedule_end_hour: u8,
    /// Days of week for migration (bitmap: bit 0 = Sunday)
    pub schedule_days: u8,
    /// Cache size for recalled files (bytes)
    pub cache_size: u64,
    /// Event logging level (0=none, 1=errors, 2=warnings, 3=info, 4=verbose)
    pub log_level: u8,
    /// Admin notification enabled
    pub notify_admin: bool,
    /// Admin email (simplified as bytes)
    pub admin_email: [u8; 64],
    /// Admin email length
    pub admin_email_len: usize,
}

impl ServiceConfig {
    /// Create default service configuration
    pub const fn new() -> Self {
        Self {
            enabled: true,
            auto_start: true,
            max_concurrent_recalls: 4,
            max_recall_queue: 1000,
            schedule_start_hour: 22,
            schedule_end_hour: 6,
            schedule_days: 0b1111111, // All days
            cache_size: 1024 * 1024 * 1024, // 1 GB
            log_level: 2,
            notify_admin: false,
            admin_email: [0u8; 64],
            admin_email_len: 0,
        }
    }
}

/// Statistics for Remote Storage
#[derive(Debug)]
pub struct ServiceStatistics {
    /// Total files migrated
    pub total_files_migrated: u64,
    /// Total bytes migrated
    pub total_bytes_migrated: u64,
    /// Total files recalled
    pub total_files_recalled: u64,
    /// Total bytes recalled
    pub total_bytes_recalled: u64,
    /// Failed migrations
    pub failed_migrations: u64,
    /// Failed recalls
    pub failed_recalls: u64,
    /// Current queue depth
    pub queue_depth: u32,
    /// Active recalls
    pub active_recalls: u32,
    /// Service start time
    pub service_start_time: u64,
    /// Last migration time
    pub last_migration_time: u64,
    /// Last recall time
    pub last_recall_time: u64,
}

impl ServiceStatistics {
    /// Create new statistics
    pub const fn new() -> Self {
        Self {
            total_files_migrated: 0,
            total_bytes_migrated: 0,
            total_files_recalled: 0,
            total_bytes_recalled: 0,
            failed_migrations: 0,
            failed_recalls: 0,
            queue_depth: 0,
            active_recalls: 0,
            service_start_time: 0,
            last_migration_time: 0,
            last_recall_time: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Remote Storage Manager state
struct RemoteStorageState {
    /// Managed volumes
    volumes: [ManagedVolume; MAX_MANAGED_VOLUMES],
    /// Storage media
    media: [StorageMedia; MAX_MEDIA_ITEMS],
    /// File selection rules
    rules: [FileSelectionRule; MAX_FILE_RULES],
    /// Recall tasks
    tasks: [RecallTask; MAX_RECALL_TASKS],
    /// Service configuration
    config: ServiceConfig,
    /// Service statistics
    statistics: ServiceStatistics,
    /// Next ID counter
    next_id: u32,
}

impl RemoteStorageState {
    /// Create new Remote Storage state
    const fn new() -> Self {
        Self {
            volumes: [const { ManagedVolume::new() }; MAX_MANAGED_VOLUMES],
            media: [const { StorageMedia::new() }; MAX_MEDIA_ITEMS],
            rules: [const { FileSelectionRule::new() }; MAX_FILE_RULES],
            tasks: [const { RecallTask::new() }; MAX_RECALL_TASKS],
            config: ServiceConfig::new(),
            statistics: ServiceStatistics::new(),
            next_id: 1,
        }
    }
}

/// Global Remote Storage state
static RSS_STATE: SpinLock<RemoteStorageState> = SpinLock::new(RemoteStorageState::new());

/// Module initialization flag
static RSS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Total managed volumes counter
static MANAGED_VOLUMES_COUNT: AtomicU32 = AtomicU32::new(0);

/// Total media items counter
static MEDIA_COUNT: AtomicU32 = AtomicU32::new(0);

/// Total recall tasks counter
static RECALL_TASKS_COUNT: AtomicU32 = AtomicU32::new(0);

/// Total bytes migrated
static TOTAL_BYTES_MIGRATED: AtomicU64 = AtomicU64::new(0);

/// Total bytes recalled
static TOTAL_BYTES_RECALLED: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Volume Management Functions
// ============================================================================

/// Add a managed volume
pub fn add_managed_volume(
    drive_letter: u8,
    guid_path: &[u8],
    label: &[u8],
    total_size: u64,
) -> Result<u32, u32> {
    let mut state = RSS_STATE.lock();

    // Find free slot
    let slot = state.volumes.iter().position(|v| !v.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x80070057), // E_INVALIDARG - no free slots
    };

    let id = state.next_id;
    state.next_id += 1;

    let volume = &mut state.volumes[slot];
    volume.id = id;
    volume.active = true;
    volume.drive_letter = drive_letter;

    let guid_len = guid_path.len().min(MAX_PATH_LEN);
    volume.guid_path[..guid_len].copy_from_slice(&guid_path[..guid_len]);
    volume.guid_path_len = guid_len;

    let label_len = label.len().min(MAX_LABEL_LEN);
    volume.label[..label_len].copy_from_slice(&label[..label_len]);
    volume.label_len = label_len;

    volume.total_size = total_size;
    volume.free_space = total_size;
    volume.status = VolumeStatus::Initializing;
    volume.hwnd = UserHandle::from_raw(id);

    MANAGED_VOLUMES_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(id)
}

/// Remove a managed volume
pub fn remove_managed_volume(volume_id: u32) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let volume = state.volumes.iter_mut().find(|v| v.active && v.id == volume_id);

    match volume {
        Some(v) => {
            v.active = false;
            v.status = VolumeStatus::NotManaged;
            MANAGED_VOLUMES_COUNT.fetch_sub(1, Ordering::Relaxed);
            Ok(())
        }
        None => Err(0x80070002), // ERROR_FILE_NOT_FOUND
    }
}

/// Set volume management status
pub fn set_volume_status(volume_id: u32, status: VolumeStatus) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let volume = state.volumes.iter_mut().find(|v| v.active && v.id == volume_id);

    match volume {
        Some(v) => {
            v.status = status;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Update volume free space
pub fn update_volume_space(volume_id: u32, free_space: u64, remote_used: u64) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let volume = state.volumes.iter_mut().find(|v| v.active && v.id == volume_id);

    match volume {
        Some(v) => {
            v.free_space = free_space;
            v.remote_used = remote_used;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Configure volume migration settings
pub fn configure_volume_migration(
    volume_id: u32,
    desired_free_percent: u8,
    min_file_size: u64,
    min_file_age_days: u32,
) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let volume = state.volumes.iter_mut().find(|v| v.active && v.id == volume_id);

    match volume {
        Some(v) => {
            v.desired_free_percent = desired_free_percent.min(100);
            v.min_file_size = min_file_size;
            v.min_file_age_days = min_file_age_days;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Get volume count
pub fn get_managed_volume_count() -> u32 {
    MANAGED_VOLUMES_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// Media Management Functions
// ============================================================================

/// Add storage media
pub fn add_storage_media(
    media_type: MediaType,
    label: &[u8],
    capacity: u64,
) -> Result<u32, u32> {
    let mut state = RSS_STATE.lock();

    let slot = state.media.iter().position(|m| !m.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x80070057),
    };

    let id = state.next_id;
    state.next_id += 1;

    let media = &mut state.media[slot];
    media.id = id;
    media.active = true;
    media.media_type = media_type;

    let label_len = label.len().min(MAX_LABEL_LEN);
    media.label[..label_len].copy_from_slice(&label[..label_len]);
    media.label_len = label_len;

    media.capacity = capacity;
    media.status = MediaStatus::Offline;
    media.hwnd = UserHandle::from_raw(id);

    MEDIA_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(id)
}

/// Remove storage media
pub fn remove_storage_media(media_id: u32) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let media = state.media.iter_mut().find(|m| m.active && m.id == media_id);

    match media {
        Some(m) => {
            if m.status != MediaStatus::Offline {
                return Err(0x80070020); // ERROR_SHARING_VIOLATION - media in use
            }
            m.active = false;
            MEDIA_COUNT.fetch_sub(1, Ordering::Relaxed);
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set media status
pub fn set_media_status(media_id: u32, status: MediaStatus) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let media = state.media.iter_mut().find(|m| m.active && m.id == media_id);

    match media {
        Some(m) => {
            m.status = status;
            if status == MediaStatus::Online {
                m.mount_count += 1;
                m.last_mount = 0; // Would use current time
            }
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Update media usage
pub fn update_media_usage(media_id: u32, used: u64) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let media = state.media.iter_mut().find(|m| m.active && m.id == media_id);

    match media {
        Some(m) => {
            m.used = used;
            if m.used >= m.capacity {
                m.status = MediaStatus::Full;
            }
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set media pool
pub fn set_media_pool(media_id: u32, pool_name: &[u8]) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let media = state.media.iter_mut().find(|m| m.active && m.id == media_id);

    match media {
        Some(m) => {
            let len = pool_name.len().min(MAX_LABEL_LEN);
            m.pool_name[..len].copy_from_slice(&pool_name[..len]);
            m.pool_name_len = len;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Get media count
pub fn get_media_count() -> u32 {
    MEDIA_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// File Selection Rule Functions
// ============================================================================

/// Add file selection rule
pub fn add_file_rule(
    name: &[u8],
    criteria: CriteriaType,
    numeric_value: u64,
    pattern: &[u8],
    include: bool,
) -> Result<u32, u32> {
    let mut state = RSS_STATE.lock();

    let slot = state.rules.iter().position(|r| !r.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x80070057),
    };

    let id = state.next_id;
    state.next_id += 1;

    let rule = &mut state.rules[slot];
    rule.id = id;
    rule.active = true;
    rule.enabled = true;

    let name_len = name.len().min(MAX_LABEL_LEN);
    rule.name[..name_len].copy_from_slice(&name[..name_len]);
    rule.name_len = name_len;

    rule.criteria = criteria;
    rule.numeric_value = numeric_value;

    let pattern_len = pattern.len().min(MAX_PATH_LEN);
    rule.pattern[..pattern_len].copy_from_slice(&pattern[..pattern_len]);
    rule.pattern_len = pattern_len;

    rule.include = include;

    Ok(id)
}

/// Remove file selection rule
pub fn remove_file_rule(rule_id: u32) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let rule = state.rules.iter_mut().find(|r| r.active && r.id == rule_id);

    match rule {
        Some(r) => {
            r.active = false;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Enable or disable file rule
pub fn set_file_rule_enabled(rule_id: u32, enabled: bool) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let rule = state.rules.iter_mut().find(|r| r.active && r.id == rule_id);

    match rule {
        Some(r) => {
            r.enabled = enabled;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set rule priority
pub fn set_file_rule_priority(rule_id: u32, priority: u32) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let rule = state.rules.iter_mut().find(|r| r.active && r.id == rule_id);

    match rule {
        Some(r) => {
            r.priority = priority;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Assign rule to specific volume
pub fn assign_rule_to_volume(rule_id: u32, volume_id: u32) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let rule = state.rules.iter_mut().find(|r| r.active && r.id == rule_id);

    match rule {
        Some(r) => {
            r.volume_id = volume_id;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

// ============================================================================
// Recall Task Functions
// ============================================================================

/// Create a recall task
pub fn create_recall_task(
    file_path: &[u8],
    file_size: u64,
    media_id: u32,
    volume_id: u32,
    priority: RecallPriority,
    process_id: u32,
) -> Result<u32, u32> {
    let mut state = RSS_STATE.lock();

    let slot = state.tasks.iter().position(|t| !t.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E), // E_OUTOFMEMORY - queue full
    };

    let id = state.next_id;
    state.next_id += 1;

    let task = &mut state.tasks[slot];
    task.id = id;
    task.active = true;

    let path_len = file_path.len().min(MAX_PATH_LEN);
    task.file_path[..path_len].copy_from_slice(&file_path[..path_len]);
    task.path_len = path_len;

    task.file_size = file_size;
    task.media_id = media_id;
    task.volume_id = volume_id;
    task.status = RecallStatus::Queued;
    task.priority = priority;
    task.process_id = process_id;
    task.request_time = 0; // Would use current time

    state.statistics.queue_depth += 1;
    RECALL_TASKS_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(id)
}

/// Cancel a recall task
pub fn cancel_recall_task(task_id: u32) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let task = state.tasks.iter_mut().find(|t| t.active && t.id == task_id);

    match task {
        Some(t) => {
            if t.status == RecallStatus::InProgress {
                return Err(0x80070005); // E_ACCESSDENIED - can't cancel in progress
            }
            t.status = RecallStatus::Cancelled;
            t.active = false;
            state.statistics.queue_depth = state.statistics.queue_depth.saturating_sub(1);
            RECALL_TASKS_COUNT.fetch_sub(1, Ordering::Relaxed);
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Update recall task status
pub fn update_recall_status(task_id: u32, status: RecallStatus) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    // Find task index first
    let task_idx = state.tasks.iter().position(|t| t.active && t.id == task_id);

    let task_idx = match task_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    // Read values we need before modifying
    let prev_status = state.tasks[task_idx].status;
    let file_size = state.tasks[task_idx].file_size;

    // Update task status
    state.tasks[task_idx].status = status;

    match status {
        RecallStatus::InProgress => {
            state.tasks[task_idx].start_time = 0; // Would use current time
            state.statistics.active_recalls += 1;
            state.statistics.queue_depth = state.statistics.queue_depth.saturating_sub(1);
        }
        RecallStatus::Completed => {
            state.tasks[task_idx].completion_time = 0; // Would use current time
            if prev_status == RecallStatus::InProgress {
                state.statistics.active_recalls =
                    state.statistics.active_recalls.saturating_sub(1);
            }
            state.statistics.total_files_recalled += 1;
            state.statistics.total_bytes_recalled += file_size;
            state.statistics.last_recall_time = 0;
            TOTAL_BYTES_RECALLED.fetch_add(file_size, Ordering::Relaxed);
            state.tasks[task_idx].active = false;
            RECALL_TASKS_COUNT.fetch_sub(1, Ordering::Relaxed);
        }
        RecallStatus::Failed => {
            if prev_status == RecallStatus::InProgress {
                state.statistics.active_recalls =
                    state.statistics.active_recalls.saturating_sub(1);
            }
            state.statistics.failed_recalls += 1;
            state.tasks[task_idx].active = false;
            RECALL_TASKS_COUNT.fetch_sub(1, Ordering::Relaxed);
        }
        _ => {}
    }

    Ok(())
}

/// Update recall progress
pub fn update_recall_progress(task_id: u32, bytes_recalled: u64) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    let task = state.tasks.iter_mut().find(|t| t.active && t.id == task_id);

    match task {
        Some(t) => {
            t.bytes_recalled = bytes_recalled;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Get active recall count
pub fn get_active_recall_count() -> u32 {
    let state = RSS_STATE.lock();
    state.statistics.active_recalls
}

/// Get recall queue depth
pub fn get_recall_queue_depth() -> u32 {
    let state = RSS_STATE.lock();
    state.statistics.queue_depth
}

// ============================================================================
// Service Configuration Functions
// ============================================================================

/// Configure service settings
pub fn configure_service(
    max_concurrent_recalls: u32,
    max_recall_queue: u32,
    cache_size: u64,
    log_level: u8,
) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    state.config.max_concurrent_recalls = max_concurrent_recalls.max(1);
    state.config.max_recall_queue = max_recall_queue.max(10);
    state.config.cache_size = cache_size;
    state.config.log_level = log_level.min(4);

    Ok(())
}

/// Configure migration schedule
pub fn configure_schedule(
    start_hour: u8,
    end_hour: u8,
    days: u8,
) -> Result<(), u32> {
    if start_hour > 23 || end_hour > 23 {
        return Err(0x80070057);
    }

    let mut state = RSS_STATE.lock();

    state.config.schedule_start_hour = start_hour;
    state.config.schedule_end_hour = end_hour;
    state.config.schedule_days = days;

    Ok(())
}

/// Enable or disable service
pub fn set_service_enabled(enabled: bool) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();
    state.config.enabled = enabled;
    Ok(())
}

/// Set admin notification
pub fn set_admin_notification(enabled: bool, email: &[u8]) -> Result<(), u32> {
    let mut state = RSS_STATE.lock();

    state.config.notify_admin = enabled;

    let email_len = email.len().min(64);
    state.config.admin_email[..email_len].copy_from_slice(&email[..email_len]);
    state.config.admin_email_len = email_len;

    Ok(())
}

/// Check if service is enabled
pub fn is_service_enabled() -> bool {
    let state = RSS_STATE.lock();
    state.config.enabled
}

// ============================================================================
// Statistics Functions
// ============================================================================

/// Record a migration
pub fn record_migration(file_size: u64, success: bool) {
    let mut state = RSS_STATE.lock();

    if success {
        state.statistics.total_files_migrated += 1;
        state.statistics.total_bytes_migrated += file_size;
        state.statistics.last_migration_time = 0; // Would use current time
        TOTAL_BYTES_MIGRATED.fetch_add(file_size, Ordering::Relaxed);
    } else {
        state.statistics.failed_migrations += 1;
    }
}

/// Get total bytes migrated
pub fn get_total_bytes_migrated() -> u64 {
    TOTAL_BYTES_MIGRATED.load(Ordering::Relaxed)
}

/// Get total bytes recalled
pub fn get_total_bytes_recalled() -> u64 {
    TOTAL_BYTES_RECALLED.load(Ordering::Relaxed)
}

/// Get total files migrated
pub fn get_total_files_migrated() -> u64 {
    let state = RSS_STATE.lock();
    state.statistics.total_files_migrated
}

/// Get total files recalled
pub fn get_total_files_recalled() -> u64 {
    let state = RSS_STATE.lock();
    state.statistics.total_files_recalled
}

/// Get failed migrations count
pub fn get_failed_migrations() -> u64 {
    let state = RSS_STATE.lock();
    state.statistics.failed_migrations
}

/// Get failed recalls count
pub fn get_failed_recalls() -> u64 {
    let state = RSS_STATE.lock();
    state.statistics.failed_recalls
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Remote Storage management module
pub fn init() -> Result<(), &'static str> {
    if RSS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(()); // Already initialized
    }

    let mut state = RSS_STATE.lock();

    // Reserve IDs for default configuration
    let volume_id = state.next_id;
    let media_id = state.next_id + 1;
    let rule_id = state.next_id + 2;
    state.next_id += 3;

    // Create example managed volume (C:)
    {
        let volume = &mut state.volumes[0];
        volume.id = volume_id;
        volume.active = true;
        volume.drive_letter = b'C';
        let label = b"System";
        volume.label[..label.len()].copy_from_slice(label);
        volume.label_len = label.len();
        volume.total_size = 100 * 1024 * 1024 * 1024; // 100 GB
        volume.free_space = 40 * 1024 * 1024 * 1024;  // 40 GB free
        volume.desired_free_percent = 15;
        volume.min_file_size = 65536;
        volume.min_file_age_days = 90;
        volume.status = VolumeStatus::Active;
        volume.hwnd = UserHandle::from_raw(volume_id);
    }

    // Create example tape media
    {
        let media = &mut state.media[0];
        media.id = media_id;
        media.active = true;
        media.media_type = MediaType::Lto;
        let label = b"BACKUP001";
        media.label[..label.len()].copy_from_slice(label);
        media.label_len = label.len();
        media.capacity = 800 * 1024 * 1024 * 1024; // 800 GB
        media.status = MediaStatus::Online;
        let pool = b"Default";
        media.pool_name[..pool.len()].copy_from_slice(pool);
        media.pool_name_len = pool.len();
        media.hwnd = UserHandle::from_raw(media_id);
    }

    // Create default file age rule
    {
        let rule = &mut state.rules[0];
        rule.id = rule_id;
        rule.active = true;
        rule.enabled = true;
        let name = b"Default Age Rule";
        rule.name[..name.len()].copy_from_slice(name);
        rule.name_len = name.len();
        rule.criteria = CriteriaType::FileAge;
        rule.numeric_value = 90; // 90 days
        rule.include = true;
        rule.priority = 100;
    }

    // Update counters
    MANAGED_VOLUMES_COUNT.store(1, Ordering::Relaxed);
    MEDIA_COUNT.store(1, Ordering::Relaxed);

    Ok(())
}

/// Check if module is initialized
pub fn is_initialized() -> bool {
    RSS_INITIALIZED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_config() {
        let config = ServiceConfig::new();
        assert!(config.enabled);
        assert_eq!(config.max_concurrent_recalls, 4);
        assert_eq!(config.schedule_start_hour, 22);
    }

    #[test]
    fn test_volume_status() {
        assert_eq!(VolumeStatus::default(), VolumeStatus::NotManaged);
        assert_eq!(VolumeStatus::Active as u32, 2);
    }

    #[test]
    fn test_media_type() {
        assert_eq!(MediaType::default(), MediaType::Unknown);
        assert_eq!(MediaType::Lto as u32, 4);
    }

    #[test]
    fn test_recall_priority() {
        assert_eq!(RecallPriority::default(), RecallPriority::Normal);
        assert_eq!(RecallPriority::Critical as u32, 3);
    }
}
