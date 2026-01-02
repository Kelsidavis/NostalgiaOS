//! System Restore
//!
//! Implements System Restore following Windows Server 2003.
//! Provides system restore points and rollback functionality.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - System Restore (rstrui.exe)
//! - System Restore service (SRService)
//! - System Properties > System Restore tab

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum restore points
const MAX_RESTORE_POINTS: usize = 32;

/// Maximum description length
const MAX_DESC: usize = 256;

/// Maximum drive entries
const MAX_DRIVES: usize = 8;

// ============================================================================
// Restore Point Type
// ============================================================================

/// Restore point type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestorePointType {
    /// Application install
    #[default]
    ApplicationInstall = 0,
    /// Application uninstall
    ApplicationUninstall = 1,
    /// Device driver install
    DriverInstall = 10,
    /// System checkpoint
    SystemCheckpoint = 7,
    /// Cancelled operation
    CancelledOperation = 13,
    /// Backup recovery
    BackupRecovery = 14,
    /// Manual restore point
    Manual = 16,
}

impl RestorePointType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RestorePointType::ApplicationInstall => "Install",
            RestorePointType::ApplicationUninstall => "Uninstall",
            RestorePointType::DriverInstall => "Device driver",
            RestorePointType::SystemCheckpoint => "System Checkpoint",
            RestorePointType::CancelledOperation => "Cancelled Operation",
            RestorePointType::BackupRecovery => "Backup Recovery",
            RestorePointType::Manual => "Manual",
        }
    }
}

// ============================================================================
// Restore Point Status
// ============================================================================

/// Restore point status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestoreStatus {
    /// Restore point created successfully
    #[default]
    Created = 0,
    /// Restore in progress
    InProgress = 1,
    /// Restore completed
    Completed = 2,
    /// Restore failed
    Failed = 3,
    /// Restore point is valid
    Valid = 4,
    /// Restore point is invalid
    Invalid = 5,
}

// ============================================================================
// Restore Point
// ============================================================================

/// Restore point entry
#[derive(Debug, Clone, Copy)]
pub struct RestorePoint {
    /// Sequence number
    pub sequence_number: u32,
    /// Restore point type
    pub restore_type: RestorePointType,
    /// Description
    pub description: [u8; MAX_DESC],
    /// Description length
    pub description_len: usize,
    /// Creation timestamp
    pub creation_time: u64,
    /// Status
    pub status: RestoreStatus,
    /// Is this a system checkpoint
    pub is_checkpoint: bool,
}

impl RestorePoint {
    pub const fn new() -> Self {
        Self {
            sequence_number: 0,
            restore_type: RestorePointType::SystemCheckpoint,
            description: [0u8; MAX_DESC],
            description_len: 0,
            creation_time: 0,
            status: RestoreStatus::Created,
            is_checkpoint: false,
        }
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_DESC);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.description_len = len;
    }
}

impl Default for RestorePoint {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Drive Settings
// ============================================================================

/// Drive restore settings
#[derive(Debug, Clone, Copy)]
pub struct DriveSettings {
    /// Drive letter
    pub drive_letter: u8,
    /// System Restore enabled on this drive
    pub enabled: bool,
    /// Maximum disk space usage (MB)
    pub max_size_mb: u32,
    /// Current disk space used (MB)
    pub used_size_mb: u32,
    /// Is system drive
    pub is_system: bool,
}

impl DriveSettings {
    pub const fn new() -> Self {
        Self {
            drive_letter: 0,
            enabled: false,
            max_size_mb: 0,
            used_size_mb: 0,
            is_system: false,
        }
    }
}

impl Default for DriveSettings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// System Restore Settings
// ============================================================================

/// Global System Restore settings
#[derive(Debug, Clone, Copy)]
pub struct SysRestoreSettings {
    /// System Restore enabled
    pub enabled: bool,
    /// Create restore points before installing unsigned drivers
    pub check_unsigned_drivers: bool,
    /// Automatic checkpoint interval (hours)
    pub checkpoint_interval: u32,
}

impl SysRestoreSettings {
    pub const fn new() -> Self {
        Self {
            enabled: true,
            check_unsigned_drivers: true,
            checkpoint_interval: 24,
        }
    }
}

impl Default for SysRestoreSettings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// System Restore State
// ============================================================================

/// System Restore state
struct SysRestoreState {
    /// Global settings
    settings: SysRestoreSettings,
    /// Restore points
    restore_points: [RestorePoint; MAX_RESTORE_POINTS],
    /// Restore point count
    point_count: usize,
    /// Drive settings
    drives: [DriveSettings; MAX_DRIVES],
    /// Drive count
    drive_count: usize,
    /// Next sequence number
    next_sequence: u32,
    /// Restore in progress
    restoring: bool,
    /// Current restore target
    restore_target: u32,
}

impl SysRestoreState {
    pub const fn new() -> Self {
        Self {
            settings: SysRestoreSettings::new(),
            restore_points: [const { RestorePoint::new() }; MAX_RESTORE_POINTS],
            point_count: 0,
            drives: [const { DriveSettings::new() }; MAX_DRIVES],
            drive_count: 0,
            next_sequence: 1,
            restoring: false,
            restore_target: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static SYSRESTORE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static SYSRESTORE_STATE: SpinLock<SysRestoreState> = SpinLock::new(SysRestoreState::new());

// Statistics
static RESTORE_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize System Restore
pub fn init() {
    if SYSRESTORE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = SYSRESTORE_STATE.lock();

    // Initialize drives
    init_drives(&mut state);

    // Add sample restore points
    add_sample_restore_points(&mut state);

    crate::serial_println!("[WIN32K] System Restore initialized");
}

/// Initialize drive settings
fn init_drives(state: &mut SysRestoreState) {
    // C: drive (system)
    let mut drive_c = DriveSettings::new();
    drive_c.drive_letter = b'C';
    drive_c.enabled = true;
    drive_c.max_size_mb = 4096; // 4GB max
    drive_c.used_size_mb = 512;
    drive_c.is_system = true;
    state.drives[0] = drive_c;

    // D: drive
    let mut drive_d = DriveSettings::new();
    drive_d.drive_letter = b'D';
    drive_d.enabled = false;
    drive_d.max_size_mb = 2048;
    drive_d.used_size_mb = 0;
    drive_d.is_system = false;
    state.drives[1] = drive_d;

    state.drive_count = 2;
}

/// Add sample restore points
fn add_sample_restore_points(state: &mut SysRestoreState) {
    let points: [(&[u8], RestorePointType, u64); 5] = [
        (b"System Checkpoint", RestorePointType::SystemCheckpoint, 1104537600),
        (b"Installed Windows Server 2003 SP1", RestorePointType::ApplicationInstall, 1104624000),
        (b"Installed Microsoft Office 2003", RestorePointType::ApplicationInstall, 1104710400),
        (b"Installed NVIDIA Display Driver", RestorePointType::DriverInstall, 1104796800),
        (b"System Checkpoint", RestorePointType::SystemCheckpoint, 1104883200),
    ];

    for (desc, rtype, time) in points.iter() {
        if state.point_count >= MAX_RESTORE_POINTS {
            break;
        }

        let mut point = RestorePoint::new();
        point.sequence_number = state.next_sequence;
        state.next_sequence += 1;
        point.restore_type = *rtype;
        point.set_description(desc);
        point.creation_time = *time;
        point.status = RestoreStatus::Valid;
        point.is_checkpoint = *rtype == RestorePointType::SystemCheckpoint;

        state.restore_points[state.point_count] = point;
        state.point_count += 1;
    }
}

// ============================================================================
// Settings Management
// ============================================================================

/// Get System Restore settings
pub fn get_settings() -> SysRestoreSettings {
    SYSRESTORE_STATE.lock().settings
}

/// Enable/disable System Restore globally
pub fn set_enabled(enabled: bool) {
    SYSRESTORE_STATE.lock().settings.enabled = enabled;
}

/// Check if System Restore is enabled
pub fn is_enabled() -> bool {
    SYSRESTORE_STATE.lock().settings.enabled
}

/// Set checkpoint interval (hours)
pub fn set_checkpoint_interval(hours: u32) {
    SYSRESTORE_STATE.lock().settings.checkpoint_interval = hours;
}

// ============================================================================
// Drive Management
// ============================================================================

/// Get drive count
pub fn get_drive_count() -> usize {
    SYSRESTORE_STATE.lock().drive_count
}

/// Get drive settings by index
pub fn get_drive_settings(index: usize) -> Option<DriveSettings> {
    let state = SYSRESTORE_STATE.lock();
    if index < state.drive_count {
        Some(state.drives[index])
    } else {
        None
    }
}

/// Get drive settings by letter
pub fn get_drive_by_letter(letter: u8) -> Option<DriveSettings> {
    let state = SYSRESTORE_STATE.lock();
    let upper = if letter >= b'a' && letter <= b'z' {
        letter - 32
    } else {
        letter
    };
    for i in 0..state.drive_count {
        if state.drives[i].drive_letter == upper {
            return Some(state.drives[i]);
        }
    }
    None
}

/// Enable/disable System Restore on a drive
pub fn set_drive_enabled(letter: u8, enabled: bool) -> bool {
    let mut state = SYSRESTORE_STATE.lock();
    let upper = if letter >= b'a' && letter <= b'z' {
        letter - 32
    } else {
        letter
    };
    for i in 0..state.drive_count {
        if state.drives[i].drive_letter == upper {
            state.drives[i].enabled = enabled;
            return true;
        }
    }
    false
}

/// Set maximum disk space for a drive
pub fn set_drive_max_size(letter: u8, max_mb: u32) -> bool {
    let mut state = SYSRESTORE_STATE.lock();
    let upper = if letter >= b'a' && letter <= b'z' {
        letter - 32
    } else {
        letter
    };
    for i in 0..state.drive_count {
        if state.drives[i].drive_letter == upper {
            state.drives[i].max_size_mb = max_mb;
            return true;
        }
    }
    false
}

// ============================================================================
// Restore Point Management
// ============================================================================

/// Get restore point count
pub fn get_point_count() -> usize {
    SYSRESTORE_STATE.lock().point_count
}

/// Get restore point by index
pub fn get_restore_point(index: usize) -> Option<RestorePoint> {
    let state = SYSRESTORE_STATE.lock();
    if index < state.point_count {
        Some(state.restore_points[index])
    } else {
        None
    }
}

/// Get restore point by sequence number
pub fn get_point_by_sequence(sequence: u32) -> Option<RestorePoint> {
    let state = SYSRESTORE_STATE.lock();
    for i in 0..state.point_count {
        if state.restore_points[i].sequence_number == sequence {
            return Some(state.restore_points[i]);
        }
    }
    None
}

/// Create a new restore point
pub fn create_restore_point(description: &[u8], restore_type: RestorePointType) -> Option<u32> {
    let mut state = SYSRESTORE_STATE.lock();

    if !state.settings.enabled {
        return None;
    }

    // If at max, remove oldest
    if state.point_count >= MAX_RESTORE_POINTS {
        // Shift all points left
        for i in 0..state.point_count - 1 {
            state.restore_points[i] = state.restore_points[i + 1];
        }
        state.point_count -= 1;
    }

    let sequence = state.next_sequence;
    state.next_sequence += 1;

    let mut point = RestorePoint::new();
    point.sequence_number = sequence;
    point.restore_type = restore_type;
    point.set_description(description);
    point.creation_time = 0; // Would be current timestamp
    point.status = RestoreStatus::Valid;
    point.is_checkpoint = restore_type == RestorePointType::SystemCheckpoint;

    let idx = state.point_count;
    state.restore_points[idx] = point;
    state.point_count += 1;

    Some(sequence)
}

/// Delete a restore point
pub fn delete_restore_point(sequence: u32) -> bool {
    let mut state = SYSRESTORE_STATE.lock();

    let mut found_index = None;
    for i in 0..state.point_count {
        if state.restore_points[i].sequence_number == sequence {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        // Shift remaining points
        for i in index..state.point_count - 1 {
            state.restore_points[i] = state.restore_points[i + 1];
        }
        state.point_count -= 1;
        true
    } else {
        false
    }
}

// ============================================================================
// Restore Operations
// ============================================================================

/// Start a system restore
pub fn start_restore(sequence: u32) -> bool {
    let mut state = SYSRESTORE_STATE.lock();

    if state.restoring {
        return false;
    }

    // Find the restore point
    let mut found = false;
    for i in 0..state.point_count {
        if state.restore_points[i].sequence_number == sequence &&
           state.restore_points[i].status == RestoreStatus::Valid {
            found = true;
            break;
        }
    }

    if !found {
        return false;
    }

    state.restoring = true;
    state.restore_target = sequence;

    // Would actually perform restore here
    // In simulation, just mark as complete
    RESTORE_COUNT.fetch_add(1, Ordering::Relaxed);

    state.restoring = false;
    state.restore_target = 0;

    true
}

/// Check if restore is in progress
pub fn is_restoring() -> bool {
    SYSRESTORE_STATE.lock().restoring
}

/// Cancel pending restore
pub fn cancel_restore() -> bool {
    let mut state = SYSRESTORE_STATE.lock();
    if state.restoring {
        state.restoring = false;
        state.restore_target = 0;
        true
    } else {
        false
    }
}

// ============================================================================
// Cleanup
// ============================================================================

/// Delete all restore points (for disk space)
pub fn delete_all_restore_points() {
    let mut state = SYSRESTORE_STATE.lock();
    state.point_count = 0;

    // Reset disk usage
    for i in 0..state.drive_count {
        state.drives[i].used_size_mb = 0;
    }
}

/// Delete restore points older than specified (except most recent)
pub fn delete_old_restore_points(older_than: u64) -> usize {
    let mut state = SYSRESTORE_STATE.lock();
    let mut deleted = 0;

    if state.point_count <= 1 {
        return 0;
    }

    let mut i = 0;
    while i < state.point_count - 1 {
        if state.restore_points[i].creation_time < older_than {
            // Shift remaining points
            for j in i..state.point_count - 1 {
                state.restore_points[j] = state.restore_points[j + 1];
            }
            state.point_count -= 1;
            deleted += 1;
        } else {
            i += 1;
        }
    }

    deleted
}

// ============================================================================
// Statistics
// ============================================================================

/// System Restore statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct SysRestoreStats {
    pub initialized: bool,
    pub enabled: bool,
    pub point_count: usize,
    pub restore_count: u32,
    pub restoring: bool,
    pub total_used_mb: u32,
}

/// Get System Restore statistics
pub fn get_stats() -> SysRestoreStats {
    let state = SYSRESTORE_STATE.lock();
    let mut total_used = 0u32;
    for i in 0..state.drive_count {
        total_used += state.drives[i].used_size_mb;
    }

    SysRestoreStats {
        initialized: SYSRESTORE_INITIALIZED.load(Ordering::Relaxed),
        enabled: state.settings.enabled,
        point_count: state.point_count,
        restore_count: RESTORE_COUNT.load(Ordering::Relaxed),
        restoring: state.restoring,
        total_used_mb: total_used,
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// System Restore dialog handle
pub type HSYSRESTOREDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create System Restore dialog
pub fn create_sysrestore_dialog(_parent: super::super::HWND) -> HSYSRESTOREDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}

/// System Restore wizard page
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestoreWizardPage {
    /// Welcome page
    #[default]
    Welcome = 0,
    /// Select restore point
    SelectPoint = 1,
    /// Confirm restore
    Confirm = 2,
    /// Restoring
    Restoring = 3,
    /// Complete
    Complete = 4,
}
