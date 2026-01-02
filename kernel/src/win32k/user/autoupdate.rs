//! Automatic Updates
//!
//! Implements the Automatic Updates configuration following Windows Server 2003.
//! Provides Windows Update settings and scheduling.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - wuaucpl.cpl - Automatic Updates control panel
//! - wuauserv service - Windows Update service
//! - Windows Update Agent

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum update history entries
const MAX_HISTORY: usize = 100;

/// Maximum update title length
const MAX_TITLE: usize = 128;

/// Maximum KB number length
const MAX_KB: usize = 16;

// ============================================================================
// Update Mode
// ============================================================================

/// Automatic Updates mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpdateMode {
    /// Disabled (not recommended)
    Disabled = 1,
    /// Notify before downloading
    NotifyDownload = 2,
    /// Download but notify before installing
    #[default]
    DownloadNotify = 3,
    /// Automatic (scheduled)
    Automatic = 4,
}

impl UpdateMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateMode::Disabled => "Turn off Automatic Updates",
            UpdateMode::NotifyDownload => "Notify me before downloading any updates",
            UpdateMode::DownloadNotify => "Download updates but let me choose when to install",
            UpdateMode::Automatic => "Automatic (recommended)",
        }
    }
}

// ============================================================================
// Update Type
// ============================================================================

/// Update classification
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpdateType {
    /// Critical update
    #[default]
    Critical = 0,
    /// Security update
    Security = 1,
    /// Important update
    Important = 2,
    /// Recommended update
    Recommended = 3,
    /// Optional update
    Optional = 4,
    /// Driver update
    Driver = 5,
    /// Service pack
    ServicePack = 6,
    /// Feature pack
    FeaturePack = 7,
}

impl UpdateType {
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateType::Critical => "Critical Update",
            UpdateType::Security => "Security Update",
            UpdateType::Important => "Important Update",
            UpdateType::Recommended => "Recommended Update",
            UpdateType::Optional => "Optional Update",
            UpdateType::Driver => "Driver Update",
            UpdateType::ServicePack => "Service Pack",
            UpdateType::FeaturePack => "Feature Pack",
        }
    }
}

// ============================================================================
// Update Status
// ============================================================================

/// Update installation status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpdateStatus {
    /// Not installed
    #[default]
    NotInstalled = 0,
    /// Downloaded
    Downloaded = 1,
    /// Installing
    Installing = 2,
    /// Installed
    Installed = 3,
    /// Failed
    Failed = 4,
    /// Superseded
    Superseded = 5,
    /// Hidden (user declined)
    Hidden = 6,
}

impl UpdateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateStatus::NotInstalled => "Not Installed",
            UpdateStatus::Downloaded => "Downloaded",
            UpdateStatus::Installing => "Installing",
            UpdateStatus::Installed => "Installed",
            UpdateStatus::Failed => "Failed",
            UpdateStatus::Superseded => "Superseded",
            UpdateStatus::Hidden => "Hidden",
        }
    }
}

// ============================================================================
// Schedule Day
// ============================================================================

/// Day of week for scheduled updates
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScheduleDay {
    /// Every day
    #[default]
    EveryDay = 0,
    /// Sunday
    Sunday = 1,
    /// Monday
    Monday = 2,
    /// Tuesday
    Tuesday = 3,
    /// Wednesday
    Wednesday = 4,
    /// Thursday
    Thursday = 5,
    /// Friday
    Friday = 6,
    /// Saturday
    Saturday = 7,
}

impl ScheduleDay {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScheduleDay::EveryDay => "Every day",
            ScheduleDay::Sunday => "Sunday",
            ScheduleDay::Monday => "Monday",
            ScheduleDay::Tuesday => "Tuesday",
            ScheduleDay::Wednesday => "Wednesday",
            ScheduleDay::Thursday => "Thursday",
            ScheduleDay::Friday => "Friday",
            ScheduleDay::Saturday => "Saturday",
        }
    }
}

// ============================================================================
// Update Entry
// ============================================================================

/// Update history entry
#[derive(Debug, Clone, Copy)]
pub struct UpdateEntry {
    /// Update title
    pub title: [u8; MAX_TITLE],
    /// Title length
    pub title_len: usize,
    /// KB article number
    pub kb_number: [u8; MAX_KB],
    /// KB length
    pub kb_len: usize,
    /// Update type
    pub update_type: UpdateType,
    /// Status
    pub status: UpdateStatus,
    /// Size in bytes
    pub size: u64,
    /// Install date (timestamp)
    pub install_date: u64,
    /// Requires restart
    pub requires_restart: bool,
}

impl UpdateEntry {
    pub const fn new() -> Self {
        Self {
            title: [0u8; MAX_TITLE],
            title_len: 0,
            kb_number: [0u8; MAX_KB],
            kb_len: 0,
            update_type: UpdateType::Critical,
            status: UpdateStatus::NotInstalled,
            size: 0,
            install_date: 0,
            requires_restart: false,
        }
    }

    pub fn set_title(&mut self, title: &[u8]) {
        let len = title.len().min(MAX_TITLE);
        self.title[..len].copy_from_slice(&title[..len]);
        self.title_len = len;
    }

    pub fn set_kb(&mut self, kb: &[u8]) {
        let len = kb.len().min(MAX_KB);
        self.kb_number[..len].copy_from_slice(&kb[..len]);
        self.kb_len = len;
    }
}

impl Default for UpdateEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Auto Update Settings
// ============================================================================

/// Automatic Updates settings
#[derive(Debug, Clone, Copy)]
pub struct AutoUpdateSettings {
    /// Update mode
    pub mode: UpdateMode,
    /// Scheduled day
    pub schedule_day: ScheduleDay,
    /// Scheduled hour (0-23)
    pub schedule_hour: u8,
    /// Include recommended updates
    pub include_recommended: bool,
    /// Allow non-admin to install updates
    pub allow_non_admin: bool,
    /// Use Microsoft Update (vs Windows Update only)
    pub use_microsoft_update: bool,
    /// WSUS server URL (for enterprise)
    pub wsus_server: [u8; 256],
    /// WSUS server length
    pub wsus_len: usize,
}

impl AutoUpdateSettings {
    pub const fn new() -> Self {
        Self {
            mode: UpdateMode::DownloadNotify,
            schedule_day: ScheduleDay::EveryDay,
            schedule_hour: 3, // 3:00 AM default
            include_recommended: false,
            allow_non_admin: false,
            use_microsoft_update: false,
            wsus_server: [0u8; 256],
            wsus_len: 0,
        }
    }

    pub fn set_wsus_server(&mut self, url: &[u8]) {
        let len = url.len().min(256);
        self.wsus_server[..len].copy_from_slice(&url[..len]);
        self.wsus_len = len;
    }
}

impl Default for AutoUpdateSettings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Auto Update State
// ============================================================================

/// Automatic Updates state
struct AutoUpdateState {
    /// Settings
    settings: AutoUpdateSettings,
    /// Update history
    history: [UpdateEntry; MAX_HISTORY],
    /// History count
    history_count: usize,
    /// Pending updates (waiting to be installed)
    pending: [UpdateEntry; 32],
    /// Pending count
    pending_count: usize,
    /// Last check timestamp
    last_check: u64,
    /// Next scheduled check
    next_check: u64,
    /// Currently checking for updates
    checking: bool,
    /// Currently downloading
    downloading: bool,
    /// Currently installing
    installing: bool,
    /// Restart required
    restart_required: bool,
}

impl AutoUpdateState {
    pub const fn new() -> Self {
        Self {
            settings: AutoUpdateSettings::new(),
            history: [const { UpdateEntry::new() }; MAX_HISTORY],
            history_count: 0,
            pending: [const { UpdateEntry::new() }; 32],
            pending_count: 0,
            last_check: 0,
            next_check: 0,
            checking: false,
            downloading: false,
            installing: false,
            restart_required: false,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static AUTOUPDATE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static AUTOUPDATE_STATE: SpinLock<AutoUpdateState> = SpinLock::new(AutoUpdateState::new());

// Statistics
static UPDATES_INSTALLED: AtomicU32 = AtomicU32::new(0);
static UPDATES_FAILED: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Automatic Updates
pub fn init() {
    if AUTOUPDATE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = AUTOUPDATE_STATE.lock();

    // Default settings
    state.settings = AutoUpdateSettings::new();

    // Add sample update history
    add_sample_history(&mut state);

    crate::serial_println!("[WIN32K] Automatic Updates initialized");
}

/// Add sample update history
fn add_sample_history(state: &mut AutoUpdateState) {
    let updates: [(&[u8], &[u8], UpdateType, u64); 8] = [
        (b"Security Update for Windows Server 2003 (KB835732)", b"KB835732", UpdateType::Security, 5_242_880),
        (b"Cumulative Security Update for Internet Explorer", b"KB867282", UpdateType::Security, 3_145_728),
        (b"Update for Windows Server 2003 (KB885835)", b"KB885835", UpdateType::Important, 1_048_576),
        (b"Windows Server 2003 Service Pack 1", b"SP1", UpdateType::ServicePack, 314_572_800),
        (b"Security Update for Windows Server 2003 (KB890046)", b"KB890046", UpdateType::Security, 2_097_152),
        (b"Update for Background Intelligent Transfer Service", b"KB842773", UpdateType::Important, 524_288),
        (b"DirectX End-User Runtime", b"KB839643", UpdateType::Recommended, 52_428_800),
        (b"Windows Malicious Software Removal Tool", b"KB890830", UpdateType::Important, 10_485_760),
    ];

    for (title, kb, utype, size) in updates.iter() {
        if state.history_count >= MAX_HISTORY {
            break;
        }
        let mut entry = UpdateEntry::new();
        entry.set_title(title);
        entry.set_kb(kb);
        entry.update_type = *utype;
        entry.status = UpdateStatus::Installed;
        entry.size = *size;
        entry.install_date = 1104537600 + (state.history_count as u64 * 86400);
        state.history[state.history_count] = entry;
        state.history_count += 1;
    }

    UPDATES_INSTALLED.store(state.history_count as u32, Ordering::Relaxed);
}

// ============================================================================
// Settings Management
// ============================================================================

/// Get current settings
pub fn get_settings() -> AutoUpdateSettings {
    AUTOUPDATE_STATE.lock().settings
}

/// Set update mode
pub fn set_mode(mode: UpdateMode) {
    AUTOUPDATE_STATE.lock().settings.mode = mode;
}

/// Get update mode
pub fn get_mode() -> UpdateMode {
    AUTOUPDATE_STATE.lock().settings.mode
}

/// Set schedule
pub fn set_schedule(day: ScheduleDay, hour: u8) {
    let mut state = AUTOUPDATE_STATE.lock();
    state.settings.schedule_day = day;
    state.settings.schedule_hour = hour.min(23);
}

/// Get schedule day
pub fn get_schedule_day() -> ScheduleDay {
    AUTOUPDATE_STATE.lock().settings.schedule_day
}

/// Get schedule hour
pub fn get_schedule_hour() -> u8 {
    AUTOUPDATE_STATE.lock().settings.schedule_hour
}

/// Set include recommended updates
pub fn set_include_recommended(include: bool) {
    AUTOUPDATE_STATE.lock().settings.include_recommended = include;
}

/// Set WSUS server
pub fn set_wsus_server(url: &[u8]) {
    AUTOUPDATE_STATE.lock().settings.set_wsus_server(url);
}

// ============================================================================
// Update Operations
// ============================================================================

/// Check for updates
pub fn check_for_updates() -> bool {
    let mut state = AUTOUPDATE_STATE.lock();

    if state.checking {
        return false;
    }

    state.checking = true;
    // Would actually query Windows Update servers here
    state.last_check = 0; // Would be current timestamp
    state.checking = false;

    true
}

/// Is currently checking for updates
pub fn is_checking() -> bool {
    AUTOUPDATE_STATE.lock().checking
}

/// Get pending update count
pub fn get_pending_count() -> usize {
    AUTOUPDATE_STATE.lock().pending_count
}

/// Get pending update by index
pub fn get_pending_update(index: usize) -> Option<UpdateEntry> {
    let state = AUTOUPDATE_STATE.lock();
    if index < state.pending_count {
        Some(state.pending[index])
    } else {
        None
    }
}

/// Install all pending updates
pub fn install_updates() -> bool {
    let mut state = AUTOUPDATE_STATE.lock();

    if state.installing || state.pending_count == 0 {
        return false;
    }

    state.installing = true;

    // Would actually install updates here
    // For simulation, just move to history
    let pending_count = state.pending_count;
    for i in 0..pending_count {
        if state.history_count < MAX_HISTORY {
            state.pending[i].status = UpdateStatus::Installed;
            state.pending[i].install_date = 0; // Would be current timestamp
            let hist_idx = state.history_count;
            state.history[hist_idx] = state.pending[i];
            state.history_count += 1;
            UPDATES_INSTALLED.fetch_add(1, Ordering::Relaxed);
        }
    }
    state.pending_count = 0;
    state.installing = false;
    state.restart_required = true;

    true
}

/// Is currently installing updates
pub fn is_installing() -> bool {
    AUTOUPDATE_STATE.lock().installing
}

/// Check if restart is required
pub fn is_restart_required() -> bool {
    AUTOUPDATE_STATE.lock().restart_required
}

/// Clear restart required flag
pub fn clear_restart_required() {
    AUTOUPDATE_STATE.lock().restart_required = false;
}

// ============================================================================
// History
// ============================================================================

/// Get history count
pub fn get_history_count() -> usize {
    AUTOUPDATE_STATE.lock().history_count
}

/// Get history entry by index
pub fn get_history_entry(index: usize) -> Option<UpdateEntry> {
    let state = AUTOUPDATE_STATE.lock();
    if index < state.history_count {
        Some(state.history[index])
    } else {
        None
    }
}

/// Get last check timestamp
pub fn get_last_check() -> u64 {
    AUTOUPDATE_STATE.lock().last_check
}

// ============================================================================
// Statistics
// ============================================================================

/// Automatic Updates statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct AutoUpdateStats {
    pub initialized: bool,
    pub mode: UpdateMode,
    pub updates_installed: u32,
    pub updates_failed: u32,
    pub pending_count: usize,
    pub history_count: usize,
    pub restart_required: bool,
    pub checking: bool,
    pub installing: bool,
}

/// Get Automatic Updates statistics
pub fn get_stats() -> AutoUpdateStats {
    let state = AUTOUPDATE_STATE.lock();
    AutoUpdateStats {
        initialized: AUTOUPDATE_INITIALIZED.load(Ordering::Relaxed),
        mode: state.settings.mode,
        updates_installed: UPDATES_INSTALLED.load(Ordering::Relaxed),
        updates_failed: UPDATES_FAILED.load(Ordering::Relaxed),
        pending_count: state.pending_count,
        history_count: state.history_count,
        restart_required: state.restart_required,
        checking: state.checking,
        installing: state.installing,
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Automatic Updates dialog handle
pub type HAUTOUPDATEDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Automatic Updates dialog
pub fn create_autoupdate_dialog(_parent: super::super::HWND) -> HAUTOUPDATEDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
