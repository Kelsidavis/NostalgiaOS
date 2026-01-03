//! Windows Update Agent Service (wuauserv)
//!
//! Automatic Updates and Windows Update client functionality:
//!
//! - **Update Detection**: Check for available updates
//! - **Download Management**: Download updates using BITS
//! - **Installation**: Install downloaded updates
//! - **Scheduled Updates**: Automatic update scheduling
//! - **Update History**: Track installed updates
//!
//! # Registry Location
//!
//! `HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate`
//! `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate`

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;
use alloc::vec::Vec;

// ============================================================================
// Windows Update Constants
// ============================================================================

/// Maximum updates in queue
pub const MAX_UPDATES: usize = 64;

/// Maximum installed updates history
pub const MAX_HISTORY: usize = 128;

/// Maximum update title length
pub const MAX_TITLE: usize = 128;

/// Maximum update description length
pub const MAX_DESCRIPTION: usize = 256;

/// Maximum KB number length
pub const MAX_KB_NUMBER: usize = 16;

/// Maximum update ID (GUID) length
pub const MAX_UPDATE_ID: usize = 40;

/// Maximum URL length
pub const MAX_URL: usize = 256;

// ============================================================================
// Update Type
// ============================================================================

/// Update classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum UpdateType {
    /// Security update
    #[default]
    Security = 0,
    /// Critical update
    Critical = 1,
    /// Recommended update (feature pack)
    Recommended = 2,
    /// Optional update
    Optional = 3,
    /// Driver update
    Driver = 4,
    /// Definition update (antivirus)
    Definition = 5,
    /// Service pack
    ServicePack = 6,
    /// Hotfix
    Hotfix = 7,
}

impl UpdateType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => UpdateType::Security,
            1 => UpdateType::Critical,
            2 => UpdateType::Recommended,
            3 => UpdateType::Optional,
            4 => UpdateType::Driver,
            5 => UpdateType::Definition,
            6 => UpdateType::ServicePack,
            7 => UpdateType::Hotfix,
            _ => UpdateType::Optional,
        }
    }

    /// Get priority (lower = higher priority)
    pub fn priority(&self) -> u32 {
        match self {
            UpdateType::Critical => 1,
            UpdateType::Security => 2,
            UpdateType::ServicePack => 3,
            UpdateType::Hotfix => 4,
            UpdateType::Definition => 5,
            UpdateType::Recommended => 6,
            UpdateType::Driver => 7,
            UpdateType::Optional => 8,
        }
    }
}

// ============================================================================
// Update State
// ============================================================================

/// Update installation state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum UpdateState {
    /// Not yet downloaded
    #[default]
    NotStarted = 0,
    /// Downloading
    Downloading = 1,
    /// Download complete, ready to install
    Downloaded = 2,
    /// Installing
    Installing = 3,
    /// Installation complete
    Installed = 4,
    /// Pending reboot to complete
    PendingReboot = 5,
    /// Installation failed
    Failed = 6,
    /// User declined
    Declined = 7,
    /// Hidden by user
    Hidden = 8,
}

impl UpdateState {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => UpdateState::NotStarted,
            1 => UpdateState::Downloading,
            2 => UpdateState::Downloaded,
            3 => UpdateState::Installing,
            4 => UpdateState::Installed,
            5 => UpdateState::PendingReboot,
            6 => UpdateState::Failed,
            7 => UpdateState::Declined,
            8 => UpdateState::Hidden,
            _ => UpdateState::NotStarted,
        }
    }
}

// ============================================================================
// Automatic Update Options
// ============================================================================

/// Automatic update notification level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum AutoUpdateNotify {
    /// Disabled (not recommended)
    Disabled = 1,
    /// Notify before download
    NotifyBeforeDownload = 2,
    /// Auto download, notify before install
    #[default]
    AutoDownloadNotifyInstall = 3,
    /// Auto download and install on schedule
    ScheduledInstall = 4,
}

impl AutoUpdateNotify {
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => AutoUpdateNotify::Disabled,
            2 => AutoUpdateNotify::NotifyBeforeDownload,
            3 => AutoUpdateNotify::AutoDownloadNotifyInstall,
            4 => AutoUpdateNotify::ScheduledInstall,
            _ => AutoUpdateNotify::AutoDownloadNotifyInstall,
        }
    }
}

// ============================================================================
// Error Codes
// ============================================================================

/// Windows Update error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WuError {
    /// Success
    Success = 0,
    /// Update not found
    UpdateNotFound = 0x80240007,
    /// Invalid parameter
    InvalidParameter = 0x80240008,
    /// Download failed
    DownloadFailed = 0x80240009,
    /// Install failed
    InstallFailed = 0x8024000A,
    /// Service not running
    ServiceNotRunning = 0x8024000B,
    /// Already downloading
    AlreadyDownloading = 0x8024000C,
    /// Already installed
    AlreadyInstalled = 0x8024000D,
    /// Reboot required
    RebootRequired = 0x8024000E,
    /// Network error
    NetworkError = 0x8024000F,
    /// Maximum updates reached
    MaxUpdatesReached = 0x80240010,
    /// Server error
    ServerError = 0x80240011,
    /// Update declined
    Declined = 0x80240012,
}

// ============================================================================
// Update Entry
// ============================================================================

/// Windows Update entry
#[repr(C)]
pub struct UpdateEntry {
    /// Update ID (GUID string)
    pub update_id: [u8; MAX_UPDATE_ID],
    /// KB number (e.g., "KB123456")
    pub kb_number: [u8; MAX_KB_NUMBER],
    /// Update title
    pub title: [u8; MAX_TITLE],
    /// Description
    pub description: [u8; MAX_DESCRIPTION],
    /// Download URL
    pub download_url: [u8; MAX_URL],
    /// Update type
    pub update_type: UpdateType,
    /// Current state
    pub state: AtomicU32,
    /// Download size (bytes)
    pub download_size: u64,
    /// Downloaded bytes
    pub downloaded_bytes: u64,
    /// Severity level (0-4, 4 = critical)
    pub severity: u32,
    /// Requires reboot
    pub requires_reboot: bool,
    /// Is mandatory
    pub mandatory: bool,
    /// Is EULA accepted
    pub eula_accepted: bool,
    /// Detection time
    pub detection_time: u64,
    /// Installation time (if installed)
    pub install_time: u64,
    /// Entry valid
    pub valid: bool,
}

impl UpdateEntry {
    pub const fn empty() -> Self {
        Self {
            update_id: [0; MAX_UPDATE_ID],
            kb_number: [0; MAX_KB_NUMBER],
            title: [0; MAX_TITLE],
            description: [0; MAX_DESCRIPTION],
            download_url: [0; MAX_URL],
            update_type: UpdateType::Security,
            state: AtomicU32::new(UpdateState::NotStarted as u32),
            download_size: 0,
            downloaded_bytes: 0,
            severity: 0,
            requires_reboot: false,
            mandatory: false,
            eula_accepted: false,
            detection_time: 0,
            install_time: 0,
            valid: false,
        }
    }

    pub fn set_update_id(&mut self, id: &str) {
        let bytes = id.as_bytes();
        let len = bytes.len().min(MAX_UPDATE_ID - 1);
        self.update_id[..len].copy_from_slice(&bytes[..len]);
        self.update_id[len] = 0;
    }

    pub fn update_id_str(&self) -> &str {
        let len = self.update_id.iter().position(|&b| b == 0).unwrap_or(MAX_UPDATE_ID);
        core::str::from_utf8(&self.update_id[..len]).unwrap_or("")
    }

    pub fn set_kb_number(&mut self, kb: &str) {
        let bytes = kb.as_bytes();
        let len = bytes.len().min(MAX_KB_NUMBER - 1);
        self.kb_number[..len].copy_from_slice(&bytes[..len]);
        self.kb_number[len] = 0;
    }

    pub fn kb_number_str(&self) -> &str {
        let len = self.kb_number.iter().position(|&b| b == 0).unwrap_or(MAX_KB_NUMBER);
        core::str::from_utf8(&self.kb_number[..len]).unwrap_or("")
    }

    pub fn set_title(&mut self, title: &str) {
        let bytes = title.as_bytes();
        let len = bytes.len().min(MAX_TITLE - 1);
        self.title[..len].copy_from_slice(&bytes[..len]);
        self.title[len] = 0;
    }

    pub fn title_str(&self) -> &str {
        let len = self.title.iter().position(|&b| b == 0).unwrap_or(MAX_TITLE);
        core::str::from_utf8(&self.title[..len]).unwrap_or("")
    }

    pub fn set_description(&mut self, desc: &str) {
        let bytes = desc.as_bytes();
        let len = bytes.len().min(MAX_DESCRIPTION - 1);
        self.description[..len].copy_from_slice(&bytes[..len]);
        self.description[len] = 0;
    }

    pub fn set_download_url(&mut self, url: &str) {
        let bytes = url.as_bytes();
        let len = bytes.len().min(MAX_URL - 1);
        self.download_url[..len].copy_from_slice(&bytes[..len]);
        self.download_url[len] = 0;
    }

    pub fn download_url_str(&self) -> &str {
        let len = self.download_url.iter().position(|&b| b == 0).unwrap_or(MAX_URL);
        core::str::from_utf8(&self.download_url[..len]).unwrap_or("")
    }

    pub fn get_state(&self) -> UpdateState {
        UpdateState::from_u32(self.state.load(Ordering::SeqCst))
    }

    pub fn set_state(&self, state: UpdateState) {
        self.state.store(state as u32, Ordering::SeqCst);
    }

    /// Get download progress (0-100)
    pub fn download_progress(&self) -> u32 {
        if self.download_size == 0 {
            return 0;
        }
        ((self.downloaded_bytes * 100) / self.download_size) as u32
    }
}

// ============================================================================
// Update History Entry
// ============================================================================

/// Installed update history entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UpdateHistoryEntry {
    /// Update ID
    pub update_id: [u8; MAX_UPDATE_ID],
    /// KB number
    pub kb_number: [u8; MAX_KB_NUMBER],
    /// Title
    pub title: [u8; MAX_TITLE],
    /// Update type
    pub update_type: UpdateType,
    /// Installation date
    pub install_date: u64,
    /// Result code (0 = success)
    pub result_code: u32,
    /// Entry valid
    pub valid: bool,
}

impl UpdateHistoryEntry {
    pub const fn empty() -> Self {
        Self {
            update_id: [0; MAX_UPDATE_ID],
            kb_number: [0; MAX_KB_NUMBER],
            title: [0; MAX_TITLE],
            update_type: UpdateType::Security,
            install_date: 0,
            result_code: 0,
            valid: false,
        }
    }

    pub fn kb_number_str(&self) -> &str {
        let len = self.kb_number.iter().position(|&b| b == 0).unwrap_or(MAX_KB_NUMBER);
        core::str::from_utf8(&self.kb_number[..len]).unwrap_or("")
    }

    pub fn title_str(&self) -> &str {
        let len = self.title.iter().position(|&b| b == 0).unwrap_or(MAX_TITLE);
        core::str::from_utf8(&self.title[..len]).unwrap_or("")
    }
}

// ============================================================================
// Windows Update Configuration
// ============================================================================

/// Windows Update configuration
#[repr(C)]
pub struct WuConfig {
    /// Automatic update setting
    pub auto_update: AutoUpdateNotify,
    /// Scheduled install day (0=every day, 1-7=Sun-Sat)
    pub scheduled_day: u32,
    /// Scheduled install time (hour, 0-23)
    pub scheduled_time: u32,
    /// Enable recommended updates
    pub include_recommended: bool,
    /// Use Microsoft Update (not just Windows Update)
    pub use_microsoft_update: bool,
    /// Allow non-admin install
    pub non_admin_install: bool,
    /// Show update notifications
    pub show_notifications: bool,
    /// Auto-reboot after install
    pub auto_reboot: bool,
    /// WSUS server URL (if using internal server)
    pub wsus_server: [u8; MAX_URL],
    /// Detection frequency (hours)
    pub detection_frequency: u32,
}

impl WuConfig {
    pub const fn new() -> Self {
        Self {
            auto_update: AutoUpdateNotify::AutoDownloadNotifyInstall,
            scheduled_day: 0,
            scheduled_time: 3, // 3 AM
            include_recommended: true,
            use_microsoft_update: false,
            non_admin_install: false,
            show_notifications: true,
            auto_reboot: false,
            wsus_server: [0; MAX_URL],
            detection_frequency: 22, // Every 22 hours
        }
    }
}

// ============================================================================
// Windows Update State
// ============================================================================

/// Windows Update service state
#[repr(C)]
pub struct WuState {
    /// Configuration
    pub config: WuConfig,
    /// Pending updates
    pub updates: [UpdateEntry; MAX_UPDATES],
    /// Update count
    pub update_count: usize,
    /// Installation history
    pub history: [UpdateHistoryEntry; MAX_HISTORY],
    /// History count
    pub history_count: usize,
    /// Last detection time
    pub last_detection: u64,
    /// Last installation time
    pub last_install: u64,
    /// Reboot pending
    pub reboot_pending: bool,
    /// Currently checking
    pub checking: bool,
    /// Currently downloading
    pub downloading: bool,
    /// Currently installing
    pub installing: bool,
    /// Service running
    pub running: bool,
}

impl WuState {
    pub const fn new() -> Self {
        Self {
            config: WuConfig::new(),
            updates: [const { UpdateEntry::empty() }; MAX_UPDATES],
            update_count: 0,
            history: [const { UpdateHistoryEntry::empty() }; MAX_HISTORY],
            history_count: 0,
            last_detection: 0,
            last_install: 0,
            reboot_pending: false,
            checking: false,
            downloading: false,
            installing: false,
            running: false,
        }
    }
}

/// Global Windows Update state
static WU_STATE: SpinLock<WuState> = SpinLock::new(WuState::new());

/// Windows Update statistics
pub struct WuStats {
    /// Detection checks performed
    pub checks_performed: AtomicU64,
    /// Updates detected
    pub updates_detected: AtomicU64,
    /// Updates downloaded
    pub updates_downloaded: AtomicU64,
    /// Updates installed
    pub updates_installed: AtomicU64,
    /// Updates failed
    pub updates_failed: AtomicU64,
    /// Bytes downloaded
    pub bytes_downloaded: AtomicU64,
    /// Reboots triggered
    pub reboots_triggered: AtomicU64,
}

impl WuStats {
    pub const fn new() -> Self {
        Self {
            checks_performed: AtomicU64::new(0),
            updates_detected: AtomicU64::new(0),
            updates_downloaded: AtomicU64::new(0),
            updates_installed: AtomicU64::new(0),
            updates_failed: AtomicU64::new(0),
            bytes_downloaded: AtomicU64::new(0),
            reboots_triggered: AtomicU64::new(0),
        }
    }
}

static WU_STATS: WuStats = WuStats::new();

// ============================================================================
// Windows Update API
// ============================================================================

/// Check for updates
pub fn check_for_updates() -> Result<u32, WuError> {
    let mut state = WU_STATE.lock();

    if !state.running {
        return Err(WuError::ServiceNotRunning);
    }

    if state.checking {
        return Ok(0); // Already checking
    }

    state.checking = true;
    let current_time = crate::hal::apic::get_tick_count();
    state.last_detection = current_time;

    crate::serial_println!("[WU] Checking for updates...");

    // In a real implementation, this would:
    // 1. Connect to Windows Update / WSUS server
    // 2. Send system information
    // 3. Receive available updates
    // 4. Parse and add to pending updates

    // For simulation, add some sample updates
    let sample_updates = [
        ("KB123456", "Security Update for Windows", UpdateType::Security, 4, 1024 * 1024),
        ("KB234567", "Cumulative Update", UpdateType::Critical, 3, 50 * 1024 * 1024),
        ("KB345678", ".NET Framework Update", UpdateType::Recommended, 2, 10 * 1024 * 1024),
    ];

    let mut detected = 0u32;
    for (kb, title, update_type, severity, size) in sample_updates {
        let update_count = state.update_count;
        if update_count < MAX_UPDATES {
            let update = &mut state.updates[update_count];
            *update = UpdateEntry::empty();
            update.set_kb_number(kb);
            update.set_title(title);
            update.update_type = update_type;
            update.severity = severity;
            update.download_size = size;
            update.detection_time = current_time;
            update.valid = true;

            state.update_count += 1;
            detected += 1;

            WU_STATS.updates_detected.fetch_add(1, Ordering::Relaxed);
        }
    }

    state.checking = false;

    WU_STATS.checks_performed.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[WU] Found {} updates", detected);

    Ok(detected)
}

/// Download an update
pub fn download_update(kb_number: &str) -> Result<(), WuError> {
    let mut state = WU_STATE.lock();

    if !state.running {
        return Err(WuError::ServiceNotRunning);
    }

    // Find update
    let mut update_idx = None;
    for i in 0..state.update_count {
        if state.updates[i].valid && state.updates[i].kb_number_str() == kb_number {
            update_idx = Some(i);
            break;
        }
    }

    let idx = match update_idx {
        Some(i) => i,
        None => return Err(WuError::UpdateNotFound),
    };

    let current_state = state.updates[idx].get_state();
    match current_state {
        UpdateState::NotStarted | UpdateState::Failed => {
            state.updates[idx].set_state(UpdateState::Downloading);
            state.downloading = true;

            crate::serial_println!("[WU] Starting download of {}", kb_number);

            // In real implementation, this would use BITS to download
            // For simulation, mark as downloaded
            let size = state.updates[idx].download_size;
            state.updates[idx].downloaded_bytes = size;
            state.updates[idx].set_state(UpdateState::Downloaded);

            WU_STATS.updates_downloaded.fetch_add(1, Ordering::Relaxed);
            WU_STATS.bytes_downloaded.fetch_add(size, Ordering::Relaxed);

            state.downloading = false;

            crate::serial_println!("[WU] Download complete: {}", kb_number);

            Ok(())
        }
        UpdateState::Downloading => Err(WuError::AlreadyDownloading),
        UpdateState::Downloaded | UpdateState::Installed => Err(WuError::AlreadyInstalled),
        _ => Err(WuError::InvalidParameter),
    }
}

/// Install an update
pub fn install_update(kb_number: &str) -> Result<(), WuError> {
    let mut state = WU_STATE.lock();

    if !state.running {
        return Err(WuError::ServiceNotRunning);
    }

    // Find update
    let mut update_idx = None;
    for i in 0..state.update_count {
        if state.updates[i].valid && state.updates[i].kb_number_str() == kb_number {
            update_idx = Some(i);
            break;
        }
    }

    let idx = match update_idx {
        Some(i) => i,
        None => return Err(WuError::UpdateNotFound),
    };

    let current_state = state.updates[idx].get_state();
    if current_state != UpdateState::Downloaded {
        return Err(WuError::InvalidParameter);
    }

    state.updates[idx].set_state(UpdateState::Installing);
    state.installing = true;

    let current_time = crate::hal::apic::get_tick_count();

    crate::serial_println!("[WU] Installing {}...", kb_number);

    // Simulate installation
    state.updates[idx].install_time = current_time;

    let requires_reboot = state.updates[idx].requires_reboot;
    if requires_reboot {
        state.updates[idx].set_state(UpdateState::PendingReboot);
        state.reboot_pending = true;
    } else {
        state.updates[idx].set_state(UpdateState::Installed);
    }

    // Add to history
    let history_count = state.history_count;
    if history_count < MAX_HISTORY {
        // Copy values from update first
        let update_id = state.updates[idx].update_id;
        let kb_number = state.updates[idx].kb_number;
        let title = state.updates[idx].title;
        let update_type = state.updates[idx].update_type;

        let history = &mut state.history[history_count];
        history.update_id = update_id;
        history.kb_number = kb_number;
        history.title = title;
        history.update_type = update_type;
        history.install_date = current_time;
        history.result_code = 0;
        history.valid = true;
        state.history_count += 1;
    }

    state.last_install = current_time;
    state.installing = false;

    WU_STATS.updates_installed.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[WU] Installation complete: {} (reboot={})",
        kb_number, requires_reboot);

    if requires_reboot {
        Ok(())
    } else {
        Ok(())
    }
}

/// Download all pending updates
pub fn download_all() -> Result<u32, WuError> {
    let state = WU_STATE.lock();

    if !state.running {
        return Err(WuError::ServiceNotRunning);
    }

    // Collect KB numbers to download
    let mut to_download = Vec::new();
    for i in 0..state.update_count {
        if state.updates[i].valid && state.updates[i].get_state() == UpdateState::NotStarted {
            let mut kb = [0u8; MAX_KB_NUMBER];
            kb.copy_from_slice(&state.updates[i].kb_number);
            to_download.push(kb);
        }
    }

    drop(state); // Release lock

    let mut downloaded = 0u32;
    for kb in to_download {
        let kb_str = {
            let len = kb.iter().position(|&b| b == 0).unwrap_or(MAX_KB_NUMBER);
            core::str::from_utf8(&kb[..len]).unwrap_or("")
        };
        if download_update(kb_str).is_ok() {
            downloaded += 1;
        }
    }

    Ok(downloaded)
}

/// Install all downloaded updates
pub fn install_all() -> Result<u32, WuError> {
    let state = WU_STATE.lock();

    if !state.running {
        return Err(WuError::ServiceNotRunning);
    }

    // Collect KB numbers to install
    let mut to_install = Vec::new();
    for i in 0..state.update_count {
        if state.updates[i].valid && state.updates[i].get_state() == UpdateState::Downloaded {
            let mut kb = [0u8; MAX_KB_NUMBER];
            kb.copy_from_slice(&state.updates[i].kb_number);
            to_install.push(kb);
        }
    }

    drop(state); // Release lock

    let mut installed = 0u32;
    for kb in to_install {
        let kb_str = {
            let len = kb.iter().position(|&b| b == 0).unwrap_or(MAX_KB_NUMBER);
            core::str::from_utf8(&kb[..len]).unwrap_or("")
        };
        if install_update(kb_str).is_ok() {
            installed += 1;
        }
    }

    Ok(installed)
}

/// Hide an update (don't show again)
pub fn hide_update(kb_number: &str) -> Result<(), WuError> {
    let state = WU_STATE.lock();

    for i in 0..state.update_count {
        if state.updates[i].valid && state.updates[i].kb_number_str() == kb_number {
            state.updates[i].set_state(UpdateState::Hidden);
            crate::serial_println!("[WU] Hidden update: {}", kb_number);
            return Ok(());
        }
    }

    Err(WuError::UpdateNotFound)
}

/// Get pending update count
pub fn get_pending_count() -> (u32, u32, u32) {
    let state = WU_STATE.lock();

    let mut not_downloaded = 0u32;
    let mut downloaded = 0u32;
    let mut pending_reboot = 0u32;

    for i in 0..state.update_count {
        if !state.updates[i].valid {
            continue;
        }
        match state.updates[i].get_state() {
            UpdateState::NotStarted => not_downloaded += 1,
            UpdateState::Downloaded => downloaded += 1,
            UpdateState::PendingReboot => pending_reboot += 1,
            _ => {}
        }
    }

    (not_downloaded, downloaded, pending_reboot)
}

/// Enumerate pending updates
pub fn enumerate_updates() -> Vec<([u8; MAX_KB_NUMBER], UpdateState)> {
    let state = WU_STATE.lock();
    let mut result = Vec::new();

    for i in 0..state.update_count {
        if state.updates[i].valid {
            let state_val = state.updates[i].get_state();
            result.push((state.updates[i].kb_number, state_val));
        }
    }

    result
}

/// Get update history
pub fn get_history() -> Vec<([u8; MAX_KB_NUMBER], u64)> {
    let state = WU_STATE.lock();
    let mut result = Vec::new();

    for i in 0..state.history_count {
        if state.history[i].valid {
            result.push((state.history[i].kb_number, state.history[i].install_date));
        }
    }

    result
}

/// Set automatic update mode
pub fn set_auto_update(mode: AutoUpdateNotify) -> Result<(), WuError> {
    let mut state = WU_STATE.lock();
    state.config.auto_update = mode;
    crate::serial_println!("[WU] Auto-update mode set to {:?}", mode);
    Ok(())
}

/// Check if reboot is pending
pub fn is_reboot_pending() -> bool {
    let state = WU_STATE.lock();
    state.reboot_pending
}

// ============================================================================
// Automatic Update Processing
// ============================================================================

/// Process automatic updates (called periodically)
pub fn process_auto_update() {
    let state = WU_STATE.lock();

    if !state.running {
        return;
    }

    let auto_mode = state.config.auto_update;
    let detection_freq = state.config.detection_frequency as u64;
    let last_detection = state.last_detection;
    let current_time = crate::hal::apic::get_tick_count();

    drop(state); // Release lock

    // Check if detection is needed
    let freq_ms = detection_freq * 60 * 60 * 1000; // Hours to ms
    if auto_mode != AutoUpdateNotify::Disabled && current_time > last_detection + freq_ms {
        let _ = check_for_updates();
    }

    // Auto-download if configured
    match auto_mode {
        AutoUpdateNotify::AutoDownloadNotifyInstall | AutoUpdateNotify::ScheduledInstall => {
            let (pending, _, _) = get_pending_count();
            if pending > 0 {
                let _ = download_all();
            }
        }
        _ => {}
    }

    // Auto-install if scheduled
    if auto_mode == AutoUpdateNotify::ScheduledInstall {
        let state = WU_STATE.lock();
        let _scheduled_hour = state.config.scheduled_time;
        // In real implementation, check current time vs scheduled time
        // For now, just indicate capability
        drop(state);
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get Windows Update statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64, u64) {
    (
        WU_STATS.checks_performed.load(Ordering::Relaxed),
        WU_STATS.updates_detected.load(Ordering::Relaxed),
        WU_STATS.updates_downloaded.load(Ordering::Relaxed),
        WU_STATS.updates_installed.load(Ordering::Relaxed),
        WU_STATS.updates_failed.load(Ordering::Relaxed),
        WU_STATS.bytes_downloaded.load(Ordering::Relaxed),
        WU_STATS.reboots_triggered.load(Ordering::Relaxed),
    )
}

/// Get update count
pub fn get_update_count() -> usize {
    let state = WU_STATE.lock();
    state.update_count
}

/// Get history count
pub fn get_history_count() -> usize {
    let state = WU_STATE.lock();
    state.history_count
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = WU_STATE.lock();
    state.running
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Windows Update service
pub fn init() {
    crate::serial_println!("[WU] Initializing Windows Update Agent Service...");

    let mut state = WU_STATE.lock();
    state.running = true;

    crate::serial_println!("[WU] Windows Update initialized (mode: {:?})",
        state.config.auto_update);
}

/// Shutdown Windows Update service
pub fn shutdown() {
    crate::serial_println!("[WU] Shutting down Windows Update...");

    let mut state = WU_STATE.lock();
    state.running = false;

    let (checks, detected, downloaded, installed, failed, _, _) = get_statistics();
    crate::serial_println!("[WU] Stats: {} checks, {} detected, {} downloaded, {} installed, {} failed",
        checks, detected, downloaded, installed, failed);
}
