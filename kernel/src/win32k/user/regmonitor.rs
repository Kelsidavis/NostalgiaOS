//! Registry Change Monitoring
//!
//! Provides registry change notification support following the Windows
//! RegNotifyChangeKeyValue API pattern.
//!
//! # References
//!
//! - Windows Server 2003 advapi32 registry notification APIs
//! - RegNotifyChangeKeyValue and related functions

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::HWND;

// ============================================================================
// Constants
// ============================================================================

/// Maximum registry watchers
const MAX_REG_WATCHERS: usize = 256;

/// Maximum pending notifications
const MAX_PENDING_NOTIFICATIONS: usize = 1024;

/// Registry notification filter flags (REG_NOTIFY_CHANGE_*)
pub mod notify_filter {
    /// Notify on subkey creation/deletion
    pub const NAME: u32 = 0x00000001;
    /// Notify on attribute changes
    pub const ATTRIBUTES: u32 = 0x00000002;
    /// Notify on value changes
    pub const LAST_SET: u32 = 0x00000004;
    /// Notify on security descriptor changes
    pub const SECURITY: u32 = 0x00000008;
    /// Notify on all changes
    pub const ALL: u32 = NAME | ATTRIBUTES | LAST_SET | SECURITY;
}

/// Registry change event types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegChangeType {
    /// Subkey added
    SubkeyAdded = 0,
    /// Subkey deleted
    SubkeyDeleted = 1,
    /// Value added
    ValueAdded = 2,
    /// Value deleted
    ValueDeleted = 3,
    /// Value changed
    ValueChanged = 4,
    /// Key attributes changed
    AttributesChanged = 5,
    /// Security descriptor changed
    SecurityChanged = 6,
    /// Key renamed
    KeyRenamed = 7,
}

/// Registry hive identifiers
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegHive {
    #[default]
    ClassesRoot = 0x80000000,
    CurrentUser = 0x80000001,
    LocalMachine = 0x80000002,
    Users = 0x80000003,
    CurrentConfig = 0x80000005,
}

// ============================================================================
// Structures
// ============================================================================

/// Registry watcher state
#[derive(Debug, Clone, Copy)]
pub struct RegWatcher {
    /// Watcher is active
    pub active: bool,
    /// Watcher ID
    pub id: u32,
    /// Registry hive
    pub hive: RegHive,
    /// Subkey path hash (for matching)
    pub path_hash: u64,
    /// Notification filter
    pub filter: u32,
    /// Watch subtree
    pub watch_subtree: bool,
    /// Associated window for notifications
    pub hwnd: HWND,
    /// Custom notification message
    pub message: u32,
    /// Event handle for signaling
    pub event_handle: u32,
    /// Callback function pointer
    pub callback: usize,
    /// User data for callback
    pub user_data: usize,
    /// Pending notification count
    pub pending_count: u32,
}

impl RegWatcher {
    const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            hive: RegHive::LocalMachine,
            path_hash: 0,
            filter: 0,
            watch_subtree: false,
            hwnd: super::super::UserHandle::NULL,
            message: 0,
            event_handle: 0,
            callback: 0,
            user_data: 0,
            pending_count: 0,
        }
    }
}

/// Registry change notification
#[derive(Debug, Clone, Copy)]
pub struct RegNotification {
    /// Notification is valid
    pub valid: bool,
    /// Watcher that triggered this
    pub watcher_id: u32,
    /// Change type
    pub change_type: RegChangeType,
    /// Registry hive
    pub hive: RegHive,
    /// Path hash (for identifying key)
    pub path_hash: u64,
    /// Value name hash (if applicable)
    pub value_hash: u64,
    /// Timestamp
    pub timestamp: u64,
}

impl RegNotification {
    const fn new() -> Self {
        Self {
            valid: false,
            watcher_id: 0,
            change_type: RegChangeType::ValueChanged,
            hive: RegHive::LocalMachine,
            path_hash: 0,
            value_hash: 0,
            timestamp: 0,
        }
    }
}

/// Registry monitor statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct RegMonitorStats {
    /// Active watcher count
    pub watcher_count: u32,
    /// Total notifications processed
    pub notifications_processed: u64,
    /// Pending notifications
    pub pending_count: u32,
    /// Dropped notifications (buffer full)
    pub dropped_count: u64,
}

// ============================================================================
// State
// ============================================================================

static REGMON_INITIALIZED: AtomicBool = AtomicBool::new(false);
static REGMON_LOCK: SpinLock<()> = SpinLock::new(());
static NEXT_WATCHER_ID: AtomicU32 = AtomicU32::new(1);

static WATCHERS: SpinLock<[RegWatcher; MAX_REG_WATCHERS]> =
    SpinLock::new([const { RegWatcher::new() }; MAX_REG_WATCHERS]);

static NOTIFICATIONS: SpinLock<[RegNotification; MAX_PENDING_NOTIFICATIONS]> =
    SpinLock::new([const { RegNotification::new() }; MAX_PENDING_NOTIFICATIONS]);

static NOTIFICATIONS_PROCESSED: AtomicU32 = AtomicU32::new(0);
static NOTIFICATIONS_DROPPED: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize registry monitoring subsystem
pub fn init() {
    let _guard = REGMON_LOCK.lock();

    if REGMON_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[REGMON] Initializing registry monitoring...");

    REGMON_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[REGMON] Registry monitoring initialized");
}

// ============================================================================
// Watcher Management
// ============================================================================

/// Register for registry change notifications
///
/// # Arguments
/// * `hive` - Registry hive to monitor
/// * `path` - Subkey path to monitor
/// * `filter` - Notification filter flags
/// * `watch_subtree` - Watch subtree if true
/// * `event_handle` - Event to signal on changes
pub fn reg_notify_change_key_value(
    hive: RegHive,
    path: &[u8],
    filter: u32,
    watch_subtree: bool,
    event_handle: u32,
) -> Option<u32> {
    if !REGMON_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let path_hash = hash_path(path);
    let mut watchers = WATCHERS.lock();

    // Find free slot
    for watcher in watchers.iter_mut() {
        if !watcher.active {
            let id = NEXT_WATCHER_ID.fetch_add(1, Ordering::Relaxed);

            watcher.active = true;
            watcher.id = id;
            watcher.hive = hive;
            watcher.path_hash = path_hash;
            watcher.filter = filter;
            watcher.watch_subtree = watch_subtree;
            watcher.event_handle = event_handle;
            watcher.hwnd = super::super::UserHandle::NULL;
            watcher.message = 0;
            watcher.callback = 0;
            watcher.user_data = 0;
            watcher.pending_count = 0;

            return Some(id);
        }
    }

    None
}

/// Register for registry change notifications with window message
pub fn reg_notify_change_key_value_ex(
    hive: RegHive,
    path: &[u8],
    filter: u32,
    watch_subtree: bool,
    hwnd: HWND,
    message: u32,
) -> Option<u32> {
    if !REGMON_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let path_hash = hash_path(path);
    let mut watchers = WATCHERS.lock();

    for watcher in watchers.iter_mut() {
        if !watcher.active {
            let id = NEXT_WATCHER_ID.fetch_add(1, Ordering::Relaxed);

            watcher.active = true;
            watcher.id = id;
            watcher.hive = hive;
            watcher.path_hash = path_hash;
            watcher.filter = filter;
            watcher.watch_subtree = watch_subtree;
            watcher.event_handle = 0;
            watcher.hwnd = hwnd;
            watcher.message = message;
            watcher.callback = 0;
            watcher.user_data = 0;
            watcher.pending_count = 0;

            return Some(id);
        }
    }

    None
}

/// Register for registry change notifications with callback
pub fn reg_notify_change_key_value_callback(
    hive: RegHive,
    path: &[u8],
    filter: u32,
    watch_subtree: bool,
    callback: usize,
    user_data: usize,
) -> Option<u32> {
    if !REGMON_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let path_hash = hash_path(path);
    let mut watchers = WATCHERS.lock();

    for watcher in watchers.iter_mut() {
        if !watcher.active {
            let id = NEXT_WATCHER_ID.fetch_add(1, Ordering::Relaxed);

            watcher.active = true;
            watcher.id = id;
            watcher.hive = hive;
            watcher.path_hash = path_hash;
            watcher.filter = filter;
            watcher.watch_subtree = watch_subtree;
            watcher.event_handle = 0;
            watcher.hwnd = super::super::UserHandle::NULL;
            watcher.message = 0;
            watcher.callback = callback;
            watcher.user_data = user_data;
            watcher.pending_count = 0;

            return Some(id);
        }
    }

    None
}

/// Unregister a registry watcher
pub fn reg_unregister_notify(watcher_id: u32) -> bool {
    if !REGMON_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut watchers = WATCHERS.lock();

    for watcher in watchers.iter_mut() {
        if watcher.active && watcher.id == watcher_id {
            watcher.active = false;
            return true;
        }
    }

    false
}

/// Get watcher information
pub fn reg_get_watcher_info(watcher_id: u32) -> Option<RegWatcher> {
    if !REGMON_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let watchers = WATCHERS.lock();

    for watcher in watchers.iter() {
        if watcher.active && watcher.id == watcher_id {
            return Some(*watcher);
        }
    }

    None
}

// ============================================================================
// Notification Processing
// ============================================================================

/// Report a registry change (called by registry subsystem)
pub fn reg_report_change(
    hive: RegHive,
    path: &[u8],
    change_type: RegChangeType,
    value_name: Option<&[u8]>,
) {
    if !REGMON_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    let path_hash = hash_path(path);
    let value_hash = value_name.map(hash_path).unwrap_or(0);
    let filter_flag = change_type_to_filter(change_type);

    let watchers = WATCHERS.lock();

    for watcher in watchers.iter() {
        if !watcher.active {
            continue;
        }

        // Check if watcher matches this change
        if watcher.hive != hive {
            continue;
        }

        if (watcher.filter & filter_flag) == 0 {
            continue;
        }

        // Check path match
        if watcher.watch_subtree {
            // For subtree watch, check if path starts with watched path
            // (simplified - using hash comparison)
            if watcher.path_hash != path_hash {
                // In a real implementation, we'd check prefix
                continue;
            }
        } else {
            // Exact match required
            if watcher.path_hash != path_hash {
                continue;
            }
        }

        // Queue notification
        queue_notification(watcher.id, change_type, hive, path_hash, value_hash);
    }
}

/// Queue a notification for processing
fn queue_notification(
    watcher_id: u32,
    change_type: RegChangeType,
    hive: RegHive,
    path_hash: u64,
    value_hash: u64,
) {
    let mut notifications = NOTIFICATIONS.lock();

    // Find free slot
    for notification in notifications.iter_mut() {
        if !notification.valid {
            notification.valid = true;
            notification.watcher_id = watcher_id;
            notification.change_type = change_type;
            notification.hive = hive;
            notification.path_hash = path_hash;
            notification.value_hash = value_hash;
            notification.timestamp = get_timestamp();
            return;
        }
    }

    // Buffer full - drop notification
    NOTIFICATIONS_DROPPED.fetch_add(1, Ordering::Relaxed);
}

/// Process pending notifications
pub fn reg_process_notifications() {
    if !REGMON_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    let mut notifications = NOTIFICATIONS.lock();
    let watchers = WATCHERS.lock();

    for notification in notifications.iter_mut() {
        if !notification.valid {
            continue;
        }

        // Find watcher
        let mut watcher_found = false;
        for watcher in watchers.iter() {
            if watcher.active && watcher.id == notification.watcher_id {
                watcher_found = true;

                // Signal event if set
                if watcher.event_handle != 0 {
                    // Signal event (would call ke::event::set_event)
                }

                // Post message if set
                if watcher.hwnd != super::super::UserHandle::NULL && watcher.message != 0 {
                    super::message::post_message(
                        watcher.hwnd,
                        watcher.message,
                        notification.change_type as usize,
                        notification.path_hash as isize,
                    );
                }

                // Call callback if set
                if watcher.callback != 0 {
                    // Callback would be called here
                }

                break;
            }
        }

        // Mark as processed
        notification.valid = false;
        NOTIFICATIONS_PROCESSED.fetch_add(1, Ordering::Relaxed);

        if !watcher_found {
            // Watcher was unregistered - just drop
        }
    }
}

/// Get pending notification for a watcher
pub fn reg_get_pending_notification(watcher_id: u32) -> Option<RegNotification> {
    if !REGMON_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let mut notifications = NOTIFICATIONS.lock();

    for notification in notifications.iter_mut() {
        if notification.valid && notification.watcher_id == watcher_id {
            let result = *notification;
            notification.valid = false;
            NOTIFICATIONS_PROCESSED.fetch_add(1, Ordering::Relaxed);
            return Some(result);
        }
    }

    None
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Hash a path for quick comparison
fn hash_path(path: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV-1a offset basis

    for &byte in path {
        // Case-insensitive hashing
        let b = if byte >= b'a' && byte <= b'z' {
            byte - 32
        } else {
            byte
        };
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV prime
    }

    hash
}

/// Convert change type to filter flag
fn change_type_to_filter(change_type: RegChangeType) -> u32 {
    match change_type {
        RegChangeType::SubkeyAdded | RegChangeType::SubkeyDeleted | RegChangeType::KeyRenamed => {
            notify_filter::NAME
        }
        RegChangeType::ValueAdded | RegChangeType::ValueDeleted | RegChangeType::ValueChanged => {
            notify_filter::LAST_SET
        }
        RegChangeType::AttributesChanged => notify_filter::ATTRIBUTES,
        RegChangeType::SecurityChanged => notify_filter::SECURITY,
    }
}

/// Get current timestamp
fn get_timestamp() -> u64 {
    // Would use proper time source
    0
}

// ============================================================================
// Statistics
// ============================================================================

/// Get registry monitor statistics
pub fn reg_get_monitor_stats() -> RegMonitorStats {
    let watchers = WATCHERS.lock();
    let notifications = NOTIFICATIONS.lock();

    let watcher_count = watchers.iter().filter(|w| w.active).count() as u32;
    let pending_count = notifications.iter().filter(|n| n.valid).count() as u32;

    RegMonitorStats {
        watcher_count,
        notifications_processed: NOTIFICATIONS_PROCESSED.load(Ordering::Relaxed) as u64,
        pending_count,
        dropped_count: NOTIFICATIONS_DROPPED.load(Ordering::Relaxed) as u64,
    }
}

// ============================================================================
// Key Path Monitoring
// ============================================================================

/// Well-known registry paths to monitor
pub mod well_known_paths {
    /// Run key for current user
    pub const HKCU_RUN: &[u8] = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    /// Run key for local machine
    pub const HKLM_RUN: &[u8] = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    /// RunOnce key for current user
    pub const HKCU_RUNONCE: &[u8] = b"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    /// RunOnce key for local machine
    pub const HKLM_RUNONCE: &[u8] = b"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    /// Shell folders
    pub const SHELL_FOLDERS: &[u8] = b"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
    /// User shell folders
    pub const USER_SHELL_FOLDERS: &[u8] = b"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";
    /// File associations
    pub const FILE_EXTS: &[u8] = b"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts";
    /// Desktop settings
    pub const DESKTOP: &[u8] = b"Control Panel\\Desktop";
    /// Colors
    pub const COLORS: &[u8] = b"Control Panel\\Colors";
    /// Appearance
    pub const APPEARANCE: &[u8] = b"Control Panel\\Appearance";
}

/// Monitor common startup locations
/// Returns array of watcher IDs and count of valid entries
pub fn reg_monitor_startup_locations(hwnd: HWND, message: u32) -> ([u32; 4], usize) {
    let mut ids = [0u32; 4];
    let mut count = 0;

    if let Some(id) = reg_notify_change_key_value_ex(
        RegHive::CurrentUser,
        well_known_paths::HKCU_RUN,
        notify_filter::ALL,
        false,
        hwnd,
        message,
    ) {
        ids[count] = id;
        count += 1;
    }

    if let Some(id) = reg_notify_change_key_value_ex(
        RegHive::LocalMachine,
        well_known_paths::HKLM_RUN,
        notify_filter::ALL,
        false,
        hwnd,
        message,
    ) {
        ids[count] = id;
        count += 1;
    }

    if let Some(id) = reg_notify_change_key_value_ex(
        RegHive::CurrentUser,
        well_known_paths::HKCU_RUNONCE,
        notify_filter::ALL,
        false,
        hwnd,
        message,
    ) {
        ids[count] = id;
        count += 1;
    }

    if let Some(id) = reg_notify_change_key_value_ex(
        RegHive::LocalMachine,
        well_known_paths::HKLM_RUNONCE,
        notify_filter::ALL,
        false,
        hwnd,
        message,
    ) {
        ids[count] = id;
        count += 1;
    }

    (ids, count)
}

/// Monitor desktop settings
/// Returns array of watcher IDs and count of valid entries
pub fn reg_monitor_desktop_settings(hwnd: HWND, message: u32) -> ([u32; 3], usize) {
    let mut ids = [0u32; 3];
    let mut count = 0;

    if let Some(id) = reg_notify_change_key_value_ex(
        RegHive::CurrentUser,
        well_known_paths::DESKTOP,
        notify_filter::LAST_SET,
        false,
        hwnd,
        message,
    ) {
        ids[count] = id;
        count += 1;
    }

    if let Some(id) = reg_notify_change_key_value_ex(
        RegHive::CurrentUser,
        well_known_paths::COLORS,
        notify_filter::LAST_SET,
        false,
        hwnd,
        message,
    ) {
        ids[count] = id;
        count += 1;
    }

    if let Some(id) = reg_notify_change_key_value_ex(
        RegHive::CurrentUser,
        well_known_paths::APPEARANCE,
        notify_filter::LAST_SET,
        false,
        hwnd,
        message,
    ) {
        ids[count] = id;
        count += 1;
    }

    (ids, count)
}

// ============================================================================
// Batch Operations
// ============================================================================

/// Maximum keys to monitor at once
pub const MAX_BATCH_KEYS: usize = 16;

/// Monitor multiple keys at once
/// Returns array of watcher IDs and count of valid entries
pub fn reg_monitor_keys(
    keys: &[(RegHive, &[u8], u32)],
    hwnd: HWND,
    message: u32,
) -> ([u32; MAX_BATCH_KEYS], usize) {
    let mut ids = [0u32; MAX_BATCH_KEYS];
    let mut count = 0;

    for (hive, path, filter) in keys {
        if count >= MAX_BATCH_KEYS {
            break;
        }
        if let Some(id) = reg_notify_change_key_value_ex(
            *hive,
            path,
            *filter,
            false,
            hwnd,
            message,
        ) {
            ids[count] = id;
            count += 1;
        }
    }

    (ids, count)
}

/// Unregister multiple watchers
pub fn reg_unregister_watchers(watcher_ids: &[u32]) {
    for &id in watcher_ids {
        reg_unregister_notify(id);
    }
}
