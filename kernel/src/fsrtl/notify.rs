//! Directory Change Notification Support
//!
//! Provides directory change notifications for file systems.
//! Applications can watch directories for changes and receive
//! notifications when files are created, modified, or deleted.
//!
//! This implementation is NT 5.2 (Windows Server 2003) compatible.

use core::ptr;
use crate::ex::fast_mutex::FastMutex;

/// Maximum notifications to buffer
const MAX_BUFFERED_NOTIFICATIONS: usize = 64;

/// File action codes for notifications
pub mod file_action {
    pub const FILE_ACTION_ADDED: u32 = 0x00000001;
    pub const FILE_ACTION_REMOVED: u32 = 0x00000002;
    pub const FILE_ACTION_MODIFIED: u32 = 0x00000003;
    pub const FILE_ACTION_RENAMED_OLD_NAME: u32 = 0x00000004;
    pub const FILE_ACTION_RENAMED_NEW_NAME: u32 = 0x00000005;
}

/// Notification filter flags
pub mod notify_filter {
    pub const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x00000001;
    pub const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x00000002;
    pub const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x00000004;
    pub const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x00000008;
    pub const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x00000010;
    pub const FILE_NOTIFY_CHANGE_LAST_ACCESS: u32 = 0x00000020;
    pub const FILE_NOTIFY_CHANGE_CREATION: u32 = 0x00000040;
    pub const FILE_NOTIFY_CHANGE_EA: u32 = 0x00000080;
    pub const FILE_NOTIFY_CHANGE_SECURITY: u32 = 0x00000100;
    pub const FILE_NOTIFY_CHANGE_STREAM_NAME: u32 = 0x00000200;
    pub const FILE_NOTIFY_CHANGE_STREAM_SIZE: u32 = 0x00000400;
    pub const FILE_NOTIFY_CHANGE_STREAM_WRITE: u32 = 0x00000800;
}

/// A single notification entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NotifyEntry {
    /// File action (added, removed, modified, etc.)
    pub action: u32,
    /// Notification filter that triggered this
    pub filter: u32,
    /// Name of the affected file/directory
    pub name: [u8; 256],
    /// Length of the name
    pub name_length: u16,
}

impl NotifyEntry {
    pub const fn new() -> Self {
        Self {
            action: 0,
            filter: 0,
            name: [0; 256],
            name_length: 0,
        }
    }
}

impl Default for NotifyEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Notification synchronization object
#[repr(C)]
pub struct NotifySync {
    /// Fast mutex for synchronization
    pub fast_mutex: FastMutex,
    /// Owning thread for recursive acquisition
    pub owning_thread: usize,
    /// Recursion count
    pub owner_count: u32,
}

impl NotifySync {
    pub const fn new() -> Self {
        Self {
            fast_mutex: FastMutex::new(),
            owning_thread: 0,
            owner_count: 0,
        }
    }
}

impl Default for NotifySync {
    fn default() -> Self {
        Self::new()
    }
}

/// Directory change notification watch
#[repr(C)]
pub struct NotifyChange {
    /// Synchronization object
    pub notify_sync: *mut NotifySync,
    /// File system context (FCB)
    pub fs_context: usize,
    /// Stream ID
    pub stream_id: usize,
    /// Filter mask for this watch
    pub completion_filter: u32,
    /// Watch subtree flag
    pub watch_subtree: bool,
    /// Full directory path being watched
    pub full_directory_name: [u8; 512],
    /// Length of directory name
    pub directory_name_length: u16,
    /// Buffered notifications
    pub notifications: [NotifyEntry; MAX_BUFFERED_NOTIFICATIONS],
    /// Number of buffered notifications
    pub notification_count: u32,
    /// Next read index
    pub read_index: u32,
    /// Next write index
    pub write_index: u32,
    /// IRP waiting for notification
    pub pending_irp: usize,
}

impl NotifyChange {
    pub const fn new() -> Self {
        const EMPTY_ENTRY: NotifyEntry = NotifyEntry::new();
        Self {
            notify_sync: ptr::null_mut(),
            fs_context: 0,
            stream_id: 0,
            completion_filter: 0,
            watch_subtree: false,
            full_directory_name: [0; 512],
            directory_name_length: 0,
            notifications: [EMPTY_ENTRY; MAX_BUFFERED_NOTIFICATIONS],
            notification_count: 0,
            read_index: 0,
            write_index: 0,
            pending_irp: 0,
        }
    }
}

impl Default for NotifyChange {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Initialize a notification sync object
pub fn fsrtl_notify_initialize_sync(sync: &mut NotifySync) {
    sync.fast_mutex.init();
    sync.owning_thread = 0;
    sync.owner_count = 0;
}

/// Uninitialize a notification sync object
pub fn fsrtl_notify_uninitialize_sync(sync: &mut NotifySync) {
    sync.owning_thread = 0;
    sync.owner_count = 0;
}

/// Acquire the notify sync (supports recursion)
unsafe fn acquire_notify_sync(sync: *mut NotifySync) {
    let current_thread = crate::ke::prcb::get_current_thread() as usize;

    if (*sync).owning_thread == current_thread {
        (*sync).owner_count += 1;
        return;
    }

    (*sync).fast_mutex.acquire();
    (*sync).owning_thread = current_thread;
    (*sync).owner_count = 1;
}

/// Release the notify sync
unsafe fn release_notify_sync(sync: *mut NotifySync) {
    (*sync).owner_count -= 1;
    if (*sync).owner_count == 0 {
        (*sync).owning_thread = 0;
        (*sync).fast_mutex.release();
    }
}

/// Register a directory change notification watch
///
/// # Arguments
/// * `notify_sync` - Synchronization object
/// * `notify_list` - List head for watches
/// * `notify` - The watch to register
/// * `full_directory_name` - Path of directory to watch
/// * `watch_subtree` - Whether to watch subdirectories
/// * `completion_filter` - Types of changes to watch for
pub fn fsrtl_notify_change_directory(
    notify_sync: *mut NotifySync,
    notify: &mut NotifyChange,
    full_directory_name: &str,
    watch_subtree: bool,
    completion_filter: u32,
    fs_context: usize,
) {
    notify.notify_sync = notify_sync;
    notify.fs_context = fs_context;
    notify.completion_filter = completion_filter;
    notify.watch_subtree = watch_subtree;
    notify.notification_count = 0;
    notify.read_index = 0;
    notify.write_index = 0;

    // Copy directory name
    let name_bytes = full_directory_name.as_bytes();
    let copy_len = name_bytes.len().min(notify.full_directory_name.len() - 1);
    notify.full_directory_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    notify.directory_name_length = copy_len as u16;
}

/// Report a file system change
///
/// # Arguments
/// * `notify_sync` - Synchronization object
/// * `notify_list` - List of active watches
/// * `full_target_name` - Full path of affected item
/// * `filter_match` - Filter flags that match this change
/// * `action` - Type of change (added, removed, etc.)
pub fn fsrtl_notify_full_report_change(
    notify: &mut NotifyChange,
    full_target_name: &str,
    filter_match: u32,
    action: u32,
) {
    // Check if this notification matches the watch filter
    if (notify.completion_filter & filter_match) == 0 {
        return;
    }

    // Check if the changed item is under the watched directory
    let target = full_target_name.as_bytes();
    let watched = &notify.full_directory_name[..notify.directory_name_length as usize];

    if !target.starts_with(watched) {
        return;
    }

    // If not watching subtree, check that it's a direct child
    if !notify.watch_subtree {
        let remaining = &target[watched.len()..];
        // Skip leading separator
        let remaining = if remaining.first() == Some(&b'\\') {
            &remaining[1..]
        } else {
            remaining
        };
        // Check for another separator (would indicate a subdirectory)
        if remaining.iter().any(|&b| b == b'\\') {
            return;
        }
    }

    // Add notification to buffer
    if notify.notification_count < MAX_BUFFERED_NOTIFICATIONS as u32 {
        let idx = notify.write_index as usize;
        let entry = &mut notify.notifications[idx];

        entry.action = action;
        entry.filter = filter_match;

        // Extract relative name
        let relative_name = &target[watched.len()..];
        let relative_name = if relative_name.first() == Some(&b'\\') {
            &relative_name[1..]
        } else {
            relative_name
        };

        let copy_len = relative_name.len().min(entry.name.len() - 1);
        entry.name[..copy_len].copy_from_slice(&relative_name[..copy_len]);
        entry.name_length = copy_len as u16;

        notify.write_index = ((notify.write_index + 1) as usize % MAX_BUFFERED_NOTIFICATIONS) as u32;
        notify.notification_count += 1;

        // TODO: Complete pending IRP if one is waiting
    }
}

/// Clean up notifications when a file object is closed
pub fn fsrtl_notify_cleanup(notify: &mut NotifyChange) {
    // Clear the watch
    notify.completion_filter = 0;
    notify.notification_count = 0;
    notify.pending_irp = 0;
}

/// Get the next notification
pub fn fsrtl_get_next_notification(notify: &mut NotifyChange) -> Option<NotifyEntry> {
    if notify.notification_count == 0 {
        return None;
    }

    let idx = notify.read_index as usize;
    let entry = notify.notifications[idx];

    notify.read_index = ((notify.read_index + 1) as usize % MAX_BUFFERED_NOTIFICATIONS) as u32;
    notify.notification_count -= 1;

    Some(entry)
}
