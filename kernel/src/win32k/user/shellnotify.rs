//! Shell Notification Helpers
//!
//! Implements extended shell notification APIs including file system
//! change notifications, shell change notify, and folder monitoring.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/shlobj.h` - Shell object definitions
//! - `shell/shell32/shchangenotify.c` - Change notification
//! - `shell/shell32/fstreex.c` - File system tree

use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::HWND;

// ============================================================================
// Constants
// ============================================================================

/// Maximum change notify registrations
const MAX_REGISTRATIONS: usize = 128;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Maximum pending events
const MAX_PENDING_EVENTS: usize = 256;

// ============================================================================
// Shell Change Notify Events
// ============================================================================

bitflags::bitflags! {
    /// Shell change notification events (SHCNE_*)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ShellChangeEvents: u32 {
        /// Item renamed
        const RENAMEITEM = 0x00000001;
        /// Item created
        const CREATE = 0x00000002;
        /// Item deleted
        const DELETE = 0x00000004;
        /// Directory created
        const MKDIR = 0x00000008;
        /// Directory deleted
        const RMDIR = 0x00000010;
        /// Media inserted
        const MEDIAINSERTED = 0x00000020;
        /// Media removed
        const MEDIAREMOVED = 0x00000040;
        /// Drive removed
        const DRIVEREMOVED = 0x00000080;
        /// Drive added
        const DRIVEADD = 0x00000100;
        /// Network share
        const NETSHARE = 0x00000200;
        /// Network unshare
        const NETUNSHARE = 0x00000400;
        /// Attributes changed
        const ATTRIBUTES = 0x00000800;
        /// Directory updated
        const UPDATEDIR = 0x00001000;
        /// Item updated
        const UPDATEITEM = 0x00002000;
        /// Server disconnected
        const SERVERDISCONNECT = 0x00004000;
        /// Image updated
        const UPDATEIMAGE = 0x00008000;
        /// Drive type changed
        const DRIVEADDGUI = 0x00010000;
        /// Folder renamed
        const RENAMEFOLDER = 0x00020000;
        /// Free space changed
        const FREESPACE = 0x00040000;
        /// Extended event
        const EXTENDED_EVENT = 0x04000000;
        /// Assoc changed
        const ASSOCCHANGED = 0x08000000;
        /// Disk events
        const DISKEVENTS = 0x0002381F;
        /// Global events
        const GLOBALEVENTS = 0x0C0581E0;
        /// All events
        const ALLEVENTS = 0x7FFFFFFF;
        /// Interrupt
        const INTERRUPT = 0x80000000;
    }
}

// ============================================================================
// Shell Change Notify Flags
// ============================================================================

bitflags::bitflags! {
    /// Shell change notification flags (SHCNF_*)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ShellChangeFlags: u32 {
        /// ID list
        const IDLIST = 0x0000;
        /// Path A (ANSI)
        const PATHA = 0x0001;
        /// Printer A
        const PRINTERA = 0x0002;
        /// DWORD value
        const DWORD = 0x0003;
        /// Path W (Unicode)
        const PATHW = 0x0005;
        /// Printer W
        const PRINTERW = 0x0006;
        /// Type mask
        const TYPE = 0x00FF;
        /// Flush
        const FLUSH = 0x1000;
        /// Flush no wait
        const FLUSHNOWAIT = 0x3000;
        /// Notify recursively
        const NOTIFYRECURSIVE = 0x10000;
    }
}

// ============================================================================
// Change Notify Registration
// ============================================================================

/// Change notification registration
#[derive(Debug)]
struct ChangeNotifyReg {
    in_use: bool,
    id: u32,
    hwnd: HWND,
    message: u32,
    events: ShellChangeEvents,
    path: [u8; MAX_PATH],
    recursive: bool,
    sources: ShellChangeNotifySource,
}

impl ChangeNotifyReg {
    const fn new() -> Self {
        Self {
            in_use: false,
            id: 0,
            hwnd: super::UserHandle::NULL,
            message: 0,
            events: ShellChangeEvents::empty(),
            path: [0u8; MAX_PATH],
            recursive: false,
            sources: ShellChangeNotifySource::empty(),
        }
    }
}

// Change notification sources
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ShellChangeNotifySource: u32 {
        /// Shell events
        const SHELL = 0x0001;
        /// Interrupt events
        const INTERRUPT = 0x0002;
        /// New delivery
        const NEWDELIVERY = 0x8000;
    }
}

// ============================================================================
// Pending Event
// ============================================================================

/// Pending shell change event
#[derive(Debug, Clone)]
struct PendingEvent {
    in_use: bool,
    event: ShellChangeEvents,
    path1: [u8; MAX_PATH],
    path2: [u8; MAX_PATH],
}

impl PendingEvent {
    const fn new() -> Self {
        Self {
            in_use: false,
            event: ShellChangeEvents::empty(),
            path1: [0u8; MAX_PATH],
            path2: [0u8; MAX_PATH],
        }
    }
}

// ============================================================================
// State
// ============================================================================

static NOTIFY_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_REG_ID: AtomicU32 = AtomicU32::new(1);
static REGISTRATIONS: SpinLock<[ChangeNotifyReg; MAX_REGISTRATIONS]> = SpinLock::new(
    [const { ChangeNotifyReg::new() }; MAX_REGISTRATIONS]
);
static PENDING_EVENTS: SpinLock<[PendingEvent; MAX_PENDING_EVENTS]> = SpinLock::new(
    [const { PendingEvent::new() }; MAX_PENDING_EVENTS]
);
static SUSPENDED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize shell notification subsystem
pub fn init() {
    if NOTIFY_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[SHELLNOTIFY] Initializing shell notifications...");
    crate::serial_println!("[SHELLNOTIFY] Shell notifications initialized");
}

// ============================================================================
// Registration Functions
// ============================================================================

/// Register for shell change notifications
pub fn sh_change_notify_register(
    hwnd: HWND,
    sources: ShellChangeNotifySource,
    events: ShellChangeEvents,
    message: u32,
    path: &[u8],
    recursive: bool,
) -> Option<u32> {
    let mut regs = REGISTRATIONS.lock();

    // Find free slot
    let slot_idx = regs.iter().position(|r| !r.in_use);
    let idx = match slot_idx {
        Some(i) => i,
        None => return None,
    };

    let id = NEXT_REG_ID.fetch_add(1, Ordering::SeqCst);

    let reg = &mut regs[idx];
    reg.in_use = true;
    reg.id = id;
    reg.hwnd = hwnd;
    reg.message = message;
    reg.events = events;
    reg.recursive = recursive;
    reg.sources = sources;

    let path_len = str_len(path).min(MAX_PATH - 1);
    reg.path[..path_len].copy_from_slice(&path[..path_len]);
    reg.path[path_len] = 0;

    Some(id)
}

/// Deregister shell change notifications
pub fn sh_change_notify_deregister(id: u32) -> bool {
    let mut regs = REGISTRATIONS.lock();

    for reg in regs.iter_mut() {
        if reg.in_use && reg.id == id {
            reg.in_use = false;
            return true;
        }
    }

    false
}

// ============================================================================
// Notification Functions
// ============================================================================

/// Notify shell of a change
pub fn sh_change_notify(
    event: ShellChangeEvents,
    flags: ShellChangeFlags,
    item1: Option<&[u8]>,
    item2: Option<&[u8]>,
) {
    let _ = flags;

    if SUSPENDED.load(Ordering::Relaxed) {
        // Queue the event
        queue_event(event, item1, item2);
        return;
    }

    // Find matching registrations and notify
    let regs = REGISTRATIONS.lock();

    for reg in regs.iter() {
        if !reg.in_use {
            continue;
        }

        if !reg.events.intersects(event) {
            continue;
        }

        // Check path match if applicable
        if let Some(path) = item1 {
            if !path_matches(&reg.path, path, reg.recursive) {
                continue;
            }
        }

        // Would post message to window
        // post_message(reg.hwnd, reg.message, ...)
    }
}

/// Queue an event for later delivery
fn queue_event(event: ShellChangeEvents, item1: Option<&[u8]>, item2: Option<&[u8]>) {
    let mut events = PENDING_EVENTS.lock();

    let slot_idx = events.iter().position(|e| !e.in_use);
    if let Some(idx) = slot_idx {
        let evt = &mut events[idx];
        evt.in_use = true;
        evt.event = event;

        if let Some(path) = item1 {
            let len = str_len(path).min(MAX_PATH - 1);
            evt.path1[..len].copy_from_slice(&path[..len]);
            evt.path1[len] = 0;
        }

        if let Some(path) = item2 {
            let len = str_len(path).min(MAX_PATH - 1);
            evt.path2[..len].copy_from_slice(&path[..len]);
            evt.path2[len] = 0;
        }
    }
}

/// Suspend shell change notifications
pub fn sh_change_notify_suspend_resume(suspend: bool) {
    SUSPENDED.store(suspend, Ordering::SeqCst);

    if !suspend {
        // Flush pending events
        flush_pending_events();
    }
}

/// Flush pending events
fn flush_pending_events() {
    let mut events = PENDING_EVENTS.lock();

    for evt in events.iter_mut() {
        if evt.in_use {
            // Would deliver the event
            evt.in_use = false;
        }
    }
}

// ============================================================================
// File System Notifications
// ============================================================================

// File notify change flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct FileNotifyChange: u32 {
        const FILE_NAME = 0x00000001;
        const DIR_NAME = 0x00000002;
        const ATTRIBUTES = 0x00000004;
        const SIZE = 0x00000008;
        const LAST_WRITE = 0x00000010;
        const LAST_ACCESS = 0x00000020;
        const CREATION = 0x00000040;
        const SECURITY = 0x00000100;
    }
}

/// File notify action
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileNotifyAction {
    Added = 1,
    Removed = 2,
    Modified = 3,
    RenamedOldName = 4,
    RenamedNewName = 5,
}

/// File notification entry
#[derive(Debug)]
struct FileNotifyWatch {
    in_use: bool,
    id: u32,
    path: [u8; MAX_PATH],
    filter: FileNotifyChange,
    subtree: bool,
    callback: Option<fn(action: FileNotifyAction, path: &[u8])>,
}

impl FileNotifyWatch {
    const fn new() -> Self {
        Self {
            in_use: false,
            id: 0,
            path: [0u8; MAX_PATH],
            filter: FileNotifyChange::empty(),
            subtree: false,
            callback: None,
        }
    }
}

const MAX_FILE_WATCHES: usize = 64;
static FILE_WATCHES: SpinLock<[FileNotifyWatch; MAX_FILE_WATCHES]> = SpinLock::new(
    [const { FileNotifyWatch::new() }; MAX_FILE_WATCHES]
);
static NEXT_WATCH_ID: AtomicU32 = AtomicU32::new(1);

/// Find first change notification
pub fn find_first_change_notification(
    path: &[u8],
    watch_subtree: bool,
    filter: FileNotifyChange,
) -> Option<u32> {
    let mut watches = FILE_WATCHES.lock();

    let slot_idx = watches.iter().position(|w| !w.in_use);
    let idx = match slot_idx {
        Some(i) => i,
        None => return None,
    };

    let id = NEXT_WATCH_ID.fetch_add(1, Ordering::SeqCst);

    let watch = &mut watches[idx];
    watch.in_use = true;
    watch.id = id;
    watch.filter = filter;
    watch.subtree = watch_subtree;

    let path_len = str_len(path).min(MAX_PATH - 1);
    watch.path[..path_len].copy_from_slice(&path[..path_len]);
    watch.path[path_len] = 0;

    Some(id)
}

/// Find next change notification
pub fn find_next_change_notification(handle: u32) -> bool {
    let watches = FILE_WATCHES.lock();

    watches.iter().any(|w| w.in_use && w.id == handle)
}

/// Find close change notification
pub fn find_close_change_notification(handle: u32) -> bool {
    let mut watches = FILE_WATCHES.lock();

    for watch in watches.iter_mut() {
        if watch.in_use && watch.id == handle {
            watch.in_use = false;
            return true;
        }
    }

    false
}

/// Read directory changes (async)
pub fn read_directory_changes(
    handle: u32,
    buffer: &mut [u8],
    watch_subtree: bool,
    filter: FileNotifyChange,
) -> Option<usize> {
    let _ = (handle, watch_subtree, filter);

    // Would return file change information
    if !buffer.is_empty() {
        buffer[0] = 0;
    }

    Some(0)
}

// ============================================================================
// Icon Overlay Notifications
// ============================================================================

/// Icon overlay identifier
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IconOverlay {
    #[default]
    None = 0,
    /// Shared folder overlay
    Share = 1,
    /// Shortcut overlay
    Link = 2,
    /// Slow file overlay
    SlowFile = 3,
    /// Offline overlay
    Offline = 4,
}

/// Notify icon overlay changed
pub fn sh_notify_icon_overlay_changed(path: &[u8], overlay: IconOverlay) {
    let _ = (path, overlay);

    // Would update icon overlays in shell
    sh_change_notify(
        ShellChangeEvents::UPDATEITEM,
        ShellChangeFlags::PATHA,
        Some(path),
        None,
    );
}

// ============================================================================
// Shell Update Functions
// ============================================================================

/// Update an item in the shell
pub fn sh_update_item(path: &[u8]) {
    sh_change_notify(
        ShellChangeEvents::UPDATEITEM,
        ShellChangeFlags::PATHA,
        Some(path),
        None,
    );
}

/// Update a directory in the shell
pub fn sh_update_directory(path: &[u8]) {
    sh_change_notify(
        ShellChangeEvents::UPDATEDIR,
        ShellChangeFlags::PATHA,
        Some(path),
        None,
    );
}

/// Notify item created
pub fn sh_notify_create(path: &[u8], is_directory: bool) {
    let event = if is_directory {
        ShellChangeEvents::MKDIR
    } else {
        ShellChangeEvents::CREATE
    };

    sh_change_notify(event, ShellChangeFlags::PATHA, Some(path), None);
}

/// Notify item deleted
pub fn sh_notify_delete(path: &[u8], is_directory: bool) {
    let event = if is_directory {
        ShellChangeEvents::RMDIR
    } else {
        ShellChangeEvents::DELETE
    };

    sh_change_notify(event, ShellChangeFlags::PATHA, Some(path), None);
}

/// Notify item renamed
pub fn sh_notify_rename(old_path: &[u8], new_path: &[u8], is_directory: bool) {
    let event = if is_directory {
        ShellChangeEvents::RENAMEFOLDER
    } else {
        ShellChangeEvents::RENAMEITEM
    };

    sh_change_notify(event, ShellChangeFlags::PATHA, Some(old_path), Some(new_path));
}

/// Notify attributes changed
pub fn sh_notify_attributes(path: &[u8]) {
    sh_change_notify(
        ShellChangeEvents::ATTRIBUTES,
        ShellChangeFlags::PATHA,
        Some(path),
        None,
    );
}

/// Notify drive added
pub fn sh_notify_drive_add(drive_letter: u8) {
    let mut path = [0u8; 4];
    path[0] = drive_letter;
    path[1] = b':';
    path[2] = b'\\';

    sh_change_notify(
        ShellChangeEvents::DRIVEADD,
        ShellChangeFlags::PATHA,
        Some(&path),
        None,
    );
}

/// Notify drive removed
pub fn sh_notify_drive_remove(drive_letter: u8) {
    let mut path = [0u8; 4];
    path[0] = drive_letter;
    path[1] = b':';
    path[2] = b'\\';

    sh_change_notify(
        ShellChangeEvents::DRIVEREMOVED,
        ShellChangeFlags::PATHA,
        Some(&path),
        None,
    );
}

/// Notify media inserted
pub fn sh_notify_media_insert(drive_letter: u8) {
    let mut path = [0u8; 4];
    path[0] = drive_letter;
    path[1] = b':';
    path[2] = b'\\';

    sh_change_notify(
        ShellChangeEvents::MEDIAINSERTED,
        ShellChangeFlags::PATHA,
        Some(&path),
        None,
    );
}

/// Notify media removed
pub fn sh_notify_media_remove(drive_letter: u8) {
    let mut path = [0u8; 4];
    path[0] = drive_letter;
    path[1] = b':';
    path[2] = b'\\';

    sh_change_notify(
        ShellChangeEvents::MEDIAREMOVED,
        ShellChangeFlags::PATHA,
        Some(&path),
        None,
    );
}

/// Notify association changed
pub fn sh_notify_assoc_changed() {
    sh_change_notify(
        ShellChangeEvents::ASSOCCHANGED,
        ShellChangeFlags::IDLIST,
        None,
        None,
    );
}

/// Notify free space changed
pub fn sh_notify_free_space(drive_letter: u8) {
    let mut path = [0u8; 4];
    path[0] = drive_letter;
    path[1] = b':';
    path[2] = b'\\';

    sh_change_notify(
        ShellChangeEvents::FREESPACE,
        ShellChangeFlags::PATHA,
        Some(&path),
        None,
    );
}

// ============================================================================
// Batch Notification
// ============================================================================

/// Begin batch notification
pub fn sh_change_notify_begin_batch() {
    SUSPENDED.store(true, Ordering::SeqCst);
}

/// End batch notification
pub fn sh_change_notify_end_batch() {
    SUSPENDED.store(false, Ordering::SeqCst);
    flush_pending_events();
}

// ============================================================================
// Helper Functions
// ============================================================================

fn str_len(s: &[u8]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

fn path_matches(registered: &[u8], changed: &[u8], recursive: bool) -> bool {
    let reg_len = str_len(registered);
    let changed_len = str_len(changed);

    if reg_len == 0 {
        return true; // Watch all
    }

    if changed_len < reg_len {
        return false;
    }

    // Check prefix match (case insensitive)
    for i in 0..reg_len {
        if registered[i].to_ascii_uppercase() != changed[i].to_ascii_uppercase() {
            return false;
        }
    }

    if changed_len == reg_len {
        return true; // Exact match
    }

    if recursive {
        // Check if it's a subdirectory
        changed[reg_len] == b'\\' || changed[reg_len] == b'/'
    } else {
        // Non-recursive: only match if it's directly in this directory
        let remainder = &changed[reg_len..changed_len];
        if remainder[0] != b'\\' && remainder[0] != b'/' {
            return false;
        }

        // Check no more separators
        !remainder[1..].iter().any(|&c| c == b'\\' || c == b'/')
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Shell notification statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ShellNotifyStats {
    pub initialized: bool,
    pub registration_count: u32,
    pub pending_event_count: u32,
    pub file_watch_count: u32,
    pub suspended: bool,
}

/// Get shell notification statistics
pub fn get_stats() -> ShellNotifyStats {
    let regs = REGISTRATIONS.lock();
    let events = PENDING_EVENTS.lock();
    let watches = FILE_WATCHES.lock();

    ShellNotifyStats {
        initialized: NOTIFY_INITIALIZED.load(Ordering::Relaxed),
        registration_count: regs.iter().filter(|r| r.in_use).count() as u32,
        pending_event_count: events.iter().filter(|e| e.in_use).count() as u32,
        file_watch_count: watches.iter().filter(|w| w.in_use).count() as u32,
        suspended: SUSPENDED.load(Ordering::Relaxed),
    }
}
