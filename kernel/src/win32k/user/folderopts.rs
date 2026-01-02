//! Folder Options
//!
//! Kernel-mode folder options dialog following Windows NT patterns.
//! Provides view settings, file type associations, and offline files.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/shell32/fldopts.cpp` - Folder options dialog

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// Maximum file types
const MAX_FILE_TYPES: usize = 256;

/// Maximum extension length
const MAX_EXTENSION: usize = 16;

/// Maximum type name length
const MAX_TYPE_NAME: usize = 128;

/// Maximum action name length
const MAX_ACTION_NAME: usize = 64;

/// Maximum command length
const MAX_COMMAND: usize = 512;

/// Maximum actions per type
const MAX_ACTIONS: usize = 8;

/// View style options
pub mod view_style {
    /// Use Windows classic folders
    pub const CLASSIC: u32 = 0;
    /// Show common tasks in folders
    pub const COMMON_TASKS: u32 = 1;
}

/// Click behavior
pub mod click_behavior {
    /// Single-click to open
    pub const SINGLE_CLICK: u32 = 0;
    /// Double-click to open
    pub const DOUBLE_CLICK: u32 = 1;
}

/// Icon underline
pub mod icon_underline {
    /// Always underline
    pub const ALWAYS: u32 = 0;
    /// Underline on hover
    pub const HOVER: u32 = 1;
    /// Never underline
    pub const NEVER: u32 = 2;
}

/// View options flags
pub mod view_flags {
    /// Show hidden files and folders
    pub const SHOW_HIDDEN: u32 = 0x00000001;
    /// Show file extensions
    pub const SHOW_EXTENSIONS: u32 = 0x00000002;
    /// Show protected operating system files
    pub const SHOW_SYSTEM: u32 = 0x00000004;
    /// Show full path in title bar
    pub const SHOW_FULL_PATH: u32 = 0x00000008;
    /// Show full path in address bar
    pub const SHOW_FULL_PATH_ADDRESS: u32 = 0x00000010;
    /// Hide protected operating system files
    pub const HIDE_SYSTEM: u32 = 0x00000020;
    /// Show encrypted or compressed NTFS files in color
    pub const SHOW_ENCRYPTED_COLOR: u32 = 0x00000040;
    /// Show pop-up description for folder and desktop items
    pub const SHOW_INFO_TIP: u32 = 0x00000080;
    /// Display simple folder view
    pub const SIMPLE_FOLDER: u32 = 0x00000100;
    /// Show My Documents on the desktop
    pub const SHOW_MY_DOCS: u32 = 0x00000200;
    /// Show My Computer on the desktop
    pub const SHOW_MY_COMPUTER: u32 = 0x00000400;
    /// Show Network Places on the desktop
    pub const SHOW_NETWORK: u32 = 0x00000800;
    /// Show Recycle Bin on the desktop
    pub const SHOW_RECYCLE_BIN: u32 = 0x00001000;
    /// Launch folder windows in separate process
    pub const SEPARATE_PROCESS: u32 = 0x00002000;
    /// Restore previous folder windows at logon
    pub const RESTORE_FOLDERS: u32 = 0x00004000;
    /// Automatically search for network folders
    pub const AUTO_SEARCH_NETWORK: u32 = 0x00008000;
    /// Display file size in folder tips
    pub const SHOW_SIZE_TIP: u32 = 0x00010000;
    /// Remember each folder's view settings
    pub const REMEMBER_VIEWS: u32 = 0x00020000;
    /// Show preview handlers in preview pane
    pub const SHOW_PREVIEW: u32 = 0x00040000;
    /// Always show menus
    pub const ALWAYS_SHOW_MENUS: u32 = 0x00080000;
}

// ============================================================================
// Types
// ============================================================================

/// File type action
#[derive(Clone, Copy)]
pub struct FileTypeAction {
    /// Action name (e.g., "open", "edit", "print")
    pub name: [u8; MAX_ACTION_NAME],
    /// Name length
    pub name_len: u8,
    /// Display name (e.g., "&Open")
    pub display: [u8; MAX_ACTION_NAME],
    /// Display length
    pub display_len: u8,
    /// Command to execute
    pub command: [u8; MAX_COMMAND],
    /// Command length
    pub cmd_len: u16,
    /// DDE message (if applicable)
    pub dde_message: [u8; MAX_ACTION_NAME],
    /// DDE message length
    pub dde_len: u8,
    /// Is default action
    pub is_default: bool,
}

impl FileTypeAction {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_ACTION_NAME],
            name_len: 0,
            display: [0; MAX_ACTION_NAME],
            display_len: 0,
            command: [0; MAX_COMMAND],
            cmd_len: 0,
            dde_message: [0; MAX_ACTION_NAME],
            dde_len: 0,
            is_default: false,
        }
    }
}

/// File type association
#[derive(Clone, Copy)]
pub struct FileType {
    /// Extension (without dot)
    pub extension: [u8; MAX_EXTENSION],
    /// Extension length
    pub ext_len: u8,
    /// Type name
    pub type_name: [u8; MAX_TYPE_NAME],
    /// Type name length
    pub type_len: u8,
    /// Content type (MIME)
    pub content_type: [u8; 64],
    /// Content type length
    pub content_len: u8,
    /// Perceived type (text, image, audio, video, etc.)
    pub perceived_type: u8,
    /// Icon resource
    pub icon: [u8; MAX_COMMAND],
    /// Icon length
    pub icon_len: u16,
    /// Actions
    pub actions: [FileTypeAction; MAX_ACTIONS],
    /// Action count
    pub action_count: u8,
    /// Always show extension
    pub always_show_ext: bool,
    /// Browse in same window
    pub browse_same: bool,
}

impl FileType {
    pub const fn new() -> Self {
        Self {
            extension: [0; MAX_EXTENSION],
            ext_len: 0,
            type_name: [0; MAX_TYPE_NAME],
            type_len: 0,
            content_type: [0; 64],
            content_len: 0,
            perceived_type: 0,
            icon: [0; MAX_COMMAND],
            icon_len: 0,
            actions: [const { FileTypeAction::new() }; MAX_ACTIONS],
            action_count: 0,
            always_show_ext: false,
            browse_same: true,
        }
    }
}

/// Folder view settings
#[derive(Clone, Copy)]
pub struct FolderViewSettings {
    /// View style (view_style)
    pub style: u32,
    /// Click behavior (click_behavior)
    pub click: u32,
    /// Icon underline (icon_underline)
    pub underline: u32,
    /// View flags (view_flags)
    pub flags: u32,
}

impl FolderViewSettings {
    pub const fn new() -> Self {
        Self {
            style: view_style::COMMON_TASKS,
            click: click_behavior::DOUBLE_CLICK,
            underline: icon_underline::HOVER,
            flags: view_flags::SHOW_EXTENSIONS |
                   view_flags::SHOW_INFO_TIP |
                   view_flags::SHOW_MY_DOCS |
                   view_flags::SHOW_MY_COMPUTER |
                   view_flags::SHOW_NETWORK |
                   view_flags::SHOW_RECYCLE_BIN |
                   view_flags::SHOW_SIZE_TIP |
                   view_flags::REMEMBER_VIEWS,
        }
    }
}

/// Offline files settings
#[derive(Clone, Copy)]
pub struct OfflineFilesSettings {
    /// Offline files enabled
    pub enabled: bool,
    /// Synchronize at logon
    pub sync_at_logon: bool,
    /// Synchronize at logoff
    pub sync_at_logoff: bool,
    /// Remind me every X minutes
    pub reminder_interval: u32,
    /// Enable reminder balloons
    pub show_reminders: bool,
    /// Encrypt offline files
    pub encrypt: bool,
    /// Amount of disk space (percentage)
    pub disk_space_percent: u32,
}

impl OfflineFilesSettings {
    pub const fn new() -> Self {
        Self {
            enabled: true,
            sync_at_logon: true,
            sync_at_logoff: true,
            reminder_interval: 60,
            show_reminders: true,
            encrypt: false,
            disk_space_percent: 10,
        }
    }
}

/// Folder options dialog state
struct FolderOptsDialog {
    /// Parent window
    parent: HWND,
    /// Current tab
    current_tab: u32,
    /// Modified flag
    modified: bool,
}

impl FolderOptsDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            current_tab: 0,
            modified: false,
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// File types
static FILE_TYPES: SpinLock<[FileType; MAX_FILE_TYPES]> =
    SpinLock::new([const { FileType::new() }; MAX_FILE_TYPES]);

/// File type count
static TYPE_COUNT: AtomicU32 = AtomicU32::new(0);

/// View settings
static VIEW_SETTINGS: SpinLock<FolderViewSettings> =
    SpinLock::new(FolderViewSettings::new());

/// Offline files settings
static OFFLINE_SETTINGS: SpinLock<OfflineFilesSettings> =
    SpinLock::new(OfflineFilesSettings::new());

/// Dialog state
static DIALOG: SpinLock<FolderOptsDialog> = SpinLock::new(FolderOptsDialog::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize folder options
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Initialize default file types
    init_file_types();

    crate::serial_println!("[FOLDEROPTS] Folder options initialized");
}

/// Initialize default file types
fn init_file_types() {
    let mut types = FILE_TYPES.lock();
    let mut count = 0;

    let defaults: &[(&[u8], &[u8], &[u8])] = &[
        (b"txt", b"Text Document", b"text/plain"),
        (b"doc", b"Microsoft Word Document", b"application/msword"),
        (b"docx", b"Microsoft Word Document", b"application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        (b"xls", b"Microsoft Excel Spreadsheet", b"application/vnd.ms-excel"),
        (b"xlsx", b"Microsoft Excel Spreadsheet", b"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (b"ppt", b"Microsoft PowerPoint Presentation", b"application/vnd.ms-powerpoint"),
        (b"pdf", b"PDF Document", b"application/pdf"),
        (b"zip", b"Compressed (zipped) Folder", b"application/zip"),
        (b"exe", b"Application", b"application/x-msdownload"),
        (b"dll", b"Application Extension", b"application/x-msdownload"),
        (b"sys", b"System File", b"application/octet-stream"),
        (b"ini", b"Configuration Settings", b"text/plain"),
        (b"bat", b"Windows Batch File", b"application/x-msdos-program"),
        (b"cmd", b"Windows Command Script", b"application/x-msdos-program"),
        (b"vbs", b"VBScript Script File", b"text/vbscript"),
        (b"js", b"JScript Script File", b"application/javascript"),
        (b"htm", b"HTML Document", b"text/html"),
        (b"html", b"HTML Document", b"text/html"),
        (b"xml", b"XML Document", b"text/xml"),
        (b"css", b"Cascading Style Sheet", b"text/css"),
        (b"jpg", b"JPEG Image", b"image/jpeg"),
        (b"jpeg", b"JPEG Image", b"image/jpeg"),
        (b"png", b"PNG Image", b"image/png"),
        (b"gif", b"GIF Image", b"image/gif"),
        (b"bmp", b"Bitmap Image", b"image/bmp"),
        (b"ico", b"Icon", b"image/x-icon"),
        (b"tif", b"TIFF Image", b"image/tiff"),
        (b"tiff", b"TIFF Image", b"image/tiff"),
        (b"mp3", b"MP3 Audio", b"audio/mpeg"),
        (b"wav", b"WAV Audio", b"audio/wav"),
        (b"wma", b"Windows Media Audio", b"audio/x-ms-wma"),
        (b"mp4", b"MP4 Video", b"video/mp4"),
        (b"avi", b"AVI Video", b"video/avi"),
        (b"wmv", b"Windows Media Video", b"video/x-ms-wmv"),
        (b"mpeg", b"MPEG Video", b"video/mpeg"),
        (b"mpg", b"MPEG Video", b"video/mpeg"),
        (b"mov", b"QuickTime Movie", b"video/quicktime"),
        (b"lnk", b"Shortcut", b"application/x-ms-shortcut"),
        (b"url", b"Internet Shortcut", b"application/x-url"),
        (b"log", b"Log File", b"text/plain"),
        (b"reg", b"Registration Entries", b"text/plain"),
        (b"inf", b"Setup Information", b"text/plain"),
        (b"hlp", b"Help File", b"application/winhlp"),
        (b"chm", b"Compiled HTML Help", b"application/x-chm"),
        (b"msi", b"Windows Installer Package", b"application/x-msi"),
        (b"cab", b"Windows Cabinet", b"application/vnd.ms-cab-compressed"),
        (b"ttf", b"TrueType Font", b"font/ttf"),
        (b"otf", b"OpenType Font", b"font/otf"),
    ];

    for (ext, name, content) in defaults.iter() {
        if count >= MAX_FILE_TYPES {
            break;
        }

        let ft = &mut types[count];

        let elen = ext.len().min(MAX_EXTENSION);
        ft.extension[..elen].copy_from_slice(&ext[..elen]);
        ft.ext_len = elen as u8;

        let nlen = name.len().min(MAX_TYPE_NAME);
        ft.type_name[..nlen].copy_from_slice(&name[..nlen]);
        ft.type_len = nlen as u8;

        let clen = content.len().min(64);
        ft.content_type[..clen].copy_from_slice(&content[..clen]);
        ft.content_len = clen as u8;

        // Add default open action
        ft.actions[0].name[..4].copy_from_slice(b"open");
        ft.actions[0].name_len = 4;
        ft.actions[0].display[..5].copy_from_slice(b"&Open");
        ft.actions[0].display_len = 5;
        ft.actions[0].is_default = true;
        ft.action_count = 1;

        count += 1;
    }

    TYPE_COUNT.store(count as u32, Ordering::Release);
}

// ============================================================================
// View Settings
// ============================================================================

/// Get folder view settings
pub fn get_view_settings(settings: &mut FolderViewSettings) {
    *settings = *VIEW_SETTINGS.lock();
}

/// Set folder view settings
pub fn set_view_settings(settings: &FolderViewSettings) {
    *VIEW_SETTINGS.lock() = *settings;
}

/// Get a specific view flag
pub fn get_view_flag(flag: u32) -> bool {
    VIEW_SETTINGS.lock().flags & flag != 0
}

/// Set a specific view flag
pub fn set_view_flag(flag: u32, value: bool) {
    let mut settings = VIEW_SETTINGS.lock();
    if value {
        settings.flags |= flag;
    } else {
        settings.flags &= !flag;
    }
}

/// Get click behavior
pub fn get_click_behavior() -> u32 {
    VIEW_SETTINGS.lock().click
}

/// Set click behavior
pub fn set_click_behavior(behavior: u32) {
    VIEW_SETTINGS.lock().click = behavior;
}

/// Reset to default view settings
pub fn reset_view_settings() {
    *VIEW_SETTINGS.lock() = FolderViewSettings::new();
}

/// Apply view settings to all folders
pub fn apply_to_all_folders() {
    // Would update view settings for all folder types
}

// ============================================================================
// File Type Associations
// ============================================================================

/// Get number of file types
pub fn get_file_type_count() -> u32 {
    TYPE_COUNT.load(Ordering::Acquire)
}

/// Get file type by index
pub fn get_file_type(index: usize, ft: &mut FileType) -> bool {
    let types = FILE_TYPES.lock();
    let count = TYPE_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    *ft = types[index];
    true
}

/// Find file type by extension
pub fn find_file_type(extension: &[u8]) -> Option<usize> {
    let types = FILE_TYPES.lock();
    let count = TYPE_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = types[i].ext_len as usize;
        if &types[i].extension[..len] == extension {
            return Some(i);
        }
    }
    None
}

/// Get type name for extension
pub fn get_type_name(extension: &[u8], name: &mut [u8]) -> usize {
    let types = FILE_TYPES.lock();
    let count = TYPE_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = types[i].ext_len as usize;
        if &types[i].extension[..len] == extension {
            let name_len = (types[i].type_len as usize).min(name.len());
            name[..name_len].copy_from_slice(&types[i].type_name[..name_len]);
            return name_len;
        }
    }
    0
}

/// Register a new file type
pub fn register_file_type(ft: &FileType) -> bool {
    let mut types = FILE_TYPES.lock();
    let count = TYPE_COUNT.load(Ordering::Acquire) as usize;

    // Check for existing
    for i in 0..count {
        let len = types[i].ext_len as usize;
        let new_len = ft.ext_len as usize;
        if &types[i].extension[..len] == &ft.extension[..new_len] {
            // Update existing
            types[i] = *ft;
            return true;
        }
    }

    // Add new
    if count < MAX_FILE_TYPES {
        types[count] = *ft;
        TYPE_COUNT.store((count + 1) as u32, Ordering::Release);
        return true;
    }

    false
}

/// Unregister a file type
pub fn unregister_file_type(extension: &[u8]) -> bool {
    let mut types = FILE_TYPES.lock();
    let count = TYPE_COUNT.load(Ordering::Acquire) as usize;

    let mut found_index = None;
    for i in 0..count {
        let len = types[i].ext_len as usize;
        if &types[i].extension[..len] == extension {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..(count - 1) {
            types[i] = types[i + 1];
        }
        types[count - 1] = FileType::new();
        TYPE_COUNT.store((count - 1) as u32, Ordering::Release);
        return true;
    }

    false
}

/// Get default action command for a file type
pub fn get_default_action(extension: &[u8], command: &mut [u8]) -> usize {
    let types = FILE_TYPES.lock();
    let count = TYPE_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = types[i].ext_len as usize;
        if &types[i].extension[..len] == extension {
            let action_count = types[i].action_count as usize;
            for j in 0..action_count {
                if types[i].actions[j].is_default {
                    let cmd_len = (types[i].actions[j].cmd_len as usize).min(command.len());
                    command[..cmd_len].copy_from_slice(&types[i].actions[j].command[..cmd_len]);
                    return cmd_len;
                }
            }
        }
    }
    0
}

// ============================================================================
// Offline Files
// ============================================================================

/// Get offline files settings
pub fn get_offline_settings(settings: &mut OfflineFilesSettings) {
    *settings = *OFFLINE_SETTINGS.lock();
}

/// Set offline files settings
pub fn set_offline_settings(settings: &OfflineFilesSettings) {
    *OFFLINE_SETTINGS.lock() = *settings;
}

/// Check if offline files are enabled
pub fn is_offline_enabled() -> bool {
    OFFLINE_SETTINGS.lock().enabled
}

/// Enable or disable offline files
pub fn set_offline_enabled(enabled: bool) {
    OFFLINE_SETTINGS.lock().enabled = enabled;
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show folder options dialog
pub fn show_folder_options(parent: HWND, tab: u32) -> bool {
    let mut dialog = DIALOG.lock();

    dialog.parent = parent;
    dialog.current_tab = tab;
    dialog.modified = false;

    // Would show dialog with tabs:
    // - General (tasks, click, browse)
    // - View (advanced settings)
    // - File Types
    // - Offline Files

    true
}

/// Show file type dialog for editing
pub fn show_file_type_dialog(parent: HWND, extension: &[u8]) -> bool {
    let _ = (parent, extension);
    // Would show file type editing dialog
    true
}

/// Show new file type wizard
pub fn show_new_type_wizard(parent: HWND) -> bool {
    let _ = parent;
    // Would show wizard for creating new file type
    true
}
