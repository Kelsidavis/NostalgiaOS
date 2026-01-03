//! File Properties Dialog
//!
//! Provides file/folder properties dialogs following the Windows shell32
//! SHMultiFileProperties pattern.
//!
//! # References
//!
//! - Windows Server 2003 shell32 file properties
//! - Property sheet pages for files

use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum path length
pub const MAX_PATH: usize = 260;

/// WM_NOTIFY message
const WM_NOTIFY: u32 = 0x004E;

/// File attributes
pub mod file_attributes {
    /// Read-only
    pub const READONLY: u32 = 0x00000001;
    /// Hidden
    pub const HIDDEN: u32 = 0x00000002;
    /// System
    pub const SYSTEM: u32 = 0x00000004;
    /// Directory
    pub const DIRECTORY: u32 = 0x00000010;
    /// Archive
    pub const ARCHIVE: u32 = 0x00000020;
    /// Encrypted
    pub const ENCRYPTED: u32 = 0x00004000;
    /// Compressed
    pub const COMPRESSED: u32 = 0x00000800;
    /// Temporary
    pub const TEMPORARY: u32 = 0x00000100;
    /// Sparse file
    pub const SPARSE_FILE: u32 = 0x00000200;
    /// Reparse point
    pub const REPARSE_POINT: u32 = 0x00000400;
    /// Offline
    pub const OFFLINE: u32 = 0x00001000;
    /// Not content indexed
    pub const NOT_CONTENT_INDEXED: u32 = 0x00002000;
}

/// Property page IDs
pub mod prop_pages {
    /// General page
    pub const GENERAL: u32 = 0;
    /// Security page
    pub const SECURITY: u32 = 1;
    /// Summary page (for documents)
    pub const SUMMARY: u32 = 2;
    /// Sharing page
    pub const SHARING: u32 = 3;
    /// Previous versions page
    pub const PREVIOUS_VERSIONS: u32 = 4;
    /// Customize page (for folders)
    pub const CUSTOMIZE: u32 = 5;
}

// ============================================================================
// Structures
// ============================================================================

/// File info for properties dialog
#[derive(Clone, Copy)]
pub struct FileInfo {
    /// File exists
    pub exists: bool,
    /// Is directory
    pub is_directory: bool,
    /// Attributes
    pub attributes: u32,
    /// Size in bytes
    pub size: u64,
    /// Size on disk
    pub size_on_disk: u64,
    /// Creation time (FILETIME format)
    pub creation_time: u64,
    /// Last access time
    pub access_time: u64,
    /// Last write time
    pub write_time: u64,
    /// File name length
    pub name_len: u8,
    /// File name
    pub name: [u8; 256],
    /// Full path length
    pub path_len: u16,
    /// Full path
    pub path: [u8; MAX_PATH],
    /// Type description length
    pub type_len: u8,
    /// Type description
    pub type_desc: [u8; 64],
    /// Opens with program length
    pub opens_with_len: u8,
    /// Opens with program
    pub opens_with: [u8; 64],
    /// Contains count (for folders)
    pub file_count: u32,
    /// Contains folder count
    pub folder_count: u32,
}

impl FileInfo {
    pub const fn new() -> Self {
        Self {
            exists: false,
            is_directory: false,
            attributes: 0,
            size: 0,
            size_on_disk: 0,
            creation_time: 0,
            access_time: 0,
            write_time: 0,
            name_len: 0,
            name: [0; 256],
            path_len: 0,
            path: [0; MAX_PATH],
            type_len: 0,
            type_desc: [0; 64],
            opens_with_len: 0,
            opens_with: [0; 64],
            file_count: 0,
            folder_count: 0,
        }
    }

    /// Set file name
    pub fn set_name(&mut self, name: &[u8]) {
        self.name_len = name.len().min(256) as u8;
        self.name[..self.name_len as usize].copy_from_slice(&name[..self.name_len as usize]);
    }

    /// Set path
    pub fn set_path(&mut self, path: &[u8]) {
        self.path_len = path.len().min(MAX_PATH) as u16;
        self.path[..self.path_len as usize].copy_from_slice(&path[..self.path_len as usize]);
    }
}

/// Properties dialog state
#[derive(Clone, Copy)]
pub struct PropsDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Current page
    pub current_page: u32,
    /// Changes pending
    pub changes_pending: bool,
    /// File info
    pub info: FileInfo,
    /// Modified attributes
    pub new_attributes: u32,
}

impl PropsDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            current_page: 0,
            changes_pending: false,
            info: FileInfo::new(),
            new_attributes: 0,
        }
    }
}

/// Sharing info
#[derive(Debug, Clone, Copy)]
pub struct SharingInfo {
    /// Share is enabled
    pub shared: bool,
    /// Share name length
    pub share_name_len: u8,
    /// Share name
    pub share_name: [u8; 64],
    /// Comment length
    pub comment_len: u8,
    /// Comment
    pub comment: [u8; 128],
    /// Maximum users (0 = unlimited)
    pub max_users: u16,
    /// Permission flags
    pub permissions: u32,
}

impl SharingInfo {
    const fn new() -> Self {
        Self {
            shared: false,
            share_name_len: 0,
            share_name: [0; 64],
            comment_len: 0,
            comment: [0; 128],
            max_users: 0,
            permissions: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static FILEPROPS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static FILEPROPS_LOCK: SpinLock<()> = SpinLock::new(());

static CURRENT_STATE: SpinLock<PropsDialogState> = SpinLock::new(PropsDialogState::new());
static SHARING_INFO: SpinLock<SharingInfo> = SpinLock::new(SharingInfo::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize file properties dialog subsystem
pub fn init() {
    let _guard = FILEPROPS_LOCK.lock();

    if FILEPROPS_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[FILEPROPS] Initializing file properties dialog...");

    FILEPROPS_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[FILEPROPS] File properties dialog initialized");
}

// ============================================================================
// File Properties API
// ============================================================================

/// Show file properties dialog
pub fn show_file_properties(path: &[u8]) -> bool {
    if !FILEPROPS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        return false;
    }

    // Initialize file info
    let mut info = FileInfo::new();
    info.set_path(path);

    // Extract file name from path
    if let Some(pos) = path.iter().rposition(|&c| c == b'\\' || c == b'/') {
        info.set_name(&path[pos + 1..]);
    } else {
        info.set_name(path);
    }

    // Would query file system for actual info
    info.exists = true;

    state.info = info;
    state.new_attributes = info.attributes;
    state.changes_pending = false;
    state.current_page = prop_pages::GENERAL;

    // Create dialog
    let hwnd = create_props_dialog(&state.info);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    // Run dialog
    let result = run_props_dialog(hwnd);

    // Apply changes if OK was pressed
    if result {
        apply_file_changes();
    }

    // Clean up
    let mut state = CURRENT_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

/// Show multi-file properties
pub fn show_multi_file_properties(paths: &[[u8; MAX_PATH]], count: usize) -> bool {
    if !FILEPROPS_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    if count == 0 {
        return false;
    }

    if count == 1 {
        let path_end = paths[0].iter().position(|&c| c == 0).unwrap_or(MAX_PATH);
        return show_file_properties(&paths[0][..path_end]);
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        return false;
    }

    // Create combined info for multiple files
    let mut info = FileInfo::new();
    info.exists = true;

    // Set name to show count
    let mut name_buf = [0u8; 256];
    let len = format_multi_count(count, &mut name_buf);
    info.name_len = len as u8;
    info.name[..len].copy_from_slice(&name_buf[..len]);

    // Calculate total size
    info.size = 0;
    info.file_count = count as u32;

    state.info = info;
    state.current_page = prop_pages::GENERAL;

    // Create dialog
    let hwnd = create_props_dialog(&state.info);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    // Run dialog
    let result = run_props_dialog(hwnd);

    // Clean up
    let mut state = CURRENT_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

/// Close properties dialog
pub fn close_props_dialog() {
    let mut state = CURRENT_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }

        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Apply file changes
fn apply_file_changes() {
    let state = CURRENT_STATE.lock();

    if !state.changes_pending {
        return;
    }

    // Would apply attribute changes to file system
    let _ = state.new_attributes;
}

// ============================================================================
// Attribute Management
// ============================================================================

/// Set file attribute
pub fn set_attribute(attr: u32, enabled: bool) -> bool {
    let mut state = CURRENT_STATE.lock();

    if !state.active {
        return false;
    }

    if enabled {
        state.new_attributes |= attr;
    } else {
        state.new_attributes &= !attr;
    }

    state.changes_pending = state.new_attributes != state.info.attributes;
    true
}

/// Get current attributes
pub fn get_attributes() -> u32 {
    let state = CURRENT_STATE.lock();
    state.new_attributes
}

/// Check if attribute is set
pub fn has_attribute(attr: u32) -> bool {
    let state = CURRENT_STATE.lock();
    (state.new_attributes & attr) != 0
}

// ============================================================================
// Sharing
// ============================================================================

/// Get sharing info
pub fn get_sharing_info() -> SharingInfo {
    *SHARING_INFO.lock()
}

/// Set sharing enabled
pub fn set_sharing(enabled: bool, share_name: &[u8]) -> bool {
    let mut info = SHARING_INFO.lock();
    info.shared = enabled;
    let len = share_name.len().min(64);
    info.share_name_len = len as u8;
    info.share_name[..len].copy_from_slice(&share_name[..len]);
    true
}

// ============================================================================
// Formatting Helpers
// ============================================================================

/// Format file size
pub fn format_file_size(size: u64, buffer: &mut [u8]) -> usize {
    if size < 1024 {
        // Bytes
        let pos = format_number(size, buffer);
        let suffix = b" bytes";
        let copy_len = suffix.len().min(buffer.len() - pos);
        buffer[pos..pos + copy_len].copy_from_slice(&suffix[..copy_len]);
        pos + copy_len
    } else if size < 1024 * 1024 {
        // KB
        let kb = size / 1024;
        let pos = format_number(kb, buffer);
        let suffix = b" KB";
        let copy_len = suffix.len().min(buffer.len() - pos);
        buffer[pos..pos + copy_len].copy_from_slice(&suffix[..copy_len]);
        pos + copy_len
    } else if size < 1024 * 1024 * 1024 {
        // MB
        let mb = size / (1024 * 1024);
        let pos = format_number(mb, buffer);
        let suffix = b" MB";
        let copy_len = suffix.len().min(buffer.len() - pos);
        buffer[pos..pos + copy_len].copy_from_slice(&suffix[..copy_len]);
        pos + copy_len
    } else {
        // GB
        let gb = size / (1024 * 1024 * 1024);
        let pos = format_number(gb, buffer);
        let suffix = b" GB";
        let copy_len = suffix.len().min(buffer.len() - pos);
        buffer[pos..pos + copy_len].copy_from_slice(&suffix[..copy_len]);
        pos + copy_len
    }
}

/// Format number
fn format_number(mut n: u64, buffer: &mut [u8]) -> usize {
    if n == 0 {
        if !buffer.is_empty() {
            buffer[0] = b'0';
            return 1;
        }
        return 0;
    }

    let mut temp = [0u8; 20];
    let mut len = 0;

    while n > 0 && len < 20 {
        temp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }

    // Reverse into buffer
    let copy_len = len.min(buffer.len());
    for i in 0..copy_len {
        buffer[i] = temp[len - 1 - i];
    }

    copy_len
}

/// Format multi-file count
fn format_multi_count(count: usize, buffer: &mut [u8]) -> usize {
    let pos = format_number(count as u64, buffer);
    let suffix = b" items selected";
    let copy_len = suffix.len().min(buffer.len() - pos);
    buffer[pos..pos + copy_len].copy_from_slice(&suffix[..copy_len]);
    pos + copy_len
}

/// Format attributes as text
pub fn format_attributes(attrs: u32, buffer: &mut [u8]) -> usize {
    let mut pos = 0;

    let attr_names: &[(&[u8], u32)] = &[
        (b"Read-only", file_attributes::READONLY),
        (b"Hidden", file_attributes::HIDDEN),
        (b"System", file_attributes::SYSTEM),
        (b"Archive", file_attributes::ARCHIVE),
        (b"Compressed", file_attributes::COMPRESSED),
        (b"Encrypted", file_attributes::ENCRYPTED),
    ];

    let mut first = true;
    for (name, attr) in attr_names {
        if (attrs & attr) != 0 {
            if !first && pos + 2 <= buffer.len() {
                buffer[pos..pos + 2].copy_from_slice(b", ");
                pos += 2;
            }
            first = false;

            let copy_len = name.len().min(buffer.len() - pos);
            buffer[pos..pos + copy_len].copy_from_slice(&name[..copy_len]);
            pos += copy_len;
        }
    }

    pos
}

// ============================================================================
// Dialog Creation
// ============================================================================

/// Create properties dialog window
fn create_props_dialog(_info: &FileInfo) -> HWND {
    // Would create property sheet dialog
    UserHandle::NULL
}

/// Run properties dialog modal loop
fn run_props_dialog(_hwnd: HWND) -> bool {
    // Would run modal dialog loop
    true
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Properties dialog window procedure
pub fn props_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_props_command(hwnd, wparam as u32)
        }
        WM_NOTIFY => {
            handle_props_notify(hwnd, wparam)
        }
        super::message::WM_CLOSE => {
            close_props_dialog();
            0
        }
        _ => 0,
    }
}

/// Handle properties dialog commands
fn handle_props_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        1 => {
            // OK button - apply and close
            let state = CURRENT_STATE.lock();
            if state.active && state.hwnd == hwnd {
                drop(state);
                apply_file_changes();
                close_props_dialog();
            }
            0
        }
        2 => {
            // Cancel button
            close_props_dialog();
            0
        }
        3 => {
            // Apply button
            apply_file_changes();
            let mut state = CURRENT_STATE.lock();
            state.changes_pending = false;
            0
        }
        100 => {
            // Read-only checkbox
            let state = CURRENT_STATE.lock();
            let current = (state.new_attributes & file_attributes::READONLY) != 0;
            drop(state);
            set_attribute(file_attributes::READONLY, !current);
            0
        }
        101 => {
            // Hidden checkbox
            let state = CURRENT_STATE.lock();
            let current = (state.new_attributes & file_attributes::HIDDEN) != 0;
            drop(state);
            set_attribute(file_attributes::HIDDEN, !current);
            0
        }
        102 => {
            // Archive checkbox
            let state = CURRENT_STATE.lock();
            let current = (state.new_attributes & file_attributes::ARCHIVE) != 0;
            drop(state);
            set_attribute(file_attributes::ARCHIVE, !current);
            0
        }
        200 => {
            // Advanced button - show advanced attributes
            show_advanced_attributes();
            0
        }
        _ => 0,
    }
}

/// Handle properties dialog notifications
fn handle_props_notify(_hwnd: HWND, _wparam: usize) -> isize {
    // Would handle tab control page changes
    0
}

/// Show advanced attributes dialog
fn show_advanced_attributes() {
    // Would show dialog with:
    // - Index for fast searching
    // - Compress contents
    // - Encrypt contents
}

// ============================================================================
// File Type Info
// ============================================================================

/// Get file type description
pub fn get_file_type_description(extension: &[u8], buffer: &mut [u8]) -> usize {
    let desc: &[u8] = match extension {
        b".txt" => b"Text Document",
        b".doc" | b".docx" => b"Microsoft Word Document",
        b".xls" | b".xlsx" => b"Microsoft Excel Spreadsheet",
        b".ppt" | b".pptx" => b"Microsoft PowerPoint Presentation",
        b".pdf" => b"PDF Document",
        b".jpg" | b".jpeg" => b"JPEG Image",
        b".png" => b"PNG Image",
        b".gif" => b"GIF Image",
        b".bmp" => b"Bitmap Image",
        b".mp3" => b"MP3 Audio File",
        b".wav" => b"WAV Audio File",
        b".mp4" => b"MP4 Video File",
        b".avi" => b"AVI Video File",
        b".wmv" => b"Windows Media Video",
        b".zip" => b"Compressed (zipped) Folder",
        b".rar" => b"WinRAR Archive",
        b".exe" => b"Application",
        b".dll" => b"Application Extension",
        b".sys" => b"System File",
        b".ini" => b"Configuration Settings",
        b".bat" | b".cmd" => b"Windows Batch File",
        b".htm" | b".html" => b"HTML Document",
        b".xml" => b"XML Document",
        b".js" => b"JavaScript File",
        b".css" => b"Cascading Style Sheet",
        _ => b"File",
    };

    let len = desc.len().min(buffer.len());
    buffer[..len].copy_from_slice(&desc[..len]);
    len
}
