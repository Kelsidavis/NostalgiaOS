//! File Dialog Support
//!
//! Provides Open/Save file dialogs following the Windows comdlg32
//! GetOpenFileName/GetSaveFileName patterns.
//!
//! # References
//!
//! - Windows Server 2003 comdlg32 file dialogs
//! - OPENFILENAME structure and related APIs

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum path length
pub const MAX_PATH: usize = 260;

/// Maximum filter length
pub const MAX_FILTER: usize = 512;

/// Maximum title length
pub const MAX_TITLE: usize = 128;

/// Maximum file entries for multi-select
pub const MAX_FILES: usize = 32;

/// Open file dialog flags (OFN_*)
pub mod ofn_flags {
    /// Allow read-only
    pub const READONLY: u32 = 0x00000001;
    /// Overwrite prompt
    pub const OVERWRITEPROMPT: u32 = 0x00000002;
    /// Hide read-only checkbox
    pub const HIDEREADONLY: u32 = 0x00000004;
    /// No change directory
    pub const NOCHANGEDIR: u32 = 0x00000008;
    /// Show help button
    pub const SHOWHELP: u32 = 0x00000010;
    /// Enable hook
    pub const ENABLEHOOK: u32 = 0x00000020;
    /// Enable template
    pub const ENABLETEMPLATE: u32 = 0x00000040;
    /// Enable template handle
    pub const ENABLETEMPLATEHANDLE: u32 = 0x00000080;
    /// No validate
    pub const NOVALIDATE: u32 = 0x00000100;
    /// Allow multi select
    pub const ALLOWMULTISELECT: u32 = 0x00000200;
    /// Extension different
    pub const EXTENSIONDIFFERENT: u32 = 0x00000400;
    /// Path must exist
    pub const PATHMUSTEXIST: u32 = 0x00000800;
    /// File must exist
    pub const FILEMUSTEXIST: u32 = 0x00001000;
    /// Create prompt
    pub const CREATEPROMPT: u32 = 0x00002000;
    /// Share aware
    pub const SHAREAWARE: u32 = 0x00004000;
    /// No read only return
    pub const NOREADONLYRETURN: u32 = 0x00008000;
    /// No test file create
    pub const NOTESTFILECREATE: u32 = 0x00010000;
    /// No network button
    pub const NONETWORKBUTTON: u32 = 0x00020000;
    /// No long names
    pub const NOLONGNAMES: u32 = 0x00040000;
    /// Explorer style
    pub const EXPLORER: u32 = 0x00080000;
    /// No dereference links
    pub const NODEREFERENCELINKS: u32 = 0x00100000;
    /// Long names
    pub const LONGNAMES: u32 = 0x00200000;
    /// Enable include notify
    pub const ENABLEINCLUDENOTIFY: u32 = 0x00400000;
    /// Enable sizing
    pub const ENABLESIZING: u32 = 0x00800000;
    /// Don't add to recent
    pub const DONTADDTORECENT: u32 = 0x02000000;
    /// Force show hidden
    pub const FORCESHOWHIDDEN: u32 = 0x10000000;
}

/// File dialog type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileDialogType {
    /// Open file dialog
    Open = 0,
    /// Save file dialog
    Save = 1,
    /// Select folder dialog
    SelectFolder = 2,
}

/// File dialog result
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileDialogResult {
    /// User cancelled
    Cancelled = 0,
    /// File(s) selected
    Ok = 1,
    /// Error occurred
    Error = 2,
}

// ============================================================================
// Structures
// ============================================================================

/// File filter entry
#[derive(Debug, Clone, Copy)]
pub struct FileFilter {
    /// Filter is valid
    pub valid: bool,
    /// Display name length
    pub name_len: u16,
    /// Display name (e.g., "Text Files")
    pub name: [u8; 64],
    /// Pattern length
    pub pattern_len: u16,
    /// Pattern (e.g., "*.txt")
    pub pattern: [u8; 64],
}

impl FileFilter {
    pub const fn new() -> Self {
        Self {
            valid: false,
            name_len: 0,
            name: [0; 64],
            pattern_len: 0,
            pattern: [0; 64],
        }
    }

    /// Create a filter from name and pattern
    pub fn from_parts(name: &[u8], pattern: &[u8]) -> Self {
        let mut filter = Self::new();
        filter.valid = true;
        filter.name_len = name.len().min(64) as u16;
        filter.name[..filter.name_len as usize].copy_from_slice(&name[..filter.name_len as usize]);
        filter.pattern_len = pattern.len().min(64) as u16;
        filter.pattern[..filter.pattern_len as usize].copy_from_slice(&pattern[..filter.pattern_len as usize]);
        filter
    }
}

/// Open/Save file name structure (OPENFILENAME equivalent)
#[derive(Debug, Clone)]
pub struct OpenFileName {
    /// Structure size
    pub struct_size: u32,
    /// Owner window
    pub hwnd_owner: HWND,
    /// Instance handle
    pub instance: u32,
    /// Filter list
    pub filters: [FileFilter; 16],
    /// Number of filters
    pub filter_count: u8,
    /// Selected filter index
    pub filter_index: u8,
    /// Initial directory length
    pub initial_dir_len: u16,
    /// Initial directory
    pub initial_dir: [u8; MAX_PATH],
    /// Initial file name length
    pub initial_file_len: u16,
    /// Initial file name
    pub initial_file: [u8; MAX_PATH],
    /// File name buffer length
    pub file_len: u16,
    /// Selected file name(s)
    pub file: [u8; MAX_PATH],
    /// File title length
    pub file_title_len: u16,
    /// File title (name without path)
    pub file_title: [u8; MAX_PATH],
    /// Default extension length
    pub def_ext_len: u8,
    /// Default extension (e.g., "txt")
    pub def_ext: [u8; 16],
    /// Dialog title length
    pub title_len: u8,
    /// Dialog title
    pub title: [u8; MAX_TITLE],
    /// Flags
    pub flags: u32,
    /// File offset in path
    pub file_offset: u16,
    /// Extension offset in path
    pub file_extension: u16,
    /// Custom data
    pub cust_data: usize,
    /// Hook function
    pub hook_fn: usize,
    /// Template name
    pub template_name: u32,
}

impl OpenFileName {
    pub const fn new() -> Self {
        Self {
            struct_size: 0,
            hwnd_owner: UserHandle::NULL,
            instance: 0,
            filters: [const { FileFilter::new() }; 16],
            filter_count: 0,
            filter_index: 0,
            initial_dir_len: 0,
            initial_dir: [0; MAX_PATH],
            initial_file_len: 0,
            initial_file: [0; MAX_PATH],
            file_len: 0,
            file: [0; MAX_PATH],
            file_title_len: 0,
            file_title: [0; MAX_PATH],
            def_ext_len: 0,
            def_ext: [0; 16],
            title_len: 0,
            title: [0; MAX_TITLE],
            flags: 0,
            file_offset: 0,
            file_extension: 0,
            cust_data: 0,
            hook_fn: 0,
            template_name: 0,
        }
    }
}

/// Multi-select file list
#[derive(Debug, Clone)]
pub struct FileList {
    /// Number of files
    pub count: usize,
    /// Directory path length
    pub dir_len: u16,
    /// Directory path
    pub directory: [u8; MAX_PATH],
    /// File entry lengths
    pub file_lens: [u16; MAX_FILES],
    /// File names (without path)
    pub files: [[u8; MAX_PATH]; MAX_FILES],
}

impl FileList {
    pub const fn new() -> Self {
        Self {
            count: 0,
            dir_len: 0,
            directory: [0; MAX_PATH],
            file_lens: [0; MAX_FILES],
            files: [[0; MAX_PATH]; MAX_FILES],
        }
    }
}

/// File dialog state
#[derive(Debug, Clone, Copy)]
pub struct FileDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Dialog type
    pub dialog_type: FileDialogType,
    /// Current directory hash
    pub current_dir_hash: u64,
    /// Selected filter index
    pub filter_index: u8,
    /// Show hidden files
    pub show_hidden: bool,
    /// View mode (0=list, 1=details, 2=icons, 3=thumbnails)
    pub view_mode: u8,
}

impl FileDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            dialog_type: FileDialogType::Open,
            current_dir_hash: 0,
            filter_index: 0,
            show_hidden: false,
            view_mode: 1, // Details view default
        }
    }
}

// ============================================================================
// State
// ============================================================================

static FILEDLG_INITIALIZED: AtomicBool = AtomicBool::new(false);
static FILEDLG_LOCK: SpinLock<()> = SpinLock::new(());
static DIALOG_COUNT: AtomicU32 = AtomicU32::new(0);

static CURRENT_STATE: SpinLock<FileDialogState> = SpinLock::new(FileDialogState::new());

// Recent directories (MRU)
static RECENT_DIRS: SpinLock<[[u8; MAX_PATH]; 16]> = SpinLock::new([[0; MAX_PATH]; 16]);
static RECENT_DIR_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize file dialog subsystem
pub fn init() {
    let _guard = FILEDLG_LOCK.lock();

    if FILEDLG_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[FILEDLG] Initializing file dialogs...");

    FILEDLG_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[FILEDLG] File dialogs initialized");
}

// ============================================================================
// Open File Dialog
// ============================================================================

/// Show open file dialog
pub fn get_open_file_name(ofn: &mut OpenFileName) -> bool {
    if !FILEDLG_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        return false;
    }

    // Create dialog window
    let hwnd = create_file_dialog(FileDialogType::Open, ofn);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;
    state.dialog_type = FileDialogType::Open;
    state.filter_index = ofn.filter_index;
    state.show_hidden = (ofn.flags & ofn_flags::FORCESHOWHIDDEN) != 0;

    drop(state);

    // Run dialog (would block in modal loop)
    let result = run_file_dialog(hwnd, ofn);

    // Clean up
    let mut state = CURRENT_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

/// Show open file dialog with multi-select
pub fn get_open_file_names(ofn: &mut OpenFileName) -> Option<FileList> {
    ofn.flags |= ofn_flags::ALLOWMULTISELECT | ofn_flags::EXPLORER;

    if !get_open_file_name(ofn) {
        return None;
    }

    // Parse multi-select result
    Some(parse_multiselect_result(&ofn.file, ofn.file_len as usize))
}

// ============================================================================
// Save File Dialog
// ============================================================================

/// Show save file dialog
pub fn get_save_file_name(ofn: &mut OpenFileName) -> bool {
    if !FILEDLG_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    // Set save-specific flags
    ofn.flags |= ofn_flags::OVERWRITEPROMPT;

    let mut state = CURRENT_STATE.lock();

    if state.active {
        return false;
    }

    let hwnd = create_file_dialog(FileDialogType::Save, ofn);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;
    state.dialog_type = FileDialogType::Save;
    state.filter_index = ofn.filter_index;

    drop(state);

    let result = run_file_dialog(hwnd, ofn);

    let mut state = CURRENT_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

// ============================================================================
// Folder Browser Dialog
// ============================================================================

/// Browse info structure for folder selection
#[derive(Debug, Clone, Copy)]
pub struct BrowseInfo {
    /// Owner window
    pub hwnd_owner: HWND,
    /// Root folder (shell item)
    pub root: u32,
    /// Display name buffer
    pub display_name: [u8; MAX_PATH],
    /// Display name length
    pub display_name_len: u16,
    /// Title length
    pub title_len: u8,
    /// Title text
    pub title: [u8; MAX_TITLE],
    /// Flags
    pub flags: u32,
    /// Callback function
    pub callback: usize,
    /// User parameter
    pub lparam: isize,
    /// Selected folder image
    pub image: i32,
}

impl BrowseInfo {
    pub const fn new() -> Self {
        Self {
            hwnd_owner: UserHandle::NULL,
            root: 0,
            display_name: [0; MAX_PATH],
            display_name_len: 0,
            title_len: 0,
            title: [0; MAX_TITLE],
            flags: 0,
            callback: 0,
            lparam: 0,
            image: 0,
        }
    }
}

/// Browse for folder flags (BIF_*)
pub mod bif_flags {
    /// Return only file system directories
    pub const RETURNONLYFSDIRS: u32 = 0x00000001;
    /// Don't include network folders
    pub const DONTGOBELOWDOMAIN: u32 = 0x00000002;
    /// Show status text
    pub const STATUSTEXT: u32 = 0x00000004;
    /// Include file ancestor
    pub const RETURNFSANCESTORS: u32 = 0x00000008;
    /// Include edit box
    pub const EDITBOX: u32 = 0x00000010;
    /// Validate edit box
    pub const VALIDATE: u32 = 0x00000020;
    /// Use new UI
    pub const NEWDIALOGSTYLE: u32 = 0x00000040;
    /// Browse for computers
    pub const BROWSEFORCOMPUTER: u32 = 0x00001000;
    /// Browse for printers
    pub const BROWSEFORPRINTER: u32 = 0x00002000;
    /// Browse for everything
    pub const BROWSEINCLUDEFILES: u32 = 0x00004000;
    /// Shareable
    pub const SHAREABLE: u32 = 0x00008000;
    /// Browse for URLs
    pub const BROWSEINCLUDEURLS: u32 = 0x00010000;
    /// Use usage hint
    pub const UAHINT: u32 = 0x00000100;
    /// No new folder button
    pub const NONEWFOLDERBUTTON: u32 = 0x00000200;
    /// No translate targets
    pub const NOTRANSLATETARGETS: u32 = 0x00000400;
}

/// Browse for folder
pub fn sh_browse_for_folder(bi: &mut BrowseInfo, path_buffer: &mut [u8]) -> bool {
    if !FILEDLG_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        return false;
    }

    let hwnd = create_folder_dialog(bi);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;
    state.dialog_type = FileDialogType::SelectFolder;

    drop(state);

    let result = run_folder_dialog(hwnd, bi, path_buffer);

    let mut state = CURRENT_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create file dialog window
fn create_file_dialog(_dialog_type: FileDialogType, _ofn: &OpenFileName) -> HWND {
    // Would create the actual dialog window
    DIALOG_COUNT.fetch_add(1, Ordering::Relaxed);
    UserHandle::NULL
}

/// Create folder dialog window
fn create_folder_dialog(_bi: &BrowseInfo) -> HWND {
    DIALOG_COUNT.fetch_add(1, Ordering::Relaxed);
    UserHandle::NULL
}

/// Run file dialog modal loop
fn run_file_dialog(_hwnd: HWND, _ofn: &mut OpenFileName) -> bool {
    // Would run modal dialog loop
    true
}

/// Run folder dialog modal loop
fn run_folder_dialog(_hwnd: HWND, _bi: &mut BrowseInfo, _path: &mut [u8]) -> bool {
    true
}

/// Parse multi-select result
fn parse_multiselect_result(buffer: &[u8], len: usize) -> FileList {
    let mut list = FileList::new();

    if len == 0 {
        return list;
    }

    // Multi-select format: directory\0file1\0file2\0...\0\0
    let mut pos = 0;
    let mut first = true;

    while pos < len {
        // Find null terminator
        let mut end = pos;
        while end < len && buffer[end] != 0 {
            end += 1;
        }

        if end == pos {
            // Double null - end of list
            break;
        }

        if first {
            // First entry is directory
            list.dir_len = (end - pos).min(MAX_PATH) as u16;
            list.directory[..list.dir_len as usize].copy_from_slice(&buffer[pos..pos + list.dir_len as usize]);
            first = false;
        } else {
            // Subsequent entries are file names
            if list.count < MAX_FILES {
                let file_len = (end - pos).min(MAX_PATH);
                list.file_lens[list.count] = file_len as u16;
                list.files[list.count][..file_len].copy_from_slice(&buffer[pos..pos + file_len]);
                list.count += 1;
            }
        }

        pos = end + 1;
    }

    // If only one entry, it's the full path
    if list.count == 0 && list.dir_len > 0 {
        // Extract file name from path
        let dir = &list.directory[..list.dir_len as usize];
        if let Some(sep_pos) = dir.iter().rposition(|&b| b == b'\\' || b == b'/') {
            // Split into directory and file
            let file_part = &dir[sep_pos + 1..];
            list.file_lens[0] = file_part.len() as u16;
            list.files[0][..file_part.len()].copy_from_slice(file_part);
            list.dir_len = sep_pos as u16;
            list.count = 1;
        }
    }

    list
}

/// Close file dialog
pub fn close_file_dialog() {
    let mut state = CURRENT_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }

        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Get current dialog state
pub fn get_dialog_state() -> FileDialogState {
    *CURRENT_STATE.lock()
}

// ============================================================================
// Recent Directories
// ============================================================================

/// Add directory to recent list
pub fn add_recent_directory(path: &[u8]) {
    let mut recent = RECENT_DIRS.lock();
    let count = RECENT_DIR_COUNT.load(Ordering::Relaxed) as usize;

    // Check if already in list
    let path_len = path.len().min(MAX_PATH);
    for i in 0..count.min(16) {
        if recent[i][..path_len] == path[..path_len] {
            // Move to front
            if i > 0 {
                let entry = recent[i];
                for j in (1..=i).rev() {
                    recent[j] = recent[j - 1];
                }
                recent[0] = entry;
            }
            return;
        }
    }

    // Add new entry at front
    for i in (1..16).rev() {
        recent[i] = recent[i - 1];
    }
    recent[0] = [0; MAX_PATH];
    recent[0][..path_len].copy_from_slice(&path[..path_len]);

    if count < 16 {
        RECENT_DIR_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Get recent directories
pub fn get_recent_directories() -> ([[u8; MAX_PATH]; 16], usize) {
    let recent = RECENT_DIRS.lock();
    let count = RECENT_DIR_COUNT.load(Ordering::Relaxed) as usize;
    (*recent, count.min(16))
}

// ============================================================================
// Common Filters
// ============================================================================

/// Common file filter presets
pub mod common_filters {
    use super::FileFilter;

    /// All files filter
    pub fn all_files() -> FileFilter {
        FileFilter::from_parts(b"All Files", b"*.*")
    }

    /// Text files filter
    pub fn text_files() -> FileFilter {
        FileFilter::from_parts(b"Text Files", b"*.txt")
    }

    /// Image files filter
    pub fn image_files() -> FileFilter {
        FileFilter::from_parts(b"Image Files", b"*.bmp;*.jpg;*.jpeg;*.png;*.gif")
    }

    /// Document files filter
    pub fn document_files() -> FileFilter {
        FileFilter::from_parts(b"Documents", b"*.doc;*.docx;*.rtf;*.pdf")
    }

    /// Executable files filter
    pub fn executable_files() -> FileFilter {
        FileFilter::from_parts(b"Executables", b"*.exe;*.com;*.bat;*.cmd")
    }

    /// Source code filter
    pub fn source_files() -> FileFilter {
        FileFilter::from_parts(b"Source Files", b"*.c;*.cpp;*.h;*.rs;*.py;*.js")
    }
}

/// Create a simple open file name structure
pub fn create_simple_ofn(
    owner: HWND,
    title: &[u8],
    filter: Option<FileFilter>,
    initial_dir: Option<&[u8]>,
) -> OpenFileName {
    let mut ofn = OpenFileName::new();

    ofn.hwnd_owner = owner;

    // Set title
    ofn.title_len = title.len().min(MAX_TITLE) as u8;
    ofn.title[..ofn.title_len as usize].copy_from_slice(&title[..ofn.title_len as usize]);

    // Set filter
    if let Some(f) = filter {
        ofn.filters[0] = f;
        ofn.filter_count = 1;
    } else {
        ofn.filters[0] = common_filters::all_files();
        ofn.filter_count = 1;
    }

    // Set initial directory
    if let Some(dir) = initial_dir {
        ofn.initial_dir_len = dir.len().min(MAX_PATH) as u16;
        ofn.initial_dir[..ofn.initial_dir_len as usize].copy_from_slice(&dir[..ofn.initial_dir_len as usize]);
    }

    ofn.flags = ofn_flags::EXPLORER | ofn_flags::FILEMUSTEXIST | ofn_flags::PATHMUSTEXIST;

    ofn
}
