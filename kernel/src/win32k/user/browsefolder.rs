//! Browse for Folder Dialog
//!
//! Provides the Browse for Folder dialog following the Windows shell32
//! SHBrowseForFolder pattern.
//!
//! # References
//!
//! - Windows Server 2003 shell32 folder browser
//! - BROWSEINFO structure
//! - SHBrowseForFolder API

use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum path length
pub const MAX_PATH: usize = 260;

/// Browse flags (BIF_*)
pub mod bif_flags {
    /// Return only file system directories
    pub const RETURNONLYFSDIRS: u32 = 0x00000001;
    /// Do not include network folders
    pub const DONTGOBELOWDOMAIN: u32 = 0x00000002;
    /// Include status text area
    pub const STATUSTEXT: u32 = 0x00000004;
    /// Return file system ancestors only
    pub const RETURNFSANCESTORS: u32 = 0x00000008;
    /// Include edit field
    pub const EDITBOX: u32 = 0x00000010;
    /// Validate edit field
    pub const VALIDATE: u32 = 0x00000020;
    /// Use new UI with tree view
    pub const NEWDIALOGSTYLE: u32 = 0x00000040;
    /// Browse for everything (not just folders)
    pub const BROWSEINCLUDEFILES: u32 = 0x00004000;
    /// Allow URLs in path
    pub const BROWSEINCLUDEURLS: u32 = 0x00000080;
    /// Enable uahint for edit box
    pub const UAHINT: u32 = 0x00000100;
    /// No new folder button
    pub const NONEWFOLDERBUTTON: u32 = 0x00000200;
    /// No translate targets
    pub const NOTRANSLATETARGETS: u32 = 0x00000400;
    /// Browse for computers
    pub const BROWSEFORCOMPUTER: u32 = 0x00001000;
    /// Browse for printers
    pub const BROWSEFORPRINTER: u32 = 0x00002000;
    /// Shareable resources
    pub const SHAREABLE: u32 = 0x00008000;
}

/// WM_USER base message
const WM_USER: u32 = 0x0400;

/// WM_NOTIFY message
const WM_NOTIFY: u32 = 0x004E;

/// Browse callback messages
pub mod bffm {
    /// Initialization complete
    pub const INITIALIZED: u32 = 1;
    /// Selection changed
    pub const SELCHANGED: u32 = 2;
    /// Validate failed (ANSI)
    pub const VALIDATEFAILEDA: u32 = 3;
    /// Validate failed (Unicode)
    pub const VALIDATEFAILEDW: u32 = 4;
    /// Set status text (ANSI)
    pub const SETSTATUSTEXTA: u32 = super::WM_USER + 100;
    /// Set status text (Unicode)
    pub const SETSTATUSTEXTW: u32 = super::WM_USER + 104;
    /// Enable OK button
    pub const ENABLEOK: u32 = super::WM_USER + 101;
    /// Set selection (ANSI)
    pub const SETSELECTIONA: u32 = super::WM_USER + 102;
    /// Set selection (Unicode)
    pub const SETSELECTIONW: u32 = super::WM_USER + 103;
    /// Set expanded state
    pub const SETEXPANDED: u32 = super::WM_USER + 106;
    /// Set OK text
    pub const SETOKTEXT: u32 = super::WM_USER + 105;
}

/// Special folder IDs (CSIDL_*)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpecialFolder {
    #[default]
    Desktop = 0x0000,
    Internet = 0x0001,
    Programs = 0x0002,
    Controls = 0x0003,
    Printers = 0x0004,
    Personal = 0x0005,
    Favorites = 0x0006,
    Startup = 0x0007,
    Recent = 0x0008,
    SendTo = 0x0009,
    BitBucket = 0x000A,
    StartMenu = 0x000B,
    MyDocuments = 0x000C,
    MyMusic = 0x000D,
    MyVideo = 0x000E,
    DesktopDirectory = 0x0010,
    Drives = 0x0011,
    Network = 0x0012,
    Nethood = 0x0013,
    Fonts = 0x0014,
    Templates = 0x0015,
    CommonStartMenu = 0x0016,
    CommonPrograms = 0x0017,
    CommonStartup = 0x0018,
    CommonDesktopDirectory = 0x0019,
    AppData = 0x001A,
    PrintHood = 0x001B,
    LocalAppData = 0x001C,
    CommonFavorites = 0x001F,
    InternetCache = 0x0020,
    Cookies = 0x0021,
    History = 0x0022,
    CommonAppData = 0x0023,
    Windows = 0x0024,
    System = 0x0025,
    ProgramFiles = 0x0026,
    MyPictures = 0x0027,
    Profile = 0x0028,
    SystemX86 = 0x0029,
    ProgramFilesX86 = 0x002A,
    CommonProgramFiles = 0x002B,
    CommonProgramFilesX86 = 0x002C,
    CommonTemplates = 0x002D,
    CommonDocuments = 0x002E,
    CommonAdminTools = 0x002F,
    AdminTools = 0x0030,
    Connections = 0x0031,
    CommonMusic = 0x0035,
    CommonPictures = 0x0036,
    CommonVideo = 0x0037,
    Resources = 0x0038,
    ResourcesLocalized = 0x0039,
    CDburn = 0x003B,
    ComputersNearMe = 0x003D,
}

// ============================================================================
// Structures
// ============================================================================

/// Browse info structure (BROWSEINFO equivalent)
#[derive(Clone, Copy)]
pub struct BrowseInfo {
    /// Owner window
    pub hwnd_owner: HWND,
    /// Root folder
    pub root: u32,
    /// Display name buffer
    pub display_name: [u8; MAX_PATH],
    /// Display name length
    pub display_name_len: usize,
    /// Title length
    pub title_len: u8,
    /// Title
    pub title: [u8; 128],
    /// Flags
    pub flags: u32,
    /// Callback function
    pub callback: usize,
    /// Callback parameter
    pub lparam: isize,
    /// Image index
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
            title: [0; 128],
            flags: bif_flags::RETURNONLYFSDIRS | bif_flags::NEWDIALOGSTYLE,
            callback: 0,
            lparam: 0,
            image: 0,
        }
    }

    /// Set title
    pub fn set_title(&mut self, title: &[u8]) {
        self.title_len = title.len().min(128) as u8;
        self.title[..self.title_len as usize].copy_from_slice(&title[..self.title_len as usize]);
    }
}

/// Folder item in tree
#[derive(Debug, Clone, Copy)]
pub struct FolderItem {
    /// Item is valid
    pub valid: bool,
    /// Is folder (vs file)
    pub is_folder: bool,
    /// Has children
    pub has_children: bool,
    /// Is expanded
    pub expanded: bool,
    /// Parent index (0 = root)
    pub parent: u16,
    /// Icon index
    pub icon: u16,
    /// Name length
    pub name_len: u8,
    /// Name
    pub name: [u8; 64],
    /// Full path length
    pub path_len: u16,
    /// Full path
    pub path: [u8; MAX_PATH],
}

impl FolderItem {
    const fn new() -> Self {
        Self {
            valid: false,
            is_folder: true,
            has_children: false,
            expanded: false,
            parent: 0,
            icon: 0,
            name_len: 0,
            name: [0; 64],
            path_len: 0,
            path: [0; MAX_PATH],
        }
    }
}

/// Browse dialog state
#[derive(Clone, Copy)]
pub struct BrowseDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Selected item index
    pub selected_item: usize,
    /// OK button enabled
    pub ok_enabled: bool,
    /// Result path length
    pub result_len: usize,
    /// Result path
    pub result_path: [u8; MAX_PATH],
    /// Browse info
    pub info: BrowseInfo,
}

impl BrowseDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            selected_item: 0,
            ok_enabled: false,
            result_len: 0,
            result_path: [0; MAX_PATH],
            info: BrowseInfo::new(),
        }
    }
}

// ============================================================================
// State
// ============================================================================

static BROWSE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static BROWSE_LOCK: SpinLock<()> = SpinLock::new(());

static CURRENT_STATE: SpinLock<BrowseDialogState> = SpinLock::new(BrowseDialogState::new());

// Folder tree items
const MAX_ITEMS: usize = 256;
static FOLDER_ITEMS: SpinLock<[FolderItem; MAX_ITEMS]> =
    SpinLock::new([const { FolderItem::new() }; MAX_ITEMS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize browse folder dialog subsystem
pub fn init() {
    let _guard = BROWSE_LOCK.lock();

    if BROWSE_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[BROWSEFOLDER] Initializing browse folder dialog...");

    BROWSE_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[BROWSEFOLDER] Browse folder dialog initialized");
}

// ============================================================================
// Browse Folder API
// ============================================================================

/// Show browse for folder dialog
pub fn sh_browse_for_folder(info: &mut BrowseInfo) -> Option<[u8; MAX_PATH]> {
    if !BROWSE_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        return None;
    }

    // Initialize state
    state.info = *info;
    state.selected_item = 0;
    state.ok_enabled = false;
    state.result_len = 0;
    state.result_path = [0; MAX_PATH];

    // Create dialog
    let hwnd = create_browse_dialog(info);

    if hwnd == UserHandle::NULL {
        return None;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    // Initialize folder tree
    init_folder_tree(info);

    // Call initialization callback if set
    if info.callback != 0 {
        // Would call callback with BFFM_INITIALIZED
    }

    // Run dialog
    let result = run_browse_dialog(hwnd);

    // Get result
    if result {
        let state = CURRENT_STATE.lock();
        let mut path = [0u8; MAX_PATH];
        let len = state.result_len.min(MAX_PATH);
        path[..len].copy_from_slice(&state.result_path[..len]);

        // Copy display name
        info.display_name[..state.info.display_name_len]
            .copy_from_slice(&state.info.display_name[..state.info.display_name_len]);
        info.display_name_len = state.info.display_name_len;
        info.image = state.info.image;

        drop(state);

        // Clean up
        let mut state = CURRENT_STATE.lock();
        state.active = false;
        state.hwnd = UserHandle::NULL;

        return Some(path);
    }

    // Clean up
    let mut state = CURRENT_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    None
}

/// Close browse dialog
pub fn close_browse_dialog() {
    let mut state = CURRENT_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }

        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Get selected path
pub fn get_selected_path() -> Option<([u8; MAX_PATH], usize)> {
    let state = CURRENT_STATE.lock();

    if !state.active {
        return None;
    }

    if state.selected_item == 0 {
        return None;
    }

    let items = FOLDER_ITEMS.lock();
    let item = &items[state.selected_item];

    if item.valid {
        let mut path = [0u8; MAX_PATH];
        let len = item.path_len as usize;
        path[..len].copy_from_slice(&item.path[..len]);
        Some((path, len))
    } else {
        None
    }
}

/// Set selection by path
pub fn set_selection(path: &[u8]) -> bool {
    if !BROWSE_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = CURRENT_STATE.lock();

    if !state.active {
        return false;
    }

    // Find item with matching path
    let items = FOLDER_ITEMS.lock();
    for (i, item) in items.iter().enumerate() {
        if item.valid && item.path_len as usize == path.len() {
            if &item.path[..item.path_len as usize] == path {
                drop(items);
                state.selected_item = i;
                state.ok_enabled = true;
                return true;
            }
        }
    }

    false
}

/// Set status text
pub fn set_status_text(text: &[u8]) -> bool {
    let state = CURRENT_STATE.lock();

    if !state.active {
        return false;
    }

    // Would update status text in dialog
    let _ = text;
    true
}

/// Enable/disable OK button
pub fn enable_ok(enable: bool) -> bool {
    let mut state = CURRENT_STATE.lock();

    if !state.active {
        return false;
    }

    state.ok_enabled = enable;
    true
}

// ============================================================================
// Folder Tree Management
// ============================================================================

/// Initialize folder tree
fn init_folder_tree(info: &BrowseInfo) {
    let mut items = FOLDER_ITEMS.lock();

    // Clear existing items
    for item in items.iter_mut() {
        item.valid = false;
    }

    // Add root item
    let root = &mut items[0];
    root.valid = true;
    root.is_folder = true;
    root.has_children = true;
    root.expanded = true;
    root.parent = 0;
    root.icon = 0;

    // Set root name based on root folder type
    let root_name = match info.root {
        0 => b"Desktop" as &[u8],
        0x11 => b"My Computer" as &[u8],
        0x12 => b"Network" as &[u8],
        _ => b"Folder" as &[u8],
    };
    root.name_len = root_name.len() as u8;
    root.name[..root.name_len as usize].copy_from_slice(root_name);
    root.path_len = 0;

    // Would populate children from file system
}

/// Add folder item
pub fn add_folder_item(parent: usize, name: &[u8], path: &[u8], has_children: bool) -> Option<usize> {
    let mut items = FOLDER_ITEMS.lock();

    // Find free slot
    for (i, item) in items.iter_mut().enumerate() {
        if !item.valid {
            item.valid = true;
            item.is_folder = true;
            item.has_children = has_children;
            item.expanded = false;
            item.parent = parent as u16;
            item.icon = 3; // Folder icon
            item.name_len = name.len().min(64) as u8;
            item.name[..item.name_len as usize].copy_from_slice(&name[..item.name_len as usize]);
            item.path_len = path.len().min(MAX_PATH) as u16;
            item.path[..item.path_len as usize].copy_from_slice(&path[..item.path_len as usize]);

            return Some(i);
        }
    }

    None
}

/// Expand folder item
pub fn expand_folder(index: usize) -> bool {
    let mut items = FOLDER_ITEMS.lock();

    if index >= MAX_ITEMS || !items[index].valid {
        return false;
    }

    items[index].expanded = true;
    // Would populate children from file system
    true
}

/// Collapse folder item
pub fn collapse_folder(index: usize) -> bool {
    let mut items = FOLDER_ITEMS.lock();

    if index >= MAX_ITEMS || !items[index].valid {
        return false;
    }

    items[index].expanded = false;
    true
}

/// Get folder children
pub fn get_folder_children(parent: usize) -> ([usize; 64], usize) {
    let items = FOLDER_ITEMS.lock();
    let mut children = [0usize; 64];
    let mut count = 0;

    for (i, item) in items.iter().enumerate() {
        if item.valid && item.parent as usize == parent && i != parent {
            if count < 64 {
                children[count] = i;
                count += 1;
            }
        }
    }

    (children, count)
}

/// Get folder item info
pub fn get_folder_item(index: usize) -> Option<FolderItem> {
    let items = FOLDER_ITEMS.lock();

    if index < MAX_ITEMS && items[index].valid {
        Some(items[index])
    } else {
        None
    }
}

// ============================================================================
// Dialog Creation
// ============================================================================

/// Create browse dialog window
fn create_browse_dialog(_info: &BrowseInfo) -> HWND {
    // Would create browse dialog window
    UserHandle::NULL
}

/// Run browse dialog modal loop
fn run_browse_dialog(_hwnd: HWND) -> bool {
    // Would run modal dialog loop
    false
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Browse dialog window procedure
pub fn browse_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_browse_command(hwnd, wparam as u32)
        }
        WM_NOTIFY => {
            handle_browse_notify(hwnd, wparam)
        }
        super::message::WM_CLOSE => {
            close_browse_dialog();
            0
        }
        _ => 0,
    }
}

/// Handle browse dialog commands
fn handle_browse_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        1 => {
            // OK button
            let state = CURRENT_STATE.lock();
            if state.active && state.hwnd == hwnd && state.ok_enabled {
                // Copy selected path to result
                if let Some((path, len)) = get_selected_path() {
                    drop(state);
                    let mut state = CURRENT_STATE.lock();
                    state.result_path = path;
                    state.result_len = len;
                    drop(state);
                    close_browse_dialog();
                }
            }
            1
        }
        2 => {
            // Cancel button
            close_browse_dialog();
            0
        }
        100 => {
            // New folder button
            create_new_folder();
            0
        }
        _ => 0,
    }
}

/// Handle browse dialog notifications
fn handle_browse_notify(_hwnd: HWND, _wparam: usize) -> isize {
    // Would handle treeview notifications
    0
}

/// Create new folder
fn create_new_folder() {
    let state = CURRENT_STATE.lock();

    if !state.active {
        return;
    }

    // Would prompt for folder name and create folder
}

// ============================================================================
// Special Folder Paths
// ============================================================================

/// Get special folder path
pub fn get_special_folder_path(folder: SpecialFolder, buffer: &mut [u8]) -> usize {
    let path: &[u8] = match folder {
        SpecialFolder::Desktop => b"C:\\Documents and Settings\\User\\Desktop",
        SpecialFolder::Personal | SpecialFolder::MyDocuments => b"C:\\Documents and Settings\\User\\My Documents",
        SpecialFolder::MyMusic => b"C:\\Documents and Settings\\User\\My Documents\\My Music",
        SpecialFolder::MyPictures => b"C:\\Documents and Settings\\User\\My Documents\\My Pictures",
        SpecialFolder::MyVideo => b"C:\\Documents and Settings\\User\\My Documents\\My Videos",
        SpecialFolder::Programs => b"C:\\Documents and Settings\\User\\Start Menu\\Programs",
        SpecialFolder::StartMenu => b"C:\\Documents and Settings\\User\\Start Menu",
        SpecialFolder::Startup => b"C:\\Documents and Settings\\User\\Start Menu\\Programs\\Startup",
        SpecialFolder::Recent => b"C:\\Documents and Settings\\User\\Recent",
        SpecialFolder::SendTo => b"C:\\Documents and Settings\\User\\SendTo",
        SpecialFolder::Favorites => b"C:\\Documents and Settings\\User\\Favorites",
        SpecialFolder::Templates => b"C:\\Documents and Settings\\User\\Templates",
        SpecialFolder::AppData => b"C:\\Documents and Settings\\User\\Application Data",
        SpecialFolder::LocalAppData => b"C:\\Documents and Settings\\User\\Local Settings\\Application Data",
        SpecialFolder::InternetCache => b"C:\\Documents and Settings\\User\\Local Settings\\Temporary Internet Files",
        SpecialFolder::Cookies => b"C:\\Documents and Settings\\User\\Cookies",
        SpecialFolder::History => b"C:\\Documents and Settings\\User\\Local Settings\\History",
        SpecialFolder::Windows => b"C:\\WINDOWS",
        SpecialFolder::System => b"C:\\WINDOWS\\system32",
        SpecialFolder::SystemX86 => b"C:\\WINDOWS\\SysWOW64",
        SpecialFolder::ProgramFiles => b"C:\\Program Files",
        SpecialFolder::ProgramFilesX86 => b"C:\\Program Files (x86)",
        SpecialFolder::CommonProgramFiles => b"C:\\Program Files\\Common Files",
        SpecialFolder::CommonProgramFilesX86 => b"C:\\Program Files (x86)\\Common Files",
        SpecialFolder::CommonStartMenu => b"C:\\Documents and Settings\\All Users\\Start Menu",
        SpecialFolder::CommonPrograms => b"C:\\Documents and Settings\\All Users\\Start Menu\\Programs",
        SpecialFolder::CommonStartup => b"C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup",
        SpecialFolder::CommonDesktopDirectory => b"C:\\Documents and Settings\\All Users\\Desktop",
        SpecialFolder::CommonDocuments => b"C:\\Documents and Settings\\All Users\\Documents",
        SpecialFolder::CommonAppData => b"C:\\Documents and Settings\\All Users\\Application Data",
        SpecialFolder::CommonTemplates => b"C:\\Documents and Settings\\All Users\\Templates",
        SpecialFolder::Fonts => b"C:\\WINDOWS\\Fonts",
        SpecialFolder::Profile => b"C:\\Documents and Settings\\User",
        SpecialFolder::Drives => b"My Computer",
        SpecialFolder::Network => b"Network",
        _ => b"",
    };

    let len = path.len().min(buffer.len());
    buffer[..len].copy_from_slice(&path[..len]);
    len
}

/// Create simple browse for folder
pub fn browse_for_folder(title: &[u8]) -> Option<([u8; MAX_PATH], usize)> {
    let mut info = BrowseInfo::new();
    info.set_title(title);
    info.flags = bif_flags::RETURNONLYFSDIRS | bif_flags::NEWDIALOGSTYLE;

    if let Some(path) = sh_browse_for_folder(&mut info) {
        // Find actual length
        let len = path.iter().position(|&c| c == 0).unwrap_or(MAX_PATH);
        Some((path, len))
    } else {
        None
    }
}
