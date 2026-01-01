//! Help System Support
//!
//! WinHelp and HTML Help support.
//! Based on Windows Server 2003 winuser.h and htmlhelp.h.
//!
//! # Features
//!
//! - WinHelp (.hlp) support
//! - HTML Help (.chm) support
//! - Context-sensitive help
//! - Help windows management
//!
//! # References
//!
//! - `public/sdk/inc/winuser.h` - WinHelp
//! - `public/sdk/inc/htmlhelp.h` - HTML Help API

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Point};

// ============================================================================
// WinHelp Commands (HELP_*)
// ============================================================================

/// Display help on context
pub const HELP_CONTEXT: u32 = 0x0001;

/// Display help index
pub const HELP_INDEX: u32 = 0x0003;

/// Display help on topic
pub const HELP_HELPONHELP: u32 = 0x0004;

/// Set help window position
pub const HELP_SETWINPOS: u32 = 0x0005;

/// Display help on keyword
pub const HELP_KEY: u32 = 0x0101;

/// Display help on command
pub const HELP_COMMAND: u32 = 0x0102;

/// Display help on partial keyword
pub const HELP_PARTIALKEY: u32 = 0x0105;

/// Display help on multi-keyword
pub const HELP_MULTIKEY: u32 = 0x0201;

/// Set help contents
pub const HELP_SETCONTENTS: u32 = 0x0005;

/// Display context popup
pub const HELP_CONTEXTPOPUP: u32 = 0x0008;

/// Force file (internal)
pub const HELP_FORCEFILE: u32 = 0x0009;

/// Finder
pub const HELP_FINDER: u32 = 0x000B;

/// What's this mode
pub const HELP_WM_HELP: u32 = 0x000C;

/// Set popup position
pub const HELP_SETPOPUP_POS: u32 = 0x000D;

/// Contents
pub const HELP_CONTENTS: u32 = 0x0003;

/// Quit help
pub const HELP_QUIT: u32 = 0x0002;

/// Context ID for help topics
pub const HELP_CONTEXTMENU: u32 = 0x000A;

/// Tray notify
pub const HELP_TRAY: u32 = 0x0800;

// ============================================================================
// HTML Help Commands (HH_*)
// ============================================================================

/// Display topic
pub const HH_DISPLAY_TOPIC: u32 = 0x0000;

/// Display TOC
pub const HH_DISPLAY_TOC: u32 = 0x0001;

/// Display index
pub const HH_DISPLAY_INDEX: u32 = 0x0002;

/// Display search
pub const HH_DISPLAY_SEARCH: u32 = 0x0003;

/// Set window type
pub const HH_SET_WIN_TYPE: u32 = 0x0004;

/// Get window type
pub const HH_GET_WIN_TYPE: u32 = 0x0005;

/// Get window handle
pub const HH_GET_WIN_HANDLE: u32 = 0x0006;

/// Display text popup
pub const HH_DISPLAY_TEXT_POPUP: u32 = 0x000E;

/// Help context
pub const HH_HELP_CONTEXT: u32 = 0x000F;

/// Display topic (old)
pub const HH_TP_HELP_CONTEXTMENU: u32 = 0x0010;

/// Display topic (old)
pub const HH_TP_HELP_WM_HELP: u32 = 0x0011;

/// Close all windows
pub const HH_CLOSE_ALL: u32 = 0x0012;

/// Keyword lookup
pub const HH_KEYWORD_LOOKUP: u32 = 0x000D;

/// Safe display topic
pub const HH_SAFE_DISPLAY_TOPIC: u32 = 0x0020;

/// Initialize
pub const HH_INITIALIZE: u32 = 0x001C;

/// Uninitialize
pub const HH_UNINITIALIZE: u32 = 0x001D;

// ============================================================================
// HTML Help Window Type Flags (HHWIN_*)
// ============================================================================

/// Default navigation pane width
pub const HHWIN_DEF_NAVWIDTH: u32 = 200;

/// Toolbar
pub const HHWIN_TB_MARGIN: u32 = 0x00000000;

/// Window button flags
pub const HHWIN_BUTTON_EXPAND: u32 = 0x00000002;
pub const HHWIN_BUTTON_BACK: u32 = 0x00000004;
pub const HHWIN_BUTTON_FORWARD: u32 = 0x00000008;
pub const HHWIN_BUTTON_STOP: u32 = 0x00000010;
pub const HHWIN_BUTTON_REFRESH: u32 = 0x00000020;
pub const HHWIN_BUTTON_HOME: u32 = 0x00000040;
pub const HHWIN_BUTTON_BROWSE_FWD: u32 = 0x00000080;
pub const HHWIN_BUTTON_BROWSE_BCK: u32 = 0x00000100;
pub const HHWIN_BUTTON_NOTES: u32 = 0x00000200;
pub const HHWIN_BUTTON_CONTENTS: u32 = 0x00000400;
pub const HHWIN_BUTTON_SYNC: u32 = 0x00000800;
pub const HHWIN_BUTTON_OPTIONS: u32 = 0x00001000;
pub const HHWIN_BUTTON_PRINT: u32 = 0x00002000;
pub const HHWIN_BUTTON_INDEX: u32 = 0x00004000;
pub const HHWIN_BUTTON_SEARCH: u32 = 0x00008000;
pub const HHWIN_BUTTON_HISTORY: u32 = 0x00010000;
pub const HHWIN_BUTTON_FAVORITES: u32 = 0x00020000;
pub const HHWIN_BUTTON_JUMP1: u32 = 0x00040000;
pub const HHWIN_BUTTON_JUMP2: u32 = 0x00080000;
pub const HHWIN_BUTTON_ZOOM: u32 = 0x00100000;
pub const HHWIN_BUTTON_TOC_NEXT: u32 = 0x00200000;
pub const HHWIN_BUTTON_TOC_PREV: u32 = 0x00400000;

/// Default buttons
pub const HHWIN_DEF_BUTTONS: u32 = HHWIN_BUTTON_EXPAND
    | HHWIN_BUTTON_BACK
    | HHWIN_BUTTON_OPTIONS
    | HHWIN_BUTTON_PRINT;

// ============================================================================
// HTML Help Window Properties (HHWIN_PROP_*)
// ============================================================================

/// Ontop
pub const HHWIN_PROP_ONTOP: u32 = 0x00000002;

/// Notitlebar
pub const HHWIN_PROP_NOTITLEBAR: u32 = 0x00000004;

/// Nodef styles
pub const HHWIN_PROP_NODEF_STYLES: u32 = 0x00000008;

/// Nodef exstyles
pub const HHWIN_PROP_NODEF_EXSTYLES: u32 = 0x00000010;

/// Tri pane
pub const HHWIN_PROP_TRI_PANE: u32 = 0x00000020;

/// Notb text
pub const HHWIN_PROP_NOTB_TEXT: u32 = 0x00000040;

/// Post quit
pub const HHWIN_PROP_POST_QUIT: u32 = 0x00000080;

/// Auto sync
pub const HHWIN_PROP_AUTO_SYNC: u32 = 0x00000100;

/// Tracking
pub const HHWIN_PROP_TRACKING: u32 = 0x00000200;

/// Tab search
pub const HHWIN_PROP_TAB_SEARCH: u32 = 0x00000400;

/// Tab history
pub const HHWIN_PROP_TAB_HISTORY: u32 = 0x00000800;

/// Tab favorites
pub const HHWIN_PROP_TAB_FAVORITES: u32 = 0x00001000;

/// Change title
pub const HHWIN_PROP_CHANGE_TITLE: u32 = 0x00002000;

/// Nav only win
pub const HHWIN_PROP_NAV_ONLY_WIN: u32 = 0x00004000;

/// No toolbar
pub const HHWIN_PROP_NO_TOOLBAR: u32 = 0x00008000;

/// Menu
pub const HHWIN_PROP_MENU: u32 = 0x00010000;

/// Tab advsearch
pub const HHWIN_PROP_TAB_ADVSEARCH: u32 = 0x00020000;

/// User pos
pub const HHWIN_PROP_USER_POS: u32 = 0x00040000;

// ============================================================================
// Constants
// ============================================================================

/// Maximum help windows
pub const MAX_HELP_WINDOWS: usize = 16;

/// Maximum help files
pub const MAX_HELP_FILES: usize = 32;

/// Maximum path length
pub const MAX_PATH: usize = 260;

/// Maximum topic length
pub const MAX_TOPIC: usize = 256;

// ============================================================================
// Help File Types
// ============================================================================

/// Help file type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpFileType {
    /// Unknown
    Unknown,
    /// WinHelp (.hlp)
    WinHelp,
    /// HTML Help (.chm)
    HtmlHelp,
}

// ============================================================================
// Help Window
// ============================================================================

/// Help window
#[derive(Clone)]
pub struct HelpWindow {
    /// Is this slot in use
    pub in_use: bool,
    /// Window handle
    pub hwnd: HWND,
    /// Parent window
    pub parent_hwnd: HWND,
    /// Help file path
    pub file_path: [u8; MAX_PATH],
    /// Current topic
    pub topic: [u8; MAX_TOPIC],
    /// File type
    pub file_type: HelpFileType,
    /// Is visible
    pub visible: bool,
    /// Window properties
    pub properties: u32,
    /// Button flags
    pub buttons: u32,
}

impl HelpWindow {
    /// Create empty window
    pub const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle::NULL,
            parent_hwnd: UserHandle::NULL,
            file_path: [0; MAX_PATH],
            topic: [0; MAX_TOPIC],
            file_type: HelpFileType::Unknown,
            visible: false,
            properties: 0,
            buttons: HHWIN_DEF_BUTTONS,
        }
    }
}

// ============================================================================
// Help Context Entry
// ============================================================================

/// Help context mapping
#[derive(Clone, Copy)]
pub struct HelpContextEntry {
    /// Is this slot in use
    pub in_use: bool,
    /// Control ID
    pub control_id: u32,
    /// Help context ID
    pub help_id: u32,
}

impl HelpContextEntry {
    /// Create empty entry
    pub const fn new() -> Self {
        Self {
            in_use: false,
            control_id: 0,
            help_id: 0,
        }
    }
}

// ============================================================================
// Help File Registration
// ============================================================================

/// Help file registration
#[derive(Clone)]
pub struct HelpFileEntry {
    /// Is this slot in use
    pub in_use: bool,
    /// File path
    pub path: [u8; MAX_PATH],
    /// File type
    pub file_type: HelpFileType,
    /// Is open
    pub is_open: bool,
    /// Associated window
    pub hwnd: HWND,
}

impl HelpFileEntry {
    /// Create empty entry
    pub const fn new() -> Self {
        Self {
            in_use: false,
            path: [0; MAX_PATH],
            file_type: HelpFileType::Unknown,
            is_open: false,
            hwnd: UserHandle::NULL,
        }
    }
}

// ============================================================================
// HTML Help Popup
// ============================================================================

/// HTML Help popup info
#[derive(Clone)]
pub struct HtmlHelpPopup {
    /// Structure size
    pub cb_struct: u32,
    /// Instance handle
    pub hinst: usize,
    /// Text resource ID or string
    pub id_string: u32,
    /// Text (if not resource)
    pub text: [u8; 256],
    /// Point for popup
    pub pt: Point,
    /// Text color
    pub clr_foreground: u32,
    /// Background color
    pub clr_background: u32,
    /// Margins
    pub rc_margins: (i32, i32, i32, i32),
    /// Font
    pub font: [u8; 64],
}

impl HtmlHelpPopup {
    /// Create default popup
    pub const fn new() -> Self {
        Self {
            cb_struct: 0,
            hinst: 0,
            id_string: 0,
            text: [0; 256],
            pt: Point { x: 0, y: 0 },
            clr_foreground: 0,
            clr_background: 0x00FFFFFF,
            rc_margins: (0, 0, 0, 0),
            font: [0; 64],
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global help windows
static HELP_WINDOWS: SpinLock<[HelpWindow; MAX_HELP_WINDOWS]> =
    SpinLock::new([const { HelpWindow::new() }; MAX_HELP_WINDOWS]);

/// Global help files
static HELP_FILES: SpinLock<[HelpFileEntry; MAX_HELP_FILES]> =
    SpinLock::new([const { HelpFileEntry::new() }; MAX_HELP_FILES]);

/// Global context mappings
static CONTEXT_MAP: SpinLock<[HelpContextEntry; 128]> =
    SpinLock::new([const { HelpContextEntry::new() }; 128]);

/// Is HTML Help initialized
static HH_INITIALIZED: SpinLock<bool> = SpinLock::new(false);

/// HTML Help cookie
static HH_COOKIE: SpinLock<usize> = SpinLock::new(0);

// ============================================================================
// Public API
// ============================================================================

/// Initialize help system
pub fn init() {
    crate::serial_println!("[USER] Help system initialized");
}

/// WinHelp function
pub fn win_help(hwnd: HWND, help_file: &[u8], command: u32, data: usize) -> bool {
    match command {
        HELP_CONTEXT | HELP_CONTEXTPOPUP => {
            // Display help for context ID
            let _ = data; // context ID
            show_help_topic(hwnd, help_file, data as u32)
        }
        HELP_KEY | HELP_PARTIALKEY => {
            // Keyword search
            show_help_topic(hwnd, help_file, 0)
        }
        HELP_CONTENTS | HELP_FINDER => {
            // Show help contents/index (HELP_INDEX has same value as HELP_CONTENTS)
            show_help_contents(hwnd, help_file)
        }
        HELP_QUIT => {
            // Close help
            close_help(hwnd, help_file)
        }
        HELP_HELPONHELP => {
            // Show help on help
            show_help_contents(hwnd, b"winhelp.hlp")
        }
        _ => false,
    }
}

/// HTML Help function
pub fn html_help(hwnd: HWND, file: &[u8], command: u32, data: usize) -> HWND {
    match command {
        HH_INITIALIZE => {
            let mut initialized = HH_INITIALIZED.lock();
            let mut cookie = HH_COOKIE.lock();

            if !*initialized {
                *initialized = true;
                *cookie = 1;
            } else {
                *cookie += 1;
            }

            return UserHandle::from_raw(*cookie as u32);
        }
        HH_UNINITIALIZE => {
            let mut cookie = HH_COOKIE.lock();
            if *cookie > 0 {
                *cookie -= 1;
            }
            return UserHandle::NULL;
        }
        HH_DISPLAY_TOPIC | HH_SAFE_DISPLAY_TOPIC => {
            if show_help_topic(hwnd, file, 0) {
                return find_help_window(file);
            }
        }
        HH_DISPLAY_TOC => {
            if show_help_contents(hwnd, file) {
                return find_help_window(file);
            }
        }
        HH_DISPLAY_INDEX => {
            if show_help_index(hwnd, file) {
                return find_help_window(file);
            }
        }
        HH_DISPLAY_SEARCH => {
            if show_help_search(hwnd, file) {
                return find_help_window(file);
            }
        }
        HH_HELP_CONTEXT => {
            // data is context ID
            if show_help_topic(hwnd, file, data as u32) {
                return find_help_window(file);
            }
        }
        HH_DISPLAY_TEXT_POPUP => {
            // data points to HH_POPUP structure
            let _ = data;
            // Would display popup
        }
        HH_KEYWORD_LOOKUP => {
            // data points to HH_AKLINK structure
            let _ = data;
            // Would do keyword lookup
        }
        HH_CLOSE_ALL => {
            close_all_help();
        }
        HH_GET_WIN_HANDLE => {
            return find_help_window(file);
        }
        _ => {}
    }

    UserHandle::NULL
}

/// Show help topic
fn show_help_topic(hwnd: HWND, file: &[u8], context_id: u32) -> bool {
    let mut windows = HELP_WINDOWS.lock();

    // Find or create help window
    let window = find_or_create_help_window(&mut windows, hwnd, file);

    if let Some(win) = window {
        win.visible = true;
        // Set topic based on context ID
        let _ = context_id;
        return true;
    }

    false
}

/// Show help contents
fn show_help_contents(hwnd: HWND, file: &[u8]) -> bool {
    let mut windows = HELP_WINDOWS.lock();

    let window = find_or_create_help_window(&mut windows, hwnd, file);

    if let Some(win) = window {
        win.visible = true;
        // Navigate to contents
        let topic = b"contents";
        let len = topic.len().min(MAX_TOPIC - 1);
        win.topic[..len].copy_from_slice(&topic[..len]);
        win.topic[len] = 0;
        return true;
    }

    false
}

/// Show help index
fn show_help_index(hwnd: HWND, file: &[u8]) -> bool {
    let mut windows = HELP_WINDOWS.lock();

    let window = find_or_create_help_window(&mut windows, hwnd, file);

    if let Some(win) = window {
        win.visible = true;
        let topic = b"index";
        let len = topic.len().min(MAX_TOPIC - 1);
        win.topic[..len].copy_from_slice(&topic[..len]);
        win.topic[len] = 0;
        return true;
    }

    false
}

/// Show help search
fn show_help_search(hwnd: HWND, file: &[u8]) -> bool {
    let mut windows = HELP_WINDOWS.lock();

    let window = find_or_create_help_window(&mut windows, hwnd, file);

    if let Some(win) = window {
        win.visible = true;
        let topic = b"search";
        let len = topic.len().min(MAX_TOPIC - 1);
        win.topic[..len].copy_from_slice(&topic[..len]);
        win.topic[len] = 0;
        return true;
    }

    false
}

/// Find or create help window
fn find_or_create_help_window<'a>(
    windows: &'a mut [HelpWindow; MAX_HELP_WINDOWS],
    parent: HWND,
    file: &[u8],
) -> Option<&'a mut HelpWindow> {
    let file_len = super::strhelp::str_len(file);

    // Find existing or first free slot
    let mut existing_idx: Option<usize> = None;
    let mut free_idx: Option<usize> = None;

    for (i, win) in windows.iter().enumerate() {
        if win.in_use {
            let path_len = super::strhelp::str_len(&win.file_path);
            if file_len == path_len &&
               super::strhelp::str_cmp_ni(&win.file_path, file, file_len) == 0 {
                existing_idx = Some(i);
                break;
            }
        } else if free_idx.is_none() {
            free_idx = Some(i);
        }
    }

    // Return existing if found
    if let Some(idx) = existing_idx {
        return Some(&mut windows[idx]);
    }

    // Create new if free slot available
    if let Some(idx) = free_idx {
        let win = &mut windows[idx];
        win.in_use = true;
        win.parent_hwnd = parent;
        win.hwnd = UserHandle::NULL;

        let len = file_len.min(MAX_PATH - 1);
        win.file_path[..len].copy_from_slice(&file[..len]);
        win.file_path[len] = 0;

        win.file_type = detect_help_file_type(file);

        return Some(win);
    }

    None
}

/// Detect help file type from extension
fn detect_help_file_type(file: &[u8]) -> HelpFileType {
    let len = super::strhelp::str_len(file);
    if len < 4 {
        return HelpFileType::Unknown;
    }

    // Check extension
    let ext = &file[len.saturating_sub(4)..len];

    if super::strhelp::str_cmp_ni(ext, b".hlp", 4) == 0 {
        HelpFileType::WinHelp
    } else if super::strhelp::str_cmp_ni(ext, b".chm", 4) == 0 {
        HelpFileType::HtmlHelp
    } else {
        HelpFileType::Unknown
    }
}

/// Find help window by file
fn find_help_window(file: &[u8]) -> HWND {
    let windows = HELP_WINDOWS.lock();

    for win in windows.iter() {
        if win.in_use {
            let file_len = super::strhelp::str_len(file);
            let path_len = super::strhelp::str_len(&win.file_path);
            if file_len == path_len &&
               super::strhelp::str_cmp_ni(&win.file_path, file, file_len) == 0 {
                return win.hwnd;
            }
        }
    }

    UserHandle::NULL
}

/// Close help for window
fn close_help(hwnd: HWND, file: &[u8]) -> bool {
    let mut windows = HELP_WINDOWS.lock();

    for win in windows.iter_mut() {
        if win.in_use {
            let matches = if super::strhelp::str_len(file) == 0 {
                win.parent_hwnd == hwnd
            } else {
                let file_len = super::strhelp::str_len(file);
                let path_len = super::strhelp::str_len(&win.file_path);
                file_len == path_len &&
                    super::strhelp::str_cmp_ni(&win.file_path, file, file_len) == 0
            };

            if matches {
                *win = HelpWindow::new();
                return true;
            }
        }
    }

    false
}

/// Close all help windows
fn close_all_help() {
    let mut windows = HELP_WINDOWS.lock();

    for win in windows.iter_mut() {
        if win.in_use {
            *win = HelpWindow::new();
        }
    }
}

/// Register help context mapping
pub fn set_window_context_help_id(hwnd: HWND, help_id: u32) -> bool {
    let _ = hwnd;

    let mut map = CONTEXT_MAP.lock();

    for entry in map.iter_mut() {
        if !entry.in_use {
            entry.in_use = true;
            entry.control_id = 0; // Would use window handle
            entry.help_id = help_id;
            return true;
        }
    }

    false
}

/// Get help context for window
pub fn get_window_context_help_id(hwnd: HWND) -> u32 {
    let _ = hwnd;

    // Would look up context ID for window
    0
}

/// Show What's This help
pub fn show_whats_this_help(hwnd: HWND, pt: Point, context_id: u32) -> bool {
    let _ = (hwnd, pt, context_id);
    // Would display popup help at point
    true
}

/// Create What's This cursor
pub fn create_whats_this_cursor() -> usize {
    // Would return cursor handle
    1
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> HelpStats {
    let windows = HELP_WINDOWS.lock();
    let files = HELP_FILES.lock();
    let initialized = *HH_INITIALIZED.lock();

    let mut win_count = 0;
    let mut file_count = 0;
    let mut winhelp_count = 0;
    let mut htmlhelp_count = 0;

    for win in windows.iter() {
        if win.in_use {
            win_count += 1;
            match win.file_type {
                HelpFileType::WinHelp => winhelp_count += 1,
                HelpFileType::HtmlHelp => htmlhelp_count += 1,
                _ => {}
            }
        }
    }

    for file in files.iter() {
        if file.in_use {
            file_count += 1;
        }
    }

    HelpStats {
        max_windows: MAX_HELP_WINDOWS,
        active_windows: win_count,
        max_files: MAX_HELP_FILES,
        registered_files: file_count,
        winhelp_windows: winhelp_count,
        htmlhelp_windows: htmlhelp_count,
        htmlhelp_initialized: initialized,
    }
}

/// Help statistics
#[derive(Debug, Clone, Copy)]
pub struct HelpStats {
    pub max_windows: usize,
    pub active_windows: usize,
    pub max_files: usize,
    pub registered_files: usize,
    pub winhelp_windows: usize,
    pub htmlhelp_windows: usize,
    pub htmlhelp_initialized: bool,
}
