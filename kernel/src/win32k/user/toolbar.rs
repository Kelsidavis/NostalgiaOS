//! Toolbar Control - Windows Common Controls
//!
//! Implements the Toolbar control following the Windows Common Controls architecture.
//! Toolbars provide a row of buttons for quick access to commands.
//!
//! # Features
//!
//! - Standard and custom buttons with images/text
//! - Separator support for grouping
//! - Flat and 3D button styles
//! - Dropdown menus
//! - Tooltips integration
//! - Customization dialog
//!
//! # Window Class
//!
//! The toolbar control uses the "ToolbarWindow32" class name.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/commctrl.h` - Toolbar definitions
//! - Common Controls toolbar implementation

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Rect};

// ============================================================================
// Toolbar Styles (TBSTYLE_*)
// ============================================================================

/// Standard button
pub const TBSTYLE_BUTTON: u8 = 0x00;
/// Separator (gap between buttons)
pub const TBSTYLE_SEP: u8 = 0x01;
/// Check button (toggle)
pub const TBSTYLE_CHECK: u8 = 0x02;
/// Button is part of a group
pub const TBSTYLE_GROUP: u8 = 0x04;
/// Check group (radio button behavior)
pub const TBSTYLE_CHECKGROUP: u8 = TBSTYLE_GROUP | TBSTYLE_CHECK;
/// Dropdown button
pub const TBSTYLE_DROPDOWN: u8 = 0x08;
/// Auto-size button to fit text
pub const TBSTYLE_AUTOSIZE: u8 = 0x10;
/// Don't draw prefix underline
pub const TBSTYLE_NOPREFIX: u8 = 0x20;
/// Show text for this button
pub const TBSTYLE_SHOWTEXT: u8 = 0x40;
/// Whole dropdown (no split)
pub const TBSTYLE_WHOLEDROPDOWN: u8 = 0x80;

// ============================================================================
// Toolbar Window Styles (TBSTYLE_* for window)
// ============================================================================

/// Enable tooltips
pub const TBSTYLE_TOOLTIPS: u32 = 0x0100;
/// Wrap buttons when toolbar is too narrow
pub const TBSTYLE_WRAPABLE: u32 = 0x0200;
/// Allow drag to rearrange buttons
pub const TBSTYLE_ALTDRAG: u32 = 0x0400;
/// Flat buttons (no 3D border until hover)
pub const TBSTYLE_FLAT: u32 = 0x0800;
/// Text appears to the right of image
pub const TBSTYLE_LIST: u32 = 0x1000;
/// Send NM_CUSTOMDRAW for background
pub const TBSTYLE_CUSTOMERASE: u32 = 0x2000;
/// Allow drop-target registration
pub const TBSTYLE_REGISTERDROP: u32 = 0x4000;
/// Transparent background
pub const TBSTYLE_TRANSPARENT: u32 = 0x8000;

// ============================================================================
// Extended Toolbar Styles (TBSTYLE_EX_*)
// ============================================================================

/// Draw dropdown arrows
pub const TBSTYLE_EX_DRAWDDARROWS: u32 = 0x00000001;
/// Mix text and image buttons
pub const TBSTYLE_EX_MIXEDBUTTONS: u32 = 0x00000008;
/// Hide clipped buttons
pub const TBSTYLE_EX_HIDECLIPPEDBUTTONS: u32 = 0x00000010;
/// Double buffer the toolbar
pub const TBSTYLE_EX_DOUBLEBUFFER: u32 = 0x00000080;

// ============================================================================
// Toolbar Button States (TBSTATE_*)
// ============================================================================

/// Button is checked
pub const TBSTATE_CHECKED: u8 = 0x01;
/// Button is pressed
pub const TBSTATE_PRESSED: u8 = 0x02;
/// Button is enabled
pub const TBSTATE_ENABLED: u8 = 0x04;
/// Button is hidden
pub const TBSTATE_HIDDEN: u8 = 0x08;
/// Button is in indeterminate state
pub const TBSTATE_INDETERMINATE: u8 = 0x10;
/// Button causes wrap to next row
pub const TBSTATE_WRAP: u8 = 0x20;
/// Text is truncated with ellipses
pub const TBSTATE_ELLIPSES: u8 = 0x40;
/// Button is marked (highlighted)
pub const TBSTATE_MARKED: u8 = 0x80;

// ============================================================================
// Toolbar Messages (TB_*)
// ============================================================================

/// WM_USER base for toolbar messages
const WM_USER: u32 = 0x0400;

/// Enable/disable a button
pub const TB_ENABLEBUTTON: u32 = WM_USER + 1;
/// Check/uncheck a button
pub const TB_CHECKBUTTON: u32 = WM_USER + 2;
/// Press/release a button
pub const TB_PRESSBUTTON: u32 = WM_USER + 3;
/// Hide/show a button
pub const TB_HIDEBUTTON: u32 = WM_USER + 4;
/// Set button indeterminate state
pub const TB_INDETERMINATE: u32 = WM_USER + 5;
/// Mark/unmark a button
pub const TB_MARKBUTTON: u32 = WM_USER + 6;
/// Check if button is enabled
pub const TB_ISBUTTONENABLED: u32 = WM_USER + 9;
/// Check if button is checked
pub const TB_ISBUTTONCHECKED: u32 = WM_USER + 10;
/// Check if button is pressed
pub const TB_ISBUTTONPRESSED: u32 = WM_USER + 11;
/// Check if button is hidden
pub const TB_ISBUTTONHIDDEN: u32 = WM_USER + 12;
/// Check if button is indeterminate
pub const TB_ISBUTTONINDETERMINATE: u32 = WM_USER + 13;
/// Check if button is highlighted
pub const TB_ISBUTTONHIGHLIGHTED: u32 = WM_USER + 14;
/// Set button state
pub const TB_SETSTATE: u32 = WM_USER + 17;
/// Get button state
pub const TB_GETSTATE: u32 = WM_USER + 18;
/// Add a bitmap to the image list
pub const TB_ADDBITMAP: u32 = WM_USER + 19;
/// Add buttons to the toolbar
pub const TB_ADDBUTTONS: u32 = WM_USER + 20;
/// Insert a button
pub const TB_INSERTBUTTON: u32 = WM_USER + 21;
/// Delete a button
pub const TB_DELETEBUTTON: u32 = WM_USER + 22;
/// Get button info
pub const TB_GETBUTTON: u32 = WM_USER + 23;
/// Get button count
pub const TB_BUTTONCOUNT: u32 = WM_USER + 24;
/// Command ID to button index
pub const TB_COMMANDTOINDEX: u32 = WM_USER + 25;
/// Save/restore toolbar state
pub const TB_SAVERESTOREA: u32 = WM_USER + 26;
/// Add string to string pool
pub const TB_ADDSTRINGA: u32 = WM_USER + 28;
/// Get item rectangle
pub const TB_GETITEMRECT: u32 = WM_USER + 29;
/// Set button size
pub const TB_BUTTONSTRUCTSIZE: u32 = WM_USER + 30;
/// Set button size
pub const TB_SETBUTTONSIZE: u32 = WM_USER + 31;
/// Set bitmap size
pub const TB_SETBITMAPSIZE: u32 = WM_USER + 32;
/// Auto-size the toolbar
pub const TB_AUTOSIZE: u32 = WM_USER + 33;
/// Get tooltip control
pub const TB_GETTOOLTIPS: u32 = WM_USER + 35;
/// Set tooltip control
pub const TB_SETTOOLTIPS: u32 = WM_USER + 36;
/// Set parent window for notifications
pub const TB_SETPARENT: u32 = WM_USER + 37;
/// Set number of button rows
pub const TB_SETROWS: u32 = WM_USER + 39;
/// Get number of button rows
pub const TB_GETROWS: u32 = WM_USER + 40;
/// Get button text
pub const TB_GETBITMAPFLAGS: u32 = WM_USER + 41;
/// Set command ID for a button
pub const TB_SETCMDID: u32 = WM_USER + 42;
/// Change a button's bitmap
pub const TB_CHANGEBITMAP: u32 = WM_USER + 43;
/// Get button's bitmap index
pub const TB_GETBITMAP: u32 = WM_USER + 44;
/// Get button text
pub const TB_GETBUTTONTEXTA: u32 = WM_USER + 45;
/// Replace bitmap
pub const TB_REPLACEBITMAP: u32 = WM_USER + 46;
/// Set indent
pub const TB_SETINDENT: u32 = WM_USER + 47;
/// Set image list
pub const TB_SETIMAGELIST: u32 = WM_USER + 48;
/// Get image list
pub const TB_GETIMAGELIST: u32 = WM_USER + 49;
/// Load images from resources
pub const TB_LOADIMAGES: u32 = WM_USER + 50;
/// Get toolbar rect
pub const TB_GETRECT: u32 = WM_USER + 51;
/// Set hot image list
pub const TB_SETHOTIMAGELIST: u32 = WM_USER + 52;
/// Get hot image list
pub const TB_GETHOTIMAGELIST: u32 = WM_USER + 53;
/// Set disabled image list
pub const TB_SETDISABLEDIMAGELIST: u32 = WM_USER + 54;
/// Get disabled image list
pub const TB_GETDISABLEDIMAGELIST: u32 = WM_USER + 55;
/// Set toolbar style
pub const TB_SETSTYLE: u32 = WM_USER + 56;
/// Get toolbar style
pub const TB_GETSTYLE: u32 = WM_USER + 57;
/// Get button size
pub const TB_GETBUTTONSIZE: u32 = WM_USER + 58;
/// Set button width range
pub const TB_SETBUTTONWIDTH: u32 = WM_USER + 59;
/// Set max text rows
pub const TB_SETMAXTEXTROWS: u32 = WM_USER + 60;
/// Get text rows
pub const TB_GETTEXTROWS: u32 = WM_USER + 61;
/// Set extended style
pub const TB_SETEXTENDEDSTYLE: u32 = WM_USER + 84;
/// Get extended style
pub const TB_GETEXTENDEDSTYLE: u32 = WM_USER + 85;
/// Set button padding
pub const TB_SETPADDING: u32 = WM_USER + 87;
/// Get button padding
pub const TB_GETPADDING: u32 = WM_USER + 88;
/// Get string
pub const TB_GETSTRINGA: u32 = WM_USER + 92;
/// Get string (Unicode)
pub const TB_GETSTRINGW: u32 = WM_USER + 91;

// ============================================================================
// Toolbar Notifications (TBN_*)
// ============================================================================

/// First toolbar notification
pub const TBN_FIRST: i32 = -700;
/// Toolbar query for tooltip info
pub const TBN_GETBUTTONINFOA: i32 = TBN_FIRST - 0;
/// Begin dragging button
pub const TBN_BEGINDRAG: i32 = TBN_FIRST - 1;
/// End dragging button
pub const TBN_ENDDRAG: i32 = TBN_FIRST - 2;
/// Begin adjust dialog
pub const TBN_BEGINADJUST: i32 = TBN_FIRST - 3;
/// End adjust dialog
pub const TBN_ENDADJUST: i32 = TBN_FIRST - 4;
/// Reset toolbar to default
pub const TBN_RESET: i32 = TBN_FIRST - 5;
/// Query insert button
pub const TBN_QUERYINSERT: i32 = TBN_FIRST - 6;
/// Query delete button
pub const TBN_QUERYDELETE: i32 = TBN_FIRST - 7;
/// Show customize dialog
pub const TBN_TOOLBARCHANGE: i32 = TBN_FIRST - 8;
/// Custom help requested
pub const TBN_CUSTHELP: i32 = TBN_FIRST - 9;
/// Dropdown button clicked
pub const TBN_DROPDOWN: i32 = TBN_FIRST - 10;
/// Toolbar hot item changed
pub const TBN_HOTITEMCHANGE: i32 = TBN_FIRST - 13;

// ============================================================================
// Standard Bitmap IDs
// ============================================================================

/// Standard small color bitmaps
pub const IDB_STD_SMALL_COLOR: u32 = 0;
/// Standard large color bitmaps
pub const IDB_STD_LARGE_COLOR: u32 = 1;
/// View small color bitmaps
pub const IDB_VIEW_SMALL_COLOR: u32 = 4;
/// View large color bitmaps
pub const IDB_VIEW_LARGE_COLOR: u32 = 5;
/// History small color bitmaps
pub const IDB_HIST_SMALL_COLOR: u32 = 8;
/// History large color bitmaps
pub const IDB_HIST_LARGE_COLOR: u32 = 9;

// ============================================================================
// Standard Button IDs
// ============================================================================

/// Cut
pub const STD_CUT: u32 = 0;
/// Copy
pub const STD_COPY: u32 = 1;
/// Paste
pub const STD_PASTE: u32 = 2;
/// Undo
pub const STD_UNDO: u32 = 3;
/// Redo
pub const STD_REDO: u32 = 4;
/// Delete
pub const STD_DELETE: u32 = 5;
/// New file
pub const STD_FILENEW: u32 = 6;
/// Open file
pub const STD_FILEOPEN: u32 = 7;
/// Save file
pub const STD_FILESAVE: u32 = 8;
/// Print preview
pub const STD_PRINTPRE: u32 = 9;
/// Properties
pub const STD_PROPERTIES: u32 = 10;
/// Help
pub const STD_HELP: u32 = 11;
/// Find
pub const STD_FIND: u32 = 12;
/// Replace
pub const STD_REPLACE: u32 = 13;
/// Print
pub const STD_PRINT: u32 = 14;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum toolbar controls
const MAX_TOOLBARS: usize = 64;

/// Maximum buttons per toolbar
const MAX_BUTTONS: usize = 64;

/// Maximum button text length
const MAX_BUTTON_TEXT: usize = 64;

/// Default button width
const DEFAULT_BUTTON_WIDTH: i32 = 24;

/// Default button height
const DEFAULT_BUTTON_HEIGHT: i32 = 22;

/// Default bitmap width
const DEFAULT_BITMAP_WIDTH: i32 = 16;

/// Default bitmap height
const DEFAULT_BITMAP_HEIGHT: i32 = 15;

/// Default separator width
const DEFAULT_SEPARATOR_WIDTH: i32 = 8;

// ============================================================================
// Structures
// ============================================================================

/// Toolbar button structure (TBBUTTON)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ToolbarButton {
    /// Bitmap index
    pub bitmap_index: i32,
    /// Command ID
    pub command_id: i32,
    /// Button state (TBSTATE_*)
    pub state: u8,
    /// Button style (TBSTYLE_*)
    pub style: u8,
    /// Reserved padding
    pub reserved: [u8; 2],
    /// Application-defined data
    pub data: usize,
    /// String index or pointer
    pub string_index: isize,
}

impl ToolbarButton {
    /// Create a new standard button
    pub const fn new(bitmap_index: i32, command_id: i32) -> Self {
        Self {
            bitmap_index,
            command_id,
            state: TBSTATE_ENABLED,
            style: TBSTYLE_BUTTON,
            reserved: [0; 2],
            data: 0,
            string_index: 0,
        }
    }

    /// Create a separator
    pub const fn separator() -> Self {
        Self {
            bitmap_index: 0,
            command_id: 0,
            state: 0,
            style: TBSTYLE_SEP,
            reserved: [0; 2],
            data: 0,
            string_index: 0,
        }
    }
}

impl Default for ToolbarButton {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Internal button data
#[derive(Clone, Copy)]
struct ButtonData {
    /// Button in use
    in_use: bool,
    /// Button definition
    button: ToolbarButton,
    /// Calculated X position
    x: i32,
    /// Calculated Y position
    y: i32,
    /// Calculated width
    width: i32,
    /// Calculated height
    height: i32,
    /// Button text
    text: [u8; MAX_BUTTON_TEXT],
    /// Text length
    text_len: usize,
    /// Is hot (hovered)
    hot: bool,
}

impl ButtonData {
    const fn new() -> Self {
        Self {
            in_use: false,
            button: ToolbarButton::new(0, 0),
            x: 0,
            y: 0,
            width: DEFAULT_BUTTON_WIDTH,
            height: DEFAULT_BUTTON_HEIGHT,
            text: [0; MAX_BUTTON_TEXT],
            text_len: 0,
            hot: false,
        }
    }
}

/// Toolbar control state
#[derive(Clone, Copy)]
struct ToolbarControl {
    /// Control in use
    in_use: bool,
    /// Window handle
    hwnd: HWND,
    /// Toolbar style
    style: u32,
    /// Extended style
    ex_style: u32,
    /// Button width
    button_width: i32,
    /// Button height
    button_height: i32,
    /// Bitmap width
    bitmap_width: i32,
    /// Bitmap height
    bitmap_height: i32,
    /// Number of buttons
    button_count: usize,
    /// Button data
    buttons: [ButtonData; MAX_BUTTONS],
    /// Indent (left margin)
    indent: i32,
    /// Number of rows
    rows: i32,
    /// Hot button index (-1 for none)
    hot_item: i32,
    /// Pressed button index (-1 for none)
    pressed_item: i32,
    /// Padding between buttons
    padding_x: i32,
    /// Vertical padding
    padding_y: i32,
    /// Max text rows
    max_text_rows: i32,
}

impl ToolbarControl {
    const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle(0),
            style: 0,
            ex_style: 0,
            button_width: DEFAULT_BUTTON_WIDTH,
            button_height: DEFAULT_BUTTON_HEIGHT,
            bitmap_width: DEFAULT_BITMAP_WIDTH,
            bitmap_height: DEFAULT_BITMAP_HEIGHT,
            button_count: 0,
            buttons: [const { ButtonData::new() }; MAX_BUTTONS],
            indent: 0,
            rows: 1,
            hot_item: -1,
            pressed_item: -1,
            padding_x: 0,
            padding_y: 0,
            max_text_rows: 1,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Toolbar subsystem initialized
static TOOLBAR_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Toolbar lock
static TOOLBAR_LOCK: SpinLock<()> = SpinLock::new(());

/// All toolbar controls
static TOOLBARS: SpinLock<[ToolbarControl; MAX_TOOLBARS]> =
    SpinLock::new([const { ToolbarControl::new() }; MAX_TOOLBARS]);

/// Toolbar count
static TOOLBAR_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize toolbar subsystem
pub fn init() {
    let _guard = TOOLBAR_LOCK.lock();

    if TOOLBAR_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[TOOLBAR] Initializing Toolbar Control...");

    TOOLBAR_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[TOOLBAR] Toolbar Control initialized");
}

// ============================================================================
// Toolbar Creation and Deletion
// ============================================================================

/// Create a toolbar control
///
/// # Arguments
/// * `hwnd` - Window handle for the toolbar
/// * `style` - Toolbar style flags
///
/// # Returns
/// true if created successfully
pub fn create_toolbar(hwnd: HWND, style: u32) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut toolbars = TOOLBARS.lock();

    // Check if already exists
    for tb in toolbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return false;
        }
    }

    // Find free slot
    for tb in toolbars.iter_mut() {
        if !tb.in_use {
            tb.in_use = true;
            tb.hwnd = hwnd;
            tb.style = style;
            tb.ex_style = 0;
            tb.button_width = DEFAULT_BUTTON_WIDTH;
            tb.button_height = DEFAULT_BUTTON_HEIGHT;
            tb.bitmap_width = DEFAULT_BITMAP_WIDTH;
            tb.bitmap_height = DEFAULT_BITMAP_HEIGHT;
            tb.button_count = 0;
            tb.indent = 0;
            tb.rows = 1;
            tb.hot_item = -1;
            tb.pressed_item = -1;

            TOOLBAR_COUNT.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }

    false
}

/// Destroy a toolbar control
///
/// # Arguments
/// * `hwnd` - Window handle
///
/// # Returns
/// true if destroyed
pub fn destroy_toolbar(hwnd: HWND) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut toolbars = TOOLBARS.lock();

    for tb in toolbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            tb.in_use = false;
            TOOLBAR_COUNT.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }

    false
}

// ============================================================================
// Button Management
// ============================================================================

/// Add buttons to a toolbar
///
/// # Arguments
/// * `hwnd` - Toolbar window handle
/// * `buttons` - Array of button definitions
///
/// # Returns
/// Number of buttons added
pub fn add_buttons(hwnd: HWND, buttons: &[ToolbarButton]) -> usize {
    if hwnd.0 == 0 || buttons.is_empty() {
        return 0;
    }

    let mut toolbars = TOOLBARS.lock();

    for tb in toolbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            let mut added = 0;

            for btn in buttons {
                if tb.button_count >= MAX_BUTTONS {
                    break;
                }

                let idx = tb.button_count;
                tb.buttons[idx].in_use = true;
                tb.buttons[idx].button = *btn;
                tb.buttons[idx].hot = false;
                tb.button_count += 1;
                added += 1;
            }

            // Recalculate layout
            recalculate_layout(tb);

            return added;
        }
    }

    0
}

/// Insert a button at a specific index
///
/// # Arguments
/// * `hwnd` - Toolbar window handle
/// * `index` - Position to insert at
/// * `button` - Button to insert
///
/// # Returns
/// true if inserted
pub fn insert_button(hwnd: HWND, index: usize, button: &ToolbarButton) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut toolbars = TOOLBARS.lock();

    for tb in toolbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            if tb.button_count >= MAX_BUTTONS {
                return false;
            }

            let insert_idx = index.min(tb.button_count);

            // Shift buttons
            for i in (insert_idx..tb.button_count).rev() {
                tb.buttons[i + 1] = tb.buttons[i];
            }

            tb.buttons[insert_idx].in_use = true;
            tb.buttons[insert_idx].button = *button;
            tb.buttons[insert_idx].hot = false;
            tb.button_count += 1;

            recalculate_layout(tb);
            return true;
        }
    }

    false
}

/// Delete a button
///
/// # Arguments
/// * `hwnd` - Toolbar window handle
/// * `index` - Button index to delete
///
/// # Returns
/// true if deleted
pub fn delete_button(hwnd: HWND, index: usize) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut toolbars = TOOLBARS.lock();

    for tb in toolbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            if index >= tb.button_count {
                return false;
            }

            // Shift buttons
            for i in index..(tb.button_count - 1) {
                tb.buttons[i] = tb.buttons[i + 1];
            }

            tb.buttons[tb.button_count - 1].in_use = false;
            tb.button_count -= 1;

            recalculate_layout(tb);
            return true;
        }
    }

    false
}

/// Get button count
pub fn get_button_count(hwnd: HWND) -> usize {
    if hwnd.0 == 0 {
        return 0;
    }

    let toolbars = TOOLBARS.lock();

    for tb in toolbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return tb.button_count;
        }
    }

    0
}

/// Get button at index
pub fn get_button(hwnd: HWND, index: usize) -> Option<ToolbarButton> {
    if hwnd.0 == 0 {
        return None;
    }

    let toolbars = TOOLBARS.lock();

    for tb in toolbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            if index < tb.button_count {
                return Some(tb.buttons[index].button);
            }
        }
    }

    None
}

// ============================================================================
// Button State
// ============================================================================

/// Get button state
pub fn get_button_state(hwnd: HWND, command_id: i32) -> Option<u8> {
    if hwnd.0 == 0 {
        return None;
    }

    let toolbars = TOOLBARS.lock();

    for tb in toolbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            for i in 0..tb.button_count {
                if tb.buttons[i].button.command_id == command_id {
                    return Some(tb.buttons[i].button.state);
                }
            }
        }
    }

    None
}

/// Set button state
pub fn set_button_state(hwnd: HWND, command_id: i32, state: u8) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut toolbars = TOOLBARS.lock();

    for tb in toolbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            for i in 0..tb.button_count {
                if tb.buttons[i].button.command_id == command_id {
                    tb.buttons[i].button.state = state;
                    return true;
                }
            }
        }
    }

    false
}

/// Enable or disable a button
pub fn enable_button(hwnd: HWND, command_id: i32, enable: bool) -> bool {
    if let Some(state) = get_button_state(hwnd, command_id) {
        let new_state = if enable {
            state | TBSTATE_ENABLED
        } else {
            state & !TBSTATE_ENABLED
        };
        return set_button_state(hwnd, command_id, new_state);
    }
    false
}

/// Check or uncheck a button
pub fn check_button(hwnd: HWND, command_id: i32, check: bool) -> bool {
    if let Some(state) = get_button_state(hwnd, command_id) {
        let new_state = if check {
            state | TBSTATE_CHECKED
        } else {
            state & !TBSTATE_CHECKED
        };
        return set_button_state(hwnd, command_id, new_state);
    }
    false
}

/// Press or release a button
pub fn press_button(hwnd: HWND, command_id: i32, press: bool) -> bool {
    if let Some(state) = get_button_state(hwnd, command_id) {
        let new_state = if press {
            state | TBSTATE_PRESSED
        } else {
            state & !TBSTATE_PRESSED
        };
        return set_button_state(hwnd, command_id, new_state);
    }
    false
}

/// Hide or show a button
pub fn hide_button(hwnd: HWND, command_id: i32, hide: bool) -> bool {
    if let Some(state) = get_button_state(hwnd, command_id) {
        let new_state = if hide {
            state | TBSTATE_HIDDEN
        } else {
            state & !TBSTATE_HIDDEN
        };
        let result = set_button_state(hwnd, command_id, new_state);

        // Recalculate layout when hiding/showing
        let mut toolbars = TOOLBARS.lock();
        for tb in toolbars.iter_mut() {
            if tb.in_use && tb.hwnd == hwnd {
                recalculate_layout(tb);
                break;
            }
        }

        return result;
    }
    false
}

/// Check if button is enabled
pub fn is_button_enabled(hwnd: HWND, command_id: i32) -> bool {
    get_button_state(hwnd, command_id)
        .map(|s| (s & TBSTATE_ENABLED) != 0)
        .unwrap_or(false)
}

/// Check if button is checked
pub fn is_button_checked(hwnd: HWND, command_id: i32) -> bool {
    get_button_state(hwnd, command_id)
        .map(|s| (s & TBSTATE_CHECKED) != 0)
        .unwrap_or(false)
}

/// Check if button is pressed
pub fn is_button_pressed(hwnd: HWND, command_id: i32) -> bool {
    get_button_state(hwnd, command_id)
        .map(|s| (s & TBSTATE_PRESSED) != 0)
        .unwrap_or(false)
}

/// Check if button is hidden
pub fn is_button_hidden(hwnd: HWND, command_id: i32) -> bool {
    get_button_state(hwnd, command_id)
        .map(|s| (s & TBSTATE_HIDDEN) != 0)
        .unwrap_or(false)
}

// ============================================================================
// Toolbar Configuration
// ============================================================================

/// Set button size
pub fn set_button_size(hwnd: HWND, width: i32, height: i32) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut toolbars = TOOLBARS.lock();

    for tb in toolbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            tb.button_width = width.max(1);
            tb.button_height = height.max(1);
            recalculate_layout(tb);
            return true;
        }
    }

    false
}

/// Get button size
pub fn get_button_size(hwnd: HWND) -> Option<(i32, i32)> {
    if hwnd.0 == 0 {
        return None;
    }

    let toolbars = TOOLBARS.lock();

    for tb in toolbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return Some((tb.button_width, tb.button_height));
        }
    }

    None
}

/// Set bitmap size
pub fn set_bitmap_size(hwnd: HWND, width: i32, height: i32) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut toolbars = TOOLBARS.lock();

    for tb in toolbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            tb.bitmap_width = width.max(1);
            tb.bitmap_height = height.max(1);
            return true;
        }
    }

    false
}

/// Set toolbar indent
pub fn set_indent(hwnd: HWND, indent: i32) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut toolbars = TOOLBARS.lock();

    for tb in toolbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            tb.indent = indent.max(0);
            recalculate_layout(tb);
            return true;
        }
    }

    false
}

/// Set extended style
pub fn set_extended_style(hwnd: HWND, style: u32) -> u32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let mut toolbars = TOOLBARS.lock();

    for tb in toolbars.iter_mut() {
        if tb.in_use && tb.hwnd == hwnd {
            let old = tb.ex_style;
            tb.ex_style = style;
            return old;
        }
    }

    0
}

/// Get extended style
pub fn get_extended_style(hwnd: HWND) -> u32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let toolbars = TOOLBARS.lock();

    for tb in toolbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            return tb.ex_style;
        }
    }

    0
}

// ============================================================================
// Layout
// ============================================================================

/// Recalculate button positions
fn recalculate_layout(tb: &mut ToolbarControl) {
    let mut x = tb.indent;
    let mut y = 0;
    let mut row = 0;

    for i in 0..tb.button_count {
        if !tb.buttons[i].in_use {
            continue;
        }

        // Skip hidden buttons
        if (tb.buttons[i].button.state & TBSTATE_HIDDEN) != 0 {
            tb.buttons[i].x = -1;
            tb.buttons[i].y = -1;
            continue;
        }

        // Handle separator
        if tb.buttons[i].button.style == TBSTYLE_SEP {
            tb.buttons[i].x = x;
            tb.buttons[i].y = y;
            tb.buttons[i].width = DEFAULT_SEPARATOR_WIDTH;
            tb.buttons[i].height = tb.button_height;
            x += DEFAULT_SEPARATOR_WIDTH;
            continue;
        }

        // Handle wrap
        if (tb.buttons[i].button.state & TBSTATE_WRAP) != 0 && row < tb.rows - 1 {
            row += 1;
            x = tb.indent;
            y += tb.button_height + tb.padding_y;
        }

        tb.buttons[i].x = x;
        tb.buttons[i].y = y;
        tb.buttons[i].width = tb.button_width;
        tb.buttons[i].height = tb.button_height;

        x += tb.button_width + tb.padding_x;
    }
}

/// Get item rectangle
pub fn get_item_rect(hwnd: HWND, index: usize) -> Option<Rect> {
    if hwnd.0 == 0 {
        return None;
    }

    let toolbars = TOOLBARS.lock();

    for tb in toolbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            if index < tb.button_count {
                let btn = &tb.buttons[index];
                return Some(Rect {
                    left: btn.x,
                    top: btn.y,
                    right: btn.x + btn.width,
                    bottom: btn.y + btn.height,
                });
            }
        }
    }

    None
}

/// Auto-size the toolbar
pub fn autosize(hwnd: HWND) {
    // In a real implementation, this would resize the toolbar
    // to fit its parent window width
    let _ = hwnd;
}

/// Command ID to button index
pub fn command_to_index(hwnd: HWND, command_id: i32) -> i32 {
    if hwnd.0 == 0 {
        return -1;
    }

    let toolbars = TOOLBARS.lock();

    for tb in toolbars.iter() {
        if tb.in_use && tb.hwnd == hwnd {
            for i in 0..tb.button_count {
                if tb.buttons[i].button.command_id == command_id {
                    return i as i32;
                }
            }
        }
    }

    -1
}

// ============================================================================
// Message Handler
// ============================================================================

/// Process toolbar message
///
/// # Returns
/// (handled, result)
pub fn process_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> (bool, isize) {
    match msg {
        TB_BUTTONCOUNT => {
            (true, get_button_count(hwnd) as isize)
        }
        TB_GETSTATE => {
            let state = get_button_state(hwnd, wparam as i32).unwrap_or(0);
            (true, state as isize)
        }
        TB_SETSTATE => {
            let cmd_id = lparam as i32 & 0xFFFF;
            let state = (lparam >> 16) as u8;
            (true, set_button_state(hwnd, cmd_id, state) as isize)
        }
        TB_ENABLEBUTTON => {
            let enable = lparam != 0;
            (true, enable_button(hwnd, wparam as i32, enable) as isize)
        }
        TB_CHECKBUTTON => {
            let check = lparam != 0;
            (true, check_button(hwnd, wparam as i32, check) as isize)
        }
        TB_PRESSBUTTON => {
            let press = lparam != 0;
            (true, press_button(hwnd, wparam as i32, press) as isize)
        }
        TB_HIDEBUTTON => {
            let hide = lparam != 0;
            (true, hide_button(hwnd, wparam as i32, hide) as isize)
        }
        TB_ISBUTTONENABLED => {
            (true, is_button_enabled(hwnd, wparam as i32) as isize)
        }
        TB_ISBUTTONCHECKED => {
            (true, is_button_checked(hwnd, wparam as i32) as isize)
        }
        TB_ISBUTTONPRESSED => {
            (true, is_button_pressed(hwnd, wparam as i32) as isize)
        }
        TB_ISBUTTONHIDDEN => {
            (true, is_button_hidden(hwnd, wparam as i32) as isize)
        }
        TB_COMMANDTOINDEX => {
            (true, command_to_index(hwnd, wparam as i32) as isize)
        }
        TB_DELETEBUTTON => {
            (true, delete_button(hwnd, wparam) as isize)
        }
        TB_SETBUTTONSIZE => {
            let cx = (lparam & 0xFFFF) as i32;
            let cy = ((lparam >> 16) & 0xFFFF) as i32;
            (true, set_button_size(hwnd, cx, cy) as isize)
        }
        TB_GETBUTTONSIZE => {
            if let Some((w, h)) = get_button_size(hwnd) {
                (true, ((h as isize) << 16) | (w as isize & 0xFFFF))
            } else {
                (true, 0)
            }
        }
        TB_SETBITMAPSIZE => {
            let cx = (lparam & 0xFFFF) as i32;
            let cy = ((lparam >> 16) & 0xFFFF) as i32;
            (true, set_bitmap_size(hwnd, cx, cy) as isize)
        }
        TB_SETINDENT => {
            (true, set_indent(hwnd, wparam as i32) as isize)
        }
        TB_SETEXTENDEDSTYLE => {
            (true, set_extended_style(hwnd, lparam as u32) as isize)
        }
        TB_GETEXTENDEDSTYLE => {
            (true, get_extended_style(hwnd) as isize)
        }
        TB_AUTOSIZE => {
            autosize(hwnd);
            (true, 0)
        }
        _ => (false, 0),
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Get number of toolbar controls
pub fn get_toolbar_count() -> u32 {
    TOOLBAR_COUNT.load(Ordering::Relaxed)
}
