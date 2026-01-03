//! Common Dialogs Implementation
//!
//! Windows common dialog boxes (File Open/Save, Font, Color, Print).
//! Based on Windows Server 2003 commdlg.h.
//!
//! # Features
//!
//! - File Open/Save dialogs
//! - Font selection dialog
//! - Color picker dialog
//! - Print dialog
//! - Find/Replace dialog
//!
//! # References
//!
//! - `public/sdk/inc/commdlg.h` - Common dialog structures

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, ColorRef};

// ============================================================================
// Open/Save File Dialog Flags (OFN_*)
// ============================================================================

/// Allow read-only selection
pub const OFN_READONLY: u32 = 0x00000001;

/// Overwrite prompt
pub const OFN_OVERWRITEPROMPT: u32 = 0x00000002;

/// Hide read-only checkbox
pub const OFN_HIDEREADONLY: u32 = 0x00000004;

/// No change dir
pub const OFN_NOCHANGEDIR: u32 = 0x00000008;

/// Show help button
pub const OFN_SHOWHELP: u32 = 0x00000010;

/// Enable hook
pub const OFN_ENABLEHOOK: u32 = 0x00000020;

/// Enable template
pub const OFN_ENABLETEMPLATE: u32 = 0x00000040;

/// Enable template handle
pub const OFN_ENABLETEMPLATEHANDLE: u32 = 0x00000080;

/// No validate
pub const OFN_NOVALIDATE: u32 = 0x00000100;

/// Allow multi-select
pub const OFN_ALLOWMULTISELECT: u32 = 0x00000200;

/// Extend different extension
pub const OFN_EXTENSIONDIFFERENT: u32 = 0x00000400;

/// Path must exist
pub const OFN_PATHMUSTEXIST: u32 = 0x00000800;

/// File must exist
pub const OFN_FILEMUSTEXIST: u32 = 0x00001000;

/// Create prompt
pub const OFN_CREATEPROMPT: u32 = 0x00002000;

/// Share aware
pub const OFN_SHAREAWARE: u32 = 0x00004000;

/// No read-only return
pub const OFN_NOREADONLYRETURN: u32 = 0x00008000;

/// No test file create
pub const OFN_NOTESTFILECREATE: u32 = 0x00010000;

/// No network button
pub const OFN_NONETWORKBUTTON: u32 = 0x00020000;

/// No long names
pub const OFN_NOLONGNAMES: u32 = 0x00040000;

/// Explorer style
pub const OFN_EXPLORER: u32 = 0x00080000;

/// No dereference links
pub const OFN_NODEREFERENCELINKS: u32 = 0x00100000;

/// Long names
pub const OFN_LONGNAMES: u32 = 0x00200000;

/// Enable include notify
pub const OFN_ENABLEINCLUDENOTIFY: u32 = 0x00400000;

/// Enable sizing
pub const OFN_ENABLESIZING: u32 = 0x00800000;

/// Don't add to recent
pub const OFN_DONTADDTORECENT: u32 = 0x02000000;

/// Force show hidden
pub const OFN_FORCESHOWHIDDEN: u32 = 0x10000000;

// ============================================================================
// Color Dialog Flags (CC_*)
// ============================================================================

/// RGB init
pub const CC_RGBINIT: u32 = 0x00000001;

/// Full open
pub const CC_FULLOPEN: u32 = 0x00000002;

/// Prevent full open
pub const CC_PREVENTFULLOPEN: u32 = 0x00000004;

/// Show help
pub const CC_SHOWHELP: u32 = 0x00000008;

/// Enable hook
pub const CC_ENABLEHOOK: u32 = 0x00000010;

/// Enable template
pub const CC_ENABLETEMPLATE: u32 = 0x00000020;

/// Enable template handle
pub const CC_ENABLETEMPLATEHANDLE: u32 = 0x00000040;

/// Solid color
pub const CC_SOLIDCOLOR: u32 = 0x00000080;

/// Any color
pub const CC_ANYCOLOR: u32 = 0x00000100;

// ============================================================================
// Font Dialog Flags (CF_*)
// ============================================================================

/// Screen fonts
pub const CF_SCREENFONTS: u32 = 0x00000001;

/// Printer fonts
pub const CF_PRINTERFONTS: u32 = 0x00000002;

/// Both fonts
pub const CF_BOTH: u32 = CF_SCREENFONTS | CF_PRINTERFONTS;

/// Show help
pub const CF_SHOWHELP: u32 = 0x00000004;

/// Enable hook
pub const CF_ENABLEHOOK: u32 = 0x00000008;

/// Enable template
pub const CF_ENABLETEMPLATE: u32 = 0x00000010;

/// Enable template handle
pub const CF_ENABLETEMPLATEHANDLE: u32 = 0x00000020;

/// Init to logfont
pub const CF_INITTOLOGFONTSTRUCT: u32 = 0x00000040;

/// Use style
pub const CF_USESTYLE: u32 = 0x00000080;

/// Effects
pub const CF_EFFECTS: u32 = 0x00000100;

/// Apply
pub const CF_APPLY: u32 = 0x00000200;

/// ANSI only
pub const CF_ANSIONLY: u32 = 0x00000400;

/// Scripts only
pub const CF_SCRIPTSONLY: u32 = CF_ANSIONLY;

/// No vector fonts
pub const CF_NOVECTORFONTS: u32 = 0x00000800;

/// No simulations
pub const CF_NOSIMULATIONS: u32 = 0x00001000;

/// Limit size
pub const CF_LIMITSIZE: u32 = 0x00002000;

/// Fixed pitch only
pub const CF_FIXEDPITCHONLY: u32 = 0x00004000;

/// WYSIWYG
pub const CF_WYSIWYG: u32 = 0x00008000;

/// Force font exist
pub const CF_FORCEFONTEXIST: u32 = 0x00010000;

/// Scalable only
pub const CF_SCALABLEONLY: u32 = 0x00020000;

/// TrueType only
pub const CF_TTONLY: u32 = 0x00040000;

/// No face select
pub const CF_NOFACESEL: u32 = 0x00080000;

/// No style select
pub const CF_NOSTYLESEL: u32 = 0x00100000;

/// No size select
pub const CF_NOSIZESEL: u32 = 0x00200000;

/// Select script
pub const CF_SELECTSCRIPT: u32 = 0x00400000;

/// No script select
pub const CF_NOSCRIPTSEL: u32 = 0x00800000;

/// No vertical fonts
pub const CF_NOVERTFONTS: u32 = 0x01000000;

// ============================================================================
// Print Dialog Flags (PD_*)
// ============================================================================

/// All pages
pub const PD_ALLPAGES: u32 = 0x00000000;

/// Selection
pub const PD_SELECTION: u32 = 0x00000001;

/// Page nums
pub const PD_PAGENUMS: u32 = 0x00000002;

/// No selection
pub const PD_NOSELECTION: u32 = 0x00000004;

/// No page nums
pub const PD_NOPAGENUMS: u32 = 0x00000008;

/// Collate
pub const PD_COLLATE: u32 = 0x00000010;

/// Print to file
pub const PD_PRINTTOFILE: u32 = 0x00000020;

/// Print setup
pub const PD_PRINTSETUP: u32 = 0x00000040;

/// No warning
pub const PD_NOWARNING: u32 = 0x00000080;

/// Return DC
pub const PD_RETURNDC: u32 = 0x00000100;

/// Return IC
pub const PD_RETURNIC: u32 = 0x00000200;

/// Return default
pub const PD_RETURNDEFAULT: u32 = 0x00000400;

/// Show help
pub const PD_SHOWHELP: u32 = 0x00000800;

/// Enable print hook
pub const PD_ENABLEPRINTHOOK: u32 = 0x00001000;

/// Enable setup hook
pub const PD_ENABLESETUPHOOK: u32 = 0x00002000;

/// Enable print template
pub const PD_ENABLEPRINTTEMPLATE: u32 = 0x00004000;

/// Enable setup template
pub const PD_ENABLESETUPTEMPLATE: u32 = 0x00008000;

/// Enable print template handle
pub const PD_ENABLEPRINTTEMPLATEHANDLE: u32 = 0x00010000;

/// Enable setup template handle
pub const PD_ENABLESETUPTEMPLATEHANDLE: u32 = 0x00020000;

/// Use dev mode copies/collate
pub const PD_USEDEVMODECOPIESANDCOLLATE: u32 = 0x00040000;

/// Disable print to file
pub const PD_DISABLEPRINTTOFILE: u32 = 0x00080000;

/// Hide print to file
pub const PD_HIDEPRINTTOFILE: u32 = 0x00100000;

/// No current page
pub const PD_NOCURRENTPAGE: u32 = 0x00800000;

// ============================================================================
// Find/Replace Flags (FR_*)
// ============================================================================

/// Down direction
pub const FR_DOWN: u32 = 0x00000001;

/// Whole word
pub const FR_WHOLEWORD: u32 = 0x00000002;

/// Match case
pub const FR_MATCHCASE: u32 = 0x00000004;

/// Find next
pub const FR_FINDNEXT: u32 = 0x00000008;

/// Replace
pub const FR_REPLACE: u32 = 0x00000010;

/// Replace all
pub const FR_REPLACEALL: u32 = 0x00000020;

/// Dialog term
pub const FR_DIALOGTERM: u32 = 0x00000040;

/// Show help
pub const FR_SHOWHELP: u32 = 0x00000080;

/// Enable hook
pub const FR_ENABLEHOOK: u32 = 0x00000100;

/// Enable template
pub const FR_ENABLETEMPLATE: u32 = 0x00000200;

/// No up down
pub const FR_NOUPDOWN: u32 = 0x00000400;

/// No match case
pub const FR_NOMATCHCASE: u32 = 0x00000800;

/// No whole word
pub const FR_NOWHOLEWORD: u32 = 0x00001000;

/// Enable template handle
pub const FR_ENABLETEMPLATEHANDLE: u32 = 0x00002000;

/// Hide up down
pub const FR_HIDEUPDOWN: u32 = 0x00004000;

/// Hide match case
pub const FR_HIDEMATCHCASE: u32 = 0x00008000;

/// Hide whole word
pub const FR_HIDEWHOLEWORD: u32 = 0x00010000;

/// Raw
pub const FR_RAW: u32 = 0x00020000;

// ============================================================================
// Dialog Structures
// ============================================================================

/// Maximum path length
pub const MAX_PATH: usize = 260;

/// Maximum filter length
pub const MAX_FILTER: usize = 256;

/// Open/Save filename structure
#[derive(Clone)]
pub struct OpenFileName {
    /// Structure size
    pub struct_size: u32,
    /// Owner window
    pub hwnd_owner: HWND,
    /// Instance (not used)
    pub instance: usize,
    /// Filter string
    pub filter: [u8; MAX_FILTER],
    /// Custom filter
    pub custom_filter: [u8; MAX_FILTER],
    /// Max custom filter
    pub max_cust_filter: u32,
    /// Filter index
    pub filter_index: u32,
    /// File path
    pub file: [u8; MAX_PATH],
    /// Max file length
    pub max_file: u32,
    /// File title
    pub file_title: [u8; MAX_PATH],
    /// Max file title
    pub max_file_title: u32,
    /// Initial directory
    pub initial_dir: [u8; MAX_PATH],
    /// Dialog title
    pub title: [u8; 128],
    /// Flags
    pub flags: u32,
    /// File offset
    pub file_offset: u16,
    /// File extension offset
    pub file_extension: u16,
    /// Default extension
    pub def_ext: [u8; 16],
    /// Custom data
    pub cust_data: usize,
    /// Hook procedure
    pub hook: usize,
    /// Template name
    pub template_name: usize,
}

impl OpenFileName {
    /// Create default structure
    pub const fn new() -> Self {
        Self {
            struct_size: 0,
            hwnd_owner: UserHandle::NULL,
            instance: 0,
            filter: [0; MAX_FILTER],
            custom_filter: [0; MAX_FILTER],
            max_cust_filter: MAX_FILTER as u32,
            filter_index: 1,
            file: [0; MAX_PATH],
            max_file: MAX_PATH as u32,
            file_title: [0; MAX_PATH],
            max_file_title: MAX_PATH as u32,
            initial_dir: [0; MAX_PATH],
            title: [0; 128],
            flags: 0,
            file_offset: 0,
            file_extension: 0,
            def_ext: [0; 16],
            cust_data: 0,
            hook: 0,
            template_name: 0,
        }
    }
}

/// Choose color structure
#[derive(Clone, Copy)]
pub struct ChooseColor {
    /// Structure size
    pub struct_size: u32,
    /// Owner window
    pub hwnd_owner: HWND,
    /// Instance
    pub instance: usize,
    /// Result color
    pub result: ColorRef,
    /// Custom colors (16 colors)
    pub custom_colors: [ColorRef; 16],
    /// Flags
    pub flags: u32,
    /// Custom data
    pub cust_data: usize,
    /// Hook procedure
    pub hook: usize,
    /// Template name
    pub template_name: usize,
}

impl ChooseColor {
    /// Create default structure
    pub const fn new() -> Self {
        Self {
            struct_size: 0,
            hwnd_owner: UserHandle::NULL,
            instance: 0,
            result: ColorRef(0),
            custom_colors: [ColorRef(0xFFFFFF); 16],
            flags: 0,
            cust_data: 0,
            hook: 0,
            template_name: 0,
        }
    }
}

/// Choose font structure (simplified)
#[derive(Clone)]
pub struct ChooseFont {
    /// Structure size
    pub struct_size: u32,
    /// Owner window
    pub hwnd_owner: HWND,
    /// DC for printer fonts
    pub hdc: usize,
    /// Font name
    pub face_name: [u8; 32],
    /// Point size (in 1/10 points)
    pub point_size: i32,
    /// Flags
    pub flags: u32,
    /// Result color
    pub color: ColorRef,
    /// Custom data
    pub cust_data: usize,
    /// Hook procedure
    pub hook: usize,
    /// Template name
    pub template_name: usize,
    /// Instance
    pub instance: usize,
    /// Style name
    pub style: [u8; 64],
    /// Font type
    pub font_type: u16,
    /// Min size
    pub size_min: i32,
    /// Max size
    pub size_max: i32,
}

impl ChooseFont {
    /// Create default structure
    pub const fn new() -> Self {
        Self {
            struct_size: 0,
            hwnd_owner: UserHandle::NULL,
            hdc: 0,
            face_name: [0; 32],
            point_size: 0,
            flags: 0,
            color: ColorRef(0),
            cust_data: 0,
            hook: 0,
            template_name: 0,
            instance: 0,
            style: [0; 64],
            font_type: 0,
            size_min: 0,
            size_max: 0,
        }
    }
}

/// Find/Replace text structure
#[derive(Clone)]
pub struct FindReplace {
    /// Structure size
    pub struct_size: u32,
    /// Owner window
    pub hwnd_owner: HWND,
    /// Instance
    pub instance: usize,
    /// Flags
    pub flags: u32,
    /// Find what
    pub find_what: [u8; 256],
    /// Replace with
    pub replace_with: [u8; 256],
    /// Find what length
    pub find_what_len: u16,
    /// Replace with length
    pub replace_with_len: u16,
    /// Custom data
    pub cust_data: usize,
    /// Hook procedure
    pub hook: usize,
    /// Template name
    pub template_name: usize,
}

impl FindReplace {
    /// Create default structure
    pub const fn new() -> Self {
        Self {
            struct_size: 0,
            hwnd_owner: UserHandle::NULL,
            instance: 0,
            flags: 0,
            find_what: [0; 256],
            replace_with: [0; 256],
            find_what_len: 256,
            replace_with_len: 256,
            cust_data: 0,
            hook: 0,
            template_name: 0,
        }
    }
}

// ============================================================================
// Dialog State
// ============================================================================

/// Maximum active dialogs
pub const MAX_COMMON_DIALOGS: usize = 8;

/// Active dialog state
#[derive(Clone)]
struct DialogState {
    in_use: bool,
    dialog_type: DialogType,
    hwnd: HWND,
    result: i32,
}

impl DialogState {
    const fn new() -> Self {
        Self {
            in_use: false,
            dialog_type: DialogType::None,
            hwnd: UserHandle::NULL,
            result: 0,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum DialogType {
    None,
    OpenFile,
    SaveFile,
    Color,
    Font,
    Print,
    FindText,
    ReplaceText,
}

static DIALOGS: SpinLock<[DialogState; MAX_COMMON_DIALOGS]> =
    SpinLock::new([const { DialogState::new() }; MAX_COMMON_DIALOGS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize common dialogs
pub fn init() {
    crate::serial_println!("[USER] Common dialogs initialized");
}

/// Show Open File dialog
pub fn get_open_file_name(ofn: &mut OpenFileName) -> bool {
    // In a real implementation, this would create and show the dialog
    // For now, just validate and return false (cancelled)

    if ofn.max_file == 0 {
        return false;
    }

    // Check required flags
    if (ofn.flags & OFN_FILEMUSTEXIST) != 0 {
        // Would verify file exists
    }

    if (ofn.flags & OFN_PATHMUSTEXIST) != 0 {
        // Would verify path exists
    }

    // Simulate cancel
    false
}

/// Show Save File dialog
pub fn get_save_file_name(ofn: &mut OpenFileName) -> bool {
    // In a real implementation, this would create and show the dialog

    if ofn.max_file == 0 {
        return false;
    }

    // Check overwrite prompt
    if (ofn.flags & OFN_OVERWRITEPROMPT) != 0 {
        // Would prompt if file exists
    }

    // Simulate cancel
    false
}

/// Show Color picker dialog
pub fn choose_color(cc: &mut ChooseColor) -> bool {
    // In a real implementation, this would create and show the dialog

    if (cc.flags & CC_RGBINIT) != 0 {
        // Use cc.result as initial color
    }

    // Simulate cancel
    false
}

/// Show Font picker dialog
pub fn choose_font(cf: &mut ChooseFont) -> bool {
    // In a real implementation, this would create and show the dialog

    if (cf.flags & CF_INITTOLOGFONTSTRUCT) != 0 {
        // Use cf.face_name as initial font
    }

    if (cf.flags & CF_EFFECTS) != 0 {
        // Show color and effects options
    }

    // Simulate cancel
    false
}

/// Show Find Text dialog (modeless)
pub fn find_text(fr: &mut FindReplace) -> HWND {
    let mut dialogs = DIALOGS.lock();

    // Find free slot
    for (i, dialog) in dialogs.iter_mut().enumerate() {
        if !dialog.in_use {
            dialog.in_use = true;
            dialog.dialog_type = DialogType::FindText;
            // In a real implementation, create the dialog window
            dialog.hwnd = UserHandle::from_raw((i + 1) as u32);

            let _ = fr;
            return dialog.hwnd;
        }
    }

    UserHandle::NULL
}

/// Show Replace Text dialog (modeless)
pub fn replace_text(fr: &mut FindReplace) -> HWND {
    let mut dialogs = DIALOGS.lock();

    // Find free slot
    for (i, dialog) in dialogs.iter_mut().enumerate() {
        if !dialog.in_use {
            dialog.in_use = true;
            dialog.dialog_type = DialogType::ReplaceText;
            // In a real implementation, create the dialog window
            dialog.hwnd = UserHandle::from_raw((i + 1) as u32);

            let _ = fr;
            return dialog.hwnd;
        }
    }

    UserHandle::NULL
}

/// Close a modeless dialog
pub fn close_dialog(hwnd: HWND) -> bool {
    let mut dialogs = DIALOGS.lock();

    for dialog in dialogs.iter_mut() {
        if dialog.in_use && dialog.hwnd == hwnd {
            dialog.in_use = false;
            dialog.dialog_type = DialogType::None;
            dialog.hwnd = UserHandle::NULL;
            return true;
        }
    }

    false
}

/// Check if dialog is a common dialog
pub fn is_common_dialog(hwnd: HWND) -> bool {
    let dialogs = DIALOGS.lock();

    for dialog in dialogs.iter() {
        if dialog.in_use && dialog.hwnd == hwnd {
            return true;
        }
    }

    false
}

/// Get dialog type
pub fn get_dialog_type(hwnd: HWND) -> u32 {
    let dialogs = DIALOGS.lock();

    for dialog in dialogs.iter() {
        if dialog.in_use && dialog.hwnd == hwnd {
            return match dialog.dialog_type {
                DialogType::None => 0,
                DialogType::OpenFile => 1,
                DialogType::SaveFile => 2,
                DialogType::Color => 3,
                DialogType::Font => 4,
                DialogType::Print => 5,
                DialogType::FindText => 6,
                DialogType::ReplaceText => 7,
            };
        }
    }

    0
}

// ============================================================================
// Error Handling
// ============================================================================

/// Common dialog extended error codes
pub const CDERR_DIALOGFAILURE: u32 = 0xFFFF;
pub const CDERR_GENERALCODES: u32 = 0x0000;
pub const CDERR_STRUCTSIZE: u32 = 0x0001;
pub const CDERR_INITIALIZATION: u32 = 0x0002;
pub const CDERR_NOTEMPLATE: u32 = 0x0003;
pub const CDERR_NOHINSTANCE: u32 = 0x0004;
pub const CDERR_LOADSTRFAILURE: u32 = 0x0005;
pub const CDERR_FINDRESFAILURE: u32 = 0x0006;
pub const CDERR_LOADRESFAILURE: u32 = 0x0007;
pub const CDERR_LOCKRESFAILURE: u32 = 0x0008;
pub const CDERR_MEMALLOCFAILURE: u32 = 0x0009;
pub const CDERR_MEMLOCKFAILURE: u32 = 0x000A;
pub const CDERR_NOHOOK: u32 = 0x000B;
pub const CDERR_REGISTERMSGFAIL: u32 = 0x000C;

/// Last error
static LAST_ERROR: SpinLock<u32> = SpinLock::new(0);

/// Get extended error
pub fn comm_dlg_extended_error() -> u32 {
    *LAST_ERROR.lock()
}

/// Set extended error
fn set_extended_error(error: u32) {
    *LAST_ERROR.lock() = error;
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> ComDlgStats {
    let dialogs = DIALOGS.lock();

    let mut active_count = 0;
    for dialog in dialogs.iter() {
        if dialog.in_use {
            active_count += 1;
        }
    }

    ComDlgStats {
        max_dialogs: MAX_COMMON_DIALOGS,
        active_dialogs: active_count,
    }
}

/// Common dialog statistics
#[derive(Debug, Clone, Copy)]
pub struct ComDlgStats {
    pub max_dialogs: usize,
    pub active_dialogs: usize,
}
