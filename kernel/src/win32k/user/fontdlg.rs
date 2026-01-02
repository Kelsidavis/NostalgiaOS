//! Font Picker Dialog
//!
//! Provides the font selection dialog following the Windows comdlg32
//! ChooseFont pattern.
//!
//! # References
//!
//! - Windows Server 2003 comdlg32 font dialog
//! - CHOOSEFONT structure and LOGFONT

use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, ColorRef};

// ============================================================================
// Constants
// ============================================================================

/// Maximum face name length
pub const LF_FACESIZE: usize = 32;

/// Maximum full name length
pub const LF_FULLFACESIZE: usize = 64;

/// Choose font flags (CF_*)
pub mod cf_flags {
    /// Screen fonts only
    pub const SCREENFONTS: u32 = 0x00000001;
    /// Printer fonts only
    pub const PRINTERFONTS: u32 = 0x00000002;
    /// Both screen and printer fonts
    pub const BOTH: u32 = SCREENFONTS | PRINTERFONTS;
    /// Show help button
    pub const SHOWHELP: u32 = 0x00000004;
    /// Enable hook
    pub const ENABLEHOOK: u32 = 0x00000008;
    /// Enable template
    pub const ENABLETEMPLATE: u32 = 0x00000010;
    /// Enable template handle
    pub const ENABLETEMPLATEHANDLE: u32 = 0x00000020;
    /// Use LOGFONT for init
    pub const INITTOLOGFONTSTRUCT: u32 = 0x00000040;
    /// Use size for init
    pub const USESTYLE: u32 = 0x00000080;
    /// Show effects (strikeout, underline, color)
    pub const EFFECTS: u32 = 0x00000100;
    /// Apply button
    pub const APPLY: u32 = 0x00000200;
    /// ANSI only
    pub const ANSIONLY: u32 = 0x00000400;
    /// Script only
    pub const SCRIPTSONLY: u32 = ANSIONLY;
    /// No OEM fonts
    pub const NOVECTORFONTS: u32 = 0x00000800;
    /// No simulations
    pub const NOSIMULATIONS: u32 = 0x00001000;
    /// Limit size
    pub const LIMITSIZE: u32 = 0x00002000;
    /// Fixed pitch only
    pub const FIXEDPITCHONLY: u32 = 0x00004000;
    /// WYSIWYG
    pub const WYSIWYG: u32 = 0x00008000;
    /// Force font exist
    pub const FORCEFONTEXIST: u32 = 0x00010000;
    /// Scalable only
    pub const SCALABLEONLY: u32 = 0x00020000;
    /// TrueType only
    pub const TTONLY: u32 = 0x00040000;
    /// No face selection
    pub const NOFACESEL: u32 = 0x00080000;
    /// No style selection
    pub const NOSTYLESEL: u32 = 0x00100000;
    /// No size selection
    pub const NOSIZESEL: u32 = 0x00200000;
    /// Select script
    pub const SELECTSCRIPT: u32 = 0x00400000;
    /// No script selection
    pub const NOSCRIPTSEL: u32 = 0x00800000;
    /// No vertical fonts
    pub const NOVERTFONTS: u32 = 0x01000000;
    /// Init using style
    pub const INACTIVEFONTS: u32 = 0x02000000;
}

/// Font weight values
pub mod font_weight {
    pub const DONTCARE: u32 = 0;
    pub const THIN: u32 = 100;
    pub const EXTRALIGHT: u32 = 200;
    pub const LIGHT: u32 = 300;
    pub const NORMAL: u32 = 400;
    pub const MEDIUM: u32 = 500;
    pub const SEMIBOLD: u32 = 600;
    pub const BOLD: u32 = 700;
    pub const EXTRABOLD: u32 = 800;
    pub const HEAVY: u32 = 900;
}

/// Font charset values
pub mod font_charset {
    pub const ANSI: u8 = 0;
    pub const DEFAULT: u8 = 1;
    pub const SYMBOL: u8 = 2;
    pub const SHIFTJIS: u8 = 128;
    pub const HANGUL: u8 = 129;
    pub const GB2312: u8 = 134;
    pub const CHINESEBIG5: u8 = 136;
    pub const OEM: u8 = 255;
    pub const GREEK: u8 = 161;
    pub const TURKISH: u8 = 162;
    pub const HEBREW: u8 = 177;
    pub const ARABIC: u8 = 178;
    pub const BALTIC: u8 = 186;
    pub const RUSSIAN: u8 = 204;
    pub const THAI: u8 = 222;
    pub const EASTEUROPE: u8 = 238;
}

/// Font pitch and family
pub mod font_pitch {
    pub const DEFAULT_PITCH: u8 = 0;
    pub const FIXED_PITCH: u8 = 1;
    pub const VARIABLE_PITCH: u8 = 2;
    pub const MONO_FONT: u8 = 8;
}

pub mod font_family {
    pub const FF_DONTCARE: u8 = 0;
    pub const FF_ROMAN: u8 = 1 << 4;
    pub const FF_SWISS: u8 = 2 << 4;
    pub const FF_MODERN: u8 = 3 << 4;
    pub const FF_SCRIPT: u8 = 4 << 4;
    pub const FF_DECORATIVE: u8 = 5 << 4;
}

// ============================================================================
// Structures
// ============================================================================

/// Logical font structure (LOGFONT equivalent)
#[derive(Debug, Clone, Copy)]
pub struct LogFont {
    /// Height in logical units
    pub height: i32,
    /// Width in logical units
    pub width: i32,
    /// Escapement angle (0.1 degrees)
    pub escapement: i32,
    /// Orientation angle (0.1 degrees)
    pub orientation: i32,
    /// Font weight
    pub weight: u32,
    /// Italic
    pub italic: bool,
    /// Underline
    pub underline: bool,
    /// Strikeout
    pub strikeout: bool,
    /// Character set
    pub charset: u8,
    /// Output precision
    pub out_precision: u8,
    /// Clip precision
    pub clip_precision: u8,
    /// Quality
    pub quality: u8,
    /// Pitch and family
    pub pitch_and_family: u8,
    /// Face name length
    pub face_name_len: u8,
    /// Face name
    pub face_name: [u8; LF_FACESIZE],
}

impl LogFont {
    pub const fn new() -> Self {
        Self {
            height: 0,
            width: 0,
            escapement: 0,
            orientation: 0,
            weight: font_weight::NORMAL,
            italic: false,
            underline: false,
            strikeout: false,
            charset: font_charset::DEFAULT,
            out_precision: 0,
            clip_precision: 0,
            quality: 0,
            pitch_and_family: font_pitch::DEFAULT_PITCH | font_family::FF_DONTCARE,
            face_name_len: 0,
            face_name: [0; LF_FACESIZE],
        }
    }

    /// Set face name
    pub fn set_face_name(&mut self, name: &[u8]) {
        self.face_name_len = name.len().min(LF_FACESIZE) as u8;
        self.face_name[..self.face_name_len as usize].copy_from_slice(&name[..self.face_name_len as usize]);
    }

    /// Get point size from height (assuming 96 DPI)
    pub fn point_size(&self) -> u32 {
        if self.height < 0 {
            ((-self.height) * 72 / 96) as u32
        } else if self.height > 0 {
            (self.height * 72 / 96) as u32
        } else {
            12 // Default
        }
    }

    /// Set height from point size (assuming 96 DPI)
    pub fn set_point_size(&mut self, points: u32) {
        self.height = -((points * 96 / 72) as i32);
    }
}

/// Choose font structure (CHOOSEFONT equivalent)
#[derive(Debug, Clone, Copy)]
pub struct ChooseFont {
    /// Structure size
    pub struct_size: u32,
    /// Owner window
    pub hwnd_owner: HWND,
    /// Device context
    pub hdc: u32,
    /// Logical font
    pub log_font: LogFont,
    /// Point size (in 1/10 points)
    pub point_size: i32,
    /// Flags
    pub flags: u32,
    /// Text color
    pub rgb_colors: ColorRef,
    /// Custom data
    pub cust_data: usize,
    /// Hook function
    pub hook_fn: usize,
    /// Template name
    pub template_name: u32,
    /// Instance
    pub instance: u32,
    /// Style length
    pub style_len: u8,
    /// Style name
    pub style: [u8; LF_FACESIZE],
    /// Font type
    pub font_type: u16,
    /// Minimum size
    pub size_min: i32,
    /// Maximum size
    pub size_max: i32,
}

impl ChooseFont {
    pub const fn new() -> Self {
        Self {
            struct_size: 0,
            hwnd_owner: UserHandle::NULL,
            hdc: 0,
            log_font: LogFont::new(),
            point_size: 120, // 12 points
            flags: 0,
            rgb_colors: ColorRef(0), // Black
            cust_data: 0,
            hook_fn: 0,
            template_name: 0,
            instance: 0,
            style_len: 0,
            style: [0; LF_FACESIZE],
            font_type: 0,
            size_min: 8,
            size_max: 72,
        }
    }
}

/// Font dialog state
#[derive(Debug, Clone, Copy)]
pub struct FontDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Selected font index
    pub font_index: u16,
    /// Selected style index
    pub style_index: u8,
    /// Selected size index
    pub size_index: u8,
    /// Show effects
    pub show_effects: bool,
    /// Current color
    pub color: ColorRef,
}

impl FontDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            font_index: 0,
            style_index: 0,
            size_index: 4, // 12pt default
            show_effects: true,
            color: ColorRef(0),
        }
    }
}

/// Font entry for font list
#[derive(Debug, Clone, Copy)]
pub struct FontEntry {
    /// Entry is valid
    pub valid: bool,
    /// Font name length
    pub name_len: u8,
    /// Font name
    pub name: [u8; LF_FACESIZE],
    /// Font charset
    pub charset: u8,
    /// Font family
    pub family: u8,
    /// Is TrueType
    pub truetype: bool,
    /// Is fixed pitch
    pub fixed_pitch: bool,
    /// Supports regular style
    pub has_regular: bool,
    /// Supports italic
    pub has_italic: bool,
    /// Supports bold
    pub has_bold: bool,
    /// Supports bold italic
    pub has_bold_italic: bool,
}

impl FontEntry {
    const fn new() -> Self {
        Self {
            valid: false,
            name_len: 0,
            name: [0; LF_FACESIZE],
            charset: font_charset::DEFAULT,
            family: font_family::FF_DONTCARE,
            truetype: false,
            fixed_pitch: false,
            has_regular: true,
            has_italic: true,
            has_bold: true,
            has_bold_italic: true,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static FONTDLG_INITIALIZED: AtomicBool = AtomicBool::new(false);
static FONTDLG_LOCK: SpinLock<()> = SpinLock::new(());

static CURRENT_STATE: SpinLock<FontDialogState> = SpinLock::new(FontDialogState::new());

// Common font sizes (in points)
static COMMON_SIZES: [u32; 16] = [8, 9, 10, 11, 12, 14, 16, 18, 20, 22, 24, 26, 28, 36, 48, 72];

// System fonts list
const MAX_FONTS: usize = 64;
static FONT_LIST: SpinLock<[FontEntry; MAX_FONTS]> =
    SpinLock::new([const { FontEntry::new() }; MAX_FONTS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize font dialog subsystem
pub fn init() {
    let _guard = FONTDLG_LOCK.lock();

    if FONTDLG_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[FONTDLG] Initializing font dialog...");

    // Initialize common fonts
    init_common_fonts();

    FONTDLG_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[FONTDLG] Font dialog initialized");
}

/// Initialize common system fonts
fn init_common_fonts() {
    let common_fonts: &[(&[u8], bool, bool)] = &[
        (b"Arial", false, true),
        (b"Times New Roman", false, true),
        (b"Courier New", true, true),
        (b"Tahoma", false, true),
        (b"Verdana", false, true),
        (b"Georgia", false, true),
        (b"Trebuchet MS", false, true),
        (b"Comic Sans MS", false, true),
        (b"Impact", false, true),
        (b"Lucida Console", true, true),
        (b"Consolas", true, true),
        (b"Segoe UI", false, true),
        (b"Calibri", false, true),
        (b"Cambria", false, true),
        (b"Symbol", false, false),
        (b"Wingdings", false, false),
    ];

    let mut fonts = FONT_LIST.lock();
    let mut idx = 0;

    for (name, fixed, truetype) in common_fonts {
        if idx >= MAX_FONTS {
            break;
        }

        let entry = &mut fonts[idx];
        entry.valid = true;
        entry.name_len = name.len().min(LF_FACESIZE) as u8;
        entry.name[..entry.name_len as usize].copy_from_slice(&name[..entry.name_len as usize]);
        entry.truetype = *truetype;
        entry.fixed_pitch = *fixed;
        entry.charset = font_charset::DEFAULT;
        entry.family = if *fixed {
            font_family::FF_MODERN
        } else {
            font_family::FF_SWISS
        };

        idx += 1;
    }
}

// ============================================================================
// Font Dialog API
// ============================================================================

/// Show font picker dialog
pub fn choose_font(cf: &mut ChooseFont) -> bool {
    if !FONTDLG_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        return false;
    }

    state.show_effects = (cf.flags & cf_flags::EFFECTS) != 0;
    state.color = cf.rgb_colors;

    // Create dialog
    let hwnd = create_font_dialog(cf);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    // Run dialog
    let result = run_font_dialog(hwnd, cf);

    // Clean up
    let mut state = CURRENT_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

/// Quick font picker (simplified API)
pub fn pick_font(owner: HWND, initial: Option<&LogFont>) -> Option<LogFont> {
    let mut cf = ChooseFont::new();
    cf.hwnd_owner = owner;
    cf.flags = cf_flags::SCREENFONTS | cf_flags::EFFECTS | cf_flags::INITTOLOGFONTSTRUCT;

    if let Some(lf) = initial {
        cf.log_font = *lf;
    } else {
        cf.log_font.set_face_name(b"Arial");
        cf.log_font.set_point_size(12);
    }

    if choose_font(&mut cf) {
        Some(cf.log_font)
    } else {
        None
    }
}

/// Close font dialog
pub fn close_font_dialog() {
    let mut state = CURRENT_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }

        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Get dialog state
pub fn get_dialog_state() -> FontDialogState {
    *CURRENT_STATE.lock()
}

// ============================================================================
// Font Enumeration
// ============================================================================

/// Get available fonts
pub fn get_font_list() -> ([FontEntry; MAX_FONTS], usize) {
    let fonts = FONT_LIST.lock();
    let count = fonts.iter().filter(|f| f.valid).count();
    (*fonts, count)
}

/// Get common font sizes
pub fn get_common_sizes() -> &'static [u32; 16] {
    &COMMON_SIZES
}

/// Find font by name
pub fn find_font(name: &[u8]) -> Option<FontEntry> {
    let fonts = FONT_LIST.lock();

    for font in fonts.iter() {
        if font.valid && font.name[..font.name_len as usize] == *name {
            return Some(*font);
        }
    }

    None
}

// ============================================================================
// Dialog Creation
// ============================================================================

/// Create font dialog window
fn create_font_dialog(_cf: &ChooseFont) -> HWND {
    UserHandle::NULL
}

/// Run font dialog modal loop
fn run_font_dialog(_hwnd: HWND, _cf: &mut ChooseFont) -> bool {
    true
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Font dialog window procedure
pub fn font_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_font_command(hwnd, wparam as u32)
        }
        super::message::WM_CLOSE => {
            close_font_dialog();
            0
        }
        _ => 0,
    }
}

/// Handle font dialog commands
fn handle_font_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        1 => {
            // OK button
            let state = CURRENT_STATE.lock();
            if state.active && state.hwnd == hwnd {
                drop(state);
                close_font_dialog();
            }
            1
        }
        2 => {
            // Cancel button
            close_font_dialog();
            0
        }
        100 => {
            // Font list selection changed
            let mut state = CURRENT_STATE.lock();
            state.font_index = (command >> 16) as u16;
            0
        }
        101 => {
            // Style list selection changed
            let mut state = CURRENT_STATE.lock();
            state.style_index = ((command >> 16) & 0xFF) as u8;
            0
        }
        102 => {
            // Size list selection changed
            let mut state = CURRENT_STATE.lock();
            state.size_index = ((command >> 16) & 0xFF) as u8;
            0
        }
        103 => {
            // Strikeout checkbox
            0
        }
        104 => {
            // Underline checkbox
            0
        }
        105 => {
            // Color selection
            0
        }
        _ => 0,
    }
}

// ============================================================================
// Font Utilities
// ============================================================================

/// Create a LogFont from simple parameters
pub fn create_log_font(
    face_name: &[u8],
    point_size: u32,
    bold: bool,
    italic: bool,
) -> LogFont {
    let mut lf = LogFont::new();
    lf.set_face_name(face_name);
    lf.set_point_size(point_size);
    lf.weight = if bold { font_weight::BOLD } else { font_weight::NORMAL };
    lf.italic = italic;
    lf
}

/// Get style name from LogFont
pub fn get_font_style_name(lf: &LogFont) -> &'static [u8] {
    match (lf.weight >= font_weight::BOLD, lf.italic) {
        (false, false) => b"Regular",
        (false, true) => b"Italic",
        (true, false) => b"Bold",
        (true, true) => b"Bold Italic",
    }
}

/// Compare two LogFonts
pub fn compare_log_fonts(lf1: &LogFont, lf2: &LogFont) -> bool {
    lf1.height == lf2.height &&
    lf1.weight == lf2.weight &&
    lf1.italic == lf2.italic &&
    lf1.underline == lf2.underline &&
    lf1.strikeout == lf2.strikeout &&
    lf1.face_name_len == lf2.face_name_len &&
    lf1.face_name[..lf1.face_name_len as usize] == lf2.face_name[..lf2.face_name_len as usize]
}
