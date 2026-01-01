//! NativeFont Control Implementation
//!
//! Windows NativeFontCtl for font linking support.
//! Based on Windows Server 2003 commctrl.h.
//!
//! # Features
//!
//! - Font linking for international text
//! - Automatic font substitution
//! - Script-aware rendering
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - NativeFontCtl class

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, GdiHandle};

// ============================================================================
// NativeFontCtl Styles (NFS_*)
// ============================================================================

/// Edit control style
pub const NFS_EDIT: u32 = 0x00000001;

/// Static control style
pub const NFS_STATIC: u32 = 0x00000002;

/// Listbox control style
pub const NFS_LISTCOMBO: u32 = 0x00000004;

/// Button control style
pub const NFS_BUTTON: u32 = 0x00000008;

/// All styles combined
pub const NFS_ALL: u32 = NFS_EDIT | NFS_STATIC | NFS_LISTCOMBO | NFS_BUTTON;

/// Use theme fonts
pub const NFS_USEFONTASSOC: u32 = 0x00000010;

// ============================================================================
// Font Script Types
// ============================================================================

/// Script identifier
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FontScript {
    #[default]
    Latin = 0,
    Greek = 1,
    Cyrillic = 2,
    Armenian = 3,
    Hebrew = 4,
    Arabic = 5,
    Syriac = 6,
    Thaana = 7,
    Devanagari = 8,
    Bengali = 9,
    Gurmukhi = 10,
    Gujarati = 11,
    Oriya = 12,
    Tamil = 13,
    Telugu = 14,
    Kannada = 15,
    Malayalam = 16,
    Sinhala = 17,
    Thai = 18,
    Lao = 19,
    Tibetan = 20,
    Myanmar = 21,
    Georgian = 22,
    Hangul = 23,
    Ethiopic = 24,
    Cherokee = 25,
    CanadianAboriginal = 26,
    Ogham = 27,
    Runic = 28,
    Khmer = 29,
    Mongolian = 30,
    Hiragana = 31,
    Katakana = 32,
    Bopomofo = 33,
    Han = 34,
    Yi = 35,
}

// ============================================================================
// Font Association Entry
// ============================================================================

/// Maximum font name length
pub const MAX_FONT_NAME: usize = 64;

/// Font association entry
#[derive(Clone)]
pub struct FontAssociation {
    /// Is this entry in use
    pub in_use: bool,
    /// Script type
    pub script: FontScript,
    /// Base font name
    pub base_font: [u8; MAX_FONT_NAME],
    pub base_font_len: usize,
    /// Associated font name
    pub assoc_font: [u8; MAX_FONT_NAME],
    pub assoc_font_len: usize,
    /// Font handle (cached)
    pub hfont: GdiHandle,
}

impl FontAssociation {
    /// Create new font association
    pub const fn new() -> Self {
        Self {
            in_use: false,
            script: FontScript::Latin,
            base_font: [0u8; MAX_FONT_NAME],
            base_font_len: 0,
            assoc_font: [0u8; MAX_FONT_NAME],
            assoc_font_len: 0,
            hfont: GdiHandle::NULL,
        }
    }

    /// Set base font
    pub fn set_base_font(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_FONT_NAME - 1);
        self.base_font[..len].copy_from_slice(&bytes[..len]);
        self.base_font_len = len;
    }

    /// Set associated font
    pub fn set_assoc_font(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_FONT_NAME - 1);
        self.assoc_font[..len].copy_from_slice(&bytes[..len]);
        self.assoc_font_len = len;
    }
}

// ============================================================================
// NativeFont Control State
// ============================================================================

/// Maximum associations per control
pub const MAX_ASSOCIATIONS: usize = 16;

/// Maximum native font controls
pub const MAX_NATIVE_FONT_CONTROLS: usize = 32;

/// Native font control state
#[derive(Clone)]
pub struct NativeFontControl {
    /// Is this slot in use
    pub in_use: bool,
    /// Control handle
    pub hwnd: HWND,
    /// Control type/style
    pub style: u32,
    /// Default font handle
    pub default_font: GdiHandle,
    /// Font associations
    pub associations: [FontAssociation; MAX_ASSOCIATIONS],
    pub assoc_count: usize,
    /// Use font association
    pub use_font_assoc: bool,
    /// Current script being rendered
    pub current_script: FontScript,
}

impl NativeFontControl {
    /// Create new native font control
    pub const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle::NULL,
            style: NFS_EDIT,
            default_font: GdiHandle::NULL,
            associations: [const { FontAssociation::new() }; MAX_ASSOCIATIONS],
            assoc_count: 0,
            use_font_assoc: false,
            current_script: FontScript::Latin,
        }
    }

    /// Reset control
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Add font association
    pub fn add_association(&mut self, script: FontScript, base: &str, assoc: &str) -> bool {
        if self.assoc_count >= MAX_ASSOCIATIONS {
            return false;
        }

        let entry = &mut self.associations[self.assoc_count];
        entry.in_use = true;
        entry.script = script;
        entry.set_base_font(base);
        entry.set_assoc_font(assoc);
        self.assoc_count += 1;

        true
    }

    /// Find font for script
    pub fn find_font_for_script(&self, script: FontScript) -> Option<&FontAssociation> {
        for assoc in self.associations[..self.assoc_count].iter() {
            if assoc.in_use && assoc.script == script {
                return Some(assoc);
            }
        }
        None
    }

    /// Get font for character
    pub fn get_font_for_char(&self, ch: char) -> GdiHandle {
        let script = detect_script(ch);

        if let Some(assoc) = self.find_font_for_script(script) {
            if assoc.hfont != GdiHandle::NULL {
                return assoc.hfont;
            }
        }

        self.default_font
    }
}

// ============================================================================
// Script Detection
// ============================================================================

/// Detect script from Unicode character
pub fn detect_script(ch: char) -> FontScript {
    let code = ch as u32;

    match code {
        // Basic Latin
        0x0000..=0x007F => FontScript::Latin,
        // Latin Extended
        0x0080..=0x024F => FontScript::Latin,
        // Greek
        0x0370..=0x03FF => FontScript::Greek,
        // Cyrillic
        0x0400..=0x04FF => FontScript::Cyrillic,
        // Armenian
        0x0530..=0x058F => FontScript::Armenian,
        // Hebrew
        0x0590..=0x05FF => FontScript::Hebrew,
        // Arabic
        0x0600..=0x06FF => FontScript::Arabic,
        // Syriac
        0x0700..=0x074F => FontScript::Syriac,
        // Thaana
        0x0780..=0x07BF => FontScript::Thaana,
        // Devanagari
        0x0900..=0x097F => FontScript::Devanagari,
        // Bengali
        0x0980..=0x09FF => FontScript::Bengali,
        // Gurmukhi
        0x0A00..=0x0A7F => FontScript::Gurmukhi,
        // Gujarati
        0x0A80..=0x0AFF => FontScript::Gujarati,
        // Oriya
        0x0B00..=0x0B7F => FontScript::Oriya,
        // Tamil
        0x0B80..=0x0BFF => FontScript::Tamil,
        // Telugu
        0x0C00..=0x0C7F => FontScript::Telugu,
        // Kannada
        0x0C80..=0x0CFF => FontScript::Kannada,
        // Malayalam
        0x0D00..=0x0D7F => FontScript::Malayalam,
        // Sinhala
        0x0D80..=0x0DFF => FontScript::Sinhala,
        // Thai
        0x0E00..=0x0E7F => FontScript::Thai,
        // Lao
        0x0E80..=0x0EFF => FontScript::Lao,
        // Tibetan
        0x0F00..=0x0FFF => FontScript::Tibetan,
        // Myanmar
        0x1000..=0x109F => FontScript::Myanmar,
        // Georgian
        0x10A0..=0x10FF => FontScript::Georgian,
        // Hangul Jamo
        0x1100..=0x11FF => FontScript::Hangul,
        // Ethiopic
        0x1200..=0x137F => FontScript::Ethiopic,
        // Cherokee
        0x13A0..=0x13FF => FontScript::Cherokee,
        // Canadian Aboriginal Syllabics
        0x1400..=0x167F => FontScript::CanadianAboriginal,
        // Ogham
        0x1680..=0x169F => FontScript::Ogham,
        // Runic
        0x16A0..=0x16FF => FontScript::Runic,
        // Khmer
        0x1780..=0x17FF => FontScript::Khmer,
        // Mongolian
        0x1800..=0x18AF => FontScript::Mongolian,
        // Hiragana
        0x3040..=0x309F => FontScript::Hiragana,
        // Katakana
        0x30A0..=0x30FF => FontScript::Katakana,
        // Bopomofo
        0x3100..=0x312F => FontScript::Bopomofo,
        // Hangul Compatibility Jamo
        0x3130..=0x318F => FontScript::Hangul,
        // CJK Unified Ideographs
        0x4E00..=0x9FFF => FontScript::Han,
        // Hangul Syllables
        0xAC00..=0xD7AF => FontScript::Hangul,
        // Yi Syllables
        0xA000..=0xA48F => FontScript::Yi,

        _ => FontScript::Latin,
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global native font control storage
static NATIVE_FONT_CONTROLS: SpinLock<[NativeFontControl; MAX_NATIVE_FONT_CONTROLS]> =
    SpinLock::new([const { NativeFontControl::new() }; MAX_NATIVE_FONT_CONTROLS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize NativeFont subsystem
pub fn init() {
    crate::serial_println!("[USER] NativeFont initialized");
}

/// Create a native font control
pub fn create(hwnd: HWND, style: u32) -> usize {
    let mut controls = NATIVE_FONT_CONTROLS.lock();

    for (i, ctrl) in controls.iter_mut().enumerate() {
        if !ctrl.in_use {
            ctrl.reset();
            ctrl.in_use = true;
            ctrl.hwnd = hwnd;
            ctrl.style = style;
            ctrl.use_font_assoc = (style & NFS_USEFONTASSOC) != 0;
            return i + 1;
        }
    }

    0
}

/// Destroy a native font control
pub fn destroy(ctrl_idx: usize) -> bool {
    if ctrl_idx == 0 {
        return false;
    }

    let mut controls = NATIVE_FONT_CONTROLS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_NATIVE_FONT_CONTROLS {
        return false;
    }

    if controls[idx].in_use {
        controls[idx].reset();
        true
    } else {
        false
    }
}

/// Set default font
pub fn set_default_font(ctrl_idx: usize, hfont: GdiHandle) -> bool {
    if ctrl_idx == 0 {
        return false;
    }

    let mut controls = NATIVE_FONT_CONTROLS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_NATIVE_FONT_CONTROLS || !controls[idx].in_use {
        return false;
    }

    controls[idx].default_font = hfont;
    true
}

/// Add font association
pub fn add_association(ctrl_idx: usize, script: FontScript, base: &str, assoc: &str) -> bool {
    if ctrl_idx == 0 {
        return false;
    }

    let mut controls = NATIVE_FONT_CONTROLS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_NATIVE_FONT_CONTROLS || !controls[idx].in_use {
        return false;
    }

    controls[idx].add_association(script, base, assoc)
}

/// Get font for character
pub fn get_font_for_char(ctrl_idx: usize, ch: char) -> GdiHandle {
    if ctrl_idx == 0 {
        return GdiHandle::NULL;
    }

    let controls = NATIVE_FONT_CONTROLS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_NATIVE_FONT_CONTROLS || !controls[idx].in_use {
        return GdiHandle::NULL;
    }

    controls[idx].get_font_for_char(ch)
}

/// Get script for character
pub fn get_script(ch: char) -> FontScript {
    detect_script(ch)
}

/// Check if character is complex script
pub fn is_complex_script(ch: char) -> bool {
    matches!(
        detect_script(ch),
        FontScript::Arabic
            | FontScript::Hebrew
            | FontScript::Thai
            | FontScript::Devanagari
            | FontScript::Bengali
            | FontScript::Tamil
            | FontScript::Telugu
            | FontScript::Kannada
            | FontScript::Malayalam
            | FontScript::Sinhala
            | FontScript::Myanmar
            | FontScript::Khmer
            | FontScript::Tibetan
    )
}

/// Check if character requires RTL layout
pub fn is_rtl_script(ch: char) -> bool {
    matches!(
        detect_script(ch),
        FontScript::Hebrew | FontScript::Arabic | FontScript::Syriac | FontScript::Thaana
    )
}

/// Get association count
pub fn get_association_count(ctrl_idx: usize) -> usize {
    if ctrl_idx == 0 {
        return 0;
    }

    let controls = NATIVE_FONT_CONTROLS.lock();
    let idx = ctrl_idx - 1;

    if idx >= MAX_NATIVE_FONT_CONTROLS || !controls[idx].in_use {
        return 0;
    }

    controls[idx].assoc_count
}

/// Get statistics
pub fn get_stats() -> NativeFontStats {
    let controls = NATIVE_FONT_CONTROLS.lock();

    let mut active_count = 0;
    let mut total_assoc = 0;

    for ctrl in controls.iter() {
        if ctrl.in_use {
            active_count += 1;
            total_assoc += ctrl.assoc_count;
        }
    }

    NativeFontStats {
        max_controls: MAX_NATIVE_FONT_CONTROLS,
        active_controls: active_count,
        total_associations: total_assoc,
    }
}

/// NativeFont statistics
#[derive(Debug, Clone, Copy)]
pub struct NativeFontStats {
    pub max_controls: usize,
    pub active_controls: usize,
    pub total_associations: usize,
}
