//! Input Method Editor (IME) Support
//!
//! IME support for East Asian and complex script input.
//! Based on Windows Server 2003 imm.h and immdev.h.
//!
//! # Features
//!
//! - Input context management (HIMC)
//! - Composition string handling
//! - Candidate list support
//! - IME window management
//!
//! # References
//!
//! - `public/sdk/inc/imm.h` - IME Manager
//! - `public/sdk/inc/immdev.h` - IME development

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Point, Rect};

// ============================================================================
// IME Handle Types
// ============================================================================

/// Input Method Context handle
pub type HIMC = usize;

/// Null HIMC
pub const NULL_HIMC: HIMC = 0;

/// Input Method Editor handle
pub type HKL = usize;

// ============================================================================
// IME Conversion Mode (IME_CMODE_*)
// ============================================================================

/// Alphanumeric mode
pub const IME_CMODE_ALPHANUMERIC: u32 = 0x0000;

/// Native mode
pub const IME_CMODE_NATIVE: u32 = 0x0001;

/// Chinese mode
pub const IME_CMODE_CHINESE: u32 = IME_CMODE_NATIVE;

/// Hangul mode
pub const IME_CMODE_HANGUL: u32 = IME_CMODE_NATIVE;

/// Japanese mode
pub const IME_CMODE_JAPANESE: u32 = IME_CMODE_NATIVE;

/// Katakana mode
pub const IME_CMODE_KATAKANA: u32 = 0x0002;

/// Language mode
pub const IME_CMODE_LANGUAGE: u32 = 0x0003;

/// Full shape mode
pub const IME_CMODE_FULLSHAPE: u32 = 0x0008;

/// Roman mode
pub const IME_CMODE_ROMAN: u32 = 0x0010;

/// Character code mode
pub const IME_CMODE_CHARCODE: u32 = 0x0020;

/// Hanja convert mode
pub const IME_CMODE_HANJACONVERT: u32 = 0x0040;

/// Soft keyboard mode
pub const IME_CMODE_SOFTKBD: u32 = 0x0080;

/// No conversion mode
pub const IME_CMODE_NOCONVERSION: u32 = 0x0100;

/// EUDC mode
pub const IME_CMODE_EUDC: u32 = 0x0200;

/// Symbol mode
pub const IME_CMODE_SYMBOL: u32 = 0x0400;

/// Fixed mode
pub const IME_CMODE_FIXED: u32 = 0x0800;

// ============================================================================
// IME Sentence Mode (IME_SMODE_*)
// ============================================================================

/// None
pub const IME_SMODE_NONE: u32 = 0x0000;

/// PLAURALCLAUSE
pub const IME_SMODE_PLAURALCLAUSE: u32 = 0x0001;

/// Single convert
pub const IME_SMODE_SINGLECONVERT: u32 = 0x0002;

/// Automatic
pub const IME_SMODE_AUTOMATIC: u32 = 0x0004;

/// Phrase predict
pub const IME_SMODE_PHRASEPREDICT: u32 = 0x0008;

/// Conversation
pub const IME_SMODE_CONVERSATION: u32 = 0x0010;

// ============================================================================
// IME Composition String (GCS_*)
// ============================================================================

/// Composition string
pub const GCS_COMPSTR: u32 = 0x0008;

/// Composition attribute
pub const GCS_COMPATTR: u32 = 0x0010;

/// Composition clause
pub const GCS_COMPCLAUSE: u32 = 0x0020;

/// Composition reading string
pub const GCS_COMPREADSTR: u32 = 0x0001;

/// Composition reading attribute
pub const GCS_COMPREADATTR: u32 = 0x0002;

/// Composition reading clause
pub const GCS_COMPREADCLAUSE: u32 = 0x0004;

/// Result string
pub const GCS_RESULTSTR: u32 = 0x0800;

/// Result clause
pub const GCS_RESULTCLAUSE: u32 = 0x1000;

/// Result reading string
pub const GCS_RESULTREADSTR: u32 = 0x0200;

/// Result reading clause
pub const GCS_RESULTREADCLAUSE: u32 = 0x0400;

/// Cursor position
pub const GCS_CURSORPOS: u32 = 0x0080;

/// Delta start
pub const GCS_DELTASTART: u32 = 0x0100;

// ============================================================================
// IME Candidate List Style (IME_CAND_*)
// ============================================================================

/// Unknown candidate style
pub const IME_CAND_UNKNOWN: u32 = 0x0000;

/// Read candidate
pub const IME_CAND_READ: u32 = 0x0001;

/// Code candidate
pub const IME_CAND_CODE: u32 = 0x0002;

/// Meaning candidate
pub const IME_CAND_MEANING: u32 = 0x0003;

/// Radical candidate
pub const IME_CAND_RADICAL: u32 = 0x0004;

/// Stroke candidate
pub const IME_CAND_STROKE: u32 = 0x0005;

// ============================================================================
// IME Notification (IMN_*)
// ============================================================================

/// Close status window
pub const IMN_CLOSESTATUSWINDOW: u32 = 0x0001;

/// Open status window
pub const IMN_OPENSTATUSWINDOW: u32 = 0x0002;

/// Change candidate
pub const IMN_CHANGECANDIDATE: u32 = 0x0003;

/// Close candidate
pub const IMN_CLOSECANDIDATE: u32 = 0x0004;

/// Open candidate
pub const IMN_OPENCANDIDATE: u32 = 0x0005;

/// Set conversion mode
pub const IMN_SETCONVERSIONMODE: u32 = 0x0006;

/// Set sentence mode
pub const IMN_SETSENTENCEMODE: u32 = 0x0007;

/// Set open status
pub const IMN_SETOPENSTATUS: u32 = 0x0008;

/// Set candidate position
pub const IMN_SETCANDIDATEPOS: u32 = 0x0009;

/// Set composition font
pub const IMN_SETCOMPOSITIONFONT: u32 = 0x000A;

/// Set composition window
pub const IMN_SETCOMPOSITIONWINDOW: u32 = 0x000B;

/// Set status window position
pub const IMN_SETSTATUSWINDOWPOS: u32 = 0x000C;

/// Guideline
pub const IMN_GUIDELINE: u32 = 0x000D;

/// Private
pub const IMN_PRIVATE: u32 = 0x000E;

// ============================================================================
// IME Composition Form Style (CFS_*)
// ============================================================================

/// Default position
pub const CFS_DEFAULT: u32 = 0x0000;

/// Rectangle
pub const CFS_RECT: u32 = 0x0001;

/// Point
pub const CFS_POINT: u32 = 0x0002;

/// Force position
pub const CFS_FORCE_POSITION: u32 = 0x0020;

/// Candidate exclude
pub const CFS_CANDIDATEPOS: u32 = 0x0040;

/// Exclude rectangle
pub const CFS_EXCLUDE: u32 = 0x0080;

// ============================================================================
// IME Attribute Values (ATTR_*)
// ============================================================================

/// Input
pub const ATTR_INPUT: u8 = 0x00;

/// Target converted
pub const ATTR_TARGET_CONVERTED: u8 = 0x01;

/// Converted
pub const ATTR_CONVERTED: u8 = 0x02;

/// Target not converted
pub const ATTR_TARGET_NOTCONVERTED: u8 = 0x03;

/// Input error
pub const ATTR_INPUT_ERROR: u8 = 0x04;

/// Fixed converted
pub const ATTR_FIXEDCONVERTED: u8 = 0x05;

// ============================================================================
// IME Configuration (IME_CONFIG_*)
// ============================================================================

/// General
pub const IME_CONFIG_GENERAL: u32 = 1;

/// Register word
pub const IME_CONFIG_REGISTERWORD: u32 = 2;

/// Select symbols
pub const IME_CONFIG_SELECTDICTIONARY: u32 = 3;

// ============================================================================
// IME Property (IGP_*)
// ============================================================================

/// Get property
pub const IGP_GETIMEVERSION: u32 = 0xFFFFFFFE;

/// Property
pub const IGP_PROPERTY: u32 = 0x00000004;

/// Conversion
pub const IGP_CONVERSION: u32 = 0x00000008;

/// Sentence
pub const IGP_SENTENCE: u32 = 0x0000000C;

/// UI
pub const IGP_UI: u32 = 0x00000010;

/// Set composition string
pub const IGP_SETCOMPSTR: u32 = 0x00000014;

/// Select
pub const IGP_SELECT: u32 = 0x00000018;

// ============================================================================
// IME Property Bits (IME_PROP_*)
// ============================================================================

/// At caret
pub const IME_PROP_AT_CARET: u32 = 0x00010000;

/// Special UI
pub const IME_PROP_SPECIAL_UI: u32 = 0x00020000;

/// Candidate per page max
pub const IME_PROP_CANDLIST_START_FROM_1: u32 = 0x00040000;

/// Unicode
pub const IME_PROP_UNICODE: u32 = 0x00080000;

/// Complete on unselect
pub const IME_PROP_COMPLETE_ON_UNSELECT: u32 = 0x00100000;

// ============================================================================
// Constants
// ============================================================================

/// Maximum input contexts
pub const MAX_INPUT_CONTEXTS: usize = 64;

/// Maximum composition string length
pub const MAX_COMP_STRING: usize = 256;

/// Maximum candidate strings
pub const MAX_CANDIDATES: usize = 10;

/// Maximum candidate string length
pub const MAX_CANDIDATE_LEN: usize = 64;

// ============================================================================
// Composition Form
// ============================================================================

/// Composition form
#[derive(Clone, Copy)]
pub struct CompositionForm {
    /// Style (CFS_*)
    pub style: u32,
    /// Current position
    pub pt_current_pos: Point,
    /// Rectangle
    pub rc_area: Rect,
}

impl CompositionForm {
    /// Create default form
    pub const fn new() -> Self {
        Self {
            style: CFS_DEFAULT,
            pt_current_pos: Point { x: 0, y: 0 },
            rc_area: Rect {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
        }
    }
}

// ============================================================================
// Candidate Form
// ============================================================================

/// Candidate form
#[derive(Clone, Copy)]
pub struct CandidateForm {
    /// Candidate list index
    pub index: u32,
    /// Style
    pub style: u32,
    /// Current position
    pub pt_current_pos: Point,
    /// Exclude area
    pub rc_area: Rect,
}

impl CandidateForm {
    /// Create default form
    pub const fn new() -> Self {
        Self {
            index: 0,
            style: CFS_DEFAULT,
            pt_current_pos: Point { x: 0, y: 0 },
            rc_area: Rect {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
        }
    }
}

// ============================================================================
// Candidate List
// ============================================================================

/// Candidate list
#[derive(Clone)]
pub struct CandidateList {
    /// Is active
    pub active: bool,
    /// Size
    pub size: u32,
    /// Style (IME_CAND_*)
    pub style: u32,
    /// Number of candidates
    pub count: u32,
    /// Current selection
    pub selection: u32,
    /// Page start
    pub page_start: u32,
    /// Page size
    pub page_size: u32,
    /// Candidate strings
    pub candidates: [[u8; MAX_CANDIDATE_LEN]; MAX_CANDIDATES],
}

impl CandidateList {
    /// Create empty list
    pub const fn new() -> Self {
        Self {
            active: false,
            size: 0,
            style: IME_CAND_UNKNOWN,
            count: 0,
            selection: 0,
            page_start: 0,
            page_size: 5,
            candidates: [[0; MAX_CANDIDATE_LEN]; MAX_CANDIDATES],
        }
    }

    /// Add candidate
    pub fn add_candidate(&mut self, candidate: &[u8]) -> bool {
        if self.count as usize >= MAX_CANDIDATES {
            return false;
        }

        let len = super::strhelp::str_len(candidate).min(MAX_CANDIDATE_LEN - 1);
        let idx = self.count as usize;
        self.candidates[idx][..len].copy_from_slice(&candidate[..len]);
        self.candidates[idx][len] = 0;
        self.count += 1;

        true
    }

    /// Get candidate
    pub fn get_candidate(&self, index: u32) -> Option<&[u8]> {
        if index < self.count {
            Some(&self.candidates[index as usize])
        } else {
            None
        }
    }

    /// Clear list
    pub fn clear(&mut self) {
        self.count = 0;
        self.selection = 0;
        self.page_start = 0;
        self.active = false;
    }
}

// ============================================================================
// Input Context
// ============================================================================

/// Input Method Context
#[derive(Clone)]
pub struct InputContext {
    /// Is this slot in use
    pub in_use: bool,
    /// Handle value
    pub handle: HIMC,
    /// Associated window
    pub hwnd: HWND,
    /// Is open (IME active)
    pub open: bool,
    /// Conversion mode
    pub conversion_mode: u32,
    /// Sentence mode
    pub sentence_mode: u32,
    /// Composition string
    pub comp_str: [u8; MAX_COMP_STRING],
    /// Composition string length
    pub comp_str_len: usize,
    /// Composition attributes
    pub comp_attr: [u8; MAX_COMP_STRING],
    /// Cursor position in composition
    pub cursor_pos: u32,
    /// Delta start position
    pub delta_start: u32,
    /// Result string
    pub result_str: [u8; MAX_COMP_STRING],
    /// Result string length
    pub result_str_len: usize,
    /// Composition form
    pub comp_form: CompositionForm,
    /// Candidate form
    pub cand_form: [CandidateForm; 4],
    /// Candidate lists
    pub cand_list: [CandidateList; 4],
    /// Status window position
    pub status_pos: Point,
    /// Soft keyboard window position
    pub soft_kbd_pos: Point,
}

impl InputContext {
    /// Create empty context
    pub const fn new() -> Self {
        Self {
            in_use: false,
            handle: NULL_HIMC,
            hwnd: UserHandle::NULL,
            open: false,
            conversion_mode: IME_CMODE_ALPHANUMERIC,
            sentence_mode: IME_SMODE_NONE,
            comp_str: [0; MAX_COMP_STRING],
            comp_str_len: 0,
            comp_attr: [0; MAX_COMP_STRING],
            cursor_pos: 0,
            delta_start: 0,
            result_str: [0; MAX_COMP_STRING],
            result_str_len: 0,
            comp_form: CompositionForm::new(),
            cand_form: [const { CandidateForm::new() }; 4],
            cand_list: [const { CandidateList::new() }; 4],
            status_pos: Point { x: 0, y: 0 },
            soft_kbd_pos: Point { x: 0, y: 0 },
        }
    }

    /// Clear composition
    pub fn clear_composition(&mut self) {
        self.comp_str = [0; MAX_COMP_STRING];
        self.comp_str_len = 0;
        self.comp_attr = [0; MAX_COMP_STRING];
        self.cursor_pos = 0;
        self.delta_start = 0;
    }

    /// Clear result
    pub fn clear_result(&mut self) {
        self.result_str = [0; MAX_COMP_STRING];
        self.result_str_len = 0;
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global input contexts
static INPUT_CONTEXTS: SpinLock<[InputContext; MAX_INPUT_CONTEXTS]> =
    SpinLock::new([const { InputContext::new() }; MAX_INPUT_CONTEXTS]);

/// Next handle value
static NEXT_HANDLE: SpinLock<HIMC> = SpinLock::new(1);

/// Default input context per window storage
static DEFAULT_CONTEXTS: SpinLock<[(HWND, HIMC); 64]> =
    SpinLock::new([(UserHandle::NULL, NULL_HIMC); 64]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize IME support
pub fn init() {
    crate::serial_println!("[USER] IME support initialized");
}

/// Get input context for window
pub fn imm_get_context(hwnd: HWND) -> HIMC {
    // Check if window has a default context
    let defaults = DEFAULT_CONTEXTS.lock();

    for &(w, h) in defaults.iter() {
        if w == hwnd && h != NULL_HIMC {
            return h;
        }
    }

    // No context, create one
    drop(defaults);
    imm_create_context()
}

/// Release input context
pub fn imm_release_context(hwnd: HWND, himc: HIMC) -> bool {
    let _ = (hwnd, himc);
    // Contexts are managed, just return success
    true
}

/// Create new input context
pub fn imm_create_context() -> HIMC {
    let mut contexts = INPUT_CONTEXTS.lock();
    let mut next = NEXT_HANDLE.lock();

    for ctx in contexts.iter_mut() {
        if !ctx.in_use {
            let handle = *next;
            *next += 1;

            ctx.in_use = true;
            ctx.handle = handle;
            ctx.hwnd = UserHandle::NULL;
            ctx.open = false;
            ctx.conversion_mode = IME_CMODE_ALPHANUMERIC;
            ctx.sentence_mode = IME_SMODE_NONE;
            ctx.clear_composition();
            ctx.clear_result();

            return handle;
        }
    }

    NULL_HIMC
}

/// Destroy input context
pub fn imm_destroy_context(himc: HIMC) -> bool {
    if himc == NULL_HIMC {
        return false;
    }

    let mut contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter_mut() {
        if ctx.in_use && ctx.handle == himc {
            *ctx = InputContext::new();
            return true;
        }
    }

    false
}

/// Associate context with window
pub fn imm_associate_context(hwnd: HWND, himc: HIMC) -> HIMC {
    let mut defaults = DEFAULT_CONTEXTS.lock();

    // Find existing association
    for entry in defaults.iter_mut() {
        if entry.0 == hwnd {
            let old = entry.1;
            entry.1 = himc;
            return old;
        }
    }

    // Create new association
    for entry in defaults.iter_mut() {
        if entry.0 == UserHandle::NULL {
            entry.0 = hwnd;
            entry.1 = himc;
            return NULL_HIMC;
        }
    }

    NULL_HIMC
}

/// Associate context with window (extended)
pub fn imm_associate_context_ex(hwnd: HWND, himc: HIMC, flags: u32) -> bool {
    let _ = flags;
    imm_associate_context(hwnd, himc);
    true
}

/// Get open status
pub fn imm_get_open_status(himc: HIMC) -> bool {
    if himc == NULL_HIMC {
        return false;
    }

    let contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter() {
        if ctx.in_use && ctx.handle == himc {
            return ctx.open;
        }
    }

    false
}

/// Set open status
pub fn imm_set_open_status(himc: HIMC, open: bool) -> bool {
    if himc == NULL_HIMC {
        return false;
    }

    let mut contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter_mut() {
        if ctx.in_use && ctx.handle == himc {
            ctx.open = open;
            return true;
        }
    }

    false
}

/// Get conversion status
pub fn imm_get_conversion_status(himc: HIMC, conversion: &mut u32, sentence: &mut u32) -> bool {
    if himc == NULL_HIMC {
        return false;
    }

    let contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter() {
        if ctx.in_use && ctx.handle == himc {
            *conversion = ctx.conversion_mode;
            *sentence = ctx.sentence_mode;
            return true;
        }
    }

    false
}

/// Set conversion status
pub fn imm_set_conversion_status(himc: HIMC, conversion: u32, sentence: u32) -> bool {
    if himc == NULL_HIMC {
        return false;
    }

    let mut contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter_mut() {
        if ctx.in_use && ctx.handle == himc {
            ctx.conversion_mode = conversion;
            ctx.sentence_mode = sentence;
            return true;
        }
    }

    false
}

/// Get composition string
pub fn imm_get_composition_string(himc: HIMC, index: u32, buffer: &mut [u8]) -> i32 {
    if himc == NULL_HIMC {
        return -1;
    }

    let contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter() {
        if ctx.in_use && ctx.handle == himc {
            match index {
                GCS_COMPSTR => {
                    let len = ctx.comp_str_len.min(buffer.len());
                    buffer[..len].copy_from_slice(&ctx.comp_str[..len]);
                    return len as i32;
                }
                GCS_COMPATTR => {
                    let len = ctx.comp_str_len.min(buffer.len());
                    buffer[..len].copy_from_slice(&ctx.comp_attr[..len]);
                    return len as i32;
                }
                GCS_RESULTSTR => {
                    let len = ctx.result_str_len.min(buffer.len());
                    buffer[..len].copy_from_slice(&ctx.result_str[..len]);
                    return len as i32;
                }
                GCS_CURSORPOS => {
                    return ctx.cursor_pos as i32;
                }
                GCS_DELTASTART => {
                    return ctx.delta_start as i32;
                }
                _ => return 0,
            }
        }
    }

    -1
}

/// Set composition string
pub fn imm_set_composition_string(
    himc: HIMC,
    index: u32,
    comp: Option<&[u8]>,
    read: Option<&[u8]>,
) -> bool {
    let _ = read;

    if himc == NULL_HIMC {
        return false;
    }

    let mut contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter_mut() {
        if ctx.in_use && ctx.handle == himc {
            if let Some(comp_data) = comp {
                match index {
                    GCS_COMPSTR => {
                        let len = comp_data.len().min(MAX_COMP_STRING - 1);
                        ctx.comp_str[..len].copy_from_slice(&comp_data[..len]);
                        ctx.comp_str[len] = 0;
                        ctx.comp_str_len = len;
                        return true;
                    }
                    GCS_RESULTSTR => {
                        let len = comp_data.len().min(MAX_COMP_STRING - 1);
                        ctx.result_str[..len].copy_from_slice(&comp_data[..len]);
                        ctx.result_str[len] = 0;
                        ctx.result_str_len = len;
                        return true;
                    }
                    _ => {}
                }
            }
            return false;
        }
    }

    false
}

/// Get composition form
pub fn imm_get_composition_window(himc: HIMC, form: &mut CompositionForm) -> bool {
    if himc == NULL_HIMC {
        return false;
    }

    let contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter() {
        if ctx.in_use && ctx.handle == himc {
            *form = ctx.comp_form;
            return true;
        }
    }

    false
}

/// Set composition form
pub fn imm_set_composition_window(himc: HIMC, form: &CompositionForm) -> bool {
    if himc == NULL_HIMC {
        return false;
    }

    let mut contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter_mut() {
        if ctx.in_use && ctx.handle == himc {
            ctx.comp_form = *form;
            return true;
        }
    }

    false
}

/// Get candidate form
pub fn imm_get_candidate_window(himc: HIMC, index: u32, form: &mut CandidateForm) -> bool {
    if himc == NULL_HIMC || index >= 4 {
        return false;
    }

    let contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter() {
        if ctx.in_use && ctx.handle == himc {
            *form = ctx.cand_form[index as usize];
            return true;
        }
    }

    false
}

/// Set candidate form
pub fn imm_set_candidate_window(himc: HIMC, form: &CandidateForm) -> bool {
    if himc == NULL_HIMC || form.index >= 4 {
        return false;
    }

    let mut contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter_mut() {
        if ctx.in_use && ctx.handle == himc {
            ctx.cand_form[form.index as usize] = *form;
            return true;
        }
    }

    false
}

/// Get candidate list count
pub fn imm_get_candidate_list_count(himc: HIMC, list_count: &mut u32) -> u32 {
    if himc == NULL_HIMC {
        *list_count = 0;
        return 0;
    }

    let contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter() {
        if ctx.in_use && ctx.handle == himc {
            let mut count = 0u32;
            let mut total_size = 0u32;

            for list in ctx.cand_list.iter() {
                if list.active {
                    count += 1;
                    total_size += list.size;
                }
            }

            *list_count = count;
            return total_size;
        }
    }

    *list_count = 0;
    0
}

/// Get candidate list
pub fn imm_get_candidate_list(
    himc: HIMC,
    index: u32,
    buffer: &mut [u8],
) -> u32 {
    if himc == NULL_HIMC || index >= 4 {
        return 0;
    }

    let contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter() {
        if ctx.in_use && ctx.handle == himc {
            let list = &ctx.cand_list[index as usize];
            if !list.active {
                return 0;
            }

            // Copy candidate strings to buffer
            let mut offset = 0usize;
            for i in 0..list.count {
                if let Some(cand) = list.get_candidate(i) {
                    let len = super::strhelp::str_len(cand);
                    if offset + len + 1 > buffer.len() {
                        break;
                    }
                    buffer[offset..offset + len].copy_from_slice(&cand[..len]);
                    buffer[offset + len] = 0;
                    offset += len + 1;
                }
            }

            return offset as u32;
        }
    }

    0
}

/// Notify IME
pub fn imm_notify_ime(himc: HIMC, action: u32, index: u32, value: u32) -> bool {
    let _ = (index, value);

    if himc == NULL_HIMC {
        return false;
    }

    let mut contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter_mut() {
        if ctx.in_use && ctx.handle == himc {
            match action {
                // CPS_COMPLETE - finalize composition
                0x0001 => {
                    // Copy composition to result
                    ctx.result_str = ctx.comp_str;
                    ctx.result_str_len = ctx.comp_str_len;
                    ctx.clear_composition();
                    return true;
                }
                // CPS_CANCEL - cancel composition
                0x0004 => {
                    ctx.clear_composition();
                    return true;
                }
                _ => {}
            }
            return true;
        }
    }

    false
}

/// Get status window position
pub fn imm_get_status_window_pos(himc: HIMC, pt: &mut Point) -> bool {
    if himc == NULL_HIMC {
        return false;
    }

    let contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter() {
        if ctx.in_use && ctx.handle == himc {
            *pt = ctx.status_pos;
            return true;
        }
    }

    false
}

/// Set status window position
pub fn imm_set_status_window_pos(himc: HIMC, pt: &Point) -> bool {
    if himc == NULL_HIMC {
        return false;
    }

    let mut contexts = INPUT_CONTEXTS.lock();

    for ctx in contexts.iter_mut() {
        if ctx.in_use && ctx.handle == himc {
            ctx.status_pos = *pt;
            return true;
        }
    }

    false
}

/// Get default IME window
pub fn imm_get_default_ime_wnd(hwnd: HWND) -> HWND {
    let _ = hwnd;
    // In a real implementation, would return the IME window
    UserHandle::NULL
}

/// Get virtual key
pub fn imm_get_virtual_key(hwnd: HWND) -> u32 {
    let _ = hwnd;
    0
}

/// Simulate key input
pub fn imm_simulate_hot_key(hwnd: HWND, hot_key_id: u32) -> bool {
    let _ = (hwnd, hot_key_id);
    false
}

/// Is IME enabled
pub fn imm_is_ime() -> bool {
    // Return true to indicate IME is available
    true
}

/// Get property
pub fn imm_get_property(hkl: HKL, index: u32) -> u32 {
    let _ = hkl;

    match index {
        IGP_PROPERTY => IME_PROP_UNICODE,
        IGP_CONVERSION => IME_CMODE_NATIVE | IME_CMODE_FULLSHAPE | IME_CMODE_KATAKANA,
        IGP_SENTENCE => IME_SMODE_PHRASEPREDICT,
        IGP_UI => 0,
        IGP_SETCOMPSTR => GCS_COMPSTR | GCS_RESULTSTR,
        IGP_SELECT => 0,
        _ => 0,
    }
}

/// Get description
pub fn imm_get_description(hkl: HKL, buffer: &mut [u8]) -> usize {
    let _ = hkl;

    let desc = b"Default IME";
    let len = desc.len().min(buffer.len().saturating_sub(1));
    buffer[..len].copy_from_slice(&desc[..len]);
    if len < buffer.len() {
        buffer[len] = 0;
    }
    len
}

/// Get IME file name
pub fn imm_get_ime_file_name(hkl: HKL, buffer: &mut [u8]) -> usize {
    let _ = hkl;

    let name = b"imm32.dll";
    let len = name.len().min(buffer.len().saturating_sub(1));
    buffer[..len].copy_from_slice(&name[..len]);
    if len < buffer.len() {
        buffer[len] = 0;
    }
    len
}

/// Install IME
pub fn imm_install_ime(_ime_file: &[u8], _layout_text: &[u8]) -> HKL {
    // Would install IME, for now just return a fake handle
    0x04090409 // en-US keyboard
}

/// Check if window is an IME window
pub fn imm_is_ui_message(hwnd: HWND, msg: u32, _wparam: usize, _lparam: usize) -> bool {
    let _ = hwnd;

    // WM_IME_* messages range
    match msg {
        0x010D..=0x010F | 0x0281..=0x0284 => true,
        _ => false,
    }
}

/// Disable IME for thread
pub fn imm_disable_ime(thread_id: u32) -> bool {
    let _ = thread_id;
    true
}

/// Disable text frame service
pub fn imm_disable_text_frame_service(thread_id: u32) -> bool {
    let _ = thread_id;
    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> ImeStats {
    let contexts = INPUT_CONTEXTS.lock();

    let mut count = 0;
    let mut open_count = 0;

    for ctx in contexts.iter() {
        if ctx.in_use {
            count += 1;
            if ctx.open {
                open_count += 1;
            }
        }
    }

    ImeStats {
        max_contexts: MAX_INPUT_CONTEXTS,
        active_contexts: count,
        open_contexts: open_count,
    }
}

/// IME statistics
#[derive(Debug, Clone, Copy)]
pub struct ImeStats {
    pub max_contexts: usize,
    pub active_contexts: usize,
    pub open_contexts: usize,
}
