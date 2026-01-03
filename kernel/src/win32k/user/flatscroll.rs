//! Flat ScrollBar Implementation
//!
//! Windows Flat ScrollBar for themed scrollbar appearance.
//! Based on Windows Server 2003 commctrl.h.
//!
//! # Features
//!
//! - Flat visual style
//! - Hot tracking
//! - Custom colors
//! - Integration with common controls
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - FlatSB_* functions

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, ColorRef};

// ============================================================================
// Flat ScrollBar Styles (WSB_PROP_*)
// ============================================================================

/// Vertical scrollbar style property
pub const WSB_PROP_CYVSCROLL: u32 = 0x00000001;

/// Horizontal scrollbar style property
pub const WSB_PROP_CXHSCROLL: u32 = 0x00000002;

/// Vertical thumb style property
pub const WSB_PROP_CYHSCROLL: u32 = 0x00000004;

/// Horizontal thumb style property
pub const WSB_PROP_CXVSCROLL: u32 = 0x00000008;

/// Horizontal thumb width
pub const WSB_PROP_CXHTHUMB: u32 = 0x00000010;

/// Vertical thumb height
pub const WSB_PROP_CYVTHUMB: u32 = 0x00000020;

/// Vertical scrollbar
pub const WSB_PROP_VBKGCOLOR: u32 = 0x00000040;

/// Horizontal scrollbar
pub const WSB_PROP_HBKGCOLOR: u32 = 0x00000080;

/// Vertical style
pub const WSB_PROP_VSTYLE: u32 = 0x00000100;

/// Horizontal style
pub const WSB_PROP_HSTYLE: u32 = 0x00000200;

/// Window style
pub const WSB_PROP_WINSTYLE: u32 = 0x00000400;

/// Palette
pub const WSB_PROP_PALETTE: u32 = 0x00000800;

/// Mask for all properties
pub const WSB_PROP_MASK: u32 = 0x00000FFF;

// ============================================================================
// Flat ScrollBar Style Values (FSB_*)
// ============================================================================

/// Regular scrollbar (not flat)
pub const FSB_REGULAR_MODE: u32 = 0;

/// Flat mode - always flat appearance
pub const FSB_FLAT_MODE: u32 = 1;

/// Encarta mode - flat with border when hot
pub const FSB_ENCARTA_MODE: u32 = 2;

// ============================================================================
// Scrollbar Types (SB_*)
// ============================================================================

/// Horizontal scrollbar
pub const SB_HORZ: u32 = 0;

/// Vertical scrollbar
pub const SB_VERT: u32 = 1;

/// Both scrollbars
pub const SB_BOTH: u32 = 3;

/// Scrollbar control
pub const SB_CTL: u32 = 2;

// ============================================================================
// Scroll Commands (SB_*)
// ============================================================================

/// Line up/left
pub const SB_LINEUP: u32 = 0;

/// Line down/right
pub const SB_LINEDOWN: u32 = 1;

/// Page up/left
pub const SB_PAGEUP: u32 = 2;

/// Page down/right
pub const SB_PAGEDOWN: u32 = 3;

/// Thumb position
pub const SB_THUMBPOSITION: u32 = 4;

/// Thumb track
pub const SB_THUMBTRACK: u32 = 5;

/// Top/Left
pub const SB_TOP: u32 = 6;

/// Bottom/Right
pub const SB_BOTTOM: u32 = 7;

/// End scroll
pub const SB_ENDSCROLL: u32 = 8;

// ============================================================================
// Scrollbar Info Flags (SIF_*)
// ============================================================================

/// Range
pub const SIF_RANGE: u32 = 0x0001;

/// Page size
pub const SIF_PAGE: u32 = 0x0002;

/// Position
pub const SIF_POS: u32 = 0x0004;

/// Disable no scroll
pub const SIF_DISABLENOSCROLL: u32 = 0x0008;

/// Track position
pub const SIF_TRACKPOS: u32 = 0x0010;

/// All info
pub const SIF_ALL: u32 = SIF_RANGE | SIF_PAGE | SIF_POS | SIF_TRACKPOS;

// ============================================================================
// Constants
// ============================================================================

/// Maximum flat scrollbar controls
pub const MAX_FLAT_SCROLLBARS: usize = 64;

/// Default scrollbar width
pub const DEFAULT_SCROLLBAR_WIDTH: i32 = 16;

/// Default arrow height
pub const DEFAULT_ARROW_HEIGHT: i32 = 16;

/// Minimum thumb size
pub const MIN_THUMB_SIZE: i32 = 8;

// ============================================================================
// Scrollbar Info Structure
// ============================================================================

/// Scrollbar information
#[derive(Clone, Copy, Debug)]
pub struct ScrollInfo {
    /// Minimum position
    pub min: i32,
    /// Maximum position
    pub max: i32,
    /// Page size
    pub page: u32,
    /// Current position
    pub pos: i32,
    /// Track position (during dragging)
    pub track_pos: i32,
}

impl ScrollInfo {
    /// Create default scroll info
    pub const fn new() -> Self {
        Self {
            min: 0,
            max: 100,
            page: 10,
            pos: 0,
            track_pos: 0,
        }
    }

    /// Get scroll range
    pub fn range(&self) -> i32 {
        self.max - self.min
    }

    /// Clamp position to valid range
    pub fn clamp_pos(&self, pos: i32) -> i32 {
        let max_pos = self.max - self.page as i32 + 1;
        pos.max(self.min).min(max_pos.max(self.min))
    }
}

// ============================================================================
// Scrollbar State
// ============================================================================

/// Scrollbar part being tracked
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScrollbarPart {
    #[default]
    None = 0,
    ArrowUp = 1,
    ArrowDown = 2,
    PageUp = 3,
    PageDown = 4,
    Thumb = 5,
}

/// Single scrollbar state
#[derive(Clone, Copy)]
pub struct ScrollbarState {
    /// Scrollbar info
    pub info: ScrollInfo,
    /// Is enabled
    pub enabled: bool,
    /// Is visible
    pub visible: bool,
    /// Current style
    pub style: u32,
    /// Background color
    pub bk_color: ColorRef,
    /// Hot part
    pub hot_part: ScrollbarPart,
    /// Pressed part
    pub pressed_part: ScrollbarPart,
    /// Thumb size (pixels)
    pub thumb_size: i32,
    /// Scrollbar width
    pub width: i32,
}

impl ScrollbarState {
    /// Create default scrollbar state
    pub const fn new() -> Self {
        Self {
            info: ScrollInfo::new(),
            enabled: true,
            visible: true,
            style: FSB_REGULAR_MODE,
            bk_color: ColorRef(0xC0C0C0), // Light gray
            hot_part: ScrollbarPart::None,
            pressed_part: ScrollbarPart::None,
            thumb_size: MIN_THUMB_SIZE,
            width: DEFAULT_SCROLLBAR_WIDTH,
        }
    }

    /// Calculate thumb position and size
    pub fn calc_thumb(&self, track_length: i32) -> (i32, i32) {
        let range = self.info.range();
        if range <= 0 {
            return (0, track_length);
        }

        // Calculate thumb size based on page
        let thumb_size = ((self.info.page as i32 * track_length) / (range + 1))
            .max(MIN_THUMB_SIZE)
            .min(track_length);

        // Calculate thumb position
        let available = track_length - thumb_size;
        let pos_range = range - self.info.page as i32 + 1;
        let thumb_pos = if pos_range > 0 {
            ((self.info.pos - self.info.min) * available) / pos_range
        } else {
            0
        };

        (thumb_pos.max(0).min(available), thumb_size)
    }

    /// Hit test scrollbar
    pub fn hit_test(&self, track_length: i32, pos: i32, arrow_size: i32) -> ScrollbarPart {
        if pos < arrow_size {
            return ScrollbarPart::ArrowUp;
        }

        if pos >= track_length + arrow_size {
            return ScrollbarPart::ArrowDown;
        }

        let track_pos = pos - arrow_size;
        let (thumb_pos, thumb_size) = self.calc_thumb(track_length);

        if track_pos < thumb_pos {
            ScrollbarPart::PageUp
        } else if track_pos >= thumb_pos + thumb_size {
            ScrollbarPart::PageDown
        } else {
            ScrollbarPart::Thumb
        }
    }
}

// ============================================================================
// Flat ScrollBar Control
// ============================================================================

/// Flat scrollbar control state
#[derive(Clone)]
pub struct FlatScrollBar {
    /// Is this slot in use
    pub in_use: bool,
    /// Window handle
    pub hwnd: HWND,
    /// Horizontal scrollbar
    pub horz: ScrollbarState,
    /// Vertical scrollbar
    pub vert: ScrollbarState,
    /// Is initialized
    pub initialized: bool,
    /// Properties mask
    pub props_mask: u32,
}

impl FlatScrollBar {
    /// Create new flat scrollbar
    pub const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle::NULL,
            horz: ScrollbarState::new(),
            vert: ScrollbarState::new(),
            initialized: false,
            props_mask: 0,
        }
    }

    /// Reset state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Get scrollbar for type
    pub fn get_scrollbar(&self, sb_type: u32) -> Option<&ScrollbarState> {
        match sb_type {
            SB_HORZ => Some(&self.horz),
            SB_VERT => Some(&self.vert),
            _ => None,
        }
    }

    /// Get mutable scrollbar for type
    pub fn get_scrollbar_mut(&mut self, sb_type: u32) -> Option<&mut ScrollbarState> {
        match sb_type {
            SB_HORZ => Some(&mut self.horz),
            SB_VERT => Some(&mut self.vert),
            _ => None,
        }
    }

    /// Set scroll info
    pub fn set_scroll_info(&mut self, sb_type: u32, info: &ScrollInfo, mask: u32) -> i32 {
        let sb = match self.get_scrollbar_mut(sb_type) {
            Some(sb) => sb,
            None => return 0,
        };

        if mask & SIF_RANGE != 0 {
            sb.info.min = info.min;
            sb.info.max = info.max;
        }

        if mask & SIF_PAGE != 0 {
            sb.info.page = info.page;
        }

        if mask & SIF_POS != 0 {
            sb.info.pos = sb.info.clamp_pos(info.pos);
        }

        sb.info.pos
    }

    /// Get scroll info
    pub fn get_scroll_info(&self, sb_type: u32, mask: u32) -> Option<ScrollInfo> {
        let sb = self.get_scrollbar(sb_type)?;

        let mut info = ScrollInfo::new();

        if mask & SIF_RANGE != 0 {
            info.min = sb.info.min;
            info.max = sb.info.max;
        }

        if mask & SIF_PAGE != 0 {
            info.page = sb.info.page;
        }

        if mask & SIF_POS != 0 {
            info.pos = sb.info.pos;
        }

        if mask & SIF_TRACKPOS != 0 {
            info.track_pos = sb.info.track_pos;
        }

        Some(info)
    }

    /// Set scroll position
    pub fn set_scroll_pos(&mut self, sb_type: u32, pos: i32) -> i32 {
        let sb = match self.get_scrollbar_mut(sb_type) {
            Some(sb) => sb,
            None => return 0,
        };

        let old_pos = sb.info.pos;
        sb.info.pos = sb.info.clamp_pos(pos);
        old_pos
    }

    /// Get scroll position
    pub fn get_scroll_pos(&self, sb_type: u32) -> i32 {
        match self.get_scrollbar(sb_type) {
            Some(sb) => sb.info.pos,
            None => 0,
        }
    }

    /// Set scroll range
    pub fn set_scroll_range(&mut self, sb_type: u32, min: i32, max: i32) -> bool {
        let sb = match self.get_scrollbar_mut(sb_type) {
            Some(sb) => sb,
            None => return false,
        };

        sb.info.min = min;
        sb.info.max = max;
        sb.info.pos = sb.info.clamp_pos(sb.info.pos);
        true
    }

    /// Enable/disable scrollbar
    pub fn enable_scrollbar(&mut self, sb_type: u32, enable: bool) -> bool {
        match sb_type {
            SB_HORZ => {
                self.horz.enabled = enable;
                true
            }
            SB_VERT => {
                self.vert.enabled = enable;
                true
            }
            SB_BOTH => {
                self.horz.enabled = enable;
                self.vert.enabled = enable;
                true
            }
            _ => false,
        }
    }

    /// Show/hide scrollbar
    pub fn show_scrollbar(&mut self, sb_type: u32, show: bool) -> bool {
        match sb_type {
            SB_HORZ => {
                self.horz.visible = show;
                true
            }
            SB_VERT => {
                self.vert.visible = show;
                true
            }
            SB_BOTH => {
                self.horz.visible = show;
                self.vert.visible = show;
                true
            }
            _ => false,
        }
    }

    /// Get scrollbar property
    pub fn get_prop(&self, prop: u32) -> i32 {
        match prop {
            WSB_PROP_CXVSCROLL => self.vert.width,
            WSB_PROP_CYHSCROLL => self.horz.width,
            WSB_PROP_CYVSCROLL => DEFAULT_ARROW_HEIGHT,
            WSB_PROP_CXHSCROLL => DEFAULT_ARROW_HEIGHT,
            WSB_PROP_CXHTHUMB => self.horz.thumb_size,
            WSB_PROP_CYVTHUMB => self.vert.thumb_size,
            WSB_PROP_VBKGCOLOR => self.vert.bk_color.0 as i32,
            WSB_PROP_HBKGCOLOR => self.horz.bk_color.0 as i32,
            WSB_PROP_VSTYLE => self.vert.style as i32,
            WSB_PROP_HSTYLE => self.horz.style as i32,
            _ => 0,
        }
    }

    /// Set scrollbar property
    pub fn set_prop(&mut self, prop: u32, value: i32) -> bool {
        match prop {
            WSB_PROP_CXVSCROLL => {
                self.vert.width = value.max(1);
                true
            }
            WSB_PROP_CYHSCROLL => {
                self.horz.width = value.max(1);
                true
            }
            WSB_PROP_VBKGCOLOR => {
                self.vert.bk_color = ColorRef(value as u32);
                true
            }
            WSB_PROP_HBKGCOLOR => {
                self.horz.bk_color = ColorRef(value as u32);
                true
            }
            WSB_PROP_VSTYLE => {
                self.vert.style = value as u32;
                true
            }
            WSB_PROP_HSTYLE => {
                self.horz.style = value as u32;
                true
            }
            _ => false,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global flat scrollbar storage
static FLAT_SCROLLBARS: SpinLock<[FlatScrollBar; MAX_FLAT_SCROLLBARS]> =
    SpinLock::new([const { FlatScrollBar::new() }; MAX_FLAT_SCROLLBARS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize FlatScrollBar subsystem
pub fn init() {
    crate::serial_println!("[USER] FlatScrollBar initialized");
}

/// Initialize flat scrollbars for a window
pub fn init_flat_sb(hwnd: HWND) -> bool {
    let mut scrollbars = FLAT_SCROLLBARS.lock();

    // Check if already initialized
    for sb in scrollbars.iter() {
        if sb.in_use && sb.hwnd == hwnd {
            return true;
        }
    }

    // Find free slot
    for sb in scrollbars.iter_mut() {
        if !sb.in_use {
            sb.reset();
            sb.in_use = true;
            sb.hwnd = hwnd;
            sb.initialized = true;
            return true;
        }
    }

    false
}

/// Uninitialize flat scrollbars for a window
pub fn uninit_flat_sb(hwnd: HWND) -> bool {
    let mut scrollbars = FLAT_SCROLLBARS.lock();

    for sb in scrollbars.iter_mut() {
        if sb.in_use && sb.hwnd == hwnd {
            sb.reset();
            return true;
        }
    }

    false
}

/// Find flat scrollbar for window
fn find_flat_sb(hwnd: HWND) -> Option<usize> {
    let scrollbars = FLAT_SCROLLBARS.lock();

    for (i, sb) in scrollbars.iter().enumerate() {
        if sb.in_use && sb.hwnd == hwnd {
            return Some(i);
        }
    }

    None
}

/// Get scroll info
pub fn get_scroll_info(hwnd: HWND, sb_type: u32, mask: u32) -> Option<ScrollInfo> {
    let idx = find_flat_sb(hwnd)?;
    let scrollbars = FLAT_SCROLLBARS.lock();
    scrollbars[idx].get_scroll_info(sb_type, mask)
}

/// Set scroll info
pub fn set_scroll_info(hwnd: HWND, sb_type: u32, info: &ScrollInfo, mask: u32, redraw: bool) -> i32 {
    let idx = match find_flat_sb(hwnd) {
        Some(i) => i,
        None => return 0,
    };

    let mut scrollbars = FLAT_SCROLLBARS.lock();
    let pos = scrollbars[idx].set_scroll_info(sb_type, info, mask);

    let _ = redraw; // Would trigger repaint in real implementation

    pos
}

/// Get scroll position
pub fn get_scroll_pos(hwnd: HWND, sb_type: u32) -> i32 {
    let idx = match find_flat_sb(hwnd) {
        Some(i) => i,
        None => return 0,
    };

    let scrollbars = FLAT_SCROLLBARS.lock();
    scrollbars[idx].get_scroll_pos(sb_type)
}

/// Set scroll position
pub fn set_scroll_pos(hwnd: HWND, sb_type: u32, pos: i32, redraw: bool) -> i32 {
    let idx = match find_flat_sb(hwnd) {
        Some(i) => i,
        None => return 0,
    };

    let mut scrollbars = FLAT_SCROLLBARS.lock();
    let old_pos = scrollbars[idx].set_scroll_pos(sb_type, pos);

    let _ = redraw; // Would trigger repaint in real implementation

    old_pos
}

/// Get scroll range
pub fn get_scroll_range(hwnd: HWND, sb_type: u32) -> Option<(i32, i32)> {
    let idx = find_flat_sb(hwnd)?;
    let scrollbars = FLAT_SCROLLBARS.lock();

    let sb = scrollbars[idx].get_scrollbar(sb_type)?;
    Some((sb.info.min, sb.info.max))
}

/// Set scroll range
pub fn set_scroll_range(hwnd: HWND, sb_type: u32, min: i32, max: i32, redraw: bool) -> bool {
    let idx = match find_flat_sb(hwnd) {
        Some(i) => i,
        None => return false,
    };

    let mut scrollbars = FLAT_SCROLLBARS.lock();
    let result = scrollbars[idx].set_scroll_range(sb_type, min, max);

    let _ = redraw;

    result
}

/// Enable scrollbar arrows
pub fn enable_scroll_bar(hwnd: HWND, sb_type: u32, arrows: u32) -> bool {
    let idx = match find_flat_sb(hwnd) {
        Some(i) => i,
        None => return false,
    };

    let mut scrollbars = FLAT_SCROLLBARS.lock();
    let enable = arrows != 3; // ESB_DISABLE_BOTH = 3
    scrollbars[idx].enable_scrollbar(sb_type, enable)
}

/// Show scrollbar
pub fn show_scroll_bar(hwnd: HWND, sb_type: u32, show: bool) -> bool {
    let idx = match find_flat_sb(hwnd) {
        Some(i) => i,
        None => return false,
    };

    let mut scrollbars = FLAT_SCROLLBARS.lock();
    scrollbars[idx].show_scrollbar(sb_type, show)
}

/// Get scrollbar property
pub fn get_scroll_prop(hwnd: HWND, prop: u32) -> i32 {
    let idx = match find_flat_sb(hwnd) {
        Some(i) => i,
        None => return 0,
    };

    let scrollbars = FLAT_SCROLLBARS.lock();
    scrollbars[idx].get_prop(prop)
}

/// Set scrollbar property
pub fn set_scroll_prop(hwnd: HWND, prop: u32, value: i32, redraw: bool) -> bool {
    let idx = match find_flat_sb(hwnd) {
        Some(i) => i,
        None => return false,
    };

    let mut scrollbars = FLAT_SCROLLBARS.lock();
    let result = scrollbars[idx].set_prop(prop, value);

    let _ = redraw;

    result
}

/// Get statistics
pub fn get_stats() -> FlatScrollStats {
    let scrollbars = FLAT_SCROLLBARS.lock();

    let mut active_count = 0;

    for sb in scrollbars.iter() {
        if sb.in_use {
            active_count += 1;
        }
    }

    FlatScrollStats {
        max_scrollbars: MAX_FLAT_SCROLLBARS,
        active_scrollbars: active_count,
    }
}

/// FlatScrollBar statistics
#[derive(Debug, Clone, Copy)]
pub struct FlatScrollStats {
    pub max_scrollbars: usize,
    pub active_scrollbars: usize,
}
