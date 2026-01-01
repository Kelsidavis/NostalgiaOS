//! Custom Draw Support Implementation
//!
//! Windows Custom Draw for owner-drawn control rendering.
//! Based on Windows Server 2003 commctrl.h.
//!
//! # Features
//!
//! - Draw stage notifications
//! - Item-level customization
//! - Sub-item drawing
//! - Font and color overrides
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - NMCUSTOMDRAW structure

use super::super::{UserHandle, HWND, Rect, ColorRef, GdiHandle};

// ============================================================================
// Custom Draw Draw Stage (CDDS_*)
// ============================================================================

/// Pre-paint stage
pub const CDDS_PREPAINT: u32 = 0x00000001;

/// Post-paint stage
pub const CDDS_POSTPAINT: u32 = 0x00000002;

/// Pre-erase stage
pub const CDDS_PREERASE: u32 = 0x00000003;

/// Post-erase stage
pub const CDDS_POSTERASE: u32 = 0x00000004;

/// Item stage
pub const CDDS_ITEM: u32 = 0x00010000;

/// Item pre-paint
pub const CDDS_ITEMPREPAINT: u32 = CDDS_ITEM | CDDS_PREPAINT;

/// Item post-paint
pub const CDDS_ITEMPOSTPAINT: u32 = CDDS_ITEM | CDDS_POSTPAINT;

/// Item pre-erase
pub const CDDS_ITEMPREERASE: u32 = CDDS_ITEM | CDDS_PREERASE;

/// Item post-erase
pub const CDDS_ITEMPOSTERASE: u32 = CDDS_ITEM | CDDS_POSTERASE;

/// Sub-item stage
pub const CDDS_SUBITEM: u32 = 0x00020000;

// ============================================================================
// Custom Draw Return Values (CDRF_*)
// ============================================================================

/// Use default processing
pub const CDRF_DODEFAULT: u32 = 0x00000000;

/// Application drew item
pub const CDRF_SKIPDEFAULT: u32 = 0x00000004;

/// Notify for each item
pub const CDRF_NOTIFYPOSTPAINT: u32 = 0x00000010;

/// Notify for each item before
pub const CDRF_NOTIFYITEMDRAW: u32 = 0x00000020;

/// Notify for each sub-item
pub const CDRF_NOTIFYSUBITEMDRAW: u32 = 0x00000020;

/// Notify after erase
pub const CDRF_NOTIFYPOSTERASE: u32 = 0x00000040;

/// New font selected
pub const CDRF_NEWFONT: u32 = 0x00000002;

/// Skip post-paint
pub const CDRF_SKIPPOSTPAINT: u32 = 0x00000100;

// ============================================================================
// Custom Draw Item State (CDIS_*)
// ============================================================================

/// Item is selected
pub const CDIS_SELECTED: u32 = 0x0001;

/// Item is grayed
pub const CDIS_GRAYED: u32 = 0x0002;

/// Item is disabled
pub const CDIS_DISABLED: u32 = 0x0004;

/// Item is checked
pub const CDIS_CHECKED: u32 = 0x0008;

/// Item has focus
pub const CDIS_FOCUS: u32 = 0x0010;

/// Item is default
pub const CDIS_DEFAULT: u32 = 0x0020;

/// Item is hot (mouse over)
pub const CDIS_HOT: u32 = 0x0040;

/// Item is marked
pub const CDIS_MARKED: u32 = 0x0080;

/// Item is indeterminate
pub const CDIS_INDETERMINATE: u32 = 0x0100;

/// Show keyboard accelerator
pub const CDIS_SHOWKEYBOARDCUES: u32 = 0x0200;

/// Item is nested
pub const CDIS_NEARHOT: u32 = 0x0400;

/// Item is other hot
pub const CDIS_OTHERSIDEHOT: u32 = 0x0800;

/// Item is drop hilited
pub const CDIS_DROPHILITED: u32 = 0x1000;

// ============================================================================
// NMCUSTOMDRAW Structure
// ============================================================================

/// Custom draw notification data
#[derive(Clone, Copy)]
pub struct NmCustomDraw {
    /// Notification header - hwnd from
    pub hwnd_from: HWND,
    /// Notification header - control id
    pub id_from: usize,
    /// Notification header - notification code
    pub code: u32,
    /// Draw stage
    pub draw_stage: u32,
    /// Device context handle
    pub hdc: GdiHandle,
    /// Bounding rectangle
    pub rc: Rect,
    /// Item spec (item number or pointer)
    pub item_spec: usize,
    /// Item state
    pub item_state: u32,
    /// Item lparam
    pub lparam: isize,
}

impl NmCustomDraw {
    /// Create new custom draw structure
    pub const fn new() -> Self {
        Self {
            hwnd_from: UserHandle::NULL,
            id_from: 0,
            code: 0,
            draw_stage: 0,
            hdc: GdiHandle::NULL,
            rc: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            item_spec: 0,
            item_state: 0,
            lparam: 0,
        }
    }

    /// Check if this is pre-paint stage
    pub fn is_prepaint(&self) -> bool {
        (self.draw_stage & 0xFFFF) == CDDS_PREPAINT
    }

    /// Check if this is post-paint stage
    pub fn is_postpaint(&self) -> bool {
        (self.draw_stage & 0xFFFF) == CDDS_POSTPAINT
    }

    /// Check if this is item stage
    pub fn is_item(&self) -> bool {
        (self.draw_stage & CDDS_ITEM) != 0
    }

    /// Check if this is sub-item stage
    pub fn is_subitem(&self) -> bool {
        (self.draw_stage & CDDS_SUBITEM) != 0
    }

    /// Check if item is selected
    pub fn is_selected(&self) -> bool {
        (self.item_state & CDIS_SELECTED) != 0
    }

    /// Check if item has focus
    pub fn is_focused(&self) -> bool {
        (self.item_state & CDIS_FOCUS) != 0
    }

    /// Check if item is hot
    pub fn is_hot(&self) -> bool {
        (self.item_state & CDIS_HOT) != 0
    }

    /// Check if item is disabled
    pub fn is_disabled(&self) -> bool {
        (self.item_state & CDIS_DISABLED) != 0
    }
}

// ============================================================================
// NMTVCUSTOMDRAW Structure (TreeView)
// ============================================================================

/// TreeView custom draw structure
#[derive(Clone, Copy)]
pub struct NmTvCustomDraw {
    /// Base custom draw
    pub nmcd: NmCustomDraw,
    /// Text color
    pub clr_text: ColorRef,
    /// Background color
    pub clr_text_bk: ColorRef,
    /// Tree item level (0 = root)
    pub level: i32,
}

impl NmTvCustomDraw {
    /// Create new treeview custom draw
    pub const fn new() -> Self {
        Self {
            nmcd: NmCustomDraw::new(),
            clr_text: ColorRef(0),
            clr_text_bk: ColorRef(0xFFFFFF),
            level: 0,
        }
    }
}

// ============================================================================
// NMLVCUSTOMDRAW Structure (ListView)
// ============================================================================

/// ListView custom draw structure
#[derive(Clone, Copy)]
pub struct NmLvCustomDraw {
    /// Base custom draw
    pub nmcd: NmCustomDraw,
    /// Text color
    pub clr_text: ColorRef,
    /// Background color
    pub clr_text_bk: ColorRef,
    /// Sub-item index
    pub sub_item: i32,
    /// Item type
    pub item_type: u32,
    /// Text color for group header
    pub clr_face: ColorRef,
    /// Icon effect
    pub icon_effect: i32,
    /// Icon phase
    pub icon_phase: i32,
    /// Align
    pub align: i32,
}

impl NmLvCustomDraw {
    /// Create new listview custom draw
    pub const fn new() -> Self {
        Self {
            nmcd: NmCustomDraw::new(),
            clr_text: ColorRef(0),
            clr_text_bk: ColorRef(0xFFFFFF),
            sub_item: 0,
            item_type: 0,
            clr_face: ColorRef(0),
            icon_effect: 0,
            icon_phase: 0,
            align: 0,
        }
    }
}

// ============================================================================
// NMTBCUSTOMDRAW Structure (Toolbar)
// ============================================================================

/// Toolbar custom draw structure
#[derive(Clone, Copy)]
pub struct NmTbCustomDraw {
    /// Base custom draw
    pub nmcd: NmCustomDraw,
    /// Brush for button background
    pub hbr_mono_dither: GdiHandle,
    /// Brush for lines
    pub hbr_lines: GdiHandle,
    /// Pen for button highlight
    pub hpen_lines: GdiHandle,
    /// Text color
    pub clr_text: ColorRef,
    /// Mark color
    pub clr_mark: ColorRef,
    /// Background color
    pub clr_text_highlight: ColorRef,
    /// Button text color
    pub clr_btn_face: ColorRef,
    /// Button highlight color
    pub clr_btn_highlight: ColorRef,
    /// Highlight hot track color
    pub clr_highlight_hot_track: ColorRef,
    /// Rectangle offset
    pub rc_text: Rect,
    /// Draw flags
    pub draw_flags: i32,
}

impl NmTbCustomDraw {
    /// Create new toolbar custom draw
    pub const fn new() -> Self {
        Self {
            nmcd: NmCustomDraw::new(),
            hbr_mono_dither: GdiHandle::NULL,
            hbr_lines: GdiHandle::NULL,
            hpen_lines: GdiHandle::NULL,
            clr_text: ColorRef(0),
            clr_mark: ColorRef(0),
            clr_text_highlight: ColorRef(0),
            clr_btn_face: ColorRef(0xC0C0C0),
            clr_btn_highlight: ColorRef(0xFFFFFF),
            clr_highlight_hot_track: ColorRef(0xFFD700),
            rc_text: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            draw_flags: 0,
        }
    }
}

// ============================================================================
// Custom Draw Helper Functions
// ============================================================================

/// Create a custom draw notification
pub fn create_notification(
    hwnd: HWND,
    id: usize,
    code: u32,
    hdc: GdiHandle,
    rc: &Rect,
    draw_stage: u32,
) -> NmCustomDraw {
    NmCustomDraw {
        hwnd_from: hwnd,
        id_from: id,
        code,
        draw_stage,
        hdc,
        rc: *rc,
        item_spec: 0,
        item_state: 0,
        lparam: 0,
    }
}

/// Process custom draw return value
pub fn process_return(result: u32) -> CustomDrawResult {
    CustomDrawResult {
        skip_default: (result & CDRF_SKIPDEFAULT) != 0,
        notify_postpaint: (result & CDRF_NOTIFYPOSTPAINT) != 0,
        notify_item_draw: (result & CDRF_NOTIFYITEMDRAW) != 0,
        notify_subitem_draw: (result & CDRF_NOTIFYSUBITEMDRAW) != 0,
        new_font: (result & CDRF_NEWFONT) != 0,
        skip_postpaint: (result & CDRF_SKIPPOSTPAINT) != 0,
    }
}

/// Processed custom draw result
#[derive(Debug, Clone, Copy)]
pub struct CustomDrawResult {
    pub skip_default: bool,
    pub notify_postpaint: bool,
    pub notify_item_draw: bool,
    pub notify_subitem_draw: bool,
    pub new_font: bool,
    pub skip_postpaint: bool,
}

impl CustomDrawResult {
    /// Create default result
    pub const fn default() -> Self {
        Self {
            skip_default: false,
            notify_postpaint: false,
            notify_item_draw: false,
            notify_subitem_draw: false,
            new_font: false,
            skip_postpaint: false,
        }
    }
}

/// Get default colors for item state
pub fn get_state_colors(state: u32) -> (ColorRef, ColorRef) {
    if state & CDIS_SELECTED != 0 {
        // Selected: white on blue
        (ColorRef(0xFFFFFF), ColorRef(0x800000))
    } else if state & CDIS_HOT != 0 {
        // Hot: black on light blue
        (ColorRef(0x000000), ColorRef(0xFFE4B5))
    } else if state & CDIS_DISABLED != 0 {
        // Disabled: gray on gray
        (ColorRef(0x808080), ColorRef(0xC0C0C0))
    } else {
        // Normal: black on white
        (ColorRef(0x000000), ColorRef(0xFFFFFF))
    }
}

/// Build item state from flags
pub fn build_item_state(
    selected: bool,
    focused: bool,
    hot: bool,
    disabled: bool,
    checked: bool,
) -> u32 {
    let mut state = 0u32;

    if selected {
        state |= CDIS_SELECTED;
    }
    if focused {
        state |= CDIS_FOCUS;
    }
    if hot {
        state |= CDIS_HOT;
    }
    if disabled {
        state |= CDIS_DISABLED;
    }
    if checked {
        state |= CDIS_CHECKED;
    }

    state
}

/// Initialize custom draw subsystem
pub fn init() {
    crate::serial_println!("[USER] CustomDraw initialized");
}
