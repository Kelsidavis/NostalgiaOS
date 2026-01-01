//! ComboBoxEx Control Implementation
//!
//! Extended ComboBox control with image list support.
//! Based on Windows Server 2003 commctrl.h and ComboBoxEx32.
//!
//! # Features
//!
//! - Image list integration for items
//! - Item indentation
//! - Overlay and selected images
//! - Extended styles
//! - Edit control access
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - CBEM_* messages, CBES_* styles

use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Rect};

// ============================================================================
// ComboBoxEx Item Flags (CBEIF_*)
// ============================================================================

/// Text field is valid
pub const CBEIF_TEXT: u32 = 0x00000001;

/// Image field is valid
pub const CBEIF_IMAGE: u32 = 0x00000002;

/// Selected image field is valid
pub const CBEIF_SELECTEDIMAGE: u32 = 0x00000004;

/// Overlay field is valid
pub const CBEIF_OVERLAY: u32 = 0x00000008;

/// Indent field is valid
pub const CBEIF_INDENT: u32 = 0x00000010;

/// lParam field is valid
pub const CBEIF_LPARAM: u32 = 0x00000020;

/// Set item (for display info)
pub const CBEIF_DI_SETITEM: u32 = 0x10000000;

// ============================================================================
// ComboBoxEx Extended Styles (CBES_EX_*)
// ============================================================================

/// Don't show image in edit portion
pub const CBES_EX_NOEDITIMAGE: u32 = 0x00000001;

/// Don't indent edit to account for image
pub const CBES_EX_NOEDITIMAGEINDENT: u32 = 0x00000002;

/// Use path word break proc
pub const CBES_EX_PATHWORDBREAKPROC: u32 = 0x00000004;

/// No size limit
pub const CBES_EX_NOSIZELIMIT: u32 = 0x00000008;

/// Case sensitive
pub const CBES_EX_CASESENSITIVE: u32 = 0x00000010;

// ============================================================================
// ComboBoxEx Messages
// ============================================================================

/// WM_USER base
pub const WM_USER: u32 = 0x0400;

/// Insert an item (ANSI)
pub const CBEM_INSERTITEMA: u32 = WM_USER + 1;

/// Set image list
pub const CBEM_SETIMAGELIST: u32 = WM_USER + 2;

/// Get image list
pub const CBEM_GETIMAGELIST: u32 = WM_USER + 3;

/// Get item (ANSI)
pub const CBEM_GETITEMA: u32 = WM_USER + 4;

/// Set item (ANSI)
pub const CBEM_SETITEMA: u32 = WM_USER + 5;

/// Delete item (same as CB_DELETESTRING)
pub const CBEM_DELETEITEM: u32 = 0x0144; // CB_DELETESTRING

/// Get combo control handle
pub const CBEM_GETCOMBOCONTROL: u32 = WM_USER + 6;

/// Get edit control handle
pub const CBEM_GETEDITCONTROL: u32 = WM_USER + 7;

/// Set extended style
pub const CBEM_SETEXTENDEDSTYLE: u32 = WM_USER + 14;

/// Get extended style
pub const CBEM_GETEXTENDEDSTYLE: u32 = WM_USER + 9;

/// Check if edit has changed
pub const CBEM_HASEDITCHANGED: u32 = WM_USER + 10;

/// Insert item (Unicode)
pub const CBEM_INSERTITEMW: u32 = WM_USER + 11;

/// Set item (Unicode)
pub const CBEM_SETITEMW: u32 = WM_USER + 12;

/// Get item (Unicode)
pub const CBEM_GETITEMW: u32 = WM_USER + 13;

/// Alias for CBEM_INSERTITEMA
pub const CBEM_INSERTITEM: u32 = CBEM_INSERTITEMA;

/// Alias for CBEM_SETITEMA
pub const CBEM_SETITEM: u32 = CBEM_SETITEMA;

/// Alias for CBEM_GETITEM
pub const CBEM_GETITEM: u32 = CBEM_GETITEMA;

// ============================================================================
// Notifications (CBEN_*)
// ============================================================================

/// First CBEN notification code
pub const CBEN_FIRST: u32 = 0u32.wrapping_sub(800);

/// Get display info (ANSI)
pub const CBEN_GETDISPINFOA: u32 = CBEN_FIRST.wrapping_sub(0);

/// Item inserted
pub const CBEN_INSERTITEM: u32 = CBEN_FIRST.wrapping_sub(1);

/// Item deleted
pub const CBEN_DELETEITEM: u32 = CBEN_FIRST.wrapping_sub(2);

/// Begin editing
pub const CBEN_BEGINEDIT: u32 = CBEN_FIRST.wrapping_sub(4);

/// End editing (ANSI)
pub const CBEN_ENDEDITA: u32 = CBEN_FIRST.wrapping_sub(5);

/// End editing (Unicode)
pub const CBEN_ENDEDITW: u32 = CBEN_FIRST.wrapping_sub(6);

/// Get display info (Unicode)
pub const CBEN_GETDISPINFOW: u32 = CBEN_FIRST.wrapping_sub(7);

/// Drag begin (ANSI)
pub const CBEN_DRAGBEGINA: u32 = CBEN_FIRST.wrapping_sub(8);

/// Drag begin (Unicode)
pub const CBEN_DRAGBEGINW: u32 = CBEN_FIRST.wrapping_sub(9);

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of ComboBoxEx controls
pub const MAX_COMBOBOXEX_CONTROLS: usize = 64;

/// Maximum items per control
pub const MAX_COMBOBOXEX_ITEMS: usize = 256;

/// Maximum item text length
pub const MAX_ITEM_TEXT: usize = 256;

/// ComboBoxEx class name
pub const COMBOBOXEX_CLASS: &str = "ComboBoxEx32";

/// Invalid image index
pub const I_IMAGECALLBACK: i32 = -1;

/// No image
pub const I_IMAGENONE: i32 = -2;

// ============================================================================
// ComboBoxEx Item
// ============================================================================

/// ComboBoxEx item information
#[derive(Clone)]
pub struct ComboBoxExItem {
    /// Item is in use
    pub in_use: bool,
    /// Mask of valid fields
    pub mask: u32,
    /// Item index
    pub item: i32,
    /// Item text
    pub text: [u8; MAX_ITEM_TEXT],
    pub text_len: usize,
    /// Image index
    pub image: i32,
    /// Selected image index
    pub selected_image: i32,
    /// Overlay image index
    pub overlay: i32,
    /// Indentation level
    pub indent: i32,
    /// User data
    pub lparam: isize,
}

impl ComboBoxExItem {
    /// Create a new item
    pub const fn new() -> Self {
        Self {
            in_use: false,
            mask: 0,
            item: -1,
            text: [0u8; MAX_ITEM_TEXT],
            text_len: 0,
            image: I_IMAGENONE,
            selected_image: I_IMAGENONE,
            overlay: 0,
            indent: 0,
            lparam: 0,
        }
    }

    /// Reset item
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Set text
    pub fn set_text(&mut self, text: &[u8]) {
        let len = core::cmp::min(text.len(), MAX_ITEM_TEXT);
        self.text[..len].copy_from_slice(&text[..len]);
        self.text_len = len;
        self.mask |= CBEIF_TEXT;
    }

    /// Get text
    pub fn get_text(&self, buffer: &mut [u8]) -> usize {
        let len = core::cmp::min(self.text_len, buffer.len());
        buffer[..len].copy_from_slice(&self.text[..len]);
        len
    }
}

// ============================================================================
// ComboBoxEx Control Structure
// ============================================================================

/// ComboBoxEx control state
#[derive(Clone)]
pub struct ComboBoxExControl {
    /// Control handle
    pub hwnd: HWND,
    /// Is this slot in use
    pub in_use: bool,
    /// Display rectangle
    pub rect: Rect,
    /// Extended style flags
    pub ex_style: u32,
    /// Items
    pub items: [ComboBoxExItem; MAX_COMBOBOXEX_ITEMS],
    /// Item count
    pub item_count: usize,
    /// Currently selected item
    pub selected: i32,
    /// Image list handle
    pub image_list: usize,
    /// Combo control handle
    pub combo_hwnd: HWND,
    /// Edit control handle
    pub edit_hwnd: HWND,
    /// Edit has changed
    pub edit_changed: bool,
    /// Is dropped down
    pub dropped: bool,
}

impl ComboBoxExControl {
    /// Create a new ComboBoxEx control
    pub const fn new() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            in_use: false,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            ex_style: 0,
            items: [const { ComboBoxExItem::new() }; MAX_COMBOBOXEX_ITEMS],
            item_count: 0,
            selected: -1,
            image_list: 0,
            combo_hwnd: UserHandle::NULL,
            edit_hwnd: UserHandle::NULL,
            edit_changed: false,
            dropped: false,
        }
    }

    /// Reset control to default state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Insert an item
    pub fn insert_item(&mut self, index: i32) -> i32 {
        if self.item_count >= MAX_COMBOBOXEX_ITEMS {
            return -1;
        }

        let insert_pos = if index < 0 || index as usize >= self.item_count {
            self.item_count
        } else {
            index as usize
        };

        // Shift items down
        for i in (insert_pos..self.item_count).rev() {
            self.items[i + 1] = self.items[i].clone();
            self.items[i + 1].item = (i + 1) as i32;
        }

        self.items[insert_pos].reset();
        self.items[insert_pos].in_use = true;
        self.items[insert_pos].item = insert_pos as i32;
        self.item_count += 1;

        insert_pos as i32
    }

    /// Delete an item
    pub fn delete_item(&mut self, index: usize) -> bool {
        if index >= self.item_count {
            return false;
        }

        // Shift items up
        for i in index..self.item_count - 1 {
            self.items[i] = self.items[i + 1].clone();
            self.items[i].item = i as i32;
        }

        self.items[self.item_count - 1].reset();
        self.item_count -= 1;

        // Adjust selection
        if self.selected as usize == index {
            self.selected = -1;
        } else if self.selected as usize > index {
            self.selected -= 1;
        }

        true
    }

    /// Get item count
    pub fn get_count(&self) -> usize {
        self.item_count
    }

    /// Set item
    pub fn set_item(&mut self, index: usize, mask: u32, text: Option<&[u8]>,
                    image: i32, sel_image: i32, overlay: i32, indent: i32, lparam: isize) -> bool {
        if index >= self.item_count {
            return false;
        }

        let item = &mut self.items[index];
        item.mask = mask;

        if mask & CBEIF_TEXT != 0 {
            if let Some(t) = text {
                item.set_text(t);
            }
        }
        if mask & CBEIF_IMAGE != 0 {
            item.image = image;
        }
        if mask & CBEIF_SELECTEDIMAGE != 0 {
            item.selected_image = sel_image;
        }
        if mask & CBEIF_OVERLAY != 0 {
            item.overlay = overlay;
        }
        if mask & CBEIF_INDENT != 0 {
            item.indent = indent;
        }
        if mask & CBEIF_LPARAM != 0 {
            item.lparam = lparam;
        }

        true
    }

    /// Get item text
    pub fn get_item_text(&self, index: usize, buffer: &mut [u8]) -> usize {
        if index >= self.item_count {
            return 0;
        }

        self.items[index].get_text(buffer)
    }

    /// Select an item
    pub fn set_cur_sel(&mut self, index: i32) -> i32 {
        let old = self.selected;

        if index < 0 || index as usize >= self.item_count {
            self.selected = -1;
        } else {
            self.selected = index;
        }

        old
    }

    /// Get current selection
    pub fn get_cur_sel(&self) -> i32 {
        self.selected
    }

    /// Set image list
    pub fn set_image_list(&mut self, himl: usize) -> usize {
        let old = self.image_list;
        self.image_list = himl;
        old
    }

    /// Get image list
    pub fn get_image_list(&self) -> usize {
        self.image_list
    }

    /// Set extended style
    pub fn set_extended_style(&mut self, mask: u32, style: u32) -> u32 {
        let old = self.ex_style;
        if mask == 0 {
            self.ex_style = style;
        } else {
            self.ex_style = (self.ex_style & !mask) | (style & mask);
        }
        old
    }

    /// Get extended style
    pub fn get_extended_style(&self) -> u32 {
        self.ex_style
    }

    /// Check if edit has changed
    pub fn has_edit_changed(&self) -> bool {
        self.edit_changed
    }

    /// Mark edit as changed
    pub fn set_edit_changed(&mut self, changed: bool) {
        self.edit_changed = changed;
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global ComboBoxEx control storage
static COMBOBOXEX_CONTROLS: SpinLock<[ComboBoxExControl; MAX_COMBOBOXEX_CONTROLS]> =
    SpinLock::new([const { ComboBoxExControl::new() }; MAX_COMBOBOXEX_CONTROLS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize ComboBoxEx control subsystem
pub fn init() {
    crate::serial_println!("[USER] ComboBoxEx control initialized");
}

/// Create a ComboBoxEx control
pub fn create_comboboxex(hwnd: HWND, rect: &Rect) -> Option<usize> {
    let mut controls = COMBOBOXEX_CONTROLS.lock();

    for (i, control) in controls.iter_mut().enumerate() {
        if !control.in_use {
            control.reset();
            control.hwnd = hwnd;
            control.in_use = true;
            control.rect = *rect;
            return Some(i);
        }
    }

    None
}

/// Destroy a ComboBoxEx control
pub fn destroy_comboboxex(index: usize) -> bool {
    let mut controls = COMBOBOXEX_CONTROLS.lock();

    if index >= MAX_COMBOBOXEX_CONTROLS {
        return false;
    }

    if controls[index].in_use {
        controls[index].reset();
        true
    } else {
        false
    }
}

/// Insert an item
pub fn insert_item(index: usize, item_index: i32) -> i32 {
    let mut controls = COMBOBOXEX_CONTROLS.lock();

    if index >= MAX_COMBOBOXEX_CONTROLS || !controls[index].in_use {
        return -1;
    }

    controls[index].insert_item(item_index)
}

/// Delete an item
pub fn delete_item(index: usize, item_index: usize) -> bool {
    let mut controls = COMBOBOXEX_CONTROLS.lock();

    if index >= MAX_COMBOBOXEX_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].delete_item(item_index)
}

/// Get item count
pub fn get_count(index: usize) -> usize {
    let controls = COMBOBOXEX_CONTROLS.lock();

    if index >= MAX_COMBOBOXEX_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].item_count
}

/// Set image list
pub fn set_image_list(index: usize, himl: usize) -> usize {
    let mut controls = COMBOBOXEX_CONTROLS.lock();

    if index >= MAX_COMBOBOXEX_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].set_image_list(himl)
}

/// Get image list
pub fn get_image_list(index: usize) -> usize {
    let controls = COMBOBOXEX_CONTROLS.lock();

    if index >= MAX_COMBOBOXEX_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].image_list
}

/// Set extended style
pub fn set_extended_style(index: usize, mask: u32, style: u32) -> u32 {
    let mut controls = COMBOBOXEX_CONTROLS.lock();

    if index >= MAX_COMBOBOXEX_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].set_extended_style(mask, style)
}

/// Get extended style
pub fn get_extended_style(index: usize) -> u32 {
    let controls = COMBOBOXEX_CONTROLS.lock();

    if index >= MAX_COMBOBOXEX_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].ex_style
}

/// Process ComboBoxEx control message
pub fn process_message(index: usize, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        CBEM_INSERTITEMA | CBEM_INSERTITEMW => {
            // wparam is item index or -1 for append
            insert_item(index, wparam as i32) as isize
        }
        CBEM_DELETEITEM => {
            if delete_item(index, wparam) { wparam as isize } else { -1 }
        }
        CBEM_SETIMAGELIST => {
            set_image_list(index, lparam as usize) as isize
        }
        CBEM_GETIMAGELIST => {
            get_image_list(index) as isize
        }
        CBEM_SETEXTENDEDSTYLE => {
            set_extended_style(index, wparam as u32, lparam as u32) as isize
        }
        CBEM_GETEXTENDEDSTYLE => {
            get_extended_style(index) as isize
        }
        CBEM_GETCOMBOCONTROL => {
            let controls = COMBOBOXEX_CONTROLS.lock();
            if index < MAX_COMBOBOXEX_CONTROLS && controls[index].in_use {
                // Return the internal combo control handle
                0 // Would return combo_hwnd in real implementation
            } else {
                0
            }
        }
        CBEM_GETEDITCONTROL => {
            let controls = COMBOBOXEX_CONTROLS.lock();
            if index < MAX_COMBOBOXEX_CONTROLS && controls[index].in_use {
                // Return the internal edit control handle
                0 // Would return edit_hwnd in real implementation
            } else {
                0
            }
        }
        CBEM_HASEDITCHANGED => {
            let controls = COMBOBOXEX_CONTROLS.lock();
            if index < MAX_COMBOBOXEX_CONTROLS && controls[index].in_use {
                if controls[index].edit_changed { 1 } else { 0 }
            } else {
                0
            }
        }
        _ => 0,
    }
}

/// Get statistics
pub fn get_stats() -> ComboBoxExStats {
    let controls = COMBOBOXEX_CONTROLS.lock();

    let mut active_count = 0;
    let mut total_items = 0;

    for control in controls.iter() {
        if control.in_use {
            active_count += 1;
            total_items += control.item_count;
        }
    }

    ComboBoxExStats {
        max_controls: MAX_COMBOBOXEX_CONTROLS,
        active_controls: active_count,
        total_items,
    }
}

/// ComboBoxEx statistics
#[derive(Debug, Clone, Copy)]
pub struct ComboBoxExStats {
    pub max_controls: usize,
    pub active_controls: usize,
    pub total_items: usize,
}
