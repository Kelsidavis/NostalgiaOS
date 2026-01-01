//! Rebar Control Implementation
//!
//! Windows Rebar (coolbar) control for hosting multiple bands with child controls.
//! Based on Windows Server 2003 commctrl.h and ReBarWindow32.
//!
//! # Features
//!
//! - Multiple resizable bands
//! - Gripper-based band reordering
//! - Variable height bands
//! - Band minimization/maximization
//! - Drag and drop support
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - RB_* messages, RBS_* styles, RBBS_* band styles

use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Rect, Point};

// ============================================================================
// Rebar Styles (RBS_*)
// ============================================================================

/// Show tooltips
pub const RBS_TOOLTIPS: u32 = 0x0100;

/// Variable height bands
pub const RBS_VARHEIGHT: u32 = 0x0200;

/// Draw band borders
pub const RBS_BANDBORDERS: u32 = 0x0400;

/// Fixed band order (no dragging)
pub const RBS_FIXEDORDER: u32 = 0x0800;

/// Register for drop target
pub const RBS_REGISTERDROP: u32 = 0x1000;

/// Auto-size to content
pub const RBS_AUTOSIZE: u32 = 0x2000;

/// Always show vertical gripper
pub const RBS_VERTICALGRIPPER: u32 = 0x4000;

/// Double-click toggles band
pub const RBS_DBLCLKTOGGLE: u32 = 0x8000;

// ============================================================================
// Band Styles (RBBS_*)
// ============================================================================

/// Break to new line
pub const RBBS_BREAK: u32 = 0x00000001;

/// Band can't be sized
pub const RBBS_FIXEDSIZE: u32 = 0x00000002;

/// Edge around child window
pub const RBBS_CHILDEDGE: u32 = 0x00000004;

/// Don't show band
pub const RBBS_HIDDEN: u32 = 0x00000008;

/// Don't show when vertical
pub const RBBS_NOVERT: u32 = 0x00000010;

/// Bitmap doesn't move during resize
pub const RBBS_FIXEDBMP: u32 = 0x00000020;

/// Allow vertical autosizing
pub const RBBS_VARIABLEHEIGHT: u32 = 0x00000040;

/// Always show gripper
pub const RBBS_GRIPPERALWAYS: u32 = 0x00000080;

/// Never show gripper
pub const RBBS_NOGRIPPER: u32 = 0x00000100;

/// Show chevron when too small
pub const RBBS_USECHEVRON: u32 = 0x00000200;

/// Hide band title
pub const RBBS_HIDETITLE: u32 = 0x00000400;

/// Top-align band
pub const RBBS_TOPALIGN: u32 = 0x00000800;

// ============================================================================
// Band Info Mask (RBBIM_*)
// ============================================================================

/// Style field is valid
pub const RBBIM_STYLE: u32 = 0x00000001;

/// Colors field is valid
pub const RBBIM_COLORS: u32 = 0x00000002;

/// Text field is valid
pub const RBBIM_TEXT: u32 = 0x00000004;

/// Image field is valid
pub const RBBIM_IMAGE: u32 = 0x00000008;

/// Child field is valid
pub const RBBIM_CHILD: u32 = 0x00000010;

/// Child size field is valid
pub const RBBIM_CHILDSIZE: u32 = 0x00000020;

/// Size field is valid
pub const RBBIM_SIZE: u32 = 0x00000040;

/// Background field is valid
pub const RBBIM_BACKGROUND: u32 = 0x00000080;

/// ID field is valid
pub const RBBIM_ID: u32 = 0x00000100;

/// Ideal size field is valid
pub const RBBIM_IDEALSIZE: u32 = 0x00000200;

/// lParam field is valid
pub const RBBIM_LPARAM: u32 = 0x00000400;

/// Header size field is valid
pub const RBBIM_HEADERSIZE: u32 = 0x00000800;

// ============================================================================
// Rebar Messages
// ============================================================================

/// WM_USER base
pub const WM_USER: u32 = 0x0400;

/// Insert a band (ANSI)
pub const RB_INSERTBANDA: u32 = WM_USER + 1;

/// Delete a band
pub const RB_DELETEBAND: u32 = WM_USER + 2;

/// Get bar info
pub const RB_GETBARINFO: u32 = WM_USER + 3;

/// Set bar info
pub const RB_SETBARINFO: u32 = WM_USER + 4;

/// Set band info (ANSI)
pub const RB_SETBANDINFOA: u32 = WM_USER + 6;

/// Set parent window
pub const RB_SETPARENT: u32 = WM_USER + 7;

/// Hit test
pub const RB_HITTEST: u32 = WM_USER + 8;

/// Get band rectangle
pub const RB_GETRECT: u32 = WM_USER + 9;

/// Insert a band (Unicode)
pub const RB_INSERTBANDW: u32 = WM_USER + 10;

/// Set band info (Unicode)
pub const RB_SETBANDINFOW: u32 = WM_USER + 11;

/// Get band count
pub const RB_GETBANDCOUNT: u32 = WM_USER + 12;

/// Get row count
pub const RB_GETROWCOUNT: u32 = WM_USER + 13;

/// Get row height
pub const RB_GETROWHEIGHT: u32 = WM_USER + 14;

/// Convert ID to index
pub const RB_IDTOINDEX: u32 = WM_USER + 16;

/// Get tooltips handle
pub const RB_GETTOOLTIPS: u32 = WM_USER + 17;

/// Set tooltips handle
pub const RB_SETTOOLTIPS: u32 = WM_USER + 18;

/// Set background color
pub const RB_SETBKCOLOR: u32 = WM_USER + 19;

/// Get background color
pub const RB_GETBKCOLOR: u32 = WM_USER + 20;

/// Set text color
pub const RB_SETTEXTCOLOR: u32 = WM_USER + 21;

/// Get text color
pub const RB_GETTEXTCOLOR: u32 = WM_USER + 22;

/// Size to rectangle
pub const RB_SIZETORECT: u32 = WM_USER + 23;

/// Begin band drag
pub const RB_BEGINDRAG: u32 = WM_USER + 24;

/// End band drag
pub const RB_ENDDRAG: u32 = WM_USER + 25;

/// Move during drag
pub const RB_DRAGMOVE: u32 = WM_USER + 26;

/// Get bar height
pub const RB_GETBARHEIGHT: u32 = WM_USER + 27;

/// Get band info (Unicode)
pub const RB_GETBANDINFOW: u32 = WM_USER + 28;

/// Get band info (ANSI)
pub const RB_GETBANDINFOA: u32 = WM_USER + 29;

/// Minimize band
pub const RB_MINIMIZEBAND: u32 = WM_USER + 30;

/// Maximize band
pub const RB_MAXIMIZEBAND: u32 = WM_USER + 31;

/// Get band borders
pub const RB_GETBANDBORDERS: u32 = WM_USER + 34;

/// Show/hide band
pub const RB_SHOWBAND: u32 = WM_USER + 35;

/// Set palette
pub const RB_SETPALETTE: u32 = WM_USER + 37;

/// Get palette
pub const RB_GETPALETTE: u32 = WM_USER + 38;

/// Move band
pub const RB_MOVEBAND: u32 = WM_USER + 39;

/// Alias for RB_INSERTBANDA
pub const RB_INSERTBAND: u32 = RB_INSERTBANDA;

/// Alias for RB_SETBANDINFOA
pub const RB_SETBANDINFO: u32 = RB_SETBANDINFOA;

/// Alias for RB_GETBANDINFOA
pub const RB_GETBANDINFO: u32 = RB_GETBANDINFOA;

// ============================================================================
// Notifications (RBN_*)
// ============================================================================

/// First RBN notification code
pub const RBN_FIRST: u32 = 0u32.wrapping_sub(831);

/// Height changed
pub const RBN_HEIGHTCHANGE: u32 = RBN_FIRST.wrapping_sub(0);

/// Get object notification
pub const RBN_GETOBJECT: u32 = RBN_FIRST.wrapping_sub(1);

/// Layout changed
pub const RBN_LAYOUTCHANGED: u32 = RBN_FIRST.wrapping_sub(2);

/// Auto-size notification
pub const RBN_AUTOSIZE: u32 = RBN_FIRST.wrapping_sub(3);

/// Begin drag notification
pub const RBN_BEGINDRAG: u32 = RBN_FIRST.wrapping_sub(4);

/// End drag notification
pub const RBN_ENDDRAG: u32 = RBN_FIRST.wrapping_sub(5);

/// Deleting band notification
pub const RBN_DELETINGBAND: u32 = RBN_FIRST.wrapping_sub(6);

/// Deleted band notification
pub const RBN_DELETEDBAND: u32 = RBN_FIRST.wrapping_sub(7);

/// Child size notification
pub const RBN_CHILDSIZE: u32 = RBN_FIRST.wrapping_sub(8);

/// Chevron pushed notification
pub const RBN_CHEVRONPUSHED: u32 = RBN_FIRST.wrapping_sub(10);

// ============================================================================
// Hit Test Results (RBHT_*)
// ============================================================================

/// Nowhere
pub const RBHT_NOWHERE: u32 = 0x0001;

/// On caption
pub const RBHT_CAPTION: u32 = 0x0002;

/// On client area
pub const RBHT_CLIENT: u32 = 0x0003;

/// On gripper
pub const RBHT_GRABBER: u32 = 0x0004;

/// On chevron
pub const RBHT_CHEVRON: u32 = 0x0008;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of Rebar controls
pub const MAX_REBAR_CONTROLS: usize = 32;

/// Maximum bands per rebar
pub const MAX_BANDS: usize = 32;

/// Maximum band text length
pub const MAX_BAND_TEXT: usize = 64;

/// Rebar class name
pub const REBAR_CLASS: &str = "ReBarWindow32";

/// Default gripper width
pub const GRIPPER_WIDTH: i32 = 12;

/// Default band border
pub const BAND_BORDER: i32 = 2;

// ============================================================================
// Band Structure
// ============================================================================

/// Rebar band information
#[derive(Clone)]
pub struct RebarBand {
    /// Band is in use
    pub in_use: bool,
    /// Band style flags
    pub style: u32,
    /// Foreground color
    pub fg_color: u32,
    /// Background color
    pub bg_color: u32,
    /// Band text
    pub text: [u8; MAX_BAND_TEXT],
    pub text_len: usize,
    /// Child window handle
    pub child: HWND,
    /// Minimum child width
    pub min_child_width: i32,
    /// Minimum child height
    pub min_child_height: i32,
    /// Current band width
    pub width: i32,
    /// Ideal width
    pub ideal_width: i32,
    /// Header width
    pub header_width: i32,
    /// Band ID
    pub id: u32,
    /// User data
    pub lparam: isize,
    /// Row this band is on
    pub row: u32,
    /// Calculated rectangle
    pub rect: Rect,
    /// Is minimized
    pub minimized: bool,
}

impl RebarBand {
    /// Create a new band
    pub const fn new() -> Self {
        Self {
            in_use: false,
            style: 0,
            fg_color: 0x000000,
            bg_color: 0xFFFFFF,
            text: [0u8; MAX_BAND_TEXT],
            text_len: 0,
            child: UserHandle::NULL,
            min_child_width: 0,
            min_child_height: 0,
            width: 100,
            ideal_width: 100,
            header_width: 0,
            id: 0,
            lparam: 0,
            row: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            minimized: false,
        }
    }

    /// Reset band
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Check if band is visible
    pub fn is_visible(&self) -> bool {
        self.in_use && (self.style & RBBS_HIDDEN) == 0
    }

    /// Check if band has gripper
    pub fn has_gripper(&self) -> bool {
        if self.style & RBBS_NOGRIPPER != 0 {
            return false;
        }
        if self.style & RBBS_GRIPPERALWAYS != 0 {
            return true;
        }
        // Default: show gripper if not fixed size
        (self.style & RBBS_FIXEDSIZE) == 0
    }

    /// Set text
    pub fn set_text(&mut self, text: &[u8]) {
        let len = core::cmp::min(text.len(), MAX_BAND_TEXT);
        self.text[..len].copy_from_slice(&text[..len]);
        self.text_len = len;
    }
}

// ============================================================================
// Rebar Control Structure
// ============================================================================

/// Rebar control state
#[derive(Clone)]
pub struct RebarControl {
    /// Control handle
    pub hwnd: HWND,
    /// Is this slot in use
    pub in_use: bool,
    /// Control style flags
    pub style: u32,
    /// Display rectangle
    pub rect: Rect,
    /// Parent window
    pub parent: HWND,
    /// Bands
    pub bands: [RebarBand; MAX_BANDS],
    /// Band count
    pub band_count: usize,
    /// Background color
    pub bk_color: u32,
    /// Text color
    pub text_color: u32,
    /// Total height
    pub height: i32,
    /// Row count
    pub row_count: u32,
    /// Currently dragging band index (or -1)
    pub drag_band: i32,
    /// Drag start X position
    pub drag_start_x: i32,
    /// Tooltips handle
    pub tooltips: HWND,
}

impl RebarControl {
    /// Create a new Rebar control
    pub const fn new() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            in_use: false,
            style: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            parent: UserHandle::NULL,
            bands: [const { RebarBand::new() }; MAX_BANDS],
            band_count: 0,
            bk_color: 0xD4D0C8, // Default button face
            text_color: 0x000000,
            height: 0,
            row_count: 1,
            drag_band: -1,
            drag_start_x: 0,
            tooltips: UserHandle::NULL,
        }
    }

    /// Reset control to default state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Insert a band at position
    pub fn insert_band(&mut self, index: usize) -> Option<usize> {
        if self.band_count >= MAX_BANDS {
            return None;
        }

        let insert_pos = if index > self.band_count { self.band_count } else { index };

        // Shift bands down
        for i in (insert_pos..self.band_count).rev() {
            self.bands[i + 1] = self.bands[i].clone();
        }

        self.bands[insert_pos].reset();
        self.bands[insert_pos].in_use = true;
        self.band_count += 1;

        self.layout_bands();
        Some(insert_pos)
    }

    /// Delete a band
    pub fn delete_band(&mut self, index: usize) -> bool {
        if index >= self.band_count {
            return false;
        }

        // Shift bands up
        for i in index..self.band_count - 1 {
            self.bands[i] = self.bands[i + 1].clone();
        }

        self.bands[self.band_count - 1].reset();
        self.band_count -= 1;

        self.layout_bands();
        true
    }

    /// Get band count
    pub fn get_band_count(&self) -> usize {
        self.band_count
    }

    /// Get band by ID
    pub fn id_to_index(&self, id: u32) -> Option<usize> {
        for (i, band) in self.bands[..self.band_count].iter().enumerate() {
            if band.id == id {
                return Some(i);
            }
        }
        None
    }

    /// Layout all bands
    pub fn layout_bands(&mut self) {
        let bar_width = self.rect.right - self.rect.left;
        let mut x = 0;
        let mut y = 0;
        let mut row_height = 0i32;
        let mut current_row = 0u32;

        for i in 0..self.band_count {
            let band = &mut self.bands[i];

            if !band.is_visible() {
                continue;
            }

            // Check for line break
            let band_width = if band.minimized {
                band.header_width + GRIPPER_WIDTH
            } else {
                band.width
            };

            if band.style & RBBS_BREAK != 0 || x + band_width > bar_width {
                // Start new row
                y += row_height;
                x = 0;
                row_height = 0;
                current_row += 1;
            }

            // Calculate band height
            let band_height = band.min_child_height + BAND_BORDER * 2;
            if band_height > row_height {
                row_height = band_height;
            }

            // Set band rectangle
            band.rect.left = self.rect.left + x;
            band.rect.top = self.rect.top + y;
            band.rect.right = band.rect.left + band_width;
            band.rect.bottom = band.rect.top + band_height;
            band.row = current_row;

            x += band_width;
        }

        self.height = y + row_height;
        self.row_count = current_row + 1;
    }

    /// Hit test
    pub fn hit_test(&self, pt: &Point) -> (u32, i32) {
        for (i, band) in self.bands[..self.band_count].iter().enumerate() {
            if !band.is_visible() {
                continue;
            }

            if pt.x >= band.rect.left && pt.x < band.rect.right &&
               pt.y >= band.rect.top && pt.y < band.rect.bottom {
                // Check if on gripper
                if band.has_gripper() {
                    let gripper_right = band.rect.left + GRIPPER_WIDTH;
                    if pt.x < gripper_right {
                        return (RBHT_GRABBER, i as i32);
                    }
                }

                return (RBHT_CLIENT, i as i32);
            }
        }

        (RBHT_NOWHERE, -1)
    }

    /// Get row height
    pub fn get_row_height(&self, row: u32) -> i32 {
        let mut max_height = 0i32;
        for band in &self.bands[..self.band_count] {
            if band.is_visible() && band.row == row {
                let height = band.rect.bottom - band.rect.top;
                if height > max_height {
                    max_height = height;
                }
            }
        }
        max_height
    }

    /// Minimize a band
    pub fn minimize_band(&mut self, index: usize) -> bool {
        if index >= self.band_count {
            return false;
        }
        self.bands[index].minimized = true;
        self.layout_bands();
        true
    }

    /// Maximize a band
    pub fn maximize_band(&mut self, index: usize) -> bool {
        if index >= self.band_count {
            return false;
        }
        self.bands[index].minimized = false;
        self.layout_bands();
        true
    }

    /// Show/hide a band
    pub fn show_band(&mut self, index: usize, show: bool) -> bool {
        if index >= self.band_count {
            return false;
        }

        if show {
            self.bands[index].style &= !RBBS_HIDDEN;
        } else {
            self.bands[index].style |= RBBS_HIDDEN;
        }

        self.layout_bands();
        true
    }

    /// Move a band
    pub fn move_band(&mut self, from: usize, to: usize) -> bool {
        if from >= self.band_count || to >= self.band_count || from == to {
            return false;
        }

        let band = self.bands[from].clone();

        if from < to {
            for i in from..to {
                self.bands[i] = self.bands[i + 1].clone();
            }
        } else {
            for i in (to..from).rev() {
                self.bands[i + 1] = self.bands[i].clone();
            }
        }

        self.bands[to] = band;
        self.layout_bands();
        true
    }

    /// Begin dragging a band
    pub fn begin_drag(&mut self, index: usize, x: i32) -> bool {
        if index >= self.band_count {
            return false;
        }
        if self.style & RBS_FIXEDORDER != 0 {
            return false;
        }

        self.drag_band = index as i32;
        self.drag_start_x = x;
        true
    }

    /// End dragging
    pub fn end_drag(&mut self) {
        self.drag_band = -1;
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global Rebar control storage
static REBAR_CONTROLS: SpinLock<[RebarControl; MAX_REBAR_CONTROLS]> =
    SpinLock::new([const { RebarControl::new() }; MAX_REBAR_CONTROLS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize Rebar control subsystem
pub fn init() {
    crate::serial_println!("[USER] Rebar control initialized");
}

/// Create a Rebar control
pub fn create_rebar(hwnd: HWND, style: u32, rect: &Rect) -> Option<usize> {
    let mut controls = REBAR_CONTROLS.lock();

    for (i, control) in controls.iter_mut().enumerate() {
        if !control.in_use {
            control.reset();
            control.hwnd = hwnd;
            control.in_use = true;
            control.style = style;
            control.rect = *rect;
            return Some(i);
        }
    }

    None
}

/// Destroy a Rebar control
pub fn destroy_rebar(index: usize) -> bool {
    let mut controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS {
        return false;
    }

    if controls[index].in_use {
        controls[index].reset();
        true
    } else {
        false
    }
}

/// Insert a band
pub fn insert_band(index: usize, band_index: usize) -> Option<usize> {
    let mut controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return None;
    }

    controls[index].insert_band(band_index)
}

/// Delete a band
pub fn delete_band(index: usize, band_index: usize) -> bool {
    let mut controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].delete_band(band_index)
}

/// Get band count
pub fn get_band_count(index: usize) -> usize {
    let controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].band_count
}

/// Get row count
pub fn get_row_count(index: usize) -> u32 {
    let controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].row_count
}

/// Get row height
pub fn get_row_height(index: usize, row: u32) -> i32 {
    let controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].get_row_height(row)
}

/// Get bar height
pub fn get_bar_height(index: usize) -> i32 {
    let controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].height
}

/// Set background color
pub fn set_bk_color(index: usize, color: u32) -> u32 {
    let mut controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return 0;
    }

    let old = controls[index].bk_color;
    controls[index].bk_color = color;
    old
}

/// Get background color
pub fn get_bk_color(index: usize) -> u32 {
    let controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].bk_color
}

/// Set text color
pub fn set_text_color(index: usize, color: u32) -> u32 {
    let mut controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return 0;
    }

    let old = controls[index].text_color;
    controls[index].text_color = color;
    old
}

/// Get text color
pub fn get_text_color(index: usize) -> u32 {
    let controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].text_color
}

/// Hit test
pub fn hit_test(index: usize, pt: &Point) -> (u32, i32) {
    let controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return (RBHT_NOWHERE, -1);
    }

    controls[index].hit_test(pt)
}

/// ID to index
pub fn id_to_index(index: usize, id: u32) -> Option<usize> {
    let controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return None;
    }

    controls[index].id_to_index(id)
}

/// Minimize band
pub fn minimize_band(index: usize, band: usize) -> bool {
    let mut controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].minimize_band(band)
}

/// Maximize band
pub fn maximize_band(index: usize, band: usize) -> bool {
    let mut controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].maximize_band(band)
}

/// Show/hide band
pub fn show_band(index: usize, band: usize, show: bool) -> bool {
    let mut controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].show_band(band, show)
}

/// Move band
pub fn move_band(index: usize, from: usize, to: usize) -> bool {
    let mut controls = REBAR_CONTROLS.lock();

    if index >= MAX_REBAR_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].move_band(from, to)
}

/// Process Rebar control message
pub fn process_message(index: usize, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        RB_INSERTBANDA | RB_INSERTBANDW => {
            if let Some(band_idx) = insert_band(index, wparam) {
                band_idx as isize
            } else {
                -1
            }
        }
        RB_DELETEBAND => {
            if delete_band(index, wparam) { 1 } else { 0 }
        }
        RB_GETBANDCOUNT => {
            get_band_count(index) as isize
        }
        RB_GETROWCOUNT => {
            get_row_count(index) as isize
        }
        RB_GETROWHEIGHT => {
            get_row_height(index, wparam as u32) as isize
        }
        RB_GETBARHEIGHT => {
            get_bar_height(index) as isize
        }
        RB_SETBKCOLOR => {
            set_bk_color(index, lparam as u32) as isize
        }
        RB_GETBKCOLOR => {
            get_bk_color(index) as isize
        }
        RB_SETTEXTCOLOR => {
            set_text_color(index, lparam as u32) as isize
        }
        RB_GETTEXTCOLOR => {
            get_text_color(index) as isize
        }
        RB_IDTOINDEX => {
            if let Some(idx) = id_to_index(index, wparam as u32) {
                idx as isize
            } else {
                -1
            }
        }
        RB_MINIMIZEBAND => {
            if minimize_band(index, wparam) { 1 } else { 0 }
        }
        RB_MAXIMIZEBAND => {
            if maximize_band(index, wparam) { 1 } else { 0 }
        }
        RB_SHOWBAND => {
            if show_band(index, wparam, lparam != 0) { 1 } else { 0 }
        }
        RB_MOVEBAND => {
            if move_band(index, wparam, lparam as usize) { 1 } else { 0 }
        }
        _ => 0,
    }
}

/// Get statistics
pub fn get_stats() -> RebarStats {
    let controls = REBAR_CONTROLS.lock();

    let mut active_count = 0;
    let mut total_bands = 0;

    for control in controls.iter() {
        if control.in_use {
            active_count += 1;
            total_bands += control.band_count;
        }
    }

    RebarStats {
        max_controls: MAX_REBAR_CONTROLS,
        active_controls: active_count,
        total_bands,
    }
}

/// Rebar statistics
#[derive(Debug, Clone, Copy)]
pub struct RebarStats {
    pub max_controls: usize,
    pub active_controls: usize,
    pub total_bands: usize,
}
