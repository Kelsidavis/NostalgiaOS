//! PropertySheet Implementation
//!
//! Windows PropertySheet for tabbed dialog pages.
//! Based on Windows Server 2003 prsht.h.
//!
//! # Features
//!
//! - Multiple property pages in tabbed interface
//! - Apply/OK/Cancel button handling
//! - Page navigation
//! - Wizard mode support
//!
//! # References
//!
//! - `public/sdk/inc/prsht.h` - PropertySheet structures and messages

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// PropertySheet Header Flags (PSH_*)
// ============================================================================

/// Default header style
pub const PSH_DEFAULT: u32 = 0x00000000;

/// Use callback function
pub const PSH_USECALLBACK: u32 = 0x00000100;

/// Use HICON instead of icon resource
pub const PSH_USEHICON: u32 = 0x00000002;

/// Use icon resource ID
pub const PSH_USEICONID: u32 = 0x00000004;

/// Use HINSTANCE for page resources
pub const PSH_PROPSHEETPAGE: u32 = 0x00000008;

/// Use wizard mode
pub const PSH_WIZARD: u32 = 0x00000020;

/// Use Wizard97 style
pub const PSH_WIZARD97: u32 = 0x00002000;

/// Use header bitmap
pub const PSH_HEADER: u32 = 0x00080000;

/// Use watermark bitmap
pub const PSH_WATERMARK: u32 = 0x00008000;

/// Stretch watermark
pub const PSH_STRETCHWATERMARK: u32 = 0x00040000;

/// Has help button
pub const PSH_HASHELP: u32 = 0x00000200;

/// Modal dialog
pub const PSH_MODELESS: u32 = 0x00000400;

/// RTL reading
pub const PSH_RTLREADING: u32 = 0x00000800;

/// Use wizard lite style
pub const PSH_WIZARDCONTEXTHELP: u32 = 0x00001000;

/// No apply button
pub const PSH_NOAPPLYNOW: u32 = 0x00000080;

/// Use PropSheetPage structures
pub const PSH_PROPTITLE: u32 = 0x00000001;

/// Wizard with hardware pages
pub const PSH_WIZARDHWPAGE: u32 = 0x00004000;

/// No context help
pub const PSH_NOCONTEXTHELP: u32 = 0x02000000;

/// Aero wizard style
pub const PSH_AEROWIZARD: u32 = 0x00004000;

/// Resize existing pages
pub const PSH_RESIZABLE: u32 = 0x04000000;

/// Use header subtitle
pub const PSH_HEADERSUBTITLE: u32 = 0x08000000;

/// Use small header
pub const PSH_USEPSTARTPAGE: u32 = 0x00000040;

// ============================================================================
// PropertySheet Page Flags (PSP_*)
// ============================================================================

/// Default page style
pub const PSP_DEFAULT: u32 = 0x00000000;

/// Use dialog template from resource
pub const PSP_DLGINDIRECT: u32 = 0x00000001;

/// Use HICON
pub const PSP_USEHICON: u32 = 0x00000002;

/// Use icon resource ID
pub const PSP_USEICONID: u32 = 0x00000004;

/// Use page title
pub const PSP_USETITLE: u32 = 0x00000008;

/// RTL reading
pub const PSP_RTLREADING: u32 = 0x00000010;

/// Has help button
pub const PSP_HASHELP: u32 = 0x00000020;

/// Use reference data
pub const PSP_USEREFPARENT: u32 = 0x00000040;

/// Use callback
pub const PSP_USECALLBACK: u32 = 0x00000080;

/// Premature termination
pub const PSP_PREMATURE: u32 = 0x00000400;

/// Hide header
pub const PSP_HIDEHEADER: u32 = 0x00000800;

/// Use header title
pub const PSP_USEHEADERTITLE: u32 = 0x00001000;

/// Use header subtitle
pub const PSP_USEHEADERSUBTITLE: u32 = 0x00002000;

/// Use fusion context
pub const PSP_USEFUSIONCONTEXT: u32 = 0x00004000;

// ============================================================================
// PropertySheet Messages (PSM_*)
// ============================================================================

/// First PropertySheet message
pub const PSM_FIRST: u32 = 0x0400;

/// Set current page by index
pub const PSM_SETCURSEL: u32 = PSM_FIRST + 1;

/// Remove a page
pub const PSM_REMOVEPAGE: u32 = PSM_FIRST + 2;

/// Add a page
pub const PSM_ADDPAGE: u32 = PSM_FIRST + 3;

/// Changed notification
pub const PSM_CHANGED: u32 = PSM_FIRST + 4;

/// Restart Windows
pub const PSM_RESTARTWINDOWS: u32 = PSM_FIRST + 5;

/// Reboot system
pub const PSM_REBOOTSYSTEM: u32 = PSM_FIRST + 6;

/// Cancel to close
pub const PSM_CANCELTOCLOSE: u32 = PSM_FIRST + 7;

/// Query siblings
pub const PSM_QUERYSIBLINGS: u32 = PSM_FIRST + 8;

/// Unchanged notification
pub const PSM_UNCHANGED: u32 = PSM_FIRST + 9;

/// Apply changes
pub const PSM_APPLY: u32 = PSM_FIRST + 10;

/// Set page title
pub const PSM_SETTITLE: u32 = PSM_FIRST + 11;

/// Set wizard buttons
pub const PSM_SETWIZBUTTONS: u32 = PSM_FIRST + 12;

/// Press button
pub const PSM_PRESSBUTTON: u32 = PSM_FIRST + 13;

/// Set current page by ID
pub const PSM_SETCURSELID: u32 = PSM_FIRST + 14;

/// Set finish text
pub const PSM_SETFINISHTEXT: u32 = PSM_FIRST + 15;

/// Get tab control
pub const PSM_GETTABCONTROL: u32 = PSM_FIRST + 16;

/// Is dialog message
pub const PSM_ISDIALOGMESSAGE: u32 = PSM_FIRST + 17;

/// Get current page HWND
pub const PSM_GETCURRENTPAGEHWND: u32 = PSM_FIRST + 18;

/// Insert a page
pub const PSM_INSERTPAGE: u32 = PSM_FIRST + 19;

/// Set header title
pub const PSM_SETHEADERTITLE: u32 = PSM_FIRST + 20;

/// Set header subtitle
pub const PSM_SETHEADERSUBTITLE: u32 = PSM_FIRST + 21;

/// Hwnd to index
pub const PSM_HWNDTOINDEX: u32 = PSM_FIRST + 22;

/// Index to hwnd
pub const PSM_INDEXTOHWND: u32 = PSM_FIRST + 23;

/// Page to index
pub const PSM_PAGETOINDEX: u32 = PSM_FIRST + 24;

/// Index to page
pub const PSM_INDEXTOPAGE: u32 = PSM_FIRST + 25;

/// Index to ID
pub const PSM_INDEXTOID: u32 = PSM_FIRST + 26;

/// ID to index
pub const PSM_IDTOINDEX: u32 = PSM_FIRST + 27;

/// Get result
pub const PSM_GETRESULT: u32 = PSM_FIRST + 28;

/// Recalc page sizes
pub const PSM_RECALCPAGESIZES: u32 = PSM_FIRST + 29;

// ============================================================================
// PropertySheet Notifications (PSN_*)
// ============================================================================

/// First notification
pub const PSN_FIRST: i32 = -200;

/// Set active page
pub const PSN_SETACTIVE: i32 = PSN_FIRST - 0;

/// Kill active page
pub const PSN_KILLACTIVE: i32 = PSN_FIRST - 1;

/// Apply changes
pub const PSN_APPLY: i32 = PSN_FIRST - 2;

/// Reset/Cancel
pub const PSN_RESET: i32 = PSN_FIRST - 3;

/// Help requested
pub const PSN_HELP: i32 = PSN_FIRST - 5;

/// Wizard back
pub const PSN_WIZBACK: i32 = PSN_FIRST - 6;

/// Wizard next
pub const PSN_WIZNEXT: i32 = PSN_FIRST - 7;

/// Wizard finish
pub const PSN_WIZFINISH: i32 = PSN_FIRST - 8;

/// Query cancel
pub const PSN_QUERYCANCEL: i32 = PSN_FIRST - 9;

/// Get object
pub const PSN_GETOBJECT: i32 = PSN_FIRST - 10;

/// Translate accelerator
pub const PSN_TRANSLATEACCELERATOR: i32 = PSN_FIRST - 12;

/// Query initial focus
pub const PSN_QUERYINITIALFOCUS: i32 = PSN_FIRST - 13;

// ============================================================================
// Wizard Button Flags (PSWIZB_*)
// ============================================================================

/// Enable Back button
pub const PSWIZB_BACK: u32 = 0x00000001;

/// Enable Next button
pub const PSWIZB_NEXT: u32 = 0x00000002;

/// Enable Finish button
pub const PSWIZB_FINISH: u32 = 0x00000004;

/// Disable Finish button
pub const PSWIZB_DISABLEDFINISH: u32 = 0x00000008;

/// Cancel button enabled
pub const PSWIZB_CANCEL: u32 = 0x00000010;

// ============================================================================
// Button IDs (PSBTN_*)
// ============================================================================

/// Back button
pub const PSBTN_BACK: u32 = 0;

/// Next button
pub const PSBTN_NEXT: u32 = 1;

/// Finish button
pub const PSBTN_FINISH: u32 = 2;

/// OK button
pub const PSBTN_OK: u32 = 3;

/// Apply button
pub const PSBTN_APPLYNOW: u32 = 4;

/// Cancel button
pub const PSBTN_CANCEL: u32 = 5;

/// Help button
pub const PSBTN_HELP: u32 = 6;

/// Maximum buttons
pub const PSBTN_MAX: u32 = 6;

// ============================================================================
// Return Values
// ============================================================================

/// Page not set
pub const PSNRET_NOERROR: i32 = 0;

/// Invalid page
pub const PSNRET_INVALID: i32 = 1;

/// Page not valid, don't leave
pub const PSNRET_INVALID_NOCHANGEPAGE: i32 = 2;

/// Cancel message handled
pub const PSNRET_MESSAGEHANDLED: i32 = 3;

// ============================================================================
// Constants
// ============================================================================

/// Maximum property sheets
pub const MAX_PROPERTY_SHEETS: usize = 32;

/// Maximum pages per sheet
pub const MAX_PAGES_PER_SHEET: usize = 16;

/// Maximum title length
pub const MAX_TITLE_LENGTH: usize = 128;

// ============================================================================
// Page State
// ============================================================================

/// Page state flags
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PageState {
    #[default]
    Normal = 0,
    Active = 1,
    Changed = 2,
    Hidden = 4,
}

// ============================================================================
// PropertySheetPage Structure
// ============================================================================

/// Property sheet page
#[derive(Clone)]
pub struct PropertySheetPage {
    /// Page is in use
    pub in_use: bool,
    /// Page flags (PSP_*)
    pub flags: u32,
    /// Dialog resource ID
    pub dialog_id: u32,
    /// Page title
    pub title: [u8; MAX_TITLE_LENGTH],
    pub title_len: usize,
    /// Header title (for wizard)
    pub header_title: [u8; MAX_TITLE_LENGTH],
    pub header_title_len: usize,
    /// Header subtitle (for wizard)
    pub header_subtitle: [u8; MAX_TITLE_LENGTH],
    pub header_subtitle_len: usize,
    /// Icon handle or resource ID
    pub icon: usize,
    /// Callback function pointer
    pub callback: usize,
    /// Dialog procedure
    pub dlg_proc: usize,
    /// Application data
    pub lparam: isize,
    /// Page window handle
    pub hwnd: HWND,
    /// Page state
    pub state: u32,
    /// Reference count
    pub ref_count: u32,
}

impl PropertySheetPage {
    /// Create new page
    pub const fn new() -> Self {
        Self {
            in_use: false,
            flags: 0,
            dialog_id: 0,
            title: [0u8; MAX_TITLE_LENGTH],
            title_len: 0,
            header_title: [0u8; MAX_TITLE_LENGTH],
            header_title_len: 0,
            header_subtitle: [0u8; MAX_TITLE_LENGTH],
            header_subtitle_len: 0,
            icon: 0,
            callback: 0,
            dlg_proc: 0,
            lparam: 0,
            hwnd: UserHandle::NULL,
            state: 0,
            ref_count: 0,
        }
    }

    /// Set title
    pub fn set_title(&mut self, title: &str) {
        let bytes = title.as_bytes();
        let len = bytes.len().min(MAX_TITLE_LENGTH - 1);
        self.title[..len].copy_from_slice(&bytes[..len]);
        self.title_len = len;
    }

    /// Get title as string slice
    pub fn get_title(&self) -> &[u8] {
        &self.title[..self.title_len]
    }

    /// Set header title
    pub fn set_header_title(&mut self, title: &str) {
        let bytes = title.as_bytes();
        let len = bytes.len().min(MAX_TITLE_LENGTH - 1);
        self.header_title[..len].copy_from_slice(&bytes[..len]);
        self.header_title_len = len;
    }

    /// Set header subtitle
    pub fn set_header_subtitle(&mut self, subtitle: &str) {
        let bytes = subtitle.as_bytes();
        let len = bytes.len().min(MAX_TITLE_LENGTH - 1);
        self.header_subtitle[..len].copy_from_slice(&bytes[..len]);
        self.header_subtitle_len = len;
    }
}

// ============================================================================
// PropertySheet Structure
// ============================================================================

/// Property sheet dialog
#[derive(Clone)]
pub struct PropertySheet {
    /// Sheet is in use
    pub in_use: bool,
    /// Header flags (PSH_*)
    pub flags: u32,
    /// Parent window
    pub parent: HWND,
    /// Sheet title
    pub title: [u8; MAX_TITLE_LENGTH],
    pub title_len: usize,
    /// Icon handle or resource ID
    pub icon: usize,
    /// Start page index
    pub start_page: usize,
    /// Current active page
    pub active_page: usize,
    /// Page count
    pub page_count: usize,
    /// Pages
    pub pages: [PropertySheetPage; MAX_PAGES_PER_SHEET],
    /// Sheet window handle
    pub hwnd: HWND,
    /// Tab control handle
    pub hwnd_tab: HWND,
    /// Wizard buttons state
    pub wizard_buttons: u32,
    /// Result (IDOK, IDCANCEL, etc.)
    pub result: i32,
    /// Modified flag
    pub modified: bool,
    /// Need restart
    pub need_restart: bool,
    /// Need reboot
    pub need_reboot: bool,
}

impl PropertySheet {
    /// Create new property sheet
    pub const fn new() -> Self {
        Self {
            in_use: false,
            flags: 0,
            parent: UserHandle::NULL,
            title: [0u8; MAX_TITLE_LENGTH],
            title_len: 0,
            icon: 0,
            start_page: 0,
            active_page: 0,
            page_count: 0,
            pages: [const { PropertySheetPage::new() }; MAX_PAGES_PER_SHEET],
            hwnd: UserHandle::NULL,
            hwnd_tab: UserHandle::NULL,
            wizard_buttons: PSWIZB_NEXT,
            result: 0,
            modified: false,
            need_restart: false,
            need_reboot: false,
        }
    }

    /// Reset sheet
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Set title
    pub fn set_title(&mut self, title: &str) {
        let bytes = title.as_bytes();
        let len = bytes.len().min(MAX_TITLE_LENGTH - 1);
        self.title[..len].copy_from_slice(&bytes[..len]);
        self.title_len = len;
    }

    /// Add a page
    pub fn add_page(&mut self, page: &PropertySheetPage) -> bool {
        if self.page_count >= MAX_PAGES_PER_SHEET {
            return false;
        }

        self.pages[self.page_count] = page.clone();
        self.pages[self.page_count].in_use = true;
        self.page_count += 1;
        true
    }

    /// Remove a page by index
    pub fn remove_page(&mut self, index: usize) -> bool {
        if index >= self.page_count {
            return false;
        }

        // Shift pages down
        for i in index..self.page_count - 1 {
            self.pages[i] = self.pages[i + 1].clone();
        }
        self.pages[self.page_count - 1] = PropertySheetPage::new();
        self.page_count -= 1;

        // Adjust active page if needed
        if self.active_page >= self.page_count && self.page_count > 0 {
            self.active_page = self.page_count - 1;
        }

        true
    }

    /// Insert a page at index
    pub fn insert_page(&mut self, index: usize, page: &PropertySheetPage) -> bool {
        if self.page_count >= MAX_PAGES_PER_SHEET {
            return false;
        }

        let insert_idx = index.min(self.page_count);

        // Shift pages up
        for i in (insert_idx..self.page_count).rev() {
            self.pages[i + 1] = self.pages[i].clone();
        }

        self.pages[insert_idx] = page.clone();
        self.pages[insert_idx].in_use = true;
        self.page_count += 1;

        // Adjust active page if needed
        if self.active_page >= insert_idx {
            self.active_page += 1;
        }

        true
    }

    /// Set current page by index
    pub fn set_cur_sel(&mut self, index: usize) -> bool {
        if index >= self.page_count {
            return false;
        }

        self.active_page = index;
        true
    }

    /// Get current page index
    pub fn get_cur_sel(&self) -> usize {
        self.active_page
    }

    /// Set wizard buttons
    pub fn set_wizard_buttons(&mut self, buttons: u32) {
        self.wizard_buttons = buttons;
    }

    /// Mark page as changed
    pub fn set_changed(&mut self, page_hwnd: HWND) {
        self.modified = true;
        for page in self.pages[..self.page_count].iter_mut() {
            if page.hwnd == page_hwnd {
                page.state |= PageState::Changed as u32;
                break;
            }
        }
    }

    /// Mark page as unchanged
    pub fn set_unchanged(&mut self, page_hwnd: HWND) {
        for page in self.pages[..self.page_count].iter_mut() {
            if page.hwnd == page_hwnd {
                page.state &= !(PageState::Changed as u32);
                break;
            }
        }

        // Check if any page is still changed
        self.modified = self.pages[..self.page_count]
            .iter()
            .any(|p| p.state & (PageState::Changed as u32) != 0);
    }

    /// Apply changes
    pub fn apply(&mut self) -> bool {
        // In a real implementation, this would send PSN_APPLY to all pages
        self.modified = false;
        for page in self.pages[..self.page_count].iter_mut() {
            page.state &= !(PageState::Changed as u32);
        }
        true
    }

    /// Request restart
    pub fn restart_windows(&mut self) {
        self.need_restart = true;
    }

    /// Request reboot
    pub fn reboot_system(&mut self) {
        self.need_reboot = true;
    }

    /// Is wizard mode
    pub fn is_wizard(&self) -> bool {
        (self.flags & (PSH_WIZARD | PSH_WIZARD97 | PSH_AEROWIZARD)) != 0
    }

    /// Get page count
    pub fn get_page_count(&self) -> usize {
        self.page_count
    }

    /// Page index to hwnd
    pub fn index_to_hwnd(&self, index: usize) -> HWND {
        if index < self.page_count {
            self.pages[index].hwnd
        } else {
            UserHandle::NULL
        }
    }

    /// Hwnd to page index
    pub fn hwnd_to_index(&self, hwnd: HWND) -> Option<usize> {
        for (i, page) in self.pages[..self.page_count].iter().enumerate() {
            if page.hwnd == hwnd {
                return Some(i);
            }
        }
        None
    }

    /// Press a button
    pub fn press_button(&mut self, button: u32) -> bool {
        match button {
            PSBTN_BACK => {
                if self.active_page > 0 {
                    self.active_page -= 1;
                    true
                } else {
                    false
                }
            }
            PSBTN_NEXT => {
                if self.active_page < self.page_count - 1 {
                    self.active_page += 1;
                    true
                } else {
                    false
                }
            }
            PSBTN_FINISH | PSBTN_OK => {
                self.apply();
                self.result = 1; // IDOK
                true
            }
            PSBTN_APPLYNOW => {
                self.apply()
            }
            PSBTN_CANCEL => {
                self.result = 2; // IDCANCEL
                true
            }
            PSBTN_HELP => {
                // Send help notification
                true
            }
            _ => false,
        }
    }

    /// Process message
    pub fn process_message(&mut self, msg: u32, wparam: usize, lparam: isize) -> isize {
        match msg {
            PSM_SETCURSEL => {
                if self.set_cur_sel(wparam) {
                    1
                } else {
                    0
                }
            }
            PSM_REMOVEPAGE => {
                if self.remove_page(wparam) {
                    1
                } else {
                    0
                }
            }
            PSM_ADDPAGE => {
                // wparam is pointer to PROPSHEETPAGE
                1
            }
            PSM_CHANGED => {
                let hwnd = UserHandle::from_raw(wparam as u32);
                self.set_changed(hwnd);
                1
            }
            PSM_UNCHANGED => {
                let hwnd = UserHandle::from_raw(wparam as u32);
                self.set_unchanged(hwnd);
                1
            }
            PSM_RESTARTWINDOWS => {
                self.restart_windows();
                1
            }
            PSM_REBOOTSYSTEM => {
                self.reboot_system();
                1
            }
            PSM_APPLY => {
                if self.apply() { 1 } else { 0 }
            }
            PSM_SETWIZBUTTONS => {
                self.set_wizard_buttons(lparam as u32);
                1
            }
            PSM_PRESSBUTTON => {
                if self.press_button(wparam as u32) { 1 } else { 0 }
            }
            PSM_GETTABCONTROL => {
                self.hwnd_tab.raw() as isize
            }
            PSM_GETCURRENTPAGEHWND => {
                self.index_to_hwnd(self.active_page).raw() as isize
            }
            PSM_HWNDTOINDEX => {
                let hwnd = UserHandle::from_raw(wparam as u32);
                if let Some(idx) = self.hwnd_to_index(hwnd) {
                    idx as isize
                } else {
                    -1
                }
            }
            PSM_INDEXTOHWND => {
                self.index_to_hwnd(wparam).raw() as isize
            }
            PSM_GETRESULT => {
                self.result as isize
            }
            _ => 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global property sheet storage
static PROPERTY_SHEETS: SpinLock<[PropertySheet; MAX_PROPERTY_SHEETS]> =
    SpinLock::new([const { PropertySheet::new() }; MAX_PROPERTY_SHEETS]);

// ============================================================================
// Handle Type
// ============================================================================

/// Property sheet handle
pub type HPROPSHEETPAGE = usize;

/// Null page handle
pub const NULL_HPROPSHEETPAGE: HPROPSHEETPAGE = 0;

// ============================================================================
// Public API
// ============================================================================

/// Initialize PropertySheet subsystem
pub fn init() {
    crate::serial_println!("[USER] PropertySheet initialized");
}

/// Create a property sheet page
pub fn create_page(flags: u32, dialog_id: u32, title: &str) -> HPROPSHEETPAGE {
    let mut page = PropertySheetPage::new();
    page.flags = flags;
    page.dialog_id = dialog_id;
    page.set_title(title);

    // In a real implementation, we'd store this in a page pool
    // For now, return a mock handle
    // The page will be copied when added to a sheet
    1
}

/// Destroy a property sheet page
pub fn destroy_page(_hpage: HPROPSHEETPAGE) -> bool {
    // In a real implementation, release page resources
    true
}

/// Create and display a property sheet
pub fn property_sheet(parent: HWND, flags: u32, title: &str) -> usize {
    let mut sheets = PROPERTY_SHEETS.lock();

    for (i, sheet) in sheets.iter_mut().enumerate() {
        if !sheet.in_use {
            sheet.reset();
            sheet.in_use = true;
            sheet.flags = flags;
            sheet.parent = parent;
            sheet.set_title(title);
            return i + 1; // Handle is index + 1
        }
    }

    0
}

/// Add a page to a property sheet
pub fn add_page(sheet_idx: usize, page: &PropertySheetPage) -> bool {
    if sheet_idx == 0 {
        return false;
    }

    let mut sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS || !sheets[idx].in_use {
        return false;
    }

    sheets[idx].add_page(page)
}

/// Remove a page from a property sheet
pub fn remove_page(sheet_idx: usize, page_idx: usize) -> bool {
    if sheet_idx == 0 {
        return false;
    }

    let mut sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS || !sheets[idx].in_use {
        return false;
    }

    sheets[idx].remove_page(page_idx)
}

/// Set current page
pub fn set_cur_sel(sheet_idx: usize, page_idx: usize) -> bool {
    if sheet_idx == 0 {
        return false;
    }

    let mut sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS || !sheets[idx].in_use {
        return false;
    }

    sheets[idx].set_cur_sel(page_idx)
}

/// Get current page
pub fn get_cur_sel(sheet_idx: usize) -> usize {
    if sheet_idx == 0 {
        return 0;
    }

    let sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS || !sheets[idx].in_use {
        return 0;
    }

    sheets[idx].get_cur_sel()
}

/// Set wizard buttons
pub fn set_wizard_buttons(sheet_idx: usize, buttons: u32) {
    if sheet_idx == 0 {
        return;
    }

    let mut sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS || !sheets[idx].in_use {
        return;
    }

    sheets[idx].set_wizard_buttons(buttons);
}

/// Press a button
pub fn press_button(sheet_idx: usize, button: u32) -> bool {
    if sheet_idx == 0 {
        return false;
    }

    let mut sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS || !sheets[idx].in_use {
        return false;
    }

    sheets[idx].press_button(button)
}

/// Apply changes
pub fn apply(sheet_idx: usize) -> bool {
    if sheet_idx == 0 {
        return false;
    }

    let mut sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS || !sheets[idx].in_use {
        return false;
    }

    sheets[idx].apply()
}

/// Mark page as changed
pub fn changed(sheet_idx: usize, page_hwnd: HWND) {
    if sheet_idx == 0 {
        return;
    }

    let mut sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS || !sheets[idx].in_use {
        return;
    }

    sheets[idx].set_changed(page_hwnd);
}

/// Mark page as unchanged
pub fn unchanged(sheet_idx: usize, page_hwnd: HWND) {
    if sheet_idx == 0 {
        return;
    }

    let mut sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS || !sheets[idx].in_use {
        return;
    }

    sheets[idx].set_unchanged(page_hwnd);
}

/// Destroy a property sheet
pub fn destroy(sheet_idx: usize) -> bool {
    if sheet_idx == 0 {
        return false;
    }

    let mut sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS {
        return false;
    }

    if sheets[idx].in_use {
        sheets[idx].reset();
        true
    } else {
        false
    }
}

/// Get result (IDOK, IDCANCEL, etc.)
pub fn get_result(sheet_idx: usize) -> i32 {
    if sheet_idx == 0 {
        return 0;
    }

    let sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS || !sheets[idx].in_use {
        return 0;
    }

    sheets[idx].result
}

/// Check if restart is needed
pub fn needs_restart(sheet_idx: usize) -> bool {
    if sheet_idx == 0 {
        return false;
    }

    let sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS || !sheets[idx].in_use {
        return false;
    }

    sheets[idx].need_restart
}

/// Check if reboot is needed
pub fn needs_reboot(sheet_idx: usize) -> bool {
    if sheet_idx == 0 {
        return false;
    }

    let sheets = PROPERTY_SHEETS.lock();
    let idx = sheet_idx - 1;

    if idx >= MAX_PROPERTY_SHEETS || !sheets[idx].in_use {
        return false;
    }

    sheets[idx].need_reboot
}

/// Get statistics
pub fn get_stats() -> PropSheetStats {
    let sheets = PROPERTY_SHEETS.lock();

    let mut active_count = 0;
    let mut total_pages = 0;

    for sheet in sheets.iter() {
        if sheet.in_use {
            active_count += 1;
            total_pages += sheet.page_count;
        }
    }

    PropSheetStats {
        max_sheets: MAX_PROPERTY_SHEETS,
        active_sheets: active_count,
        total_pages,
    }
}

/// PropertySheet statistics
#[derive(Debug, Clone, Copy)]
pub struct PropSheetStats {
    pub max_sheets: usize,
    pub active_sheets: usize,
    pub total_pages: usize,
}
