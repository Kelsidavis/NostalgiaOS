//! Wizard Control Implementation
//!
//! Windows Wizard for step-by-step dialogs.
//! Built on top of PropertySheet with wizard-specific styling.
//!
//! # Features
//!
//! - Sequential page navigation
//! - Back/Next/Finish buttons
//! - Wizard97 style with watermark/header
//! - Aero wizard style
//!
//! # References
//!
//! - Based on Windows PropertySheet wizard mode (PSH_WIZARD, PSH_WIZARD97)

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};
use super::propsheet::{
    PSH_WIZARD, PSH_WIZARD97, PSH_AEROWIZARD, PSH_HEADER, PSH_WATERMARK,
    PSH_HASHELP, PSH_NOCONTEXTHELP, PSH_STRETCHWATERMARK,
    PSWIZB_BACK, PSWIZB_NEXT, PSWIZB_FINISH, PSWIZB_DISABLEDFINISH, PSWIZB_CANCEL,
    PSBTN_BACK, PSBTN_NEXT, PSBTN_FINISH, PSBTN_CANCEL,
    PSN_SETACTIVE, PSN_KILLACTIVE, PSN_WIZBACK, PSN_WIZNEXT, PSN_WIZFINISH,
    PSN_QUERYCANCEL, PSN_HELP,
    PropertySheetPage, MAX_TITLE_LENGTH,
};

// ============================================================================
// Wizard Styles
// ============================================================================

/// Standard wizard (Windows 95/NT4 style)
pub const WIZARD_STANDARD: u32 = PSH_WIZARD;

/// Wizard97 style with large header area
pub const WIZARD_97: u32 = PSH_WIZARD97 | PSH_HEADER;

/// Wizard97 with watermark on intro/finish pages
pub const WIZARD_97_WATERMARK: u32 = PSH_WIZARD97 | PSH_WATERMARK;

/// Aero wizard style (Vista+)
pub const WIZARD_AERO: u32 = PSH_AEROWIZARD;

// ============================================================================
// Wizard Page Types
// ============================================================================

/// Wizard page type for different layouts
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WizardPageType {
    /// Standard interior page
    #[default]
    Interior = 0,
    /// Exterior page (intro/welcome) with watermark
    Exterior = 1,
    /// Completion/finish page
    Completion = 2,
}

// ============================================================================
// Wizard Page
// ============================================================================

/// Wizard page configuration
#[derive(Clone)]
pub struct WizardPage {
    /// Base property sheet page
    pub page: PropertySheetPage,
    /// Page type
    pub page_type: WizardPageType,
    /// Can go back from this page
    pub can_back: bool,
    /// Can go forward from this page
    pub can_next: bool,
    /// Is this the finish page
    pub is_finish: bool,
    /// Custom back page index (-1 for default)
    pub back_page: i32,
    /// Custom next page index (-1 for default)
    pub next_page: i32,
}

impl WizardPage {
    /// Create new wizard page
    pub const fn new() -> Self {
        Self {
            page: PropertySheetPage::new(),
            page_type: WizardPageType::Interior,
            can_back: true,
            can_next: true,
            is_finish: false,
            back_page: -1,
            next_page: -1,
        }
    }

    /// Set page title
    pub fn set_title(&mut self, title: &str) {
        self.page.set_title(title);
    }

    /// Set header title (for Wizard97)
    pub fn set_header_title(&mut self, title: &str) {
        self.page.set_header_title(title);
    }

    /// Set header subtitle (for Wizard97)
    pub fn set_header_subtitle(&mut self, subtitle: &str) {
        self.page.set_header_subtitle(subtitle);
    }

    /// Get the buttons that should be enabled for this page
    pub fn get_wizard_buttons(&self, is_first: bool, is_last: bool) -> u32 {
        let mut buttons = 0u32;

        if self.can_back && !is_first {
            buttons |= PSWIZB_BACK;
        }

        if is_last || self.is_finish {
            buttons |= PSWIZB_FINISH;
        } else if self.can_next {
            buttons |= PSWIZB_NEXT;
        }

        buttons |= PSWIZB_CANCEL;

        buttons
    }
}

// ============================================================================
// Wizard State
// ============================================================================

/// Maximum pages per wizard
pub const MAX_WIZARD_PAGES: usize = 24;

/// Maximum wizards
pub const MAX_WIZARDS: usize = 16;

/// Wizard state
#[derive(Clone)]
pub struct Wizard {
    /// Is this slot in use
    pub in_use: bool,
    /// Wizard style
    pub style: u32,
    /// Parent window
    pub parent: HWND,
    /// Wizard title
    pub title: [u8; MAX_TITLE_LENGTH],
    pub title_len: usize,
    /// Current page index
    pub current_page: usize,
    /// Page count
    pub page_count: usize,
    /// Pages
    pub pages: [WizardPage; MAX_WIZARD_PAGES],
    /// Wizard window handle
    pub hwnd: HWND,
    /// Navigation history for back functionality
    pub history: [usize; MAX_WIZARD_PAGES],
    pub history_len: usize,
    /// Result code
    pub result: i32,
    /// Cancelled flag
    pub cancelled: bool,
    /// Finished flag
    pub finished: bool,
    /// Has help button
    pub has_help: bool,
}

impl Wizard {
    /// Create new wizard
    pub const fn new() -> Self {
        Self {
            in_use: false,
            style: WIZARD_STANDARD,
            parent: UserHandle::NULL,
            title: [0u8; MAX_TITLE_LENGTH],
            title_len: 0,
            current_page: 0,
            page_count: 0,
            pages: [const { WizardPage::new() }; MAX_WIZARD_PAGES],
            hwnd: UserHandle::NULL,
            history: [0usize; MAX_WIZARD_PAGES],
            history_len: 0,
            result: 0,
            cancelled: false,
            finished: false,
            has_help: false,
        }
    }

    /// Reset wizard
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
    pub fn add_page(&mut self, page: WizardPage) -> bool {
        if self.page_count >= MAX_WIZARD_PAGES {
            return false;
        }

        self.pages[self.page_count] = page;
        self.pages[self.page_count].page.in_use = true;
        self.page_count += 1;
        true
    }

    /// Get current page
    pub fn get_current_page(&self) -> usize {
        self.current_page
    }

    /// Is on first page
    pub fn is_first_page(&self) -> bool {
        self.current_page == 0
    }

    /// Is on last page
    pub fn is_last_page(&self) -> bool {
        self.current_page >= self.page_count.saturating_sub(1)
    }

    /// Get enabled wizard buttons for current page
    pub fn get_current_buttons(&self) -> u32 {
        if self.current_page >= self.page_count {
            return PSWIZB_CANCEL;
        }

        self.pages[self.current_page].get_wizard_buttons(
            self.is_first_page(),
            self.is_last_page(),
        )
    }

    /// Go to next page
    pub fn next(&mut self) -> bool {
        if self.current_page >= self.page_count {
            return false;
        }

        let page = &self.pages[self.current_page];

        // Check if custom next page is specified
        let next_idx = if page.next_page >= 0 {
            page.next_page as usize
        } else {
            self.current_page + 1
        };

        if next_idx >= self.page_count {
            return false;
        }

        // Push current page to history
        if self.history_len < MAX_WIZARD_PAGES {
            self.history[self.history_len] = self.current_page;
            self.history_len += 1;
        }

        self.current_page = next_idx;
        true
    }

    /// Go to previous page
    pub fn back(&mut self) -> bool {
        // Pop from history if available
        if self.history_len > 0 {
            self.history_len -= 1;
            self.current_page = self.history[self.history_len];
            return true;
        }

        // Otherwise check if custom back page specified
        if self.current_page < self.page_count {
            let page = &self.pages[self.current_page];
            if page.back_page >= 0 {
                self.current_page = page.back_page as usize;
                return true;
            }
        }

        // Default: go to previous page
        if self.current_page > 0 {
            self.current_page -= 1;
            return true;
        }

        false
    }

    /// Go to specific page
    pub fn go_to_page(&mut self, index: usize) -> bool {
        if index >= self.page_count {
            return false;
        }

        // Push current page to history
        if self.history_len < MAX_WIZARD_PAGES {
            self.history[self.history_len] = self.current_page;
            self.history_len += 1;
        }

        self.current_page = index;
        true
    }

    /// Finish the wizard
    pub fn finish(&mut self) -> bool {
        self.finished = true;
        self.result = 1; // IDOK
        true
    }

    /// Cancel the wizard
    pub fn cancel(&mut self) -> bool {
        self.cancelled = true;
        self.result = 2; // IDCANCEL
        true
    }

    /// Press a button
    pub fn press_button(&mut self, button: u32) -> bool {
        match button {
            PSBTN_BACK => self.back(),
            PSBTN_NEXT => self.next(),
            PSBTN_FINISH => self.finish(),
            PSBTN_CANCEL => self.cancel(),
            _ => false,
        }
    }

    /// Check if wizard is complete
    pub fn is_complete(&self) -> bool {
        self.finished || self.cancelled
    }

    /// Get result
    pub fn get_result(&self) -> i32 {
        self.result
    }

    /// Send notification to current page
    pub fn send_notification(&self, notification: i32) -> i32 {
        // In a real implementation, this would send to the page dialog proc
        match notification {
            PSN_SETACTIVE => 0, // Allow activation
            PSN_KILLACTIVE => 0, // Allow deactivation
            PSN_WIZBACK => 0, // Allow back
            PSN_WIZNEXT => 0, // Allow next
            PSN_WIZFINISH => 1, // Allow finish
            PSN_QUERYCANCEL => 0, // Allow cancel (0 = allow, non-0 = prevent)
            PSN_HELP => 0,
            _ => 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global wizard storage
static WIZARDS: SpinLock<[Wizard; MAX_WIZARDS]> =
    SpinLock::new([const { Wizard::new() }; MAX_WIZARDS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize Wizard subsystem
pub fn init() {
    crate::serial_println!("[USER] Wizard control initialized");
}

/// Create a wizard
pub fn create(parent: HWND, style: u32, title: &str) -> usize {
    let mut wizards = WIZARDS.lock();

    for (i, wizard) in wizards.iter_mut().enumerate() {
        if !wizard.in_use {
            wizard.reset();
            wizard.in_use = true;
            wizard.style = style;
            wizard.parent = parent;
            wizard.set_title(title);
            wizard.has_help = (style & PSH_HASHELP) != 0;
            return i + 1; // Handle is index + 1
        }
    }

    0
}

/// Destroy a wizard
pub fn destroy(wizard_idx: usize) -> bool {
    if wizard_idx == 0 {
        return false;
    }

    let mut wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS {
        return false;
    }

    if wizards[idx].in_use {
        wizards[idx].reset();
        true
    } else {
        false
    }
}

/// Add a page to the wizard
pub fn add_page(wizard_idx: usize, page: WizardPage) -> bool {
    if wizard_idx == 0 {
        return false;
    }

    let mut wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return false;
    }

    wizards[idx].add_page(page)
}

/// Add a simple page with title
pub fn add_simple_page(wizard_idx: usize, title: &str, page_type: WizardPageType) -> bool {
    let mut page = WizardPage::new();
    page.set_title(title);
    page.page_type = page_type;

    add_page(wizard_idx, page)
}

/// Get current page index
pub fn get_current_page(wizard_idx: usize) -> usize {
    if wizard_idx == 0 {
        return 0;
    }

    let wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return 0;
    }

    wizards[idx].get_current_page()
}

/// Go to next page
pub fn next(wizard_idx: usize) -> bool {
    if wizard_idx == 0 {
        return false;
    }

    let mut wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return false;
    }

    wizards[idx].next()
}

/// Go to previous page
pub fn back(wizard_idx: usize) -> bool {
    if wizard_idx == 0 {
        return false;
    }

    let mut wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return false;
    }

    wizards[idx].back()
}

/// Go to specific page
pub fn go_to_page(wizard_idx: usize, page_idx: usize) -> bool {
    if wizard_idx == 0 {
        return false;
    }

    let mut wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return false;
    }

    wizards[idx].go_to_page(page_idx)
}

/// Finish the wizard
pub fn finish(wizard_idx: usize) -> bool {
    if wizard_idx == 0 {
        return false;
    }

    let mut wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return false;
    }

    wizards[idx].finish()
}

/// Cancel the wizard
pub fn cancel(wizard_idx: usize) -> bool {
    if wizard_idx == 0 {
        return false;
    }

    let mut wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return false;
    }

    wizards[idx].cancel()
}

/// Press a button
pub fn press_button(wizard_idx: usize, button: u32) -> bool {
    if wizard_idx == 0 {
        return false;
    }

    let mut wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return false;
    }

    wizards[idx].press_button(button)
}

/// Get enabled buttons for current page
pub fn get_buttons(wizard_idx: usize) -> u32 {
    if wizard_idx == 0 {
        return PSWIZB_CANCEL;
    }

    let wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return PSWIZB_CANCEL;
    }

    wizards[idx].get_current_buttons()
}

/// Check if wizard is complete
pub fn is_complete(wizard_idx: usize) -> bool {
    if wizard_idx == 0 {
        return true;
    }

    let wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return true;
    }

    wizards[idx].is_complete()
}

/// Get result
pub fn get_result(wizard_idx: usize) -> i32 {
    if wizard_idx == 0 {
        return 0;
    }

    let wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return 0;
    }

    wizards[idx].get_result()
}

/// Get page count
pub fn get_page_count(wizard_idx: usize) -> usize {
    if wizard_idx == 0 {
        return 0;
    }

    let wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return 0;
    }

    wizards[idx].page_count
}

/// Check if on first page
pub fn is_first_page(wizard_idx: usize) -> bool {
    if wizard_idx == 0 {
        return true;
    }

    let wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return true;
    }

    wizards[idx].is_first_page()
}

/// Check if on last page
pub fn is_last_page(wizard_idx: usize) -> bool {
    if wizard_idx == 0 {
        return true;
    }

    let wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return true;
    }

    wizards[idx].is_last_page()
}

/// Set page navigation options
pub fn set_page_navigation(wizard_idx: usize, page_idx: usize, can_back: bool, can_next: bool) -> bool {
    if wizard_idx == 0 {
        return false;
    }

    let mut wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return false;
    }

    if page_idx >= wizards[idx].page_count {
        return false;
    }

    wizards[idx].pages[page_idx].can_back = can_back;
    wizards[idx].pages[page_idx].can_next = can_next;
    true
}

/// Set page as finish page
pub fn set_finish_page(wizard_idx: usize, page_idx: usize, is_finish: bool) -> bool {
    if wizard_idx == 0 {
        return false;
    }

    let mut wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return false;
    }

    if page_idx >= wizards[idx].page_count {
        return false;
    }

    wizards[idx].pages[page_idx].is_finish = is_finish;
    true
}

/// Set custom navigation for a page
pub fn set_custom_navigation(wizard_idx: usize, page_idx: usize, back_page: i32, next_page: i32) -> bool {
    if wizard_idx == 0 {
        return false;
    }

    let mut wizards = WIZARDS.lock();
    let idx = wizard_idx - 1;

    if idx >= MAX_WIZARDS || !wizards[idx].in_use {
        return false;
    }

    if page_idx >= wizards[idx].page_count {
        return false;
    }

    wizards[idx].pages[page_idx].back_page = back_page;
    wizards[idx].pages[page_idx].next_page = next_page;
    true
}

/// Get statistics
pub fn get_stats() -> WizardStats {
    let wizards = WIZARDS.lock();

    let mut active_count = 0;
    let mut total_pages = 0;

    for wizard in wizards.iter() {
        if wizard.in_use {
            active_count += 1;
            total_pages += wizard.page_count;
        }
    }

    WizardStats {
        max_wizards: MAX_WIZARDS,
        active_wizards: active_count,
        total_pages,
    }
}

/// Wizard statistics
#[derive(Debug, Clone, Copy)]
pub struct WizardStats {
    pub max_wizards: usize,
    pub active_wizards: usize,
    pub total_pages: usize,
}
