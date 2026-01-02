//! Page Setup Dialog
//!
//! Provides the Page Setup dialog following the Windows comdlg32
//! PageSetupDlg pattern.
//!
//! # References
//!
//! - Windows Server 2003 comdlg32 page setup dialog
//! - PAGESETUPDLG structure

use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Rect};

// ============================================================================
// Constants
// ============================================================================

/// Page setup flags (PSD_*)
pub mod psd_flags {
    /// Default minimum margins
    pub const DEFAULTMINMARGINS: u32 = 0x00000000;
    /// Use supplied minimum margins
    pub const MINMARGINS: u32 = 0x00000001;
    /// Use supplied margins
    pub const MARGINS: u32 = 0x00000002;
    /// Margins in thousandths of inch
    pub const INTHOUSANDTHSOFINCHES: u32 = 0x00000004;
    /// Margins in hundredths of mm
    pub const INHUNDREDTHSOFMILLIMETERS: u32 = 0x00000008;
    /// Disable margins
    pub const DISABLEMARGINS: u32 = 0x00000010;
    /// Disable printer button
    pub const DISABLEPRINTER: u32 = 0x00000020;
    /// No warning
    pub const NOWARNING: u32 = 0x00000080;
    /// Disable orientation
    pub const DISABLEORIENTATION: u32 = 0x00000100;
    /// Return default
    pub const RETURNDEFAULT: u32 = 0x00000400;
    /// Disable paper
    pub const DISABLEPAPER: u32 = 0x00000200;
    /// Show help
    pub const SHOWHELP: u32 = 0x00000800;
    /// Enable page setup hook
    pub const ENABLEPAGESETUPHOOK: u32 = 0x00002000;
    /// Enable page setup template
    pub const ENABLEPAGESETUPTEMPLATE: u32 = 0x00008000;
    /// Enable page setup template handle
    pub const ENABLEPAGESETUPTEMPLATEHANDLE: u32 = 0x00020000;
    /// Enable page paint hook
    pub const ENABLEPAGEPAINTHOOK: u32 = 0x00040000;
    /// Disable page painting
    pub const DISABLEPAGEPAINTING: u32 = 0x00080000;
    /// No network button
    pub const NONETWORKBUTTON: u32 = 0x00200000;
}

// ============================================================================
// Structures
// ============================================================================

/// Page setup dialog structure (PAGESETUPDLG equivalent)
#[derive(Debug, Clone, Copy)]
pub struct PageSetupDlg {
    /// Structure size
    pub struct_size: u32,
    /// Owner window
    pub hwnd_owner: HWND,
    /// Device mode handle
    pub dev_mode: u32,
    /// Device names handle
    pub dev_names: u32,
    /// Flags
    pub flags: u32,
    /// Paper size (in units specified by flags)
    pub paper_size: Point,
    /// Minimum margins
    pub min_margin: Rect,
    /// Margins
    pub margin: Rect,
    /// Instance
    pub instance: u32,
    /// Custom data
    pub cust_data: usize,
    /// Page setup hook
    pub page_setup_hook: usize,
    /// Page paint hook
    pub page_paint_hook: usize,
    /// Template name
    pub template_name: u32,
    /// Template handle
    pub template: u32,
}

/// Simple point structure
#[derive(Debug, Clone, Copy, Default)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl PageSetupDlg {
    pub const fn new() -> Self {
        Self {
            struct_size: 0,
            hwnd_owner: UserHandle::NULL,
            dev_mode: 0,
            dev_names: 0,
            flags: psd_flags::MARGINS | psd_flags::INTHOUSANDTHSOFINCHES,
            paper_size: Point { x: 8500, y: 11000 }, // 8.5" x 11" in thousandths
            min_margin: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            margin: Rect { left: 1000, top: 1000, right: 1000, bottom: 1000 }, // 1" margins
            instance: 0,
            cust_data: 0,
            page_setup_hook: 0,
            page_paint_hook: 0,
            template_name: 0,
            template: 0,
        }
    }
}

/// Page setup state
#[derive(Debug, Clone, Copy)]
pub struct PageSetupState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Portrait orientation
    pub portrait: bool,
    /// Paper size (index)
    pub paper_size: u8,
    /// Left margin (thousandths of inch)
    pub margin_left: i32,
    /// Top margin
    pub margin_top: i32,
    /// Right margin
    pub margin_right: i32,
    /// Bottom margin
    pub margin_bottom: i32,
    /// Paper source
    pub paper_source: u8,
}

impl PageSetupState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            portrait: true,
            paper_size: 0, // Letter
            margin_left: 1000,
            margin_top: 1000,
            margin_right: 1000,
            margin_bottom: 1000,
            paper_source: 0,
        }
    }
}

/// Paper source entry
#[derive(Debug, Clone, Copy)]
pub struct PaperSource {
    /// Source is valid
    pub valid: bool,
    /// Source name length
    pub name_len: u8,
    /// Source name
    pub name: [u8; 32],
    /// Source ID
    pub id: u16,
}

impl PaperSource {
    const fn new() -> Self {
        Self {
            valid: false,
            name_len: 0,
            name: [0; 32],
            id: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static PAGESETUP_INITIALIZED: AtomicBool = AtomicBool::new(false);
static PAGESETUP_LOCK: SpinLock<()> = SpinLock::new(());

static CURRENT_STATE: SpinLock<PageSetupState> = SpinLock::new(PageSetupState::new());

// Paper sources
const MAX_SOURCES: usize = 8;
static PAPER_SOURCES: SpinLock<[PaperSource; MAX_SOURCES]> =
    SpinLock::new([const { PaperSource::new() }; MAX_SOURCES]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize page setup dialog subsystem
pub fn init() {
    let _guard = PAGESETUP_LOCK.lock();

    if PAGESETUP_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[PAGESETUP] Initializing page setup dialog...");

    // Initialize paper sources
    init_paper_sources();

    PAGESETUP_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[PAGESETUP] Page setup dialog initialized");
}

/// Initialize paper sources
fn init_paper_sources() {
    let sources: &[(&[u8], u16)] = &[
        (b"Auto Select", 15),
        (b"Manual Feed", 4),
        (b"Tray 1", 1),
        (b"Tray 2", 2),
        (b"Envelope", 5),
    ];

    let mut paper_sources = PAPER_SOURCES.lock();

    for (i, (name, id)) in sources.iter().enumerate() {
        if i >= MAX_SOURCES {
            break;
        }

        let source = &mut paper_sources[i];
        source.valid = true;
        source.name_len = name.len().min(32) as u8;
        source.name[..source.name_len as usize].copy_from_slice(&name[..source.name_len as usize]);
        source.id = *id;
    }
}

// ============================================================================
// Page Setup Dialog API
// ============================================================================

/// Show page setup dialog
pub fn page_setup_dlg(psd: &mut PageSetupDlg) -> bool {
    if !PAGESETUP_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        return false;
    }

    // Initialize state from input
    state.margin_left = psd.margin.left;
    state.margin_top = psd.margin.top;
    state.margin_right = psd.margin.right;
    state.margin_bottom = psd.margin.bottom;

    // Create dialog
    let hwnd = create_page_setup_dialog(psd);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    // Run dialog
    let result = run_page_setup_dialog(hwnd, psd);

    // Get results
    if result {
        let state = CURRENT_STATE.lock();
        psd.margin.left = state.margin_left;
        psd.margin.top = state.margin_top;
        psd.margin.right = state.margin_right;
        psd.margin.bottom = state.margin_bottom;

        // Update paper size based on orientation
        if state.portrait {
            psd.paper_size = Point { x: 8500, y: 11000 };
        } else {
            psd.paper_size = Point { x: 11000, y: 8500 };
        }
    }

    // Clean up
    let mut state = CURRENT_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

/// Close page setup dialog
pub fn close_page_setup_dialog() {
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
pub fn get_dialog_state() -> PageSetupState {
    *CURRENT_STATE.lock()
}

// ============================================================================
// Paper Sources
// ============================================================================

/// Get paper sources
pub fn get_paper_sources() -> ([PaperSource; MAX_SOURCES], usize) {
    let sources = PAPER_SOURCES.lock();
    let count = sources.iter().filter(|s| s.valid).count();
    (*sources, count)
}

// ============================================================================
// Dialog Creation
// ============================================================================

/// Create page setup dialog window
fn create_page_setup_dialog(_psd: &PageSetupDlg) -> HWND {
    UserHandle::NULL
}

/// Run page setup dialog modal loop
fn run_page_setup_dialog(_hwnd: HWND, _psd: &mut PageSetupDlg) -> bool {
    true
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Page setup dialog window procedure
pub fn page_setup_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_page_setup_command(hwnd, wparam as u32)
        }
        super::message::WM_CLOSE => {
            close_page_setup_dialog();
            0
        }
        _ => 0,
    }
}

/// Handle page setup dialog commands
fn handle_page_setup_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        1 => {
            // OK button
            let state = CURRENT_STATE.lock();
            if state.active && state.hwnd == hwnd {
                drop(state);
                close_page_setup_dialog();
            }
            1
        }
        2 => {
            // Cancel button
            close_page_setup_dialog();
            0
        }
        100 => {
            // Portrait radio
            let mut state = CURRENT_STATE.lock();
            state.portrait = true;
            0
        }
        101 => {
            // Landscape radio
            let mut state = CURRENT_STATE.lock();
            state.portrait = false;
            0
        }
        200 => {
            // Paper size selection
            let mut state = CURRENT_STATE.lock();
            state.paper_size = ((command >> 16) & 0xFF) as u8;
            0
        }
        201 => {
            // Paper source selection
            let mut state = CURRENT_STATE.lock();
            state.paper_source = ((command >> 16) & 0xFF) as u8;
            0
        }
        300 => {
            // Printer button
            // Would show printer selection dialog
            0
        }
        _ => 0,
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert thousandths of inch to hundredths of mm
pub fn inches_to_mm(thousandths_inch: i32) -> i32 {
    // 1 inch = 25.4 mm
    // thousandths_inch / 1000 * 25.4 * 100 = thousandths_inch * 2.54
    (thousandths_inch as i64 * 254 / 100) as i32
}

/// Convert hundredths of mm to thousandths of inch
pub fn mm_to_inches(hundredths_mm: i32) -> i32 {
    // hundredths_mm / 100 / 25.4 * 1000 = hundredths_mm * 10 / 25.4
    (hundredths_mm as i64 * 100 / 254) as i32
}

/// Get printable area from paper size and margins
pub fn get_printable_area(paper_size: Point, margin: &Rect) -> Rect {
    Rect {
        left: margin.left,
        top: margin.top,
        right: paper_size.x - margin.right,
        bottom: paper_size.y - margin.bottom,
    }
}

/// Validate margins against paper size and minimum margins
pub fn validate_margins(
    paper_size: Point,
    margin: &Rect,
    min_margin: &Rect,
) -> bool {
    // Check against minimum
    if margin.left < min_margin.left ||
       margin.top < min_margin.top ||
       margin.right < min_margin.right ||
       margin.bottom < min_margin.bottom {
        return false;
    }

    // Check that margins don't exceed paper size
    if margin.left + margin.right >= paper_size.x {
        return false;
    }
    if margin.top + margin.bottom >= paper_size.y {
        return false;
    }

    true
}

/// Get paper size name
pub fn get_paper_size_name(size: super::printdlg::PaperSize) -> &'static [u8] {
    match size {
        super::printdlg::PaperSize::Letter => b"Letter (8.5\" x 11\")",
        super::printdlg::PaperSize::Legal => b"Legal (8.5\" x 14\")",
        super::printdlg::PaperSize::A4 => b"A4 (210mm x 297mm)",
        super::printdlg::PaperSize::A3 => b"A3 (297mm x 420mm)",
        super::printdlg::PaperSize::A5 => b"A5 (148mm x 210mm)",
        super::printdlg::PaperSize::B4 => b"B4 (250mm x 353mm)",
        super::printdlg::PaperSize::B5 => b"B5 (176mm x 250mm)",
        super::printdlg::PaperSize::Tabloid => b"Tabloid (11\" x 17\")",
        super::printdlg::PaperSize::Ledger => b"Ledger (17\" x 11\")",
        super::printdlg::PaperSize::Executive => b"Executive (7.25\" x 10.5\")",
        _ => b"Unknown",
    }
}

/// Create default page setup
pub fn create_default_page_setup() -> PageSetupDlg {
    let mut psd = PageSetupDlg::new();
    psd.flags = psd_flags::MARGINS | psd_flags::INTHOUSANDTHSOFINCHES;
    psd.paper_size = Point { x: 8500, y: 11000 }; // Letter
    psd.margin = Rect {
        left: 1000,  // 1 inch
        top: 1000,
        right: 1000,
        bottom: 1000,
    };
    psd.min_margin = Rect {
        left: 250,   // 0.25 inch
        top: 250,
        right: 250,
        bottom: 250,
    };
    psd
}
