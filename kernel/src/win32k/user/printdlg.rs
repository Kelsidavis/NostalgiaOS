//! Print Dialog
//!
//! Provides the Print dialog following the Windows comdlg32
//! PrintDlg/PrintDlgEx patterns.
//!
//! # References
//!
//! - Windows Server 2003 comdlg32 print dialog
//! - PRINTDLG structure

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum printer name length
pub const MAX_PRINTER_NAME: usize = 64;

/// Maximum port name length
pub const MAX_PORT_NAME: usize = 64;

/// Maximum driver name length
pub const MAX_DRIVER_NAME: usize = 64;

/// Print dialog flags (PD_*)
pub mod pd_flags {
    /// All pages
    pub const ALLPAGES: u32 = 0x00000000;
    /// Selection only
    pub const SELECTION: u32 = 0x00000001;
    /// Page range
    pub const PAGENUMS: u32 = 0x00000002;
    /// No selection option
    pub const NOSELECTION: u32 = 0x00000004;
    /// No page numbers
    pub const NOPAGENUMS: u32 = 0x00000008;
    /// Collate copies
    pub const COLLATE: u32 = 0x00000010;
    /// Print to file
    pub const PRINTTOFILE: u32 = 0x00000020;
    /// Print setup dialog
    pub const PRINTSETUP: u32 = 0x00000040;
    /// No warning
    pub const NOWARNING: u32 = 0x00000080;
    /// Return DC
    pub const RETURNDC: u32 = 0x00000100;
    /// Return IC
    pub const RETURNIC: u32 = 0x00000200;
    /// Return default
    pub const RETURNDEFAULT: u32 = 0x00000400;
    /// Show help
    pub const SHOWHELP: u32 = 0x00000800;
    /// Enable print hook
    pub const ENABLEPRINTHOOK: u32 = 0x00001000;
    /// Enable setup hook
    pub const ENABLESETUPHOOK: u32 = 0x00002000;
    /// Enable print template
    pub const ENABLEPRINTTEMPLATE: u32 = 0x00004000;
    /// Enable setup template
    pub const ENABLESETUPTEMPLATE: u32 = 0x00008000;
    /// Enable print template handle
    pub const ENABLEPRINTTEMPLATEHANDLE: u32 = 0x00010000;
    /// Enable setup template handle
    pub const ENABLESETUPTEMPLATEHANDLE: u32 = 0x00020000;
    /// Use device mode copies
    pub const USEDEVMODECOPIES: u32 = 0x00040000;
    /// Use device mode copies and collate
    pub const USEDEVMODECOPIESANDCOLLATE: u32 = 0x00040000;
    /// Disable print to file
    pub const DISABLEPRINTTOFILE: u32 = 0x00080000;
    /// Hide print to file
    pub const HIDEPRINTTOFILE: u32 = 0x00100000;
    /// No current page
    pub const NOCURRENTPAGE: u32 = 0x00800000;
    /// Current page
    pub const CURRENTPAGE: u32 = 0x00400000;
    /// Exclusive selection
    pub const EXCLUSIVESELECTION: u32 = 0x01000000;
    /// Use large template
    pub const USELARGETEMPLATE: u32 = 0x10000000;
}

/// Print range type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrintRange {
    #[default]
    /// All pages
    All = 0,
    /// Selection only
    Selection = 1,
    /// Page range
    Pages = 2,
    /// Current page
    CurrentPage = 3,
}

/// Orientation
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Orientation {
    #[default]
    Portrait = 1,
    Landscape = 2,
}

/// Paper size
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaperSize {
    #[default]
    Letter = 1,
    LetterSmall = 2,
    Tabloid = 3,
    Ledger = 4,
    Legal = 5,
    Statement = 6,
    Executive = 7,
    A3 = 8,
    A4 = 9,
    A4Small = 10,
    A5 = 11,
    B4 = 12,
    B5 = 13,
    Folio = 14,
    Quarto = 15,
    Size10x14 = 16,
    Size11x17 = 17,
    Note = 18,
    Envelope9 = 19,
    Envelope10 = 20,
}

// ============================================================================
// Structures
// ============================================================================

/// Print dialog structure (PRINTDLG equivalent)
#[derive(Debug, Clone, Copy)]
pub struct PrintDlg {
    /// Structure size
    pub struct_size: u32,
    /// Owner window
    pub hwnd_owner: HWND,
    /// Device mode handle
    pub dev_mode: u32,
    /// Device names handle
    pub dev_names: u32,
    /// Printer DC
    pub hdc: u32,
    /// Flags
    pub flags: u32,
    /// From page
    pub from_page: u16,
    /// To page
    pub to_page: u16,
    /// Minimum page
    pub min_page: u16,
    /// Maximum page
    pub max_page: u16,
    /// Number of copies
    pub copies: u16,
    /// Instance
    pub instance: u32,
    /// Custom data
    pub cust_data: usize,
    /// Print hook
    pub print_hook: usize,
    /// Setup hook
    pub setup_hook: usize,
    /// Print template name
    pub print_template_name: u32,
    /// Setup template name
    pub setup_template_name: u32,
    /// Print template handle
    pub print_template: u32,
    /// Setup template handle
    pub setup_template: u32,
}

impl PrintDlg {
    pub const fn new() -> Self {
        Self {
            struct_size: 0,
            hwnd_owner: UserHandle::NULL,
            dev_mode: 0,
            dev_names: 0,
            hdc: 0,
            flags: 0,
            from_page: 1,
            to_page: 1,
            min_page: 1,
            max_page: 9999,
            copies: 1,
            instance: 0,
            cust_data: 0,
            print_hook: 0,
            setup_hook: 0,
            print_template_name: 0,
            setup_template_name: 0,
            print_template: 0,
            setup_template: 0,
        }
    }
}

/// Printer information
#[derive(Debug, Clone, Copy)]
pub struct PrinterInfo {
    /// Printer is valid
    pub valid: bool,
    /// Is default printer
    pub is_default: bool,
    /// Printer name length
    pub name_len: u8,
    /// Printer name
    pub name: [u8; MAX_PRINTER_NAME],
    /// Port name length
    pub port_len: u8,
    /// Port name
    pub port: [u8; MAX_PORT_NAME],
    /// Driver name length
    pub driver_len: u8,
    /// Driver name
    pub driver: [u8; MAX_DRIVER_NAME],
    /// Status flags
    pub status: u32,
    /// Jobs in queue
    pub jobs: u32,
}

impl PrinterInfo {
    const fn new() -> Self {
        Self {
            valid: false,
            is_default: false,
            name_len: 0,
            name: [0; MAX_PRINTER_NAME],
            port_len: 0,
            port: [0; MAX_PORT_NAME],
            driver_len: 0,
            driver: [0; MAX_DRIVER_NAME],
            status: 0,
            jobs: 0,
        }
    }
}

/// Device mode structure (simplified DEVMODE)
#[derive(Debug, Clone, Copy)]
pub struct DevMode {
    /// Device name length
    pub device_name_len: u8,
    /// Device name
    pub device_name: [u8; 32],
    /// Orientation
    pub orientation: Orientation,
    /// Paper size
    pub paper_size: PaperSize,
    /// Paper length (tenths of mm)
    pub paper_length: u16,
    /// Paper width (tenths of mm)
    pub paper_width: u16,
    /// Scale (percent)
    pub scale: u16,
    /// Copies
    pub copies: u16,
    /// Default source
    pub default_source: u16,
    /// Print quality (DPI or negative for draft/low/medium/high)
    pub print_quality: i16,
    /// Color mode (1 = mono, 2 = color)
    pub color: u16,
    /// Duplex mode
    pub duplex: u16,
    /// Y resolution (DPI)
    pub y_resolution: i16,
    /// TrueType option
    pub tt_option: u16,
    /// Collate
    pub collate: bool,
}

impl DevMode {
    pub const fn new() -> Self {
        Self {
            device_name_len: 0,
            device_name: [0; 32],
            orientation: Orientation::Portrait,
            paper_size: PaperSize::Letter,
            paper_length: 2794, // Letter: 11 inches = 279.4mm
            paper_width: 2159,  // Letter: 8.5 inches = 215.9mm
            scale: 100,
            copies: 1,
            default_source: 0,
            print_quality: 300,
            color: 1,
            duplex: 1,
            y_resolution: 300,
            tt_option: 0,
            collate: false,
        }
    }
}

/// Print dialog state
#[derive(Debug, Clone, Copy)]
pub struct PrintDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// Print range
    pub print_range: PrintRange,
    /// From page
    pub from_page: u16,
    /// To page
    pub to_page: u16,
    /// Copies
    pub copies: u16,
    /// Collate
    pub collate: bool,
    /// Print to file
    pub print_to_file: bool,
    /// Selected printer index
    pub printer_index: u8,
}

impl PrintDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            print_range: PrintRange::All,
            from_page: 1,
            to_page: 1,
            copies: 1,
            collate: false,
            print_to_file: false,
            printer_index: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static PRINTDLG_INITIALIZED: AtomicBool = AtomicBool::new(false);
static PRINTDLG_LOCK: SpinLock<()> = SpinLock::new(());
static PRINT_COUNT: AtomicU32 = AtomicU32::new(0);

static CURRENT_STATE: SpinLock<PrintDialogState> = SpinLock::new(PrintDialogState::new());
static CURRENT_DEVMODE: SpinLock<DevMode> = SpinLock::new(DevMode::new());

// Printer list
const MAX_PRINTERS: usize = 16;
static PRINTER_LIST: SpinLock<[PrinterInfo; MAX_PRINTERS]> =
    SpinLock::new([const { PrinterInfo::new() }; MAX_PRINTERS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize print dialog subsystem
pub fn init() {
    let _guard = PRINTDLG_LOCK.lock();

    if PRINTDLG_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[PRINTDLG] Initializing print dialog...");

    // Initialize default printers
    init_default_printers();

    PRINTDLG_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[PRINTDLG] Print dialog initialized");
}

/// Initialize default printers
fn init_default_printers() {
    let mut printers = PRINTER_LIST.lock();

    // Add a default printer
    let printer = &mut printers[0];
    printer.valid = true;
    printer.is_default = true;
    let name = b"Default Printer";
    printer.name_len = name.len() as u8;
    printer.name[..name.len()].copy_from_slice(name);
    let port = b"LPT1:";
    printer.port_len = port.len() as u8;
    printer.port[..port.len()].copy_from_slice(port);
    let driver = b"Generic / Text Only";
    printer.driver_len = driver.len() as u8;
    printer.driver[..driver.len()].copy_from_slice(driver);
}

// ============================================================================
// Print Dialog API
// ============================================================================

/// Show print dialog
pub fn print_dlg(pd: &mut PrintDlg) -> bool {
    if !PRINTDLG_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        return false;
    }

    // Initialize state
    state.print_range = if (pd.flags & pd_flags::SELECTION) != 0 {
        PrintRange::Selection
    } else if (pd.flags & pd_flags::PAGENUMS) != 0 {
        PrintRange::Pages
    } else {
        PrintRange::All
    };
    state.from_page = pd.from_page;
    state.to_page = pd.to_page;
    state.copies = pd.copies;
    state.collate = (pd.flags & pd_flags::COLLATE) != 0;
    state.print_to_file = (pd.flags & pd_flags::PRINTTOFILE) != 0;

    // Create dialog
    let hwnd = create_print_dialog(pd);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    // Run dialog
    let result = run_print_dialog(hwnd, pd);

    // Get results
    if result {
        let state = CURRENT_STATE.lock();
        pd.from_page = state.from_page;
        pd.to_page = state.to_page;
        pd.copies = state.copies;

        pd.flags &= !(pd_flags::ALLPAGES | pd_flags::SELECTION | pd_flags::PAGENUMS);
        match state.print_range {
            PrintRange::All => pd.flags |= pd_flags::ALLPAGES,
            PrintRange::Selection => pd.flags |= pd_flags::SELECTION,
            PrintRange::Pages => pd.flags |= pd_flags::PAGENUMS,
            PrintRange::CurrentPage => pd.flags |= pd_flags::CURRENTPAGE,
        }

        if state.collate {
            pd.flags |= pd_flags::COLLATE;
        }
        if state.print_to_file {
            pd.flags |= pd_flags::PRINTTOFILE;
        }
    }

    // Clean up
    let mut state = CURRENT_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    PRINT_COUNT.fetch_add(1, Ordering::Relaxed);

    result
}

/// Close print dialog
pub fn close_print_dialog() {
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
pub fn get_dialog_state() -> PrintDialogState {
    *CURRENT_STATE.lock()
}

/// Get current device mode
pub fn get_dev_mode() -> DevMode {
    *CURRENT_DEVMODE.lock()
}

/// Set device mode
pub fn set_dev_mode(dm: &DevMode) {
    *CURRENT_DEVMODE.lock() = *dm;
}

// ============================================================================
// Printer Management
// ============================================================================

/// Get printer list
pub fn get_printer_list() -> ([PrinterInfo; MAX_PRINTERS], usize) {
    let printers = PRINTER_LIST.lock();
    let count = printers.iter().filter(|p| p.valid).count();
    (*printers, count)
}

/// Get default printer
pub fn get_default_printer() -> Option<PrinterInfo> {
    let printers = PRINTER_LIST.lock();

    for printer in printers.iter() {
        if printer.valid && printer.is_default {
            return Some(*printer);
        }
    }

    None
}

/// Set default printer by index
pub fn set_default_printer(index: usize) -> bool {
    let mut printers = PRINTER_LIST.lock();

    if index >= MAX_PRINTERS || !printers[index].valid {
        return false;
    }

    // Clear existing default
    for printer in printers.iter_mut() {
        printer.is_default = false;
    }

    printers[index].is_default = true;
    true
}

// ============================================================================
// Dialog Creation
// ============================================================================

/// Create print dialog window
fn create_print_dialog(_pd: &PrintDlg) -> HWND {
    UserHandle::NULL
}

/// Run print dialog modal loop
fn run_print_dialog(_hwnd: HWND, _pd: &mut PrintDlg) -> bool {
    true
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// Print dialog window procedure
pub fn print_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_print_command(hwnd, wparam as u32)
        }
        super::message::WM_CLOSE => {
            close_print_dialog();
            0
        }
        _ => 0,
    }
}

/// Handle print dialog commands
fn handle_print_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        1 => {
            // OK/Print button
            let state = CURRENT_STATE.lock();
            if state.active && state.hwnd == hwnd {
                drop(state);
                close_print_dialog();
            }
            1
        }
        2 => {
            // Cancel button
            close_print_dialog();
            0
        }
        100 => {
            // All pages radio
            let mut state = CURRENT_STATE.lock();
            state.print_range = PrintRange::All;
            0
        }
        101 => {
            // Selection radio
            let mut state = CURRENT_STATE.lock();
            state.print_range = PrintRange::Selection;
            0
        }
        102 => {
            // Pages radio
            let mut state = CURRENT_STATE.lock();
            state.print_range = PrintRange::Pages;
            0
        }
        103 => {
            // Current page radio
            let mut state = CURRENT_STATE.lock();
            state.print_range = PrintRange::CurrentPage;
            0
        }
        200 => {
            // Collate checkbox
            let mut state = CURRENT_STATE.lock();
            state.collate = !state.collate;
            0
        }
        201 => {
            // Print to file checkbox
            let mut state = CURRENT_STATE.lock();
            state.print_to_file = !state.print_to_file;
            0
        }
        300 => {
            // Printer selection changed
            let mut state = CURRENT_STATE.lock();
            state.printer_index = ((command >> 16) & 0xFF) as u8;
            0
        }
        400 => {
            // Properties button
            // Would show printer properties dialog
            0
        }
        _ => 0,
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get paper size dimensions in tenths of mm
pub fn get_paper_dimensions(size: PaperSize) -> (u16, u16) {
    match size {
        PaperSize::Letter => (2159, 2794),      // 8.5" x 11"
        PaperSize::Legal => (2159, 3556),       // 8.5" x 14"
        PaperSize::A4 => (2100, 2970),          // 210mm x 297mm
        PaperSize::A3 => (2970, 4200),          // 297mm x 420mm
        PaperSize::A5 => (1480, 2100),          // 148mm x 210mm
        PaperSize::B4 => (2500, 3530),          // 250mm x 353mm
        PaperSize::B5 => (1760, 2500),          // 176mm x 250mm
        PaperSize::Tabloid => (2794, 4318),     // 11" x 17"
        PaperSize::Ledger => (4318, 2794),      // 17" x 11"
        PaperSize::Executive => (1841, 2667),   // 7.25" x 10.5"
        _ => (2159, 2794), // Default to Letter
    }
}

/// Convert inches to tenths of mm
pub fn inches_to_tenths_mm(inches: f32) -> u16 {
    (inches * 254.0) as u16
}

/// Convert tenths of mm to inches
pub fn tenths_mm_to_inches(tenths: u16) -> f32 {
    tenths as f32 / 254.0
}
