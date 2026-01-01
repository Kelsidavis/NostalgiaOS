//! Printing Support
//!
//! Print spooler and printing UI support.
//! Based on Windows Server 2003 winspool.h and commdlg.h.
//!
//! # Features
//!
//! - Printer enumeration
//! - Print job management
//! - Print dialogs
//! - Page setup
//!
//! # References
//!
//! - `public/sdk/inc/winspool.h` - Print spooler API
//! - `public/sdk/inc/commdlg.h` - Print dialogs

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Rect};

// ============================================================================
// Printer Status Constants (PRINTER_STATUS_*)
// ============================================================================

/// Printer is paused
pub const PRINTER_STATUS_PAUSED: u32 = 0x00000001;

/// Error
pub const PRINTER_STATUS_ERROR: u32 = 0x00000002;

/// Pending deletion
pub const PRINTER_STATUS_PENDING_DELETION: u32 = 0x00000004;

/// Paper jam
pub const PRINTER_STATUS_PAPER_JAM: u32 = 0x00000008;

/// Paper out
pub const PRINTER_STATUS_PAPER_OUT: u32 = 0x00000010;

/// Manual feed
pub const PRINTER_STATUS_MANUAL_FEED: u32 = 0x00000020;

/// Paper problem
pub const PRINTER_STATUS_PAPER_PROBLEM: u32 = 0x00000040;

/// Offline
pub const PRINTER_STATUS_OFFLINE: u32 = 0x00000080;

/// IO active
pub const PRINTER_STATUS_IO_ACTIVE: u32 = 0x00000100;

/// Busy
pub const PRINTER_STATUS_BUSY: u32 = 0x00000200;

/// Printing
pub const PRINTER_STATUS_PRINTING: u32 = 0x00000400;

/// Output bin full
pub const PRINTER_STATUS_OUTPUT_BIN_FULL: u32 = 0x00000800;

/// Not available
pub const PRINTER_STATUS_NOT_AVAILABLE: u32 = 0x00001000;

/// Waiting
pub const PRINTER_STATUS_WAITING: u32 = 0x00002000;

/// Processing
pub const PRINTER_STATUS_PROCESSING: u32 = 0x00004000;

/// Initializing
pub const PRINTER_STATUS_INITIALIZING: u32 = 0x00008000;

/// Warming up
pub const PRINTER_STATUS_WARMING_UP: u32 = 0x00010000;

/// Toner low
pub const PRINTER_STATUS_TONER_LOW: u32 = 0x00020000;

/// No toner
pub const PRINTER_STATUS_NO_TONER: u32 = 0x00040000;

/// Page punt
pub const PRINTER_STATUS_PAGE_PUNT: u32 = 0x00080000;

/// User intervention
pub const PRINTER_STATUS_USER_INTERVENTION: u32 = 0x00100000;

/// Out of memory
pub const PRINTER_STATUS_OUT_OF_MEMORY: u32 = 0x00200000;

/// Door open
pub const PRINTER_STATUS_DOOR_OPEN: u32 = 0x00400000;

/// Server unknown
pub const PRINTER_STATUS_SERVER_UNKNOWN: u32 = 0x00800000;

/// Power save
pub const PRINTER_STATUS_POWER_SAVE: u32 = 0x01000000;

// ============================================================================
// Job Status Constants (JOB_STATUS_*)
// ============================================================================

/// Job paused
pub const JOB_STATUS_PAUSED: u32 = 0x00000001;

/// Job error
pub const JOB_STATUS_ERROR: u32 = 0x00000002;

/// Job deleting
pub const JOB_STATUS_DELETING: u32 = 0x00000004;

/// Job spooling
pub const JOB_STATUS_SPOOLING: u32 = 0x00000008;

/// Job printing
pub const JOB_STATUS_PRINTING: u32 = 0x00000010;

/// Job offline
pub const JOB_STATUS_OFFLINE: u32 = 0x00000020;

/// Job paperout
pub const JOB_STATUS_PAPEROUT: u32 = 0x00000040;

/// Job printed
pub const JOB_STATUS_PRINTED: u32 = 0x00000080;

/// Job deleted
pub const JOB_STATUS_DELETED: u32 = 0x00000100;

/// Job blocked
pub const JOB_STATUS_BLOCKED_DEVQ: u32 = 0x00000200;

/// Job user intervention
pub const JOB_STATUS_USER_INTERVENTION: u32 = 0x00000400;

/// Job restart
pub const JOB_STATUS_RESTART: u32 = 0x00000800;

/// Job complete
pub const JOB_STATUS_COMPLETE: u32 = 0x00001000;

// ============================================================================
// Print Dialog Flags (PD_*)
// ============================================================================

/// All pages
pub const PD_ALLPAGES: u32 = 0x00000000;

/// Selection
pub const PD_SELECTION: u32 = 0x00000001;

/// Page numbers
pub const PD_PAGENUMS: u32 = 0x00000002;

/// No selection
pub const PD_NOSELECTION: u32 = 0x00000004;

/// No page numbers
pub const PD_NOPAGENUMS: u32 = 0x00000008;

/// Collate
pub const PD_COLLATE: u32 = 0x00000010;

/// Print to file
pub const PD_PRINTTOFILE: u32 = 0x00000020;

/// Print setup
pub const PD_PRINTSETUP: u32 = 0x00000040;

/// No warning
pub const PD_NOWARNING: u32 = 0x00000080;

/// Return DC
pub const PD_RETURNDC: u32 = 0x00000100;

/// Return IC
pub const PD_RETURNIC: u32 = 0x00000200;

/// Return default
pub const PD_RETURNDEFAULT: u32 = 0x00000400;

/// Show help
pub const PD_SHOWHELP: u32 = 0x00000800;

/// Enable print hook
pub const PD_ENABLEPRINTHOOK: u32 = 0x00001000;

/// Enable setup hook
pub const PD_ENABLESETUPHOOK: u32 = 0x00002000;

/// Enable print template
pub const PD_ENABLEPRINTTEMPLATE: u32 = 0x00004000;

/// Enable setup template
pub const PD_ENABLESETUPTEMPLATE: u32 = 0x00008000;

/// Use devmode copies and collate
pub const PD_USEDEVMODECOPIESANDCOLLATE: u32 = 0x00040000;

/// Disable print to file
pub const PD_DISABLEPRINTTOFILE: u32 = 0x00080000;

/// Hide print to file
pub const PD_HIDEPRINTTOFILE: u32 = 0x00100000;

/// No current page
pub const PD_NOCURRENTPAGE: u32 = 0x00800000;

/// Current page
pub const PD_CURRENTPAGE: u32 = 0x00400000;

// ============================================================================
// Page Setup Flags (PSD_*)
// ============================================================================

/// Default min margins
pub const PSD_DEFAULTMINMARGINS: u32 = 0x00000000;

/// In thousandths of inches
pub const PSD_INTHOUSANDTHSOFINCHES: u32 = 0x00000004;

/// In hundredths of millimeters
pub const PSD_INHUNDREDTHSOFMILLIMETERS: u32 = 0x00000008;

/// Disable margins
pub const PSD_DISABLEMARGINS: u32 = 0x00000010;

/// Disable printers
pub const PSD_DISABLEPRINTER: u32 = 0x00000020;

/// No warning
pub const PSD_NOWARNING: u32 = 0x00000080;

/// Disable orientation
pub const PSD_DISABLEORIENTATION: u32 = 0x00000100;

/// Return default
pub const PSD_RETURNDEFAULT: u32 = 0x00000400;

/// Disable paper
pub const PSD_DISABLEPAPER: u32 = 0x00000200;

/// Show help
pub const PSD_SHOWHELP: u32 = 0x00000800;

/// Min margins
pub const PSD_MINMARGINS: u32 = 0x00000001;

/// Margins
pub const PSD_MARGINS: u32 = 0x00000002;

// ============================================================================
// Paper Sizes (DMPAPER_*)
// ============================================================================

/// Letter 8.5x11
pub const DMPAPER_LETTER: i16 = 1;

/// Letter small
pub const DMPAPER_LETTERSMALL: i16 = 2;

/// Tabloid 11x17
pub const DMPAPER_TABLOID: i16 = 3;

/// Ledger 17x11
pub const DMPAPER_LEDGER: i16 = 4;

/// Legal 8.5x14
pub const DMPAPER_LEGAL: i16 = 5;

/// Statement 5.5x8.5
pub const DMPAPER_STATEMENT: i16 = 6;

/// Executive 7.25x10.5
pub const DMPAPER_EXECUTIVE: i16 = 7;

/// A3 297x420mm
pub const DMPAPER_A3: i16 = 8;

/// A4 210x297mm
pub const DMPAPER_A4: i16 = 9;

/// A4 small
pub const DMPAPER_A4SMALL: i16 = 10;

/// A5 148x210mm
pub const DMPAPER_A5: i16 = 11;

/// B4 (JIS) 257x364mm
pub const DMPAPER_B4: i16 = 12;

/// B5 (JIS) 182x257mm
pub const DMPAPER_B5: i16 = 13;

/// Folio 8.5x13
pub const DMPAPER_FOLIO: i16 = 14;

/// Quarto 215x275mm
pub const DMPAPER_QUARTO: i16 = 15;

/// 10x14
pub const DMPAPER_10X14: i16 = 16;

/// 11x17
pub const DMPAPER_11X17: i16 = 17;

/// Note 8.5x11
pub const DMPAPER_NOTE: i16 = 18;

/// Envelope #9
pub const DMPAPER_ENV_9: i16 = 19;

/// Envelope #10
pub const DMPAPER_ENV_10: i16 = 20;

/// Envelope #11
pub const DMPAPER_ENV_11: i16 = 21;

/// Envelope #12
pub const DMPAPER_ENV_12: i16 = 22;

/// Envelope #14
pub const DMPAPER_ENV_14: i16 = 23;

// ============================================================================
// Orientation (DMORIENT_*)
// ============================================================================

/// Portrait
pub const DMORIENT_PORTRAIT: i16 = 1;

/// Landscape
pub const DMORIENT_LANDSCAPE: i16 = 2;

// ============================================================================
// Print Quality (DMRES_*)
// ============================================================================

/// Draft quality
pub const DMRES_DRAFT: i16 = -1;

/// Low quality
pub const DMRES_LOW: i16 = -2;

/// Medium quality
pub const DMRES_MEDIUM: i16 = -3;

/// High quality
pub const DMRES_HIGH: i16 = -4;

// ============================================================================
// Color Mode (DMCOLOR_*)
// ============================================================================

/// Monochrome
pub const DMCOLOR_MONOCHROME: i16 = 1;

/// Color
pub const DMCOLOR_COLOR: i16 = 2;

// ============================================================================
// Duplex Mode (DMDUP_*)
// ============================================================================

/// Simplex
pub const DMDUP_SIMPLEX: i16 = 1;

/// Vertical duplex
pub const DMDUP_VERTICAL: i16 = 2;

/// Horizontal duplex
pub const DMDUP_HORIZONTAL: i16 = 3;

// ============================================================================
// Constants
// ============================================================================

/// Maximum printers
pub const MAX_PRINTERS: usize = 16;

/// Maximum print jobs
pub const MAX_PRINT_JOBS: usize = 64;

/// Maximum name length
pub const MAX_PRINTER_NAME: usize = 128;

/// Maximum path length
pub const MAX_PATH: usize = 260;

// ============================================================================
// Printer Handle
// ============================================================================

/// Printer handle type
pub type HPRINTER = usize;

/// Null printer handle
pub const NULL_HPRINTER: HPRINTER = 0;

// ============================================================================
// Printer Info
// ============================================================================

/// Printer information
#[derive(Clone)]
pub struct PrinterInfo {
    /// Is this slot in use
    pub in_use: bool,
    /// Handle value
    pub handle: HPRINTER,
    /// Printer name
    pub name: [u8; MAX_PRINTER_NAME],
    /// Port name
    pub port: [u8; 64],
    /// Driver name
    pub driver: [u8; 64],
    /// Status
    pub status: u32,
    /// Jobs count
    pub jobs: u32,
    /// Is default printer
    pub is_default: bool,
    /// Is network printer
    pub is_network: bool,
}

impl PrinterInfo {
    /// Create empty printer
    pub const fn new() -> Self {
        Self {
            in_use: false,
            handle: 0,
            name: [0; MAX_PRINTER_NAME],
            port: [0; 64],
            driver: [0; 64],
            status: 0,
            jobs: 0,
            is_default: false,
            is_network: false,
        }
    }
}

// ============================================================================
// Print Job
// ============================================================================

/// Print job information
#[derive(Clone)]
pub struct PrintJob {
    /// Is this slot in use
    pub in_use: bool,
    /// Job ID
    pub job_id: u32,
    /// Printer handle
    pub printer: HPRINTER,
    /// Document name
    pub document: [u8; MAX_PATH],
    /// Status
    pub status: u32,
    /// Priority
    pub priority: u32,
    /// Pages printed
    pub pages_printed: u32,
    /// Total pages
    pub total_pages: u32,
    /// Bytes printed
    pub bytes_printed: u32,
    /// Total bytes
    pub total_bytes: u32,
}

impl PrintJob {
    /// Create empty job
    pub const fn new() -> Self {
        Self {
            in_use: false,
            job_id: 0,
            printer: 0,
            document: [0; MAX_PATH],
            status: 0,
            priority: 1,
            pages_printed: 0,
            total_pages: 0,
            bytes_printed: 0,
            total_bytes: 0,
        }
    }
}

// ============================================================================
// DEVMODE Structure (simplified)
// ============================================================================

/// Device mode
#[derive(Clone)]
pub struct DevMode {
    /// Device name
    pub device_name: [u8; 32],
    /// Spec version
    pub spec_version: u16,
    /// Driver version
    pub driver_version: u16,
    /// Size
    pub size: u16,
    /// Driver extra
    pub driver_extra: u16,
    /// Fields
    pub fields: u32,
    /// Orientation
    pub orientation: i16,
    /// Paper size
    pub paper_size: i16,
    /// Paper length
    pub paper_length: i16,
    /// Paper width
    pub paper_width: i16,
    /// Scale
    pub scale: i16,
    /// Copies
    pub copies: i16,
    /// Default source
    pub default_source: i16,
    /// Print quality
    pub print_quality: i16,
    /// Color
    pub color: i16,
    /// Duplex
    pub duplex: i16,
    /// Y resolution
    pub y_resolution: i16,
    /// TT option
    pub tt_option: i16,
    /// Collate
    pub collate: i16,
}

impl DevMode {
    /// Create default devmode
    pub const fn new() -> Self {
        Self {
            device_name: [0; 32],
            spec_version: 0x0401,
            driver_version: 0,
            size: 0,
            driver_extra: 0,
            fields: 0,
            orientation: DMORIENT_PORTRAIT,
            paper_size: DMPAPER_LETTER,
            paper_length: 0,
            paper_width: 0,
            scale: 100,
            copies: 1,
            default_source: 0,
            print_quality: DMRES_HIGH,
            color: DMCOLOR_COLOR,
            duplex: DMDUP_SIMPLEX,
            y_resolution: 0,
            tt_option: 0,
            collate: 0,
        }
    }
}

// ============================================================================
// Print Dialog Structure
// ============================================================================

/// Print dialog info
#[derive(Clone)]
pub struct PrintDlgInfo {
    /// Structure size
    pub struct_size: u32,
    /// Owner window
    pub owner: HWND,
    /// Device mode
    pub dev_mode: DevMode,
    /// Flags
    pub flags: u32,
    /// From page
    pub from_page: u16,
    /// To page
    pub to_page: u16,
    /// Min page
    pub min_page: u16,
    /// Max page
    pub max_page: u16,
    /// Copies
    pub copies: u16,
    /// Result DC
    pub dc: usize,
}

impl PrintDlgInfo {
    /// Create default dialog
    pub const fn new() -> Self {
        Self {
            struct_size: 0,
            owner: UserHandle::NULL,
            dev_mode: DevMode::new(),
            flags: 0,
            from_page: 1,
            to_page: 1,
            min_page: 1,
            max_page: 9999,
            copies: 1,
            dc: 0,
        }
    }
}

// ============================================================================
// Page Setup Dialog Structure
// ============================================================================

/// Page setup dialog info
#[derive(Clone, Copy)]
pub struct PageSetupDlgInfo {
    /// Structure size
    pub struct_size: u32,
    /// Owner window
    pub owner: HWND,
    /// Flags
    pub flags: u32,
    /// Paper size (in units specified by flags)
    pub paper_size: (i32, i32),
    /// Min margins
    pub min_margin: Rect,
    /// Margins
    pub margin: Rect,
}

impl PageSetupDlgInfo {
    /// Create default dialog
    pub const fn new() -> Self {
        Self {
            struct_size: 0,
            owner: UserHandle::NULL,
            flags: 0,
            paper_size: (8500, 11000), // Letter in thousandths
            min_margin: Rect {
                left: 250,
                top: 250,
                right: 250,
                bottom: 250,
            },
            margin: Rect {
                left: 1000,
                top: 1000,
                right: 1000,
                bottom: 1000,
            },
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global printer storage
static PRINTERS: SpinLock<[PrinterInfo; MAX_PRINTERS]> =
    SpinLock::new([const { PrinterInfo::new() }; MAX_PRINTERS]);

/// Global print job storage
static PRINT_JOBS: SpinLock<[PrintJob; MAX_PRINT_JOBS]> =
    SpinLock::new([const { PrintJob::new() }; MAX_PRINT_JOBS]);

/// Next printer handle
static NEXT_PRINTER: SpinLock<HPRINTER> = SpinLock::new(1);

/// Next job ID
static NEXT_JOB_ID: SpinLock<u32> = SpinLock::new(1);

/// Default printer name
static DEFAULT_PRINTER: SpinLock<[u8; MAX_PRINTER_NAME]> = SpinLock::new([0; MAX_PRINTER_NAME]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize printing support
pub fn init() {
    // Register some default printers
    register_default_printers();
    crate::serial_println!("[USER] Printing support initialized");
}

/// Register default printers
fn register_default_printers() {
    // Add a default printer
    let mut printers = PRINTERS.lock();
    let mut next = NEXT_PRINTER.lock();

    if let Some(printer) = printers.first_mut() {
        printer.in_use = true;
        printer.handle = *next;
        *next += 1;

        let name = b"Microsoft XPS Document Writer";
        let len = name.len().min(MAX_PRINTER_NAME - 1);
        printer.name[..len].copy_from_slice(&name[..len]);
        printer.name[len] = 0;

        let port = b"XPSPort:";
        let plen = port.len().min(63);
        printer.port[..plen].copy_from_slice(&port[..plen]);
        printer.port[plen] = 0;

        let driver = b"Microsoft XPS Document Writer";
        let dlen = driver.len().min(63);
        printer.driver[..dlen].copy_from_slice(&driver[..dlen]);
        printer.driver[dlen] = 0;

        printer.status = 0;
        printer.is_default = true;

        // Set as default
        drop(printers);
        drop(next);
        let mut default = DEFAULT_PRINTER.lock();
        default[..len].copy_from_slice(&name[..len]);
        default[len] = 0;
    }
}

/// Open printer
pub fn open_printer(printer_name: &[u8], printer: &mut HPRINTER) -> bool {
    let printers = PRINTERS.lock();

    for p in printers.iter() {
        if p.in_use {
            let name_len = super::strhelp::str_len(&p.name);
            let query_len = super::strhelp::str_len(printer_name);
            if name_len == query_len &&
               super::strhelp::str_cmp_ni(&p.name, printer_name, name_len) == 0 {
                *printer = p.handle;
                return true;
            }
        }
    }

    *printer = NULL_HPRINTER;
    false
}

/// Close printer
pub fn close_printer(printer: HPRINTER) -> bool {
    let _ = printer;
    // Printers are persistent, just return success
    true
}

/// Get default printer
pub fn get_default_printer(buffer: &mut [u8]) -> bool {
    let default = DEFAULT_PRINTER.lock();
    let len = super::strhelp::str_len(&*default);

    if len == 0 {
        return false;
    }

    let copy_len = len.min(buffer.len().saturating_sub(1));
    buffer[..copy_len].copy_from_slice(&default[..copy_len]);
    if copy_len < buffer.len() {
        buffer[copy_len] = 0;
    }

    true
}

/// Set default printer
pub fn set_default_printer(printer_name: &[u8]) -> bool {
    // Verify printer exists
    let printers = PRINTERS.lock();
    let mut found = false;

    for p in printers.iter() {
        if p.in_use {
            let name_len = super::strhelp::str_len(&p.name);
            let query_len = super::strhelp::str_len(printer_name);
            if name_len == query_len &&
               super::strhelp::str_cmp_ni(&p.name, printer_name, name_len) == 0 {
                found = true;
                break;
            }
        }
    }

    drop(printers);

    if found {
        let mut default = DEFAULT_PRINTER.lock();
        let len = super::strhelp::str_len(printer_name).min(MAX_PRINTER_NAME - 1);
        default[..len].copy_from_slice(&printer_name[..len]);
        default[len] = 0;
        true
    } else {
        false
    }
}

/// Enumerate printers
pub fn enum_printers(flags: u32, name: Option<&[u8]>, count: &mut u32) -> bool {
    let _ = (flags, name);

    let printers = PRINTERS.lock();
    let mut c = 0u32;

    for p in printers.iter() {
        if p.in_use {
            c += 1;
        }
    }

    *count = c;
    true
}

/// Get printer info
pub fn get_printer(printer: HPRINTER, level: u32, info: &mut PrinterInfo) -> bool {
    let _ = level;

    let printers = PRINTERS.lock();

    for p in printers.iter() {
        if p.in_use && p.handle == printer {
            *info = p.clone();
            return true;
        }
    }

    false
}

/// Start document
pub fn start_doc_printer(printer: HPRINTER, doc_name: &[u8]) -> u32 {
    let mut jobs = PRINT_JOBS.lock();
    let mut next_id = NEXT_JOB_ID.lock();

    for job in jobs.iter_mut() {
        if !job.in_use {
            let job_id = *next_id;
            *next_id += 1;

            job.in_use = true;
            job.job_id = job_id;
            job.printer = printer;
            job.status = JOB_STATUS_SPOOLING;

            let len = super::strhelp::str_len(doc_name).min(MAX_PATH - 1);
            job.document[..len].copy_from_slice(&doc_name[..len]);
            job.document[len] = 0;

            return job_id;
        }
    }

    0
}

/// End document
pub fn end_doc_printer(printer: HPRINTER) -> bool {
    let mut jobs = PRINT_JOBS.lock();

    for job in jobs.iter_mut() {
        if job.in_use && job.printer == printer &&
           (job.status & JOB_STATUS_SPOOLING) != 0 {
            job.status = JOB_STATUS_PRINTED;
            return true;
        }
    }

    false
}

/// Abort document
pub fn abort_printer(printer: HPRINTER) -> bool {
    let mut jobs = PRINT_JOBS.lock();

    for job in jobs.iter_mut() {
        if job.in_use && job.printer == printer &&
           (job.status & JOB_STATUS_SPOOLING) != 0 {
            job.status = JOB_STATUS_DELETED;
            job.in_use = false;
            return true;
        }
    }

    false
}

/// Start page
pub fn start_page_printer(printer: HPRINTER) -> bool {
    let _ = printer;
    true
}

/// End page
pub fn end_page_printer(printer: HPRINTER) -> bool {
    let mut jobs = PRINT_JOBS.lock();

    for job in jobs.iter_mut() {
        if job.in_use && job.printer == printer {
            job.pages_printed += 1;
            return true;
        }
    }

    false
}

/// Write printer data
pub fn write_printer(printer: HPRINTER, data: &[u8]) -> u32 {
    let mut jobs = PRINT_JOBS.lock();

    for job in jobs.iter_mut() {
        if job.in_use && job.printer == printer {
            job.bytes_printed += data.len() as u32;
            return data.len() as u32;
        }
    }

    0
}

/// Get job info
pub fn get_job(printer: HPRINTER, job_id: u32, _level: u32, info: &mut PrintJob) -> bool {
    let jobs = PRINT_JOBS.lock();

    for job in jobs.iter() {
        if job.in_use && job.printer == printer && job.job_id == job_id {
            *info = job.clone();
            return true;
        }
    }

    false
}

/// Set job info
pub fn set_job(printer: HPRINTER, job_id: u32, _level: u32, command: u32) -> bool {
    let mut jobs = PRINT_JOBS.lock();

    for job in jobs.iter_mut() {
        if job.in_use && job.printer == printer && job.job_id == job_id {
            match command {
                0 => {} // JOB_CONTROL_NONE
                1 => job.status |= JOB_STATUS_PAUSED,  // JOB_CONTROL_PAUSE
                2 => job.status &= !JOB_STATUS_PAUSED, // JOB_CONTROL_RESUME
                3 => {                                  // JOB_CONTROL_CANCEL
                    job.status = JOB_STATUS_DELETED;
                    job.in_use = false;
                }
                4 => job.status |= JOB_STATUS_RESTART, // JOB_CONTROL_RESTART
                5 => {                                  // JOB_CONTROL_DELETE
                    job.in_use = false;
                }
                _ => return false,
            }
            return true;
        }
    }

    false
}

/// Enumerate jobs
pub fn enum_jobs(
    printer: HPRINTER,
    first_job: u32,
    _no_jobs: u32,
    _level: u32,
    count: &mut u32,
) -> bool {
    let jobs = PRINT_JOBS.lock();
    let mut c = 0u32;
    let mut skipped = 0u32;

    for job in jobs.iter() {
        if job.in_use && job.printer == printer {
            if skipped >= first_job {
                c += 1;
            } else {
                skipped += 1;
            }
        }
    }

    *count = c;
    true
}

// ============================================================================
// Print Dialog Functions
// ============================================================================

/// Show print dialog
pub fn print_dlg(info: &mut PrintDlgInfo) -> bool {
    // In a real implementation, this would show a dialog
    // For now, just set up with defaults

    if (info.flags & PD_RETURNDEFAULT) != 0 {
        // Return default printer without showing dialog
        let default = DEFAULT_PRINTER.lock();
        let len = super::strhelp::str_len(&*default);
        if len > 0 {
            let name_len = len.min(31);
            info.dev_mode.device_name[..name_len].copy_from_slice(&default[..name_len]);
            info.dev_mode.device_name[name_len] = 0;
            return true;
        }
        return false;
    }

    // Would show dialog and return user selection
    true
}

/// Show page setup dialog
pub fn page_setup_dlg(info: &mut PageSetupDlgInfo) -> bool {
    // In a real implementation, this would show a dialog
    // For now, just return success with defaults

    if (info.flags & PSD_RETURNDEFAULT) != 0 {
        // Just return defaults
        return true;
    }

    // Would show dialog and return user selection
    true
}

/// Get printer DC
pub fn create_dc(
    driver: &[u8],
    device: &[u8],
    _output: Option<&[u8]>,
    _dev_mode: Option<&DevMode>,
) -> usize {
    let _ = (driver, device);
    // Would create a device context for the printer
    // Return a fake DC handle
    1
}

/// Delete DC
pub fn delete_dc(dc: usize) -> bool {
    let _ = dc;
    true
}

// ============================================================================
// Document Info
// ============================================================================

/// Document info
#[derive(Clone)]
pub struct DocInfo {
    /// Size
    pub size: u32,
    /// Document name
    pub doc_name: [u8; MAX_PATH],
    /// Output file
    pub output: [u8; MAX_PATH],
    /// Data type
    pub data_type: [u8; 32],
}

impl DocInfo {
    /// Create default doc info
    pub const fn new() -> Self {
        Self {
            size: 0,
            doc_name: [0; MAX_PATH],
            output: [0; MAX_PATH],
            data_type: [0; 32],
        }
    }
}

/// Start document (GDI style)
pub fn start_doc(dc: usize, doc: &DocInfo) -> i32 {
    let _ = dc;

    // Get first available printer
    let printers = PRINTERS.lock();
    let printer = printers.iter().find(|p| p.in_use).map(|p| p.handle);
    drop(printers);

    if let Some(h) = printer {
        start_doc_printer(h, &doc.doc_name) as i32
    } else {
        -1
    }
}

/// End document (GDI style)
pub fn end_doc(dc: usize) -> i32 {
    let _ = dc;
    // Would end the document
    1
}

/// Start page (GDI style)
pub fn start_page(dc: usize) -> i32 {
    let _ = dc;
    1
}

/// End page (GDI style)
pub fn end_page(dc: usize) -> i32 {
    let _ = dc;
    1
}

/// Abort document (GDI style)
pub fn abort_doc(dc: usize) -> i32 {
    let _ = dc;
    1
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> PrintStats {
    let printers = PRINTERS.lock();
    let jobs = PRINT_JOBS.lock();

    let mut printer_count = 0;
    let mut job_count = 0;
    let mut pending_count = 0;

    for p in printers.iter() {
        if p.in_use {
            printer_count += 1;
        }
    }

    for j in jobs.iter() {
        if j.in_use {
            job_count += 1;
            if (j.status & (JOB_STATUS_SPOOLING | JOB_STATUS_PRINTING)) != 0 {
                pending_count += 1;
            }
        }
    }

    PrintStats {
        max_printers: MAX_PRINTERS,
        registered_printers: printer_count,
        max_jobs: MAX_PRINT_JOBS,
        active_jobs: job_count,
        pending_jobs: pending_count,
    }
}

/// Print statistics
#[derive(Debug, Clone, Copy)]
pub struct PrintStats {
    pub max_printers: usize,
    pub registered_printers: usize,
    pub max_jobs: usize,
    pub active_jobs: usize,
    pub pending_jobs: usize,
}
