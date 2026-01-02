//! Printers and Faxes Control Panel
//!
//! Kernel-mode printer management dialog following Windows NT patterns.
//! Provides printer enumeration, installation, properties, and job management.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `printscan/print/spooler/` - Print spooler
//! - `shell/cpls/printers/` - Printers control panel

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// Maximum printers
const MAX_PRINTERS: usize = 32;

/// Maximum print jobs per printer
const MAX_JOBS: usize = 64;

/// Maximum printer name length
const MAX_NAME: usize = 256;

/// Maximum port name length
const MAX_PORT: usize = 64;

/// Maximum driver name length
const MAX_DRIVER: usize = 256;

/// Maximum location length
const MAX_LOCATION: usize = 256;

/// Maximum comment length
const MAX_COMMENT: usize = 256;

/// Maximum document name length
const MAX_DOCUMENT: usize = 256;

/// Printer status codes
pub mod printer_status {
    pub const READY: u32 = 0x00000000;
    pub const PAUSED: u32 = 0x00000001;
    pub const ERROR: u32 = 0x00000002;
    pub const PENDING_DELETION: u32 = 0x00000004;
    pub const PAPER_JAM: u32 = 0x00000008;
    pub const PAPER_OUT: u32 = 0x00000010;
    pub const MANUAL_FEED: u32 = 0x00000020;
    pub const PAPER_PROBLEM: u32 = 0x00000040;
    pub const OFFLINE: u32 = 0x00000080;
    pub const IO_ACTIVE: u32 = 0x00000100;
    pub const BUSY: u32 = 0x00000200;
    pub const PRINTING: u32 = 0x00000400;
    pub const OUTPUT_BIN_FULL: u32 = 0x00000800;
    pub const NOT_AVAILABLE: u32 = 0x00001000;
    pub const WAITING: u32 = 0x00002000;
    pub const PROCESSING: u32 = 0x00004000;
    pub const INITIALIZING: u32 = 0x00008000;
    pub const WARMING_UP: u32 = 0x00010000;
    pub const TONER_LOW: u32 = 0x00020000;
    pub const NO_TONER: u32 = 0x00040000;
    pub const PAGE_PUNT: u32 = 0x00080000;
    pub const USER_INTERVENTION: u32 = 0x00100000;
    pub const OUT_OF_MEMORY: u32 = 0x00200000;
    pub const DOOR_OPEN: u32 = 0x00400000;
    pub const SERVER_UNKNOWN: u32 = 0x00800000;
    pub const POWER_SAVE: u32 = 0x01000000;
}

/// Printer attributes
pub mod printer_attr {
    pub const QUEUED: u32 = 0x00000001;
    pub const DIRECT: u32 = 0x00000002;
    pub const DEFAULT: u32 = 0x00000004;
    pub const SHARED: u32 = 0x00000008;
    pub const NETWORK: u32 = 0x00000010;
    pub const HIDDEN: u32 = 0x00000020;
    pub const LOCAL: u32 = 0x00000040;
    pub const ENABLE_DEVQ: u32 = 0x00000080;
    pub const KEEPPRINTEDJOBS: u32 = 0x00000100;
    pub const DO_COMPLETE_FIRST: u32 = 0x00000200;
    pub const WORK_OFFLINE: u32 = 0x00000400;
    pub const ENABLE_BIDI: u32 = 0x00000800;
    pub const RAW_ONLY: u32 = 0x00001000;
    pub const PUBLISHED: u32 = 0x00002000;
    pub const FAX: u32 = 0x00004000;
    pub const TS: u32 = 0x00008000;
}

/// Job status codes
pub mod job_status {
    pub const PAUSED: u32 = 0x00000001;
    pub const ERROR: u32 = 0x00000002;
    pub const DELETING: u32 = 0x00000004;
    pub const SPOOLING: u32 = 0x00000008;
    pub const PRINTING: u32 = 0x00000010;
    pub const OFFLINE: u32 = 0x00000020;
    pub const PAPEROUT: u32 = 0x00000040;
    pub const PRINTED: u32 = 0x00000080;
    pub const DELETED: u32 = 0x00000100;
    pub const BLOCKED_DEVQ: u32 = 0x00000200;
    pub const USER_INTERVENTION: u32 = 0x00000400;
    pub const RESTART: u32 = 0x00000800;
    pub const COMPLETE: u32 = 0x00001000;
    pub const RETAINED: u32 = 0x00002000;
    pub const RENDERING_LOCALLY: u32 = 0x00004000;
}

/// Paper sizes
pub mod paper_size {
    pub const LETTER: u32 = 1;
    pub const LETTERSMALL: u32 = 2;
    pub const TABLOID: u32 = 3;
    pub const LEDGER: u32 = 4;
    pub const LEGAL: u32 = 5;
    pub const STATEMENT: u32 = 6;
    pub const EXECUTIVE: u32 = 7;
    pub const A3: u32 = 8;
    pub const A4: u32 = 9;
    pub const A4SMALL: u32 = 10;
    pub const A5: u32 = 11;
    pub const B4: u32 = 12;
    pub const B5: u32 = 13;
    pub const FOLIO: u32 = 14;
    pub const QUARTO: u32 = 15;
    pub const ENVELOPE_10: u32 = 20;
    pub const ENVELOPE_DL: u32 = 27;
    pub const ENVELOPE_C5: u32 = 28;
}

/// Print quality
pub mod print_quality {
    pub const HIGH: i32 = -4;
    pub const MEDIUM: i32 = -3;
    pub const LOW: i32 = -2;
    pub const DRAFT: i32 = -1;
}

// ============================================================================
// Types
// ============================================================================

/// Printer information
#[derive(Clone, Copy)]
pub struct PrinterInfo {
    /// Printer name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: u16,
    /// Port name
    pub port: [u8; MAX_PORT],
    /// Port length
    pub port_len: u8,
    /// Driver name
    pub driver: [u8; MAX_DRIVER],
    /// Driver length
    pub driver_len: u16,
    /// Location
    pub location: [u8; MAX_LOCATION],
    /// Location length
    pub location_len: u16,
    /// Comment
    pub comment: [u8; MAX_COMMENT],
    /// Comment length
    pub comment_len: u16,
    /// Status
    pub status: u32,
    /// Attributes
    pub attributes: u32,
    /// Priority (1-99)
    pub priority: u8,
    /// Default priority for jobs
    pub default_priority: u8,
    /// Number of jobs
    pub job_count: u32,
    /// Average pages per minute
    pub pages_per_minute: u32,
    /// Is default printer
    pub is_default: bool,
}

impl PrinterInfo {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            port: [0; MAX_PORT],
            port_len: 0,
            driver: [0; MAX_DRIVER],
            driver_len: 0,
            location: [0; MAX_LOCATION],
            location_len: 0,
            comment: [0; MAX_COMMENT],
            comment_len: 0,
            status: printer_status::READY,
            attributes: printer_attr::LOCAL,
            priority: 1,
            default_priority: 1,
            job_count: 0,
            pages_per_minute: 0,
            is_default: false,
        }
    }
}

/// Print job information
#[derive(Clone, Copy)]
pub struct PrintJob {
    /// Job ID
    pub job_id: u32,
    /// Printer index
    pub printer_index: u8,
    /// Document name
    pub document: [u8; MAX_DOCUMENT],
    /// Document name length
    pub document_len: u16,
    /// User name
    pub user: [u8; MAX_NAME],
    /// User name length
    pub user_len: u8,
    /// Status
    pub status: u32,
    /// Priority
    pub priority: u8,
    /// Position in queue
    pub position: u32,
    /// Total pages
    pub total_pages: u32,
    /// Pages printed
    pub pages_printed: u32,
    /// Total bytes
    pub total_bytes: u64,
    /// Bytes printed
    pub bytes_printed: u64,
    /// Submit time
    pub submitted: u64,
}

impl PrintJob {
    pub const fn new() -> Self {
        Self {
            job_id: 0,
            printer_index: 0,
            document: [0; MAX_DOCUMENT],
            document_len: 0,
            user: [0; MAX_NAME],
            user_len: 0,
            status: 0,
            priority: 1,
            position: 0,
            total_pages: 0,
            pages_printed: 0,
            total_bytes: 0,
            bytes_printed: 0,
            submitted: 0,
        }
    }
}

/// Printer preferences
#[derive(Clone, Copy)]
pub struct PrinterPrefs {
    /// Paper size
    pub paper_size: u32,
    /// Orientation (1=portrait, 2=landscape)
    pub orientation: u8,
    /// Copies
    pub copies: u16,
    /// Print quality
    pub quality: i32,
    /// Color mode (1=mono, 2=color)
    pub color: u8,
    /// Duplex mode (1=simplex, 2=horizontal, 3=vertical)
    pub duplex: u8,
    /// Collate
    pub collate: bool,
    /// Paper source tray
    pub paper_source: u32,
}

impl PrinterPrefs {
    pub const fn new() -> Self {
        Self {
            paper_size: paper_size::LETTER,
            orientation: 1,
            copies: 1,
            quality: print_quality::HIGH,
            color: 2,
            duplex: 1,
            collate: false,
            paper_source: 1,
        }
    }
}

/// Printers dialog state
struct PrintersDialog {
    /// Parent window
    parent: HWND,
    /// Selected printer index
    selected: i32,
    /// View mode (0=icons, 1=list, 2=details)
    view_mode: u32,
    /// Modified flag
    modified: bool,
}

impl PrintersDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            selected: -1,
            view_mode: 0,
            modified: false,
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Printers
static PRINTERS: SpinLock<[PrinterInfo; MAX_PRINTERS]> =
    SpinLock::new([const { PrinterInfo::new() }; MAX_PRINTERS]);

/// Printer count
static PRINTER_COUNT: AtomicU32 = AtomicU32::new(0);

/// Print jobs
static JOBS: SpinLock<[PrintJob; MAX_JOBS]> =
    SpinLock::new([const { PrintJob::new() }; MAX_JOBS]);

/// Job count
static JOB_COUNT: AtomicU32 = AtomicU32::new(0);

/// Next job ID
static NEXT_JOB_ID: AtomicU32 = AtomicU32::new(1);

/// Dialog state
static DIALOG: SpinLock<PrintersDialog> = SpinLock::new(PrintersDialog::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize printers control panel
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Add default printers
    init_default_printers();

    crate::serial_println!("[PRINTERS] Printers control panel initialized");
}

/// Initialize default printers
fn init_default_printers() {
    let mut printers = PRINTERS.lock();
    let mut count = 0;

    // Add a virtual PDF printer
    {
        let printer = &mut printers[count];
        let name = b"Microsoft Print to PDF";
        let nlen = name.len();
        printer.name[..nlen].copy_from_slice(name);
        printer.name_len = nlen as u16;

        let port = b"PORTPROMPT:";
        let plen = port.len();
        printer.port[..plen].copy_from_slice(port);
        printer.port_len = plen as u8;

        let driver = b"Microsoft Print To PDF";
        let dlen = driver.len();
        printer.driver[..dlen].copy_from_slice(driver);
        printer.driver_len = dlen as u16;

        printer.attributes = printer_attr::LOCAL;
        printer.is_default = true;
        count += 1;
    }

    // Add a virtual XPS printer
    {
        let printer = &mut printers[count];
        let name = b"Microsoft XPS Document Writer";
        let nlen = name.len();
        printer.name[..nlen].copy_from_slice(name);
        printer.name_len = nlen as u16;

        let port = b"XPSPort:";
        let plen = port.len();
        printer.port[..plen].copy_from_slice(port);
        printer.port_len = plen as u8;

        let driver = b"Microsoft XPS Document Writer v4";
        let dlen = driver.len();
        printer.driver[..dlen].copy_from_slice(driver);
        printer.driver_len = dlen as u16;

        printer.attributes = printer_attr::LOCAL;
        count += 1;
    }

    // Add fax service
    {
        let printer = &mut printers[count];
        let name = b"Fax";
        let nlen = name.len();
        printer.name[..nlen].copy_from_slice(name);
        printer.name_len = nlen as u16;

        let port = b"SHRFAX:";
        let plen = port.len();
        printer.port[..plen].copy_from_slice(port);
        printer.port_len = plen as u8;

        let driver = b"Microsoft Shared Fax Driver";
        let dlen = driver.len();
        printer.driver[..dlen].copy_from_slice(driver);
        printer.driver_len = dlen as u16;

        printer.attributes = printer_attr::LOCAL | printer_attr::FAX;
        count += 1;
    }

    PRINTER_COUNT.store(count as u32, Ordering::Release);
}

// ============================================================================
// Printer Management
// ============================================================================

/// Get number of printers
pub fn get_printer_count() -> u32 {
    PRINTER_COUNT.load(Ordering::Acquire)
}

/// Get printer info by index
pub fn get_printer(index: usize, info: &mut PrinterInfo) -> bool {
    let printers = PRINTERS.lock();
    let count = PRINTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    *info = printers[index];
    true
}

/// Find printer by name
pub fn find_printer(name: &[u8]) -> Option<usize> {
    let printers = PRINTERS.lock();
    let count = PRINTER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = printers[i].name_len as usize;
        if &printers[i].name[..len] == name {
            return Some(i);
        }
    }
    None
}

/// Get default printer index
pub fn get_default_printer() -> Option<usize> {
    let printers = PRINTERS.lock();
    let count = PRINTER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        if printers[i].is_default {
            return Some(i);
        }
    }
    None
}

/// Set default printer
pub fn set_default_printer(name: &[u8]) -> bool {
    let mut printers = PRINTERS.lock();
    let count = PRINTER_COUNT.load(Ordering::Acquire) as usize;

    let mut found = false;
    for i in 0..count {
        let len = printers[i].name_len as usize;
        if &printers[i].name[..len] == name {
            printers[i].is_default = true;
            found = true;
        } else {
            printers[i].is_default = false;
        }
    }

    found
}

/// Add a printer
pub fn add_printer(name: &[u8], port: &[u8], driver: &[u8]) -> bool {
    let mut printers = PRINTERS.lock();
    let count = PRINTER_COUNT.load(Ordering::Acquire) as usize;

    if count >= MAX_PRINTERS {
        return false;
    }

    let printer = &mut printers[count];

    let nlen = name.len().min(MAX_NAME);
    printer.name[..nlen].copy_from_slice(&name[..nlen]);
    printer.name_len = nlen as u16;

    let plen = port.len().min(MAX_PORT);
    printer.port[..plen].copy_from_slice(&port[..plen]);
    printer.port_len = plen as u8;

    let dlen = driver.len().min(MAX_DRIVER);
    printer.driver[..dlen].copy_from_slice(&driver[..dlen]);
    printer.driver_len = dlen as u16;

    printer.attributes = printer_attr::LOCAL;
    printer.status = printer_status::READY;

    PRINTER_COUNT.store((count + 1) as u32, Ordering::Release);

    true
}

/// Remove a printer
pub fn remove_printer(name: &[u8]) -> bool {
    let mut printers = PRINTERS.lock();
    let count = PRINTER_COUNT.load(Ordering::Acquire) as usize;

    let mut found_index = None;
    for i in 0..count {
        let len = printers[i].name_len as usize;
        if &printers[i].name[..len] == name {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..(count - 1) {
            printers[i] = printers[i + 1];
        }
        printers[count - 1] = PrinterInfo::new();
        PRINTER_COUNT.store((count - 1) as u32, Ordering::Release);
        return true;
    }

    false
}

/// Pause a printer
pub fn pause_printer(name: &[u8]) -> bool {
    let mut printers = PRINTERS.lock();
    let count = PRINTER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = printers[i].name_len as usize;
        if &printers[i].name[..len] == name {
            printers[i].status |= printer_status::PAUSED;
            return true;
        }
    }
    false
}

/// Resume a printer
pub fn resume_printer(name: &[u8]) -> bool {
    let mut printers = PRINTERS.lock();
    let count = PRINTER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = printers[i].name_len as usize;
        if &printers[i].name[..len] == name {
            printers[i].status &= !printer_status::PAUSED;
            return true;
        }
    }
    false
}

// ============================================================================
// Print Job Management
// ============================================================================

/// Get number of print jobs
pub fn get_job_count() -> u32 {
    JOB_COUNT.load(Ordering::Acquire)
}

/// Get print jobs for a printer
pub fn get_printer_jobs(printer_index: usize, jobs: &mut [PrintJob]) -> usize {
    let all_jobs = JOBS.lock();
    let count = JOB_COUNT.load(Ordering::Acquire) as usize;

    let mut found = 0;
    for i in 0..count {
        if all_jobs[i].printer_index == printer_index as u8 {
            if found < jobs.len() {
                jobs[found] = all_jobs[i];
            }
            found += 1;
        }
    }

    found
}

/// Add a print job
pub fn add_job(printer_index: usize, document: &[u8], user: &[u8],
               total_pages: u32, total_bytes: u64) -> Option<u32> {
    let mut jobs = JOBS.lock();
    let count = JOB_COUNT.load(Ordering::Acquire) as usize;

    if count >= MAX_JOBS {
        return None;
    }

    let job_id = NEXT_JOB_ID.fetch_add(1, Ordering::SeqCst);
    let job = &mut jobs[count];

    job.job_id = job_id;
    job.printer_index = printer_index as u8;

    let dlen = document.len().min(MAX_DOCUMENT);
    job.document[..dlen].copy_from_slice(&document[..dlen]);
    job.document_len = dlen as u16;

    let ulen = user.len().min(MAX_NAME);
    job.user[..ulen].copy_from_slice(&user[..ulen]);
    job.user_len = ulen as u8;

    job.status = job_status::SPOOLING;
    job.total_pages = total_pages;
    job.total_bytes = total_bytes;
    job.position = (count + 1) as u32;

    // Update printer job count
    {
        let mut printers = PRINTERS.lock();
        if printer_index < MAX_PRINTERS {
            printers[printer_index].job_count += 1;
        }
    }

    JOB_COUNT.store((count + 1) as u32, Ordering::Release);

    Some(job_id)
}

/// Cancel a print job
pub fn cancel_job(job_id: u32) -> bool {
    let mut jobs = JOBS.lock();
    let count = JOB_COUNT.load(Ordering::Acquire) as usize;

    let mut found_index = None;
    let mut printer_index = 0;

    for i in 0..count {
        if jobs[i].job_id == job_id {
            found_index = Some(i);
            printer_index = jobs[i].printer_index as usize;
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..(count - 1) {
            jobs[i] = jobs[i + 1];
        }
        jobs[count - 1] = PrintJob::new();
        JOB_COUNT.store((count - 1) as u32, Ordering::Release);

        // Update printer job count
        {
            let mut printers = PRINTERS.lock();
            if printer_index < MAX_PRINTERS && printers[printer_index].job_count > 0 {
                printers[printer_index].job_count -= 1;
            }
        }

        return true;
    }

    false
}

/// Pause a print job
pub fn pause_job(job_id: u32) -> bool {
    let mut jobs = JOBS.lock();
    let count = JOB_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        if jobs[i].job_id == job_id {
            jobs[i].status |= job_status::PAUSED;
            return true;
        }
    }
    false
}

/// Resume a print job
pub fn resume_job(job_id: u32) -> bool {
    let mut jobs = JOBS.lock();
    let count = JOB_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        if jobs[i].job_id == job_id {
            jobs[i].status &= !job_status::PAUSED;
            return true;
        }
    }
    false
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show printers and faxes folder
pub fn show_printers(parent: HWND) -> bool {
    let mut dialog = DIALOG.lock();

    dialog.parent = parent;
    dialog.selected = -1;
    dialog.view_mode = 0;
    dialog.modified = false;

    // Would show explorer-style window with:
    // - Add Printer wizard link
    // - Printer icons
    // - Context menu for properties, set default, delete

    true
}

/// Show add printer wizard
pub fn show_add_printer_wizard(parent: HWND) -> bool {
    let _ = parent;
    // Would show add printer wizard
    true
}

/// Show printer properties
pub fn show_printer_properties(parent: HWND, name: &[u8]) -> bool {
    let _ = (parent, name);
    // Would show printer properties dialog
    true
}

/// Show print queue window
pub fn show_print_queue(parent: HWND, name: &[u8]) -> bool {
    let _ = (parent, name);
    // Would show print queue window
    true
}
