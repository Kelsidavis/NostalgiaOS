//! Print Spooler Service
//!
//! The Print Spooler manages printing operations:
//!
//! - **Printer Management**: Add, remove, configure printers
//! - **Print Queue**: Queue and manage print jobs
//! - **Port Monitors**: LPT, USB, TCP/IP ports
//! - **Print Processors**: RAW, EMF, TEXT
//! - **Driver Management**: Printer driver installation
//!
//! # Registry Location
//!
//! `HKLM\System\CurrentControlSet\Control\Print`
//!
//! Printers are stored in:
//! `HKLM\System\CurrentControlSet\Control\Print\Printers`

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;
use alloc::vec::Vec;

// ============================================================================
// Print Spooler Constants
// ============================================================================

/// Maximum printers
pub const MAX_PRINTERS: usize = 16;

/// Maximum print jobs per printer
pub const MAX_JOBS_PER_PRINTER: usize = 32;

/// Maximum printer name length
pub const MAX_PRINTER_NAME: usize = 128;

/// Maximum port name length
pub const MAX_PORT_NAME: usize = 64;

/// Maximum driver name length
pub const MAX_DRIVER_NAME: usize = 64;

/// Maximum document name length
pub const MAX_DOCUMENT_NAME: usize = 128;

/// Maximum user name length
pub const MAX_USER_NAME: usize = 64;

/// Maximum comment length
pub const MAX_COMMENT: usize = 128;

// ============================================================================
// Printer Status
// ============================================================================

/// Printer status flags
pub mod printer_status {
    /// Printer is paused
    pub const PAUSED: u32 = 0x00000001;
    /// Error condition
    pub const ERROR: u32 = 0x00000002;
    /// Pending deletion
    pub const PENDING_DELETION: u32 = 0x00000004;
    /// Paper jam
    pub const PAPER_JAM: u32 = 0x00000008;
    /// Paper out
    pub const PAPER_OUT: u32 = 0x00000010;
    /// Manual feed required
    pub const MANUAL_FEED: u32 = 0x00000020;
    /// Paper problem
    pub const PAPER_PROBLEM: u32 = 0x00000040;
    /// Offline
    pub const OFFLINE: u32 = 0x00000080;
    /// I/O active
    pub const IO_ACTIVE: u32 = 0x00000100;
    /// Busy
    pub const BUSY: u32 = 0x00000200;
    /// Printing
    pub const PRINTING: u32 = 0x00000400;
    /// Output bin full
    pub const OUTPUT_BIN_FULL: u32 = 0x00000800;
    /// Not available
    pub const NOT_AVAILABLE: u32 = 0x00001000;
    /// Waiting
    pub const WAITING: u32 = 0x00002000;
    /// Processing
    pub const PROCESSING: u32 = 0x00004000;
    /// Initializing
    pub const INITIALIZING: u32 = 0x00008000;
    /// Warming up
    pub const WARMING_UP: u32 = 0x00010000;
    /// Toner low
    pub const TONER_LOW: u32 = 0x00020000;
    /// No toner
    pub const NO_TONER: u32 = 0x00040000;
    /// Page punt
    pub const PAGE_PUNT: u32 = 0x00080000;
    /// User intervention required
    pub const USER_INTERVENTION: u32 = 0x00100000;
    /// Out of memory
    pub const OUT_OF_MEMORY: u32 = 0x00200000;
    /// Door open
    pub const DOOR_OPEN: u32 = 0x00400000;
    /// Server unknown
    pub const SERVER_UNKNOWN: u32 = 0x00800000;
    /// Power save
    pub const POWER_SAVE: u32 = 0x01000000;
}

// ============================================================================
// Job Status
// ============================================================================

/// Print job status flags
pub mod job_status {
    /// Job is paused
    pub const PAUSED: u32 = 0x00000001;
    /// Error condition
    pub const ERROR: u32 = 0x00000002;
    /// Deleting
    pub const DELETING: u32 = 0x00000004;
    /// Spooling
    pub const SPOOLING: u32 = 0x00000008;
    /// Printing
    pub const PRINTING: u32 = 0x00000010;
    /// Offline
    pub const OFFLINE: u32 = 0x00000020;
    /// Paper out
    pub const PAPEROUT: u32 = 0x00000040;
    /// Printed
    pub const PRINTED: u32 = 0x00000080;
    /// Deleted
    pub const DELETED: u32 = 0x00000100;
    /// Blocked (device queue)
    pub const BLOCKED_DEVQ: u32 = 0x00000200;
    /// User intervention required
    pub const USER_INTERVENTION: u32 = 0x00000400;
    /// Restart
    pub const RESTART: u32 = 0x00000800;
    /// Complete
    pub const COMPLETE: u32 = 0x00001000;
    /// Retained
    pub const RETAINED: u32 = 0x00002000;
    /// Rendering locally
    pub const RENDERING_LOCALLY: u32 = 0x00004000;
}

// ============================================================================
// Printer Attributes
// ============================================================================

/// Printer attribute flags
pub mod printer_attributes {
    /// Queue jobs when offline
    pub const QUEUED: u32 = 0x00000001;
    /// Direct printing (no spooling)
    pub const DIRECT: u32 = 0x00000002;
    /// Default printer
    pub const DEFAULT: u32 = 0x00000004;
    /// Shared printer
    pub const SHARED: u32 = 0x00000008;
    /// Network printer
    pub const NETWORK: u32 = 0x00000010;
    /// Hidden printer
    pub const HIDDEN: u32 = 0x00000020;
    /// Local printer
    pub const LOCAL: u32 = 0x00000040;
    /// Enable devquery print
    pub const ENABLE_DEVQ: u32 = 0x00000080;
    /// Keep printed jobs
    pub const KEEPPRINTEDJOBS: u32 = 0x00000100;
    /// Do complete first
    pub const DO_COMPLETE_FIRST: u32 = 0x00000200;
    /// Work offline
    pub const WORK_OFFLINE: u32 = 0x00000400;
    /// Enable BIDI
    pub const ENABLE_BIDI: u32 = 0x00000800;
    /// Raw only
    pub const RAW_ONLY: u32 = 0x00001000;
    /// Published in directory
    pub const PUBLISHED: u32 = 0x00002000;
}

// ============================================================================
// Port Type
// ============================================================================

/// Printer port type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum PortType {
    /// Local port (LPT, COM)
    #[default]
    Local = 0,
    /// USB port
    Usb = 1,
    /// TCP/IP port
    TcpIp = 2,
    /// File port
    File = 3,
    /// Virtual port (PDF, XPS)
    Virtual = 4,
}

// ============================================================================
// Print Processor
// ============================================================================

/// Print processor/data type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum DataType {
    /// Raw data (pass-through)
    #[default]
    Raw = 0,
    /// RAW with FF appended
    RawFF = 1,
    /// RAW with FF auto
    RawFFAuto = 2,
    /// NT EMF (Enhanced Metafile)
    NtEmf = 3,
    /// Text
    Text = 4,
}

// ============================================================================
// Priority
// ============================================================================

/// Print job priority (1-99, default 1)
pub const MIN_PRIORITY: u32 = 1;
pub const MAX_PRIORITY: u32 = 99;
pub const DEF_PRIORITY: u32 = 1;

// ============================================================================
// Error Codes
// ============================================================================

/// Print Spooler error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SpoolerError {
    /// Success
    Success = 0,
    /// Invalid printer name
    InvalidPrinterName = 0x00000709,
    /// Invalid printer handle
    InvalidPrinterHandle = 0x00000006,
    /// Print job not found
    JobNotFound = 0x0000070D,
    /// Printer not found
    PrinterNotFound = 0x0000070E,
    /// Printer already exists
    PrinterAlreadyExists = 0x0000070F,
    /// Invalid datatype
    InvalidDatatype = 0x0000070A,
    /// Invalid priority
    InvalidPriority = 0x0000070B,
    /// Spooler not running
    SpoolerNotRunning = 0x00000710,
    /// Print queue full
    QueueFull = 0x00000711,
    /// Out of paper
    OutOfPaper = 0x0000071C,
    /// Printer offline
    PrinterOffline = 0x0000071D,
    /// Access denied
    AccessDenied = 0x00000005,
}

// ============================================================================
// Print Job
// ============================================================================

/// Print job
#[repr(C)]
pub struct PrintJob {
    /// Job ID
    pub job_id: u32,
    /// Printer index
    pub printer_index: usize,
    /// Document name
    pub document: [u8; MAX_DOCUMENT_NAME],
    /// User name (job owner)
    pub user_name: [u8; MAX_USER_NAME],
    /// Data type
    pub data_type: DataType,
    /// Job status
    pub status: AtomicU32,
    /// Priority (1-99)
    pub priority: u32,
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
    /// Start time (printing began)
    pub start_time: u64,
    /// Job valid
    pub valid: bool,
}

impl PrintJob {
    pub const fn empty() -> Self {
        Self {
            job_id: 0,
            printer_index: 0,
            document: [0; MAX_DOCUMENT_NAME],
            user_name: [0; MAX_USER_NAME],
            data_type: DataType::Raw,
            status: AtomicU32::new(0),
            priority: DEF_PRIORITY,
            position: 0,
            total_pages: 0,
            pages_printed: 0,
            total_bytes: 0,
            bytes_printed: 0,
            submitted: 0,
            start_time: 0,
            valid: false,
        }
    }

    pub fn set_document(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_DOCUMENT_NAME - 1);
        self.document[..len].copy_from_slice(&bytes[..len]);
        self.document[len] = 0;
    }

    pub fn document_str(&self) -> &str {
        let len = self.document.iter().position(|&b| b == 0).unwrap_or(MAX_DOCUMENT_NAME);
        core::str::from_utf8(&self.document[..len]).unwrap_or("")
    }

    pub fn set_user(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_USER_NAME - 1);
        self.user_name[..len].copy_from_slice(&bytes[..len]);
        self.user_name[len] = 0;
    }

    pub fn user_str(&self) -> &str {
        let len = self.user_name.iter().position(|&b| b == 0).unwrap_or(MAX_USER_NAME);
        core::str::from_utf8(&self.user_name[..len]).unwrap_or("")
    }

    pub fn get_status(&self) -> u32 {
        self.status.load(Ordering::SeqCst)
    }

    pub fn set_status(&self, status: u32) {
        self.status.store(status, Ordering::SeqCst);
    }

    pub fn add_status(&self, flag: u32) {
        self.status.fetch_or(flag, Ordering::SeqCst);
    }

    pub fn remove_status(&self, flag: u32) {
        self.status.fetch_and(!flag, Ordering::SeqCst);
    }

    /// Get progress percentage (0-100)
    pub fn progress(&self) -> u32 {
        if self.total_bytes == 0 {
            return 0;
        }
        ((self.bytes_printed * 100) / self.total_bytes) as u32
    }
}

// ============================================================================
// Printer
// ============================================================================

/// Printer definition
#[repr(C)]
pub struct Printer {
    /// Printer name
    pub name: [u8; MAX_PRINTER_NAME],
    /// Share name (if shared)
    pub share_name: [u8; MAX_PRINTER_NAME],
    /// Port name
    pub port_name: [u8; MAX_PORT_NAME],
    /// Driver name
    pub driver_name: [u8; MAX_DRIVER_NAME],
    /// Comment
    pub comment: [u8; MAX_COMMENT],
    /// Location
    pub location: [u8; MAX_COMMENT],
    /// Port type
    pub port_type: PortType,
    /// Printer attributes
    pub attributes: u32,
    /// Printer status
    pub status: AtomicU32,
    /// Default priority
    pub default_priority: u32,
    /// Start time (minutes from midnight)
    pub start_time: u32,
    /// Until time (minutes from midnight)
    pub until_time: u32,
    /// Print jobs
    pub jobs: [PrintJob; MAX_JOBS_PER_PRINTER],
    /// Job count
    pub job_count: usize,
    /// Next job ID
    pub next_job_id: u32,
    /// Total jobs printed
    pub total_jobs: u64,
    /// Total pages printed
    pub total_pages: u64,
    /// Total bytes printed
    pub total_bytes: u64,
    /// Printer valid
    pub valid: bool,
}

impl Printer {
    pub const fn empty() -> Self {
        Self {
            name: [0; MAX_PRINTER_NAME],
            share_name: [0; MAX_PRINTER_NAME],
            port_name: [0; MAX_PORT_NAME],
            driver_name: [0; MAX_DRIVER_NAME],
            comment: [0; MAX_COMMENT],
            location: [0; MAX_COMMENT],
            port_type: PortType::Local,
            attributes: printer_attributes::LOCAL | printer_attributes::QUEUED,
            status: AtomicU32::new(0),
            default_priority: DEF_PRIORITY,
            start_time: 0,
            until_time: 0,
            jobs: [const { PrintJob::empty() }; MAX_JOBS_PER_PRINTER],
            job_count: 0,
            next_job_id: 1,
            total_jobs: 0,
            total_pages: 0,
            total_bytes: 0,
            valid: false,
        }
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_PRINTER_NAME - 1);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0;
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_PRINTER_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_port(&mut self, port: &str) {
        let bytes = port.as_bytes();
        let len = bytes.len().min(MAX_PORT_NAME - 1);
        self.port_name[..len].copy_from_slice(&bytes[..len]);
        self.port_name[len] = 0;
    }

    pub fn port_str(&self) -> &str {
        let len = self.port_name.iter().position(|&b| b == 0).unwrap_or(MAX_PORT_NAME);
        core::str::from_utf8(&self.port_name[..len]).unwrap_or("")
    }

    pub fn set_driver(&mut self, driver: &str) {
        let bytes = driver.as_bytes();
        let len = bytes.len().min(MAX_DRIVER_NAME - 1);
        self.driver_name[..len].copy_from_slice(&bytes[..len]);
        self.driver_name[len] = 0;
    }

    pub fn driver_str(&self) -> &str {
        let len = self.driver_name.iter().position(|&b| b == 0).unwrap_or(MAX_DRIVER_NAME);
        core::str::from_utf8(&self.driver_name[..len]).unwrap_or("")
    }

    pub fn get_status(&self) -> u32 {
        self.status.load(Ordering::SeqCst)
    }

    pub fn set_status(&self, status: u32) {
        self.status.store(status, Ordering::SeqCst);
    }

    pub fn is_paused(&self) -> bool {
        (self.get_status() & printer_status::PAUSED) != 0
    }

    pub fn is_offline(&self) -> bool {
        (self.get_status() & printer_status::OFFLINE) != 0
    }

    pub fn is_shared(&self) -> bool {
        (self.attributes & printer_attributes::SHARED) != 0
    }

    pub fn is_default(&self) -> bool {
        (self.attributes & printer_attributes::DEFAULT) != 0
    }
}

// ============================================================================
// Spooler State
// ============================================================================

/// Print Spooler configuration
#[repr(C)]
pub struct SpoolerConfig {
    /// Spool directory path
    pub spool_directory: [u8; 260],
    /// Delete jobs after printing
    pub delete_after_print: bool,
    /// Allow remote connections
    pub allow_remote: bool,
    /// Beep on errors
    pub beep_enabled: bool,
    /// Retry interval (seconds)
    pub retry_interval: u32,
}

impl SpoolerConfig {
    pub const fn new() -> Self {
        Self {
            spool_directory: [0; 260],
            delete_after_print: true,
            allow_remote: true,
            beep_enabled: true,
            retry_interval: 30,
        }
    }
}

/// Print Spooler state
#[repr(C)]
pub struct SpoolerState {
    /// Configuration
    pub config: SpoolerConfig,
    /// Printers
    pub printers: [Printer; MAX_PRINTERS],
    /// Printer count
    pub printer_count: usize,
    /// Default printer index
    pub default_printer: Option<usize>,
    /// Service running
    pub running: bool,
}

impl SpoolerState {
    pub const fn new() -> Self {
        Self {
            config: SpoolerConfig::new(),
            printers: [const { Printer::empty() }; MAX_PRINTERS],
            printer_count: 0,
            default_printer: None,
            running: false,
        }
    }
}

/// Global spooler state
static SPOOLER_STATE: SpinLock<SpoolerState> = SpinLock::new(SpoolerState::new());

/// Spooler statistics
pub struct SpoolerStats {
    /// Total jobs submitted
    pub jobs_submitted: AtomicU64,
    /// Jobs completed
    pub jobs_completed: AtomicU64,
    /// Jobs cancelled
    pub jobs_cancelled: AtomicU64,
    /// Jobs failed
    pub jobs_failed: AtomicU64,
    /// Total pages printed
    pub pages_printed: AtomicU64,
    /// Total bytes printed
    pub bytes_printed: AtomicU64,
    /// Printers added
    pub printers_added: AtomicU64,
}

impl SpoolerStats {
    pub const fn new() -> Self {
        Self {
            jobs_submitted: AtomicU64::new(0),
            jobs_completed: AtomicU64::new(0),
            jobs_cancelled: AtomicU64::new(0),
            jobs_failed: AtomicU64::new(0),
            pages_printed: AtomicU64::new(0),
            bytes_printed: AtomicU64::new(0),
            printers_added: AtomicU64::new(0),
        }
    }
}

static SPOOLER_STATS: SpoolerStats = SpoolerStats::new();

// ============================================================================
// Spooler API
// ============================================================================

/// Add a printer
pub fn add_printer(
    name: &str,
    port: &str,
    driver: &str,
    port_type: PortType,
) -> Result<usize, SpoolerError> {
    let mut state = SPOOLER_STATE.lock();

    if !state.running {
        return Err(SpoolerError::SpoolerNotRunning);
    }

    // Check for existing printer
    for i in 0..MAX_PRINTERS {
        if state.printers[i].valid && state.printers[i].name_str() == name {
            return Err(SpoolerError::PrinterAlreadyExists);
        }
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_PRINTERS {
        if !state.printers[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(SpoolerError::QueueFull),
    };

    // Check if this should be default before setting up printer
    let should_be_default = state.default_printer.is_none();

    let printer = &mut state.printers[slot];
    *printer = Printer::empty();
    printer.set_name(name);
    printer.set_port(port);
    printer.set_driver(driver);
    printer.port_type = port_type;
    printer.valid = true;
    if should_be_default {
        printer.attributes |= printer_attributes::DEFAULT;
    }

    state.printer_count += 1;

    // Set as default if first printer
    if should_be_default {
        state.default_printer = Some(slot);
    }

    SPOOLER_STATS.printers_added.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[SPOOLER] Added printer '{}' on port '{}' (driver: {})",
        name, port, driver);

    Ok(slot)
}

/// Delete a printer
pub fn delete_printer(name: &str) -> Result<(), SpoolerError> {
    let mut state = SPOOLER_STATE.lock();

    if !state.running {
        return Err(SpoolerError::SpoolerNotRunning);
    }

    for i in 0..MAX_PRINTERS {
        if state.printers[i].valid && state.printers[i].name_str() == name {
            // Check for pending jobs
            if state.printers[i].job_count > 0 {
                state.printers[i].set_status(printer_status::PENDING_DELETION);
                return Ok(());
            }

            state.printers[i].valid = false;
            state.printer_count = state.printer_count.saturating_sub(1);

            // Update default printer if needed
            if state.default_printer == Some(i) {
                state.default_printer = None;
                // Find new default
                for j in 0..MAX_PRINTERS {
                    if state.printers[j].valid {
                        state.default_printer = Some(j);
                        state.printers[j].attributes |= printer_attributes::DEFAULT;
                        break;
                    }
                }
            }

            crate::serial_println!("[SPOOLER] Deleted printer '{}'", name);
            return Ok(());
        }
    }

    Err(SpoolerError::PrinterNotFound)
}

/// Set default printer
pub fn set_default_printer(name: &str) -> Result<(), SpoolerError> {
    let mut state = SPOOLER_STATE.lock();

    if !state.running {
        return Err(SpoolerError::SpoolerNotRunning);
    }

    // Find printer
    let mut new_default = None;
    for i in 0..MAX_PRINTERS {
        if state.printers[i].valid && state.printers[i].name_str() == name {
            new_default = Some(i);
            break;
        }
    }

    let new_idx = match new_default {
        Some(i) => i,
        None => return Err(SpoolerError::PrinterNotFound),
    };

    // Clear old default
    if let Some(old_idx) = state.default_printer {
        state.printers[old_idx].attributes &= !printer_attributes::DEFAULT;
    }

    // Set new default
    state.printers[new_idx].attributes |= printer_attributes::DEFAULT;
    state.default_printer = Some(new_idx);

    crate::serial_println!("[SPOOLER] Default printer set to '{}'", name);

    Ok(())
}

/// Submit a print job
pub fn start_doc(
    printer_name: &str,
    document_name: &str,
    user_name: &str,
    data_type: DataType,
) -> Result<u32, SpoolerError> {
    let mut state = SPOOLER_STATE.lock();

    if !state.running {
        return Err(SpoolerError::SpoolerNotRunning);
    }

    // Find printer
    let mut printer_idx = None;
    for i in 0..MAX_PRINTERS {
        if state.printers[i].valid && state.printers[i].name_str() == printer_name {
            printer_idx = Some(i);
            break;
        }
    }

    let idx = match printer_idx {
        Some(i) => i,
        None => return Err(SpoolerError::PrinterNotFound),
    };

    // Check if printer is accepting jobs
    let printer_status = state.printers[idx].get_status();
    if (printer_status & printer_status::OFFLINE) != 0 {
        return Err(SpoolerError::PrinterOffline);
    }

    // Find free job slot
    let job_count = state.printers[idx].job_count;
    if job_count >= MAX_JOBS_PER_PRINTER {
        return Err(SpoolerError::QueueFull);
    }

    let mut job_slot = None;
    for i in 0..MAX_JOBS_PER_PRINTER {
        if !state.printers[idx].jobs[i].valid {
            job_slot = Some(i);
            break;
        }
    }

    let job_slot = match job_slot {
        Some(s) => s,
        None => return Err(SpoolerError::QueueFull),
    };

    let job_id = state.printers[idx].next_job_id;
    state.printers[idx].next_job_id += 1;
    let default_priority = state.printers[idx].default_priority;

    let current_time = crate::hal::apic::get_tick_count();

    let job = &mut state.printers[idx].jobs[job_slot];
    *job = PrintJob::empty();
    job.job_id = job_id;
    job.printer_index = idx;
    job.set_document(document_name);
    job.set_user(user_name);
    job.data_type = data_type;
    job.priority = default_priority;
    job.submitted = current_time;
    job.set_status(job_status::SPOOLING);
    job.valid = true;

    state.printers[idx].job_count += 1;

    SPOOLER_STATS.jobs_submitted.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[SPOOLER] Job {} started: '{}' on '{}'",
        job_id, document_name, printer_name);

    Ok(job_id)
}

/// Write data to print job
pub fn write_printer(
    printer_name: &str,
    job_id: u32,
    data_len: u64,
) -> Result<(), SpoolerError> {
    let mut state = SPOOLER_STATE.lock();

    // Find printer and job
    for i in 0..MAX_PRINTERS {
        if !state.printers[i].valid || state.printers[i].name_str() != printer_name {
            continue;
        }

        for j in 0..MAX_JOBS_PER_PRINTER {
            if state.printers[i].jobs[j].valid && state.printers[i].jobs[j].job_id == job_id {
                state.printers[i].jobs[j].total_bytes += data_len;
                return Ok(());
            }
        }
    }

    Err(SpoolerError::JobNotFound)
}

/// End a print job (start printing)
pub fn end_doc(printer_name: &str, job_id: u32) -> Result<(), SpoolerError> {
    let mut state = SPOOLER_STATE.lock();

    // Find printer and job
    for i in 0..MAX_PRINTERS {
        if !state.printers[i].valid || state.printers[i].name_str() != printer_name {
            continue;
        }

        for j in 0..MAX_JOBS_PER_PRINTER {
            if state.printers[i].jobs[j].valid && state.printers[i].jobs[j].job_id == job_id {
                // Transition from spooling to printing
                state.printers[i].jobs[j].remove_status(job_status::SPOOLING);
                state.printers[i].jobs[j].add_status(job_status::PRINTING);

                let current_time = crate::hal::apic::get_tick_count();
                state.printers[i].jobs[j].start_time = current_time;

                crate::serial_println!("[SPOOLER] Job {} queued for printing", job_id);
                return Ok(());
            }
        }
    }

    Err(SpoolerError::JobNotFound)
}

/// Cancel a print job
pub fn cancel_job(printer_name: &str, job_id: u32) -> Result<(), SpoolerError> {
    let mut state = SPOOLER_STATE.lock();

    for i in 0..MAX_PRINTERS {
        if !state.printers[i].valid || state.printers[i].name_str() != printer_name {
            continue;
        }

        for j in 0..MAX_JOBS_PER_PRINTER {
            if state.printers[i].jobs[j].valid && state.printers[i].jobs[j].job_id == job_id {
                state.printers[i].jobs[j].set_status(job_status::DELETED);
                state.printers[i].jobs[j].valid = false;
                state.printers[i].job_count = state.printers[i].job_count.saturating_sub(1);

                SPOOLER_STATS.jobs_cancelled.fetch_add(1, Ordering::Relaxed);

                crate::serial_println!("[SPOOLER] Job {} cancelled", job_id);
                return Ok(());
            }
        }
    }

    Err(SpoolerError::JobNotFound)
}

/// Pause a printer
pub fn pause_printer(name: &str) -> Result<(), SpoolerError> {
    let state = SPOOLER_STATE.lock();

    for i in 0..MAX_PRINTERS {
        if state.printers[i].valid && state.printers[i].name_str() == name {
            state.printers[i].status.fetch_or(printer_status::PAUSED, Ordering::SeqCst);
            crate::serial_println!("[SPOOLER] Printer '{}' paused", name);
            return Ok(());
        }
    }

    Err(SpoolerError::PrinterNotFound)
}

/// Resume a printer
pub fn resume_printer(name: &str) -> Result<(), SpoolerError> {
    let state = SPOOLER_STATE.lock();

    for i in 0..MAX_PRINTERS {
        if state.printers[i].valid && state.printers[i].name_str() == name {
            state.printers[i].status.fetch_and(!printer_status::PAUSED, Ordering::SeqCst);
            crate::serial_println!("[SPOOLER] Printer '{}' resumed", name);
            return Ok(());
        }
    }

    Err(SpoolerError::PrinterNotFound)
}

/// Enumerate printers
pub fn enumerate_printers() -> Vec<([u8; MAX_PRINTER_NAME], u32, usize)> {
    let state = SPOOLER_STATE.lock();
    let mut result = Vec::new();

    for i in 0..MAX_PRINTERS {
        if state.printers[i].valid {
            result.push((
                state.printers[i].name,
                state.printers[i].get_status(),
                state.printers[i].job_count,
            ));
        }
    }

    result
}

/// Enumerate jobs for a printer
pub fn enumerate_jobs(printer_name: &str) -> Vec<(u32, u32, u32)> {
    let state = SPOOLER_STATE.lock();
    let mut result = Vec::new();

    for i in 0..MAX_PRINTERS {
        if !state.printers[i].valid || state.printers[i].name_str() != printer_name {
            continue;
        }

        for j in 0..MAX_JOBS_PER_PRINTER {
            if state.printers[i].jobs[j].valid {
                result.push((
                    state.printers[i].jobs[j].job_id,
                    state.printers[i].jobs[j].get_status(),
                    state.printers[i].jobs[j].progress(),
                ));
            }
        }
        break;
    }

    result
}

/// Get default printer name
pub fn get_default_printer() -> Option<[u8; MAX_PRINTER_NAME]> {
    let state = SPOOLER_STATE.lock();

    if let Some(idx) = state.default_printer {
        if state.printers[idx].valid {
            return Some(state.printers[idx].name);
        }
    }

    None
}

// ============================================================================
// Job Processing
// ============================================================================

/// Process print jobs (called periodically)
pub fn process_jobs() {
    let mut state = SPOOLER_STATE.lock();

    if !state.running {
        return;
    }

    for i in 0..MAX_PRINTERS {
        if !state.printers[i].valid {
            continue;
        }

        let printer_status_val = state.printers[i].get_status();
        if (printer_status_val & printer_status::PAUSED) != 0 {
            continue;
        }
        if (printer_status_val & printer_status::OFFLINE) != 0 {
            continue;
        }

        // Find next job to print
        for j in 0..MAX_JOBS_PER_PRINTER {
            if !state.printers[i].jobs[j].valid {
                continue;
            }

            let job_status_val = state.printers[i].jobs[j].get_status();

            if (job_status_val & job_status::PRINTING) != 0 {
                // Simulate printing progress
                let total = state.printers[i].jobs[j].total_bytes;
                let printed = state.printers[i].jobs[j].bytes_printed;

                if printed < total {
                    // Print some bytes
                    let chunk = (total / 10).max(1024);
                    state.printers[i].jobs[j].bytes_printed =
                        (printed + chunk).min(total);
                    state.printers[i].jobs[j].pages_printed += 1;
                } else {
                    // Job complete
                    state.printers[i].jobs[j].remove_status(job_status::PRINTING);
                    state.printers[i].jobs[j].add_status(job_status::PRINTED | job_status::COMPLETE);

                    let job_id = state.printers[i].jobs[j].job_id;
                    let pages = state.printers[i].jobs[j].pages_printed;
                    let bytes = state.printers[i].jobs[j].bytes_printed;

                    state.printers[i].total_jobs += 1;
                    state.printers[i].total_pages += pages as u64;
                    state.printers[i].total_bytes += bytes;

                    // Delete job after completion
                    state.printers[i].jobs[j].valid = false;
                    state.printers[i].job_count = state.printers[i].job_count.saturating_sub(1);

                    SPOOLER_STATS.jobs_completed.fetch_add(1, Ordering::Relaxed);
                    SPOOLER_STATS.pages_printed.fetch_add(pages as u64, Ordering::Relaxed);
                    SPOOLER_STATS.bytes_printed.fetch_add(bytes, Ordering::Relaxed);

                    crate::serial_println!("[SPOOLER] Job {} completed ({} pages)",
                        job_id, pages);
                }

                // Only process one job per printer per cycle
                break;
            }
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get spooler statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64, u64) {
    (
        SPOOLER_STATS.jobs_submitted.load(Ordering::Relaxed),
        SPOOLER_STATS.jobs_completed.load(Ordering::Relaxed),
        SPOOLER_STATS.jobs_cancelled.load(Ordering::Relaxed),
        SPOOLER_STATS.jobs_failed.load(Ordering::Relaxed),
        SPOOLER_STATS.pages_printed.load(Ordering::Relaxed),
        SPOOLER_STATS.bytes_printed.load(Ordering::Relaxed),
        SPOOLER_STATS.printers_added.load(Ordering::Relaxed),
    )
}

/// Get printer count
pub fn get_printer_count() -> usize {
    let state = SPOOLER_STATE.lock();
    state.printer_count
}

/// Check if spooler is running
pub fn is_running() -> bool {
    let state = SPOOLER_STATE.lock();
    state.running
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Print Spooler service
pub fn init() {
    crate::serial_println!("[SPOOLER] Initializing Print Spooler Service...");

    let mut state = SPOOLER_STATE.lock();

    // Set spool directory
    let spool_path = b"\\SystemRoot\\System32\\spool\\PRINTERS";
    state.config.spool_directory[..spool_path.len()].copy_from_slice(spool_path);

    state.running = true;

    crate::serial_println!("[SPOOLER] Print Spooler initialized");
}

/// Shutdown Print Spooler
pub fn shutdown() {
    crate::serial_println!("[SPOOLER] Shutting down Print Spooler...");

    let mut state = SPOOLER_STATE.lock();
    state.running = false;

    let (submitted, completed, cancelled, failed, pages, _, printers) = get_statistics();
    crate::serial_println!("[SPOOLER] Stats: {} submitted, {} completed, {} cancelled, {} failed, {} pages, {} printers",
        submitted, completed, cancelled, failed, pages, printers);
}
