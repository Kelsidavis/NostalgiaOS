//! Print Management (printmanagement.msc) implementation
//!
//! Provides centralized management of print servers, printers, drivers,
//! and print queues across the network.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Local type alias for window handles
type HWND = UserHandle;

/// Maximum print servers
const MAX_SERVERS: usize = 32;

/// Maximum printers per server
const MAX_PRINTERS: usize = 64;

/// Maximum print jobs
const MAX_JOBS: usize = 256;

/// Maximum drivers
const MAX_DRIVERS: usize = 64;

/// Maximum ports
const MAX_PORTS: usize = 32;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Printer status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PrinterStatus {
    /// Printer is ready
    Ready = 0,
    /// Printer is paused
    Paused = 1,
    /// Printer has an error
    Error = 2,
    /// Printer is pending deletion
    PendingDeletion = 4,
    /// Paper jam
    PaperJam = 8,
    /// Paper out
    PaperOut = 16,
    /// Manual feed required
    ManualFeed = 32,
    /// Paper problem
    PaperProblem = 64,
    /// Printer is offline
    Offline = 128,
    /// Printer is busy
    Busy = 512,
    /// Printer is printing
    Printing = 1024,
    /// Output bin is full
    OutputBinFull = 2048,
    /// Not available
    NotAvailable = 4096,
    /// Printer is waiting
    Waiting = 8192,
    /// Printer is processing
    Processing = 16384,
    /// Printer is initializing
    Initializing = 32768,
    /// Printer is warming up
    WarmingUp = 65536,
    /// Toner/ink low
    TonerLow = 131072,
    /// No toner
    NoToner = 262144,
    /// Page punt
    PagePunt = 524288,
    /// User intervention required
    UserIntervention = 1048576,
    /// Printer is out of memory
    OutOfMemory = 2097152,
    /// Door open
    DoorOpen = 4194304,
    /// Server unknown
    ServerUnknown = 8388608,
    /// Power save mode
    PowerSave = 16777216,
}

impl PrinterStatus {
    /// Create new status
    pub const fn new() -> Self {
        Self::Ready
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::Paused => "Paused",
            Self::Error => "Error",
            Self::PendingDeletion => "Deleting",
            Self::PaperJam => "Paper Jam",
            Self::PaperOut => "Paper Out",
            Self::ManualFeed => "Manual Feed",
            Self::PaperProblem => "Paper Problem",
            Self::Offline => "Offline",
            Self::Busy => "Busy",
            Self::Printing => "Printing",
            Self::OutputBinFull => "Output Bin Full",
            Self::NotAvailable => "Not Available",
            Self::Waiting => "Waiting",
            Self::Processing => "Processing",
            Self::Initializing => "Initializing",
            Self::WarmingUp => "Warming Up",
            Self::TonerLow => "Toner Low",
            Self::NoToner => "No Toner",
            Self::PagePunt => "Page Punt",
            Self::UserIntervention => "User Intervention",
            Self::OutOfMemory => "Out of Memory",
            Self::DoorOpen => "Door Open",
            Self::ServerUnknown => "Server Unknown",
            Self::PowerSave => "Power Save",
        }
    }
}

impl Default for PrinterStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// Print job status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum JobStatus {
    /// Job is paused
    Paused = 0x00000001,
    /// Job has an error
    Error = 0x00000002,
    /// Job is deleting
    Deleting = 0x00000004,
    /// Job is spooling
    Spooling = 0x00000008,
    /// Job is printing
    Printing = 0x00000010,
    /// Job is offline
    Offline = 0x00000020,
    /// Paper out
    PaperOut = 0x00000040,
    /// Job printed
    Printed = 0x00000080,
    /// Job deleted
    Deleted = 0x00000100,
    /// Job blocked by driver upgrade
    BlockedDevQueue = 0x00000200,
    /// User intervention required
    UserIntervention = 0x00000400,
    /// Job restarted
    Restart = 0x00000800,
    /// Job completed
    Complete = 0x00001000,
    /// Job retained after printing
    Retained = 0x00002000,
    /// Rendering locally
    RenderingLocally = 0x00004000,
}

impl JobStatus {
    /// Create new status
    pub const fn new() -> Self {
        Self::Spooling
    }
}

impl Default for JobStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// Printer attributes
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PrinterAttributes: u32 {
        /// Direct printing (no spooling)
        const DIRECT = 0x00000002;
        /// Default printer
        const DEFAULT = 0x00000004;
        /// Shared printer
        const SHARED = 0x00000008;
        /// Network printer
        const NETWORK = 0x00000010;
        /// Hidden printer
        const HIDDEN = 0x00000020;
        /// Local printer
        const LOCAL = 0x00000040;
        /// Enable DevQuery
        const ENABLE_DEVQ = 0x00000080;
        /// Keep printed jobs
        const KEEPPRINTEDJOBS = 0x00000100;
        /// Do complete first
        const DO_COMPLETE_FIRST = 0x00000200;
        /// Work offline
        const WORK_OFFLINE = 0x00000400;
        /// Enable BIDI
        const ENABLE_BIDI = 0x00000800;
        /// Raw only
        const RAW_ONLY = 0x00001000;
        /// Published in AD
        const PUBLISHED = 0x00002000;
        /// FAX printer
        const FAX = 0x00004000;
    }
}

impl Default for PrinterAttributes {
    fn default() -> Self {
        Self::LOCAL
    }
}

/// Port type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PortType {
    /// Local port
    Local = 0,
    /// TCP/IP port
    TcpIp = 1,
    /// USB port
    Usb = 2,
    /// LPT (parallel) port
    Lpt = 3,
    /// COM (serial) port
    Com = 4,
    /// File port
    File = 5,
    /// Web Services for Devices
    Wsd = 6,
}

impl PortType {
    /// Create new port type
    pub const fn new() -> Self {
        Self::Local
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Local => "Local Port",
            Self::TcpIp => "Standard TCP/IP Port",
            Self::Usb => "USB Port",
            Self::Lpt => "LPT Port",
            Self::Com => "COM Port",
            Self::File => "FILE Port",
            Self::Wsd => "WSD Port",
        }
    }
}

impl Default for PortType {
    fn default() -> Self {
        Self::new()
    }
}

/// Driver architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DriverArch {
    /// x86 (32-bit)
    X86 = 0,
    /// x64 (64-bit)
    X64 = 1,
    /// IA64 (Itanium)
    Ia64 = 2,
}

impl DriverArch {
    /// Create new architecture
    pub const fn new() -> Self {
        Self::X86
    }

    /// Get environment string
    pub fn environment(&self) -> &'static str {
        match self {
            Self::X86 => "Windows NT x86",
            Self::X64 => "Windows x64",
            Self::Ia64 => "Windows IA64",
        }
    }
}

impl Default for DriverArch {
    fn default() -> Self {
        Self::new()
    }
}

/// Print port
#[derive(Clone)]
pub struct PrintPort {
    /// Port ID
    pub port_id: u32,
    /// Port name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Port type
    pub port_type: PortType,
    /// Description
    pub description: [u8; MAX_NAME_LEN],
    /// Description length
    pub desc_len: usize,
    /// Monitor name
    pub monitor: [u8; MAX_NAME_LEN],
    /// Monitor length
    pub monitor_len: usize,
    /// For TCP/IP: IP address
    pub address: [u8; 64],
    /// Address length
    pub addr_len: usize,
    /// In use flag
    pub in_use: bool,
}

impl PrintPort {
    /// Create new port
    pub const fn new() -> Self {
        Self {
            port_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            port_type: PortType::Local,
            description: [0; MAX_NAME_LEN],
            desc_len: 0,
            monitor: [0; MAX_NAME_LEN],
            monitor_len: 0,
            address: [0; 64],
            addr_len: 0,
            in_use: false,
        }
    }

    /// Set port name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for PrintPort {
    fn default() -> Self {
        Self::new()
    }
}

/// Print driver
#[derive(Clone)]
pub struct PrintDriver {
    /// Driver ID
    pub driver_id: u32,
    /// Driver name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Architecture
    pub arch: DriverArch,
    /// Driver version
    pub version: u32,
    /// Driver path
    pub driver_path: [u8; MAX_PATH_LEN],
    /// Path length
    pub path_len: usize,
    /// Data file path
    pub data_file: [u8; MAX_PATH_LEN],
    /// Data file length
    pub data_len: usize,
    /// Config file path
    pub config_file: [u8; MAX_PATH_LEN],
    /// Config file length
    pub config_len: usize,
    /// Manufacturer
    pub manufacturer: [u8; MAX_NAME_LEN],
    /// Manufacturer length
    pub mfg_len: usize,
    /// In use flag
    pub in_use: bool,
}

impl PrintDriver {
    /// Create new driver
    pub const fn new() -> Self {
        Self {
            driver_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            arch: DriverArch::X86,
            version: 3,
            driver_path: [0; MAX_PATH_LEN],
            path_len: 0,
            data_file: [0; MAX_PATH_LEN],
            data_len: 0,
            config_file: [0; MAX_PATH_LEN],
            config_len: 0,
            manufacturer: [0; MAX_NAME_LEN],
            mfg_len: 0,
            in_use: false,
        }
    }

    /// Set driver name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for PrintDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// Print job
#[derive(Clone)]
pub struct PrintJob {
    /// Job ID
    pub job_id: u32,
    /// Printer ID
    pub printer_id: u32,
    /// Document name
    pub document: [u8; MAX_NAME_LEN],
    /// Document name length
    pub doc_len: usize,
    /// User name
    pub user: [u8; MAX_NAME_LEN],
    /// User length
    pub user_len: usize,
    /// Machine name
    pub machine: [u8; MAX_NAME_LEN],
    /// Machine length
    pub machine_len: usize,
    /// Status
    pub status: JobStatus,
    /// Priority (1-99)
    pub priority: u8,
    /// Reserved
    pub reserved: [u8; 3],
    /// Position in queue
    pub position: u32,
    /// Total pages
    pub total_pages: u32,
    /// Pages printed
    pub pages_printed: u32,
    /// Total bytes
    pub size: u64,
    /// Bytes printed
    pub bytes_printed: u64,
    /// Submit time
    pub submitted: u64,
    /// Start time
    pub start_time: u64,
    /// In use flag
    pub in_use: bool,
}

impl PrintJob {
    /// Create new job
    pub const fn new() -> Self {
        Self {
            job_id: 0,
            printer_id: 0,
            document: [0; MAX_NAME_LEN],
            doc_len: 0,
            user: [0; MAX_NAME_LEN],
            user_len: 0,
            machine: [0; MAX_NAME_LEN],
            machine_len: 0,
            status: JobStatus::Spooling,
            priority: 50,
            reserved: [0; 3],
            position: 0,
            total_pages: 0,
            pages_printed: 0,
            size: 0,
            bytes_printed: 0,
            submitted: 0,
            start_time: 0,
            in_use: false,
        }
    }

    /// Set document name
    pub fn set_document(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.document[..len].copy_from_slice(&name[..len]);
        self.doc_len = len;
    }

    /// Set user name
    pub fn set_user(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.user[..len].copy_from_slice(&name[..len]);
        self.user_len = len;
    }
}

impl Default for PrintJob {
    fn default() -> Self {
        Self::new()
    }
}

/// Printer
#[derive(Clone)]
pub struct Printer {
    /// Printer ID
    pub printer_id: u32,
    /// Printer name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Share name
    pub share_name: [u8; MAX_NAME_LEN],
    /// Share name length
    pub share_len: usize,
    /// Location
    pub location: [u8; MAX_NAME_LEN],
    /// Location length
    pub location_len: usize,
    /// Comment/description
    pub comment: [u8; MAX_NAME_LEN],
    /// Comment length
    pub comment_len: usize,
    /// Port ID
    pub port_id: u32,
    /// Driver ID
    pub driver_id: u32,
    /// Status
    pub status: PrinterStatus,
    /// Attributes
    pub attributes: PrinterAttributes,
    /// Priority
    pub priority: u8,
    /// Default priority for jobs
    pub default_priority: u8,
    /// Reserved
    pub reserved: [u8; 2],
    /// Total jobs
    pub total_jobs: u32,
    /// Total pages printed
    pub total_pages: u64,
    /// Total bytes printed
    pub total_bytes: u64,
    /// Server ID
    pub server_id: u32,
    /// In use flag
    pub in_use: bool,
}

impl Printer {
    /// Create new printer
    pub const fn new() -> Self {
        Self {
            printer_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            share_name: [0; MAX_NAME_LEN],
            share_len: 0,
            location: [0; MAX_NAME_LEN],
            location_len: 0,
            comment: [0; MAX_NAME_LEN],
            comment_len: 0,
            port_id: 0,
            driver_id: 0,
            status: PrinterStatus::Ready,
            attributes: PrinterAttributes::LOCAL,
            priority: 1,
            default_priority: 50,
            reserved: [0; 2],
            total_jobs: 0,
            total_pages: 0,
            total_bytes: 0,
            server_id: 0,
            in_use: false,
        }
    }

    /// Set printer name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Set share name
    pub fn set_share_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.share_name[..len].copy_from_slice(&name[..len]);
        self.share_len = len;
    }

    /// Set location
    pub fn set_location(&mut self, location: &[u8]) {
        let len = location.len().min(MAX_NAME_LEN);
        self.location[..len].copy_from_slice(&location[..len]);
        self.location_len = len;
    }
}

impl Default for Printer {
    fn default() -> Self {
        Self::new()
    }
}

/// Print server
#[derive(Clone)]
pub struct PrintServer {
    /// Server ID
    pub server_id: u32,
    /// Server name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Is local server
    pub is_local: bool,
    /// Reserved
    pub reserved: [u8; 3],
    /// Printers
    pub printers: [Printer; MAX_PRINTERS],
    /// Printer count
    pub printer_count: usize,
    /// Ports
    pub ports: [PrintPort; MAX_PORTS],
    /// Port count
    pub port_count: usize,
    /// Drivers
    pub drivers: [PrintDriver; MAX_DRIVERS],
    /// Driver count
    pub driver_count: usize,
    /// In use flag
    pub in_use: bool,
}

impl PrintServer {
    /// Create new server
    pub const fn new() -> Self {
        Self {
            server_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            is_local: false,
            reserved: [0; 3],
            printers: [const { Printer::new() }; MAX_PRINTERS],
            printer_count: 0,
            ports: [const { PrintPort::new() }; MAX_PORTS],
            port_count: 0,
            drivers: [const { PrintDriver::new() }; MAX_DRIVERS],
            driver_count: 0,
            in_use: false,
        }
    }

    /// Set server name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Find printer by name
    pub fn find_printer(&self, name: &[u8]) -> Option<usize> {
        for (i, printer) in self.printers.iter().enumerate() {
            if printer.in_use && &printer.name[..printer.name_len] == name {
                return Some(i);
            }
        }
        None
    }
}

impl Default for PrintServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Print Management state
pub struct PrintMgmtState {
    /// Servers
    pub servers: [PrintServer; MAX_SERVERS],
    /// Server count
    pub server_count: usize,
    /// Print jobs
    pub jobs: [PrintJob; MAX_JOBS],
    /// Job count
    pub job_count: usize,
    /// Next ID
    pub next_id: u32,
    /// Next job ID
    pub next_job_id: u32,
}

impl PrintMgmtState {
    /// Create new state
    pub const fn new() -> Self {
        Self {
            servers: [const { PrintServer::new() }; MAX_SERVERS],
            server_count: 0,
            jobs: [const { PrintJob::new() }; MAX_JOBS],
            job_count: 0,
            next_id: 1,
            next_job_id: 1,
        }
    }

    /// Find server by ID
    pub fn find_server(&self, server_id: u32) -> Option<usize> {
        for (i, server) in self.servers.iter().enumerate() {
            if server.in_use && server.server_id == server_id {
                return Some(i);
            }
        }
        None
    }
}

impl Default for PrintMgmtState {
    fn default() -> Self {
        Self::new()
    }
}

/// Global state
static PRINTMGMT_STATE: SpinLock<PrintMgmtState> = SpinLock::new(PrintMgmtState::new());

/// Initialization flag
static PRINTMGMT_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Statistics
static PRINTMGMT_OPERATION_COUNT: AtomicU32 = AtomicU32::new(0);

/// Error codes
pub mod error {
    pub const SUCCESS: u32 = 0;
    pub const NOT_INITIALIZED: u32 = 0xF2000001;
    pub const SERVER_NOT_FOUND: u32 = 0xF2000002;
    pub const PRINTER_NOT_FOUND: u32 = 0xF2000003;
    pub const DRIVER_NOT_FOUND: u32 = 0xF2000004;
    pub const PORT_NOT_FOUND: u32 = 0xF2000005;
    pub const JOB_NOT_FOUND: u32 = 0xF2000006;
    pub const ALREADY_EXISTS: u32 = 0xF2000007;
    pub const NO_MORE_OBJECTS: u32 = 0xF2000008;
    pub const ACCESS_DENIED: u32 = 0xF2000009;
    pub const PRINTER_OFFLINE: u32 = 0xF200000A;
}

/// Initialize Print Management
pub fn init() {
    if PRINTMGMT_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = PRINTMGMT_STATE.lock();

    // Reserve all IDs first to avoid borrow issues
    let server_id = state.next_id;
    let port_id = state.next_id + 1;
    let driver_id = state.next_id + 2;
    state.next_id += 3;

    // Create local print server
    {
        let server = &mut state.servers[0];
        server.in_use = true;
        server.server_id = server_id;
        server.set_name(b"localhost");
        server.is_local = true;

        // Create default port (LPT1)
        let port = &mut server.ports[0];
        port.in_use = true;
        port.port_id = port_id;
        port.set_name(b"LPT1:");
        port.port_type = PortType::Lpt;
        server.port_count = 1;

        // Create virtual PDF printer driver
        let driver = &mut server.drivers[0];
        driver.in_use = true;
        driver.driver_id = driver_id;
        driver.set_name(b"Microsoft Print to PDF");
        driver.arch = DriverArch::X64;
        driver.version = 3;
        server.driver_count = 1;
    }

    state.server_count = 1;
}

/// Add a print server
pub fn add_server(name: &[u8]) -> Result<u32, u32> {
    if !PRINTMGMT_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = PRINTMGMT_STATE.lock();

    // Find free slot
    let mut slot_idx = None;
    for (i, server) in state.servers.iter().enumerate() {
        if !server.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let server_id = state.next_id;
    state.next_id += 1;

    let server = &mut state.servers[idx];
    server.in_use = true;
    server.server_id = server_id;
    server.set_name(name);
    server.is_local = false;

    state.server_count += 1;
    PRINTMGMT_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(server_id)
}

/// Add a printer to a server
pub fn add_printer(
    server_id: u32,
    name: &[u8],
    port_id: u32,
    driver_id: u32,
) -> Result<u32, u32> {
    if !PRINTMGMT_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = PRINTMGMT_STATE.lock();

    let srv_idx = match state.find_server(server_id) {
        Some(i) => i,
        None => return Err(error::SERVER_NOT_FOUND),
    };

    // Find free printer slot
    let mut slot_idx = None;
    for (i, printer) in state.servers[srv_idx].printers.iter().enumerate() {
        if !printer.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let printer_id = state.next_id;
    state.next_id += 1;

    let printer = &mut state.servers[srv_idx].printers[idx];
    printer.in_use = true;
    printer.printer_id = printer_id;
    printer.set_name(name);
    printer.port_id = port_id;
    printer.driver_id = driver_id;
    printer.server_id = server_id;
    printer.status = PrinterStatus::Ready;
    printer.attributes = PrinterAttributes::LOCAL;

    state.servers[srv_idx].printer_count += 1;
    PRINTMGMT_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(printer_id)
}

/// Delete a printer
pub fn delete_printer(server_id: u32, printer_id: u32) -> Result<(), u32> {
    if !PRINTMGMT_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = PRINTMGMT_STATE.lock();

    let srv_idx = match state.find_server(server_id) {
        Some(i) => i,
        None => return Err(error::SERVER_NOT_FOUND),
    };

    let mut found = false;
    for printer in state.servers[srv_idx].printers.iter_mut() {
        if printer.in_use && printer.printer_id == printer_id {
            printer.in_use = false;
            found = true;
            break;
        }
    }

    if !found {
        return Err(error::PRINTER_NOT_FOUND);
    }

    state.servers[srv_idx].printer_count = state.servers[srv_idx].printer_count.saturating_sub(1);
    PRINTMGMT_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Pause/resume printer
pub fn set_printer_paused(server_id: u32, printer_id: u32, paused: bool) -> Result<(), u32> {
    if !PRINTMGMT_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = PRINTMGMT_STATE.lock();

    let srv_idx = match state.find_server(server_id) {
        Some(i) => i,
        None => return Err(error::SERVER_NOT_FOUND),
    };

    for printer in state.servers[srv_idx].printers.iter_mut() {
        if printer.in_use && printer.printer_id == printer_id {
            printer.status = if paused {
                PrinterStatus::Paused
            } else {
                PrinterStatus::Ready
            };
            PRINTMGMT_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(error::PRINTER_NOT_FOUND)
}

/// Submit a print job
pub fn submit_job(
    printer_id: u32,
    document: &[u8],
    user: &[u8],
    size: u64,
    pages: u32,
) -> Result<u32, u32> {
    if !PRINTMGMT_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = PRINTMGMT_STATE.lock();

    // Find free job slot
    let mut slot_idx = None;
    for (i, job) in state.jobs.iter().enumerate() {
        if !job.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let job_id = state.next_job_id;
    state.next_job_id += 1;

    let job = &mut state.jobs[idx];
    job.in_use = true;
    job.job_id = job_id;
    job.printer_id = printer_id;
    job.set_document(document);
    job.set_user(user);
    job.size = size;
    job.total_pages = pages;
    job.status = JobStatus::Spooling;
    job.submitted = 1; // Would be current timestamp

    state.job_count += 1;
    PRINTMGMT_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(job_id)
}

/// Cancel a print job
pub fn cancel_job(job_id: u32) -> Result<(), u32> {
    if !PRINTMGMT_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = PRINTMGMT_STATE.lock();

    for job in state.jobs.iter_mut() {
        if job.in_use && job.job_id == job_id {
            job.status = JobStatus::Deleted;
            job.in_use = false;
            state.job_count = state.job_count.saturating_sub(1);
            PRINTMGMT_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(error::JOB_NOT_FOUND)
}

/// Get server count
pub fn get_server_count() -> usize {
    if !PRINTMGMT_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = PRINTMGMT_STATE.lock();
    state.server_count
}

/// Get total printer count
pub fn get_printer_count() -> usize {
    if !PRINTMGMT_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = PRINTMGMT_STATE.lock();
    state.servers.iter().filter(|s| s.in_use).map(|s| s.printer_count).sum()
}

/// Create Print Management window
pub fn create_printmgmt_dialog(parent: HWND) -> HWND {
    if !PRINTMGMT_INITIALIZED.load(Ordering::SeqCst) {
        init();
    }

    let id = 0xF2710000u32;
    let _parent = parent;

    UserHandle::from_raw(id)
}

/// Dialog messages
pub mod messages {
    pub const PM_REFRESH: u32 = 0x0820;
    pub const PM_ADD_SERVER: u32 = 0x0821;
    pub const PM_REMOVE_SERVER: u32 = 0x0822;
    pub const PM_ADD_PRINTER: u32 = 0x0823;
    pub const PM_DELETE_PRINTER: u32 = 0x0824;
    pub const PM_PRINTER_PROPERTIES: u32 = 0x0825;
    pub const PM_PAUSE_PRINTER: u32 = 0x0826;
    pub const PM_RESUME_PRINTER: u32 = 0x0827;
    pub const PM_CANCEL_JOB: u32 = 0x0828;
    pub const PM_PAUSE_JOB: u32 = 0x0829;
    pub const PM_RESUME_JOB: u32 = 0x082A;
    pub const PM_ADD_DRIVER: u32 = 0x082B;
    pub const PM_DELETE_DRIVER: u32 = 0x082C;
}

/// Get statistics
pub fn get_statistics() -> (usize, usize, usize, u32) {
    let state = PRINTMGMT_STATE.lock();
    let printers: usize = state.servers.iter().filter(|s| s.in_use).map(|s| s.printer_count).sum();
    let op_count = PRINTMGMT_OPERATION_COUNT.load(Ordering::Relaxed);
    (state.server_count, printers, state.job_count, op_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_mgmt_init() {
        init();
        assert!(PRINTMGMT_INITIALIZED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_printer_status() {
        assert_eq!(PrinterStatus::Ready.display_name(), "Ready");
    }

    #[test]
    fn test_port_type() {
        assert_eq!(PortType::TcpIp.display_name(), "Standard TCP/IP Port");
    }
}
