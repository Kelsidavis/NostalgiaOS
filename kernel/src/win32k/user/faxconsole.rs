//! Fax Service Console implementation
//!
//! Provides management of fax devices, incoming/outgoing faxes,
//! cover pages, and fax server configuration.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Local type alias for window handles
type HWND = UserHandle;

/// Maximum fax devices
const MAX_DEVICES: usize = 16;

/// Maximum fax jobs
const MAX_JOBS: usize = 256;

/// Maximum cover pages
const MAX_COVERS: usize = 32;

/// Maximum routing rules
const MAX_ROUTES: usize = 32;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Maximum phone number length
const MAX_PHONE_LEN: usize = 32;

/// Fax device status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceStatus {
    /// Device is idle
    Idle = 0,
    /// Device is sending
    Sending = 1,
    /// Device is receiving
    Receiving = 2,
    /// Device is ringing
    Ringing = 3,
    /// Device is dialing
    Dialing = 4,
    /// Device is offline
    Offline = 5,
    /// Device has error
    Error = 6,
    /// Device is initializing
    Initializing = 7,
    /// Device is answering
    Answering = 8,
    /// Device is busy
    Busy = 9,
}

impl DeviceStatus {
    /// Create new status
    pub const fn new() -> Self {
        Self::Idle
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Sending => "Sending",
            Self::Receiving => "Receiving",
            Self::Ringing => "Ringing",
            Self::Dialing => "Dialing",
            Self::Offline => "Offline",
            Self::Error => "Error",
            Self::Initializing => "Initializing",
            Self::Answering => "Answering",
            Self::Busy => "Busy",
        }
    }
}

impl Default for DeviceStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// Fax job status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum JobStatus {
    /// Job is pending
    Pending = 0,
    /// Job is in progress
    InProgress = 1,
    /// Job completed successfully
    Completed = 2,
    /// Job failed
    Failed = 3,
    /// Job is paused
    Paused = 4,
    /// No line available
    NoLine = 5,
    /// Job is retrying
    Retrying = 6,
    /// Job is routing
    Routing = 7,
    /// Job cancelled
    Cancelled = 8,
}

impl JobStatus {
    /// Create new status
    pub const fn new() -> Self {
        Self::Pending
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::InProgress => "In Progress",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::Paused => "Paused",
            Self::NoLine => "No Line",
            Self::Retrying => "Retrying",
            Self::Routing => "Routing",
            Self::Cancelled => "Cancelled",
        }
    }

    /// Is final state
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

impl Default for JobStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// Fax job type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum JobType {
    /// Outgoing fax
    Send = 0,
    /// Incoming fax
    Receive = 1,
    /// Routing job
    Routing = 2,
}

impl JobType {
    /// Create new job type
    pub const fn new() -> Self {
        Self::Send
    }
}

impl Default for JobType {
    fn default() -> Self {
        Self::new()
    }
}

/// Device receive mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ReceiveMode {
    /// No receive
    NoAnswer = 0,
    /// Auto answer
    AutoAnswer = 1,
    /// Manual answer
    ManualAnswer = 2,
}

impl ReceiveMode {
    /// Create new mode
    pub const fn new() -> Self {
        Self::AutoAnswer
    }
}

impl Default for ReceiveMode {
    fn default() -> Self {
        Self::new()
    }
}

/// Routing action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RoutingAction {
    /// Store in folder
    StoreInFolder = 0,
    /// Print
    Print = 1,
    /// Send to email
    Email = 2,
    /// Store in document library
    DocumentLibrary = 3,
}

impl RoutingAction {
    /// Create new action
    pub const fn new() -> Self {
        Self::StoreInFolder
    }
}

impl Default for RoutingAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Fax device
#[derive(Clone)]
pub struct FaxDevice {
    /// Device ID
    pub device_id: u32,
    /// Device name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Provider name
    pub provider: [u8; MAX_NAME_LEN],
    /// Provider length
    pub provider_len: usize,
    /// Status
    pub status: DeviceStatus,
    /// Receive mode
    pub receive_mode: ReceiveMode,
    /// Rings before answer
    pub rings_before_answer: u8,
    /// Send enabled
    pub send_enabled: bool,
    /// Receive enabled
    pub receive_enabled: bool,
    /// Reserved
    pub reserved: u8,
    /// CSID (Called Station ID)
    pub csid: [u8; MAX_NAME_LEN],
    /// CSID length
    pub csid_len: usize,
    /// TSID (Transmitting Station ID)
    pub tsid: [u8; MAX_NAME_LEN],
    /// TSID length
    pub tsid_len: usize,
    /// Total sent count
    pub sent_count: u32,
    /// Total received count
    pub received_count: u32,
    /// In use flag
    pub in_use: bool,
}

impl FaxDevice {
    /// Create new device
    pub const fn new() -> Self {
        Self {
            device_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            provider: [0; MAX_NAME_LEN],
            provider_len: 0,
            status: DeviceStatus::Idle,
            receive_mode: ReceiveMode::AutoAnswer,
            rings_before_answer: 2,
            send_enabled: true,
            receive_enabled: true,
            reserved: 0,
            csid: [0; MAX_NAME_LEN],
            csid_len: 0,
            tsid: [0; MAX_NAME_LEN],
            tsid_len: 0,
            sent_count: 0,
            received_count: 0,
            in_use: false,
        }
    }

    /// Set device name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Set CSID
    pub fn set_csid(&mut self, csid: &[u8]) {
        let len = csid.len().min(MAX_NAME_LEN);
        self.csid[..len].copy_from_slice(&csid[..len]);
        self.csid_len = len;
    }

    /// Set TSID
    pub fn set_tsid(&mut self, tsid: &[u8]) {
        let len = tsid.len().min(MAX_NAME_LEN);
        self.tsid[..len].copy_from_slice(&tsid[..len]);
        self.tsid_len = len;
    }
}

impl Default for FaxDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// Fax job
#[derive(Clone)]
pub struct FaxJob {
    /// Job ID
    pub job_id: u32,
    /// Job type
    pub job_type: JobType,
    /// Status
    pub status: JobStatus,
    /// Device ID
    pub device_id: u32,
    /// Document name
    pub document: [u8; MAX_NAME_LEN],
    /// Document name length
    pub doc_len: usize,
    /// Sender name
    pub sender: [u8; MAX_NAME_LEN],
    /// Sender length
    pub sender_len: usize,
    /// Sender fax number
    pub sender_number: [u8; MAX_PHONE_LEN],
    /// Sender number length
    pub sender_num_len: usize,
    /// Recipient name
    pub recipient: [u8; MAX_NAME_LEN],
    /// Recipient length
    pub recipient_len: usize,
    /// Recipient fax number
    pub recipient_number: [u8; MAX_PHONE_LEN],
    /// Recipient number length
    pub recipient_num_len: usize,
    /// Subject
    pub subject: [u8; MAX_NAME_LEN],
    /// Subject length
    pub subject_len: usize,
    /// Total pages
    pub total_pages: u32,
    /// Pages transmitted
    pub pages_done: u32,
    /// Size in bytes
    pub size: u64,
    /// Submit time
    pub submitted: u64,
    /// Start time
    pub start_time: u64,
    /// End time
    pub end_time: u64,
    /// Retry count
    pub retries: u8,
    /// Priority (0-255)
    pub priority: u8,
    /// Reserved
    pub reserved: [u8; 2],
    /// Extended status code
    pub extended_status: u32,
    /// In use flag
    pub in_use: bool,
}

impl FaxJob {
    /// Create new job
    pub const fn new() -> Self {
        Self {
            job_id: 0,
            job_type: JobType::Send,
            status: JobStatus::Pending,
            device_id: 0,
            document: [0; MAX_NAME_LEN],
            doc_len: 0,
            sender: [0; MAX_NAME_LEN],
            sender_len: 0,
            sender_number: [0; MAX_PHONE_LEN],
            sender_num_len: 0,
            recipient: [0; MAX_NAME_LEN],
            recipient_len: 0,
            recipient_number: [0; MAX_PHONE_LEN],
            recipient_num_len: 0,
            subject: [0; MAX_NAME_LEN],
            subject_len: 0,
            total_pages: 0,
            pages_done: 0,
            size: 0,
            submitted: 0,
            start_time: 0,
            end_time: 0,
            retries: 0,
            priority: 128,
            reserved: [0; 2],
            extended_status: 0,
            in_use: false,
        }
    }

    /// Set recipient
    pub fn set_recipient(&mut self, name: &[u8], number: &[u8]) {
        let name_len = name.len().min(MAX_NAME_LEN);
        self.recipient[..name_len].copy_from_slice(&name[..name_len]);
        self.recipient_len = name_len;

        let num_len = number.len().min(MAX_PHONE_LEN);
        self.recipient_number[..num_len].copy_from_slice(&number[..num_len]);
        self.recipient_num_len = num_len;
    }

    /// Set sender
    pub fn set_sender(&mut self, name: &[u8], number: &[u8]) {
        let name_len = name.len().min(MAX_NAME_LEN);
        self.sender[..name_len].copy_from_slice(&name[..name_len]);
        self.sender_len = name_len;

        let num_len = number.len().min(MAX_PHONE_LEN);
        self.sender_number[..num_len].copy_from_slice(&number[..num_len]);
        self.sender_num_len = num_len;
    }

    /// Set document
    pub fn set_document(&mut self, doc: &[u8]) {
        let len = doc.len().min(MAX_NAME_LEN);
        self.document[..len].copy_from_slice(&doc[..len]);
        self.doc_len = len;
    }
}

impl Default for FaxJob {
    fn default() -> Self {
        Self::new()
    }
}

/// Cover page template
#[derive(Clone)]
pub struct CoverPage {
    /// Cover page ID
    pub cover_id: u32,
    /// Name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// File path
    pub path: [u8; MAX_PATH_LEN],
    /// Path length
    pub path_len: usize,
    /// Is server cover page
    pub is_server: bool,
    /// Reserved
    pub reserved: [u8; 3],
    /// In use flag
    pub in_use: bool,
}

impl CoverPage {
    /// Create new cover page
    pub const fn new() -> Self {
        Self {
            cover_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            path: [0; MAX_PATH_LEN],
            path_len: 0,
            is_server: false,
            reserved: [0; 3],
            in_use: false,
        }
    }

    /// Set name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Set path
    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_PATH_LEN);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }
}

impl Default for CoverPage {
    fn default() -> Self {
        Self::new()
    }
}

/// Inbound routing rule
#[derive(Clone)]
pub struct RoutingRule {
    /// Rule ID
    pub rule_id: u32,
    /// Device ID (0 for all devices)
    pub device_id: u32,
    /// Action
    pub action: RoutingAction,
    /// Destination (folder path, printer name, or email)
    pub destination: [u8; MAX_PATH_LEN],
    /// Destination length
    pub dest_len: usize,
    /// Enabled
    pub enabled: bool,
    /// Reserved
    pub reserved: [u8; 3],
    /// Priority
    pub priority: u32,
    /// In use flag
    pub in_use: bool,
}

impl RoutingRule {
    /// Create new rule
    pub const fn new() -> Self {
        Self {
            rule_id: 0,
            device_id: 0,
            action: RoutingAction::StoreInFolder,
            destination: [0; MAX_PATH_LEN],
            dest_len: 0,
            enabled: true,
            reserved: [0; 3],
            priority: 0,
            in_use: false,
        }
    }

    /// Set destination
    pub fn set_destination(&mut self, dest: &[u8]) {
        let len = dest.len().min(MAX_PATH_LEN);
        self.destination[..len].copy_from_slice(&dest[..len]);
        self.dest_len = len;
    }
}

impl Default for RoutingRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Fax server configuration
#[derive(Clone)]
pub struct FaxServerConfig {
    /// Server started
    pub started: bool,
    /// Use device TSID
    pub use_device_tsid: bool,
    /// Branding enabled
    pub branding: bool,
    /// Reserved
    pub reserved: u8,
    /// Retry count
    pub retries: u8,
    /// Retry delay (minutes)
    pub retry_delay: u8,
    /// Reserved
    pub reserved2: [u8; 2],
    /// Discount rate start hour
    pub discount_start_hour: u8,
    /// Discount rate start minute
    pub discount_start_min: u8,
    /// Discount rate end hour
    pub discount_end_hour: u8,
    /// Discount rate end minute
    pub discount_end_min: u8,
    /// Archive outgoing faxes
    pub archive_outgoing: bool,
    /// Archive path
    pub archive_path: [u8; MAX_PATH_LEN],
    /// Archive path length
    pub archive_len: usize,
    /// Incoming fax folder
    pub incoming_path: [u8; MAX_PATH_LEN],
    /// Incoming path length
    pub incoming_len: usize,
}

impl FaxServerConfig {
    /// Create new config
    pub const fn new() -> Self {
        Self {
            started: true,
            use_device_tsid: true,
            branding: true,
            reserved: 0,
            retries: 3,
            retry_delay: 10,
            reserved2: [0; 2],
            discount_start_hour: 23,
            discount_start_min: 0,
            discount_end_hour: 6,
            discount_end_min: 0,
            archive_outgoing: false,
            archive_path: [0; MAX_PATH_LEN],
            archive_len: 0,
            incoming_path: [0; MAX_PATH_LEN],
            incoming_len: 0,
        }
    }
}

impl Default for FaxServerConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Fax Console state
pub struct FaxConsoleState {
    /// Server config
    pub config: FaxServerConfig,
    /// Devices
    pub devices: [FaxDevice; MAX_DEVICES],
    /// Device count
    pub device_count: usize,
    /// Jobs (inbox, outbox, sent items)
    pub jobs: [FaxJob; MAX_JOBS],
    /// Job count
    pub job_count: usize,
    /// Cover pages
    pub covers: [CoverPage; MAX_COVERS],
    /// Cover page count
    pub cover_count: usize,
    /// Routing rules
    pub routes: [RoutingRule; MAX_ROUTES],
    /// Route count
    pub route_count: usize,
    /// Next ID
    pub next_id: u32,
    /// Next job ID
    pub next_job_id: u32,
}

impl FaxConsoleState {
    /// Create new state
    pub const fn new() -> Self {
        Self {
            config: FaxServerConfig::new(),
            devices: [const { FaxDevice::new() }; MAX_DEVICES],
            device_count: 0,
            jobs: [const { FaxJob::new() }; MAX_JOBS],
            job_count: 0,
            covers: [const { CoverPage::new() }; MAX_COVERS],
            cover_count: 0,
            routes: [const { RoutingRule::new() }; MAX_ROUTES],
            route_count: 0,
            next_id: 1,
            next_job_id: 1,
        }
    }

    /// Find device by ID
    pub fn find_device(&self, device_id: u32) -> Option<usize> {
        for (i, dev) in self.devices.iter().enumerate() {
            if dev.in_use && dev.device_id == device_id {
                return Some(i);
            }
        }
        None
    }

    /// Find job by ID
    pub fn find_job(&self, job_id: u32) -> Option<usize> {
        for (i, job) in self.jobs.iter().enumerate() {
            if job.in_use && job.job_id == job_id {
                return Some(i);
            }
        }
        None
    }
}

impl Default for FaxConsoleState {
    fn default() -> Self {
        Self::new()
    }
}

/// Global state
static FAX_STATE: SpinLock<FaxConsoleState> = SpinLock::new(FaxConsoleState::new());

/// Initialization flag
static FAX_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Statistics
static FAX_OPERATION_COUNT: AtomicU32 = AtomicU32::new(0);

/// Error codes
pub mod error {
    pub const SUCCESS: u32 = 0;
    pub const NOT_INITIALIZED: u32 = 0xFA000001;
    pub const DEVICE_NOT_FOUND: u32 = 0xFA000002;
    pub const JOB_NOT_FOUND: u32 = 0xFA000003;
    pub const DEVICE_BUSY: u32 = 0xFA000004;
    pub const NO_LINE: u32 = 0xFA000005;
    pub const ALREADY_EXISTS: u32 = 0xFA000006;
    pub const NO_MORE_OBJECTS: u32 = 0xFA000007;
    pub const INVALID_PARAMETER: u32 = 0xFA000008;
    pub const SERVICE_NOT_RUNNING: u32 = 0xFA000009;
}

/// Initialize Fax Console
pub fn init() {
    if FAX_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = FAX_STATE.lock();

    // Create default fax device
    let device_id = state.next_id;
    state.next_id += 1;

    let device = &mut state.devices[0];
    device.in_use = true;
    device.device_id = device_id;
    device.set_name(b"Fax Modem");
    device.status = DeviceStatus::Idle;
    device.receive_mode = ReceiveMode::AutoAnswer;
    device.rings_before_answer = 2;
    device.send_enabled = true;
    device.receive_enabled = true;
    device.set_csid(b"Fax");
    device.set_tsid(b"Fax");

    state.device_count = 1;

    // Create default routing rule
    let rule_id = state.next_id;
    state.next_id += 1;

    let rule = &mut state.routes[0];
    rule.in_use = true;
    rule.rule_id = rule_id;
    rule.device_id = 0; // All devices
    rule.action = RoutingAction::StoreInFolder;
    rule.set_destination(b"C:\\Documents and Settings\\All Users\\Application Data\\Microsoft\\Windows NT\\MSFax\\Inbox");
    rule.enabled = true;

    state.route_count = 1;

    // Create default cover page
    let cover_id = state.next_id;
    state.next_id += 1;

    let cover = &mut state.covers[0];
    cover.in_use = true;
    cover.cover_id = cover_id;
    cover.set_name(b"Generic");
    cover.set_path(b"C:\\Documents and Settings\\All Users\\Application Data\\Microsoft\\Windows NT\\MSFax\\Common Coverpages\\generic.cov");
    cover.is_server = true;

    state.cover_count = 1;
}

/// Send a fax
pub fn send_fax(
    document: &[u8],
    recipient_name: &[u8],
    recipient_number: &[u8],
    cover_page_id: Option<u32>,
) -> Result<u32, u32> {
    if !FAX_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = FAX_STATE.lock();

    if !state.config.started {
        return Err(error::SERVICE_NOT_RUNNING);
    }

    // Find available device
    let mut available_device = None;
    for dev in state.devices.iter() {
        if dev.in_use && dev.send_enabled && dev.status == DeviceStatus::Idle {
            available_device = Some(dev.device_id);
            break;
        }
    }

    let device_id = match available_device {
        Some(id) => id,
        None => return Err(error::NO_LINE),
    };

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
    job.job_type = JobType::Send;
    job.status = JobStatus::Pending;
    job.device_id = device_id;
    job.set_document(document);
    job.set_recipient(recipient_name, recipient_number);
    job.submitted = 1; // Would be current timestamp

    let _ = cover_page_id; // Would attach cover page

    state.job_count += 1;
    FAX_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(job_id)
}

/// Cancel a fax job
pub fn cancel_job(job_id: u32) -> Result<(), u32> {
    if !FAX_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = FAX_STATE.lock();

    let idx = match state.find_job(job_id) {
        Some(i) => i,
        None => return Err(error::JOB_NOT_FOUND),
    };

    if state.jobs[idx].status.is_final() {
        return Err(error::INVALID_PARAMETER);
    }

    state.jobs[idx].status = JobStatus::Cancelled;
    state.jobs[idx].end_time = 1; // Would be current timestamp

    FAX_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Pause a fax job
pub fn pause_job(job_id: u32) -> Result<(), u32> {
    if !FAX_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = FAX_STATE.lock();

    let idx = match state.find_job(job_id) {
        Some(i) => i,
        None => return Err(error::JOB_NOT_FOUND),
    };

    if state.jobs[idx].status != JobStatus::Pending {
        return Err(error::INVALID_PARAMETER);
    }

    state.jobs[idx].status = JobStatus::Paused;

    FAX_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Resume a paused fax job
pub fn resume_job(job_id: u32) -> Result<(), u32> {
    if !FAX_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = FAX_STATE.lock();

    let idx = match state.find_job(job_id) {
        Some(i) => i,
        None => return Err(error::JOB_NOT_FOUND),
    };

    if state.jobs[idx].status != JobStatus::Paused {
        return Err(error::INVALID_PARAMETER);
    }

    state.jobs[idx].status = JobStatus::Pending;

    FAX_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Set device receive mode
pub fn set_receive_mode(device_id: u32, mode: ReceiveMode) -> Result<(), u32> {
    if !FAX_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = FAX_STATE.lock();

    let idx = match state.find_device(device_id) {
        Some(i) => i,
        None => return Err(error::DEVICE_NOT_FOUND),
    };

    state.devices[idx].receive_mode = mode;
    state.devices[idx].receive_enabled = mode != ReceiveMode::NoAnswer;

    FAX_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Enable/disable device for sending
pub fn set_send_enabled(device_id: u32, enabled: bool) -> Result<(), u32> {
    if !FAX_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = FAX_STATE.lock();

    let idx = match state.find_device(device_id) {
        Some(i) => i,
        None => return Err(error::DEVICE_NOT_FOUND),
    };

    state.devices[idx].send_enabled = enabled;

    FAX_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Get device count
pub fn get_device_count() -> usize {
    if !FAX_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = FAX_STATE.lock();
    state.device_count
}

/// Get job count
pub fn get_job_count() -> usize {
    if !FAX_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = FAX_STATE.lock();
    state.job_count
}

/// Get pending job count
pub fn get_pending_count() -> usize {
    if !FAX_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = FAX_STATE.lock();
    state.jobs.iter().filter(|j| j.in_use && j.status == JobStatus::Pending).count()
}

/// Create Fax Console window
pub fn create_fax_dialog(parent: HWND) -> HWND {
    if !FAX_INITIALIZED.load(Ordering::SeqCst) {
        init();
    }

    let id = 0xFA200000u32;
    let _parent = parent;

    UserHandle::from_raw(id)
}

/// Dialog messages
pub mod messages {
    pub const FAX_REFRESH: u32 = 0x0860;
    pub const FAX_SEND: u32 = 0x0861;
    pub const FAX_CANCEL: u32 = 0x0862;
    pub const FAX_PAUSE: u32 = 0x0863;
    pub const FAX_RESUME: u32 = 0x0864;
    pub const FAX_DELETE: u32 = 0x0865;
    pub const FAX_PROPERTIES: u32 = 0x0866;
    pub const FAX_DEVICE_CONFIG: u32 = 0x0867;
    pub const FAX_SERVER_CONFIG: u32 = 0x0868;
    pub const FAX_ROUTING: u32 = 0x0869;
    pub const FAX_COVER_PAGES: u32 = 0x086A;
}

/// Get statistics
pub fn get_statistics() -> (usize, usize, usize, u32) {
    let state = FAX_STATE.lock();
    let pending = state.jobs.iter().filter(|j| j.in_use && j.status == JobStatus::Pending).count();
    let op_count = FAX_OPERATION_COUNT.load(Ordering::Relaxed);
    (state.device_count, state.job_count, pending, op_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fax_init() {
        init();
        assert!(FAX_INITIALIZED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_device_status() {
        assert_eq!(DeviceStatus::Sending.display_name(), "Sending");
    }

    #[test]
    fn test_job_status_final() {
        assert!(JobStatus::Completed.is_final());
        assert!(!JobStatus::Pending.is_final());
    }
}
