//! Services Control Manager UI
//!
//! Implements the Services management console following Windows Server 2003.
//! Provides service enumeration, control, and configuration.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - services.msc - Services MMC snap-in
//! - sc.exe - Service Control command
//! - advapi32.dll - Service Control Manager API

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum services
const MAX_SERVICES: usize = 256;

/// Maximum service name length
const MAX_NAME: usize = 64;

/// Maximum display name length
const MAX_DISPLAY_NAME: usize = 128;

/// Maximum description length
const MAX_DESC: usize = 256;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Maximum dependencies
const MAX_DEPENDENCIES: usize = 8;

// ============================================================================
// Service State
// ============================================================================

/// Service state
pub mod service_state {
    /// Service is stopped
    pub const STOPPED: u32 = 1;
    /// Service is starting
    pub const START_PENDING: u32 = 2;
    /// Service is stopping
    pub const STOP_PENDING: u32 = 3;
    /// Service is running
    pub const RUNNING: u32 = 4;
    /// Service is continuing
    pub const CONTINUE_PENDING: u32 = 5;
    /// Service is pausing
    pub const PAUSE_PENDING: u32 = 6;
    /// Service is paused
    pub const PAUSED: u32 = 7;
}

// ============================================================================
// Service Start Type
// ============================================================================

/// Service start type
pub mod start_type {
    /// Boot start (loaded by boot loader)
    pub const BOOT_START: u32 = 0;
    /// System start (loaded during kernel init)
    pub const SYSTEM_START: u32 = 1;
    /// Automatic (started by SCM at boot)
    pub const AUTO_START: u32 = 2;
    /// Manual (started on demand)
    pub const DEMAND_START: u32 = 3;
    /// Disabled (cannot be started)
    pub const DISABLED: u32 = 4;
}

// ============================================================================
// Service Type
// ============================================================================

/// Service type flags
pub mod service_type {
    /// Kernel driver
    pub const KERNEL_DRIVER: u32 = 0x01;
    /// File system driver
    pub const FILE_SYSTEM_DRIVER: u32 = 0x02;
    /// Win32 own process
    pub const WIN32_OWN_PROCESS: u32 = 0x10;
    /// Win32 share process
    pub const WIN32_SHARE_PROCESS: u32 = 0x20;
    /// Interactive process
    pub const INTERACTIVE_PROCESS: u32 = 0x100;
}

// ============================================================================
// Error Control
// ============================================================================

/// Error control level
pub mod error_control {
    /// Ignore errors
    pub const IGNORE: u32 = 0;
    /// Log errors but continue
    pub const NORMAL: u32 = 1;
    /// Log errors and switch to LastKnownGood
    pub const SEVERE: u32 = 2;
    /// Log errors and fail boot
    pub const CRITICAL: u32 = 3;
}

// ============================================================================
// Service Entry
// ============================================================================

/// Service entry
#[derive(Clone, Copy)]
pub struct ServiceEntry {
    /// Service name (short name)
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Display name
    pub display_name: [u8; MAX_DISPLAY_NAME],
    /// Display name length
    pub display_name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC],
    /// Description length
    pub description_len: usize,
    /// Binary path
    pub binary_path: [u8; MAX_PATH],
    /// Path length
    pub path_len: usize,
    /// Service type
    pub service_type: u32,
    /// Start type
    pub start_type: u32,
    /// Error control
    pub error_control: u32,
    /// Current state
    pub state: u32,
    /// Process ID (if running)
    pub process_id: u32,
    /// Accepts stop
    pub accepts_stop: bool,
    /// Accepts pause
    pub accepts_pause: bool,
    /// Log on as (account name)
    pub logon_account: [u8; MAX_NAME],
    /// Logon account length
    pub logon_account_len: usize,
    /// Dependencies (service names, separated)
    pub dependencies: [[u8; MAX_NAME]; MAX_DEPENDENCIES],
    /// Dependency count
    pub dependency_count: usize,
}

impl ServiceEntry {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            display_name: [0u8; MAX_DISPLAY_NAME],
            display_name_len: 0,
            description: [0u8; MAX_DESC],
            description_len: 0,
            binary_path: [0u8; MAX_PATH],
            path_len: 0,
            service_type: service_type::WIN32_OWN_PROCESS,
            start_type: start_type::DEMAND_START,
            error_control: error_control::NORMAL,
            state: service_state::STOPPED,
            process_id: 0,
            accepts_stop: true,
            accepts_pause: false,
            logon_account: [0u8; MAX_NAME],
            logon_account_len: 0,
            dependencies: [[0u8; MAX_NAME]; MAX_DEPENDENCIES],
            dependency_count: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_display_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_DISPLAY_NAME);
        self.display_name[..len].copy_from_slice(&name[..len]);
        self.display_name_len = len;
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_DESC);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.description_len = len;
    }

    pub fn set_binary_path(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_PATH);
        self.binary_path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }

    pub fn set_logon_account(&mut self, account: &[u8]) {
        let len = account.len().min(MAX_NAME);
        self.logon_account[..len].copy_from_slice(&account[..len]);
        self.logon_account_len = len;
    }

    pub fn add_dependency(&mut self, dep: &[u8]) -> bool {
        if self.dependency_count >= MAX_DEPENDENCIES {
            return false;
        }
        let len = dep.len().min(MAX_NAME);
        self.dependencies[self.dependency_count][..len].copy_from_slice(&dep[..len]);
        self.dependency_count += 1;
        true
    }

    pub fn state_name(&self) -> &'static str {
        match self.state {
            service_state::STOPPED => "Stopped",
            service_state::START_PENDING => "Starting",
            service_state::STOP_PENDING => "Stopping",
            service_state::RUNNING => "Running",
            service_state::CONTINUE_PENDING => "Continuing",
            service_state::PAUSE_PENDING => "Pausing",
            service_state::PAUSED => "Paused",
            _ => "Unknown",
        }
    }

    pub fn start_type_name(&self) -> &'static str {
        match self.start_type {
            start_type::BOOT_START => "Boot",
            start_type::SYSTEM_START => "System",
            start_type::AUTO_START => "Automatic",
            start_type::DEMAND_START => "Manual",
            start_type::DISABLED => "Disabled",
            _ => "Unknown",
        }
    }
}

impl Default for ServiceEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Services State
// ============================================================================

/// Services state
struct ServicesState {
    /// All services
    services: [ServiceEntry; MAX_SERVICES],
    /// Service count
    service_count: usize,
}

impl ServicesState {
    pub const fn new() -> Self {
        Self {
            services: [const { ServiceEntry::new() }; MAX_SERVICES],
            service_count: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static SERVICES_INITIALIZED: AtomicBool = AtomicBool::new(false);
static SERVICES_STATE: SpinLock<ServicesState> = SpinLock::new(ServicesState::new());

// Statistics
static SERVICE_START_COUNT: AtomicU32 = AtomicU32::new(0);
static SERVICE_STOP_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Services
pub fn init() {
    if SERVICES_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = SERVICES_STATE.lock();

    // Add Windows services
    add_windows_services(&mut state);

    crate::serial_println!("[WIN32K] Services initialized");
}

/// Add Windows services
fn add_windows_services(state: &mut ServicesState) {
    // Core system services
    add_service(state, b"EventLog", b"Windows Event Log",
        b"Manages events and event logs. Supports logging events, querying events, subscribing to events.",
        b"%SystemRoot%\\System32\\services.exe",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"PlugPlay", b"Plug and Play",
        b"Enables a computer to recognize and adapt to hardware changes with little or no user input.",
        b"%SystemRoot%\\System32\\services.exe",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"RpcSs", b"Remote Procedure Call (RPC)",
        b"Serves as the endpoint mapper and COM Service Control Manager.",
        b"%SystemRoot%\\System32\\svchost.exe -k rpcss",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"DCOM Server Process Launcher", b"DCOM Server Process Launcher",
        b"Provides launch functionality for DCOM services.",
        b"%SystemRoot%\\System32\\svchost.exe -k DcomLaunch",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"Dhcp", b"DHCP Client",
        b"Registers and updates IP addresses and DNS records for this computer.",
        b"%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"Dnscache", b"DNS Client",
        b"Resolves and caches Domain Name System (DNS) names for this computer.",
        b"%SystemRoot%\\System32\\svchost.exe -k NetworkService",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"LanmanServer", b"Server",
        b"Supports file, print, and named-pipe sharing over the network.",
        b"%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"LanmanWorkstation", b"Workstation",
        b"Creates and maintains client network connections to remote servers.",
        b"%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"Netlogon", b"Net Logon",
        b"Maintains a secure channel between this computer and the domain controller.",
        b"%SystemRoot%\\System32\\lsass.exe",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"SamSs", b"Security Accounts Manager",
        b"Stores security information for local user accounts.",
        b"%SystemRoot%\\System32\\lsass.exe",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"Spooler", b"Print Spooler",
        b"Loads files to memory for later printing.",
        b"%SystemRoot%\\System32\\spoolsv.exe",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"Schedule", b"Task Scheduler",
        b"Enables a user to configure and schedule automated tasks on this computer.",
        b"%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"W32Time", b"Windows Time",
        b"Maintains date and time synchronization on all clients and servers in the network.",
        b"%SystemRoot%\\System32\\svchost.exe -k LocalService",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"Themes", b"Themes",
        b"Provides user experience theme management.",
        b"%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"AudioSrv", b"Windows Audio",
        b"Manages audio devices for Windows-based programs.",
        b"%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"Wuauserv", b"Automatic Updates",
        b"Enables the download and installation of Windows updates.",
        b"%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"BITS", b"Background Intelligent Transfer Service",
        b"Transfers files in the background using idle network bandwidth.",
        b"%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        start_type::DEMAND_START, service_state::STOPPED);

    add_service(state, b"CryptSvc", b"Cryptographic Services",
        b"Provides three management services: Catalog Database Service, Protected Root Service, and Key Service.",
        b"%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"TermService", b"Terminal Services",
        b"Allows users to connect interactively to a remote computer.",
        b"%SystemRoot%\\System32\\svchost.exe -k termsvcs",
        start_type::DEMAND_START, service_state::STOPPED);

    add_service(state, b"RemoteRegistry", b"Remote Registry",
        b"Enables remote users to modify registry settings on this computer.",
        b"%SystemRoot%\\System32\\svchost.exe -k regsvc",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"Messenger", b"Messenger",
        b"Transmits net send and Alerter service messages between clients and servers.",
        b"%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        start_type::DISABLED, service_state::STOPPED);

    add_service(state, b"Alerter", b"Alerter",
        b"Notifies selected users and computers of administrative alerts.",
        b"%SystemRoot%\\System32\\svchost.exe -k LocalService",
        start_type::DISABLED, service_state::STOPPED);

    add_service(state, b"TlntSvr", b"Telnet",
        b"Enables a remote user to log on to this computer and run programs.",
        b"%SystemRoot%\\System32\\tlntsvr.exe",
        start_type::DISABLED, service_state::STOPPED);

    add_service(state, b"SharedAccess", b"Windows Firewall/Internet Connection Sharing",
        b"Provides network address translation, addressing, name resolution and/or intrusion prevention services.",
        b"%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        start_type::AUTO_START, service_state::RUNNING);

    add_service(state, b"WZCSVC", b"Wireless Zero Configuration",
        b"Provides automatic configuration for the 802.11 adapters.",
        b"%SystemRoot%\\System32\\svchost.exe -k netsvcs",
        start_type::AUTO_START, service_state::RUNNING);
}

/// Helper to add a service
fn add_service(state: &mut ServicesState, name: &[u8], display: &[u8], desc: &[u8], path: &[u8], start: u32, initial_state: u32) {
    if state.service_count >= MAX_SERVICES {
        return;
    }

    let mut svc = ServiceEntry::new();
    svc.set_name(name);
    svc.set_display_name(display);
    svc.set_description(desc);
    svc.set_binary_path(path);
    svc.start_type = start;
    svc.state = initial_state;
    svc.set_logon_account(b"LocalSystem");

    state.services[state.service_count] = svc;
    state.service_count += 1;
}

// ============================================================================
// Service Enumeration
// ============================================================================

/// Get service count
pub fn get_service_count() -> usize {
    SERVICES_STATE.lock().service_count
}

/// Get service by index
pub fn get_service(index: usize) -> Option<ServiceEntry> {
    let state = SERVICES_STATE.lock();
    if index < state.service_count {
        Some(state.services[index])
    } else {
        None
    }
}

/// Find service by name
pub fn find_service(name: &[u8]) -> Option<usize> {
    let state = SERVICES_STATE.lock();
    for i in 0..state.service_count {
        let svc = &state.services[i];
        if svc.name_len == name.len() && &svc.name[..svc.name_len] == name {
            return Some(i);
        }
    }
    None
}

/// Get services by state
pub fn get_services_by_state(target_state: u32) -> ([usize; 64], usize) {
    let state = SERVICES_STATE.lock();
    let mut indices = [0usize; 64];
    let mut count = 0;

    for i in 0..state.service_count {
        if state.services[i].state == target_state && count < 64 {
            indices[count] = i;
            count += 1;
        }
    }

    (indices, count)
}

/// Get running services count
pub fn get_running_count() -> usize {
    let state = SERVICES_STATE.lock();
    let mut count = 0;
    for i in 0..state.service_count {
        if state.services[i].state == service_state::RUNNING {
            count += 1;
        }
    }
    count
}

// ============================================================================
// Service Control
// ============================================================================

/// Start a service
pub fn start_service(index: usize) -> bool {
    let mut state = SERVICES_STATE.lock();
    if index >= state.service_count {
        return false;
    }

    let svc = &mut state.services[index];

    // Check if already running
    if svc.state == service_state::RUNNING {
        return true;
    }

    // Check if disabled
    if svc.start_type == start_type::DISABLED {
        return false;
    }

    // Simulate starting
    svc.state = service_state::START_PENDING;
    // Would actually start the service process here
    svc.state = service_state::RUNNING;
    svc.process_id = 1000 + index as u32; // Fake PID

    SERVICE_START_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

/// Stop a service
pub fn stop_service(index: usize) -> bool {
    let mut state = SERVICES_STATE.lock();
    if index >= state.service_count {
        return false;
    }

    let svc = &mut state.services[index];

    // Check if already stopped
    if svc.state == service_state::STOPPED {
        return true;
    }

    // Check if accepts stop
    if !svc.accepts_stop {
        return false;
    }

    // Simulate stopping
    svc.state = service_state::STOP_PENDING;
    // Would actually stop the service process here
    svc.state = service_state::STOPPED;
    svc.process_id = 0;

    SERVICE_STOP_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

/// Pause a service
pub fn pause_service(index: usize) -> bool {
    let mut state = SERVICES_STATE.lock();
    if index >= state.service_count {
        return false;
    }

    let svc = &mut state.services[index];

    if svc.state != service_state::RUNNING || !svc.accepts_pause {
        return false;
    }

    svc.state = service_state::PAUSE_PENDING;
    svc.state = service_state::PAUSED;
    true
}

/// Resume a service
pub fn resume_service(index: usize) -> bool {
    let mut state = SERVICES_STATE.lock();
    if index >= state.service_count {
        return false;
    }

    let svc = &mut state.services[index];

    if svc.state != service_state::PAUSED {
        return false;
    }

    svc.state = service_state::CONTINUE_PENDING;
    svc.state = service_state::RUNNING;
    true
}

/// Restart a service
pub fn restart_service(index: usize) -> bool {
    if !stop_service(index) {
        return false;
    }
    start_service(index)
}

// ============================================================================
// Service Configuration
// ============================================================================

/// Set service start type
pub fn set_start_type(index: usize, new_start_type: u32) -> bool {
    let mut state = SERVICES_STATE.lock();
    if index >= state.service_count {
        return false;
    }

    state.services[index].start_type = new_start_type;
    true
}

/// Set service description
pub fn set_description(index: usize, desc: &[u8]) -> bool {
    let mut state = SERVICES_STATE.lock();
    if index >= state.service_count {
        return false;
    }

    state.services[index].set_description(desc);
    true
}

/// Set logon account
pub fn set_logon_account(index: usize, account: &[u8]) -> bool {
    let mut state = SERVICES_STATE.lock();
    if index >= state.service_count {
        return false;
    }

    state.services[index].set_logon_account(account);
    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Services statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ServicesStats {
    pub initialized: bool,
    pub total_services: usize,
    pub running_services: usize,
    pub stopped_services: usize,
    pub paused_services: usize,
    pub start_count: u32,
    pub stop_count: u32,
}

/// Get services statistics
pub fn get_stats() -> ServicesStats {
    let state = SERVICES_STATE.lock();
    let mut running = 0;
    let mut stopped = 0;
    let mut paused = 0;

    for i in 0..state.service_count {
        match state.services[i].state {
            service_state::RUNNING => running += 1,
            service_state::STOPPED => stopped += 1,
            service_state::PAUSED => paused += 1,
            _ => {}
        }
    }

    ServicesStats {
        initialized: SERVICES_INITIALIZED.load(Ordering::Relaxed),
        total_services: state.service_count,
        running_services: running,
        stopped_services: stopped,
        paused_services: paused,
        start_count: SERVICE_START_COUNT.load(Ordering::Relaxed),
        stop_count: SERVICE_STOP_COUNT.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Services dialog handle
pub type HSERVICESDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Services dialog
pub fn create_services_dialog(_parent: super::super::HWND) -> HSERVICESDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}

/// Service properties tab
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServicePropertiesTab {
    /// General tab
    #[default]
    General = 0,
    /// Log On tab
    LogOn = 1,
    /// Recovery tab
    Recovery = 2,
    /// Dependencies tab
    Dependencies = 3,
}

/// Get properties tab count
pub fn get_properties_tab_count() -> u32 {
    4
}

/// Get properties tab name
pub fn get_properties_tab_name(tab: ServicePropertiesTab) -> &'static str {
    match tab {
        ServicePropertiesTab::General => "General",
        ServicePropertiesTab::LogOn => "Log On",
        ServicePropertiesTab::Recovery => "Recovery",
        ServicePropertiesTab::Dependencies => "Dependencies",
    }
}
