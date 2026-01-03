//! Windows Firewall Control Panel
//!
//! Implements the Windows Firewall settings dialog following Windows Server 2003.
//! Provides network protection, exception rules, and logging configuration.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - Windows Firewall/Internet Connection Sharing (ICS) service
//! - netsh firewall commands
//! - firewall.cpl control panel applet

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum firewall rules
const MAX_RULES: usize = 256;

/// Maximum exceptions
const MAX_EXCEPTIONS: usize = 64;

/// Maximum program exceptions
const MAX_PROGRAM_EXCEPTIONS: usize = 64;

/// Maximum port exceptions
const MAX_PORT_EXCEPTIONS: usize = 64;

/// Maximum name length
const MAX_NAME: usize = 64;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Maximum description length
const MAX_DESC: usize = 256;

// ============================================================================
// Firewall Profile Type
// ============================================================================

/// Firewall profile type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FirewallProfile {
    /// Domain profile (connected to domain network)
    #[default]
    Domain = 0,
    /// Standard profile (connected to other networks)
    Standard = 1,
    /// Current profile
    Current = 2,
}

// ============================================================================
// Firewall Action
// ============================================================================

/// Firewall rule action
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FirewallAction {
    /// Allow the connection
    #[default]
    Allow = 0,
    /// Block the connection
    Block = 1,
}

// ============================================================================
// Protocol Type
// ============================================================================

/// Network protocol
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    /// Any protocol
    #[default]
    Any = 0,
    /// TCP protocol
    Tcp = 6,
    /// UDP protocol
    Udp = 17,
    /// ICMP protocol
    Icmp = 1,
}

// ============================================================================
// Scope Type
// ============================================================================

/// Rule scope
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleScope {
    /// All computers
    #[default]
    All = 0,
    /// Local subnet only
    LocalSubnet = 1,
    /// Custom IP list
    Custom = 2,
}

// ============================================================================
// Firewall Settings
// ============================================================================

/// Firewall profile settings
#[derive(Debug, Clone, Copy)]
pub struct ProfileSettings {
    /// Firewall enabled
    pub enabled: bool,
    /// Don't allow exceptions
    pub no_exceptions: bool,
    /// Display notification on blocked connections
    pub notifications: bool,
    /// Allow unicast response to multicast/broadcast
    pub unicast_response: bool,
}

impl ProfileSettings {
    pub const fn new() -> Self {
        Self {
            enabled: true,
            no_exceptions: false,
            notifications: true,
            unicast_response: true,
        }
    }
}

impl Default for ProfileSettings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Logging Settings
// ============================================================================

/// Firewall logging settings
#[derive(Debug, Clone, Copy)]
pub struct LoggingSettings {
    /// Log dropped packets
    pub log_dropped: bool,
    /// Log successful connections
    pub log_success: bool,
    /// Log file path (as bytes)
    pub log_path: [u8; MAX_PATH],
    /// Log file path length
    pub log_path_len: usize,
    /// Maximum log file size in KB
    pub max_size_kb: u32,
}

impl LoggingSettings {
    pub const fn new() -> Self {
        // Default path: %systemroot%\pfirewall.log
        let mut path = [0u8; MAX_PATH];
        let default_path = b"C:\\Windows\\pfirewall.log";
        let mut i = 0;
        while i < default_path.len() {
            path[i] = default_path[i];
            i += 1;
        }
        Self {
            log_dropped: false,
            log_success: false,
            log_path: path,
            log_path_len: default_path.len(),
            max_size_kb: 4096,
        }
    }
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ICMP Settings
// ============================================================================

/// ICMP settings (what types are allowed)
#[derive(Debug, Clone, Copy)]
pub struct IcmpSettings {
    /// Allow incoming echo request (ping)
    pub allow_echo_request: bool,
    /// Allow incoming timestamp request
    pub allow_timestamp: bool,
    /// Allow incoming mask request
    pub allow_mask_request: bool,
    /// Allow incoming router request
    pub allow_router_request: bool,
    /// Allow outgoing destination unreachable
    pub allow_dest_unreachable: bool,
    /// Allow outgoing source quench
    pub allow_source_quench: bool,
    /// Allow redirect
    pub allow_redirect: bool,
    /// Allow outgoing time exceeded
    pub allow_time_exceeded: bool,
    /// Allow outgoing parameter problem
    pub allow_param_problem: bool,
}

impl IcmpSettings {
    pub const fn new() -> Self {
        Self {
            allow_echo_request: false,
            allow_timestamp: false,
            allow_mask_request: false,
            allow_router_request: false,
            allow_dest_unreachable: true,
            allow_source_quench: false,
            allow_redirect: false,
            allow_time_exceeded: true,
            allow_param_problem: true,
        }
    }
}

impl Default for IcmpSettings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Program Exception
// ============================================================================

/// Program exception entry
#[derive(Debug, Clone, Copy)]
pub struct ProgramException {
    /// Program name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Program path
    pub path: [u8; MAX_PATH],
    /// Path length
    pub path_len: usize,
    /// Exception enabled
    pub enabled: bool,
    /// Rule scope
    pub scope: RuleScope,
    /// Custom addresses (for Custom scope)
    pub custom_addresses: [u8; MAX_DESC],
    /// Custom addresses length
    pub custom_len: usize,
}

impl ProgramException {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            path: [0u8; MAX_PATH],
            path_len: 0,
            enabled: true,
            scope: RuleScope::All,
            custom_addresses: [0u8; MAX_DESC],
            custom_len: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_PATH);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }
}

impl Default for ProgramException {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Port Exception
// ============================================================================

/// Port exception entry
#[derive(Debug, Clone, Copy)]
pub struct PortException {
    /// Exception name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Port number
    pub port: u16,
    /// Protocol (TCP or UDP)
    pub protocol: Protocol,
    /// Exception enabled
    pub enabled: bool,
    /// Rule scope
    pub scope: RuleScope,
    /// Custom addresses (for Custom scope)
    pub custom_addresses: [u8; MAX_DESC],
    /// Custom addresses length
    pub custom_len: usize,
}

impl PortException {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            port: 0,
            protocol: Protocol::Tcp,
            enabled: true,
            scope: RuleScope::All,
            custom_addresses: [0u8; MAX_DESC],
            custom_len: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for PortException {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Built-in Service Exceptions
// ============================================================================

/// Built-in service that can be allowed
#[derive(Debug, Clone, Copy)]
pub struct ServiceException {
    /// Service name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC],
    /// Description length
    pub desc_len: usize,
    /// Service enabled
    pub enabled: bool,
    /// Rule scope
    pub scope: RuleScope,
}

impl ServiceException {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            description: [0u8; MAX_DESC],
            desc_len: 0,
            enabled: false,
            scope: RuleScope::LocalSubnet,
        }
    }

    pub const fn with_info(name: &[u8], desc: &[u8]) -> Self {
        let mut svc = Self::new();
        let mut i = 0;
        while i < name.len() && i < MAX_NAME {
            svc.name[i] = name[i];
            i += 1;
        }
        svc.name_len = i;
        i = 0;
        while i < desc.len() && i < MAX_DESC {
            svc.description[i] = desc[i];
            i += 1;
        }
        svc.desc_len = i;
        svc
    }
}

impl Default for ServiceException {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Firewall State
// ============================================================================

/// Global firewall state
struct FirewallState {
    /// Domain profile settings
    domain_profile: ProfileSettings,
    /// Standard profile settings
    standard_profile: ProfileSettings,
    /// Current profile type
    current_profile: FirewallProfile,
    /// Logging settings
    logging: LoggingSettings,
    /// ICMP settings
    icmp: IcmpSettings,
    /// Program exceptions
    program_exceptions: [ProgramException; MAX_PROGRAM_EXCEPTIONS],
    /// Number of program exceptions
    program_count: usize,
    /// Port exceptions
    port_exceptions: [PortException; MAX_PORT_EXCEPTIONS],
    /// Number of port exceptions
    port_count: usize,
    /// Built-in service exceptions
    services: [ServiceException; 8],
}

impl FirewallState {
    pub const fn new() -> Self {
        Self {
            domain_profile: ProfileSettings::new(),
            standard_profile: ProfileSettings::new(),
            current_profile: FirewallProfile::Standard,
            logging: LoggingSettings::new(),
            icmp: IcmpSettings::new(),
            program_exceptions: [const { ProgramException::new() }; MAX_PROGRAM_EXCEPTIONS],
            program_count: 0,
            port_exceptions: [const { PortException::new() }; MAX_PORT_EXCEPTIONS],
            port_count: 0,
            services: [
                ServiceException::with_info(b"File and Printer Sharing", b"Allows file and printer sharing over the network"),
                ServiceException::with_info(b"Remote Desktop", b"Allows remote connections to this computer"),
                ServiceException::with_info(b"Remote Assistance", b"Allows Remote Assistance invitations"),
                ServiceException::with_info(b"UPnP Framework", b"Allows Universal Plug and Play"),
                ServiceException::with_info(b"Network Discovery", b"Allows network discovery"),
                ServiceException::with_info(b"ICMP (Ping)", b"Allows ICMP echo requests"),
                ServiceException::with_info(b"Remote Administration", b"Allows remote administration"),
                ServiceException::with_info(b"Web Server (HTTP)", b"Allows incoming HTTP connections"),
            ],
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static FIREWALL_INITIALIZED: AtomicBool = AtomicBool::new(false);
static FIREWALL_STATE: SpinLock<FirewallState> = SpinLock::new(FirewallState::new());

// Statistics
static BLOCKED_CONNECTIONS: AtomicU32 = AtomicU32::new(0);
static ALLOWED_CONNECTIONS: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Windows Firewall
pub fn init() {
    if FIREWALL_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = FIREWALL_STATE.lock();

    // Add default program exceptions
    add_default_program_exceptions(&mut state);

    // Add default port exceptions
    add_default_port_exceptions(&mut state);

    crate::serial_println!("[WIN32K] Windows Firewall initialized");
}

/// Add default program exceptions
fn add_default_program_exceptions(state: &mut FirewallState) {
    let defaults: [(&[u8], &[u8]); 4] = [
        (b"Windows Messenger", b"%ProgramFiles%\\Messenger\\msmsgs.exe"),
        (b"Remote Assistance", b"%SystemRoot%\\system32\\sessmgr.exe"),
        (b"Windows Media Player", b"%ProgramFiles%\\Windows Media Player\\wmplayer.exe"),
        (b"NetMeeting", b"%ProgramFiles%\\NetMeeting\\conf.exe"),
    ];

    for (name, path) in defaults.iter() {
        if state.program_count >= MAX_PROGRAM_EXCEPTIONS {
            break;
        }
        let mut exc = ProgramException::new();
        exc.set_name(name);
        exc.set_path(path);
        exc.enabled = false; // Disabled by default
        state.program_exceptions[state.program_count] = exc;
        state.program_count += 1;
    }
}

/// Add default port exceptions
fn add_default_port_exceptions(state: &mut FirewallState) {
    let defaults: [(&[u8], u16, Protocol); 6] = [
        (b"HTTP", 80, Protocol::Tcp),
        (b"HTTPS", 443, Protocol::Tcp),
        (b"FTP", 21, Protocol::Tcp),
        (b"SSH", 22, Protocol::Tcp),
        (b"RDP", 3389, Protocol::Tcp),
        (b"DNS", 53, Protocol::Udp),
    ];

    for (name, port, proto) in defaults.iter() {
        if state.port_count >= MAX_PORT_EXCEPTIONS {
            break;
        }
        let mut exc = PortException::new();
        exc.set_name(name);
        exc.port = *port;
        exc.protocol = *proto;
        exc.enabled = false; // Disabled by default
        state.port_exceptions[state.port_count] = exc;
        state.port_count += 1;
    }
}

// ============================================================================
// Firewall Enable/Disable
// ============================================================================

/// Enable or disable firewall for a profile
pub fn set_firewall_enabled(profile: FirewallProfile, enabled: bool) -> bool {
    let mut state = FIREWALL_STATE.lock();

    match profile {
        FirewallProfile::Domain => state.domain_profile.enabled = enabled,
        FirewallProfile::Standard => state.standard_profile.enabled = enabled,
        FirewallProfile::Current => {
            match state.current_profile {
                FirewallProfile::Domain => state.domain_profile.enabled = enabled,
                FirewallProfile::Standard => state.standard_profile.enabled = enabled,
                _ => {}
            }
        }
    }

    true
}

/// Check if firewall is enabled
pub fn is_firewall_enabled(profile: FirewallProfile) -> bool {
    let state = FIREWALL_STATE.lock();

    match profile {
        FirewallProfile::Domain => state.domain_profile.enabled,
        FirewallProfile::Standard => state.standard_profile.enabled,
        FirewallProfile::Current => {
            match state.current_profile {
                FirewallProfile::Domain => state.domain_profile.enabled,
                FirewallProfile::Standard => state.standard_profile.enabled,
                _ => state.standard_profile.enabled,
            }
        }
    }
}

/// Get current profile type
pub fn get_current_profile() -> FirewallProfile {
    FIREWALL_STATE.lock().current_profile
}

/// Set current profile type
pub fn set_current_profile(profile: FirewallProfile) {
    FIREWALL_STATE.lock().current_profile = profile;
}

// ============================================================================
// Exception Settings
// ============================================================================

/// Set "no exceptions" mode (block all)
pub fn set_no_exceptions(profile: FirewallProfile, no_exceptions: bool) -> bool {
    let mut state = FIREWALL_STATE.lock();

    match profile {
        FirewallProfile::Domain => state.domain_profile.no_exceptions = no_exceptions,
        FirewallProfile::Standard => state.standard_profile.no_exceptions = no_exceptions,
        FirewallProfile::Current => {
            match state.current_profile {
                FirewallProfile::Domain => state.domain_profile.no_exceptions = no_exceptions,
                FirewallProfile::Standard => state.standard_profile.no_exceptions = no_exceptions,
                _ => {}
            }
        }
    }

    true
}

/// Set notification on blocked connections
pub fn set_notifications(profile: FirewallProfile, enabled: bool) -> bool {
    let mut state = FIREWALL_STATE.lock();

    match profile {
        FirewallProfile::Domain => state.domain_profile.notifications = enabled,
        FirewallProfile::Standard => state.standard_profile.notifications = enabled,
        FirewallProfile::Current => {
            match state.current_profile {
                FirewallProfile::Domain => state.domain_profile.notifications = enabled,
                FirewallProfile::Standard => state.standard_profile.notifications = enabled,
                _ => {}
            }
        }
    }

    true
}

// ============================================================================
// Program Exceptions
// ============================================================================

/// Add a program exception
pub fn add_program_exception(name: &[u8], path: &[u8], enabled: bool) -> bool {
    let mut state = FIREWALL_STATE.lock();

    if state.program_count >= MAX_PROGRAM_EXCEPTIONS {
        return false;
    }

    let mut exc = ProgramException::new();
    exc.set_name(name);
    exc.set_path(path);
    exc.enabled = enabled;

    let idx = state.program_count;
    state.program_exceptions[idx] = exc;
    state.program_count += 1;

    true
}

/// Remove a program exception by index
pub fn remove_program_exception(index: usize) -> bool {
    let mut state = FIREWALL_STATE.lock();

    if index >= state.program_count {
        return false;
    }

    // Shift remaining exceptions
    for i in index..state.program_count - 1 {
        state.program_exceptions[i] = state.program_exceptions[i + 1];
    }
    state.program_count -= 1;

    true
}

/// Enable/disable a program exception
pub fn set_program_exception_enabled(index: usize, enabled: bool) -> bool {
    let mut state = FIREWALL_STATE.lock();

    if index >= state.program_count {
        return false;
    }

    state.program_exceptions[index].enabled = enabled;
    true
}

/// Get program exception count
pub fn get_program_exception_count() -> usize {
    FIREWALL_STATE.lock().program_count
}

/// Get program exception by index
pub fn get_program_exception(index: usize) -> Option<ProgramException> {
    let state = FIREWALL_STATE.lock();
    if index < state.program_count {
        Some(state.program_exceptions[index])
    } else {
        None
    }
}

// ============================================================================
// Port Exceptions
// ============================================================================

/// Add a port exception
pub fn add_port_exception(name: &[u8], port: u16, protocol: Protocol, enabled: bool) -> bool {
    let mut state = FIREWALL_STATE.lock();

    if state.port_count >= MAX_PORT_EXCEPTIONS {
        return false;
    }

    let mut exc = PortException::new();
    exc.set_name(name);
    exc.port = port;
    exc.protocol = protocol;
    exc.enabled = enabled;

    let idx = state.port_count;
    state.port_exceptions[idx] = exc;
    state.port_count += 1;

    true
}

/// Remove a port exception by index
pub fn remove_port_exception(index: usize) -> bool {
    let mut state = FIREWALL_STATE.lock();

    if index >= state.port_count {
        return false;
    }

    // Shift remaining exceptions
    for i in index..state.port_count - 1 {
        state.port_exceptions[i] = state.port_exceptions[i + 1];
    }
    state.port_count -= 1;

    true
}

/// Enable/disable a port exception
pub fn set_port_exception_enabled(index: usize, enabled: bool) -> bool {
    let mut state = FIREWALL_STATE.lock();

    if index >= state.port_count {
        return false;
    }

    state.port_exceptions[index].enabled = enabled;
    true
}

/// Get port exception count
pub fn get_port_exception_count() -> usize {
    FIREWALL_STATE.lock().port_count
}

/// Get port exception by index
pub fn get_port_exception(index: usize) -> Option<PortException> {
    let state = FIREWALL_STATE.lock();
    if index < state.port_count {
        Some(state.port_exceptions[index])
    } else {
        None
    }
}

// ============================================================================
// Service Exceptions
// ============================================================================

/// Enable/disable a built-in service exception
pub fn set_service_enabled(index: usize, enabled: bool) -> bool {
    let mut state = FIREWALL_STATE.lock();

    if index >= state.services.len() {
        return false;
    }

    state.services[index].enabled = enabled;
    true
}

/// Set service scope
pub fn set_service_scope(index: usize, scope: RuleScope) -> bool {
    let mut state = FIREWALL_STATE.lock();

    if index >= state.services.len() {
        return false;
    }

    state.services[index].scope = scope;
    true
}

/// Get service count
pub fn get_service_count() -> usize {
    FIREWALL_STATE.lock().services.len()
}

/// Get service by index
pub fn get_service(index: usize) -> Option<ServiceException> {
    let state = FIREWALL_STATE.lock();
    if index < state.services.len() {
        Some(state.services[index])
    } else {
        None
    }
}

// ============================================================================
// ICMP Settings
// ============================================================================

/// Get ICMP settings
pub fn get_icmp_settings() -> IcmpSettings {
    FIREWALL_STATE.lock().icmp
}

/// Set ICMP settings
pub fn set_icmp_settings(settings: IcmpSettings) {
    FIREWALL_STATE.lock().icmp = settings;
}

/// Allow/deny ICMP echo request (ping)
pub fn set_allow_ping(allow: bool) {
    FIREWALL_STATE.lock().icmp.allow_echo_request = allow;
}

/// Check if ping is allowed
pub fn is_ping_allowed() -> bool {
    FIREWALL_STATE.lock().icmp.allow_echo_request
}

// ============================================================================
// Logging Settings
// ============================================================================

/// Get logging settings
pub fn get_logging_settings() -> LoggingSettings {
    FIREWALL_STATE.lock().logging
}

/// Set logging settings
pub fn set_logging_settings(settings: LoggingSettings) {
    FIREWALL_STATE.lock().logging = settings;
}

/// Enable/disable dropped packet logging
pub fn set_log_dropped(enabled: bool) {
    FIREWALL_STATE.lock().logging.log_dropped = enabled;
}

/// Enable/disable successful connection logging
pub fn set_log_success(enabled: bool) {
    FIREWALL_STATE.lock().logging.log_success = enabled;
}

/// Set log file path
pub fn set_log_path(path: &[u8]) -> bool {
    let mut state = FIREWALL_STATE.lock();
    let len = path.len().min(MAX_PATH);
    state.logging.log_path[..len].copy_from_slice(&path[..len]);
    state.logging.log_path_len = len;
    true
}

/// Set maximum log file size
pub fn set_log_max_size(size_kb: u32) {
    FIREWALL_STATE.lock().logging.max_size_kb = size_kb;
}

// ============================================================================
// Connection Filtering (Simulation)
// ============================================================================

/// Check if a connection should be allowed
pub fn check_connection(
    protocol: Protocol,
    local_port: u16,
    _remote_port: u16,
    _remote_addr: [u8; 4],
    is_inbound: bool,
) -> bool {
    let state = FIREWALL_STATE.lock();

    // Get current profile settings
    let profile_settings = match state.current_profile {
        FirewallProfile::Domain => &state.domain_profile,
        FirewallProfile::Standard => &state.standard_profile,
        _ => &state.standard_profile,
    };

    // If firewall is disabled, allow all
    if !profile_settings.enabled {
        ALLOWED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        return true;
    }

    // If no exceptions mode, block inbound
    if profile_settings.no_exceptions && is_inbound {
        BLOCKED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    // Check port exceptions for inbound
    if is_inbound {
        for i in 0..state.port_count {
            let exc = &state.port_exceptions[i];
            if exc.enabled && exc.port == local_port && (exc.protocol == protocol || exc.protocol == Protocol::Any) {
                ALLOWED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }

        // Check service exceptions
        // Service 0: File and Printer Sharing (ports 137-139, 445)
        if state.services[0].enabled {
            if matches!(local_port, 137..=139 | 445) {
                ALLOWED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }

        // Service 1: Remote Desktop (port 3389)
        if state.services[1].enabled && local_port == 3389 {
            ALLOWED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        // Service 7: HTTP (port 80)
        if state.services[7].enabled && local_port == 80 {
            ALLOWED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        // Block unknown inbound
        BLOCKED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    // Allow outbound by default
    ALLOWED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    true
}

/// Record a blocked connection
pub fn record_blocked_connection() {
    BLOCKED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
}

/// Record an allowed connection
pub fn record_allowed_connection() {
    ALLOWED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// Statistics
// ============================================================================

/// Firewall statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct FirewallStats {
    pub initialized: bool,
    pub enabled: bool,
    pub current_profile: FirewallProfile,
    pub program_exception_count: usize,
    pub port_exception_count: usize,
    pub blocked_connections: u32,
    pub allowed_connections: u32,
}

/// Get firewall statistics
pub fn get_stats() -> FirewallStats {
    let state = FIREWALL_STATE.lock();
    let enabled = match state.current_profile {
        FirewallProfile::Domain => state.domain_profile.enabled,
        FirewallProfile::Standard => state.standard_profile.enabled,
        _ => state.standard_profile.enabled,
    };

    FirewallStats {
        initialized: FIREWALL_INITIALIZED.load(Ordering::Relaxed),
        enabled,
        current_profile: state.current_profile,
        program_exception_count: state.program_count,
        port_exception_count: state.port_count,
        blocked_connections: BLOCKED_CONNECTIONS.load(Ordering::Relaxed),
        allowed_connections: ALLOWED_CONNECTIONS.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Firewall dialog handle
pub type HFIREWALLDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create firewall settings dialog
pub fn create_firewall_dialog(_parent: super::super::HWND) -> HFIREWALLDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}

/// Firewall dialog tab
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FirewallTab {
    /// General settings
    #[default]
    General = 0,
    /// Exceptions
    Exceptions = 1,
    /// Advanced settings
    Advanced = 2,
}

/// Get firewall dialog tab count
pub fn get_tab_count() -> u32 {
    3
}

/// Get tab name
pub fn get_tab_name(tab: FirewallTab) -> &'static str {
    match tab {
        FirewallTab::General => "General",
        FirewallTab::Exceptions => "Exceptions",
        FirewallTab::Advanced => "Advanced",
    }
}

// ============================================================================
// Restore Defaults
// ============================================================================

/// Restore firewall to default settings
pub fn restore_defaults() {
    let mut state = FIREWALL_STATE.lock();

    // Reset profile settings
    state.domain_profile = ProfileSettings::new();
    state.standard_profile = ProfileSettings::new();

    // Reset logging
    state.logging = LoggingSettings::new();

    // Reset ICMP
    state.icmp = IcmpSettings::new();

    // Disable all exceptions
    for i in 0..state.program_count {
        state.program_exceptions[i].enabled = false;
    }
    for i in 0..state.port_count {
        state.port_exceptions[i].enabled = false;
    }
    for svc in state.services.iter_mut() {
        svc.enabled = false;
    }
}
