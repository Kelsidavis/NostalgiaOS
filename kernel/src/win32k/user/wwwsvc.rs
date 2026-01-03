//! WWW Service Module
//!
//! Windows Server 2003 World Wide Web Service implementation for HTTP hosting.
//! Provides web site management, virtual directory configuration, ISAPI filters,
//! authentication settings, and HTTP compression.

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use crate::win32k::user::UserHandle;

/// Maximum number of web sites
const MAX_WEBSITES: usize = 64;

/// Maximum number of virtual directories
const MAX_VDIRS: usize = 256;

/// Maximum number of ISAPI filters
const MAX_FILTERS: usize = 32;

/// Maximum number of active connections
const MAX_CONNECTIONS: usize = 512;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Maximum host header length
const MAX_HOST_LEN: usize = 253;

/// Maximum MIME type length
const MAX_MIME_LEN: usize = 128;

/// Site state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SiteState {
    /// Site is stopped
    Stopped = 0,
    /// Site is starting
    Starting = 1,
    /// Site is running
    Running = 2,
    /// Site is paused
    Paused = 3,
    /// Site is stopping
    Stopping = 4,
}

impl Default for SiteState {
    fn default() -> Self {
        Self::Stopped
    }
}

/// Authentication type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthType {
    /// Anonymous access
    Anonymous = 0,
    /// Basic authentication
    Basic = 1,
    /// Digest authentication
    Digest = 2,
    /// Integrated Windows authentication
    Windows = 3,
    /// Certificate authentication
    Certificate = 4,
}

impl Default for AuthType {
    fn default() -> Self {
        Self::Anonymous
    }
}

/// Handler type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HandlerType {
    /// Static file
    StaticFile = 0,
    /// ISAPI Extension
    Isapi = 1,
    /// CGI executable
    Cgi = 2,
    /// ASP
    Asp = 3,
    /// ASP.NET
    AspNet = 4,
}

impl Default for HandlerType {
    fn default() -> Self {
        Self::StaticFile
    }
}

bitflags::bitflags! {
    /// Site flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SiteFlags: u32 {
        /// Enable directory browsing
        const DIR_BROWSING = 0x0001;
        /// Enable logging
        const LOGGING = 0x0002;
        /// Enable default document
        const DEFAULT_DOC = 0x0004;
        /// Enable custom errors
        const CUSTOM_ERRORS = 0x0008;
        /// Enable HTTP compression
        const COMPRESSION = 0x0010;
        /// Enable HTTP keep-alive
        const KEEP_ALIVE = 0x0020;
        /// Enable ASP
        const ASP_ENABLED = 0x0040;
        /// Enable ASP.NET
        const ASPNET_ENABLED = 0x0080;
        /// Enable CGI
        const CGI_ENABLED = 0x0100;
        /// Enable ISAPI
        const ISAPI_ENABLED = 0x0200;
        /// Enable SSL
        const SSL_ENABLED = 0x0400;
        /// Require SSL
        const REQUIRE_SSL = 0x0800;
    }
}

impl Default for SiteFlags {
    fn default() -> Self {
        Self::LOGGING | Self::DEFAULT_DOC | Self::KEEP_ALIVE
    }
}

bitflags::bitflags! {
    /// Virtual directory permissions
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VdirAccess: u32 {
        /// Read access
        const READ = 0x0001;
        /// Write access
        const WRITE = 0x0002;
        /// Script execution
        const SCRIPT = 0x0004;
        /// Execute (CGI/ISAPI)
        const EXECUTE = 0x0008;
        /// Source access
        const SOURCE = 0x0010;
    }
}

impl Default for VdirAccess {
    fn default() -> Self {
        Self::READ | Self::SCRIPT
    }
}

/// Web site
#[derive(Debug)]
pub struct WebSite {
    /// Site is active
    active: bool,
    /// Site ID
    id: u32,
    /// Site name
    name: [u8; 64],
    /// Name length
    name_len: usize,
    /// Binding IP address
    ip_address: [u8; 45],
    /// IP length
    ip_len: usize,
    /// Port number
    port: u16,
    /// SSL port
    ssl_port: u16,
    /// Host header
    host_header: [u8; MAX_HOST_LEN],
    /// Host header length
    host_len: usize,
    /// Site state
    state: SiteState,
    /// Site flags
    flags: SiteFlags,
    /// Home directory
    home_dir: [u8; MAX_PATH_LEN],
    /// Home dir length
    home_len: usize,
    /// Application pool ID
    app_pool_id: u32,
    /// Default document
    default_doc: [u8; 64],
    /// Default doc length
    doc_len: usize,
    /// Maximum connections
    max_connections: u32,
    /// Connection timeout (seconds)
    connection_timeout: u32,
    /// Maximum bandwidth (bytes/sec, 0 = unlimited)
    max_bandwidth: u32,
    /// Current connections
    current_connections: u32,
    /// Total requests
    total_requests: u64,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
    /// Handle for management
    handle: UserHandle,
}

impl WebSite {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            name: [0u8; 64],
            name_len: 0,
            ip_address: [0u8; 45],
            ip_len: 0,
            port: 80,
            ssl_port: 443,
            host_header: [0u8; MAX_HOST_LEN],
            host_len: 0,
            state: SiteState::Stopped,
            flags: SiteFlags::empty(),
            home_dir: [0u8; MAX_PATH_LEN],
            home_len: 0,
            app_pool_id: 0,
            default_doc: [0u8; 64],
            doc_len: 0,
            max_connections: 0, // unlimited
            connection_timeout: 120,
            max_bandwidth: 0,
            current_connections: 0,
            total_requests: 0,
            bytes_sent: 0,
            bytes_received: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// Virtual directory
#[derive(Debug)]
pub struct VirtualDir {
    /// Directory is active
    active: bool,
    /// Directory ID
    id: u32,
    /// Parent site ID
    site_id: u32,
    /// Virtual path
    virtual_path: [u8; MAX_PATH_LEN],
    /// Virtual path length
    vpath_len: usize,
    /// Physical path
    physical_path: [u8; MAX_PATH_LEN],
    /// Physical path length
    ppath_len: usize,
    /// Access permissions
    access: VdirAccess,
    /// Application pool ID (0 = inherit)
    app_pool_id: u32,
    /// Default document
    default_doc: [u8; 64],
    /// Default doc length
    doc_len: usize,
    /// Handler type
    handler: HandlerType,
    /// Handle for management
    handle: UserHandle,
}

impl VirtualDir {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            site_id: 0,
            virtual_path: [0u8; MAX_PATH_LEN],
            vpath_len: 0,
            physical_path: [0u8; MAX_PATH_LEN],
            ppath_len: 0,
            access: VdirAccess::empty(),
            app_pool_id: 0,
            default_doc: [0u8; 64],
            doc_len: 0,
            handler: HandlerType::StaticFile,
            handle: UserHandle::NULL,
        }
    }
}

/// ISAPI filter
#[derive(Debug)]
pub struct IsapiFilter {
    /// Filter is active
    active: bool,
    /// Filter ID
    id: u32,
    /// Parent site ID (0 = global)
    site_id: u32,
    /// Filter name
    name: [u8; 64],
    /// Name length
    name_len: usize,
    /// DLL path
    dll_path: [u8; MAX_PATH_LEN],
    /// Path length
    path_len: usize,
    /// Priority (higher = earlier)
    priority: u32,
    /// Filter enabled
    enabled: bool,
    /// Handle for management
    handle: UserHandle,
}

impl IsapiFilter {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            site_id: 0,
            name: [0u8; 64],
            name_len: 0,
            dll_path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            priority: 100,
            enabled: true,
            handle: UserHandle::NULL,
        }
    }
}

/// Active HTTP connection
#[derive(Debug)]
pub struct HttpConnection {
    /// Connection is active
    active: bool,
    /// Connection ID
    id: u32,
    /// Site ID
    site_id: u32,
    /// Client IP
    client_ip: [u8; 45],
    /// IP length
    ip_len: usize,
    /// Client port
    client_port: u16,
    /// Authenticated user
    username: [u8; 64],
    /// Username length
    user_len: usize,
    /// Current request URL
    request_url: [u8; 256],
    /// URL length
    url_len: usize,
    /// Request method (GET, POST, etc.)
    method: [u8; 16],
    /// Method length
    method_len: usize,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
    /// Connect time
    connect_time: u64,
    /// Handle for management
    handle: UserHandle,
}

impl HttpConnection {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            site_id: 0,
            client_ip: [0u8; 45],
            ip_len: 0,
            client_port: 0,
            username: [0u8; 64],
            user_len: 0,
            request_url: [0u8; 256],
            url_len: 0,
            method: [0u8; 16],
            method_len: 0,
            bytes_sent: 0,
            bytes_received: 0,
            connect_time: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// WWW service statistics
#[derive(Debug)]
pub struct WwwStats {
    /// Total sites
    pub total_sites: u32,
    /// Running sites
    pub running_sites: u32,
    /// Total virtual directories
    pub total_vdirs: u32,
    /// Total ISAPI filters
    pub total_filters: u32,
    /// Active connections
    pub active_connections: u32,
    /// Total requests
    pub total_requests: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// GET requests
    pub get_requests: u64,
    /// POST requests
    pub post_requests: u64,
    /// 404 errors
    pub not_found: u64,
    /// 500 errors
    pub server_errors: u64,
}

impl WwwStats {
    pub const fn new() -> Self {
        Self {
            total_sites: 0,
            running_sites: 0,
            total_vdirs: 0,
            total_filters: 0,
            active_connections: 0,
            total_requests: 0,
            bytes_sent: 0,
            bytes_received: 0,
            get_requests: 0,
            post_requests: 0,
            not_found: 0,
            server_errors: 0,
        }
    }
}

/// WWW service state
struct WwwState {
    /// Web sites
    sites: [WebSite; MAX_WEBSITES],
    /// Virtual directories
    vdirs: [VirtualDir; MAX_VDIRS],
    /// ISAPI filters
    filters: [IsapiFilter; MAX_FILTERS],
    /// Connections
    connections: [HttpConnection; MAX_CONNECTIONS],
    /// Statistics
    stats: WwwStats,
    /// Next ID
    next_id: u32,
}

impl WwwState {
    pub const fn new() -> Self {
        Self {
            sites: [const { WebSite::new() }; MAX_WEBSITES],
            vdirs: [const { VirtualDir::new() }; MAX_VDIRS],
            filters: [const { IsapiFilter::new() }; MAX_FILTERS],
            connections: [const { HttpConnection::new() }; MAX_CONNECTIONS],
            stats: WwwStats::new(),
            next_id: 1,
        }
    }
}

/// Global WWW state
static WWW_STATE: Mutex<WwwState> = Mutex::new(WwwState::new());

/// Initialization flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the WWW service module
pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    Ok(())
}

/// Create a new web site
pub fn create_site(
    name: &str,
    ip_address: &str,
    port: u16,
    home_dir: &str,
    flags: SiteFlags,
) -> Result<UserHandle, u32> {
    let mut state = WWW_STATE.lock();

    // Check for binding conflict
    for site in state.sites.iter() {
        if site.active {
            let existing_ip = &site.ip_address[..site.ip_len];
            if existing_ip == ip_address.as_bytes() && site.port == port {
                // Check host header
                if site.host_len == 0 {
                    return Err(0x80070050);
                }
            }
        }
    }

    let slot_idx = state.sites.iter().position(|s| !s.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(64);
    let ip_bytes = ip_address.as_bytes();
    let ip_len = ip_bytes.len().min(45);
    let home_bytes = home_dir.as_bytes();
    let home_len = home_bytes.len().min(MAX_PATH_LEN);

    state.sites[slot_idx].active = true;
    state.sites[slot_idx].id = id;
    state.sites[slot_idx].name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    state.sites[slot_idx].name_len = name_len;
    state.sites[slot_idx].ip_address[..ip_len].copy_from_slice(&ip_bytes[..ip_len]);
    state.sites[slot_idx].ip_len = ip_len;
    state.sites[slot_idx].port = port;
    state.sites[slot_idx].ssl_port = 443;
    state.sites[slot_idx].host_len = 0;
    state.sites[slot_idx].state = SiteState::Stopped;
    state.sites[slot_idx].flags = flags;
    state.sites[slot_idx].home_dir[..home_len].copy_from_slice(&home_bytes[..home_len]);
    state.sites[slot_idx].home_len = home_len;
    state.sites[slot_idx].app_pool_id = 0;
    state.sites[slot_idx].doc_len = 0;
    state.sites[slot_idx].max_connections = 0;
    state.sites[slot_idx].connection_timeout = 120;
    state.sites[slot_idx].max_bandwidth = 0;
    state.sites[slot_idx].current_connections = 0;
    state.sites[slot_idx].total_requests = 0;
    state.sites[slot_idx].bytes_sent = 0;
    state.sites[slot_idx].bytes_received = 0;
    state.sites[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_sites += 1;

    Ok(state.sites[slot_idx].handle)
}

/// Delete a web site
pub fn delete_site(site_id: u32) -> Result<(), u32> {
    let mut state = WWW_STATE.lock();

    let site_idx = state.sites.iter().position(|s| s.active && s.id == site_id);
    let site_idx = match site_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    if state.sites[site_idx].state != SiteState::Stopped {
        return Err(0x80070020);
    }

    // Remove related vdirs and filters
    let mut vdirs_to_remove = 0u32;
    let mut filters_to_remove = 0u32;

    for vdir in state.vdirs.iter() {
        if vdir.active && vdir.site_id == site_id {
            vdirs_to_remove += 1;
        }
    }

    for filter in state.filters.iter() {
        if filter.active && filter.site_id == site_id {
            filters_to_remove += 1;
        }
    }

    for vdir in state.vdirs.iter_mut() {
        if vdir.active && vdir.site_id == site_id {
            vdir.active = false;
        }
    }

    for filter in state.filters.iter_mut() {
        if filter.active && filter.site_id == site_id {
            filter.active = false;
        }
    }

    state.sites[site_idx].active = false;
    state.stats.total_sites = state.stats.total_sites.saturating_sub(1);
    state.stats.total_vdirs = state.stats.total_vdirs.saturating_sub(vdirs_to_remove);
    state.stats.total_filters = state.stats.total_filters.saturating_sub(filters_to_remove);

    Ok(())
}

/// Start a web site
pub fn start_site(site_id: u32) -> Result<(), u32> {
    let mut state = WWW_STATE.lock();

    let site = state.sites.iter_mut().find(|s| s.active && s.id == site_id);
    let site = match site {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    match site.state {
        SiteState::Running => return Ok(()),
        SiteState::Starting | SiteState::Stopping => return Err(0x80070015),
        _ => {}
    }

    site.state = SiteState::Starting;
    site.state = SiteState::Running;
    state.stats.running_sites += 1;

    Ok(())
}

/// Stop a web site
pub fn stop_site(site_id: u32) -> Result<(), u32> {
    let mut state = WWW_STATE.lock();

    let site_idx = state.sites.iter().position(|s| s.active && s.id == site_id);
    let site_idx = match site_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    match state.sites[site_idx].state {
        SiteState::Stopped => return Ok(()),
        SiteState::Starting | SiteState::Stopping => return Err(0x80070015),
        _ => {}
    }

    // Disconnect all connections
    let mut conns_closed = 0u32;
    for conn in state.connections.iter_mut() {
        if conn.active && conn.site_id == site_id {
            conn.active = false;
            conns_closed += 1;
        }
    }

    state.sites[site_idx].state = SiteState::Stopping;
    state.sites[site_idx].state = SiteState::Stopped;
    state.sites[site_idx].current_connections = 0;
    state.stats.running_sites = state.stats.running_sites.saturating_sub(1);
    state.stats.active_connections = state.stats.active_connections.saturating_sub(conns_closed);

    Ok(())
}

/// Add a virtual directory
pub fn add_virtual_directory(
    site_id: u32,
    virtual_path: &str,
    physical_path: &str,
    access: VdirAccess,
) -> Result<UserHandle, u32> {
    let mut state = WWW_STATE.lock();

    let site_exists = state.sites.iter().any(|s| s.active && s.id == site_id);
    if !site_exists {
        return Err(0x80070002);
    }

    // Check for duplicate
    for vdir in state.vdirs.iter() {
        if vdir.active && vdir.site_id == site_id {
            let existing = &vdir.virtual_path[..vdir.vpath_len];
            if existing == virtual_path.as_bytes() {
                return Err(0x80070050);
            }
        }
    }

    let slot_idx = state.vdirs.iter().position(|v| !v.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let vpath_bytes = virtual_path.as_bytes();
    let vpath_len = vpath_bytes.len().min(MAX_PATH_LEN);
    let ppath_bytes = physical_path.as_bytes();
    let ppath_len = ppath_bytes.len().min(MAX_PATH_LEN);

    state.vdirs[slot_idx].active = true;
    state.vdirs[slot_idx].id = id;
    state.vdirs[slot_idx].site_id = site_id;
    state.vdirs[slot_idx].virtual_path[..vpath_len].copy_from_slice(&vpath_bytes[..vpath_len]);
    state.vdirs[slot_idx].vpath_len = vpath_len;
    state.vdirs[slot_idx].physical_path[..ppath_len].copy_from_slice(&ppath_bytes[..ppath_len]);
    state.vdirs[slot_idx].ppath_len = ppath_len;
    state.vdirs[slot_idx].access = access;
    state.vdirs[slot_idx].app_pool_id = 0;
    state.vdirs[slot_idx].doc_len = 0;
    state.vdirs[slot_idx].handler = HandlerType::StaticFile;
    state.vdirs[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_vdirs += 1;

    Ok(state.vdirs[slot_idx].handle)
}

/// Remove a virtual directory
pub fn remove_virtual_directory(vdir_id: u32) -> Result<(), u32> {
    let mut state = WWW_STATE.lock();

    let vdir_idx = state.vdirs.iter().position(|v| v.active && v.id == vdir_id);
    let vdir_idx = match vdir_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    state.vdirs[vdir_idx].active = false;
    state.stats.total_vdirs = state.stats.total_vdirs.saturating_sub(1);

    Ok(())
}

/// Add an ISAPI filter
pub fn add_isapi_filter(
    site_id: u32,
    name: &str,
    dll_path: &str,
    priority: u32,
) -> Result<UserHandle, u32> {
    let mut state = WWW_STATE.lock();

    // Site ID 0 means global filter
    if site_id > 0 {
        let site_exists = state.sites.iter().any(|s| s.active && s.id == site_id);
        if !site_exists {
            return Err(0x80070002);
        }
    }

    let slot_idx = state.filters.iter().position(|f| !f.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(64);
    let path_bytes = dll_path.as_bytes();
    let path_len = path_bytes.len().min(MAX_PATH_LEN);

    state.filters[slot_idx].active = true;
    state.filters[slot_idx].id = id;
    state.filters[slot_idx].site_id = site_id;
    state.filters[slot_idx].name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    state.filters[slot_idx].name_len = name_len;
    state.filters[slot_idx].dll_path[..path_len].copy_from_slice(&path_bytes[..path_len]);
    state.filters[slot_idx].path_len = path_len;
    state.filters[slot_idx].priority = priority;
    state.filters[slot_idx].enabled = true;
    state.filters[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_filters += 1;

    Ok(state.filters[slot_idx].handle)
}

/// Remove an ISAPI filter
pub fn remove_isapi_filter(filter_id: u32) -> Result<(), u32> {
    let mut state = WWW_STATE.lock();

    let filter_idx = state.filters.iter().position(|f| f.active && f.id == filter_id);
    let filter_idx = match filter_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    state.filters[filter_idx].active = false;
    state.stats.total_filters = state.stats.total_filters.saturating_sub(1);

    Ok(())
}

/// Get site information
pub fn get_site_info(site_id: u32) -> Result<(SiteState, u32, u64, u64), u32> {
    let state = WWW_STATE.lock();

    let site = state.sites.iter().find(|s| s.active && s.id == site_id);
    let site = match site {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    Ok((
        site.state,
        site.current_connections,
        site.total_requests,
        site.bytes_sent,
    ))
}

/// Get WWW service statistics
pub fn get_statistics() -> WwwStats {
    let state = WWW_STATE.lock();
    WwwStats {
        total_sites: state.stats.total_sites,
        running_sites: state.stats.running_sites,
        total_vdirs: state.stats.total_vdirs,
        total_filters: state.stats.total_filters,
        active_connections: state.stats.active_connections,
        total_requests: state.stats.total_requests,
        bytes_sent: state.stats.bytes_sent,
        bytes_received: state.stats.bytes_received,
        get_requests: state.stats.get_requests,
        post_requests: state.stats.post_requests,
        not_found: state.stats.not_found,
        server_errors: state.stats.server_errors,
    }
}

/// List all sites
pub fn list_sites() -> [(bool, u32, SiteState); MAX_WEBSITES] {
    let state = WWW_STATE.lock();
    let mut result = [(false, 0u32, SiteState::Stopped); MAX_WEBSITES];

    for (i, site) in state.sites.iter().enumerate() {
        if site.active {
            result[i] = (true, site.id, site.state);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_site_lifecycle() {
        init().unwrap();

        let handle = create_site(
            "Default Web Site",
            "*",
            80,
            "C:\\Inetpub\\wwwroot",
            SiteFlags::default(),
        ).unwrap();
        assert_ne!(handle, UserHandle::NULL);

        start_site(1).unwrap_or(());
        stop_site(1).unwrap_or(());
    }

    #[test]
    fn test_statistics() {
        init().unwrap();

        let stats = get_statistics();
        assert!(stats.total_sites <= MAX_WEBSITES as u32);
    }
}
