//! Internet Information Services Manager
//!
//! Implements IIS Manager following Windows Server 2003.
//! Provides web server, FTP, and SMTP service management.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - inetmgr.exe - Internet Information Services (IIS) Manager
//! - IIS 6.0 architecture
//! - Web Sites, Application Pools, FTP Sites, SMTP Virtual Server

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum web sites
const MAX_SITES: usize = 32;

/// Maximum virtual directories
const MAX_VDIRS: usize = 64;

/// Maximum application pools
const MAX_POOLS: usize = 16;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Maximum name length
const MAX_NAME: usize = 64;

// ============================================================================
// Site State
// ============================================================================

/// Web site state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SiteState {
    /// Starting
    Starting = 0,
    /// Started (Running)
    #[default]
    Started = 1,
    /// Stopping
    Stopping = 2,
    /// Stopped
    Stopped = 3,
    /// Pausing
    Pausing = 4,
    /// Paused
    Paused = 5,
}

impl SiteState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SiteState::Starting => "Starting",
            SiteState::Started => "Started",
            SiteState::Stopping => "Stopping",
            SiteState::Stopped => "Stopped",
            SiteState::Pausing => "Pausing",
            SiteState::Paused => "Paused",
        }
    }
}

// ============================================================================
// Authentication Mode
// ============================================================================

bitflags::bitflags! {
    /// Authentication methods
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AuthMethods: u32 {
        const ANONYMOUS = 0x0001;
        const BASIC = 0x0002;
        const DIGEST = 0x0004;
        const INTEGRATED = 0x0008;
        const PASSPORT = 0x0010;
        const CERTIFICATE = 0x0020;

        const DEFAULT = Self::ANONYMOUS.bits() | Self::INTEGRATED.bits();
    }
}

// ============================================================================
// Web Site
// ============================================================================

/// Web site entry
#[derive(Debug, Clone, Copy)]
pub struct WebSite {
    /// Site ID
    pub site_id: u32,
    /// Site name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Home directory path
    pub home_dir: [u8; MAX_PATH],
    /// Home dir length
    pub home_len: usize,
    /// State
    pub state: SiteState,
    /// IP address (0 = All Unassigned)
    pub ip_address: [u8; 4],
    /// TCP port
    pub port: u16,
    /// Host header
    pub host_header: [u8; MAX_NAME],
    /// Host header length
    pub host_len: usize,
    /// SSL port (0 = disabled)
    pub ssl_port: u16,
    /// Application pool name
    pub app_pool: [u8; MAX_NAME],
    /// App pool name length
    pub pool_len: usize,
    /// Authentication methods
    pub auth_methods: AuthMethods,
    /// Enable default document
    pub default_doc: bool,
    /// Enable directory browsing
    pub dir_browsing: bool,
    /// Log file path
    pub log_path: [u8; MAX_PATH],
    /// Log path length
    pub log_path_len: usize,
    /// Connection timeout (seconds)
    pub timeout: u32,
    /// Maximum bandwidth (0 = unlimited)
    pub max_bandwidth: u32,
    /// Maximum connections (0 = unlimited)
    pub max_connections: u32,
}

impl WebSite {
    pub const fn new() -> Self {
        Self {
            site_id: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            home_dir: [0u8; MAX_PATH],
            home_len: 0,
            state: SiteState::Stopped,
            ip_address: [0; 4],
            port: 80,
            host_header: [0u8; MAX_NAME],
            host_len: 0,
            ssl_port: 0,
            app_pool: [0u8; MAX_NAME],
            pool_len: 0,
            auth_methods: AuthMethods::DEFAULT,
            default_doc: true,
            dir_browsing: false,
            log_path: [0u8; MAX_PATH],
            log_path_len: 0,
            timeout: 120,
            max_bandwidth: 0,
            max_connections: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_home_dir(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_PATH);
        self.home_dir[..len].copy_from_slice(&path[..len]);
        self.home_len = len;
    }

    pub fn set_app_pool(&mut self, pool: &[u8]) {
        let len = pool.len().min(MAX_NAME);
        self.app_pool[..len].copy_from_slice(&pool[..len]);
        self.pool_len = len;
    }
}

impl Default for WebSite {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Virtual Directory
// ============================================================================

/// Virtual directory
#[derive(Debug, Clone, Copy)]
pub struct VirtualDir {
    /// VDir ID
    pub vdir_id: u32,
    /// Parent site ID
    pub site_id: u32,
    /// Virtual path (alias)
    pub virtual_path: [u8; MAX_PATH],
    /// Virtual path length
    pub vpath_len: usize,
    /// Physical path
    pub physical_path: [u8; MAX_PATH],
    /// Physical path length
    pub ppath_len: usize,
    /// Is application
    pub is_application: bool,
    /// Application pool (if is_application)
    pub app_pool: [u8; MAX_NAME],
    /// App pool length
    pub pool_len: usize,
    /// Execute permissions
    pub execute_perms: ExecutePerms,
    /// Access permissions
    pub access_perms: AccessPerms,
}

impl VirtualDir {
    pub const fn new() -> Self {
        Self {
            vdir_id: 0,
            site_id: 0,
            virtual_path: [0u8; MAX_PATH],
            vpath_len: 0,
            physical_path: [0u8; MAX_PATH],
            ppath_len: 0,
            is_application: false,
            app_pool: [0u8; MAX_NAME],
            pool_len: 0,
            execute_perms: ExecutePerms::Scripts,
            access_perms: AccessPerms::READ,
        }
    }

    pub fn set_virtual_path(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_PATH);
        self.virtual_path[..len].copy_from_slice(&path[..len]);
        self.vpath_len = len;
    }

    pub fn set_physical_path(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_PATH);
        self.physical_path[..len].copy_from_slice(&path[..len]);
        self.ppath_len = len;
    }
}

impl Default for VirtualDir {
    fn default() -> Self {
        Self::new()
    }
}

/// Execute permissions
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecutePerms {
    /// None
    None = 0,
    /// Scripts only
    #[default]
    Scripts = 1,
    /// Scripts and Executables
    ScriptsAndExecutables = 2,
}

bitflags::bitflags! {
    /// Access permissions
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AccessPerms: u32 {
        const READ = 0x0001;
        const WRITE = 0x0002;
        const SCRIPT_SOURCE = 0x0004;
        const DIRECTORY_BROWSING = 0x0008;
        const LOG_VISITS = 0x0010;
        const INDEX_RESOURCE = 0x0020;
    }
}

// ============================================================================
// Application Pool
// ============================================================================

/// Application pool
#[derive(Debug, Clone, Copy)]
pub struct AppPool {
    /// Pool ID
    pub pool_id: u32,
    /// Pool name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// State
    pub state: SiteState,
    /// Worker process identity
    pub identity: PoolIdentity,
    /// Custom username (if identity is Custom)
    pub custom_user: [u8; MAX_NAME],
    /// Custom user length
    pub custom_len: usize,
    /// Idle timeout (minutes)
    pub idle_timeout: u32,
    /// Recycle worker process (minutes, 0 = disabled)
    pub recycle_minutes: u32,
    /// Maximum worker processes
    pub max_processes: u32,
    /// Rapid-fail protection enabled
    pub rapid_fail: bool,
    /// Pipeline mode
    pub pipeline_mode: PipelineMode,
}

impl AppPool {
    pub const fn new() -> Self {
        Self {
            pool_id: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            state: SiteState::Started,
            identity: PoolIdentity::NetworkService,
            custom_user: [0u8; MAX_NAME],
            custom_len: 0,
            idle_timeout: 20,
            recycle_minutes: 1740, // 29 hours
            max_processes: 1,
            rapid_fail: true,
            pipeline_mode: PipelineMode::Integrated,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for AppPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Application pool identity
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PoolIdentity {
    /// Local System
    LocalSystem = 0,
    /// Local Service
    LocalService = 1,
    /// Network Service
    #[default]
    NetworkService = 2,
    /// Custom account
    Custom = 3,
}

/// Pipeline mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PipelineMode {
    /// Integrated mode
    #[default]
    Integrated = 0,
    /// Classic mode
    Classic = 1,
}

// ============================================================================
// IIS Manager State
// ============================================================================

/// IIS Manager state
struct IisMgrState {
    /// Web sites
    sites: [WebSite; MAX_SITES],
    /// Site count
    site_count: usize,
    /// Next site ID
    next_site_id: u32,
    /// Virtual directories
    vdirs: [VirtualDir; MAX_VDIRS],
    /// VDir count
    vdir_count: usize,
    /// Next VDir ID
    next_vdir_id: u32,
    /// Application pools
    pools: [AppPool; MAX_POOLS],
    /// Pool count
    pool_count: usize,
    /// Next pool ID
    next_pool_id: u32,
    /// Selected site ID
    selected_site: u32,
    /// Server name
    server_name: [u8; MAX_NAME],
    /// Server name length
    server_len: usize,
}

impl IisMgrState {
    pub const fn new() -> Self {
        Self {
            sites: [const { WebSite::new() }; MAX_SITES],
            site_count: 0,
            next_site_id: 1,
            vdirs: [const { VirtualDir::new() }; MAX_VDIRS],
            vdir_count: 0,
            next_vdir_id: 1,
            pools: [const { AppPool::new() }; MAX_POOLS],
            pool_count: 0,
            next_pool_id: 1,
            selected_site: 0,
            server_name: [0u8; MAX_NAME],
            server_len: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static IIS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static IIS_STATE: SpinLock<IisMgrState> = SpinLock::new(IisMgrState::new());

// Statistics
static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_BYTES_SENT: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize IIS Manager
pub fn init() {
    if IIS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = IIS_STATE.lock();

    // Set server name
    let name = b"localhost";
    let len = name.len().min(MAX_NAME);
    state.server_name[..len].copy_from_slice(&name[..len]);
    state.server_len = len;

    // Create default application pool
    create_default_pools(&mut state);

    // Create default web site
    create_default_site(&mut state);

    crate::serial_println!("[WIN32K] IIS Manager initialized");
}

/// Create default application pools
fn create_default_pools(state: &mut IisMgrState) {
    let pools: [(&[u8], PoolIdentity); 2] = [
        (b"DefaultAppPool", PoolIdentity::NetworkService),
        (b"Classic .NET AppPool", PoolIdentity::NetworkService),
    ];

    for (name, identity) in pools.iter() {
        if state.pool_count >= MAX_POOLS {
            break;
        }
        let mut pool = AppPool::new();
        pool.pool_id = state.next_pool_id;
        state.next_pool_id += 1;
        pool.set_name(name);
        pool.identity = *identity;
        pool.state = SiteState::Started;

        let idx = state.pool_count;
        state.pools[idx] = pool;
        state.pool_count += 1;
    }
}

/// Create default web site
fn create_default_site(state: &mut IisMgrState) {
    if state.site_count >= MAX_SITES {
        return;
    }

    let mut site = WebSite::new();
    site.site_id = state.next_site_id;
    state.next_site_id += 1;
    site.set_name(b"Default Web Site");
    site.set_home_dir(b"C:\\Inetpub\\wwwroot");
    site.port = 80;
    site.set_app_pool(b"DefaultAppPool");
    site.state = SiteState::Started;
    site.default_doc = true;

    // Set log path
    let log = b"C:\\WINDOWS\\system32\\LogFiles\\W3SVC1";
    let llen = log.len().min(MAX_PATH);
    site.log_path[..llen].copy_from_slice(&log[..llen]);
    site.log_path_len = llen;

    state.sites[0] = site;
    state.site_count = 1;
    state.selected_site = site.site_id;
}

// ============================================================================
// Web Site Management
// ============================================================================

/// Get site count
pub fn get_site_count() -> usize {
    IIS_STATE.lock().site_count
}

/// Get site by index
pub fn get_site(index: usize) -> Option<WebSite> {
    let state = IIS_STATE.lock();
    if index < state.site_count {
        Some(state.sites[index])
    } else {
        None
    }
}

/// Get site by ID
pub fn get_site_by_id(site_id: u32) -> Option<WebSite> {
    let state = IIS_STATE.lock();
    for i in 0..state.site_count {
        if state.sites[i].site_id == site_id {
            return Some(state.sites[i]);
        }
    }
    None
}

/// Create web site
pub fn create_site(name: &[u8], home_dir: &[u8], port: u16) -> Option<u32> {
    let mut state = IIS_STATE.lock();

    if state.site_count >= MAX_SITES {
        return None;
    }

    let site_id = state.next_site_id;
    state.next_site_id += 1;

    let mut site = WebSite::new();
    site.site_id = site_id;
    site.set_name(name);
    site.set_home_dir(home_dir);
    site.port = port;
    site.set_app_pool(b"DefaultAppPool");

    let idx = state.site_count;
    state.sites[idx] = site;
    state.site_count += 1;

    Some(site_id)
}

/// Delete web site
pub fn delete_site(site_id: u32) -> bool {
    let mut state = IIS_STATE.lock();

    let mut found_index = None;
    for i in 0..state.site_count {
        if state.sites[i].site_id == site_id {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        // Remove associated virtual directories
        let mut i = 0;
        while i < state.vdir_count {
            if state.vdirs[i].site_id == site_id {
                for j in i..state.vdir_count - 1 {
                    state.vdirs[j] = state.vdirs[j + 1];
                }
                state.vdir_count -= 1;
            } else {
                i += 1;
            }
        }

        // Remove site
        for i in index..state.site_count - 1 {
            state.sites[i] = state.sites[i + 1];
        }
        state.site_count -= 1;
        true
    } else {
        false
    }
}

/// Start web site
pub fn start_site(site_id: u32) -> bool {
    let mut state = IIS_STATE.lock();
    for i in 0..state.site_count {
        if state.sites[i].site_id == site_id {
            state.sites[i].state = SiteState::Started;
            return true;
        }
    }
    false
}

/// Stop web site
pub fn stop_site(site_id: u32) -> bool {
    let mut state = IIS_STATE.lock();
    for i in 0..state.site_count {
        if state.sites[i].site_id == site_id {
            state.sites[i].state = SiteState::Stopped;
            return true;
        }
    }
    false
}

/// Select site
pub fn select_site(site_id: u32) {
    IIS_STATE.lock().selected_site = site_id;
}

/// Get selected site
pub fn get_selected_site() -> u32 {
    IIS_STATE.lock().selected_site
}

// ============================================================================
// Application Pool Management
// ============================================================================

/// Get pool count
pub fn get_pool_count() -> usize {
    IIS_STATE.lock().pool_count
}

/// Get pool by index
pub fn get_pool(index: usize) -> Option<AppPool> {
    let state = IIS_STATE.lock();
    if index < state.pool_count {
        Some(state.pools[index])
    } else {
        None
    }
}

/// Create application pool
pub fn create_pool(name: &[u8]) -> Option<u32> {
    let mut state = IIS_STATE.lock();

    if state.pool_count >= MAX_POOLS {
        return None;
    }

    let pool_id = state.next_pool_id;
    state.next_pool_id += 1;

    let mut pool = AppPool::new();
    pool.pool_id = pool_id;
    pool.set_name(name);

    let idx = state.pool_count;
    state.pools[idx] = pool;
    state.pool_count += 1;

    Some(pool_id)
}

/// Delete application pool
pub fn delete_pool(pool_id: u32) -> bool {
    let mut state = IIS_STATE.lock();

    let mut found_index = None;
    for i in 0..state.pool_count {
        if state.pools[i].pool_id == pool_id {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..state.pool_count - 1 {
            state.pools[i] = state.pools[i + 1];
        }
        state.pool_count -= 1;
        true
    } else {
        false
    }
}

/// Start application pool
pub fn start_pool(pool_id: u32) -> bool {
    let mut state = IIS_STATE.lock();
    for i in 0..state.pool_count {
        if state.pools[i].pool_id == pool_id {
            state.pools[i].state = SiteState::Started;
            return true;
        }
    }
    false
}

/// Stop application pool
pub fn stop_pool(pool_id: u32) -> bool {
    let mut state = IIS_STATE.lock();
    for i in 0..state.pool_count {
        if state.pools[i].pool_id == pool_id {
            state.pools[i].state = SiteState::Stopped;
            return true;
        }
    }
    false
}

/// Recycle application pool
pub fn recycle_pool(pool_id: u32) -> bool {
    let state = IIS_STATE.lock();
    for i in 0..state.pool_count {
        if state.pools[i].pool_id == pool_id {
            // Would trigger worker process recycle
            return true;
        }
    }
    false
}

// ============================================================================
// Virtual Directory Management
// ============================================================================

/// Get virtual directory count for site
pub fn get_vdir_count(site_id: u32) -> usize {
    let state = IIS_STATE.lock();
    state.vdirs[..state.vdir_count].iter().filter(|v| v.site_id == site_id).count()
}

/// Get virtual directories for site
pub fn get_vdirs(site_id: u32, buffer: &mut [VirtualDir]) -> usize {
    let state = IIS_STATE.lock();
    let mut count = 0;
    for i in 0..state.vdir_count {
        if state.vdirs[i].site_id == site_id {
            if count < buffer.len() {
                buffer[count] = state.vdirs[i];
                count += 1;
            }
        }
    }
    count
}

/// Create virtual directory
pub fn create_vdir(site_id: u32, virtual_path: &[u8], physical_path: &[u8]) -> Option<u32> {
    let mut state = IIS_STATE.lock();

    if state.vdir_count >= MAX_VDIRS {
        return None;
    }

    let vdir_id = state.next_vdir_id;
    state.next_vdir_id += 1;

    let mut vdir = VirtualDir::new();
    vdir.vdir_id = vdir_id;
    vdir.site_id = site_id;
    vdir.set_virtual_path(virtual_path);
    vdir.set_physical_path(physical_path);

    let idx = state.vdir_count;
    state.vdirs[idx] = vdir;
    state.vdir_count += 1;

    Some(vdir_id)
}

// ============================================================================
// Statistics
// ============================================================================

/// IIS Manager statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct IisMgrStats {
    pub initialized: bool,
    pub site_count: usize,
    pub pool_count: usize,
    pub vdir_count: usize,
    pub running_sites: usize,
    pub running_pools: usize,
    pub total_requests: u64,
    pub total_bytes_sent: u64,
}

/// Get IIS Manager statistics
pub fn get_stats() -> IisMgrStats {
    let state = IIS_STATE.lock();
    let running_sites = state.sites[..state.site_count].iter().filter(|s| s.state == SiteState::Started).count();
    let running_pools = state.pools[..state.pool_count].iter().filter(|p| p.state == SiteState::Started).count();
    IisMgrStats {
        initialized: IIS_INITIALIZED.load(Ordering::Relaxed),
        site_count: state.site_count,
        pool_count: state.pool_count,
        vdir_count: state.vdir_count,
        running_sites,
        running_pools,
        total_requests: TOTAL_REQUESTS.load(Ordering::Relaxed),
        total_bytes_sent: TOTAL_BYTES_SENT.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// IIS Manager dialog handle
pub type HIISMGRDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create IIS Manager dialog
pub fn create_iismgr_dialog(_parent: super::super::HWND) -> HIISMGRDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
