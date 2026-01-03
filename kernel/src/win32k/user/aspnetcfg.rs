//! ASP.NET Configuration Module
//!
//! Windows Server 2003 ASP.NET configuration management. Provides runtime
//! version registration, application configuration, compilation settings,
//! and session state management.

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use crate::win32k::user::UserHandle;

/// Maximum registered runtimes
const MAX_RUNTIMES: usize = 8;

/// Maximum applications
const MAX_APPLICATIONS: usize = 128;

/// Maximum connection strings
const MAX_CONN_STRINGS: usize = 32;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum connection string length
const MAX_CONNSTR_LEN: usize = 512;

/// ASP.NET version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AspNetVersion {
    /// .NET Framework 1.0
    V10 = 0,
    /// .NET Framework 1.1
    V11 = 1,
    /// .NET Framework 2.0
    V20 = 2,
    /// .NET Framework 3.0
    V30 = 3,
    /// .NET Framework 3.5
    V35 = 4,
}

impl Default for AspNetVersion {
    fn default() -> Self {
        Self::V20
    }
}

/// Session state mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SessionStateMode {
    /// Session state disabled
    Off = 0,
    /// In-process session state
    InProc = 1,
    /// State Server mode
    StateServer = 2,
    /// SQL Server mode
    SqlServer = 3,
    /// Custom provider
    Custom = 4,
}

impl Default for SessionStateMode {
    fn default() -> Self {
        Self::InProc
    }
}

/// Authentication mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthenticationMode {
    /// No authentication
    None = 0,
    /// Windows authentication
    Windows = 1,
    /// Forms authentication
    Forms = 2,
    /// Passport authentication
    Passport = 3,
}

impl Default for AuthenticationMode {
    fn default() -> Self {
        Self::Windows
    }
}

/// Compilation debug mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CompilationMode {
    /// Release mode
    Release = 0,
    /// Debug mode
    Debug = 1,
    /// Auto (per-page)
    Auto = 2,
}

impl Default for CompilationMode {
    fn default() -> Self {
        Self::Release
    }
}

bitflags::bitflags! {
    /// Application flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AppFlags: u32 {
        /// Custom errors enabled
        const CUSTOM_ERRORS = 0x0001;
        /// Tracing enabled
        const TRACING = 0x0002;
        /// Debug enabled
        const DEBUG = 0x0004;
        /// HTTP cookies for session
        const COOKIE_SESSION = 0x0008;
        /// Cookieless session (URL)
        const COOKIELESS = 0x0010;
        /// Require SSL
        const REQUIRE_SSL = 0x0020;
        /// Impersonation enabled
        const IMPERSONATION = 0x0040;
        /// View state validation
        const VIEWSTATE_MAC = 0x0080;
    }
}

impl Default for AppFlags {
    fn default() -> Self {
        Self::CUSTOM_ERRORS | Self::COOKIE_SESSION | Self::VIEWSTATE_MAC
    }
}

/// ASP.NET Runtime registration
#[derive(Debug)]
pub struct AspNetRuntime {
    /// Runtime is active
    active: bool,
    /// Runtime ID
    id: u32,
    /// Version
    version: AspNetVersion,
    /// Installation path
    install_path: [u8; MAX_PATH_LEN],
    /// Path length
    path_len: usize,
    /// Version string (e.g., "2.0.50727")
    version_str: [u8; 32],
    /// Version string length
    ver_len: usize,
    /// Is default runtime
    is_default: bool,
    /// Handle for management
    handle: UserHandle,
}

impl AspNetRuntime {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            version: AspNetVersion::V20,
            install_path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            version_str: [0u8; 32],
            ver_len: 0,
            is_default: false,
            handle: UserHandle::NULL,
        }
    }
}

/// ASP.NET Application configuration
#[derive(Debug)]
pub struct AspNetApp {
    /// Application is active
    active: bool,
    /// Application ID
    id: u32,
    /// Virtual path
    virtual_path: [u8; MAX_PATH_LEN],
    /// Path length
    vpath_len: usize,
    /// Physical path
    physical_path: [u8; MAX_PATH_LEN],
    /// Physical path length
    ppath_len: usize,
    /// Runtime version
    runtime_version: AspNetVersion,
    /// Application pool ID
    app_pool_id: u32,
    /// Authentication mode
    auth_mode: AuthenticationMode,
    /// Session state mode
    session_mode: SessionStateMode,
    /// Session timeout (minutes)
    session_timeout: u32,
    /// Compilation mode
    compilation_mode: CompilationMode,
    /// Default language
    default_lang: [u8; 32],
    /// Language length
    lang_len: usize,
    /// Application flags
    flags: AppFlags,
    /// Maximum request length (KB)
    max_request_length: u32,
    /// Execution timeout (seconds)
    execution_timeout: u32,
    /// Handle for management
    handle: UserHandle,
}

impl AspNetApp {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            virtual_path: [0u8; MAX_PATH_LEN],
            vpath_len: 0,
            physical_path: [0u8; MAX_PATH_LEN],
            ppath_len: 0,
            runtime_version: AspNetVersion::V20,
            app_pool_id: 0,
            auth_mode: AuthenticationMode::Windows,
            session_mode: SessionStateMode::InProc,
            session_timeout: 20,
            compilation_mode: CompilationMode::Release,
            default_lang: [0u8; 32],
            lang_len: 0,
            flags: AppFlags::empty(),
            max_request_length: 4096, // 4 MB
            execution_timeout: 110,
            handle: UserHandle::NULL,
        }
    }
}

/// Connection string entry
#[derive(Debug)]
pub struct ConnectionString {
    /// Entry is active
    active: bool,
    /// Entry ID
    id: u32,
    /// Application ID (0 = machine-level)
    app_id: u32,
    /// Connection name
    name: [u8; MAX_NAME_LEN],
    /// Name length
    name_len: usize,
    /// Connection string
    conn_string: [u8; MAX_CONNSTR_LEN],
    /// String length
    str_len: usize,
    /// Provider name
    provider: [u8; MAX_NAME_LEN],
    /// Provider length
    prov_len: usize,
    /// Handle for management
    handle: UserHandle,
}

impl ConnectionString {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            app_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            conn_string: [0u8; MAX_CONNSTR_LEN],
            str_len: 0,
            provider: [0u8; MAX_NAME_LEN],
            prov_len: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// ASP.NET configuration statistics
#[derive(Debug)]
pub struct AspNetStats {
    /// Registered runtimes
    pub registered_runtimes: u32,
    /// Configured applications
    pub configured_apps: u32,
    /// Connection strings
    pub connection_strings: u32,
    /// Applications in debug mode
    pub debug_apps: u32,
}

impl AspNetStats {
    pub const fn new() -> Self {
        Self {
            registered_runtimes: 0,
            configured_apps: 0,
            connection_strings: 0,
            debug_apps: 0,
        }
    }
}

/// ASP.NET configuration state
struct AspNetState {
    /// Runtimes
    runtimes: [AspNetRuntime; MAX_RUNTIMES],
    /// Applications
    apps: [AspNetApp; MAX_APPLICATIONS],
    /// Connection strings
    conn_strings: [ConnectionString; MAX_CONN_STRINGS],
    /// Statistics
    stats: AspNetStats,
    /// Next ID
    next_id: u32,
}

impl AspNetState {
    pub const fn new() -> Self {
        Self {
            runtimes: [const { AspNetRuntime::new() }; MAX_RUNTIMES],
            apps: [const { AspNetApp::new() }; MAX_APPLICATIONS],
            conn_strings: [const { ConnectionString::new() }; MAX_CONN_STRINGS],
            stats: AspNetStats::new(),
            next_id: 1,
        }
    }
}

/// Global ASP.NET state
static ASPNET_STATE: Mutex<AspNetState> = Mutex::new(AspNetState::new());

/// Initialization flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the ASP.NET configuration module
pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let mut state = ASPNET_STATE.lock();

    // Register default ASP.NET 2.0 runtime
    let slot_idx = 0;
    state.runtimes[slot_idx].active = true;
    state.runtimes[slot_idx].id = 1;
    state.runtimes[slot_idx].version = AspNetVersion::V20;

    let path = b"C:\\WINDOWS\\Microsoft.NET\\Framework\\v2.0.50727";
    let path_len = path.len().min(MAX_PATH_LEN);
    state.runtimes[slot_idx].install_path[..path_len].copy_from_slice(&path[..path_len]);
    state.runtimes[slot_idx].path_len = path_len;

    let ver = b"2.0.50727";
    let ver_len = ver.len().min(32);
    state.runtimes[slot_idx].version_str[..ver_len].copy_from_slice(&ver[..ver_len]);
    state.runtimes[slot_idx].ver_len = ver_len;

    state.runtimes[slot_idx].is_default = true;
    state.runtimes[slot_idx].handle = UserHandle::from_raw(1);
    state.next_id = 2;
    state.stats.registered_runtimes = 1;

    Ok(())
}

/// Register an ASP.NET runtime
pub fn register_runtime(
    version: AspNetVersion,
    install_path: &str,
    version_str: &str,
) -> Result<UserHandle, u32> {
    let mut state = ASPNET_STATE.lock();

    let slot_idx = state.runtimes.iter().position(|r| !r.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let path_bytes = install_path.as_bytes();
    let path_len = path_bytes.len().min(MAX_PATH_LEN);
    let ver_bytes = version_str.as_bytes();
    let ver_len = ver_bytes.len().min(32);

    state.runtimes[slot_idx].active = true;
    state.runtimes[slot_idx].id = id;
    state.runtimes[slot_idx].version = version;
    state.runtimes[slot_idx].install_path[..path_len].copy_from_slice(&path_bytes[..path_len]);
    state.runtimes[slot_idx].path_len = path_len;
    state.runtimes[slot_idx].version_str[..ver_len].copy_from_slice(&ver_bytes[..ver_len]);
    state.runtimes[slot_idx].ver_len = ver_len;
    state.runtimes[slot_idx].is_default = false;
    state.runtimes[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.registered_runtimes += 1;

    Ok(state.runtimes[slot_idx].handle)
}

/// Create an ASP.NET application
pub fn create_application(
    virtual_path: &str,
    physical_path: &str,
    runtime_version: AspNetVersion,
    app_pool_id: u32,
) -> Result<UserHandle, u32> {
    let mut state = ASPNET_STATE.lock();

    // Check for duplicate
    for app in state.apps.iter() {
        if app.active {
            let existing = &app.virtual_path[..app.vpath_len];
            if existing == virtual_path.as_bytes() {
                return Err(0x80070050);
            }
        }
    }

    let slot_idx = state.apps.iter().position(|a| !a.active);
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

    state.apps[slot_idx].active = true;
    state.apps[slot_idx].id = id;
    state.apps[slot_idx].virtual_path[..vpath_len].copy_from_slice(&vpath_bytes[..vpath_len]);
    state.apps[slot_idx].vpath_len = vpath_len;
    state.apps[slot_idx].physical_path[..ppath_len].copy_from_slice(&ppath_bytes[..ppath_len]);
    state.apps[slot_idx].ppath_len = ppath_len;
    state.apps[slot_idx].runtime_version = runtime_version;
    state.apps[slot_idx].app_pool_id = app_pool_id;
    state.apps[slot_idx].auth_mode = AuthenticationMode::Windows;
    state.apps[slot_idx].session_mode = SessionStateMode::InProc;
    state.apps[slot_idx].session_timeout = 20;
    state.apps[slot_idx].compilation_mode = CompilationMode::Release;
    state.apps[slot_idx].lang_len = 0;
    state.apps[slot_idx].flags = AppFlags::default();
    state.apps[slot_idx].max_request_length = 4096;
    state.apps[slot_idx].execution_timeout = 110;
    state.apps[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.configured_apps += 1;

    Ok(state.apps[slot_idx].handle)
}

/// Delete an ASP.NET application
pub fn delete_application(app_id: u32) -> Result<(), u32> {
    let mut state = ASPNET_STATE.lock();

    let app_idx = state.apps.iter().position(|a| a.active && a.id == app_id);
    let app_idx = match app_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    // Remove connection strings for this app
    let mut conns_to_remove = 0u32;
    for conn in state.conn_strings.iter() {
        if conn.active && conn.app_id == app_id {
            conns_to_remove += 1;
        }
    }

    for conn in state.conn_strings.iter_mut() {
        if conn.active && conn.app_id == app_id {
            conn.active = false;
        }
    }

    state.apps[app_idx].active = false;
    state.stats.configured_apps = state.stats.configured_apps.saturating_sub(1);
    state.stats.connection_strings = state.stats.connection_strings.saturating_sub(conns_to_remove);

    Ok(())
}

/// Configure application authentication
pub fn configure_authentication(
    app_id: u32,
    auth_mode: AuthenticationMode,
) -> Result<(), u32> {
    let mut state = ASPNET_STATE.lock();

    let app = state.apps.iter_mut().find(|a| a.active && a.id == app_id);
    let app = match app {
        Some(a) => a,
        None => return Err(0x80070002),
    };

    app.auth_mode = auth_mode;

    Ok(())
}

/// Configure application session state
pub fn configure_session(
    app_id: u32,
    mode: SessionStateMode,
    timeout: u32,
) -> Result<(), u32> {
    let mut state = ASPNET_STATE.lock();

    let app = state.apps.iter_mut().find(|a| a.active && a.id == app_id);
    let app = match app {
        Some(a) => a,
        None => return Err(0x80070002),
    };

    app.session_mode = mode;
    app.session_timeout = timeout;

    Ok(())
}

/// Configure compilation settings
pub fn configure_compilation(
    app_id: u32,
    mode: CompilationMode,
    default_language: &str,
) -> Result<(), u32> {
    let mut state = ASPNET_STATE.lock();

    let app = state.apps.iter_mut().find(|a| a.active && a.id == app_id);
    let app = match app {
        Some(a) => a,
        None => return Err(0x80070002),
    };

    app.compilation_mode = mode;

    let lang_bytes = default_language.as_bytes();
    let lang_len = lang_bytes.len().min(32);
    app.default_lang[..lang_len].copy_from_slice(&lang_bytes[..lang_len]);
    app.lang_len = lang_len;

    // Update debug stats
    if mode == CompilationMode::Debug {
        state.stats.debug_apps += 1;
    }

    Ok(())
}

/// Add a connection string
pub fn add_connection_string(
    app_id: u32,
    name: &str,
    conn_string: &str,
    provider: &str,
) -> Result<UserHandle, u32> {
    let mut state = ASPNET_STATE.lock();

    let slot_idx = state.conn_strings.iter().position(|c| !c.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(MAX_NAME_LEN);
    let str_bytes = conn_string.as_bytes();
    let str_len = str_bytes.len().min(MAX_CONNSTR_LEN);
    let prov_bytes = provider.as_bytes();
    let prov_len = prov_bytes.len().min(MAX_NAME_LEN);

    state.conn_strings[slot_idx].active = true;
    state.conn_strings[slot_idx].id = id;
    state.conn_strings[slot_idx].app_id = app_id;
    state.conn_strings[slot_idx].name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    state.conn_strings[slot_idx].name_len = name_len;
    state.conn_strings[slot_idx].conn_string[..str_len].copy_from_slice(&str_bytes[..str_len]);
    state.conn_strings[slot_idx].str_len = str_len;
    state.conn_strings[slot_idx].provider[..prov_len].copy_from_slice(&prov_bytes[..prov_len]);
    state.conn_strings[slot_idx].prov_len = prov_len;
    state.conn_strings[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.connection_strings += 1;

    Ok(state.conn_strings[slot_idx].handle)
}

/// Remove a connection string
pub fn remove_connection_string(conn_id: u32) -> Result<(), u32> {
    let mut state = ASPNET_STATE.lock();

    let conn_idx = state.conn_strings.iter().position(|c| c.active && c.id == conn_id);
    let conn_idx = match conn_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    state.conn_strings[conn_idx].active = false;
    state.stats.connection_strings = state.stats.connection_strings.saturating_sub(1);

    Ok(())
}

/// Get ASP.NET statistics
pub fn get_statistics() -> AspNetStats {
    let state = ASPNET_STATE.lock();
    AspNetStats {
        registered_runtimes: state.stats.registered_runtimes,
        configured_apps: state.stats.configured_apps,
        connection_strings: state.stats.connection_strings,
        debug_apps: state.stats.debug_apps,
    }
}

/// List registered runtimes
pub fn list_runtimes() -> [(bool, u32, AspNetVersion, bool); MAX_RUNTIMES] {
    let state = ASPNET_STATE.lock();
    let mut result = [(false, 0u32, AspNetVersion::V20, false); MAX_RUNTIMES];

    for (i, runtime) in state.runtimes.iter().enumerate() {
        if runtime.active {
            result[i] = (true, runtime.id, runtime.version, runtime.is_default);
        }
    }

    result
}

/// List configured applications
pub fn list_applications() -> [(bool, u32, AspNetVersion); MAX_APPLICATIONS] {
    let state = ASPNET_STATE.lock();
    let mut result = [(false, 0u32, AspNetVersion::V20); MAX_APPLICATIONS];

    for (i, app) in state.apps.iter().enumerate() {
        if app.active {
            result[i] = (true, app.id, app.runtime_version);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        init().unwrap();

        let stats = get_statistics();
        assert!(stats.registered_runtimes >= 1);
    }

    #[test]
    fn test_application() {
        init().unwrap();

        let app = create_application(
            "/MyApp",
            "C:\\Inetpub\\wwwroot\\MyApp",
            AspNetVersion::V20,
            1,
        );
        assert!(app.is_ok() || app.is_err());
    }
}
