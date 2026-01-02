//! Component Services
//!
//! Implements Component Services (COM+) management following Windows Server 2003.
//! Provides COM+ application configuration and DCOM settings.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - dcomcnfg.exe / comexp.msc - Component Services
//! - COM+ Applications, DCOM Config, Running Processes

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum COM+ applications
const MAX_APPLICATIONS: usize = 64;

/// Maximum components per application
const MAX_COMPONENTS: usize = 32;

/// Maximum DCOM applications
const MAX_DCOM_APPS: usize = 128;

/// Maximum name length
const MAX_NAME: usize = 128;

/// Maximum GUID length
const GUID_LEN: usize = 38;

// ============================================================================
// Application Activation
// ============================================================================

/// COM+ application activation type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActivationType {
    /// Library application (in-process)
    #[default]
    Library = 0,
    /// Server application (out-of-process)
    Server = 1,
}

impl ActivationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActivationType::Library => "Library application",
            ActivationType::Server => "Server application",
        }
    }
}

// ============================================================================
// Authentication Level
// ============================================================================

/// DCOM authentication level
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthLevel {
    /// Default
    #[default]
    Default = 0,
    /// None
    None = 1,
    /// Connect
    Connect = 2,
    /// Call
    Call = 3,
    /// Packet
    Packet = 4,
    /// Packet Integrity
    PacketIntegrity = 5,
    /// Packet Privacy
    PacketPrivacy = 6,
}

impl AuthLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthLevel::Default => "Default",
            AuthLevel::None => "None",
            AuthLevel::Connect => "Connect",
            AuthLevel::Call => "Call",
            AuthLevel::Packet => "Packet",
            AuthLevel::PacketIntegrity => "Packet Integrity",
            AuthLevel::PacketPrivacy => "Packet Privacy",
        }
    }
}

// ============================================================================
// Impersonation Level
// ============================================================================

/// DCOM impersonation level
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImpersonationLevel {
    /// Anonymous
    Anonymous = 1,
    /// Identify
    #[default]
    Identify = 2,
    /// Impersonate
    Impersonate = 3,
    /// Delegate
    Delegate = 4,
}

impl ImpersonationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ImpersonationLevel::Anonymous => "Anonymous",
            ImpersonationLevel::Identify => "Identify",
            ImpersonationLevel::Impersonate => "Impersonate",
            ImpersonationLevel::Delegate => "Delegate",
        }
    }
}

// ============================================================================
// Transaction Support
// ============================================================================

/// Transaction support level
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransactionSupport {
    /// Disabled
    #[default]
    Disabled = 0,
    /// Not Supported
    NotSupported = 1,
    /// Supported
    Supported = 2,
    /// Required
    Required = 3,
    /// Requires New
    RequiresNew = 4,
}

impl TransactionSupport {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransactionSupport::Disabled => "Disabled",
            TransactionSupport::NotSupported => "Not Supported",
            TransactionSupport::Supported => "Supported",
            TransactionSupport::Required => "Required",
            TransactionSupport::RequiresNew => "Requires New",
        }
    }
}

// ============================================================================
// COM+ Component
// ============================================================================

/// COM+ component
#[derive(Debug, Clone, Copy)]
pub struct ComComponent {
    /// Component CLSID
    pub clsid: [u8; GUID_LEN],
    /// CLSID length
    pub clsid_len: usize,
    /// ProgID
    pub prog_id: [u8; MAX_NAME],
    /// ProgID length
    pub prog_id_len: usize,
    /// Description
    pub description: [u8; MAX_NAME],
    /// Description length
    pub desc_len: usize,
    /// DLL path
    pub dll_path: [u8; MAX_NAME],
    /// DLL path length
    pub dll_len: usize,
    /// Transaction support
    pub transaction: TransactionSupport,
    /// Synchronization required
    pub sync_required: bool,
    /// Object pooling enabled
    pub pooling_enabled: bool,
    /// Pool size minimum
    pub pool_min: u32,
    /// Pool size maximum
    pub pool_max: u32,
    /// Construction string enabled
    pub construction_enabled: bool,
    /// JIT activation enabled
    pub jit_enabled: bool,
}

impl ComComponent {
    pub const fn new() -> Self {
        Self {
            clsid: [0u8; GUID_LEN],
            clsid_len: 0,
            prog_id: [0u8; MAX_NAME],
            prog_id_len: 0,
            description: [0u8; MAX_NAME],
            desc_len: 0,
            dll_path: [0u8; MAX_NAME],
            dll_len: 0,
            transaction: TransactionSupport::Disabled,
            sync_required: true,
            pooling_enabled: false,
            pool_min: 0,
            pool_max: 1,
            construction_enabled: false,
            jit_enabled: true,
        }
    }

    pub fn set_clsid(&mut self, clsid: &[u8]) {
        let len = clsid.len().min(GUID_LEN);
        self.clsid[..len].copy_from_slice(&clsid[..len]);
        self.clsid_len = len;
    }

    pub fn set_prog_id(&mut self, prog_id: &[u8]) {
        let len = prog_id.len().min(MAX_NAME);
        self.prog_id[..len].copy_from_slice(&prog_id[..len]);
        self.prog_id_len = len;
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_NAME);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.desc_len = len;
    }
}

impl Default for ComComponent {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// COM+ Application
// ============================================================================

/// COM+ application
#[derive(Debug, Clone, Copy)]
pub struct ComApplication {
    /// Application ID (GUID)
    pub app_id: [u8; GUID_LEN],
    /// App ID length
    pub app_id_len: usize,
    /// Application name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Activation type
    pub activation: ActivationType,
    /// Authentication level
    pub auth_level: AuthLevel,
    /// Impersonation level
    pub impersonation: ImpersonationLevel,
    /// Is running
    pub running: bool,
    /// Process ID (if running)
    pub pid: u32,
    /// Component count
    pub component_count: usize,
    /// Components
    pub components: [ComComponent; MAX_COMPONENTS],
    /// Queuing enabled
    pub queuing_enabled: bool,
    /// Enable 3GB support
    pub enable_3gb: bool,
    /// Enable COM+ events
    pub events_enabled: bool,
    /// Access checks level
    pub access_checks: AccessChecks,
}

impl ComApplication {
    pub const fn new() -> Self {
        Self {
            app_id: [0u8; GUID_LEN],
            app_id_len: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            activation: ActivationType::Library,
            auth_level: AuthLevel::Packet,
            impersonation: ImpersonationLevel::Impersonate,
            running: false,
            pid: 0,
            component_count: 0,
            components: [const { ComComponent::new() }; MAX_COMPONENTS],
            queuing_enabled: false,
            enable_3gb: false,
            events_enabled: true,
            access_checks: AccessChecks::ProcessAndComponent,
        }
    }

    pub fn set_app_id(&mut self, app_id: &[u8]) {
        let len = app_id.len().min(GUID_LEN);
        self.app_id[..len].copy_from_slice(&app_id[..len]);
        self.app_id_len = len;
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for ComApplication {
    fn default() -> Self {
        Self::new()
    }
}

/// Access checks level
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessChecks {
    /// Perform access checks at process level only
    ProcessOnly = 0,
    /// Perform access checks at process and component level
    #[default]
    ProcessAndComponent = 1,
}

// ============================================================================
// DCOM Application
// ============================================================================

/// DCOM application entry
#[derive(Debug, Clone, Copy)]
pub struct DcomApp {
    /// CLSID
    pub clsid: [u8; GUID_LEN],
    /// CLSID length
    pub clsid_len: usize,
    /// Application name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Application path
    pub app_path: [u8; MAX_NAME],
    /// Path length
    pub path_len: usize,
    /// Local server
    pub local_server: bool,
    /// Remote server
    pub remote_server: bool,
    /// Authentication level
    pub auth_level: AuthLevel,
}

impl DcomApp {
    pub const fn new() -> Self {
        Self {
            clsid: [0u8; GUID_LEN],
            clsid_len: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            app_path: [0u8; MAX_NAME],
            path_len: 0,
            local_server: true,
            remote_server: false,
            auth_level: AuthLevel::Connect,
        }
    }

    pub fn set_clsid(&mut self, clsid: &[u8]) {
        let len = clsid.len().min(GUID_LEN);
        self.clsid[..len].copy_from_slice(&clsid[..len]);
        self.clsid_len = len;
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for DcomApp {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Component Services State
// ============================================================================

/// Component Services state
struct ComPlusState {
    /// COM+ applications
    applications: [ComApplication; MAX_APPLICATIONS],
    /// Application count
    app_count: usize,
    /// DCOM applications
    dcom_apps: [DcomApp; MAX_DCOM_APPS],
    /// DCOM app count
    dcom_count: usize,
    /// Default authentication level
    default_auth: AuthLevel,
    /// Default impersonation level
    default_impersonation: ImpersonationLevel,
    /// Enable DCOM
    dcom_enabled: bool,
    /// Selected application index
    selected_app: usize,
}

impl ComPlusState {
    pub const fn new() -> Self {
        Self {
            applications: [const { ComApplication::new() }; MAX_APPLICATIONS],
            app_count: 0,
            dcom_apps: [const { DcomApp::new() }; MAX_DCOM_APPS],
            dcom_count: 0,
            default_auth: AuthLevel::Connect,
            default_impersonation: ImpersonationLevel::Identify,
            dcom_enabled: true,
            selected_app: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static COMPLUS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static COMPLUS_STATE: SpinLock<ComPlusState> = SpinLock::new(ComPlusState::new());

// Statistics
static APPS_STARTED: AtomicU32 = AtomicU32::new(0);
static APPS_STOPPED: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Component Services
pub fn init() {
    if COMPLUS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = COMPLUS_STATE.lock();

    // Add sample COM+ applications
    add_sample_applications(&mut state);

    // Add sample DCOM applications
    add_sample_dcom_apps(&mut state);

    crate::serial_println!("[WIN32K] Component Services initialized");
}

/// Add sample COM+ applications
fn add_sample_applications(state: &mut ComPlusState) {
    let apps: [(&[u8], &[u8], ActivationType); 4] = [
        (b"{00000001-0000-0000-0000-000000000001}", b"COM+ Utilities", ActivationType::Library),
        (b"{00000002-0000-0000-0000-000000000002}", b"COM+ QC Dead Letter Queue Listener", ActivationType::Server),
        (b"{00000003-0000-0000-0000-000000000003}", b"IIS In-Process Applications", ActivationType::Library),
        (b"{00000004-0000-0000-0000-000000000004}", b"IIS Out-Of-Process Pool Applications", ActivationType::Server),
    ];

    for (app_id, name, activation) in apps.iter() {
        if state.app_count >= MAX_APPLICATIONS {
            break;
        }
        let mut app = ComApplication::new();
        app.set_app_id(app_id);
        app.set_name(name);
        app.activation = *activation;

        let idx = state.app_count;
        state.applications[idx] = app;
        state.app_count += 1;
    }
}

/// Add sample DCOM applications
fn add_sample_dcom_apps(state: &mut ComPlusState) {
    let dcom_apps: [(&[u8], &[u8]); 8] = [
        (b"{00020812-0000-0000-C000-000000000046}", b"Microsoft Excel Application"),
        (b"{00020906-0000-0000-C000-000000000046}", b"Microsoft Word Document"),
        (b"{000209FF-0000-0000-C000-000000000046}", b"Microsoft Word Application"),
        (b"{00024500-0000-0000-C000-000000000046}", b"Microsoft Access Application"),
        (b"{91493441-5A91-11CF-8700-00AA0060263B}", b"Microsoft PowerPoint Application"),
        (b"{0002DF01-0000-0000-C000-000000000046}", b"Internet Explorer"),
        (b"{871C5380-42A0-1069-A2EA-08002B30309D}", b"Internet Shortcut"),
        (b"{D5CDD505-2E9C-101B-9397-08002B2CF9AE}", b"Shell Folder"),
    ];

    for (clsid, name) in dcom_apps.iter() {
        if state.dcom_count >= MAX_DCOM_APPS {
            break;
        }
        let mut app = DcomApp::new();
        app.set_clsid(clsid);
        app.set_name(name);

        let idx = state.dcom_count;
        state.dcom_apps[idx] = app;
        state.dcom_count += 1;
    }
}

// ============================================================================
// COM+ Application Management
// ============================================================================

/// Get COM+ application count
pub fn get_app_count() -> usize {
    COMPLUS_STATE.lock().app_count
}

/// Get COM+ application by index
pub fn get_app(index: usize) -> Option<ComApplication> {
    let state = COMPLUS_STATE.lock();
    if index < state.app_count {
        Some(state.applications[index])
    } else {
        None
    }
}

/// Start COM+ application
pub fn start_app(index: usize) -> bool {
    let mut state = COMPLUS_STATE.lock();
    if index >= state.app_count {
        return false;
    }
    if state.applications[index].activation == ActivationType::Server {
        state.applications[index].running = true;
        state.applications[index].pid = 1000 + index as u32;
        APPS_STARTED.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false // Library apps run in client process
    }
}

/// Stop COM+ application
pub fn stop_app(index: usize) -> bool {
    let mut state = COMPLUS_STATE.lock();
    if index >= state.app_count {
        return false;
    }
    if state.applications[index].running {
        state.applications[index].running = false;
        state.applications[index].pid = 0;
        APPS_STOPPED.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// Set application activation type
pub fn set_activation_type(index: usize, activation: ActivationType) -> bool {
    let mut state = COMPLUS_STATE.lock();
    if index >= state.app_count {
        return false;
    }
    state.applications[index].activation = activation;
    true
}

/// Set application security settings
pub fn set_app_security(index: usize, auth: AuthLevel, impersonation: ImpersonationLevel) -> bool {
    let mut state = COMPLUS_STATE.lock();
    if index >= state.app_count {
        return false;
    }
    state.applications[index].auth_level = auth;
    state.applications[index].impersonation = impersonation;
    true
}

// ============================================================================
// DCOM Management
// ============================================================================

/// Get DCOM application count
pub fn get_dcom_count() -> usize {
    COMPLUS_STATE.lock().dcom_count
}

/// Get DCOM application by index
pub fn get_dcom_app(index: usize) -> Option<DcomApp> {
    let state = COMPLUS_STATE.lock();
    if index < state.dcom_count {
        Some(state.dcom_apps[index])
    } else {
        None
    }
}

/// Is DCOM enabled
pub fn is_dcom_enabled() -> bool {
    COMPLUS_STATE.lock().dcom_enabled
}

/// Enable/disable DCOM
pub fn set_dcom_enabled(enabled: bool) {
    COMPLUS_STATE.lock().dcom_enabled = enabled;
}

/// Get default authentication level
pub fn get_default_auth() -> AuthLevel {
    COMPLUS_STATE.lock().default_auth
}

/// Set default authentication level
pub fn set_default_auth(auth: AuthLevel) {
    COMPLUS_STATE.lock().default_auth = auth;
}

/// Get default impersonation level
pub fn get_default_impersonation() -> ImpersonationLevel {
    COMPLUS_STATE.lock().default_impersonation
}

/// Set default impersonation level
pub fn set_default_impersonation(level: ImpersonationLevel) {
    COMPLUS_STATE.lock().default_impersonation = level;
}

// ============================================================================
// Running Processes
// ============================================================================

/// Get running COM+ applications
pub fn get_running_apps(buffer: &mut [ComApplication]) -> usize {
    let state = COMPLUS_STATE.lock();
    let mut count = 0;
    for i in 0..state.app_count {
        if state.applications[i].running {
            if count < buffer.len() {
                buffer[count] = state.applications[i];
                count += 1;
            }
        }
    }
    count
}

/// Get running application count
pub fn get_running_count() -> usize {
    let state = COMPLUS_STATE.lock();
    state.applications[..state.app_count]
        .iter()
        .filter(|a| a.running)
        .count()
}

// ============================================================================
// Statistics
// ============================================================================

/// Component Services statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ComPlusStats {
    pub initialized: bool,
    pub app_count: usize,
    pub dcom_count: usize,
    pub running_count: usize,
    pub dcom_enabled: bool,
    pub apps_started: u32,
    pub apps_stopped: u32,
}

/// Get Component Services statistics
pub fn get_stats() -> ComPlusStats {
    let state = COMPLUS_STATE.lock();
    let running = state.applications[..state.app_count]
        .iter()
        .filter(|a| a.running)
        .count();
    ComPlusStats {
        initialized: COMPLUS_INITIALIZED.load(Ordering::Relaxed),
        app_count: state.app_count,
        dcom_count: state.dcom_count,
        running_count: running,
        dcom_enabled: state.dcom_enabled,
        apps_started: APPS_STARTED.load(Ordering::Relaxed),
        apps_stopped: APPS_STOPPED.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Component Services dialog handle
pub type HCOMPLUSDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Component Services dialog
pub fn create_complus_dialog(_parent: super::super::HWND) -> HCOMPLUSDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
