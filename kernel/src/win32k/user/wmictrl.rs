//! WMI Control (wmimgmt.msc) implementation
//!
//! Provides management and configuration of Windows Management
//! Instrumentation (WMI) service settings, security, and logging.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Local type alias for window handles
type HWND = UserHandle;

/// Maximum namespaces
const MAX_NAMESPACES: usize = 64;

/// Maximum providers
const MAX_PROVIDERS: usize = 128;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Maximum security entries
const MAX_SECURITY_ENTRIES: usize = 32;

/// WMI service status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WmiStatus {
    /// Service running
    Running = 0,
    /// Service stopped
    Stopped = 1,
    /// Service starting
    Starting = 2,
    /// Service stopping
    Stopping = 3,
    /// Service paused
    Paused = 4,
    /// Service error
    Error = 5,
}

impl WmiStatus {
    /// Create new status
    pub const fn new() -> Self {
        Self::Running
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Running => "Running",
            Self::Stopped => "Stopped",
            Self::Starting => "Starting",
            Self::Stopping => "Stopping",
            Self::Paused => "Paused",
            Self::Error => "Error",
        }
    }
}

impl Default for WmiStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// Provider hosting model
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HostingModel {
    /// WMI Core
    WmiCore = 0,
    /// Decoupled: Provider runs in its own process
    Decoupled = 1,
    /// Network Service account
    NetworkService = 2,
    /// Local Service account
    LocalService = 3,
    /// Local System account
    LocalSystem = 4,
    /// Self-hosted
    SelfHost = 5,
}

impl HostingModel {
    /// Create new hosting model
    pub const fn new() -> Self {
        Self::WmiCore
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::WmiCore => "WMI Core",
            Self::Decoupled => "Decoupled",
            Self::NetworkService => "Network Service",
            Self::LocalService => "Local Service",
            Self::LocalSystem => "Local System",
            Self::SelfHost => "Self-Hosted",
        }
    }
}

impl Default for HostingModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ProviderType {
    /// Class provider
    Class = 0,
    /// Instance provider
    Instance = 1,
    /// Property provider
    Property = 2,
    /// Method provider
    Method = 3,
    /// Event provider
    Event = 4,
    /// Event consumer
    EventConsumer = 5,
    /// Push provider
    Push = 6,
}

impl ProviderType {
    /// Create new provider type
    pub const fn new() -> Self {
        Self::Instance
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Class => "Class Provider",
            Self::Instance => "Instance Provider",
            Self::Property => "Property Provider",
            Self::Method => "Method Provider",
            Self::Event => "Event Provider",
            Self::EventConsumer => "Event Consumer",
            Self::Push => "Push Provider",
        }
    }
}

impl Default for ProviderType {
    fn default() -> Self {
        Self::new()
    }
}

/// Logging level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LogLevel {
    /// No logging
    Disabled = 0,
    /// Errors only
    Errors = 1,
    /// Errors and warnings
    ErrorsAndWarnings = 2,
    /// Verbose (all events)
    Verbose = 3,
}

impl LogLevel {
    /// Create new log level
    pub const fn new() -> Self {
        Self::Errors
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Disabled => "Disabled",
            Self::Errors => "Errors only",
            Self::ErrorsAndWarnings => "Errors and warnings",
            Self::Verbose => "Verbose",
        }
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::new()
    }
}

// WMI permissions
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WmiPermissions: u32 {
        /// Execute methods
        const EXECUTE_METHODS = 0x00000001;
        /// Full write
        const FULL_WRITE = 0x00000002;
        /// Partial write
        const PARTIAL_WRITE = 0x00000004;
        /// Provider write
        const PROVIDER_WRITE = 0x00000008;
        /// Enable account
        const ENABLE_ACCOUNT = 0x00000010;
        /// Remote enable
        const REMOTE_ENABLE = 0x00000020;
        /// Read security
        const READ_SECURITY = 0x00000040;
        /// Edit security
        const EDIT_SECURITY = 0x00000080;
    }
}

impl Default for WmiPermissions {
    fn default() -> Self {
        Self::empty()
    }
}

/// Security entry
#[derive(Clone)]
pub struct SecurityEntry {
    /// Entry ID
    pub entry_id: u32,
    /// Account name
    pub account: [u8; MAX_NAME_LEN],
    /// Account name length
    pub account_len: usize,
    /// Is group (vs user)
    pub is_group: bool,
    /// Allow or deny
    pub allow: bool,
    /// Reserved
    pub reserved: [u8; 2],
    /// Permissions
    pub permissions: WmiPermissions,
    /// In use flag
    pub in_use: bool,
}

impl SecurityEntry {
    /// Create new entry
    pub const fn new() -> Self {
        Self {
            entry_id: 0,
            account: [0; MAX_NAME_LEN],
            account_len: 0,
            is_group: false,
            allow: true,
            reserved: [0; 2],
            permissions: WmiPermissions::empty(),
            in_use: false,
        }
    }

    /// Set account name
    pub fn set_account(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.account[..len].copy_from_slice(&name[..len]);
        self.account_len = len;
    }
}

impl Default for SecurityEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// WMI Provider
#[derive(Clone)]
pub struct WmiProvider {
    /// Provider ID
    pub provider_id: u32,
    /// Provider name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// CLSID
    pub clsid: [u8; 38],
    /// CLSID length
    pub clsid_len: usize,
    /// Provider type
    pub provider_type: ProviderType,
    /// Hosting model
    pub hosting_model: HostingModel,
    /// Namespace
    pub namespace: [u8; MAX_PATH_LEN],
    /// Namespace length
    pub ns_len: usize,
    /// DLL path
    pub dll_path: [u8; MAX_PATH_LEN],
    /// DLL path length
    pub dll_len: usize,
    /// Is per-user initialization
    pub per_user_init: bool,
    /// Is pure (no impersonation)
    pub pure: bool,
    /// Reserved
    pub reserved: [u8; 2],
    /// Is loaded
    pub loaded: bool,
    /// In use flag
    pub in_use: bool,
}

impl WmiProvider {
    /// Create new provider
    pub const fn new() -> Self {
        Self {
            provider_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            clsid: [0; 38],
            clsid_len: 0,
            provider_type: ProviderType::Instance,
            hosting_model: HostingModel::WmiCore,
            namespace: [0; MAX_PATH_LEN],
            ns_len: 0,
            dll_path: [0; MAX_PATH_LEN],
            dll_len: 0,
            per_user_init: false,
            pure: false,
            reserved: [0; 2],
            loaded: false,
            in_use: false,
        }
    }

    /// Set provider name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Set namespace
    pub fn set_namespace(&mut self, ns: &[u8]) {
        let len = ns.len().min(MAX_PATH_LEN);
        self.namespace[..len].copy_from_slice(&ns[..len]);
        self.ns_len = len;
    }
}

impl Default for WmiProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// WMI Namespace
#[derive(Clone)]
pub struct WmiNamespace {
    /// Namespace ID
    pub namespace_id: u32,
    /// Namespace path
    pub path: [u8; MAX_PATH_LEN],
    /// Path length
    pub path_len: usize,
    /// Description
    pub description: [u8; MAX_NAME_LEN],
    /// Description length
    pub desc_len: usize,
    /// Parent namespace ID (0 for root)
    pub parent_id: u32,
    /// Security entries
    pub security: [SecurityEntry; MAX_SECURITY_ENTRIES],
    /// Security entry count
    pub security_count: usize,
    /// Provider count in this namespace
    pub provider_count: usize,
    /// In use flag
    pub in_use: bool,
}

impl WmiNamespace {
    /// Create new namespace
    pub const fn new() -> Self {
        Self {
            namespace_id: 0,
            path: [0; MAX_PATH_LEN],
            path_len: 0,
            description: [0; MAX_NAME_LEN],
            desc_len: 0,
            parent_id: 0,
            security: [const { SecurityEntry::new() }; MAX_SECURITY_ENTRIES],
            security_count: 0,
            provider_count: 0,
            in_use: false,
        }
    }

    /// Set path
    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_PATH_LEN);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }

    /// Get path
    pub fn get_path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

impl Default for WmiNamespace {
    fn default() -> Self {
        Self::new()
    }
}

/// Backup configuration
#[derive(Clone)]
pub struct BackupConfig {
    /// Automatic backup enabled
    pub auto_backup: bool,
    /// Backup interval (hours)
    pub interval_hours: u32,
    /// Backup path
    pub backup_path: [u8; MAX_PATH_LEN],
    /// Path length
    pub path_len: usize,
    /// Last backup time
    pub last_backup: u64,
    /// Keep backup count
    pub keep_count: u32,
}

impl BackupConfig {
    /// Create new config
    pub const fn new() -> Self {
        Self {
            auto_backup: false,
            interval_hours: 24,
            backup_path: [0; MAX_PATH_LEN],
            path_len: 0,
            last_backup: 0,
            keep_count: 5,
        }
    }
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Logging configuration
#[derive(Clone)]
pub struct LoggingConfig {
    /// Logging enabled
    pub enabled: bool,
    /// Reserved
    pub reserved: [u8; 3],
    /// Log level
    pub level: LogLevel,
    /// Log file path
    pub log_path: [u8; MAX_PATH_LEN],
    /// Path length
    pub path_len: usize,
    /// Maximum log size (bytes)
    pub max_size: u64,
    /// Directory to log
    pub log_directory: [u8; MAX_PATH_LEN],
    /// Directory length
    pub dir_len: usize,
}

impl LoggingConfig {
    /// Create new config
    pub const fn new() -> Self {
        Self {
            enabled: true,
            reserved: [0; 3],
            level: LogLevel::Errors,
            log_path: [0; MAX_PATH_LEN],
            path_len: 0,
            max_size: 65536,
            log_directory: [0; MAX_PATH_LEN],
            dir_len: 0,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// WMI Control state
pub struct WmiState {
    /// Service status
    pub status: WmiStatus,
    /// Namespaces
    pub namespaces: [WmiNamespace; MAX_NAMESPACES],
    /// Namespace count
    pub namespace_count: usize,
    /// Providers
    pub providers: [WmiProvider; MAX_PROVIDERS],
    /// Provider count
    pub provider_count: usize,
    /// Next ID
    pub next_id: u32,
    /// Backup config
    pub backup: BackupConfig,
    /// Logging config
    pub logging: LoggingConfig,
    /// Connected computer
    pub computer: [u8; MAX_NAME_LEN],
    /// Computer name length
    pub computer_len: usize,
    /// Repository location
    pub repository: [u8; MAX_PATH_LEN],
    /// Repository path length
    pub repo_len: usize,
}

impl WmiState {
    /// Create new state
    pub const fn new() -> Self {
        Self {
            status: WmiStatus::Running,
            namespaces: [const { WmiNamespace::new() }; MAX_NAMESPACES],
            namespace_count: 0,
            providers: [const { WmiProvider::new() }; MAX_PROVIDERS],
            provider_count: 0,
            next_id: 1,
            backup: BackupConfig::new(),
            logging: LoggingConfig::new(),
            computer: [0; MAX_NAME_LEN],
            computer_len: 0,
            repository: [0; MAX_PATH_LEN],
            repo_len: 0,
        }
    }

    /// Find namespace by path
    pub fn find_namespace(&self, path: &[u8]) -> Option<usize> {
        for (i, ns) in self.namespaces.iter().enumerate() {
            if ns.in_use && &ns.path[..ns.path_len] == path {
                return Some(i);
            }
        }
        None
    }

    /// Find namespace by ID
    pub fn find_namespace_by_id(&self, ns_id: u32) -> Option<usize> {
        for (i, ns) in self.namespaces.iter().enumerate() {
            if ns.in_use && ns.namespace_id == ns_id {
                return Some(i);
            }
        }
        None
    }

    /// Find provider by ID
    pub fn find_provider(&self, provider_id: u32) -> Option<usize> {
        for (i, prov) in self.providers.iter().enumerate() {
            if prov.in_use && prov.provider_id == provider_id {
                return Some(i);
            }
        }
        None
    }
}

impl Default for WmiState {
    fn default() -> Self {
        Self::new()
    }
}

/// Global state
static WMI_STATE: SpinLock<WmiState> = SpinLock::new(WmiState::new());

/// Initialization flag
static WMI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Statistics
static WMI_OPERATION_COUNT: AtomicU32 = AtomicU32::new(0);

/// Error codes
pub mod error {
    pub const SUCCESS: u32 = 0;
    pub const NOT_INITIALIZED: u32 = 0x57000001;
    pub const NAMESPACE_NOT_FOUND: u32 = 0x57000002;
    pub const PROVIDER_NOT_FOUND: u32 = 0x57000003;
    pub const ALREADY_EXISTS: u32 = 0x57000004;
    pub const ACCESS_DENIED: u32 = 0x57000005;
    pub const NO_MORE_OBJECTS: u32 = 0x57000006;
    pub const SERVICE_NOT_RUNNING: u32 = 0x57000007;
    pub const BACKUP_FAILED: u32 = 0x57000008;
    pub const RESTORE_FAILED: u32 = 0x57000009;
}

/// Initialize WMI Control
pub fn init() {
    if WMI_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = WMI_STATE.lock();

    // Set computer name
    let computer = b"localhost";
    let len = computer.len();
    state.computer[..len].copy_from_slice(computer);
    state.computer_len = len;

    // Set repository location
    let repo = b"%SystemRoot%\\System32\\wbem\\Repository";
    let repo_len = repo.len();
    state.repository[..repo_len].copy_from_slice(repo);
    state.repo_len = repo_len;

    // Create root namespace
    let root_id = state.next_id;
    state.next_id += 1;

    let root = &mut state.namespaces[0];
    root.in_use = true;
    root.namespace_id = root_id;
    root.set_path(b"root");
    state.namespace_count = 1;

    // Create root\CIMV2 namespace
    let cimv2_id = state.next_id;
    state.next_id += 1;

    let cimv2 = &mut state.namespaces[1];
    cimv2.in_use = true;
    cimv2.namespace_id = cimv2_id;
    cimv2.set_path(b"root\\CIMV2");
    cimv2.parent_id = root_id;

    // Add default security
    let entry = &mut cimv2.security[0];
    entry.in_use = true;
    entry.entry_id = 1;
    entry.set_account(b"Administrators");
    entry.is_group = true;
    entry.allow = true;
    entry.permissions = WmiPermissions::EXECUTE_METHODS
        | WmiPermissions::FULL_WRITE
        | WmiPermissions::ENABLE_ACCOUNT
        | WmiPermissions::REMOTE_ENABLE
        | WmiPermissions::READ_SECURITY
        | WmiPermissions::EDIT_SECURITY;
    cimv2.security_count = 1;

    state.namespace_count = 2;

    // Create root\WMI namespace
    let wmi_id = state.next_id;
    state.next_id += 1;

    let wmi_ns = &mut state.namespaces[2];
    wmi_ns.in_use = true;
    wmi_ns.namespace_id = wmi_id;
    wmi_ns.set_path(b"root\\WMI");
    wmi_ns.parent_id = root_id;
    state.namespace_count = 3;

    // Create a sample provider
    let prov_id = state.next_id;
    state.next_id += 1;

    let provider = &mut state.providers[0];
    provider.in_use = true;
    provider.provider_id = prov_id;
    provider.set_name(b"CIMWin32");
    provider.provider_type = ProviderType::Instance;
    provider.hosting_model = HostingModel::NetworkService;
    provider.set_namespace(b"root\\CIMV2");
    provider.loaded = true;

    state.provider_count = 1;
    state.status = WmiStatus::Running;
}

/// Connect to computer
pub fn connect(computer: &[u8]) -> Result<(), u32> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = WMI_STATE.lock();

    let len = computer.len().min(MAX_NAME_LEN);
    state.computer[..len].copy_from_slice(&computer[..len]);
    state.computer_len = len;

    WMI_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Get namespace security entry count
pub fn get_namespace_security_count(namespace_id: u32) -> Result<usize, u32> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let state = WMI_STATE.lock();

    let idx = match state.find_namespace_by_id(namespace_id) {
        Some(i) => i,
        None => return Err(error::NAMESPACE_NOT_FOUND),
    };

    Ok(state.namespaces[idx].security_count)
}

/// Add security entry
pub fn add_security_entry(
    namespace_id: u32,
    account: &[u8],
    is_group: bool,
    allow: bool,
    permissions: WmiPermissions,
) -> Result<u32, u32> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = WMI_STATE.lock();

    let idx = match state.find_namespace_by_id(namespace_id) {
        Some(i) => i,
        None => return Err(error::NAMESPACE_NOT_FOUND),
    };

    // Find free security slot
    let mut slot_idx = None;
    for (i, entry) in state.namespaces[idx].security.iter().enumerate() {
        if !entry.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let sec_idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let entry_id = state.next_id;
    state.next_id += 1;

    let entry = &mut state.namespaces[idx].security[sec_idx];
    entry.in_use = true;
    entry.entry_id = entry_id;
    entry.set_account(account);
    entry.is_group = is_group;
    entry.allow = allow;
    entry.permissions = permissions;

    state.namespaces[idx].security_count += 1;
    WMI_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(entry_id)
}

/// Remove security entry
pub fn remove_security_entry(namespace_id: u32, entry_id: u32) -> Result<(), u32> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = WMI_STATE.lock();

    let idx = match state.find_namespace_by_id(namespace_id) {
        Some(i) => i,
        None => return Err(error::NAMESPACE_NOT_FOUND),
    };

    let mut found = false;
    for entry in state.namespaces[idx].security.iter_mut() {
        if entry.in_use && entry.entry_id == entry_id {
            entry.in_use = false;
            found = true;
            break;
        }
    }

    if !found {
        return Err(error::ACCESS_DENIED);
    }

    state.namespaces[idx].security_count = state.namespaces[idx].security_count.saturating_sub(1);
    WMI_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Set logging configuration
pub fn set_logging(enabled: bool, level: LogLevel, max_size: u64) -> Result<(), u32> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = WMI_STATE.lock();

    state.logging.enabled = enabled;
    state.logging.level = level;
    state.logging.max_size = max_size;

    WMI_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Set backup configuration
pub fn set_backup_config(auto_backup: bool, interval_hours: u32, keep_count: u32) -> Result<(), u32> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = WMI_STATE.lock();

    state.backup.auto_backup = auto_backup;
    state.backup.interval_hours = interval_hours;
    state.backup.keep_count = keep_count;

    WMI_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Backup repository
pub fn backup_repository(path: &[u8]) -> Result<(), u32> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = WMI_STATE.lock();

    if state.status != WmiStatus::Running {
        return Err(error::SERVICE_NOT_RUNNING);
    }

    let len = path.len().min(MAX_PATH_LEN);
    state.backup.backup_path[..len].copy_from_slice(&path[..len]);
    state.backup.path_len = len;
    state.backup.last_backup = 1; // Would be current timestamp

    WMI_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Restore repository
pub fn restore_repository(path: &[u8]) -> Result<(), u32> {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let _path = path;
    // In real implementation, would restore from backup

    WMI_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Get namespace count
pub fn get_namespace_count() -> usize {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = WMI_STATE.lock();
    state.namespace_count
}

/// Get provider count
pub fn get_provider_count() -> usize {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = WMI_STATE.lock();
    state.provider_count
}

/// Get service status
pub fn get_status() -> WmiStatus {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        return WmiStatus::Stopped;
    }

    let state = WMI_STATE.lock();
    state.status
}

/// Create WMI Control window
pub fn create_wmi_dialog(parent: HWND) -> HWND {
    if !WMI_INITIALIZED.load(Ordering::SeqCst) {
        init();
    }

    let id = 0x5757C000u32;
    let _parent = parent;

    UserHandle::from_raw(id)
}

/// Dialog messages
pub mod messages {
    pub const WMI_REFRESH: u32 = 0x0840;
    pub const WMI_CONNECT: u32 = 0x0841;
    pub const WMI_PROPERTIES: u32 = 0x0842;
    pub const WMI_SECURITY: u32 = 0x0843;
    pub const WMI_BACKUP: u32 = 0x0844;
    pub const WMI_RESTORE: u32 = 0x0845;
    pub const WMI_LOGGING: u32 = 0x0846;
    pub const WMI_ADVANCED: u32 = 0x0847;
}

/// Get statistics
pub fn get_statistics() -> (usize, usize, WmiStatus, u32) {
    let state = WMI_STATE.lock();
    let op_count = WMI_OPERATION_COUNT.load(Ordering::Relaxed);
    (state.namespace_count, state.provider_count, state.status, op_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wmi_init() {
        init();
        assert!(WMI_INITIALIZED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_wmi_status() {
        assert_eq!(WmiStatus::Running.display_name(), "Running");
    }

    #[test]
    fn test_hosting_model() {
        assert_eq!(HostingModel::NetworkService.display_name(), "Network Service");
    }

    #[test]
    fn test_log_level() {
        assert_eq!(LogLevel::Verbose.display_name(), "Verbose");
    }
}
