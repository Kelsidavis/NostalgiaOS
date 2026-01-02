//! Connection Manager Administration Kit (CMAK)
//!
//! This module implements the Win32k USER subsystem support for the
//! Connection Manager Administration Kit. CMAK allows administrators
//! to create customized connection profiles for VPN and dial-up access.
//!
//! # Windows Server 2003 Reference
//!
//! CMAK creates connection profiles that can be distributed to users,
//! providing pre-configured VPN or dial-up settings with custom branding,
//! phone books, and scripts.
//!
//! Key components:
//! - Connection profile creation and editing
//! - Phone book management
//! - Custom actions and scripts
//! - Branding (icons, bitmaps, help files)
//! - VPN and dial-up settings

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Type alias for window handles
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of connection profiles
const MAX_PROFILES: usize = 64;

/// Maximum number of phone book entries
const MAX_PHONEBOOK_ENTRIES: usize = 256;

/// Maximum number of custom actions
const MAX_CUSTOM_ACTIONS: usize = 32;

/// Maximum number of VPN servers
const MAX_VPN_SERVERS: usize = 32;

/// Maximum name length
const MAX_NAME_LEN: usize = 128;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Maximum phone number length
const MAX_PHONE_LEN: usize = 64;

/// Maximum command line length
const MAX_CMDLINE_LEN: usize = 512;

// ============================================================================
// Enumerations
// ============================================================================

/// Connection type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ConnectionType {
    /// VPN (Virtual Private Network)
    Vpn = 0,
    /// Dial-up connection
    Dialup = 1,
    /// VPN over dial-up
    VpnOverDialup = 2,
    /// Direct connection (PPPoE, etc.)
    Direct = 3,
}

impl Default for ConnectionType {
    fn default() -> Self {
        Self::Vpn
    }
}

/// VPN protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VpnProtocol {
    /// Automatic (try PPTP, then L2TP)
    Automatic = 0,
    /// PPTP (Point-to-Point Tunneling Protocol)
    Pptp = 1,
    /// L2TP/IPSec
    L2tpIpsec = 2,
    /// L2TP without IPSec
    L2tp = 3,
}

impl Default for VpnProtocol {
    fn default() -> Self {
        Self::Automatic
    }
}

/// Authentication method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthMethod {
    /// PAP (Password Authentication Protocol)
    Pap = 0,
    /// CHAP (Challenge Handshake Authentication Protocol)
    Chap = 1,
    /// MS-CHAPv1
    MsChapV1 = 2,
    /// MS-CHAPv2
    MsChapV2 = 3,
    /// EAP (Extensible Authentication Protocol)
    Eap = 4,
    /// Smart Card or Certificate
    SmartCard = 5,
}

impl Default for AuthMethod {
    fn default() -> Self {
        Self::MsChapV2
    }
}

/// Custom action type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ActionType {
    /// Pre-connect action
    PreConnect = 0,
    /// Pre-tunnel action
    PreTunnel = 1,
    /// Post-connect action
    PostConnect = 2,
    /// On-disconnect action
    OnDisconnect = 3,
    /// On-logon action
    OnLogon = 4,
    /// On-logoff action
    OnLogoff = 5,
}

impl Default for ActionType {
    fn default() -> Self {
        Self::PostConnect
    }
}

/// Profile status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ProfileStatus {
    /// Draft (being edited)
    Draft = 0,
    /// Ready for deployment
    Ready = 1,
    /// Deployed
    Deployed = 2,
    /// Archived
    Archived = 3,
}

impl Default for ProfileStatus {
    fn default() -> Self {
        Self::Draft
    }
}

/// Encryption level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EncryptionLevel {
    /// No encryption
    None = 0,
    /// Optional encryption
    Optional = 1,
    /// Require encryption
    Required = 2,
    /// Maximum encryption
    Maximum = 3,
}

impl Default for EncryptionLevel {
    fn default() -> Self {
        Self::Required
    }
}

// ============================================================================
// Structures
// ============================================================================

/// Connection profile
#[derive(Debug)]
pub struct ConnectionProfile {
    /// Profile ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Profile name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Service name (displayed to users)
    pub service_name: [u8; MAX_NAME_LEN],
    /// Service name length
    pub service_name_len: usize,
    /// Connection type
    pub conn_type: ConnectionType,
    /// VPN protocol
    pub vpn_protocol: VpnProtocol,
    /// Authentication method
    pub auth_method: AuthMethod,
    /// Encryption level
    pub encryption: EncryptionLevel,
    /// Profile status
    pub status: ProfileStatus,
    /// Version number
    pub version: u32,
    /// Primary VPN/dial-up server
    pub primary_server: [u8; MAX_NAME_LEN],
    /// Primary server length
    pub primary_server_len: usize,
    /// Backup VPN/dial-up server
    pub backup_server: [u8; MAX_NAME_LEN],
    /// Backup server length
    pub backup_server_len: usize,
    /// Use phone book
    pub use_phonebook: bool,
    /// Split tunneling enabled
    pub split_tunneling: bool,
    /// Auto-reconnect enabled
    pub auto_reconnect: bool,
    /// Idle disconnect timeout (seconds, 0 = disabled)
    pub idle_timeout: u32,
    /// Domain name
    pub domain: [u8; MAX_NAME_LEN],
    /// Domain length
    pub domain_len: usize,
    /// DNS suffix
    pub dns_suffix: [u8; MAX_NAME_LEN],
    /// DNS suffix length
    pub dns_suffix_len: usize,
    /// Custom icon path
    pub icon_path: [u8; MAX_PATH_LEN],
    /// Icon path length
    pub icon_path_len: usize,
    /// Help file path
    pub help_path: [u8; MAX_PATH_LEN],
    /// Help path length
    pub help_path_len: usize,
    /// Created time
    pub created_time: u64,
    /// Modified time
    pub modified_time: u64,
    /// Window handle
    pub hwnd: HWND,
}

impl ConnectionProfile {
    /// Create new profile
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            service_name: [0u8; MAX_NAME_LEN],
            service_name_len: 0,
            conn_type: ConnectionType::Vpn,
            vpn_protocol: VpnProtocol::Automatic,
            auth_method: AuthMethod::MsChapV2,
            encryption: EncryptionLevel::Required,
            status: ProfileStatus::Draft,
            version: 1,
            primary_server: [0u8; MAX_NAME_LEN],
            primary_server_len: 0,
            backup_server: [0u8; MAX_NAME_LEN],
            backup_server_len: 0,
            use_phonebook: false,
            split_tunneling: false,
            auto_reconnect: true,
            idle_timeout: 0,
            domain: [0u8; MAX_NAME_LEN],
            domain_len: 0,
            dns_suffix: [0u8; MAX_NAME_LEN],
            dns_suffix_len: 0,
            icon_path: [0u8; MAX_PATH_LEN],
            icon_path_len: 0,
            help_path: [0u8; MAX_PATH_LEN],
            help_path_len: 0,
            created_time: 0,
            modified_time: 0,
            hwnd: UserHandle::NULL,
        }
    }
}

/// Phone book entry
#[derive(Debug)]
pub struct PhoneBookEntry {
    /// Entry ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Entry name/description
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Phone number
    pub phone_number: [u8; MAX_PHONE_LEN],
    /// Phone number length
    pub phone_len: usize,
    /// Country/region code
    pub country_code: u16,
    /// Area code
    pub area_code: [u8; 8],
    /// Area code length
    pub area_code_len: usize,
    /// POP (Point of Presence) name
    pub pop_name: [u8; MAX_NAME_LEN],
    /// POP name length
    pub pop_name_len: usize,
    /// Profile ID this entry belongs to
    pub profile_id: u32,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Enabled flag
    pub enabled: bool,
}

impl PhoneBookEntry {
    /// Create new entry
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            phone_number: [0u8; MAX_PHONE_LEN],
            phone_len: 0,
            country_code: 1, // Default to US
            area_code: [0u8; 8],
            area_code_len: 0,
            pop_name: [0u8; MAX_NAME_LEN],
            pop_name_len: 0,
            profile_id: 0,
            priority: 0,
            enabled: true,
        }
    }
}

/// Custom action
#[derive(Debug)]
pub struct CustomAction {
    /// Action ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Action name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Action type
    pub action_type: ActionType,
    /// Program path
    pub program: [u8; MAX_PATH_LEN],
    /// Program path length
    pub program_len: usize,
    /// Command line arguments
    pub arguments: [u8; MAX_CMDLINE_LEN],
    /// Arguments length
    pub arguments_len: usize,
    /// Working directory
    pub working_dir: [u8; MAX_PATH_LEN],
    /// Working directory length
    pub working_dir_len: usize,
    /// Run minimized
    pub minimized: bool,
    /// Wait for completion
    pub wait_for_completion: bool,
    /// Timeout (seconds, 0 = no timeout)
    pub timeout: u32,
    /// Profile ID this action belongs to
    pub profile_id: u32,
    /// Execution order
    pub order: u32,
}

impl CustomAction {
    /// Create new action
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            action_type: ActionType::PostConnect,
            program: [0u8; MAX_PATH_LEN],
            program_len: 0,
            arguments: [0u8; MAX_CMDLINE_LEN],
            arguments_len: 0,
            working_dir: [0u8; MAX_PATH_LEN],
            working_dir_len: 0,
            minimized: true,
            wait_for_completion: false,
            timeout: 0,
            profile_id: 0,
            order: 0,
        }
    }
}

/// VPN server entry
#[derive(Debug)]
pub struct VpnServer {
    /// Server ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Server hostname or IP
    pub hostname: [u8; MAX_NAME_LEN],
    /// Hostname length
    pub hostname_len: usize,
    /// Friendly name
    pub friendly_name: [u8; MAX_NAME_LEN],
    /// Friendly name length
    pub friendly_name_len: usize,
    /// Profile ID
    pub profile_id: u32,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Region/location
    pub region: [u8; 64],
    /// Region length
    pub region_len: usize,
    /// Enabled flag
    pub enabled: bool,
}

impl VpnServer {
    /// Create new VPN server entry
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            hostname: [0u8; MAX_NAME_LEN],
            hostname_len: 0,
            friendly_name: [0u8; MAX_NAME_LEN],
            friendly_name_len: 0,
            profile_id: 0,
            priority: 0,
            region: [0u8; 64],
            region_len: 0,
            enabled: true,
        }
    }
}

/// Profile build settings
#[derive(Debug)]
pub struct BuildSettings {
    /// Include phone book
    pub include_phonebook: bool,
    /// Include custom actions
    pub include_actions: bool,
    /// Include custom help
    pub include_help: bool,
    /// Include license agreement
    pub include_license: bool,
    /// Self-extracting executable
    pub self_extracting: bool,
    /// Target Windows version (major * 100 + minor)
    pub target_version: u16,
    /// Include uninstaller
    pub include_uninstall: bool,
    /// Silent install option
    pub silent_install: bool,
}

impl BuildSettings {
    /// Create default build settings
    pub const fn new() -> Self {
        Self {
            include_phonebook: true,
            include_actions: true,
            include_help: true,
            include_license: false,
            self_extracting: true,
            target_version: 502, // Windows Server 2003
            include_uninstall: true,
            silent_install: true,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// CMAK state
struct CmakState {
    /// Connection profiles
    profiles: [ConnectionProfile; MAX_PROFILES],
    /// Phone book entries
    phonebook: [PhoneBookEntry; MAX_PHONEBOOK_ENTRIES],
    /// Custom actions
    actions: [CustomAction; MAX_CUSTOM_ACTIONS],
    /// VPN servers
    vpn_servers: [VpnServer; MAX_VPN_SERVERS],
    /// Build settings
    build_settings: BuildSettings,
    /// Next ID counter
    next_id: u32,
}

impl CmakState {
    /// Create new state
    const fn new() -> Self {
        Self {
            profiles: [const { ConnectionProfile::new() }; MAX_PROFILES],
            phonebook: [const { PhoneBookEntry::new() }; MAX_PHONEBOOK_ENTRIES],
            actions: [const { CustomAction::new() }; MAX_CUSTOM_ACTIONS],
            vpn_servers: [const { VpnServer::new() }; MAX_VPN_SERVERS],
            build_settings: BuildSettings::new(),
            next_id: 1,
        }
    }
}

/// Global state
static CMAK_STATE: SpinLock<CmakState> = SpinLock::new(CmakState::new());

/// Module initialized flag
static CMAK_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Profile count
static PROFILE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Phonebook entry count
static PHONEBOOK_COUNT: AtomicU32 = AtomicU32::new(0);

/// Action count
static ACTION_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Profile Management Functions
// ============================================================================

/// Create a new connection profile
pub fn create_profile(
    name: &[u8],
    service_name: &[u8],
    conn_type: ConnectionType,
) -> Result<u32, u32> {
    let mut state = CMAK_STATE.lock();

    let slot = state.profiles.iter().position(|p| !p.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E), // E_OUTOFMEMORY
    };

    let id = state.next_id;
    state.next_id += 1;

    let profile = &mut state.profiles[slot];
    profile.id = id;
    profile.active = true;

    let name_len = name.len().min(MAX_NAME_LEN);
    profile.name[..name_len].copy_from_slice(&name[..name_len]);
    profile.name_len = name_len;

    let svc_len = service_name.len().min(MAX_NAME_LEN);
    profile.service_name[..svc_len].copy_from_slice(&service_name[..svc_len]);
    profile.service_name_len = svc_len;

    profile.conn_type = conn_type;
    profile.status = ProfileStatus::Draft;
    profile.version = 1;
    profile.created_time = 0; // Would use current time
    profile.modified_time = 0;
    profile.hwnd = UserHandle::from_raw(id);

    PROFILE_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(id)
}

/// Delete a profile
pub fn delete_profile(profile_id: u32) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let profile = state.profiles.iter_mut().find(|p| p.active && p.id == profile_id);

    match profile {
        Some(p) => {
            p.active = false;

            // Delete associated phone book entries
            for entry in state.phonebook.iter_mut() {
                if entry.active && entry.profile_id == profile_id {
                    entry.active = false;
                    PHONEBOOK_COUNT.fetch_sub(1, Ordering::Relaxed);
                }
            }

            // Delete associated custom actions
            for action in state.actions.iter_mut() {
                if action.active && action.profile_id == profile_id {
                    action.active = false;
                    ACTION_COUNT.fetch_sub(1, Ordering::Relaxed);
                }
            }

            // Delete associated VPN servers
            for server in state.vpn_servers.iter_mut() {
                if server.active && server.profile_id == profile_id {
                    server.active = false;
                }
            }

            PROFILE_COUNT.fetch_sub(1, Ordering::Relaxed);
            Ok(())
        }
        None => Err(0x80070002), // ERROR_FILE_NOT_FOUND
    }
}

/// Set profile VPN settings
pub fn set_profile_vpn(
    profile_id: u32,
    vpn_protocol: VpnProtocol,
    auth_method: AuthMethod,
    encryption: EncryptionLevel,
) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let profile = state.profiles.iter_mut().find(|p| p.active && p.id == profile_id);

    match profile {
        Some(p) => {
            p.vpn_protocol = vpn_protocol;
            p.auth_method = auth_method;
            p.encryption = encryption;
            p.modified_time = 0;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set profile primary server
pub fn set_profile_server(
    profile_id: u32,
    primary_server: &[u8],
    backup_server: &[u8],
) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let profile = state.profiles.iter_mut().find(|p| p.active && p.id == profile_id);

    match profile {
        Some(p) => {
            let primary_len = primary_server.len().min(MAX_NAME_LEN);
            p.primary_server[..primary_len].copy_from_slice(&primary_server[..primary_len]);
            p.primary_server_len = primary_len;

            let backup_len = backup_server.len().min(MAX_NAME_LEN);
            p.backup_server[..backup_len].copy_from_slice(&backup_server[..backup_len]);
            p.backup_server_len = backup_len;

            p.modified_time = 0;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set profile connection options
pub fn set_profile_options(
    profile_id: u32,
    split_tunneling: bool,
    auto_reconnect: bool,
    idle_timeout: u32,
) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let profile = state.profiles.iter_mut().find(|p| p.active && p.id == profile_id);

    match profile {
        Some(p) => {
            p.split_tunneling = split_tunneling;
            p.auto_reconnect = auto_reconnect;
            p.idle_timeout = idle_timeout;
            p.modified_time = 0;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set profile domain settings
pub fn set_profile_domain(
    profile_id: u32,
    domain: &[u8],
    dns_suffix: &[u8],
) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let profile = state.profiles.iter_mut().find(|p| p.active && p.id == profile_id);

    match profile {
        Some(p) => {
            let domain_len = domain.len().min(MAX_NAME_LEN);
            p.domain[..domain_len].copy_from_slice(&domain[..domain_len]);
            p.domain_len = domain_len;

            let suffix_len = dns_suffix.len().min(MAX_NAME_LEN);
            p.dns_suffix[..suffix_len].copy_from_slice(&dns_suffix[..suffix_len]);
            p.dns_suffix_len = suffix_len;

            p.modified_time = 0;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set profile branding
pub fn set_profile_branding(
    profile_id: u32,
    icon_path: &[u8],
    help_path: &[u8],
) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let profile = state.profiles.iter_mut().find(|p| p.active && p.id == profile_id);

    match profile {
        Some(p) => {
            let icon_len = icon_path.len().min(MAX_PATH_LEN);
            p.icon_path[..icon_len].copy_from_slice(&icon_path[..icon_len]);
            p.icon_path_len = icon_len;

            let help_len = help_path.len().min(MAX_PATH_LEN);
            p.help_path[..help_len].copy_from_slice(&help_path[..help_len]);
            p.help_path_len = help_len;

            p.modified_time = 0;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set profile status
pub fn set_profile_status(profile_id: u32, status: ProfileStatus) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let profile = state.profiles.iter_mut().find(|p| p.active && p.id == profile_id);

    match profile {
        Some(p) => {
            p.status = status;
            if status == ProfileStatus::Ready {
                p.version += 1;
            }
            p.modified_time = 0;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Get profile count
pub fn get_profile_count() -> u32 {
    PROFILE_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// Phone Book Functions
// ============================================================================

/// Add a phone book entry
pub fn add_phonebook_entry(
    profile_id: u32,
    name: &[u8],
    phone_number: &[u8],
    country_code: u16,
) -> Result<u32, u32> {
    let mut state = CMAK_STATE.lock();

    // Verify profile exists
    if !state.profiles.iter().any(|p| p.active && p.id == profile_id) {
        return Err(0x80070002);
    }

    let slot = state.phonebook.iter().position(|e| !e.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let entry = &mut state.phonebook[slot];
    entry.id = id;
    entry.active = true;

    let name_len = name.len().min(MAX_NAME_LEN);
    entry.name[..name_len].copy_from_slice(&name[..name_len]);
    entry.name_len = name_len;

    let phone_len = phone_number.len().min(MAX_PHONE_LEN);
    entry.phone_number[..phone_len].copy_from_slice(&phone_number[..phone_len]);
    entry.phone_len = phone_len;

    entry.country_code = country_code;
    entry.profile_id = profile_id;

    PHONEBOOK_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(id)
}

/// Remove a phone book entry
pub fn remove_phonebook_entry(entry_id: u32) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let entry = state.phonebook.iter_mut().find(|e| e.active && e.id == entry_id);

    match entry {
        Some(e) => {
            e.active = false;
            PHONEBOOK_COUNT.fetch_sub(1, Ordering::Relaxed);
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set phone book entry priority
pub fn set_phonebook_priority(entry_id: u32, priority: u32) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let entry = state.phonebook.iter_mut().find(|e| e.active && e.id == entry_id);

    match entry {
        Some(e) => {
            e.priority = priority;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Get phone book entry count
pub fn get_phonebook_count() -> u32 {
    PHONEBOOK_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// Custom Action Functions
// ============================================================================

/// Add a custom action
pub fn add_custom_action(
    profile_id: u32,
    name: &[u8],
    action_type: ActionType,
    program: &[u8],
) -> Result<u32, u32> {
    let mut state = CMAK_STATE.lock();

    // Verify profile exists
    if !state.profiles.iter().any(|p| p.active && p.id == profile_id) {
        return Err(0x80070002);
    }

    let slot = state.actions.iter().position(|a| !a.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let action = &mut state.actions[slot];
    action.id = id;
    action.active = true;

    let name_len = name.len().min(MAX_NAME_LEN);
    action.name[..name_len].copy_from_slice(&name[..name_len]);
    action.name_len = name_len;

    action.action_type = action_type;

    let prog_len = program.len().min(MAX_PATH_LEN);
    action.program[..prog_len].copy_from_slice(&program[..prog_len]);
    action.program_len = prog_len;

    action.profile_id = profile_id;

    ACTION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(id)
}

/// Remove a custom action
pub fn remove_custom_action(action_id: u32) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let action = state.actions.iter_mut().find(|a| a.active && a.id == action_id);

    match action {
        Some(a) => {
            a.active = false;
            ACTION_COUNT.fetch_sub(1, Ordering::Relaxed);
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set custom action arguments
pub fn set_action_arguments(
    action_id: u32,
    arguments: &[u8],
    working_dir: &[u8],
) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let action = state.actions.iter_mut().find(|a| a.active && a.id == action_id);

    match action {
        Some(a) => {
            let args_len = arguments.len().min(MAX_CMDLINE_LEN);
            a.arguments[..args_len].copy_from_slice(&arguments[..args_len]);
            a.arguments_len = args_len;

            let dir_len = working_dir.len().min(MAX_PATH_LEN);
            a.working_dir[..dir_len].copy_from_slice(&working_dir[..dir_len]);
            a.working_dir_len = dir_len;

            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set custom action options
pub fn set_action_options(
    action_id: u32,
    minimized: bool,
    wait_for_completion: bool,
    timeout: u32,
) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let action = state.actions.iter_mut().find(|a| a.active && a.id == action_id);

    match action {
        Some(a) => {
            a.minimized = minimized;
            a.wait_for_completion = wait_for_completion;
            a.timeout = timeout;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Get action count
pub fn get_action_count() -> u32 {
    ACTION_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// VPN Server Functions
// ============================================================================

/// Add a VPN server
pub fn add_vpn_server(
    profile_id: u32,
    hostname: &[u8],
    friendly_name: &[u8],
) -> Result<u32, u32> {
    let mut state = CMAK_STATE.lock();

    // Verify profile exists
    if !state.profiles.iter().any(|p| p.active && p.id == profile_id) {
        return Err(0x80070002);
    }

    let slot = state.vpn_servers.iter().position(|s| !s.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let server = &mut state.vpn_servers[slot];
    server.id = id;
    server.active = true;

    let host_len = hostname.len().min(MAX_NAME_LEN);
    server.hostname[..host_len].copy_from_slice(&hostname[..host_len]);
    server.hostname_len = host_len;

    let name_len = friendly_name.len().min(MAX_NAME_LEN);
    server.friendly_name[..name_len].copy_from_slice(&friendly_name[..name_len]);
    server.friendly_name_len = name_len;

    server.profile_id = profile_id;

    Ok(id)
}

/// Remove a VPN server
pub fn remove_vpn_server(server_id: u32) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let server = state.vpn_servers.iter_mut().find(|s| s.active && s.id == server_id);

    match server {
        Some(s) => {
            s.active = false;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set VPN server region
pub fn set_vpn_server_region(server_id: u32, region: &[u8]) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let server = state.vpn_servers.iter_mut().find(|s| s.active && s.id == server_id);

    match server {
        Some(s) => {
            let region_len = region.len().min(64);
            s.region[..region_len].copy_from_slice(&region[..region_len]);
            s.region_len = region_len;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

// ============================================================================
// Build Functions
// ============================================================================

/// Configure build settings
pub fn configure_build(settings: BuildSettings) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();
    state.build_settings = settings;
    Ok(())
}

/// Get build settings
pub fn get_build_settings() -> BuildSettings {
    let state = CMAK_STATE.lock();
    BuildSettings {
        include_phonebook: state.build_settings.include_phonebook,
        include_actions: state.build_settings.include_actions,
        include_help: state.build_settings.include_help,
        include_license: state.build_settings.include_license,
        self_extracting: state.build_settings.self_extracting,
        target_version: state.build_settings.target_version,
        include_uninstall: state.build_settings.include_uninstall,
        silent_install: state.build_settings.silent_install,
    }
}

/// Build a profile (simulate building the installer package)
pub fn build_profile(profile_id: u32) -> Result<(), u32> {
    let mut state = CMAK_STATE.lock();

    let profile = state.profiles.iter_mut().find(|p| p.active && p.id == profile_id);

    match profile {
        Some(p) => {
            if p.status == ProfileStatus::Draft {
                return Err(0x80070005); // Must be ready to build
            }
            // In real implementation, would build the installer
            p.status = ProfileStatus::Deployed;
            p.modified_time = 0;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize CMAK module
pub fn init() -> Result<(), &'static str> {
    if CMAK_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let mut state = CMAK_STATE.lock();

    // Reserve ID for example profile
    let profile_id = state.next_id;
    let server_id = state.next_id + 1;
    state.next_id += 2;

    // Create example VPN profile
    {
        let profile = &mut state.profiles[0];
        profile.id = profile_id;
        profile.active = true;
        let name = b"Corporate VPN";
        profile.name[..name.len()].copy_from_slice(name);
        profile.name_len = name.len();
        let svc = b"Company Remote Access";
        profile.service_name[..svc.len()].copy_from_slice(svc);
        profile.service_name_len = svc.len();
        profile.conn_type = ConnectionType::Vpn;
        profile.vpn_protocol = VpnProtocol::L2tpIpsec;
        profile.auth_method = AuthMethod::MsChapV2;
        profile.encryption = EncryptionLevel::Required;
        profile.status = ProfileStatus::Ready;
        let server = b"vpn.company.com";
        profile.primary_server[..server.len()].copy_from_slice(server);
        profile.primary_server_len = server.len();
        profile.hwnd = UserHandle::from_raw(profile_id);
    }

    // Create example VPN server
    {
        let server = &mut state.vpn_servers[0];
        server.id = server_id;
        server.active = true;
        let host = b"vpn.company.com";
        server.hostname[..host.len()].copy_from_slice(host);
        server.hostname_len = host.len();
        let name = b"Primary VPN Gateway";
        server.friendly_name[..name.len()].copy_from_slice(name);
        server.friendly_name_len = name.len();
        server.profile_id = profile_id;
    }

    PROFILE_COUNT.store(1, Ordering::Relaxed);

    Ok(())
}

/// Check if module is initialized
pub fn is_initialized() -> bool {
    CMAK_INITIALIZED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_type() {
        assert_eq!(ConnectionType::default(), ConnectionType::Vpn);
        assert_eq!(ConnectionType::Dialup as u32, 1);
    }

    #[test]
    fn test_vpn_protocol() {
        assert_eq!(VpnProtocol::default(), VpnProtocol::Automatic);
        assert_eq!(VpnProtocol::L2tpIpsec as u32, 2);
    }

    #[test]
    fn test_build_settings() {
        let settings = BuildSettings::new();
        assert!(settings.include_phonebook);
        assert!(settings.self_extracting);
        assert_eq!(settings.target_version, 502);
    }
}
