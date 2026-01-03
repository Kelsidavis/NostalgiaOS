//! Network Dialogs and Connection UI
//!
//! Implements Windows network browsing and connection dialogs following winnetwk.h.
//! Provides UI for mapping network drives, browsing network resources, and
//! network connection management.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/winnetwk.h` - Network API definitions
//! - `shell/shell32/netview.c` - Network browsing
//! - `shell/shell32/netconn.c` - Network connections

use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::HWND;

// ============================================================================
// Constants
// ============================================================================

/// Maximum network name length
const MAX_NET_NAME: usize = 260;

/// Maximum provider name length
const MAX_PROVIDER_NAME: usize = 64;

/// Maximum username length
const MAX_USERNAME: usize = 256;

/// Maximum password length
const MAX_PASSWORD: usize = 256;

/// Maximum comment length
const MAX_COMMENT: usize = 256;

/// Maximum network connections
const MAX_CONNECTIONS: usize = 64;

/// Maximum network resources in browse list
const MAX_RESOURCES: usize = 256;

// ============================================================================
// WNet Error Codes
// ============================================================================

/// Network error codes
pub mod error {
    pub const NO_ERROR: u32 = 0;
    pub const ERROR_NOT_CONNECTED: u32 = 2250;
    pub const ERROR_OPEN_FILES: u32 = 2401;
    pub const ERROR_ACTIVE_CONNECTIONS: u32 = 2402;
    pub const ERROR_DEVICE_IN_USE: u32 = 2404;
    pub const ERROR_BAD_DEVICE: u32 = 1200;
    pub const ERROR_BAD_NET_NAME: u32 = 67;
    pub const ERROR_BAD_PROVIDER: u32 = 1204;
    pub const ERROR_BUSY: u32 = 170;
    pub const ERROR_CANCELLED: u32 = 1223;
    pub const ERROR_CANNOT_OPEN_PROFILE: u32 = 1205;
    pub const ERROR_DEVICE_ALREADY_REMEMBERED: u32 = 1202;
    pub const ERROR_EXTENDED_ERROR: u32 = 1208;
    pub const ERROR_INVALID_ADDRESS: u32 = 487;
    pub const ERROR_INVALID_PARAMETER: u32 = 87;
    pub const ERROR_INVALID_PASSWORD: u32 = 1216;
    pub const ERROR_MORE_DATA: u32 = 234;
    pub const ERROR_NO_MORE_ITEMS: u32 = 259;
    pub const ERROR_NO_NET_OR_BAD_PATH: u32 = 1203;
    pub const ERROR_NO_NETWORK: u32 = 1222;
    pub const ERROR_BAD_PROFILE: u32 = 1206;
    pub const ERROR_NOT_CONTAINER: u32 = 1207;
    pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
    pub const ERROR_NOT_LOGGED_ON: u32 = 1245;
    pub const ERROR_NOT_SUPPORTED: u32 = 50;
    pub const ERROR_SESSION_CREDENTIAL_CONFLICT: u32 = 1219;
}

// ============================================================================
// Resource Types
// ============================================================================

/// Resource scope
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourceScope {
    #[default]
    Connected = 0x00000001,
    GlobalNet = 0x00000002,
    Remembered = 0x00000003,
    Recent = 0x00000004,
    Context = 0x00000005,
}

/// Resource type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourceType {
    #[default]
    Any = 0x00000000,
    Disk = 0x00000001,
    Print = 0x00000002,
    Reserved = 0x00000008,
}

/// Resource display type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisplayType {
    #[default]
    Generic = 0x00000000,
    Domain = 0x00000001,
    Server = 0x00000002,
    Share = 0x00000003,
    File = 0x00000004,
    Group = 0x00000005,
    Network = 0x00000006,
    Root = 0x00000007,
    ShareAdmin = 0x00000008,
    Directory = 0x00000009,
    Tree = 0x0000000A,
    NdsContainer = 0x0000000B,
}

// Resource usage
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ResourceUsage: u32 {
        const CONNECTABLE = 0x00000001;
        const CONTAINER = 0x00000002;
        const NOLOCALDEVICE = 0x00000004;
        const SIBLING = 0x00000008;
        const ATTACHED = 0x00000010;
        const ALL = Self::CONNECTABLE.bits() | Self::CONTAINER.bits() | Self::ATTACHED.bits();
    }
}

// ============================================================================
// Connection Flags
// ============================================================================

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ConnectFlags: u32 {
        /// Update profile with connection
        const UPDATE_PROFILE = 0x00000001;
        /// Update recent list
        const UPDATE_RECENT = 0x00000002;
        /// Temporary connection
        const TEMPORARY = 0x00000004;
        /// Interactive (prompt for credentials)
        const INTERACTIVE = 0x00000008;
        /// Prompt if needed
        const PROMPT = 0x00000010;
        /// Redirect device
        const REDIRECT = 0x00000080;
        /// Current media
        const CURRENT_MEDIA = 0x00000200;
        /// Deferred connection
        const DEFERRED = 0x00000400;
        /// Windows 2000 provider type
        const PROVIDER = 0x00001000;
        /// Command line interface
        const COMMANDLINE = 0x00000800;
        /// Command-line credentials saved
        const CMD_SAVECRED = 0x00001000;
        /// Credentials dialog
        const CRED_RESET = 0x00002000;
    }
}

// ============================================================================
// Disconnect Flags
// ============================================================================

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct DisconnectFlags: u32 {
        /// Update profile
        const UPDATE_PROFILE = 0x00000001;
        /// Force disconnect
        const FORCE = 0x00000002;
    }
}

// ============================================================================
// NETRESOURCE Structure
// ============================================================================

/// Network resource information
#[derive(Debug, Clone)]
pub struct NetResource {
    /// Resource scope
    pub scope: ResourceScope,
    /// Resource type
    pub resource_type: ResourceType,
    /// Display type
    pub display_type: DisplayType,
    /// Usage flags
    pub usage: ResourceUsage,
    /// Local name (e.g., "Z:")
    pub local_name: [u8; MAX_NET_NAME],
    /// Remote name (e.g., "\\\\server\\share")
    pub remote_name: [u8; MAX_NET_NAME],
    /// Comment/description
    pub comment: [u8; MAX_COMMENT],
    /// Provider name
    pub provider: [u8; MAX_PROVIDER_NAME],
}

impl NetResource {
    pub const fn new() -> Self {
        Self {
            scope: ResourceScope::Connected,
            resource_type: ResourceType::Any,
            display_type: DisplayType::Generic,
            usage: ResourceUsage::empty(),
            local_name: [0u8; MAX_NET_NAME],
            remote_name: [0u8; MAX_NET_NAME],
            comment: [0u8; MAX_COMMENT],
            provider: [0u8; MAX_PROVIDER_NAME],
        }
    }

    pub fn set_local_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NET_NAME - 1);
        self.local_name[..len].copy_from_slice(&name[..len]);
        self.local_name[len] = 0;
    }

    pub fn set_remote_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NET_NAME - 1);
        self.remote_name[..len].copy_from_slice(&name[..len]);
        self.remote_name[len] = 0;
    }

    pub fn set_comment(&mut self, comment: &[u8]) {
        let len = comment.len().min(MAX_COMMENT - 1);
        self.comment[..len].copy_from_slice(&comment[..len]);
        self.comment[len] = 0;
    }

    pub fn set_provider(&mut self, provider: &[u8]) {
        let len = provider.len().min(MAX_PROVIDER_NAME - 1);
        self.provider[..len].copy_from_slice(&provider[..len]);
        self.provider[len] = 0;
    }
}

impl Default for NetResource {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Network Connection State
// ============================================================================

/// Active network connection
#[derive(Debug)]
struct NetworkConnection {
    in_use: bool,
    resource: NetResource,
    username: [u8; MAX_USERNAME],
    remembered: bool,
    connected: bool,
}

impl NetworkConnection {
    const fn new() -> Self {
        Self {
            in_use: false,
            resource: NetResource::new(),
            username: [0u8; MAX_USERNAME],
            remembered: false,
            connected: false,
        }
    }
}

// ============================================================================
// Enumeration Handle
// ============================================================================

/// Network enumeration handle
#[derive(Debug)]
struct EnumHandle {
    in_use: bool,
    id: u32,
    scope: ResourceScope,
    resource_type: ResourceType,
    usage: ResourceUsage,
    current_index: usize,
}

impl EnumHandle {
    const fn new() -> Self {
        Self {
            in_use: false,
            id: 0,
            scope: ResourceScope::Connected,
            resource_type: ResourceType::Any,
            usage: ResourceUsage::empty(),
            current_index: 0,
        }
    }
}

/// Maximum enum handles
const MAX_ENUM_HANDLES: usize = 16;

// ============================================================================
// Connection Dialog Flags
// ============================================================================

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ConnDlgFlags: u32 {
        /// Read-only path
        const READONLY_PATH = 0x00000001;
        /// Connection dialog
        const CONN_POINT = 0x00000002;
        /// Use MRU list
        const USE_MRU = 0x00000004;
        /// Hide box
        const HIDE_BOX = 0x00000008;
        /// Persist connection
        const PERSIST = 0x00000010;
        /// Don't persist
        const NOT_PERSIST = 0x00000020;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct DiscDlgFlags: u32 {
        /// Update profile
        const UPDATE_PROFILE = 0x00000001;
        /// Don't confirm
        const NO_FORCE = 0x00000040;
    }
}

// ============================================================================
// Dialog Structures
// ============================================================================

/// Connection dialog structure
#[derive(Debug, Clone)]
pub struct ConnectDlgStruct {
    pub hwnd_owner: HWND,
    pub net_resource: NetResource,
    pub flags: ConnDlgFlags,
    pub dev_num: u32,
}

impl ConnectDlgStruct {
    pub fn new(hwnd_owner: HWND) -> Self {
        Self {
            hwnd_owner,
            net_resource: NetResource::new(),
            flags: ConnDlgFlags::empty(),
            dev_num: 0,
        }
    }
}

/// Disconnect dialog structure
#[derive(Debug, Clone)]
pub struct DisconnectDlgStruct {
    pub hwnd_owner: HWND,
    pub local_name: [u8; MAX_NET_NAME],
    pub remote_name: [u8; MAX_NET_NAME],
    pub flags: DiscDlgFlags,
}

impl DisconnectDlgStruct {
    pub fn new(hwnd_owner: HWND) -> Self {
        Self {
            hwnd_owner,
            local_name: [0u8; MAX_NET_NAME],
            remote_name: [0u8; MAX_NET_NAME],
            flags: DiscDlgFlags::empty(),
        }
    }
}

// ============================================================================
// Universal Naming Convention (UNC)
// ============================================================================

/// UNC info levels
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniversalInfoLevel {
    LocalDrive = 1,
    RemoteName = 2,
    LocalPath = 3,
}

/// Universal name info (Level 1)
#[derive(Debug, Clone)]
pub struct UniversalNameInfo {
    pub universal_name: [u8; MAX_NET_NAME],
}

impl UniversalNameInfo {
    pub const fn new() -> Self {
        Self {
            universal_name: [0u8; MAX_NET_NAME],
        }
    }
}

/// Remote name info (Level 2)
#[derive(Debug, Clone)]
pub struct RemoteNameInfo {
    pub universal_name: [u8; MAX_NET_NAME],
    pub connection_name: [u8; MAX_NET_NAME],
    pub remaining_path: [u8; MAX_NET_NAME],
}

impl RemoteNameInfo {
    pub const fn new() -> Self {
        Self {
            universal_name: [0u8; MAX_NET_NAME],
            connection_name: [0u8; MAX_NET_NAME],
            remaining_path: [0u8; MAX_NET_NAME],
        }
    }
}

// ============================================================================
// Network Provider
// ============================================================================

/// Network provider types
pub mod provider {
    pub const WNNC_NET_MSNET: u32 = 0x00010000;
    pub const WNNC_NET_SMB: u32 = 0x00020000;
    pub const WNNC_NET_NETWARE: u32 = 0x00030000;
    pub const WNNC_NET_VINES: u32 = 0x00040000;
    pub const WNNC_NET_10NET: u32 = 0x00050000;
    pub const WNNC_NET_LOCUS: u32 = 0x00060000;
    pub const WNNC_NET_SUN_PC_NFS: u32 = 0x00070000;
    pub const WNNC_NET_LANSTEP: u32 = 0x00080000;
    pub const WNNC_NET_9TILES: u32 = 0x00090000;
    pub const WNNC_NET_LANTASTIC: u32 = 0x000A0000;
    pub const WNNC_NET_AS400: u32 = 0x000B0000;
    pub const WNNC_NET_FTP_NFS: u32 = 0x000C0000;
    pub const WNNC_NET_PATHWORKS: u32 = 0x000D0000;
    pub const WNNC_NET_LIFENET: u32 = 0x000E0000;
    pub const WNNC_NET_POWERLAN: u32 = 0x000F0000;
    pub const WNNC_NET_BWNFS: u32 = 0x00100000;
    pub const WNNC_NET_COGENT: u32 = 0x00110000;
    pub const WNNC_NET_FARALLON: u32 = 0x00120000;
    pub const WNNC_NET_APPLETALK: u32 = 0x00130000;
    pub const WNNC_NET_INTERGRAPH: u32 = 0x00140000;
    pub const WNNC_NET_SYMFONET: u32 = 0x00150000;
    pub const WNNC_NET_CLEARCASE: u32 = 0x00160000;
    pub const WNNC_NET_FRONTIER: u32 = 0x00170000;
    pub const WNNC_NET_BMC: u32 = 0x00180000;
    pub const WNNC_NET_DCE: u32 = 0x00190000;
    pub const WNNC_NET_AVID: u32 = 0x001A0000;
    pub const WNNC_NET_DOCUSPACE: u32 = 0x001B0000;
    pub const WNNC_NET_MANGOSOFT: u32 = 0x001C0000;
    pub const WNNC_NET_SERNET: u32 = 0x001D0000;
    pub const WNNC_NET_RIVERFRONT1: u32 = 0x001E0000;
    pub const WNNC_NET_RIVERFRONT2: u32 = 0x001F0000;
    pub const WNNC_NET_DECORB: u32 = 0x00200000;
    pub const WNNC_NET_PROTSTOR: u32 = 0x00210000;
    pub const WNNC_NET_FJ_REDIR: u32 = 0x00220000;
    pub const WNNC_NET_DISTINCT: u32 = 0x00230000;
    pub const WNNC_NET_TWINS: u32 = 0x00240000;
    pub const WNNC_NET_RDR2SAMPLE: u32 = 0x00250000;
    pub const WNNC_NET_CSC: u32 = 0x00260000;
    pub const WNNC_NET_3IN1: u32 = 0x00270000;
    pub const WNNC_NET_EXTENDNET: u32 = 0x00290000;
    pub const WNNC_NET_STAC: u32 = 0x002A0000;
    pub const WNNC_NET_FOXBAT: u32 = 0x002B0000;
    pub const WNNC_NET_YAHOO: u32 = 0x002C0000;
    pub const WNNC_NET_EXIFS: u32 = 0x002D0000;
    pub const WNNC_NET_DAV: u32 = 0x002E0000;
    pub const WNNC_NET_KNOWARE: u32 = 0x002F0000;
    pub const WNNC_NET_OBJECT_DIRE: u32 = 0x00300000;
    pub const WNNC_NET_MASFAX: u32 = 0x00310000;
    pub const WNNC_NET_HOB_NFS: u32 = 0x00320000;
    pub const WNNC_NET_SHIVA: u32 = 0x00330000;
    pub const WNNC_NET_IBMAL: u32 = 0x00340000;
    pub const WNNC_NET_LOCK: u32 = 0x00350000;
    pub const WNNC_NET_TERMSRV: u32 = 0x00360000;
    pub const WNNC_NET_SRT: u32 = 0x00370000;
    pub const WNNC_NET_QUINCY: u32 = 0x00380000;
}

// ============================================================================
// State
// ============================================================================

static NETWORK_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_ENUM_ID: AtomicU32 = AtomicU32::new(1);
static CONNECTIONS: SpinLock<[NetworkConnection; MAX_CONNECTIONS]> = SpinLock::new(
    [const { NetworkConnection::new() }; MAX_CONNECTIONS]
);
static ENUM_HANDLES: SpinLock<[EnumHandle; MAX_ENUM_HANDLES]> = SpinLock::new(
    [const { EnumHandle::new() }; MAX_ENUM_HANDLES]
);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize network dialogs subsystem
pub fn init() {
    if NETWORK_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[NETWORK] Initializing network dialogs...");
    crate::serial_println!("[NETWORK] Network dialogs initialized");
}

// ============================================================================
// WNet Connection Functions
// ============================================================================

/// Add a network connection
pub fn wnet_add_connection(
    remote_name: &[u8],
    password: Option<&[u8]>,
    local_name: Option<&[u8]>,
) -> u32 {
    let mut resource = NetResource::new();
    resource.resource_type = ResourceType::Disk;
    resource.set_remote_name(remote_name);
    if let Some(local) = local_name {
        resource.set_local_name(local);
    }

    wnet_add_connection2(&resource, password, None, ConnectFlags::empty())
}

/// Add a network connection (extended)
pub fn wnet_add_connection2(
    resource: &NetResource,
    password: Option<&[u8]>,
    username: Option<&[u8]>,
    flags: ConnectFlags,
) -> u32 {
    let _ = password;

    let mut connections = CONNECTIONS.lock();

    // Find free slot
    let slot = connections.iter_mut().find(|c| !c.in_use);

    let conn = match slot {
        Some(c) => c,
        None => return error::ERROR_NOT_ENOUGH_MEMORY,
    };

    conn.in_use = true;
    conn.resource = resource.clone();
    conn.remembered = flags.contains(ConnectFlags::UPDATE_PROFILE);
    conn.connected = true;

    if let Some(user) = username {
        let len = user.len().min(MAX_USERNAME - 1);
        conn.username[..len].copy_from_slice(&user[..len]);
        conn.username[len] = 0;
    }

    error::NO_ERROR
}

/// Add a network connection (extended 3)
pub fn wnet_add_connection3(
    hwnd_owner: HWND,
    resource: &NetResource,
    password: Option<&[u8]>,
    username: Option<&[u8]>,
    flags: ConnectFlags,
) -> u32 {
    let _ = hwnd_owner;
    wnet_add_connection2(resource, password, username, flags)
}

/// Cancel a network connection
pub fn wnet_cancel_connection(name: &[u8], force: bool) -> u32 {
    let flags = if force {
        DisconnectFlags::FORCE
    } else {
        DisconnectFlags::empty()
    };

    wnet_cancel_connection2(name, flags)
}

/// Cancel a network connection (extended)
pub fn wnet_cancel_connection2(name: &[u8], flags: DisconnectFlags) -> u32 {
    let mut connections = CONNECTIONS.lock();

    for conn in connections.iter_mut() {
        if !conn.in_use {
            continue;
        }

        // Check if local or remote name matches
        let local_matches = name_matches(&conn.resource.local_name, name);
        let remote_matches = name_matches(&conn.resource.remote_name, name);

        if local_matches || remote_matches {
            if !flags.contains(DisconnectFlags::FORCE) && conn.connected {
                // Would check for open files here
            }

            conn.in_use = false;
            conn.connected = false;

            if flags.contains(DisconnectFlags::UPDATE_PROFILE) {
                conn.remembered = false;
            }

            return error::NO_ERROR;
        }
    }

    error::ERROR_NOT_CONNECTED
}

/// Get connection details
pub fn wnet_get_connection(local_name: &[u8], remote_name: &mut [u8]) -> (u32, usize) {
    let connections = CONNECTIONS.lock();

    for conn in connections.iter() {
        if !conn.in_use {
            continue;
        }

        if name_matches(&conn.resource.local_name, local_name) {
            let len = str_len(&conn.resource.remote_name);
            if len <= remote_name.len() {
                remote_name[..len].copy_from_slice(&conn.resource.remote_name[..len]);
                return (error::NO_ERROR, len);
            } else {
                return (error::ERROR_MORE_DATA, len);
            }
        }
    }

    (error::ERROR_NOT_CONNECTED, 0)
}

/// Get user name for a network resource
pub fn wnet_get_user(name: Option<&[u8]>, user_name: &mut [u8]) -> (u32, usize) {
    let connections = CONNECTIONS.lock();

    if let Some(resource_name) = name {
        for conn in connections.iter() {
            if !conn.in_use {
                continue;
            }

            let matches = name_matches(&conn.resource.local_name, resource_name)
                || name_matches(&conn.resource.remote_name, resource_name);

            if matches {
                let len = str_len(&conn.username);
                if len <= user_name.len() {
                    user_name[..len].copy_from_slice(&conn.username[..len]);
                    return (error::NO_ERROR, len);
                } else {
                    return (error::ERROR_MORE_DATA, len);
                }
            }
        }
    }

    // Return default user
    let default = b"User";
    let len = default.len().min(user_name.len());
    user_name[..len].copy_from_slice(&default[..len]);
    (error::NO_ERROR, len)
}

// ============================================================================
// WNet Enumeration Functions
// ============================================================================

/// Open network resource enumeration
pub fn wnet_open_enum(
    scope: ResourceScope,
    resource_type: ResourceType,
    usage: ResourceUsage,
    _resource: Option<&NetResource>,
) -> Result<u32, u32> {
    let mut handles = ENUM_HANDLES.lock();

    // Find free handle
    let slot_idx = handles.iter().position(|h| !h.in_use);

    let idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::ERROR_NOT_ENOUGH_MEMORY),
    };

    let id = NEXT_ENUM_ID.fetch_add(1, Ordering::SeqCst);

    let handle = &mut handles[idx];
    handle.in_use = true;
    handle.id = id;
    handle.scope = scope;
    handle.resource_type = resource_type;
    handle.usage = usage;
    handle.current_index = 0;

    Ok(id)
}

/// Enumerate network resources
pub fn wnet_enum_resource(
    handle_id: u32,
    resources: &mut [NetResource],
    count: &mut usize,
) -> u32 {
    let mut handles = ENUM_HANDLES.lock();

    let handle = match handles.iter_mut().find(|h| h.in_use && h.id == handle_id) {
        Some(h) => h,
        None => return error::ERROR_INVALID_PARAMETER,
    };

    let connections = CONNECTIONS.lock();

    let mut returned = 0;
    let mut index = handle.current_index;

    for conn in connections.iter().skip(index) {
        if !conn.in_use {
            index += 1;
            continue;
        }

        // Filter by scope
        if handle.scope == ResourceScope::Connected && !conn.connected {
            index += 1;
            continue;
        }

        // Filter by type
        if handle.resource_type != ResourceType::Any
            && conn.resource.resource_type != handle.resource_type
        {
            index += 1;
            continue;
        }

        if returned >= resources.len() {
            break;
        }

        resources[returned] = conn.resource.clone();
        returned += 1;
        index += 1;
    }

    handle.current_index = index;
    *count = returned;

    if returned == 0 {
        error::ERROR_NO_MORE_ITEMS
    } else {
        error::NO_ERROR
    }
}

/// Close network resource enumeration
pub fn wnet_close_enum(handle_id: u32) -> u32 {
    let mut handles = ENUM_HANDLES.lock();

    for handle in handles.iter_mut() {
        if handle.in_use && handle.id == handle_id {
            handle.in_use = false;
            return error::NO_ERROR;
        }
    }

    error::ERROR_INVALID_PARAMETER
}

// ============================================================================
// WNet Dialog Functions
// ============================================================================

/// Display the "Map Network Drive" dialog
pub fn wnet_connection_dialog(hwnd: HWND, resource_type: ResourceType) -> u32 {
    let _ = (hwnd, resource_type);

    // Would display connection dialog
    crate::serial_println!("[NETWORK] Connection dialog requested");

    error::NO_ERROR
}

/// Display connection dialog (extended)
pub fn wnet_connection_dialog1(dlg: &mut ConnectDlgStruct) -> u32 {
    let _ = dlg;

    // Would display connection dialog
    crate::serial_println!("[NETWORK] Connection dialog 1 requested");

    error::NO_ERROR
}

/// Display the "Disconnect Network Drive" dialog
pub fn wnet_disconnect_dialog(hwnd: HWND, resource_type: ResourceType) -> u32 {
    let _ = (hwnd, resource_type);

    // Would display disconnect dialog
    crate::serial_println!("[NETWORK] Disconnect dialog requested");

    error::NO_ERROR
}

/// Display disconnect dialog (extended)
pub fn wnet_disconnect_dialog1(dlg: &DisconnectDlgStruct) -> u32 {
    let _ = dlg;

    // Would display disconnect dialog
    crate::serial_println!("[NETWORK] Disconnect dialog 1 requested");

    error::NO_ERROR
}

// ============================================================================
// WNet Information Functions
// ============================================================================

/// Get provider name
pub fn wnet_get_provider_name(net_type: u32, provider_name: &mut [u8]) -> (u32, usize) {
    let name: &[u8] = match net_type {
        provider::WNNC_NET_SMB => b"Microsoft Windows Network",
        provider::WNNC_NET_NETWARE => b"Novell NetWare",
        provider::WNNC_NET_DAV => b"Web Client Network",
        _ => return (error::ERROR_BAD_PROVIDER, 0),
    };

    let len = name.len().min(provider_name.len());
    provider_name[..len].copy_from_slice(&name[..len]);
    (error::NO_ERROR, len)
}

/// Get network information
pub fn wnet_get_network_information(
    provider: &[u8],
    net_info: &mut [u32],
) -> u32 {
    if net_info.len() < 4 {
        return error::ERROR_INVALID_PARAMETER;
    }

    let _ = provider;

    // Return capabilities
    net_info[0] = 0x0001; // Version
    net_info[1] = 0x0001; // Supports connection
    net_info[2] = 0x0001; // Supports enumeration
    net_info[3] = 0x0000; // No special features

    error::NO_ERROR
}

/// Get last extended error
pub fn wnet_get_last_error(
    error_code: &mut u32,
    error_buf: &mut [u8],
    name_buf: &mut [u8],
) -> u32 {
    // No extended error
    *error_code = 0;
    if !error_buf.is_empty() {
        error_buf[0] = 0;
    }
    if !name_buf.is_empty() {
        name_buf[0] = 0;
    }

    error::NO_ERROR
}

/// Get resource information
pub fn wnet_get_resource_information(
    resource: &NetResource,
    buffer: &mut NetResource,
    remaining_path: &mut [u8],
) -> u32 {
    *buffer = resource.clone();

    if !remaining_path.is_empty() {
        remaining_path[0] = 0;
    }

    error::NO_ERROR
}

/// Get resource parent
pub fn wnet_get_resource_parent(
    resource: &NetResource,
    buffer: &mut NetResource,
) -> u32 {
    *buffer = resource.clone();

    // Clear the remote name to just parent path
    // e.g., \\server\share -> \\server
    let remote = &resource.remote_name;
    let len = str_len(remote);

    if len > 2 && remote[0] == b'\\' && remote[1] == b'\\' {
        // Find last backslash
        let mut last_slash = 2;
        for i in 2..len {
            if remote[i] == b'\\' {
                last_slash = i;
            }
        }

        if last_slash > 2 {
            buffer.remote_name[..last_slash].copy_from_slice(&remote[..last_slash]);
            buffer.remote_name[last_slash] = 0;
            buffer.display_type = DisplayType::Server;
        }
    }

    error::NO_ERROR
}

// ============================================================================
// UNC Path Functions
// ============================================================================

/// Get universal name from local path
pub fn wnet_get_universal_name(
    local_path: &[u8],
    info_level: UniversalInfoLevel,
    buffer: &mut [u8],
) -> (u32, usize) {
    let connections = CONNECTIONS.lock();

    // Check if path starts with a drive letter
    if local_path.len() < 2 || local_path[1] != b':' {
        return (error::ERROR_NOT_CONNECTED, 0);
    }

    let drive_letter = local_path[0].to_ascii_uppercase();
    let drive_name = [drive_letter, b':', 0];

    // Find matching connection
    for conn in connections.iter() {
        if !conn.in_use {
            continue;
        }

        if conn.resource.local_name[0].to_ascii_uppercase() == drive_letter {
            let remote_len = str_len(&conn.resource.remote_name);
            let remaining_path = if local_path.len() > 2 {
                &local_path[2..]
            } else {
                &[][..]
            };
            let remaining_len = str_len(remaining_path);

            match info_level {
                UniversalInfoLevel::LocalDrive => {
                    let total_len = remote_len + remaining_len;
                    if buffer.len() < total_len {
                        return (error::ERROR_MORE_DATA, total_len);
                    }
                    buffer[..remote_len].copy_from_slice(&conn.resource.remote_name[..remote_len]);
                    if remaining_len > 0 {
                        buffer[remote_len..remote_len + remaining_len]
                            .copy_from_slice(&remaining_path[..remaining_len]);
                    }
                    return (error::NO_ERROR, total_len);
                }
                UniversalInfoLevel::RemoteName => {
                    // Return RemoteNameInfo
                    let needed = core::mem::size_of::<RemoteNameInfo>();
                    if buffer.len() < needed {
                        return (error::ERROR_MORE_DATA, needed);
                    }
                    return (error::NO_ERROR, needed);
                }
                UniversalInfoLevel::LocalPath => {
                    let len = drive_name.len();
                    if buffer.len() < len {
                        return (error::ERROR_MORE_DATA, len);
                    }
                    buffer[..len].copy_from_slice(&drive_name);
                    return (error::NO_ERROR, len);
                }
            }
        }
    }

    (error::ERROR_NOT_CONNECTED, 0)
}

// ============================================================================
// Browse Dialog
// ============================================================================

// Browse dialog flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct BrowseFlags: u32 {
        /// Browse for computers
        const BIF_BROWSEFORCOMPUTER = 0x1000;
        /// Browse for printers
        const BIF_BROWSEFORPRINTER = 0x2000;
        /// Browse for shares
        const BIF_DONTGOBELOWDOMAIN = 0x0002;
        /// Include files
        const BIF_BROWSEINCLUDEFILES = 0x4000;
    }
}

/// Network browse dialog info
#[derive(Debug, Clone)]
pub struct NetBrowseInfo {
    pub hwnd_owner: HWND,
    pub root: NetResource,
    pub display_name: [u8; MAX_NET_NAME],
    pub title: [u8; 128],
    pub flags: BrowseFlags,
}

impl NetBrowseInfo {
    pub fn new(hwnd_owner: HWND) -> Self {
        Self {
            hwnd_owner,
            root: NetResource::new(),
            display_name: [0u8; MAX_NET_NAME],
            title: [0u8; 128],
            flags: BrowseFlags::empty(),
        }
    }
}

/// Display network browse dialog
pub fn wnet_browse_dialog(info: &mut NetBrowseInfo) -> u32 {
    let _ = info;

    // Would display browse dialog
    crate::serial_println!("[NETWORK] Browse dialog requested");

    error::NO_ERROR
}

// ============================================================================
// Helper Functions
// ============================================================================

fn str_len(s: &[u8]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

fn name_matches(stored: &[u8], search: &[u8]) -> bool {
    let stored_len = str_len(stored);
    let search_len = str_len(search);

    if stored_len != search_len {
        return false;
    }

    for i in 0..stored_len {
        if stored[i].to_ascii_uppercase() != search[i].to_ascii_uppercase() {
            return false;
        }
    }

    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Network statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkStats {
    pub initialized: bool,
    pub connection_count: u32,
    pub remembered_count: u32,
    pub enum_handle_count: u32,
}

/// Get network statistics
pub fn get_stats() -> NetworkStats {
    let connections = CONNECTIONS.lock();
    let handles = ENUM_HANDLES.lock();

    let mut connected = 0u32;
    let mut remembered = 0u32;

    for conn in connections.iter() {
        if conn.in_use {
            connected += 1;
            if conn.remembered {
                remembered += 1;
            }
        }
    }

    let handle_count = handles.iter().filter(|h| h.in_use).count() as u32;

    NetworkStats {
        initialized: NETWORK_INITIALIZED.load(Ordering::Relaxed),
        connection_count: connected,
        remembered_count: remembered,
        enum_handle_count: handle_count,
    }
}
