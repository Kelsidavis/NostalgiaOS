//! Internet Authentication Service (IAS) Management
//!
//! Windows Server 2003 implementation of IAS snap-in (ias.msc).
//! Provides RADIUS server configuration for network access authentication.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex as SpinLock;
use bitflags::bitflags;
use crate::win32k::user::UserHandle;

type HWND = UserHandle;

/// Maximum RADIUS clients
const MAX_RADIUS_CLIENTS: usize = 128;

/// Maximum RADIUS policies
const MAX_POLICIES: usize = 64;

/// Maximum connection request policies
const MAX_CONNECTION_POLICIES: usize = 32;

/// Maximum conditions per policy
const MAX_CONDITIONS: usize = 16;

/// Maximum profile attributes
const MAX_PROFILE_ATTRIBUTES: usize = 32;

/// Maximum RADIUS server groups
const MAX_SERVER_GROUPS: usize = 16;

/// Maximum servers per group
const MAX_SERVERS_PER_GROUP: usize = 8;

/// Maximum vendor-specific attributes
const MAX_VSA: usize = 64;

// ============================================================================
// RADIUS Client Types
// ============================================================================

/// RADIUS client vendor type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RadiusVendor {
    /// Standard RADIUS
    RadiusStandard = 0,
    /// Microsoft
    Microsoft = 311,
    /// Cisco
    Cisco = 9,
    /// 3Com
    ThreeCom = 43,
    /// Ascend
    Ascend = 529,
    /// Nortel
    Nortel = 562,
    /// Juniper
    Juniper = 2636,
    /// Custom vendor
    Custom = 0xFFFF,
}

impl Default for RadiusVendor {
    fn default() -> Self {
        Self::RadiusStandard
    }
}

/// RADIUS client status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ClientStatus {
    /// Client is disabled
    Disabled = 0,
    /// Client is enabled
    Enabled = 1,
    /// Client is pending verification
    Pending = 2,
}

impl Default for ClientStatus {
    fn default() -> Self {
        Self::Disabled
    }
}

/// RADIUS client configuration
#[derive(Debug, Clone, Copy)]
pub struct RadiusClient {
    /// Client ID
    pub id: u32,
    /// Client in use
    pub in_use: bool,
    /// Friendly name
    pub friendly_name: [u8; 64],
    /// Friendly name length
    pub friendly_name_len: usize,
    /// IP address
    pub ip_address: [u8; 4],
    /// Subnet mask (for address range)
    pub subnet_mask: [u8; 4],
    /// Shared secret (encrypted in memory)
    pub shared_secret: [u8; 128],
    /// Secret length
    pub secret_len: usize,
    /// Vendor type
    pub vendor: RadiusVendor,
    /// Custom vendor ID (if vendor is Custom)
    pub custom_vendor_id: u32,
    /// Client status
    pub status: ClientStatus,
    /// Enable message authenticator
    pub require_message_auth: bool,
    /// Enable NAP capability
    pub nap_capable: bool,
    /// Created timestamp
    pub created: u64,
    /// Last authentication
    pub last_auth: u64,
    /// Authentication count
    pub auth_count: u64,
    /// Reject count
    pub reject_count: u64,
}

impl RadiusClient {
    pub const fn new() -> Self {
        Self {
            id: 0,
            in_use: false,
            friendly_name: [0u8; 64],
            friendly_name_len: 0,
            ip_address: [0u8; 4],
            subnet_mask: [255, 255, 255, 255],
            shared_secret: [0u8; 128],
            secret_len: 0,
            vendor: RadiusVendor::RadiusStandard,
            custom_vendor_id: 0,
            status: ClientStatus::Disabled,
            require_message_auth: true,
            nap_capable: false,
            created: 0,
            last_auth: 0,
            auth_count: 0,
            reject_count: 0,
        }
    }
}

// ============================================================================
// Remote Access Policy Types
// ============================================================================

/// Policy condition type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ConditionType {
    /// Windows groups
    WindowsGroups = 0,
    /// Machine groups
    MachineGroups = 1,
    /// Day and time restrictions
    DayTimeRestrictions = 2,
    /// Called station ID (phone number or MAC)
    CalledStationId = 3,
    /// Calling station ID
    CallingStationId = 4,
    /// NAS identifier
    NasIdentifier = 5,
    /// NAS IP address
    NasIpAddress = 6,
    /// NAS port type
    NasPortType = 7,
    /// Service type
    ServiceType = 8,
    /// Tunnel type
    TunnelType = 9,
    /// Framed protocol
    FramedProtocol = 10,
    /// Client vendor
    ClientVendor = 11,
    /// Client friendly name
    ClientFriendlyName = 12,
    /// Authentication type
    AuthenticationType = 13,
    /// EAP type
    EapType = 14,
    /// HCAP location groups
    HcapLocationGroups = 15,
    /// HCAP user groups
    HcapUserGroups = 16,
    /// Allowed EAP types
    AllowedEapTypes = 17,
    /// Health policies
    HealthPolicies = 18,
}

impl Default for ConditionType {
    fn default() -> Self {
        Self::WindowsGroups
    }
}

/// Policy condition
#[derive(Debug, Clone, Copy)]
pub struct PolicyCondition {
    /// Condition in use
    pub in_use: bool,
    /// Condition type
    pub condition_type: ConditionType,
    /// Condition value (interpretation depends on type)
    pub value: [u8; 256],
    /// Value length
    pub value_len: usize,
    /// Match type (0=matches, 1=not matches)
    pub match_type: u8,
}

impl PolicyCondition {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            condition_type: ConditionType::WindowsGroups,
            value: [0u8; 256],
            value_len: 0,
            match_type: 0,
        }
    }
}

/// Authentication type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthenticationType {
    /// PAP (Password Authentication Protocol)
    Pap = 0,
    /// CHAP (Challenge Handshake Authentication Protocol)
    Chap = 1,
    /// MS-CHAP v1
    MsChapV1 = 2,
    /// MS-CHAP v2
    MsChapV2 = 3,
    /// EAP (Extensible Authentication Protocol)
    Eap = 4,
    /// Unauthenticated
    Unauthenticated = 5,
}

impl Default for AuthenticationType {
    fn default() -> Self {
        Self::MsChapV2
    }
}

/// EAP type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EapType {
    /// MD5-Challenge
    Md5Challenge = 4,
    /// Generic Token Card
    Gtc = 6,
    /// TLS
    Tls = 13,
    /// TTLS
    Ttls = 21,
    /// PEAP
    Peap = 25,
    /// MS-CHAP v2
    MsChapV2 = 26,
    /// SIM
    Sim = 18,
    /// AKA
    Aka = 23,
}

impl Default for EapType {
    fn default() -> Self {
        Self::Peap
    }
}

bitflags! {
    /// Authentication method flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AuthMethodFlags: u32 {
        /// Allow PAP
        const PAP = 0x0001;
        /// Allow CHAP
        const CHAP = 0x0002;
        /// Allow MS-CHAP v1
        const MSCHAP_V1 = 0x0004;
        /// Allow MS-CHAP v2
        const MSCHAP_V2 = 0x0008;
        /// Allow EAP
        const EAP = 0x0010;
        /// Allow unauthenticated
        const UNAUTHENTICATED = 0x0020;
    }
}

impl Default for AuthMethodFlags {
    fn default() -> Self {
        Self::MSCHAP_V2 | Self::EAP
    }
}

/// Encryption policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EncryptionPolicy {
    /// No encryption
    NoEncryption = 0,
    /// Basic (40-bit)
    Basic = 1,
    /// Strong (56-bit)
    Strong = 2,
    /// Strongest (128-bit)
    Strongest = 3,
}

impl Default for EncryptionPolicy {
    fn default() -> Self {
        Self::Strongest
    }
}

bitflags! {
    /// Encryption flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct EncryptionFlags: u32 {
        /// No encryption allowed
        const NO_ENCRYPTION = 0x0001;
        /// Basic encryption (40-bit)
        const BASIC = 0x0002;
        /// Strong encryption (56-bit)
        const STRONG = 0x0004;
        /// Strongest encryption (128-bit)
        const STRONGEST = 0x0008;
    }
}

impl Default for EncryptionFlags {
    fn default() -> Self {
        Self::STRONGEST
    }
}

/// Remote access profile
#[derive(Debug, Clone, Copy)]
pub struct RemoteAccessProfile {
    /// Dial-in constraints
    pub dial_in_constraints: DialInConstraints,
    /// IP settings
    pub ip_settings: IpSettings,
    /// Multilink settings
    pub multilink_settings: MultilinkSettings,
    /// Authentication methods
    pub auth_methods: AuthMethodFlags,
    /// Encryption settings
    pub encryption: EncryptionFlags,
    /// Advanced attributes
    pub attributes: [ProfileAttribute; MAX_PROFILE_ATTRIBUTES],
    /// Attribute count
    pub attribute_count: usize,
}

impl RemoteAccessProfile {
    pub const fn new() -> Self {
        Self {
            dial_in_constraints: DialInConstraints::new(),
            ip_settings: IpSettings::new(),
            multilink_settings: MultilinkSettings::new(),
            auth_methods: AuthMethodFlags::MSCHAP_V2,
            encryption: EncryptionFlags::STRONGEST,
            attributes: [const { ProfileAttribute::new() }; MAX_PROFILE_ATTRIBUTES],
            attribute_count: 0,
        }
    }
}

/// Dial-in constraints
#[derive(Debug, Clone, Copy)]
pub struct DialInConstraints {
    /// Idle timeout (minutes, 0 = no limit)
    pub idle_timeout: u32,
    /// Session timeout (minutes, 0 = no limit)
    pub session_timeout: u32,
    /// Day/time restrictions (bitmap)
    pub day_time_restrictions: [u8; 21],
    /// Restrict dial-in media
    pub restrict_dial_in_media: bool,
    /// Allowed NAS port types (bitmap)
    pub allowed_port_types: u32,
}

impl DialInConstraints {
    pub const fn new() -> Self {
        Self {
            idle_timeout: 0,
            session_timeout: 0,
            day_time_restrictions: [0xFF; 21],
            restrict_dial_in_media: false,
            allowed_port_types: 0xFFFFFFFF,
        }
    }
}

/// IP settings for remote access
#[derive(Debug, Clone, Copy)]
pub struct IpSettings {
    /// IP address policy (0=server assigns, 1=client requests, 2=static)
    pub ip_address_policy: u8,
    /// Static IP address (if policy is static)
    pub static_ip: [u8; 4],
    /// IP filters inbound
    pub ip_filters_in: [IpFilter; 8],
    /// Inbound filter count
    pub filter_in_count: usize,
    /// IP filters outbound
    pub ip_filters_out: [IpFilter; 8],
    /// Outbound filter count
    pub filter_out_count: usize,
}

impl IpSettings {
    pub const fn new() -> Self {
        Self {
            ip_address_policy: 0,
            static_ip: [0u8; 4],
            ip_filters_in: [const { IpFilter::new() }; 8],
            filter_in_count: 0,
            ip_filters_out: [const { IpFilter::new() }; 8],
            filter_out_count: 0,
        }
    }
}

/// IP filter entry
#[derive(Debug, Clone, Copy)]
pub struct IpFilter {
    /// Filter in use
    pub in_use: bool,
    /// Source network
    pub source_network: [u8; 4],
    /// Source mask
    pub source_mask: [u8; 4],
    /// Destination network
    pub dest_network: [u8; 4],
    /// Destination mask
    pub dest_mask: [u8; 4],
    /// Protocol (0=any, 6=TCP, 17=UDP, etc.)
    pub protocol: u8,
    /// Source port (0=any)
    pub source_port: u16,
    /// Destination port (0=any)
    pub dest_port: u16,
    /// Action (0=permit, 1=deny)
    pub action: u8,
}

impl IpFilter {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            source_network: [0u8; 4],
            source_mask: [0u8; 4],
            dest_network: [0u8; 4],
            dest_mask: [0u8; 4],
            protocol: 0,
            source_port: 0,
            dest_port: 0,
            action: 0,
        }
    }
}

/// Multilink settings
#[derive(Debug, Clone, Copy)]
pub struct MultilinkSettings {
    /// Enable multilink
    pub enabled: bool,
    /// Maximum links
    pub max_links: u32,
    /// BAP (Bandwidth Allocation Protocol) policies
    pub bap_required: bool,
    /// BAP line down time (seconds)
    pub bap_line_down_time: u32,
    /// BAP line down percent
    pub bap_line_down_percent: u8,
}

impl MultilinkSettings {
    pub const fn new() -> Self {
        Self {
            enabled: false,
            max_links: 2,
            bap_required: false,
            bap_line_down_time: 0,
            bap_line_down_percent: 50,
        }
    }
}

/// Profile attribute (RADIUS attribute)
#[derive(Debug, Clone, Copy)]
pub struct ProfileAttribute {
    /// Attribute in use
    pub in_use: bool,
    /// Vendor ID (0 for standard RADIUS)
    pub vendor_id: u32,
    /// Attribute type
    pub attribute_type: u8,
    /// Attribute value
    pub value: [u8; 253],
    /// Value length
    pub value_len: usize,
}

impl ProfileAttribute {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            vendor_id: 0,
            attribute_type: 0,
            value: [0u8; 253],
            value_len: 0,
        }
    }
}

/// Remote access policy
#[derive(Debug, Clone, Copy)]
pub struct RemoteAccessPolicy {
    /// Policy ID
    pub id: u32,
    /// Policy in use
    pub in_use: bool,
    /// Policy name
    pub name: [u8; 64],
    /// Name length
    pub name_len: usize,
    /// Policy enabled
    pub enabled: bool,
    /// Processing order (lower = higher priority)
    pub order: u32,
    /// Grant or deny access
    pub grant_access: bool,
    /// Conditions
    pub conditions: [PolicyCondition; MAX_CONDITIONS],
    /// Condition count
    pub condition_count: usize,
    /// Profile
    pub profile: RemoteAccessProfile,
}

impl RemoteAccessPolicy {
    pub const fn new() -> Self {
        Self {
            id: 0,
            in_use: false,
            name: [0u8; 64],
            name_len: 0,
            enabled: true,
            order: 0,
            grant_access: true,
            conditions: [const { PolicyCondition::new() }; MAX_CONDITIONS],
            condition_count: 0,
            profile: RemoteAccessProfile::new(),
        }
    }
}

// ============================================================================
// Connection Request Policy
// ============================================================================

/// Connection request policy action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ConnectionRequestAction {
    /// Authenticate locally
    AuthenticateLocally = 0,
    /// Forward to remote RADIUS server group
    ForwardToRemoteGroup = 1,
    /// Accept without authentication
    AcceptWithoutAuth = 2,
}

impl Default for ConnectionRequestAction {
    fn default() -> Self {
        Self::AuthenticateLocally
    }
}

/// Connection request policy
#[derive(Debug, Clone, Copy)]
pub struct ConnectionRequestPolicy {
    /// Policy ID
    pub id: u32,
    /// Policy in use
    pub in_use: bool,
    /// Policy name
    pub name: [u8; 64],
    /// Name length
    pub name_len: usize,
    /// Policy enabled
    pub enabled: bool,
    /// Processing order
    pub order: u32,
    /// Conditions
    pub conditions: [PolicyCondition; MAX_CONDITIONS],
    /// Condition count
    pub condition_count: usize,
    /// Action
    pub action: ConnectionRequestAction,
    /// Remote server group ID (for forwarding)
    pub remote_group_id: u32,
    /// Override authentication settings
    pub override_auth: bool,
    /// Attribute manipulation rules
    pub strip_realm: bool,
}

impl ConnectionRequestPolicy {
    pub const fn new() -> Self {
        Self {
            id: 0,
            in_use: false,
            name: [0u8; 64],
            name_len: 0,
            enabled: true,
            order: 0,
            conditions: [const { PolicyCondition::new() }; MAX_CONDITIONS],
            condition_count: 0,
            action: ConnectionRequestAction::AuthenticateLocally,
            remote_group_id: 0,
            override_auth: false,
            strip_realm: false,
        }
    }
}

// ============================================================================
// Remote RADIUS Server Groups
// ============================================================================

/// Load balancing method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LoadBalanceMethod {
    /// Use priority and weight
    PriorityWeight = 0,
    /// Round robin
    RoundRobin = 1,
    /// Failover only
    FailoverOnly = 2,
}

impl Default for LoadBalanceMethod {
    fn default() -> Self {
        Self::PriorityWeight
    }
}

/// Remote RADIUS server
#[derive(Debug, Clone, Copy)]
pub struct RemoteRadiusServer {
    /// Server in use
    pub in_use: bool,
    /// Server name/address
    pub address: [u8; 128],
    /// Address length
    pub address_len: usize,
    /// Authentication port
    pub auth_port: u16,
    /// Accounting port
    pub acct_port: u16,
    /// Shared secret
    pub shared_secret: [u8; 128],
    /// Secret length
    pub secret_len: usize,
    /// Timeout (seconds)
    pub timeout: u32,
    /// Maximum retries
    pub max_retries: u32,
    /// Priority (1-65535, lower = higher)
    pub priority: u16,
    /// Weight (1-100)
    pub weight: u8,
    /// Use message authenticator
    pub use_message_auth: bool,
}

impl RemoteRadiusServer {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            address: [0u8; 128],
            address_len: 0,
            auth_port: 1812,
            acct_port: 1813,
            shared_secret: [0u8; 128],
            secret_len: 0,
            timeout: 3,
            max_retries: 3,
            priority: 1,
            weight: 50,
            use_message_auth: true,
        }
    }
}

/// Remote RADIUS server group
#[derive(Debug, Clone, Copy)]
pub struct RadiusServerGroup {
    /// Group ID
    pub id: u32,
    /// Group in use
    pub in_use: bool,
    /// Group name
    pub name: [u8; 64],
    /// Name length
    pub name_len: usize,
    /// Servers
    pub servers: [RemoteRadiusServer; MAX_SERVERS_PER_GROUP],
    /// Server count
    pub server_count: usize,
    /// Load balancing method
    pub load_balance: LoadBalanceMethod,
    /// Detect failed server (seconds, 0=disabled)
    pub dead_server_detection: u32,
}

impl RadiusServerGroup {
    pub const fn new() -> Self {
        Self {
            id: 0,
            in_use: false,
            name: [0u8; 64],
            name_len: 0,
            servers: [const { RemoteRadiusServer::new() }; MAX_SERVERS_PER_GROUP],
            server_count: 0,
            load_balance: LoadBalanceMethod::PriorityWeight,
            dead_server_detection: 60,
        }
    }
}

// ============================================================================
// Vendor-Specific Attributes
// ============================================================================

/// Vendor-specific attribute definition
#[derive(Debug, Clone, Copy)]
pub struct VendorAttribute {
    /// Attribute in use
    pub in_use: bool,
    /// Vendor ID
    pub vendor_id: u32,
    /// Vendor name
    pub vendor_name: [u8; 64],
    /// Vendor name length
    pub vendor_name_len: usize,
    /// Attribute type
    pub attribute_type: u8,
    /// Attribute name
    pub attribute_name: [u8; 64],
    /// Attribute name length
    pub attribute_name_len: usize,
    /// Data type (0=string, 1=integer, 2=ip, 3=time, 4=hex)
    pub data_type: u8,
    /// Description
    pub description: [u8; 128],
    /// Description length
    pub description_len: usize,
}

impl VendorAttribute {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            vendor_id: 0,
            vendor_name: [0u8; 64],
            vendor_name_len: 0,
            attribute_type: 0,
            attribute_name: [0u8; 64],
            attribute_name_len: 0,
            data_type: 0,
            description: [0u8; 128],
            description_len: 0,
        }
    }
}

// ============================================================================
// IAS Service Configuration
// ============================================================================

/// IAS service status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IasServiceStatus {
    /// Service stopped
    Stopped = 0,
    /// Service starting
    Starting = 1,
    /// Service running
    Running = 2,
    /// Service stopping
    Stopping = 3,
    /// Service error
    Error = 4,
}

impl Default for IasServiceStatus {
    fn default() -> Self {
        Self::Stopped
    }
}

/// IAS server configuration
#[derive(Debug, Clone, Copy)]
pub struct IasServerConfig {
    /// Authentication port
    pub auth_port: u16,
    /// Accounting port
    pub acct_port: u16,
    /// Enable logging
    pub logging_enabled: bool,
    /// Log file path
    pub log_path: [u8; 260],
    /// Log path length
    pub log_path_len: usize,
    /// Log format (0=IAS, 1=database compatible)
    pub log_format: u8,
    /// Log authentication requests
    pub log_auth_requests: bool,
    /// Log accounting requests
    pub log_acct_requests: bool,
    /// Log periodic status
    pub log_periodic_status: bool,
    /// New log frequency (0=daily, 1=weekly, 2=monthly, 3=unlimited)
    pub new_log_frequency: u8,
    /// Reject messages without message authenticator
    pub require_message_auth: bool,
}

impl IasServerConfig {
    pub const fn new() -> Self {
        Self {
            auth_port: 1812,
            acct_port: 1813,
            logging_enabled: true,
            log_path: [0u8; 260],
            log_path_len: 0,
            log_format: 0,
            log_auth_requests: true,
            log_acct_requests: true,
            log_periodic_status: false,
            new_log_frequency: 0,
            require_message_auth: false,
        }
    }
}

// ============================================================================
// IAS Global State
// ============================================================================

/// IAS manager state
pub struct IasState {
    /// RADIUS clients
    pub clients: [RadiusClient; MAX_RADIUS_CLIENTS],
    /// Remote access policies
    pub policies: [RemoteAccessPolicy; MAX_POLICIES],
    /// Connection request policies
    pub connection_policies: [ConnectionRequestPolicy; MAX_CONNECTION_POLICIES],
    /// Remote RADIUS server groups
    pub server_groups: [RadiusServerGroup; MAX_SERVER_GROUPS],
    /// Vendor-specific attributes
    pub vendor_attributes: [VendorAttribute; MAX_VSA],
    /// Server configuration
    pub config: IasServerConfig,
    /// Service status
    pub status: IasServiceStatus,
    /// Next client ID
    pub next_client_id: u32,
    /// Next policy ID
    pub next_policy_id: u32,
    /// Next connection policy ID
    pub next_conn_policy_id: u32,
    /// Next server group ID
    pub next_group_id: u32,
    /// Total authentication requests
    pub total_auth_requests: u64,
    /// Total accounting requests
    pub total_acct_requests: u64,
    /// Total access accepts
    pub access_accepts: u64,
    /// Total access rejects
    pub access_rejects: u64,
    /// Total access challenges
    pub access_challenges: u64,
}

impl IasState {
    pub const fn new() -> Self {
        Self {
            clients: [const { RadiusClient::new() }; MAX_RADIUS_CLIENTS],
            policies: [const { RemoteAccessPolicy::new() }; MAX_POLICIES],
            connection_policies: [const { ConnectionRequestPolicy::new() }; MAX_CONNECTION_POLICIES],
            server_groups: [const { RadiusServerGroup::new() }; MAX_SERVER_GROUPS],
            vendor_attributes: [const { VendorAttribute::new() }; MAX_VSA],
            config: IasServerConfig::new(),
            status: IasServiceStatus::Stopped,
            next_client_id: 1,
            next_policy_id: 1,
            next_conn_policy_id: 1,
            next_group_id: 1,
            total_auth_requests: 0,
            total_acct_requests: 0,
            access_accepts: 0,
            access_rejects: 0,
            access_challenges: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static IAS_STATE: SpinLock<IasState> = SpinLock::new(IasState::new());
static IAS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

// ============================================================================
// RADIUS Client Management
// ============================================================================

/// Add a new RADIUS client
pub fn add_radius_client(
    name: &[u8],
    ip: [u8; 4],
    secret: &[u8],
    vendor: RadiusVendor,
) -> Result<u32, &'static str> {
    let mut state = IAS_STATE.lock();

    // Find free slot
    let slot_index = state.clients.iter().position(|c| !c.in_use)
        .ok_or("Maximum RADIUS clients reached")?;

    let client_id = state.next_client_id;
    state.next_client_id += 1;

    let client = &mut state.clients[slot_index];
    client.in_use = true;
    client.id = client_id;

    let name_len = name.len().min(64);
    client.friendly_name[..name_len].copy_from_slice(&name[..name_len]);
    client.friendly_name_len = name_len;

    client.ip_address = ip;

    let secret_len = secret.len().min(128);
    client.shared_secret[..secret_len].copy_from_slice(&secret[..secret_len]);
    client.secret_len = secret_len;

    client.vendor = vendor;
    client.status = ClientStatus::Enabled;
    client.require_message_auth = true;

    Ok(client_id)
}

/// Remove a RADIUS client
pub fn remove_radius_client(client_id: u32) -> Result<(), &'static str> {
    let mut state = IAS_STATE.lock();

    let client = state.clients.iter_mut()
        .find(|c| c.in_use && c.id == client_id)
        .ok_or("RADIUS client not found")?;

    *client = RadiusClient::new();
    Ok(())
}

/// Get RADIUS client by ID
pub fn get_radius_client(client_id: u32) -> Option<RadiusClient> {
    let state = IAS_STATE.lock();
    state.clients.iter()
        .find(|c| c.in_use && c.id == client_id)
        .copied()
}

/// Enable or disable RADIUS client
pub fn set_client_status(client_id: u32, status: ClientStatus) -> Result<(), &'static str> {
    let mut state = IAS_STATE.lock();

    let client = state.clients.iter_mut()
        .find(|c| c.in_use && c.id == client_id)
        .ok_or("RADIUS client not found")?;

    client.status = status;
    Ok(())
}

// ============================================================================
// Remote Access Policy Management
// ============================================================================

/// Create a new remote access policy
pub fn create_remote_access_policy(
    name: &[u8],
    grant_access: bool,
) -> Result<u32, &'static str> {
    let mut state = IAS_STATE.lock();

    // Find max order for new policy
    let max_order = state.policies.iter()
        .filter(|p| p.in_use)
        .map(|p| p.order)
        .max()
        .unwrap_or(0);

    let slot_index = state.policies.iter().position(|p| !p.in_use)
        .ok_or("Maximum policies reached")?;

    let policy_id = state.next_policy_id;
    state.next_policy_id += 1;

    let policy = &mut state.policies[slot_index];
    policy.in_use = true;
    policy.id = policy_id;

    let name_len = name.len().min(64);
    policy.name[..name_len].copy_from_slice(&name[..name_len]);
    policy.name_len = name_len;

    policy.enabled = true;
    policy.order = max_order + 1;
    policy.grant_access = grant_access;

    Ok(policy_id)
}

/// Add condition to policy
pub fn add_policy_condition(
    policy_id: u32,
    condition_type: ConditionType,
    value: &[u8],
) -> Result<(), &'static str> {
    let mut state = IAS_STATE.lock();

    let policy = state.policies.iter_mut()
        .find(|p| p.in_use && p.id == policy_id)
        .ok_or("Policy not found")?;

    if policy.condition_count >= MAX_CONDITIONS {
        return Err("Maximum conditions reached");
    }

    let cond = &mut policy.conditions[policy.condition_count];
    cond.in_use = true;
    cond.condition_type = condition_type;

    let value_len = value.len().min(256);
    cond.value[..value_len].copy_from_slice(&value[..value_len]);
    cond.value_len = value_len;

    policy.condition_count += 1;

    Ok(())
}

/// Set policy authentication methods
pub fn set_policy_auth_methods(
    policy_id: u32,
    methods: AuthMethodFlags,
) -> Result<(), &'static str> {
    let mut state = IAS_STATE.lock();

    let policy = state.policies.iter_mut()
        .find(|p| p.in_use && p.id == policy_id)
        .ok_or("Policy not found")?;

    policy.profile.auth_methods = methods;
    Ok(())
}

/// Set policy encryption settings
pub fn set_policy_encryption(
    policy_id: u32,
    encryption: EncryptionFlags,
) -> Result<(), &'static str> {
    let mut state = IAS_STATE.lock();

    let policy = state.policies.iter_mut()
        .find(|p| p.in_use && p.id == policy_id)
        .ok_or("Policy not found")?;

    policy.profile.encryption = encryption;
    Ok(())
}

/// Delete remote access policy
pub fn delete_policy(policy_id: u32) -> Result<(), &'static str> {
    let mut state = IAS_STATE.lock();

    let policy = state.policies.iter_mut()
        .find(|p| p.in_use && p.id == policy_id)
        .ok_or("Policy not found")?;

    *policy = RemoteAccessPolicy::new();
    Ok(())
}

// ============================================================================
// Connection Request Policy Management
// ============================================================================

/// Create connection request policy
pub fn create_connection_request_policy(
    name: &[u8],
    action: ConnectionRequestAction,
) -> Result<u32, &'static str> {
    let mut state = IAS_STATE.lock();

    let max_order = state.connection_policies.iter()
        .filter(|p| p.in_use)
        .map(|p| p.order)
        .max()
        .unwrap_or(0);

    let slot_index = state.connection_policies.iter().position(|p| !p.in_use)
        .ok_or("Maximum connection policies reached")?;

    let policy_id = state.next_conn_policy_id;
    state.next_conn_policy_id += 1;

    let policy = &mut state.connection_policies[slot_index];
    policy.in_use = true;
    policy.id = policy_id;

    let name_len = name.len().min(64);
    policy.name[..name_len].copy_from_slice(&name[..name_len]);
    policy.name_len = name_len;

    policy.enabled = true;
    policy.order = max_order + 1;
    policy.action = action;

    Ok(policy_id)
}

/// Set connection policy to forward to remote group
pub fn set_forward_to_group(
    policy_id: u32,
    group_id: u32,
) -> Result<(), &'static str> {
    let mut state = IAS_STATE.lock();

    // Verify group exists
    let group_exists = state.server_groups.iter()
        .any(|g| g.in_use && g.id == group_id);
    if !group_exists {
        return Err("Server group not found");
    }

    let policy = state.connection_policies.iter_mut()
        .find(|p| p.in_use && p.id == policy_id)
        .ok_or("Connection policy not found")?;

    policy.action = ConnectionRequestAction::ForwardToRemoteGroup;
    policy.remote_group_id = group_id;

    Ok(())
}

// ============================================================================
// Remote RADIUS Server Group Management
// ============================================================================

/// Create remote RADIUS server group
pub fn create_server_group(name: &[u8]) -> Result<u32, &'static str> {
    let mut state = IAS_STATE.lock();

    let slot_index = state.server_groups.iter().position(|g| !g.in_use)
        .ok_or("Maximum server groups reached")?;

    let group_id = state.next_group_id;
    state.next_group_id += 1;

    let group = &mut state.server_groups[slot_index];
    group.in_use = true;
    group.id = group_id;

    let name_len = name.len().min(64);
    group.name[..name_len].copy_from_slice(&name[..name_len]);
    group.name_len = name_len;

    Ok(group_id)
}

/// Add server to group
pub fn add_server_to_group(
    group_id: u32,
    address: &[u8],
    auth_port: u16,
    acct_port: u16,
    secret: &[u8],
    priority: u16,
    weight: u8,
) -> Result<(), &'static str> {
    let mut state = IAS_STATE.lock();

    let group = state.server_groups.iter_mut()
        .find(|g| g.in_use && g.id == group_id)
        .ok_or("Server group not found")?;

    if group.server_count >= MAX_SERVERS_PER_GROUP {
        return Err("Maximum servers in group reached");
    }

    let server = &mut group.servers[group.server_count];
    server.in_use = true;

    let addr_len = address.len().min(128);
    server.address[..addr_len].copy_from_slice(&address[..addr_len]);
    server.address_len = addr_len;

    server.auth_port = auth_port;
    server.acct_port = acct_port;

    let secret_len = secret.len().min(128);
    server.shared_secret[..secret_len].copy_from_slice(&secret[..secret_len]);
    server.secret_len = secret_len;

    server.priority = priority;
    server.weight = weight;

    group.server_count += 1;

    Ok(())
}

/// Set group load balancing method
pub fn set_group_load_balance(
    group_id: u32,
    method: LoadBalanceMethod,
) -> Result<(), &'static str> {
    let mut state = IAS_STATE.lock();

    let group = state.server_groups.iter_mut()
        .find(|g| g.in_use && g.id == group_id)
        .ok_or("Server group not found")?;

    group.load_balance = method;
    Ok(())
}

// ============================================================================
// Service Control
// ============================================================================

/// Start IAS service
pub fn start_service() -> Result<(), &'static str> {
    let mut state = IAS_STATE.lock();

    match state.status {
        IasServiceStatus::Running => return Err("Service already running"),
        IasServiceStatus::Starting => return Err("Service is starting"),
        _ => {}
    }

    state.status = IasServiceStatus::Starting;

    // Initialize logging, bind to ports, etc.
    // For now, just set to running
    state.status = IasServiceStatus::Running;

    Ok(())
}

/// Stop IAS service
pub fn stop_service() -> Result<(), &'static str> {
    let mut state = IAS_STATE.lock();

    match state.status {
        IasServiceStatus::Stopped => return Err("Service already stopped"),
        IasServiceStatus::Stopping => return Err("Service is stopping"),
        _ => {}
    }

    state.status = IasServiceStatus::Stopping;
    state.status = IasServiceStatus::Stopped;

    Ok(())
}

/// Get service status
pub fn get_service_status() -> IasServiceStatus {
    IAS_STATE.lock().status
}

/// Get server configuration
pub fn get_server_config() -> IasServerConfig {
    IAS_STATE.lock().config
}

/// Update server configuration
pub fn set_server_config(config: IasServerConfig) -> Result<(), &'static str> {
    let mut state = IAS_STATE.lock();

    // Validate ports
    if config.auth_port == 0 || config.acct_port == 0 {
        return Err("Invalid port configuration");
    }

    state.config = config;
    Ok(())
}

// ============================================================================
// Statistics
// ============================================================================

/// Get IAS statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64) {
    let state = IAS_STATE.lock();
    (
        state.total_auth_requests,
        state.total_acct_requests,
        state.access_accepts,
        state.access_rejects,
        state.access_challenges,
    )
}

/// Reset statistics
pub fn reset_statistics() {
    let mut state = IAS_STATE.lock();
    state.total_auth_requests = 0;
    state.total_acct_requests = 0;
    state.access_accepts = 0;
    state.access_rejects = 0;
    state.access_challenges = 0;
}

// ============================================================================
// Snap-in Dialog Management
// ============================================================================

/// Show IAS Management main window
pub fn show_ias_console() -> HWND {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::SeqCst);
    UserHandle::from_raw(id)
}

/// Show new RADIUS client wizard
pub fn show_new_client_wizard() -> HWND {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::SeqCst);
    UserHandle::from_raw(id)
}

/// Show RADIUS client properties dialog
pub fn show_client_properties(_client_id: u32) -> HWND {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::SeqCst);
    UserHandle::from_raw(id)
}

/// Show new remote access policy wizard
pub fn show_new_policy_wizard() -> HWND {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::SeqCst);
    UserHandle::from_raw(id)
}

/// Show policy properties dialog
pub fn show_policy_properties(_policy_id: u32) -> HWND {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::SeqCst);
    UserHandle::from_raw(id)
}

/// Show new connection request policy wizard
pub fn show_new_connection_policy_wizard() -> HWND {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::SeqCst);
    UserHandle::from_raw(id)
}

/// Show server group properties
pub fn show_server_group_properties(_group_id: u32) -> HWND {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::SeqCst);
    UserHandle::from_raw(id)
}

/// Show IAS server properties
pub fn show_server_properties() -> HWND {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::SeqCst);
    UserHandle::from_raw(id)
}

// ============================================================================
// Module Initialization
// ============================================================================

/// Initialize IAS management module
pub fn init() {
    if IAS_INITIALIZED.compare_exchange(
        false,
        true,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ).is_err() {
        return; // Already initialized
    }

    let mut state = IAS_STATE.lock();

    // Create default remote access policy
    let policy_id = state.next_policy_id;
    state.next_policy_id += 1;

    let default_policy = &mut state.policies[0];
    default_policy.in_use = true;
    default_policy.id = policy_id;

    let name = b"Connections to Microsoft Routing and Remote Access server";
    let name_len = name.len().min(64);
    default_policy.name[..name_len].copy_from_slice(&name[..name_len]);
    default_policy.name_len = name_len;

    default_policy.enabled = true;
    default_policy.order = 1;
    default_policy.grant_access = true;

    // Set default authentication to MS-CHAP v2 and EAP
    default_policy.profile.auth_methods = AuthMethodFlags::MSCHAP_V2 | AuthMethodFlags::EAP;
    default_policy.profile.encryption = EncryptionFlags::STRONGEST;

    // Create default connection request policy (authenticate locally)
    let conn_policy_id = state.next_conn_policy_id;
    state.next_conn_policy_id += 1;

    let default_conn_policy = &mut state.connection_policies[0];
    default_conn_policy.in_use = true;
    default_conn_policy.id = conn_policy_id;

    let conn_name = b"Use Windows authentication for all users";
    let conn_name_len = conn_name.len().min(64);
    default_conn_policy.name[..conn_name_len].copy_from_slice(&conn_name[..conn_name_len]);
    default_conn_policy.name_len = conn_name_len;

    default_conn_policy.enabled = true;
    default_conn_policy.order = 1;
    default_conn_policy.action = ConnectionRequestAction::AuthenticateLocally;

    // Set default log path
    let log_path = b"C:\\Windows\\System32\\LogFiles\\IAS";
    let log_len = log_path.len().min(260);
    state.config.log_path[..log_len].copy_from_slice(&log_path[..log_len]);
    state.config.log_path_len = log_len;
}
