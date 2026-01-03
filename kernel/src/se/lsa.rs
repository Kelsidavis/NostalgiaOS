//! Local Security Authority (LSA)
//!
//! The Local Security Authority is the central security component in Windows NT:
//!
//! - **Authentication**: Validates user credentials (NTLM, Kerberos)
//! - **Policy Management**: Security policies and audit settings
//! - **Secret Storage**: Protected storage for credentials
//! - **Privilege Assignment**: User rights and privileges
//! - **Logon Sessions**: Tracks active logon sessions
//! - **Trust Relationships**: Domain trust management
//!
//! LSA works with:
//! - SAM (Security Account Manager) for local accounts
//! - Active Directory for domain accounts
//! - Authentication packages (NTLM, Kerberos, etc.)

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::ke::SpinLock;
use crate::hal::apic::get_tick_count;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of logon sessions
pub const MAX_LOGON_SESSIONS: usize = 256;

/// Maximum number of authentication packages
pub const MAX_AUTH_PACKAGES: usize = 16;

/// Maximum number of secrets
pub const MAX_SECRETS: usize = 128;

/// Maximum number of policies
pub const MAX_POLICIES: usize = 64;

/// Maximum number of trust relationships
pub const MAX_TRUSTS: usize = 32;

/// Maximum secret name length
pub const MAX_SECRET_NAME: usize = 128;

/// Maximum secret data length
pub const MAX_SECRET_DATA: usize = 512;

/// LSA policy handle signature
pub const LSA_POLICY_SIGNATURE: u32 = 0x4C534150; // 'LSAP'

// ============================================================================
// Error Types
// ============================================================================

/// LSA error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LsaError {
    /// Success
    Success = 0,
    /// Invalid parameter
    InvalidParameter = 0xC000000D,
    /// Invalid handle
    InvalidHandle = 0xC0000008,
    /// Access denied
    AccessDenied = 0xC0000022,
    /// No such privilege
    NoSuchPrivilege = 0xC0000060,
    /// Object not found
    ObjectNotFound = 0xC0000034,
    /// Insufficient resources
    InsufficientResources = 0xC000009A,
    /// No more entries
    NoMoreEntries = 0x8000001A,
    /// Invalid SID
    InvalidSid = 0xC0000078,
    /// Authentication failed
    AuthenticationFailed = 0xC000006D,
    /// Logon failure
    LogonFailure = 0xC000006E,
    /// No logon servers available
    NoLogonServers = 0xC000005E,
    /// Account disabled
    AccountDisabled = 0xC0000072,
    /// Password expired
    PasswordExpired = 0xC0000071,
    /// Account locked
    AccountLocked = 0xC0000234,
    /// Invalid workstation
    InvalidWorkstation = 0xC0000070,
    /// Logon type not granted
    LogonTypeNotGranted = 0xC000015B,
    /// Not initialized
    NotInitialized = 0xC0000001,
    /// Secret not found
    SecretNotFound = 0xC0000033,
    /// Trust not found
    TrustNotFound = 0xC00000DF,
    /// Package not found
    PackageNotFound = 0xC00000FE,
}

// ============================================================================
// Logon Types
// ============================================================================

/// Logon types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LogonType {
    /// Interactive logon (console)
    Interactive = 2,
    /// Network logon (SMB, etc.)
    Network = 3,
    /// Batch logon (scheduled tasks)
    Batch = 4,
    /// Service logon
    Service = 5,
    /// Unlock workstation
    Unlock = 7,
    /// Network cleartext (HTTP Basic)
    NetworkCleartext = 8,
    /// New credentials (RunAs)
    NewCredentials = 9,
    /// Remote interactive (RDP)
    RemoteInteractive = 10,
    /// Cached interactive (offline logon)
    CachedInteractive = 11,
}

/// Logon session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogonSessionState {
    /// Session is active
    Active = 0,
    /// Session is terminating
    Terminating = 1,
    /// Session terminated
    Terminated = 2,
}

// ============================================================================
// Policy Types
// ============================================================================

/// Policy access rights
pub mod policy_access {
    pub const POLICY_VIEW_LOCAL_INFORMATION: u32 = 0x00000001;
    pub const POLICY_VIEW_AUDIT_INFORMATION: u32 = 0x00000002;
    pub const POLICY_GET_PRIVATE_INFORMATION: u32 = 0x00000004;
    pub const POLICY_TRUST_ADMIN: u32 = 0x00000008;
    pub const POLICY_CREATE_ACCOUNT: u32 = 0x00000010;
    pub const POLICY_CREATE_SECRET: u32 = 0x00000020;
    pub const POLICY_CREATE_PRIVILEGE: u32 = 0x00000040;
    pub const POLICY_SET_DEFAULT_QUOTA_LIMITS: u32 = 0x00000080;
    pub const POLICY_SET_AUDIT_REQUIREMENTS: u32 = 0x00000100;
    pub const POLICY_AUDIT_LOG_ADMIN: u32 = 0x00000200;
    pub const POLICY_SERVER_ADMIN: u32 = 0x00000400;
    pub const POLICY_LOOKUP_NAMES: u32 = 0x00000800;
    pub const POLICY_ALL_ACCESS: u32 = 0x00000FFF;
}

/// Policy information classes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PolicyInformationClass {
    /// Audit log info
    PolicyAuditLogInformation = 1,
    /// Audit events info
    PolicyAuditEventsInformation = 2,
    /// Primary domain info
    PolicyPrimaryDomainInformation = 3,
    /// PD account info
    PolicyPdAccountInformation = 4,
    /// Account domain info
    PolicyAccountDomainInformation = 5,
    /// LSA server role info
    PolicyLsaServerRoleInformation = 6,
    /// Replica source info
    PolicyReplicaSourceInformation = 7,
    /// Default quota info
    PolicyDefaultQuotaInformation = 8,
    /// Modification info
    PolicyModificationInformation = 9,
    /// Audit full set info
    PolicyAuditFullSetInformation = 10,
    /// Audit full query info
    PolicyAuditFullQueryInformation = 11,
    /// DNS domain info
    PolicyDnsDomainInformation = 12,
}

/// Trust direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TrustDirection {
    /// Disabled trust
    Disabled = 0,
    /// Inbound trust
    Inbound = 1,
    /// Outbound trust
    Outbound = 2,
    /// Bidirectional trust
    Bidirectional = 3,
}

/// Trust type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TrustType {
    /// Downlevel (NT4) trust
    Downlevel = 1,
    /// Uplevel (AD) trust
    Uplevel = 2,
    /// MIT Kerberos trust
    Mit = 3,
    /// DCE trust
    Dce = 4,
}

// ============================================================================
// Data Structures
// ============================================================================

/// Logon ID (LUID for logon sessions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct LogonId {
    /// Low part
    pub low_part: u32,
    /// High part
    pub high_part: i32,
}

impl LogonId {
    pub const fn new(low: u32, high: i32) -> Self {
        Self {
            low_part: low,
            high_part: high,
        }
    }

    pub const fn from_u64(value: u64) -> Self {
        Self {
            low_part: value as u32,
            high_part: (value >> 32) as i32,
        }
    }

    pub const fn to_u64(&self) -> u64 {
        (self.low_part as u64) | ((self.high_part as u64) << 32)
    }
}

/// Well-known logon IDs
pub mod well_known_logon_ids {
    use super::LogonId;

    /// System logon session
    pub const SYSTEM_LUID: LogonId = LogonId::new(0x3E7, 0);
    /// Local service logon session
    pub const LOCAL_SERVICE_LUID: LogonId = LogonId::new(0x3E5, 0);
    /// Network service logon session
    pub const NETWORK_SERVICE_LUID: LogonId = LogonId::new(0x3E4, 0);
    /// Anonymous logon session
    pub const ANONYMOUS_LUID: LogonId = LogonId::new(0x3E6, 0);
}

/// Logon session
#[derive(Debug, Clone)]
pub struct LogonSession {
    /// Session in use
    pub in_use: bool,
    /// Logon ID
    pub logon_id: LogonId,
    /// Logon type
    pub logon_type: LogonType,
    /// Session state
    pub state: LogonSessionState,
    /// User SID (simplified as u64 for now)
    pub user_sid: u64,
    /// Username
    pub username: [u8; 64],
    pub username_len: usize,
    /// Domain name
    pub domain: [u8; 64],
    pub domain_len: usize,
    /// Authentication package ID
    pub auth_package_id: u32,
    /// Logon time (ticks)
    pub logon_time: u64,
    /// Logon server
    pub logon_server: [u8; 64],
    pub logon_server_len: usize,
    /// Token handle
    pub token_handle: u64,
    /// Reference count
    pub ref_count: u32,
}

impl LogonSession {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            logon_id: LogonId::new(0, 0),
            logon_type: LogonType::Interactive,
            state: LogonSessionState::Active,
            user_sid: 0,
            username: [0u8; 64],
            username_len: 0,
            domain: [0u8; 64],
            domain_len: 0,
            auth_package_id: 0,
            logon_time: 0,
            logon_server: [0u8; 64],
            logon_server_len: 0,
            token_handle: 0,
            ref_count: 0,
        }
    }

    pub fn get_username(&self) -> &[u8] {
        &self.username[..self.username_len]
    }

    pub fn get_domain(&self) -> &[u8] {
        &self.domain[..self.domain_len]
    }
}

/// Authentication package
#[derive(Debug, Clone)]
pub struct AuthPackage {
    /// Package in use
    pub in_use: bool,
    /// Package ID
    pub id: u32,
    /// Package name
    pub name: [u8; 64],
    pub name_len: usize,
    /// Package comment/description
    pub comment: [u8; 128],
    pub comment_len: usize,
    /// Package capabilities
    pub capabilities: u32,
    /// RPC ID
    pub rpc_id: u32,
    /// Maximum token size
    pub max_token_size: u32,
    /// Package version
    pub version: u32,
}

impl AuthPackage {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            id: 0,
            name: [0u8; 64],
            name_len: 0,
            comment: [0u8; 128],
            comment_len: 0,
            capabilities: 0,
            rpc_id: 0,
            max_token_size: 0,
            version: 0,
        }
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Authentication package capabilities
pub mod package_capabilities {
    pub const SECPKG_FLAG_INTEGRITY: u32 = 0x00000001;
    pub const SECPKG_FLAG_PRIVACY: u32 = 0x00000002;
    pub const SECPKG_FLAG_TOKEN_ONLY: u32 = 0x00000004;
    pub const SECPKG_FLAG_DATAGRAM: u32 = 0x00000008;
    pub const SECPKG_FLAG_CONNECTION: u32 = 0x00000010;
    pub const SECPKG_FLAG_MULTI_REQUIRED: u32 = 0x00000020;
    pub const SECPKG_FLAG_CLIENT_ONLY: u32 = 0x00000040;
    pub const SECPKG_FLAG_EXTENDED_ERROR: u32 = 0x00000080;
    pub const SECPKG_FLAG_IMPERSONATION: u32 = 0x00000100;
    pub const SECPKG_FLAG_ACCEPT_WIN32_NAME: u32 = 0x00000200;
    pub const SECPKG_FLAG_STREAM: u32 = 0x00000400;
    pub const SECPKG_FLAG_NEGOTIABLE: u32 = 0x00000800;
    pub const SECPKG_FLAG_GSS_COMPATIBLE: u32 = 0x00001000;
    pub const SECPKG_FLAG_LOGON: u32 = 0x00002000;
    pub const SECPKG_FLAG_MUTUAL_AUTH: u32 = 0x00010000;
    pub const SECPKG_FLAG_DELEGATION: u32 = 0x00020000;
}

/// LSA secret
#[derive(Debug, Clone)]
pub struct LsaSecret {
    /// Secret in use
    pub in_use: bool,
    /// Secret name
    pub name: [u8; MAX_SECRET_NAME],
    pub name_len: usize,
    /// Current value
    pub current_value: [u8; MAX_SECRET_DATA],
    pub current_value_len: usize,
    /// Old value
    pub old_value: [u8; MAX_SECRET_DATA],
    pub old_value_len: usize,
    /// Current value set time
    pub current_set_time: u64,
    /// Old value set time
    pub old_set_time: u64,
    /// Access mask
    pub access_mask: u32,
}

impl LsaSecret {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            name: [0u8; MAX_SECRET_NAME],
            name_len: 0,
            current_value: [0u8; MAX_SECRET_DATA],
            current_value_len: 0,
            old_value: [0u8; MAX_SECRET_DATA],
            old_value_len: 0,
            current_set_time: 0,
            old_set_time: 0,
            access_mask: 0,
        }
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Domain trust information
#[derive(Debug, Clone)]
pub struct TrustInfo {
    /// Trust in use
    pub in_use: bool,
    /// Trusted domain name
    pub domain_name: [u8; 64],
    pub domain_name_len: usize,
    /// Flat (NetBIOS) name
    pub flat_name: [u8; 32],
    pub flat_name_len: usize,
    /// Domain SID (simplified)
    pub domain_sid: u64,
    /// Trust direction
    pub direction: TrustDirection,
    /// Trust type
    pub trust_type: TrustType,
    /// Trust attributes
    pub attributes: u32,
    /// Forest trust info present
    pub forest_trust: bool,
}

impl TrustInfo {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            domain_name: [0u8; 64],
            domain_name_len: 0,
            flat_name: [0u8; 32],
            flat_name_len: 0,
            domain_sid: 0,
            direction: TrustDirection::Disabled,
            trust_type: TrustType::Downlevel,
            attributes: 0,
            forest_trust: false,
        }
    }
}

/// Trust attributes
pub mod trust_attributes {
    pub const TRUST_ATTRIBUTE_NON_TRANSITIVE: u32 = 0x00000001;
    pub const TRUST_ATTRIBUTE_UPLEVEL_ONLY: u32 = 0x00000002;
    pub const TRUST_ATTRIBUTE_QUARANTINED_DOMAIN: u32 = 0x00000004;
    pub const TRUST_ATTRIBUTE_FOREST_TRANSITIVE: u32 = 0x00000008;
    pub const TRUST_ATTRIBUTE_CROSS_ORGANIZATION: u32 = 0x00000010;
    pub const TRUST_ATTRIBUTE_WITHIN_FOREST: u32 = 0x00000020;
    pub const TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL: u32 = 0x00000040;
}

/// LSA policy information
#[derive(Debug, Clone)]
pub struct PolicyInfo {
    /// Primary domain name
    pub primary_domain: [u8; 64],
    pub primary_domain_len: usize,
    /// Primary domain SID
    pub primary_domain_sid: u64,
    /// Account domain name
    pub account_domain: [u8; 64],
    pub account_domain_len: usize,
    /// Account domain SID
    pub account_domain_sid: u64,
    /// Server role
    pub server_role: ServerRole,
    /// Audit log maximum size
    pub audit_log_max_size: u32,
    /// Audit log retention period
    pub audit_retention_period: u64,
    /// Audit event flags
    pub audit_events: u32,
    /// Machine password age (days)
    pub machine_password_age: u32,
}

impl PolicyInfo {
    pub const fn new() -> Self {
        Self {
            primary_domain: [0u8; 64],
            primary_domain_len: 0,
            primary_domain_sid: 0,
            account_domain: [0u8; 64],
            account_domain_len: 0,
            account_domain_sid: 0,
            server_role: ServerRole::Standalone,
            audit_log_max_size: 0x100000, // 1MB default
            audit_retention_period: 0,
            audit_events: 0,
            machine_password_age: 30,
        }
    }
}

/// LSA server role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServerRole {
    /// Standalone server/workstation
    Standalone = 0,
    /// Primary domain controller
    PrimaryDC = 1,
    /// Backup domain controller
    BackupDC = 2,
}

/// LSA handle
#[derive(Debug, Clone)]
pub struct LsaHandle {
    /// Handle in use
    pub in_use: bool,
    /// Signature
    pub signature: u32,
    /// Handle ID
    pub id: u64,
    /// Handle type
    pub handle_type: LsaHandleType,
    /// Access mask
    pub access_mask: u32,
    /// Object reference (varies by type)
    pub object_ref: u64,
}

impl LsaHandle {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            signature: 0,
            id: 0,
            handle_type: LsaHandleType::Policy,
            access_mask: 0,
            object_ref: 0,
        }
    }
}

/// LSA handle types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LsaHandleType {
    /// Policy handle
    Policy = 0,
    /// Account handle
    Account = 1,
    /// Secret handle
    Secret = 2,
    /// Trusted domain handle
    TrustedDomain = 3,
}

// ============================================================================
// Global State
// ============================================================================

/// LSA subsystem state
struct LsaState {
    /// Initialized flag
    initialized: bool,
    /// Logon sessions
    sessions: [LogonSession; MAX_LOGON_SESSIONS],
    session_count: usize,
    /// Authentication packages
    auth_packages: [AuthPackage; MAX_AUTH_PACKAGES],
    auth_package_count: usize,
    /// LSA secrets
    secrets: [LsaSecret; MAX_SECRETS],
    secret_count: usize,
    /// Trust relationships
    trusts: [TrustInfo; MAX_TRUSTS],
    trust_count: usize,
    /// Policy information
    policy: PolicyInfo,
    /// Next logon ID
    next_logon_id: u64,
    /// Next handle ID
    next_handle_id: u64,
}

impl LsaState {
    const fn new() -> Self {
        Self {
            initialized: false,
            sessions: [const { LogonSession::empty() }; MAX_LOGON_SESSIONS],
            session_count: 0,
            auth_packages: [const { AuthPackage::empty() }; MAX_AUTH_PACKAGES],
            auth_package_count: 0,
            secrets: [const { LsaSecret::empty() }; MAX_SECRETS],
            secret_count: 0,
            trusts: [const { TrustInfo::empty() }; MAX_TRUSTS],
            trust_count: 0,
            policy: PolicyInfo::new(),
            next_logon_id: 0x1000, // Start after well-known LUIDs
            next_handle_id: 1,
        }
    }
}

static LSA_STATE: SpinLock<LsaState> = SpinLock::new(LsaState::new());

/// LSA statistics
struct LsaStats {
    /// Successful logons
    logons_success: AtomicU64,
    /// Failed logons
    logons_failed: AtomicU64,
    /// Logoffs
    logoffs: AtomicU64,
    /// Authentication calls
    auth_calls: AtomicU64,
    /// Policy lookups
    policy_lookups: AtomicU64,
    /// Secret accesses
    secret_accesses: AtomicU64,
}

static LSA_STATS: LsaStats = LsaStats {
    logons_success: AtomicU64::new(0),
    logons_failed: AtomicU64::new(0),
    logoffs: AtomicU64::new(0),
    auth_calls: AtomicU64::new(0),
    policy_lookups: AtomicU64::new(0),
    secret_accesses: AtomicU64::new(0),
};

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the LSA subsystem
pub fn init() {
    crate::serial_println!("[LSA] Initializing Local Security Authority...");

    let mut state = LSA_STATE.lock();

    if state.initialized {
        crate::serial_println!("[LSA] Already initialized");
        return;
    }

    // Set up default policy
    setup_default_policy(&mut state);

    // Register built-in authentication packages
    register_builtin_packages(&mut state);

    // Create system logon session
    create_system_session(&mut state);

    state.initialized = true;

    crate::serial_println!("[LSA] Local Security Authority initialized");
}

fn setup_default_policy(state: &mut LsaState) {
    // Set default domain names
    let workgroup = b"WORKGROUP";
    state.policy.primary_domain[..workgroup.len()].copy_from_slice(workgroup);
    state.policy.primary_domain_len = workgroup.len();

    let local = b"LOCAL";
    state.policy.account_domain[..local.len()].copy_from_slice(local);
    state.policy.account_domain_len = local.len();

    // Generate domain SIDs (simplified)
    state.policy.primary_domain_sid = 0x0105_0000_0000_0015; // S-1-5-21-...
    state.policy.account_domain_sid = 0x0105_0000_0000_0015;

    state.policy.server_role = ServerRole::Standalone;
}

fn register_builtin_packages(state: &mut LsaState) {
    // Register NTLM package
    let count = state.auth_package_count;
    if count < MAX_AUTH_PACKAGES {
        let pkg = &mut state.auth_packages[count];
        pkg.in_use = true;
        pkg.id = count as u32;

        let name = b"NTLM";
        pkg.name[..name.len()].copy_from_slice(name);
        pkg.name_len = name.len();

        let comment = b"NTLM Security Package";
        pkg.comment[..comment.len()].copy_from_slice(comment);
        pkg.comment_len = comment.len();

        pkg.capabilities = package_capabilities::SECPKG_FLAG_INTEGRITY
            | package_capabilities::SECPKG_FLAG_PRIVACY
            | package_capabilities::SECPKG_FLAG_TOKEN_ONLY
            | package_capabilities::SECPKG_FLAG_CONNECTION
            | package_capabilities::SECPKG_FLAG_ACCEPT_WIN32_NAME
            | package_capabilities::SECPKG_FLAG_LOGON;
        pkg.rpc_id = 10; // RPC_C_AUTHN_WINNT
        pkg.max_token_size = 2888;
        pkg.version = 1;

        state.auth_package_count += 1;
    }

    // Register Negotiate package
    let count = state.auth_package_count;
    if count < MAX_AUTH_PACKAGES {
        let pkg = &mut state.auth_packages[count];
        pkg.in_use = true;
        pkg.id = count as u32;

        let name = b"Negotiate";
        pkg.name[..name.len()].copy_from_slice(name);
        pkg.name_len = name.len();

        let comment = b"Microsoft Package Negotiator";
        pkg.comment[..comment.len()].copy_from_slice(comment);
        pkg.comment_len = comment.len();

        pkg.capabilities = package_capabilities::SECPKG_FLAG_INTEGRITY
            | package_capabilities::SECPKG_FLAG_PRIVACY
            | package_capabilities::SECPKG_FLAG_TOKEN_ONLY
            | package_capabilities::SECPKG_FLAG_CONNECTION
            | package_capabilities::SECPKG_FLAG_ACCEPT_WIN32_NAME
            | package_capabilities::SECPKG_FLAG_NEGOTIABLE
            | package_capabilities::SECPKG_FLAG_GSS_COMPATIBLE
            | package_capabilities::SECPKG_FLAG_LOGON
            | package_capabilities::SECPKG_FLAG_MUTUAL_AUTH
            | package_capabilities::SECPKG_FLAG_DELEGATION;
        pkg.rpc_id = 9; // RPC_C_AUTHN_GSS_NEGOTIATE
        pkg.max_token_size = 12000;
        pkg.version = 1;

        state.auth_package_count += 1;
    }

    // Register Kerberos package
    let count = state.auth_package_count;
    if count < MAX_AUTH_PACKAGES {
        let pkg = &mut state.auth_packages[count];
        pkg.in_use = true;
        pkg.id = count as u32;

        let name = b"Kerberos";
        pkg.name[..name.len()].copy_from_slice(name);
        pkg.name_len = name.len();

        let comment = b"Microsoft Kerberos V1.0";
        pkg.comment[..comment.len()].copy_from_slice(comment);
        pkg.comment_len = comment.len();

        pkg.capabilities = package_capabilities::SECPKG_FLAG_INTEGRITY
            | package_capabilities::SECPKG_FLAG_PRIVACY
            | package_capabilities::SECPKG_FLAG_TOKEN_ONLY
            | package_capabilities::SECPKG_FLAG_DATAGRAM
            | package_capabilities::SECPKG_FLAG_CONNECTION
            | package_capabilities::SECPKG_FLAG_ACCEPT_WIN32_NAME
            | package_capabilities::SECPKG_FLAG_GSS_COMPATIBLE
            | package_capabilities::SECPKG_FLAG_LOGON
            | package_capabilities::SECPKG_FLAG_MUTUAL_AUTH
            | package_capabilities::SECPKG_FLAG_DELEGATION;
        pkg.rpc_id = 16; // RPC_C_AUTHN_GSS_KERBEROS
        pkg.max_token_size = 12000;
        pkg.version = 1;

        state.auth_package_count += 1;
    }

    crate::serial_println!("[LSA] Registered {} authentication packages", state.auth_package_count);
}

fn create_system_session(state: &mut LsaState) {
    // Create SYSTEM logon session
    if state.session_count < MAX_LOGON_SESSIONS {
        let session = &mut state.sessions[state.session_count];
        session.in_use = true;
        session.logon_id = well_known_logon_ids::SYSTEM_LUID;
        session.logon_type = LogonType::Service;
        session.state = LogonSessionState::Active;
        session.user_sid = 0x0101_0000_0000_0012; // S-1-5-18 (LocalSystem)

        let username = b"SYSTEM";
        session.username[..username.len()].copy_from_slice(username);
        session.username_len = username.len();

        let domain = b"NT AUTHORITY";
        session.domain[..domain.len()].copy_from_slice(domain);
        session.domain_len = domain.len();

        session.auth_package_id = 0; // NTLM
        session.logon_time = 0;
        session.ref_count = 1;

        state.session_count += 1;
    }
}

// ============================================================================
// Logon Session Management
// ============================================================================

/// Create a new logon session
pub fn lsa_create_logon_session(logon_type: LogonType) -> Result<LogonId, LsaError> {
    let mut state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    if state.session_count >= MAX_LOGON_SESSIONS {
        return Err(LsaError::InsufficientResources);
    }

    // Allocate new logon ID
    let logon_id = LogonId::from_u64(state.next_logon_id);
    state.next_logon_id += 1;

    // Find free slot
    for i in 0..MAX_LOGON_SESSIONS {
        if !state.sessions[i].in_use {
            let session = &mut state.sessions[i];
            session.in_use = true;
            session.logon_id = logon_id;
            session.logon_type = logon_type;
            session.state = LogonSessionState::Active;
            session.ref_count = 1;
            session.logon_time = get_tick_count();

            state.session_count += 1;

            return Ok(logon_id);
        }
    }

    Err(LsaError::InsufficientResources)
}

/// Delete a logon session
pub fn lsa_delete_logon_session(logon_id: &LogonId) -> Result<(), LsaError> {
    let mut state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    for i in 0..MAX_LOGON_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].logon_id == *logon_id {
            state.sessions[i].state = LogonSessionState::Terminated;
            state.sessions[i].in_use = false;

            if state.session_count > 0 {
                state.session_count -= 1;
            }

            LSA_STATS.logoffs.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(LsaError::ObjectNotFound)
}

/// Get logon session data
pub fn lsa_get_logon_session_data(logon_id: &LogonId) -> Result<LogonSession, LsaError> {
    let state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    for i in 0..MAX_LOGON_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].logon_id == *logon_id {
            return Ok(state.sessions[i].clone());
        }
    }

    Err(LsaError::ObjectNotFound)
}

/// Enumerate logon sessions
pub fn lsa_enumerate_logon_sessions() -> Vec<LogonId> {
    let state = LSA_STATE.lock();
    let mut sessions = Vec::new();

    if !state.initialized {
        return sessions;
    }

    for i in 0..MAX_LOGON_SESSIONS {
        if state.sessions[i].in_use {
            sessions.push(state.sessions[i].logon_id);
        }
    }

    sessions
}

// ============================================================================
// Authentication
// ============================================================================

/// Perform a logon operation
pub fn lsa_logon_user(
    logon_type: LogonType,
    auth_package_name: &[u8],
    username: &[u8],
    domain: &[u8],
    _credentials: &[u8],
) -> Result<LogonId, LsaError> {
    let mut state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    LSA_STATS.auth_calls.fetch_add(1, Ordering::Relaxed);

    // Find authentication package
    let mut pkg_id = None;
    for i in 0..state.auth_package_count {
        if state.auth_packages[i].in_use
            && state.auth_packages[i].get_name() == auth_package_name
        {
            pkg_id = Some(state.auth_packages[i].id);
            break;
        }
    }

    let pkg_id = match pkg_id {
        Some(id) => id,
        None => {
            LSA_STATS.logons_failed.fetch_add(1, Ordering::Relaxed);
            return Err(LsaError::PackageNotFound);
        }
    };

    // For now, accept any logon (no real authentication)
    // In a real implementation, this would validate credentials

    // Create logon session
    if state.session_count >= MAX_LOGON_SESSIONS {
        LSA_STATS.logons_failed.fetch_add(1, Ordering::Relaxed);
        return Err(LsaError::InsufficientResources);
    }

    let logon_id = LogonId::from_u64(state.next_logon_id);
    state.next_logon_id += 1;

    // Find free slot
    for i in 0..MAX_LOGON_SESSIONS {
        if !state.sessions[i].in_use {
            let session = &mut state.sessions[i];
            session.in_use = true;
            session.logon_id = logon_id;
            session.logon_type = logon_type;
            session.state = LogonSessionState::Active;
            session.auth_package_id = pkg_id;
            session.logon_time = get_tick_count();
            session.ref_count = 1;

            // Copy username
            let ulen = username.len().min(64);
            session.username[..ulen].copy_from_slice(&username[..ulen]);
            session.username_len = ulen;

            // Copy domain
            let dlen = domain.len().min(64);
            session.domain[..dlen].copy_from_slice(&domain[..dlen]);
            session.domain_len = dlen;

            state.session_count += 1;

            LSA_STATS.logons_success.fetch_add(1, Ordering::Relaxed);
            return Ok(logon_id);
        }
    }

    LSA_STATS.logons_failed.fetch_add(1, Ordering::Relaxed);
    Err(LsaError::InsufficientResources)
}

/// Get authentication package by name
pub fn lsa_lookup_authentication_package(name: &[u8]) -> Result<u32, LsaError> {
    let state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    for i in 0..state.auth_package_count {
        if state.auth_packages[i].in_use && state.auth_packages[i].get_name() == name {
            return Ok(state.auth_packages[i].id);
        }
    }

    Err(LsaError::PackageNotFound)
}

/// Enumerate authentication packages
pub fn lsa_enumerate_auth_packages() -> Vec<AuthPackage> {
    let state = LSA_STATE.lock();
    let mut packages = Vec::new();

    if !state.initialized {
        return packages;
    }

    for i in 0..state.auth_package_count {
        if state.auth_packages[i].in_use {
            packages.push(state.auth_packages[i].clone());
        }
    }

    packages
}

// ============================================================================
// Secrets Management
// ============================================================================

/// Create or open a secret
pub fn lsa_create_secret(name: &[u8], access_mask: u32) -> Result<u64, LsaError> {
    let mut state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    if name.len() > MAX_SECRET_NAME {
        return Err(LsaError::InvalidParameter);
    }

    // Check if exists
    for i in 0..MAX_SECRETS {
        if state.secrets[i].in_use && state.secrets[i].get_name() == name {
            // Return existing handle
            let handle = state.next_handle_id;
            state.next_handle_id += 1;
            return Ok(handle);
        }
    }

    // Create new
    if state.secret_count >= MAX_SECRETS {
        return Err(LsaError::InsufficientResources);
    }

    for i in 0..MAX_SECRETS {
        if !state.secrets[i].in_use {
            let secret = &mut state.secrets[i];
            secret.in_use = true;
            secret.name[..name.len()].copy_from_slice(name);
            secret.name_len = name.len();
            secret.access_mask = access_mask;
            secret.current_set_time = get_tick_count();

            state.secret_count += 1;

            let handle = state.next_handle_id;
            state.next_handle_id += 1;
            return Ok(handle);
        }
    }

    Err(LsaError::InsufficientResources)
}

/// Set secret value
pub fn lsa_set_secret(name: &[u8], value: &[u8]) -> Result<(), LsaError> {
    let mut state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    if value.len() > MAX_SECRET_DATA {
        return Err(LsaError::InvalidParameter);
    }

    for i in 0..MAX_SECRETS {
        if state.secrets[i].in_use && state.secrets[i].get_name() == name {
            let secret = &mut state.secrets[i];

            // Move current to old
            secret.old_value = secret.current_value;
            secret.old_value_len = secret.current_value_len;
            secret.old_set_time = secret.current_set_time;

            // Set new current
            secret.current_value = [0u8; MAX_SECRET_DATA];
            secret.current_value[..value.len()].copy_from_slice(value);
            secret.current_value_len = value.len();
            secret.current_set_time = get_tick_count();

            LSA_STATS.secret_accesses.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(LsaError::SecretNotFound)
}

/// Query secret value
pub fn lsa_query_secret(name: &[u8]) -> Result<Vec<u8>, LsaError> {
    let state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    for i in 0..MAX_SECRETS {
        if state.secrets[i].in_use && state.secrets[i].get_name() == name {
            LSA_STATS.secret_accesses.fetch_add(1, Ordering::Relaxed);
            let len = state.secrets[i].current_value_len;
            return Ok(state.secrets[i].current_value[..len].to_vec());
        }
    }

    Err(LsaError::SecretNotFound)
}

/// Delete a secret
pub fn lsa_delete_secret(name: &[u8]) -> Result<(), LsaError> {
    let mut state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    for i in 0..MAX_SECRETS {
        if state.secrets[i].in_use && state.secrets[i].get_name() == name {
            state.secrets[i].in_use = false;
            state.secrets[i] = LsaSecret::empty();

            if state.secret_count > 0 {
                state.secret_count -= 1;
            }

            return Ok(());
        }
    }

    Err(LsaError::SecretNotFound)
}

// ============================================================================
// Policy Operations
// ============================================================================

/// Query policy information
pub fn lsa_query_information_policy(
    info_class: PolicyInformationClass,
) -> Result<PolicyInfo, LsaError> {
    let state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    LSA_STATS.policy_lookups.fetch_add(1, Ordering::Relaxed);

    match info_class {
        PolicyInformationClass::PolicyPrimaryDomainInformation
        | PolicyInformationClass::PolicyAccountDomainInformation
        | PolicyInformationClass::PolicyLsaServerRoleInformation
        | PolicyInformationClass::PolicyAuditLogInformation
        | PolicyInformationClass::PolicyAuditEventsInformation => {
            Ok(state.policy.clone())
        }
        _ => Err(LsaError::InvalidParameter),
    }
}

/// Set policy information
pub fn lsa_set_information_policy(
    info_class: PolicyInformationClass,
    policy: &PolicyInfo,
) -> Result<(), LsaError> {
    let mut state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    match info_class {
        PolicyInformationClass::PolicyPrimaryDomainInformation => {
            state.policy.primary_domain = policy.primary_domain;
            state.policy.primary_domain_len = policy.primary_domain_len;
            state.policy.primary_domain_sid = policy.primary_domain_sid;
            Ok(())
        }
        PolicyInformationClass::PolicyAccountDomainInformation => {
            state.policy.account_domain = policy.account_domain;
            state.policy.account_domain_len = policy.account_domain_len;
            state.policy.account_domain_sid = policy.account_domain_sid;
            Ok(())
        }
        PolicyInformationClass::PolicyLsaServerRoleInformation => {
            state.policy.server_role = policy.server_role;
            Ok(())
        }
        PolicyInformationClass::PolicyAuditLogInformation => {
            state.policy.audit_log_max_size = policy.audit_log_max_size;
            state.policy.audit_retention_period = policy.audit_retention_period;
            Ok(())
        }
        PolicyInformationClass::PolicyAuditEventsInformation => {
            state.policy.audit_events = policy.audit_events;
            Ok(())
        }
        _ => Err(LsaError::InvalidParameter),
    }
}

// ============================================================================
// Trust Management
// ============================================================================

/// Create a trusted domain
pub fn lsa_create_trusted_domain(
    domain_name: &[u8],
    domain_sid: u64,
    direction: TrustDirection,
    trust_type: TrustType,
) -> Result<(), LsaError> {
    let mut state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    if domain_name.len() > 64 {
        return Err(LsaError::InvalidParameter);
    }

    // Check if exists
    for i in 0..MAX_TRUSTS {
        let len = state.trusts[i].domain_name_len;
        if state.trusts[i].in_use && &state.trusts[i].domain_name[..len] == domain_name {
            return Err(LsaError::InvalidParameter);
        }
    }

    // Create new
    if state.trust_count >= MAX_TRUSTS {
        return Err(LsaError::InsufficientResources);
    }

    for i in 0..MAX_TRUSTS {
        if !state.trusts[i].in_use {
            let trust = &mut state.trusts[i];
            trust.in_use = true;
            trust.domain_name[..domain_name.len()].copy_from_slice(domain_name);
            trust.domain_name_len = domain_name.len();
            trust.domain_sid = domain_sid;
            trust.direction = direction;
            trust.trust_type = trust_type;

            state.trust_count += 1;
            return Ok(());
        }
    }

    Err(LsaError::InsufficientResources)
}

/// Query trusted domain information
pub fn lsa_query_trusted_domain(domain_name: &[u8]) -> Result<TrustInfo, LsaError> {
    let state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    for i in 0..MAX_TRUSTS {
        let len = state.trusts[i].domain_name_len;
        if state.trusts[i].in_use && &state.trusts[i].domain_name[..len] == domain_name {
            return Ok(state.trusts[i].clone());
        }
    }

    Err(LsaError::TrustNotFound)
}

/// Delete a trusted domain
pub fn lsa_delete_trusted_domain(domain_name: &[u8]) -> Result<(), LsaError> {
    let mut state = LSA_STATE.lock();

    if !state.initialized {
        return Err(LsaError::NotInitialized);
    }

    for i in 0..MAX_TRUSTS {
        let len = state.trusts[i].domain_name_len;
        if state.trusts[i].in_use && &state.trusts[i].domain_name[..len] == domain_name {
            state.trusts[i].in_use = false;
            state.trusts[i] = TrustInfo::empty();

            if state.trust_count > 0 {
                state.trust_count -= 1;
            }

            return Ok(());
        }
    }

    Err(LsaError::TrustNotFound)
}

/// Enumerate trusted domains
pub fn lsa_enumerate_trusted_domains() -> Vec<TrustInfo> {
    let state = LSA_STATE.lock();
    let mut trusts = Vec::new();

    if !state.initialized {
        return trusts;
    }

    for i in 0..MAX_TRUSTS {
        if state.trusts[i].in_use {
            trusts.push(state.trusts[i].clone());
        }
    }

    trusts
}

// ============================================================================
// Statistics
// ============================================================================

/// LSA statistics snapshot
#[derive(Debug, Clone, Default)]
pub struct LsaStatsSnapshot {
    pub logons_success: u64,
    pub logons_failed: u64,
    pub logoffs: u64,
    pub auth_calls: u64,
    pub policy_lookups: u64,
    pub secret_accesses: u64,
    pub session_count: usize,
    pub package_count: usize,
    pub secret_count: usize,
    pub trust_count: usize,
}

/// Get LSA statistics
pub fn lsa_get_stats() -> LsaStatsSnapshot {
    let state = LSA_STATE.lock();

    LsaStatsSnapshot {
        logons_success: LSA_STATS.logons_success.load(Ordering::Relaxed),
        logons_failed: LSA_STATS.logons_failed.load(Ordering::Relaxed),
        logoffs: LSA_STATS.logoffs.load(Ordering::Relaxed),
        auth_calls: LSA_STATS.auth_calls.load(Ordering::Relaxed),
        policy_lookups: LSA_STATS.policy_lookups.load(Ordering::Relaxed),
        secret_accesses: LSA_STATS.secret_accesses.load(Ordering::Relaxed),
        session_count: state.session_count,
        package_count: state.auth_package_count,
        secret_count: state.secret_count,
        trust_count: state.trust_count,
    }
}

/// Check if LSA is initialized
pub fn lsa_is_initialized() -> bool {
    LSA_STATE.lock().initialized
}

/// Get logon type name
pub fn logon_type_name(logon_type: LogonType) -> &'static str {
    match logon_type {
        LogonType::Interactive => "Interactive",
        LogonType::Network => "Network",
        LogonType::Batch => "Batch",
        LogonType::Service => "Service",
        LogonType::Unlock => "Unlock",
        LogonType::NetworkCleartext => "NetworkCleartext",
        LogonType::NewCredentials => "NewCredentials",
        LogonType::RemoteInteractive => "RemoteInteractive",
        LogonType::CachedInteractive => "CachedInteractive",
    }
}

/// Get server role name
pub fn server_role_name(role: ServerRole) -> &'static str {
    match role {
        ServerRole::Standalone => "Standalone",
        ServerRole::PrimaryDC => "Primary Domain Controller",
        ServerRole::BackupDC => "Backup Domain Controller",
    }
}
