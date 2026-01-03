//! IPSEC - IP Security
//!
//! IPSEC provides network layer security for IP packets:
//! - Authentication Header (AH) - integrity and authentication
//! - Encapsulating Security Payload (ESP) - confidentiality + auth
//! - Internet Key Exchange (IKE) - key management
//!
//! Security Associations (SAs) define the security parameters
//! for protected communications.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;
use crate::net::ip::Ipv4Address;

/// Maximum Security Associations
const MAX_SECURITY_ASSOCIATIONS: usize = 256;

/// Maximum Security Policies
const MAX_SECURITY_POLICIES: usize = 128;

/// Maximum IKE sessions
const MAX_IKE_SESSIONS: usize = 64;

/// SPI (Security Parameter Index) minimum
const SPI_MIN: u32 = 256;

// ============================================================================
// IPSEC Protocols
// ============================================================================

/// IPSEC protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpsecProtocol {
    /// Authentication Header
    Ah = 51,
    /// Encapsulating Security Payload
    Esp = 50,
}

/// IPSEC mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsecMode {
    /// Transport mode (end-to-end)
    Transport,
    /// Tunnel mode (gateway-to-gateway)
    Tunnel,
}

// ============================================================================
// Encryption Algorithms
// ============================================================================

/// Encryption algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// No encryption (NULL)
    Null,
    /// DES-CBC
    DesCbc,
    /// 3DES-CBC
    TripleDesCbc,
    /// AES-CBC 128-bit
    AesCbc128,
    /// AES-CBC 192-bit
    AesCbc192,
    /// AES-CBC 256-bit
    AesCbc256,
    /// AES-GCM 128-bit
    AesGcm128,
    /// AES-GCM 256-bit
    AesGcm256,
}

/// Authentication algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAlgorithm {
    /// No authentication
    None,
    /// HMAC-MD5
    HmacMd5,
    /// HMAC-SHA1
    HmacSha1,
    /// HMAC-SHA256
    HmacSha256,
    /// HMAC-SHA384
    HmacSha384,
    /// HMAC-SHA512
    HmacSha512,
    /// AES-XCBC-MAC
    AesXcbcMac,
}

// ============================================================================
// Security Association (SA)
// ============================================================================

/// SA state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaState {
    /// SA is being negotiated
    Larval,
    /// SA is active
    Mature,
    /// SA is expiring
    Dying,
    /// SA is dead
    Dead,
}

/// SA direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaDirection {
    /// Inbound SA
    Inbound,
    /// Outbound SA
    Outbound,
}

/// Security Association
#[derive(Clone)]
pub struct SecurityAssociation {
    /// SA ID
    pub id: u32,
    /// Security Parameter Index
    pub spi: u32,
    /// Protocol (AH or ESP)
    pub protocol: IpsecProtocol,
    /// Mode (transport or tunnel)
    pub mode: IpsecMode,
    /// Direction
    pub direction: SaDirection,
    /// State
    pub state: SaState,
    /// Source address
    pub src_addr: Ipv4Address,
    /// Destination address
    pub dst_addr: Ipv4Address,
    /// Encryption algorithm
    pub enc_alg: EncryptionAlgorithm,
    /// Authentication algorithm
    pub auth_alg: AuthAlgorithm,
    /// Encryption key
    pub enc_key: [u8; 64],
    /// Encryption key length
    pub enc_key_len: usize,
    /// Authentication key
    pub auth_key: [u8; 64],
    /// Authentication key length
    pub auth_key_len: usize,
    /// Sequence number
    pub seq_num: u64,
    /// Replay window
    pub replay_window: u64,
    /// Anti-replay bitmap
    pub replay_bitmap: u64,
    /// Lifetime (seconds)
    pub lifetime_secs: u32,
    /// Lifetime (bytes)
    pub lifetime_bytes: u64,
    /// Bytes processed
    pub bytes_processed: u64,
    /// Packets processed
    pub packets_processed: u64,
    /// Creation timestamp
    pub created: u64,
    /// Active flag
    pub active: bool,
}

impl Default for SecurityAssociation {
    fn default() -> Self {
        Self {
            id: 0,
            spi: 0,
            protocol: IpsecProtocol::Esp,
            mode: IpsecMode::Transport,
            direction: SaDirection::Outbound,
            state: SaState::Larval,
            src_addr: Ipv4Address([0, 0, 0, 0]),
            dst_addr: Ipv4Address([0, 0, 0, 0]),
            enc_alg: EncryptionAlgorithm::Null,
            auth_alg: AuthAlgorithm::None,
            enc_key: [0; 64],
            enc_key_len: 0,
            auth_key: [0; 64],
            auth_key_len: 0,
            seq_num: 0,
            replay_window: 64,
            replay_bitmap: 0,
            lifetime_secs: 28800, // 8 hours
            lifetime_bytes: 0,
            bytes_processed: 0,
            packets_processed: 0,
            created: 0,
            active: false,
        }
    }
}

// ============================================================================
// Security Policy
// ============================================================================

/// Policy action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Discard the packet
    Discard,
    /// Bypass IPSEC (cleartext)
    Bypass,
    /// Protect with IPSEC
    Protect,
}

/// Policy direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDirection {
    /// Inbound traffic
    Inbound,
    /// Outbound traffic
    Outbound,
}

/// Traffic selector
#[derive(Clone)]
pub struct TrafficSelector {
    /// Source address
    pub src_addr: Ipv4Address,
    /// Source mask
    pub src_mask: Ipv4Address,
    /// Destination address
    pub dst_addr: Ipv4Address,
    /// Destination mask
    pub dst_mask: Ipv4Address,
    /// Protocol (0 = any)
    pub protocol: u8,
    /// Source port range start
    pub src_port_start: u16,
    /// Source port range end
    pub src_port_end: u16,
    /// Destination port range start
    pub dst_port_start: u16,
    /// Destination port range end
    pub dst_port_end: u16,
}

impl Default for TrafficSelector {
    fn default() -> Self {
        Self {
            src_addr: Ipv4Address([0, 0, 0, 0]),
            src_mask: Ipv4Address([0, 0, 0, 0]),
            dst_addr: Ipv4Address([0, 0, 0, 0]),
            dst_mask: Ipv4Address([0, 0, 0, 0]),
            protocol: 0,
            src_port_start: 0,
            src_port_end: 65535,
            dst_port_start: 0,
            dst_port_end: 65535,
        }
    }
}

/// Security Policy
#[derive(Clone)]
pub struct SecurityPolicy {
    /// Policy ID
    pub id: u32,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Direction
    pub direction: PolicyDirection,
    /// Traffic selector
    pub selector: TrafficSelector,
    /// Action
    pub action: PolicyAction,
    /// Required protocol (if action is Protect)
    pub protocol: IpsecProtocol,
    /// Required mode
    pub mode: IpsecMode,
    /// Required encryption algorithm
    pub enc_alg: EncryptionAlgorithm,
    /// Required auth algorithm
    pub auth_alg: AuthAlgorithm,
    /// Associated SA ID (if established)
    pub sa_id: Option<u32>,
    /// Match count
    pub match_count: u64,
    /// Active flag
    pub active: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            id: 0,
            priority: 1000,
            direction: PolicyDirection::Outbound,
            selector: TrafficSelector::default(),
            action: PolicyAction::Bypass,
            protocol: IpsecProtocol::Esp,
            mode: IpsecMode::Transport,
            enc_alg: EncryptionAlgorithm::AesCbc128,
            auth_alg: AuthAlgorithm::HmacSha256,
            sa_id: None,
            match_count: 0,
            active: false,
        }
    }
}

// ============================================================================
// IKE (Internet Key Exchange)
// ============================================================================

/// IKE version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeVersion {
    /// IKEv1
    V1,
    /// IKEv2
    V2,
}

/// IKE session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeState {
    /// Initial
    Initial,
    /// SA_INIT sent/received
    SaInit,
    /// SA_AUTH sent/received
    SaAuth,
    /// Established
    Established,
    /// Rekeying
    Rekeying,
    /// Deleting
    Deleting,
    /// Dead
    Dead,
}

/// IKE session
#[derive(Clone)]
pub struct IkeSession {
    /// Session ID
    pub id: u32,
    /// Local SPI
    pub local_spi: u64,
    /// Remote SPI
    pub remote_spi: u64,
    /// IKE version
    pub version: IkeVersion,
    /// State
    pub state: IkeState,
    /// Local address
    pub local_addr: Ipv4Address,
    /// Remote address
    pub remote_addr: Ipv4Address,
    /// Local port
    pub local_port: u16,
    /// Remote port
    pub remote_port: u16,
    /// Created child SAs
    pub child_sa_count: u32,
    /// Message ID
    pub msg_id: u32,
    /// Active flag
    pub active: bool,
}

impl Default for IkeSession {
    fn default() -> Self {
        Self {
            id: 0,
            local_spi: 0,
            remote_spi: 0,
            version: IkeVersion::V2,
            state: IkeState::Initial,
            local_addr: Ipv4Address([0, 0, 0, 0]),
            remote_addr: Ipv4Address([0, 0, 0, 0]),
            local_port: 500,
            remote_port: 500,
            child_sa_count: 0,
            msg_id: 0,
            active: false,
        }
    }
}

// ============================================================================
// IPSEC Statistics
// ============================================================================

/// IPSEC statistics
#[derive(Debug)]
pub struct IpsecStatistics {
    /// Packets protected (outbound)
    pub packets_protected: AtomicU64,
    /// Packets decrypted (inbound)
    pub packets_decrypted: AtomicU64,
    /// Bytes protected
    pub bytes_protected: AtomicU64,
    /// Bytes decrypted
    pub bytes_decrypted: AtomicU64,
    /// Authentication failures
    pub auth_failures: AtomicU64,
    /// Replay attacks detected
    pub replay_attacks: AtomicU64,
    /// SA lookup failures
    pub sa_lookup_failures: AtomicU64,
    /// Policy matches
    pub policy_matches: AtomicU64,
    /// Active SAs
    pub active_sas: AtomicU32,
    /// Active policies
    pub active_policies: AtomicU32,
    /// Active IKE sessions
    pub active_ike_sessions: AtomicU32,
}

impl Default for IpsecStatistics {
    fn default() -> Self {
        Self {
            packets_protected: AtomicU64::new(0),
            packets_decrypted: AtomicU64::new(0),
            bytes_protected: AtomicU64::new(0),
            bytes_decrypted: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            replay_attacks: AtomicU64::new(0),
            sa_lookup_failures: AtomicU64::new(0),
            policy_matches: AtomicU64::new(0),
            active_sas: AtomicU32::new(0),
            active_policies: AtomicU32::new(0),
            active_ike_sessions: AtomicU32::new(0),
        }
    }
}

// ============================================================================
// IPSEC Errors
// ============================================================================

/// IPSEC error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum IpsecError {
    /// Success
    Success = 0,
    /// Not initialized
    NotInitialized = -1,
    /// Invalid parameter
    InvalidParameter = -2,
    /// SA not found
    SaNotFound = -3,
    /// Policy not found
    PolicyNotFound = -4,
    /// Session not found
    SessionNotFound = -5,
    /// Already exists
    AlreadyExists = -6,
    /// No more entries
    NoMoreEntries = -7,
    /// Authentication failed
    AuthFailed = -8,
    /// Replay attack
    ReplayAttack = -9,
    /// Invalid SPI
    InvalidSpi = -10,
    /// Encryption failed
    EncryptionFailed = -11,
    /// Decryption failed
    DecryptionFailed = -12,
    /// Invalid packet
    InvalidPacket = -13,
}

// ============================================================================
// IPSEC Global State
// ============================================================================

/// IPSEC global state
pub struct IpsecState {
    /// Security Associations
    pub sas: [SecurityAssociation; MAX_SECURITY_ASSOCIATIONS],
    /// Next SA ID
    pub next_sa_id: u32,
    /// Next SPI
    pub next_spi: u32,
    /// Security Policies
    pub policies: [SecurityPolicy; MAX_SECURITY_POLICIES],
    /// Next policy ID
    pub next_policy_id: u32,
    /// IKE sessions
    pub ike_sessions: [IkeSession; MAX_IKE_SESSIONS],
    /// Next IKE session ID
    pub next_ike_id: u32,
    /// Statistics
    pub statistics: IpsecStatistics,
    /// Initialized flag
    pub initialized: bool,
}

impl IpsecState {
    const fn new() -> Self {
        Self {
            sas: [const { SecurityAssociation {
                id: 0,
                spi: 0,
                protocol: IpsecProtocol::Esp,
                mode: IpsecMode::Transport,
                direction: SaDirection::Outbound,
                state: SaState::Larval,
                src_addr: Ipv4Address([0, 0, 0, 0]),
                dst_addr: Ipv4Address([0, 0, 0, 0]),
                enc_alg: EncryptionAlgorithm::Null,
                auth_alg: AuthAlgorithm::None,
                enc_key: [0; 64],
                enc_key_len: 0,
                auth_key: [0; 64],
                auth_key_len: 0,
                seq_num: 0,
                replay_window: 64,
                replay_bitmap: 0,
                lifetime_secs: 28800,
                lifetime_bytes: 0,
                bytes_processed: 0,
                packets_processed: 0,
                created: 0,
                active: false,
            }}; MAX_SECURITY_ASSOCIATIONS],
            next_sa_id: 1,
            next_spi: SPI_MIN,
            policies: [const { SecurityPolicy {
                id: 0,
                priority: 1000,
                direction: PolicyDirection::Outbound,
                selector: TrafficSelector {
                    src_addr: Ipv4Address([0, 0, 0, 0]),
                    src_mask: Ipv4Address([0, 0, 0, 0]),
                    dst_addr: Ipv4Address([0, 0, 0, 0]),
                    dst_mask: Ipv4Address([0, 0, 0, 0]),
                    protocol: 0,
                    src_port_start: 0,
                    src_port_end: 65535,
                    dst_port_start: 0,
                    dst_port_end: 65535,
                },
                action: PolicyAction::Bypass,
                protocol: IpsecProtocol::Esp,
                mode: IpsecMode::Transport,
                enc_alg: EncryptionAlgorithm::AesCbc128,
                auth_alg: AuthAlgorithm::HmacSha256,
                sa_id: None,
                match_count: 0,
                active: false,
            }}; MAX_SECURITY_POLICIES],
            next_policy_id: 1,
            ike_sessions: [const { IkeSession {
                id: 0,
                local_spi: 0,
                remote_spi: 0,
                version: IkeVersion::V2,
                state: IkeState::Initial,
                local_addr: Ipv4Address([0, 0, 0, 0]),
                remote_addr: Ipv4Address([0, 0, 0, 0]),
                local_port: 500,
                remote_port: 500,
                child_sa_count: 0,
                msg_id: 0,
                active: false,
            }}; MAX_IKE_SESSIONS],
            next_ike_id: 1,
            statistics: IpsecStatistics {
                packets_protected: AtomicU64::new(0),
                packets_decrypted: AtomicU64::new(0),
                bytes_protected: AtomicU64::new(0),
                bytes_decrypted: AtomicU64::new(0),
                auth_failures: AtomicU64::new(0),
                replay_attacks: AtomicU64::new(0),
                sa_lookup_failures: AtomicU64::new(0),
                policy_matches: AtomicU64::new(0),
                active_sas: AtomicU32::new(0),
                active_policies: AtomicU32::new(0),
                active_ike_sessions: AtomicU32::new(0),
            },
            initialized: false,
        }
    }
}

/// Global IPSEC state
static IPSEC_STATE: SpinLock<IpsecState> = SpinLock::new(IpsecState::new());

// ============================================================================
// Security Association Management
// ============================================================================

/// Create a Security Association
pub fn ipsec_create_sa(
    protocol: IpsecProtocol,
    mode: IpsecMode,
    direction: SaDirection,
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    enc_alg: EncryptionAlgorithm,
    auth_alg: AuthAlgorithm,
    enc_key: &[u8],
    auth_key: &[u8],
) -> Result<(u32, u32), IpsecError> {
    let mut state = IPSEC_STATE.lock();

    if !state.initialized {
        return Err(IpsecError::NotInitialized);
    }

    if enc_key.len() > 64 || auth_key.len() > 64 {
        return Err(IpsecError::InvalidParameter);
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_SECURITY_ASSOCIATIONS {
        if !state.sas[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(IpsecError::NoMoreEntries)?;

    let sa_id = state.next_sa_id;
    state.next_sa_id += 1;

    let spi = state.next_spi;
    state.next_spi += 1;

    state.sas[idx].id = sa_id;
    state.sas[idx].spi = spi;
    state.sas[idx].protocol = protocol;
    state.sas[idx].mode = mode;
    state.sas[idx].direction = direction;
    state.sas[idx].state = SaState::Mature;
    state.sas[idx].src_addr = src_addr;
    state.sas[idx].dst_addr = dst_addr;
    state.sas[idx].enc_alg = enc_alg;
    state.sas[idx].auth_alg = auth_alg;
    state.sas[idx].enc_key_len = enc_key.len();
    state.sas[idx].enc_key[..enc_key.len()].copy_from_slice(enc_key);
    state.sas[idx].auth_key_len = auth_key.len();
    state.sas[idx].auth_key[..auth_key.len()].copy_from_slice(auth_key);
    state.sas[idx].seq_num = 1;
    state.sas[idx].active = true;

    state.statistics.active_sas.fetch_add(1, Ordering::Relaxed);

    Ok((sa_id, spi))
}

/// Delete a Security Association
pub fn ipsec_delete_sa(sa_id: u32) -> Result<(), IpsecError> {
    let mut state = IPSEC_STATE.lock();

    if !state.initialized {
        return Err(IpsecError::NotInitialized);
    }

    for idx in 0..MAX_SECURITY_ASSOCIATIONS {
        if state.sas[idx].active && state.sas[idx].id == sa_id {
            state.sas[idx].state = SaState::Dead;
            state.sas[idx].active = false;
            state.statistics.active_sas.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(IpsecError::SaNotFound)
}

/// Lookup SA by SPI
pub fn ipsec_lookup_sa(spi: u32, dst_addr: Ipv4Address) -> Result<u32, IpsecError> {
    let state = IPSEC_STATE.lock();

    if !state.initialized {
        return Err(IpsecError::NotInitialized);
    }

    for idx in 0..MAX_SECURITY_ASSOCIATIONS {
        if state.sas[idx].active
            && state.sas[idx].spi == spi
            && state.sas[idx].dst_addr == dst_addr
        {
            return Ok(state.sas[idx].id);
        }
    }

    state.statistics.sa_lookup_failures.fetch_add(1, Ordering::Relaxed);
    Err(IpsecError::SaNotFound)
}

// ============================================================================
// Security Policy Management
// ============================================================================

/// Add a security policy
pub fn ipsec_add_policy(
    direction: PolicyDirection,
    selector: TrafficSelector,
    action: PolicyAction,
    priority: u32,
) -> Result<u32, IpsecError> {
    let mut state = IPSEC_STATE.lock();

    if !state.initialized {
        return Err(IpsecError::NotInitialized);
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_SECURITY_POLICIES {
        if !state.policies[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(IpsecError::NoMoreEntries)?;

    let policy_id = state.next_policy_id;
    state.next_policy_id += 1;

    state.policies[idx].id = policy_id;
    state.policies[idx].priority = priority;
    state.policies[idx].direction = direction;
    state.policies[idx].selector = selector;
    state.policies[idx].action = action;
    state.policies[idx].active = true;

    state.statistics.active_policies.fetch_add(1, Ordering::Relaxed);

    Ok(policy_id)
}

/// Remove a security policy
pub fn ipsec_remove_policy(policy_id: u32) -> Result<(), IpsecError> {
    let mut state = IPSEC_STATE.lock();

    if !state.initialized {
        return Err(IpsecError::NotInitialized);
    }

    for idx in 0..MAX_SECURITY_POLICIES {
        if state.policies[idx].active && state.policies[idx].id == policy_id {
            state.policies[idx].active = false;
            state.statistics.active_policies.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(IpsecError::PolicyNotFound)
}

/// Match policy for a packet
pub fn ipsec_match_policy(
    direction: PolicyDirection,
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> Result<(u32, PolicyAction), IpsecError> {
    let mut state = IPSEC_STATE.lock();

    if !state.initialized {
        return Err(IpsecError::NotInitialized);
    }

    let mut best_match: Option<(usize, u32)> = None;

    for idx in 0..MAX_SECURITY_POLICIES {
        if !state.policies[idx].active {
            continue;
        }

        if state.policies[idx].direction != direction {
            continue;
        }

        let sel = &state.policies[idx].selector;

        // Check address match (simplified - should use mask)
        let src_match = sel.src_addr.0 == [0, 0, 0, 0] || sel.src_addr == src_addr;
        let dst_match = sel.dst_addr.0 == [0, 0, 0, 0] || sel.dst_addr == dst_addr;
        let proto_match = sel.protocol == 0 || sel.protocol == protocol;
        let src_port_match = src_port >= sel.src_port_start && src_port <= sel.src_port_end;
        let dst_port_match = dst_port >= sel.dst_port_start && dst_port <= sel.dst_port_end;

        if src_match && dst_match && proto_match && src_port_match && dst_port_match {
            if best_match.is_none() || state.policies[idx].priority < best_match.unwrap().1 {
                best_match = Some((idx, state.policies[idx].priority));
            }
        }
    }

    if let Some((idx, _)) = best_match {
        state.policies[idx].match_count += 1;
        state.statistics.policy_matches.fetch_add(1, Ordering::Relaxed);
        return Ok((state.policies[idx].id, state.policies[idx].action));
    }

    // Default to bypass
    Ok((0, PolicyAction::Bypass))
}

// ============================================================================
// Query Functions
// ============================================================================

/// List Security Associations
pub fn ipsec_list_sas() -> Vec<(u32, u32, IpsecProtocol, SaState)> {
    let state = IPSEC_STATE.lock();
    let mut result = Vec::new();

    for idx in 0..MAX_SECURITY_ASSOCIATIONS {
        if state.sas[idx].active {
            result.push((
                state.sas[idx].id,
                state.sas[idx].spi,
                state.sas[idx].protocol,
                state.sas[idx].state,
            ));
        }
    }

    result
}

/// List Security Policies
pub fn ipsec_list_policies() -> Vec<(u32, PolicyDirection, PolicyAction, u32)> {
    let state = IPSEC_STATE.lock();
    let mut result = Vec::new();

    for idx in 0..MAX_SECURITY_POLICIES {
        if state.policies[idx].active {
            result.push((
                state.policies[idx].id,
                state.policies[idx].direction,
                state.policies[idx].action,
                state.policies[idx].priority,
            ));
        }
    }

    result
}

/// Get IPSEC statistics
pub fn ipsec_get_statistics() -> IpsecStatistics {
    let state = IPSEC_STATE.lock();

    IpsecStatistics {
        packets_protected: AtomicU64::new(state.statistics.packets_protected.load(Ordering::Relaxed)),
        packets_decrypted: AtomicU64::new(state.statistics.packets_decrypted.load(Ordering::Relaxed)),
        bytes_protected: AtomicU64::new(state.statistics.bytes_protected.load(Ordering::Relaxed)),
        bytes_decrypted: AtomicU64::new(state.statistics.bytes_decrypted.load(Ordering::Relaxed)),
        auth_failures: AtomicU64::new(state.statistics.auth_failures.load(Ordering::Relaxed)),
        replay_attacks: AtomicU64::new(state.statistics.replay_attacks.load(Ordering::Relaxed)),
        sa_lookup_failures: AtomicU64::new(state.statistics.sa_lookup_failures.load(Ordering::Relaxed)),
        policy_matches: AtomicU64::new(state.statistics.policy_matches.load(Ordering::Relaxed)),
        active_sas: AtomicU32::new(state.statistics.active_sas.load(Ordering::Relaxed)),
        active_policies: AtomicU32::new(state.statistics.active_policies.load(Ordering::Relaxed)),
        active_ike_sessions: AtomicU32::new(state.statistics.active_ike_sessions.load(Ordering::Relaxed)),
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize IPSEC subsystem
pub fn init() {
    crate::serial_println!("[IPSEC] Initializing IP Security...");

    {
        let mut state = IPSEC_STATE.lock();
        state.initialized = true;
    }

    crate::serial_println!("[IPSEC] IPSEC initialized");
}
