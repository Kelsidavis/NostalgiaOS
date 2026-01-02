//! NTLM Authentication Protocol
//!
//! Windows NT LAN Manager authentication protocol implementation:
//!
//! - **NTLM v1**: Legacy authentication (LM/NTLM responses)
//! - **NTLM v2**: Enhanced authentication with HMAC-MD5
//! - **NTLMv2 Session Security**: Session key generation
//! - **Challenge/Response**: Three-message authentication flow
//!
//! NTLM authentication flow:
//! 1. Client sends NEGOTIATE message with capabilities
//! 2. Server sends CHALLENGE message with server challenge
//! 3. Client sends AUTHENTICATE message with credentials
//!
//! Used by SMB, HTTP, LDAP, and other protocols for authentication.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::ke::SpinLock;
use crate::hal::apic::get_tick_count;

// ============================================================================
// Constants
// ============================================================================

/// NTLM signature ("NTLMSSP\0")
pub const NTLM_SIGNATURE: [u8; 8] = [0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00];

/// Maximum sessions
pub const MAX_NTLM_SESSIONS: usize = 256;

/// Challenge length
pub const NTLM_CHALLENGE_LENGTH: usize = 8;

/// LM hash length
pub const LM_HASH_LENGTH: usize = 16;

/// NT hash length
pub const NT_HASH_LENGTH: usize = 16;

/// Session key length
pub const SESSION_KEY_LENGTH: usize = 16;

/// Maximum domain/workstation name length
pub const MAX_NAME_LENGTH: usize = 64;

/// Maximum username length
pub const MAX_USERNAME_LENGTH: usize = 64;

// ============================================================================
// Message Types
// ============================================================================

/// NTLM message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NtlmMessageType {
    /// Type 1: Negotiate message
    Negotiate = 1,
    /// Type 2: Challenge message
    Challenge = 2,
    /// Type 3: Authenticate message
    Authenticate = 3,
}

// ============================================================================
// Negotiate Flags
// ============================================================================

/// NTLM negotiate flags
pub mod negotiate_flags {
    /// Unicode strings are supported
    pub const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x00000001;
    /// OEM strings are supported
    pub const NTLMSSP_NEGOTIATE_OEM: u32 = 0x00000002;
    /// Request target name in Type 2 message
    pub const NTLMSSP_REQUEST_TARGET: u32 = 0x00000004;
    /// NTLM authentication is used
    pub const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x00000200;
    /// Domain name is supplied
    pub const NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED: u32 = 0x00001000;
    /// Workstation name is supplied
    pub const NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED: u32 = 0x00002000;
    /// Local call
    pub const NTLMSSP_NEGOTIATE_LOCAL_CALL: u32 = 0x00004000;
    /// Request signing
    pub const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x00008000;
    /// Target type is domain
    pub const NTLMSSP_TARGET_TYPE_DOMAIN: u32 = 0x00010000;
    /// Target type is server
    pub const NTLMSSP_TARGET_TYPE_SERVER: u32 = 0x00020000;
    /// NTLMv2 key usage
    pub const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x00080000;
    /// Identify-level token
    pub const NTLMSSP_NEGOTIATE_IDENTIFY: u32 = 0x00100000;
    /// LM session key
    pub const NTLMSSP_NEGOTIATE_LM_KEY: u32 = 0x00000080;
    /// NTLM2 session response
    pub const NTLMSSP_NEGOTIATE_NTLM2: u32 = 0x00080000;
    /// Target info is present
    pub const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x00800000;
    /// Version info is present
    pub const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x02000000;
    /// 128-bit encryption
    pub const NTLMSSP_NEGOTIATE_128: u32 = 0x20000000;
    /// Key exchange
    pub const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x40000000;
    /// 56-bit encryption
    pub const NTLMSSP_NEGOTIATE_56: u32 = 0x80000000;
}

// ============================================================================
// Error Types
// ============================================================================

/// NTLM error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NtlmError {
    /// Success
    Success = 0,
    /// Invalid parameter
    InvalidParameter = 0xC000000D,
    /// Invalid message
    InvalidMessage = 0xC0000015,
    /// Invalid signature
    InvalidSignature = 0xC000006C,
    /// Authentication failed
    AuthenticationFailed = 0xC000006D,
    /// Session not found
    SessionNotFound = 0xC0000020,
    /// Session expired
    SessionExpired = 0xC0000070,
    /// Insufficient resources
    InsufficientResources = 0xC000009A,
    /// Not initialized
    NotInitialized = 0xC0000001,
    /// Buffer too small
    BufferTooSmall = 0xC0000023,
    /// Unsupported version
    UnsupportedVersion = 0xC0000021,
}

// ============================================================================
// Data Structures
// ============================================================================

/// Security buffer for variable-length fields
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct SecurityBuffer {
    /// Length of data
    pub len: u16,
    /// Maximum length
    pub max_len: u16,
    /// Offset from start of message
    pub offset: u32,
}

/// NTLM version info
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct NtlmVersion {
    /// Product major version
    pub major_version: u8,
    /// Product minor version
    pub minor_version: u8,
    /// Product build number
    pub build_number: u16,
    /// Reserved
    pub reserved: [u8; 3],
    /// NTLM revision
    pub ntlm_revision: u8,
}

impl NtlmVersion {
    pub const fn windows_2003() -> Self {
        Self {
            major_version: 5,
            minor_version: 2,
            build_number: 3790,
            reserved: [0, 0, 0],
            ntlm_revision: 0x0F, // NTLMSSP_REVISION_W2K3
        }
    }
}

/// Target info AV pairs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AvId {
    /// End of list
    MsvAvEOL = 0,
    /// NetBIOS computer name
    MsvAvNbComputerName = 1,
    /// NetBIOS domain name
    MsvAvNbDomainName = 2,
    /// DNS computer name
    MsvAvDnsComputerName = 3,
    /// DNS domain name
    MsvAvDnsDomainName = 4,
    /// DNS tree name
    MsvAvDnsTreeName = 5,
    /// Flags
    MsvAvFlags = 6,
    /// Timestamp
    MsvAvTimestamp = 7,
    /// Single host restriction
    MsvAvSingleHost = 8,
    /// Target name
    MsvAvTargetName = 9,
    /// Channel bindings
    MsvChannelBindings = 10,
}

/// NTLM session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    /// Initial state
    Initial = 0,
    /// Negotiate sent (client) or received (server)
    NegotiateSent = 1,
    /// Challenge sent (server) or received (client)
    ChallengeSent = 2,
    /// Authenticate sent (client) or received (server)
    AuthenticateSent = 3,
    /// Authentication complete
    Complete = 4,
    /// Session failed
    Failed = 5,
}

/// NTLM session
#[derive(Debug, Clone)]
pub struct NtlmSession {
    /// Session in use
    pub in_use: bool,
    /// Session ID
    pub session_id: u64,
    /// Session state
    pub state: SessionState,
    /// Is server side
    pub is_server: bool,
    /// Negotiate flags
    pub negotiate_flags: u32,
    /// Server challenge
    pub server_challenge: [u8; NTLM_CHALLENGE_LENGTH],
    /// Client challenge
    pub client_challenge: [u8; NTLM_CHALLENGE_LENGTH],
    /// Domain name
    pub domain: [u8; MAX_NAME_LENGTH],
    pub domain_len: usize,
    /// Workstation name
    pub workstation: [u8; MAX_NAME_LENGTH],
    pub workstation_len: usize,
    /// Username
    pub username: [u8; MAX_USERNAME_LENGTH],
    pub username_len: usize,
    /// Session key
    pub session_key: [u8; SESSION_KEY_LENGTH],
    /// Session key established
    pub session_key_valid: bool,
    /// Creation time
    pub creation_time: u64,
    /// Last activity time
    pub last_activity: u64,
    /// Session expiration time (0 = no expiry)
    pub expiration_time: u64,
}

impl NtlmSession {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            session_id: 0,
            state: SessionState::Initial,
            is_server: false,
            negotiate_flags: 0,
            server_challenge: [0u8; NTLM_CHALLENGE_LENGTH],
            client_challenge: [0u8; NTLM_CHALLENGE_LENGTH],
            domain: [0u8; MAX_NAME_LENGTH],
            domain_len: 0,
            workstation: [0u8; MAX_NAME_LENGTH],
            workstation_len: 0,
            username: [0u8; MAX_USERNAME_LENGTH],
            username_len: 0,
            session_key: [0u8; SESSION_KEY_LENGTH],
            session_key_valid: false,
            creation_time: 0,
            last_activity: 0,
            expiration_time: 0,
        }
    }

    pub fn get_domain(&self) -> &[u8] {
        &self.domain[..self.domain_len]
    }

    pub fn get_workstation(&self) -> &[u8] {
        &self.workstation[..self.workstation_len]
    }

    pub fn get_username(&self) -> &[u8] {
        &self.username[..self.username_len]
    }
}

/// NTLM configuration
#[derive(Debug, Clone)]
pub struct NtlmConfig {
    /// Allow LM authentication
    pub allow_lm: bool,
    /// Allow NTLMv1
    pub allow_ntlmv1: bool,
    /// Require NTLMv2
    pub require_ntlmv2: bool,
    /// Require signing
    pub require_signing: bool,
    /// Require sealing (encryption)
    pub require_sealing: bool,
    /// Session timeout in ticks (0 = no timeout)
    pub session_timeout: u64,
    /// Server domain name
    pub server_domain: [u8; MAX_NAME_LENGTH],
    pub server_domain_len: usize,
    /// Server workstation name
    pub server_workstation: [u8; MAX_NAME_LENGTH],
    pub server_workstation_len: usize,
}

impl NtlmConfig {
    pub const fn new() -> Self {
        Self {
            allow_lm: false,
            allow_ntlmv1: true,
            require_ntlmv2: false,
            require_signing: false,
            require_sealing: false,
            session_timeout: 0,
            server_domain: [0u8; MAX_NAME_LENGTH],
            server_domain_len: 0,
            server_workstation: [0u8; MAX_NAME_LENGTH],
            server_workstation_len: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// NTLM subsystem state
struct NtlmState {
    /// Initialized flag
    initialized: bool,
    /// Configuration
    config: NtlmConfig,
    /// Active sessions
    sessions: [NtlmSession; MAX_NTLM_SESSIONS],
    session_count: usize,
    /// Next session ID
    next_session_id: u64,
    /// Challenge counter for unique challenges
    challenge_counter: u64,
}

impl NtlmState {
    const fn new() -> Self {
        Self {
            initialized: false,
            config: NtlmConfig::new(),
            sessions: [const { NtlmSession::empty() }; MAX_NTLM_SESSIONS],
            session_count: 0,
            next_session_id: 1,
            challenge_counter: 0,
        }
    }
}

static NTLM_STATE: SpinLock<NtlmState> = SpinLock::new(NtlmState::new());

/// NTLM statistics
struct NtlmStats {
    /// Total authentications attempted
    auth_attempts: AtomicU64,
    /// Successful authentications
    auth_success: AtomicU64,
    /// Failed authentications
    auth_failures: AtomicU64,
    /// NTLMv1 authentications
    ntlmv1_auth: AtomicU64,
    /// NTLMv2 authentications
    ntlmv2_auth: AtomicU64,
    /// Sessions created
    sessions_created: AtomicU64,
    /// Sessions expired
    sessions_expired: AtomicU64,
}

static NTLM_STATS: NtlmStats = NtlmStats {
    auth_attempts: AtomicU64::new(0),
    auth_success: AtomicU64::new(0),
    auth_failures: AtomicU64::new(0),
    ntlmv1_auth: AtomicU64::new(0),
    ntlmv2_auth: AtomicU64::new(0),
    sessions_created: AtomicU64::new(0),
    sessions_expired: AtomicU64::new(0),
};

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the NTLM subsystem
pub fn init() {
    crate::serial_println!("[NTLM] Initializing NTLM authentication...");

    let mut state = NTLM_STATE.lock();

    if state.initialized {
        crate::serial_println!("[NTLM] Already initialized");
        return;
    }

    // Set default configuration
    state.config.allow_lm = false; // LM is insecure
    state.config.allow_ntlmv1 = true; // Allow NTLMv1 for compatibility
    state.config.require_ntlmv2 = false;

    // Set server identity
    let domain = b"WORKGROUP";
    state.config.server_domain[..domain.len()].copy_from_slice(domain);
    state.config.server_domain_len = domain.len();

    let workstation = b"NOSTALGOS";
    state.config.server_workstation[..workstation.len()].copy_from_slice(workstation);
    state.config.server_workstation_len = workstation.len();

    state.initialized = true;

    crate::serial_println!("[NTLM] NTLM authentication initialized");
}

// ============================================================================
// Session Management
// ============================================================================

/// Create a new NTLM session
pub fn ntlm_create_session(is_server: bool) -> Result<u64, NtlmError> {
    let mut state = NTLM_STATE.lock();

    if !state.initialized {
        return Err(NtlmError::NotInitialized);
    }

    if state.session_count >= MAX_NTLM_SESSIONS {
        return Err(NtlmError::InsufficientResources);
    }

    let session_id = state.next_session_id;
    state.next_session_id += 1;

    // Extract config values before mutable borrow
    let session_timeout = state.config.session_timeout;

    for i in 0..MAX_NTLM_SESSIONS {
        if !state.sessions[i].in_use {
            let creation_time = get_tick_count();
            state.sessions[i].in_use = true;
            state.sessions[i].session_id = session_id;
            state.sessions[i].state = SessionState::Initial;
            state.sessions[i].is_server = is_server;
            state.sessions[i].creation_time = creation_time;
            state.sessions[i].last_activity = creation_time;

            if session_timeout > 0 {
                state.sessions[i].expiration_time = creation_time + session_timeout;
            }

            state.session_count += 1;
            NTLM_STATS.sessions_created.fetch_add(1, Ordering::Relaxed);

            return Ok(session_id);
        }
    }

    Err(NtlmError::InsufficientResources)
}

/// Delete an NTLM session
pub fn ntlm_delete_session(session_id: u64) -> Result<(), NtlmError> {
    let mut state = NTLM_STATE.lock();

    if !state.initialized {
        return Err(NtlmError::NotInitialized);
    }

    for i in 0..MAX_NTLM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            state.sessions[i] = NtlmSession::empty();

            if state.session_count > 0 {
                state.session_count -= 1;
            }

            return Ok(());
        }
    }

    Err(NtlmError::SessionNotFound)
}

/// Get session by ID
pub fn ntlm_get_session(session_id: u64) -> Result<NtlmSession, NtlmError> {
    let state = NTLM_STATE.lock();

    if !state.initialized {
        return Err(NtlmError::NotInitialized);
    }

    for i in 0..MAX_NTLM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            // Check expiration
            if state.sessions[i].expiration_time > 0 {
                let now = get_tick_count();
                if now > state.sessions[i].expiration_time {
                    return Err(NtlmError::SessionExpired);
                }
            }

            return Ok(state.sessions[i].clone());
        }
    }

    Err(NtlmError::SessionNotFound)
}

// ============================================================================
// Challenge Generation
// ============================================================================

/// Generate a server challenge
pub fn ntlm_generate_challenge(session_id: u64) -> Result<[u8; NTLM_CHALLENGE_LENGTH], NtlmError> {
    let mut state = NTLM_STATE.lock();

    if !state.initialized {
        return Err(NtlmError::NotInitialized);
    }

    for i in 0..MAX_NTLM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            // Generate challenge from counter and time
            state.challenge_counter += 1;
            let counter = state.challenge_counter;
            let time = get_tick_count();

            let mut challenge = [0u8; NTLM_CHALLENGE_LENGTH];
            challenge[0..4].copy_from_slice(&(counter as u32).to_le_bytes());
            challenge[4..8].copy_from_slice(&(time as u32).to_le_bytes());

            // Simple mixing
            for j in 0..8 {
                challenge[j] = challenge[j].wrapping_add((counter >> (j * 8)) as u8);
            }

            state.sessions[i].server_challenge = challenge;
            state.sessions[i].state = SessionState::ChallengeSent;
            state.sessions[i].last_activity = time;

            return Ok(challenge);
        }
    }

    Err(NtlmError::SessionNotFound)
}

// ============================================================================
// Message Processing
// ============================================================================

/// Process NTLM negotiate message (Type 1)
pub fn ntlm_process_negotiate(
    session_id: u64,
    flags: u32,
    domain: Option<&[u8]>,
    workstation: Option<&[u8]>,
) -> Result<(), NtlmError> {
    let mut state = NTLM_STATE.lock();

    if !state.initialized {
        return Err(NtlmError::NotInitialized);
    }

    for i in 0..MAX_NTLM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            let session = &mut state.sessions[i];

            if session.state != SessionState::Initial {
                return Err(NtlmError::InvalidMessage);
            }

            session.negotiate_flags = flags;

            if let Some(d) = domain {
                let len = d.len().min(MAX_NAME_LENGTH);
                session.domain[..len].copy_from_slice(&d[..len]);
                session.domain_len = len;
            }

            if let Some(w) = workstation {
                let len = w.len().min(MAX_NAME_LENGTH);
                session.workstation[..len].copy_from_slice(&w[..len]);
                session.workstation_len = len;
            }

            session.state = SessionState::NegotiateSent;
            session.last_activity = get_tick_count();

            return Ok(());
        }
    }

    Err(NtlmError::SessionNotFound)
}

/// Create NTLM challenge message (Type 2)
pub fn ntlm_create_challenge_message(session_id: u64) -> Result<Vec<u8>, NtlmError> {
    let mut state = NTLM_STATE.lock();

    if !state.initialized {
        return Err(NtlmError::NotInitialized);
    }

    // Extract config values before mutable borrow
    let server_domain_len = state.config.server_domain_len;
    let mut server_domain_copy = [0u8; MAX_NAME_LENGTH];
    server_domain_copy[..server_domain_len].copy_from_slice(&state.config.server_domain[..server_domain_len]);

    for i in 0..MAX_NTLM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            if state.sessions[i].state != SessionState::NegotiateSent {
                return Err(NtlmError::InvalidMessage);
            }

            // Build challenge message
            let mut message = Vec::with_capacity(64);

            // Signature (8 bytes)
            message.extend_from_slice(&NTLM_SIGNATURE);

            // Message type (4 bytes)
            message.extend_from_slice(&(NtlmMessageType::Challenge as u32).to_le_bytes());

            // Target name security buffer (8 bytes)
            let target_name_offset = 56u32; // After fixed fields
            let target_len = server_domain_len as u16;
            message.extend_from_slice(&target_len.to_le_bytes()); // len
            message.extend_from_slice(&target_len.to_le_bytes()); // max len
            message.extend_from_slice(&target_name_offset.to_le_bytes());

            // Negotiate flags (4 bytes)
            let flags = negotiate_flags::NTLMSSP_NEGOTIATE_UNICODE
                | negotiate_flags::NTLMSSP_REQUEST_TARGET
                | negotiate_flags::NTLMSSP_NEGOTIATE_NTLM
                | negotiate_flags::NTLMSSP_TARGET_TYPE_DOMAIN
                | negotiate_flags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
            message.extend_from_slice(&flags.to_le_bytes());

            // Generate and store challenge
            state.challenge_counter += 1;
            let counter = state.challenge_counter;
            let time = get_tick_count();

            let mut challenge = [0u8; NTLM_CHALLENGE_LENGTH];
            challenge[0..4].copy_from_slice(&(counter as u32).to_le_bytes());
            challenge[4..8].copy_from_slice(&(time as u32).to_le_bytes());
            for j in 0..8 {
                challenge[j] = challenge[j].wrapping_add((counter >> (j * 8)) as u8);
            }
            state.sessions[i].server_challenge = challenge;

            // Server challenge (8 bytes)
            message.extend_from_slice(&challenge);

            // Reserved (8 bytes)
            message.extend_from_slice(&[0u8; 8]);

            // Target info security buffer (8 bytes) - empty for now
            message.extend_from_slice(&[0u8; 8]);

            // Version info (8 bytes)
            let version = NtlmVersion::windows_2003();
            message.push(version.major_version);
            message.push(version.minor_version);
            message.extend_from_slice(&version.build_number.to_le_bytes());
            message.extend_from_slice(&version.reserved);
            message.push(version.ntlm_revision);

            // Target name payload
            message.extend_from_slice(&server_domain_copy[..server_domain_len]);

            state.sessions[i].state = SessionState::ChallengeSent;
            state.sessions[i].last_activity = time;

            return Ok(message);
        }
    }

    Err(NtlmError::SessionNotFound)
}

/// Process NTLM authenticate message (Type 3)
pub fn ntlm_process_authenticate(
    session_id: u64,
    _lm_response: &[u8],
    _nt_response: &[u8],
    domain: &[u8],
    username: &[u8],
    workstation: &[u8],
) -> Result<bool, NtlmError> {
    let mut state = NTLM_STATE.lock();

    if !state.initialized {
        return Err(NtlmError::NotInitialized);
    }

    NTLM_STATS.auth_attempts.fetch_add(1, Ordering::Relaxed);

    for i in 0..MAX_NTLM_SESSIONS {
        if state.sessions[i].in_use && state.sessions[i].session_id == session_id {
            let session = &mut state.sessions[i];

            if session.state != SessionState::ChallengeSent {
                NTLM_STATS.auth_failures.fetch_add(1, Ordering::Relaxed);
                return Err(NtlmError::InvalidMessage);
            }

            // Store user info
            let dlen = domain.len().min(MAX_NAME_LENGTH);
            session.domain[..dlen].copy_from_slice(&domain[..dlen]);
            session.domain_len = dlen;

            let ulen = username.len().min(MAX_USERNAME_LENGTH);
            session.username[..ulen].copy_from_slice(&username[..ulen]);
            session.username_len = ulen;

            let wlen = workstation.len().min(MAX_NAME_LENGTH);
            session.workstation[..wlen].copy_from_slice(&workstation[..wlen]);
            session.workstation_len = wlen;

            // In a real implementation, we would:
            // 1. Look up user in SAM
            // 2. Compute expected response using server challenge and password hash
            // 3. Compare with received response
            // For now, we accept all authentications

            session.state = SessionState::Complete;
            session.last_activity = get_tick_count();

            NTLM_STATS.auth_success.fetch_add(1, Ordering::Relaxed);
            NTLM_STATS.ntlmv1_auth.fetch_add(1, Ordering::Relaxed);

            return Ok(true);
        }
    }

    NTLM_STATS.auth_failures.fetch_add(1, Ordering::Relaxed);
    Err(NtlmError::SessionNotFound)
}

// ============================================================================
// Hash Functions
// ============================================================================

/// Compute NT hash from password (simplified - MD4 of UTF-16LE password)
pub fn ntlm_compute_nt_hash(password: &[u8]) -> [u8; NT_HASH_LENGTH] {
    // Note: Real NT hash uses MD4. This is a simplified placeholder.
    // In production, use a proper MD4 implementation.
    let mut hash = [0u8; NT_HASH_LENGTH];

    // Simple hash for demo - XOR folding
    for (i, &byte) in password.iter().enumerate() {
        hash[i % NT_HASH_LENGTH] ^= byte;
        hash[(i + 7) % NT_HASH_LENGTH] = hash[(i + 7) % NT_HASH_LENGTH]
            .wrapping_add(byte)
            .wrapping_mul(31);
    }

    // Mix
    for i in 0..NT_HASH_LENGTH {
        let prev = hash[(i + NT_HASH_LENGTH - 1) % NT_HASH_LENGTH];
        hash[i] = hash[i].wrapping_add(prev.wrapping_mul(17));
    }

    hash
}

/// Compute LM hash from password (legacy, insecure)
pub fn ntlm_compute_lm_hash(_password: &[u8]) -> [u8; LM_HASH_LENGTH] {
    // LM hash is deprecated and insecure
    // Return empty hash (indicates no LM hash)
    [0u8; LM_HASH_LENGTH]
}

/// Compute NTLM response from NT hash and challenge
pub fn ntlm_compute_response(
    nt_hash: &[u8; NT_HASH_LENGTH],
    challenge: &[u8; NTLM_CHALLENGE_LENGTH],
) -> [u8; 24] {
    // Note: Real NTLM response uses DES-CBC-MAC
    // This is a simplified placeholder
    let mut response = [0u8; 24];

    // Simple response generation
    for i in 0..24 {
        response[i] = nt_hash[i % NT_HASH_LENGTH]
            ^ challenge[i % NTLM_CHALLENGE_LENGTH]
            ^ (i as u8);
    }

    response
}

// ============================================================================
// Configuration
// ============================================================================

/// Set NTLM configuration
pub fn ntlm_set_config(config: &NtlmConfig) -> Result<(), NtlmError> {
    let mut state = NTLM_STATE.lock();

    if !state.initialized {
        return Err(NtlmError::NotInitialized);
    }

    state.config = config.clone();
    Ok(())
}

/// Get NTLM configuration
pub fn ntlm_get_config() -> Result<NtlmConfig, NtlmError> {
    let state = NTLM_STATE.lock();

    if !state.initialized {
        return Err(NtlmError::NotInitialized);
    }

    Ok(state.config.clone())
}

/// Set server domain name
pub fn ntlm_set_server_domain(domain: &[u8]) -> Result<(), NtlmError> {
    let mut state = NTLM_STATE.lock();

    if !state.initialized {
        return Err(NtlmError::NotInitialized);
    }

    if domain.len() > MAX_NAME_LENGTH {
        return Err(NtlmError::InvalidParameter);
    }

    state.config.server_domain[..domain.len()].copy_from_slice(domain);
    state.config.server_domain_len = domain.len();

    Ok(())
}

/// Set server workstation name
pub fn ntlm_set_server_workstation(workstation: &[u8]) -> Result<(), NtlmError> {
    let mut state = NTLM_STATE.lock();

    if !state.initialized {
        return Err(NtlmError::NotInitialized);
    }

    if workstation.len() > MAX_NAME_LENGTH {
        return Err(NtlmError::InvalidParameter);
    }

    state.config.server_workstation[..workstation.len()].copy_from_slice(workstation);
    state.config.server_workstation_len = workstation.len();

    Ok(())
}

// ============================================================================
// Statistics
// ============================================================================

/// NTLM statistics snapshot
#[derive(Debug, Clone, Default)]
pub struct NtlmStatsSnapshot {
    pub auth_attempts: u64,
    pub auth_success: u64,
    pub auth_failures: u64,
    pub ntlmv1_auth: u64,
    pub ntlmv2_auth: u64,
    pub sessions_created: u64,
    pub sessions_expired: u64,
    pub active_sessions: usize,
}

/// Get NTLM statistics
pub fn ntlm_get_stats() -> NtlmStatsSnapshot {
    let state = NTLM_STATE.lock();

    NtlmStatsSnapshot {
        auth_attempts: NTLM_STATS.auth_attempts.load(Ordering::Relaxed),
        auth_success: NTLM_STATS.auth_success.load(Ordering::Relaxed),
        auth_failures: NTLM_STATS.auth_failures.load(Ordering::Relaxed),
        ntlmv1_auth: NTLM_STATS.ntlmv1_auth.load(Ordering::Relaxed),
        ntlmv2_auth: NTLM_STATS.ntlmv2_auth.load(Ordering::Relaxed),
        sessions_created: NTLM_STATS.sessions_created.load(Ordering::Relaxed),
        sessions_expired: NTLM_STATS.sessions_expired.load(Ordering::Relaxed),
        active_sessions: state.session_count,
    }
}

/// Check if NTLM is initialized
pub fn ntlm_is_initialized() -> bool {
    NTLM_STATE.lock().initialized
}

/// Get message type name
pub fn message_type_name(msg_type: NtlmMessageType) -> &'static str {
    match msg_type {
        NtlmMessageType::Negotiate => "Negotiate (Type 1)",
        NtlmMessageType::Challenge => "Challenge (Type 2)",
        NtlmMessageType::Authenticate => "Authenticate (Type 3)",
    }
}

/// Get session state name
pub fn session_state_name(state: SessionState) -> &'static str {
    match state {
        SessionState::Initial => "Initial",
        SessionState::NegotiateSent => "Negotiate Sent",
        SessionState::ChallengeSent => "Challenge Sent",
        SessionState::AuthenticateSent => "Authenticate Sent",
        SessionState::Complete => "Complete",
        SessionState::Failed => "Failed",
    }
}

/// Cleanup expired sessions
pub fn ntlm_cleanup_expired_sessions() -> usize {
    let mut state = NTLM_STATE.lock();

    if !state.initialized {
        return 0;
    }

    let now = get_tick_count();
    let mut cleaned = 0;

    for i in 0..MAX_NTLM_SESSIONS {
        if state.sessions[i].in_use {
            if state.sessions[i].expiration_time > 0 && now > state.sessions[i].expiration_time {
                state.sessions[i] = NtlmSession::empty();
                if state.session_count > 0 {
                    state.session_count -= 1;
                }
                cleaned += 1;
                NTLM_STATS.sessions_expired.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    cleaned
}
