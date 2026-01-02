//! Schannel - Secure Channel
//!
//! Schannel is the Windows security support provider (SSP) for SSL/TLS.
//! It provides secure network communications through:
//! - SSL 2.0/3.0 (deprecated)
//! - TLS 1.0/1.1/1.2/1.3
//! - DTLS (Datagram TLS)
//!
//! Schannel integrates with the Security Support Provider Interface (SSPI)
//! to provide authentication and encryption services.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum TLS sessions
const MAX_TLS_SESSIONS: usize = 256;

/// Maximum certificates
const MAX_CERTIFICATES: usize = 64;

/// Maximum cipher suites
const MAX_CIPHER_SUITES: usize = 32;

/// Maximum name length
const MAX_NAME_LEN: usize = 256;

// ============================================================================
// Protocol Versions
// ============================================================================

/// TLS/SSL protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum ProtocolVersion {
    /// SSL 2.0 (deprecated)
    Ssl2 = 0x0002,
    /// SSL 3.0 (deprecated)
    Ssl3 = 0x0300,
    /// TLS 1.0
    Tls10 = 0x0301,
    /// TLS 1.1
    Tls11 = 0x0302,
    /// TLS 1.2
    Tls12 = 0x0303,
    /// TLS 1.3
    Tls13 = 0x0304,
}

impl ProtocolVersion {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ssl2 => "SSL 2.0",
            Self::Ssl3 => "SSL 3.0",
            Self::Tls10 => "TLS 1.0",
            Self::Tls11 => "TLS 1.1",
            Self::Tls12 => "TLS 1.2",
            Self::Tls13 => "TLS 1.3",
        }
    }
}

// ============================================================================
// Cipher Suites
// ============================================================================

/// Key exchange algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchange {
    /// RSA key exchange
    Rsa,
    /// Diffie-Hellman Ephemeral
    Dhe,
    /// Elliptic Curve Diffie-Hellman Ephemeral
    Ecdhe,
    /// Pre-Shared Key
    Psk,
}

/// Authentication algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authentication {
    /// RSA authentication
    Rsa,
    /// ECDSA authentication
    Ecdsa,
    /// Pre-Shared Key
    Psk,
    /// Anonymous (no auth)
    Anonymous,
}

/// Bulk cipher algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkCipher {
    /// No encryption (NULL)
    Null,
    /// AES-128 CBC
    Aes128Cbc,
    /// AES-256 CBC
    Aes256Cbc,
    /// AES-128 GCM
    Aes128Gcm,
    /// AES-256 GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    Chacha20Poly1305,
    /// 3DES CBC (deprecated)
    TripleDesCbc,
}

/// MAC algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAlgorithm {
    /// No MAC (AEAD ciphers)
    None,
    /// HMAC-SHA1
    HmacSha1,
    /// HMAC-SHA256
    HmacSha256,
    /// HMAC-SHA384
    HmacSha384,
}

/// Cipher suite
#[derive(Debug, Clone, Copy)]
pub struct CipherSuite {
    /// Cipher suite ID (IANA number)
    pub id: u16,
    /// Key exchange
    pub key_exchange: KeyExchange,
    /// Authentication
    pub authentication: Authentication,
    /// Bulk cipher
    pub bulk_cipher: BulkCipher,
    /// MAC algorithm
    pub mac: MacAlgorithm,
    /// Minimum TLS version
    pub min_version: ProtocolVersion,
    /// Enabled
    pub enabled: bool,
}

// Well-known cipher suites
pub mod cipher_suites {
    use super::*;

    pub const TLS_RSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        id: 0x002F,
        key_exchange: KeyExchange::Rsa,
        authentication: Authentication::Rsa,
        bulk_cipher: BulkCipher::Aes128Cbc,
        mac: MacAlgorithm::HmacSha1,
        min_version: ProtocolVersion::Tls10,
        enabled: true,
    };

    pub const TLS_RSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        id: 0x0035,
        key_exchange: KeyExchange::Rsa,
        authentication: Authentication::Rsa,
        bulk_cipher: BulkCipher::Aes256Cbc,
        mac: MacAlgorithm::HmacSha1,
        min_version: ProtocolVersion::Tls10,
        enabled: true,
    };

    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        id: 0xC02F,
        key_exchange: KeyExchange::Ecdhe,
        authentication: Authentication::Rsa,
        bulk_cipher: BulkCipher::Aes128Gcm,
        mac: MacAlgorithm::None,
        min_version: ProtocolVersion::Tls12,
        enabled: true,
    };

    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        id: 0xC030,
        key_exchange: KeyExchange::Ecdhe,
        authentication: Authentication::Rsa,
        bulk_cipher: BulkCipher::Aes256Gcm,
        mac: MacAlgorithm::None,
        min_version: ProtocolVersion::Tls12,
        enabled: true,
    };

    pub const TLS_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        id: 0x1301,
        key_exchange: KeyExchange::Ecdhe, // TLS 1.3 always uses ECDHE
        authentication: Authentication::Rsa,
        bulk_cipher: BulkCipher::Aes128Gcm,
        mac: MacAlgorithm::None,
        min_version: ProtocolVersion::Tls13,
        enabled: true,
    };

    pub const TLS_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        id: 0x1302,
        key_exchange: KeyExchange::Ecdhe,
        authentication: Authentication::Rsa,
        bulk_cipher: BulkCipher::Aes256Gcm,
        mac: MacAlgorithm::None,
        min_version: ProtocolVersion::Tls13,
        enabled: true,
    };

    pub const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        id: 0x1303,
        key_exchange: KeyExchange::Ecdhe,
        authentication: Authentication::Rsa,
        bulk_cipher: BulkCipher::Chacha20Poly1305,
        mac: MacAlgorithm::None,
        min_version: ProtocolVersion::Tls13,
        enabled: true,
    };
}

// ============================================================================
// Certificate
// ============================================================================

/// Certificate type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateType {
    /// X.509 certificate
    X509,
    /// Raw public key
    RawPublicKey,
}

/// Certificate usage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateUsage {
    /// Server authentication
    Server,
    /// Client authentication
    Client,
    /// Both server and client
    Both,
    /// Certificate Authority
    Ca,
}

/// Certificate
#[derive(Clone)]
pub struct Certificate {
    /// Certificate ID
    pub id: u32,
    /// Subject name
    pub subject: [u8; MAX_NAME_LEN],
    /// Subject length
    pub subject_len: usize,
    /// Issuer name
    pub issuer: [u8; MAX_NAME_LEN],
    /// Issuer length
    pub issuer_len: usize,
    /// Serial number
    pub serial: [u8; 32],
    /// Serial length
    pub serial_len: usize,
    /// Certificate type
    pub cert_type: CertificateType,
    /// Usage
    pub usage: CertificateUsage,
    /// Not before timestamp
    pub not_before: u64,
    /// Not after timestamp
    pub not_after: u64,
    /// Public key (simplified - would be full DER in real impl)
    pub public_key: [u8; 512],
    /// Public key length
    pub public_key_len: usize,
    /// Thumbprint (SHA-256)
    pub thumbprint: [u8; 32],
    /// Is trusted
    pub trusted: bool,
    /// Active flag
    pub active: bool,
}

impl Default for Certificate {
    fn default() -> Self {
        Self {
            id: 0,
            subject: [0; MAX_NAME_LEN],
            subject_len: 0,
            issuer: [0; MAX_NAME_LEN],
            issuer_len: 0,
            serial: [0; 32],
            serial_len: 0,
            cert_type: CertificateType::X509,
            usage: CertificateUsage::Server,
            not_before: 0,
            not_after: 0,
            public_key: [0; 512],
            public_key_len: 0,
            thumbprint: [0; 32],
            trusted: false,
            active: false,
        }
    }
}

// ============================================================================
// TLS Session
// ============================================================================

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state
    Initial,
    /// ClientHello sent
    ClientHello,
    /// ServerHello received
    ServerHello,
    /// Certificate exchange
    Certificate,
    /// Key exchange
    KeyExchange,
    /// Finished
    Finished,
    /// Established
    Established,
    /// Rekeying
    Rekeying,
    /// Closing
    Closing,
    /// Closed
    Closed,
    /// Error
    Error,
}

/// Session role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Client role
    Client,
    /// Server role
    Server,
}

/// TLS session
#[derive(Clone)]
pub struct TlsSession {
    /// Session ID
    pub id: u32,
    /// Session role
    pub role: SessionRole,
    /// State
    pub state: SessionState,
    /// Negotiated protocol version
    pub version: ProtocolVersion,
    /// Negotiated cipher suite
    pub cipher_suite: u16,
    /// Server name (SNI)
    pub server_name: [u8; MAX_NAME_LEN],
    /// Server name length
    pub server_name_len: usize,
    /// Local certificate ID
    pub local_cert_id: Option<u32>,
    /// Peer certificate ID
    pub peer_cert_id: Option<u32>,
    /// Session ticket (for resumption)
    pub session_ticket: [u8; 256],
    /// Session ticket length
    pub ticket_len: usize,
    /// Master secret
    pub master_secret: [u8; 48],
    /// Client random
    pub client_random: [u8; 32],
    /// Server random
    pub server_random: [u8; 32],
    /// Sequence number (send)
    pub seq_send: u64,
    /// Sequence number (recv)
    pub seq_recv: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Established timestamp
    pub established: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Active flag
    pub active: bool,
}

impl Default for TlsSession {
    fn default() -> Self {
        Self {
            id: 0,
            role: SessionRole::Client,
            state: SessionState::Initial,
            version: ProtocolVersion::Tls12,
            cipher_suite: 0,
            server_name: [0; MAX_NAME_LEN],
            server_name_len: 0,
            local_cert_id: None,
            peer_cert_id: None,
            session_ticket: [0; 256],
            ticket_len: 0,
            master_secret: [0; 48],
            client_random: [0; 32],
            server_random: [0; 32],
            seq_send: 0,
            seq_recv: 0,
            bytes_sent: 0,
            bytes_received: 0,
            established: 0,
            last_activity: 0,
            active: false,
        }
    }
}

// ============================================================================
// Schannel Credentials
// ============================================================================

/// Credential flags
pub mod credential_flags {
    pub const NO_SYSTEM_MAPPER: u32 = 0x0002;
    pub const NO_SERVERNAME_CHECK: u32 = 0x0004;
    pub const MANUAL_CRED_VALIDATION: u32 = 0x0008;
    pub const NO_DEFAULT_CREDS: u32 = 0x0010;
    pub const AUTO_CRED_VALIDATION: u32 = 0x0020;
    pub const USE_DEFAULT_CREDS: u32 = 0x0040;
    pub const DISABLE_RECONNECTS: u32 = 0x0080;
    pub const REVOCATION_CHECK_END_CERT: u32 = 0x0100;
    pub const REVOCATION_CHECK_CHAIN: u32 = 0x0200;
}

/// Schannel credentials
#[derive(Clone)]
pub struct SchannelCredential {
    /// Credential ID
    pub id: u32,
    /// Flags
    pub flags: u32,
    /// Enabled protocols (bitmask)
    pub enabled_protocols: u32,
    /// Minimum cipher strength
    pub min_cipher_strength: u32,
    /// Maximum cipher strength
    pub max_cipher_strength: u32,
    /// Associated certificate IDs
    pub cert_ids: [Option<u32>; 4],
    /// Certificate count
    pub cert_count: usize,
    /// Active flag
    pub active: bool,
}

impl Default for SchannelCredential {
    fn default() -> Self {
        Self {
            id: 0,
            flags: 0,
            enabled_protocols: 0x0C00, // TLS 1.2 + TLS 1.3
            min_cipher_strength: 128,
            max_cipher_strength: 256,
            cert_ids: [None; 4],
            cert_count: 0,
            active: false,
        }
    }
}

// ============================================================================
// Schannel Statistics
// ============================================================================

/// Schannel statistics
#[derive(Debug)]
pub struct SchannelStatistics {
    /// Active sessions
    pub active_sessions: AtomicU32,
    /// Handshakes completed
    pub handshakes_completed: AtomicU64,
    /// Handshake failures
    pub handshake_failures: AtomicU64,
    /// Session resumptions
    pub session_resumptions: AtomicU64,
    /// Bytes encrypted
    pub bytes_encrypted: AtomicU64,
    /// Bytes decrypted
    pub bytes_decrypted: AtomicU64,
    /// Certificate validations
    pub cert_validations: AtomicU64,
    /// Certificate failures
    pub cert_failures: AtomicU64,
    /// Renegotiations
    pub renegotiations: AtomicU64,
}

impl Default for SchannelStatistics {
    fn default() -> Self {
        Self {
            active_sessions: AtomicU32::new(0),
            handshakes_completed: AtomicU64::new(0),
            handshake_failures: AtomicU64::new(0),
            session_resumptions: AtomicU64::new(0),
            bytes_encrypted: AtomicU64::new(0),
            bytes_decrypted: AtomicU64::new(0),
            cert_validations: AtomicU64::new(0),
            cert_failures: AtomicU64::new(0),
            renegotiations: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Schannel Errors
// ============================================================================

/// Schannel error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SchannelError {
    /// Success
    Success = 0,
    /// Not initialized
    NotInitialized = -1,
    /// Invalid parameter
    InvalidParameter = -2,
    /// Session not found
    SessionNotFound = -3,
    /// Certificate not found
    CertificateNotFound = -4,
    /// No more entries
    NoMoreEntries = -5,
    /// Invalid state
    InvalidState = -6,
    /// Handshake failed
    HandshakeFailed = -7,
    /// Certificate expired
    CertificateExpired = -8,
    /// Certificate revoked
    CertificateRevoked = -9,
    /// Certificate untrusted
    CertificateUntrusted = -10,
    /// Protocol not supported
    UnsupportedProtocol = -11,
    /// Cipher not supported
    UnsupportedCipher = -12,
    /// Decryption failed
    DecryptionFailed = -13,
    /// Encryption failed
    EncryptionFailed = -14,
    /// Connection closed
    ConnectionClosed = -15,
}

// ============================================================================
// Schannel Global State
// ============================================================================

/// Schannel global state
pub struct SchannelState {
    /// TLS sessions
    pub sessions: [TlsSession; MAX_TLS_SESSIONS],
    /// Next session ID
    pub next_session_id: u32,
    /// Certificates
    pub certificates: [Certificate; MAX_CERTIFICATES],
    /// Next certificate ID
    pub next_cert_id: u32,
    /// Enabled cipher suites
    pub cipher_suites: [CipherSuite; MAX_CIPHER_SUITES],
    /// Cipher suite count
    pub cipher_suite_count: usize,
    /// Statistics
    pub statistics: SchannelStatistics,
    /// Initialized flag
    pub initialized: bool,
}

impl SchannelState {
    const fn new() -> Self {
        Self {
            sessions: [const { TlsSession {
                id: 0,
                role: SessionRole::Client,
                state: SessionState::Initial,
                version: ProtocolVersion::Tls12,
                cipher_suite: 0,
                server_name: [0; MAX_NAME_LEN],
                server_name_len: 0,
                local_cert_id: None,
                peer_cert_id: None,
                session_ticket: [0; 256],
                ticket_len: 0,
                master_secret: [0; 48],
                client_random: [0; 32],
                server_random: [0; 32],
                seq_send: 0,
                seq_recv: 0,
                bytes_sent: 0,
                bytes_received: 0,
                established: 0,
                last_activity: 0,
                active: false,
            }}; MAX_TLS_SESSIONS],
            next_session_id: 1,
            certificates: [const { Certificate {
                id: 0,
                subject: [0; MAX_NAME_LEN],
                subject_len: 0,
                issuer: [0; MAX_NAME_LEN],
                issuer_len: 0,
                serial: [0; 32],
                serial_len: 0,
                cert_type: CertificateType::X509,
                usage: CertificateUsage::Server,
                not_before: 0,
                not_after: 0,
                public_key: [0; 512],
                public_key_len: 0,
                thumbprint: [0; 32],
                trusted: false,
                active: false,
            }}; MAX_CERTIFICATES],
            next_cert_id: 1,
            cipher_suites: [const { CipherSuite {
                id: 0,
                key_exchange: KeyExchange::Rsa,
                authentication: Authentication::Rsa,
                bulk_cipher: BulkCipher::Null,
                mac: MacAlgorithm::None,
                min_version: ProtocolVersion::Tls10,
                enabled: false,
            }}; MAX_CIPHER_SUITES],
            cipher_suite_count: 0,
            statistics: SchannelStatistics {
                active_sessions: AtomicU32::new(0),
                handshakes_completed: AtomicU64::new(0),
                handshake_failures: AtomicU64::new(0),
                session_resumptions: AtomicU64::new(0),
                bytes_encrypted: AtomicU64::new(0),
                bytes_decrypted: AtomicU64::new(0),
                cert_validations: AtomicU64::new(0),
                cert_failures: AtomicU64::new(0),
                renegotiations: AtomicU64::new(0),
            },
            initialized: false,
        }
    }
}

/// Global Schannel state
static SCHANNEL_STATE: SpinLock<SchannelState> = SpinLock::new(SchannelState::new());

// ============================================================================
// Session Management
// ============================================================================

/// Create a TLS session
pub fn schannel_create_session(
    role: SessionRole,
    server_name: Option<&str>,
) -> Result<u32, SchannelError> {
    let mut state = SCHANNEL_STATE.lock();

    if !state.initialized {
        return Err(SchannelError::NotInitialized);
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_TLS_SESSIONS {
        if !state.sessions[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(SchannelError::NoMoreEntries)?;

    let session_id = state.next_session_id;
    state.next_session_id += 1;

    state.sessions[idx].id = session_id;
    state.sessions[idx].role = role;
    state.sessions[idx].state = SessionState::Initial;
    state.sessions[idx].version = ProtocolVersion::Tls12;
    state.sessions[idx].active = true;

    if let Some(sn) = server_name {
        let sn_bytes = sn.as_bytes();
        let len = core::cmp::min(sn_bytes.len(), MAX_NAME_LEN);
        state.sessions[idx].server_name_len = len;
        state.sessions[idx].server_name[..len].copy_from_slice(&sn_bytes[..len]);
    }

    state.statistics.active_sessions.fetch_add(1, Ordering::Relaxed);

    Ok(session_id)
}

/// Close a TLS session
pub fn schannel_close_session(session_id: u32) -> Result<(), SchannelError> {
    let mut state = SCHANNEL_STATE.lock();

    if !state.initialized {
        return Err(SchannelError::NotInitialized);
    }

    for idx in 0..MAX_TLS_SESSIONS {
        if state.sessions[idx].active && state.sessions[idx].id == session_id {
            state.sessions[idx].state = SessionState::Closed;
            state.sessions[idx].active = false;
            state.statistics.active_sessions.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(SchannelError::SessionNotFound)
}

/// Get session state
pub fn schannel_get_session_state(session_id: u32) -> Result<SessionState, SchannelError> {
    let state = SCHANNEL_STATE.lock();

    if !state.initialized {
        return Err(SchannelError::NotInitialized);
    }

    for idx in 0..MAX_TLS_SESSIONS {
        if state.sessions[idx].active && state.sessions[idx].id == session_id {
            return Ok(state.sessions[idx].state);
        }
    }

    Err(SchannelError::SessionNotFound)
}

// ============================================================================
// Certificate Management
// ============================================================================

/// Add a certificate
pub fn schannel_add_certificate(
    subject: &str,
    issuer: &str,
    usage: CertificateUsage,
    trusted: bool,
) -> Result<u32, SchannelError> {
    let mut state = SCHANNEL_STATE.lock();

    if !state.initialized {
        return Err(SchannelError::NotInitialized);
    }

    let subject_bytes = subject.as_bytes();
    let issuer_bytes = issuer.as_bytes();

    if subject_bytes.len() > MAX_NAME_LEN || issuer_bytes.len() > MAX_NAME_LEN {
        return Err(SchannelError::InvalidParameter);
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_CERTIFICATES {
        if !state.certificates[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(SchannelError::NoMoreEntries)?;

    let cert_id = state.next_cert_id;
    state.next_cert_id += 1;

    state.certificates[idx].id = cert_id;
    state.certificates[idx].subject_len = subject_bytes.len();
    state.certificates[idx].subject[..subject_bytes.len()].copy_from_slice(subject_bytes);
    state.certificates[idx].issuer_len = issuer_bytes.len();
    state.certificates[idx].issuer[..issuer_bytes.len()].copy_from_slice(issuer_bytes);
    state.certificates[idx].usage = usage;
    state.certificates[idx].trusted = trusted;
    state.certificates[idx].active = true;

    Ok(cert_id)
}

/// Remove a certificate
pub fn schannel_remove_certificate(cert_id: u32) -> Result<(), SchannelError> {
    let mut state = SCHANNEL_STATE.lock();

    if !state.initialized {
        return Err(SchannelError::NotInitialized);
    }

    for idx in 0..MAX_CERTIFICATES {
        if state.certificates[idx].active && state.certificates[idx].id == cert_id {
            state.certificates[idx].active = false;
            return Ok(());
        }
    }

    Err(SchannelError::CertificateNotFound)
}

// ============================================================================
// Cipher Suite Management
// ============================================================================

/// Enable a cipher suite
pub fn schannel_enable_cipher_suite(suite: CipherSuite) -> Result<(), SchannelError> {
    let mut state = SCHANNEL_STATE.lock();

    if !state.initialized {
        return Err(SchannelError::NotInitialized);
    }

    if state.cipher_suite_count >= MAX_CIPHER_SUITES {
        return Err(SchannelError::NoMoreEntries);
    }

    // Check if already enabled
    for idx in 0..state.cipher_suite_count {
        if state.cipher_suites[idx].id == suite.id {
            state.cipher_suites[idx].enabled = true;
            return Ok(());
        }
    }

    // Add new
    let count = state.cipher_suite_count;
    state.cipher_suites[count] = suite;
    state.cipher_suite_count += 1;

    Ok(())
}

/// Disable a cipher suite
pub fn schannel_disable_cipher_suite(suite_id: u16) -> Result<(), SchannelError> {
    let mut state = SCHANNEL_STATE.lock();

    if !state.initialized {
        return Err(SchannelError::NotInitialized);
    }

    for idx in 0..state.cipher_suite_count {
        if state.cipher_suites[idx].id == suite_id {
            state.cipher_suites[idx].enabled = false;
            return Ok(());
        }
    }

    Err(SchannelError::UnsupportedCipher)
}

// ============================================================================
// Query Functions
// ============================================================================

/// List active sessions
pub fn schannel_list_sessions() -> Vec<(u32, SessionRole, SessionState, ProtocolVersion)> {
    let state = SCHANNEL_STATE.lock();
    let mut result = Vec::new();

    for idx in 0..MAX_TLS_SESSIONS {
        if state.sessions[idx].active {
            result.push((
                state.sessions[idx].id,
                state.sessions[idx].role,
                state.sessions[idx].state,
                state.sessions[idx].version,
            ));
        }
    }

    result
}

/// List certificates
pub fn schannel_list_certificates() -> Vec<(u32, String, CertificateUsage, bool)> {
    let state = SCHANNEL_STATE.lock();
    let mut result = Vec::new();

    for idx in 0..MAX_CERTIFICATES {
        if state.certificates[idx].active {
            let subject = core::str::from_utf8(
                &state.certificates[idx].subject[..state.certificates[idx].subject_len],
            )
            .map(String::from)
            .unwrap_or_default();

            result.push((
                state.certificates[idx].id,
                subject,
                state.certificates[idx].usage,
                state.certificates[idx].trusted,
            ));
        }
    }

    result
}

/// Get Schannel statistics
pub fn schannel_get_statistics() -> SchannelStatistics {
    let state = SCHANNEL_STATE.lock();

    SchannelStatistics {
        active_sessions: AtomicU32::new(state.statistics.active_sessions.load(Ordering::Relaxed)),
        handshakes_completed: AtomicU64::new(state.statistics.handshakes_completed.load(Ordering::Relaxed)),
        handshake_failures: AtomicU64::new(state.statistics.handshake_failures.load(Ordering::Relaxed)),
        session_resumptions: AtomicU64::new(state.statistics.session_resumptions.load(Ordering::Relaxed)),
        bytes_encrypted: AtomicU64::new(state.statistics.bytes_encrypted.load(Ordering::Relaxed)),
        bytes_decrypted: AtomicU64::new(state.statistics.bytes_decrypted.load(Ordering::Relaxed)),
        cert_validations: AtomicU64::new(state.statistics.cert_validations.load(Ordering::Relaxed)),
        cert_failures: AtomicU64::new(state.statistics.cert_failures.load(Ordering::Relaxed)),
        renegotiations: AtomicU64::new(state.statistics.renegotiations.load(Ordering::Relaxed)),
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Schannel
pub fn init() {
    crate::serial_println!("[SCHANNEL] Initializing Secure Channel...");

    {
        let mut state = SCHANNEL_STATE.lock();

        // Enable default cipher suites
        state.cipher_suites[0] = cipher_suites::TLS_AES_256_GCM_SHA384;
        state.cipher_suites[1] = cipher_suites::TLS_AES_128_GCM_SHA256;
        state.cipher_suites[2] = cipher_suites::TLS_CHACHA20_POLY1305_SHA256;
        state.cipher_suites[3] = cipher_suites::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
        state.cipher_suites[4] = cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        state.cipher_suites[5] = cipher_suites::TLS_RSA_WITH_AES_256_CBC_SHA;
        state.cipher_suites[6] = cipher_suites::TLS_RSA_WITH_AES_128_CBC_SHA;
        state.cipher_suite_count = 7;

        state.initialized = true;
    }

    crate::serial_println!("[SCHANNEL] Schannel initialized");
}
