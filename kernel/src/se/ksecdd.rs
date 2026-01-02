//! KSECDD - Kernel Security Device Driver
//!
//! KSECDD provides cryptographic and security services to the Windows kernel.
//! It exports functions for:
//! - Random number generation
//! - Cryptographic hashing (MD5, SHA-1, SHA-256)
//! - Symmetric encryption (DES, 3DES, AES)
//! - Asymmetric operations (RSA)
//! - SSPI (Security Support Provider Interface) integration
//! - LSA (Local Security Authority) integration

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum number of security contexts
const MAX_SECURITY_CONTEXTS: usize = 256;

/// Maximum number of crypto handles
const MAX_CRYPTO_HANDLES: usize = 1024;

// ============================================================================
// Hash Algorithms
// ============================================================================

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HashAlgorithm {
    /// MD5 (128-bit)
    Md5 = 0x8003,
    /// SHA-1 (160-bit)
    Sha1 = 0x8004,
    /// SHA-256 (256-bit)
    Sha256 = 0x800C,
    /// SHA-384 (384-bit)
    Sha384 = 0x800D,
    /// SHA-512 (512-bit)
    Sha512 = 0x800E,
    /// HMAC
    Hmac = 0x8009,
}

impl HashAlgorithm {
    /// Get the output size in bytes
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Md5 => 16,
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Hmac => 32, // Default to SHA-256 size
        }
    }
}

// ============================================================================
// Encryption Algorithms
// ============================================================================

/// Supported symmetric encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SymmetricAlgorithm {
    /// DES (64-bit key)
    Des = 0x6601,
    /// Triple DES (168-bit key)
    TripleDes = 0x6603,
    /// AES-128
    Aes128 = 0x660E,
    /// AES-192
    Aes192 = 0x660F,
    /// AES-256
    Aes256 = 0x6610,
    /// RC4 stream cipher
    Rc4 = 0x6801,
}

impl SymmetricAlgorithm {
    /// Get the key size in bytes
    pub fn key_size(&self) -> usize {
        match self {
            SymmetricAlgorithm::Des => 8,
            SymmetricAlgorithm::TripleDes => 24,
            SymmetricAlgorithm::Aes128 => 16,
            SymmetricAlgorithm::Aes192 => 24,
            SymmetricAlgorithm::Aes256 => 32,
            SymmetricAlgorithm::Rc4 => 16, // Typical key size
        }
    }

    /// Get the block size in bytes
    pub fn block_size(&self) -> usize {
        match self {
            SymmetricAlgorithm::Des => 8,
            SymmetricAlgorithm::TripleDes => 8,
            SymmetricAlgorithm::Aes128 => 16,
            SymmetricAlgorithm::Aes192 => 16,
            SymmetricAlgorithm::Aes256 => 16,
            SymmetricAlgorithm::Rc4 => 1, // Stream cipher
        }
    }
}

/// Asymmetric algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AsymmetricAlgorithm {
    /// RSA
    Rsa = 0x0001,
    /// DSA
    Dsa = 0x0002,
    /// ECDSA
    Ecdsa = 0x0003,
    /// ECDH
    Ecdh = 0x0004,
    /// Diffie-Hellman
    Dh = 0x0005,
}

/// Cipher modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CipherMode {
    /// Electronic Codebook
    Ecb = 1,
    /// Cipher Block Chaining
    Cbc = 2,
    /// Cipher Feedback
    Cfb = 3,
    /// Output Feedback
    Ofb = 4,
    /// Counter Mode
    Ctr = 5,
    /// Galois/Counter Mode
    Gcm = 6,
}

/// Padding mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PaddingMode {
    /// No padding
    None = 1,
    /// PKCS#7 padding
    Pkcs7 = 2,
    /// Zero padding
    Zeros = 3,
    /// ANSI X.923
    AnsiX923 = 4,
    /// ISO 10126
    Iso10126 = 5,
}

// ============================================================================
// Crypto Handle
// ============================================================================

/// Crypto handle type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoHandleType {
    /// Hash computation
    Hash,
    /// Symmetric encryption
    Symmetric,
    /// Asymmetric operations
    Asymmetric,
    /// Random number generator
    Random,
    /// Key
    Key,
}

/// Crypto handle state
#[derive(Debug, Clone)]
pub struct CryptoHandle {
    /// Handle ID
    pub id: u64,
    /// Handle type
    pub handle_type: CryptoHandleType,
    /// Algorithm (as u32 for generic storage)
    pub algorithm: u32,
    /// Key data (for encryption handles)
    pub key_data: Vec<u8>,
    /// IV/Nonce
    pub iv: Vec<u8>,
    /// Cipher mode
    pub cipher_mode: CipherMode,
    /// Padding mode
    pub padding_mode: PaddingMode,
    /// Hash state (intermediate hash values)
    pub hash_state: Vec<u8>,
    /// Total bytes processed
    pub bytes_processed: u64,
    /// Owning process
    pub process_id: u32,
    /// Active flag
    pub active: bool,
}

impl Default for CryptoHandle {
    fn default() -> Self {
        Self {
            id: 0,
            handle_type: CryptoHandleType::Hash,
            algorithm: 0,
            key_data: Vec::new(),
            iv: Vec::new(),
            cipher_mode: CipherMode::Cbc,
            padding_mode: PaddingMode::Pkcs7,
            hash_state: Vec::new(),
            bytes_processed: 0,
            process_id: 0,
            active: false,
        }
    }
}

// ============================================================================
// Security Context
// ============================================================================

/// Security package type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SecurityPackage {
    /// NTLM authentication
    Ntlm = 1,
    /// Kerberos authentication
    Kerberos = 2,
    /// Negotiate (SPNEGO)
    Negotiate = 3,
    /// Digest
    Digest = 4,
    /// Schannel (SSL/TLS)
    Schannel = 5,
    /// Credential Delegation
    CredSsp = 6,
}

/// Security context state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityContextState {
    /// Not initialized
    None,
    /// Initializing
    Initializing,
    /// Established
    Established,
    /// Renegotiating
    Renegotiating,
    /// Closed
    Closed,
}

/// Security context
#[derive(Clone)]
pub struct SecurityContext {
    /// Context ID
    pub id: u64,
    /// Security package
    pub package: SecurityPackage,
    /// Context state
    pub state: SecurityContextState,
    /// Target name (SPN)
    pub target_name: Option<String>,
    /// Session key
    pub session_key: Vec<u8>,
    /// Sequence numbers
    pub send_seq: u64,
    pub recv_seq: u64,
    /// Context flags
    pub flags: u32,
    /// Expiry time
    pub expiry: u64,
    /// Owning process
    pub process_id: u32,
    /// Active flag
    pub active: bool,
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self {
            id: 0,
            package: SecurityPackage::Ntlm,
            state: SecurityContextState::None,
            target_name: None,
            session_key: Vec::new(),
            send_seq: 0,
            recv_seq: 0,
            flags: 0,
            expiry: 0,
            process_id: 0,
            active: false,
        }
    }
}

// ============================================================================
// KSECDD Statistics
// ============================================================================

/// KSECDD statistics
#[derive(Debug)]
pub struct KsecddStatistics {
    /// Random bytes generated
    pub random_bytes: AtomicU64,
    /// Hash operations
    pub hash_operations: AtomicU64,
    /// Encrypt operations
    pub encrypt_operations: AtomicU64,
    /// Decrypt operations
    pub decrypt_operations: AtomicU64,
    /// Active crypto handles
    pub active_handles: AtomicU32,
    /// Active security contexts
    pub active_contexts: AtomicU32,
    /// Authentication successes
    pub auth_successes: AtomicU64,
    /// Authentication failures
    pub auth_failures: AtomicU64,
}

impl Default for KsecddStatistics {
    fn default() -> Self {
        Self {
            random_bytes: AtomicU64::new(0),
            hash_operations: AtomicU64::new(0),
            encrypt_operations: AtomicU64::new(0),
            decrypt_operations: AtomicU64::new(0),
            active_handles: AtomicU32::new(0),
            active_contexts: AtomicU32::new(0),
            auth_successes: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// KSECDD Errors
// ============================================================================

/// KSECDD error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum KsecddError {
    /// Success
    Success = 0,
    /// Not initialized
    NotInitialized = -1,
    /// Invalid parameter
    InvalidParameter = -2,
    /// Invalid handle
    InvalidHandle = -3,
    /// Algorithm not supported
    AlgorithmNotSupported = -4,
    /// Key too small
    KeyTooSmall = -5,
    /// Buffer too small
    BufferTooSmall = -6,
    /// Invalid key
    InvalidKey = -7,
    /// Invalid signature
    InvalidSignature = -8,
    /// Authentication failed
    AuthFailed = -9,
    /// Context expired
    ContextExpired = -10,
    /// Too many handles
    TooManyHandles = -11,
    /// Too many contexts
    TooManyContexts = -12,
    /// Internal error
    InternalError = -13,
}

// ============================================================================
// KSECDD State
// ============================================================================

/// KSECDD global state
pub struct KsecddState {
    /// Crypto handles
    pub handles: [CryptoHandle; MAX_CRYPTO_HANDLES],
    /// Security contexts
    pub contexts: [SecurityContext; MAX_SECURITY_CONTEXTS],
    /// Next handle ID
    pub next_handle_id: u64,
    /// Next context ID
    pub next_context_id: u64,
    /// Random seed
    pub random_seed: u64,
    /// Statistics
    pub statistics: KsecddStatistics,
    /// Initialized flag
    pub initialized: bool,
}

impl KsecddState {
    const fn new() -> Self {
        const DEFAULT_HANDLE: CryptoHandle = CryptoHandle {
            id: 0,
            handle_type: CryptoHandleType::Hash,
            algorithm: 0,
            key_data: Vec::new(),
            iv: Vec::new(),
            cipher_mode: CipherMode::Cbc,
            padding_mode: PaddingMode::Pkcs7,
            hash_state: Vec::new(),
            bytes_processed: 0,
            process_id: 0,
            active: false,
        };

        const DEFAULT_CONTEXT: SecurityContext = SecurityContext {
            id: 0,
            package: SecurityPackage::Ntlm,
            state: SecurityContextState::None,
            target_name: None,
            session_key: Vec::new(),
            send_seq: 0,
            recv_seq: 0,
            flags: 0,
            expiry: 0,
            process_id: 0,
            active: false,
        };

        Self {
            handles: [DEFAULT_HANDLE; MAX_CRYPTO_HANDLES],
            contexts: [DEFAULT_CONTEXT; MAX_SECURITY_CONTEXTS],
            next_handle_id: 1,
            next_context_id: 1,
            random_seed: 0x5DEECE66D, // LCG seed
            statistics: KsecddStatistics {
                random_bytes: AtomicU64::new(0),
                hash_operations: AtomicU64::new(0),
                encrypt_operations: AtomicU64::new(0),
                decrypt_operations: AtomicU64::new(0),
                active_handles: AtomicU32::new(0),
                active_contexts: AtomicU32::new(0),
                auth_successes: AtomicU64::new(0),
                auth_failures: AtomicU64::new(0),
            },
            initialized: false,
        }
    }
}

/// Global KSECDD state
static KSECDD_STATE: SpinLock<KsecddState> = SpinLock::new(KsecddState::new());

// ============================================================================
// Random Number Generation
// ============================================================================

/// Generate cryptographically random bytes
pub fn ksec_gen_random(buffer: &mut [u8]) -> Result<(), KsecddError> {
    let mut state = KSECDD_STATE.lock();

    if !state.initialized {
        return Err(KsecddError::NotInitialized);
    }

    // Simple LCG-based PRNG (in real implementation, use hardware RNG or better CSPRNG)
    for byte in buffer.iter_mut() {
        state.random_seed = state.random_seed
            .wrapping_mul(0x5DEECE66D)
            .wrapping_add(0xB);
        *byte = (state.random_seed >> 16) as u8;
    }

    state.statistics.random_bytes.fetch_add(buffer.len() as u64, Ordering::Relaxed);

    Ok(())
}

/// Generate a random 32-bit value
pub fn ksec_gen_random_u32() -> Result<u32, KsecddError> {
    let mut bytes = [0u8; 4];
    ksec_gen_random(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Generate a random 64-bit value
pub fn ksec_gen_random_u64() -> Result<u64, KsecddError> {
    let mut bytes = [0u8; 8];
    ksec_gen_random(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

// ============================================================================
// Hash Operations
// ============================================================================

/// Create a hash handle
pub fn ksec_hash_create(
    algorithm: HashAlgorithm,
    process_id: u32,
) -> Result<u64, KsecddError> {
    let mut state = KSECDD_STATE.lock();

    if !state.initialized {
        return Err(KsecddError::NotInitialized);
    }

    // Find free handle slot
    let mut slot_idx = None;
    for idx in 0..MAX_CRYPTO_HANDLES {
        if !state.handles[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(KsecddError::TooManyHandles)?;

    let handle_id = state.next_handle_id;
    state.next_handle_id += 1;

    state.handles[idx] = CryptoHandle {
        id: handle_id,
        handle_type: CryptoHandleType::Hash,
        algorithm: algorithm as u32,
        key_data: Vec::new(),
        iv: Vec::new(),
        cipher_mode: CipherMode::Cbc,
        padding_mode: PaddingMode::Pkcs7,
        hash_state: vec![0; algorithm.output_size()],
        bytes_processed: 0,
        process_id,
        active: true,
    };

    state.statistics.active_handles.fetch_add(1, Ordering::Relaxed);

    Ok(handle_id)
}

/// Update hash with data
pub fn ksec_hash_update(handle_id: u64, data: &[u8]) -> Result<(), KsecddError> {
    let mut state = KSECDD_STATE.lock();

    if !state.initialized {
        return Err(KsecddError::NotInitialized);
    }

    let mut found_idx = None;
    for idx in 0..MAX_CRYPTO_HANDLES {
        if state.handles[idx].active && state.handles[idx].id == handle_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(KsecddError::InvalidHandle)?;

    if state.handles[idx].handle_type != CryptoHandleType::Hash {
        return Err(KsecddError::InvalidHandle);
    }

    // Simplified hash update - XOR with existing state
    // Real implementation would use proper hash algorithm
    for (i, &byte) in data.iter().enumerate() {
        let state_idx = i % state.handles[idx].hash_state.len();
        state.handles[idx].hash_state[state_idx] ^= byte;
    }

    state.handles[idx].bytes_processed += data.len() as u64;

    Ok(())
}

/// Finalize hash and get result
pub fn ksec_hash_finalize(handle_id: u64, output: &mut [u8]) -> Result<usize, KsecddError> {
    let mut state = KSECDD_STATE.lock();

    if !state.initialized {
        return Err(KsecddError::NotInitialized);
    }

    let mut found_idx = None;
    for idx in 0..MAX_CRYPTO_HANDLES {
        if state.handles[idx].active && state.handles[idx].id == handle_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(KsecddError::InvalidHandle)?;

    if state.handles[idx].handle_type != CryptoHandleType::Hash {
        return Err(KsecddError::InvalidHandle);
    }

    let hash_len = state.handles[idx].hash_state.len();
    if output.len() < hash_len {
        return Err(KsecddError::BufferTooSmall);
    }

    output[..hash_len].copy_from_slice(&state.handles[idx].hash_state);

    state.statistics.hash_operations.fetch_add(1, Ordering::Relaxed);

    Ok(hash_len)
}

/// Compute hash in one operation
pub fn ksec_hash_data(
    algorithm: HashAlgorithm,
    data: &[u8],
    output: &mut [u8],
) -> Result<usize, KsecddError> {
    let handle = ksec_hash_create(algorithm, 0)?;
    ksec_hash_update(handle, data)?;
    let len = ksec_hash_finalize(handle, output)?;
    ksec_close_handle(handle)?;
    Ok(len)
}

// ============================================================================
// Symmetric Encryption
// ============================================================================

/// Create a symmetric encryption handle
pub fn ksec_symmetric_create(
    algorithm: SymmetricAlgorithm,
    key: &[u8],
    iv: Option<&[u8]>,
    mode: CipherMode,
    process_id: u32,
) -> Result<u64, KsecddError> {
    let mut state = KSECDD_STATE.lock();

    if !state.initialized {
        return Err(KsecddError::NotInitialized);
    }

    // Validate key size
    if key.len() != algorithm.key_size() {
        return Err(KsecddError::KeyTooSmall);
    }

    // Find free handle slot
    let mut slot_idx = None;
    for idx in 0..MAX_CRYPTO_HANDLES {
        if !state.handles[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(KsecddError::TooManyHandles)?;

    let handle_id = state.next_handle_id;
    state.next_handle_id += 1;

    state.handles[idx] = CryptoHandle {
        id: handle_id,
        handle_type: CryptoHandleType::Symmetric,
        algorithm: algorithm as u32,
        key_data: key.to_vec(),
        iv: iv.map(|v| v.to_vec()).unwrap_or_else(|| vec![0; algorithm.block_size()]),
        cipher_mode: mode,
        padding_mode: PaddingMode::Pkcs7,
        hash_state: Vec::new(),
        bytes_processed: 0,
        process_id,
        active: true,
    };

    state.statistics.active_handles.fetch_add(1, Ordering::Relaxed);

    Ok(handle_id)
}

/// Encrypt data
pub fn ksec_encrypt(
    handle_id: u64,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> Result<usize, KsecddError> {
    let mut state = KSECDD_STATE.lock();

    if !state.initialized {
        return Err(KsecddError::NotInitialized);
    }

    let mut found_idx = None;
    for idx in 0..MAX_CRYPTO_HANDLES {
        if state.handles[idx].active && state.handles[idx].id == handle_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(KsecddError::InvalidHandle)?;

    if state.handles[idx].handle_type != CryptoHandleType::Symmetric {
        return Err(KsecddError::InvalidHandle);
    }

    if ciphertext.len() < plaintext.len() {
        return Err(KsecddError::BufferTooSmall);
    }

    // Simplified XOR "encryption" (real implementation would use proper cipher)
    for (i, &byte) in plaintext.iter().enumerate() {
        let key_idx = i % state.handles[idx].key_data.len();
        let iv_idx = i % state.handles[idx].iv.len();
        ciphertext[i] = byte ^ state.handles[idx].key_data[key_idx] ^ state.handles[idx].iv[iv_idx];
    }

    state.handles[idx].bytes_processed += plaintext.len() as u64;
    state.statistics.encrypt_operations.fetch_add(1, Ordering::Relaxed);

    Ok(plaintext.len())
}

/// Decrypt data
pub fn ksec_decrypt(
    handle_id: u64,
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> Result<usize, KsecddError> {
    let mut state = KSECDD_STATE.lock();

    if !state.initialized {
        return Err(KsecddError::NotInitialized);
    }

    let mut found_idx = None;
    for idx in 0..MAX_CRYPTO_HANDLES {
        if state.handles[idx].active && state.handles[idx].id == handle_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(KsecddError::InvalidHandle)?;

    if state.handles[idx].handle_type != CryptoHandleType::Symmetric {
        return Err(KsecddError::InvalidHandle);
    }

    if plaintext.len() < ciphertext.len() {
        return Err(KsecddError::BufferTooSmall);
    }

    // Simplified XOR "decryption" (same as encrypt for XOR)
    for (i, &byte) in ciphertext.iter().enumerate() {
        let key_idx = i % state.handles[idx].key_data.len();
        let iv_idx = i % state.handles[idx].iv.len();
        plaintext[i] = byte ^ state.handles[idx].key_data[key_idx] ^ state.handles[idx].iv[iv_idx];
    }

    state.handles[idx].bytes_processed += ciphertext.len() as u64;
    state.statistics.decrypt_operations.fetch_add(1, Ordering::Relaxed);

    Ok(ciphertext.len())
}

// ============================================================================
// Handle Management
// ============================================================================

/// Close a crypto handle
pub fn ksec_close_handle(handle_id: u64) -> Result<(), KsecddError> {
    let mut state = KSECDD_STATE.lock();

    if !state.initialized {
        return Err(KsecddError::NotInitialized);
    }

    for idx in 0..MAX_CRYPTO_HANDLES {
        if state.handles[idx].active && state.handles[idx].id == handle_id {
            // Securely clear key material
            for byte in state.handles[idx].key_data.iter_mut() {
                *byte = 0;
            }
            state.handles[idx].active = false;
            state.statistics.active_handles.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(KsecddError::InvalidHandle)
}

// ============================================================================
// Security Context Operations (SSPI)
// ============================================================================

/// Acquire security credentials
pub fn ksec_acquire_credentials(
    package: SecurityPackage,
    principal: Option<&str>,
    process_id: u32,
) -> Result<u64, KsecddError> {
    let mut state = KSECDD_STATE.lock();

    if !state.initialized {
        return Err(KsecddError::NotInitialized);
    }

    // Find free context slot
    let mut slot_idx = None;
    for idx in 0..MAX_SECURITY_CONTEXTS {
        if !state.contexts[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(KsecddError::TooManyContexts)?;

    let context_id = state.next_context_id;
    state.next_context_id += 1;

    state.contexts[idx] = SecurityContext {
        id: context_id,
        package,
        state: SecurityContextState::Initializing,
        target_name: principal.map(String::from),
        session_key: Vec::new(),
        send_seq: 0,
        recv_seq: 0,
        flags: 0,
        expiry: 0,
        process_id,
        active: true,
    };

    state.statistics.active_contexts.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[KSECDD] Acquired credentials for {:?}", package);

    Ok(context_id)
}

/// Initialize security context (client-side)
pub fn ksec_init_security_context(
    context_id: u64,
    target: &str,
    input_token: Option<&[u8]>,
    output_token: &mut Vec<u8>,
) -> Result<bool, KsecddError> {
    let mut state = KSECDD_STATE.lock();

    if !state.initialized {
        return Err(KsecddError::NotInitialized);
    }

    let mut found_idx = None;
    for idx in 0..MAX_SECURITY_CONTEXTS {
        if state.contexts[idx].active && state.contexts[idx].id == context_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(KsecddError::InvalidHandle)?;

    state.contexts[idx].target_name = Some(String::from(target));

    // Simplified token generation
    output_token.clear();
    output_token.extend_from_slice(b"NTLMSSP\0");
    output_token.extend_from_slice(&[1, 0, 0, 0]); // Type 1 message

    if input_token.is_some() {
        // Got response, mark as established
        state.contexts[idx].state = SecurityContextState::Established;
        state.statistics.auth_successes.fetch_add(1, Ordering::Relaxed);
        return Ok(true);
    }

    Ok(false) // Need more tokens
}

/// Accept security context (server-side)
pub fn ksec_accept_security_context(
    context_id: u64,
    input_token: &[u8],
    output_token: &mut Vec<u8>,
) -> Result<bool, KsecddError> {
    let mut state = KSECDD_STATE.lock();

    if !state.initialized {
        return Err(KsecddError::NotInitialized);
    }

    let mut found_idx = None;
    for idx in 0..MAX_SECURITY_CONTEXTS {
        if state.contexts[idx].active && state.contexts[idx].id == context_id {
            found_idx = Some(idx);
            break;
        }
    }

    let idx = found_idx.ok_or(KsecddError::InvalidHandle)?;

    // Validate input token (simplified)
    if input_token.len() < 8 || &input_token[0..7] != b"NTLMSSP" {
        state.statistics.auth_failures.fetch_add(1, Ordering::Relaxed);
        return Err(KsecddError::AuthFailed);
    }

    // Generate challenge response
    output_token.clear();
    output_token.extend_from_slice(b"NTLMSSP\0");
    output_token.extend_from_slice(&[2, 0, 0, 0]); // Type 2 message

    state.contexts[idx].state = SecurityContextState::Established;
    state.statistics.auth_successes.fetch_add(1, Ordering::Relaxed);

    Ok(true)
}

/// Delete security context
pub fn ksec_delete_security_context(context_id: u64) -> Result<(), KsecddError> {
    let mut state = KSECDD_STATE.lock();

    if !state.initialized {
        return Err(KsecddError::NotInitialized);
    }

    for idx in 0..MAX_SECURITY_CONTEXTS {
        if state.contexts[idx].active && state.contexts[idx].id == context_id {
            // Clear sensitive data
            for byte in state.contexts[idx].session_key.iter_mut() {
                *byte = 0;
            }
            state.contexts[idx].state = SecurityContextState::Closed;
            state.contexts[idx].active = false;
            state.statistics.active_contexts.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(KsecddError::InvalidHandle)
}

// ============================================================================
// Statistics
// ============================================================================

/// Get KSECDD statistics
pub fn ksec_get_statistics() -> KsecddStatistics {
    let state = KSECDD_STATE.lock();

    KsecddStatistics {
        random_bytes: AtomicU64::new(state.statistics.random_bytes.load(Ordering::Relaxed)),
        hash_operations: AtomicU64::new(state.statistics.hash_operations.load(Ordering::Relaxed)),
        encrypt_operations: AtomicU64::new(state.statistics.encrypt_operations.load(Ordering::Relaxed)),
        decrypt_operations: AtomicU64::new(state.statistics.decrypt_operations.load(Ordering::Relaxed)),
        active_handles: AtomicU32::new(state.statistics.active_handles.load(Ordering::Relaxed)),
        active_contexts: AtomicU32::new(state.statistics.active_contexts.load(Ordering::Relaxed)),
        auth_successes: AtomicU64::new(state.statistics.auth_successes.load(Ordering::Relaxed)),
        auth_failures: AtomicU64::new(state.statistics.auth_failures.load(Ordering::Relaxed)),
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize KSECDD
pub fn init() {
    crate::serial_println!("[KSECDD] Initializing Kernel Security Device Driver...");

    {
        let mut state = KSECDD_STATE.lock();

        // Initialize random seed with some entropy
        // In real implementation, use hardware RNG or collect entropy
        state.random_seed = 0x5DEECE66D ^ get_timestamp();

        state.initialized = true;
    }

    crate::serial_println!("[KSECDD] KSECDD initialized");
}

/// Wrapper for rdtsc that doesn't require unsafe in const context
fn get_timestamp() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() as u64 }
}
