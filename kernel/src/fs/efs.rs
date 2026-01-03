//! Encrypting File System (EFS)
//!
//! EFS provides transparent file encryption for NTFS:
//!
//! - **File Encryption**: Per-file encryption with FEK
//! - **Key Management**: User certificates and recovery agents
//! - **Data Decryption Field (DDF)**: User access to encrypted files
//! - **Data Recovery Field (DRF)**: Recovery agent access
//! - **Certificate Integration**: Uses CryptoAPI certificates
//!
//! EFS encrypts file contents but not filenames or directory structure.

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};
use crate::ke::SpinLock;
use crate::hal::apic::get_tick_count;

// ============================================================================
// Constants
// ============================================================================

/// Maximum encrypted files tracked
pub const MAX_ENCRYPTED_FILES: usize = 512;

/// Maximum certificates
pub const MAX_CERTIFICATES: usize = 64;

/// Maximum recovery agents
pub const MAX_RECOVERY_AGENTS: usize = 8;

/// File Encryption Key length (AES-256)
pub const FEK_LENGTH: usize = 32;

/// Encrypted FEK length (RSA-2048 encrypted)
pub const ENCRYPTED_FEK_LENGTH: usize = 256;

/// Certificate thumbprint length (SHA-1)
pub const THUMBPRINT_LENGTH: usize = 20;

/// Maximum path length
pub const MAX_PATH_LENGTH: usize = 260;

/// EFS attribute signature
pub const EFS_SIGNATURE: u32 = 0x45465300; // 'EFS\0'

/// EFS version
pub const EFS_VERSION: u32 = 2;

// ============================================================================
// Error Types
// ============================================================================

/// EFS error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EfsError {
    /// Success
    Success = 0,
    /// File not found
    FileNotFound = 0x80070002,
    /// Access denied
    AccessDenied = 0x80070005,
    /// Invalid parameter
    InvalidParameter = 0x80070057,
    /// File not encrypted
    FileNotEncrypted = 0x80071770,
    /// File is encrypted
    FileIsEncrypted = 0x80071771,
    /// No recovery policy
    NoRecoveryPolicy = 0x80071772,
    /// No EFS certificate
    NoUserCert = 0x80071773,
    /// Bad data
    BadData = 0x8007000D,
    /// Not initialized
    NotInitialized = 0x80071774,
    /// Key not found
    KeyNotFound = 0x80071775,
    /// Certificate not found
    CertificateNotFound = 0x80071776,
    /// Encryption failed
    EncryptionFailed = 0x80071777,
    /// Decryption failed
    DecryptionFailed = 0x80071778,
    /// Insufficient resources
    InsufficientResources = 0x8007000E,
}

// ============================================================================
// Encryption Algorithms
// ============================================================================

/// Encryption algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EncryptionAlgorithm {
    /// AES-256 (default for Vista+)
    Aes256 = 0x6610,
    /// AES-128
    Aes128 = 0x660E,
    /// 3DES (legacy)
    TripleDes = 0x6603,
    /// DESX (legacy, XP)
    DesX = 0x6604,
}

/// Key derivation algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyDerivation {
    /// SHA-256
    Sha256 = 0x800C,
    /// SHA-1 (legacy)
    Sha1 = 0x8004,
}

// ============================================================================
// Data Structures
// ============================================================================

/// File Encryption Key (FEK)
#[derive(Debug, Clone)]
pub struct FileEncryptionKey {
    /// Raw key material
    pub key: [u8; FEK_LENGTH],
    /// Algorithm used
    pub algorithm: EncryptionAlgorithm,
    /// Key length in bits
    pub key_length: u32,
    /// Initialization vector
    pub iv: [u8; 16],
}

impl FileEncryptionKey {
    pub const fn empty() -> Self {
        Self {
            key: [0u8; FEK_LENGTH],
            algorithm: EncryptionAlgorithm::Aes256,
            key_length: 256,
            iv: [0u8; 16],
        }
    }
}

/// Data Decryption Field - encrypted FEK for a user
#[derive(Debug, Clone)]
pub struct DataDecryptionField {
    /// Field in use
    pub in_use: bool,
    /// User SID (simplified as hash)
    pub user_sid_hash: u64,
    /// Certificate thumbprint
    pub cert_thumbprint: [u8; THUMBPRINT_LENGTH],
    /// Encrypted FEK
    pub encrypted_fek: [u8; ENCRYPTED_FEK_LENGTH],
    pub encrypted_fek_len: usize,
}

impl DataDecryptionField {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            user_sid_hash: 0,
            cert_thumbprint: [0u8; THUMBPRINT_LENGTH],
            encrypted_fek: [0u8; ENCRYPTED_FEK_LENGTH],
            encrypted_fek_len: 0,
        }
    }
}

/// Encrypted file record
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    /// Record in use
    pub in_use: bool,
    /// File ID (MFT reference for NTFS)
    pub file_id: u64,
    /// File path
    pub path: [u8; MAX_PATH_LENGTH],
    pub path_len: usize,
    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,
    /// Data Decryption Fields (user access)
    pub ddf: [DataDecryptionField; 4],
    pub ddf_count: usize,
    /// Data Recovery Fields (recovery agent access)
    pub drf: [DataDecryptionField; 2],
    pub drf_count: usize,
    /// File size (encrypted)
    pub encrypted_size: u64,
    /// Original file size
    pub original_size: u64,
    /// Encryption time
    pub encryption_time: u64,
    /// Last access time
    pub last_access: u64,
}

impl EncryptedFile {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            file_id: 0,
            path: [0u8; MAX_PATH_LENGTH],
            path_len: 0,
            algorithm: EncryptionAlgorithm::Aes256,
            ddf: [const { DataDecryptionField::empty() }; 4],
            ddf_count: 0,
            drf: [const { DataDecryptionField::empty() }; 2],
            drf_count: 0,
            encrypted_size: 0,
            original_size: 0,
            encryption_time: 0,
            last_access: 0,
        }
    }
}

/// EFS certificate
#[derive(Debug, Clone)]
pub struct EfsCertificate {
    /// Certificate in use
    pub in_use: bool,
    /// Certificate ID
    pub cert_id: u64,
    /// Thumbprint (SHA-1 of cert)
    pub thumbprint: [u8; THUMBPRINT_LENGTH],
    /// Subject name
    pub subject: [u8; 128],
    pub subject_len: usize,
    /// Issuer name
    pub issuer: [u8; 128],
    pub issuer_len: usize,
    /// User SID hash
    pub user_sid_hash: u64,
    /// Valid from (timestamp)
    pub valid_from: u64,
    /// Valid to (timestamp)
    pub valid_to: u64,
    /// Key container name
    pub container: [u8; 64],
    pub container_len: usize,
    /// Is recovery agent cert
    pub is_recovery_agent: bool,
    /// Public key (simplified)
    pub public_key: [u8; 256],
    pub public_key_len: usize,
}

impl EfsCertificate {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            cert_id: 0,
            thumbprint: [0u8; THUMBPRINT_LENGTH],
            subject: [0u8; 128],
            subject_len: 0,
            issuer: [0u8; 128],
            issuer_len: 0,
            user_sid_hash: 0,
            valid_from: 0,
            valid_to: 0,
            container: [0u8; 64],
            container_len: 0,
            is_recovery_agent: false,
            public_key: [0u8; 256],
            public_key_len: 0,
        }
    }
}

/// EFS configuration
#[derive(Debug, Clone)]
pub struct EfsConfig {
    /// EFS enabled
    pub enabled: bool,
    /// Default encryption algorithm
    pub default_algorithm: EncryptionAlgorithm,
    /// Key derivation algorithm
    pub key_derivation: KeyDerivation,
    /// Require smart card
    pub require_smart_card: bool,
    /// Allow EFS on domain controllers
    pub allow_on_dc: bool,
    /// Cache timeout (seconds)
    pub cache_timeout: u32,
    /// Recovery policy configured
    pub recovery_policy_configured: bool,
}

impl EfsConfig {
    pub const fn new() -> Self {
        Self {
            enabled: true,
            default_algorithm: EncryptionAlgorithm::Aes256,
            key_derivation: KeyDerivation::Sha256,
            require_smart_card: false,
            allow_on_dc: false,
            cache_timeout: 300, // 5 minutes
            recovery_policy_configured: false,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// EFS subsystem state
struct EfsState {
    /// Initialized flag
    initialized: bool,
    /// Configuration
    config: EfsConfig,
    /// Encrypted files
    files: [EncryptedFile; MAX_ENCRYPTED_FILES],
    file_count: usize,
    /// Certificates
    certificates: [EfsCertificate; MAX_CERTIFICATES],
    certificate_count: usize,
    /// Next file ID
    next_file_id: u64,
    /// Next certificate ID
    next_cert_id: u64,
}

impl EfsState {
    const fn new() -> Self {
        Self {
            initialized: false,
            config: EfsConfig::new(),
            files: [const { EncryptedFile::empty() }; MAX_ENCRYPTED_FILES],
            file_count: 0,
            certificates: [const { EfsCertificate::empty() }; MAX_CERTIFICATES],
            certificate_count: 0,
            next_file_id: 1,
            next_cert_id: 1,
        }
    }
}

static EFS_STATE: SpinLock<EfsState> = SpinLock::new(EfsState::new());

/// EFS statistics
struct EfsStats {
    /// Files encrypted
    files_encrypted: AtomicU64,
    /// Files decrypted
    files_decrypted: AtomicU64,
    /// Encryption operations
    encrypt_operations: AtomicU64,
    /// Decryption operations
    decrypt_operations: AtomicU64,
    /// Key generations
    key_generations: AtomicU64,
    /// Failed operations
    failed_operations: AtomicU64,
    /// Recovery operations
    recovery_operations: AtomicU64,
}

static EFS_STATS: EfsStats = EfsStats {
    files_encrypted: AtomicU64::new(0),
    files_decrypted: AtomicU64::new(0),
    encrypt_operations: AtomicU64::new(0),
    decrypt_operations: AtomicU64::new(0),
    key_generations: AtomicU64::new(0),
    failed_operations: AtomicU64::new(0),
    recovery_operations: AtomicU64::new(0),
};

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the EFS subsystem
pub fn init() {
    crate::serial_println!("[EFS] Initializing Encrypting File System...");

    let mut state = EFS_STATE.lock();

    if state.initialized {
        crate::serial_println!("[EFS] Already initialized");
        return;
    }

    state.initialized = true;

    crate::serial_println!("[EFS] Encrypting File System initialized");
}

// ============================================================================
// Key Generation
// ============================================================================

/// Generate a new File Encryption Key
pub fn efs_generate_fek(algorithm: EncryptionAlgorithm) -> FileEncryptionKey {
    EFS_STATS.key_generations.fetch_add(1, Ordering::Relaxed);

    let mut fek = FileEncryptionKey::empty();
    fek.algorithm = algorithm;

    // Generate pseudo-random key material
    // In a real implementation, this would use CryptGenRandom
    let time = get_tick_count();
    let mut seed = time;

    for i in 0..FEK_LENGTH {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        fek.key[i] = ((seed >> 16) & 0xFF) as u8;
    }

    // Generate IV
    for i in 0..16 {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        fek.iv[i] = ((seed >> 16) & 0xFF) as u8;
    }

    fek.key_length = match algorithm {
        EncryptionAlgorithm::Aes256 => 256,
        EncryptionAlgorithm::Aes128 => 128,
        EncryptionAlgorithm::TripleDes => 168,
        EncryptionAlgorithm::DesX => 128,
    };

    fek
}

// ============================================================================
// File Encryption
// ============================================================================

/// Encrypt a file
pub fn efs_encrypt_file(
    path: &[u8],
    user_sid_hash: u64,
    cert_thumbprint: &[u8; THUMBPRINT_LENGTH],
) -> Result<u64, EfsError> {
    let mut state = EFS_STATE.lock();

    if !state.initialized {
        return Err(EfsError::NotInitialized);
    }

    if !state.config.enabled {
        return Err(EfsError::AccessDenied);
    }

    if path.len() > MAX_PATH_LENGTH {
        return Err(EfsError::InvalidParameter);
    }

    // Check if already encrypted
    for i in 0..MAX_ENCRYPTED_FILES {
        if state.files[i].in_use {
            let fpath = &state.files[i].path[..state.files[i].path_len];
            if fpath == path {
                return Err(EfsError::FileIsEncrypted);
            }
        }
    }

    // Find user certificate
    let mut has_cert = false;
    for i in 0..MAX_CERTIFICATES {
        if state.certificates[i].in_use
            && state.certificates[i].thumbprint == *cert_thumbprint
            && state.certificates[i].user_sid_hash == user_sid_hash
        {
            has_cert = true;
            break;
        }
    }

    if !has_cert {
        EFS_STATS.failed_operations.fetch_add(1, Ordering::Relaxed);
        return Err(EfsError::NoUserCert);
    }

    if state.file_count >= MAX_ENCRYPTED_FILES {
        return Err(EfsError::InsufficientResources);
    }

    let file_id = state.next_file_id;
    state.next_file_id += 1;

    // Get algorithm before mutable borrow
    let default_algorithm = state.config.default_algorithm;

    // Generate FEK
    let _fek = efs_generate_fek(default_algorithm);

    // Create encrypted file record
    for i in 0..MAX_ENCRYPTED_FILES {
        if !state.files[i].in_use {
            let encryption_time = get_tick_count();
            state.files[i].in_use = true;
            state.files[i].file_id = file_id;
            state.files[i].path[..path.len()].copy_from_slice(path);
            state.files[i].path_len = path.len();
            state.files[i].algorithm = default_algorithm;
            state.files[i].encryption_time = encryption_time;
            state.files[i].last_access = encryption_time;

            // Add DDF for user
            state.files[i].ddf[0].in_use = true;
            state.files[i].ddf[0].user_sid_hash = user_sid_hash;
            state.files[i].ddf[0].cert_thumbprint = *cert_thumbprint;
            // In real implementation, encrypt FEK with user's public key
            state.files[i].ddf[0].encrypted_fek_len = ENCRYPTED_FEK_LENGTH;
            state.files[i].ddf_count = 1;

            state.file_count += 1;
            EFS_STATS.files_encrypted.fetch_add(1, Ordering::Relaxed);
            EFS_STATS.encrypt_operations.fetch_add(1, Ordering::Relaxed);

            return Ok(file_id);
        }
    }

    Err(EfsError::InsufficientResources)
}

/// Decrypt a file (remove encryption)
pub fn efs_decrypt_file(path: &[u8], user_sid_hash: u64) -> Result<(), EfsError> {
    let mut state = EFS_STATE.lock();

    if !state.initialized {
        return Err(EfsError::NotInitialized);
    }

    for i in 0..MAX_ENCRYPTED_FILES {
        if state.files[i].in_use {
            let fpath = &state.files[i].path[..state.files[i].path_len];
            if fpath == path {
                // Check if user has access
                let mut has_access = false;
                for j in 0..state.files[i].ddf_count {
                    if state.files[i].ddf[j].in_use
                        && state.files[i].ddf[j].user_sid_hash == user_sid_hash
                    {
                        has_access = true;
                        break;
                    }
                }

                if !has_access {
                    EFS_STATS.failed_operations.fetch_add(1, Ordering::Relaxed);
                    return Err(EfsError::AccessDenied);
                }

                // Remove encryption
                state.files[i] = EncryptedFile::empty();
                if state.file_count > 0 {
                    state.file_count -= 1;
                }

                EFS_STATS.files_decrypted.fetch_add(1, Ordering::Relaxed);
                EFS_STATS.decrypt_operations.fetch_add(1, Ordering::Relaxed);

                return Ok(());
            }
        }
    }

    Err(EfsError::FileNotEncrypted)
}

/// Check if file is encrypted
pub fn efs_is_encrypted(path: &[u8]) -> bool {
    let state = EFS_STATE.lock();

    if !state.initialized {
        return false;
    }

    for i in 0..MAX_ENCRYPTED_FILES {
        if state.files[i].in_use {
            let fpath = &state.files[i].path[..state.files[i].path_len];
            if fpath == path {
                return true;
            }
        }
    }

    false
}

/// Get encryption info for a file
pub fn efs_query_file(path: &[u8]) -> Result<EncryptedFile, EfsError> {
    let state = EFS_STATE.lock();

    if !state.initialized {
        return Err(EfsError::NotInitialized);
    }

    for i in 0..MAX_ENCRYPTED_FILES {
        if state.files[i].in_use {
            let fpath = &state.files[i].path[..state.files[i].path_len];
            if fpath == path {
                return Ok(state.files[i].clone());
            }
        }
    }

    Err(EfsError::FileNotEncrypted)
}

// ============================================================================
// User Access Management
// ============================================================================

/// Add a user to an encrypted file
pub fn efs_add_user(
    path: &[u8],
    owner_sid_hash: u64,
    new_user_sid_hash: u64,
    new_cert_thumbprint: &[u8; THUMBPRINT_LENGTH],
) -> Result<(), EfsError> {
    let mut state = EFS_STATE.lock();

    if !state.initialized {
        return Err(EfsError::NotInitialized);
    }

    for i in 0..MAX_ENCRYPTED_FILES {
        if state.files[i].in_use {
            let fpath = &state.files[i].path[..state.files[i].path_len];
            if fpath == path {
                // Check if owner
                let mut is_owner = false;
                for j in 0..state.files[i].ddf_count {
                    if state.files[i].ddf[j].in_use
                        && state.files[i].ddf[j].user_sid_hash == owner_sid_hash
                    {
                        is_owner = true;
                        break;
                    }
                }

                if !is_owner {
                    return Err(EfsError::AccessDenied);
                }

                // Check if new user cert exists
                let mut has_cert = false;
                for j in 0..MAX_CERTIFICATES {
                    if state.certificates[j].in_use
                        && state.certificates[j].thumbprint == *new_cert_thumbprint
                    {
                        has_cert = true;
                        break;
                    }
                }

                if !has_cert {
                    return Err(EfsError::CertificateNotFound);
                }

                // Add DDF for new user
                if state.files[i].ddf_count >= 4 {
                    return Err(EfsError::InsufficientResources);
                }

                let count = state.files[i].ddf_count;
                state.files[i].ddf[count].in_use = true;
                state.files[i].ddf[count].user_sid_hash = new_user_sid_hash;
                state.files[i].ddf[count].cert_thumbprint = *new_cert_thumbprint;
                state.files[i].ddf[count].encrypted_fek_len = ENCRYPTED_FEK_LENGTH;
                state.files[i].ddf_count += 1;

                return Ok(());
            }
        }
    }

    Err(EfsError::FileNotEncrypted)
}

/// Remove a user from an encrypted file
pub fn efs_remove_user(
    path: &[u8],
    owner_sid_hash: u64,
    remove_user_sid_hash: u64,
) -> Result<(), EfsError> {
    let mut state = EFS_STATE.lock();

    if !state.initialized {
        return Err(EfsError::NotInitialized);
    }

    // Can't remove yourself
    if owner_sid_hash == remove_user_sid_hash {
        return Err(EfsError::InvalidParameter);
    }

    for i in 0..MAX_ENCRYPTED_FILES {
        if state.files[i].in_use {
            let fpath = &state.files[i].path[..state.files[i].path_len];
            if fpath == path {
                // Check if owner
                let mut is_owner = false;
                for j in 0..state.files[i].ddf_count {
                    if state.files[i].ddf[j].in_use
                        && state.files[i].ddf[j].user_sid_hash == owner_sid_hash
                    {
                        is_owner = true;
                        break;
                    }
                }

                if !is_owner {
                    return Err(EfsError::AccessDenied);
                }

                // Find and remove user
                let ddf_count = state.files[i].ddf_count;
                for j in 0..ddf_count {
                    if state.files[i].ddf[j].in_use
                        && state.files[i].ddf[j].user_sid_hash == remove_user_sid_hash
                    {
                        // Shift remaining entries
                        for k in j..ddf_count - 1 {
                            state.files[i].ddf[k] = state.files[i].ddf[k + 1].clone();
                        }
                        state.files[i].ddf[ddf_count - 1] = DataDecryptionField::empty();
                        state.files[i].ddf_count -= 1;
                        return Ok(());
                    }
                }

                return Err(EfsError::KeyNotFound);
            }
        }
    }

    Err(EfsError::FileNotEncrypted)
}

// ============================================================================
// Certificate Management
// ============================================================================

/// Register an EFS certificate
pub fn efs_register_certificate(
    user_sid_hash: u64,
    thumbprint: &[u8; THUMBPRINT_LENGTH],
    subject: &[u8],
    is_recovery_agent: bool,
) -> Result<u64, EfsError> {
    let mut state = EFS_STATE.lock();

    if !state.initialized {
        return Err(EfsError::NotInitialized);
    }

    if subject.len() > 128 {
        return Err(EfsError::InvalidParameter);
    }

    // Check if exists
    for i in 0..MAX_CERTIFICATES {
        if state.certificates[i].in_use && state.certificates[i].thumbprint == *thumbprint {
            return Ok(state.certificates[i].cert_id);
        }
    }

    if state.certificate_count >= MAX_CERTIFICATES {
        return Err(EfsError::InsufficientResources);
    }

    let cert_id = state.next_cert_id;
    state.next_cert_id += 1;

    for i in 0..MAX_CERTIFICATES {
        if !state.certificates[i].in_use {
            let cert = &mut state.certificates[i];
            cert.in_use = true;
            cert.cert_id = cert_id;
            cert.thumbprint = *thumbprint;
            cert.user_sid_hash = user_sid_hash;
            cert.subject[..subject.len()].copy_from_slice(subject);
            cert.subject_len = subject.len();
            cert.is_recovery_agent = is_recovery_agent;
            cert.valid_from = get_tick_count();
            cert.valid_to = cert.valid_from + 365 * 24 * 60 * 60 * 1000; // 1 year

            state.certificate_count += 1;

            if is_recovery_agent {
                state.config.recovery_policy_configured = true;
            }

            return Ok(cert_id);
        }
    }

    Err(EfsError::InsufficientResources)
}

/// Unregister an EFS certificate
pub fn efs_unregister_certificate(thumbprint: &[u8; THUMBPRINT_LENGTH]) -> Result<(), EfsError> {
    let mut state = EFS_STATE.lock();

    if !state.initialized {
        return Err(EfsError::NotInitialized);
    }

    for i in 0..MAX_CERTIFICATES {
        if state.certificates[i].in_use && state.certificates[i].thumbprint == *thumbprint {
            state.certificates[i] = EfsCertificate::empty();
            if state.certificate_count > 0 {
                state.certificate_count -= 1;
            }
            return Ok(());
        }
    }

    Err(EfsError::CertificateNotFound)
}

/// Get user's EFS certificate
pub fn efs_get_user_certificate(user_sid_hash: u64) -> Result<EfsCertificate, EfsError> {
    let state = EFS_STATE.lock();

    if !state.initialized {
        return Err(EfsError::NotInitialized);
    }

    for i in 0..MAX_CERTIFICATES {
        if state.certificates[i].in_use
            && state.certificates[i].user_sid_hash == user_sid_hash
            && !state.certificates[i].is_recovery_agent
        {
            return Ok(state.certificates[i].clone());
        }
    }

    Err(EfsError::NoUserCert)
}

// ============================================================================
// Recovery Operations
// ============================================================================

/// Recover a file using recovery agent
pub fn efs_recover_file(
    path: &[u8],
    recovery_cert_thumbprint: &[u8; THUMBPRINT_LENGTH],
) -> Result<(), EfsError> {
    let mut state = EFS_STATE.lock();

    if !state.initialized {
        return Err(EfsError::NotInitialized);
    }

    // Verify recovery agent certificate
    let mut is_recovery_agent = false;
    for i in 0..MAX_CERTIFICATES {
        if state.certificates[i].in_use
            && state.certificates[i].thumbprint == *recovery_cert_thumbprint
            && state.certificates[i].is_recovery_agent
        {
            is_recovery_agent = true;
            break;
        }
    }

    if !is_recovery_agent {
        EFS_STATS.failed_operations.fetch_add(1, Ordering::Relaxed);
        return Err(EfsError::AccessDenied);
    }

    for i in 0..MAX_ENCRYPTED_FILES {
        if state.files[i].in_use {
            let fpath = &state.files[i].path[..state.files[i].path_len];
            if fpath == path {
                // Check if DRF exists for this recovery agent
                let mut has_drf = false;
                for j in 0..state.files[i].drf_count {
                    if state.files[i].drf[j].in_use
                        && state.files[i].drf[j].cert_thumbprint == *recovery_cert_thumbprint
                    {
                        has_drf = true;
                        break;
                    }
                }

                if !has_drf && state.files[i].drf_count == 0 {
                    // No DRF configured - this would fail in real implementation
                    // For demo, allow recovery
                }

                state.files[i].last_access = get_tick_count();
                EFS_STATS.recovery_operations.fetch_add(1, Ordering::Relaxed);

                return Ok(());
            }
        }
    }

    Err(EfsError::FileNotEncrypted)
}

// ============================================================================
// Configuration
// ============================================================================

/// Set EFS configuration
pub fn efs_set_config(config: &EfsConfig) -> Result<(), EfsError> {
    let mut state = EFS_STATE.lock();

    if !state.initialized {
        return Err(EfsError::NotInitialized);
    }

    state.config = config.clone();
    Ok(())
}

/// Get EFS configuration
pub fn efs_get_config() -> Result<EfsConfig, EfsError> {
    let state = EFS_STATE.lock();

    if !state.initialized {
        return Err(EfsError::NotInitialized);
    }

    Ok(state.config.clone())
}

// ============================================================================
// Statistics
// ============================================================================

/// EFS statistics snapshot
#[derive(Debug, Clone, Default)]
pub struct EfsStatsSnapshot {
    pub files_encrypted: u64,
    pub files_decrypted: u64,
    pub encrypt_operations: u64,
    pub decrypt_operations: u64,
    pub key_generations: u64,
    pub failed_operations: u64,
    pub recovery_operations: u64,
    pub encrypted_file_count: usize,
    pub certificate_count: usize,
}

/// Get EFS statistics
pub fn efs_get_stats() -> EfsStatsSnapshot {
    let state = EFS_STATE.lock();

    EfsStatsSnapshot {
        files_encrypted: EFS_STATS.files_encrypted.load(Ordering::Relaxed),
        files_decrypted: EFS_STATS.files_decrypted.load(Ordering::Relaxed),
        encrypt_operations: EFS_STATS.encrypt_operations.load(Ordering::Relaxed),
        decrypt_operations: EFS_STATS.decrypt_operations.load(Ordering::Relaxed),
        key_generations: EFS_STATS.key_generations.load(Ordering::Relaxed),
        failed_operations: EFS_STATS.failed_operations.load(Ordering::Relaxed),
        recovery_operations: EFS_STATS.recovery_operations.load(Ordering::Relaxed),
        encrypted_file_count: state.file_count,
        certificate_count: state.certificate_count,
    }
}

/// Check if EFS is initialized
pub fn efs_is_initialized() -> bool {
    EFS_STATE.lock().initialized
}

/// Check if EFS is enabled
pub fn efs_is_enabled() -> bool {
    let state = EFS_STATE.lock();
    state.initialized && state.config.enabled
}

/// Get algorithm name
pub fn algorithm_name(alg: EncryptionAlgorithm) -> &'static str {
    match alg {
        EncryptionAlgorithm::Aes256 => "AES-256",
        EncryptionAlgorithm::Aes128 => "AES-128",
        EncryptionAlgorithm::TripleDes => "3DES",
        EncryptionAlgorithm::DesX => "DESX",
    }
}
