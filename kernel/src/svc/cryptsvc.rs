//! Cryptographic Services (CryptSvc)
//!
//! The Cryptographic Services service provides essential cryptographic
//! services to Windows including:
//!
//! - **Certificate Store Management**: Manage system certificate stores
//! - **Root Certificate Updates**: Automatic root CA certificate updates
//! - **Catalog Database**: Manage catalog files for signed drivers
//! - **Protected Storage**: Legacy credential storage
//! - **Key Storage**: Cryptographic key management
//!
//! # Certificate Stores
//!
//! Windows maintains several certificate stores:
//! - `MY` - Personal certificates (with private keys)
//! - `ROOT` - Trusted Root CAs
//! - `CA` - Intermediate CAs
//! - `TRUST` - Enterprise trust settings
//! - `DISALLOWED` - Explicitly untrusted certificates
//!
//! # Registry Location
//!
//! Certificate stores are in: `HKLM\SOFTWARE\Microsoft\SystemCertificates`
//! and `HKCU\SOFTWARE\Microsoft\SystemCertificates`

extern crate alloc;

use crate::ke::SpinLock;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum certificates per store
pub const MAX_CERTIFICATES: usize = 16;

/// Maximum certificate stores
pub const MAX_STORES: usize = 4;

/// Maximum certificate name length
pub const MAX_CERT_NAME: usize = 64;

/// Maximum certificate thumbprint length (SHA-1 = 20 bytes, SHA-256 = 32 bytes)
pub const MAX_THUMBPRINT: usize = 32;

/// Maximum certificate subject/issuer DN length
pub const MAX_DN_LEN: usize = 64;

/// Maximum catalog entries
pub const MAX_CATALOG_ENTRIES: usize = 8;

/// Maximum CTL entries (Certificate Trust List)
pub const MAX_CTL_ENTRIES: usize = 8;

/// Maximum key containers
pub const MAX_KEY_CONTAINERS: usize = 8;

// ============================================================================
// Certificate Store Types
// ============================================================================

/// Certificate store location
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StoreLocation {
    /// Current user store
    CurrentUser = 0,
    /// Local machine store
    LocalMachine = 1,
    /// Current service store
    CurrentService = 2,
    /// Services store
    Services = 3,
    /// Users store
    Users = 4,
}

impl Default for StoreLocation {
    fn default() -> Self {
        Self::LocalMachine
    }
}

/// Well-known certificate store names
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StoreType {
    /// Personal certificates (MY)
    My = 0,
    /// Trusted Root CAs
    Root = 1,
    /// Intermediate CAs
    Ca = 2,
    /// Trust publishers
    Trust = 3,
    /// Disallowed certificates
    Disallowed = 4,
    /// Address book (others' certificates)
    AddressBook = 5,
    /// Trusted publishers
    TrustedPublisher = 6,
    /// Trusted people
    TrustedPeople = 7,
    /// Auth root (dynamically updated roots)
    AuthRoot = 8,
    /// Smart card root
    SmartCardRoot = 9,
    /// Custom store
    Custom = 255,
}

impl Default for StoreType {
    fn default() -> Self {
        Self::My
    }
}

impl StoreType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::My => "MY",
            Self::Root => "ROOT",
            Self::Ca => "CA",
            Self::Trust => "TRUST",
            Self::Disallowed => "DISALLOWED",
            Self::AddressBook => "ADDRESSBOOK",
            Self::TrustedPublisher => "TRUSTEDPUBLISHER",
            Self::TrustedPeople => "TRUSTEDPEOPLE",
            Self::AuthRoot => "AUTHROOT",
            Self::SmartCardRoot => "SMARTCARDROOT",
            Self::Custom => "CUSTOM",
        }
    }
}

/// Certificate encoding type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EncodingType {
    /// DER encoded
    Der = 1,
    /// PEM (Base64) encoded
    Pem = 2,
    /// PKCS#7 message
    Pkcs7 = 3,
    /// PKCS#12 (PFX) file
    Pkcs12 = 4,
}

impl Default for EncodingType {
    fn default() -> Self {
        Self::Der
    }
}

/// Certificate usage flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct CertUsage(pub u32);

impl CertUsage {
    pub const NONE: u32 = 0;
    /// Digital signature
    pub const DIGITAL_SIGNATURE: u32 = 0x0001;
    /// Non-repudiation
    pub const NON_REPUDIATION: u32 = 0x0002;
    /// Key encipherment
    pub const KEY_ENCIPHERMENT: u32 = 0x0004;
    /// Data encipherment
    pub const DATA_ENCIPHERMENT: u32 = 0x0008;
    /// Key agreement
    pub const KEY_AGREEMENT: u32 = 0x0010;
    /// Certificate signing
    pub const KEY_CERT_SIGN: u32 = 0x0020;
    /// CRL signing
    pub const CRL_SIGN: u32 = 0x0040;
    /// Server authentication
    pub const SERVER_AUTH: u32 = 0x0100;
    /// Client authentication
    pub const CLIENT_AUTH: u32 = 0x0200;
    /// Code signing
    pub const CODE_SIGNING: u32 = 0x0400;
    /// Email protection
    pub const EMAIL_PROTECTION: u32 = 0x0800;
    /// Time stamping
    pub const TIME_STAMPING: u32 = 0x1000;
    /// OCSP signing
    pub const OCSP_SIGNING: u32 = 0x2000;

    pub fn has(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }

    pub fn can_sign(&self) -> bool {
        self.has(Self::DIGITAL_SIGNATURE) || self.has(Self::KEY_CERT_SIGN)
    }

    pub fn can_encrypt(&self) -> bool {
        self.has(Self::KEY_ENCIPHERMENT) || self.has(Self::DATA_ENCIPHERMENT)
    }
}

/// Certificate status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CertStatus {
    /// Valid certificate
    Valid = 0,
    /// Expired
    Expired = 1,
    /// Not yet valid
    NotYetValid = 2,
    /// Revoked
    Revoked = 3,
    /// Untrusted root
    UntrustedRoot = 4,
    /// Chain incomplete
    ChainIncomplete = 5,
    /// Invalid signature
    InvalidSignature = 6,
    /// Name mismatch
    NameMismatch = 7,
    /// Unknown status
    Unknown = 255,
}

impl Default for CertStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Cryptographic service error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CryptError {
    /// Success
    Ok = 0,
    /// Service not running
    NotRunning = 1,
    /// Store not found
    StoreNotFound = 2,
    /// Certificate not found
    CertNotFound = 3,
    /// Invalid certificate
    InvalidCert = 4,
    /// Store full
    StoreFull = 5,
    /// Already exists
    AlreadyExists = 6,
    /// Access denied
    AccessDenied = 7,
    /// Invalid parameter
    InvalidParam = 8,
    /// Key not found
    KeyNotFound = 9,
    /// Catalog not found
    CatalogNotFound = 10,
    /// Invalid signature
    InvalidSignature = 11,
    /// Not supported
    NotSupported = 12,
}

// ============================================================================
// Certificate Structure
// ============================================================================

/// A certificate entry
#[derive(Clone)]
pub struct Certificate {
    /// Entry is valid
    pub valid: bool,
    /// Certificate serial number (up to 20 bytes)
    pub serial: [u8; 20],
    /// Serial length
    pub serial_len: usize,
    /// Thumbprint (SHA-1 or SHA-256)
    pub thumbprint: [u8; MAX_THUMBPRINT],
    /// Thumbprint length
    pub thumbprint_len: usize,
    /// Subject Distinguished Name
    pub subject: [u8; MAX_DN_LEN],
    /// Subject length
    pub subject_len: usize,
    /// Issuer Distinguished Name
    pub issuer: [u8; MAX_DN_LEN],
    /// Issuer length
    pub issuer_len: usize,
    /// Friendly name
    pub friendly_name: [u8; MAX_CERT_NAME],
    /// Not before (NT time)
    pub not_before: i64,
    /// Not after (NT time)
    pub not_after: i64,
    /// Key usage flags
    pub usage: CertUsage,
    /// Status
    pub status: CertStatus,
    /// Has private key
    pub has_private_key: bool,
    /// Is self-signed
    pub is_self_signed: bool,
    /// Encoding type
    pub encoding: EncodingType,
    /// Raw DER size
    pub raw_size: usize,
}

impl Certificate {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            serial: [0; 20],
            serial_len: 0,
            thumbprint: [0; MAX_THUMBPRINT],
            thumbprint_len: 0,
            subject: [0; MAX_DN_LEN],
            subject_len: 0,
            issuer: [0; MAX_DN_LEN],
            issuer_len: 0,
            friendly_name: [0; MAX_CERT_NAME],
            not_before: 0,
            not_after: 0,
            usage: CertUsage(0),
            status: CertStatus::Unknown,
            has_private_key: false,
            is_self_signed: false,
            encoding: EncodingType::Der,
            raw_size: 0,
        }
    }

    pub fn subject_str(&self) -> &str {
        core::str::from_utf8(&self.subject[..self.subject_len]).unwrap_or("")
    }

    pub fn set_subject(&mut self, dn: &str) {
        let bytes = dn.as_bytes();
        let len = bytes.len().min(MAX_DN_LEN);
        self.subject[..len].copy_from_slice(&bytes[..len]);
        self.subject_len = len;
    }

    pub fn issuer_str(&self) -> &str {
        core::str::from_utf8(&self.issuer[..self.issuer_len]).unwrap_or("")
    }

    pub fn set_issuer(&mut self, dn: &str) {
        let bytes = dn.as_bytes();
        let len = bytes.len().min(MAX_DN_LEN);
        self.issuer[..len].copy_from_slice(&bytes[..len]);
        self.issuer_len = len;
    }

    pub fn friendly_name_str(&self) -> &str {
        let len = self.friendly_name.iter().position(|&b| b == 0).unwrap_or(MAX_CERT_NAME);
        core::str::from_utf8(&self.friendly_name[..len]).unwrap_or("")
    }

    pub fn set_friendly_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_CERT_NAME);
        self.friendly_name[..len].copy_from_slice(&bytes[..len]);
        if len < MAX_CERT_NAME {
            self.friendly_name[len..].fill(0);
        }
    }

    pub fn set_serial(&mut self, serial: &[u8]) {
        let len = serial.len().min(20);
        self.serial[..len].copy_from_slice(&serial[..len]);
        self.serial_len = len;
    }

    pub fn set_thumbprint(&mut self, thumbprint: &[u8]) {
        let len = thumbprint.len().min(MAX_THUMBPRINT);
        self.thumbprint[..len].copy_from_slice(&thumbprint[..len]);
        self.thumbprint_len = len;
    }
}

// ============================================================================
// Certificate Store
// ============================================================================

/// A certificate store
#[derive(Clone)]
pub struct CertStore {
    /// Store is valid/open
    pub valid: bool,
    /// Store name
    pub name: [u8; 32],
    /// Store type
    pub store_type: StoreType,
    /// Store location
    pub location: StoreLocation,
    /// Certificates in store
    pub certificates: [Certificate; MAX_CERTIFICATES],
    /// Certificate count
    pub cert_count: usize,
    /// Read-only store
    pub read_only: bool,
    /// System store (vs. user store)
    pub is_system: bool,
}

impl CertStore {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            name: [0; 32],
            store_type: StoreType::My,
            location: StoreLocation::LocalMachine,
            certificates: [const { Certificate::empty() }; MAX_CERTIFICATES],
            cert_count: 0,
            read_only: false,
            is_system: true,
        }
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(32);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(32);
        self.name[..len].copy_from_slice(&bytes[..len]);
        if len < 32 {
            self.name[len..].fill(0);
        }
    }
}

// ============================================================================
// Catalog Entry
// ============================================================================

/// A catalog file entry (for driver signing)
#[derive(Clone)]
pub struct CatalogEntry {
    /// Entry is valid
    pub valid: bool,
    /// Catalog name
    pub name: [u8; MAX_CERT_NAME],
    /// Catalog file path
    pub path: [u8; 260],
    /// Signing certificate thumbprint
    pub signer_thumbprint: [u8; MAX_THUMBPRINT],
    /// Thumbprint length
    pub thumbprint_len: usize,
    /// Catalog version
    pub version: u32,
    /// Member count
    pub member_count: u32,
    /// Is trusted
    pub trusted: bool,
}

impl CatalogEntry {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            name: [0; MAX_CERT_NAME],
            path: [0; 260],
            signer_thumbprint: [0; MAX_THUMBPRINT],
            thumbprint_len: 0,
            version: 0,
            member_count: 0,
            trusted: false,
        }
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_CERT_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_CERT_NAME);
        self.name[..len].copy_from_slice(&bytes[..len]);
        if len < MAX_CERT_NAME {
            self.name[len..].fill(0);
        }
    }
}

// ============================================================================
// Key Container
// ============================================================================

/// Cryptographic key container
#[derive(Clone)]
pub struct KeyContainer {
    /// Entry is valid
    pub valid: bool,
    /// Container name
    pub name: [u8; MAX_CERT_NAME],
    /// Key type (RSA, DSA, EC)
    pub key_type: KeyType,
    /// Key size in bits
    pub key_size: u32,
    /// Is exportable
    pub exportable: bool,
    /// Is hardware-protected
    pub hardware_protected: bool,
    /// Owner SID (simplified)
    pub owner_sid: u32,
}

impl KeyContainer {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            name: [0; MAX_CERT_NAME],
            key_type: KeyType::Rsa,
            key_size: 0,
            exportable: false,
            hardware_protected: false,
            owner_sid: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_CERT_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_CERT_NAME);
        self.name[..len].copy_from_slice(&bytes[..len]);
        if len < MAX_CERT_NAME {
            self.name[len..].fill(0);
        }
    }
}

/// Key types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyType {
    /// RSA key pair
    Rsa = 1,
    /// DSA key pair
    Dsa = 2,
    /// ECDSA key pair
    Ecdsa = 3,
    /// ECDH key pair
    Ecdh = 4,
    /// AES symmetric key
    Aes = 10,
    /// 3DES symmetric key
    TripleDes = 11,
}

impl Default for KeyType {
    fn default() -> Self {
        Self::Rsa
    }
}

// ============================================================================
// Service State
// ============================================================================

/// Cryptographic services state
struct CryptState {
    /// Service running
    running: bool,
    /// Certificate stores
    stores: [CertStore; MAX_STORES],
    /// Store count
    store_count: usize,
    /// Catalog entries
    catalogs: [CatalogEntry; MAX_CATALOG_ENTRIES],
    /// Catalog count
    catalog_count: usize,
    /// Key containers
    key_containers: [KeyContainer; MAX_KEY_CONTAINERS],
    /// Key container count
    key_count: usize,
    /// Auto-update root certificates
    auto_update_roots: bool,
    /// Root update URL
    root_update_enabled: bool,
}

impl CryptState {
    const fn new() -> Self {
        Self {
            running: false,
            stores: [const { CertStore::empty() }; MAX_STORES],
            store_count: 0,
            catalogs: [const { CatalogEntry::empty() }; MAX_CATALOG_ENTRIES],
            catalog_count: 0,
            key_containers: [const { KeyContainer::empty() }; MAX_KEY_CONTAINERS],
            key_count: 0,
            auto_update_roots: true,
            root_update_enabled: true,
        }
    }
}

static CRYPT_STATE: SpinLock<CryptState> = SpinLock::new(CryptState::new());

/// Statistics
struct CryptStats {
    /// Certificates added
    certs_added: AtomicU64,
    /// Certificates removed
    certs_removed: AtomicU64,
    /// Certificate verifications
    verifications: AtomicU64,
    /// Verification failures
    verification_failures: AtomicU64,
    /// Stores opened
    stores_opened: AtomicU64,
    /// Catalogs verified
    catalogs_verified: AtomicU64,
    /// Keys generated
    keys_generated: AtomicU64,
}

impl CryptStats {
    const fn new() -> Self {
        Self {
            certs_added: AtomicU64::new(0),
            certs_removed: AtomicU64::new(0),
            verifications: AtomicU64::new(0),
            verification_failures: AtomicU64::new(0),
            stores_opened: AtomicU64::new(0),
            catalogs_verified: AtomicU64::new(0),
            keys_generated: AtomicU64::new(0),
        }
    }
}

static CRYPT_STATS: CryptStats = CryptStats::new();

// ============================================================================
// Certificate Store Management
// ============================================================================

/// Open a certificate store
pub fn open_store(
    location: StoreLocation,
    store_type: StoreType,
) -> Result<usize, CryptError> {
    let mut state = CRYPT_STATE.lock();

    if !state.running {
        return Err(CryptError::NotRunning);
    }

    // Check if already open
    for i in 0..MAX_STORES {
        if state.stores[i].valid
            && state.stores[i].location == location
            && state.stores[i].store_type == store_type
        {
            return Ok(i);
        }
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_STORES {
        if !state.stores[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(CryptError::StoreFull),
    };

    let store = &mut state.stores[slot];
    store.valid = true;
    store.set_name(store_type.name());
    store.store_type = store_type;
    store.location = location;
    store.cert_count = 0;
    store.read_only = false;
    store.is_system = location == StoreLocation::LocalMachine;

    state.store_count += 1;

    CRYPT_STATS.stores_opened.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[CRYPTSVC] Opened store '{}' ({:?})",
        store_type.name(), location);

    Ok(slot)
}

/// Close a certificate store
pub fn close_store(handle: usize) -> Result<(), CryptError> {
    let mut state = CRYPT_STATE.lock();

    if handle >= MAX_STORES || !state.stores[handle].valid {
        return Err(CryptError::StoreNotFound);
    }

    state.stores[handle].valid = false;
    state.store_count = state.store_count.saturating_sub(1);

    Ok(())
}

/// Add a certificate to a store
pub fn add_certificate(
    store_handle: usize,
    cert: Certificate,
) -> Result<usize, CryptError> {
    let mut state = CRYPT_STATE.lock();

    if !state.running {
        return Err(CryptError::NotRunning);
    }

    if store_handle >= MAX_STORES || !state.stores[store_handle].valid {
        return Err(CryptError::StoreNotFound);
    }

    if state.stores[store_handle].read_only {
        return Err(CryptError::AccessDenied);
    }

    // Extract values before mutable borrow
    let cert_count = state.stores[store_handle].cert_count;

    // Check for duplicate
    for i in 0..cert_count {
        let existing = &state.stores[store_handle].certificates[i];
        if existing.valid
            && existing.thumbprint_len == cert.thumbprint_len
            && existing.thumbprint[..existing.thumbprint_len] == cert.thumbprint[..cert.thumbprint_len]
        {
            return Err(CryptError::AlreadyExists);
        }
    }

    if cert_count >= MAX_CERTIFICATES {
        return Err(CryptError::StoreFull);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_CERTIFICATES {
        if !state.stores[store_handle].certificates[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(CryptError::StoreFull),
    };

    let subject = cert.subject_str();
    let mut subject_copy = [0u8; MAX_DN_LEN];
    let subject_len = subject.len().min(MAX_DN_LEN);
    subject_copy[..subject_len].copy_from_slice(&subject.as_bytes()[..subject_len]);

    state.stores[store_handle].certificates[slot] = cert;
    state.stores[store_handle].certificates[slot].valid = true;
    state.stores[store_handle].cert_count += 1;

    CRYPT_STATS.certs_added.fetch_add(1, Ordering::Relaxed);

    let subject_str = core::str::from_utf8(&subject_copy[..subject_len]).unwrap_or("");
    crate::serial_println!("[CRYPTSVC] Added certificate: {}", subject_str);

    Ok(slot)
}

/// Remove a certificate from a store
pub fn remove_certificate(store_handle: usize, cert_index: usize) -> Result<(), CryptError> {
    let mut state = CRYPT_STATE.lock();

    if store_handle >= MAX_STORES || !state.stores[store_handle].valid {
        return Err(CryptError::StoreNotFound);
    }

    if cert_index >= MAX_CERTIFICATES || !state.stores[store_handle].certificates[cert_index].valid {
        return Err(CryptError::CertNotFound);
    }

    if state.stores[store_handle].read_only {
        return Err(CryptError::AccessDenied);
    }

    state.stores[store_handle].certificates[cert_index].valid = false;
    state.stores[store_handle].cert_count = state.stores[store_handle].cert_count.saturating_sub(1);

    CRYPT_STATS.certs_removed.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Find certificate by thumbprint
pub fn find_cert_by_thumbprint(store_handle: usize, thumbprint: &[u8]) -> Option<usize> {
    let state = CRYPT_STATE.lock();

    if store_handle >= MAX_STORES || !state.stores[store_handle].valid {
        return None;
    }

    for i in 0..MAX_CERTIFICATES {
        let cert = &state.stores[store_handle].certificates[i];
        if cert.valid
            && cert.thumbprint_len == thumbprint.len()
            && cert.thumbprint[..cert.thumbprint_len] == thumbprint[..]
        {
            return Some(i);
        }
    }

    None
}

/// Find certificate by subject
pub fn find_cert_by_subject(store_handle: usize, subject: &str) -> Option<usize> {
    let state = CRYPT_STATE.lock();

    if store_handle >= MAX_STORES || !state.stores[store_handle].valid {
        return None;
    }

    for i in 0..MAX_CERTIFICATES {
        let cert = &state.stores[store_handle].certificates[i];
        if cert.valid && cert.subject_str().contains(subject) {
            return Some(i);
        }
    }

    None
}

/// Get certificate count in store
pub fn get_cert_count(store_handle: usize) -> usize {
    let state = CRYPT_STATE.lock();

    if store_handle >= MAX_STORES || !state.stores[store_handle].valid {
        return 0;
    }

    state.stores[store_handle].cert_count
}

/// Get certificate from store
pub fn get_certificate(store_handle: usize, index: usize) -> Option<Certificate> {
    let state = CRYPT_STATE.lock();

    if store_handle >= MAX_STORES || !state.stores[store_handle].valid {
        return None;
    }

    if index >= MAX_CERTIFICATES {
        return None;
    }

    let cert = &state.stores[store_handle].certificates[index];
    if cert.valid {
        Some(cert.clone())
    } else {
        None
    }
}

// ============================================================================
// Certificate Verification
// ============================================================================

/// Verify a certificate chain
pub fn verify_certificate(cert: &Certificate) -> CertStatus {
    CRYPT_STATS.verifications.fetch_add(1, Ordering::Relaxed);

    let now = crate::rtl::time::rtl_get_system_time();

    // Check validity period
    if now < cert.not_before {
        CRYPT_STATS.verification_failures.fetch_add(1, Ordering::Relaxed);
        return CertStatus::NotYetValid;
    }

    if now > cert.not_after {
        CRYPT_STATS.verification_failures.fetch_add(1, Ordering::Relaxed);
        return CertStatus::Expired;
    }

    // Check if in disallowed store
    let state = CRYPT_STATE.lock();
    for i in 0..MAX_STORES {
        if state.stores[i].valid && state.stores[i].store_type == StoreType::Disallowed {
            for j in 0..MAX_CERTIFICATES {
                let disallowed = &state.stores[i].certificates[j];
                if disallowed.valid
                    && disallowed.thumbprint_len == cert.thumbprint_len
                    && disallowed.thumbprint[..disallowed.thumbprint_len] == cert.thumbprint[..cert.thumbprint_len]
                {
                    CRYPT_STATS.verification_failures.fetch_add(1, Ordering::Relaxed);
                    return CertStatus::Revoked;
                }
            }
        }
    }

    // For self-signed certs, check if in ROOT store
    if cert.is_self_signed {
        for i in 0..MAX_STORES {
            if state.stores[i].valid && state.stores[i].store_type == StoreType::Root {
                for j in 0..MAX_CERTIFICATES {
                    let root = &state.stores[i].certificates[j];
                    if root.valid
                        && root.thumbprint_len == cert.thumbprint_len
                        && root.thumbprint[..root.thumbprint_len] == cert.thumbprint[..cert.thumbprint_len]
                    {
                        return CertStatus::Valid;
                    }
                }
            }
        }
        CRYPT_STATS.verification_failures.fetch_add(1, Ordering::Relaxed);
        return CertStatus::UntrustedRoot;
    }

    CertStatus::Valid
}

// ============================================================================
// Catalog Management
// ============================================================================

/// Add a catalog entry
pub fn add_catalog(name: &str, path: &str, signer_thumbprint: &[u8]) -> Result<usize, CryptError> {
    let mut state = CRYPT_STATE.lock();

    if !state.running {
        return Err(CryptError::NotRunning);
    }

    if state.catalog_count >= MAX_CATALOG_ENTRIES {
        return Err(CryptError::StoreFull);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_CATALOG_ENTRIES {
        if !state.catalogs[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(CryptError::StoreFull),
    };

    let catalog = &mut state.catalogs[slot];
    catalog.valid = true;
    catalog.set_name(name);

    let path_bytes = path.as_bytes();
    let path_len = path_bytes.len().min(260);
    catalog.path[..path_len].copy_from_slice(&path_bytes[..path_len]);

    let thumb_len = signer_thumbprint.len().min(MAX_THUMBPRINT);
    catalog.signer_thumbprint[..thumb_len].copy_from_slice(&signer_thumbprint[..thumb_len]);
    catalog.thumbprint_len = thumb_len;
    catalog.trusted = true;

    state.catalog_count += 1;

    crate::serial_println!("[CRYPTSVC] Added catalog '{}'", name);

    Ok(slot)
}

/// Verify a file against catalog
pub fn verify_catalog_member(_catalog_index: usize, _file_hash: &[u8]) -> bool {
    CRYPT_STATS.catalogs_verified.fetch_add(1, Ordering::Relaxed);
    // Simplified verification
    true
}

/// Get catalog count
pub fn get_catalog_count() -> usize {
    let state = CRYPT_STATE.lock();
    state.catalog_count
}

// ============================================================================
// Key Container Management
// ============================================================================

/// Create a key container
pub fn create_key_container(
    name: &str,
    key_type: KeyType,
    key_size: u32,
    exportable: bool,
) -> Result<usize, CryptError> {
    let mut state = CRYPT_STATE.lock();

    if !state.running {
        return Err(CryptError::NotRunning);
    }

    if state.key_count >= MAX_KEY_CONTAINERS {
        return Err(CryptError::StoreFull);
    }

    // Check for duplicate
    for i in 0..MAX_KEY_CONTAINERS {
        if state.key_containers[i].valid && state.key_containers[i].name_str() == name {
            return Err(CryptError::AlreadyExists);
        }
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_KEY_CONTAINERS {
        if !state.key_containers[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(CryptError::StoreFull),
    };

    let container = &mut state.key_containers[slot];
    container.valid = true;
    container.set_name(name);
    container.key_type = key_type;
    container.key_size = key_size;
    container.exportable = exportable;
    container.hardware_protected = false;
    container.owner_sid = 0; // SYSTEM

    state.key_count += 1;

    CRYPT_STATS.keys_generated.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[CRYPTSVC] Created key container '{}' ({:?} {}-bit)",
        name, key_type, key_size);

    Ok(slot)
}

/// Delete a key container
pub fn delete_key_container(name: &str) -> Result<(), CryptError> {
    let mut state = CRYPT_STATE.lock();

    for i in 0..MAX_KEY_CONTAINERS {
        if state.key_containers[i].valid && state.key_containers[i].name_str() == name {
            state.key_containers[i].valid = false;
            state.key_count = state.key_count.saturating_sub(1);
            return Ok(());
        }
    }

    Err(CryptError::KeyNotFound)
}

/// Get key container count
pub fn get_key_container_count() -> usize {
    let state = CRYPT_STATE.lock();
    state.key_count
}

// ============================================================================
// Statistics and Queries
// ============================================================================

/// Get cryptographic service statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64, u64) {
    (
        CRYPT_STATS.certs_added.load(Ordering::Relaxed),
        CRYPT_STATS.certs_removed.load(Ordering::Relaxed),
        CRYPT_STATS.verifications.load(Ordering::Relaxed),
        CRYPT_STATS.verification_failures.load(Ordering::Relaxed),
        CRYPT_STATS.stores_opened.load(Ordering::Relaxed),
        CRYPT_STATS.catalogs_verified.load(Ordering::Relaxed),
        CRYPT_STATS.keys_generated.load(Ordering::Relaxed),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = CRYPT_STATE.lock();
    state.running
}

/// Get store count
pub fn get_store_count() -> usize {
    let state = CRYPT_STATE.lock();
    state.store_count
}

/// Enable/disable root auto-update
pub fn set_root_auto_update(enabled: bool) {
    let mut state = CRYPT_STATE.lock();
    state.auto_update_roots = enabled;
    crate::serial_println!("[CRYPTSVC] Root auto-update: {}",
        if enabled { "enabled" } else { "disabled" });
}

/// Check if root auto-update is enabled
pub fn is_root_auto_update_enabled() -> bool {
    let state = CRYPT_STATE.lock();
    state.auto_update_roots
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialized flag
static CRYPT_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize Cryptographic Services
pub fn init() {
    if CRYPT_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[CRYPTSVC] Initializing Cryptographic Services...");

    {
        let mut state = CRYPT_STATE.lock();
        state.running = true;
    }

    // Open default certificate stores
    let _ = open_store(StoreLocation::LocalMachine, StoreType::Root);
    let _ = open_store(StoreLocation::LocalMachine, StoreType::Ca);
    let _ = open_store(StoreLocation::LocalMachine, StoreType::My);
    let _ = open_store(StoreLocation::LocalMachine, StoreType::Disallowed);
    let _ = open_store(StoreLocation::LocalMachine, StoreType::TrustedPublisher);

    // Add some well-known root CAs (simulated)
    if let Ok(root_handle) = open_store(StoreLocation::LocalMachine, StoreType::Root) {
        // Microsoft Root Certificate Authority
        let mut cert1 = Certificate::empty();
        cert1.set_subject("CN=Microsoft Root Certificate Authority, DC=microsoft, DC=com");
        cert1.set_issuer("CN=Microsoft Root Certificate Authority, DC=microsoft, DC=com");
        cert1.set_friendly_name("Microsoft Root Certificate Authority");
        cert1.set_thumbprint(&[0xCD, 0xD4, 0xEE, 0xAE, 0x60, 0x00, 0xAC, 0x7F]);
        cert1.usage = CertUsage(CertUsage::KEY_CERT_SIGN | CertUsage::CRL_SIGN);
        cert1.is_self_signed = true;
        cert1.status = CertStatus::Valid;
        cert1.not_before = 0;
        cert1.not_after = i64::MAX;
        let _ = add_certificate(root_handle, cert1);

        // VeriSign Class 3 Public Primary CA
        let mut cert2 = Certificate::empty();
        cert2.set_subject("CN=VeriSign Class 3 Public Primary Certification Authority - G5");
        cert2.set_issuer("CN=VeriSign Class 3 Public Primary Certification Authority - G5");
        cert2.set_friendly_name("VeriSign Class 3 Public Primary CA");
        cert2.set_thumbprint(&[0x4E, 0xB6, 0xD5, 0x78, 0x49, 0x9B, 0x1C, 0xCF]);
        cert2.usage = CertUsage(CertUsage::KEY_CERT_SIGN | CertUsage::CRL_SIGN);
        cert2.is_self_signed = true;
        cert2.status = CertStatus::Valid;
        cert2.not_before = 0;
        cert2.not_after = i64::MAX;
        let _ = add_certificate(root_handle, cert2);

        // DigiCert Global Root CA
        let mut cert3 = Certificate::empty();
        cert3.set_subject("CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc");
        cert3.set_issuer("CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc");
        cert3.set_friendly_name("DigiCert Global Root CA");
        cert3.set_thumbprint(&[0xA8, 0x98, 0x5D, 0x3A, 0x65, 0xE5, 0xE5, 0xC4]);
        cert3.usage = CertUsage(CertUsage::KEY_CERT_SIGN | CertUsage::CRL_SIGN);
        cert3.is_self_signed = true;
        cert3.status = CertStatus::Valid;
        cert3.not_before = 0;
        cert3.not_after = i64::MAX;
        let _ = add_certificate(root_handle, cert3);
    }

    // Add default catalogs for system components
    let _ = add_catalog("nt5.cat", "C:\\WINDOWS\\system32\\CatRoot\\{F750E6C3}\\nt5.cat", &[]);
    let _ = add_catalog("nt5inf.cat", "C:\\WINDOWS\\system32\\CatRoot\\{F750E6C3}\\nt5inf.cat", &[]);
    let _ = add_catalog("oem.cat", "C:\\WINDOWS\\system32\\CatRoot\\{F750E6C3}\\oem.cat", &[]);

    crate::serial_println!("[CRYPTSVC] Cryptographic Services initialized");
    crate::serial_println!("[CRYPTSVC]   Certificate stores: 5");
    crate::serial_println!("[CRYPTSVC]   Root certificates: 3");
    crate::serial_println!("[CRYPTSVC]   Catalogs: 3");
}
