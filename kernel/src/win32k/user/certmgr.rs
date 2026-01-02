//! Certificate Manager
//!
//! Implements the Certificate Manager snap-in following Windows Server 2003.
//! Provides digital certificate management for users and computers.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - certmgr.msc - Certificate Manager snap-in
//! - Certificate stores (Personal, Trusted Root CAs, etc.)
//! - X.509 certificate handling

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum certificates per store
const MAX_CERTS: usize = 64;

/// Maximum certificate stores
const MAX_STORES: usize = 16;

/// Maximum name length
const MAX_NAME: usize = 128;

/// Maximum thumbprint length (SHA-1 = 40 hex chars)
const MAX_THUMBPRINT: usize = 40;

// ============================================================================
// Certificate Store Type
// ============================================================================

/// Certificate store type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StoreType {
    /// Personal certificates
    #[default]
    Personal = 0,
    /// Trusted Root Certification Authorities
    TrustedRoot = 1,
    /// Enterprise Trust
    EnterpriseTrust = 2,
    /// Intermediate Certification Authorities
    IntermediateCA = 3,
    /// Trusted Publishers
    TrustedPublishers = 4,
    /// Untrusted Certificates
    Untrusted = 5,
    /// Third-Party Root Certification Authorities
    ThirdPartyRoot = 6,
    /// Trusted People
    TrustedPeople = 7,
    /// Other People
    OtherPeople = 8,
    /// Certificate Enrollment Requests
    EnrollmentRequests = 9,
    /// Active Directory User Object
    AdUserObject = 10,
}

impl StoreType {
    pub fn as_str(&self) -> &'static str {
        match self {
            StoreType::Personal => "Personal",
            StoreType::TrustedRoot => "Trusted Root Certification Authorities",
            StoreType::EnterpriseTrust => "Enterprise Trust",
            StoreType::IntermediateCA => "Intermediate Certification Authorities",
            StoreType::TrustedPublishers => "Trusted Publishers",
            StoreType::Untrusted => "Untrusted Certificates",
            StoreType::ThirdPartyRoot => "Third-Party Root Certification Authorities",
            StoreType::TrustedPeople => "Trusted People",
            StoreType::OtherPeople => "Other People",
            StoreType::EnrollmentRequests => "Certificate Enrollment Requests",
            StoreType::AdUserObject => "Active Directory User Object",
        }
    }
}

// ============================================================================
// Certificate Purpose
// ============================================================================

/// Certificate intended purpose
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CertPurpose {
    /// All purposes
    #[default]
    All = 0,
    /// Server Authentication
    ServerAuth = 1,
    /// Client Authentication
    ClientAuth = 2,
    /// Code Signing
    CodeSigning = 3,
    /// Secure Email
    SecureEmail = 4,
    /// Time Stamping
    TimeStamping = 5,
    /// IP Security End System
    IpsecEndSystem = 6,
    /// IP Security Tunnel Termination
    IpsecTunnel = 7,
    /// IP Security User
    IpsecUser = 8,
    /// Encrypting File System
    Efs = 9,
    /// Windows Hardware Driver Verification
    DriverVerification = 10,
    /// Smart Card Logon
    SmartCardLogon = 11,
}

impl CertPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertPurpose::All => "<All>",
            CertPurpose::ServerAuth => "Server Authentication",
            CertPurpose::ClientAuth => "Client Authentication",
            CertPurpose::CodeSigning => "Code Signing",
            CertPurpose::SecureEmail => "Secure Email",
            CertPurpose::TimeStamping => "Time Stamping",
            CertPurpose::IpsecEndSystem => "IP Security End System",
            CertPurpose::IpsecTunnel => "IP Security Tunnel Termination",
            CertPurpose::IpsecUser => "IP Security User",
            CertPurpose::Efs => "Encrypting File System",
            CertPurpose::DriverVerification => "Windows Hardware Driver Verification",
            CertPurpose::SmartCardLogon => "Smart Card Logon",
        }
    }

    pub fn oid(&self) -> &'static str {
        match self {
            CertPurpose::All => "",
            CertPurpose::ServerAuth => "1.3.6.1.5.5.7.3.1",
            CertPurpose::ClientAuth => "1.3.6.1.5.5.7.3.2",
            CertPurpose::CodeSigning => "1.3.6.1.5.5.7.3.3",
            CertPurpose::SecureEmail => "1.3.6.1.5.5.7.3.4",
            CertPurpose::TimeStamping => "1.3.6.1.5.5.7.3.8",
            CertPurpose::IpsecEndSystem => "1.3.6.1.5.5.7.3.5",
            CertPurpose::IpsecTunnel => "1.3.6.1.5.5.7.3.6",
            CertPurpose::IpsecUser => "1.3.6.1.5.5.7.3.7",
            CertPurpose::Efs => "1.3.6.1.4.1.311.10.3.4",
            CertPurpose::DriverVerification => "1.3.6.1.4.1.311.10.3.5",
            CertPurpose::SmartCardLogon => "1.3.6.1.4.1.311.20.2.2",
        }
    }
}

// ============================================================================
// Key Usage
// ============================================================================

bitflags::bitflags! {
    /// Key usage flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyUsage: u16 {
        const DIGITAL_SIGNATURE = 0x0080;
        const NON_REPUDIATION = 0x0040;
        const KEY_ENCIPHERMENT = 0x0020;
        const DATA_ENCIPHERMENT = 0x0010;
        const KEY_AGREEMENT = 0x0008;
        const KEY_CERT_SIGN = 0x0004;
        const CRL_SIGN = 0x0002;
        const ENCIPHER_ONLY = 0x0001;
        const DECIPHER_ONLY = 0x8000;
    }
}

// ============================================================================
// Certificate Entry
// ============================================================================

/// Certificate entry
#[derive(Debug, Clone, Copy)]
pub struct CertificateEntry {
    /// Certificate ID
    pub cert_id: u32,
    /// Store type
    pub store: StoreType,
    /// Issued To (Subject CN)
    pub issued_to: [u8; MAX_NAME],
    /// Issued to length
    pub issued_to_len: usize,
    /// Issued By (Issuer CN)
    pub issued_by: [u8; MAX_NAME],
    /// Issued by length
    pub issued_by_len: usize,
    /// Expiration date (Unix timestamp)
    pub expiration: u64,
    /// Not before date
    pub not_before: u64,
    /// Thumbprint (SHA-1 hash)
    pub thumbprint: [u8; MAX_THUMBPRINT],
    /// Thumbprint length
    pub thumbprint_len: usize,
    /// Serial number
    pub serial: [u8; 32],
    /// Serial length
    pub serial_len: usize,
    /// Primary purpose
    pub purpose: CertPurpose,
    /// Key usage
    pub key_usage: KeyUsage,
    /// Key size (bits)
    pub key_size: u16,
    /// Signature algorithm
    pub sig_algorithm: [u8; 32],
    /// Sig algorithm length
    pub sig_alg_len: usize,
    /// Has private key
    pub has_private_key: bool,
    /// Is self-signed
    pub is_self_signed: bool,
    /// Is expired
    pub is_expired: bool,
    /// Friendly name
    pub friendly_name: [u8; 64],
    /// Friendly name length
    pub friendly_len: usize,
}

impl CertificateEntry {
    pub const fn new() -> Self {
        Self {
            cert_id: 0,
            store: StoreType::Personal,
            issued_to: [0u8; MAX_NAME],
            issued_to_len: 0,
            issued_by: [0u8; MAX_NAME],
            issued_by_len: 0,
            expiration: 0,
            not_before: 0,
            thumbprint: [0u8; MAX_THUMBPRINT],
            thumbprint_len: 0,
            serial: [0u8; 32],
            serial_len: 0,
            purpose: CertPurpose::All,
            key_usage: KeyUsage::empty(),
            key_size: 2048,
            sig_algorithm: [0u8; 32],
            sig_alg_len: 0,
            has_private_key: false,
            is_self_signed: false,
            is_expired: false,
            friendly_name: [0u8; 64],
            friendly_len: 0,
        }
    }

    pub fn set_issued_to(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.issued_to[..len].copy_from_slice(&name[..len]);
        self.issued_to_len = len;
    }

    pub fn set_issued_by(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.issued_by[..len].copy_from_slice(&name[..len]);
        self.issued_by_len = len;
    }

    pub fn set_thumbprint(&mut self, thumb: &[u8]) {
        let len = thumb.len().min(MAX_THUMBPRINT);
        self.thumbprint[..len].copy_from_slice(&thumb[..len]);
        self.thumbprint_len = len;
    }

    pub fn set_serial(&mut self, serial: &[u8]) {
        let len = serial.len().min(32);
        self.serial[..len].copy_from_slice(&serial[..len]);
        self.serial_len = len;
    }

    pub fn set_friendly_name(&mut self, name: &[u8]) {
        let len = name.len().min(64);
        self.friendly_name[..len].copy_from_slice(&name[..len]);
        self.friendly_len = len;
    }
}

impl Default for CertificateEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Certificate Store
// ============================================================================

/// Certificate store
#[derive(Debug, Clone, Copy)]
pub struct CertStore {
    /// Store type
    pub store_type: StoreType,
    /// Physical store name
    pub physical_name: [u8; 32],
    /// Name length
    pub name_len: usize,
    /// Certificate count
    pub cert_count: usize,
    /// Is read-only
    pub read_only: bool,
}

impl CertStore {
    pub const fn new() -> Self {
        Self {
            store_type: StoreType::Personal,
            physical_name: [0u8; 32],
            name_len: 0,
            cert_count: 0,
            read_only: false,
        }
    }
}

impl Default for CertStore {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Certificate Manager State
// ============================================================================

/// Certificate Manager state
struct CertMgrState {
    /// Certificate stores
    stores: [CertStore; MAX_STORES],
    /// Store count
    store_count: usize,
    /// Certificates
    certs: [CertificateEntry; MAX_CERTS],
    /// Certificate count
    cert_count: usize,
    /// Next certificate ID
    next_cert_id: u32,
    /// Selected store type
    selected_store: StoreType,
    /// Selected certificate ID
    selected_cert: u32,
    /// View filter (purpose)
    filter_purpose: CertPurpose,
    /// Show archived certificates
    show_archived: bool,
    /// Show physical stores
    show_physical: bool,
}

impl CertMgrState {
    pub const fn new() -> Self {
        Self {
            stores: [const { CertStore::new() }; MAX_STORES],
            store_count: 0,
            certs: [const { CertificateEntry::new() }; MAX_CERTS],
            cert_count: 0,
            next_cert_id: 1,
            selected_store: StoreType::Personal,
            selected_cert: 0,
            filter_purpose: CertPurpose::All,
            show_archived: false,
            show_physical: false,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static CERTMGR_INITIALIZED: AtomicBool = AtomicBool::new(false);
static CERTMGR_STATE: SpinLock<CertMgrState> = SpinLock::new(CertMgrState::new());

// Statistics
static CERTS_IMPORTED: AtomicU32 = AtomicU32::new(0);
static CERTS_EXPORTED: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Certificate Manager
pub fn init() {
    if CERTMGR_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = CERTMGR_STATE.lock();

    // Initialize certificate stores
    init_stores(&mut state);

    // Add sample certificates
    add_sample_certs(&mut state);

    crate::serial_println!("[WIN32K] Certificate Manager initialized");
}

/// Initialize certificate stores
fn init_stores(state: &mut CertMgrState) {
    let stores = [
        StoreType::Personal,
        StoreType::TrustedRoot,
        StoreType::EnterpriseTrust,
        StoreType::IntermediateCA,
        StoreType::TrustedPublishers,
        StoreType::Untrusted,
        StoreType::ThirdPartyRoot,
        StoreType::TrustedPeople,
    ];

    for store_type in stores.iter() {
        if state.store_count >= MAX_STORES {
            break;
        }
        let mut store = CertStore::new();
        store.store_type = *store_type;
        let name = store_type.as_str().as_bytes();
        let len = name.len().min(32);
        store.physical_name[..len].copy_from_slice(&name[..len]);
        store.name_len = len;

        let idx = state.store_count;
        state.stores[idx] = store;
        state.store_count += 1;
    }
}

/// Add sample certificates
fn add_sample_certs(state: &mut CertMgrState) {
    // Sample root CAs
    let root_cas: [(&[u8], &[u8], u64); 5] = [
        (b"Microsoft Root Certificate Authority", b"Microsoft Root Certificate Authority", 2082758400),
        (b"VeriSign Class 3 Public Primary CA", b"VeriSign Class 3 Public Primary CA", 1753920000),
        (b"DigiCert Global Root CA", b"DigiCert Global Root CA", 2037772800),
        (b"Thawte Premium Server CA", b"Thawte Premium Server CA", 1609459200),
        (b"GeoTrust Global CA", b"GeoTrust Global CA", 1753920000),
    ];

    for (issued_to, issued_by, exp) in root_cas.iter() {
        if state.cert_count >= MAX_CERTS {
            break;
        }
        let mut cert = CertificateEntry::new();
        cert.cert_id = state.next_cert_id;
        state.next_cert_id += 1;
        cert.store = StoreType::TrustedRoot;
        cert.set_issued_to(issued_to);
        cert.set_issued_by(issued_by);
        cert.expiration = *exp;
        cert.not_before = 946684800; // 2000-01-01
        cert.is_self_signed = true;
        cert.key_usage = KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN;
        cert.key_size = 4096;

        let idx = state.cert_count;
        state.certs[idx] = cert;
        state.cert_count += 1;

        // Update store count
        for i in 0..state.store_count {
            if state.stores[i].store_type == StoreType::TrustedRoot {
                state.stores[i].cert_count += 1;
                break;
            }
        }
    }

    // Sample intermediate CAs
    let int_cas: [(&[u8], &[u8]); 3] = [
        (b"Microsoft Code Signing PCA", b"Microsoft Root Certificate Authority"),
        (b"VeriSign Class 3 Extended Validation SSL CA", b"VeriSign Class 3 Public Primary CA"),
        (b"DigiCert SHA2 Extended Validation Server CA", b"DigiCert High Assurance EV Root CA"),
    ];

    for (issued_to, issued_by) in int_cas.iter() {
        if state.cert_count >= MAX_CERTS {
            break;
        }
        let mut cert = CertificateEntry::new();
        cert.cert_id = state.next_cert_id;
        state.next_cert_id += 1;
        cert.store = StoreType::IntermediateCA;
        cert.set_issued_to(issued_to);
        cert.set_issued_by(issued_by);
        cert.expiration = 1893456000; // 2030
        cert.not_before = 1262304000; // 2010
        cert.key_usage = KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN | KeyUsage::DIGITAL_SIGNATURE;
        cert.key_size = 2048;

        let idx = state.cert_count;
        state.certs[idx] = cert;
        state.cert_count += 1;

        for i in 0..state.store_count {
            if state.stores[i].store_type == StoreType::IntermediateCA {
                state.stores[i].cert_count += 1;
                break;
            }
        }
    }
}

// ============================================================================
// Store Management
// ============================================================================

/// Get store count
pub fn get_store_count() -> usize {
    CERTMGR_STATE.lock().store_count
}

/// Get store by index
pub fn get_store(index: usize) -> Option<CertStore> {
    let state = CERTMGR_STATE.lock();
    if index < state.store_count {
        Some(state.stores[index])
    } else {
        None
    }
}

/// Get store by type
pub fn get_store_by_type(store_type: StoreType) -> Option<CertStore> {
    let state = CERTMGR_STATE.lock();
    for i in 0..state.store_count {
        if state.stores[i].store_type == store_type {
            return Some(state.stores[i]);
        }
    }
    None
}

/// Select store
pub fn select_store(store_type: StoreType) {
    CERTMGR_STATE.lock().selected_store = store_type;
}

/// Get selected store
pub fn get_selected_store() -> StoreType {
    CERTMGR_STATE.lock().selected_store
}

// ============================================================================
// Certificate Management
// ============================================================================

/// Get certificate count in store
pub fn get_cert_count(store_type: StoreType) -> usize {
    let state = CERTMGR_STATE.lock();
    state.certs[..state.cert_count]
        .iter()
        .filter(|c| c.store == store_type)
        .count()
}

/// Get certificates in store
pub fn get_certs_in_store(store_type: StoreType, buffer: &mut [CertificateEntry]) -> usize {
    let state = CERTMGR_STATE.lock();
    let mut count = 0;
    for i in 0..state.cert_count {
        if state.certs[i].store == store_type {
            if count < buffer.len() {
                buffer[count] = state.certs[i];
                count += 1;
            }
        }
    }
    count
}

/// Get certificate by ID
pub fn get_cert(cert_id: u32) -> Option<CertificateEntry> {
    let state = CERTMGR_STATE.lock();
    for i in 0..state.cert_count {
        if state.certs[i].cert_id == cert_id {
            return Some(state.certs[i]);
        }
    }
    None
}

/// Select certificate
pub fn select_cert(cert_id: u32) {
    CERTMGR_STATE.lock().selected_cert = cert_id;
}

/// Get selected certificate
pub fn get_selected_cert() -> u32 {
    CERTMGR_STATE.lock().selected_cert
}

/// Delete certificate
pub fn delete_cert(cert_id: u32) -> bool {
    let mut state = CERTMGR_STATE.lock();

    let mut found_index = None;
    let mut store_type = StoreType::Personal;
    for i in 0..state.cert_count {
        if state.certs[i].cert_id == cert_id {
            found_index = Some(i);
            store_type = state.certs[i].store;
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..state.cert_count - 1 {
            state.certs[i] = state.certs[i + 1];
        }
        state.cert_count -= 1;

        // Update store count
        for i in 0..state.store_count {
            if state.stores[i].store_type == store_type && state.stores[i].cert_count > 0 {
                state.stores[i].cert_count -= 1;
                break;
            }
        }
        true
    } else {
        false
    }
}

/// Move certificate to different store
pub fn move_cert(cert_id: u32, new_store: StoreType) -> bool {
    let mut state = CERTMGR_STATE.lock();

    let mut old_store = StoreType::Personal;
    let mut found = false;

    for i in 0..state.cert_count {
        if state.certs[i].cert_id == cert_id {
            old_store = state.certs[i].store;
            state.certs[i].store = new_store;
            found = true;
            break;
        }
    }

    if found {
        // Update old store count
        for i in 0..state.store_count {
            if state.stores[i].store_type == old_store && state.stores[i].cert_count > 0 {
                state.stores[i].cert_count -= 1;
                break;
            }
        }
        // Update new store count
        for i in 0..state.store_count {
            if state.stores[i].store_type == new_store {
                state.stores[i].cert_count += 1;
                break;
            }
        }
    }
    found
}

// ============================================================================
// Import/Export
// ============================================================================

/// Certificate file format
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CertFormat {
    /// DER encoded binary X.509
    #[default]
    DerBinary = 0,
    /// Base-64 encoded X.509
    Base64 = 1,
    /// PKCS #7 Certificates
    Pkcs7 = 2,
    /// Personal Information Exchange (PKCS #12)
    Pfx = 3,
}

/// Import certificate (stub)
pub fn import_cert(_path: &[u8], _store: StoreType, _format: CertFormat) -> Option<u32> {
    let mut state = CERTMGR_STATE.lock();

    if state.cert_count >= MAX_CERTS {
        return None;
    }

    let cert_id = state.next_cert_id;
    state.next_cert_id += 1;

    let mut cert = CertificateEntry::new();
    cert.cert_id = cert_id;
    cert.store = _store;
    cert.set_issued_to(b"Imported Certificate");
    cert.set_issued_by(b"Unknown CA");
    cert.expiration = 1893456000;

    let idx = state.cert_count;
    state.certs[idx] = cert;
    state.cert_count += 1;

    // Update store count
    for i in 0..state.store_count {
        if state.stores[i].store_type == _store {
            state.stores[i].cert_count += 1;
            break;
        }
    }

    CERTS_IMPORTED.fetch_add(1, Ordering::Relaxed);
    Some(cert_id)
}

/// Export certificate (stub)
pub fn export_cert(_cert_id: u32, _path: &[u8], _format: CertFormat) -> bool {
    CERTS_EXPORTED.fetch_add(1, Ordering::Relaxed);
    true
}

/// Request new certificate (stub - would contact CA)
pub fn request_cert(_template: &[u8]) -> bool {
    // Would initiate certificate enrollment
    true
}

// ============================================================================
// View Options
// ============================================================================

/// Set purpose filter
pub fn set_purpose_filter(purpose: CertPurpose) {
    CERTMGR_STATE.lock().filter_purpose = purpose;
}

/// Get purpose filter
pub fn get_purpose_filter() -> CertPurpose {
    CERTMGR_STATE.lock().filter_purpose
}

/// Set show archived
pub fn set_show_archived(show: bool) {
    CERTMGR_STATE.lock().show_archived = show;
}

/// Set show physical stores
pub fn set_show_physical(show: bool) {
    CERTMGR_STATE.lock().show_physical = show;
}

// ============================================================================
// Certificate Verification
// ============================================================================

/// Verification result
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerifyResult {
    /// Certificate is valid
    #[default]
    Valid = 0,
    /// Certificate is expired
    Expired = 1,
    /// Certificate is not yet valid
    NotYetValid = 2,
    /// Certificate is revoked
    Revoked = 3,
    /// Untrusted root
    UntrustedRoot = 4,
    /// Invalid signature
    InvalidSignature = 5,
    /// Purpose mismatch
    PurposeMismatch = 6,
}

/// Verify certificate (stub)
pub fn verify_cert(cert_id: u32) -> VerifyResult {
    let state = CERTMGR_STATE.lock();
    for i in 0..state.cert_count {
        if state.certs[i].cert_id == cert_id {
            if state.certs[i].is_expired {
                return VerifyResult::Expired;
            }
            return VerifyResult::Valid;
        }
    }
    VerifyResult::UntrustedRoot
}

// ============================================================================
// Statistics
// ============================================================================

/// Certificate Manager statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct CertMgrStats {
    pub initialized: bool,
    pub store_count: usize,
    pub cert_count: usize,
    pub certs_imported: u32,
    pub certs_exported: u32,
}

/// Get Certificate Manager statistics
pub fn get_stats() -> CertMgrStats {
    let state = CERTMGR_STATE.lock();
    CertMgrStats {
        initialized: CERTMGR_INITIALIZED.load(Ordering::Relaxed),
        store_count: state.store_count,
        cert_count: state.cert_count,
        certs_imported: CERTS_IMPORTED.load(Ordering::Relaxed),
        certs_exported: CERTS_EXPORTED.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Certificate Manager dialog handle
pub type HCERTMGRDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Certificate Manager dialog
pub fn create_certmgr_dialog(_parent: super::super::HWND) -> HCERTMGRDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
