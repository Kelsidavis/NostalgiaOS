//! Software Restriction Policies
//!
//! Windows Server 2003 Software Restriction Policies implementation.
//! Provides application execution control.
//!
//! # Features
//!
//! - Security levels (Disallowed, Unrestricted)
//! - Path rules
//! - Hash rules
//! - Certificate rules
//! - Internet zone rules
//! - Designated file types
//!
//! # References
//!
//! Based on Windows Server 2003 Software Restriction Policies

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::UserHandle;
use bitflags::bitflags;

/// HWND type alias
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum path rules
const MAX_PATH_RULES: usize = 128;

/// Maximum hash rules
const MAX_HASH_RULES: usize = 64;

/// Maximum certificate rules
const MAX_CERT_RULES: usize = 32;

/// Maximum zone rules
const MAX_ZONE_RULES: usize = 8;

/// Maximum designated file types
const MAX_FILE_TYPES: usize = 64;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Maximum description length
const MAX_DESC_LEN: usize = 256;

/// Hash size (SHA-1 = 20 bytes, MD5 = 16 bytes)
const MAX_HASH_LEN: usize = 32;

// ============================================================================
// Security Level
// ============================================================================

/// Security level for software restriction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum SecurityLevel {
    /// Disallowed - software cannot run
    Disallowed = 0,
    /// Basic User - run as normal user (not admin)
    BasicUser = 0x10000,
    /// Constrained - limited privileges
    Constrained = 0x20000,
    /// Unrestricted - software can run
    #[default]
    Unrestricted = 0x40000,
}

impl SecurityLevel {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Disallowed => "Disallowed",
            Self::BasicUser => "Basic User",
            Self::Constrained => "Constrained",
            Self::Unrestricted => "Unrestricted",
        }
    }
}

// ============================================================================
// Rule Type
// ============================================================================

/// Software restriction rule type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum RuleType {
    /// Path-based rule
    #[default]
    Path = 0,
    /// Hash-based rule
    Hash = 1,
    /// Certificate-based rule
    Certificate = 2,
    /// Internet zone rule
    Zone = 3,
}

impl RuleType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Path => "Path",
            Self::Hash => "Hash",
            Self::Certificate => "Certificate",
            Self::Zone => "Internet Zone",
        }
    }
}

// ============================================================================
// Hash Algorithm
// ============================================================================

/// Hash algorithm for hash rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum HashAlgorithm {
    /// MD5 (16 bytes)
    #[default]
    Md5 = 0,
    /// SHA-1 (20 bytes)
    Sha1 = 1,
    /// SHA-256 (32 bytes) - Windows XP SP2+
    Sha256 = 2,
}

impl HashAlgorithm {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
        }
    }

    pub const fn hash_len(&self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

// ============================================================================
// Internet Zone
// ============================================================================

/// Internet Explorer security zone
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum InternetZone {
    /// Local Machine
    LocalMachine = 0,
    /// Local Intranet
    LocalIntranet = 1,
    /// Trusted Sites
    TrustedSites = 2,
    /// Internet
    #[default]
    Internet = 3,
    /// Restricted Sites
    RestrictedSites = 4,
}

impl InternetZone {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LocalMachine => "Local Machine",
            Self::LocalIntranet => "Local Intranet",
            Self::TrustedSites => "Trusted Sites",
            Self::Internet => "Internet",
            Self::RestrictedSites => "Restricted Sites",
        }
    }
}

bitflags! {
    /// Software restriction policy flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct PolicyFlags: u32 {
        /// Policy is enabled
        const ENABLED = 0x0001;
        /// Apply to DLLs (slower but more secure)
        const APPLY_TO_DLLS = 0x0002;
        /// Skip administrators
        const SKIP_ADMINISTRATORS = 0x0004;
        /// Enforce certificate rules
        const ENFORCE_CERT_RULES = 0x0008;
    }
}

// ============================================================================
// Path Rule
// ============================================================================

/// Path-based software restriction rule
#[derive(Clone, Copy)]
pub struct PathRule {
    /// Rule in use
    pub in_use: bool,
    /// Rule GUID (for GPO tracking)
    pub guid: [u8; 38],
    /// GUID length
    pub guid_len: usize,
    /// Path pattern (supports wildcards)
    pub path: [u8; MAX_PATH_LEN],
    /// Path length
    pub path_len: usize,
    /// Security level
    pub level: SecurityLevel,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub desc_len: usize,
    /// Last modified timestamp
    pub last_modified: u64,
}

impl PathRule {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            guid: [0u8; 38],
            guid_len: 0,
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            level: SecurityLevel::Unrestricted,
            description: [0u8; MAX_DESC_LEN],
            desc_len: 0,
            last_modified: 0,
        }
    }

    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_PATH_LEN);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_DESC_LEN);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.desc_len = len;
    }

    /// Check if path matches this rule
    pub fn matches(&self, test_path: &[u8]) -> bool {
        // Simple wildcard matching
        if self.path_len == 0 || test_path.is_empty() {
            return false;
        }

        // Check for exact match first
        if self.path[..self.path_len] == test_path[..test_path.len().min(self.path_len)] {
            return true;
        }

        // Check for wildcard at end (e.g., "C:\Windows\*")
        if self.path_len > 0 && self.path[self.path_len - 1] == b'*' {
            let prefix = &self.path[..self.path_len - 1];
            if test_path.len() >= prefix.len() && test_path[..prefix.len()] == *prefix {
                return true;
            }
        }

        false
    }
}

// ============================================================================
// Hash Rule
// ============================================================================

/// Hash-based software restriction rule
#[derive(Clone, Copy)]
pub struct HashRule {
    /// Rule in use
    pub in_use: bool,
    /// Rule GUID
    pub guid: [u8; 38],
    /// GUID length
    pub guid_len: usize,
    /// Hash value
    pub hash: [u8; MAX_HASH_LEN],
    /// Hash length
    pub hash_len: usize,
    /// Hash algorithm
    pub algorithm: HashAlgorithm,
    /// Security level
    pub level: SecurityLevel,
    /// Friendly name (usually filename)
    pub friendly_name: [u8; 64],
    /// Name length
    pub name_len: usize,
    /// File size (for additional verification)
    pub file_size: u64,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub desc_len: usize,
    /// Last modified timestamp
    pub last_modified: u64,
}

impl HashRule {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            guid: [0u8; 38],
            guid_len: 0,
            hash: [0u8; MAX_HASH_LEN],
            hash_len: 0,
            algorithm: HashAlgorithm::Sha1,
            level: SecurityLevel::Unrestricted,
            friendly_name: [0u8; 64],
            name_len: 0,
            file_size: 0,
            description: [0u8; MAX_DESC_LEN],
            desc_len: 0,
            last_modified: 0,
        }
    }

    pub fn set_hash(&mut self, hash: &[u8], algorithm: HashAlgorithm) {
        let len = hash.len().min(algorithm.hash_len());
        self.hash[..len].copy_from_slice(&hash[..len]);
        self.hash_len = len;
        self.algorithm = algorithm;
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(64);
        self.friendly_name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Check if hash matches this rule
    pub fn matches(&self, test_hash: &[u8]) -> bool {
        if test_hash.len() != self.hash_len {
            return false;
        }
        self.hash[..self.hash_len] == test_hash[..self.hash_len]
    }
}

// ============================================================================
// Certificate Rule
// ============================================================================

/// Certificate-based software restriction rule
#[derive(Clone, Copy)]
pub struct CertificateRule {
    /// Rule in use
    pub in_use: bool,
    /// Rule GUID
    pub guid: [u8; 38],
    /// GUID length
    pub guid_len: usize,
    /// Certificate thumbprint (SHA-1)
    pub thumbprint: [u8; 20],
    /// Security level
    pub level: SecurityLevel,
    /// Subject name
    pub subject: [u8; 128],
    /// Subject length
    pub subject_len: usize,
    /// Issuer name
    pub issuer: [u8; 128],
    /// Issuer length
    pub issuer_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub desc_len: usize,
    /// Last modified timestamp
    pub last_modified: u64,
}

impl CertificateRule {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            guid: [0u8; 38],
            guid_len: 0,
            thumbprint: [0u8; 20],
            level: SecurityLevel::Unrestricted,
            subject: [0u8; 128],
            subject_len: 0,
            issuer: [0u8; 128],
            issuer_len: 0,
            description: [0u8; MAX_DESC_LEN],
            desc_len: 0,
            last_modified: 0,
        }
    }

    pub fn set_thumbprint(&mut self, thumbprint: &[u8]) {
        let len = thumbprint.len().min(20);
        self.thumbprint[..len].copy_from_slice(&thumbprint[..len]);
    }

    pub fn set_subject(&mut self, subject: &[u8]) {
        let len = subject.len().min(128);
        self.subject[..len].copy_from_slice(&subject[..len]);
        self.subject_len = len;
    }
}

// ============================================================================
// Zone Rule
// ============================================================================

/// Internet zone software restriction rule
#[derive(Clone, Copy)]
pub struct ZoneRule {
    /// Rule in use
    pub in_use: bool,
    /// Zone
    pub zone: InternetZone,
    /// Security level
    pub level: SecurityLevel,
    /// Last modified timestamp
    pub last_modified: u64,
}

impl ZoneRule {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            zone: InternetZone::Internet,
            level: SecurityLevel::Unrestricted,
            last_modified: 0,
        }
    }
}

// ============================================================================
// File Type
// ============================================================================

/// Designated executable file type
#[derive(Clone, Copy)]
pub struct DesignatedFileType {
    /// Type in use
    pub in_use: bool,
    /// File extension (without dot)
    pub extension: [u8; 16],
    /// Extension length
    pub ext_len: usize,
}

impl DesignatedFileType {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            extension: [0u8; 16],
            ext_len: 0,
        }
    }

    pub fn set_extension(&mut self, ext: &[u8]) {
        let len = ext.len().min(16);
        self.extension[..len].copy_from_slice(&ext[..len]);
        self.ext_len = len;
    }
}

// ============================================================================
// SRP State
// ============================================================================

/// Software Restriction Policies state
struct SrpState {
    /// Policy flags
    pub flags: PolicyFlags,
    /// Default security level
    pub default_level: SecurityLevel,
    /// Path rules
    pub path_rules: [PathRule; MAX_PATH_RULES],
    /// Path rule count
    pub path_rule_count: usize,
    /// Hash rules
    pub hash_rules: [HashRule; MAX_HASH_RULES],
    /// Hash rule count
    pub hash_rule_count: usize,
    /// Certificate rules
    pub cert_rules: [CertificateRule; MAX_CERT_RULES],
    /// Cert rule count
    pub cert_rule_count: usize,
    /// Zone rules
    pub zone_rules: [ZoneRule; MAX_ZONE_RULES],
    /// Zone rule count
    pub zone_rule_count: usize,
    /// Designated file types
    pub file_types: [DesignatedFileType; MAX_FILE_TYPES],
    /// File type count
    pub file_type_count: usize,
    /// Dialog handle
    pub dialog_handle: HWND,
}

impl SrpState {
    pub const fn new() -> Self {
        Self {
            flags: PolicyFlags::empty(),
            default_level: SecurityLevel::Unrestricted,
            path_rules: [const { PathRule::new() }; MAX_PATH_RULES],
            path_rule_count: 0,
            hash_rules: [const { HashRule::new() }; MAX_HASH_RULES],
            hash_rule_count: 0,
            cert_rules: [const { CertificateRule::new() }; MAX_CERT_RULES],
            cert_rule_count: 0,
            zone_rules: [const { ZoneRule::new() }; MAX_ZONE_RULES],
            zone_rule_count: 0,
            file_types: [const { DesignatedFileType::new() }; MAX_FILE_TYPES],
            file_type_count: 0,
            dialog_handle: UserHandle::from_raw(0),
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static SRP_INITIALIZED: AtomicBool = AtomicBool::new(false);
static SRP_STATE: SpinLock<SrpState> = SpinLock::new(SrpState::new());

// Statistics
static RULE_COUNT: AtomicU32 = AtomicU32::new(0);
static CHECK_COUNT: AtomicU64 = AtomicU64::new(0);
static BLOCK_COUNT: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Software Restriction Policies
pub fn init() {
    if SRP_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = SRP_STATE.lock();

    // Set up default designated file types
    let default_types: &[&[u8]] = &[
        b"exe", b"com", b"bat", b"cmd", b"vbs", b"vbe", b"js", b"jse",
        b"wsh", b"wsf", b"scr", b"pif", b"msi", b"msp", b"mst", b"ocx",
    ];

    for (i, ext) in default_types.iter().enumerate() {
        if i >= MAX_FILE_TYPES {
            break;
        }
        let ft = &mut state.file_types[i];
        ft.in_use = true;
        ft.set_extension(ext);
    }
    state.file_type_count = default_types.len().min(MAX_FILE_TYPES);

    // Default zone rules
    state.zone_rules[0].in_use = true;
    state.zone_rules[0].zone = InternetZone::RestrictedSites;
    state.zone_rules[0].level = SecurityLevel::Disallowed;
    state.zone_rule_count = 1;
}

// ============================================================================
// Policy Configuration
// ============================================================================

/// Enable or disable SRP
pub fn set_enabled(enabled: bool) {
    let mut state = SRP_STATE.lock();
    if enabled {
        state.flags |= PolicyFlags::ENABLED;
    } else {
        state.flags &= !PolicyFlags::ENABLED;
    }
}

/// Check if SRP is enabled
pub fn is_enabled() -> bool {
    SRP_STATE.lock().flags.contains(PolicyFlags::ENABLED)
}

/// Set default security level
pub fn set_default_level(level: SecurityLevel) {
    SRP_STATE.lock().default_level = level;
}

/// Get default security level
pub fn get_default_level() -> SecurityLevel {
    SRP_STATE.lock().default_level
}

/// Set policy flags
pub fn set_flags(flags: PolicyFlags) {
    SRP_STATE.lock().flags = flags;
}

/// Get policy flags
pub fn get_flags() -> PolicyFlags {
    SRP_STATE.lock().flags
}

// ============================================================================
// Path Rule Management
// ============================================================================

/// Add a path rule
pub fn add_path_rule(path: &[u8], level: SecurityLevel, description: &[u8]) -> Option<usize> {
    let mut state = SRP_STATE.lock();

    if state.path_rule_count >= MAX_PATH_RULES {
        return None;
    }

    let idx = state.path_rule_count;
    let rule = &mut state.path_rules[idx];
    rule.in_use = true;
    rule.set_path(path);
    rule.level = level;
    rule.set_description(description);

    state.path_rule_count += 1;
    RULE_COUNT.fetch_add(1, Ordering::Relaxed);

    Some(idx)
}

/// Remove a path rule
pub fn remove_path_rule(index: usize) -> bool {
    let mut state = SRP_STATE.lock();

    if index >= MAX_PATH_RULES || !state.path_rules[index].in_use {
        return false;
    }

    state.path_rules[index] = PathRule::new();
    RULE_COUNT.fetch_sub(1, Ordering::Relaxed);
    true
}

/// Get path rule
pub fn get_path_rule(index: usize) -> Option<PathRule> {
    let state = SRP_STATE.lock();
    if index < state.path_rule_count && state.path_rules[index].in_use {
        Some(state.path_rules[index])
    } else {
        None
    }
}

/// Get path rule count
pub fn get_path_rule_count() -> usize {
    SRP_STATE.lock().path_rule_count
}

// ============================================================================
// Hash Rule Management
// ============================================================================

/// Add a hash rule
pub fn add_hash_rule(
    hash: &[u8],
    algorithm: HashAlgorithm,
    level: SecurityLevel,
    friendly_name: &[u8],
    file_size: u64,
) -> Option<usize> {
    let mut state = SRP_STATE.lock();

    if state.hash_rule_count >= MAX_HASH_RULES {
        return None;
    }

    let idx = state.hash_rule_count;
    let rule = &mut state.hash_rules[idx];
    rule.in_use = true;
    rule.set_hash(hash, algorithm);
    rule.level = level;
    rule.set_name(friendly_name);
    rule.file_size = file_size;

    state.hash_rule_count += 1;
    RULE_COUNT.fetch_add(1, Ordering::Relaxed);

    Some(idx)
}

/// Remove a hash rule
pub fn remove_hash_rule(index: usize) -> bool {
    let mut state = SRP_STATE.lock();

    if index >= MAX_HASH_RULES || !state.hash_rules[index].in_use {
        return false;
    }

    state.hash_rules[index] = HashRule::new();
    RULE_COUNT.fetch_sub(1, Ordering::Relaxed);
    true
}

/// Get hash rule
pub fn get_hash_rule(index: usize) -> Option<HashRule> {
    let state = SRP_STATE.lock();
    if index < state.hash_rule_count && state.hash_rules[index].in_use {
        Some(state.hash_rules[index])
    } else {
        None
    }
}

// ============================================================================
// Certificate Rule Management
// ============================================================================

/// Add a certificate rule
pub fn add_cert_rule(
    thumbprint: &[u8],
    level: SecurityLevel,
    subject: &[u8],
) -> Option<usize> {
    let mut state = SRP_STATE.lock();

    if state.cert_rule_count >= MAX_CERT_RULES {
        return None;
    }

    let idx = state.cert_rule_count;
    let rule = &mut state.cert_rules[idx];
    rule.in_use = true;
    rule.set_thumbprint(thumbprint);
    rule.level = level;
    rule.set_subject(subject);

    state.cert_rule_count += 1;
    RULE_COUNT.fetch_add(1, Ordering::Relaxed);

    Some(idx)
}

/// Remove a certificate rule
pub fn remove_cert_rule(index: usize) -> bool {
    let mut state = SRP_STATE.lock();

    if index >= MAX_CERT_RULES || !state.cert_rules[index].in_use {
        return false;
    }

    state.cert_rules[index] = CertificateRule::new();
    RULE_COUNT.fetch_sub(1, Ordering::Relaxed);
    true
}

// ============================================================================
// Zone Rule Management
// ============================================================================

/// Set zone rule
pub fn set_zone_rule(zone: InternetZone, level: SecurityLevel) -> bool {
    let mut state = SRP_STATE.lock();

    // Find existing or add new
    for rule in state.zone_rules.iter_mut() {
        if rule.in_use && rule.zone == zone {
            rule.level = level;
            return true;
        }
    }

    // Add new
    if state.zone_rule_count >= MAX_ZONE_RULES {
        return false;
    }

    let idx = state.zone_rule_count;
    state.zone_rules[idx].in_use = true;
    state.zone_rules[idx].zone = zone;
    state.zone_rules[idx].level = level;
    state.zone_rule_count += 1;
    RULE_COUNT.fetch_add(1, Ordering::Relaxed);

    true
}

/// Get zone rule
pub fn get_zone_rule(zone: InternetZone) -> Option<SecurityLevel> {
    let state = SRP_STATE.lock();
    for rule in state.zone_rules.iter() {
        if rule.in_use && rule.zone == zone {
            return Some(rule.level);
        }
    }
    None
}

// ============================================================================
// File Type Management
// ============================================================================

/// Add a designated file type
pub fn add_file_type(extension: &[u8]) -> bool {
    let mut state = SRP_STATE.lock();

    // Check if already exists
    for ft in state.file_types.iter() {
        if ft.in_use && ft.extension[..ft.ext_len] == extension[..extension.len().min(ft.ext_len)] {
            return true; // Already exists
        }
    }

    if state.file_type_count >= MAX_FILE_TYPES {
        return false;
    }

    let idx = state.file_type_count;
    state.file_types[idx].in_use = true;
    state.file_types[idx].set_extension(extension);
    state.file_type_count += 1;

    true
}

/// Remove a designated file type
pub fn remove_file_type(extension: &[u8]) -> bool {
    let mut state = SRP_STATE.lock();

    for ft in state.file_types.iter_mut() {
        if ft.in_use && ft.extension[..ft.ext_len] == extension[..extension.len().min(ft.ext_len)] {
            *ft = DesignatedFileType::new();
            return true;
        }
    }
    false
}

/// Check if file type is designated
pub fn is_designated_type(extension: &[u8]) -> bool {
    let state = SRP_STATE.lock();
    for ft in state.file_types.iter() {
        if ft.in_use && ft.extension[..ft.ext_len] == extension[..extension.len().min(ft.ext_len)] {
            return true;
        }
    }
    false
}

// ============================================================================
// Policy Evaluation
// ============================================================================

/// Check software restriction for a path
pub fn check_path(path: &[u8]) -> SecurityLevel {
    CHECK_COUNT.fetch_add(1, Ordering::Relaxed);

    let state = SRP_STATE.lock();

    // If not enabled, allow everything
    if !state.flags.contains(PolicyFlags::ENABLED) {
        return SecurityLevel::Unrestricted;
    }

    // Check path rules (most specific wins)
    let mut best_match: Option<SecurityLevel> = None;
    let mut best_match_len = 0usize;

    for rule in state.path_rules.iter() {
        if rule.in_use && rule.matches(path) {
            if rule.path_len > best_match_len {
                best_match = Some(rule.level);
                best_match_len = rule.path_len;
            }
        }
    }

    if let Some(level) = best_match {
        if level == SecurityLevel::Disallowed {
            BLOCK_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        return level;
    }

    // No rule matched, use default
    state.default_level
}

/// Check software restriction for a hash
pub fn check_hash(hash: &[u8]) -> SecurityLevel {
    CHECK_COUNT.fetch_add(1, Ordering::Relaxed);

    let state = SRP_STATE.lock();

    if !state.flags.contains(PolicyFlags::ENABLED) {
        return SecurityLevel::Unrestricted;
    }

    for rule in state.hash_rules.iter() {
        if rule.in_use && rule.matches(hash) {
            if rule.level == SecurityLevel::Disallowed {
                BLOCK_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            return rule.level;
        }
    }

    state.default_level
}

/// Check software restriction for an internet zone
pub fn check_zone(zone: InternetZone) -> SecurityLevel {
    CHECK_COUNT.fetch_add(1, Ordering::Relaxed);

    let state = SRP_STATE.lock();

    if !state.flags.contains(PolicyFlags::ENABLED) {
        return SecurityLevel::Unrestricted;
    }

    for rule in state.zone_rules.iter() {
        if rule.in_use && rule.zone == zone {
            if rule.level == SecurityLevel::Disallowed {
                BLOCK_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            return rule.level;
        }
    }

    state.default_level
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_statistics() -> (u32, u64, u64) {
    (
        RULE_COUNT.load(Ordering::Relaxed),
        CHECK_COUNT.load(Ordering::Relaxed),
        BLOCK_COUNT.load(Ordering::Relaxed),
    )
}

// ============================================================================
// Dialog Functions
// ============================================================================

/// Show SRP editor
pub fn show_dialog(_parent: HWND) -> HWND {
    let mut state = SRP_STATE.lock();
    let handle = UserHandle::from_raw(0x5301);
    state.dialog_handle = handle;
    handle
}

/// Show new path rule dialog
pub fn show_new_path_rule_dialog() -> HWND {
    UserHandle::from_raw(0x5302)
}

/// Show new hash rule dialog
pub fn show_new_hash_rule_dialog() -> HWND {
    UserHandle::from_raw(0x5303)
}

/// Show new certificate rule dialog
pub fn show_new_cert_rule_dialog() -> HWND {
    UserHandle::from_raw(0x5304)
}

/// Show designated file types dialog
pub fn show_file_types_dialog() -> HWND {
    UserHandle::from_raw(0x5305)
}

/// Show enforcement properties
pub fn show_enforcement_dialog() -> HWND {
    UserHandle::from_raw(0x5306)
}

/// Show trusted publishers
pub fn show_trusted_publishers_dialog() -> HWND {
    UserHandle::from_raw(0x5307)
}

/// Close dialog
pub fn close_dialog() {
    let mut state = SRP_STATE.lock();
    state.dialog_handle = UserHandle::from_raw(0);
}
