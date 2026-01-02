//! Active Directory Domains and Trusts (domain.msc) implementation
//!
//! Provides management of domain and forest trusts, domain functional
//! levels, UPN suffixes, and operations master roles.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Local type alias for window handles
type HWND = UserHandle;

/// Maximum domains
const MAX_DOMAINS: usize = 32;

/// Maximum trusts per domain
const MAX_TRUSTS: usize = 32;

/// Maximum UPN suffixes
const MAX_UPN_SUFFIXES: usize = 16;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum DN length
const MAX_DN_LEN: usize = 256;

/// Domain functional level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum DomainFunctionalLevel {
    /// Windows 2000 mixed mode
    Windows2000Mixed = 0,
    /// Windows 2000 native mode
    Windows2000Native = 1,
    /// Windows Server 2003 interim
    WindowsServer2003Interim = 2,
    /// Windows Server 2003
    WindowsServer2003 = 3,
}

impl DomainFunctionalLevel {
    /// Create new domain functional level
    pub const fn new() -> Self {
        Self::Windows2000Mixed
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Windows2000Mixed => "Windows 2000 mixed",
            Self::Windows2000Native => "Windows 2000 native",
            Self::WindowsServer2003Interim => "Windows Server 2003 interim",
            Self::WindowsServer2003 => "Windows Server 2003",
        }
    }

    /// Can be raised to this level
    pub fn can_raise_to(&self, target: Self) -> bool {
        target > *self
    }
}

impl Default for DomainFunctionalLevel {
    fn default() -> Self {
        Self::new()
    }
}

/// Forest functional level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ForestFunctionalLevel {
    /// Windows 2000
    Windows2000 = 0,
    /// Windows Server 2003 interim
    WindowsServer2003Interim = 1,
    /// Windows Server 2003
    WindowsServer2003 = 2,
}

impl ForestFunctionalLevel {
    /// Create new forest functional level
    pub const fn new() -> Self {
        Self::Windows2000
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Windows2000 => "Windows 2000",
            Self::WindowsServer2003Interim => "Windows Server 2003 interim",
            Self::WindowsServer2003 => "Windows Server 2003",
        }
    }
}

impl Default for ForestFunctionalLevel {
    fn default() -> Self {
        Self::new()
    }
}

/// Trust direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TrustDirection {
    /// Disabled trust
    Disabled = 0,
    /// Inbound trust (trusted domain trusts this domain)
    Inbound = 1,
    /// Outbound trust (this domain trusts trusted domain)
    Outbound = 2,
    /// Bidirectional trust
    Bidirectional = 3,
}

impl TrustDirection {
    /// Create new trust direction
    pub const fn new() -> Self {
        Self::Disabled
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Disabled => "Disabled",
            Self::Inbound => "Incoming",
            Self::Outbound => "Outgoing",
            Self::Bidirectional => "Two-way",
        }
    }
}

impl Default for TrustDirection {
    fn default() -> Self {
        Self::new()
    }
}

/// Trust type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TrustType {
    /// Downlevel trust (Windows NT 4.0)
    Downlevel = 1,
    /// Uplevel trust (Windows 2000+)
    Uplevel = 2,
    /// MIT Kerberos realm trust
    Mit = 3,
    /// DCE trust
    Dce = 4,
}

impl TrustType {
    /// Create new trust type
    pub const fn new() -> Self {
        Self::Uplevel
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Downlevel => "Windows NT",
            Self::Uplevel => "Windows",
            Self::Mit => "Kerberos Realm",
            Self::Dce => "DCE",
        }
    }
}

impl Default for TrustType {
    fn default() -> Self {
        Self::new()
    }
}

/// Trust attributes
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TrustAttributes: u32 {
        /// Non-transitive trust
        const NON_TRANSITIVE = 0x00000001;
        /// Uplevel clients only
        const UPLEVEL_ONLY = 0x00000002;
        /// Quarantined domain (SID filtering)
        const QUARANTINED_DOMAIN = 0x00000004;
        /// Forest trust
        const FOREST_TRANSITIVE = 0x00000008;
        /// Cross-organization trust
        const CROSS_ORGANIZATION = 0x00000010;
        /// Within same forest
        const WITHIN_FOREST = 0x00000020;
        /// Treat as external trust
        const TREAT_AS_EXTERNAL = 0x00000040;
        /// Use RC4 encryption
        const USES_RC4_ENCRYPTION = 0x00000080;
    }
}

impl Default for TrustAttributes {
    fn default() -> Self {
        Self::empty()
    }
}

/// Operations Master (FSMO) role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FsmoRole {
    /// Schema Master (forest-wide)
    SchemaMaster = 0,
    /// Domain Naming Master (forest-wide)
    DomainNamingMaster = 1,
    /// PDC Emulator (domain-wide)
    PdcEmulator = 2,
    /// RID Master (domain-wide)
    RidMaster = 3,
    /// Infrastructure Master (domain-wide)
    InfrastructureMaster = 4,
}

impl FsmoRole {
    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::SchemaMaster => "Schema master",
            Self::DomainNamingMaster => "Domain naming master",
            Self::PdcEmulator => "PDC emulator",
            Self::RidMaster => "RID master",
            Self::InfrastructureMaster => "Infrastructure master",
        }
    }

    /// Is forest-wide role
    pub fn is_forest_role(&self) -> bool {
        matches!(self, Self::SchemaMaster | Self::DomainNamingMaster)
    }
}

/// Trust relationship
#[derive(Clone)]
pub struct Trust {
    /// Trust ID
    pub trust_id: u32,
    /// Trusted domain name
    pub trusted_domain: [u8; MAX_NAME_LEN],
    /// Trusted domain length
    pub trusted_len: usize,
    /// Trusted domain flat name (NetBIOS)
    pub flat_name: [u8; 16],
    /// Flat name length
    pub flat_len: usize,
    /// Trust direction
    pub direction: TrustDirection,
    /// Trust type
    pub trust_type: TrustType,
    /// Trust attributes
    pub attributes: TrustAttributes,
    /// Is transitive
    pub transitive: bool,
    /// SID filtering enabled
    pub sid_filtering: bool,
    /// Selective authentication
    pub selective_auth: bool,
    /// Reserved
    pub reserved: u8,
    /// Creation time
    pub created: u64,
    /// Last verified time
    pub last_verified: u64,
    /// Trust partner SID
    pub trust_sid: [u8; 28],
    /// SID length
    pub sid_len: usize,
    /// In use flag
    pub in_use: bool,
}

impl Trust {
    /// Create new trust
    pub const fn new() -> Self {
        Self {
            trust_id: 0,
            trusted_domain: [0; MAX_NAME_LEN],
            trusted_len: 0,
            flat_name: [0; 16],
            flat_len: 0,
            direction: TrustDirection::Disabled,
            trust_type: TrustType::Uplevel,
            attributes: TrustAttributes::empty(),
            transitive: true,
            sid_filtering: false,
            selective_auth: false,
            reserved: 0,
            created: 0,
            last_verified: 0,
            trust_sid: [0; 28],
            sid_len: 0,
            in_use: false,
        }
    }

    /// Set trusted domain name
    pub fn set_trusted_domain(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.trusted_domain[..len].copy_from_slice(&name[..len]);
        self.trusted_len = len;
    }

    /// Set flat name
    pub fn set_flat_name(&mut self, name: &[u8]) {
        let len = name.len().min(16);
        self.flat_name[..len].copy_from_slice(&name[..len]);
        self.flat_len = len;
    }

    /// Get trusted domain name
    pub fn get_trusted_domain(&self) -> &[u8] {
        &self.trusted_domain[..self.trusted_len]
    }
}

impl Default for Trust {
    fn default() -> Self {
        Self::new()
    }
}

/// Domain
#[derive(Clone)]
pub struct Domain {
    /// Domain ID
    pub domain_id: u32,
    /// Domain DNS name
    pub dns_name: [u8; MAX_NAME_LEN],
    /// DNS name length
    pub dns_len: usize,
    /// NetBIOS name
    pub netbios_name: [u8; 16],
    /// NetBIOS name length
    pub netbios_len: usize,
    /// Domain SID
    pub domain_sid: [u8; 28],
    /// SID length
    pub sid_len: usize,
    /// Domain DN
    pub dn: [u8; MAX_DN_LEN],
    /// DN length
    pub dn_len: usize,
    /// Domain functional level
    pub functional_level: DomainFunctionalLevel,
    /// Is forest root
    pub is_forest_root: bool,
    /// Reserved
    pub reserved: [u8; 3],
    /// Parent domain ID (0 if root)
    pub parent_id: u32,
    /// PDC emulator holder
    pub pdc_emulator: [u8; MAX_NAME_LEN],
    /// PDC emulator name length
    pub pdc_len: usize,
    /// RID master holder
    pub rid_master: [u8; MAX_NAME_LEN],
    /// RID master name length
    pub rid_len: usize,
    /// Infrastructure master holder
    pub infra_master: [u8; MAX_NAME_LEN],
    /// Infrastructure master name length
    pub infra_len: usize,
    /// Trusts
    pub trusts: [Trust; MAX_TRUSTS],
    /// Trust count
    pub trust_count: usize,
    /// In use flag
    pub in_use: bool,
}

impl Domain {
    /// Create new domain
    pub const fn new() -> Self {
        Self {
            domain_id: 0,
            dns_name: [0; MAX_NAME_LEN],
            dns_len: 0,
            netbios_name: [0; 16],
            netbios_len: 0,
            domain_sid: [0; 28],
            sid_len: 0,
            dn: [0; MAX_DN_LEN],
            dn_len: 0,
            functional_level: DomainFunctionalLevel::Windows2000Mixed,
            is_forest_root: false,
            reserved: [0; 3],
            parent_id: 0,
            pdc_emulator: [0; MAX_NAME_LEN],
            pdc_len: 0,
            rid_master: [0; MAX_NAME_LEN],
            rid_len: 0,
            infra_master: [0; MAX_NAME_LEN],
            infra_len: 0,
            trusts: [const { Trust::new() }; MAX_TRUSTS],
            trust_count: 0,
            in_use: false,
        }
    }

    /// Set DNS name
    pub fn set_dns_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.dns_name[..len].copy_from_slice(&name[..len]);
        self.dns_len = len;
    }

    /// Set NetBIOS name
    pub fn set_netbios_name(&mut self, name: &[u8]) {
        let len = name.len().min(16);
        self.netbios_name[..len].copy_from_slice(&name[..len]);
        self.netbios_len = len;
    }

    /// Get DNS name
    pub fn get_dns_name(&self) -> &[u8] {
        &self.dns_name[..self.dns_len]
    }

    /// Set FSMO role holder
    pub fn set_fsmo_holder(&mut self, role: FsmoRole, holder: &[u8]) {
        let len = holder.len().min(MAX_NAME_LEN);
        match role {
            FsmoRole::PdcEmulator => {
                self.pdc_emulator[..len].copy_from_slice(&holder[..len]);
                self.pdc_len = len;
            }
            FsmoRole::RidMaster => {
                self.rid_master[..len].copy_from_slice(&holder[..len]);
                self.rid_len = len;
            }
            FsmoRole::InfrastructureMaster => {
                self.infra_master[..len].copy_from_slice(&holder[..len]);
                self.infra_len = len;
            }
            _ => {}
        }
    }

    /// Find trust by trusted domain name
    pub fn find_trust(&self, domain_name: &[u8]) -> Option<usize> {
        for (i, trust) in self.trusts.iter().enumerate() {
            if trust.in_use && &trust.trusted_domain[..trust.trusted_len] == domain_name {
                return Some(i);
            }
        }
        None
    }
}

impl Default for Domain {
    fn default() -> Self {
        Self::new()
    }
}

/// Forest information
#[derive(Clone)]
pub struct Forest {
    /// Forest name (root domain DNS name)
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Forest functional level
    pub functional_level: ForestFunctionalLevel,
    /// Schema master holder
    pub schema_master: [u8; MAX_NAME_LEN],
    /// Schema master name length
    pub schema_len: usize,
    /// Domain naming master holder
    pub naming_master: [u8; MAX_NAME_LEN],
    /// Domain naming master name length
    pub naming_len: usize,
    /// UPN suffixes
    pub upn_suffixes: [[u8; MAX_NAME_LEN]; MAX_UPN_SUFFIXES],
    /// UPN suffix lengths
    pub upn_lens: [usize; MAX_UPN_SUFFIXES],
    /// UPN suffix count
    pub upn_count: usize,
    /// SPN suffixes
    pub spn_suffixes: [[u8; MAX_NAME_LEN]; MAX_UPN_SUFFIXES],
    /// SPN suffix lengths
    pub spn_lens: [usize; MAX_UPN_SUFFIXES],
    /// SPN suffix count
    pub spn_count: usize,
}

impl Forest {
    /// Create new forest
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            functional_level: ForestFunctionalLevel::Windows2000,
            schema_master: [0; MAX_NAME_LEN],
            schema_len: 0,
            naming_master: [0; MAX_NAME_LEN],
            naming_len: 0,
            upn_suffixes: [[0; MAX_NAME_LEN]; MAX_UPN_SUFFIXES],
            upn_lens: [0; MAX_UPN_SUFFIXES],
            upn_count: 0,
            spn_suffixes: [[0; MAX_NAME_LEN]; MAX_UPN_SUFFIXES],
            spn_lens: [0; MAX_UPN_SUFFIXES],
            spn_count: 0,
        }
    }

    /// Set forest name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Set FSMO role holder
    pub fn set_fsmo_holder(&mut self, role: FsmoRole, holder: &[u8]) {
        let len = holder.len().min(MAX_NAME_LEN);
        match role {
            FsmoRole::SchemaMaster => {
                self.schema_master[..len].copy_from_slice(&holder[..len]);
                self.schema_len = len;
            }
            FsmoRole::DomainNamingMaster => {
                self.naming_master[..len].copy_from_slice(&holder[..len]);
                self.naming_len = len;
            }
            _ => {}
        }
    }

    /// Add UPN suffix
    pub fn add_upn_suffix(&mut self, suffix: &[u8]) -> bool {
        if self.upn_count >= MAX_UPN_SUFFIXES {
            return false;
        }
        let len = suffix.len().min(MAX_NAME_LEN);
        self.upn_suffixes[self.upn_count][..len].copy_from_slice(&suffix[..len]);
        self.upn_lens[self.upn_count] = len;
        self.upn_count += 1;
        true
    }
}

impl Default for Forest {
    fn default() -> Self {
        Self::new()
    }
}

/// AD Domains and Trusts state
pub struct AdDomState {
    /// Forest
    pub forest: Forest,
    /// Domains
    pub domains: [Domain; MAX_DOMAINS],
    /// Domain count
    pub domain_count: usize,
    /// Next ID
    pub next_id: u32,
    /// Connected
    pub connected: bool,
    /// Reserved
    pub reserved: [u8; 3],
}

impl AdDomState {
    /// Create new state
    pub const fn new() -> Self {
        Self {
            forest: Forest::new(),
            domains: [const { Domain::new() }; MAX_DOMAINS],
            domain_count: 0,
            next_id: 1,
            connected: false,
            reserved: [0; 3],
        }
    }

    /// Find domain by ID
    pub fn find_domain(&self, domain_id: u32) -> Option<usize> {
        for (i, domain) in self.domains.iter().enumerate() {
            if domain.in_use && domain.domain_id == domain_id {
                return Some(i);
            }
        }
        None
    }

    /// Find domain by DNS name
    pub fn find_by_name(&self, dns_name: &[u8]) -> Option<usize> {
        for (i, domain) in self.domains.iter().enumerate() {
            if domain.in_use && &domain.dns_name[..domain.dns_len] == dns_name {
                return Some(i);
            }
        }
        None
    }

    /// Get root domain
    pub fn get_root_domain(&self) -> Option<usize> {
        for (i, domain) in self.domains.iter().enumerate() {
            if domain.in_use && domain.is_forest_root {
                return Some(i);
            }
        }
        None
    }
}

impl Default for AdDomState {
    fn default() -> Self {
        Self::new()
    }
}

/// Global state
static ADDOM_STATE: SpinLock<AdDomState> = SpinLock::new(AdDomState::new());

/// Initialization flag
static ADDOM_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Statistics
static ADDOM_OPERATION_COUNT: AtomicU32 = AtomicU32::new(0);

/// Error codes
pub mod error {
    pub const SUCCESS: u32 = 0;
    pub const NOT_INITIALIZED: u32 = 0xADD00001;
    pub const NOT_CONNECTED: u32 = 0xADD00002;
    pub const DOMAIN_NOT_FOUND: u32 = 0xADD00003;
    pub const TRUST_NOT_FOUND: u32 = 0xADD00004;
    pub const ALREADY_EXISTS: u32 = 0xADD00005;
    pub const INVALID_PARAMETER: u32 = 0xADD00006;
    pub const CANNOT_LOWER_LEVEL: u32 = 0xADD00007;
    pub const NO_MORE_OBJECTS: u32 = 0xADD00008;
    pub const ACCESS_DENIED: u32 = 0xADD00009;
    pub const TRUST_FAILED: u32 = 0xADD0000A;
}

/// Initialize AD Domains and Trusts
pub fn init() {
    if ADDOM_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = ADDOM_STATE.lock();

    // Set forest name
    state.forest.set_name(b"forest.local");
    state.forest.functional_level = ForestFunctionalLevel::WindowsServer2003;
    state.forest.set_fsmo_holder(FsmoRole::SchemaMaster, b"DC1.forest.local");
    state.forest.set_fsmo_holder(FsmoRole::DomainNamingMaster, b"DC1.forest.local");

    // Create root domain
    let domain_id = state.next_id;
    state.next_id += 1;

    let domain = &mut state.domains[0];
    domain.in_use = true;
    domain.domain_id = domain_id;
    domain.set_dns_name(b"forest.local");
    domain.set_netbios_name(b"FOREST");
    domain.functional_level = DomainFunctionalLevel::WindowsServer2003;
    domain.is_forest_root = true;
    domain.set_fsmo_holder(FsmoRole::PdcEmulator, b"DC1.forest.local");
    domain.set_fsmo_holder(FsmoRole::RidMaster, b"DC1.forest.local");
    domain.set_fsmo_holder(FsmoRole::InfrastructureMaster, b"DC1.forest.local");

    state.domain_count = 1;
    state.connected = true;
}

/// Raise domain functional level
pub fn raise_domain_level(domain_id: u32, level: DomainFunctionalLevel) -> Result<(), u32> {
    if !ADDOM_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADDOM_STATE.lock();

    let idx = match state.find_domain(domain_id) {
        Some(i) => i,
        None => return Err(error::DOMAIN_NOT_FOUND),
    };

    if !state.domains[idx].functional_level.can_raise_to(level) {
        return Err(error::CANNOT_LOWER_LEVEL);
    }

    state.domains[idx].functional_level = level;

    ADDOM_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Raise forest functional level
pub fn raise_forest_level(level: ForestFunctionalLevel) -> Result<(), u32> {
    if !ADDOM_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADDOM_STATE.lock();

    if level <= state.forest.functional_level {
        return Err(error::CANNOT_LOWER_LEVEL);
    }

    // Check all domains meet minimum level
    let min_domain_level = match level {
        ForestFunctionalLevel::Windows2000 => DomainFunctionalLevel::Windows2000Mixed,
        ForestFunctionalLevel::WindowsServer2003Interim => DomainFunctionalLevel::WindowsServer2003Interim,
        ForestFunctionalLevel::WindowsServer2003 => DomainFunctionalLevel::WindowsServer2003,
    };

    for domain in state.domains.iter() {
        if domain.in_use && domain.functional_level < min_domain_level {
            return Err(error::CANNOT_LOWER_LEVEL);
        }
    }

    state.forest.functional_level = level;

    ADDOM_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Create a trust relationship
pub fn create_trust(
    domain_id: u32,
    trusted_domain: &[u8],
    direction: TrustDirection,
    trust_type: TrustType,
    transitive: bool,
) -> Result<u32, u32> {
    if !ADDOM_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADDOM_STATE.lock();

    let idx = match state.find_domain(domain_id) {
        Some(i) => i,
        None => return Err(error::DOMAIN_NOT_FOUND),
    };

    // Find free trust slot
    let mut slot_idx = None;
    for (i, trust) in state.domains[idx].trusts.iter().enumerate() {
        if !trust.in_use {
            slot_idx = Some(i);
            break;
        }
    }

    let trust_idx = match slot_idx {
        Some(i) => i,
        None => return Err(error::NO_MORE_OBJECTS),
    };

    let trust_id = state.next_id;
    state.next_id += 1;

    let trust = &mut state.domains[idx].trusts[trust_idx];
    trust.in_use = true;
    trust.trust_id = trust_id;
    trust.set_trusted_domain(trusted_domain);
    trust.direction = direction;
    trust.trust_type = trust_type;
    trust.transitive = transitive;

    if !transitive {
        trust.attributes.insert(TrustAttributes::NON_TRANSITIVE);
    }

    state.domains[idx].trust_count += 1;
    ADDOM_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(trust_id)
}

/// Delete a trust relationship
pub fn delete_trust(domain_id: u32, trust_id: u32) -> Result<(), u32> {
    if !ADDOM_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADDOM_STATE.lock();

    let idx = match state.find_domain(domain_id) {
        Some(i) => i,
        None => return Err(error::DOMAIN_NOT_FOUND),
    };

    let mut found = false;
    for trust in state.domains[idx].trusts.iter_mut() {
        if trust.in_use && trust.trust_id == trust_id {
            trust.in_use = false;
            found = true;
            break;
        }
    }

    if !found {
        return Err(error::TRUST_NOT_FOUND);
    }

    state.domains[idx].trust_count = state.domains[idx].trust_count.saturating_sub(1);
    ADDOM_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Verify a trust relationship
pub fn verify_trust(domain_id: u32, trust_id: u32) -> Result<bool, u32> {
    if !ADDOM_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADDOM_STATE.lock();

    let idx = match state.find_domain(domain_id) {
        Some(i) => i,
        None => return Err(error::DOMAIN_NOT_FOUND),
    };

    for trust in state.domains[idx].trusts.iter_mut() {
        if trust.in_use && trust.trust_id == trust_id {
            // Simulate verification
            trust.last_verified = 1; // Would be current timestamp
            ADDOM_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);
            return Ok(true);
        }
    }

    Err(error::TRUST_NOT_FOUND)
}

/// Reset trust password
pub fn reset_trust_password(domain_id: u32, trust_id: u32) -> Result<(), u32> {
    if !ADDOM_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let state = ADDOM_STATE.lock();

    let idx = match state.find_domain(domain_id) {
        Some(i) => i,
        None => return Err(error::DOMAIN_NOT_FOUND),
    };

    let mut found = false;
    for trust in state.domains[idx].trusts.iter() {
        if trust.in_use && trust.trust_id == trust_id {
            found = true;
            break;
        }
    }

    if !found {
        return Err(error::TRUST_NOT_FOUND);
    }

    // In real implementation, would reset trust password on both sides
    ADDOM_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Add UPN suffix
pub fn add_upn_suffix(suffix: &[u8]) -> Result<(), u32> {
    if !ADDOM_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADDOM_STATE.lock();

    if !state.forest.add_upn_suffix(suffix) {
        return Err(error::NO_MORE_OBJECTS);
    }

    ADDOM_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Remove UPN suffix
pub fn remove_upn_suffix(suffix: &[u8]) -> Result<(), u32> {
    if !ADDOM_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADDOM_STATE.lock();

    let mut found_idx = None;
    for i in 0..state.forest.upn_count {
        let len = state.forest.upn_lens[i];
        if &state.forest.upn_suffixes[i][..len] == suffix {
            found_idx = Some(i);
            break;
        }
    }

    let idx = match found_idx {
        Some(i) => i,
        None => return Err(error::NOT_CONNECTED),
    };

    // Shift remaining suffixes
    for i in idx..state.forest.upn_count - 1 {
        state.forest.upn_suffixes[i] = state.forest.upn_suffixes[i + 1];
        state.forest.upn_lens[i] = state.forest.upn_lens[i + 1];
    }
    state.forest.upn_count -= 1;

    ADDOM_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Transfer FSMO role
pub fn transfer_fsmo_role(role: FsmoRole, target_server: &[u8]) -> Result<(), u32> {
    if !ADDOM_INITIALIZED.load(Ordering::SeqCst) {
        return Err(error::NOT_INITIALIZED);
    }

    let mut state = ADDOM_STATE.lock();

    if role.is_forest_role() {
        state.forest.set_fsmo_holder(role, target_server);
    } else {
        // For domain-wide roles, update root domain
        if let Some(idx) = state.get_root_domain() {
            state.domains[idx].set_fsmo_holder(role, target_server);
        }
    }

    ADDOM_OPERATION_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Get domain count
pub fn get_domain_count() -> usize {
    if !ADDOM_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = ADDOM_STATE.lock();
    state.domain_count
}

/// Get trust count for domain
pub fn get_trust_count(domain_id: u32) -> usize {
    if !ADDOM_INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }

    let state = ADDOM_STATE.lock();

    match state.find_domain(domain_id) {
        Some(idx) => state.domains[idx].trust_count,
        None => 0,
    }
}

/// Create AD Domains and Trusts window
pub fn create_addom_dialog(parent: HWND) -> HWND {
    if !ADDOM_INITIALIZED.load(Ordering::SeqCst) {
        init();
    }

    let id = 0xADD00000u32;
    let _parent = parent;

    UserHandle::from_raw(id)
}

/// Dialog messages
pub mod messages {
    pub const ADDOM_REFRESH: u32 = 0x0780;
    pub const ADDOM_CONNECT: u32 = 0x0781;
    pub const ADDOM_CREATE_TRUST: u32 = 0x0782;
    pub const ADDOM_DELETE_TRUST: u32 = 0x0783;
    pub const ADDOM_VERIFY_TRUST: u32 = 0x0784;
    pub const ADDOM_PROPERTIES: u32 = 0x0785;
    pub const ADDOM_RAISE_DOMAIN_LEVEL: u32 = 0x0786;
    pub const ADDOM_RAISE_FOREST_LEVEL: u32 = 0x0787;
    pub const ADDOM_MANAGE_UPN: u32 = 0x0788;
    pub const ADDOM_TRANSFER_ROLE: u32 = 0x0789;
}

/// Get statistics
pub fn get_statistics() -> (usize, ForestFunctionalLevel, u32) {
    let state = ADDOM_STATE.lock();
    let op_count = ADDOM_OPERATION_COUNT.load(Ordering::Relaxed);
    (state.domain_count, state.forest.functional_level, op_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addom_init() {
        init();
        assert!(ADDOM_INITIALIZED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_functional_level_ordering() {
        assert!(DomainFunctionalLevel::WindowsServer2003 > DomainFunctionalLevel::Windows2000Mixed);
    }

    #[test]
    fn test_trust_direction() {
        assert_eq!(TrustDirection::Bidirectional.display_name(), "Two-way");
    }

    #[test]
    fn test_fsmo_role() {
        assert!(FsmoRole::SchemaMaster.is_forest_role());
        assert!(!FsmoRole::PdcEmulator.is_forest_role());
    }
}
