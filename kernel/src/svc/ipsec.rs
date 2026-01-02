//! IPSec Policy Agent Service
//!
//! The IPSec Policy Agent manages Internet Protocol Security (IPSec)
//! policies for secure network communications.
//!
//! # Features
//!
//! - **Policy Management**: Create and apply IPSec policies
//! - **Security Associations**: IKE negotiation and SA management
//! - **Filters**: Inbound and outbound packet filtering
//! - **Authentication**: Kerberos, certificates, pre-shared keys
//!
//! # IPSec Protocols
//!
//! - AH (Authentication Header): Integrity and authentication
//! - ESP (Encapsulating Security Payload): Encryption + integrity
//!
//! # Policy Sources
//!
//! - Active Directory Group Policy
//! - Local Security Policy
//! - Programmatic API

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum policies
const MAX_POLICIES: usize = 16;

/// Maximum rules per policy
const MAX_RULES: usize = 32;

/// Maximum security associations
const MAX_SA: usize = 64;

/// Maximum name length
const MAX_NAME: usize = 64;

/// Maximum description length
const MAX_DESC: usize = 256;

/// IPSec action
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsecAction {
    /// Permit (no IPSec)
    Permit = 0,
    /// Block
    Block = 1,
    /// Negotiate security
    Negotiate = 2,
}

impl IpsecAction {
    const fn empty() -> Self {
        IpsecAction::Negotiate
    }
}

/// Authentication method
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// Pre-shared key
    PreSharedKey = 0,
    /// Kerberos
    Kerberos = 1,
    /// Certificate
    Certificate = 2,
}

impl AuthMethod {
    const fn empty() -> Self {
        AuthMethod::Kerberos
    }
}

/// Encryption algorithm
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// No encryption (null)
    None = 0,
    /// DES
    Des = 1,
    /// 3DES
    TripleDes = 2,
    /// AES-128
    Aes128 = 3,
    /// AES-256
    Aes256 = 4,
}

impl EncryptionAlgorithm {
    const fn empty() -> Self {
        EncryptionAlgorithm::TripleDes
    }
}

/// Integrity algorithm
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityAlgorithm {
    /// MD5
    Md5 = 0,
    /// SHA-1
    Sha1 = 1,
    /// SHA-256
    Sha256 = 2,
}

impl IntegrityAlgorithm {
    const fn empty() -> Self {
        IntegrityAlgorithm::Sha1
    }
}

/// IPSec protocol
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsecProtocol {
    /// AH (Authentication Header)
    Ah = 0,
    /// ESP (Encapsulating Security Payload)
    Esp = 1,
    /// Both AH and ESP
    Both = 2,
}

impl IpsecProtocol {
    const fn empty() -> Self {
        IpsecProtocol::Esp
    }
}

/// SA state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaState {
    /// Larval (being created)
    Larval = 0,
    /// Mature (active)
    Mature = 1,
    /// Dying (being deleted)
    Dying = 2,
    /// Dead
    Dead = 3,
}

impl SaState {
    const fn empty() -> Self {
        SaState::Larval
    }
}

/// IP address filter
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpFilter {
    /// Source IP (0 = any)
    pub src_ip: [u8; 4],
    /// Source mask
    pub src_mask: [u8; 4],
    /// Destination IP (0 = any)
    pub dst_ip: [u8; 4],
    /// Destination mask
    pub dst_mask: [u8; 4],
    /// Protocol (0 = any, 6 = TCP, 17 = UDP)
    pub protocol: u8,
    /// Source port (0 = any)
    pub src_port: u16,
    /// Destination port (0 = any)
    pub dst_port: u16,
    /// Is mirrored
    pub mirrored: bool,
}

impl IpFilter {
    const fn any() -> Self {
        IpFilter {
            src_ip: [0; 4],
            src_mask: [0; 4],
            dst_ip: [0; 4],
            dst_mask: [0; 4],
            protocol: 0,
            src_port: 0,
            dst_port: 0,
            mirrored: true,
        }
    }
}

/// Security method
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecurityMethod {
    /// IPSec protocol
    pub protocol: IpsecProtocol,
    /// Encryption algorithm
    pub encryption: EncryptionAlgorithm,
    /// Integrity algorithm
    pub integrity: IntegrityAlgorithm,
    /// Key lifetime (seconds)
    pub key_lifetime: u32,
    /// Key lifetime (kilobytes)
    pub key_lifetime_kb: u32,
    /// Perfect forward secrecy
    pub pfs: bool,
}

impl SecurityMethod {
    const fn default_method() -> Self {
        SecurityMethod {
            protocol: IpsecProtocol::Esp,
            encryption: EncryptionAlgorithm::TripleDes,
            integrity: IntegrityAlgorithm::Sha1,
            key_lifetime: 3600,      // 1 hour
            key_lifetime_kb: 100000, // 100 MB
            pfs: false,
        }
    }
}

/// IPSec rule
#[repr(C)]
#[derive(Clone)]
pub struct IpsecRule {
    /// Rule ID
    pub rule_id: u64,
    /// Rule name
    pub name: [u8; MAX_NAME],
    /// Filter
    pub filter: IpFilter,
    /// Action
    pub action: IpsecAction,
    /// Authentication method
    pub auth_method: AuthMethod,
    /// Security method
    pub security: SecurityMethod,
    /// Is enabled
    pub enabled: bool,
    /// Entry is valid
    pub valid: bool,
}

impl IpsecRule {
    const fn empty() -> Self {
        IpsecRule {
            rule_id: 0,
            name: [0; MAX_NAME],
            filter: IpFilter::any(),
            action: IpsecAction::empty(),
            auth_method: AuthMethod::empty(),
            security: SecurityMethod::default_method(),
            enabled: true,
            valid: false,
        }
    }
}

/// IPSec policy
#[repr(C)]
#[derive(Clone)]
pub struct IpsecPolicy {
    /// Policy ID
    pub policy_id: u64,
    /// Policy name
    pub name: [u8; MAX_NAME],
    /// Description
    pub description: [u8; MAX_DESC],
    /// Rules
    pub rules: [IpsecRule; MAX_RULES],
    /// Rule count
    pub rule_count: usize,
    /// Next rule ID
    pub next_rule_id: u64,
    /// Is assigned (active)
    pub assigned: bool,
    /// Policy source (AD, local, etc.)
    pub source: [u8; 32],
    /// Created time
    pub created: i64,
    /// Modified time
    pub modified: i64,
    /// Entry is valid
    pub valid: bool,
}

impl IpsecPolicy {
    const fn empty() -> Self {
        IpsecPolicy {
            policy_id: 0,
            name: [0; MAX_NAME],
            description: [0; MAX_DESC],
            rules: [const { IpsecRule::empty() }; MAX_RULES],
            rule_count: 0,
            next_rule_id: 1,
            assigned: false,
            source: [0; 32],
            created: 0,
            modified: 0,
            valid: false,
        }
    }
}

/// Security Association
#[repr(C)]
#[derive(Clone)]
pub struct SecurityAssociation {
    /// SA ID (SPI)
    pub spi: u32,
    /// Source IP
    pub src_ip: [u8; 4],
    /// Destination IP
    pub dst_ip: [u8; 4],
    /// Protocol
    pub protocol: IpsecProtocol,
    /// Encryption algorithm
    pub encryption: EncryptionAlgorithm,
    /// Integrity algorithm
    pub integrity: IntegrityAlgorithm,
    /// State
    pub state: SaState,
    /// Bytes processed
    pub bytes: u64,
    /// Packets processed
    pub packets: u64,
    /// Created time
    pub created: i64,
    /// Expires time
    pub expires: i64,
    /// Entry is valid
    pub valid: bool,
}

impl SecurityAssociation {
    const fn empty() -> Self {
        SecurityAssociation {
            spi: 0,
            src_ip: [0; 4],
            dst_ip: [0; 4],
            protocol: IpsecProtocol::empty(),
            encryption: EncryptionAlgorithm::empty(),
            integrity: IntegrityAlgorithm::empty(),
            state: SaState::empty(),
            bytes: 0,
            packets: 0,
            created: 0,
            expires: 0,
            valid: false,
        }
    }
}

/// IPSec service state
pub struct IpsecState {
    /// Service is running
    pub running: bool,
    /// Policies
    pub policies: [IpsecPolicy; MAX_POLICIES],
    /// Policy count
    pub policy_count: usize,
    /// Next policy ID
    pub next_policy_id: u64,
    /// Active policy ID (only one can be assigned)
    pub active_policy: u64,
    /// Security associations
    pub sas: [SecurityAssociation; MAX_SA],
    /// SA count
    pub sa_count: usize,
    /// Next SPI
    pub next_spi: u32,
    /// IPSec enabled
    pub enabled: bool,
    /// Service start time
    pub start_time: i64,
}

impl IpsecState {
    const fn new() -> Self {
        IpsecState {
            running: false,
            policies: [const { IpsecPolicy::empty() }; MAX_POLICIES],
            policy_count: 0,
            next_policy_id: 1,
            active_policy: 0,
            sas: [const { SecurityAssociation::empty() }; MAX_SA],
            sa_count: 0,
            next_spi: 0x100,
            enabled: true,
            start_time: 0,
        }
    }
}

/// Global state
static IPSEC_STATE: Mutex<IpsecState> = Mutex::new(IpsecState::new());

/// Statistics
static PACKETS_PROTECTED: AtomicU64 = AtomicU64::new(0);
static PACKETS_BLOCKED: AtomicU64 = AtomicU64::new(0);
static SA_ESTABLISHED: AtomicU64 = AtomicU64::new(0);
static SA_EXPIRED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize IPSec Policy Agent
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = IPSEC_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    crate::serial_println!("[IPSEC] IPSec Policy Agent initialized");
}

/// Create a policy
pub fn create_policy(
    name: &[u8],
    description: &[u8],
) -> Result<u64, u32> {
    let mut state = IPSEC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_NAME);

    // Check for duplicate
    for policy in state.policies.iter() {
        if policy.valid && policy.name[..name_len] == name[..name_len] {
            return Err(0x80070055);
        }
    }

    let slot = state.policies.iter().position(|p| !p.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let policy_id = state.next_policy_id;
    state.next_policy_id += 1;
    state.policy_count += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    let desc_len = description.len().min(MAX_DESC);

    let policy = &mut state.policies[slot];
    policy.policy_id = policy_id;
    policy.name = [0; MAX_NAME];
    policy.name[..name_len].copy_from_slice(&name[..name_len]);
    policy.description = [0; MAX_DESC];
    policy.description[..desc_len].copy_from_slice(&description[..desc_len]);
    policy.created = now;
    policy.modified = now;
    policy.valid = true;

    Ok(policy_id)
}

/// Delete a policy
pub fn delete_policy(policy_id: u64) -> Result<(), u32> {
    let mut state = IPSEC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Cannot delete active policy
    if state.active_policy == policy_id {
        return Err(0x80070005);
    }

    let idx = state.policies.iter()
        .position(|p| p.valid && p.policy_id == policy_id);

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.policies[idx].valid = false;
    state.policy_count = state.policy_count.saturating_sub(1);

    Ok(())
}

/// Add a rule to a policy
pub fn add_rule(
    policy_id: u64,
    name: &[u8],
    filter: IpFilter,
    action: IpsecAction,
    auth_method: AuthMethod,
    security: SecurityMethod,
) -> Result<u64, u32> {
    let mut state = IPSEC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let policy_idx = state.policies.iter()
        .position(|p| p.valid && p.policy_id == policy_id);

    let policy_idx = match policy_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let rule_slot = state.policies[policy_idx].rules.iter()
        .position(|r| !r.valid);

    let rule_slot = match rule_slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let rule_id = state.policies[policy_idx].next_rule_id;
    state.policies[policy_idx].next_rule_id += 1;
    state.policies[policy_idx].rule_count += 1;
    state.policies[policy_idx].modified = crate::rtl::time::rtl_get_system_time();

    let name_len = name.len().min(MAX_NAME);

    let rule = &mut state.policies[policy_idx].rules[rule_slot];
    rule.rule_id = rule_id;
    rule.name = [0; MAX_NAME];
    rule.name[..name_len].copy_from_slice(&name[..name_len]);
    rule.filter = filter;
    rule.action = action;
    rule.auth_method = auth_method;
    rule.security = security;
    rule.enabled = true;
    rule.valid = true;

    Ok(rule_id)
}

/// Remove a rule
pub fn remove_rule(policy_id: u64, rule_id: u64) -> Result<(), u32> {
    let mut state = IPSEC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let policy_idx = state.policies.iter()
        .position(|p| p.valid && p.policy_id == policy_id);

    let policy_idx = match policy_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let rule_idx = state.policies[policy_idx].rules.iter()
        .position(|r| r.valid && r.rule_id == rule_id);

    let rule_idx = match rule_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.policies[policy_idx].rules[rule_idx].valid = false;
    state.policies[policy_idx].rule_count =
        state.policies[policy_idx].rule_count.saturating_sub(1);
    state.policies[policy_idx].modified = crate::rtl::time::rtl_get_system_time();

    Ok(())
}

/// Assign (activate) a policy
pub fn assign_policy(policy_id: u64) -> Result<(), u32> {
    let mut state = IPSEC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Unassign current policy if any
    let current_policy = state.active_policy;
    if current_policy != 0 {
        for policy in state.policies.iter_mut() {
            if policy.valid && policy.policy_id == current_policy {
                policy.assigned = false;
                break;
            }
        }
    }

    // Find and assign new policy
    let policy = state.policies.iter_mut()
        .find(|p| p.valid && p.policy_id == policy_id);

    let policy = match policy {
        Some(p) => p,
        None => return Err(0x80070057),
    };

    policy.assigned = true;
    state.active_policy = policy_id;

    Ok(())
}

/// Unassign the current policy
pub fn unassign_policy() -> Result<(), u32> {
    let mut state = IPSEC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let current_policy = state.active_policy;
    if current_policy == 0 {
        return Ok(());
    }

    for policy in state.policies.iter_mut() {
        if policy.valid && policy.policy_id == current_policy {
            policy.assigned = false;
            break;
        }
    }

    state.active_policy = 0;

    Ok(())
}

/// Create a security association
pub fn create_sa(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    protocol: IpsecProtocol,
    encryption: EncryptionAlgorithm,
    integrity: IntegrityAlgorithm,
    lifetime: u32,
) -> Result<u32, u32> {
    let mut state = IPSEC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.sas.iter().position(|s| !s.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let spi = state.next_spi;
    state.next_spi = state.next_spi.wrapping_add(1);
    if state.next_spi < 0x100 {
        state.next_spi = 0x100; // Reserved SPIs are < 256
    }
    state.sa_count += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    let expires = now + (lifetime as i64 * 10_000_000);

    let sa = &mut state.sas[slot];
    sa.spi = spi;
    sa.src_ip = src_ip;
    sa.dst_ip = dst_ip;
    sa.protocol = protocol;
    sa.encryption = encryption;
    sa.integrity = integrity;
    sa.state = SaState::Mature;
    sa.created = now;
    sa.expires = expires;
    sa.valid = true;

    SA_ESTABLISHED.fetch_add(1, Ordering::SeqCst);

    Ok(spi)
}

/// Delete a security association
pub fn delete_sa(spi: u32) -> Result<(), u32> {
    let mut state = IPSEC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.sas.iter()
        .position(|s| s.valid && s.spi == spi);

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.sas[idx].state = SaState::Dead;
    state.sas[idx].valid = false;
    state.sa_count = state.sa_count.saturating_sub(1);

    SA_EXPIRED.fetch_add(1, Ordering::SeqCst);

    Ok(())
}

/// Update SA statistics
pub fn update_sa_stats(spi: u32, bytes: u64, packets: u64) -> Result<(), u32> {
    let mut state = IPSEC_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let sa = state.sas.iter_mut()
        .find(|s| s.valid && s.spi == spi);

    let sa = match sa {
        Some(s) => s,
        None => return Err(0x80070057),
    };

    sa.bytes += bytes;
    sa.packets += packets;
    PACKETS_PROTECTED.fetch_add(packets, Ordering::SeqCst);

    Ok(())
}

/// Expire old SAs
pub fn expire_sas() {
    let mut state = IPSEC_STATE.lock();

    if !state.running {
        return;
    }

    let now = crate::rtl::time::rtl_get_system_time();
    let mut expired_count = 0usize;

    for sa in state.sas.iter_mut() {
        if sa.valid && sa.state == SaState::Mature && now >= sa.expires {
            sa.state = SaState::Dying;
            // In real implementation, would start rekeying
            sa.valid = false;
            expired_count += 1;
            SA_EXPIRED.fetch_add(1, Ordering::SeqCst);
        }
    }

    state.sa_count = state.sa_count.saturating_sub(expired_count);
}

/// Get policies
pub fn enum_policies() -> ([IpsecPolicy; MAX_POLICIES], usize) {
    let state = IPSEC_STATE.lock();
    let mut result = [const { IpsecPolicy::empty() }; MAX_POLICIES];
    let mut count = 0;

    for policy in state.policies.iter() {
        if policy.valid && count < MAX_POLICIES {
            result[count] = policy.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get security associations
pub fn enum_sas() -> ([SecurityAssociation; MAX_SA], usize) {
    let state = IPSEC_STATE.lock();
    let mut result = [const { SecurityAssociation::empty() }; MAX_SA];
    let mut count = 0;

    for sa in state.sas.iter() {
        if sa.valid && count < MAX_SA {
            result[count] = sa.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get active policy
pub fn get_active_policy() -> Option<IpsecPolicy> {
    let state = IPSEC_STATE.lock();

    if state.active_policy == 0 {
        return None;
    }

    state.policies.iter()
        .find(|p| p.valid && p.policy_id == state.active_policy)
        .cloned()
}

/// Enable/disable IPSec
pub fn set_enabled(enabled: bool) {
    let mut state = IPSEC_STATE.lock();
    state.enabled = enabled;
}

/// Check if IPSec is enabled
pub fn is_enabled() -> bool {
    let state = IPSEC_STATE.lock();
    state.enabled
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        PACKETS_PROTECTED.load(Ordering::SeqCst),
        PACKETS_BLOCKED.load(Ordering::SeqCst),
        SA_ESTABLISHED.load(Ordering::SeqCst),
        SA_EXPIRED.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = IPSEC_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = IPSEC_STATE.lock();
    state.running = false;

    // Mark all SAs as dying
    for sa in state.sas.iter_mut() {
        if sa.valid {
            sa.state = SaState::Dying;
        }
    }

    crate::serial_println!("[IPSEC] IPSec Policy Agent stopped");
}
