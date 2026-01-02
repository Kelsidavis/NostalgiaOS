//! Local Security Policy
//!
//! Implements the Local Security Policy editor following Windows Server 2003.
//! Provides security settings for the local computer.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - secpol.msc - Local Security Policy snap-in
//! - Account Policies, Local Policies, Security Options
//! - Audit Policy, User Rights Assignment

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum policies
const MAX_POLICIES: usize = 128;

/// Maximum name length
const MAX_NAME: usize = 64;

/// Maximum description length
const MAX_DESC: usize = 256;

/// Maximum groups/users per right
const MAX_TRUSTEES: usize = 16;

// ============================================================================
// Policy Category
// ============================================================================

/// Policy category
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyCategory {
    /// Account Policies
    #[default]
    AccountPolicies = 0,
    /// Local Policies
    LocalPolicies = 1,
    /// Public Key Policies
    PublicKeyPolicies = 2,
    /// Software Restriction Policies
    SoftwareRestriction = 3,
    /// IP Security Policies
    IpSecurity = 4,
}

impl PolicyCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyCategory::AccountPolicies => "Account Policies",
            PolicyCategory::LocalPolicies => "Local Policies",
            PolicyCategory::PublicKeyPolicies => "Public Key Policies",
            PolicyCategory::SoftwareRestriction => "Software Restriction Policies",
            PolicyCategory::IpSecurity => "IP Security Policies on Local Computer",
        }
    }
}

// ============================================================================
// Policy Subcategory
// ============================================================================

/// Policy subcategory
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicySubcategory {
    /// Password Policy
    #[default]
    PasswordPolicy = 0,
    /// Account Lockout Policy
    AccountLockout = 1,
    /// Kerberos Policy
    KerberosPolicy = 2,
    /// Audit Policy
    AuditPolicy = 3,
    /// User Rights Assignment
    UserRights = 4,
    /// Security Options
    SecurityOptions = 5,
}

impl PolicySubcategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicySubcategory::PasswordPolicy => "Password Policy",
            PolicySubcategory::AccountLockout => "Account Lockout Policy",
            PolicySubcategory::KerberosPolicy => "Kerberos Policy",
            PolicySubcategory::AuditPolicy => "Audit Policy",
            PolicySubcategory::UserRights => "User Rights Assignment",
            PolicySubcategory::SecurityOptions => "Security Options",
        }
    }

    pub fn get_category(&self) -> PolicyCategory {
        match self {
            PolicySubcategory::PasswordPolicy |
            PolicySubcategory::AccountLockout |
            PolicySubcategory::KerberosPolicy => PolicyCategory::AccountPolicies,
            PolicySubcategory::AuditPolicy |
            PolicySubcategory::UserRights |
            PolicySubcategory::SecurityOptions => PolicyCategory::LocalPolicies,
        }
    }
}

// ============================================================================
// Policy Value Type
// ============================================================================

/// Policy value type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyValueType {
    /// Boolean (enabled/disabled)
    #[default]
    Boolean = 0,
    /// Numeric value
    Numeric = 1,
    /// String value
    String = 2,
    /// List of trustees (users/groups)
    TrusteeList = 3,
    /// Audit setting (Success/Failure)
    AuditSetting = 4,
}

// ============================================================================
// Audit Setting
// ============================================================================

/// Audit setting flags
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditSetting {
    /// No auditing
    #[default]
    NoAudit = 0,
    /// Audit success
    Success = 1,
    /// Audit failure
    Failure = 2,
    /// Audit both
    Both = 3,
}

impl AuditSetting {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditSetting::NoAudit => "No auditing",
            AuditSetting::Success => "Success",
            AuditSetting::Failure => "Failure",
            AuditSetting::Both => "Success, Failure",
        }
    }
}

// ============================================================================
// Policy Entry
// ============================================================================

/// Security policy entry
#[derive(Debug, Clone, Copy)]
pub struct PolicyEntry {
    /// Policy ID
    pub policy_id: u32,
    /// Display name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC],
    /// Description length
    pub desc_len: usize,
    /// Category
    pub category: PolicyCategory,
    /// Subcategory
    pub subcategory: PolicySubcategory,
    /// Value type
    pub value_type: PolicyValueType,
    /// Current value (interpretation depends on value_type)
    pub value: u32,
    /// Default value
    pub default_value: u32,
    /// Minimum value (for numeric)
    pub min_value: u32,
    /// Maximum value (for numeric)
    pub max_value: u32,
}

impl PolicyEntry {
    pub const fn new() -> Self {
        Self {
            policy_id: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            description: [0u8; MAX_DESC],
            desc_len: 0,
            category: PolicyCategory::AccountPolicies,
            subcategory: PolicySubcategory::PasswordPolicy,
            value_type: PolicyValueType::Boolean,
            value: 0,
            default_value: 0,
            min_value: 0,
            max_value: 1,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_DESC);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.desc_len = len;
    }
}

impl Default for PolicyEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// User Right
// ============================================================================

/// User right assignment
#[derive(Debug, Clone, Copy)]
pub struct UserRight {
    /// Right ID
    pub right_id: u32,
    /// Display name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Assigned trustees (user/group names)
    pub trustees: [[u8; 32]; MAX_TRUSTEES],
    /// Trustee name lengths
    pub trustee_lens: [usize; MAX_TRUSTEES],
    /// Trustee count
    pub trustee_count: usize,
}

impl UserRight {
    pub const fn new() -> Self {
        Self {
            right_id: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            trustees: [[0u8; 32]; MAX_TRUSTEES],
            trustee_lens: [0; MAX_TRUSTEES],
            trustee_count: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn add_trustee(&mut self, trustee: &[u8]) -> bool {
        if self.trustee_count >= MAX_TRUSTEES {
            return false;
        }
        let len = trustee.len().min(32);
        let idx = self.trustee_count;
        self.trustees[idx][..len].copy_from_slice(&trustee[..len]);
        self.trustee_lens[idx] = len;
        self.trustee_count += 1;
        true
    }
}

impl Default for UserRight {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Security Policy State
// ============================================================================

/// Security policy state
struct SecpolState {
    /// Policies
    policies: [PolicyEntry; MAX_POLICIES],
    /// Policy count
    policy_count: usize,
    /// User rights
    rights: [UserRight; 32],
    /// User rights count
    rights_count: usize,
    /// Next policy ID
    next_policy_id: u32,
}

impl SecpolState {
    pub const fn new() -> Self {
        Self {
            policies: [const { PolicyEntry::new() }; MAX_POLICIES],
            policy_count: 0,
            rights: [const { UserRight::new() }; 32],
            rights_count: 0,
            next_policy_id: 1,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static SECPOL_INITIALIZED: AtomicBool = AtomicBool::new(false);
static SECPOL_STATE: SpinLock<SecpolState> = SpinLock::new(SecpolState::new());

// Statistics
static POLICY_CHANGES: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Local Security Policy
pub fn init() {
    if SECPOL_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = SECPOL_STATE.lock();

    // Add password policies
    add_password_policies(&mut state);

    // Add account lockout policies
    add_lockout_policies(&mut state);

    // Add audit policies
    add_audit_policies(&mut state);

    // Add security options
    add_security_options(&mut state);

    // Add user rights
    add_user_rights(&mut state);

    crate::serial_println!("[WIN32K] Local Security Policy initialized");
}

/// Add password policies
fn add_password_policies(state: &mut SecpolState) {
    let policies: [(&[u8], &[u8], u32, u32, u32); 6] = [
        (b"Enforce password history", b"Number of passwords remembered", 24, 0, 24),
        (b"Maximum password age", b"Days until password expires", 42, 0, 999),
        (b"Minimum password age", b"Days before password can be changed", 1, 0, 998),
        (b"Minimum password length", b"Minimum number of characters", 7, 0, 14),
        (b"Password must meet complexity", b"Require complex passwords", 1, 0, 1),
        (b"Store passwords reversibly", b"Store using reversible encryption", 0, 0, 1),
    ];

    for (name, desc, default, min, max) in policies.iter() {
        if state.policy_count >= MAX_POLICIES {
            break;
        }
        let mut policy = PolicyEntry::new();
        policy.policy_id = state.next_policy_id;
        state.next_policy_id += 1;
        policy.set_name(name);
        policy.set_description(desc);
        policy.category = PolicyCategory::AccountPolicies;
        policy.subcategory = PolicySubcategory::PasswordPolicy;
        policy.value_type = if *max == 1 { PolicyValueType::Boolean } else { PolicyValueType::Numeric };
        policy.value = *default;
        policy.default_value = *default;
        policy.min_value = *min;
        policy.max_value = *max;

        let idx = state.policy_count;
        state.policies[idx] = policy;
        state.policy_count += 1;
    }
}

/// Add account lockout policies
fn add_lockout_policies(state: &mut SecpolState) {
    let policies: [(&[u8], &[u8], u32, u32, u32); 3] = [
        (b"Account lockout duration", b"Minutes account is locked out", 30, 0, 99999),
        (b"Account lockout threshold", b"Invalid logon attempts before lockout", 0, 0, 999),
        (b"Reset lockout counter after", b"Minutes to reset failed logon count", 30, 1, 99999),
    ];

    for (name, desc, default, min, max) in policies.iter() {
        if state.policy_count >= MAX_POLICIES {
            break;
        }
        let mut policy = PolicyEntry::new();
        policy.policy_id = state.next_policy_id;
        state.next_policy_id += 1;
        policy.set_name(name);
        policy.set_description(desc);
        policy.category = PolicyCategory::AccountPolicies;
        policy.subcategory = PolicySubcategory::AccountLockout;
        policy.value_type = PolicyValueType::Numeric;
        policy.value = *default;
        policy.default_value = *default;
        policy.min_value = *min;
        policy.max_value = *max;

        let idx = state.policy_count;
        state.policies[idx] = policy;
        state.policy_count += 1;
    }
}

/// Add audit policies
fn add_audit_policies(state: &mut SecpolState) {
    let policies: [(&[u8], u32); 9] = [
        (b"Audit account logon events", 0),
        (b"Audit account management", 0),
        (b"Audit directory service access", 0),
        (b"Audit logon events", 0),
        (b"Audit object access", 0),
        (b"Audit policy change", 0),
        (b"Audit privilege use", 0),
        (b"Audit process tracking", 0),
        (b"Audit system events", 0),
    ];

    for (name, default) in policies.iter() {
        if state.policy_count >= MAX_POLICIES {
            break;
        }
        let mut policy = PolicyEntry::new();
        policy.policy_id = state.next_policy_id;
        state.next_policy_id += 1;
        policy.set_name(name);
        policy.set_description(b"Configure auditing for this event category");
        policy.category = PolicyCategory::LocalPolicies;
        policy.subcategory = PolicySubcategory::AuditPolicy;
        policy.value_type = PolicyValueType::AuditSetting;
        policy.value = *default;
        policy.default_value = *default;
        policy.min_value = 0;
        policy.max_value = 3;

        let idx = state.policy_count;
        state.policies[idx] = policy;
        state.policy_count += 1;
    }
}

/// Add security options
fn add_security_options(state: &mut SecpolState) {
    let policies: [(&[u8], u32); 15] = [
        (b"Accounts: Limit local use of blank passwords", 1),
        (b"Accounts: Rename administrator account", 0),
        (b"Accounts: Rename guest account", 0),
        (b"Audit: Force audit policy subcategory", 0),
        (b"Devices: Prevent users from installing drivers", 0),
        (b"Interactive logon: Display last user name", 1),
        (b"Interactive logon: Message text for users", 0),
        (b"Interactive logon: Message title for users", 0),
        (b"Interactive logon: Require smart card", 0),
        (b"Network access: Let Everyone apply to anonymous", 0),
        (b"Network security: LAN Manager authentication", 0),
        (b"Recovery console: Allow automatic logon", 0),
        (b"Shutdown: Allow system to be shut down without logon", 0),
        (b"Shutdown: Clear virtual memory pagefile", 0),
        (b"System objects: Default owner for objects", 0),
    ];

    for (name, default) in policies.iter() {
        if state.policy_count >= MAX_POLICIES {
            break;
        }
        let mut policy = PolicyEntry::new();
        policy.policy_id = state.next_policy_id;
        state.next_policy_id += 1;
        policy.set_name(name);
        policy.set_description(b"Security option setting");
        policy.category = PolicyCategory::LocalPolicies;
        policy.subcategory = PolicySubcategory::SecurityOptions;
        policy.value_type = PolicyValueType::Boolean;
        policy.value = *default;
        policy.default_value = *default;
        policy.min_value = 0;
        policy.max_value = 1;

        let idx = state.policy_count;
        state.policies[idx] = policy;
        state.policy_count += 1;
    }
}

/// Add user rights
fn add_user_rights(state: &mut SecpolState) {
    let rights: [(&[u8], &[&[u8]]); 10] = [
        (b"Access this computer from network", &[b"Administrators" as &[u8], b"Users", b"Backup Operators"]),
        (b"Allow log on locally", &[b"Administrators", b"Users", b"Backup Operators"]),
        (b"Allow log on through Remote Desktop", &[b"Administrators", b"Remote Desktop Users"]),
        (b"Back up files and directories", &[b"Administrators", b"Backup Operators"]),
        (b"Change the system time", &[b"Administrators", b"LOCAL SERVICE"]),
        (b"Create a pagefile", &[b"Administrators"]),
        (b"Debug programs", &[b"Administrators"]),
        (b"Deny access to this computer from network", &[b"Guest"]),
        (b"Force shutdown from a remote system", &[b"Administrators"]),
        (b"Shut down the system", &[b"Administrators", b"Backup Operators", b"Users"]),
    ];

    for (i, (name, trustees)) in rights.iter().enumerate() {
        if i >= 32 {
            break;
        }
        let mut right = UserRight::new();
        right.right_id = i as u32;
        right.set_name(name);
        for trustee in trustees.iter() {
            right.add_trustee(trustee);
        }
        state.rights[state.rights_count] = right;
        state.rights_count += 1;
    }
}

// ============================================================================
// Policy Management
// ============================================================================

/// Get policy count
pub fn get_policy_count() -> usize {
    SECPOL_STATE.lock().policy_count
}

/// Get policy by index
pub fn get_policy(index: usize) -> Option<PolicyEntry> {
    let state = SECPOL_STATE.lock();
    if index < state.policy_count {
        Some(state.policies[index])
    } else {
        None
    }
}

/// Get policy by ID
pub fn get_policy_by_id(policy_id: u32) -> Option<PolicyEntry> {
    let state = SECPOL_STATE.lock();
    for i in 0..state.policy_count {
        if state.policies[i].policy_id == policy_id {
            return Some(state.policies[i]);
        }
    }
    None
}

/// Get policies by subcategory
pub fn get_policies_by_subcategory(subcategory: PolicySubcategory, buffer: &mut [PolicyEntry]) -> usize {
    let state = SECPOL_STATE.lock();
    let mut count = 0;
    for i in 0..state.policy_count {
        if state.policies[i].subcategory == subcategory {
            if count < buffer.len() {
                buffer[count] = state.policies[i];
                count += 1;
            }
        }
    }
    count
}

/// Set policy value
pub fn set_policy_value(policy_id: u32, value: u32) -> bool {
    let mut state = SECPOL_STATE.lock();
    for i in 0..state.policy_count {
        if state.policies[i].policy_id == policy_id {
            // Validate value
            if value < state.policies[i].min_value || value > state.policies[i].max_value {
                return false;
            }
            state.policies[i].value = value;
            POLICY_CHANGES.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Reset policy to default
pub fn reset_policy(policy_id: u32) -> bool {
    let mut state = SECPOL_STATE.lock();
    for i in 0..state.policy_count {
        if state.policies[i].policy_id == policy_id {
            state.policies[i].value = state.policies[i].default_value;
            POLICY_CHANGES.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

// ============================================================================
// User Rights Management
// ============================================================================

/// Get user right count
pub fn get_right_count() -> usize {
    SECPOL_STATE.lock().rights_count
}

/// Get user right by index
pub fn get_right(index: usize) -> Option<UserRight> {
    let state = SECPOL_STATE.lock();
    if index < state.rights_count {
        Some(state.rights[index])
    } else {
        None
    }
}

/// Add trustee to right
pub fn add_trustee_to_right(right_id: u32, trustee: &[u8]) -> bool {
    let mut state = SECPOL_STATE.lock();
    for i in 0..state.rights_count {
        if state.rights[i].right_id == right_id {
            if state.rights[i].add_trustee(trustee) {
                POLICY_CHANGES.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            return false;
        }
    }
    false
}

/// Remove trustee from right
pub fn remove_trustee_from_right(right_id: u32, trustee_index: usize) -> bool {
    let mut state = SECPOL_STATE.lock();
    for i in 0..state.rights_count {
        if state.rights[i].right_id == right_id {
            if trustee_index >= state.rights[i].trustee_count {
                return false;
            }
            // Shift remaining trustees
            for j in trustee_index..state.rights[i].trustee_count - 1 {
                state.rights[i].trustees[j] = state.rights[i].trustees[j + 1];
                state.rights[i].trustee_lens[j] = state.rights[i].trustee_lens[j + 1];
            }
            state.rights[i].trustee_count -= 1;
            POLICY_CHANGES.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Check if user has right
pub fn user_has_right(right_id: u32, user_name: &[u8]) -> bool {
    let state = SECPOL_STATE.lock();
    for i in 0..state.rights_count {
        if state.rights[i].right_id == right_id {
            for j in 0..state.rights[i].trustee_count {
                let len = state.rights[i].trustee_lens[j];
                if len == user_name.len() && &state.rights[i].trustees[j][..len] == user_name {
                    return true;
                }
            }
            return false;
        }
    }
    false
}

// ============================================================================
// Audit Policy Helpers
// ============================================================================

/// Set audit policy
pub fn set_audit_policy(policy_id: u32, setting: AuditSetting) -> bool {
    set_policy_value(policy_id, setting as u32)
}

/// Get audit policy
pub fn get_audit_policy(policy_id: u32) -> Option<AuditSetting> {
    let state = SECPOL_STATE.lock();
    for i in 0..state.policy_count {
        if state.policies[i].policy_id == policy_id && state.policies[i].value_type == PolicyValueType::AuditSetting {
            return match state.policies[i].value {
                0 => Some(AuditSetting::NoAudit),
                1 => Some(AuditSetting::Success),
                2 => Some(AuditSetting::Failure),
                3 => Some(AuditSetting::Both),
                _ => None,
            };
        }
    }
    None
}

// ============================================================================
// Statistics
// ============================================================================

/// Security Policy statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct SecpolStats {
    pub initialized: bool,
    pub policy_count: usize,
    pub rights_count: usize,
    pub policy_changes: u32,
}

/// Get Security Policy statistics
pub fn get_stats() -> SecpolStats {
    let state = SECPOL_STATE.lock();
    SecpolStats {
        initialized: SECPOL_INITIALIZED.load(Ordering::Relaxed),
        policy_count: state.policy_count,
        rights_count: state.rights_count,
        policy_changes: POLICY_CHANGES.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Security Policy dialog handle
pub type HSECPOLDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Security Policy dialog
pub fn create_secpol_dialog(_parent: super::super::HWND) -> HSECPOLDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
