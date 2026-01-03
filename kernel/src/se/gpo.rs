//! Group Policy Object (GPO) Infrastructure
//!
//! Group Policy provides centralized management of system configuration:
//!
//! - **Local Group Policy**: Local machine policy (gpedit.msc)
//! - **Domain Group Policy**: Active Directory policies (LDAP-based)
//! - **Policy Categories**: Computer config, User config
//! - **Administrative Templates**: Registry-based settings
//! - **Security Settings**: Account policies, local policies
//! - **Software Settings**: Software installation, restrictions
//!
//! # Registry Locations
//!
//! - `HKLM\Software\Policies`: Machine policies
//! - `HKCU\Software\Policies`: User policies
//! - `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies`: Additional policies
//!
//! # Policy Processing Order
//!
//! 1. Local GPO (LGPO)
//! 2. Site GPOs
//! 3. Domain GPOs
//! 4. Organizational Unit GPOs

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};
use crate::ke::SpinLock;
use alloc::vec::Vec;

// ============================================================================
// GPO Constants
// ============================================================================

/// Maximum GPOs
pub const MAX_GPOS: usize = 32;

/// Maximum policies per GPO
pub const MAX_POLICIES: usize = 64;

/// Maximum GPO name length
pub const MAX_GPO_NAME: usize = 128;

/// Maximum policy name length
pub const MAX_POLICY_NAME: usize = 128;

/// Maximum registry path length
pub const MAX_REG_PATH: usize = 256;

/// Maximum policy value length
pub const MAX_POLICY_VALUE: usize = 512;

/// Maximum GPO links
pub const MAX_GPO_LINKS: usize = 8;

// ============================================================================
// GPO Flags
// ============================================================================

/// GPO options flags
pub mod gpo_flags {
    /// GPO is disabled
    pub const DISABLED: u32 = 0x00000001;
    /// User configuration disabled
    pub const USER_DISABLED: u32 = 0x00000002;
    /// Computer configuration disabled
    pub const COMPUTER_DISABLED: u32 = 0x00000004;
    /// GPO enforced (no override)
    pub const ENFORCED: u32 = 0x00000008;
    /// Block policy inheritance
    pub const BLOCK_INHERITANCE: u32 = 0x00000010;
}

// ============================================================================
// Policy Type
// ============================================================================

/// Policy data type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum PolicyType {
    /// No value
    #[default]
    None = 0,
    /// DWORD (REG_DWORD)
    Dword = 1,
    /// String (REG_SZ)
    String = 2,
    /// Expandable string (REG_EXPAND_SZ)
    ExpandString = 3,
    /// Multi-string (REG_MULTI_SZ)
    MultiString = 4,
    /// Binary (REG_BINARY)
    Binary = 5,
    /// Delete value
    Delete = 6,
}

impl PolicyType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => PolicyType::None,
            1 => PolicyType::Dword,
            2 => PolicyType::String,
            3 => PolicyType::ExpandString,
            4 => PolicyType::MultiString,
            5 => PolicyType::Binary,
            6 => PolicyType::Delete,
            _ => PolicyType::None,
        }
    }
}

// ============================================================================
// Policy Scope
// ============================================================================

/// Policy scope (Computer or User)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum PolicyScope {
    /// Machine/Computer configuration
    #[default]
    Machine = 0,
    /// User configuration
    User = 1,
}

// ============================================================================
// Policy Category
// ============================================================================

/// Policy category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum PolicyCategory {
    /// Administrative templates (registry policies)
    #[default]
    Administrative = 0,
    /// Security settings
    Security = 1,
    /// Software settings
    Software = 2,
    /// Windows settings
    Windows = 3,
    /// Scripts (startup/shutdown/logon/logoff)
    Scripts = 4,
    /// Folder redirection
    FolderRedirection = 5,
    /// Preferences
    Preferences = 6,
}

// ============================================================================
// GPO Scope
// ============================================================================

/// GPO scope level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum GpoScope {
    /// Local machine policy
    #[default]
    Local = 0,
    /// Site level
    Site = 1,
    /// Domain level
    Domain = 2,
    /// Organizational Unit level
    OrganizationalUnit = 3,
}

// ============================================================================
// Error Codes
// ============================================================================

/// Group Policy error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GpoError {
    /// Success
    Success = 0,
    /// GPO not found
    GpoNotFound = 0x80072020,
    /// Policy not found
    PolicyNotFound = 0x80072021,
    /// Invalid parameter
    InvalidParameter = 0x80072022,
    /// Access denied
    AccessDenied = 0x80072023,
    /// Maximum GPOs reached
    MaxGposReached = 0x80072024,
    /// Maximum policies reached
    MaxPoliciesReached = 0x80072025,
    /// GPO already exists
    GpoAlreadyExists = 0x80072026,
    /// Invalid scope
    InvalidScope = 0x80072027,
    /// Service not running
    NotRunning = 0x80072028,
}

// ============================================================================
// Policy Entry
// ============================================================================

/// Individual policy setting
#[repr(C)]
pub struct PolicyEntry {
    /// Policy name/key
    pub name: [u8; MAX_POLICY_NAME],
    /// Registry path
    pub registry_path: [u8; MAX_REG_PATH],
    /// Registry value name
    pub value_name: [u8; MAX_POLICY_NAME],
    /// Policy type
    pub policy_type: PolicyType,
    /// Category
    pub category: PolicyCategory,
    /// Scope (machine/user)
    pub scope: PolicyScope,
    /// DWORD value (if applicable)
    pub dword_value: u32,
    /// String/binary value
    pub string_value: [u8; MAX_POLICY_VALUE],
    /// Value length
    pub value_length: usize,
    /// Policy enabled
    pub enabled: bool,
    /// Entry valid
    pub valid: bool,
}

impl PolicyEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0; MAX_POLICY_NAME],
            registry_path: [0; MAX_REG_PATH],
            value_name: [0; MAX_POLICY_NAME],
            policy_type: PolicyType::None,
            category: PolicyCategory::Administrative,
            scope: PolicyScope::Machine,
            dword_value: 0,
            string_value: [0; MAX_POLICY_VALUE],
            value_length: 0,
            enabled: true,
            valid: false,
        }
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_POLICY_NAME - 1);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0;
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_POLICY_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_registry_path(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_REG_PATH - 1);
        self.registry_path[..len].copy_from_slice(&bytes[..len]);
        self.registry_path[len] = 0;
    }

    pub fn registry_path_str(&self) -> &str {
        let len = self.registry_path.iter().position(|&b| b == 0).unwrap_or(MAX_REG_PATH);
        core::str::from_utf8(&self.registry_path[..len]).unwrap_or("")
    }

    pub fn set_value_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_POLICY_NAME - 1);
        self.value_name[..len].copy_from_slice(&bytes[..len]);
        self.value_name[len] = 0;
    }

    pub fn value_name_str(&self) -> &str {
        let len = self.value_name.iter().position(|&b| b == 0).unwrap_or(MAX_POLICY_NAME);
        core::str::from_utf8(&self.value_name[..len]).unwrap_or("")
    }

    pub fn set_string_value(&mut self, value: &str) {
        let bytes = value.as_bytes();
        let len = bytes.len().min(MAX_POLICY_VALUE - 1);
        self.string_value[..len].copy_from_slice(&bytes[..len]);
        self.string_value[len] = 0;
        self.value_length = len;
    }

    pub fn string_value_str(&self) -> &str {
        let len = self.value_length.min(MAX_POLICY_VALUE);
        core::str::from_utf8(&self.string_value[..len]).unwrap_or("")
    }
}

// ============================================================================
// GPO Link
// ============================================================================

/// GPO link to a scope/container
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GpoLink {
    /// GPO ID
    pub gpo_id: u64,
    /// Link order (priority, lower = higher priority)
    pub link_order: u32,
    /// Link enabled
    pub enabled: bool,
    /// Link enforced (no override)
    pub enforced: bool,
    /// Link valid
    pub valid: bool,
}

impl GpoLink {
    pub const fn empty() -> Self {
        Self {
            gpo_id: 0,
            link_order: 0,
            enabled: true,
            enforced: false,
            valid: false,
        }
    }
}

// ============================================================================
// Group Policy Object
// ============================================================================

/// Group Policy Object
#[repr(C)]
pub struct GroupPolicyObject {
    /// GPO ID (GUID-like)
    pub gpo_id: u64,
    /// GPO name
    pub name: [u8; MAX_GPO_NAME],
    /// Display name
    pub display_name: [u8; MAX_GPO_NAME],
    /// GPO scope
    pub scope: GpoScope,
    /// GPO flags
    pub flags: u32,
    /// Version number
    pub version: u32,
    /// Policies
    pub policies: [PolicyEntry; MAX_POLICIES],
    /// Policy count
    pub policy_count: usize,
    /// Links to this GPO
    pub links: [GpoLink; MAX_GPO_LINKS],
    /// Link count
    pub link_count: usize,
    /// Creation time
    pub creation_time: u64,
    /// Modification time
    pub modification_time: u64,
    /// GPO enabled
    pub enabled: bool,
    /// GPO valid
    pub valid: bool,
}

impl GroupPolicyObject {
    pub const fn empty() -> Self {
        Self {
            gpo_id: 0,
            name: [0; MAX_GPO_NAME],
            display_name: [0; MAX_GPO_NAME],
            scope: GpoScope::Local,
            flags: 0,
            version: 0,
            policies: [const { PolicyEntry::empty() }; MAX_POLICIES],
            policy_count: 0,
            links: [const { GpoLink::empty() }; MAX_GPO_LINKS],
            link_count: 0,
            creation_time: 0,
            modification_time: 0,
            enabled: true,
            valid: false,
        }
    }

    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_GPO_NAME - 1);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0;
    }

    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(MAX_GPO_NAME);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn set_display_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_GPO_NAME - 1);
        self.display_name[..len].copy_from_slice(&bytes[..len]);
        self.display_name[len] = 0;
    }

    pub fn display_name_str(&self) -> &str {
        let len = self.display_name.iter().position(|&b| b == 0).unwrap_or(MAX_GPO_NAME);
        core::str::from_utf8(&self.display_name[..len]).unwrap_or("")
    }

    /// Add a policy to this GPO
    pub fn add_policy(&mut self, policy: PolicyEntry) -> Result<(), GpoError> {
        if self.policy_count >= MAX_POLICIES {
            return Err(GpoError::MaxPoliciesReached);
        }
        self.policies[self.policy_count] = policy;
        self.policy_count += 1;
        self.version += 1;
        Ok(())
    }

    /// Check if GPO is disabled
    pub fn is_disabled(&self) -> bool {
        !self.enabled || (self.flags & gpo_flags::DISABLED) != 0
    }

    /// Check if computer config disabled
    pub fn is_computer_disabled(&self) -> bool {
        (self.flags & gpo_flags::COMPUTER_DISABLED) != 0
    }

    /// Check if user config disabled
    pub fn is_user_disabled(&self) -> bool {
        (self.flags & gpo_flags::USER_DISABLED) != 0
    }
}

// ============================================================================
// Well-Known Policy Settings
// ============================================================================

/// Common security policy IDs
pub mod security_policies {
    /// Minimum password length
    pub const MIN_PASSWORD_LENGTH: &str = "MinimumPasswordLength";
    /// Maximum password age (days)
    pub const MAX_PASSWORD_AGE: &str = "MaximumPasswordAge";
    /// Password complexity required
    pub const PASSWORD_COMPLEXITY: &str = "PasswordComplexity";
    /// Account lockout threshold
    pub const LOCKOUT_THRESHOLD: &str = "LockoutBadCount";
    /// Account lockout duration (minutes)
    pub const LOCKOUT_DURATION: &str = "LockoutDuration";
    /// Reset lockout counter after (minutes)
    pub const LOCKOUT_RESET: &str = "ResetLockoutCount";
    /// Interactive logon message title
    pub const LOGON_MESSAGE_TITLE: &str = "LegalNoticeCaption";
    /// Interactive logon message text
    pub const LOGON_MESSAGE_TEXT: &str = "LegalNoticeText";
    /// Audit account logon
    pub const AUDIT_LOGON: &str = "AuditLogonEvents";
    /// Audit object access
    pub const AUDIT_OBJECT: &str = "AuditObjectAccess";
    /// Audit policy change
    pub const AUDIT_POLICY: &str = "AuditPolicyChange";
}

/// Common administrative template policies
pub mod admin_templates {
    /// Windows Update
    pub const WU_AUTO_UPDATE: &str = "NoAutoUpdate";
    pub const WU_SCHEDULE_DAY: &str = "ScheduledInstallDay";
    pub const WU_SCHEDULE_TIME: &str = "ScheduledInstallTime";
    /// Internet Explorer
    pub const IE_HOMEPAGE: &str = "Start Page";
    pub const IE_SEARCH_PAGE: &str = "Search Page";
    /// Explorer
    pub const NO_RUN: &str = "NoRun";
    pub const NO_DESKTOP: &str = "NoDesktop";
    pub const NO_TASK_MANAGER: &str = "DisableTaskMgr";
    /// Control Panel
    pub const NO_CONTROL_PANEL: &str = "NoControlPanel";
    pub const NO_ADD_REMOVE_PROGRAMS: &str = "NoAddRemovePrograms";
}

// ============================================================================
// GPO State
// ============================================================================

/// Group Policy configuration
#[repr(C)]
pub struct GpoConfig {
    /// Refresh interval (minutes)
    pub refresh_interval: u32,
    /// Refresh offset randomization (minutes)
    pub refresh_offset: u32,
    /// Enable background refresh
    pub background_refresh: bool,
    /// Enable async policy processing
    pub async_processing: bool,
    /// Log policy events
    pub log_events: bool,
}

impl GpoConfig {
    pub const fn new() -> Self {
        Self {
            refresh_interval: 90,   // 90 minutes
            refresh_offset: 30,     // +/- 30 minutes
            background_refresh: true,
            async_processing: true,
            log_events: true,
        }
    }
}

/// Group Policy service state
#[repr(C)]
pub struct GpoState {
    /// Configuration
    pub config: GpoConfig,
    /// GPOs
    pub gpos: [GroupPolicyObject; MAX_GPOS],
    /// GPO count
    pub gpo_count: usize,
    /// Next GPO ID
    pub next_gpo_id: u64,
    /// Last refresh time
    pub last_refresh: u64,
    /// Service running
    pub running: bool,
}

impl GpoState {
    pub const fn new() -> Self {
        Self {
            config: GpoConfig::new(),
            gpos: [const { GroupPolicyObject::empty() }; MAX_GPOS],
            gpo_count: 0,
            next_gpo_id: 1,
            last_refresh: 0,
            running: false,
        }
    }
}

/// Global GPO state
static GPO_STATE: SpinLock<GpoState> = SpinLock::new(GpoState::new());

/// GPO statistics
pub struct GpoStats {
    /// GPOs created
    pub gpos_created: AtomicU64,
    /// GPOs deleted
    pub gpos_deleted: AtomicU64,
    /// Policies applied
    pub policies_applied: AtomicU64,
    /// Policy refreshes
    pub refreshes: AtomicU64,
    /// Policy errors
    pub errors: AtomicU64,
}

impl GpoStats {
    pub const fn new() -> Self {
        Self {
            gpos_created: AtomicU64::new(0),
            gpos_deleted: AtomicU64::new(0),
            policies_applied: AtomicU64::new(0),
            refreshes: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }
}

static GPO_STATS: GpoStats = GpoStats::new();

// ============================================================================
// GPO API
// ============================================================================

/// Create a new GPO
pub fn create_gpo(name: &str, scope: GpoScope) -> Result<u64, GpoError> {
    let mut state = GPO_STATE.lock();

    if !state.running {
        return Err(GpoError::NotRunning);
    }

    // Check for existing GPO with same name
    for i in 0..MAX_GPOS {
        if state.gpos[i].valid && state.gpos[i].name_str() == name {
            return Err(GpoError::GpoAlreadyExists);
        }
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_GPOS {
        if !state.gpos[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(GpoError::MaxGposReached),
    };

    let gpo_id = state.next_gpo_id;
    state.next_gpo_id += 1;

    let current_time = crate::hal::apic::get_tick_count();

    let gpo = &mut state.gpos[slot];
    *gpo = GroupPolicyObject::empty();
    gpo.gpo_id = gpo_id;
    gpo.set_name(name);
    gpo.set_display_name(name);
    gpo.scope = scope;
    gpo.creation_time = current_time;
    gpo.modification_time = current_time;
    gpo.version = 1;
    gpo.valid = true;

    state.gpo_count += 1;

    GPO_STATS.gpos_created.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[GPO] Created GPO {} '{}' (scope={:?})",
        gpo_id, name, scope);

    Ok(gpo_id)
}

/// Delete a GPO
pub fn delete_gpo(gpo_id: u64) -> Result<(), GpoError> {
    let mut state = GPO_STATE.lock();

    let gpo = find_gpo_mut(&mut state, gpo_id)?;

    let name = gpo.name_str();
    crate::serial_println!("[GPO] Deleting GPO {} '{}'", gpo_id, name);

    gpo.valid = false;
    state.gpo_count = state.gpo_count.saturating_sub(1);

    GPO_STATS.gpos_deleted.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Add a DWORD policy to a GPO
pub fn add_dword_policy(
    gpo_id: u64,
    name: &str,
    registry_path: &str,
    value_name: &str,
    value: u32,
    scope: PolicyScope,
) -> Result<(), GpoError> {
    let mut state = GPO_STATE.lock();

    let gpo = find_gpo_mut(&mut state, gpo_id)?;

    let mut policy = PolicyEntry::empty();
    policy.set_name(name);
    policy.set_registry_path(registry_path);
    policy.set_value_name(value_name);
    policy.policy_type = PolicyType::Dword;
    policy.scope = scope;
    policy.dword_value = value;
    policy.valid = true;

    gpo.add_policy(policy)?;

    let current_time = crate::hal::apic::get_tick_count();
    gpo.modification_time = current_time;

    crate::serial_println!("[GPO] GPO {}: Added DWORD policy '{}' = {}",
        gpo_id, name, value);

    Ok(())
}

/// Add a string policy to a GPO
pub fn add_string_policy(
    gpo_id: u64,
    name: &str,
    registry_path: &str,
    value_name: &str,
    value: &str,
    scope: PolicyScope,
) -> Result<(), GpoError> {
    let mut state = GPO_STATE.lock();

    let gpo = find_gpo_mut(&mut state, gpo_id)?;

    let mut policy = PolicyEntry::empty();
    policy.set_name(name);
    policy.set_registry_path(registry_path);
    policy.set_value_name(value_name);
    policy.policy_type = PolicyType::String;
    policy.scope = scope;
    policy.set_string_value(value);
    policy.valid = true;

    gpo.add_policy(policy)?;

    let current_time = crate::hal::apic::get_tick_count();
    gpo.modification_time = current_time;

    crate::serial_println!("[GPO] GPO {}: Added string policy '{}' = '{}'",
        gpo_id, name, value);

    Ok(())
}

/// Enable/disable a GPO
pub fn set_gpo_enabled(gpo_id: u64, enabled: bool) -> Result<(), GpoError> {
    let mut state = GPO_STATE.lock();

    let gpo = find_gpo_mut(&mut state, gpo_id)?;

    gpo.enabled = enabled;
    if enabled {
        gpo.flags &= !gpo_flags::DISABLED;
    } else {
        gpo.flags |= gpo_flags::DISABLED;
    }

    let current_time = crate::hal::apic::get_tick_count();
    gpo.modification_time = current_time;

    crate::serial_println!("[GPO] GPO {} {}", gpo_id,
        if enabled { "enabled" } else { "disabled" });

    Ok(())
}

/// Set GPO flags
pub fn set_gpo_flags(gpo_id: u64, flags: u32) -> Result<(), GpoError> {
    let mut state = GPO_STATE.lock();

    let gpo = find_gpo_mut(&mut state, gpo_id)?;

    gpo.flags = flags;

    let current_time = crate::hal::apic::get_tick_count();
    gpo.modification_time = current_time;

    Ok(())
}

/// Get policy value (DWORD)
pub fn get_policy_dword(
    registry_path: &str,
    value_name: &str,
    scope: PolicyScope,
) -> Option<u32> {
    let state = GPO_STATE.lock();

    // Search all enabled GPOs in order (local first, then domain)
    for gpo_scope in [GpoScope::Local, GpoScope::Site, GpoScope::Domain, GpoScope::OrganizationalUnit] {
        for i in 0..MAX_GPOS {
            if !state.gpos[i].valid || state.gpos[i].is_disabled() {
                continue;
            }

            if state.gpos[i].scope != gpo_scope {
                continue;
            }

            // Check scope (machine/user)
            if scope == PolicyScope::Machine && state.gpos[i].is_computer_disabled() {
                continue;
            }
            if scope == PolicyScope::User && state.gpos[i].is_user_disabled() {
                continue;
            }

            // Search policies
            for j in 0..state.gpos[i].policy_count {
                let policy = &state.gpos[i].policies[j];
                if !policy.valid || !policy.enabled {
                    continue;
                }
                if policy.scope != scope {
                    continue;
                }
                if policy.policy_type != PolicyType::Dword {
                    continue;
                }
                if policy.registry_path_str() == registry_path &&
                   policy.value_name_str() == value_name {
                    return Some(policy.dword_value);
                }
            }
        }
    }

    None
}

/// Get policy value (string)
pub fn get_policy_string<'a>(
    registry_path: &str,
    value_name: &str,
    scope: PolicyScope,
) -> Option<&'static str> {
    // Note: This returns 'static because we're returning from global state
    // In a real implementation, this would need more careful lifetime handling

    let state = GPO_STATE.lock();

    for i in 0..MAX_GPOS {
        if !state.gpos[i].valid || state.gpos[i].is_disabled() {
            continue;
        }

        for j in 0..state.gpos[i].policy_count {
            let policy = &state.gpos[i].policies[j];
            if !policy.valid || !policy.enabled {
                continue;
            }
            if policy.scope != scope {
                continue;
            }
            if policy.policy_type != PolicyType::String {
                continue;
            }
            if policy.registry_path_str() == registry_path &&
               policy.value_name_str() == value_name {
                // For now, return a static indication
                return Some("(policy set)");
            }
        }
    }

    None
}

/// Enumerate GPOs
pub fn enumerate_gpos() -> Vec<u64> {
    let state = GPO_STATE.lock();
    let mut result = Vec::new();

    for i in 0..MAX_GPOS {
        if state.gpos[i].valid {
            result.push(state.gpos[i].gpo_id);
        }
    }

    result
}

/// Get GPO info
pub fn get_gpo_info(gpo_id: u64) -> Result<(GpoScope, u32, usize, bool), GpoError> {
    let state = GPO_STATE.lock();

    for i in 0..MAX_GPOS {
        if state.gpos[i].valid && state.gpos[i].gpo_id == gpo_id {
            return Ok((
                state.gpos[i].scope,
                state.gpos[i].version,
                state.gpos[i].policy_count,
                state.gpos[i].enabled,
            ));
        }
    }

    Err(GpoError::GpoNotFound)
}

// ============================================================================
// Policy Processing
// ============================================================================

/// Apply policies from all GPOs
pub fn apply_policies(scope: PolicyScope) -> u32 {
    let state = GPO_STATE.lock();

    let mut applied = 0u32;

    // Process GPOs in order: Local -> Site -> Domain -> OU
    for gpo_scope in [GpoScope::Local, GpoScope::Site, GpoScope::Domain, GpoScope::OrganizationalUnit] {
        for i in 0..MAX_GPOS {
            if !state.gpos[i].valid || state.gpos[i].is_disabled() {
                continue;
            }

            if state.gpos[i].scope != gpo_scope {
                continue;
            }

            // Check scope (machine/user)
            if scope == PolicyScope::Machine && state.gpos[i].is_computer_disabled() {
                continue;
            }
            if scope == PolicyScope::User && state.gpos[i].is_user_disabled() {
                continue;
            }

            // Apply policies from this GPO
            for j in 0..state.gpos[i].policy_count {
                let policy = &state.gpos[i].policies[j];
                if !policy.valid || !policy.enabled {
                    continue;
                }
                if policy.scope != scope {
                    continue;
                }

                // In a real implementation, this would write to the registry
                applied += 1;
            }
        }
    }

    GPO_STATS.policies_applied.fetch_add(applied as u64, Ordering::Relaxed);

    applied
}

/// Refresh policy (trigger reprocessing)
pub fn refresh_policy(force: bool) {
    let mut state = GPO_STATE.lock();

    let current_time = crate::hal::apic::get_tick_count();

    // Check if refresh needed
    if !force {
        let interval_ms = (state.config.refresh_interval as u64) * 60 * 1000;
        if current_time < state.last_refresh + interval_ms {
            return;
        }
    }

    crate::serial_println!("[GPO] Refreshing group policy...");

    // Apply computer policies
    let computer_count = apply_policies(PolicyScope::Machine);

    // Apply user policies
    let user_count = apply_policies(PolicyScope::User);

    state.last_refresh = current_time;

    GPO_STATS.refreshes.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[GPO] Refresh complete: {} computer, {} user policies",
        computer_count, user_count);
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Find GPO by ID (mutable)
fn find_gpo_mut(state: &mut GpoState, gpo_id: u64) -> Result<&mut GroupPolicyObject, GpoError> {
    for i in 0..MAX_GPOS {
        if state.gpos[i].valid && state.gpos[i].gpo_id == gpo_id {
            return Ok(&mut state.gpos[i]);
        }
    }
    Err(GpoError::GpoNotFound)
}

/// Get GPO statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64) {
    (
        GPO_STATS.gpos_created.load(Ordering::Relaxed),
        GPO_STATS.gpos_deleted.load(Ordering::Relaxed),
        GPO_STATS.policies_applied.load(Ordering::Relaxed),
        GPO_STATS.refreshes.load(Ordering::Relaxed),
        GPO_STATS.errors.load(Ordering::Relaxed),
    )
}

/// Get GPO count
pub fn get_gpo_count() -> usize {
    let state = GPO_STATE.lock();
    state.gpo_count
}

/// Check if GPO service is running
pub fn is_running() -> bool {
    let state = GPO_STATE.lock();
    state.running
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Group Policy infrastructure
pub fn init() {
    crate::serial_println!("[GPO] Initializing Group Policy infrastructure...");

    let mut state = GPO_STATE.lock();
    state.running = true;

    // Create local machine GPO
    drop(state); // Release lock before calling create_gpo
    if let Ok(lgpo_id) = create_gpo("Local Computer Policy", GpoScope::Local) {
        crate::serial_println!("[GPO] Created Local Computer Policy (GPO {})", lgpo_id);
    }

    crate::serial_println!("[GPO] Group Policy initialized");
}

/// Shutdown Group Policy
pub fn shutdown() {
    crate::serial_println!("[GPO] Shutting down Group Policy...");

    let mut state = GPO_STATE.lock();
    state.running = false;

    let (created, deleted, applied, refreshes, _) = get_statistics();
    crate::serial_println!("[GPO] Stats: {} GPOs created, {} deleted, {} policies applied, {} refreshes",
        created, deleted, applied, refreshes);
}
