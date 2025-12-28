//! Privilege Implementation
//!
//! Privileges are special rights that allow holders to perform
//! system-level operations that would otherwise be denied.
//!
//! # Privilege Model
//! - Privileges are assigned to tokens during logon
//! - Most privileges are disabled by default
//! - Programs must explicitly enable privileges before use
//! - Some privileges are very powerful (SeDebugPrivilege, SeTcbPrivilege)
//!
//! # Common Privileges
//! - SeDebugPrivilege: Debug any process
//! - SeBackupPrivilege: Bypass file security for backup
//! - SeRestorePrivilege: Bypass file security for restore
//! - SeShutdownPrivilege: Shut down the system
//! - SeTakeOwnershipPrivilege: Take ownership of objects

/// Maximum number of privileges
pub const SE_MAX_PRIVILEGES: usize = 36;

/// Privilege LUID (Locally Unique Identifier)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Luid {
    pub low_part: u32,
    pub high_part: i32,
}

impl Luid {
    pub const fn new(low: u32, high: i32) -> Self {
        Self {
            low_part: low,
            high_part: high,
        }
    }

    pub const fn from_u32(value: u32) -> Self {
        Self {
            low_part: value,
            high_part: 0,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.low_part == 0 && self.high_part == 0
    }
}

impl Default for Luid {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Privilege attribute flags
pub mod privilege_attributes {
    /// Privilege is disabled
    pub const SE_PRIVILEGE_DISABLED: u32 = 0x00000000;
    /// Privilege is enabled by default
    pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x00000001;
    /// Privilege is enabled
    pub const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;
    /// Privilege was used for access check
    pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x80000000;
    /// Privilege is removed
    pub const SE_PRIVILEGE_REMOVED: u32 = 0x00000004;
}

/// LUID and Attributes - privilege with its current state
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LuidAndAttributes {
    /// The privilege LUID
    pub luid: Luid,
    /// Current attributes (enabled/disabled)
    pub attributes: u32,
}

impl LuidAndAttributes {
    pub const fn new() -> Self {
        Self {
            luid: Luid::new(0, 0),
            attributes: 0,
        }
    }

    pub const fn with_luid(luid: Luid, attributes: u32) -> Self {
        Self { luid, attributes }
    }

    /// Check if this privilege is enabled
    pub fn is_enabled(&self) -> bool {
        (self.attributes & privilege_attributes::SE_PRIVILEGE_ENABLED) != 0
    }

    /// Check if this privilege is enabled by default
    pub fn is_enabled_by_default(&self) -> bool {
        (self.attributes & privilege_attributes::SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0
    }

    /// Enable this privilege
    pub fn enable(&mut self) {
        self.attributes |= privilege_attributes::SE_PRIVILEGE_ENABLED;
    }

    /// Disable this privilege
    pub fn disable(&mut self) {
        self.attributes &= !privilege_attributes::SE_PRIVILEGE_ENABLED;
    }
}

impl Default for LuidAndAttributes {
    fn default() -> Self {
        Self::new()
    }
}

/// Privilege Set - collection of privileges for access checking
#[repr(C)]
pub struct PrivilegeSet {
    /// Number of privileges
    pub privilege_count: u32,
    /// Control flags
    pub control: u32,
    /// Array of privileges (variable length)
    pub privilege: [LuidAndAttributes; SE_MAX_PRIVILEGES],
}

impl PrivilegeSet {
    pub const fn new() -> Self {
        Self {
            privilege_count: 0,
            control: 0,
            privilege: [LuidAndAttributes::new(); SE_MAX_PRIVILEGES],
        }
    }
}

impl Default for PrivilegeSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Privilege control flags for PrivilegeSet
pub mod privilege_control {
    /// All privileges must be held (AND)
    pub const PRIVILEGE_SET_ALL_NECESSARY: u32 = 1;
}

// ============================================================================
// Well-Known Privilege LUIDs
// ============================================================================

/// Privilege indices (used as LUID low_part)
pub mod privilege_values {
    pub const SE_CREATE_TOKEN_PRIVILEGE: u32 = 2;
    pub const SE_ASSIGNPRIMARYTOKEN_PRIVILEGE: u32 = 3;
    pub const SE_LOCK_MEMORY_PRIVILEGE: u32 = 4;
    pub const SE_INCREASE_QUOTA_PRIVILEGE: u32 = 5;
    pub const SE_MACHINE_ACCOUNT_PRIVILEGE: u32 = 6;
    pub const SE_TCB_PRIVILEGE: u32 = 7;
    pub const SE_SECURITY_PRIVILEGE: u32 = 8;
    pub const SE_TAKE_OWNERSHIP_PRIVILEGE: u32 = 9;
    pub const SE_LOAD_DRIVER_PRIVILEGE: u32 = 10;
    pub const SE_SYSTEM_PROFILE_PRIVILEGE: u32 = 11;
    pub const SE_SYSTEMTIME_PRIVILEGE: u32 = 12;
    pub const SE_PROF_SINGLE_PROCESS_PRIVILEGE: u32 = 13;
    pub const SE_INC_BASE_PRIORITY_PRIVILEGE: u32 = 14;
    pub const SE_CREATE_PAGEFILE_PRIVILEGE: u32 = 15;
    pub const SE_CREATE_PERMANENT_PRIVILEGE: u32 = 16;
    pub const SE_BACKUP_PRIVILEGE: u32 = 17;
    pub const SE_RESTORE_PRIVILEGE: u32 = 18;
    pub const SE_SHUTDOWN_PRIVILEGE: u32 = 19;
    pub const SE_DEBUG_PRIVILEGE: u32 = 20;
    pub const SE_AUDIT_PRIVILEGE: u32 = 21;
    pub const SE_SYSTEM_ENVIRONMENT_PRIVILEGE: u32 = 22;
    pub const SE_CHANGE_NOTIFY_PRIVILEGE: u32 = 23;
    pub const SE_REMOTE_SHUTDOWN_PRIVILEGE: u32 = 24;
    pub const SE_UNDOCK_PRIVILEGE: u32 = 25;
    pub const SE_SYNC_AGENT_PRIVILEGE: u32 = 26;
    pub const SE_ENABLE_DELEGATION_PRIVILEGE: u32 = 27;
    pub const SE_MANAGE_VOLUME_PRIVILEGE: u32 = 28;
    pub const SE_IMPERSONATE_PRIVILEGE: u32 = 29;
    pub const SE_CREATE_GLOBAL_PRIVILEGE: u32 = 30;
    pub const SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE: u32 = 31;
    pub const SE_RELABEL_PRIVILEGE: u32 = 32;
    pub const SE_INC_WORKING_SET_PRIVILEGE: u32 = 33;
    pub const SE_TIME_ZONE_PRIVILEGE: u32 = 34;
    pub const SE_CREATE_SYMBOLIC_LINK_PRIVILEGE: u32 = 35;
}

/// Well-known privilege LUIDs
pub mod privilege_luids {
    use super::{Luid, privilege_values::*};

    pub const SE_CREATE_TOKEN_LUID: Luid = Luid::from_u32(SE_CREATE_TOKEN_PRIVILEGE);
    pub const SE_ASSIGNPRIMARYTOKEN_LUID: Luid = Luid::from_u32(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE);
    pub const SE_LOCK_MEMORY_LUID: Luid = Luid::from_u32(SE_LOCK_MEMORY_PRIVILEGE);
    pub const SE_INCREASE_QUOTA_LUID: Luid = Luid::from_u32(SE_INCREASE_QUOTA_PRIVILEGE);
    pub const SE_TCB_LUID: Luid = Luid::from_u32(SE_TCB_PRIVILEGE);
    pub const SE_SECURITY_LUID: Luid = Luid::from_u32(SE_SECURITY_PRIVILEGE);
    pub const SE_TAKE_OWNERSHIP_LUID: Luid = Luid::from_u32(SE_TAKE_OWNERSHIP_PRIVILEGE);
    pub const SE_LOAD_DRIVER_LUID: Luid = Luid::from_u32(SE_LOAD_DRIVER_PRIVILEGE);
    pub const SE_SYSTEM_PROFILE_LUID: Luid = Luid::from_u32(SE_SYSTEM_PROFILE_PRIVILEGE);
    pub const SE_SYSTEMTIME_LUID: Luid = Luid::from_u32(SE_SYSTEMTIME_PRIVILEGE);
    pub const SE_PROF_SINGLE_PROCESS_LUID: Luid = Luid::from_u32(SE_PROF_SINGLE_PROCESS_PRIVILEGE);
    pub const SE_INC_BASE_PRIORITY_LUID: Luid = Luid::from_u32(SE_INC_BASE_PRIORITY_PRIVILEGE);
    pub const SE_CREATE_PAGEFILE_LUID: Luid = Luid::from_u32(SE_CREATE_PAGEFILE_PRIVILEGE);
    pub const SE_CREATE_PERMANENT_LUID: Luid = Luid::from_u32(SE_CREATE_PERMANENT_PRIVILEGE);
    pub const SE_BACKUP_LUID: Luid = Luid::from_u32(SE_BACKUP_PRIVILEGE);
    pub const SE_RESTORE_LUID: Luid = Luid::from_u32(SE_RESTORE_PRIVILEGE);
    pub const SE_SHUTDOWN_LUID: Luid = Luid::from_u32(SE_SHUTDOWN_PRIVILEGE);
    pub const SE_DEBUG_LUID: Luid = Luid::from_u32(SE_DEBUG_PRIVILEGE);
    pub const SE_AUDIT_LUID: Luid = Luid::from_u32(SE_AUDIT_PRIVILEGE);
    pub const SE_SYSTEM_ENVIRONMENT_LUID: Luid = Luid::from_u32(SE_SYSTEM_ENVIRONMENT_PRIVILEGE);
    pub const SE_CHANGE_NOTIFY_LUID: Luid = Luid::from_u32(SE_CHANGE_NOTIFY_PRIVILEGE);
    pub const SE_REMOTE_SHUTDOWN_LUID: Luid = Luid::from_u32(SE_REMOTE_SHUTDOWN_PRIVILEGE);
    pub const SE_UNDOCK_LUID: Luid = Luid::from_u32(SE_UNDOCK_PRIVILEGE);
    pub const SE_IMPERSONATE_LUID: Luid = Luid::from_u32(SE_IMPERSONATE_PRIVILEGE);
    pub const SE_CREATE_GLOBAL_LUID: Luid = Luid::from_u32(SE_CREATE_GLOBAL_PRIVILEGE);
    pub const SE_MANAGE_VOLUME_LUID: Luid = Luid::from_u32(SE_MANAGE_VOLUME_PRIVILEGE);
}

// ============================================================================
// Privilege Operations
// ============================================================================

/// Check if a privilege is held in a privilege set
pub fn se_privilege_check(
    required: &LuidAndAttributes,
    privileges: &PrivilegeSet,
) -> bool {
    for i in 0..privileges.privilege_count as usize {
        if i >= SE_MAX_PRIVILEGES {
            break;
        }
        let priv_entry = &privileges.privilege[i];
        if priv_entry.luid == required.luid && priv_entry.is_enabled() {
            return true;
        }
    }
    false
}

/// Check if all required privileges are held
pub fn se_privilege_check_all(
    required: &[LuidAndAttributes],
    privileges: &PrivilegeSet,
) -> bool {
    for req in required {
        if !se_privilege_check(req, privileges) {
            return false;
        }
    }
    true
}

/// Check if any required privileges are held
pub fn se_privilege_check_any(
    required: &[LuidAndAttributes],
    privileges: &PrivilegeSet,
) -> bool {
    for req in required {
        if se_privilege_check(req, privileges) {
            return true;
        }
    }
    false
}

/// Check if a single privilege LUID is held and enabled
pub fn se_single_privilege_check(
    luid: Luid,
    privileges: &PrivilegeSet,
) -> bool {
    for i in 0..privileges.privilege_count as usize {
        if i >= SE_MAX_PRIVILEGES {
            break;
        }
        let priv_entry = &privileges.privilege[i];
        if priv_entry.luid == luid && priv_entry.is_enabled() {
            return true;
        }
    }
    false
}

/// Initialize privilege subsystem
pub fn init() {
    crate::serial_println!("[SE] Privilege subsystem initialized ({} privileges defined)", SE_MAX_PRIVILEGES);
}
