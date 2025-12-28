//! Access Check Implementation
//!
//! The Security Reference Monitor performs access checks to determine
//! whether a security principal (represented by a token) is allowed
//! to perform a requested operation on an object.
//!
//! # Access Check Algorithm
//! 1. If no DACL, grant all access
//! 2. If empty DACL, deny all access
//! 3. Process ACEs in order:
//!    - For each ACE matching the token's user or groups:
//!      - If ACCESS_DENIED: deny those access rights
//!      - If ACCESS_ALLOWED: grant those access rights
//! 4. After processing all ACEs:
//!    - If all requested rights granted: success
//!    - Otherwise: access denied
//!
//! # Special Cases
//! - Owner always has READ_CONTROL and WRITE_DAC
//! - SeSecurityPrivilege grants ACCESS_SYSTEM_SECURITY
//! - SeBackupPrivilege grants read access for backup
//! - SeRestorePrivilege grants write access for restore
//! - SeTakeOwnershipPrivilege grants WRITE_OWNER

use super::token::Token;
use super::descriptor::SimpleSecurityDescriptor;
use super::acl::{AceType, SimpleAce, generic_rights, standard_rights, special_rights};
use super::privilege::privilege_luids;

/// Access check result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessCheckResult {
    /// Access granted
    Granted,
    /// Access denied
    Denied,
    /// Access denied - no DACL (null DACL grants all)
    DeniedNoSD,
    /// Privilege required
    PrivilegeRequired,
}

/// Generic mapping - maps generic rights to specific rights
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GenericMapping {
    pub generic_read: u32,
    pub generic_write: u32,
    pub generic_execute: u32,
    pub generic_all: u32,
}

impl GenericMapping {
    pub const fn new() -> Self {
        Self {
            generic_read: standard_rights::STANDARD_RIGHTS_READ,
            generic_write: standard_rights::STANDARD_RIGHTS_WRITE,
            generic_execute: standard_rights::STANDARD_RIGHTS_EXECUTE,
            generic_all: standard_rights::STANDARD_RIGHTS_ALL,
        }
    }

    /// Map generic rights to specific rights
    pub fn map_generic(&self, access_mask: u32) -> u32 {
        let mut result = access_mask;

        if (result & generic_rights::GENERIC_READ) != 0 {
            result &= !generic_rights::GENERIC_READ;
            result |= self.generic_read;
        }
        if (result & generic_rights::GENERIC_WRITE) != 0 {
            result &= !generic_rights::GENERIC_WRITE;
            result |= self.generic_write;
        }
        if (result & generic_rights::GENERIC_EXECUTE) != 0 {
            result &= !generic_rights::GENERIC_EXECUTE;
            result |= self.generic_execute;
        }
        if (result & generic_rights::GENERIC_ALL) != 0 {
            result &= !generic_rights::GENERIC_ALL;
            result |= self.generic_all;
        }

        result
    }
}

impl Default for GenericMapping {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform an access check
///
/// # Arguments
/// * `token` - The access token representing the security context
/// * `sd` - The security descriptor of the object
/// * `desired_access` - The requested access rights
/// * `generic_mapping` - Mapping from generic to specific rights
///
/// # Returns
/// * `Ok(granted_access)` - Access granted with the resulting access mask
/// * `Err(AccessCheckResult)` - Access denied with reason
pub fn se_access_check(
    token: &Token,
    sd: &SimpleSecurityDescriptor,
    desired_access: u32,
    generic_mapping: &GenericMapping,
) -> Result<u32, AccessCheckResult> {
    // Validate security descriptor
    if !sd.is_valid() {
        return Err(AccessCheckResult::DeniedNoSD);
    }

    // Map generic rights to specific rights
    let mut remaining = generic_mapping.map_generic(desired_access);
    let mut granted: u32 = 0;
    let mut denied: u32 = 0;

    // Handle MAXIMUM_ALLOWED
    let maximum_allowed = (remaining & special_rights::MAXIMUM_ALLOWED) != 0;
    remaining &= !special_rights::MAXIMUM_ALLOWED;

    // Handle ACCESS_SYSTEM_SECURITY - requires SeSecurityPrivilege
    if (remaining & special_rights::ACCESS_SYSTEM_SECURITY) != 0 {
        if token.is_privilege_enabled(privilege_luids::SE_SECURITY_LUID) {
            granted |= special_rights::ACCESS_SYSTEM_SECURITY;
            remaining &= !special_rights::ACCESS_SYSTEM_SECURITY;
        } else {
            return Err(AccessCheckResult::PrivilegeRequired);
        }
    }

    // Check for owner - owner gets READ_CONTROL and WRITE_DAC
    if sd.owner_present && token.is_member(&sd.owner) {
        granted |= standard_rights::READ_CONTROL | standard_rights::WRITE_DAC;
        remaining &= !(standard_rights::READ_CONTROL | standard_rights::WRITE_DAC);
    }

    // Handle WRITE_OWNER - requires SeTakeOwnershipPrivilege
    if (remaining & standard_rights::WRITE_OWNER) != 0 {
        if token.is_privilege_enabled(privilege_luids::SE_TAKE_OWNERSHIP_LUID) {
            granted |= standard_rights::WRITE_OWNER;
            remaining &= !standard_rights::WRITE_OWNER;
        }
    }

    // Check backup/restore privileges
    if token.is_privilege_enabled(privilege_luids::SE_BACKUP_LUID) {
        // SeBackupPrivilege grants all read access
        let read_rights = standard_rights::READ_CONTROL | generic_mapping.generic_read;
        granted |= remaining & read_rights;
        remaining &= !read_rights;
    }

    if token.is_privilege_enabled(privilege_luids::SE_RESTORE_LUID) {
        // SeRestorePrivilege grants all write access
        let write_rights = standard_rights::WRITE_DAC | standard_rights::WRITE_OWNER |
                          standard_rights::DELETE | generic_mapping.generic_write;
        granted |= remaining & write_rights;
        remaining &= !write_rights;
    }

    // If no DACL present, grant all remaining access
    if (sd.control & super::descriptor::sd_control::SE_DACL_PRESENT) == 0 {
        granted |= remaining;
        remaining = 0;
    } else if sd.dacl.is_empty() {
        // Empty DACL denies all access
        denied = remaining;
    } else {
        // Process ACEs in order
        for i in 0..sd.dacl.ace_count as usize {
            if let Some(ace) = sd.dacl.get_ace(i) {
                // Check if ACE applies to this token
                if !ace_applies_to_token(ace, token) {
                    continue;
                }

                let ace_mask = generic_mapping.map_generic(ace.mask);

                match ace.ace_type {
                    AceType::AccessDenied => {
                        // Deny ACE - mark rights as denied
                        denied |= ace_mask & remaining;
                        // For maximum allowed, track what's denied
                        if maximum_allowed {
                            denied |= ace_mask;
                        }
                    }
                    AceType::AccessAllowed => {
                        // Allow ACE - only grant rights not yet denied
                        let can_grant = ace_mask & !denied;
                        granted |= can_grant & remaining;
                        remaining &= !can_grant;
                    }
                    _ => {
                        // Other ACE types (audit, etc.) don't affect access
                    }
                }
            }
        }
    }

    // For maximum allowed, return what we got
    if maximum_allowed {
        return Ok(granted);
    }

    // Check if all requested rights were granted
    if remaining == 0 || (remaining & !granted) == 0 {
        Ok(granted | (desired_access & !remaining))
    } else {
        Err(AccessCheckResult::Denied)
    }
}

/// Check if an ACE applies to a token
fn ace_applies_to_token(ace: &SimpleAce, token: &Token) -> bool {
    // Check if ACE SID matches token's user
    if token.is_user(&ace.sid) {
        return true;
    }

    // Check if ACE SID matches any of token's groups
    token.has_group(&ace.sid)
}

/// Simplified access check for common cases
///
/// Returns true if all requested access is granted.
pub fn se_access_check_simple(
    token: &Token,
    sd: &SimpleSecurityDescriptor,
    desired_access: u32,
) -> bool {
    let mapping = GenericMapping::new();
    se_access_check(token, sd, desired_access, &mapping).is_ok()
}

/// Check if token can open object for deletion
pub fn se_check_delete_access(token: &Token, sd: &SimpleSecurityDescriptor) -> bool {
    se_access_check_simple(token, sd, standard_rights::DELETE)
}

/// Check if token can read object's security descriptor
pub fn se_check_read_control(token: &Token, sd: &SimpleSecurityDescriptor) -> bool {
    se_access_check_simple(token, sd, standard_rights::READ_CONTROL)
}

/// Check if token can modify object's DACL
pub fn se_check_write_dac(token: &Token, sd: &SimpleSecurityDescriptor) -> bool {
    se_access_check_simple(token, sd, standard_rights::WRITE_DAC)
}

/// Check if token can take ownership of object
pub fn se_check_write_owner(token: &Token, sd: &SimpleSecurityDescriptor) -> bool {
    se_access_check_simple(token, sd, standard_rights::WRITE_OWNER)
}

// ============================================================================
// Privilege Checking
// ============================================================================

/// Check if a privilege is held and enabled
pub fn se_privilege_check(token: &Token, privilege: super::privilege::Luid) -> bool {
    token.is_privilege_enabled(privilege)
}

/// Check for single privilege, with option to audit
pub fn se_single_privilege_check(
    token: &Token,
    privilege: super::privilege::Luid,
    _previous_mode: u8, // 0 = kernel, 1 = user
) -> bool {
    // In user mode, the privilege must be enabled
    // In kernel mode, we might be more lenient
    token.is_privilege_enabled(privilege)
}

/// Check if token has TCB privilege (Trusted Computing Base)
pub fn se_check_tcb_privilege(token: &Token) -> bool {
    se_privilege_check(token, privilege_luids::SE_TCB_LUID)
}

/// Check if token has Debug privilege
pub fn se_check_debug_privilege(token: &Token) -> bool {
    se_privilege_check(token, privilege_luids::SE_DEBUG_LUID)
}

/// Check if token has Security privilege
pub fn se_check_security_privilege(token: &Token) -> bool {
    se_privilege_check(token, privilege_luids::SE_SECURITY_LUID)
}

/// Check if token has Backup privilege
pub fn se_check_backup_privilege(token: &Token) -> bool {
    se_privilege_check(token, privilege_luids::SE_BACKUP_LUID)
}

/// Check if token has Restore privilege
pub fn se_check_restore_privilege(token: &Token) -> bool {
    se_privilege_check(token, privilege_luids::SE_RESTORE_LUID)
}

// ============================================================================
// Audit Support (Stubs)
// ============================================================================

/// Generate audit for object access
pub fn se_open_object_audit(
    _object_type_name: &[u8],
    _object_name: &[u8],
    _token: &Token,
    _desired_access: u32,
    _granted_access: u32,
    _access_granted: bool,
) {
    // Auditing not implemented yet
    // Would write to security event log
}

/// Initialize access check subsystem
pub fn init() {
    crate::serial_println!("[SE] Access check subsystem initialized");
}
