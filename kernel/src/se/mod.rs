//! Security Reference Monitor (se)
//!
//! The security subsystem enforces access control:
//!
//! - **Access Tokens**: Security context for processes/threads
//! - **Security Identifiers (SIDs)**: User/group identification
//! - **Access Control Lists (ACLs)**: Permission lists
//! - **Access Checks**: Permission verification
//! - **Privileges**: Special capabilities (SeDebugPrivilege, etc.)
//! - **Impersonation**: Thread-level security context switching
//!
//! # Security Descriptor
//!
//! Each object can have:
//! - Owner SID
//! - Group SID
//! - DACL (Discretionary ACL) - who can access
//! - SACL (System ACL) - auditing
//!
//! # Key Structures
//!
//! - `TOKEN`: Access token
//! - `SID`: Security identifier
//! - `ACL`: Access control list
//! - `SECURITY_DESCRIPTOR`: Full security info

pub mod sid;
pub mod privilege;
pub mod acl;
pub mod descriptor;
pub mod token;
pub mod access;
pub mod audit;

// Re-export SID types
pub use sid::{
    Sid,
    SidAndAttributes,
    SID_MAX_SUB_AUTHORITIES,
    SID_REVISION,
    identifier_authority,
    well_known_rids,
    sid_attributes,
    // Well-known SIDs
    SID_NULL,
    SID_WORLD,
    SID_LOCAL_SYSTEM,
    SID_LOCAL_SERVICE,
    SID_NETWORK_SERVICE,
    SID_BUILTIN_ADMINISTRATORS,
    SID_BUILTIN_USERS,
    SID_AUTHENTICATED_USERS,
    // Functions
    se_allocate_sid,
    se_free_sid,
    rtl_copy_sid,
};

// Re-export privilege types
pub use privilege::{
    Luid,
    LuidAndAttributes,
    PrivilegeSet,
    SE_MAX_PRIVILEGES,
    privilege_attributes,
    privilege_values,
    privilege_luids,
    privilege_control,
    // Functions
    se_privilege_check,
    se_privilege_check_all,
    se_privilege_check_any,
    se_single_privilege_check,
};

// Re-export ACL types
pub use acl::{
    Acl,
    AceType,
    AceHeader,
    AccessAllowedAce,
    AccessDeniedAce,
    SystemAuditAce,
    SimpleAce,
    SimpleAcl,
    StaticAcl,
    ACL_REVISION,
    MAX_ACE_COUNT,
    ace_flags,
    generic_rights,
    standard_rights,
    special_rights,
};

// Re-export security descriptor types
pub use descriptor::{
    SecurityDescriptor,
    SimpleSecurityDescriptor,
    SECURITY_DESCRIPTOR_REVISION,
    sd_control,
    se_allocate_security_descriptor,
    se_free_security_descriptor,
    create_system_security_descriptor,
};

// Re-export token types
pub use token::{
    Token,
    TokenType,
    SecurityImpersonationLevel,
    TokenElevationType,
    TokenSource,
    TokenStatistics,
    TokenPoolStats,
    TokenSnapshot,
    TOKEN_MAX_GROUPS,
    MAX_TOKENS,
    se_create_token,
    se_free_token,
    se_create_system_token,
    se_get_system_token,
    get_token_stats,
    se_get_token_snapshots,
    token_type_name,
    impersonation_level_name,
};

// Re-export access check types
pub use access::{
    AccessCheckResult,
    GenericMapping,
    se_access_check,
    se_access_check_simple,
    se_check_delete_access,
    se_check_read_control,
    se_check_write_dac,
    se_check_write_owner,
    se_check_tcb_privilege,
    se_check_debug_privilege,
    se_check_security_privilege,
    se_check_backup_privilege,
    se_check_restore_privilege,
    se_open_object_audit,
};

// Re-export audit types
pub use audit::{
    AuditEventCategory,
    AuditEventType,
    AuditParameterType,
    AuditParameter,
    AuditParameterArray,
    AuditWorkItem,
    AuditBounds,
    AuditOptions,
    AuditPolicy,
    audit_event_id,
    // Core audit functions
    sep_adt_init,
    sep_adt_set_bounds,
    sep_adt_get_bounds,
    sep_adt_set_crash_on_fail,
    sep_adt_get_crash_on_fail,
    sep_adt_set_policy,
    sep_adt_get_policy,
    sep_adt_set_options,
    sep_adt_get_options,
    sep_adt_should_audit,
    sep_adt_log_audit_record,
    sep_adt_dequeue_work_item,
    sep_adt_get_queue_length,
    sep_adt_clear_queue,
    sep_adt_get_recent,
    sep_adt_get_stats,
    sep_adt_get_all_policies,
    // Convenience audit functions
    se_audit_logon_success,
    se_audit_logon_failure,
    se_audit_logoff,
    se_audit_object_access,
    se_audit_privilege_use,
    se_audit_process_created,
    se_audit_process_exit,
    se_audit_policy_change,
    se_audit_user_created,
    se_audit_system_startup,
    se_audit_system_shutdown,
    audit_category_name,
};

/// Initialize the Security Reference Monitor
///
/// This initializes all security subsystems in the correct order:
/// 1. SID subsystem
/// 2. Privilege subsystem
/// 3. ACL subsystem
/// 4. Security descriptor subsystem
/// 5. Token subsystem
/// 6. Access check subsystem
/// 7. Audit subsystem
pub fn init() {
    crate::serial_println!("[SE] Initializing Security Reference Monitor...");

    // Initialize subsystems
    sid::init();
    privilege::init();
    acl::init();
    descriptor::init();
    token::init();
    access::init();
    audit::sep_adt_init();

    crate::serial_println!("[SE] Security Reference Monitor initialized");
}
