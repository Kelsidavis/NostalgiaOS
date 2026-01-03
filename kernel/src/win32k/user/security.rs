//! Security UI Dialogs
//!
//! Implements Windows security-related UI dialogs and authorization prompts.
//! Provides access control editor, permission dialogs, and elevation UI.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/aclui.h` - ACL editor definitions
//! - `shell/osshell/security/aclui/` - ACL editor implementation
//! - `ds/security/azroles/azui/` - Authorization UI

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::HWND;

// ============================================================================
// Constants
// ============================================================================

/// Maximum ACL entries displayed
const MAX_ACL_ENTRIES: usize = 64;

/// Maximum object name length
const MAX_OBJECT_NAME: usize = 260;

/// Maximum security descriptor size
const MAX_SD_SIZE: usize = 4096;

/// Maximum principal name length
const MAX_PRINCIPAL_NAME: usize = 256;

/// Maximum permission name length
const MAX_PERMISSION_NAME: usize = 64;

// ============================================================================
// Security Information Flags
// ============================================================================

bitflags::bitflags! {
    /// Security information flags (SECURITY_INFORMATION)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct SecurityInfo: u32 {
        const OWNER_SECURITY_INFORMATION = 0x00000001;
        const GROUP_SECURITY_INFORMATION = 0x00000002;
        const DACL_SECURITY_INFORMATION = 0x00000004;
        const SACL_SECURITY_INFORMATION = 0x00000008;
        const LABEL_SECURITY_INFORMATION = 0x00000010;
        const ATTRIBUTE_SECURITY_INFORMATION = 0x00000020;
        const SCOPE_SECURITY_INFORMATION = 0x00000040;
        const PROCESS_TRUST_LABEL = 0x00000080;
        const BACKUP_SECURITY_INFORMATION = 0x00010000;
        const PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
        const PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000;
        const UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000;
        const UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000;
    }
}

// ============================================================================
// ACL Editor Flags
// ============================================================================

bitflags::bitflags! {
    /// ACL editor initialization flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct AclEditorFlags: u32 {
        /// Container object
        const SI_CONTAINER = 0x00000004;
        /// Edit perms
        const SI_EDIT_PERMS = 0x00000000;
        /// Edit audits
        const SI_EDIT_AUDITS = 0x00000002;
        /// Edit owner
        const SI_EDIT_OWNER = 0x00000001;
        /// Edit effective
        const SI_EDIT_EFFECTIVE = 0x00020000;
        /// Advanced button
        const SI_ADVANCED = 0x00000010;
        /// Edit all
        const SI_EDIT_ALL = Self::SI_EDIT_PERMS.bits() | Self::SI_EDIT_AUDITS.bits() | Self::SI_EDIT_OWNER.bits();
        /// Reset permissions
        const SI_RESET = 0x00000020;
        /// Owner read-only
        const SI_OWNER_READONLY = 0x00000040;
        /// No ACL protect
        const SI_NO_ACL_PROTECT = 0x00000200;
        /// No tree apply
        const SI_NO_TREE_APPLY = 0x00000400;
        /// No additional permission
        const SI_NO_ADDITIONAL_PERMISSION = 0x00200000;
        /// View only
        const SI_VIEW_ONLY = 0x00400000;
        /// Page title
        const SI_PAGE_TITLE = 0x00000800;
        /// Server is DC
        const SI_SERVER_IS_DC = 0x00001000;
        /// Object GUID
        const SI_OBJECT_GUID = 0x00010000;
        /// Enable inherited
        const SI_ENABLE_INHERITED = 0x00004000;
        /// Enable edit attribute
        const SI_ENABLE_EDIT_ATTRIBUTE = 0x00008000;
        /// Readonly
        const SI_READONLY = 0x00800000;
    }
}

// ============================================================================
// Access Rights
// ============================================================================

/// Standard access rights
pub mod rights {
    pub const DELETE: u32 = 0x00010000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const SYNCHRONIZE: u32 = 0x00100000;

    pub const STANDARD_RIGHTS_REQUIRED: u32 = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER;
    pub const STANDARD_RIGHTS_READ: u32 = READ_CONTROL;
    pub const STANDARD_RIGHTS_WRITE: u32 = READ_CONTROL;
    pub const STANDARD_RIGHTS_EXECUTE: u32 = READ_CONTROL;
    pub const STANDARD_RIGHTS_ALL: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE;

    // Generic rights
    pub const GENERIC_READ: u32 = 0x80000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    pub const GENERIC_ALL: u32 = 0x10000000;

    // File-specific rights
    pub const FILE_READ_DATA: u32 = 0x0001;
    pub const FILE_WRITE_DATA: u32 = 0x0002;
    pub const FILE_APPEND_DATA: u32 = 0x0004;
    pub const FILE_READ_EA: u32 = 0x0008;
    pub const FILE_WRITE_EA: u32 = 0x0010;
    pub const FILE_EXECUTE: u32 = 0x0020;
    pub const FILE_DELETE_CHILD: u32 = 0x0040;
    pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;

    // Registry-specific rights
    pub const KEY_QUERY_VALUE: u32 = 0x0001;
    pub const KEY_SET_VALUE: u32 = 0x0002;
    pub const KEY_CREATE_SUB_KEY: u32 = 0x0004;
    pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
    pub const KEY_NOTIFY: u32 = 0x0010;
    pub const KEY_CREATE_LINK: u32 = 0x0020;
}

// ============================================================================
// ACE Types
// ============================================================================

/// Access control entry types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AceType {
    #[default]
    AccessAllowed = 0,
    AccessDenied = 1,
    SystemAudit = 2,
    SystemAlarm = 3,
    AccessAllowedCompound = 4,
    AccessAllowedObject = 5,
    AccessDeniedObject = 6,
    SystemAuditObject = 7,
    SystemAlarmObject = 8,
    AccessAllowedCallback = 9,
    AccessDeniedCallback = 10,
    AccessAllowedCallbackObject = 11,
    AccessDeniedCallbackObject = 12,
    SystemAuditCallback = 13,
    SystemAlarmCallback = 14,
    SystemAuditCallbackObject = 15,
    SystemAlarmCallbackObject = 16,
    SystemMandatoryLabel = 17,
}

// ACE flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct AceFlags: u8 {
        const OBJECT_INHERIT_ACE = 0x01;
        const CONTAINER_INHERIT_ACE = 0x02;
        const NO_PROPAGATE_INHERIT_ACE = 0x04;
        const INHERIT_ONLY_ACE = 0x08;
        const INHERITED_ACE = 0x10;
        const SUCCESSFUL_ACCESS_ACE_FLAG = 0x40;
        const FAILED_ACCESS_ACE_FLAG = 0x80;
    }
}

// ============================================================================
// Security Structures
// ============================================================================

/// Access permission entry
#[derive(Debug, Clone)]
pub struct AccessEntry {
    pub ace_type: AceType,
    pub ace_flags: AceFlags,
    pub access_mask: u32,
    pub principal_name: [u8; MAX_PRINCIPAL_NAME],
    pub inherited: bool,
}

impl AccessEntry {
    pub const fn new() -> Self {
        Self {
            ace_type: AceType::AccessAllowed,
            ace_flags: AceFlags::empty(),
            access_mask: 0,
            principal_name: [0u8; MAX_PRINCIPAL_NAME],
            inherited: false,
        }
    }

    pub fn set_principal(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_PRINCIPAL_NAME - 1);
        self.principal_name[..len].copy_from_slice(&name[..len]);
        self.principal_name[len] = 0;
    }
}

impl Default for AccessEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Permission definition for UI
#[derive(Debug, Clone)]
pub struct PermissionDef {
    pub access_mask: u32,
    pub name: [u8; MAX_PERMISSION_NAME],
    pub description: [u8; 128],
}

impl PermissionDef {
    pub const fn new() -> Self {
        Self {
            access_mask: 0,
            name: [0u8; MAX_PERMISSION_NAME],
            description: [0u8; 128],
        }
    }
}

impl Default for PermissionDef {
    fn default() -> Self {
        Self::new()
    }
}

/// Security descriptor info
#[derive(Debug)]
pub struct SecurityDescriptorInfo {
    pub object_name: [u8; MAX_OBJECT_NAME],
    pub object_type: ObjectType,
    pub owner: [u8; MAX_PRINCIPAL_NAME],
    pub group: [u8; MAX_PRINCIPAL_NAME],
    pub dacl_entries: [AccessEntry; MAX_ACL_ENTRIES],
    pub dacl_count: usize,
    pub sacl_entries: [AccessEntry; MAX_ACL_ENTRIES],
    pub sacl_count: usize,
    pub flags: AclEditorFlags,
}

impl SecurityDescriptorInfo {
    pub fn new() -> Self {
        Self {
            object_name: [0u8; MAX_OBJECT_NAME],
            object_type: ObjectType::Unknown,
            owner: [0u8; MAX_PRINCIPAL_NAME],
            group: [0u8; MAX_PRINCIPAL_NAME],
            dacl_entries: [const { AccessEntry::new() }; MAX_ACL_ENTRIES],
            dacl_count: 0,
            sacl_entries: [const { AccessEntry::new() }; MAX_ACL_ENTRIES],
            sacl_count: 0,
            flags: AclEditorFlags::empty(),
        }
    }
}

impl Default for SecurityDescriptorInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Object Types
// ============================================================================

/// Object types for security UI
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ObjectType {
    #[default]
    Unknown = 0,
    File = 1,
    Directory = 2,
    RegistryKey = 3,
    Service = 4,
    Printer = 5,
    Share = 6,
    Process = 7,
    Thread = 8,
    Job = 9,
    Desktop = 10,
    WindowStation = 11,
    Semaphore = 12,
    Mutex = 13,
    Event = 14,
    Timer = 15,
    Token = 16,
    Section = 17,
    Symlink = 18,
}

// ============================================================================
// ACL Editor Callbacks
// ============================================================================

/// Result from ACL editor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclEditorResult {
    Ok,
    Cancel,
    Apply,
    Error(u32),
}

// ============================================================================
// State
// ============================================================================

static SECURITY_INITIALIZED: AtomicBool = AtomicBool::new(false);
static DIALOG_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize security UI subsystem
pub fn init() {
    if SECURITY_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[SECURITY UI] Initializing security UI...");
    crate::serial_println!("[SECURITY UI] Security UI initialized");
}

// ============================================================================
// ACL Editor Functions
// ============================================================================

/// Show the ACL editor dialog
pub fn edit_security(
    hwnd_owner: HWND,
    object_name: &[u8],
    object_type: ObjectType,
    info: &mut SecurityDescriptorInfo,
) -> AclEditorResult {
    let _ = hwnd_owner;

    DIALOG_COUNT.fetch_add(1, Ordering::SeqCst);

    // Copy object name
    let len = object_name.len().min(MAX_OBJECT_NAME - 1);
    info.object_name[..len].copy_from_slice(&object_name[..len]);
    info.object_name[len] = 0;
    info.object_type = object_type;

    crate::serial_println!("[SECURITY UI] Edit security dialog opened for {:?}", object_type);

    // Would display the ACL editor dialog
    AclEditorResult::Ok
}

/// Create an ACL editor page (for property sheets)
pub fn create_security_page(
    info: &SecurityDescriptorInfo,
    flags: AclEditorFlags,
) -> HWND {
    let _ = (info, flags);

    // Would create a property page for the ACL editor
    super::UserHandle::NULL
}

// ============================================================================
// Permission Dialog Functions
// ============================================================================

/// Show simple permissions dialog
pub fn show_permissions_dialog(
    hwnd_owner: HWND,
    object_name: &[u8],
    entries: &[AccessEntry],
) -> AclEditorResult {
    let _ = (hwnd_owner, object_name, entries);

    crate::serial_println!("[SECURITY UI] Permissions dialog shown");

    AclEditorResult::Ok
}

/// Show advanced permissions dialog
pub fn show_advanced_permissions(
    hwnd_owner: HWND,
    info: &mut SecurityDescriptorInfo,
) -> AclEditorResult {
    let _ = hwnd_owner;

    crate::serial_println!("[SECURITY UI] Advanced permissions dialog shown");

    // Would show advanced permissions editor
    info.flags |= AclEditorFlags::SI_ADVANCED;

    AclEditorResult::Ok
}

// ============================================================================
// Owner/Group Dialog
// ============================================================================

/// Show owner selection dialog
pub fn show_owner_dialog(
    hwnd_owner: HWND,
    current_owner: &[u8],
    new_owner: &mut [u8],
) -> bool {
    let _ = (hwnd_owner, current_owner);

    crate::serial_println!("[SECURITY UI] Owner dialog shown");

    // Would display owner selection dialog
    // For now, just keep current owner
    if !new_owner.is_empty() {
        new_owner[0] = 0;
    }

    false // No change
}

/// Show group selection dialog
pub fn show_group_dialog(
    hwnd_owner: HWND,
    current_group: &[u8],
    new_group: &mut [u8],
) -> bool {
    let _ = (hwnd_owner, current_group);

    crate::serial_println!("[SECURITY UI] Group dialog shown");

    if !new_group.is_empty() {
        new_group[0] = 0;
    }

    false
}

// ============================================================================
// Principal Selection (Object Picker)
// ============================================================================

// Object picker scope
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct PickerScope: u32 {
        const TARGET_COMPUTER = 0x00000001;
        const UPLEVEL_JOINED_DOMAIN = 0x00000002;
        const DOWNLEVEL_JOINED_DOMAIN = 0x00000004;
        const ENTERPRISE_DOMAIN = 0x00000008;
        const GLOBAL_CATALOG = 0x00000010;
        const EXTERNAL_UPLEVEL_DOMAIN = 0x00000020;
        const EXTERNAL_DOWNLEVEL_DOMAIN = 0x00000040;
        const WORKGROUP = 0x00000080;
        const USER_ENTERED_UPLEVEL_SCOPE = 0x00000100;
        const USER_ENTERED_DOWNLEVEL_SCOPE = 0x00000200;
    }
}

// Object picker filter
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct PickerFilter: u32 {
        const USERS = 0x00000001;
        const GROUPS = 0x00000002;
        const COMPUTERS = 0x00000004;
        const CONTACTS = 0x00000008;
        const BUILTIN_GROUPS = 0x00000010;
        const WELL_KNOWN_PRINCIPALS = 0x00000020;
        const UNIVERSAL_GROUPS = 0x00000040;
        const GLOBAL_GROUPS = 0x00000080;
        const DOMAIN_LOCAL_GROUPS = 0x00000100;
        const ALL_GROUPS = Self::GROUPS.bits() | Self::BUILTIN_GROUPS.bits() |
                          Self::WELL_KNOWN_PRINCIPALS.bits() | Self::UNIVERSAL_GROUPS.bits() |
                          Self::GLOBAL_GROUPS.bits() | Self::DOMAIN_LOCAL_GROUPS.bits();
        const ALL = Self::USERS.bits() | Self::ALL_GROUPS.bits() | Self::COMPUTERS.bits();
    }
}

/// Show object picker dialog
pub fn show_object_picker(
    hwnd_owner: HWND,
    scope: PickerScope,
    filter: PickerFilter,
    multi_select: bool,
    selected: &mut [[u8; MAX_PRINCIPAL_NAME]],
) -> usize {
    let _ = (hwnd_owner, scope, filter, multi_select);

    crate::serial_println!("[SECURITY UI] Object picker shown");

    // Would display the object picker dialog
    // Return 0 selections for now
    if !selected.is_empty() {
        selected[0][0] = 0;
    }

    0
}

// ============================================================================
// Elevation UI
// ============================================================================

/// Elevation reason
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ElevationReason {
    #[default]
    Unknown = 0,
    RequireAdmin = 1,
    HighIntegrity = 2,
    MediumIntegrity = 3,
    LowIntegrity = 4,
    UntrustedIntegrity = 5,
}

/// Elevation result
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ElevationResult {
    #[default]
    Denied = 0,
    Approved = 1,
    Cancelled = 2,
    Error = 3,
}

/// Show elevation prompt (UAC-style dialog)
pub fn show_elevation_prompt(
    hwnd_owner: HWND,
    application_name: &[u8],
    publisher: &[u8],
    reason: ElevationReason,
) -> ElevationResult {
    let _ = (hwnd_owner, application_name, publisher);

    crate::serial_println!("[SECURITY UI] Elevation prompt shown, reason: {:?}", reason);

    // Would display UAC-style elevation prompt
    // For now, approve all elevations
    ElevationResult::Approved
}

/// Show consent UI for elevation
pub fn show_consent_ui(
    hwnd_owner: HWND,
    application_name: &[u8],
    command_line: &[u8],
) -> ElevationResult {
    let _ = (hwnd_owner, application_name, command_line);

    crate::serial_println!("[SECURITY UI] Consent UI shown");

    ElevationResult::Approved
}

// ============================================================================
// Certificate Trust Dialog
// ============================================================================

/// Certificate trust level
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CertTrustLevel {
    #[default]
    Untrusted = 0,
    Trusted = 1,
    PartiallyTrusted = 2,
    Revoked = 3,
    Expired = 4,
}

/// Certificate info for display
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: [u8; 256],
    pub issuer: [u8; 256],
    pub valid_from: u64,
    pub valid_to: u64,
    pub thumbprint: [u8; 64],
    pub trust_level: CertTrustLevel,
}

impl CertificateInfo {
    pub const fn new() -> Self {
        Self {
            subject: [0u8; 256],
            issuer: [0u8; 256],
            valid_from: 0,
            valid_to: 0,
            thumbprint: [0u8; 64],
            trust_level: CertTrustLevel::Untrusted,
        }
    }
}

impl Default for CertificateInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Show certificate dialog
pub fn show_certificate_dialog(
    hwnd_owner: HWND,
    cert_info: &CertificateInfo,
) -> bool {
    let _ = (hwnd_owner, cert_info);

    crate::serial_println!("[SECURITY UI] Certificate dialog shown");

    true
}

/// Show certificate trust dialog
pub fn show_certificate_trust_dialog(
    hwnd_owner: HWND,
    cert_info: &CertificateInfo,
    publisher_name: &[u8],
) -> bool {
    let _ = (hwnd_owner, cert_info, publisher_name);

    crate::serial_println!("[SECURITY UI] Certificate trust dialog shown");

    // Would prompt user to trust certificate
    true
}

// ============================================================================
// Password Dialog
// ============================================================================

// Password dialog flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct PasswordFlags: u32 {
        const REQUIRE_STRONG = 0x00000001;
        const SHOW_STRENGTH = 0x00000002;
        const CONFIRM = 0x00000004;
        const SHOW_TOGGLE = 0x00000008;
    }
}

/// Show password change dialog
pub fn show_password_change_dialog(
    hwnd_owner: HWND,
    username: &[u8],
    domain: &[u8],
    flags: PasswordFlags,
) -> bool {
    let _ = (hwnd_owner, username, domain, flags);

    crate::serial_println!("[SECURITY UI] Password change dialog shown");

    // Would display password change dialog
    false
}

/// Show password entry dialog
pub fn show_password_dialog(
    hwnd_owner: HWND,
    prompt: &[u8],
    flags: PasswordFlags,
    password: &mut [u8],
) -> bool {
    let _ = (hwnd_owner, prompt, flags);

    if !password.is_empty() {
        password[0] = 0;
    }

    crate::serial_println!("[SECURITY UI] Password dialog shown");

    false
}

// ============================================================================
// Audit Policy Dialog
// ============================================================================

/// Show audit policy dialog
pub fn show_audit_policy_dialog(
    hwnd_owner: HWND,
    info: &mut SecurityDescriptorInfo,
) -> AclEditorResult {
    let _ = hwnd_owner;

    info.flags |= AclEditorFlags::SI_EDIT_AUDITS;

    crate::serial_println!("[SECURITY UI] Audit policy dialog shown");

    AclEditorResult::Ok
}

// ============================================================================
// Effective Permissions Dialog
// ============================================================================

/// Show effective permissions dialog
pub fn show_effective_permissions(
    hwnd_owner: HWND,
    object_name: &[u8],
    principal_name: &[u8],
    effective_rights: &mut u32,
) -> bool {
    let _ = (hwnd_owner, object_name, principal_name);

    *effective_rights = 0;

    crate::serial_println!("[SECURITY UI] Effective permissions dialog shown");

    true
}

// ============================================================================
// Permission Definitions
// ============================================================================

/// Get standard file permissions
pub fn get_file_permissions() -> &'static [PermissionDef] {
    static FILE_PERMS: [PermissionDef; 6] = [
        PermissionDef {
            access_mask: rights::GENERIC_READ,
            name: *b"Read\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            description: [0u8; 128],
        },
        PermissionDef {
            access_mask: rights::GENERIC_WRITE,
            name: *b"Write\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            description: [0u8; 128],
        },
        PermissionDef {
            access_mask: rights::GENERIC_EXECUTE,
            name: *b"Execute\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            description: [0u8; 128],
        },
        PermissionDef {
            access_mask: rights::DELETE,
            name: *b"Delete\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            description: [0u8; 128],
        },
        PermissionDef {
            access_mask: rights::READ_CONTROL,
            name: *b"Read Permissions\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            description: [0u8; 128],
        },
        PermissionDef {
            access_mask: rights::GENERIC_ALL,
            name: *b"Full Control\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            description: [0u8; 128],
        },
    ];
    &FILE_PERMS
}

/// Get standard registry permissions
pub fn get_registry_permissions() -> &'static [PermissionDef] {
    static REG_PERMS: [PermissionDef; 4] = [
        PermissionDef {
            access_mask: rights::KEY_QUERY_VALUE | rights::KEY_ENUMERATE_SUB_KEYS | rights::KEY_NOTIFY,
            name: *b"Read\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            description: [0u8; 128],
        },
        PermissionDef {
            access_mask: rights::KEY_SET_VALUE | rights::KEY_CREATE_SUB_KEY,
            name: *b"Write\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            description: [0u8; 128],
        },
        PermissionDef {
            access_mask: rights::DELETE,
            name: *b"Delete\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            description: [0u8; 128],
        },
        PermissionDef {
            access_mask: rights::GENERIC_ALL,
            name: *b"Full Control\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            description: [0u8; 128],
        },
    ];
    &REG_PERMS
}

// ============================================================================
// Statistics
// ============================================================================

/// Security UI statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityStats {
    pub initialized: bool,
    pub dialogs_shown: u32,
}

/// Get security UI statistics
pub fn get_stats() -> SecurityStats {
    SecurityStats {
        initialized: SECURITY_INITIALIZED.load(Ordering::Relaxed),
        dialogs_shown: DIALOG_COUNT.load(Ordering::Relaxed),
    }
}
