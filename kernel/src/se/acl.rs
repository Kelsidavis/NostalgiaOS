//! Access Control List (ACL) Implementation
//!
//! ACLs contain Access Control Entries (ACEs) that specify access rights
//! for security principals (users, groups).
//!
//! # ACL Types
//! - DACL (Discretionary ACL): Controls access to an object
//! - SACL (System ACL): Controls auditing
//!
//! # ACE Types
//! - ACCESS_ALLOWED_ACE: Grants access
//! - ACCESS_DENIED_ACE: Denies access (processed first)
//! - SYSTEM_AUDIT_ACE: Audits access attempts
//!
//! # ACE Ordering
//! ACEs are processed in order. Denied ACEs should come before allowed.
//! The recommended order is:
//! 1. Explicit deny ACEs
//! 2. Explicit allow ACEs
//! 3. Inherited deny ACEs
//! 4. Inherited allow ACEs

use core::ptr;
use super::sid::Sid;

/// ACL revision
pub const ACL_REVISION: u8 = 2;
pub const ACL_REVISION_DS: u8 = 4;

/// Maximum ACL size
pub const MAX_ACL_SIZE: usize = 4096;

/// Maximum number of ACEs in an ACL
pub const MAX_ACE_COUNT: usize = 64;

/// Access Control List header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Acl {
    /// ACL revision
    pub acl_revision: u8,
    /// Padding
    pub sbz1: u8,
    /// Total size of the ACL in bytes
    pub acl_size: u16,
    /// Number of ACEs in the ACL
    pub ace_count: u16,
    /// Padding
    pub sbz2: u16,
}

impl Acl {
    pub const fn new() -> Self {
        Self {
            acl_revision: ACL_REVISION,
            sbz1: 0,
            acl_size: core::mem::size_of::<Self>() as u16,
            ace_count: 0,
            sbz2: 0,
        }
    }

    /// Check if this ACL is valid
    pub fn is_valid(&self) -> bool {
        (self.acl_revision == ACL_REVISION || self.acl_revision == ACL_REVISION_DS) &&
        self.acl_size >= core::mem::size_of::<Self>() as u16
    }

    /// Check if this ACL is empty
    pub fn is_empty(&self) -> bool {
        self.ace_count == 0
    }
}

impl Default for Acl {
    fn default() -> Self {
        Self::new()
    }
}

/// ACE types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AceType {
    /// Access allowed
    AccessAllowed = 0,
    /// Access denied
    AccessDenied = 1,
    /// System audit
    SystemAudit = 2,
    /// System alarm (not used)
    SystemAlarm = 3,
    /// Access allowed (compound - not used)
    AccessAllowedCompound = 4,
    /// Access allowed (object-specific)
    AccessAllowedObject = 5,
    /// Access denied (object-specific)
    AccessDeniedObject = 6,
    /// System audit (object-specific)
    SystemAuditObject = 7,
    /// System alarm (object-specific)
    SystemAlarmObject = 8,
    /// Access allowed (callback)
    AccessAllowedCallback = 9,
    /// Access denied (callback)
    AccessDeniedCallback = 10,
    /// Access allowed (callback, object-specific)
    AccessAllowedCallbackObject = 11,
    /// Access denied (callback, object-specific)
    AccessDeniedCallbackObject = 12,
    /// System audit (callback)
    SystemAuditCallback = 13,
    /// System alarm (callback)
    SystemAlarmCallback = 14,
    /// System audit (callback, object-specific)
    SystemAuditCallbackObject = 15,
    /// System alarm (callback, object-specific)
    SystemAlarmCallbackObject = 16,
    /// Mandatory label
    SystemMandatoryLabel = 17,
}

/// ACE flags
pub mod ace_flags {
    /// ACE inherited from parent container
    pub const OBJECT_INHERIT_ACE: u8 = 0x01;
    /// ACE inherited by sub-containers
    pub const CONTAINER_INHERIT_ACE: u8 = 0x02;
    /// Don't propagate inherit flags
    pub const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
    /// ACE applies only to inherited objects
    pub const INHERIT_ONLY_ACE: u8 = 0x08;
    /// ACE was inherited
    pub const INHERITED_ACE: u8 = 0x10;
    /// Audit on successful access
    pub const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;
    /// Audit on failed access
    pub const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;
}

/// ACE header - common to all ACE types
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AceHeader {
    /// ACE type
    pub ace_type: u8,
    /// ACE flags
    pub ace_flags: u8,
    /// Size of the entire ACE
    pub ace_size: u16,
}

impl AceHeader {
    pub const fn new(ace_type: AceType) -> Self {
        Self {
            ace_type: ace_type as u8,
            ace_flags: 0,
            ace_size: 0,
        }
    }

    /// Get the ACE type
    pub fn get_type(&self) -> Option<AceType> {
        match self.ace_type {
            0 => Some(AceType::AccessAllowed),
            1 => Some(AceType::AccessDenied),
            2 => Some(AceType::SystemAudit),
            3 => Some(AceType::SystemAlarm),
            17 => Some(AceType::SystemMandatoryLabel),
            _ => None,
        }
    }

    /// Check if this ACE is inherited
    pub fn is_inherited(&self) -> bool {
        (self.ace_flags & ace_flags::INHERITED_ACE) != 0
    }

    /// Check if this ACE is inherit-only
    pub fn is_inherit_only(&self) -> bool {
        (self.ace_flags & ace_flags::INHERIT_ONLY_ACE) != 0
    }
}

impl Default for AceHeader {
    fn default() -> Self {
        Self::new(AceType::AccessAllowed)
    }
}

/// Access Allowed ACE
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AccessAllowedAce {
    /// ACE header
    pub header: AceHeader,
    /// Access mask being granted
    pub mask: u32,
    /// SID of the trustee (variable length follows)
    pub sid_start: u32,
}

impl AccessAllowedAce {
    pub const fn new() -> Self {
        Self {
            header: AceHeader::new(AceType::AccessAllowed),
            mask: 0,
            sid_start: 0,
        }
    }
}

impl Default for AccessAllowedAce {
    fn default() -> Self {
        Self::new()
    }
}

/// Access Denied ACE
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AccessDeniedAce {
    /// ACE header
    pub header: AceHeader,
    /// Access mask being denied
    pub mask: u32,
    /// SID of the trustee (variable length follows)
    pub sid_start: u32,
}

impl AccessDeniedAce {
    pub const fn new() -> Self {
        Self {
            header: AceHeader::new(AceType::AccessDenied),
            mask: 0,
            sid_start: 0,
        }
    }
}

impl Default for AccessDeniedAce {
    fn default() -> Self {
        Self::new()
    }
}

/// System Audit ACE
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SystemAuditAce {
    /// ACE header
    pub header: AceHeader,
    /// Access mask to audit
    pub mask: u32,
    /// SID of the trustee (variable length follows)
    pub sid_start: u32,
}

impl SystemAuditAce {
    pub const fn new() -> Self {
        Self {
            header: AceHeader::new(AceType::SystemAudit),
            mask: 0,
            sid_start: 0,
        }
    }
}

impl Default for SystemAuditAce {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Generic Access Rights
// ============================================================================

/// Generic access rights (mapped to specific rights per object type)
pub mod generic_rights {
    pub const GENERIC_READ: u32 = 0x80000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    pub const GENERIC_ALL: u32 = 0x10000000;
}

/// Standard access rights (apply to all object types)
pub mod standard_rights {
    pub const DELETE: u32 = 0x00010000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const SYNCHRONIZE: u32 = 0x00100000;

    pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F0000;
    pub const STANDARD_RIGHTS_READ: u32 = READ_CONTROL;
    pub const STANDARD_RIGHTS_WRITE: u32 = READ_CONTROL;
    pub const STANDARD_RIGHTS_EXECUTE: u32 = READ_CONTROL;
    pub const STANDARD_RIGHTS_ALL: u32 = 0x001F0000;
}

/// Special access rights
pub mod special_rights {
    pub const ACCESS_SYSTEM_SECURITY: u32 = 0x01000000;
    pub const MAXIMUM_ALLOWED: u32 = 0x02000000;
}

// ============================================================================
// Static ACL Storage
// ============================================================================

/// Static ACL structure for fixed-size allocations
#[repr(C)]
pub struct StaticAcl {
    /// ACL header
    pub header: Acl,
    /// ACE storage
    pub ace_data: [u8; MAX_ACL_SIZE - 8],
}

impl StaticAcl {
    pub const fn new() -> Self {
        Self {
            header: Acl::new(),
            ace_data: [0; MAX_ACL_SIZE - 8],
        }
    }

    /// Initialize as an empty ACL
    pub fn init(&mut self) {
        self.header = Acl::new();
        self.header.acl_size = MAX_ACL_SIZE as u16;
    }

    /// Get the ACL header
    pub fn acl(&self) -> &Acl {
        &self.header
    }

    /// Get the ACL header mutably
    pub fn acl_mut(&mut self) -> &mut Acl {
        &mut self.header
    }
}

impl Default for StaticAcl {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Simple ACE storage (for our static allocation model)
// ============================================================================

/// Simplified ACE for static storage
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SimpleAce {
    /// ACE type (allow/deny/audit)
    pub ace_type: AceType,
    /// ACE flags
    pub flags: u8,
    /// Access mask
    pub mask: u32,
    /// SID (inline, not pointer)
    pub sid: Sid,
}

impl SimpleAce {
    pub const fn new() -> Self {
        Self {
            ace_type: AceType::AccessAllowed,
            flags: 0,
            mask: 0,
            sid: Sid::new(),
        }
    }

    /// Create an access allowed ACE
    pub fn access_allowed(sid: Sid, mask: u32) -> Self {
        Self {
            ace_type: AceType::AccessAllowed,
            flags: 0,
            mask,
            sid,
        }
    }

    /// Create an access denied ACE
    pub fn access_denied(sid: Sid, mask: u32) -> Self {
        Self {
            ace_type: AceType::AccessDenied,
            flags: 0,
            mask,
            sid,
        }
    }

    /// Check if this is an allow ACE
    pub fn is_allow(&self) -> bool {
        matches!(self.ace_type, AceType::AccessAllowed)
    }

    /// Check if this is a deny ACE
    pub fn is_deny(&self) -> bool {
        matches!(self.ace_type, AceType::AccessDenied)
    }

    /// Check if this ACE applies to the given SID
    pub fn applies_to(&self, sid: &Sid) -> bool {
        self.sid.equal(sid)
    }
}

impl Default for SimpleAce {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple ACL structure for our static model
#[repr(C)]
pub struct SimpleAcl {
    /// Revision
    pub revision: u8,
    /// Number of ACEs
    pub ace_count: u8,
    /// ACEs (fixed array)
    pub aces: [SimpleAce; MAX_ACE_COUNT],
}

impl SimpleAcl {
    pub const fn new() -> Self {
        Self {
            revision: ACL_REVISION,
            ace_count: 0,
            aces: [SimpleAce::new(); MAX_ACE_COUNT],
        }
    }

    /// Add an ACE to the ACL
    pub fn add_ace(&mut self, ace: SimpleAce) -> bool {
        if (self.ace_count as usize) >= MAX_ACE_COUNT {
            return false;
        }

        self.aces[self.ace_count as usize] = ace;
        self.ace_count += 1;
        true
    }

    /// Add an access allowed ACE
    pub fn add_access_allowed(&mut self, sid: Sid, mask: u32) -> bool {
        self.add_ace(SimpleAce::access_allowed(sid, mask))
    }

    /// Add an access denied ACE
    pub fn add_access_denied(&mut self, sid: Sid, mask: u32) -> bool {
        self.add_ace(SimpleAce::access_denied(sid, mask))
    }

    /// Check if the ACL is empty
    pub fn is_empty(&self) -> bool {
        self.ace_count == 0
    }

    /// Get an ACE by index
    pub fn get_ace(&self, index: usize) -> Option<&SimpleAce> {
        if index < self.ace_count as usize {
            Some(&self.aces[index])
        } else {
            None
        }
    }
}

impl Default for SimpleAcl {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize ACL subsystem
pub fn init() {
    crate::serial_println!("[SE] ACL subsystem initialized");
}
