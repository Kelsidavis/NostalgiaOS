//! Security Descriptor Implementation
//!
//! A security descriptor contains the security information for an object:
//! - Owner SID: Who owns the object
//! - Group SID: Primary group of the object
//! - DACL: Discretionary ACL - who can access the object
//! - SACL: System ACL - auditing information
//!
//! # Formats
//! - Self-relative: All data in one contiguous block (for storage/transmission)
//! - Absolute: Contains pointers to separate structures (for manipulation)

use core::ptr;
use super::sid::Sid;
use super::acl::{Acl, SimpleAcl};
use crate::ke::SpinLock;

/// Security descriptor revision
pub const SECURITY_DESCRIPTOR_REVISION: u8 = 1;

/// Security descriptor control flags
pub mod sd_control {
    /// Owner defaulted (set by RM, not creator)
    pub const SE_OWNER_DEFAULTED: u16 = 0x0001;
    /// Group defaulted
    pub const SE_GROUP_DEFAULTED: u16 = 0x0002;
    /// DACL present
    pub const SE_DACL_PRESENT: u16 = 0x0004;
    /// DACL defaulted
    pub const SE_DACL_DEFAULTED: u16 = 0x0008;
    /// SACL present
    pub const SE_SACL_PRESENT: u16 = 0x0010;
    /// SACL defaulted
    pub const SE_SACL_DEFAULTED: u16 = 0x0020;
    /// DACL auto-inherited by children
    pub const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
    /// SACL auto-inherited by children
    pub const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
    /// DACL was auto-inherited
    pub const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
    /// SACL was auto-inherited
    pub const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
    /// DACL protected from inheritance
    pub const SE_DACL_PROTECTED: u16 = 0x1000;
    /// SACL protected from inheritance
    pub const SE_SACL_PROTECTED: u16 = 0x2000;
    /// Resource manager control bits
    pub const SE_RM_CONTROL_VALID: u16 = 0x4000;
    /// Self-relative format
    pub const SE_SELF_RELATIVE: u16 = 0x8000;
}

/// Security Descriptor structure (absolute format)
///
/// In Windows, this structure uses pointers to separate allocations.
/// Our simplified version uses inline storage.
#[repr(C)]
pub struct SecurityDescriptor {
    /// Revision (always 1)
    pub revision: u8,
    /// Padding
    pub sbz1: u8,
    /// Control flags
    pub control: u16,
    /// Owner SID
    pub owner: *mut Sid,
    /// Group SID
    pub group: *mut Sid,
    /// System ACL (for auditing)
    pub sacl: *mut Acl,
    /// Discretionary ACL (for access control)
    pub dacl: *mut Acl,
}

impl SecurityDescriptor {
    /// Create a new empty security descriptor
    pub const fn new() -> Self {
        Self {
            revision: SECURITY_DESCRIPTOR_REVISION,
            sbz1: 0,
            control: 0,
            owner: ptr::null_mut(),
            group: ptr::null_mut(),
            sacl: ptr::null_mut(),
            dacl: ptr::null_mut(),
        }
    }

    /// Check if this security descriptor is valid
    pub fn is_valid(&self) -> bool {
        self.revision == SECURITY_DESCRIPTOR_REVISION
    }

    /// Check if owner is present
    pub fn has_owner(&self) -> bool {
        !self.owner.is_null()
    }

    /// Check if group is present
    pub fn has_group(&self) -> bool {
        !self.group.is_null()
    }

    /// Check if DACL is present
    pub fn has_dacl(&self) -> bool {
        (self.control & sd_control::SE_DACL_PRESENT) != 0
    }

    /// Check if SACL is present
    pub fn has_sacl(&self) -> bool {
        (self.control & sd_control::SE_SACL_PRESENT) != 0
    }

    /// Check if this is in self-relative format
    pub fn is_self_relative(&self) -> bool {
        (self.control & sd_control::SE_SELF_RELATIVE) != 0
    }

    /// Set the owner SID
    pub fn set_owner(&mut self, owner: *mut Sid) {
        self.owner = owner;
        self.control &= !sd_control::SE_OWNER_DEFAULTED;
    }

    /// Set the group SID
    pub fn set_group(&mut self, group: *mut Sid) {
        self.group = group;
        self.control &= !sd_control::SE_GROUP_DEFAULTED;
    }

    /// Set the DACL
    pub fn set_dacl(&mut self, dacl: *mut Acl, present: bool, defaulted: bool) {
        self.dacl = dacl;
        if present {
            self.control |= sd_control::SE_DACL_PRESENT;
        } else {
            self.control &= !sd_control::SE_DACL_PRESENT;
        }
        if defaulted {
            self.control |= sd_control::SE_DACL_DEFAULTED;
        } else {
            self.control &= !sd_control::SE_DACL_DEFAULTED;
        }
    }

    /// Set the SACL
    pub fn set_sacl(&mut self, sacl: *mut Acl, present: bool, defaulted: bool) {
        self.sacl = sacl;
        if present {
            self.control |= sd_control::SE_SACL_PRESENT;
        } else {
            self.control &= !sd_control::SE_SACL_PRESENT;
        }
        if defaulted {
            self.control |= sd_control::SE_SACL_DEFAULTED;
        } else {
            self.control &= !sd_control::SE_SACL_DEFAULTED;
        }
    }
}

impl Default for SecurityDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: SecurityDescriptor is designed for kernel use
unsafe impl Sync for SecurityDescriptor {}
unsafe impl Send for SecurityDescriptor {}

// ============================================================================
// Simplified Security Descriptor (with inline storage)
// ============================================================================

/// Simplified security descriptor with inline storage
///
/// This avoids dynamic allocation by embedding the SIDs and ACL directly.
#[repr(C)]
pub struct SimpleSecurityDescriptor {
    /// Revision
    pub revision: u8,
    /// Control flags
    pub control: u16,
    /// Owner SID (inline)
    pub owner: Sid,
    /// Owner is present
    pub owner_present: bool,
    /// Group SID (inline)
    pub group: Sid,
    /// Group is present
    pub group_present: bool,
    /// DACL (inline, simplified)
    pub dacl: SimpleAcl,
}

impl SimpleSecurityDescriptor {
    pub const fn new() -> Self {
        Self {
            revision: SECURITY_DESCRIPTOR_REVISION,
            control: 0,
            owner: Sid::new(),
            owner_present: false,
            group: Sid::new(),
            group_present: false,
            dacl: SimpleAcl::new(),
        }
    }

    /// Check if valid
    pub fn is_valid(&self) -> bool {
        self.revision == SECURITY_DESCRIPTOR_REVISION
    }

    /// Set the owner
    pub fn set_owner(&mut self, owner: Sid) {
        self.owner = owner;
        self.owner_present = true;
        self.control &= !sd_control::SE_OWNER_DEFAULTED;
    }

    /// Set the group
    pub fn set_group(&mut self, group: Sid) {
        self.group = group;
        self.group_present = true;
        self.control &= !sd_control::SE_GROUP_DEFAULTED;
    }

    /// Set the DACL as present
    pub fn set_dacl_present(&mut self, present: bool) {
        if present {
            self.control |= sd_control::SE_DACL_PRESENT;
        } else {
            self.control &= !sd_control::SE_DACL_PRESENT;
        }
    }

    /// Add an access allowed entry to the DACL
    pub fn add_access_allowed(&mut self, sid: Sid, mask: u32) -> bool {
        if self.dacl.add_access_allowed(sid, mask) {
            self.set_dacl_present(true);
            true
        } else {
            false
        }
    }

    /// Add an access denied entry to the DACL
    pub fn add_access_denied(&mut self, sid: Sid, mask: u32) -> bool {
        if self.dacl.add_access_denied(sid, mask) {
            self.set_dacl_present(true);
            true
        } else {
            false
        }
    }
}

impl Default for SimpleSecurityDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Security Descriptor Pool
// ============================================================================

/// Maximum number of security descriptors
pub const MAX_SECURITY_DESCRIPTORS: usize = 64;

/// Security descriptor pool
static mut SD_POOL: [SimpleSecurityDescriptor; MAX_SECURITY_DESCRIPTORS] = {
    const INIT: SimpleSecurityDescriptor = SimpleSecurityDescriptor::new();
    [INIT; MAX_SECURITY_DESCRIPTORS]
};

/// Security descriptor pool bitmap
static mut SD_POOL_BITMAP: u64 = 0;

/// Security descriptor pool lock
static SD_POOL_LOCK: SpinLock<()> = SpinLock::new(());

/// Allocate a security descriptor
pub unsafe fn se_allocate_security_descriptor() -> *mut SimpleSecurityDescriptor {
    let _guard = SD_POOL_LOCK.lock();

    for i in 0..MAX_SECURITY_DESCRIPTORS {
        if SD_POOL_BITMAP & (1 << i) == 0 {
            SD_POOL_BITMAP |= 1 << i;
            let sd = &mut SD_POOL[i] as *mut SimpleSecurityDescriptor;
            *sd = SimpleSecurityDescriptor::new();
            return sd;
        }
    }

    ptr::null_mut()
}

/// Free a security descriptor
pub unsafe fn se_free_security_descriptor(sd: *mut SimpleSecurityDescriptor) {
    if sd.is_null() {
        return;
    }

    let _guard = SD_POOL_LOCK.lock();

    let base = SD_POOL.as_ptr() as usize;
    let offset = sd as usize - base;
    let index = offset / core::mem::size_of::<SimpleSecurityDescriptor>();

    if index < MAX_SECURITY_DESCRIPTORS {
        SD_POOL_BITMAP &= !(1 << index);
    }
}

/// Create a default security descriptor for system objects
pub fn create_system_security_descriptor() -> SimpleSecurityDescriptor {
    let mut sd = SimpleSecurityDescriptor::new();

    // System is the owner
    sd.set_owner(super::sid::SID_LOCAL_SYSTEM);

    // Administrators group
    sd.set_group(super::sid::SID_BUILTIN_ADMINISTRATORS);

    // DACL: System and Administrators have full access
    sd.add_access_allowed(
        super::sid::SID_LOCAL_SYSTEM,
        super::acl::generic_rights::GENERIC_ALL,
    );
    sd.add_access_allowed(
        super::sid::SID_BUILTIN_ADMINISTRATORS,
        super::acl::generic_rights::GENERIC_ALL,
    );

    sd
}

/// Initialize security descriptor subsystem
pub fn init() {
    crate::serial_println!("[SE] Security descriptor subsystem initialized ({} SDs available)", MAX_SECURITY_DESCRIPTORS);
}
