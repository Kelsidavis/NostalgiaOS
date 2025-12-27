//! Security Identifier (SID) Implementation
//!
//! A SID uniquely identifies a security principal (user, group, or computer).
//! SIDs have the format: S-R-I-S-S-S...
//! - S: Literal 'S' identifying a SID string
//! - R: Revision level (always 1)
//! - I: Identifier authority (48-bit)
//! - S: Sub-authorities (32-bit each, variable count)
//!
//! # Well-Known SIDs
//! - S-1-0-0: Null SID
//! - S-1-1-0: World (Everyone)
//! - S-1-5-18: Local System
//! - S-1-5-19: Local Service
//! - S-1-5-20: Network Service
//! - S-1-5-32-544: Administrators

use core::ptr;

/// Maximum number of sub-authorities in a SID
pub const SID_MAX_SUB_AUTHORITIES: usize = 15;

/// SID revision
pub const SID_REVISION: u8 = 1;

/// Identifier Authority values
pub mod identifier_authority {
    /// Null authority
    pub const SECURITY_NULL_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 0];
    /// World authority (Everyone)
    pub const SECURITY_WORLD_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 1];
    /// Local authority
    pub const SECURITY_LOCAL_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 2];
    /// Creator authority
    pub const SECURITY_CREATOR_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 3];
    /// Non-unique authority
    pub const SECURITY_NON_UNIQUE_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 4];
    /// NT authority (most common)
    pub const SECURITY_NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];
}

/// Well-known relative identifiers (RIDs)
pub mod well_known_rids {
    /// Null RID
    pub const SECURITY_NULL_RID: u32 = 0;
    /// World RID (Everyone)
    pub const SECURITY_WORLD_RID: u32 = 0;
    /// Local RID
    pub const SECURITY_LOCAL_RID: u32 = 0;
    /// Creator owner RID
    pub const SECURITY_CREATOR_OWNER_RID: u32 = 0;
    /// Creator group RID
    pub const SECURITY_CREATOR_GROUP_RID: u32 = 1;

    /// NT Authority sub-authorities
    pub const SECURITY_DIALUP_RID: u32 = 1;
    pub const SECURITY_NETWORK_RID: u32 = 2;
    pub const SECURITY_BATCH_RID: u32 = 3;
    pub const SECURITY_INTERACTIVE_RID: u32 = 4;
    pub const SECURITY_SERVICE_RID: u32 = 6;
    pub const SECURITY_ANONYMOUS_LOGON_RID: u32 = 7;
    pub const SECURITY_PROXY_RID: u32 = 8;
    pub const SECURITY_ENTERPRISE_CONTROLLERS_RID: u32 = 9;
    pub const SECURITY_PRINCIPAL_SELF_RID: u32 = 10;
    pub const SECURITY_AUTHENTICATED_USER_RID: u32 = 11;
    pub const SECURITY_RESTRICTED_CODE_RID: u32 = 12;
    pub const SECURITY_TERMINAL_SERVER_RID: u32 = 13;
    pub const SECURITY_LOCAL_SYSTEM_RID: u32 = 18;
    pub const SECURITY_LOCAL_SERVICE_RID: u32 = 19;
    pub const SECURITY_NETWORK_SERVICE_RID: u32 = 20;

    /// Built-in domain RID
    pub const SECURITY_BUILTIN_DOMAIN_RID: u32 = 32;

    /// Built-in group RIDs
    pub const DOMAIN_ALIAS_RID_ADMINS: u32 = 544;
    pub const DOMAIN_ALIAS_RID_USERS: u32 = 545;
    pub const DOMAIN_ALIAS_RID_GUESTS: u32 = 546;
    pub const DOMAIN_ALIAS_RID_POWER_USERS: u32 = 547;
}

/// Security Identifier (SID)
///
/// Variable-length structure identifying a security principal.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sid {
    /// Revision (always 1)
    pub revision: u8,
    /// Number of sub-authorities
    pub sub_authority_count: u8,
    /// Identifier authority (6 bytes, big-endian)
    pub identifier_authority: [u8; 6],
    /// Sub-authorities (variable length)
    pub sub_authority: [u32; SID_MAX_SUB_AUTHORITIES],
}

impl Sid {
    /// Create a new empty SID
    pub const fn new() -> Self {
        Self {
            revision: SID_REVISION,
            sub_authority_count: 0,
            identifier_authority: [0; 6],
            sub_authority: [0; SID_MAX_SUB_AUTHORITIES],
        }
    }

    /// Create a SID with the given authority and sub-authorities
    pub fn create(authority: [u8; 6], sub_authorities: &[u32]) -> Option<Self> {
        if sub_authorities.len() > SID_MAX_SUB_AUTHORITIES {
            return None;
        }

        let mut sid = Self::new();
        sid.identifier_authority = authority;
        sid.sub_authority_count = sub_authorities.len() as u8;

        for (i, &sa) in sub_authorities.iter().enumerate() {
            sid.sub_authority[i] = sa;
        }

        Some(sid)
    }

    /// Get the size of this SID in bytes
    pub fn length(&self) -> usize {
        // Header (revision + count + authority) + sub-authorities
        8 + (self.sub_authority_count as usize * 4)
    }

    /// Check if this is a valid SID
    pub fn is_valid(&self) -> bool {
        self.revision == SID_REVISION &&
        self.sub_authority_count <= SID_MAX_SUB_AUTHORITIES as u8
    }

    /// Get the last sub-authority (RID)
    pub fn get_rid(&self) -> Option<u32> {
        if self.sub_authority_count > 0 {
            Some(self.sub_authority[(self.sub_authority_count - 1) as usize])
        } else {
            None
        }
    }

    /// Compare two SIDs for equality
    pub fn equal(&self, other: &Sid) -> bool {
        if self.revision != other.revision ||
           self.sub_authority_count != other.sub_authority_count ||
           self.identifier_authority != other.identifier_authority {
            return false;
        }

        for i in 0..self.sub_authority_count as usize {
            if self.sub_authority[i] != other.sub_authority[i] {
                return false;
            }
        }

        true
    }

    /// Check if this SID is a prefix of another SID
    pub fn is_prefix_of(&self, other: &Sid) -> bool {
        if self.revision != other.revision ||
           self.identifier_authority != other.identifier_authority ||
           self.sub_authority_count > other.sub_authority_count {
            return false;
        }

        for i in 0..self.sub_authority_count as usize {
            if self.sub_authority[i] != other.sub_authority[i] {
                return false;
            }
        }

        true
    }
}

impl Default for Sid {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Sid {
    fn eq(&self, other: &Self) -> bool {
        self.equal(other)
    }
}

impl Eq for Sid {}

// ============================================================================
// Well-Known SIDs
// ============================================================================

/// Null SID (S-1-0-0)
pub const SID_NULL: Sid = Sid {
    revision: SID_REVISION,
    sub_authority_count: 1,
    identifier_authority: identifier_authority::SECURITY_NULL_SID_AUTHORITY,
    sub_authority: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
};

/// Everyone SID (S-1-1-0)
pub const SID_WORLD: Sid = Sid {
    revision: SID_REVISION,
    sub_authority_count: 1,
    identifier_authority: identifier_authority::SECURITY_WORLD_SID_AUTHORITY,
    sub_authority: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
};

/// Local System SID (S-1-5-18)
pub const SID_LOCAL_SYSTEM: Sid = Sid {
    revision: SID_REVISION,
    sub_authority_count: 1,
    identifier_authority: identifier_authority::SECURITY_NT_AUTHORITY,
    sub_authority: [well_known_rids::SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
};

/// Local Service SID (S-1-5-19)
pub const SID_LOCAL_SERVICE: Sid = Sid {
    revision: SID_REVISION,
    sub_authority_count: 1,
    identifier_authority: identifier_authority::SECURITY_NT_AUTHORITY,
    sub_authority: [well_known_rids::SECURITY_LOCAL_SERVICE_RID, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
};

/// Network Service SID (S-1-5-20)
pub const SID_NETWORK_SERVICE: Sid = Sid {
    revision: SID_REVISION,
    sub_authority_count: 1,
    identifier_authority: identifier_authority::SECURITY_NT_AUTHORITY,
    sub_authority: [well_known_rids::SECURITY_NETWORK_SERVICE_RID, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
};

/// Administrators group SID (S-1-5-32-544)
pub const SID_BUILTIN_ADMINISTRATORS: Sid = Sid {
    revision: SID_REVISION,
    sub_authority_count: 2,
    identifier_authority: identifier_authority::SECURITY_NT_AUTHORITY,
    sub_authority: [well_known_rids::SECURITY_BUILTIN_DOMAIN_RID, well_known_rids::DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
};

/// Users group SID (S-1-5-32-545)
pub const SID_BUILTIN_USERS: Sid = Sid {
    revision: SID_REVISION,
    sub_authority_count: 2,
    identifier_authority: identifier_authority::SECURITY_NT_AUTHORITY,
    sub_authority: [well_known_rids::SECURITY_BUILTIN_DOMAIN_RID, well_known_rids::DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
};

/// Authenticated Users SID (S-1-5-11)
pub const SID_AUTHENTICATED_USERS: Sid = Sid {
    revision: SID_REVISION,
    sub_authority_count: 1,
    identifier_authority: identifier_authority::SECURITY_NT_AUTHORITY,
    sub_authority: [well_known_rids::SECURITY_AUTHENTICATED_USER_RID, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
};

// ============================================================================
// SID and Attributes (for group membership in tokens)
// ============================================================================

/// SID attribute flags
pub mod sid_attributes {
    /// SID is mandatory (cannot be disabled)
    pub const SE_GROUP_MANDATORY: u32 = 0x00000001;
    /// SID is enabled by default
    pub const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x00000002;
    /// SID is enabled
    pub const SE_GROUP_ENABLED: u32 = 0x00000004;
    /// SID is the owner
    pub const SE_GROUP_OWNER: u32 = 0x00000008;
    /// SID is used for deny-only
    pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x00000010;
    /// SID is the integrity level
    pub const SE_GROUP_INTEGRITY: u32 = 0x00000020;
    /// SID is enabled for integrity checks
    pub const SE_GROUP_INTEGRITY_ENABLED: u32 = 0x00000040;
    /// SID is a logon ID
    pub const SE_GROUP_LOGON_ID: u32 = 0xC0000000;
    /// SID is a resource
    pub const SE_GROUP_RESOURCE: u32 = 0x20000000;
}

/// SID and Attributes structure
///
/// Used in tokens to associate attributes with group SIDs.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SidAndAttributes {
    /// Pointer to the SID
    pub sid: *const Sid,
    /// Attributes for this SID
    pub attributes: u32,
}

impl SidAndAttributes {
    pub const fn new() -> Self {
        Self {
            sid: ptr::null(),
            attributes: 0,
        }
    }

    pub fn with_sid(sid: *const Sid, attributes: u32) -> Self {
        Self { sid, attributes }
    }

    /// Check if this group is enabled
    pub fn is_enabled(&self) -> bool {
        (self.attributes & sid_attributes::SE_GROUP_ENABLED) != 0
    }

    /// Check if this is a mandatory group
    pub fn is_mandatory(&self) -> bool {
        (self.attributes & sid_attributes::SE_GROUP_MANDATORY) != 0
    }

    /// Check if this is used for deny-only
    pub fn is_deny_only(&self) -> bool {
        (self.attributes & sid_attributes::SE_GROUP_USE_FOR_DENY_ONLY) != 0
    }
}

impl Default for SidAndAttributes {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SID Pool
// ============================================================================

/// Maximum number of SIDs in the pool
pub const MAX_SIDS: usize = 128;

/// SID pool for dynamic allocation
static mut SID_POOL: [Sid; MAX_SIDS] = {
    const INIT: Sid = Sid::new();
    [INIT; MAX_SIDS]
};

/// SID pool bitmap
static mut SID_POOL_BITMAP: [u64; 2] = [0; 2];

/// Allocate a SID from the pool
pub unsafe fn se_allocate_sid() -> *mut Sid {
    for word_idx in 0..2 {
        if SID_POOL_BITMAP[word_idx] != u64::MAX {
            for bit_idx in 0..64 {
                let global_idx = word_idx * 64 + bit_idx;
                if global_idx >= MAX_SIDS {
                    return ptr::null_mut();
                }
                if SID_POOL_BITMAP[word_idx] & (1 << bit_idx) == 0 {
                    SID_POOL_BITMAP[word_idx] |= 1 << bit_idx;
                    let sid = &mut SID_POOL[global_idx] as *mut Sid;
                    *sid = Sid::new();
                    return sid;
                }
            }
        }
    }

    ptr::null_mut()
}

/// Free a SID back to the pool
pub unsafe fn se_free_sid(sid: *mut Sid) {
    if sid.is_null() {
        return;
    }

    let base = SID_POOL.as_ptr() as usize;
    let offset = sid as usize - base;
    let index = offset / core::mem::size_of::<Sid>();

    if index < MAX_SIDS {
        let word_idx = index / 64;
        let bit_idx = index % 64;
        SID_POOL_BITMAP[word_idx] &= !(1 << bit_idx);
    }
}

/// Copy a SID
pub unsafe fn rtl_copy_sid(dest: *mut Sid, src: *const Sid) -> bool {
    if dest.is_null() || src.is_null() {
        return false;
    }

    *dest = *src;
    true
}

/// Initialize SID subsystem
pub fn init() {
    crate::serial_println!("[SE] SID subsystem initialized ({} SIDs available)", MAX_SIDS);
}
