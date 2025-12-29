//! Locally Unique Identifier (LUID)
//!
//! LUIDs are 64-bit identifiers guaranteed to be unique on the local machine
//! since the last boot. They are used throughout the security subsystem for
//! tokens, privileges, and authentication.
//!
//! # Design
//!
//! - Values 0-1000 are reserved for predefined system LUIDs
//! - The allocator starts at 1001 and increments atomically
//! - With 64-bit space, exhaustion is impossible (~15,000 years at 100ns intervals)
//!
//! # Windows Equivalent
//! This implements NT's luid.c functionality.
//!
//! # Example
//! ```
//! let luid = ex_allocate_locally_unique_id();
//! // luid is now a unique identifier for this session
//! ```

use core::sync::atomic::{AtomicU64, Ordering};

/// Locally Unique Identifier
///
/// A 64-bit value split into low and high parts for compatibility with
/// the original Windows structure.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct Luid {
    /// Low 32 bits
    pub low_part: u32,
    /// High 32 bits (signed in original, but we use u32 for simplicity)
    pub high_part: u32,
}

impl Luid {
    /// Create a new LUID from parts
    pub const fn new(low: u32, high: u32) -> Self {
        Self {
            low_part: low,
            high_part: high,
        }
    }

    /// Create a new LUID from a 64-bit value
    pub const fn from_u64(value: u64) -> Self {
        Self {
            low_part: value as u32,
            high_part: (value >> 32) as u32,
        }
    }

    /// Convert to a 64-bit value
    pub const fn to_u64(self) -> u64 {
        ((self.high_part as u64) << 32) | (self.low_part as u64)
    }

    /// Check if this is a null LUID
    pub const fn is_null(self) -> bool {
        self.low_part == 0 && self.high_part == 0
    }
}

/// Well-known system LUIDs (reserved 0-1000)
pub mod system_luids {
    use super::Luid;

    /// The system LUID (used by SYSTEM account)
    pub const SYSTEM_LUID: Luid = Luid::new(0x3e7, 0);

    /// The anonymous logon LUID
    pub const ANONYMOUS_LOGON_LUID: Luid = Luid::new(0x3e6, 0);

    /// The local service LUID
    pub const LOCAL_SERVICE_LUID: Luid = Luid::new(0x3e5, 0);

    /// The network service LUID
    pub const NETWORK_SERVICE_LUID: Luid = Luid::new(0x3e4, 0);

    /// The iuser LUID (IIS)
    pub const IUSER_LUID: Luid = Luid::new(0x3e3, 0);

    /// Protected authenticator LUID
    pub const PROTECTED_TO_SYSTEM_LUID: Luid = Luid::new(0x3e2, 0);
}

/// Well-known privilege LUIDs
pub mod privilege_luids {
    use super::Luid;

    /// SeCreateTokenPrivilege
    pub const SE_CREATE_TOKEN_PRIVILEGE: Luid = Luid::new(2, 0);

    /// SeAssignPrimaryTokenPrivilege
    pub const SE_ASSIGNPRIMARYTOKEN_PRIVILEGE: Luid = Luid::new(3, 0);

    /// SeLockMemoryPrivilege
    pub const SE_LOCK_MEMORY_PRIVILEGE: Luid = Luid::new(4, 0);

    /// SeIncreaseQuotaPrivilege
    pub const SE_INCREASE_QUOTA_PRIVILEGE: Luid = Luid::new(5, 0);

    /// SeMachineAccountPrivilege (unsolicited input)
    pub const SE_MACHINE_ACCOUNT_PRIVILEGE: Luid = Luid::new(6, 0);

    /// SeTcbPrivilege (act as part of OS)
    pub const SE_TCB_PRIVILEGE: Luid = Luid::new(7, 0);

    /// SeSecurityPrivilege
    pub const SE_SECURITY_PRIVILEGE: Luid = Luid::new(8, 0);

    /// SeTakeOwnershipPrivilege
    pub const SE_TAKE_OWNERSHIP_PRIVILEGE: Luid = Luid::new(9, 0);

    /// SeLoadDriverPrivilege
    pub const SE_LOAD_DRIVER_PRIVILEGE: Luid = Luid::new(10, 0);

    /// SeSystemProfilePrivilege
    pub const SE_SYSTEM_PROFILE_PRIVILEGE: Luid = Luid::new(11, 0);

    /// SeSystemtimePrivilege
    pub const SE_SYSTEMTIME_PRIVILEGE: Luid = Luid::new(12, 0);

    /// SeProfileSingleProcessPrivilege
    pub const SE_PROF_SINGLE_PROCESS_PRIVILEGE: Luid = Luid::new(13, 0);

    /// SeIncreaseBasePriorityPrivilege
    pub const SE_INC_BASE_PRIORITY_PRIVILEGE: Luid = Luid::new(14, 0);

    /// SeCreatePagefilePrivilege
    pub const SE_CREATE_PAGEFILE_PRIVILEGE: Luid = Luid::new(15, 0);

    /// SeCreatePermanentPrivilege
    pub const SE_CREATE_PERMANENT_PRIVILEGE: Luid = Luid::new(16, 0);

    /// SeBackupPrivilege
    pub const SE_BACKUP_PRIVILEGE: Luid = Luid::new(17, 0);

    /// SeRestorePrivilege
    pub const SE_RESTORE_PRIVILEGE: Luid = Luid::new(18, 0);

    /// SeShutdownPrivilege
    pub const SE_SHUTDOWN_PRIVILEGE: Luid = Luid::new(19, 0);

    /// SeDebugPrivilege
    pub const SE_DEBUG_PRIVILEGE: Luid = Luid::new(20, 0);

    /// SeAuditPrivilege
    pub const SE_AUDIT_PRIVILEGE: Luid = Luid::new(21, 0);

    /// SeSystemEnvironmentPrivilege
    pub const SE_SYSTEM_ENVIRONMENT_PRIVILEGE: Luid = Luid::new(22, 0);

    /// SeChangeNotifyPrivilege
    pub const SE_CHANGE_NOTIFY_PRIVILEGE: Luid = Luid::new(23, 0);

    /// SeRemoteShutdownPrivilege
    pub const SE_REMOTE_SHUTDOWN_PRIVILEGE: Luid = Luid::new(24, 0);

    /// SeUndockPrivilege
    pub const SE_UNDOCK_PRIVILEGE: Luid = Luid::new(25, 0);

    /// SeSyncAgentPrivilege
    pub const SE_SYNC_AGENT_PRIVILEGE: Luid = Luid::new(26, 0);

    /// SeEnableDelegationPrivilege
    pub const SE_ENABLE_DELEGATION_PRIVILEGE: Luid = Luid::new(27, 0);

    /// SeManageVolumePrivilege
    pub const SE_MANAGE_VOLUME_PRIVILEGE: Luid = Luid::new(28, 0);

    /// SeImpersonatePrivilege
    pub const SE_IMPERSONATE_PRIVILEGE: Luid = Luid::new(29, 0);

    /// SeCreateGlobalPrivilege
    pub const SE_CREATE_GLOBAL_PRIVILEGE: Luid = Luid::new(30, 0);

    /// Maximum privilege value
    pub const SE_MAX_WELL_KNOWN_PRIVILEGE: Luid = Luid::new(30, 0);
}

/// The first 1000 values are reserved for static definitions
const LUID_RESERVED_COUNT: u64 = 1001;

/// Global LUID source - starts at LUID_RESERVED_COUNT
/// This is the "next" allocatable LUID
static LUID_SOURCE: AtomicU64 = AtomicU64::new(LUID_RESERVED_COUNT);

/// Initialize the LUID subsystem
///
/// Called during phase 0 initialization. The LUID allocation services
/// are needed by security early in boot.
pub fn ex_luid_initialization() -> bool {
    // Nothing to do - atomic is initialized statically
    true
}

/// Allocate a new locally unique identifier (ExAllocateLocallyUniqueId)
///
/// This is the kernel-mode internal function that allocates a new LUID.
/// It is thread-safe and lock-free.
///
/// # Returns
/// A new LUID guaranteed to be unique since boot
#[inline]
pub fn ex_allocate_locally_unique_id() -> Luid {
    let value = LUID_SOURCE.fetch_add(1, Ordering::Relaxed);
    Luid::from_u64(value)
}

/// Allocate a new LUID and store it at the specified location
///
/// This is a convenience wrapper used by the syscall interface.
pub fn ex_allocate_luid(luid: &mut Luid) {
    *luid = ex_allocate_locally_unique_id();
}

/// Compare two LUIDs for equality
pub fn rtl_equal_luid(luid1: &Luid, luid2: &Luid) -> bool {
    luid1.low_part == luid2.low_part && luid1.high_part == luid2.high_part
}

/// Check if a LUID is zero (null)
pub fn rtl_is_zero_luid(luid: &Luid) -> bool {
    luid.is_null()
}

/// Copy a LUID
pub fn rtl_copy_luid(dest: &mut Luid, src: &Luid) {
    *dest = *src;
}

// ============================================================================
// LUID_AND_ATTRIBUTES structure for privilege management
// ============================================================================

/// Privilege attributes
pub mod luid_attributes {
    /// Privilege is enabled by default
    pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x00000001;
    /// Privilege is enabled
    pub const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;
    /// Privilege was removed from the token
    pub const SE_PRIVILEGE_REMOVED: u32 = 0x00000004;
    /// Privilege was used for access check
    pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x80000000;
}

/// LUID with associated attributes (for privilege sets)
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct LuidAndAttributes {
    /// The LUID
    pub luid: Luid,
    /// Attribute flags
    pub attributes: u32,
}

impl LuidAndAttributes {
    /// Create a new LUID with attributes
    pub const fn new(luid: Luid, attributes: u32) -> Self {
        Self { luid, attributes }
    }

    /// Check if this privilege is enabled
    pub const fn is_enabled(&self) -> bool {
        (self.attributes & luid_attributes::SE_PRIVILEGE_ENABLED) != 0
    }

    /// Check if this privilege is enabled by default
    pub const fn is_enabled_by_default(&self) -> bool {
        (self.attributes & luid_attributes::SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0
    }
}

// ============================================================================
// Privilege Set for access checking
// ============================================================================

/// Control flags for privilege sets
pub mod privilege_set_control {
    /// All specified privileges must be held (AND)
    pub const PRIVILEGE_SET_ALL_NECESSARY: u32 = 1;
}

/// Maximum privileges in a privilege set
pub const ANYSIZE_ARRAY: usize = 1;

/// A set of privileges
#[repr(C)]
pub struct PrivilegeSet {
    /// Number of privileges in the set
    pub privilege_count: u32,
    /// Control flags (PRIVILEGE_SET_ALL_NECESSARY means all must be held)
    pub control: u32,
    /// Array of privileges (variable length)
    pub privilege: [LuidAndAttributes; ANYSIZE_ARRAY],
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the LUID subsystem (called during boot)
pub fn luid_init() {
    if !ex_luid_initialization() {
        panic!("Failed to initialize LUID subsystem");
    }
    crate::serial_println!("[EX] LUID allocator initialized (next: {})", LUID_RESERVED_COUNT);
}

// ============================================================================
// Inspection Functions
// ============================================================================

/// LUID allocator statistics
#[derive(Debug, Clone, Copy)]
pub struct LuidStats {
    /// Number of reserved LUIDs (0-1000)
    pub reserved_count: u64,
    /// Next LUID that will be allocated
    pub next_luid: u64,
    /// Total LUIDs allocated so far
    pub allocated_count: u64,
    /// Number of well-known privilege LUIDs
    pub privilege_luid_count: u32,
    /// Number of well-known system LUIDs
    pub system_luid_count: u32,
}

/// Get LUID allocator statistics
pub fn get_luid_stats() -> LuidStats {
    let next = LUID_SOURCE.load(Ordering::Relaxed);
    let allocated = next.saturating_sub(LUID_RESERVED_COUNT);

    LuidStats {
        reserved_count: LUID_RESERVED_COUNT,
        next_luid: next,
        allocated_count: allocated,
        privilege_luid_count: 29, // SE_CREATE_TOKEN (2) to SE_CREATE_GLOBAL (30)
        system_luid_count: 6,     // SYSTEM, ANONYMOUS, LOCAL_SERVICE, NETWORK_SERVICE, IUSER, PROTECTED
    }
}

/// Well-known LUID information
#[derive(Debug, Clone, Copy)]
pub struct WellKnownLuid {
    /// LUID value
    pub luid: Luid,
    /// Name of the LUID
    pub name: &'static str,
}

/// Get list of well-known system LUIDs
pub fn get_system_luids() -> [WellKnownLuid; 6] {
    [
        WellKnownLuid { luid: system_luids::SYSTEM_LUID, name: "SYSTEM" },
        WellKnownLuid { luid: system_luids::ANONYMOUS_LOGON_LUID, name: "ANONYMOUS_LOGON" },
        WellKnownLuid { luid: system_luids::LOCAL_SERVICE_LUID, name: "LOCAL_SERVICE" },
        WellKnownLuid { luid: system_luids::NETWORK_SERVICE_LUID, name: "NETWORK_SERVICE" },
        WellKnownLuid { luid: system_luids::IUSER_LUID, name: "IUSER" },
        WellKnownLuid { luid: system_luids::PROTECTED_TO_SYSTEM_LUID, name: "PROTECTED_TO_SYSTEM" },
    ]
}

/// Get list of well-known privilege LUIDs (first 16)
pub fn get_privilege_luids() -> [WellKnownLuid; 16] {
    [
        WellKnownLuid { luid: privilege_luids::SE_CREATE_TOKEN_PRIVILEGE, name: "CreateToken" },
        WellKnownLuid { luid: privilege_luids::SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, name: "AssignPrimaryToken" },
        WellKnownLuid { luid: privilege_luids::SE_LOCK_MEMORY_PRIVILEGE, name: "LockMemory" },
        WellKnownLuid { luid: privilege_luids::SE_INCREASE_QUOTA_PRIVILEGE, name: "IncreaseQuota" },
        WellKnownLuid { luid: privilege_luids::SE_MACHINE_ACCOUNT_PRIVILEGE, name: "MachineAccount" },
        WellKnownLuid { luid: privilege_luids::SE_TCB_PRIVILEGE, name: "Tcb" },
        WellKnownLuid { luid: privilege_luids::SE_SECURITY_PRIVILEGE, name: "Security" },
        WellKnownLuid { luid: privilege_luids::SE_TAKE_OWNERSHIP_PRIVILEGE, name: "TakeOwnership" },
        WellKnownLuid { luid: privilege_luids::SE_LOAD_DRIVER_PRIVILEGE, name: "LoadDriver" },
        WellKnownLuid { luid: privilege_luids::SE_SYSTEM_PROFILE_PRIVILEGE, name: "SystemProfile" },
        WellKnownLuid { luid: privilege_luids::SE_SYSTEMTIME_PRIVILEGE, name: "Systemtime" },
        WellKnownLuid { luid: privilege_luids::SE_PROF_SINGLE_PROCESS_PRIVILEGE, name: "ProfileSingleProcess" },
        WellKnownLuid { luid: privilege_luids::SE_INC_BASE_PRIORITY_PRIVILEGE, name: "IncreaseBasePriority" },
        WellKnownLuid { luid: privilege_luids::SE_CREATE_PAGEFILE_PRIVILEGE, name: "CreatePagefile" },
        WellKnownLuid { luid: privilege_luids::SE_CREATE_PERMANENT_PRIVILEGE, name: "CreatePermanent" },
        WellKnownLuid { luid: privilege_luids::SE_BACKUP_PRIVILEGE, name: "Backup" },
    ]
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luid_conversion() {
        let luid = Luid::new(0x12345678, 0xABCDEF00);
        let value = luid.to_u64();
        let luid2 = Luid::from_u64(value);
        assert_eq!(luid, luid2);
    }

    #[test]
    fn test_luid_allocation_unique() {
        let luid1 = ex_allocate_locally_unique_id();
        let luid2 = ex_allocate_locally_unique_id();
        assert_ne!(luid1.to_u64(), luid2.to_u64());
    }

    #[test]
    fn test_system_luids() {
        assert_eq!(system_luids::SYSTEM_LUID.low_part, 0x3e7);
        assert_eq!(system_luids::SYSTEM_LUID.high_part, 0);
    }
}
