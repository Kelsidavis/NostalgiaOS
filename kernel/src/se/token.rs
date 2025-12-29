//! Access Token Implementation
//!
//! Tokens represent the security context of a process or thread.
//! They contain:
//! - User SID: Identity of the user
//! - Group SIDs: Group memberships
//! - Privileges: Special rights (SeDebugPrivilege, etc.)
//! - Default DACL: Applied to new objects
//! - Token type: Primary (process) or Impersonation (thread)
//!
//! # Token Types
//! - Primary Token: Assigned to processes, defines the process security context
//! - Impersonation Token: Used by threads to temporarily assume another identity
//!
//! # Impersonation Levels
//! - Anonymous: Server cannot identify or impersonate client
//! - Identification: Server can identify but not impersonate
//! - Impersonation: Server can impersonate locally
//! - Delegation: Server can impersonate on remote systems

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::ke::SpinLock;
use crate::ob::ObjectHeader;
use super::sid::{Sid, SidAndAttributes, SID_LOCAL_SYSTEM, SID_BUILTIN_ADMINISTRATORS, sid_attributes};
use super::privilege::{Luid, LuidAndAttributes, PrivilegeSet, SE_MAX_PRIVILEGES, privilege_attributes};
use super::acl::SimpleAcl;

/// Maximum number of groups in a token
pub const TOKEN_MAX_GROUPS: usize = 32;

/// Token type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[derive(Default)]
pub enum TokenType {
    /// Primary token (for processes)
    #[default]
    Primary = 1,
    /// Impersonation token (for threads)
    Impersonation = 2,
}


/// Impersonation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
#[derive(Default)]
pub enum SecurityImpersonationLevel {
    /// Cannot obtain identification or impersonation
    Anonymous = 0,
    /// Can obtain identity but not impersonate
    Identification = 1,
    /// Can impersonate on local system
    #[default]
    Impersonation = 2,
    /// Can impersonate on remote systems
    Delegation = 3,
}


/// Token elevation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[derive(Default)]
pub enum TokenElevationType {
    /// Default
    #[default]
    Default = 1,
    /// Full (elevated)
    Full = 2,
    /// Limited (not elevated)
    Limited = 3,
}


/// Token source (identifies creator)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TokenSource {
    /// Source name (8 characters)
    pub source_name: [u8; 8],
    /// Source identifier
    pub source_identifier: Luid,
}

impl TokenSource {
    pub const fn new() -> Self {
        Self {
            source_name: [0; 8],
            source_identifier: Luid::new(0, 0),
        }
    }

    pub fn with_name(name: &[u8]) -> Self {
        let mut source = Self::new();
        let len = name.len().min(8);
        source.source_name[..len].copy_from_slice(&name[..len]);
        source
    }
}

impl Default for TokenSource {
    fn default() -> Self {
        Self::new()
    }
}

/// Token statistics
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TokenStatistics {
    /// Token ID
    pub token_id: Luid,
    /// Authentication ID (logon session)
    pub authentication_id: Luid,
    /// Expiration time
    pub expiration_time: u64,
    /// Token type
    pub token_type: TokenType,
    /// Impersonation level
    pub impersonation_level: SecurityImpersonationLevel,
    /// Dynamic charged (bytes)
    pub dynamic_charged: u32,
    /// Dynamic available (bytes)
    pub dynamic_available: u32,
    /// Group count
    pub group_count: u32,
    /// Privilege count
    pub privilege_count: u32,
    /// Modified ID
    pub modified_id: Luid,
}

impl TokenStatistics {
    pub const fn new() -> Self {
        Self {
            token_id: Luid::new(0, 0),
            authentication_id: Luid::new(0, 0),
            expiration_time: 0,
            token_type: TokenType::Primary,
            impersonation_level: SecurityImpersonationLevel::Impersonation,
            dynamic_charged: 0,
            dynamic_available: 0,
            group_count: 0,
            privilege_count: 0,
            modified_id: Luid::new(0, 0),
        }
    }
}

impl Default for TokenStatistics {
    fn default() -> Self {
        Self::new()
    }
}

/// Access Token structure
#[repr(C)]
pub struct Token {
    /// Object header for object manager integration
    pub header: ObjectHeader,

    /// Token lock
    pub token_lock: SpinLock<()>,

    /// Token ID (unique identifier)
    pub token_id: Luid,

    /// Authentication ID (logon session)
    pub authentication_id: Luid,

    /// Parent token ID (for filtered tokens)
    pub parent_token_id: Luid,

    /// Expiration time (0 = never)
    pub expiration_time: u64,

    /// Token type (Primary or Impersonation)
    pub token_type: TokenType,

    /// Impersonation level
    pub impersonation_level: SecurityImpersonationLevel,

    /// Token source
    pub token_source: TokenSource,

    /// Reference count
    pub reference_count: AtomicU32,

    /// Token flags
    pub flags: AtomicU32,

    /// User SID
    pub user: Sid,

    /// Number of groups
    pub group_count: u8,

    /// Groups (SIDs with attributes)
    pub groups: [SidAndAttributes; TOKEN_MAX_GROUPS],
    /// Group SID storage (inline)
    pub group_sids: [Sid; TOKEN_MAX_GROUPS],

    /// Owner SID (for new objects) - index into groups, or user
    pub owner_index: i8,

    /// Primary group (for new objects) - index into groups
    pub primary_group_index: i8,

    /// Privileges
    pub privileges: PrivilegeSet,

    /// Default DACL for new objects
    pub default_dacl: SimpleAcl,

    /// Session ID
    pub session_id: u32,

    /// Restricted SID count
    pub restricted_sid_count: u8,

    /// Elevation type
    pub elevation_type: TokenElevationType,

    /// Is elevated
    pub is_elevated: bool,
}

impl Token {
    pub const fn new() -> Self {
        Self {
            header: ObjectHeader::new(),
            token_lock: SpinLock::new(()),
            token_id: Luid::new(0, 0),
            authentication_id: Luid::new(0, 0),
            parent_token_id: Luid::new(0, 0),
            expiration_time: 0,
            token_type: TokenType::Primary,
            impersonation_level: SecurityImpersonationLevel::Impersonation,
            token_source: TokenSource::new(),
            reference_count: AtomicU32::new(1),
            flags: AtomicU32::new(0),
            user: Sid::new(),
            group_count: 0,
            groups: [SidAndAttributes::new(); TOKEN_MAX_GROUPS],
            group_sids: [Sid::new(); TOKEN_MAX_GROUPS],
            owner_index: -1,
            primary_group_index: -1,
            privileges: PrivilegeSet::new(),
            default_dacl: SimpleAcl::new(),
            session_id: 0,
            restricted_sid_count: 0,
            elevation_type: TokenElevationType::Default,
            is_elevated: false,
        }
    }

    /// Initialize the token
    pub fn init(&mut self, user: Sid, token_type: TokenType) {
        self.user = user;
        self.token_type = token_type;
        self.reference_count.store(1, Ordering::SeqCst);
    }

    /// Add a group to the token
    pub fn add_group(&mut self, sid: Sid, attributes: u32) -> bool {
        if self.group_count as usize >= TOKEN_MAX_GROUPS {
            return false;
        }

        let index = self.group_count as usize;
        self.group_sids[index] = sid;
        self.groups[index] = SidAndAttributes {
            sid: &self.group_sids[index] as *const Sid,
            attributes,
        };
        self.group_count += 1;
        true
    }

    /// Add a privilege to the token
    pub fn add_privilege(&mut self, luid: Luid, attributes: u32) -> bool {
        let count = self.privileges.privilege_count as usize;
        if count >= SE_MAX_PRIVILEGES {
            return false;
        }

        self.privileges.privilege[count] = LuidAndAttributes::with_luid(luid, attributes);
        self.privileges.privilege_count += 1;
        true
    }

    /// Check if token has a specific privilege
    pub fn has_privilege(&self, luid: Luid) -> bool {
        for i in 0..self.privileges.privilege_count as usize {
            if self.privileges.privilege[i].luid == luid {
                return true;
            }
        }
        false
    }

    /// Check if privilege is enabled
    pub fn is_privilege_enabled(&self, luid: Luid) -> bool {
        for i in 0..self.privileges.privilege_count as usize {
            let priv_entry = &self.privileges.privilege[i];
            if priv_entry.luid == luid && priv_entry.is_enabled() {
                return true;
            }
        }
        false
    }

    /// Enable a privilege
    pub fn enable_privilege(&mut self, luid: Luid) -> bool {
        for i in 0..self.privileges.privilege_count as usize {
            if self.privileges.privilege[i].luid == luid {
                self.privileges.privilege[i].enable();
                return true;
            }
        }
        false
    }

    /// Disable a privilege
    pub fn disable_privilege(&mut self, luid: Luid) -> bool {
        for i in 0..self.privileges.privilege_count as usize {
            if self.privileges.privilege[i].luid == luid {
                self.privileges.privilege[i].disable();
                return true;
            }
        }
        false
    }

    /// Check if token user matches a SID
    pub fn is_user(&self, sid: &Sid) -> bool {
        self.user.equal(sid)
    }

    /// Check if token has a specific group
    pub fn has_group(&self, sid: &Sid) -> bool {
        for i in 0..self.group_count as usize {
            if self.group_sids[i].equal(sid) {
                // Check if group is enabled
                if self.groups[i].is_enabled() {
                    return true;
                }
            }
        }
        false
    }

    /// Check if token is a member (user or group) of a SID
    pub fn is_member(&self, sid: &Sid) -> bool {
        self.is_user(sid) || self.has_group(sid)
    }

    /// Get token statistics
    pub fn get_statistics(&self) -> TokenStatistics {
        TokenStatistics {
            token_id: self.token_id,
            authentication_id: self.authentication_id,
            expiration_time: self.expiration_time,
            token_type: self.token_type,
            impersonation_level: self.impersonation_level,
            dynamic_charged: 0,
            dynamic_available: 0,
            group_count: self.group_count as u32,
            privilege_count: self.privileges.privilege_count,
            modified_id: Luid::new(0, 0),
        }
    }

    /// Add reference
    pub fn add_ref(&self) {
        self.reference_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Release reference
    pub fn release(&self) -> u32 {
        self.reference_count.fetch_sub(1, Ordering::SeqCst)
    }
}

impl Default for Token {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: Token uses locks and atomics
unsafe impl Sync for Token {}
unsafe impl Send for Token {}

// ============================================================================
// Token Pool
// ============================================================================

/// Maximum number of tokens
pub const MAX_TOKENS: usize = 64;

/// Token pool
pub static mut TOKEN_POOL: [Token; MAX_TOKENS] = {
    const INIT: Token = Token::new();
    [INIT; MAX_TOKENS]
};

/// Token pool bitmap
pub static mut TOKEN_POOL_BITMAP: u64 = 0;

/// Token pool lock
static TOKEN_POOL_LOCK: SpinLock<()> = SpinLock::new(());

/// Next token ID
static mut NEXT_TOKEN_ID: u32 = 1;

/// Allocate a new token
pub unsafe fn se_create_token(
    user: Sid,
    token_type: TokenType,
) -> *mut Token {
    let _guard = TOKEN_POOL_LOCK.lock();

    for i in 0..MAX_TOKENS {
        if TOKEN_POOL_BITMAP & (1 << i) == 0 {
            TOKEN_POOL_BITMAP |= 1 << i;
            let token = &mut TOKEN_POOL[i] as *mut Token;
            *token = Token::new();
            (*token).init(user, token_type);
            (*token).token_id = Luid::from_u32(NEXT_TOKEN_ID);
            NEXT_TOKEN_ID += 1;
            return token;
        }
    }

    ptr::null_mut()
}

/// Free a token
pub unsafe fn se_free_token(token: *mut Token) {
    if token.is_null() {
        return;
    }

    let _guard = TOKEN_POOL_LOCK.lock();

    let base = TOKEN_POOL.as_ptr() as usize;
    let offset = token as usize - base;
    let index = offset / core::mem::size_of::<Token>();

    if index < MAX_TOKENS {
        TOKEN_POOL_BITMAP &= !(1 << index);
    }
}

/// Create a system token with full privileges
pub unsafe fn se_create_system_token() -> *mut Token {
    let token = se_create_token(SID_LOCAL_SYSTEM, TokenType::Primary);
    if token.is_null() {
        return token;
    }

    // Add Administrators group
    (*token).add_group(
        SID_BUILTIN_ADMINISTRATORS,
        sid_attributes::SE_GROUP_ENABLED | sid_attributes::SE_GROUP_ENABLED_BY_DEFAULT | sid_attributes::SE_GROUP_MANDATORY,
    );

    // Add all privileges with enabled by default
    use super::privilege::privilege_luids::*;
    let all_privs = [
        SE_TCB_LUID,
        SE_DEBUG_LUID,
        SE_SECURITY_LUID,
        SE_TAKE_OWNERSHIP_LUID,
        SE_LOAD_DRIVER_LUID,
        SE_BACKUP_LUID,
        SE_RESTORE_LUID,
        SE_SHUTDOWN_LUID,
        SE_SYSTEM_ENVIRONMENT_LUID,
        SE_CHANGE_NOTIFY_LUID,
        SE_IMPERSONATE_LUID,
        SE_CREATE_GLOBAL_LUID,
        SE_MANAGE_VOLUME_LUID,
        SE_CREATE_PAGEFILE_LUID,
        SE_CREATE_PERMANENT_LUID,
        SE_INCREASE_QUOTA_LUID,
        SE_INC_BASE_PRIORITY_LUID,
        SE_SYSTEMTIME_LUID,
        SE_PROF_SINGLE_PROCESS_LUID,
        SE_SYSTEM_PROFILE_LUID,
        SE_ASSIGNPRIMARYTOKEN_LUID,
        SE_AUDIT_LUID,
    ];

    for &priv_luid in &all_privs {
        (*token).add_privilege(
            priv_luid,
            privilege_attributes::SE_PRIVILEGE_ENABLED | privilege_attributes::SE_PRIVILEGE_ENABLED_BY_DEFAULT,
        );
    }

    (*token).is_elevated = true;
    (*token).elevation_type = TokenElevationType::Full;
    (*token).token_source = TokenSource::with_name(b"*SYSTEM*");

    token
}

/// Static system token
static mut SYSTEM_TOKEN: Token = Token::new();
static mut SYSTEM_TOKEN_INITIALIZED: bool = false;

/// Get the system token
pub unsafe fn se_get_system_token() -> *mut Token {
    if !SYSTEM_TOKEN_INITIALIZED {
        // Initialize the static system token
        SYSTEM_TOKEN = Token::new();
        SYSTEM_TOKEN.init(SID_LOCAL_SYSTEM, TokenType::Primary);
        SYSTEM_TOKEN.token_id = Luid::from_u32(0);

        // Add Administrators group
        SYSTEM_TOKEN.add_group(
            SID_BUILTIN_ADMINISTRATORS,
            sid_attributes::SE_GROUP_ENABLED | sid_attributes::SE_GROUP_ENABLED_BY_DEFAULT | sid_attributes::SE_GROUP_MANDATORY,
        );

        // Add key privileges
        use super::privilege::privilege_luids::*;
        let all_privs = [
            SE_TCB_LUID, SE_DEBUG_LUID, SE_SECURITY_LUID, SE_TAKE_OWNERSHIP_LUID,
            SE_LOAD_DRIVER_LUID, SE_BACKUP_LUID, SE_RESTORE_LUID, SE_SHUTDOWN_LUID,
        ];

        for &priv_luid in &all_privs {
            SYSTEM_TOKEN.add_privilege(
                priv_luid,
                privilege_attributes::SE_PRIVILEGE_ENABLED | privilege_attributes::SE_PRIVILEGE_ENABLED_BY_DEFAULT,
            );
        }

        SYSTEM_TOKEN.is_elevated = true;
        SYSTEM_TOKEN.elevation_type = TokenElevationType::Full;
        SYSTEM_TOKEN.token_source = TokenSource::with_name(b"*SYSTEM*");

        SYSTEM_TOKEN_INITIALIZED = true;
    }

    &mut SYSTEM_TOKEN as *mut Token
}

/// Initialize token subsystem
pub fn init() {
    unsafe {
        // Initialize system token
        let _ = se_get_system_token();
    }
    crate::serial_println!("[SE] Token subsystem initialized ({} tokens available)", MAX_TOKENS);
}
