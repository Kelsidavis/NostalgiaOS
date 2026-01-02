//! Security Account Manager (SAM)
//!
//! The SAM database stores local user and group account information:
//!
//! - **Users**: Local user accounts with credentials
//! - **Groups**: Local and global groups
//! - **Aliases**: Local group aliases
//! - **Domains**: Domain information
//!
//! SAM is used by LSA for local authentication and works with:
//! - LSA for authentication requests
//! - Registry for persistent storage (HKEY_LOCAL_MACHINE\SAM)
//! - NetLogon for domain operations

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::ke::SpinLock;
use crate::hal::apic::get_tick_count;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of users
pub const MAX_USERS: usize = 256;

/// Maximum number of groups
pub const MAX_GROUPS: usize = 128;

/// Maximum number of aliases
pub const MAX_ALIASES: usize = 128;

/// Maximum username length
pub const MAX_USERNAME_LEN: usize = 64;

/// Maximum password hash length (NT hash = 16 bytes)
pub const MAX_PASSWORD_HASH_LEN: usize = 16;

/// Maximum group name length
pub const MAX_GROUP_NAME_LEN: usize = 64;

/// Maximum comment length
pub const MAX_COMMENT_LEN: usize = 256;

/// Maximum group members
pub const MAX_GROUP_MEMBERS: usize = 64;

/// SAM signature
pub const SAM_SIGNATURE: u32 = 0x53414D00; // 'SAM\0'

// ============================================================================
// Error Types
// ============================================================================

/// SAM error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SamError {
    /// Success
    Success = 0,
    /// Invalid parameter
    InvalidParameter = 0xC000000D,
    /// Invalid handle
    InvalidHandle = 0xC0000008,
    /// Access denied
    AccessDenied = 0xC0000022,
    /// User not found
    UserNotFound = 0xC0000064,
    /// Group not found
    GroupNotFound = 0xC0000066,
    /// Alias not found
    AliasNotFound = 0xC0000151,
    /// User already exists
    UserExists = 0xC0000063,
    /// Group already exists
    GroupExists = 0xC0000065,
    /// Alias already exists
    AliasExists = 0xC0000154,
    /// Member not found
    MemberNotFound = 0xC0000068,
    /// Member already in group
    MemberInAlias = 0xC0000152,
    /// Insufficient resources
    InsufficientResources = 0xC000009A,
    /// Wrong password
    WrongPassword = 0xC000006A,
    /// Account disabled
    AccountDisabled = 0xC0000072,
    /// Account locked
    AccountLocked = 0xC0000234,
    /// Password expired
    PasswordExpired = 0xC0000071,
    /// Not initialized
    NotInitialized = 0xC0000001,
    /// Database error
    DatabaseError = 0xC0000043,
}

// ============================================================================
// User Account Flags
// ============================================================================

/// User account control flags
pub mod user_account_control {
    /// Account is disabled
    pub const UF_ACCOUNT_DISABLED: u32 = 0x00000001;
    /// Home directory required
    pub const UF_HOMEDIR_REQUIRED: u32 = 0x00000002;
    /// Password not required
    pub const UF_PASSWORD_NOT_REQUIRED: u32 = 0x00000004;
    /// Password can't change
    pub const UF_PASSWORD_CANT_CHANGE: u32 = 0x00000008;
    /// Store password using reversible encryption
    pub const UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED: u32 = 0x00000010;
    /// Normal account
    pub const UF_NORMAL_ACCOUNT: u32 = 0x00000200;
    /// Interdomain trust account
    pub const UF_INTERDOMAIN_TRUST_ACCOUNT: u32 = 0x00000800;
    /// Workstation trust account
    pub const UF_WORKSTATION_TRUST_ACCOUNT: u32 = 0x00001000;
    /// Server trust account
    pub const UF_SERVER_TRUST_ACCOUNT: u32 = 0x00002000;
    /// Password doesn't expire
    pub const UF_DONT_EXPIRE_PASSWORD: u32 = 0x00010000;
    /// Smart card required
    pub const UF_SMARTCARD_REQUIRED: u32 = 0x00040000;
    /// Account locked out
    pub const UF_LOCKOUT: u32 = 0x00000010;
}

/// Group types
pub mod group_type {
    /// Builtin local group
    pub const GROUP_TYPE_BUILTIN_LOCAL_GROUP: u32 = 0x00000001;
    /// Account group
    pub const GROUP_TYPE_ACCOUNT_GROUP: u32 = 0x00000002;
    /// Resource group
    pub const GROUP_TYPE_RESOURCE_GROUP: u32 = 0x00000004;
    /// Universal group
    pub const GROUP_TYPE_UNIVERSAL_GROUP: u32 = 0x00000008;
    /// Security enabled
    pub const GROUP_TYPE_SECURITY_ENABLED: u32 = 0x80000000;
}

// ============================================================================
// Data Structures
// ============================================================================

/// User relative ID
pub type Rid = u32;

/// Well-known RIDs
pub mod well_known_rids {
    use super::Rid;

    /// Administrator user
    pub const DOMAIN_USER_RID_ADMIN: Rid = 0x000001F4; // 500
    /// Guest user
    pub const DOMAIN_USER_RID_GUEST: Rid = 0x000001F5; // 501
    /// KRBTGT (Kerberos TGT)
    pub const DOMAIN_USER_RID_KRBTGT: Rid = 0x000001F6; // 502

    /// Domain Admins group
    pub const DOMAIN_GROUP_RID_ADMINS: Rid = 0x00000200; // 512
    /// Domain Users group
    pub const DOMAIN_GROUP_RID_USERS: Rid = 0x00000201; // 513
    /// Domain Guests group
    pub const DOMAIN_GROUP_RID_GUESTS: Rid = 0x00000202; // 514
    /// Domain Computers group
    pub const DOMAIN_GROUP_RID_COMPUTERS: Rid = 0x00000203; // 515
    /// Domain Controllers group
    pub const DOMAIN_GROUP_RID_CONTROLLERS: Rid = 0x00000204; // 516

    /// Administrators alias
    pub const DOMAIN_ALIAS_RID_ADMINS: Rid = 0x00000220; // 544
    /// Users alias
    pub const DOMAIN_ALIAS_RID_USERS: Rid = 0x00000221; // 545
    /// Guests alias
    pub const DOMAIN_ALIAS_RID_GUESTS: Rid = 0x00000222; // 546
    /// Power Users alias
    pub const DOMAIN_ALIAS_RID_POWER_USERS: Rid = 0x00000223; // 547
    /// Backup Operators alias
    pub const DOMAIN_ALIAS_RID_BACKUP_OPS: Rid = 0x00000227; // 551
    /// Remote Desktop Users alias
    pub const DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS: Rid = 0x0000022B; // 555
}

/// User account
#[derive(Debug, Clone)]
pub struct UserAccount {
    /// Account in use
    pub in_use: bool,
    /// User RID
    pub rid: Rid,
    /// Username
    pub username: [u8; MAX_USERNAME_LEN],
    pub username_len: usize,
    /// Full name
    pub full_name: [u8; MAX_USERNAME_LEN],
    pub full_name_len: usize,
    /// Comment/description
    pub comment: [u8; MAX_COMMENT_LEN],
    pub comment_len: usize,
    /// NT password hash
    pub nt_password_hash: [u8; MAX_PASSWORD_HASH_LEN],
    /// LM password hash (legacy)
    pub lm_password_hash: [u8; MAX_PASSWORD_HASH_LEN],
    /// User account control flags
    pub user_account_control: u32,
    /// Primary group RID
    pub primary_group_rid: Rid,
    /// Home directory
    pub home_directory: [u8; 128],
    pub home_directory_len: usize,
    /// Profile path
    pub profile_path: [u8; 128],
    pub profile_path_len: usize,
    /// Logon script
    pub logon_script: [u8; 128],
    pub logon_script_len: usize,
    /// Account creation time
    pub creation_time: u64,
    /// Last logon time
    pub last_logon: u64,
    /// Last logoff time
    pub last_logoff: u64,
    /// Last password change time
    pub password_last_set: u64,
    /// Account expiration time (0 = never)
    pub account_expires: u64,
    /// Bad password count
    pub bad_password_count: u16,
    /// Logon count
    pub logon_count: u32,
    /// Country code
    pub country_code: u16,
    /// Code page
    pub code_page: u16,
}

impl UserAccount {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            rid: 0,
            username: [0u8; MAX_USERNAME_LEN],
            username_len: 0,
            full_name: [0u8; MAX_USERNAME_LEN],
            full_name_len: 0,
            comment: [0u8; MAX_COMMENT_LEN],
            comment_len: 0,
            nt_password_hash: [0u8; MAX_PASSWORD_HASH_LEN],
            lm_password_hash: [0u8; MAX_PASSWORD_HASH_LEN],
            user_account_control: user_account_control::UF_NORMAL_ACCOUNT,
            primary_group_rid: well_known_rids::DOMAIN_GROUP_RID_USERS,
            home_directory: [0u8; 128],
            home_directory_len: 0,
            profile_path: [0u8; 128],
            profile_path_len: 0,
            logon_script: [0u8; 128],
            logon_script_len: 0,
            creation_time: 0,
            last_logon: 0,
            last_logoff: 0,
            password_last_set: 0,
            account_expires: 0,
            bad_password_count: 0,
            logon_count: 0,
            country_code: 0,
            code_page: 0,
        }
    }

    pub fn get_username(&self) -> &[u8] {
        &self.username[..self.username_len]
    }

    pub fn get_full_name(&self) -> &[u8] {
        &self.full_name[..self.full_name_len]
    }

    pub fn is_disabled(&self) -> bool {
        self.user_account_control & user_account_control::UF_ACCOUNT_DISABLED != 0
    }

    pub fn is_locked(&self) -> bool {
        self.user_account_control & user_account_control::UF_LOCKOUT != 0
    }
}

/// Group account
#[derive(Debug, Clone)]
pub struct GroupAccount {
    /// Group in use
    pub in_use: bool,
    /// Group RID
    pub rid: Rid,
    /// Group name
    pub name: [u8; MAX_GROUP_NAME_LEN],
    pub name_len: usize,
    /// Comment/description
    pub comment: [u8; MAX_COMMENT_LEN],
    pub comment_len: usize,
    /// Group attributes/type
    pub attributes: u32,
    /// Member RIDs
    pub members: [Rid; MAX_GROUP_MEMBERS],
    pub member_count: usize,
}

impl GroupAccount {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            rid: 0,
            name: [0u8; MAX_GROUP_NAME_LEN],
            name_len: 0,
            comment: [0u8; MAX_COMMENT_LEN],
            comment_len: 0,
            attributes: group_type::GROUP_TYPE_ACCOUNT_GROUP | group_type::GROUP_TYPE_SECURITY_ENABLED,
            members: [0; MAX_GROUP_MEMBERS],
            member_count: 0,
        }
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    pub fn has_member(&self, rid: Rid) -> bool {
        for i in 0..self.member_count {
            if self.members[i] == rid {
                return true;
            }
        }
        false
    }
}

/// Alias (local group)
#[derive(Debug, Clone)]
pub struct AliasAccount {
    /// Alias in use
    pub in_use: bool,
    /// Alias RID
    pub rid: Rid,
    /// Alias name
    pub name: [u8; MAX_GROUP_NAME_LEN],
    pub name_len: usize,
    /// Comment/description
    pub comment: [u8; MAX_COMMENT_LEN],
    pub comment_len: usize,
    /// Member SIDs (simplified as RIDs)
    pub members: [Rid; MAX_GROUP_MEMBERS],
    pub member_count: usize,
}

impl AliasAccount {
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            rid: 0,
            name: [0u8; MAX_GROUP_NAME_LEN],
            name_len: 0,
            comment: [0u8; MAX_COMMENT_LEN],
            comment_len: 0,
            members: [0; MAX_GROUP_MEMBERS],
            member_count: 0,
        }
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    pub fn has_member(&self, rid: Rid) -> bool {
        for i in 0..self.member_count {
            if self.members[i] == rid {
                return true;
            }
        }
        false
    }
}

/// Domain information
#[derive(Debug, Clone)]
pub struct DomainInfo {
    /// Domain name
    pub name: [u8; 64],
    pub name_len: usize,
    /// Domain SID (simplified)
    pub sid: u64,
    /// Server role
    pub server_role: ServerRole,
    /// Minimum password length
    pub min_password_length: u16,
    /// Password history length
    pub password_history_length: u16,
    /// Maximum password age (in 100ns units, 0 = never)
    pub max_password_age: u64,
    /// Minimum password age (in 100ns units)
    pub min_password_age: u64,
    /// Lockout threshold
    pub lockout_threshold: u16,
    /// Lockout duration (in 100ns units)
    pub lockout_duration: u64,
    /// Lockout observation window
    pub lockout_observation_window: u64,
    /// Next RID to allocate
    pub next_rid: Rid,
    /// User count
    pub user_count: u32,
    /// Group count
    pub group_count: u32,
    /// Alias count
    pub alias_count: u32,
}

impl DomainInfo {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 64],
            name_len: 0,
            sid: 0,
            server_role: ServerRole::Standalone,
            min_password_length: 0,
            password_history_length: 0,
            max_password_age: 0,
            min_password_age: 0,
            lockout_threshold: 0,
            lockout_duration: 0,
            lockout_observation_window: 0,
            next_rid: 1000, // RIDs below 1000 are reserved
            user_count: 0,
            group_count: 0,
            alias_count: 0,
        }
    }
}

/// Server role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServerRole {
    /// Standalone server/workstation
    Standalone = 0,
    /// Member server/workstation
    MemberServer = 1,
    /// Primary domain controller
    PrimaryDC = 2,
    /// Backup domain controller
    BackupDC = 3,
}

/// SAM handle types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SamHandleType {
    /// Server handle
    Server = 0,
    /// Domain handle
    Domain = 1,
    /// User handle
    User = 2,
    /// Group handle
    Group = 3,
    /// Alias handle
    Alias = 4,
}

// ============================================================================
// Global State
// ============================================================================

/// SAM database state
struct SamState {
    /// Initialized flag
    initialized: bool,
    /// Domain information
    domain: DomainInfo,
    /// User accounts
    users: [UserAccount; MAX_USERS],
    user_count: usize,
    /// Group accounts
    groups: [GroupAccount; MAX_GROUPS],
    group_count: usize,
    /// Alias accounts
    aliases: [AliasAccount; MAX_ALIASES],
    alias_count: usize,
    /// Next handle ID
    next_handle_id: u64,
}

impl SamState {
    const fn new() -> Self {
        Self {
            initialized: false,
            domain: DomainInfo::new(),
            users: [const { UserAccount::empty() }; MAX_USERS],
            user_count: 0,
            groups: [const { GroupAccount::empty() }; MAX_GROUPS],
            group_count: 0,
            aliases: [const { AliasAccount::empty() }; MAX_ALIASES],
            alias_count: 0,
            next_handle_id: 1,
        }
    }
}

static SAM_STATE: SpinLock<SamState> = SpinLock::new(SamState::new());

/// SAM statistics
struct SamStats {
    /// User lookups
    user_lookups: AtomicU64,
    /// Group lookups
    group_lookups: AtomicU64,
    /// Password validations
    password_validations: AtomicU64,
    /// Failed password validations
    failed_validations: AtomicU64,
    /// Account creations
    account_creations: AtomicU64,
    /// Account deletions
    account_deletions: AtomicU64,
}

static SAM_STATS: SamStats = SamStats {
    user_lookups: AtomicU64::new(0),
    group_lookups: AtomicU64::new(0),
    password_validations: AtomicU64::new(0),
    failed_validations: AtomicU64::new(0),
    account_creations: AtomicU64::new(0),
    account_deletions: AtomicU64::new(0),
};

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the SAM database
pub fn init() {
    crate::serial_println!("[SAM] Initializing Security Account Manager...");

    let mut state = SAM_STATE.lock();

    if state.initialized {
        crate::serial_println!("[SAM] Already initialized");
        return;
    }

    // Set up domain
    setup_domain(&mut state);

    // Create builtin accounts
    create_builtin_users(&mut state);
    create_builtin_groups(&mut state);
    create_builtin_aliases(&mut state);

    state.initialized = true;

    crate::serial_println!("[SAM] Security Account Manager initialized");
}

fn setup_domain(state: &mut SamState) {
    let name = b"BUILTIN";
    state.domain.name[..name.len()].copy_from_slice(name);
    state.domain.name_len = name.len();

    // Generate domain SID
    state.domain.sid = 0x0105_0000_0000_0020; // S-1-5-32 (BUILTIN)

    state.domain.server_role = ServerRole::Standalone;
    state.domain.min_password_length = 0;
    state.domain.password_history_length = 0;
    state.domain.lockout_threshold = 0;
}

fn create_builtin_users(state: &mut SamState) {
    // Create Administrator
    if state.user_count < MAX_USERS {
        let user = &mut state.users[state.user_count];
        user.in_use = true;
        user.rid = well_known_rids::DOMAIN_USER_RID_ADMIN;

        let name = b"Administrator";
        user.username[..name.len()].copy_from_slice(name);
        user.username_len = name.len();

        let full = b"Built-in account for administering the computer/domain";
        let full_len = full.len().min(MAX_USERNAME_LEN);
        user.full_name[..full_len].copy_from_slice(&full[..full_len]);
        user.full_name_len = full_len;

        user.user_account_control = user_account_control::UF_NORMAL_ACCOUNT;
        user.primary_group_rid = well_known_rids::DOMAIN_GROUP_RID_ADMINS;
        user.creation_time = get_tick_count();

        state.user_count += 1;
        state.domain.user_count += 1;
    }

    // Create Guest (disabled by default)
    if state.user_count < MAX_USERS {
        let user = &mut state.users[state.user_count];
        user.in_use = true;
        user.rid = well_known_rids::DOMAIN_USER_RID_GUEST;

        let name = b"Guest";
        user.username[..name.len()].copy_from_slice(name);
        user.username_len = name.len();

        let full = b"Built-in account for guest access to the computer/domain";
        let full_len = full.len().min(MAX_USERNAME_LEN);
        user.full_name[..full_len].copy_from_slice(&full[..full_len]);
        user.full_name_len = full_len;

        user.user_account_control = user_account_control::UF_NORMAL_ACCOUNT
            | user_account_control::UF_ACCOUNT_DISABLED
            | user_account_control::UF_PASSWORD_NOT_REQUIRED;
        user.primary_group_rid = well_known_rids::DOMAIN_GROUP_RID_GUESTS;
        user.creation_time = get_tick_count();

        state.user_count += 1;
        state.domain.user_count += 1;
    }

    crate::serial_println!("[SAM] Created {} builtin users", state.user_count);
}

fn create_builtin_groups(state: &mut SamState) {
    // Domain Admins
    if state.group_count < MAX_GROUPS {
        let group = &mut state.groups[state.group_count];
        group.in_use = true;
        group.rid = well_known_rids::DOMAIN_GROUP_RID_ADMINS;

        let name = b"Domain Admins";
        group.name[..name.len()].copy_from_slice(name);
        group.name_len = name.len();

        let comment = b"Designated administrators of the domain";
        group.comment[..comment.len()].copy_from_slice(comment);
        group.comment_len = comment.len();

        // Add Administrator to Domain Admins
        group.members[0] = well_known_rids::DOMAIN_USER_RID_ADMIN;
        group.member_count = 1;

        state.group_count += 1;
        state.domain.group_count += 1;
    }

    // Domain Users
    if state.group_count < MAX_GROUPS {
        let group = &mut state.groups[state.group_count];
        group.in_use = true;
        group.rid = well_known_rids::DOMAIN_GROUP_RID_USERS;

        let name = b"Domain Users";
        group.name[..name.len()].copy_from_slice(name);
        group.name_len = name.len();

        let comment = b"All domain users";
        group.comment[..comment.len()].copy_from_slice(comment);
        group.comment_len = comment.len();

        state.group_count += 1;
        state.domain.group_count += 1;
    }

    // Domain Guests
    if state.group_count < MAX_GROUPS {
        let group = &mut state.groups[state.group_count];
        group.in_use = true;
        group.rid = well_known_rids::DOMAIN_GROUP_RID_GUESTS;

        let name = b"Domain Guests";
        group.name[..name.len()].copy_from_slice(name);
        group.name_len = name.len();

        let comment = b"All domain guests";
        group.comment[..comment.len()].copy_from_slice(comment);
        group.comment_len = comment.len();

        // Add Guest to Domain Guests
        group.members[0] = well_known_rids::DOMAIN_USER_RID_GUEST;
        group.member_count = 1;

        state.group_count += 1;
        state.domain.group_count += 1;
    }

    crate::serial_println!("[SAM] Created {} builtin groups", state.group_count);
}

fn create_builtin_aliases(state: &mut SamState) {
    // Administrators
    if state.alias_count < MAX_ALIASES {
        let alias = &mut state.aliases[state.alias_count];
        alias.in_use = true;
        alias.rid = well_known_rids::DOMAIN_ALIAS_RID_ADMINS;

        let name = b"Administrators";
        alias.name[..name.len()].copy_from_slice(name);
        alias.name_len = name.len();

        let comment = b"Administrators have complete and unrestricted access to the computer/domain";
        let comment_len = comment.len().min(MAX_COMMENT_LEN);
        alias.comment[..comment_len].copy_from_slice(&comment[..comment_len]);
        alias.comment_len = comment_len;

        state.alias_count += 1;
        state.domain.alias_count += 1;
    }

    // Users
    if state.alias_count < MAX_ALIASES {
        let alias = &mut state.aliases[state.alias_count];
        alias.in_use = true;
        alias.rid = well_known_rids::DOMAIN_ALIAS_RID_USERS;

        let name = b"Users";
        alias.name[..name.len()].copy_from_slice(name);
        alias.name_len = name.len();

        let comment = b"Users are prevented from making accidental or intentional system-wide changes";
        let comment_len = comment.len().min(MAX_COMMENT_LEN);
        alias.comment[..comment_len].copy_from_slice(&comment[..comment_len]);
        alias.comment_len = comment_len;

        state.alias_count += 1;
        state.domain.alias_count += 1;
    }

    // Guests
    if state.alias_count < MAX_ALIASES {
        let alias = &mut state.aliases[state.alias_count];
        alias.in_use = true;
        alias.rid = well_known_rids::DOMAIN_ALIAS_RID_GUESTS;

        let name = b"Guests";
        alias.name[..name.len()].copy_from_slice(name);
        alias.name_len = name.len();

        let comment = b"Guests have the same access as members of the Users group by default";
        alias.comment[..comment.len()].copy_from_slice(comment);
        alias.comment_len = comment.len();

        state.alias_count += 1;
        state.domain.alias_count += 1;
    }

    // Power Users
    if state.alias_count < MAX_ALIASES {
        let alias = &mut state.aliases[state.alias_count];
        alias.in_use = true;
        alias.rid = well_known_rids::DOMAIN_ALIAS_RID_POWER_USERS;

        let name = b"Power Users";
        alias.name[..name.len()].copy_from_slice(name);
        alias.name_len = name.len();

        let comment = b"Power Users possess most administrative powers with some restrictions";
        alias.comment[..comment.len()].copy_from_slice(comment);
        alias.comment_len = comment.len();

        state.alias_count += 1;
        state.domain.alias_count += 1;
    }

    // Backup Operators
    if state.alias_count < MAX_ALIASES {
        let alias = &mut state.aliases[state.alias_count];
        alias.in_use = true;
        alias.rid = well_known_rids::DOMAIN_ALIAS_RID_BACKUP_OPS;

        let name = b"Backup Operators";
        alias.name[..name.len()].copy_from_slice(name);
        alias.name_len = name.len();

        let comment = b"Backup Operators can override security restrictions for the sole purpose of backing up or restoring files";
        let comment_len = comment.len().min(MAX_COMMENT_LEN);
        alias.comment[..comment_len].copy_from_slice(&comment[..comment_len]);
        alias.comment_len = comment_len;

        state.alias_count += 1;
        state.domain.alias_count += 1;
    }

    // Remote Desktop Users
    if state.alias_count < MAX_ALIASES {
        let alias = &mut state.aliases[state.alias_count];
        alias.in_use = true;
        alias.rid = well_known_rids::DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS;

        let name = b"Remote Desktop Users";
        alias.name[..name.len()].copy_from_slice(name);
        alias.name_len = name.len();

        let comment = b"Members in this group are granted the right to logon remotely";
        alias.comment[..comment.len()].copy_from_slice(comment);
        alias.comment_len = comment.len();

        state.alias_count += 1;
        state.domain.alias_count += 1;
    }

    crate::serial_println!("[SAM] Created {} builtin aliases", state.alias_count);
}

// ============================================================================
// User Operations
// ============================================================================

/// Create a new user account
pub fn sam_create_user(username: &[u8]) -> Result<Rid, SamError> {
    let mut state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    if username.len() > MAX_USERNAME_LEN {
        return Err(SamError::InvalidParameter);
    }

    // Check if exists
    for i in 0..MAX_USERS {
        if state.users[i].in_use && state.users[i].get_username() == username {
            return Err(SamError::UserExists);
        }
    }

    if state.user_count >= MAX_USERS {
        return Err(SamError::InsufficientResources);
    }

    // Allocate RID
    let rid = state.domain.next_rid;
    state.domain.next_rid += 1;

    // Find free slot
    for i in 0..MAX_USERS {
        if !state.users[i].in_use {
            let user = &mut state.users[i];
            user.in_use = true;
            user.rid = rid;
            user.username[..username.len()].copy_from_slice(username);
            user.username_len = username.len();
            user.user_account_control = user_account_control::UF_NORMAL_ACCOUNT;
            user.primary_group_rid = well_known_rids::DOMAIN_GROUP_RID_USERS;
            user.creation_time = get_tick_count();

            state.user_count += 1;
            state.domain.user_count += 1;

            SAM_STATS.account_creations.fetch_add(1, Ordering::Relaxed);

            return Ok(rid);
        }
    }

    Err(SamError::InsufficientResources)
}

/// Delete a user account
pub fn sam_delete_user(rid: Rid) -> Result<(), SamError> {
    let mut state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    // Can't delete builtin accounts
    if rid == well_known_rids::DOMAIN_USER_RID_ADMIN
        || rid == well_known_rids::DOMAIN_USER_RID_GUEST
    {
        return Err(SamError::AccessDenied);
    }

    for i in 0..MAX_USERS {
        if state.users[i].in_use && state.users[i].rid == rid {
            state.users[i].in_use = false;
            state.users[i] = UserAccount::empty();

            if state.user_count > 0 {
                state.user_count -= 1;
            }
            if state.domain.user_count > 0 {
                state.domain.user_count -= 1;
            }

            SAM_STATS.account_deletions.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(SamError::UserNotFound)
}

/// Get user by RID
pub fn sam_get_user_by_rid(rid: Rid) -> Result<UserAccount, SamError> {
    let state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    SAM_STATS.user_lookups.fetch_add(1, Ordering::Relaxed);

    for i in 0..MAX_USERS {
        if state.users[i].in_use && state.users[i].rid == rid {
            return Ok(state.users[i].clone());
        }
    }

    Err(SamError::UserNotFound)
}

/// Get user by username
pub fn sam_get_user_by_name(username: &[u8]) -> Result<UserAccount, SamError> {
    let state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    SAM_STATS.user_lookups.fetch_add(1, Ordering::Relaxed);

    for i in 0..MAX_USERS {
        if state.users[i].in_use && state.users[i].get_username() == username {
            return Ok(state.users[i].clone());
        }
    }

    Err(SamError::UserNotFound)
}

/// Set user password (NT hash)
pub fn sam_set_user_password(rid: Rid, nt_hash: &[u8]) -> Result<(), SamError> {
    let mut state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    if nt_hash.len() != MAX_PASSWORD_HASH_LEN {
        return Err(SamError::InvalidParameter);
    }

    for i in 0..MAX_USERS {
        if state.users[i].in_use && state.users[i].rid == rid {
            state.users[i].nt_password_hash.copy_from_slice(nt_hash);
            state.users[i].password_last_set = get_tick_count();
            return Ok(());
        }
    }

    Err(SamError::UserNotFound)
}

/// Validate user password
pub fn sam_validate_password(rid: Rid, nt_hash: &[u8]) -> Result<bool, SamError> {
    let state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    if nt_hash.len() != MAX_PASSWORD_HASH_LEN {
        return Err(SamError::InvalidParameter);
    }

    SAM_STATS.password_validations.fetch_add(1, Ordering::Relaxed);

    for i in 0..MAX_USERS {
        if state.users[i].in_use && state.users[i].rid == rid {
            // Check if account is disabled
            if state.users[i].is_disabled() {
                return Err(SamError::AccountDisabled);
            }
            if state.users[i].is_locked() {
                return Err(SamError::AccountLocked);
            }

            // Compare hashes
            if state.users[i].nt_password_hash == nt_hash {
                return Ok(true);
            } else {
                SAM_STATS.failed_validations.fetch_add(1, Ordering::Relaxed);
                return Ok(false);
            }
        }
    }

    Err(SamError::UserNotFound)
}

/// Enable or disable user account
pub fn sam_set_user_enabled(rid: Rid, enabled: bool) -> Result<(), SamError> {
    let mut state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    for i in 0..MAX_USERS {
        if state.users[i].in_use && state.users[i].rid == rid {
            if enabled {
                state.users[i].user_account_control &= !user_account_control::UF_ACCOUNT_DISABLED;
            } else {
                state.users[i].user_account_control |= user_account_control::UF_ACCOUNT_DISABLED;
            }
            return Ok(());
        }
    }

    Err(SamError::UserNotFound)
}

/// Enumerate users
pub fn sam_enumerate_users() -> Vec<UserAccount> {
    let state = SAM_STATE.lock();
    let mut users = Vec::new();

    if !state.initialized {
        return users;
    }

    for i in 0..MAX_USERS {
        if state.users[i].in_use {
            users.push(state.users[i].clone());
        }
    }

    users
}

// ============================================================================
// Group Operations
// ============================================================================

/// Create a new group
pub fn sam_create_group(name: &[u8]) -> Result<Rid, SamError> {
    let mut state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    if name.len() > MAX_GROUP_NAME_LEN {
        return Err(SamError::InvalidParameter);
    }

    // Check if exists
    for i in 0..MAX_GROUPS {
        if state.groups[i].in_use && state.groups[i].get_name() == name {
            return Err(SamError::GroupExists);
        }
    }

    if state.group_count >= MAX_GROUPS {
        return Err(SamError::InsufficientResources);
    }

    let rid = state.domain.next_rid;
    state.domain.next_rid += 1;

    for i in 0..MAX_GROUPS {
        if !state.groups[i].in_use {
            let group = &mut state.groups[i];
            group.in_use = true;
            group.rid = rid;
            group.name[..name.len()].copy_from_slice(name);
            group.name_len = name.len();
            group.attributes = group_type::GROUP_TYPE_ACCOUNT_GROUP
                | group_type::GROUP_TYPE_SECURITY_ENABLED;

            state.group_count += 1;
            state.domain.group_count += 1;

            return Ok(rid);
        }
    }

    Err(SamError::InsufficientResources)
}

/// Get group by RID
pub fn sam_get_group_by_rid(rid: Rid) -> Result<GroupAccount, SamError> {
    let state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    SAM_STATS.group_lookups.fetch_add(1, Ordering::Relaxed);

    for i in 0..MAX_GROUPS {
        if state.groups[i].in_use && state.groups[i].rid == rid {
            return Ok(state.groups[i].clone());
        }
    }

    Err(SamError::GroupNotFound)
}

/// Add member to group
pub fn sam_add_member_to_group(group_rid: Rid, member_rid: Rid) -> Result<(), SamError> {
    let mut state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    for i in 0..MAX_GROUPS {
        if state.groups[i].in_use && state.groups[i].rid == group_rid {
            // Check if already member
            if state.groups[i].has_member(member_rid) {
                return Err(SamError::MemberInAlias);
            }

            if state.groups[i].member_count >= MAX_GROUP_MEMBERS {
                return Err(SamError::InsufficientResources);
            }

            let count = state.groups[i].member_count;
            state.groups[i].members[count] = member_rid;
            state.groups[i].member_count += 1;

            return Ok(());
        }
    }

    Err(SamError::GroupNotFound)
}

/// Remove member from group
pub fn sam_remove_member_from_group(group_rid: Rid, member_rid: Rid) -> Result<(), SamError> {
    let mut state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    for i in 0..MAX_GROUPS {
        if state.groups[i].in_use && state.groups[i].rid == group_rid {
            for j in 0..state.groups[i].member_count {
                if state.groups[i].members[j] == member_rid {
                    // Shift remaining members
                    for k in j..state.groups[i].member_count - 1 {
                        state.groups[i].members[k] = state.groups[i].members[k + 1];
                    }
                    state.groups[i].member_count -= 1;
                    return Ok(());
                }
            }
            return Err(SamError::MemberNotFound);
        }
    }

    Err(SamError::GroupNotFound)
}

/// Enumerate groups
pub fn sam_enumerate_groups() -> Vec<GroupAccount> {
    let state = SAM_STATE.lock();
    let mut groups = Vec::new();

    if !state.initialized {
        return groups;
    }

    for i in 0..MAX_GROUPS {
        if state.groups[i].in_use {
            groups.push(state.groups[i].clone());
        }
    }

    groups
}

// ============================================================================
// Alias Operations
// ============================================================================

/// Get alias by RID
pub fn sam_get_alias_by_rid(rid: Rid) -> Result<AliasAccount, SamError> {
    let state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    for i in 0..MAX_ALIASES {
        if state.aliases[i].in_use && state.aliases[i].rid == rid {
            return Ok(state.aliases[i].clone());
        }
    }

    Err(SamError::AliasNotFound)
}

/// Add member to alias
pub fn sam_add_member_to_alias(alias_rid: Rid, member_rid: Rid) -> Result<(), SamError> {
    let mut state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    for i in 0..MAX_ALIASES {
        if state.aliases[i].in_use && state.aliases[i].rid == alias_rid {
            if state.aliases[i].has_member(member_rid) {
                return Err(SamError::MemberInAlias);
            }

            if state.aliases[i].member_count >= MAX_GROUP_MEMBERS {
                return Err(SamError::InsufficientResources);
            }

            let count = state.aliases[i].member_count;
            state.aliases[i].members[count] = member_rid;
            state.aliases[i].member_count += 1;

            return Ok(());
        }
    }

    Err(SamError::AliasNotFound)
}

/// Enumerate aliases
pub fn sam_enumerate_aliases() -> Vec<AliasAccount> {
    let state = SAM_STATE.lock();
    let mut aliases = Vec::new();

    if !state.initialized {
        return aliases;
    }

    for i in 0..MAX_ALIASES {
        if state.aliases[i].in_use {
            aliases.push(state.aliases[i].clone());
        }
    }

    aliases
}

// ============================================================================
// Domain Operations
// ============================================================================

/// Get domain information
pub fn sam_get_domain_info() -> Result<DomainInfo, SamError> {
    let state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    Ok(state.domain.clone())
}

/// Set domain password policy
pub fn sam_set_password_policy(
    min_length: u16,
    history_length: u16,
    max_age: u64,
    min_age: u64,
) -> Result<(), SamError> {
    let mut state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    state.domain.min_password_length = min_length;
    state.domain.password_history_length = history_length;
    state.domain.max_password_age = max_age;
    state.domain.min_password_age = min_age;

    Ok(())
}

/// Set domain lockout policy
pub fn sam_set_lockout_policy(
    threshold: u16,
    duration: u64,
    observation_window: u64,
) -> Result<(), SamError> {
    let mut state = SAM_STATE.lock();

    if !state.initialized {
        return Err(SamError::NotInitialized);
    }

    state.domain.lockout_threshold = threshold;
    state.domain.lockout_duration = duration;
    state.domain.lockout_observation_window = observation_window;

    Ok(())
}

// ============================================================================
// Statistics
// ============================================================================

/// SAM statistics snapshot
#[derive(Debug, Clone, Default)]
pub struct SamStatsSnapshot {
    pub user_lookups: u64,
    pub group_lookups: u64,
    pub password_validations: u64,
    pub failed_validations: u64,
    pub account_creations: u64,
    pub account_deletions: u64,
    pub user_count: usize,
    pub group_count: usize,
    pub alias_count: usize,
}

/// Get SAM statistics
pub fn sam_get_stats() -> SamStatsSnapshot {
    let state = SAM_STATE.lock();

    SamStatsSnapshot {
        user_lookups: SAM_STATS.user_lookups.load(Ordering::Relaxed),
        group_lookups: SAM_STATS.group_lookups.load(Ordering::Relaxed),
        password_validations: SAM_STATS.password_validations.load(Ordering::Relaxed),
        failed_validations: SAM_STATS.failed_validations.load(Ordering::Relaxed),
        account_creations: SAM_STATS.account_creations.load(Ordering::Relaxed),
        account_deletions: SAM_STATS.account_deletions.load(Ordering::Relaxed),
        user_count: state.user_count,
        group_count: state.group_count,
        alias_count: state.alias_count,
    }
}

/// Check if SAM is initialized
pub fn sam_is_initialized() -> bool {
    SAM_STATE.lock().initialized
}

/// Get server role name
pub fn server_role_name(role: ServerRole) -> &'static str {
    match role {
        ServerRole::Standalone => "Standalone",
        ServerRole::MemberServer => "Member Server",
        ServerRole::PrimaryDC => "Primary Domain Controller",
        ServerRole::BackupDC => "Backup Domain Controller",
    }
}
