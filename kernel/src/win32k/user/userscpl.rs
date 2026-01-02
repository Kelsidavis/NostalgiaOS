//! User Accounts Control Panel
//!
//! Kernel-mode user accounts management dialog following Windows NT patterns.
//! Provides user creation, password management, and group membership.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/cpls/nusrmgr/` - User accounts control panel

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// Maximum users displayed
const MAX_USERS: usize = 64;

/// Maximum groups
const MAX_GROUPS: usize = 32;

/// Maximum user name length
const MAX_USER_NAME: usize = 256;

/// Maximum password length
const MAX_PASSWORD: usize = 127;

/// Maximum full name length
const MAX_FULL_NAME: usize = 256;

/// Maximum description length
const MAX_DESCRIPTION: usize = 256;

/// Maximum home directory path
const MAX_HOME_DIR: usize = 260;

/// Maximum profile path
const MAX_PROFILE: usize = 260;

/// Maximum logon script path
const MAX_SCRIPT: usize = 260;

/// Account types
pub mod account_type {
    /// Standard user
    pub const STANDARD: u32 = 0;
    /// Administrator
    pub const ADMINISTRATOR: u32 = 1;
    /// Guest
    pub const GUEST: u32 = 2;
    /// Power user
    pub const POWER_USER: u32 = 3;
}

/// User flags
pub mod user_flags {
    /// Account is disabled
    pub const DISABLED: u32 = 0x0001;
    /// Home directory required
    pub const HOMEDIR_REQUIRED: u32 = 0x0002;
    /// Password not required
    pub const PASSWD_NOTREQD: u32 = 0x0004;
    /// Password can't change
    pub const PASSWD_CANT_CHANGE: u32 = 0x0008;
    /// Account locked out
    pub const LOCKOUT: u32 = 0x0010;
    /// Don't expire password
    pub const DONT_EXPIRE_PASSWD: u32 = 0x0020;
    /// Encrypted text password allowed
    pub const ENCRYPTED_TEXT_PWD: u32 = 0x0080;
    /// Account is trusted for delegation
    pub const TRUSTED_FOR_DELEGATION: u32 = 0x0100;
    /// Account is sensitive
    pub const NOT_DELEGATED: u32 = 0x0200;
    /// Use DES encryption types
    pub const USE_DES_KEY_ONLY: u32 = 0x0400;
    /// Don't require preauth
    pub const DONT_REQ_PREAUTH: u32 = 0x0800;
    /// Password expired
    pub const PASSWORD_EXPIRED: u32 = 0x1000;
    /// Normal account
    pub const NORMAL_ACCOUNT: u32 = 0x0200;
    /// Interdomain trust account
    pub const INTERDOMAIN_TRUST: u32 = 0x0800;
    /// Workstation trust account
    pub const WORKSTATION_TRUST: u32 = 0x1000;
    /// Server trust account
    pub const SERVER_TRUST: u32 = 0x2000;
}

/// Group types
pub mod group_type {
    /// Built-in local group
    pub const BUILTIN_LOCAL: u32 = 0x00000001;
    /// Account group
    pub const ACCOUNT: u32 = 0x00000002;
    /// Resource group
    pub const RESOURCE: u32 = 0x00000004;
    /// Universal group
    pub const UNIVERSAL: u32 = 0x00000008;
    /// Security enabled
    pub const SECURITY_ENABLED: u32 = 0x80000000;
}

/// Well-known SIDs
pub mod well_known_sid {
    /// Everyone
    pub const EVERYONE: u32 = 0;
    /// Administrators
    pub const ADMINISTRATORS: u32 = 1;
    /// Users
    pub const USERS: u32 = 2;
    /// Guests
    pub const GUESTS: u32 = 3;
    /// Power Users
    pub const POWER_USERS: u32 = 4;
    /// Backup Operators
    pub const BACKUP_OPERATORS: u32 = 5;
    /// Remote Desktop Users
    pub const REMOTE_DESKTOP_USERS: u32 = 6;
    /// Network Configuration Operators
    pub const NETWORK_CONFIG_OPS: u32 = 7;
}

// ============================================================================
// Types
// ============================================================================

/// User account information
#[derive(Clone, Copy)]
pub struct UserAccount {
    /// User name
    pub name: [u8; MAX_USER_NAME],
    /// Name length
    pub name_len: u8,
    /// Full name (display name)
    pub full_name: [u8; MAX_FULL_NAME],
    /// Full name length
    pub full_name_len: u8,
    /// Description
    pub description: [u8; MAX_DESCRIPTION],
    /// Description length
    pub desc_len: u8,
    /// Account type
    pub account_type: u32,
    /// User flags
    pub flags: u32,
    /// Home directory
    pub home_dir: [u8; MAX_HOME_DIR],
    /// Home dir length
    pub home_dir_len: u16,
    /// Profile path
    pub profile: [u8; MAX_PROFILE],
    /// Profile length
    pub profile_len: u16,
    /// Logon script
    pub script: [u8; MAX_SCRIPT],
    /// Script length
    pub script_len: u16,
    /// Password last set timestamp
    pub password_last_set: u64,
    /// Account expires timestamp (0 = never)
    pub expires: u64,
    /// Last logon timestamp
    pub last_logon: u64,
    /// Number of logons
    pub logon_count: u32,
    /// Bad password count
    pub bad_password_count: u32,
    /// User ID (RID)
    pub user_id: u32,
    /// Primary group ID
    pub primary_group: u32,
}

impl UserAccount {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_USER_NAME],
            name_len: 0,
            full_name: [0; MAX_FULL_NAME],
            full_name_len: 0,
            description: [0; MAX_DESCRIPTION],
            desc_len: 0,
            account_type: account_type::STANDARD,
            flags: user_flags::NORMAL_ACCOUNT,
            home_dir: [0; MAX_HOME_DIR],
            home_dir_len: 0,
            profile: [0; MAX_PROFILE],
            profile_len: 0,
            script: [0; MAX_SCRIPT],
            script_len: 0,
            password_last_set: 0,
            expires: 0,
            last_logon: 0,
            logon_count: 0,
            bad_password_count: 0,
            user_id: 0,
            primary_group: 0,
        }
    }
}

/// Local group information
#[derive(Clone, Copy)]
pub struct LocalGroup {
    /// Group name
    pub name: [u8; MAX_USER_NAME],
    /// Name length
    pub name_len: u8,
    /// Description
    pub description: [u8; MAX_DESCRIPTION],
    /// Description length
    pub desc_len: u8,
    /// Group type
    pub group_type: u32,
    /// Group ID (RID)
    pub group_id: u32,
    /// Is built-in group
    pub is_builtin: bool,
}

impl LocalGroup {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_USER_NAME],
            name_len: 0,
            description: [0; MAX_DESCRIPTION],
            desc_len: 0,
            group_type: group_type::ACCOUNT | group_type::SECURITY_ENABLED,
            group_id: 0,
            is_builtin: false,
        }
    }
}

/// User accounts dialog state
struct UsersDialog {
    /// Parent window
    parent: HWND,
    /// Selected user index
    selected_user: i32,
    /// Selected group index
    selected_group: i32,
    /// Current view (0=users, 1=groups)
    current_view: u32,
    /// Modified flag
    modified: bool,
}

impl UsersDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            selected_user: -1,
            selected_group: -1,
            current_view: 0,
            modified: false,
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// User accounts
static USERS: SpinLock<[UserAccount; MAX_USERS]> =
    SpinLock::new([const { UserAccount::new() }; MAX_USERS]);

/// User count
static USER_COUNT: AtomicU32 = AtomicU32::new(0);

/// Local groups
static GROUPS: SpinLock<[LocalGroup; MAX_GROUPS]> =
    SpinLock::new([const { LocalGroup::new() }; MAX_GROUPS]);

/// Group count
static GROUP_COUNT: AtomicU32 = AtomicU32::new(0);

/// Dialog state
static DIALOG: SpinLock<UsersDialog> = SpinLock::new(UsersDialog::new());

/// Next user ID
static NEXT_USER_ID: AtomicU32 = AtomicU32::new(1000);

/// Next group ID
static NEXT_GROUP_ID: AtomicU32 = AtomicU32::new(1000);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize user accounts control panel
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Initialize built-in accounts
    init_builtin_accounts();

    // Initialize built-in groups
    init_builtin_groups();

    crate::serial_println!("[USERSCPL] User accounts initialized");
}

/// Initialize built-in user accounts
fn init_builtin_accounts() {
    let mut users = USERS.lock();
    let mut count = 0;

    // Administrator
    {
        let user = &mut users[count];
        let name = b"Administrator";
        let nlen = name.len();
        user.name[..nlen].copy_from_slice(name);
        user.name_len = nlen as u8;

        let desc = b"Built-in account for administering the computer/domain";
        let dlen = desc.len();
        user.description[..dlen].copy_from_slice(desc);
        user.desc_len = dlen as u8;

        user.account_type = account_type::ADMINISTRATOR;
        user.flags = user_flags::NORMAL_ACCOUNT | user_flags::DONT_EXPIRE_PASSWD;
        user.user_id = 500;
        user.primary_group = 513; // Domain Users
        count += 1;
    }

    // Guest
    {
        let user = &mut users[count];
        let name = b"Guest";
        let nlen = name.len();
        user.name[..nlen].copy_from_slice(name);
        user.name_len = nlen as u8;

        let desc = b"Built-in account for guest access to the computer/domain";
        let dlen = desc.len();
        user.description[..dlen].copy_from_slice(desc);
        user.desc_len = dlen as u8;

        user.account_type = account_type::GUEST;
        user.flags = user_flags::NORMAL_ACCOUNT | user_flags::DISABLED |
                    user_flags::PASSWD_NOTREQD | user_flags::DONT_EXPIRE_PASSWD;
        user.user_id = 501;
        user.primary_group = 514; // Domain Guests
        count += 1;
    }

    USER_COUNT.store(count as u32, Ordering::Release);
}

/// Initialize built-in groups
fn init_builtin_groups() {
    let mut groups = GROUPS.lock();
    let mut count = 0;

    let builtin_groups: &[(&[u8], &[u8], u32)] = &[
        (b"Administrators", b"Administrators have complete access to the computer", 544),
        (b"Users", b"Users can operate the computer and save documents", 545),
        (b"Guests", b"Guests have the same access as Users by default", 546),
        (b"Power Users", b"Power Users have more capabilities than Users", 547),
        (b"Backup Operators", b"Backup Operators can backup and restore files", 551),
        (b"Remote Desktop Users", b"Members can log on remotely", 555),
        (b"Network Configuration Operators", b"Members can manage network features", 556),
    ];

    for (name, desc, gid) in builtin_groups.iter() {
        if count >= MAX_GROUPS {
            break;
        }

        let group = &mut groups[count];

        let nlen = name.len().min(MAX_USER_NAME);
        group.name[..nlen].copy_from_slice(&name[..nlen]);
        group.name_len = nlen as u8;

        let dlen = desc.len().min(MAX_DESCRIPTION);
        group.description[..dlen].copy_from_slice(&desc[..dlen]);
        group.desc_len = dlen as u8;

        group.group_type = group_type::BUILTIN_LOCAL | group_type::SECURITY_ENABLED;
        group.group_id = *gid;
        group.is_builtin = true;

        count += 1;
    }

    GROUP_COUNT.store(count as u32, Ordering::Release);
}

// ============================================================================
// User Account Management
// ============================================================================

/// Get number of user accounts
pub fn get_user_count() -> u32 {
    USER_COUNT.load(Ordering::Acquire)
}

/// Get user account by index
pub fn get_user(index: usize, account: &mut UserAccount) -> bool {
    let users = USERS.lock();
    let count = USER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    *account = users[index];
    true
}

/// Find user by name
pub fn find_user(name: &[u8]) -> Option<usize> {
    let users = USERS.lock();
    let count = USER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = users[i].name_len as usize;
        if &users[i].name[..len] == name {
            return Some(i);
        }
    }
    None
}

/// Create a new user account
pub fn create_user(name: &[u8], full_name: &[u8], password: &[u8],
                   account_type: u32) -> Option<u32> {
    let mut users = USERS.lock();
    let count = USER_COUNT.load(Ordering::Acquire) as usize;

    if count >= MAX_USERS {
        return None;
    }

    // Check for duplicate name
    for i in 0..count {
        let len = users[i].name_len as usize;
        if &users[i].name[..len] == name {
            return None;
        }
    }

    let user = &mut users[count];
    let user_id = NEXT_USER_ID.fetch_add(1, Ordering::SeqCst);

    let nlen = name.len().min(MAX_USER_NAME);
    user.name[..nlen].copy_from_slice(&name[..nlen]);
    user.name_len = nlen as u8;

    let flen = full_name.len().min(MAX_FULL_NAME);
    user.full_name[..flen].copy_from_slice(&full_name[..flen]);
    user.full_name_len = flen as u8;

    user.account_type = account_type;
    user.flags = user_flags::NORMAL_ACCOUNT;
    user.user_id = user_id;
    user.primary_group = 513;

    // Would hash and store password
    let _ = password;

    USER_COUNT.store((count + 1) as u32, Ordering::Release);

    Some(user_id)
}

/// Delete a user account
pub fn delete_user(name: &[u8]) -> bool {
    let mut users = USERS.lock();
    let count = USER_COUNT.load(Ordering::Acquire) as usize;

    let mut found_index = None;
    for i in 0..count {
        let len = users[i].name_len as usize;
        if &users[i].name[..len] == name {
            // Don't delete built-in accounts
            if users[i].user_id == 500 || users[i].user_id == 501 {
                return false;
            }
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        // Shift remaining users
        for i in index..(count - 1) {
            users[i] = users[i + 1];
        }
        users[count - 1] = UserAccount::new();
        USER_COUNT.store((count - 1) as u32, Ordering::Release);
        return true;
    }

    false
}

/// Set user password
pub fn set_user_password(name: &[u8], _old_password: &[u8], _new_password: &[u8]) -> bool {
    let mut users = USERS.lock();
    let count = USER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = users[i].name_len as usize;
        if &users[i].name[..len] == name {
            // Would verify old password and hash new password
            users[i].password_last_set = 0; // Would set to current time
            users[i].flags &= !user_flags::PASSWORD_EXPIRED;
            return true;
        }
    }

    false
}

/// Enable or disable a user account
pub fn set_user_enabled(name: &[u8], enabled: bool) -> bool {
    let mut users = USERS.lock();
    let count = USER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = users[i].name_len as usize;
        if &users[i].name[..len] == name {
            if enabled {
                users[i].flags &= !user_flags::DISABLED;
            } else {
                users[i].flags |= user_flags::DISABLED;
            }
            return true;
        }
    }

    false
}

/// Set user account type
pub fn set_user_type(name: &[u8], acc_type: u32) -> bool {
    let mut users = USERS.lock();
    let count = USER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = users[i].name_len as usize;
        if &users[i].name[..len] == name {
            users[i].account_type = acc_type;
            return true;
        }
    }

    false
}

/// Check if user is administrator
pub fn is_user_admin(name: &[u8]) -> bool {
    let users = USERS.lock();
    let count = USER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = users[i].name_len as usize;
        if &users[i].name[..len] == name {
            return users[i].account_type == account_type::ADMINISTRATOR;
        }
    }

    false
}

// ============================================================================
// Group Management
// ============================================================================

/// Get number of groups
pub fn get_group_count() -> u32 {
    GROUP_COUNT.load(Ordering::Acquire)
}

/// Get group by index
pub fn get_group(index: usize, group: &mut LocalGroup) -> bool {
    let groups = GROUPS.lock();
    let count = GROUP_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    *group = groups[index];
    true
}

/// Find group by name
pub fn find_group(name: &[u8]) -> Option<usize> {
    let groups = GROUPS.lock();
    let count = GROUP_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = groups[i].name_len as usize;
        if &groups[i].name[..len] == name {
            return Some(i);
        }
    }
    None
}

/// Create a new local group
pub fn create_group(name: &[u8], description: &[u8]) -> Option<u32> {
    let mut groups = GROUPS.lock();
    let count = GROUP_COUNT.load(Ordering::Acquire) as usize;

    if count >= MAX_GROUPS {
        return None;
    }

    // Check for duplicate name
    for i in 0..count {
        let len = groups[i].name_len as usize;
        if &groups[i].name[..len] == name {
            return None;
        }
    }

    let group = &mut groups[count];
    let group_id = NEXT_GROUP_ID.fetch_add(1, Ordering::SeqCst);

    let nlen = name.len().min(MAX_USER_NAME);
    group.name[..nlen].copy_from_slice(&name[..nlen]);
    group.name_len = nlen as u8;

    let dlen = description.len().min(MAX_DESCRIPTION);
    group.description[..dlen].copy_from_slice(&description[..dlen]);
    group.desc_len = dlen as u8;

    group.group_type = group_type::ACCOUNT | group_type::SECURITY_ENABLED;
    group.group_id = group_id;
    group.is_builtin = false;

    GROUP_COUNT.store((count + 1) as u32, Ordering::Release);

    Some(group_id)
}

/// Delete a local group
pub fn delete_group(name: &[u8]) -> bool {
    let mut groups = GROUPS.lock();
    let count = GROUP_COUNT.load(Ordering::Acquire) as usize;

    let mut found_index = None;
    for i in 0..count {
        let len = groups[i].name_len as usize;
        if &groups[i].name[..len] == name {
            // Don't delete built-in groups
            if groups[i].is_builtin {
                return false;
            }
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..(count - 1) {
            groups[i] = groups[i + 1];
        }
        groups[count - 1] = LocalGroup::new();
        GROUP_COUNT.store((count - 1) as u32, Ordering::Release);
        return true;
    }

    false
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show user accounts control panel
pub fn show_user_accounts(parent: HWND) -> bool {
    let mut dialog = DIALOG.lock();

    dialog.parent = parent;
    dialog.selected_user = -1;
    dialog.selected_group = -1;
    dialog.current_view = 0;
    dialog.modified = false;

    // Would create dialog with:
    // - User list with icons
    // - Create/Delete/Properties buttons
    // - Change password button
    // - Group membership tab

    true
}

/// Show create user wizard
pub fn show_create_user_wizard(parent: HWND) -> bool {
    let _ = parent;
    // Would show wizard for creating new user
    true
}

/// Show user properties dialog
pub fn show_user_properties(parent: HWND, name: &[u8]) -> bool {
    let _ = (parent, name);
    // Would show properties dialog for user
    true
}

/// Show change password dialog
pub fn show_change_password(parent: HWND, name: &[u8]) -> bool {
    let _ = (parent, name);
    // Would show password change dialog
    true
}
