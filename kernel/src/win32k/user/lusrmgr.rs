//! Local Users and Groups
//!
//! Implements Local Users and Groups management following Windows Server 2003.
//! Provides local user account and group management.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - lusrmgr.msc - Local Users and Groups snap-in
//! - User Manager (usrmgr.exe)
//! - Net user / net localgroup commands

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum users
const MAX_USERS: usize = 64;

/// Maximum groups
const MAX_GROUPS: usize = 32;

/// Maximum group members
const MAX_MEMBERS: usize = 64;

/// Maximum name length
const MAX_NAME: usize = 64;

/// Maximum description length
const MAX_DESC: usize = 256;

// ============================================================================
// Account Flags
// ============================================================================

bitflags::bitflags! {
    /// User account flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AccountFlags: u32 {
        /// Account is disabled
        const DISABLED = 0x0001;
        /// Account is locked out
        const LOCKED_OUT = 0x0002;
        /// Password never expires
        const PASSWORD_NEVER_EXPIRES = 0x0004;
        /// User cannot change password
        const CANNOT_CHANGE_PASSWORD = 0x0008;
        /// User must change password at next logon
        const MUST_CHANGE_PASSWORD = 0x0010;
        /// Password not required
        const PASSWORD_NOT_REQUIRED = 0x0020;
        /// Account expired
        const EXPIRED = 0x0040;
        /// Smart card required
        const SMARTCARD_REQUIRED = 0x0080;
        /// Account is trusted for delegation
        const TRUSTED_FOR_DELEGATION = 0x0100;
        /// Normal account
        const NORMAL_ACCOUNT = 0x1000;
    }
}

// ============================================================================
// User Entry
// ============================================================================

/// Local user account
#[derive(Debug, Clone, Copy)]
pub struct UserEntry {
    /// User ID (RID)
    pub user_id: u32,
    /// Username
    pub username: [u8; MAX_NAME],
    /// Username length
    pub username_len: usize,
    /// Full name
    pub full_name: [u8; MAX_NAME],
    /// Full name length
    pub fullname_len: usize,
    /// Description
    pub description: [u8; MAX_DESC],
    /// Description length
    pub desc_len: usize,
    /// Account flags
    pub flags: AccountFlags,
    /// Home directory
    pub home_dir: [u8; MAX_NAME],
    /// Home dir length
    pub home_len: usize,
    /// Logon script
    pub script_path: [u8; MAX_NAME],
    /// Script path length
    pub script_len: usize,
    /// Profile path
    pub profile_path: [u8; MAX_NAME],
    /// Profile path length
    pub profile_len: usize,
    /// Last logon time
    pub last_logon: u64,
    /// Password last set
    pub password_set: u64,
    /// Account expires (0 = never)
    pub account_expires: u64,
    /// Number of logons
    pub logon_count: u32,
    /// Bad password count
    pub bad_password_count: u32,
}

impl UserEntry {
    pub const fn new() -> Self {
        Self {
            user_id: 0,
            username: [0u8; MAX_NAME],
            username_len: 0,
            full_name: [0u8; MAX_NAME],
            fullname_len: 0,
            description: [0u8; MAX_DESC],
            desc_len: 0,
            flags: AccountFlags::NORMAL_ACCOUNT,
            home_dir: [0u8; MAX_NAME],
            home_len: 0,
            script_path: [0u8; MAX_NAME],
            script_len: 0,
            profile_path: [0u8; MAX_NAME],
            profile_len: 0,
            last_logon: 0,
            password_set: 0,
            account_expires: 0,
            logon_count: 0,
            bad_password_count: 0,
        }
    }

    pub fn set_username(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.username[..len].copy_from_slice(&name[..len]);
        self.username_len = len;
    }

    pub fn set_full_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.full_name[..len].copy_from_slice(&name[..len]);
        self.fullname_len = len;
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_DESC);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.desc_len = len;
    }

    pub fn is_disabled(&self) -> bool {
        self.flags.contains(AccountFlags::DISABLED)
    }

    pub fn is_locked(&self) -> bool {
        self.flags.contains(AccountFlags::LOCKED_OUT)
    }
}

impl Default for UserEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Group Type
// ============================================================================

/// Group type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GroupType {
    /// Security group - local
    #[default]
    SecurityLocal = 0,
    /// Distribution group
    Distribution = 1,
}

// ============================================================================
// Group Entry
// ============================================================================

/// Local group
#[derive(Debug, Clone, Copy)]
pub struct GroupEntry {
    /// Group ID (RID)
    pub group_id: u32,
    /// Group name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC],
    /// Description length
    pub desc_len: usize,
    /// Group type
    pub group_type: GroupType,
    /// Is built-in group
    pub is_builtin: bool,
    /// Member count
    pub member_count: usize,
    /// Member user IDs
    pub members: [u32; MAX_MEMBERS],
}

impl GroupEntry {
    pub const fn new() -> Self {
        Self {
            group_id: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            description: [0u8; MAX_DESC],
            desc_len: 0,
            group_type: GroupType::SecurityLocal,
            is_builtin: false,
            member_count: 0,
            members: [0; MAX_MEMBERS],
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_description(&mut self, desc: &[u8]) {
        let len = desc.len().min(MAX_DESC);
        self.description[..len].copy_from_slice(&desc[..len]);
        self.desc_len = len;
    }

    pub fn add_member(&mut self, user_id: u32) -> bool {
        if self.member_count >= MAX_MEMBERS {
            return false;
        }
        // Check if already a member
        for i in 0..self.member_count {
            if self.members[i] == user_id {
                return false;
            }
        }
        self.members[self.member_count] = user_id;
        self.member_count += 1;
        true
    }

    pub fn remove_member(&mut self, user_id: u32) -> bool {
        for i in 0..self.member_count {
            if self.members[i] == user_id {
                for j in i..self.member_count - 1 {
                    self.members[j] = self.members[j + 1];
                }
                self.member_count -= 1;
                return true;
            }
        }
        false
    }

    pub fn is_member(&self, user_id: u32) -> bool {
        for i in 0..self.member_count {
            if self.members[i] == user_id {
                return true;
            }
        }
        false
    }
}

impl Default for GroupEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// User Manager State
// ============================================================================

/// Local Users and Groups state
struct LusrMgrState {
    /// Users
    users: [UserEntry; MAX_USERS],
    /// User count
    user_count: usize,
    /// Next user ID
    next_user_id: u32,
    /// Groups
    groups: [GroupEntry; MAX_GROUPS],
    /// Group count
    group_count: usize,
    /// Next group ID
    next_group_id: u32,
    /// Selected user ID
    selected_user: u32,
    /// Selected group ID
    selected_group: u32,
}

impl LusrMgrState {
    pub const fn new() -> Self {
        Self {
            users: [const { UserEntry::new() }; MAX_USERS],
            user_count: 0,
            next_user_id: 1000, // Start at 1000 (RIDs below are built-in)
            groups: [const { GroupEntry::new() }; MAX_GROUPS],
            group_count: 0,
            next_group_id: 1000,
            selected_user: 0,
            selected_group: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static LUSRMGR_INITIALIZED: AtomicBool = AtomicBool::new(false);
static LUSRMGR_STATE: SpinLock<LusrMgrState> = SpinLock::new(LusrMgrState::new());

// Statistics
static USERS_CREATED: AtomicU32 = AtomicU32::new(0);
static GROUPS_CREATED: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Local Users and Groups
pub fn init() {
    if LUSRMGR_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = LUSRMGR_STATE.lock();

    // Add built-in users
    add_builtin_users(&mut state);

    // Add built-in groups
    add_builtin_groups(&mut state);

    // Add users to groups
    setup_group_membership(&mut state);

    crate::serial_println!("[WIN32K] Local Users and Groups initialized");
}

/// Add built-in users
fn add_builtin_users(state: &mut LusrMgrState) {
    let users: [(&[u8], &[u8], u32, AccountFlags); 4] = [
        (b"Administrator", b"Built-in account for administering the computer/domain", 500,
         AccountFlags::NORMAL_ACCOUNT),
        (b"Guest", b"Built-in account for guest access to the computer/domain", 501,
         AccountFlags::NORMAL_ACCOUNT | AccountFlags::DISABLED | AccountFlags::PASSWORD_NOT_REQUIRED),
        (b"SUPPORT_388945a0", b"This is a vendor's account for the Help and Support Service", 1001,
         AccountFlags::NORMAL_ACCOUNT | AccountFlags::DISABLED),
        (b"HelpAssistant", b"Account for providing Remote Assistance", 1002,
         AccountFlags::NORMAL_ACCOUNT | AccountFlags::DISABLED),
    ];

    for (name, desc, rid, flags) in users.iter() {
        if state.user_count >= MAX_USERS {
            break;
        }
        let mut user = UserEntry::new();
        user.user_id = *rid;
        user.set_username(name);
        user.set_description(desc);
        user.flags = *flags;
        user.password_set = 1104537600; // Some time in the past

        let idx = state.user_count;
        state.users[idx] = user;
        state.user_count += 1;
    }
}

/// Add built-in groups
fn add_builtin_groups(state: &mut LusrMgrState) {
    let groups: [(&[u8], &[u8], u32); 10] = [
        (b"Administrators", b"Administrators have complete and unrestricted access to the computer/domain", 544),
        (b"Backup Operators", b"Backup Operators can override security restrictions for the sole purpose of backing up or restoring files", 551),
        (b"Guests", b"Guests have the same access as members of the Users group by default", 546),
        (b"Network Configuration Operators", b"Members in this group can have some administrative privileges to manage configuration of networking features", 556),
        (b"Power Users", b"Power Users possess most administrative powers with some restrictions", 547),
        (b"Remote Desktop Users", b"Members in this group are granted the right to logon remotely", 555),
        (b"Replicator", b"Supports file replication in a domain", 552),
        (b"Users", b"Users are prevented from making accidental or intentional system-wide changes", 545),
        (b"HelpServicesGroup", b"Group for the Help and Support Center", 1003),
        (b"TelnetClients", b"Members of this group have access to Telnet Server on this system", 1004),
    ];

    for (name, desc, rid) in groups.iter() {
        if state.group_count >= MAX_GROUPS {
            break;
        }
        let mut group = GroupEntry::new();
        group.group_id = *rid;
        group.set_name(name);
        group.set_description(desc);
        group.is_builtin = *rid < 1000;

        let idx = state.group_count;
        state.groups[idx] = group;
        state.group_count += 1;
    }
}

/// Set up initial group membership
fn setup_group_membership(state: &mut LusrMgrState) {
    // Add Administrator to Administrators group
    for i in 0..state.group_count {
        if state.groups[i].group_id == 544 { // Administrators
            state.groups[i].add_member(500); // Administrator user
            break;
        }
    }

    // Add Guest to Guests group
    for i in 0..state.group_count {
        if state.groups[i].group_id == 546 { // Guests
            state.groups[i].add_member(501); // Guest user
            break;
        }
    }
}

// ============================================================================
// User Management
// ============================================================================

/// Get user count
pub fn get_user_count() -> usize {
    LUSRMGR_STATE.lock().user_count
}

/// Get user by index
pub fn get_user(index: usize) -> Option<UserEntry> {
    let state = LUSRMGR_STATE.lock();
    if index < state.user_count {
        Some(state.users[index])
    } else {
        None
    }
}

/// Get user by ID
pub fn get_user_by_id(user_id: u32) -> Option<UserEntry> {
    let state = LUSRMGR_STATE.lock();
    for i in 0..state.user_count {
        if state.users[i].user_id == user_id {
            return Some(state.users[i]);
        }
    }
    None
}

/// Get user by name
pub fn get_user_by_name(username: &[u8]) -> Option<UserEntry> {
    let state = LUSRMGR_STATE.lock();
    for i in 0..state.user_count {
        if state.users[i].username_len == username.len() &&
           &state.users[i].username[..state.users[i].username_len] == username {
            return Some(state.users[i]);
        }
    }
    None
}

/// Create new user
pub fn create_user(username: &[u8], full_name: &[u8], description: &[u8]) -> Option<u32> {
    let mut state = LUSRMGR_STATE.lock();

    if state.user_count >= MAX_USERS {
        return None;
    }

    // Check for duplicate username
    for i in 0..state.user_count {
        if state.users[i].username_len == username.len() &&
           &state.users[i].username[..state.users[i].username_len] == username {
            return None;
        }
    }

    let user_id = state.next_user_id;
    state.next_user_id += 1;

    let mut user = UserEntry::new();
    user.user_id = user_id;
    user.set_username(username);
    user.set_full_name(full_name);
    user.set_description(description);
    user.flags = AccountFlags::NORMAL_ACCOUNT | AccountFlags::MUST_CHANGE_PASSWORD;

    let idx = state.user_count;
    state.users[idx] = user;
    state.user_count += 1;

    USERS_CREATED.fetch_add(1, Ordering::Relaxed);
    Some(user_id)
}

/// Delete user
pub fn delete_user(user_id: u32) -> bool {
    let mut state = LUSRMGR_STATE.lock();

    // Cannot delete built-in accounts
    if user_id == 500 || user_id == 501 {
        return false;
    }

    let mut found_index = None;
    for i in 0..state.user_count {
        if state.users[i].user_id == user_id {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..state.user_count - 1 {
            state.users[i] = state.users[i + 1];
        }
        state.user_count -= 1;

        // Remove from all groups
        for g in 0..state.group_count {
            state.groups[g].remove_member(user_id);
        }

        true
    } else {
        false
    }
}

/// Enable/disable user
pub fn set_user_enabled(user_id: u32, enabled: bool) -> bool {
    let mut state = LUSRMGR_STATE.lock();
    for i in 0..state.user_count {
        if state.users[i].user_id == user_id {
            if enabled {
                state.users[i].flags.remove(AccountFlags::DISABLED);
            } else {
                state.users[i].flags.insert(AccountFlags::DISABLED);
            }
            return true;
        }
    }
    false
}

/// Unlock user account
pub fn unlock_user(user_id: u32) -> bool {
    let mut state = LUSRMGR_STATE.lock();
    for i in 0..state.user_count {
        if state.users[i].user_id == user_id {
            state.users[i].flags.remove(AccountFlags::LOCKED_OUT);
            state.users[i].bad_password_count = 0;
            return true;
        }
    }
    false
}

/// Set user flags
pub fn set_user_flags(user_id: u32, flags: AccountFlags) -> bool {
    let mut state = LUSRMGR_STATE.lock();
    for i in 0..state.user_count {
        if state.users[i].user_id == user_id {
            // Preserve NORMAL_ACCOUNT flag
            state.users[i].flags = flags | AccountFlags::NORMAL_ACCOUNT;
            return true;
        }
    }
    false
}

/// Reset user password (stub)
pub fn reset_password(user_id: u32, _new_password: &[u8]) -> bool {
    let mut state = LUSRMGR_STATE.lock();
    for i in 0..state.user_count {
        if state.users[i].user_id == user_id {
            state.users[i].password_set = 0; // Would be current timestamp
            state.users[i].flags.remove(AccountFlags::MUST_CHANGE_PASSWORD);
            return true;
        }
    }
    false
}

/// Select user
pub fn select_user(user_id: u32) {
    LUSRMGR_STATE.lock().selected_user = user_id;
}

/// Get selected user
pub fn get_selected_user() -> u32 {
    LUSRMGR_STATE.lock().selected_user
}

// ============================================================================
// Group Management
// ============================================================================

/// Get group count
pub fn get_group_count() -> usize {
    LUSRMGR_STATE.lock().group_count
}

/// Get group by index
pub fn get_group(index: usize) -> Option<GroupEntry> {
    let state = LUSRMGR_STATE.lock();
    if index < state.group_count {
        Some(state.groups[index])
    } else {
        None
    }
}

/// Get group by ID
pub fn get_group_by_id(group_id: u32) -> Option<GroupEntry> {
    let state = LUSRMGR_STATE.lock();
    for i in 0..state.group_count {
        if state.groups[i].group_id == group_id {
            return Some(state.groups[i]);
        }
    }
    None
}

/// Get group by name
pub fn get_group_by_name(name: &[u8]) -> Option<GroupEntry> {
    let state = LUSRMGR_STATE.lock();
    for i in 0..state.group_count {
        if state.groups[i].name_len == name.len() &&
           &state.groups[i].name[..state.groups[i].name_len] == name {
            return Some(state.groups[i]);
        }
    }
    None
}

/// Create new group
pub fn create_group(name: &[u8], description: &[u8]) -> Option<u32> {
    let mut state = LUSRMGR_STATE.lock();

    if state.group_count >= MAX_GROUPS {
        return None;
    }

    // Check for duplicate name
    for i in 0..state.group_count {
        if state.groups[i].name_len == name.len() &&
           &state.groups[i].name[..state.groups[i].name_len] == name {
            return None;
        }
    }

    let group_id = state.next_group_id;
    state.next_group_id += 1;

    let mut group = GroupEntry::new();
    group.group_id = group_id;
    group.set_name(name);
    group.set_description(description);

    let idx = state.group_count;
    state.groups[idx] = group;
    state.group_count += 1;

    GROUPS_CREATED.fetch_add(1, Ordering::Relaxed);
    Some(group_id)
}

/// Delete group
pub fn delete_group(group_id: u32) -> bool {
    let mut state = LUSRMGR_STATE.lock();

    // Cannot delete built-in groups
    for i in 0..state.group_count {
        if state.groups[i].group_id == group_id {
            if state.groups[i].is_builtin {
                return false;
            }
            break;
        }
    }

    let mut found_index = None;
    for i in 0..state.group_count {
        if state.groups[i].group_id == group_id {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..state.group_count - 1 {
            state.groups[i] = state.groups[i + 1];
        }
        state.group_count -= 1;
        true
    } else {
        false
    }
}

/// Add member to group
pub fn add_group_member(group_id: u32, user_id: u32) -> bool {
    let mut state = LUSRMGR_STATE.lock();
    for i in 0..state.group_count {
        if state.groups[i].group_id == group_id {
            return state.groups[i].add_member(user_id);
        }
    }
    false
}

/// Remove member from group
pub fn remove_group_member(group_id: u32, user_id: u32) -> bool {
    let mut state = LUSRMGR_STATE.lock();
    for i in 0..state.group_count {
        if state.groups[i].group_id == group_id {
            return state.groups[i].remove_member(user_id);
        }
    }
    false
}

/// Get groups for user
pub fn get_user_groups(user_id: u32, buffer: &mut [GroupEntry]) -> usize {
    let state = LUSRMGR_STATE.lock();
    let mut count = 0;
    for i in 0..state.group_count {
        if state.groups[i].is_member(user_id) {
            if count < buffer.len() {
                buffer[count] = state.groups[i];
                count += 1;
            }
        }
    }
    count
}

/// Select group
pub fn select_group(group_id: u32) {
    LUSRMGR_STATE.lock().selected_group = group_id;
}

/// Get selected group
pub fn get_selected_group() -> u32 {
    LUSRMGR_STATE.lock().selected_group
}

// ============================================================================
// Statistics
// ============================================================================

/// Local Users and Groups statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct LusrMgrStats {
    pub initialized: bool,
    pub user_count: usize,
    pub group_count: usize,
    pub disabled_users: usize,
    pub locked_users: usize,
    pub users_created: u32,
    pub groups_created: u32,
}

/// Get Local Users and Groups statistics
pub fn get_stats() -> LusrMgrStats {
    let state = LUSRMGR_STATE.lock();
    let disabled = state.users[..state.user_count].iter().filter(|u| u.is_disabled()).count();
    let locked = state.users[..state.user_count].iter().filter(|u| u.is_locked()).count();
    LusrMgrStats {
        initialized: LUSRMGR_INITIALIZED.load(Ordering::Relaxed),
        user_count: state.user_count,
        group_count: state.group_count,
        disabled_users: disabled,
        locked_users: locked,
        users_created: USERS_CREATED.load(Ordering::Relaxed),
        groups_created: GROUPS_CREATED.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Local Users and Groups dialog handle
pub type HLUSRMGRDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Local Users and Groups dialog
pub fn create_lusrmgr_dialog(_parent: super::super::HWND) -> HLUSRMGRDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
