//! User Profile Functions
//!
//! Implements Windows user profile management APIs for loading, unloading,
//! and querying user profiles.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/userenv.h` - User environment definitions
//! - `ds/security/gina/userenv/` - User environment implementation
//! - `shell/ext/userenv/` - Shell user environment

use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum loaded profiles
const MAX_PROFILES: usize = 32;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Maximum username length
const MAX_USERNAME: usize = 256;

/// Maximum domain length
const MAX_DOMAIN: usize = 256;

/// Maximum profile type name
const MAX_PROFILE_TYPE_NAME: usize = 64;

// ============================================================================
// Profile Types
// ============================================================================

/// User profile type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProfileType {
    #[default]
    /// Local profile
    Local = 0,
    /// Roaming profile
    Roaming = 1,
    /// Mandatory profile
    Mandatory = 2,
    /// Temporary profile
    Temporary = 4,
}

/// Profile info flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ProfileFlags: u32 {
        /// Use default user profile if user profile doesn't exist
        const PI_NOUI = 0x00000001;
        /// Load profile for backup/restore
        const PI_APPLYPOLICY = 0x00000002;
        /// Load user profile as guest
        const PI_LITELOAD = 0x00000004;
    }
}

// ============================================================================
// Known Folders
// ============================================================================

/// Known folder IDs
pub mod known_folders {
    pub const CSIDL_DESKTOP: u32 = 0x0000;
    pub const CSIDL_INTERNET: u32 = 0x0001;
    pub const CSIDL_PROGRAMS: u32 = 0x0002;
    pub const CSIDL_CONTROLS: u32 = 0x0003;
    pub const CSIDL_PRINTERS: u32 = 0x0004;
    pub const CSIDL_PERSONAL: u32 = 0x0005;
    pub const CSIDL_FAVORITES: u32 = 0x0006;
    pub const CSIDL_STARTUP: u32 = 0x0007;
    pub const CSIDL_RECENT: u32 = 0x0008;
    pub const CSIDL_SENDTO: u32 = 0x0009;
    pub const CSIDL_BITBUCKET: u32 = 0x000A;
    pub const CSIDL_STARTMENU: u32 = 0x000B;
    pub const CSIDL_MYDOCUMENTS: u32 = 0x000C;
    pub const CSIDL_MYMUSIC: u32 = 0x000D;
    pub const CSIDL_MYVIDEO: u32 = 0x000E;
    pub const CSIDL_DESKTOPDIRECTORY: u32 = 0x0010;
    pub const CSIDL_DRIVES: u32 = 0x0011;
    pub const CSIDL_NETWORK: u32 = 0x0012;
    pub const CSIDL_NETHOOD: u32 = 0x0013;
    pub const CSIDL_FONTS: u32 = 0x0014;
    pub const CSIDL_TEMPLATES: u32 = 0x0015;
    pub const CSIDL_COMMON_STARTMENU: u32 = 0x0016;
    pub const CSIDL_COMMON_PROGRAMS: u32 = 0x0017;
    pub const CSIDL_COMMON_STARTUP: u32 = 0x0018;
    pub const CSIDL_COMMON_DESKTOPDIRECTORY: u32 = 0x0019;
    pub const CSIDL_APPDATA: u32 = 0x001A;
    pub const CSIDL_PRINTHOOD: u32 = 0x001B;
    pub const CSIDL_LOCAL_APPDATA: u32 = 0x001C;
    pub const CSIDL_ALTSTARTUP: u32 = 0x001D;
    pub const CSIDL_COMMON_ALTSTARTUP: u32 = 0x001E;
    pub const CSIDL_COMMON_FAVORITES: u32 = 0x001F;
    pub const CSIDL_INTERNET_CACHE: u32 = 0x0020;
    pub const CSIDL_COOKIES: u32 = 0x0021;
    pub const CSIDL_HISTORY: u32 = 0x0022;
    pub const CSIDL_COMMON_APPDATA: u32 = 0x0023;
    pub const CSIDL_WINDOWS: u32 = 0x0024;
    pub const CSIDL_SYSTEM: u32 = 0x0025;
    pub const CSIDL_PROGRAM_FILES: u32 = 0x0026;
    pub const CSIDL_MYPICTURES: u32 = 0x0027;
    pub const CSIDL_PROFILE: u32 = 0x0028;
    pub const CSIDL_SYSTEMX86: u32 = 0x0029;
    pub const CSIDL_PROGRAM_FILESX86: u32 = 0x002A;
    pub const CSIDL_PROGRAM_FILES_COMMON: u32 = 0x002B;
    pub const CSIDL_PROGRAM_FILES_COMMONX86: u32 = 0x002C;
    pub const CSIDL_COMMON_TEMPLATES: u32 = 0x002D;
    pub const CSIDL_COMMON_DOCUMENTS: u32 = 0x002E;
    pub const CSIDL_COMMON_ADMINTOOLS: u32 = 0x002F;
    pub const CSIDL_ADMINTOOLS: u32 = 0x0030;
    pub const CSIDL_CONNECTIONS: u32 = 0x0031;
    pub const CSIDL_COMMON_MUSIC: u32 = 0x0035;
    pub const CSIDL_COMMON_PICTURES: u32 = 0x0036;
    pub const CSIDL_COMMON_VIDEO: u32 = 0x0037;
    pub const CSIDL_RESOURCES: u32 = 0x0038;
    pub const CSIDL_RESOURCES_LOCALIZED: u32 = 0x0039;
    pub const CSIDL_COMMON_OEM_LINKS: u32 = 0x003A;
    pub const CSIDL_CDBURN_AREA: u32 = 0x003B;
    pub const CSIDL_COMPUTERSNEARME: u32 = 0x003D;

    // Flags
    pub const CSIDL_FLAG_CREATE: u32 = 0x8000;
    pub const CSIDL_FLAG_DONT_VERIFY: u32 = 0x4000;
    pub const CSIDL_FLAG_DONT_UNEXPAND: u32 = 0x2000;
    pub const CSIDL_FLAG_NO_ALIAS: u32 = 0x1000;
    pub const CSIDL_FLAG_PER_USER_INIT: u32 = 0x0800;
    pub const CSIDL_FLAG_MASK: u32 = 0xFF00;
}

// ============================================================================
// Profile Info Structure
// ============================================================================

/// Profile information for loading
#[derive(Debug, Clone)]
pub struct ProfileInfo {
    /// Username
    pub user_name: [u8; MAX_USERNAME],
    /// Flags
    pub flags: ProfileFlags,
    /// Profile path (output)
    pub profile_path: [u8; MAX_PATH],
    /// Default profile path
    pub default_path: [u8; MAX_PATH],
    /// Server name for roaming profiles
    pub server_name: [u8; MAX_PATH],
    /// Policy path
    pub policy_path: [u8; MAX_PATH],
    /// User's profile handle (output)
    pub profile_handle: u32,
}

impl ProfileInfo {
    pub fn new() -> Self {
        Self {
            user_name: [0u8; MAX_USERNAME],
            flags: ProfileFlags::empty(),
            profile_path: [0u8; MAX_PATH],
            default_path: [0u8; MAX_PATH],
            server_name: [0u8; MAX_PATH],
            policy_path: [0u8; MAX_PATH],
            profile_handle: 0,
        }
    }

    pub fn set_user_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_USERNAME - 1);
        self.user_name[..len].copy_from_slice(&name[..len]);
        self.user_name[len] = 0;
    }
}

impl Default for ProfileInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Loaded Profile State
// ============================================================================

/// Loaded profile entry
#[derive(Debug)]
struct LoadedProfile {
    in_use: bool,
    handle: u32,
    user_name: [u8; MAX_USERNAME],
    domain: [u8; MAX_DOMAIN],
    profile_path: [u8; MAX_PATH],
    profile_type: ProfileType,
    ref_count: u32,
    user_token: u32,
}

impl LoadedProfile {
    const fn new() -> Self {
        Self {
            in_use: false,
            handle: 0,
            user_name: [0u8; MAX_USERNAME],
            domain: [0u8; MAX_DOMAIN],
            profile_path: [0u8; MAX_PATH],
            profile_type: ProfileType::Local,
            ref_count: 0,
            user_token: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static PROFILE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_PROFILE_HANDLE: AtomicU32 = AtomicU32::new(1);
static PROFILES: SpinLock<[LoadedProfile; MAX_PROFILES]> = SpinLock::new(
    [const { LoadedProfile::new() }; MAX_PROFILES]
);
static PROFILES_DIR: SpinLock<[u8; MAX_PATH]> = SpinLock::new([0u8; MAX_PATH]);
static DEFAULT_USER_PROFILE: SpinLock<[u8; MAX_PATH]> = SpinLock::new([0u8; MAX_PATH]);
static ALL_USERS_PROFILE: SpinLock<[u8; MAX_PATH]> = SpinLock::new([0u8; MAX_PATH]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize user profile subsystem
pub fn init() {
    if PROFILE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[PROFILE] Initializing user profile subsystem...");

    // Set default paths
    let profiles_dir = b"C:\\Documents and Settings";
    let mut dir = PROFILES_DIR.lock();
    dir[..profiles_dir.len()].copy_from_slice(profiles_dir);

    let default_profile = b"C:\\Documents and Settings\\Default User";
    let mut def = DEFAULT_USER_PROFILE.lock();
    def[..default_profile.len()].copy_from_slice(default_profile);

    let all_users = b"C:\\Documents and Settings\\All Users";
    let mut all = ALL_USERS_PROFILE.lock();
    all[..all_users.len()].copy_from_slice(all_users);

    crate::serial_println!("[PROFILE] User profile subsystem initialized");
}

// ============================================================================
// Profile Load/Unload Functions
// ============================================================================

/// Load a user profile
pub fn load_user_profile(user_token: u32, info: &mut ProfileInfo) -> bool {
    let mut profiles = PROFILES.lock();

    // Check if already loaded for this user
    for profile in profiles.iter() {
        if profile.in_use && name_matches(&profile.user_name, &info.user_name) {
            info.profile_handle = profile.handle;
            let path_len = str_len(&profile.profile_path);
            info.profile_path[..path_len].copy_from_slice(&profile.profile_path[..path_len]);
            return true;
        }
    }

    // Find free slot
    let slot_idx = profiles.iter().position(|p| !p.in_use);
    let idx = match slot_idx {
        Some(i) => i,
        None => return false,
    };

    let handle = NEXT_PROFILE_HANDLE.fetch_add(1, Ordering::SeqCst);

    let profile = &mut profiles[idx];
    profile.in_use = true;
    profile.handle = handle;
    profile.user_token = user_token;
    profile.ref_count = 1;
    profile.profile_type = ProfileType::Local;

    // Copy username
    let name_len = str_len(&info.user_name);
    profile.user_name[..name_len].copy_from_slice(&info.user_name[..name_len]);

    // Build profile path
    let profiles_dir = PROFILES_DIR.lock();
    let dir_len = str_len(&*profiles_dir);

    let mut path_pos = 0;
    profile.profile_path[path_pos..path_pos + dir_len].copy_from_slice(&profiles_dir[..dir_len]);
    path_pos += dir_len;

    if path_pos < MAX_PATH - 1 {
        profile.profile_path[path_pos] = b'\\';
        path_pos += 1;
    }

    let copy_len = name_len.min(MAX_PATH - path_pos - 1);
    profile.profile_path[path_pos..path_pos + copy_len].copy_from_slice(&info.user_name[..copy_len]);
    path_pos += copy_len;
    profile.profile_path[path_pos] = 0;

    // Copy path to output
    info.profile_path[..path_pos].copy_from_slice(&profile.profile_path[..path_pos]);
    info.profile_handle = handle;

    crate::serial_println!("[PROFILE] Loaded profile for user, handle {}", handle);

    true
}

/// Unload a user profile
pub fn unload_user_profile(user_token: u32, profile_handle: u32) -> bool {
    let _ = user_token;

    let mut profiles = PROFILES.lock();

    for profile in profiles.iter_mut() {
        if profile.in_use && profile.handle == profile_handle {
            profile.ref_count = profile.ref_count.saturating_sub(1);

            if profile.ref_count == 0 {
                profile.in_use = false;
                crate::serial_println!("[PROFILE] Unloaded profile {}", profile_handle);
            }

            return true;
        }
    }

    false
}

// ============================================================================
// Profile Path Functions
// ============================================================================

/// Get the user profile directory
pub fn get_user_profile_directory(user_token: u32, buffer: &mut [u8]) -> Option<usize> {
    let profiles = PROFILES.lock();

    for profile in profiles.iter() {
        if profile.in_use && profile.user_token == user_token {
            let len = str_len(&profile.profile_path);
            let copy_len = len.min(buffer.len() - 1);
            buffer[..copy_len].copy_from_slice(&profile.profile_path[..copy_len]);
            buffer[copy_len] = 0;
            return Some(copy_len);
        }
    }

    None
}

/// Get the All Users profile directory
pub fn get_all_users_profile_directory(buffer: &mut [u8]) -> Option<usize> {
    let all_users = ALL_USERS_PROFILE.lock();
    let len = str_len(&*all_users);
    let copy_len = len.min(buffer.len() - 1);
    buffer[..copy_len].copy_from_slice(&all_users[..copy_len]);
    buffer[copy_len] = 0;
    Some(copy_len)
}

/// Get the Default User profile directory
pub fn get_default_user_profile_directory(buffer: &mut [u8]) -> Option<usize> {
    let default_user = DEFAULT_USER_PROFILE.lock();
    let len = str_len(&*default_user);
    let copy_len = len.min(buffer.len() - 1);
    buffer[..copy_len].copy_from_slice(&default_user[..copy_len]);
    buffer[copy_len] = 0;
    Some(copy_len)
}

/// Get the profiles directory
pub fn get_profiles_directory(buffer: &mut [u8]) -> Option<usize> {
    let profiles_dir = PROFILES_DIR.lock();
    let len = str_len(&*profiles_dir);
    let copy_len = len.min(buffer.len() - 1);
    buffer[..copy_len].copy_from_slice(&profiles_dir[..copy_len]);
    buffer[copy_len] = 0;
    Some(copy_len)
}

/// Get profile type
pub fn get_profile_type(user_token: u32) -> Option<ProfileType> {
    let profiles = PROFILES.lock();

    for profile in profiles.iter() {
        if profile.in_use && profile.user_token == user_token {
            return Some(profile.profile_type);
        }
    }

    None
}

// ============================================================================
// Special Folder Functions
// ============================================================================

/// Get special folder path
pub fn get_folder_path(
    user_token: Option<u32>,
    folder: u32,
    buffer: &mut [u8],
) -> Option<usize> {
    let csidl = folder & !known_folders::CSIDL_FLAG_MASK;

    // Get base profile path
    let base_path = if let Some(token) = user_token {
        let profiles = PROFILES.lock();
        let mut path = [0u8; MAX_PATH];

        let found = profiles.iter().find(|p| p.in_use && p.user_token == token);

        if let Some(profile) = found {
            let len = str_len(&profile.profile_path);
            path[..len].copy_from_slice(&profile.profile_path[..len]);
        }
        path
    } else {
        let default = DEFAULT_USER_PROFILE.lock();
        let mut path = [0u8; MAX_PATH];
        let len = str_len(&*default);
        path[..len].copy_from_slice(&default[..len]);
        path
    };

    let base_len = str_len(&base_path);

    // Get folder suffix based on CSIDL
    let suffix: &[u8] = match csidl {
        known_folders::CSIDL_DESKTOP | known_folders::CSIDL_DESKTOPDIRECTORY => b"\\Desktop",
        known_folders::CSIDL_PROGRAMS => b"\\Start Menu\\Programs",
        known_folders::CSIDL_PERSONAL | known_folders::CSIDL_MYDOCUMENTS => b"\\My Documents",
        known_folders::CSIDL_FAVORITES => b"\\Favorites",
        known_folders::CSIDL_STARTUP => b"\\Start Menu\\Programs\\Startup",
        known_folders::CSIDL_RECENT => b"\\Recent",
        known_folders::CSIDL_SENDTO => b"\\SendTo",
        known_folders::CSIDL_STARTMENU => b"\\Start Menu",
        known_folders::CSIDL_MYMUSIC => b"\\My Documents\\My Music",
        known_folders::CSIDL_MYVIDEO => b"\\My Documents\\My Videos",
        known_folders::CSIDL_MYPICTURES => b"\\My Documents\\My Pictures",
        known_folders::CSIDL_NETHOOD => b"\\NetHood",
        known_folders::CSIDL_TEMPLATES => b"\\Templates",
        known_folders::CSIDL_APPDATA => b"\\Application Data",
        known_folders::CSIDL_PRINTHOOD => b"\\PrintHood",
        known_folders::CSIDL_LOCAL_APPDATA => b"\\Local Settings\\Application Data",
        known_folders::CSIDL_INTERNET_CACHE => b"\\Local Settings\\Temporary Internet Files",
        known_folders::CSIDL_COOKIES => b"\\Cookies",
        known_folders::CSIDL_HISTORY => b"\\Local Settings\\History",
        known_folders::CSIDL_ADMINTOOLS => b"\\Start Menu\\Programs\\Administrative Tools",
        known_folders::CSIDL_PROFILE => b"",
        known_folders::CSIDL_FONTS => {
            let path = b"C:\\Windows\\Fonts";
            let len = path.len().min(buffer.len() - 1);
            buffer[..len].copy_from_slice(&path[..len]);
            buffer[len] = 0;
            return Some(len);
        }
        known_folders::CSIDL_WINDOWS => {
            let path = b"C:\\Windows";
            let len = path.len().min(buffer.len() - 1);
            buffer[..len].copy_from_slice(&path[..len]);
            buffer[len] = 0;
            return Some(len);
        }
        known_folders::CSIDL_SYSTEM => {
            let path = b"C:\\Windows\\System32";
            let len = path.len().min(buffer.len() - 1);
            buffer[..len].copy_from_slice(&path[..len]);
            buffer[len] = 0;
            return Some(len);
        }
        known_folders::CSIDL_PROGRAM_FILES => {
            let path = b"C:\\Program Files";
            let len = path.len().min(buffer.len() - 1);
            buffer[..len].copy_from_slice(&path[..len]);
            buffer[len] = 0;
            return Some(len);
        }
        known_folders::CSIDL_COMMON_APPDATA => {
            let all_users = ALL_USERS_PROFILE.lock();
            let len = str_len(&*all_users);
            let suffix = b"\\Application Data";
            let total = len + suffix.len();
            if total < buffer.len() {
                buffer[..len].copy_from_slice(&all_users[..len]);
                buffer[len..len + suffix.len()].copy_from_slice(suffix);
                buffer[total] = 0;
                return Some(total);
            }
            return None;
        }
        known_folders::CSIDL_COMMON_DOCUMENTS => {
            let all_users = ALL_USERS_PROFILE.lock();
            let len = str_len(&*all_users);
            let suffix = b"\\Documents";
            let total = len + suffix.len();
            if total < buffer.len() {
                buffer[..len].copy_from_slice(&all_users[..len]);
                buffer[len..len + suffix.len()].copy_from_slice(suffix);
                buffer[total] = 0;
                return Some(total);
            }
            return None;
        }
        _ => return None,
    };

    let total_len = base_len + suffix.len();
    if total_len >= buffer.len() {
        return None;
    }

    buffer[..base_len].copy_from_slice(&base_path[..base_len]);
    buffer[base_len..base_len + suffix.len()].copy_from_slice(suffix);
    buffer[total_len] = 0;

    Some(total_len)
}

// ============================================================================
// Environment Block Functions
// ============================================================================

/// Create environment block for user
pub fn create_environment_block(
    user_token: Option<u32>,
    inherit: bool,
    buffer: &mut [u8],
) -> usize {
    let _ = inherit;

    let mut pos = 0;

    // Add standard environment variables
    let vars: &[(&[u8], &[u8])] = &[
        (b"ALLUSERSPROFILE", b"C:\\Documents and Settings\\All Users"),
        (b"APPDATA", b"C:\\Documents and Settings\\User\\Application Data"),
        (b"COMMONPROGRAMFILES", b"C:\\Program Files\\Common Files"),
        (b"COMPUTERNAME", b"COMPUTER"),
        (b"COMSPEC", b"C:\\Windows\\System32\\cmd.exe"),
        (b"HOMEDRIVE", b"C:"),
        (b"HOMEPATH", b"\\Documents and Settings\\User"),
        (b"LOCALAPPDATA", b"C:\\Documents and Settings\\User\\Local Settings\\Application Data"),
        (b"LOGONSERVER", b"\\\\COMPUTER"),
        (b"NUMBER_OF_PROCESSORS", b"1"),
        (b"OS", b"Windows_NT"),
        (b"PATH", b"C:\\Windows\\System32;C:\\Windows"),
        (b"PATHEXT", b".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH"),
        (b"PROCESSOR_ARCHITECTURE", b"AMD64"),
        (b"PROCESSOR_IDENTIFIER", b"AMD64 Family 6 Model 0 Stepping 0"),
        (b"PROCESSOR_LEVEL", b"6"),
        (b"PROCESSOR_REVISION", b"0000"),
        (b"PROGRAMFILES", b"C:\\Program Files"),
        (b"SYSTEMDRIVE", b"C:"),
        (b"SYSTEMROOT", b"C:\\Windows"),
        (b"TEMP", b"C:\\Documents and Settings\\User\\Local Settings\\Temp"),
        (b"TMP", b"C:\\Documents and Settings\\User\\Local Settings\\Temp"),
        (b"USERDOMAIN", b"COMPUTER"),
        (b"USERNAME", b"User"),
        (b"USERPROFILE", b"C:\\Documents and Settings\\User"),
        (b"WINDIR", b"C:\\Windows"),
    ];

    // Override with actual profile path if available
    let profile_path = if let Some(token) = user_token {
        let profiles = PROFILES.lock();
        profiles.iter()
            .find(|p| p.in_use && p.user_token == token)
            .map(|p| {
                let len = str_len(&p.profile_path);
                let mut path = [0u8; MAX_PATH];
                path[..len].copy_from_slice(&p.profile_path[..len]);
                path
            })
    } else {
        None
    };

    for &(name, value) in vars {
        // Check if we should override with actual profile path
        let actual_value = if name == b"USERPROFILE" {
            if let Some(ref path) = profile_path {
                &path[..]
            } else {
                value
            }
        } else {
            value
        };

        let name_len = name.len();
        let value_len = str_len(actual_value);

        // NAME=VALUE\0
        let entry_len = name_len + 1 + value_len + 1;

        if pos + entry_len >= buffer.len() {
            break;
        }

        buffer[pos..pos + name_len].copy_from_slice(name);
        pos += name_len;
        buffer[pos] = b'=';
        pos += 1;
        buffer[pos..pos + value_len].copy_from_slice(&actual_value[..value_len]);
        pos += value_len;
        buffer[pos] = 0;
        pos += 1;
    }

    // Double null terminator
    if pos < buffer.len() {
        buffer[pos] = 0;
        pos += 1;
    }

    pos
}

/// Destroy environment block
pub fn destroy_environment_block(_buffer: &[u8]) -> bool {
    // No-op in this implementation
    true
}

// ============================================================================
// Profile Enumeration
// ============================================================================

/// Profile enumeration callback
pub type ProfileEnumCallback = fn(
    profile_path: &[u8],
    profile_type: ProfileType,
    lparam: usize,
) -> bool;

/// Enumerate all user profiles
pub fn enum_profiles(callback: ProfileEnumCallback, lparam: usize) -> bool {
    let profiles = PROFILES.lock();

    for profile in profiles.iter() {
        if profile.in_use {
            let path_len = str_len(&profile.profile_path);
            if !callback(&profile.profile_path[..path_len], profile.profile_type, lparam) {
                return false;
            }
        }
    }

    true
}

// ============================================================================
// Profile Deletion
// ============================================================================

/// Delete a user profile
pub fn delete_profile(sid_string: &[u8], profile_path: Option<&[u8]>) -> bool {
    let _ = (sid_string, profile_path);

    // Would delete the profile directory and registry entries
    crate::serial_println!("[PROFILE] Delete profile requested");

    true
}

// ============================================================================
// Roaming Profile Functions
// ============================================================================

/// Get roaming profile path from AD
pub fn get_roaming_profile_path(
    user_name: &[u8],
    domain: &[u8],
    buffer: &mut [u8],
) -> Option<usize> {
    let _ = (user_name, domain);

    // Would query Active Directory for roaming profile path
    if !buffer.is_empty() {
        buffer[0] = 0;
    }

    None
}

/// Set roaming profile path in AD
pub fn set_roaming_profile_path(
    user_name: &[u8],
    domain: &[u8],
    profile_path: &[u8],
) -> bool {
    let _ = (user_name, domain, profile_path);

    // Would update Active Directory
    false
}

// ============================================================================
// Helper Functions
// ============================================================================

fn str_len(s: &[u8]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

fn name_matches(stored: &[u8], search: &[u8]) -> bool {
    let stored_len = str_len(stored);
    let search_len = str_len(search);

    if stored_len != search_len {
        return false;
    }

    for i in 0..stored_len {
        if stored[i].to_ascii_uppercase() != search[i].to_ascii_uppercase() {
            return false;
        }
    }

    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Profile statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ProfileStats {
    pub initialized: bool,
    pub loaded_count: u32,
}

/// Get profile statistics
pub fn get_stats() -> ProfileStats {
    let profiles = PROFILES.lock();

    ProfileStats {
        initialized: PROFILE_INITIALIZED.load(Ordering::Relaxed),
        loaded_count: profiles.iter().filter(|p| p.in_use).count() as u32,
    }
}
