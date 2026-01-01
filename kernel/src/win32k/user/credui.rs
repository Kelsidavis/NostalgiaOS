//! Credential UI Support
//!
//! Credential management and authentication dialogs.
//! Based on Windows Server 2003 wincred.h and credui.h.
//!
//! # Features
//!
//! - Credential prompts
//! - Credential storage
//! - Smart card support
//! - Certificate selection
//!
//! # References
//!
//! - `public/sdk/inc/wincred.h` - Credential Manager
//! - `public/sdk/inc/credui.h` - Credential UI

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Credential Types (CRED_TYPE_*)
// ============================================================================

/// Generic credential
pub const CRED_TYPE_GENERIC: u32 = 1;

/// Domain password
pub const CRED_TYPE_DOMAIN_PASSWORD: u32 = 2;

/// Domain certificate
pub const CRED_TYPE_DOMAIN_CERTIFICATE: u32 = 3;

/// Domain visible password
pub const CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: u32 = 4;

/// Generic certificate
pub const CRED_TYPE_GENERIC_CERTIFICATE: u32 = 5;

/// Domain extended
pub const CRED_TYPE_DOMAIN_EXTENDED: u32 = 6;

/// Maximum credential type
pub const CRED_TYPE_MAXIMUM: u32 = 7;

/// Maximum extended credential type
pub const CRED_TYPE_MAXIMUM_EX: u32 = CRED_TYPE_MAXIMUM + 1000;

// ============================================================================
// Credential Persist (CRED_PERSIST_*)
// ============================================================================

/// Don't persist
pub const CRED_PERSIST_NONE: u32 = 0;

/// Persist for session
pub const CRED_PERSIST_SESSION: u32 = 1;

/// Persist locally
pub const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;

/// Persist for enterprise
pub const CRED_PERSIST_ENTERPRISE: u32 = 3;

// ============================================================================
// Credential Flags (CRED_FLAGS_*)
// ============================================================================

/// Prompt now
pub const CRED_FLAGS_PROMPT_NOW: u32 = 0x0002;

/// Username target
pub const CRED_FLAGS_USERNAME_TARGET: u32 = 0x0004;

// ============================================================================
// CredUI Flags (CREDUI_FLAGS_*)
// ============================================================================

/// Incorrect password
pub const CREDUI_FLAGS_INCORRECT_PASSWORD: u32 = 0x00000001;

/// Do not persist
pub const CREDUI_FLAGS_DO_NOT_PERSIST: u32 = 0x00000002;

/// Request administrator
pub const CREDUI_FLAGS_REQUEST_ADMINISTRATOR: u32 = 0x00000004;

/// Exclude certificates
pub const CREDUI_FLAGS_EXCLUDE_CERTIFICATES: u32 = 0x00000008;

/// Require certificate
pub const CREDUI_FLAGS_REQUIRE_CERTIFICATE: u32 = 0x00000010;

/// Show save check box
pub const CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX: u32 = 0x00000040;

/// Always show UI
pub const CREDUI_FLAGS_ALWAYS_SHOW_UI: u32 = 0x00000080;

/// Require smartcard
pub const CREDUI_FLAGS_REQUIRE_SMARTCARD: u32 = 0x00000100;

/// Password only OK
pub const CREDUI_FLAGS_PASSWORD_ONLY_OK: u32 = 0x00000200;

/// Validate username
pub const CREDUI_FLAGS_VALIDATE_USERNAME: u32 = 0x00000400;

/// Complete username
pub const CREDUI_FLAGS_COMPLETE_USERNAME: u32 = 0x00000800;

/// Persist
pub const CREDUI_FLAGS_PERSIST: u32 = 0x00001000;

/// Server credential
pub const CREDUI_FLAGS_SERVER_CREDENTIAL: u32 = 0x00004000;

/// Expect confirmation
pub const CREDUI_FLAGS_EXPECT_CONFIRMATION: u32 = 0x00020000;

/// Generic credentials
pub const CREDUI_FLAGS_GENERIC_CREDENTIALS: u32 = 0x00040000;

/// Username target credentials
pub const CREDUI_FLAGS_USERNAME_TARGET_CREDENTIALS: u32 = 0x00080000;

/// Keep username
pub const CREDUI_FLAGS_KEEP_USERNAME: u32 = 0x00100000;

// ============================================================================
// CredUI Return Codes
// ============================================================================

/// No error
pub const NO_ERROR: u32 = 0;

/// Cancelled
pub const ERROR_CANCELLED: u32 = 1223;

/// No such logon session
pub const ERROR_NO_SUCH_LOGON_SESSION: u32 = 1312;

/// Not found
pub const ERROR_NOT_FOUND: u32 = 1168;

/// Invalid account name
pub const ERROR_INVALID_ACCOUNT_NAME: u32 = 1315;

/// Invalid flags
pub const ERROR_INVALID_FLAGS: u32 = 1004;

/// Bad arguments
pub const ERROR_BAD_ARGUMENTS: u32 = 160;

// ============================================================================
// Constants
// ============================================================================

/// Maximum credentials
pub const MAX_CREDENTIALS: usize = 64;

/// Maximum username length
pub const CREDUI_MAX_USERNAME_LENGTH: usize = 256;

/// Maximum password length
pub const CREDUI_MAX_PASSWORD_LENGTH: usize = 256;

/// Maximum domain length
pub const CREDUI_MAX_DOMAIN_TARGET_LENGTH: usize = 256;

/// Maximum generic target length
pub const CREDUI_MAX_GENERIC_TARGET_LENGTH: usize = 32767;

/// Maximum message length
pub const CREDUI_MAX_MESSAGE_LENGTH: usize = 32767;

/// Maximum caption length
pub const CREDUI_MAX_CAPTION_LENGTH: usize = 128;

// ============================================================================
// Credential Structure
// ============================================================================

/// Credential entry
#[derive(Clone)]
pub struct Credential {
    /// Is this slot in use
    pub in_use: bool,
    /// Flags
    pub flags: u32,
    /// Type
    pub cred_type: u32,
    /// Target name
    pub target_name: [u8; 512],
    /// Comment
    pub comment: [u8; 256],
    /// Last written (fake timestamp)
    pub last_written: u64,
    /// Credential blob (password etc)
    pub credential_blob: [u8; CREDUI_MAX_PASSWORD_LENGTH],
    /// Credential blob size
    pub credential_blob_size: u32,
    /// Persist type
    pub persist: u32,
    /// User name
    pub user_name: [u8; CREDUI_MAX_USERNAME_LENGTH],
}

impl Credential {
    /// Create empty credential
    pub const fn new() -> Self {
        Self {
            in_use: false,
            flags: 0,
            cred_type: CRED_TYPE_GENERIC,
            target_name: [0; 512],
            comment: [0; 256],
            last_written: 0,
            credential_blob: [0; CREDUI_MAX_PASSWORD_LENGTH],
            credential_blob_size: 0,
            persist: CRED_PERSIST_SESSION,
            user_name: [0; CREDUI_MAX_USERNAME_LENGTH],
        }
    }
}

// ============================================================================
// Credential UI Info Structure
// ============================================================================

/// Credential UI info
#[derive(Clone)]
pub struct CredUIInfo {
    /// Size
    pub size: u32,
    /// Parent window
    pub parent: HWND,
    /// Message text
    pub message: [u8; 512],
    /// Caption
    pub caption: [u8; CREDUI_MAX_CAPTION_LENGTH],
    /// Banner bitmap (handle)
    pub banner: usize,
}

impl CredUIInfo {
    /// Create default info
    pub const fn new() -> Self {
        Self {
            size: 0,
            parent: UserHandle::NULL,
            message: [0; 512],
            caption: [0; CREDUI_MAX_CAPTION_LENGTH],
            banner: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global credential storage
static CREDENTIALS: SpinLock<[Credential; MAX_CREDENTIALS]> =
    SpinLock::new([const { Credential::new() }; MAX_CREDENTIALS]);

/// Credential timestamp counter
static CRED_TIMESTAMP: SpinLock<u64> = SpinLock::new(1);

// ============================================================================
// Public API
// ============================================================================

/// Initialize credential UI
pub fn init() {
    crate::serial_println!("[USER] Credential UI initialized");
}

/// Prompt for credentials
pub fn cred_ui_prompt_for_credentials(
    ui_info: Option<&CredUIInfo>,
    target_name: &[u8],
    _context: usize,
    _auth_error: u32,
    user_name: &mut [u8],
    password: &mut [u8],
    save: Option<&mut bool>,
    flags: u32,
) -> u32 {
    let _ = ui_info;

    // Check flags
    if (flags & CREDUI_FLAGS_DO_NOT_PERSIST) != 0 {
        if let Some(s) = save {
            *s = false;
        }
    }

    // Look for existing credential
    let creds = CREDENTIALS.lock();

    for cred in creds.iter() {
        if cred.in_use {
            let target_len = super::strhelp::str_len(target_name);
            let cred_target_len = super::strhelp::str_len(&cred.target_name);

            if target_len == cred_target_len &&
               super::strhelp::str_cmp_ni(&cred.target_name, target_name, target_len) == 0 {
                // Found matching credential
                let user_len = super::strhelp::str_len(&cred.user_name);
                let copy_user = user_len.min(user_name.len().saturating_sub(1));
                user_name[..copy_user].copy_from_slice(&cred.user_name[..copy_user]);
                if copy_user < user_name.len() {
                    user_name[copy_user] = 0;
                }

                let pass_len = cred.credential_blob_size as usize;
                let copy_pass = pass_len.min(password.len().saturating_sub(1));
                password[..copy_pass].copy_from_slice(&cred.credential_blob[..copy_pass]);
                if copy_pass < password.len() {
                    password[copy_pass] = 0;
                }

                return NO_ERROR;
            }
        }
    }

    drop(creds);

    // No credential found - in real implementation would show dialog
    // For now, if ALWAYS_SHOW_UI is not set, return cancelled
    if (flags & CREDUI_FLAGS_ALWAYS_SHOW_UI) == 0 {
        return ERROR_CANCELLED;
    }

    // Would show credential dialog
    ERROR_CANCELLED
}

/// Prompt for credentials (command line)
pub fn cred_ui_cmd_line_prompt_for_credentials(
    target_name: &[u8],
    _context: usize,
    _auth_error: u32,
    user_name: &mut [u8],
    password: &mut [u8],
    save: Option<&mut bool>,
    flags: u32,
) -> u32 {
    cred_ui_prompt_for_credentials(
        None,
        target_name,
        0,
        0,
        user_name,
        password,
        save,
        flags,
    )
}

/// Confirm credentials
pub fn cred_ui_confirm_credentials(target_name: &[u8], confirm: bool) -> u32 {
    if !confirm {
        // Remove any saved credential for this target
        let mut creds = CREDENTIALS.lock();

        for cred in creds.iter_mut() {
            if cred.in_use {
                let target_len = super::strhelp::str_len(target_name);
                let cred_target_len = super::strhelp::str_len(&cred.target_name);

                if target_len == cred_target_len &&
                   super::strhelp::str_cmp_ni(&cred.target_name, target_name, target_len) == 0 {
                    *cred = Credential::new();
                    break;
                }
            }
        }
    }

    NO_ERROR
}

/// Parse username (split into user and domain)
pub fn cred_ui_parse_user_name(
    user_name: &[u8],
    user: &mut [u8],
    domain: &mut [u8],
) -> u32 {
    let len = super::strhelp::str_len(user_name);

    // Look for backslash (domain\user) or @ (user@domain)
    let mut sep_pos = None;
    let mut is_upn = false;

    for (i, &b) in user_name[..len].iter().enumerate() {
        if b == b'\\' {
            sep_pos = Some(i);
            break;
        } else if b == b'@' {
            sep_pos = Some(i);
            is_upn = true;
            break;
        }
    }

    match sep_pos {
        Some(pos) if !is_upn => {
            // domain\user format
            let domain_len = pos.min(domain.len().saturating_sub(1));
            domain[..domain_len].copy_from_slice(&user_name[..domain_len]);
            if domain_len < domain.len() {
                domain[domain_len] = 0;
            }

            let user_part = &user_name[pos + 1..len];
            let user_len = (len - pos - 1).min(user.len().saturating_sub(1));
            user[..user_len].copy_from_slice(&user_part[..user_len]);
            if user_len < user.len() {
                user[user_len] = 0;
            }
        }
        Some(pos) if is_upn => {
            // user@domain format
            let user_len = pos.min(user.len().saturating_sub(1));
            user[..user_len].copy_from_slice(&user_name[..user_len]);
            if user_len < user.len() {
                user[user_len] = 0;
            }

            let domain_part = &user_name[pos + 1..len];
            let domain_len = (len - pos - 1).min(domain.len().saturating_sub(1));
            domain[..domain_len].copy_from_slice(&domain_part[..domain_len]);
            if domain_len < domain.len() {
                domain[domain_len] = 0;
            }
        }
        _ => {
            // No domain
            let user_len = len.min(user.len().saturating_sub(1));
            user[..user_len].copy_from_slice(&user_name[..user_len]);
            if user_len < user.len() {
                user[user_len] = 0;
            }

            if !domain.is_empty() {
                domain[0] = 0;
            }
        }
    }

    NO_ERROR
}

// ============================================================================
// Credential Manager API
// ============================================================================

/// Write credential
pub fn cred_write(cred: &Credential, _flags: u32) -> bool {
    let mut creds = CREDENTIALS.lock();
    let mut timestamp = CRED_TIMESTAMP.lock();

    let target_len = super::strhelp::str_len(&cred.target_name);

    // Check if updating existing
    for stored in creds.iter_mut() {
        if stored.in_use {
            let stored_len = super::strhelp::str_len(&stored.target_name);
            if target_len == stored_len &&
               super::strhelp::str_cmp_ni(&stored.target_name, &cred.target_name, target_len) == 0 {
                // Update existing
                *stored = cred.clone();
                stored.last_written = *timestamp;
                *timestamp += 1;
                return true;
            }
        }
    }

    // Add new
    for stored in creds.iter_mut() {
        if !stored.in_use {
            *stored = cred.clone();
            stored.in_use = true;
            stored.last_written = *timestamp;
            *timestamp += 1;
            return true;
        }
    }

    false
}

/// Read credential
pub fn cred_read(target_name: &[u8], cred_type: u32, _flags: u32, cred: &mut Credential) -> bool {
    let creds = CREDENTIALS.lock();
    let target_len = super::strhelp::str_len(target_name);

    for stored in creds.iter() {
        if stored.in_use && stored.cred_type == cred_type {
            let stored_len = super::strhelp::str_len(&stored.target_name);
            if target_len == stored_len &&
               super::strhelp::str_cmp_ni(&stored.target_name, target_name, target_len) == 0 {
                *cred = stored.clone();
                return true;
            }
        }
    }

    false
}

/// Delete credential
pub fn cred_delete(target_name: &[u8], cred_type: u32, _flags: u32) -> bool {
    let mut creds = CREDENTIALS.lock();
    let target_len = super::strhelp::str_len(target_name);

    for stored in creds.iter_mut() {
        if stored.in_use && stored.cred_type == cred_type {
            let stored_len = super::strhelp::str_len(&stored.target_name);
            if target_len == stored_len &&
               super::strhelp::str_cmp_ni(&stored.target_name, target_name, target_len) == 0 {
                *stored = Credential::new();
                return true;
            }
        }
    }

    false
}

/// Enumerate credentials
pub fn cred_enumerate(
    filter: Option<&[u8]>,
    _flags: u32,
    count: &mut u32,
) -> bool {
    let creds = CREDENTIALS.lock();
    let mut c = 0u32;

    for stored in creds.iter() {
        if stored.in_use {
            if let Some(f) = filter {
                // Simple wildcard match (just check prefix for now)
                let filter_len = super::strhelp::str_len(f);
                let target_len = super::strhelp::str_len(&stored.target_name);

                // Remove trailing * if present
                let match_len = if filter_len > 0 && f[filter_len - 1] == b'*' {
                    filter_len - 1
                } else {
                    filter_len
                };

                if target_len >= match_len &&
                   super::strhelp::str_cmp_ni(&stored.target_name, f, match_len) == 0 {
                    c += 1;
                }
            } else {
                c += 1;
            }
        }
    }

    *count = c;
    true
}

/// Rename credential
pub fn cred_rename(
    old_target_name: &[u8],
    new_target_name: &[u8],
    cred_type: u32,
    _flags: u32,
) -> bool {
    let mut creds = CREDENTIALS.lock();
    let old_len = super::strhelp::str_len(old_target_name);

    for stored in creds.iter_mut() {
        if stored.in_use && stored.cred_type == cred_type {
            let stored_len = super::strhelp::str_len(&stored.target_name);
            if old_len == stored_len &&
               super::strhelp::str_cmp_ni(&stored.target_name, old_target_name, old_len) == 0 {
                // Rename
                let new_len = super::strhelp::str_len(new_target_name).min(511);
                stored.target_name[..new_len].copy_from_slice(&new_target_name[..new_len]);
                stored.target_name[new_len] = 0;
                return true;
            }
        }
    }

    false
}

/// Get target info
pub fn cred_get_target_info(
    target_name: &[u8],
    _flags: u32,
    target_info: &mut CredTargetInfo,
) -> bool {
    // Simplified: just return target name info
    let len = super::strhelp::str_len(target_name).min(511);
    target_info.target_name[..len].copy_from_slice(&target_name[..len]);
    target_info.target_name[len] = 0;
    target_info.flags = 0;

    true
}

/// Target info structure
#[derive(Clone)]
pub struct CredTargetInfo {
    /// Target name
    pub target_name: [u8; 512],
    /// Net BIOS server name
    pub net_bios_server_name: [u8; 64],
    /// DNS server name
    pub dns_server_name: [u8; 256],
    /// Net BIOS domain name
    pub net_bios_domain_name: [u8; 64],
    /// DNS domain name
    pub dns_domain_name: [u8; 256],
    /// DNS tree name
    pub dns_tree_name: [u8; 256],
    /// Package name
    pub package_name: [u8; 64],
    /// Flags
    pub flags: u32,
}

impl CredTargetInfo {
    /// Create empty target info
    pub const fn new() -> Self {
        Self {
            target_name: [0; 512],
            net_bios_server_name: [0; 64],
            dns_server_name: [0; 256],
            net_bios_domain_name: [0; 64],
            dns_domain_name: [0; 256],
            dns_tree_name: [0; 256],
            package_name: [0; 64],
            flags: 0,
        }
    }
}

// ============================================================================
// Credential Marshaling
// ============================================================================

/// Marshal credential as blob
pub fn cred_marshal_credential(
    cred_type: u32,
    credential: &[u8],
    marshaled: &mut [u8],
) -> u32 {
    // Simple format: type (4 bytes) + length (4 bytes) + data
    if marshaled.len() < 8 + credential.len() {
        return 0;
    }

    marshaled[0..4].copy_from_slice(&cred_type.to_le_bytes());
    marshaled[4..8].copy_from_slice(&(credential.len() as u32).to_le_bytes());
    marshaled[8..8 + credential.len()].copy_from_slice(credential);

    (8 + credential.len()) as u32
}

/// Unmarshal credential
pub fn cred_unmarshal_credential(
    marshaled: &[u8],
    cred_type: &mut u32,
    credential: &mut [u8],
) -> u32 {
    if marshaled.len() < 8 {
        return 0;
    }

    *cred_type = u32::from_le_bytes([marshaled[0], marshaled[1], marshaled[2], marshaled[3]]);
    let len = u32::from_le_bytes([marshaled[4], marshaled[5], marshaled[6], marshaled[7]]) as usize;

    if marshaled.len() < 8 + len {
        return 0;
    }

    let copy_len = len.min(credential.len());
    credential[..copy_len].copy_from_slice(&marshaled[8..8 + copy_len]);

    copy_len as u32
}

/// Check if credential is marshaled
pub fn cred_is_marshaled_credential(credential: &[u8]) -> bool {
    // Check if it looks like a marshaled credential
    if credential.len() < 8 {
        return false;
    }

    let cred_type = u32::from_le_bytes([credential[0], credential[1], credential[2], credential[3]]);
    let len = u32::from_le_bytes([credential[4], credential[5], credential[6], credential[7]]) as usize;

    cred_type >= 1 && cred_type <= CRED_TYPE_MAXIMUM && credential.len() >= 8 + len
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> CredUIStats {
    let creds = CREDENTIALS.lock();

    let mut count = 0;
    let mut generic_count = 0;
    let mut domain_count = 0;

    for cred in creds.iter() {
        if cred.in_use {
            count += 1;
            match cred.cred_type {
                CRED_TYPE_GENERIC => generic_count += 1,
                CRED_TYPE_DOMAIN_PASSWORD | CRED_TYPE_DOMAIN_CERTIFICATE => domain_count += 1,
                _ => {}
            }
        }
    }

    CredUIStats {
        max_credentials: MAX_CREDENTIALS,
        stored_credentials: count,
        generic_credentials: generic_count,
        domain_credentials: domain_count,
    }
}

/// Credential UI statistics
#[derive(Debug, Clone, Copy)]
pub struct CredUIStats {
    pub max_credentials: usize,
    pub stored_credentials: usize,
    pub generic_credentials: usize,
    pub domain_credentials: usize,
}
