//! UNC Provider Support (Multiple UNC Provider)
//!
//! Provides support for registering network file system redirectors
//! with the Multiple UNC Provider (MUP) for handling UNC paths
//! like `\\server\share\path`.
//!
//! # Background
//!
//! UNC (Universal Naming Convention) paths are used to access network
//! resources. When multiple redirectors are installed (SMB, NFS, WebDAV),
//! the MUP arbitrates which redirector handles each UNC path.
//!
//! # Design
//!
//! - Redirectors register with `FsRtlRegisterUncProvider`
//! - MUP broadcasts incoming I/O to all registered providers
//! - The first provider that claims the path handles it
//! - DFS (Distributed File System) can be enabled for path referrals
//!
//! # NT Functions
//!
//! - `FsRtlRegisterUncProvider` - Register a redirector with MUP
//! - `FsRtlDeregisterUncProvider` - Unregister a redirector

use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;

/// Maximum number of UNC providers
pub const MAX_UNC_PROVIDERS: usize = 16;

/// UNC provider registration flags
pub mod provider_flags {
    /// Provider supports mailslots
    pub const MAILSLOTS_SUPPORTED: u32 = 0x01;
    /// Provider supports DFS referrals
    pub const DFS_SUPPORTED: u32 = 0x02;
    /// Provider is the primary SMB redirector
    pub const PRIMARY_SMB: u32 = 0x04;
    /// Provider handles all unrecognized paths
    pub const FALLBACK_PROVIDER: u32 = 0x08;
}

/// Registered UNC provider
#[repr(C)]
#[derive(Clone)]
pub struct UncProvider {
    /// Provider is registered
    pub registered: bool,
    /// Handle returned to provider
    pub handle: u32,
    /// Device name (e.g., "\Device\LanmanRedirector")
    pub device_name: [u8; 128],
    /// Device name length
    pub device_name_len: u32,
    /// Provider flags
    pub flags: u32,
    /// Mailslots supported
    pub mailslots_supported: bool,
    /// DFS supported
    pub dfs_supported: bool,
    /// Registration order (lower = higher priority)
    pub order: u32,
}

impl Default for UncProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl UncProvider {
    pub const fn new() -> Self {
        Self {
            registered: false,
            handle: 0,
            device_name: [0; 128],
            device_name_len: 0,
            flags: 0,
            mailslots_supported: false,
            dfs_supported: false,
            order: 0,
        }
    }
}

/// MUP (Multiple UNC Provider) state
#[repr(C)]
pub struct MupState {
    /// Registered providers
    pub providers: [UncProvider; MAX_UNC_PROVIDERS],
    /// Number of registered providers
    pub provider_count: u32,
    /// Next handle to assign
    pub next_handle: u32,
    /// DFS client enabled
    pub dfs_enabled: bool,
    /// MUP device opened
    pub mup_opened: bool,
}

impl Default for MupState {
    fn default() -> Self {
        Self::new()
    }
}

impl MupState {
    pub const fn new() -> Self {
        Self {
            providers: {
                const INIT: UncProvider = UncProvider::new();
                [INIT; MAX_UNC_PROVIDERS]
            },
            provider_count: 0,
            next_handle: 1,
            dfs_enabled: false,
            mup_opened: false,
        }
    }
}

/// Global MUP state
static mut MUP_STATE: MupState = MupState::new();

/// Lock for MUP operations
static MUP_LOCK: SpinLock<()> = SpinLock::new(());

/// Number of redirectors loaded
static REDIR_COUNT: AtomicU32 = AtomicU32::new(0);

/// DFS enabled flag
static DFS_ENABLED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// UNC Provider Registration
// ============================================================================

/// Register a UNC provider with MUP (FsRtlRegisterUncProvider)
///
/// Called by network redirectors to register for UNC path handling.
///
/// # Arguments
/// * `mup_handle` - Receives handle for deregistration
/// * `device_name` - Device name of the redirector (e.g., "\\Device\\LanmanRedirector")
/// * `mailslots_supported` - Whether the redirector supports mailslots
///
/// # Returns
/// STATUS_SUCCESS or error code
pub unsafe fn fsrtl_register_unc_provider(
    mup_handle: *mut u32,
    device_name: &str,
    mailslots_supported: bool,
) -> i32 {
    if mup_handle.is_null() || device_name.is_empty() {
        return -1073741811; // STATUS_INVALID_PARAMETER
    }

    let _guard = MUP_LOCK.lock();

    // Check for capacity
    if MUP_STATE.provider_count as usize >= MAX_UNC_PROVIDERS {
        return -1073741670; // STATUS_INSUFFICIENT_RESOURCES
    }

    // Find free slot
    let slot = {
        let mut found = None;
        for i in 0..MAX_UNC_PROVIDERS {
            if !MUP_STATE.providers[i].registered {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => return -1073741670, // STATUS_INSUFFICIENT_RESOURCES
        }
    };

    // Copy device name
    let name_bytes = device_name.as_bytes();
    let copy_len = name_bytes.len().min(127);
    MUP_STATE.providers[slot].device_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    MUP_STATE.providers[slot].device_name_len = copy_len as u32;

    // Set up provider
    MUP_STATE.providers[slot].registered = true;
    MUP_STATE.providers[slot].handle = MUP_STATE.next_handle;
    MUP_STATE.providers[slot].mailslots_supported = mailslots_supported;
    MUP_STATE.providers[slot].dfs_supported = false;
    MUP_STATE.providers[slot].order = MUP_STATE.provider_count;

    if mailslots_supported {
        MUP_STATE.providers[slot].flags |= provider_flags::MAILSLOTS_SUPPORTED;
    }

    // Update state
    *mup_handle = MUP_STATE.next_handle;
    MUP_STATE.next_handle += 1;
    MUP_STATE.provider_count += 1;

    // Increment redirector count
    let redir_count = REDIR_COUNT.fetch_add(1, Ordering::AcqRel) + 1;

    crate::serial_println!(
        "[FSRTL] UNC provider registered: {} (handle={}, mailslots={}, count={})",
        device_name,
        *mup_handle,
        mailslots_supported,
        redir_count
    );

    0 // STATUS_SUCCESS
}

/// Deregister a UNC provider (FsRtlDeregisterUncProvider)
///
/// Called when a redirector is unloading.
///
/// # Arguments
/// * `mup_handle` - Handle returned from FsRtlRegisterUncProvider
pub unsafe fn fsrtl_deregister_unc_provider(mup_handle: u32) {
    let _guard = MUP_LOCK.lock();

    // Find provider by handle
    for i in 0..MAX_UNC_PROVIDERS {
        if MUP_STATE.providers[i].registered && MUP_STATE.providers[i].handle == mup_handle {
            MUP_STATE.providers[i].registered = false;
            MUP_STATE.providers[i].handle = 0;
            MUP_STATE.providers[i].device_name_len = 0;

            if MUP_STATE.provider_count > 0 {
                MUP_STATE.provider_count -= 1;
            }

            REDIR_COUNT.fetch_sub(1, Ordering::AcqRel);

            crate::serial_println!("[FSRTL] UNC provider deregistered: handle={}", mup_handle);
            return;
        }
    }

    crate::serial_println!(
        "[FSRTL] UNC provider deregister failed: handle {} not found",
        mup_handle
    );
}

// ============================================================================
// Extended Registration
// ============================================================================

/// Extended registration information
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UncProviderRegistrationEx {
    /// Size of this structure
    pub size: u32,
    /// Device name
    pub device_name: *const u8,
    /// Device name length
    pub device_name_length: u32,
    /// Mailslots supported
    pub mailslots_supported: bool,
    /// DFS supported
    pub dfs_supported: bool,
    /// Provider flags
    pub flags: u32,
    /// Registration priority (lower = higher)
    pub priority: u32,
}

/// Register UNC provider with extended options
pub unsafe fn fsrtl_register_unc_provider_ex(
    mup_handle: *mut u32,
    registration: *const UncProviderRegistrationEx,
) -> i32 {
    if mup_handle.is_null() || registration.is_null() {
        return -1073741811; // STATUS_INVALID_PARAMETER
    }

    let reg = &*registration;

    let _guard = MUP_LOCK.lock();

    if MUP_STATE.provider_count as usize >= MAX_UNC_PROVIDERS {
        return -1073741670; // STATUS_INSUFFICIENT_RESOURCES
    }

    // Find free slot
    let slot = {
        let mut found = None;
        for i in 0..MAX_UNC_PROVIDERS {
            if !MUP_STATE.providers[i].registered {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => return -1073741670,
        }
    };

    // Copy device name
    let copy_len = (reg.device_name_length as usize).min(127);
    if !reg.device_name.is_null() && copy_len > 0 {
        let name_slice = core::slice::from_raw_parts(reg.device_name, copy_len);
        MUP_STATE.providers[slot].device_name[..copy_len].copy_from_slice(name_slice);
    }
    MUP_STATE.providers[slot].device_name_len = copy_len as u32;

    // Set up provider
    MUP_STATE.providers[slot].registered = true;
    MUP_STATE.providers[slot].handle = MUP_STATE.next_handle;
    MUP_STATE.providers[slot].mailslots_supported = reg.mailslots_supported;
    MUP_STATE.providers[slot].dfs_supported = reg.dfs_supported;
    MUP_STATE.providers[slot].flags = reg.flags;
    MUP_STATE.providers[slot].order = reg.priority;

    *mup_handle = MUP_STATE.next_handle;
    MUP_STATE.next_handle += 1;
    MUP_STATE.provider_count += 1;

    REDIR_COUNT.fetch_add(1, Ordering::AcqRel);

    0 // STATUS_SUCCESS
}

// ============================================================================
// DFS Support
// ============================================================================

/// Check if DFS is enabled
pub fn fsrtl_is_dfs_enabled() -> bool {
    DFS_ENABLED.load(Ordering::Acquire)
}

/// Enable or disable DFS
pub fn fsrtl_set_dfs_enabled(enabled: bool) {
    DFS_ENABLED.store(enabled, Ordering::Release);
    unsafe {
        MUP_STATE.dfs_enabled = enabled;
    }
}

// ============================================================================
// Query Functions
// ============================================================================

/// Get number of registered providers
pub fn get_provider_count() -> u32 {
    unsafe {
        let _guard = MUP_LOCK.lock();
        MUP_STATE.provider_count
    }
}

/// Get provider information by index
pub unsafe fn get_provider_info(index: usize) -> Option<UncProvider> {
    let _guard = MUP_LOCK.lock();

    if index >= MAX_UNC_PROVIDERS || !MUP_STATE.providers[index].registered {
        return None;
    }

    Some(MUP_STATE.providers[index].clone())
}

/// Find provider by device name
pub unsafe fn find_provider_by_name(device_name: &str) -> Option<u32> {
    let _guard = MUP_LOCK.lock();
    let name_bytes = device_name.as_bytes();

    for i in 0..MAX_UNC_PROVIDERS {
        if MUP_STATE.providers[i].registered {
            let len = MUP_STATE.providers[i].device_name_len as usize;
            if len == name_bytes.len() {
                let stored_name = &MUP_STATE.providers[i].device_name[..len];
                if stored_name == name_bytes {
                    return Some(MUP_STATE.providers[i].handle);
                }
            }
        }
    }

    None
}

// ============================================================================
// UNC Path Parsing
// ============================================================================

/// UNC path components
#[derive(Debug, Clone)]
pub struct UncPath {
    /// Server name
    pub server: [u8; 64],
    /// Server name length
    pub server_len: usize,
    /// Share name
    pub share: [u8; 64],
    /// Share name length
    pub share_len: usize,
    /// Remaining path
    pub path: [u8; 256],
    /// Path length
    pub path_len: usize,
    /// Is DFS path
    pub is_dfs: bool,
}

impl Default for UncPath {
    fn default() -> Self {
        Self::new()
    }
}

impl UncPath {
    pub const fn new() -> Self {
        Self {
            server: [0; 64],
            server_len: 0,
            share: [0; 64],
            share_len: 0,
            path: [0; 256],
            path_len: 0,
            is_dfs: false,
        }
    }
}

/// Parse a UNC path into components
///
/// Parses paths like `\\server\share\path\file.txt`
///
/// # Arguments
/// * `path` - The UNC path string
///
/// # Returns
/// Parsed UNC path components or None if not a valid UNC path
pub fn fsrtl_parse_unc_path(path: &str) -> Option<UncPath> {
    let path_bytes = path.as_bytes();

    // Must start with \\ or //
    if path_bytes.len() < 3 {
        return None;
    }

    let sep = path_bytes[0];
    if (sep != b'\\' && sep != b'/') || path_bytes[1] != sep {
        return None;
    }

    let mut result = UncPath::new();
    let mut pos = 2; // Skip initial \\

    // Parse server name
    let server_start = pos;
    while pos < path_bytes.len() && path_bytes[pos] != b'\\' && path_bytes[pos] != b'/' {
        pos += 1;
    }
    let server_len = pos - server_start;
    if server_len == 0 || server_len > 63 {
        return None;
    }
    result.server[..server_len].copy_from_slice(&path_bytes[server_start..pos]);
    result.server_len = server_len;

    // Skip separator
    if pos >= path_bytes.len() {
        return Some(result); // Just server name
    }
    pos += 1;

    // Parse share name
    let share_start = pos;
    while pos < path_bytes.len() && path_bytes[pos] != b'\\' && path_bytes[pos] != b'/' {
        pos += 1;
    }
    let share_len = pos - share_start;
    if share_len > 63 {
        return None;
    }
    if share_len > 0 {
        result.share[..share_len].copy_from_slice(&path_bytes[share_start..pos]);
        result.share_len = share_len;
    }

    // Check for DFS indicator
    if share_len > 0 {
        let share_name = &result.share[..share_len];
        if share_name == b"dfs" || share_name == b"DFS" {
            result.is_dfs = true;
        }
    }

    // Parse remaining path
    if pos < path_bytes.len() {
        let path_len = (path_bytes.len() - pos).min(255);
        result.path[..path_len].copy_from_slice(&path_bytes[pos..pos + path_len]);
        result.path_len = path_len;
    }

    Some(result)
}

/// Check if a path is a UNC path
#[inline]
pub fn fsrtl_is_unc_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2
        && (bytes[0] == b'\\' || bytes[0] == b'/')
        && bytes[1] == bytes[0]
}

/// Check if a path is a DFS path
pub fn fsrtl_is_dfs_path(path: &str) -> bool {
    if !fsrtl_is_dfs_enabled() {
        return false;
    }

    if let Some(parsed) = fsrtl_parse_unc_path(path) {
        return parsed.is_dfs;
    }

    false
}

// ============================================================================
// Statistics
// ============================================================================

/// UNC subsystem statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct UncStats {
    /// Providers registered
    pub providers_registered: u32,
    /// Providers deregistered
    pub providers_deregistered: u32,
    /// DFS lookups
    pub dfs_lookups: u32,
    /// Path parses
    pub path_parses: u32,
}

static mut UNC_STATS: UncStats = UncStats {
    providers_registered: 0,
    providers_deregistered: 0,
    dfs_lookups: 0,
    path_parses: 0,
};

/// Get UNC statistics
pub fn get_unc_stats() -> UncStats {
    unsafe { UNC_STATS }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize UNC provider support
pub fn init() {
    unsafe {
        MUP_STATE = MupState::new();
        UNC_STATS = UncStats::default();
    }

    REDIR_COUNT.store(0, Ordering::Release);
    DFS_ENABLED.store(false, Ordering::Release);

    crate::serial_println!("[FSRTL] UNC provider support initialized");
}
