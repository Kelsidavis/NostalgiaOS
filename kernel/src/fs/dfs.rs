//! DFS - Distributed File System
//!
//! DFS provides a unified namespace that spans multiple file servers,
//! allowing administrators to create virtual directory trees that map
//! to physical shares on different servers.
//!
//! Key concepts:
//! - DFS Namespace: A virtual view of shared folders
//! - DFS Root: The starting point of the namespace
//! - DFS Link: A pointer to a shared folder (target)
//! - DFS Referral: Server redirect response for path resolution
//!
//! DFS integrates with MUP to handle UNC path routing.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum namespace roots
const MAX_ROOTS: usize = 4;

/// Maximum links per root
const MAX_LINKS_PER_ROOT: usize = 8;

/// Maximum targets per link
const MAX_TARGETS_PER_LINK: usize = 4;

/// Maximum path length
const MAX_PATH_LEN: usize = 128;

/// Maximum server name length
const MAX_SERVER_NAME: usize = 64;

/// Referral cache TTL (seconds)
const DEFAULT_REFERRAL_TTL: u32 = 300;

// ============================================================================
// DFS Machine State
// ============================================================================

/// DFS machine state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfsMachineState {
    /// Unknown state
    Unknown,
    /// DFS Client only
    Client,
    /// DFS Server (hosts shares)
    Server,
    /// DFS Root Server (hosts namespace)
    RootServer,
}

/// DFS namespace type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfsNamespaceType {
    /// Domain-based DFS (uses Active Directory)
    DomainBased,
    /// Standalone DFS (single server)
    Standalone,
}

// ============================================================================
// DFS Target
// ============================================================================

/// Target state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    /// Target is online and available
    Online,
    /// Target is offline
    Offline,
    /// Target status unknown
    Unknown,
}

/// A DFS target (physical share)
#[derive(Clone)]
pub struct DfsTarget {
    /// Target ID
    pub id: u32,
    /// Server name
    pub server: [u8; MAX_SERVER_NAME],
    /// Server name length
    pub server_len: usize,
    /// Share path
    pub share: [u8; MAX_PATH_LEN],
    /// Share path length
    pub share_len: usize,
    /// Target state
    pub state: TargetState,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Last access timestamp
    pub last_access: u64,
    /// Access count
    pub access_count: u64,
    /// Active flag
    pub active: bool,
}

impl Default for DfsTarget {
    fn default() -> Self {
        Self {
            id: 0,
            server: [0; MAX_SERVER_NAME],
            server_len: 0,
            share: [0; MAX_PATH_LEN],
            share_len: 0,
            state: TargetState::Unknown,
            priority: u32::MAX,
            last_access: 0,
            access_count: 0,
            active: false,
        }
    }
}

// ============================================================================
// DFS Link
// ============================================================================

/// Link state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Link is active
    Active,
    /// Link is offline (administrator disabled)
    Offline,
    /// Link is being deleted
    Deleting,
}

/// A DFS link (virtual path to targets)
#[derive(Clone)]
pub struct DfsLink {
    /// Link ID
    pub id: u32,
    /// Link path (relative to root)
    pub path: [u8; MAX_PATH_LEN],
    /// Path length
    pub path_len: usize,
    /// Comment/description
    pub comment: [u8; 256],
    /// Comment length
    pub comment_len: usize,
    /// Targets for this link
    pub targets: [DfsTarget; MAX_TARGETS_PER_LINK],
    /// Number of active targets
    pub target_count: usize,
    /// Link state
    pub state: LinkState,
    /// Referral TTL
    pub ttl: u32,
    /// Last updated timestamp
    pub last_updated: u64,
    /// Active flag
    pub active: bool,
}

impl Default for DfsLink {
    fn default() -> Self {
        const DEFAULT_TARGET: DfsTarget = DfsTarget {
            id: 0,
            server: [0; MAX_SERVER_NAME],
            server_len: 0,
            share: [0; MAX_PATH_LEN],
            share_len: 0,
            state: TargetState::Unknown,
            priority: u32::MAX,
            last_access: 0,
            access_count: 0,
            active: false,
        };

        Self {
            id: 0,
            path: [0; MAX_PATH_LEN],
            path_len: 0,
            comment: [0; 256],
            comment_len: 0,
            targets: [DEFAULT_TARGET; MAX_TARGETS_PER_LINK],
            target_count: 0,
            state: LinkState::Active,
            ttl: DEFAULT_REFERRAL_TTL,
            last_updated: 0,
            active: false,
        }
    }
}

// ============================================================================
// DFS Root
// ============================================================================

/// Root state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootState {
    /// Root is initializing
    Initializing,
    /// Root is online
    Online,
    /// Root is offline
    Offline,
    /// Root is being deleted
    Deleting,
}

/// A DFS namespace root
#[derive(Clone)]
pub struct DfsRoot {
    /// Root ID
    pub id: u32,
    /// Root name (namespace name)
    pub name: [u8; MAX_SERVER_NAME],
    /// Name length
    pub name_len: usize,
    /// Domain name (for domain-based DFS)
    pub domain: [u8; MAX_SERVER_NAME],
    /// Domain length
    pub domain_len: usize,
    /// Root share path (\\server\share)
    pub share_path: [u8; MAX_PATH_LEN],
    /// Share path length
    pub share_path_len: usize,
    /// Namespace type
    pub namespace_type: DfsNamespaceType,
    /// Root state
    pub state: RootState,
    /// Links in this root
    pub links: [DfsLink; MAX_LINKS_PER_ROOT],
    /// Number of active links
    pub link_count: usize,
    /// Next link ID
    pub next_link_id: u32,
    /// Comment
    pub comment: [u8; 256],
    /// Comment length
    pub comment_len: usize,
    /// Active flag
    pub active: bool,
}

impl Default for DfsRoot {
    fn default() -> Self {
        Self {
            id: 0,
            name: [0; MAX_SERVER_NAME],
            name_len: 0,
            domain: [0; MAX_SERVER_NAME],
            domain_len: 0,
            share_path: [0; MAX_PATH_LEN],
            share_path_len: 0,
            namespace_type: DfsNamespaceType::Standalone,
            state: RootState::Offline,
            links: core::array::from_fn(|_| DfsLink::default()),
            link_count: 0,
            next_link_id: 1,
            comment: [0; 256],
            comment_len: 0,
            active: false,
        }
    }
}

// ============================================================================
// DFS Referral
// ============================================================================

/// Referral entry type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ReferralEntryType {
    /// Domain referral
    Domain = 0,
    /// DC (Domain Controller) referral
    DomainController = 1,
    /// Root referral
    Root = 2,
    /// Link referral
    Link = 3,
    /// Interlink referral
    Interlink = 4,
}

/// DFS Referral flags
pub mod referral_flags {
    pub const TARGET_FAILBACK: u32 = 0x0001;
    pub const SERVER_SET: u32 = 0x0002;
    pub const NAME_LIST_REFERRAL: u32 = 0x0004;
}

/// A referral response entry
#[derive(Clone)]
pub struct ReferralEntry {
    /// Entry type
    pub entry_type: ReferralEntryType,
    /// Entry flags
    pub flags: u32,
    /// Target path
    pub path: String,
    /// TTL in seconds
    pub ttl: u32,
    /// Priority
    pub priority: u32,
}

/// Complete referral response
#[derive(Clone)]
pub struct DfsReferral {
    /// Path that was queried
    pub path: String,
    /// Referral entries
    pub entries: Vec<ReferralEntry>,
    /// Timestamp when obtained
    pub timestamp: u64,
    /// TTL
    pub ttl: u32,
}

// ============================================================================
// DFS Statistics
// ============================================================================

/// DFS statistics
#[derive(Debug)]
pub struct DfsStatistics {
    /// Path resolutions
    pub path_resolutions: AtomicU64,
    /// Referral requests
    pub referral_requests: AtomicU64,
    /// Cache hits
    pub cache_hits: AtomicU64,
    /// Cache misses
    pub cache_misses: AtomicU64,
    /// Target failovers
    pub failovers: AtomicU64,
    /// Active roots
    pub active_roots: AtomicU32,
    /// Active links
    pub active_links: AtomicU32,
}

impl Default for DfsStatistics {
    fn default() -> Self {
        Self {
            path_resolutions: AtomicU64::new(0),
            referral_requests: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            failovers: AtomicU64::new(0),
            active_roots: AtomicU32::new(0),
            active_links: AtomicU32::new(0),
        }
    }
}

// ============================================================================
// DFS Errors
// ============================================================================

/// DFS error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum DfsError {
    /// Success
    Success = 0,
    /// Not initialized
    NotInitialized = -1,
    /// Invalid path
    InvalidPath = -2,
    /// Path not found
    PathNotFound = -3,
    /// Root not found
    RootNotFound = -4,
    /// Link not found
    LinkNotFound = -5,
    /// Target not found
    TargetNotFound = -6,
    /// Too many roots
    TooManyRoots = -7,
    /// Too many links
    TooManyLinks = -8,
    /// Too many targets
    TooManyTargets = -9,
    /// Already exists
    AlreadyExists = -10,
    /// Invalid parameter
    InvalidParameter = -11,
    /// Network error
    NetworkError = -12,
    /// Access denied
    AccessDenied = -13,
    /// Offline
    Offline = -14,
}

// ============================================================================
// DFS Global State
// ============================================================================

/// DFS global state
pub struct DfsState {
    /// Namespace roots
    pub roots: [DfsRoot; MAX_ROOTS],
    /// Next root ID
    pub next_root_id: u32,
    /// Machine state
    pub machine_state: DfsMachineState,
    /// Statistics
    pub statistics: DfsStatistics,
    /// Initialized flag
    pub initialized: bool,
}

impl DfsState {
    const fn new() -> Self {
        Self {
            roots: [const { DfsRoot {
                id: 0,
                name: [0; MAX_SERVER_NAME],
                name_len: 0,
                domain: [0; MAX_SERVER_NAME],
                domain_len: 0,
                share_path: [0; MAX_PATH_LEN],
                share_path_len: 0,
                namespace_type: DfsNamespaceType::Standalone,
                state: RootState::Offline,
                links: [const { DfsLink {
                    id: 0,
                    path: [0; MAX_PATH_LEN],
                    path_len: 0,
                    comment: [0; 256],
                    comment_len: 0,
                    targets: [const { DfsTarget {
                        id: 0,
                        server: [0; MAX_SERVER_NAME],
                        server_len: 0,
                        share: [0; MAX_PATH_LEN],
                        share_len: 0,
                        state: TargetState::Unknown,
                        priority: u32::MAX,
                        last_access: 0,
                        access_count: 0,
                        active: false,
                    }}; MAX_TARGETS_PER_LINK],
                    target_count: 0,
                    state: LinkState::Active,
                    ttl: DEFAULT_REFERRAL_TTL,
                    last_updated: 0,
                    active: false,
                }}; MAX_LINKS_PER_ROOT],
                link_count: 0,
                next_link_id: 1,
                comment: [0; 256],
                comment_len: 0,
                active: false,
            }}; MAX_ROOTS],
            next_root_id: 1,
            machine_state: DfsMachineState::Client,
            statistics: DfsStatistics {
                path_resolutions: AtomicU64::new(0),
                referral_requests: AtomicU64::new(0),
                cache_hits: AtomicU64::new(0),
                cache_misses: AtomicU64::new(0),
                failovers: AtomicU64::new(0),
                active_roots: AtomicU32::new(0),
                active_links: AtomicU32::new(0),
            },
            initialized: false,
        }
    }
}

/// Global DFS state
static DFS_STATE: SpinLock<DfsState> = SpinLock::new(DfsState::new());

// ============================================================================
// Root Management
// ============================================================================

/// Create a new DFS namespace root
pub fn dfs_create_root(
    name: &str,
    share_path: &str,
    namespace_type: DfsNamespaceType,
    domain: Option<&str>,
) -> Result<u32, DfsError> {
    let mut state = DFS_STATE.lock();

    if !state.initialized {
        return Err(DfsError::NotInitialized);
    }

    let name_bytes = name.as_bytes();
    let share_bytes = share_path.as_bytes();

    if name_bytes.len() > MAX_SERVER_NAME || share_bytes.len() > MAX_PATH_LEN {
        return Err(DfsError::InvalidParameter);
    }

    // Check for duplicate
    for idx in 0..MAX_ROOTS {
        if state.roots[idx].active && state.roots[idx].name_len == name_bytes.len() {
            let mut matches = true;
            for i in 0..name_bytes.len() {
                if state.roots[idx].name[i] != name_bytes[i] {
                    matches = false;
                    break;
                }
            }
            if matches {
                return Err(DfsError::AlreadyExists);
            }
        }
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_ROOTS {
        if !state.roots[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(DfsError::TooManyRoots)?;

    let root_id = state.next_root_id;
    state.next_root_id += 1;

    state.roots[idx].id = root_id;
    state.roots[idx].name_len = name_bytes.len();
    state.roots[idx].name[..name_bytes.len()].copy_from_slice(name_bytes);
    state.roots[idx].share_path_len = share_bytes.len();
    state.roots[idx].share_path[..share_bytes.len()].copy_from_slice(share_bytes);
    state.roots[idx].namespace_type = namespace_type;
    state.roots[idx].state = RootState::Online;
    state.roots[idx].link_count = 0;
    state.roots[idx].next_link_id = 1;
    state.roots[idx].active = true;

    if let Some(dom) = domain {
        let dom_bytes = dom.as_bytes();
        if dom_bytes.len() <= MAX_SERVER_NAME {
            state.roots[idx].domain_len = dom_bytes.len();
            state.roots[idx].domain[..dom_bytes.len()].copy_from_slice(dom_bytes);
        }
    }

    state.statistics.active_roots.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[DFS] Created root '{}' (type={:?})", name, namespace_type);

    Ok(root_id)
}

/// Delete a DFS root
pub fn dfs_delete_root(root_id: u32) -> Result<(), DfsError> {
    let mut state = DFS_STATE.lock();

    if !state.initialized {
        return Err(DfsError::NotInitialized);
    }

    for idx in 0..MAX_ROOTS {
        if state.roots[idx].active && state.roots[idx].id == root_id {
            let link_count = state.roots[idx].link_count;
            state.roots[idx].state = RootState::Deleting;
            state.roots[idx].active = false;

            state.statistics.active_roots.fetch_sub(1, Ordering::Relaxed);
            state.statistics.active_links.fetch_sub(link_count as u32, Ordering::Relaxed);

            crate::serial_println!("[DFS] Deleted root {}", root_id);
            return Ok(());
        }
    }

    Err(DfsError::RootNotFound)
}

// ============================================================================
// Link Management
// ============================================================================

/// Add a link to a DFS root
pub fn dfs_add_link(
    root_id: u32,
    link_path: &str,
    comment: Option<&str>,
) -> Result<u32, DfsError> {
    let mut state = DFS_STATE.lock();

    if !state.initialized {
        return Err(DfsError::NotInitialized);
    }

    let path_bytes = link_path.as_bytes();
    if path_bytes.len() > MAX_PATH_LEN {
        return Err(DfsError::InvalidParameter);
    }

    // Find root
    let root_idx = find_root_index(&state, root_id)?;

    if state.roots[root_idx].link_count >= MAX_LINKS_PER_ROOT {
        return Err(DfsError::TooManyLinks);
    }

    // Find free link slot
    let mut link_idx = None;
    for i in 0..MAX_LINKS_PER_ROOT {
        if !state.roots[root_idx].links[i].active {
            link_idx = Some(i);
            break;
        }
    }

    let lidx = link_idx.ok_or(DfsError::TooManyLinks)?;

    let link_id = state.roots[root_idx].next_link_id;
    state.roots[root_idx].next_link_id += 1;

    state.roots[root_idx].links[lidx].id = link_id;
    state.roots[root_idx].links[lidx].path_len = path_bytes.len();
    state.roots[root_idx].links[lidx].path[..path_bytes.len()].copy_from_slice(path_bytes);
    state.roots[root_idx].links[lidx].state = LinkState::Active;
    state.roots[root_idx].links[lidx].ttl = DEFAULT_REFERRAL_TTL;
    state.roots[root_idx].links[lidx].target_count = 0;
    state.roots[root_idx].links[lidx].active = true;

    if let Some(cmt) = comment {
        let cmt_bytes = cmt.as_bytes();
        let len = core::cmp::min(cmt_bytes.len(), 256);
        state.roots[root_idx].links[lidx].comment_len = len;
        state.roots[root_idx].links[lidx].comment[..len].copy_from_slice(&cmt_bytes[..len]);
    }

    state.roots[root_idx].link_count += 1;
    state.statistics.active_links.fetch_add(1, Ordering::Relaxed);

    Ok(link_id)
}

/// Remove a link from a DFS root
pub fn dfs_remove_link(root_id: u32, link_id: u32) -> Result<(), DfsError> {
    let mut state = DFS_STATE.lock();

    if !state.initialized {
        return Err(DfsError::NotInitialized);
    }

    let root_idx = find_root_index(&state, root_id)?;

    for lidx in 0..MAX_LINKS_PER_ROOT {
        if state.roots[root_idx].links[lidx].active
            && state.roots[root_idx].links[lidx].id == link_id
        {
            state.roots[root_idx].links[lidx].state = LinkState::Deleting;
            state.roots[root_idx].links[lidx].active = false;
            state.roots[root_idx].link_count -= 1;
            state.statistics.active_links.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(DfsError::LinkNotFound)
}

// ============================================================================
// Target Management
// ============================================================================

/// Add a target to a link
pub fn dfs_add_target(
    root_id: u32,
    link_id: u32,
    server: &str,
    share: &str,
    priority: u32,
) -> Result<u32, DfsError> {
    let mut state = DFS_STATE.lock();

    if !state.initialized {
        return Err(DfsError::NotInitialized);
    }

    let server_bytes = server.as_bytes();
    let share_bytes = share.as_bytes();

    if server_bytes.len() > MAX_SERVER_NAME || share_bytes.len() > MAX_PATH_LEN {
        return Err(DfsError::InvalidParameter);
    }

    let root_idx = find_root_index(&state, root_id)?;
    let link_idx = find_link_index(&state.roots[root_idx], link_id)?;

    if state.roots[root_idx].links[link_idx].target_count >= MAX_TARGETS_PER_LINK {
        return Err(DfsError::TooManyTargets);
    }

    // Find free target slot
    let mut target_idx = None;
    for i in 0..MAX_TARGETS_PER_LINK {
        if !state.roots[root_idx].links[link_idx].targets[i].active {
            target_idx = Some(i);
            break;
        }
    }

    let tidx = target_idx.ok_or(DfsError::TooManyTargets)?;
    let target_id = tidx as u32 + 1;

    state.roots[root_idx].links[link_idx].targets[tidx].id = target_id;
    state.roots[root_idx].links[link_idx].targets[tidx].server_len = server_bytes.len();
    state.roots[root_idx].links[link_idx].targets[tidx].server[..server_bytes.len()]
        .copy_from_slice(server_bytes);
    state.roots[root_idx].links[link_idx].targets[tidx].share_len = share_bytes.len();
    state.roots[root_idx].links[link_idx].targets[tidx].share[..share_bytes.len()]
        .copy_from_slice(share_bytes);
    state.roots[root_idx].links[link_idx].targets[tidx].priority = priority;
    state.roots[root_idx].links[link_idx].targets[tidx].state = TargetState::Online;
    state.roots[root_idx].links[link_idx].targets[tidx].active = true;

    state.roots[root_idx].links[link_idx].target_count += 1;

    Ok(target_id)
}

/// Remove a target from a link
pub fn dfs_remove_target(root_id: u32, link_id: u32, target_id: u32) -> Result<(), DfsError> {
    let mut state = DFS_STATE.lock();

    if !state.initialized {
        return Err(DfsError::NotInitialized);
    }

    let root_idx = find_root_index(&state, root_id)?;
    let link_idx = find_link_index(&state.roots[root_idx], link_id)?;

    for tidx in 0..MAX_TARGETS_PER_LINK {
        if state.roots[root_idx].links[link_idx].targets[tidx].active
            && state.roots[root_idx].links[link_idx].targets[tidx].id == target_id
        {
            state.roots[root_idx].links[link_idx].targets[tidx].active = false;
            state.roots[root_idx].links[link_idx].target_count -= 1;
            return Ok(());
        }
    }

    Err(DfsError::TargetNotFound)
}

/// Set target state (online/offline)
pub fn dfs_set_target_state(
    root_id: u32,
    link_id: u32,
    target_id: u32,
    state_val: TargetState,
) -> Result<(), DfsError> {
    let mut state = DFS_STATE.lock();

    if !state.initialized {
        return Err(DfsError::NotInitialized);
    }

    let root_idx = find_root_index(&state, root_id)?;
    let link_idx = find_link_index(&state.roots[root_idx], link_id)?;

    for tidx in 0..MAX_TARGETS_PER_LINK {
        if state.roots[root_idx].links[link_idx].targets[tidx].active
            && state.roots[root_idx].links[link_idx].targets[tidx].id == target_id
        {
            state.roots[root_idx].links[link_idx].targets[tidx].state = state_val;
            return Ok(());
        }
    }

    Err(DfsError::TargetNotFound)
}

// ============================================================================
// Path Resolution
// ============================================================================

/// Resolve a DFS path to a target
pub fn dfs_resolve_path(path: &str) -> Result<String, DfsError> {
    let mut state = DFS_STATE.lock();

    if !state.initialized {
        return Err(DfsError::NotInitialized);
    }

    state.statistics.path_resolutions.fetch_add(1, Ordering::Relaxed);

    // Parse the DFS path: \\domain\namespace\path or \\server\namespace\path
    let parts: Vec<&str> = path
        .trim_start_matches('\\')
        .split('\\')
        .collect();

    if parts.len() < 2 {
        return Err(DfsError::InvalidPath);
    }

    let namespace = parts[1];
    let link_path = if parts.len() > 2 {
        parts[2..].join("\\")
    } else {
        String::new()
    };

    // Find matching root
    for ridx in 0..MAX_ROOTS {
        if !state.roots[ridx].active {
            continue;
        }

        let root_name = core::str::from_utf8(&state.roots[ridx].name[..state.roots[ridx].name_len])
            .unwrap_or("");

        if root_name.eq_ignore_ascii_case(namespace) {
            // Found matching namespace, now find link
            if link_path.is_empty() {
                // Return root share path
                let share = core::str::from_utf8(
                    &state.roots[ridx].share_path[..state.roots[ridx].share_path_len],
                )
                .unwrap_or("");
                return Ok(share.to_string());
            }

            // Search links
            for lidx in 0..MAX_LINKS_PER_ROOT {
                if !state.roots[ridx].links[lidx].active {
                    continue;
                }

                let lpath = core::str::from_utf8(
                    &state.roots[ridx].links[lidx].path[..state.roots[ridx].links[lidx].path_len],
                )
                .unwrap_or("");

                if link_path.starts_with(lpath) {
                    // Found matching link, get best target
                    let target = get_best_target(&state.roots[ridx].links[lidx])?;

                    let server = core::str::from_utf8(&target.server[..target.server_len])
                        .unwrap_or("");
                    let share = core::str::from_utf8(&target.share[..target.share_len])
                        .unwrap_or("");

                    let remaining = &link_path[lpath.len()..].trim_start_matches('\\');
                    let result = if remaining.is_empty() {
                        alloc::format!("\\\\{}\\{}", server, share)
                    } else {
                        alloc::format!("\\\\{}\\{}\\{}", server, share, remaining)
                    };

                    return Ok(result);
                }
            }
        }
    }

    Err(DfsError::PathNotFound)
}

/// Get DFS referral for a path
pub fn dfs_get_referral(path: &str) -> Result<DfsReferral, DfsError> {
    let mut state = DFS_STATE.lock();

    if !state.initialized {
        return Err(DfsError::NotInitialized);
    }

    state.statistics.referral_requests.fetch_add(1, Ordering::Relaxed);

    let parts: Vec<&str> = path
        .trim_start_matches('\\')
        .split('\\')
        .collect();

    if parts.len() < 2 {
        return Err(DfsError::InvalidPath);
    }

    let namespace = parts[1];
    let mut entries = Vec::new();

    for ridx in 0..MAX_ROOTS {
        if !state.roots[ridx].active {
            continue;
        }

        let root_name = core::str::from_utf8(&state.roots[ridx].name[..state.roots[ridx].name_len])
            .unwrap_or("");

        if root_name.eq_ignore_ascii_case(namespace) {
            // Build referral entries for all targets
            for lidx in 0..MAX_LINKS_PER_ROOT {
                if !state.roots[ridx].links[lidx].active {
                    continue;
                }

                for tidx in 0..MAX_TARGETS_PER_LINK {
                    if !state.roots[ridx].links[lidx].targets[tidx].active {
                        continue;
                    }

                    let target = &state.roots[ridx].links[lidx].targets[tidx];
                    let server = core::str::from_utf8(&target.server[..target.server_len])
                        .unwrap_or("");
                    let share = core::str::from_utf8(&target.share[..target.share_len])
                        .unwrap_or("");

                    entries.push(ReferralEntry {
                        entry_type: ReferralEntryType::Link,
                        flags: 0,
                        path: alloc::format!("\\\\{}\\{}", server, share),
                        ttl: state.roots[ridx].links[lidx].ttl,
                        priority: target.priority,
                    });
                }
            }

            return Ok(DfsReferral {
                path: path.to_string(),
                entries,
                timestamp: 0, // TODO: system time
                ttl: DEFAULT_REFERRAL_TTL,
            });
        }
    }

    Err(DfsError::RootNotFound)
}

// ============================================================================
// Query Functions
// ============================================================================

/// List all DFS roots
pub fn dfs_list_roots() -> Vec<(u32, String, DfsNamespaceType, RootState)> {
    let state = DFS_STATE.lock();
    let mut result = Vec::new();

    for ridx in 0..MAX_ROOTS {
        if state.roots[ridx].active {
            let name = core::str::from_utf8(&state.roots[ridx].name[..state.roots[ridx].name_len])
                .map(String::from)
                .unwrap_or_default();

            result.push((
                state.roots[ridx].id,
                name,
                state.roots[ridx].namespace_type,
                state.roots[ridx].state,
            ));
        }
    }

    result
}

/// List links in a root
pub fn dfs_list_links(root_id: u32) -> Result<Vec<(u32, String, LinkState, usize)>, DfsError> {
    let state = DFS_STATE.lock();

    if !state.initialized {
        return Err(DfsError::NotInitialized);
    }

    let root_idx = find_root_index(&state, root_id)?;
    let mut result = Vec::new();

    for lidx in 0..MAX_LINKS_PER_ROOT {
        if state.roots[root_idx].links[lidx].active {
            let path = core::str::from_utf8(
                &state.roots[root_idx].links[lidx].path[..state.roots[root_idx].links[lidx].path_len],
            )
            .map(String::from)
            .unwrap_or_default();

            result.push((
                state.roots[root_idx].links[lidx].id,
                path,
                state.roots[root_idx].links[lidx].state,
                state.roots[root_idx].links[lidx].target_count,
            ));
        }
    }

    Ok(result)
}

/// Get DFS statistics
pub fn dfs_get_statistics() -> DfsStatistics {
    let state = DFS_STATE.lock();

    DfsStatistics {
        path_resolutions: AtomicU64::new(state.statistics.path_resolutions.load(Ordering::Relaxed)),
        referral_requests: AtomicU64::new(state.statistics.referral_requests.load(Ordering::Relaxed)),
        cache_hits: AtomicU64::new(state.statistics.cache_hits.load(Ordering::Relaxed)),
        cache_misses: AtomicU64::new(state.statistics.cache_misses.load(Ordering::Relaxed)),
        failovers: AtomicU64::new(state.statistics.failovers.load(Ordering::Relaxed)),
        active_roots: AtomicU32::new(state.statistics.active_roots.load(Ordering::Relaxed)),
        active_links: AtomicU32::new(state.statistics.active_links.load(Ordering::Relaxed)),
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn find_root_index(state: &DfsState, root_id: u32) -> Result<usize, DfsError> {
    for idx in 0..MAX_ROOTS {
        if state.roots[idx].active && state.roots[idx].id == root_id {
            return Ok(idx);
        }
    }
    Err(DfsError::RootNotFound)
}

fn find_link_index(root: &DfsRoot, link_id: u32) -> Result<usize, DfsError> {
    for idx in 0..MAX_LINKS_PER_ROOT {
        if root.links[idx].active && root.links[idx].id == link_id {
            return Ok(idx);
        }
    }
    Err(DfsError::LinkNotFound)
}

fn get_best_target(link: &DfsLink) -> Result<DfsTarget, DfsError> {
    let mut best: Option<(usize, u32)> = None;

    for tidx in 0..MAX_TARGETS_PER_LINK {
        if link.targets[tidx].active && link.targets[tidx].state == TargetState::Online {
            if best.is_none() || link.targets[tidx].priority < best.unwrap().1 {
                best = Some((tidx, link.targets[tidx].priority));
            }
        }
    }

    if let Some((idx, _)) = best {
        Ok(link.targets[idx].clone())
    } else {
        Err(DfsError::Offline)
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize DFS subsystem
pub fn init() {
    crate::serial_println!("[DFS] Initializing Distributed File System...");

    {
        let mut state = DFS_STATE.lock();
        state.machine_state = DfsMachineState::Client;
        state.initialized = true;
    }

    crate::serial_println!("[DFS] DFS initialized");
}
