//! Distributed File System Service (DFS)
//!
//! The DFS service provides a unified namespace for file shares
//! distributed across multiple servers, enabling transparent access
//! to distributed resources.
//!
//! # Features
//!
//! - **DFS Roots**: Domain-based and standalone roots
//! - **DFS Links**: Virtual folders mapping to shared folders
//! - **Targets**: Multiple target servers per link (failover/load balance)
//! - **Referrals**: Client redirection to actual servers
//!
//! # DFS Types
//!
//! - Domain-based: Stored in Active Directory
//! - Standalone: Stored locally on server
//!
//! # Architecture
//!
//! - DFS Namespace: Virtual folder tree
//! - DFS Links: Map virtual paths to UNC paths
//! - Targets: Physical server shares

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum DFS roots
const MAX_ROOTS: usize = 8;

/// Maximum links per root
const MAX_LINKS: usize = 128;

/// Maximum targets per link
const MAX_TARGETS: usize = 4;

/// Maximum path length
const MAX_PATH: usize = 260;

/// Maximum server name length
const MAX_SERVER: usize = 64;

/// Maximum comment length
const MAX_COMMENT: usize = 128;

/// DFS root type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootType {
    /// Standalone DFS root
    Standalone = 0,
    /// Domain-based DFS root
    DomainBased = 1,
}

impl RootType {
    const fn empty() -> Self {
        RootType::Standalone
    }
}

/// DFS root state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootState {
    /// Offline
    Offline = 0,
    /// Online
    Online = 1,
    /// Inconsistent (needs replication)
    Inconsistent = 2,
}

impl RootState {
    const fn empty() -> Self {
        RootState::Offline
    }
}

/// Target state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    /// Offline
    Offline = 0,
    /// Online
    Online = 1,
    /// Unreachable
    Unreachable = 2,
}

impl TargetState {
    const fn empty() -> Self {
        TargetState::Online
    }
}

/// Target priority class
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityClass {
    /// Site cost normal (default)
    SiteCostNormal = 0,
    /// Global high priority
    GlobalHigh = 1,
    /// Site cost high
    SiteCostHigh = 2,
    /// Site cost low
    SiteCostLow = 3,
    /// Global low priority
    GlobalLow = 4,
}

impl PriorityClass {
    const fn empty() -> Self {
        PriorityClass::SiteCostNormal
    }
}

/// DFS target (physical server share)
#[repr(C)]
#[derive(Clone)]
pub struct DfsTarget {
    /// Server name
    pub server: [u8; MAX_SERVER],
    /// Share name
    pub share: [u8; MAX_SERVER],
    /// Target state
    pub state: TargetState,
    /// Priority class
    pub priority: PriorityClass,
    /// Priority rank (0-31)
    pub rank: u32,
    /// Last check time
    pub last_check: i64,
    /// Entry is valid
    pub valid: bool,
}

impl DfsTarget {
    const fn empty() -> Self {
        DfsTarget {
            server: [0; MAX_SERVER],
            share: [0; MAX_SERVER],
            state: TargetState::empty(),
            priority: PriorityClass::empty(),
            rank: 0,
            last_check: 0,
            valid: false,
        }
    }
}

/// DFS link (virtual folder)
#[repr(C)]
#[derive(Clone)]
pub struct DfsLink {
    /// Link ID
    pub link_id: u64,
    /// Link path (relative to root)
    pub path: [u8; MAX_PATH],
    /// Comment/description
    pub comment: [u8; MAX_COMMENT],
    /// Targets
    pub targets: [DfsTarget; MAX_TARGETS],
    /// Target count
    pub target_count: usize,
    /// TTL for referrals (seconds)
    pub referral_ttl: u32,
    /// Is online
    pub online: bool,
    /// Creation time
    pub created: i64,
    /// Entry is valid
    pub valid: bool,
}

impl DfsLink {
    const fn empty() -> Self {
        DfsLink {
            link_id: 0,
            path: [0; MAX_PATH],
            comment: [0; MAX_COMMENT],
            targets: [const { DfsTarget::empty() }; MAX_TARGETS],
            target_count: 0,
            referral_ttl: 1800, // 30 minutes
            online: true,
            created: 0,
            valid: false,
        }
    }
}

/// DFS root
#[repr(C)]
#[derive(Clone)]
pub struct DfsRoot {
    /// Root ID
    pub root_id: u64,
    /// Root name
    pub name: [u8; MAX_SERVER],
    /// Root type
    pub root_type: RootType,
    /// State
    pub state: RootState,
    /// Comment
    pub comment: [u8; MAX_COMMENT],
    /// Domain (for domain-based)
    pub domain: [u8; MAX_SERVER],
    /// Host server
    pub host_server: [u8; MAX_SERVER],
    /// Host share
    pub host_share: [u8; MAX_SERVER],
    /// Links
    pub links: [DfsLink; MAX_LINKS],
    /// Link count
    pub link_count: usize,
    /// Next link ID
    pub next_link_id: u64,
    /// Creation time
    pub created: i64,
    /// Entry is valid
    pub valid: bool,
}

impl DfsRoot {
    const fn empty() -> Self {
        DfsRoot {
            root_id: 0,
            name: [0; MAX_SERVER],
            root_type: RootType::empty(),
            state: RootState::empty(),
            comment: [0; MAX_COMMENT],
            domain: [0; MAX_SERVER],
            host_server: [0; MAX_SERVER],
            host_share: [0; MAX_SERVER],
            links: [const { DfsLink::empty() }; MAX_LINKS],
            link_count: 0,
            next_link_id: 1,
            created: 0,
            valid: false,
        }
    }
}

/// DFS referral entry (returned to clients)
#[repr(C)]
#[derive(Clone)]
pub struct DfsReferral {
    /// UNC path to target
    pub path: [u8; MAX_PATH],
    /// Priority
    pub priority: u32,
    /// TTL
    pub ttl: u32,
    /// Entry is valid
    pub valid: bool,
}

impl DfsReferral {
    const fn empty() -> Self {
        DfsReferral {
            path: [0; MAX_PATH],
            priority: 0,
            ttl: 1800,
            valid: false,
        }
    }
}

/// DFS service state
pub struct DfsState {
    /// Service is running
    pub running: bool,
    /// DFS roots
    pub roots: [DfsRoot; MAX_ROOTS],
    /// Root count
    pub root_count: usize,
    /// Next root ID
    pub next_root_id: u64,
    /// Local server name
    pub server_name: [u8; MAX_SERVER],
    /// Service start time
    pub start_time: i64,
}

impl DfsState {
    const fn new() -> Self {
        DfsState {
            running: false,
            roots: [const { DfsRoot::empty() }; MAX_ROOTS],
            root_count: 0,
            next_root_id: 1,
            server_name: [0; MAX_SERVER],
            start_time: 0,
        }
    }
}

/// Global state
static DFS_STATE: Mutex<DfsState> = Mutex::new(DfsState::new());

/// Statistics
static REFERRALS_SERVED: AtomicU64 = AtomicU64::new(0);
static REFERRALS_FAILED: AtomicU64 = AtomicU64::new(0);
static LINKS_CREATED: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize DFS service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = DFS_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    let name = b"NOSTALGOS";
    state.server_name[..name.len()].copy_from_slice(name);

    crate::serial_println!("[DFS] Distributed File System service initialized");
}

/// Create a standalone DFS root
pub fn create_standalone_root(
    name: &[u8],
    share: &[u8],
    comment: &[u8],
) -> Result<u64, u32> {
    let mut state = DFS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_SERVER);

    // Check for duplicate
    for root in state.roots.iter() {
        if root.valid && root.name[..name_len] == name[..name_len] {
            return Err(0x80070055);
        }
    }

    let slot = state.roots.iter().position(|r| !r.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let root_id = state.next_root_id;
    state.next_root_id += 1;
    state.root_count += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    let share_len = share.len().min(MAX_SERVER);
    let comment_len = comment.len().min(MAX_COMMENT);
    let server_name = state.server_name;

    let root = &mut state.roots[slot];
    root.root_id = root_id;
    root.name = [0; MAX_SERVER];
    root.name[..name_len].copy_from_slice(&name[..name_len]);
    root.root_type = RootType::Standalone;
    root.state = RootState::Online;
    root.comment = [0; MAX_COMMENT];
    root.comment[..comment_len].copy_from_slice(&comment[..comment_len]);
    root.host_server = server_name;
    root.host_share = [0; MAX_SERVER];
    root.host_share[..share_len].copy_from_slice(&share[..share_len]);
    root.created = now;
    root.valid = true;

    Ok(root_id)
}

/// Create a domain-based DFS root
pub fn create_domain_root(
    domain: &[u8],
    name: &[u8],
    share: &[u8],
    comment: &[u8],
) -> Result<u64, u32> {
    let mut state = DFS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let name_len = name.len().min(MAX_SERVER);

    let slot = state.roots.iter().position(|r| !r.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let root_id = state.next_root_id;
    state.next_root_id += 1;
    state.root_count += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    let domain_len = domain.len().min(MAX_SERVER);
    let share_len = share.len().min(MAX_SERVER);
    let comment_len = comment.len().min(MAX_COMMENT);
    let server_name = state.server_name;

    let root = &mut state.roots[slot];
    root.root_id = root_id;
    root.name = [0; MAX_SERVER];
    root.name[..name_len].copy_from_slice(&name[..name_len]);
    root.root_type = RootType::DomainBased;
    root.state = RootState::Online;
    root.domain = [0; MAX_SERVER];
    root.domain[..domain_len].copy_from_slice(&domain[..domain_len]);
    root.comment = [0; MAX_COMMENT];
    root.comment[..comment_len].copy_from_slice(&comment[..comment_len]);
    root.host_server = server_name;
    root.host_share = [0; MAX_SERVER];
    root.host_share[..share_len].copy_from_slice(&share[..share_len]);
    root.created = now;
    root.valid = true;

    Ok(root_id)
}

/// Delete a DFS root
pub fn delete_root(root_id: u64) -> Result<(), u32> {
    let mut state = DFS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.roots.iter()
        .position(|r| r.valid && r.root_id == root_id);

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    // Clear all links
    for link in state.roots[idx].links.iter_mut() {
        link.valid = false;
    }

    state.roots[idx].valid = false;
    state.root_count = state.root_count.saturating_sub(1);

    Ok(())
}

/// Add a link to a root
pub fn add_link(
    root_id: u64,
    path: &[u8],
    server: &[u8],
    share: &[u8],
    comment: &[u8],
) -> Result<u64, u32> {
    let mut state = DFS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let root_idx = state.roots.iter()
        .position(|r| r.valid && r.root_id == root_id);

    let root_idx = match root_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let path_len = path.len().min(MAX_PATH);

    // Check for duplicate path in this root
    for link in state.roots[root_idx].links.iter() {
        if link.valid && link.path[..path_len] == path[..path_len] {
            return Err(0x80070055);
        }
    }

    let link_slot = state.roots[root_idx].links.iter().position(|l| !l.valid);
    let link_slot = match link_slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let link_id = state.roots[root_idx].next_link_id;
    state.roots[root_idx].next_link_id += 1;
    state.roots[root_idx].link_count += 1;

    let now = crate::rtl::time::rtl_get_system_time();
    let server_len = server.len().min(MAX_SERVER);
    let share_len = share.len().min(MAX_SERVER);
    let comment_len = comment.len().min(MAX_COMMENT);

    let link = &mut state.roots[root_idx].links[link_slot];
    link.link_id = link_id;
    link.path = [0; MAX_PATH];
    link.path[..path_len].copy_from_slice(&path[..path_len]);
    link.comment = [0; MAX_COMMENT];
    link.comment[..comment_len].copy_from_slice(&comment[..comment_len]);
    link.created = now;
    link.online = true;
    link.valid = true;

    // Add first target
    link.targets[0].server = [0; MAX_SERVER];
    link.targets[0].server[..server_len].copy_from_slice(&server[..server_len]);
    link.targets[0].share = [0; MAX_SERVER];
    link.targets[0].share[..share_len].copy_from_slice(&share[..share_len]);
    link.targets[0].state = TargetState::Online;
    link.targets[0].priority = PriorityClass::SiteCostNormal;
    link.targets[0].last_check = now;
    link.targets[0].valid = true;
    link.target_count = 1;

    LINKS_CREATED.fetch_add(1, Ordering::SeqCst);

    Ok(link_id)
}

/// Remove a link
pub fn remove_link(root_id: u64, link_id: u64) -> Result<(), u32> {
    let mut state = DFS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let root_idx = state.roots.iter()
        .position(|r| r.valid && r.root_id == root_id);

    let root_idx = match root_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let link_idx = state.roots[root_idx].links.iter()
        .position(|l| l.valid && l.link_id == link_id);

    let link_idx = match link_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.roots[root_idx].links[link_idx].valid = false;
    state.roots[root_idx].link_count = state.roots[root_idx].link_count.saturating_sub(1);

    Ok(())
}

/// Add a target to a link
pub fn add_target(
    root_id: u64,
    link_id: u64,
    server: &[u8],
    share: &[u8],
) -> Result<(), u32> {
    let mut state = DFS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let root_idx = state.roots.iter()
        .position(|r| r.valid && r.root_id == root_id);

    let root_idx = match root_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let link_idx = state.roots[root_idx].links.iter()
        .position(|l| l.valid && l.link_id == link_id);

    let link_idx = match link_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let link = &mut state.roots[root_idx].links[link_idx];

    let target_slot = link.targets.iter().position(|t| !t.valid);
    let target_slot = match target_slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let server_len = server.len().min(MAX_SERVER);
    let share_len = share.len().min(MAX_SERVER);
    let now = crate::rtl::time::rtl_get_system_time();

    let target = &mut link.targets[target_slot];
    target.server = [0; MAX_SERVER];
    target.server[..server_len].copy_from_slice(&server[..server_len]);
    target.share = [0; MAX_SERVER];
    target.share[..share_len].copy_from_slice(&share[..share_len]);
    target.state = TargetState::Online;
    target.priority = PriorityClass::SiteCostNormal;
    target.last_check = now;
    target.valid = true;

    link.target_count += 1;

    Ok(())
}

/// Remove a target from a link
pub fn remove_target(
    root_id: u64,
    link_id: u64,
    server: &[u8],
) -> Result<(), u32> {
    let mut state = DFS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let root_idx = state.roots.iter()
        .position(|r| r.valid && r.root_id == root_id);

    let root_idx = match root_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let link_idx = state.roots[root_idx].links.iter()
        .position(|l| l.valid && l.link_id == link_id);

    let link_idx = match link_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let server_len = server.len().min(MAX_SERVER);
    let link = &mut state.roots[root_idx].links[link_idx];

    let target_idx = link.targets.iter()
        .position(|t| t.valid && t.server[..server_len] == server[..server_len]);

    let target_idx = match target_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    link.targets[target_idx].valid = false;
    link.target_count = link.target_count.saturating_sub(1);

    Ok(())
}

/// Get referral for a DFS path
pub fn get_referral(
    dfs_path: &[u8],
) -> Result<([DfsReferral; MAX_TARGETS], usize), u32> {
    let state = DFS_STATE.lock();

    if !state.running {
        REFERRALS_FAILED.fetch_add(1, Ordering::SeqCst);
        return Err(0x80070426);
    }

    // Parse path: \\domain\root\link or \\server\root\link
    // For simplicity, find matching root and link

    let mut result = [const { DfsReferral::empty() }; MAX_TARGETS];
    let mut count = 0;

    // Search through roots and links
    for root in state.roots.iter() {
        if !root.valid || root.state != RootState::Online {
            continue;
        }

        for link in root.links.iter() {
            if !link.valid || !link.online {
                continue;
            }

            // Build referrals from targets
            for target in link.targets.iter() {
                if target.valid && target.state == TargetState::Online && count < MAX_TARGETS {
                    // Build UNC path: \\server\share
                    let mut path = [0u8; MAX_PATH];
                    let mut pos = 0;

                    path[pos] = b'\\';
                    pos += 1;
                    path[pos] = b'\\';
                    pos += 1;

                    let server_end = target.server.iter()
                        .position(|&c| c == 0)
                        .unwrap_or(MAX_SERVER);
                    let copy_len = server_end.min(MAX_PATH - pos);
                    path[pos..pos + copy_len].copy_from_slice(&target.server[..copy_len]);
                    pos += copy_len;

                    path[pos] = b'\\';
                    pos += 1;

                    let share_end = target.share.iter()
                        .position(|&c| c == 0)
                        .unwrap_or(MAX_SERVER);
                    let copy_len = share_end.min(MAX_PATH - pos);
                    path[pos..pos + copy_len].copy_from_slice(&target.share[..copy_len]);

                    result[count].path = path;
                    result[count].priority = target.rank;
                    result[count].ttl = link.referral_ttl;
                    result[count].valid = true;
                    count += 1;
                }
            }

            if count > 0 {
                REFERRALS_SERVED.fetch_add(1, Ordering::SeqCst);
                return Ok((result, count));
            }
        }
    }

    REFERRALS_FAILED.fetch_add(1, Ordering::SeqCst);
    Err(0x80070057)
}

/// Enumerate roots
pub fn enum_roots() -> ([DfsRoot; MAX_ROOTS], usize) {
    let state = DFS_STATE.lock();
    let mut result = [const { DfsRoot::empty() }; MAX_ROOTS];
    let mut count = 0;

    for root in state.roots.iter() {
        if root.valid && count < MAX_ROOTS {
            result[count] = root.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get root info
pub fn get_root_info(root_id: u64) -> Option<DfsRoot> {
    let state = DFS_STATE.lock();

    state.roots.iter()
        .find(|r| r.valid && r.root_id == root_id)
        .cloned()
}

/// Set root online/offline
pub fn set_root_state(root_id: u64, online: bool) -> Result<(), u32> {
    let mut state = DFS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let root = state.roots.iter_mut()
        .find(|r| r.valid && r.root_id == root_id);

    let root = match root {
        Some(r) => r,
        None => return Err(0x80070057),
    };

    root.state = if online { RootState::Online } else { RootState::Offline };

    Ok(())
}

/// Set link online/offline
pub fn set_link_state(root_id: u64, link_id: u64, online: bool) -> Result<(), u32> {
    let mut state = DFS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let root_idx = state.roots.iter()
        .position(|r| r.valid && r.root_id == root_id);

    let root_idx = match root_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let link = state.roots[root_idx].links.iter_mut()
        .find(|l| l.valid && l.link_id == link_id);

    let link = match link {
        Some(l) => l,
        None => return Err(0x80070057),
    };

    link.online = online;

    Ok(())
}

/// Set target priority
pub fn set_target_priority(
    root_id: u64,
    link_id: u64,
    server: &[u8],
    priority: PriorityClass,
    rank: u32,
) -> Result<(), u32> {
    let mut state = DFS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let root_idx = state.roots.iter()
        .position(|r| r.valid && r.root_id == root_id);

    let root_idx = match root_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let link_idx = state.roots[root_idx].links.iter()
        .position(|l| l.valid && l.link_id == link_id);

    let link_idx = match link_idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let server_len = server.len().min(MAX_SERVER);
    let target = state.roots[root_idx].links[link_idx].targets.iter_mut()
        .find(|t| t.valid && t.server[..server_len] == server[..server_len]);

    let target = match target {
        Some(t) => t,
        None => return Err(0x80070057),
    };

    target.priority = priority;
    target.rank = rank.min(31);

    Ok(())
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64) {
    (
        REFERRALS_SERVED.load(Ordering::SeqCst),
        REFERRALS_FAILED.load(Ordering::SeqCst),
        LINKS_CREATED.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = DFS_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = DFS_STATE.lock();
    state.running = false;

    // Set all roots offline
    for root in state.roots.iter_mut() {
        if root.valid {
            root.state = RootState::Offline;
        }
    }

    crate::serial_println!("[DFS] Distributed File System service stopped");
}
