//! DFS Management
//!
//! Windows Server 2003 Distributed File System Management snap-in implementation.
//! Provides DFS namespace and replication management.
//!
//! # Features
//!
//! - DFS Namespaces (stand-alone and domain-based)
//! - DFS targets (folder targets)
//! - DFS links (virtual folders)
//! - Referral settings
//! - DFS Replication (FRS)
//!
//! # References
//!
//! Based on Windows Server 2003 DFS Management snap-in

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::UserHandle;

/// HWND type alias
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum DFS roots
const MAX_ROOTS: usize = 16;

/// Maximum links per root
const MAX_LINKS: usize = 128;

/// Maximum targets per link
const MAX_TARGETS: usize = 8;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Maximum comment length
const MAX_COMMENT_LEN: usize = 256;

// ============================================================================
// DFS Root Type
// ============================================================================

/// DFS root type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DfsRootType {
    /// Stand-alone DFS root
    #[default]
    Standalone = 0,
    /// Domain-based DFS root (fault tolerant)
    DomainBased = 1,
}

impl DfsRootType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Standalone => "Stand-alone",
            Self::DomainBased => "Domain-based",
        }
    }
}

// ============================================================================
// DFS State
// ============================================================================

/// DFS root/link state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DfsState {
    /// Normal operation
    #[default]
    Normal = 0,
    /// Inconsistent (needs verification)
    Inconsistent = 1,
    /// Offline
    Offline = 2,
    /// Online (recovering)
    Online = 3,
}

impl DfsState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Inconsistent => "Inconsistent",
            Self::Offline => "Offline",
            Self::Online => "Online",
        }
    }
}

// ============================================================================
// Target Priority
// ============================================================================

/// Target priority class
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TargetPriority {
    /// Same site, same cost
    #[default]
    SiteCostNormal = 0,
    /// Same site, high priority
    SiteCostHigh = 1,
    /// Same site, low priority
    SiteCostLow = 2,
    /// Global, high priority
    GlobalHigh = 3,
    /// Global, low priority
    GlobalLow = 4,
}

impl TargetPriority {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SiteCostNormal => "Normal (same site)",
            Self::SiteCostHigh => "High (same site)",
            Self::SiteCostLow => "Low (same site)",
            Self::GlobalHigh => "High (global)",
            Self::GlobalLow => "Low (global)",
        }
    }
}

// ============================================================================
// DFS Target
// ============================================================================

/// DFS folder target
#[derive(Clone, Copy)]
pub struct DfsTarget {
    /// Server name
    pub server: [u8; MAX_NAME_LEN],
    /// Server name length
    pub server_len: u8,
    /// Share name
    pub share: [u8; MAX_NAME_LEN],
    /// Share name length
    pub share_len: u8,
    /// Full UNC path
    pub path: [u8; MAX_PATH_LEN],
    /// Path length
    pub path_len: u16,
    /// Target priority
    pub priority: TargetPriority,
    /// Target state
    pub state: DfsState,
    /// Target is enabled
    pub enabled: bool,
    /// Target is online
    pub online: bool,
    /// Target is in use
    pub in_use: bool,
    /// Referral count (how many times referred)
    pub referral_count: u64,
}

impl DfsTarget {
    pub const fn new() -> Self {
        Self {
            server: [0u8; MAX_NAME_LEN],
            server_len: 0,
            share: [0u8; MAX_NAME_LEN],
            share_len: 0,
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            priority: TargetPriority::SiteCostNormal,
            state: DfsState::Normal,
            enabled: true,
            online: true,
            in_use: false,
            referral_count: 0,
        }
    }

    pub fn set_server(&mut self, server: &[u8]) {
        let len = server.len().min(MAX_NAME_LEN);
        self.server[..len].copy_from_slice(&server[..len]);
        self.server_len = len as u8;
    }

    pub fn set_share(&mut self, share: &[u8]) {
        let len = share.len().min(MAX_NAME_LEN);
        self.share[..len].copy_from_slice(&share[..len]);
        self.share_len = len as u8;
    }

    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_PATH_LEN);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path_len = len as u16;
    }

    pub fn get_path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }
}

// ============================================================================
// DFS Link
// ============================================================================

/// DFS link (virtual folder)
#[derive(Clone, Copy)]
pub struct DfsLink {
    /// Link name (folder name in DFS namespace)
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: u8,
    /// Comment
    pub comment: [u8; MAX_COMMENT_LEN],
    /// Comment length
    pub comment_len: u16,
    /// Link state
    pub state: DfsState,
    /// Targets for this link
    pub targets: [DfsTarget; MAX_TARGETS],
    /// Target count
    pub target_count: u32,
    /// Referral TTL (seconds)
    pub referral_ttl: u32,
    /// Link is in use
    pub in_use: bool,
}

impl DfsLink {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            comment: [0u8; MAX_COMMENT_LEN],
            comment_len: 0,
            state: DfsState::Normal,
            targets: [const { DfsTarget::new() }; MAX_TARGETS],
            target_count: 0,
            referral_ttl: 1800, // 30 minutes default
            in_use: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    pub fn set_comment(&mut self, comment: &[u8]) {
        let len = comment.len().min(MAX_COMMENT_LEN);
        self.comment[..len].copy_from_slice(&comment[..len]);
        self.comment_len = len as u16;
    }

    /// Add a target to this link
    pub fn add_target(&mut self, server: &[u8], share: &[u8], path: &[u8]) -> Option<usize> {
        for (i, target) in self.targets.iter_mut().enumerate() {
            if !target.in_use {
                target.set_server(server);
                target.set_share(share);
                target.set_path(path);
                target.enabled = true;
                target.online = true;
                target.state = DfsState::Normal;
                target.in_use = true;
                self.target_count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Remove a target
    pub fn remove_target(&mut self, index: usize) -> bool {
        if index < MAX_TARGETS && self.targets[index].in_use {
            self.targets[index].in_use = false;
            self.target_count = self.target_count.saturating_sub(1);
            true
        } else {
            false
        }
    }
}

// ============================================================================
// DFS Root
// ============================================================================

/// DFS root (namespace)
pub struct DfsRoot {
    /// Root name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: u8,
    /// Server hosting the root
    pub server: [u8; MAX_NAME_LEN],
    /// Server name length
    pub server_len: u8,
    /// Share name for the root
    pub share: [u8; MAX_NAME_LEN],
    /// Share name length
    pub share_len: u8,
    /// Comment
    pub comment: [u8; MAX_COMMENT_LEN],
    /// Comment length
    pub comment_len: u16,
    /// Root type
    pub root_type: DfsRootType,
    /// Root state
    pub state: DfsState,
    /// Links in this root
    pub links: [DfsLink; MAX_LINKS],
    /// Link count
    pub link_count: u32,
    /// Root is in use
    pub in_use: bool,
    /// Enable site costing
    pub site_costing: bool,
    /// Enable in-site referrals
    pub insite_referrals: bool,
    /// Enable root scalability mode
    pub root_scalability: bool,
}

impl DfsRoot {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            server: [0u8; MAX_NAME_LEN],
            server_len: 0,
            share: [0u8; MAX_NAME_LEN],
            share_len: 0,
            comment: [0u8; MAX_COMMENT_LEN],
            comment_len: 0,
            root_type: DfsRootType::Standalone,
            state: DfsState::Normal,
            links: [const { DfsLink::new() }; MAX_LINKS],
            link_count: 0,
            in_use: false,
            site_costing: true,
            insite_referrals: true,
            root_scalability: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    pub fn set_server(&mut self, server: &[u8]) {
        let len = server.len().min(MAX_NAME_LEN);
        self.server[..len].copy_from_slice(&server[..len]);
        self.server_len = len as u8;
    }

    pub fn set_share(&mut self, share: &[u8]) {
        let len = share.len().min(MAX_NAME_LEN);
        self.share[..len].copy_from_slice(&share[..len]);
        self.share_len = len as u8;
    }

    /// Add a link to this root
    pub fn add_link(&mut self, name: &[u8]) -> Option<usize> {
        for (i, link) in self.links.iter_mut().enumerate() {
            if !link.in_use {
                link.set_name(name);
                link.state = DfsState::Normal;
                link.in_use = true;
                self.link_count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Remove a link
    pub fn remove_link(&mut self, index: usize) -> bool {
        if index < MAX_LINKS && self.links[index].in_use {
            self.links[index].in_use = false;
            self.link_count = self.link_count.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Find a link by name
    pub fn find_link(&self, name: &[u8]) -> Option<usize> {
        for (i, link) in self.links.iter().enumerate() {
            if link.in_use && link.get_name() == name {
                return Some(i);
            }
        }
        None
    }
}

// ============================================================================
// Manager State
// ============================================================================

/// DFS Manager state
struct DfsManagerState {
    /// DFS roots
    roots: [DfsRoot; MAX_ROOTS],
    /// Root count
    root_count: u32,
    /// Selected root
    selected_root: Option<usize>,
    /// Selected link
    selected_link: Option<usize>,
    /// Dialog handle
    dialog_handle: HWND,
    /// View mode (0=roots, 1=links, 2=targets)
    view_mode: u8,
}

impl DfsManagerState {
    pub const fn new() -> Self {
        Self {
            roots: [const { DfsRoot::new() }; MAX_ROOTS],
            root_count: 0,
            selected_root: None,
            selected_link: None,
            dialog_handle: UserHandle::from_raw(0),
            view_mode: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static DFS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static DFS_MANAGER: SpinLock<DfsManagerState> = SpinLock::new(DfsManagerState::new());

// Statistics
static ROOT_COUNT: AtomicU32 = AtomicU32::new(0);
static LINK_COUNT: AtomicU32 = AtomicU32::new(0);
static REFERRAL_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize DFS Manager
pub fn init() {
    if DFS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = DFS_MANAGER.lock();

    // Create a default standalone DFS root
    let root = &mut state.roots[0];
    root.set_name(b"Public");
    root.set_server(b"localhost");
    root.set_share(b"DfsRoot");
    root.root_type = DfsRootType::Standalone;
    root.state = DfsState::Normal;
    root.in_use = true;

    // Add a sample link
    if let Some(link_idx) = root.add_link(b"Shared") {
        root.links[link_idx].add_target(b"server1", b"share1", b"\\\\server1\\share1");
    }

    state.root_count = 1;
    ROOT_COUNT.store(1, Ordering::Relaxed);
    LINK_COUNT.store(1, Ordering::Relaxed);

    crate::serial_println!("[WIN32K] DFS Manager initialized");
}

// ============================================================================
// Root Management
// ============================================================================

/// Create a new DFS root
pub fn create_root(
    name: &[u8],
    server: &[u8],
    share: &[u8],
    root_type: DfsRootType,
) -> Option<usize> {
    let mut state = DFS_MANAGER.lock();

    for (i, root) in state.roots.iter_mut().enumerate() {
        if !root.in_use {
            root.set_name(name);
            root.set_server(server);
            root.set_share(share);
            root.root_type = root_type;
            root.state = DfsState::Normal;
            root.in_use = true;
            state.root_count += 1;
            ROOT_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(i);
        }
    }
    None
}

/// Delete a DFS root
pub fn delete_root(index: usize) -> bool {
    let mut state = DFS_MANAGER.lock();

    if index < MAX_ROOTS && state.roots[index].in_use {
        let link_count = state.roots[index].link_count;
        state.roots[index].in_use = false;
        state.root_count = state.root_count.saturating_sub(1);
        ROOT_COUNT.fetch_sub(1, Ordering::Relaxed);
        LINK_COUNT.fetch_sub(link_count, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// Get root info
pub fn get_root_info(index: usize) -> Option<(DfsRootType, DfsState, u32)> {
    let state = DFS_MANAGER.lock();

    if index < MAX_ROOTS && state.roots[index].in_use {
        Some((
            state.roots[index].root_type,
            state.roots[index].state,
            state.roots[index].link_count,
        ))
    } else {
        None
    }
}

// ============================================================================
// Link Management
// ============================================================================

/// Create a new DFS link
pub fn create_link(root_index: usize, name: &[u8]) -> Option<usize> {
    let mut state = DFS_MANAGER.lock();

    if root_index < MAX_ROOTS && state.roots[root_index].in_use {
        let result = state.roots[root_index].add_link(name);
        if result.is_some() {
            LINK_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        result
    } else {
        None
    }
}

/// Delete a DFS link
pub fn delete_link(root_index: usize, link_index: usize) -> bool {
    let mut state = DFS_MANAGER.lock();

    if root_index < MAX_ROOTS && state.roots[root_index].in_use {
        if state.roots[root_index].remove_link(link_index) {
            LINK_COUNT.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Add target to a link
pub fn add_target(
    root_index: usize,
    link_index: usize,
    server: &[u8],
    share: &[u8],
    path: &[u8],
) -> Option<usize> {
    let mut state = DFS_MANAGER.lock();

    if root_index < MAX_ROOTS && state.roots[root_index].in_use {
        if link_index < MAX_LINKS && state.roots[root_index].links[link_index].in_use {
            return state.roots[root_index].links[link_index].add_target(server, share, path);
        }
    }
    None
}

/// Remove target from a link
pub fn remove_target(root_index: usize, link_index: usize, target_index: usize) -> bool {
    let mut state = DFS_MANAGER.lock();

    if root_index < MAX_ROOTS && state.roots[root_index].in_use {
        if link_index < MAX_LINKS && state.roots[root_index].links[link_index].in_use {
            return state.roots[root_index].links[link_index].remove_target(target_index);
        }
    }
    false
}

/// Set target priority
pub fn set_target_priority(
    root_index: usize,
    link_index: usize,
    target_index: usize,
    priority: TargetPriority,
) -> bool {
    let mut state = DFS_MANAGER.lock();

    if root_index < MAX_ROOTS && state.roots[root_index].in_use {
        if link_index < MAX_LINKS && state.roots[root_index].links[link_index].in_use {
            if target_index < MAX_TARGETS {
                if state.roots[root_index].links[link_index].targets[target_index].in_use {
                    state.roots[root_index].links[link_index].targets[target_index].priority = priority;
                    return true;
                }
            }
        }
    }
    false
}

/// Enable/disable target
pub fn set_target_enabled(
    root_index: usize,
    link_index: usize,
    target_index: usize,
    enabled: bool,
) -> bool {
    let mut state = DFS_MANAGER.lock();

    if root_index < MAX_ROOTS && state.roots[root_index].in_use {
        if link_index < MAX_LINKS && state.roots[root_index].links[link_index].in_use {
            if target_index < MAX_TARGETS {
                if state.roots[root_index].links[link_index].targets[target_index].in_use {
                    state.roots[root_index].links[link_index].targets[target_index].enabled = enabled;
                    return true;
                }
            }
        }
    }
    false
}

// ============================================================================
// Referral Operations
// ============================================================================

/// Get a referral for a DFS path
pub fn get_referral(root_index: usize, path: &[u8]) -> Option<usize> {
    let mut state = DFS_MANAGER.lock();

    if root_index < MAX_ROOTS && state.roots[root_index].in_use {
        // Simple path matching - find link by name
        for (i, link) in state.roots[root_index].links.iter_mut().enumerate() {
            if link.in_use && link.get_name() == path {
                REFERRAL_COUNT.fetch_add(1, Ordering::Relaxed);
                // Increment referral count for first enabled target
                for target in link.targets.iter_mut() {
                    if target.in_use && target.enabled && target.online {
                        target.referral_count += 1;
                        break;
                    }
                }
                return Some(i);
            }
        }
    }
    None
}

/// Set referral TTL for a link
pub fn set_referral_ttl(root_index: usize, link_index: usize, ttl_seconds: u32) -> bool {
    let mut state = DFS_MANAGER.lock();

    if root_index < MAX_ROOTS && state.roots[root_index].in_use {
        if link_index < MAX_LINKS && state.roots[root_index].links[link_index].in_use {
            state.roots[root_index].links[link_index].referral_ttl = ttl_seconds;
            return true;
        }
    }
    false
}

// ============================================================================
// Configuration
// ============================================================================

/// Set site costing for a root
pub fn set_site_costing(root_index: usize, enabled: bool) -> bool {
    let mut state = DFS_MANAGER.lock();

    if root_index < MAX_ROOTS && state.roots[root_index].in_use {
        state.roots[root_index].site_costing = enabled;
        true
    } else {
        false
    }
}

/// Set in-site referrals for a root
pub fn set_insite_referrals(root_index: usize, enabled: bool) -> bool {
    let mut state = DFS_MANAGER.lock();

    if root_index < MAX_ROOTS && state.roots[root_index].in_use {
        state.roots[root_index].insite_referrals = enabled;
        true
    } else {
        false
    }
}

// ============================================================================
// Dialog Management
// ============================================================================

/// Show DFS Manager dialog
pub fn show_dialog(parent: HWND) -> HWND {
    let mut state = DFS_MANAGER.lock();

    let handle = UserHandle::from_raw(0xE601);
    state.dialog_handle = handle;
    state.selected_root = Some(0);
    state.selected_link = None;
    state.view_mode = 0;

    let _ = parent;
    handle
}

/// Close DFS Manager dialog
pub fn close_dialog() {
    let mut state = DFS_MANAGER.lock();
    state.dialog_handle = UserHandle::from_raw(0);
}

/// Select a root
pub fn select_root(index: usize) {
    let mut state = DFS_MANAGER.lock();
    if index < MAX_ROOTS && state.roots[index].in_use {
        state.selected_root = Some(index);
        state.selected_link = None;
    }
}

/// Select a link
pub fn select_link(index: usize) {
    let mut state = DFS_MANAGER.lock();
    if let Some(root_idx) = state.selected_root {
        if index < MAX_LINKS && state.roots[root_idx].links[index].in_use {
            state.selected_link = Some(index);
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// DFS statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct DfsStats {
    pub initialized: bool,
    pub root_count: u32,
    pub link_count: u32,
    pub referral_count: u32,
}

/// Get DFS statistics
pub fn get_stats() -> DfsStats {
    DfsStats {
        initialized: DFS_INITIALIZED.load(Ordering::Relaxed),
        root_count: ROOT_COUNT.load(Ordering::Relaxed),
        link_count: LINK_COUNT.load(Ordering::Relaxed),
        referral_count: REFERRAL_COUNT.load(Ordering::Relaxed),
    }
}
