//! Cluster Administrator
//!
//! Windows Server 2003 Failover Cluster Management snap-in implementation.
//! Provides cluster node, group, resource, and network management.
//!
//! # Features
//!
//! - Cluster creation and management
//! - Node management (join, evict, pause)
//! - Resource groups and failover policies
//! - Cluster resources (disks, IP addresses, services)
//! - Quorum configuration
//! - Cluster networks
//!
//! # References
//!
//! Based on Windows Server 2003 Cluster Administrator (cluadmin.exe)

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::UserHandle;
use bitflags::bitflags;

/// HWND type alias
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum clusters
const MAX_CLUSTERS: usize = 4;

/// Maximum nodes per cluster
const MAX_NODES: usize = 8;

/// Maximum resource groups per cluster
const MAX_GROUPS: usize = 32;

/// Maximum resources per group
const MAX_RESOURCES: usize = 16;

/// Maximum cluster networks
const MAX_NETWORKS: usize = 8;

/// Maximum dependencies per resource
const MAX_DEPENDENCIES: usize = 8;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum description length
const MAX_DESC_LEN: usize = 256;

// ============================================================================
// Node State
// ============================================================================

/// Cluster node state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum NodeState {
    /// Node state unknown
    #[default]
    Unknown = 0,
    /// Node is up and running
    Up = 1,
    /// Node is down
    Down = 2,
    /// Node is paused
    Paused = 3,
    /// Node is joining cluster
    Joining = 4,
}

impl NodeState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Up => "Up",
            Self::Down => "Down",
            Self::Paused => "Paused",
            Self::Joining => "Joining",
        }
    }
}

// ============================================================================
// Resource State
// ============================================================================

/// Cluster resource state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ResourceState {
    /// State unknown
    #[default]
    Unknown = 0,
    /// Resource is online
    Online = 1,
    /// Resource is offline
    Offline = 2,
    /// Resource is failed
    Failed = 3,
    /// Resource is pending online
    OnlinePending = 4,
    /// Resource is pending offline
    OfflinePending = 5,
    /// Resource inherited state
    Inherited = 6,
}

impl ResourceState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Online => "Online",
            Self::Offline => "Offline",
            Self::Failed => "Failed",
            Self::OnlinePending => "Online Pending",
            Self::OfflinePending => "Offline Pending",
            Self::Inherited => "Inherited",
        }
    }
}

// ============================================================================
// Group State
// ============================================================================

/// Resource group state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum GroupState {
    /// State unknown
    #[default]
    Unknown = 0,
    /// Group is online
    Online = 1,
    /// Group is offline
    Offline = 2,
    /// Group failed
    Failed = 3,
    /// Group partially online
    PartialOnline = 4,
    /// Group pending
    Pending = 5,
}

impl GroupState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Online => "Online",
            Self::Offline => "Offline",
            Self::Failed => "Failed",
            Self::PartialOnline => "Partial Online",
            Self::Pending => "Pending",
        }
    }
}

// ============================================================================
// Resource Types
// ============================================================================

/// Cluster resource type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ResourceType {
    /// Generic resource
    #[default]
    Generic = 0,
    /// Physical disk
    PhysicalDisk = 1,
    /// IP address
    IpAddress = 2,
    /// Network name
    NetworkName = 3,
    /// File share
    FileShare = 4,
    /// Print spooler
    PrintSpooler = 5,
    /// Generic application
    GenericApplication = 6,
    /// Generic script
    GenericScript = 7,
    /// Generic service
    GenericService = 8,
    /// DHCP server
    DhcpServer = 9,
    /// WINS server
    WinsServer = 10,
    /// Distributed transaction coordinator
    Msdtc = 11,
    /// Message queuing
    Msmq = 12,
    /// SQL Server
    SqlServer = 13,
    /// IIS virtual server
    IisServer = 14,
    /// Quorum disk
    Quorum = 15,
}

impl ResourceType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Generic => "Generic",
            Self::PhysicalDisk => "Physical Disk",
            Self::IpAddress => "IP Address",
            Self::NetworkName => "Network Name",
            Self::FileShare => "File Share",
            Self::PrintSpooler => "Print Spooler",
            Self::GenericApplication => "Generic Application",
            Self::GenericScript => "Generic Script",
            Self::GenericService => "Generic Service",
            Self::DhcpServer => "DHCP",
            Self::WinsServer => "WINS",
            Self::Msdtc => "DTC",
            Self::Msmq => "Message Queuing",
            Self::SqlServer => "SQL Server",
            Self::IisServer => "IIS",
            Self::Quorum => "Quorum",
        }
    }
}

// ============================================================================
// Quorum Type
// ============================================================================

/// Cluster quorum type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum QuorumType {
    /// Shared disk quorum
    #[default]
    SharedDisk = 0,
    /// Majority node set
    MajorityNodeSet = 1,
    /// Local quorum
    LocalQuorum = 2,
}

impl QuorumType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SharedDisk => "Shared Disk",
            Self::MajorityNodeSet => "Majority Node Set",
            Self::LocalQuorum => "Local Quorum",
        }
    }
}

// ============================================================================
// Network Role
// ============================================================================

/// Cluster network role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum NetworkRole {
    /// Not used for cluster
    #[default]
    None = 0,
    /// Internal cluster communication only
    InternalOnly = 1,
    /// Client access only
    ClientOnly = 2,
    /// All communication (internal + client)
    All = 3,
}

impl NetworkRole {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "Not used",
            Self::InternalOnly => "Internal Only",
            Self::ClientOnly => "Client Access Only",
            Self::All => "All Communications",
        }
    }
}

bitflags! {
    /// Cluster resource flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ResourceFlags: u32 {
        /// Resource is core (cannot be deleted)
        const CORE = 0x0001;
        /// Resource affects quorum
        const QUORUM_RESOURCE = 0x0002;
        /// Resource is local quorum capable
        const LOCAL_QUORUM_CAPABLE = 0x0004;
        /// Delete on failure
        const DELETE_ON_FAILURE = 0x0008;
        /// Do not monitor
        const DO_NOT_CHECKPOINT = 0x0010;
    }
}

// ============================================================================
// Cluster Node
// ============================================================================

/// Cluster node
#[derive(Clone, Copy)]
pub struct ClusterNode {
    /// Node in use
    pub in_use: bool,
    /// Node ID
    pub node_id: u32,
    /// Node name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Node state
    pub state: NodeState,
    /// IP address
    pub ip_address: [u8; 4],
    /// Highest version supported
    pub highest_version: u32,
    /// Lowest version supported
    pub lowest_version: u32,
    /// Build number
    pub build_number: u32,
    /// CSD version (service pack)
    pub csd_version: [u8; 32],
    /// CSD version length
    pub csd_version_len: usize,
}

impl ClusterNode {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            node_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            state: NodeState::Unknown,
            ip_address: [0u8; 4],
            highest_version: 0,
            lowest_version: 0,
            build_number: 0,
            csd_version: [0u8; 32],
            csd_version_len: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

// ============================================================================
// Cluster Resource
// ============================================================================

/// Cluster resource
#[derive(Clone, Copy)]
pub struct ClusterResource {
    /// Resource in use
    pub in_use: bool,
    /// Resource ID
    pub resource_id: u32,
    /// Resource name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Resource type
    pub resource_type: ResourceType,
    /// Resource state
    pub state: ResourceState,
    /// Owner node ID
    pub owner_node: u32,
    /// Resource flags
    pub flags: ResourceFlags,
    /// Restart action (0=no restart, 1=restart, 2=restart no notify)
    pub restart_action: u8,
    /// Restart threshold
    pub restart_threshold: u32,
    /// Restart period (ms)
    pub restart_period: u32,
    /// Pending timeout (ms)
    pub pending_timeout: u32,
    /// Dependencies (resource IDs)
    pub dependencies: [u32; MAX_DEPENDENCIES],
    /// Dependency count
    pub dependency_count: usize,
    /// Private properties (type-specific data)
    pub private_data: [u8; 128],
    /// Private data length
    pub private_data_len: usize,
}

impl ClusterResource {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            resource_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            resource_type: ResourceType::Generic,
            state: ResourceState::Unknown,
            owner_node: 0,
            flags: ResourceFlags::empty(),
            restart_action: 1,
            restart_threshold: 3,
            restart_period: 900000, // 15 minutes
            pending_timeout: 180000, // 3 minutes
            dependencies: [0u32; MAX_DEPENDENCIES],
            dependency_count: 0,
            private_data: [0u8; 128],
            private_data_len: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn add_dependency(&mut self, resource_id: u32) -> bool {
        if self.dependency_count >= MAX_DEPENDENCIES {
            return false;
        }
        self.dependencies[self.dependency_count] = resource_id;
        self.dependency_count += 1;
        true
    }
}

// ============================================================================
// Resource Group
// ============================================================================

/// Resource group
#[derive(Clone, Copy)]
pub struct ResourceGroup {
    /// Group in use
    pub in_use: bool,
    /// Group ID
    pub group_id: u32,
    /// Group name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub description_len: usize,
    /// Group state
    pub state: GroupState,
    /// Owner node ID
    pub owner_node: u32,
    /// Preferred owners (node IDs, in order)
    pub preferred_owners: [u32; MAX_NODES],
    /// Preferred owner count
    pub preferred_owner_count: usize,
    /// Failover threshold
    pub failover_threshold: u32,
    /// Failover period (hours)
    pub failover_period: u32,
    /// Auto failback (0=disabled, 1=immediate, 2=scheduled)
    pub auto_failback: u8,
    /// Failback window start (hours)
    pub failback_start: u8,
    /// Failback window end (hours)
    pub failback_end: u8,
    /// Resources in this group
    pub resources: [ClusterResource; MAX_RESOURCES],
    /// Resource count
    pub resource_count: usize,
}

impl ResourceGroup {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            group_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            description: [0u8; MAX_DESC_LEN],
            description_len: 0,
            state: GroupState::Unknown,
            owner_node: 0,
            preferred_owners: [0u32; MAX_NODES],
            preferred_owner_count: 0,
            failover_threshold: 10,
            failover_period: 6,
            auto_failback: 0,
            failback_start: 0,
            failback_end: 0,
            resources: [const { ClusterResource::new() }; MAX_RESOURCES],
            resource_count: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn add_resource(&mut self, resource: ClusterResource) -> Option<usize> {
        if self.resource_count >= MAX_RESOURCES {
            return None;
        }
        self.resources[self.resource_count] = resource;
        let idx = self.resource_count;
        self.resource_count += 1;
        Some(idx)
    }
}

// ============================================================================
// Cluster Network
// ============================================================================

/// Cluster network
#[derive(Clone, Copy)]
pub struct ClusterNetwork {
    /// Network in use
    pub in_use: bool,
    /// Network ID
    pub network_id: u32,
    /// Network name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub description_len: usize,
    /// Network role
    pub role: NetworkRole,
    /// Network address
    pub address: [u8; 4],
    /// Subnet mask
    pub subnet_mask: [u8; 4],
    /// State (0=unavailable, 1=down, 2=partitioned, 3=up)
    pub state: u8,
}

impl ClusterNetwork {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            network_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            description: [0u8; MAX_DESC_LEN],
            description_len: 0,
            role: NetworkRole::None,
            address: [0u8; 4],
            subnet_mask: [255, 255, 255, 0],
            state: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

// ============================================================================
// Cluster
// ============================================================================

/// Failover cluster
#[derive(Clone, Copy)]
pub struct Cluster {
    /// Cluster in use
    pub in_use: bool,
    /// Cluster ID
    pub cluster_id: u32,
    /// Cluster name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_DESC_LEN],
    /// Description length
    pub description_len: usize,
    /// Quorum type
    pub quorum_type: QuorumType,
    /// Quorum resource ID
    pub quorum_resource: u32,
    /// Quorum path
    pub quorum_path: [u8; 128],
    /// Quorum path length
    pub quorum_path_len: usize,
    /// Nodes
    pub nodes: [ClusterNode; MAX_NODES],
    /// Node count
    pub node_count: usize,
    /// Resource groups
    pub groups: [ResourceGroup; MAX_GROUPS],
    /// Group count
    pub group_count: usize,
    /// Networks
    pub networks: [ClusterNetwork; MAX_NETWORKS],
    /// Network count
    pub network_count: usize,
    /// Next resource ID
    pub next_resource_id: u32,
    /// Next group ID
    pub next_group_id: u32,
}

impl Cluster {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            cluster_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            description: [0u8; MAX_DESC_LEN],
            description_len: 0,
            quorum_type: QuorumType::SharedDisk,
            quorum_resource: 0,
            quorum_path: [0u8; 128],
            quorum_path_len: 0,
            nodes: [const { ClusterNode::new() }; MAX_NODES],
            node_count: 0,
            groups: [const { ResourceGroup::new() }; MAX_GROUPS],
            group_count: 0,
            networks: [const { ClusterNetwork::new() }; MAX_NETWORKS],
            network_count: 0,
            next_resource_id: 1,
            next_group_id: 1,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Add a node to the cluster
    pub fn add_node(&mut self, name: &[u8], ip: [u8; 4]) -> Option<usize> {
        if self.node_count >= MAX_NODES {
            return None;
        }
        let node = &mut self.nodes[self.node_count];
        node.in_use = true;
        node.node_id = self.node_count as u32 + 1;
        node.set_name(name);
        node.ip_address = ip;
        node.state = NodeState::Up;
        node.highest_version = 0x00050002; // 5.2
        node.lowest_version = 0x00050002;
        node.build_number = 3790;
        let idx = self.node_count;
        self.node_count += 1;
        Some(idx)
    }

    /// Add a resource group
    pub fn add_group(&mut self, name: &[u8]) -> Option<usize> {
        if self.group_count >= MAX_GROUPS {
            return None;
        }
        let group = &mut self.groups[self.group_count];
        group.in_use = true;
        group.group_id = self.next_group_id;
        self.next_group_id += 1;
        group.set_name(name);
        group.state = GroupState::Offline;
        if self.node_count > 0 {
            group.owner_node = self.nodes[0].node_id;
        }
        let idx = self.group_count;
        self.group_count += 1;
        Some(idx)
    }

    /// Add a network
    pub fn add_network(&mut self, name: &[u8], address: [u8; 4], mask: [u8; 4]) -> Option<usize> {
        if self.network_count >= MAX_NETWORKS {
            return None;
        }
        let net = &mut self.networks[self.network_count];
        net.in_use = true;
        net.network_id = self.network_count as u32 + 1;
        net.set_name(name);
        net.address = address;
        net.subnet_mask = mask;
        net.role = NetworkRole::All;
        net.state = 3; // Up
        let idx = self.network_count;
        self.network_count += 1;
        Some(idx)
    }
}

// ============================================================================
// Manager State
// ============================================================================

/// Cluster Administrator state
struct ClusterAdminState {
    /// Clusters
    clusters: [Cluster; MAX_CLUSTERS],
    /// Cluster count
    cluster_count: usize,
    /// Selected cluster
    selected_cluster: Option<usize>,
    /// Selected node
    selected_node: Option<usize>,
    /// Selected group
    selected_group: Option<usize>,
    /// Dialog handle
    dialog_handle: HWND,
    /// View mode (0=tree, 1=details)
    view_mode: u8,
    /// Next cluster ID
    next_cluster_id: u32,
}

impl ClusterAdminState {
    pub const fn new() -> Self {
        Self {
            clusters: [const { Cluster::new() }; MAX_CLUSTERS],
            cluster_count: 0,
            selected_cluster: None,
            selected_node: None,
            selected_group: None,
            dialog_handle: UserHandle::from_raw(0),
            view_mode: 0,
            next_cluster_id: 1,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static CLUSTER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static CLUSTER_MANAGER: SpinLock<ClusterAdminState> = SpinLock::new(ClusterAdminState::new());

// Statistics
static CLUSTER_COUNT: AtomicU32 = AtomicU32::new(0);
static NODE_COUNT: AtomicU32 = AtomicU32::new(0);
static GROUP_COUNT: AtomicU32 = AtomicU32::new(0);
static FAILOVER_COUNT: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Cluster Administrator
pub fn init() {
    if CLUSTER_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }
    // No default cluster - clusters must be created or connected to
}

// ============================================================================
// Cluster Management
// ============================================================================

/// Create a new cluster
pub fn create_cluster(name: &[u8]) -> Option<usize> {
    let mut state = CLUSTER_MANAGER.lock();

    if state.cluster_count >= MAX_CLUSTERS {
        return None;
    }

    let cluster_id = state.next_cluster_id;
    state.next_cluster_id += 1;

    let idx = state.cluster_count;
    let cluster = &mut state.clusters[idx];
    cluster.in_use = true;
    cluster.cluster_id = cluster_id;
    cluster.set_name(name);

    state.cluster_count += 1;
    CLUSTER_COUNT.fetch_add(1, Ordering::Relaxed);

    Some(idx)
}

/// Connect to an existing cluster
pub fn open_cluster(name: &[u8]) -> Option<usize> {
    let state = CLUSTER_MANAGER.lock();

    for (i, cluster) in state.clusters.iter().enumerate() {
        if cluster.in_use && cluster.name[..cluster.name_len] == name[..name.len().min(cluster.name_len)] {
            return Some(i);
        }
    }
    None
}

/// Get cluster by index
pub fn get_cluster(index: usize) -> Option<Cluster> {
    let state = CLUSTER_MANAGER.lock();
    if index < state.cluster_count && state.clusters[index].in_use {
        Some(state.clusters[index])
    } else {
        None
    }
}

/// Delete a cluster
pub fn delete_cluster(index: usize) -> bool {
    let mut state = CLUSTER_MANAGER.lock();

    if index >= MAX_CLUSTERS || !state.clusters[index].in_use {
        return false;
    }

    state.clusters[index] = Cluster::new();
    state.cluster_count = state.cluster_count.saturating_sub(1);
    CLUSTER_COUNT.fetch_sub(1, Ordering::Relaxed);

    true
}

// ============================================================================
// Node Management
// ============================================================================

/// Add a node to cluster
pub fn add_node(cluster_index: usize, name: &[u8], ip: [u8; 4]) -> Option<usize> {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return None;
    }

    let result = state.clusters[cluster_index].add_node(name, ip);
    if result.is_some() {
        NODE_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Evict a node from cluster
pub fn evict_node(cluster_index: usize, node_index: usize) -> bool {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if node_index >= cluster.node_count || !cluster.nodes[node_index].in_use {
        return false;
    }

    cluster.nodes[node_index] = ClusterNode::new();
    NODE_COUNT.fetch_sub(1, Ordering::Relaxed);

    true
}

/// Pause a node
pub fn pause_node(cluster_index: usize, node_index: usize) -> bool {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if node_index >= cluster.node_count || !cluster.nodes[node_index].in_use {
        return false;
    }

    if cluster.nodes[node_index].state == NodeState::Up {
        cluster.nodes[node_index].state = NodeState::Paused;
        return true;
    }
    false
}

/// Resume a paused node
pub fn resume_node(cluster_index: usize, node_index: usize) -> bool {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if node_index >= cluster.node_count || !cluster.nodes[node_index].in_use {
        return false;
    }

    if cluster.nodes[node_index].state == NodeState::Paused {
        cluster.nodes[node_index].state = NodeState::Up;
        return true;
    }
    false
}

/// Get node state
pub fn get_node_state(cluster_index: usize, node_index: usize) -> Option<NodeState> {
    let state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return None;
    }

    let cluster = &state.clusters[cluster_index];
    if node_index >= cluster.node_count || !cluster.nodes[node_index].in_use {
        return None;
    }

    Some(cluster.nodes[node_index].state)
}

// ============================================================================
// Resource Group Management
// ============================================================================

/// Create a resource group
pub fn create_group(cluster_index: usize, name: &[u8]) -> Option<usize> {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return None;
    }

    let result = state.clusters[cluster_index].add_group(name);
    if result.is_some() {
        GROUP_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Delete a resource group
pub fn delete_group(cluster_index: usize, group_index: usize) -> bool {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if group_index >= cluster.group_count || !cluster.groups[group_index].in_use {
        return false;
    }

    cluster.groups[group_index] = ResourceGroup::new();
    GROUP_COUNT.fetch_sub(1, Ordering::Relaxed);

    true
}

/// Bring a group online
pub fn online_group(cluster_index: usize, group_index: usize) -> bool {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if group_index >= cluster.group_count || !cluster.groups[group_index].in_use {
        return false;
    }

    let group = &mut cluster.groups[group_index];
    if group.state == GroupState::Offline {
        group.state = GroupState::Online;
        // Bring all resources online
        for i in 0..group.resource_count {
            if group.resources[i].in_use {
                group.resources[i].state = ResourceState::Online;
            }
        }
        return true;
    }
    false
}

/// Take a group offline
pub fn offline_group(cluster_index: usize, group_index: usize) -> bool {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if group_index >= cluster.group_count || !cluster.groups[group_index].in_use {
        return false;
    }

    let group = &mut cluster.groups[group_index];
    if group.state == GroupState::Online {
        group.state = GroupState::Offline;
        // Take all resources offline
        for i in 0..group.resource_count {
            if group.resources[i].in_use {
                group.resources[i].state = ResourceState::Offline;
            }
        }
        return true;
    }
    false
}

/// Move a group to another node
pub fn move_group(cluster_index: usize, group_index: usize, target_node: u32) -> bool {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if group_index >= cluster.group_count || !cluster.groups[group_index].in_use {
        return false;
    }

    // Verify target node exists and is up
    let mut target_valid = false;
    for node in cluster.nodes.iter() {
        if node.in_use && node.node_id == target_node && node.state == NodeState::Up {
            target_valid = true;
            break;
        }
    }

    if !target_valid {
        return false;
    }

    cluster.groups[group_index].owner_node = target_node;
    FAILOVER_COUNT.fetch_add(1, Ordering::Relaxed);

    true
}

// ============================================================================
// Resource Management
// ============================================================================

/// Add a resource to a group
pub fn add_resource(
    cluster_index: usize,
    group_index: usize,
    name: &[u8],
    resource_type: ResourceType,
) -> Option<usize> {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return None;
    }

    let cluster = &mut state.clusters[cluster_index];
    if group_index >= cluster.group_count || !cluster.groups[group_index].in_use {
        return None;
    }

    let resource_id = cluster.next_resource_id;
    cluster.next_resource_id += 1;

    let group = &mut cluster.groups[group_index];
    if group.resource_count >= MAX_RESOURCES {
        return None;
    }

    let resource = &mut group.resources[group.resource_count];
    resource.in_use = true;
    resource.resource_id = resource_id;
    resource.set_name(name);
    resource.resource_type = resource_type;
    resource.state = ResourceState::Offline;
    resource.owner_node = group.owner_node;

    let idx = group.resource_count;
    group.resource_count += 1;

    Some(idx)
}

/// Remove a resource from a group
pub fn remove_resource(cluster_index: usize, group_index: usize, resource_index: usize) -> bool {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if group_index >= cluster.group_count || !cluster.groups[group_index].in_use {
        return false;
    }

    let group = &mut cluster.groups[group_index];
    if resource_index >= group.resource_count || !group.resources[resource_index].in_use {
        return false;
    }

    group.resources[resource_index] = ClusterResource::new();
    true
}

/// Bring a resource online
pub fn online_resource(cluster_index: usize, group_index: usize, resource_index: usize) -> bool {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if group_index >= cluster.group_count || !cluster.groups[group_index].in_use {
        return false;
    }

    let group = &mut cluster.groups[group_index];
    if resource_index >= group.resource_count || !group.resources[resource_index].in_use {
        return false;
    }

    if group.resources[resource_index].state == ResourceState::Offline {
        group.resources[resource_index].state = ResourceState::Online;
        return true;
    }
    false
}

/// Take a resource offline
pub fn offline_resource(cluster_index: usize, group_index: usize, resource_index: usize) -> bool {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if group_index >= cluster.group_count || !cluster.groups[group_index].in_use {
        return false;
    }

    let group = &mut cluster.groups[group_index];
    if resource_index >= group.resource_count || !group.resources[resource_index].in_use {
        return false;
    }

    if group.resources[resource_index].state == ResourceState::Online {
        group.resources[resource_index].state = ResourceState::Offline;
        return true;
    }
    false
}

// ============================================================================
// Quorum Configuration
// ============================================================================

/// Set quorum configuration
pub fn set_quorum(
    cluster_index: usize,
    quorum_type: QuorumType,
    resource_id: u32,
    path: &[u8],
) -> bool {
    let mut state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    cluster.quorum_type = quorum_type;
    cluster.quorum_resource = resource_id;

    let path_len = path.len().min(128);
    cluster.quorum_path[..path_len].copy_from_slice(&path[..path_len]);
    cluster.quorum_path_len = path_len;

    true
}

/// Get quorum configuration
pub fn get_quorum(cluster_index: usize) -> Option<(QuorumType, u32)> {
    let state = CLUSTER_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return None;
    }

    let cluster = &state.clusters[cluster_index];
    Some((cluster.quorum_type, cluster.quorum_resource))
}

// ============================================================================
// Statistics
// ============================================================================

/// Get cluster statistics
pub fn get_statistics() -> (u32, u32, u32, u64) {
    (
        CLUSTER_COUNT.load(Ordering::Relaxed),
        NODE_COUNT.load(Ordering::Relaxed),
        GROUP_COUNT.load(Ordering::Relaxed),
        FAILOVER_COUNT.load(Ordering::Relaxed),
    )
}

// ============================================================================
// Dialog Functions
// ============================================================================

/// Show Cluster Administrator main window
pub fn show_dialog(_parent: HWND) -> HWND {
    let mut state = CLUSTER_MANAGER.lock();
    let handle = UserHandle::from_raw(0xCA01);
    state.dialog_handle = handle;
    handle
}

/// Show new cluster wizard
pub fn show_new_cluster_wizard() -> HWND {
    UserHandle::from_raw(0xCA02)
}

/// Show cluster properties
pub fn show_cluster_properties(_cluster_index: usize) -> HWND {
    UserHandle::from_raw(0xCA03)
}

/// Show add node wizard
pub fn show_add_node_wizard() -> HWND {
    UserHandle::from_raw(0xCA04)
}

/// Show node properties
pub fn show_node_properties(_cluster_index: usize, _node_index: usize) -> HWND {
    UserHandle::from_raw(0xCA05)
}

/// Show new group wizard
pub fn show_new_group_wizard() -> HWND {
    UserHandle::from_raw(0xCA06)
}

/// Show group properties
pub fn show_group_properties(_cluster_index: usize, _group_index: usize) -> HWND {
    UserHandle::from_raw(0xCA07)
}

/// Show new resource wizard
pub fn show_new_resource_wizard() -> HWND {
    UserHandle::from_raw(0xCA08)
}

/// Show resource properties
pub fn show_resource_properties(_cluster_index: usize, _group_index: usize, _resource_index: usize) -> HWND {
    UserHandle::from_raw(0xCA09)
}

/// Close dialog
pub fn close_dialog() {
    let mut state = CLUSTER_MANAGER.lock();
    state.dialog_handle = UserHandle::from_raw(0);
}
