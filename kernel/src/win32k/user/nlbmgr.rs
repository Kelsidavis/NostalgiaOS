//! Network Load Balancing Manager
//!
//! Windows Server 2003 NLB Manager snap-in implementation.
//! Provides network load balancing cluster configuration.
//!
//! # Features
//!
//! - NLB cluster creation and management
//! - Host parameters configuration
//! - Port rules for load balancing
//! - Affinity settings
//! - Cluster operations (start, stop, drainstop)
//!
//! # References
//!
//! Based on Windows Server 2003 NLB Manager (nlbmgr.exe)

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::UserHandle;
use bitflags::bitflags;

/// HWND type alias
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum NLB clusters
const MAX_CLUSTERS: usize = 8;

/// Maximum hosts per cluster
const MAX_HOSTS: usize = 32;

/// Maximum port rules per cluster
const MAX_PORT_RULES: usize = 16;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

// ============================================================================
// Cluster Operation Mode
// ============================================================================

/// NLB cluster operation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ClusterMode {
    /// Unicast mode
    #[default]
    Unicast = 0,
    /// Multicast mode
    Multicast = 1,
    /// IGMP multicast
    IgmpMulticast = 2,
}

impl ClusterMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unicast => "Unicast",
            Self::Multicast => "Multicast",
            Self::IgmpMulticast => "IGMP Multicast",
        }
    }
}

// ============================================================================
// Host State
// ============================================================================

/// NLB host state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum HostState {
    /// Host state unknown
    #[default]
    Unknown = 0,
    /// Host is converged (operational)
    Converged = 1,
    /// Host is converging
    Converging = 2,
    /// Host is stopped
    Stopped = 3,
    /// Host is draining
    Draining = 4,
    /// Host is suspended
    Suspended = 5,
}

impl HostState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Converged => "Converged",
            Self::Converging => "Converging",
            Self::Stopped => "Stopped",
            Self::Draining => "Draining",
            Self::Suspended => "Suspended",
        }
    }
}

// ============================================================================
// Filtering Mode
// ============================================================================

/// Port rule filtering mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum FilteringMode {
    /// Multiple hosts handle traffic
    #[default]
    Multiple = 0,
    /// Single host handles all traffic
    Single = 1,
    /// Disabled (no traffic accepted)
    Disabled = 2,
}

impl FilteringMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Multiple => "Multiple Hosts",
            Self::Single => "Single Host",
            Self::Disabled => "Disabled",
        }
    }
}

// ============================================================================
// Affinity Mode
// ============================================================================

/// Client affinity mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum AffinityMode {
    /// No affinity
    None = 0,
    /// Single client affinity (Class C)
    #[default]
    Single = 1,
    /// Network affinity (Class C network)
    Network = 2,
}

impl AffinityMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Single => "Single",
            Self::Network => "Network (Class C)",
        }
    }
}

// ============================================================================
// Protocol
// ============================================================================

/// Port rule protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Protocol {
    /// TCP and UDP
    #[default]
    Both = 0,
    /// TCP only
    Tcp = 1,
    /// UDP only
    Udp = 2,
}

impl Protocol {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Both => "Both",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

bitflags! {
    /// NLB cluster options
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ClusterOptions: u32 {
        /// Remote control enabled
        const REMOTE_CONTROL = 0x0001;
        /// BDA team mode
        const BDA_TEAM = 0x0002;
        /// Remove packets handled by port rules
        const REMOVE_VLAN_TAG = 0x0004;
    }
}

// ============================================================================
// Port Rule
// ============================================================================

/// NLB port rule
#[derive(Clone, Copy)]
pub struct PortRule {
    /// Rule in use
    pub in_use: bool,
    /// Start port
    pub start_port: u16,
    /// End port
    pub end_port: u16,
    /// Protocol
    pub protocol: Protocol,
    /// Filtering mode
    pub filtering_mode: FilteringMode,
    /// Affinity mode
    pub affinity: AffinityMode,
    /// Load weight (for multiple host mode)
    pub load_weight: u32,
    /// Handle priority (for single host mode)
    pub handling_priority: u32,
    /// Equal load distribution (ignored if load_weight set)
    pub equal_load: bool,
}

impl PortRule {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            start_port: 0,
            end_port: 65535,
            protocol: Protocol::Both,
            filtering_mode: FilteringMode::Multiple,
            affinity: AffinityMode::Single,
            load_weight: 50,
            handling_priority: 1,
            equal_load: true,
        }
    }
}

// ============================================================================
// NLB Host
// ============================================================================

/// NLB cluster host
#[derive(Clone, Copy)]
pub struct NlbHost {
    /// Host in use
    pub in_use: bool,
    /// Host priority (unique ID 1-32)
    pub priority: u8,
    /// Hostname
    pub hostname: [u8; MAX_NAME_LEN],
    /// Hostname length
    pub hostname_len: usize,
    /// Dedicated IP address
    pub dedicated_ip: [u8; 4],
    /// Dedicated IP subnet mask
    pub dedicated_mask: [u8; 4],
    /// Host state
    pub state: HostState,
    /// Initial host state (0=started, 1=stopped, 2=suspended)
    pub initial_state: u8,
    /// Port rules (overrides cluster defaults)
    pub port_rules: [PortRule; MAX_PORT_RULES],
    /// Port rule count
    pub port_rule_count: usize,
    /// Connections handled
    pub connections: u64,
    /// Bytes transferred
    pub bytes_transferred: u64,
}

impl NlbHost {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            priority: 0,
            hostname: [0u8; MAX_NAME_LEN],
            hostname_len: 0,
            dedicated_ip: [0u8; 4],
            dedicated_mask: [255, 255, 255, 0],
            state: HostState::Unknown,
            initial_state: 0,
            port_rules: [const { PortRule::new() }; MAX_PORT_RULES],
            port_rule_count: 0,
            connections: 0,
            bytes_transferred: 0,
        }
    }

    pub fn set_hostname(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.hostname[..len].copy_from_slice(&name[..len]);
        self.hostname_len = len;
    }
}

// ============================================================================
// NLB Cluster
// ============================================================================

/// NLB cluster
#[derive(Clone, Copy)]
pub struct NlbCluster {
    /// Cluster in use
    pub in_use: bool,
    /// Cluster name (fully qualified domain name)
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Cluster IP address (virtual IP)
    pub cluster_ip: [u8; 4],
    /// Cluster subnet mask
    pub cluster_mask: [u8; 4],
    /// Cluster MAC address
    pub cluster_mac: [u8; 6],
    /// Operation mode
    pub mode: ClusterMode,
    /// Cluster options
    pub options: ClusterOptions,
    /// Remote control password hash
    pub remote_password_hash: u32,
    /// Default port rules
    pub port_rules: [PortRule; MAX_PORT_RULES],
    /// Port rule count
    pub port_rule_count: usize,
    /// Hosts in cluster
    pub hosts: [NlbHost; MAX_HOSTS],
    /// Host count
    pub host_count: usize,
    /// Next host priority
    pub next_priority: u8,
}

impl NlbCluster {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            cluster_ip: [0u8; 4],
            cluster_mask: [255, 255, 255, 0],
            cluster_mac: [0u8; 6],
            mode: ClusterMode::Unicast,
            options: ClusterOptions::empty(),
            remote_password_hash: 0,
            port_rules: [const { PortRule::new() }; MAX_PORT_RULES],
            port_rule_count: 0,
            hosts: [const { NlbHost::new() }; MAX_HOSTS],
            host_count: 0,
            next_priority: 1,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Add a default port rule
    pub fn add_port_rule(&mut self, start: u16, end: u16, protocol: Protocol, mode: FilteringMode) -> Option<usize> {
        if self.port_rule_count >= MAX_PORT_RULES {
            return None;
        }

        let rule = &mut self.port_rules[self.port_rule_count];
        rule.in_use = true;
        rule.start_port = start;
        rule.end_port = end;
        rule.protocol = protocol;
        rule.filtering_mode = mode;

        let idx = self.port_rule_count;
        self.port_rule_count += 1;
        Some(idx)
    }

    /// Add a host to the cluster
    pub fn add_host(&mut self, hostname: &[u8], dedicated_ip: [u8; 4]) -> Option<usize> {
        if self.host_count >= MAX_HOSTS || self.next_priority > 32 {
            return None;
        }

        let host = &mut self.hosts[self.host_count];
        host.in_use = true;
        host.priority = self.next_priority;
        self.next_priority += 1;
        host.set_hostname(hostname);
        host.dedicated_ip = dedicated_ip;
        host.state = HostState::Stopped;

        let idx = self.host_count;
        self.host_count += 1;
        Some(idx)
    }

    /// Generate cluster MAC address from IP
    pub fn generate_mac(&mut self) {
        // Standard NLB MAC prefix: 02-bf for unicast, 03-bf for multicast
        let prefix = match self.mode {
            ClusterMode::Unicast => 0x02,
            ClusterMode::Multicast | ClusterMode::IgmpMulticast => 0x03,
        };

        self.cluster_mac[0] = prefix;
        self.cluster_mac[1] = 0xbf;
        // Last 4 bytes are cluster IP
        self.cluster_mac[2] = self.cluster_ip[0];
        self.cluster_mac[3] = self.cluster_ip[1];
        self.cluster_mac[4] = self.cluster_ip[2];
        self.cluster_mac[5] = self.cluster_ip[3];
    }
}

// ============================================================================
// Manager State
// ============================================================================

/// NLB Manager state
struct NlbManagerState {
    /// Clusters
    clusters: [NlbCluster; MAX_CLUSTERS],
    /// Cluster count
    cluster_count: usize,
    /// Selected cluster
    selected_cluster: Option<usize>,
    /// Selected host
    selected_host: Option<usize>,
    /// Dialog handle
    dialog_handle: HWND,
    /// Log entries (circular buffer index)
    log_index: usize,
}

impl NlbManagerState {
    pub const fn new() -> Self {
        Self {
            clusters: [const { NlbCluster::new() }; MAX_CLUSTERS],
            cluster_count: 0,
            selected_cluster: None,
            selected_host: None,
            dialog_handle: UserHandle::from_raw(0),
            log_index: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static NLB_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NLB_MANAGER: SpinLock<NlbManagerState> = SpinLock::new(NlbManagerState::new());

// Statistics
static CLUSTER_COUNT: AtomicU32 = AtomicU32::new(0);
static HOST_COUNT: AtomicU32 = AtomicU32::new(0);
static CONVERGENCE_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize NLB Manager
pub fn init() {
    if NLB_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }
    // No default clusters - clusters must be created or connected
}

// ============================================================================
// Cluster Management
// ============================================================================

/// Create a new NLB cluster
pub fn create_cluster(
    name: &[u8],
    cluster_ip: [u8; 4],
    cluster_mask: [u8; 4],
    mode: ClusterMode,
) -> Option<usize> {
    let mut state = NLB_MANAGER.lock();

    if state.cluster_count >= MAX_CLUSTERS {
        return None;
    }

    let idx = state.cluster_count;
    let cluster = &mut state.clusters[idx];
    cluster.in_use = true;
    cluster.set_name(name);
    cluster.cluster_ip = cluster_ip;
    cluster.cluster_mask = cluster_mask;
    cluster.mode = mode;
    cluster.generate_mac();

    // Add default port rule for all ports
    cluster.add_port_rule(0, 65535, Protocol::Both, FilteringMode::Multiple);

    state.cluster_count += 1;
    CLUSTER_COUNT.fetch_add(1, Ordering::Relaxed);

    Some(idx)
}

/// Connect to existing cluster
pub fn connect_cluster(name: &[u8]) -> Option<usize> {
    let state = NLB_MANAGER.lock();

    for (i, cluster) in state.clusters.iter().enumerate() {
        if cluster.in_use && cluster.name[..cluster.name_len] == name[..name.len().min(cluster.name_len)] {
            return Some(i);
        }
    }
    None
}

/// Get cluster by index
pub fn get_cluster(index: usize) -> Option<NlbCluster> {
    let state = NLB_MANAGER.lock();
    if index < state.cluster_count && state.clusters[index].in_use {
        Some(state.clusters[index])
    } else {
        None
    }
}

/// Delete a cluster
pub fn delete_cluster(index: usize) -> bool {
    let mut state = NLB_MANAGER.lock();

    if index >= MAX_CLUSTERS || !state.clusters[index].in_use {
        return false;
    }

    let host_count = state.clusters[index].host_count;
    state.clusters[index] = NlbCluster::new();
    state.cluster_count = state.cluster_count.saturating_sub(1);

    CLUSTER_COUNT.fetch_sub(1, Ordering::Relaxed);
    HOST_COUNT.fetch_sub(host_count as u32, Ordering::Relaxed);

    true
}

/// Set cluster mode
pub fn set_cluster_mode(cluster_index: usize, mode: ClusterMode) -> bool {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    state.clusters[cluster_index].mode = mode;
    state.clusters[cluster_index].generate_mac();
    true
}

// ============================================================================
// Host Management
// ============================================================================

/// Add a host to cluster
pub fn add_host(cluster_index: usize, hostname: &[u8], dedicated_ip: [u8; 4]) -> Option<usize> {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return None;
    }

    let result = state.clusters[cluster_index].add_host(hostname, dedicated_ip);
    if result.is_some() {
        HOST_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Remove a host from cluster
pub fn remove_host(cluster_index: usize, host_index: usize) -> bool {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if host_index >= cluster.host_count || !cluster.hosts[host_index].in_use {
        return false;
    }

    cluster.hosts[host_index] = NlbHost::new();
    HOST_COUNT.fetch_sub(1, Ordering::Relaxed);

    true
}

/// Get host state
pub fn get_host_state(cluster_index: usize, host_index: usize) -> Option<HostState> {
    let state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return None;
    }

    let cluster = &state.clusters[cluster_index];
    if host_index >= cluster.host_count || !cluster.hosts[host_index].in_use {
        return None;
    }

    Some(cluster.hosts[host_index].state)
}

// ============================================================================
// Host Operations
// ============================================================================

/// Start a host
pub fn start_host(cluster_index: usize, host_index: usize) -> bool {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if host_index >= cluster.host_count || !cluster.hosts[host_index].in_use {
        return false;
    }

    let host = &mut cluster.hosts[host_index];
    if host.state == HostState::Stopped || host.state == HostState::Suspended {
        host.state = HostState::Converging;
        // In real implementation, would trigger convergence
        host.state = HostState::Converged;
        CONVERGENCE_COUNT.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}

/// Stop a host
pub fn stop_host(cluster_index: usize, host_index: usize) -> bool {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if host_index >= cluster.host_count || !cluster.hosts[host_index].in_use {
        return false;
    }

    let host = &mut cluster.hosts[host_index];
    if host.state == HostState::Converged || host.state == HostState::Converging {
        host.state = HostState::Stopped;
        return true;
    }
    false
}

/// Drain stop a host (finish existing connections then stop)
pub fn drainstop_host(cluster_index: usize, host_index: usize) -> bool {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if host_index >= cluster.host_count || !cluster.hosts[host_index].in_use {
        return false;
    }

    let host = &mut cluster.hosts[host_index];
    if host.state == HostState::Converged {
        host.state = HostState::Draining;
        // In real implementation, would wait for connections to finish
        return true;
    }
    false
}

/// Suspend a host
pub fn suspend_host(cluster_index: usize, host_index: usize) -> bool {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if host_index >= cluster.host_count || !cluster.hosts[host_index].in_use {
        return false;
    }

    let host = &mut cluster.hosts[host_index];
    if host.state == HostState::Converged {
        host.state = HostState::Suspended;
        return true;
    }
    false
}

/// Resume a suspended host
pub fn resume_host(cluster_index: usize, host_index: usize) -> bool {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if host_index >= cluster.host_count || !cluster.hosts[host_index].in_use {
        return false;
    }

    let host = &mut cluster.hosts[host_index];
    if host.state == HostState::Suspended {
        host.state = HostState::Converging;
        host.state = HostState::Converged;
        CONVERGENCE_COUNT.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}

// ============================================================================
// Cluster Operations
// ============================================================================

/// Start all hosts in cluster
pub fn start_cluster(cluster_index: usize) -> bool {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    let mut started = 0u32;

    for i in 0..cluster.host_count {
        if cluster.hosts[i].in_use {
            let host = &mut cluster.hosts[i];
            if host.state == HostState::Stopped || host.state == HostState::Suspended {
                host.state = HostState::Converged;
                started += 1;
            }
        }
    }

    if started > 0 {
        CONVERGENCE_COUNT.fetch_add(started, Ordering::Relaxed);
    }
    true
}

/// Stop all hosts in cluster
pub fn stop_cluster(cluster_index: usize) -> bool {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];

    for i in 0..cluster.host_count {
        if cluster.hosts[i].in_use {
            cluster.hosts[i].state = HostState::Stopped;
        }
    }
    true
}

/// Drain stop all hosts in cluster
pub fn drainstop_cluster(cluster_index: usize) -> bool {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];

    for i in 0..cluster.host_count {
        if cluster.hosts[i].in_use && cluster.hosts[i].state == HostState::Converged {
            cluster.hosts[i].state = HostState::Draining;
        }
    }
    true
}

// ============================================================================
// Port Rule Management
// ============================================================================

/// Add a port rule to cluster
pub fn add_port_rule(
    cluster_index: usize,
    start_port: u16,
    end_port: u16,
    protocol: Protocol,
    filtering_mode: FilteringMode,
    affinity: AffinityMode,
) -> Option<usize> {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return None;
    }

    let cluster = &mut state.clusters[cluster_index];
    if cluster.port_rule_count >= MAX_PORT_RULES {
        return None;
    }

    let rule = &mut cluster.port_rules[cluster.port_rule_count];
    rule.in_use = true;
    rule.start_port = start_port;
    rule.end_port = end_port;
    rule.protocol = protocol;
    rule.filtering_mode = filtering_mode;
    rule.affinity = affinity;

    let idx = cluster.port_rule_count;
    cluster.port_rule_count += 1;
    Some(idx)
}

/// Remove a port rule
pub fn remove_port_rule(cluster_index: usize, rule_index: usize) -> bool {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if rule_index >= cluster.port_rule_count || !cluster.port_rules[rule_index].in_use {
        return false;
    }

    cluster.port_rules[rule_index] = PortRule::new();
    true
}

/// Set port rule load weight
pub fn set_rule_load_weight(
    cluster_index: usize,
    rule_index: usize,
    weight: u32,
) -> bool {
    let mut state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return false;
    }

    let cluster = &mut state.clusters[cluster_index];
    if rule_index >= cluster.port_rule_count || !cluster.port_rules[rule_index].in_use {
        return false;
    }

    cluster.port_rules[rule_index].load_weight = weight;
    cluster.port_rules[rule_index].equal_load = false;
    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Get NLB statistics
pub fn get_statistics() -> (u32, u32, u32) {
    (
        CLUSTER_COUNT.load(Ordering::Relaxed),
        HOST_COUNT.load(Ordering::Relaxed),
        CONVERGENCE_COUNT.load(Ordering::Relaxed),
    )
}

/// Get host statistics
pub fn get_host_statistics(cluster_index: usize, host_index: usize) -> Option<(u64, u64)> {
    let state = NLB_MANAGER.lock();

    if cluster_index >= MAX_CLUSTERS || !state.clusters[cluster_index].in_use {
        return None;
    }

    let cluster = &state.clusters[cluster_index];
    if host_index >= cluster.host_count || !cluster.hosts[host_index].in_use {
        return None;
    }

    let host = &cluster.hosts[host_index];
    Some((host.connections, host.bytes_transferred))
}

// ============================================================================
// Dialog Functions
// ============================================================================

/// Show NLB Manager main window
pub fn show_dialog(_parent: HWND) -> HWND {
    let mut state = NLB_MANAGER.lock();
    let handle = UserHandle::from_raw(0x4E01);
    state.dialog_handle = handle;
    handle
}

/// Show new cluster wizard
pub fn show_new_cluster_wizard() -> HWND {
    UserHandle::from_raw(0x4E02)
}

/// Show cluster properties
pub fn show_cluster_properties(_cluster_index: usize) -> HWND {
    UserHandle::from_raw(0x4E03)
}

/// Show add host wizard
pub fn show_add_host_wizard() -> HWND {
    UserHandle::from_raw(0x4E04)
}

/// Show host properties
pub fn show_host_properties(_cluster_index: usize, _host_index: usize) -> HWND {
    UserHandle::from_raw(0x4E05)
}

/// Show port rule properties
pub fn show_port_rule_properties(_cluster_index: usize, _rule_index: usize) -> HWND {
    UserHandle::from_raw(0x4E06)
}

/// Close dialog
pub fn close_dialog() {
    let mut state = NLB_MANAGER.lock();
    state.dialog_handle = UserHandle::from_raw(0);
}
