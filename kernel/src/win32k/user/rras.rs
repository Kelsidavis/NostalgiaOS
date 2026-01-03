//! Routing and Remote Access Service (RRAS)
//!
//! Windows Server 2003 Routing and Remote Access snap-in implementation.
//! Provides VPN, dial-up, and IP routing configuration.
//!
//! # Features
//!
//! - Remote access (VPN, dial-up)
//! - IP routing protocols (RIP, OSPF, static routes)
//! - NAT/Basic Firewall
//! - RADIUS integration
//! - Remote access policies
//!
//! # References
//!
//! Based on Windows Server 2003 RRAS snap-in

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::UserHandle;

/// HWND type alias
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum interfaces
const MAX_INTERFACES: usize = 32;

/// Maximum static routes
const MAX_ROUTES: usize = 128;

/// Maximum VPN clients
const MAX_CLIENTS: usize = 64;

/// Maximum remote access policies
const MAX_POLICIES: usize = 16;

/// Maximum IP pools
const MAX_IP_POOLS: usize = 8;

/// Maximum name length
const MAX_NAME_LEN: usize = 64;

/// Maximum description length
const MAX_DESC_LEN: usize = 256;

// ============================================================================
// Service State
// ============================================================================

/// RRAS service state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServiceState {
    /// Service is not configured
    #[default]
    NotConfigured = 0,
    /// Service is stopped
    Stopped = 1,
    /// Service is starting
    Starting = 2,
    /// Service is running
    Running = 3,
    /// Service is stopping
    Stopping = 4,
}

impl ServiceState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotConfigured => "Not Configured",
            Self::Stopped => "Stopped",
            Self::Starting => "Starting",
            Self::Running => "Running",
            Self::Stopping => "Stopping",
        }
    }
}

// ============================================================================
// Interface Types
// ============================================================================

/// Interface type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterfaceType {
    /// Loopback interface
    #[default]
    Loopback = 0,
    /// LAN interface (Ethernet)
    Lan = 1,
    /// Demand-dial interface
    DemandDial = 2,
    /// PPTP tunnel
    PptpTunnel = 3,
    /// L2TP tunnel
    L2tpTunnel = 4,
    /// Internal interface
    Internal = 5,
}

impl InterfaceType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Loopback => "Loopback",
            Self::Lan => "LAN",
            Self::DemandDial => "Demand-Dial",
            Self::PptpTunnel => "PPTP",
            Self::L2tpTunnel => "L2TP",
            Self::Internal => "Internal",
        }
    }
}

/// Interface state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterfaceState {
    /// Interface is disabled
    #[default]
    Disabled = 0,
    /// Interface is disconnected
    Disconnected = 1,
    /// Interface is connecting
    Connecting = 2,
    /// Interface is connected
    Connected = 3,
}

impl InterfaceState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "Disabled",
            Self::Disconnected => "Disconnected",
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
        }
    }
}

// ============================================================================
// VPN Protocol Types
// ============================================================================

/// VPN protocol type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VpnProtocol {
    /// PPTP (Point-to-Point Tunneling Protocol)
    #[default]
    Pptp = 0,
    /// L2TP (Layer 2 Tunneling Protocol)
    L2tp = 1,
    /// L2TP with IPsec
    L2tpIpsec = 2,
    /// IKEv2
    Ikev2 = 3,
    /// SSTP (Secure Socket Tunneling Protocol)
    Sstp = 4,
}

impl VpnProtocol {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pptp => "PPTP",
            Self::L2tp => "L2TP",
            Self::L2tpIpsec => "L2TP/IPsec",
            Self::Ikev2 => "IKEv2",
            Self::Sstp => "SSTP",
        }
    }
}

// ============================================================================
// Authentication Methods
// ============================================================================

bitflags::bitflags! {
    /// Authentication methods
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct AuthMethods: u32 {
        /// MS-CHAP v2
        const MSCHAP_V2 = 0x0001;
        /// MS-CHAP
        const MSCHAP = 0x0002;
        /// CHAP
        const CHAP = 0x0004;
        /// SPAP
        const SPAP = 0x0008;
        /// PAP
        const PAP = 0x0010;
        /// EAP
        const EAP = 0x0020;
        /// Certificate (EAP-TLS)
        const CERTIFICATE = 0x0040;
        /// Smart card
        const SMART_CARD = 0x0080;
    }
}

// ============================================================================
// Encryption Levels
// ============================================================================

bitflags::bitflags! {
    /// Encryption levels
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct EncryptionLevels: u32 {
        /// No encryption allowed
        const NONE = 0x0001;
        /// Basic (40-bit)
        const BASIC = 0x0002;
        /// Strong (56-bit)
        const STRONG = 0x0004;
        /// Strongest (128-bit)
        const STRONGEST = 0x0008;
    }
}

// ============================================================================
// Routing Protocol
// ============================================================================

/// Routing protocol
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoutingProtocol {
    /// Static routing
    #[default]
    Static = 0,
    /// RIP version 2
    RipV2 = 1,
    /// OSPF
    Ospf = 2,
    /// NAT
    Nat = 3,
    /// IGMP
    Igmp = 4,
}

impl RoutingProtocol {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Static => "Static Routes",
            Self::RipV2 => "RIP Version 2",
            Self::Ospf => "OSPF",
            Self::Nat => "NAT/Basic Firewall",
            Self::Igmp => "IGMP",
        }
    }
}

// ============================================================================
// Route Entry
// ============================================================================

/// Static route entry
#[derive(Clone, Copy)]
pub struct RouteEntry {
    /// Destination network
    pub destination: [u8; 4],
    /// Network mask
    pub mask: [u8; 4],
    /// Gateway (next hop)
    pub gateway: [u8; 4],
    /// Metric
    pub metric: u32,
    /// Interface index
    pub interface_id: u32,
    /// Route is in use
    pub in_use: bool,
    /// Route is persistent
    pub persistent: bool,
}

impl RouteEntry {
    pub const fn new() -> Self {
        Self {
            destination: [0u8; 4],
            mask: [0u8; 4],
            gateway: [0u8; 4],
            metric: 1,
            interface_id: 0,
            in_use: false,
            persistent: true,
        }
    }

    /// Check if this is a default route
    pub fn is_default(&self) -> bool {
        self.destination == [0, 0, 0, 0] && self.mask == [0, 0, 0, 0]
    }

    /// Check if this is a host route
    pub fn is_host_route(&self) -> bool {
        self.mask == [255, 255, 255, 255]
    }
}

// ============================================================================
// Interface
// ============================================================================

/// Network interface
#[derive(Clone, Copy)]
pub struct RrasInterface {
    /// Interface name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: u8,
    /// Interface type
    pub interface_type: InterfaceType,
    /// Interface state
    pub state: InterfaceState,
    /// IP address
    pub ip_address: [u8; 4],
    /// Subnet mask
    pub subnet_mask: [u8; 4],
    /// Interface is in use
    pub in_use: bool,
    /// Enable routing
    pub routing_enabled: bool,
    /// Enable remote access
    pub remote_access_enabled: bool,
    /// Interface ID
    pub interface_id: u32,
    /// Bytes received
    pub bytes_rx: u64,
    /// Bytes transmitted
    pub bytes_tx: u64,
}

impl RrasInterface {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            interface_type: InterfaceType::Lan,
            state: InterfaceState::Disconnected,
            ip_address: [0u8; 4],
            subnet_mask: [0u8; 4],
            in_use: false,
            routing_enabled: false,
            remote_access_enabled: false,
            interface_id: 0,
            bytes_rx: 0,
            bytes_tx: 0,
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
}

// ============================================================================
// VPN Client
// ============================================================================

/// Connected VPN client
#[derive(Clone, Copy)]
pub struct VpnClient {
    /// Client username
    pub username: [u8; MAX_NAME_LEN],
    /// Username length
    pub username_len: u8,
    /// Client IP address (tunnel)
    pub tunnel_ip: [u8; 4],
    /// Client IP address (remote)
    pub remote_ip: [u8; 4],
    /// VPN protocol
    pub protocol: VpnProtocol,
    /// Connection time (epoch seconds)
    pub connect_time: u64,
    /// Bytes received
    pub bytes_rx: u64,
    /// Bytes transmitted
    pub bytes_tx: u64,
    /// Client is connected
    pub connected: bool,
    /// Port number
    pub port: u32,
}

impl VpnClient {
    pub const fn new() -> Self {
        Self {
            username: [0u8; MAX_NAME_LEN],
            username_len: 0,
            tunnel_ip: [0u8; 4],
            remote_ip: [0u8; 4],
            protocol: VpnProtocol::Pptp,
            connect_time: 0,
            bytes_rx: 0,
            bytes_tx: 0,
            connected: false,
            port: 0,
        }
    }

    pub fn set_username(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.username[..len].copy_from_slice(&name[..len]);
        self.username_len = len as u8;
    }

    pub fn get_username(&self) -> &[u8] {
        &self.username[..self.username_len as usize]
    }

    /// Get connection duration in seconds
    pub fn duration(&self, current_time: u64) -> u64 {
        current_time.saturating_sub(self.connect_time)
    }
}

// ============================================================================
// Remote Access Policy
// ============================================================================

/// Remote access policy condition type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyCondition {
    /// Windows groups membership
    #[default]
    WindowsGroups = 0,
    /// Day and time restrictions
    DayTime = 1,
    /// Called station ID (phone number)
    CalledStationId = 2,
    /// Calling station ID
    CallingStationId = 3,
    /// Client IP address
    ClientIp = 4,
    /// Framed protocol
    FramedProtocol = 5,
    /// Tunnel type
    TunnelType = 6,
    /// Service type
    ServiceType = 7,
}

/// Remote access policy
#[derive(Clone, Copy)]
pub struct RemoteAccessPolicy {
    /// Policy name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: u8,
    /// Policy is enabled
    pub enabled: bool,
    /// Grant or deny access
    pub grant_access: bool,
    /// Policy order (priority)
    pub order: u32,
    /// Policy is in use
    pub in_use: bool,
    /// Condition type
    pub condition: PolicyCondition,
    /// Allowed authentication methods
    pub auth_methods: AuthMethods,
    /// Required encryption levels
    pub encryption: EncryptionLevels,
    /// Idle timeout (seconds, 0 = no timeout)
    pub idle_timeout: u32,
    /// Session timeout (seconds, 0 = no timeout)
    pub session_timeout: u32,
}

impl RemoteAccessPolicy {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            enabled: true,
            grant_access: true,
            order: 0,
            in_use: false,
            condition: PolicyCondition::WindowsGroups,
            auth_methods: AuthMethods::MSCHAP_V2,
            encryption: EncryptionLevels::STRONGEST,
            idle_timeout: 0,
            session_timeout: 0,
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
}

// ============================================================================
// IP Pool
// ============================================================================

/// Static IP address pool for VPN clients
#[derive(Clone, Copy)]
pub struct IpPool {
    /// Pool name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: u8,
    /// Start IP address
    pub start: [u8; 4],
    /// End IP address
    pub end: [u8; 4],
    /// Pool is in use
    pub in_use: bool,
    /// Number of addresses assigned
    pub assigned_count: u32,
}

impl IpPool {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            start: [0u8; 4],
            end: [0u8; 4],
            in_use: false,
            assigned_count: 0,
        }
    }

    /// Get total addresses in pool
    pub fn total_count(&self) -> u32 {
        let start_val = u32::from_be_bytes(self.start);
        let end_val = u32::from_be_bytes(self.end);
        end_val.saturating_sub(start_val) + 1
    }

    /// Get available addresses
    pub fn available_count(&self) -> u32 {
        self.total_count().saturating_sub(self.assigned_count)
    }
}

// ============================================================================
// Server Configuration
// ============================================================================

/// RRAS server configuration
pub struct RrasServerConfig {
    /// Enable remote access (VPN/dial-up)
    pub remote_access_enabled: bool,
    /// Enable IP routing
    pub routing_enabled: bool,
    /// Enable demand-dial routing
    pub demand_dial_enabled: bool,
    /// Maximum VPN ports
    pub max_vpn_ports: u32,
    /// PPTP ports
    pub pptp_ports: u32,
    /// L2TP ports
    pub l2tp_ports: u32,
    /// Enable logging
    pub logging_enabled: bool,
    /// Log authentication events
    pub log_auth: bool,
    /// Log accounting events
    pub log_accounting: bool,
    /// Log periodic status
    pub log_periodic: bool,
    /// Use RADIUS for authentication
    pub use_radius_auth: bool,
    /// Use RADIUS for accounting
    pub use_radius_accounting: bool,
    /// RADIUS server address
    pub radius_server: [u8; 4],
    /// RADIUS secret
    pub radius_secret: [u8; 64],
    /// RADIUS secret length
    pub radius_secret_len: u8,
    /// Use DHCP for client IP assignment
    pub use_dhcp: bool,
    /// Use static IP pools
    pub use_static_pools: bool,
    /// Enable NAT
    pub nat_enabled: bool,
    /// Enable basic firewall
    pub firewall_enabled: bool,
}

impl RrasServerConfig {
    pub const fn new() -> Self {
        Self {
            remote_access_enabled: false,
            routing_enabled: false,
            demand_dial_enabled: false,
            max_vpn_ports: 128,
            pptp_ports: 128,
            l2tp_ports: 128,
            logging_enabled: true,
            log_auth: true,
            log_accounting: true,
            log_periodic: false,
            use_radius_auth: false,
            use_radius_accounting: false,
            radius_server: [0u8; 4],
            radius_secret: [0u8; 64],
            radius_secret_len: 0,
            use_dhcp: true,
            use_static_pools: false,
            nat_enabled: false,
            firewall_enabled: false,
        }
    }
}

// ============================================================================
// RRAS Manager State
// ============================================================================

/// RRAS manager state
struct RrasManagerState {
    /// Service state
    service_state: ServiceState,
    /// Server configuration
    config: RrasServerConfig,
    /// Interfaces
    interfaces: [RrasInterface; MAX_INTERFACES],
    /// Interface count
    interface_count: u32,
    /// Static routes
    routes: [RouteEntry; MAX_ROUTES],
    /// Route count
    route_count: u32,
    /// Connected VPN clients
    clients: [VpnClient; MAX_CLIENTS],
    /// Client count
    client_count: u32,
    /// Remote access policies
    policies: [RemoteAccessPolicy; MAX_POLICIES],
    /// Policy count
    policy_count: u32,
    /// IP pools
    ip_pools: [IpPool; MAX_IP_POOLS],
    /// Pool count
    pool_count: u32,
    /// Next interface ID
    next_interface_id: u32,
    /// Dialog handle
    dialog_handle: HWND,
    /// Selected item
    selected_item: Option<usize>,
    /// View mode
    view_mode: u8,
}

impl RrasManagerState {
    pub const fn new() -> Self {
        Self {
            service_state: ServiceState::NotConfigured,
            config: RrasServerConfig::new(),
            interfaces: [const { RrasInterface::new() }; MAX_INTERFACES],
            interface_count: 0,
            routes: [const { RouteEntry::new() }; MAX_ROUTES],
            route_count: 0,
            clients: [const { VpnClient::new() }; MAX_CLIENTS],
            client_count: 0,
            policies: [const { RemoteAccessPolicy::new() }; MAX_POLICIES],
            policy_count: 0,
            ip_pools: [const { IpPool::new() }; MAX_IP_POOLS],
            pool_count: 0,
            next_interface_id: 1,
            dialog_handle: UserHandle::from_raw(0),
            selected_item: None,
            view_mode: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static RRAS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static RRAS_MANAGER: SpinLock<RrasManagerState> = SpinLock::new(RrasManagerState::new());

// Statistics
static TOTAL_CONNECTIONS: AtomicU32 = AtomicU32::new(0);
static ACTIVE_CONNECTIONS: AtomicU32 = AtomicU32::new(0);
static FAILED_CONNECTIONS: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize RRAS Manager
pub fn init() {
    if RRAS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = RRAS_MANAGER.lock();

    // Add loopback interface
    let if_idx = 0;
    state.interfaces[if_idx].set_name(b"Loopback");
    state.interfaces[if_idx].interface_type = InterfaceType::Loopback;
    state.interfaces[if_idx].state = InterfaceState::Connected;
    state.interfaces[if_idx].ip_address = [127, 0, 0, 1];
    state.interfaces[if_idx].subnet_mask = [255, 0, 0, 0];
    state.interfaces[if_idx].interface_id = 0;
    state.interfaces[if_idx].in_use = true;

    // Add internal interface
    let if_idx = 1;
    state.interfaces[if_idx].set_name(b"Internal");
    state.interfaces[if_idx].interface_type = InterfaceType::Internal;
    state.interfaces[if_idx].state = InterfaceState::Connected;
    state.interfaces[if_idx].ip_address = [192, 168, 1, 1];
    state.interfaces[if_idx].subnet_mask = [255, 255, 255, 0];
    state.interfaces[if_idx].interface_id = 1;
    state.interfaces[if_idx].routing_enabled = true;
    state.interfaces[if_idx].in_use = true;

    state.interface_count = 2;
    state.next_interface_id = 2;

    // Add default remote access policy
    let pol_idx = 0;
    state.policies[pol_idx].set_name(b"Allow remote access");
    state.policies[pol_idx].enabled = true;
    state.policies[pol_idx].grant_access = true;
    state.policies[pol_idx].order = 1;
    state.policies[pol_idx].auth_methods = AuthMethods::MSCHAP_V2 | AuthMethods::EAP;
    state.policies[pol_idx].encryption = EncryptionLevels::STRONGEST | EncryptionLevels::STRONG;
    state.policies[pol_idx].in_use = true;
    state.policy_count = 1;

    crate::serial_println!("[WIN32K] RRAS Manager initialized");
}

// ============================================================================
// Service Control
// ============================================================================

/// Configure and enable RRAS
pub fn configure_server(remote_access: bool, routing: bool) -> bool {
    let mut state = RRAS_MANAGER.lock();

    state.config.remote_access_enabled = remote_access;
    state.config.routing_enabled = routing;
    state.service_state = ServiceState::Stopped;

    true
}

/// Start RRAS service
pub fn start_service() -> bool {
    let mut state = RRAS_MANAGER.lock();

    if state.service_state == ServiceState::NotConfigured {
        return false;
    }

    state.service_state = ServiceState::Starting;
    // Simulate startup
    state.service_state = ServiceState::Running;

    true
}

/// Stop RRAS service
pub fn stop_service() -> bool {
    let mut state = RRAS_MANAGER.lock();

    if state.service_state != ServiceState::Running {
        return false;
    }

    state.service_state = ServiceState::Stopping;

    // Disconnect all clients
    for client in state.clients.iter_mut() {
        client.connected = false;
    }
    state.client_count = 0;

    state.service_state = ServiceState::Stopped;

    ACTIVE_CONNECTIONS.store(0, Ordering::Relaxed);

    true
}

/// Get service state
pub fn get_service_state() -> ServiceState {
    let state = RRAS_MANAGER.lock();
    state.service_state
}

// ============================================================================
// Interface Management
// ============================================================================

/// Add a network interface
pub fn add_interface(
    name: &[u8],
    interface_type: InterfaceType,
    ip: [u8; 4],
    mask: [u8; 4],
) -> Option<u32> {
    let mut state = RRAS_MANAGER.lock();

    // Find available slot first
    let mut slot_index: Option<usize> = None;
    for (i, iface) in state.interfaces.iter().enumerate() {
        if !iface.in_use {
            slot_index = Some(i);
            break;
        }
    }

    if let Some(idx) = slot_index {
        let new_interface_id = state.next_interface_id;
        state.interfaces[idx].set_name(name);
        state.interfaces[idx].interface_type = interface_type;
        state.interfaces[idx].ip_address = ip;
        state.interfaces[idx].subnet_mask = mask;
        state.interfaces[idx].state = InterfaceState::Disconnected;
        state.interfaces[idx].interface_id = new_interface_id;
        state.interfaces[idx].in_use = true;

        state.next_interface_id += 1;
        state.interface_count += 1;

        return Some(new_interface_id);
    }
    None
}

/// Remove an interface
pub fn remove_interface(interface_id: u32) -> bool {
    let mut state = RRAS_MANAGER.lock();

    for iface in state.interfaces.iter_mut() {
        if iface.in_use && iface.interface_id == interface_id {
            // Don't allow removing loopback or internal
            if iface.interface_type == InterfaceType::Loopback ||
               iface.interface_type == InterfaceType::Internal {
                return false;
            }
            iface.in_use = false;
            state.interface_count = state.interface_count.saturating_sub(1);
            return true;
        }
    }
    false
}

/// Enable/disable routing on interface
pub fn set_interface_routing(interface_id: u32, enabled: bool) -> bool {
    let mut state = RRAS_MANAGER.lock();

    for iface in state.interfaces.iter_mut() {
        if iface.in_use && iface.interface_id == interface_id {
            iface.routing_enabled = enabled;
            return true;
        }
    }
    false
}

// ============================================================================
// Routing Management
// ============================================================================

/// Add a static route
pub fn add_static_route(
    destination: [u8; 4],
    mask: [u8; 4],
    gateway: [u8; 4],
    metric: u32,
    interface_id: u32,
) -> Option<usize> {
    let mut state = RRAS_MANAGER.lock();

    for (i, route) in state.routes.iter_mut().enumerate() {
        if !route.in_use {
            route.destination = destination;
            route.mask = mask;
            route.gateway = gateway;
            route.metric = metric;
            route.interface_id = interface_id;
            route.persistent = true;
            route.in_use = true;

            state.route_count += 1;
            return Some(i);
        }
    }
    None
}

/// Remove a static route
pub fn remove_static_route(index: usize) -> bool {
    let mut state = RRAS_MANAGER.lock();

    if index < MAX_ROUTES && state.routes[index].in_use {
        state.routes[index].in_use = false;
        state.route_count = state.route_count.saturating_sub(1);
        true
    } else {
        false
    }
}

/// Get route count
pub fn get_route_count() -> u32 {
    let state = RRAS_MANAGER.lock();
    state.route_count
}

// ============================================================================
// VPN Client Management
// ============================================================================

/// Connect a VPN client
pub fn connect_client(
    username: &[u8],
    remote_ip: [u8; 4],
    protocol: VpnProtocol,
    current_time: u64,
) -> Option<[u8; 4]> {
    let mut state = RRAS_MANAGER.lock();

    if state.service_state != ServiceState::Running {
        return None;
    }

    if !state.config.remote_access_enabled {
        return None;
    }

    // Allocate tunnel IP from pool
    let tunnel_ip = allocate_client_ip(&mut state)?;

    for client in state.clients.iter_mut() {
        if !client.connected {
            client.set_username(username);
            client.remote_ip = remote_ip;
            client.tunnel_ip = tunnel_ip;
            client.protocol = protocol;
            client.connect_time = current_time;
            client.bytes_rx = 0;
            client.bytes_tx = 0;
            client.connected = true;

            state.client_count += 1;
            TOTAL_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
            ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);

            return Some(tunnel_ip);
        }
    }

    FAILED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    None
}

/// Disconnect a VPN client
pub fn disconnect_client(tunnel_ip: [u8; 4]) -> bool {
    let mut state = RRAS_MANAGER.lock();

    for client in state.clients.iter_mut() {
        if client.connected && client.tunnel_ip == tunnel_ip {
            client.connected = false;
            state.client_count = state.client_count.saturating_sub(1);
            ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);

            // Return IP to pool
            release_client_ip(&mut state, tunnel_ip);

            return true;
        }
    }
    false
}

/// Get active client count
pub fn get_active_clients() -> u32 {
    let state = RRAS_MANAGER.lock();
    state.client_count
}

/// Allocate IP address for client
fn allocate_client_ip(state: &mut RrasManagerState) -> Option<[u8; 4]> {
    if state.config.use_static_pools {
        for pool in state.ip_pools.iter_mut() {
            if pool.in_use && pool.available_count() > 0 {
                let start = u32::from_be_bytes(pool.start);
                let ip = start + pool.assigned_count;
                pool.assigned_count += 1;
                return Some(ip.to_be_bytes());
            }
        }
        None
    } else {
        // Default pool: 10.0.0.x
        let client_num = state.client_count + 1;
        if client_num < 255 {
            Some([10, 0, 0, client_num as u8])
        } else {
            None
        }
    }
}

/// Release client IP address
fn release_client_ip(state: &mut RrasManagerState, ip: [u8; 4]) {
    if state.config.use_static_pools {
        for pool in state.ip_pools.iter_mut() {
            if pool.in_use {
                let ip_val = u32::from_be_bytes(ip);
                let start_val = u32::from_be_bytes(pool.start);
                let end_val = u32::from_be_bytes(pool.end);
                if ip_val >= start_val && ip_val <= end_val {
                    pool.assigned_count = pool.assigned_count.saturating_sub(1);
                    break;
                }
            }
        }
    }
}

// ============================================================================
// Remote Access Policies
// ============================================================================

/// Add a remote access policy
pub fn add_policy(name: &[u8], grant_access: bool, order: u32) -> Option<usize> {
    let mut state = RRAS_MANAGER.lock();

    for (i, policy) in state.policies.iter_mut().enumerate() {
        if !policy.in_use {
            policy.set_name(name);
            policy.grant_access = grant_access;
            policy.order = order;
            policy.enabled = true;
            policy.auth_methods = AuthMethods::MSCHAP_V2;
            policy.encryption = EncryptionLevels::STRONGEST;
            policy.in_use = true;

            state.policy_count += 1;
            return Some(i);
        }
    }
    None
}

/// Remove a remote access policy
pub fn remove_policy(index: usize) -> bool {
    let mut state = RRAS_MANAGER.lock();

    if index < MAX_POLICIES && state.policies[index].in_use {
        state.policies[index].in_use = false;
        state.policy_count = state.policy_count.saturating_sub(1);
        true
    } else {
        false
    }
}

/// Enable/disable a policy
pub fn set_policy_enabled(index: usize, enabled: bool) -> bool {
    let mut state = RRAS_MANAGER.lock();

    if index < MAX_POLICIES && state.policies[index].in_use {
        state.policies[index].enabled = enabled;
        true
    } else {
        false
    }
}

// ============================================================================
// IP Pool Management
// ============================================================================

/// Add a static IP pool
pub fn add_ip_pool(name: &[u8], start: [u8; 4], end: [u8; 4]) -> Option<usize> {
    let mut state = RRAS_MANAGER.lock();

    for (i, pool) in state.ip_pools.iter_mut().enumerate() {
        if !pool.in_use {
            pool.name[..name.len().min(MAX_NAME_LEN)].copy_from_slice(
                &name[..name.len().min(MAX_NAME_LEN)]
            );
            pool.name_len = name.len().min(MAX_NAME_LEN) as u8;
            pool.start = start;
            pool.end = end;
            pool.assigned_count = 0;
            pool.in_use = true;

            state.pool_count += 1;
            return Some(i);
        }
    }
    None
}

/// Remove an IP pool
pub fn remove_ip_pool(index: usize) -> bool {
    let mut state = RRAS_MANAGER.lock();

    if index < MAX_IP_POOLS && state.ip_pools[index].in_use {
        state.ip_pools[index].in_use = false;
        state.pool_count = state.pool_count.saturating_sub(1);
        true
    } else {
        false
    }
}

// ============================================================================
// NAT Configuration
// ============================================================================

/// Enable NAT on interface
pub fn enable_nat(interface_id: u32) -> bool {
    let mut state = RRAS_MANAGER.lock();

    state.config.nat_enabled = true;
    // In real implementation, would configure NAT on the specified interface
    let _ = interface_id;

    true
}

/// Disable NAT
pub fn disable_nat() -> bool {
    let mut state = RRAS_MANAGER.lock();
    state.config.nat_enabled = false;
    true
}

/// Enable basic firewall
pub fn enable_firewall() -> bool {
    let mut state = RRAS_MANAGER.lock();
    state.config.firewall_enabled = true;
    true
}

/// Disable firewall
pub fn disable_firewall() -> bool {
    let mut state = RRAS_MANAGER.lock();
    state.config.firewall_enabled = false;
    true
}

// ============================================================================
// Dialog Management
// ============================================================================

/// Show RRAS Manager dialog
pub fn show_dialog(_parent: HWND) -> HWND {
    let mut state = RRAS_MANAGER.lock();

    let handle = UserHandle::from_raw(0xAA01);
    state.dialog_handle = handle;
    state.selected_item = None;
    state.view_mode = 0;

    handle
}

/// Close RRAS Manager dialog
pub fn close_dialog() {
    let mut state = RRAS_MANAGER.lock();
    state.dialog_handle = UserHandle::from_raw(0);
}

// ============================================================================
// Statistics
// ============================================================================

/// RRAS statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct RrasStats {
    pub initialized: bool,
    pub service_state: ServiceState,
    pub interface_count: u32,
    pub route_count: u32,
    pub active_clients: u32,
    pub total_connections: u32,
    pub failed_connections: u32,
}

/// Get RRAS statistics
pub fn get_stats() -> RrasStats {
    let state = RRAS_MANAGER.lock();
    RrasStats {
        initialized: RRAS_INITIALIZED.load(Ordering::Relaxed),
        service_state: state.service_state,
        interface_count: state.interface_count,
        route_count: state.route_count,
        active_clients: state.client_count,
        total_connections: TOTAL_CONNECTIONS.load(Ordering::Relaxed),
        failed_connections: FAILED_CONNECTIONS.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Check if RRAS is running
pub fn is_running() -> bool {
    let state = RRAS_MANAGER.lock();
    state.service_state == ServiceState::Running
}

/// Get configuration summary
pub fn get_config_summary() -> (bool, bool, bool, bool) {
    let state = RRAS_MANAGER.lock();
    (
        state.config.remote_access_enabled,
        state.config.routing_enabled,
        state.config.nat_enabled,
        state.config.firewall_enabled,
    )
}
