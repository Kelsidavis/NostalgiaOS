//! Network Location Awareness Service (NLA)
//!
//! The Network Location Awareness service collects and stores network
//! configuration information and notifies applications when this information
//! changes. It determines which network the computer is connected to.
//!
//! # Features
//!
//! - **Network Detection**: Identify connected networks
//! - **Connectivity Status**: Track internet connectivity
//! - **Location Profiles**: Associate networks with locations
//! - **Change Notification**: Notify applications of network changes
//!
//! # Network Categories
//!
//! - Public: Untrusted networks (airports, cafes)
//! - Private: Trusted home/work networks
//! - Domain: Active Directory domain networks
//!
//! # Connectivity Levels
//!
//! - None: No connectivity
//! - LocalNetwork: Connected to local network only
//! - Internet: Full internet connectivity

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum network connections
const MAX_NETWORKS: usize = 16;

/// Maximum network name length
const MAX_NETWORK_NAME: usize = 64;

/// Maximum network description length
const MAX_DESCRIPTION: usize = 128;

/// Network category
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCategory {
    /// Public network (untrusted)
    Public = 0,
    /// Private network (trusted)
    Private = 1,
    /// Domain network
    Domain = 2,
}

impl NetworkCategory {
    const fn empty() -> Self {
        NetworkCategory::Public
    }
}

/// Connectivity level
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConnectivityLevel {
    /// No network connectivity
    None = 0,
    /// Connected to local network only
    LocalNetwork = 1,
    /// Connected to subnet only
    SubnetNetwork = 2,
    /// Connected with internet access
    Internet = 3,
}

impl ConnectivityLevel {
    const fn empty() -> Self {
        ConnectivityLevel::None
    }
}

/// Network connection type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Unknown connection type
    Unknown = 0,
    /// Wired Ethernet connection
    Ethernet = 1,
    /// Wireless (WiFi) connection
    Wireless = 2,
    /// Mobile broadband connection
    Mobile = 3,
    /// VPN connection
    Vpn = 4,
    /// Dial-up connection
    Dialup = 5,
}

impl ConnectionType {
    const fn empty() -> Self {
        ConnectionType::Unknown
    }
}

/// Network status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkStatus {
    /// Network is disconnected
    Disconnected = 0,
    /// Network is connecting
    Connecting = 1,
    /// Network is connected
    Connected = 2,
    /// Network is disconnecting
    Disconnecting = 3,
}

impl NetworkStatus {
    const fn empty() -> Self {
        NetworkStatus::Disconnected
    }
}

/// Network connection info
#[repr(C)]
#[derive(Clone)]
pub struct NetworkConnection {
    /// Network ID (GUID-like)
    pub network_id: u64,
    /// Network name
    pub name: [u8; MAX_NETWORK_NAME],
    /// Network description
    pub description: [u8; MAX_DESCRIPTION],
    /// Network category
    pub category: NetworkCategory,
    /// Connection type
    pub connection_type: ConnectionType,
    /// Connectivity level
    pub connectivity: ConnectivityLevel,
    /// Network status
    pub status: NetworkStatus,
    /// Interface index
    pub if_index: u32,
    /// Is default gateway network
    pub is_default: bool,
    /// Has IPv4 connectivity
    pub ipv4_connected: bool,
    /// Has IPv6 connectivity
    pub ipv6_connected: bool,
    /// Network is managed (domain joined)
    pub is_managed: bool,
    /// First connected timestamp
    pub first_connected: i64,
    /// Last connected timestamp
    pub last_connected: i64,
    /// Entry is valid
    pub valid: bool,
}

impl NetworkConnection {
    const fn empty() -> Self {
        NetworkConnection {
            network_id: 0,
            name: [0; MAX_NETWORK_NAME],
            description: [0; MAX_DESCRIPTION],
            category: NetworkCategory::empty(),
            connection_type: ConnectionType::empty(),
            connectivity: ConnectivityLevel::empty(),
            status: NetworkStatus::empty(),
            if_index: 0,
            is_default: false,
            ipv4_connected: false,
            ipv6_connected: false,
            is_managed: false,
            first_connected: 0,
            last_connected: 0,
            valid: false,
        }
    }
}

/// Network change notification callback
pub type NetworkChangeCallback = fn(network_id: u64, change_type: NetworkChangeType);

/// Network change types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkChangeType {
    /// Network connected
    Connected = 0,
    /// Network disconnected
    Disconnected = 1,
    /// Connectivity changed
    ConnectivityChange = 2,
    /// Category changed
    CategoryChange = 3,
    /// Network renamed
    Renamed = 4,
}

/// Registered callback entry
#[repr(C)]
#[derive(Clone, Copy)]
struct CallbackEntry {
    /// Callback ID
    id: u64,
    /// Callback function (stored as function pointer)
    callback: Option<NetworkChangeCallback>,
    /// Entry is valid
    valid: bool,
}

impl CallbackEntry {
    const fn empty() -> Self {
        CallbackEntry {
            id: 0,
            callback: None,
            valid: false,
        }
    }
}

/// Maximum registered callbacks
const MAX_CALLBACKS: usize = 32;

/// NLA service state
pub struct NlaState {
    /// Service is running
    pub running: bool,
    /// Network connections
    pub networks: [NetworkConnection; MAX_NETWORKS],
    /// Network count
    pub network_count: usize,
    /// Next network ID
    pub next_network_id: u64,
    /// Registered callbacks
    callbacks: [CallbackEntry; MAX_CALLBACKS],
    /// Callback count
    callback_count: usize,
    /// Next callback ID
    next_callback_id: u64,
    /// Default network index
    pub default_network_idx: Option<usize>,
    /// Service start time
    pub start_time: i64,
}

impl NlaState {
    const fn new() -> Self {
        NlaState {
            running: false,
            networks: [const { NetworkConnection::empty() }; MAX_NETWORKS],
            network_count: 0,
            next_network_id: 1,
            callbacks: [const { CallbackEntry::empty() }; MAX_CALLBACKS],
            callback_count: 0,
            next_callback_id: 1,
            default_network_idx: None,
            start_time: 0,
        }
    }
}

/// Global state
static NLA_STATE: Mutex<NlaState> = Mutex::new(NlaState::new());

/// Statistics
static NETWORKS_DETECTED: AtomicU64 = AtomicU64::new(0);
static CONNECTIVITY_CHECKS: AtomicU64 = AtomicU64::new(0);
static NOTIFICATIONS_SENT: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize NLA service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = NLA_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    crate::serial_println!("[NLA] Network Location Awareness service initialized");
}

/// Report a new network connection
pub fn report_network(
    if_index: u32,
    name: &[u8],
    connection_type: ConnectionType,
    category: NetworkCategory,
) -> Result<u64, u32> {
    let mut state = NLA_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Check if already known by interface index
    for net in state.networks.iter() {
        if net.valid && net.if_index == if_index {
            return Err(0x80070055); // ERROR_DUP_NAME
        }
    }

    let slot = state.networks.iter().position(|n| !n.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let network_id = state.next_network_id;
    state.next_network_id += 1;

    let now = crate::rtl::time::rtl_get_system_time();

    // Check if this should be the default before taking mutable borrow
    let set_as_default = state.default_network_idx.is_none();
    if set_as_default {
        state.default_network_idx = Some(slot);
    }
    state.network_count += 1;

    let name_len = name.len().min(MAX_NETWORK_NAME);

    let network = &mut state.networks[slot];
    network.network_id = network_id;
    network.if_index = if_index;
    network.connection_type = connection_type;
    network.category = category;
    network.status = NetworkStatus::Connecting;
    network.connectivity = ConnectivityLevel::None;
    network.first_connected = now;
    network.last_connected = now;
    network.is_default = set_as_default;
    network.valid = true;
    network.name[..name_len].copy_from_slice(&name[..name_len]);

    NETWORKS_DETECTED.fetch_add(1, Ordering::SeqCst);

    Ok(network_id)
}

/// Update network status
pub fn update_network_status(network_id: u64, status: NetworkStatus) -> Result<(), u32> {
    let mut state = NLA_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.networks.iter().position(|n| n.valid && n.network_id == network_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let old_status = state.networks[idx].status;
    state.networks[idx].status = status;
    state.networks[idx].last_connected = crate::rtl::time::rtl_get_system_time();

    if old_status != status {
        let change_type = match status {
            NetworkStatus::Connected => NetworkChangeType::Connected,
            NetworkStatus::Disconnected => NetworkChangeType::Disconnected,
            _ => return Ok(()),
        };

        // Notify callbacks (collect first to avoid borrow issues)
        let callbacks: [(u64, Option<NetworkChangeCallback>); MAX_CALLBACKS] =
            core::array::from_fn(|i| (state.callbacks[i].id, state.callbacks[i].callback));
        let valid_callbacks: [(u64, Option<NetworkChangeCallback>, bool); MAX_CALLBACKS] =
            core::array::from_fn(|i| (callbacks[i].0, callbacks[i].1, state.callbacks[i].valid));

        drop(state); // Release lock before calling callbacks

        for (_, callback, valid) in valid_callbacks.iter() {
            if *valid {
                if let Some(cb) = callback {
                    cb(network_id, change_type);
                    NOTIFICATIONS_SENT.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }

    Ok(())
}

/// Update network connectivity
pub fn update_connectivity(network_id: u64, connectivity: ConnectivityLevel) -> Result<(), u32> {
    let mut state = NLA_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.networks.iter().position(|n| n.valid && n.network_id == network_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let old_connectivity = state.networks[idx].connectivity;
    state.networks[idx].connectivity = connectivity;

    // Update IPv4/IPv6 flags based on connectivity
    if connectivity >= ConnectivityLevel::LocalNetwork {
        state.networks[idx].ipv4_connected = true;
    } else {
        state.networks[idx].ipv4_connected = false;
        state.networks[idx].ipv6_connected = false;
    }

    CONNECTIVITY_CHECKS.fetch_add(1, Ordering::SeqCst);

    if old_connectivity != connectivity {
        // Collect callbacks
        let callbacks: [(Option<NetworkChangeCallback>, bool); MAX_CALLBACKS] =
            core::array::from_fn(|i| (state.callbacks[i].callback, state.callbacks[i].valid));

        drop(state);

        for (callback, valid) in callbacks.iter() {
            if *valid {
                if let Some(cb) = callback {
                    cb(network_id, NetworkChangeType::ConnectivityChange);
                    NOTIFICATIONS_SENT.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }

    Ok(())
}

/// Set network category
pub fn set_network_category(network_id: u64, category: NetworkCategory) -> Result<(), u32> {
    let mut state = NLA_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.networks.iter().position(|n| n.valid && n.network_id == network_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let old_category = state.networks[idx].category;
    state.networks[idx].category = category;

    if old_category != category {
        let callbacks: [(Option<NetworkChangeCallback>, bool); MAX_CALLBACKS] =
            core::array::from_fn(|i| (state.callbacks[i].callback, state.callbacks[i].valid));

        drop(state);

        for (callback, valid) in callbacks.iter() {
            if *valid {
                if let Some(cb) = callback {
                    cb(network_id, NetworkChangeType::CategoryChange);
                    NOTIFICATIONS_SENT.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }

    Ok(())
}

/// Remove a network
pub fn remove_network(network_id: u64) -> Result<(), u32> {
    let mut state = NLA_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.networks.iter().position(|n| n.valid && n.network_id == network_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.networks[idx].valid = false;
    state.network_count = state.network_count.saturating_sub(1);

    // Update default network if needed
    if state.default_network_idx == Some(idx) {
        state.default_network_idx = state.networks.iter()
            .position(|n| n.valid && n.status == NetworkStatus::Connected);

        if let Some(new_default) = state.default_network_idx {
            state.networks[new_default].is_default = true;
        }
    }

    // Notify disconnection
    let callbacks: [(Option<NetworkChangeCallback>, bool); MAX_CALLBACKS] =
        core::array::from_fn(|i| (state.callbacks[i].callback, state.callbacks[i].valid));

    drop(state);

    for (callback, valid) in callbacks.iter() {
        if *valid {
            if let Some(cb) = callback {
                cb(network_id, NetworkChangeType::Disconnected);
                NOTIFICATIONS_SENT.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    Ok(())
}

/// Get network info by ID
pub fn get_network(network_id: u64) -> Option<NetworkConnection> {
    let state = NLA_STATE.lock();

    state.networks.iter()
        .find(|n| n.valid && n.network_id == network_id)
        .cloned()
}

/// Get network by interface index
pub fn get_network_by_interface(if_index: u32) -> Option<NetworkConnection> {
    let state = NLA_STATE.lock();

    state.networks.iter()
        .find(|n| n.valid && n.if_index == if_index)
        .cloned()
}

/// Get default network
pub fn get_default_network() -> Option<NetworkConnection> {
    let state = NLA_STATE.lock();

    match state.default_network_idx {
        Some(idx) if state.networks[idx].valid => Some(state.networks[idx].clone()),
        _ => None,
    }
}

/// Enumerate all networks
pub fn enum_networks() -> ([NetworkConnection; MAX_NETWORKS], usize) {
    let state = NLA_STATE.lock();
    let mut result = [const { NetworkConnection::empty() }; MAX_NETWORKS];
    let mut count = 0;

    for net in state.networks.iter() {
        if net.valid && count < MAX_NETWORKS {
            result[count] = net.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get connected network count
pub fn get_connected_count() -> usize {
    let state = NLA_STATE.lock();
    state.networks.iter()
        .filter(|n| n.valid && n.status == NetworkStatus::Connected)
        .count()
}

/// Check if any network has internet
pub fn has_internet_connectivity() -> bool {
    let state = NLA_STATE.lock();
    state.networks.iter()
        .any(|n| n.valid && n.connectivity == ConnectivityLevel::Internet)
}

/// Register for network change notifications
pub fn register_notification(callback: NetworkChangeCallback) -> Result<u64, u32> {
    let mut state = NLA_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let slot = state.callbacks.iter().position(|c| !c.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let callback_id = state.next_callback_id;
    state.next_callback_id += 1;

    state.callbacks[slot].id = callback_id;
    state.callbacks[slot].callback = Some(callback);
    state.callbacks[slot].valid = true;
    state.callback_count += 1;

    Ok(callback_id)
}

/// Unregister notification callback
pub fn unregister_notification(callback_id: u64) -> Result<(), u32> {
    let mut state = NLA_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.callbacks.iter().position(|c| c.valid && c.id == callback_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.callbacks[idx].valid = false;
    state.callbacks[idx].callback = None;
    state.callback_count = state.callback_count.saturating_sub(1);

    Ok(())
}

/// Set network as default
pub fn set_default_network(network_id: u64) -> Result<(), u32> {
    let mut state = NLA_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.networks.iter().position(|n| n.valid && n.network_id == network_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    // Clear old default
    if let Some(old_idx) = state.default_network_idx {
        if state.networks[old_idx].valid {
            state.networks[old_idx].is_default = false;
        }
    }

    state.networks[idx].is_default = true;
    state.default_network_idx = Some(idx);

    Ok(())
}

/// Set network name
pub fn set_network_name(network_id: u64, name: &[u8]) -> Result<(), u32> {
    let mut state = NLA_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.networks.iter().position(|n| n.valid && n.network_id == network_id);
    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    let name_len = name.len().min(MAX_NETWORK_NAME);
    state.networks[idx].name = [0; MAX_NETWORK_NAME];
    state.networks[idx].name[..name_len].copy_from_slice(&name[..name_len]);

    // Collect callbacks
    let callbacks: [(Option<NetworkChangeCallback>, bool); MAX_CALLBACKS] =
        core::array::from_fn(|i| (state.callbacks[i].callback, state.callbacks[i].valid));

    drop(state);

    for (callback, valid) in callbacks.iter() {
        if *valid {
            if let Some(cb) = callback {
                cb(network_id, NetworkChangeType::Renamed);
                NOTIFICATIONS_SENT.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    Ok(())
}

/// Get network connectivity
pub fn get_connectivity(network_id: u64) -> Option<ConnectivityLevel> {
    let state = NLA_STATE.lock();

    state.networks.iter()
        .find(|n| n.valid && n.network_id == network_id)
        .map(|n| n.connectivity)
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64) {
    (
        NETWORKS_DETECTED.load(Ordering::SeqCst),
        CONNECTIVITY_CHECKS.load(Ordering::SeqCst),
        NOTIFICATIONS_SENT.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = NLA_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = NLA_STATE.lock();
    state.running = false;

    // Clear all networks
    for net in state.networks.iter_mut() {
        net.valid = false;
    }
    state.network_count = 0;
    state.default_network_idx = None;

    // Clear callbacks
    for cb in state.callbacks.iter_mut() {
        cb.valid = false;
        cb.callback = None;
    }
    state.callback_count = 0;

    crate::serial_println!("[NLA] Network Location Awareness service stopped");
}
