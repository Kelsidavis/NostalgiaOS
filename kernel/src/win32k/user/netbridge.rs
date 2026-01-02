//! Network Bridge Management
//!
//! This module implements the Win32k USER subsystem support for
//! Network Bridge configuration in Windows Server 2003.
//!
//! # Windows Server 2003 Reference
//!
//! Network Bridge allows combining multiple network adapters into
//! a single logical network segment, enabling transparent bridging
//! between different network types (Ethernet, wireless, etc.).
//!
//! Key components:
//! - Bridge interface management
//! - Adapter membership
//! - MAC address table
//! - Spanning Tree Protocol (STP) support
//! - Traffic statistics

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::win32k::user::UserHandle;

/// Type alias for window handles
type HWND = UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of bridges
const MAX_BRIDGES: usize = 8;

/// Maximum adapters per bridge
const MAX_ADAPTERS_PER_BRIDGE: usize = 16;

/// Maximum total adapters
const MAX_ADAPTERS: usize = 64;

/// Maximum MAC table entries
const MAX_MAC_ENTRIES: usize = 1024;

/// Maximum name length
const MAX_NAME_LEN: usize = 128;

/// MAC address length
const MAC_LEN: usize = 6;

// ============================================================================
// Enumerations
// ============================================================================

/// Bridge status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BridgeStatus {
    /// Bridge is disabled
    Disabled = 0,
    /// Bridge is enabled
    Enabled = 1,
    /// Bridge is learning
    Learning = 2,
    /// Bridge has error
    Error = 3,
}

impl Default for BridgeStatus {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Adapter type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AdapterType {
    /// Ethernet adapter
    Ethernet = 0,
    /// Wireless adapter
    Wireless = 1,
    /// FireWire (IEEE 1394)
    FireWire = 2,
    /// HomePNA
    HomePna = 3,
    /// Virtual adapter
    Virtual = 4,
    /// Other
    Other = 5,
}

impl Default for AdapterType {
    fn default() -> Self {
        Self::Ethernet
    }
}

/// Adapter state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AdapterState {
    /// Disconnected
    Disconnected = 0,
    /// Connected
    Connected = 1,
    /// Media disconnected
    MediaDisconnected = 2,
    /// Disabled
    Disabled = 3,
}

impl Default for AdapterState {
    fn default() -> Self {
        Self::Disconnected
    }
}

/// STP port state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StpPortState {
    /// Blocking
    Blocking = 0,
    /// Listening
    Listening = 1,
    /// Learning
    Learning = 2,
    /// Forwarding
    Forwarding = 3,
    /// Disabled
    Disabled = 4,
}

impl Default for StpPortState {
    fn default() -> Self {
        Self::Disabled
    }
}

/// MAC entry type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MacEntryType {
    /// Learned dynamically
    Dynamic = 0,
    /// Static entry
    Static = 1,
    /// Local interface
    Local = 2,
}

impl Default for MacEntryType {
    fn default() -> Self {
        Self::Dynamic
    }
}

// ============================================================================
// Structures
// ============================================================================

/// Network bridge
#[derive(Debug)]
pub struct NetworkBridge {
    /// Bridge ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Bridge name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Bridge MAC address
    pub mac_address: [u8; MAC_LEN],
    /// Bridge status
    pub status: BridgeStatus,
    /// Number of adapters
    pub adapter_count: u32,
    /// Adapter IDs in this bridge
    pub adapters: [u32; MAX_ADAPTERS_PER_BRIDGE],
    /// STP enabled
    pub stp_enabled: bool,
    /// Bridge priority (for STP)
    pub stp_priority: u16,
    /// Is root bridge
    pub is_root: bool,
    /// Root bridge ID (MAC of root)
    pub root_bridge_id: [u8; MAC_LEN],
    /// Forward delay (seconds)
    pub forward_delay: u8,
    /// Max age (seconds)
    pub max_age: u8,
    /// Hello time (seconds)
    pub hello_time: u8,
    /// MAC table size
    pub mac_table_size: u32,
    /// MAC aging time (seconds)
    pub mac_aging_time: u32,
    /// Packets forwarded
    pub packets_forwarded: u64,
    /// Packets dropped
    pub packets_dropped: u64,
    /// Created time
    pub created_time: u64,
    /// Window handle
    pub hwnd: HWND,
}

impl NetworkBridge {
    /// Create new bridge
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            mac_address: [0u8; MAC_LEN],
            status: BridgeStatus::Disabled,
            adapter_count: 0,
            adapters: [0u32; MAX_ADAPTERS_PER_BRIDGE],
            stp_enabled: true,
            stp_priority: 32768, // Default STP priority
            is_root: false,
            root_bridge_id: [0u8; MAC_LEN],
            forward_delay: 15,
            max_age: 20,
            hello_time: 2,
            mac_table_size: 0,
            mac_aging_time: 300, // 5 minutes
            packets_forwarded: 0,
            packets_dropped: 0,
            created_time: 0,
            hwnd: UserHandle::NULL,
        }
    }
}

/// Network adapter (that can be bridged)
#[derive(Debug)]
pub struct BridgeAdapter {
    /// Adapter ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// Adapter name
    pub name: [u8; MAX_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Description
    pub description: [u8; MAX_NAME_LEN],
    /// Description length
    pub desc_len: usize,
    /// MAC address
    pub mac_address: [u8; MAC_LEN],
    /// Adapter type
    pub adapter_type: AdapterType,
    /// Connection state
    pub state: AdapterState,
    /// Speed (Mbps)
    pub speed_mbps: u32,
    /// Is bridgeable
    pub bridgeable: bool,
    /// Bridge ID (0 if not bridged)
    pub bridge_id: u32,
    /// STP port state
    pub stp_state: StpPortState,
    /// STP port priority
    pub stp_port_priority: u8,
    /// STP path cost
    pub stp_path_cost: u32,
    /// Packets received
    pub rx_packets: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Errors
    pub errors: u64,
}

impl BridgeAdapter {
    /// Create new adapter
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            description: [0u8; MAX_NAME_LEN],
            desc_len: 0,
            mac_address: [0u8; MAC_LEN],
            adapter_type: AdapterType::Ethernet,
            state: AdapterState::Disconnected,
            speed_mbps: 0,
            bridgeable: true,
            bridge_id: 0,
            stp_state: StpPortState::Disabled,
            stp_port_priority: 128,
            stp_path_cost: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            errors: 0,
        }
    }
}

/// MAC address table entry
#[derive(Debug)]
pub struct MacTableEntry {
    /// Entry ID
    pub id: u32,
    /// Active flag
    pub active: bool,
    /// MAC address
    pub mac_address: [u8; MAC_LEN],
    /// Bridge ID
    pub bridge_id: u32,
    /// Adapter ID (port)
    pub adapter_id: u32,
    /// Entry type
    pub entry_type: MacEntryType,
    /// Last seen time
    pub last_seen: u64,
    /// Hit count
    pub hit_count: u64,
}

impl MacTableEntry {
    /// Create new entry
    pub const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            mac_address: [0u8; MAC_LEN],
            bridge_id: 0,
            adapter_id: 0,
            entry_type: MacEntryType::Dynamic,
            last_seen: 0,
            hit_count: 0,
        }
    }
}

/// Bridge statistics
#[derive(Debug)]
pub struct BridgeStatistics {
    /// Total bridges
    pub total_bridges: u32,
    /// Active bridges
    pub active_bridges: u32,
    /// Total adapters
    pub total_adapters: u32,
    /// Bridged adapters
    pub bridged_adapters: u32,
    /// Total MAC entries
    pub mac_entries: u32,
    /// Total packets forwarded
    pub packets_forwarded: u64,
    /// Total packets dropped
    pub packets_dropped: u64,
}

impl BridgeStatistics {
    /// Create new statistics
    pub const fn new() -> Self {
        Self {
            total_bridges: 0,
            active_bridges: 0,
            total_adapters: 0,
            bridged_adapters: 0,
            mac_entries: 0,
            packets_forwarded: 0,
            packets_dropped: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Network Bridge state
struct NetBridgeState {
    /// Bridges
    bridges: [NetworkBridge; MAX_BRIDGES],
    /// Adapters
    adapters: [BridgeAdapter; MAX_ADAPTERS],
    /// MAC table
    mac_table: [MacTableEntry; MAX_MAC_ENTRIES],
    /// Statistics
    stats: BridgeStatistics,
    /// Next ID counter
    next_id: u32,
}

impl NetBridgeState {
    /// Create new state
    const fn new() -> Self {
        Self {
            bridges: [const { NetworkBridge::new() }; MAX_BRIDGES],
            adapters: [const { BridgeAdapter::new() }; MAX_ADAPTERS],
            mac_table: [const { MacTableEntry::new() }; MAX_MAC_ENTRIES],
            stats: BridgeStatistics::new(),
            next_id: 1,
        }
    }
}

/// Global state
static NETBRIDGE_STATE: SpinLock<NetBridgeState> = SpinLock::new(NetBridgeState::new());

/// Module initialized flag
static NETBRIDGE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Bridge count
static BRIDGE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Adapter count
static ADAPTER_COUNT: AtomicU32 = AtomicU32::new(0);

/// Total packets forwarded
static TOTAL_FORWARDED: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Bridge Functions
// ============================================================================

/// Create a network bridge
pub fn create_bridge(name: &[u8]) -> Result<u32, u32> {
    let mut state = NETBRIDGE_STATE.lock();

    let slot = state.bridges.iter().position(|b| !b.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let bridge = &mut state.bridges[slot];
    bridge.id = id;
    bridge.active = true;

    let name_len = name.len().min(MAX_NAME_LEN);
    bridge.name[..name_len].copy_from_slice(&name[..name_len]);
    bridge.name_len = name_len;

    // Generate bridge MAC (simplified)
    bridge.mac_address = [0x02, 0x00, 0x00, 0x00, 0x00, id as u8];

    bridge.status = BridgeStatus::Disabled;
    bridge.created_time = 0;
    bridge.hwnd = UserHandle::from_raw(id);

    state.stats.total_bridges += 1;
    BRIDGE_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(id)
}

/// Delete a bridge
pub fn delete_bridge(bridge_id: u32) -> Result<(), u32> {
    let mut state = NETBRIDGE_STATE.lock();

    // Find bridge index
    let bridge_idx = state.bridges.iter().position(|b| b.active && b.id == bridge_id);
    let bridge_idx = match bridge_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    // Count adapters and MAC entries to remove first
    let mut adapters_to_unbind = 0u32;
    let mut mac_entries_to_remove = 0u32;

    for adapter in state.adapters.iter() {
        if adapter.active && adapter.bridge_id == bridge_id {
            adapters_to_unbind += 1;
        }
    }

    for entry in state.mac_table.iter() {
        if entry.active && entry.bridge_id == bridge_id {
            mac_entries_to_remove += 1;
        }
    }

    // Now update the items
    for adapter in state.adapters.iter_mut() {
        if adapter.active && adapter.bridge_id == bridge_id {
            adapter.bridge_id = 0;
            adapter.stp_state = StpPortState::Disabled;
        }
    }

    for entry in state.mac_table.iter_mut() {
        if entry.active && entry.bridge_id == bridge_id {
            entry.active = false;
        }
    }

    // Check bridge status before marking inactive
    let was_enabled = state.bridges[bridge_idx].status == BridgeStatus::Enabled;
    state.bridges[bridge_idx].active = false;

    // Update stats
    state.stats.bridged_adapters = state.stats.bridged_adapters.saturating_sub(adapters_to_unbind);
    state.stats.mac_entries = state.stats.mac_entries.saturating_sub(mac_entries_to_remove);

    if was_enabled {
        state.stats.active_bridges = state.stats.active_bridges.saturating_sub(1);
    }

    state.stats.total_bridges = state.stats.total_bridges.saturating_sub(1);
    BRIDGE_COUNT.fetch_sub(1, Ordering::Relaxed);

    Ok(())
}

/// Enable a bridge
pub fn enable_bridge(bridge_id: u32) -> Result<(), u32> {
    let mut state = NETBRIDGE_STATE.lock();

    let bridge = state.bridges.iter_mut().find(|b| b.active && b.id == bridge_id);

    match bridge {
        Some(b) => {
            if b.status != BridgeStatus::Enabled {
                b.status = BridgeStatus::Enabled;
                state.stats.active_bridges += 1;
            }
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Disable a bridge
pub fn disable_bridge(bridge_id: u32) -> Result<(), u32> {
    let mut state = NETBRIDGE_STATE.lock();

    // Find bridge index
    let bridge_idx = state.bridges.iter().position(|b| b.active && b.id == bridge_id);
    let bridge_idx = match bridge_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    if state.bridges[bridge_idx].status == BridgeStatus::Enabled {
        state.stats.active_bridges = state.stats.active_bridges.saturating_sub(1);
    }
    state.bridges[bridge_idx].status = BridgeStatus::Disabled;

    Ok(())
}

/// Configure STP for a bridge
pub fn configure_stp(
    bridge_id: u32,
    enabled: bool,
    priority: u16,
    forward_delay: u8,
    max_age: u8,
) -> Result<(), u32> {
    let mut state = NETBRIDGE_STATE.lock();

    let bridge = state.bridges.iter_mut().find(|b| b.active && b.id == bridge_id);

    match bridge {
        Some(b) => {
            b.stp_enabled = enabled;
            b.stp_priority = priority;
            b.forward_delay = forward_delay;
            b.max_age = max_age;
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Set MAC aging time
pub fn set_mac_aging_time(bridge_id: u32, aging_time: u32) -> Result<(), u32> {
    let mut state = NETBRIDGE_STATE.lock();

    let bridge = state.bridges.iter_mut().find(|b| b.active && b.id == bridge_id);

    match bridge {
        Some(b) => {
            b.mac_aging_time = aging_time.max(10).min(1000000);
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Get bridge count
pub fn get_bridge_count() -> u32 {
    BRIDGE_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// Adapter Functions
// ============================================================================

/// Register an adapter
pub fn register_adapter(
    name: &[u8],
    description: &[u8],
    mac_address: [u8; MAC_LEN],
    adapter_type: AdapterType,
) -> Result<u32, u32> {
    let mut state = NETBRIDGE_STATE.lock();

    let slot = state.adapters.iter().position(|a| !a.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let adapter = &mut state.adapters[slot];
    adapter.id = id;
    adapter.active = true;

    let name_len = name.len().min(MAX_NAME_LEN);
    adapter.name[..name_len].copy_from_slice(&name[..name_len]);
    adapter.name_len = name_len;

    let desc_len = description.len().min(MAX_NAME_LEN);
    adapter.description[..desc_len].copy_from_slice(&description[..desc_len]);
    adapter.desc_len = desc_len;

    adapter.mac_address = mac_address;
    adapter.adapter_type = adapter_type;
    adapter.state = AdapterState::Disconnected;
    adapter.bridgeable = true;

    state.stats.total_adapters += 1;
    ADAPTER_COUNT.fetch_add(1, Ordering::Relaxed);

    Ok(id)
}

/// Unregister an adapter
pub fn unregister_adapter(adapter_id: u32) -> Result<(), u32> {
    let mut state = NETBRIDGE_STATE.lock();

    // Find adapter index
    let adapter_idx = state.adapters.iter().position(|a| a.active && a.id == adapter_id);
    let adapter_idx = match adapter_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    // Check if bridged before modifying
    let was_bridged = state.adapters[adapter_idx].bridge_id != 0;

    state.adapters[adapter_idx].active = false;

    // Update stats
    if was_bridged {
        state.stats.bridged_adapters = state.stats.bridged_adapters.saturating_sub(1);
    }
    state.stats.total_adapters = state.stats.total_adapters.saturating_sub(1);
    ADAPTER_COUNT.fetch_sub(1, Ordering::Relaxed);

    Ok(())
}

/// Add adapter to bridge
pub fn add_adapter_to_bridge(bridge_id: u32, adapter_id: u32) -> Result<(), u32> {
    let mut state = NETBRIDGE_STATE.lock();

    // Find bridge index
    let bridge_idx = state.bridges.iter().position(|b| b.active && b.id == bridge_id);
    let bridge_idx = match bridge_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    // Find adapter index
    let adapter_idx = state.adapters.iter().position(|a| a.active && a.id == adapter_id);
    let adapter_idx = match adapter_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    // Check if adapter is bridgeable
    if !state.adapters[adapter_idx].bridgeable {
        return Err(0x80070057);
    }

    // Check if adapter is already bridged
    if state.adapters[adapter_idx].bridge_id != 0 {
        return Err(0x80070005);
    }

    // Check bridge adapter limit
    if state.bridges[bridge_idx].adapter_count >= MAX_ADAPTERS_PER_BRIDGE as u32 {
        return Err(0x8007000E);
    }

    // Add adapter to bridge
    let count = state.bridges[bridge_idx].adapter_count as usize;
    state.bridges[bridge_idx].adapters[count] = adapter_id;
    state.bridges[bridge_idx].adapter_count += 1;

    state.adapters[adapter_idx].bridge_id = bridge_id;
    state.adapters[adapter_idx].stp_state = StpPortState::Listening;

    state.stats.bridged_adapters += 1;

    Ok(())
}

/// Remove adapter from bridge
pub fn remove_adapter_from_bridge(adapter_id: u32) -> Result<(), u32> {
    let mut state = NETBRIDGE_STATE.lock();

    // Find adapter index
    let adapter_idx = state.adapters.iter().position(|a| a.active && a.id == adapter_id);
    let adapter_idx = match adapter_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    let bridge_id = state.adapters[adapter_idx].bridge_id;
    if bridge_id == 0 {
        return Err(0x80070002); // Not bridged
    }

    // Find bridge index
    let bridge_idx = state.bridges.iter().position(|b| b.active && b.id == bridge_id);
    if let Some(bridge_idx) = bridge_idx {
        // Remove adapter from bridge's adapter list
        let count = state.bridges[bridge_idx].adapter_count as usize;
        for i in 0..count {
            if state.bridges[bridge_idx].adapters[i] == adapter_id {
                // Shift remaining adapters
                for j in i..count - 1 {
                    state.bridges[bridge_idx].adapters[j] = state.bridges[bridge_idx].adapters[j + 1];
                }
                state.bridges[bridge_idx].adapters[count - 1] = 0;
                state.bridges[bridge_idx].adapter_count -= 1;
                break;
            }
        }
    }

    state.adapters[adapter_idx].bridge_id = 0;
    state.adapters[adapter_idx].stp_state = StpPortState::Disabled;
    state.stats.bridged_adapters = state.stats.bridged_adapters.saturating_sub(1);

    Ok(())
}

/// Update adapter state
pub fn update_adapter_state(adapter_id: u32, state_val: AdapterState, speed: u32) -> Result<(), u32> {
    let mut state = NETBRIDGE_STATE.lock();

    let adapter = state.adapters.iter_mut().find(|a| a.active && a.id == adapter_id);

    match adapter {
        Some(a) => {
            a.state = state_val;
            a.speed_mbps = speed;
            // Calculate STP path cost based on speed
            a.stp_path_cost = if speed > 0 { 20000000 / speed } else { 0 };
            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Get adapter count
pub fn get_adapter_count() -> u32 {
    ADAPTER_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// MAC Table Functions
// ============================================================================

/// Learn a MAC address
pub fn learn_mac(
    bridge_id: u32,
    adapter_id: u32,
    mac_address: [u8; MAC_LEN],
) -> Result<u32, u32> {
    let mut state = NETBRIDGE_STATE.lock();

    // Check if entry already exists
    for entry in state.mac_table.iter_mut() {
        if entry.active && entry.bridge_id == bridge_id && entry.mac_address == mac_address {
            entry.adapter_id = adapter_id;
            entry.last_seen = 0;
            entry.hit_count += 1;
            return Ok(entry.id);
        }
    }

    // Add new entry
    let slot = state.mac_table.iter().position(|e| !e.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let entry = &mut state.mac_table[slot];
    entry.id = id;
    entry.active = true;
    entry.mac_address = mac_address;
    entry.bridge_id = bridge_id;
    entry.adapter_id = adapter_id;
    entry.entry_type = MacEntryType::Dynamic;
    entry.last_seen = 0;
    entry.hit_count = 1;

    state.stats.mac_entries += 1;

    // Update bridge MAC table size
    if let Some(b) = state.bridges.iter_mut().find(|b| b.active && b.id == bridge_id) {
        b.mac_table_size += 1;
    }

    Ok(id)
}

/// Add static MAC entry
pub fn add_static_mac(
    bridge_id: u32,
    adapter_id: u32,
    mac_address: [u8; MAC_LEN],
) -> Result<u32, u32> {
    let mut state = NETBRIDGE_STATE.lock();

    let slot = state.mac_table.iter().position(|e| !e.active);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let id = state.next_id;
    state.next_id += 1;

    let entry = &mut state.mac_table[slot];
    entry.id = id;
    entry.active = true;
    entry.mac_address = mac_address;
    entry.bridge_id = bridge_id;
    entry.adapter_id = adapter_id;
    entry.entry_type = MacEntryType::Static;
    entry.last_seen = 0;
    entry.hit_count = 0;

    state.stats.mac_entries += 1;

    Ok(id)
}

/// Remove MAC entry
pub fn remove_mac_entry(entry_id: u32) -> Result<(), u32> {
    let mut state = NETBRIDGE_STATE.lock();

    let entry = state.mac_table.iter_mut().find(|e| e.active && e.id == entry_id);

    match entry {
        Some(e) => {
            let bridge_id = e.bridge_id;
            e.active = false;
            state.stats.mac_entries = state.stats.mac_entries.saturating_sub(1);

            // Update bridge MAC table size
            if let Some(b) = state.bridges.iter_mut().find(|b| b.active && b.id == bridge_id) {
                b.mac_table_size = b.mac_table_size.saturating_sub(1);
            }

            Ok(())
        }
        None => Err(0x80070002),
    }
}

/// Flush MAC table for a bridge
pub fn flush_mac_table(bridge_id: u32, dynamic_only: bool) -> Result<u32, u32> {
    let mut state = NETBRIDGE_STATE.lock();

    let mut count = 0u32;

    for entry in state.mac_table.iter_mut() {
        if entry.active && entry.bridge_id == bridge_id {
            if !dynamic_only || entry.entry_type == MacEntryType::Dynamic {
                entry.active = false;
                count += 1;
            }
        }
    }

    state.stats.mac_entries = state.stats.mac_entries.saturating_sub(count);

    // Update bridge MAC table size
    if let Some(b) = state.bridges.iter_mut().find(|b| b.active && b.id == bridge_id) {
        b.mac_table_size = b.mac_table_size.saturating_sub(count);
    }

    Ok(count)
}

// ============================================================================
// Statistics Functions
// ============================================================================

/// Record packet forwarded
pub fn record_packet_forwarded(bridge_id: u32) {
    let mut state = NETBRIDGE_STATE.lock();

    if let Some(b) = state.bridges.iter_mut().find(|b| b.active && b.id == bridge_id) {
        b.packets_forwarded += 1;
        state.stats.packets_forwarded += 1;
        TOTAL_FORWARDED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record packet dropped
pub fn record_packet_dropped(bridge_id: u32) {
    let mut state = NETBRIDGE_STATE.lock();

    if let Some(b) = state.bridges.iter_mut().find(|b| b.active && b.id == bridge_id) {
        b.packets_dropped += 1;
        state.stats.packets_dropped += 1;
    }
}

/// Get bridge statistics
pub fn get_statistics() -> BridgeStatistics {
    let state = NETBRIDGE_STATE.lock();
    BridgeStatistics {
        total_bridges: state.stats.total_bridges,
        active_bridges: state.stats.active_bridges,
        total_adapters: state.stats.total_adapters,
        bridged_adapters: state.stats.bridged_adapters,
        mac_entries: state.stats.mac_entries,
        packets_forwarded: state.stats.packets_forwarded,
        packets_dropped: state.stats.packets_dropped,
    }
}

/// Get total packets forwarded
pub fn get_total_forwarded() -> u64 {
    TOTAL_FORWARDED.load(Ordering::Relaxed)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Network Bridge module
pub fn init() -> Result<(), &'static str> {
    if NETBRIDGE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let mut state = NETBRIDGE_STATE.lock();

    // Reserve IDs for example entries
    let adapter1_id = state.next_id;
    let adapter2_id = state.next_id + 1;
    state.next_id += 2;

    // Create example Ethernet adapter
    {
        let adapter = &mut state.adapters[0];
        adapter.id = adapter1_id;
        adapter.active = true;
        let name = b"Local Area Connection";
        adapter.name[..name.len()].copy_from_slice(name);
        adapter.name_len = name.len();
        let desc = b"Intel PRO/1000 MT Network Connection";
        adapter.description[..desc.len()].copy_from_slice(desc);
        adapter.desc_len = desc.len();
        adapter.mac_address = [0x00, 0x0C, 0x29, 0x01, 0x02, 0x03];
        adapter.adapter_type = AdapterType::Ethernet;
        adapter.state = AdapterState::Connected;
        adapter.speed_mbps = 1000;
        adapter.bridgeable = true;
    }

    // Create example Wireless adapter
    {
        let adapter = &mut state.adapters[1];
        adapter.id = adapter2_id;
        adapter.active = true;
        let name = b"Wireless Network Connection";
        adapter.name[..name.len()].copy_from_slice(name);
        adapter.name_len = name.len();
        let desc = b"Intel PRO/Wireless 2200BG";
        adapter.description[..desc.len()].copy_from_slice(desc);
        adapter.desc_len = desc.len();
        adapter.mac_address = [0x00, 0x16, 0x6F, 0x04, 0x05, 0x06];
        adapter.adapter_type = AdapterType::Wireless;
        adapter.state = AdapterState::Connected;
        adapter.speed_mbps = 54;
        adapter.bridgeable = true;
    }

    state.stats.total_adapters = 2;
    ADAPTER_COUNT.store(2, Ordering::Relaxed);

    Ok(())
}

/// Check if module is initialized
pub fn is_initialized() -> bool {
    NETBRIDGE_INITIALIZED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_status() {
        assert_eq!(BridgeStatus::default(), BridgeStatus::Disabled);
        assert_eq!(BridgeStatus::Enabled as u32, 1);
    }

    #[test]
    fn test_adapter_type() {
        assert_eq!(AdapterType::default(), AdapterType::Ethernet);
        assert_eq!(AdapterType::Wireless as u32, 1);
    }

    #[test]
    fn test_stp_port_state() {
        assert_eq!(StpPortState::default(), StpPortState::Disabled);
        assert_eq!(StpPortState::Forwarding as u32, 3);
    }
}
