//! Network Connections
//!
//! Kernel-mode network connections folder following Windows NT patterns.
//! Provides network adapter configuration, status, and connection management.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `net/config/netcfg/` - Network configuration
//! - `shell/cpls/ncpa/` - Network control panel applet

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// Maximum network adapters
const MAX_ADAPTERS: usize = 16;

/// Maximum adapter name length
const MAX_NAME: usize = 256;

/// Maximum description length
const MAX_DESC: usize = 256;

/// Maximum IP addresses per adapter
const MAX_IPS: usize = 8;

/// Maximum DNS servers
const MAX_DNS: usize = 4;

/// Maximum WINS servers
const MAX_WINS: usize = 2;

/// Connection status
pub mod connection_status {
    /// Not connected
    pub const DISCONNECTED: u32 = 0;
    /// Connecting
    pub const CONNECTING: u32 = 1;
    /// Connected
    pub const CONNECTED: u32 = 2;
    /// Disconnecting
    pub const DISCONNECTING: u32 = 3;
    /// Hardware not present
    pub const HARDWARE_NOT_PRESENT: u32 = 4;
    /// Hardware disabled
    pub const HARDWARE_DISABLED: u32 = 5;
    /// Hardware malfunction
    pub const HARDWARE_MALFUNCTION: u32 = 6;
    /// Media disconnected
    pub const MEDIA_DISCONNECTED: u32 = 7;
    /// Authenticating
    pub const AUTHENTICATING: u32 = 8;
    /// Authentication failed
    pub const AUTH_FAILED: u32 = 9;
    /// Invalid address
    pub const INVALID_ADDRESS: u32 = 10;
    /// Credentials required
    pub const CREDENTIALS_REQUIRED: u32 = 11;
}

/// Adapter type
pub mod adapter_type {
    /// Ethernet
    pub const ETHERNET: u32 = 6;
    /// Token Ring
    pub const TOKEN_RING: u32 = 9;
    /// PPP
    pub const PPP: u32 = 23;
    /// Loopback
    pub const LOOPBACK: u32 = 24;
    /// ATM
    pub const ATM: u32 = 37;
    /// IEEE 802.11 Wireless
    pub const IEEE80211: u32 = 71;
    /// Tunnel
    pub const TUNNEL: u32 = 131;
    /// IEEE 1394 (FireWire)
    pub const IEEE1394: u32 = 144;
}

/// IP configuration mode
pub mod ip_mode {
    /// DHCP
    pub const DHCP: u32 = 0;
    /// Static/Manual
    pub const STATIC: u32 = 1;
}

/// Connection flags
pub mod connection_flags {
    /// Show icon in notification area
    pub const SHOW_ICON: u32 = 0x0001;
    /// Notify when connected
    pub const NOTIFY_CONNECTED: u32 = 0x0002;
    /// Notify when disconnected
    pub const NOTIFY_DISCONNECTED: u32 = 0x0004;
    /// All users can modify
    pub const ALL_USERS: u32 = 0x0008;
    /// Is incoming connection
    pub const INCOMING: u32 = 0x0010;
    /// Is VPN connection
    pub const VPN: u32 = 0x0020;
    /// Is dial-up connection
    pub const DIALUP: u32 = 0x0040;
    /// Is LAN connection
    pub const LAN: u32 = 0x0080;
    /// Is bridge
    pub const BRIDGE: u32 = 0x0100;
    /// Is shared
    pub const SHARED: u32 = 0x0200;
    /// Firewall enabled
    pub const FIREWALL: u32 = 0x0400;
    /// Default connection
    pub const DEFAULT: u32 = 0x0800;
}

// ============================================================================
// Types
// ============================================================================

/// IPv4 address
#[derive(Clone, Copy, Default)]
pub struct Ipv4Address {
    pub octets: [u8; 4],
}

impl Ipv4Address {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self { octets: [a, b, c, d] }
    }

    pub const fn any() -> Self {
        Self { octets: [0, 0, 0, 0] }
    }

    pub const fn loopback() -> Self {
        Self { octets: [127, 0, 0, 1] }
    }
}

/// IP configuration for an adapter
#[derive(Clone, Copy)]
pub struct IpConfig {
    /// IP configuration mode (DHCP or static)
    pub mode: u32,
    /// IP addresses
    pub addresses: [Ipv4Address; MAX_IPS],
    /// Subnet masks
    pub masks: [Ipv4Address; MAX_IPS],
    /// Address count
    pub address_count: u8,
    /// Default gateway
    pub gateway: Ipv4Address,
    /// Gateway metric
    pub gateway_metric: u32,
    /// DNS servers
    pub dns: [Ipv4Address; MAX_DNS],
    /// DNS count
    pub dns_count: u8,
    /// WINS servers
    pub wins: [Ipv4Address; MAX_WINS],
    /// WINS count
    pub wins_count: u8,
    /// Register DNS
    pub register_dns: bool,
    /// Use DNS suffix
    pub use_dns_suffix: bool,
    /// DNS suffix
    pub dns_suffix: [u8; 256],
    /// DNS suffix length
    pub suffix_len: u8,
}

impl IpConfig {
    pub const fn new() -> Self {
        Self {
            mode: ip_mode::DHCP,
            addresses: [Ipv4Address::any(); MAX_IPS],
            masks: [Ipv4Address::any(); MAX_IPS],
            address_count: 0,
            gateway: Ipv4Address::any(),
            gateway_metric: 1,
            dns: [Ipv4Address::any(); MAX_DNS],
            dns_count: 0,
            wins: [Ipv4Address::any(); MAX_WINS],
            wins_count: 0,
            register_dns: true,
            use_dns_suffix: false,
            dns_suffix: [0; 256],
            suffix_len: 0,
        }
    }
}

/// Network adapter information
#[derive(Clone, Copy)]
pub struct NetworkAdapter {
    /// Adapter name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: u16,
    /// Description
    pub description: [u8; MAX_DESC],
    /// Description length
    pub desc_len: u16,
    /// Adapter type
    pub adapter_type: u32,
    /// MAC address
    pub mac: [u8; 6],
    /// Connection status
    pub status: u32,
    /// Connection flags
    pub flags: u32,
    /// Speed (Mbps)
    pub speed: u32,
    /// MTU
    pub mtu: u32,
    /// IP configuration
    pub ip_config: IpConfig,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Errors
    pub errors: u32,
    /// Is enabled
    pub enabled: bool,
}

impl NetworkAdapter {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            description: [0; MAX_DESC],
            desc_len: 0,
            adapter_type: adapter_type::ETHERNET,
            mac: [0; 6],
            status: connection_status::DISCONNECTED,
            flags: connection_flags::LAN | connection_flags::SHOW_ICON,
            speed: 0,
            mtu: 1500,
            ip_config: IpConfig::new(),
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            errors: 0,
            enabled: true,
        }
    }
}

/// Network connections dialog state
struct NetConnDialog {
    /// Parent window
    parent: HWND,
    /// Selected adapter index
    selected: i32,
    /// View mode
    view_mode: u32,
}

impl NetConnDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            selected: -1,
            view_mode: 0,
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Network adapters
static ADAPTERS: SpinLock<[NetworkAdapter; MAX_ADAPTERS]> =
    SpinLock::new([const { NetworkAdapter::new() }; MAX_ADAPTERS]);

/// Adapter count
static ADAPTER_COUNT: AtomicU32 = AtomicU32::new(0);

/// Dialog state
static DIALOG: SpinLock<NetConnDialog> = SpinLock::new(NetConnDialog::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize network connections
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Initialize default adapters
    init_default_adapters();

    crate::serial_println!("[NETCONNECT] Network connections initialized");
}

/// Initialize default network adapters
fn init_default_adapters() {
    let mut adapters = ADAPTERS.lock();
    let mut count = 0;

    // Local Area Connection
    {
        let adapter = &mut adapters[count];
        let name = b"Local Area Connection";
        let nlen = name.len();
        adapter.name[..nlen].copy_from_slice(name);
        adapter.name_len = nlen as u16;

        let desc = b"Intel(R) PRO/1000 MT Network Connection";
        let dlen = desc.len();
        adapter.description[..dlen].copy_from_slice(desc);
        adapter.desc_len = dlen as u16;

        adapter.adapter_type = adapter_type::ETHERNET;
        adapter.mac = [0x00, 0x0C, 0x29, 0x12, 0x34, 0x56];
        adapter.status = connection_status::CONNECTED;
        adapter.flags = connection_flags::LAN | connection_flags::SHOW_ICON;
        adapter.speed = 1000;
        adapter.mtu = 1500;
        adapter.enabled = true;

        // DHCP configuration
        adapter.ip_config.mode = ip_mode::DHCP;
        adapter.ip_config.addresses[0] = Ipv4Address::new(192, 168, 1, 100);
        adapter.ip_config.masks[0] = Ipv4Address::new(255, 255, 255, 0);
        adapter.ip_config.address_count = 1;
        adapter.ip_config.gateway = Ipv4Address::new(192, 168, 1, 1);
        adapter.ip_config.dns[0] = Ipv4Address::new(8, 8, 8, 8);
        adapter.ip_config.dns[1] = Ipv4Address::new(8, 8, 4, 4);
        adapter.ip_config.dns_count = 2;

        count += 1;
    }

    // Loopback
    {
        let adapter = &mut adapters[count];
        let name = b"Loopback Pseudo-Interface";
        let nlen = name.len();
        adapter.name[..nlen].copy_from_slice(name);
        adapter.name_len = nlen as u16;

        let desc = b"Software Loopback Interface 1";
        let dlen = desc.len();
        adapter.description[..dlen].copy_from_slice(desc);
        adapter.desc_len = dlen as u16;

        adapter.adapter_type = adapter_type::LOOPBACK;
        adapter.mac = [0; 6];
        adapter.status = connection_status::CONNECTED;
        adapter.flags = connection_flags::LAN;
        adapter.speed = 0;
        adapter.mtu = 65536;
        adapter.enabled = true;

        adapter.ip_config.mode = ip_mode::STATIC;
        adapter.ip_config.addresses[0] = Ipv4Address::loopback();
        adapter.ip_config.masks[0] = Ipv4Address::new(255, 0, 0, 0);
        adapter.ip_config.address_count = 1;

        count += 1;
    }

    ADAPTER_COUNT.store(count as u32, Ordering::Release);
}

// ============================================================================
// Adapter Management
// ============================================================================

/// Get number of network adapters
pub fn get_adapter_count() -> u32 {
    ADAPTER_COUNT.load(Ordering::Acquire)
}

/// Get adapter by index
pub fn get_adapter(index: usize, adapter: &mut NetworkAdapter) -> bool {
    let adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    *adapter = adapters[index];
    true
}

/// Find adapter by name
pub fn find_adapter(name: &[u8]) -> Option<usize> {
    let adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = adapters[i].name_len as usize;
        if &adapters[i].name[..len] == name {
            return Some(i);
        }
    }
    None
}

/// Enable or disable an adapter
pub fn set_adapter_enabled(index: usize, enabled: bool) -> bool {
    let mut adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    adapters[index].enabled = enabled;
    if !enabled {
        adapters[index].status = connection_status::HARDWARE_DISABLED;
    } else {
        adapters[index].status = connection_status::DISCONNECTED;
        // Would trigger reconnection
    }

    true
}

/// Rename an adapter
pub fn rename_adapter(index: usize, new_name: &[u8]) -> bool {
    let mut adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    let nlen = new_name.len().min(MAX_NAME);
    adapters[index].name[..nlen].copy_from_slice(&new_name[..nlen]);
    adapters[index].name_len = nlen as u16;

    true
}

/// Get adapter IP configuration
pub fn get_ip_config(index: usize, config: &mut IpConfig) -> bool {
    let adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    *config = adapters[index].ip_config;
    true
}

/// Set adapter IP configuration
pub fn set_ip_config(index: usize, config: &IpConfig) -> bool {
    let mut adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    adapters[index].ip_config = *config;
    // Would apply configuration to network stack

    true
}

/// Release DHCP lease
pub fn release_dhcp(index: usize) -> bool {
    let mut adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    if adapters[index].ip_config.mode != ip_mode::DHCP {
        return false;
    }

    // Clear IP configuration
    adapters[index].ip_config.addresses[0] = Ipv4Address::any();
    adapters[index].ip_config.address_count = 0;
    adapters[index].status = connection_status::DISCONNECTED;

    true
}

/// Renew DHCP lease
pub fn renew_dhcp(index: usize) -> bool {
    let adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    if adapters[index].ip_config.mode != ip_mode::DHCP {
        return false;
    }

    // Would send DHCP request
    true
}

/// Get adapter statistics
pub fn get_adapter_stats(index: usize) -> Option<(u64, u64, u64, u64, u32)> {
    let adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return None;
    }

    let a = &adapters[index];
    Some((a.bytes_sent, a.bytes_received, a.packets_sent, a.packets_received, a.errors))
}

/// Reset adapter statistics
pub fn reset_adapter_stats(index: usize) -> bool {
    let mut adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    adapters[index].bytes_sent = 0;
    adapters[index].bytes_received = 0;
    adapters[index].packets_sent = 0;
    adapters[index].packets_received = 0;
    adapters[index].errors = 0;

    true
}

// ============================================================================
// Connection Operations
// ============================================================================

/// Connect an adapter
pub fn connect(index: usize) -> bool {
    let mut adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    if !adapters[index].enabled {
        return false;
    }

    adapters[index].status = connection_status::CONNECTING;
    // Would initiate connection process

    true
}

/// Disconnect an adapter
pub fn disconnect(index: usize) -> bool {
    let mut adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    adapters[index].status = connection_status::DISCONNECTING;
    // Would initiate disconnection

    adapters[index].status = connection_status::DISCONNECTED;

    true
}

/// Check if any adapter is connected
pub fn is_connected() -> bool {
    let adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        if adapters[i].status == connection_status::CONNECTED {
            return true;
        }
    }
    false
}

/// Get default gateway
pub fn get_default_gateway() -> Ipv4Address {
    let adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        if adapters[i].status == connection_status::CONNECTED {
            return adapters[i].ip_config.gateway;
        }
    }
    Ipv4Address::any()
}

// ============================================================================
// Internet Connection Sharing
// ============================================================================

/// Enable ICS on an adapter
pub fn enable_ics(index: usize) -> bool {
    let mut adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    adapters[index].flags |= connection_flags::SHARED;
    // Would configure NAT and DHCP for ICS

    true
}

/// Disable ICS on an adapter
pub fn disable_ics(index: usize) -> bool {
    let mut adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    adapters[index].flags &= !connection_flags::SHARED;

    true
}

/// Check if ICS is enabled on any adapter
pub fn is_ics_enabled() -> bool {
    let adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        if adapters[i].flags & connection_flags::SHARED != 0 {
            return true;
        }
    }
    false
}

// ============================================================================
// Network Bridge
// ============================================================================

/// Create a network bridge
pub fn create_bridge(adapter_indices: &[usize]) -> bool {
    if adapter_indices.len() < 2 {
        return false;
    }

    let mut adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    for &index in adapter_indices {
        if index >= count {
            return false;
        }
        adapters[index].flags |= connection_flags::BRIDGE;
    }

    // Would create bridge interface

    true
}

/// Remove network bridge
pub fn remove_bridge() -> bool {
    let mut adapters = ADAPTERS.lock();
    let count = ADAPTER_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        adapters[i].flags &= !connection_flags::BRIDGE;
    }

    true
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show network connections folder
pub fn show_network_connections(parent: HWND) -> bool {
    let mut dialog = DIALOG.lock();

    dialog.parent = parent;
    dialog.selected = -1;
    dialog.view_mode = 0;

    // Would show explorer-style folder with:
    // - Connection icons with status
    // - Create new connection wizard
    // - Bridge connections option

    true
}

/// Show adapter properties
pub fn show_adapter_properties(parent: HWND, index: usize) -> bool {
    let _ = (parent, index);
    // Would show adapter properties dialog with:
    // - General tab (connection status)
    // - Advanced tab (protocol bindings)
    // - TCP/IP properties

    true
}

/// Show adapter status
pub fn show_adapter_status(parent: HWND, index: usize) -> bool {
    let _ = (parent, index);
    // Would show connection status dialog with statistics

    true
}

/// Show new connection wizard
pub fn show_new_connection_wizard(parent: HWND) -> bool {
    let _ = parent;
    // Would show wizard for creating new connections
    true
}
