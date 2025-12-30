//! Network Device Abstraction
//!
//! Provides the base abstraction for network interface cards (NICs).
//! In Windows NT, this would be part of NDIS (Network Driver Interface Specification).

extern crate alloc;

use super::ethernet::MacAddress;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

/// Network device state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NetworkDeviceState {
    /// Device is not initialized
    NotInitialized = 0,
    /// Device is initializing
    Initializing = 1,
    /// Device is ready but not connected
    Disconnected = 2,
    /// Device is connected and ready
    Connected = 3,
    /// Device is in error state
    Error = 4,
    /// Device is being reset
    Resetting = 5,
    /// Device is being removed
    Removing = 6,
}

impl From<u32> for NetworkDeviceState {
    fn from(v: u32) -> Self {
        match v {
            0 => NetworkDeviceState::NotInitialized,
            1 => NetworkDeviceState::Initializing,
            2 => NetworkDeviceState::Disconnected,
            3 => NetworkDeviceState::Connected,
            4 => NetworkDeviceState::Error,
            5 => NetworkDeviceState::Resetting,
            6 => NetworkDeviceState::Removing,
            _ => NetworkDeviceState::NotInitialized,
        }
    }
}

/// Device capabilities flags
pub mod device_caps {
    /// Device supports checksum offload for TX
    pub const TX_CHECKSUM: u32 = 0x0001;
    /// Device supports checksum offload for RX
    pub const RX_CHECKSUM: u32 = 0x0002;
    /// Device supports scatter-gather DMA
    pub const SCATTER_GATHER: u32 = 0x0004;
    /// Device supports VLAN tagging
    pub const VLAN: u32 = 0x0008;
    /// Device supports wake-on-LAN
    pub const WAKE_ON_LAN: u32 = 0x0010;
    /// Device supports jumbo frames
    pub const JUMBO_FRAMES: u32 = 0x0020;
    /// Device supports promiscuous mode
    pub const PROMISCUOUS: u32 = 0x0040;
    /// Device supports multicast filtering
    pub const MULTICAST: u32 = 0x0080;
}

/// Device capabilities
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceCapabilities {
    /// Capability flags (see device_caps module)
    pub flags: u32,
    /// Maximum transmission unit
    pub mtu: u32,
    /// Maximum frame size
    pub max_frame_size: u32,
    /// Link speed in Mbps
    pub link_speed: u32,
}

impl DeviceCapabilities {
    pub fn has_capability(&self, cap: u32) -> bool {
        self.flags & cap != 0
    }
}

/// Network device information
#[derive(Debug, Clone)]
pub struct NetworkDeviceInfo {
    /// Device name (e.g., "eth0", "Intel PRO/1000")
    pub name: String,
    /// MAC address
    pub mac_address: MacAddress,
    /// Device capabilities
    pub capabilities: DeviceCapabilities,
    /// Vendor ID (PCI)
    pub vendor_id: u16,
    /// Device ID (PCI)
    pub device_id: u16,
}

impl NetworkDeviceInfo {
    pub fn new(name: &str, mac: MacAddress) -> Self {
        Self {
            name: String::from(name),
            mac_address: mac,
            capabilities: DeviceCapabilities {
                flags: 0,
                mtu: super::ETHERNET_MTU as u32,
                max_frame_size: super::MAX_PACKET_SIZE as u32,
                link_speed: 1000, // Default 1Gbps
            },
            vendor_id: 0,
            device_id: 0,
        }
    }
}

/// Network device statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceStatistics {
    /// Packets received
    pub rx_packets: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Receive errors
    pub rx_errors: u64,
    /// Transmit errors
    pub tx_errors: u64,
    /// Dropped receive packets
    pub rx_dropped: u64,
    /// Dropped transmit packets
    pub tx_dropped: u64,
    /// Multicast packets received
    pub rx_multicast: u64,
    /// Collisions
    pub collisions: u64,
}

/// Transmit callback type
pub type TxCallback = fn(device: &NetworkDevice, packet: &[u8]) -> Result<usize, &'static str>;

/// Network device
pub struct NetworkDevice {
    /// Device information
    pub info: NetworkDeviceInfo,
    /// Current state
    state: AtomicU32,
    /// Is promiscuous mode enabled
    pub promiscuous: AtomicBool,
    /// Device statistics
    pub stats: DeviceStatistics,
    /// IP address (if assigned)
    pub ip_address: Option<super::ip::Ipv4Address>,
    /// Subnet mask
    pub subnet_mask: Option<super::ip::Ipv4Address>,
    /// Default gateway
    pub gateway: Option<super::ip::Ipv4Address>,
    /// Transmit callback (driver-specific)
    pub tx_callback: Option<TxCallback>,
    /// Driver-specific data pointer
    pub driver_data: *mut u8,
}

// Safety: NetworkDevice uses atomics for shared state
unsafe impl Sync for NetworkDevice {}
unsafe impl Send for NetworkDevice {}

impl NetworkDevice {
    /// Create a new network device
    pub fn new(info: NetworkDeviceInfo) -> Self {
        Self {
            info,
            state: AtomicU32::new(NetworkDeviceState::NotInitialized as u32),
            promiscuous: AtomicBool::new(false),
            stats: DeviceStatistics::default(),
            ip_address: None,
            subnet_mask: None,
            gateway: None,
            tx_callback: None,
            driver_data: core::ptr::null_mut(),
        }
    }

    /// Get current device state
    pub fn state(&self) -> NetworkDeviceState {
        NetworkDeviceState::from(self.state.load(Ordering::SeqCst))
    }

    /// Set device state
    pub fn set_state(&self, state: NetworkDeviceState) {
        self.state.store(state as u32, Ordering::SeqCst);
    }

    /// Check if device is connected
    pub fn is_connected(&self) -> bool {
        self.state() == NetworkDeviceState::Connected
    }

    /// Check if device is ready to send/receive
    pub fn is_ready(&self) -> bool {
        matches!(self.state(), NetworkDeviceState::Connected | NetworkDeviceState::Disconnected)
    }

    /// Enable promiscuous mode
    pub fn set_promiscuous(&self, enabled: bool) {
        self.promiscuous.store(enabled, Ordering::SeqCst);
    }

    /// Check if promiscuous mode is enabled
    pub fn is_promiscuous(&self) -> bool {
        self.promiscuous.load(Ordering::SeqCst)
    }

    /// Set IP configuration
    pub fn set_ip_config(
        &mut self,
        ip: super::ip::Ipv4Address,
        mask: super::ip::Ipv4Address,
        gateway: Option<super::ip::Ipv4Address>,
    ) {
        self.ip_address = Some(ip);
        self.subnet_mask = Some(mask);
        self.gateway = gateway;
        crate::serial_println!(
            "[NET] Device {} configured: IP={:?}, Mask={:?}, GW={:?}",
            self.info.name,
            ip,
            mask,
            gateway
        );
    }

    /// Transmit a packet
    pub fn transmit(&mut self, packet: &[u8]) -> Result<usize, &'static str> {
        if !self.is_ready() {
            return Err("Device not ready");
        }

        if packet.len() > self.info.capabilities.max_frame_size as usize {
            return Err("Packet too large");
        }

        if let Some(callback) = self.tx_callback {
            let result = callback(self, packet);
            if result.is_ok() {
                self.stats.tx_packets += 1;
                self.stats.tx_bytes += packet.len() as u64;
            } else {
                self.stats.tx_errors += 1;
            }
            result
        } else {
            Err("No transmit callback registered")
        }
    }

    /// Record a received packet
    pub fn record_rx(&mut self, bytes: usize) {
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += bytes as u64;
    }

    /// Record a receive error
    pub fn record_rx_error(&mut self) {
        self.stats.rx_errors += 1;
    }
}
