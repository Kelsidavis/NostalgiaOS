//! Network Subsystem
//!
//! The Windows NT network stack is layered:
//! - NDIS (Network Driver Interface Specification) - NIC drivers
//! - TDI (Transport Driver Interface) - Transport protocols
//! - Winsock Kernel (WSK) - Socket interface
//!
//! This module provides the foundation for the network stack.

extern crate alloc;

pub mod device;
pub mod ethernet;
pub mod arp;
pub mod ip;
pub mod icmp;
pub mod udp;
pub mod dns;
pub mod dhcp;
pub mod tcp;
pub mod http;
pub mod telnet;
pub mod httpd;
pub mod ntp;
pub mod wol;
pub mod tftp;
pub mod loopback;
pub mod ftp;
pub mod syslog;
pub mod smtp;
pub mod pop3;
pub mod snmp;
pub mod echo;
pub mod qotd;
pub mod time;
pub mod discard;
pub mod daytime;
pub mod finger;
pub mod whois;
pub mod ident;
pub mod tdi;
pub mod ndis;

use core::sync::atomic::{AtomicBool, Ordering};
use alloc::vec::Vec;
use crate::ke::SpinLock;

/// Maximum packet size (Ethernet MTU + headers)
pub const MAX_PACKET_SIZE: usize = 1536;

/// Standard Ethernet MTU
pub const ETHERNET_MTU: usize = 1500;

/// Minimum Ethernet frame size (excluding FCS)
pub const MIN_ETHERNET_FRAME: usize = 60;

// Re-export common types
pub use device::{NetworkDevice, NetworkDeviceInfo, NetworkDeviceState, DeviceCapabilities};
pub use ethernet::{EthernetHeader, EtherType, MacAddress, parse_ethernet_frame, create_ethernet_frame};
pub use arp::{ArpPacket, ArpOperation, arp_resolve, arp_announce};
pub use ip::{Ipv4Header, Ipv4Address, IpProtocol, parse_ipv4_header, create_ipv4_header};
pub use icmp::{IcmpHeader, IcmpType, handle_icmp_packet, send_icmp_echo_request};

/// Network subsystem statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkStats {
    /// Total packets received
    pub packets_received: u64,
    /// Total packets transmitted
    pub packets_transmitted: u64,
    /// Receive errors
    pub receive_errors: u64,
    /// Transmit errors
    pub transmit_errors: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Bytes transmitted
    pub bytes_transmitted: u64,
    /// ARP requests sent
    pub arp_requests: u64,
    /// ARP replies received
    pub arp_replies: u64,
    /// ICMP echo requests received
    pub icmp_echo_requests: u64,
    /// ICMP echo replies sent
    pub icmp_echo_replies: u64,
}

/// Global network statistics
static mut NETWORK_STATS: NetworkStats = NetworkStats {
    packets_received: 0,
    packets_transmitted: 0,
    receive_errors: 0,
    transmit_errors: 0,
    bytes_received: 0,
    bytes_transmitted: 0,
    arp_requests: 0,
    arp_replies: 0,
    icmp_echo_requests: 0,
    icmp_echo_replies: 0,
};

/// Network initialized flag
static NETWORK_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Registered network devices
static mut NETWORK_DEVICES: Option<Vec<NetworkDevice>> = None;
static DEVICE_LOCK: SpinLock<()> = SpinLock::new(());

/// Initialize the network subsystem
pub fn init() {
    crate::serial_println!("[NET] Initializing network subsystem...");

    // Initialize device list
    unsafe {
        NETWORK_DEVICES = Some(Vec::new());
    }

    // Initialize sub-modules
    arp::init();
    icmp::init();
    udp::init();
    tcp::init();
    dns::init();
    dhcp::init();
    http::init();
    telnet::init();
    httpd::init();
    ntp::init();
    wol::init();
    tftp::init();
    ftp::init();
    syslog::init();
    smtp::init();
    pop3::init();
    snmp::init();
    echo::init();
    qotd::init();
    time::init();
    discard::init();
    daytime::init();
    finger::init();
    whois::init();
    ident::init();
    tdi::init();
    ndis::init();

    NETWORK_INITIALIZED.store(true, Ordering::SeqCst);

    // Initialize loopback device
    if let Err(e) = loopback::init() {
        crate::serial_println!("[NET] Warning: Failed to initialize loopback: {}", e);
    }

    // Try to initialize VirtIO-NET driver (if available)
    match crate::drivers::virtio::net::init() {
        Ok(idx) => {
            crate::serial_println!("[NET] VirtIO-NET initialized as device {}", idx);
        }
        Err(e) => {
            crate::serial_println!("[NET] VirtIO-NET not available: {}", e);
        }
    }

    crate::serial_println!("[NET] Network subsystem initialized");
}

/// Check if network is initialized
pub fn is_initialized() -> bool {
    NETWORK_INITIALIZED.load(Ordering::SeqCst)
}

/// Register a network device
pub fn register_device(device: NetworkDevice) -> Result<usize, &'static str> {
    if !is_initialized() {
        return Err("Network not initialized");
    }

    let _guard = DEVICE_LOCK.lock();
    unsafe {
        if let Some(ref mut devices) = NETWORK_DEVICES {
            let index = devices.len();
            crate::serial_println!(
                "[NET] Registering device {}: {} ({:?})",
                index,
                device.info.name,
                device.info.mac_address
            );
            devices.push(device);
            Ok(index)
        } else {
            Err("Device list not initialized")
        }
    }
}

/// Get a network device by index
pub fn get_device(index: usize) -> Option<&'static NetworkDevice> {
    let _guard = DEVICE_LOCK.lock();
    unsafe {
        NETWORK_DEVICES.as_ref().and_then(|d| d.get(index))
    }
}

/// Get mutable network device by index
pub fn get_device_mut(index: usize) -> Option<&'static mut NetworkDevice> {
    let _guard = DEVICE_LOCK.lock();
    unsafe {
        NETWORK_DEVICES.as_mut().and_then(|d| d.get_mut(index))
    }
}

/// Get the number of registered devices
pub fn get_device_count() -> usize {
    let _guard = DEVICE_LOCK.lock();
    unsafe {
        NETWORK_DEVICES.as_ref().map(|d| d.len()).unwrap_or(0)
    }
}

/// Get network statistics
pub fn get_stats() -> NetworkStats {
    unsafe { NETWORK_STATS }
}

/// Update received packet statistics
pub fn record_rx_packet(bytes: usize) {
    unsafe {
        NETWORK_STATS.packets_received += 1;
        NETWORK_STATS.bytes_received += bytes as u64;
    }
}

/// Update transmitted packet statistics
pub fn record_tx_packet(bytes: usize) {
    unsafe {
        NETWORK_STATS.packets_transmitted += 1;
        NETWORK_STATS.bytes_transmitted += bytes as u64;
    }
}

/// Record a receive error
pub fn record_rx_error() {
    unsafe {
        NETWORK_STATS.receive_errors += 1;
    }
}

/// Record a transmit error
pub fn record_tx_error() {
    unsafe {
        NETWORK_STATS.transmit_errors += 1;
    }
}

/// Handle an incoming packet from a network device
pub fn handle_rx_packet(device_index: usize, packet: &[u8]) {
    if packet.len() < ethernet::ETHERNET_HEADER_SIZE {
        record_rx_error();
        return;
    }

    record_rx_packet(packet.len());

    // Parse Ethernet header
    let eth_header = match ethernet::parse_ethernet_frame(packet) {
        Some(h) => h,
        None => {
            record_rx_error();
            return;
        }
    };

    // Get payload (after Ethernet header)
    let payload = &packet[ethernet::ETHERNET_HEADER_SIZE..];

    // Handle based on EtherType
    match eth_header.ether_type {
        EtherType::Ipv4 => {
            if let Some(ip_header) = ip::parse_ipv4_header(payload) {
                handle_ip_packet(device_index, &eth_header, &ip_header, payload);
            }
        }
        EtherType::Arp => {
            if let Some(arp_packet) = arp::parse_arp_packet(payload) {
                arp::handle_arp_packet(device_index, &eth_header, &arp_packet);
            }
        }
        EtherType::Ipv6 => {
            // IPv6 not yet supported
            crate::serial_println!("[NET] IPv6 packet received (not supported)");
        }
        _ => {
            crate::serial_println!("[NET] Unknown EtherType: {:#06x}", eth_header.ether_type as u16);
        }
    }
}

/// Handle an incoming IP packet
fn handle_ip_packet(
    device_index: usize,
    eth_header: &EthernetHeader,
    ip_header: &Ipv4Header,
    data: &[u8],
) {
    let ip_header_len = (ip_header.version_ihl & 0x0F) as usize * 4;
    if data.len() < ip_header_len {
        return;
    }

    let ip_payload = &data[ip_header_len..];

    match ip_header.protocol {
        IpProtocol::Icmp => {
            if let Some(icmp) = icmp::parse_icmp_packet(ip_payload) {
                icmp::handle_icmp_packet(device_index, eth_header, ip_header, &icmp, ip_payload);
            }
        }
        IpProtocol::Tcp => {
            if let Some(tcp_header) = tcp::parse_tcp_header(ip_payload) {
                tcp::handle_tcp_packet(device_index, ip_header, &tcp_header, ip_payload);
            }
        }
        IpProtocol::Udp => {
            if let Some(udp_header) = udp::parse_udp_packet(ip_payload) {
                udp::handle_udp_packet(device_index, ip_header, &udp_header, ip_payload);
            }
        }
        _ => {
            crate::serial_println!(
                "[NET] IP protocol {} from {:?}",
                ip_header.protocol as u8,
                ip_header.source_addr
            );
        }
    }
}
