//! DHCP (Dynamic Host Configuration Protocol) Client
//!
//! RFC 2131 - Dynamic Host Configuration Protocol
//! Provides automatic IP address configuration.

extern crate alloc;

use super::ip::Ipv4Address;
use super::ethernet::MacAddress;
use super::udp;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

/// DHCP server port
pub const DHCP_SERVER_PORT: u16 = 67;
/// DHCP client port
pub const DHCP_CLIENT_PORT: u16 = 68;

/// DHCP packet size (minimum)
pub const DHCP_MIN_PACKET_SIZE: usize = 236;
/// DHCP options start offset
pub const DHCP_OPTIONS_OFFSET: usize = 236;
/// DHCP magic cookie
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// DHCP message types
pub mod message_type {
    pub const DISCOVER: u8 = 1;
    pub const OFFER: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const DECLINE: u8 = 4;
    pub const ACK: u8 = 5;
    pub const NAK: u8 = 6;
    pub const RELEASE: u8 = 7;
    pub const INFORM: u8 = 8;
}

/// DHCP option codes
pub mod option {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS_SERVER: u8 = 6;
    pub const HOSTNAME: u8 = 12;
    pub const DOMAIN_NAME: u8 = 15;
    pub const REQUESTED_IP: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAMETER_REQUEST: u8 = 55;
    pub const END: u8 = 255;
}

/// DHCP op codes
pub mod op {
    pub const BOOTREQUEST: u8 = 1;
    pub const BOOTREPLY: u8 = 2;
}

/// Hardware type for Ethernet
pub const HTYPE_ETHERNET: u8 = 1;

/// DHCP transaction ID counter
static XID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// DHCP lease information
#[derive(Debug, Clone, Copy)]
pub struct DhcpLease {
    /// Assigned IP address
    pub ip_address: Ipv4Address,
    /// Subnet mask
    pub subnet_mask: Ipv4Address,
    /// Default gateway/router
    pub gateway: Option<Ipv4Address>,
    /// DNS server
    pub dns_server: Option<Ipv4Address>,
    /// DHCP server that granted the lease
    pub server_id: Ipv4Address,
    /// Lease time in seconds
    pub lease_time: u32,
}

/// DHCP client state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

/// Build a DHCP DISCOVER packet
fn build_discover(mac: MacAddress, xid: u32) -> Vec<u8> {
    let mut packet = vec![0u8; 300];

    // BOOTP header
    packet[0] = op::BOOTREQUEST;  // op
    packet[1] = HTYPE_ETHERNET;   // htype
    packet[2] = 6;                // hlen (MAC address length)
    packet[3] = 0;                // hops

    // Transaction ID
    packet[4..8].copy_from_slice(&xid.to_be_bytes());

    // secs = 0, flags = 0x8000 (broadcast)
    packet[10] = 0x80;
    packet[11] = 0x00;

    // ciaddr, yiaddr, siaddr, giaddr = 0

    // chaddr (client hardware address)
    packet[28..34].copy_from_slice(&mac.0);

    // Skip sname (64 bytes) and file (128 bytes)

    // Magic cookie
    packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

    // DHCP options
    let mut opt_pos = 240;

    // Option 53: DHCP Message Type = DISCOVER
    packet[opt_pos] = option::MESSAGE_TYPE;
    packet[opt_pos + 1] = 1;
    packet[opt_pos + 2] = message_type::DISCOVER;
    opt_pos += 3;

    // Option 55: Parameter Request List
    packet[opt_pos] = option::PARAMETER_REQUEST;
    packet[opt_pos + 1] = 4;
    packet[opt_pos + 2] = option::SUBNET_MASK;
    packet[opt_pos + 3] = option::ROUTER;
    packet[opt_pos + 4] = option::DNS_SERVER;
    packet[opt_pos + 5] = option::LEASE_TIME;
    opt_pos += 6;

    // End option
    packet[opt_pos] = option::END;

    packet.truncate(opt_pos + 1);
    packet
}

/// Build a DHCP REQUEST packet
fn build_request(mac: MacAddress, xid: u32, requested_ip: Ipv4Address, server_id: Ipv4Address) -> Vec<u8> {
    let mut packet = vec![0u8; 300];

    // BOOTP header
    packet[0] = op::BOOTREQUEST;
    packet[1] = HTYPE_ETHERNET;
    packet[2] = 6;
    packet[3] = 0;

    // Transaction ID
    packet[4..8].copy_from_slice(&xid.to_be_bytes());

    // flags = 0x8000 (broadcast)
    packet[10] = 0x80;
    packet[11] = 0x00;

    // chaddr
    packet[28..34].copy_from_slice(&mac.0);

    // Magic cookie
    packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

    // DHCP options
    let mut opt_pos = 240;

    // Option 53: DHCP Message Type = REQUEST
    packet[opt_pos] = option::MESSAGE_TYPE;
    packet[opt_pos + 1] = 1;
    packet[opt_pos + 2] = message_type::REQUEST;
    opt_pos += 3;

    // Option 50: Requested IP Address
    packet[opt_pos] = option::REQUESTED_IP;
    packet[opt_pos + 1] = 4;
    packet[opt_pos + 2..opt_pos + 6].copy_from_slice(&requested_ip.0);
    opt_pos += 6;

    // Option 54: Server Identifier
    packet[opt_pos] = option::SERVER_ID;
    packet[opt_pos + 1] = 4;
    packet[opt_pos + 2..opt_pos + 6].copy_from_slice(&server_id.0);
    opt_pos += 6;

    // Option 55: Parameter Request List
    packet[opt_pos] = option::PARAMETER_REQUEST;
    packet[opt_pos + 1] = 4;
    packet[opt_pos + 2] = option::SUBNET_MASK;
    packet[opt_pos + 3] = option::ROUTER;
    packet[opt_pos + 4] = option::DNS_SERVER;
    packet[opt_pos + 5] = option::LEASE_TIME;
    opt_pos += 6;

    // End option
    packet[opt_pos] = option::END;

    packet.truncate(opt_pos + 1);
    packet
}

/// Parse DHCP options from a packet
fn parse_options(data: &[u8]) -> (Option<u8>, Option<Ipv4Address>, Option<Ipv4Address>, Option<Ipv4Address>, Option<Ipv4Address>, Option<u32>) {
    let mut msg_type = None;
    let mut subnet_mask = None;
    let mut router = None;
    let mut dns = None;
    let mut server_id = None;
    let mut lease_time = None;

    let mut pos = 0;
    while pos < data.len() {
        let opt = data[pos];

        if opt == option::PAD {
            pos += 1;
            continue;
        }

        if opt == option::END {
            break;
        }

        if pos + 1 >= data.len() {
            break;
        }

        let len = data[pos + 1] as usize;
        if pos + 2 + len > data.len() {
            break;
        }

        let value = &data[pos + 2..pos + 2 + len];

        match opt {
            option::MESSAGE_TYPE if len >= 1 => {
                msg_type = Some(value[0]);
            }
            option::SUBNET_MASK if len >= 4 => {
                subnet_mask = Some(Ipv4Address::new([value[0], value[1], value[2], value[3]]));
            }
            option::ROUTER if len >= 4 => {
                router = Some(Ipv4Address::new([value[0], value[1], value[2], value[3]]));
            }
            option::DNS_SERVER if len >= 4 => {
                dns = Some(Ipv4Address::new([value[0], value[1], value[2], value[3]]));
            }
            option::SERVER_ID if len >= 4 => {
                server_id = Some(Ipv4Address::new([value[0], value[1], value[2], value[3]]));
            }
            option::LEASE_TIME if len >= 4 => {
                lease_time = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            _ => {}
        }

        pos += 2 + len;
    }

    (msg_type, subnet_mask, router, dns, server_id, lease_time)
}

/// Parse a DHCP response packet
fn parse_response(data: &[u8], expected_xid: u32) -> Option<(u8, Ipv4Address, Ipv4Address, Option<Ipv4Address>, Option<Ipv4Address>, Ipv4Address, u32)> {
    if data.len() < DHCP_OPTIONS_OFFSET + 4 {
        return None;
    }

    // Verify op code
    if data[0] != op::BOOTREPLY {
        return None;
    }

    // Verify transaction ID
    let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if xid != expected_xid {
        return None;
    }

    // Get offered IP (yiaddr)
    let your_ip = Ipv4Address::new([data[16], data[17], data[18], data[19]]);

    // Verify magic cookie
    if data[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }

    // Parse options
    let options = &data[240..];
    let (msg_type, subnet_mask, router, dns, server_id, lease_time) = parse_options(options);

    let msg_type = msg_type?;
    let subnet_mask = subnet_mask.unwrap_or(Ipv4Address::new([255, 255, 255, 0]));
    let server_id = server_id?;
    let lease_time = lease_time.unwrap_or(86400); // Default 24 hours

    Some((msg_type, your_ip, subnet_mask, router, dns, server_id, lease_time))
}

/// DHCP timeout in milliseconds
const DHCP_TIMEOUT_MS: u64 = 10000;

/// Perform DHCP discovery and obtain a lease
pub fn discover(device_index: usize) -> Result<DhcpLease, &'static str> {
    let device = super::get_device(device_index).ok_or("Device not found")?;
    let mac = device.info.mac_address;

    crate::serial_println!("[DHCP] Starting DHCP discovery on device {}", device_index);

    // Create UDP socket
    let socket = udp::socket_create().ok_or("Failed to create socket")?;

    // Bind to DHCP client port
    if udp::socket_bind(socket, DHCP_CLIENT_PORT).is_err() {
        let _ = udp::socket_close(socket);
        return Err("Failed to bind to DHCP port");
    }

    // Generate transaction ID
    let xid = XID_COUNTER.fetch_add(1, Ordering::SeqCst);

    // Build and send DISCOVER
    let _discover_packet = build_discover(mac, xid);

    // Send to broadcast address
    // Note: For broadcast, we need to use the raw ethernet frame
    // For now, we'll send to 255.255.255.255
    let _broadcast = Ipv4Address::new([255, 255, 255, 255]);

    // We need a special send that doesn't require ARP for broadcast
    // For now, log that we would send
    crate::serial_println!("[DHCP] DISCOVER would be sent (broadcast not fully implemented)");
    crate::serial_println!("[DHCP] XID: {:#010X}, MAC: {:?}", xid, mac);

    // In a full implementation, we would:
    // 1. Send DISCOVER as broadcast
    // 2. Wait for OFFER
    // 3. Send REQUEST
    // 4. Wait for ACK

    // For now, return an error indicating broadcast is not implemented
    let _ = udp::socket_close(socket);
    Err("DHCP broadcast not yet implemented - use manual IP configuration")
}

/// Configure a device manually with static IP
pub fn configure_static(
    device_index: usize,
    ip: Ipv4Address,
    mask: Ipv4Address,
    gateway: Option<Ipv4Address>,
) -> Result<(), &'static str> {
    let device = super::get_device_mut(device_index).ok_or("Device not found")?;

    device.set_ip_config(ip, mask, gateway);

    crate::serial_println!(
        "[DHCP] Static IP configured: {:?}/{:?} gw={:?}",
        ip, mask, gateway
    );

    // Update DNS server if gateway is provided (common setup)
    if let Some(gw) = gateway {
        super::dns::set_dns_server(gw);
    }

    Ok(())
}

/// Initialize DHCP module
pub fn init() {
    crate::serial_println!("[DHCP] DHCP client initialized");
}
