//! ICMP (Internet Control Message Protocol)
//!
//! RFC 792 - Internet Control Message Protocol

extern crate alloc;

use super::ethernet::{MacAddress, EtherType, create_ethernet_frame};
use super::ip::{Ipv4Header, Ipv4Address, IpProtocol, internet_checksum};
use alloc::vec::Vec;

/// ICMP header size
pub const ICMP_HEADER_SIZE: usize = 8;

/// ICMP message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    /// Echo Reply (ping response)
    EchoReply = 0,
    /// Destination Unreachable
    DestUnreachable = 3,
    /// Source Quench (deprecated)
    SourceQuench = 4,
    /// Redirect
    Redirect = 5,
    /// Echo Request (ping)
    EchoRequest = 8,
    /// Router Advertisement
    RouterAdvertisement = 9,
    /// Router Solicitation
    RouterSolicitation = 10,
    /// Time Exceeded
    TimeExceeded = 11,
    /// Parameter Problem
    ParameterProblem = 12,
    /// Timestamp Request
    TimestampRequest = 13,
    /// Timestamp Reply
    TimestampReply = 14,
    /// Unknown
    Unknown = 255,
}

impl From<u8> for IcmpType {
    fn from(value: u8) -> Self {
        match value {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestUnreachable,
            4 => IcmpType::SourceQuench,
            5 => IcmpType::Redirect,
            8 => IcmpType::EchoRequest,
            9 => IcmpType::RouterAdvertisement,
            10 => IcmpType::RouterSolicitation,
            11 => IcmpType::TimeExceeded,
            12 => IcmpType::ParameterProblem,
            13 => IcmpType::TimestampRequest,
            14 => IcmpType::TimestampReply,
            _ => IcmpType::Unknown,
        }
    }
}

/// Destination Unreachable codes
pub mod dest_unreachable_code {
    pub const NET_UNREACHABLE: u8 = 0;
    pub const HOST_UNREACHABLE: u8 = 1;
    pub const PROTOCOL_UNREACHABLE: u8 = 2;
    pub const PORT_UNREACHABLE: u8 = 3;
    pub const FRAGMENTATION_NEEDED: u8 = 4;
    pub const SOURCE_ROUTE_FAILED: u8 = 5;
}

/// Time Exceeded codes
pub mod time_exceeded_code {
    pub const TTL_EXCEEDED: u8 = 0;
    pub const FRAGMENT_REASSEMBLY: u8 = 1;
}

/// ICMP header (for Echo Request/Reply)
#[derive(Debug, Clone, Copy)]
pub struct IcmpHeader {
    /// Type
    pub icmp_type: IcmpType,
    /// Code
    pub code: u8,
    /// Checksum
    pub checksum: u16,
    /// Identifier (for echo)
    pub identifier: u16,
    /// Sequence number (for echo)
    pub sequence: u16,
}

impl IcmpHeader {
    /// Create an Echo Request
    pub fn echo_request(identifier: u16, sequence: u16) -> Self {
        Self {
            icmp_type: IcmpType::EchoRequest,
            code: 0,
            checksum: 0,
            identifier,
            sequence,
        }
    }

    /// Create an Echo Reply
    pub fn echo_reply(identifier: u16, sequence: u16) -> Self {
        Self {
            icmp_type: IcmpType::EchoReply,
            code: 0,
            checksum: 0,
            identifier,
            sequence,
        }
    }

    /// Serialize the header to bytes
    pub fn to_bytes(&self) -> [u8; ICMP_HEADER_SIZE] {
        let mut bytes = [0u8; ICMP_HEADER_SIZE];

        bytes[0] = self.icmp_type as u8;
        bytes[1] = self.code;
        bytes[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.sequence.to_be_bytes());

        bytes
    }

    /// Compute and set checksum
    pub fn compute_checksum(&mut self, data: &[u8]) {
        self.checksum = 0;
        let header_bytes = self.to_bytes();

        // Combine header and data for checksum
        let mut full_data = Vec::with_capacity(header_bytes.len() + data.len());
        full_data.extend_from_slice(&header_bytes);
        full_data.extend_from_slice(data);

        self.checksum = internet_checksum(&full_data);
    }
}

/// Parse an ICMP packet
pub fn parse_icmp_packet(data: &[u8]) -> Option<IcmpHeader> {
    if data.len() < ICMP_HEADER_SIZE {
        return None;
    }

    Some(IcmpHeader {
        icmp_type: IcmpType::from(data[0]),
        code: data[1],
        checksum: u16::from_be_bytes([data[2], data[3]]),
        identifier: u16::from_be_bytes([data[4], data[5]]),
        sequence: u16::from_be_bytes([data[6], data[7]]),
    })
}

/// Initialize ICMP module
pub fn init() {
    crate::serial_println!("[ICMP] ICMP module initialized");
}

/// Handle an incoming ICMP packet
pub fn handle_icmp_packet(
    device_index: usize,
    eth_header: &super::ethernet::EthernetHeader,
    ip_header: &Ipv4Header,
    icmp: &IcmpHeader,
    full_icmp_data: &[u8],
) {
    match icmp.icmp_type {
        IcmpType::EchoRequest => {
            crate::serial_println!(
                "[ICMP] Echo Request from {:?} (id={}, seq={})",
                ip_header.source_addr,
                icmp.identifier,
                icmp.sequence
            );

            unsafe {
                super::NETWORK_STATS.icmp_echo_requests += 1;
            }

            // Send Echo Reply
            send_echo_reply(
                device_index,
                eth_header.src_mac,
                ip_header.source_addr,
                icmp.identifier,
                icmp.sequence,
                &full_icmp_data[ICMP_HEADER_SIZE..], // Echo data
            );
        }
        IcmpType::EchoReply => {
            crate::serial_println!(
                "[ICMP] Echo Reply from {:?} (id={}, seq={})",
                ip_header.source_addr,
                icmp.identifier,
                icmp.sequence
            );
        }
        IcmpType::DestUnreachable => {
            crate::serial_println!(
                "[ICMP] Destination Unreachable from {:?} (code={})",
                ip_header.source_addr,
                icmp.code
            );
        }
        IcmpType::TimeExceeded => {
            crate::serial_println!(
                "[ICMP] Time Exceeded from {:?} (code={})",
                ip_header.source_addr,
                icmp.code
            );
        }
        _ => {
            crate::serial_println!(
                "[ICMP] Type {:?} from {:?}",
                icmp.icmp_type,
                ip_header.source_addr
            );
        }
    }
}

/// Send an ICMP Echo Reply
fn send_echo_reply(
    device_index: usize,
    dest_mac: MacAddress,
    dest_ip: Ipv4Address,
    identifier: u16,
    sequence: u16,
    echo_data: &[u8],
) {
    let device = match super::get_device(device_index) {
        Some(d) => d,
        None => return,
    };

    let src_ip = match device.ip_address {
        Some(ip) => ip,
        None => return,
    };
    let src_mac = device.info.mac_address;

    // Build ICMP Echo Reply
    let mut icmp = IcmpHeader::echo_reply(identifier, sequence);
    icmp.compute_checksum(echo_data);

    let icmp_bytes = icmp.to_bytes();

    // Build IP header
    let payload_len = (ICMP_HEADER_SIZE + echo_data.len()) as u16;
    let mut ip_header = Ipv4Header::new(src_ip, dest_ip, IpProtocol::Icmp, payload_len, 64);
    ip_header.compute_checksum();

    let ip_bytes = ip_header.to_bytes();

    // Build full packet
    let mut packet = Vec::with_capacity(ip_bytes.len() + icmp_bytes.len() + echo_data.len());
    packet.extend_from_slice(&ip_bytes);
    packet.extend_from_slice(&icmp_bytes);
    packet.extend_from_slice(echo_data);

    // Create Ethernet frame
    let frame = create_ethernet_frame(dest_mac, src_mac, EtherType::Ipv4, &packet);

    // Send
    if let Some(device) = super::get_device_mut(device_index) {
        if device.transmit(&frame).is_ok() {
            unsafe {
                super::NETWORK_STATS.icmp_echo_replies += 1;
            }
            super::record_tx_packet(frame.len());
        }
    }
}

/// Send an ICMP Echo Request (ping)
pub fn send_icmp_echo_request(
    device_index: usize,
    dest_ip: Ipv4Address,
    identifier: u16,
    sequence: u16,
    data: &[u8],
) -> Result<(), &'static str> {
    let device = super::get_device(device_index).ok_or("Device not found")?;

    let src_ip = device.ip_address.ok_or("No IP configured")?;
    let src_mac = device.info.mac_address;

    // Resolve destination MAC
    let dest_mac = super::arp::arp_resolve(device_index, dest_ip, 3000)
        .ok_or("ARP resolution failed")?;

    // Build ICMP Echo Request
    let mut icmp = IcmpHeader::echo_request(identifier, sequence);
    icmp.compute_checksum(data);

    let icmp_bytes = icmp.to_bytes();

    // Build IP header
    let payload_len = (ICMP_HEADER_SIZE + data.len()) as u16;
    let mut ip_header = Ipv4Header::new(src_ip, dest_ip, IpProtocol::Icmp, payload_len, 64);
    ip_header.compute_checksum();

    let ip_bytes = ip_header.to_bytes();

    // Build full packet
    let mut packet = Vec::with_capacity(ip_bytes.len() + icmp_bytes.len() + data.len());
    packet.extend_from_slice(&ip_bytes);
    packet.extend_from_slice(&icmp_bytes);
    packet.extend_from_slice(data);

    // Create Ethernet frame
    let frame = create_ethernet_frame(dest_mac, src_mac, EtherType::Ipv4, &packet);

    // Send
    if let Some(device) = super::get_device_mut(device_index) {
        device.transmit(&frame)?;
        super::record_tx_packet(frame.len());
    }

    Ok(())
}
