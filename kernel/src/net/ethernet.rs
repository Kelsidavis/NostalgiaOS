//! Ethernet Frame Handling
//!
//! IEEE 802.3 Ethernet frame format:
//! - Preamble (7 bytes) - hardware handled
//! - SFD (1 byte) - hardware handled
//! - Destination MAC (6 bytes)
//! - Source MAC (6 bytes)
//! - EtherType/Length (2 bytes)
//! - Payload (46-1500 bytes)
//! - FCS (4 bytes) - usually hardware handled

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Ethernet header size in bytes
pub const ETHERNET_HEADER_SIZE: usize = 14;

/// MAC address (6 bytes)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Broadcast MAC address (FF:FF:FF:FF:FF:FF)
    pub const BROADCAST: MacAddress = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    /// Zero MAC address
    pub const ZERO: MacAddress = MacAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    /// Create a new MAC address
    pub const fn new(bytes: [u8; 6]) -> Self {
        MacAddress(bytes)
    }

    /// Check if this is a broadcast address
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Check if this is a multicast address (bit 0 of first byte is 1)
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Check if this is a unicast address
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    /// Check if this is a locally administered address
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Get the bytes
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Default for MacAddress {
    fn default() -> Self {
        Self::ZERO
    }
}

/// Ethernet frame types (EtherType)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EtherType {
    /// IPv4
    Ipv4 = 0x0800,
    /// ARP (Address Resolution Protocol)
    Arp = 0x0806,
    /// RARP (Reverse ARP)
    Rarp = 0x8035,
    /// AppleTalk
    AppleTalk = 0x809B,
    /// AARP (AppleTalk ARP)
    Aarp = 0x80F3,
    /// IEEE 802.1Q VLAN tag
    Vlan = 0x8100,
    /// IPv6
    Ipv6 = 0x86DD,
    /// PPPoE Discovery
    PppoeDiscovery = 0x8863,
    /// PPPoE Session
    PppoeSession = 0x8864,
    /// Unknown/Other
    Unknown = 0x0000,
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::Arp,
            0x8035 => EtherType::Rarp,
            0x809B => EtherType::AppleTalk,
            0x80F3 => EtherType::Aarp,
            0x8100 => EtherType::Vlan,
            0x86DD => EtherType::Ipv6,
            0x8863 => EtherType::PppoeDiscovery,
            0x8864 => EtherType::PppoeSession,
            _ => EtherType::Unknown,
        }
    }
}

/// Ethernet frame header
#[derive(Debug, Clone, Copy)]
pub struct EthernetHeader {
    /// Destination MAC address
    pub dest_mac: MacAddress,
    /// Source MAC address
    pub src_mac: MacAddress,
    /// EtherType (indicates payload protocol)
    pub ether_type: EtherType,
}

impl EthernetHeader {
    /// Create a new Ethernet header
    pub fn new(dest: MacAddress, src: MacAddress, ether_type: EtherType) -> Self {
        Self {
            dest_mac: dest,
            src_mac: src,
            ether_type,
        }
    }

    /// Serialize the header to bytes
    pub fn to_bytes(&self) -> [u8; ETHERNET_HEADER_SIZE] {
        let mut bytes = [0u8; ETHERNET_HEADER_SIZE];
        bytes[0..6].copy_from_slice(&self.dest_mac.0);
        bytes[6..12].copy_from_slice(&self.src_mac.0);
        let etype = self.ether_type as u16;
        bytes[12] = (etype >> 8) as u8;
        bytes[13] = (etype & 0xFF) as u8;
        bytes
    }
}

/// Parse an Ethernet frame header
pub fn parse_ethernet_frame(data: &[u8]) -> Option<EthernetHeader> {
    if data.len() < ETHERNET_HEADER_SIZE {
        return None;
    }

    let dest_mac = MacAddress::new([
        data[0], data[1], data[2], data[3], data[4], data[5],
    ]);

    let src_mac = MacAddress::new([
        data[6], data[7], data[8], data[9], data[10], data[11],
    ]);

    let ether_type = EtherType::from(u16::from_be_bytes([data[12], data[13]]));

    Some(EthernetHeader {
        dest_mac,
        src_mac,
        ether_type,
    })
}

/// Create an Ethernet frame with the given payload
pub fn create_ethernet_frame(
    dest: MacAddress,
    src: MacAddress,
    ether_type: EtherType,
    payload: &[u8],
) -> Vec<u8> {
    let header = EthernetHeader::new(dest, src, ether_type);
    let header_bytes = header.to_bytes();

    let mut frame = Vec::with_capacity(ETHERNET_HEADER_SIZE + payload.len());
    frame.extend_from_slice(&header_bytes);
    frame.extend_from_slice(payload);

    // Pad to minimum Ethernet frame size if needed
    while frame.len() < super::MIN_ETHERNET_FRAME {
        frame.push(0);
    }

    frame
}

/// Check if a frame is addressed to us or broadcast/multicast
pub fn should_receive(frame_dest: &MacAddress, our_mac: &MacAddress, promiscuous: bool) -> bool {
    if promiscuous {
        return true;
    }

    if frame_dest.is_broadcast() {
        return true;
    }

    if *frame_dest == *our_mac {
        return true;
    }

    // Check for all-hosts multicast (224.0.0.1 -> 01:00:5E:00:00:01)
    if frame_dest.is_multicast() {
        // TODO: Check multicast group membership
        return true;
    }

    false
}
