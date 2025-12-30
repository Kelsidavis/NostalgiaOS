//! IPv4 Protocol Implementation
//!
//! RFC 791 - Internet Protocol

use core::fmt;

/// IPv4 header minimum size
pub const IPV4_HEADER_MIN_SIZE: usize = 20;

/// IPv4 header maximum size (with options)
pub const IPV4_HEADER_MAX_SIZE: usize = 60;

/// IPv4 address (4 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Ipv4Address(pub [u8; 4]);

impl Ipv4Address {
    /// Any address (0.0.0.0)
    pub const ANY: Ipv4Address = Ipv4Address([0, 0, 0, 0]);

    /// Broadcast address (255.255.255.255)
    pub const BROADCAST: Ipv4Address = Ipv4Address([255, 255, 255, 255]);

    /// Localhost (127.0.0.1)
    pub const LOCALHOST: Ipv4Address = Ipv4Address([127, 0, 0, 1]);

    /// Create a new IPv4 address
    pub const fn new(bytes: [u8; 4]) -> Self {
        Ipv4Address(bytes)
    }

    /// Create from individual octets
    pub const fn from_octets(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Address([a, b, c, d])
    }

    /// Get as u32 (network byte order)
    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    /// Create from u32 (network byte order)
    pub fn from_u32(value: u32) -> Self {
        Ipv4Address(value.to_be_bytes())
    }

    /// Check if this is a broadcast address
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Check if this is a multicast address (224.0.0.0 - 239.255.255.255)
    pub fn is_multicast(&self) -> bool {
        self.0[0] >= 224 && self.0[0] <= 239
    }

    /// Check if this is a loopback address (127.0.0.0/8)
    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    /// Check if this is a link-local address (169.254.0.0/16)
    pub fn is_link_local(&self) -> bool {
        self.0[0] == 169 && self.0[1] == 254
    }

    /// Check if this is a private address
    pub fn is_private(&self) -> bool {
        // 10.0.0.0/8
        if self.0[0] == 10 {
            return true;
        }
        // 172.16.0.0/12
        if self.0[0] == 172 && (self.0[1] >= 16 && self.0[1] <= 31) {
            return true;
        }
        // 192.168.0.0/16
        if self.0[0] == 192 && self.0[1] == 168 {
            return true;
        }
        false
    }

    /// Apply a subnet mask
    pub fn apply_mask(&self, mask: &Ipv4Address) -> Ipv4Address {
        Ipv4Address([
            self.0[0] & mask.0[0],
            self.0[1] & mask.0[1],
            self.0[2] & mask.0[2],
            self.0[3] & mask.0[3],
        ])
    }

    /// Check if address is in the same subnet
    pub fn same_subnet(&self, other: &Ipv4Address, mask: &Ipv4Address) -> bool {
        self.apply_mask(mask) == other.apply_mask(mask)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }
}

impl fmt::Debug for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// IP protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol {
    /// ICMP
    Icmp = 1,
    /// IGMP
    Igmp = 2,
    /// TCP
    Tcp = 6,
    /// UDP
    Udp = 17,
    /// IPv6 encapsulation
    Ipv6 = 41,
    /// GRE
    Gre = 47,
    /// ESP (IPsec)
    Esp = 50,
    /// AH (IPsec)
    Ah = 51,
    /// SCTP
    Sctp = 132,
    /// Unknown
    Unknown = 255,
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::Icmp,
            2 => IpProtocol::Igmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            41 => IpProtocol::Ipv6,
            47 => IpProtocol::Gre,
            50 => IpProtocol::Esp,
            51 => IpProtocol::Ah,
            132 => IpProtocol::Sctp,
            _ => IpProtocol::Unknown,
        }
    }
}

/// IPv4 header flags
pub mod ip_flags {
    /// Don't fragment
    pub const DF: u16 = 0x4000;
    /// More fragments
    pub const MF: u16 = 0x2000;
    /// Fragment offset mask
    pub const OFFSET_MASK: u16 = 0x1FFF;
}

/// IPv4 header
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    /// Version (4 bits) and IHL (4 bits)
    pub version_ihl: u8,
    /// Type of Service / DSCP + ECN
    pub tos: u8,
    /// Total length (header + data)
    pub total_length: u16,
    /// Identification (for fragmentation)
    pub identification: u16,
    /// Flags and fragment offset
    pub flags_fragment: u16,
    /// Time to live
    pub ttl: u8,
    /// Protocol
    pub protocol: IpProtocol,
    /// Header checksum
    pub checksum: u16,
    /// Source address
    pub source_addr: Ipv4Address,
    /// Destination address
    pub dest_addr: Ipv4Address,
}

impl Ipv4Header {
    /// Create a new IPv4 header
    pub fn new(
        source: Ipv4Address,
        dest: Ipv4Address,
        protocol: IpProtocol,
        payload_len: u16,
        ttl: u8,
    ) -> Self {
        Self {
            version_ihl: 0x45, // Version 4, IHL 5 (20 bytes)
            tos: 0,
            total_length: IPV4_HEADER_MIN_SIZE as u16 + payload_len,
            identification: 0,
            flags_fragment: ip_flags::DF, // Don't fragment
            ttl,
            protocol,
            checksum: 0, // Will be computed
            source_addr: source,
            dest_addr: dest,
        }
    }

    /// Get IP version
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Get header length in bytes
    pub fn header_len(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }

    /// Get payload length
    pub fn payload_len(&self) -> usize {
        self.total_length as usize - self.header_len()
    }

    /// Check if don't fragment flag is set
    pub fn dont_fragment(&self) -> bool {
        self.flags_fragment & ip_flags::DF != 0
    }

    /// Check if more fragments flag is set
    pub fn more_fragments(&self) -> bool {
        self.flags_fragment & ip_flags::MF != 0
    }

    /// Get fragment offset (in 8-byte units)
    pub fn fragment_offset(&self) -> u16 {
        self.flags_fragment & ip_flags::OFFSET_MASK
    }

    /// Serialize the header to bytes
    pub fn to_bytes(&self) -> [u8; IPV4_HEADER_MIN_SIZE] {
        let mut bytes = [0u8; IPV4_HEADER_MIN_SIZE];

        bytes[0] = self.version_ihl;
        bytes[1] = self.tos;
        bytes[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.identification.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.flags_fragment.to_be_bytes());
        bytes[8] = self.ttl;
        bytes[9] = self.protocol as u8;
        // Checksum will be computed separately
        bytes[10..12].copy_from_slice(&[0, 0]);
        bytes[12..16].copy_from_slice(&self.source_addr.0);
        bytes[16..20].copy_from_slice(&self.dest_addr.0);

        bytes
    }

    /// Compute and set checksum
    pub fn compute_checksum(&mut self) {
        self.checksum = 0;
        let bytes = self.to_bytes();
        self.checksum = internet_checksum(&bytes);
    }

    /// Verify checksum
    pub fn verify_checksum(&self) -> bool {
        let bytes = self.to_bytes();
        // Create a copy with the stored checksum
        let mut check_bytes = bytes;
        check_bytes[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        internet_checksum(&check_bytes) == 0
    }
}

/// Parse an IPv4 header
pub fn parse_ipv4_header(data: &[u8]) -> Option<Ipv4Header> {
    if data.len() < IPV4_HEADER_MIN_SIZE {
        return None;
    }

    let version_ihl = data[0];
    let version = version_ihl >> 4;

    // Must be IPv4
    if version != 4 {
        return None;
    }

    let header_len = ((version_ihl & 0x0F) as usize) * 4;
    if data.len() < header_len {
        return None;
    }

    Some(Ipv4Header {
        version_ihl,
        tos: data[1],
        total_length: u16::from_be_bytes([data[2], data[3]]),
        identification: u16::from_be_bytes([data[4], data[5]]),
        flags_fragment: u16::from_be_bytes([data[6], data[7]]),
        ttl: data[8],
        protocol: IpProtocol::from(data[9]),
        checksum: u16::from_be_bytes([data[10], data[11]]),
        source_addr: Ipv4Address::new([data[12], data[13], data[14], data[15]]),
        dest_addr: Ipv4Address::new([data[16], data[17], data[18], data[19]]),
    })
}

/// Create an IPv4 header for a packet
pub fn create_ipv4_header(
    source: Ipv4Address,
    dest: Ipv4Address,
    protocol: IpProtocol,
    payload_len: u16,
) -> Ipv4Header {
    let mut header = Ipv4Header::new(source, dest, protocol, payload_len, 64);
    header.compute_checksum();
    header
}

/// Compute Internet checksum (RFC 1071)
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !(sum as u16)
}

/// Compute checksum for UDP/TCP pseudo-header + data
pub fn transport_checksum(
    source: Ipv4Address,
    dest: Ipv4Address,
    protocol: IpProtocol,
    data: &[u8],
) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    sum += u16::from_be_bytes([source.0[0], source.0[1]]) as u32;
    sum += u16::from_be_bytes([source.0[2], source.0[3]]) as u32;
    sum += u16::from_be_bytes([dest.0[0], dest.0[1]]) as u32;
    sum += u16::from_be_bytes([dest.0[2], dest.0[3]]) as u32;
    sum += protocol as u32;
    sum += data.len() as u32;

    // Data
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold and complement
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
