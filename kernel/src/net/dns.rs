//! DNS (Domain Name System) Client
//!
//! RFC 1035 - Domain Names - Implementation and Specification
//! Provides hostname to IP address resolution.

extern crate alloc;

use super::ip::Ipv4Address;
use super::udp;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, Ordering};

/// DNS server port
pub const DNS_PORT: u16 = 53;

/// DNS header size
pub const DNS_HEADER_SIZE: usize = 12;

/// Maximum DNS name length
pub const MAX_DNS_NAME: usize = 255;

/// DNS query timeout in milliseconds
pub const DNS_TIMEOUT_MS: u64 = 5000;

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsRecordType {
    /// A record (IPv4 address)
    A = 1,
    /// NS record (name server)
    NS = 2,
    /// CNAME record (canonical name)
    CNAME = 5,
    /// SOA record (start of authority)
    SOA = 6,
    /// PTR record (pointer)
    PTR = 12,
    /// MX record (mail exchange)
    MX = 15,
    /// TXT record (text)
    TXT = 16,
    /// AAAA record (IPv6 address)
    AAAA = 28,
}

/// DNS record class
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsClass {
    /// Internet
    IN = 1,
}

/// DNS response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnsRcode {
    /// No error
    NoError = 0,
    /// Format error
    FormErr = 1,
    /// Server failure
    ServFail = 2,
    /// Name error (NXDOMAIN)
    NXDomain = 3,
    /// Not implemented
    NotImpl = 4,
    /// Refused
    Refused = 5,
}

impl From<u8> for DnsRcode {
    fn from(v: u8) -> Self {
        match v {
            0 => DnsRcode::NoError,
            1 => DnsRcode::FormErr,
            2 => DnsRcode::ServFail,
            3 => DnsRcode::NXDomain,
            4 => DnsRcode::NotImpl,
            5 => DnsRcode::Refused,
            _ => DnsRcode::ServFail,
        }
    }
}

/// DNS header
#[derive(Debug, Clone, Copy)]
pub struct DnsHeader {
    /// Transaction ID
    pub id: u16,
    /// Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    pub flags: u16,
    /// Number of questions
    pub qd_count: u16,
    /// Number of answers
    pub an_count: u16,
    /// Number of authority records
    pub ns_count: u16,
    /// Number of additional records
    pub ar_count: u16,
}

impl DnsHeader {
    /// Create a new query header
    pub fn query(id: u16) -> Self {
        Self {
            id,
            flags: 0x0100, // RD (recursion desired) = 1
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; DNS_HEADER_SIZE] {
        let mut bytes = [0u8; DNS_HEADER_SIZE];
        bytes[0..2].copy_from_slice(&self.id.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.flags.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.qd_count.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.an_count.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.ns_count.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.ar_count.to_be_bytes());
        bytes
    }

    /// Parse header from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < DNS_HEADER_SIZE {
            return None;
        }

        Some(Self {
            id: u16::from_be_bytes([data[0], data[1]]),
            flags: u16::from_be_bytes([data[2], data[3]]),
            qd_count: u16::from_be_bytes([data[4], data[5]]),
            an_count: u16::from_be_bytes([data[6], data[7]]),
            ns_count: u16::from_be_bytes([data[8], data[9]]),
            ar_count: u16::from_be_bytes([data[10], data[11]]),
        })
    }

    /// Check if this is a response
    pub fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    /// Get response code
    pub fn rcode(&self) -> DnsRcode {
        DnsRcode::from((self.flags & 0x000F) as u8)
    }
}

/// DNS question
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    /// Query name (e.g., "example.com")
    pub name: String,
    /// Query type
    pub qtype: DnsRecordType,
    /// Query class
    pub qclass: DnsClass,
}

impl DnsQuestion {
    /// Create a new A record query
    pub fn a_record(name: &str) -> Self {
        Self {
            name: String::from(name),
            qtype: DnsRecordType::A,
            qclass: DnsClass::IN,
        }
    }

    /// Encode the question to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode name as labels
        for label in self.name.split('.') {
            if label.len() > 63 {
                continue; // Skip invalid labels
            }
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0); // Null terminator

        // Type and class
        bytes.extend_from_slice(&(self.qtype as u16).to_be_bytes());
        bytes.extend_from_slice(&(self.qclass as u16).to_be_bytes());

        bytes
    }
}

/// DNS resource record (answer)
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Record name
    pub name: String,
    /// Record type
    pub rtype: u16,
    /// Record class
    pub rclass: u16,
    /// Time to live
    pub ttl: u32,
    /// Record data
    pub rdata: Vec<u8>,
}

impl DnsRecord {
    /// Get IPv4 address if this is an A record
    pub fn as_ipv4(&self) -> Option<Ipv4Address> {
        if self.rtype == DnsRecordType::A as u16 && self.rdata.len() == 4 {
            Some(Ipv4Address::new([
                self.rdata[0],
                self.rdata[1],
                self.rdata[2],
                self.rdata[3],
            ]))
        } else {
            None
        }
    }
}

/// DNS response
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// Response header
    pub header: DnsHeader,
    /// Answer records
    pub answers: Vec<DnsRecord>,
}

/// Next transaction ID
static NEXT_TX_ID: AtomicU16 = AtomicU16::new(1);

/// Default DNS server (Google Public DNS)
static mut DNS_SERVER: Ipv4Address = Ipv4Address::new([8, 8, 8, 8]);

/// Initialize DNS module
pub fn init() {
    crate::serial_println!("[DNS] DNS client initialized (server: 8.8.8.8)");
}

/// Set the DNS server
pub fn set_dns_server(server: Ipv4Address) {
    unsafe {
        DNS_SERVER = server;
    }
    crate::serial_println!("[DNS] DNS server set to {:?}", server);
}

/// Get the current DNS server
pub fn get_dns_server() -> Ipv4Address {
    unsafe { DNS_SERVER }
}

/// Build a DNS query packet
fn build_query(name: &str, qtype: DnsRecordType) -> (u16, Vec<u8>) {
    let tx_id = NEXT_TX_ID.fetch_add(1, Ordering::SeqCst);

    let header = DnsHeader::query(tx_id);
    let question = DnsQuestion {
        name: String::from(name),
        qtype,
        qclass: DnsClass::IN,
    };

    let mut packet = Vec::new();
    packet.extend_from_slice(&header.to_bytes());
    packet.extend_from_slice(&question.to_bytes());

    (tx_id, packet)
}

/// Parse a DNS name from the response
fn parse_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut jumped = false;
    let mut jump_pos = 0;

    loop {
        if pos >= data.len() {
            return None;
        }

        let len = data[pos] as usize;

        if len == 0 {
            // End of name
            if !jumped {
                pos += 1;
            }
            break;
        }

        // Check for compression pointer
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let offset = ((len & 0x3F) as usize) << 8 | data[pos + 1] as usize;
            if !jumped {
                jump_pos = pos + 2;
                jumped = true;
            }
            pos = offset;
            continue;
        }

        pos += 1;
        if pos + len > data.len() {
            return None;
        }

        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(core::str::from_utf8(&data[pos..pos + len]).unwrap_or("?"));
        pos += len;
    }

    let end_pos = if jumped { jump_pos } else { pos };
    Some((name, end_pos))
}

/// Parse a DNS response
fn parse_response(data: &[u8], expected_id: u16) -> Option<DnsResponse> {
    let header = DnsHeader::from_bytes(data)?;

    // Verify this is a response and ID matches
    if !header.is_response() || header.id != expected_id {
        return None;
    }

    // Check for errors
    if header.rcode() != DnsRcode::NoError {
        crate::serial_println!("[DNS] Response error: {:?}", header.rcode());
        return None;
    }

    let mut pos = DNS_HEADER_SIZE;

    // Skip questions
    for _ in 0..header.qd_count {
        let (_, end) = parse_name(data, pos)?;
        pos = end + 4; // Skip QTYPE and QCLASS
    }

    // Parse answers
    let mut answers = Vec::new();
    for _ in 0..header.an_count {
        let (name, end) = parse_name(data, pos)?;
        pos = end;

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            break;
        }

        let rdata = data[pos..pos + rdlength].to_vec();
        pos += rdlength;

        answers.push(DnsRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        });
    }

    Some(DnsResponse { header, answers })
}

/// Resolve a hostname to an IPv4 address
pub fn resolve(device_index: usize, hostname: &str) -> Option<Ipv4Address> {
    crate::serial_println!("[DNS] Resolving {}...", hostname);

    // Build query
    let (tx_id, query_packet) = build_query(hostname, DnsRecordType::A);

    // Create UDP socket
    let socket = udp::socket_create()?;

    // Bind to any port
    if udp::socket_bind(socket, 0).is_err() {
        let _ = udp::socket_close(socket);
        return None;
    }

    // Get DNS server
    let dns_server = get_dns_server();

    // Send query
    if udp::socket_sendto(socket, device_index, dns_server, DNS_PORT, &query_packet).is_err() {
        crate::serial_println!("[DNS] Failed to send query");
        let _ = udp::socket_close(socket);
        return None;
    }

    crate::serial_println!("[DNS] Query sent (id={}), waiting for response...", tx_id);

    // Wait for response
    let start = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);
    loop {
        // Check for response
        if let Some(datagram) = udp::socket_recvfrom(socket) {
            // Parse response
            if let Some(response) = parse_response(&datagram.data, tx_id) {
                crate::serial_println!("[DNS] Got {} answers", response.answers.len());

                // Find first A record
                for answer in &response.answers {
                    if let Some(ip) = answer.as_ipv4() {
                        crate::serial_println!("[DNS] {} -> {:?} (TTL={}s)", hostname, ip, answer.ttl);
                        let _ = udp::socket_close(socket);
                        return Some(ip);
                    }
                }

                crate::serial_println!("[DNS] No A record found");
                let _ = udp::socket_close(socket);
                return None;
            }
        }

        // Process loopback queue (for testing)
        super::loopback::process_queue();

        // Check timeout
        let elapsed = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed) - start;
        if elapsed >= DNS_TIMEOUT_MS {
            crate::serial_println!("[DNS] Query timeout");
            let _ = udp::socket_close(socket);
            return None;
        }

        core::hint::spin_loop();
    }
}

/// Resolve and cache (simple implementation without actual caching)
pub fn resolve_cached(device_index: usize, hostname: &str) -> Option<Ipv4Address> {
    // TODO: Add DNS cache
    resolve(device_index, hostname)
}
