//! SNMP Client
//!
//! RFC 1157 - Simple Network Management Protocol (SNMPv1)
//! Basic SNMP client for reading values from network devices.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, Ordering};
use super::udp;
use super::ip::Ipv4Address;

/// Default SNMP port
pub const SNMP_PORT: u16 = 161;

/// SNMP trap port
pub const SNMP_TRAP_PORT: u16 = 162;

/// Maximum SNMP message size
pub const MAX_SNMP_SIZE: usize = 1472;

/// SNMP version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SnmpVersion {
    V1 = 0,
    V2c = 1,
}

/// SNMP PDU types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    GetRequest = 0xA0,
    GetNextRequest = 0xA1,
    GetResponse = 0xA2,
    SetRequest = 0xA3,
    Trap = 0xA4,
}

/// SNMP error status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorStatus {
    NoError = 0,
    TooBig = 1,
    NoSuchName = 2,
    BadValue = 3,
    ReadOnly = 4,
    GenErr = 5,
}

impl ErrorStatus {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::NoError,
            1 => Self::TooBig,
            2 => Self::NoSuchName,
            3 => Self::BadValue,
            4 => Self::ReadOnly,
            _ => Self::GenErr,
        }
    }
}

/// ASN.1/BER tags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AsnTag {
    Integer = 0x02,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    Sequence = 0x30,
    IpAddress = 0x40,
    Counter = 0x41,
    Gauge = 0x42,
    TimeTicks = 0x43,
    Opaque = 0x44,
}

/// SNMP value types
#[derive(Debug, Clone)]
pub enum SnmpValue {
    Integer(i64),
    OctetString(Vec<u8>),
    ObjectIdentifier(Vec<u32>),
    IpAddress([u8; 4]),
    Counter(u32),
    Gauge(u32),
    TimeTicks(u32),
    Null,
}

impl SnmpValue {
    /// Get value as string representation
    pub fn to_string(&self) -> String {
        match self {
            SnmpValue::Integer(v) => alloc::format!("{}", v),
            SnmpValue::OctetString(v) => {
                if let Ok(s) = core::str::from_utf8(v) {
                    String::from(s)
                } else {
                    // Hex encode non-UTF8 strings
                    let mut s = String::new();
                    for byte in v {
                        s.push_str(&alloc::format!("{:02X}", byte));
                    }
                    s
                }
            }
            SnmpValue::ObjectIdentifier(oid) => oid_to_string(oid),
            SnmpValue::IpAddress(ip) => alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            SnmpValue::Counter(v) => alloc::format!("{}", v),
            SnmpValue::Gauge(v) => alloc::format!("{}", v),
            SnmpValue::TimeTicks(v) => {
                // Ticks are in 1/100th of a second
                let secs = v / 100;
                let days = secs / 86400;
                let hours = (secs % 86400) / 3600;
                let mins = (secs % 3600) / 60;
                let s = secs % 60;
                alloc::format!("{}d {}h {}m {}s", days, hours, mins, s)
            }
            SnmpValue::Null => String::from("NULL"),
        }
    }
}

/// Convert OID to dotted string
pub fn oid_to_string(oid: &[u32]) -> String {
    let mut s = String::new();
    for (i, &n) in oid.iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        s.push_str(&alloc::format!("{}", n));
    }
    s
}

/// Parse dotted OID string to vector
pub fn parse_oid(s: &str) -> Option<Vec<u32>> {
    let parts: Result<Vec<u32>, _> = s.split('.').map(|p| p.parse()).collect();
    parts.ok()
}

/// Common OIDs
pub mod oid {
    /// System description (SNMPv2-MIB::sysDescr.0)
    pub const SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
    /// System object ID (SNMPv2-MIB::sysObjectID.0)
    pub const SYS_OBJECT_ID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
    /// System uptime (SNMPv2-MIB::sysUpTime.0)
    pub const SYS_UP_TIME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
    /// System contact (SNMPv2-MIB::sysContact.0)
    pub const SYS_CONTACT: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 4, 0];
    /// System name (SNMPv2-MIB::sysName.0)
    pub const SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
    /// System location (SNMPv2-MIB::sysLocation.0)
    pub const SYS_LOCATION: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 6, 0];
    /// Interface number (IF-MIB::ifNumber.0)
    pub const IF_NUMBER: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 1, 0];
}

/// Encode OID to ASN.1/BER format
fn encode_oid(oid: &[u32]) -> Vec<u8> {
    let mut encoded = Vec::new();

    if oid.len() >= 2 {
        // First two components are encoded as 40*first + second
        encoded.push((oid[0] * 40 + oid[1]) as u8);

        // Remaining components
        for &component in &oid[2..] {
            if component < 128 {
                encoded.push(component as u8);
            } else {
                // Multi-byte encoding
                let mut bytes = Vec::new();
                let mut n = component;
                while n > 0 {
                    bytes.push((n & 0x7F) as u8);
                    n >>= 7;
                }
                bytes.reverse();
                for (i, b) in bytes.iter().enumerate() {
                    if i < bytes.len() - 1 {
                        encoded.push(b | 0x80);
                    } else {
                        encoded.push(*b);
                    }
                }
            }
        }
    }

    encoded
}

/// Decode OID from ASN.1/BER format
fn decode_oid(data: &[u8]) -> Option<Vec<u32>> {
    if data.is_empty() {
        return None;
    }

    let mut oid = Vec::new();

    // First byte encodes two components
    oid.push((data[0] / 40) as u32);
    oid.push((data[0] % 40) as u32);

    let mut i = 1;
    while i < data.len() {
        let mut component: u32 = 0;
        while i < data.len() {
            let byte = data[i];
            i += 1;
            component = (component << 7) | (byte & 0x7F) as u32;
            if byte & 0x80 == 0 {
                break;
            }
        }
        oid.push(component);
    }

    Some(oid)
}

/// Encode length in ASN.1/BER format
fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

/// Decode length from ASN.1/BER format
fn decode_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    if data[0] < 128 {
        Some((data[0] as usize, 1))
    } else {
        let num_bytes = (data[0] & 0x7F) as usize;
        if data.len() < 1 + num_bytes {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | data[1 + i] as usize;
        }
        Some((len, 1 + num_bytes))
    }
}

/// Encode integer in ASN.1/BER format
fn encode_integer(value: i64) -> Vec<u8> {
    let mut bytes = Vec::new();

    if value == 0 {
        bytes.push(0);
    } else {
        let mut n = value;
        while n != 0 && n != -1 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        // Add sign byte if needed
        if value > 0 && (bytes.last().unwrap_or(&0) & 0x80) != 0 {
            bytes.push(0);
        } else if value < 0 && (bytes.last().unwrap_or(&0xFF) & 0x80) == 0 {
            bytes.push(0xFF);
        }
        bytes.reverse();
    }

    bytes
}

/// Build SNMP GET request packet
pub fn build_get_request(
    community: &str,
    request_id: u32,
    oids: &[&[u32]],
) -> Vec<u8> {
    let mut packet = Vec::new();

    // Build varbind list
    let mut varbinds = Vec::new();
    for oid in oids {
        let encoded_oid = encode_oid(oid);
        let oid_len = encode_length(encoded_oid.len());

        // Varbind: SEQUENCE { OID, NULL }
        let varbind_content_len = 1 + oid_len.len() + encoded_oid.len() + 2; // OID + NULL
        let varbind_len = encode_length(varbind_content_len);

        varbinds.push(0x30); // SEQUENCE
        varbinds.extend(&varbind_len);
        varbinds.push(0x06); // OBJECT IDENTIFIER
        varbinds.extend(&oid_len);
        varbinds.extend(&encoded_oid);
        varbinds.push(0x05); // NULL
        varbinds.push(0x00);
    }

    // Varbind list wrapper
    let varbind_list_len = encode_length(varbinds.len());

    // PDU: request-id, error-status, error-index, varbind-list
    let request_id_bytes = encode_integer(request_id as i64);
    let error_status_bytes = encode_integer(0);
    let error_index_bytes = encode_integer(0);

    let pdu_content_len =
        1 + encode_length(request_id_bytes.len()).len() + request_id_bytes.len() +
        1 + encode_length(error_status_bytes.len()).len() + error_status_bytes.len() +
        1 + encode_length(error_index_bytes.len()).len() + error_index_bytes.len() +
        1 + varbind_list_len.len() + varbinds.len();

    let pdu_len = encode_length(pdu_content_len);

    // Community string
    let community_bytes = community.as_bytes();
    let community_len = encode_length(community_bytes.len());

    // Version (SNMPv1 = 0)
    let version_bytes = encode_integer(0);
    let version_len = encode_length(version_bytes.len());

    // Total message content length
    let message_content_len =
        1 + version_len.len() + version_bytes.len() +
        1 + community_len.len() + community_bytes.len() +
        1 + pdu_len.len() + pdu_content_len;

    let message_len = encode_length(message_content_len);

    // Build packet
    packet.push(0x30); // SEQUENCE
    packet.extend(&message_len);

    // Version
    packet.push(0x02); // INTEGER
    packet.extend(&version_len);
    packet.extend(&version_bytes);

    // Community
    packet.push(0x04); // OCTET STRING
    packet.extend(&community_len);
    packet.extend(community_bytes);

    // PDU (GetRequest)
    packet.push(0xA0); // GetRequest-PDU
    packet.extend(&pdu_len);

    // Request ID
    packet.push(0x02);
    packet.extend(&encode_length(request_id_bytes.len()));
    packet.extend(&request_id_bytes);

    // Error status
    packet.push(0x02);
    packet.extend(&encode_length(error_status_bytes.len()));
    packet.extend(&error_status_bytes);

    // Error index
    packet.push(0x02);
    packet.extend(&encode_length(error_index_bytes.len()));
    packet.extend(&error_index_bytes);

    // Varbind list
    packet.push(0x30);
    packet.extend(&varbind_list_len);
    packet.extend(&varbinds);

    packet
}

/// Parse SNMP response packet
pub fn parse_response(data: &[u8]) -> Option<Vec<(Vec<u32>, SnmpValue)>> {
    if data.len() < 10 {
        return None;
    }

    let mut pos = 0;

    // Message SEQUENCE
    if data[pos] != 0x30 {
        return None;
    }
    pos += 1;
    let (_, len_bytes) = decode_length(&data[pos..])?;
    pos += len_bytes;

    // Version
    if data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (ver_len, len_bytes) = decode_length(&data[pos..])?;
    pos += len_bytes + ver_len;

    // Community
    if data[pos] != 0x04 {
        return None;
    }
    pos += 1;
    let (comm_len, len_bytes) = decode_length(&data[pos..])?;
    pos += len_bytes + comm_len;

    // PDU (GetResponse = 0xA2)
    if data[pos] != 0xA2 {
        return None;
    }
    pos += 1;
    let (_, len_bytes) = decode_length(&data[pos..])?;
    pos += len_bytes;

    // Request ID
    if data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (req_len, len_bytes) = decode_length(&data[pos..])?;
    pos += len_bytes + req_len;

    // Error status
    if data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (err_len, len_bytes) = decode_length(&data[pos..])?;
    pos += len_bytes + err_len;

    // Error index
    if data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (idx_len, len_bytes) = decode_length(&data[pos..])?;
    pos += len_bytes + idx_len;

    // Varbind list SEQUENCE
    if data[pos] != 0x30 {
        return None;
    }
    pos += 1;
    let (_, len_bytes) = decode_length(&data[pos..])?;
    pos += len_bytes;

    // Parse varbinds
    let mut results = Vec::new();

    while pos < data.len() {
        // Varbind SEQUENCE
        if data[pos] != 0x30 {
            break;
        }
        pos += 1;
        let (vb_len, len_bytes) = decode_length(&data[pos..])?;
        pos += len_bytes;
        let vb_end = pos + vb_len;

        // OID
        if data[pos] != 0x06 {
            break;
        }
        pos += 1;
        let (oid_len, len_bytes) = decode_length(&data[pos..])?;
        pos += len_bytes;
        let oid = decode_oid(&data[pos..pos + oid_len])?;
        pos += oid_len;

        // Value
        let value_tag = data[pos];
        pos += 1;
        let (val_len, len_bytes) = decode_length(&data[pos..])?;
        pos += len_bytes;
        let value_data = &data[pos..pos + val_len];
        pos += val_len;

        let value = match value_tag {
            0x02 => {
                // INTEGER
                let mut n: i64 = 0;
                let mut first = true;
                for &b in value_data {
                    if first && (b & 0x80) != 0 {
                        n = -1;
                    }
                    first = false;
                    n = (n << 8) | b as i64;
                }
                SnmpValue::Integer(n)
            }
            0x04 => SnmpValue::OctetString(value_data.to_vec()),
            0x05 => SnmpValue::Null,
            0x06 => {
                if let Some(oid) = decode_oid(value_data) {
                    SnmpValue::ObjectIdentifier(oid)
                } else {
                    SnmpValue::Null
                }
            }
            0x40 => {
                if value_data.len() == 4 {
                    SnmpValue::IpAddress([value_data[0], value_data[1], value_data[2], value_data[3]])
                } else {
                    SnmpValue::Null
                }
            }
            0x41 => {
                let mut n: u32 = 0;
                for &b in value_data {
                    n = (n << 8) | b as u32;
                }
                SnmpValue::Counter(n)
            }
            0x42 => {
                let mut n: u32 = 0;
                for &b in value_data {
                    n = (n << 8) | b as u32;
                }
                SnmpValue::Gauge(n)
            }
            0x43 => {
                let mut n: u32 = 0;
                for &b in value_data {
                    n = (n << 8) | b as u32;
                }
                SnmpValue::TimeTicks(n)
            }
            _ => SnmpValue::OctetString(value_data.to_vec()),
        };

        results.push((oid, value));

        if pos >= vb_end {
            continue;
        }
    }

    Some(results)
}

/// Perform SNMP GET request
pub fn get(
    device_index: usize,
    target_ip: Ipv4Address,
    community: &str,
    oids: &[&[u32]],
    timeout_ms: u32,
) -> Result<Vec<(Vec<u32>, SnmpValue)>, &'static str> {
    // Create UDP socket
    let socket = udp::socket_create().ok_or("Failed to create socket")?;

    // Bind to any local port
    udp::socket_bind(socket, 0)?;

    // Build request
    let request_id = REQUESTS_SENT.fetch_add(1, Ordering::Relaxed);
    let packet = build_get_request(community, request_id, oids);

    // Send request
    udp::socket_sendto(socket, device_index, target_ip, SNMP_PORT, &packet)?;

    // Poll for response with timeout
    let start = crate::hal::apic::get_tick_count();
    let timeout_ticks = timeout_ms as u64 * 1000; // Convert ms to ticks (assuming ~1MHz tick rate)

    loop {
        if let Some(datagram) = udp::socket_recvfrom(socket) {
            let _ = udp::socket_close(socket);
            RESPONSES_RECEIVED.fetch_add(1, Ordering::Relaxed);
            return parse_response(&datagram.data).ok_or("Failed to parse response");
        }

        let elapsed = crate::hal::apic::get_tick_count() - start;
        if elapsed > timeout_ticks {
            let _ = udp::socket_close(socket);
            TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            return Err("Request timeout");
        }

        // Small delay to avoid busy waiting
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}

/// Get a single OID value
pub fn get_single(
    device_index: usize,
    target_ip: Ipv4Address,
    community: &str,
    oid: &[u32],
    timeout_ms: u32,
) -> Result<SnmpValue, &'static str> {
    let results = get(device_index, target_ip, community, &[oid], timeout_ms)?;
    results.into_iter().next().map(|(_, v)| v).ok_or("No value returned")
}

/// Global SNMP statistics
static REQUESTS_SENT: AtomicU32 = AtomicU32::new(0);
static RESPONSES_RECEIVED: AtomicU32 = AtomicU32::new(0);
static TIMEOUTS: AtomicU32 = AtomicU32::new(0);

/// SNMP statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct SnmpStats {
    pub requests_sent: u32,
    pub responses_received: u32,
    pub timeouts: u32,
}

/// Get SNMP statistics
pub fn get_stats() -> SnmpStats {
    SnmpStats {
        requests_sent: REQUESTS_SENT.load(Ordering::Relaxed),
        responses_received: RESPONSES_RECEIVED.load(Ordering::Relaxed),
        timeouts: TIMEOUTS.load(Ordering::Relaxed),
    }
}

/// Initialize SNMP module
pub fn init() {
    crate::serial_println!("[SNMP] SNMP client initialized");
}
