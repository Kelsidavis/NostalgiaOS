//! ARP (Address Resolution Protocol)
//!
//! ARP maps IPv4 addresses to MAC addresses.
//! RFC 826 - An Ethernet Address Resolution Protocol

extern crate alloc;

use super::ethernet::{MacAddress, EthernetHeader, EtherType, create_ethernet_frame};
use super::ip::Ipv4Address;
use alloc::vec::Vec;
use crate::ke::SpinLock;
use core::sync::atomic::Ordering;

/// ARP hardware type for Ethernet
pub const ARP_HARDWARE_ETHERNET: u16 = 1;

/// ARP protocol type for IPv4
pub const ARP_PROTOCOL_IPV4: u16 = 0x0800;

/// ARP packet size (for Ethernet/IPv4)
pub const ARP_PACKET_SIZE: usize = 28;

/// Maximum ARP cache entries
pub const MAX_ARP_ENTRIES: usize = 64;

/// ARP cache timeout in milliseconds (5 minutes)
pub const ARP_CACHE_TIMEOUT_MS: u64 = 300_000;

/// ARP operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ArpOperation {
    /// ARP request (who-has)
    Request = 1,
    /// ARP reply (is-at)
    Reply = 2,
    /// RARP request
    RarpRequest = 3,
    /// RARP reply
    RarpReply = 4,
}

impl From<u16> for ArpOperation {
    fn from(value: u16) -> Self {
        match value {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            3 => ArpOperation::RarpRequest,
            4 => ArpOperation::RarpReply,
            _ => ArpOperation::Request, // Default
        }
    }
}

/// ARP packet (for Ethernet/IPv4)
#[derive(Debug, Clone, Copy)]
pub struct ArpPacket {
    /// Hardware type (1 = Ethernet)
    pub hardware_type: u16,
    /// Protocol type (0x0800 = IPv4)
    pub protocol_type: u16,
    /// Hardware address length (6 for Ethernet)
    pub hardware_len: u8,
    /// Protocol address length (4 for IPv4)
    pub protocol_len: u8,
    /// Operation code
    pub operation: ArpOperation,
    /// Sender hardware (MAC) address
    pub sender_mac: MacAddress,
    /// Sender protocol (IP) address
    pub sender_ip: Ipv4Address,
    /// Target hardware (MAC) address
    pub target_mac: MacAddress,
    /// Target protocol (IP) address
    pub target_ip: Ipv4Address,
}

impl ArpPacket {
    /// Create a new ARP request
    pub fn request(sender_mac: MacAddress, sender_ip: Ipv4Address, target_ip: Ipv4Address) -> Self {
        Self {
            hardware_type: ARP_HARDWARE_ETHERNET,
            protocol_type: ARP_PROTOCOL_IPV4,
            hardware_len: 6,
            protocol_len: 4,
            operation: ArpOperation::Request,
            sender_mac,
            sender_ip,
            target_mac: MacAddress::ZERO,
            target_ip,
        }
    }

    /// Create a new ARP reply
    pub fn reply(
        sender_mac: MacAddress,
        sender_ip: Ipv4Address,
        target_mac: MacAddress,
        target_ip: Ipv4Address,
    ) -> Self {
        Self {
            hardware_type: ARP_HARDWARE_ETHERNET,
            protocol_type: ARP_PROTOCOL_IPV4,
            hardware_len: 6,
            protocol_len: 4,
            operation: ArpOperation::Reply,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }

    /// Serialize the ARP packet to bytes
    pub fn to_bytes(&self) -> [u8; ARP_PACKET_SIZE] {
        let mut bytes = [0u8; ARP_PACKET_SIZE];

        bytes[0..2].copy_from_slice(&self.hardware_type.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.protocol_type.to_be_bytes());
        bytes[4] = self.hardware_len;
        bytes[5] = self.protocol_len;
        bytes[6..8].copy_from_slice(&(self.operation as u16).to_be_bytes());
        bytes[8..14].copy_from_slice(&self.sender_mac.0);
        bytes[14..18].copy_from_slice(&self.sender_ip.0);
        bytes[18..24].copy_from_slice(&self.target_mac.0);
        bytes[24..28].copy_from_slice(&self.target_ip.0);

        bytes
    }
}

/// Parse an ARP packet
pub fn parse_arp_packet(data: &[u8]) -> Option<ArpPacket> {
    if data.len() < ARP_PACKET_SIZE {
        return None;
    }

    let hardware_type = u16::from_be_bytes([data[0], data[1]]);
    let protocol_type = u16::from_be_bytes([data[2], data[3]]);
    let hardware_len = data[4];
    let protocol_len = data[5];
    let operation = ArpOperation::from(u16::from_be_bytes([data[6], data[7]]));

    // Verify this is Ethernet/IPv4
    if hardware_type != ARP_HARDWARE_ETHERNET || protocol_type != ARP_PROTOCOL_IPV4 {
        return None;
    }
    if hardware_len != 6 || protocol_len != 4 {
        return None;
    }

    let sender_mac = MacAddress::new([data[8], data[9], data[10], data[11], data[12], data[13]]);
    let sender_ip = Ipv4Address::new([data[14], data[15], data[16], data[17]]);
    let target_mac = MacAddress::new([data[18], data[19], data[20], data[21], data[22], data[23]]);
    let target_ip = Ipv4Address::new([data[24], data[25], data[26], data[27]]);

    Some(ArpPacket {
        hardware_type,
        protocol_type,
        hardware_len,
        protocol_len,
        operation,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

/// ARP cache entry
#[derive(Debug, Clone, Copy)]
pub struct ArpCacheEntry {
    /// IP address
    pub ip_address: Ipv4Address,
    /// MAC address
    pub mac_address: MacAddress,
    /// Timestamp when entry was created/updated (ticks)
    pub timestamp: u64,
    /// Is this a static entry (doesn't expire)
    pub is_static: bool,
    /// Entry is valid
    pub valid: bool,
}

impl ArpCacheEntry {
    pub const fn empty() -> Self {
        Self {
            ip_address: Ipv4Address::new([0, 0, 0, 0]),
            mac_address: MacAddress::ZERO,
            timestamp: 0,
            is_static: false,
            valid: false,
        }
    }
}

/// ARP cache
static mut ARP_CACHE: [ArpCacheEntry; MAX_ARP_ENTRIES] = [ArpCacheEntry::empty(); MAX_ARP_ENTRIES];
static ARP_LOCK: SpinLock<()> = SpinLock::new(());

/// Initialize ARP module
pub fn init() {
    crate::serial_println!("[ARP] ARP module initialized");
}

/// Look up a MAC address in the ARP cache
pub fn arp_cache_lookup(ip: Ipv4Address) -> Option<MacAddress> {
    let _guard = ARP_LOCK.lock();
    let current_time = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);

    unsafe {
        for entry in ARP_CACHE.iter() {
            if entry.valid && entry.ip_address == ip {
                // Check if entry has expired
                if !entry.is_static {
                    let age = current_time.saturating_sub(entry.timestamp);
                    if age > ARP_CACHE_TIMEOUT_MS {
                        continue; // Entry expired
                    }
                }
                return Some(entry.mac_address);
            }
        }
    }

    None
}

/// Add or update an ARP cache entry
pub fn arp_cache_add(ip: Ipv4Address, mac: MacAddress, is_static: bool) {
    let _guard = ARP_LOCK.lock();
    let current_time = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);

    unsafe {
        // First, try to find existing entry
        for entry in ARP_CACHE.iter_mut() {
            if entry.valid && entry.ip_address == ip {
                entry.mac_address = mac;
                entry.timestamp = current_time;
                entry.is_static = is_static;
                crate::serial_println!("[ARP] Updated {:?} -> {:?}", ip, mac);
                return;
            }
        }

        // Find a free slot or oldest entry
        let mut best_idx = 0;
        let mut oldest_time = u64::MAX;

        for (i, entry) in ARP_CACHE.iter().enumerate() {
            if !entry.valid {
                best_idx = i;
                break;
            }
            if !entry.is_static && entry.timestamp < oldest_time {
                oldest_time = entry.timestamp;
                best_idx = i;
            }
        }

        // Add the new entry
        ARP_CACHE[best_idx] = ArpCacheEntry {
            ip_address: ip,
            mac_address: mac,
            timestamp: current_time,
            is_static,
            valid: true,
        };

        crate::serial_println!("[ARP] Added {:?} -> {:?}", ip, mac);
    }
}

/// Handle an incoming ARP packet
pub fn handle_arp_packet(
    device_index: usize,
    _eth_header: &EthernetHeader,
    arp: &ArpPacket,
) {
    crate::serial_println!(
        "[ARP] {:?} from {:?} ({:?}), target {:?}",
        arp.operation,
        arp.sender_ip,
        arp.sender_mac,
        arp.target_ip
    );

    // Always learn from the sender (even for requests)
    arp_cache_add(arp.sender_ip, arp.sender_mac, false);

    // Update global stats
    unsafe {
        if arp.operation == ArpOperation::Reply {
            super::NETWORK_STATS.arp_replies += 1;
        }
    }

    match arp.operation {
        ArpOperation::Request => {
            // Check if the request is for us
            if let Some(device) = super::get_device(device_index) {
                if let Some(our_ip) = device.ip_address {
                    if arp.target_ip == our_ip {
                        // Send ARP reply
                        crate::serial_println!("[ARP] Replying to request for {:?}", our_ip);
                        let _ = send_arp_reply(
                            device_index,
                            device.info.mac_address,
                            our_ip,
                            arp.sender_mac,
                            arp.sender_ip,
                        );
                    }
                }
            }
        }
        ArpOperation::Reply => {
            // Already added to cache above
        }
        _ => {}
    }
}

/// Send an ARP request
pub fn send_arp_request(
    device_index: usize,
    sender_mac: MacAddress,
    sender_ip: Ipv4Address,
    target_ip: Ipv4Address,
) -> Result<(), &'static str> {
    let arp = ArpPacket::request(sender_mac, sender_ip, target_ip);
    let arp_bytes = arp.to_bytes();

    let frame = create_ethernet_frame(
        MacAddress::BROADCAST,
        sender_mac,
        EtherType::Arp,
        &arp_bytes,
    );

    if let Some(device) = super::get_device_mut(device_index) {
        device.transmit(&frame)?;
        unsafe {
            super::NETWORK_STATS.arp_requests += 1;
        }
        Ok(())
    } else {
        Err("Device not found")
    }
}

/// Send an ARP reply
fn send_arp_reply(
    device_index: usize,
    sender_mac: MacAddress,
    sender_ip: Ipv4Address,
    target_mac: MacAddress,
    target_ip: Ipv4Address,
) -> Result<(), &'static str> {
    let arp = ArpPacket::reply(sender_mac, sender_ip, target_mac, target_ip);
    let arp_bytes = arp.to_bytes();

    let frame = create_ethernet_frame(target_mac, sender_mac, EtherType::Arp, &arp_bytes);

    if let Some(device) = super::get_device_mut(device_index) {
        device.transmit(&frame).map(|_| ())
    } else {
        Err("Device not found")
    }
}

/// Resolve an IP address to a MAC address (blocking)
pub fn arp_resolve(
    device_index: usize,
    target_ip: Ipv4Address,
    timeout_ms: u64,
) -> Option<MacAddress> {
    // Check cache first
    if let Some(mac) = arp_cache_lookup(target_ip) {
        return Some(mac);
    }

    // Get device info
    let (sender_mac, sender_ip) = {
        let device = super::get_device(device_index)?;
        (device.info.mac_address, device.ip_address?)
    };

    // Send ARP request
    if send_arp_request(device_index, sender_mac, sender_ip, target_ip).is_err() {
        return None;
    }

    // Wait for reply (simple polling)
    let start = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);
    loop {
        if let Some(mac) = arp_cache_lookup(target_ip) {
            return Some(mac);
        }

        let elapsed = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed) - start;
        if elapsed >= timeout_ms {
            crate::serial_println!("[ARP] Timeout resolving {:?}", target_ip);
            return None;
        }

        // Small delay
        core::hint::spin_loop();
    }
}

/// Send a gratuitous ARP (announce our IP)
pub fn arp_announce(device_index: usize) -> Result<(), &'static str> {
    let device = super::get_device(device_index).ok_or("Device not found")?;
    let mac = device.info.mac_address;
    let ip = device.ip_address.ok_or("No IP configured")?;

    // Gratuitous ARP: sender IP == target IP
    send_arp_request(device_index, mac, ip, ip)
}

/// Get ARP cache entries count
pub fn get_cache_count() -> usize {
    let _guard = ARP_LOCK.lock();
    unsafe { ARP_CACHE.iter().filter(|e| e.valid).count() }
}

/// Get all ARP cache entries
pub fn get_cache_entries() -> Vec<ArpCacheEntry> {
    let _guard = ARP_LOCK.lock();
    unsafe { ARP_CACHE.iter().filter(|e| e.valid).copied().collect() }
}
