//! Wake-on-LAN (WoL)
//!
//! Send magic packets to wake remote machines.
//! The magic packet is a broadcast frame containing 6 bytes of 0xFF
//! followed by the target MAC address repeated 16 times.

extern crate alloc;

use super::ethernet::{MacAddress, EtherType, create_ethernet_frame};
use super::ip::Ipv4Address;
use super::udp;
use core::sync::atomic::{AtomicU32, Ordering};

/// WoL UDP port (commonly used)
pub const WOL_PORT: u16 = 9;

/// Magic packet size (6 + 16*6 = 102 bytes)
pub const MAGIC_PACKET_SIZE: usize = 102;

/// Packets sent counter
static PACKETS_SENT: AtomicU32 = AtomicU32::new(0);

/// Build a Wake-on-LAN magic packet
pub fn build_magic_packet(target_mac: MacAddress) -> [u8; MAGIC_PACKET_SIZE] {
    let mut packet = [0u8; MAGIC_PACKET_SIZE];

    // 6 bytes of 0xFF
    for i in 0..6 {
        packet[i] = 0xFF;
    }

    // Target MAC repeated 16 times
    for i in 0..16 {
        let offset = 6 + i * 6;
        packet[offset..offset + 6].copy_from_slice(&target_mac.0);
    }

    packet
}

/// Build a SecureOn magic packet with password
pub fn build_magic_packet_secure(target_mac: MacAddress, password: &[u8; 6]) -> [u8; 108] {
    let mut packet = [0u8; 108];

    // 6 bytes of 0xFF
    for i in 0..6 {
        packet[i] = 0xFF;
    }

    // Target MAC repeated 16 times
    for i in 0..16 {
        let offset = 6 + i * 6;
        packet[offset..offset + 6].copy_from_slice(&target_mac.0);
    }

    // 6-byte password
    packet[102..108].copy_from_slice(password);

    packet
}

/// Send Wake-on-LAN packet via UDP broadcast
pub fn wake_udp(
    device_index: usize,
    target_mac: MacAddress,
) -> Result<(), &'static str> {
    let magic = build_magic_packet(target_mac);

    // Create UDP socket
    let socket = udp::socket_create().ok_or("Failed to create UDP socket")?;

    // Send to broadcast address
    let broadcast = Ipv4Address::new([255, 255, 255, 255]);
    let result = udp::socket_sendto(socket, device_index, broadcast, WOL_PORT, &magic);

    let _ = udp::socket_close(socket);

    if result.is_ok() {
        PACKETS_SENT.fetch_add(1, Ordering::Relaxed);
        crate::serial_println!("[WOL] Magic packet sent to {:?}", target_mac);
    }

    result.map(|_| ())
}

/// Send Wake-on-LAN packet via raw Ethernet broadcast
pub fn wake_raw(
    device_index: usize,
    target_mac: MacAddress,
) -> Result<(), &'static str> {
    let magic = build_magic_packet(target_mac);

    // Get source MAC
    let device = super::get_device(device_index).ok_or("Device not found")?;
    let src_mac = device.info.mac_address;

    // Broadcast MAC
    let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    // Create Ethernet frame with magic packet as payload
    // Use EtherType 0x0842 (Wake-on-LAN) or encapsulate in UDP
    let frame = create_ethernet_frame(dst_mac, src_mac, EtherType::Ipv4, &magic);

    // Send via device
    if let Some(dev) = super::get_device_mut(device_index) {
        dev.transmit(&frame)?;
        super::record_tx_packet(frame.len());
        PACKETS_SENT.fetch_add(1, Ordering::Relaxed);
        crate::serial_println!("[WOL] Raw magic packet sent to {:?}", target_mac);
        Ok(())
    } else {
        Err("Device not found")
    }
}

/// Send Wake-on-LAN to a specific IP address (directed broadcast)
pub fn wake_directed(
    device_index: usize,
    target_mac: MacAddress,
    target_ip: Ipv4Address,
) -> Result<(), &'static str> {
    let magic = build_magic_packet(target_mac);

    // Create UDP socket
    let socket = udp::socket_create().ok_or("Failed to create UDP socket")?;

    // Send to target IP
    let result = udp::socket_sendto(socket, device_index, target_ip, WOL_PORT, &magic);

    let _ = udp::socket_close(socket);

    if result.is_ok() {
        PACKETS_SENT.fetch_add(1, Ordering::Relaxed);
        crate::serial_println!("[WOL] Directed magic packet sent to {:?} at {:?}", target_mac, target_ip);
    }

    result.map(|_| ())
}

/// Parse MAC address from string (formats: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF)
pub fn parse_mac(s: &str) -> Option<MacAddress> {
    let mut octets = [0u8; 6];
    let mut idx = 0;
    let mut current: u8 = 0;
    let mut digits = 0;

    for c in s.chars() {
        if c == ':' || c == '-' {
            if digits == 0 {
                return None;
            }
            if idx >= 6 {
                return None;
            }
            octets[idx] = current;
            idx += 1;
            current = 0;
            digits = 0;
        } else if let Some(d) = c.to_digit(16) {
            if digits >= 2 {
                return None;
            }
            current = (current << 4) | (d as u8);
            digits += 1;
        } else {
            return None;
        }
    }

    // Last octet
    if digits > 0 && idx < 6 {
        octets[idx] = current;
        idx += 1;
    }

    if idx == 6 {
        Some(MacAddress(octets))
    } else {
        None
    }
}

/// Get WoL statistics
pub fn get_stats() -> u32 {
    PACKETS_SENT.load(Ordering::Relaxed)
}

/// Initialize WoL module
pub fn init() {
    crate::serial_println!("[WOL] Wake-on-LAN module initialized");
}
