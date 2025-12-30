//! Loopback Network Device
//!
//! A virtual network device for testing the network stack.
//! Packets transmitted are looped back as received packets.

extern crate alloc;

use super::device::{NetworkDevice, NetworkDeviceInfo, NetworkDeviceState, DeviceCapabilities, TxCallback};
use super::ethernet::MacAddress;
use super::ip::Ipv4Address;
use alloc::string::String;
use alloc::vec::Vec;
use crate::ke::SpinLock;

/// Loopback MAC address (locally administered)
pub const LOOPBACK_MAC: MacAddress = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

/// Loopback IP address (127.0.0.1)
pub const LOOPBACK_IP: Ipv4Address = Ipv4Address::new([127, 0, 0, 1]);

/// Loopback subnet mask (255.0.0.0)
pub const LOOPBACK_MASK: Ipv4Address = Ipv4Address::new([255, 0, 0, 0]);

/// Maximum number of queued packets
const MAX_QUEUE_SIZE: usize = 16;

/// Maximum packet size
const MAX_PACKET_SIZE: usize = 1536;

/// Packet queue entry
struct QueuedPacket {
    data: [u8; MAX_PACKET_SIZE],
    len: usize,
    valid: bool,
}

impl QueuedPacket {
    const fn empty() -> Self {
        Self {
            data: [0u8; MAX_PACKET_SIZE],
            len: 0,
            valid: false,
        }
    }
}

/// Loopback device packet queue
static mut LOOPBACK_QUEUE: [QueuedPacket; MAX_QUEUE_SIZE] = [
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
    QueuedPacket::empty(),
];
static mut LOOPBACK_QUEUE_HEAD: usize = 0;
static mut LOOPBACK_QUEUE_TAIL: usize = 0;
static LOOPBACK_LOCK: SpinLock<()> = SpinLock::new(());

/// Loopback device index (set after registration)
static mut LOOPBACK_DEVICE_INDEX: Option<usize> = None;

/// Transmit callback for loopback device
fn loopback_tx(_device: &NetworkDevice, packet: &[u8]) -> Result<usize, &'static str> {
    if packet.len() > MAX_PACKET_SIZE {
        return Err("Packet too large");
    }

    let _guard = LOOPBACK_LOCK.lock();

    unsafe {
        // Check if queue is full
        let next_tail = (LOOPBACK_QUEUE_TAIL + 1) % MAX_QUEUE_SIZE;
        if next_tail == LOOPBACK_QUEUE_HEAD && LOOPBACK_QUEUE[LOOPBACK_QUEUE_TAIL].valid {
            return Err("Queue full");
        }

        // Queue the packet
        let entry = &mut LOOPBACK_QUEUE[LOOPBACK_QUEUE_TAIL];
        entry.data[..packet.len()].copy_from_slice(packet);
        entry.len = packet.len();
        entry.valid = true;
        LOOPBACK_QUEUE_TAIL = next_tail;
    }

    Ok(packet.len())
}

/// Create a loopback network device
pub fn create_loopback_device() -> NetworkDevice {
    let info = NetworkDeviceInfo {
        name: String::from("lo0"),
        mac_address: LOOPBACK_MAC,
        capabilities: DeviceCapabilities {
            flags: 0,
            mtu: super::ETHERNET_MTU as u32,
            max_frame_size: MAX_PACKET_SIZE as u32,
            link_speed: 10000, // 10 Gbps virtual speed
        },
        vendor_id: 0,
        device_id: 0,
    };

    let mut device = NetworkDevice::new(info);
    device.tx_callback = Some(loopback_tx as TxCallback);
    device.set_state(NetworkDeviceState::Connected);
    device.set_ip_config(LOOPBACK_IP, LOOPBACK_MASK, None);

    device
}

/// Initialize and register the loopback device
pub fn init() -> Result<usize, &'static str> {
    crate::serial_println!("[NET] Initializing loopback device...");

    let device = create_loopback_device();
    let index = super::register_device(device)?;

    unsafe {
        LOOPBACK_DEVICE_INDEX = Some(index);
    }

    crate::serial_println!("[NET] Loopback device registered as device {}", index);
    Ok(index)
}

/// Get the loopback device index
pub fn get_device_index() -> Option<usize> {
    unsafe { LOOPBACK_DEVICE_INDEX }
}

/// Process queued loopback packets (should be called periodically)
pub fn process_queue() -> usize {
    let _guard = LOOPBACK_LOCK.lock();
    let mut processed = 0;

    unsafe {
        while LOOPBACK_QUEUE[LOOPBACK_QUEUE_HEAD].valid {
            let entry = &mut LOOPBACK_QUEUE[LOOPBACK_QUEUE_HEAD];

            // Process the packet as a received packet
            if let Some(device_idx) = LOOPBACK_DEVICE_INDEX {
                super::handle_rx_packet(device_idx, &entry.data[..entry.len]);
            }

            // Mark as processed
            entry.valid = false;
            LOOPBACK_QUEUE_HEAD = (LOOPBACK_QUEUE_HEAD + 1) % MAX_QUEUE_SIZE;
            processed += 1;
        }
    }

    processed
}

/// Get queue statistics
pub fn get_queue_stats() -> (usize, usize) {
    let _guard = LOOPBACK_LOCK.lock();

    unsafe {
        let mut count = 0;
        for i in 0..MAX_QUEUE_SIZE {
            if LOOPBACK_QUEUE[i].valid {
                count += 1;
            }
        }
        (count, MAX_QUEUE_SIZE)
    }
}
