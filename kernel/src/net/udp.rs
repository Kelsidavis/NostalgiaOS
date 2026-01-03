//! UDP (User Datagram Protocol)
//!
//! RFC 768 - User Datagram Protocol
//! Provides connectionless, unreliable datagram delivery.

extern crate alloc;

use super::ethernet::{EtherType, create_ethernet_frame};
use super::ip::{Ipv4Header, Ipv4Address, IpProtocol, internet_checksum};
use alloc::vec::Vec;
use crate::ke::SpinLock;
use core::sync::atomic::{AtomicU16, Ordering};

/// UDP header size in bytes
pub const UDP_HEADER_SIZE: usize = 8;

/// Maximum UDP payload size (MTU - IP header - UDP header)
pub const MAX_UDP_PAYLOAD: usize = 1500 - 20 - 8;

/// Maximum number of UDP sockets
pub const MAX_UDP_SOCKETS: usize = 32;

/// Maximum receive queue size per socket
pub const MAX_RX_QUEUE: usize = 16;

/// UDP header
#[derive(Debug, Clone, Copy)]
pub struct UdpHeader {
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Length (header + data)
    pub length: u16,
    /// Checksum (optional in IPv4, but we compute it)
    pub checksum: u16,
}

impl UdpHeader {
    /// Create a new UDP header
    pub fn new(src_port: u16, dst_port: u16, data_len: usize) -> Self {
        Self {
            src_port,
            dst_port,
            length: (UDP_HEADER_SIZE + data_len) as u16,
            checksum: 0,
        }
    }

    /// Serialize the header to bytes
    pub fn to_bytes(&self) -> [u8; UDP_HEADER_SIZE] {
        let mut bytes = [0u8; UDP_HEADER_SIZE];
        bytes[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.length.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.checksum.to_be_bytes());
        bytes
    }

    /// Compute UDP checksum (includes pseudo-header)
    pub fn compute_checksum(&mut self, src_ip: Ipv4Address, dst_ip: Ipv4Address, data: &[u8]) {
        // Build pseudo-header + UDP header + data for checksum
        let mut pseudo = Vec::with_capacity(12 + UDP_HEADER_SIZE + data.len());

        // Pseudo-header
        pseudo.extend_from_slice(&src_ip.0);
        pseudo.extend_from_slice(&dst_ip.0);
        pseudo.push(0); // Reserved
        pseudo.push(IpProtocol::Udp as u8);
        pseudo.extend_from_slice(&self.length.to_be_bytes());

        // UDP header (with checksum = 0)
        self.checksum = 0;
        pseudo.extend_from_slice(&self.to_bytes());

        // Data
        pseudo.extend_from_slice(data);

        // Pad to even length if needed
        if pseudo.len() % 2 != 0 {
            pseudo.push(0);
        }

        self.checksum = internet_checksum(&pseudo);

        // UDP uses 0xFFFF if computed checksum is 0
        if self.checksum == 0 {
            self.checksum = 0xFFFF;
        }
    }
}

/// Parse a UDP packet
pub fn parse_udp_packet(data: &[u8]) -> Option<UdpHeader> {
    if data.len() < UDP_HEADER_SIZE {
        return None;
    }

    Some(UdpHeader {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
        length: u16::from_be_bytes([data[4], data[5]]),
        checksum: u16::from_be_bytes([data[6], data[7]]),
    })
}

/// Received UDP datagram
#[derive(Clone)]
pub struct UdpDatagram {
    /// Source IP address
    pub src_ip: Ipv4Address,
    /// Source port
    pub src_port: u16,
    /// Data payload
    pub data: Vec<u8>,
}

/// UDP socket state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSocketState {
    /// Socket is closed/unused
    Closed,
    /// Socket is bound to a port
    Bound,
}

/// UDP socket receive queue entry
struct RxQueueEntry {
    datagram: Option<UdpDatagram>,
}

impl RxQueueEntry {
    const fn empty() -> Self {
        Self { datagram: None }
    }
}

/// UDP socket
pub struct UdpSocket {
    /// Socket state
    pub state: UdpSocketState,
    /// Local port (0 = unbound)
    pub local_port: u16,
    /// Local IP address (0.0.0.0 = any)
    pub local_ip: Ipv4Address,
    /// Receive queue
    rx_queue: [RxQueueEntry; MAX_RX_QUEUE],
    /// Receive queue head (next to read)
    rx_head: usize,
    /// Receive queue tail (next to write)
    rx_tail: usize,
    /// Number of items in queue
    rx_count: usize,
}

impl UdpSocket {
    const fn new() -> Self {
        const EMPTY_ENTRY: RxQueueEntry = RxQueueEntry::empty();
        Self {
            state: UdpSocketState::Closed,
            local_port: 0,
            local_ip: Ipv4Address::new([0, 0, 0, 0]),
            rx_queue: [EMPTY_ENTRY; MAX_RX_QUEUE],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
        }
    }

    /// Check if socket has pending data
    pub fn has_data(&self) -> bool {
        self.rx_count > 0
    }

    /// Get number of pending datagrams
    pub fn pending_count(&self) -> usize {
        self.rx_count
    }
}

/// UDP socket table
static mut UDP_SOCKETS: [UdpSocket; MAX_UDP_SOCKETS] = {
    const EMPTY_SOCKET: UdpSocket = UdpSocket::new();
    [EMPTY_SOCKET; MAX_UDP_SOCKETS]
};
static UDP_LOCK: SpinLock<()> = SpinLock::new(());

/// Next ephemeral port
static NEXT_EPHEMERAL_PORT: AtomicU16 = AtomicU16::new(49152);

/// Initialize UDP module
pub fn init() {
    crate::serial_println!("[UDP] UDP module initialized");
}

/// Allocate an ephemeral port
fn allocate_ephemeral_port() -> u16 {
    loop {
        let port = NEXT_EPHEMERAL_PORT.fetch_add(1, Ordering::SeqCst);
        // Wrap around in ephemeral range (49152-65535)
        if port > 65534 {
            NEXT_EPHEMERAL_PORT.store(49152, Ordering::SeqCst);
        }

        // Check if port is in use
        let in_use = unsafe {
            UDP_SOCKETS.iter().any(|s| s.state == UdpSocketState::Bound && s.local_port == port)
        };

        if !in_use {
            return port;
        }
    }
}

/// Create a new UDP socket
pub fn socket_create() -> Option<usize> {
    let _guard = UDP_LOCK.lock();

    unsafe {
        for (i, socket) in UDP_SOCKETS.iter_mut().enumerate() {
            if socket.state == UdpSocketState::Closed {
                socket.state = UdpSocketState::Bound;
                socket.local_port = 0;
                socket.local_ip = Ipv4Address::new([0, 0, 0, 0]);
                socket.rx_head = 0;
                socket.rx_tail = 0;
                socket.rx_count = 0;
                return Some(i);
            }
        }
    }

    None
}

/// Bind a socket to a local port
pub fn socket_bind(socket_id: usize, port: u16) -> Result<(), &'static str> {
    let _guard = UDP_LOCK.lock();

    unsafe {
        if socket_id >= MAX_UDP_SOCKETS {
            return Err("Invalid socket ID");
        }

        let socket = &mut UDP_SOCKETS[socket_id];
        if socket.state == UdpSocketState::Closed {
            return Err("Socket not open");
        }

        // Check if port is already in use
        for (i, s) in UDP_SOCKETS.iter().enumerate() {
            if i != socket_id && s.state == UdpSocketState::Bound && s.local_port == port {
                return Err("Port already in use");
            }
        }

        socket.local_port = port;
        Ok(())
    }
}

/// Close a UDP socket
pub fn socket_close(socket_id: usize) -> Result<(), &'static str> {
    let _guard = UDP_LOCK.lock();

    unsafe {
        if socket_id >= MAX_UDP_SOCKETS {
            return Err("Invalid socket ID");
        }

        let socket = &mut UDP_SOCKETS[socket_id];
        socket.state = UdpSocketState::Closed;
        socket.local_port = 0;
        socket.rx_head = 0;
        socket.rx_tail = 0;
        socket.rx_count = 0;

        // Clear receive queue
        for entry in socket.rx_queue.iter_mut() {
            entry.datagram = None;
        }

        Ok(())
    }
}

/// Send a UDP datagram
pub fn socket_sendto(
    socket_id: usize,
    device_index: usize,
    dst_ip: Ipv4Address,
    dst_port: u16,
    data: &[u8],
) -> Result<usize, &'static str> {
    if data.len() > MAX_UDP_PAYLOAD {
        return Err("Data too large");
    }

    let (src_ip, src_mac, local_port) = {
        let _guard = UDP_LOCK.lock();

        unsafe {
            if socket_id >= MAX_UDP_SOCKETS {
                return Err("Invalid socket ID");
            }

            let socket = &mut UDP_SOCKETS[socket_id];
            if socket.state == UdpSocketState::Closed {
                return Err("Socket not open");
            }

            // Assign ephemeral port if not bound
            if socket.local_port == 0 {
                socket.local_port = allocate_ephemeral_port();
            }

            let device = super::get_device(device_index).ok_or("Device not found")?;
            let src_ip = device.ip_address.ok_or("No IP configured")?;
            let src_mac = device.info.mac_address;

            (src_ip, src_mac, socket.local_port)
        }
    };

    // Resolve destination MAC
    let dst_mac = super::arp::arp_resolve(device_index, dst_ip, 3000)
        .ok_or("ARP resolution failed")?;

    // Build UDP header
    let mut udp_header = UdpHeader::new(local_port, dst_port, data.len());
    udp_header.compute_checksum(src_ip, dst_ip, data);
    let udp_bytes = udp_header.to_bytes();

    // Build IP header
    let payload_len = (UDP_HEADER_SIZE + data.len()) as u16;
    let mut ip_header = Ipv4Header::new(src_ip, dst_ip, IpProtocol::Udp, payload_len, 64);
    ip_header.compute_checksum();
    let ip_bytes = ip_header.to_bytes();

    // Build full packet
    let mut packet = Vec::with_capacity(ip_bytes.len() + udp_bytes.len() + data.len());
    packet.extend_from_slice(&ip_bytes);
    packet.extend_from_slice(&udp_bytes);
    packet.extend_from_slice(data);

    // Create Ethernet frame
    let frame = create_ethernet_frame(dst_mac, src_mac, EtherType::Ipv4, &packet);

    // Send
    if let Some(device) = super::get_device_mut(device_index) {
        device.transmit(&frame)?;
        super::record_tx_packet(frame.len());
        Ok(data.len())
    } else {
        Err("Device not found")
    }
}

/// Receive a UDP datagram (non-blocking)
pub fn socket_recvfrom(socket_id: usize) -> Option<UdpDatagram> {
    let _guard = UDP_LOCK.lock();

    unsafe {
        if socket_id >= MAX_UDP_SOCKETS {
            return None;
        }

        let socket = &mut UDP_SOCKETS[socket_id];
        if socket.state == UdpSocketState::Closed || socket.rx_count == 0 {
            return None;
        }

        let entry = &mut socket.rx_queue[socket.rx_head];
        let datagram = entry.datagram.take();
        socket.rx_head = (socket.rx_head + 1) % MAX_RX_QUEUE;
        socket.rx_count -= 1;

        datagram
    }
}

/// Check if socket has pending data
pub fn socket_has_data(socket_id: usize) -> bool {
    let _guard = UDP_LOCK.lock();

    unsafe {
        if socket_id >= MAX_UDP_SOCKETS {
            return false;
        }
        UDP_SOCKETS[socket_id].rx_count > 0
    }
}

/// Handle an incoming UDP packet
pub fn handle_udp_packet(
    _device_index: usize,
    ip_header: &Ipv4Header,
    udp: &UdpHeader,
    data: &[u8],
) {
    crate::serial_println!(
        "[UDP] Packet from {:?}:{} to port {} ({} bytes)",
        ip_header.source_addr,
        udp.src_port,
        udp.dst_port,
        data.len()
    );

    let _guard = UDP_LOCK.lock();

    unsafe {
        // Find a socket bound to this port
        for socket in UDP_SOCKETS.iter_mut() {
            if socket.state == UdpSocketState::Bound && socket.local_port == udp.dst_port {
                // Check if queue has space
                if socket.rx_count >= MAX_RX_QUEUE {
                    crate::serial_println!("[UDP] Socket receive queue full, dropping packet");
                    return;
                }

                // Extract payload (after UDP header)
                let payload = if data.len() > UDP_HEADER_SIZE {
                    &data[UDP_HEADER_SIZE..]
                } else {
                    &[]
                };

                // Queue the datagram
                let entry = &mut socket.rx_queue[socket.rx_tail];
                entry.datagram = Some(UdpDatagram {
                    src_ip: ip_header.source_addr,
                    src_port: udp.src_port,
                    data: payload.to_vec(),
                });
                socket.rx_tail = (socket.rx_tail + 1) % MAX_RX_QUEUE;
                socket.rx_count += 1;

                crate::serial_println!("[UDP] Queued packet for socket (queue: {})", socket.rx_count);
                return;
            }
        }

        crate::serial_println!("[UDP] No socket bound to port {}", udp.dst_port);
    }
}

/// Get UDP socket statistics
pub fn get_socket_stats() -> (usize, usize) {
    let _guard = UDP_LOCK.lock();

    unsafe {
        let active = UDP_SOCKETS.iter().filter(|s| s.state == UdpSocketState::Bound).count();
        (active, MAX_UDP_SOCKETS)
    }
}

/// Get info about a specific socket
pub fn get_socket_info(socket_id: usize) -> Option<(UdpSocketState, u16, usize)> {
    let _guard = UDP_LOCK.lock();

    unsafe {
        if socket_id >= MAX_UDP_SOCKETS {
            return None;
        }

        let socket = &UDP_SOCKETS[socket_id];
        Some((socket.state, socket.local_port, socket.rx_count))
    }
}

/// UDP endpoint info for netstat display
#[derive(Debug, Clone)]
pub struct UdpEndpointInfo {
    pub socket_id: usize,
    pub state: UdpSocketState,
    pub local_port: u16,
    pub local_ip: Ipv4Address,
    pub rx_queue: usize,
}

/// Enumerate all active UDP endpoints
pub fn enumerate_endpoints() -> alloc::vec::Vec<UdpEndpointInfo> {
    let _guard = UDP_LOCK.lock();
    let mut endpoints = alloc::vec::Vec::new();

    unsafe {
        for (i, socket) in UDP_SOCKETS.iter().enumerate() {
            if socket.state == UdpSocketState::Bound {
                endpoints.push(UdpEndpointInfo {
                    socket_id: i,
                    state: socket.state,
                    local_port: socket.local_port,
                    local_ip: socket.local_ip,
                    rx_queue: socket.rx_count,
                });
            }
        }
    }

    endpoints
}
