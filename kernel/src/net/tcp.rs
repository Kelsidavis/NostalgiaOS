//! TCP (Transmission Control Protocol)
//!
//! RFC 793 - Transmission Control Protocol
//! Provides reliable, ordered, connection-oriented byte streams.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use crate::ke::SpinLock;
use super::ip::{Ipv4Address, IpProtocol};
use super::Ipv4Header;

/// TCP header size (without options)
pub const TCP_HEADER_SIZE: usize = 20;

/// Maximum segment size (default)
pub const TCP_DEFAULT_MSS: u16 = 536;

/// TCP window size
pub const TCP_WINDOW_SIZE: u16 = 8192;

/// Maximum number of TCP sockets
pub const MAX_TCP_SOCKETS: usize = 64;

/// Maximum pending connections for listen socket
pub const TCP_BACKLOG_SIZE: usize = 8;

/// Retransmission timeout (in ticks, ~ms)
pub const TCP_RTO_INITIAL: u64 = 1000;

/// Time-wait timeout (2 * MSL, ~60 seconds)
pub const TCP_TIME_WAIT_TIMEOUT: u64 = 60000;

/// TCP flags
pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// TCP option kinds
pub mod option {
    pub const END: u8 = 0;
    pub const NOP: u8 = 1;
    pub const MSS: u8 = 2;
    pub const WINDOW_SCALE: u8 = 3;
    pub const SACK_PERMITTED: u8 = 4;
    pub const SACK: u8 = 5;
    pub const TIMESTAMP: u8 = 8;
}

/// TCP connection states (RFC 793)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// Initial state, socket created but not in use
    Closed,
    /// Waiting for connection request (server)
    Listen,
    /// SYN sent, waiting for SYN-ACK (client)
    SynSent,
    /// SYN received, SYN-ACK sent, waiting for ACK (server)
    SynReceived,
    /// Connection established, data transfer possible
    Established,
    /// FIN sent, waiting for ACK (active close)
    FinWait1,
    /// FIN-ACK received, waiting for FIN from peer
    FinWait2,
    /// FIN received, waiting for application to close
    CloseWait,
    /// Both sides initiated close simultaneously
    Closing,
    /// Waiting for ACK of FIN (passive close)
    LastAck,
    /// Waiting for enough time to pass to ensure remote received ACK
    TimeWait,
}

/// TCP header structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TcpHeader {
    /// Source port
    pub source_port: u16,
    /// Destination port
    pub dest_port: u16,
    /// Sequence number
    pub seq_num: u32,
    /// Acknowledgment number
    pub ack_num: u32,
    /// Data offset (4 bits) + Reserved (3 bits) + NS flag (1 bit)
    pub data_offset_reserved: u8,
    /// TCP flags
    pub flags: u8,
    /// Window size
    pub window: u16,
    /// Checksum
    pub checksum: u16,
    /// Urgent pointer
    pub urgent_ptr: u16,
}

impl TcpHeader {
    /// Get data offset in bytes (header length)
    pub fn data_offset(&self) -> usize {
        ((self.data_offset_reserved >> 4) as usize) * 4
    }

    /// Check if SYN flag is set
    pub fn is_syn(&self) -> bool {
        self.flags & flags::SYN != 0
    }

    /// Check if ACK flag is set
    pub fn is_ack(&self) -> bool {
        self.flags & flags::ACK != 0
    }

    /// Check if FIN flag is set
    pub fn is_fin(&self) -> bool {
        self.flags & flags::FIN != 0
    }

    /// Check if RST flag is set
    pub fn is_rst(&self) -> bool {
        self.flags & flags::RST != 0
    }

    /// Check if PSH flag is set
    pub fn is_psh(&self) -> bool {
        self.flags & flags::PSH != 0
    }
}

/// Parse TCP header from packet data
pub fn parse_tcp_header(data: &[u8]) -> Option<TcpHeader> {
    if data.len() < TCP_HEADER_SIZE {
        return None;
    }

    Some(TcpHeader {
        source_port: u16::from_be_bytes([data[0], data[1]]),
        dest_port: u16::from_be_bytes([data[2], data[3]]),
        seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        data_offset_reserved: data[12],
        flags: data[13],
        window: u16::from_be_bytes([data[14], data[15]]),
        checksum: u16::from_be_bytes([data[16], data[17]]),
        urgent_ptr: u16::from_be_bytes([data[18], data[19]]),
    })
}

/// TCP pseudo-header for checksum calculation
fn tcp_checksum(src_ip: Ipv4Address, dst_ip: Ipv4Address, tcp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    sum += u16::from_be_bytes([src_ip.0[0], src_ip.0[1]]) as u32;
    sum += u16::from_be_bytes([src_ip.0[2], src_ip.0[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip.0[0], dst_ip.0[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip.0[2], dst_ip.0[3]]) as u32;
    sum += IpProtocol::Tcp as u32;
    sum += tcp_data.len() as u32;

    // TCP header + data
    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Build TCP segment
fn build_tcp_segment(
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    tcp_flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let header_len = TCP_HEADER_SIZE;
    let total_len = header_len + payload.len();
    let mut segment = vec![0u8; total_len];

    // Source port
    segment[0..2].copy_from_slice(&src_port.to_be_bytes());
    // Destination port
    segment[2..4].copy_from_slice(&dst_port.to_be_bytes());
    // Sequence number
    segment[4..8].copy_from_slice(&seq_num.to_be_bytes());
    // Acknowledgment number
    segment[8..12].copy_from_slice(&ack_num.to_be_bytes());
    // Data offset (5 = 20 bytes header) and reserved
    segment[12] = (header_len as u8 / 4) << 4;
    // Flags
    segment[13] = tcp_flags;
    // Window
    segment[14..16].copy_from_slice(&window.to_be_bytes());
    // Checksum (initially 0)
    segment[16..18].copy_from_slice(&[0, 0]);
    // Urgent pointer
    segment[18..20].copy_from_slice(&[0, 0]);

    // Copy payload
    if !payload.is_empty() {
        segment[header_len..].copy_from_slice(payload);
    }

    // Calculate checksum
    let checksum = tcp_checksum(src_ip, dst_ip, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());

    segment
}

/// TCP socket handle
pub type TcpSocket = usize;

/// Pending connection for listen sockets
#[derive(Debug, Clone)]
struct PendingConnection {
    remote_ip: Ipv4Address,
    remote_port: u16,
    seq_num: u32,
    timestamp: u64,
}

/// TCP Transmission Control Block (TCB)
struct TcpControlBlock {
    /// Socket state
    state: TcpState,
    /// Local port
    local_port: u16,
    /// Remote IP address
    remote_ip: Ipv4Address,
    /// Remote port
    remote_port: u16,
    /// Network device index
    device_index: usize,
    /// Send sequence variables
    snd_una: u32,  // Oldest unacknowledged sequence number
    snd_nxt: u32,  // Next sequence number to send
    snd_wnd: u16,  // Send window
    /// Receive sequence variables
    rcv_nxt: u32,  // Next expected sequence number
    rcv_wnd: u16,  // Receive window
    /// Initial sequence number
    iss: u32,
    /// Initial receive sequence number
    irs: u32,
    /// Receive buffer
    rx_buffer: VecDeque<u8>,
    /// Send buffer
    tx_buffer: VecDeque<u8>,
    /// Pending connections (for LISTEN sockets)
    pending: VecDeque<PendingConnection>,
    /// Time of last activity (for timeouts)
    last_activity: u64,
    /// Socket is open
    is_open: bool,
}

impl TcpControlBlock {
    fn new() -> Self {
        Self {
            state: TcpState::Closed,
            local_port: 0,
            remote_ip: Ipv4Address::new([0, 0, 0, 0]),
            remote_port: 0,
            device_index: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: TCP_WINDOW_SIZE,
            rcv_nxt: 0,
            rcv_wnd: TCP_WINDOW_SIZE,
            iss: 0,
            irs: 0,
            rx_buffer: VecDeque::with_capacity(2048),
            tx_buffer: VecDeque::with_capacity(2048),
            pending: VecDeque::with_capacity(TCP_BACKLOG_SIZE),
            last_activity: 0,
            is_open: false,
        }
    }
}

/// Global TCP socket table
static mut TCP_SOCKETS: Option<Vec<SpinLock<TcpControlBlock>>> = None;
static TCP_INIT: AtomicUsize = AtomicUsize::new(0);

/// Sequence number generator
static TCP_ISN: AtomicU32 = AtomicU32::new(0x12345678);

/// Ephemeral port counter
static EPHEMERAL_PORT: AtomicU32 = AtomicU32::new(49152);

/// Generate initial sequence number
fn generate_isn() -> u32 {
    // Simple ISN generation - in production, use more secure method
    let tick = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed) as u32;
    TCP_ISN.fetch_add(tick.wrapping_add(64000), Ordering::SeqCst)
}

/// Allocate ephemeral port
fn allocate_ephemeral_port() -> u16 {
    loop {
        let port = EPHEMERAL_PORT.fetch_add(1, Ordering::SeqCst);
        let port = ((port - 49152) % 16384 + 49152) as u16;

        // Check if port is in use
        let in_use = unsafe {
            if let Some(ref sockets) = TCP_SOCKETS {
                sockets.iter().any(|s| {
                    let tcb = s.lock();
                    tcb.is_open && tcb.local_port == port
                })
            } else {
                false
            }
        };

        if !in_use {
            return port;
        }
    }
}

/// Initialize TCP subsystem
pub fn init() {
    unsafe {
        let mut sockets = Vec::with_capacity(MAX_TCP_SOCKETS);
        for _ in 0..MAX_TCP_SOCKETS {
            sockets.push(SpinLock::new(TcpControlBlock::new()));
        }
        TCP_SOCKETS = Some(sockets);
    }
    TCP_INIT.store(1, Ordering::SeqCst);
    crate::serial_println!("[TCP] TCP subsystem initialized ({} sockets)", MAX_TCP_SOCKETS);
}

/// Create a new TCP socket
pub fn socket_create() -> Option<TcpSocket> {
    if TCP_INIT.load(Ordering::SeqCst) == 0 {
        return None;
    }

    unsafe {
        if let Some(ref sockets) = TCP_SOCKETS {
            for (i, socket) in sockets.iter().enumerate() {
                let mut tcb = socket.lock();
                if !tcb.is_open {
                    *tcb = TcpControlBlock::new();
                    tcb.is_open = true;
                    tcb.state = TcpState::Closed;
                    return Some(i);
                }
            }
        }
    }
    None
}

/// Bind socket to local port
pub fn socket_bind(socket: TcpSocket, port: u16) -> Result<(), &'static str> {
    unsafe {
        if let Some(ref sockets) = TCP_SOCKETS {
            if socket >= sockets.len() {
                return Err("Invalid socket");
            }

            // Check if port is already in use
            for (i, s) in sockets.iter().enumerate() {
                if i != socket {
                    let tcb = s.lock();
                    if tcb.is_open && tcb.local_port == port {
                        return Err("Port already in use");
                    }
                }
            }

            let mut tcb = sockets[socket].lock();
            if !tcb.is_open {
                return Err("Socket not open");
            }
            tcb.local_port = port;
            Ok(())
        } else {
            Err("TCP not initialized")
        }
    }
}

/// Listen for incoming connections
pub fn socket_listen(socket: TcpSocket, _backlog: usize) -> Result<(), &'static str> {
    unsafe {
        if let Some(ref sockets) = TCP_SOCKETS {
            if socket >= sockets.len() {
                return Err("Invalid socket");
            }

            let mut tcb = sockets[socket].lock();
            if !tcb.is_open {
                return Err("Socket not open");
            }
            if tcb.local_port == 0 {
                return Err("Socket not bound");
            }
            if tcb.state != TcpState::Closed {
                return Err("Socket already in use");
            }

            tcb.state = TcpState::Listen;
            tcb.pending.clear();
            Ok(())
        } else {
            Err("TCP not initialized")
        }
    }
}

/// Connect to remote host (active open)
pub fn socket_connect(
    socket: TcpSocket,
    device_index: usize,
    remote_ip: Ipv4Address,
    remote_port: u16,
) -> Result<(), &'static str> {
    let (local_port, iss, src_ip);

    unsafe {
        if let Some(ref sockets) = TCP_SOCKETS {
            if socket >= sockets.len() {
                return Err("Invalid socket");
            }

            let mut tcb = sockets[socket].lock();
            if !tcb.is_open {
                return Err("Socket not open");
            }
            if tcb.state != TcpState::Closed {
                return Err("Socket already connected");
            }

            // Assign ephemeral port if not bound
            if tcb.local_port == 0 {
                tcb.local_port = allocate_ephemeral_port();
            }
            local_port = tcb.local_port;

            // Generate ISN
            tcb.iss = generate_isn();
            iss = tcb.iss;
            tcb.snd_una = iss;
            tcb.snd_nxt = iss.wrapping_add(1);

            tcb.remote_ip = remote_ip;
            tcb.remote_port = remote_port;
            tcb.device_index = device_index;
            tcb.state = TcpState::SynSent;
            tcb.last_activity = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);

            // Get source IP
            src_ip = super::get_device(device_index)
                .and_then(|d| d.ip_address)
                .ok_or("No IP address configured")?;
        } else {
            return Err("TCP not initialized");
        }
    }

    // Send SYN
    let segment = build_tcp_segment(
        src_ip,
        remote_ip,
        local_port,
        remote_port,
        iss,
        0,
        flags::SYN,
        TCP_WINDOW_SIZE,
        &[],
    );

    send_tcp_segment(device_index, src_ip, remote_ip, &segment)?;
    crate::serial_println!("[TCP] SYN sent to {:?}:{}", remote_ip, remote_port);

    Ok(())
}

/// Close a TCP connection
pub fn socket_close(socket: TcpSocket) -> Result<(), &'static str> {
    unsafe {
        if let Some(ref sockets) = TCP_SOCKETS {
            if socket >= sockets.len() {
                return Err("Invalid socket");
            }

            let mut tcb = sockets[socket].lock();
            if !tcb.is_open {
                return Err("Socket not open");
            }

            match tcb.state {
                TcpState::Closed | TcpState::Listen | TcpState::SynSent => {
                    // Simply close
                    tcb.state = TcpState::Closed;
                    tcb.is_open = false;
                }
                TcpState::SynReceived | TcpState::Established => {
                    // Send FIN
                    if let Some(device) = super::get_device(tcb.device_index) {
                        if let Some(src_ip) = device.ip_address {
                            let segment = build_tcp_segment(
                                src_ip,
                                tcb.remote_ip,
                                tcb.local_port,
                                tcb.remote_port,
                                tcb.snd_nxt,
                                tcb.rcv_nxt,
                                flags::FIN | flags::ACK,
                                tcb.rcv_wnd,
                                &[],
                            );
                            let _ = send_tcp_segment(tcb.device_index, src_ip, tcb.remote_ip, &segment);
                            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                        }
                    }
                    tcb.state = TcpState::FinWait1;
                }
                TcpState::CloseWait => {
                    // Send FIN
                    if let Some(device) = super::get_device(tcb.device_index) {
                        if let Some(src_ip) = device.ip_address {
                            let segment = build_tcp_segment(
                                src_ip,
                                tcb.remote_ip,
                                tcb.local_port,
                                tcb.remote_port,
                                tcb.snd_nxt,
                                tcb.rcv_nxt,
                                flags::FIN | flags::ACK,
                                tcb.rcv_wnd,
                                &[],
                            );
                            let _ = send_tcp_segment(tcb.device_index, src_ip, tcb.remote_ip, &segment);
                            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                        }
                    }
                    tcb.state = TcpState::LastAck;
                }
                _ => {
                    // Already closing
                }
            }

            Ok(())
        } else {
            Err("TCP not initialized")
        }
    }
}

/// Send data on a connected socket
pub fn socket_send(socket: TcpSocket, data: &[u8]) -> Result<usize, &'static str> {
    unsafe {
        if let Some(ref sockets) = TCP_SOCKETS {
            if socket >= sockets.len() {
                return Err("Invalid socket");
            }

            let mut tcb = sockets[socket].lock();
            if !tcb.is_open {
                return Err("Socket not open");
            }
            if tcb.state != TcpState::Established {
                return Err("Connection not established");
            }

            // Add data to send buffer
            let can_send = (tcb.snd_wnd as usize).saturating_sub(tcb.tx_buffer.len());
            let to_send = data.len().min(can_send);

            for &byte in &data[..to_send] {
                tcb.tx_buffer.push_back(byte);
            }

            // Try to send immediately
            if let Some(device) = super::get_device(tcb.device_index) {
                if let Some(src_ip) = device.ip_address {
                    // Send up to MSS bytes
                    let send_len = tcb.tx_buffer.len().min(TCP_DEFAULT_MSS as usize);
                    if send_len > 0 {
                        let payload: Vec<u8> = tcb.tx_buffer.drain(..send_len).collect();

                        let segment = build_tcp_segment(
                            src_ip,
                            tcb.remote_ip,
                            tcb.local_port,
                            tcb.remote_port,
                            tcb.snd_nxt,
                            tcb.rcv_nxt,
                            flags::ACK | flags::PSH,
                            tcb.rcv_wnd,
                            &payload,
                        );

                        if send_tcp_segment(tcb.device_index, src_ip, tcb.remote_ip, &segment).is_ok() {
                            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(payload.len() as u32);
                        }
                    }
                }
            }

            Ok(to_send)
        } else {
            Err("TCP not initialized")
        }
    }
}

/// Receive data from a connected socket
pub fn socket_recv(socket: TcpSocket, buffer: &mut [u8]) -> Result<usize, &'static str> {
    unsafe {
        if let Some(ref sockets) = TCP_SOCKETS {
            if socket >= sockets.len() {
                return Err("Invalid socket");
            }

            let mut tcb = sockets[socket].lock();
            if !tcb.is_open {
                return Err("Socket not open");
            }

            // Allow recv in ESTABLISHED and CLOSE_WAIT states
            if tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait {
                return Err("Cannot receive in current state");
            }

            let available = tcb.rx_buffer.len().min(buffer.len());
            for i in 0..available {
                buffer[i] = tcb.rx_buffer.pop_front().unwrap();
            }

            Ok(available)
        } else {
            Err("TCP not initialized")
        }
    }
}

/// Get socket state
pub fn socket_state(socket: TcpSocket) -> Option<TcpState> {
    unsafe {
        if let Some(ref sockets) = TCP_SOCKETS {
            if socket < sockets.len() {
                let tcb = sockets[socket].lock();
                if tcb.is_open {
                    return Some(tcb.state);
                }
            }
        }
    }
    None
}

/// Send TCP segment via IP layer
fn send_tcp_segment(
    device_index: usize,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    tcp_segment: &[u8],
) -> Result<(), &'static str> {
    use super::ethernet::{create_ethernet_frame, EtherType};
    use super::arp::arp_resolve;

    let device = super::get_device(device_index).ok_or("Device not found")?;
    let src_mac = device.info.mac_address;

    // Resolve destination MAC - for TCP we typically go through gateway
    let dst_mac = if dst_ip.is_broadcast() {
        super::ethernet::MacAddress::new([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    } else {
        // Try direct ARP first, then gateway
        match arp_resolve(device_index, dst_ip, 1000) {
            Some(mac) => mac,
            None => {
                // Try via gateway
                if let Some(gateway) = device.gateway {
                    arp_resolve(device_index, gateway, 1000).ok_or("Gateway ARP failed")?
                } else {
                    return Err("No route to host");
                }
            }
        }
    };

    // Build IP header
    let payload_len = tcp_segment.len() as u16;
    let mut ip_header = super::Ipv4Header::new(src_ip, dst_ip, IpProtocol::Tcp, payload_len, 64);
    ip_header.compute_checksum();
    let ip_bytes = ip_header.to_bytes();

    // Build full IP packet
    let mut packet = Vec::with_capacity(ip_bytes.len() + tcp_segment.len());
    packet.extend_from_slice(&ip_bytes);
    packet.extend_from_slice(tcp_segment);

    // Build Ethernet frame
    let frame = create_ethernet_frame(dst_mac, src_mac, EtherType::Ipv4, &packet);

    // Transmit
    if let Some(device_mut) = super::get_device_mut(device_index) {
        device_mut.transmit(&frame)?;
        super::record_tx_packet(frame.len());
        Ok(())
    } else {
        Err("Device not found")
    }
}

/// Handle incoming TCP segment
pub fn handle_tcp_packet(
    device_index: usize,
    ip_header: &Ipv4Header,
    tcp_header: &TcpHeader,
    data: &[u8],
) {
    let src_ip = ip_header.source_addr;
    let dst_ip = ip_header.dest_addr;
    // Copy values from packed struct to avoid unaligned references
    let src_port = tcp_header.source_port;
    let dst_port = tcp_header.dest_port;
    let seq_num = tcp_header.seq_num;
    let ack_num = tcp_header.ack_num;
    let flags = tcp_header.flags;

    let header_len = tcp_header.data_offset();
    let payload = if data.len() > header_len {
        &data[header_len..]
    } else {
        &[]
    };

    crate::serial_println!(
        "[TCP] {:?}:{} -> {:?}:{} seq={} ack={} flags={:#04x} len={}",
        src_ip, src_port, dst_ip, dst_port,
        seq_num, ack_num,
        flags, payload.len()
    );

    // Find matching socket
    unsafe {
        if let Some(ref sockets) = TCP_SOCKETS {
            // First, look for exact match (connected socket)
            for socket in sockets.iter() {
                let mut tcb = socket.lock();
                if tcb.is_open
                    && tcb.local_port == dst_port
                    && tcb.remote_port == src_port
                    && tcb.remote_ip == src_ip
                {
                    handle_tcp_for_socket(&mut tcb, device_index, ip_header, tcp_header, payload);
                    return;
                }
            }

            // Then, look for listening socket
            for socket in sockets.iter() {
                let mut tcb = socket.lock();
                if tcb.is_open && tcb.state == TcpState::Listen && tcb.local_port == dst_port {
                    handle_tcp_for_socket(&mut tcb, device_index, ip_header, tcp_header, payload);
                    return;
                }
            }
        }
    }

    // No matching socket - send RST
    crate::serial_println!("[TCP] No socket for port {}, sending RST", dst_port);
    send_rst(device_index, dst_ip, src_ip, dst_port, src_port, tcp_header.seq_num, tcp_header.ack_num);
}

/// Handle TCP segment for a specific socket
fn handle_tcp_for_socket(
    tcb: &mut TcpControlBlock,
    device_index: usize,
    ip_header: &Ipv4Header,
    tcp_header: &TcpHeader,
    payload: &[u8],
) {
    let src_ip = ip_header.source_addr;

    tcb.last_activity = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);

    // Handle RST
    if tcp_header.is_rst() {
        crate::serial_println!("[TCP] RST received, closing connection");
        tcb.state = TcpState::Closed;
        return;
    }

    match tcb.state {
        TcpState::Listen => {
            // Expecting SYN
            if tcp_header.is_syn() && !tcp_header.is_ack() {
                crate::serial_println!("[TCP] SYN received on listening socket");

                // Generate ISN and send SYN-ACK
                tcb.iss = generate_isn();
                tcb.irs = tcp_header.seq_num;
                tcb.rcv_nxt = tcp_header.seq_num.wrapping_add(1);
                tcb.snd_nxt = tcb.iss.wrapping_add(1);
                tcb.snd_una = tcb.iss;
                tcb.remote_ip = src_ip;
                tcb.remote_port = tcp_header.source_port;
                tcb.device_index = device_index;
                tcb.state = TcpState::SynReceived;

                // Send SYN-ACK
                if let Some(device) = super::get_device(device_index) {
                    if let Some(local_ip) = device.ip_address {
                        let segment = build_tcp_segment(
                            local_ip,
                            src_ip,
                            tcb.local_port,
                            tcp_header.source_port,
                            tcb.iss,
                            tcb.rcv_nxt,
                            flags::SYN | flags::ACK,
                            tcb.rcv_wnd,
                            &[],
                        );
                        let _ = send_tcp_segment(device_index, local_ip, src_ip, &segment);
                        crate::serial_println!("[TCP] SYN-ACK sent");
                    }
                }
            }
        }

        TcpState::SynSent => {
            // Expecting SYN-ACK
            if tcp_header.is_syn() && tcp_header.is_ack() {
                if tcp_header.ack_num == tcb.snd_nxt {
                    tcb.irs = tcp_header.seq_num;
                    tcb.rcv_nxt = tcp_header.seq_num.wrapping_add(1);
                    tcb.snd_una = tcp_header.ack_num;
                    tcb.snd_wnd = tcp_header.window;
                    tcb.state = TcpState::Established;

                    // Send ACK
                    if let Some(device) = super::get_device(device_index) {
                        if let Some(local_ip) = device.ip_address {
                            let segment = build_tcp_segment(
                                local_ip,
                                tcb.remote_ip,
                                tcb.local_port,
                                tcb.remote_port,
                                tcb.snd_nxt,
                                tcb.rcv_nxt,
                                flags::ACK,
                                tcb.rcv_wnd,
                                &[],
                            );
                            let _ = send_tcp_segment(device_index, local_ip, tcb.remote_ip, &segment);
                        }
                    }
                    crate::serial_println!("[TCP] Connection established (client)");
                }
            }
        }

        TcpState::SynReceived => {
            // Expecting ACK to complete handshake
            if tcp_header.is_ack() && tcp_header.ack_num == tcb.snd_nxt {
                tcb.snd_una = tcp_header.ack_num;
                tcb.snd_wnd = tcp_header.window;
                tcb.state = TcpState::Established;
                crate::serial_println!("[TCP] Connection established (server)");
            }
        }

        TcpState::Established => {
            // Handle incoming data
            if tcp_header.is_ack() {
                // Update send window
                if tcp_header.ack_num.wrapping_sub(tcb.snd_una) <= tcb.snd_nxt.wrapping_sub(tcb.snd_una) {
                    tcb.snd_una = tcp_header.ack_num;
                }
                tcb.snd_wnd = tcp_header.window;
            }

            // Process data
            if !payload.is_empty() && tcp_header.seq_num == tcb.rcv_nxt {
                // In-order data
                for &byte in payload {
                    if tcb.rx_buffer.len() < 2048 {
                        tcb.rx_buffer.push_back(byte);
                    }
                }
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload.len() as u32);

                // Send ACK
                if let Some(device) = super::get_device(device_index) {
                    if let Some(local_ip) = device.ip_address {
                        let segment = build_tcp_segment(
                            local_ip,
                            tcb.remote_ip,
                            tcb.local_port,
                            tcb.remote_port,
                            tcb.snd_nxt,
                            tcb.rcv_nxt,
                            flags::ACK,
                            tcb.rcv_wnd,
                            &[],
                        );
                        let _ = send_tcp_segment(device_index, local_ip, tcb.remote_ip, &segment);
                    }
                }
            }

            // Handle FIN
            if tcp_header.is_fin() {
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                tcb.state = TcpState::CloseWait;

                // Send ACK
                if let Some(device) = super::get_device(device_index) {
                    if let Some(local_ip) = device.ip_address {
                        let segment = build_tcp_segment(
                            local_ip,
                            tcb.remote_ip,
                            tcb.local_port,
                            tcb.remote_port,
                            tcb.snd_nxt,
                            tcb.rcv_nxt,
                            flags::ACK,
                            tcb.rcv_wnd,
                            &[],
                        );
                        let _ = send_tcp_segment(device_index, local_ip, tcb.remote_ip, &segment);
                    }
                }
                crate::serial_println!("[TCP] FIN received, entering CLOSE_WAIT");
            }
        }

        TcpState::FinWait1 => {
            if tcp_header.is_ack() && tcp_header.ack_num == tcb.snd_nxt {
                if tcp_header.is_fin() {
                    // Simultaneous close
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                    tcb.state = TcpState::TimeWait;
                    // Send ACK
                    send_ack(tcb, device_index);
                } else {
                    tcb.state = TcpState::FinWait2;
                }
            } else if tcp_header.is_fin() {
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                tcb.state = TcpState::Closing;
                send_ack(tcb, device_index);
            }
        }

        TcpState::FinWait2 => {
            if tcp_header.is_fin() {
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                tcb.state = TcpState::TimeWait;
                send_ack(tcb, device_index);
                crate::serial_println!("[TCP] Entering TIME_WAIT");
            }
        }

        TcpState::Closing => {
            if tcp_header.is_ack() && tcp_header.ack_num == tcb.snd_nxt {
                tcb.state = TcpState::TimeWait;
            }
        }

        TcpState::LastAck => {
            if tcp_header.is_ack() && tcp_header.ack_num == tcb.snd_nxt {
                tcb.state = TcpState::Closed;
                tcb.is_open = false;
                crate::serial_println!("[TCP] Connection closed");
            }
        }

        TcpState::TimeWait => {
            // Ignore, wait for timeout
        }

        _ => {}
    }
}

/// Send ACK helper
fn send_ack(tcb: &TcpControlBlock, device_index: usize) {
    if let Some(device) = super::get_device(device_index) {
        if let Some(local_ip) = device.ip_address {
            let segment = build_tcp_segment(
                local_ip,
                tcb.remote_ip,
                tcb.local_port,
                tcb.remote_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                flags::ACK,
                tcb.rcv_wnd,
                &[],
            );
            let _ = send_tcp_segment(device_index, local_ip, tcb.remote_ip, &segment);
        }
    }
}

/// Send RST segment
fn send_rst(
    device_index: usize,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
) {
    let segment = build_tcp_segment(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ack,
        seq.wrapping_add(1),
        flags::RST | flags::ACK,
        0,
        &[],
    );
    let _ = send_tcp_segment(device_index, src_ip, dst_ip, &segment);
}

/// Get TCP socket statistics
pub fn get_socket_stats() -> (usize, usize) {
    let mut active = 0;
    unsafe {
        if let Some(ref sockets) = TCP_SOCKETS {
            for socket in sockets.iter() {
                let tcb = socket.lock();
                if tcb.is_open {
                    active += 1;
                }
            }
        }
    }
    (active, MAX_TCP_SOCKETS)
}

/// Get socket info
pub fn get_socket_info(socket: TcpSocket) -> Option<(TcpState, u16, u16, Ipv4Address, usize, usize)> {
    unsafe {
        if let Some(ref sockets) = TCP_SOCKETS {
            if socket < sockets.len() {
                let tcb = sockets[socket].lock();
                if tcb.is_open {
                    return Some((
                        tcb.state,
                        tcb.local_port,
                        tcb.remote_port,
                        tcb.remote_ip,
                        tcb.rx_buffer.len(),
                        tcb.tx_buffer.len(),
                    ));
                }
            }
        }
    }
    None
}

/// Connection info for netstat display
#[derive(Debug, Clone)]
pub struct TcpConnectionInfo {
    pub socket_id: usize,
    pub state: TcpState,
    pub local_port: u16,
    pub remote_port: u16,
    pub remote_ip: Ipv4Address,
    pub rx_queue: usize,
    pub tx_queue: usize,
}

/// Enumerate all active TCP connections
pub fn enumerate_connections() -> alloc::vec::Vec<TcpConnectionInfo> {
    let mut connections = alloc::vec::Vec::new();

    unsafe {
        if let Some(ref sockets) = TCP_SOCKETS {
            for (i, socket) in sockets.iter().enumerate() {
                let tcb = socket.lock();
                if tcb.is_open && tcb.state != TcpState::Closed {
                    connections.push(TcpConnectionInfo {
                        socket_id: i,
                        state: tcb.state,
                        local_port: tcb.local_port,
                        remote_port: tcb.remote_port,
                        remote_ip: tcb.remote_ip,
                        rx_queue: tcb.rx_buffer.len(),
                        tx_queue: tcb.tx_buffer.len(),
                    });
                }
            }
        }
    }

    connections
}
