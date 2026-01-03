//! Echo and Chargen Services
//!
//! RFC 862 - Echo Protocol
//! RFC 864 - Character Generator Protocol
//!
//! Simple network services for testing connectivity.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::udp;
use super::ip::Ipv4Address;

/// Echo port (RFC 862)
pub const ECHO_PORT: u16 = 7;

/// Chargen port (RFC 864)
pub const CHARGEN_PORT: u16 = 19;

/// Discard port (RFC 863)
pub const DISCARD_PORT: u16 = 9;

/// Daytime port (RFC 867)
pub const DAYTIME_PORT: u16 = 13;

/// Echo server state
static ECHO_UDP_RUNNING: AtomicBool = AtomicBool::new(false);
static ECHO_TCP_RUNNING: AtomicBool = AtomicBool::new(false);
static CHARGEN_UDP_RUNNING: AtomicBool = AtomicBool::new(false);

/// Statistics
static ECHO_UDP_PACKETS: AtomicU32 = AtomicU32::new(0);
static ECHO_UDP_BYTES: AtomicU32 = AtomicU32::new(0);
static CHARGEN_PACKETS: AtomicU32 = AtomicU32::new(0);

/// Character generator pattern (printable ASCII 32-126)
const CHARGEN_PATTERN: &[u8; 95] = b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

/// UDP Echo socket
static mut ECHO_UDP_SOCKET: Option<usize> = None;

/// UDP Chargen socket
static mut CHARGEN_UDP_SOCKET: Option<usize> = None;

/// Start UDP echo server
pub fn start_echo_udp() -> Result<(), &'static str> {
    if ECHO_UDP_RUNNING.load(Ordering::SeqCst) {
        return Err("Echo UDP server already running");
    }

    let socket = udp::socket_create().ok_or("Failed to create socket")?;
    udp::socket_bind(socket, ECHO_PORT)?;

    unsafe {
        ECHO_UDP_SOCKET = Some(socket);
    }
    ECHO_UDP_RUNNING.store(true, Ordering::SeqCst);

    crate::serial_println!("[ECHO] UDP echo server started on port {}", ECHO_PORT);
    Ok(())
}

/// Stop UDP echo server
pub fn stop_echo_udp() {
    if !ECHO_UDP_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    unsafe {
        if let Some(socket) = ECHO_UDP_SOCKET.take() {
            let _ = udp::socket_close(socket);
        }
    }
    ECHO_UDP_RUNNING.store(false, Ordering::SeqCst);
    crate::serial_println!("[ECHO] UDP echo server stopped");
}

/// Process UDP echo packets (call from network handler)
pub fn process_echo_udp(device_index: usize) {
    if !ECHO_UDP_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    let socket = unsafe { ECHO_UDP_SOCKET };
    if let Some(socket) = socket {
        while let Some(datagram) = udp::socket_recvfrom(socket) {
            // Echo back the data
            let _ = udp::socket_sendto(
                socket,
                device_index,
                datagram.src_ip,
                datagram.src_port,
                &datagram.data,
            );
            ECHO_UDP_PACKETS.fetch_add(1, Ordering::Relaxed);
            ECHO_UDP_BYTES.fetch_add(datagram.data.len() as u32, Ordering::Relaxed);
        }
    }
}

/// Start UDP chargen server
pub fn start_chargen_udp() -> Result<(), &'static str> {
    if CHARGEN_UDP_RUNNING.load(Ordering::SeqCst) {
        return Err("Chargen UDP server already running");
    }

    let socket = udp::socket_create().ok_or("Failed to create socket")?;
    udp::socket_bind(socket, CHARGEN_PORT)?;

    unsafe {
        CHARGEN_UDP_SOCKET = Some(socket);
    }
    CHARGEN_UDP_RUNNING.store(true, Ordering::SeqCst);

    crate::serial_println!("[CHARGEN] UDP chargen server started on port {}", CHARGEN_PORT);
    Ok(())
}

/// Stop UDP chargen server
pub fn stop_chargen_udp() {
    if !CHARGEN_UDP_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    unsafe {
        if let Some(socket) = CHARGEN_UDP_SOCKET.take() {
            let _ = udp::socket_close(socket);
        }
    }
    CHARGEN_UDP_RUNNING.store(false, Ordering::SeqCst);
    crate::serial_println!("[CHARGEN] UDP chargen server stopped");
}

/// Process UDP chargen packets
pub fn process_chargen_udp(device_index: usize) {
    if !CHARGEN_UDP_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    let socket = unsafe { CHARGEN_UDP_SOCKET };
    if let Some(socket) = socket {
        while let Some(datagram) = udp::socket_recvfrom(socket) {
            // Generate a line of characters (72 chars + CRLF)
            let mut response = [0u8; 74];
            let offset = CHARGEN_PACKETS.fetch_add(1, Ordering::Relaxed) as usize % 95;
            for i in 0..72 {
                response[i] = CHARGEN_PATTERN[(offset + i) % 95];
            }
            response[72] = b'\r';
            response[73] = b'\n';

            let _ = udp::socket_sendto(
                socket,
                device_index,
                datagram.src_ip,
                datagram.src_port,
                &response,
            );
        }
    }
}

/// Send echo request (ping-like using echo protocol)
pub fn send_echo(
    device_index: usize,
    target_ip: Ipv4Address,
    data: &[u8],
    timeout_ms: u32,
) -> Result<(usize, u64), &'static str> {
    let socket = udp::socket_create().ok_or("Failed to create socket")?;
    udp::socket_bind(socket, 0)?;

    let start = crate::hal::apic::get_tick_count();

    // Send echo request
    udp::socket_sendto(socket, device_index, target_ip, ECHO_PORT, data)?;

    // Wait for response
    let timeout_ticks = timeout_ms as u64 * 1000;

    loop {
        if let Some(datagram) = udp::socket_recvfrom(socket) {
            let elapsed = crate::hal::apic::get_tick_count() - start;
            let _ = udp::socket_close(socket);

            // Verify response matches request
            if datagram.data == data {
                let elapsed_ms = elapsed / 1000;
                return Ok((datagram.data.len(), elapsed_ms));
            } else {
                return Err("Echo response mismatch");
            }
        }

        let elapsed = crate::hal::apic::get_tick_count() - start;
        if elapsed > timeout_ticks {
            let _ = udp::socket_close(socket);
            return Err("Echo timeout");
        }

        // Small delay
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}

/// Echo service statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct EchoStats {
    pub udp_packets: u32,
    pub udp_bytes: u32,
    pub chargen_packets: u32,
    pub echo_udp_running: bool,
    pub chargen_udp_running: bool,
}

/// Get echo service statistics
pub fn get_stats() -> EchoStats {
    EchoStats {
        udp_packets: ECHO_UDP_PACKETS.load(Ordering::Relaxed),
        udp_bytes: ECHO_UDP_BYTES.load(Ordering::Relaxed),
        chargen_packets: CHARGEN_PACKETS.load(Ordering::Relaxed),
        echo_udp_running: ECHO_UDP_RUNNING.load(Ordering::SeqCst),
        chargen_udp_running: CHARGEN_UDP_RUNNING.load(Ordering::SeqCst),
    }
}

/// Initialize echo services
pub fn init() {
    crate::serial_println!("[ECHO] Echo/chargen services initialized");
}
