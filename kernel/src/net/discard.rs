//! Discard Service
//!
//! RFC 863 - Discard Protocol
//!
//! Simple service that discards all received data without response.
//! Useful for network testing and traffic sinking.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use super::udp;

/// Discard port (RFC 863)
pub const DISCARD_PORT: u16 = 9;

/// Server state
static DISCARD_UDP_RUNNING: AtomicBool = AtomicBool::new(false);

/// Statistics
static DISCARD_PACKETS: AtomicU32 = AtomicU32::new(0);
static DISCARD_BYTES: AtomicU64 = AtomicU64::new(0);

/// UDP Socket
static mut DISCARD_UDP_SOCKET: Option<usize> = None;

/// Start UDP discard server
pub fn start_discard_udp() -> Result<(), &'static str> {
    if DISCARD_UDP_RUNNING.load(Ordering::SeqCst) {
        return Err("Discard UDP server already running");
    }

    let socket = udp::socket_create().ok_or("Failed to create socket")?;
    udp::socket_bind(socket, DISCARD_PORT)?;

    unsafe {
        DISCARD_UDP_SOCKET = Some(socket);
    }
    DISCARD_UDP_RUNNING.store(true, Ordering::SeqCst);

    crate::serial_println!("[DISCARD] UDP server started on port {}", DISCARD_PORT);
    Ok(())
}

/// Stop UDP discard server
pub fn stop_discard_udp() {
    if !DISCARD_UDP_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    unsafe {
        if let Some(socket) = DISCARD_UDP_SOCKET.take() {
            let _ = udp::socket_close(socket);
        }
    }
    DISCARD_UDP_RUNNING.store(false, Ordering::SeqCst);
    crate::serial_println!("[DISCARD] UDP server stopped");
}

/// Process UDP discard packets (just consume and discard)
pub fn process_discard_udp(_device_index: usize) {
    if !DISCARD_UDP_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    let socket = unsafe { DISCARD_UDP_SOCKET };
    if let Some(socket) = socket {
        while let Some(datagram) = udp::socket_recvfrom(socket) {
            // Just count and discard - no response
            DISCARD_PACKETS.fetch_add(1, Ordering::Relaxed);
            DISCARD_BYTES.fetch_add(datagram.data.len() as u64, Ordering::Relaxed);
        }
    }
}

/// Discard service statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscardStats {
    pub packets: u32,
    pub bytes: u64,
    pub udp_running: bool,
}

/// Get discard service statistics
pub fn get_stats() -> DiscardStats {
    DiscardStats {
        packets: DISCARD_PACKETS.load(Ordering::Relaxed),
        bytes: DISCARD_BYTES.load(Ordering::Relaxed),
        udp_running: DISCARD_UDP_RUNNING.load(Ordering::SeqCst),
    }
}

/// Initialize discard service
pub fn init() {
    crate::serial_println!("[DISCARD] Discard service initialized");
}
