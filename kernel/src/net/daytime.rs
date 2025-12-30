//! Daytime Service
//!
//! RFC 867 - Daytime Protocol
//!
//! Returns the current date and time as a human-readable ASCII string.
//! The format is not strictly specified, but typically:
//! "Weekday, Month DD, YYYY HH:MM:SS-Zone\r\n"

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::udp;
use super::ip::Ipv4Address;

/// Daytime port (RFC 867)
pub const DAYTIME_PORT: u16 = 13;

/// Server state
static DAYTIME_UDP_RUNNING: AtomicBool = AtomicBool::new(false);

/// Statistics
static DAYTIME_REQUESTS: AtomicU32 = AtomicU32::new(0);

/// UDP Socket
static mut DAYTIME_UDP_SOCKET: Option<usize> = None;

/// Day names
const DAYS: &[&str] = &["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/// Month names
const MONTHS: &[&str] = &[
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
];

/// Format the current date and time as a human-readable string
pub fn format_daytime() -> alloc::string::String {
    use alloc::format;

    let dt = crate::hal::rtc::get_datetime();

    // day_of_week is 1-7 (Sunday = 1), adjust for 0-based array
    let day_name = DAYS.get((dt.day_of_week.saturating_sub(1)) as usize)
        .unwrap_or(&"Unknown");
    let month_name = MONTHS.get((dt.month.saturating_sub(1)) as usize)
        .unwrap_or(&"Unknown");

    format!(
        "{}, {} {:02}, {:04} {:02}:{:02}:{:02} UTC\r\n",
        day_name,
        month_name,
        dt.day,
        dt.year,
        dt.hour,
        dt.minute,
        dt.second
    )
}

/// Start UDP daytime server
pub fn start_daytime_udp() -> Result<(), &'static str> {
    if DAYTIME_UDP_RUNNING.load(Ordering::SeqCst) {
        return Err("Daytime UDP server already running");
    }

    let socket = udp::socket_create().ok_or("Failed to create socket")?;
    udp::socket_bind(socket, DAYTIME_PORT)?;

    unsafe {
        DAYTIME_UDP_SOCKET = Some(socket);
    }
    DAYTIME_UDP_RUNNING.store(true, Ordering::SeqCst);

    crate::serial_println!("[DAYTIME] UDP server started on port {}", DAYTIME_PORT);
    Ok(())
}

/// Stop UDP daytime server
pub fn stop_daytime_udp() {
    if !DAYTIME_UDP_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    unsafe {
        if let Some(socket) = DAYTIME_UDP_SOCKET.take() {
            let _ = udp::socket_close(socket);
        }
    }
    DAYTIME_UDP_RUNNING.store(false, Ordering::SeqCst);
    crate::serial_println!("[DAYTIME] UDP server stopped");
}

/// Process UDP daytime requests
pub fn process_daytime_udp(device_index: usize) {
    if !DAYTIME_UDP_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    let socket = unsafe { DAYTIME_UDP_SOCKET };
    if let Some(socket) = socket {
        while let Some(datagram) = udp::socket_recvfrom(socket) {
            let response = format_daytime();

            let _ = udp::socket_sendto(
                socket,
                device_index,
                datagram.src_ip,
                datagram.src_port,
                response.as_bytes(),
            );
            DAYTIME_REQUESTS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Request daytime from a server (client)
pub fn request_daytime(
    device_index: usize,
    server_ip: Ipv4Address,
    timeout_ms: u32,
) -> Result<alloc::string::String, &'static str> {
    let socket = udp::socket_create().ok_or("Failed to create socket")?;
    udp::socket_bind(socket, 0)?;

    let start = crate::hal::apic::get_tick_count();

    // Send empty request
    udp::socket_sendto(socket, device_index, server_ip, DAYTIME_PORT, &[0])?;

    // Wait for response
    let timeout_ticks = timeout_ms as u64 * 1000;

    loop {
        if let Some(datagram) = udp::socket_recvfrom(socket) {
            let _ = udp::socket_close(socket);

            // Convert response to string
            if let Ok(s) = core::str::from_utf8(&datagram.data) {
                return Ok(alloc::string::String::from(s));
            } else {
                return Err("Invalid UTF-8 in response");
            }
        }

        let elapsed = crate::hal::apic::get_tick_count() - start;
        if elapsed > timeout_ticks {
            let _ = udp::socket_close(socket);
            return Err("Daytime timeout");
        }

        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}

/// Daytime service statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct DaytimeStats {
    pub requests: u32,
    pub udp_running: bool,
}

/// Get daytime service statistics
pub fn get_stats() -> DaytimeStats {
    DaytimeStats {
        requests: DAYTIME_REQUESTS.load(Ordering::Relaxed),
        udp_running: DAYTIME_UDP_RUNNING.load(Ordering::SeqCst),
    }
}

/// Initialize daytime service
pub fn init() {
    crate::serial_println!("[DAYTIME] Daytime service initialized");
}
