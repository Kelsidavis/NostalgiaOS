//! TIME Protocol
//!
//! RFC 868 - Time Protocol
//!
//! Returns the current time as a 32-bit value representing seconds since
//! January 1, 1900 (NTP epoch, different from Unix epoch of 1970).

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::udp;
use super::ip::Ipv4Address;

/// TIME port (RFC 868)
pub const TIME_PORT: u16 = 37;

/// Server state
static TIME_UDP_RUNNING: AtomicBool = AtomicBool::new(false);

/// Statistics
static TIME_REQUESTS: AtomicU32 = AtomicU32::new(0);

/// UDP Socket
static mut TIME_UDP_SOCKET: Option<usize> = None;

/// Difference between NTP epoch (1900) and Unix epoch (1970) in seconds
/// 70 years = 2208988800 seconds
pub const NTP_UNIX_OFFSET: u32 = 2208988800;

/// Days in each month (non-leap year)
const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Check if a year is a leap year
fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Convert DateTime to Unix timestamp (seconds since 1970-01-01 00:00:00)
fn datetime_to_unix(dt: &crate::hal::rtc::DateTime) -> u32 {
    let mut days: u32 = 0;

    // Add days for years since 1970
    for y in 1970..dt.year as u32 {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Add days for months in current year
    for m in 0..(dt.month as usize).saturating_sub(1) {
        days += DAYS_IN_MONTH[m];
        // Add leap day for February in leap years
        if m == 1 && is_leap_year(dt.year as u32) {
            days += 1;
        }
    }

    // Add days in current month (day is 1-based)
    days += dt.day.saturating_sub(1) as u32;

    // Convert to seconds
    let hours = dt.hour as u32;
    let minutes = dt.minute as u32;
    let seconds = dt.second as u32;

    days * 86400 + hours * 3600 + minutes * 60 + seconds
}

/// Get current time in NTP format (seconds since 1900-01-01 00:00:00)
pub fn get_ntp_time() -> u32 {
    let unix_time = get_unix_time();
    unix_time.wrapping_add(NTP_UNIX_OFFSET)
}

/// Get current Unix time (seconds since 1970-01-01 00:00:00)
pub fn get_unix_time() -> u32 {
    let dt = crate::hal::rtc::get_datetime();
    datetime_to_unix(&dt)
}

/// Start UDP TIME server
pub fn start_time_udp() -> Result<(), &'static str> {
    if TIME_UDP_RUNNING.load(Ordering::SeqCst) {
        return Err("TIME UDP server already running");
    }

    let socket = udp::socket_create().ok_or("Failed to create socket")?;
    udp::socket_bind(socket, TIME_PORT)?;

    unsafe {
        TIME_UDP_SOCKET = Some(socket);
    }
    TIME_UDP_RUNNING.store(true, Ordering::SeqCst);

    crate::serial_println!("[TIME] UDP server started on port {}", TIME_PORT);
    Ok(())
}

/// Stop UDP TIME server
pub fn stop_time_udp() {
    if !TIME_UDP_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    unsafe {
        if let Some(socket) = TIME_UDP_SOCKET.take() {
            let _ = udp::socket_close(socket);
        }
    }
    TIME_UDP_RUNNING.store(false, Ordering::SeqCst);
    crate::serial_println!("[TIME] UDP server stopped");
}

/// Process UDP TIME requests
pub fn process_time_udp(device_index: usize) {
    if !TIME_UDP_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    let socket = unsafe { TIME_UDP_SOCKET };
    if let Some(socket) = socket {
        while let Some(datagram) = udp::socket_recvfrom(socket) {
            // Get current time in NTP format (32-bit, big endian)
            let time = get_ntp_time();
            let response = time.to_be_bytes();

            let _ = udp::socket_sendto(
                socket,
                device_index,
                datagram.src_ip,
                datagram.src_port,
                &response,
            );
            TIME_REQUESTS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Request time from a TIME server (client)
pub fn request_time(
    device_index: usize,
    server_ip: Ipv4Address,
    timeout_ms: u32,
) -> Result<u32, &'static str> {
    let socket = udp::socket_create().ok_or("Failed to create socket")?;
    udp::socket_bind(socket, 0)?;

    let start = crate::hal::apic::get_tick_count();

    // Send empty request
    udp::socket_sendto(socket, device_index, server_ip, TIME_PORT, &[0])?;

    // Wait for response
    let timeout_ticks = timeout_ms as u64 * 1000;

    loop {
        if let Some(datagram) = udp::socket_recvfrom(socket) {
            let _ = udp::socket_close(socket);

            if datagram.data.len() >= 4 {
                let ntp_time = u32::from_be_bytes([
                    datagram.data[0],
                    datagram.data[1],
                    datagram.data[2],
                    datagram.data[3],
                ]);
                return Ok(ntp_time);
            } else {
                return Err("Invalid TIME response");
            }
        }

        let elapsed = crate::hal::apic::get_tick_count() - start;
        if elapsed > timeout_ticks {
            let _ = udp::socket_close(socket);
            return Err("TIME timeout");
        }

        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}

/// Convert NTP time to Unix time
pub fn ntp_to_unix(ntp_time: u32) -> u32 {
    ntp_time.wrapping_sub(NTP_UNIX_OFFSET)
}

/// Convert Unix time to NTP time
pub fn unix_to_ntp(unix_time: u32) -> u32 {
    unix_time.wrapping_add(NTP_UNIX_OFFSET)
}

/// TIME service statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeStats {
    pub requests: u32,
    pub udp_running: bool,
}

/// Get TIME service statistics
pub fn get_stats() -> TimeStats {
    TimeStats {
        requests: TIME_REQUESTS.load(Ordering::Relaxed),
        udp_running: TIME_UDP_RUNNING.load(Ordering::SeqCst),
    }
}

/// Initialize TIME service
pub fn init() {
    crate::serial_println!("[TIME] Time protocol service initialized");
}
