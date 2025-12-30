//! Finger Protocol
//!
//! RFC 1288 - The Finger User Information Protocol
//!
//! Provides information about users logged into the system.
//! This implementation provides client-side query functionality.
//! Server functionality is simplified due to TCP stack limitations.

extern crate alloc;

use alloc::string::String;
use alloc::format;
use core::sync::atomic::{AtomicU32, Ordering};
use super::tcp;
use super::ip::Ipv4Address;

/// Finger port (RFC 1288)
pub const FINGER_PORT: u16 = 79;

/// Statistics
static FINGER_QUERIES: AtomicU32 = AtomicU32::new(0);

/// Generate finger response for the system (used for local queries)
pub fn generate_finger_response(query: &str) -> String {
    let query = query.trim();

    if query.is_empty() {
        // List all "users" (in our case, system info)
        let uptime = crate::hal::rtc::get_uptime_seconds();
        let dt = crate::hal::rtc::get_datetime();

        format!(
            "Nostalgia OS Finger Service\r\n\
             ===========================\r\n\
             \r\n\
             System Information:\r\n\
             Login     Name                   Idle     When     Where\r\n\
             kernel    Kernel Process          -       -        console\r\n\
             shell     Interactive Shell       -       {:02}:{:02}    serial\r\n\
             \r\n\
             System Uptime: {} seconds\r\n\
             Current Time:  {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC\r\n",
            dt.hour, dt.minute,
            uptime,
            dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second
        )
    } else if query.eq_ignore_ascii_case("kernel") || query.eq_ignore_ascii_case("system") {
        // System/kernel info
        format!(
            "Login: kernel                        Name: Kernel Process\r\n\
             Directory: /                         Shell: N/A\r\n\
             No Plan.\r\n"
        )
    } else if query.eq_ignore_ascii_case("shell") || query.eq_ignore_ascii_case("user") {
        // Shell info
        format!(
            "Login: shell                         Name: Interactive Shell\r\n\
             Directory: /                         Shell: /bin/sh\r\n\
             On since boot.\r\n\
             No Plan.\r\n"
        )
    } else if query.starts_with("/W") || query.starts_with("/w") {
        // Verbose format requested
        let clean_query = query.trim_start_matches(['/','W','w',' '].as_ref()).trim();
        if clean_query.is_empty() {
            generate_finger_response("")
        } else {
            generate_finger_response(clean_query)
        }
    } else {
        format!(
            "finger: {}: no such user.\r\n",
            query
        )
    }
}

/// Query a finger server (client)
pub fn finger_query(
    device_index: usize,
    server_ip: Ipv4Address,
    query: &str,
    timeout_ms: u32,
) -> Result<String, &'static str> {
    let socket = tcp::socket_create().ok_or("Failed to create socket")?;
    tcp::socket_connect(socket, device_index, server_ip, FINGER_PORT)?;

    // Send query with CRLF
    let query_bytes: String = format!("{}\r\n", query);
    tcp::socket_send(socket, query_bytes.as_bytes())?;

    // Read response
    let mut response_buf = [0u8; 4096];
    let mut response_len = 0;

    let start = crate::hal::apic::get_tick_count();
    let timeout_ticks = timeout_ms as u64 * 1000;

    loop {
        match tcp::socket_recv(socket, &mut response_buf[response_len..]) {
            Ok(n) if n > 0 => {
                response_len += n;
                if response_len >= response_buf.len() {
                    break;
                }
            }
            Ok(_) => {
                // Connection closed by server or no data
                break;
            }
            Err(_) => {
                break;
            }
        }

        let elapsed = crate::hal::apic::get_tick_count() - start;
        if elapsed > timeout_ticks {
            let _ = tcp::socket_close(socket);
            return Err("Finger timeout");
        }

        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    let _ = tcp::socket_close(socket);

    FINGER_QUERIES.fetch_add(1, Ordering::Relaxed);

    if let Ok(s) = core::str::from_utf8(&response_buf[..response_len]) {
        Ok(String::from(s))
    } else {
        Err("Invalid UTF-8 in response")
    }
}

/// Finger service statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct FingerStats {
    pub queries: u32,
}

/// Get finger service statistics
pub fn get_stats() -> FingerStats {
    FingerStats {
        queries: FINGER_QUERIES.load(Ordering::Relaxed),
    }
}

/// Initialize finger service
pub fn init() {
    crate::serial_println!("[FINGER] Finger service initialized");
}
