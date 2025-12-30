//! Ident Protocol
//!
//! RFC 1413 - Identification Protocol
//!
//! Used to identify the user of a particular TCP connection.
//! While less common today, it's still used by some IRC servers
//! and other legacy systems.

extern crate alloc;

use alloc::string::String;
use alloc::format;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use super::tcp;
use super::ip::Ipv4Address;

/// Ident port (RFC 1413)
pub const IDENT_PORT: u16 = 113;

/// Server state
static IDENT_RUNNING: AtomicBool = AtomicBool::new(false);

/// Statistics
static IDENT_QUERIES: AtomicU32 = AtomicU32::new(0);
static IDENT_RESPONSES: AtomicU32 = AtomicU32::new(0);

/// Default username to report
static mut IDENT_USERNAME: [u8; 32] = *b"nostalgia\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
static mut IDENT_USERNAME_LEN: usize = 9;

/// Ident response types
pub mod response_type {
    pub const USERID: &str = "USERID";
    pub const ERROR: &str = "ERROR";
}

/// Ident error codes
pub mod error_code {
    pub const INVALID_PORT: &str = "INVALID-PORT";
    pub const NO_USER: &str = "NO-USER";
    pub const HIDDEN_USER: &str = "HIDDEN-USER";
    pub const UNKNOWN_ERROR: &str = "UNKNOWN-ERROR";
}

/// Set the username to report
pub fn set_username(name: &str) {
    unsafe {
        let len = name.len().min(31);
        IDENT_USERNAME[..len].copy_from_slice(&name.as_bytes()[..len]);
        IDENT_USERNAME_LEN = len;
    }
}

/// Get the configured username
pub fn get_username() -> &'static str {
    unsafe {
        core::str::from_utf8(&IDENT_USERNAME[..IDENT_USERNAME_LEN]).unwrap_or("unknown")
    }
}

/// Parse an ident request (format: "port-on-server, port-on-client\r\n")
fn parse_ident_request(request: &str) -> Option<(u16, u16)> {
    let request = request.trim();
    let parts: alloc::vec::Vec<&str> = request.split(',').collect();
    if parts.len() != 2 {
        return None;
    }

    let server_port: u16 = parts[0].trim().parse().ok()?;
    let client_port: u16 = parts[1].trim().parse().ok()?;

    Some((server_port, client_port))
}

/// Generate ident response
pub fn generate_response(server_port: u16, client_port: u16) -> String {
    // In a real implementation, we would look up the connection
    // For now, we just return our configured username
    let username = get_username();

    format!(
        "{}, {} : {} : UNIX : {}\r\n",
        server_port, client_port, response_type::USERID, username
    )
}

/// Generate error response
pub fn generate_error(server_port: u16, client_port: u16, error: &str) -> String {
    format!(
        "{}, {} : {} : {}\r\n",
        server_port, client_port, response_type::ERROR, error
    )
}

/// Query a remote ident server
pub fn ident_query(
    device_index: usize,
    server_ip: Ipv4Address,
    server_port: u16,
    client_port: u16,
    timeout_ms: u32,
) -> Result<String, &'static str> {
    let socket = tcp::socket_create().ok_or("Failed to create socket")?;
    tcp::socket_connect(socket, device_index, server_ip, IDENT_PORT)?;

    // Send query
    let query = format!("{}, {}\r\n", server_port, client_port);
    tcp::socket_send(socket, query.as_bytes())?;

    // Read response
    let mut response_buf = [0u8; 512];
    let mut response_len = 0;

    let start = crate::hal::apic::get_tick_count();
    let timeout_ticks = timeout_ms as u64 * 1000;

    loop {
        match tcp::socket_recv(socket, &mut response_buf[response_len..]) {
            Ok(n) if n > 0 => {
                response_len += n;
                // Check for CRLF
                if response_len >= 2 &&
                   response_buf[response_len - 2] == b'\r' &&
                   response_buf[response_len - 1] == b'\n' {
                    break;
                }
                if response_len >= response_buf.len() {
                    break;
                }
            }
            Ok(_) => break,
            Err(_) => break,
        }

        let elapsed = crate::hal::apic::get_tick_count() - start;
        if elapsed > timeout_ticks {
            let _ = tcp::socket_close(socket);
            return Err("Ident timeout");
        }

        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    let _ = tcp::socket_close(socket);

    IDENT_QUERIES.fetch_add(1, Ordering::Relaxed);

    if let Ok(s) = core::str::from_utf8(&response_buf[..response_len]) {
        Ok(String::from(s.trim()))
    } else {
        Err("Invalid UTF-8 in response")
    }
}

/// Parse ident response
/// Returns (server_port, client_port, response_type, os_type, user_id)
pub fn parse_response(response: &str) -> Option<(u16, u16, &str, Option<&str>, Option<&str>)> {
    let response = response.trim();
    let parts: alloc::vec::Vec<&str> = response.splitn(3, ':').collect();

    if parts.len() < 2 {
        return None;
    }

    // Parse ports
    let port_parts: alloc::vec::Vec<&str> = parts[0].split(',').collect();
    if port_parts.len() != 2 {
        return None;
    }

    let server_port: u16 = port_parts[0].trim().parse().ok()?;
    let client_port: u16 = port_parts[1].trim().parse().ok()?;

    let response_type = parts[1].trim();

    if parts.len() == 3 {
        let rest = parts[2].trim();
        if response_type == response_type::USERID {
            // Format: OS : user-id
            let user_parts: alloc::vec::Vec<&str> = rest.splitn(2, ':').collect();
            if user_parts.len() == 2 {
                return Some((server_port, client_port, response_type,
                            Some(user_parts[0].trim()), Some(user_parts[1].trim())));
            }
        }
        return Some((server_port, client_port, response_type, Some(rest), None));
    }

    Some((server_port, client_port, response_type, None, None))
}

/// Ident service statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentStats {
    pub queries: u32,
    pub responses: u32,
    pub running: bool,
}

/// Get ident statistics
pub fn get_stats() -> IdentStats {
    IdentStats {
        queries: IDENT_QUERIES.load(Ordering::Relaxed),
        responses: IDENT_RESPONSES.load(Ordering::Relaxed),
        running: IDENT_RUNNING.load(Ordering::SeqCst),
    }
}

/// Initialize ident service
pub fn init() {
    crate::serial_println!("[IDENT] Ident service initialized");
}
