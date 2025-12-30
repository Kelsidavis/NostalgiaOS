//! Whois Protocol Client
//!
//! RFC 3912 - WHOIS Protocol Specification
//!
//! Query domain registration information from WHOIS servers.

extern crate alloc;

use alloc::string::String;
use alloc::format;
use core::sync::atomic::{AtomicU32, Ordering};
use super::tcp;
use super::ip::Ipv4Address;

/// Standard WHOIS port (RFC 3912)
pub const WHOIS_PORT: u16 = 43;

/// Statistics
static WHOIS_QUERIES: AtomicU32 = AtomicU32::new(0);

/// Common WHOIS servers
pub mod servers {
    use super::Ipv4Address;

    /// IANA WHOIS server (whois.iana.org) - 192.0.32.59
    pub const IANA: Ipv4Address = Ipv4Address::new([192, 0, 32, 59]);

    /// ARIN WHOIS server (whois.arin.net) - 199.212.0.43
    pub const ARIN: Ipv4Address = Ipv4Address::new([199, 212, 0, 43]);

    /// RIPE WHOIS server (whois.ripe.net) - 193.0.6.139
    pub const RIPE: Ipv4Address = Ipv4Address::new([193, 0, 6, 139]);

    /// APNIC WHOIS server (whois.apnic.net) - 202.12.29.205
    pub const APNIC: Ipv4Address = Ipv4Address::new([202, 12, 29, 205]);

    /// Verisign WHOIS server (whois.verisign-grs.com) - for .com/.net
    pub const VERISIGN: Ipv4Address = Ipv4Address::new([199, 7, 55, 74]);
}

/// Query a WHOIS server
pub fn whois_query(
    device_index: usize,
    server_ip: Ipv4Address,
    query: &str,
    timeout_ms: u32,
) -> Result<String, &'static str> {
    let socket = tcp::socket_create().ok_or("Failed to create socket")?;
    tcp::socket_connect(socket, device_index, server_ip, WHOIS_PORT)?;

    // Send query with CRLF
    let query_bytes = format!("{}\r\n", query);
    tcp::socket_send(socket, query_bytes.as_bytes())?;

    // Read response (WHOIS responses can be large)
    let mut response_buf = [0u8; 8192];
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
                // Connection closed by server
                break;
            }
            Err(_) => {
                break;
            }
        }

        let elapsed = crate::hal::apic::get_tick_count() - start;
        if elapsed > timeout_ticks {
            let _ = tcp::socket_close(socket);
            return Err("WHOIS timeout");
        }

        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    let _ = tcp::socket_close(socket);

    WHOIS_QUERIES.fetch_add(1, Ordering::Relaxed);

    if let Ok(s) = core::str::from_utf8(&response_buf[..response_len]) {
        Ok(String::from(s))
    } else {
        Err("Invalid UTF-8 in response")
    }
}

/// Query IANA for TLD/IP allocation info
pub fn whois_iana(
    device_index: usize,
    query: &str,
    timeout_ms: u32,
) -> Result<String, &'static str> {
    whois_query(device_index, servers::IANA, query, timeout_ms)
}

/// Query ARIN for North American IP allocations
pub fn whois_arin(
    device_index: usize,
    query: &str,
    timeout_ms: u32,
) -> Result<String, &'static str> {
    whois_query(device_index, servers::ARIN, query, timeout_ms)
}

/// WHOIS service statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct WhoisStats {
    pub queries: u32,
}

/// Get WHOIS statistics
pub fn get_stats() -> WhoisStats {
    WhoisStats {
        queries: WHOIS_QUERIES.load(Ordering::Relaxed),
    }
}

/// Initialize WHOIS service
pub fn init() {
    crate::serial_println!("[WHOIS] WHOIS client initialized");
}
