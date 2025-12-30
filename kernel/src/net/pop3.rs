//! POP3 Client
//!
//! RFC 1939 - Post Office Protocol Version 3
//! Basic POP3 client for retrieving email messages.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use super::tcp;
use super::ip::Ipv4Address;

/// Default POP3 port
pub const POP3_PORT: u16 = 110;

/// POP3 over TLS port
pub const POP3S_PORT: u16 = 995;

/// Maximum response line length
pub const MAX_LINE_LENGTH: usize = 512;

/// POP3 session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pop3State {
    Disconnected,
    Authorization,
    Transaction,
}

/// POP3 message info
#[derive(Debug, Clone)]
pub struct MessageInfo {
    /// Message number (1-based)
    pub number: u32,
    /// Message size in bytes
    pub size: u32,
    /// Unique ID (if available)
    pub uid: Option<String>,
}

/// POP3 client session
pub struct Pop3Session {
    device_index: usize,
    server_ip: Ipv4Address,
    server_port: u16,
    socket: Option<usize>,
    state: Pop3State,
}

impl Pop3Session {
    /// Create a new POP3 session
    pub fn new(device_index: usize, server_ip: Ipv4Address) -> Self {
        Self {
            device_index,
            server_ip,
            server_port: POP3_PORT,
            socket: None,
            state: Pop3State::Disconnected,
        }
    }

    /// Set POP3 port
    pub fn set_port(&mut self, port: u16) {
        self.server_port = port;
    }

    /// Connect to POP3 server
    pub fn connect(&mut self) -> Result<(), &'static str> {
        if self.state != Pop3State::Disconnected {
            return Err("Already connected");
        }

        // Create TCP socket and connect
        let socket = tcp::socket_create().ok_or("Failed to create socket")?;
        tcp::socket_connect(socket, self.device_index, self.server_ip, self.server_port)?;

        self.socket = Some(socket);
        CONNECTIONS.fetch_add(1, Ordering::Relaxed);

        // Wait for server greeting
        let response = self.read_response()?;
        if !response.starts_with("+OK") {
            self.disconnect();
            return Err("Server not ready");
        }

        self.state = Pop3State::Authorization;
        Ok(())
    }

    /// Authenticate with USER/PASS
    pub fn login(&mut self, username: &str, password: &str) -> Result<(), &'static str> {
        if self.state != Pop3State::Authorization {
            return Err("Not in authorization state");
        }

        // Send USER command
        let mut cmd = Vec::with_capacity(username.len() + 7);
        cmd.extend_from_slice(b"USER ");
        cmd.extend_from_slice(username.as_bytes());
        cmd.extend_from_slice(b"\r\n");

        self.send_command(&cmd)?;
        let response = self.read_response()?;

        if !response.starts_with("+OK") {
            FAILED_LOGINS.fetch_add(1, Ordering::Relaxed);
            return Err("USER rejected");
        }

        // Send PASS command
        let mut cmd = Vec::with_capacity(password.len() + 7);
        cmd.extend_from_slice(b"PASS ");
        cmd.extend_from_slice(password.as_bytes());
        cmd.extend_from_slice(b"\r\n");

        self.send_command(&cmd)?;
        let response = self.read_response()?;

        if response.starts_with("+OK") {
            self.state = Pop3State::Transaction;
            SUCCESSFUL_LOGINS.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            FAILED_LOGINS.fetch_add(1, Ordering::Relaxed);
            Err("Authentication failed")
        }
    }

    /// Get mailbox statistics (STAT command)
    /// Returns (message_count, total_size)
    pub fn stat(&mut self) -> Result<(u32, u32), &'static str> {
        if self.state != Pop3State::Transaction {
            return Err("Not authenticated");
        }

        self.send_command(b"STAT\r\n")?;
        let response = self.read_response()?;

        if !response.starts_with("+OK") {
            return Err("STAT failed");
        }

        // Parse "+OK count size"
        let parts: Vec<&str> = response.split_whitespace().collect();
        if parts.len() >= 3 {
            let count = parts[1].parse().unwrap_or(0);
            let size = parts[2].parse().unwrap_or(0);
            Ok((count, size))
        } else {
            Err("Invalid STAT response")
        }
    }

    /// List messages (LIST command)
    pub fn list(&mut self) -> Result<Vec<MessageInfo>, &'static str> {
        if self.state != Pop3State::Transaction {
            return Err("Not authenticated");
        }

        self.send_command(b"LIST\r\n")?;
        let response = self.read_multiline_response()?;

        let mut messages = Vec::new();

        for line in response.lines().skip(1) {
            // Skip +OK line
            if line == "." {
                break;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let (Ok(num), Ok(size)) = (parts[0].parse(), parts[1].parse()) {
                    messages.push(MessageInfo {
                        number: num,
                        size,
                        uid: None,
                    });
                }
            }
        }

        Ok(messages)
    }

    /// Get unique IDs (UIDL command)
    pub fn uidl(&mut self) -> Result<Vec<MessageInfo>, &'static str> {
        if self.state != Pop3State::Transaction {
            return Err("Not authenticated");
        }

        self.send_command(b"UIDL\r\n")?;
        let response = self.read_multiline_response()?;

        let mut messages = Vec::new();

        for line in response.lines().skip(1) {
            if line == "." {
                break;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(num) = parts[0].parse() {
                    messages.push(MessageInfo {
                        number: num,
                        size: 0,
                        uid: Some(String::from(parts[1])),
                    });
                }
            }
        }

        Ok(messages)
    }

    /// Retrieve a message (RETR command)
    pub fn retrieve(&mut self, msg_number: u32) -> Result<String, &'static str> {
        if self.state != Pop3State::Transaction {
            return Err("Not authenticated");
        }

        let mut cmd = Vec::with_capacity(16);
        cmd.extend_from_slice(b"RETR ");
        cmd.extend_from_slice(alloc::format!("{}", msg_number).as_bytes());
        cmd.extend_from_slice(b"\r\n");

        self.send_command(&cmd)?;
        let response = self.read_multiline_response()?;

        if !response.starts_with("+OK") {
            return Err("RETR failed");
        }

        MESSAGES_RETRIEVED.fetch_add(1, Ordering::Relaxed);

        // Skip the +OK line and return the message
        if let Some(pos) = response.find("\r\n") {
            let message = &response[pos + 2..];
            // Remove trailing ".\r\n"
            let message = message.trim_end_matches(".\r\n").trim_end_matches("\r\n.\r\n");
            Ok(String::from(message))
        } else {
            Ok(response)
        }
    }

    /// Get message headers only (TOP command)
    pub fn top(&mut self, msg_number: u32, lines: u32) -> Result<String, &'static str> {
        if self.state != Pop3State::Transaction {
            return Err("Not authenticated");
        }

        let mut cmd = Vec::with_capacity(24);
        cmd.extend_from_slice(b"TOP ");
        cmd.extend_from_slice(alloc::format!("{} {}", msg_number, lines).as_bytes());
        cmd.extend_from_slice(b"\r\n");

        self.send_command(&cmd)?;
        let response = self.read_multiline_response()?;

        if !response.starts_with("+OK") {
            return Err("TOP failed");
        }

        if let Some(pos) = response.find("\r\n") {
            Ok(String::from(&response[pos + 2..]))
        } else {
            Ok(response)
        }
    }

    /// Delete a message (DELE command)
    pub fn delete(&mut self, msg_number: u32) -> Result<(), &'static str> {
        if self.state != Pop3State::Transaction {
            return Err("Not authenticated");
        }

        let mut cmd = Vec::with_capacity(16);
        cmd.extend_from_slice(b"DELE ");
        cmd.extend_from_slice(alloc::format!("{}", msg_number).as_bytes());
        cmd.extend_from_slice(b"\r\n");

        self.send_command(&cmd)?;
        let response = self.read_response()?;

        if response.starts_with("+OK") {
            MESSAGES_DELETED.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err("DELE failed")
        }
    }

    /// Reset deleted messages (RSET command)
    pub fn reset(&mut self) -> Result<(), &'static str> {
        if self.state != Pop3State::Transaction {
            return Err("Not authenticated");
        }

        self.send_command(b"RSET\r\n")?;
        let response = self.read_response()?;

        if response.starts_with("+OK") {
            Ok(())
        } else {
            Err("RSET failed")
        }
    }

    /// Send NOOP (keep-alive)
    pub fn noop(&mut self) -> Result<(), &'static str> {
        if self.state != Pop3State::Transaction {
            return Err("Not authenticated");
        }

        self.send_command(b"NOOP\r\n")?;
        let response = self.read_response()?;

        if response.starts_with("+OK") {
            Ok(())
        } else {
            Err("NOOP failed")
        }
    }

    /// Disconnect from server
    pub fn disconnect(&mut self) {
        if let Some(socket) = self.socket.take() {
            // Send QUIT
            let _ = self.send_command(b"QUIT\r\n");
            let _ = tcp::socket_close(socket);
        }
        self.state = Pop3State::Disconnected;
    }

    /// Send a command
    fn send_command(&self, command: &[u8]) -> Result<(), &'static str> {
        let socket = self.socket.ok_or("Not connected")?;
        tcp::socket_send(socket, command).map(|_| ())
    }

    /// Read a single-line response
    fn read_response(&self) -> Result<String, &'static str> {
        let socket = self.socket.ok_or("Not connected")?;
        let mut buf = [0u8; MAX_LINE_LENGTH];
        let mut response = Vec::new();

        loop {
            let n = tcp::socket_recv(socket, &mut buf)?;
            if n == 0 {
                return Err("Connection closed");
            }
            response.extend_from_slice(&buf[..n]);

            // Check for complete line
            if response.ends_with(b"\r\n") {
                break;
            }
        }

        String::from_utf8(response).map_err(|_| "Invalid response")
    }

    /// Read a multi-line response (ends with ".\r\n")
    fn read_multiline_response(&self) -> Result<String, &'static str> {
        let socket = self.socket.ok_or("Not connected")?;
        let mut buf = [0u8; 1024];
        let mut response = Vec::new();

        loop {
            let n = tcp::socket_recv(socket, &mut buf)?;
            if n == 0 {
                return Err("Connection closed");
            }
            response.extend_from_slice(&buf[..n]);

            // Check for end of multi-line response
            if response.ends_with(b"\r\n.\r\n") {
                break;
            }

            // Also check for error response (single line)
            if response.starts_with(b"-ERR") && response.ends_with(b"\r\n") {
                break;
            }
        }

        String::from_utf8(response).map_err(|_| "Invalid response")
    }
}

impl Drop for Pop3Session {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// Global POP3 statistics
static CONNECTIONS: AtomicU32 = AtomicU32::new(0);
static SUCCESSFUL_LOGINS: AtomicU32 = AtomicU32::new(0);
static FAILED_LOGINS: AtomicU32 = AtomicU32::new(0);
static MESSAGES_RETRIEVED: AtomicU32 = AtomicU32::new(0);
static MESSAGES_DELETED: AtomicU32 = AtomicU32::new(0);

/// POP3 statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct Pop3Stats {
    pub connections: u32,
    pub successful_logins: u32,
    pub failed_logins: u32,
    pub messages_retrieved: u32,
    pub messages_deleted: u32,
}

/// Get POP3 statistics
pub fn get_stats() -> Pop3Stats {
    Pop3Stats {
        connections: CONNECTIONS.load(Ordering::Relaxed),
        successful_logins: SUCCESSFUL_LOGINS.load(Ordering::Relaxed),
        failed_logins: FAILED_LOGINS.load(Ordering::Relaxed),
        messages_retrieved: MESSAGES_RETRIEVED.load(Ordering::Relaxed),
        messages_deleted: MESSAGES_DELETED.load(Ordering::Relaxed),
    }
}

/// Initialize POP3 module
pub fn init() {
    crate::serial_println!("[POP3] POP3 client initialized");
}
