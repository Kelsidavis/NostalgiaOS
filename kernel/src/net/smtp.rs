//! SMTP Client
//!
//! RFC 5321 - Simple Mail Transfer Protocol
//! Basic SMTP client for sending email notifications.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use super::tcp;
use super::ip::Ipv4Address;
use crate::ke::SpinLock;

/// Default SMTP port
pub const SMTP_PORT: u16 = 25;

/// SMTP submission port (with authentication)
pub const SMTP_SUBMISSION_PORT: u16 = 587;

/// Maximum line length in SMTP
pub const MAX_LINE_LENGTH: usize = 998;

/// SMTP response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SmtpReplyCode {
    /// System status
    SystemStatus = 211,
    /// Help message
    Help = 214,
    /// Service ready
    ServiceReady = 220,
    /// Service closing
    ServiceClosing = 221,
    /// Authentication successful
    AuthSuccess = 235,
    /// Requested action completed
    Ok = 250,
    /// User not local, will forward
    UserNotLocal = 251,
    /// Cannot verify user
    CannotVerify = 252,
    /// Authentication challenge
    AuthChallenge = 334,
    /// Start mail input
    StartMailInput = 354,
    /// Service not available
    ServiceUnavailable = 421,
    /// Mailbox unavailable (busy)
    MailboxBusy = 450,
    /// Local error
    LocalError = 451,
    /// Insufficient storage
    InsufficientStorage = 452,
    /// Command not recognized
    CommandNotRecognized = 500,
    /// Syntax error in parameters
    SyntaxError = 501,
    /// Command not implemented
    CommandNotImplemented = 502,
    /// Bad sequence of commands
    BadSequence = 503,
    /// Parameter not implemented
    ParameterNotImplemented = 504,
    /// Authentication required
    AuthRequired = 530,
    /// Authentication failed
    AuthFailed = 535,
    /// Mailbox unavailable
    MailboxUnavailable = 550,
    /// User not local
    UserNotLocalError = 551,
    /// Storage exceeded
    StorageExceeded = 552,
    /// Mailbox name not allowed
    MailboxNameNotAllowed = 553,
    /// Transaction failed
    TransactionFailed = 554,
}

impl SmtpReplyCode {
    pub fn from_u16(code: u16) -> Option<Self> {
        match code {
            211 => Some(Self::SystemStatus),
            214 => Some(Self::Help),
            220 => Some(Self::ServiceReady),
            221 => Some(Self::ServiceClosing),
            235 => Some(Self::AuthSuccess),
            250 => Some(Self::Ok),
            251 => Some(Self::UserNotLocal),
            252 => Some(Self::CannotVerify),
            334 => Some(Self::AuthChallenge),
            354 => Some(Self::StartMailInput),
            421 => Some(Self::ServiceUnavailable),
            450 => Some(Self::MailboxBusy),
            451 => Some(Self::LocalError),
            452 => Some(Self::InsufficientStorage),
            500 => Some(Self::CommandNotRecognized),
            501 => Some(Self::SyntaxError),
            502 => Some(Self::CommandNotImplemented),
            503 => Some(Self::BadSequence),
            504 => Some(Self::ParameterNotImplemented),
            530 => Some(Self::AuthRequired),
            535 => Some(Self::AuthFailed),
            550 => Some(Self::MailboxUnavailable),
            551 => Some(Self::UserNotLocalError),
            552 => Some(Self::StorageExceeded),
            553 => Some(Self::MailboxNameNotAllowed),
            554 => Some(Self::TransactionFailed),
            _ => None,
        }
    }

    pub fn is_positive(&self) -> bool {
        (*self as u16) >= 200 && (*self as u16) < 400
    }

    pub fn is_positive_completion(&self) -> bool {
        (*self as u16) >= 200 && (*self as u16) < 300
    }

    pub fn is_positive_intermediate(&self) -> bool {
        (*self as u16) >= 300 && (*self as u16) < 400
    }

    pub fn is_negative(&self) -> bool {
        (*self as u16) >= 400
    }
}

/// SMTP session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpState {
    Disconnected,
    Connected,
    Greeted,
    MailFrom,
    RcptTo,
    Data,
}

/// SMTP client session
pub struct SmtpSession {
    device_index: usize,
    server_ip: Ipv4Address,
    server_port: u16,
    socket: Option<usize>,
    state: SmtpState,
    hostname: [u8; 64],
    hostname_len: usize,
}

impl SmtpSession {
    /// Create a new SMTP session
    pub fn new(device_index: usize, server_ip: Ipv4Address) -> Self {
        let mut hostname = [0u8; 64];
        hostname[..9].copy_from_slice(b"nostalgos");

        Self {
            device_index,
            server_ip,
            server_port: SMTP_PORT,
            socket: None,
            state: SmtpState::Disconnected,
            hostname,
            hostname_len: 9,
        }
    }

    /// Set SMTP port
    pub fn set_port(&mut self, port: u16) {
        self.server_port = port;
    }

    /// Set local hostname (for HELO/EHLO)
    pub fn set_hostname(&mut self, hostname: &str) {
        let bytes = hostname.as_bytes();
        let len = bytes.len().min(64);
        self.hostname[..len].copy_from_slice(&bytes[..len]);
        self.hostname_len = len;
    }

    /// Connect to SMTP server
    pub fn connect(&mut self) -> Result<(), &'static str> {
        if self.state != SmtpState::Disconnected {
            return Err("Already connected");
        }

        // Create TCP socket and connect
        let socket = tcp::socket_create().ok_or("Failed to create socket")?;
        tcp::socket_connect(socket, self.device_index, self.server_ip, self.server_port)?;

        self.socket = Some(socket);
        self.state = SmtpState::Connected;
        CONNECTIONS.fetch_add(1, Ordering::Relaxed);

        // Wait for server greeting (220)
        let response = self.read_response()?;
        if response.0 != 220 {
            self.disconnect();
            return Err("Server not ready");
        }

        Ok(())
    }

    /// Send EHLO or HELO
    pub fn hello(&mut self) -> Result<(), &'static str> {
        if self.state != SmtpState::Connected {
            return Err("Not connected");
        }

        // Try EHLO first
        let mut cmd = Vec::with_capacity(self.hostname_len + 7);
        cmd.extend_from_slice(b"EHLO ");
        cmd.extend_from_slice(&self.hostname[..self.hostname_len]);
        cmd.extend_from_slice(b"\r\n");

        self.send_command(&cmd)?;
        let response = self.read_response()?;

        if response.0 == 250 {
            self.state = SmtpState::Greeted;
            return Ok(());
        }

        // Fall back to HELO
        let mut cmd = Vec::with_capacity(self.hostname_len + 7);
        cmd.extend_from_slice(b"HELO ");
        cmd.extend_from_slice(&self.hostname[..self.hostname_len]);
        cmd.extend_from_slice(b"\r\n");

        self.send_command(&cmd)?;
        let response = self.read_response()?;

        if response.0 == 250 {
            self.state = SmtpState::Greeted;
            Ok(())
        } else {
            Err("HELO rejected")
        }
    }

    /// Set the sender (MAIL FROM)
    pub fn mail_from(&mut self, sender: &str) -> Result<(), &'static str> {
        if self.state != SmtpState::Greeted && self.state != SmtpState::RcptTo {
            return Err("Invalid state");
        }

        let mut cmd = Vec::with_capacity(sender.len() + 15);
        cmd.extend_from_slice(b"MAIL FROM:<");
        cmd.extend_from_slice(sender.as_bytes());
        cmd.extend_from_slice(b">\r\n");

        self.send_command(&cmd)?;
        let response = self.read_response()?;

        if response.0 == 250 {
            self.state = SmtpState::MailFrom;
            Ok(())
        } else {
            Err("MAIL FROM rejected")
        }
    }

    /// Add a recipient (RCPT TO)
    pub fn rcpt_to(&mut self, recipient: &str) -> Result<(), &'static str> {
        if self.state != SmtpState::MailFrom && self.state != SmtpState::RcptTo {
            return Err("Invalid state");
        }

        let mut cmd = Vec::with_capacity(recipient.len() + 13);
        cmd.extend_from_slice(b"RCPT TO:<");
        cmd.extend_from_slice(recipient.as_bytes());
        cmd.extend_from_slice(b">\r\n");

        self.send_command(&cmd)?;
        let response = self.read_response()?;

        if response.0 == 250 || response.0 == 251 {
            self.state = SmtpState::RcptTo;
            Ok(())
        } else {
            Err("RCPT TO rejected")
        }
    }

    /// Send message data (DATA)
    pub fn data(&mut self, subject: &str, body: &str) -> Result<(), &'static str> {
        if self.state != SmtpState::RcptTo {
            return Err("No recipients set");
        }

        // Send DATA command
        self.send_command(b"DATA\r\n")?;
        let response = self.read_response()?;

        if response.0 != 354 {
            return Err("DATA rejected");
        }

        self.state = SmtpState::Data;

        // Send headers
        let mut message = Vec::new();
        message.extend_from_slice(b"Subject: ");
        message.extend_from_slice(subject.as_bytes());
        message.extend_from_slice(b"\r\n");
        message.extend_from_slice(b"Content-Type: text/plain; charset=UTF-8\r\n");
        message.extend_from_slice(b"\r\n");

        // Send body (escape leading dots)
        for line in body.lines() {
            if line.starts_with('.') {
                message.push(b'.'); // Dot stuffing
            }
            message.extend_from_slice(line.as_bytes());
            message.extend_from_slice(b"\r\n");
        }

        // End with <CRLF>.<CRLF>
        message.extend_from_slice(b".\r\n");

        self.send_command(&message)?;
        let response = self.read_response()?;

        if response.0 == 250 {
            MESSAGES_SENT.fetch_add(1, Ordering::Relaxed);
            BYTES_SENT.fetch_add(message.len() as u32, Ordering::Relaxed);
            self.state = SmtpState::Greeted;
            Ok(())
        } else {
            SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
            Err("Message rejected")
        }
    }

    /// Send a complete email
    pub fn send_mail(
        &mut self,
        from: &str,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), &'static str> {
        self.mail_from(from)?;
        self.rcpt_to(to)?;
        self.data(subject, body)
    }

    /// Disconnect from server
    pub fn disconnect(&mut self) {
        if let Some(socket) = self.socket.take() {
            // Send QUIT
            let _ = self.send_command(b"QUIT\r\n");
            let _ = tcp::socket_close(socket);
        }
        self.state = SmtpState::Disconnected;
    }

    /// Send a command
    fn send_command(&self, command: &[u8]) -> Result<(), &'static str> {
        let socket = self.socket.ok_or("Not connected")?;
        tcp::socket_send(socket, command).map(|_| ())
    }

    /// Read server response
    fn read_response(&self) -> Result<(u16, String), &'static str> {
        let socket = self.socket.ok_or("Not connected")?;
        let mut buf = [0u8; 512];
        let mut response = Vec::new();

        // Read until we get a complete response
        loop {
            let n = tcp::socket_recv(socket, &mut buf)?;
            if n == 0 {
                return Err("Connection closed");
            }
            response.extend_from_slice(&buf[..n]);

            // Check if we have a complete response (ends with CRLF)
            if response.ends_with(b"\r\n") {
                // Check if this is a continuation line (code followed by -)
                if response.len() >= 4 {
                    let last_line_start = response.len() - response.iter().rev()
                        .take_while(|&&b| b != b'\n')
                        .count() - 1;

                    // If the line before CRLF has code followed by space, we're done
                    if last_line_start + 4 <= response.len() {
                        let code_indicator = response.get(last_line_start + 3);
                        if code_indicator == Some(&b' ') || code_indicator == None {
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
        }

        // Parse response code
        if response.len() < 3 {
            return Err("Invalid response");
        }

        let code_str = core::str::from_utf8(&response[..3]).map_err(|_| "Invalid response")?;
        let code: u16 = code_str.parse().map_err(|_| "Invalid response code")?;

        let message = core::str::from_utf8(&response[4..])
            .unwrap_or("")
            .trim()
            .into();

        Ok((code, message))
    }
}

impl Drop for SmtpSession {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// Global SMTP statistics
static CONNECTIONS: AtomicU32 = AtomicU32::new(0);
static MESSAGES_SENT: AtomicU32 = AtomicU32::new(0);
static BYTES_SENT: AtomicU32 = AtomicU32::new(0);
static SEND_ERRORS: AtomicU32 = AtomicU32::new(0);

/// SMTP configuration for notifications
static SMTP_ENABLED: AtomicBool = AtomicBool::new(false);
static mut SMTP_CONFIG: Option<SmtpConfig> = None;
static SMTP_LOCK: SpinLock<()> = SpinLock::new(());

/// SMTP notification configuration
#[derive(Clone)]
pub struct SmtpConfig {
    pub device_index: usize,
    pub server_ip: Ipv4Address,
    pub server_port: u16,
    pub from_address: [u8; 128],
    pub from_len: usize,
    pub to_address: [u8; 128],
    pub to_len: usize,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            device_index: 0,
            server_ip: Ipv4Address::new([0, 0, 0, 0]),
            server_port: SMTP_PORT,
            from_address: [0; 128],
            from_len: 0,
            to_address: [0; 128],
            to_len: 0,
        }
    }
}

/// Configure SMTP notifications
pub fn configure(config: SmtpConfig) {
    let _guard = SMTP_LOCK.lock();
    unsafe {
        SMTP_CONFIG = Some(config);
    }
    SMTP_ENABLED.store(true, Ordering::SeqCst);
    crate::serial_println!("[SMTP] Notifications configured");
}

/// Enable SMTP notifications
pub fn enable() {
    SMTP_ENABLED.store(true, Ordering::SeqCst);
}

/// Disable SMTP notifications
pub fn disable() {
    SMTP_ENABLED.store(false, Ordering::SeqCst);
}

/// Send a notification email
pub fn send_notification(subject: &str, body: &str) -> Result<(), &'static str> {
    if !SMTP_ENABLED.load(Ordering::SeqCst) {
        return Ok(()); // Silently succeed if disabled
    }

    let config = {
        let _guard = SMTP_LOCK.lock();
        unsafe { SMTP_CONFIG.clone() }
    }.ok_or("SMTP not configured")?;

    if config.server_ip == Ipv4Address::new([0, 0, 0, 0]) {
        return Err("No SMTP server configured");
    }

    let from = core::str::from_utf8(&config.from_address[..config.from_len])
        .map_err(|_| "Invalid from address")?;
    let to = core::str::from_utf8(&config.to_address[..config.to_len])
        .map_err(|_| "Invalid to address")?;

    let mut session = SmtpSession::new(config.device_index, config.server_ip);
    session.set_port(config.server_port);
    session.connect()?;
    session.hello()?;
    session.send_mail(from, to, subject, body)?;

    Ok(())
}

/// SMTP statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct SmtpStats {
    pub connections: u32,
    pub messages_sent: u32,
    pub bytes_sent: u32,
    pub errors: u32,
}

/// Get SMTP statistics
pub fn get_stats() -> SmtpStats {
    SmtpStats {
        connections: CONNECTIONS.load(Ordering::Relaxed),
        messages_sent: MESSAGES_SENT.load(Ordering::Relaxed),
        bytes_sent: BYTES_SENT.load(Ordering::Relaxed),
        errors: SEND_ERRORS.load(Ordering::Relaxed),
    }
}

/// Check if SMTP is configured
pub fn is_configured() -> bool {
    let _guard = SMTP_LOCK.lock();
    unsafe {
        SMTP_CONFIG.as_ref()
            .map(|c| c.server_ip != Ipv4Address::new([0, 0, 0, 0]))
            .unwrap_or(false)
    }
}

/// Initialize SMTP module
pub fn init() {
    unsafe {
        SMTP_CONFIG = Some(SmtpConfig::default());
    }
    crate::serial_println!("[SMTP] SMTP client initialized");
}
