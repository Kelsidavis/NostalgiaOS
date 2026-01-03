//! Telnet Server
//!
//! RFC 854 - Telnet Protocol Specification
//! Provides remote shell access over TCP.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::ke::SpinLock;
use super::tcp::{self, TcpSocket, TcpState};
use super::ip::Ipv4Address;

/// Telnet default port
pub const TELNET_PORT: u16 = 23;

/// Maximum telnet sessions
pub const MAX_TELNET_SESSIONS: usize = 4;

/// Input buffer size per session
pub const INPUT_BUFFER_SIZE: usize = 256;

/// Output buffer size per session
pub const OUTPUT_BUFFER_SIZE: usize = 4096;

/// Telnet command bytes (IAC sequences)
pub mod iac {
    pub const IAC: u8 = 255;   // Interpret As Command
    pub const DONT: u8 = 254;  // Refuse to perform option
    pub const DO: u8 = 253;    // Request to perform option
    pub const WONT: u8 = 252;  // Refuse to perform option
    pub const WILL: u8 = 251;  // Agree to perform option
    pub const SB: u8 = 250;    // Subnegotiation begin
    pub const GA: u8 = 249;    // Go ahead
    pub const EL: u8 = 248;    // Erase line
    pub const EC: u8 = 247;    // Erase character
    pub const AYT: u8 = 246;   // Are you there
    pub const AO: u8 = 245;    // Abort output
    pub const IP: u8 = 244;    // Interrupt process
    pub const BRK: u8 = 243;   // Break
    pub const DM: u8 = 242;    // Data mark
    pub const NOP: u8 = 241;   // No operation
    pub const SE: u8 = 240;    // Subnegotiation end
}

/// Telnet options
pub mod options {
    pub const ECHO: u8 = 1;           // Echo
    pub const SUPPRESS_GO_AHEAD: u8 = 3;  // Suppress Go Ahead
    pub const STATUS: u8 = 5;         // Status
    pub const TIMING_MARK: u8 = 6;    // Timing Mark
    pub const TERMINAL_TYPE: u8 = 24; // Terminal Type
    pub const WINDOW_SIZE: u8 = 31;   // Window Size
    pub const TERMINAL_SPEED: u8 = 32;// Terminal Speed
    pub const LINEMODE: u8 = 34;      // Linemode
}

/// Telnet session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelnetState {
    /// Session not in use
    Closed,
    /// Waiting for connection
    Listening,
    /// Connection established, negotiating
    Negotiating,
    /// Ready for commands
    Ready,
    /// Processing a command
    Processing,
}

/// IAC parsing state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IacState {
    Normal,
    Iac,
    Will,
    Wont,
    Do,
    Dont,
    Sb,
    SbData,
}

/// Telnet session
pub struct TelnetSession {
    /// Session state
    state: TelnetState,
    /// TCP socket handle
    socket: Option<TcpSocket>,
    /// Network device index
    device_index: usize,
    /// Remote IP address
    remote_ip: Ipv4Address,
    /// Remote port
    remote_port: u16,
    /// Input buffer (commands from client)
    input_buffer: [u8; INPUT_BUFFER_SIZE],
    /// Input buffer position
    input_pos: usize,
    /// Output buffer (responses to client)
    output_buffer: Vec<u8>,
    /// IAC parsing state
    iac_state: IacState,
    /// Echo enabled
    echo_enabled: bool,
    /// Line mode (buffer until newline)
    line_mode: bool,
    /// Session active
    active: bool,
}

impl TelnetSession {
    const fn new() -> Self {
        Self {
            state: TelnetState::Closed,
            socket: None,
            device_index: 0,
            remote_ip: Ipv4Address::new([0, 0, 0, 0]),
            remote_port: 0,
            input_buffer: [0u8; INPUT_BUFFER_SIZE],
            input_pos: 0,
            output_buffer: Vec::new(),
            iac_state: IacState::Normal,
            echo_enabled: true,
            line_mode: true,
            active: false,
        }
    }

    fn reset(&mut self) {
        self.state = TelnetState::Closed;
        self.socket = None;
        self.remote_ip = Ipv4Address::new([0, 0, 0, 0]);
        self.remote_port = 0;
        self.input_pos = 0;
        self.output_buffer.clear();
        self.iac_state = IacState::Normal;
        self.echo_enabled = true;
        self.line_mode = true;
        self.active = false;
    }
}

/// Global telnet sessions
static mut TELNET_SESSIONS: [TelnetSession; MAX_TELNET_SESSIONS] = [
    TelnetSession::new(),
    TelnetSession::new(),
    TelnetSession::new(),
    TelnetSession::new(),
];

/// Telnet server state
static TELNET_INITIALIZED: AtomicBool = AtomicBool::new(false);
static TELNET_LISTENING: AtomicBool = AtomicBool::new(false);
static TELNET_LISTEN_SOCKET: AtomicUsize = AtomicUsize::new(usize::MAX);
static TELNET_DEVICE_INDEX: AtomicUsize = AtomicUsize::new(0);
static TELNET_LOCK: SpinLock<()> = SpinLock::new(());

/// Active session count
static ACTIVE_SESSIONS: AtomicUsize = AtomicUsize::new(0);

/// Initialize telnet server
pub fn init() {
    TELNET_INITIALIZED.store(true, Ordering::SeqCst);
    crate::serial_println!("[TELNET] Telnet server initialized");
}

/// Start telnet server on specified device
pub fn start_server(device_index: usize, port: u16) -> Result<(), &'static str> {
    if !TELNET_INITIALIZED.load(Ordering::SeqCst) {
        return Err("Telnet not initialized");
    }

    if TELNET_LISTENING.load(Ordering::SeqCst) {
        return Err("Server already running");
    }

    // Create listening socket
    let socket = tcp::socket_create().ok_or("Failed to create socket")?;

    // Bind to port
    tcp::socket_bind(socket, port)?;

    // Start listening
    tcp::socket_listen(socket, MAX_TELNET_SESSIONS)?;

    TELNET_LISTEN_SOCKET.store(socket, Ordering::SeqCst);
    TELNET_DEVICE_INDEX.store(device_index, Ordering::SeqCst);
    TELNET_LISTENING.store(true, Ordering::SeqCst);

    crate::serial_println!("[TELNET] Server started on port {}", port);
    Ok(())
}

/// Stop telnet server
pub fn stop_server() -> Result<(), &'static str> {
    if !TELNET_LISTENING.load(Ordering::SeqCst) {
        return Err("Server not running");
    }

    let socket = TELNET_LISTEN_SOCKET.load(Ordering::SeqCst);
    if socket != usize::MAX {
        let _ = tcp::socket_close(socket);
    }

    // Close all sessions
    let _guard = TELNET_LOCK.lock();
    unsafe {
        for session in TELNET_SESSIONS.iter_mut() {
            if session.active {
                if let Some(sock) = session.socket {
                    let _ = tcp::socket_close(sock);
                }
                session.reset();
            }
        }
    }

    TELNET_LISTEN_SOCKET.store(usize::MAX, Ordering::SeqCst);
    TELNET_LISTENING.store(false, Ordering::SeqCst);
    ACTIVE_SESSIONS.store(0, Ordering::SeqCst);

    crate::serial_println!("[TELNET] Server stopped");
    Ok(())
}

/// Poll telnet server (should be called periodically)
pub fn poll() {
    if !TELNET_LISTENING.load(Ordering::SeqCst) {
        return;
    }

    // Poll network for incoming data
    crate::drivers::virtio::net::poll();

    let _guard = TELNET_LOCK.lock();

    // Check for new connections on listen socket
    check_new_connections();

    // Process existing sessions
    unsafe {
        for i in 0..MAX_TELNET_SESSIONS {
            if TELNET_SESSIONS[i].active {
                process_session(i);
            }
        }
    }
}

/// Check for new connections
fn check_new_connections() {
    let listen_socket = TELNET_LISTEN_SOCKET.load(Ordering::SeqCst);
    if listen_socket == usize::MAX {
        return;
    }

    // Check if listening socket has a pending connection
    if let Some(state) = tcp::socket_state(listen_socket) {
        if state == TcpState::Established {
            // Find a free session slot
            unsafe {
                for i in 0..MAX_TELNET_SESSIONS {
                    if !TELNET_SESSIONS[i].active {
                        // Accept this connection by moving socket to session
                        accept_connection(i, listen_socket);

                        // Create new listening socket
                        if let Some(new_socket) = tcp::socket_create() {
                            if tcp::socket_bind(new_socket, TELNET_PORT).is_ok() {
                                if tcp::socket_listen(new_socket, MAX_TELNET_SESSIONS).is_ok() {
                                    TELNET_LISTEN_SOCKET.store(new_socket, Ordering::SeqCst);
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
}

/// Accept a new connection
fn accept_connection(session_idx: usize, socket: TcpSocket) {
    unsafe {
        let session = &mut TELNET_SESSIONS[session_idx];

        // Get connection info from socket
        if let Some((_, _local_port, remote_port, remote_ip, _, _)) = tcp::get_socket_info(socket) {
            session.socket = Some(socket);
            session.remote_ip = remote_ip;
            session.remote_port = remote_port;
            session.device_index = TELNET_DEVICE_INDEX.load(Ordering::SeqCst);
            session.state = TelnetState::Negotiating;
            session.active = true;
            session.output_buffer = Vec::with_capacity(OUTPUT_BUFFER_SIZE);

            ACTIVE_SESSIONS.fetch_add(1, Ordering::SeqCst);

            crate::serial_println!(
                "[TELNET] Session {} accepted from {:?}:{}",
                session_idx, remote_ip, remote_port
            );

            // Send initial negotiation and banner
            send_initial_negotiation(session_idx);
        }
    }
}

/// Send initial telnet negotiation
fn send_initial_negotiation(session_idx: usize) {
    unsafe {
        let session = &mut TELNET_SESSIONS[session_idx];

        // Tell client we will echo
        session.output_buffer.extend_from_slice(&[iac::IAC, iac::WILL, options::ECHO]);

        // Tell client we will suppress go-ahead
        session.output_buffer.extend_from_slice(&[iac::IAC, iac::WILL, options::SUPPRESS_GO_AHEAD]);

        // Request client suppress go-ahead
        session.output_buffer.extend_from_slice(&[iac::IAC, iac::DO, options::SUPPRESS_GO_AHEAD]);

        // Send banner
        let banner = "\r\n\
            ======================================\r\n\
            Welcome to NostalgOS Telnet Server\r\n\
            Windows Server 2003 Recreation\r\n\
            ======================================\r\n\
            \r\n";
        session.output_buffer.extend_from_slice(banner.as_bytes());

        // Send prompt
        session.output_buffer.extend_from_slice(b"NostalgOS> ");

        session.state = TelnetState::Ready;

        // Flush output
        flush_output(session_idx);
    }
}

/// Process a telnet session
fn process_session(session_idx: usize) {
    unsafe {
        let session = &mut TELNET_SESSIONS[session_idx];

        if !session.active {
            return;
        }

        let socket = match session.socket {
            Some(s) => s,
            None => {
                session.reset();
                ACTIVE_SESSIONS.fetch_sub(1, Ordering::SeqCst);
                return;
            }
        };

        // Check socket state
        match tcp::socket_state(socket) {
            Some(TcpState::Established) | Some(TcpState::CloseWait) => {
                // Socket is connected, process I/O
            }
            Some(TcpState::Closed) | None => {
                // Connection closed
                crate::serial_println!("[TELNET] Session {} closed", session_idx);
                let _ = tcp::socket_close(socket);
                session.reset();
                ACTIVE_SESSIONS.fetch_sub(1, Ordering::SeqCst);
                return;
            }
            _ => {
                // Other states, just wait
                return;
            }
        }

        // Receive data from client
        let mut recv_buf = [0u8; 128];
        match tcp::socket_recv(socket, &mut recv_buf) {
            Ok(n) if n > 0 => {
                // Process received bytes
                for i in 0..n {
                    process_byte(session_idx, recv_buf[i]);
                }
            }
            _ => {}
        }

        // Send any pending output
        flush_output(session_idx);
    }
}

/// Process a single byte from client
fn process_byte(session_idx: usize, byte: u8) {
    unsafe {
        let session = &mut TELNET_SESSIONS[session_idx];

        match session.iac_state {
            IacState::Normal => {
                if byte == iac::IAC {
                    session.iac_state = IacState::Iac;
                } else if byte == b'\r' {
                    // Carriage return - might be followed by \n or \0
                    // Process the command
                    process_command(session_idx);
                } else if byte == b'\n' {
                    // Line feed alone - ignore (usually follows \r)
                } else if byte == 127 || byte == 8 {
                    // Backspace or DEL
                    if session.input_pos > 0 {
                        session.input_pos -= 1;
                        // Echo backspace
                        if session.echo_enabled {
                            session.output_buffer.extend_from_slice(b"\x08 \x08");
                        }
                    }
                } else if byte >= 32 && byte < 127 {
                    // Printable character
                    if session.input_pos < INPUT_BUFFER_SIZE - 1 {
                        session.input_buffer[session.input_pos] = byte;
                        session.input_pos += 1;

                        // Echo character
                        if session.echo_enabled {
                            session.output_buffer.push(byte);
                        }
                    }
                }
            }
            IacState::Iac => {
                match byte {
                    iac::IAC => {
                        // Escaped IAC (literal 255)
                        if session.input_pos < INPUT_BUFFER_SIZE - 1 {
                            session.input_buffer[session.input_pos] = 255;
                            session.input_pos += 1;
                        }
                        session.iac_state = IacState::Normal;
                    }
                    iac::WILL => session.iac_state = IacState::Will,
                    iac::WONT => session.iac_state = IacState::Wont,
                    iac::DO => session.iac_state = IacState::Do,
                    iac::DONT => session.iac_state = IacState::Dont,
                    iac::SB => session.iac_state = IacState::Sb,
                    iac::NOP | iac::GA => session.iac_state = IacState::Normal,
                    _ => session.iac_state = IacState::Normal,
                }
            }
            IacState::Will => {
                // Client will do something - acknowledge or refuse
                handle_will(session_idx, byte);
                session.iac_state = IacState::Normal;
            }
            IacState::Wont => {
                // Client won't do something - acknowledge
                session.iac_state = IacState::Normal;
            }
            IacState::Do => {
                // Client wants us to do something
                handle_do(session_idx, byte);
                session.iac_state = IacState::Normal;
            }
            IacState::Dont => {
                // Client doesn't want us to do something
                handle_dont(session_idx, byte);
                session.iac_state = IacState::Normal;
            }
            IacState::Sb => {
                // Subnegotiation - just skip to SE
                session.iac_state = IacState::SbData;
            }
            IacState::SbData => {
                if byte == iac::SE {
                    session.iac_state = IacState::Normal;
                } else if byte == iac::IAC {
                    // Could be IAC SE
                }
            }
        }
    }
}

/// Handle WILL option
fn handle_will(session_idx: usize, option: u8) {
    unsafe {
        let session = &mut TELNET_SESSIONS[session_idx];

        match option {
            options::SUPPRESS_GO_AHEAD => {
                // Accept
                session.output_buffer.extend_from_slice(&[iac::IAC, iac::DO, option]);
            }
            _ => {
                // Refuse other options
                session.output_buffer.extend_from_slice(&[iac::IAC, iac::DONT, option]);
            }
        }
    }
}

/// Handle DO option
fn handle_do(session_idx: usize, option: u8) {
    unsafe {
        let session = &mut TELNET_SESSIONS[session_idx];

        match option {
            options::ECHO => {
                session.echo_enabled = true;
                session.output_buffer.extend_from_slice(&[iac::IAC, iac::WILL, option]);
            }
            options::SUPPRESS_GO_AHEAD => {
                session.output_buffer.extend_from_slice(&[iac::IAC, iac::WILL, option]);
            }
            _ => {
                // Refuse other options
                session.output_buffer.extend_from_slice(&[iac::IAC, iac::WONT, option]);
            }
        }
    }
}

/// Handle DONT option
fn handle_dont(session_idx: usize, option: u8) {
    unsafe {
        let session = &mut TELNET_SESSIONS[session_idx];

        match option {
            options::ECHO => {
                session.echo_enabled = false;
                session.output_buffer.extend_from_slice(&[iac::IAC, iac::WONT, option]);
            }
            _ => {
                session.output_buffer.extend_from_slice(&[iac::IAC, iac::WONT, option]);
            }
        }
    }
}

/// Process a complete command line
fn process_command(session_idx: usize) {
    unsafe {
        let session = &mut TELNET_SESSIONS[session_idx];

        // Get command string
        let cmd_len = session.input_pos;
        if cmd_len == 0 {
            // Empty command, just send new prompt
            session.output_buffer.extend_from_slice(b"\r\nNostalgOS> ");
            session.input_pos = 0;
            return;
        }

        let cmd_str = core::str::from_utf8(&session.input_buffer[..cmd_len])
            .unwrap_or("");
        let cmd_str = cmd_str.trim();

        // Echo newline
        session.output_buffer.extend_from_slice(b"\r\n");

        // Process command
        let output = execute_telnet_command(cmd_str, session_idx);

        // Send output
        for line in output.lines() {
            session.output_buffer.extend_from_slice(line.as_bytes());
            session.output_buffer.extend_from_slice(b"\r\n");
        }

        // Send prompt
        session.output_buffer.extend_from_slice(b"NostalgOS> ");

        // Clear input buffer
        session.input_pos = 0;
    }
}

/// Execute a command for telnet session
fn execute_telnet_command(cmd: &str, session_idx: usize) -> String {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return String::new();
    }

    let command = parts[0].to_ascii_lowercase();

    match command.as_str() {
        "help" | "?" => {
            String::from(
                "Available commands:\n\
                 help       - Show this help\n\
                 version    - Show version info\n\
                 uptime     - Show system uptime\n\
                 mem        - Show memory usage\n\
                 net        - Show network status\n\
                 who        - Show telnet sessions\n\
                 exit       - Close connection\n\
                 \n\
                 For full shell access, use local console."
            )
        }
        "version" | "ver" => {
            String::from("NostalgOS v0.1.0 (Windows Server 2003 Recreation)\nKernel: Rust x86_64")
        }
        "uptime" => {
            let ticks = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);
            let seconds = ticks / 1000;
            let minutes = seconds / 60;
            let hours = minutes / 60;
            alloc::format!(
                "System uptime: {}h {}m {}s ({} ticks)",
                hours, minutes % 60, seconds % 60, ticks
            )
        }
        "mem" | "memory" => {
            use crate::mm::pfn;
            let stats = pfn::mm_get_stats();
            alloc::format!(
                "Memory Usage:\n\
                 Total Pages:  {}\n\
                 Free Pages:   {}\n\
                 Used Pages:   {}",
                stats.total_pages,
                stats.free_pages,
                stats.total_pages - stats.free_pages
            )
        }
        "net" | "network" => {
            let device_count = super::get_device_count();
            let mut output = alloc::format!("Network Devices: {}\n", device_count);

            for i in 0..device_count {
                if let Some(device) = super::get_device(i) {
                    output.push_str(&alloc::format!(
                        "  {}: {} {:?}\n",
                        i, device.info.name, device.state()
                    ));
                    if let Some(ip) = device.ip_address {
                        output.push_str(&alloc::format!("     IP: {:?}\n", ip));
                    }
                }
            }

            let stats = super::get_stats();
            output.push_str(&alloc::format!(
                "\nPackets: RX={} TX={}\n",
                stats.packets_received, stats.packets_transmitted
            ));

            output
        }
        "who" | "sessions" => {
            let mut output = String::from("Telnet Sessions:\n");
            unsafe {
                for i in 0..MAX_TELNET_SESSIONS {
                    let session = &TELNET_SESSIONS[i];
                    if session.active {
                        let marker = if i == session_idx { " *" } else { "" };
                        output.push_str(&alloc::format!(
                            "  {}: {:?}:{} {:?}{}\n",
                            i, session.remote_ip, session.remote_port, session.state, marker
                        ));
                    }
                }
            }
            let active = ACTIVE_SESSIONS.load(Ordering::SeqCst);
            output.push_str(&alloc::format!("\nActive: {}/{}\n", active, MAX_TELNET_SESSIONS));
            output
        }
        "exit" | "quit" | "logout" => {
            // Close this session
            unsafe {
                let session = &mut TELNET_SESSIONS[session_idx];
                session.output_buffer.extend_from_slice(b"Goodbye!\r\n");
                flush_output(session_idx);

                if let Some(socket) = session.socket {
                    let _ = tcp::socket_close(socket);
                }
                session.reset();
                ACTIVE_SESSIONS.fetch_sub(1, Ordering::SeqCst);
            }
            String::new()
        }
        _ => {
            alloc::format!("Unknown command: {}\nType 'help' for available commands.", parts[0])
        }
    }
}

/// Flush output buffer to socket
fn flush_output(session_idx: usize) {
    unsafe {
        let session = &mut TELNET_SESSIONS[session_idx];

        if session.output_buffer.is_empty() {
            return;
        }

        if let Some(socket) = session.socket {
            // Send in chunks
            let data = core::mem::take(&mut session.output_buffer);
            let mut sent = 0;

            while sent < data.len() {
                let chunk_size = (data.len() - sent).min(512);
                match tcp::socket_send(socket, &data[sent..sent + chunk_size]) {
                    Ok(n) => sent += n,
                    Err(_) => break,
                }
            }

            // Keep any unsent data
            if sent < data.len() {
                session.output_buffer = data[sent..].to_vec();
            }
        }
    }
}

/// Get telnet server status
pub fn get_status() -> (bool, usize, u16) {
    let listening = TELNET_LISTENING.load(Ordering::SeqCst);
    let active = ACTIVE_SESSIONS.load(Ordering::SeqCst);
    (listening, active, TELNET_PORT)
}

/// Get session info
pub fn get_session_info(idx: usize) -> Option<(TelnetState, Ipv4Address, u16)> {
    if idx >= MAX_TELNET_SESSIONS {
        return None;
    }

    let _guard = TELNET_LOCK.lock();
    unsafe {
        let session = &TELNET_SESSIONS[idx];
        if session.active {
            Some((session.state, session.remote_ip, session.remote_port))
        } else {
            None
        }
    }
}

/// String lowercase helper
trait AsciiLower {
    fn to_ascii_lowercase(&self) -> String;
}

impl AsciiLower for str {
    fn to_ascii_lowercase(&self) -> String {
        self.chars()
            .map(|c| if c.is_ascii_uppercase() { (c as u8 + 32) as char } else { c })
            .collect()
    }
}
