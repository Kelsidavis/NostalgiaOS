//! FTP (File Transfer Protocol) Client
//!
//! RFC 959 - File Transfer Protocol
//! Basic FTP client for downloading and uploading files.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use super::tcp;
use super::ip::Ipv4Address;

/// FTP control port
pub const FTP_PORT: u16 = 21;

/// FTP data port (active mode)
pub const FTP_DATA_PORT: u16 = 20;

/// FTP buffer size
pub const FTP_BUFFER_SIZE: usize = 4096;

/// FTP timeout in milliseconds
pub const FTP_TIMEOUT_MS: u64 = 30000;

/// FTP response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FtpResponse {
    /// 120 - Service ready in nnn minutes
    ServiceReadySoon = 120,
    /// 125 - Data connection already open
    DataConnectionOpen = 125,
    /// 150 - File status okay; about to open data connection
    FileStatusOk = 150,
    /// 200 - Command okay
    CommandOk = 200,
    /// 211 - System status
    SystemStatus = 211,
    /// 215 - NAME system type
    SystemType = 215,
    /// 220 - Service ready
    ServiceReady = 220,
    /// 221 - Service closing control connection
    ServiceClosing = 221,
    /// 225 - Data connection open; no transfer in progress
    DataConnectionReady = 225,
    /// 226 - Closing data connection; transfer complete
    TransferComplete = 226,
    /// 227 - Entering Passive Mode
    PassiveMode = 227,
    /// 230 - User logged in
    UserLoggedIn = 230,
    /// 250 - Requested file action okay
    FileActionOk = 250,
    /// 257 - "PATHNAME" created
    PathnameCreated = 257,
    /// 331 - User name okay, need password
    NeedPassword = 331,
    /// 332 - Need account for login
    NeedAccount = 332,
    /// 350 - Requested file action pending further info
    FileActionPending = 350,
    /// 421 - Service not available
    ServiceUnavailable = 421,
    /// 425 - Can't open data connection
    CantOpenData = 425,
    /// 426 - Connection closed; transfer aborted
    TransferAborted = 426,
    /// 450 - File unavailable (busy)
    FileBusy = 450,
    /// 451 - Local error in processing
    LocalError = 451,
    /// 452 - Insufficient storage space
    InsufficientStorage = 452,
    /// 500 - Syntax error
    SyntaxError = 500,
    /// 501 - Syntax error in parameters
    ParameterError = 501,
    /// 502 - Command not implemented
    NotImplemented = 502,
    /// 503 - Bad sequence of commands
    BadSequence = 503,
    /// 504 - Command not implemented for parameter
    NotImplementedParam = 504,
    /// 530 - Not logged in
    NotLoggedIn = 530,
    /// 532 - Need account for storing files
    NeedAccountStore = 532,
    /// 550 - File unavailable
    FileUnavailable = 550,
    /// 551 - Page type unknown
    PageTypeUnknown = 551,
    /// 552 - Exceeded storage allocation
    StorageExceeded = 552,
    /// 553 - File name not allowed
    FileNameNotAllowed = 553,
    /// Unknown response
    Unknown = 0,
}

impl From<u16> for FtpResponse {
    fn from(code: u16) -> Self {
        match code {
            120 => FtpResponse::ServiceReadySoon,
            125 => FtpResponse::DataConnectionOpen,
            150 => FtpResponse::FileStatusOk,
            200 => FtpResponse::CommandOk,
            211 => FtpResponse::SystemStatus,
            215 => FtpResponse::SystemType,
            220 => FtpResponse::ServiceReady,
            221 => FtpResponse::ServiceClosing,
            225 => FtpResponse::DataConnectionReady,
            226 => FtpResponse::TransferComplete,
            227 => FtpResponse::PassiveMode,
            230 => FtpResponse::UserLoggedIn,
            250 => FtpResponse::FileActionOk,
            257 => FtpResponse::PathnameCreated,
            331 => FtpResponse::NeedPassword,
            332 => FtpResponse::NeedAccount,
            350 => FtpResponse::FileActionPending,
            421 => FtpResponse::ServiceUnavailable,
            425 => FtpResponse::CantOpenData,
            426 => FtpResponse::TransferAborted,
            450 => FtpResponse::FileBusy,
            451 => FtpResponse::LocalError,
            452 => FtpResponse::InsufficientStorage,
            500 => FtpResponse::SyntaxError,
            501 => FtpResponse::ParameterError,
            502 => FtpResponse::NotImplemented,
            503 => FtpResponse::BadSequence,
            504 => FtpResponse::NotImplementedParam,
            530 => FtpResponse::NotLoggedIn,
            532 => FtpResponse::NeedAccountStore,
            550 => FtpResponse::FileUnavailable,
            551 => FtpResponse::PageTypeUnknown,
            552 => FtpResponse::StorageExceeded,
            553 => FtpResponse::FileNameNotAllowed,
            _ => FtpResponse::Unknown,
        }
    }
}

/// FTP transfer mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    /// ASCII mode
    Ascii,
    /// Binary mode
    Binary,
}

/// FTP transfer type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    /// Active mode (server connects to client)
    Active,
    /// Passive mode (client connects to server)
    Passive,
}

/// FTP session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpState {
    /// Not connected
    Disconnected,
    /// Connected, not authenticated
    Connected,
    /// Authenticated
    LoggedIn,
    /// Data transfer in progress
    Transferring,
}

/// Statistics
static SESSIONS_OPENED: AtomicU32 = AtomicU32::new(0);
static FILES_DOWNLOADED: AtomicU32 = AtomicU32::new(0);
static FILES_UPLOADED: AtomicU32 = AtomicU32::new(0);
static BYTES_TRANSFERRED: AtomicU32 = AtomicU32::new(0);

/// FTP session
pub struct FtpSession {
    /// Device index
    device_index: usize,
    /// Server IP
    server_ip: Ipv4Address,
    /// Control socket
    control_socket: Option<usize>,
    /// Current state
    state: FtpState,
    /// Transfer mode
    transfer_mode: TransferMode,
    /// Response buffer
    response_buf: [u8; 512],
}

impl FtpSession {
    /// Create a new FTP session
    pub fn new(device_index: usize, server_ip: Ipv4Address) -> Self {
        Self {
            device_index,
            server_ip,
            control_socket: None,
            state: FtpState::Disconnected,
            transfer_mode: TransferMode::Binary,
            response_buf: [0u8; 512],
        }
    }

    /// Connect to FTP server
    pub fn connect(&mut self) -> Result<(), &'static str> {
        if self.state != FtpState::Disconnected {
            return Err("Already connected");
        }

        // Create TCP socket for control connection
        let socket = tcp::socket_create().ok_or("Failed to create socket")?;

        // Connect to server
        tcp::socket_connect(socket, self.device_index, self.server_ip, FTP_PORT)?;

        self.control_socket = Some(socket);

        // Wait for server greeting (220)
        let response = self.read_response()?;
        if response != FtpResponse::ServiceReady {
            self.disconnect();
            return Err("Server not ready");
        }

        self.state = FtpState::Connected;
        SESSIONS_OPENED.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Login with username and password
    pub fn login(&mut self, username: &str, password: &str) -> Result<(), &'static str> {
        if self.state != FtpState::Connected {
            return Err("Not connected");
        }

        // Send USER command
        self.send_command("USER", Some(username))?;
        let response = self.read_response()?;

        match response {
            FtpResponse::UserLoggedIn => {
                self.state = FtpState::LoggedIn;
                return Ok(());
            }
            FtpResponse::NeedPassword => {}
            _ => return Err("Login failed"),
        }

        // Send PASS command
        self.send_command("PASS", Some(password))?;
        let response = self.read_response()?;

        if response == FtpResponse::UserLoggedIn {
            self.state = FtpState::LoggedIn;
            Ok(())
        } else {
            Err("Authentication failed")
        }
    }

    /// Set transfer mode (ASCII or Binary)
    pub fn set_mode(&mut self, mode: TransferMode) -> Result<(), &'static str> {
        if self.state != FtpState::LoggedIn {
            return Err("Not logged in");
        }

        let type_cmd = match mode {
            TransferMode::Ascii => "A",
            TransferMode::Binary => "I",
        };

        self.send_command("TYPE", Some(type_cmd))?;
        let response = self.read_response()?;

        if response == FtpResponse::CommandOk {
            self.transfer_mode = mode;
            Ok(())
        } else {
            Err("Failed to set transfer mode")
        }
    }

    /// Change directory
    pub fn cwd(&mut self, path: &str) -> Result<(), &'static str> {
        if self.state != FtpState::LoggedIn {
            return Err("Not logged in");
        }

        self.send_command("CWD", Some(path))?;
        let response = self.read_response()?;

        if response == FtpResponse::FileActionOk {
            Ok(())
        } else {
            Err("Failed to change directory")
        }
    }

    /// Get current directory
    pub fn pwd(&mut self) -> Result<String, &'static str> {
        if self.state != FtpState::LoggedIn {
            return Err("Not logged in");
        }

        self.send_command("PWD", None)?;
        let response = self.read_response()?;

        if response == FtpResponse::PathnameCreated {
            // Parse directory from response
            // Response format: 257 "pathname"
            let response_str = core::str::from_utf8(&self.response_buf)
                .map_err(|_| "Invalid response")?;

            if let Some(start) = response_str.find('"') {
                if let Some(end) = response_str[start + 1..].find('"') {
                    return Ok(String::from(&response_str[start + 1..start + 1 + end]));
                }
            }
            Err("Failed to parse directory")
        } else {
            Err("Failed to get directory")
        }
    }

    /// Enter passive mode and get data port
    fn enter_passive(&mut self) -> Result<(Ipv4Address, u16), &'static str> {
        self.send_command("PASV", None)?;
        let response = self.read_response()?;

        if response != FtpResponse::PassiveMode {
            return Err("Passive mode failed");
        }

        // Parse response: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
        let response_str = core::str::from_utf8(&self.response_buf)
            .map_err(|_| "Invalid response")?;

        // Find the parentheses
        let start = response_str.find('(').ok_or("Invalid PASV response")?;
        let end = response_str.find(')').ok_or("Invalid PASV response")?;

        let nums: Vec<u8> = response_str[start + 1..end]
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();

        if nums.len() != 6 {
            return Err("Invalid PASV response format");
        }

        let ip = Ipv4Address::new([nums[0], nums[1], nums[2], nums[3]]);
        let port = ((nums[4] as u16) << 8) | (nums[5] as u16);

        Ok((ip, port))
    }

    /// Download a file
    pub fn get(&mut self, remote_path: &str) -> Result<Vec<u8>, &'static str> {
        if self.state != FtpState::LoggedIn {
            return Err("Not logged in");
        }

        // Enter passive mode
        let (data_ip, data_port) = self.enter_passive()?;

        // Create data socket and connect
        let data_socket = tcp::socket_create().ok_or("Failed to create data socket")?;
        tcp::socket_connect(data_socket, self.device_index, data_ip, data_port)?;

        // Send RETR command
        self.send_command("RETR", Some(remote_path))?;
        let response = self.read_response()?;

        if response != FtpResponse::FileStatusOk && response != FtpResponse::DataConnectionOpen {
            let _ = tcp::socket_close(data_socket);
            return Err("File not available");
        }

        self.state = FtpState::Transferring;

        // Read data
        let mut data = Vec::new();
        let mut buffer = [0u8; FTP_BUFFER_SIZE];

        loop {
            // Poll for data
            crate::drivers::virtio::net::poll();

            match tcp::socket_recv(data_socket, &mut buffer) {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    data.extend_from_slice(&buffer[..n]);
                }
                Err(_) => break,
            }

            // Small delay
            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }

        let _ = tcp::socket_close(data_socket);

        // Wait for transfer complete response
        let response = self.read_response()?;
        if response != FtpResponse::TransferComplete {
            crate::serial_println!("[FTP] Warning: Unexpected response after transfer");
        }

        self.state = FtpState::LoggedIn;
        FILES_DOWNLOADED.fetch_add(1, Ordering::Relaxed);
        BYTES_TRANSFERRED.fetch_add(data.len() as u32, Ordering::Relaxed);

        crate::serial_println!("[FTP] Downloaded {} bytes", data.len());
        Ok(data)
    }

    /// Upload a file
    pub fn put(&mut self, remote_path: &str, data: &[u8]) -> Result<(), &'static str> {
        if self.state != FtpState::LoggedIn {
            return Err("Not logged in");
        }

        // Enter passive mode
        let (data_ip, data_port) = self.enter_passive()?;

        // Create data socket and connect
        let data_socket = tcp::socket_create().ok_or("Failed to create data socket")?;
        tcp::socket_connect(data_socket, self.device_index, data_ip, data_port)?;

        // Send STOR command
        self.send_command("STOR", Some(remote_path))?;
        let response = self.read_response()?;

        if response != FtpResponse::FileStatusOk && response != FtpResponse::DataConnectionOpen {
            let _ = tcp::socket_close(data_socket);
            return Err("Cannot store file");
        }

        self.state = FtpState::Transferring;

        // Send data
        let mut offset = 0;
        while offset < data.len() {
            let chunk_size = (data.len() - offset).min(FTP_BUFFER_SIZE);
            tcp::socket_send(data_socket, &data[offset..offset + chunk_size])?;
            offset += chunk_size;
        }

        let _ = tcp::socket_close(data_socket);

        // Wait for transfer complete response
        let response = self.read_response()?;
        if response != FtpResponse::TransferComplete {
            return Err("Upload failed");
        }

        self.state = FtpState::LoggedIn;
        FILES_UPLOADED.fetch_add(1, Ordering::Relaxed);
        BYTES_TRANSFERRED.fetch_add(data.len() as u32, Ordering::Relaxed);

        crate::serial_println!("[FTP] Uploaded {} bytes", data.len());
        Ok(())
    }

    /// Delete a file
    pub fn delete(&mut self, path: &str) -> Result<(), &'static str> {
        if self.state != FtpState::LoggedIn {
            return Err("Not logged in");
        }

        self.send_command("DELE", Some(path))?;
        let response = self.read_response()?;

        if response == FtpResponse::FileActionOk {
            Ok(())
        } else {
            Err("Delete failed")
        }
    }

    /// Create directory
    pub fn mkdir(&mut self, path: &str) -> Result<(), &'static str> {
        if self.state != FtpState::LoggedIn {
            return Err("Not logged in");
        }

        self.send_command("MKD", Some(path))?;
        let response = self.read_response()?;

        if response == FtpResponse::PathnameCreated {
            Ok(())
        } else {
            Err("Mkdir failed")
        }
    }

    /// Remove directory
    pub fn rmdir(&mut self, path: &str) -> Result<(), &'static str> {
        if self.state != FtpState::LoggedIn {
            return Err("Not logged in");
        }

        self.send_command("RMD", Some(path))?;
        let response = self.read_response()?;

        if response == FtpResponse::FileActionOk {
            Ok(())
        } else {
            Err("Rmdir failed")
        }
    }

    /// Disconnect from server
    pub fn disconnect(&mut self) {
        if let Some(socket) = self.control_socket.take() {
            // Send QUIT command (ignore response)
            let _ = self.send_command("QUIT", None);
            let _ = tcp::socket_close(socket);
        }
        self.state = FtpState::Disconnected;
    }

    /// Send a command to the server
    fn send_command(&mut self, cmd: &str, arg: Option<&str>) -> Result<(), &'static str> {
        let socket = self.control_socket.ok_or("Not connected")?;

        let mut command = String::from(cmd);
        if let Some(a) = arg {
            command.push(' ');
            command.push_str(a);
        }
        command.push_str("\r\n");

        tcp::socket_send(socket, command.as_bytes()).map(|_| ())
    }

    /// Read server response
    fn read_response(&mut self) -> Result<FtpResponse, &'static str> {
        let socket = self.control_socket.ok_or("Not connected")?;

        // Clear response buffer
        self.response_buf.fill(0);

        // Poll for response
        let mut total_read = 0;
        let mut polls = 0;
        const MAX_POLLS: usize = 5000;

        while polls < MAX_POLLS {
            crate::drivers::virtio::net::poll();

            match tcp::socket_recv(socket, &mut self.response_buf[total_read..]) {
                Ok(0) => {}
                Ok(n) => {
                    total_read += n;
                    // Check for end of response (ends with \r\n)
                    if total_read >= 2 &&
                       self.response_buf[total_read - 2] == b'\r' &&
                       self.response_buf[total_read - 1] == b'\n' {
                        break;
                    }
                }
                Err(_) => {}
            }

            polls += 1;
            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }

        if total_read == 0 {
            return Err("No response from server");
        }

        // Parse response code (first 3 digits)
        if total_read < 3 {
            return Err("Invalid response");
        }

        let code_str = core::str::from_utf8(&self.response_buf[..3])
            .map_err(|_| "Invalid response encoding")?;

        let code: u16 = code_str.parse().map_err(|_| "Invalid response code")?;

        Ok(FtpResponse::from(code))
    }

    /// Get current session state
    pub fn get_state(&self) -> FtpState {
        self.state
    }
}

impl Drop for FtpSession {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// Get FTP statistics
pub fn get_stats() -> (u32, u32, u32, u32) {
    (
        SESSIONS_OPENED.load(Ordering::Relaxed),
        FILES_DOWNLOADED.load(Ordering::Relaxed),
        FILES_UPLOADED.load(Ordering::Relaxed),
        BYTES_TRANSFERRED.load(Ordering::Relaxed),
    )
}

/// Initialize FTP module
pub fn init() {
    crate::serial_println!("[FTP] FTP client initialized");
}
