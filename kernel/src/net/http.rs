//! HTTP Client
//!
//! Simple HTTP/1.0 client for making GET requests.
//! Uses the TCP socket API for connections.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::ip::Ipv4Address;
use super::tcp;

/// HTTP default port
pub const HTTP_PORT: u16 = 80;

/// Maximum response size (64KB)
pub const MAX_RESPONSE_SIZE: usize = 65536;

/// HTTP request timeout in polls
pub const HTTP_TIMEOUT_POLLS: usize = 5000;

/// HTTP response structure
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code (e.g., 200, 404)
    pub status_code: u16,
    /// Status text (e.g., "OK", "Not Found")
    pub status_text: String,
    /// Response headers
    pub headers: Vec<(String, String)>,
    /// Response body
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Get a header value by name (case-insensitive)
    pub fn get_header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        for (k, v) in &self.headers {
            if k.to_ascii_lowercase() == name_lower {
                return Some(v.as_str());
            }
        }
        None
    }

    /// Get Content-Length header value
    pub fn content_length(&self) -> Option<usize> {
        self.get_header("Content-Length")
            .and_then(|s| s.parse().ok())
    }

    /// Get body as string (assumes UTF-8)
    pub fn body_as_string(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }
}

/// HTTP client state
pub struct HttpClient {
    socket: Option<tcp::TcpSocket>,
    device_index: usize,
}

impl HttpClient {
    /// Create a new HTTP client
    pub fn new(device_index: usize) -> Self {
        Self {
            socket: None,
            device_index,
        }
    }

    /// Perform a GET request
    pub fn get(&mut self, host: &str, ip: Ipv4Address, port: u16, path: &str) -> Result<HttpResponse, &'static str> {
        // Create socket
        let socket = tcp::socket_create().ok_or("Failed to create socket")?;
        self.socket = Some(socket);

        // Connect to server
        tcp::socket_connect(socket, self.device_index, ip, port)?;

        // Wait for connection to be established
        let mut polls = 0;
        loop {
            if polls > HTTP_TIMEOUT_POLLS {
                let _ = tcp::socket_close(socket);
                self.socket = None;
                return Err("Connection timeout");
            }

            match tcp::socket_state(socket) {
                Some(tcp::TcpState::Established) => break,
                Some(tcp::TcpState::SynSent) => {
                    // Still connecting, poll the network
                    crate::drivers::virtio::net::poll();
                    polls += 1;
                    // Small delay
                    for _ in 0..1000 {
                        core::hint::spin_loop();
                    }
                }
                Some(tcp::TcpState::Closed) | None => {
                    self.socket = None;
                    return Err("Connection refused");
                }
                _ => {
                    polls += 1;
                }
            }
        }

        crate::serial_println!("[HTTP] Connected to {:?}:{}", ip, port);

        // Build HTTP request
        let request = format!(
            "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: NostalgOS/1.0\r\nConnection: close\r\n\r\n",
            path, host
        );

        // Send request
        tcp::socket_send(socket, request.as_bytes())?;
        crate::serial_println!("[HTTP] Request sent ({} bytes)", request.len());

        // Receive response
        let mut response_data = Vec::with_capacity(4096);
        let mut recv_buf = [0u8; 1024];
        polls = 0;

        loop {
            if polls > HTTP_TIMEOUT_POLLS {
                break;
            }

            // Poll network
            crate::drivers::virtio::net::poll();

            // Try to receive data
            match tcp::socket_recv(socket, &mut recv_buf) {
                Ok(n) if n > 0 => {
                    response_data.extend_from_slice(&recv_buf[..n]);
                    polls = 0; // Reset timeout on data received

                    if response_data.len() >= MAX_RESPONSE_SIZE {
                        break;
                    }
                }
                Ok(_) => {
                    // No data available
                    polls += 1;
                    for _ in 0..100 {
                        core::hint::spin_loop();
                    }
                }
                Err(_) => {
                    // Check if connection closed
                    match tcp::socket_state(socket) {
                        Some(tcp::TcpState::CloseWait) |
                        Some(tcp::TcpState::Closed) |
                        None => break,
                        _ => {
                            polls += 1;
                        }
                    }
                }
            }
        }

        // Close socket
        let _ = tcp::socket_close(socket);
        self.socket = None;

        crate::serial_println!("[HTTP] Received {} bytes", response_data.len());

        // Parse response
        parse_http_response(&response_data)
    }
}

impl Drop for HttpClient {
    fn drop(&mut self) {
        if let Some(socket) = self.socket.take() {
            let _ = tcp::socket_close(socket);
        }
    }
}

/// Parse HTTP response
fn parse_http_response(data: &[u8]) -> Result<HttpResponse, &'static str> {
    // Find header/body separator
    let header_end = find_crlf_crlf(data).ok_or("Invalid HTTP response")?;
    let header_data = &data[..header_end];
    let body = data[header_end + 4..].to_vec();

    // Parse status line
    let header_str = core::str::from_utf8(header_data).map_err(|_| "Invalid UTF-8 in headers")?;
    let mut lines = header_str.lines();

    let status_line = lines.next().ok_or("No status line")?;
    let (status_code, status_text) = parse_status_line(status_line)?;

    // Parse headers
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = parse_header_line(line) {
            headers.push((name, value));
        }
    }

    Ok(HttpResponse {
        status_code,
        status_text,
        headers,
        body,
    })
}

/// Find \r\n\r\n in data
fn find_crlf_crlf(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == b'\r' && data[i + 1] == b'\n'
            && data[i + 2] == b'\r' && data[i + 3] == b'\n' {
            return Some(i);
        }
    }
    None
}

/// Parse HTTP status line (e.g., "HTTP/1.1 200 OK")
fn parse_status_line(line: &str) -> Result<(u16, String), &'static str> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err("Invalid status line");
    }

    let code: u16 = parts[1].parse().map_err(|_| "Invalid status code")?;
    let text = if parts.len() >= 3 {
        String::from(parts[2])
    } else {
        String::from("")
    };

    Ok((code, text))
}

/// Parse header line (e.g., "Content-Type: text/html")
fn parse_header_line(line: &str) -> Option<(String, String)> {
    let idx = line.find(':')?;
    let name = String::from(line[..idx].trim());
    let value = String::from(line[idx + 1..].trim());
    Some((name, value))
}

/// Simple synchronous GET request helper
pub fn http_get(
    device_index: usize,
    host: &str,
    ip: Ipv4Address,
    port: u16,
    path: &str,
) -> Result<HttpResponse, &'static str> {
    let mut client = HttpClient::new(device_index);
    client.get(host, ip, port, path)
}

/// Initialize HTTP module
pub fn init() {
    crate::serial_println!("[HTTP] HTTP client initialized");
}

/// String extension for to_ascii_lowercase (no_std friendly)
trait AsciiLowercase {
    fn to_ascii_lowercase(&self) -> String;
}

impl AsciiLowercase for str {
    fn to_ascii_lowercase(&self) -> String {
        self.chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    (c as u8 + 32) as char
                } else {
                    c
                }
            })
            .collect()
    }
}

impl AsciiLowercase for String {
    fn to_ascii_lowercase(&self) -> String {
        self.as_str().to_ascii_lowercase()
    }
}
