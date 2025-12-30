//! HTTP Server (httpd)
//!
//! Simple HTTP/1.0 server for system status and management.
//! Provides a web interface to NostalgOS.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use core::sync::atomic::{AtomicBool, AtomicUsize, AtomicU64, Ordering};
use crate::ke::SpinLock;
use super::tcp::{self, TcpSocket, TcpState};
use super::ip::Ipv4Address;

/// HTTP server default port
pub const HTTP_PORT: u16 = 80;

/// Maximum concurrent connections
pub const MAX_HTTP_CONNECTIONS: usize = 8;

/// Request buffer size
pub const REQUEST_BUFFER_SIZE: usize = 2048;

/// Response buffer size
pub const RESPONSE_BUFFER_SIZE: usize = 8192;

/// HTTP methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Unknown,
}

/// HTTP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Closed,
    Reading,
    Processing,
    Writing,
}

/// HTTP connection
struct HttpConnection {
    state: ConnectionState,
    socket: Option<TcpSocket>,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    response_pos: usize,
    remote_ip: Ipv4Address,
    remote_port: u16,
}

impl HttpConnection {
    const fn new() -> Self {
        Self {
            state: ConnectionState::Closed,
            socket: None,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
            response_pos: 0,
            remote_ip: Ipv4Address::new([0, 0, 0, 0]),
            remote_port: 0,
        }
    }

    fn reset(&mut self) {
        self.state = ConnectionState::Closed;
        self.socket = None;
        self.request_buffer.clear();
        self.response_buffer.clear();
        self.response_pos = 0;
        self.remote_ip = Ipv4Address::new([0, 0, 0, 0]);
        self.remote_port = 0;
    }
}

/// Global HTTP server state
static mut HTTP_CONNECTIONS: [HttpConnection; MAX_HTTP_CONNECTIONS] = [
    HttpConnection::new(), HttpConnection::new(),
    HttpConnection::new(), HttpConnection::new(),
    HttpConnection::new(), HttpConnection::new(),
    HttpConnection::new(), HttpConnection::new(),
];

static HTTPD_INITIALIZED: AtomicBool = AtomicBool::new(false);
static HTTPD_RUNNING: AtomicBool = AtomicBool::new(false);
static HTTPD_LISTEN_SOCKET: AtomicUsize = AtomicUsize::new(usize::MAX);
static HTTPD_DEVICE_INDEX: AtomicUsize = AtomicUsize::new(0);
static HTTPD_PORT: AtomicUsize = AtomicUsize::new(80);
static HTTPD_LOCK: SpinLock<()> = SpinLock::new(());

/// Statistics
static REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REQUESTS_SUCCESS: AtomicU64 = AtomicU64::new(0);
static REQUESTS_ERROR: AtomicU64 = AtomicU64::new(0);
static BYTES_SENT: AtomicU64 = AtomicU64::new(0);

/// Initialize HTTP server
pub fn init() {
    unsafe {
        for conn in HTTP_CONNECTIONS.iter_mut() {
            conn.request_buffer = Vec::with_capacity(REQUEST_BUFFER_SIZE);
            conn.response_buffer = Vec::with_capacity(RESPONSE_BUFFER_SIZE);
        }
    }
    HTTPD_INITIALIZED.store(true, Ordering::SeqCst);
    crate::serial_println!("[HTTPD] HTTP server initialized");
}

/// Start HTTP server
pub fn start_server(device_index: usize, port: u16) -> Result<(), &'static str> {
    if !HTTPD_INITIALIZED.load(Ordering::SeqCst) {
        return Err("HTTP server not initialized");
    }

    if HTTPD_RUNNING.load(Ordering::SeqCst) {
        return Err("Server already running");
    }

    // Create listening socket
    let socket = tcp::socket_create().ok_or("Failed to create socket")?;
    tcp::socket_bind(socket, port)?;
    tcp::socket_listen(socket, MAX_HTTP_CONNECTIONS)?;

    HTTPD_LISTEN_SOCKET.store(socket, Ordering::SeqCst);
    HTTPD_DEVICE_INDEX.store(device_index, Ordering::SeqCst);
    HTTPD_PORT.store(port as usize, Ordering::SeqCst);
    HTTPD_RUNNING.store(true, Ordering::SeqCst);

    crate::serial_println!("[HTTPD] Server started on port {}", port);
    Ok(())
}

/// Stop HTTP server
pub fn stop_server() -> Result<(), &'static str> {
    if !HTTPD_RUNNING.load(Ordering::SeqCst) {
        return Err("Server not running");
    }

    // Close listen socket
    let socket = HTTPD_LISTEN_SOCKET.load(Ordering::SeqCst);
    if socket != usize::MAX {
        let _ = tcp::socket_close(socket);
    }

    // Close all connections
    let _guard = HTTPD_LOCK.lock();
    unsafe {
        for conn in HTTP_CONNECTIONS.iter_mut() {
            if conn.state != ConnectionState::Closed {
                if let Some(sock) = conn.socket {
                    let _ = tcp::socket_close(sock);
                }
                conn.reset();
            }
        }
    }

    HTTPD_LISTEN_SOCKET.store(usize::MAX, Ordering::SeqCst);
    HTTPD_RUNNING.store(false, Ordering::SeqCst);

    crate::serial_println!("[HTTPD] Server stopped");
    Ok(())
}

/// Poll HTTP server
pub fn poll() {
    if !HTTPD_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    // Poll network
    crate::drivers::virtio::net::poll();

    let _guard = HTTPD_LOCK.lock();

    // Check for new connections
    check_new_connections();

    // Process existing connections
    unsafe {
        for i in 0..MAX_HTTP_CONNECTIONS {
            if HTTP_CONNECTIONS[i].state != ConnectionState::Closed {
                process_connection(i);
            }
        }
    }
}

/// Check for new connections
fn check_new_connections() {
    let listen_socket = HTTPD_LISTEN_SOCKET.load(Ordering::SeqCst);
    if listen_socket == usize::MAX {
        return;
    }

    if let Some(state) = tcp::socket_state(listen_socket) {
        if state == TcpState::Established {
            // Find free connection slot
            unsafe {
                for i in 0..MAX_HTTP_CONNECTIONS {
                    if HTTP_CONNECTIONS[i].state == ConnectionState::Closed {
                        accept_connection(i, listen_socket);

                        // Create new listen socket
                        if let Some(new_socket) = tcp::socket_create() {
                            let port = HTTPD_PORT.load(Ordering::SeqCst) as u16;
                            if tcp::socket_bind(new_socket, port).is_ok() {
                                if tcp::socket_listen(new_socket, MAX_HTTP_CONNECTIONS).is_ok() {
                                    HTTPD_LISTEN_SOCKET.store(new_socket, Ordering::SeqCst);
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
fn accept_connection(conn_idx: usize, socket: TcpSocket) {
    unsafe {
        let conn = &mut HTTP_CONNECTIONS[conn_idx];

        if let Some((_, _, remote_port, remote_ip, _, _)) = tcp::get_socket_info(socket) {
            conn.socket = Some(socket);
            conn.remote_ip = remote_ip;
            conn.remote_port = remote_port;
            conn.state = ConnectionState::Reading;
            conn.request_buffer.clear();
            conn.response_buffer.clear();
            conn.response_pos = 0;

            crate::serial_println!("[HTTPD] Connection {} from {:?}:{}", conn_idx, remote_ip, remote_port);
        }
    }
}

/// Process a connection
fn process_connection(conn_idx: usize) {
    unsafe {
        let conn = &mut HTTP_CONNECTIONS[conn_idx];

        let socket = match conn.socket {
            Some(s) => s,
            None => {
                conn.reset();
                return;
            }
        };

        // Check socket state
        match tcp::socket_state(socket) {
            Some(TcpState::Established) | Some(TcpState::CloseWait) => {}
            Some(TcpState::Closed) | None => {
                let _ = tcp::socket_close(socket);
                conn.reset();
                return;
            }
            _ => return,
        }

        match conn.state {
            ConnectionState::Reading => {
                // Read request data
                let mut buf = [0u8; 512];
                match tcp::socket_recv(socket, &mut buf) {
                    Ok(n) if n > 0 => {
                        conn.request_buffer.extend_from_slice(&buf[..n]);

                        // Check if request is complete (ends with \r\n\r\n)
                        if request_complete(&conn.request_buffer) {
                            conn.state = ConnectionState::Processing;
                            process_request(conn_idx);
                        } else if conn.request_buffer.len() > REQUEST_BUFFER_SIZE {
                            // Request too large
                            send_error_response(conn_idx, 413, "Request Entity Too Large");
                        }
                    }
                    _ => {}
                }
            }
            ConnectionState::Processing => {
                // Should not happen, processing is synchronous
                conn.state = ConnectionState::Writing;
            }
            ConnectionState::Writing => {
                // Send response data
                if conn.response_pos < conn.response_buffer.len() {
                    let remaining = &conn.response_buffer[conn.response_pos..];
                    let chunk_size = remaining.len().min(1024);

                    match tcp::socket_send(socket, &remaining[..chunk_size]) {
                        Ok(n) => {
                            conn.response_pos += n;
                            BYTES_SENT.fetch_add(n as u64, Ordering::SeqCst);
                        }
                        Err(_) => {}
                    }
                } else {
                    // Response complete, close connection (HTTP/1.0 style)
                    let _ = tcp::socket_close(socket);
                    conn.reset();
                }
            }
            ConnectionState::Closed => {}
        }
    }
}

/// Check if HTTP request is complete
fn request_complete(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Look for \r\n\r\n
    for i in 0..data.len() - 3 {
        if data[i] == b'\r' && data[i + 1] == b'\n'
            && data[i + 2] == b'\r' && data[i + 3] == b'\n'
        {
            return true;
        }
    }
    false
}

/// Process HTTP request
fn process_request(conn_idx: usize) {
    unsafe {
        let conn = &mut HTTP_CONNECTIONS[conn_idx];

        REQUESTS_TOTAL.fetch_add(1, Ordering::SeqCst);

        // Parse request line
        let request_str = match core::str::from_utf8(&conn.request_buffer) {
            Ok(s) => s,
            Err(_) => {
                send_error_response(conn_idx, 400, "Bad Request");
                return;
            }
        };

        let first_line = request_str.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        if parts.len() < 2 {
            send_error_response(conn_idx, 400, "Bad Request");
            return;
        }

        let method = match parts[0] {
            "GET" => HttpMethod::Get,
            "HEAD" => HttpMethod::Head,
            "POST" => HttpMethod::Post,
            _ => HttpMethod::Unknown,
        };

        let path = parts[1];

        crate::serial_println!("[HTTPD] {} {}", parts[0], path);

        // Route request
        match method {
            HttpMethod::Get | HttpMethod::Head => {
                let (status, content_type, body) = route_get_request(path);

                if method == HttpMethod::Head {
                    send_response(conn_idx, status, content_type, &[]);
                } else {
                    send_response(conn_idx, status, content_type, body.as_bytes());
                }
            }
            HttpMethod::Post => {
                send_error_response(conn_idx, 501, "Not Implemented");
            }
            HttpMethod::Unknown => {
                send_error_response(conn_idx, 405, "Method Not Allowed");
            }
        }
    }
}

/// Route GET request to handler
fn route_get_request(path: &str) -> (u16, &'static str, String) {
    match path {
        "/" | "/index.html" => (200, "text/html", generate_index_page()),
        "/status" | "/status.html" => (200, "text/html", generate_status_page()),
        "/api/status" => (200, "application/json", generate_status_json()),
        "/api/memory" => (200, "application/json", generate_memory_json()),
        "/api/network" => (200, "application/json", generate_network_json()),
        "/api/uptime" => (200, "application/json", generate_uptime_json()),
        "/favicon.ico" => (204, "image/x-icon", String::new()),
        _ => (404, "text/html", generate_404_page(path)),
    }
}

/// Send HTTP response
fn send_response(conn_idx: usize, status: u16, content_type: &str, body: &[u8]) {
    unsafe {
        let conn = &mut HTTP_CONNECTIONS[conn_idx];

        let status_text = match status {
            200 => "OK",
            204 => "No Content",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            413 => "Request Entity Too Large",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            _ => "Unknown",
        };

        // Build response headers
        let headers = format!(
            "HTTP/1.0 {} {}\r\n\
             Server: NostalgOS/1.0\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            status, status_text, content_type, body.len()
        );

        conn.response_buffer.clear();
        conn.response_buffer.extend_from_slice(headers.as_bytes());
        conn.response_buffer.extend_from_slice(body);
        conn.response_pos = 0;
        conn.state = ConnectionState::Writing;

        if status >= 200 && status < 300 {
            REQUESTS_SUCCESS.fetch_add(1, Ordering::SeqCst);
        } else {
            REQUESTS_ERROR.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Send error response
fn send_error_response(conn_idx: usize, status: u16, message: &str) {
    let body = format!(
        "<!DOCTYPE html>\n\
         <html><head><title>{} {}</title></head>\n\
         <body><h1>{} {}</h1></body></html>\n",
        status, message, status, message
    );
    send_response(conn_idx, status, "text/html", body.as_bytes());
}

/// Generate index page
fn generate_index_page() -> String {
    let uptime_secs = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed) / 1000;

    format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>NostalgOS Web Console</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f0f0f0; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }}
        .info {{ background: #e7f3ff; padding: 15px; border-radius: 4px; margin: 15px 0; }}
        a {{ color: #0078d4; }}
        .stats {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }}
        .stat {{ background: #f8f8f8; padding: 10px; border-radius: 4px; }}
        .stat-label {{ color: #666; font-size: 0.9em; }}
        .stat-value {{ font-size: 1.5em; font-weight: bold; color: #333; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>NostalgOS Web Console</h1>
        <div class="info">
            <strong>Windows Server 2003 Recreation</strong><br>
            Kernel: Rust x86_64 | Uptime: {} seconds
        </div>
        <h2>Quick Links</h2>
        <ul>
            <li><a href="/status">System Status</a></li>
            <li><a href="/api/status">Status API (JSON)</a></li>
            <li><a href="/api/memory">Memory API (JSON)</a></li>
            <li><a href="/api/network">Network API (JSON)</a></li>
        </ul>
        <h2>Server Statistics</h2>
        <div class="stats">
            <div class="stat">
                <div class="stat-label">Requests</div>
                <div class="stat-value">{}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Bytes Sent</div>
                <div class="stat-value">{}</div>
            </div>
        </div>
    </div>
</body>
</html>"#,
        uptime_secs,
        REQUESTS_TOTAL.load(Ordering::Relaxed),
        BYTES_SENT.load(Ordering::Relaxed)
    )
}

/// Generate status page
fn generate_status_page() -> String {
    let ticks = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);
    let uptime_secs = ticks / 1000;
    let hours = uptime_secs / 3600;
    let minutes = (uptime_secs % 3600) / 60;
    let seconds = uptime_secs % 60;

    let mem_stats = crate::mm::pfn::mm_get_stats();
    let net_stats = super::get_stats();

    format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>System Status - NostalgOS</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f0f0f0; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #0078d4; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f8f8; }}
        .section {{ margin: 20px 0; }}
    </style>
    <meta http-equiv="refresh" content="5">
</head>
<body>
    <div class="container">
        <h1>System Status</h1>
        <p><a href="/">← Back to Home</a> | Auto-refresh: 5s</p>

        <div class="section">
            <h2>System</h2>
            <table>
                <tr><th>Uptime</th><td>{}h {}m {}s</td></tr>
                <tr><th>Ticks</th><td>{}</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>Memory</h2>
            <table>
                <tr><th>Total Pages</th><td>{}</td></tr>
                <tr><th>Free Pages</th><td>{}</td></tr>
                <tr><th>Used Pages</th><td>{}</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>Network</h2>
            <table>
                <tr><th>Packets Received</th><td>{}</td></tr>
                <tr><th>Packets Transmitted</th><td>{}</td></tr>
                <tr><th>Bytes Received</th><td>{}</td></tr>
                <tr><th>Bytes Transmitted</th><td>{}</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>HTTP Server</h2>
            <table>
                <tr><th>Total Requests</th><td>{}</td></tr>
                <tr><th>Successful</th><td>{}</td></tr>
                <tr><th>Errors</th><td>{}</td></tr>
                <tr><th>Bytes Sent</th><td>{}</td></tr>
            </table>
        </div>
    </div>
</body>
</html>"#,
        hours, minutes, seconds, ticks,
        mem_stats.total_pages, mem_stats.free_pages,
        mem_stats.total_pages - mem_stats.free_pages,
        net_stats.packets_received, net_stats.packets_transmitted,
        net_stats.bytes_received, net_stats.bytes_transmitted,
        REQUESTS_TOTAL.load(Ordering::Relaxed),
        REQUESTS_SUCCESS.load(Ordering::Relaxed),
        REQUESTS_ERROR.load(Ordering::Relaxed),
        BYTES_SENT.load(Ordering::Relaxed)
    )
}

/// Generate 404 page
fn generate_404_page(path: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested path <code>{}</code> was not found.</p>
    <p><a href="/">Return to home</a></p>
</body>
</html>"#, path)
}

/// Generate status JSON
fn generate_status_json() -> String {
    let ticks = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);
    let mem_stats = crate::mm::pfn::mm_get_stats();

    format!(r#"{{"uptime_ms":{},"memory":{{"total":{},"free":{},"used":{}}},"requests":{}}}"#,
        ticks,
        mem_stats.total_pages,
        mem_stats.free_pages,
        mem_stats.total_pages - mem_stats.free_pages,
        REQUESTS_TOTAL.load(Ordering::Relaxed)
    )
}

/// Generate memory JSON
fn generate_memory_json() -> String {
    let stats = crate::mm::pfn::mm_get_stats();
    format!(r#"{{"total_pages":{},"free_pages":{},"used_pages":{}}}"#,
        stats.total_pages,
        stats.free_pages,
        stats.total_pages - stats.free_pages
    )
}

/// Generate network JSON
fn generate_network_json() -> String {
    let stats = super::get_stats();
    format!(r#"{{"rx_packets":{},"tx_packets":{},"rx_bytes":{},"tx_bytes":{},"rx_errors":{},"tx_errors":{}}}"#,
        stats.packets_received,
        stats.packets_transmitted,
        stats.bytes_received,
        stats.bytes_transmitted,
        stats.receive_errors,
        stats.transmit_errors
    )
}

/// Generate uptime JSON
fn generate_uptime_json() -> String {
    let ticks = crate::hal::apic::TICK_COUNT.load(Ordering::Relaxed);
    format!(r#"{{"ticks":{},"seconds":{}}}"#, ticks, ticks / 1000)
}

/// Get server status
pub fn get_status() -> (bool, u16, u64, u64) {
    let running = HTTPD_RUNNING.load(Ordering::SeqCst);
    let port = HTTPD_PORT.load(Ordering::SeqCst) as u16;
    let requests = REQUESTS_TOTAL.load(Ordering::Relaxed);
    let bytes = BYTES_SENT.load(Ordering::Relaxed);
    (running, port, requests, bytes)
}

/// Get active connection count
pub fn get_connection_count() -> usize {
    let _guard = HTTPD_LOCK.lock();
    let mut count = 0;
    unsafe {
        for conn in HTTP_CONNECTIONS.iter() {
            if conn.state != ConnectionState::Closed {
                count += 1;
            }
        }
    }
    count
}
