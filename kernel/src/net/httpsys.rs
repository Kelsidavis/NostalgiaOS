//! HTTP.sys - Kernel-Mode HTTP Server
//!
//! HTTP.sys provides high-performance kernel-mode HTTP hosting capabilities.
//! It was introduced in Windows Server 2003 and is used by IIS, ASP.NET,
//! and other web services for efficient HTTP request handling.
//!
//! Key features:
//! - URL namespace reservation and registration
//! - Request queue management
//! - Kernel-mode HTTP request parsing
//! - Response caching
//! - SSL/TLS termination
//! - Connection management and keep-alive

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum number of request queues
const MAX_REQUEST_QUEUES: usize = 64;

/// Maximum number of URL reservations
const MAX_URL_RESERVATIONS: usize = 256;

/// Maximum number of pending requests per queue
const MAX_PENDING_REQUESTS: usize = 1000;

/// Maximum URL length
const MAX_URL_LEN: usize = 2048;

/// Maximum header size
const MAX_HEADER_SIZE: usize = 16384;

/// Maximum request body size for buffering
const MAX_BODY_BUFFER_SIZE: usize = 65536;

// ============================================================================
// HTTP Methods
// ============================================================================

/// HTTP request methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HttpMethod {
    /// GET request
    Get = 0,
    /// HEAD request
    Head = 1,
    /// POST request
    Post = 2,
    /// PUT request
    Put = 3,
    /// DELETE request
    Delete = 4,
    /// OPTIONS request
    Options = 5,
    /// TRACE request
    Trace = 6,
    /// CONNECT request
    Connect = 7,
    /// PATCH request
    Patch = 8,
    /// Unknown method
    Unknown = 255,
}

impl From<&str> for HttpMethod {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "HEAD" => HttpMethod::Head,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "DELETE" => HttpMethod::Delete,
            "OPTIONS" => HttpMethod::Options,
            "TRACE" => HttpMethod::Trace,
            "CONNECT" => HttpMethod::Connect,
            "PATCH" => HttpMethod::Patch,
            _ => HttpMethod::Unknown,
        }
    }
}

// ============================================================================
// HTTP Version
// ============================================================================

/// HTTP version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2.0
    Http20,
    /// Unknown version
    Unknown,
}

// ============================================================================
// HTTP Status Codes
// ============================================================================

/// Common HTTP status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HttpStatus {
    /// 200 OK
    Ok = 200,
    /// 201 Created
    Created = 201,
    /// 204 No Content
    NoContent = 204,
    /// 301 Moved Permanently
    MovedPermanently = 301,
    /// 302 Found
    Found = 302,
    /// 304 Not Modified
    NotModified = 304,
    /// 400 Bad Request
    BadRequest = 400,
    /// 401 Unauthorized
    Unauthorized = 401,
    /// 403 Forbidden
    Forbidden = 403,
    /// 404 Not Found
    NotFound = 404,
    /// 405 Method Not Allowed
    MethodNotAllowed = 405,
    /// 500 Internal Server Error
    InternalServerError = 500,
    /// 501 Not Implemented
    NotImplemented = 501,
    /// 502 Bad Gateway
    BadGateway = 502,
    /// 503 Service Unavailable
    ServiceUnavailable = 503,
}

impl HttpStatus {
    /// Get the reason phrase for a status code
    pub fn reason_phrase(&self) -> &'static str {
        match self {
            HttpStatus::Ok => "OK",
            HttpStatus::Created => "Created",
            HttpStatus::NoContent => "No Content",
            HttpStatus::MovedPermanently => "Moved Permanently",
            HttpStatus::Found => "Found",
            HttpStatus::NotModified => "Not Modified",
            HttpStatus::BadRequest => "Bad Request",
            HttpStatus::Unauthorized => "Unauthorized",
            HttpStatus::Forbidden => "Forbidden",
            HttpStatus::NotFound => "Not Found",
            HttpStatus::MethodNotAllowed => "Method Not Allowed",
            HttpStatus::InternalServerError => "Internal Server Error",
            HttpStatus::NotImplemented => "Not Implemented",
            HttpStatus::BadGateway => "Bad Gateway",
            HttpStatus::ServiceUnavailable => "Service Unavailable",
        }
    }
}

// ============================================================================
// HTTP Header
// ============================================================================

/// HTTP header
#[derive(Debug, Clone)]
pub struct HttpHeader {
    /// Header name
    pub name: String,
    /// Header value
    pub value: String,
}

// ============================================================================
// HTTP Request
// ============================================================================

/// HTTP request
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Request ID
    pub id: u64,
    /// Connection ID
    pub connection_id: u64,
    /// HTTP method
    pub method: HttpMethod,
    /// Request URL path
    pub url: String,
    /// Query string
    pub query_string: Option<String>,
    /// HTTP version
    pub version: HttpVersion,
    /// Request headers
    pub headers: Vec<HttpHeader>,
    /// Request body
    pub body: Vec<u8>,
    /// Content length (from header)
    pub content_length: usize,
    /// Host header value
    pub host: Option<String>,
    /// Keep-alive requested
    pub keep_alive: bool,
    /// Client IP address
    pub client_addr: [u8; 4],
    /// Client port
    pub client_port: u16,
    /// Request queue it's assigned to
    pub queue_id: u64,
    /// Timestamp
    pub timestamp: u64,
}

impl Default for HttpRequest {
    fn default() -> Self {
        Self {
            id: 0,
            connection_id: 0,
            method: HttpMethod::Get,
            url: String::new(),
            query_string: None,
            version: HttpVersion::Http11,
            headers: Vec::new(),
            body: Vec::new(),
            content_length: 0,
            host: None,
            keep_alive: true,
            client_addr: [0; 4],
            client_port: 0,
            queue_id: 0,
            timestamp: 0,
        }
    }
}

// ============================================================================
// HTTP Response
// ============================================================================

/// HTTP response
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Request ID this is responding to
    pub request_id: u64,
    /// Status code
    pub status: HttpStatus,
    /// Custom status code (if not standard)
    pub status_code: u16,
    /// Custom reason phrase
    pub reason_phrase: Option<String>,
    /// Response headers
    pub headers: Vec<HttpHeader>,
    /// Response body
    pub body: Vec<u8>,
}

impl Default for HttpResponse {
    fn default() -> Self {
        Self {
            request_id: 0,
            status: HttpStatus::Ok,
            status_code: 200,
            reason_phrase: None,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

// ============================================================================
// URL Reservation
// ============================================================================

/// URL namespace reservation
#[derive(Clone)]
pub struct UrlReservation {
    /// Reservation ID
    pub id: u64,
    /// URL prefix (e.g., "http://+:80/myapp/")
    pub url_prefix: String,
    /// Security descriptor (SDDL string)
    pub security_descriptor: Option<String>,
    /// Owning request queue ID
    pub queue_id: u64,
    /// Active flag
    pub active: bool,
}

impl Default for UrlReservation {
    fn default() -> Self {
        Self {
            id: 0,
            url_prefix: String::new(),
            security_descriptor: None,
            queue_id: 0,
            active: false,
        }
    }
}

// ============================================================================
// Request Queue
// ============================================================================

/// HTTP request queue
pub struct RequestQueue {
    /// Queue ID
    pub id: u64,
    /// Queue name
    pub name: String,
    /// Pending requests
    pub requests: VecDeque<HttpRequest>,
    /// Maximum pending requests
    pub max_requests: usize,
    /// Owning process ID
    pub process_id: u32,
    /// Active flag
    pub active: bool,
    /// Total requests received
    pub requests_received: u64,
    /// Total requests completed
    pub requests_completed: u64,
}

impl Default for RequestQueue {
    fn default() -> Self {
        Self {
            id: 0,
            name: String::new(),
            requests: VecDeque::new(),
            max_requests: MAX_PENDING_REQUESTS,
            process_id: 0,
            active: false,
            requests_received: 0,
            requests_completed: 0,
        }
    }
}

// ============================================================================
// Connection
// ============================================================================

/// HTTP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection established
    Connected,
    /// Receiving request
    ReceivingRequest,
    /// Request complete, waiting for response
    WaitingForResponse,
    /// Sending response
    SendingResponse,
    /// Keep-alive, waiting for next request
    KeepAlive,
    /// Closing
    Closing,
    /// Closed
    Closed,
}

/// HTTP connection
#[derive(Clone)]
pub struct HttpConnection {
    /// Connection ID
    pub id: u64,
    /// Associated socket/AFD handle
    pub socket_id: u64,
    /// Current state
    pub state: ConnectionState,
    /// Client address
    pub client_addr: [u8; 4],
    /// Client port
    pub client_port: u16,
    /// Server port
    pub server_port: u16,
    /// Keep-alive enabled
    pub keep_alive: bool,
    /// Requests on this connection
    pub request_count: u64,
    /// SSL/TLS enabled
    pub is_ssl: bool,
    /// Active flag
    pub active: bool,
}

impl Default for HttpConnection {
    fn default() -> Self {
        Self {
            id: 0,
            socket_id: 0,
            state: ConnectionState::Connected,
            client_addr: [0; 4],
            client_port: 0,
            server_port: 80,
            keep_alive: true,
            request_count: 0,
            is_ssl: false,
            active: false,
        }
    }
}

// ============================================================================
// HTTP.sys Statistics
// ============================================================================

/// HTTP.sys statistics
#[derive(Debug)]
pub struct HttpSysStatistics {
    /// Total connections
    pub connections: AtomicU64,
    /// Active connections
    pub active_connections: AtomicU32,
    /// Total requests
    pub requests: AtomicU64,
    /// Total responses
    pub responses: AtomicU64,
    /// Bytes received
    pub bytes_received: AtomicU64,
    /// Bytes sent
    pub bytes_sent: AtomicU64,
    /// Cache hits
    pub cache_hits: AtomicU64,
    /// Cache misses
    pub cache_misses: AtomicU64,
}

impl Default for HttpSysStatistics {
    fn default() -> Self {
        Self {
            connections: AtomicU64::new(0),
            active_connections: AtomicU32::new(0),
            requests: AtomicU64::new(0),
            responses: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// HTTP.sys Errors
// ============================================================================

/// HTTP.sys error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum HttpSysError {
    /// Success
    Success = 0,
    /// Not initialized
    NotInitialized = -1,
    /// Invalid parameter
    InvalidParameter = -2,
    /// Queue not found
    QueueNotFound = -3,
    /// URL not found
    UrlNotFound = -4,
    /// Too many queues
    TooManyQueues = -5,
    /// Too many URLs
    TooManyUrls = -6,
    /// Queue full
    QueueFull = -7,
    /// No requests
    NoRequests = -8,
    /// URL already registered
    UrlAlreadyRegistered = -9,
    /// Access denied
    AccessDenied = -10,
    /// Invalid handle
    InvalidHandle = -11,
    /// Connection closed
    ConnectionClosed = -12,
    /// Timeout
    Timeout = -13,
}

// ============================================================================
// HTTP.sys State
// ============================================================================

/// Maximum connections
const MAX_CONNECTIONS: usize = 4096;

/// HTTP.sys global state
pub struct HttpSysState {
    /// Request queues
    pub queues: Vec<RequestQueue>,
    /// URL reservations
    pub reservations: Vec<UrlReservation>,
    /// Active connections
    pub connections: [HttpConnection; MAX_CONNECTIONS],
    /// Next queue ID
    pub next_queue_id: u64,
    /// Next reservation ID
    pub next_reservation_id: u64,
    /// Next request ID
    pub next_request_id: u64,
    /// Next connection ID
    pub next_connection_id: u64,
    /// Statistics
    pub statistics: HttpSysStatistics,
    /// Initialized
    pub initialized: bool,
}

const DEFAULT_CONNECTION: HttpConnection = HttpConnection {
    id: 0,
    socket_id: 0,
    state: ConnectionState::Closed,
    client_addr: [0; 4],
    client_port: 0,
    server_port: 80,
    keep_alive: true,
    request_count: 0,
    is_ssl: false,
    active: false,
};

const DEFAULT_HTTPSYS_STATE: HttpSysState = HttpSysState {
    queues: Vec::new(),
    reservations: Vec::new(),
    connections: [DEFAULT_CONNECTION; MAX_CONNECTIONS],
    next_queue_id: 1,
    next_reservation_id: 1,
    next_request_id: 1,
    next_connection_id: 1,
    statistics: HttpSysStatistics {
        connections: AtomicU64::new(0),
        active_connections: AtomicU32::new(0),
        requests: AtomicU64::new(0),
        responses: AtomicU64::new(0),
        bytes_received: AtomicU64::new(0),
        bytes_sent: AtomicU64::new(0),
        cache_hits: AtomicU64::new(0),
        cache_misses: AtomicU64::new(0),
    },
    initialized: false,
};

/// Global HTTP.sys state
static HTTPSYS_STATE: SpinLock<HttpSysState> = SpinLock::new(DEFAULT_HTTPSYS_STATE);

// ============================================================================
// Request Queue Operations
// ============================================================================

/// Create a request queue
pub fn http_create_request_queue(
    name: &str,
    process_id: u32,
) -> Result<u64, HttpSysError> {
    let mut state = HTTPSYS_STATE.lock();

    if !state.initialized {
        return Err(HttpSysError::NotInitialized);
    }

    if state.queues.len() >= MAX_REQUEST_QUEUES {
        return Err(HttpSysError::TooManyQueues);
    }

    let queue_id = state.next_queue_id;
    state.next_queue_id += 1;

    let queue = RequestQueue {
        id: queue_id,
        name: String::from(name),
        requests: VecDeque::new(),
        max_requests: MAX_PENDING_REQUESTS,
        process_id,
        active: true,
        requests_received: 0,
        requests_completed: 0,
    };

    state.queues.push(queue);

    crate::serial_println!("[HTTP.sys] Created request queue '{}' (id={})", name, queue_id);

    Ok(queue_id)
}

/// Close a request queue
pub fn http_close_request_queue(queue_id: u64) -> Result<(), HttpSysError> {
    let mut state = HTTPSYS_STATE.lock();

    if !state.initialized {
        return Err(HttpSysError::NotInitialized);
    }

    let mut found = false;
    state.queues.retain(|q| {
        if q.id == queue_id {
            found = true;
            false
        } else {
            true
        }
    });

    if found {
        crate::serial_println!("[HTTP.sys] Closed request queue {}", queue_id);
        Ok(())
    } else {
        Err(HttpSysError::QueueNotFound)
    }
}

/// Receive a request from a queue
pub fn http_receive_request(
    queue_id: u64,
    timeout_ms: u32,
) -> Result<HttpRequest, HttpSysError> {
    let mut state = HTTPSYS_STATE.lock();

    if !state.initialized {
        return Err(HttpSysError::NotInitialized);
    }

    for queue in state.queues.iter_mut() {
        if queue.id == queue_id && queue.active {
            if let Some(request) = queue.requests.pop_front() {
                return Ok(request);
            }

            if timeout_ms == 0 {
                return Err(HttpSysError::NoRequests);
            }

            // Would block/wait in real implementation
            return Err(HttpSysError::Timeout);
        }
    }

    Err(HttpSysError::QueueNotFound)
}

/// Send a response
pub fn http_send_response(
    queue_id: u64,
    response: &HttpResponse,
) -> Result<(), HttpSysError> {
    let mut state = HTTPSYS_STATE.lock();

    if !state.initialized {
        return Err(HttpSysError::NotInitialized);
    }

    // Find the queue
    let mut found = false;
    for queue in state.queues.iter_mut() {
        if queue.id == queue_id && queue.active {
            queue.requests_completed += 1;
            found = true;
            break;
        }
    }

    if !found {
        return Err(HttpSysError::QueueNotFound);
    }

    // Build response bytes
    let response_bytes = build_http_response(response);
    state.statistics.bytes_sent.fetch_add(response_bytes.len() as u64, Ordering::Relaxed);
    state.statistics.responses.fetch_add(1, Ordering::Relaxed);

    // TODO: Actually send via socket

    Ok(())
}

/// Build HTTP response bytes
fn build_http_response(response: &HttpResponse) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Status line
    let reason = response.reason_phrase.as_ref()
        .map(|s| s.as_str())
        .unwrap_or(response.status.reason_phrase());

    let status_line = alloc::format!("HTTP/1.1 {} {}\r\n", response.status_code, reason);
    bytes.extend_from_slice(status_line.as_bytes());

    // Headers
    for header in &response.headers {
        let header_line = alloc::format!("{}: {}\r\n", header.name, header.value);
        bytes.extend_from_slice(header_line.as_bytes());
    }

    // Content-Length if body present
    if !response.body.is_empty() {
        let cl_header = alloc::format!("Content-Length: {}\r\n", response.body.len());
        bytes.extend_from_slice(cl_header.as_bytes());
    }

    // End of headers
    bytes.extend_from_slice(b"\r\n");

    // Body
    bytes.extend_from_slice(&response.body);

    bytes
}

// ============================================================================
// URL Reservation Operations
// ============================================================================

/// Add a URL reservation
pub fn http_add_url(
    queue_id: u64,
    url_prefix: &str,
) -> Result<u64, HttpSysError> {
    let mut state = HTTPSYS_STATE.lock();

    if !state.initialized {
        return Err(HttpSysError::NotInitialized);
    }

    // Check if URL already registered
    for res in &state.reservations {
        if res.active && res.url_prefix == url_prefix {
            return Err(HttpSysError::UrlAlreadyRegistered);
        }
    }

    if state.reservations.len() >= MAX_URL_RESERVATIONS {
        return Err(HttpSysError::TooManyUrls);
    }

    // Verify queue exists
    let queue_exists = state.queues.iter().any(|q| q.id == queue_id && q.active);
    if !queue_exists {
        return Err(HttpSysError::QueueNotFound);
    }

    let reservation_id = state.next_reservation_id;
    state.next_reservation_id += 1;

    let reservation = UrlReservation {
        id: reservation_id,
        url_prefix: String::from(url_prefix),
        security_descriptor: None,
        queue_id,
        active: true,
    };

    state.reservations.push(reservation);

    crate::serial_println!("[HTTP.sys] Added URL '{}' to queue {}", url_prefix, queue_id);

    Ok(reservation_id)
}

/// Remove a URL reservation
pub fn http_remove_url(
    queue_id: u64,
    url_prefix: &str,
) -> Result<(), HttpSysError> {
    let mut state = HTTPSYS_STATE.lock();

    if !state.initialized {
        return Err(HttpSysError::NotInitialized);
    }

    let mut found = false;
    state.reservations.retain(|r| {
        if r.active && r.queue_id == queue_id && r.url_prefix == url_prefix {
            found = true;
            false
        } else {
            true
        }
    });

    if found {
        crate::serial_println!("[HTTP.sys] Removed URL '{}'", url_prefix);
        Ok(())
    } else {
        Err(HttpSysError::UrlNotFound)
    }
}

// ============================================================================
// Request Delivery
// ============================================================================

/// Deliver an incoming HTTP request to the appropriate queue
pub fn http_deliver_request(request: HttpRequest) -> Result<(), HttpSysError> {
    let mut state = HTTPSYS_STATE.lock();

    if !state.initialized {
        return Err(HttpSysError::NotInitialized);
    }

    // Find matching URL reservation
    let mut target_queue_id = None;

    for res in &state.reservations {
        if res.active && matches_url_prefix(&request.url, &res.url_prefix) {
            target_queue_id = Some(res.queue_id);
            break;
        }
    }

    let queue_id = target_queue_id.ok_or(HttpSysError::UrlNotFound)?;

    // Find the queue index
    let mut queue_idx = None;
    for idx in 0..state.queues.len() {
        if state.queues[idx].id == queue_id && state.queues[idx].active {
            queue_idx = Some(idx);
            break;
        }
    }

    let idx = queue_idx.ok_or(HttpSysError::QueueNotFound)?;

    // Check capacity
    if state.queues[idx].requests.len() >= state.queues[idx].max_requests {
        return Err(HttpSysError::QueueFull);
    }

    // Get request ID before modifying queue
    let request_id = state.next_request_id;
    state.next_request_id += 1;

    // Create the modified request
    let mut req = request;
    req.id = request_id;
    req.queue_id = queue_id;

    // Add to queue
    state.queues[idx].requests.push_back(req);
    state.queues[idx].requests_received += 1;

    state.statistics.requests.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Check if URL matches a URL prefix
fn matches_url_prefix(url: &str, prefix: &str) -> bool {
    // Simple prefix matching
    // Real implementation would handle wildcards (+, *), ports, etc.
    url.starts_with(prefix) || prefix == "*" || prefix.ends_with("*")
}

// ============================================================================
// Connection Management
// ============================================================================

/// Register a new connection
pub fn http_new_connection(
    socket_id: u64,
    client_addr: [u8; 4],
    client_port: u16,
    server_port: u16,
    is_ssl: bool,
) -> Result<u64, HttpSysError> {
    let mut state = HTTPSYS_STATE.lock();

    if !state.initialized {
        return Err(HttpSysError::NotInitialized);
    }

    // Find free connection slot
    let mut slot_idx = None;
    for idx in 0..MAX_CONNECTIONS {
        if !state.connections[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(HttpSysError::TooManyQueues)?;

    let conn_id = state.next_connection_id;
    state.next_connection_id += 1;

    state.connections[idx] = HttpConnection {
        id: conn_id,
        socket_id,
        state: ConnectionState::Connected,
        client_addr,
        client_port,
        server_port,
        keep_alive: true,
        request_count: 0,
        is_ssl,
        active: true,
    };

    state.statistics.connections.fetch_add(1, Ordering::Relaxed);
    state.statistics.active_connections.fetch_add(1, Ordering::Relaxed);

    Ok(conn_id)
}

/// Close a connection
pub fn http_close_connection(connection_id: u64) -> Result<(), HttpSysError> {
    let mut state = HTTPSYS_STATE.lock();

    if !state.initialized {
        return Err(HttpSysError::NotInitialized);
    }

    for idx in 0..MAX_CONNECTIONS {
        if state.connections[idx].active && state.connections[idx].id == connection_id {
            state.connections[idx].state = ConnectionState::Closed;
            state.connections[idx].active = false;
            state.statistics.active_connections.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    Err(HttpSysError::InvalidHandle)
}

// ============================================================================
// HTTP Request Parsing
// ============================================================================

/// Parse an HTTP request from raw bytes
pub fn http_parse_request(
    data: &[u8],
    client_addr: [u8; 4],
    client_port: u16,
) -> Result<HttpRequest, HttpSysError> {
    // Find end of headers
    let header_end = find_header_end(data).ok_or(HttpSysError::InvalidParameter)?;

    // Parse request line
    let header_data = &data[..header_end];
    let header_str = core::str::from_utf8(header_data)
        .map_err(|_| HttpSysError::InvalidParameter)?;

    let mut lines = header_str.lines();

    // First line is request line
    let request_line = lines.next().ok_or(HttpSysError::InvalidParameter)?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();

    if parts.len() < 3 {
        return Err(HttpSysError::InvalidParameter);
    }

    let method = HttpMethod::from(parts[0]);
    let url_part = parts[1];
    let version = match parts[2] {
        "HTTP/1.0" => HttpVersion::Http10,
        "HTTP/1.1" => HttpVersion::Http11,
        "HTTP/2.0" => HttpVersion::Http20,
        _ => HttpVersion::Unknown,
    };

    // Parse URL and query string
    let (url, query_string) = if let Some(pos) = url_part.find('?') {
        (String::from(&url_part[..pos]), Some(String::from(&url_part[pos + 1..])))
    } else {
        (String::from(url_part), None)
    };

    // Parse headers
    let mut headers = Vec::new();
    let mut host = None;
    let mut content_length = 0;
    let mut keep_alive = version == HttpVersion::Http11;

    for line in lines {
        if line.is_empty() {
            break;
        }

        if let Some(pos) = line.find(':') {
            let name = line[..pos].trim();
            let value = line[pos + 1..].trim();

            // Check for special headers
            match name.to_lowercase().as_str() {
                "host" => host = Some(String::from(value)),
                "content-length" => {
                    content_length = value.parse().unwrap_or(0);
                }
                "connection" => {
                    keep_alive = value.to_lowercase() != "close";
                }
                _ => {}
            }

            headers.push(HttpHeader {
                name: String::from(name),
                value: String::from(value),
            });
        }
    }

    // Extract body (if present)
    let body = if header_end + 4 < data.len() && content_length > 0 {
        let body_start = header_end + 4;
        let body_end = core::cmp::min(body_start + content_length, data.len());
        data[body_start..body_end].to_vec()
    } else {
        Vec::new()
    };

    Ok(HttpRequest {
        id: 0,
        connection_id: 0,
        method,
        url,
        query_string,
        version,
        headers,
        body,
        content_length,
        host,
        keep_alive,
        client_addr,
        client_port,
        queue_id: 0,
        timestamp: 0,
    })
}

/// Find the end of HTTP headers (double CRLF)
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == b'\r' && data[i + 1] == b'\n' &&
           data[i + 2] == b'\r' && data[i + 3] == b'\n' {
            return Some(i);
        }
    }
    None
}

// ============================================================================
// Statistics
// ============================================================================

/// Get HTTP.sys statistics
pub fn http_get_statistics() -> HttpSysStatistics {
    let state = HTTPSYS_STATE.lock();

    HttpSysStatistics {
        connections: AtomicU64::new(state.statistics.connections.load(Ordering::Relaxed)),
        active_connections: AtomicU32::new(state.statistics.active_connections.load(Ordering::Relaxed)),
        requests: AtomicU64::new(state.statistics.requests.load(Ordering::Relaxed)),
        responses: AtomicU64::new(state.statistics.responses.load(Ordering::Relaxed)),
        bytes_received: AtomicU64::new(state.statistics.bytes_received.load(Ordering::Relaxed)),
        bytes_sent: AtomicU64::new(state.statistics.bytes_sent.load(Ordering::Relaxed)),
        cache_hits: AtomicU64::new(state.statistics.cache_hits.load(Ordering::Relaxed)),
        cache_misses: AtomicU64::new(state.statistics.cache_misses.load(Ordering::Relaxed)),
    }
}

/// List URL reservations
pub fn http_list_urls() -> Vec<(String, u64)> {
    let state = HTTPSYS_STATE.lock();
    let mut result = Vec::new();

    for res in &state.reservations {
        if res.active {
            result.push((res.url_prefix.clone(), res.queue_id));
        }
    }

    result
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize HTTP.sys
pub fn init() {
    crate::serial_println!("[HTTP.sys] Initializing kernel-mode HTTP server...");

    {
        let mut state = HTTPSYS_STATE.lock();
        state.initialized = true;
    }

    crate::serial_println!("[HTTP.sys] HTTP.sys initialized");
}
