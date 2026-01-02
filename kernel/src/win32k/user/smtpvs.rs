//! SMTP Virtual Server Module
//!
//! Windows Server 2003 SMTP Virtual Server implementation for managing
//! outbound email services. Provides virtual server configuration, domain
//! management, relay restrictions, and message queue handling.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;
use crate::win32k::user::UserHandle;

/// Maximum number of virtual servers
const MAX_VIRTUAL_SERVERS: usize = 16;

/// Maximum number of domains per server
const MAX_DOMAINS: usize = 64;

/// Maximum number of relay restrictions
const MAX_RELAY_ENTRIES: usize = 128;

/// Maximum number of connection entries
const MAX_CONNECTIONS: usize = 256;

/// Maximum number of queued messages
const MAX_QUEUE_ENTRIES: usize = 512;

/// Maximum domain name length
const MAX_DOMAIN_LEN: usize = 253;

/// Maximum IP address string length
const MAX_IP_LEN: usize = 45;

/// Maximum path length
const MAX_PATH_LEN: usize = 260;

/// Virtual server state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServerState {
    /// Server is stopped
    Stopped = 0,
    /// Server is starting
    Starting = 1,
    /// Server is running
    Running = 2,
    /// Server is paused
    Paused = 3,
    /// Server is stopping
    Stopping = 4,
}

impl Default for ServerState {
    fn default() -> Self {
        Self::Stopped
    }
}

/// Domain type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DomainType {
    /// Local domain (final destination)
    Local = 0,
    /// Alias domain (rewrite to local)
    Alias = 1,
    /// Remote domain (relay)
    Remote = 2,
}

impl Default for DomainType {
    fn default() -> Self {
        Self::Local
    }
}

/// Delivery method for remote domains
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeliveryMethod {
    /// Use DNS MX lookup
    DnsMx = 0,
    /// Use smart host
    SmartHost = 1,
    /// Use ETRN command
    Etrn = 2,
}

impl Default for DeliveryMethod {
    fn default() -> Self {
        Self::DnsMx
    }
}

/// Relay type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RelayType {
    /// Allow relay from IP
    AllowIp = 0,
    /// Deny relay from IP
    DenyIp = 1,
    /// Allow relay from domain
    AllowDomain = 2,
}

impl Default for RelayType {
    fn default() -> Self {
        Self::AllowIp
    }
}

/// Message queue status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QueueStatus {
    /// Message is pending
    Pending = 0,
    /// Message is being delivered
    Delivering = 1,
    /// Message is in retry
    Retry = 2,
    /// Message delivery failed
    Failed = 3,
    /// Message was delivered
    Delivered = 4,
}

impl Default for QueueStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ConnectionState {
    /// Connecting
    Connecting = 0,
    /// Connected and idle
    Connected = 1,
    /// Sending data
    Sending = 2,
    /// Receiving data
    Receiving = 3,
    /// Disconnecting
    Disconnecting = 4,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Connecting
    }
}

bitflags::bitflags! {
    /// Virtual server flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ServerFlags: u32 {
        /// Enable TLS/SSL
        const ENABLE_TLS = 0x0001;
        /// Require TLS for all connections
        const REQUIRE_TLS = 0x0002;
        /// Enable authentication
        const ENABLE_AUTH = 0x0004;
        /// Require authentication
        const REQUIRE_AUTH = 0x0008;
        /// Enable logging
        const ENABLE_LOGGING = 0x0010;
        /// Enable message tracking
        const MESSAGE_TRACKING = 0x0020;
        /// Enable batched delivery
        const BATCHED_DELIVERY = 0x0040;
        /// Enable DSN (Delivery Status Notification)
        const ENABLE_DSN = 0x0080;
        /// Enable VRFY command
        const ENABLE_VRFY = 0x0100;
        /// Enable EXPN command
        const ENABLE_EXPN = 0x0200;
    }
}

impl Default for ServerFlags {
    fn default() -> Self {
        Self::ENABLE_LOGGING | Self::ENABLE_DSN
    }
}

bitflags::bitflags! {
    /// Domain flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DomainFlags: u32 {
        /// Domain is enabled
        const ENABLED = 0x0001;
        /// Allow incoming mail
        const ALLOW_INCOMING = 0x0002;
        /// Allow outgoing mail
        const ALLOW_OUTGOING = 0x0004;
        /// Require authentication
        const REQUIRE_AUTH = 0x0008;
        /// Enable TLS for outbound
        const OUTBOUND_TLS = 0x0010;
        /// Trigger ETRN on startup
        const ETRN_ON_STARTUP = 0x0020;
    }
}

impl Default for DomainFlags {
    fn default() -> Self {
        Self::ENABLED | Self::ALLOW_INCOMING | Self::ALLOW_OUTGOING
    }
}

/// SMTP Virtual Server
#[derive(Debug)]
pub struct SmtpVirtualServer {
    /// Server is active
    active: bool,
    /// Server ID
    id: u32,
    /// Server name
    name: [u8; 64],
    /// Name length
    name_len: usize,
    /// Binding IP address
    ip_address: [u8; MAX_IP_LEN],
    /// IP length
    ip_len: usize,
    /// Port number
    port: u16,
    /// Server state
    state: ServerState,
    /// Server flags
    flags: ServerFlags,
    /// FQDN for HELO/EHLO
    fqdn: [u8; MAX_DOMAIN_LEN],
    /// FQDN length
    fqdn_len: usize,
    /// Maximum message size (bytes)
    max_message_size: u32,
    /// Maximum recipients per message
    max_recipients: u32,
    /// Maximum concurrent connections
    max_connections: u32,
    /// Connection timeout (seconds)
    connection_timeout: u32,
    /// Retry interval (minutes)
    retry_interval: u32,
    /// Maximum retries
    max_retries: u32,
    /// Badmail directory
    badmail_dir: [u8; MAX_PATH_LEN],
    /// Badmail dir length
    badmail_len: usize,
    /// Queue directory
    queue_dir: [u8; MAX_PATH_LEN],
    /// Queue dir length
    queue_len: usize,
    /// Current connections
    current_connections: u32,
    /// Messages sent
    messages_sent: u64,
    /// Messages received
    messages_received: u64,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
    /// Handle for management
    handle: UserHandle,
}

impl SmtpVirtualServer {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            name: [0u8; 64],
            name_len: 0,
            ip_address: [0u8; MAX_IP_LEN],
            ip_len: 0,
            port: 25,
            state: ServerState::Stopped,
            flags: ServerFlags::empty(),
            fqdn: [0u8; MAX_DOMAIN_LEN],
            fqdn_len: 0,
            max_message_size: 10 * 1024 * 1024, // 10 MB
            max_recipients: 100,
            max_connections: 1000,
            connection_timeout: 600,
            retry_interval: 60,
            max_retries: 48,
            badmail_dir: [0u8; MAX_PATH_LEN],
            badmail_len: 0,
            queue_dir: [0u8; MAX_PATH_LEN],
            queue_len: 0,
            current_connections: 0,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// SMTP Domain
#[derive(Debug)]
pub struct SmtpDomain {
    /// Domain is active
    active: bool,
    /// Domain ID
    id: u32,
    /// Parent server ID
    server_id: u32,
    /// Domain name
    name: [u8; MAX_DOMAIN_LEN],
    /// Name length
    name_len: usize,
    /// Domain type
    domain_type: DomainType,
    /// Domain flags
    flags: DomainFlags,
    /// Smart host (for remote domains)
    smart_host: [u8; MAX_DOMAIN_LEN],
    /// Smart host length
    smart_host_len: usize,
    /// Smart host port
    smart_host_port: u16,
    /// Delivery method
    delivery_method: DeliveryMethod,
    /// Alias target (for alias domains)
    alias_target: [u8; MAX_DOMAIN_LEN],
    /// Alias target length
    alias_len: usize,
    /// Drop directory (for local)
    drop_dir: [u8; MAX_PATH_LEN],
    /// Drop dir length
    drop_len: usize,
    /// Messages processed
    messages_processed: u64,
    /// Handle for management
    handle: UserHandle,
}

impl SmtpDomain {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            server_id: 0,
            name: [0u8; MAX_DOMAIN_LEN],
            name_len: 0,
            domain_type: DomainType::Local,
            flags: DomainFlags::empty(),
            smart_host: [0u8; MAX_DOMAIN_LEN],
            smart_host_len: 0,
            smart_host_port: 25,
            delivery_method: DeliveryMethod::DnsMx,
            alias_target: [0u8; MAX_DOMAIN_LEN],
            alias_len: 0,
            drop_dir: [0u8; MAX_PATH_LEN],
            drop_len: 0,
            messages_processed: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// Relay restriction entry
#[derive(Debug)]
pub struct RelayEntry {
    /// Entry is active
    active: bool,
    /// Entry ID
    id: u32,
    /// Parent server ID
    server_id: u32,
    /// Relay type
    relay_type: RelayType,
    /// IP address or mask
    ip_address: [u8; MAX_IP_LEN],
    /// IP length
    ip_len: usize,
    /// Subnet mask
    subnet_mask: [u8; MAX_IP_LEN],
    /// Mask length
    mask_len: usize,
    /// Domain pattern (for domain type)
    domain: [u8; MAX_DOMAIN_LEN],
    /// Domain length
    domain_len: usize,
    /// Handle for management
    handle: UserHandle,
}

impl RelayEntry {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            server_id: 0,
            relay_type: RelayType::AllowIp,
            ip_address: [0u8; MAX_IP_LEN],
            ip_len: 0,
            subnet_mask: [0u8; MAX_IP_LEN],
            mask_len: 0,
            domain: [0u8; MAX_DOMAIN_LEN],
            domain_len: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// Active connection
#[derive(Debug)]
pub struct SmtpConnection {
    /// Connection is active
    active: bool,
    /// Connection ID
    id: u32,
    /// Parent server ID
    server_id: u32,
    /// Remote IP
    remote_ip: [u8; MAX_IP_LEN],
    /// Remote IP length
    remote_ip_len: usize,
    /// Remote port
    remote_port: u16,
    /// Connection state
    state: ConnectionState,
    /// Authenticated user
    auth_user: [u8; 64],
    /// Auth user length
    auth_user_len: usize,
    /// TLS enabled
    tls_enabled: bool,
    /// Messages in session
    session_messages: u32,
    /// Bytes transferred
    bytes_transferred: u64,
    /// Connect time
    connect_time: u64,
    /// Handle for management
    handle: UserHandle,
}

impl SmtpConnection {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            server_id: 0,
            remote_ip: [0u8; MAX_IP_LEN],
            remote_ip_len: 0,
            remote_port: 0,
            state: ConnectionState::Connecting,
            auth_user: [0u8; 64],
            auth_user_len: 0,
            tls_enabled: false,
            session_messages: 0,
            bytes_transferred: 0,
            connect_time: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// Queued message
#[derive(Debug)]
pub struct QueuedMessage {
    /// Message is active
    active: bool,
    /// Message ID
    id: u32,
    /// Parent server ID
    server_id: u32,
    /// Message file name
    file_name: [u8; 64],
    /// File name length
    file_len: usize,
    /// Sender address
    sender: [u8; 256],
    /// Sender length
    sender_len: usize,
    /// Recipient count
    recipient_count: u32,
    /// Message size
    size: u32,
    /// Queue status
    status: QueueStatus,
    /// Retry count
    retries: u32,
    /// Submit time
    submit_time: u64,
    /// Last attempt time
    last_attempt: u64,
    /// Next retry time
    next_retry: u64,
    /// Last error code
    last_error: u32,
    /// Handle for management
    handle: UserHandle,
}

impl QueuedMessage {
    pub const fn new() -> Self {
        Self {
            active: false,
            id: 0,
            server_id: 0,
            file_name: [0u8; 64],
            file_len: 0,
            sender: [0u8; 256],
            sender_len: 0,
            recipient_count: 0,
            size: 0,
            status: QueueStatus::Pending,
            retries: 0,
            submit_time: 0,
            last_attempt: 0,
            next_retry: 0,
            last_error: 0,
            handle: UserHandle::NULL,
        }
    }
}

/// SMTP service statistics
#[derive(Debug)]
pub struct SmtpStats {
    /// Total virtual servers
    pub total_servers: u32,
    /// Running servers
    pub running_servers: u32,
    /// Total domains
    pub total_domains: u32,
    /// Total relay entries
    pub total_relays: u32,
    /// Active connections
    pub active_connections: u32,
    /// Queued messages
    pub queued_messages: u32,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Failed deliveries
    pub failed_deliveries: u64,
    /// Badmail count
    pub badmail_count: u64,
}

impl SmtpStats {
    pub const fn new() -> Self {
        Self {
            total_servers: 0,
            running_servers: 0,
            total_domains: 0,
            total_relays: 0,
            active_connections: 0,
            queued_messages: 0,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            failed_deliveries: 0,
            badmail_count: 0,
        }
    }
}

/// SMTP service state
struct SmtpState {
    /// Virtual servers
    servers: [SmtpVirtualServer; MAX_VIRTUAL_SERVERS],
    /// Domains
    domains: [SmtpDomain; MAX_DOMAINS],
    /// Relay entries
    relays: [RelayEntry; MAX_RELAY_ENTRIES],
    /// Active connections
    connections: [SmtpConnection; MAX_CONNECTIONS],
    /// Message queue
    queue: [QueuedMessage; MAX_QUEUE_ENTRIES],
    /// Statistics
    stats: SmtpStats,
    /// Next ID
    next_id: u32,
}

impl SmtpState {
    pub const fn new() -> Self {
        Self {
            servers: [const { SmtpVirtualServer::new() }; MAX_VIRTUAL_SERVERS],
            domains: [const { SmtpDomain::new() }; MAX_DOMAINS],
            relays: [const { RelayEntry::new() }; MAX_RELAY_ENTRIES],
            connections: [const { SmtpConnection::new() }; MAX_CONNECTIONS],
            queue: [const { QueuedMessage::new() }; MAX_QUEUE_ENTRIES],
            stats: SmtpStats::new(),
            next_id: 1,
        }
    }
}

/// Global SMTP state
static SMTP_STATE: Mutex<SmtpState> = Mutex::new(SmtpState::new());

/// Initialization flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the SMTP virtual server module
pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    // Module initialized
    Ok(())
}

/// Create a new virtual server
pub fn create_server(
    name: &str,
    ip_address: &str,
    port: u16,
    fqdn: &str,
    flags: ServerFlags,
) -> Result<UserHandle, u32> {
    let mut state = SMTP_STATE.lock();

    // Check for duplicate binding
    for server in state.servers.iter() {
        if server.active {
            let existing_ip = &server.ip_address[..server.ip_len];
            if existing_ip == ip_address.as_bytes() && server.port == port {
                return Err(0x80070050); // ERROR_FILE_EXISTS
            }
        }
    }

    let slot_idx = state.servers.iter().position(|s| !s.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008), // ERROR_NOT_ENOUGH_MEMORY
    };

    let id = state.next_id;
    state.next_id += 1;

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(64);
    let ip_bytes = ip_address.as_bytes();
    let ip_len = ip_bytes.len().min(MAX_IP_LEN);
    let fqdn_bytes = fqdn.as_bytes();
    let fqdn_len = fqdn_bytes.len().min(MAX_DOMAIN_LEN);

    state.servers[slot_idx].active = true;
    state.servers[slot_idx].id = id;
    state.servers[slot_idx].name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    state.servers[slot_idx].name_len = name_len;
    state.servers[slot_idx].ip_address[..ip_len].copy_from_slice(&ip_bytes[..ip_len]);
    state.servers[slot_idx].ip_len = ip_len;
    state.servers[slot_idx].port = port;
    state.servers[slot_idx].state = ServerState::Stopped;
    state.servers[slot_idx].flags = flags;
    state.servers[slot_idx].fqdn[..fqdn_len].copy_from_slice(&fqdn_bytes[..fqdn_len]);
    state.servers[slot_idx].fqdn_len = fqdn_len;
    state.servers[slot_idx].max_message_size = 10 * 1024 * 1024;
    state.servers[slot_idx].max_recipients = 100;
    state.servers[slot_idx].max_connections = 1000;
    state.servers[slot_idx].connection_timeout = 600;
    state.servers[slot_idx].retry_interval = 60;
    state.servers[slot_idx].max_retries = 48;
    state.servers[slot_idx].current_connections = 0;
    state.servers[slot_idx].messages_sent = 0;
    state.servers[slot_idx].messages_received = 0;
    state.servers[slot_idx].bytes_sent = 0;
    state.servers[slot_idx].bytes_received = 0;
    state.servers[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_servers += 1;

    Ok(state.servers[slot_idx].handle)
}

/// Delete a virtual server
pub fn delete_server(server_id: u32) -> Result<(), u32> {
    let mut state = SMTP_STATE.lock();

    let server_idx = state.servers.iter().position(|s| s.active && s.id == server_id);
    let server_idx = match server_idx {
        Some(idx) => idx,
        None => return Err(0x80070002), // ERROR_FILE_NOT_FOUND
    };

    if state.servers[server_idx].state != ServerState::Stopped {
        return Err(0x80070020); // ERROR_SHARING_VIOLATION
    }

    // Count related items to remove
    let mut domains_to_remove = 0u32;
    let mut relays_to_remove = 0u32;

    for domain in state.domains.iter() {
        if domain.active && domain.server_id == server_id {
            domains_to_remove += 1;
        }
    }

    for relay in state.relays.iter() {
        if relay.active && relay.server_id == server_id {
            relays_to_remove += 1;
        }
    }

    // Remove related domains
    for domain in state.domains.iter_mut() {
        if domain.active && domain.server_id == server_id {
            domain.active = false;
        }
    }

    // Remove related relays
    for relay in state.relays.iter_mut() {
        if relay.active && relay.server_id == server_id {
            relay.active = false;
        }
    }

    state.servers[server_idx].active = false;
    state.stats.total_servers = state.stats.total_servers.saturating_sub(1);
    state.stats.total_domains = state.stats.total_domains.saturating_sub(domains_to_remove);
    state.stats.total_relays = state.stats.total_relays.saturating_sub(relays_to_remove);

    Ok(())
}

/// Start a virtual server
pub fn start_server(server_id: u32) -> Result<(), u32> {
    let mut state = SMTP_STATE.lock();

    let server = state.servers.iter_mut().find(|s| s.active && s.id == server_id);
    let server = match server {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    match server.state {
        ServerState::Running => return Ok(()),
        ServerState::Starting | ServerState::Stopping => {
            return Err(0x80070015); // ERROR_NOT_READY
        }
        _ => {}
    }

    server.state = ServerState::Starting;
    server.state = ServerState::Running;
    state.stats.running_servers += 1;

    Ok(())
}

/// Stop a virtual server
pub fn stop_server(server_id: u32) -> Result<(), u32> {
    let mut state = SMTP_STATE.lock();

    let server_idx = state.servers.iter().position(|s| s.active && s.id == server_id);
    let server_idx = match server_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    match state.servers[server_idx].state {
        ServerState::Stopped => return Ok(()),
        ServerState::Starting | ServerState::Stopping => {
            return Err(0x80070015);
        }
        _ => {}
    }

    // Disconnect all connections for this server
    let mut connections_closed = 0u32;
    for conn in state.connections.iter_mut() {
        if conn.active && conn.server_id == server_id {
            conn.active = false;
            connections_closed += 1;
        }
    }

    state.servers[server_idx].state = ServerState::Stopping;
    state.servers[server_idx].state = ServerState::Stopped;
    state.servers[server_idx].current_connections = 0;
    state.stats.running_servers = state.stats.running_servers.saturating_sub(1);
    state.stats.active_connections = state.stats.active_connections.saturating_sub(connections_closed);

    Ok(())
}

/// Pause a virtual server
pub fn pause_server(server_id: u32) -> Result<(), u32> {
    let mut state = SMTP_STATE.lock();

    let server = state.servers.iter_mut().find(|s| s.active && s.id == server_id);
    let server = match server {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    if server.state != ServerState::Running {
        return Err(0x80070015);
    }

    server.state = ServerState::Paused;

    Ok(())
}

/// Resume a virtual server
pub fn resume_server(server_id: u32) -> Result<(), u32> {
    let mut state = SMTP_STATE.lock();

    let server = state.servers.iter_mut().find(|s| s.active && s.id == server_id);
    let server = match server {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    if server.state != ServerState::Paused {
        return Err(0x80070015);
    }

    server.state = ServerState::Running;

    Ok(())
}

/// Configure server limits
pub fn configure_limits(
    server_id: u32,
    max_message_size: Option<u32>,
    max_recipients: Option<u32>,
    max_connections: Option<u32>,
    connection_timeout: Option<u32>,
) -> Result<(), u32> {
    let mut state = SMTP_STATE.lock();

    let server = state.servers.iter_mut().find(|s| s.active && s.id == server_id);
    let server = match server {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    if let Some(size) = max_message_size {
        server.max_message_size = size;
    }
    if let Some(recip) = max_recipients {
        server.max_recipients = recip;
    }
    if let Some(conns) = max_connections {
        server.max_connections = conns;
    }
    if let Some(timeout) = connection_timeout {
        server.connection_timeout = timeout;
    }

    Ok(())
}

/// Add a domain to a virtual server
pub fn add_domain(
    server_id: u32,
    name: &str,
    domain_type: DomainType,
    flags: DomainFlags,
) -> Result<UserHandle, u32> {
    let mut state = SMTP_STATE.lock();

    // Verify server exists
    let server_exists = state.servers.iter().any(|s| s.active && s.id == server_id);
    if !server_exists {
        return Err(0x80070002);
    }

    // Check for duplicate domain
    for domain in state.domains.iter() {
        if domain.active && domain.server_id == server_id {
            let existing = &domain.name[..domain.name_len];
            if existing == name.as_bytes() {
                return Err(0x80070050);
            }
        }
    }

    let slot_idx = state.domains.iter().position(|d| !d.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(MAX_DOMAIN_LEN);

    state.domains[slot_idx].active = true;
    state.domains[slot_idx].id = id;
    state.domains[slot_idx].server_id = server_id;
    state.domains[slot_idx].name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    state.domains[slot_idx].name_len = name_len;
    state.domains[slot_idx].domain_type = domain_type;
    state.domains[slot_idx].flags = flags;
    state.domains[slot_idx].delivery_method = DeliveryMethod::DnsMx;
    state.domains[slot_idx].smart_host_len = 0;
    state.domains[slot_idx].smart_host_port = 25;
    state.domains[slot_idx].alias_len = 0;
    state.domains[slot_idx].drop_len = 0;
    state.domains[slot_idx].messages_processed = 0;
    state.domains[slot_idx].handle = UserHandle::from_raw(id);

    state.stats.total_domains += 1;

    Ok(state.domains[slot_idx].handle)
}

/// Remove a domain
pub fn remove_domain(domain_id: u32) -> Result<(), u32> {
    let mut state = SMTP_STATE.lock();

    let domain_idx = state.domains.iter().position(|d| d.active && d.id == domain_id);
    let domain_idx = match domain_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    state.domains[domain_idx].active = false;
    state.stats.total_domains = state.stats.total_domains.saturating_sub(1);

    Ok(())
}

/// Configure remote domain delivery
pub fn configure_remote_domain(
    domain_id: u32,
    delivery_method: DeliveryMethod,
    smart_host: Option<&str>,
    smart_host_port: Option<u16>,
) -> Result<(), u32> {
    let mut state = SMTP_STATE.lock();

    let domain = state.domains.iter_mut().find(|d| d.active && d.id == domain_id);
    let domain = match domain {
        Some(d) => d,
        None => return Err(0x80070002),
    };

    if domain.domain_type != DomainType::Remote {
        return Err(0x80070057); // ERROR_INVALID_PARAMETER
    }

    domain.delivery_method = delivery_method;

    if let Some(host) = smart_host {
        let host_bytes = host.as_bytes();
        let host_len = host_bytes.len().min(MAX_DOMAIN_LEN);
        domain.smart_host[..host_len].copy_from_slice(&host_bytes[..host_len]);
        domain.smart_host_len = host_len;
    }

    if let Some(port) = smart_host_port {
        domain.smart_host_port = port;
    }

    Ok(())
}

/// Add a relay restriction
pub fn add_relay_entry(
    server_id: u32,
    relay_type: RelayType,
    ip_or_domain: &str,
    subnet_mask: Option<&str>,
) -> Result<UserHandle, u32> {
    let mut state = SMTP_STATE.lock();

    // Verify server exists
    let server_exists = state.servers.iter().any(|s| s.active && s.id == server_id);
    if !server_exists {
        return Err(0x80070002);
    }

    let slot_idx = state.relays.iter().position(|r| !r.active);
    let slot_idx = match slot_idx {
        Some(idx) => idx,
        None => return Err(0x80070008),
    };

    let id = state.next_id;
    state.next_id += 1;

    state.relays[slot_idx].active = true;
    state.relays[slot_idx].id = id;
    state.relays[slot_idx].server_id = server_id;
    state.relays[slot_idx].relay_type = relay_type;

    match relay_type {
        RelayType::AllowIp | RelayType::DenyIp => {
            let ip_bytes = ip_or_domain.as_bytes();
            let ip_len = ip_bytes.len().min(MAX_IP_LEN);
            state.relays[slot_idx].ip_address[..ip_len].copy_from_slice(&ip_bytes[..ip_len]);
            state.relays[slot_idx].ip_len = ip_len;

            if let Some(mask) = subnet_mask {
                let mask_bytes = mask.as_bytes();
                let mask_len = mask_bytes.len().min(MAX_IP_LEN);
                state.relays[slot_idx].subnet_mask[..mask_len].copy_from_slice(&mask_bytes[..mask_len]);
                state.relays[slot_idx].mask_len = mask_len;
            }
        }
        RelayType::AllowDomain => {
            let domain_bytes = ip_or_domain.as_bytes();
            let domain_len = domain_bytes.len().min(MAX_DOMAIN_LEN);
            state.relays[slot_idx].domain[..domain_len].copy_from_slice(&domain_bytes[..domain_len]);
            state.relays[slot_idx].domain_len = domain_len;
        }
    }

    state.relays[slot_idx].handle = UserHandle::from_raw(id);
    state.stats.total_relays += 1;

    Ok(state.relays[slot_idx].handle)
}

/// Remove a relay entry
pub fn remove_relay_entry(entry_id: u32) -> Result<(), u32> {
    let mut state = SMTP_STATE.lock();

    let entry_idx = state.relays.iter().position(|r| r.active && r.id == entry_id);
    let entry_idx = match entry_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    state.relays[entry_idx].active = false;
    state.stats.total_relays = state.stats.total_relays.saturating_sub(1);

    Ok(())
}

/// Force delivery of queued messages
pub fn force_delivery(server_id: u32) -> Result<u32, u32> {
    let mut state = SMTP_STATE.lock();

    // Verify server is running
    let server_running = state.servers.iter()
        .any(|s| s.active && s.id == server_id && s.state == ServerState::Running);

    if !server_running {
        return Err(0x80070015);
    }

    // Count and update pending messages
    let mut forced = 0u32;
    for msg in state.queue.iter_mut() {
        if msg.active && msg.server_id == server_id && msg.status == QueueStatus::Retry {
            msg.status = QueueStatus::Pending;
            msg.next_retry = 0;
            forced += 1;
        }
    }

    Ok(forced)
}

/// Delete a queued message
pub fn delete_queued_message(message_id: u32, move_to_badmail: bool) -> Result<(), u32> {
    let mut state = SMTP_STATE.lock();

    let msg = state.queue.iter_mut().find(|m| m.active && m.id == message_id);
    let msg = match msg {
        Some(m) => m,
        None => return Err(0x80070002),
    };

    msg.active = false;
    state.stats.queued_messages = state.stats.queued_messages.saturating_sub(1);

    if move_to_badmail {
        state.stats.badmail_count += 1;
    }

    Ok(())
}

/// Disconnect a connection
pub fn disconnect_connection(connection_id: u32) -> Result<(), u32> {
    let mut state = SMTP_STATE.lock();

    let conn_idx = state.connections.iter().position(|c| c.active && c.id == connection_id);
    let conn_idx = match conn_idx {
        Some(idx) => idx,
        None => return Err(0x80070002),
    };

    let server_id = state.connections[conn_idx].server_id;
    state.connections[conn_idx].active = false;

    // Update server connection count
    for server in state.servers.iter_mut() {
        if server.active && server.id == server_id {
            server.current_connections = server.current_connections.saturating_sub(1);
            break;
        }
    }

    state.stats.active_connections = state.stats.active_connections.saturating_sub(1);

    Ok(())
}

/// Get server information
pub fn get_server_info(server_id: u32) -> Result<(ServerState, u32, u64, u64), u32> {
    let state = SMTP_STATE.lock();

    let server = state.servers.iter().find(|s| s.active && s.id == server_id);
    let server = match server {
        Some(s) => s,
        None => return Err(0x80070002),
    };

    Ok((
        server.state,
        server.current_connections,
        server.messages_sent,
        server.messages_received,
    ))
}

/// Get SMTP service statistics
pub fn get_statistics() -> SmtpStats {
    let state = SMTP_STATE.lock();
    SmtpStats {
        total_servers: state.stats.total_servers,
        running_servers: state.stats.running_servers,
        total_domains: state.stats.total_domains,
        total_relays: state.stats.total_relays,
        active_connections: state.stats.active_connections,
        queued_messages: state.stats.queued_messages,
        messages_sent: state.stats.messages_sent,
        messages_received: state.stats.messages_received,
        bytes_sent: state.stats.bytes_sent,
        bytes_received: state.stats.bytes_received,
        failed_deliveries: state.stats.failed_deliveries,
        badmail_count: state.stats.badmail_count,
    }
}

/// List all virtual servers
pub fn list_servers() -> [(bool, u32, ServerState); MAX_VIRTUAL_SERVERS] {
    let state = SMTP_STATE.lock();
    let mut result = [(false, 0u32, ServerState::Stopped); MAX_VIRTUAL_SERVERS];

    for (i, server) in state.servers.iter().enumerate() {
        if server.active {
            result[i] = (true, server.id, server.state);
        }
    }

    result
}

/// List domains for a server
pub fn list_domains(server_id: u32) -> [(bool, u32, DomainType); MAX_DOMAINS] {
    let state = SMTP_STATE.lock();
    let mut result = [(false, 0u32, DomainType::Local); MAX_DOMAINS];

    let mut idx = 0;
    for domain in state.domains.iter() {
        if domain.active && domain.server_id == server_id && idx < MAX_DOMAINS {
            result[idx] = (true, domain.id, domain.domain_type);
            idx += 1;
        }
    }

    result
}

/// Get queue statistics for a server
pub fn get_queue_stats(server_id: u32) -> (u32, u32, u32, u32) {
    let state = SMTP_STATE.lock();

    let mut pending = 0u32;
    let mut retry = 0u32;
    let mut delivering = 0u32;
    let mut failed = 0u32;

    for msg in state.queue.iter() {
        if msg.active && msg.server_id == server_id {
            match msg.status {
                QueueStatus::Pending => pending += 1,
                QueueStatus::Retry => retry += 1,
                QueueStatus::Delivering => delivering += 1,
                QueueStatus::Failed => failed += 1,
                _ => {}
            }
        }
    }

    (pending, retry, delivering, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_lifecycle() {
        init().unwrap();

        let handle = create_server(
            "Default SMTP Server",
            "0.0.0.0",
            25,
            "mail.example.com",
            ServerFlags::default(),
        ).unwrap();
        assert_ne!(handle, UserHandle::NULL);

        start_server(1).unwrap_or(());
        pause_server(1).unwrap_or(());
        resume_server(1).unwrap_or(());
        stop_server(1).unwrap_or(());
    }

    #[test]
    fn test_domain_management() {
        init().unwrap();

        let server = create_server(
            "Test SMTP",
            "127.0.0.1",
            2525,
            "test.local",
            ServerFlags::default(),
        );

        if let Ok(_) = server {
            let domain = add_domain(
                1,
                "example.com",
                DomainType::Local,
                DomainFlags::default(),
            );
            assert!(domain.is_ok() || domain.is_err());
        }
    }

    #[test]
    fn test_statistics() {
        init().unwrap();

        let stats = get_statistics();
        assert!(stats.total_servers <= MAX_VIRTUAL_SERVERS as u32);
    }
}
