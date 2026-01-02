//! DNS Client Service
//!
//! The DNS Client service provides name resolution caching and management:
//!
//! - **Name Resolution Cache**: Caches DNS query results
//! - **Negative Caching**: Caches failed lookups to reduce query load
//! - **Server Selection**: Manages DNS server list and failover
//! - **HOSTS File**: Parses local hosts file entries
//! - **Suffix Search**: Appends domain suffixes for short names
//!
//! # Cache Management
//!
//! The DNS cache stores:
//! - A records (IPv4 addresses)
//! - AAAA records (IPv6 addresses)
//! - CNAME records (canonical names)
//! - Negative entries (NXDOMAIN responses)
//!
//! # Configuration
//!
//! Registry location: `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`

extern crate alloc;

use crate::ke::SpinLock;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum cache entries
pub const MAX_CACHE_ENTRIES: usize = 1024;

/// Maximum DNS servers
pub const MAX_DNS_SERVERS: usize = 8;

/// Maximum hosts file entries
pub const MAX_HOSTS_ENTRIES: usize = 64;

/// Maximum hostname length
pub const MAX_HOSTNAME: usize = 256;

/// Maximum domain suffix length
pub const MAX_SUFFIX: usize = 64;

/// Maximum suffixes
pub const MAX_SUFFIXES: usize = 8;

/// Default cache TTL (seconds)
pub const DEFAULT_TTL: u32 = 3600;

/// Negative cache TTL (seconds)
pub const NEGATIVE_TTL: u32 = 300;

// ============================================================================
// Types
// ============================================================================

/// DNS record type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    /// IPv4 address
    A = 1,
    /// IPv6 address
    Aaaa = 28,
    /// Canonical name
    Cname = 5,
    /// Mail exchanger
    Mx = 15,
    /// Name server
    Ns = 2,
    /// Pointer (reverse lookup)
    Ptr = 12,
    /// Start of authority
    Soa = 6,
    /// Service record
    Srv = 33,
    /// Text record
    Txt = 16,
    /// Unknown
    Unknown = 0,
}

impl Default for RecordType {
    fn default() -> Self {
        Self::A
    }
}

impl RecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Ptr => "PTR",
            Self::Soa => "SOA",
            Self::Srv => "SRV",
            Self::Txt => "TXT",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Cache entry status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CacheStatus {
    /// Valid entry
    Valid = 0,
    /// Expired
    Expired = 1,
    /// Negative (NXDOMAIN)
    Negative = 2,
    /// Pending resolution
    Pending = 3,
}

impl Default for CacheStatus {
    fn default() -> Self {
        Self::Valid
    }
}

/// DNS client error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DnsClientError {
    /// Success
    Ok = 0,
    /// Service not running
    NotRunning = 1,
    /// Name not found
    NameNotFound = 2,
    /// Server failure
    ServerFailure = 3,
    /// Query refused
    Refused = 4,
    /// Timeout
    Timeout = 5,
    /// No DNS servers configured
    NoServers = 6,
    /// Cache full
    CacheFull = 7,
    /// Invalid name
    InvalidName = 8,
    /// Not implemented
    NotImplemented = 9,
}

// ============================================================================
// Cache Entry
// ============================================================================

/// A DNS cache entry
#[derive(Clone)]
pub struct CacheEntry {
    /// Entry is valid
    pub valid: bool,
    /// Hostname
    pub hostname: [u8; MAX_HOSTNAME],
    /// Hostname length
    pub hostname_len: usize,
    /// Record type
    pub record_type: RecordType,
    /// Status
    pub status: CacheStatus,
    /// IPv4 address (for A records)
    pub ipv4: [u8; 4],
    /// IPv6 address (for AAAA records)
    pub ipv6: [u8; 16],
    /// Canonical name (for CNAME records)
    pub cname: [u8; MAX_HOSTNAME],
    /// CNAME length
    pub cname_len: usize,
    /// Time to live (seconds remaining)
    pub ttl: u32,
    /// Original TTL from response
    pub original_ttl: u32,
    /// Creation time
    pub created_at: i64,
    /// Last access time
    pub last_access: i64,
    /// Hit count
    pub hits: u32,
}

impl CacheEntry {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            hostname: [0; MAX_HOSTNAME],
            hostname_len: 0,
            record_type: RecordType::A,
            status: CacheStatus::Valid,
            ipv4: [0; 4],
            ipv6: [0; 16],
            cname: [0; MAX_HOSTNAME],
            cname_len: 0,
            ttl: 0,
            original_ttl: 0,
            created_at: 0,
            last_access: 0,
            hits: 0,
        }
    }

    pub fn hostname_str(&self) -> &str {
        core::str::from_utf8(&self.hostname[..self.hostname_len]).unwrap_or("")
    }

    pub fn set_hostname(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_HOSTNAME);
        self.hostname[..len].copy_from_slice(&bytes[..len]);
        self.hostname_len = len;
    }

    pub fn cname_str(&self) -> &str {
        core::str::from_utf8(&self.cname[..self.cname_len]).unwrap_or("")
    }

    pub fn set_cname(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_HOSTNAME);
        self.cname[..len].copy_from_slice(&bytes[..len]);
        self.cname_len = len;
    }

    pub fn is_expired(&self, now: i64) -> bool {
        let elapsed = ((now - self.created_at) / 10_000_000) as u32; // NT time to seconds
        elapsed >= self.ttl
    }
}

// ============================================================================
// DNS Server
// ============================================================================

/// A DNS server entry
#[derive(Clone)]
pub struct DnsServer {
    /// Entry is valid
    pub valid: bool,
    /// Server IP address
    pub ip: [u8; 4],
    /// Server port
    pub port: u16,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Is primary server
    pub is_primary: bool,
    /// Queries sent
    pub queries: u64,
    /// Successful responses
    pub successes: u64,
    /// Failed queries
    pub failures: u64,
    /// Average response time (ms)
    pub avg_response_ms: u32,
}

impl DnsServer {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            ip: [0; 4],
            port: 53,
            priority: 0,
            is_primary: false,
            queries: 0,
            successes: 0,
            failures: 0,
            avg_response_ms: 0,
        }
    }

    pub fn ip_str(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        let mut pos = 0;

        for (i, &octet) in self.ip.iter().enumerate() {
            if i > 0 {
                buf[pos] = b'.';
                pos += 1;
            }
            // Simple number to string
            if octet >= 100 {
                buf[pos] = b'0' + (octet / 100);
                pos += 1;
            }
            if octet >= 10 {
                buf[pos] = b'0' + ((octet / 10) % 10);
                pos += 1;
            }
            buf[pos] = b'0' + (octet % 10);
            pos += 1;
        }

        buf
    }
}

// ============================================================================
// Hosts File Entry
// ============================================================================

/// A hosts file entry
#[derive(Clone)]
pub struct HostsEntry {
    /// Entry is valid
    pub valid: bool,
    /// Hostname
    pub hostname: [u8; MAX_HOSTNAME],
    /// Hostname length
    pub hostname_len: usize,
    /// IP address
    pub ip: [u8; 4],
    /// Is IPv6
    pub is_ipv6: bool,
    /// IPv6 address
    pub ipv6: [u8; 16],
}

impl HostsEntry {
    pub const fn empty() -> Self {
        Self {
            valid: false,
            hostname: [0; MAX_HOSTNAME],
            hostname_len: 0,
            ip: [0; 4],
            is_ipv6: false,
            ipv6: [0; 16],
        }
    }

    pub fn hostname_str(&self) -> &str {
        core::str::from_utf8(&self.hostname[..self.hostname_len]).unwrap_or("")
    }

    pub fn set_hostname(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_HOSTNAME);
        self.hostname[..len].copy_from_slice(&bytes[..len]);
        self.hostname_len = len;
    }
}

// ============================================================================
// Service State
// ============================================================================

/// DNS client service state
struct DnsClientState {
    /// Service running
    running: bool,
    /// Cache entries
    cache: [CacheEntry; MAX_CACHE_ENTRIES],
    /// Cache entry count
    cache_count: usize,
    /// DNS servers
    servers: [DnsServer; MAX_DNS_SERVERS],
    /// Server count
    server_count: usize,
    /// Hosts file entries
    hosts: [HostsEntry; MAX_HOSTS_ENTRIES],
    /// Hosts count
    hosts_count: usize,
    /// Domain suffixes
    suffixes: [[u8; MAX_SUFFIX]; MAX_SUFFIXES],
    /// Suffix count
    suffix_count: usize,
    /// Caching enabled
    caching_enabled: bool,
    /// Negative caching enabled
    negative_caching: bool,
    /// Default TTL
    default_ttl: u32,
}

impl DnsClientState {
    const fn new() -> Self {
        Self {
            running: false,
            cache: [const { CacheEntry::empty() }; MAX_CACHE_ENTRIES],
            cache_count: 0,
            servers: [const { DnsServer::empty() }; MAX_DNS_SERVERS],
            server_count: 0,
            hosts: [const { HostsEntry::empty() }; MAX_HOSTS_ENTRIES],
            hosts_count: 0,
            suffixes: [[0; MAX_SUFFIX]; MAX_SUFFIXES],
            suffix_count: 0,
            caching_enabled: true,
            negative_caching: true,
            default_ttl: DEFAULT_TTL,
        }
    }
}

static DNS_STATE: SpinLock<DnsClientState> = SpinLock::new(DnsClientState::new());

/// Statistics
struct DnsStats {
    /// Total queries
    queries: AtomicU64,
    /// Cache hits
    cache_hits: AtomicU64,
    /// Cache misses
    cache_misses: AtomicU64,
    /// Successful resolutions
    successful: AtomicU64,
    /// Failed resolutions
    failed: AtomicU64,
    /// NXDOMAIN responses
    nxdomain: AtomicU64,
    /// Timeouts
    timeouts: AtomicU64,
    /// Hosts file hits
    hosts_hits: AtomicU64,
}

impl DnsStats {
    const fn new() -> Self {
        Self {
            queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            successful: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            nxdomain: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            hosts_hits: AtomicU64::new(0),
        }
    }
}

static DNS_STATS: DnsStats = DnsStats::new();

// ============================================================================
// DNS Server Management
// ============================================================================

/// Add a DNS server
pub fn add_server(ip: [u8; 4], is_primary: bool) -> Result<usize, DnsClientError> {
    let mut state = DNS_STATE.lock();

    if !state.running {
        return Err(DnsClientError::NotRunning);
    }

    if state.server_count >= MAX_DNS_SERVERS {
        return Err(DnsClientError::CacheFull);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_DNS_SERVERS {
        if !state.servers[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(DnsClientError::CacheFull),
    };

    let priority = if is_primary { 0 } else { state.server_count as u32 };

    let server = &mut state.servers[slot];
    server.valid = true;
    server.ip = ip;
    server.port = 53;
    server.priority = priority;
    server.is_primary = is_primary;
    server.queries = 0;
    server.successes = 0;
    server.failures = 0;
    server.avg_response_ms = 0;

    state.server_count += 1;

    crate::serial_println!("[DNSCLIENT] Added DNS server {}.{}.{}.{}",
        ip[0], ip[1], ip[2], ip[3]);

    Ok(slot)
}

/// Remove a DNS server
pub fn remove_server(ip: [u8; 4]) -> Result<(), DnsClientError> {
    let mut state = DNS_STATE.lock();

    for i in 0..MAX_DNS_SERVERS {
        if state.servers[i].valid && state.servers[i].ip == ip {
            state.servers[i].valid = false;
            state.server_count = state.server_count.saturating_sub(1);
            return Ok(());
        }
    }

    Err(DnsClientError::NotRunning)
}

/// Get DNS server count
pub fn get_server_count() -> usize {
    let state = DNS_STATE.lock();
    state.server_count
}

// ============================================================================
// Hosts File Management
// ============================================================================

/// Add a hosts file entry
pub fn add_hosts_entry(hostname: &str, ip: [u8; 4]) -> Result<usize, DnsClientError> {
    let mut state = DNS_STATE.lock();

    if !state.running {
        return Err(DnsClientError::NotRunning);
    }

    if state.hosts_count >= MAX_HOSTS_ENTRIES {
        return Err(DnsClientError::CacheFull);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_HOSTS_ENTRIES {
        if !state.hosts[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(DnsClientError::CacheFull),
    };

    let entry = &mut state.hosts[slot];
    entry.valid = true;
    entry.set_hostname(hostname);
    entry.ip = ip;
    entry.is_ipv6 = false;

    state.hosts_count += 1;

    Ok(slot)
}

/// Lookup hostname in hosts file
fn lookup_hosts(hostname: &str) -> Option<[u8; 4]> {
    let state = DNS_STATE.lock();
    let lower_host = hostname.to_ascii_lowercase();

    for i in 0..MAX_HOSTS_ENTRIES {
        if state.hosts[i].valid && state.hosts[i].hostname_str().eq_ignore_ascii_case(&lower_host) {
            DNS_STATS.hosts_hits.fetch_add(1, Ordering::Relaxed);
            return Some(state.hosts[i].ip);
        }
    }

    None
}

// ============================================================================
// Cache Management
// ============================================================================

/// Add an entry to the cache
pub fn cache_add(
    hostname: &str,
    record_type: RecordType,
    ipv4: Option<[u8; 4]>,
    ttl: u32,
) -> Result<usize, DnsClientError> {
    let mut state = DNS_STATE.lock();

    if !state.running || !state.caching_enabled {
        return Err(DnsClientError::NotRunning);
    }

    // Find existing or free slot
    let mut slot = None;
    for i in 0..MAX_CACHE_ENTRIES {
        if state.cache[i].valid && state.cache[i].hostname_str().eq_ignore_ascii_case(hostname) {
            slot = Some(i);
            break;
        }
        if slot.is_none() && !state.cache[i].valid {
            slot = Some(i);
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => {
            // Evict oldest entry
            let mut oldest_idx = 0;
            let mut oldest_time = i64::MAX;
            for i in 0..MAX_CACHE_ENTRIES {
                if state.cache[i].last_access < oldest_time {
                    oldest_time = state.cache[i].last_access;
                    oldest_idx = i;
                }
            }
            oldest_idx
        }
    };

    let now = crate::rtl::time::rtl_get_system_time();

    let entry = &mut state.cache[slot];
    let was_valid = entry.valid;
    entry.valid = true;
    entry.set_hostname(hostname);
    entry.record_type = record_type;
    entry.status = CacheStatus::Valid;
    if let Some(ip) = ipv4 {
        entry.ipv4 = ip;
    }
    entry.ttl = ttl;
    entry.original_ttl = ttl;
    entry.created_at = now;
    entry.last_access = now;
    entry.hits = 0;

    if !was_valid {
        state.cache_count += 1;
    }

    Ok(slot)
}

/// Add a negative cache entry
pub fn cache_add_negative(hostname: &str) -> Result<usize, DnsClientError> {
    let mut state = DNS_STATE.lock();

    if !state.running || !state.negative_caching {
        return Err(DnsClientError::NotRunning);
    }

    // Find free slot
    let mut slot = None;
    for i in 0..MAX_CACHE_ENTRIES {
        if !state.cache[i].valid {
            slot = Some(i);
            break;
        }
    }

    let slot = match slot {
        Some(s) => s,
        None => return Err(DnsClientError::CacheFull),
    };

    let now = crate::rtl::time::rtl_get_system_time();

    let entry = &mut state.cache[slot];
    entry.valid = true;
    entry.set_hostname(hostname);
    entry.record_type = RecordType::A;
    entry.status = CacheStatus::Negative;
    entry.ttl = NEGATIVE_TTL;
    entry.original_ttl = NEGATIVE_TTL;
    entry.created_at = now;
    entry.last_access = now;
    entry.hits = 0;

    state.cache_count += 1;

    DNS_STATS.nxdomain.fetch_add(1, Ordering::Relaxed);

    Ok(slot)
}

/// Lookup hostname in cache
pub fn cache_lookup(hostname: &str) -> Option<(CacheStatus, [u8; 4])> {
    let mut state = DNS_STATE.lock();
    let now = crate::rtl::time::rtl_get_system_time();

    for i in 0..MAX_CACHE_ENTRIES {
        if state.cache[i].valid && state.cache[i].hostname_str().eq_ignore_ascii_case(hostname) {
            if state.cache[i].is_expired(now) {
                state.cache[i].valid = false;
                state.cache_count = state.cache_count.saturating_sub(1);
                return None;
            }

            state.cache[i].last_access = now;
            state.cache[i].hits += 1;

            DNS_STATS.cache_hits.fetch_add(1, Ordering::Relaxed);

            return Some((state.cache[i].status, state.cache[i].ipv4));
        }
    }

    DNS_STATS.cache_misses.fetch_add(1, Ordering::Relaxed);

    None
}

/// Flush the DNS cache
pub fn flush_cache() -> usize {
    let mut state = DNS_STATE.lock();
    let count = state.cache_count;

    for i in 0..MAX_CACHE_ENTRIES {
        state.cache[i].valid = false;
    }
    state.cache_count = 0;

    crate::serial_println!("[DNSCLIENT] Flushed {} cache entries", count);

    count
}

/// Get cache entry count
pub fn get_cache_count() -> usize {
    let state = DNS_STATE.lock();
    state.cache_count
}

// ============================================================================
// Name Resolution
// ============================================================================

/// Resolve a hostname to an IP address
pub fn resolve(hostname: &str) -> Result<[u8; 4], DnsClientError> {
    DNS_STATS.queries.fetch_add(1, Ordering::Relaxed);

    // Check hosts file first
    if let Some(ip) = lookup_hosts(hostname) {
        DNS_STATS.successful.fetch_add(1, Ordering::Relaxed);
        return Ok(ip);
    }

    // Check cache
    if let Some((status, ip)) = cache_lookup(hostname) {
        match status {
            CacheStatus::Valid => {
                DNS_STATS.successful.fetch_add(1, Ordering::Relaxed);
                return Ok(ip);
            }
            CacheStatus::Negative => {
                DNS_STATS.failed.fetch_add(1, Ordering::Relaxed);
                return Err(DnsClientError::NameNotFound);
            }
            _ => {}
        }
    }

    // In a real implementation, this would send DNS queries to servers
    // For now, just return an error (no actual network lookup)
    DNS_STATS.failed.fetch_add(1, Ordering::Relaxed);
    Err(DnsClientError::ServerFailure)
}

/// Register a successful resolution (for external DNS module integration)
pub fn register_resolution(hostname: &str, ip: [u8; 4], ttl: u32) -> Result<(), DnsClientError> {
    cache_add(hostname, RecordType::A, Some(ip), ttl)?;
    DNS_STATS.successful.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

// ============================================================================
// Configuration
// ============================================================================

/// Enable/disable caching
pub fn set_caching_enabled(enabled: bool) {
    let mut state = DNS_STATE.lock();
    state.caching_enabled = enabled;
    crate::serial_println!("[DNSCLIENT] Caching: {}",
        if enabled { "enabled" } else { "disabled" });
}

/// Enable/disable negative caching
pub fn set_negative_caching(enabled: bool) {
    let mut state = DNS_STATE.lock();
    state.negative_caching = enabled;
}

/// Add a domain suffix for name resolution
pub fn add_suffix(suffix: &str) -> Result<(), DnsClientError> {
    let mut state = DNS_STATE.lock();

    if state.suffix_count >= MAX_SUFFIXES {
        return Err(DnsClientError::CacheFull);
    }

    let idx = state.suffix_count;
    let bytes = suffix.as_bytes();
    let len = bytes.len().min(MAX_SUFFIX);
    state.suffixes[idx][..len].copy_from_slice(&bytes[..len]);
    state.suffix_count += 1;

    Ok(())
}

// ============================================================================
// Statistics
// ============================================================================

/// Get DNS client statistics
pub fn get_statistics() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        DNS_STATS.queries.load(Ordering::Relaxed),
        DNS_STATS.cache_hits.load(Ordering::Relaxed),
        DNS_STATS.cache_misses.load(Ordering::Relaxed),
        DNS_STATS.successful.load(Ordering::Relaxed),
        DNS_STATS.failed.load(Ordering::Relaxed),
        DNS_STATS.nxdomain.load(Ordering::Relaxed),
        DNS_STATS.timeouts.load(Ordering::Relaxed),
        DNS_STATS.hosts_hits.load(Ordering::Relaxed),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = DNS_STATE.lock();
    state.running
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialized flag
static DNS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the DNS Client service
pub fn init() {
    if DNS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::serial_println!("[DNSCLIENT] Initializing DNS Client Service...");

    {
        let mut state = DNS_STATE.lock();
        state.running = true;
        state.caching_enabled = true;
        state.negative_caching = true;
        state.default_ttl = DEFAULT_TTL;
    }

    // Add default hosts file entries
    let _ = add_hosts_entry("localhost", [127, 0, 0, 1]);
    let _ = add_hosts_entry("localhost.localdomain", [127, 0, 0, 1]);

    // Add default DNS servers (Google DNS)
    let _ = add_server([8, 8, 8, 8], true);
    let _ = add_server([8, 8, 4, 4], false);

    // Add default suffix
    let _ = add_suffix("local");

    crate::serial_println!("[DNSCLIENT] DNS Client Service initialized");
    crate::serial_println!("[DNSCLIENT]   DNS servers: 2");
    crate::serial_println!("[DNSCLIENT]   Hosts entries: 2");
    crate::serial_println!("[DNSCLIENT]   Caching: enabled");
}
