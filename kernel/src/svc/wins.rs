//! WINS Client Service
//!
//! The WINS (Windows Internet Name Service) client registers NetBIOS
//! names with WINS servers and resolves NetBIOS names to IP addresses.
//!
//! # Features
//!
//! - **Name Registration**: Register NetBIOS names with WINS
//! - **Name Resolution**: Resolve names to IP addresses
//! - **Name Refresh**: Maintain name registrations
//! - **Multiple Servers**: Support primary and secondary WINS
//!
//! # NetBIOS Name Types
//!
//! - Unique: Single owner (workstation, server)
//! - Group: Multiple owners (domain name)
//! - Multihomed: Single owner, multiple IPs
//!
//! # Name Suffixes
//!
//! - 0x00: Workstation
//! - 0x03: Messenger
//! - 0x20: File server
//! - 0x1C: Domain controller group
//! - 0x1D: Master browser

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Maximum WINS servers
const MAX_SERVERS: usize = 4;

/// Maximum registered names
const MAX_NAMES: usize = 32;

/// Maximum cached resolutions
const MAX_CACHE: usize = 128;

/// NetBIOS name length
const NETBIOS_NAME_LEN: usize = 16;

/// Name type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameType {
    /// Unique name (single owner)
    Unique = 0,
    /// Group name (multiple owners)
    Group = 1,
    /// Multihomed (single owner, multiple IPs)
    Multihomed = 2,
}

impl NameType {
    const fn empty() -> Self {
        NameType::Unique
    }
}

/// Name state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameState {
    /// Not registered
    Unregistered = 0,
    /// Registration pending
    Registering = 1,
    /// Registered
    Registered = 2,
    /// Refresh pending
    Refreshing = 3,
    /// Release pending
    Releasing = 4,
    /// Conflict detected
    Conflict = 5,
}

impl NameState {
    const fn empty() -> Self {
        NameState::Unregistered
    }
}

/// Common NetBIOS suffixes
pub mod suffixes {
    /// Workstation service
    pub const WORKSTATION: u8 = 0x00;
    /// Messenger service
    pub const MESSENGER: u8 = 0x03;
    /// RAS server
    pub const RAS_SERVER: u8 = 0x06;
    /// Domain master browser
    pub const DOMAIN_MASTER: u8 = 0x1B;
    /// Domain controllers group
    pub const DOMAIN_CONTROLLERS: u8 = 0x1C;
    /// Master browser
    pub const MASTER_BROWSER: u8 = 0x1D;
    /// Browser elections
    pub const BROWSER_ELECTIONS: u8 = 0x1E;
    /// File server
    pub const FILE_SERVER: u8 = 0x20;
}

/// WINS server info
#[repr(C)]
#[derive(Clone)]
pub struct WinsServer {
    /// Server IP address (as bytes)
    pub address: [u8; 4],
    /// Is primary server
    pub is_primary: bool,
    /// Last successful contact
    pub last_contact: i64,
    /// Failed attempts
    pub failed_attempts: u32,
    /// Is reachable
    pub reachable: bool,
    /// Entry is valid
    pub valid: bool,
}

impl WinsServer {
    const fn empty() -> Self {
        WinsServer {
            address: [0; 4],
            is_primary: false,
            last_contact: 0,
            failed_attempts: 0,
            reachable: true,
            valid: false,
        }
    }
}

/// Registered name entry
#[repr(C)]
#[derive(Clone)]
pub struct RegisteredName {
    /// NetBIOS name (15 chars + suffix)
    pub name: [u8; NETBIOS_NAME_LEN],
    /// Name type
    pub name_type: NameType,
    /// Current state
    pub state: NameState,
    /// Our IP address for this name
    pub ip_address: [u8; 4],
    /// Time-to-live (seconds)
    pub ttl: u32,
    /// Registration time
    pub registered: i64,
    /// Next refresh time
    pub next_refresh: i64,
    /// Entry is valid
    pub valid: bool,
}

impl RegisteredName {
    const fn empty() -> Self {
        RegisteredName {
            name: [0; NETBIOS_NAME_LEN],
            name_type: NameType::empty(),
            state: NameState::empty(),
            ip_address: [0; 4],
            ttl: 3600 * 6, // 6 hours default
            registered: 0,
            next_refresh: 0,
            valid: false,
        }
    }
}

/// Name cache entry (resolved name)
#[repr(C)]
#[derive(Clone)]
pub struct CacheEntry {
    /// NetBIOS name
    pub name: [u8; NETBIOS_NAME_LEN],
    /// Resolved IP address
    pub ip_address: [u8; 4],
    /// Name type
    pub name_type: NameType,
    /// Time-to-live
    pub ttl: u32,
    /// Cached time
    pub cached: i64,
    /// Expires time
    pub expires: i64,
    /// Entry is valid
    pub valid: bool,
}

impl CacheEntry {
    const fn empty() -> Self {
        CacheEntry {
            name: [0; NETBIOS_NAME_LEN],
            ip_address: [0; 4],
            name_type: NameType::empty(),
            ttl: 0,
            cached: 0,
            expires: 0,
            valid: false,
        }
    }
}

/// WINS Client state
pub struct WinsClientState {
    /// Service is running
    pub running: bool,
    /// Our computer name
    pub computer_name: [u8; 15],
    /// Our IP address
    pub ip_address: [u8; 4],
    /// WINS servers
    pub servers: [WinsServer; MAX_SERVERS],
    /// Server count
    pub server_count: usize,
    /// Registered names
    pub names: [RegisteredName; MAX_NAMES],
    /// Name count
    pub name_count: usize,
    /// Name cache
    pub cache: [CacheEntry; MAX_CACHE],
    /// Cache count
    pub cache_count: usize,
    /// WINS enabled
    pub enabled: bool,
    /// Service start time
    pub start_time: i64,
}

impl WinsClientState {
    const fn new() -> Self {
        WinsClientState {
            running: false,
            computer_name: [0; 15],
            ip_address: [0; 4],
            servers: [const { WinsServer::empty() }; MAX_SERVERS],
            server_count: 0,
            names: [const { RegisteredName::empty() }; MAX_NAMES],
            name_count: 0,
            cache: [const { CacheEntry::empty() }; MAX_CACHE],
            cache_count: 0,
            enabled: true,
            start_time: 0,
        }
    }
}

/// Global state
static WINS_STATE: Mutex<WinsClientState> = Mutex::new(WinsClientState::new());

/// Statistics
static REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
static RESOLUTIONS: AtomicU64 = AtomicU64::new(0);
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
static SERVICE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize WINS Client service
pub fn init() {
    if SERVICE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = WINS_STATE.lock();
    state.running = true;
    state.start_time = crate::rtl::time::rtl_get_system_time();

    // Set default computer name
    let name = b"NOSTALGOS";
    state.computer_name[..name.len()].copy_from_slice(name);

    crate::serial_println!("[WINS] WINS Client service initialized");
}

/// Add a WINS server
pub fn add_server(address: [u8; 4], is_primary: bool) -> Result<usize, u32> {
    let mut state = WINS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Check for duplicate
    for server in state.servers.iter() {
        if server.valid && server.address == address {
            return Err(0x80070055);
        }
    }

    let slot = state.servers.iter().position(|s| !s.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let server = &mut state.servers[slot];
    server.address = address;
    server.is_primary = is_primary;
    server.last_contact = 0;
    server.failed_attempts = 0;
    server.reachable = true;
    server.valid = true;

    state.server_count += 1;

    Ok(slot)
}

/// Remove a WINS server
pub fn remove_server(address: [u8; 4]) -> Result<(), u32> {
    let mut state = WINS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    let idx = state.servers.iter()
        .position(|s| s.valid && s.address == address);

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    state.servers[idx].valid = false;
    state.server_count = state.server_count.saturating_sub(1);

    Ok(())
}

/// Register a NetBIOS name
pub fn register_name(
    name: &[u8],
    suffix: u8,
    name_type: NameType,
    ip_address: [u8; 4],
) -> Result<usize, u32> {
    let mut state = WINS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    if !state.enabled {
        return Err(0x80070005);
    }

    // Build full NetBIOS name (15 chars + suffix)
    let mut full_name = [0x20u8; NETBIOS_NAME_LEN]; // Pad with spaces
    let name_len = name.len().min(15);
    full_name[..name_len].copy_from_slice(&name[..name_len]);
    full_name[15] = suffix;

    // Check for duplicate
    for entry in state.names.iter() {
        if entry.valid && entry.name == full_name {
            return Err(0x80070055);
        }
    }

    let slot = state.names.iter().position(|n| !n.valid);
    let slot = match slot {
        Some(s) => s,
        None => return Err(0x8007000E),
    };

    let now = crate::rtl::time::rtl_get_system_time();
    let ttl = 3600 * 6; // 6 hours

    // Increment count before taking mutable reference to entry
    state.name_count += 1;

    let entry = &mut state.names[slot];
    entry.name = full_name;
    entry.name_type = name_type;
    entry.state = NameState::Registering;
    entry.ip_address = ip_address;
    entry.ttl = ttl;
    entry.registered = now;
    entry.next_refresh = now + ((ttl as i64 / 2) * 10_000_000);
    entry.valid = true;

    // Would send registration to WINS server here
    entry.state = NameState::Registered;

    REGISTRATIONS.fetch_add(1, Ordering::SeqCst);

    Ok(slot)
}

/// Release a NetBIOS name
pub fn release_name(name: &[u8], suffix: u8) -> Result<(), u32> {
    let mut state = WINS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Build full name
    let mut full_name = [0x20u8; NETBIOS_NAME_LEN];
    let name_len = name.len().min(15);
    full_name[..name_len].copy_from_slice(&name[..name_len]);
    full_name[15] = suffix;

    let idx = state.names.iter()
        .position(|n| n.valid && n.name == full_name);

    let idx = match idx {
        Some(i) => i,
        None => return Err(0x80070057),
    };

    // Would send release to WINS server here
    state.names[idx].state = NameState::Releasing;
    state.names[idx].valid = false;
    state.name_count = state.name_count.saturating_sub(1);

    Ok(())
}

/// Resolve a NetBIOS name to IP
pub fn resolve_name(name: &[u8], suffix: u8) -> Result<[u8; 4], u32> {
    let state = WINS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Build full name
    let mut full_name = [0x20u8; NETBIOS_NAME_LEN];
    let name_len = name.len().min(15);
    full_name[..name_len].copy_from_slice(&name[..name_len]);
    full_name[15] = suffix;

    let now = crate::rtl::time::rtl_get_system_time();

    // Check cache first
    for entry in state.cache.iter() {
        if entry.valid && entry.name == full_name && now < entry.expires {
            CACHE_HITS.fetch_add(1, Ordering::SeqCst);
            RESOLUTIONS.fetch_add(1, Ordering::SeqCst);
            return Ok(entry.ip_address);
        }
    }

    CACHE_MISSES.fetch_add(1, Ordering::SeqCst);

    // Would query WINS server here
    // For now, return not found
    RESOLUTIONS.fetch_add(1, Ordering::SeqCst);
    Err(0x80070057)
}

/// Add entry to cache
pub fn cache_entry(
    name: &[u8],
    suffix: u8,
    ip_address: [u8; 4],
    name_type: NameType,
    ttl: u32,
) -> Result<(), u32> {
    let mut state = WINS_STATE.lock();

    if !state.running {
        return Err(0x80070426);
    }

    // Build full name
    let mut full_name = [0x20u8; NETBIOS_NAME_LEN];
    let name_len = name.len().min(15);
    full_name[..name_len].copy_from_slice(&name[..name_len]);
    full_name[15] = suffix;

    let now = crate::rtl::time::rtl_get_system_time();

    // Find existing or free slot
    let slot = state.cache.iter()
        .position(|c| c.valid && c.name == full_name)
        .or_else(|| state.cache.iter().position(|c| !c.valid));

    let slot = match slot {
        Some(s) => s,
        None => {
            // Cache full, evict oldest
            let oldest = state.cache.iter()
                .enumerate()
                .filter(|(_, c)| c.valid)
                .min_by_key(|(_, c)| c.cached)
                .map(|(i, _)| i)
                .unwrap_or(0);
            oldest
        }
    };

    let entry = &mut state.cache[slot];
    let was_new = !entry.valid;
    entry.name = full_name;
    entry.ip_address = ip_address;
    entry.name_type = name_type;
    entry.ttl = ttl;
    entry.cached = now;
    entry.expires = now + (ttl as i64 * 10_000_000);
    entry.valid = true;

    if was_new {
        state.cache_count += 1;
    }

    Ok(())
}

/// Flush the name cache
pub fn flush_cache() {
    let mut state = WINS_STATE.lock();

    for entry in state.cache.iter_mut() {
        entry.valid = false;
    }
    state.cache_count = 0;
}

/// Refresh registered names
pub fn refresh_names() {
    let mut state = WINS_STATE.lock();

    if !state.running || !state.enabled {
        return;
    }

    let now = crate::rtl::time::rtl_get_system_time();

    for name in state.names.iter_mut() {
        if name.valid && name.state == NameState::Registered {
            if now >= name.next_refresh {
                name.state = NameState::Refreshing;
                // Would send refresh to WINS server
                name.next_refresh = now + ((name.ttl as i64 / 2) * 10_000_000);
                name.state = NameState::Registered;
            }
        }
    }
}

/// Get registered names
pub fn get_registered_names() -> ([RegisteredName; MAX_NAMES], usize) {
    let state = WINS_STATE.lock();
    let mut result = [const { RegisteredName::empty() }; MAX_NAMES];
    let mut count = 0;

    for name in state.names.iter() {
        if name.valid && count < MAX_NAMES {
            result[count] = name.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Get WINS servers
pub fn get_servers() -> ([WinsServer; MAX_SERVERS], usize) {
    let state = WINS_STATE.lock();
    let mut result = [const { WinsServer::empty() }; MAX_SERVERS];
    let mut count = 0;

    for server in state.servers.iter() {
        if server.valid && count < MAX_SERVERS {
            result[count] = server.clone();
            count += 1;
        }
    }

    (result, count)
}

/// Set IP address
pub fn set_ip_address(ip: [u8; 4]) {
    let mut state = WINS_STATE.lock();
    state.ip_address = ip;
}

/// Enable/disable WINS
pub fn set_enabled(enabled: bool) {
    let mut state = WINS_STATE.lock();
    state.enabled = enabled;
}

/// Check if WINS is enabled
pub fn is_enabled() -> bool {
    let state = WINS_STATE.lock();
    state.enabled
}

/// Get cache stats
pub fn get_cache_stats() -> (usize, u64, u64) {
    let state = WINS_STATE.lock();
    (
        state.cache_count,
        CACHE_HITS.load(Ordering::SeqCst),
        CACHE_MISSES.load(Ordering::SeqCst),
    )
}

/// Get statistics
pub fn get_statistics() -> (u64, u64, u64, u64) {
    (
        REGISTRATIONS.load(Ordering::SeqCst),
        RESOLUTIONS.load(Ordering::SeqCst),
        CACHE_HITS.load(Ordering::SeqCst),
        CACHE_MISSES.load(Ordering::SeqCst),
    )
}

/// Check if service is running
pub fn is_running() -> bool {
    let state = WINS_STATE.lock();
    state.running
}

/// Stop the service
pub fn stop() {
    let mut state = WINS_STATE.lock();
    state.running = false;

    // Release all registered names
    for name in state.names.iter_mut() {
        if name.valid {
            name.state = NameState::Releasing;
            name.valid = false;
        }
    }
    state.name_count = 0;

    crate::serial_println!("[WINS] WINS Client service stopped");
}
