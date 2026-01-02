//! MUP - Multiple UNC Provider
//!
//! MUP is responsible for routing UNC paths (\\server\share) to the appropriate
//! network redirector (provider). It maintains a list of registered providers
//! and dispatches I/O requests to them.
//!
//! The provider order determines which redirector handles a given UNC path
//! when multiple providers might be able to handle it.
//!
//! Examples of providers:
//! - LanmanWorkstation (SMB/CIFS)
//! - WebClient (WebDAV)
//! - NFS Client
//! - DFS Client

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum number of registered providers
const MAX_PROVIDERS: usize = 32;

/// Maximum number of known prefixes (cached resolutions)
const MAX_KNOWN_PREFIXES: usize = 256;

/// Maximum UNC path length
const MAX_UNC_PATH_LEN: usize = 260;

/// Provider device name length
const MAX_DEVICE_NAME_LEN: usize = 128;

// ============================================================================
// Provider Types
// ============================================================================

/// Network provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ProviderType {
    /// LAN Manager (SMB/CIFS)
    LanMan = 0x00020000,
    /// NetWare
    NetWare = 0x00030000,
    /// WebDAV
    WebDav = 0x00050000,
    /// NFS
    Nfs = 0x00060000,
    /// DFS
    Dfs = 0x00070000,
    /// Other/Unknown
    Other = 0x00000000,
}

/// Provider capabilities
#[derive(Debug, Clone, Copy)]
pub struct ProviderCapabilities {
    /// Supports file I/O
    pub file_io: bool,
    /// Supports directory operations
    pub directory_ops: bool,
    /// Supports extended attributes
    pub extended_attrs: bool,
    /// Supports security
    pub security: bool,
    /// Supports named pipes
    pub named_pipes: bool,
    /// Supports mailslots
    pub mailslots: bool,
    /// Supports oplocks
    pub oplocks: bool,
    /// Supports Unicode
    pub unicode: bool,
}

impl Default for ProviderCapabilities {
    fn default() -> Self {
        Self {
            file_io: true,
            directory_ops: true,
            extended_attrs: false,
            security: true,
            named_pipes: true,
            mailslots: true,
            oplocks: true,
            unicode: true,
        }
    }
}

/// Provider state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderState {
    /// Provider registered but not started
    Registered,
    /// Provider active and accepting requests
    Active,
    /// Provider stopping
    Stopping,
    /// Provider stopped
    Stopped,
}

// ============================================================================
// Network Provider
// ============================================================================

/// A registered network provider
#[derive(Clone)]
pub struct NetworkProvider {
    /// Provider ID
    pub id: u32,
    /// Provider name
    pub name: [u8; MAX_DEVICE_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Device name (e.g., \Device\LanmanRedirector)
    pub device_name: [u8; MAX_DEVICE_NAME_LEN],
    /// Device name length
    pub device_name_len: usize,
    /// Provider type
    pub provider_type: ProviderType,
    /// Provider order (lower = higher priority)
    pub order: u32,
    /// Capabilities
    pub capabilities: ProviderCapabilities,
    /// Current state
    pub state: ProviderState,
    /// Requests handled
    pub requests_handled: u64,
    /// Requests failed
    pub requests_failed: u64,
    /// Active flag
    pub active: bool,
}

impl Default for NetworkProvider {
    fn default() -> Self {
        Self {
            id: 0,
            name: [0; MAX_DEVICE_NAME_LEN],
            name_len: 0,
            device_name: [0; MAX_DEVICE_NAME_LEN],
            device_name_len: 0,
            provider_type: ProviderType::Other,
            order: u32::MAX,
            capabilities: ProviderCapabilities::default(),
            state: ProviderState::Stopped,
            requests_handled: 0,
            requests_failed: 0,
            active: false,
        }
    }
}

// ============================================================================
// Known Prefix (Cached Resolution)
// ============================================================================

/// A cached UNC prefix to provider mapping
#[derive(Clone)]
pub struct KnownPrefix {
    /// Prefix ID
    pub id: u64,
    /// UNC prefix (e.g., \\server\share)
    pub prefix: [u8; MAX_UNC_PATH_LEN],
    /// Prefix length
    pub prefix_len: usize,
    /// Resolved provider ID
    pub provider_id: u32,
    /// Cache timestamp
    pub timestamp: u64,
    /// TTL in seconds
    pub ttl: u32,
    /// Hit count
    pub hits: u64,
    /// Active flag
    pub active: bool,
}

impl Default for KnownPrefix {
    fn default() -> Self {
        Self {
            id: 0,
            prefix: [0; MAX_UNC_PATH_LEN],
            prefix_len: 0,
            provider_id: 0,
            timestamp: 0,
            ttl: 300, // 5 minutes default
            hits: 0,
            active: false,
        }
    }
}

// ============================================================================
// UNC Path Parsing
// ============================================================================

/// Parsed UNC path components
#[derive(Debug, Clone)]
pub struct UncPath {
    /// Server name
    pub server: String,
    /// Share name
    pub share: String,
    /// Remaining path (after share)
    pub path: String,
    /// Full original path
    pub full_path: String,
}

impl UncPath {
    /// Parse a UNC path string
    pub fn parse(path: &str) -> Option<Self> {
        // Must start with \\ or //
        if !path.starts_with("\\\\") && !path.starts_with("//") {
            return None;
        }

        let path_normalized = path.replace('/', "\\");
        let parts: Vec<&str> = path_normalized[2..].splitn(3, '\\').collect();

        if parts.is_empty() {
            return None;
        }

        let server = parts.get(0)?.to_string();
        let share = parts.get(1).map(|s| s.to_string()).unwrap_or_default();
        let remaining = parts.get(2).map(|s| s.to_string()).unwrap_or_default();

        Some(Self {
            server,
            share,
            path: remaining,
            full_path: path.to_string(),
        })
    }

    /// Get the prefix (\\server\share)
    pub fn prefix(&self) -> String {
        if self.share.is_empty() {
            alloc::format!("\\\\{}", self.server)
        } else {
            alloc::format!("\\\\{}\\{}", self.server, self.share)
        }
    }
}

// ============================================================================
// MUP Statistics
// ============================================================================

/// MUP statistics
#[derive(Debug)]
pub struct MupStatistics {
    /// Prefix lookups
    pub prefix_lookups: AtomicU64,
    /// Cache hits
    pub cache_hits: AtomicU64,
    /// Cache misses
    pub cache_misses: AtomicU64,
    /// Provider queries
    pub provider_queries: AtomicU64,
    /// Successful resolutions
    pub resolutions: AtomicU64,
    /// Failed resolutions
    pub resolution_failures: AtomicU64,
    /// Active providers
    pub active_providers: AtomicU32,
    /// Cached prefixes
    pub cached_prefixes: AtomicU32,
}

impl Default for MupStatistics {
    fn default() -> Self {
        Self {
            prefix_lookups: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            provider_queries: AtomicU64::new(0),
            resolutions: AtomicU64::new(0),
            resolution_failures: AtomicU64::new(0),
            active_providers: AtomicU32::new(0),
            cached_prefixes: AtomicU32::new(0),
        }
    }
}

// ============================================================================
// MUP Errors
// ============================================================================

/// MUP error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MupError {
    /// Success
    Success = 0,
    /// Not initialized
    NotInitialized = -1,
    /// Invalid UNC path
    InvalidPath = -2,
    /// No provider found
    NoProvider = -3,
    /// Provider not responding
    ProviderNotResponding = -4,
    /// Too many providers
    TooManyProviders = -5,
    /// Provider already registered
    ProviderExists = -6,
    /// Provider not found
    ProviderNotFound = -7,
    /// Invalid parameter
    InvalidParameter = -8,
    /// Access denied
    AccessDenied = -9,
    /// Network error
    NetworkError = -10,
    /// Path not found
    PathNotFound = -11,
}

// ============================================================================
// MUP State
// ============================================================================

/// MUP global state
pub struct MupState {
    /// Registered providers
    pub providers: [NetworkProvider; MAX_PROVIDERS],
    /// Known prefixes (cache)
    pub known_prefixes: [KnownPrefix; MAX_KNOWN_PREFIXES],
    /// Next provider ID
    pub next_provider_id: u32,
    /// Next prefix ID
    pub next_prefix_id: u64,
    /// Statistics
    pub statistics: MupStatistics,
    /// Initialized flag
    pub initialized: bool,
}

impl MupState {
    const fn new() -> Self {
        const DEFAULT_PROVIDER: NetworkProvider = NetworkProvider {
            id: 0,
            name: [0; MAX_DEVICE_NAME_LEN],
            name_len: 0,
            device_name: [0; MAX_DEVICE_NAME_LEN],
            device_name_len: 0,
            provider_type: ProviderType::Other,
            order: u32::MAX,
            capabilities: ProviderCapabilities {
                file_io: true,
                directory_ops: true,
                extended_attrs: false,
                security: true,
                named_pipes: true,
                mailslots: true,
                oplocks: true,
                unicode: true,
            },
            state: ProviderState::Stopped,
            requests_handled: 0,
            requests_failed: 0,
            active: false,
        };

        const DEFAULT_PREFIX: KnownPrefix = KnownPrefix {
            id: 0,
            prefix: [0; MAX_UNC_PATH_LEN],
            prefix_len: 0,
            provider_id: 0,
            timestamp: 0,
            ttl: 300,
            hits: 0,
            active: false,
        };

        Self {
            providers: [DEFAULT_PROVIDER; MAX_PROVIDERS],
            known_prefixes: [DEFAULT_PREFIX; MAX_KNOWN_PREFIXES],
            next_provider_id: 1,
            next_prefix_id: 1,
            statistics: MupStatistics {
                prefix_lookups: AtomicU64::new(0),
                cache_hits: AtomicU64::new(0),
                cache_misses: AtomicU64::new(0),
                provider_queries: AtomicU64::new(0),
                resolutions: AtomicU64::new(0),
                resolution_failures: AtomicU64::new(0),
                active_providers: AtomicU32::new(0),
                cached_prefixes: AtomicU32::new(0),
            },
            initialized: false,
        }
    }
}

/// Global MUP state
static MUP_STATE: SpinLock<MupState> = SpinLock::new(MupState::new());

// ============================================================================
// Provider Registration
// ============================================================================

/// Register a network provider
pub fn mup_register_provider(
    name: &str,
    device_name: &str,
    provider_type: ProviderType,
    order: u32,
    capabilities: ProviderCapabilities,
) -> Result<u32, MupError> {
    let mut state = MUP_STATE.lock();

    if !state.initialized {
        return Err(MupError::NotInitialized);
    }

    let name_bytes = name.as_bytes();
    let device_bytes = device_name.as_bytes();

    if name_bytes.len() > MAX_DEVICE_NAME_LEN || device_bytes.len() > MAX_DEVICE_NAME_LEN {
        return Err(MupError::InvalidParameter);
    }

    // Check if already registered
    for idx in 0..MAX_PROVIDERS {
        if state.providers[idx].active && state.providers[idx].name_len == name_bytes.len() {
            let mut matches = true;
            for i in 0..name_bytes.len() {
                if state.providers[idx].name[i] != name_bytes[i] {
                    matches = false;
                    break;
                }
            }
            if matches {
                return Err(MupError::ProviderExists);
            }
        }
    }

    // Find free slot
    let mut slot_idx = None;
    for idx in 0..MAX_PROVIDERS {
        if !state.providers[idx].active {
            slot_idx = Some(idx);
            break;
        }
    }

    let idx = slot_idx.ok_or(MupError::TooManyProviders)?;

    let provider_id = state.next_provider_id;
    state.next_provider_id += 1;

    state.providers[idx] = NetworkProvider {
        id: provider_id,
        name: [0; MAX_DEVICE_NAME_LEN],
        name_len: name_bytes.len(),
        device_name: [0; MAX_DEVICE_NAME_LEN],
        device_name_len: device_bytes.len(),
        provider_type,
        order,
        capabilities,
        state: ProviderState::Active,
        requests_handled: 0,
        requests_failed: 0,
        active: true,
    };

    state.providers[idx].name[..name_bytes.len()].copy_from_slice(name_bytes);
    state.providers[idx].device_name[..device_bytes.len()].copy_from_slice(device_bytes);

    state.statistics.active_providers.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[MUP] Registered provider '{}' (order={})", name, order);

    Ok(provider_id)
}

/// Deregister a network provider
pub fn mup_deregister_provider(provider_id: u32) -> Result<(), MupError> {
    let mut state = MUP_STATE.lock();

    if !state.initialized {
        return Err(MupError::NotInitialized);
    }

    for idx in 0..MAX_PROVIDERS {
        if state.providers[idx].active && state.providers[idx].id == provider_id {
            state.providers[idx].state = ProviderState::Stopped;
            state.providers[idx].active = false;

            state.statistics.active_providers.fetch_sub(1, Ordering::Relaxed);

            crate::serial_println!("[MUP] Deregistered provider {}", provider_id);
            return Ok(());
        }
    }

    Err(MupError::ProviderNotFound)
}

// ============================================================================
// UNC Path Resolution
// ============================================================================

/// Resolve a UNC path to a provider
pub fn mup_resolve_path(path: &str) -> Result<u32, MupError> {
    let mut state = MUP_STATE.lock();

    if !state.initialized {
        return Err(MupError::NotInitialized);
    }

    state.statistics.prefix_lookups.fetch_add(1, Ordering::Relaxed);

    // Parse the UNC path
    let unc = UncPath::parse(path).ok_or(MupError::InvalidPath)?;
    let prefix = unc.prefix();
    let prefix_bytes = prefix.as_bytes();

    // Check cache first
    for idx in 0..MAX_KNOWN_PREFIXES {
        if state.known_prefixes[idx].active {
            if state.known_prefixes[idx].prefix_len == prefix_bytes.len() {
                let mut matches = true;
                for i in 0..prefix_bytes.len() {
                    if state.known_prefixes[idx].prefix[i] != prefix_bytes[i] {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    state.known_prefixes[idx].hits += 1;
                    state.statistics.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(state.known_prefixes[idx].provider_id);
                }
            }
        }
    }

    state.statistics.cache_misses.fetch_add(1, Ordering::Relaxed);

    // Query providers in order
    let mut best_provider: Option<(u32, u32)> = None; // (provider_id, order)

    for idx in 0..MAX_PROVIDERS {
        if state.providers[idx].active && state.providers[idx].state == ProviderState::Active {
            state.statistics.provider_queries.fetch_add(1, Ordering::Relaxed);

            // Simplified: assume all active providers can handle the path
            // Real implementation would call provider's claim function
            if best_provider.is_none() || state.providers[idx].order < best_provider.unwrap().1 {
                best_provider = Some((state.providers[idx].id, state.providers[idx].order));
            }
        }
    }

    if let Some((provider_id, _)) = best_provider {
        // Cache the resolution
        if prefix_bytes.len() <= MAX_UNC_PATH_LEN {
            let mut cache_idx = None;
            for idx in 0..MAX_KNOWN_PREFIXES {
                if !state.known_prefixes[idx].active {
                    cache_idx = Some(idx);
                    break;
                }
            }

            if let Some(idx) = cache_idx {
                let prefix_id = state.next_prefix_id;
                state.next_prefix_id += 1;

                state.known_prefixes[idx] = KnownPrefix {
                    id: prefix_id,
                    prefix: [0; MAX_UNC_PATH_LEN],
                    prefix_len: prefix_bytes.len(),
                    provider_id,
                    timestamp: 0, // TODO: system time
                    ttl: 300,
                    hits: 0,
                    active: true,
                };

                state.known_prefixes[idx].prefix[..prefix_bytes.len()].copy_from_slice(prefix_bytes);
                state.statistics.cached_prefixes.fetch_add(1, Ordering::Relaxed);
            }
        }

        state.statistics.resolutions.fetch_add(1, Ordering::Relaxed);
        return Ok(provider_id);
    }

    state.statistics.resolution_failures.fetch_add(1, Ordering::Relaxed);
    Err(MupError::NoProvider)
}

/// Invalidate cached prefix
pub fn mup_invalidate_prefix(path: &str) -> Result<(), MupError> {
    let mut state = MUP_STATE.lock();

    if !state.initialized {
        return Err(MupError::NotInitialized);
    }

    let unc = UncPath::parse(path).ok_or(MupError::InvalidPath)?;
    let prefix = unc.prefix();
    let prefix_bytes = prefix.as_bytes();

    for idx in 0..MAX_KNOWN_PREFIXES {
        if state.known_prefixes[idx].active {
            if state.known_prefixes[idx].prefix_len == prefix_bytes.len() {
                let mut matches = true;
                for i in 0..prefix_bytes.len() {
                    if state.known_prefixes[idx].prefix[i] != prefix_bytes[i] {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    state.known_prefixes[idx].active = false;
                    state.statistics.cached_prefixes.fetch_sub(1, Ordering::Relaxed);
                    return Ok(());
                }
            }
        }
    }

    Err(MupError::PathNotFound)
}

/// Get provider for a path
pub fn mup_get_provider(provider_id: u32) -> Result<(String, String, ProviderType), MupError> {
    let state = MUP_STATE.lock();

    if !state.initialized {
        return Err(MupError::NotInitialized);
    }

    for idx in 0..MAX_PROVIDERS {
        if state.providers[idx].active && state.providers[idx].id == provider_id {
            let name = core::str::from_utf8(&state.providers[idx].name[..state.providers[idx].name_len])
                .map(String::from)
                .unwrap_or_default();
            let device = core::str::from_utf8(&state.providers[idx].device_name[..state.providers[idx].device_name_len])
                .map(String::from)
                .unwrap_or_default();

            return Ok((name, device, state.providers[idx].provider_type));
        }
    }

    Err(MupError::ProviderNotFound)
}

/// List all registered providers
pub fn mup_list_providers() -> Vec<(u32, String, ProviderType, u32)> {
    let state = MUP_STATE.lock();
    let mut result = Vec::new();

    for idx in 0..MAX_PROVIDERS {
        if state.providers[idx].active {
            let name = core::str::from_utf8(&state.providers[idx].name[..state.providers[idx].name_len])
                .map(String::from)
                .unwrap_or_default();

            result.push((
                state.providers[idx].id,
                name,
                state.providers[idx].provider_type,
                state.providers[idx].order,
            ));
        }
    }

    // Sort by order
    result.sort_by_key(|&(_, _, _, order)| order);

    result
}

// ============================================================================
// Statistics
// ============================================================================

/// Get MUP statistics
pub fn mup_get_statistics() -> MupStatistics {
    let state = MUP_STATE.lock();

    MupStatistics {
        prefix_lookups: AtomicU64::new(state.statistics.prefix_lookups.load(Ordering::Relaxed)),
        cache_hits: AtomicU64::new(state.statistics.cache_hits.load(Ordering::Relaxed)),
        cache_misses: AtomicU64::new(state.statistics.cache_misses.load(Ordering::Relaxed)),
        provider_queries: AtomicU64::new(state.statistics.provider_queries.load(Ordering::Relaxed)),
        resolutions: AtomicU64::new(state.statistics.resolutions.load(Ordering::Relaxed)),
        resolution_failures: AtomicU64::new(state.statistics.resolution_failures.load(Ordering::Relaxed)),
        active_providers: AtomicU32::new(state.statistics.active_providers.load(Ordering::Relaxed)),
        cached_prefixes: AtomicU32::new(state.statistics.cached_prefixes.load(Ordering::Relaxed)),
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize MUP
pub fn init() {
    crate::serial_println!("[MUP] Initializing Multiple UNC Provider...");

    {
        let mut state = MUP_STATE.lock();
        state.initialized = true;
    }

    // Register built-in LanMan provider
    let _ = mup_register_provider(
        "LanmanWorkstation",
        "\\Device\\LanmanRedirector",
        ProviderType::LanMan,
        1,
        ProviderCapabilities::default(),
    );

    crate::serial_println!("[MUP] MUP initialized");
}
