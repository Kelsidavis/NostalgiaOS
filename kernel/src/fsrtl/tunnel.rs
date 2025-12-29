//! Short Name Tunneling Support
//!
//! Provides short name (8.3) preservation when files are renamed or deleted
//! and recreated quickly. This allows applications that rely on consistent
//! short names to continue working across delete/create cycles.
//!
//! The tunnel cache stores the mapping between long names and their
//! associated short names for a configurable timeout period.
//!
//! This implementation is NT 5.2 (Windows Server 2003) compatible.

use crate::ex::fast_mutex::FastMutex;

/// Maximum number of tunnel entries
const MAX_TUNNEL_ENTRIES: usize = 256;

/// Default tunnel timeout in 100ns units (15 seconds)
const DEFAULT_TUNNEL_TIMEOUT: i64 = 15 * 10_000_000;

/// Maximum short name length
const MAX_SHORT_NAME_LENGTH: usize = 13;  // 8.3 + dot + null

/// Maximum long name length for tunneling
const MAX_LONG_NAME_LENGTH: usize = 256;

/// A tunnel cache entry
#[repr(C)]
#[derive(Clone)]
pub struct TunnelEntry {
    /// Long file name
    pub long_name: [u8; MAX_LONG_NAME_LENGTH],
    /// Length of long name
    pub long_name_length: u16,
    /// Short file name (8.3)
    pub short_name: [u8; MAX_SHORT_NAME_LENGTH],
    /// Length of short name
    pub short_name_length: u8,
    /// Directory key (parent directory ID)
    pub directory_key: u64,
    /// Timestamp when entry was created
    pub create_time: i64,
    /// Whether this entry is in use
    pub in_use: bool,
}

impl TunnelEntry {
    pub const fn new() -> Self {
        Self {
            long_name: [0; MAX_LONG_NAME_LENGTH],
            long_name_length: 0,
            short_name: [0; MAX_SHORT_NAME_LENGTH],
            short_name_length: 0,
            directory_key: 0,
            create_time: 0,
            in_use: false,
        }
    }

    /// Check if this entry has expired
    pub fn is_expired(&self, current_time: i64, timeout: i64) -> bool {
        if !self.in_use {
            return true;
        }
        (current_time - self.create_time) > timeout
    }
}

impl Default for TunnelEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Tunnel cache for short name preservation
#[repr(C)]
pub struct TunnelCache {
    /// Synchronization mutex
    mutex: FastMutex,
    /// Tunnel entries
    entries: [TunnelEntry; MAX_TUNNEL_ENTRIES],
    /// Number of entries in use
    num_entries: u32,
    /// Timeout in 100ns units
    timeout: i64,
    /// Next index for round-robin replacement
    next_index: usize,
}

impl TunnelCache {
    /// Create a new empty tunnel cache
    pub const fn new() -> Self {
        const EMPTY_ENTRY: TunnelEntry = TunnelEntry::new();
        Self {
            mutex: FastMutex::new(),
            entries: [EMPTY_ENTRY; MAX_TUNNEL_ENTRIES],
            num_entries: 0,
            timeout: DEFAULT_TUNNEL_TIMEOUT,
            next_index: 0,
        }
    }
}

impl Default for TunnelCache {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Initialize a tunnel cache
pub fn fsrtl_initialize_tunnel_cache(cache: &mut TunnelCache) {
    cache.mutex.init();
    cache.num_entries = 0;
    cache.timeout = DEFAULT_TUNNEL_TIMEOUT;
    cache.next_index = 0;

    for entry in cache.entries.iter_mut() {
        entry.in_use = false;
    }
}

/// Delete and clean up a tunnel cache
pub fn fsrtl_delete_tunnel_cache(cache: &mut TunnelCache) {
    cache.mutex.acquire();

    for entry in cache.entries.iter_mut() {
        entry.in_use = false;
    }
    cache.num_entries = 0;

    cache.mutex.release();
}

/// Add an entry to the tunnel cache
///
/// Called when a file is deleted or renamed to preserve its short name
/// association.
///
/// # Arguments
/// * `cache` - The tunnel cache
/// * `directory_key` - Parent directory identifier
/// * `short_name` - The 8.3 short name
/// * `long_name` - The long file name
/// * `current_time` - Current system time in 100ns units
pub fn fsrtl_add_to_tunnel_cache(
    cache: &mut TunnelCache,
    directory_key: u64,
    short_name: &str,
    long_name: &str,
    current_time: i64,
) {
    cache.mutex.acquire();

    // First, purge expired entries
    purge_expired_entries(cache, current_time);

    // Check if we already have an entry for this name
    let existing_idx = find_entry_by_long_name(cache, directory_key, long_name);

    let idx = if let Some(i) = existing_idx {
        // Update existing entry
        i
    } else {
        // Find a free slot or use round-robin replacement
        find_free_slot(cache)
    };

    let entry = &mut cache.entries[idx];

    // Copy short name
    let short_bytes = short_name.as_bytes();
    let short_len = short_bytes.len().min(MAX_SHORT_NAME_LENGTH - 1);
    entry.short_name[..short_len].copy_from_slice(&short_bytes[..short_len]);
    entry.short_name_length = short_len as u8;

    // Copy long name
    let long_bytes = long_name.as_bytes();
    let long_len = long_bytes.len().min(MAX_LONG_NAME_LENGTH - 1);
    entry.long_name[..long_len].copy_from_slice(&long_bytes[..long_len]);
    entry.long_name_length = long_len as u16;

    entry.directory_key = directory_key;
    entry.create_time = current_time;

    if !entry.in_use {
        entry.in_use = true;
        cache.num_entries += 1;
    }

    cache.mutex.release();
}

/// Look up a tunneled short name
///
/// Called when a file is created to check if there's a tunneled short name
/// that should be reused.
///
/// # Arguments
/// * `cache` - The tunnel cache
/// * `directory_key` - Parent directory identifier
/// * `long_name` - The long file name being created
/// * `short_name_buffer` - Buffer to receive the short name
/// * `current_time` - Current system time
///
/// # Returns
/// true if a tunneled short name was found
pub fn fsrtl_find_in_tunnel_cache(
    cache: &mut TunnelCache,
    directory_key: u64,
    long_name: &str,
    short_name_buffer: &mut [u8],
    current_time: i64,
) -> Option<usize> {
    cache.mutex.acquire();

    let result = find_entry_by_long_name(cache, directory_key, long_name)
        .and_then(|idx| {
            let entry = &cache.entries[idx];

            // Check if entry has expired
            if entry.is_expired(current_time, cache.timeout) {
                return None;
            }

            // Copy short name to buffer
            let copy_len = (entry.short_name_length as usize).min(short_name_buffer.len());
            short_name_buffer[..copy_len].copy_from_slice(&entry.short_name[..copy_len]);

            Some(copy_len)
        });

    cache.mutex.release();

    result
}

/// Delete a specific entry from the tunnel cache
///
/// Called when a tunneled entry should no longer be preserved.
pub fn fsrtl_delete_from_tunnel_cache(
    cache: &mut TunnelCache,
    directory_key: u64,
    long_name: &str,
) {
    cache.mutex.acquire();

    if let Some(idx) = find_entry_by_long_name(cache, directory_key, long_name) {
        cache.entries[idx].in_use = false;
        cache.num_entries = cache.num_entries.saturating_sub(1);
    }

    cache.mutex.release();
}

/// Delete all entries for a directory
///
/// Called when a directory is deleted.
pub fn fsrtl_delete_key_from_tunnel_cache(
    cache: &mut TunnelCache,
    directory_key: u64,
) {
    cache.mutex.acquire();

    for entry in cache.entries.iter_mut() {
        if entry.in_use && entry.directory_key == directory_key {
            entry.in_use = false;
            cache.num_entries = cache.num_entries.saturating_sub(1);
        }
    }

    cache.mutex.release();
}

/// Set the tunnel cache timeout
pub fn fsrtl_set_tunnel_cache_timeout(cache: &mut TunnelCache, timeout: i64) {
    cache.timeout = timeout;
}

/// Get the number of entries in the tunnel cache
pub fn fsrtl_get_tunnel_cache_size(cache: &TunnelCache) -> u32 {
    cache.num_entries
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

/// Find an entry by long name (case-insensitive)
fn find_entry_by_long_name(
    cache: &TunnelCache,
    directory_key: u64,
    long_name: &str,
) -> Option<usize> {
    let search_bytes = long_name.as_bytes();

    for (i, entry) in cache.entries.iter().enumerate() {
        if !entry.in_use {
            continue;
        }

        if entry.directory_key != directory_key {
            continue;
        }

        if entry.long_name_length as usize != search_bytes.len() {
            continue;
        }

        // Case-insensitive comparison
        let entry_name = &entry.long_name[..entry.long_name_length as usize];
        let matches = entry_name.iter().zip(search_bytes.iter()).all(|(a, b)| {
            a.to_ascii_uppercase() == b.to_ascii_uppercase()
        });

        if matches {
            return Some(i);
        }
    }

    None
}

/// Find a free slot in the cache
fn find_free_slot(cache: &mut TunnelCache) -> usize {
    // First try to find an empty slot
    for (i, entry) in cache.entries.iter().enumerate() {
        if !entry.in_use {
            return i;
        }
    }

    // No free slots - use round-robin replacement
    let idx = cache.next_index;
    cache.next_index = (cache.next_index + 1) % MAX_TUNNEL_ENTRIES;

    // Mark as not in use (will be set to in_use when populated)
    if cache.entries[idx].in_use {
        cache.entries[idx].in_use = false;
        cache.num_entries = cache.num_entries.saturating_sub(1);
    }

    idx
}

/// Purge expired entries from the cache
fn purge_expired_entries(cache: &mut TunnelCache, current_time: i64) {
    for entry in cache.entries.iter_mut() {
        if entry.is_expired(current_time, cache.timeout) && entry.in_use {
            entry.in_use = false;
            cache.num_entries = cache.num_entries.saturating_sub(1);
        }
    }
}
