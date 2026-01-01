//! MRU (Most Recently Used) List Implementation
//!
//! Windows MRU list for tracking recently used items.
//! Based on Windows Server 2003 shlwapi.
//!
//! # Features
//!
//! - Track recently used strings/data
//! - Configurable maximum entries
//! - Automatic ordering (most recent first)
//! - Persistent storage support
//!
//! # References
//!
//! - `shell/shlwapi/mru.c` - MRU list implementation

use crate::ke::spinlock::SpinLock;

// ============================================================================
// MRU Flags
// ============================================================================

/// String MRU list
pub const MRU_STRING: u32 = 0x00000000;

/// Binary data MRU list
pub const MRU_BINARY: u32 = 0x00000001;

/// Cache writes (don't persist immediately)
pub const MRU_CACHEWRITE: u32 = 0x00000002;

/// Add to end of list (not front)
pub const MRU_ADDTOEND: u32 = 0x00000004;

/// Delete on create (clear existing)
pub const MRU_DELETEONOPEN: u32 = 0x00000008;

// ============================================================================
// Constants
// ============================================================================

/// Maximum MRU lists
pub const MAX_MRU_LISTS: usize = 32;

/// Maximum entries per list
pub const MAX_MRU_ENTRIES: usize = 26;

/// Maximum string length
pub const MAX_MRU_STRING: usize = 256;

/// Maximum binary data size
pub const MAX_MRU_DATA: usize = 512;

// ============================================================================
// MRU Entry
// ============================================================================

/// MRU entry data
#[derive(Clone)]
pub struct MruEntry {
    /// Is this entry in use
    pub in_use: bool,
    /// Entry slot (a-z)
    pub slot: u8,
    /// String data
    pub string_data: [u8; MAX_MRU_STRING],
    pub string_len: usize,
    /// Binary data
    pub binary_data: [u8; MAX_MRU_DATA],
    pub binary_len: usize,
    /// Is binary data
    pub is_binary: bool,
}

impl MruEntry {
    /// Create empty entry
    pub const fn new() -> Self {
        Self {
            in_use: false,
            slot: 0,
            string_data: [0u8; MAX_MRU_STRING],
            string_len: 0,
            binary_data: [0u8; MAX_MRU_DATA],
            binary_len: 0,
            is_binary: false,
        }
    }

    /// Set string data
    pub fn set_string(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(MAX_MRU_STRING - 1);
        self.string_data[..len].copy_from_slice(&bytes[..len]);
        self.string_len = len;
        self.is_binary = false;
        self.in_use = true;
    }

    /// Get string data
    pub fn get_string(&self) -> &[u8] {
        &self.string_data[..self.string_len]
    }

    /// Set binary data
    pub fn set_binary(&mut self, data: &[u8]) {
        let len = data.len().min(MAX_MRU_DATA);
        self.binary_data[..len].copy_from_slice(&data[..len]);
        self.binary_len = len;
        self.is_binary = true;
        self.in_use = true;
    }

    /// Get binary data
    pub fn get_binary(&self) -> &[u8] {
        &self.binary_data[..self.binary_len]
    }

    /// Compare with string
    pub fn matches_string(&self, s: &str) -> bool {
        if self.is_binary || !self.in_use {
            return false;
        }
        let bytes = s.as_bytes();
        bytes.len() == self.string_len && bytes == &self.string_data[..self.string_len]
    }

    /// Compare with binary
    pub fn matches_binary(&self, data: &[u8]) -> bool {
        if !self.is_binary || !self.in_use {
            return false;
        }
        data.len() == self.binary_len && data == &self.binary_data[..self.binary_len]
    }
}

// ============================================================================
// MRU List
// ============================================================================

/// MRU list state
#[derive(Clone)]
pub struct MruList {
    /// Is this list in use
    pub in_use: bool,
    /// List flags
    pub flags: u32,
    /// Maximum entries
    pub max_entries: usize,
    /// Entries
    pub entries: [MruEntry; MAX_MRU_ENTRIES],
    /// Order of entries (index into entries array, most recent first)
    pub order: [u8; MAX_MRU_ENTRIES],
    /// Number of entries in use
    pub count: usize,
    /// List name/key
    pub name: [u8; 64],
    pub name_len: usize,
    /// Modified flag
    pub modified: bool,
}

impl MruList {
    /// Create empty MRU list
    pub const fn new() -> Self {
        Self {
            in_use: false,
            flags: 0,
            max_entries: MAX_MRU_ENTRIES,
            entries: [const { MruEntry::new() }; MAX_MRU_ENTRIES],
            order: [0u8; MAX_MRU_ENTRIES],
            count: 0,
            name: [0u8; 64],
            name_len: 0,
            modified: false,
        }
    }

    /// Reset list
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Initialize list
    pub fn init(&mut self, name: &str, max_entries: usize, flags: u32) {
        self.flags = flags;
        self.max_entries = max_entries.min(MAX_MRU_ENTRIES);
        self.count = 0;
        self.modified = false;

        let bytes = name.as_bytes();
        let len = bytes.len().min(63);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name_len = len;

        // Initialize order
        for i in 0..MAX_MRU_ENTRIES {
            self.order[i] = i as u8;
            self.entries[i].slot = b'a' + i as u8;
        }

        if flags & MRU_DELETEONOPEN != 0 {
            // Clear any existing entries
            for entry in self.entries.iter_mut() {
                entry.in_use = false;
            }
        }
    }

    /// Find string in list
    pub fn find_string(&self, s: &str) -> Option<usize> {
        for i in 0..self.count {
            let idx = self.order[i] as usize;
            if self.entries[idx].matches_string(s) {
                return Some(i);
            }
        }
        None
    }

    /// Find binary in list
    pub fn find_binary(&self, data: &[u8]) -> Option<usize> {
        for i in 0..self.count {
            let idx = self.order[i] as usize;
            if self.entries[idx].matches_binary(data) {
                return Some(i);
            }
        }
        None
    }

    /// Add string to list
    pub fn add_string(&mut self, s: &str) -> i32 {
        // Check if already exists
        if let Some(pos) = self.find_string(s) {
            // Move to front
            self.move_to_front(pos);
            return self.order[0] as i32;
        }

        // Find slot for new entry
        let slot_idx = if self.count < self.max_entries {
            // Use next available slot
            let idx = self.count;
            self.count += 1;
            idx
        } else {
            // Reuse last entry
            self.order[self.max_entries - 1] as usize
        };

        // Set entry data
        self.entries[slot_idx].set_string(s);

        // Move to front if not MRU_ADDTOEND
        if self.flags & MRU_ADDTOEND == 0 {
            // Shift order down
            for i in (1..self.count).rev() {
                self.order[i] = self.order[i - 1];
            }
            self.order[0] = slot_idx as u8;
        }

        self.modified = true;
        slot_idx as i32
    }

    /// Add binary to list
    pub fn add_binary(&mut self, data: &[u8]) -> i32 {
        // Check if already exists
        if let Some(pos) = self.find_binary(data) {
            // Move to front
            self.move_to_front(pos);
            return self.order[0] as i32;
        }

        // Find slot for new entry
        let slot_idx = if self.count < self.max_entries {
            let idx = self.count;
            self.count += 1;
            idx
        } else {
            self.order[self.max_entries - 1] as usize
        };

        // Set entry data
        self.entries[slot_idx].set_binary(data);

        // Move to front if not MRU_ADDTOEND
        if self.flags & MRU_ADDTOEND == 0 {
            for i in (1..self.count).rev() {
                self.order[i] = self.order[i - 1];
            }
            self.order[0] = slot_idx as u8;
        }

        self.modified = true;
        slot_idx as i32
    }

    /// Move entry at position to front
    fn move_to_front(&mut self, pos: usize) {
        if pos == 0 || pos >= self.count {
            return;
        }

        let entry_idx = self.order[pos];

        // Shift entries down
        for i in (1..=pos).rev() {
            self.order[i] = self.order[i - 1];
        }
        self.order[0] = entry_idx;

        self.modified = true;
    }

    /// Delete entry at position
    pub fn delete(&mut self, pos: usize) -> bool {
        if pos >= self.count {
            return false;
        }

        let entry_idx = self.order[pos] as usize;
        self.entries[entry_idx].in_use = false;

        // Shift order up
        for i in pos..self.count - 1 {
            self.order[i] = self.order[i + 1];
        }
        self.count -= 1;

        self.modified = true;
        true
    }

    /// Get entry at position
    pub fn get_entry(&self, pos: usize) -> Option<&MruEntry> {
        if pos >= self.count {
            return None;
        }
        let idx = self.order[pos] as usize;
        if self.entries[idx].in_use {
            Some(&self.entries[idx])
        } else {
            None
        }
    }

    /// Get string at position
    pub fn get_string(&self, pos: usize) -> Option<&[u8]> {
        let entry = self.get_entry(pos)?;
        if entry.is_binary {
            None
        } else {
            Some(entry.get_string())
        }
    }

    /// Get binary at position
    pub fn get_binary(&self, pos: usize) -> Option<&[u8]> {
        let entry = self.get_entry(pos)?;
        if entry.is_binary {
            Some(entry.get_binary())
        } else {
            None
        }
    }

    /// Get order string (e.g., "abcdefg" for entries in order)
    pub fn get_order(&self) -> [u8; MAX_MRU_ENTRIES + 1] {
        let mut order = [0u8; MAX_MRU_ENTRIES + 1];
        for i in 0..self.count {
            order[i] = self.entries[self.order[i] as usize].slot;
        }
        order
    }

    /// Get count
    pub fn get_count(&self) -> usize {
        self.count
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.in_use = false;
        }
        self.count = 0;
        self.modified = true;
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global MRU list storage
static MRU_LISTS: SpinLock<[MruList; MAX_MRU_LISTS]> =
    SpinLock::new([const { MruList::new() }; MAX_MRU_LISTS]);

/// MRU list handle
pub type HMRULIST = usize;

/// Null handle
pub const NULL_HMRULIST: HMRULIST = 0;

// ============================================================================
// Public API
// ============================================================================

/// Initialize MRU subsystem
pub fn init() {
    crate::serial_println!("[USER] MRUList initialized");
}

/// Create MRU list
pub fn create(name: &str, max_entries: usize, flags: u32) -> HMRULIST {
    let mut lists = MRU_LISTS.lock();

    for (i, list) in lists.iter_mut().enumerate() {
        if !list.in_use {
            list.reset();
            list.in_use = true;
            list.init(name, max_entries, flags);
            return i + 1;
        }
    }

    NULL_HMRULIST
}

/// Destroy MRU list
pub fn destroy(hmru: HMRULIST) -> bool {
    if hmru == NULL_HMRULIST {
        return false;
    }

    let mut lists = MRU_LISTS.lock();
    let idx = hmru - 1;

    if idx >= MAX_MRU_LISTS {
        return false;
    }

    if lists[idx].in_use {
        lists[idx].reset();
        true
    } else {
        false
    }
}

/// Add string to MRU list
pub fn add_string(hmru: HMRULIST, s: &str) -> i32 {
    if hmru == NULL_HMRULIST {
        return -1;
    }

    let mut lists = MRU_LISTS.lock();
    let idx = hmru - 1;

    if idx >= MAX_MRU_LISTS || !lists[idx].in_use {
        return -1;
    }

    lists[idx].add_string(s)
}

/// Add binary data to MRU list
pub fn add_binary(hmru: HMRULIST, data: &[u8]) -> i32 {
    if hmru == NULL_HMRULIST {
        return -1;
    }

    let mut lists = MRU_LISTS.lock();
    let idx = hmru - 1;

    if idx >= MAX_MRU_LISTS || !lists[idx].in_use {
        return -1;
    }

    lists[idx].add_binary(data)
}

/// Find string in MRU list
pub fn find_string(hmru: HMRULIST, s: &str) -> i32 {
    if hmru == NULL_HMRULIST {
        return -1;
    }

    let lists = MRU_LISTS.lock();
    let idx = hmru - 1;

    if idx >= MAX_MRU_LISTS || !lists[idx].in_use {
        return -1;
    }

    match lists[idx].find_string(s) {
        Some(pos) => pos as i32,
        None => -1,
    }
}

/// Delete entry from MRU list
pub fn delete(hmru: HMRULIST, pos: usize) -> bool {
    if hmru == NULL_HMRULIST {
        return false;
    }

    let mut lists = MRU_LISTS.lock();
    let idx = hmru - 1;

    if idx >= MAX_MRU_LISTS || !lists[idx].in_use {
        return false;
    }

    lists[idx].delete(pos)
}

/// Get string from MRU list
pub fn get_string(hmru: HMRULIST, pos: usize, buffer: &mut [u8]) -> i32 {
    if hmru == NULL_HMRULIST {
        return -1;
    }

    let lists = MRU_LISTS.lock();
    let idx = hmru - 1;

    if idx >= MAX_MRU_LISTS || !lists[idx].in_use {
        return -1;
    }

    match lists[idx].get_string(pos) {
        Some(s) => {
            let len = s.len().min(buffer.len());
            buffer[..len].copy_from_slice(&s[..len]);
            len as i32
        }
        None => -1,
    }
}

/// Get entry count
pub fn get_count(hmru: HMRULIST) -> usize {
    if hmru == NULL_HMRULIST {
        return 0;
    }

    let lists = MRU_LISTS.lock();
    let idx = hmru - 1;

    if idx >= MAX_MRU_LISTS || !lists[idx].in_use {
        return 0;
    }

    lists[idx].get_count()
}

/// Clear MRU list
pub fn clear(hmru: HMRULIST) -> bool {
    if hmru == NULL_HMRULIST {
        return false;
    }

    let mut lists = MRU_LISTS.lock();
    let idx = hmru - 1;

    if idx >= MAX_MRU_LISTS || !lists[idx].in_use {
        return false;
    }

    lists[idx].clear();
    true
}

/// Enumerate entries (returns next position or -1)
pub fn enum_entries(hmru: HMRULIST, pos: usize) -> i32 {
    if hmru == NULL_HMRULIST {
        return -1;
    }

    let lists = MRU_LISTS.lock();
    let idx = hmru - 1;

    if idx >= MAX_MRU_LISTS || !lists[idx].in_use {
        return -1;
    }

    if pos < lists[idx].count {
        (pos + 1) as i32
    } else {
        -1
    }
}

/// Get statistics
pub fn get_stats() -> MruStats {
    let lists = MRU_LISTS.lock();

    let mut active_count = 0;
    let mut total_entries = 0;

    for list in lists.iter() {
        if list.in_use {
            active_count += 1;
            total_entries += list.count;
        }
    }

    MruStats {
        max_lists: MAX_MRU_LISTS,
        active_lists: active_count,
        total_entries,
    }
}

/// MRU statistics
#[derive(Debug, Clone, Copy)]
pub struct MruStats {
    pub max_lists: usize,
    pub active_lists: usize,
    pub total_entries: usize,
}
