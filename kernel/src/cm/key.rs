//! Registry Key Structures
//!
//! Registry keys are hierarchical containers that hold values and subkeys.
//! Each key has a name and can contain up to MAX_VALUES values and
//! MAX_SUBKEYS subkeys.
//!
//! # Key Hierarchy
//! - HKEY_LOCAL_MACHINE (HKLM) - Machine-wide configuration
//!   - SYSTEM - Boot configuration, drivers
//!   - SOFTWARE - Installed software
//!   - HARDWARE - Hardware descriptions
//! - HKEY_USERS (HKU) - User-specific configuration
//! - HKEY_CURRENT_CONFIG - Current hardware profile

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use super::value::{CmKeyValue, MAX_VALUE_NAME_LENGTH};

/// Maximum key name length (characters)
pub const MAX_KEY_NAME_LENGTH: usize = 64;

/// Maximum values per key
pub const MAX_VALUES_PER_KEY: usize = 16;

/// Maximum subkeys per key
pub const MAX_SUBKEYS_PER_KEY: usize = 16;

/// Maximum total keys in the system
pub const MAX_KEYS: usize = 256;

/// Key flags
pub mod key_flags {
    /// Key is in use
    pub const KEY_IN_USE: u32 = 0x0001;
    /// Key is volatile (not persisted)
    pub const KEY_VOLATILE: u32 = 0x0002;
    /// Key is a symbolic link
    pub const KEY_LINK: u32 = 0x0004;
    /// Key was created by system
    pub const KEY_SYSTEM: u32 = 0x0008;
    /// Key is read-only
    pub const KEY_READONLY: u32 = 0x0010;
    /// Key is a hive root
    pub const KEY_HIVE_ROOT: u32 = 0x0020;
    /// Key has been modified
    pub const KEY_DIRTY: u32 = 0x0040;
}

/// Registry key name
#[derive(Clone, Copy)]
pub struct CmKeyName {
    /// Name characters (UTF-8)
    pub chars: [u8; MAX_KEY_NAME_LENGTH],
    /// Name length
    pub length: u8,
}

impl CmKeyName {
    /// Create empty name
    pub const fn empty() -> Self {
        Self {
            chars: [0; MAX_KEY_NAME_LENGTH],
            length: 0,
        }
    }

    /// Create from string
    pub fn from_str(s: &str) -> Self {
        let mut name = Self::empty();
        let bytes = s.as_bytes();
        let len = bytes.len().min(MAX_KEY_NAME_LENGTH);
        name.chars[..len].copy_from_slice(&bytes[..len]);
        name.length = len as u8;
        name
    }

    /// Get as string slice
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.chars[..self.length as usize]).unwrap_or("")
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Compare with string (case-insensitive)
    pub fn equals_ignore_case(&self, s: &str) -> bool {
        let self_str = self.as_str();
        if self_str.len() != s.len() {
            return false;
        }
        self_str.chars().zip(s.chars()).all(|(a, b)| {
            a.to_ascii_lowercase() == b.to_ascii_lowercase()
        })
    }
}

impl Default for CmKeyName {
    fn default() -> Self {
        Self::empty()
    }
}

/// Registry key node
#[repr(C)]
pub struct CmKeyNode {
    /// Key name
    pub name: CmKeyName,

    /// Key flags
    pub flags: AtomicU32,

    /// Parent key index (u32::MAX if root)
    pub parent: u32,

    /// Hive index this key belongs to
    pub hive_index: u16,

    /// Number of subkeys
    pub subkey_count: u16,

    /// Number of values
    pub value_count: u16,

    /// Reserved
    _reserved: u16,

    /// Subkey indices
    pub subkeys: [u32; MAX_SUBKEYS_PER_KEY],

    /// Values
    pub values: [CmKeyValue; MAX_VALUES_PER_KEY],

    /// Last write time (ticks)
    pub last_write_time: u64,

    /// Security descriptor index
    pub security_index: u32,

    /// Class name offset (for class-named keys)
    pub class_offset: u32,
}

impl CmKeyNode {
    /// Create an empty key node
    pub const fn empty() -> Self {
        Self {
            name: CmKeyName::empty(),
            flags: AtomicU32::new(0),
            parent: u32::MAX,
            hive_index: 0,
            subkey_count: 0,
            value_count: 0,
            _reserved: 0,
            subkeys: [u32::MAX; MAX_SUBKEYS_PER_KEY],
            values: [CmKeyValue::empty(); MAX_VALUES_PER_KEY],
            last_write_time: 0,
            security_index: u32::MAX,
            class_offset: 0,
        }
    }

    /// Create a new key with name
    pub fn new(name: &str, parent: u32, hive_index: u16) -> Self {
        let mut key = Self::empty();
        key.name = CmKeyName::from_str(name);
        key.parent = parent;
        key.hive_index = hive_index;
        key.flags.store(key_flags::KEY_IN_USE, Ordering::SeqCst);
        key
    }

    /// Check if key is in use
    pub fn is_in_use(&self) -> bool {
        (self.flags.load(Ordering::SeqCst) & key_flags::KEY_IN_USE) != 0
    }

    /// Check if key is volatile
    pub fn is_volatile(&self) -> bool {
        (self.flags.load(Ordering::SeqCst) & key_flags::KEY_VOLATILE) != 0
    }

    /// Check if key is a hive root
    pub fn is_hive_root(&self) -> bool {
        (self.flags.load(Ordering::SeqCst) & key_flags::KEY_HIVE_ROOT) != 0
    }

    /// Set flag
    pub fn set_flag(&self, flag: u32) {
        self.flags.fetch_or(flag, Ordering::SeqCst);
    }

    /// Clear flag
    pub fn clear_flag(&self, flag: u32) {
        self.flags.fetch_and(!flag, Ordering::SeqCst);
    }

    /// Add a subkey
    pub fn add_subkey(&mut self, key_index: u32) -> bool {
        if self.subkey_count as usize >= MAX_SUBKEYS_PER_KEY {
            return false;
        }
        self.subkeys[self.subkey_count as usize] = key_index;
        self.subkey_count += 1;
        self.set_flag(key_flags::KEY_DIRTY);
        true
    }

    /// Remove a subkey
    pub fn remove_subkey(&mut self, key_index: u32) -> bool {
        for i in 0..self.subkey_count as usize {
            if self.subkeys[i] == key_index {
                // Shift remaining subkeys
                for j in i..(self.subkey_count as usize - 1) {
                    self.subkeys[j] = self.subkeys[j + 1];
                }
                self.subkey_count -= 1;
                self.subkeys[self.subkey_count as usize] = u32::MAX;
                self.set_flag(key_flags::KEY_DIRTY);
                return true;
            }
        }
        false
    }

    /// Find subkey by name
    pub fn find_subkey_index(&self, name: &str, keys: &[CmKeyNode]) -> Option<u32> {
        for i in 0..self.subkey_count as usize {
            let idx = self.subkeys[i] as usize;
            if idx < keys.len() && keys[idx].name.equals_ignore_case(name) {
                return Some(self.subkeys[i]);
            }
        }
        None
    }

    /// Add a value
    pub fn add_value(&mut self, value: CmKeyValue) -> bool {
        // Check if value with same name exists
        for i in 0..self.value_count as usize {
            if self.values[i].name.equals_ignore_case(value.name.as_str()) {
                // Replace existing value
                self.values[i] = value;
                self.set_flag(key_flags::KEY_DIRTY);
                return true;
            }
        }

        // Add new value
        if self.value_count as usize >= MAX_VALUES_PER_KEY {
            return false;
        }
        self.values[self.value_count as usize] = value;
        self.value_count += 1;
        self.set_flag(key_flags::KEY_DIRTY);
        true
    }

    /// Remove a value by name
    pub fn remove_value(&mut self, name: &str) -> bool {
        for i in 0..self.value_count as usize {
            if self.values[i].name.equals_ignore_case(name) {
                // Shift remaining values
                for j in i..(self.value_count as usize - 1) {
                    self.values[j] = self.values[j + 1];
                }
                self.value_count -= 1;
                self.values[self.value_count as usize].clear();
                self.set_flag(key_flags::KEY_DIRTY);
                return true;
            }
        }
        false
    }

    /// Find a value by name
    pub fn find_value(&self, name: &str) -> Option<&CmKeyValue> {
        for i in 0..self.value_count as usize {
            if self.values[i].name.equals_ignore_case(name) {
                return Some(&self.values[i]);
            }
        }
        None
    }

    /// Find a value by name (mutable)
    pub fn find_value_mut(&mut self, name: &str) -> Option<&mut CmKeyValue> {
        for i in 0..self.value_count as usize {
            if self.values[i].name.equals_ignore_case(name) {
                return Some(&mut self.values[i]);
            }
        }
        None
    }

    /// Get the default value (empty name)
    pub fn get_default_value(&self) -> Option<&CmKeyValue> {
        self.find_value("")
    }

    /// Set the default value
    pub fn set_default_value(&mut self, value: CmKeyValue) -> bool {
        let mut val = value;
        val.name = super::value::CmValueName::empty();
        self.add_value(val)
    }

    /// Clear the key
    pub fn clear(&mut self) {
        *self = Self::empty();
    }

    /// Get subkey count
    pub fn subkey_count(&self) -> usize {
        self.subkey_count as usize
    }

    /// Get value count
    pub fn value_count(&self) -> usize {
        self.value_count as usize
    }

    /// Enumerate subkeys
    pub fn enumerate_subkeys(&self) -> &[u32] {
        &self.subkeys[..self.subkey_count as usize]
    }

    /// Enumerate values
    pub fn enumerate_values(&self) -> &[CmKeyValue] {
        &self.values[..self.value_count as usize]
    }
}

impl Default for CmKeyNode {
    fn default() -> Self {
        Self::empty()
    }
}

// Safety: Key uses atomics for flags
unsafe impl Sync for CmKeyNode {}
unsafe impl Send for CmKeyNode {}

// ============================================================================
// Key Pool
// ============================================================================

use crate::ke::SpinLock;

/// Key pool
static mut KEY_POOL: [CmKeyNode; MAX_KEYS] = {
    const INIT: CmKeyNode = CmKeyNode::empty();
    [INIT; MAX_KEYS]
};

/// Key allocation bitmap
static mut KEY_BITMAP: [u64; (MAX_KEYS + 63) / 64] = [0; (MAX_KEYS + 63) / 64];

/// Key pool lock
static KEY_POOL_LOCK: SpinLock<()> = SpinLock::new(());

/// Free key count
static FREE_KEY_COUNT: AtomicU32 = AtomicU32::new(MAX_KEYS as u32);

/// Allocate a key from the pool
pub unsafe fn cm_allocate_key() -> Option<u32> {
    let _guard = KEY_POOL_LOCK.lock();

    // Find a free slot
    for (word_idx, word) in KEY_BITMAP.iter_mut().enumerate() {
        if *word != u64::MAX {
            let bit_idx = (!*word).trailing_zeros() as usize;
            let key_idx = word_idx * 64 + bit_idx;

            if key_idx >= MAX_KEYS {
                break;
            }

            // Mark as allocated
            *word |= 1u64 << bit_idx;
            FREE_KEY_COUNT.fetch_sub(1, Ordering::SeqCst);

            return Some(key_idx as u32);
        }
    }

    None
}

/// Free a key back to the pool
pub unsafe fn cm_free_key(key_index: u32) {
    if key_index as usize >= MAX_KEYS {
        return;
    }

    let _guard = KEY_POOL_LOCK.lock();

    // Clear the key
    KEY_POOL[key_index as usize].clear();

    // Mark as free
    let word_idx = key_index as usize / 64;
    let bit_idx = key_index as usize % 64;
    KEY_BITMAP[word_idx] &= !(1u64 << bit_idx);
    FREE_KEY_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Get a key by index
pub unsafe fn cm_get_key(key_index: u32) -> Option<&'static CmKeyNode> {
    if key_index as usize >= MAX_KEYS {
        return None;
    }
    let key = &KEY_POOL[key_index as usize];
    if key.is_in_use() {
        Some(key)
    } else {
        None
    }
}

/// Get a mutable key by index
pub unsafe fn cm_get_key_mut(key_index: u32) -> Option<&'static mut CmKeyNode> {
    if key_index as usize >= MAX_KEYS {
        return None;
    }
    let key = &mut KEY_POOL[key_index as usize];
    if key.is_in_use() {
        Some(key)
    } else {
        None
    }
}

/// Get the key pool (for internal use)
pub unsafe fn cm_get_key_pool() -> &'static [CmKeyNode] {
    &KEY_POOL
}

/// Get mutable key pool
pub unsafe fn cm_get_key_pool_mut() -> &'static mut [CmKeyNode] {
    &mut KEY_POOL
}

/// Get key statistics
pub fn cm_get_key_stats() -> CmKeyStats {
    let free = FREE_KEY_COUNT.load(Ordering::SeqCst);
    CmKeyStats {
        total_keys: MAX_KEYS as u32,
        free_keys: free,
        allocated_keys: MAX_KEYS as u32 - free,
    }
}

/// Key statistics
#[derive(Debug, Clone, Copy)]
pub struct CmKeyStats {
    pub total_keys: u32,
    pub free_keys: u32,
    pub allocated_keys: u32,
}

/// Initialize key subsystem
pub fn init() {
    crate::serial_println!("[CM] Key subsystem initialized ({} keys available)", MAX_KEYS);
}
