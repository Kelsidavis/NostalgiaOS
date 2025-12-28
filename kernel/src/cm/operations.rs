//! Registry Operations
//!
//! High-level registry API modeled after NT's Zw/Nt functions:
//!
//! - `cm_open_key` - Open a registry key
//! - `cm_create_key` - Create or open a registry key
//! - `cm_close_key` - Close a registry key handle
//! - `cm_query_value` - Read a registry value
//! - `cm_set_value` - Write a registry value
//! - `cm_delete_key` - Delete a registry key
//! - `cm_delete_value` - Delete a registry value
//! - `cm_enumerate_key` - Enumerate subkeys
//! - `cm_enumerate_value` - Enumerate values

use super::key::{
    CmKeyNode,
    cm_allocate_key, cm_free_key, cm_get_key, cm_get_key_mut,
    key_flags,
};
use super::value::CmKeyValue;
use super::hive::{cm_get_hive, cm_get_hive_mut, hive_indices};

/// Registry status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CmStatus {
    /// Operation succeeded
    Success = 0,
    /// Key not found
    KeyNotFound = -1,
    /// Value not found
    ValueNotFound = -2,
    /// Access denied
    AccessDenied = -3,
    /// Key already exists
    KeyExists = -4,
    /// Invalid parameter
    InvalidParameter = -5,
    /// Buffer too small
    BufferTooSmall = -6,
    /// No more entries
    NoMoreEntries = -7,
    /// Out of memory
    OutOfMemory = -8,
    /// Invalid key
    InvalidKey = -9,
    /// Key has subkeys
    KeyHasSubkeys = -10,
    /// Registry I/O error
    IoError = -11,
}

impl CmStatus {
    pub fn is_success(&self) -> bool {
        *self == CmStatus::Success
    }

    pub fn is_error(&self) -> bool {
        *self != CmStatus::Success
    }
}

/// Key handle (just wraps key index for now)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmKeyHandle(u32);

impl CmKeyHandle {
    pub const INVALID: CmKeyHandle = CmKeyHandle(u32::MAX);

    pub fn new(index: u32) -> Self {
        Self(index)
    }

    pub fn index(&self) -> u32 {
        self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0 != u32::MAX
    }
}

/// Well-known root key handles
pub mod root_keys {
    use super::CmKeyHandle;

    /// HKEY_LOCAL_MACHINE - placeholder, resolved at runtime
    pub const HKLM: CmKeyHandle = CmKeyHandle(0x80000002);
    /// HKEY_USERS - placeholder
    pub const HKU: CmKeyHandle = CmKeyHandle(0x80000003);
    /// HKEY_CURRENT_USER - placeholder
    pub const HKCU: CmKeyHandle = CmKeyHandle(0x80000001);
    /// HKEY_CLASSES_ROOT - placeholder
    pub const HKCR: CmKeyHandle = CmKeyHandle(0x80000000);
    /// HKEY_CURRENT_CONFIG - placeholder
    pub const HKCC: CmKeyHandle = CmKeyHandle(0x80000005);
}

/// Disposition flags for create operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CmDisposition {
    /// New key was created
    CreatedNew = 1,
    /// Existing key was opened
    OpenedExisting = 2,
}

/// Open options
pub mod open_options {
    /// Create a volatile key (not persisted)
    pub const REG_OPTION_VOLATILE: u32 = 0x0001;
    /// Create a symbolic link
    pub const REG_OPTION_CREATE_LINK: u32 = 0x0002;
    /// Don't virtualize this key
    pub const REG_OPTION_DONT_VIRTUALIZE: u32 = 0x0004;
}

/// Access rights
pub mod access_rights {
    pub const KEY_QUERY_VALUE: u32 = 0x0001;
    pub const KEY_SET_VALUE: u32 = 0x0002;
    pub const KEY_CREATE_SUB_KEY: u32 = 0x0004;
    pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
    pub const KEY_NOTIFY: u32 = 0x0010;
    pub const KEY_CREATE_LINK: u32 = 0x0020;

    pub const KEY_READ: u32 = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY;
    pub const KEY_WRITE: u32 = KEY_SET_VALUE | KEY_CREATE_SUB_KEY;
    pub const KEY_EXECUTE: u32 = KEY_READ;
    pub const KEY_ALL_ACCESS: u32 = KEY_READ | KEY_WRITE | KEY_CREATE_LINK;
}

// ============================================================================
// Key Path Parsing
// ============================================================================

/// Parse a registry path into components
fn parse_path(path: &str) -> impl Iterator<Item = &str> {
    path.split('\\').filter(|s| !s.is_empty())
}

/// Resolve a root key path to hive and starting key
unsafe fn resolve_root_path(path: &str) -> Option<(u16, u32, &str)> {
    let path = path.trim_start_matches('\\');

    // Check for HKEY_LOCAL_MACHINE paths
    if path.starts_with("MACHINE\\") || path.eq_ignore_ascii_case("MACHINE") {
        let rest = path.strip_prefix("MACHINE\\").unwrap_or("");
        return resolve_hklm_path(rest);
    }

    // Check for system hive names directly
    if path.starts_with("SYSTEM\\") || path.eq_ignore_ascii_case("SYSTEM") {
        let hive = cm_get_hive(hive_indices::HIVE_SYSTEM)?;
        let rest = path.strip_prefix("SYSTEM\\").unwrap_or("");
        return Some((hive_indices::HIVE_SYSTEM, hive.root_key, rest));
    }

    if path.starts_with("SOFTWARE\\") || path.eq_ignore_ascii_case("SOFTWARE") {
        let hive = cm_get_hive(hive_indices::HIVE_SOFTWARE)?;
        let rest = path.strip_prefix("SOFTWARE\\").unwrap_or("");
        return Some((hive_indices::HIVE_SOFTWARE, hive.root_key, rest));
    }

    if path.starts_with("HARDWARE\\") || path.eq_ignore_ascii_case("HARDWARE") {
        let hive = cm_get_hive(hive_indices::HIVE_HARDWARE)?;
        let rest = path.strip_prefix("HARDWARE\\").unwrap_or("");
        return Some((hive_indices::HIVE_HARDWARE, hive.root_key, rest));
    }

    None
}

/// Resolve HKLM subpath
unsafe fn resolve_hklm_path(subpath: &str) -> Option<(u16, u32, &str)> {
    // Determine which hive based on first component
    let first = subpath.split('\\').next().unwrap_or("");

    if first.eq_ignore_ascii_case("SYSTEM") {
        let hive = cm_get_hive(hive_indices::HIVE_SYSTEM)?;
        let rest = subpath.strip_prefix("SYSTEM\\").unwrap_or("");
        return Some((hive_indices::HIVE_SYSTEM, hive.root_key, rest));
    }

    if first.eq_ignore_ascii_case("SOFTWARE") {
        let hive = cm_get_hive(hive_indices::HIVE_SOFTWARE)?;
        let rest = subpath.strip_prefix("SOFTWARE\\").unwrap_or("");
        return Some((hive_indices::HIVE_SOFTWARE, hive.root_key, rest));
    }

    if first.eq_ignore_ascii_case("HARDWARE") {
        let hive = cm_get_hive(hive_indices::HIVE_HARDWARE)?;
        let rest = subpath.strip_prefix("HARDWARE\\").unwrap_or("");
        return Some((hive_indices::HIVE_HARDWARE, hive.root_key, rest));
    }

    if first.eq_ignore_ascii_case("SAM") {
        let hive = cm_get_hive(hive_indices::HIVE_SAM)?;
        let rest = subpath.strip_prefix("SAM\\").unwrap_or("");
        return Some((hive_indices::HIVE_SAM, hive.root_key, rest));
    }

    if first.eq_ignore_ascii_case("SECURITY") {
        let hive = cm_get_hive(hive_indices::HIVE_SECURITY)?;
        let rest = subpath.strip_prefix("SECURITY\\").unwrap_or("");
        return Some((hive_indices::HIVE_SECURITY, hive.root_key, rest));
    }

    None
}

// ============================================================================
// Key Operations
// ============================================================================

/// Open a registry key by path
pub unsafe fn cm_open_key(path: &str) -> Result<CmKeyHandle, CmStatus> {
    let (hive_idx, start_key, subpath) = resolve_root_path(path)
        .ok_or(CmStatus::KeyNotFound)?;

    // Walk the path
    let mut current_key = start_key;

    if !subpath.is_empty() {
        let key_pool = super::key::cm_get_key_pool();

        for component in parse_path(subpath) {
            let key = cm_get_key(current_key).ok_or(CmStatus::KeyNotFound)?;
            current_key = key.find_subkey_index(component, key_pool)
                .ok_or(CmStatus::KeyNotFound)?;
        }
    }

    Ok(CmKeyHandle::new(current_key))
}

/// Create a registry key (or open if exists)
pub unsafe fn cm_create_key(
    path: &str,
    options: u32,
) -> Result<(CmKeyHandle, CmDisposition), CmStatus> {
    let (hive_idx, start_key, subpath) = resolve_root_path(path)
        .ok_or(CmStatus::KeyNotFound)?;

    if subpath.is_empty() {
        // Trying to create root key - just return it
        return Ok((CmKeyHandle::new(start_key), CmDisposition::OpenedExisting));
    }

    let key_pool = super::key::cm_get_key_pool_mut();
    let mut current_key = start_key;
    let mut created = false;

    for component in parse_path(subpath) {
        // Try to find existing subkey
        let found = {
            let key = &key_pool[current_key as usize];
            key.find_subkey_index(component, key_pool)
        };

        match found {
            Some(idx) => {
                current_key = idx;
            }
            None => {
                // Create new subkey
                let new_key_idx = cm_allocate_key().ok_or(CmStatus::OutOfMemory)?;

                // Initialize the key
                {
                    let new_key = &mut key_pool[new_key_idx as usize];
                    *new_key = CmKeyNode::new(component, current_key, hive_idx);

                    if (options & open_options::REG_OPTION_VOLATILE) != 0 {
                        new_key.set_flag(key_flags::KEY_VOLATILE);
                    }
                }

                // Add to parent
                let parent = &mut key_pool[current_key as usize];
                if !parent.add_subkey(new_key_idx) {
                    cm_free_key(new_key_idx);
                    return Err(CmStatus::OutOfMemory);
                }

                // Update hive stats
                if let Some(hive) = cm_get_hive_mut(hive_idx) {
                    hive.add_key();
                }

                current_key = new_key_idx;
                created = true;
            }
        }
    }

    let disposition = if created {
        CmDisposition::CreatedNew
    } else {
        CmDisposition::OpenedExisting
    };

    Ok((CmKeyHandle::new(current_key), disposition))
}

/// Close a registry key handle
pub fn cm_close_key(_handle: CmKeyHandle) -> CmStatus {
    // For now, handles don't need cleanup
    CmStatus::Success
}

/// Delete a registry key
pub unsafe fn cm_delete_key(path: &str) -> CmStatus {
    let handle = match cm_open_key(path) {
        Ok(h) => h,
        Err(e) => return e,
    };

    let key = match cm_get_key_mut(handle.index()) {
        Some(k) => k,
        None => return CmStatus::InvalidKey,
    };

    // Can't delete key with subkeys
    if key.subkey_count() > 0 {
        return CmStatus::KeyHasSubkeys;
    }

    // Can't delete hive roots
    if key.is_hive_root() {
        return CmStatus::AccessDenied;
    }

    let parent_idx = key.parent;
    let hive_idx = key.hive_index;

    // Remove from parent
    if parent_idx != u32::MAX {
        if let Some(parent) = cm_get_key_mut(parent_idx) {
            parent.remove_subkey(handle.index());
        }
    }

    // Free the key
    cm_free_key(handle.index());

    // Update hive stats
    if let Some(hive) = cm_get_hive_mut(hive_idx) {
        hive.remove_key();
    }

    CmStatus::Success
}

// ============================================================================
// Value Operations
// ============================================================================

/// Query a registry value
pub unsafe fn cm_query_value(
    handle: CmKeyHandle,
    value_name: &str,
) -> Result<CmKeyValue, CmStatus> {
    let key = cm_get_key(handle.index()).ok_or(CmStatus::InvalidKey)?;

    key.find_value(value_name)
        .cloned()
        .ok_or(CmStatus::ValueNotFound)
}

/// Set a registry value
pub unsafe fn cm_set_value(
    handle: CmKeyHandle,
    value: CmKeyValue,
) -> CmStatus {
    let key = cm_get_key_mut(handle.index()).ok_or(CmStatus::InvalidKey);
    let key = match key {
        Ok(k) => k,
        Err(e) => return e,
    };

    let hive_idx = key.hive_index;

    if key.add_value(value) {
        if let Some(hive) = cm_get_hive_mut(hive_idx) {
            hive.add_value();
        }
        CmStatus::Success
    } else {
        CmStatus::OutOfMemory
    }
}

/// Set a string value
pub unsafe fn cm_set_value_string(
    handle: CmKeyHandle,
    name: &str,
    value: &str,
) -> CmStatus {
    cm_set_value(handle, CmKeyValue::new_string(name, value))
}

/// Set a DWORD value
pub unsafe fn cm_set_value_dword(
    handle: CmKeyHandle,
    name: &str,
    value: u32,
) -> CmStatus {
    cm_set_value(handle, CmKeyValue::new_dword(name, value))
}

/// Set a QWORD value
pub unsafe fn cm_set_value_qword(
    handle: CmKeyHandle,
    name: &str,
    value: u64,
) -> CmStatus {
    cm_set_value(handle, CmKeyValue::new_qword(name, value))
}

/// Delete a registry value
pub unsafe fn cm_delete_value(handle: CmKeyHandle, name: &str) -> CmStatus {
    let key = cm_get_key_mut(handle.index()).ok_or(CmStatus::InvalidKey);
    let key = match key {
        Ok(k) => k,
        Err(e) => return e,
    };

    let hive_idx = key.hive_index;

    if key.remove_value(name) {
        if let Some(hive) = cm_get_hive_mut(hive_idx) {
            hive.remove_value();
        }
        CmStatus::Success
    } else {
        CmStatus::ValueNotFound
    }
}

// ============================================================================
// Enumeration Operations
// ============================================================================

/// Enumerate subkeys
pub unsafe fn cm_enumerate_key(
    handle: CmKeyHandle,
    index: usize,
) -> Result<CmKeyHandle, CmStatus> {
    let key = cm_get_key(handle.index()).ok_or(CmStatus::InvalidKey)?;

    let subkeys = key.enumerate_subkeys();
    if index >= subkeys.len() {
        return Err(CmStatus::NoMoreEntries);
    }

    Ok(CmKeyHandle::new(subkeys[index]))
}

/// Get subkey name
pub unsafe fn cm_get_key_name(handle: CmKeyHandle) -> Option<&'static str> {
    let key = cm_get_key(handle.index())?;
    Some(key.name.as_str())
}

/// Enumerate values
pub unsafe fn cm_enumerate_value(
    handle: CmKeyHandle,
    index: usize,
) -> Result<&'static CmKeyValue, CmStatus> {
    let key = cm_get_key(handle.index()).ok_or(CmStatus::InvalidKey)?;

    let values = key.enumerate_values();
    if index >= values.len() {
        return Err(CmStatus::NoMoreEntries);
    }

    Ok(&values[index])
}

/// Get key information
pub unsafe fn cm_query_key_info(handle: CmKeyHandle) -> Result<CmKeyInfo, CmStatus> {
    let key = cm_get_key(handle.index()).ok_or(CmStatus::InvalidKey)?;

    Ok(CmKeyInfo {
        subkey_count: key.subkey_count(),
        value_count: key.value_count(),
        last_write_time: key.last_write_time,
        is_volatile: key.is_volatile(),
    })
}

/// Key information
#[derive(Debug, Clone, Copy)]
pub struct CmKeyInfo {
    pub subkey_count: usize,
    pub value_count: usize,
    pub last_write_time: u64,
    pub is_volatile: bool,
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Read a string value by path
/// Note: Returns a reference to the value in the global key pool
pub unsafe fn cm_read_string(path: &str, value_name: &str) -> Option<&'static str> {
    let handle = cm_open_key(path).ok()?;
    let key = cm_get_key(handle.index())?;
    let value = key.find_value(value_name)?;
    value.get_string()
}

/// Read a DWORD value by path
pub unsafe fn cm_read_dword(path: &str, value_name: &str) -> Option<u32> {
    let handle = cm_open_key(path).ok()?;
    let value = cm_query_value(handle, value_name).ok()?;
    value.get_dword()
}

/// Write a string value by path
pub unsafe fn cm_write_string(path: &str, value_name: &str, value: &str) -> CmStatus {
    let (handle, _) = match cm_create_key(path, 0) {
        Ok(h) => h,
        Err(e) => return e,
    };
    cm_set_value_string(handle, value_name, value)
}

/// Write a DWORD value by path
pub unsafe fn cm_write_dword(path: &str, value_name: &str, value: u32) -> CmStatus {
    let (handle, _) = match cm_create_key(path, 0) {
        Ok(h) => h,
        Err(e) => return e,
    };
    cm_set_value_dword(handle, value_name, value)
}

/// Initialize operations subsystem
pub fn init() {
    crate::serial_println!("[CM] Operations subsystem initialized");
}
