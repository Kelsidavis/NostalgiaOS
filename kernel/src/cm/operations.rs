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

extern crate alloc;

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
    let (_hive_idx, start_key, subpath) = resolve_root_path(path)
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

/// Get key last write time
pub unsafe fn cm_get_key_last_write_time(handle: CmKeyHandle) -> u64 {
    cm_get_key(handle.index())
        .map(|key| key.last_write_time)
        .unwrap_or(0)
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
// NT-Style Information Classes
// ============================================================================

/// Key information class for NtQueryKey/NtEnumerateKey
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyInformationClass {
    /// Basic key information (name, last write time)
    KeyBasicInformation = 0,
    /// Node information (name, class name, last write time)
    KeyNodeInformation = 1,
    /// Full information (name, class, subkey/value counts)
    KeyFullInformation = 2,
    /// Just the key name
    KeyNameInformation = 3,
    /// Cached key information
    KeyCachedInformation = 4,
    /// Key flags information
    KeyFlagsInformation = 5,
    /// Virtualization information
    KeyVirtualizationInformation = 6,
    /// Handle tags information
    KeyHandleTagsInformation = 7,
}

/// Value information class for NtQueryValueKey/NtEnumerateValueKey
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyValueInformationClass {
    /// Basic value information (name, type, data length)
    KeyValueBasicInformation = 0,
    /// Full information (name, type, data)
    KeyValueFullInformation = 1,
    /// Partial information (type, data only)
    KeyValuePartialInformation = 2,
    /// Partial information aligned to 64-bit
    KeyValuePartialInformationAlign64 = 3,
    /// Full information aligned to 64-bit
    KeyValueFullInformationAlign64 = 4,
}

/// Maximum name length for returned key/value info
pub const MAX_INFO_NAME_LENGTH: usize = 128;

/// Maximum class name length
pub const MAX_CLASS_NAME_LENGTH: usize = 64;

/// KEY_BASIC_INFORMATION structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KeyBasicInformation {
    /// Last write time (100-ns intervals since 1601)
    pub last_write_time: u64,
    /// Title index (usually 0)
    pub title_index: u32,
    /// Name length in bytes
    pub name_length: u32,
    /// Key name (variable length, up to MAX_INFO_NAME_LENGTH)
    pub name: [u8; MAX_INFO_NAME_LENGTH],
}

impl KeyBasicInformation {
    pub const fn empty() -> Self {
        Self {
            last_write_time: 0,
            title_index: 0,
            name_length: 0,
            name: [0; MAX_INFO_NAME_LENGTH],
        }
    }

    /// Get the name as a string slice
    pub fn get_name(&self) -> &str {
        let len = (self.name_length as usize).min(MAX_INFO_NAME_LENGTH);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }
}

/// KEY_NODE_INFORMATION structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KeyNodeInformation {
    /// Last write time
    pub last_write_time: u64,
    /// Title index
    pub title_index: u32,
    /// Offset to class name from structure start
    pub class_offset: u32,
    /// Class name length in bytes
    pub class_length: u32,
    /// Name length in bytes
    pub name_length: u32,
    /// Key name
    pub name: [u8; MAX_INFO_NAME_LENGTH],
    /// Class name
    pub class_name: [u8; MAX_CLASS_NAME_LENGTH],
}

impl KeyNodeInformation {
    pub const fn empty() -> Self {
        Self {
            last_write_time: 0,
            title_index: 0,
            class_offset: 0,
            class_length: 0,
            name_length: 0,
            name: [0; MAX_INFO_NAME_LENGTH],
            class_name: [0; MAX_CLASS_NAME_LENGTH],
        }
    }

    /// Get the name as a string slice
    pub fn get_name(&self) -> &str {
        let len = (self.name_length as usize).min(MAX_INFO_NAME_LENGTH);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    /// Get the class name as a string slice
    pub fn get_class_name(&self) -> &str {
        let len = (self.class_length as usize).min(MAX_CLASS_NAME_LENGTH);
        core::str::from_utf8(&self.class_name[..len]).unwrap_or("")
    }
}

/// KEY_FULL_INFORMATION structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KeyFullInformation {
    /// Last write time
    pub last_write_time: u64,
    /// Title index
    pub title_index: u32,
    /// Offset to class name
    pub class_offset: u32,
    /// Class name length
    pub class_length: u32,
    /// Number of subkeys
    pub subkey_count: u32,
    /// Maximum subkey name length
    pub max_subkey_name_length: u32,
    /// Maximum subkey class length
    pub max_subkey_class_length: u32,
    /// Number of values
    pub value_count: u32,
    /// Maximum value name length
    pub max_value_name_length: u32,
    /// Maximum value data length
    pub max_value_data_length: u32,
    /// Class name
    pub class_name: [u8; MAX_CLASS_NAME_LENGTH],
}

impl KeyFullInformation {
    pub const fn empty() -> Self {
        Self {
            last_write_time: 0,
            title_index: 0,
            class_offset: 0,
            class_length: 0,
            subkey_count: 0,
            max_subkey_name_length: 0,
            max_subkey_class_length: 0,
            value_count: 0,
            max_value_name_length: 0,
            max_value_data_length: 0,
            class_name: [0; MAX_CLASS_NAME_LENGTH],
        }
    }
}

/// KEY_NAME_INFORMATION structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KeyNameInformation {
    /// Name length in bytes
    pub name_length: u32,
    /// Key name
    pub name: [u8; MAX_INFO_NAME_LENGTH],
}

impl KeyNameInformation {
    pub const fn empty() -> Self {
        Self {
            name_length: 0,
            name: [0; MAX_INFO_NAME_LENGTH],
        }
    }

    /// Get the name as a string slice
    pub fn get_name(&self) -> &str {
        let len = (self.name_length as usize).min(MAX_INFO_NAME_LENGTH);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }
}

/// KEY_CACHED_INFORMATION structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KeyCachedInformation {
    /// Last write time
    pub last_write_time: u64,
    /// Title index
    pub title_index: u32,
    /// Number of subkeys
    pub subkey_count: u32,
    /// Maximum subkey name length
    pub max_subkey_name_length: u32,
    /// Number of values
    pub value_count: u32,
    /// Maximum value name length
    pub max_value_name_length: u32,
    /// Maximum value data length
    pub max_value_data_length: u32,
    /// Name length
    pub name_length: u32,
}

impl KeyCachedInformation {
    pub const fn empty() -> Self {
        Self {
            last_write_time: 0,
            title_index: 0,
            subkey_count: 0,
            max_subkey_name_length: 0,
            value_count: 0,
            max_value_name_length: 0,
            max_value_data_length: 0,
            name_length: 0,
        }
    }
}

/// Maximum value data in returned info
pub const MAX_INFO_VALUE_DATA: usize = 256;

/// KEY_VALUE_BASIC_INFORMATION structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KeyValueBasicInformation {
    /// Title index
    pub title_index: u32,
    /// Value type (REG_SZ, REG_DWORD, etc.)
    pub value_type: u32,
    /// Name length in bytes
    pub name_length: u32,
    /// Value name
    pub name: [u8; MAX_INFO_NAME_LENGTH],
}

impl KeyValueBasicInformation {
    pub const fn empty() -> Self {
        Self {
            title_index: 0,
            value_type: 0,
            name_length: 0,
            name: [0; MAX_INFO_NAME_LENGTH],
        }
    }

    /// Get the name as a string slice
    pub fn get_name(&self) -> &str {
        let len = (self.name_length as usize).min(MAX_INFO_NAME_LENGTH);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }
}

/// KEY_VALUE_FULL_INFORMATION structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KeyValueFullInformation {
    /// Title index
    pub title_index: u32,
    /// Value type
    pub value_type: u32,
    /// Offset to data from structure start
    pub data_offset: u32,
    /// Data length
    pub data_length: u32,
    /// Name length
    pub name_length: u32,
    /// Value name
    pub name: [u8; MAX_INFO_NAME_LENGTH],
    /// Value data
    pub data: [u8; MAX_INFO_VALUE_DATA],
}

impl KeyValueFullInformation {
    pub const fn empty() -> Self {
        Self {
            title_index: 0,
            value_type: 0,
            data_offset: 0,
            data_length: 0,
            name_length: 0,
            name: [0; MAX_INFO_NAME_LENGTH],
            data: [0; MAX_INFO_VALUE_DATA],
        }
    }

    /// Get the name as a string slice
    pub fn get_name(&self) -> &str {
        let len = (self.name_length as usize).min(MAX_INFO_NAME_LENGTH);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    /// Get the data bytes
    pub fn get_data(&self) -> &[u8] {
        let len = (self.data_length as usize).min(MAX_INFO_VALUE_DATA);
        &self.data[..len]
    }
}

/// KEY_VALUE_PARTIAL_INFORMATION structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KeyValuePartialInformation {
    /// Title index
    pub title_index: u32,
    /// Value type
    pub value_type: u32,
    /// Data length
    pub data_length: u32,
    /// Value data
    pub data: [u8; MAX_INFO_VALUE_DATA],
}

impl KeyValuePartialInformation {
    pub const fn empty() -> Self {
        Self {
            title_index: 0,
            value_type: 0,
            data_length: 0,
            data: [0; MAX_INFO_VALUE_DATA],
        }
    }

    /// Get the data bytes
    pub fn get_data(&self) -> &[u8] {
        let len = (self.data_length as usize).min(MAX_INFO_VALUE_DATA);
        &self.data[..len]
    }
}

// ============================================================================
// Enhanced Enumeration APIs (NT-Style)
// ============================================================================

/// Query key information (NtQueryKey equivalent)
pub unsafe fn cm_query_key_ex(
    handle: CmKeyHandle,
    info_class: KeyInformationClass,
) -> Result<KeyQueryResult, CmStatus> {
    let key = cm_get_key(handle.index()).ok_or(CmStatus::InvalidKey)?;
    let key_pool = super::key::cm_get_key_pool();

    match info_class {
        KeyInformationClass::KeyBasicInformation => {
            let mut info = KeyBasicInformation::empty();
            info.last_write_time = key.last_write_time;
            info.title_index = 0;

            let name = key.name.as_str();
            let name_bytes = name.as_bytes();
            let len = name_bytes.len().min(MAX_INFO_NAME_LENGTH);
            info.name[..len].copy_from_slice(&name_bytes[..len]);
            info.name_length = len as u32;

            Ok(KeyQueryResult::Basic(info))
        }
        KeyInformationClass::KeyNodeInformation => {
            let mut info = KeyNodeInformation::empty();
            info.last_write_time = key.last_write_time;
            info.title_index = 0;

            let name = key.name.as_str();
            let name_bytes = name.as_bytes();
            let len = name_bytes.len().min(MAX_INFO_NAME_LENGTH);
            info.name[..len].copy_from_slice(&name_bytes[..len]);
            info.name_length = len as u32;

            // Class name is typically empty for most keys
            info.class_offset = 0;
            info.class_length = 0;

            Ok(KeyQueryResult::Node(info))
        }
        KeyInformationClass::KeyFullInformation => {
            let mut info = KeyFullInformation::empty();
            info.last_write_time = key.last_write_time;
            info.title_index = 0;
            info.subkey_count = key.subkey_count as u32;
            info.value_count = key.value_count as u32;

            // Calculate max subkey name length
            let mut max_subkey_name = 0u32;
            for i in 0..key.subkey_count as usize {
                let subkey_idx = key.subkeys[i] as usize;
                if subkey_idx < key_pool.len() {
                    let name_len = key_pool[subkey_idx].name.length as u32;
                    if name_len > max_subkey_name {
                        max_subkey_name = name_len;
                    }
                }
            }
            info.max_subkey_name_length = max_subkey_name;
            info.max_subkey_class_length = 0;

            // Calculate max value name/data lengths
            let mut max_value_name = 0u32;
            let mut max_value_data = 0u32;
            for i in 0..key.value_count as usize {
                let name_len = key.values[i].name.length as u32;
                let data_len = key.values[i].data.size as u32;
                if name_len > max_value_name {
                    max_value_name = name_len;
                }
                if data_len > max_value_data {
                    max_value_data = data_len;
                }
            }
            info.max_value_name_length = max_value_name;
            info.max_value_data_length = max_value_data;

            Ok(KeyQueryResult::Full(info))
        }
        KeyInformationClass::KeyNameInformation => {
            let mut info = KeyNameInformation::empty();

            let name = key.name.as_str();
            let name_bytes = name.as_bytes();
            let len = name_bytes.len().min(MAX_INFO_NAME_LENGTH);
            info.name[..len].copy_from_slice(&name_bytes[..len]);
            info.name_length = len as u32;

            Ok(KeyQueryResult::Name(info))
        }
        KeyInformationClass::KeyCachedInformation => {
            let mut info = KeyCachedInformation::empty();
            info.last_write_time = key.last_write_time;
            info.title_index = 0;
            info.subkey_count = key.subkey_count as u32;
            info.value_count = key.value_count as u32;
            info.name_length = key.name.length as u32;

            // Calculate max lengths
            let mut max_subkey_name = 0u32;
            for i in 0..key.subkey_count as usize {
                let subkey_idx = key.subkeys[i] as usize;
                if subkey_idx < key_pool.len() {
                    let name_len = key_pool[subkey_idx].name.length as u32;
                    if name_len > max_subkey_name {
                        max_subkey_name = name_len;
                    }
                }
            }
            info.max_subkey_name_length = max_subkey_name;

            let mut max_value_name = 0u32;
            let mut max_value_data = 0u32;
            for i in 0..key.value_count as usize {
                let name_len = key.values[i].name.length as u32;
                let data_len = key.values[i].data.size as u32;
                if name_len > max_value_name {
                    max_value_name = name_len;
                }
                if data_len > max_value_data {
                    max_value_data = data_len;
                }
            }
            info.max_value_name_length = max_value_name;
            info.max_value_data_length = max_value_data;

            Ok(KeyQueryResult::Cached(info))
        }
        _ => Err(CmStatus::InvalidParameter),
    }
}

/// Result of key query
#[derive(Debug, Clone, Copy)]
pub enum KeyQueryResult {
    Basic(KeyBasicInformation),
    Node(KeyNodeInformation),
    Full(KeyFullInformation),
    Name(KeyNameInformation),
    Cached(KeyCachedInformation),
}

/// Enumerate key with information class (NtEnumerateKey equivalent)
pub unsafe fn cm_enumerate_key_ex(
    handle: CmKeyHandle,
    index: usize,
    info_class: KeyInformationClass,
) -> Result<KeyQueryResult, CmStatus> {
    let subkey_handle = cm_enumerate_key(handle, index)?;
    cm_query_key_ex(subkey_handle, info_class)
}

/// Query value with information class (NtQueryValueKey equivalent)
pub unsafe fn cm_query_value_ex(
    handle: CmKeyHandle,
    value_name: &str,
    info_class: KeyValueInformationClass,
) -> Result<ValueQueryResult, CmStatus> {
    let key = cm_get_key(handle.index()).ok_or(CmStatus::InvalidKey)?;
    let value = key.find_value(value_name).ok_or(CmStatus::ValueNotFound)?;

    match info_class {
        KeyValueInformationClass::KeyValueBasicInformation => {
            let mut info = KeyValueBasicInformation::empty();
            info.title_index = 0;
            info.value_type = value.value_type as u32;

            let name = value.name.as_str();
            let name_bytes = name.as_bytes();
            let len = name_bytes.len().min(MAX_INFO_NAME_LENGTH);
            info.name[..len].copy_from_slice(&name_bytes[..len]);
            info.name_length = len as u32;

            Ok(ValueQueryResult::Basic(info))
        }
        KeyValueInformationClass::KeyValueFullInformation
        | KeyValueInformationClass::KeyValueFullInformationAlign64 => {
            let mut info = KeyValueFullInformation::empty();
            info.title_index = 0;
            info.value_type = value.value_type as u32;

            let name = value.name.as_str();
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len().min(MAX_INFO_NAME_LENGTH);
            info.name[..name_len].copy_from_slice(&name_bytes[..name_len]);
            info.name_length = name_len as u32;

            let data_bytes = value.data.as_bytes();
            let data_len = data_bytes.len().min(MAX_INFO_VALUE_DATA);
            info.data[..data_len].copy_from_slice(&data_bytes[..data_len]);
            info.data_length = data_len as u32;
            info.data_offset = core::mem::size_of::<u32>() as u32 * 5
                + MAX_INFO_NAME_LENGTH as u32;

            Ok(ValueQueryResult::Full(info))
        }
        KeyValueInformationClass::KeyValuePartialInformation
        | KeyValueInformationClass::KeyValuePartialInformationAlign64 => {
            let mut info = KeyValuePartialInformation::empty();
            info.title_index = 0;
            info.value_type = value.value_type as u32;

            let data_bytes = value.data.as_bytes();
            let data_len = data_bytes.len().min(MAX_INFO_VALUE_DATA);
            info.data[..data_len].copy_from_slice(&data_bytes[..data_len]);
            info.data_length = data_len as u32;

            Ok(ValueQueryResult::Partial(info))
        }
    }
}

/// Result of value query
#[derive(Debug, Clone, Copy)]
pub enum ValueQueryResult {
    Basic(KeyValueBasicInformation),
    Full(KeyValueFullInformation),
    Partial(KeyValuePartialInformation),
}

/// Enumerate value with information class (NtEnumerateValueKey equivalent)
pub unsafe fn cm_enumerate_value_ex(
    handle: CmKeyHandle,
    index: usize,
    info_class: KeyValueInformationClass,
) -> Result<ValueQueryResult, CmStatus> {
    let key = cm_get_key(handle.index()).ok_or(CmStatus::InvalidKey)?;

    let values = key.enumerate_values();
    if index >= values.len() {
        return Err(CmStatus::NoMoreEntries);
    }

    let value = &values[index];

    match info_class {
        KeyValueInformationClass::KeyValueBasicInformation => {
            let mut info = KeyValueBasicInformation::empty();
            info.title_index = 0;
            info.value_type = value.value_type as u32;

            let name = value.name.as_str();
            let name_bytes = name.as_bytes();
            let len = name_bytes.len().min(MAX_INFO_NAME_LENGTH);
            info.name[..len].copy_from_slice(&name_bytes[..len]);
            info.name_length = len as u32;

            Ok(ValueQueryResult::Basic(info))
        }
        KeyValueInformationClass::KeyValueFullInformation
        | KeyValueInformationClass::KeyValueFullInformationAlign64 => {
            let mut info = KeyValueFullInformation::empty();
            info.title_index = 0;
            info.value_type = value.value_type as u32;

            let name = value.name.as_str();
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len().min(MAX_INFO_NAME_LENGTH);
            info.name[..name_len].copy_from_slice(&name_bytes[..name_len]);
            info.name_length = name_len as u32;

            let data_bytes = value.data.as_bytes();
            let data_len = data_bytes.len().min(MAX_INFO_VALUE_DATA);
            info.data[..data_len].copy_from_slice(&data_bytes[..data_len]);
            info.data_length = data_len as u32;
            info.data_offset = core::mem::size_of::<u32>() as u32 * 5
                + MAX_INFO_NAME_LENGTH as u32;

            Ok(ValueQueryResult::Full(info))
        }
        KeyValueInformationClass::KeyValuePartialInformation
        | KeyValueInformationClass::KeyValuePartialInformationAlign64 => {
            let mut info = KeyValuePartialInformation::empty();
            info.title_index = 0;
            info.value_type = value.value_type as u32;

            let data_bytes = value.data.as_bytes();
            let data_len = data_bytes.len().min(MAX_INFO_VALUE_DATA);
            info.data[..data_len].copy_from_slice(&data_bytes[..data_len]);
            info.data_length = data_len as u32;

            Ok(ValueQueryResult::Partial(info))
        }
    }
}

/// Get full key path (useful for debugging)
pub unsafe fn cm_get_key_full_path(handle: CmKeyHandle) -> Option<alloc::string::String> {
    use alloc::string::String;
    use alloc::vec::Vec;

    let mut path_parts: Vec<&str> = Vec::new();
    let mut current = handle.index();

    // Walk up the key tree
    while current != u32::MAX {
        let key = cm_get_key(current)?;
        path_parts.push(key.name.as_str());
        current = key.parent;
    }

    // Reverse and join
    path_parts.reverse();
    let path = path_parts.join("\\");
    Some(String::from("\\") + &path)
}

/// Count subkeys matching a pattern
pub unsafe fn cm_count_subkeys_matching(
    handle: CmKeyHandle,
    pattern: &str,
) -> Result<usize, CmStatus> {
    let key = cm_get_key(handle.index()).ok_or(CmStatus::InvalidKey)?;
    let key_pool = super::key::cm_get_key_pool();

    let mut count = 0;
    for i in 0..key.subkey_count as usize {
        let subkey_idx = key.subkeys[i] as usize;
        if subkey_idx < key_pool.len() {
            let subkey_name = key_pool[subkey_idx].name.as_str();
            if subkey_name.contains(pattern) {
                count += 1;
            }
        }
    }

    Ok(count)
}

/// Find subkey by name pattern
pub unsafe fn cm_find_subkey(
    handle: CmKeyHandle,
    name: &str,
) -> Result<CmKeyHandle, CmStatus> {
    let key = cm_get_key(handle.index()).ok_or(CmStatus::InvalidKey)?;
    let key_pool = super::key::cm_get_key_pool();

    let subkey_idx = key.find_subkey_index(name, key_pool)
        .ok_or(CmStatus::KeyNotFound)?;

    Ok(CmKeyHandle::new(subkey_idx))
}

/// Check if key has subkey with given name
pub unsafe fn cm_key_has_subkey(handle: CmKeyHandle, name: &str) -> bool {
    cm_find_subkey(handle, name).is_ok()
}

/// Check if key has value with given name
pub unsafe fn cm_key_has_value(handle: CmKeyHandle, name: &str) -> bool {
    if let Some(key) = cm_get_key(handle.index()) {
        key.find_value(name).is_some()
    } else {
        false
    }
}

/// Flush key (persist changes to disk)
pub unsafe fn cm_flush_key(handle: CmKeyHandle) -> CmStatus {
    let key = match cm_get_key_mut(handle.index()) {
        Some(k) => k,
        None => return CmStatus::InvalidKey,
    };

    // Clear dirty flag
    key.clear_flag(key_flags::KEY_DIRTY);

    // In a full implementation, this would write to the hive file
    CmStatus::Success
}

/// Notify on key change (placeholder for future implementation)
pub unsafe fn cm_notify_change_key(
    handle: CmKeyHandle,
    _watch_subtree: bool,
    _notify_filter: u32,
) -> CmStatus {
    if cm_get_key(handle.index()).is_none() {
        return CmStatus::InvalidKey;
    }

    // In a full implementation, this would set up change notification
    // For now, just return success
    CmStatus::Success
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
