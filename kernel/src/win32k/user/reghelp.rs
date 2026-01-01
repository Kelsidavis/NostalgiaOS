//! Registry Helper Functions
//!
//! Windows shlwapi.h style registry helper functions.
//! Based on Windows Server 2003 shlwapi.h.
//!
//! # Features
//!
//! - Simplified registry key access
//! - Value reading/writing helpers
//! - Path and string value helpers
//! - Default value handling
//!
//! # References
//!
//! - `public/sdk/inc/shlwapi.h` - SHReg* functions

use crate::ke::spinlock::SpinLock;
use super::strhelp;

// ============================================================================
// Registry Key Constants
// ============================================================================

/// Predefined registry keys
pub const HKEY_CLASSES_ROOT: usize = 0x80000000;
pub const HKEY_CURRENT_USER: usize = 0x80000001;
pub const HKEY_LOCAL_MACHINE: usize = 0x80000002;
pub const HKEY_USERS: usize = 0x80000003;
pub const HKEY_PERFORMANCE_DATA: usize = 0x80000004;
pub const HKEY_CURRENT_CONFIG: usize = 0x80000005;
pub const HKEY_DYN_DATA: usize = 0x80000006;

/// Registry access rights
pub const KEY_QUERY_VALUE: u32 = 0x0001;
pub const KEY_SET_VALUE: u32 = 0x0002;
pub const KEY_CREATE_SUB_KEY: u32 = 0x0004;
pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
pub const KEY_NOTIFY: u32 = 0x0010;
pub const KEY_CREATE_LINK: u32 = 0x0020;
pub const KEY_WOW64_64KEY: u32 = 0x0100;
pub const KEY_WOW64_32KEY: u32 = 0x0200;

pub const KEY_READ: u32 = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY;
pub const KEY_WRITE: u32 = KEY_SET_VALUE | KEY_CREATE_SUB_KEY;
pub const KEY_ALL_ACCESS: u32 = KEY_READ | KEY_WRITE | KEY_CREATE_LINK;

/// Registry value types
pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_DWORD_LITTLE_ENDIAN: u32 = 4;
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_RESOURCE_LIST: u32 = 8;
pub const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 9;
pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
pub const REG_QWORD: u32 = 11;
pub const REG_QWORD_LITTLE_ENDIAN: u32 = 11;

// ============================================================================
// SHREGENUM Flags
// ============================================================================

/// SHRegEnumUSKey flags
pub const SHREGENUM_DEFAULT: u32 = 0x00000000;
pub const SHREGENUM_HKCU: u32 = 0x00000001;
pub const SHREGENUM_HKLM: u32 = 0x00000002;
pub const SHREGENUM_BOTH: u32 = 0x00000003;

// ============================================================================
// SHREGDEL Flags
// ============================================================================

/// SHRegDeleteUSValue flags
pub const SHREGDEL_DEFAULT: u32 = 0x00000000;
pub const SHREGDEL_HKCU: u32 = 0x00000001;
pub const SHREGDEL_HKLM: u32 = 0x00000002;
pub const SHREGDEL_BOTH: u32 = 0x00000003;

// ============================================================================
// SHREGSET Flags
// ============================================================================

/// SHRegSetUSValue flags
pub const SHREGSET_HKCU: u32 = 0x00000001;
pub const SHREGSET_FORCE_HKCU: u32 = 0x00000002;
pub const SHREGSET_HKLM: u32 = 0x00000004;
pub const SHREGSET_FORCE_HKLM: u32 = 0x00000008;
pub const SHREGSET_DEFAULT: u32 = SHREGSET_FORCE_HKCU | SHREGSET_HKLM;

// ============================================================================
// Registry Storage
// ============================================================================

/// Maximum registry keys
pub const MAX_REG_KEYS: usize = 128;

/// Maximum value name length
pub const MAX_VALUE_NAME: usize = 64;

/// Maximum value data length
pub const MAX_VALUE_DATA: usize = 256;

/// Maximum subkey name length
pub const MAX_KEY_NAME: usize = 128;

/// Registry value entry
#[derive(Clone)]
pub struct RegValue {
    /// Is this entry in use
    pub in_use: bool,
    /// Value name
    pub name: [u8; MAX_VALUE_NAME],
    /// Value type
    pub value_type: u32,
    /// Value data
    pub data: [u8; MAX_VALUE_DATA],
    /// Data length
    pub data_len: usize,
}

impl RegValue {
    /// Create empty value
    pub const fn new() -> Self {
        Self {
            in_use: false,
            name: [0; MAX_VALUE_NAME],
            value_type: REG_NONE,
            data: [0; MAX_VALUE_DATA],
            data_len: 0,
        }
    }

    /// Reset value
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Set string value
    pub fn set_string(&mut self, name: &[u8], value: &[u8]) {
        self.in_use = true;
        let name_len = strhelp::str_len(name).min(MAX_VALUE_NAME - 1);
        self.name[..name_len].copy_from_slice(&name[..name_len]);
        self.name[name_len] = 0;
        self.value_type = REG_SZ;
        let value_len = strhelp::str_len(value).min(MAX_VALUE_DATA - 1);
        self.data[..value_len].copy_from_slice(&value[..value_len]);
        self.data[value_len] = 0;
        self.data_len = value_len + 1;
    }

    /// Set DWORD value
    pub fn set_dword(&mut self, name: &[u8], value: u32) {
        self.in_use = true;
        let name_len = strhelp::str_len(name).min(MAX_VALUE_NAME - 1);
        self.name[..name_len].copy_from_slice(&name[..name_len]);
        self.name[name_len] = 0;
        self.value_type = REG_DWORD;
        self.data[0] = (value & 0xFF) as u8;
        self.data[1] = ((value >> 8) & 0xFF) as u8;
        self.data[2] = ((value >> 16) & 0xFF) as u8;
        self.data[3] = ((value >> 24) & 0xFF) as u8;
        self.data_len = 4;
    }

    /// Set binary value
    pub fn set_binary(&mut self, name: &[u8], value: &[u8]) {
        self.in_use = true;
        let name_len = strhelp::str_len(name).min(MAX_VALUE_NAME - 1);
        self.name[..name_len].copy_from_slice(&name[..name_len]);
        self.name[name_len] = 0;
        self.value_type = REG_BINARY;
        let value_len = value.len().min(MAX_VALUE_DATA);
        self.data[..value_len].copy_from_slice(&value[..value_len]);
        self.data_len = value_len;
    }

    /// Get DWORD value
    pub fn get_dword(&self) -> Option<u32> {
        if self.value_type == REG_DWORD && self.data_len >= 4 {
            Some(
                (self.data[0] as u32)
                    | ((self.data[1] as u32) << 8)
                    | ((self.data[2] as u32) << 16)
                    | ((self.data[3] as u32) << 24),
            )
        } else {
            None
        }
    }

    /// Get string value
    pub fn get_string(&self, buffer: &mut [u8]) -> usize {
        if self.value_type == REG_SZ || self.value_type == REG_EXPAND_SZ {
            let len = (self.data_len - 1).min(buffer.len());
            buffer[..len].copy_from_slice(&self.data[..len]);
            if len < buffer.len() {
                buffer[len] = 0;
            }
            len
        } else {
            0
        }
    }
}

/// Registry key entry
#[derive(Clone)]
pub struct RegKey {
    /// Is this entry in use
    pub in_use: bool,
    /// Parent key (predefined key or index)
    pub parent: usize,
    /// Key name
    pub name: [u8; MAX_KEY_NAME],
    /// Values
    pub values: [RegValue; 8],
    /// Value count
    pub value_count: usize,
}

impl RegKey {
    /// Create empty key
    pub const fn new() -> Self {
        Self {
            in_use: false,
            parent: 0,
            name: [0; MAX_KEY_NAME],
            values: [const { RegValue::new() }; 8],
            value_count: 0,
        }
    }

    /// Reset key
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Find value by name
    pub fn find_value(&self, name: &[u8]) -> Option<&RegValue> {
        for value in &self.values {
            if value.in_use && strhelp::str_cmp_i(&value.name, name) == 0 {
                return Some(value);
            }
        }
        None
    }

    /// Find value by name (mutable)
    pub fn find_value_mut(&mut self, name: &[u8]) -> Option<&mut RegValue> {
        for value in &mut self.values {
            if value.in_use && strhelp::str_cmp_i(&value.name, name) == 0 {
                return Some(value);
            }
        }
        None
    }

    /// Get or create value
    pub fn get_or_create_value(&mut self, name: &[u8]) -> Option<&mut RegValue> {
        // First try to find existing
        for i in 0..self.values.len() {
            if self.values[i].in_use && strhelp::str_cmp_i(&self.values[i].name, name) == 0 {
                return Some(&mut self.values[i]);
            }
        }

        // Create new
        for i in 0..self.values.len() {
            if !self.values[i].in_use {
                self.values[i].reset();
                self.values[i].in_use = true;
                let name_len = strhelp::str_len(name).min(MAX_VALUE_NAME - 1);
                self.values[i].name[..name_len].copy_from_slice(&name[..name_len]);
                self.values[i].name[name_len] = 0;
                self.value_count += 1;
                return Some(&mut self.values[i]);
            }
        }

        None
    }

    /// Delete value
    pub fn delete_value(&mut self, name: &[u8]) -> bool {
        for value in &mut self.values {
            if value.in_use && strhelp::str_cmp_i(&value.name, name) == 0 {
                value.reset();
                self.value_count -= 1;
                return true;
            }
        }
        false
    }
}

/// Registry handle
pub type HKEY = usize;

/// Invalid handle
pub const INVALID_HKEY: HKEY = 0;

// ============================================================================
// Global State
// ============================================================================

/// Global registry key storage
static REGISTRY: SpinLock<[RegKey; MAX_REG_KEYS]> =
    SpinLock::new([const { RegKey::new() }; MAX_REG_KEYS]);

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if handle is a predefined key
fn is_predefined_key(hkey: HKEY) -> bool {
    hkey >= HKEY_CLASSES_ROOT && hkey <= HKEY_DYN_DATA
}

/// Convert handle to index
fn hkey_to_index(hkey: HKEY) -> Option<usize> {
    if is_predefined_key(hkey) {
        None
    } else if hkey > 0 && hkey <= MAX_REG_KEYS {
        Some(hkey - 1)
    } else {
        None
    }
}

/// Convert index to handle
fn index_to_hkey(index: usize) -> HKEY {
    index + 1
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize registry helpers
pub fn init() {
    crate::serial_println!("[USER] Registry helpers initialized");
}

/// Open registry key
pub fn sh_reg_open_key(hkey: HKEY, subkey: &[u8], desired: u32, result: &mut HKEY) -> i32 {
    let _ = desired;
    let mut registry = REGISTRY.lock();

    // Search for matching key
    for (i, key) in registry.iter_mut().enumerate() {
        if key.in_use && key.parent == hkey && strhelp::str_cmp_i(&key.name, subkey) == 0 {
            *result = index_to_hkey(i);
            return 0; // ERROR_SUCCESS
        }
    }

    2 // ERROR_FILE_NOT_FOUND
}

/// Create registry key
pub fn sh_reg_create_key(hkey: HKEY, subkey: &[u8], desired: u32, result: &mut HKEY) -> i32 {
    let _ = desired;
    let mut registry = REGISTRY.lock();

    // Check if already exists
    for (i, key) in registry.iter().enumerate() {
        if key.in_use && key.parent == hkey && strhelp::str_cmp_i(&key.name, subkey) == 0 {
            *result = index_to_hkey(i);
            return 0;
        }
    }

    // Create new key
    for (i, key) in registry.iter_mut().enumerate() {
        if !key.in_use {
            key.reset();
            key.in_use = true;
            key.parent = hkey;
            let name_len = strhelp::str_len(subkey).min(MAX_KEY_NAME - 1);
            key.name[..name_len].copy_from_slice(&subkey[..name_len]);
            key.name[name_len] = 0;
            *result = index_to_hkey(i);
            return 0;
        }
    }

    8 // ERROR_NOT_ENOUGH_MEMORY
}

/// Close registry key
pub fn sh_reg_close_key(hkey: HKEY) -> i32 {
    // Predefined keys don't need to be closed
    if is_predefined_key(hkey) {
        return 0;
    }

    // Just return success (in our simplified model, keys persist)
    0
}

/// Query registry value
pub fn sh_reg_query_value(hkey: HKEY, value_name: &[u8], value_type: &mut u32, data: &mut [u8], data_len: &mut usize) -> i32 {
    let registry = REGISTRY.lock();

    // Find key
    if let Some(idx) = hkey_to_index(hkey) {
        if !registry[idx].in_use {
            return 2; // ERROR_FILE_NOT_FOUND
        }

        // Find value
        if let Some(value) = registry[idx].find_value(value_name) {
            *value_type = value.value_type;
            let copy_len = value.data_len.min(data.len());
            data[..copy_len].copy_from_slice(&value.data[..copy_len]);
            *data_len = value.data_len;
            return 0;
        }
    }

    2 // ERROR_FILE_NOT_FOUND
}

/// Set registry value
pub fn sh_reg_set_value(hkey: HKEY, value_name: &[u8], value_type: u32, data: &[u8]) -> i32 {
    let mut registry = REGISTRY.lock();

    // Find or create key
    if let Some(idx) = hkey_to_index(hkey) {
        if !registry[idx].in_use {
            return 2;
        }

        // Get or create value
        if let Some(value) = registry[idx].get_or_create_value(value_name) {
            value.value_type = value_type;
            let data_len = data.len().min(MAX_VALUE_DATA);
            value.data[..data_len].copy_from_slice(&data[..data_len]);
            value.data_len = data_len;
            return 0;
        }

        return 8; // ERROR_NOT_ENOUGH_MEMORY
    }

    2 // ERROR_FILE_NOT_FOUND
}

/// Delete registry value
pub fn sh_reg_delete_value(hkey: HKEY, value_name: &[u8]) -> i32 {
    let mut registry = REGISTRY.lock();

    if let Some(idx) = hkey_to_index(hkey) {
        if registry[idx].in_use && registry[idx].delete_value(value_name) {
            return 0;
        }
    }

    2
}

/// Delete registry key
pub fn sh_reg_delete_key(hkey: HKEY, subkey: &[u8]) -> i32 {
    let mut registry = REGISTRY.lock();

    for key in registry.iter_mut() {
        if key.in_use && key.parent == hkey && strhelp::str_cmp_i(&key.name, subkey) == 0 {
            key.reset();
            return 0;
        }
    }

    2
}

// ============================================================================
// Simplified Helper API (SHReg* style)
// ============================================================================

/// Get DWORD value with default
pub fn sh_reg_get_dword(hkey: HKEY, subkey: &[u8], value_name: &[u8], default: u32) -> u32 {
    let mut key_handle: HKEY = INVALID_HKEY;

    if sh_reg_open_key(hkey, subkey, KEY_READ, &mut key_handle) != 0 {
        return default;
    }

    let mut value_type: u32 = 0;
    let mut data = [0u8; 4];
    let mut data_len = 4;

    if sh_reg_query_value(key_handle, value_name, &mut value_type, &mut data, &mut data_len) != 0 {
        return default;
    }

    if value_type != REG_DWORD || data_len < 4 {
        return default;
    }

    (data[0] as u32)
        | ((data[1] as u32) << 8)
        | ((data[2] as u32) << 16)
        | ((data[3] as u32) << 24)
}

/// Get string value
pub fn sh_reg_get_string(hkey: HKEY, subkey: &[u8], value_name: &[u8], buffer: &mut [u8]) -> bool {
    let mut key_handle: HKEY = INVALID_HKEY;

    if sh_reg_open_key(hkey, subkey, KEY_READ, &mut key_handle) != 0 {
        return false;
    }

    let mut value_type: u32 = 0;
    let mut data_len = buffer.len();

    if sh_reg_query_value(key_handle, value_name, &mut value_type, buffer, &mut data_len) != 0 {
        return false;
    }

    value_type == REG_SZ || value_type == REG_EXPAND_SZ
}

/// Set DWORD value
pub fn sh_reg_set_dword(hkey: HKEY, subkey: &[u8], value_name: &[u8], value: u32) -> bool {
    let mut key_handle: HKEY = INVALID_HKEY;

    if sh_reg_create_key(hkey, subkey, KEY_WRITE, &mut key_handle) != 0 {
        return false;
    }

    let data = [
        (value & 0xFF) as u8,
        ((value >> 8) & 0xFF) as u8,
        ((value >> 16) & 0xFF) as u8,
        ((value >> 24) & 0xFF) as u8,
    ];

    sh_reg_set_value(key_handle, value_name, REG_DWORD, &data) == 0
}

/// Set string value
pub fn sh_reg_set_string(hkey: HKEY, subkey: &[u8], value_name: &[u8], value: &[u8]) -> bool {
    let mut key_handle: HKEY = INVALID_HKEY;

    if sh_reg_create_key(hkey, subkey, KEY_WRITE, &mut key_handle) != 0 {
        return false;
    }

    sh_reg_set_value(key_handle, value_name, REG_SZ, value) == 0
}

/// Check if key exists
pub fn sh_reg_key_exists(hkey: HKEY, subkey: &[u8]) -> bool {
    let mut key_handle: HKEY = INVALID_HKEY;
    sh_reg_open_key(hkey, subkey, KEY_READ, &mut key_handle) == 0
}

/// Check if value exists
pub fn sh_reg_value_exists(hkey: HKEY, subkey: &[u8], value_name: &[u8]) -> bool {
    let mut key_handle: HKEY = INVALID_HKEY;

    if sh_reg_open_key(hkey, subkey, KEY_READ, &mut key_handle) != 0 {
        return false;
    }

    let mut value_type: u32 = 0;
    let mut data = [0u8; 1];
    let mut data_len = 0;

    sh_reg_query_value(key_handle, value_name, &mut value_type, &mut data, &mut data_len) == 0
}

// ============================================================================
// User Settings Helper (HKCU Software path)
// ============================================================================

/// Read user setting DWORD
pub fn sh_reg_get_usr_value_dword(app_name: &[u8], value_name: &[u8], default: u32) -> u32 {
    // Build path: Software\<app_name>
    let mut path = [0u8; 128];
    strhelp::str_cpy(&mut path, b"Software\\");
    strhelp::str_cat(&mut path, app_name);

    sh_reg_get_dword(HKEY_CURRENT_USER, &path, value_name, default)
}

/// Write user setting DWORD
pub fn sh_reg_set_usr_value_dword(app_name: &[u8], value_name: &[u8], value: u32) -> bool {
    let mut path = [0u8; 128];
    strhelp::str_cpy(&mut path, b"Software\\");
    strhelp::str_cat(&mut path, app_name);

    sh_reg_set_dword(HKEY_CURRENT_USER, &path, value_name, value)
}

/// Read user setting string
pub fn sh_reg_get_usr_value_string(app_name: &[u8], value_name: &[u8], buffer: &mut [u8]) -> bool {
    let mut path = [0u8; 128];
    strhelp::str_cpy(&mut path, b"Software\\");
    strhelp::str_cat(&mut path, app_name);

    sh_reg_get_string(HKEY_CURRENT_USER, &path, value_name, buffer)
}

/// Write user setting string
pub fn sh_reg_set_usr_value_string(app_name: &[u8], value_name: &[u8], value: &[u8]) -> bool {
    let mut path = [0u8; 128];
    strhelp::str_cpy(&mut path, b"Software\\");
    strhelp::str_cat(&mut path, app_name);

    sh_reg_set_string(HKEY_CURRENT_USER, &path, value_name, value)
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> RegStats {
    let registry = REGISTRY.lock();

    let mut key_count = 0;
    let mut value_count = 0;

    for key in registry.iter() {
        if key.in_use {
            key_count += 1;
            value_count += key.value_count;
        }
    }

    RegStats {
        max_keys: MAX_REG_KEYS,
        used_keys: key_count,
        total_values: value_count,
    }
}

/// Registry statistics
#[derive(Debug, Clone, Copy)]
pub struct RegStats {
    pub max_keys: usize,
    pub used_keys: usize,
    pub total_values: usize,
}
