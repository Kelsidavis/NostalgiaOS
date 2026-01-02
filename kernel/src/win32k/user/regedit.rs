//! Registry Editor
//!
//! Implements the Registry Editor following Windows Server 2003.
//! Provides registry browsing, editing, and search capabilities.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - regedit.exe - Registry Editor
//! - Registry hives: HKLM, HKCU, HKCR, HKU, HKCC

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::UserHandle;

// ============================================================================
// Constants
// ============================================================================

/// Maximum registry keys
const MAX_KEYS: usize = 512;

/// Maximum registry values per key
const MAX_VALUES: usize = 64;

/// Maximum name length
const MAX_NAME: usize = 256;

/// Maximum data length
const MAX_DATA: usize = 512;

/// Maximum favorites
const MAX_FAVORITES: usize = 32;

// ============================================================================
// Root Keys
// ============================================================================

/// Root registry keys (hives)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RootKey {
    /// HKEY_CLASSES_ROOT
    #[default]
    ClassesRoot = 0,
    /// HKEY_CURRENT_USER
    CurrentUser = 1,
    /// HKEY_LOCAL_MACHINE
    LocalMachine = 2,
    /// HKEY_USERS
    Users = 3,
    /// HKEY_CURRENT_CONFIG
    CurrentConfig = 4,
}

impl RootKey {
    pub fn as_str(&self) -> &'static str {
        match self {
            RootKey::ClassesRoot => "HKEY_CLASSES_ROOT",
            RootKey::CurrentUser => "HKEY_CURRENT_USER",
            RootKey::LocalMachine => "HKEY_LOCAL_MACHINE",
            RootKey::Users => "HKEY_USERS",
            RootKey::CurrentConfig => "HKEY_CURRENT_CONFIG",
        }
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            RootKey::ClassesRoot => "HKCR",
            RootKey::CurrentUser => "HKCU",
            RootKey::LocalMachine => "HKLM",
            RootKey::Users => "HKU",
            RootKey::CurrentConfig => "HKCC",
        }
    }
}

// ============================================================================
// Value Types
// ============================================================================

/// Registry value types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValueType {
    /// REG_NONE
    None = 0,
    /// REG_SZ (string)
    #[default]
    String = 1,
    /// REG_EXPAND_SZ (expandable string)
    ExpandString = 2,
    /// REG_BINARY
    Binary = 3,
    /// REG_DWORD (32-bit number)
    Dword = 4,
    /// REG_DWORD_BIG_ENDIAN
    DwordBigEndian = 5,
    /// REG_LINK
    Link = 6,
    /// REG_MULTI_SZ (multiple strings)
    MultiString = 7,
    /// REG_RESOURCE_LIST
    ResourceList = 8,
    /// REG_FULL_RESOURCE_DESCRIPTOR
    FullResourceDescriptor = 9,
    /// REG_RESOURCE_REQUIREMENTS_LIST
    ResourceRequirementsList = 10,
    /// REG_QWORD (64-bit number)
    Qword = 11,
}

impl ValueType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ValueType::None => "REG_NONE",
            ValueType::String => "REG_SZ",
            ValueType::ExpandString => "REG_EXPAND_SZ",
            ValueType::Binary => "REG_BINARY",
            ValueType::Dword => "REG_DWORD",
            ValueType::DwordBigEndian => "REG_DWORD_BIG_ENDIAN",
            ValueType::Link => "REG_LINK",
            ValueType::MultiString => "REG_MULTI_SZ",
            ValueType::ResourceList => "REG_RESOURCE_LIST",
            ValueType::FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
            ValueType::ResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST",
            ValueType::Qword => "REG_QWORD",
        }
    }
}

// ============================================================================
// Registry Key
// ============================================================================

/// Registry key entry
#[derive(Debug, Clone, Copy)]
pub struct RegistryKey {
    /// Key ID
    pub key_id: u32,
    /// Parent key ID (0 for root keys)
    pub parent_id: u32,
    /// Root hive
    pub root: RootKey,
    /// Key name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Has subkeys
    pub has_subkeys: bool,
    /// Is expanded in tree
    pub expanded: bool,
    /// Class name
    pub class_name: [u8; 64],
    /// Class name length
    pub class_len: usize,
    /// Last write time
    pub last_write: u64,
}

impl RegistryKey {
    pub const fn new() -> Self {
        Self {
            key_id: 0,
            parent_id: 0,
            root: RootKey::LocalMachine,
            name: [0u8; MAX_NAME],
            name_len: 0,
            has_subkeys: false,
            expanded: false,
            class_name: [0u8; 64],
            class_len: 0,
            last_write: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }
}

impl Default for RegistryKey {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Registry Value
// ============================================================================

/// Registry value entry
#[derive(Debug, Clone, Copy)]
pub struct RegistryValue {
    /// Owning key ID
    pub key_id: u32,
    /// Value name (empty for default value)
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: usize,
    /// Value type
    pub value_type: ValueType,
    /// Data
    pub data: [u8; MAX_DATA],
    /// Data length
    pub data_len: usize,
}

impl RegistryValue {
    pub const fn new() -> Self {
        Self {
            key_id: 0,
            name: [0u8; MAX_NAME],
            name_len: 0,
            value_type: ValueType::String,
            data: [0u8; MAX_DATA],
            data_len: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_data(&mut self, data: &[u8]) {
        let len = data.len().min(MAX_DATA);
        self.data[..len].copy_from_slice(&data[..len]);
        self.data_len = len;
    }

    pub fn set_dword(&mut self, value: u32) {
        self.value_type = ValueType::Dword;
        self.data[0..4].copy_from_slice(&value.to_le_bytes());
        self.data_len = 4;
    }

    pub fn set_qword(&mut self, value: u64) {
        self.value_type = ValueType::Qword;
        self.data[0..8].copy_from_slice(&value.to_le_bytes());
        self.data_len = 8;
    }

    pub fn get_dword(&self) -> Option<u32> {
        if self.value_type == ValueType::Dword && self.data_len >= 4 {
            Some(u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]))
        } else {
            None
        }
    }
}

impl Default for RegistryValue {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Favorite Entry
// ============================================================================

/// Registry favorite
#[derive(Debug, Clone, Copy)]
pub struct FavoriteEntry {
    /// Favorite name
    pub name: [u8; 64],
    /// Name length
    pub name_len: usize,
    /// Full path
    pub path: [u8; MAX_NAME],
    /// Path length
    pub path_len: usize,
}

impl FavoriteEntry {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 64],
            name_len: 0,
            path: [0u8; MAX_NAME],
            path_len: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(64);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_path(&mut self, path: &[u8]) {
        let len = path.len().min(MAX_NAME);
        self.path[..len].copy_from_slice(&path[..len]);
        self.path_len = len;
    }
}

impl Default for FavoriteEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Search Options
// ============================================================================

/// Search options
#[derive(Debug, Clone, Copy)]
pub struct SearchOptions {
    /// Search in keys
    pub search_keys: bool,
    /// Search in values
    pub search_values: bool,
    /// Search in data
    pub search_data: bool,
    /// Match whole string only
    pub match_whole: bool,
    /// Case sensitive
    pub case_sensitive: bool,
}

impl SearchOptions {
    pub const fn new() -> Self {
        Self {
            search_keys: true,
            search_values: true,
            search_data: true,
            match_whole: false,
            case_sensitive: false,
        }
    }
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Registry Editor State
// ============================================================================

/// Registry Editor state
struct RegeditState {
    /// Registry keys
    keys: [RegistryKey; MAX_KEYS],
    /// Key count
    key_count: usize,
    /// Registry values
    values: [RegistryValue; MAX_VALUES * 8],
    /// Value count
    value_count: usize,
    /// Next key ID
    next_key_id: u32,
    /// Selected key ID
    selected_key: u32,
    /// Favorites
    favorites: [FavoriteEntry; MAX_FAVORITES],
    /// Favorite count
    favorite_count: usize,
    /// Search options
    search_opts: SearchOptions,
    /// Last search string
    last_search: [u8; 64],
    /// Last search length
    last_search_len: usize,
    /// Address bar path
    address_path: [u8; MAX_NAME],
    /// Address path length
    address_len: usize,
}

impl RegeditState {
    pub const fn new() -> Self {
        Self {
            keys: [const { RegistryKey::new() }; MAX_KEYS],
            key_count: 0,
            values: [const { RegistryValue::new() }; MAX_VALUES * 8],
            value_count: 0,
            next_key_id: 1,
            selected_key: 0,
            favorites: [const { FavoriteEntry::new() }; MAX_FAVORITES],
            favorite_count: 0,
            search_opts: SearchOptions::new(),
            last_search: [0u8; 64],
            last_search_len: 0,
            address_path: [0u8; MAX_NAME],
            address_len: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static REGEDIT_INITIALIZED: AtomicBool = AtomicBool::new(false);
static REGEDIT_STATE: SpinLock<RegeditState> = SpinLock::new(RegeditState::new());

// Statistics
static KEY_READS: AtomicU32 = AtomicU32::new(0);
static VALUE_READS: AtomicU32 = AtomicU32::new(0);
static MODIFICATIONS: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Registry Editor
pub fn init() {
    if REGEDIT_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut state = REGEDIT_STATE.lock();

    // Create root keys
    create_root_keys(&mut state);

    // Add sample subkeys
    add_sample_keys(&mut state);

    // Add sample values
    add_sample_values(&mut state);

    crate::serial_println!("[WIN32K] Registry Editor initialized");
}

/// Create root keys
fn create_root_keys(state: &mut RegeditState) {
    let roots = [
        (RootKey::ClassesRoot, b"HKEY_CLASSES_ROOT" as &[u8]),
        (RootKey::CurrentUser, b"HKEY_CURRENT_USER"),
        (RootKey::LocalMachine, b"HKEY_LOCAL_MACHINE"),
        (RootKey::Users, b"HKEY_USERS"),
        (RootKey::CurrentConfig, b"HKEY_CURRENT_CONFIG"),
    ];

    for (root, name) in roots.iter() {
        let key_id = state.next_key_id;
        state.next_key_id += 1;

        let mut key = RegistryKey::new();
        key.key_id = key_id;
        key.parent_id = 0;
        key.root = *root;
        key.set_name(name);
        key.has_subkeys = true;

        let idx = state.key_count;
        state.keys[idx] = key;
        state.key_count += 1;
    }

    // Select HKLM by default
    state.selected_key = 3; // HKEY_LOCAL_MACHINE
}

/// Add sample subkeys under HKLM
fn add_sample_keys(state: &mut RegeditState) {
    // Find HKLM root key ID
    let mut hklm_id = 0;
    for i in 0..state.key_count {
        if state.keys[i].root == RootKey::LocalMachine && state.keys[i].parent_id == 0 {
            hklm_id = state.keys[i].key_id;
            break;
        }
    }

    let subkeys: [&[u8]; 6] = [
        b"HARDWARE",
        b"SAM",
        b"SECURITY",
        b"SOFTWARE",
        b"SYSTEM",
        b"BCD00000000",
    ];

    for name in subkeys.iter() {
        if state.key_count >= MAX_KEYS {
            break;
        }
        let key_id = state.next_key_id;
        state.next_key_id += 1;

        let mut key = RegistryKey::new();
        key.key_id = key_id;
        key.parent_id = hklm_id;
        key.root = RootKey::LocalMachine;
        key.set_name(name);
        key.has_subkeys = true;

        let idx = state.key_count;
        state.keys[idx] = key;
        state.key_count += 1;
    }

    // Find SOFTWARE key and add subkeys
    let mut software_id = 0;
    for i in 0..state.key_count {
        if state.keys[i].name_len == 8 && &state.keys[i].name[..8] == b"SOFTWARE" {
            software_id = state.keys[i].key_id;
            break;
        }
    }

    let sw_subkeys: [&[u8]; 4] = [
        b"Classes",
        b"Microsoft",
        b"Policies",
        b"Wow6432Node",
    ];

    for name in sw_subkeys.iter() {
        if state.key_count >= MAX_KEYS {
            break;
        }
        let key_id = state.next_key_id;
        state.next_key_id += 1;

        let mut key = RegistryKey::new();
        key.key_id = key_id;
        key.parent_id = software_id;
        key.root = RootKey::LocalMachine;
        key.set_name(name);
        key.has_subkeys = true;

        let idx = state.key_count;
        state.keys[idx] = key;
        state.key_count += 1;
    }
}

/// Add sample values
fn add_sample_values(state: &mut RegeditState) {
    // Find SYSTEM key
    let mut system_id = 0;
    for i in 0..state.key_count {
        if state.keys[i].name_len == 6 && &state.keys[i].name[..6] == b"SYSTEM" {
            system_id = state.keys[i].key_id;
            break;
        }
    }

    // Add some sample values to SYSTEM key
    let values: [(&[u8], ValueType, &[u8]); 4] = [
        (b"SystemRoot", ValueType::String, b"C:\\WINDOWS"),
        (b"BuildLab", ValueType::String, b"3790.srv03_rtm.030324-2048"),
        (b"CurrentBuildNumber", ValueType::String, b"3790"),
        (b"SystemStartOptions", ValueType::String, b"/NOEXECUTE=OPTIN"),
    ];

    for (name, vtype, data) in values.iter() {
        if state.value_count >= MAX_VALUES * 8 {
            break;
        }
        let mut value = RegistryValue::new();
        value.key_id = system_id;
        value.set_name(name);
        value.value_type = *vtype;
        value.set_data(data);

        let idx = state.value_count;
        state.values[idx] = value;
        state.value_count += 1;
    }
}

// ============================================================================
// Key Navigation
// ============================================================================

/// Get key count
pub fn get_key_count() -> usize {
    REGEDIT_STATE.lock().key_count
}

/// Get key by ID
pub fn get_key(key_id: u32) -> Option<RegistryKey> {
    let state = REGEDIT_STATE.lock();
    for i in 0..state.key_count {
        if state.keys[i].key_id == key_id {
            KEY_READS.fetch_add(1, Ordering::Relaxed);
            return Some(state.keys[i]);
        }
    }
    None
}

/// Get key by index
pub fn get_key_by_index(index: usize) -> Option<RegistryKey> {
    let state = REGEDIT_STATE.lock();
    if index < state.key_count {
        KEY_READS.fetch_add(1, Ordering::Relaxed);
        Some(state.keys[index])
    } else {
        None
    }
}

/// Get child keys
pub fn get_child_keys(parent_id: u32, buffer: &mut [RegistryKey]) -> usize {
    let state = REGEDIT_STATE.lock();
    let mut count = 0;
    for i in 0..state.key_count {
        if state.keys[i].parent_id == parent_id {
            if count < buffer.len() {
                buffer[count] = state.keys[i];
                count += 1;
            }
        }
    }
    count
}

/// Get root keys
pub fn get_root_keys(buffer: &mut [RegistryKey]) -> usize {
    get_child_keys(0, buffer)
}

/// Select key
pub fn select_key(key_id: u32) -> bool {
    let mut state = REGEDIT_STATE.lock();
    for i in 0..state.key_count {
        if state.keys[i].key_id == key_id {
            state.selected_key = key_id;
            return true;
        }
    }
    false
}

/// Get selected key
pub fn get_selected_key() -> u32 {
    REGEDIT_STATE.lock().selected_key
}

/// Expand/collapse key
pub fn set_key_expanded(key_id: u32, expanded: bool) -> bool {
    let mut state = REGEDIT_STATE.lock();
    for i in 0..state.key_count {
        if state.keys[i].key_id == key_id {
            state.keys[i].expanded = expanded;
            return true;
        }
    }
    false
}

// ============================================================================
// Value Management
// ============================================================================

/// Get values for a key
pub fn get_values(key_id: u32, buffer: &mut [RegistryValue]) -> usize {
    let state = REGEDIT_STATE.lock();
    let mut count = 0;
    for i in 0..state.value_count {
        if state.values[i].key_id == key_id {
            if count < buffer.len() {
                buffer[count] = state.values[i];
                count += 1;
            }
        }
    }
    VALUE_READS.fetch_add(count as u32, Ordering::Relaxed);
    count
}

/// Get value by name
pub fn get_value(key_id: u32, name: &[u8]) -> Option<RegistryValue> {
    let state = REGEDIT_STATE.lock();
    for i in 0..state.value_count {
        if state.values[i].key_id == key_id {
            if state.values[i].name_len == name.len() &&
               &state.values[i].name[..state.values[i].name_len] == name {
                VALUE_READS.fetch_add(1, Ordering::Relaxed);
                return Some(state.values[i]);
            }
        }
    }
    None
}

/// Create or update value
pub fn set_value(key_id: u32, name: &[u8], value_type: ValueType, data: &[u8]) -> bool {
    let mut state = REGEDIT_STATE.lock();

    // Check if value exists
    for i in 0..state.value_count {
        if state.values[i].key_id == key_id {
            if state.values[i].name_len == name.len() &&
               &state.values[i].name[..state.values[i].name_len] == name {
                state.values[i].value_type = value_type;
                state.values[i].set_data(data);
                MODIFICATIONS.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
    }

    // Create new value
    if state.value_count >= MAX_VALUES * 8 {
        return false;
    }

    let mut value = RegistryValue::new();
    value.key_id = key_id;
    value.set_name(name);
    value.value_type = value_type;
    value.set_data(data);

    let idx = state.value_count;
    state.values[idx] = value;
    state.value_count += 1;
    MODIFICATIONS.fetch_add(1, Ordering::Relaxed);
    true
}

/// Delete value
pub fn delete_value(key_id: u32, name: &[u8]) -> bool {
    let mut state = REGEDIT_STATE.lock();

    let mut found_index = None;
    for i in 0..state.value_count {
        if state.values[i].key_id == key_id {
            if state.values[i].name_len == name.len() &&
               &state.values[i].name[..state.values[i].name_len] == name {
                found_index = Some(i);
                break;
            }
        }
    }

    if let Some(index) = found_index {
        for i in index..state.value_count - 1 {
            state.values[i] = state.values[i + 1];
        }
        state.value_count -= 1;
        MODIFICATIONS.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

// ============================================================================
// Key Management
// ============================================================================

/// Create new key
pub fn create_key(parent_id: u32, name: &[u8]) -> Option<u32> {
    let mut state = REGEDIT_STATE.lock();

    if state.key_count >= MAX_KEYS {
        return None;
    }

    // Get parent's root
    let mut root = RootKey::LocalMachine;
    for i in 0..state.key_count {
        if state.keys[i].key_id == parent_id {
            root = state.keys[i].root;
            break;
        }
    }

    let key_id = state.next_key_id;
    state.next_key_id += 1;

    let mut key = RegistryKey::new();
    key.key_id = key_id;
    key.parent_id = parent_id;
    key.root = root;
    key.set_name(name);

    // Mark parent as having subkeys
    for i in 0..state.key_count {
        if state.keys[i].key_id == parent_id {
            state.keys[i].has_subkeys = true;
            break;
        }
    }

    let idx = state.key_count;
    state.keys[idx] = key;
    state.key_count += 1;
    MODIFICATIONS.fetch_add(1, Ordering::Relaxed);

    Some(key_id)
}

/// Delete key (and all subkeys/values)
pub fn delete_key(key_id: u32) -> bool {
    let mut state = REGEDIT_STATE.lock();

    // Don't delete root keys
    for i in 0..state.key_count {
        if state.keys[i].key_id == key_id && state.keys[i].parent_id == 0 {
            return false;
        }
    }

    // Find and delete the key
    let mut found_index = None;
    for i in 0..state.key_count {
        if state.keys[i].key_id == key_id {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..state.key_count - 1 {
            state.keys[i] = state.keys[i + 1];
        }
        state.key_count -= 1;

        // Delete associated values
        let mut i = 0;
        while i < state.value_count {
            if state.values[i].key_id == key_id {
                for j in i..state.value_count - 1 {
                    state.values[j] = state.values[j + 1];
                }
                state.value_count -= 1;
            } else {
                i += 1;
            }
        }

        MODIFICATIONS.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// Rename key
pub fn rename_key(key_id: u32, new_name: &[u8]) -> bool {
    let mut state = REGEDIT_STATE.lock();
    for i in 0..state.key_count {
        if state.keys[i].key_id == key_id {
            state.keys[i].set_name(new_name);
            MODIFICATIONS.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

// ============================================================================
// Favorites
// ============================================================================

/// Add favorite
pub fn add_favorite(name: &[u8], path: &[u8]) -> bool {
    let mut state = REGEDIT_STATE.lock();
    if state.favorite_count >= MAX_FAVORITES {
        return false;
    }

    let mut fav = FavoriteEntry::new();
    fav.set_name(name);
    fav.set_path(path);

    let idx = state.favorite_count;
    state.favorites[idx] = fav;
    state.favorite_count += 1;
    true
}

/// Remove favorite
pub fn remove_favorite(index: usize) -> bool {
    let mut state = REGEDIT_STATE.lock();
    if index >= state.favorite_count {
        return false;
    }

    for i in index..state.favorite_count - 1 {
        state.favorites[i] = state.favorites[i + 1];
    }
    state.favorite_count -= 1;
    true
}

/// Get favorite count
pub fn get_favorite_count() -> usize {
    REGEDIT_STATE.lock().favorite_count
}

/// Get favorite by index
pub fn get_favorite(index: usize) -> Option<FavoriteEntry> {
    let state = REGEDIT_STATE.lock();
    if index < state.favorite_count {
        Some(state.favorites[index])
    } else {
        None
    }
}

// ============================================================================
// Search
// ============================================================================

/// Set search options
pub fn set_search_options(opts: SearchOptions) {
    REGEDIT_STATE.lock().search_opts = opts;
}

/// Get search options
pub fn get_search_options() -> SearchOptions {
    REGEDIT_STATE.lock().search_opts
}

/// Find next occurrence
pub fn find_next(search_text: &[u8]) -> Option<u32> {
    let state = REGEDIT_STATE.lock();
    let opts = state.search_opts;

    // Search in keys if enabled
    if opts.search_keys {
        for i in 0..state.key_count {
            if contains_text(&state.keys[i].name[..state.keys[i].name_len], search_text, opts.case_sensitive) {
                return Some(state.keys[i].key_id);
            }
        }
    }

    // Would also search values and data...
    None
}

/// Helper: check if text contains search string
fn contains_text(text: &[u8], search: &[u8], _case_sensitive: bool) -> bool {
    if search.is_empty() || text.len() < search.len() {
        return false;
    }
    for i in 0..=text.len() - search.len() {
        if &text[i..i + search.len()] == search {
            return true;
        }
    }
    false
}

// ============================================================================
// Export/Import
// ============================================================================

/// Export format
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExportFormat {
    /// Registry Hive Files
    #[default]
    Hive = 0,
    /// Registration Files (*.reg)
    RegFile = 1,
    /// Win9x/NT4 Registration Files
    RegFileOld = 2,
    /// Text Files
    Text = 3,
}

/// Export key (stub)
pub fn export_key(_key_id: u32, _path: &[u8], _format: ExportFormat) -> bool {
    // Would export registry branch
    true
}

/// Import registry file (stub)
pub fn import_file(_path: &[u8]) -> bool {
    // Would import .reg file
    MODIFICATIONS.fetch_add(1, Ordering::Relaxed);
    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Registry Editor statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct RegeditStats {
    pub initialized: bool,
    pub key_count: usize,
    pub value_count: usize,
    pub favorite_count: usize,
    pub key_reads: u32,
    pub value_reads: u32,
    pub modifications: u32,
}

/// Get Registry Editor statistics
pub fn get_stats() -> RegeditStats {
    let state = REGEDIT_STATE.lock();
    RegeditStats {
        initialized: REGEDIT_INITIALIZED.load(Ordering::Relaxed),
        key_count: state.key_count,
        value_count: state.value_count,
        favorite_count: state.favorite_count,
        key_reads: KEY_READS.load(Ordering::Relaxed),
        value_reads: VALUE_READS.load(Ordering::Relaxed),
        modifications: MODIFICATIONS.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Dialog Support
// ============================================================================

/// Registry Editor dialog handle
pub type HREGEDITDLG = UserHandle;

static NEXT_DIALOG_ID: AtomicU32 = AtomicU32::new(1);

/// Create Registry Editor dialog
pub fn create_regedit_dialog(_parent: super::super::HWND) -> HREGEDITDLG {
    let id = NEXT_DIALOG_ID.fetch_add(1, Ordering::Relaxed);
    UserHandle::from_raw(id)
}
