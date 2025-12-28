//! Registry Hives
//!
//! A hive is a discrete body of registry keys, subkeys, and values.
//! The registry is composed of multiple hives:
//!
//! # System Hives (HKEY_LOCAL_MACHINE)
//! - SYSTEM: Boot configuration, drivers, services
//! - SOFTWARE: Installed software settings
//! - SAM: Security Accounts Manager
//! - SECURITY: Security policy
//! - HARDWARE: Hardware descriptions (volatile)
//!
//! # User Hives (HKEY_USERS)
//! - DEFAULT: Default user profile
//! - .DEFAULT: System services
//! - S-1-5-xx: User SIDs
//!
//! # Volatile Hives
//! - HARDWARE: Rebuilt each boot
//! - SYSTEM\CurrentControlSet: Active control set

use core::sync::atomic::{AtomicU32, Ordering};
use crate::ke::SpinLock;
use super::key::{CmKeyNode, cm_allocate_key, cm_get_key_mut, cm_get_key_pool_mut, key_flags};
use super::cell::CmCellTable;

/// Maximum number of hives
pub const MAX_HIVES: usize = 16;

/// Maximum hive name length
pub const MAX_HIVE_NAME_LENGTH: usize = 32;

/// Hive types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CmHiveType {
    /// Primary hive (SYSTEM, SOFTWARE, etc.)
    Primary = 0,
    /// Volatile hive (in-memory only)
    Volatile = 1,
    /// User hive
    User = 2,
    /// Alternate hive (backup)
    Alternate = 3,
}

impl Default for CmHiveType {
    fn default() -> Self {
        Self::Primary
    }
}

/// Well-known hive indices
pub mod hive_indices {
    /// HKEY_LOCAL_MACHINE\SYSTEM
    pub const HIVE_SYSTEM: u16 = 0;
    /// HKEY_LOCAL_MACHINE\SOFTWARE
    pub const HIVE_SOFTWARE: u16 = 1;
    /// HKEY_LOCAL_MACHINE\HARDWARE
    pub const HIVE_HARDWARE: u16 = 2;
    /// HKEY_LOCAL_MACHINE\SAM
    pub const HIVE_SAM: u16 = 3;
    /// HKEY_LOCAL_MACHINE\SECURITY
    pub const HIVE_SECURITY: u16 = 4;
    /// HKEY_USERS\.DEFAULT
    pub const HIVE_DEFAULT: u16 = 5;
}

/// Hive flags
pub mod hive_flags {
    /// Hive is loaded
    pub const HIVE_LOADED: u32 = 0x0001;
    /// Hive is volatile
    pub const HIVE_VOLATILE: u32 = 0x0002;
    /// Hive is dirty (needs flush)
    pub const HIVE_DIRTY: u32 = 0x0004;
    /// Hive is read-only
    pub const HIVE_READONLY: u32 = 0x0008;
    /// Hive is being initialized
    pub const HIVE_INITIALIZING: u32 = 0x0010;
    /// Hive is a system hive
    pub const HIVE_SYSTEM: u32 = 0x0020;
}

/// Hive name
#[derive(Clone, Copy)]
pub struct CmHiveName {
    pub chars: [u8; MAX_HIVE_NAME_LENGTH],
    pub length: u8,
}

impl CmHiveName {
    pub const fn empty() -> Self {
        Self {
            chars: [0; MAX_HIVE_NAME_LENGTH],
            length: 0,
        }
    }

    pub fn from_str(s: &str) -> Self {
        let mut name = Self::empty();
        let bytes = s.as_bytes();
        let len = bytes.len().min(MAX_HIVE_NAME_LENGTH);
        name.chars[..len].copy_from_slice(&bytes[..len]);
        name.length = len as u8;
        name
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.chars[..self.length as usize]).unwrap_or("")
    }
}

impl Default for CmHiveName {
    fn default() -> Self {
        Self::empty()
    }
}

/// Registry Hive
#[repr(C)]
pub struct CmHive {
    /// Hive name (e.g., "SYSTEM", "SOFTWARE")
    pub name: CmHiveName,

    /// Hive type
    pub hive_type: CmHiveType,

    /// Hive flags
    pub flags: AtomicU32,

    /// Root key index in global key pool
    pub root_key: u32,

    /// Hive index (for quick lookup)
    pub hive_index: u16,

    /// Reserved
    _reserved: u16,

    /// Cell table for this hive
    pub cells: CmCellTable,

    /// Statistics
    pub key_count: AtomicU32,
    pub value_count: AtomicU32,

    /// Last flush time
    pub last_flush_time: u64,

    /// Modification sequence number
    pub sequence: AtomicU32,
}

impl CmHive {
    /// Create an empty hive
    pub const fn empty() -> Self {
        Self {
            name: CmHiveName::empty(),
            hive_type: CmHiveType::Primary,
            flags: AtomicU32::new(0),
            root_key: u32::MAX,
            hive_index: 0,
            _reserved: 0,
            cells: CmCellTable::new(),
            key_count: AtomicU32::new(0),
            value_count: AtomicU32::new(0),
            last_flush_time: 0,
            sequence: AtomicU32::new(0),
        }
    }

    /// Check if hive is loaded
    pub fn is_loaded(&self) -> bool {
        (self.flags.load(Ordering::SeqCst) & hive_flags::HIVE_LOADED) != 0
    }

    /// Check if hive is volatile
    pub fn is_volatile(&self) -> bool {
        (self.flags.load(Ordering::SeqCst) & hive_flags::HIVE_VOLATILE) != 0
    }

    /// Check if hive is dirty
    pub fn is_dirty(&self) -> bool {
        (self.flags.load(Ordering::SeqCst) & hive_flags::HIVE_DIRTY) != 0
    }

    /// Set flag
    pub fn set_flag(&self, flag: u32) {
        self.flags.fetch_or(flag, Ordering::SeqCst);
    }

    /// Clear flag
    pub fn clear_flag(&self, flag: u32) {
        self.flags.fetch_and(!flag, Ordering::SeqCst);
    }

    /// Get root key
    pub unsafe fn get_root_key(&self) -> Option<&'static CmKeyNode> {
        super::key::cm_get_key(self.root_key)
    }

    /// Get mutable root key
    pub unsafe fn get_root_key_mut(&self) -> Option<&'static mut CmKeyNode> {
        super::key::cm_get_key_mut(self.root_key)
    }

    /// Increment key count
    pub fn add_key(&self) {
        self.key_count.fetch_add(1, Ordering::SeqCst);
        self.set_flag(hive_flags::HIVE_DIRTY);
    }

    /// Decrement key count
    pub fn remove_key(&self) {
        self.key_count.fetch_sub(1, Ordering::SeqCst);
        self.set_flag(hive_flags::HIVE_DIRTY);
    }

    /// Increment value count
    pub fn add_value(&self) {
        self.value_count.fetch_add(1, Ordering::SeqCst);
        self.set_flag(hive_flags::HIVE_DIRTY);
    }

    /// Decrement value count
    pub fn remove_value(&self) {
        self.value_count.fetch_sub(1, Ordering::SeqCst);
        self.set_flag(hive_flags::HIVE_DIRTY);
    }

    /// Get statistics
    pub fn stats(&self) -> CmHiveStats {
        CmHiveStats {
            key_count: self.key_count.load(Ordering::SeqCst),
            value_count: self.value_count.load(Ordering::SeqCst),
            cell_stats: self.cells.stats(),
        }
    }

    /// Clear the hive
    pub fn clear(&mut self) {
        *self = Self::empty();
    }
}

impl Default for CmHive {
    fn default() -> Self {
        Self::empty()
    }
}

// Safety: Hive uses atomics for thread safety
unsafe impl Sync for CmHive {}
unsafe impl Send for CmHive {}

/// Hive statistics
#[derive(Debug, Clone, Copy)]
pub struct CmHiveStats {
    pub key_count: u32,
    pub value_count: u32,
    pub cell_stats: super::cell::CellTableStats,
}

// ============================================================================
// Hive Pool
// ============================================================================

/// Hive pool
static mut HIVE_POOL: [CmHive; MAX_HIVES] = {
    const INIT: CmHive = CmHive::empty();
    [INIT; MAX_HIVES]
};

/// Hive pool lock
static HIVE_POOL_LOCK: SpinLock<()> = SpinLock::new(());

/// Loaded hive count
static LOADED_HIVE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Get a hive by index
pub unsafe fn cm_get_hive(hive_index: u16) -> Option<&'static CmHive> {
    if (hive_index as usize) < MAX_HIVES {
        let hive = &HIVE_POOL[hive_index as usize];
        if hive.is_loaded() {
            return Some(hive);
        }
    }
    None
}

/// Get a mutable hive by index
pub unsafe fn cm_get_hive_mut(hive_index: u16) -> Option<&'static mut CmHive> {
    if (hive_index as usize) < MAX_HIVES {
        let hive = &mut HIVE_POOL[hive_index as usize];
        if hive.is_loaded() {
            return Some(hive);
        }
    }
    None
}

/// Initialize a hive
pub unsafe fn cm_init_hive(
    hive_index: u16,
    name: &str,
    hive_type: CmHiveType,
    is_volatile: bool,
) -> bool {
    if hive_index as usize >= MAX_HIVES {
        return false;
    }

    let _guard = HIVE_POOL_LOCK.lock();

    let hive = &mut HIVE_POOL[hive_index as usize];

    // Don't reinitialize a loaded hive
    if hive.is_loaded() {
        return false;
    }

    // Allocate root key
    let root_key = match cm_allocate_key() {
        Some(k) => k,
        None => return false,
    };

    // Initialize root key
    let key_pool = cm_get_key_pool_mut();
    let root = &mut key_pool[root_key as usize];
    *root = CmKeyNode::new(name, u32::MAX, hive_index);
    root.set_flag(key_flags::KEY_HIVE_ROOT);

    // Initialize hive
    hive.name = CmHiveName::from_str(name);
    hive.hive_type = hive_type;
    hive.root_key = root_key;
    hive.hive_index = hive_index;
    hive.key_count.store(1, Ordering::SeqCst); // Root key
    hive.value_count.store(0, Ordering::SeqCst);
    hive.sequence.store(1, Ordering::SeqCst);

    let mut flags = hive_flags::HIVE_LOADED;
    if is_volatile {
        flags |= hive_flags::HIVE_VOLATILE;
        root.set_flag(key_flags::KEY_VOLATILE);
    }
    hive.flags.store(flags, Ordering::SeqCst);

    LOADED_HIVE_COUNT.fetch_add(1, Ordering::SeqCst);

    crate::serial_println!("[CM] Initialized hive: {} (index {})", name, hive_index);
    true
}

/// Unload a hive
pub unsafe fn cm_unload_hive(hive_index: u16) -> bool {
    if hive_index as usize >= MAX_HIVES {
        return false;
    }

    let _guard = HIVE_POOL_LOCK.lock();

    let hive = &mut HIVE_POOL[hive_index as usize];
    if !hive.is_loaded() {
        return false;
    }

    // TODO: Free all keys and values

    // Free root key
    if hive.root_key != u32::MAX {
        super::key::cm_free_key(hive.root_key);
    }

    hive.clear();
    LOADED_HIVE_COUNT.fetch_sub(1, Ordering::SeqCst);

    true
}

/// Find hive by name
pub unsafe fn cm_find_hive(name: &str) -> Option<u16> {
    for i in 0..MAX_HIVES {
        let hive = &HIVE_POOL[i];
        if hive.is_loaded() && hive.name.as_str().eq_ignore_ascii_case(name) {
            return Some(i as u16);
        }
    }
    None
}

/// Get number of loaded hives
pub fn cm_get_hive_count() -> u32 {
    LOADED_HIVE_COUNT.load(Ordering::SeqCst)
}

/// Enumerate loaded hives
pub unsafe fn cm_enumerate_hives() -> impl Iterator<Item = &'static CmHive> {
    HIVE_POOL.iter().filter(|h| h.is_loaded())
}

// ============================================================================
// Standard Hives
// ============================================================================

/// Initialize standard system hives
pub unsafe fn cm_init_standard_hives() {
    use hive_indices::*;

    // HKEY_LOCAL_MACHINE hives
    cm_init_hive(HIVE_SYSTEM, "SYSTEM", CmHiveType::Primary, false);
    cm_init_hive(HIVE_SOFTWARE, "SOFTWARE", CmHiveType::Primary, false);
    cm_init_hive(HIVE_HARDWARE, "HARDWARE", CmHiveType::Volatile, true);
    cm_init_hive(HIVE_SAM, "SAM", CmHiveType::Primary, false);
    cm_init_hive(HIVE_SECURITY, "SECURITY", CmHiveType::Primary, false);

    // HKEY_USERS hive
    cm_init_hive(HIVE_DEFAULT, ".DEFAULT", CmHiveType::User, false);
}

/// Create standard subkeys for SYSTEM hive
pub unsafe fn cm_init_system_hive_structure() {
    use hive_indices::HIVE_SYSTEM;

    let hive = match cm_get_hive_mut(HIVE_SYSTEM) {
        Some(h) => h,
        None => return,
    };

    // Create CurrentControlSet subkey
    let _ccs = create_subkey(hive.root_key, "CurrentControlSet", HIVE_SYSTEM);

    // Create ControlSet001 subkey
    let cs001 = create_subkey(hive.root_key, "ControlSet001", HIVE_SYSTEM);
    if let Some(cs_idx) = cs001 {
        create_subkey(cs_idx, "Control", HIVE_SYSTEM);
        create_subkey(cs_idx, "Enum", HIVE_SYSTEM);
        create_subkey(cs_idx, "Hardware Profiles", HIVE_SYSTEM);
        create_subkey(cs_idx, "Services", HIVE_SYSTEM);
    }

    // Create Select subkey
    let select = create_subkey(hive.root_key, "Select", HIVE_SYSTEM);
    if let Some(select_idx) = select {
        if let Some(key) = cm_get_key_mut(select_idx) {
            key.add_value(super::value::CmKeyValue::new_dword("Current", 1));
            key.add_value(super::value::CmKeyValue::new_dword("Default", 1));
            key.add_value(super::value::CmKeyValue::new_dword("Failed", 0));
            key.add_value(super::value::CmKeyValue::new_dword("LastKnownGood", 1));
        }
    }

    // Create Setup subkey
    create_subkey(hive.root_key, "Setup", HIVE_SYSTEM);
}

/// Create standard subkeys for SOFTWARE hive
pub unsafe fn cm_init_software_hive_structure() {
    use hive_indices::HIVE_SOFTWARE;

    let hive = match cm_get_hive_mut(HIVE_SOFTWARE) {
        Some(h) => h,
        None => return,
    };

    // Create standard subkeys
    create_subkey(hive.root_key, "Classes", HIVE_SOFTWARE);
    create_subkey(hive.root_key, "Clients", HIVE_SOFTWARE);

    let ms = create_subkey(hive.root_key, "Microsoft", HIVE_SOFTWARE);
    if let Some(ms_idx) = ms {
        let win = create_subkey(ms_idx, "Windows", HIVE_SOFTWARE);
        if let Some(win_idx) = win {
            let cv = create_subkey(win_idx, "CurrentVersion", HIVE_SOFTWARE);
            if let Some(cv_idx) = cv {
                if let Some(key) = cm_get_key_mut(cv_idx) {
                    key.add_value(super::value::CmKeyValue::new_string(
                        "ProductName", "Nostalgia OS"
                    ));
                    key.add_value(super::value::CmKeyValue::new_string(
                        "CurrentVersion", "0.1"
                    ));
                    key.add_value(super::value::CmKeyValue::new_string(
                        "CurrentBuildNumber", "1"
                    ));
                }
            }
        }

        create_subkey(ms_idx, "Windows NT", HIVE_SOFTWARE);
    }

    create_subkey(hive.root_key, "Policies", HIVE_SOFTWARE);
    create_subkey(hive.root_key, "RegisteredApplications", HIVE_SOFTWARE);
}

/// Create standard subkeys for HARDWARE hive
pub unsafe fn cm_init_hardware_hive_structure() {
    use hive_indices::HIVE_HARDWARE;

    let hive = match cm_get_hive_mut(HIVE_HARDWARE) {
        Some(h) => h,
        None => return,
    };

    let desc = create_subkey(hive.root_key, "DESCRIPTION", HIVE_HARDWARE);
    if let Some(desc_idx) = desc {
        let sys = create_subkey(desc_idx, "System", HIVE_HARDWARE);
        if let Some(sys_idx) = sys {
            if let Some(key) = cm_get_key_mut(sys_idx) {
                key.add_value(super::value::CmKeyValue::new_string(
                    "Identifier", "AT/AT COMPATIBLE"
                ));
            }

            create_subkey(sys_idx, "CentralProcessor", HIVE_HARDWARE);
            create_subkey(sys_idx, "FloatingPointProcessor", HIVE_HARDWARE);
        }
    }

    create_subkey(hive.root_key, "DEVICEMAP", HIVE_HARDWARE);
    create_subkey(hive.root_key, "RESOURCEMAP", HIVE_HARDWARE);
}

/// Helper: Create a subkey under a parent
unsafe fn create_subkey(parent_key: u32, name: &str, hive_index: u16) -> Option<u32> {
    let parent = cm_get_key_mut(parent_key)?;

    // Allocate new key
    let new_key_idx = cm_allocate_key()?;

    // Initialize the key
    let key_pool = cm_get_key_pool_mut();
    let new_key = &mut key_pool[new_key_idx as usize];
    *new_key = CmKeyNode::new(name, parent_key, hive_index);

    // Add to parent
    if !parent.add_subkey(new_key_idx) {
        super::key::cm_free_key(new_key_idx);
        return None;
    }

    // Update hive stats
    if let Some(hive) = cm_get_hive_mut(hive_index) {
        hive.add_key();
    }

    Some(new_key_idx)
}

/// Initialize hive subsystem
pub fn init() {
    crate::serial_println!("[CM] Hive subsystem initialized ({} hives available)", MAX_HIVES);
}
