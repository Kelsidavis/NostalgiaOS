//! Configuration Manager (cm)
//!
//! The Configuration Manager handles the Windows Registry:
//!
//! - **Hives**: Discrete registry files (SYSTEM, SOFTWARE, etc.)
//! - **Keys**: Hierarchical containers for values
//! - **Values**: Named data items with types (REG_SZ, REG_DWORD, etc.)
//! - **Cells**: Low-level storage units
//!
//! # Registry Structure
//!
//! ```text
//! HKEY_LOCAL_MACHINE (HKLM)
//! ├── SYSTEM
//! │   ├── CurrentControlSet
//! │   ├── ControlSet001
//! │   └── Select
//! ├── SOFTWARE
//! │   ├── Microsoft
//! │   └── Classes
//! ├── HARDWARE (volatile)
//! ├── SAM
//! └── SECURITY
//!
//! HKEY_USERS (HKU)
//! └── .DEFAULT
//! ```
//!
//! # Key Types
//!
//! - REG_SZ: Null-terminated string
//! - REG_DWORD: 32-bit integer
//! - REG_QWORD: 64-bit integer
//! - REG_BINARY: Binary data
//! - REG_MULTI_SZ: Multiple strings
//! - REG_EXPAND_SZ: Expandable string

pub mod value;
pub mod key;
pub mod cell;
pub mod hive;
pub mod operations;

// Re-export value types
pub use value::{
    RegType,
    CmValueName,
    CmValueData,
    CmKeyValue,
    MAX_VALUE_NAME_LENGTH,
    MAX_VALUE_DATA_SIZE,
    value_flags,
};

// Re-export key types
pub use key::{
    CmKeyNode,
    CmKeyName,
    CmKeyStats,
    MAX_KEY_NAME_LENGTH,
    MAX_VALUES_PER_KEY,
    MAX_SUBKEYS_PER_KEY,
    MAX_KEYS,
    key_flags,
    cm_allocate_key,
    cm_free_key,
    cm_get_key,
    cm_get_key_mut,
    cm_get_key_pool,
    cm_get_key_stats,
};

// Re-export cell types
pub use cell::{
    CmCell,
    CmCellHeader,
    CmCellTable,
    CmCellType,
    CellIndex,
    CellTableStats,
    HCELL_NIL,
    MAX_CELLS_PER_HIVE,
    cell_flags,
};

// Re-export hive types
pub use hive::{
    CmHive,
    CmHiveName,
    CmHiveType,
    CmHiveStats,
    MAX_HIVES,
    MAX_HIVE_NAME_LENGTH,
    hive_flags,
    hive_indices,
    cm_get_hive,
    cm_get_hive_mut,
    cm_init_hive,
    cm_unload_hive,
    cm_find_hive,
    cm_get_hive_count,
    cm_enumerate_hives,
    cm_init_standard_hives,
    cm_init_system_hive_structure,
    cm_init_software_hive_structure,
    cm_init_hardware_hive_structure,
};

// Re-export operations
pub use operations::{
    CmStatus,
    CmKeyHandle,
    CmDisposition,
    CmKeyInfo,
    root_keys,
    open_options,
    access_rights,
    cm_open_key,
    cm_create_key,
    cm_close_key,
    cm_delete_key,
    cm_query_value,
    cm_set_value,
    cm_set_value_string,
    cm_set_value_dword,
    cm_set_value_qword,
    cm_delete_value,
    cm_enumerate_key,
    cm_enumerate_value,
    cm_get_key_name,
    cm_get_key_last_write_time,
    cm_query_key_info,
    cm_read_string,
    cm_read_dword,
    cm_write_string,
    cm_write_dword,
};

/// Initialize the Configuration Manager
///
/// This initializes all registry subsystems and creates the standard hives:
/// 1. Value subsystem
/// 2. Key subsystem
/// 3. Cell subsystem
/// 4. Hive subsystem
/// 5. Operations subsystem
/// 6. Standard hives and structure
pub unsafe fn init() {
    crate::serial_println!("[CM] Initializing Configuration Manager...");

    // Initialize subsystems
    value::init();
    key::init();
    cell::init();
    hive::init();
    operations::init();

    // Initialize standard hives
    cm_init_standard_hives();

    // Create standard hive structures
    cm_init_system_hive_structure();
    cm_init_software_hive_structure();
    cm_init_hardware_hive_structure();

    // Print summary
    let key_stats = cm_get_key_stats();
    let hive_count = cm_get_hive_count();

    crate::serial_println!("[CM] Configuration Manager initialized");
    crate::serial_println!("[CM]   {} hives loaded", hive_count);
    crate::serial_println!("[CM]   {} keys allocated", key_stats.allocated_keys);
}
