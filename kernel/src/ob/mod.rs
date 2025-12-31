//! Object Manager (ob)
//!
//! The object manager provides a unified object model for all kernel resources:
//!
//! - **Object Types**: Process, Thread, File, Section, Event, etc.
//! - **Namespace**: Hierarchical directory structure for named objects
//! - **Handle Tables**: Per-process handle-to-object mapping
//! - **Reference Counting**: Automatic object lifetime management
//! - **Security**: Per-object security descriptors
//!
//! # Object Structure
//!
//! Every kernel object has:
//! - OBJECT_HEADER: Type, ref counts, optional name/quota/creator info
//! - Object Body: Type-specific data
//!
//! # Namespace Hierarchy
//!
//! - `\` - Root directory
//! - `\ObjectTypes` - Type objects
//! - `\Device` - Device objects
//! - `\DosDevices` - Drive letters (C:, etc.)
//! - `\Global??` - Per-session devices
//!
//! # Key Structures
//!
//! - `OBJECT_HEADER`: Object metadata
//! - `OBJECT_TYPE`: Type descriptor with callbacks
//! - `OBJECT_DIRECTORY`: Namespace directory
//! - `HANDLE_TABLE`: Per-process handle table

// Submodules
pub mod directory;
pub mod handle;
pub mod header;
pub mod object_type;
pub mod symlink;

// Re-exports for convenience
pub use header::{ObjectHeader, ObjectNameInfo, flags, OB_MAX_NAME_LENGTH};
pub use object_type::{
    ObjectType, ObjectTypeCallbacks, ObjectTypeInfo,
    type_index, OB_MAX_TYPE_NAME, MAX_OBJECT_TYPES,
    get_object_type, init_object_types, create_object_type,
    ObjectTypeSnapshot, ObjectTypeStats, ob_get_type_stats, ob_get_type_snapshots,
};
pub use handle::{
    Handle, HandleTable, HandleTableEntry, handle_attributes,
    INVALID_HANDLE_VALUE, NULL_HANDLE, HANDLE_INCREMENT, MAX_HANDLES,
    ob_create_handle, ob_close_handle, ob_reference_object_by_handle,
    ob_dereference_object, get_system_handle_table, init_system_handle_table,
    HandleEntrySnapshot, HandleTableStats, ob_get_handle_stats, ob_get_handle_snapshots,
};
pub use directory::{
    ObjectDirectory, DirectoryEntry, MAX_DIRECTORY_ENTRIES,
    get_root_directory, get_object_types_directory,
    get_base_named_objects, get_device_directory,
    init_namespace, ob_lookup_object,
    DirectoryEntrySnapshot, DirectoryStats, ob_get_directory_stats,
    ob_get_directory_entries, ob_get_directory_name,
};
pub use symlink::{
    ObjectSymbolicLink, symlink_flags, symlink_access,
    ob_create_symbolic_link, ob_create_symbolic_link_ex, ob_create_dos_device_link,
    ob_delete_symbolic_link, ob_query_symbolic_link, ob_parse_symbolic_link,
    ob_resolve_symbolic_links, ob_is_symbolic_link, ob_list_symbolic_links,
    ob_get_symlink_stats, obp_symlink_init,
};

/// Initialize the Object Manager
///
/// # Safety
/// Must be called once during kernel Phase 1 initialization
pub unsafe fn init() {
    crate::serial_println!("[OB] Initializing Object Manager...");

    // Initialize object types first
    object_type::init_object_types();

    // Initialize the namespace
    directory::init_namespace();

    // Initialize the system handle table
    handle::init_system_handle_table();

    // Initialize symbolic links
    symlink::obp_symlink_init();

    crate::serial_println!("[OB] Object Manager initialized");
}
