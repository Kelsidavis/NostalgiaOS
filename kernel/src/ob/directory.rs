//! Object Directory Implementation
//!
//! Object directories form the namespace hierarchy for named kernel objects.
//! The root directory (\) contains subdirectories like:
//! - \ObjectTypes - Type objects
//! - \Device - Device objects
//! - \DosDevices - Drive letters
//! - \BaseNamedObjects - Named events, mutexes, etc.
//!
//! # Directory Operations
//! - Lookup: Find object by name
//! - Insert: Add named object
//! - Delete: Remove named object

use core::ptr;
use super::header::{ObjectHeader, ObjectNameInfo, flags};
use super::object_type::type_index;
use crate::ke::SpinLock;

/// Maximum entries per directory (simple implementation)
pub const MAX_DIRECTORY_ENTRIES: usize = 64;

/// Directory entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DirectoryEntry {
    /// Object pointer (null if entry free)
    pub object: *mut u8,
    /// Hash of name (for faster lookup)
    pub name_hash: u32,
}

impl DirectoryEntry {
    /// Create empty entry
    pub const fn new() -> Self {
        Self {
            object: ptr::null_mut(),
            name_hash: 0,
        }
    }

    /// Check if entry is in use
    #[inline]
    pub fn is_used(&self) -> bool {
        !self.object.is_null()
    }
}

impl Default for DirectoryEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Object directory
#[repr(C)]
pub struct ObjectDirectory {
    /// Object header
    pub header: ObjectHeader,
    /// Directory entries
    entries: [DirectoryEntry; MAX_DIRECTORY_ENTRIES],
    /// Number of entries in use
    entry_count: u32,
    /// Lock for directory operations
    lock: SpinLock<()>,
}

// Safety: ObjectDirectory uses locks
unsafe impl Sync for ObjectDirectory {}
unsafe impl Send for ObjectDirectory {}

impl ObjectDirectory {
    /// Create a new empty directory
    pub const fn new() -> Self {
        Self {
            header: ObjectHeader::new(),
            entries: [DirectoryEntry::new(); MAX_DIRECTORY_ENTRIES],
            entry_count: 0,
            lock: SpinLock::new(()),
        }
    }

    /// Initialize the directory
    pub unsafe fn init(&mut self, name: Option<&[u8]>, parent: *mut ObjectDirectory) {
        // Set up header
        if let Some(dir_type) = super::object_type::get_object_type_mut(type_index::TYPE_DIRECTORY) {
            self.header.init(dir_type);
            dir_type.increment_object_count();
        }

        // Set name if provided
        if let Some(n) = name {
            self.set_name(n, parent);
        }

        self.entry_count = 0;
        for entry in self.entries.iter_mut() {
            *entry = DirectoryEntry::new();
        }
    }

    /// Set directory name
    unsafe fn set_name(&mut self, name: &[u8], parent: *mut ObjectDirectory) {
        // Allocate name info (for now, use static storage - need proper allocator)
        static mut NAME_INFO_POOL: [ObjectNameInfo; 32] = {
            const INIT: ObjectNameInfo = ObjectNameInfo::new();
            [INIT; 32]
        };
        static mut NAME_INFO_INDEX: usize = 0;

        if NAME_INFO_INDEX >= 32 {
            return; // Out of name info slots
        }

        let name_info = &mut NAME_INFO_POOL[NAME_INFO_INDEX];
        NAME_INFO_INDEX += 1;

        name_info.set_name(name);
        name_info.directory = parent;

        self.header.name_info = name_info;
        self.header.set_flag(flags::OB_FLAG_NAMED);
        self.header.set_flag(flags::OB_FLAG_IN_NAMESPACE);
    }

    /// Simple hash function for names
    fn hash_name(name: &[u8]) -> u32 {
        let mut hash: u32 = 0;
        for &byte in name {
            // Case-insensitive hash (convert to uppercase)
            hash = hash.wrapping_mul(31).wrapping_add(byte.to_ascii_uppercase() as u32);
        }
        hash
    }

    /// Case-insensitive name comparison
    fn names_equal(a: &[u8], b: &[u8]) -> bool {
        a.eq_ignore_ascii_case(b)
    }

    /// Look up an object by name
    ///
    /// # Returns
    /// Pointer to the object, or null if not found
    pub unsafe fn lookup(&self, name: &[u8]) -> *mut u8 {
        let _guard = self.lock.lock();
        let hash = Self::hash_name(name);

        for entry in self.entries.iter() {
            if !entry.is_used() {
                continue;
            }
            if entry.name_hash != hash {
                continue;
            }

            // Hash matches - check actual name
            let header = ObjectHeader::from_body(entry.object);
            if let Some(obj_name) = (*header).get_name() {
                if Self::names_equal(name, obj_name) {
                    return entry.object;
                }
            }
        }

        ptr::null_mut()
    }

    /// Insert a named object into the directory
    ///
    /// # Returns
    /// true if inserted, false if directory full or name exists
    pub unsafe fn insert(&mut self, object: *mut u8, name: &[u8]) -> bool {
        if object.is_null() || name.is_empty() {
            return false;
        }

        let _guard = self.lock.lock();

        // Check if name already exists
        let hash = Self::hash_name(name);
        for entry in self.entries.iter() {
            if !entry.is_used() {
                continue;
            }
            if entry.name_hash != hash {
                continue;
            }
            let header = ObjectHeader::from_body(entry.object);
            if let Some(obj_name) = (*header).get_name() {
                if Self::names_equal(name, obj_name) {
                    return false; // Name already exists
                }
            }
        }

        // Find a free entry
        for entry in self.entries.iter_mut() {
            if !entry.is_used() {
                entry.object = object;
                entry.name_hash = hash;
                self.entry_count += 1;

                // Mark object as in namespace
                let header = ObjectHeader::from_body(object);
                (*header).set_flag(flags::OB_FLAG_IN_NAMESPACE);

                return true;
            }
        }

        false // Directory full
    }

    /// Remove an object from the directory
    ///
    /// # Returns
    /// true if removed, false if not found
    pub unsafe fn remove(&mut self, name: &[u8]) -> bool {
        let _guard = self.lock.lock();
        let hash = Self::hash_name(name);

        for entry in self.entries.iter_mut() {
            if !entry.is_used() {
                continue;
            }
            if entry.name_hash != hash {
                continue;
            }

            let header = ObjectHeader::from_body(entry.object);
            if let Some(obj_name) = (*header).get_name() {
                if Self::names_equal(name, obj_name) {
                    // Clear namespace flag
                    (*header).clear_flag(flags::OB_FLAG_IN_NAMESPACE);

                    // Clear entry
                    *entry = DirectoryEntry::new();
                    self.entry_count -= 1;
                    return true;
                }
            }
        }

        false
    }

    /// Remove an object by pointer
    pub unsafe fn remove_object(&mut self, object: *mut u8) -> bool {
        let _guard = self.lock.lock();

        for entry in self.entries.iter_mut() {
            if entry.object == object {
                let header = ObjectHeader::from_body(object);
                (*header).clear_flag(flags::OB_FLAG_IN_NAMESPACE);

                *entry = DirectoryEntry::new();
                self.entry_count -= 1;
                return true;
            }
        }

        false
    }

    /// Get number of entries
    #[inline]
    pub fn count(&self) -> u32 {
        self.entry_count
    }

    /// Iterate over directory entries
    pub fn iter(&self) -> impl Iterator<Item = *mut u8> + '_ {
        self.entries.iter()
            .filter(|e| e.is_used())
            .map(|e| e.object)
    }
}

impl Default for ObjectDirectory {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse procedure for directory objects
///
/// Called when looking up a name within a directory.
pub fn directory_parse_procedure(
    object: *mut u8,
    remaining_name: &[u8],
    found_object: *mut *mut u8,
) -> i32 {
    const STATUS_INVALID_PARAMETER: i32 = 0xC000000Du32 as i32;

    if object.is_null() || remaining_name.is_empty() || found_object.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    unsafe {
        let dir = object as *mut ObjectDirectory;

        // Find the first component of the remaining name
        let mut component_end = remaining_name.len();
        for (i, &c) in remaining_name.iter().enumerate() {
            if c == b'\\' || c == b'/' {
                component_end = i;
                break;
            }
        }

        let component = &remaining_name[..component_end];
        let result = (*dir).lookup(component);

        if result.is_null() {
            *found_object = ptr::null_mut();
            return -2; // STATUS_OBJECT_NAME_NOT_FOUND
        }

        // If there's more path remaining, recurse
        if component_end < remaining_name.len() {
            let rest = &remaining_name[component_end + 1..];
            if rest.is_empty() {
                *found_object = result;
                return 0;
            }

            // Check if found object is also a directory
            let header = ObjectHeader::from_body(result);
            if let Some(obj_type) = (*header).get_type() {
                if obj_type.type_index == type_index::TYPE_DIRECTORY {
                    if let Some(parse) = obj_type.callbacks.parse {
                        return parse(result, rest, found_object);
                    }
                }
            }

            // Can't continue parsing
            *found_object = ptr::null_mut();
            return -3; // STATUS_OBJECT_TYPE_MISMATCH
        }

        *found_object = result;
        0 // STATUS_SUCCESS
    }
}

// ============================================================================
// Root Namespace
// ============================================================================

/// Root directory
static mut ROOT_DIRECTORY: ObjectDirectory = ObjectDirectory::new();

/// ObjectTypes directory
static mut OBJECT_TYPES_DIRECTORY: ObjectDirectory = ObjectDirectory::new();

/// BaseNamedObjects directory
static mut BASE_NAMED_OBJECTS: ObjectDirectory = ObjectDirectory::new();

/// Device directory
static mut DEVICE_DIRECTORY: ObjectDirectory = ObjectDirectory::new();

/// Get the root directory
pub fn get_root_directory() -> *mut ObjectDirectory {
    unsafe { &mut ROOT_DIRECTORY as *mut ObjectDirectory }
}

/// Get the ObjectTypes directory
pub fn get_object_types_directory() -> *mut ObjectDirectory {
    unsafe { &mut OBJECT_TYPES_DIRECTORY as *mut ObjectDirectory }
}

/// Get the BaseNamedObjects directory
pub fn get_base_named_objects() -> *mut ObjectDirectory {
    unsafe { &mut BASE_NAMED_OBJECTS as *mut ObjectDirectory }
}

/// Get the Device directory
pub fn get_device_directory() -> *mut ObjectDirectory {
    unsafe { &mut DEVICE_DIRECTORY as *mut ObjectDirectory }
}

/// Initialize the object namespace
///
/// # Safety
/// Must be called once during kernel initialization
pub unsafe fn init_namespace() {
    // Initialize root directory
    ROOT_DIRECTORY.init(None, ptr::null_mut());
    ROOT_DIRECTORY.header.set_flag(flags::OB_FLAG_PERMANENT);

    // Initialize ObjectTypes directory
    OBJECT_TYPES_DIRECTORY.init(Some(b"ObjectTypes"), &mut ROOT_DIRECTORY);
    OBJECT_TYPES_DIRECTORY.header.set_flag(flags::OB_FLAG_PERMANENT);
    ROOT_DIRECTORY.insert(
        &mut OBJECT_TYPES_DIRECTORY as *mut _ as *mut u8,
        b"ObjectTypes",
    );

    // Initialize BaseNamedObjects directory
    BASE_NAMED_OBJECTS.init(Some(b"BaseNamedObjects"), &mut ROOT_DIRECTORY);
    BASE_NAMED_OBJECTS.header.set_flag(flags::OB_FLAG_PERMANENT);
    ROOT_DIRECTORY.insert(
        &mut BASE_NAMED_OBJECTS as *mut _ as *mut u8,
        b"BaseNamedObjects",
    );

    // Initialize Device directory
    DEVICE_DIRECTORY.init(Some(b"Device"), &mut ROOT_DIRECTORY);
    DEVICE_DIRECTORY.header.set_flag(flags::OB_FLAG_PERMANENT);
    ROOT_DIRECTORY.insert(
        &mut DEVICE_DIRECTORY as *mut _ as *mut u8,
        b"Device",
    );

    crate::serial_println!("[OB] Namespace initialized");
    crate::serial_println!("[OB]   \\ObjectTypes");
    crate::serial_println!("[OB]   \\BaseNamedObjects");
    crate::serial_println!("[OB]   \\Device");
}

/// Look up an object by path
///
/// # Arguments
/// * `path` - Full path starting with \ (e.g., "\BaseNamedObjects\MyEvent")
///
/// # Returns
/// Pointer to object, or null if not found
pub unsafe fn ob_lookup_object(path: &[u8]) -> *mut u8 {
    if path.is_empty() || path[0] != b'\\' {
        return ptr::null_mut();
    }

    // Skip leading backslash
    let path = &path[1..];

    if path.is_empty() {
        return &mut ROOT_DIRECTORY as *mut _ as *mut u8;
    }

    let mut found: *mut u8 = ptr::null_mut();
    let status = directory_parse_procedure(
        &mut ROOT_DIRECTORY as *mut _ as *mut u8,
        path,
        &mut found,
    );

    if status == 0 {
        found
    } else {
        ptr::null_mut()
    }
}
