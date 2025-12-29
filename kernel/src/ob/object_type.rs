//! Object Type Implementation
//!
//! Each object type (Process, Thread, Event, File, etc.) is described
//! by an OBJECT_TYPE structure that defines:
//! - Type name
//! - Pool type and default quota
//! - Type-specific callbacks (open, close, delete, parse, security)
//!
//! # Standard Object Types
//! - Type (the type of types)
//! - Directory
//! - SymbolicLink
//! - Process
//! - Thread
//! - Event
//! - Semaphore
//! - Mutex
//! - Timer
//! - File
//! - Section
//! - Key (registry)

use core::sync::atomic::{AtomicU32, Ordering};
use core::ptr;
use super::header::ObjectHeader;

/// Maximum type name length
pub const OB_MAX_TYPE_NAME: usize = 64;

/// Object type index values (well-known types)
pub mod type_index {
    pub const TYPE_TYPE: u8 = 1;
    pub const TYPE_DIRECTORY: u8 = 2;
    pub const TYPE_SYMBOLIC_LINK: u8 = 3;
    pub const TYPE_PROCESS: u8 = 4;
    pub const TYPE_THREAD: u8 = 5;
    pub const TYPE_EVENT: u8 = 6;
    pub const TYPE_SEMAPHORE: u8 = 7;
    pub const TYPE_MUTEX: u8 = 8;
    pub const TYPE_TIMER: u8 = 9;
    pub const TYPE_FILE: u8 = 10;
    pub const TYPE_SECTION: u8 = 11;
    pub const TYPE_KEY: u8 = 12;
    pub const TYPE_TOKEN: u8 = 13;
    pub const TYPE_DEVICE: u8 = 14;
    pub const TYPE_DRIVER: u8 = 15;
}

/// Open procedure - called when a handle is created
///
/// # Arguments
/// * `object` - The object being opened
/// * `access_mask` - Requested access rights
/// * `handle_attributes` - Handle attributes
///
/// # Returns
/// Status code (0 = success)
pub type OpenProcedure = fn(
    object: *mut u8,
    access_mask: u32,
    handle_attributes: u32,
) -> i32;

/// Close procedure - called when a handle is closed
///
/// # Arguments
/// * `object` - The object being closed
/// * `handle_count` - Remaining handle count after this close
pub type CloseProcedure = fn(
    object: *mut u8,
    handle_count: i32,
);

/// Delete procedure - called when object is being deleted
///
/// # Arguments
/// * `object` - The object being deleted
pub type DeleteProcedure = fn(object: *mut u8);

/// Parse procedure - called to resolve name within object
///
/// # Arguments
/// * `object` - The current object
/// * `remaining_name` - Remaining path to parse
/// * `found_object` - Output: the found object
///
/// # Returns
/// Status code (0 = success)
pub type ParseProcedure = fn(
    object: *mut u8,
    remaining_name: &[u8],
    found_object: *mut *mut u8,
) -> i32;

/// Security procedure - for security operations
///
/// # Arguments
/// * `object` - The object
/// * `operation` - Security operation type
/// * `security_info` - Security information
///
/// # Returns
/// Status code (0 = success)
pub type SecurityProcedure = fn(
    object: *mut u8,
    operation: u32,
    security_info: *mut u8,
) -> i32;

/// Dump procedure - for debugging
pub type DumpProcedure = fn(object: *mut u8);

/// Object type callbacks
#[repr(C)]
pub struct ObjectTypeCallbacks {
    /// Called when handle is opened
    pub open: Option<OpenProcedure>,
    /// Called when handle is closed
    pub close: Option<CloseProcedure>,
    /// Called when object is deleted
    pub delete: Option<DeleteProcedure>,
    /// Called to parse name within object (for directories, etc.)
    pub parse: Option<ParseProcedure>,
    /// Called for security operations
    pub security: Option<SecurityProcedure>,
    /// Called for debug dump
    pub dump: Option<DumpProcedure>,
}

impl ObjectTypeCallbacks {
    /// Create empty callbacks
    pub const fn new() -> Self {
        Self {
            open: None,
            close: None,
            delete: None,
            parse: None,
            security: None,
            dump: None,
        }
    }
}

impl Default for ObjectTypeCallbacks {
    fn default() -> Self {
        Self::new()
    }
}

/// Object type attributes
#[repr(C)]
pub struct ObjectTypeInfo {
    /// Size of object body (excluding header)
    pub object_body_size: u32,
    /// Default quota for objects of this type
    pub default_quota: u32,
    /// Default access mask
    pub valid_access_mask: u32,
    /// Pool type (0 = nonpaged, 1 = paged)
    pub pool_type: u8,
    /// Whether objects maintain a handle database
    pub maintain_handle_count: bool,
    /// Whether objects can be named
    pub allow_naming: bool,
    /// Whether type supports security
    pub security_required: bool,
}

impl ObjectTypeInfo {
    /// Create default type info
    pub const fn new() -> Self {
        Self {
            object_body_size: 0,
            default_quota: 0,
            valid_access_mask: 0xFFFFFFFF,
            pool_type: 0, // Nonpaged
            maintain_handle_count: true,
            allow_naming: true,
            security_required: false,
        }
    }
}

impl Default for ObjectTypeInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Object type descriptor
///
/// Describes a type of kernel object. Every object type
/// (Process, Thread, Event, etc.) has one of these.
#[repr(C)]
pub struct ObjectType {
    /// Object header for type object itself
    pub header: ObjectHeader,
    /// Type name (e.g., "Process", "Event")
    pub name: [u8; OB_MAX_TYPE_NAME],
    /// Type name length
    pub name_length: u8,
    /// Type index (unique identifier)
    pub type_index: u8,
    /// Number of objects of this type
    pub object_count: AtomicU32,
    /// Number of handles to objects of this type
    pub handle_count: AtomicU32,
    /// Type info (sizes, flags)
    pub type_info: ObjectTypeInfo,
    /// Type callbacks
    pub callbacks: ObjectTypeCallbacks,
}

// Safety: ObjectType uses atomics for counts
unsafe impl Sync for ObjectType {}
unsafe impl Send for ObjectType {}

impl ObjectType {
    /// Create a new uninitialized object type
    pub const fn new() -> Self {
        Self {
            header: ObjectHeader::new(),
            name: [0; OB_MAX_TYPE_NAME],
            name_length: 0,
            type_index: 0,
            object_count: AtomicU32::new(0),
            handle_count: AtomicU32::new(0),
            type_info: ObjectTypeInfo::new(),
            callbacks: ObjectTypeCallbacks::new(),
        }
    }

    /// Initialize the object type
    pub fn init(
        &mut self,
        name: &[u8],
        type_index: u8,
        type_info: ObjectTypeInfo,
        callbacks: ObjectTypeCallbacks,
    ) {
        let len = name.len().min(OB_MAX_TYPE_NAME - 1);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name[len] = 0;
        self.name_length = len as u8;
        self.type_index = type_index;
        self.type_info = type_info;
        self.callbacks = callbacks;
        self.object_count = AtomicU32::new(0);
        self.handle_count = AtomicU32::new(0);

        // Initialize header (type object points to Type type)
        self.header.init(ptr::null_mut()); // Will be set to Type type
    }

    /// Get the type name
    pub fn name_slice(&self) -> &[u8] {
        &self.name[..self.name_length as usize]
    }

    /// Increment object count
    pub fn increment_object_count(&self) {
        self.object_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrement object count
    pub fn decrement_object_count(&self) {
        self.object_count.fetch_sub(1, Ordering::SeqCst);
    }

    /// Get current object count
    pub fn get_object_count(&self) -> u32 {
        self.object_count.load(Ordering::SeqCst)
    }

    /// Increment handle count
    pub fn increment_handle_count(&self) {
        self.handle_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrement handle count
    pub fn decrement_handle_count(&self) {
        self.handle_count.fetch_sub(1, Ordering::SeqCst);
    }

    /// Get current handle count
    pub fn get_handle_count(&self) -> u32 {
        self.handle_count.load(Ordering::SeqCst)
    }
}

impl Default for ObjectType {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Standard Object Types (Static Instances)
// ============================================================================

use crate::ke::SpinLock;

/// Maximum number of object types
pub const MAX_OBJECT_TYPES: usize = 32;

/// Global object type table
static mut OBJECT_TYPE_TABLE: [ObjectType; MAX_OBJECT_TYPES] = {
    const INIT: ObjectType = ObjectType::new();
    [INIT; MAX_OBJECT_TYPES]
};

/// Next available type index
static mut NEXT_TYPE_INDEX: u8 = 1;

/// Type table lock
static TYPE_TABLE_LOCK: SpinLock<()> = SpinLock::new(());

/// Initialize the object type system
///
/// # Safety
/// Must be called once during kernel initialization
pub unsafe fn init_object_types() {
    // Initialize the "Type" type (type of all types)
    let type_type_info = ObjectTypeInfo {
        object_body_size: core::mem::size_of::<ObjectType>() as u32,
        default_quota: 0,
        valid_access_mask: 0x000F0001, // SYNCHRONIZE | TYPE_ALL_ACCESS
        pool_type: 0,
        maintain_handle_count: true,
        allow_naming: true,
        security_required: false,
    };

    create_object_type(
        b"Type",
        type_index::TYPE_TYPE,
        type_type_info,
        ObjectTypeCallbacks::new(),
    );

    // Initialize Directory type
    let dir_type_info = ObjectTypeInfo {
        object_body_size: core::mem::size_of::<super::directory::ObjectDirectory>() as u32,
        default_quota: 0,
        valid_access_mask: 0x000F000F, // DIRECTORY_ALL_ACCESS
        pool_type: 0,
        maintain_handle_count: true,
        allow_naming: true,
        security_required: false,
    };

    let dir_callbacks = ObjectTypeCallbacks {
        parse: Some(super::directory::directory_parse_procedure),
        ..ObjectTypeCallbacks::new()
    };

    create_object_type(
        b"Directory",
        type_index::TYPE_DIRECTORY,
        dir_type_info,
        dir_callbacks,
    );

    // Initialize Event type
    let event_type_info = ObjectTypeInfo {
        object_body_size: core::mem::size_of::<crate::ke::KEvent>() as u32,
        default_quota: 0,
        valid_access_mask: 0x001F0003, // EVENT_ALL_ACCESS
        pool_type: 0,
        maintain_handle_count: true,
        allow_naming: true,
        security_required: false,
    };

    create_object_type(
        b"Event",
        type_index::TYPE_EVENT,
        event_type_info,
        ObjectTypeCallbacks::new(),
    );

    // Initialize Semaphore type
    let sem_type_info = ObjectTypeInfo {
        object_body_size: core::mem::size_of::<crate::ke::KSemaphore>() as u32,
        default_quota: 0,
        valid_access_mask: 0x001F0003, // SEMAPHORE_ALL_ACCESS
        pool_type: 0,
        maintain_handle_count: true,
        allow_naming: true,
        security_required: false,
    };

    create_object_type(
        b"Semaphore",
        type_index::TYPE_SEMAPHORE,
        sem_type_info,
        ObjectTypeCallbacks::new(),
    );

    // Initialize Mutex type
    let mutex_type_info = ObjectTypeInfo {
        object_body_size: core::mem::size_of::<crate::ke::KMutex>() as u32,
        default_quota: 0,
        valid_access_mask: 0x001F0001, // MUTEX_ALL_ACCESS
        pool_type: 0,
        maintain_handle_count: true,
        allow_naming: true,
        security_required: false,
    };

    create_object_type(
        b"Mutant",  // NT calls mutexes "Mutant"
        type_index::TYPE_MUTEX,
        mutex_type_info,
        ObjectTypeCallbacks::new(),
    );

    // Initialize Timer type
    let timer_type_info = ObjectTypeInfo {
        object_body_size: core::mem::size_of::<crate::ke::KTimer>() as u32,
        default_quota: 0,
        valid_access_mask: 0x001F0003, // TIMER_ALL_ACCESS
        pool_type: 0,
        maintain_handle_count: true,
        allow_naming: true,
        security_required: false,
    };

    create_object_type(
        b"Timer",
        type_index::TYPE_TIMER,
        timer_type_info,
        ObjectTypeCallbacks::new(),
    );

    // Initialize Process type
    let process_type_info = ObjectTypeInfo {
        object_body_size: core::mem::size_of::<crate::ke::KProcess>() as u32,
        default_quota: 0,
        valid_access_mask: 0x001FFFFF, // PROCESS_ALL_ACCESS
        pool_type: 0,
        maintain_handle_count: true,
        allow_naming: false, // Processes aren't named in namespace
        security_required: true,
    };

    create_object_type(
        b"Process",
        type_index::TYPE_PROCESS,
        process_type_info,
        ObjectTypeCallbacks::new(),
    );

    // Initialize Thread type
    let thread_type_info = ObjectTypeInfo {
        object_body_size: core::mem::size_of::<crate::ke::KThread>() as u32,
        default_quota: 0,
        valid_access_mask: 0x001FFFFF, // THREAD_ALL_ACCESS
        pool_type: 0,
        maintain_handle_count: true,
        allow_naming: false, // Threads aren't named in namespace
        security_required: true,
    };

    create_object_type(
        b"Thread",
        type_index::TYPE_THREAD,
        thread_type_info,
        ObjectTypeCallbacks::new(),
    );

    crate::serial_println!("[OB] Object types initialized");
}

/// Create a new object type
///
/// # Safety
/// Must hold TYPE_TABLE_LOCK or be in initialization
pub unsafe fn create_object_type(
    name: &[u8],
    type_index: u8,
    type_info: ObjectTypeInfo,
    callbacks: ObjectTypeCallbacks,
) -> *mut ObjectType {
    let index = type_index as usize;
    if index >= MAX_OBJECT_TYPES {
        return ptr::null_mut();
    }

    let obj_type = &mut OBJECT_TYPE_TABLE[index];
    obj_type.init(name, type_index, type_info, callbacks);

    // Set up header to point to Type type (self-referential for Type type)
    if type_index == type_index::TYPE_TYPE {
        obj_type.header.object_type = obj_type as *mut ObjectType;
    } else if !OBJECT_TYPE_TABLE[type_index::TYPE_TYPE as usize].header.object_type.is_null() {
        obj_type.header.object_type = &mut OBJECT_TYPE_TABLE[type_index::TYPE_TYPE as usize];
    }

    obj_type as *mut ObjectType
}

/// Get an object type by index
pub fn get_object_type(type_index: u8) -> Option<&'static ObjectType> {
    let index = type_index as usize;
    if index >= MAX_OBJECT_TYPES {
        return None;
    }
    unsafe {
        let obj_type = &OBJECT_TYPE_TABLE[index];
        if obj_type.type_index == 0 {
            None
        } else {
            Some(obj_type)
        }
    }
}

/// Get a mutable object type by index
pub unsafe fn get_object_type_mut(type_index: u8) -> Option<&'static mut ObjectType> {
    let index = type_index as usize;
    if index >= MAX_OBJECT_TYPES {
        return None;
    }
    let obj_type = &mut OBJECT_TYPE_TABLE[index];
    if obj_type.type_index == 0 {
        None
    } else {
        Some(obj_type)
    }
}

// ============================================================================
// Object Type Inspection (for debugging)
// ============================================================================

/// Snapshot of an object type for debugging
#[derive(Debug, Clone, Copy)]
pub struct ObjectTypeSnapshot {
    /// Type index
    pub type_index: u8,
    /// Type name (as bytes)
    pub name: [u8; 32],
    /// Name length
    pub name_length: u8,
    /// Object count
    pub object_count: u32,
    /// Handle count
    pub handle_count: u32,
    /// Object body size
    pub body_size: u32,
    /// Pool type (0 = nonpaged, 1 = paged)
    pub pool_type: u8,
    /// Allows naming
    pub allow_naming: bool,
}

/// Object type statistics
#[derive(Debug, Clone, Copy)]
pub struct ObjectTypeStats {
    /// Number of registered object types
    pub type_count: usize,
    /// Total objects across all types
    pub total_objects: u32,
    /// Total handles across all types
    pub total_handles: u32,
}

/// Get object type statistics
pub fn ob_get_type_stats() -> ObjectTypeStats {
    let mut type_count = 0;
    let mut total_objects = 0u32;
    let mut total_handles = 0u32;

    for i in 1..MAX_OBJECT_TYPES {
        if let Some(obj_type) = get_object_type(i as u8) {
            type_count += 1;
            total_objects += obj_type.get_object_count();
            total_handles += obj_type.get_handle_count();
        }
    }

    ObjectTypeStats {
        type_count,
        total_objects,
        total_handles,
    }
}

/// Get snapshots of all object types
pub fn ob_get_type_snapshots() -> ([ObjectTypeSnapshot; 32], usize) {
    let mut snapshots = [ObjectTypeSnapshot {
        type_index: 0,
        name: [0; 32],
        name_length: 0,
        object_count: 0,
        handle_count: 0,
        body_size: 0,
        pool_type: 0,
        allow_naming: false,
    }; 32];

    let mut count = 0;

    for i in 1..MAX_OBJECT_TYPES {
        if let Some(obj_type) = get_object_type(i as u8) {
            let name_len = (obj_type.name_length as usize).min(31);
            let mut name = [0u8; 32];
            name[..name_len].copy_from_slice(&obj_type.name[..name_len]);

            snapshots[count] = ObjectTypeSnapshot {
                type_index: obj_type.type_index,
                name,
                name_length: name_len as u8,
                object_count: obj_type.get_object_count(),
                handle_count: obj_type.get_handle_count(),
                body_size: obj_type.type_info.object_body_size,
                pool_type: obj_type.type_info.pool_type,
                allow_naming: obj_type.type_info.allow_naming,
            };

            count += 1;
            if count >= 32 {
                break;
            }
        }
    }

    (snapshots, count)
}
