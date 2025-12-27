//! Object Header Implementation
//!
//! Every kernel object is preceded by an OBJECT_HEADER that contains
//! metadata about the object including type, reference counts, and
//! optional information like name and security descriptor.
//!
//! # Memory Layout
//! ```text
//! +-------------------+
//! | Optional Headers  |  <- OBJECT_HEADER_NAME_INFO, etc.
//! +-------------------+
//! | OBJECT_HEADER     |
//! +-------------------+
//! | Object Body       |  <- The actual object (KPROCESS, KEVENT, etc.)
//! +-------------------+
//! ```

use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use core::ptr;

/// Object header flags
pub mod flags {
    /// Object has a name
    pub const OB_FLAG_NAMED: u8 = 0x01;
    /// Object is permanent (not deleted when ref count reaches 0)
    pub const OB_FLAG_PERMANENT: u8 = 0x02;
    /// Object has exclusive access
    pub const OB_FLAG_EXCLUSIVE: u8 = 0x04;
    /// Object is being created
    pub const OB_FLAG_CREATE_IN_PROGRESS: u8 = 0x08;
    /// Object is being deleted
    pub const OB_FLAG_DELETE_IN_PROGRESS: u8 = 0x10;
    /// Object is in namespace
    pub const OB_FLAG_IN_NAMESPACE: u8 = 0x20;
    /// Object has security descriptor
    pub const OB_FLAG_SECURITY: u8 = 0x40;
    /// Kernel-only object
    pub const OB_FLAG_KERNEL_OBJECT: u8 = 0x80;
}

/// Maximum object name length
pub const OB_MAX_NAME_LENGTH: usize = 256;

/// Object name information (optional, precedes header)
#[repr(C)]
pub struct ObjectNameInfo {
    /// Parent directory object
    pub directory: *mut super::directory::ObjectDirectory,
    /// Object name (null-terminated)
    pub name: [u8; OB_MAX_NAME_LENGTH],
    /// Name length (excluding null terminator)
    pub name_length: u16,
}

impl ObjectNameInfo {
    /// Create empty name info
    pub const fn new() -> Self {
        Self {
            directory: ptr::null_mut(),
            name: [0; OB_MAX_NAME_LENGTH],
            name_length: 0,
        }
    }

    /// Set the object name
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(OB_MAX_NAME_LENGTH - 1);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name[len] = 0;
        self.name_length = len as u16;
    }

    /// Get the object name as a slice
    pub fn name_slice(&self) -> &[u8] {
        &self.name[..self.name_length as usize]
    }
}

/// Object header - precedes every kernel object
#[repr(C)]
pub struct ObjectHeader {
    /// Pointer reference count (direct pointers to object)
    pointer_count: AtomicI32,
    /// Handle reference count (handles to object)
    handle_count: AtomicI32,
    /// Object type
    pub object_type: *mut super::object_type::ObjectType,
    /// Object flags
    pub flags: AtomicU32,
    /// Pointer to name info (if OB_FLAG_NAMED is set)
    pub name_info: *mut ObjectNameInfo,
    /// Security descriptor (if OB_FLAG_SECURITY is set)
    pub security_descriptor: *mut u8,
    /// Owner process (for quota tracking)
    pub owner_process: *mut crate::ke::KProcess,
    /// Quota charged for this object
    pub quota_charged: u32,
}

// Safety: ObjectHeader uses atomic operations for ref counts
unsafe impl Sync for ObjectHeader {}
unsafe impl Send for ObjectHeader {}

impl ObjectHeader {
    /// Create a new object header
    pub const fn new() -> Self {
        Self {
            pointer_count: AtomicI32::new(1), // Initial reference
            handle_count: AtomicI32::new(0),
            object_type: ptr::null_mut(),
            flags: AtomicU32::new(0),
            name_info: ptr::null_mut(),
            security_descriptor: ptr::null_mut(),
            owner_process: ptr::null_mut(),
            quota_charged: 0,
        }
    }

    /// Initialize the object header with a type
    pub fn init(&mut self, object_type: *mut super::object_type::ObjectType) {
        self.pointer_count = AtomicI32::new(1);
        self.handle_count = AtomicI32::new(0);
        self.object_type = object_type;
        self.flags = AtomicU32::new(0);
        self.name_info = ptr::null_mut();
        self.security_descriptor = ptr::null_mut();
        self.owner_process = ptr::null_mut();
        self.quota_charged = 0;
    }

    /// Get the object body (immediately follows the header)
    #[inline]
    pub fn body(&self) -> *mut u8 {
        unsafe {
            (self as *const Self as *mut u8).add(core::mem::size_of::<Self>())
        }
    }

    /// Get the header from an object body pointer
    #[inline]
    pub unsafe fn from_body<T>(body: *const T) -> *mut ObjectHeader {
        (body as *mut u8).sub(core::mem::size_of::<ObjectHeader>()) as *mut ObjectHeader
    }

    /// Increment pointer reference count
    #[inline]
    pub fn reference(&self) -> i32 {
        self.pointer_count.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Decrement pointer reference count
    ///
    /// Returns true if this was the last reference
    #[inline]
    pub fn dereference(&self) -> bool {
        let old = self.pointer_count.fetch_sub(1, Ordering::SeqCst);
        old == 1
    }

    /// Get current pointer reference count
    #[inline]
    pub fn pointer_count(&self) -> i32 {
        self.pointer_count.load(Ordering::SeqCst)
    }

    /// Increment handle reference count
    #[inline]
    pub fn reference_handle(&self) -> i32 {
        self.handle_count.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Decrement handle reference count
    #[inline]
    pub fn dereference_handle(&self) -> i32 {
        self.handle_count.fetch_sub(1, Ordering::SeqCst) - 1
    }

    /// Get current handle reference count
    #[inline]
    pub fn handle_count(&self) -> i32 {
        self.handle_count.load(Ordering::SeqCst)
    }

    /// Check if object has a specific flag
    #[inline]
    pub fn has_flag(&self, flag: u8) -> bool {
        (self.flags.load(Ordering::SeqCst) & flag as u32) != 0
    }

    /// Set a flag
    #[inline]
    pub fn set_flag(&self, flag: u8) {
        self.flags.fetch_or(flag as u32, Ordering::SeqCst);
    }

    /// Clear a flag
    #[inline]
    pub fn clear_flag(&self, flag: u8) {
        self.flags.fetch_and(!(flag as u32), Ordering::SeqCst);
    }

    /// Check if object is permanent
    #[inline]
    pub fn is_permanent(&self) -> bool {
        self.has_flag(flags::OB_FLAG_PERMANENT)
    }

    /// Check if object has a name
    #[inline]
    pub fn is_named(&self) -> bool {
        self.has_flag(flags::OB_FLAG_NAMED)
    }

    /// Get the object type
    #[inline]
    pub fn get_type(&self) -> Option<&super::object_type::ObjectType> {
        if self.object_type.is_null() {
            None
        } else {
            unsafe { Some(&*self.object_type) }
        }
    }

    /// Get the object name (if named)
    pub fn get_name(&self) -> Option<&[u8]> {
        if self.name_info.is_null() {
            None
        } else {
            unsafe { Some((*self.name_info).name_slice()) }
        }
    }
}

impl Default for ObjectHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro to get object header from object body
#[macro_export]
macro_rules! object_header {
    ($obj:expr) => {
        unsafe { $crate::ob::ObjectHeader::from_body($obj) }
    };
}
