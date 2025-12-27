//! Handle Table Implementation
//!
//! Each process has a handle table that maps handles (small integers)
//! to kernel objects. This provides:
//! - User-mode access to kernel objects
//! - Reference counting integration
//! - Access rights checking
//!
//! # Handle Format
//! Handles are multiples of 4 (so bits 0-1 are always 0).
//! This allows using those bits for flags in some contexts.
//!
//! # Handle Table Structure
//! Windows uses a 3-level table for handles, but we use a simpler
//! flat array for now (sufficient for early development).

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use super::header::ObjectHeader;
use super::object_type::ObjectType;
use crate::ke::SpinLock;

/// Handle type (unsigned 32-bit, like Windows HANDLE)
pub type Handle = u32;

/// Invalid handle value
pub const INVALID_HANDLE_VALUE: Handle = 0xFFFFFFFF;

/// Null handle
pub const NULL_HANDLE: Handle = 0;

/// Handle increment (handles are multiples of 4)
pub const HANDLE_INCREMENT: Handle = 4;

/// Maximum handles per process (for our simple implementation)
pub const MAX_HANDLES: usize = 1024;

/// Handle table entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HandleTableEntry {
    /// Pointer to object (null if entry is free)
    pub object: *mut u8,
    /// Granted access mask
    pub access_mask: u32,
    /// Handle attributes (inherit, protect, etc.)
    pub attributes: u32,
}

impl HandleTableEntry {
    /// Create an empty entry
    pub const fn new() -> Self {
        Self {
            object: ptr::null_mut(),
            access_mask: 0,
            attributes: 0,
        }
    }

    /// Check if entry is in use
    #[inline]
    pub fn is_used(&self) -> bool {
        !self.object.is_null()
    }

    /// Clear the entry
    pub fn clear(&mut self) {
        self.object = ptr::null_mut();
        self.access_mask = 0;
        self.attributes = 0;
    }
}

impl Default for HandleTableEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle attributes
pub mod handle_attributes {
    /// Handle is inherited by child processes
    pub const OBJ_INHERIT: u32 = 0x00000002;
    /// Handle is protected from close
    pub const OBJ_PROTECT_CLOSE: u32 = 0x00000001;
    /// Kernel handle (high bit set)
    pub const OBJ_KERNEL_HANDLE: u32 = 0x80000000;
}

/// Handle table for a process
#[repr(C)]
pub struct HandleTable {
    /// Table entries
    entries: [HandleTableEntry; MAX_HANDLES],
    /// Number of handles in use
    handle_count: AtomicU32,
    /// Next handle hint (for faster allocation)
    next_handle_hint: u32,
    /// Lock for table operations
    lock: SpinLock<()>,
    /// Owning process
    pub owner_process: *mut crate::ke::KProcess,
}

// Safety: HandleTable uses locks for synchronization
unsafe impl Sync for HandleTable {}
unsafe impl Send for HandleTable {}

impl HandleTable {
    /// Create a new empty handle table
    pub const fn new() -> Self {
        Self {
            entries: [HandleTableEntry::new(); MAX_HANDLES],
            handle_count: AtomicU32::new(0),
            next_handle_hint: HANDLE_INCREMENT,
            lock: SpinLock::new(()),
            owner_process: ptr::null_mut(),
        }
    }

    /// Initialize the handle table
    pub fn init(&mut self, owner: *mut crate::ke::KProcess) {
        self.owner_process = owner;
        self.handle_count = AtomicU32::new(0);
        self.next_handle_hint = HANDLE_INCREMENT;
        for entry in self.entries.iter_mut() {
            entry.clear();
        }
    }

    /// Convert handle to entry index
    #[inline]
    fn handle_to_index(handle: Handle) -> Option<usize> {
        if handle == 0 || handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let index = (handle / HANDLE_INCREMENT) as usize;
        if index >= MAX_HANDLES {
            None
        } else {
            Some(index)
        }
    }

    /// Convert entry index to handle
    #[inline]
    fn index_to_handle(index: usize) -> Handle {
        (index as Handle) * HANDLE_INCREMENT
    }

    /// Allocate a new handle for an object
    ///
    /// # Arguments
    /// * `object` - Pointer to the object body
    /// * `access_mask` - Granted access rights
    /// * `attributes` - Handle attributes
    ///
    /// # Returns
    /// The new handle, or INVALID_HANDLE_VALUE on failure
    pub unsafe fn create_handle(
        &mut self,
        object: *mut u8,
        access_mask: u32,
        attributes: u32,
    ) -> Handle {
        if object.is_null() {
            return INVALID_HANDLE_VALUE;
        }

        let _guard = self.lock.lock();

        // Find a free entry starting from hint
        let start_index = (self.next_handle_hint / HANDLE_INCREMENT) as usize;
        let mut found_index = None;

        // Search from hint to end
        for i in start_index..MAX_HANDLES {
            if !self.entries[i].is_used() {
                found_index = Some(i);
                break;
            }
        }

        // If not found, search from beginning to hint
        if found_index.is_none() {
            for i in 1..start_index {
                if !self.entries[i].is_used() {
                    found_index = Some(i);
                    break;
                }
            }
        }

        let index = match found_index {
            Some(i) => i,
            None => return INVALID_HANDLE_VALUE, // Table full
        };

        // Set up the entry
        self.entries[index] = HandleTableEntry {
            object,
            access_mask,
            attributes,
        };

        // Update hint for next allocation
        self.next_handle_hint = Self::index_to_handle(index + 1);
        if self.next_handle_hint >= Self::index_to_handle(MAX_HANDLES) {
            self.next_handle_hint = HANDLE_INCREMENT;
        }

        // Increment counts
        self.handle_count.fetch_add(1, Ordering::SeqCst);

        // Reference the object
        let header = ObjectHeader::from_body(object);
        (*header).reference_handle();

        // Update type handle count
        if let Some(obj_type) = (*header).get_type() {
            obj_type.increment_handle_count();
        }

        Self::index_to_handle(index)
    }

    /// Close a handle
    ///
    /// # Returns
    /// true if handle was valid and closed, false otherwise
    pub unsafe fn close_handle(&mut self, handle: Handle) -> bool {
        let index = match Self::handle_to_index(handle) {
            Some(i) => i,
            None => return false,
        };

        let _guard = self.lock.lock();

        let entry = &mut self.entries[index];
        if !entry.is_used() {
            return false;
        }

        // Check if protected from close
        if (entry.attributes & handle_attributes::OBJ_PROTECT_CLOSE) != 0 {
            return false;
        }

        let object = entry.object;

        // Get header and type
        let header = ObjectHeader::from_body(object);
        let remaining = (*header).dereference_handle();

        // Call close callback if any
        if let Some(obj_type) = (*header).get_type() {
            obj_type.decrement_handle_count();
            if let Some(close_proc) = obj_type.callbacks.close {
                close_proc(object, remaining);
            }
        }

        // Clear the entry
        entry.clear();

        // Decrement table handle count
        self.handle_count.fetch_sub(1, Ordering::SeqCst);

        // Also decrement pointer count (handle implied a reference)
        let should_delete = (*header).dereference();
        if should_delete && !(*header).is_permanent() {
            // Object should be deleted
            self.delete_object(object);
        }

        true
    }

    /// Look up an object by handle
    ///
    /// # Arguments
    /// * `handle` - The handle to look up
    /// * `desired_access` - Access rights to check for
    ///
    /// # Returns
    /// Pointer to object body, or null if invalid/access denied
    pub unsafe fn reference_object_by_handle(
        &self,
        handle: Handle,
        desired_access: u32,
    ) -> *mut u8 {
        let index = match Self::handle_to_index(handle) {
            Some(i) => i,
            None => return ptr::null_mut(),
        };

        let _guard = self.lock.lock();

        let entry = &self.entries[index];
        if !entry.is_used() {
            return ptr::null_mut();
        }

        // Check access
        if desired_access != 0 && (entry.access_mask & desired_access) != desired_access {
            return ptr::null_mut();
        }

        // Reference the object
        let header = ObjectHeader::from_body(entry.object);
        (*header).reference();

        entry.object
    }

    /// Get handle entry without referencing
    pub fn get_entry(&self, handle: Handle) -> Option<&HandleTableEntry> {
        let index = Self::handle_to_index(handle)?;
        let entry = &self.entries[index];
        if entry.is_used() {
            Some(entry)
        } else {
            None
        }
    }

    /// Get mutable handle entry
    pub fn get_entry_mut(&mut self, handle: Handle) -> Option<&mut HandleTableEntry> {
        let index = Self::handle_to_index(handle)?;
        let entry = &mut self.entries[index];
        if entry.is_used() {
            Some(entry)
        } else {
            None
        }
    }

    /// Duplicate a handle
    ///
    /// # Returns
    /// The new handle, or INVALID_HANDLE_VALUE on failure
    pub unsafe fn duplicate_handle(
        &mut self,
        source_handle: Handle,
        desired_access: u32,
        attributes: u32,
    ) -> Handle {
        let index = match Self::handle_to_index(source_handle) {
            Some(i) => i,
            None => return INVALID_HANDLE_VALUE,
        };

        let _guard = self.lock.lock();

        let source_entry = &self.entries[index];
        if !source_entry.is_used() {
            return INVALID_HANDLE_VALUE;
        }

        // Use source access if 0
        let access = if desired_access == 0 {
            source_entry.access_mask
        } else {
            // Can only request subset of source access
            desired_access & source_entry.access_mask
        };

        drop(_guard);

        // Create new handle to same object
        self.create_handle(source_entry.object, access, attributes)
    }

    /// Get number of handles in table
    #[inline]
    pub fn count(&self) -> u32 {
        self.handle_count.load(Ordering::SeqCst)
    }

    /// Delete an object (called when last reference removed)
    unsafe fn delete_object(&self, object: *mut u8) {
        let header = ObjectHeader::from_body(object);

        // Set delete in progress flag
        (*header).set_flag(super::header::flags::OB_FLAG_DELETE_IN_PROGRESS);

        // Call delete callback
        if let Some(obj_type) = (*header).get_type() {
            obj_type.decrement_object_count();
            if let Some(delete_proc) = obj_type.callbacks.delete {
                delete_proc(object);
            }
        }

        // TODO: Remove from namespace if named
        // TODO: Free memory (need allocator)
    }

    /// Close all handles in the table (for process termination)
    pub unsafe fn close_all(&mut self) {
        let _guard = self.lock.lock();

        for i in 1..MAX_HANDLES {
            if self.entries[i].is_used() {
                // Clear protection to allow close
                self.entries[i].attributes &= !handle_attributes::OBJ_PROTECT_CLOSE;
            }
        }

        drop(_guard);

        // Close each handle
        for i in 1..MAX_HANDLES {
            let handle = Self::index_to_handle(i);
            self.close_handle(handle);
        }
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Handle Operations
// ============================================================================

/// Create a handle in the current process
///
/// # Safety
/// Object must be valid
pub unsafe fn ob_create_handle(
    object: *mut u8,
    access_mask: u32,
    attributes: u32,
) -> Handle {
    // Get current process's handle table
    let prcb = crate::ke::prcb::get_current_prcb_mut();
    if prcb.current_thread.is_null() {
        return INVALID_HANDLE_VALUE;
    }

    let process = (*prcb.current_thread).process;
    if process.is_null() {
        return INVALID_HANDLE_VALUE;
    }

    // Get handle table from process
    // For now, use the system handle table
    let table = get_system_handle_table();
    (*table).create_handle(object, access_mask, attributes)
}

/// Close a handle in the current process
pub unsafe fn ob_close_handle(handle: Handle) -> bool {
    let table = get_system_handle_table();
    (*table).close_handle(handle)
}

/// Reference an object by handle
pub unsafe fn ob_reference_object_by_handle(
    handle: Handle,
    desired_access: u32,
) -> *mut u8 {
    let table = get_system_handle_table();
    (*table).reference_object_by_handle(handle, desired_access)
}

/// Dereference an object (after use)
pub unsafe fn ob_dereference_object(object: *mut u8) {
    if object.is_null() {
        return;
    }
    let header = ObjectHeader::from_body(object);
    (*header).dereference();
}

// ============================================================================
// System Handle Table (Global)
// ============================================================================

/// System handle table (for kernel-mode handles)
static mut SYSTEM_HANDLE_TABLE: HandleTable = HandleTable::new();

/// Get the system handle table
pub fn get_system_handle_table() -> *mut HandleTable {
    unsafe { &mut SYSTEM_HANDLE_TABLE as *mut HandleTable }
}

/// Initialize the system handle table
///
/// # Safety
/// Must be called once during kernel initialization
pub unsafe fn init_system_handle_table() {
    SYSTEM_HANDLE_TABLE.init(crate::ke::process::get_system_process_mut());
    crate::serial_println!("[OB] System handle table initialized");
}
