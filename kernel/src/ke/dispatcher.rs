//! Dispatcher Objects (DISPATCHER_HEADER)
//!
//! All waitable kernel objects (mutex, event, semaphore, thread, etc.)
//! share a common DISPATCHER_HEADER structure that enables the wait
//! system to handle them uniformly.
//!
//! The dispatcher handles:
//! - Object signaling (making objects signaled/not-signaled)
//! - Thread waiting (blocking threads until objects are signaled)
//! - Wait satisfaction (waking threads when objects become signaled)

use core::cell::UnsafeCell;
use core::ptr;
use super::list::ListEntry;
use super::thread::KThread;

/// Object types for dispatcher objects
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DispatcherType {
    /// Event object (manual or auto-reset)
    Event = 0,
    /// Mutex object
    Mutex = 1,
    /// Semaphore object
    Semaphore = 2,
    /// Timer object
    Timer = 3,
    /// Thread object (can wait for thread termination)
    Thread = 4,
    /// Process object
    Process = 5,
    /// Queue object
    Queue = 6,
}

/// Dispatcher object header
///
/// This is embedded at the start of all waitable objects.
/// Equivalent to NT's DISPATCHER_HEADER.
///
/// Uses interior mutability for fields that change during wait/signal operations.
#[repr(C)]
pub struct DispatcherHeader {
    /// Object type
    pub object_type: DispatcherType,
    /// Object-specific flags
    pub flags: u8,
    /// Size of the object (in 32-bit units, NT compatibility)
    pub size: u8,
    /// Reserved/padding
    pub reserved: u8,
    /// Signal state (interior mutable for wait/signal operations)
    /// - For events: 0 = not signaled, 1 = signaled
    /// - For mutex: 1 = signaled (available), 0 = not signaled (owned)
    /// - For semaphore: count of available resources
    signal_state: UnsafeCell<i32>,
    /// List of threads waiting on this object
    wait_list_head: UnsafeCell<ListEntry>,
}

// Safety: Protected by caller synchronization (spinlocks/interrupt disable)
unsafe impl Sync for DispatcherHeader {}
unsafe impl Send for DispatcherHeader {}

impl DispatcherHeader {
    /// Create a new dispatcher header
    pub const fn new(object_type: DispatcherType) -> Self {
        Self {
            object_type,
            flags: 0,
            size: 0,
            reserved: 0,
            signal_state: UnsafeCell::new(0),
            wait_list_head: UnsafeCell::new(ListEntry::new()),
        }
    }

    /// Initialize the dispatcher header
    pub fn init(&mut self, object_type: DispatcherType, signal_state: i32) {
        self.object_type = object_type;
        self.flags = 0;
        self.size = 0;
        self.reserved = 0;
        unsafe {
            *self.signal_state.get() = signal_state;
            (*self.wait_list_head.get()).init_head();
        }
    }

    /// Get the signal state
    #[inline]
    pub fn signal_state(&self) -> i32 {
        unsafe { *self.signal_state.get() }
    }

    /// Set the signal state
    ///
    /// # Safety
    /// Must be called with proper synchronization
    #[inline]
    pub unsafe fn set_signal_state(&self, state: i32) {
        *self.signal_state.get() = state;
    }

    /// Check if the object is signaled
    #[inline]
    pub fn is_signaled(&self) -> bool {
        self.signal_state() > 0
    }

    /// Get mutable reference to wait list head
    ///
    /// # Safety
    /// Must be called with proper synchronization
    #[inline]
    pub unsafe fn wait_list(&self) -> &mut ListEntry {
        &mut *self.wait_list_head.get()
    }

    /// Check if there are waiters
    #[inline]
    pub fn has_waiters(&self) -> bool {
        unsafe { !(*self.wait_list_head.get()).is_empty() }
    }
}

/// Wait block - represents a thread's wait on an object
///
/// When a thread waits on an object, a wait block is created
/// linking the thread to the object's wait list.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct KWaitBlock {
    /// Link in the object's wait list
    pub wait_list_entry: ListEntry,
    /// Thread that is waiting
    pub thread: *mut KThread,
    /// Object being waited on
    pub object: *mut DispatcherHeader,
    /// Wait type (WaitAll or WaitAny)
    pub wait_type: WaitType,
    /// Block index (for multi-object waits)
    pub block_index: u8,
    /// Reserved
    pub reserved: [u8; 2],
}

impl KWaitBlock {
    /// Create a new wait block
    pub const fn new() -> Self {
        Self {
            wait_list_entry: ListEntry::new(),
            thread: ptr::null_mut(),
            object: ptr::null_mut(),
            wait_type: WaitType::WaitAny,
            block_index: 0,
            reserved: [0; 2],
        }
    }

    /// Initialize a wait block
    pub fn init(&mut self, thread: *mut KThread, object: *mut DispatcherHeader, wait_type: WaitType) {
        self.wait_list_entry.init_head();
        self.thread = thread;
        self.object = object;
        self.wait_type = wait_type;
        self.block_index = 0;
    }
}

impl Default for KWaitBlock {
    fn default() -> Self {
        Self::new()
    }
}

/// Wait type for multi-object waits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WaitType {
    /// Wait for any one object to be signaled
    WaitAny = 0,
    /// Wait for all objects to be signaled
    WaitAll = 1,
}

/// Wait status returned from wait operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum WaitStatus {
    /// Object 0 was signaled (or first object in WaitAny)
    Object0 = 0,
    /// Wait was abandoned (mutex owner terminated)
    Abandoned = 0x80,
    /// Wait timed out
    Timeout = 0x102,
    /// Invalid wait (internal error)
    Invalid = -1,
}

impl WaitStatus {
    /// Create a status for a specific object index
    pub fn object(index: u32) -> Self {
        match index {
            0 => WaitStatus::Object0,
            _ => WaitStatus::Object0, // For now, we only support single object waits
        }
    }
}

/// Maximum number of objects in a multi-object wait
pub const MAXIMUM_WAIT_OBJECTS: usize = 64;

/// Number of built-in wait blocks per thread
pub const THREAD_WAIT_BLOCKS: usize = 4;
