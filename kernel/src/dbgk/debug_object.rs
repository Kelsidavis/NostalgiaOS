//! Debug Object Management
//!
//! Provides the DEBUG_OBJECT structure and its lifecycle management.
//! Debug objects represent a debug session and contain the queue of
//! debug events waiting for the debugger to process.

use crate::ex::fast_mutex::FastMutex;
use crate::ke::event::KEvent;
use crate::ke::list::ListEntry;
use crate::ps::cid::ClientId;
use super::event::{DebugEvent, ContinueStatus, DbgkmApiMsg};
use crate::ke::event::EventType;

/// Debug object flag: deletion is pending
pub const DEBUG_OBJECT_DELETE_PENDING: u32 = 0x01;
/// Debug object flag: kill processes when debug object handle closed
pub const DEBUG_OBJECT_KILL_ON_CLOSE: u32 = 0x02;

/// Maximum queued events per debug object
const MAX_DEBUG_EVENTS: usize = 64;

/// Debug Object
///
/// Represents a debug session. Contains a queue of debug events
/// waiting for the debugger to process.
#[repr(C)]
pub struct DebugObject {
    /// Event signaled when events are available
    pub events_present: KEvent,
    /// Mutex protecting this structure
    pub mutex: FastMutex,
    /// List head for queued debug events
    pub event_list: ListEntry,
    /// Object flags
    pub flags: u32,
    /// Number of queued events
    pub event_count: u32,
    /// Static storage for debug events
    events: [DebugEvent; MAX_DEBUG_EVENTS],
    /// Bitmap of which event slots are in use
    event_in_use: [bool; MAX_DEBUG_EVENTS],
}

impl DebugObject {
    /// Create a new debug object
    pub const fn new() -> Self {
        const EMPTY_EVENT: DebugEvent = DebugEvent::new();
        Self {
            events_present: KEvent::new(),
            mutex: FastMutex::new(),
            event_list: ListEntry::new(),
            flags: 0,
            event_count: 0,
            events: [EMPTY_EVENT; MAX_DEBUG_EVENTS],
            event_in_use: [false; MAX_DEBUG_EVENTS],
        }
    }

    /// Initialize the debug object
    pub fn init(&mut self, flags: u32) {
        self.events_present.init(EventType::Notification, false); // notification event, not signaled
        self.mutex.init();
        self.event_list.init_head();
        self.flags = flags;
        self.event_count = 0;

        for i in 0..MAX_DEBUG_EVENTS {
            self.event_in_use[i] = false;
        }
    }

    /// Check if object is being deleted
    pub fn is_delete_pending(&self) -> bool {
        self.flags & DEBUG_OBJECT_DELETE_PENDING != 0
    }

    /// Check if processes should be killed on close
    pub fn kill_on_close(&self) -> bool {
        self.flags & DEBUG_OBJECT_KILL_ON_CLOSE != 0
    }

    /// Allocate a debug event slot
    fn allocate_event(&mut self) -> Option<usize> {
        for i in 0..MAX_DEBUG_EVENTS {
            if !self.event_in_use[i] {
                self.event_in_use[i] = true;
                return Some(i);
            }
        }
        None
    }

    /// Free a debug event slot
    fn free_event(&mut self, index: usize) {
        if index < MAX_DEBUG_EVENTS {
            self.event_in_use[index] = false;
        }
    }

    /// Get event by index
    pub fn get_event_mut(&mut self, index: usize) -> Option<&mut DebugEvent> {
        if index < MAX_DEBUG_EVENTS && self.event_in_use[index] {
            Some(&mut self.events[index])
        } else {
            None
        }
    }

    /// Find event by client ID
    pub fn find_event_by_client_id(&self, client_id: &ClientId) -> Option<usize> {
        for i in 0..MAX_DEBUG_EVENTS {
            if self.event_in_use[i] {
                if self.events[i].client_id.unique_process == client_id.unique_process
                    && self.events[i].client_id.unique_thread == client_id.unique_thread
                    && self.events[i].is_read()
                {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Queue a debug event
    ///
    /// Returns the event index if successful
    pub fn queue_event(
        &mut self,
        process: usize,
        thread: usize,
        client_id: ClientId,
        api_msg: DbgkmApiMsg,
        flags: u32,
    ) -> Option<usize> {
        // Allocate event slot
        let index = self.allocate_event()?;

        // Initialize the event
        let event = &mut self.events[index];
        event.event_list.init_head();
        event.continue_event.init(EventType::Synchronization, false); // synchronization event
        event.client_id = client_id;
        event.process = process;
        event.thread = thread;
        event.status = 0;
        event.flags = flags;
        event.backout_thread = 0;
        event.api_msg = api_msg;

        // Insert into the list
        unsafe { self.event_list.insert_tail(&mut event.event_list); }
        self.event_count += 1;

        // Signal that events are present
        unsafe { self.events_present.set(); }

        Some(index)
    }

    /// Get the next unread event
    ///
    /// Returns the event index if one is available
    pub fn get_next_event(&mut self) -> Option<usize> {
        for i in 0..MAX_DEBUG_EVENTS {
            if self.event_in_use[i] && !self.events[i].is_read() && !self.events[i].is_inactive() {
                self.events[i].set_read();
                return Some(i);
            }
        }
        None
    }

    /// Complete an event (debugger called continue)
    pub fn complete_event(&mut self, index: usize, status: i32) -> bool {
        if index >= MAX_DEBUG_EVENTS || !self.event_in_use[index] {
            return false;
        }

        let event = &mut self.events[index];

        // Set the status
        event.status = status;
        event.api_msg.returned_status = status;

        // Remove from list
        unsafe { event.event_list.remove_entry(); }
        self.event_count = self.event_count.saturating_sub(1);

        // Signal the continue event to wake the waiting thread
        unsafe { event.continue_event.set(); }

        // Free the event slot
        self.free_event(index);

        // Update events_present state
        if self.event_count == 0 {
            unsafe { self.events_present.reset(); }
        }

        true
    }

    /// Wait for the continue event
    ///
    /// Called by the thread that generated the event after queueing it.
    /// Returns the continue status.
    pub fn wait_for_continue(&self, index: usize) -> i32 {
        if index >= MAX_DEBUG_EVENTS {
            return ContinueStatus::Continue as i32;
        }

        // Wait for the debugger to continue us
        unsafe { self.events[index].continue_event.wait(); }

        self.events[index].status
    }

    /// Clear all events (called during cleanup)
    pub fn clear_all_events(&mut self) {
        for i in 0..MAX_DEBUG_EVENTS {
            if self.event_in_use[i] {
                let event = &mut self.events[i];
                event.status = -1073741510i32; // STATUS_DEBUGGER_INACTIVE
                unsafe { event.continue_event.set(); }
                unsafe { event.event_list.remove_entry(); }
                self.event_in_use[i] = false;
            }
        }
        self.event_count = 0;
        unsafe { self.events_present.reset(); }
    }
}

impl Default for DebugObject {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Create a debug object
pub fn dbgk_create_debug_object(flags: u32) -> Option<DebugObject> {
    let mut obj = DebugObject::new();
    obj.init(flags);
    Some(obj)
}

/// Set the debug object for a process
///
/// Associates a debug object with a process, enabling debugging.
pub fn dbgk_set_process_debug_object(
    process: usize,
    debug_object: *mut DebugObject,
) -> bool {
    if process == 0 || debug_object.is_null() {
        return false;
    }

    // Acquire the global debug port lock
    super::acquire_debug_port_lock();

    // TODO: Set process->DebugPort = debug_object
    // For now, we just track the association

    super::release_debug_port_lock();

    true
}

/// Clear the debug object from a process
pub fn dbgk_clear_process_debug_object(process: usize) {
    if process == 0 {
        return;
    }

    super::acquire_debug_port_lock();

    // TODO: Clear process->DebugPort

    super::release_debug_port_lock();
}

/// Wait for a debug event
///
/// Blocks until a debug event is available or timeout expires.
///
/// # Arguments
/// * `debug_object` - The debug object to wait on
/// * `timeout_ms` - Timeout in milliseconds (0 for no wait, -1 for infinite)
///
/// # Returns
/// Event index if available, None if timeout or error
pub fn dbgk_wait_for_debug_event(
    debug_object: &mut DebugObject,
    timeout_ms: i64,
) -> Option<usize> {
    debug_object.mutex.acquire();

    // Check for pending events first
    if let Some(index) = debug_object.get_next_event() {
        debug_object.mutex.release();
        return Some(index);
    }

    // No events - need to wait
    debug_object.mutex.release();

    // Wait for events to become available
    if timeout_ms == 0 {
        return None; // Non-blocking
    }

    let _wait_result = if timeout_ms < 0 {
        unsafe { debug_object.events_present.wait(); }
        true
    } else {
        unsafe { debug_object.events_present.wait_timeout(timeout_ms as u64) }
    };

    // Re-acquire mutex and try again
    debug_object.mutex.acquire();
    let result = debug_object.get_next_event();
    debug_object.mutex.release();

    result
}

/// Continue a debug event
///
/// Called by the debugger to resume execution of a debugged thread.
///
/// # Arguments
/// * `debug_object` - The debug object
/// * `client_id` - Client ID of the thread to continue
/// * `continue_status` - How to continue (handle exception, terminate, etc.)
pub fn dbgk_debug_continue(
    debug_object: &mut DebugObject,
    client_id: &ClientId,
    continue_status: ContinueStatus,
) -> bool {
    debug_object.mutex.acquire();

    // Find the event for this client ID
    if let Some(index) = debug_object.find_event_by_client_id(client_id) {
        let result = debug_object.complete_event(index, continue_status as i32);
        debug_object.mutex.release();
        result
    } else {
        debug_object.mutex.release();
        false
    }
}

/// Close callback for debug objects
///
/// Called when the last handle to the debug object is closed.
pub fn dbgk_close_object(object: *mut u8) {
    if object.is_null() {
        return;
    }

    let debug_object = unsafe { &mut *(object as *mut DebugObject) };

    debug_object.mutex.acquire();

    // Mark as being deleted
    debug_object.flags |= DEBUG_OBJECT_DELETE_PENDING;

    // If kill-on-close is set, would need to terminate all debugged processes
    // TODO: Iterate all processes and terminate those with this debug object

    // Wake up all waiting threads with error status
    debug_object.clear_all_events();

    debug_object.mutex.release();
}

/// Delete callback for debug objects
///
/// Called when the object reference count reaches zero.
pub fn dbgk_delete_object(object: *mut u8) {
    if object.is_null() {
        return;
    }

    let debug_object = unsafe { &mut *(object as *mut DebugObject) };

    // Assert that event list is empty
    debug_assert!(debug_object.event_count == 0);
}
