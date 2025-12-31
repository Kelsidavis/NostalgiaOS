//! Debug Object Management
//!
//! Provides the DEBUG_OBJECT structure and its lifecycle management.
//! Debug objects represent a debug session and contain the queue of
//! debug events waiting for the debugger to process.

extern crate alloc;

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

// ============================================================================
// Debug Port Lookup Functions (NT 5.2 API)
// ============================================================================

/// STATUS_PORT_NOT_SET - No debug port is set for this process
pub const STATUS_PORT_NOT_SET: i32 = 0xC0000353u32 as i32;

/// STATUS_SUCCESS
pub const STATUS_SUCCESS: i32 = 0;

/// DEBUG_ALL_ACCESS
pub const DEBUG_ALL_ACCESS: u32 = 0x1F000F;

/// Global tracking of debugged processes
static DEBUGGED_PROCESSES: spin::Mutex<DebuggedProcessList> =
    spin::Mutex::new(DebuggedProcessList::new());

/// Maximum number of tracked debugged processes
const MAX_DEBUGGED_PROCESSES: usize = 64;

/// Entry tracking a debugged process
#[derive(Clone, Copy)]
struct DebuggedProcessEntry {
    /// Process ID
    process_id: usize,
    /// Pointer to EPROCESS (or placeholder)
    process: usize,
    /// Debug object pointer
    debug_object: usize,
    /// Is currently being debugged
    active: bool,
}

impl DebuggedProcessEntry {
    pub const fn new() -> Self {
        Self {
            process_id: 0,
            process: 0,
            debug_object: 0,
            active: false,
        }
    }
}

/// List of all debugged processes
struct DebuggedProcessList {
    entries: [DebuggedProcessEntry; MAX_DEBUGGED_PROCESSES],
    count: usize,
}

impl DebuggedProcessList {
    pub const fn new() -> Self {
        Self {
            entries: [DebuggedProcessEntry::new(); MAX_DEBUGGED_PROCESSES],
            count: 0,
        }
    }
}

/// DBGK Statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct DbgkStats {
    /// Total debug sessions created
    pub sessions_created: u64,
    /// Total debug sessions closed
    pub sessions_closed: u64,
    /// Total processes attached for debugging
    pub processes_attached: u64,
    /// Total processes detached from debugging
    pub processes_detached: u64,
    /// Total debug events generated
    pub events_generated: u64,
    /// Total debug events delivered
    pub events_delivered: u64,
    /// Thread create events
    pub thread_create_events: u64,
    /// Thread exit events
    pub thread_exit_events: u64,
    /// Process exit events
    pub process_exit_events: u64,
    /// Exception events
    pub exception_events: u64,
    /// Module load events
    pub module_load_events: u64,
    /// Module unload events
    pub module_unload_events: u64,
    /// Continue calls
    pub continue_calls: u64,
    /// Currently active debug sessions
    pub active_sessions: u32,
    /// Currently debugged processes
    pub debugged_processes: u32,
}

/// Global DBGK statistics
static DBGK_STATS: spin::Mutex<DbgkStats> = spin::Mutex::new(DbgkStats {
    sessions_created: 0,
    sessions_closed: 0,
    processes_attached: 0,
    processes_detached: 0,
    events_generated: 0,
    events_delivered: 0,
    thread_create_events: 0,
    thread_exit_events: 0,
    process_exit_events: 0,
    exception_events: 0,
    module_load_events: 0,
    module_unload_events: 0,
    continue_calls: 0,
    active_sessions: 0,
    debugged_processes: 0,
});

/// Get DBGK statistics
pub fn dbgk_get_stats() -> DbgkStats {
    *DBGK_STATS.lock()
}

/// Update DBGK statistics
fn update_stats<F: FnOnce(&mut DbgkStats)>(f: F) {
    let mut stats = DBGK_STATS.lock();
    f(&mut stats);
}

/// Reference a process's debug port
///
/// This function safely references the debug port of a target process,
/// allowing the caller to operate on it. The caller must call
/// `dbgk_dereference_process_debug_port` when done.
///
/// # Arguments
/// * `process` - The target process (EPROCESS pointer as usize)
///
/// # Returns
/// Pointer to the debug object if the process has a debug port, 0 otherwise
pub fn dbgk_reference_process_debug_port(process: usize) -> usize {
    if process == 0 {
        return 0;
    }

    super::acquire_debug_port_lock();

    // Look up the process in our tracking list
    let list = DEBUGGED_PROCESSES.lock();
    let mut debug_object = 0usize;

    for entry in &list.entries {
        if entry.active && entry.process == process {
            debug_object = entry.debug_object;
            break;
        }
    }

    super::release_debug_port_lock();

    // If found, reference the debug object
    if debug_object != 0 {
        // In a full implementation, we'd call ObReferenceObject here
        // For now, just return the pointer
    }

    debug_object
}

/// Dereference a process's debug port
///
/// Called after done operating on a debug object obtained from
/// `dbgk_reference_process_debug_port`.
pub fn dbgk_dereference_process_debug_port(debug_object: usize) {
    if debug_object != 0 {
        // In a full implementation, we'd call ObDereferenceObject here
    }
}

/// Open a handle to a process's debug port
///
/// This allows a debugger to obtain a handle to the debug object
/// associated with a process.
///
/// # Arguments
/// * `process` - Target process (EPROCESS pointer as usize)
/// * `kernel_mode` - Whether caller is in kernel mode
/// * `handle_out` - Output handle (placeholder - returns debug object pointer)
///
/// # Returns
/// STATUS_SUCCESS or STATUS_PORT_NOT_SET
pub fn dbgk_open_process_debug_port(
    process: usize,
    _kernel_mode: bool,
    handle_out: &mut usize,
) -> i32 {
    *handle_out = 0;

    if process == 0 {
        return STATUS_PORT_NOT_SET;
    }

    super::acquire_debug_port_lock();

    let list = DEBUGGED_PROCESSES.lock();
    let mut found = false;
    let mut debug_object = 0usize;

    for entry in &list.entries {
        if entry.active && entry.process == process {
            debug_object = entry.debug_object;
            found = true;
            break;
        }
    }

    drop(list); // Release the list lock before doing more work
    super::release_debug_port_lock();

    if !found || debug_object == 0 {
        return STATUS_PORT_NOT_SET;
    }

    // In a full implementation, we'd:
    // 1. ObReferenceObject(debug_object)
    // 2. Check DEBUG_OBJECT_DELETE_PENDING
    // 3. ObOpenObjectByPointer to get a handle
    // 4. On failure, ObDereferenceObject

    // For now, just return the debug object pointer as the "handle"
    *handle_out = debug_object;
    STATUS_SUCCESS
}

/// Register a process as being debugged
///
/// Internal function to track which processes are being debugged.
pub fn dbgk_register_debugged_process(
    process_id: usize,
    process: usize,
    debug_object: usize,
) -> bool {
    let mut list = DEBUGGED_PROCESSES.lock();

    // Find a free slot
    for entry in &mut list.entries {
        if !entry.active {
            entry.process_id = process_id;
            entry.process = process;
            entry.debug_object = debug_object;
            entry.active = true;
            list.count += 1;

            update_stats(|s| {
                s.processes_attached += 1;
                s.debugged_processes += 1;
            });

            return true;
        }
    }

    false // No free slots
}

/// Unregister a process from debugging
pub fn dbgk_unregister_debugged_process(process: usize) -> bool {
    let mut list = DEBUGGED_PROCESSES.lock();

    for entry in &mut list.entries {
        if entry.active && entry.process == process {
            entry.active = false;
            entry.process = 0;
            entry.process_id = 0;
            entry.debug_object = 0;
            list.count = list.count.saturating_sub(1);

            update_stats(|s| {
                s.processes_detached += 1;
                s.debugged_processes = s.debugged_processes.saturating_sub(1);
            });

            return true;
        }
    }

    false
}

/// Get list of all debugged processes
///
/// Returns a list of (process_id, process_ptr, debug_object) tuples
pub fn dbgk_get_debugged_processes() -> alloc::vec::Vec<(usize, usize, usize)> {
    let mut result = alloc::vec::Vec::new();
    let list = DEBUGGED_PROCESSES.lock();

    for entry in &list.entries {
        if entry.active {
            result.push((entry.process_id, entry.process, entry.debug_object));
        }
    }

    result
}

/// Check if a process is being debugged
pub fn dbgk_is_process_being_debugged(process: usize) -> bool {
    let list = DEBUGGED_PROCESSES.lock();

    for entry in &list.entries {
        if entry.active && entry.process == process {
            return true;
        }
    }

    false
}

/// Get the debug object for a process
///
/// Returns 0 if the process is not being debugged.
pub fn dbgk_get_process_debug_object(process: usize) -> usize {
    let list = DEBUGGED_PROCESSES.lock();

    for entry in &list.entries {
        if entry.active && entry.process == process {
            return entry.debug_object;
        }
    }

    0
}

/// Increment event generated stat
pub fn dbgk_log_event_generated(event_type: super::event::DebugApiNumber) {
    use super::event::DebugApiNumber;

    update_stats(|s| {
        s.events_generated += 1;
        match event_type {
            DebugApiNumber::CreateThreadApi => s.thread_create_events += 1,
            DebugApiNumber::ExitThreadApi => s.thread_exit_events += 1,
            DebugApiNumber::ExitProcessApi => s.process_exit_events += 1,
            DebugApiNumber::ExceptionApi => s.exception_events += 1,
            DebugApiNumber::LoadDllApi => s.module_load_events += 1,
            DebugApiNumber::UnloadDllApi => s.module_unload_events += 1,
            _ => {}
        }
    });
}

/// Increment continue calls stat
pub fn dbgk_log_continue() {
    update_stats(|s| {
        s.continue_calls += 1;
        s.events_delivered += 1;
    });
}

/// Increment session created stat
pub fn dbgk_log_session_created() {
    update_stats(|s| {
        s.sessions_created += 1;
        s.active_sessions += 1;
    });
}

/// Increment session closed stat
pub fn dbgk_log_session_closed() {
    update_stats(|s| {
        s.sessions_closed += 1;
        s.active_sessions = s.active_sessions.saturating_sub(1);
    });
}
