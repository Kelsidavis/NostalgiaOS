//! Debug Object Support
//!
//! Debug objects are used for debugging processes in Windows NT.
//! A debugger creates a debug object and attaches it to a process.
//! The debugged process sends debug events to the debug object.
//!
//! # Key Structures
//!
//! - `DebugObject`: The main debug object with event queue
//! - `DebugEvent`: Events sent by the debugged process
//!
//! # Debug Event Types
//!
//! - CREATE_PROCESS_DEBUG_EVENT (3)
//! - CREATE_THREAD_DEBUG_EVENT (2)
//! - EXCEPTION_DEBUG_EVENT (1)
//! - EXIT_PROCESS_DEBUG_EVENT (5)
//! - EXIT_THREAD_DEBUG_EVENT (4)
//! - LOAD_DLL_DEBUG_EVENT (6)
//! - UNLOAD_DLL_DEBUG_EVENT (7)
//! - OUTPUT_DEBUG_STRING_EVENT (8)

use core::sync::atomic::{AtomicU32, Ordering};
use super::list::ListEntry;
use super::event::{KEvent, EventType};
use super::SpinLock;
use super::dispatcher::WaitStatus;

/// Maximum number of debug objects in the system
pub const MAX_DEBUG_OBJECTS: usize = 64;

/// Maximum number of pending debug events per debug object
pub const MAX_DEBUG_EVENTS: usize = 32;

/// Debug object flags
pub mod debug_flags {
    /// Kill the debugged process when debug object is closed
    pub const DEBUG_KILL_ON_CLOSE: u32 = 0x0001;
    /// Object is being deleted
    pub const DEBUG_OBJECT_DELETE_PENDING: u32 = 0x0002;
}

/// Debug event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DebugEventType {
    /// Exception occurred
    Exception = 1,
    /// Thread created
    CreateThread = 2,
    /// Process created
    CreateProcess = 3,
    /// Thread exited
    ExitThread = 4,
    /// Process exited
    ExitProcess = 5,
    /// DLL loaded
    LoadDll = 6,
    /// DLL unloaded
    UnloadDll = 7,
    /// Debug string output
    OutputDebugString = 8,
    /// RIP event (system error)
    Rip = 9,
}

impl Default for DebugEventType {
    fn default() -> Self {
        DebugEventType::Exception
    }
}

/// Exception debug event info
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ExceptionDebugInfo {
    /// Exception code
    pub exception_code: u32,
    /// Exception flags
    pub exception_flags: u32,
    /// Exception address
    pub exception_address: u64,
    /// First chance exception?
    pub first_chance: bool,
}

/// Create process debug event info
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CreateProcessDebugInfo {
    /// Handle to the process
    pub process_handle: u64,
    /// Handle to the initial thread
    pub thread_handle: u64,
    /// Base of the image
    pub base_of_image: u64,
    /// Start address
    pub start_address: u64,
}

/// Create thread debug event info
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CreateThreadDebugInfo {
    /// Handle to the thread
    pub thread_handle: u64,
    /// Start address
    pub start_address: u64,
}

/// Exit process debug event info
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ExitProcessDebugInfo {
    /// Exit code
    pub exit_code: u32,
}

/// Exit thread debug event info
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ExitThreadDebugInfo {
    /// Exit code
    pub exit_code: u32,
}

/// Load DLL debug event info
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct LoadDllDebugInfo {
    /// Handle to the DLL
    pub file_handle: u64,
    /// Base address of the DLL
    pub base_of_dll: u64,
    /// Offset to the name
    pub name_pointer: u64,
    /// Is this Unicode?
    pub unicode: bool,
}

/// Unload DLL debug event info
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UnloadDllDebugInfo {
    /// Base address of the DLL
    pub base_of_dll: u64,
}

/// Output debug string event info
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct OutputDebugStringInfo {
    /// Pointer to the string
    pub string_pointer: u64,
    /// Length of the string
    pub string_length: u16,
    /// Is this Unicode?
    pub unicode: bool,
}

/// Debug event union
#[derive(Clone, Copy)]
#[repr(C)]
pub union DebugEventInfo {
    pub exception: ExceptionDebugInfo,
    pub create_process: CreateProcessDebugInfo,
    pub create_thread: CreateThreadDebugInfo,
    pub exit_process: ExitProcessDebugInfo,
    pub exit_thread: ExitThreadDebugInfo,
    pub load_dll: LoadDllDebugInfo,
    pub unload_dll: UnloadDllDebugInfo,
    pub output_string: OutputDebugStringInfo,
}

impl Default for DebugEventInfo {
    fn default() -> Self {
        Self { exception: ExceptionDebugInfo::default() }
    }
}

/// Debug event structure
#[repr(C)]
pub struct DebugEvent {
    /// Link for event queue
    pub list_entry: ListEntry,
    /// Process ID
    pub process_id: u32,
    /// Thread ID
    pub thread_id: u32,
    /// Event type
    pub event_type: DebugEventType,
    /// Event-specific info
    pub info: DebugEventInfo,
    /// Has this event been reported?
    pub reported: bool,
    /// Thread waiting to be continued
    pub waiting_thread: *mut u8,
}

impl DebugEvent {
    pub const fn new() -> Self {
        Self {
            list_entry: ListEntry::new(),
            process_id: 0,
            thread_id: 0,
            event_type: DebugEventType::Exception,
            info: DebugEventInfo { exception: ExceptionDebugInfo {
                exception_code: 0,
                exception_flags: 0,
                exception_address: 0,
                first_chance: false
            }},
            reported: false,
            waiting_thread: core::ptr::null_mut(),
        }
    }
}

unsafe impl Sync for DebugEvent {}
unsafe impl Send for DebugEvent {}

/// Debug object structure
#[repr(C)]
pub struct DebugObject {
    /// Kernel event for signaling new events
    pub events_present: KEvent,
    /// Spinlock protecting the event queue
    pub lock: SpinLock<()>,
    /// List head for pending events
    pub event_list: ListEntry,
    /// Number of pending events
    pub event_count: AtomicU32,
    /// Debug object flags
    pub flags: AtomicU32,
    /// Process being debugged (0 if not attached)
    pub debugged_process_id: AtomicU32,
    /// Is this object allocated?
    pub allocated: bool,
}

impl DebugObject {
    pub const fn new() -> Self {
        Self {
            events_present: KEvent::new(),
            lock: SpinLock::new(()),
            event_list: ListEntry::new(),
            event_count: AtomicU32::new(0),
            flags: AtomicU32::new(0),
            debugged_process_id: AtomicU32::new(0),
            allocated: false,
        }
    }

    /// Initialize the debug object
    pub fn init(&mut self) {
        self.events_present.init(EventType::Synchronization, false);
        self.event_list.init_head();
        self.event_count.store(0, Ordering::SeqCst);
        self.flags.store(0, Ordering::SeqCst);
        self.debugged_process_id.store(0, Ordering::SeqCst);
        self.allocated = true;
    }

    /// Check if attached to a process
    pub fn is_attached(&self) -> bool {
        self.debugged_process_id.load(Ordering::SeqCst) != 0
    }

    /// Get the debugged process ID
    pub fn get_debugged_pid(&self) -> u32 {
        self.debugged_process_id.load(Ordering::SeqCst)
    }

    /// Attach to a process
    pub fn attach(&self, pid: u32) {
        self.debugged_process_id.store(pid, Ordering::SeqCst);
    }

    /// Detach from a process
    pub fn detach(&self) {
        self.debugged_process_id.store(0, Ordering::SeqCst);
    }

    /// Set flags
    pub fn set_flags(&self, flags: u32) {
        self.flags.fetch_or(flags, Ordering::SeqCst);
    }

    /// Clear flags
    pub fn clear_flags(&self, flags: u32) {
        self.flags.fetch_and(!flags, Ordering::SeqCst);
    }

    /// Get flags
    pub fn get_flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }

    /// Check if KILL_ON_CLOSE is set
    pub fn kill_on_close(&self) -> bool {
        (self.get_flags() & debug_flags::DEBUG_KILL_ON_CLOSE) != 0
    }

    /// Get event count
    pub fn get_event_count(&self) -> u32 {
        self.event_count.load(Ordering::SeqCst)
    }

    /// Has pending events?
    pub fn has_events(&self) -> bool {
        self.get_event_count() > 0
    }
}

unsafe impl Sync for DebugObject {}
unsafe impl Send for DebugObject {}

// ============================================================================
// Global Debug Object Pool
// ============================================================================

/// Debug object pool
static mut DEBUG_OBJECT_POOL: [DebugObject; MAX_DEBUG_OBJECTS] = {
    const INIT: DebugObject = DebugObject::new();
    [INIT; MAX_DEBUG_OBJECTS]
};

/// Debug event pool
static mut DEBUG_EVENT_POOL: [DebugEvent; MAX_DEBUG_OBJECTS * MAX_DEBUG_EVENTS] = {
    const INIT: DebugEvent = DebugEvent::new();
    [INIT; MAX_DEBUG_OBJECTS * MAX_DEBUG_EVENTS]
};

/// Debug event allocation bitmap
static mut DEBUG_EVENT_BITMAP: u64 = 0;

/// Pool lock
static DEBUG_POOL_LOCK: SpinLock<()> = SpinLock::new(());

// ============================================================================
// Debug Object Functions
// ============================================================================

/// Allocate a new debug object
pub unsafe fn dbgk_create_debug_object(flags: u32) -> Option<usize> {
    let _guard = DEBUG_POOL_LOCK.lock();

    for i in 0..MAX_DEBUG_OBJECTS {
        if !DEBUG_OBJECT_POOL[i].allocated {
            DEBUG_OBJECT_POOL[i].init();
            DEBUG_OBJECT_POOL[i].set_flags(flags);
            return Some(i);
        }
    }
    None
}

/// Get a debug object by index
pub unsafe fn dbgk_get_debug_object(index: usize) -> Option<&'static mut DebugObject> {
    if index < MAX_DEBUG_OBJECTS && DEBUG_OBJECT_POOL[index].allocated {
        Some(&mut DEBUG_OBJECT_POOL[index])
    } else {
        None
    }
}

/// Close a debug object
pub unsafe fn dbgk_close_debug_object(index: usize) {
    if index < MAX_DEBUG_OBJECTS {
        let obj = &mut DEBUG_OBJECT_POOL[index];
        if obj.allocated {
            // If KILL_ON_CLOSE is set and we have an attached process,
            // we would terminate it here
            let pid = obj.get_debugged_pid();
            if obj.kill_on_close() && pid != 0 {
                crate::serial_println!("[DEBUG] Kill on close: would terminate process {}", pid);
                // TODO: Actually terminate the process
            }

            // Free all pending events
            // In a full implementation, we'd walk the event list

            obj.allocated = false;
            obj.debugged_process_id.store(0, Ordering::SeqCst);
            obj.flags.store(0, Ordering::SeqCst);
            obj.event_count.store(0, Ordering::SeqCst);
        }
    }
}

/// Attach debug object to a process
pub unsafe fn dbgk_attach_process(debug_index: usize, pid: u32) -> bool {
    if let Some(obj) = dbgk_get_debug_object(debug_index) {
        if obj.is_attached() {
            return false; // Already attached
        }
        obj.attach(pid);

        // In a full implementation, we'd:
        // 1. Set process->DebugPort = debug_object
        // 2. Generate initial debug events (CREATE_PROCESS, CREATE_THREAD for existing threads, LOAD_DLL for loaded modules)

        crate::serial_println!("[DEBUG] Attached debug object {} to process {}", debug_index, pid);
        true
    } else {
        false
    }
}

/// Detach debug object from a process
pub unsafe fn dbgk_detach_process(debug_index: usize) -> bool {
    if let Some(obj) = dbgk_get_debug_object(debug_index) {
        if !obj.is_attached() {
            return false;
        }
        let pid = obj.get_debugged_pid();
        obj.detach();

        crate::serial_println!("[DEBUG] Detached debug object {} from process {}", debug_index, pid);
        true
    } else {
        false
    }
}

/// Allocate a debug event
unsafe fn alloc_debug_event() -> Option<&'static mut DebugEvent> {
    for i in 0..DEBUG_EVENT_POOL.len() {
        let bit = 1u64 << (i % 64);
        let word = i / 64;
        if word > 0 {
            continue; // Only use first 64 events for simplicity
        }
        if (DEBUG_EVENT_BITMAP & bit) == 0 {
            DEBUG_EVENT_BITMAP |= bit;
            DEBUG_EVENT_POOL[i].list_entry.init_head();
            DEBUG_EVENT_POOL[i].reported = false;
            DEBUG_EVENT_POOL[i].waiting_thread = core::ptr::null_mut();
            return Some(&mut DEBUG_EVENT_POOL[i]);
        }
    }
    None
}

/// Free a debug event
unsafe fn free_debug_event(event: *mut DebugEvent) {
    // Find the index
    let base = DEBUG_EVENT_POOL.as_ptr() as usize;
    let event_addr = event as usize;
    let index = (event_addr - base) / core::mem::size_of::<DebugEvent>();

    if index < 64 {
        DEBUG_EVENT_BITMAP &= !(1u64 << index);
    }
}

/// Queue a debug event to a debug object
pub unsafe fn dbgk_queue_debug_event(
    debug_index: usize,
    event_type: DebugEventType,
    pid: u32,
    tid: u32,
    info: DebugEventInfo,
) -> bool {
    let obj = match dbgk_get_debug_object(debug_index) {
        Some(o) => o,
        None => return false,
    };

    let event = match alloc_debug_event() {
        Some(e) => e,
        None => return false,
    };

    event.event_type = event_type;
    event.process_id = pid;
    event.thread_id = tid;
    event.info = info;
    event.reported = false;

    // Add to queue
    let _guard = obj.lock.lock();
    obj.event_list.insert_tail(&mut event.list_entry);
    obj.event_count.fetch_add(1, Ordering::SeqCst);

    // Signal that events are present
    obj.events_present.set();

    crate::serial_println!("[DEBUG] Queued {:?} event for pid={} tid={}",
        event_type, pid, tid);

    true
}

/// Wait for a debug event
pub unsafe fn dbgk_wait_for_debug_event(
    debug_index: usize,
    timeout_ms: Option<u64>,
) -> Option<(*mut DebugEvent, DebugEventType, u32, u32)> {
    let obj = match dbgk_get_debug_object(debug_index) {
        Some(o) => o,
        None => return None,
    };

    // Wait for an event to be available
    use super::wait::ke_wait_for_single_object;
    use super::dispatcher::DispatcherHeader;

    let wait_result = ke_wait_for_single_object(
        &obj.events_present.header as *const DispatcherHeader as *mut DispatcherHeader,
        timeout_ms,
    );

    // Check if wait was successful
    if wait_result != WaitStatus::Object0 {
        return None; // Timeout or error
    }

    // Get the first unreported event
    let _guard = obj.lock.lock();

    if obj.event_list.is_empty() {
        return None;
    }

    // Get first event
    let entry = obj.event_list.flink;
    let event = crate::containing_record!(entry, DebugEvent, list_entry);

    if (*event).reported {
        return None;
    }

    (*event).reported = true;

    let event_type = (*event).event_type;
    let pid = (*event).process_id;
    let tid = (*event).thread_id;

    Some((event, event_type, pid, tid))
}

/// Continue from a debug event (the debugger calls this to resume the debugged thread)
pub unsafe fn dbgk_continue_debug_event(
    debug_index: usize,
    pid: u32,
    tid: u32,
    continue_status: u32,
) -> bool {
    let obj = match dbgk_get_debug_object(debug_index) {
        Some(o) => o,
        None => return false,
    };

    let _guard = obj.lock.lock();

    // Find and remove the event
    let mut current = obj.event_list.flink;
    while current != &obj.event_list as *const _ as *mut _ {
        let event = crate::containing_record!(current, DebugEvent, list_entry);

        if (*event).process_id == pid && (*event).thread_id == tid && (*event).reported {
            // Remove from list
            (*event).list_entry.remove_entry();
            obj.event_count.fetch_sub(1, Ordering::SeqCst);

            // In a full implementation, we'd wake the waiting thread here
            // based on continue_status (DBG_CONTINUE or DBG_EXCEPTION_NOT_HANDLED)

            // Free the event
            free_debug_event(event);

            crate::serial_println!("[DEBUG] Continued event for pid={} tid={} status={:#x}",
                pid, tid, continue_status);

            // If there are more events, re-signal
            if obj.get_event_count() > 0 {
                obj.events_present.set();
            }

            return true;
        }

        current = (*current).flink;
    }

    false
}

/// Generate initial debug events when attaching to a process
pub unsafe fn dbgk_generate_initial_events(debug_index: usize, pid: u32) {
    // Generate CREATE_PROCESS event
    let create_info = CreateProcessDebugInfo {
        process_handle: 0, // Placeholder
        thread_handle: 0,
        base_of_image: 0x00400000, // Default image base
        start_address: 0,
    };

    dbgk_queue_debug_event(
        debug_index,
        DebugEventType::CreateProcess,
        pid,
        1, // Main thread ID (placeholder)
        DebugEventInfo { create_process: create_info },
    );

    // In a full implementation, we'd also generate:
    // - CREATE_THREAD for each existing thread
    // - LOAD_DLL for each loaded module
}

/// Initialize the debug subsystem
pub fn init() {
    crate::serial_println!("[DEBUG] Debug subsystem initialized");
}
