//! Debug Event Structures
//!
//! Defines the debug event types and message structures used for
//! communication between the kernel and user-mode debuggers.
//!
//! Event types:
//! - CREATE_PROCESS: First thread of new process starts
//! - CREATE_THREAD: New thread created
//! - EXIT_THREAD: Thread terminating
//! - EXIT_PROCESS: Process terminating
//! - LOAD_DLL: DLL loaded into address space
//! - UNLOAD_DLL: DLL unloaded
//! - EXCEPTION: Unhandled exception occurred

use crate::ke::event::KEvent;
use crate::ke::list::ListEntry;
use crate::ps::cid::ClientId;

/// Debug API message numbers
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugApiNumber {
    /// Exception occurred
    ExceptionApi = 0,
    /// New process created (sent for first thread)
    CreateProcessApi = 1,
    /// New thread created
    CreateThreadApi = 2,
    /// Thread exited
    ExitThreadApi = 3,
    /// Process exited
    ExitProcessApi = 4,
    /// DLL loaded
    LoadDllApi = 5,
    /// DLL unloaded
    UnloadDllApi = 6,
    /// Maximum API number
    MaxApiNumber = 7,
}

/// Continue status values returned by debugger
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinueStatus {
    /// Continue normal execution
    Continue = 0x00010002,
    /// Exception was handled
    ExceptionHandled = 0x00010001,
    /// Exception was not handled
    ExceptionNotHandled = 0x80010001u32 as i32,
    /// Terminate the thread
    TerminateThread = 0x40010003,
    /// Terminate the process
    TerminateProcess = 0x40010004,
}

impl ContinueStatus {
    /// Convert from NTSTATUS
    pub fn from_status(status: i32) -> Self {
        match status {
            0x00010002 => ContinueStatus::Continue,
            0x00010001 => ContinueStatus::ExceptionHandled,
            0x40010003 => ContinueStatus::TerminateThread,
            0x40010004 => ContinueStatus::TerminateProcess,
            _ => ContinueStatus::ExceptionNotHandled,
        }
    }
}

/// Debug event flags
#[allow(non_snake_case)]
pub mod DebugEventFlags {
    /// Event has been read by debugger
    pub const READ: u32 = 0x01;
    /// Event was created with no wait
    pub const NOWAIT: u32 = 0x02;
    /// Event is inactive
    pub const INACTIVE: u32 = 0x04;
    /// Event should be released
    pub const RELEASE: u32 = 0x08;
    /// Protection failed during event creation
    pub const PROTECT_FAILED: u32 = 0x10;
    /// Process/thread was suspended for this event
    pub const SUSPEND: u32 = 0x20;
}

/// Exception record (simplified)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExceptionRecord {
    /// Exception code
    pub exception_code: u32,
    /// Exception flags
    pub exception_flags: u32,
    /// Pointer to next exception record
    pub exception_record: usize,
    /// Address where exception occurred
    pub exception_address: usize,
    /// Number of parameters
    pub number_parameters: u32,
    /// Exception parameters
    pub exception_information: [usize; 4],
}

impl ExceptionRecord {
    pub const fn new() -> Self {
        Self {
            exception_code: 0,
            exception_flags: 0,
            exception_record: 0,
            exception_address: 0,
            number_parameters: 0,
            exception_information: [0; 4],
        }
    }
}

impl Default for ExceptionRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// Create process message
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DbgkmCreateProcess {
    /// Subsection start
    pub subsection_base: usize,
    /// File handle to executable (if available)
    pub file_handle: usize,
    /// Base address of image
    pub base_of_image: usize,
    /// Debug info offset in PE
    pub debug_info_file_offset: u32,
    /// Debug info size
    pub debug_info_size: u32,
    /// Thread info
    pub initial_thread: DbgkmCreateThread,
}

impl DbgkmCreateProcess {
    pub const fn new() -> Self {
        Self {
            subsection_base: 0,
            file_handle: 0,
            base_of_image: 0,
            debug_info_file_offset: 0,
            debug_info_size: 0,
            initial_thread: DbgkmCreateThread::new(),
        }
    }
}

impl Default for DbgkmCreateProcess {
    fn default() -> Self {
        Self::new()
    }
}

/// Create thread message
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DbgkmCreateThread {
    /// Subsection start
    pub subsection_base: usize,
    /// Thread start address
    pub start_address: usize,
}

impl DbgkmCreateThread {
    pub const fn new() -> Self {
        Self {
            subsection_base: 0,
            start_address: 0,
        }
    }
}

impl Default for DbgkmCreateThread {
    fn default() -> Self {
        Self::new()
    }
}

/// Exit thread message
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DbgkmExitThread {
    /// Thread exit status
    pub exit_status: i32,
}

impl DbgkmExitThread {
    pub const fn new() -> Self {
        Self { exit_status: 0 }
    }
}

impl Default for DbgkmExitThread {
    fn default() -> Self {
        Self::new()
    }
}

/// Exit process message
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DbgkmExitProcess {
    /// Process exit status
    pub exit_status: i32,
}

impl DbgkmExitProcess {
    pub const fn new() -> Self {
        Self { exit_status: 0 }
    }
}

impl Default for DbgkmExitProcess {
    fn default() -> Self {
        Self::new()
    }
}

/// Load DLL message
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DbgkmLoadDll {
    /// File handle to DLL
    pub file_handle: usize,
    /// Base address of DLL
    pub base_of_dll: usize,
    /// Debug info offset
    pub debug_info_file_offset: u32,
    /// Debug info size
    pub debug_info_size: u32,
    /// Pointer to name in target address space
    pub name_pointer: usize,
}

impl DbgkmLoadDll {
    pub const fn new() -> Self {
        Self {
            file_handle: 0,
            base_of_dll: 0,
            debug_info_file_offset: 0,
            debug_info_size: 0,
            name_pointer: 0,
        }
    }
}

impl Default for DbgkmLoadDll {
    fn default() -> Self {
        Self::new()
    }
}

/// Unload DLL message
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DbgkmUnloadDll {
    /// Base address of DLL being unloaded
    pub base_of_dll: usize,
}

impl DbgkmUnloadDll {
    pub const fn new() -> Self {
        Self { base_of_dll: 0 }
    }
}

impl Default for DbgkmUnloadDll {
    fn default() -> Self {
        Self::new()
    }
}

/// Exception message
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DbgkmException {
    /// Exception record
    pub exception_record: ExceptionRecord,
    /// Is this the first chance at handling?
    pub first_chance: bool,
}

impl DbgkmException {
    pub const fn new() -> Self {
        Self {
            exception_record: ExceptionRecord::new(),
            first_chance: true,
        }
    }
}

impl Default for DbgkmException {
    fn default() -> Self {
        Self::new()
    }
}

/// Debug API message union
#[repr(C)]
pub union DbgkmApiMsgPayload {
    pub create_process: DbgkmCreateProcess,
    pub create_thread: DbgkmCreateThread,
    pub exit_thread: DbgkmExitThread,
    pub exit_process: DbgkmExitProcess,
    pub load_dll: DbgkmLoadDll,
    pub unload_dll: DbgkmUnloadDll,
    pub exception: DbgkmException,
}

impl DbgkmApiMsgPayload {
    pub const fn zeroed() -> Self {
        Self {
            create_process: DbgkmCreateProcess::new(),
        }
    }
}

/// Debug API message
#[repr(C)]
pub struct DbgkmApiMsg {
    /// API number (message type)
    pub api_number: DebugApiNumber,
    /// Status returned by debugger
    pub returned_status: i32,
    /// Message payload
    pub payload: DbgkmApiMsgPayload,
}

impl DbgkmApiMsg {
    pub const fn new() -> Self {
        Self {
            api_number: DebugApiNumber::ExceptionApi,
            returned_status: 0,
            payload: DbgkmApiMsgPayload::zeroed(),
        }
    }
}

impl Default for DbgkmApiMsg {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal debug event structure
///
/// This represents an event waiting for the debugger in the debug object's queue.
#[repr(C)]
pub struct DebugEvent {
    /// Link in debug object's event list
    pub event_list: ListEntry,
    /// Event signaled when debugger issues continue
    pub continue_event: KEvent,
    /// Client ID of the thread that generated this event
    pub client_id: ClientId,
    /// Reference to the process
    pub process: usize, // *mut EProcess
    /// Reference to the thread
    pub thread: usize, // *mut EThread
    /// Status code to return to the waiting thread
    pub status: i32,
    /// Event flags
    pub flags: u32,
    /// Backout thread for attach
    pub backout_thread: usize,
    /// The actual API message
    pub api_msg: DbgkmApiMsg,
}

impl DebugEvent {
    pub const fn new() -> Self {
        Self {
            event_list: ListEntry::new(),
            continue_event: KEvent::new(),
            client_id: ClientId::null(),
            process: 0,
            thread: 0,
            status: 0,
            flags: 0,
            backout_thread: 0,
            api_msg: DbgkmApiMsg::new(),
        }
    }

    /// Check if event has been read
    pub fn is_read(&self) -> bool {
        self.flags & DebugEventFlags::READ != 0
    }

    /// Mark event as read
    pub fn set_read(&mut self) {
        self.flags |= DebugEventFlags::READ;
    }

    /// Check if event is inactive
    pub fn is_inactive(&self) -> bool {
        self.flags & DebugEventFlags::INACTIVE != 0
    }

    /// Mark event as inactive
    pub fn set_inactive(&mut self) {
        self.flags |= DebugEventFlags::INACTIVE;
    }
}

impl Default for DebugEvent {
    fn default() -> Self {
        Self::new()
    }
}

/// User-mode debug state change (returned by NtWaitForDebugEvent)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DbgUiWaitStateChange {
    /// New state
    pub new_state: u32,
    /// App client ID (process/thread that generated event)
    pub app_client_id: ClientId,
    /// State-specific info
    pub state_info: DbgUiStateInfo,
}

/// State-specific information union
#[repr(C)]
#[derive(Clone, Copy)]
pub union DbgUiStateInfo {
    pub exception: DbgUiExceptionStateInfo,
    pub create_thread: DbgUiCreateThreadStateInfo,
    pub create_process: DbgUiCreateProcessStateInfo,
    pub exit_thread: DbgkmExitThread,
    pub exit_process: DbgkmExitProcess,
    pub load_dll: DbgkmLoadDll,
    pub unload_dll: DbgkmUnloadDll,
}

/// Exception state info
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DbgUiExceptionStateInfo {
    pub exception_record: ExceptionRecord,
    pub first_chance: bool,
}

/// Create thread state info
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DbgUiCreateThreadStateInfo {
    pub handle_to_thread: usize,
    pub new_thread: DbgkmCreateThread,
}

/// Create process state info
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DbgUiCreateProcessStateInfo {
    pub handle_to_process: usize,
    pub handle_to_thread: usize,
    pub new_process: DbgkmCreateProcess,
}
