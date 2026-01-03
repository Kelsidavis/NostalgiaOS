//! Client/Server Runtime (CSR) Subsystem
//!
//! CSRSS (Client/Server Runtime Subsystem) is the user-mode side of the Win32
//! environment subsystem. It manages Windows sessions, console windows, and
//! process/thread creation for Win32 applications.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Session Manager (SMSS)                    │
//! │                                                             │
//! │  Creates CSRSS for each session                            │
//! └────────────────────────┬────────────────────────────────────┘
//!                          │
//!          ┌───────────────┴───────────────┐
//!          ▼                               ▼
//! ┌─────────────────┐             ┌─────────────────┐
//! │  Session 0      │             │  Session 1      │
//! │  (Services)     │             │  (User Desktop) │
//! │                 │             │                 │
//! │  ┌───────────┐  │             │  ┌───────────┐  │
//! │  │  CSRSS    │  │             │  │  CSRSS    │  │
//! │  └───────────┘  │             │  └───────────┘  │
//! │        │        │             │        │        │
//! │  ┌─────┴─────┐  │             │  ┌─────┴─────┐  │
//! │  │ Consoles  │  │             │  │ Win32     │  │
//! │  │ Services  │  │             │  │ Processes │  │
//! │  └───────────┘  │             │  └───────────┘  │
//! └─────────────────┘             └─────────────────┘
//! ```
//!
//! # Components
//!
//! - **Session management**: Creates and manages login sessions
//! - **Process management**: Win32 process/thread creation
//! - **Console management**: Console window allocation
//! - **Shutdown coordination**: Clean shutdown of applications
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `base/subsys/csr/` - CSR subsystem
//! - `base/subsys/csr/server/` - CSR server implementation

extern crate alloc;

pub mod session;
pub mod process;
pub mod console;
pub mod server;

use crate::ke::spinlock::SpinLock;
use crate::ob::handle::Handle;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::BTreeMap;

// ============================================================================
// CSR Constants
// ============================================================================

/// Maximum number of sessions
pub const MAX_SESSIONS: usize = 64;

/// Maximum console windows per session
pub const MAX_CONSOLES_PER_SESSION: usize = 256;

/// CSR API numbers
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrApiNumber {
    /// Create process
    BasepCreateProcess = 0,
    /// Create thread
    BasepCreateThread = 1,
    /// Exit process
    BasepExitProcess = 2,
    /// Debug process
    BasepDebugProcess = 3,
    /// Check VDM
    BasepCheckVDM = 4,
    /// Update VDM entry
    BasepUpdateVDMEntry = 5,
    /// Get next VDM command
    BasepGetNextVDMCommand = 6,
    /// Exit VDM
    BasepExitVDM = 7,
    /// Set reboot
    BasepSetRebootCommand = 8,
    /// Refresh INI file
    BasepRefreshIniFileMapping = 9,
    /// Define DOS device
    BasepDefineDosDevice = 10,
    /// Sound sentry
    BasepSoundSentry = 11,
    /// Get temp file
    BasepGetTempFile = 12,
    /// Create activation context
    SxsCreateActivationContext = 13,
    /// Query activation context
    SxsQueryActivationContext = 14,
}

/// CSR message types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrMessageType {
    /// API request
    ApiRequest = 0,
    /// Reply
    Reply = 1,
    /// Exception
    Exception = 2,
    /// Debug event
    DebugEvent = 3,
}

/// Session state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is being created
    Creating = 0,
    /// Session is active
    Active = 1,
    /// Session is disconnected (Terminal Services)
    Disconnected = 2,
    /// Session is being destroyed
    Destroying = 3,
    /// Session is destroyed
    Destroyed = 4,
}

/// Shutdown level
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownLevel {
    /// Reserved (system)
    Reserved = 0x00,
    /// First to shutdown
    First = 0x100,
    /// Normal applications
    Normal = 0x200,
    /// Explorer shell
    Explorer = 0x300,
    /// Last to shutdown (services)
    Last = 0x3FF,
}

// ============================================================================
// CSR Structures
// ============================================================================

/// CSR API message header
#[derive(Debug, Clone)]
#[repr(C)]
pub struct CsrApiMessage {
    /// Port message header (LPC)
    pub header: CsrPortMessage,
    /// API number
    pub api_number: CsrApiNumber,
    /// Return status
    pub status: i32,
    /// API-specific data
    pub data: [u8; 256],
}

/// CSR port message (LPC compatible)
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct CsrPortMessage {
    /// Total length
    pub length: u16,
    /// Data length
    pub data_length: u16,
    /// Message type
    pub msg_type: u16,
    /// Data info offset
    pub data_info_offset: u16,
    /// Process ID
    pub process_id: u32,
    /// Thread ID
    pub thread_id: u32,
    /// Message ID
    pub message_id: u32,
    /// Client view size
    pub client_view_size: u32,
}

/// CSR server DLL entry
#[derive(Debug, Clone)]
pub struct CsrServerDll {
    /// DLL name
    pub name: String,
    /// API dispatch table base
    pub api_base: u32,
    /// Number of APIs
    pub api_count: u32,
    /// Module handle
    pub module_handle: Handle,
    /// Connect routine
    pub connect_routine: usize,
    /// Disconnect routine
    pub disconnect_routine: usize,
    /// Shutdown routine
    pub shutdown_routine: usize,
}

/// CSR process entry
#[derive(Debug, Clone)]
pub struct CsrProcess {
    /// Client process handle
    pub process_handle: Handle,
    /// Process ID
    pub process_id: u32,
    /// Session ID
    pub session_id: u32,
    /// Shutdown level
    pub shutdown_level: ShutdownLevel,
    /// Shutdown flags
    pub shutdown_flags: u32,
    /// Thread count
    pub thread_count: u32,
    /// Reference count
    pub ref_count: u32,
    /// Flags
    pub flags: CsrProcessFlags,
}

bitflags::bitflags! {
    /// CSR process flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CsrProcessFlags: u32 {
        /// Process is being debugged
        const DEBUGGED = 1 << 0;
        /// Process has created a GUI
        const HAS_GUI = 1 << 1;
        /// Process is a service
        const SERVICE_PROCESS = 1 << 2;
        /// Process is a console app
        const CONSOLE_APP = 1 << 3;
        /// Process is terminating
        const TERMINATING = 1 << 4;
        /// Process has shutdown exemption
        const SHUTDOWN_EXEMPT = 1 << 5;
    }
}

/// CSR thread entry
#[derive(Debug, Clone)]
pub struct CsrThread {
    /// Thread handle
    pub thread_handle: Handle,
    /// Thread ID
    pub thread_id: u32,
    /// Process this thread belongs to
    pub process_id: u32,
    /// CSR wait block
    pub wait_block: Option<CsrWaitBlock>,
    /// Impersonation token
    pub impersonation_token: Option<Handle>,
    /// Flags
    pub flags: u32,
}

/// CSR wait block (for server waits)
#[derive(Debug, Clone)]
pub struct CsrWaitBlock {
    /// Wait reason
    pub reason: u32,
    /// Wait timeout
    pub timeout: i64,
    /// Wait satisfied
    pub satisfied: bool,
}

// ============================================================================
// CSR Global State
// ============================================================================

struct CsrState {
    /// Registered server DLLs
    server_dlls: Vec<CsrServerDll>,
    /// Process table
    processes: BTreeMap<u32, CsrProcess>,
    /// Thread table
    threads: BTreeMap<u32, CsrThread>,
    /// Session table
    sessions: BTreeMap<u32, session::CsrSession>,
    /// Next process ID
    next_pid: u32,
    /// Console session
    console_session: u32,
}

impl CsrState {
    const fn new() -> Self {
        Self {
            server_dlls: Vec::new(),
            processes: BTreeMap::new(),
            threads: BTreeMap::new(),
            sessions: BTreeMap::new(),
            next_pid: 1000,
            console_session: 0,
        }
    }
}

static CSR_STATE: SpinLock<CsrState> = SpinLock::new(CsrState::new());

// ============================================================================
// CSR Functions
// ============================================================================

/// Initialize the CSR subsystem
pub fn init() {
    session::init();
    process::init();
    console::init();
    server::init();

    // Create session 0 (services)
    session::create_session(0);

    crate::serial_println!("[CSR] Client/Server Runtime subsystem initialized");
}

/// Register a CSR server DLL
pub fn register_server_dll(dll: CsrServerDll) -> bool {
    let mut state = CSR_STATE.lock();
    state.server_dlls.push(dll);
    true
}

/// Get server DLL by name
pub fn get_server_dll(name: &str) -> Option<CsrServerDll> {
    let state = CSR_STATE.lock();
    state.server_dlls.iter()
        .find(|dll| dll.name == name)
        .cloned()
}

/// Create a new CSR process
pub fn create_process(process_handle: Handle, session_id: u32) -> Option<u32> {
    let mut state = CSR_STATE.lock();

    let pid = state.next_pid;
    state.next_pid += 1;

    let process = CsrProcess {
        process_handle,
        process_id: pid,
        session_id,
        shutdown_level: ShutdownLevel::Normal,
        shutdown_flags: 0,
        thread_count: 0,
        ref_count: 1,
        flags: CsrProcessFlags::empty(),
    };

    state.processes.insert(pid, process);
    Some(pid)
}

/// Get CSR process by ID
pub fn get_process(pid: u32) -> Option<CsrProcess> {
    let state = CSR_STATE.lock();
    state.processes.get(&pid).cloned()
}

/// Remove a CSR process
pub fn remove_process(pid: u32) -> bool {
    let mut state = CSR_STATE.lock();
    state.processes.remove(&pid).is_some()
}

/// Create a new CSR thread
pub fn create_thread(thread_handle: Handle, process_id: u32) -> Option<u32> {
    let mut state = CSR_STATE.lock();

    // Increment process thread count
    if let Some(process) = state.processes.get_mut(&process_id) {
        process.thread_count += 1;
    } else {
        return None;
    }

    let tid = state.next_pid; // Use same counter for simplicity
    state.next_pid += 1;

    let thread = CsrThread {
        thread_handle,
        thread_id: tid,
        process_id,
        wait_block: None,
        impersonation_token: None,
        flags: 0,
    };

    state.threads.insert(tid, thread);
    Some(tid)
}

/// Handle CSR API request
pub fn handle_api_request(msg: &mut CsrApiMessage) -> i32 {
    match msg.api_number {
        CsrApiNumber::BasepCreateProcess => {
            process::handle_create_process(msg)
        }
        CsrApiNumber::BasepCreateThread => {
            process::handle_create_thread(msg)
        }
        CsrApiNumber::BasepExitProcess => {
            process::handle_exit_process(msg)
        }
        CsrApiNumber::BasepCheckVDM => {
            // VDM check - return success
            0
        }
        CsrApiNumber::BasepDefineDosDevice => {
            process::handle_define_dos_device(msg)
        }
        CsrApiNumber::BasepGetTempFile => {
            process::handle_get_temp_file(msg)
        }
        _ => {
            crate::serial_println!("[CSR] Unknown API: {:?}", msg.api_number);
            -1
        }
    }
}

/// Initiate system shutdown
pub fn initiate_shutdown(session_id: u32, flags: u32) -> i32 {
    crate::serial_println!("[CSR] Initiating shutdown for session {}, flags {:08x}",
        session_id, flags);

    let state = CSR_STATE.lock();

    // Get processes in this session, sorted by shutdown level
    let mut session_processes: Vec<_> = state.processes.values()
        .filter(|p| p.session_id == session_id)
        .cloned()
        .collect();

    session_processes.sort_by_key(|p| p.shutdown_level as u32);
    drop(state);

    // Notify processes of shutdown (highest level first)
    for process in session_processes.iter().rev() {
        if !process.flags.contains(CsrProcessFlags::SHUTDOWN_EXEMPT) {
            crate::serial_println!("[CSR] Shutting down process {}", process.process_id);
            // Would send WM_QUERYENDSESSION / WM_ENDSESSION here
        }
    }

    0
}

// Re-exports
pub use session::{
    CsrSession,
    create_session,
    destroy_session,
    get_session,
    set_active_session,
};

pub use console::{
    CsrConsole,
    create_console,
    destroy_console,
    write_console,
    read_console,
};

pub use process::{
    set_process_shutdown_level,
    set_process_flags,
};
