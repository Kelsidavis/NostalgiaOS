//! CSR Process Management
//!
//! Handles Win32 process and thread creation notifications,
//! process flags, and shutdown coordination.

extern crate alloc;

use super::{CSR_STATE, CsrApiMessage, CsrProcess, CsrProcessFlags, ShutdownLevel};
use crate::ob::handle::Handle;
use alloc::vec::Vec;

// ============================================================================
// Process Creation Data
// ============================================================================

/// Process creation data from CSR API
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct CreateProcessData {
    /// Process handle
    pub process_handle: u64,
    /// Thread handle
    pub thread_handle: u64,
    /// Process ID
    pub process_id: u32,
    /// Thread ID
    pub thread_id: u32,
    /// Creation flags
    pub creation_flags: u32,
    /// Image file name offset
    pub image_name_offset: u32,
    /// Image file name length
    pub image_name_length: u32,
}

/// Thread creation data
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct CreateThreadData {
    /// Thread handle
    pub thread_handle: u64,
    /// Process ID
    pub process_id: u32,
    /// Thread ID
    pub thread_id: u32,
    /// Creation flags
    pub flags: u32,
}

/// DOS device definition data
#[derive(Debug, Clone)]
#[repr(C)]
pub struct DefineDosDeviceData {
    /// Device name offset
    pub device_name_offset: u32,
    /// Device name length
    pub device_name_length: u32,
    /// Target path offset
    pub target_path_offset: u32,
    /// Target path length
    pub target_path_length: u32,
    /// Flags
    pub flags: u32,
}

/// Temp file data
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct GetTempFileData {
    /// Unique ID
    pub unique_id: u32,
}

// ============================================================================
// Process Functions
// ============================================================================

/// Initialize process management
pub fn init() {
    crate::serial_println!("[CSR] Process management initialized");
}

/// Handle process creation notification
pub fn handle_create_process(msg: &mut CsrApiMessage) -> i32 {
    // Extract process data from message
    let data = unsafe {
        core::ptr::read(msg.data.as_ptr() as *const CreateProcessData)
    };

    crate::serial_println!("[CSR] Create process: PID={}, TID={}",
        data.process_id, data.thread_id);

    // Register the process with CSR
    let mut state = CSR_STATE.lock();

    // Determine session from calling process
    let session_id = 0; // Default to session 0

    let process = CsrProcess {
        process_handle: data.process_handle as Handle,
        process_id: data.process_id,
        session_id,
        shutdown_level: ShutdownLevel::Normal,
        shutdown_flags: 0,
        thread_count: 1,
        ref_count: 1,
        flags: if (data.creation_flags & 0x10) != 0 {
            CsrProcessFlags::CONSOLE_APP
        } else {
            CsrProcessFlags::HAS_GUI
        },
    };

    state.processes.insert(data.process_id, process);

    0
}

/// Handle thread creation notification
pub fn handle_create_thread(msg: &mut CsrApiMessage) -> i32 {
    let data = unsafe {
        core::ptr::read(msg.data.as_ptr() as *const CreateThreadData)
    };

    crate::serial_println!("[CSR] Create thread: PID={}, TID={}",
        data.process_id, data.thread_id);

    let mut state = CSR_STATE.lock();

    // Increment thread count for process
    if let Some(process) = state.processes.get_mut(&data.process_id) {
        process.thread_count += 1;
    }

    0
}

/// Handle process exit notification
pub fn handle_exit_process(msg: &mut CsrApiMessage) -> i32 {
    // Get process ID from message
    let process_id = unsafe {
        core::ptr::read(msg.data.as_ptr() as *const u32)
    };

    crate::serial_println!("[CSR] Exit process: PID={}", process_id);

    let mut state = CSR_STATE.lock();
    state.processes.remove(&process_id);

    0
}

/// Handle DOS device definition
pub fn handle_define_dos_device(_msg: &mut CsrApiMessage) -> i32 {
    // DOS device management
    crate::serial_println!("[CSR] Define DOS device");
    0
}

/// Handle temp file request
pub fn handle_get_temp_file(msg: &mut CsrApiMessage) -> i32 {
    static TEMP_FILE_COUNTER: crate::ke::spinlock::SpinLock<u32> =
        crate::ke::spinlock::SpinLock::new(0);

    let mut counter = TEMP_FILE_COUNTER.lock();
    *counter += 1;
    let unique_id = *counter;

    // Write unique ID back to message
    unsafe {
        let data = msg.data.as_mut_ptr() as *mut GetTempFileData;
        (*data).unique_id = unique_id;
    }

    0
}

/// Set process shutdown level
pub fn set_process_shutdown_level(pid: u32, level: ShutdownLevel) -> bool {
    let mut state = CSR_STATE.lock();
    if let Some(process) = state.processes.get_mut(&pid) {
        process.shutdown_level = level;
        true
    } else {
        false
    }
}

/// Set process flags
pub fn set_process_flags(pid: u32, flags: CsrProcessFlags, set: bool) -> bool {
    let mut state = CSR_STATE.lock();
    if let Some(process) = state.processes.get_mut(&pid) {
        if set {
            process.flags.insert(flags);
        } else {
            process.flags.remove(flags);
        }
        true
    } else {
        false
    }
}

/// Get processes in session
pub fn get_session_processes(session_id: u32) -> Vec<u32> {
    let state = CSR_STATE.lock();
    state.processes.iter()
        .filter(|(_, p)| p.session_id == session_id)
        .map(|(pid, _)| *pid)
        .collect()
}

/// Get process count
pub fn get_process_count() -> usize {
    let state = CSR_STATE.lock();
    state.processes.len()
}

/// Check if process is GUI app
pub fn is_gui_process(pid: u32) -> bool {
    let state = CSR_STATE.lock();
    state.processes.get(&pid)
        .map(|p| p.flags.contains(CsrProcessFlags::HAS_GUI))
        .unwrap_or(false)
}

/// Check if process is console app
pub fn is_console_process(pid: u32) -> bool {
    let state = CSR_STATE.lock();
    state.processes.get(&pid)
        .map(|p| p.flags.contains(CsrProcessFlags::CONSOLE_APP))
        .unwrap_or(false)
}

/// Mark process as terminating
pub fn mark_process_terminating(pid: u32) -> bool {
    set_process_flags(pid, CsrProcessFlags::TERMINATING, true)
}

/// Exempt process from shutdown
pub fn exempt_from_shutdown(pid: u32, exempt: bool) -> bool {
    set_process_flags(pid, CsrProcessFlags::SHUTDOWN_EXEMPT, exempt)
}
