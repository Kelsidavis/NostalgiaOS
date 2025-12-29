//! Debug Notification Functions
//!
//! These functions are called by the kernel at various lifecycle points
//! to generate debug events. They hook into:
//! - Thread creation/exit
//! - Process exit
//! - DLL load/unload
//! - Exception handling
//!
//! Each function checks if the process has a debug object attached
//! and generates the appropriate debug event if so.

use crate::ps::cid::ClientId;
use super::debug_object::DebugObject;
use super::event::{
    DebugApiNumber, DebugEventFlags, DbgkmApiMsg, DbgkmApiMsgPayload,
    DbgkmCreateProcess, DbgkmCreateThread, DbgkmExitThread, DbgkmExitProcess,
    DbgkmLoadDll, DbgkmUnloadDll, DbgkmException, ExceptionRecord,
};

// ============================================================================
// Thread/Process Lifecycle Hooks
// ============================================================================

/// Called when a new thread is created
///
/// Generates CREATE_THREAD or CREATE_PROCESS event.
///
/// # Arguments
/// * `thread` - Pointer to the new ETHREAD
/// * `start_address` - Thread start routine address
/// * `is_first_thread` - Whether this is the first thread of the process
pub fn dbgk_create_thread(
    thread: usize,
    start_address: usize,
    is_first_thread: bool,
) {
    // Get the process debug object
    let debug_object = match get_thread_debug_object(thread) {
        Some(obj) => obj,
        None => return, // No debugger attached
    };

    // Build the message
    let client_id = get_thread_client_id(thread);
    let process = get_thread_process(thread);

    let api_msg = if is_first_thread {
        // First thread - send CREATE_PROCESS
        let mut msg = DbgkmApiMsg::new();
        msg.api_number = DebugApiNumber::CreateProcessApi;
        msg.payload = DbgkmApiMsgPayload {
            create_process: DbgkmCreateProcess {
                subsection_base: 0,
                file_handle: 0, // TODO: Open handle to executable
                base_of_image: get_process_image_base(process),
                debug_info_file_offset: 0,
                debug_info_size: 0,
                initial_thread: DbgkmCreateThread {
                    subsection_base: 0,
                    start_address,
                },
            },
        };
        msg
    } else {
        // Subsequent thread - send CREATE_THREAD
        let mut msg = DbgkmApiMsg::new();
        msg.api_number = DebugApiNumber::CreateThreadApi;
        msg.payload = DbgkmApiMsgPayload {
            create_thread: DbgkmCreateThread {
                subsection_base: 0,
                start_address,
            },
        };
        msg
    };

    // Queue the event and wait for debugger
    queue_and_wait(debug_object, process, thread, client_id, api_msg);
}

/// Called when a thread is exiting
///
/// Generates EXIT_THREAD event.
///
/// # Arguments
/// * `thread` - Pointer to the exiting ETHREAD
/// * `exit_status` - Thread exit status code
pub fn dbgk_exit_thread(thread: usize, exit_status: i32) {
    let debug_object = match get_thread_debug_object(thread) {
        Some(obj) => obj,
        None => return,
    };

    let client_id = get_thread_client_id(thread);
    let process = get_thread_process(thread);

    let mut msg = DbgkmApiMsg::new();
    msg.api_number = DebugApiNumber::ExitThreadApi;
    msg.payload = DbgkmApiMsgPayload {
        exit_thread: DbgkmExitThread { exit_status },
    };

    // Queue but don't wait (thread is terminating)
    queue_no_wait(debug_object, process, thread, client_id, msg);
}

/// Called when a process is exiting
///
/// Generates EXIT_PROCESS event (sent after all thread exit events).
///
/// # Arguments
/// * `process` - Pointer to the exiting EPROCESS
/// * `exit_status` - Process exit status code
pub fn dbgk_exit_process(process: usize, exit_status: i32) {
    let debug_object = match get_process_debug_object(process) {
        Some(obj) => obj,
        None => return,
    };

    // Get the last thread's client ID
    let client_id = get_process_first_thread_client_id(process);

    let mut msg = DbgkmApiMsg::new();
    msg.api_number = DebugApiNumber::ExitProcessApi;
    msg.payload = DbgkmApiMsgPayload {
        exit_process: DbgkmExitProcess { exit_status },
    };

    queue_no_wait(debug_object, process, 0, client_id, msg);
}

/// Called when a DLL is mapped into the process
///
/// Generates LOAD_DLL event.
///
/// # Arguments
/// * `process` - Pointer to the EPROCESS
/// * `base_address` - Base address where DLL is mapped
/// * `file_handle` - Handle to the DLL file (if available)
pub fn dbgk_map_view_of_section(
    process: usize,
    base_address: usize,
    file_handle: usize,
) {
    let debug_object = match get_process_debug_object(process) {
        Some(obj) => obj,
        None => return,
    };

    // Get current thread info
    let thread = get_current_thread();
    let client_id = get_thread_client_id(thread);

    let mut msg = DbgkmApiMsg::new();
    msg.api_number = DebugApiNumber::LoadDllApi;
    msg.payload = DbgkmApiMsgPayload {
        load_dll: DbgkmLoadDll {
            file_handle,
            base_of_dll: base_address,
            debug_info_file_offset: 0,
            debug_info_size: 0,
            name_pointer: 0, // TODO: Get DLL name pointer from PEB loader data
        },
    };

    queue_and_wait(debug_object, process, thread, client_id, msg);
}

/// Called when a DLL is unmapped from the process
///
/// Generates UNLOAD_DLL event.
///
/// # Arguments
/// * `process` - Pointer to the EPROCESS
/// * `base_address` - Base address of DLL being unmapped
pub fn dbgk_unmap_view_of_section(process: usize, base_address: usize) {
    let debug_object = match get_process_debug_object(process) {
        Some(obj) => obj,
        None => return,
    };

    let thread = get_current_thread();
    let client_id = get_thread_client_id(thread);

    let mut msg = DbgkmApiMsg::new();
    msg.api_number = DebugApiNumber::UnloadDllApi;
    msg.payload = DbgkmApiMsgPayload {
        unload_dll: DbgkmUnloadDll {
            base_of_dll: base_address,
        },
    };

    // Unload doesn't wait for debugger
    queue_no_wait(debug_object, process, thread, client_id, msg);
}

/// Forward an exception to the debugger
///
/// Called when an exception occurs and the debugger should be notified.
///
/// # Arguments
/// * `exception_record` - Exception information
/// * `first_chance` - Whether this is the first chance to handle
///
/// # Returns
/// true if debugger handled the exception, false otherwise
pub fn dbgk_forward_exception(
    exception_record: &ExceptionRecord,
    first_chance: bool,
) -> bool {
    let thread = get_current_thread();
    let process = get_thread_process(thread);

    let debug_object = match get_process_debug_object(process) {
        Some(obj) => obj,
        None => return false,
    };

    let client_id = get_thread_client_id(thread);

    let mut msg = DbgkmApiMsg::new();
    msg.api_number = DebugApiNumber::ExceptionApi;
    msg.payload = DbgkmApiMsgPayload {
        exception: DbgkmException {
            exception_record: *exception_record,
            first_chance,
        },
    };

    // Queue the event and wait for debugger response
    let status = queue_and_wait(debug_object, process, thread, client_id, msg);

    // Check if debugger handled the exception
    status == 0x00010001 // DBG_EXCEPTION_HANDLED
}

/// Copy debug port from parent to child process
///
/// Called during process creation to inherit debugging.
///
/// # Arguments
/// * `target_process` - Child process
/// * `source_process` - Parent process
pub fn dbgk_copy_process_debug_port(_target_process: usize, source_process: usize) {
    // Get parent's debug object
    let _debug_object = match get_process_debug_object(source_process) {
        Some(obj) => obj,
        None => return,
    };

    // TODO: Check PS_PROCESS_FLAGS_NO_DEBUG_INHERIT flag

    // Set child's debug port
    super::acquire_debug_port_lock();

    // TODO: Set target_process->DebugPort = source_process->DebugPort
    // Also need to increment reference count on debug object

    super::release_debug_port_lock();
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

/// Queue an event and wait for the debugger to continue
fn queue_and_wait(
    debug_object: &mut DebugObject,
    process: usize,
    thread: usize,
    client_id: ClientId,
    api_msg: DbgkmApiMsg,
) -> i32 {
    debug_object.mutex.acquire();

    // Check if debug object is being deleted
    if debug_object.is_delete_pending() {
        debug_object.mutex.release();
        return -1073741510i32; // STATUS_DEBUGGER_INACTIVE
    }

    // Queue the event
    let index = match debug_object.queue_event(
        process,
        thread,
        client_id,
        api_msg,
        DebugEventFlags::SUSPEND,
    ) {
        Some(idx) => idx,
        None => {
            debug_object.mutex.release();
            return -1073741670i32; // STATUS_NO_MEMORY
        }
    };

    debug_object.mutex.release();

    // Wait for debugger to continue us
    debug_object.wait_for_continue(index)
}

/// Queue an event without waiting
fn queue_no_wait(
    debug_object: &mut DebugObject,
    process: usize,
    thread: usize,
    client_id: ClientId,
    api_msg: DbgkmApiMsg,
) {
    debug_object.mutex.acquire();

    if !debug_object.is_delete_pending() {
        let _ = debug_object.queue_event(
            process,
            thread,
            client_id,
            api_msg,
            DebugEventFlags::NOWAIT,
        );
    }

    debug_object.mutex.release();
}

// ============================================================================
// Stub Functions - Need Integration with PS/KE
// ============================================================================

/// Get the debug object for a thread's process
fn get_thread_debug_object(_thread: usize) -> Option<&'static mut DebugObject> {
    // TODO: Get thread->Process->DebugPort
    None
}

/// Get the debug object for a process
fn get_process_debug_object(_process: usize) -> Option<&'static mut DebugObject> {
    // TODO: Get process->DebugPort
    None
}

/// Get client ID for a thread
fn get_thread_client_id(_thread: usize) -> ClientId {
    // TODO: Get thread->Cid
    ClientId::null()
}

/// Get the process pointer for a thread
fn get_thread_process(_thread: usize) -> usize {
    // TODO: Get thread->Process
    0
}

/// Get the current thread
fn get_current_thread() -> usize {
    // TODO: KeGetCurrentThread()
    0
}

/// Get the image base for a process
fn get_process_image_base(_process: usize) -> usize {
    // TODO: Get process->SectionBaseAddress
    0
}

/// Get the first thread's client ID for a process
fn get_process_first_thread_client_id(_process: usize) -> ClientId {
    // TODO: Enumerate process threads
    ClientId::null()
}
