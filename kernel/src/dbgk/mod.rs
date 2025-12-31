//! DBGK - Kernel Debugger Support
//!
//! Provides the kernel-side debugger infrastructure for NT-compatible debugging.
//!
//! Key features:
//! - Debug objects for debugger sessions
//! - Debug event notification (CREATE_THREAD, EXIT_PROCESS, EXCEPTION, etc.)
//! - Process attach/detach support
//! - Exception forwarding to debuggers
//! - Synthetic event generation for attach to running processes
//!
//! This implementation is NT 5.2 (Windows Server 2003) compatible.

pub mod debug_object;
pub mod event;
pub mod notify;

// Re-export main types and functions
pub use debug_object::{
    // Types
    DebugObject, DbgkStats,
    // Constants
    DEBUG_OBJECT_DELETE_PENDING, DEBUG_OBJECT_KILL_ON_CLOSE,
    STATUS_PORT_NOT_SET, STATUS_SUCCESS, DEBUG_ALL_ACCESS,
    // Session management
    dbgk_create_debug_object, dbgk_set_process_debug_object,
    dbgk_clear_process_debug_object, dbgk_wait_for_debug_event,
    dbgk_debug_continue,
    // Debug port lookups (NT 5.2 API)
    dbgk_open_process_debug_port, dbgk_reference_process_debug_port,
    dbgk_dereference_process_debug_port, dbgk_is_process_being_debugged,
    dbgk_get_process_debug_object, dbgk_get_debugged_processes,
    // Process tracking
    dbgk_register_debugged_process, dbgk_unregister_debugged_process,
    // Statistics
    dbgk_get_stats, dbgk_log_event_generated, dbgk_log_continue,
    dbgk_log_session_created, dbgk_log_session_closed,
};

pub use event::{
    DebugEvent, DebugEventFlags, DebugApiNumber,
    DbgkmCreateProcess, DbgkmCreateThread, DbgkmExitThread,
    DbgkmExitProcess, DbgkmLoadDll, DbgkmUnloadDll, DbgkmException,
    DbgkmApiMsg, ContinueStatus,
};

pub use notify::{
    dbgk_create_thread, dbgk_exit_thread, dbgk_exit_process,
    dbgk_map_view_of_section, dbgk_unmap_view_of_section,
    dbgk_forward_exception, dbgk_copy_process_debug_port,
};

use crate::ob::object_type::{ObjectType, ObjectTypeInfo, ObjectTypeCallbacks};
use crate::ke::spinlock::RawSpinLock;

/// Global debug object type
static mut DEBUG_OBJECT_TYPE: Option<ObjectType> = None;

/// Global mutex for process debug port access
static DEBUG_PORT_LOCK: RawSpinLock = RawSpinLock::new();

/// Initialize the DBGK subsystem
///
/// Called during kernel initialization to create the DebugObject type.
pub fn dbgk_initialize() {
    // Create the DebugObject object type
    let mut object_type = ObjectType::new();

    // Configure type info
    let type_info = ObjectTypeInfo {
        object_body_size: core::mem::size_of::<DebugObject>() as u32,
        default_quota: 0,
        valid_access_mask: 0x1F000F,    // DEBUG_ALL_ACCESS
        pool_type: 0, // NonPagedPool
        maintain_handle_count: true,
        allow_naming: true,
        security_required: false,
    };

    // Configure callbacks
    let mut callbacks = ObjectTypeCallbacks::new();
    callbacks.delete = Some(debug_object::dbgk_delete_object);
    callbacks.close = Some(|obj, _| {
        debug_object::dbgk_close_object(obj);
    });

    // Initialize the object type
    object_type.init(b"DebugObject", 16, type_info, callbacks);

    unsafe {
        DEBUG_OBJECT_TYPE = Some(object_type);
    }
}

/// Get the debug object type
pub fn get_debug_object_type() -> Option<&'static ObjectType> {
    unsafe { DEBUG_OBJECT_TYPE.as_ref() }
}

/// State tracking for debug port lock (stores whether interrupts were enabled)
static mut DEBUG_PORT_LOCK_STATE: bool = false;

/// Acquire the debug port lock
pub fn acquire_debug_port_lock() {
    let state = DEBUG_PORT_LOCK.acquire();
    unsafe {
        DEBUG_PORT_LOCK_STATE = state;
    }
}

/// Release the debug port lock
pub fn release_debug_port_lock() {
    let state = unsafe { DEBUG_PORT_LOCK_STATE };
    DEBUG_PORT_LOCK.release(state);
}
