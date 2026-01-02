//! CSR Server DLL Management
//!
//! Manages the registration and dispatch of CSR server DLLs.
//! Server DLLs extend CSRSS functionality (BASESRV, WINSRV, etc.).

extern crate alloc;

use super::{CsrServerDll, CsrApiMessage, CSR_STATE};
use crate::ob::handle::Handle;
use alloc::string::String;
use alloc::vec::Vec;

// ============================================================================
// Server DLL Constants
// ============================================================================

/// Base server DLL (kernel32 support)
pub const BASESRV_DLL: &str = "basesrv.dll";
/// Window server DLL (user32/gdi32 support)
pub const WINSRV_DLL: &str = "winsrv.dll";
/// Console server DLL (console support)
pub const CONSRV_DLL: &str = "consrv.dll";

/// Server DLL API ranges
pub const BASESRV_API_BASE: u32 = 0;
pub const BASESRV_API_COUNT: u32 = 32;
pub const WINSRV_API_BASE: u32 = 0x10000;
pub const WINSRV_API_COUNT: u32 = 128;
pub const CONSRV_API_BASE: u32 = 0x20000;
pub const CONSRV_API_COUNT: u32 = 64;

// ============================================================================
// Server DLL Callbacks
// ============================================================================

/// Server DLL connect callback signature
pub type ServerConnectRoutine = fn(process_id: u32, connection_info: &[u8]) -> i32;

/// Server DLL disconnect callback signature
pub type ServerDisconnectRoutine = fn(process_id: u32) -> i32;

/// Server DLL shutdown callback signature
pub type ServerShutdownRoutine = fn(flags: u32) -> i32;

/// Server DLL API dispatch signature
pub type ServerApiDispatch = fn(msg: &mut CsrApiMessage) -> i32;

// ============================================================================
// Server State
// ============================================================================

/// Built-in BASESRV APIs
static BASESRV_APIS: &[(&str, u32)] = &[
    ("BasepCreateProcess", 0),
    ("BasepCreateThread", 1),
    ("BasepExitProcess", 2),
    ("BasepDebugProcess", 3),
    ("BasepCheckVDM", 4),
    ("BasepUpdateVDMEntry", 5),
    ("BasepGetNextVDMCommand", 6),
    ("BasepExitVDM", 7),
    ("BasepSetRebootCommand", 8),
    ("BasepRefreshIniFileMapping", 9),
    ("BasepDefineDosDevice", 10),
    ("BasepSoundSentry", 11),
    ("BasepGetTempFile", 12),
];

/// Built-in WINSRV APIs
static WINSRV_APIS: &[(&str, u32)] = &[
    ("ConsolepOpenConsole", 0),
    ("ConsolepGetConsoleInput", 1),
    ("ConsolepWriteConsoleInput", 2),
    ("ConsolepReadConsoleOutput", 3),
    ("ConsolepWriteConsoleOutput", 4),
    ("ConsolepGetScreenBufferInfo", 5),
    ("ConsolepSetScreenBufferInfo", 6),
    ("ConsolepSetCursorPosition", 7),
    ("ConsolepSetTextAttribute", 8),
    ("ConsolepSetTitle", 9),
    ("ConsolepGetTitle", 10),
    ("ConsolepScrollScreen", 11),
    ("ConsolepFlushInputBuffer", 12),
    ("ConsolepSetMode", 13),
    ("ConsolepGetMode", 14),
    ("ConsolepCreateScreenBuffer", 15),
    ("ConsolepSetActiveScreenBuffer", 16),
    ("ConsolepCloseHandle", 17),
    ("ConsolepDuplicateHandle", 18),
    ("ConsolepGetNumberOfConsoleFonts", 19),
    ("ConsolepSetFont", 20),
    ("ConsolepGetConsoleCP", 21),
    ("ConsolepSetConsoleCP", 22),
    ("ConsolepGetKeyboardLayoutName", 23),
    ("ConsolepGetConsoleWindow", 24),
    ("ConsolepNotifyLastClose", 25),
];

// ============================================================================
// Server Functions
// ============================================================================

/// Initialize server DLL management
pub fn init() {
    // Register built-in server DLLs
    register_builtin_servers();

    crate::serial_println!("[CSR] Server DLL management initialized");
}

/// Register built-in server DLLs
fn register_builtin_servers() {
    // BASESRV - Base Windows services
    let basesrv = CsrServerDll {
        name: String::from(BASESRV_DLL),
        api_base: BASESRV_API_BASE,
        api_count: BASESRV_API_COUNT,
        module_handle: 0, // NULL handle
        connect_routine: 0,
        disconnect_routine: 0,
        shutdown_routine: 0,
    };
    super::register_server_dll(basesrv);

    // WINSRV - Window/Console services
    let winsrv = CsrServerDll {
        name: String::from(WINSRV_DLL),
        api_base: WINSRV_API_BASE,
        api_count: WINSRV_API_COUNT,
        module_handle: 0, // NULL handle
        connect_routine: 0,
        disconnect_routine: 0,
        shutdown_routine: 0,
    };
    super::register_server_dll(winsrv);

    crate::serial_println!("[CSR] Registered {} built-in server DLLs", 2);
}

/// Get API name by number
pub fn get_api_name(api_number: u32) -> Option<&'static str> {
    if api_number < WINSRV_API_BASE {
        // BASESRV API
        BASESRV_APIS.iter()
            .find(|(_, num)| *num == api_number)
            .map(|(name, _)| *name)
    } else if api_number < CONSRV_API_BASE {
        // WINSRV API
        let local_num = api_number - WINSRV_API_BASE;
        WINSRV_APIS.iter()
            .find(|(_, num)| *num == local_num)
            .map(|(name, _)| *name)
    } else {
        None
    }
}

/// Dispatch API to appropriate server
pub fn dispatch_api(msg: &mut CsrApiMessage) -> i32 {
    let api = msg.api_number as u32;

    // Log the API call
    if let Some(name) = get_api_name(api) {
        crate::serial_println!("[CSR] Dispatch API: {} (0x{:x})", name, api);
    }

    // Route to appropriate handler
    super::handle_api_request(msg)
}

/// Call server connect routines for new process
pub fn call_connect_routines(process_id: u32, connection_info: &[u8]) -> i32 {
    let state = CSR_STATE.lock();

    for dll in state.server_dlls.iter() {
        if dll.connect_routine != 0 {
            // In real implementation, would call the routine
            crate::serial_println!("[CSR] Connect routine for {} (process {})",
                dll.name, process_id);
        }
    }

    0
}

/// Call server disconnect routines for exiting process
pub fn call_disconnect_routines(process_id: u32) -> i32 {
    let state = CSR_STATE.lock();

    for dll in state.server_dlls.iter() {
        if dll.disconnect_routine != 0 {
            crate::serial_println!("[CSR] Disconnect routine for {} (process {})",
                dll.name, process_id);
        }
    }

    0
}

/// Call server shutdown routines
pub fn call_shutdown_routines(flags: u32) -> i32 {
    let state = CSR_STATE.lock();

    for dll in state.server_dlls.iter() {
        if dll.shutdown_routine != 0 {
            crate::serial_println!("[CSR] Shutdown routine for {} (flags {:08x})",
                dll.name, flags);
        }
    }

    0
}

/// Get registered server DLL count
pub fn get_server_dll_count() -> usize {
    let state = CSR_STATE.lock();
    state.server_dlls.len()
}

/// Get list of registered server DLLs
pub fn get_server_dll_list() -> Vec<String> {
    let state = CSR_STATE.lock();
    state.server_dlls.iter()
        .map(|dll| dll.name.clone())
        .collect()
}

/// Check if server DLL is registered
pub fn is_server_registered(name: &str) -> bool {
    let state = CSR_STATE.lock();
    state.server_dlls.iter()
        .any(|dll| dll.name == name)
}

/// Get API range for server DLL
pub fn get_api_range(name: &str) -> Option<(u32, u32)> {
    let state = CSR_STATE.lock();
    state.server_dlls.iter()
        .find(|dll| dll.name == name)
        .map(|dll| (dll.api_base, dll.api_base + dll.api_count))
}
