//! KERNEL32.DLL Stub Implementation
//!
//! KERNEL32 provides the Win32 base API:
//! - Process and thread management
//! - Memory management
//! - File I/O
//! - Console I/O
//! - Error handling
//! - Synchronization
//!
//! Most functions wrap NTDLL functions with Win32-friendly interfaces.

use super::ntdll;

/// Initialize kernel32 stubs
pub fn init() {
    crate::serial_println!("[KERNEL32] Initializing kernel32.dll stubs");
}

/// Get export address by name
pub fn get_export(name: &str) -> Option<u64> {
    let addr = match name {
        // Process/Thread
        "GetCurrentProcess" => get_current_process as *const () as u64,
        "GetCurrentProcessId" => get_current_process_id as *const () as u64,
        "GetCurrentThread" => get_current_thread as *const () as u64,
        "GetCurrentThreadId" => get_current_thread_id as *const () as u64,
        "CreateThread" => create_thread as *const () as u64,
        "ExitThread" => exit_thread as *const () as u64,
        "ExitProcess" => exit_process as *const () as u64,
        "TerminateProcess" => terminate_process as *const () as u64,
        "TerminateThread" => terminate_thread as *const () as u64,
        "GetExitCodeProcess" => get_exit_code_process as *const () as u64,
        "GetExitCodeThread" => get_exit_code_thread as *const () as u64,
        "Sleep" => sleep as *const () as u64,
        "SleepEx" => sleep_ex as *const () as u64,
        "SwitchToThread" => switch_to_thread as *const () as u64,

        // Memory
        "VirtualAlloc" => virtual_alloc as *const () as u64,
        "VirtualAllocEx" => virtual_alloc_ex as *const () as u64,
        "VirtualFree" => virtual_free as *const () as u64,
        "VirtualFreeEx" => virtual_free_ex as *const () as u64,
        "VirtualProtect" => virtual_protect as *const () as u64,
        "VirtualProtectEx" => virtual_protect_ex as *const () as u64,
        "VirtualQuery" => virtual_query as *const () as u64,
        "VirtualQueryEx" => virtual_query_ex as *const () as u64,
        "GetProcessHeap" => get_process_heap as *const () as u64,
        "HeapCreate" => heap_create as *const () as u64,
        "HeapDestroy" => heap_destroy as *const () as u64,
        "HeapAlloc" => heap_alloc as *const () as u64,
        "HeapFree" => heap_free as *const () as u64,
        "HeapReAlloc" => heap_realloc as *const () as u64,
        "HeapSize" => heap_size as *const () as u64,
        "GlobalAlloc" => global_alloc as *const () as u64,
        "GlobalFree" => global_free as *const () as u64,
        "GlobalLock" => global_lock as *const () as u64,
        "GlobalUnlock" => global_unlock as *const () as u64,
        "LocalAlloc" => local_alloc as *const () as u64,
        "LocalFree" => local_free as *const () as u64,
        "LocalLock" => local_lock as *const () as u64,
        "LocalUnlock" => local_unlock as *const () as u64,

        // File I/O
        "CreateFileA" => create_file_a as *const () as u64,
        "CreateFileW" => create_file_w as *const () as u64,
        "ReadFile" => read_file as *const () as u64,
        "WriteFile" => write_file as *const () as u64,
        "CloseHandle" => close_handle as *const () as u64,
        "DeleteFileA" => delete_file_a as *const () as u64,
        "DeleteFileW" => delete_file_w as *const () as u64,
        "GetFileSize" => get_file_size as *const () as u64,
        "GetFileSizeEx" => get_file_size_ex as *const () as u64,
        "SetFilePointer" => set_file_pointer as *const () as u64,
        "SetFilePointerEx" => set_file_pointer_ex as *const () as u64,
        "FlushFileBuffers" => flush_file_buffers as *const () as u64,
        "GetFileType" => get_file_type as *const () as u64,
        "GetFileAttributesA" => get_file_attributes_a as *const () as u64,
        "GetFileAttributesW" => get_file_attributes_w as *const () as u64,
        "SetFileAttributesA" => set_file_attributes_a as *const () as u64,
        "SetFileAttributesW" => set_file_attributes_w as *const () as u64,
        "FindFirstFileA" => find_first_file_a as *const () as u64,
        "FindFirstFileW" => find_first_file_w as *const () as u64,
        "FindNextFileA" => find_next_file_a as *const () as u64,
        "FindNextFileW" => find_next_file_w as *const () as u64,
        "FindClose" => find_close as *const () as u64,
        "CreateDirectoryA" => create_directory_a as *const () as u64,
        "CreateDirectoryW" => create_directory_w as *const () as u64,
        "RemoveDirectoryA" => remove_directory_a as *const () as u64,
        "RemoveDirectoryW" => remove_directory_w as *const () as u64,
        "GetCurrentDirectoryA" => get_current_directory_a as *const () as u64,
        "GetCurrentDirectoryW" => get_current_directory_w as *const () as u64,
        "SetCurrentDirectoryA" => set_current_directory_a as *const () as u64,
        "SetCurrentDirectoryW" => set_current_directory_w as *const () as u64,

        // Console
        "GetStdHandle" => get_std_handle as *const () as u64,
        "SetStdHandle" => set_std_handle as *const () as u64,
        "WriteConsoleA" => write_console_a as *const () as u64,
        "WriteConsoleW" => write_console_w as *const () as u64,
        "ReadConsoleA" => read_console_a as *const () as u64,
        "ReadConsoleW" => read_console_w as *const () as u64,
        "AllocConsole" => alloc_console as *const () as u64,
        "FreeConsole" => free_console as *const () as u64,
        "SetConsoleMode" => set_console_mode as *const () as u64,
        "GetConsoleMode" => get_console_mode as *const () as u64,
        "SetConsoleTitleA" => set_console_title_a as *const () as u64,
        "SetConsoleTitleW" => set_console_title_w as *const () as u64,

        // Synchronization
        "WaitForSingleObject" => wait_for_single_object as *const () as u64,
        "WaitForSingleObjectEx" => wait_for_single_object_ex as *const () as u64,
        "WaitForMultipleObjects" => wait_for_multiple_objects as *const () as u64,
        "WaitForMultipleObjectsEx" => wait_for_multiple_objects_ex as *const () as u64,
        "CreateEventA" => create_event_a as *const () as u64,
        "CreateEventW" => create_event_w as *const () as u64,
        "SetEvent" => set_event as *const () as u64,
        "ResetEvent" => reset_event as *const () as u64,
        "CreateMutexA" => create_mutex_a as *const () as u64,
        "CreateMutexW" => create_mutex_w as *const () as u64,
        "ReleaseMutex" => release_mutex as *const () as u64,
        "CreateSemaphoreA" => create_semaphore_a as *const () as u64,
        "CreateSemaphoreW" => create_semaphore_w as *const () as u64,
        "ReleaseSemaphore" => release_semaphore as *const () as u64,
        "InitializeCriticalSection" => initialize_critical_section as *const () as u64,
        "DeleteCriticalSection" => delete_critical_section as *const () as u64,
        "EnterCriticalSection" => enter_critical_section as *const () as u64,
        "LeaveCriticalSection" => leave_critical_section as *const () as u64,
        "TryEnterCriticalSection" => try_enter_critical_section as *const () as u64,

        // Error handling
        "GetLastError" => get_last_error as *const () as u64,
        "SetLastError" => set_last_error as *const () as u64,

        // Module/Library
        "GetModuleHandleA" => get_module_handle_a as *const () as u64,
        "GetModuleHandleW" => get_module_handle_w as *const () as u64,
        "GetModuleFileNameA" => get_module_filename_a as *const () as u64,
        "GetModuleFileNameW" => get_module_filename_w as *const () as u64,
        "LoadLibraryA" => load_library_a as *const () as u64,
        "LoadLibraryW" => load_library_w as *const () as u64,
        "LoadLibraryExA" => load_library_ex_a as *const () as u64,
        "LoadLibraryExW" => load_library_ex_w as *const () as u64,
        "FreeLibrary" => free_library as *const () as u64,
        "GetProcAddress" => get_proc_address as *const () as u64,

        // Environment
        "GetCommandLineA" => get_command_line_a as *const () as u64,
        "GetCommandLineW" => get_command_line_w as *const () as u64,
        "GetEnvironmentVariableA" => get_environment_variable_a as *const () as u64,
        "GetEnvironmentVariableW" => get_environment_variable_w as *const () as u64,
        "SetEnvironmentVariableA" => set_environment_variable_a as *const () as u64,
        "SetEnvironmentVariableW" => set_environment_variable_w as *const () as u64,
        "GetEnvironmentStringsA" => get_environment_strings_a as *const () as u64,
        "GetEnvironmentStringsW" => get_environment_strings_w as *const () as u64,

        // System Info
        "GetSystemInfo" => get_system_info as *const () as u64,
        "GetVersionExA" => get_version_ex_a as *const () as u64,
        "GetVersionExW" => get_version_ex_w as *const () as u64,
        "GetVersion" => get_version as *const () as u64,
        "GetTickCount" => get_tick_count as *const () as u64,
        "GetTickCount64" => get_tick_count64 as *const () as u64,
        "QueryPerformanceCounter" => query_performance_counter as *const () as u64,
        "QueryPerformanceFrequency" => query_performance_frequency as *const () as u64,
        "GetSystemTime" => get_system_time as *const () as u64,
        "GetLocalTime" => get_local_time as *const () as u64,
        "GetSystemTimeAsFileTime" => get_system_time_as_file_time as *const () as u64,

        // String functions
        "lstrlenA" => lstrlen_a as *const () as u64,
        "lstrlenW" => lstrlen_w as *const () as u64,
        "lstrcpyA" => lstrcpy_a as *const () as u64,
        "lstrcpyW" => lstrcpy_w as *const () as u64,
        "lstrcatA" => lstrcat_a as *const () as u64,
        "lstrcatW" => lstrcat_w as *const () as u64,
        "lstrcmpA" => lstrcmp_a as *const () as u64,
        "lstrcmpW" => lstrcmp_w as *const () as u64,
        "lstrcmpiA" => lstrcmpi_a as *const () as u64,
        "lstrcmpiW" => lstrcmpi_w as *const () as u64,
        "MultiByteToWideChar" => multi_byte_to_wide_char as *const () as u64,
        "WideCharToMultiByte" => wide_char_to_multi_byte as *const () as u64,

        // Output debug
        "OutputDebugStringA" => output_debug_string_a as *const () as u64,
        "OutputDebugStringW" => output_debug_string_w as *const () as u64,

        _ => return None,
    };

    Some(addr)
}

// =============================================================================
// Thread-local storage for last error
// =============================================================================

// Per-thread last error (simplified - should be in TEB)
static mut LAST_ERROR: u32 = 0;

#[no_mangle]
pub extern "C" fn get_last_error() -> u32 {
    unsafe { LAST_ERROR }
}

#[no_mangle]
pub extern "C" fn set_last_error(error: u32) {
    unsafe { LAST_ERROR = error; }
}

// =============================================================================
// Process/Thread Functions
// =============================================================================

/// Pseudo-handle for current process (-1)
const CURRENT_PROCESS: usize = usize::MAX;
/// Pseudo-handle for current thread (-2)
const CURRENT_THREAD: usize = usize::MAX - 1;

#[no_mangle]
pub extern "C" fn get_current_process() -> usize {
    CURRENT_PROCESS
}

#[no_mangle]
pub extern "C" fn get_current_process_id() -> u32 {
    // Get from process manager
    let proc = crate::ps::get_current_process();
    if proc.is_null() {
        return 0;
    }
    unsafe { (*proc).unique_process_id }
}

#[no_mangle]
pub extern "C" fn get_current_thread() -> usize {
    CURRENT_THREAD
}

#[no_mangle]
pub extern "C" fn get_current_thread_id() -> u32 {
    // Get from process manager
    let thread = crate::ps::get_current_thread();
    if thread.is_null() {
        return 0;
    }
    unsafe { (*thread).thread_id() }
}

#[no_mangle]
pub unsafe extern "C" fn create_thread(
    attribs: usize,
    stack_size: usize,
    start_routine: usize,
    param: usize,
    flags: u32,
    thread_id: *mut u32,
) -> usize {
    // TODO: Implement via NtCreateThread
    0 // NULL = failure
}

#[no_mangle]
pub unsafe extern "C" fn exit_thread(exit_code: u32) {
    ntdll::nt_terminate_thread(CURRENT_THREAD, exit_code as usize);
}

#[no_mangle]
pub unsafe extern "C" fn exit_process(exit_code: u32) {
    ntdll::nt_terminate_process(CURRENT_PROCESS, exit_code as usize);
}

#[no_mangle]
pub unsafe extern "C" fn terminate_process(process: usize, exit_code: u32) -> i32 {
    let result = ntdll::nt_terminate_process(process, exit_code as usize);
    if result >= 0 { 1 } else { set_last_error(result as u32); 0 }
}

#[no_mangle]
pub unsafe extern "C" fn terminate_thread(thread: usize, exit_code: u32) -> i32 {
    let result = ntdll::nt_terminate_thread(thread, exit_code as usize);
    if result >= 0 { 1 } else { set_last_error(result as u32); 0 }
}

#[no_mangle]
pub unsafe extern "C" fn get_exit_code_process(process: usize, exit_code: *mut u32) -> i32 {
    // TODO: Query process info
    if !exit_code.is_null() {
        *exit_code = 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn get_exit_code_thread(thread: usize, exit_code: *mut u32) -> i32 {
    if !exit_code.is_null() {
        *exit_code = 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn sleep(milliseconds: u32) {
    sleep_ex(milliseconds, 0);
}

#[no_mangle]
pub unsafe extern "C" fn sleep_ex(milliseconds: u32, alertable: u32) -> u32 {
    // Convert to 100ns units (negative = relative)
    let delay: i64 = -(milliseconds as i64 * 10000);
    ntdll::nt_delay_execution(alertable as u8, &delay);
    0
}

#[no_mangle]
pub unsafe extern "C" fn switch_to_thread() -> i32 {
    ntdll::nt_yield_execution();
    1
}

// =============================================================================
// Memory Functions
// =============================================================================

#[no_mangle]
pub unsafe extern "C" fn virtual_alloc(
    address: usize,
    size: usize,
    alloc_type: u32,
    protect: u32,
) -> *mut u8 {
    virtual_alloc_ex(CURRENT_PROCESS, address, size, alloc_type, protect)
}

#[no_mangle]
pub unsafe extern "C" fn virtual_alloc_ex(
    process: usize,
    address: usize,
    size: usize,
    alloc_type: u32,
    protect: u32,
) -> *mut u8 {
    let mut base = address;
    let mut alloc_size = size;
    let result = ntdll::nt_allocate_virtual_memory(
        process,
        &mut base as *mut usize,
        0,
        &mut alloc_size as *mut usize,
        alloc_type,
        protect,
    );
    if result >= 0 {
        base as *mut u8
    } else {
        set_last_error(result as u32);
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn virtual_free(address: *mut u8, size: usize, free_type: u32) -> i32 {
    virtual_free_ex(CURRENT_PROCESS, address, size, free_type)
}

#[no_mangle]
pub unsafe extern "C" fn virtual_free_ex(
    process: usize,
    address: *mut u8,
    size: usize,
    free_type: u32,
) -> i32 {
    let mut base = address as usize;
    let mut free_size = size;
    let result = ntdll::nt_free_virtual_memory(
        process,
        &mut base as *mut usize,
        &mut free_size as *mut usize,
        free_type,
    );
    if result >= 0 { 1 } else { set_last_error(result as u32); 0 }
}

#[no_mangle]
pub unsafe extern "C" fn virtual_protect(
    address: *mut u8,
    size: usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    virtual_protect_ex(CURRENT_PROCESS, address, size, new_protect, old_protect)
}

#[no_mangle]
pub unsafe extern "C" fn virtual_protect_ex(
    process: usize,
    address: *mut u8,
    size: usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    let mut base = address as usize;
    let mut prot_size = size;
    let result = ntdll::nt_protect_virtual_memory(
        process,
        &mut base as *mut usize,
        &mut prot_size as *mut usize,
        new_protect,
        old_protect,
    );
    if result >= 0 { 1 } else { set_last_error(result as u32); 0 }
}

#[no_mangle]
pub unsafe extern "C" fn virtual_query(address: *const u8, buffer: *mut u8, length: usize) -> usize {
    virtual_query_ex(CURRENT_PROCESS, address, buffer, length)
}

#[no_mangle]
pub unsafe extern "C" fn virtual_query_ex(
    process: usize,
    address: *const u8,
    buffer: *mut u8,
    length: usize,
) -> usize {
    let mut return_length: usize = 0;
    let result = ntdll::nt_query_virtual_memory(
        process,
        address as usize,
        0, // MemoryBasicInformation
        buffer,
        length,
        &mut return_length as *mut usize,
    );
    if result >= 0 { return_length } else { 0 }
}

// Heap functions
#[no_mangle]
pub unsafe extern "C" fn get_process_heap() -> usize {
    ntdll::rtl_get_process_heap()
}

#[no_mangle]
pub unsafe extern "C" fn heap_create(options: u32, initial_size: usize, max_size: usize) -> usize {
    ntdll::rtl_create_heap(options, 0, max_size, initial_size, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn heap_destroy(heap: usize) -> i32 {
    ntdll::rtl_destroy_heap(heap) as i32
}

#[no_mangle]
pub unsafe extern "C" fn heap_alloc(heap: usize, flags: u32, size: usize) -> *mut u8 {
    ntdll::rtl_allocate_heap(heap, flags, size)
}

#[no_mangle]
pub unsafe extern "C" fn heap_free(heap: usize, flags: u32, ptr: *mut u8) -> i32 {
    ntdll::rtl_free_heap(heap, flags, ptr) as i32
}

#[no_mangle]
pub unsafe extern "C" fn heap_realloc(heap: usize, flags: u32, ptr: *mut u8, size: usize) -> *mut u8 {
    // Simple realloc: alloc new, copy, free old
    let new_ptr = heap_alloc(heap, flags, size);
    if !new_ptr.is_null() && !ptr.is_null() {
        core::ptr::copy_nonoverlapping(ptr, new_ptr, size);
        heap_free(heap, flags, ptr);
    }
    new_ptr
}

#[no_mangle]
pub unsafe extern "C" fn heap_size(heap: usize, flags: u32, ptr: *const u8) -> usize {
    // TODO: Implement
    0
}

// Global/Local memory (legacy, wrapper around heap)
#[no_mangle]
pub unsafe extern "C" fn global_alloc(flags: u32, size: usize) -> usize {
    heap_alloc(get_process_heap(), 0, size) as usize
}

#[no_mangle]
pub unsafe extern "C" fn global_free(mem: usize) -> usize {
    heap_free(get_process_heap(), 0, mem as *mut u8);
    0
}

#[no_mangle]
pub unsafe extern "C" fn global_lock(mem: usize) -> *mut u8 {
    mem as *mut u8
}

#[no_mangle]
pub unsafe extern "C" fn global_unlock(mem: usize) -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn local_alloc(flags: u32, size: usize) -> usize {
    global_alloc(flags, size)
}

#[no_mangle]
pub unsafe extern "C" fn local_free(mem: usize) -> usize {
    global_free(mem)
}

#[no_mangle]
pub unsafe extern "C" fn local_lock(mem: usize) -> *mut u8 {
    global_lock(mem)
}

#[no_mangle]
pub unsafe extern "C" fn local_unlock(mem: usize) -> i32 {
    global_unlock(mem)
}

// =============================================================================
// File I/O Functions
// =============================================================================

const INVALID_HANDLE_VALUE: usize = usize::MAX;

#[no_mangle]
pub unsafe extern "C" fn create_file_a(
    filename: *const u8,
    access: u32,
    share_mode: u32,
    security: usize,
    creation: u32,
    flags: u32,
    template: usize,
) -> usize {
    // TODO: Convert ANSI to UNICODE and call NtCreateFile
    crate::serial_println!("[KERNEL32] CreateFileA called");
    INVALID_HANDLE_VALUE
}

#[no_mangle]
pub unsafe extern "C" fn create_file_w(
    filename: *const u16,
    access: u32,
    share_mode: u32,
    security: usize,
    creation: u32,
    flags: u32,
    template: usize,
) -> usize {
    // TODO: Call NtCreateFile
    crate::serial_println!("[KERNEL32] CreateFileW called");
    INVALID_HANDLE_VALUE
}

#[no_mangle]
pub unsafe extern "C" fn read_file(
    file: usize,
    buffer: *mut u8,
    bytes_to_read: u32,
    bytes_read: *mut u32,
    overlapped: usize,
) -> i32 {
    // TODO: Implement via NtReadFile
    if !bytes_read.is_null() {
        *bytes_read = 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn write_file(
    file: usize,
    buffer: *const u8,
    bytes_to_write: u32,
    bytes_written: *mut u32,
    overlapped: usize,
) -> i32 {
    // TODO: Implement via NtWriteFile
    if !bytes_written.is_null() {
        *bytes_written = 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn close_handle(handle: usize) -> i32 {
    let result = ntdll::nt_close(handle);
    if result >= 0 { 1 } else { set_last_error(result as u32); 0 }
}

#[no_mangle]
pub unsafe extern "C" fn delete_file_a(filename: *const u8) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn delete_file_w(filename: *const u16) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn get_file_size(file: usize, high: *mut u32) -> u32 {
    0xFFFFFFFF // INVALID_FILE_SIZE
}

#[no_mangle]
pub unsafe extern "C" fn get_file_size_ex(file: usize, size: *mut i64) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn set_file_pointer(file: usize, distance: i32, high: *mut i32, method: u32) -> u32 {
    0xFFFFFFFF
}

#[no_mangle]
pub unsafe extern "C" fn set_file_pointer_ex(file: usize, distance: i64, new_pos: *mut i64, method: u32) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn flush_file_buffers(file: usize) -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn get_file_type(file: usize) -> u32 {
    0 // FILE_TYPE_UNKNOWN
}

#[no_mangle]
pub unsafe extern "C" fn get_file_attributes_a(filename: *const u8) -> u32 {
    0xFFFFFFFF // INVALID_FILE_ATTRIBUTES
}

#[no_mangle]
pub unsafe extern "C" fn get_file_attributes_w(filename: *const u16) -> u32 {
    0xFFFFFFFF
}

#[no_mangle]
pub unsafe extern "C" fn set_file_attributes_a(filename: *const u8, attribs: u32) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn set_file_attributes_w(filename: *const u16, attribs: u32) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn find_first_file_a(filename: *const u8, data: *mut u8) -> usize {
    INVALID_HANDLE_VALUE
}

#[no_mangle]
pub unsafe extern "C" fn find_first_file_w(filename: *const u16, data: *mut u8) -> usize {
    INVALID_HANDLE_VALUE
}

#[no_mangle]
pub unsafe extern "C" fn find_next_file_a(handle: usize, data: *mut u8) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn find_next_file_w(handle: usize, data: *mut u8) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn find_close(handle: usize) -> i32 {
    close_handle(handle)
}

#[no_mangle]
pub unsafe extern "C" fn create_directory_a(path: *const u8, security: usize) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn create_directory_w(path: *const u16, security: usize) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn remove_directory_a(path: *const u8) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn remove_directory_w(path: *const u16) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn get_current_directory_a(size: u32, buffer: *mut u8) -> u32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn get_current_directory_w(size: u32, buffer: *mut u16) -> u32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn set_current_directory_a(path: *const u8) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn set_current_directory_w(path: *const u16) -> i32 {
    0
}

// =============================================================================
// Console Functions
// =============================================================================

const STD_INPUT_HANDLE: u32 = 0xFFFFFFF6;
const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;
const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4;

static mut STD_IN: usize = 0;
static mut STD_OUT: usize = 0;
static mut STD_ERR: usize = 0;

#[no_mangle]
pub unsafe extern "C" fn get_std_handle(handle_type: u32) -> usize {
    match handle_type {
        0xFFFFFFF6 => STD_IN,
        0xFFFFFFF5 => STD_OUT,
        0xFFFFFFF4 => STD_ERR,
        _ => INVALID_HANDLE_VALUE,
    }
}

#[no_mangle]
pub unsafe extern "C" fn set_std_handle(handle_type: u32, handle: usize) -> i32 {
    match handle_type {
        0xFFFFFFF6 => { STD_IN = handle; 1 }
        0xFFFFFFF5 => { STD_OUT = handle; 1 }
        0xFFFFFFF4 => { STD_ERR = handle; 1 }
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn write_console_a(
    handle: usize,
    buffer: *const u8,
    chars: u32,
    written: *mut u32,
    reserved: usize,
) -> i32 {
    // Write to serial for now
    for i in 0..chars as usize {
        crate::serial_print!("{}", *buffer.add(i) as char);
    }
    if !written.is_null() {
        *written = chars;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn write_console_w(
    handle: usize,
    buffer: *const u16,
    chars: u32,
    written: *mut u32,
    reserved: usize,
) -> i32 {
    for i in 0..chars as usize {
        let c = *buffer.add(i);
        if c < 128 {
            crate::serial_print!("{}", c as u8 as char);
        }
    }
    if !written.is_null() {
        *written = chars;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn read_console_a(
    handle: usize,
    buffer: *mut u8,
    chars: u32,
    read: *mut u32,
    input_control: usize,
) -> i32 {
    if !read.is_null() {
        *read = 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn read_console_w(
    handle: usize,
    buffer: *mut u16,
    chars: u32,
    read: *mut u32,
    input_control: usize,
) -> i32 {
    if !read.is_null() {
        *read = 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn alloc_console() -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn free_console() -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn set_console_mode(handle: usize, mode: u32) -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn get_console_mode(handle: usize, mode: *mut u32) -> i32 {
    if !mode.is_null() {
        *mode = 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn set_console_title_a(title: *const u8) -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn set_console_title_w(title: *const u16) -> i32 {
    1
}

// =============================================================================
// Synchronization Functions
// =============================================================================

const INFINITE: u32 = 0xFFFFFFFF;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_ABANDONED: u32 = 0x80;
const WAIT_TIMEOUT: u32 = 0x102;
const WAIT_FAILED: u32 = 0xFFFFFFFF;

#[no_mangle]
pub unsafe extern "C" fn wait_for_single_object(handle: usize, milliseconds: u32) -> u32 {
    wait_for_single_object_ex(handle, milliseconds, 0)
}

#[no_mangle]
pub unsafe extern "C" fn wait_for_single_object_ex(handle: usize, milliseconds: u32, alertable: u32) -> u32 {
    let timeout = if milliseconds == INFINITE {
        core::ptr::null()
    } else {
        static mut TIMEOUT: i64 = 0;
        TIMEOUT = -(milliseconds as i64 * 10000);
        &TIMEOUT as *const i64
    };

    let result = ntdll::nt_wait_for_single_object(handle, alertable as u8, timeout);
    if result >= 0 { result as u32 } else { WAIT_FAILED }
}

#[no_mangle]
pub unsafe extern "C" fn wait_for_multiple_objects(
    count: u32,
    handles: *const usize,
    wait_all: i32,
    milliseconds: u32,
) -> u32 {
    wait_for_multiple_objects_ex(count, handles, wait_all, milliseconds, 0)
}

#[no_mangle]
pub unsafe extern "C" fn wait_for_multiple_objects_ex(
    count: u32,
    handles: *const usize,
    wait_all: i32,
    milliseconds: u32,
    alertable: u32,
) -> u32 {
    let timeout = if milliseconds == INFINITE {
        core::ptr::null()
    } else {
        static mut TIMEOUT: i64 = 0;
        TIMEOUT = -(milliseconds as i64 * 10000);
        &TIMEOUT as *const i64
    };

    let result = ntdll::nt_wait_for_multiple_objects(
        count,
        handles,
        if wait_all != 0 { 1 } else { 0 },
        alertable as u8,
        timeout,
    );
    if result >= 0 { result as u32 } else { WAIT_FAILED }
}

#[no_mangle]
pub unsafe extern "C" fn create_event_a(
    attribs: usize,
    manual_reset: i32,
    initial_state: i32,
    name: *const u8,
) -> usize {
    let mut handle: usize = 0;
    let result = ntdll::nt_create_event(
        &mut handle as *mut usize,
        0x1F0003, // EVENT_ALL_ACCESS
        0,
        if manual_reset != 0 { 1 } else { 0 }, // Manual vs Auto reset
        initial_state as u8,
    );
    if result >= 0 { handle } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn create_event_w(
    attribs: usize,
    manual_reset: i32,
    initial_state: i32,
    name: *const u16,
) -> usize {
    create_event_a(attribs, manual_reset, initial_state, core::ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn set_event(handle: usize) -> i32 {
    let result = ntdll::nt_set_event(handle, core::ptr::null_mut());
    if result >= 0 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn reset_event(handle: usize) -> i32 {
    let result = ntdll::nt_reset_event(handle, core::ptr::null_mut());
    if result >= 0 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn create_mutex_a(
    attribs: usize,
    initial_owner: i32,
    name: *const u8,
) -> usize {
    let mut handle: usize = 0;
    let result = ntdll::nt_create_mutant(
        &mut handle as *mut usize,
        0x1F0001, // MUTANT_ALL_ACCESS
        0,
        initial_owner as u8,
    );
    if result >= 0 { handle } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn create_mutex_w(
    attribs: usize,
    initial_owner: i32,
    name: *const u16,
) -> usize {
    create_mutex_a(attribs, initial_owner, core::ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn release_mutex(handle: usize) -> i32 {
    let result = ntdll::nt_release_mutant(handle, core::ptr::null_mut());
    if result >= 0 { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn create_semaphore_a(
    attribs: usize,
    initial_count: i32,
    maximum_count: i32,
    name: *const u8,
) -> usize {
    let mut handle: usize = 0;
    let result = ntdll::nt_create_semaphore(
        &mut handle as *mut usize,
        0x1F0003, // SEMAPHORE_ALL_ACCESS
        0,
        initial_count as u32,
        maximum_count as u32,
    );
    if result >= 0 { handle } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn create_semaphore_w(
    attribs: usize,
    initial_count: i32,
    maximum_count: i32,
    name: *const u16,
) -> usize {
    create_semaphore_a(attribs, initial_count, maximum_count, core::ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn release_semaphore(
    handle: usize,
    release_count: i32,
    previous_count: *mut i32,
) -> i32 {
    let result = ntdll::nt_release_semaphore(handle, release_count as u32, previous_count as *mut u32);
    if result >= 0 { 1 } else { 0 }
}

// Critical section functions
#[no_mangle]
pub unsafe extern "C" fn initialize_critical_section(cs: *mut ntdll::CriticalSection) {
    ntdll::rtl_initialize_critical_section(cs);
}

#[no_mangle]
pub unsafe extern "C" fn delete_critical_section(cs: *mut ntdll::CriticalSection) {
    ntdll::rtl_delete_critical_section(cs);
}

#[no_mangle]
pub unsafe extern "C" fn enter_critical_section(cs: *mut ntdll::CriticalSection) {
    ntdll::rtl_enter_critical_section(cs);
}

#[no_mangle]
pub unsafe extern "C" fn leave_critical_section(cs: *mut ntdll::CriticalSection) {
    ntdll::rtl_leave_critical_section(cs);
}

#[no_mangle]
pub unsafe extern "C" fn try_enter_critical_section(cs: *mut ntdll::CriticalSection) -> i32 {
    // Simplified: just try to enter
    enter_critical_section(cs);
    1
}

// =============================================================================
// Module Functions
// =============================================================================

#[no_mangle]
pub unsafe extern "C" fn get_module_handle_a(name: *const u8) -> usize {
    // NULL = current module
    if name.is_null() {
        // Return image base from PEB
        return 0x400000; // Default
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn get_module_handle_w(name: *const u16) -> usize {
    if name.is_null() {
        return 0x400000;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn get_module_filename_a(module: usize, filename: *mut u8, size: u32) -> u32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn get_module_filename_w(module: usize, filename: *mut u16, size: u32) -> u32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn load_library_a(name: *const u8) -> usize {
    crate::serial_println!("[KERNEL32] LoadLibraryA called");
    0
}

#[no_mangle]
pub unsafe extern "C" fn load_library_w(name: *const u16) -> usize {
    crate::serial_println!("[KERNEL32] LoadLibraryW called");
    0
}

#[no_mangle]
pub unsafe extern "C" fn load_library_ex_a(name: *const u8, file: usize, flags: u32) -> usize {
    load_library_a(name)
}

#[no_mangle]
pub unsafe extern "C" fn load_library_ex_w(name: *const u16, file: usize, flags: u32) -> usize {
    load_library_w(name)
}

#[no_mangle]
pub unsafe extern "C" fn free_library(module: usize) -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn get_proc_address(module: usize, name: *const u8) -> usize {
    crate::serial_println!("[KERNEL32] GetProcAddress called");
    0
}

// =============================================================================
// Environment Functions
// =============================================================================

static mut COMMAND_LINE_A: [u8; 256] = [0; 256];
static mut COMMAND_LINE_W: [u16; 256] = [0; 256];

#[no_mangle]
pub unsafe extern "C" fn get_command_line_a() -> *const u8 {
    COMMAND_LINE_A.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn get_command_line_w() -> *const u16 {
    COMMAND_LINE_W.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn get_environment_variable_a(name: *const u8, buffer: *mut u8, size: u32) -> u32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn get_environment_variable_w(name: *const u16, buffer: *mut u16, size: u32) -> u32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn set_environment_variable_a(name: *const u8, value: *const u8) -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn set_environment_variable_w(name: *const u16, value: *const u16) -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn get_environment_strings_a() -> *const u8 {
    core::ptr::null()
}

#[no_mangle]
pub unsafe extern "C" fn get_environment_strings_w() -> *const u16 {
    core::ptr::null()
}

// =============================================================================
// System Info Functions
// =============================================================================

#[repr(C)]
pub struct SystemInfo {
    pub processor_architecture: u16,
    pub reserved: u16,
    pub page_size: u32,
    pub minimum_application_address: usize,
    pub maximum_application_address: usize,
    pub active_processor_mask: usize,
    pub number_of_processors: u32,
    pub processor_type: u32,
    pub allocation_granularity: u32,
    pub processor_level: u16,
    pub processor_revision: u16,
}

#[no_mangle]
pub unsafe extern "C" fn get_system_info(info: *mut SystemInfo) {
    if info.is_null() { return; }

    (*info).processor_architecture = 9; // AMD64
    (*info).page_size = 4096;
    (*info).minimum_application_address = 0x10000;
    (*info).maximum_application_address = 0x7FFFFFFF0000;
    (*info).active_processor_mask = 1;
    (*info).number_of_processors = 1;
    (*info).processor_type = 8664; // AMD64
    (*info).allocation_granularity = 65536;
    (*info).processor_level = 6;
    (*info).processor_revision = 0;
}

#[repr(C)]
pub struct OsVersionInfoA {
    pub size: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
    pub csd_version: [u8; 128],
}

#[no_mangle]
pub unsafe extern "C" fn get_version_ex_a(info: *mut OsVersionInfoA) -> i32 {
    if info.is_null() { return 0; }

    (*info).major_version = 5;
    (*info).minor_version = 2; // Windows Server 2003
    (*info).build_number = 3790;
    (*info).platform_id = 2; // VER_PLATFORM_WIN32_NT
    (*info).csd_version = [0; 128];
    1
}

#[no_mangle]
pub unsafe extern "C" fn get_version_ex_w(info: *mut u8) -> i32 {
    1
}

#[no_mangle]
pub extern "C" fn get_version() -> u32 {
    // Build 3790, Minor 2, Major 5
    (3790 << 16) | (2 << 8) | 5
}

#[no_mangle]
pub extern "C" fn get_tick_count() -> u32 {
    // TODO: Get actual tick count
    0
}

#[no_mangle]
pub extern "C" fn get_tick_count64() -> u64 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn query_performance_counter(counter: *mut i64) -> i32 {
    if !counter.is_null() {
        *counter = 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn query_performance_frequency(frequency: *mut i64) -> i32 {
    if !frequency.is_null() {
        *frequency = 1000000; // 1MHz
    }
    1
}

#[repr(C)]
pub struct SystemTime {
    pub year: u16,
    pub month: u16,
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
}

#[no_mangle]
pub unsafe extern "C" fn get_system_time(time: *mut SystemTime) {
    if time.is_null() { return; }

    (*time).year = 2003;
    (*time).month = 1;
    (*time).day_of_week = 0;
    (*time).day = 1;
    (*time).hour = 0;
    (*time).minute = 0;
    (*time).second = 0;
    (*time).milliseconds = 0;
}

#[no_mangle]
pub unsafe extern "C" fn get_local_time(time: *mut SystemTime) {
    get_system_time(time);
}

#[no_mangle]
pub unsafe extern "C" fn get_system_time_as_file_time(time: *mut i64) {
    if !time.is_null() {
        *time = 0;
    }
}

// =============================================================================
// String Functions
// =============================================================================

#[no_mangle]
pub unsafe extern "C" fn lstrlen_a(s: *const u8) -> i32 {
    if s.is_null() { return 0; }
    let mut len = 0;
    let mut p = s;
    while *p != 0 {
        len += 1;
        p = p.add(1);
    }
    len
}

#[no_mangle]
pub unsafe extern "C" fn lstrlen_w(s: *const u16) -> i32 {
    if s.is_null() { return 0; }
    let mut len = 0;
    let mut p = s;
    while *p != 0 {
        len += 1;
        p = p.add(1);
    }
    len
}

#[no_mangle]
pub unsafe extern "C" fn lstrcpy_a(dest: *mut u8, src: *const u8) -> *mut u8 {
    if dest.is_null() { return dest; }
    if src.is_null() { return dest; }

    let mut d = dest;
    let mut s = src;
    while *s != 0 {
        *d = *s;
        d = d.add(1);
        s = s.add(1);
    }
    *d = 0;
    dest
}

#[no_mangle]
pub unsafe extern "C" fn lstrcpy_w(dest: *mut u16, src: *const u16) -> *mut u16 {
    if dest.is_null() { return dest; }
    if src.is_null() { return dest; }

    let mut d = dest;
    let mut s = src;
    while *s != 0 {
        *d = *s;
        d = d.add(1);
        s = s.add(1);
    }
    *d = 0;
    dest
}

#[no_mangle]
pub unsafe extern "C" fn lstrcat_a(dest: *mut u8, src: *const u8) -> *mut u8 {
    if dest.is_null() { return dest; }
    // Find end of dest
    let mut d = dest;
    while *d != 0 {
        d = d.add(1);
    }
    lstrcpy_a(d, src);
    dest
}

#[no_mangle]
pub unsafe extern "C" fn lstrcat_w(dest: *mut u16, src: *const u16) -> *mut u16 {
    if dest.is_null() { return dest; }
    let mut d = dest;
    while *d != 0 {
        d = d.add(1);
    }
    lstrcpy_w(d, src);
    dest
}

#[no_mangle]
pub unsafe extern "C" fn lstrcmp_a(s1: *const u8, s2: *const u8) -> i32 {
    if s1.is_null() && s2.is_null() { return 0; }
    if s1.is_null() { return -1; }
    if s2.is_null() { return 1; }

    let mut p1 = s1;
    let mut p2 = s2;
    while *p1 != 0 && *p2 != 0 {
        if *p1 < *p2 { return -1; }
        if *p1 > *p2 { return 1; }
        p1 = p1.add(1);
        p2 = p2.add(1);
    }
    if *p1 == 0 && *p2 == 0 { 0 }
    else if *p1 == 0 { -1 }
    else { 1 }
}

#[no_mangle]
pub unsafe extern "C" fn lstrcmp_w(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() && s2.is_null() { return 0; }
    if s1.is_null() { return -1; }
    if s2.is_null() { return 1; }

    let mut p1 = s1;
    let mut p2 = s2;
    while *p1 != 0 && *p2 != 0 {
        if *p1 < *p2 { return -1; }
        if *p1 > *p2 { return 1; }
        p1 = p1.add(1);
        p2 = p2.add(1);
    }
    if *p1 == 0 && *p2 == 0 { 0 }
    else if *p1 == 0 { -1 }
    else { 1 }
}

#[no_mangle]
pub unsafe extern "C" fn lstrcmpi_a(s1: *const u8, s2: *const u8) -> i32 {
    // Case-insensitive compare
    if s1.is_null() && s2.is_null() { return 0; }
    if s1.is_null() { return -1; }
    if s2.is_null() { return 1; }

    let mut p1 = s1;
    let mut p2 = s2;
    while *p1 != 0 && *p2 != 0 {
        let c1 = (*p1 as char).to_ascii_lowercase() as u8;
        let c2 = (*p2 as char).to_ascii_lowercase() as u8;
        if c1 < c2 { return -1; }
        if c1 > c2 { return 1; }
        p1 = p1.add(1);
        p2 = p2.add(1);
    }
    if *p1 == 0 && *p2 == 0 { 0 }
    else if *p1 == 0 { -1 }
    else { 1 }
}

#[no_mangle]
pub unsafe extern "C" fn lstrcmpi_w(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() && s2.is_null() { return 0; }
    if s1.is_null() { return -1; }
    if s2.is_null() { return 1; }

    let mut p1 = s1;
    let mut p2 = s2;
    while *p1 != 0 && *p2 != 0 {
        let c1 = if *p1 < 128 { (*p1 as u8 as char).to_ascii_lowercase() as u16 } else { *p1 };
        let c2 = if *p2 < 128 { (*p2 as u8 as char).to_ascii_lowercase() as u16 } else { *p2 };
        if c1 < c2 { return -1; }
        if c1 > c2 { return 1; }
        p1 = p1.add(1);
        p2 = p2.add(1);
    }
    if *p1 == 0 && *p2 == 0 { 0 }
    else if *p1 == 0 { -1 }
    else { 1 }
}

#[no_mangle]
pub unsafe extern "C" fn multi_byte_to_wide_char(
    code_page: u32,
    flags: u32,
    src: *const u8,
    src_len: i32,
    dest: *mut u16,
    dest_len: i32,
) -> i32 {
    if src.is_null() { return 0; }

    let len = if src_len < 0 { lstrlen_a(src) + 1 } else { src_len };

    if dest.is_null() || dest_len == 0 {
        return len;
    }

    let copy_len = len.min(dest_len);
    for i in 0..copy_len as usize {
        *dest.add(i) = *src.add(i) as u16;
    }
    copy_len
}

#[no_mangle]
pub unsafe extern "C" fn wide_char_to_multi_byte(
    code_page: u32,
    flags: u32,
    src: *const u16,
    src_len: i32,
    dest: *mut u8,
    dest_len: i32,
    default_char: *const u8,
    used_default: *mut i32,
) -> i32 {
    if src.is_null() { return 0; }

    let len = if src_len < 0 { lstrlen_w(src) + 1 } else { src_len };

    if dest.is_null() || dest_len == 0 {
        return len;
    }

    let copy_len = len.min(dest_len);
    for i in 0..copy_len as usize {
        let c = *src.add(i);
        *dest.add(i) = if c < 128 { c as u8 } else { b'?' };
    }
    copy_len
}

// =============================================================================
// Debug Functions
// =============================================================================

#[no_mangle]
pub unsafe extern "C" fn output_debug_string_a(string: *const u8) {
    if string.is_null() { return; }

    let mut p = string;
    while *p != 0 {
        crate::serial_print!("{}", *p as char);
        p = p.add(1);
    }
    crate::serial_println!("");
}

#[no_mangle]
pub unsafe extern "C" fn output_debug_string_w(string: *const u16) {
    if string.is_null() { return; }

    let mut p = string;
    while *p != 0 {
        if *p < 128 {
            crate::serial_print!("{}", *p as u8 as char);
        }
        p = p.add(1);
    }
    crate::serial_println!("");
}
