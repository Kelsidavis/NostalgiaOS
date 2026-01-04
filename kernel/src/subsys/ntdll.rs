//! NTDLL.DLL Stub Implementation
//!
//! NTDLL is the lowest-level user-mode DLL. It provides:
//! - Syscall stubs (Nt*/Zw* functions)
//! - Runtime library (Rtl* functions)
//! - Loader functions (Ldr* functions)
//! - CSR client functions
//!
//! All other DLLs depend on NTDLL.

use core::arch::asm;

/// NTDLL image base (will be set during injection)
static mut NTDLL_BASE: u64 = 0;

/// Initialize NTDLL stubs
pub fn init() {
    crate::serial_println!("[NTDLL] Initializing ntdll.dll stubs");
}

/// Get export address by name
pub fn get_export(name: &str) -> Option<u64> {
    // Return the address of our stub functions
    let addr = match name {
        // Process/Thread
        "NtTerminateProcess" => nt_terminate_process as *const () as u64,
        "NtTerminateThread" => nt_terminate_thread as *const () as u64,
        "NtCreateThread" => nt_create_thread as *const () as u64,
        "NtCreateThreadEx" => nt_create_thread_ex as *const () as u64,
        "NtGetCurrentProcessorNumber" => nt_get_current_processor as *const () as u64,
        "NtYieldExecution" => nt_yield_execution as *const () as u64,
        "NtDelayExecution" => nt_delay_execution as *const () as u64,
        "NtQueryInformationProcess" => nt_query_information_process as *const () as u64,
        "NtQueryInformationThread" => nt_query_information_thread as *const () as u64,

        // Memory
        "NtAllocateVirtualMemory" => nt_allocate_virtual_memory as *const () as u64,
        "NtFreeVirtualMemory" => nt_free_virtual_memory as *const () as u64,
        "NtProtectVirtualMemory" => nt_protect_virtual_memory as *const () as u64,
        "NtQueryVirtualMemory" => nt_query_virtual_memory as *const () as u64,
        "NtReadVirtualMemory" => nt_read_virtual_memory as *const () as u64,
        "NtWriteVirtualMemory" => nt_write_virtual_memory as *const () as u64,

        // File I/O
        "NtCreateFile" => nt_create_file as *const () as u64,
        "NtOpenFile" => nt_open_file as *const () as u64,
        "NtReadFile" => nt_read_file as *const () as u64,
        "NtWriteFile" => nt_write_file as *const () as u64,
        "NtClose" => nt_close as *const () as u64,
        "NtQueryInformationFile" => nt_query_information_file as *const () as u64,
        "NtSetInformationFile" => nt_set_information_file as *const () as u64,
        "NtDeleteFile" => nt_delete_file as *const () as u64,
        "NtQueryDirectoryFile" => nt_query_directory_file as *const () as u64,
        "NtFlushBuffersFile" => nt_flush_buffers_file as *const () as u64,

        // Synchronization
        "NtWaitForSingleObject" => nt_wait_for_single_object as *const () as u64,
        "NtWaitForMultipleObjects" => nt_wait_for_multiple_objects as *const () as u64,
        "NtCreateEvent" => nt_create_event as *const () as u64,
        "NtSetEvent" => nt_set_event as *const () as u64,
        "NtResetEvent" => nt_reset_event as *const () as u64,
        "NtCreateSemaphore" => nt_create_semaphore as *const () as u64,
        "NtReleaseSemaphore" => nt_release_semaphore as *const () as u64,
        "NtCreateMutant" => nt_create_mutant as *const () as u64,
        "NtReleaseMutant" => nt_release_mutant as *const () as u64,

        // Sections/Memory Mapping
        "NtCreateSection" => nt_create_section as *const () as u64,
        "NtOpenSection" => nt_open_section as *const () as u64,
        "NtMapViewOfSection" => nt_map_view_of_section as *const () as u64,
        "NtUnmapViewOfSection" => nt_unmap_view_of_section as *const () as u64,

        // Registry
        "NtCreateKey" => nt_create_key as *const () as u64,
        "NtOpenKey" => nt_open_key as *const () as u64,
        "NtQueryValueKey" => nt_query_value_key as *const () as u64,
        "NtSetValueKey" => nt_set_value_key as *const () as u64,
        "NtDeleteKey" => nt_delete_key as *const () as u64,
        "NtEnumerateKey" => nt_enumerate_key as *const () as u64,
        "NtEnumerateValueKey" => nt_enumerate_value_key as *const () as u64,

        // Runtime Library
        "RtlInitUnicodeString" => rtl_init_unicode_string as *const () as u64,
        "RtlCopyMemory" => rtl_copy_memory as *const () as u64,
        "RtlZeroMemory" => rtl_zero_memory as *const () as u64,
        "RtlFillMemory" => rtl_fill_memory as *const () as u64,
        "RtlMoveMemory" => rtl_move_memory as *const () as u64,
        "RtlCompareMemory" => rtl_compare_memory as *const () as u64,
        "RtlAllocateHeap" => rtl_allocate_heap as *const () as u64,
        "RtlFreeHeap" => rtl_free_heap as *const () as u64,
        "RtlCreateHeap" => rtl_create_heap as *const () as u64,
        "RtlDestroyHeap" => rtl_destroy_heap as *const () as u64,
        "RtlGetProcessHeap" => rtl_get_process_heap as *const () as u64,
        "RtlEnterCriticalSection" => rtl_enter_critical_section as *const () as u64,
        "RtlLeaveCriticalSection" => rtl_leave_critical_section as *const () as u64,
        "RtlInitializeCriticalSection" => rtl_initialize_critical_section as *const () as u64,
        "RtlDeleteCriticalSection" => rtl_delete_critical_section as *const () as u64,

        // Loader
        "LdrLoadDll" => ldr_load_dll as *const () as u64,
        "LdrUnloadDll" => ldr_unload_dll as *const () as u64,
        "LdrGetProcedureAddress" => ldr_get_procedure_address as *const () as u64,
        "LdrGetDllHandle" => ldr_get_dll_handle as *const () as u64,

        // Debug
        "DbgPrint" => dbg_print as *const () as u64,
        "DbgBreakPoint" => dbg_break_point as *const () as u64,

        _ => return None,
    };

    Some(addr)
}

// =============================================================================
// Syscall Helper
// =============================================================================

/// Invoke a syscall with the given number and arguments
#[inline(always)]
unsafe fn syscall(num: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    let result: isize;
    asm!(
        "syscall",
        inlateout("rax") num => result,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r10") a4,
        in("r8") a5,
        in("r9") a6,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    result
}

// =============================================================================
// Process/Thread Functions
// =============================================================================

#[no_mangle]
pub unsafe extern "C" fn nt_terminate_process(handle: usize, exit_status: usize) -> isize {
    syscall(0, handle, exit_status, 0, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_terminate_thread(handle: usize, exit_status: usize) -> isize {
    syscall(1, handle, exit_status, 0, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_create_thread(
    thread_handle: *mut usize,
    access: u32,
    attribs: usize,
    process: usize,
    client_id: usize,
    context: usize,
) -> isize {
    syscall(2, thread_handle as usize, access as usize, attribs, process, client_id, context)
}

#[no_mangle]
pub unsafe extern "C" fn nt_create_thread_ex(
    thread_handle: *mut usize,
    access: u32,
    attribs: usize,
    process: usize,
    start_routine: usize,
    argument: usize,
) -> isize {
    syscall(2, thread_handle as usize, access as usize, attribs, process, start_routine, argument)
}

#[no_mangle]
pub unsafe extern "C" fn nt_get_current_processor() -> usize {
    // Return 0 for now (single processor)
    0
}

#[no_mangle]
pub unsafe extern "C" fn nt_yield_execution() -> isize {
    syscall(5, 0, 0, 0, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_delay_execution(alertable: u8, delay: *const i64) -> isize {
    syscall(6, alertable as usize, delay as usize, 0, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_query_information_process(
    handle: usize,
    info_class: u32,
    buffer: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> isize {
    // TODO: Implement via syscall
    0 // STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn nt_query_information_thread(
    handle: usize,
    info_class: u32,
    buffer: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> isize {
    // TODO: Implement via syscall
    0 // STATUS_SUCCESS
}

// =============================================================================
// Memory Functions
// =============================================================================

#[no_mangle]
pub unsafe extern "C" fn nt_allocate_virtual_memory(
    process: usize,
    base_addr: *mut usize,
    zero_bits: usize,
    size: *mut usize,
    alloc_type: u32,
    protect: u32,
) -> isize {
    syscall(10, process, base_addr as usize, zero_bits, size as usize, alloc_type as usize, protect as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_free_virtual_memory(
    process: usize,
    base_addr: *mut usize,
    size: *mut usize,
    free_type: u32,
) -> isize {
    syscall(11, process, base_addr as usize, size as usize, free_type as usize, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_protect_virtual_memory(
    process: usize,
    base_addr: *mut usize,
    size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> isize {
    syscall(12, process, base_addr as usize, size as usize, new_protect as usize, old_protect as usize, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_query_virtual_memory(
    process: usize,
    base_addr: usize,
    info_class: u32,
    buffer: *mut u8,
    length: usize,
    return_length: *mut usize,
) -> isize {
    syscall(13, process, base_addr, info_class as usize, buffer as usize, length, return_length as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_read_virtual_memory(
    process: usize,
    base: usize,
    buffer: *mut u8,
    size: usize,
    bytes_read: *mut usize,
) -> isize {
    syscall(51, process, base, buffer as usize, size, bytes_read as usize, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_write_virtual_memory(
    process: usize,
    base: usize,
    buffer: *const u8,
    size: usize,
    bytes_written: *mut usize,
) -> isize {
    syscall(50, process, base, buffer as usize, size, bytes_written as usize, 0)
}

// =============================================================================
// File I/O Functions
// =============================================================================

#[no_mangle]
pub unsafe extern "C" fn nt_create_file(
    file_handle: *mut usize,
    access: u32,
    obj_attribs: usize,
    io_status: usize,
    alloc_size: usize,
    file_attribs: u32,
) -> isize {
    syscall(20, file_handle as usize, access as usize, obj_attribs, io_status, alloc_size, file_attribs as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_open_file(
    file_handle: *mut usize,
    access: u32,
    obj_attribs: usize,
    io_status: usize,
    share_access: u32,
    open_options: u32,
) -> isize {
    syscall(21, file_handle as usize, access as usize, obj_attribs, io_status, share_access as usize, open_options as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_read_file(
    handle: usize,
    event: usize,
    apc_routine: usize,
    apc_context: usize,
    io_status: usize,
    buffer: *mut u8,
) -> isize {
    syscall(22, handle, event, apc_routine, apc_context, io_status, buffer as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_write_file(
    handle: usize,
    event: usize,
    apc_routine: usize,
    apc_context: usize,
    io_status: usize,
    buffer: *const u8,
) -> isize {
    syscall(23, handle, event, apc_routine, apc_context, io_status, buffer as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_close(handle: usize) -> isize {
    syscall(24, handle, 0, 0, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_query_information_file(
    handle: usize,
    io_status: usize,
    buffer: *mut u8,
    length: u32,
    info_class: u32,
) -> isize {
    syscall(25, handle, io_status, buffer as usize, length as usize, info_class as usize, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_set_information_file(
    handle: usize,
    io_status: usize,
    buffer: *const u8,
    length: u32,
    info_class: u32,
) -> isize {
    syscall(26, handle, io_status, buffer as usize, length as usize, info_class as usize, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_delete_file(obj_attribs: usize) -> isize {
    syscall(27, obj_attribs, 0, 0, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_query_directory_file(
    handle: usize,
    event: usize,
    apc_routine: usize,
    apc_context: usize,
    io_status: usize,
    buffer: *mut u8,
) -> isize {
    syscall(28, handle, event, apc_routine, apc_context, io_status, buffer as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_flush_buffers_file(handle: usize, io_status: usize) -> isize {
    // TODO: Implement
    0
}

// =============================================================================
// Synchronization Functions
// =============================================================================

#[no_mangle]
pub unsafe extern "C" fn nt_wait_for_single_object(handle: usize, alertable: u8, timeout: *const i64) -> isize {
    syscall(30, handle, alertable as usize, timeout as usize, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_wait_for_multiple_objects(
    count: u32,
    handles: *const usize,
    wait_type: u32,
    alertable: u8,
    timeout: *const i64,
) -> isize {
    syscall(31, count as usize, handles as usize, wait_type as usize, alertable as usize, timeout as usize, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_create_event(
    event_handle: *mut usize,
    access: u32,
    attribs: usize,
    event_type: u32,
    initial_state: u8,
) -> isize {
    syscall(34, event_handle as usize, access as usize, attribs, event_type as usize, initial_state as usize, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_set_event(handle: usize, previous_state: *mut i32) -> isize {
    syscall(32, handle, previous_state as usize, 0, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_reset_event(handle: usize, previous_state: *mut i32) -> isize {
    syscall(33, handle, previous_state as usize, 0, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_create_semaphore(
    semaphore_handle: *mut usize,
    access: u32,
    attribs: usize,
    initial_count: u32,
    maximum_count: u32,
) -> isize {
    syscall(36, semaphore_handle as usize, access as usize, attribs, initial_count as usize, maximum_count as usize, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_release_semaphore(handle: usize, release_count: u32, previous_count: *mut u32) -> isize {
    syscall(35, handle, release_count as usize, previous_count as usize, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_create_mutant(
    mutant_handle: *mut usize,
    access: u32,
    attribs: usize,
    initial_owner: u8,
) -> isize {
    syscall(38, mutant_handle as usize, access as usize, attribs, initial_owner as usize, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_release_mutant(handle: usize, previous_count: *mut u32) -> isize {
    syscall(37, handle, previous_count as usize, 0, 0, 0, 0)
}

// =============================================================================
// Section Functions
// =============================================================================

#[no_mangle]
pub unsafe extern "C" fn nt_create_section(
    section_handle: *mut usize,
    access: u32,
    attribs: usize,
    max_size: *const i64,
    protect: u32,
    alloc_attribs: u32,
) -> isize {
    syscall(40, section_handle as usize, access as usize, attribs, max_size as usize, protect as usize, alloc_attribs as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_open_section(
    section_handle: *mut usize,
    access: u32,
    attribs: usize,
) -> isize {
    syscall(41, section_handle as usize, access as usize, attribs, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_map_view_of_section(
    section: usize,
    process: usize,
    base_addr: *mut usize,
    zero_bits: usize,
    commit_size: usize,
    section_offset: *mut i64,
) -> isize {
    syscall(42, section, process, base_addr as usize, zero_bits, commit_size, section_offset as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_unmap_view_of_section(process: usize, base_addr: usize) -> isize {
    syscall(43, process, base_addr, 0, 0, 0, 0)
}

// =============================================================================
// Registry Functions
// =============================================================================

#[no_mangle]
pub unsafe extern "C" fn nt_create_key(
    key_handle: *mut usize,
    access: u32,
    attribs: usize,
    title_index: u32,
    class: usize,
    options: u32,
) -> isize {
    syscall(60, key_handle as usize, access as usize, attribs, title_index as usize, class, options as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_open_key(key_handle: *mut usize, access: u32, attribs: usize) -> isize {
    syscall(61, key_handle as usize, access as usize, attribs, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_query_value_key(
    key_handle: usize,
    value_name: usize,
    info_class: u32,
    buffer: *mut u8,
    length: u32,
    result_length: *mut u32,
) -> isize {
    syscall(63, key_handle, value_name, info_class as usize, buffer as usize, length as usize, result_length as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_set_value_key(
    key_handle: usize,
    value_name: usize,
    title_index: u32,
    value_type: u32,
    data: *const u8,
    data_size: u32,
) -> isize {
    syscall(64, key_handle, value_name, title_index as usize, value_type as usize, data as usize, data_size as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_delete_key(key_handle: usize) -> isize {
    syscall(65, key_handle, 0, 0, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn nt_enumerate_key(
    key_handle: usize,
    index: u32,
    info_class: u32,
    buffer: *mut u8,
    length: u32,
    result_length: *mut u32,
) -> isize {
    syscall(67, key_handle, index as usize, info_class as usize, buffer as usize, length as usize, result_length as usize)
}

#[no_mangle]
pub unsafe extern "C" fn nt_enumerate_value_key(
    key_handle: usize,
    index: u32,
    info_class: u32,
    buffer: *mut u8,
    length: u32,
    result_length: *mut u32,
) -> isize {
    syscall(68, key_handle, index as usize, info_class as usize, buffer as usize, length as usize, result_length as usize)
}

// =============================================================================
// Runtime Library Functions
// =============================================================================

/// Unicode string structure
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[no_mangle]
pub unsafe extern "C" fn rtl_init_unicode_string(dest: *mut UnicodeString, source: *const u16) {
    if dest.is_null() {
        return;
    }

    if source.is_null() {
        (*dest).length = 0;
        (*dest).maximum_length = 0;
        (*dest).buffer = core::ptr::null_mut();
        return;
    }

    // Find string length
    let mut len = 0u16;
    let mut p = source;
    while *p != 0 {
        len += 1;
        p = p.add(1);
    }

    (*dest).length = len * 2; // Bytes
    (*dest).maximum_length = (len + 1) * 2;
    (*dest).buffer = source as *mut u16;
}

#[no_mangle]
pub unsafe extern "C" fn rtl_copy_memory(dest: *mut u8, src: *const u8, length: usize) {
    core::ptr::copy_nonoverlapping(src, dest, length);
}

#[no_mangle]
pub unsafe extern "C" fn rtl_zero_memory(dest: *mut u8, length: usize) {
    core::ptr::write_bytes(dest, 0, length);
}

#[no_mangle]
pub unsafe extern "C" fn rtl_fill_memory(dest: *mut u8, length: usize, fill: u8) {
    core::ptr::write_bytes(dest, fill, length);
}

#[no_mangle]
pub unsafe extern "C" fn rtl_move_memory(dest: *mut u8, src: *const u8, length: usize) {
    core::ptr::copy(src, dest, length); // Handles overlapping
}

#[no_mangle]
pub unsafe extern "C" fn rtl_compare_memory(src1: *const u8, src2: *const u8, length: usize) -> usize {
    for i in 0..length {
        if *src1.add(i) != *src2.add(i) {
            return i;
        }
    }
    length
}

// Heap functions - simplified for now
static mut PROCESS_HEAP: usize = 0;

#[no_mangle]
pub unsafe extern "C" fn rtl_get_process_heap() -> usize {
    PROCESS_HEAP
}

#[no_mangle]
pub unsafe extern "C" fn rtl_create_heap(flags: u32, base: usize, reserve: usize, commit: usize, lock: usize, params: usize) -> usize {
    // Simplified: just return a dummy heap handle
    0x1000_0000
}

#[no_mangle]
pub unsafe extern "C" fn rtl_destroy_heap(heap: usize) -> u32 {
    0 // TRUE
}

#[no_mangle]
pub unsafe extern "C" fn rtl_allocate_heap(heap: usize, flags: u32, size: usize) -> *mut u8 {
    // Use syscall to allocate memory
    let mut base: usize = 0;
    let mut alloc_size = size;
    let result = nt_allocate_virtual_memory(
        usize::MAX, // Current process
        &mut base as *mut usize,
        0,
        &mut alloc_size as *mut usize,
        0x1000 | 0x2000, // MEM_COMMIT | MEM_RESERVE
        0x04, // PAGE_READWRITE
    );
    if result >= 0 {
        base as *mut u8
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rtl_free_heap(heap: usize, flags: u32, ptr: *mut u8) -> u32 {
    if ptr.is_null() {
        return 1; // TRUE
    }
    let mut base = ptr as usize;
    let mut size: usize = 0;
    let result = nt_free_virtual_memory(
        usize::MAX,
        &mut base as *mut usize,
        &mut size as *mut usize,
        0x8000, // MEM_RELEASE
    );
    if result >= 0 { 1 } else { 0 }
}

// Critical section - simplified
#[repr(C)]
pub struct CriticalSection {
    debug_info: usize,
    lock_count: i32,
    recursion_count: i32,
    owning_thread: usize,
    lock_semaphore: usize,
    spin_count: usize,
}

#[no_mangle]
pub unsafe extern "C" fn rtl_initialize_critical_section(cs: *mut CriticalSection) -> isize {
    if !cs.is_null() {
        (*cs).debug_info = 0;
        (*cs).lock_count = -1;
        (*cs).recursion_count = 0;
        (*cs).owning_thread = 0;
        (*cs).lock_semaphore = 0;
        (*cs).spin_count = 0;
    }
    0 // STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn rtl_delete_critical_section(cs: *mut CriticalSection) -> isize {
    0 // STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn rtl_enter_critical_section(cs: *mut CriticalSection) -> isize {
    // Simplified: just set ownership
    if !cs.is_null() {
        (*cs).lock_count += 1;
        (*cs).recursion_count += 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rtl_leave_critical_section(cs: *mut CriticalSection) -> isize {
    if !cs.is_null() {
        (*cs).recursion_count -= 1;
        (*cs).lock_count -= 1;
    }
    0
}

// =============================================================================
// Loader Functions
// =============================================================================

#[no_mangle]
pub unsafe extern "C" fn ldr_load_dll(
    search_path: usize,
    dll_characteristics: *const u32,
    dll_name: *const UnicodeString,
    dll_handle: *mut usize,
) -> isize {
    // TODO: Implement DLL loading via kernel
    crate::serial_println!("[NTDLL] LdrLoadDll called");
    0xC0000135u32 as isize // STATUS_DLL_NOT_FOUND
}

#[no_mangle]
pub unsafe extern "C" fn ldr_unload_dll(dll_handle: usize) -> isize {
    0 // STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ldr_get_procedure_address(
    dll_handle: usize,
    proc_name: *const u8,
    ordinal: u32,
    proc_address: *mut usize,
) -> isize {
    // TODO: Implement
    0xC0000139u32 as isize // STATUS_ENTRYPOINT_NOT_FOUND
}

#[no_mangle]
pub unsafe extern "C" fn ldr_get_dll_handle(
    search_path: usize,
    dll_characteristics: *const u32,
    dll_name: *const UnicodeString,
    dll_handle: *mut usize,
) -> isize {
    // TODO: Implement
    0xC0000135u32 as isize // STATUS_DLL_NOT_FOUND
}

// =============================================================================
// Debug Functions
// =============================================================================

/// Debug print function
/// Note: This simplified version just passes the format string, not variadic args
#[no_mangle]
pub unsafe extern "C" fn dbg_print(format: *const u8) -> isize {
    syscall(52, format as usize, 0, 0, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "C" fn dbg_break_point() {
    core::arch::asm!("int3");
}
