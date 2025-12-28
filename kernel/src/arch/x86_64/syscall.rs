//! System Call (SYSCALL/SYSRET) support for x86_64
//!
//! This module implements the fast system call mechanism using the SYSCALL
//! instruction. On x86_64, SYSCALL is the preferred method for entering
//! kernel mode from user space.
//!
//! ## MSR Configuration
//! - STAR (0xC0000081): Segment selectors for SYSCALL/SYSRET
//! - LSTAR (0xC0000082): 64-bit syscall entry point
//! - SFMASK (0xC0000084): RFLAGS mask (bits to clear on SYSCALL)
//!
//! ## Calling Convention
//! - RAX: System call number
//! - RDI, RSI, RDX, R10, R8, R9: Arguments 1-6
//! - RAX: Return value
//! - RCX: Destroyed (contains return RIP)
//! - R11: Destroyed (contains return RFLAGS)

use core::arch::{asm, naked_asm};

/// MSR addresses for syscall configuration
mod msr {
    pub const STAR: u32 = 0xC000_0081;   // Segment selectors
    pub const LSTAR: u32 = 0xC000_0082;  // 64-bit syscall entry
    pub const CSTAR: u32 = 0xC000_0083;  // Compatibility mode entry (not used)
    pub const SFMASK: u32 = 0xC000_0084; // RFLAGS mask
    pub const EFER: u32 = 0xC000_0080;   // Extended Feature Enable Register
}

/// EFER bits
mod efer {
    pub const SCE: u64 = 1 << 0; // System Call Extensions (enable SYSCALL/SYSRET)
}

/// RFLAGS bits to clear on syscall entry
/// Clear IF (interrupts), TF (trap), DF (direction), AC (alignment check)
const SFMASK_VALUE: u64 = 0x4700; // IF | TF | DF | AC | NT

/// Maximum number of syscalls
pub const MAX_SYSCALLS: usize = 256;

/// System call numbers (NT-compatible naming)
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    // Process/Thread control
    NtTerminateProcess = 0,
    NtTerminateThread = 1,
    NtCreateThread = 2,
    NtGetCurrentProcessId = 3,
    NtGetCurrentThreadId = 4,
    NtYieldExecution = 5,
    NtDelayExecution = 6,

    // Memory management
    NtAllocateVirtualMemory = 10,
    NtFreeVirtualMemory = 11,
    NtProtectVirtualMemory = 12,
    NtQueryVirtualMemory = 13,

    // File operations
    NtCreateFile = 20,
    NtOpenFile = 21,
    NtReadFile = 22,
    NtWriteFile = 23,
    NtClose = 24,
    NtQueryInformationFile = 25,
    NtSetInformationFile = 26,
    NtDeleteFile = 27,
    NtQueryDirectoryFile = 28,
    NtLockFile = 29,

    // Synchronization
    NtWaitForSingleObject = 30,
    NtWaitForMultipleObjects = 31,
    NtSetEvent = 32,
    NtResetEvent = 33,
    NtCreateEvent = 34,
    NtReleaseSemaphore = 35,
    NtCreateSemaphore = 36,
    NtReleaseMutant = 37,
    NtCreateMutant = 38,

    // Section objects (shared memory/file mapping)
    NtCreateSection = 40,
    NtOpenSection = 41,
    NtMapViewOfSection = 42,
    NtUnmapViewOfSection = 43,
    NtExtendSection = 44,
    NtQuerySection = 45,

    // I/O Completion Ports
    NtCreateIoCompletion = 46,
    NtSetIoCompletion = 47,
    NtRemoveIoCompletion = 48,
    NtQueryIoCompletion = 49,

    // Debug/Console
    NtWriteVirtualMemory = 50,
    NtReadVirtualMemory = 51,
    NtDebugPrint = 52,

    // Registry operations
    NtCreateKey = 60,
    NtOpenKey = 61,
    NtCloseKey = 62,
    NtQueryValueKey = 63,
    NtSetValueKey = 64,
    NtDeleteKey = 65,
    NtDeleteValueKey = 66,
    NtEnumerateKey = 67,
    NtEnumerateValueKey = 68,
    NtQueryKey = 69,

    // LPC (Local Procedure Call) operations
    NtCreatePort = 70,
    NtConnectPort = 71,
    NtListenPort = 72,
    NtAcceptConnectPort = 73,
    NtRequestPort = 74,
    NtRequestWaitReplyPort = 75,
    NtReplyPort = 76,
    NtReplyWaitReceivePort = 77,
    NtClosePort = 78,
    NtQueryInformationPort = 79,

    // Object/Handle operations
    NtDuplicateHandle = 80,
    NtQueryObject = 81,
    NtSetInformationObject = 82,
    NtWaitForMultipleObjects32 = 83,

    // Process operations
    NtOpenProcess = 90,
    NtQueryInformationProcess = 91,
    NtSetInformationProcess = 92,
    NtSuspendProcess = 93,
    NtResumeProcess = 94,

    // Thread operations
    NtOpenThread = 95,
    NtQueryInformationThread = 96,
    NtSetInformationThread = 97,
    NtSuspendThread = 98,
    NtResumeThread = 99,

    // Security/Token operations
    NtOpenProcessToken = 100,
    NtOpenThreadToken = 101,
    NtQueryInformationToken = 102,
    NtSetInformationToken = 103,
    NtDuplicateToken = 104,
    NtAdjustPrivilegesToken = 105,
    NtAdjustGroupsToken = 106,
    NtImpersonateThread = 107,
}

/// Syscall handler function type
/// Arguments: (arg1, arg2, arg3, arg4, arg5, arg6) -> result
pub type SyscallHandler = fn(usize, usize, usize, usize, usize, usize) -> isize;

/// Syscall dispatch table
static mut SYSCALL_TABLE: [Option<SyscallHandler>; MAX_SYSCALLS] = [None; MAX_SYSCALLS];

/// Read an MSR
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
        options(nomem, nostack, preserves_flags)
    );
    ((hi as u64) << 32) | (lo as u64)
}

/// Write an MSR
#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") lo,
        in("edx") hi,
        options(nomem, nostack, preserves_flags)
    );
}

/// Initialize syscall support
///
/// Sets up the MSRs for SYSCALL/SYSRET instruction support.
///
/// # Safety
/// Must be called once during kernel initialization, after GDT is set up.
pub unsafe fn init() {
    // Enable SYSCALL/SYSRET in EFER
    let efer = rdmsr(msr::EFER);
    wrmsr(msr::EFER, efer | efer::SCE);

    // Set up STAR register
    // Bits 47:32 = kernel CS (SYSCALL loads CS from here, SS from here + 8)
    // Bits 63:48 = user CS base (SYSRET loads CS from here + 16, SS from here + 8)
    //
    // For our GDT layout:
    // - Kernel code: 0x08, Kernel data: 0x10
    // - User data: 0x18 (0x1B with RPL 3), User code: 0x20 (0x23 with RPL 3)
    //
    // SYSCALL: CS = STAR[47:32], SS = STAR[47:32] + 8
    //   So STAR[47:32] = 0x08 => CS = 0x08, SS = 0x10 ✓
    //
    // SYSRET (64-bit): CS = STAR[63:48] + 16, SS = STAR[63:48] + 8
    //   We need CS = 0x20|3 = 0x23, SS = 0x18|3 = 0x1B
    //   So STAR[63:48] = 0x10 => CS = 0x10 + 16 = 0x20 (CPU adds RPL 3)
    //                        => SS = 0x10 + 8 = 0x18 (CPU adds RPL 3)
    let kernel_cs = 0x08u64;
    let user_cs_base = 0x10u64; // SYSRET will add 16 for CS, 8 for SS
    let star = (user_cs_base << 48) | (kernel_cs << 32);
    wrmsr(msr::STAR, star);

    // Set syscall entry point
    wrmsr(msr::LSTAR, syscall_entry as u64);

    // Set compatibility mode entry (not used, but set anyway)
    wrmsr(msr::CSTAR, 0);

    // Set RFLAGS mask - these bits are cleared on SYSCALL entry
    wrmsr(msr::SFMASK, SFMASK_VALUE);

    // Initialize syscall table with default handlers
    init_syscall_table();

    crate::serial_println!("[SYSCALL] Initialized syscall support");
    crate::serial_println!("[SYSCALL] STAR={:#x}, LSTAR={:#x}, SFMASK={:#x}",
        star, syscall_entry as u64, SFMASK_VALUE);
}

/// Initialize the syscall dispatch table
unsafe fn init_syscall_table() {
    // Clear all entries
    for entry in SYSCALL_TABLE.iter_mut() {
        *entry = None;
    }

    // Register default syscall handlers
    register_syscall(SyscallNumber::NtTerminateProcess as usize, sys_terminate_process);
    register_syscall(SyscallNumber::NtTerminateThread as usize, sys_terminate_thread);
    register_syscall(SyscallNumber::NtCreateThread as usize, sys_create_thread);
    register_syscall(SyscallNumber::NtGetCurrentProcessId as usize, sys_get_current_process_id);
    register_syscall(SyscallNumber::NtGetCurrentThreadId as usize, sys_get_current_thread_id);
    register_syscall(SyscallNumber::NtYieldExecution as usize, sys_yield_execution);
    register_syscall(SyscallNumber::NtDelayExecution as usize, sys_delay_execution);
    register_syscall(SyscallNumber::NtDebugPrint as usize, sys_debug_print);
    register_syscall(SyscallNumber::NtClose as usize, sys_close);

    // File operation syscalls
    register_syscall(SyscallNumber::NtCreateFile as usize, sys_create_file);
    register_syscall(SyscallNumber::NtOpenFile as usize, sys_open_file);
    register_syscall(SyscallNumber::NtReadFile as usize, sys_read_file);
    register_syscall(SyscallNumber::NtWriteFile as usize, sys_write_file);
    register_syscall(SyscallNumber::NtQueryInformationFile as usize, sys_query_information_file);
    register_syscall(SyscallNumber::NtSetInformationFile as usize, sys_set_information_file);
    register_syscall(SyscallNumber::NtDeleteFile as usize, sys_delete_file);
    register_syscall(SyscallNumber::NtQueryDirectoryFile as usize, sys_query_directory_file);
    register_syscall(SyscallNumber::NtLockFile as usize, sys_lock_file);

    // Synchronization syscalls
    register_syscall(SyscallNumber::NtWaitForSingleObject as usize, sys_wait_for_single_object);
    register_syscall(SyscallNumber::NtWaitForMultipleObjects as usize, sys_wait_for_multiple_objects);
    register_syscall(SyscallNumber::NtSetEvent as usize, sys_set_event);
    register_syscall(SyscallNumber::NtResetEvent as usize, sys_reset_event);
    register_syscall(SyscallNumber::NtCreateEvent as usize, sys_create_event);
    register_syscall(SyscallNumber::NtReleaseSemaphore as usize, sys_release_semaphore);
    register_syscall(SyscallNumber::NtCreateSemaphore as usize, sys_create_semaphore);
    register_syscall(SyscallNumber::NtReleaseMutant as usize, sys_release_mutant);
    register_syscall(SyscallNumber::NtCreateMutant as usize, sys_create_mutant);

    // Memory management syscalls
    register_syscall(SyscallNumber::NtAllocateVirtualMemory as usize, sys_allocate_virtual_memory);
    register_syscall(SyscallNumber::NtFreeVirtualMemory as usize, sys_free_virtual_memory);
    register_syscall(SyscallNumber::NtProtectVirtualMemory as usize, sys_protect_virtual_memory);
    register_syscall(SyscallNumber::NtQueryVirtualMemory as usize, sys_query_virtual_memory);

    // Section (shared memory) syscalls
    register_syscall(SyscallNumber::NtCreateSection as usize, sys_create_section);
    register_syscall(SyscallNumber::NtMapViewOfSection as usize, sys_map_view_of_section);
    register_syscall(SyscallNumber::NtUnmapViewOfSection as usize, sys_unmap_view_of_section);
    register_syscall(SyscallNumber::NtQuerySection as usize, sys_query_section);

    // I/O Completion Port syscalls
    register_syscall(SyscallNumber::NtCreateIoCompletion as usize, sys_create_io_completion);
    register_syscall(SyscallNumber::NtSetIoCompletion as usize, sys_set_io_completion);
    register_syscall(SyscallNumber::NtRemoveIoCompletion as usize, sys_remove_io_completion);

    // Registry syscalls
    register_syscall(SyscallNumber::NtCreateKey as usize, sys_create_key);
    register_syscall(SyscallNumber::NtOpenKey as usize, sys_open_key);
    register_syscall(SyscallNumber::NtCloseKey as usize, sys_close_key);
    register_syscall(SyscallNumber::NtQueryValueKey as usize, sys_query_value_key);
    register_syscall(SyscallNumber::NtSetValueKey as usize, sys_set_value_key);
    register_syscall(SyscallNumber::NtDeleteKey as usize, sys_delete_key);
    register_syscall(SyscallNumber::NtDeleteValueKey as usize, sys_delete_value_key);
    register_syscall(SyscallNumber::NtEnumerateKey as usize, sys_enumerate_key);
    register_syscall(SyscallNumber::NtEnumerateValueKey as usize, sys_enumerate_value_key);
    register_syscall(SyscallNumber::NtQueryKey as usize, sys_query_key);

    // LPC syscalls
    register_syscall(SyscallNumber::NtCreatePort as usize, sys_create_port);
    register_syscall(SyscallNumber::NtConnectPort as usize, sys_connect_port);
    register_syscall(SyscallNumber::NtListenPort as usize, sys_listen_port);
    register_syscall(SyscallNumber::NtAcceptConnectPort as usize, sys_accept_connect_port);
    register_syscall(SyscallNumber::NtRequestPort as usize, sys_request_port);
    register_syscall(SyscallNumber::NtRequestWaitReplyPort as usize, sys_request_wait_reply_port);
    register_syscall(SyscallNumber::NtReplyPort as usize, sys_reply_port);
    register_syscall(SyscallNumber::NtReplyWaitReceivePort as usize, sys_reply_wait_receive_port);
    register_syscall(SyscallNumber::NtClosePort as usize, sys_close_port);
    register_syscall(SyscallNumber::NtQueryInformationPort as usize, sys_query_information_port);

    // Object/Handle syscalls
    register_syscall(SyscallNumber::NtDuplicateHandle as usize, sys_duplicate_handle);
    register_syscall(SyscallNumber::NtQueryObject as usize, sys_query_object);

    // Process syscalls
    register_syscall(SyscallNumber::NtOpenProcess as usize, sys_open_process);
    register_syscall(SyscallNumber::NtQueryInformationProcess as usize, sys_query_information_process);
    register_syscall(SyscallNumber::NtSuspendProcess as usize, sys_suspend_process);
    register_syscall(SyscallNumber::NtResumeProcess as usize, sys_resume_process);

    // Thread syscalls
    register_syscall(SyscallNumber::NtOpenThread as usize, sys_open_thread);
    register_syscall(SyscallNumber::NtQueryInformationThread as usize, sys_query_information_thread);
    register_syscall(SyscallNumber::NtSuspendThread as usize, sys_suspend_thread);
    register_syscall(SyscallNumber::NtResumeThread as usize, sys_resume_thread);

    // Token syscalls
    register_syscall(SyscallNumber::NtOpenProcessToken as usize, sys_open_process_token);
    register_syscall(SyscallNumber::NtOpenThreadToken as usize, sys_open_thread_token);
    register_syscall(SyscallNumber::NtQueryInformationToken as usize, sys_query_information_token);
    register_syscall(SyscallNumber::NtDuplicateToken as usize, sys_duplicate_token);
    register_syscall(SyscallNumber::NtAdjustPrivilegesToken as usize, sys_adjust_privileges_token);
}

/// Register a syscall handler
///
/// # Safety
/// Handler must be a valid function that handles the syscall correctly.
pub unsafe fn register_syscall(number: usize, handler: SyscallHandler) {
    if number < MAX_SYSCALLS {
        SYSCALL_TABLE[number] = Some(handler);
    }
}

/// Syscall entry point (naked function)
///
/// On entry from SYSCALL:
/// - RCX = return RIP (user)
/// - R11 = return RFLAGS (user)
/// - RSP = user stack (we need to switch to kernel stack!)
/// - RAX = syscall number
/// - RDI, RSI, RDX, R10, R8, R9 = arguments
///
/// We need to:
/// 1. Save user RSP (using swapgs to access per-CPU data)
/// 2. Load kernel RSP
/// 3. Save callee-saved registers
/// 4. Call the syscall dispatcher
/// 5. Restore and return via SYSRET
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        // At this point:
        // - We're in kernel mode (CS = kernel code)
        // - RSP is still the user stack!
        // - RCX = user RIP, R11 = user RFLAGS
        // - RAX = syscall number
        // - RDI, RSI, RDX, R10, R8, R9 = args

        // Swap GS to get access to kernel per-CPU data
        // (In a full implementation, we'd use this to get kernel stack)
        "swapgs",

        // For now, we use a dedicated syscall stack
        // In a full implementation, we'd get this from the PRCB
        // Save user stack pointer in R15 temporarily
        "mov r15, rsp",

        // Load kernel syscall stack
        "mov rsp, gs:[0]",  // Assumes per-CPU syscall stack at gs:0

        // If no per-CPU data set up, use a fallback static stack
        "test rsp, rsp",
        "jnz 2f",
        "lea rsp, [{syscall_stack} + {stack_size}]",
        "2:",

        // Now on kernel stack - save user context
        // Push user stack pointer
        "push r15",
        // Push return address and flags
        "push rcx",         // User RIP
        "push r11",         // User RFLAGS

        // Save callee-saved registers
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // Syscall number is in RAX
        // Arguments: RDI, RSI, RDX, R10, R8, R9
        // Note: R10 replaces RCX in syscall convention

        // Move R10 to RCX for standard calling convention
        "mov rcx, r10",

        // Call the Rust dispatcher
        // dispatcher(syscall_num, arg1, arg2, arg3, arg4, arg5, arg6)
        //           rdi,         rsi,  rdx,  rcx,  r8,   r9,   [stack]
        // We need to set up: rdi=syscall_num, rsi=arg1, rdx=arg2, rcx=arg3, r8=arg4, r9=arg5

        // Current register state:
        // RAX = syscall number
        // RDI = arg1, RSI = arg2, RDX = arg3, RCX = arg4 (was R10), R8 = arg5, R9 = arg6

        // Rearrange for dispatcher call
        // Push arg6 (R9) for stack argument
        "push r9",
        // Set up arguments for dispatcher
        "mov r9, r8",       // arg5 -> r9
        "mov r8, rcx",      // arg4 -> r8
        "mov rcx, rdx",     // arg3 -> rcx
        "mov rdx, rsi",     // arg2 -> rdx
        "mov rsi, rdi",     // arg1 -> rsi
        "mov rdi, rax",     // syscall_num -> rdi

        // Align stack to 16 bytes (required by System V ABI)
        "sub rsp, 8",

        // Call the dispatcher
        "call {dispatcher}",

        // Result is in RAX
        // Clean up stack
        "add rsp, 16",      // Remove alignment + arg6

        // Restore callee-saved registers
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",

        // Restore return context
        "pop r11",          // User RFLAGS
        "pop rcx",          // User RIP
        "pop rsp",          // User RSP

        // Swap back to user GS
        "swapgs",

        // Return to user mode
        // SYSRETQ: RCX -> RIP, R11 -> RFLAGS
        "sysretq",

        dispatcher = sym syscall_dispatcher,
        syscall_stack = sym SYSCALL_STACK,
        stack_size = const SYSCALL_STACK_SIZE,
    )
}

/// Size of syscall stack
const SYSCALL_STACK_SIZE: usize = 16384; // 16KB

/// Aligned syscall stack wrapper
#[repr(C, align(16))]
struct SyscallStack {
    data: [u8; SYSCALL_STACK_SIZE],
}

/// Dedicated syscall stack (used if per-CPU data not available)
static mut SYSCALL_STACK: SyscallStack = SyscallStack {
    data: [0; SYSCALL_STACK_SIZE],
};

/// Per-CPU data structure for syscall handling
/// GS base points to this structure
/// gs:[0] contains the kernel stack pointer
#[repr(C)]
struct PerCpuSyscall {
    kernel_stack: u64, // Offset 0: kernel stack pointer for syscalls
}

/// Static per-CPU data for syscall
static mut SYSCALL_PERCPU: PerCpuSyscall = PerCpuSyscall {
    kernel_stack: 0,
};

/// Syscall dispatcher (called from assembly)
///
/// Looks up the syscall handler and invokes it.
#[no_mangle]
extern "C" fn syscall_dispatcher(
    syscall_num: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> isize {
    // Validate syscall number
    if syscall_num >= MAX_SYSCALLS {
        crate::serial_println!("[SYSCALL] Invalid syscall number: {}", syscall_num);
        return -1; // STATUS_INVALID_SYSTEM_SERVICE
    }

    // Get handler from table
    let handler = unsafe { SYSCALL_TABLE[syscall_num] };

    match handler {
        Some(func) => {
            // Call the handler
            func(arg1, arg2, arg3, arg4, arg5, arg6)
        }
        None => {
            crate::serial_println!("[SYSCALL] Unimplemented syscall: {}", syscall_num);
            -1 // STATUS_NOT_IMPLEMENTED
        }
    }
}

// ============================================================================
// Default Syscall Implementations
// ============================================================================

/// NtTerminateProcess - Terminate the current process
fn sys_terminate_process(
    _exit_code: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtTerminateProcess(exit_code={})", _exit_code);
    // For now, just halt
    loop {
        unsafe { asm!("hlt"); }
    }
}

/// NtTerminateThread - Terminate the current thread
fn sys_terminate_thread(
    exit_code: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtTerminateThread(exit_code={})", exit_code);

    // Check if we're returning from a user mode test
    unsafe {
        if KERNEL_CONTEXT.valid {
            // Save the exit code
            USER_MODE_RESULT = exit_code as isize;

            // Mark context as used
            KERNEL_CONTEXT.valid = false;

            // Restore kernel context and return
            // We do this by restoring registers and jumping back
            asm!(
                // Restore callee-saved registers
                "mov r15, {r15}",
                "mov r14, {r14}",
                "mov r13, {r13}",
                "mov r12, {r12}",
                "mov rbx, {rbx}",
                "mov rbp, {rbp}",
                "mov rsp, {rsp}",
                // Return to saved location
                "ret",
                rsp = in(reg) KERNEL_CONTEXT.rsp,
                rbp = in(reg) KERNEL_CONTEXT.rbp,
                rbx = in(reg) KERNEL_CONTEXT.rbx,
                r12 = in(reg) KERNEL_CONTEXT.r12,
                r13 = in(reg) KERNEL_CONTEXT.r13,
                r14 = in(reg) KERNEL_CONTEXT.r14,
                r15 = in(reg) KERNEL_CONTEXT.r15,
                options(noreturn)
            );
        }
    }

    // Normal thread termination (not from user mode test)
    0
}

// ============================================================================
// Thread Handle Management
// ============================================================================

/// Thread handle table
const MAX_THREAD_HANDLES: usize = 64;
const THREAD_HANDLE_BASE: usize = 0x4000;

/// Thread handle entries (maps to thread IDs)
static mut THREAD_HANDLE_MAP: [u32; MAX_THREAD_HANDLES] = [u32::MAX; MAX_THREAD_HANDLES];

/// Allocate a thread handle
unsafe fn alloc_thread_handle(thread_id: u32) -> Option<usize> {
    for i in 0..MAX_THREAD_HANDLES {
        if THREAD_HANDLE_MAP[i] == u32::MAX {
            THREAD_HANDLE_MAP[i] = thread_id;
            return Some(i + THREAD_HANDLE_BASE);
        }
    }
    None
}

/// Get thread ID from handle
unsafe fn get_thread_id(handle: usize) -> Option<u32> {
    if handle < THREAD_HANDLE_BASE {
        return None;
    }
    let idx = handle - THREAD_HANDLE_BASE;
    if idx >= MAX_THREAD_HANDLES {
        return None;
    }
    let tid = THREAD_HANDLE_MAP[idx];
    if tid == u32::MAX {
        None
    } else {
        Some(tid)
    }
}

/// Free a thread handle
unsafe fn free_thread_handle(handle: usize) {
    if handle >= THREAD_HANDLE_BASE {
        let idx = handle - THREAD_HANDLE_BASE;
        if idx < MAX_THREAD_HANDLES {
            THREAD_HANDLE_MAP[idx] = u32::MAX;
        }
    }
}

/// NtCreateThread - Create a new thread
///
/// Arguments:
/// - thread_handle: Pointer to receive handle
/// - desired_access: Access rights for handle
/// - object_attributes: Security attributes (ignored for now)
/// - process_handle: Handle to owning process
/// - client_id: Receives thread/process IDs
/// - thread_context: Initial context (rip = start address)
fn sys_create_thread(
    thread_handle_ptr: usize,
    _desired_access: usize,
    _object_attributes: usize,
    _process_handle: usize,
    client_id_ptr: usize,
    thread_context_ptr: usize,
) -> isize {
    if thread_handle_ptr == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    crate::serial_println!("[SYSCALL] NtCreateThread()");

    // Get the start address from context
    // Thread context layout (simplified):
    // offset 0x0: rip (instruction pointer / start address)
    // offset 0x8: rsp (stack pointer)
    // offset 0x10: rbp
    // etc.
    let (start_address, initial_rsp) = if thread_context_ptr != 0 {
        unsafe {
            let rip = *(thread_context_ptr as *const u64);
            let rsp = *((thread_context_ptr + 8) as *const u64);
            (rip, rsp)
        }
    } else {
        return -1; // Need a context with at least RIP
    };

    crate::serial_println!("[SYSCALL] NtCreateThread: start_address={:#x}, rsp={:#x}",
        start_address, initial_rsp);

    // Create a wrapper start routine
    // For now, we create a kernel thread that simulates user-mode execution
    // Real NT would set up proper user-mode context

    // Store parameters for the new thread
    static mut THREAD_PARAMS: [(u64, u64); 64] = [(0, 0); 64];
    static mut THREAD_PARAM_IDX: usize = 0;

    unsafe {
        let idx = THREAD_PARAM_IDX % 64;
        THREAD_PARAMS[idx] = (start_address, initial_rsp);
        THREAD_PARAM_IDX += 1;
    }

    // Create system thread (for now, all threads are kernel threads)
    // Real implementation would create user-mode threads with proper address space
    let thread = unsafe {
        crate::ps::create::ps_create_system_thread(
            thread_start_wrapper,
            start_address as *mut u8,
            8, // Normal priority
        )
    };

    if thread.is_null() {
        crate::serial_println!("[SYSCALL] NtCreateThread: failed to create thread");
        return -1; // STATUS_UNSUCCESSFUL
    }

    // Get thread ID
    let thread_id = unsafe { (*thread).cid.unique_thread };

    // Allocate handle
    let handle = unsafe { alloc_thread_handle(thread_id) };
    match handle {
        Some(h) => {
            unsafe { *(thread_handle_ptr as *mut usize) = h; }

            // Fill in client ID if provided
            if client_id_ptr != 0 {
                unsafe {
                    // CLIENT_ID structure: { ProcessId, ThreadId }
                    *(client_id_ptr as *mut u32) = (*thread).cid.unique_process;
                    *((client_id_ptr + 4) as *mut u32) = thread_id;
                }
            }

            // Start the thread
            unsafe {
                crate::ps::create::ps_start_thread(thread);
            }

            crate::serial_println!("[SYSCALL] NtCreateThread -> handle {:#x}, tid {}",
                h, thread_id);
            0 // STATUS_SUCCESS
        }
        None => {
            crate::serial_println!("[SYSCALL] NtCreateThread: no handles available");
            -1 // STATUS_INSUFFICIENT_RESOURCES
        }
    }
}

/// Thread start wrapper
/// This function is called as the thread entry point
fn thread_start_wrapper(_param: *mut u8) {
    // The param is the start address
    // For now, just log and halt
    // Real implementation would:
    // 1. Set up user-mode stack
    // 2. Switch to user mode
    // 3. Jump to start_address

    crate::serial_println!("[THREAD] Thread started at address {:#x}", _param as u64);

    // Simulate doing some work
    for _ in 0..10 {
        unsafe {
            crate::ke::scheduler::ki_yield();
        }
    }

    crate::serial_println!("[THREAD] Thread exiting");
}

/// NtGetCurrentProcessId - Get current process ID
fn sys_get_current_process_id(
    _: usize, _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // Return process ID (for now, always 4 - the System process)
    4
}

/// NtGetCurrentThreadId - Get current thread ID
fn sys_get_current_thread_id(
    _: usize, _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    let thread_id = unsafe {
        let prcb = crate::ke::prcb::get_current_prcb();
        if !prcb.current_thread.is_null() {
            (*prcb.current_thread).thread_id as isize
        } else {
            0
        }
    };
    thread_id
}

/// NtYieldExecution - Yield the current thread's time slice
fn sys_yield_execution(
    _: usize, _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    unsafe {
        crate::ke::scheduler::ki_yield();
    }
    0 // STATUS_SUCCESS
}

/// NtDebugPrint - Print debug message to serial console
fn sys_debug_print(
    buffer: usize,
    length: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // Validate buffer pointer and length
    if buffer == 0 || length == 0 || length > 1024 {
        return -1;
    }

    // Read string from user memory
    // TODO: Proper user memory validation
    let slice = unsafe {
        core::slice::from_raw_parts(buffer as *const u8, length)
    };

    // Convert to string and print
    if let Ok(s) = core::str::from_utf8(slice) {
        crate::serial_print!("{}", s);
        0 // STATUS_SUCCESS
    } else {
        -1 // STATUS_INVALID_PARAMETER
    }
}

/// NtClose - Close a handle
fn sys_close(
    handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtClose(handle={})", handle);

    // Check if this is a file handle
    if let Some(fs_handle) = unsafe { get_fs_handle(handle) } {
        // Close the fs handle
        let _ = crate::fs::close(fs_handle);
        // Free the syscall handle mapping
        unsafe { free_file_handle(handle); }
        return 0;
    }

    // TODO: Handle other handle types via object manager
    0
}

/// NtReadFile - Read from a file
fn sys_read_file(
    handle: usize,
    buffer: usize,
    length: usize,
    bytes_read_ptr: usize,
    _: usize, _: usize,
) -> isize {
    if buffer == 0 || length == 0 {
        return -1;
    }

    // Special case: handle 0 = stdin (not implemented)
    if handle == 0 {
        if bytes_read_ptr != 0 {
            unsafe { *(bytes_read_ptr as *mut usize) = 0; }
        }
        return 0;
    }

    // Try to get fs handle
    let fs_handle = match unsafe { get_fs_handle(handle) } {
        Some(h) => h,
        None => {
            // Not a file handle - return error
            crate::serial_println!("[SYSCALL] NtReadFile: invalid handle {}", handle);
            return -1;
        }
    };

    // Read from file system
    let buf_slice = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };

    match crate::fs::read(fs_handle, buf_slice) {
        Ok(bytes_read) => {
            if bytes_read_ptr != 0 {
                unsafe { *(bytes_read_ptr as *mut usize) = bytes_read; }
            }
            crate::serial_println!("[SYSCALL] NtReadFile(handle={}) -> {} bytes", handle, bytes_read);
            0
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtReadFile(handle={}) -> error {:?}", handle, e);
            if bytes_read_ptr != 0 {
                unsafe { *(bytes_read_ptr as *mut usize) = 0; }
            }
            -1
        }
    }
}

/// NtWriteFile - Write to a file
fn sys_write_file(
    handle: usize,
    buffer: usize,
    length: usize,
    bytes_written_ptr: usize,
    _: usize, _: usize,
) -> isize {
    if buffer == 0 || length == 0 {
        return -1;
    }

    // Special case: handle 1 = stdout (serial console)
    if handle == 1 && length <= 4096 {
        let slice = unsafe {
            core::slice::from_raw_parts(buffer as *const u8, length)
        };

        if let Ok(s) = core::str::from_utf8(slice) {
            crate::serial_print!("{}", s);
            if bytes_written_ptr != 0 {
                unsafe { *(bytes_written_ptr as *mut usize) = length; }
            }
            return 0;
        }
    }

    // Special case: handle 2 = stderr (serial console)
    if handle == 2 && length <= 4096 {
        let slice = unsafe {
            core::slice::from_raw_parts(buffer as *const u8, length)
        };

        if let Ok(s) = core::str::from_utf8(slice) {
            crate::serial_print!("{}", s);
            if bytes_written_ptr != 0 {
                unsafe { *(bytes_written_ptr as *mut usize) = length; }
            }
            return 0;
        }
    }

    // Try to get fs handle
    let fs_handle = match unsafe { get_fs_handle(handle) } {
        Some(h) => h,
        None => {
            crate::serial_println!("[SYSCALL] NtWriteFile: invalid handle {}", handle);
            return -1;
        }
    };

    // Write to file system
    let buf_slice = unsafe { core::slice::from_raw_parts(buffer as *const u8, length) };

    match crate::fs::write(fs_handle, buf_slice) {
        Ok(bytes_written) => {
            if bytes_written_ptr != 0 {
                unsafe { *(bytes_written_ptr as *mut usize) = bytes_written; }
            }
            crate::serial_println!("[SYSCALL] NtWriteFile(handle={}) -> {} bytes", handle, bytes_written);
            0
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtWriteFile(handle={}) -> error {:?}", handle, e);
            if bytes_written_ptr != 0 {
                unsafe { *(bytes_written_ptr as *mut usize) = 0; }
            }
            -1
        }
    }
}

// ============================================================================
// File Operation Syscalls (NtCreateFile, NtOpenFile, etc.)
// ============================================================================

/// File handle table - maps syscall handles to fs handles
/// Handles 0-99 reserved for special handles (stdin, stdout, etc.)
/// Handles 100+ are file system handles
const FILE_HANDLE_BASE: usize = 100;
const MAX_FILE_HANDLES: usize = 256;

/// File handle to fs handle mapping
static mut FILE_HANDLE_MAP: [u16; MAX_FILE_HANDLES] = [0xFFFF; MAX_FILE_HANDLES];

/// Allocate a syscall file handle
unsafe fn alloc_file_handle(fs_handle: u16) -> Option<usize> {
    for i in 0..MAX_FILE_HANDLES {
        if FILE_HANDLE_MAP[i] == 0xFFFF {
            FILE_HANDLE_MAP[i] = fs_handle;
            return Some(i + FILE_HANDLE_BASE);
        }
    }
    None
}

/// Get fs handle from syscall handle
unsafe fn get_fs_handle(syscall_handle: usize) -> Option<u16> {
    if syscall_handle < FILE_HANDLE_BASE {
        return None; // Reserved handles
    }
    let idx = syscall_handle - FILE_HANDLE_BASE;
    if idx >= MAX_FILE_HANDLES {
        return None;
    }
    let fs_handle = FILE_HANDLE_MAP[idx];
    if fs_handle == 0xFFFF {
        None
    } else {
        Some(fs_handle)
    }
}

/// Free a syscall file handle
unsafe fn free_file_handle(syscall_handle: usize) {
    if syscall_handle >= FILE_HANDLE_BASE {
        let idx = syscall_handle - FILE_HANDLE_BASE;
        if idx < MAX_FILE_HANDLES {
            FILE_HANDLE_MAP[idx] = 0xFFFF;
        }
    }
}

/// NT file creation disposition values
pub mod file_disposition {
    pub const FILE_SUPERSEDE: u32 = 0;
    pub const FILE_OPEN: u32 = 1;
    pub const FILE_CREATE: u32 = 2;
    pub const FILE_OPEN_IF: u32 = 3;
    pub const FILE_OVERWRITE: u32 = 4;
    pub const FILE_OVERWRITE_IF: u32 = 5;
}

/// NT file create options
pub mod file_options {
    pub const FILE_DIRECTORY_FILE: u32 = 0x00000001;
    pub const FILE_WRITE_THROUGH: u32 = 0x00000002;
    pub const FILE_SEQUENTIAL_ONLY: u32 = 0x00000004;
    pub const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x00000008;
    pub const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x00000010;
    pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
    pub const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
    pub const FILE_DELETE_ON_CLOSE: u32 = 0x00001000;
}

/// Read a path string from user memory
unsafe fn read_user_path(path_ptr: usize, max_len: usize) -> Option<([u8; 260], usize)> {
    if path_ptr == 0 {
        return None;
    }

    let mut path_buf = [0u8; 260];
    let src = path_ptr as *const u8;
    let mut len = 0;

    while len < max_len && len < 260 {
        let byte = *src.add(len);
        if byte == 0 {
            break;
        }
        path_buf[len] = byte;
        len += 1;
    }

    if len == 0 {
        None
    } else {
        Some((path_buf, len))
    }
}

/// NtCreateFile - Create or open a file
///
/// Arguments:
/// - file_handle: Pointer to receive handle
/// - desired_access: Access mask
/// - object_attributes: Pointer to OBJECT_ATTRIBUTES (contains file name)
/// - io_status_block: Pointer to IO_STATUS_BLOCK
/// - allocation_size: Initial size for new files
/// - file_attributes: File attributes for new files
fn sys_create_file(
    file_handle_ptr: usize,
    desired_access: usize,
    object_attributes: usize,
    io_status_block: usize,
    _allocation_size: usize,
    file_attributes: usize,
) -> isize {
    if file_handle_ptr == 0 || object_attributes == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // OBJECT_ATTRIBUTES layout (simplified):
    // offset 0: length (u32)
    // offset 8: root_directory (handle)
    // offset 16: object_name (pointer to UNICODE_STRING)
    // For now, we read object_name as a simple pointer to path string

    // Read the path from object_attributes
    // Simplified: assume object_attributes points to path string directly
    let path_result = unsafe { read_user_path(object_attributes, 260) };

    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return -1, // STATUS_INVALID_PARAMETER
    };

    let path_str = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    crate::serial_println!("[SYSCALL] NtCreateFile(path='{}', access={:#x})", path_str, desired_access);

    // Try to create the file
    let result = crate::fs::create(path_str, file_attributes as u32);

    match result {
        Ok(fs_handle) => {
            // Allocate syscall handle
            let syscall_handle = unsafe { alloc_file_handle(fs_handle) };
            match syscall_handle {
                Some(h) => {
                    unsafe {
                        *(file_handle_ptr as *mut usize) = h;
                        if io_status_block != 0 {
                            // IO_STATUS_BLOCK: status at offset 0, information at offset 8
                            *(io_status_block as *mut i32) = 0; // STATUS_SUCCESS
                            *((io_status_block + 8) as *mut usize) = 1; // FILE_CREATED
                        }
                    }
                    0 // STATUS_SUCCESS
                }
                None => {
                    let _ = crate::fs::close(fs_handle);
                    -1 // STATUS_INSUFFICIENT_RESOURCES
                }
            }
        }
        Err(_e) => {
            // Try to open existing file instead
            match crate::fs::open(path_str, desired_access as u32) {
                Ok(fs_handle) => {
                    let syscall_handle = unsafe { alloc_file_handle(fs_handle) };
                    match syscall_handle {
                        Some(h) => {
                            unsafe {
                                *(file_handle_ptr as *mut usize) = h;
                                if io_status_block != 0 {
                                    *(io_status_block as *mut i32) = 0;
                                    *((io_status_block + 8) as *mut usize) = 2; // FILE_OPENED
                                }
                            }
                            0
                        }
                        None => {
                            let _ = crate::fs::close(fs_handle);
                            -1
                        }
                    }
                }
                Err(_) => -1, // STATUS_OBJECT_NAME_NOT_FOUND
            }
        }
    }
}

/// NtOpenFile - Open an existing file
fn sys_open_file(
    file_handle_ptr: usize,
    desired_access: usize,
    object_attributes: usize,
    io_status_block: usize,
    share_access: usize,
    open_options: usize,
) -> isize {
    if file_handle_ptr == 0 || object_attributes == 0 {
        return -1;
    }

    let _ = share_access;
    let _ = open_options;

    let path_result = unsafe { read_user_path(object_attributes, 260) };

    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return -1,
    };

    let path_str = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    crate::serial_println!("[SYSCALL] NtOpenFile(path='{}', access={:#x})", path_str, desired_access);

    match crate::fs::open(path_str, desired_access as u32) {
        Ok(fs_handle) => {
            let syscall_handle = unsafe { alloc_file_handle(fs_handle) };
            match syscall_handle {
                Some(h) => {
                    unsafe {
                        *(file_handle_ptr as *mut usize) = h;
                        if io_status_block != 0 {
                            *(io_status_block as *mut i32) = 0;
                            *((io_status_block + 8) as *mut usize) = 2; // FILE_OPENED
                        }
                    }
                    0
                }
                None => {
                    let _ = crate::fs::close(fs_handle);
                    -1
                }
            }
        }
        Err(_) => -1, // STATUS_OBJECT_NAME_NOT_FOUND
    }
}

/// NtQueryInformationFile - Query file information
fn sys_query_information_file(
    file_handle: usize,
    io_status_block: usize,
    file_information: usize,
    length: usize,
    file_information_class: usize,
    _: usize,
) -> isize {
    if file_handle == 0 || file_information == 0 || length == 0 {
        return -1;
    }

    let fs_handle = match unsafe { get_fs_handle(file_handle) } {
        Some(h) => h,
        None => return -1, // STATUS_INVALID_HANDLE
    };

    crate::serial_println!(
        "[SYSCALL] NtQueryInformationFile(handle={}, class={})",
        file_handle, file_information_class
    );

    // Get file info via fs::fstat
    match crate::fs::fstat(fs_handle) {
        Ok(info) => {
            // File information class 5 = FileStandardInformation
            // File information class 18 = FileAllInformation
            // For now, return basic info for all classes
            unsafe {
                if length >= 24 {
                    // FileStandardInformation layout:
                    // AllocationSize: i64
                    // EndOfFile: i64
                    // NumberOfLinks: u32
                    // DeletePending: u8
                    // Directory: u8
                    *(file_information as *mut i64) = info.size as i64; // AllocationSize
                    *((file_information + 8) as *mut i64) = info.size as i64; // EndOfFile
                    *((file_information + 16) as *mut u32) = 1; // NumberOfLinks
                    *((file_information + 20) as *mut u8) = 0; // DeletePending
                    *((file_information + 21) as *mut u8) = if matches!(info.file_type, crate::fs::FileType::Directory) { 1 } else { 0 }; // Directory
                }

                if io_status_block != 0 {
                    *(io_status_block as *mut i32) = 0;
                    *((io_status_block + 8) as *mut usize) = 24;
                }
            }
            0
        }
        Err(_) => -1,
    }
}

/// NtSetInformationFile - Set file information
fn sys_set_information_file(
    file_handle: usize,
    io_status_block: usize,
    file_information: usize,
    length: usize,
    file_information_class: usize,
    _: usize,
) -> isize {
    if file_handle == 0 || file_information == 0 {
        return -1;
    }

    let fs_handle = match unsafe { get_fs_handle(file_handle) } {
        Some(h) => h,
        None => return -1,
    };

    crate::serial_println!(
        "[SYSCALL] NtSetInformationFile(handle={}, class={}, len={})",
        file_handle, file_information_class, length
    );

    // FilePositionInformation = 14 - set file position
    if file_information_class == 14 && length >= 8 {
        let new_position = unsafe { *(file_information as *const i64) };
        if new_position >= 0 {
            // Use seek to set position
            let _ = crate::fs::seek(fs_handle, new_position, crate::fs::SeekWhence::Set);
        }
    }

    // FileEndOfFileInformation = 20 - truncate/extend file
    if file_information_class == 20 && length >= 8 {
        let new_size = unsafe { *(file_information as *const u64) };
        let _ = crate::fs::truncate(fs_handle, new_size);
    }

    unsafe {
        if io_status_block != 0 {
            *(io_status_block as *mut i32) = 0;
            *((io_status_block + 8) as *mut usize) = 0;
        }
    }

    0
}

/// NtDeleteFile - Delete a file
fn sys_delete_file(
    object_attributes: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    if object_attributes == 0 {
        return -1;
    }

    let path_result = unsafe { read_user_path(object_attributes, 260) };

    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return -1,
    };

    let path_str = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    crate::serial_println!("[SYSCALL] NtDeleteFile(path='{}')", path_str);

    match crate::fs::delete(path_str) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Get the syscall stack pointer for per-CPU initialization
pub fn get_syscall_stack() -> *mut u8 {
    unsafe {
        SYSCALL_STACK.data.as_mut_ptr().add(SYSCALL_STACK_SIZE)
    }
}

// ============================================================================
// User Mode Support
// ============================================================================

/// Size of user mode stack
const USER_STACK_SIZE: usize = 16384; // 16KB

/// User mode stack wrapper
#[repr(C, align(16))]
struct UserStack {
    data: [u8; USER_STACK_SIZE],
}

/// Static user mode stack for testing
static mut USER_STACK: UserStack = UserStack {
    data: [0; USER_STACK_SIZE],
};

/// Saved kernel context for returning from user mode test
#[repr(C)]
struct KernelContext {
    rsp: u64,
    rbp: u64,
    rbx: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    valid: bool,
}

static mut KERNEL_CONTEXT: KernelContext = KernelContext {
    rsp: 0, rbp: 0, rbx: 0, r12: 0, r13: 0, r14: 0, r15: 0, valid: false,
};

/// User mode test result (set by NtTerminateThread)
pub static mut USER_MODE_RESULT: isize = -1;

/// Check if returning from user mode
pub fn is_returning_from_user() -> bool {
    unsafe { KERNEL_CONTEXT.valid }
}

/// Enter user mode and execute code at the given address
///
/// Uses IRETQ to switch to ring 3 with the specified entry point.
/// The user code should execute SYSCALL to return to kernel mode.
///
/// # Arguments
/// * `entry_point` - Physical address of user code (must be identity-mapped)
/// * `user_stack` - Physical address of user stack top (must be identity-mapped)
///
/// # Safety
/// - entry_point must be valid executable code at an identity-mapped address
/// - user_stack must be valid stack memory at an identity-mapped address
/// - The code at entry_point should eventually call SYSCALL to return
pub unsafe fn enter_user_mode(entry_point: u64, user_stack: u64) {
    // User mode segments with RPL 3
    let user_cs: u64 = 0x20 | 3; // User code segment | RPL 3 = 0x23
    let user_ss: u64 = 0x18 | 3; // User data segment | RPL 3 = 0x1B

    // RFLAGS with IF (interrupts enabled)
    let rflags: u64 = 0x202;

    // Set up kernel GS base for SWAPGS
    // After SWAPGS, gs:[0] should contain the kernel syscall stack pointer
    let kernel_syscall_stack = SYSCALL_STACK.data.as_mut_ptr().add(SYSCALL_STACK_SIZE) as u64;
    wrmsr(0xC000_0102, kernel_syscall_stack); // MSR_KERNEL_GS_BASE

    // Use IRETQ to switch to ring 3
    // Stack layout for IRETQ: SS, RSP, RFLAGS, CS, RIP
    asm!(
        // Push SS
        "push {ss}",
        // Push RSP (user stack)
        "push {rsp}",
        // Push RFLAGS
        "push {rflags}",
        // Push CS
        "push {cs}",
        // Push RIP (entry point)
        "push {rip}",
        // Execute IRETQ
        "iretq",
        ss = in(reg) user_ss,
        rsp = in(reg) user_stack,
        rflags = in(reg) rflags,
        cs = in(reg) user_cs,
        rip = in(reg) entry_point,
        options(noreturn)
    );
}

/// Simple user mode test stub
///
/// This function is meant to be executed in ring 3.
/// It executes a SYSCALL to print a message and then terminates.
#[unsafe(naked)]
pub unsafe extern "C" fn user_mode_test_stub() {
    naked_asm!(
        // NtDebugPrint syscall
        // RAX = syscall number (52)
        // RDI = buffer pointer
        // RSI = length

        // Set up the message on stack (simpler than referencing data)
        // "User mode OK!\n" = 14 bytes

        // Use a simple approach: just call NtGetCurrentThreadId
        "mov rax, 4",       // NtGetCurrentThreadId
        "syscall",

        // Result is in RAX (thread ID)
        // Now call NtTerminateThread with that as exit code
        "mov rdi, rax",     // exit code = thread id
        "mov rax, 1",       // NtTerminateThread
        "syscall",

        // Should not reach here, but if we do, loop
        "2:",
        "jmp 2b",
    )
}

/// Run user code and return the result
///
/// This function:
/// 1. Saves kernel context (RSP, callee-saved registers, return address)
/// 2. Switches to user page tables
/// 3. Enters ring 3 via IRETQ
/// 4. User code executes and calls NtTerminateThread via SYSCALL
/// 5. NtTerminateThread restores kernel context and returns here
/// 6. Returns the exit code from user mode
///
/// # Arguments
/// * `entry_virt` - Virtual address of user code entry point (mapped in user page tables)
/// * `stack_virt` - Virtual address of user stack top (mapped in user page tables)
///
/// # Returns
/// Exit code from user mode (value passed to NtTerminateThread)
///
/// # Safety
/// - entry_virt must point to valid executable code in user page tables
/// - stack_virt must point to valid stack memory in user page tables
/// - User page tables must be properly initialized
#[inline(never)]
pub unsafe fn run_user_code(entry_virt: u64, stack_virt: u64) -> isize {
    // Set up kernel GS base for SWAPGS
    // When user code executes SYSCALL, SWAPGS will swap GS base to this value
    // Then gs:[0] will read the kernel stack pointer from SYSCALL_PERCPU.kernel_stack
    let kernel_syscall_stack = SYSCALL_STACK.data.as_mut_ptr().add(SYSCALL_STACK_SIZE) as u64;

    // Store the stack pointer in the per-CPU structure
    SYSCALL_PERCPU.kernel_stack = kernel_syscall_stack;

    // Set GS base to point to the per-CPU structure
    let percpu_addr = &SYSCALL_PERCPU as *const _ as u64;
    wrmsr(0xC000_0102, percpu_addr); // MSR_KERNEL_GS_BASE

    let user_cr3 = crate::mm::get_user_cr3();

    // Disable interrupts for the CR3 switch + IRETQ sequence
    core::arch::asm!("cli", options(nostack, preserves_flags));

    // Save kernel context before entering user mode
    // When NtTerminateThread restores context and does "ret",
    // it will return to just after the IRETQ asm block
    KERNEL_CONTEXT.valid = true;
    USER_MODE_RESULT = -1;

    // Save callee-saved registers
    asm!(
        "mov [{ctx} + 0], rsp",
        "mov [{ctx} + 8], rbp",
        "mov [{ctx} + 16], rbx",
        "mov [{ctx} + 24], r12",
        "mov [{ctx} + 32], r13",
        "mov [{ctx} + 40], r14",
        "mov [{ctx} + 48], r15",
        ctx = in(reg) &KERNEL_CONTEXT as *const _ as u64,
        options(nostack, preserves_flags),
    );

    // Now do the CR3 switch + IRETQ
    // Note: We need to save return address, switch CR3, and IRETQ atomically
    asm!(
        // Push return address for NtTerminateThread to use
        "lea rax, [rip + 2f]",
        "push rax",
        // Update saved RSP
        "mov [{ctx} + 0], rsp",

        // Switch to user page tables
        "mov rax, {user_cr3}",
        "mov cr3, rax",

        // Set up IRETQ stack frame (SS, RSP, RFLAGS, CS, RIP)
        "push {ss}",
        "push {stack}",
        "push {rflags}",
        "push {cs}",
        "push {entry}",

        // Execute IRETQ to enter ring 3
        "iretq",

        // Return point - NtTerminateThread will restore context and return here
        "2:",

        ctx = in(reg) &KERNEL_CONTEXT as *const _ as u64,
        user_cr3 = in(reg) user_cr3,
        entry = in(reg) entry_virt,
        stack = in(reg) stack_virt,
        cs = in(reg) 0x23u64,
        ss = in(reg) 0x1Bu64,
        rflags = in(reg) 0x202u64,
        out("rax") _,
        out("dx") _,
        clobber_abi("C"),
    );

    // Switch back to kernel page tables
    let kernel_cr3 = crate::mm::get_kernel_cr3();
    asm!("mov cr3, {}", in(reg) kernel_cr3, options(nostack));

    USER_MODE_RESULT
}

/// Test user mode by entering ring 3 and executing a syscall
///
/// # Safety
/// Requires proper page table setup with user-accessible mappings
pub unsafe fn test_user_mode() {
    // Check if user page tables are initialized
    if !crate::mm::user_pages_initialized() {
        crate::serial_println!("[SYSCALL] User page tables not initialized!");
        return;
    }

    // Use VIRTUAL addresses - these are what the user page tables map!
    // USER_TEST_BASE (0x400000) maps to the code area
    // USER_STACK_TOP (0x800000) is the stack top
    let code_virt = crate::mm::USER_TEST_BASE;
    let stack_virt = crate::mm::USER_STACK_TOP;

    // The user code was already copied by init_user_page_tables()
    let result = run_user_code(code_virt, stack_virt);

    crate::serial_println!("[SYSCALL] User mode test completed with exit code: {}", result);
}

// ============================================================================
// Delay Execution Syscall
// ============================================================================

/// NtDelayExecution - Delay (sleep) the current thread
fn sys_delay_execution(
    alertable: usize,
    delay_interval: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // delay_interval is a pointer to a LARGE_INTEGER (i64)
    // Positive value = absolute time, negative = relative time
    // For now, we only support relative delays
    let _ = alertable; // TODO: Handle alertable waits

    if delay_interval == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // Read the delay value (negative = relative delay in 100ns units)
    let delay_100ns = unsafe { *(delay_interval as *const i64) };

    if delay_100ns >= 0 {
        // Absolute time not yet supported
        return -1;
    }

    // Convert to milliseconds (negative 100ns -> positive ms)
    let delay_ms = ((-delay_100ns) / 10_000) as u64;

    // Use the scheduler's delay mechanism
    unsafe {
        crate::ke::scheduler::ki_delay_execution(delay_ms);
    }

    0 // STATUS_SUCCESS
}

// ============================================================================
// Synchronization Syscalls
// ============================================================================

/// NtWaitForSingleObject - Wait for a single object to become signaled
fn sys_wait_for_single_object(
    handle: usize,
    alertable: usize,
    timeout: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    let _ = alertable; // TODO: Handle alertable waits

    // Get the object from handle
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
        if obj.is_null() {
            return -1; // STATUS_INVALID_HANDLE
        }
        obj
    };

    // Get timeout value (NULL = infinite wait)
    let timeout_ms = if timeout == 0 {
        None
    } else {
        let timeout_100ns = unsafe { *(timeout as *const i64) };
        if timeout_100ns < 0 {
            Some(((-timeout_100ns) / 10_000) as u64)
        } else {
            Some(0) // Absolute time treated as no-wait
        }
    };

    // Wait on the event (assuming it's an event for now)
    let result = unsafe {
        let event = object as *mut crate::ke::event::KEvent;
        if let Some(ms) = timeout_ms {
            if (*event).wait_timeout(ms) {
                0 // STATUS_SUCCESS
            } else {
                0x102 // STATUS_TIMEOUT
            }
        } else {
            (*event).wait();
            0 // STATUS_SUCCESS
        }
    };

    // Dereference the object
    unsafe { crate::ob::ob_dereference_object(object); }

    result
}

/// NtWaitForMultipleObjects - Wait for multiple objects
fn sys_wait_for_multiple_objects(
    count: usize,
    handles: usize,
    wait_type: usize,
    alertable: usize,
    timeout: usize,
    _: usize,
) -> isize {
    let _ = alertable; // TODO: Handle alertable waits
    let _ = wait_type; // 0 = WaitAll, 1 = WaitAny

    if count == 0 || count > 64 || handles == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // For now, just wait on each object sequentially (simplified)
    let handle_array = unsafe {
        core::slice::from_raw_parts(handles as *const usize, count)
    };

    for (i, &handle) in handle_array.iter().enumerate() {
        let result = sys_wait_for_single_object(handle, 0, timeout, 0, 0, 0);
        if result != 0 && result != 0x102 {
            return result;
        }
        if wait_type == 1 && result == 0 {
            // WaitAny - return which object was signaled
            return i as isize;
        }
    }

    0 // STATUS_SUCCESS (all objects signaled for WaitAll)
}

/// NtSetEvent - Set (signal) an event
fn sys_set_event(
    handle: usize,
    previous_state: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(handle) } {
        if obj_type != SyncObjectType::Event {
            return -1;
        }

        let was_signaled = unsafe {
            let event = &mut *core::ptr::addr_of_mut!((*entry).data.event);
            event.set()
        };

        if previous_state != 0 {
            unsafe { *(previous_state as *mut i32) = was_signaled as i32; }
        }

        return 0;
    }

    // Fall back to object manager handles
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
        if obj.is_null() {
            return -1;
        }
        obj
    };

    let was_signaled = unsafe {
        let event = object as *mut crate::ke::event::KEvent;
        (*event).set()
    };

    if previous_state != 0 {
        unsafe { *(previous_state as *mut i32) = was_signaled as i32; }
    }

    unsafe { crate::ob::ob_dereference_object(object); }

    0 // STATUS_SUCCESS
}

/// NtResetEvent - Reset (unsignal) an event
fn sys_reset_event(
    handle: usize,
    previous_state: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(handle) } {
        if obj_type != SyncObjectType::Event {
            return -1;
        }

        let was_signaled = unsafe {
            let event = &mut *core::ptr::addr_of_mut!((*entry).data.event);
            event.reset()
        };

        if previous_state != 0 {
            unsafe { *(previous_state as *mut i32) = was_signaled as i32; }
        }

        return 0;
    }

    // Fall back to object manager handles
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
        if obj.is_null() {
            return -1;
        }
        obj
    };

    let was_signaled = unsafe {
        let event = object as *mut crate::ke::event::KEvent;
        (*event).reset()
    };

    if previous_state != 0 {
        unsafe { *(previous_state as *mut i32) = was_signaled as i32; }
    }

    unsafe { crate::ob::ob_dereference_object(object); }

    0
}

// ============================================================================
// Synchronization Object Pool
// ============================================================================

/// Maximum number of sync objects
const MAX_SYNC_OBJECTS: usize = 128;

/// Sync object pool entry
#[repr(C)]
union SyncObjectUnion {
    event: core::mem::ManuallyDrop<crate::ke::KEvent>,
    semaphore: core::mem::ManuallyDrop<crate::ke::KSemaphore>,
    mutex: core::mem::ManuallyDrop<crate::ke::KMutex>,
}

/// Type of sync object
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum SyncObjectType {
    None = 0,
    Event = 1,
    Semaphore = 2,
    Mutex = 3,
}

/// Sync object pool entry wrapper
struct SyncObjectEntry {
    obj_type: SyncObjectType,
    data: SyncObjectUnion,
}

impl SyncObjectEntry {
    const fn new() -> Self {
        Self {
            obj_type: SyncObjectType::None,
            data: SyncObjectUnion {
                event: core::mem::ManuallyDrop::new(crate::ke::KEvent::new()),
            },
        }
    }
}

/// Pool of synchronization objects
static mut SYNC_OBJECT_POOL: [SyncObjectEntry; MAX_SYNC_OBJECTS] = {
    const INIT: SyncObjectEntry = SyncObjectEntry::new();
    [INIT; MAX_SYNC_OBJECTS]
};

/// Bitmap for sync object allocation
static mut SYNC_OBJECT_BITMAP: [u64; 2] = [0; 2]; // 128 bits

/// Sync object handle base (0x1000+)
const SYNC_HANDLE_BASE: usize = 0x1000;

/// Allocate a sync object from the pool
unsafe fn alloc_sync_object(obj_type: SyncObjectType) -> Option<usize> {
    for word_idx in 0..2 {
        if SYNC_OBJECT_BITMAP[word_idx] != u64::MAX {
            for bit_idx in 0..64 {
                let global_idx = word_idx * 64 + bit_idx;
                if global_idx >= MAX_SYNC_OBJECTS {
                    return None;
                }
                if SYNC_OBJECT_BITMAP[word_idx] & (1 << bit_idx) == 0 {
                    SYNC_OBJECT_BITMAP[word_idx] |= 1 << bit_idx;
                    SYNC_OBJECT_POOL[global_idx].obj_type = obj_type;
                    return Some(global_idx + SYNC_HANDLE_BASE);
                }
            }
        }
    }
    None
}

/// Get sync object from handle
unsafe fn get_sync_object(handle: usize) -> Option<(*mut SyncObjectEntry, SyncObjectType)> {
    if handle < SYNC_HANDLE_BASE {
        return None;
    }
    let idx = handle - SYNC_HANDLE_BASE;
    if idx >= MAX_SYNC_OBJECTS {
        return None;
    }
    let word_idx = idx / 64;
    let bit_idx = idx % 64;
    if SYNC_OBJECT_BITMAP[word_idx] & (1 << bit_idx) == 0 {
        return None;
    }
    let entry = &mut SYNC_OBJECT_POOL[idx];
    Some((entry as *mut SyncObjectEntry, entry.obj_type))
}

/// Free a sync object
unsafe fn free_sync_object(handle: usize) {
    if handle >= SYNC_HANDLE_BASE {
        let idx = handle - SYNC_HANDLE_BASE;
        if idx < MAX_SYNC_OBJECTS {
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            SYNC_OBJECT_BITMAP[word_idx] &= !(1 << bit_idx);
            SYNC_OBJECT_POOL[idx].obj_type = SyncObjectType::None;
        }
    }
}

/// NtCreateEvent - Create a new event object
fn sys_create_event(
    event_handle: usize,
    _desired_access: usize,
    _object_attributes: usize,
    event_type: usize,
    initial_state: usize,
    _: usize,
) -> isize {
    if event_handle == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // Allocate event from pool
    let handle = match unsafe { alloc_sync_object(SyncObjectType::Event) } {
        Some(h) => h,
        None => return -1, // STATUS_INSUFFICIENT_RESOURCES
    };

    // Initialize the event
    unsafe {
        let (entry, _) = get_sync_object(handle).unwrap();
        let event = &mut *core::ptr::addr_of_mut!((*entry).data.event);

        // event_type: 0 = NotificationEvent, 1 = SynchronizationEvent
        let ke_event_type = if event_type == 0 {
            crate::ke::EventType::Notification
        } else {
            crate::ke::EventType::Synchronization
        };

        event.init(ke_event_type, initial_state != 0);

        *(event_handle as *mut usize) = handle;
    }

    crate::serial_println!("[SYSCALL] NtCreateEvent(type={}, init={}) -> handle {:#x}",
        event_type, initial_state, handle);

    0 // STATUS_SUCCESS
}

/// NtReleaseSemaphore - Release a semaphore
fn sys_release_semaphore(
    handle: usize,
    release_count: usize,
    previous_count: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(handle) } {
        if obj_type != SyncObjectType::Semaphore {
            return -1; // Wrong object type
        }

        let prev = unsafe {
            let sem = &mut *core::ptr::addr_of_mut!((*entry).data.semaphore);
            sem.release(release_count as i32)
        };

        if previous_count != 0 {
            unsafe { *(previous_count as *mut i32) = prev; }
        }

        return 0;
    }

    // Fall back to object manager handles
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
        if obj.is_null() {
            return -1;
        }
        obj
    };

    let prev = unsafe {
        let sem = object as *mut crate::ke::KSemaphore;
        (*sem).release(release_count as i32)
    };

    if previous_count != 0 {
        unsafe { *(previous_count as *mut i32) = prev; }
    }

    unsafe { crate::ob::ob_dereference_object(object); }

    0
}

/// NtCreateSemaphore - Create a semaphore object
fn sys_create_semaphore(
    semaphore_handle: usize,
    _desired_access: usize,
    _object_attributes: usize,
    initial_count: usize,
    maximum_count: usize,
    _: usize,
) -> isize {
    if semaphore_handle == 0 {
        return -1;
    }

    // Allocate semaphore from pool
    let handle = match unsafe { alloc_sync_object(SyncObjectType::Semaphore) } {
        Some(h) => h,
        None => return -1,
    };

    // Initialize the semaphore
    unsafe {
        let (entry, _) = get_sync_object(handle).unwrap();
        let sem = &mut *core::ptr::addr_of_mut!((*entry).data.semaphore);

        *sem = core::mem::ManuallyDrop::new(crate::ke::KSemaphore::new());
        sem.init(initial_count as i32, maximum_count as i32);

        *(semaphore_handle as *mut usize) = handle;
    }

    crate::serial_println!("[SYSCALL] NtCreateSemaphore(init={}, max={}) -> handle {:#x}",
        initial_count, maximum_count, handle);

    0
}

/// NtReleaseMutant - Release a mutex (mutant in NT terminology)
fn sys_release_mutant(
    handle: usize,
    previous_count: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(handle) } {
        if obj_type != SyncObjectType::Mutex {
            return -1;
        }

        let prev = unsafe {
            let mutex = &mut *core::ptr::addr_of_mut!((*entry).data.mutex);
            let was_owned = mutex.is_owned();
            mutex.release();
            was_owned as i32
        };

        if previous_count != 0 {
            unsafe { *(previous_count as *mut i32) = prev; }
        }

        return 0;
    }

    // Fall back to object manager handles
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
        if obj.is_null() {
            return -1;
        }
        obj
    };

    let prev = unsafe {
        let mutex = object as *mut crate::ke::KMutex;
        let was_owned = (*mutex).is_owned();
        (*mutex).release();
        was_owned as i32
    };

    if previous_count != 0 {
        unsafe { *(previous_count as *mut i32) = prev; }
    }

    unsafe { crate::ob::ob_dereference_object(object); }

    0
}

/// NtCreateMutant - Create a mutex object
fn sys_create_mutant(
    mutant_handle: usize,
    _desired_access: usize,
    _object_attributes: usize,
    initial_owner: usize,
    _: usize, _: usize,
) -> isize {
    if mutant_handle == 0 {
        return -1;
    }

    // Allocate mutex from pool
    let handle = match unsafe { alloc_sync_object(SyncObjectType::Mutex) } {
        Some(h) => h,
        None => return -1,
    };

    // Initialize the mutex
    unsafe {
        let (entry, _) = get_sync_object(handle).unwrap();
        let mutex = &mut *core::ptr::addr_of_mut!((*entry).data.mutex);

        *mutex = core::mem::ManuallyDrop::new(crate::ke::KMutex::new());
        mutex.init();

        // If initial_owner is true, acquire the mutex
        if initial_owner != 0 {
            mutex.acquire();
        }

        *(mutant_handle as *mut usize) = handle;
    }

    crate::serial_println!("[SYSCALL] NtCreateMutant(initial_owner={}) -> handle {:#x}",
        initial_owner, handle);

    0
}

// ============================================================================
// Memory Management Syscalls
// ============================================================================

/// NtAllocateVirtualMemory - Allocate virtual memory
fn sys_allocate_virtual_memory(
    _process_handle: usize,
    base_address: usize,
    _zero_bits: usize,
    region_size: usize,
    allocation_type: usize,
    protect: usize,
) -> isize {
    if base_address == 0 || region_size == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // Read the requested base address and size
    let requested_base = unsafe { *(base_address as *const usize) };
    let requested_size = unsafe { *(region_size as *const usize) };

    // Get the system address space (for now, we use system aspace)
    let aspace = unsafe { crate::mm::mm_get_system_address_space() };

    // Allocate virtual memory
    let result = unsafe {
        crate::mm::mm_allocate_virtual_memory(
            aspace,
            if requested_base == 0 { None } else { Some(requested_base as u64) },
            requested_size as u64,
            allocation_type as u32,
            protect as u32,
        )
    };

    match result {
        Some(actual_base) => {
            unsafe {
                *(base_address as *mut usize) = actual_base as usize;
                // Region size is page-aligned by the allocator
            }
            0 // STATUS_SUCCESS
        }
        None => -1, // STATUS_NO_MEMORY
    }
}

/// NtFreeVirtualMemory - Free virtual memory
fn sys_free_virtual_memory(
    _process_handle: usize,
    base_address: usize,
    region_size: usize,
    free_type: usize,
    _: usize, _: usize,
) -> isize {
    if base_address == 0 || region_size == 0 {
        return -1;
    }

    let addr = unsafe { *(base_address as *const usize) };
    let size = unsafe { *(region_size as *const usize) };

    // Get the system address space
    let aspace = unsafe { crate::mm::mm_get_system_address_space() };

    let result = unsafe {
        crate::mm::mm_free_virtual_memory(aspace, addr as u64, size as u64, free_type as u32)
    };

    if result { 0 } else { -1 }
}

/// NtProtectVirtualMemory - Change memory protection
fn sys_protect_virtual_memory(
    process_handle: usize,
    base_address: usize,
    region_size: usize,
    new_protect: usize,
    old_protect: usize,
    _: usize,
) -> isize {
    let _ = process_handle;

    if base_address == 0 || region_size == 0 || old_protect == 0 {
        return -1;
    }

    let addr = unsafe { *(base_address as *const usize) };
    let size = unsafe { *(region_size as *const usize) };

    let result = unsafe {
        crate::mm::mm_protect_virtual_memory(addr, size, new_protect as u32)
    };

    match result {
        Ok(old) => {
            unsafe {
                *(old_protect as *mut u32) = old;
            }
            0
        }
        Err(_) => -1,
    }
}

/// NtQueryVirtualMemory - Query information about virtual memory
fn sys_query_virtual_memory(
    _process_handle: usize,
    base_address: usize,
    _info_class: usize,
    buffer: usize,
    buffer_size: usize,
    return_length: usize,
) -> isize {
    if buffer == 0 || buffer_size < core::mem::size_of::<crate::mm::MmMemoryInfo>() {
        return -1;
    }

    // Get the system address space
    let aspace = unsafe { crate::mm::mm_get_system_address_space() };

    let result = unsafe {
        crate::mm::mm_query_virtual_memory(aspace, base_address as u64)
    };

    match result {
        Some(info) => {
            // Copy result to user buffer
            unsafe {
                *(buffer as *mut crate::mm::MmMemoryInfo) = info;
            }
            if return_length != 0 {
                unsafe {
                    *(return_length as *mut usize) = core::mem::size_of::<crate::mm::MmMemoryInfo>();
                }
            }
            0
        }
        None => -1,
    }
}

// ============================================================================
// Section Object Syscalls
// ============================================================================

/// NtCreateSection - Create a section object (shared memory)
fn sys_create_section(
    section_handle: usize,
    _desired_access: usize,
    _object_attributes: usize,
    maximum_size: usize,
    section_page_protection: usize,
    allocation_attributes: usize,
) -> isize {
    if section_handle == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // Get size from pointer (NT style)
    let size = if maximum_size != 0 {
        unsafe { *(maximum_size as *const u64) }
    } else {
        4096 // Default to one page
    };

    let _ = allocation_attributes; // For file-backed sections

    // Create page-file backed section
    let section = unsafe {
        crate::mm::mm_create_section(size, section_page_protection as u32)
    };

    if section.is_null() {
        return -1; // STATUS_INSUFFICIENT_RESOURCES
    }

    // Return section handle (pointer as handle for now)
    unsafe {
        *(section_handle as *mut usize) = section as usize;
    }

    0 // STATUS_SUCCESS
}

/// NtMapViewOfSection - Map a view of a section into an address space
fn sys_map_view_of_section(
    section_handle: usize,
    _process_handle: usize,
    base_address: usize,
    _zero_bits: usize,
    _commit_size: usize,
    section_offset: usize,
) -> isize {
    // Additional parameters would be in stack (view_size, protection, etc.)
    // For simplicity, we use defaults

    if section_handle == 0 || base_address == 0 {
        return -1;
    }

    let section = section_handle as *mut crate::mm::Section;

    // Read requested base and offset
    let requested_base = unsafe { *(base_address as *const u64) };
    let offset = if section_offset != 0 {
        unsafe { *(section_offset as *const u64) }
    } else {
        0
    };

    // Map the view
    let result = unsafe {
        crate::mm::mm_map_view_of_section(
            section,
            core::ptr::null_mut(), // Current process
            if requested_base == 0 { None } else { Some(requested_base) },
            offset,
            0, // Map entire section
            crate::mm::page_protection::PAGE_READWRITE,
        )
    };

    match result {
        Some(mapped_base) => {
            unsafe {
                *(base_address as *mut u64) = mapped_base;
            }
            0
        }
        None => -1,
    }
}

/// NtUnmapViewOfSection - Unmap a view of a section
fn sys_unmap_view_of_section(
    _process_handle: usize,
    base_address: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    if base_address == 0 {
        return -1;
    }

    // We need to find the section for this base address
    // For now, this is a stub - full implementation would track views
    crate::serial_println!("[SYSCALL] NtUnmapViewOfSection - stub at {:#x}", base_address);

    0
}

/// NtQuerySection - Query section information
fn sys_query_section(
    section_handle: usize,
    _info_class: usize,
    buffer: usize,
    buffer_size: usize,
    return_length: usize,
    _: usize,
) -> isize {
    if section_handle == 0 || buffer == 0 {
        return -1;
    }

    if buffer_size < core::mem::size_of::<crate::mm::SectionInfo>() {
        return -1; // STATUS_BUFFER_TOO_SMALL
    }

    let section = section_handle as *mut crate::mm::Section;

    let result = unsafe { crate::mm::mm_query_section(section) };

    match result {
        Some(info) => {
            unsafe {
                *(buffer as *mut crate::mm::SectionInfo) = info;
            }
            if return_length != 0 {
                unsafe {
                    *(return_length as *mut usize) = core::mem::size_of::<crate::mm::SectionInfo>();
                }
            }
            0
        }
        None => -1,
    }
}

// ============================================================================
// I/O Completion Port Syscalls
// ============================================================================

/// NtCreateIoCompletion - Create an I/O completion port
fn sys_create_io_completion(
    completion_handle: usize,
    _desired_access: usize,
    _object_attributes: usize,
    concurrent_threads: usize,
    _: usize, _: usize,
) -> isize {
    if completion_handle == 0 {
        return -1;
    }

    let port = unsafe {
        crate::io::io_create_completion_port(concurrent_threads as u32)
    };

    if port.is_null() {
        return -1; // STATUS_INSUFFICIENT_RESOURCES
    }

    unsafe {
        *(completion_handle as *mut usize) = port as usize;
    }

    0
}

/// NtSetIoCompletion - Post a completion to a port
fn sys_set_io_completion(
    completion_handle: usize,
    key: usize,
    overlapped: usize,
    status: usize,
    information: usize,
    _: usize,
) -> isize {
    if completion_handle == 0 {
        return -1;
    }

    let port = completion_handle as *mut crate::io::IoCompletionPort;

    let result = unsafe {
        crate::io::io_set_completion(port, key, overlapped, status as i32, information)
    };

    if result { 0 } else { -1 }
}

/// NtRemoveIoCompletion - Wait for and retrieve a completion
fn sys_remove_io_completion(
    completion_handle: usize,
    key_out: usize,
    overlapped_out: usize,
    io_status_out: usize,
    timeout: usize,
    _: usize,
) -> isize {
    if completion_handle == 0 {
        return -1;
    }

    let port = completion_handle as *mut crate::io::IoCompletionPort;

    // Get timeout value
    let timeout_ms = if timeout == 0 {
        None
    } else {
        let timeout_100ns = unsafe { *(timeout as *const i64) };
        if timeout_100ns < 0 {
            Some(((-timeout_100ns) / 10_000) as u64)
        } else {
            Some(0)
        }
    };

    let result = unsafe { crate::io::io_remove_completion(port, timeout_ms) };

    match result {
        Some(packet) => {
            if key_out != 0 {
                unsafe { *(key_out as *mut usize) = packet.key; }
            }
            if overlapped_out != 0 {
                unsafe { *(overlapped_out as *mut usize) = packet.overlapped; }
            }
            if io_status_out != 0 {
                unsafe {
                    let status_block = io_status_out as *mut crate::io::IoStatusBlock;
                    (*status_block).status = packet.status;
                    (*status_block).information = packet.information;
                }
            }
            0
        }
        None => 0x102, // STATUS_TIMEOUT
    }
}

// ============================================================================
// Directory and File Lock Syscalls
// ============================================================================

/// File information returned by NtQueryDirectoryFile
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileDirectoryInformation {
    /// Offset to next entry (0 if last)
    pub next_entry_offset: u32,
    /// File index (for resume)
    pub file_index: u32,
    /// Creation time (100ns since 1601)
    pub creation_time: i64,
    /// Last access time
    pub last_access_time: i64,
    /// Last write time
    pub last_write_time: i64,
    /// Change time
    pub change_time: i64,
    /// End of file position
    pub end_of_file: i64,
    /// Allocation size (on disk)
    pub allocation_size: i64,
    /// File attributes (FILE_ATTRIBUTE_*)
    pub file_attributes: u32,
    /// Length of file name in bytes
    pub file_name_length: u32,
    // file_name follows in memory (variable length, Unicode)
}

/// File attributes for FileDirectoryInformation
pub mod file_attributes {
    pub const READONLY: u32 = 0x0001;
    pub const HIDDEN: u32 = 0x0002;
    pub const SYSTEM: u32 = 0x0004;
    pub const DIRECTORY: u32 = 0x0010;
    pub const ARCHIVE: u32 = 0x0020;
    pub const NORMAL: u32 = 0x0080;
}

/// NtQueryDirectoryFile - Enumerate directory contents
///
/// NT-style directory enumeration. Returns one or more entries per call.
///
/// Arguments:
/// - file_handle: Handle to an open directory
/// - event: Optional event to signal on completion (async)
/// - apc_routine: Optional APC callback
/// - apc_context: Context for APC
/// - io_status_block: Receives completion status
/// - file_information: Output buffer for entries
fn sys_query_directory_file(
    file_handle: usize,
    _event: usize,
    file_information: usize,
    length: usize,
    _return_single_entry: usize,
    file_name_pattern: usize,
) -> isize {
    // Validate parameters
    if file_handle == 0 || file_information == 0 || length == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // For now, use a simplified implementation using our fs module
    // In a full implementation, we'd work with file handles properly

    // Get the file name pattern (optional wildcard like "*.txt")
    let pattern_str: Option<&str> = if file_name_pattern != 0 {
        // Read the pattern - assume it's a null-terminated ASCII string for simplicity
        let pattern_ptr = file_name_pattern as *const u8;
        let mut len = 0;
        unsafe {
            while *pattern_ptr.add(len) != 0 && len < 256 {
                len += 1;
            }
            if len > 0 {
                Some(core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(pattern_ptr, len)
                ))
            } else {
                None
            }
        }
    } else {
        None
    };

    let _ = pattern_str; // TODO: Implement pattern matching

    // For now, just log and return success with empty result
    // A full implementation would enumerate the directory
    crate::serial_println!(
        "[SYSCALL] NtQueryDirectoryFile(handle={}, buf={:#x}, len={})",
        file_handle, file_information, length
    );

    // Return STATUS_NO_MORE_FILES to indicate end of directory
    0x80000006u32 as isize // STATUS_NO_MORE_FILES
}

/// File lock info for NtLockFile
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileLockInfo {
    /// Byte offset to start of lock
    pub byte_offset: i64,
    /// Length of lock in bytes
    pub length: i64,
    /// Key for this lock (used for unlock)
    pub key: u32,
    /// Is this an exclusive lock?
    pub exclusive: bool,
    /// Fail immediately if can't lock?
    pub fail_immediately: bool,
}

/// NtLockFile - Lock a byte range in a file
///
/// Provides byte-range locking for file coordination between processes.
///
/// Arguments:
/// - file_handle: Handle to the file
/// - event: Optional event for async completion
/// - apc_routine: Optional APC callback
/// - apc_context: Context for APC
/// - io_status_block: Receives status
/// - byte_offset: Starting offset of lock (LARGE_INTEGER pointer)
fn sys_lock_file(
    file_handle: usize,
    _event: usize,
    byte_offset: usize,
    length: usize,
    key: usize,
    fail_immediately: usize,
) -> isize {
    // Validate parameters
    if file_handle == 0 || byte_offset == 0 || length == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // Read the byte offset and length (passed as LARGE_INTEGER pointers)
    let offset = unsafe { *(byte_offset as *const i64) };
    let len = unsafe { *(length as *const i64) };

    crate::serial_println!(
        "[SYSCALL] NtLockFile(handle={}, offset={}, len={}, key={}, fail_immed={})",
        file_handle, offset, len, key, fail_immediately != 0
    );

    // For now, just record the lock request
    // A full implementation would:
    // 1. Check for conflicting locks
    // 2. Either wait or fail immediately based on fail_immediately
    // 3. Add lock to the file's lock list

    // Track locks per file (simplified - in reality this would be per file object)
    // For now, just succeed
    0 // STATUS_SUCCESS
}

/// NtUnlockFile - Unlock a byte range in a file
///
/// Arguments:
/// - file_handle: Handle to the file
/// - io_status_block: Receives status
/// - byte_offset: Starting offset of region to unlock
/// - length: Length of region to unlock
/// - key: Key that was used when locking
fn sys_unlock_file(
    file_handle: usize,
    byte_offset: usize,
    length: usize,
    key: usize,
    _: usize, _: usize,
) -> isize {
    if file_handle == 0 || byte_offset == 0 || length == 0 {
        return -1;
    }

    let offset = unsafe { *(byte_offset as *const i64) };
    let len = unsafe { *(length as *const i64) };

    crate::serial_println!(
        "[SYSCALL] NtUnlockFile(handle={}, offset={}, len={}, key={})",
        file_handle, offset, len, key
    );

    // For now, just succeed
    0 // STATUS_SUCCESS
}

// ============================================================================
// Registry Syscalls
// ============================================================================

/// Registry key handle table
/// Maps syscall handles to CM key handles
const MAX_KEY_HANDLES: usize = 128;
const KEY_HANDLE_BASE: usize = 0x2000;

/// Key handle entries
static mut KEY_HANDLE_MAP: [u32; MAX_KEY_HANDLES] = [u32::MAX; MAX_KEY_HANDLES];

/// Allocate a registry key handle
unsafe fn alloc_key_handle(cm_handle: crate::cm::CmKeyHandle) -> Option<usize> {
    for i in 0..MAX_KEY_HANDLES {
        if KEY_HANDLE_MAP[i] == u32::MAX {
            KEY_HANDLE_MAP[i] = cm_handle.index();
            return Some(i + KEY_HANDLE_BASE);
        }
    }
    None
}

/// Get CM key handle from syscall handle
unsafe fn get_cm_key_handle(syscall_handle: usize) -> Option<crate::cm::CmKeyHandle> {
    if syscall_handle < KEY_HANDLE_BASE {
        return None;
    }
    let idx = syscall_handle - KEY_HANDLE_BASE;
    if idx >= MAX_KEY_HANDLES {
        return None;
    }
    let cm_idx = KEY_HANDLE_MAP[idx];
    if cm_idx == u32::MAX {
        None
    } else {
        Some(crate::cm::CmKeyHandle::new(cm_idx))
    }
}

/// Free a registry key handle
unsafe fn free_key_handle(syscall_handle: usize) {
    if syscall_handle >= KEY_HANDLE_BASE {
        let idx = syscall_handle - KEY_HANDLE_BASE;
        if idx < MAX_KEY_HANDLES {
            KEY_HANDLE_MAP[idx] = u32::MAX;
        }
    }
}

/// NtCreateKey - Create or open a registry key
///
/// Arguments:
/// - key_handle: Pointer to receive handle
/// - desired_access: Access mask
/// - object_attributes: Pointer to path string (simplified)
/// - _title_index: Not used
/// - _class: Optional class string
/// - create_options: REG_OPTION_* flags
fn sys_create_key(
    key_handle_ptr: usize,
    _desired_access: usize,
    object_attributes: usize,
    _title_index: usize,
    _class: usize,
    create_options: usize,
) -> isize {
    if key_handle_ptr == 0 || object_attributes == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // Read path from object_attributes (simplified - assume it's a path string)
    let path_result = unsafe { read_user_path(object_attributes, 260) };

    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return -1,
    };

    let path_str = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    crate::serial_println!("[SYSCALL] NtCreateKey(path='{}')", path_str);

    // Create or open the key
    let result = unsafe {
        crate::cm::cm_create_key(path_str, create_options as u32)
    };

    match result {
        Ok((cm_handle, disposition)) => {
            // Allocate syscall handle
            let syscall_handle = unsafe { alloc_key_handle(cm_handle) };
            match syscall_handle {
                Some(h) => {
                    unsafe {
                        *(key_handle_ptr as *mut usize) = h;
                    }
                    // Return disposition in high word
                    let disp_value = match disposition {
                        crate::cm::CmDisposition::CreatedNew => 1,
                        crate::cm::CmDisposition::OpenedExisting => 2,
                    };
                    crate::serial_println!("[SYSCALL] NtCreateKey -> handle {:#x}, disposition {}",
                        h, disp_value);
                    0 // STATUS_SUCCESS
                }
                None => {
                    let _ = crate::cm::cm_close_key(cm_handle);
                    -1 // STATUS_INSUFFICIENT_RESOURCES
                }
            }
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtCreateKey failed: {:?}", e);
            e as isize
        }
    }
}

/// NtOpenKey - Open an existing registry key
fn sys_open_key(
    key_handle_ptr: usize,
    _desired_access: usize,
    object_attributes: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    if key_handle_ptr == 0 || object_attributes == 0 {
        return -1;
    }

    let path_result = unsafe { read_user_path(object_attributes, 260) };

    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return -1,
    };

    let path_str = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    crate::serial_println!("[SYSCALL] NtOpenKey(path='{}')", path_str);

    let result = unsafe { crate::cm::cm_open_key(path_str) };

    match result {
        Ok(cm_handle) => {
            let syscall_handle = unsafe { alloc_key_handle(cm_handle) };
            match syscall_handle {
                Some(h) => {
                    unsafe { *(key_handle_ptr as *mut usize) = h; }
                    crate::serial_println!("[SYSCALL] NtOpenKey -> handle {:#x}", h);
                    0
                }
                None => {
                    let _ = crate::cm::cm_close_key(cm_handle);
                    -1
                }
            }
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtOpenKey failed: {:?}", e);
            e as isize
        }
    }
}

/// NtCloseKey - Close a registry key handle
fn sys_close_key(
    key_handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtCloseKey(handle={:#x})", key_handle);

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return -1, // STATUS_INVALID_HANDLE
    };

    let _ = crate::cm::cm_close_key(cm_handle);
    unsafe { free_key_handle(key_handle); }

    0 // STATUS_SUCCESS
}

/// Key value information class
pub mod key_value_info_class {
    pub const KEY_VALUE_BASIC_INFORMATION: u32 = 0;
    pub const KEY_VALUE_FULL_INFORMATION: u32 = 1;
    pub const KEY_VALUE_PARTIAL_INFORMATION: u32 = 2;
}

/// KEY_VALUE_PARTIAL_INFORMATION structure
#[repr(C)]
pub struct KeyValuePartialInformation {
    pub title_index: u32,
    pub value_type: u32,
    pub data_length: u32,
    // data follows
}

/// NtQueryValueKey - Query a registry value
fn sys_query_value_key(
    key_handle: usize,
    value_name_ptr: usize,
    key_value_info_class: usize,
    key_value_info: usize,
    length: usize,
    result_length: usize,
) -> isize {
    if key_handle == 0 || value_name_ptr == 0 || key_value_info == 0 {
        return -1;
    }

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return -1,
    };

    // Read value name
    let name_result = unsafe { read_user_path(value_name_ptr, 260) };
    let (name_buf, name_len) = match name_result {
        Some((buf, len)) => (buf, len),
        None => return -1,
    };

    let value_name = match core::str::from_utf8(&name_buf[..name_len]) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    crate::serial_println!("[SYSCALL] NtQueryValueKey(handle={:#x}, name='{}')",
        key_handle, value_name);

    // Query the value
    let result = unsafe { crate::cm::cm_query_value(cm_handle, value_name) };

    match result {
        Ok(value) => {
            // Return partial information (most common)
            let reg_type = value.value_type as u32;
            let data = value.data.as_bytes();
            let data_len = data.len();

            // Calculate required size
            let required = core::mem::size_of::<KeyValuePartialInformation>() + data_len;

            if result_length != 0 {
                unsafe { *(result_length as *mut usize) = required; }
            }

            if length < required {
                return 0x80000005u32 as isize; // STATUS_BUFFER_OVERFLOW
            }

            // Fill in the structure
            unsafe {
                let info = key_value_info as *mut KeyValuePartialInformation;
                (*info).title_index = 0;
                (*info).value_type = reg_type;
                (*info).data_length = data_len as u32;

                // Copy data after the structure
                let data_ptr = (key_value_info + core::mem::size_of::<KeyValuePartialInformation>()) as *mut u8;
                core::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data_len);
            }

            crate::serial_println!("[SYSCALL] NtQueryValueKey -> type={}, len={}", reg_type, data_len);
            0
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtQueryValueKey failed: {:?}", e);
            e as isize
        }
    }
}

/// NtSetValueKey - Set a registry value
fn sys_set_value_key(
    key_handle: usize,
    value_name_ptr: usize,
    _title_index: usize,
    value_type: usize,
    data_ptr: usize,
    data_size: usize,
) -> isize {
    if key_handle == 0 || value_name_ptr == 0 {
        return -1;
    }

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return -1,
    };

    // Read value name
    let name_result = unsafe { read_user_path(value_name_ptr, 260) };
    let (name_buf, name_len) = match name_result {
        Some((buf, len)) => (buf, len),
        None => return -1,
    };

    let value_name = match core::str::from_utf8(&name_buf[..name_len]) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    crate::serial_println!("[SYSCALL] NtSetValueKey(handle={:#x}, name='{}', type={}, size={})",
        key_handle, value_name, value_type, data_size);

    // Create the value based on type
    let reg_type = crate::cm::RegType::from_u32(value_type as u32)
        .unwrap_or(crate::cm::RegType::Binary);

    let result = match reg_type {
        crate::cm::RegType::Dword if data_size >= 4 => {
            let dword_val = unsafe { *(data_ptr as *const u32) };
            unsafe { crate::cm::cm_set_value_dword(cm_handle, value_name, dword_val) }
        }
        crate::cm::RegType::Qword if data_size >= 8 => {
            let qword_val = unsafe { *(data_ptr as *const u64) };
            unsafe { crate::cm::cm_set_value_qword(cm_handle, value_name, qword_val) }
        }
        crate::cm::RegType::Sz | crate::cm::RegType::ExpandSz => {
            // Read string data
            if data_ptr != 0 && data_size > 0 {
                let str_slice = unsafe {
                    core::slice::from_raw_parts(data_ptr as *const u8, data_size)
                };
                // Find null terminator or use full length
                let str_len = str_slice.iter().position(|&b| b == 0).unwrap_or(data_size);
                if let Ok(s) = core::str::from_utf8(&str_slice[..str_len]) {
                    unsafe { crate::cm::cm_set_value_string(cm_handle, value_name, s) }
                } else {
                    crate::cm::CmStatus::InvalidParameter
                }
            } else {
                unsafe { crate::cm::cm_set_value_string(cm_handle, value_name, "") }
            }
        }
        _ => {
            // Binary or other type - create binary value
            let value = if data_ptr != 0 && data_size > 0 {
                let data_slice = unsafe {
                    core::slice::from_raw_parts(data_ptr as *const u8, data_size.min(256))
                };
                crate::cm::CmKeyValue::new_binary(value_name, data_slice)
            } else {
                crate::cm::CmKeyValue::new_binary(value_name, &[])
            };
            unsafe { crate::cm::cm_set_value(cm_handle, value) }
        }
    };

    if result.is_success() {
        crate::serial_println!("[SYSCALL] NtSetValueKey -> success");
        0
    } else {
        crate::serial_println!("[SYSCALL] NtSetValueKey failed: {:?}", result);
        result as isize
    }
}

/// NtDeleteKey - Delete a registry key
fn sys_delete_key(
    key_handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtDeleteKey(handle={:#x})", key_handle);

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return -1,
    };

    // Get key name for deletion (we need the path)
    let key_name = unsafe { crate::cm::cm_get_key_name(cm_handle) };

    // For now, just mark the key as deleted
    // A full implementation would walk back to get the full path
    crate::serial_println!("[SYSCALL] NtDeleteKey - key name: {:?}", key_name);

    // Close and free the handle
    let _ = crate::cm::cm_close_key(cm_handle);
    unsafe { free_key_handle(key_handle); }

    0 // STATUS_SUCCESS (simplified)
}

/// NtDeleteValueKey - Delete a registry value
fn sys_delete_value_key(
    key_handle: usize,
    value_name_ptr: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    if key_handle == 0 || value_name_ptr == 0 {
        return -1;
    }

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return -1,
    };

    // Read value name
    let name_result = unsafe { read_user_path(value_name_ptr, 260) };
    let (name_buf, name_len) = match name_result {
        Some((buf, len)) => (buf, len),
        None => return -1,
    };

    let value_name = match core::str::from_utf8(&name_buf[..name_len]) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    crate::serial_println!("[SYSCALL] NtDeleteValueKey(handle={:#x}, name='{}')",
        key_handle, value_name);

    let result = unsafe { crate::cm::cm_delete_value(cm_handle, value_name) };

    if result.is_success() {
        0
    } else {
        result as isize
    }
}

/// Key information class for NtEnumerateKey
pub mod key_info_class {
    pub const KEY_BASIC_INFORMATION: u32 = 0;
    pub const KEY_NODE_INFORMATION: u32 = 1;
    pub const KEY_FULL_INFORMATION: u32 = 2;
    pub const KEY_NAME_INFORMATION: u32 = 3;
}

/// KEY_BASIC_INFORMATION structure
#[repr(C)]
pub struct KeyBasicInformation {
    pub last_write_time: i64,
    pub title_index: u32,
    pub name_length: u32,
    // name follows (Unicode)
}

/// NtEnumerateKey - Enumerate subkeys
fn sys_enumerate_key(
    key_handle: usize,
    index: usize,
    key_info_class: usize,
    key_info: usize,
    length: usize,
    result_length: usize,
) -> isize {
    if key_handle == 0 || key_info == 0 {
        return -1;
    }

    let _ = key_info_class; // Simplified - always return basic info

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtEnumerateKey(handle={:#x}, index={})",
        key_handle, index);

    let result = unsafe { crate::cm::cm_enumerate_key(cm_handle, index) };

    match result {
        Ok(subkey_handle) => {
            // Get the subkey name
            let name = unsafe { crate::cm::cm_get_key_name(subkey_handle) };
            let name_str = name.unwrap_or("");
            let name_bytes = name_str.as_bytes();
            let name_len = name_bytes.len();

            // Calculate required size
            let required = core::mem::size_of::<KeyBasicInformation>() + name_len;

            if result_length != 0 {
                unsafe { *(result_length as *mut usize) = required; }
            }

            if length < required {
                return 0x80000005u32 as isize; // STATUS_BUFFER_OVERFLOW
            }

            // Fill in the structure
            unsafe {
                let info = key_info as *mut KeyBasicInformation;
                (*info).last_write_time = 0; // TODO: Get from key
                (*info).title_index = 0;
                (*info).name_length = name_len as u32;

                // Copy name after the structure
                let name_ptr = (key_info + core::mem::size_of::<KeyBasicInformation>()) as *mut u8;
                core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_ptr, name_len);
            }

            crate::serial_println!("[SYSCALL] NtEnumerateKey -> '{}'", name_str);
            0
        }
        Err(crate::cm::CmStatus::NoMoreEntries) => {
            0x8000001A_u32 as isize // STATUS_NO_MORE_ENTRIES
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtEnumerateKey failed: {:?}", e);
            e as isize
        }
    }
}

/// KEY_VALUE_BASIC_INFORMATION structure
#[repr(C)]
pub struct KeyValueBasicInformation {
    pub title_index: u32,
    pub value_type: u32,
    pub name_length: u32,
    // name follows
}

/// NtEnumerateValueKey - Enumerate values
fn sys_enumerate_value_key(
    key_handle: usize,
    index: usize,
    key_value_info_class: usize,
    key_value_info: usize,
    length: usize,
    result_length: usize,
) -> isize {
    if key_handle == 0 || key_value_info == 0 {
        return -1;
    }

    let _ = key_value_info_class; // Simplified

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtEnumerateValueKey(handle={:#x}, index={})",
        key_handle, index);

    let result = unsafe { crate::cm::cm_enumerate_value(cm_handle, index) };

    match result {
        Ok(value) => {
            let name_str = value.name.as_str();
            let name_bytes = name_str.as_bytes();
            let name_len = name_bytes.len();

            // Calculate required size
            let required = core::mem::size_of::<KeyValueBasicInformation>() + name_len;

            if result_length != 0 {
                unsafe { *(result_length as *mut usize) = required; }
            }

            if length < required {
                return 0x80000005u32 as isize; // STATUS_BUFFER_OVERFLOW
            }

            // Fill in the structure
            unsafe {
                let info = key_value_info as *mut KeyValueBasicInformation;
                (*info).title_index = 0;
                (*info).value_type = value.value_type as u32;
                (*info).name_length = name_len as u32;

                // Copy name after the structure
                let name_ptr = (key_value_info + core::mem::size_of::<KeyValueBasicInformation>()) as *mut u8;
                core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_ptr, name_len);
            }

            crate::serial_println!("[SYSCALL] NtEnumerateValueKey -> '{}'", name_str);
            0
        }
        Err(crate::cm::CmStatus::NoMoreEntries) => {
            0x8000001A_u32 as isize // STATUS_NO_MORE_ENTRIES
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtEnumerateValueKey failed: {:?}", e);
            e as isize
        }
    }
}

/// KEY_FULL_INFORMATION structure
#[repr(C)]
pub struct KeyFullInformation {
    pub last_write_time: i64,
    pub title_index: u32,
    pub class_offset: u32,
    pub class_length: u32,
    pub sub_keys: u32,
    pub max_name_len: u32,
    pub max_class_len: u32,
    pub values: u32,
    pub max_value_name_len: u32,
    pub max_value_data_len: u32,
    // class follows
}

/// NtQueryKey - Query key information
fn sys_query_key(
    key_handle: usize,
    key_info_class: usize,
    key_info: usize,
    length: usize,
    result_length: usize,
    _: usize,
) -> isize {
    if key_handle == 0 || key_info == 0 {
        return -1;
    }

    let _ = key_info_class; // Simplified - return full info

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtQueryKey(handle={:#x})", key_handle);

    let result = unsafe { crate::cm::cm_query_key_info(cm_handle) };

    match result {
        Ok(info) => {
            let required = core::mem::size_of::<KeyFullInformation>();

            if result_length != 0 {
                unsafe { *(result_length as *mut usize) = required; }
            }

            if length < required {
                return 0x80000005u32 as isize; // STATUS_BUFFER_OVERFLOW
            }

            unsafe {
                let key_full_info = key_info as *mut KeyFullInformation;
                (*key_full_info).last_write_time = info.last_write_time as i64;
                (*key_full_info).title_index = 0;
                (*key_full_info).class_offset = 0;
                (*key_full_info).class_length = 0;
                (*key_full_info).sub_keys = info.subkey_count as u32;
                (*key_full_info).max_name_len = 256;
                (*key_full_info).max_class_len = 0;
                (*key_full_info).values = info.value_count as u32;
                (*key_full_info).max_value_name_len = 256;
                (*key_full_info).max_value_data_len = 4096;
            }

            crate::serial_println!("[SYSCALL] NtQueryKey -> subkeys={}, values={}",
                info.subkey_count, info.value_count);
            0
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtQueryKey failed: {:?}", e);
            e as isize
        }
    }
}

// ============================================================================
// LPC (Local Procedure Call) Syscalls
// ============================================================================

/// LPC port handle table
const MAX_LPC_HANDLES: usize = 64;
const LPC_HANDLE_BASE: usize = 0x3000;

/// LPC handle entries (maps to lpc port index)
static mut LPC_HANDLE_MAP: [u16; MAX_LPC_HANDLES] = [0xFFFF; MAX_LPC_HANDLES];

/// Allocate an LPC handle
unsafe fn alloc_lpc_handle(port_index: u16) -> Option<usize> {
    for i in 0..MAX_LPC_HANDLES {
        if LPC_HANDLE_MAP[i] == 0xFFFF {
            LPC_HANDLE_MAP[i] = port_index;
            return Some(i + LPC_HANDLE_BASE);
        }
    }
    None
}

/// Get LPC port index from handle
unsafe fn get_lpc_port(handle: usize) -> Option<u16> {
    if handle < LPC_HANDLE_BASE {
        return None;
    }
    let idx = handle - LPC_HANDLE_BASE;
    if idx >= MAX_LPC_HANDLES {
        return None;
    }
    let port_idx = LPC_HANDLE_MAP[idx];
    if port_idx == 0xFFFF {
        None
    } else {
        Some(port_idx)
    }
}

/// Free an LPC handle
unsafe fn free_lpc_handle(handle: usize) {
    if handle >= LPC_HANDLE_BASE {
        let idx = handle - LPC_HANDLE_BASE;
        if idx < MAX_LPC_HANDLES {
            LPC_HANDLE_MAP[idx] = 0xFFFF;
        }
    }
}

/// NtCreatePort - Create an LPC server port
fn sys_create_port(
    port_handle_ptr: usize,
    object_attributes: usize,
    max_connection_info_length: usize,
    max_message_length: usize,
    _max_pool_usage: usize,
    _: usize,
) -> isize {
    if port_handle_ptr == 0 || object_attributes == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // Read port name from object_attributes
    let path_result = unsafe { read_user_path(object_attributes, 260) };
    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return -1,
    };

    let port_name = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let _ = max_connection_info_length;

    crate::serial_println!("[SYSCALL] NtCreatePort(name='{}')", port_name);

    // Create server port
    let port_index = unsafe {
        crate::lpc::lpc_create_port(
            port_name,
            crate::lpc::LpcPortType::ServerConnection,
            max_message_length as u32,
        )
    };

    match port_index {
        Some(idx) => {
            let handle = unsafe { alloc_lpc_handle(idx) };
            match handle {
                Some(h) => {
                    unsafe { *(port_handle_ptr as *mut usize) = h; }
                    crate::serial_println!("[SYSCALL] NtCreatePort -> handle {:#x}", h);
                    0
                }
                None => {
                    unsafe { crate::lpc::lpc_close_port(idx); }
                    -1
                }
            }
        }
        None => -1,
    }
}

/// NtConnectPort - Connect to an LPC server port
fn sys_connect_port(
    port_handle_ptr: usize,
    port_name_ptr: usize,
    _security_qos: usize,
    client_view: usize,
    server_view: usize,
    _max_message_length: usize,
) -> isize {
    if port_handle_ptr == 0 || port_name_ptr == 0 {
        return -1;
    }

    let _ = client_view;
    let _ = server_view;

    let path_result = unsafe { read_user_path(port_name_ptr, 260) };
    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return -1,
    };

    let port_name = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    crate::serial_println!("[SYSCALL] NtConnectPort(name='{}')", port_name);

    // Connect to server port
    let client_port = unsafe { crate::lpc::lpc_connect_port(port_name, &[]) };

    match client_port {
        Some(idx) => {
            let handle = unsafe { alloc_lpc_handle(idx) };
            match handle {
                Some(h) => {
                    unsafe { *(port_handle_ptr as *mut usize) = h; }
                    crate::serial_println!("[SYSCALL] NtConnectPort -> handle {:#x}", h);
                    0
                }
                None => {
                    unsafe { crate::lpc::lpc_close_port(idx); }
                    -1
                }
            }
        }
        None => -1,
    }
}

/// NtListenPort - Wait for a connection request
fn sys_listen_port(
    port_handle: usize,
    connection_request: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    if port_handle == 0 {
        return -1;
    }

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtListenPort(handle={:#x})", port_handle);

    // Listen for pending connections
    let conn = unsafe { crate::lpc::lpc_listen_port(port_idx) };

    match conn {
        Some(c) => {
            // Return connection info if buffer provided
            if connection_request != 0 {
                unsafe {
                    // Write connection info (simplified)
                    *(connection_request as *mut u32) = c.client_port as u32;
                    *((connection_request + 4) as *mut u32) = c.client_pid;
                }
            }
            crate::serial_println!("[SYSCALL] NtListenPort -> connection from port {}", c.client_port);
            0
        }
        None => {
            crate::serial_println!("[SYSCALL] NtListenPort -> no pending connections");
            0x102 // STATUS_TIMEOUT (no pending connections)
        }
    }
}

/// NtAcceptConnectPort - Accept or reject a connection
fn sys_accept_connect_port(
    port_handle_ptr: usize,
    port_context: usize,
    connection_request: usize,
    accept_connection: usize,
    _server_view: usize,
    _client_view: usize,
) -> isize {
    if port_handle_ptr == 0 || connection_request == 0 {
        return -1;
    }

    let _ = port_context;

    // Read client port from connection request
    let client_port = unsafe { *(connection_request as *const u32) as u16 };

    // Get server port (from context or somewhere)
    // For now, we need to find the server port that has this pending connection
    // This is simplified - real NT passes server port handle

    crate::serial_println!("[SYSCALL] NtAcceptConnectPort(client={}, accept={})",
        client_port, accept_connection != 0);

    if accept_connection == 0 {
        // Reject connection
        return 0;
    }

    // Accept connection - create communication port
    // We need the server port index - for simplicity, search for it
    let mut server_idx: Option<u16> = None;
    for i in 0..MAX_LPC_HANDLES {
        unsafe {
            if LPC_HANDLE_MAP[i] != 0xFFFF {
                if let Some(info) = crate::lpc::lpc_get_port_info(LPC_HANDLE_MAP[i]) {
                    if info.port_type == crate::lpc::LpcPortType::ServerConnection
                        && info.pending_connections > 0
                    {
                        server_idx = Some(LPC_HANDLE_MAP[i]);
                        break;
                    }
                }
            }
        }
    }

    let server_port = match server_idx {
        Some(s) => s,
        None => return -1,
    };

    let comm_port = unsafe {
        crate::lpc::lpc_accept_connection(server_port, client_port, true)
    };

    match comm_port {
        Some(idx) => {
            let handle = unsafe { alloc_lpc_handle(idx) };
            match handle {
                Some(h) => {
                    unsafe { *(port_handle_ptr as *mut usize) = h; }
                    crate::serial_println!("[SYSCALL] NtAcceptConnectPort -> handle {:#x}", h);
                    0
                }
                None => {
                    unsafe { crate::lpc::lpc_close_port(idx); }
                    -1
                }
            }
        }
        None => -1,
    }
}

/// NtRequestPort - Send a datagram (no reply expected)
fn sys_request_port(
    port_handle: usize,
    message: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    if port_handle == 0 || message == 0 {
        return -1;
    }

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return -1,
    };

    // Read message data (simplified - assume first 256 bytes)
    let data = unsafe {
        core::slice::from_raw_parts(message as *const u8, 256)
    };

    crate::serial_println!("[SYSCALL] NtRequestPort(handle={:#x})", port_handle);

    let msg = crate::lpc::LpcMessage::datagram(data);
    let result = unsafe { crate::lpc::lpc_send_message(port_idx, &msg) };

    if result.is_some() { 0 } else { -1 }
}

/// NtRequestWaitReplyPort - Send request and wait for reply
fn sys_request_wait_reply_port(
    port_handle: usize,
    message: usize,
    reply_message: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    if port_handle == 0 || message == 0 {
        return -1;
    }

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return -1,
    };

    // Read message data
    let data = unsafe {
        core::slice::from_raw_parts(message as *const u8, 256)
    };

    crate::serial_println!("[SYSCALL] NtRequestWaitReplyPort(handle={:#x})", port_handle);

    let msg = crate::lpc::LpcMessage::request(data);
    let msg_id = unsafe { crate::lpc::lpc_send_message(port_idx, &msg) };

    if msg_id.is_none() {
        return -1;
    }

    // Wait for reply (simplified - just check for messages)
    let reply = unsafe { crate::lpc::lpc_receive_message(port_idx) };

    match reply {
        Some(r) => {
            if reply_message != 0 {
                unsafe {
                    let dest = reply_message as *mut u8;
                    core::ptr::copy_nonoverlapping(r.get_data().as_ptr(), dest, r.get_data().len());
                }
            }
            0
        }
        None => 0x102, // STATUS_TIMEOUT
    }
}

/// NtReplyPort - Send a reply message
fn sys_reply_port(
    port_handle: usize,
    reply_message: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    if port_handle == 0 || reply_message == 0 {
        return -1;
    }

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return -1,
    };

    // Read reply data and message ID
    let msg_id = unsafe { *(reply_message as *const u32) };
    let data = unsafe {
        core::slice::from_raw_parts((reply_message + 32) as *const u8, 224)
    };

    crate::serial_println!("[SYSCALL] NtReplyPort(handle={:#x}, msg_id={})", port_handle, msg_id);

    let result = unsafe { crate::lpc::lpc_reply_message(port_idx, msg_id, data) };

    if result { 0 } else { -1 }
}

/// NtReplyWaitReceivePort - Reply and wait for next message
fn sys_reply_wait_receive_port(
    port_handle: usize,
    port_context: usize,
    reply_message: usize,
    receive_message: usize,
    _: usize, _: usize,
) -> isize {
    let _ = port_context;

    if port_handle == 0 {
        return -1;
    }

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtReplyWaitReceivePort(handle={:#x})", port_handle);

    // Send reply if provided
    if reply_message != 0 {
        let msg_id = unsafe { *(reply_message as *const u32) };
        let data = unsafe {
            core::slice::from_raw_parts((reply_message + 32) as *const u8, 224)
        };
        let _ = unsafe { crate::lpc::lpc_reply_message(port_idx, msg_id, data) };
    }

    // Wait for next message
    let msg = unsafe { crate::lpc::lpc_receive_message(port_idx) };

    match msg {
        Some(m) => {
            if receive_message != 0 {
                unsafe {
                    // Write message header (simplified)
                    *(receive_message as *mut u32) = m.header.message_id;
                    *((receive_message + 4) as *mut u16) = m.header.data_length;
                    // Copy data
                    let dest = (receive_message + 32) as *mut u8;
                    core::ptr::copy_nonoverlapping(m.get_data().as_ptr(), dest, m.get_data().len());
                }
            }
            0
        }
        None => 0x102, // STATUS_TIMEOUT
    }
}

/// NtClosePort - Close an LPC port handle
fn sys_close_port(
    port_handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtClosePort(handle={:#x})", port_handle);

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return -1,
    };

    let result = unsafe { crate::lpc::lpc_close_port(port_idx) };
    unsafe { free_lpc_handle(port_handle); }

    if result { 0 } else { -1 }
}

/// NtQueryInformationPort - Query port information
fn sys_query_information_port(
    port_handle: usize,
    _port_information_class: usize,
    port_information: usize,
    length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    if port_handle == 0 || port_information == 0 {
        return -1;
    }

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtQueryInformationPort(handle={:#x})", port_handle);

    let info = unsafe { crate::lpc::lpc_get_port_info(port_idx) };

    match info {
        Some(i) => {
            let required = core::mem::size_of::<crate::lpc::LpcPortInfo>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if length < required {
                return 0x80000005u32 as isize; // STATUS_BUFFER_OVERFLOW
            }

            unsafe {
                *(port_information as *mut crate::lpc::LpcPortInfo) = i;
            }

            0
        }
        None => -1,
    }
}

// ============================================================================
// Object/Handle Syscalls
// ============================================================================

/// Handle type enumeration for the unified handle table
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandleType {
    None = 0,
    File = 1,
    Event = 2,
    Semaphore = 3,
    Mutex = 4,
    Section = 5,
    Key = 6,
    Port = 7,
    Thread = 8,
    Process = 9,
    Token = 10,
    IoCompletion = 11,
}

/// Generic handle entry
#[derive(Clone, Copy)]
struct HandleEntry {
    handle_type: HandleType,
    object_index: u32,  // Index into type-specific pool
    access_mask: u32,
    flags: u32,
}

impl HandleEntry {
    const fn empty() -> Self {
        Self {
            handle_type: HandleType::None,
            object_index: u32::MAX,
            access_mask: 0,
            flags: 0,
        }
    }

    fn is_valid(&self) -> bool {
        self.handle_type != HandleType::None && self.object_index != u32::MAX
    }
}

/// Process handle table
const MAX_PROCESS_HANDLES: usize = 64;
const PROCESS_HANDLE_BASE: usize = 0x5000;

static mut PROCESS_HANDLE_MAP: [u32; MAX_PROCESS_HANDLES] = [u32::MAX; MAX_PROCESS_HANDLES];

/// Allocate a process handle
unsafe fn alloc_process_handle(pid: u32) -> Option<usize> {
    for i in 0..MAX_PROCESS_HANDLES {
        if PROCESS_HANDLE_MAP[i] == u32::MAX {
            PROCESS_HANDLE_MAP[i] = pid;
            return Some(i + PROCESS_HANDLE_BASE);
        }
    }
    None
}

/// Get process ID from handle
unsafe fn get_process_id(handle: usize) -> Option<u32> {
    if handle < PROCESS_HANDLE_BASE {
        return None;
    }
    let idx = handle - PROCESS_HANDLE_BASE;
    if idx >= MAX_PROCESS_HANDLES {
        return None;
    }
    let pid = PROCESS_HANDLE_MAP[idx];
    if pid == u32::MAX { None } else { Some(pid) }
}

/// Free a process handle
unsafe fn free_process_handle(handle: usize) {
    if handle >= PROCESS_HANDLE_BASE {
        let idx = handle - PROCESS_HANDLE_BASE;
        if idx < MAX_PROCESS_HANDLES {
            PROCESS_HANDLE_MAP[idx] = u32::MAX;
        }
    }
}

/// Token handle table
const MAX_TOKEN_HANDLES: usize = 64;
const TOKEN_HANDLE_BASE: usize = 0x6000;

static mut TOKEN_HANDLE_MAP: [u32; MAX_TOKEN_HANDLES] = [u32::MAX; MAX_TOKEN_HANDLES];

/// Allocate a token handle
unsafe fn alloc_token_handle(token_id: u32) -> Option<usize> {
    for i in 0..MAX_TOKEN_HANDLES {
        if TOKEN_HANDLE_MAP[i] == u32::MAX {
            TOKEN_HANDLE_MAP[i] = token_id;
            return Some(i + TOKEN_HANDLE_BASE);
        }
    }
    None
}

/// Get token ID from handle
unsafe fn get_token_id(handle: usize) -> Option<u32> {
    if handle < TOKEN_HANDLE_BASE {
        return None;
    }
    let idx = handle - TOKEN_HANDLE_BASE;
    if idx >= MAX_TOKEN_HANDLES {
        return None;
    }
    let tid = TOKEN_HANDLE_MAP[idx];
    if tid == u32::MAX { None } else { Some(tid) }
}

/// Determine handle type from handle value
fn get_handle_type(handle: usize) -> HandleType {
    if handle >= TOKEN_HANDLE_BASE && handle < TOKEN_HANDLE_BASE + MAX_TOKEN_HANDLES {
        HandleType::Token
    } else if handle >= PROCESS_HANDLE_BASE && handle < PROCESS_HANDLE_BASE + MAX_PROCESS_HANDLES {
        HandleType::Process
    } else if handle >= THREAD_HANDLE_BASE && handle < THREAD_HANDLE_BASE + MAX_THREAD_HANDLES {
        HandleType::Thread
    } else if handle >= LPC_HANDLE_BASE && handle < LPC_HANDLE_BASE + MAX_LPC_HANDLES {
        HandleType::Port
    } else if handle >= KEY_HANDLE_BASE && handle < KEY_HANDLE_BASE + MAX_KEY_HANDLES {
        HandleType::Key
    } else if handle >= SYNC_HANDLE_BASE && handle < SYNC_HANDLE_BASE + MAX_SYNC_OBJECTS {
        // Check sync object type
        let idx = handle - SYNC_HANDLE_BASE;
        unsafe {
            match SYNC_OBJECT_POOL[idx].obj_type {
                SyncObjectType::Event => HandleType::Event,
                SyncObjectType::Semaphore => HandleType::Semaphore,
                SyncObjectType::Mutex => HandleType::Mutex,
                _ => HandleType::None,
            }
        }
    } else if handle >= FILE_HANDLE_BASE && handle < FILE_HANDLE_BASE + MAX_FILE_HANDLES {
        HandleType::File
    } else {
        HandleType::None
    }
}

/// Duplicate handle options
pub mod duplicate_options {
    pub const DUPLICATE_CLOSE_SOURCE: u32 = 0x00000001;
    pub const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;
    pub const DUPLICATE_SAME_ATTRIBUTES: u32 = 0x00000004;
}

/// NtDuplicateHandle - Duplicate a handle
fn sys_duplicate_handle(
    source_process_handle: usize,
    source_handle: usize,
    target_process_handle: usize,
    target_handle_ptr: usize,
    desired_access: usize,
    _handle_attributes: usize,
) -> isize {
    // For now, only support current process to current process
    let _ = source_process_handle;
    let _ = target_process_handle;

    if target_handle_ptr == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    crate::serial_println!("[SYSCALL] NtDuplicateHandle(source={:#x})", source_handle);

    let handle_type = get_handle_type(source_handle);

    // Duplicate based on handle type
    let new_handle = match handle_type {
        HandleType::File => unsafe {
            if let Some(fs_handle) = get_fs_handle(source_handle) {
                alloc_file_handle(fs_handle)
            } else {
                None
            }
        },
        HandleType::Event | HandleType::Semaphore | HandleType::Mutex => unsafe {
            // For sync objects, just create a new reference to the same object
            let idx = source_handle - SYNC_HANDLE_BASE;
            if idx < MAX_SYNC_OBJECTS && SYNC_OBJECT_POOL[idx].obj_type != SyncObjectType::None {
                // Find a new slot and copy the reference
                for i in 0..MAX_SYNC_OBJECTS {
                    if SYNC_OBJECT_POOL[i].obj_type == SyncObjectType::None {
                        SYNC_OBJECT_POOL[i].obj_type = SYNC_OBJECT_POOL[idx].obj_type;
                        // Note: We're not actually duplicating the object, just the handle
                        // A real implementation would increment a reference count
                        return {
                            let h = i + SYNC_HANDLE_BASE;
                            *(target_handle_ptr as *mut usize) = h;
                            crate::serial_println!("[SYSCALL] NtDuplicateHandle -> {:#x}", h);
                            0
                        };
                    }
                }
                None
            } else {
                None
            }
        },
        HandleType::Key => unsafe {
            if let Some(cm_handle) = get_cm_key_handle(source_handle) {
                alloc_key_handle(cm_handle)
            } else {
                None
            }
        },
        HandleType::Port => unsafe {
            if let Some(port_idx) = get_lpc_port(source_handle) {
                alloc_lpc_handle(port_idx)
            } else {
                None
            }
        },
        HandleType::Thread => unsafe {
            if let Some(tid) = get_thread_id(source_handle) {
                alloc_thread_handle(tid)
            } else {
                None
            }
        },
        HandleType::Process => unsafe {
            if let Some(pid) = get_process_id(source_handle) {
                alloc_process_handle(pid)
            } else {
                None
            }
        },
        HandleType::Token => unsafe {
            if let Some(tok_id) = get_token_id(source_handle) {
                alloc_token_handle(tok_id)
            } else {
                None
            }
        },
        _ => None,
    };

    let _ = desired_access;

    match new_handle {
        Some(h) => {
            unsafe { *(target_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtDuplicateHandle -> {:#x}", h);
            0
        }
        None => {
            crate::serial_println!("[SYSCALL] NtDuplicateHandle failed");
            -1
        }
    }
}

/// Object information class
pub mod object_info_class {
    pub const OBJECT_BASIC_INFORMATION: u32 = 0;
    pub const OBJECT_NAME_INFORMATION: u32 = 1;
    pub const OBJECT_TYPE_INFORMATION: u32 = 2;
    pub const OBJECT_TYPES_INFORMATION: u32 = 3;
    pub const OBJECT_HANDLE_FLAG_INFORMATION: u32 = 4;
}

/// OBJECT_BASIC_INFORMATION structure
#[repr(C)]
pub struct ObjectBasicInformation {
    pub attributes: u32,
    pub granted_access: u32,
    pub handle_count: u32,
    pub pointer_count: u32,
    pub paged_pool_charge: u32,
    pub non_paged_pool_charge: u32,
    pub reserved: [u32; 3],
    pub name_info_size: u32,
    pub type_info_size: u32,
    pub security_descriptor_size: u32,
    pub creation_time: i64,
}

/// NtQueryObject - Query object information
fn sys_query_object(
    handle: usize,
    object_information_class: usize,
    object_information: usize,
    object_information_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    if handle == 0 || object_information == 0 {
        return -1;
    }

    crate::serial_println!("[SYSCALL] NtQueryObject(handle={:#x}, class={})",
        handle, object_information_class);

    let handle_type = get_handle_type(handle);

    match object_information_class as u32 {
        object_info_class::OBJECT_BASIC_INFORMATION => {
            let required = core::mem::size_of::<ObjectBasicInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if object_information_length < required {
                return 0x80000005u32 as isize; // STATUS_BUFFER_OVERFLOW
            }

            unsafe {
                let info = object_information as *mut ObjectBasicInformation;
                (*info).attributes = 0;
                (*info).granted_access = 0x1F0001; // GENERIC_ALL
                (*info).handle_count = 1;
                (*info).pointer_count = 1;
                (*info).paged_pool_charge = 0;
                (*info).non_paged_pool_charge = 0;
                (*info).reserved = [0; 3];
                (*info).name_info_size = 0;
                (*info).type_info_size = 32;
                (*info).security_descriptor_size = 0;
                (*info).creation_time = 0;
            }

            0
        }
        object_info_class::OBJECT_TYPE_INFORMATION => {
            // Return type name
            let type_name = match handle_type {
                HandleType::File => "File",
                HandleType::Event => "Event",
                HandleType::Semaphore => "Semaphore",
                HandleType::Mutex => "Mutant",
                HandleType::Section => "Section",
                HandleType::Key => "Key",
                HandleType::Port => "Port",
                HandleType::Thread => "Thread",
                HandleType::Process => "Process",
                HandleType::Token => "Token",
                _ => "Unknown",
            };

            let name_bytes = type_name.as_bytes();
            let required = 68 + name_bytes.len(); // Header + name

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if object_information_length < required {
                return 0x80000005u32 as isize;
            }

            // Write type info (simplified)
            unsafe {
                let ptr = object_information as *mut u8;
                // Name length at offset 0
                *(ptr as *mut u16) = name_bytes.len() as u16;
                // Name at offset 68
                core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), ptr.add(68), name_bytes.len());
            }

            0
        }
        _ => -1, // STATUS_INVALID_INFO_CLASS
    }
}

// ============================================================================
// Process Syscalls
// ============================================================================

/// Process access rights
pub mod process_access {
    pub const PROCESS_TERMINATE: u32 = 0x0001;
    pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
    pub const PROCESS_SET_SESSIONID: u32 = 0x0004;
    pub const PROCESS_VM_OPERATION: u32 = 0x0008;
    pub const PROCESS_VM_READ: u32 = 0x0010;
    pub const PROCESS_VM_WRITE: u32 = 0x0020;
    pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
    pub const PROCESS_CREATE_PROCESS: u32 = 0x0080;
    pub const PROCESS_SET_QUOTA: u32 = 0x0100;
    pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
    pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    pub const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
    pub const PROCESS_ALL_ACCESS: u32 = 0x1FFFFF;
}

/// NtOpenProcess - Open a process by ID
fn sys_open_process(
    process_handle_ptr: usize,
    desired_access: usize,
    _object_attributes: usize,
    client_id_ptr: usize,
    _: usize, _: usize,
) -> isize {
    if process_handle_ptr == 0 || client_id_ptr == 0 {
        return -1;
    }

    // Read process ID from CLIENT_ID
    let pid = unsafe { *(client_id_ptr as *const u32) };

    crate::serial_println!("[SYSCALL] NtOpenProcess(pid={}, access={:#x})",
        pid, desired_access);

    // Verify process exists (check CID table)
    let process_exists = unsafe {
        !crate::ps::cid::ps_lookup_process_by_id(pid).is_null()
    };

    if !process_exists {
        crate::serial_println!("[SYSCALL] NtOpenProcess: process {} not found", pid);
        return -1; // STATUS_INVALID_CID
    }

    // Allocate handle
    let handle = unsafe { alloc_process_handle(pid) };
    match handle {
        Some(h) => {
            unsafe { *(process_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtOpenProcess -> handle {:#x}", h);
            0
        }
        None => -1,
    }
}

/// Process information class
pub mod process_info_class {
    pub const PROCESS_BASIC_INFORMATION: u32 = 0;
    pub const PROCESS_QUOTA_LIMITS: u32 = 1;
    pub const PROCESS_IO_COUNTERS: u32 = 2;
    pub const PROCESS_VM_COUNTERS: u32 = 3;
    pub const PROCESS_TIMES: u32 = 4;
    pub const PROCESS_PRIORITY_CLASS: u32 = 18;
    pub const PROCESS_HANDLE_COUNT: u32 = 20;
    pub const PROCESS_SESSION_INFORMATION: u32 = 24;
    pub const PROCESS_IMAGE_FILE_NAME: u32 = 27;
}

/// PROCESS_BASIC_INFORMATION structure
#[repr(C)]
pub struct ProcessBasicInformation {
    pub exit_status: i32,
    pub peb_base_address: u64,
    pub affinity_mask: u64,
    pub base_priority: i32,
    pub unique_process_id: u32,
    pub inherited_from_unique_process_id: u32,
}

/// NtQueryInformationProcess - Query process information
fn sys_query_information_process(
    process_handle: usize,
    process_information_class: usize,
    process_information: usize,
    process_information_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    if process_handle == 0 || process_information == 0 {
        return -1;
    }

    // Special handle -1 means current process
    let pid = if process_handle == usize::MAX {
        4 // System process for now
    } else {
        match unsafe { get_process_id(process_handle) } {
            Some(p) => p,
            None => return -1,
        }
    };

    crate::serial_println!("[SYSCALL] NtQueryInformationProcess(pid={}, class={})",
        pid, process_information_class);

    match process_information_class as u32 {
        process_info_class::PROCESS_BASIC_INFORMATION => {
            let required = core::mem::size_of::<ProcessBasicInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return 0x80000005u32 as isize;
            }

            // Look up process
            let process = unsafe { crate::ps::cid::ps_lookup_process_by_id(pid) };

            unsafe {
                let info = process_information as *mut ProcessBasicInformation;
                (*info).exit_status = 0x103; // STATUS_PENDING (still running)
                (*info).peb_base_address = 0;
                (*info).affinity_mask = 1;
                (*info).base_priority = 8;
                (*info).unique_process_id = pid;
                (*info).inherited_from_unique_process_id = if !process.is_null() {
                    let p = process as *mut crate::ps::EProcess;
                    (*p).inherited_from_unique_process_id
                } else {
                    0
                };
            }

            0
        }
        process_info_class::PROCESS_HANDLE_COUNT => {
            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = 4; }
            }

            if process_information_length < 4 {
                return 0x80000005u32 as isize;
            }

            // Return a dummy handle count
            unsafe {
                *(process_information as *mut u32) = 10;
            }

            0
        }
        _ => {
            crate::serial_println!("[SYSCALL] NtQueryInformationProcess: unsupported class {}",
                process_information_class);
            -1 // STATUS_INVALID_INFO_CLASS
        }
    }
}

/// NtSuspendProcess - Suspend all threads in a process
fn sys_suspend_process(
    process_handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    let pid = match unsafe { get_process_id(process_handle) } {
        Some(p) => p,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtSuspendProcess(pid={})", pid);

    // TODO: Actually suspend all threads in the process
    // For now, just succeed

    0
}

/// NtResumeProcess - Resume all threads in a process
fn sys_resume_process(
    process_handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    let pid = match unsafe { get_process_id(process_handle) } {
        Some(p) => p,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtResumeProcess(pid={})", pid);

    // TODO: Actually resume all threads in the process

    0
}

// ============================================================================
// Thread Syscalls (Extended)
// ============================================================================

/// Thread access rights
pub mod thread_access {
    pub const THREAD_TERMINATE: u32 = 0x0001;
    pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;
    pub const THREAD_GET_CONTEXT: u32 = 0x0008;
    pub const THREAD_SET_CONTEXT: u32 = 0x0010;
    pub const THREAD_SET_INFORMATION: u32 = 0x0020;
    pub const THREAD_QUERY_INFORMATION: u32 = 0x0040;
    pub const THREAD_SET_THREAD_TOKEN: u32 = 0x0080;
    pub const THREAD_IMPERSONATE: u32 = 0x0100;
    pub const THREAD_DIRECT_IMPERSONATION: u32 = 0x0200;
    pub const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;
}

/// NtOpenThread - Open a thread by ID
fn sys_open_thread(
    thread_handle_ptr: usize,
    desired_access: usize,
    _object_attributes: usize,
    client_id_ptr: usize,
    _: usize, _: usize,
) -> isize {
    if thread_handle_ptr == 0 || client_id_ptr == 0 {
        return -1;
    }

    // Read thread ID from CLIENT_ID (offset 4)
    let tid = unsafe { *((client_id_ptr + 4) as *const u32) };

    crate::serial_println!("[SYSCALL] NtOpenThread(tid={}, access={:#x})",
        tid, desired_access);

    // Verify thread exists
    let thread_exists = unsafe {
        !crate::ps::cid::ps_lookup_thread_by_id(tid).is_null()
    };

    if !thread_exists {
        crate::serial_println!("[SYSCALL] NtOpenThread: thread {} not found", tid);
        return -1;
    }

    // Allocate handle
    let handle = unsafe { alloc_thread_handle(tid) };
    match handle {
        Some(h) => {
            unsafe { *(thread_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtOpenThread -> handle {:#x}", h);
            0
        }
        None => -1,
    }
}

/// Thread information class
pub mod thread_info_class {
    pub const THREAD_BASIC_INFORMATION: u32 = 0;
    pub const THREAD_TIMES: u32 = 1;
    pub const THREAD_PRIORITY: u32 = 2;
    pub const THREAD_BASE_PRIORITY: u32 = 3;
    pub const THREAD_AFFINITY_MASK: u32 = 4;
    pub const THREAD_IMPERSONATION_TOKEN: u32 = 5;
    pub const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;
    pub const THREAD_IS_TERMINATED: u32 = 20;
}

/// THREAD_BASIC_INFORMATION structure
#[repr(C)]
pub struct ThreadBasicInformation {
    pub exit_status: i32,
    pub teb_base_address: u64,
    pub client_id_process: u32,
    pub client_id_thread: u32,
    pub affinity_mask: u64,
    pub priority: i32,
    pub base_priority: i32,
}

/// NtQueryInformationThread - Query thread information
fn sys_query_information_thread(
    thread_handle: usize,
    thread_information_class: usize,
    thread_information: usize,
    thread_information_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    if thread_handle == 0 || thread_information == 0 {
        return -1;
    }

    // Special handle -2 means current thread
    let tid = if thread_handle == usize::MAX - 1 {
        unsafe {
            let prcb = crate::ke::prcb::get_current_prcb();
            if !prcb.current_thread.is_null() {
                (*prcb.current_thread).thread_id
            } else {
                0
            }
        }
    } else {
        match unsafe { get_thread_id(thread_handle) } {
            Some(t) => t,
            None => return -1,
        }
    };

    crate::serial_println!("[SYSCALL] NtQueryInformationThread(tid={}, class={})",
        tid, thread_information_class);

    match thread_information_class as u32 {
        thread_info_class::THREAD_BASIC_INFORMATION => {
            let required = core::mem::size_of::<ThreadBasicInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return 0x80000005u32 as isize;
            }

            // Look up thread
            let thread = unsafe { crate::ps::cid::ps_lookup_thread_by_id(tid) };

            unsafe {
                let info = thread_information as *mut ThreadBasicInformation;
                (*info).exit_status = 0x103; // STATUS_PENDING
                (*info).teb_base_address = 0;
                if !thread.is_null() {
                    let t = thread as *mut crate::ps::EThread;
                    (*info).client_id_process = (*t).cid.unique_process;
                    (*info).client_id_thread = (*t).cid.unique_thread;
                    (*info).priority = (*(*t).get_tcb()).priority as i32;
                    (*info).base_priority = (*(*t).get_tcb()).base_priority as i32;
                } else {
                    (*info).client_id_process = 0;
                    (*info).client_id_thread = tid;
                    (*info).priority = 8;
                    (*info).base_priority = 8;
                }
                (*info).affinity_mask = 1;
            }

            0
        }
        thread_info_class::THREAD_IS_TERMINATED => {
            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = 4; }
            }

            if thread_information_length < 4 {
                return 0x80000005u32 as isize;
            }

            // Check if thread is terminated
            unsafe {
                *(thread_information as *mut u32) = 0; // Not terminated
            }

            0
        }
        _ => {
            crate::serial_println!("[SYSCALL] NtQueryInformationThread: unsupported class {}",
                thread_information_class);
            -1
        }
    }
}

/// NtSuspendThread - Suspend a thread
fn sys_suspend_thread(
    thread_handle: usize,
    previous_suspend_count: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    let tid = match unsafe { get_thread_id(thread_handle) } {
        Some(t) => t,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtSuspendThread(tid={})", tid);

    // TODO: Actually suspend the thread
    // For now, just return previous count of 0

    if previous_suspend_count != 0 {
        unsafe { *(previous_suspend_count as *mut u32) = 0; }
    }

    0
}

/// NtResumeThread - Resume a thread
fn sys_resume_thread(
    thread_handle: usize,
    previous_suspend_count: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    let tid = match unsafe { get_thread_id(thread_handle) } {
        Some(t) => t,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtResumeThread(tid={})", tid);

    // TODO: Actually resume the thread

    if previous_suspend_count != 0 {
        unsafe { *(previous_suspend_count as *mut u32) = 0; }
    }

    0
}

// ============================================================================
// Token Syscalls
// ============================================================================

/// Token access rights
pub mod token_access {
    pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
    pub const TOKEN_DUPLICATE: u32 = 0x0002;
    pub const TOKEN_IMPERSONATE: u32 = 0x0004;
    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TOKEN_QUERY_SOURCE: u32 = 0x0010;
    pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
    pub const TOKEN_ADJUST_GROUPS: u32 = 0x0040;
    pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
    pub const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;
    pub const TOKEN_ALL_ACCESS: u32 = 0xF01FF;
}

/// Simple token ID counter
static mut NEXT_TOKEN_ID: u32 = 1;

/// NtOpenProcessToken - Open a process's token
fn sys_open_process_token(
    process_handle: usize,
    desired_access: usize,
    token_handle_ptr: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    if token_handle_ptr == 0 {
        return -1;
    }

    // Get process ID (or use current if -1)
    let pid = if process_handle == usize::MAX {
        4 // System process
    } else {
        match unsafe { get_process_id(process_handle) } {
            Some(p) => p,
            None => return -1,
        }
    };

    crate::serial_println!("[SYSCALL] NtOpenProcessToken(pid={}, access={:#x})",
        pid, desired_access);

    // Create a token handle
    // In a real implementation, we'd look up the process's token
    let token_id = unsafe {
        let id = NEXT_TOKEN_ID;
        NEXT_TOKEN_ID += 1;
        id
    };

    let handle = unsafe { alloc_token_handle(token_id) };
    match handle {
        Some(h) => {
            unsafe { *(token_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtOpenProcessToken -> handle {:#x}", h);
            0
        }
        None => -1,
    }
}

/// NtOpenThreadToken - Open a thread's impersonation token
fn sys_open_thread_token(
    thread_handle: usize,
    desired_access: usize,
    open_as_self: usize,
    token_handle_ptr: usize,
    _: usize, _: usize,
) -> isize {
    if token_handle_ptr == 0 {
        return -1;
    }

    let _ = open_as_self;

    let tid = if thread_handle == usize::MAX - 1 {
        0 // Current thread
    } else {
        match unsafe { get_thread_id(thread_handle) } {
            Some(t) => t,
            None => return -1,
        }
    };

    crate::serial_println!("[SYSCALL] NtOpenThreadToken(tid={}, access={:#x})",
        tid, desired_access);

    // Threads may not have an impersonation token
    // Return STATUS_NO_TOKEN if not impersonating
    0xC000007C_u32 as isize // STATUS_NO_TOKEN
}

/// Token information class
pub mod token_info_class {
    pub const TOKEN_USER: u32 = 1;
    pub const TOKEN_GROUPS: u32 = 2;
    pub const TOKEN_PRIVILEGES: u32 = 3;
    pub const TOKEN_OWNER: u32 = 4;
    pub const TOKEN_PRIMARY_GROUP: u32 = 5;
    pub const TOKEN_DEFAULT_DACL: u32 = 6;
    pub const TOKEN_SOURCE: u32 = 7;
    pub const TOKEN_TYPE: u32 = 8;
    pub const TOKEN_IMPERSONATION_LEVEL: u32 = 9;
    pub const TOKEN_STATISTICS: u32 = 10;
    pub const TOKEN_SESSION_ID: u32 = 12;
    pub const TOKEN_ELEVATION: u32 = 20;
    pub const TOKEN_ELEVATION_TYPE: u32 = 18;
}

/// TOKEN_STATISTICS structure
#[repr(C)]
pub struct TokenStatistics {
    pub token_id: u64,
    pub authentication_id: u64,
    pub expiration_time: i64,
    pub token_type: u32,
    pub impersonation_level: u32,
    pub dynamic_charged: u32,
    pub dynamic_available: u32,
    pub group_count: u32,
    pub privilege_count: u32,
    pub modified_id: u64,
}

/// NtQueryInformationToken - Query token information
fn sys_query_information_token(
    token_handle: usize,
    token_information_class: usize,
    token_information: usize,
    token_information_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    if token_handle == 0 || token_information == 0 {
        return -1;
    }

    let token_id = match unsafe { get_token_id(token_handle) } {
        Some(t) => t,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtQueryInformationToken(token={}, class={})",
        token_id, token_information_class);

    match token_information_class as u32 {
        token_info_class::TOKEN_STATISTICS => {
            let required = core::mem::size_of::<TokenStatistics>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if token_information_length < required {
                return 0x80000005u32 as isize;
            }

            unsafe {
                let stats = token_information as *mut TokenStatistics;
                (*stats).token_id = token_id as u64;
                (*stats).authentication_id = 0x3E7; // SYSTEM_LUID
                (*stats).expiration_time = i64::MAX;
                (*stats).token_type = 1; // TokenPrimary
                (*stats).impersonation_level = 0;
                (*stats).dynamic_charged = 4096;
                (*stats).dynamic_available = 4096;
                (*stats).group_count = 1;
                (*stats).privilege_count = 5;
                (*stats).modified_id = token_id as u64;
            }

            0
        }
        token_info_class::TOKEN_TYPE => {
            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = 4; }
            }

            if token_information_length < 4 {
                return 0x80000005u32 as isize;
            }

            // Return TokenPrimary (1) or TokenImpersonation (2)
            unsafe {
                *(token_information as *mut u32) = 1; // TokenPrimary
            }

            0
        }
        token_info_class::TOKEN_ELEVATION => {
            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = 4; }
            }

            if token_information_length < 4 {
                return 0x80000005u32 as isize;
            }

            // Return elevated status (1 = elevated)
            unsafe {
                *(token_information as *mut u32) = 1;
            }

            0
        }
        token_info_class::TOKEN_SESSION_ID => {
            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = 4; }
            }

            if token_information_length < 4 {
                return 0x80000005u32 as isize;
            }

            unsafe {
                *(token_information as *mut u32) = 0; // Session 0
            }

            0
        }
        _ => {
            crate::serial_println!("[SYSCALL] NtQueryInformationToken: unsupported class {}",
                token_information_class);
            -1
        }
    }
}

/// NtDuplicateToken - Duplicate a token
fn sys_duplicate_token(
    existing_token_handle: usize,
    desired_access: usize,
    _object_attributes: usize,
    _impersonation_level: usize,
    _token_type: usize,
    new_token_handle_ptr: usize,
) -> isize {
    if new_token_handle_ptr == 0 {
        return -1;
    }

    let token_id = match unsafe { get_token_id(existing_token_handle) } {
        Some(t) => t,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtDuplicateToken(token={}, access={:#x})",
        token_id, desired_access);

    // Create a new token ID
    let new_token_id = unsafe {
        let id = NEXT_TOKEN_ID;
        NEXT_TOKEN_ID += 1;
        id
    };

    let handle = unsafe { alloc_token_handle(new_token_id) };
    match handle {
        Some(h) => {
            unsafe { *(new_token_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtDuplicateToken -> handle {:#x}", h);
            0
        }
        None => -1,
    }
}

/// NtAdjustPrivilegesToken - Enable/disable token privileges
fn sys_adjust_privileges_token(
    token_handle: usize,
    disable_all_privileges: usize,
    new_state: usize,
    buffer_length: usize,
    previous_state: usize,
    return_length: usize,
) -> isize {
    let token_id = match unsafe { get_token_id(token_handle) } {
        Some(t) => t,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtAdjustPrivilegesToken(token={}, disable_all={})",
        token_id, disable_all_privileges != 0);

    let _ = new_state;
    let _ = buffer_length;
    let _ = previous_state;

    // Return required length if asked
    if return_length != 0 {
        unsafe { *(return_length as *mut usize) = 0; }
    }

    // For now, always succeed (all privileges are granted)
    0
}
