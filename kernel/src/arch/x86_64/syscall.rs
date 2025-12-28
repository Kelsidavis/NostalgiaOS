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

    // Virtual Memory extended operations
    NtFlushVirtualMemory = 110,
    NtLockVirtualMemory = 111,
    NtUnlockVirtualMemory = 112,

    // Debug operations
    NtCreateDebugObject = 120,
    NtDebugActiveProcess = 121,
    NtRemoveProcessDebug = 122,
    NtWaitForDebugEvent = 123,
    NtDebugContinue = 124,

    // Exception handling
    NtRaiseException = 130,
    NtContinue = 131,
    NtGetContextThread = 132,
    NtSetContextThread = 133,

    // Process creation (extended)
    NtCreateProcess = 140,
    NtCreateProcessEx = 141,

    // Job objects
    NtCreateJobObject = 150,
    NtOpenJobObject = 151,
    NtAssignProcessToJobObject = 152,
    NtQueryInformationJobObject = 153,
    NtSetInformationJobObject = 154,
    NtTerminateJobObject = 155,
    NtIsProcessInJob = 156,

    // System information
    NtQuerySystemInformation = 160,
    NtSetSystemInformation = 161,

    // Time
    NtQuerySystemTime = 170,
    NtQueryPerformanceCounter = 171,
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
    let syscall_entry_addr = syscall_entry as *const () as u64;
    wrmsr(msr::LSTAR, syscall_entry_addr);

    // Set compatibility mode entry (not used, but set anyway)
    wrmsr(msr::CSTAR, 0);

    // Set RFLAGS mask - these bits are cleared on SYSCALL entry
    wrmsr(msr::SFMASK, SFMASK_VALUE);

    // Initialize syscall table with default handlers
    init_syscall_table();

    crate::serial_println!("[SYSCALL] Initialized syscall support");
    crate::serial_println!("[SYSCALL] STAR={:#x}, LSTAR={:#x}, SFMASK={:#x}",
        star, syscall_entry_addr, SFMASK_VALUE);
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
    register_syscall(SyscallNumber::NtReadVirtualMemory as usize, sys_read_virtual_memory);
    register_syscall(SyscallNumber::NtWriteVirtualMemory as usize, sys_write_virtual_memory);

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
    register_syscall(SyscallNumber::NtAdjustGroupsToken as usize, sys_adjust_groups_token);
    register_syscall(SyscallNumber::NtImpersonateThread as usize, sys_impersonate_thread);

    // Set Information syscalls
    register_syscall(SyscallNumber::NtSetInformationProcess as usize, sys_set_information_process);
    register_syscall(SyscallNumber::NtSetInformationThread as usize, sys_set_information_thread);
    register_syscall(SyscallNumber::NtSetInformationObject as usize, sys_set_information_object);
    register_syscall(SyscallNumber::NtSetInformationToken as usize, sys_set_information_token);

    // Virtual Memory extended syscalls
    register_syscall(SyscallNumber::NtFlushVirtualMemory as usize, sys_flush_virtual_memory);
    register_syscall(SyscallNumber::NtLockVirtualMemory as usize, sys_lock_virtual_memory);
    register_syscall(SyscallNumber::NtUnlockVirtualMemory as usize, sys_unlock_virtual_memory);
    // NtReadVirtualMemory and NtWriteVirtualMemory are already registered at 50/51

    // Debug syscalls
    register_syscall(SyscallNumber::NtCreateDebugObject as usize, sys_create_debug_object);
    register_syscall(SyscallNumber::NtDebugActiveProcess as usize, sys_debug_active_process);
    register_syscall(SyscallNumber::NtRemoveProcessDebug as usize, sys_remove_process_debug);
    register_syscall(SyscallNumber::NtWaitForDebugEvent as usize, sys_wait_for_debug_event);
    register_syscall(SyscallNumber::NtDebugContinue as usize, sys_debug_continue);

    // Exception handling syscalls
    register_syscall(SyscallNumber::NtRaiseException as usize, sys_raise_exception);
    register_syscall(SyscallNumber::NtContinue as usize, sys_continue);
    register_syscall(SyscallNumber::NtGetContextThread as usize, sys_get_context_thread);
    register_syscall(SyscallNumber::NtSetContextThread as usize, sys_set_context_thread);

    // Process creation syscalls
    register_syscall(SyscallNumber::NtCreateProcess as usize, sys_create_process);
    register_syscall(SyscallNumber::NtCreateProcessEx as usize, sys_create_process_ex);

    // Job object syscalls
    register_syscall(SyscallNumber::NtCreateJobObject as usize, sys_create_job_object);
    register_syscall(SyscallNumber::NtOpenJobObject as usize, sys_open_job_object);
    register_syscall(SyscallNumber::NtAssignProcessToJobObject as usize, sys_assign_process_to_job);
    register_syscall(SyscallNumber::NtQueryInformationJobObject as usize, sys_query_information_job);
    register_syscall(SyscallNumber::NtSetInformationJobObject as usize, sys_set_information_job);
    register_syscall(SyscallNumber::NtTerminateJobObject as usize, sys_terminate_job_object);
    register_syscall(SyscallNumber::NtIsProcessInJob as usize, sys_is_process_in_job);

    // System information
    register_syscall(SyscallNumber::NtQuerySystemInformation as usize, sys_query_system_information);
    register_syscall(SyscallNumber::NtQuerySystemTime as usize, sys_query_system_time);
    register_syscall(SyscallNumber::NtQueryPerformanceCounter as usize, sys_query_performance_counter);
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
    let is_alertable = alertable != 0;

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

    // Use alertable delay mechanism
    unsafe {
        let completed = crate::ke::wait::ke_delay_execution_alertable(delay_ms, is_alertable);
        if completed {
            0 // STATUS_SUCCESS
        } else {
            0x101 // STATUS_ALERTED
        }
    }
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
    use crate::ke::dispatcher::WaitStatus;
    use crate::ke::wait::ke_wait_for_single_object_alertable;

    let is_alertable = alertable != 0;

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

    // Wait on the dispatcher object with alertable support
    let result = unsafe {
        let header = object as *mut crate::ke::dispatcher::DispatcherHeader;
        let status = ke_wait_for_single_object_alertable(header, timeout_ms, is_alertable);
        match status {
            WaitStatus::Object0 => 0, // STATUS_WAIT_0
            WaitStatus::Timeout => 0x102, // STATUS_TIMEOUT
            WaitStatus::Alerted => 0x101, // STATUS_ALERTED
            WaitStatus::Abandoned => 0x80, // STATUS_ABANDONED_WAIT_0
            WaitStatus::Invalid => -1,
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
    use crate::ke::dispatcher::{DispatcherHeader, WaitStatus, WaitType, MAXIMUM_WAIT_OBJECTS};
    use crate::ke::wait::ke_wait_for_multiple_objects_alertable;

    let is_alertable = alertable != 0;
    let nt_wait_type = if wait_type == 0 { WaitType::WaitAll } else { WaitType::WaitAny };

    if count == 0 || count > MAXIMUM_WAIT_OBJECTS || handles == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // Get all object references
    let handle_array = unsafe {
        core::slice::from_raw_parts(handles as *const usize, count)
    };

    // Build array of dispatcher headers
    let mut objects: [*mut DispatcherHeader; 64] = [core::ptr::null_mut(); 64];
    let mut valid_count = 0usize;

    for (i, &handle) in handle_array.iter().enumerate() {
        unsafe {
            let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
            if obj.is_null() {
                // Dereference already-referenced objects and return error
                for j in 0..valid_count {
                    crate::ob::ob_dereference_object(objects[j] as *mut u8);
                }
                return -1; // STATUS_INVALID_HANDLE
            }
            objects[i] = obj as *mut DispatcherHeader;
            valid_count += 1;
        }
    }

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

    // Wait on all objects with alertable support
    let result = unsafe {
        let objects_slice = &objects[..valid_count];
        let status = ke_wait_for_multiple_objects_alertable(objects_slice, nt_wait_type, timeout_ms, is_alertable);
        match status {
            WaitStatus::Object0 => 0, // STATUS_WAIT_0
            WaitStatus::Timeout => 0x102, // STATUS_TIMEOUT
            WaitStatus::Alerted => 0x101, // STATUS_ALERTED
            WaitStatus::Abandoned => 0x80, // STATUS_ABANDONED_WAIT_0
            WaitStatus::Invalid => -1,
        }
    };

    // Dereference all objects
    for i in 0..valid_count {
        unsafe { crate::ob::ob_dereference_object(objects[i] as *mut u8); }
    }

    result
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

// ============================================================================
// NtQueryVirtualMemory Types and Structures
// ============================================================================

/// Memory information class for NtQueryVirtualMemory
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryInformationClass {
    /// Basic memory information (MEMORY_BASIC_INFORMATION)
    MemoryBasicInformation = 0,
    /// Working set information
    MemoryWorkingSetInformation = 1,
    /// Mapped file name
    MemoryMappedFilenameInformation = 2,
    /// Region information
    MemoryRegionInformation = 3,
    /// Working set list (extended)
    MemoryWorkingSetExInformation = 4,
    /// Shared commit information
    MemorySharedCommitInformation = 5,
    /// Image information
    MemoryImageInformation = 6,
    /// Region information (extended)
    MemoryRegionInformationEx = 7,
    /// Priority information
    MemoryPriorityInformation = 8,
    /// Partition information
    MemoryPartitionInformation = 9,
}

/// MEMORY_BASIC_INFORMATION structure (NT compatible)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryBasicInformation {
    /// Base address of the region
    pub base_address: usize,
    /// Base address of the allocation (first reserved page)
    pub allocation_base: usize,
    /// Initial protection when region was allocated
    pub allocation_protect: u32,
    /// Partition ID (Windows 10+)
    pub partition_id: u16,
    /// Reserved
    pub _reserved: u16,
    /// Size of the region in bytes
    pub region_size: usize,
    /// State of pages: MEM_COMMIT, MEM_FREE, MEM_RESERVE
    pub state: u32,
    /// Current protection
    pub protect: u32,
    /// Type of pages: MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
    pub mem_type: u32,
}

/// Memory state constants
pub mod mem_state {
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_FREE: u32 = 0x10000;
    pub const MEM_RESET: u32 = 0x80000;
    pub const MEM_RESET_UNDO: u32 = 0x1000000;
}

/// Memory type constants
pub mod mem_type {
    pub const MEM_PRIVATE: u32 = 0x20000;
    pub const MEM_MAPPED: u32 = 0x40000;
    pub const MEM_IMAGE: u32 = 0x1000000;
}

/// Page protection constants
pub mod page_protect {
    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const PAGE_READONLY: u32 = 0x02;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_WRITECOPY: u32 = 0x08;
    pub const PAGE_EXECUTE: u32 = 0x10;
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    pub const PAGE_GUARD: u32 = 0x100;
    pub const PAGE_NOCACHE: u32 = 0x200;
    pub const PAGE_WRITECOMBINE: u32 = 0x400;
}

/// MEMORY_REGION_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegionInformation {
    /// Base address of allocation
    pub allocation_base: usize,
    /// Protection at allocation time
    pub allocation_protect: u32,
    /// Flags
    pub region_type: u32,
    /// Size of allocation
    pub region_size: usize,
    /// Commit size
    pub commit_size: usize,
    /// Partition ID
    pub partition_id: usize,
    /// Node preference
    pub node_preference: usize,
}

/// MEMORY_IMAGE_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryImageInformation {
    /// Image base address
    pub image_base: usize,
    /// Image size
    pub size_of_image: usize,
    /// Flags
    pub image_flags: u32,
}

/// NtQueryVirtualMemory - Query information about virtual memory
///
/// Parameters:
/// - process_handle: Handle to the process (use -1 for current process)
/// - base_address: Address to query
/// - info_class: MemoryInformationClass value
/// - buffer: Output buffer for information
/// - buffer_size: Size of output buffer
/// - return_length: Optional pointer to receive required size
fn sys_query_virtual_memory(
    process_handle: usize,
    base_address: usize,
    info_class: usize,
    buffer: usize,
    buffer_size: usize,
    return_length: usize,
) -> isize {
    use core::ptr;

    crate::serial_println!("[SYSCALL] NtQueryVirtualMemory(handle={:#x}, addr={:#x}, class={}, buf={:#x}, size={})",
        process_handle, base_address, info_class, buffer, buffer_size);

    // Validate buffer pointer
    if buffer == 0 {
        return 0xC0000005u32 as isize; // STATUS_ACCESS_VIOLATION
    }

    // Get the address space for the target process
    // For now, we only support the current process (-1 or 0xFFFFFFFF...)
    let aspace = if process_handle == usize::MAX || process_handle == 0 {
        unsafe { crate::mm::mm_get_system_address_space() }
    } else {
        // TODO: Look up process by handle and get its address space
        // For now, just use system address space
        unsafe { crate::mm::mm_get_system_address_space() }
    };

    if aspace.is_null() {
        return 0xC0000008u32 as isize; // STATUS_INVALID_HANDLE
    }

    match info_class as u32 {
        // MemoryBasicInformation = 0
        0 => {
            let required_size = core::mem::size_of::<MemoryBasicInformation>();

            // Write return length if provided
            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut usize, required_size);
                }
            }

            if buffer_size < required_size {
                return 0xC0000004u32 as isize; // STATUS_INFO_LENGTH_MISMATCH
            }

            // Query the memory region
            let result = unsafe {
                crate::mm::mm_query_virtual_memory(aspace, base_address as u64)
            };

            match result {
                Some(mm_info) => {
                    // Convert internal format to NT format
                    let info = MemoryBasicInformation {
                        base_address: mm_info.base_address as usize,
                        allocation_base: mm_info.allocation_base as usize,
                        allocation_protect: mm_info.allocation_protect,
                        partition_id: 0,
                        _reserved: 0,
                        region_size: mm_info.region_size as usize,
                        state: mm_info.state,
                        protect: mm_info.protect,
                        mem_type: match mm_info.vad_type {
                            0 => mem_type::MEM_PRIVATE,  // Private memory
                            1 => mem_type::MEM_MAPPED,   // Mapped view
                            2 => mem_type::MEM_IMAGE,    // Image section
                            _ => mem_type::MEM_PRIVATE,
                        },
                    };

                    unsafe {
                        ptr::write(buffer as *mut MemoryBasicInformation, info);
                    }

                    crate::serial_println!("[SYSCALL] NtQueryVirtualMemory: base={:#x}, size={:#x}, state={:#x}, protect={:#x}",
                        info.base_address, info.region_size, info.state, info.protect);

                    0 // STATUS_SUCCESS
                }
                None => {
                    // Address not in any VAD - return FREE memory info
                    let info = MemoryBasicInformation {
                        base_address,
                        allocation_base: 0,
                        allocation_protect: 0,
                        partition_id: 0,
                        _reserved: 0,
                        region_size: 0x1000, // One page
                        state: mem_state::MEM_FREE,
                        protect: page_protect::PAGE_NOACCESS,
                        mem_type: 0,
                    };

                    unsafe {
                        ptr::write(buffer as *mut MemoryBasicInformation, info);
                    }

                    crate::serial_println!("[SYSCALL] NtQueryVirtualMemory: address {:#x} is FREE", base_address);

                    0 // STATUS_SUCCESS - free memory is valid to query
                }
            }
        }

        // MemoryRegionInformation = 3
        3 => {
            let required_size = core::mem::size_of::<MemoryRegionInformation>();

            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut usize, required_size);
                }
            }

            if buffer_size < required_size {
                return 0xC0000004u32 as isize;
            }

            let result = unsafe {
                crate::mm::mm_query_virtual_memory(aspace, base_address as u64)
            };

            match result {
                Some(mm_info) => {
                    let info = MemoryRegionInformation {
                        allocation_base: mm_info.allocation_base as usize,
                        allocation_protect: mm_info.allocation_protect,
                        region_type: mm_info.vad_type,
                        region_size: mm_info.region_size as usize,
                        commit_size: if mm_info.state == mem_state::MEM_COMMIT {
                            mm_info.region_size as usize
                        } else {
                            0
                        },
                        partition_id: 0,
                        node_preference: 0,
                    };

                    unsafe {
                        ptr::write(buffer as *mut MemoryRegionInformation, info);
                    }

                    0
                }
                None => 0xC0000005u32 as isize, // STATUS_ACCESS_VIOLATION
            }
        }

        // MemoryImageInformation = 6
        6 => {
            let required_size = core::mem::size_of::<MemoryImageInformation>();

            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut usize, required_size);
                }
            }

            if buffer_size < required_size {
                return 0xC0000004u32 as isize;
            }

            let result = unsafe {
                crate::mm::mm_query_virtual_memory(aspace, base_address as u64)
            };

            match result {
                Some(mm_info) => {
                    // Only valid for image mappings
                    if mm_info.vad_type != 2 {
                        return 0xC0000005u32 as isize; // Not an image mapping
                    }

                    let info = MemoryImageInformation {
                        image_base: mm_info.allocation_base as usize,
                        size_of_image: mm_info.region_size as usize,
                        image_flags: 0,
                    };

                    unsafe {
                        ptr::write(buffer as *mut MemoryImageInformation, info);
                    }

                    0
                }
                None => 0xC0000005u32 as isize,
            }
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtQueryVirtualMemory: unsupported class {}", info_class);
            0xC0000003u32 as isize // STATUS_INVALID_INFO_CLASS
        }
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
    _key_value_info_class: usize,
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

/// Process information class constants for query operations
#[allow(non_snake_case, non_upper_case_globals)]
pub mod process_info_class {
    /// Basic process information (exit status, PEB, affinity, priority, IDs)
    pub const ProcessBasicInformation: u32 = 0;
    /// Quota limits (working set, paged/nonpaged pool)
    pub const ProcessQuotaLimits: u32 = 1;
    /// I/O counters (reads, writes, other operations)
    pub const ProcessIoCounters: u32 = 2;
    /// VM counters (virtual memory statistics)
    pub const ProcessVmCounters: u32 = 3;
    /// Process times (creation, exit, kernel, user)
    pub const ProcessTimes: u32 = 4;
    /// Base priority
    pub const ProcessBasePriority: u32 = 5;
    /// Raise priority
    pub const ProcessRaisePriority: u32 = 6;
    /// Debug port
    pub const ProcessDebugPort: u32 = 7;
    /// Exception port
    pub const ProcessExceptionPort: u32 = 8;
    /// Access token
    pub const ProcessAccessToken: u32 = 9;
    /// LDT information
    pub const ProcessLdtInformation: u32 = 10;
    /// LDT size
    pub const ProcessLdtSize: u32 = 11;
    /// Default hard error mode
    pub const ProcessDefaultHardErrorMode: u32 = 12;
    /// I/O port handlers
    pub const ProcessIoPortHandlers: u32 = 13;
    /// Pooled usage and limits
    pub const ProcessPooledUsageAndLimits: u32 = 14;
    /// Working set watch
    pub const ProcessWorkingSetWatch: u32 = 15;
    /// User mode IOPLs
    pub const ProcessUserModeIOPL: u32 = 16;
    /// Enable alignment fault fixup
    pub const ProcessEnableAlignmentFaultFixup: u32 = 17;
    /// Priority class
    pub const ProcessPriorityClass: u32 = 18;
    /// WX86 information
    pub const ProcessWx86Information: u32 = 19;
    /// Handle count
    pub const ProcessHandleCount: u32 = 20;
    /// Affinity mask
    pub const ProcessAffinityMask: u32 = 21;
    /// Priority boost
    pub const ProcessPriorityBoost: u32 = 22;
    /// Device map
    pub const ProcessDeviceMap: u32 = 23;
    /// Session information
    pub const ProcessSessionInformation: u32 = 24;
    /// Foreground information
    pub const ProcessForegroundInformation: u32 = 25;
    /// WOW64 information
    pub const ProcessWow64Information: u32 = 26;
    /// Image file name
    pub const ProcessImageFileName: u32 = 27;
    /// LUIDs for device maps
    pub const ProcessLUIDDeviceMapsEnabled: u32 = 28;
    /// Break on termination
    pub const ProcessBreakOnTermination: u32 = 29;
    /// Debug object handle
    pub const ProcessDebugObjectHandle: u32 = 30;
    /// Debug flags
    pub const ProcessDebugFlags: u32 = 31;
    /// Handle tracing
    pub const ProcessHandleTracing: u32 = 32;
    /// I/O priority
    pub const ProcessIoPriority: u32 = 33;
    /// Execute flags (DEP)
    pub const ProcessExecuteFlags: u32 = 34;
    /// TLS information
    pub const ProcessTlsInformation: u32 = 35;
    /// Cookie
    pub const ProcessCookie: u32 = 36;
    /// Image information
    pub const ProcessImageInformation: u32 = 37;
    /// Cycle time
    pub const ProcessCycleTime: u32 = 38;
    /// Page priority
    pub const ProcessPagePriority: u32 = 39;
    /// Instrumentation callback
    pub const ProcessInstrumentationCallback: u32 = 40;
    /// Thread stack allocation
    pub const ProcessThreadStackAllocation: u32 = 41;
    /// Working set watch extended
    pub const ProcessWorkingSetWatchEx: u32 = 42;
    /// Image file name (Win32)
    pub const ProcessImageFileNameWin32: u32 = 43;
    /// Image file mapping
    pub const ProcessImageFileMapping: u32 = 44;
    /// Affinity update mode
    pub const ProcessAffinityUpdateMode: u32 = 45;
    /// Memory allocation mode
    pub const ProcessMemoryAllocationMode: u32 = 46;
    /// Group information
    pub const ProcessGroupInformation: u32 = 47;
    /// Token virtualization enabled
    pub const ProcessTokenVirtualizationEnabled: u32 = 48;
    /// Console host process
    pub const ProcessConsoleHostProcess: u32 = 49;
    /// Window information
    pub const ProcessWindowInformation: u32 = 50;

    // Legacy uppercase names for compatibility
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

/// PROCESS_BASIC_INFORMATION structure (class 0)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessBasicInformation {
    /// Exit status (STATUS_PENDING if running)
    pub exit_status: i32,
    /// Pointer to Process Environment Block
    pub peb_base_address: u64,
    /// CPU affinity mask
    pub affinity_mask: u64,
    /// Base scheduling priority
    pub base_priority: i32,
    /// Process ID
    pub unique_process_id: u32,
    /// Parent process ID
    pub inherited_from_unique_process_id: u32,
}

/// QUOTA_LIMITS structure (class 1)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QuotaLimits {
    /// Paged pool quota
    pub paged_pool_limit: u64,
    /// Non-paged pool quota
    pub non_paged_pool_limit: u64,
    /// Minimum working set size
    pub minimum_working_set_size: u64,
    /// Maximum working set size
    pub maximum_working_set_size: u64,
    /// Pagefile quota
    pub pagefile_limit: u64,
    /// Time limit
    pub time_limit: i64,
}

/// IO_COUNTERS structure (class 2)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoCounters {
    /// Read operations count
    pub read_operation_count: u64,
    /// Write operations count
    pub write_operation_count: u64,
    /// Other operations count
    pub other_operation_count: u64,
    /// Bytes read
    pub read_transfer_count: u64,
    /// Bytes written
    pub write_transfer_count: u64,
    /// Other bytes transferred
    pub other_transfer_count: u64,
}

/// VM_COUNTERS structure (class 3)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VmCounters {
    /// Peak virtual size
    pub peak_virtual_size: u64,
    /// Current virtual size
    pub virtual_size: u64,
    /// Page fault count
    pub page_fault_count: u32,
    /// Peak working set size
    pub peak_working_set_size: u64,
    /// Current working set size
    pub working_set_size: u64,
    /// Quota peak paged pool usage
    pub quota_peak_paged_pool_usage: u64,
    /// Quota paged pool usage
    pub quota_paged_pool_usage: u64,
    /// Quota peak nonpaged pool usage
    pub quota_peak_non_paged_pool_usage: u64,
    /// Quota nonpaged pool usage
    pub quota_non_paged_pool_usage: u64,
    /// Pagefile usage
    pub pagefile_usage: u64,
    /// Peak pagefile usage
    pub peak_pagefile_usage: u64,
}

/// KERNEL_USER_TIMES structure for processes (class 4)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessTimes {
    /// Creation time (100-nanosecond intervals since 1601)
    pub create_time: i64,
    /// Exit time (0 if still running)
    pub exit_time: i64,
    /// Time spent in kernel mode
    pub kernel_time: i64,
    /// Time spent in user mode
    pub user_time: i64,
}

/// Process priority class structure (class 18)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessPriorityClassInfo {
    /// Whether process is in foreground
    pub foreground: u8,
    /// Priority class value
    pub priority_class: u8,
}

/// Process session information (class 24)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessSessionInfo {
    /// Session ID
    pub session_id: u32,
}

/// Process cycle time information (class 38)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessCycleTimeInfo {
    /// Accumulated cycle time
    pub accumulated_cycles: u64,
    /// Current cycle count
    pub current_cycle_count: u64,
}

/// Process handle information (class 20 extended)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessHandleInfo {
    /// Number of handles
    pub handle_count: u32,
}

/// Process WOW64 information (class 26)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessWow64Info {
    /// WOW64 PEB address (0 if native)
    pub wow64_peb: u64,
}

/// Section image information (class 37)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SectionImageInformation {
    /// Transfer address (entry point)
    pub transfer_address: u64,
    /// Zero bits
    pub zero_bits: u32,
    /// Maximum stack size
    pub maximum_stack_size: u64,
    /// Committed stack size
    pub committed_stack_size: u64,
    /// Subsystem type
    pub subsystem_type: u32,
    /// Subsystem version (minor << 16 | major)
    pub subsystem_version_low: u16,
    pub subsystem_version_high: u16,
    /// GpValue
    pub gp_value: u32,
    /// Image characteristics
    pub image_characteristics: u16,
    /// DLL characteristics
    pub dll_characteristics: u16,
    /// Machine type
    pub machine: u16,
    /// Image contains code
    pub image_contains_code: u8,
    /// Image flags
    pub image_flags: u8,
    /// Loader flags
    pub loader_flags: u32,
    /// Image file size
    pub image_file_size: u32,
    /// Checksum
    pub checksum: u32,
}

/// NtQueryInformationProcess - Query process information
///
/// Retrieves information about a process based on the specified information class.
///
/// # Arguments
/// * `process_handle` - Handle to the process (0xFFFFFFFF = current process)
/// * `process_information_class` - Type of information to query
/// * `process_information` - Buffer to receive the information
/// * `process_information_length` - Size of the buffer
/// * `return_length` - Optional pointer to receive actual size needed
fn sys_query_information_process(
    process_handle: usize,
    process_information_class: usize,
    process_information: usize,
    process_information_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;
    const STATUS_INFO_LENGTH_MISMATCH: isize = 0xC0000004u32 as isize;
    const STATUS_INVALID_INFO_CLASS: isize = 0xC0000003u32 as isize;
    const STATUS_PENDING: i32 = 0x103;

    // Validate buffer pointer
    if process_information == 0 {
        return STATUS_INVALID_HANDLE;
    }

    // Get process ID from handle
    // Special handle -1 (0xFFFFFFFF) means current process
    let pid = if process_handle == usize::MAX || process_handle == 0xFFFFFFFF {
        // Get current process ID
        unsafe {
            let prcb = crate::ke::prcb::get_current_prcb();
            if !prcb.current_thread.is_null() {
                let thread = prcb.current_thread as *mut crate::ps::EThread;
                if !(*thread).thread_process.is_null() {
                    (*(*thread).thread_process).unique_process_id
                } else {
                    4 // System process fallback
                }
            } else {
                4 // System process fallback
            }
        }
    } else if process_handle == 0 {
        return STATUS_INVALID_HANDLE;
    } else {
        match unsafe { get_process_id(process_handle) } {
            Some(p) => p,
            None => return STATUS_INVALID_HANDLE,
        }
    };

    // Look up process structure
    let process = unsafe { crate::ps::cid::ps_lookup_process_by_id(pid) };
    let eprocess = process as *mut crate::ps::EProcess;

    crate::serial_println!("[SYSCALL] NtQueryInformationProcess(pid={}, class={})",
        pid, process_information_class);

    match process_information_class as u32 {
        // Class 0: ProcessBasicInformation
        process_info_class::ProcessBasicInformation => {
            let required = core::mem::size_of::<ProcessBasicInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut ProcessBasicInformation;
                if !eprocess.is_null() {
                    let p = &*eprocess;
                    (*info).exit_status = if p.exit_time > 0 { p.exit_status } else { STATUS_PENDING };
                    (*info).peb_base_address = p.peb as u64;
                    (*info).affinity_mask = 1; // Single processor
                    (*info).base_priority = p.pcb.base_priority as i32;
                    (*info).unique_process_id = p.unique_process_id;
                    (*info).inherited_from_unique_process_id = p.inherited_from_unique_process_id;
                } else {
                    (*info).exit_status = STATUS_PENDING;
                    (*info).peb_base_address = 0;
                    (*info).affinity_mask = 1;
                    (*info).base_priority = 8;
                    (*info).unique_process_id = pid;
                    (*info).inherited_from_unique_process_id = 0;
                }
            }

            STATUS_SUCCESS
        }

        // Class 1: ProcessQuotaLimits
        process_info_class::ProcessQuotaLimits => {
            let required = core::mem::size_of::<QuotaLimits>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut QuotaLimits;
                // Default quota limits
                (*info).paged_pool_limit = 0x20000000; // 512MB
                (*info).non_paged_pool_limit = 0x10000000; // 256MB
                (*info).minimum_working_set_size = 200 * 4096; // 200 pages
                (*info).maximum_working_set_size = 45000 * 4096; // 45000 pages
                (*info).pagefile_limit = 0xFFFFFFFF; // Unlimited
                (*info).time_limit = -1; // No limit
            }

            STATUS_SUCCESS
        }

        // Class 2: ProcessIoCounters
        process_info_class::ProcessIoCounters => {
            let required = core::mem::size_of::<IoCounters>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut IoCounters;
                // We don't track I/O yet, return zeros
                (*info).read_operation_count = 0;
                (*info).write_operation_count = 0;
                (*info).other_operation_count = 0;
                (*info).read_transfer_count = 0;
                (*info).write_transfer_count = 0;
                (*info).other_transfer_count = 0;
            }

            STATUS_SUCCESS
        }

        // Class 3: ProcessVmCounters
        process_info_class::ProcessVmCounters => {
            let required = core::mem::size_of::<VmCounters>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut VmCounters;
                if !eprocess.is_null() {
                    let p = &*eprocess;
                    (*info).peak_virtual_size = p.peak_virtual_size;
                    (*info).virtual_size = p.virtual_size;
                    (*info).page_fault_count = 0;
                    (*info).peak_working_set_size = p.peak_working_set_size;
                    (*info).working_set_size = p.working_set_size;
                    (*info).quota_peak_paged_pool_usage = p.quota_paged_pool_usage;
                    (*info).quota_paged_pool_usage = p.quota_paged_pool_usage;
                    (*info).quota_peak_non_paged_pool_usage = p.quota_non_paged_pool_usage;
                    (*info).quota_non_paged_pool_usage = p.quota_non_paged_pool_usage;
                    (*info).pagefile_usage = 0;
                    (*info).peak_pagefile_usage = 0;
                } else {
                    core::ptr::write_bytes(info, 0, 1);
                }
            }

            STATUS_SUCCESS
        }

        // Class 4: ProcessTimes
        process_info_class::ProcessTimes => {
            let required = core::mem::size_of::<ProcessTimes>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut ProcessTimes;
                if !eprocess.is_null() {
                    let p = &*eprocess;
                    // Convert ticks to 100-nanosecond intervals
                    (*info).create_time = (p.create_time as i64) * 10000;
                    (*info).exit_time = if p.exit_time > 0 { (p.exit_time as i64) * 10000 } else { 0 };
                    // Estimate kernel/user time
                    let total_time = crate::hal::apic::get_tick_count().saturating_sub(p.create_time);
                    (*info).kernel_time = (total_time as i64) * 10000;
                    (*info).user_time = 0;
                } else {
                    (*info).create_time = 0;
                    (*info).exit_time = 0;
                    (*info).kernel_time = 0;
                    (*info).user_time = 0;
                }
            }

            STATUS_SUCCESS
        }

        // Class 5: ProcessBasePriority
        process_info_class::ProcessBasePriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let base_priority = if !eprocess.is_null() {
                    (*eprocess).pcb.base_priority as i32
                } else {
                    8
                };
                *(process_information as *mut i32) = base_priority;
            }

            STATUS_SUCCESS
        }

        // Class 7: ProcessDebugPort
        process_info_class::ProcessDebugPort => {
            let required = 8usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let debug_port = if !eprocess.is_null() {
                    (*eprocess).debug_port as u64
                } else {
                    0
                };
                *(process_information as *mut u64) = debug_port;
            }

            STATUS_SUCCESS
        }

        // Class 18: ProcessPriorityClass
        process_info_class::ProcessPriorityClass => {
            let required = core::mem::size_of::<ProcessPriorityClassInfo>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut ProcessPriorityClassInfo;
                if !eprocess.is_null() {
                    let priority = (*eprocess).pcb.base_priority;
                    (*info).foreground = 0;
                    // Map base priority to priority class
                    (*info).priority_class = match priority {
                        0..=4 => 1,   // IDLE
                        5..=6 => 5,   // BELOW_NORMAL
                        7..=8 => 2,   // NORMAL
                        9..=10 => 3,  // ABOVE_NORMAL
                        11..=15 => 4, // HIGH
                        _ => 6,       // REALTIME
                    };
                } else {
                    (*info).foreground = 0;
                    (*info).priority_class = 2; // NORMAL
                }
            }

            STATUS_SUCCESS
        }

        // Class 20: ProcessHandleCount
        process_info_class::ProcessHandleCount => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Get actual handle count if we have an object table
                let count = if !eprocess.is_null() && !(*eprocess).object_table.is_null() {
                    (*(*eprocess).object_table).count()
                } else {
                    10 // Default handle count
                };
                *(process_information as *mut u32) = count;
            }

            STATUS_SUCCESS
        }

        // Class 21: ProcessAffinityMask
        process_info_class::ProcessAffinityMask => {
            let required = 8usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Single processor affinity
                *(process_information as *mut u64) = 1;
            }

            STATUS_SUCCESS
        }

        // Class 22: ProcessPriorityBoost
        process_info_class::ProcessPriorityBoost => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Priority boost not disabled
                *(process_information as *mut u32) = 0;
            }

            STATUS_SUCCESS
        }

        // Class 24: ProcessSessionInformation
        process_info_class::ProcessSessionInformation => {
            let required = core::mem::size_of::<ProcessSessionInfo>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut ProcessSessionInfo;
                (*info).session_id = if !eprocess.is_null() {
                    (*eprocess).session_id
                } else {
                    0
                };
            }

            STATUS_SUCCESS
        }

        // Class 26: ProcessWow64Information
        process_info_class::ProcessWow64Information => {
            let required = core::mem::size_of::<ProcessWow64Info>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut ProcessWow64Info;
                // Native 64-bit process, no WOW64
                (*info).wow64_peb = 0;
            }

            STATUS_SUCCESS
        }

        // Class 27: ProcessImageFileName
        process_info_class::ProcessImageFileName => {
            // Returns UNICODE_STRING with image name
            // For now, return a fixed size response
            let required = 520usize; // Max path in UNICODE_STRING format

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Write UNICODE_STRING header
                let length: u16 = if !eprocess.is_null() {
                    let mut len = 0u16;
                    for &c in &(*eprocess).image_file_name {
                        if c == 0 { break; }
                        len += 2; // UTF-16
                    }
                    len
                } else {
                    0
                };

                let ptr = process_information as *mut u8;
                *(ptr as *mut u16) = length; // Length
                *(ptr.add(2) as *mut u16) = length + 2; // MaximumLength
                *(ptr.add(8) as *mut u64) = if length > 0 {
                    process_information as u64 + 16
                } else {
                    0
                };

                // Copy name as UTF-16 if we have space
                if process_information_length >= 16 + length as usize && !eprocess.is_null() {
                    let name_ptr = ptr.add(16) as *mut u16;
                    for (i, &c) in (*eprocess).image_file_name.iter().enumerate() {
                        if c == 0 { break; }
                        *name_ptr.add(i) = c as u16;
                    }
                }
            }

            STATUS_SUCCESS
        }

        // Class 29: ProcessBreakOnTermination
        process_info_class::ProcessBreakOnTermination => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Not a critical process
                *(process_information as *mut u32) = 0;
            }

            STATUS_SUCCESS
        }

        // Class 31: ProcessDebugFlags
        process_info_class::ProcessDebugFlags => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Debug inherit flag (1 = no inherit)
                let has_debug_port = if !eprocess.is_null() {
                    !(*eprocess).debug_port.is_null()
                } else {
                    false
                };
                *(process_information as *mut u32) = if has_debug_port { 0 } else { 1 };
            }

            STATUS_SUCCESS
        }

        // Class 33: ProcessIoPriority
        process_info_class::ProcessIoPriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Default I/O priority (Normal = 2)
                *(process_information as *mut u32) = 2;
            }

            STATUS_SUCCESS
        }

        // Class 34: ProcessExecuteFlags
        process_info_class::ProcessExecuteFlags => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // DEP enabled (MEM_EXECUTE_OPTION_ENABLE = 2)
                *(process_information as *mut u32) = 2;
            }

            STATUS_SUCCESS
        }

        // Class 36: ProcessCookie
        process_info_class::ProcessCookie => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Generate a simple cookie based on process ID
                let cookie = (pid as u64).wrapping_mul(0x5DEECE66D).wrapping_add(0xB) as u32;
                *(process_information as *mut u32) = cookie;
            }

            STATUS_SUCCESS
        }

        // Class 37: ProcessImageInformation
        process_info_class::ProcessImageInformation => {
            let required = core::mem::size_of::<SectionImageInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut SectionImageInformation;
                // Default values for a 64-bit Windows executable
                (*info).transfer_address = 0;
                (*info).zero_bits = 0;
                (*info).maximum_stack_size = 0x100000; // 1MB
                (*info).committed_stack_size = 0x1000; // 4KB
                (*info).subsystem_type = 3; // IMAGE_SUBSYSTEM_WINDOWS_CUI
                (*info).subsystem_version_low = 0;
                (*info).subsystem_version_high = 6; // Windows 6.x
                (*info).gp_value = 0;
                (*info).image_characteristics = 0x22; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
                (*info).dll_characteristics = 0;
                (*info).machine = 0x8664; // AMD64
                (*info).image_contains_code = 1;
                (*info).image_flags = 0;
                (*info).loader_flags = 0;
                (*info).image_file_size = 0;
                (*info).checksum = 0;
            }

            STATUS_SUCCESS
        }

        // Class 38: ProcessCycleTime
        process_info_class::ProcessCycleTime => {
            let required = core::mem::size_of::<ProcessCycleTimeInfo>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut ProcessCycleTimeInfo;
                // Read current TSC
                let tsc: u64;
                core::arch::asm!("rdtsc", "shl rdx, 32", "or rax, rdx", out("rax") tsc, out("rdx") _);
                (*info).accumulated_cycles = tsc;
                (*info).current_cycle_count = tsc;
            }

            STATUS_SUCCESS
        }

        // Class 39: ProcessPagePriority
        process_info_class::ProcessPagePriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Default page priority (5 = normal)
                *(process_information as *mut u32) = 5;
            }

            STATUS_SUCCESS
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtQueryInformationProcess: unsupported class {}",
                process_information_class);
            STATUS_INVALID_INFO_CLASS
        }
    }
}

/// NtSuspendProcess - Suspend all threads in a process
fn sys_suspend_process(
    process_handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::cid::ps_lookup_process_by_id;
    use crate::ps::eprocess::EProcess;
    use crate::ps::ethread::EThread;
    use crate::containing_record;

    let pid = match unsafe { get_process_id(process_handle) } {
        Some(p) => p,
        None => return 0xC0000008u32 as isize, // STATUS_INVALID_HANDLE
    };

    crate::serial_println!("[SYSCALL] NtSuspendProcess(pid={})", pid);

    // Look up the process
    let process = unsafe {
        ps_lookup_process_by_id(pid) as *mut EProcess
    };

    if process.is_null() {
        return 0xC0000008u32 as isize;
    }

    // Iterate through all threads in the process and suspend them
    let mut suspended_count = 0u32;
    unsafe {
        let thread_list_head = &(*process).thread_list_head;

        if thread_list_head.is_empty() {
            crate::serial_println!("[SYSCALL] NtSuspendProcess: no threads to suspend");
            return 0;
        }

        // Walk the thread list - flink is a field, not a method
        let mut current = thread_list_head.flink;
        let head_addr = thread_list_head as *const _ as usize;

        while current as usize != head_addr {
            // Get EThread from list entry
            let thread = containing_record!(current, EThread, thread_list_entry);

            // Suspend the thread's TCB
            (*thread).tcb.suspend();
            suspended_count += 1;

            crate::serial_println!("[SYSCALL] NtSuspendProcess: suspended thread {}",
                (*thread).cid.unique_thread);

            // Move to next entry
            current = (*current).flink;
        }
    }

    crate::serial_println!("[SYSCALL] NtSuspendProcess: suspended {} threads", suspended_count);
    0 // STATUS_SUCCESS
}

/// NtResumeProcess - Resume all threads in a process
fn sys_resume_process(
    process_handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::cid::ps_lookup_process_by_id;
    use crate::ps::eprocess::EProcess;
    use crate::ps::ethread::EThread;
    use crate::containing_record;

    let pid = match unsafe { get_process_id(process_handle) } {
        Some(p) => p,
        None => return 0xC0000008u32 as isize,
    };

    crate::serial_println!("[SYSCALL] NtResumeProcess(pid={})", pid);

    // Look up the process
    let process = unsafe {
        ps_lookup_process_by_id(pid) as *mut EProcess
    };

    if process.is_null() {
        return 0xC0000008u32 as isize;
    }

    // Iterate through all threads in the process and resume them
    let mut resumed_count = 0u32;
    unsafe {
        let thread_list_head = &(*process).thread_list_head;

        if thread_list_head.is_empty() {
            crate::serial_println!("[SYSCALL] NtResumeProcess: no threads to resume");
            return 0;
        }

        // Walk the thread list - flink is a field, not a method
        let mut current = thread_list_head.flink;
        let head_addr = thread_list_head as *const _ as usize;

        while current as usize != head_addr {
            // Get EThread from list entry
            let thread = containing_record!(current, EThread, thread_list_entry);

            // Resume the thread's TCB
            let prev_count = (*thread).tcb.resume();

            if prev_count > 0 {
                resumed_count += 1;
                crate::serial_println!("[SYSCALL] NtResumeProcess: resumed thread {}",
                    (*thread).cid.unique_thread);

                // If suspend count reached 0, make thread ready to run
                if (*thread).tcb.suspend_count == 0 {
                    crate::ke::scheduler::ki_ready_thread(&mut (*thread).tcb as *mut _);
                }
            }

            // Move to next entry
            current = (*current).flink;
        }
    }

    crate::serial_println!("[SYSCALL] NtResumeProcess: resumed {} threads", resumed_count);
    0 // STATUS_SUCCESS
}

// ============================================================================
// Thread Syscalls (Extended)
// ============================================================================

/// Thread access rights
#[allow(non_snake_case, non_upper_case_globals)]
pub mod thread_access {
    /// Permission to terminate the thread
    pub const THREAD_TERMINATE: u32 = 0x0001;
    /// Permission to suspend or resume the thread
    pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;
    /// Permission to alert the thread
    pub const THREAD_ALERT: u32 = 0x0004;
    /// Permission to get the thread context
    pub const THREAD_GET_CONTEXT: u32 = 0x0008;
    /// Permission to set the thread context
    pub const THREAD_SET_CONTEXT: u32 = 0x0010;
    /// Permission to set thread information
    pub const THREAD_SET_INFORMATION: u32 = 0x0020;
    /// Permission to query thread information
    pub const THREAD_QUERY_INFORMATION: u32 = 0x0040;
    /// Permission to set thread token
    pub const THREAD_SET_THREAD_TOKEN: u32 = 0x0080;
    /// Permission to impersonate
    pub const THREAD_IMPERSONATE: u32 = 0x0100;
    /// Permission for direct impersonation
    pub const THREAD_DIRECT_IMPERSONATION: u32 = 0x0200;
    /// Permission to set limited information
    pub const THREAD_SET_LIMITED_INFORMATION: u32 = 0x0400;
    /// Permission to query limited information
    pub const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
    /// Permission to resume thread (Vista+)
    pub const THREAD_RESUME: u32 = 0x1000;
    /// All access rights
    pub const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;

    /// Standard rights
    pub const DELETE: u32 = 0x00010000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const SYNCHRONIZE: u32 = 0x00100000;

    // Compatibility aliases
    pub const ThreadTerminate: u32 = THREAD_TERMINATE;
    pub const ThreadSuspendResume: u32 = THREAD_SUSPEND_RESUME;
    pub const ThreadGetContext: u32 = THREAD_GET_CONTEXT;
    pub const ThreadSetContext: u32 = THREAD_SET_CONTEXT;
    pub const ThreadQueryInformation: u32 = THREAD_QUERY_INFORMATION;
    pub const ThreadSetInformation: u32 = THREAD_SET_INFORMATION;
    pub const ThreadAllAccess: u32 = THREAD_ALL_ACCESS;
}

/// CLIENT_ID structure for NtOpenThread
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClientIdForThread {
    /// Process ID (can be 0 to match any process)
    pub unique_process: u64,
    /// Thread ID to open
    pub unique_thread: u64,
}

/// NtOpenThread - Open a thread by ID
///
/// Opens an existing thread object and returns a handle to it.
///
/// # Arguments
/// * `thread_handle` - Pointer to receive the thread handle
/// * `desired_access` - Access rights to request (THREAD_* flags)
/// * `object_attributes` - Optional object attributes (can be NULL)
/// * `client_id` - Pointer to CLIENT_ID containing thread ID to open
///
/// # Returns
/// * STATUS_SUCCESS - Thread opened successfully
/// * STATUS_INVALID_PARAMETER - Invalid parameters
/// * STATUS_INVALID_CID - Thread not found
/// * STATUS_ACCESS_DENIED - Access denied
fn sys_open_thread(
    thread_handle_ptr: usize,
    desired_access: usize,
    object_attributes: usize,
    client_id_ptr: usize,
    _: usize, _: usize,
) -> isize {
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_PARAMETER: isize = 0xC000000Du32 as isize;
    const STATUS_INVALID_CID: isize = 0xC000000Bu32 as isize;
    const STATUS_ACCESS_DENIED: isize = 0xC0000022u32 as isize;
    const STATUS_INSUFFICIENT_RESOURCES: isize = 0xC000009Au32 as isize;
    const STATUS_OBJECT_TYPE_MISMATCH: isize = 0xC0000024u32 as isize;

    // Validate required parameters
    if thread_handle_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    if client_id_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Read CLIENT_ID structure
    // CLIENT_ID is { HANDLE UniqueProcess; HANDLE UniqueThread; }
    // On x64, HANDLEs are 64-bit
    let (pid, tid) = unsafe {
        let client_id = client_id_ptr as *const ClientIdForThread;
        ((*client_id).unique_process as u32, (*client_id).unique_thread as u32)
    };

    crate::serial_println!("[SYSCALL] NtOpenThread(pid={}, tid={}, access={:#x})",
        pid, tid, desired_access);

    // Thread ID must be specified
    if tid == 0 {
        crate::serial_println!("[SYSCALL] NtOpenThread: thread ID is zero");
        return STATUS_INVALID_CID;
    }

    // Look up the thread
    let thread = unsafe { crate::ps::cid::ps_lookup_thread_by_id(tid) };

    if thread.is_null() {
        crate::serial_println!("[SYSCALL] NtOpenThread: thread {} not found", tid);
        return STATUS_INVALID_CID;
    }

    // If process ID is specified (non-zero), verify the thread belongs to that process
    if pid != 0 {
        unsafe {
            let ethread = thread as *mut crate::ps::EThread;
            if (*ethread).cid.unique_process != pid {
                crate::serial_println!(
                    "[SYSCALL] NtOpenThread: thread {} belongs to process {}, not {}",
                    tid, (*ethread).cid.unique_process, pid
                );
                return STATUS_INVALID_CID;
            }
        }
    }

    // Check if thread is terminated
    unsafe {
        let ethread = thread as *mut crate::ps::EThread;
        if (*ethread).is_terminating() {
            crate::serial_println!("[SYSCALL] NtOpenThread: thread {} is terminated", tid);
            // Still allow opening terminated threads (for querying exit status)
        }
    }

    // Parse object attributes if provided
    let _inherit_handle = if object_attributes != 0 {
        unsafe {
            // OBJECT_ATTRIBUTES.Attributes is at offset 8 (after Length and RootDirectory)
            let attrs = *((object_attributes + 8) as *const u32);
            (attrs & 0x00000002) != 0 // OBJ_INHERIT
        }
    } else {
        false
    };

    // Access check would go here in a full implementation
    // For now, we grant the requested access

    // Validate access mask
    let access = desired_access as u32;
    let valid_access = thread_access::THREAD_ALL_ACCESS |
                       thread_access::DELETE |
                       thread_access::READ_CONTROL |
                       thread_access::WRITE_DAC |
                       thread_access::WRITE_OWNER |
                       thread_access::SYNCHRONIZE;

    if (access & !valid_access) != 0 {
        crate::serial_println!("[SYSCALL] NtOpenThread: invalid access mask {:#x}", access);
        // Don't fail - just mask to valid bits for compatibility
    }

    // Allocate handle
    let handle = unsafe { alloc_thread_handle(tid) };
    match handle {
        Some(h) => {
            unsafe { *(thread_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtOpenThread(tid={}) -> handle {:#x}", tid, h);
            STATUS_SUCCESS
        }
        None => {
            crate::serial_println!("[SYSCALL] NtOpenThread: failed to allocate handle");
            STATUS_INSUFFICIENT_RESOURCES
        }
    }
}

/// Thread information class constants for query operations
#[allow(non_snake_case, non_upper_case_globals)]
pub mod thread_info_class {
    /// Basic thread information (exit status, TEB, client ID, priority)
    pub const ThreadBasicInformation: u32 = 0;
    /// Thread times (creation, exit, kernel, user)
    pub const ThreadTimes: u32 = 1;
    /// Thread priority (KPRIORITY)
    pub const ThreadPriority: u32 = 2;
    /// Thread base priority
    pub const ThreadBasePriority: u32 = 3;
    /// Thread affinity mask
    pub const ThreadAffinityMask: u32 = 4;
    /// Thread impersonation token
    pub const ThreadImpersonationToken: u32 = 5;
    /// Thread descriptor table info
    pub const ThreadDescriptorTableEntry: u32 = 6;
    /// Enable alignment fault fixup
    pub const ThreadEnableAlignmentFaultFixup: u32 = 7;
    /// Event pair client (obsolete)
    pub const ThreadEventPair_Reusable: u32 = 8;
    /// Win32 start address
    pub const ThreadQuerySetWin32StartAddress: u32 = 9;
    /// Zero TLS cell
    pub const ThreadZeroTlsCell: u32 = 10;
    /// Performance counter
    pub const ThreadPerformanceCount: u32 = 11;
    /// Is in a terminated state
    pub const ThreadAmILastThread: u32 = 12;
    /// Thread ideal processor
    pub const ThreadIdealProcessor: u32 = 13;
    /// Thread priority boost
    pub const ThreadPriorityBoost: u32 = 14;
    /// Set TLS array address
    pub const ThreadSetTlsArrayAddress: u32 = 15;
    /// Is I/O pending
    pub const ThreadIsIoPending: u32 = 16;
    /// Hide from debugger
    pub const ThreadHideFromDebugger: u32 = 17;
    /// Break on termination
    pub const ThreadBreakOnTermination: u32 = 18;
    /// Switch legacy state
    pub const ThreadSwitchLegacyState: u32 = 19;
    /// Is terminated
    pub const ThreadIsTerminated: u32 = 20;
    /// Last system call
    pub const ThreadLastSystemCall: u32 = 21;
    /// I/O priority
    pub const ThreadIoPriority: u32 = 22;
    /// Cycle time
    pub const ThreadCycleTime: u32 = 23;
    /// Page priority
    pub const ThreadPagePriority: u32 = 24;
    /// Actual base priority
    pub const ThreadActualBasePriority: u32 = 25;
    /// TEB information
    pub const ThreadTebInformation: u32 = 26;
    /// CSR API message
    pub const ThreadCSwitchMon: u32 = 27;
    /// CSR message process
    pub const ThreadCSwitchPmu: u32 = 28;
    /// WOW64 context
    pub const ThreadWow64Context: u32 = 29;
    /// Group information
    pub const ThreadGroupInformation: u32 = 30;
    /// UMS information
    pub const ThreadUmsInformation: u32 = 31;
    /// Counter profiling
    pub const ThreadCounterProfiling: u32 = 32;
    /// Ideal processor extended
    pub const ThreadIdealProcessorEx: u32 = 33;
    /// Suspend count
    pub const ThreadSuspendCount: u32 = 35;

    // Legacy names for compatibility
    pub const THREAD_BASIC_INFORMATION: u32 = 0;
    pub const THREAD_TIMES: u32 = 1;
    pub const THREAD_PRIORITY: u32 = 2;
    pub const THREAD_BASE_PRIORITY: u32 = 3;
    pub const THREAD_AFFINITY_MASK: u32 = 4;
    pub const THREAD_IMPERSONATION_TOKEN: u32 = 5;
    pub const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;
    pub const THREAD_IS_TERMINATED: u32 = 20;
}

/// THREAD_BASIC_INFORMATION structure (class 0)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadBasicInformation {
    /// Thread exit status (STATUS_PENDING if running)
    pub exit_status: i32,
    /// Pointer to Thread Environment Block
    pub teb_base_address: u64,
    /// Process ID
    pub client_id_process: u32,
    /// Thread ID
    pub client_id_thread: u32,
    /// CPU affinity mask
    pub affinity_mask: u64,
    /// Current scheduling priority
    pub priority: i32,
    /// Base scheduling priority
    pub base_priority: i32,
}

/// KERNEL_USER_TIMES structure (class 1)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelUserTimes {
    /// Creation time (100-nanosecond intervals since 1601)
    pub create_time: i64,
    /// Exit time (0 if still running)
    pub exit_time: i64,
    /// Time spent in kernel mode
    pub kernel_time: i64,
    /// Time spent in user mode
    pub user_time: i64,
}

/// Thread performance counter structure (class 11)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadPerformanceCounter {
    /// Performance counter value
    pub performance_count: i64,
}

/// Thread cycle time information (class 23)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadCycleTimeInformation {
    /// Accumulated cycle time
    pub accumulated_cycles: u64,
    /// Current cycle count
    pub current_cycle_count: u64,
}

/// Thread last system call information (class 21)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadLastSystemCall {
    /// First argument of last system call
    pub first_argument: u64,
    /// System call number
    pub system_call_number: u16,
    /// Padding
    pub _padding: u16,
    /// Reserved
    pub _reserved: u32,
}

/// Thread TEB information (class 26)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadTebInformation {
    /// TEB base address
    pub teb_base: u64,
    /// TEB offset
    pub teb_offset: u32,
    /// Bytes to read
    pub bytes_to_read: u32,
}

/// Thread group information (class 30)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadGroupInformation {
    /// Processor group
    pub group: u16,
    /// Reserved
    pub _reserved: [u16; 3],
}

/// NtQueryInformationThread - Query thread information
///
/// Retrieves information about a thread based on the specified information class.
///
/// # Arguments
/// * `thread_handle` - Handle to the thread (0xFFFFFFFE = current thread)
/// * `thread_information_class` - Type of information to query
/// * `thread_information` - Buffer to receive the information
/// * `thread_information_length` - Size of the buffer
/// * `return_length` - Optional pointer to receive actual size needed
fn sys_query_information_thread(
    thread_handle: usize,
    thread_information_class: usize,
    thread_information: usize,
    thread_information_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;
    const STATUS_INFO_LENGTH_MISMATCH: isize = 0xC0000004u32 as isize;
    const STATUS_BUFFER_TOO_SMALL: isize = 0xC0000023u32 as isize;
    const STATUS_INVALID_INFO_CLASS: isize = 0xC0000003u32 as isize;
    const STATUS_PENDING: i32 = 0x103;

    // Validate buffer pointer
    if thread_information == 0 {
        return STATUS_INVALID_HANDLE;
    }

    // Get thread ID from handle
    // Special handle -2 (0xFFFFFFFE) means current thread
    let tid = if thread_handle == usize::MAX - 1 || thread_handle == 0xFFFFFFFE {
        unsafe {
            let prcb = crate::ke::prcb::get_current_prcb();
            if !prcb.current_thread.is_null() {
                (*prcb.current_thread).thread_id
            } else {
                return STATUS_INVALID_HANDLE;
            }
        }
    } else if thread_handle == 0 {
        return STATUS_INVALID_HANDLE;
    } else {
        match unsafe { get_thread_id(thread_handle) } {
            Some(t) => t,
            None => return STATUS_INVALID_HANDLE,
        }
    };

    // Look up thread structure
    let thread = unsafe { crate::ps::cid::ps_lookup_thread_by_id(tid) };
    let ethread = thread as *mut crate::ps::EThread;

    crate::serial_println!("[SYSCALL] NtQueryInformationThread(tid={}, class={})",
        tid, thread_information_class);

    match thread_information_class as u32 {
        // Class 0: ThreadBasicInformation
        thread_info_class::ThreadBasicInformation => {
            let required = core::mem::size_of::<ThreadBasicInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = thread_information as *mut ThreadBasicInformation;
                if !ethread.is_null() {
                    let t = &*ethread;
                    (*info).exit_status = if t.is_terminating() { t.exit_status } else { STATUS_PENDING };
                    (*info).teb_base_address = t.teb as u64;
                    (*info).client_id_process = t.cid.unique_process;
                    (*info).client_id_thread = t.cid.unique_thread;
                    (*info).affinity_mask = 1; // Single processor for now
                    (*info).priority = (*t.get_tcb()).priority as i32;
                    (*info).base_priority = (*t.get_tcb()).base_priority as i32;
                } else {
                    (*info).exit_status = STATUS_PENDING;
                    (*info).teb_base_address = 0;
                    (*info).client_id_process = 0;
                    (*info).client_id_thread = tid;
                    (*info).affinity_mask = 1;
                    (*info).priority = 8;
                    (*info).base_priority = 8;
                }
            }

            STATUS_SUCCESS
        }

        // Class 1: ThreadTimes
        thread_info_class::ThreadTimes => {
            let required = core::mem::size_of::<KernelUserTimes>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = thread_information as *mut KernelUserTimes;
                if !ethread.is_null() {
                    let t = &*ethread;
                    // Convert ticks to 100-nanosecond intervals
                    // 1 tick = 1ms = 10000 * 100ns
                    (*info).create_time = (t.create_time as i64) * 10000;
                    (*info).exit_time = if t.exit_time > 0 { (t.exit_time as i64) * 10000 } else { 0 };
                    // Estimate kernel/user time (we don't track this precisely yet)
                    let total_time = crate::hal::apic::get_tick_count().saturating_sub(t.create_time);
                    (*info).kernel_time = (total_time as i64) * 10000;
                    (*info).user_time = 0; // No user mode yet
                } else {
                    (*info).create_time = 0;
                    (*info).exit_time = 0;
                    (*info).kernel_time = 0;
                    (*info).user_time = 0;
                }
            }

            STATUS_SUCCESS
        }

        // Class 2: ThreadPriority
        thread_info_class::ThreadPriority => {
            let required = 4usize; // KPRIORITY is i32

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let priority = if !ethread.is_null() {
                    (*(*ethread).get_tcb()).priority as i32
                } else {
                    8 // Normal priority
                };
                *(thread_information as *mut i32) = priority;
            }

            STATUS_SUCCESS
        }

        // Class 3: ThreadBasePriority
        thread_info_class::ThreadBasePriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let base_priority = if !ethread.is_null() {
                    (*(*ethread).get_tcb()).base_priority as i32
                } else {
                    8
                };
                *(thread_information as *mut i32) = base_priority;
            }

            STATUS_SUCCESS
        }

        // Class 4: ThreadAffinityMask
        thread_info_class::ThreadAffinityMask => {
            let required = 8usize; // KAFFINITY is u64 on x64

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // For now, single processor affinity
                *(thread_information as *mut u64) = 1;
            }

            STATUS_SUCCESS
        }

        // Class 9: ThreadQuerySetWin32StartAddress
        thread_info_class::ThreadQuerySetWin32StartAddress => {
            let required = 8usize; // Pointer size

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let start_addr = if !ethread.is_null() {
                    (*ethread).win32_start_address as u64
                } else {
                    0
                };
                *(thread_information as *mut u64) = start_addr;
            }

            STATUS_SUCCESS
        }

        // Class 11: ThreadPerformanceCount
        thread_info_class::ThreadPerformanceCount => {
            let required = core::mem::size_of::<ThreadPerformanceCounter>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = thread_information as *mut ThreadPerformanceCounter;
                // Read TSC for performance counter
                let tsc: u64;
                core::arch::asm!("rdtsc", "shl rdx, 32", "or rax, rdx", out("rax") tsc, out("rdx") _);
                (*info).performance_count = tsc as i64;
            }

            STATUS_SUCCESS
        }

        // Class 12: ThreadAmILastThread
        thread_info_class::ThreadAmILastThread => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Check if this is the last thread in the process
                let is_last = if !ethread.is_null() {
                    let process = (*ethread).thread_process;
                    if !process.is_null() {
                        (*process).thread_count() <= 1
                    } else {
                        true
                    }
                } else {
                    false
                };
                *(thread_information as *mut u32) = if is_last { 1 } else { 0 };
            }

            STATUS_SUCCESS
        }

        // Class 13: ThreadIdealProcessor
        thread_info_class::ThreadIdealProcessor => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Return processor 0 for now (single processor)
                *(thread_information as *mut u32) = 0;
            }

            STATUS_SUCCESS
        }

        // Class 14: ThreadPriorityBoost
        thread_info_class::ThreadPriorityBoost => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Priority boost disabled = 0, enabled = 1
                // We don't track this yet, assume enabled
                *(thread_information as *mut u32) = 0; // Not disabled
            }

            STATUS_SUCCESS
        }

        // Class 16: ThreadIsIoPending
        thread_info_class::ThreadIsIoPending => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let has_pending_io = if !ethread.is_null() {
                    use core::sync::atomic::Ordering;
                    (*ethread).pending_irp_count.load(Ordering::Relaxed) > 0
                } else {
                    false
                };
                *(thread_information as *mut u32) = if has_pending_io { 1 } else { 0 };
            }

            STATUS_SUCCESS
        }

        // Class 17: ThreadHideFromDebugger
        thread_info_class::ThreadHideFromDebugger => {
            let required = 1usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // We don't implement debugger hiding yet
                *(thread_information as *mut u8) = 0;
            }

            STATUS_SUCCESS
        }

        // Class 18: ThreadBreakOnTermination
        thread_info_class::ThreadBreakOnTermination => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Not implemented yet
                *(thread_information as *mut u32) = 0;
            }

            STATUS_SUCCESS
        }

        // Class 20: ThreadIsTerminated
        thread_info_class::ThreadIsTerminated => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let is_terminated = if !ethread.is_null() {
                    (*ethread).is_terminating()
                } else {
                    true // If we can't find the thread, assume terminated
                };
                *(thread_information as *mut u32) = if is_terminated { 1 } else { 0 };
            }

            STATUS_SUCCESS
        }

        // Class 22: ThreadIoPriority
        thread_info_class::ThreadIoPriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Default I/O priority (IoPriorityNormal = 2)
                *(thread_information as *mut u32) = 2;
            }

            STATUS_SUCCESS
        }

        // Class 23: ThreadCycleTime
        thread_info_class::ThreadCycleTime => {
            let required = core::mem::size_of::<ThreadCycleTimeInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = thread_information as *mut ThreadCycleTimeInformation;
                // Read current TSC
                let tsc: u64;
                core::arch::asm!("rdtsc", "shl rdx, 32", "or rax, rdx", out("rax") tsc, out("rdx") _);
                (*info).accumulated_cycles = tsc;
                (*info).current_cycle_count = tsc;
            }

            STATUS_SUCCESS
        }

        // Class 24: ThreadPagePriority
        thread_info_class::ThreadPagePriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Default page priority (5 = normal)
                *(thread_information as *mut u32) = 5;
            }

            STATUS_SUCCESS
        }

        // Class 25: ThreadActualBasePriority
        thread_info_class::ThreadActualBasePriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let base_priority = if !ethread.is_null() {
                    (*(*ethread).get_tcb()).base_priority as i32
                } else {
                    8
                };
                *(thread_information as *mut i32) = base_priority;
            }

            STATUS_SUCCESS
        }

        // Class 26: ThreadTebInformation
        thread_info_class::ThreadTebInformation => {
            let required = core::mem::size_of::<ThreadTebInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = thread_information as *mut ThreadTebInformation;
                if !ethread.is_null() {
                    (*info).teb_base = (*ethread).teb as u64;
                } else {
                    (*info).teb_base = 0;
                }
                (*info).teb_offset = 0;
                (*info).bytes_to_read = 0;
            }

            STATUS_SUCCESS
        }

        // Class 30: ThreadGroupInformation
        thread_info_class::ThreadGroupInformation => {
            let required = core::mem::size_of::<ThreadGroupInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = thread_information as *mut ThreadGroupInformation;
                (*info).group = 0; // Group 0 (single group system)
                (*info)._reserved = [0; 3];
            }

            STATUS_SUCCESS
        }

        // Class 35: ThreadSuspendCount
        thread_info_class::ThreadSuspendCount => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let suspend_count = if !ethread.is_null() {
                    (*ethread).suspend_count as u32
                } else {
                    0
                };
                *(thread_information as *mut u32) = suspend_count;
            }

            STATUS_SUCCESS
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtQueryInformationThread: unsupported class {}",
                thread_information_class);
            STATUS_INVALID_INFO_CLASS
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

    // Look up the thread by ID
    let thread_ptr = unsafe { crate::ps::cid::ps_lookup_thread_by_id(tid) };
    if thread_ptr.is_null() {
        return -1; // STATUS_INVALID_HANDLE
    }

    // Get KTHREAD from ETHREAD and suspend it
    let prev_count = unsafe {
        let ethread = thread_ptr as *mut crate::ps::EThread;
        let kthread = (*ethread).get_tcb_mut();
        (*kthread).suspend()
    };

    if previous_suspend_count != 0 {
        unsafe { *(previous_suspend_count as *mut u32) = prev_count as u32; }
    }

    crate::serial_println!("[SYSCALL] NtSuspendThread: prev_count={}", prev_count);

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

    // Look up the thread by ID
    let thread_ptr = unsafe { crate::ps::cid::ps_lookup_thread_by_id(tid) };
    if thread_ptr.is_null() {
        return -1; // STATUS_INVALID_HANDLE
    }

    // Get KTHREAD from ETHREAD and resume it
    let prev_count = unsafe {
        let ethread = thread_ptr as *mut crate::ps::EThread;
        let kthread = (*ethread).get_tcb_mut();
        (*kthread).resume()
    };

    if previous_suspend_count != 0 {
        unsafe { *(previous_suspend_count as *mut u32) = prev_count as u32; }
    }

    crate::serial_println!("[SYSCALL] NtResumeThread: prev_count={}", prev_count);

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

// ============================================================================
// NtSetInformation Syscalls
// ============================================================================

// ============================================================================
// NtSetInformationProcess Types and Structures
// ============================================================================

/// Process information classes for Set operations
#[allow(non_snake_case, non_upper_case_globals)]
pub mod ProcessInfoClassSet {
    /// Basic limit information (working set, priority)
    pub const ProcessBasicInformation: u32 = 0;
    /// Set quota limits
    pub const ProcessQuotaLimits: u32 = 1;
    /// Set I/O counters (usually read-only)
    pub const ProcessIoCounters: u32 = 2;
    /// Set VM counters (usually read-only)
    pub const ProcessVmCounters: u32 = 3;
    /// Set process times (usually read-only)
    pub const ProcessTimes: u32 = 4;
    /// Set base priority for the process
    pub const ProcessBasePriority: u32 = 5;
    /// Raise priority (temporary boost)
    pub const ProcessRaisePriority: u32 = 6;
    /// Set debug port
    pub const ProcessDebugPort: u32 = 7;
    /// Set exception port
    pub const ProcessExceptionPort: u32 = 8;
    /// Set access token
    pub const ProcessAccessToken: u32 = 9;
    /// Set LDT information
    pub const ProcessLdtInformation: u32 = 10;
    /// Set LDT size
    pub const ProcessLdtSize: u32 = 11;
    /// Set default hard error mode
    pub const ProcessDefaultHardErrorMode: u32 = 12;
    /// Set I/O port handlers (VDM)
    pub const ProcessIoPortHandlers: u32 = 13;
    /// Set foreground information
    pub const ProcessForegroundInformation: u32 = 15;
    /// Set process priority class
    pub const ProcessPriorityClass: u32 = 18;
    /// Set Wx86 information
    pub const ProcessWx86Information: u32 = 19;
    /// Set handle count (read-only typically)
    pub const ProcessHandleCount: u32 = 20;
    /// Set affinity mask
    pub const ProcessAffinityMask: u32 = 21;
    /// Set priority boost disable
    pub const ProcessPriorityBoost: u32 = 22;
    /// Set session ID
    pub const ProcessSessionInformation: u32 = 24;
    /// Set DEP policy
    pub const ProcessExecuteFlags: u32 = 34;
    /// Set break on termination flag
    pub const ProcessBreakOnTermination: u32 = 29;
    /// Set instrumentation callback
    pub const ProcessInstrumentationCallback: u32 = 40;
}

/// PROCESS_PRIORITY_CLASS structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessPriorityClass {
    /// Set to TRUE to enable foreground boost
    pub foreground: u8,
    /// Priority class value
    pub priority_class: u8,
}

/// Priority class values
#[allow(non_snake_case)]
pub mod PriorityClass {
    pub const IDLE_PRIORITY_CLASS: u8 = 1;
    pub const BELOW_NORMAL_PRIORITY_CLASS: u8 = 5;
    pub const NORMAL_PRIORITY_CLASS: u8 = 2;
    pub const ABOVE_NORMAL_PRIORITY_CLASS: u8 = 3;
    pub const HIGH_PRIORITY_CLASS: u8 = 4;
    pub const REALTIME_PRIORITY_CLASS: u8 = 6;
}

/// Base priority for each priority class
fn priority_class_to_base_priority(class: u8) -> i8 {
    match class {
        PriorityClass::IDLE_PRIORITY_CLASS => 4,
        PriorityClass::BELOW_NORMAL_PRIORITY_CLASS => 6,
        PriorityClass::NORMAL_PRIORITY_CLASS => 8,
        PriorityClass::ABOVE_NORMAL_PRIORITY_CLASS => 10,
        PriorityClass::HIGH_PRIORITY_CLASS => 13,
        PriorityClass::REALTIME_PRIORITY_CLASS => 24,
        _ => 8, // Default to normal
    }
}

/// PROCESS_ACCESS_TOKEN structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessAccessToken {
    /// Handle to the token
    pub token: usize,
    /// Thread to impersonate (optional)
    pub thread: usize,
}

/// PROCESS_SESSION_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessSessionInformation {
    /// Session ID
    pub session_id: u32,
}

/// PROCESS_FOREGROUND_BACKGROUND structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessForegroundBackground {
    /// TRUE if foreground
    pub foreground: u8,
}

/// NtSetInformationProcess - Set process attributes
///
/// Parameters:
/// - process_handle: Handle to the process (use -1 for current)
/// - process_information_class: Type of information to set
/// - process_information: Pointer to input data
/// - process_information_length: Size of input data
fn sys_set_information_process(
    process_handle: usize,
    process_information_class: usize,
    process_information: usize,
    process_information_length: usize,
    _: usize, _: usize,
) -> isize {
    use crate::ps::EProcess;
    use core::ptr;

    crate::serial_println!("[SYSCALL] NtSetInformationProcess(handle={:#x}, class={}, buf={:#x}, len={})",
        process_handle, process_information_class, process_information, process_information_length);

    // Get the process
    let process_ptr = if process_handle == 0xFFFFFFFF || process_handle == usize::MAX || process_handle == 0 {
        // Current process - get system process for now
        unsafe { crate::ps::ps_lookup_process_by_id(4) }
    } else {
        // Look up by handle
        match unsafe { get_process_id(process_handle) } {
            Some(pid) => unsafe { crate::ps::ps_lookup_process_by_id(pid) },
            None => return 0xC0000008u32 as isize, // STATUS_INVALID_HANDLE
        }
    };

    if process_ptr.is_null() {
        return 0xC0000008u32 as isize; // STATUS_INVALID_HANDLE
    }

    // Validate buffer
    if process_information == 0 && process_information_length > 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    let process = unsafe { &mut *(process_ptr as *mut EProcess) };
    let info_class = process_information_class as u32;

    match info_class {
        // ProcessBasePriority = 5
        ProcessInfoClassSet::ProcessBasePriority => {
            if process_information_length < core::mem::size_of::<i8>() {
                return 0xC0000004u32 as isize; // STATUS_INFO_LENGTH_MISMATCH
            }

            let base_priority = unsafe { *(process_information as *const i8) };

            // Validate priority range (-15 to 15, or 16-31 for realtime)
            if base_priority < -15 || base_priority > 31 {
                return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
            }

            process.pcb.base_priority = base_priority;
            crate::serial_println!("[SYSCALL] SetInformationProcess: base priority = {}", base_priority);

            0
        }

        // ProcessRaisePriority = 6
        ProcessInfoClassSet::ProcessRaisePriority => {
            if process_information_length < core::mem::size_of::<u32>() {
                return 0xC0000004u32 as isize;
            }

            let increment = unsafe { *(process_information as *const u32) };

            // Temporarily boost priority (doesn't persist)
            let new_priority = (process.pcb.base_priority as i32 + increment as i32).min(15) as i8;
            crate::serial_println!("[SYSCALL] SetInformationProcess: raise priority by {} -> {}",
                increment, new_priority);

            // In a real implementation, this would boost all threads temporarily
            0
        }

        // ProcessExceptionPort = 8
        ProcessInfoClassSet::ProcessExceptionPort => {
            if process_information_length < core::mem::size_of::<usize>() {
                return 0xC0000004u32 as isize;
            }

            let port_handle = unsafe { *(process_information as *const usize) };

            // TODO: Validate port handle and store
            process.exception_port = port_handle as *mut u8;
            crate::serial_println!("[SYSCALL] SetInformationProcess: exception port = {:#x}", port_handle);

            0
        }

        // ProcessAccessToken = 9
        ProcessInfoClassSet::ProcessAccessToken => {
            if process_information_length < core::mem::size_of::<ProcessAccessToken>() {
                return 0xC0000004u32 as isize;
            }

            let token_info = unsafe { ptr::read(process_information as *const ProcessAccessToken) };

            // TODO: Validate SeAssignPrimaryTokenPrivilege
            // TODO: Validate token handle and assign
            crate::serial_println!("[SYSCALL] SetInformationProcess: access token = {:#x}", token_info.token);

            // For now, just store the token pointer (would need proper validation)
            process.token = token_info.token as *mut u8;

            0
        }

        // ProcessDefaultHardErrorMode = 12
        ProcessInfoClassSet::ProcessDefaultHardErrorMode => {
            if process_information_length < core::mem::size_of::<u32>() {
                return 0xC0000004u32 as isize;
            }

            let error_mode = unsafe { *(process_information as *const u32) };
            crate::serial_println!("[SYSCALL] SetInformationProcess: hard error mode = {:#x}", error_mode);

            // TODO: Store in process structure
            0
        }

        // ProcessPriorityClass = 18
        ProcessInfoClassSet::ProcessPriorityClass => {
            if process_information_length < core::mem::size_of::<ProcessPriorityClass>() {
                return 0xC0000004u32 as isize;
            }

            let priority_info = unsafe { ptr::read(process_information as *const ProcessPriorityClass) };
            let new_base_priority = priority_class_to_base_priority(priority_info.priority_class);

            process.pcb.base_priority = new_base_priority;
            crate::serial_println!("[SYSCALL] SetInformationProcess: priority class {} (foreground={}) -> base {}",
                priority_info.priority_class, priority_info.foreground, new_base_priority);

            0
        }

        // ProcessAffinityMask = 21
        ProcessInfoClassSet::ProcessAffinityMask => {
            if process_information_length < core::mem::size_of::<u64>() {
                return 0xC0000004u32 as isize;
            }

            let affinity = unsafe { *(process_information as *const u64) };

            // Validate affinity (must have at least one processor)
            if affinity == 0 {
                return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
            }

            process.pcb.affinity = affinity;
            crate::serial_println!("[SYSCALL] SetInformationProcess: affinity mask = {:#x}", affinity);

            // TODO: Update all threads in the process to respect new affinity
            0
        }

        // ProcessPriorityBoost = 22
        ProcessInfoClassSet::ProcessPriorityBoost => {
            if process_information_length < core::mem::size_of::<u32>() {
                return 0xC0000004u32 as isize;
            }

            let disable_boost = unsafe { *(process_information as *const u32) };
            crate::serial_println!("[SYSCALL] SetInformationProcess: priority boost disabled = {}",
                disable_boost != 0);

            // TODO: Store boost disable flag in process
            0
        }

        // ProcessSessionInformation = 24
        ProcessInfoClassSet::ProcessSessionInformation => {
            if process_information_length < core::mem::size_of::<ProcessSessionInformation>() {
                return 0xC0000004u32 as isize;
            }

            let session_info = unsafe { ptr::read(process_information as *const ProcessSessionInformation) };

            process.session_id = session_info.session_id;
            crate::serial_println!("[SYSCALL] SetInformationProcess: session ID = {}", session_info.session_id);

            0
        }

        // ProcessBreakOnTermination = 29
        ProcessInfoClassSet::ProcessBreakOnTermination => {
            if process_information_length < core::mem::size_of::<u32>() {
                return 0xC0000004u32 as isize;
            }

            let break_on_term = unsafe { *(process_information as *const u32) };

            // Set or clear the critical process flag
            use crate::ps::eprocess::process_flags::PS_PROCESS_FLAGS_SYSTEM;
            if break_on_term != 0 {
                process.flags.fetch_or(PS_PROCESS_FLAGS_SYSTEM, core::sync::atomic::Ordering::SeqCst);
            } else {
                process.flags.fetch_and(!PS_PROCESS_FLAGS_SYSTEM, core::sync::atomic::Ordering::SeqCst);
            }

            crate::serial_println!("[SYSCALL] SetInformationProcess: break on termination = {}",
                break_on_term != 0);

            0
        }

        // ProcessExecuteFlags = 34 (DEP settings)
        ProcessInfoClassSet::ProcessExecuteFlags => {
            if process_information_length < core::mem::size_of::<u32>() {
                return 0xC0000004u32 as isize;
            }

            let execute_flags = unsafe { *(process_information as *const u32) };
            crate::serial_println!("[SYSCALL] SetInformationProcess: execute flags (DEP) = {:#x}",
                execute_flags);

            // TODO: Store DEP flags in process
            0
        }

        // ProcessDebugPort = 7
        ProcessInfoClassSet::ProcessDebugPort => {
            if process_information_length < core::mem::size_of::<usize>() {
                return 0xC0000004u32 as isize;
            }

            let debug_port = unsafe { *(process_information as *const usize) };
            process.debug_port = debug_port as *mut u8;
            crate::serial_println!("[SYSCALL] SetInformationProcess: debug port = {:#x}", debug_port);

            0
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtSetInformationProcess: unsupported class {}", info_class);
            0xC0000003u32 as isize // STATUS_INVALID_INFO_CLASS
        }
    }
}

/// Thread information classes for Set operations
#[allow(non_snake_case, non_upper_case_globals)]
pub mod set_thread_info_class {
    /// Set thread priority (relative: -15 to +15)
    pub const ThreadPriority: u32 = 1;
    /// Set thread base priority
    pub const ThreadBasePriority: u32 = 3;
    /// Set thread CPU affinity mask
    pub const ThreadAffinityMask: u32 = 4;
    /// Set thread impersonation token
    pub const ThreadImpersonationToken: u32 = 5;
    /// Enable/disable alignment fault fixup
    pub const ThreadEnableAlignmentFaultFixup: u32 = 7;
    /// Set Win32 start address
    pub const ThreadQuerySetWin32StartAddress: u32 = 9;
    /// Zero a specific TLS cell
    pub const ThreadZeroTlsCell: u32 = 10;
    /// Set ideal processor hint
    pub const ThreadIdealProcessor: u32 = 13;
    /// Set/disable priority boost
    pub const ThreadPriorityBoost: u32 = 14;
    /// Set TLS array address
    pub const ThreadSetTlsArrayAddress: u32 = 15;
    /// Hide thread from debugger
    pub const ThreadHideFromDebugger: u32 = 17;
    /// Set break on termination flag (critical thread)
    pub const ThreadBreakOnTermination: u32 = 18;
    /// Switch legacy state
    pub const ThreadSwitchLegacyState: u32 = 19;
    /// Set I/O priority
    pub const ThreadIoPriority: u32 = 22;
    /// Set page priority
    pub const ThreadPagePriority: u32 = 24;
    /// Set actual base priority
    pub const ThreadActualBasePriority: u32 = 25;
    /// Set processor group affinity
    pub const ThreadGroupInformation: u32 = 30;
    /// Set ideal processor (extended)
    pub const ThreadIdealProcessorEx: u32 = 33;
    /// Set power throttling state
    pub const ThreadPowerThrottlingState: u32 = 49;

    // Legacy uppercase names for compatibility
    pub const THREAD_PRIORITY: u32 = 1;
    pub const THREAD_BASE_PRIORITY: u32 = 3;
    pub const THREAD_AFFINITY_MASK: u32 = 4;
    pub const THREAD_IMPERSONATION_TOKEN: u32 = 5;
    pub const THREAD_IDEAL_PROCESSOR: u32 = 13;
    pub const THREAD_ZERO_TLS_CELL: u32 = 10;
    pub const THREAD_BREAK_ON_TERMINATION: u32 = 18;
    pub const THREAD_HIDE_FROM_DEBUGGER: u32 = 17;
}

/// Thread priority boost structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadPriorityBoostInfo {
    /// TRUE to disable priority boost
    pub disable_boost: u32,
}

/// Thread I/O priority hint
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadIoPriorityInfo {
    /// I/O priority level (0-4)
    pub io_priority: u32,
}

/// I/O priority levels
#[allow(non_snake_case, non_upper_case_globals)]
pub mod IoPriority {
    pub const IoPriorityVeryLow: u32 = 0;
    pub const IoPriorityLow: u32 = 1;
    pub const IoPriorityNormal: u32 = 2;
    pub const IoPriorityHigh: u32 = 3;
    pub const IoPriorityCritical: u32 = 4;
}

/// Thread page priority info
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadPagePriorityInfo {
    /// Page priority (0-7, default 5)
    pub page_priority: u32,
}

/// Thread group affinity
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GroupAffinity {
    /// Affinity mask within the group
    pub mask: u64,
    /// Processor group number
    pub group: u16,
    /// Reserved
    pub reserved: [u16; 3],
}

/// Processor number (extended ideal processor)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessorNumber {
    /// Processor group
    pub group: u16,
    /// Processor number within group
    pub number: u8,
    /// Reserved
    pub reserved: u8,
}

/// NtSetInformationThread - Set thread attributes
///
/// Sets information for a thread based on the specified information class.
///
/// # Arguments
/// * `thread_handle` - Handle to the thread (0xFFFFFFFE = current thread)
/// * `thread_information_class` - Type of information to set
/// * `thread_information` - Buffer containing the information
/// * `thread_information_length` - Size of the buffer
fn sys_set_information_thread(
    thread_handle: usize,
    thread_information_class: usize,
    thread_information: usize,
    thread_information_length: usize,
    _: usize, _: usize,
) -> isize {
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;
    const STATUS_INFO_LENGTH_MISMATCH: isize = 0xC0000004u32 as isize;
    const STATUS_INVALID_PARAMETER: isize = 0xC000000Du32 as isize;
    const STATUS_INVALID_INFO_CLASS: isize = 0xC0000003u32 as isize;
    const STATUS_ACCESS_DENIED: isize = 0xC0000022u32 as isize;

    // Get thread ID from handle
    // Special handle -2 (0xFFFFFFFE) means current thread
    let tid = if thread_handle == 0xFFFFFFFE || thread_handle == (usize::MAX - 1) {
        unsafe {
            let prcb = crate::ke::prcb::get_current_prcb();
            if !prcb.current_thread.is_null() {
                (*prcb.current_thread).thread_id
            } else {
                return STATUS_INVALID_HANDLE;
            }
        }
    } else if thread_handle == 0 {
        return STATUS_INVALID_HANDLE;
    } else {
        match unsafe { get_thread_id(thread_handle) } {
            Some(t) => t,
            None => return STATUS_INVALID_HANDLE,
        }
    };

    // Validate buffer
    if thread_information == 0 && thread_information_length > 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Look up thread structure
    let thread = unsafe { crate::ps::cid::ps_lookup_thread_by_id(tid) };
    let ethread = thread as *mut crate::ps::EThread;

    crate::serial_println!("[SYSCALL] NtSetInformationThread(tid={}, class={})",
        tid, thread_information_class);

    match thread_information_class as u32 {
        // Class 1: ThreadPriority (relative priority -15 to +15)
        set_thread_info_class::ThreadPriority => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let priority = unsafe { *(thread_information as *const i32) };

            // Validate priority range (-15 to +15 for relative priority)
            if priority < -15 || priority > 15 {
                return STATUS_INVALID_PARAMETER;
            }

            crate::serial_println!("[SYSCALL] SetInformationThread: priority delta = {}", priority);

            // Apply priority delta to thread
            if !ethread.is_null() {
                unsafe {
                    let tcb = (*ethread).get_tcb_mut();
                    let new_priority = ((*tcb).base_priority as i32 + priority)
                        .clamp(0, 31) as i8;
                    (*tcb).priority = new_priority;
                }
            }

            STATUS_SUCCESS
        }

        // Class 3: ThreadBasePriority
        set_thread_info_class::ThreadBasePriority => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let base_priority = unsafe { *(thread_information as *const i32) };

            // Validate base priority range (0-31)
            if base_priority < 0 || base_priority > 31 {
                return STATUS_INVALID_PARAMETER;
            }

            crate::serial_println!("[SYSCALL] SetInformationThread: base priority = {}", base_priority);

            if !ethread.is_null() {
                unsafe {
                    let tcb = (*ethread).get_tcb_mut();
                    (*tcb).base_priority = base_priority as i8;
                    // Also update current priority if not boosted
                    if (*tcb).priority < base_priority as i8 {
                        (*tcb).priority = base_priority as i8;
                    }
                }
            }

            STATUS_SUCCESS
        }

        // Class 4: ThreadAffinityMask
        set_thread_info_class::ThreadAffinityMask => {
            if thread_information_length < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let affinity = unsafe { *(thread_information as *const u64) };

            // Affinity must have at least one bit set
            if affinity == 0 {
                return STATUS_INVALID_PARAMETER;
            }

            crate::serial_println!("[SYSCALL] SetInformationThread: affinity = {:#x}", affinity);

            // For now, we only support single processor, so any affinity with bit 0 is valid
            if (affinity & 1) == 0 {
                return STATUS_INVALID_PARAMETER;
            }

            // TODO: Store affinity mask in thread structure when multi-processor support added

            STATUS_SUCCESS
        }

        // Class 5: ThreadImpersonationToken
        set_thread_info_class::ThreadImpersonationToken => {
            if thread_information_length < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let token_handle = unsafe { *(thread_information as *const usize) };

            crate::serial_println!("[SYSCALL] SetInformationThread: impersonation token = {:#x}",
                token_handle);

            if !ethread.is_null() {
                unsafe {
                    if token_handle == 0 {
                        // Clear impersonation
                        (*ethread).impersonation_info = core::ptr::null_mut();
                        (*ethread).clear_flag(crate::ps::ethread::thread_flags::PS_THREAD_FLAGS_IMPERSONATING);
                    } else {
                        // Set impersonation token
                        // TODO: Look up token from handle and validate
                        (*ethread).impersonation_info = token_handle as *mut u8;
                        (*ethread).set_flag(crate::ps::ethread::thread_flags::PS_THREAD_FLAGS_IMPERSONATING);
                    }
                }
            }

            STATUS_SUCCESS
        }

        // Class 7: ThreadEnableAlignmentFaultFixup
        set_thread_info_class::ThreadEnableAlignmentFaultFixup => {
            if thread_information_length < 1 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let enable = unsafe { *(thread_information as *const u8) };

            crate::serial_println!("[SYSCALL] SetInformationThread: alignment fault fixup = {}",
                enable != 0);

            // TODO: Store alignment fault fixup flag
            // This affects how unaligned memory accesses are handled

            STATUS_SUCCESS
        }

        // Class 9: ThreadQuerySetWin32StartAddress
        set_thread_info_class::ThreadQuerySetWin32StartAddress => {
            if thread_information_length < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let start_address = unsafe { *(thread_information as *const u64) };

            crate::serial_println!("[SYSCALL] SetInformationThread: Win32 start address = {:#x}",
                start_address);

            if !ethread.is_null() {
                unsafe {
                    (*ethread).win32_start_address = start_address as *mut u8;
                }
            }

            STATUS_SUCCESS
        }

        // Class 10: ThreadZeroTlsCell
        set_thread_info_class::ThreadZeroTlsCell => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let tls_index = unsafe { *(thread_information as *const u32) };

            crate::serial_println!("[SYSCALL] SetInformationThread: zero TLS cell {}", tls_index);

            // TODO: Zero the specified TLS slot in the thread's TEB
            // This requires access to the TEB structure

            STATUS_SUCCESS
        }

        // Class 13: ThreadIdealProcessor
        set_thread_info_class::ThreadIdealProcessor => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let ideal_proc = unsafe { *(thread_information as *const u32) };

            crate::serial_println!("[SYSCALL] SetInformationThread: ideal processor = {}", ideal_proc);

            // For single processor system, only processor 0 is valid
            // Special value MAXIMUM_PROCESSORS (0xFF) means no preference
            if ideal_proc != 0 && ideal_proc != 0xFF {
                // We only have one processor, but accept the request
                crate::serial_println!("[SYSCALL] Warning: ideal processor {} not available", ideal_proc);
            }

            // TODO: Store ideal processor hint for scheduler

            STATUS_SUCCESS
        }

        // Class 14: ThreadPriorityBoost
        set_thread_info_class::ThreadPriorityBoost => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let disable_boost = unsafe { *(thread_information as *const u32) };

            crate::serial_println!("[SYSCALL] SetInformationThread: priority boost disabled = {}",
                disable_boost != 0);

            // TODO: Store priority boost disable flag in thread
            // When set, the thread won't receive temporary priority boosts

            STATUS_SUCCESS
        }

        // Class 15: ThreadSetTlsArrayAddress
        set_thread_info_class::ThreadSetTlsArrayAddress => {
            if thread_information_length < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let tls_array = unsafe { *(thread_information as *const u64) };

            crate::serial_println!("[SYSCALL] SetInformationThread: TLS array address = {:#x}",
                tls_array);

            // TODO: Set TLS expansion slots array address in TEB

            STATUS_SUCCESS
        }

        // Class 17: ThreadHideFromDebugger
        set_thread_info_class::ThreadHideFromDebugger => {
            // This class takes no input data - just sets a flag
            crate::serial_println!("[SYSCALL] SetInformationThread: hide from debugger");

            // TODO: Set hidden from debugger flag
            // This makes the thread invisible to debugger enumeration

            STATUS_SUCCESS
        }

        // Class 18: ThreadBreakOnTermination
        set_thread_info_class::ThreadBreakOnTermination => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let break_on_term = unsafe { *(thread_information as *const u32) };

            crate::serial_println!("[SYSCALL] SetInformationThread: break on termination = {}",
                break_on_term != 0);

            // Setting this requires SeDebugPrivilege in real NT
            // For now, we allow it

            // TODO: Set critical thread flag - if set, terminating this thread
            // will cause a system crash (bugcheck)

            STATUS_SUCCESS
        }

        // Class 19: ThreadSwitchLegacyState
        set_thread_info_class::ThreadSwitchLegacyState => {
            crate::serial_println!("[SYSCALL] SetInformationThread: switch legacy state");

            // This is used for x87 FPU state management
            // Not critical for basic functionality

            STATUS_SUCCESS
        }

        // Class 22: ThreadIoPriority
        set_thread_info_class::ThreadIoPriority => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let io_priority = unsafe { *(thread_information as *const u32) };

            // Validate I/O priority (0-4)
            if io_priority > IoPriority::IoPriorityCritical {
                return STATUS_INVALID_PARAMETER;
            }

            crate::serial_println!("[SYSCALL] SetInformationThread: I/O priority = {}", io_priority);

            // TODO: Store I/O priority for I/O scheduling

            STATUS_SUCCESS
        }

        // Class 24: ThreadPagePriority
        set_thread_info_class::ThreadPagePriority => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let page_priority = unsafe { *(thread_information as *const u32) };

            // Validate page priority (0-7)
            if page_priority > 7 {
                return STATUS_INVALID_PARAMETER;
            }

            crate::serial_println!("[SYSCALL] SetInformationThread: page priority = {}", page_priority);

            // TODO: Store page priority for memory management

            STATUS_SUCCESS
        }

        // Class 25: ThreadActualBasePriority
        set_thread_info_class::ThreadActualBasePriority => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let actual_base = unsafe { *(thread_information as *const i32) };

            // Validate priority (0-31)
            if actual_base < 0 || actual_base > 31 {
                return STATUS_INVALID_PARAMETER;
            }

            crate::serial_println!("[SYSCALL] SetInformationThread: actual base priority = {}",
                actual_base);

            if !ethread.is_null() {
                unsafe {
                    let tcb = (*ethread).get_tcb_mut();
                    (*tcb).base_priority = actual_base as i8;
                    (*tcb).priority = actual_base as i8;
                }
            }

            STATUS_SUCCESS
        }

        // Class 30: ThreadGroupInformation
        set_thread_info_class::ThreadGroupInformation => {
            if thread_information_length < core::mem::size_of::<GroupAffinity>() {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let group_affinity = unsafe { &*(thread_information as *const GroupAffinity) };

            crate::serial_println!(
                "[SYSCALL] SetInformationThread: group {} affinity = {:#x}",
                group_affinity.group, group_affinity.mask
            );

            // We only support group 0
            if group_affinity.group != 0 {
                return STATUS_INVALID_PARAMETER;
            }

            // Mask must have at least one bit set and include processor 0
            if group_affinity.mask == 0 || (group_affinity.mask & 1) == 0 {
                return STATUS_INVALID_PARAMETER;
            }

            STATUS_SUCCESS
        }

        // Class 33: ThreadIdealProcessorEx
        set_thread_info_class::ThreadIdealProcessorEx => {
            if thread_information_length < core::mem::size_of::<ProcessorNumber>() {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let proc_num = unsafe { &*(thread_information as *const ProcessorNumber) };

            crate::serial_println!(
                "[SYSCALL] SetInformationThread: ideal processor group {} number {}",
                proc_num.group, proc_num.number
            );

            // We only support group 0, processor 0
            if proc_num.group != 0 {
                return STATUS_INVALID_PARAMETER;
            }

            STATUS_SUCCESS
        }

        // Class 49: ThreadPowerThrottlingState
        set_thread_info_class::ThreadPowerThrottlingState => {
            crate::serial_println!("[SYSCALL] SetInformationThread: power throttling state");

            // Power throttling is a Windows 10+ feature
            // Accept but ignore for compatibility

            STATUS_SUCCESS
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtSetInformationThread: unsupported class {}",
                thread_information_class);
            STATUS_INVALID_INFO_CLASS
        }
    }
}

/// Object information classes for Set operations
pub mod set_object_info_class {
    pub const OBJECT_FLAGS_INFORMATION: u32 = 4;
}

/// NtSetInformationObject - Set object attributes
fn sys_set_information_object(
    handle: usize,
    object_information_class: usize,
    object_information: usize,
    object_information_length: usize,
    _: usize, _: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtSetInformationObject(handle={:#x}, class={})",
        handle, object_information_class);

    if object_information == 0 && object_information_length > 0 {
        return -1;
    }

    match object_information_class as u32 {
        set_object_info_class::OBJECT_FLAGS_INFORMATION => {
            if object_information_length < 4 {
                return -1;
            }

            // Object flags structure:
            // BOOLEAN Inherit
            // BOOLEAN ProtectFromClose
            let flags = unsafe { *(object_information as *const u32) };
            let inherit = (flags & 1) != 0;
            let protect_from_close = (flags & 2) != 0;

            crate::serial_println!("[SYSCALL] SetInformationObject: inherit={}, protect={}",
                inherit, protect_from_close);

            // TODO: Store flags in handle table entry

            0
        }
        _ => {
            crate::serial_println!("[SYSCALL] NtSetInformationObject: unsupported class {}",
                object_information_class);
            -1
        }
    }
}

/// Token information classes for Set operations
pub mod set_token_info_class {
    pub const TOKEN_OWNER: u32 = 4;
    pub const TOKEN_PRIMARY_GROUP: u32 = 5;
    pub const TOKEN_DEFAULT_DACL: u32 = 6;
    pub const TOKEN_SESSION_ID: u32 = 12;
    pub const TOKEN_SESSION_REFERENCE: u32 = 14;
    pub const TOKEN_ORIGIN: u32 = 17;
}

/// NtSetInformationToken - Set token attributes
fn sys_set_information_token(
    token_handle: usize,
    token_information_class: usize,
    token_information: usize,
    token_information_length: usize,
    _: usize, _: usize,
) -> isize {
    let token_id = match unsafe { get_token_id(token_handle) } {
        Some(t) => t,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtSetInformationToken(token={}, class={})",
        token_id, token_information_class);

    if token_information == 0 && token_information_length > 0 {
        return -1;
    }

    match token_information_class as u32 {
        set_token_info_class::TOKEN_OWNER => {
            if token_information_length < 8 {
                return -1;
            }

            // TOKEN_OWNER contains a pointer to SID
            let owner_sid_ptr = unsafe { *(token_information as *const usize) };
            crate::serial_println!("[SYSCALL] SetInformationToken: owner SID at {:#x}",
                owner_sid_ptr);

            // TODO: Validate SID and update token owner

            0
        }
        set_token_info_class::TOKEN_PRIMARY_GROUP => {
            if token_information_length < 8 {
                return -1;
            }

            let group_sid_ptr = unsafe { *(token_information as *const usize) };
            crate::serial_println!("[SYSCALL] SetInformationToken: primary group SID at {:#x}",
                group_sid_ptr);

            // TODO: Validate SID and update token primary group

            0
        }
        set_token_info_class::TOKEN_DEFAULT_DACL => {
            // TOKEN_DEFAULT_DACL contains ACL pointer (can be NULL to remove)
            crate::serial_println!("[SYSCALL] SetInformationToken: default DACL");

            // TODO: Validate ACL and update token default DACL

            0
        }
        set_token_info_class::TOKEN_SESSION_ID => {
            if token_information_length < 4 {
                return -1;
            }

            let session_id = unsafe { *(token_information as *const u32) };
            crate::serial_println!("[SYSCALL] SetInformationToken: session ID = {}", session_id);

            // Requires SeTcbPrivilege to change
            // TODO: Validate privilege and update token session ID

            0
        }
        set_token_info_class::TOKEN_ORIGIN => {
            if token_information_length < 8 {
                return -1;
            }

            // TOKEN_ORIGIN contains LUID of originating logon session
            let origin_luid = unsafe { *(token_information as *const u64) };
            crate::serial_println!("[SYSCALL] SetInformationToken: origin LUID = {:#x}", origin_luid);

            // TODO: Store origin LUID

            0
        }
        _ => {
            crate::serial_println!("[SYSCALL] NtSetInformationToken: unsupported class {}",
                token_information_class);
            -1
        }
    }
}

/// NtAdjustGroupsToken - Enable/disable token groups
fn sys_adjust_groups_token(
    token_handle: usize,
    reset_to_default: usize,
    new_state: usize,
    buffer_length: usize,
    previous_state: usize,
    return_length: usize,
) -> isize {
    let token_id = match unsafe { get_token_id(token_handle) } {
        Some(t) => t,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtAdjustGroupsToken(token={}, reset={})",
        token_id, reset_to_default != 0);

    if reset_to_default != 0 {
        // Reset all groups to their default enabled state
        crate::serial_println!("[SYSCALL] AdjustGroupsToken: resetting to defaults");
        // TODO: Reset group enabled flags to defaults

        if return_length != 0 {
            unsafe { *(return_length as *mut usize) = 0; }
        }
        return 0;
    }

    // new_state points to TOKEN_GROUPS structure
    if new_state == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // TOKEN_GROUPS structure:
    // ULONG GroupCount
    // SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY]
    let group_count = unsafe { *(new_state as *const u32) };
    crate::serial_println!("[SYSCALL] AdjustGroupsToken: {} groups", group_count);

    let _ = buffer_length;
    let _ = previous_state;

    // TODO: Process each group and enable/disable accordingly
    // Groups with SE_GROUP_USE_FOR_DENY_ONLY cannot be enabled

    if return_length != 0 {
        unsafe { *(return_length as *mut usize) = 0; }
    }

    0
}

/// NtImpersonateThread - Impersonate another thread's security context
fn sys_impersonate_thread(
    server_thread_handle: usize,
    client_thread_handle: usize,
    security_qos: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    let server_tid = if server_thread_handle == 0xFFFFFFFE || server_thread_handle == (usize::MAX - 1) {
        // Current thread
        unsafe {
            let prcb = crate::ke::prcb::get_current_prcb();
            if !prcb.current_thread.is_null() {
                (*prcb.current_thread).thread_id
            } else {
                0
            }
        }
    } else {
        match unsafe { get_thread_id(server_thread_handle) } {
            Some(t) => t,
            None => return -1,
        }
    };

    let client_tid = match unsafe { get_thread_id(client_thread_handle) } {
        Some(t) => t,
        None => return -1, // STATUS_INVALID_HANDLE
    };

    crate::serial_println!("[SYSCALL] NtImpersonateThread(server={}, client={})",
        server_tid, client_tid);

    // security_qos points to SECURITY_QUALITY_OF_SERVICE
    // Contains: Length, ImpersonationLevel, ContextTrackingMode, EffectiveOnly
    if security_qos != 0 {
        let length = unsafe { *(security_qos as *const u32) };
        if length >= 8 {
            let impersonation_level = unsafe { *((security_qos + 4) as *const u32) };
            crate::serial_println!("[SYSCALL] ImpersonateThread: level = {}", impersonation_level);
            // Levels: 0=Anonymous, 1=Identification, 2=Impersonation, 3=Delegation
        }
    }

    // TODO: Implement actual impersonation:
    // 1. Get client thread's effective token
    // 2. Duplicate it as an impersonation token
    // 3. Set it on the server thread

    0
}

// ============================================================================
// Virtual Memory Extended Operations
// ============================================================================

/// NtFlushVirtualMemory - Flush modified pages to backing store
fn sys_flush_virtual_memory(
    process_handle: usize,
    base_address: usize,
    region_size: usize,
    io_status: usize,
    _: usize, _: usize,
) -> isize {
    let _ = process_handle;

    crate::serial_println!("[SYSCALL] NtFlushVirtualMemory(base={:#x}, size={:#x})",
        base_address, region_size);

    // For memory-mapped files, this would write dirty pages to disk
    // For now, just succeed

    if io_status != 0 {
        unsafe {
            // IO_STATUS_BLOCK: Status, Information
            *(io_status as *mut i32) = 0; // STATUS_SUCCESS
            *((io_status + 8) as *mut usize) = region_size;
        }
    }

    0
}

/// NtLockVirtualMemory - Lock pages in physical memory
fn sys_lock_virtual_memory(
    process_handle: usize,
    base_address_ptr: usize,
    region_size_ptr: usize,
    map_type: usize,
    _: usize, _: usize,
) -> isize {
    let _ = process_handle;

    if base_address_ptr == 0 || region_size_ptr == 0 {
        return -1;
    }

    let base = unsafe { *(base_address_ptr as *const usize) };
    let size = unsafe { *(region_size_ptr as *const usize) };

    crate::serial_println!("[SYSCALL] NtLockVirtualMemory(base={:#x}, size={:#x}, type={})",
        base, size, map_type);

    // map_type: 1 = MAP_PROCESS (lock in working set), 2 = MAP_SYSTEM (lock in physical memory)

    // TODO: Actually lock pages
    // Would mark PTEs as non-pageable

    0
}

/// NtUnlockVirtualMemory - Unlock previously locked pages
fn sys_unlock_virtual_memory(
    process_handle: usize,
    base_address_ptr: usize,
    region_size_ptr: usize,
    map_type: usize,
    _: usize, _: usize,
) -> isize {
    let _ = process_handle;

    if base_address_ptr == 0 || region_size_ptr == 0 {
        return -1;
    }

    let base = unsafe { *(base_address_ptr as *const usize) };
    let size = unsafe { *(region_size_ptr as *const usize) };

    crate::serial_println!("[SYSCALL] NtUnlockVirtualMemory(base={:#x}, size={:#x}, type={})",
        base, size, map_type);

    // TODO: Actually unlock pages

    0
}

/// NtReadVirtualMemory - Read memory from another process
fn sys_read_virtual_memory(
    process_handle: usize,
    base_address: usize,
    buffer: usize,
    buffer_size: usize,
    number_of_bytes_read: usize,
    _: usize,
) -> isize {
    let pid = if process_handle == 0xFFFFFFFF || process_handle == usize::MAX {
        // Current process (System = 4)
        4u32
    } else {
        match unsafe { get_process_id(process_handle) } {
            Some(p) => p,
            None => return -1,
        }
    };

    crate::serial_println!("[SYSCALL] NtReadVirtualMemory(pid={}, addr={:#x}, size={})",
        pid, base_address, buffer_size);

    if buffer == 0 || buffer_size == 0 {
        return -1;
    }

    // TODO: Implement cross-process memory read
    // Would need to:
    // 1. Attach to target process address space
    // 2. Validate source address is readable
    // 3. Copy memory
    // 4. Detach

    // For now, if reading from current process, just memcpy
    unsafe {
        core::ptr::copy_nonoverlapping(
            base_address as *const u8,
            buffer as *mut u8,
            buffer_size,
        );
    }

    if number_of_bytes_read != 0 {
        unsafe { *(number_of_bytes_read as *mut usize) = buffer_size; }
    }

    0
}

/// NtWriteVirtualMemory - Write memory to another process
fn sys_write_virtual_memory(
    process_handle: usize,
    base_address: usize,
    buffer: usize,
    buffer_size: usize,
    number_of_bytes_written: usize,
    _: usize,
) -> isize {
    let pid = if process_handle == 0xFFFFFFFF || process_handle == usize::MAX {
        // Current process (System = 4)
        4u32
    } else {
        match unsafe { get_process_id(process_handle) } {
            Some(p) => p,
            None => return -1,
        }
    };

    crate::serial_println!("[SYSCALL] NtWriteVirtualMemory(pid={}, addr={:#x}, size={})",
        pid, base_address, buffer_size);

    if buffer == 0 || buffer_size == 0 {
        return -1;
    }

    // TODO: Implement cross-process memory write
    // Similar to read, but validates write access

    // For now, if writing to current process, just memcpy
    unsafe {
        core::ptr::copy_nonoverlapping(
            buffer as *const u8,
            base_address as *mut u8,
            buffer_size,
        );
    }

    if number_of_bytes_written != 0 {
        unsafe { *(number_of_bytes_written as *mut usize) = buffer_size; }
    }

    0
}

// ============================================================================
// Debug Object Support
// ============================================================================

/// Debug object handle base
const DEBUG_HANDLE_BASE: usize = 0x7000;
const MAX_DEBUG_HANDLES: usize = 64;

/// Debug object table
static mut DEBUG_OBJECTS: [u32; MAX_DEBUG_HANDLES] = [0; MAX_DEBUG_HANDLES];

/// Allocate a debug handle
unsafe fn alloc_debug_handle(debugged_pid: u32) -> Option<usize> {
    for i in 0..MAX_DEBUG_HANDLES {
        if DEBUG_OBJECTS[i] == 0 {
            DEBUG_OBJECTS[i] = debugged_pid;
            return Some(i + DEBUG_HANDLE_BASE);
        }
    }
    None
}

/// Get debugged process from debug handle
unsafe fn get_debug_object(handle: usize) -> Option<u32> {
    if handle >= DEBUG_HANDLE_BASE && handle < DEBUG_HANDLE_BASE + MAX_DEBUG_HANDLES {
        let idx = handle - DEBUG_HANDLE_BASE;
        if DEBUG_OBJECTS[idx] != 0 {
            return Some(DEBUG_OBJECTS[idx]);
        }
    }
    None
}

/// Free a debug handle
unsafe fn free_debug_handle(handle: usize) {
    if handle >= DEBUG_HANDLE_BASE && handle < DEBUG_HANDLE_BASE + MAX_DEBUG_HANDLES {
        let idx = handle - DEBUG_HANDLE_BASE;
        DEBUG_OBJECTS[idx] = 0;
    }
}

/// NtCreateDebugObject - Create a debug object for debugging processes
fn sys_create_debug_object(
    debug_object_handle: usize,
    desired_access: usize,
    _object_attributes: usize,
    flags: usize,
    _: usize, _: usize,
) -> isize {
    if debug_object_handle == 0 {
        return -1;
    }

    crate::serial_println!("[SYSCALL] NtCreateDebugObject(access={:#x}, flags={:#x})",
        desired_access, flags);

    // flags: DEBUG_KILL_ON_CLOSE (0x1) - terminate debugged process when debug object closed

    // Allocate debug object (placeholder PID 0 until attached)
    let handle = unsafe { alloc_debug_handle(0) };

    match handle {
        Some(h) => {
            unsafe { *(debug_object_handle as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtCreateDebugObject -> handle {:#x}", h);
            0
        }
        None => -1,
    }
}

/// NtDebugActiveProcess - Attach debugger to a process
fn sys_debug_active_process(
    process_handle: usize,
    debug_object_handle: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    let pid = match unsafe { get_process_id(process_handle) } {
        Some(p) => p,
        None => return -1,
    };

    let _ = match unsafe { get_debug_object(debug_object_handle) } {
        Some(_) => (),
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtDebugActiveProcess(pid={}, debug_handle={:#x})",
        pid, debug_object_handle);

    // Update debug object with target PID
    let idx = debug_object_handle - DEBUG_HANDLE_BASE;
    unsafe {
        if idx < MAX_DEBUG_HANDLES {
            DEBUG_OBJECTS[idx] = pid;
        }
    }

    // TODO: Actually attach debugger
    // Would set process->debug_port and generate initial debug events

    0
}

/// NtRemoveProcessDebug - Detach debugger from process
fn sys_remove_process_debug(
    process_handle: usize,
    debug_object_handle: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    let pid = match unsafe { get_process_id(process_handle) } {
        Some(p) => p,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtRemoveProcessDebug(pid={}, debug_handle={:#x})",
        pid, debug_object_handle);

    // TODO: Actually detach debugger
    // Would clear process->debug_port

    0
}

/// NtWaitForDebugEvent - Wait for debug event from debugged process
fn sys_wait_for_debug_event(
    debug_object_handle: usize,
    alertable: usize,
    timeout: usize,
    wait_state_change: usize,
    _: usize, _: usize,
) -> isize {
    let debugged_pid = match unsafe { get_debug_object(debug_object_handle) } {
        Some(p) => p,
        None => return -1,
    };

    crate::serial_println!("[SYSCALL] NtWaitForDebugEvent(pid={}, alertable={}, timeout={:#x})",
        debugged_pid, alertable != 0, timeout);

    if wait_state_change == 0 {
        return -1;
    }

    // TODO: Actually wait for and return debug events
    // Would block until breakpoint, exception, thread create/exit, etc.

    // For now, just return timeout
    0x102 // STATUS_TIMEOUT
}

/// NtDebugContinue - Continue from debug event
fn sys_debug_continue(
    debug_object_handle: usize,
    client_id: usize,
    continue_status: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    let debugged_pid = match unsafe { get_debug_object(debug_object_handle) } {
        Some(p) => p,
        None => return -1,
    };

    let (pid, tid) = if client_id != 0 {
        unsafe {
            (*(client_id as *const u32), *((client_id + 4) as *const u32))
        }
    } else {
        (debugged_pid, 0)
    };

    crate::serial_println!("[SYSCALL] NtDebugContinue(pid={}, tid={}, status={:#x})",
        pid, tid, continue_status);

    // continue_status: DBG_CONTINUE (0x10002) or DBG_EXCEPTION_NOT_HANDLED (0x80010001)

    // TODO: Actually continue the debugged thread

    0
}

// ============================================================================
// Exception Handling Syscalls
// ============================================================================

/// NtRaiseException - Raise an exception in the current thread
fn sys_raise_exception(
    exception_record: usize,
    context_record: usize,
    first_chance: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    use crate::ke::exception::{ExceptionRecord, Context, ke_raise_exception};

    if exception_record == 0 || context_record == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    let is_first_chance = first_chance != 0;

    crate::serial_println!("[SYSCALL] NtRaiseException(first_chance={})", is_first_chance);

    unsafe {
        let exception = exception_record as *const ExceptionRecord;
        let context = context_record as *mut Context;

        crate::serial_println!("[SYSCALL] NtRaiseException: code={:#x} addr={:p}",
            (*exception).exception_code,
            (*exception).exception_address);

        ke_raise_exception(exception, context, is_first_chance) as isize
    }
}

/// NtContinue - Continue execution from an exception handler
fn sys_continue(
    context_record: usize,
    test_alert: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ke::exception::{Context, ke_continue};

    if context_record == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    let should_test_alert = test_alert != 0;

    crate::serial_println!("[SYSCALL] NtContinue(test_alert={})", should_test_alert);

    unsafe {
        let context = context_record as *const Context;
        ke_continue(context, should_test_alert) as isize
    }
}

/// NtGetContextThread - Get a thread's context
fn sys_get_context_thread(
    thread_handle: usize,
    context: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ke::exception::{Context, ke_get_context};

    if context == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    crate::serial_println!("[SYSCALL] NtGetContextThread(handle={:#x})", thread_handle);

    // For now, we only support getting the current thread's context
    // Full implementation would look up the thread by handle
    let prcb = unsafe { crate::ke::prcb::get_current_prcb_mut() };
    let current_handle = if prcb.current_thread.is_null() {
        0
    } else {
        // Get thread ID as pseudo-handle comparison
        unsafe { (*prcb.current_thread).thread_id as usize }
    };

    // Handle value -2 (0xFFFFFFFE) means current thread
    if thread_handle != 0xFFFFFFFE && thread_handle != current_handle {
        // For non-current thread, we'd need to suspend and read its context
        // For now, only support current thread
        crate::serial_println!("[SYSCALL] NtGetContextThread: non-current thread not yet supported");
        return 0xC0000001u32 as isize; // STATUS_UNSUCCESSFUL
    }

    unsafe {
        let ctx = context as *mut Context;
        let flags = (*ctx).context_flags;

        crate::serial_println!("[SYSCALL] NtGetContextThread: flags={:#x}", flags);

        ke_get_context(ctx, flags) as isize
    }
}

/// NtSetContextThread - Set a thread's context
fn sys_set_context_thread(
    thread_handle: usize,
    context: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ke::exception::{Context, ke_set_context};

    if context == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    crate::serial_println!("[SYSCALL] NtSetContextThread(handle={:#x})", thread_handle);

    // For now, we only support setting the current thread's context
    // Full implementation would look up the thread by handle
    let prcb = unsafe { crate::ke::prcb::get_current_prcb_mut() };
    let current_handle = if prcb.current_thread.is_null() {
        0
    } else {
        unsafe { (*prcb.current_thread).thread_id as usize }
    };

    // Handle value -2 (0xFFFFFFFE) means current thread
    if thread_handle != 0xFFFFFFFE && thread_handle != current_handle {
        // For non-current thread, we'd need to suspend and modify its context
        crate::serial_println!("[SYSCALL] NtSetContextThread: non-current thread not yet supported");
        return 0xC0000001u32 as isize; // STATUS_UNSUCCESSFUL
    }

    unsafe {
        let ctx = context as *const Context;

        crate::serial_println!("[SYSCALL] NtSetContextThread: flags={:#x}", (*ctx).context_flags);

        ke_set_context(ctx) as isize
    }
}

// ============================================================================
// Process Creation Syscalls
// ============================================================================

/// NtCreateProcess - Create a new process
///
/// This is the legacy process creation syscall. NtCreateProcessEx is preferred.
fn sys_create_process(
    process_handle: usize,
    desired_access: usize,
    object_attributes: usize,
    parent_process: usize,
    inherit_object_table: usize,
    section_handle: usize,
) -> isize {
    // Call the extended version with no debug port or exception port
    sys_create_process_internal(
        process_handle,
        desired_access,
        object_attributes,
        parent_process,
        0, // flags (inherit handles = inherit_object_table)
        section_handle,
        0, // debug_port
        0, // exception_port
        inherit_object_table,
    )
}

/// NtCreateProcessEx - Extended process creation
fn sys_create_process_ex(
    process_handle: usize,
    desired_access: usize,
    object_attributes: usize,
    parent_process: usize,
    flags: usize,
    section_handle: usize,
) -> isize {
    // Additional parameters would come from the stack in real implementation
    sys_create_process_internal(
        process_handle,
        desired_access,
        object_attributes,
        parent_process,
        flags,
        section_handle,
        0, // debug_port
        0, // exception_port
        0, // unused
    )
}

/// Internal process creation implementation
fn sys_create_process_internal(
    process_handle_ptr: usize,
    _desired_access: usize,
    object_attributes: usize,
    parent_process_handle: usize,
    flags: usize,
    section_handle: usize,
    _debug_port: usize,
    _exception_port: usize,
    _inherit_handles: usize,
) -> isize {
    use crate::ps::create::ps_create_process;
    use crate::ps::eprocess::get_system_process;
    use crate::ps::cid::ps_lookup_process_by_id;

    if process_handle_ptr == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    crate::serial_println!(
        "[SYSCALL] NtCreateProcess(parent={:#x}, flags={:#x}, section={:#x})",
        parent_process_handle, flags, section_handle
    );

    // Get parent process
    let parent = if parent_process_handle == 0 || parent_process_handle == 0xFFFFFFFF {
        // Use system process as parent if no parent specified
        get_system_process()
    } else {
        // Look up parent process by handle
        unsafe {
            if let Some(pid) = get_process_id(parent_process_handle) {
                // Look up process by PID
                let proc_ptr = ps_lookup_process_by_id(pid);
                if !proc_ptr.is_null() {
                    proc_ptr as *mut crate::ps::eprocess::EProcess
                } else {
                    return 0xC0000008u32 as isize; // STATUS_INVALID_HANDLE
                }
            } else {
                return 0xC0000008u32 as isize; // STATUS_INVALID_HANDLE
            }
        }
    };

    // Extract process name from object attributes if available
    let name = if object_attributes != 0 {
        // OBJECT_ATTRIBUTES contains a UNICODE_STRING for object name
        // For now, use a default name
        b"process.exe"
    } else {
        b"process.exe"
    };

    // Create the process
    let new_process = unsafe {
        ps_create_process(parent, name, 8) // Default priority 8
    };

    if new_process.is_null() {
        crate::serial_println!("[SYSCALL] NtCreateProcess: failed to create process");
        return 0xC0000001u32 as isize; // STATUS_UNSUCCESSFUL
    }

    // If a section handle was provided, that would be the executable to map
    // For now, we just note it
    if section_handle != 0 {
        crate::serial_println!("[SYSCALL] NtCreateProcess: section {:#x} (not yet mapped)", section_handle);
    }

    // Allocate a handle for the new process
    unsafe {
        let pid = (*new_process).unique_process_id;

        if let Some(handle_value) = alloc_process_handle(pid) {
            // Write handle to caller
            *(process_handle_ptr as *mut usize) = handle_value;

            crate::serial_println!(
                "[SYSCALL] NtCreateProcess -> handle {:#x}, pid {}",
                handle_value, pid
            );
            0 // STATUS_SUCCESS
        } else {
            crate::serial_println!("[SYSCALL] NtCreateProcess: no handle slots available");
            0xC000001Du32 as isize // STATUS_NO_MEMORY
        }
    }
}

// ============================================================================
// Job Object Syscalls
// ============================================================================

/// Job handle pool
const JOB_HANDLE_BASE: usize = 0x8000;
const MAX_JOB_HANDLES: usize = 64;
static mut JOB_HANDLE_MAP: [u32; MAX_JOB_HANDLES] = [u32::MAX; MAX_JOB_HANDLES];

unsafe fn alloc_job_handle(job_id: u32) -> Option<usize> {
    for i in 0..MAX_JOB_HANDLES {
        if JOB_HANDLE_MAP[i] == u32::MAX {
            JOB_HANDLE_MAP[i] = job_id;
            return Some(JOB_HANDLE_BASE + i);
        }
    }
    None
}

unsafe fn get_job_id(handle: usize) -> Option<u32> {
    if handle < JOB_HANDLE_BASE {
        return None;
    }
    let idx = handle - JOB_HANDLE_BASE;
    if idx >= MAX_JOB_HANDLES {
        return None;
    }
    let id = JOB_HANDLE_MAP[idx];
    if id == u32::MAX { None } else { Some(id) }
}

/// NtCreateJobObject - Create a job object
fn sys_create_job_object(
    job_handle_ptr: usize,
    desired_access: usize,
    object_attributes: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::job::ps_create_job;

    if job_handle_ptr == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    crate::serial_println!("[SYSCALL] NtCreateJobObject(access={:#x})", desired_access);

    // Extract job name if provided
    let name = if object_attributes != 0 {
        b"Job"
    } else {
        b"Job"
    };

    let job = unsafe { ps_create_job(name) };

    if job.is_null() {
        crate::serial_println!("[SYSCALL] NtCreateJobObject: failed to create job");
        return 0xC0000001u32 as isize;
    }

    unsafe {
        let job_id = (*job).job_id;

        if let Some(handle_value) = alloc_job_handle(job_id) {
            *(job_handle_ptr as *mut usize) = handle_value;

            crate::serial_println!("[SYSCALL] NtCreateJobObject -> handle {:#x}, id {}",
                handle_value, job_id);
            0
        } else {
            crate::ps::job::free_job(job);
            0xC000001Du32 as isize
        }
    }
}

/// NtOpenJobObject - Open existing job object
fn sys_open_job_object(
    job_handle_ptr: usize,
    desired_access: usize,
    object_attributes: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    if job_handle_ptr == 0 || object_attributes == 0 {
        return -1;
    }

    crate::serial_println!("[SYSCALL] NtOpenJobObject(access={:#x})", desired_access);
    0xC0000034u32 as isize // STATUS_OBJECT_NAME_NOT_FOUND
}

/// NtAssignProcessToJobObject - Assign a process to a job
fn sys_assign_process_to_job(
    job_handle: usize,
    process_handle: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::job::ps_lookup_job;
    use crate::ps::cid::ps_lookup_process_by_id;

    crate::serial_println!("[SYSCALL] NtAssignProcessToJobObject(job={:#x}, proc={:#x})",
        job_handle, process_handle);

    let job = unsafe {
        if let Some(job_id) = get_job_id(job_handle) {
            ps_lookup_job(job_id)
        } else {
            return 0xC0000008u32 as isize;
        }
    };

    if job.is_null() {
        return 0xC0000008u32 as isize;
    }

    let process = unsafe {
        if let Some(pid) = get_process_id(process_handle) {
            ps_lookup_process_by_id(pid) as *mut crate::ps::eprocess::EProcess
        } else {
            return 0xC0000008u32 as isize;
        }
    };

    if process.is_null() {
        return 0xC0000008u32 as isize;
    }

    unsafe {
        if !(*process).job.is_null() {
            return 0xC0000430u32 as isize;
        }

        if (*job).assign_process(process) {
            crate::serial_println!("[SYSCALL] NtAssignProcessToJobObject: success");
            0
        } else {
            0xC0000001u32 as isize
        }
    }
}

/// NtQueryInformationJobObject - Query job information
fn sys_query_information_job(
    job_handle: usize,
    info_class: usize,
    info_buffer: usize,
    info_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    use crate::ps::job::ps_lookup_job;

    crate::serial_println!("[SYSCALL] NtQueryInformationJobObject(handle={:#x}, class={})",
        job_handle, info_class);

    if info_buffer == 0 {
        return -1;
    }

    let job = unsafe {
        if let Some(job_id) = get_job_id(job_handle) {
            ps_lookup_job(job_id)
        } else {
            return 0xC0000008u32 as isize;
        }
    };

    if job.is_null() {
        return 0xC0000008u32 as isize;
    }

    unsafe {
        match info_class as u32 {
            1 => { // BasicAccountingInformation
                let size = core::mem::size_of::<crate::ps::job::JobBasicAccountingInformation>();
                if info_length < size {
                    if return_length != 0 {
                        *(return_length as *mut usize) = size;
                    }
                    return 0xC0000023u32 as isize;
                }
                let dest = info_buffer as *mut crate::ps::job::JobBasicAccountingInformation;
                *dest = (*job).accounting;
                if return_length != 0 {
                    *(return_length as *mut usize) = size;
                }
                0
            }
            2 => { // BasicLimitInformation
                let size = core::mem::size_of::<crate::ps::job::JobBasicLimitInformation>();
                if info_length < size {
                    if return_length != 0 {
                        *(return_length as *mut usize) = size;
                    }
                    return 0xC0000023u32 as isize;
                }
                let dest = info_buffer as *mut crate::ps::job::JobBasicLimitInformation;
                *dest = (*job).limits.basic_limit_information;
                if return_length != 0 {
                    *(return_length as *mut usize) = size;
                }
                0
            }
            9 => { // ExtendedLimitInformation
                let size = core::mem::size_of::<crate::ps::job::JobExtendedLimitInformation>();
                if info_length < size {
                    if return_length != 0 {
                        *(return_length as *mut usize) = size;
                    }
                    return 0xC0000023u32 as isize;
                }
                let dest = info_buffer as *mut crate::ps::job::JobExtendedLimitInformation;
                *dest = (*job).limits;
                if return_length != 0 {
                    *(return_length as *mut usize) = size;
                }
                0
            }
            _ => 0xC0000003u32 as isize
        }
    }
}

/// NtSetInformationJobObject - Set job limits
fn sys_set_information_job(
    job_handle: usize,
    info_class: usize,
    info_buffer: usize,
    info_length: usize,
    _: usize, _: usize,
) -> isize {
    use crate::ps::job::ps_lookup_job;

    crate::serial_println!("[SYSCALL] NtSetInformationJobObject(handle={:#x}, class={})",
        job_handle, info_class);

    if info_buffer == 0 {
        return -1;
    }

    let job = unsafe {
        if let Some(job_id) = get_job_id(job_handle) {
            ps_lookup_job(job_id)
        } else {
            return 0xC0000008u32 as isize;
        }
    };

    if job.is_null() {
        return 0xC0000008u32 as isize;
    }

    unsafe {
        match info_class as u32 {
            2 => { // BasicLimitInformation
                let size = core::mem::size_of::<crate::ps::job::JobBasicLimitInformation>();
                if info_length < size {
                    return 0xC0000023u32 as isize;
                }
                let src = info_buffer as *const crate::ps::job::JobBasicLimitInformation;
                (*job).limits.basic_limit_information = *src;
                0
            }
            9 => { // ExtendedLimitInformation
                let size = core::mem::size_of::<crate::ps::job::JobExtendedLimitInformation>();
                if info_length < size {
                    return 0xC0000023u32 as isize;
                }
                let src = info_buffer as *const crate::ps::job::JobExtendedLimitInformation;
                (*job).limits = *src;
                0
            }
            _ => 0xC0000003u32 as isize
        }
    }
}

/// NtTerminateJobObject - Terminate all processes in a job
fn sys_terminate_job_object(
    job_handle: usize,
    exit_status: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::job::ps_lookup_job;

    crate::serial_println!("[SYSCALL] NtTerminateJobObject(handle={:#x}, exit={:#x})",
        job_handle, exit_status);

    let job = unsafe {
        if let Some(job_id) = get_job_id(job_handle) {
            ps_lookup_job(job_id)
        } else {
            return 0xC0000008u32 as isize;
        }
    };

    if job.is_null() {
        return 0xC0000008u32 as isize;
    }

    unsafe {
        (*job).terminate(exit_status as i32);
    }

    0
}

/// NtIsProcessInJob - Check if a process is in a job
fn sys_is_process_in_job(
    process_handle: usize,
    job_handle: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::cid::ps_lookup_process_by_id;

    crate::serial_println!("[SYSCALL] NtIsProcessInJob(proc={:#x}, job={:#x})",
        process_handle, job_handle);

    let process = unsafe {
        if let Some(pid) = get_process_id(process_handle) {
            ps_lookup_process_by_id(pid) as *mut crate::ps::eprocess::EProcess
        } else {
            return 0xC0000008u32 as isize;
        }
    };

    if process.is_null() {
        return 0xC0000008u32 as isize;
    }

    unsafe {
        if job_handle == 0 {
            if (*process).job.is_null() {
                0xC0000001u32 as isize // Not in any job
            } else {
                0 // In some job
            }
        } else {
            if let Some(job_id) = get_job_id(job_handle) {
                let job = crate::ps::job::ps_lookup_job(job_id);
                if (*process).job == job as *mut u8 {
                    0 // In this job
                } else {
                    0xC0000001u32 as isize
                }
            } else {
                0xC0000008u32 as isize
            }
        }
    }
}

// ============================================================================
// System Information
// ============================================================================

/// System information class for NtQuerySystemInformation
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemInformationClass {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemCrashDumpInformation = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeperation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessInformation = 53,
    SystemLoadGdiDriverInSystemSpace = 54,
    SystemNumaProcessorMap = 55,
    SystemPrefetcherInformation = 56,
    SystemExtendedProcessInformation = 57,
    SystemRecommendedSharedDataAlignment = 58,
    SystemComPlusPackage = 59,
    SystemNumaAvailableMemory = 60,
    SystemProcessorPowerInformation = 61,
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
    SystemHotpatchInformation = 69,
    SystemObjectSecurityMode = 70,
    SystemWatchdogTimerHandler = 71,
    SystemWatchdogTimerInformation = 72,
    SystemLogicalProcessorInformation = 73,
    SystemWow64SharedInformationObsolete = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation = 76,
    SystemModuleInformationEx = 77,
    SystemVerifierTriageInformation = 78,
    SystemSuperfetchInformation = 79,
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    SystemThreadPriorityClientIdInformation = 82,
    SystemProcessorIdleCycleTimeInformation = 83,
    SystemVerifierCancellationInformation = 84,
    SystemProcessorPowerInformationEx = 85,
    SystemRefTraceInformation = 86,
    SystemSpecialPoolInformation = 87,
    SystemProcessIdInformation = 88,
    SystemErrorPortInformation = 89,
    SystemBootEnvironmentInformation = 90,
    SystemHypervisorInformation = 91,
    SystemVerifierInformationEx = 92,
    SystemTimeZoneInformation = 93,
    SystemImageFileExecutionOptionsInformation = 94,
    SystemCoverageInformation = 95,
    SystemPrefetchPatchInformation = 96,
    SystemVerifierFaultsInformation = 97,
    SystemSystemPartitionInformation = 98,
    SystemSystemDiskInformation = 99,
    SystemProcessorPerformanceDistribution = 100,
}

/// SYSTEM_BASIC_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemBasicInformation {
    pub reserved: u32,
    pub timer_resolution: u32,
    pub page_size: u32,
    pub number_of_physical_pages: u32,
    pub lowest_physical_page_number: u32,
    pub highest_physical_page_number: u32,
    pub allocation_granularity: u32,
    pub minimum_user_mode_address: usize,
    pub maximum_user_mode_address: usize,
    pub active_processors_affinity_mask: usize,
    pub number_of_processors: u8,
}

/// SYSTEM_PROCESSOR_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemProcessorInformation {
    pub processor_architecture: u16,
    pub processor_level: u16,
    pub processor_revision: u16,
    pub maximum_processors: u16,
    pub processor_feature_bits: u32,
}

/// SYSTEM_PERFORMANCE_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemPerformanceInformation {
    pub idle_process_time: i64,
    pub io_read_transfer_count: i64,
    pub io_write_transfer_count: i64,
    pub io_other_transfer_count: i64,
    pub io_read_operation_count: u32,
    pub io_write_operation_count: u32,
    pub io_other_operation_count: u32,
    pub available_pages: u32,
    pub committed_pages: u32,
    pub commit_limit: u32,
    pub peak_commitment: u32,
    pub page_fault_count: u32,
    pub copy_on_write_count: u32,
    pub transition_count: u32,
    pub cache_transition_count: u32,
    pub demand_zero_count: u32,
    pub page_read_count: u32,
    pub page_read_io_count: u32,
    pub cache_read_count: u32,
    pub cache_io_count: u32,
    pub dirty_pages_write_count: u32,
    pub dirty_write_io_count: u32,
    pub mapped_pages_write_count: u32,
    pub mapped_write_io_count: u32,
    pub paged_pool_pages: u32,
    pub non_paged_pool_pages: u32,
    pub paged_pool_allocs: u32,
    pub paged_pool_frees: u32,
    pub non_paged_pool_allocs: u32,
    pub non_paged_pool_frees: u32,
    pub free_system_ptes: u32,
    pub resident_system_code_page: u32,
    pub total_system_driver_pages: u32,
    pub total_system_code_pages: u32,
    pub non_paged_pool_lookaside_hits: u32,
    pub paged_pool_lookaside_hits: u32,
    pub available_paged_pool_pages: u32,
    pub resident_system_cache_page: u32,
    pub resident_paged_pool_page: u32,
    pub resident_system_driver_page: u32,
    pub cc_fast_read_no_wait: u32,
    pub cc_fast_read_wait: u32,
    pub cc_fast_read_resource_miss: u32,
    pub cc_fast_read_not_possible: u32,
    pub cc_fast_mdl_read_no_wait: u32,
    pub cc_fast_mdl_read_wait: u32,
    pub cc_fast_mdl_read_resource_miss: u32,
    pub cc_fast_mdl_read_not_possible: u32,
    pub cc_map_data_no_wait: u32,
    pub cc_map_data_wait: u32,
    pub cc_map_data_no_wait_miss: u32,
    pub cc_map_data_wait_miss: u32,
    pub cc_pin_mapped_data_count: u32,
    pub cc_pin_read_no_wait: u32,
    pub cc_pin_read_wait: u32,
    pub cc_pin_read_no_wait_miss: u32,
    pub cc_pin_read_wait_miss: u32,
    pub cc_copy_read_no_wait: u32,
    pub cc_copy_read_wait: u32,
    pub cc_copy_read_no_wait_miss: u32,
    pub cc_copy_read_wait_miss: u32,
    pub cc_mdl_read_no_wait: u32,
    pub cc_mdl_read_wait: u32,
    pub cc_mdl_read_no_wait_miss: u32,
    pub cc_mdl_read_wait_miss: u32,
    pub cc_read_ahead_ios: u32,
    pub cc_lazy_write_ios: u32,
    pub cc_lazy_write_pages: u32,
    pub cc_data_flushes: u32,
    pub cc_data_pages: u32,
    pub context_switches: u32,
    pub first_level_tb_fills: u32,
    pub second_level_tb_fills: u32,
    pub system_calls: u32,
}

/// SYSTEM_TIMEOFDAY_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemTimeOfDayInformation {
    pub boot_time: i64,
    pub current_time: i64,
    pub time_zone_bias: i64,
    pub time_zone_id: u32,
    pub reserved: u32,
    pub boot_time_bias: u64,
    pub sleep_time_bias: u64,
}

/// SYSTEM_PROCESS_INFORMATION structure (simplified)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemProcessInformation {
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub working_set_private_size: i64,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    pub create_time: i64,
    pub user_time: i64,
    pub kernel_time: i64,
    pub image_name_length: u16,
    pub image_name_maximum_length: u16,
    pub image_name_ptr: usize, // UNICODE_STRING buffer pointer
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
    pub handle_count: u32,
    pub session_id: u32,
    pub unique_process_key: usize,
    pub peak_virtual_size: usize,
    pub virtual_size: usize,
    pub page_fault_count: u32,
    pub peak_working_set_size: usize,
    pub working_set_size: usize,
    pub quota_peak_paged_pool_usage: usize,
    pub quota_paged_pool_usage: usize,
    pub quota_peak_non_paged_pool_usage: usize,
    pub quota_non_paged_pool_usage: usize,
    pub pagefile_usage: usize,
    pub peak_pagefile_usage: usize,
    pub private_page_count: usize,
    pub read_operation_count: i64,
    pub write_operation_count: i64,
    pub other_operation_count: i64,
    pub read_transfer_count: i64,
    pub write_transfer_count: i64,
    pub other_transfer_count: i64,
}

/// NtQuerySystemInformation - Query system-wide information
fn sys_query_system_information(
    info_class: usize,
    system_info: usize,
    system_info_length: usize,
    return_length: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    use core::ptr;

    crate::serial_println!("[SYSCALL] NtQuerySystemInformation(class={}, buf={:#x}, len={})",
        info_class, system_info, system_info_length);

    // Validate buffer pointer
    if system_info == 0 {
        return 0xC0000005u32 as isize; // STATUS_ACCESS_VIOLATION
    }

    match info_class as u32 {
        // SystemBasicInformation = 0
        0 => {
            let required_size = core::mem::size_of::<SystemBasicInformation>();

            // Write return length if provided
            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut u32, required_size as u32);
                }
            }

            if system_info_length < required_size {
                return 0xC0000004u32 as isize; // STATUS_INFO_LENGTH_MISMATCH
            }

            let stats = crate::mm::pfn::mm_get_stats();
            let info = SystemBasicInformation {
                reserved: 0,
                timer_resolution: 10000, // 1ms in 100ns units
                page_size: 4096,
                number_of_physical_pages: stats.total_pages,
                lowest_physical_page_number: 1,
                highest_physical_page_number: stats.total_pages,
                allocation_granularity: 65536, // 64KB
                minimum_user_mode_address: 0x10000,
                maximum_user_mode_address: 0x7FFFFFFEFFFF,
                active_processors_affinity_mask: 1, // Single processor
                number_of_processors: 1,
            };

            unsafe {
                ptr::write(system_info as *mut SystemBasicInformation, info);
            }

            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: BasicInfo - pages={}, page_size={}",
                info.number_of_physical_pages, info.page_size);

            0 // STATUS_SUCCESS
        }

        // SystemProcessorInformation = 1
        1 => {
            let required_size = core::mem::size_of::<SystemProcessorInformation>();

            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut u32, required_size as u32);
                }
            }

            if system_info_length < required_size {
                return 0xC0000004u32 as isize;
            }

            let info = SystemProcessorInformation {
                processor_architecture: 9, // PROCESSOR_ARCHITECTURE_AMD64
                processor_level: 6,        // Pentium Pro family
                processor_revision: 0x0F00,
                maximum_processors: 64,
                processor_feature_bits: 0x00000001, // Basic features
            };

            unsafe {
                ptr::write(system_info as *mut SystemProcessorInformation, info);
            }

            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: ProcessorInfo - arch=AMD64");

            0
        }

        // SystemPerformanceInformation = 2
        2 => {
            let required_size = core::mem::size_of::<SystemPerformanceInformation>();

            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut u32, required_size as u32);
                }
            }

            if system_info_length < required_size {
                return 0xC0000004u32 as isize;
            }

            let tick_count = crate::hal::apic::get_tick_count();
            let stats = crate::mm::pfn::mm_get_stats();

            let info = SystemPerformanceInformation {
                idle_process_time: 0,
                io_read_transfer_count: 0,
                io_write_transfer_count: 0,
                io_other_transfer_count: 0,
                io_read_operation_count: 0,
                io_write_operation_count: 0,
                io_other_operation_count: 0,
                available_pages: stats.free_pages + stats.zeroed_pages,
                committed_pages: 0,
                commit_limit: stats.total_pages,
                peak_commitment: 0,
                page_fault_count: 0,
                copy_on_write_count: 0,
                transition_count: 0,
                cache_transition_count: 0,
                demand_zero_count: 0,
                page_read_count: 0,
                page_read_io_count: 0,
                cache_read_count: 0,
                cache_io_count: 0,
                dirty_pages_write_count: 0,
                dirty_write_io_count: 0,
                mapped_pages_write_count: 0,
                mapped_write_io_count: 0,
                paged_pool_pages: 0,
                non_paged_pool_pages: 0,
                paged_pool_allocs: 0,
                paged_pool_frees: 0,
                non_paged_pool_allocs: 0,
                non_paged_pool_frees: 0,
                free_system_ptes: 0,
                resident_system_code_page: 0,
                total_system_driver_pages: 0,
                total_system_code_pages: 0,
                non_paged_pool_lookaside_hits: 0,
                paged_pool_lookaside_hits: 0,
                available_paged_pool_pages: 0,
                resident_system_cache_page: 0,
                resident_paged_pool_page: 0,
                resident_system_driver_page: 0,
                cc_fast_read_no_wait: 0,
                cc_fast_read_wait: 0,
                cc_fast_read_resource_miss: 0,
                cc_fast_read_not_possible: 0,
                cc_fast_mdl_read_no_wait: 0,
                cc_fast_mdl_read_wait: 0,
                cc_fast_mdl_read_resource_miss: 0,
                cc_fast_mdl_read_not_possible: 0,
                cc_map_data_no_wait: 0,
                cc_map_data_wait: 0,
                cc_map_data_no_wait_miss: 0,
                cc_map_data_wait_miss: 0,
                cc_pin_mapped_data_count: 0,
                cc_pin_read_no_wait: 0,
                cc_pin_read_wait: 0,
                cc_pin_read_no_wait_miss: 0,
                cc_pin_read_wait_miss: 0,
                cc_copy_read_no_wait: 0,
                cc_copy_read_wait: 0,
                cc_copy_read_no_wait_miss: 0,
                cc_copy_read_wait_miss: 0,
                cc_mdl_read_no_wait: 0,
                cc_mdl_read_wait: 0,
                cc_mdl_read_no_wait_miss: 0,
                cc_mdl_read_wait_miss: 0,
                cc_read_ahead_ios: 0,
                cc_lazy_write_ios: 0,
                cc_lazy_write_pages: 0,
                cc_data_flushes: 0,
                cc_data_pages: 0,
                context_switches: tick_count as u32, // Approximate
                first_level_tb_fills: 0,
                second_level_tb_fills: 0,
                system_calls: tick_count as u32 * 100, // Approximate
            };

            unsafe {
                ptr::write(system_info as *mut SystemPerformanceInformation, info);
            }

            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: PerformanceInfo - available_pages={}",
                info.available_pages);

            0
        }

        // SystemTimeOfDayInformation = 3
        3 => {
            let required_size = core::mem::size_of::<SystemTimeOfDayInformation>();

            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut u32, required_size as u32);
                }
            }

            if system_info_length < required_size {
                return 0xC0000004u32 as isize;
            }

            let tick_count = crate::hal::apic::get_tick_count();
            // Convert ticks to 100ns units (1 tick = 1ms = 10000 * 100ns)
            let current_time = tick_count as i64 * 10000;

            let info = SystemTimeOfDayInformation {
                boot_time: 0, // System boot time
                current_time,
                time_zone_bias: 0, // UTC
                time_zone_id: 0,
                reserved: 0,
                boot_time_bias: 0,
                sleep_time_bias: 0,
            };

            unsafe {
                ptr::write(system_info as *mut SystemTimeOfDayInformation, info);
            }

            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: TimeOfDay - current_time={}",
                current_time);

            0
        }

        // SystemProcessInformation = 5
        5 => {
            use crate::ps::EProcess;

            // Return list of all processes
            let mut offset = 0usize;
            let mut prev_entry_offset_ptr: Option<*mut u32> = None;

            unsafe {
                // Iterate through all processes
                for pid in 0..crate::ps::MAX_PROCESSES {
                    let process_ptr = crate::ps::ps_lookup_process_by_id(pid as u32);
                    if process_ptr.is_null() {
                        continue;
                    }

                    let entry_size = core::mem::size_of::<SystemProcessInformation>();

                    // Check if we have enough space
                    if offset + entry_size > system_info_length {
                        if return_length != 0 {
                            ptr::write(return_length as *mut u32, (offset + entry_size) as u32);
                        }
                        return 0xC0000004u32 as isize; // STATUS_INFO_LENGTH_MISMATCH
                    }

                    // Cast to proper EProcess type
                    let process = &*(process_ptr as *const EProcess);
                    let entry_ptr = (system_info + offset) as *mut SystemProcessInformation;

                    // Get thread count from the atomic field
                    let thread_count = process.thread_count.load(core::sync::atomic::Ordering::Relaxed);

                    let info = SystemProcessInformation {
                        next_entry_offset: 0, // Will be updated
                        number_of_threads: thread_count,
                        working_set_private_size: 0,
                        hard_fault_count: 0,
                        number_of_threads_high_watermark: thread_count,
                        cycle_time: 0,
                        create_time: process.create_time as i64,
                        user_time: 0,
                        kernel_time: 0,
                        image_name_length: 0,
                        image_name_maximum_length: 0,
                        image_name_ptr: 0,
                        base_priority: process.pcb.base_priority as i32,
                        unique_process_id: pid,
                        inherited_from_unique_process_id: process.inherited_from_unique_process_id as usize,
                        handle_count: 0, // Handle count not easily available
                        session_id: process.session_id,
                        unique_process_key: 0,
                        peak_virtual_size: 0,
                        virtual_size: 0,
                        page_fault_count: 0,
                        peak_working_set_size: 0,
                        working_set_size: 0,
                        quota_peak_paged_pool_usage: 0,
                        quota_paged_pool_usage: 0,
                        quota_peak_non_paged_pool_usage: 0,
                        quota_non_paged_pool_usage: 0,
                        pagefile_usage: 0,
                        peak_pagefile_usage: 0,
                        private_page_count: 0,
                        read_operation_count: 0,
                        write_operation_count: 0,
                        other_operation_count: 0,
                        read_transfer_count: 0,
                        write_transfer_count: 0,
                        other_transfer_count: 0,
                    };

                    ptr::write(entry_ptr, info);

                    // Update previous entry's next_entry_offset
                    if let Some(prev_ptr) = prev_entry_offset_ptr {
                        ptr::write(prev_ptr, offset as u32 - (prev_ptr as usize - system_info) as u32 + entry_size as u32);
                    }

                    prev_entry_offset_ptr = Some(&mut (*entry_ptr).next_entry_offset as *mut u32);
                    offset += entry_size;
                }

                // Update return length
                if return_length != 0 {
                    ptr::write(return_length as *mut u32, offset as u32);
                }

                crate::serial_println!("[SYSCALL] NtQuerySystemInformation: ProcessInfo - {} bytes", offset);
            }

            0
        }

        // SystemHandleInformation = 16
        16 => {
            // Simplified - just return count
            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut u32, 8);
                }
            }

            if system_info_length < 8 {
                return 0xC0000004u32 as isize;
            }

            unsafe {
                // Write handle count and first handle entry placeholder
                ptr::write(system_info as *mut u32, 0); // Number of handles
                ptr::write((system_info + 4) as *mut u32, 0);
            }

            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: HandleInfo");

            0
        }

        // SystemKernelDebuggerInformation = 35
        35 => {
            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut u32, 2);
                }
            }

            if system_info_length < 2 {
                return 0xC0000004u32 as isize;
            }

            unsafe {
                // KernelDebuggerEnabled, KernelDebuggerNotPresent
                ptr::write(system_info as *mut u8, 0); // Not enabled
                ptr::write((system_info + 1) as *mut u8, 1); // Not present
            }

            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: KernelDebuggerInfo");

            0
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: unsupported class {}", info_class);
            0xC0000003u32 as isize // STATUS_INVALID_INFO_CLASS
        }
    }
}

/// NtQuerySystemTime - Query current system time
fn sys_query_system_time(
    system_time: usize,
    _arg2: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    if system_time == 0 {
        return 0xC0000005u32 as isize; // STATUS_ACCESS_VIOLATION
    }

    let tick_count = crate::hal::apic::get_tick_count();
    // Convert ticks to 100ns units (1 tick = 1ms = 10000 * 100ns)
    // Add a base time (Jan 1, 1601 to Jan 1, 2024 in 100ns units, approximately)
    let base_time: i64 = 132_537_600_000_000_000; // Approximate
    let current_time = base_time + (tick_count as i64 * 10000);

    unsafe {
        core::ptr::write(system_time as *mut i64, current_time);
    }

    crate::serial_println!("[SYSCALL] NtQuerySystemTime = {}", current_time);

    0
}

/// NtQueryPerformanceCounter - Query high-resolution performance counter
fn sys_query_performance_counter(
    performance_counter: usize,
    performance_frequency: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    if performance_counter == 0 {
        return 0xC0000005u32 as isize; // STATUS_ACCESS_VIOLATION
    }

    // Read TSC (Time Stamp Counter)
    let tsc: u64;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") tsc,
            out("rdx") _,
            options(nostack, nomem)
        );
    }

    unsafe {
        core::ptr::write(performance_counter as *mut i64, tsc as i64);
    }

    // If frequency requested, return approximate TSC frequency
    // Assume ~2GHz for now (would need CPUID calibration for accuracy)
    if performance_frequency != 0 {
        unsafe {
            core::ptr::write(performance_frequency as *mut i64, 2_000_000_000i64);
        }
    }

    crate::serial_println!("[SYSCALL] NtQueryPerformanceCounter = {}", tsc);

    0
}
