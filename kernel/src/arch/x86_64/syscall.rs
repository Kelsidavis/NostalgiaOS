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
    register_syscall(SyscallNumber::NtGetCurrentProcessId as usize, sys_get_current_process_id);
    register_syscall(SyscallNumber::NtGetCurrentThreadId as usize, sys_get_current_thread_id);
    register_syscall(SyscallNumber::NtYieldExecution as usize, sys_yield_execution);
    register_syscall(SyscallNumber::NtDelayExecution as usize, sys_delay_execution);
    register_syscall(SyscallNumber::NtDebugPrint as usize, sys_debug_print);
    register_syscall(SyscallNumber::NtClose as usize, sys_close);
    register_syscall(SyscallNumber::NtReadFile as usize, sys_read_file);
    register_syscall(SyscallNumber::NtWriteFile as usize, sys_write_file);
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
    // TODO: Implement handle closing via object manager
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
    crate::serial_println!("[SYSCALL] NtReadFile(handle={}, buffer={:#x}, len={})",
        handle, buffer, length);

    // TODO: Implement file reading
    // For now, just return 0 bytes read
    if bytes_read_ptr != 0 {
        unsafe {
            *(bytes_read_ptr as *mut usize) = 0;
        }
    }
    0
}

/// NtWriteFile - Write to a file
fn sys_write_file(
    handle: usize,
    buffer: usize,
    length: usize,
    bytes_written_ptr: usize,
    _: usize, _: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtWriteFile(handle={}, buffer={:#x}, len={})",
        handle, buffer, length);

    // Special case: handle 1 = stdout (serial console)
    if handle == 1 && buffer != 0 && length > 0 && length <= 4096 {
        let slice = unsafe {
            core::slice::from_raw_parts(buffer as *const u8, length)
        };

        if let Ok(s) = core::str::from_utf8(slice) {
            crate::serial_print!("{}", s);
            if bytes_written_ptr != 0 {
                unsafe {
                    *(bytes_written_ptr as *mut usize) = length;
                }
            }
            return 0;
        }
    }

    -1
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

    // Write previous state if requested
    if previous_state != 0 {
        unsafe {
            *(previous_state as *mut i32) = was_signaled as i32;
        }
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
        unsafe {
            *(previous_state as *mut i32) = was_signaled as i32;
        }
    }

    unsafe { crate::ob::ob_dereference_object(object); }

    0
}

/// NtCreateEvent - Create a new event object
fn sys_create_event(
    event_handle: usize,
    _desired_access: usize,
    _object_attributes: usize,
    _event_type: usize,
    _initial_state: usize,
    _: usize,
) -> isize {
    if event_handle == 0 {
        return -1; // STATUS_INVALID_PARAMETER
    }

    // For now, return a stub handle value
    // TODO: Implement proper event object creation
    crate::serial_println!("[SYSCALL] NtCreateEvent - stub implementation");

    unsafe {
        *(event_handle as *mut usize) = 0x100; // Stub handle
    }
    0 // STATUS_SUCCESS
}

/// NtReleaseSemaphore - Release a semaphore
fn sys_release_semaphore(
    handle: usize,
    release_count: usize,
    previous_count: usize,
    _: usize, _: usize, _: usize,
) -> isize {
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
        unsafe {
            *(previous_count as *mut i32) = prev;
        }
    }

    unsafe { crate::ob::ob_dereference_object(object); }

    0
}

/// NtCreateSemaphore - Create a semaphore object
fn sys_create_semaphore(
    semaphore_handle: usize,
    _desired_access: usize,
    _object_attributes: usize,
    _initial_count: usize,
    _maximum_count: usize,
    _: usize,
) -> isize {
    if semaphore_handle == 0 {
        return -1;
    }

    // For now, return a stub handle value
    // TODO: Implement proper semaphore object creation
    crate::serial_println!("[SYSCALL] NtCreateSemaphore - stub implementation");

    unsafe {
        *(semaphore_handle as *mut usize) = 0x101; // Stub handle
    }
    0
}

/// NtReleaseMutant - Release a mutex (mutant in NT terminology)
fn sys_release_mutant(
    handle: usize,
    previous_count: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
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
        unsafe {
            *(previous_count as *mut i32) = prev;
        }
    }

    unsafe { crate::ob::ob_dereference_object(object); }

    0
}

/// NtCreateMutant - Create a mutex object
fn sys_create_mutant(
    mutant_handle: usize,
    _desired_access: usize,
    _object_attributes: usize,
    _initial_owner: usize,
    _: usize, _: usize,
) -> isize {
    if mutant_handle == 0 {
        return -1;
    }

    // For now, return a stub handle value
    // TODO: Implement proper mutant object creation
    crate::serial_println!("[SYSCALL] NtCreateMutant - stub implementation");

    unsafe {
        *(mutant_handle as *mut usize) = 0x102; // Stub handle
    }
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
