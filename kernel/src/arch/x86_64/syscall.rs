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
    register_syscall(SyscallNumber::NtDebugPrint as usize, sys_debug_print);
    register_syscall(SyscallNumber::NtClose as usize, sys_close);
    register_syscall(SyscallNumber::NtReadFile as usize, sys_read_file);
    register_syscall(SyscallNumber::NtWriteFile as usize, sys_write_file);
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
