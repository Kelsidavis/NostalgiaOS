//! Context switching implementation for x86_64
//!
//! Provides low-level context switch routines that save and restore
//! CPU register state between threads.
//!
//! The x86_64 ABI requires preserving: RBX, RBP, R12-R15
//! We also save/restore RFLAGS and RSP (via stack manipulation)

use core::arch::naked_asm;
use crate::ke::thread::KThread;

/// Offset of kernel_stack field in KThread structure
/// This must match the actual offset in the KThread struct!
/// Layout: state(1) + priority(1) + base_priority(1) + quantum(1) +
///         priority_decrement(1) + saturation(1) + padding(2) +
///         wait_list_entry(16) + thread_list_entry(16) = 40
const KTHREAD_KERNEL_STACK_OFFSET: usize = 40;

/// Swap context from old thread to new thread
///
/// Saves callee-saved registers of old thread and restores new thread's registers.
/// Returns when the old thread is resumed.
///
/// # Safety
/// - Both thread pointers must be valid
/// - New thread must have a valid kernel stack set up
/// - Must be called with interrupts disabled
#[unsafe(naked)]
pub unsafe extern "C" fn ki_swap_context(_old_thread: *mut KThread, _new_thread: *mut KThread) {
    naked_asm!(
        // Save callee-saved registers on old thread's stack
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "pushfq",

        // Save current stack pointer to old thread's kernel_stack
        // old_thread is in rdi, kernel_stack offset is KTHREAD_KERNEL_STACK_OFFSET
        "mov [rdi + {stack_offset}], rsp",

        // Load new thread's stack pointer
        // new_thread is in rsi
        "mov rsp, [rsi + {stack_offset}]",

        // Restore callee-saved registers from new thread's stack
        "popfq",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",

        // Return to new thread (rip is on stack from original call)
        "ret",
        stack_offset = const KTHREAD_KERNEL_STACK_OFFSET,
    )
}

/// Load context for initial thread entry (no old thread to save)
///
/// Used when starting the first thread or switching from no thread.
///
/// # Safety
/// - Thread pointer must be valid
/// - Thread must have a valid kernel stack with context set up
/// - Must be called with interrupts disabled
#[unsafe(naked)]
pub unsafe extern "C" fn ki_load_context(_new_thread: *mut KThread) {
    naked_asm!(
        // Load new thread's stack pointer
        // new_thread is in rdi
        "mov rsp, [rdi + {stack_offset}]",

        // Restore callee-saved registers from new thread's stack
        "popfq",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",

        // Return to thread entry point (rip on stack)
        "ret",
        stack_offset = const KTHREAD_KERNEL_STACK_OFFSET,
    )
}

/// Set up a thread's initial stack for first context switch
///
/// Prepares the stack so that ki_swap_context or ki_load_context
/// will properly start the thread at its entry point.
///
/// # Safety
/// - stack_top must point to the top (highest address) of a valid stack
/// - entry_point must be a valid function pointer
pub unsafe fn setup_initial_context(
    thread: *mut KThread,
    stack_top: *mut u8,
    entry_point: fn(),
) {
    // Stack layout (growing downward from stack_top):
    // [stack_top]
    //   - return address (entry_point)  <- 8 bytes
    //   - rbx                           <- 8 bytes
    //   - rbp                           <- 8 bytes
    //   - r12                           <- 8 bytes
    //   - r13                           <- 8 bytes
    //   - r14                           <- 8 bytes
    //   - r15                           <- 8 bytes
    //   - rflags                        <- 8 bytes
    // [kernel_stack points here]

    let mut sp = stack_top as usize;

    // Push return address (entry point)
    sp -= 8;
    *(sp as *mut u64) = entry_point as usize as u64;

    // Push callee-saved registers (all zero for new thread)
    sp -= 8;
    *(sp as *mut u64) = 0; // rbx

    sp -= 8;
    *(sp as *mut u64) = 0; // rbp

    sp -= 8;
    *(sp as *mut u64) = 0; // r12

    sp -= 8;
    *(sp as *mut u64) = 0; // r13

    sp -= 8;
    *(sp as *mut u64) = 0; // r14

    sp -= 8;
    *(sp as *mut u64) = 0; // r15

    // Push rflags (interrupts enabled)
    sp -= 8;
    *(sp as *mut u64) = 0x202; // IF flag set

    // Set thread's kernel_stack to point to the prepared context
    (*thread).kernel_stack = sp as *mut u8;
}

/// Perform a full context save for the current thread
///
/// This is used when entering kernel mode from an interrupt/exception
/// where we need to save the complete user context.
#[allow(dead_code)]
pub unsafe fn save_full_context() {
    // For now, we only support kernel threads, so this is a no-op
    // When user mode is added, this will save all registers including
    // SS, RSP, RFLAGS, CS, RIP from the interrupt frame
}

/// Perform a full context restore for the current thread
///
/// This is used when returning to user mode after handling an interrupt.
#[allow(dead_code)]
pub unsafe fn restore_full_context() {
    // For now, we only support kernel threads, so this is a no-op
    // When user mode is added, this will restore all registers and
    // use IRETQ to return to user mode
}
