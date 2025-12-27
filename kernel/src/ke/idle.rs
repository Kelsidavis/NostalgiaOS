//! Idle Thread Implementation
//!
//! The idle thread runs at priority 0 (lowest) and is selected when
//! no other threads are ready to run. It executes a HLT loop to
//! reduce power consumption while waiting for interrupts.
//!
//! Each processor has its own idle thread.

use core::arch::asm;
use super::thread::{KThread, ThreadState, constants};
use super::prcb;
use super::process;
use crate::arch::x86_64::context;

/// Static idle thread for the boot processor
static mut IDLE_THREAD: KThread = KThread::new();

/// Static stack for the idle thread (16KB)
#[repr(C, align(16))]
struct IdleStack {
    data: [u8; constants::THREAD_STACK_SIZE],
}

static mut IDLE_STACK: IdleStack = IdleStack {
    data: [0; constants::THREAD_STACK_SIZE],
};

/// Initialize the idle thread
///
/// # Safety
/// Must be called once during kernel initialization
pub unsafe fn init_idle_thread() {
    // Get stack base (top of stack - stacks grow downward)
    let stack_base = IDLE_STACK.data.as_mut_ptr().add(constants::THREAD_STACK_SIZE);

    // Initialize idle thread structure
    IDLE_THREAD.thread_id = 0; // Thread 0 is always idle
    IDLE_THREAD.priority = 0;  // Lowest priority
    IDLE_THREAD.base_priority = 0;
    IDLE_THREAD.quantum = constants::THREAD_QUANTUM;
    IDLE_THREAD.state = ThreadState::Running; // Starts as running
    IDLE_THREAD.process = process::get_system_process_mut();
    IDLE_THREAD.stack_base = stack_base;
    IDLE_THREAD.stack_limit = IDLE_STACK.data.as_mut_ptr();
    IDLE_THREAD.wait_list_entry.init_head();
    IDLE_THREAD.thread_list_entry.init_head();

    // Initialize APC state
    IDLE_THREAD.apc_state.init(process::get_system_process_mut());
    IDLE_THREAD.special_apc_disable = 0;
    IDLE_THREAD.kernel_apc_disable = 0;
    IDLE_THREAD.alertable = false;
    IDLE_THREAD.apc_queueable = true;

    // Set up initial context for idle thread
    context::setup_initial_context(
        &mut IDLE_THREAD as *mut KThread,
        stack_base,
        idle_thread_entry,
    );

    // Set as idle thread and current thread in PRCB
    let prcb = prcb::get_current_prcb_mut();
    prcb.idle_thread = &mut IDLE_THREAD as *mut KThread;
    prcb.current_thread = &mut IDLE_THREAD as *mut KThread;
}

/// Get the idle thread
pub fn get_idle_thread() -> *mut KThread {
    unsafe { &mut IDLE_THREAD as *mut KThread }
}

/// Idle thread entry point
///
/// This function never returns. It runs a HLT loop, waiting for
/// interrupts. When an interrupt occurs (like the timer), the
/// scheduler may switch to another thread. When no other threads
/// are ready, execution returns here.
fn idle_thread_entry() {
    loop {
        // Enable interrupts and halt until the next interrupt
        // The timer interrupt will wake us up periodically
        unsafe {
            asm!(
                "sti",      // Enable interrupts
                "hlt",      // Halt until interrupt
                options(nomem, nostack, preserves_flags)
            );
        }

        // When we wake up from HLT, check if another thread became ready
        // The timer interrupt handler will set quantum_end or next_thread
        // and we'll context switch during the interrupt return path

        // For now, just loop back to HLT
    }
}

/// Check if the current thread is the idle thread
#[inline]
pub fn is_idle_thread() -> bool {
    let prcb = prcb::get_current_prcb();
    prcb.current_thread == prcb.idle_thread
}
