//! Idle Thread Implementation
//!
//! The idle thread runs at priority 0 (lowest) and is selected when
//! no other threads are ready to run. It executes a HLT loop to
//! reduce power consumption while waiting for interrupts.
//!
//! Each processor has its own idle thread.

use core::arch::asm;
use super::thread::{KThread, ThreadState, constants};
use super::prcb::{self, MAX_CPUS};
use super::process;
use crate::arch::x86_64::context;

/// Per-CPU idle threads
static mut IDLE_THREADS: [KThread; MAX_CPUS] = [const { KThread::new() }; MAX_CPUS];

/// Static stacks for idle threads (16KB each)
#[repr(C, align(16))]
#[derive(Copy, Clone)]
struct IdleStack {
    data: [u8; constants::THREAD_STACK_SIZE],
}

static mut IDLE_STACKS: [IdleStack; MAX_CPUS] = [IdleStack {
    data: [0; constants::THREAD_STACK_SIZE],
}; MAX_CPUS];

/// Initialize the idle thread for a specific CPU
///
/// # Safety
/// Must be called once per CPU during initialization
pub unsafe fn init_idle_thread(cpu_id: usize) {
    crate::serial_println!("[IDLE] Initializing idle thread for CPU {}", cpu_id);

    if cpu_id >= MAX_CPUS {
        crate::serial_println!("[IDLE] ERROR: cpu_id {} >= MAX_CPUS", cpu_id);
        return;
    }

    // Get stack base (top of stack - stacks grow downward)
    let stack_base = IDLE_STACKS[cpu_id].data.as_mut_ptr().add(constants::THREAD_STACK_SIZE);
    crate::serial_println!("[IDLE] Stack base: {:?}", stack_base);

    // Initialize idle thread structure
    IDLE_THREADS[cpu_id].thread_id = cpu_id as u32; // Each CPU's idle thread has unique ID
    IDLE_THREADS[cpu_id].priority = 0;  // Lowest priority
    IDLE_THREADS[cpu_id].base_priority = 0;
    IDLE_THREADS[cpu_id].quantum = constants::THREAD_QUANTUM;
    IDLE_THREADS[cpu_id].state = ThreadState::Running; // Starts as running
    IDLE_THREADS[cpu_id].process = process::get_system_process_mut();
    IDLE_THREADS[cpu_id].stack_base = stack_base;
    IDLE_THREADS[cpu_id].stack_limit = IDLE_STACKS[cpu_id].data.as_mut_ptr();
    IDLE_THREADS[cpu_id].wait_list_entry.init_head();
    IDLE_THREADS[cpu_id].thread_list_entry.init_head();

    // Initialize APC state
    IDLE_THREADS[cpu_id].apc_state.init(process::get_system_process_mut());
    IDLE_THREADS[cpu_id].special_apc_disable = 0;
    IDLE_THREADS[cpu_id].kernel_apc_disable = 0;
    IDLE_THREADS[cpu_id].alertable = false;
    IDLE_THREADS[cpu_id].apc_queueable = true;

    // Set up initial context for idle thread
    context::setup_initial_context(
        &mut IDLE_THREADS[cpu_id] as *mut KThread,
        stack_base,
        idle_thread_entry,
    );

    // Set as idle thread and current thread in this CPU's PRCB
    let idle_ptr = &mut IDLE_THREADS[cpu_id] as *mut KThread;
    crate::serial_println!("[IDLE] Setting PRCB idle/current thread to {:?}", idle_ptr);

    if let Some(prcb) = prcb::get_prcb_mut(cpu_id) {
        prcb.idle_thread = idle_ptr;
        prcb.current_thread = idle_ptr;
        crate::serial_println!("[IDLE] PRCB[{}] idle_thread set to {:?}", cpu_id, prcb.idle_thread);
    } else {
        crate::serial_println!("[IDLE] ERROR: get_prcb_mut({}) returned None!", cpu_id);
    }
}

/// Get the current CPU's idle thread
pub fn get_idle_thread() -> *mut KThread {
    let prcb = prcb::get_current_prcb();
    prcb.idle_thread
}

/// Get a specific CPU's idle thread
///
/// # Safety
/// Caller must ensure cpu_id is valid
pub unsafe fn get_idle_thread_for_cpu(cpu_id: usize) -> Option<*mut KThread> {
    if cpu_id < MAX_CPUS {
        Some(&mut IDLE_THREADS[cpu_id] as *mut KThread)
    } else {
        None
    }
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
