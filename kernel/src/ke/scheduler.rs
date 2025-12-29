//! NT-style Priority Scheduler
//!
//! Implements a 32-level priority scheduler with:
//! - O(1) thread selection using ready summary bitmap
//! - Quantum-based preemption
//! - Priority boost/decay for dynamic priority threads
//!
//! Priority levels:
//! - 0-15: Dynamic (variable) priority threads
//! - 16-31: Realtime (fixed) priority threads

use core::ptr;
use super::thread::{KThread, ThreadState, constants};
use super::prcb::{KPrcb, get_current_prcb_mut};
use super::apc::{ApcMode, ki_deliver_apc};
use crate::containing_record;

/// Insert a thread into the ready queue
///
/// The thread is placed at the tail of its priority queue (round-robin within priority).
///
/// # Safety
/// - Thread must not already be in a ready queue
/// - Must be called with interrupts disabled
pub unsafe fn ki_ready_thread(thread: *mut KThread) {
    let prcb = get_current_prcb_mut();
    let priority = (*thread).priority as usize;

    // Set thread state to Ready
    (*thread).state = ThreadState::Ready;

    // Insert at tail of this priority's queue
    let queue = &mut prcb.ready_queues[priority];
    queue.insert_tail(&mut (*thread).wait_list_entry);

    // Update ready summary bitmap
    prcb.set_ready_bit(priority);
}

/// Select the highest priority ready thread
///
/// Removes and returns the first thread from the highest priority non-empty queue.
///
/// # Safety
/// Must be called with interrupts disabled
pub unsafe fn ki_select_ready_thread(prcb: &mut KPrcb) -> Option<*mut KThread> {
    // Find highest priority with ready threads
    let priority = prcb.find_highest_ready_priority()?;

    // Get the queue for this priority
    let queue = &mut prcb.ready_queues[priority];

    // Remove first thread from queue
    let entry = queue.remove_head();

    // Check if queue is now empty
    if queue.is_empty() {
        prcb.clear_ready_bit(priority);
    }

    // Get thread from list entry
    let thread = containing_record!(entry, KThread, wait_list_entry);
    Some(thread)
}

/// Remove a thread from the ready queue
///
/// # Safety
/// - Thread must be in a ready queue
/// - Must be called with interrupts disabled
pub unsafe fn ki_unready_thread(thread: *mut KThread) {
    let prcb = get_current_prcb_mut();
    let priority = (*thread).priority as usize;

    // Remove from queue
    (*thread).wait_list_entry.remove_entry();

    // Check if this priority queue is now empty
    if prcb.ready_queues[priority].is_empty() {
        prcb.clear_ready_bit(priority);
    }
}

/// Handle quantum expiration (called from timer interrupt)
///
/// Decrements the current thread's quantum and triggers a context switch
/// if the quantum has expired.
///
/// # Safety
/// Must be called from timer interrupt context
pub unsafe fn ki_quantum_end() {
    let prcb = get_current_prcb_mut();
    let current = prcb.current_thread;

    if current.is_null() {
        return;
    }

    // Decrement quantum
    (*current).quantum -= constants::CLOCK_QUANTUM_DECREMENT;

    if (*current).quantum <= 0 {
        // Quantum expired - need to reschedule
        prcb.quantum_end = true;

        // Reset quantum
        (*current).quantum = constants::THREAD_QUANTUM;

        // For non-realtime threads, decay priority
        if !(*current).is_realtime() && (*current).priority > (*current).base_priority {
            (*current).priority -= 1;
        }

        // Request dispatch
        ki_dispatch_interrupt();
    }
}

/// Request a dispatch interrupt
///
/// Schedules the scheduler to run at DISPATCH_LEVEL to perform a context switch.
/// For now, this directly calls the dispatcher since we don't have full IRQL support.
///
/// # Safety
/// Must be called with proper synchronization
pub unsafe fn ki_dispatch_interrupt() {
    let prcb = get_current_prcb_mut();

    // If no next thread selected, pick one
    if prcb.next_thread.is_null() {
        if let Some(thread) = ki_select_ready_thread(prcb) {
            prcb.next_thread = thread;
        } else if prcb.current_thread != prcb.idle_thread {
            // No ready threads and we're not the idle thread - switch to idle
            prcb.next_thread = prcb.idle_thread;
        }
    }

    // If we have a next thread and it's different from current, switch
    if !prcb.next_thread.is_null() && prcb.next_thread != prcb.current_thread {
        ki_swap_context_internal();
    }
}

/// Internal context switch implementation
///
/// Performs the actual context switch between current and next thread.
///
/// # Safety
/// Must be called from dispatcher context
unsafe fn ki_swap_context_internal() {
    let prcb = get_current_prcb_mut();

    let old_thread = prcb.current_thread;
    let new_thread = prcb.next_thread;

    if new_thread.is_null() {
        return;
    }

    // Don't switch to the same thread
    if old_thread == new_thread {
        prcb.next_thread = ptr::null_mut();
        return;
    }

    // Deliver any pending kernel APCs before switching away
    if !old_thread.is_null() && (*old_thread).apc_state.kernel_apc_pending {
        ki_deliver_apc(ApcMode::KernelMode);
    }

    // Clear next thread
    prcb.next_thread = ptr::null_mut();

    // Update states - but don't put idle thread back on ready queue
    if !old_thread.is_null()
        && (*old_thread).state == ThreadState::Running {
            // Only put non-idle threads back on the ready queue
            // Idle thread (priority 0) stays off the queue - it runs when nothing else can
            if old_thread != prcb.idle_thread {
                (*old_thread).state = ThreadState::Ready;
                ki_ready_thread(old_thread);
            }
        }

    (*new_thread).state = ThreadState::Running;
    prcb.current_thread = new_thread;
    prcb.context_switches += 1;
    prcb.quantum_end = false;

    // Perform the actual register save/restore
    if !old_thread.is_null() {
        crate::arch::x86_64::context::ki_swap_context(old_thread, new_thread);
    } else {
        // No old thread (initial switch) - just load new thread's context
        crate::arch::x86_64::context::ki_load_context(new_thread);
    }
}

/// Switch from the current thread to a specific thread
///
/// This is the main entry point for voluntary context switches.
///
/// # Safety
/// Must be called at IRQL < DISPATCH_LEVEL
pub unsafe fn ki_switch_to_thread(new_thread: *mut KThread) {
    let prcb = get_current_prcb_mut();

    // Set as next thread and dispatch
    prcb.next_thread = new_thread;
    ki_dispatch_interrupt();
}

/// Yield the current thread's remaining quantum
///
/// The current thread is placed back on the ready queue and another thread
/// (of the same or higher priority) may run.
///
/// # Safety
/// Must be called from thread context
pub unsafe fn ki_yield() {
    let prcb = get_current_prcb_mut();
    let current = prcb.current_thread;

    if current.is_null() {
        return;
    }

    // Reset quantum
    (*current).quantum = constants::THREAD_QUANTUM;

    // Put current thread back on ready queue
    (*current).state = ThreadState::Ready;
    ki_ready_thread(current);

    // Select next thread and switch
    if let Some(next) = ki_select_ready_thread(prcb) {
        prcb.next_thread = next;
        ki_dispatch_interrupt();
    }
}

/// Boost a thread's priority temporarily
///
/// Used for priority inversion prevention and I/O completion.
/// The boost decays over time back to base priority.
///
/// # Safety
/// Must be called with proper synchronization
pub unsafe fn ki_boost_priority(thread: *mut KThread, boost: i8) {
    // Only boost dynamic priority threads
    if (*thread).is_realtime() {
        return;
    }

    let new_priority = ((*thread).base_priority + boost).min(constants::LOW_REALTIME_PRIORITY - 1);
    (*thread).priority = new_priority;
}

/// Set a thread's base priority
///
/// # Safety
/// Must be called with proper synchronization
pub unsafe fn ke_set_priority(thread: *mut KThread, priority: i8) {
    let old_priority = (*thread).priority;
    (*thread).base_priority = priority;
    (*thread).priority = priority;

    // If thread is ready and priority changed, may need to requeue
    if (*thread).state == ThreadState::Ready && priority != old_priority {
        ki_unready_thread(thread);
        ki_ready_thread(thread);

        // If new priority is higher than current thread, preempt
        let prcb = get_current_prcb_mut();
        if !prcb.current_thread.is_null()
            && priority > (*prcb.current_thread).priority {
                prcb.next_thread = thread;
                ki_dispatch_interrupt();
            }
    }
}

/// Delay execution for the specified number of milliseconds
///
/// Puts the current thread to sleep for approximately the specified time.
///
/// # Safety
/// Must be called from thread context
/// Delay execution for the specified number of milliseconds
///
/// This is the proper timer-based implementation that puts the thread to sleep
/// and wakes it when the timer expires, rather than busy-waiting.
///
/// Equivalent to KeDelayExecutionThread
pub unsafe fn ki_delay_execution(delay_ms: u64) {
    use super::timer::KTimer;
    use super::wait::ke_wait_for_single_object;
    use super::dispatcher::DispatcherHeader;

    if delay_ms == 0 {
        // Zero delay just yields
        ki_yield();
        return;
    }

    // Get the current thread
    let prcb = super::prcb::get_current_prcb_mut();
    let thread = prcb.current_thread;

    if thread.is_null() {
        return;
    }

    // Use a static timer for sleep operations
    // In a full implementation, each thread would have its own wait timer
    static SLEEP_TIMER: KTimer = KTimer::new();

    // Initialize and set the timer
    SLEEP_TIMER.init();
    SLEEP_TIMER.set(delay_ms as u32, 0, None);

    // Wait for the timer to expire
    // The wait infrastructure handles putting the thread to sleep
    // and waking it when the timer fires
    let _ = ke_wait_for_single_object(
        &SLEEP_TIMER.header as *const DispatcherHeader as *mut DispatcherHeader,
        Some(delay_ms),
    );

    // Cancel timer in case wait returned early (e.g., due to APC)
    SLEEP_TIMER.cancel();
}

/// List all active threads
///
/// # Safety
/// Accesses thread pool directly
pub unsafe fn list_threads() {
    use super::thread::{THREAD_POOL, THREAD_POOL_BITMAP};

    for i in 0..constants::MAX_THREADS {
        if THREAD_POOL_BITMAP & (1 << i) != 0 {
            let thread = &THREAD_POOL[i];

            let state_str = match thread.state {
                ThreadState::Initialized => "Init  ",
                ThreadState::Ready => "Ready ",
                ThreadState::Running => "Run   ",
                ThreadState::Standby => "Standby",
                ThreadState::Terminated => "Term  ",
                ThreadState::Waiting => "Wait  ",
                ThreadState::Transition => "Trans ",
                ThreadState::DeferredReady => "DfRdy ",
                ThreadState::Suspended => "Suspnd",
            };

            crate::serial_println!("  {:>3}  {}      {:>2}",
                thread.thread_id,
                state_str,
                thread.priority
            );
        }
    }
}
