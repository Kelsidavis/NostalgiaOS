//! Process and Thread Creation
//!
//! This module provides functions for creating processes and threads.
//!
//! # Process Creation
//! - PsCreateSystemProcess: Create a system process
//! - PsCreateProcess: Create a user-mode process
//!
//! # Thread Creation
//! - PsCreateSystemThread: Create a kernel-mode thread
//! - PsCreateThread: Create a user-mode thread

use core::ptr;
use crate::ke::{
    thread::constants,
    scheduler::ki_ready_thread,
    SpinLock,
};
use crate::arch::x86_64::context::setup_initial_context;
use super::cid::{ps_allocate_process_id, ps_allocate_thread_id};
use super::eprocess::{EProcess, allocate_process, process_flags};
use super::ethread::{EThread, allocate_thread, thread_flags};

// ============================================================================
// Stack Pool for PS threads
// ============================================================================

/// Stack pool for PS-created threads
static mut PS_STACK_POOL: [[u8; constants::THREAD_STACK_SIZE]; super::cid::MAX_THREADS] =
    [[0; constants::THREAD_STACK_SIZE]; super::cid::MAX_THREADS];

/// Stack pool bitmap
static mut PS_STACK_BITMAP: [u64; 4] = [0; 4];

/// Stack pool lock
static PS_STACK_LOCK: SpinLock<()> = SpinLock::new(());

/// Allocate a stack
unsafe fn allocate_stack() -> Option<(*mut u8, usize)> {
    let _guard = PS_STACK_LOCK.lock();

    for word_idx in 0..4 {
        if PS_STACK_BITMAP[word_idx] != u64::MAX {
            for bit_idx in 0..64 {
                let global_idx = word_idx * 64 + bit_idx;
                if global_idx >= super::cid::MAX_THREADS {
                    return None;
                }
                if PS_STACK_BITMAP[word_idx] & (1 << bit_idx) == 0 {
                    PS_STACK_BITMAP[word_idx] |= 1 << bit_idx;
                    let stack_base = PS_STACK_POOL[global_idx].as_mut_ptr()
                        .add(constants::THREAD_STACK_SIZE);
                    return Some((stack_base, global_idx));
                }
            }
        }
    }
    None
}

/// Free a stack
unsafe fn free_stack(index: usize) {
    let _guard = PS_STACK_LOCK.lock();

    if index < super::cid::MAX_THREADS {
        let word_idx = index / 64;
        let bit_idx = index % 64;
        PS_STACK_BITMAP[word_idx] &= !(1 << bit_idx);
    }
}

// ============================================================================
// Process Creation
// ============================================================================

/// Create a new process
///
/// # Arguments
/// * `parent` - Parent process (or null for no parent)
/// * `name` - Process image name
/// * `base_priority` - Base priority for threads
///
/// # Returns
/// Pointer to new EPROCESS, or null on failure
///
/// # Safety
/// Must be called with interrupts disabled or proper synchronization
pub unsafe fn ps_create_process(
    parent: *mut EProcess,
    name: &[u8],
    base_priority: i8,
) -> *mut EProcess {
    // Allocate a process structure
    let process = match allocate_process() {
        Some(p) => p,
        None => return ptr::null_mut(),
    };

    // Allocate a process ID
    let pid = ps_allocate_process_id(process as *mut u8);
    if pid == 0 && !parent.is_null() {
        // PID 0 is reserved for system process
        super::eprocess::free_process(process);
        return ptr::null_mut();
    }

    // Get parent PID
    let parent_pid = if parent.is_null() {
        0
    } else {
        (*parent).unique_process_id
    };

    // Initialize the process
    (*process).init(pid, parent_pid, name, base_priority);

    // Add to active process list
    let list_head = super::eprocess::get_active_process_list();
    (*list_head).insert_tail(&mut (*process).active_process_links);

    crate::serial_println!("[PS] Created process {} '{}'", pid,
        core::str::from_utf8_unchecked((*process).image_name()));

    process
}

/// Create a system process
///
/// Creates a process for kernel-mode operations (no user-mode address space)
pub unsafe fn ps_create_system_process(name: &[u8]) -> *mut EProcess {
    let process = ps_create_process(
        super::eprocess::get_system_process(),
        name,
        8, // Normal priority
    );

    if !process.is_null() {
        (*process).set_flag(process_flags::PS_PROCESS_FLAGS_SYSTEM);
    }

    process
}

// ============================================================================
// Thread Creation
// ============================================================================

/// Thread start wrapper function type
pub type PsThreadStartRoutine = fn(*mut u8);

/// Create a new thread in a process
///
/// # Arguments
/// * `process` - Owning process
/// * `start_routine` - Thread entry point
/// * `start_context` - Argument to pass to start routine
/// * `priority` - Thread priority
///
/// # Returns
/// Pointer to new ETHREAD, or null on failure
///
/// # Safety
/// Must be called with interrupts disabled or proper synchronization
pub unsafe fn ps_create_thread(
    process: *mut EProcess,
    start_routine: fn(*mut u8),
    start_context: *mut u8,
    priority: i8,
) -> *mut EThread {
    if process.is_null() {
        return ptr::null_mut();
    }

    // Allocate a thread structure
    let thread = match allocate_thread() {
        Some(t) => t,
        None => return ptr::null_mut(),
    };

    // Allocate a stack
    let (stack_base, _stack_index) = match allocate_stack() {
        Some((base, idx)) => (base, idx),
        None => {
            super::ethread::free_thread(thread);
            return ptr::null_mut();
        }
    };

    // Allocate a thread ID
    let tid = ps_allocate_thread_id(thread as *mut u8);
    if tid == 0 {
        super::ethread::free_thread(thread);
        return ptr::null_mut();
    }

    // Initialize the thread
    (*thread).init(
        process,
        tid,
        stack_base,
        constants::THREAD_STACK_SIZE,
        start_routine,
        start_context,
        priority,
    );

    // Set up initial CPU context
    setup_initial_context(
        (*thread).get_tcb_mut(),
        stack_base,
        || {
            // This is the wrapper that will call the actual start routine
            // For now, just halt - actual implementation would get the thread
            // and call its start routine
            loop {
                core::arch::asm!("hlt");
            }
        },
    );

    // Add thread to process's thread list
    (*process).thread_list_head.insert_tail(&mut (*thread).thread_list_entry);
    (*process).increment_thread_count();

    crate::serial_println!("[PS] Created thread {} in process {}",
        tid, (*process).unique_process_id);

    thread
}

/// Create a system thread
///
/// Creates a thread in the system process for kernel-mode operations
///
/// # Arguments
/// * `start_routine` - Thread entry point
/// * `start_context` - Argument to pass to start routine
/// * `priority` - Thread priority
///
/// # Returns
/// Pointer to new ETHREAD, or null on failure
pub unsafe fn ps_create_system_thread(
    start_routine: fn(*mut u8),
    start_context: *mut u8,
    priority: i8,
) -> *mut EThread {
    let system_process = super::eprocess::get_system_process();

    let thread = ps_create_thread(
        system_process,
        start_routine,
        start_context,
        priority,
    );

    if !thread.is_null() {
        (*thread).set_flag(thread_flags::PS_THREAD_FLAGS_SYSTEM);
    }

    thread
}

/// Start a thread (make it ready to run)
///
/// # Safety
/// Thread must be properly initialized
pub unsafe fn ps_start_thread(thread: *mut EThread) {
    if thread.is_null() {
        return;
    }

    // Ready the thread in the scheduler
    ki_ready_thread((*thread).get_tcb_mut());
}

/// Create and start a system thread in one call
///
/// This is a convenience function that creates a thread and immediately
/// makes it ready to run.
pub unsafe fn ps_create_and_start_system_thread(
    start_routine: fn(*mut u8),
    start_context: *mut u8,
    priority: i8,
) -> *mut EThread {
    let thread = ps_create_system_thread(start_routine, start_context, priority);
    if !thread.is_null() {
        ps_start_thread(thread);
    }
    thread
}
