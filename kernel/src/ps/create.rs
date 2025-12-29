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
use crate::arch::x86_64::context::{setup_initial_context, setup_user_thread_context_with_teb};
use super::cid::{ps_allocate_process_id, ps_allocate_thread_id};
use super::eprocess::{EProcess, allocate_process, process_flags};
use super::ethread::{EThread, allocate_thread, thread_flags};
use super::peb::{allocate_peb, init_peb};
use super::teb::{allocate_teb, init_teb};

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

// ============================================================================
// User-Mode Thread Creation
// ============================================================================

/// Create a user-mode thread
///
/// Creates a thread that will execute in ring 3 (user mode).
/// The thread will have a kernel stack for syscall handling and
/// will IRETQ into user mode upon first scheduling.
///
/// # Arguments
/// * `process` - Owning process (must have user-mode address space)
/// * `entry_point` - Virtual address of user-mode entry point
/// * `user_stack` - Virtual address of user-mode stack top
/// * `priority` - Thread priority
///
/// # Returns
/// Pointer to new ETHREAD, or null on failure
///
/// # Safety
/// - process must have valid user-mode page tables
/// - entry_point and user_stack must be valid in the process's address space
pub unsafe fn ps_create_user_thread(
    process: *mut EProcess,
    entry_point: u64,
    user_stack: u64,
    priority: i8,
) -> *mut EThread {
    // Use default stack size
    let stack_size = 0x10000u64; // 64KB
    let stack_limit = user_stack - stack_size;
    ps_create_user_thread_ex(process, entry_point, user_stack, stack_limit, priority)
}

/// Create a user-mode thread with extended parameters
///
/// Extended version that includes stack limits for TEB initialization.
///
/// # Arguments
/// * `process` - Owning process (must have user-mode address space)
/// * `entry_point` - Virtual address of user-mode entry point
/// * `user_stack` - Virtual address of user-mode stack top (high address)
/// * `user_stack_limit` - Virtual address of user-mode stack bottom (low address)
/// * `priority` - Thread priority
///
/// # Returns
/// Pointer to new ETHREAD, or null on failure
pub unsafe fn ps_create_user_thread_ex(
    process: *mut EProcess,
    entry_point: u64,
    user_stack: u64,
    user_stack_limit: u64,
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

    // Allocate a kernel stack for this thread
    let (kernel_stack_top, _stack_index) = match allocate_stack() {
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

    // Allocate and initialize TEB
    let teb = match allocate_teb() {
        Some(t) => t,
        None => {
            crate::serial_println!("[PS] Failed to allocate TEB for thread");
            super::ethread::free_thread(thread);
            return ptr::null_mut();
        }
    };

    // Initialize TEB with process and thread info
    let peb = (*process).peb;
    let pid = (*process).unique_process_id as u64;
    init_teb(teb, peb, pid, tid as u64, user_stack, user_stack_limit);

    // Initialize the thread (using a dummy kernel-mode routine since we'll IRETQ to user)
    fn dummy_start(_: *mut u8) { loop { core::hint::spin_loop(); } }
    (*thread).init(
        process,
        tid,
        kernel_stack_top,
        constants::THREAD_STACK_SIZE,
        dummy_start,
        ptr::null_mut(),
        priority,
    );

    // Store TEB pointer in thread
    (*thread).teb = teb;

    // Set user-mode entry point
    (*thread).start_address = entry_point as *mut u8;
    (*thread).win32_start_address = entry_point as *mut u8;

    // Set up the kernel stack with trap frame for IRETQ to user mode
    // Pass TEB address for GS base setup
    setup_user_thread_context_with_teb(
        (*thread).get_tcb_mut(),
        kernel_stack_top,
        entry_point,
        user_stack,
        teb as u64,
    );

    // Add thread to process's thread list
    (*process).thread_list_head.insert_tail(&mut (*thread).thread_list_entry);
    (*process).increment_thread_count();

    crate::serial_println!("[PS] Created user-mode thread {} in process {} (entry={:#x}, TEB={:p})",
        tid, (*process).unique_process_id, entry_point, teb);

    thread
}

/// Create a user-mode process with initial thread
///
/// Creates a process with its user-mode address space and creates
/// an initial thread to execute at the given entry point.
///
/// # Arguments
/// * `parent` - Parent process
/// * `name` - Process image name
/// * `entry_point` - Virtual address of user-mode entry point
/// * `user_stack` - Virtual address of user-mode stack top
/// * `cr3` - Page table physical address for this process
/// * `image_base` - Base address where executable was loaded
/// * `image_size` - Size of loaded executable
/// * `subsystem` - PE subsystem (GUI, CUI, etc.)
///
/// # Returns
/// Tuple of (process, thread) pointers, or (null, null) on failure
///
/// # Safety
/// - entry_point and user_stack must be valid in the new address space
/// - cr3 must be a valid page table with user-mode mappings
pub unsafe fn ps_create_user_process(
    parent: *mut EProcess,
    name: &[u8],
    entry_point: u64,
    user_stack: u64,
    _cr3: u64,
) -> (*mut EProcess, *mut EThread) {
    ps_create_user_process_ex(parent, name, entry_point, user_stack, _cr3, 0, 0, 0)
}

/// Create a user-mode process with full parameters
///
/// Extended version that accepts image information for PEB initialization.
pub unsafe fn ps_create_user_process_ex(
    parent: *mut EProcess,
    name: &[u8],
    entry_point: u64,
    user_stack: u64,
    _cr3: u64,
    image_base: u64,
    image_size: u32,
    subsystem: u16,
) -> (*mut EProcess, *mut EThread) {
    // Create the process
    let process = ps_create_process(parent, name, 8);
    if process.is_null() {
        return (ptr::null_mut(), ptr::null_mut());
    }

    // Allocate and initialize PEB
    let peb = match allocate_peb() {
        Some(p) => p,
        None => {
            crate::serial_println!("[PS] Failed to allocate PEB for process");
            // TODO: Clean up the process
            return (ptr::null_mut(), ptr::null_mut());
        }
    };

    // Initialize PEB with image information
    init_peb(peb, image_base, image_size, entry_point, subsystem);

    // Store PEB pointer in process
    (*process).peb = peb;

    // Create the initial thread (with stack size for TEB initialization)
    let user_stack_size = 0x10000u64; // 64KB default stack
    let user_stack_limit = user_stack - user_stack_size;
    let thread = ps_create_user_thread_ex(process, entry_point, user_stack, user_stack_limit, 8);
    if thread.is_null() {
        // TODO: Clean up PEB and process
        return (process, ptr::null_mut());
    }

    (process, thread)
}

/// Start a user-mode thread
///
/// Makes the user-mode thread ready to run. When scheduled, it will
/// IRETQ into user mode at its entry point.
///
/// # Safety
/// Thread must be properly initialized via ps_create_user_thread
pub unsafe fn ps_start_user_thread(thread: *mut EThread) {
    if thread.is_null() {
        return;
    }

    // Ready the thread in the scheduler
    ki_ready_thread((*thread).get_tcb_mut());
}
