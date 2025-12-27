//! Multi-Object Wait Support
//!
//! Provides NT-compatible wait functions that allow threads to wait on
//! one or more dispatcher objects (events, mutexes, semaphores, timers).
//!
//! # Wait Types
//! - **WaitAny**: Wait satisfied when any one object is signaled
//! - **WaitAll**: Wait satisfied when all objects are signaled simultaneously
//!
//! # Timeout Support
//! All wait functions support optional timeouts using kernel timers.
//!
//! # NT Compatibility
//! - `ke_wait_for_single_object` - Equivalent to KeWaitForSingleObject
//! - `ke_wait_for_multiple_objects` - Equivalent to KeWaitForMultipleObjects
//!
//! # Usage
//! ```
//! // Wait for a single event
//! let status = ke_wait_for_single_object(&event.header, None);
//!
//! // Wait for any of multiple objects with 1000ms timeout
//! let objects = [&event1.header, &mutex1.header, &sem1.header];
//! let status = ke_wait_for_multiple_objects(&objects, WaitType::WaitAny, Some(1000));
//! ```

use super::dispatcher::{
    DispatcherHeader, DispatcherType, KWaitBlock, WaitType, WaitStatus,
    MAXIMUM_WAIT_OBJECTS,
};
use super::thread::{KThread, ThreadState};
use super::timer::KTimer;
use super::prcb::get_current_prcb_mut;
use super::scheduler;
use crate::containing_record;

/// Timeout representing an infinite wait
pub const TIMEOUT_INFINITE: u64 = u64::MAX;

/// Wait reason (for debugging/profiling)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WaitReason {
    /// Executive wait (general purpose)
    Executive = 0,
    /// Waiting for free page
    FreePage = 1,
    /// Waiting for page in
    PageIn = 2,
    /// Waiting on pool allocation
    PoolAllocation = 3,
    /// Waiting for executive resource
    ExecutiveResource = 4,
    /// Suspended
    Suspended = 5,
    /// User request
    UserRequest = 6,
    /// Event pair high
    EventPairHigh = 7,
    /// Event pair low
    EventPairLow = 8,
    /// LPC receive
    LpcReceive = 9,
    /// LPC reply
    LpcReply = 10,
    /// Virtual memory
    VirtualMemory = 11,
    /// Page out
    PageOut = 12,
    /// Maximum wait reason
    MaximumWaitReason = 13,
}

/// Wait mode (kernel or user)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WaitMode {
    /// Kernel mode wait
    KernelMode = 0,
    /// User mode wait
    UserMode = 1,
}

/// Wait for a single dispatcher object
///
/// Blocks the calling thread until the object is signaled or the timeout expires.
///
/// # Arguments
/// * `object` - Pointer to the dispatcher object header
/// * `timeout_ms` - Optional timeout in milliseconds (None = infinite wait)
///
/// # Returns
/// * `WaitStatus::Object0` - Object was signaled
/// * `WaitStatus::Timeout` - Wait timed out
/// * `WaitStatus::Abandoned` - Mutex was abandoned (owner terminated)
///
/// # Safety
/// - Must be called from thread context (not interrupt/DPC)
/// - Object must be a valid dispatcher object
pub unsafe fn ke_wait_for_single_object(
    object: *mut DispatcherHeader,
    timeout_ms: Option<u64>,
) -> WaitStatus {
    // Just delegate to multi-object wait with single object
    let objects = [object];
    ke_wait_for_multiple_objects(&objects, WaitType::WaitAny, timeout_ms)
}

/// Wait for multiple dispatcher objects
///
/// Blocks the calling thread until the wait condition is satisfied or timeout expires.
///
/// # Arguments
/// * `objects` - Slice of pointers to dispatcher object headers
/// * `wait_type` - WaitAny (any object) or WaitAll (all objects)
/// * `timeout_ms` - Optional timeout in milliseconds (None = infinite wait)
///
/// # Returns
/// * `WaitStatus::Object0` + index - For WaitAny, indicates which object was signaled
/// * `WaitStatus::Object0` - For WaitAll, all objects were signaled
/// * `WaitStatus::Timeout` - Wait timed out
/// * `WaitStatus::Abandoned` - A mutex was abandoned
///
/// # Safety
/// - Must be called from thread context (not interrupt/DPC)
/// - All objects must be valid dispatcher objects
/// - Number of objects must not exceed MAXIMUM_WAIT_OBJECTS
pub unsafe fn ke_wait_for_multiple_objects(
    objects: &[*mut DispatcherHeader],
    wait_type: WaitType,
    timeout_ms: Option<u64>,
) -> WaitStatus {
    let count = objects.len();

    // Validate count
    if count == 0 {
        return WaitStatus::Invalid;
    }
    if count > MAXIMUM_WAIT_OBJECTS {
        return WaitStatus::Invalid;
    }

    let prcb = get_current_prcb_mut();
    let thread = prcb.current_thread;

    if thread.is_null() {
        return WaitStatus::Invalid;
    }

    // Fast path: check if wait can be satisfied immediately
    if let Some(status) = try_satisfy_wait_immediate(objects, wait_type, thread) {
        return status;
    }

    // Slow path: must block and wait
    wait_for_objects_blocking(thread, objects, wait_type, timeout_ms)
}

/// Try to satisfy the wait immediately without blocking
///
/// Returns Some(status) if wait can be satisfied now, None if we must block.
unsafe fn try_satisfy_wait_immediate(
    objects: &[*mut DispatcherHeader],
    wait_type: WaitType,
    thread: *mut KThread,
) -> Option<WaitStatus> {
    match wait_type {
        WaitType::WaitAny => {
            // Check if any object is signaled
            for (index, &object) in objects.iter().enumerate() {
                if try_satisfy_object(object, thread) {
                    return Some(wait_status_for_index(index));
                }
            }
            None
        }
        WaitType::WaitAll => {
            // First check if all objects are signaled (without consuming)
            let all_signaled = objects.iter().all(|&obj| is_object_signaled(obj));

            if all_signaled {
                // All signaled - now consume all
                for &object in objects.iter() {
                    consume_object_signal(object, thread);
                }
                Some(WaitStatus::Object0)
            } else {
                None
            }
        }
    }
}

/// Check if an object is signaled
unsafe fn is_object_signaled(object: *mut DispatcherHeader) -> bool {
    if object.is_null() {
        return false;
    }

    let header = &*object;

    match header.object_type {
        DispatcherType::Mutex => {
            // Mutex is signaled if not owned, OR if owned by current thread
            if header.signal_state() > 0 {
                return true;
            }
            // Check for recursive acquisition
            let prcb = get_current_prcb_mut();
            let mutex = object as *mut super::mutex::KMutex;
            (*mutex).owner() == prcb.current_thread
        }
        _ => header.signal_state() > 0,
    }
}

/// Try to satisfy/consume an object's signal for a single wait
///
/// Returns true if the object was signaled and consumed (for WaitAny)
unsafe fn try_satisfy_object(object: *mut DispatcherHeader, thread: *mut KThread) -> bool {
    if object.is_null() {
        return false;
    }

    if !is_object_signaled(object) {
        return false;
    }

    consume_object_signal(object, thread);
    true
}

/// Consume an object's signal (called when wait is satisfied)
unsafe fn consume_object_signal(object: *mut DispatcherHeader, thread: *mut KThread) {
    let header = &*object;

    match header.object_type {
        DispatcherType::Event => {
            // Auto-reset events reset to 0
            // Notification events stay signaled
            let event = object as *mut super::event::KEvent;
            if (*event).event_type() == super::event::EventType::Synchronization {
                header.set_signal_state(0);
            }
        }
        DispatcherType::Mutex => {
            // Take ownership of mutex
            let mutex = object as *mut super::mutex::KMutex;
            if (*mutex).owner() == thread {
                // Recursive acquisition - increment count
                // This is handled internally by mutex
            } else {
                // New acquisition
                header.set_signal_state(0);
                // Set owner through internal pointer
                let owner_ptr = (object as *mut u8).add(core::mem::size_of::<DispatcherHeader>())
                    as *mut *mut KThread;
                *owner_ptr = thread;
                // Set recursion count to 1
                let count_ptr = owner_ptr.add(1) as *mut u32;
                *count_ptr = 1;
            }
        }
        DispatcherType::Semaphore => {
            // Decrement count
            let count = header.signal_state();
            if count > 0 {
                header.set_signal_state(count - 1);
            }
        }
        DispatcherType::Timer => {
            // Synchronization timers reset
            // Only sync timers auto-reset (notification timers stay signaled)
            // For now, don't auto-reset timers - they're typically notification type
        }
        _ => {
            // Other objects: just mark as consumed if auto-reset style
        }
    }
}

/// Wait for objects with blocking
unsafe fn wait_for_objects_blocking(
    thread: *mut KThread,
    objects: &[*mut DispatcherHeader],
    wait_type: WaitType,
    timeout_ms: Option<u64>,
) -> WaitStatus {
    let count = objects.len();

    // Allocate wait blocks on stack
    // We support up to MAXIMUM_WAIT_OBJECTS, but stack space is limited
    // For now, limit to a reasonable number
    const MAX_STACK_WAIT_BLOCKS: usize = 16;
    let mut wait_blocks: [KWaitBlock; MAX_STACK_WAIT_BLOCKS] =
        [KWaitBlock::new(); MAX_STACK_WAIT_BLOCKS];

    if count > MAX_STACK_WAIT_BLOCKS {
        // Would need dynamic allocation - not supported yet
        return WaitStatus::Invalid;
    }

    // Optional timeout timer
    let timeout_timer = KTimer::new();
    let mut timeout_wait_block = KWaitBlock::new();
    let using_timeout = timeout_ms.is_some() && timeout_ms != Some(TIMEOUT_INFINITE);

    // Set up thread wait state
    (*thread).wait_status = WaitStatus::Object0;
    (*thread).wait_block_list = wait_blocks.as_mut_ptr();
    (*thread).wait_type = wait_type;
    (*thread).wait_count = count as u8;

    // Initialize wait blocks and insert into object wait lists
    for (i, &object) in objects.iter().enumerate() {
        let block = &mut wait_blocks[i];
        block.wait_list_entry.init_head();
        block.thread = thread;
        block.object = object;
        block.wait_type = wait_type;
        block.block_index = i as u8;

        // Insert into object's wait list
        (*object).wait_list().insert_tail(&mut block.wait_list_entry);
    }

    // Set up timeout timer if needed
    if using_timeout {
        timeout_timer.init();
        timeout_timer.set(timeout_ms.unwrap() as u32, 0, None);

        // Set up timeout wait block
        timeout_wait_block.wait_list_entry.init_head();
        timeout_wait_block.thread = thread;
        timeout_wait_block.object = &timeout_timer.header as *const _ as *mut DispatcherHeader;
        timeout_wait_block.wait_type = WaitType::WaitAny;
        timeout_wait_block.block_index = count as u8; // Timer is last block

        // Insert timeout block into timer's wait list
        timeout_timer.header.wait_list().insert_tail(&mut timeout_wait_block.wait_list_entry);
    }

    // Set thread to waiting state
    (*thread).state = ThreadState::Waiting;

    // Enter wait loop
    loop {
        // Yield to scheduler - will return when we're woken
        scheduler::ki_dispatch_interrupt();

        // We've been woken - check why

        // Check if timeout occurred
        if using_timeout && timeout_timer.is_signaled() {
            // Remove wait blocks from all objects
            remove_wait_blocks(&mut wait_blocks[..count], objects);
            (*thread).state = ThreadState::Running;
            return WaitStatus::Timeout;
        }

        // Check if wait is satisfied
        match wait_type {
            WaitType::WaitAny => {
                // Check which object woke us
                for (i, &object) in objects.iter().enumerate() {
                    if is_object_signaled(object) {
                        // This object is signaled - consume and return
                        remove_wait_blocks(&mut wait_blocks[..count], objects);
                        if using_timeout {
                            timeout_timer.cancel();
                        }
                        consume_object_signal(object, thread);
                        (*thread).state = ThreadState::Running;
                        return wait_status_for_index(i);
                    }
                }
            }
            WaitType::WaitAll => {
                // Check if all objects are signaled
                let all_signaled = objects.iter().all(|&obj| is_object_signaled(obj));
                if all_signaled {
                    // All signaled - consume all and return
                    remove_wait_blocks(&mut wait_blocks[..count], objects);
                    if using_timeout {
                        timeout_timer.cancel();
                    }
                    for &object in objects.iter() {
                        consume_object_signal(object, thread);
                    }
                    (*thread).state = ThreadState::Running;
                    return WaitStatus::Object0;
                }
            }
        }

        // Not satisfied yet - go back to waiting
        (*thread).state = ThreadState::Waiting;
    }
}

/// Remove wait blocks from object wait lists
unsafe fn remove_wait_blocks(wait_blocks: &mut [KWaitBlock], objects: &[*mut DispatcherHeader]) {
    for (i, block) in wait_blocks.iter_mut().enumerate() {
        if i < objects.len() {
            block.wait_list_entry.remove_entry();
        }
    }
}

/// Convert an object index to a WaitStatus
fn wait_status_for_index(index: usize) -> WaitStatus {
    // NT returns STATUS_WAIT_0 + index
    // We encode this in the WaitStatus enum
    match index {
        0 => WaitStatus::Object0,
        n => {
            // Create status with offset
            // This is a bit hacky - in real NT this would be STATUS_WAIT_0 + n
            unsafe { core::mem::transmute((n as i32) & 0x3F) }
        }
    }
}

/// Signal a dispatcher object and satisfy waiting threads
///
/// This is the main entry point for signaling objects.
/// Called by event.set(), semaphore.release(), mutex.release(), timer expiration, etc.
///
/// # Arguments
/// * `object` - The object being signaled
/// * `increment` - Priority boost for woken threads (0 for no boost)
/// * `wait` - If true, caller will immediately wait (optimization)
///
/// # Safety
/// Must be called with appropriate synchronization
pub unsafe fn ki_signal_object(
    object: *mut DispatcherHeader,
    increment: i8,
    _wait: bool,
) {
    if object.is_null() {
        return;
    }

    let header = &*object;

    // Signal the object
    header.set_signal_state(1);

    // Wake waiting threads based on object type
    match header.object_type {
        DispatcherType::Event => {
            let event = object as *mut super::event::KEvent;
            if (*event).event_type() == super::event::EventType::Notification {
                // Notification: wake all waiters
                wake_all_waiters(object, increment);
            } else {
                // Synchronization: wake one waiter
                if header.has_waiters() {
                    wake_one_waiter(object, increment);
                    header.set_signal_state(0); // Auto-reset
                }
            }
        }
        DispatcherType::Semaphore => {
            // Wake as many as the new count allows
            let count = header.signal_state();
            let mut remaining = count;
            while remaining > 0 && header.has_waiters() {
                wake_one_waiter(object, increment);
                remaining -= 1;
            }
            header.set_signal_state(remaining);
        }
        DispatcherType::Timer => {
            // Wake all waiters for timers
            wake_all_waiters(object, increment);
        }
        DispatcherType::Mutex => {
            // Wake one waiter (if no owner)
            if header.has_waiters() {
                wake_one_waiter(object, increment);
            }
        }
        _ => {
            // Default: wake all
            wake_all_waiters(object, increment);
        }
    }
}

/// Wake one waiting thread
unsafe fn wake_one_waiter(object: *mut DispatcherHeader, boost: i8) {
    let header = &*object;

    if !header.has_waiters() {
        return;
    }

    // Get first wait block
    let entry = header.wait_list().remove_head();
    let wait_block = containing_record!(entry, KWaitBlock, wait_list_entry);
    let thread = (*wait_block).thread;

    if thread.is_null() {
        return;
    }

    // Apply priority boost if specified
    if boost > 0 && !(*thread).is_realtime() {
        let new_priority = ((*thread).priority + boost).min(15); // Cap at max dynamic priority
        (*thread).priority = new_priority;
    }

    // Make thread ready
    (*thread).state = ThreadState::Ready;
    scheduler::ki_ready_thread(thread);
}

/// Wake all waiting threads
unsafe fn wake_all_waiters(object: *mut DispatcherHeader, boost: i8) {
    let header = &*object;

    while header.has_waiters() {
        wake_one_waiter(object, boost);
    }
}

/// Unwait a thread (cancel its wait and make it ready)
///
/// Used when a thread's wait needs to be cancelled (e.g., thread termination,
/// alert delivery).
///
/// # Safety
/// Thread must be in Waiting state
pub unsafe fn ki_unwait_thread(thread: *mut KThread, status: WaitStatus) {
    if thread.is_null() {
        return;
    }

    // Set the wait status that will be returned
    (*thread).wait_status = status;

    // Remove thread from all wait lists
    // (The wait blocks are on the thread's stack and contain list entries)
    let wait_count = (*thread).wait_count as usize;
    let wait_blocks = (*thread).wait_block_list;

    if !wait_blocks.is_null() && wait_count > 0 {
        for i in 0..wait_count {
            let block = wait_blocks.add(i);
            (*block).wait_list_entry.remove_entry();
        }
    }

    // Make thread ready
    (*thread).state = ThreadState::Ready;
    scheduler::ki_ready_thread(thread);
}

/// Check if a wait can be satisfied for WaitAll
///
/// Returns true if all objects in the wait are signaled
pub unsafe fn ki_check_wait_all(thread: *mut KThread) -> bool {
    if thread.is_null() {
        return false;
    }

    let wait_count = (*thread).wait_count as usize;
    let wait_blocks = (*thread).wait_block_list;

    if wait_blocks.is_null() || wait_count == 0 {
        return false;
    }

    for i in 0..wait_count {
        let block = &*wait_blocks.add(i);
        if !is_object_signaled(block.object) {
            return false;
        }
    }

    true
}
