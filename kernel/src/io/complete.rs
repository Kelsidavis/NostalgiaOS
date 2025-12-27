//! IRP Completion Implementation
//!
//! When a driver completes processing an IRP, it calls IoCompleteRequest.
//! This routine:
//! 1. Calls completion routines registered by higher-level drivers
//! 2. Signals any waiting events
//! 3. Returns the IRP to the pool
//!
//! # Completion Flow
//! IRPs are completed bottom-up through the device stack. Each driver
//! can register a completion routine when forwarding an IRP down the
//! stack. These routines are called in reverse order during completion.

use core::sync::atomic::Ordering;
use super::irp::{Irp, irp_flags, sl_control, io_free_irp};
use super::file::FileObject;

/// Priority boost values for IRP completion
pub mod priority_boost {
    /// No priority boost
    pub const IO_NO_INCREMENT: i8 = 0;
    /// CD-ROM priority boost
    pub const IO_CD_ROM_INCREMENT: i8 = 1;
    /// Disk priority boost
    pub const IO_DISK_INCREMENT: i8 = 1;
    /// Keyboard priority boost
    pub const IO_KEYBOARD_INCREMENT: i8 = 6;
    /// Mailslot priority boost
    pub const IO_MAILSLOT_INCREMENT: i8 = 2;
    /// Mouse priority boost
    pub const IO_MOUSE_INCREMENT: i8 = 6;
    /// Named pipe priority boost
    pub const IO_NAMED_PIPE_INCREMENT: i8 = 2;
    /// Network priority boost
    pub const IO_NETWORK_INCREMENT: i8 = 2;
    /// Parallel priority boost
    pub const IO_PARALLEL_INCREMENT: i8 = 1;
    /// Serial priority boost
    pub const IO_SERIAL_INCREMENT: i8 = 2;
    /// Sound priority boost
    pub const IO_SOUND_INCREMENT: i8 = 8;
    /// Video priority boost
    pub const IO_VIDEO_INCREMENT: i8 = 1;
}

/// Complete an I/O request
///
/// This is the main entry point for completing IRPs. It processes
/// completion routines and signals waiting threads.
///
/// # Arguments
/// * `irp` - Pointer to the IRP to complete
/// * `priority_boost` - Priority boost for waiting thread
///
/// # Safety
/// Caller must ensure IRP pointer is valid and the IRP has not
/// already been completed.
pub unsafe fn io_complete_request(irp: *mut Irp, priority_boost: i8) {
    if irp.is_null() {
        return;
    }

    let irp_ref = &mut *irp;

    // Check if already completed
    if irp_ref.has_flag(irp_flags::IRP_COMPLETED) {
        crate::serial_println!("[IO] WARNING: IRP already completed!");
        return;
    }

    // Mark as completed
    irp_ref.set_flag(irp_flags::IRP_COMPLETED);

    // Process completion routines from bottom to top of stack
    let mut stack_location = irp_ref.current_location as i8;

    while stack_location < irp_ref.stack_count as i8 {
        let stack_idx = stack_location as usize;

        if stack_idx < irp_ref.stack.len() {
            let stack = &mut irp_ref.stack[stack_idx];

            // Check if there's a completion routine
            if let Some(completion_routine) = stack.completion_routine {
                let context = stack.completion_context;
                let control = stack.control;

                // Determine if we should invoke based on status and control flags
                let status = irp_ref.io_status.status;
                let should_invoke = match status {
                    s if s >= 0 => (control & sl_control::SL_INVOKE_ON_SUCCESS) != 0,
                    s if s == -1073741790 => (control & sl_control::SL_INVOKE_ON_CANCEL) != 0, // STATUS_CANCELLED
                    _ => (control & sl_control::SL_INVOKE_ON_ERROR) != 0,
                };

                if should_invoke {
                    // Call the completion routine
                    let result = completion_routine(
                        stack.device_object,
                        irp,
                        context,
                    );

                    // If completion routine returns STATUS_MORE_PROCESSING_REQUIRED,
                    // stop completion and return
                    if result == -1073741802 { // STATUS_MORE_PROCESSING_REQUIRED
                        return;
                    }
                }
            }
        }

        stack_location += 1;
    }

    // If this IRP has an associated file object, signal its event
    if !irp_ref.tail.file_object.is_null() {
        let file = irp_ref.tail.file_object;

        // For synchronous I/O, signal the file event
        if (*file).is_synchronous() {
            (*file).event.set();
        }

        // Update file position if successful read/write
        if irp_ref.io_status.status >= 0 {
            let bytes = irp_ref.io_status.information as u64;
            if bytes > 0 {
                (*file).advance_position(bytes);
            }
        }
    }

    // If there's a user event, signal it
    if !irp_ref.user_event.is_null() {
        // In full implementation, would call KeSetEvent
        // For now, we'll handle this when we have proper event support
    }

    // If pending was returned, handle async completion
    if irp_ref.pending_returned {
        // Handle completion for async I/O
        // This would typically post to a completion port
        // or signal an APC for the requesting thread
        handle_async_completion(irp, priority_boost);
    }

    // Remove from any lists
    irp_ref.list_entry.remove_entry();

    // Free the IRP
    io_free_irp(irp);
}

/// Handle asynchronous I/O completion
///
/// Called when an IRP that was marked pending completes asynchronously.
unsafe fn handle_async_completion(_irp: *mut Irp, _priority_boost: i8) {
    // In a full implementation, this would:
    // 1. Queue an APC to the requesting thread
    // 2. Or post to an I/O completion port
    // 3. Apply the priority boost to the waiting thread

    // For now, this is a placeholder as we don't have full
    // async I/O infrastructure yet
}

/// Mark an IRP as pending
///
/// Called by a driver when it cannot complete the IRP synchronously.
/// The driver must later call IoCompleteRequest to complete the IRP.
pub unsafe fn io_mark_irp_pending(irp: *mut Irp) {
    if irp.is_null() {
        return;
    }

    let irp_ref = &mut *irp;
    irp_ref.pending_returned = true;

    // Set pending in current stack location
    if irp_ref.current_location > 0 {
        let stack_idx = (irp_ref.current_location - 1) as usize;
        if stack_idx < irp_ref.stack.len() {
            irp_ref.stack[stack_idx].control |= sl_control::SL_PENDING_RETURNED;
        }
    }
}

/// Set the completion routine for an IRP
///
/// Higher-level drivers use this to be notified when a lower-level
/// driver completes the IRP.
pub unsafe fn io_set_completion_routine(
    irp: *mut Irp,
    completion_routine: super::irp::IoCompletionRoutine,
    context: *mut u8,
    invoke_on_success: bool,
    invoke_on_error: bool,
    invoke_on_cancel: bool,
) {
    if irp.is_null() {
        return;
    }

    let irp_ref = &mut *irp;

    // Set in current stack location
    if irp_ref.current_location > 0 {
        let stack_idx = (irp_ref.current_location - 1) as usize;
        if stack_idx < irp_ref.stack.len() {
            let stack = &mut irp_ref.stack[stack_idx];
            stack.completion_routine = Some(completion_routine);
            stack.completion_context = context;

            // Set control flags
            stack.control = 0;
            if invoke_on_success {
                stack.control |= sl_control::SL_INVOKE_ON_SUCCESS;
            }
            if invoke_on_error {
                stack.control |= sl_control::SL_INVOKE_ON_ERROR;
            }
            if invoke_on_cancel {
                stack.control |= sl_control::SL_INVOKE_ON_CANCEL;
            }
        }
    }
}

/// Copy current IRP stack location to next
///
/// Used by filter drivers that want to pass the IRP down unchanged.
pub unsafe fn io_copy_current_irp_stack_location_to_next(irp: *mut Irp) {
    if irp.is_null() {
        return;
    }

    let irp_ref = &mut *irp;

    if irp_ref.current_location > 1 {
        let current_idx = (irp_ref.current_location - 1) as usize;
        let next_idx = (irp_ref.current_location - 2) as usize;

        if current_idx < irp_ref.stack.len() && next_idx < irp_ref.stack.len() {
            // Copy parameters (not completion routine)
            irp_ref.stack[next_idx].major_function = irp_ref.stack[current_idx].major_function;
            irp_ref.stack[next_idx].minor_function = irp_ref.stack[current_idx].minor_function;
            irp_ref.stack[next_idx].flags = irp_ref.stack[current_idx].flags;
            irp_ref.stack[next_idx].parameters = irp_ref.stack[current_idx].parameters;
            irp_ref.stack[next_idx].file_object = irp_ref.stack[current_idx].file_object;
        }
    }
}

/// Skip current IRP stack location
///
/// Used when a driver doesn't need a completion routine and wants
/// to pass the IRP down without copying parameters.
pub unsafe fn io_skip_current_irp_stack_location(irp: *mut Irp) {
    if irp.is_null() {
        return;
    }

    let irp_ref = &mut *irp;

    // Increment current location to skip this driver's stack entry
    irp_ref.current_location += 1;
}

/// Get current IRP stack location
pub unsafe fn io_get_current_irp_stack_location(irp: *mut Irp) -> Option<&'static mut super::irp::IoStackLocation> {
    if irp.is_null() {
        return None;
    }

    let irp_ref = &mut *irp;

    if irp_ref.current_location > 0 {
        let stack_idx = (irp_ref.current_location - 1) as usize;
        if stack_idx < irp_ref.stack.len() {
            // Safety: We return a reference to a valid stack location
            // The lifetime is tied to the IRP which remains valid
            return Some(&mut *(&mut irp_ref.stack[stack_idx] as *mut _));
        }
    }

    None
}

/// Get next IRP stack location
pub unsafe fn io_get_next_irp_stack_location(irp: *mut Irp) -> Option<&'static mut super::irp::IoStackLocation> {
    if irp.is_null() {
        return None;
    }

    let irp_ref = &mut *irp;

    if irp_ref.current_location > 1 {
        let stack_idx = (irp_ref.current_location - 2) as usize;
        if stack_idx < irp_ref.stack.len() {
            return Some(&mut *(&mut irp_ref.stack[stack_idx] as *mut _));
        }
    }

    None
}

/// Cancel an IRP
///
/// Attempts to cancel an IRP. The cancel routine (if any) will be called.
pub unsafe fn io_cancel_irp(irp: *mut Irp) -> bool {
    if irp.is_null() {
        return false;
    }

    let irp_ref = &mut *irp;

    // Check if already cancelled or completed
    if irp_ref.cancel {
        return false;
    }

    // Set cancel flag
    irp_ref.cancel = true;

    // If there's a cancel routine, call it
    if let Some(cancel_routine) = irp_ref.cancel_routine.take() {
        // Get the device object from current stack location
        let device = if irp_ref.current_location > 0 {
            let stack_idx = (irp_ref.current_location - 1) as usize;
            if stack_idx < irp_ref.stack.len() {
                irp_ref.stack[stack_idx].device_object
            } else {
                core::ptr::null_mut()
            }
        } else {
            core::ptr::null_mut()
        };

        cancel_routine(device, irp);
        return true;
    }

    false
}

/// Start next packet from device queue
///
/// Called by drivers using StartIo to begin processing the next IRP.
pub unsafe fn io_start_next_packet(
    device: *mut super::device::DeviceObject,
    _cancelable: bool,
) {
    if device.is_null() {
        return;
    }

    let device_ref = &mut *device;

    // Dequeue next IRP from device queue
    if let Some(irp) = device_ref.device_queue.dequeue() {
        // Get the driver's StartIo routine
        if !device_ref.driver_object.is_null() {
            let driver = &*device_ref.driver_object;
            if let Some(start_io) = driver.driver_start_io {
                start_io(device, irp);
            }
        }
    }
}

/// Start a packet on a device
///
/// Called to queue or immediately start an IRP on a device.
pub unsafe fn io_start_packet(
    device: *mut super::device::DeviceObject,
    irp: *mut Irp,
    _key: *const u32,
    _cancel_function: Option<super::irp::IoCancel>,
) {
    if device.is_null() || irp.is_null() {
        return;
    }

    let device_ref = &mut *device;

    // Try to start immediately if device is idle
    if !device_ref.device_queue.is_busy() {
        // Mark device as busy
        device_ref.device_queue.set_busy(true);

        // Call driver's StartIo routine
        if !device_ref.driver_object.is_null() {
            let driver = &*device_ref.driver_object;
            if let Some(start_io) = driver.driver_start_io {
                start_io(device, irp);
                return;
            }
        }
    }

    // Otherwise queue the IRP
    device_ref.device_queue.enqueue(irp);
}
