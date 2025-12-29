//! Inter-Processor Interrupt (IPI) System
//!
//! This module implements NT-compatible IPI mechanisms for multi-processor
//! communication and synchronization:
//!
//! - **Simple IPIs**: Request APC, DPC, or freeze on target processors
//! - **Packet IPIs**: Send worker function with parameters to target processors
//! - **Generic Call**: Synchronously execute function on all processors
//! - **Freeze Protocol**: Halt processors for debugging
//!
//! This implementation is NT 5.2 (Windows Server 2003) compatible.

use core::sync::atomic::{AtomicUsize, Ordering, fence};
use super::prcb::{
    KPrcb, KAffinity, KipiWorker, KipiBroadcastWorker,
    ipi_request, IPI_PACKET_SHIFT, IPI_REQUEST_MASK,
    get_current_prcb, get_current_prcb_mut, get_prcb, get_prcb_mut,
    ki_get_processor_block, get_active_cpu_count, ke_get_active_processors,
    MAX_CPUS,
};
use super::kpcr::{Kirql, irql, ke_raise_irql, ke_lower_irql};
use super::queued_spinlock::KSpinLock;

// ============================================================================
// IPI Vector Numbers
// ============================================================================

/// IPI vector for generic IPI delivery
pub const IPI_VECTOR: u8 = 0xE1;

/// IPI vector for reschedule requests
pub const IPI_VECTOR_RESCHEDULE: u8 = 0xFD;

/// IPI vector for TLB shootdown
pub const IPI_VECTOR_TLB_SHOOTDOWN: u8 = 0xFE;

/// IPI vector for processor stop (debug/crash)
pub const IPI_VECTOR_STOP: u8 = 0xFF;

// ============================================================================
// Global Synchronization
// ============================================================================

/// Reverse stall IPI lock (protects generic broadcast operations)
static KI_REVERSE_STALL_IPI_LOCK: KSpinLock = KSpinLock::new();

// ============================================================================
// KiIpiSend - Simple IPI Requests
// ============================================================================

/// Send a simple IPI request to target processors
///
/// This function sends simple requests (APC, DPC, FREEZE) to target processors.
/// The requests are merged atomically into each target's RequestSummary field.
///
/// # Arguments
/// * `target_set` - Bitmask of target processors
/// * `request` - IPI request type (IPI_APC, IPI_DPC, IPI_FREEZE)
///
/// # Safety
/// - Must be at IRQL >= DISPATCH_LEVEL
/// - target_set must only include active processors
pub unsafe fn ki_ipi_send(target_set: KAffinity, request: u64) {
    if target_set == 0 {
        return;
    }

    let mut remaining = target_set;

    // Process each target processor
    while remaining != 0 {
        // Find next set bit (target processor)
        let cpu_id = remaining.trailing_zeros() as usize;
        remaining &= remaining - 1; // Clear lowest set bit

        if cpu_id >= MAX_CPUS {
            continue;
        }

        // Get target PRCB
        let target_prcb = ki_get_processor_block(cpu_id);
        if target_prcb.is_null() {
            continue;
        }

        // Atomically OR the request into the target's RequestSummary
        (*target_prcb).request_summary.fetch_or(request, Ordering::Release);
    }

    // Memory barrier before sending hardware IPI
    fence(Ordering::SeqCst);

    // Send hardware IPI to all targets
    hal_request_ipi(target_set);
}

/// Request APC delivery on target processors
#[inline]
pub unsafe fn ki_ipi_send_apc(target_set: KAffinity) {
    ki_ipi_send(target_set, ipi_request::IPI_APC);
}

/// Request DPC delivery on target processors
#[inline]
pub unsafe fn ki_ipi_send_dpc(target_set: KAffinity) {
    ki_ipi_send(target_set, ipi_request::IPI_DPC);
}

/// Request freeze on target processors (for debugger)
#[inline]
pub unsafe fn ki_ipi_send_freeze(target_set: KAffinity) {
    ki_ipi_send(target_set, ipi_request::IPI_FREEZE);
}

// ============================================================================
// KiIpiSendPacket - Worker Function IPI
// ============================================================================

/// Send a worker function packet to target processors
///
/// This function sends a worker routine with parameters to be executed on
/// target processors. The sender waits for all targets to complete.
///
/// # Arguments
/// * `target_set` - Bitmask of target processors
/// * `worker_routine` - Function to execute on targets
/// * `param1`, `param2`, `param3` - Parameters passed to worker
///
/// # Safety
/// - Must be at IRQL >= DISPATCH_LEVEL (usually IPI_LEVEL)
/// - Caller must hold appropriate locks if worker accesses shared data
pub unsafe fn ki_ipi_send_packet(
    target_set: KAffinity,
    worker_routine: KipiWorker,
    param1: *mut core::ffi::c_void,
    param2: *mut core::ffi::c_void,
    param3: *mut core::ffi::c_void,
) {
    if target_set == 0 {
        return;
    }

    let prcb = get_current_prcb_mut();
    let num_targets = target_set.count_ones();

    // Set up the packet in our PRCB
    prcb.current_packet[0].store(param1 as usize, Ordering::Relaxed);
    prcb.current_packet[1].store(param2 as usize, Ordering::Relaxed);
    prcb.current_packet[2].store(param3 as usize, Ordering::Relaxed);
    prcb.worker_routine.store(worker_routine as usize, Ordering::Relaxed);

    // Set up synchronization based on number of targets
    if num_targets == 1 {
        // Single target: use TargetSet for completion signaling
        prcb.target_set.store(target_set, Ordering::Release);
        prcb.packet_barrier.store(0, Ordering::Relaxed);
    } else {
        // Multiple targets: use PacketBarrier for completion signaling
        prcb.packet_barrier.store(target_set, Ordering::Release);
        prcb.target_set.store(0, Ordering::Relaxed);
    }

    // Memory barrier before setting up target PRCBs
    fence(Ordering::SeqCst);

    // Encode our PRCB pointer in the upper bits, packet_ready in lower bits
    let sender_prcb_encoded = ((prcb as *const KPrcb as u64) << IPI_PACKET_SHIFT)
        | ipi_request::IPI_PACKET_READY;

    // Set up each target's RequestSummary
    let mut remaining = target_set;
    while remaining != 0 {
        let cpu_id = remaining.trailing_zeros() as usize;
        remaining &= remaining - 1;

        if cpu_id >= MAX_CPUS {
            continue;
        }

        let target_prcb = ki_get_processor_block(cpu_id);
        if target_prcb.is_null() {
            continue;
        }

        // Atomically set the packet request (may merge with other requests)
        (*target_prcb).request_summary.fetch_or(sender_prcb_encoded, Ordering::Release);
    }

    // Send hardware IPI
    fence(Ordering::SeqCst);
    hal_request_ipi(target_set);

    // Wait for all targets to complete
    if num_targets == 1 {
        // Wait for target to clear TargetSet
        while prcb.target_set.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
    } else {
        // Wait for all targets to clear their bits in PacketBarrier
        while prcb.packet_barrier.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Signal completion of IPI packet on current processor
///
/// Called by target processor after executing the worker routine.
///
/// # Safety
/// - Must be called after executing worker routine
/// - sender_prcb must be the PRCB of the packet sender
unsafe fn ki_ipi_signal_packet_done(sender_prcb: *mut KPrcb) {
    let prcb = get_current_prcb();

    // Check if single-target or multi-target operation
    let target_set = (*sender_prcb).target_set.load(Ordering::Acquire);

    if target_set != 0 {
        // Single target: clear TargetSet
        (*sender_prcb).target_set.store(0, Ordering::Release);
    } else {
        // Multi-target: clear our bit in PacketBarrier
        (*sender_prcb).packet_barrier.fetch_and(!prcb.set_member, Ordering::Release);
    }
}

// ============================================================================
// KiIpiProcessRequests - IPI Handler
// ============================================================================

/// Process pending IPI requests on the current processor
///
/// This is called from the IPI interrupt handler to process all pending
/// requests merged into RequestSummary.
///
/// # Safety
/// - Must be called from IPI interrupt handler at IPI_LEVEL
pub unsafe fn ki_ipi_process_requests() {
    let prcb = get_current_prcb_mut();

    // Atomically extract and clear RequestSummary
    let requests = prcb.request_summary.swap(0, Ordering::AcqRel);

    if requests == 0 {
        return;
    }

    // Extract request type flags (lower bits)
    let request_flags = requests & IPI_REQUEST_MASK;

    // Extract packet sender PRCB pointer (upper bits)
    let sender_prcb_ptr = (requests >> IPI_PACKET_SHIFT) as *mut KPrcb;

    // Process packet if present
    if !sender_prcb_ptr.is_null() && (request_flags & ipi_request::IPI_PACKET_READY) != 0 {
        // Get worker routine and parameters from sender's PRCB
        let worker = (*sender_prcb_ptr).worker_routine.load(Ordering::Acquire);
        let param1 = (*sender_prcb_ptr).current_packet[0].load(Ordering::Acquire);
        let param2 = (*sender_prcb_ptr).current_packet[1].load(Ordering::Acquire);
        let param3 = (*sender_prcb_ptr).current_packet[2].load(Ordering::Acquire);

        if worker != 0 {
            // Execute the worker routine
            let worker_fn: KipiWorker = core::mem::transmute(worker);
            worker_fn(
                sender_prcb_ptr as *mut core::ffi::c_void,
                param1 as *mut core::ffi::c_void,
                param2 as *mut core::ffi::c_void,
                param3 as *mut core::ffi::c_void,
            );
        }

        // Signal completion
        ki_ipi_signal_packet_done(sender_prcb_ptr);
    }

    // Process APC request
    if (request_flags & ipi_request::IPI_APC) != 0 {
        // Request software interrupt for APC delivery
        // This would typically request APC_LEVEL software interrupt
        ki_request_software_interrupt(irql::APC_LEVEL);
    }

    // Process DPC request
    if (request_flags & ipi_request::IPI_DPC) != 0 {
        // Request software interrupt for DPC delivery
        prcb.dpc_interrupt_requested = true;
        ki_request_software_interrupt(irql::DISPATCH_LEVEL);
    }

    // Process FREEZE request
    if (request_flags & ipi_request::IPI_FREEZE) != 0 {
        // Enter frozen state (for debugger)
        ki_freeze_processor();
    }

    // Process SYNCH request (reverse stall)
    if (request_flags & ipi_request::IPI_SYNCH_REQUEST) != 0 {
        // This is handled by KeIpiGenericCall synchronization
    }
}

// ============================================================================
// KeIpiGenericCall - Synchronized Broadcast
// ============================================================================

/// Broadcast context for generic call synchronization
#[repr(C)]
struct GenericCallContext {
    /// Function to execute
    broadcast_function: KipiBroadcastWorker,
    /// Argument to pass
    argument: usize,
    /// Down-counter for synchronization
    count: AtomicUsize,
    /// Result accumulator
    result: AtomicUsize,
}

/// Execute a function synchronously on all processors
///
/// This function broadcasts a worker to all processors and waits for
/// completion. All processors execute at IPI_LEVEL during the call.
///
/// # Arguments
/// * `broadcast_function` - Function to execute on each processor
/// * `context` - Argument passed to the function
///
/// # Returns
/// The return value from the current processor's execution of the function
///
/// # Safety
/// - Must be at IRQL <= IPI_LEVEL
/// - Function must be safe to execute at IPI_LEVEL
pub unsafe fn ke_ipi_generic_call(
    broadcast_function: KipiBroadcastWorker,
    context: usize,
) -> usize {
    let active_cpus = get_active_cpu_count();

    // If single processor, just call directly
    if active_cpus == 1 {
        return broadcast_function(context);
    }

    // Raise to IPI level and acquire reverse stall lock
    let old_irql = ke_raise_irql(irql::IPI_LEVEL);

    // Acquire the reverse stall lock (protects broadcast operations)
    while KI_REVERSE_STALL_IPI_LOCK.is_locked() {
        core::hint::spin_loop();
    }
    // Simple acquisition for now
    super::queued_spinlock::ke_acquire_spin_lock_at_dpc_level(&KI_REVERSE_STALL_IPI_LOCK);

    // Set up broadcast context
    let mut call_context = GenericCallContext {
        broadcast_function,
        argument: context,
        count: AtomicUsize::new(active_cpus),
        result: AtomicUsize::new(0),
    };

    // Get all other active processors
    let current_cpu = get_current_prcb().number as usize;
    let target_set = ke_get_active_processors() & !(1u64 << current_cpu);

    if target_set != 0 {
        // Send packet to all other processors
        ki_ipi_send_packet(
            target_set,
            generic_call_worker,
            &mut call_context as *mut GenericCallContext as *mut core::ffi::c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
    }

    // Execute on current processor
    let result = broadcast_function(context);

    // Decrement counter and wait for others
    call_context.count.fetch_sub(1, Ordering::AcqRel);

    // Wait for all processors to complete
    while call_context.count.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }

    // Release lock and lower IRQL
    super::queued_spinlock::ke_release_spin_lock_from_dpc_level(&KI_REVERSE_STALL_IPI_LOCK);
    ke_lower_irql(old_irql);

    result
}

/// Worker routine for generic call IPI
unsafe fn generic_call_worker(
    _packet_context: *mut core::ffi::c_void,
    param1: *mut core::ffi::c_void,
    _param2: *mut core::ffi::c_void,
    _param3: *mut core::ffi::c_void,
) {
    let context = param1 as *mut GenericCallContext;
    if context.is_null() {
        return;
    }

    // Execute the broadcast function
    let function = (*context).broadcast_function;
    let argument = (*context).argument;
    let _result = function(argument);

    // Signal completion
    (*context).count.fetch_sub(1, Ordering::AcqRel);
}

// ============================================================================
// Freeze Protocol (Debugger Support)
// ============================================================================

/// Freeze the current processor
///
/// Called when IPI_FREEZE request is received. The processor enters
/// a frozen state until resumed by the debugger.
///
/// # Safety
/// - Must be called at IPI_LEVEL
unsafe fn ki_freeze_processor() {
    let prcb = get_current_prcb_mut();

    // Mark as frozen
    prcb.frozen = true;
    prcb.freeze_requested = false;

    crate::serial_println!("[FREEZE] CPU {} entering frozen state", prcb.number);

    // Spin until unfrozen (debugger would clear this)
    while prcb.frozen {
        // Allow interrupts briefly to handle debugger communication
        core::hint::spin_loop();
    }

    crate::serial_println!("[FREEZE] CPU {} resumed", prcb.number);
}

/// Freeze all processors except current
///
/// Used by debugger to halt all CPUs for breakpoint handling.
///
/// # Safety
/// - Must be at DISPATCH_LEVEL or higher
pub unsafe fn ki_freeze_all_processors() {
    let current_cpu = get_current_prcb().number as usize;
    let target_set = ke_get_active_processors() & !(1u64 << current_cpu);

    if target_set != 0 {
        // Mark targets as freeze requested
        let mut remaining = target_set;
        while remaining != 0 {
            let cpu_id = remaining.trailing_zeros() as usize;
            remaining &= remaining - 1;

            if let Some(target_prcb) = get_prcb_mut(cpu_id) {
                target_prcb.freeze_requested = true;
            }
        }

        // Send freeze IPI
        ki_ipi_send_freeze(target_set);

        // Wait for all targets to enter frozen state
        let mut remaining = target_set;
        while remaining != 0 {
            let cpu_id = remaining.trailing_zeros() as usize;

            if let Some(target_prcb) = get_prcb(cpu_id) {
                if target_prcb.frozen {
                    remaining &= !(1u64 << cpu_id);
                }
            } else {
                remaining &= !(1u64 << cpu_id);
            }

            core::hint::spin_loop();
        }
    }
}

/// Thaw (resume) all frozen processors
///
/// # Safety
/// - Must be called after ki_freeze_all_processors
pub unsafe fn ki_thaw_all_processors() {
    let current_cpu = get_current_prcb().number as usize;
    let target_set = ke_get_active_processors() & !(1u64 << current_cpu);

    let mut remaining = target_set;
    while remaining != 0 {
        let cpu_id = remaining.trailing_zeros() as usize;
        remaining &= remaining - 1;

        if let Some(target_prcb) = get_prcb_mut(cpu_id) {
            target_prcb.frozen = false;
        }
    }
}

// ============================================================================
// TLB Shootdown Support
// ============================================================================

/// TLB shootdown context
#[repr(C)]
pub struct TlbShootdownContext {
    /// Virtual address to invalidate (0 for full flush)
    pub address: u64,
    /// Process context (address space) - 0 for all
    pub process_id: u64,
    /// Number of pages to invalidate (0 for single/full)
    pub page_count: usize,
}

/// Invalidate TLB on all processors for a virtual address
///
/// # Safety
/// - Must be at DISPATCH_LEVEL or higher
/// - Address must be valid or 0 for full flush
pub unsafe fn ki_flush_single_tb(address: u64) {
    let current_cpu = get_current_prcb().number as usize;
    let target_set = ke_get_active_processors() & !(1u64 << current_cpu);

    // Invalidate locally first
    invalidate_page(address);

    // Send to other processors
    if target_set != 0 {
        let context = TlbShootdownContext {
            address,
            process_id: 0,
            page_count: 1,
        };

        ki_ipi_send_packet(
            target_set,
            tlb_shootdown_worker,
            &context as *const TlbShootdownContext as *mut core::ffi::c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
    }
}

/// Flush entire TLB on all processors
///
/// # Safety
/// - Must be at DISPATCH_LEVEL or higher
pub unsafe fn ki_flush_entire_tb() {
    let current_cpu = get_current_prcb().number as usize;
    let target_set = ke_get_active_processors() & !(1u64 << current_cpu);

    // Flush locally first
    flush_tlb();

    // Send to other processors
    if target_set != 0 {
        let context = TlbShootdownContext {
            address: 0,
            process_id: 0,
            page_count: 0,
        };

        ki_ipi_send_packet(
            target_set,
            tlb_shootdown_worker,
            &context as *const TlbShootdownContext as *mut core::ffi::c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
    }
}

/// Worker routine for TLB shootdown
unsafe fn tlb_shootdown_worker(
    _packet_context: *mut core::ffi::c_void,
    param1: *mut core::ffi::c_void,
    _param2: *mut core::ffi::c_void,
    _param3: *mut core::ffi::c_void,
) {
    let context = param1 as *const TlbShootdownContext;
    if context.is_null() {
        flush_tlb();
        return;
    }

    let addr = (*context).address;
    let count = (*context).page_count;

    if addr == 0 || count == 0 {
        // Full flush
        flush_tlb();
    } else if count == 1 {
        // Single page
        invalidate_page(addr);
    } else {
        // Multiple pages
        for i in 0..count {
            invalidate_page(addr + (i as u64 * 4096));
        }
    }
}

// ============================================================================
// Hardware Interface
// ============================================================================

/// Request hardware IPI to target processors
///
/// This calls into the HAL to send the actual IPI.
#[inline]
unsafe fn hal_request_ipi(target_set: KAffinity) {
    // Convert affinity to individual APIC IDs and send IPIs
    let mut remaining = target_set;

    while remaining != 0 {
        let cpu_id = remaining.trailing_zeros() as usize;
        remaining &= remaining - 1;

        // Get APIC ID for this CPU
        if let Some(proc_info) = crate::hal::acpi::get_processor(cpu_id) {
            crate::hal::apic::send_ipi(proc_info.apic_id, IPI_VECTOR);
        }
    }
}

/// Request a software interrupt at the specified IRQL
#[inline]
unsafe fn ki_request_software_interrupt(_irql: Kirql) {
    // On x86-64, software interrupts are typically handled by
    // checking flags when lowering IRQL rather than actual interrupts.
    // This is a placeholder for that mechanism.
}

/// Invalidate a single TLB entry
#[inline]
unsafe fn invalidate_page(address: u64) {
    core::arch::asm!(
        "invlpg [{}]",
        in(reg) address,
        options(nostack, preserves_flags)
    );
}

/// Flush the entire TLB
#[inline]
unsafe fn flush_tlb() {
    // Reload CR3 to flush TLB
    let _cr3: u64;
    core::arch::asm!(
        "mov {0}, cr3",
        "mov cr3, {0}",
        out(reg) _cr3,
        options(nostack, preserves_flags)
    );
}

// ============================================================================
// IPI Interrupt Handler Entry Point
// ============================================================================

/// IPI interrupt handler
///
/// This should be called from the IDT entry for the IPI vector.
///
/// # Safety
/// - Must be called from interrupt context at IPI_LEVEL
#[no_mangle]
pub unsafe extern "C" fn ki_ipi_interrupt_handler() {
    // Process all pending requests
    ki_ipi_process_requests();

    // Send EOI
    crate::hal::apic::eoi();
}
