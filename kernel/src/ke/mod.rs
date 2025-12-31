//! Kernel Executive (ke)
//!
//! The kernel executive is the heart of the NT kernel, providing:
//!
//! - **Scheduler**: 32 priority levels, per-processor ready queues
//! - **Dispatcher Objects**: KEVENT, KSEMAPHORE, KMUTANT, KTIMER
//! - **DPC**: Deferred Procedure Calls for interrupt deferral
//! - **APC**: Asynchronous Procedure Calls for thread-specific callbacks
//! - **Spinlocks**: Low-level synchronization primitives (including queued spinlocks)
//! - **Wait/Unwait**: Multi-object wait support
//! - **IPI**: Inter-processor interrupt for SMP communication
//!
//! # IRQL (Interrupt Request Level)
//!
//! The kernel uses IRQL to manage interrupt priority:
//! - PASSIVE_LEVEL (0): Normal thread execution
//! - APC_LEVEL (1): APC delivery enabled
//! - DISPATCH_LEVEL (2): DPC execution, scheduler runs
//! - Device IRQLs (3-26): Hardware interrupts
//! - IPI_LEVEL (29): Inter-processor interrupts
//! - HIGH_LEVEL (31): Clock, power fail
//!
//! # Key Structures
//!
//! - `KPCR`: Per-processor control region (IRQL, IDT, GDT)
//! - `KPRCB`: Per-processor control block (scheduling, IPI, queued locks)
//! - `KTHREAD`: Kernel thread object
//! - `KPROCESS`: Kernel process object
//! - `DISPATCHER_HEADER`: Common header for waitable objects

// Core modules
pub mod list;
pub mod thread;
pub mod process;
pub mod prcb;
pub mod kpcr;
pub mod scheduler;
pub mod idle;
pub mod init;

// SMP support
pub mod queued_spinlock;
pub mod ipi;

// Synchronization primitives
pub mod dispatcher;
pub mod spinlock;
pub mod mutex;
pub mod event;
pub mod semaphore;
pub mod queue;

// Deferred execution
pub mod dpc;
pub mod apc;

// Timer support
pub mod timer;

// Wait support
pub mod wait;

// Exception handling
pub mod exception;

// Debug object support
pub mod debug;

// Bug check (BSOD)
pub mod bugcheck;

// Device queue
pub mod device_queue;

// Profile object
pub mod profile;

// Balance set manager
pub mod balance;

// Re-export key types
pub use list::ListEntry;
pub use thread::{KThread, ThreadState};
pub use process::{KProcess, ProcessState};
pub use prcb::{
    KPrcb, KAffinity, KSpinLockQueue, LockQueueNumber, KipiWorker, KipiBroadcastWorker,
    ipi_request, IPI_PACKET_SHIFT, IPI_REQUEST_MASK, LOCK_QUEUE_MAXIMUM, MAX_CPUS,
    get_current_prcb, get_current_prcb_mut, get_prcb, get_prcb_mut,
    ki_get_processor_block, get_active_cpu_count, ke_get_active_processors,
    ki_get_idle_summary, ki_set_processor_idle, ki_clear_processor_idle,
    ke_get_current_processor_number, ke_get_current_processor_set_member,
    ke_get_current_thread_id, ke_get_current_process_id,
};

// Re-export KPCR types
pub use kpcr::{
    KPcr, Kirql, irql, get_current_kpcr, get_current_kpcr_mut, get_kpcr,
    ke_get_current_irql, ke_raise_irql, ke_lower_irql,
    ke_raise_irql_to_dpc_level, ke_raise_irql_to_synch_level,
    ki_enter_interrupt, ki_exit_interrupt,
    ke_is_executing_interrupt, ke_is_dpc_active,
};

// Re-export queued spinlock types
pub use queued_spinlock::{
    KQueuedSpinLock, KLockQueueHandle, KSpinLock as NtSpinLock,
    ke_acquire_queued_spinlock, ke_release_queued_spinlock,
    ke_acquire_queued_spinlock_at_dpc_level, ke_release_queued_spinlock_from_dpc_level,
    ke_try_to_acquire_queued_spinlock,
    ke_acquire_in_stack_queued_spinlock, ke_release_in_stack_queued_spinlock,
    ke_acquire_spin_lock, ke_release_spin_lock,
    ke_acquire_spin_lock_at_dpc_level, ke_release_spin_lock_from_dpc_level,
};

// Re-export IPI types
pub use ipi::{
    IPI_VECTOR, IPI_VECTOR_RESCHEDULE, IPI_VECTOR_TLB_SHOOTDOWN, IPI_VECTOR_STOP,
    ki_ipi_send, ki_ipi_send_apc, ki_ipi_send_dpc, ki_ipi_send_freeze,
    ki_ipi_send_packet, ki_ipi_process_requests, ke_ipi_generic_call,
    ki_freeze_all_processors, ki_thaw_all_processors,
    ki_flush_single_tb, ki_flush_entire_tb, TlbShootdownContext,
    ki_ipi_interrupt_handler,
};

// Re-export synchronization types
pub use dispatcher::{DispatcherHeader, DispatcherType, KWaitBlock, WaitType, WaitStatus};
pub use spinlock::{SpinLock, SpinLockGuard, RawSpinLock};
pub use mutex::{KMutex, MutexGuard};
pub use event::{KEvent, EventType};
pub use semaphore::KSemaphore;
pub use queue::{
    KQueue, WaitMode as QueueWaitMode, QueueWaitReason,
    ke_initialize_queue, ke_read_state_queue,
    ke_insert_queue, ke_insert_head_queue,
    ke_remove_queue, ke_rundown_queue,
};

// Re-export DPC types
pub use dpc::{KDpc, DpcRoutine, DpcImportance};

// Re-export APC types
pub use apc::{KApc, KApcState, ApcMode, ApcEnvironment, KernelRoutine, NormalRoutine, RundownRoutine};

// Re-export timer types
pub use timer::{KTimer, TimerType};

// Re-export wait types
pub use wait::{
    ke_wait_for_single_object, ke_wait_for_multiple_objects,
    ki_signal_object, ki_unwait_thread, ki_check_wait_all,
    WaitReason, WaitMode, TIMEOUT_INFINITE,
};

// Re-export exception types
pub use exception::{
    Context, ExceptionRecord, ExceptionPointers, M128A, LegacyFloatingSaveArea,
    ke_raise_exception, ke_continue, ke_get_context, ke_set_context,
    ContextFlags, ExceptionCode, ExceptionFlags, ExceptionDisposition,
    EXCEPTION_MAXIMUM_PARAMETERS, MAX_VEH_HANDLERS, MAX_SEH_FRAMES,
    // VEH functions
    VectoredExceptionHandler,
    rtl_add_vectored_exception_handler,
    rtl_remove_vectored_exception_handler,
    rtl_call_vectored_exception_handlers,
    rtl_get_vectored_handler_count,
    // SEH functions
    SehExceptionHandler, DispatcherContext, ExceptionRegistrationRecord,
    EXCEPTION_CHAIN_END,
    rtl_push_exception_handler, rtl_pop_exception_handler,
    rtl_get_exception_list, rtl_set_exception_list,
    rtl_dispatch_exception_seh, rtl_get_seh_frame_count,
    // Unhandled exception filter
    UnhandledExceptionFilter,
    rtl_set_unhandled_exception_filter, rtl_call_unhandled_exception_filter,
};

// Re-export debug types
pub use debug::{
    DebugObject, DebugEvent, DebugEventType, DebugEventInfo,
    ExceptionDebugInfo, CreateProcessDebugInfo, CreateThreadDebugInfo,
    ExitProcessDebugInfo, ExitThreadDebugInfo, LoadDllDebugInfo,
    UnloadDllDebugInfo, OutputDebugStringInfo, debug_flags,
    dbgk_create_debug_object, dbgk_get_debug_object, dbgk_close_debug_object,
    dbgk_attach_process, dbgk_detach_process, dbgk_queue_debug_event,
    dbgk_wait_for_debug_event, dbgk_continue_debug_event,
    dbgk_generate_initial_events,
    // Individual event posting functions
    dbgk_post_create_thread_event, dbgk_post_load_dll_event,
    dbgk_post_exit_thread_event, dbgk_post_exit_process_event,
    dbgk_post_exception_event, dbgk_post_output_debug_string_event,
    dbgk_post_unload_dll_event,
    MAX_DEBUG_OBJECTS, MAX_DEBUG_EVENTS,
};

// Re-export bugcheck types
pub use bugcheck::{
    ke_bugcheck, ke_bugcheck_ex,
    is_bugcheck_active, get_bugcheck_data,
    BugCheckData, codes as bugcheck_codes,
};

// Re-export device queue types
pub use device_queue::{
    KDeviceQueue, KDeviceQueueEntry, DEVICE_QUEUE_OBJECT,
    ke_initialize_device_queue, ke_insert_device_queue,
    ke_insert_by_key_device_queue, ke_remove_device_queue,
    ke_remove_by_key_device_queue, ke_remove_entry_device_queue,
};

// Re-export balance set manager types
pub use balance::{
    BalanceObject, BalanceSetStats, SwapEntry,
    ke_balance_init, ke_balance_set_manager,
    ke_signal_working_set_manager, ke_set_memory_pressure,
    ke_request_stack_outswap, ke_boost_thread_priority,
    ke_get_balance_stats, ke_is_balance_manager_running,
    ke_get_memory_pressure, ke_get_stack_protect_time,
    ke_set_stack_protect_time, ke_swap_in_process,
    ke_swap_out_process, ke_inswap_kernel_stack,
    MAXIMUM_THREAD_STACKS, PERIODIC_INTERVAL,
    READY_WITHOUT_RUNNING, STACK_SCAN_PERIOD,
};

// Re-export profile types
pub use profile::{
    KProfile, ProfileSource, PROFILE_OBJECT,
    ke_initialize_profile, ke_start_profile, ke_stop_profile,
    ke_query_interval_profile, ke_set_interval_profile,
    DEFAULT_PROFILE_INTERVAL, MINIMUM_PROFILE_INTERVAL,
};
