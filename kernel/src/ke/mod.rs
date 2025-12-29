//! Kernel Executive (ke)
//!
//! The kernel executive is the heart of the NT kernel, providing:
//!
//! - **Scheduler**: 32 priority levels, per-processor ready queues
//! - **Dispatcher Objects**: KEVENT, KSEMAPHORE, KMUTANT, KTIMER
//! - **DPC**: Deferred Procedure Calls for interrupt deferral
//! - **APC**: Asynchronous Procedure Calls for thread-specific callbacks
//! - **Spinlocks**: Low-level synchronization primitives
//! - **Wait/Unwait**: Multi-object wait support
//!
//! # IRQL (Interrupt Request Level)
//!
//! The kernel uses IRQL to manage interrupt priority:
//! - PASSIVE_LEVEL (0): Normal thread execution
//! - APC_LEVEL (1): APC delivery enabled
//! - DISPATCH_LEVEL (2): DPC execution, scheduler runs
//! - Device IRQLs (3-26): Hardware interrupts
//! - HIGH_LEVEL (31): Clock, IPI, power fail
//!
//! # Key Structures
//!
//! - `KPRCB`: Per-processor control block
//! - `KTHREAD`: Kernel thread object
//! - `KPROCESS`: Kernel process object
//! - `DISPATCHER_HEADER`: Common header for waitable objects

// Core modules
pub mod list;
pub mod thread;
pub mod process;
pub mod prcb;
pub mod scheduler;
pub mod idle;
pub mod init;

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

// Re-export key types
pub use list::ListEntry;
pub use thread::{KThread, ThreadState};
pub use process::{KProcess, ProcessState};
pub use prcb::KPrcb;

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

// Re-export profile types
pub use profile::{
    KProfile, ProfileSource, PROFILE_OBJECT,
    ke_initialize_profile, ke_start_profile, ke_stop_profile,
    ke_query_interval_profile, ke_set_interval_profile,
    DEFAULT_PROFILE_INTERVAL, MINIMUM_PROFILE_INTERVAL,
};
