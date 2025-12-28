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

// Deferred execution
pub mod dpc;
pub mod apc;

// Timer support
pub mod timer;

// Wait support
pub mod wait;

// Exception handling
pub mod exception;

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
    Context, ExceptionRecord, M128A, LegacyFloatingSaveArea,
    ke_raise_exception, ke_continue, ke_get_context, ke_set_context,
    ContextFlags, ExceptionCode, ExceptionFlags, EXCEPTION_MAXIMUM_PARAMETERS,
};
