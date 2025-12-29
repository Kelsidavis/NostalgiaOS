//! Process Manager (ps)
//!
//! The process manager handles process and thread lifecycle:
//!
//! - **EPROCESS**: Executive process structure
//! - **ETHREAD**: Executive thread structure
//! - **Process Creation**: Fork-like creation with address space cloning
//! - **Thread Creation**: Stack setup, context initialization
//! - **Client ID Table**: Process/thread ID management
//! - **Job Objects**: Process grouping and limits
//!
//! # Process Structure
//!
//! EPROCESS contains:
//! - Embedded KPROCESS for scheduler
//! - Virtual address space (VAD root)
//! - Handle table
//! - Token (security context)
//! - Thread list
//!
//! # Thread Structure
//!
//! ETHREAD contains:
//! - Embedded KTHREAD for scheduler
//! - IRP list (pending I/O)
//! - Impersonation info
//! - Win32 thread info
//!
//! # Key Structures
//!
//! - `EPROCESS`: Full process structure
//! - `ETHREAD`: Full thread structure
//! - `CLIENT_ID`: Process/thread ID pair

// Submodules
pub mod cid;
pub mod create;
pub mod eprocess;
pub mod ethread;
pub mod job;
pub mod peb;
pub mod teb;

// Re-exports for convenience
pub use cid::{
    ClientId, CidEntryType, CidTableEntry,
    MAX_PROCESSES, MAX_THREADS,
    ps_allocate_process_id, ps_free_process_id, ps_lookup_process_by_id,
    ps_allocate_thread_id, ps_free_thread_id, ps_lookup_thread_by_id,
};

pub use eprocess::{
    EProcess, process_flags, PS_IMAGE_NAME_LENGTH,
    allocate_process, free_process, get_system_process,
    get_active_process_list,
};

pub use ethread::{
    EThread, thread_flags,
    allocate_thread, free_thread, get_thread_by_index,
};

pub use create::{
    PsThreadStartRoutine,
    ps_create_process, ps_create_system_process,
    ps_create_thread, ps_create_system_thread,
    ps_start_thread, ps_create_and_start_system_thread,
    // User-mode thread/process creation
    ps_create_user_thread, ps_create_user_process, ps_start_user_thread,
};

pub use job::{
    Job, JobBasicLimitInformation, JobExtendedLimitInformation,
    JobBasicAccountingInformation, JobIoCounters,
    job_limit_flags, job_security_flags, job_ui_flags,
    ps_create_job, ps_lookup_job, allocate_job, free_job,
    MAX_JOBS, MAX_PROCESSES_PER_JOB,
};

pub use peb::{
    Peb, PebLdrData, LdrDataTableEntry,
    RtlUserProcessParameters, UnicodeString,
    ListEntry64, peb_flags,
};

pub use teb::{
    Teb, NtTib, GdiTebBatch,
    TLS_MINIMUM_AVAILABLE, TLS_EXPANSION_SLOTS,
    get_current_teb, get_current_peb,
    get_last_error, set_last_error,
};

/// Initialize the Process Manager
///
/// # Safety
/// Must be called once during kernel Phase 1 initialization
pub unsafe fn init() {
    crate::serial_println!("[PS] Initializing Process Manager...");

    // Initialize the CID table
    cid::init_cid_table();

    // Initialize the system process (PID 0)
    eprocess::init_system_process();

    crate::serial_println!("[PS] Process Manager initialized");
}
