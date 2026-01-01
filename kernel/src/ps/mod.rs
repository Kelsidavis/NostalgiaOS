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
pub mod quota;

// Re-exports for convenience
pub use cid::{
    ClientId, CidEntryType, CidTableEntry,
    MAX_PROCESSES, MAX_THREADS,
    ps_allocate_process_id, ps_free_process_id, ps_lookup_process_by_id,
    ps_allocate_thread_id, ps_free_thread_id, ps_lookup_thread_by_id,
    // Inspection
    CidStats, CidEntrySnapshot,
    get_cid_stats, get_process_cid_snapshots, get_thread_cid_snapshots,
};

pub use eprocess::{
    EProcess, process_flags, PS_IMAGE_NAME_LENGTH,
    allocate_process, free_process, get_system_process,
    get_active_process_list,
};

pub use ethread::{
    EThread, thread_flags,
    allocate_thread, free_thread, get_thread_by_index,
    ps_get_thread_list, ps_get_ethread_list,
};

pub use create::{
    PsThreadStartRoutine,
    ps_create_process, ps_create_system_process,
    ps_create_thread, ps_create_system_thread,
    ps_start_thread, ps_create_and_start_system_thread,
    // User-mode thread/process creation
    ps_create_user_thread, ps_create_user_thread_ex,
    ps_create_user_process, ps_create_user_process_ex,
    ps_start_user_thread,
};

pub use job::{
    Job, JobBasicLimitInformation, JobExtendedLimitInformation,
    JobBasicAccountingInformation, JobIoCounters,
    job_limit_flags, job_security_flags, job_ui_flags,
    ps_create_job, ps_lookup_job, allocate_job, free_job,
    MAX_JOBS, MAX_PROCESSES_PER_JOB,
    // Inspection
    JobStats, JobSnapshot,
    get_job_stats, ps_get_job_snapshots, job_limit_flags_name,
};

pub use peb::{
    Peb, PebLdrData, LdrDataTableEntry,
    RtlUserProcessParameters, UnicodeString,
    ListEntry64, peb_flags, ldr_flags,
    // PEB allocation and initialization
    allocate_peb, free_peb, init_peb, init_peb_ldr_data,
    // LDR entry allocation and initialization
    allocate_ldr_entry, free_ldr_entry, init_ldr_entry,
    add_ldr_entry_to_lists, create_ldr_entry_for_module,
    MAX_LDR_ENTRIES,
    // Inspection
    PebPoolStats, PebSnapshot,
    get_peb_pool_stats, ps_get_peb_snapshots,
};

pub use teb::{
    Teb, NtTib, GdiTebBatch,
    TLS_MINIMUM_AVAILABLE, TLS_EXPANSION_SLOTS,
    get_current_teb, get_current_peb,
    get_last_error, set_last_error,
    // TEB allocation and initialization
    allocate_teb, free_teb, init_teb, get_teb_gs_base,
    // Inspection
    TebPoolStats, TebSnapshot,
    get_teb_pool_stats, ps_get_teb_snapshots,
};

pub use quota::{
    QuotaBlock, QuotaUsage, QuotaLimits, QuotaLimitsEx, PoolType,
    MAX_QUOTA_BLOCKS,
    DEFAULT_PAGED_POOL_LIMIT, DEFAULT_NONPAGED_POOL_LIMIT,
    DEFAULT_PAGEFILE_LIMIT, DEFAULT_WORKING_SET_LIMIT,
    // Allocation and management
    allocate_quota_block, allocate_quota_block_with_limits,
    get_quota_block, release_quota_block,
    // NT API compatibility
    ps_charge_pool_quota, ps_return_pool_quota,
    ps_charge_process_non_paged_pool_quota, ps_return_process_non_paged_pool_quota,
    ps_charge_process_paged_pool_quota, ps_return_process_paged_pool_quota,
    ps_charge_process_page_file_quota, ps_return_process_page_file_quota,
    ps_query_quota_limits, ps_set_quota_limits,
    // Inspection
    QuotaStats, QuotaBlockSnapshot,
    get_quota_stats, get_quota_block_snapshots, get_quota_block_count,
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

    // Initialize quota management
    quota::init();

    crate::serial_println!("[PS] Process Manager initialized");
}

/// Get the current process (EPROCESS)
///
/// Returns a pointer to the EPROCESS of the current thread's process.
/// Returns null if there is no current thread.
pub fn get_current_process() -> *mut EProcess {
    // Get the current thread from PRCB
    let prcb = unsafe { crate::ke::prcb::get_current_prcb_mut() };
    let thread = prcb.current_thread;

    if thread.is_null() {
        return core::ptr::null_mut();
    }

    // Get the process from the thread
    // KThread.process points to KProcess, but KPROCESS is embedded at offset 0 in EPROCESS
    // so we can safely cast between them
    let kprocess = unsafe { (*thread).process };
    if kprocess.is_null() {
        return core::ptr::null_mut();
    }
    kprocess as *mut EProcess
}

/// Get the current thread (ETHREAD)
///
/// Returns a pointer to the ETHREAD of the current thread.
/// Returns null if there is no current thread.
pub fn get_current_thread() -> *mut EThread {
    let prcb = unsafe { crate::ke::prcb::get_current_prcb_mut() };
    let kthread = prcb.current_thread;

    if kthread.is_null() {
        return core::ptr::null_mut();
    }

    // The KTHREAD is embedded at the start of ETHREAD
    // So we can cast the pointer directly
    kthread as *mut EThread
}
