//! Job Objects Implementation
//!
//! Job objects provide a mechanism for grouping processes and applying
//! limits and restrictions to the group as a whole.
//!
//! # Features
//! - Process grouping
//! - Resource limits (CPU time, memory, handles)
//! - Security restrictions
//! - Accounting information
//!
//! # NT Compatibility
//! - NtCreateJobObject - Create a job object
//! - NtOpenJobObject - Open existing job object
//! - NtAssignProcessToJobObject - Add process to job
//! - NtQueryInformationJobObject - Query job info
//! - NtSetInformationJobObject - Set job limits
//! - NtTerminateJobObject - Terminate all processes in job

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::ke::SpinLock;
use super::eprocess::EProcess;

/// Maximum processes per job
pub const MAX_PROCESSES_PER_JOB: usize = 16;

/// Maximum jobs
pub const MAX_JOBS: usize = 32;

/// Job limit flags
pub mod job_limit_flags {
    /// Limit on active processes
    pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x00000008;
    /// Limit on job time
    pub const JOB_OBJECT_LIMIT_JOB_TIME: u32 = 0x00000004;
    /// Limit on process time
    pub const JOB_OBJECT_LIMIT_PROCESS_TIME: u32 = 0x00000002;
    /// Limit on working set size
    pub const JOB_OBJECT_LIMIT_WORKINGSET: u32 = 0x00000001;
    /// Limit on process memory
    pub const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x00000100;
    /// Limit on job memory
    pub const JOB_OBJECT_LIMIT_JOB_MEMORY: u32 = 0x00000200;
    /// Die on unhandled exception
    pub const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x00000400;
    /// Breakaway OK
    pub const JOB_OBJECT_LIMIT_BREAKAWAY_OK: u32 = 0x00000800;
    /// Silent breakaway OK
    pub const JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK: u32 = 0x00001000;
    /// Kill on job close
    pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x00002000;
}

/// Job security limit flags
pub mod job_security_flags {
    /// No admin access
    pub const JOB_OBJECT_SECURITY_NO_ADMIN: u32 = 0x00000001;
    /// Restricted token required
    pub const JOB_OBJECT_SECURITY_RESTRICTED_TOKEN: u32 = 0x00000002;
    /// Only one active process
    pub const JOB_OBJECT_SECURITY_ONLY_TOKEN: u32 = 0x00000004;
    /// Filter tokens
    pub const JOB_OBJECT_SECURITY_FILTER_TOKENS: u32 = 0x00000008;
}

/// Job UI restriction flags
pub mod job_ui_flags {
    /// Desktop restrictions
    pub const JOB_OBJECT_UILIMIT_DESKTOP: u32 = 0x00000040;
    /// Display settings restrictions
    pub const JOB_OBJECT_UILIMIT_DISPLAYSETTINGS: u32 = 0x00000010;
    /// Exit windows restrictions
    pub const JOB_OBJECT_UILIMIT_EXITWINDOWS: u32 = 0x00000080;
    /// Global atoms restrictions
    pub const JOB_OBJECT_UILIMIT_GLOBALATOMS: u32 = 0x00000020;
    /// Handle restrictions
    pub const JOB_OBJECT_UILIMIT_HANDLES: u32 = 0x00000001;
    /// Read clipboard restrictions
    pub const JOB_OBJECT_UILIMIT_READCLIPBOARD: u32 = 0x00000002;
    /// System parameters restrictions
    pub const JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS: u32 = 0x00000008;
    /// Write clipboard restrictions
    pub const JOB_OBJECT_UILIMIT_WRITECLIPBOARD: u32 = 0x00000004;
}

/// Job basic limit information
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct JobBasicLimitInformation {
    /// Per-process user-mode execution time limit
    pub per_process_user_time_limit: i64,
    /// Per-job user-mode execution time limit
    pub per_job_user_time_limit: i64,
    /// Limit flags
    pub limit_flags: u32,
    /// Minimum working set size
    pub minimum_working_set_size: usize,
    /// Maximum working set size
    pub maximum_working_set_size: usize,
    /// Active process limit
    pub active_process_limit: u32,
    /// Processor affinity
    pub affinity: usize,
    /// Per-process priority class
    pub priority_class: u32,
    /// Scheduling class
    pub scheduling_class: u32,
}

impl JobBasicLimitInformation {
    pub const fn new() -> Self {
        Self {
            per_process_user_time_limit: 0,
            per_job_user_time_limit: 0,
            limit_flags: 0,
            minimum_working_set_size: 0,
            maximum_working_set_size: 0,
            active_process_limit: 0,
            affinity: 0,
            priority_class: 0,
            scheduling_class: 0,
        }
    }
}

impl Default for JobBasicLimitInformation {
    fn default() -> Self {
        Self::new()
    }
}

/// Job extended limit information
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct JobExtendedLimitInformation {
    /// Basic limit info
    pub basic_limit_information: JobBasicLimitInformation,
    /// IO counters
    pub io_info: JobIoCounters,
    /// Process memory limit
    pub process_memory_limit: usize,
    /// Job memory limit
    pub job_memory_limit: usize,
    /// Peak process memory used
    pub peak_process_memory_used: usize,
    /// Peak job memory used
    pub peak_job_memory_used: usize,
}

impl Default for JobExtendedLimitInformation {
    fn default() -> Self {
        Self::new()
    }
}

impl JobExtendedLimitInformation {
    pub const fn new() -> Self {
        Self {
            basic_limit_information: JobBasicLimitInformation::new(),
            io_info: JobIoCounters::new(),
            process_memory_limit: 0,
            job_memory_limit: 0,
            peak_process_memory_used: 0,
            peak_job_memory_used: 0,
        }
    }
}

/// Job I/O counters
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct JobIoCounters {
    pub read_operation_count: u64,
    pub write_operation_count: u64,
    pub other_operation_count: u64,
    pub read_transfer_count: u64,
    pub write_transfer_count: u64,
    pub other_transfer_count: u64,
}

impl Default for JobIoCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl JobIoCounters {
    pub const fn new() -> Self {
        Self {
            read_operation_count: 0,
            write_operation_count: 0,
            other_operation_count: 0,
            read_transfer_count: 0,
            write_transfer_count: 0,
            other_transfer_count: 0,
        }
    }
}

/// Job basic accounting information
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct JobBasicAccountingInformation {
    pub total_user_time: i64,
    pub total_kernel_time: i64,
    pub this_period_total_user_time: i64,
    pub this_period_total_kernel_time: i64,
    pub total_page_fault_count: u32,
    pub total_processes: u32,
    pub active_processes: u32,
    pub total_terminated_processes: u32,
}

impl Default for JobBasicAccountingInformation {
    fn default() -> Self {
        Self::new()
    }
}

impl JobBasicAccountingInformation {
    pub const fn new() -> Self {
        Self {
            total_user_time: 0,
            total_kernel_time: 0,
            this_period_total_user_time: 0,
            this_period_total_kernel_time: 0,
            total_page_fault_count: 0,
            total_processes: 0,
            active_processes: 0,
            total_terminated_processes: 0,
        }
    }
}

/// Job Object
#[repr(C)]
pub struct Job {
    /// Job lock
    pub lock: SpinLock<()>,

    /// Job ID
    pub job_id: u32,

    /// Job name (for named jobs)
    pub name: [u8; 64],

    /// Limit information
    pub limits: JobExtendedLimitInformation,

    /// Security restrictions
    pub security_limit_flags: u32,

    /// UI restrictions
    pub ui_restrictions: u32,

    /// Accounting information
    pub accounting: JobBasicAccountingInformation,

    /// List of processes in this job
    pub process_list: [*mut EProcess; MAX_PROCESSES_PER_JOB],
    pub process_count: AtomicU32,

    /// Flags
    pub flags: AtomicU32,

    /// Parent job (for nested jobs)
    pub parent_job: *mut Job,

    /// Completion port (for notifications)
    pub completion_port: *mut u8,
    pub completion_key: *mut u8,
}

// Safety: Job uses locks
unsafe impl Sync for Job {}
unsafe impl Send for Job {}

impl Job {
    pub const fn new() -> Self {
        Self {
            lock: SpinLock::new(()),
            job_id: 0,
            name: [0; 64],
            limits: JobExtendedLimitInformation::new(),
            security_limit_flags: 0,
            ui_restrictions: 0,
            accounting: JobBasicAccountingInformation::new(),
            process_list: [ptr::null_mut(); MAX_PROCESSES_PER_JOB],
            process_count: AtomicU32::new(0),
            flags: AtomicU32::new(0),
            parent_job: ptr::null_mut(),
            completion_port: ptr::null_mut(),
            completion_key: ptr::null_mut(),
        }
    }

    /// Initialize a job
    pub fn init(&mut self, job_id: u32, name: &[u8]) {
        self.job_id = job_id;

        // Copy name
        let len = name.len().min(63);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name[len] = 0;

        self.process_count.store(0, Ordering::Release);
        self.flags.store(0, Ordering::Release);
    }

    /// Assign a process to this job
    pub fn assign_process(&mut self, process: *mut EProcess) -> bool {
        // Get self pointer before locking
        let self_ptr = self as *mut Job;
        let _guard = self.lock.lock();

        // Check if we've hit the active process limit
        if self.limits.basic_limit_information.limit_flags & job_limit_flags::JOB_OBJECT_LIMIT_ACTIVE_PROCESS != 0 {
            let limit = self.limits.basic_limit_information.active_process_limit;
            if self.process_count.load(Ordering::Acquire) >= limit {
                return false;
            }
        }

        // Find a free slot
        for i in 0..MAX_PROCESSES_PER_JOB {
            if self.process_list[i].is_null() {
                self.process_list[i] = process;
                self.process_count.fetch_add(1, Ordering::AcqRel);
                self.accounting.total_processes += 1;
                self.accounting.active_processes += 1;

                // Update the process to point to this job
                unsafe {
                    (*process).job = self_ptr as *mut u8;
                }

                return true;
            }
        }

        false
    }

    /// Remove a process from this job
    pub fn remove_process(&mut self, process: *mut EProcess) -> bool {
        let _guard = self.lock.lock();

        for i in 0..MAX_PROCESSES_PER_JOB {
            if self.process_list[i] == process {
                self.process_list[i] = ptr::null_mut();
                self.process_count.fetch_sub(1, Ordering::AcqRel);
                self.accounting.active_processes -= 1;

                return true;
            }
        }

        false
    }

    /// Terminate all processes in the job
    pub fn terminate(&mut self, exit_status: i32) {
        let _guard = self.lock.lock();

        for i in 0..MAX_PROCESSES_PER_JOB {
            let process = self.process_list[i];
            if !process.is_null() {
                unsafe {
                    // Mark process as exiting
                    (*process).set_flag(super::eprocess::process_flags::PS_PROCESS_FLAGS_EXITING);
                    (*process).exit_status = exit_status;
                }
                self.accounting.total_terminated_processes += 1;
            }
            self.process_list[i] = ptr::null_mut();
        }

        self.process_count.store(0, Ordering::Release);
        self.accounting.active_processes = 0;
    }

    /// Get the number of active processes
    pub fn active_process_count(&self) -> u32 {
        self.process_count.load(Ordering::Acquire)
    }

    /// Check if kill on job close is set
    pub fn kill_on_close(&self) -> bool {
        self.limits.basic_limit_information.limit_flags & job_limit_flags::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0
    }
}

impl Default for Job {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Job Pool
// ============================================================================

/// Static job pool
static mut JOB_POOL: [Job; MAX_JOBS] = {
    const INIT: Job = Job::new();
    [INIT; MAX_JOBS]
};

/// Job pool bitmap
static mut JOB_POOL_BITMAP: u32 = 0;

/// Next job ID
static mut NEXT_JOB_ID: u32 = 1;

/// Job pool lock
static JOB_POOL_LOCK: SpinLock<()> = SpinLock::new(());

/// Allocate a job from the pool
pub unsafe fn allocate_job() -> Option<*mut Job> {
    let _guard = JOB_POOL_LOCK.lock();

    for i in 0..MAX_JOBS {
        if JOB_POOL_BITMAP & (1 << i) == 0 {
            JOB_POOL_BITMAP |= 1 << i;
            let job = &mut JOB_POOL[i] as *mut Job;
            (*job) = Job::new();
            return Some(job);
        }
    }
    None
}

/// Free a job back to the pool
pub unsafe fn free_job(job: *mut Job) {
    let _guard = JOB_POOL_LOCK.lock();

    let base = JOB_POOL.as_ptr() as usize;
    let offset = job as usize - base;
    let index = offset / core::mem::size_of::<Job>();

    if index < MAX_JOBS {
        JOB_POOL_BITMAP &= !(1 << index);
    }
}

/// Create a new job object
pub unsafe fn ps_create_job(name: &[u8]) -> *mut Job {
    let job = match allocate_job() {
        Some(j) => j,
        None => return ptr::null_mut(),
    };

    let job_id = NEXT_JOB_ID;
    NEXT_JOB_ID += 1;

    (*job).init(job_id, name);

    crate::serial_println!("[JOB] Created job {} '{}'", job_id,
        core::str::from_utf8_unchecked(&name[..name.len().min(31)]));

    job
}

/// Look up a job by ID
pub unsafe fn ps_lookup_job(job_id: u32) -> *mut Job {
    for i in 0..MAX_JOBS {
        if JOB_POOL_BITMAP & (1 << i) != 0
            && JOB_POOL[i].job_id == job_id {
                return &mut JOB_POOL[i] as *mut Job;
            }
    }
    ptr::null_mut()
}
