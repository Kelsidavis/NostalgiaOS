//! Kernel Process (KPROCESS) implementation
//!
//! KPROCESS is the kernel's representation of a process. It contains:
//! - Address space information (page directory)
//! - Default scheduling parameters
//! - List of threads belonging to the process
//!
//! Note: This is a simplified implementation for the initial scheduler.
//! Full NT EPROCESS would be built on top of this.

use super::list::ListEntry;

/// Process states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProcessState {
    /// Process is initialized but has no threads
    Initialized = 0,
    /// Process is ready (has runnable threads)
    Ready = 1,
    /// Process is running (at least one thread running)
    Running = 2,
    /// Process has terminated
    Terminated = 3,
}

/// Kernel Process structure
///
/// This is modeled after Windows NT's KPROCESS structure.
#[repr(C)]
pub struct KProcess {
    /// Process state
    pub state: ProcessState,

    /// Base priority for new threads in this process
    pub base_priority: i8,

    /// Thread quantum for threads in this process
    pub thread_quantum: i8,

    /// Affinity mask (which processors threads can run on)
    pub affinity: u64,

    /// Head of thread list (threads belonging to this process)
    pub thread_list_head: ListEntry,

    /// Number of active threads
    pub active_threads: u32,

    /// Page directory base (CR3 value for this process)
    /// For kernel processes, this may be 0 (use kernel page tables)
    pub directory_table_base: u64,

    /// Process ID
    pub process_id: u32,
}

impl KProcess {
    /// Create a new uninitialized process
    pub const fn new() -> Self {
        Self {
            state: ProcessState::Initialized,
            base_priority: 8,
            thread_quantum: super::thread::constants::THREAD_QUANTUM,
            affinity: u64::MAX, // All processors
            thread_list_head: ListEntry::new(),
            active_threads: 0,
            directory_table_base: 0,
            process_id: 0,
        }
    }

    /// Initialize a process
    pub fn init(&mut self, process_id: u32, base_priority: i8, directory_table_base: u64) {
        self.process_id = process_id;
        self.base_priority = base_priority;
        self.directory_table_base = directory_table_base;
        self.thread_list_head.init_head();
        self.state = ProcessState::Initialized;
        self.active_threads = 0;
    }
}

impl Default for KProcess {
    fn default() -> Self {
        Self::new()
    }
}

/// The system process (process 0)
///
/// This is a static process that owns all kernel threads.
/// Kernel threads don't have their own address space - they use
/// the kernel's page tables.
static mut SYSTEM_PROCESS: KProcess = KProcess::new();

/// Initialize the system process
///
/// # Safety
/// Must be called exactly once during kernel initialization
pub unsafe fn init_system_process() {
    SYSTEM_PROCESS.init(0, 8, 0);
    SYSTEM_PROCESS.state = ProcessState::Ready;
}

/// Get a reference to the system process
pub fn get_system_process() -> &'static KProcess {
    unsafe { &SYSTEM_PROCESS }
}

/// Get a mutable pointer to the system process
///
/// # Safety
/// Caller must ensure proper synchronization
pub unsafe fn get_system_process_mut() -> *mut KProcess {
    &mut SYSTEM_PROCESS as *mut KProcess
}
