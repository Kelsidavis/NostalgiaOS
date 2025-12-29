//! Executive Process (EPROCESS) Implementation
//!
//! EPROCESS is the full process structure used by the executive.
//! It embeds KPROCESS (kernel process) and adds:
//! - Process ID
//! - Parent process ID
//! - Image name
//! - Creation/exit times
//! - Handle table
//! - Token (security context)
//! - Virtual address space info
//! - Thread list
//!
//! # Object Header
//! EPROCESS is preceded by an OBJECT_HEADER for object manager integration.

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::ke::{KProcess, ProcessState, list::ListEntry, SpinLock};
use crate::ob::HandleTable;
use super::cid::ClientId;

/// Maximum length of process image name
pub const PS_IMAGE_NAME_LENGTH: usize = 16;

/// Process flags
pub mod process_flags {
    /// Process has been initialized
    pub const PS_PROCESS_FLAGS_INITIALIZED: u32 = 0x0001;
    /// Process is a system process
    pub const PS_PROCESS_FLAGS_SYSTEM: u32 = 0x0002;
    /// Process is exiting
    pub const PS_PROCESS_FLAGS_EXITING: u32 = 0x0004;
    /// Process has exited
    pub const PS_PROCESS_FLAGS_DEAD: u32 = 0x0008;
    /// Process is being debugged
    pub const PS_PROCESS_FLAGS_DEBUG: u32 = 0x0010;
    /// Process is a WOW64 process
    pub const PS_PROCESS_FLAGS_WOW64: u32 = 0x0020;
    /// Process is in a job
    pub const PS_PROCESS_FLAGS_IN_JOB: u32 = 0x0040;
}

/// Executive Process structure
///
/// This is the full process structure that wraps KPROCESS and adds
/// executive-level information.
#[repr(C)]
pub struct EProcess {
    /// Embedded kernel process structure
    /// Must be first for easy casting between EPROCESS and KPROCESS
    pub pcb: KProcess,

    /// Process lock
    pub process_lock: SpinLock<()>,

    /// Process ID (unique identifier)
    pub unique_process_id: u32,

    /// Parent process ID
    pub inherited_from_unique_process_id: u32,

    /// Process creation time (system ticks)
    pub create_time: u64,

    /// Process exit time (system ticks, 0 if running)
    pub exit_time: u64,

    /// Exit status
    pub exit_status: i32,

    /// Process flags
    pub flags: AtomicU32,

    /// Image file name (short name, e.g., "notepad.exe")
    pub image_file_name: [u8; PS_IMAGE_NAME_LENGTH],

    /// Active thread count
    pub active_threads: AtomicU32,

    /// Handle table for this process
    pub object_table: *mut HandleTable,

    /// Primary access token
    pub token: *mut u8, // TODO: Should be *mut TOKEN

    /// List entry for global process list
    pub active_process_links: ListEntry,

    /// Head of thread list (ETHREAD entries)
    pub thread_list_head: ListEntry,

    /// Number of threads
    pub thread_count: AtomicU32,

    /// Virtual size of process
    pub virtual_size: u64,

    /// Peak virtual size
    pub peak_virtual_size: u64,

    /// Working set size
    pub working_set_size: u64,

    /// Peak working set size
    pub peak_working_set_size: u64,

    /// Quota usage (paged pool)
    pub quota_paged_pool_usage: u64,

    /// Quota usage (nonpaged pool)
    pub quota_non_paged_pool_usage: u64,

    /// Session ID (for Terminal Services)
    pub session_id: u32,

    /// PEB (Process Environment Block) address (user mode)
    pub peb: *mut u8,

    /// Exception port
    pub exception_port: *mut u8,

    /// Debug port
    pub debug_port: *mut u8,

    /// Job object
    pub job: *mut u8,

    /// Section object (for mapped executable)
    pub section_object: *mut u8,

    // I/O counters
    /// Read operation count
    pub read_operation_count: u64,
    /// Write operation count
    pub write_operation_count: u64,
    /// Other operation count
    pub other_operation_count: u64,
    /// Read transfer count (bytes)
    pub read_transfer_count: u64,
    /// Write transfer count (bytes)
    pub write_transfer_count: u64,
    /// Other transfer count (bytes)
    pub other_transfer_count: u64,

    // Time accounting
    /// Kernel mode execution time (100ns units)
    pub kernel_time: u64,
    /// User mode execution time (100ns units)
    pub user_time: u64,
    /// CPU cycle time counter
    pub cycle_time: u64,

    // Priority
    /// Process priority class (NORMAL_PRIORITY_CLASS, etc.)
    pub priority_class: u8,
    /// I/O priority (0=Very Low, 1=Low, 2=Normal, 3=High, 4=Critical)
    pub io_priority: u8,
    /// Page priority (0-7)
    pub page_priority: u8,

    // Counters and flags
    /// Handle count
    pub handle_count: u32,
    /// Break on termination (for debugging)
    pub break_on_termination: bool,
    /// Priority boost disabled
    pub priority_boost_disabled: bool,
    /// Hard error mode (SEM_FAILCRITICALERRORS, etc.)
    pub hard_error_mode: u32,

    /// Process cookie (for ASLR)
    pub cookie: u32,
}

// Safety: EProcess uses locks and atomics
unsafe impl Sync for EProcess {}
unsafe impl Send for EProcess {}

impl EProcess {
    /// Create a new uninitialized process
    pub const fn new() -> Self {
        Self {
            pcb: KProcess::new(),
            process_lock: SpinLock::new(()),
            unique_process_id: 0,
            inherited_from_unique_process_id: 0,
            create_time: 0,
            exit_time: 0,
            exit_status: 0,
            flags: AtomicU32::new(0),
            image_file_name: [0; PS_IMAGE_NAME_LENGTH],
            active_threads: AtomicU32::new(0),
            object_table: ptr::null_mut(),
            token: ptr::null_mut(),
            active_process_links: ListEntry::new(),
            thread_list_head: ListEntry::new(),
            thread_count: AtomicU32::new(0),
            virtual_size: 0,
            peak_virtual_size: 0,
            working_set_size: 0,
            peak_working_set_size: 0,
            quota_paged_pool_usage: 0,
            quota_non_paged_pool_usage: 0,
            session_id: 0,
            peb: ptr::null_mut(),
            exception_port: ptr::null_mut(),
            debug_port: ptr::null_mut(),
            job: ptr::null_mut(),
            section_object: ptr::null_mut(),
            // I/O counters
            read_operation_count: 0,
            write_operation_count: 0,
            other_operation_count: 0,
            read_transfer_count: 0,
            write_transfer_count: 0,
            other_transfer_count: 0,
            // Time accounting
            kernel_time: 0,
            user_time: 0,
            cycle_time: 0,
            // Priority
            priority_class: 0x20, // NORMAL_PRIORITY_CLASS
            io_priority: 2, // Normal
            page_priority: 5, // Normal
            // Counters and flags
            handle_count: 0,
            break_on_termination: false,
            priority_boost_disabled: false,
            hard_error_mode: 0,
            cookie: 0,
        }
    }

    /// Initialize a process
    ///
    /// # Safety
    /// Must be called before the process is used
    pub unsafe fn init(
        &mut self,
        process_id: u32,
        parent_id: u32,
        name: &[u8],
        base_priority: i8,
    ) {
        // Initialize embedded KPROCESS
        self.pcb.init(process_id, base_priority, 0);

        self.unique_process_id = process_id;
        self.inherited_from_unique_process_id = parent_id;

        // Set creation time
        self.create_time = crate::hal::apic::get_tick_count();
        self.exit_time = 0;
        self.exit_status = 0;

        // Copy image name
        let len = name.len().min(PS_IMAGE_NAME_LENGTH - 1);
        self.image_file_name[..len].copy_from_slice(&name[..len]);
        self.image_file_name[len] = 0;

        // Initialize lists
        self.thread_list_head.init_head();
        self.active_process_links.init_head();

        // Initialize counters
        self.active_threads = AtomicU32::new(0);
        self.thread_count = AtomicU32::new(0);

        // Mark as initialized
        self.flags.store(process_flags::PS_PROCESS_FLAGS_INITIALIZED, Ordering::Release);
    }

    /// Get the process ID
    #[inline]
    pub fn process_id(&self) -> u32 {
        self.unique_process_id
    }

    /// Get the parent process ID
    #[inline]
    pub fn parent_process_id(&self) -> u32 {
        self.inherited_from_unique_process_id
    }

    /// Get the image name as a slice
    pub fn image_name(&self) -> &[u8] {
        let len = self.image_file_name.iter()
            .position(|&b| b == 0)
            .unwrap_or(PS_IMAGE_NAME_LENGTH);
        &self.image_file_name[..len]
    }

    /// Check if this is the system process
    #[inline]
    pub fn is_system(&self) -> bool {
        (self.flags.load(Ordering::Acquire) & process_flags::PS_PROCESS_FLAGS_SYSTEM) != 0
    }

    /// Check if process is exiting
    #[inline]
    pub fn is_exiting(&self) -> bool {
        (self.flags.load(Ordering::Acquire) & process_flags::PS_PROCESS_FLAGS_EXITING) != 0
    }

    /// Set a process flag
    pub fn set_flag(&self, flag: u32) {
        self.flags.fetch_or(flag, Ordering::AcqRel);
    }

    /// Clear a process flag
    pub fn clear_flag(&self, flag: u32) {
        self.flags.fetch_and(!flag, Ordering::AcqRel);
    }

    /// Increment active thread count
    pub fn increment_thread_count(&self) -> u32 {
        self.active_threads.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Decrement active thread count
    ///
    /// # Returns
    /// New thread count (0 means process should terminate)
    pub fn decrement_thread_count(&self) -> u32 {
        let old = self.active_threads.fetch_sub(1, Ordering::SeqCst);
        if old > 0 { old - 1 } else { 0 }
    }

    /// Get active thread count
    #[inline]
    pub fn thread_count(&self) -> u32 {
        self.active_threads.load(Ordering::SeqCst)
    }

    /// Get KPROCESS pointer
    #[inline]
    pub fn get_pcb(&self) -> *const KProcess {
        &self.pcb as *const KProcess
    }

    /// Get mutable KPROCESS pointer
    #[inline]
    pub fn get_pcb_mut(&mut self) -> *mut KProcess {
        &mut self.pcb as *mut KProcess
    }

    /// Get client ID for this process (with thread ID 0)
    pub fn client_id(&self) -> ClientId {
        ClientId::new(self.unique_process_id, 0)
    }
}

impl Default for EProcess {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Process Pool (Static Allocation)
// ============================================================================

/// Maximum number of processes
pub const MAX_PROCESSES: usize = super::cid::MAX_PROCESSES;

/// Static process pool
static mut PROCESS_POOL: [EProcess; MAX_PROCESSES] = {
    const INIT: EProcess = EProcess::new();
    [INIT; MAX_PROCESSES]
};

/// Process pool bitmap
static mut PROCESS_POOL_BITMAP: u64 = 0;

/// System process (PID 0)
static mut SYSTEM_PROCESS: EProcess = EProcess::new();

/// Active process list head
static mut ACTIVE_PROCESS_LIST: ListEntry = ListEntry::new();

/// Process list lock
static PROCESS_LIST_LOCK: SpinLock<()> = SpinLock::new(());

/// Allocate a process from the pool
///
/// # Safety
/// Must be called with proper synchronization
pub unsafe fn allocate_process() -> Option<*mut EProcess> {
    for i in 0..MAX_PROCESSES {
        if PROCESS_POOL_BITMAP & (1 << i) == 0 {
            PROCESS_POOL_BITMAP |= 1 << i;
            let process = &mut PROCESS_POOL[i] as *mut EProcess;
            (*process) = EProcess::new();
            return Some(process);
        }
    }
    None
}

/// Free a process back to the pool
///
/// # Safety
/// Process must have been allocated from this pool
pub unsafe fn free_process(process: *mut EProcess) {
    let base = PROCESS_POOL.as_ptr() as usize;
    let offset = process as usize - base;
    let index = offset / core::mem::size_of::<EProcess>();
    if index < MAX_PROCESSES {
        PROCESS_POOL_BITMAP &= !(1 << index);
    }
}

/// Get the system process
pub fn get_system_process() -> *mut EProcess {
    unsafe { &mut SYSTEM_PROCESS as *mut EProcess }
}

/// Initialize the system process
///
/// # Safety
/// Must be called once during kernel initialization
pub unsafe fn init_system_process() {
    SYSTEM_PROCESS.init(0, 0, b"System", 8);
    SYSTEM_PROCESS.set_flag(process_flags::PS_PROCESS_FLAGS_SYSTEM);
    SYSTEM_PROCESS.pcb.state = ProcessState::Ready;

    // Initialize active process list
    ACTIVE_PROCESS_LIST.init_head();

    // Add system process to active list
    let _guard = PROCESS_LIST_LOCK.lock();
    ACTIVE_PROCESS_LIST.insert_tail(&mut SYSTEM_PROCESS.active_process_links);

    // Register in CID table
    super::cid::ps_register_system_process(&mut SYSTEM_PROCESS as *mut _ as *mut u8);

    crate::serial_println!("[PS] System process initialized (PID 0)");
}

/// Get the active process list head
pub unsafe fn get_active_process_list() -> *mut ListEntry {
    &mut ACTIVE_PROCESS_LIST as *mut ListEntry
}
