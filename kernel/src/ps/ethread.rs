//! Executive Thread (ETHREAD) Implementation
//!
//! ETHREAD is the full thread structure used by the executive.
//! It embeds KTHREAD (kernel thread) and adds:
//! - Thread ID
//! - Client ID (process ID + thread ID)
//! - Creation/exit times
//! - Start address
//! - IRP list (pending I/O)
//! - Impersonation info
//! - Win32 thread info
//!
//! # Object Header
//! ETHREAD is preceded by an OBJECT_HEADER for object manager integration.

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::ke::{KThread, list::ListEntry, SpinLock};
use super::cid::ClientId;
use super::eprocess::EProcess;
use super::teb::Teb;

/// Thread flags
pub mod thread_flags {
    /// Thread has been initialized
    pub const PS_THREAD_FLAGS_INITIALIZED: u32 = 0x0001;
    /// Thread is a system thread
    pub const PS_THREAD_FLAGS_SYSTEM: u32 = 0x0002;
    /// Thread is terminating
    pub const PS_THREAD_FLAGS_TERMINATED: u32 = 0x0004;
    /// Thread has pending APC
    pub const PS_THREAD_FLAGS_APC_PENDING: u32 = 0x0008;
    /// Thread is alertable
    pub const PS_THREAD_FLAGS_ALERTABLE: u32 = 0x0010;
    /// Thread is in an alertable wait
    pub const PS_THREAD_FLAGS_ALERTABLE_WAIT: u32 = 0x0020;
    /// Thread is impersonating
    pub const PS_THREAD_FLAGS_IMPERSONATING: u32 = 0x0040;
    /// Thread has been suspended
    pub const PS_THREAD_FLAGS_SUSPENDED: u32 = 0x0080;
    /// Thread is a GUI thread
    pub const PS_THREAD_FLAGS_GUI_THREAD: u32 = 0x0100;
}

/// Executive Thread structure
///
/// This is the full thread structure that wraps KTHREAD and adds
/// executive-level information.
#[repr(C)]
pub struct EThread {
    /// Embedded kernel thread structure
    /// Must be first for easy casting between ETHREAD and KTHREAD
    pub tcb: KThread,

    /// Thread lock
    pub thread_lock: SpinLock<()>,

    /// Client ID (process ID + thread ID)
    pub cid: ClientId,

    /// Thread creation time (system ticks)
    pub create_time: u64,

    /// Thread exit time (system ticks, 0 if running)
    pub exit_time: u64,

    /// Exit status
    pub exit_status: i32,

    /// Thread flags
    pub flags: AtomicU32,

    /// Owning process (EPROCESS pointer)
    pub thread_process: *mut EProcess,

    /// Start address (user mode entry point)
    pub start_address: *mut u8,

    /// Win32 start address
    pub win32_start_address: *mut u8,

    /// List entry in process's thread list
    pub thread_list_entry: ListEntry,

    /// IRP list entry head (pending I/O operations)
    pub irp_list: ListEntry,

    /// Pending IRP count
    pub pending_irp_count: AtomicU32,

    /// TEB (Thread Environment Block) address (user mode)
    pub teb: *mut Teb,

    /// Impersonation info
    pub impersonation_info: *mut u8,

    /// Cross-thread flags (accessible from other threads)
    pub cross_thread_flags: AtomicU32,

    /// Same-thread flags (only accessible from this thread)
    pub same_thread_flags: u32,

    /// LPC reply message
    pub lpc_reply_message: *mut u8,

    /// LPC reply message ID
    pub lpc_reply_message_id: u32,

    /// Win32 thread info
    pub win32_thread: *mut u8,

    /// Suspend count
    pub suspend_count: i32,

    /// Freeze count
    pub freeze_count: i32,

    /// Last error value (Win32)
    pub last_error_value: u32,

    /// Hard error mode
    pub hard_error_mode: u32,

    // Time accounting
    /// Kernel mode execution time (100ns units)
    pub kernel_time: u64,
    /// User mode execution time (100ns units)
    pub user_time: u64,
    /// CPU cycle count for this thread
    pub cycle_time: u64,

    // Priority and scheduling
    /// I/O priority (0=Very Low, 1=Low, 2=Normal, 3=High, 4=Critical)
    pub io_priority: u8,
    /// Page priority (0-7, higher = more important)
    pub page_priority: u8,
    /// Ideal processor (preferred CPU)
    pub ideal_processor: u8,
    /// Processor group for ideal processor
    pub ideal_processor_group: u16,

    // Debug flags
    /// Hide thread from debugger
    pub hide_from_debugger: bool,
    /// Break on termination
    pub break_on_termination: bool,
    /// Priority boost disabled
    pub priority_boost_disabled: bool,
    /// Enable alignment fault fixup (handles unaligned access)
    pub alignment_fault_fixup: bool,
}

// Safety: EThread uses locks and atomics
unsafe impl Sync for EThread {}
unsafe impl Send for EThread {}

impl EThread {
    /// Create a new uninitialized thread
    pub const fn new() -> Self {
        Self {
            tcb: KThread::new(),
            thread_lock: SpinLock::new(()),
            cid: ClientId::null(),
            create_time: 0,
            exit_time: 0,
            exit_status: 0,
            flags: AtomicU32::new(0),
            thread_process: ptr::null_mut(),
            start_address: ptr::null_mut(),
            win32_start_address: ptr::null_mut(),
            thread_list_entry: ListEntry::new(),
            irp_list: ListEntry::new(),
            pending_irp_count: AtomicU32::new(0),
            teb: ptr::null_mut(),
            impersonation_info: ptr::null_mut(),
            cross_thread_flags: AtomicU32::new(0),
            same_thread_flags: 0,
            lpc_reply_message: ptr::null_mut(),
            lpc_reply_message_id: 0,
            win32_thread: ptr::null_mut(),
            suspend_count: 0,
            freeze_count: 0,
            last_error_value: 0,
            hard_error_mode: 0,
            // Time accounting
            kernel_time: 0,
            user_time: 0,
            cycle_time: 0,
            // Priority and scheduling
            io_priority: 2, // Normal
            page_priority: 5, // Normal
            ideal_processor: 0,
            ideal_processor_group: 0,
            // Debug flags
            hide_from_debugger: false,
            break_on_termination: false,
            priority_boost_disabled: false,
            alignment_fault_fixup: true, // Default enabled
        }
    }

    /// Initialize a thread
    ///
    /// # Safety
    /// Must be called before the thread is used
    pub unsafe fn init(
        &mut self,
        process: *mut EProcess,
        thread_id: u32,
        stack_base: *mut u8,
        stack_size: usize,
        start_routine: fn(*mut u8),
        start_context: *mut u8,
        priority: i8,
    ) {
        // Initialize embedded KTHREAD
        self.tcb.init(
            thread_id,
            stack_base,
            stack_size,
            start_routine,
            start_context,
            priority,
            (*process).get_pcb_mut(),
        );

        // Set client ID
        self.cid = ClientId::new((*process).unique_process_id, thread_id);

        // Set creation time
        self.create_time = crate::hal::apic::get_tick_count();
        self.exit_time = 0;
        self.exit_status = 0;

        // Set process pointer
        self.thread_process = process;

        // Set start address
        self.start_address = start_routine as *mut u8;
        self.win32_start_address = ptr::null_mut();

        // Initialize lists
        self.thread_list_entry.init_head();
        self.irp_list.init_head();

        // Mark as initialized
        self.flags.store(thread_flags::PS_THREAD_FLAGS_INITIALIZED, Ordering::Release);
    }

    /// Get the thread ID
    #[inline]
    pub fn thread_id(&self) -> u32 {
        self.cid.unique_thread
    }

    /// Get the process ID
    #[inline]
    pub fn process_id(&self) -> u32 {
        self.cid.unique_process
    }

    /// Get the client ID
    #[inline]
    pub fn client_id(&self) -> ClientId {
        self.cid
    }

    /// Check if this is a system thread
    #[inline]
    pub fn is_system(&self) -> bool {
        (self.flags.load(Ordering::Acquire) & thread_flags::PS_THREAD_FLAGS_SYSTEM) != 0
    }

    /// Check if thread is terminating
    #[inline]
    pub fn is_terminating(&self) -> bool {
        (self.flags.load(Ordering::Acquire) & thread_flags::PS_THREAD_FLAGS_TERMINATED) != 0
    }

    /// Check if thread is suspended
    #[inline]
    pub fn is_suspended(&self) -> bool {
        (self.flags.load(Ordering::Acquire) & thread_flags::PS_THREAD_FLAGS_SUSPENDED) != 0
    }

    /// Set a thread flag
    pub fn set_flag(&self, flag: u32) {
        self.flags.fetch_or(flag, Ordering::AcqRel);
    }

    /// Clear a thread flag
    pub fn clear_flag(&self, flag: u32) {
        self.flags.fetch_and(!flag, Ordering::AcqRel);
    }

    /// Get KTHREAD pointer
    #[inline]
    pub fn get_tcb(&self) -> *const KThread {
        &self.tcb as *const KThread
    }

    /// Get mutable KTHREAD pointer
    #[inline]
    pub fn get_tcb_mut(&mut self) -> *mut KThread {
        &mut self.tcb as *mut KThread
    }

    /// Get the owning process
    #[inline]
    pub fn get_process(&self) -> *mut EProcess {
        self.thread_process
    }

    /// Suspend the thread
    ///
    /// # Returns
    /// Previous suspend count
    pub fn suspend(&mut self) -> i32 {
        let old = self.suspend_count;
        self.suspend_count += 1;
        if self.suspend_count == 1 {
            self.set_flag(thread_flags::PS_THREAD_FLAGS_SUSPENDED);
        }
        old
    }

    /// Resume the thread
    ///
    /// # Returns
    /// Previous suspend count
    pub fn resume(&mut self) -> i32 {
        let old = self.suspend_count;
        if self.suspend_count > 0 {
            self.suspend_count -= 1;
            if self.suspend_count == 0 {
                self.clear_flag(thread_flags::PS_THREAD_FLAGS_SUSPENDED);
            }
        }
        old
    }
}

impl Default for EThread {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Thread Pool (Static Allocation)
// ============================================================================

/// Maximum number of threads
pub const MAX_THREADS: usize = super::cid::MAX_THREADS;

/// Static thread pool
static mut THREAD_POOL: [EThread; MAX_THREADS] = {
    const INIT: EThread = EThread::new();
    [INIT; MAX_THREADS]
};

/// Thread pool bitmap (using multiple u64s for 256 threads)
static mut THREAD_POOL_BITMAP: [u64; 4] = [0; 4];

/// Thread pool lock
static THREAD_POOL_LOCK: SpinLock<()> = SpinLock::new(());

/// Allocate a thread from the pool
///
/// # Safety
/// Must be called with proper synchronization
pub unsafe fn allocate_thread() -> Option<*mut EThread> {
    let _guard = THREAD_POOL_LOCK.lock();

    for word_idx in 0..4 {
        if THREAD_POOL_BITMAP[word_idx] != u64::MAX {
            for bit_idx in 0..64 {
                let global_idx = word_idx * 64 + bit_idx;
                if global_idx >= MAX_THREADS {
                    return None;
                }
                if THREAD_POOL_BITMAP[word_idx] & (1 << bit_idx) == 0 {
                    THREAD_POOL_BITMAP[word_idx] |= 1 << bit_idx;
                    let thread = &mut THREAD_POOL[global_idx] as *mut EThread;
                    (*thread) = EThread::new();
                    return Some(thread);
                }
            }
        }
    }
    None
}

/// Free a thread back to the pool
///
/// # Safety
/// Thread must have been allocated from this pool
pub unsafe fn free_thread(thread: *mut EThread) {
    let _guard = THREAD_POOL_LOCK.lock();

    let base = THREAD_POOL.as_ptr() as usize;
    let offset = thread as usize - base;
    let index = offset / core::mem::size_of::<EThread>();
    if index < MAX_THREADS {
        let word_idx = index / 64;
        let bit_idx = index % 64;
        THREAD_POOL_BITMAP[word_idx] &= !(1 << bit_idx);
    }
}

/// Get thread by index (for iteration)
///
/// # Safety
/// Index must be valid
pub unsafe fn get_thread_by_index(index: usize) -> Option<*mut EThread> {
    if index < MAX_THREADS {
        let word_idx = index / 64;
        let bit_idx = index % 64;
        if THREAD_POOL_BITMAP[word_idx] & (1 << bit_idx) != 0 {
            return Some(&mut THREAD_POOL[index] as *mut EThread);
        }
    }
    None
}

/// Get list of all allocated threads
///
/// Returns an array of pointers to KThread (up to MAX_THREADS) and the count
pub fn ps_get_thread_list() -> ([*mut crate::ke::KThread; MAX_THREADS], usize) {
    let mut threads = [core::ptr::null_mut(); MAX_THREADS];
    let mut count = 0;

    unsafe {
        let _guard = THREAD_POOL_LOCK.lock();

        for word_idx in 0..4 {
            for bit_idx in 0..64 {
                let global_idx = word_idx * 64 + bit_idx;
                if global_idx >= MAX_THREADS {
                    break;
                }
                if THREAD_POOL_BITMAP[word_idx] & (1 << bit_idx) != 0 {
                    let ethread = &THREAD_POOL[global_idx];
                    threads[count] = ethread.get_tcb() as *mut crate::ke::KThread;
                    count += 1;
                }
            }
        }
    }

    (threads, count)
}

/// Get list of all allocated EThread pointers
///
/// Returns an array of pointers to EThread (up to MAX_THREADS) and the count
pub fn ps_get_ethread_list() -> ([*mut EThread; MAX_THREADS], usize) {
    let mut threads = [core::ptr::null_mut(); MAX_THREADS];
    let mut count = 0;

    unsafe {
        let _guard = THREAD_POOL_LOCK.lock();

        for word_idx in 0..4 {
            for bit_idx in 0..64 {
                let global_idx = word_idx * 64 + bit_idx;
                if global_idx >= MAX_THREADS {
                    break;
                }
                if THREAD_POOL_BITMAP[word_idx] & (1 << bit_idx) != 0 {
                    threads[count] = &mut THREAD_POOL[global_idx] as *mut EThread;
                    count += 1;
                }
            }
        }
    }

    (threads, count)
}
