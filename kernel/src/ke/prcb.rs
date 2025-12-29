//! Kernel Processor Control Block (KPRCB)
//!
//! The KPRCB contains per-processor state including:
//! - Current and next thread pointers
//! - Ready queues (32 priority levels)
//! - Idle thread pointer
//! - Ready summary bitmap for O(1) thread selection
//! - IPI packet mechanism for inter-processor communication
//! - Queued spinlock entries for scalable locking
//!
//! In a multiprocessor system, each CPU has its own KPRCB.
//! This implementation is NT 5.2 (Windows Server 2003) compatible.

use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use super::list::ListEntry;
use super::thread::{KThread, constants::MAXIMUM_PRIORITY};

/// Maximum number of processors (from ACPI)
pub use crate::hal::acpi::MAX_PROCESSORS as MAX_CPUS;

/// Affinity type - bitmask of processors
pub type KAffinity = u64;

// ============================================================================
// IPI Request Types (NT compatible)
// ============================================================================

/// IPI request type flags (merged atomically into RequestSummary)
pub mod ipi_request {
    /// Request APC interrupt on target processor
    pub const IPI_APC: u64 = 1;
    /// Request DPC interrupt on target processor
    pub const IPI_DPC: u64 = 2;
    /// Freeze processor execution (for debugger)
    pub const IPI_FREEZE: u64 = 4;
    /// Packet is ready for processing
    pub const IPI_PACKET_READY: u64 = 8;
    /// Synchronization request (reverse stall)
    pub const IPI_SYNCH_REQUEST: u64 = 16;
}

/// Number of bits to shift for packet address in RequestSummary (AMD64)
pub const IPI_PACKET_SHIFT: u32 = 16;

/// Mask for request type bits in RequestSummary
pub const IPI_REQUEST_MASK: u64 = (1 << IPI_PACKET_SHIFT) - 1;

// ============================================================================
// Queued Spinlock Infrastructure
// ============================================================================

/// Lock queue number constants (NT compatible)
/// These are indices into the KPRCB.LockQueue array
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockQueueNumber {
    /// Dispatcher database lock
    LockQueueDispatcherLock = 0,
    /// Unused slot 1
    LockQueueUnusedSpare1 = 1,
    /// PFN database lock
    LockQueuePfnLock = 2,
    /// System space lock
    LockQueueSystemSpaceLock = 3,
    /// Vacb (virtual address control block) lock
    LockQueueVacbLock = 4,
    /// Master lock
    LockQueueMasterLock = 5,
    /// Nonpaged pool lock
    LockQueueNonPagedPoolLock = 6,
    /// I/O cancel lock
    LockQueueIoCancelLock = 7,
    /// Working set lock
    LockQueueWorkingSetLock = 8,
    /// I/O VP lock
    LockQueueIoVpbLock = 9,
    /// I/O database lock
    LockQueueIoDatabaseLock = 10,
    /// I/O completion lock
    LockQueueIoCompletionLock = 11,
    /// NTFS structure lock
    LockQueueNtfsStructLock = 12,
    /// AFD work queue lock
    LockQueueAfdWorkQueueLock = 13,
    /// BCD lock
    LockQueueBcdLock = 14,
    /// MM non-paged pool lock
    LockQueueMmNonPagedPoolLock = 15,
    /// Maximum number of lock queues
    LockQueueMaximumLock = 16,
}

/// Number of queued spinlocks per processor
pub const LOCK_QUEUE_MAXIMUM: usize = 16;

/// Queued spinlock queue entry
///
/// Each processor has one of these per numbered lock.
/// When acquiring a queued lock, the processor adds its entry to the lock's queue.
#[repr(C, align(16))]  // Cache-line aligned to reduce false sharing
pub struct KSpinLockQueue {
    /// Next waiter in the lock queue (null if none or if we hold the lock)
    pub next: AtomicUsize,  // *mut KSpinLockQueue
    /// Pointer to the actual spinlock (null when not waiting)
    pub lock: AtomicUsize,  // *mut u64
}

impl KSpinLockQueue {
    pub const fn new() -> Self {
        Self {
            next: AtomicUsize::new(0),
            lock: AtomicUsize::new(0),
        }
    }
}

// ============================================================================
// IPI Worker Function Types
// ============================================================================

/// IPI worker function signature
///
/// Called on target processor when IPI packet is delivered.
/// Parameters are passed via KPRCB.CurrentPacket[0..3].
pub type KipiWorker = unsafe fn(
    packet_context: *mut core::ffi::c_void,
    param1: *mut core::ffi::c_void,
    param2: *mut core::ffi::c_void,
    param3: *mut core::ffi::c_void,
);

/// Broadcast worker function signature
///
/// Used by KeIpiGenericCall for synchronous execution on all processors.
/// Returns a value that is combined with other processors' results.
pub type KipiBroadcastWorker = unsafe fn(argument: usize) -> usize;

// ============================================================================
// KPRCB - Kernel Processor Control Block
// ============================================================================

/// Kernel Processor Control Block
///
/// This structure contains per-processor state and is compatible with
/// Windows NT 5.2 (Server 2003) KPRCB layout for key fields.
#[repr(C, align(64))]  // Cache-line aligned
pub struct KPrcb {
    // ========================================================================
    // Processor Identification (offset 0x00)
    // ========================================================================

    /// Unique bitmask identifying this processor (1 << processor_number)
    /// Used for affinity masks and IPI targeting
    pub set_member: KAffinity,

    /// Processor number (0 for BSP, 1+ for APs)
    pub number: u32,

    /// Padding for alignment
    _pad0: u32,

    // ========================================================================
    // Thread Pointers (offset 0x10)
    // ========================================================================

    /// Currently running thread
    pub current_thread: *mut KThread,

    /// Thread selected to run next (set by scheduler)
    pub next_thread: *mut KThread,

    /// Idle thread for this processor
    pub idle_thread: *mut KThread,

    // ========================================================================
    // IPI Packet Mechanism (offset 0x28)
    // ========================================================================

    /// Synchronization barrier for multi-processor IPI packet completion
    /// Each bit represents a processor that must complete
    pub packet_barrier: AtomicU64,

    /// Current IPI packet parameters (3 pointers passed to worker)
    pub current_packet: [AtomicUsize; 3],

    /// Set of target processors for current IPI operation
    pub target_set: AtomicU64,

    /// Worker routine to execute on target processor
    pub worker_routine: AtomicUsize,  // KipiWorker

    /// Combined request mask and packet address
    /// Lower IPI_PACKET_SHIFT bits: request type flags
    /// Upper bits: pointer to sender's KPRCB (for packet operations)
    pub request_summary: AtomicU64,

    // ========================================================================
    // Queued Spinlocks (offset ~0x68)
    // ========================================================================

    /// Per-processor queued spinlock entries
    /// One entry per numbered lock (16 total)
    pub lock_queue: [KSpinLockQueue; LOCK_QUEUE_MAXIMUM],

    // ========================================================================
    // Scheduling State (offset varies)
    // ========================================================================

    /// Bitmap of non-empty ready queues
    /// Bit N is set if ready_queues[N] is non-empty
    /// Allows O(1) highest priority thread selection using BSR instruction
    pub ready_summary: u32,

    /// Padding
    _pad1: u32,

    /// Ready queues (one per priority level 0-31)
    /// Higher index = higher priority
    pub ready_queues: [ListEntry; MAXIMUM_PRIORITY],

    // ========================================================================
    // DPC Support
    // ========================================================================

    /// DPC queue head (for deferred procedure calls)
    pub dpc_queue_head: ListEntry,

    /// Number of DPCs queued
    pub dpc_queue_depth: u32,

    /// DPC pending flag (set when DPCs need processing)
    pub dpc_pending: bool,

    /// DPC interrupt requested flag
    pub dpc_interrupt_requested: bool,

    /// Padding
    _pad2: [u8; 2],

    // ========================================================================
    // Statistics
    // ========================================================================

    /// Number of context switches on this processor
    pub context_switches: u64,

    /// Quantum end flag (set by timer, cleared by scheduler)
    pub quantum_end: bool,

    /// Padding
    _pad3: [u8; 7],

    // ========================================================================
    // Freeze Support (Debugger)
    // ========================================================================

    /// Processor is frozen (for debugger)
    pub frozen: bool,

    /// Freeze requested via IPI
    pub freeze_requested: bool,

    /// Padding
    _pad4: [u8; 6],

    // ========================================================================
    // Multi-threaded Processor Support (SMT/Hyperthreading)
    // ========================================================================

    /// Set of processors sharing this physical core (SMT)
    pub multi_thread_processor_set: KAffinity,
}

impl KPrcb {
    /// Create a new uninitialized PRCB
    pub const fn new() -> Self {
        const EMPTY_LIST: ListEntry = ListEntry::new();
        const EMPTY_QUEUE: KSpinLockQueue = KSpinLockQueue::new();

        Self {
            // Identification
            set_member: 0,
            number: 0,
            _pad0: 0,

            // Thread pointers
            current_thread: ptr::null_mut(),
            next_thread: ptr::null_mut(),
            idle_thread: ptr::null_mut(),

            // IPI mechanism
            packet_barrier: AtomicU64::new(0),
            current_packet: [
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            ],
            target_set: AtomicU64::new(0),
            worker_routine: AtomicUsize::new(0),
            request_summary: AtomicU64::new(0),

            // Queued spinlocks
            lock_queue: [EMPTY_QUEUE; LOCK_QUEUE_MAXIMUM],

            // Scheduling
            ready_summary: 0,
            _pad1: 0,
            ready_queues: [EMPTY_LIST; MAXIMUM_PRIORITY],

            // DPC
            dpc_queue_head: ListEntry::new(),
            dpc_queue_depth: 0,
            dpc_pending: false,
            dpc_interrupt_requested: false,
            _pad2: [0; 2],

            // Statistics
            context_switches: 0,
            quantum_end: false,
            _pad3: [0; 7],

            // Freeze
            frozen: false,
            freeze_requested: false,
            _pad4: [0; 6],

            // SMT
            multi_thread_processor_set: 0,
        }
    }

    /// Initialize the PRCB for a specific processor
    pub fn init(&mut self, processor_number: u32) {
        self.number = processor_number;
        self.set_member = 1u64 << processor_number;
        self.current_thread = ptr::null_mut();
        self.next_thread = ptr::null_mut();
        self.idle_thread = ptr::null_mut();

        // Reset IPI state
        self.packet_barrier.store(0, Ordering::Relaxed);
        self.target_set.store(0, Ordering::Relaxed);
        self.worker_routine.store(0, Ordering::Relaxed);
        self.request_summary.store(0, Ordering::Relaxed);
        for packet in &self.current_packet {
            packet.store(0, Ordering::Relaxed);
        }

        // Reset lock queues
        for queue in &self.lock_queue {
            queue.next.store(0, Ordering::Relaxed);
            queue.lock.store(0, Ordering::Relaxed);
        }

        // Scheduling state
        self.ready_summary = 0;
        self.context_switches = 0;
        self.quantum_end = false;

        // Initialize all ready queue heads
        for queue in self.ready_queues.iter_mut() {
            queue.init_head();
        }

        // Initialize DPC queue
        self.dpc_queue_head.init_head();
        self.dpc_queue_depth = 0;
        self.dpc_pending = false;
        self.dpc_interrupt_requested = false;

        // Freeze state
        self.frozen = false;
        self.freeze_requested = false;

        // SMT - default to just this processor
        self.multi_thread_processor_set = self.set_member;
    }

    /// Find the highest priority non-empty ready queue
    ///
    /// Returns the priority level (0-31) or None if all queues are empty.
    /// Uses the ready_summary bitmap for O(1) lookup.
    #[inline]
    pub fn find_highest_ready_priority(&self) -> Option<usize> {
        if self.ready_summary == 0 {
            return None;
        }

        // Find highest set bit (highest priority with ready threads)
        // 31 - leading_zeros gives the index of the highest set bit
        let priority = 31 - self.ready_summary.leading_zeros();
        Some(priority as usize)
    }

    /// Check if any threads are ready to run
    #[inline]
    pub fn has_ready_threads(&self) -> bool {
        self.ready_summary != 0
    }

    /// Set the ready summary bit for a priority level
    #[inline]
    pub fn set_ready_bit(&mut self, priority: usize) {
        self.ready_summary |= 1 << priority;
    }

    /// Clear the ready summary bit for a priority level
    #[inline]
    pub fn clear_ready_bit(&mut self, priority: usize) {
        self.ready_summary &= !(1 << priority);
    }

    /// Get the lock queue entry for a specific lock number
    #[inline]
    pub fn get_lock_queue(&self, lock_number: LockQueueNumber) -> &KSpinLockQueue {
        &self.lock_queue[lock_number as usize]
    }

    /// Get mutable lock queue entry for a specific lock number
    #[inline]
    pub fn get_lock_queue_mut(&mut self, lock_number: LockQueueNumber) -> &mut KSpinLockQueue {
        &mut self.lock_queue[lock_number as usize]
    }
}

impl Default for KPrcb {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global PRCB Array and Management
// ============================================================================

/// Array of PRCBs for all processors
static mut PRCB_ARRAY: [KPrcb; MAX_CPUS] = [const { KPrcb::new() }; MAX_CPUS];

/// Array of pointers to PRCBs (like NT's KiProcessorBlock)
/// This allows indirect access needed for IPI operations
static mut KI_PROCESSOR_BLOCK: [*mut KPrcb; MAX_CPUS] = [ptr::null_mut(); MAX_CPUS];

/// Number of active CPUs (updated as APs start)
static ACTIVE_CPU_COUNT: AtomicUsize = AtomicUsize::new(1);

/// Bitmask of active processors
static KE_ACTIVE_PROCESSORS: AtomicU64 = AtomicU64::new(1);

/// Bitmask of idle processors
static KI_IDLE_SUMMARY: AtomicU64 = AtomicU64::new(0);

/// Initialize a specific processor's PRCB
///
/// # Safety
/// Must be called once per CPU during initialization
pub unsafe fn init_prcb(cpu_id: usize) {
    if cpu_id < MAX_CPUS {
        PRCB_ARRAY[cpu_id].init(cpu_id as u32);

        // Set up the processor block pointer
        KI_PROCESSOR_BLOCK[cpu_id] = &mut PRCB_ARRAY[cpu_id];

        // Set GS base to point to this CPU's PRCB
        let prcb_addr = &PRCB_ARRAY[cpu_id] as *const KPrcb as u64;
        crate::arch::x86_64::percpu::set_gs_base(prcb_addr);
    }
}

/// Initialize the boot processor's PRCB
///
/// # Safety
/// Must be called exactly once during kernel initialization
pub unsafe fn init_bsp_prcb() {
    init_prcb(0);
    // BSP is already counted in ACTIVE_CPU_COUNT initial value
    KE_ACTIVE_PROCESSORS.store(1, Ordering::Release);
}

/// Get a reference to the current processor's PRCB (via GS segment)
///
/// This reads the PRCB pointer from the GS segment base, allowing
/// fast per-CPU data access without locks.
#[inline]
pub fn get_current_prcb() -> &'static KPrcb {
    unsafe {
        let prcb_ptr = crate::arch::x86_64::percpu::get_gs_base() as *const KPrcb;
        if prcb_ptr.is_null() {
            // GS not initialized yet, fall back to BSP (during early boot)
            &PRCB_ARRAY[0]
        } else {
            &*prcb_ptr
        }
    }
}

/// Get a mutable reference to the current processor's PRCB (via GS segment)
///
/// # Safety
/// Caller must ensure proper synchronization (typically IRQL >= DISPATCH_LEVEL)
#[inline]
pub unsafe fn get_current_prcb_mut() -> &'static mut KPrcb {
    let prcb_ptr = crate::arch::x86_64::percpu::get_gs_base() as *mut KPrcb;
    if prcb_ptr.is_null() {
        // GS not initialized yet, fall back to BSP (during early boot)
        &mut PRCB_ARRAY[0]
    } else {
        &mut *prcb_ptr
    }
}

/// Get a reference to a specific CPU's PRCB by index
///
/// # Safety
/// Caller must ensure cpu_id is valid (< active CPU count)
#[inline]
pub unsafe fn get_prcb(cpu_id: usize) -> Option<&'static KPrcb> {
    if cpu_id < MAX_CPUS {
        Some(&PRCB_ARRAY[cpu_id])
    } else {
        None
    }
}

/// Get a mutable reference to a specific CPU's PRCB by index
///
/// # Safety
/// Caller must ensure cpu_id is valid and proper synchronization
#[inline]
pub unsafe fn get_prcb_mut(cpu_id: usize) -> Option<&'static mut KPrcb> {
    if cpu_id < MAX_CPUS {
        Some(&mut PRCB_ARRAY[cpu_id])
    } else {
        None
    }
}

/// Get the processor block pointer (like NT's KiProcessorBlock)
///
/// # Safety
/// Must be called after PRCB initialization
#[inline]
pub unsafe fn ki_get_processor_block(cpu_id: usize) -> *mut KPrcb {
    if cpu_id < MAX_CPUS {
        KI_PROCESSOR_BLOCK[cpu_id]
    } else {
        ptr::null_mut()
    }
}

/// Get the number of active CPUs
#[inline]
pub fn get_active_cpu_count() -> usize {
    ACTIVE_CPU_COUNT.load(Ordering::Acquire)
}

/// Get the active processor mask
#[inline]
pub fn ke_get_active_processors() -> KAffinity {
    KE_ACTIVE_PROCESSORS.load(Ordering::Acquire)
}

/// Get the idle processor summary
#[inline]
pub fn ki_get_idle_summary() -> KAffinity {
    KI_IDLE_SUMMARY.load(Ordering::Acquire)
}

/// Set a processor as idle
#[inline]
pub fn ki_set_processor_idle(cpu_id: usize) {
    KI_IDLE_SUMMARY.fetch_or(1u64 << cpu_id, Ordering::Release);
}

/// Clear a processor's idle status
#[inline]
pub fn ki_clear_processor_idle(cpu_id: usize) {
    KI_IDLE_SUMMARY.fetch_and(!(1u64 << cpu_id), Ordering::Release);
}

/// Increment the active CPU count (called when an AP starts)
///
/// # Safety
/// Must be called with proper synchronization during AP startup
pub unsafe fn increment_active_cpu_count() {
    let count = ACTIVE_CPU_COUNT.fetch_add(1, Ordering::AcqRel) + 1;
    // Also update active processors mask
    let prcb = get_current_prcb();
    KE_ACTIVE_PROCESSORS.fetch_or(prcb.set_member, Ordering::Release);
    crate::serial_println!("[SMP] CPU {} online, {} total active", prcb.number, count);
}

/// Get the currently running thread
#[inline]
pub fn get_current_thread() -> *mut KThread {
    get_current_prcb().current_thread
}

/// Set the currently running thread
///
/// # Safety
/// Must be called from scheduler context with proper synchronization
#[inline]
pub unsafe fn set_current_thread(thread: *mut KThread) {
    get_current_prcb_mut().current_thread = thread;
}

/// Get the current processor number
#[inline]
pub fn ke_get_current_processor_number() -> u32 {
    get_current_prcb().number
}

/// Get the current processor's set member (affinity bit)
#[inline]
pub fn ke_get_current_processor_set_member() -> KAffinity {
    get_current_prcb().set_member
}
