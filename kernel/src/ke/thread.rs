//! Kernel Thread (KTHREAD) implementation
//!
//! KTHREAD is the kernel's representation of a thread. It contains:
//! - Scheduling state (priority, quantum, state)
//! - Thread context (saved registers for context switch)
//! - List entries for ready queue and wait list
//! - APC queues for asynchronous procedure calls
//! - Pointer to owning process

use core::ptr;
use super::list::ListEntry;
use super::process::KProcess;
use super::apc::KApcState;
use super::dispatcher::{KWaitBlock, WaitType, WaitStatus};

/// Thread states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThreadState {
    /// Thread is initialized but not yet started
    Initialized = 0,
    /// Thread is in a ready queue waiting to run
    Ready = 1,
    /// Thread is currently running on a processor
    Running = 2,
    /// Thread is in a standby state (selected to run next)
    Standby = 3,
    /// Thread has terminated
    Terminated = 4,
    /// Thread is waiting for an object
    Waiting = 5,
    /// Thread is transitioning between states
    Transition = 6,
    /// Thread is deferred ready (will be made ready)
    DeferredReady = 7,
}

/// Scheduling constants (NT compatible)
pub mod constants {
    /// Maximum priority level (0-31)
    pub const MAXIMUM_PRIORITY: usize = 32;
    /// Low realtime priority threshold
    pub const LOW_REALTIME_PRIORITY: i8 = 16;
    /// Default thread quantum (time slices)
    pub const THREAD_QUANTUM: i8 = 6;
    /// Quantum decrement per clock tick
    pub const CLOCK_QUANTUM_DECREMENT: i8 = 3;
    /// Stack size per thread (16KB)
    pub const THREAD_STACK_SIZE: usize = 16384;
    /// Maximum threads in static pool
    pub const MAX_THREADS: usize = 32;
}

/// Saved thread context for context switching
///
/// Contains callee-saved registers that must be preserved across function calls.
/// The x86-64 ABI requires preserving: RBX, RBP, R12-R15, and RSP.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ThreadContext {
    /// RBX register
    pub rbx: u64,
    /// RBP register (frame pointer)
    pub rbp: u64,
    /// R12 register
    pub r12: u64,
    /// R13 register
    pub r13: u64,
    /// R14 register
    pub r14: u64,
    /// R15 register
    pub r15: u64,
    /// RFLAGS register
    pub rflags: u64,
    /// RIP register (instruction pointer) - return address
    pub rip: u64,
}

impl ThreadContext {
    pub const fn new() -> Self {
        Self {
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rflags: 0x202, // Interrupts enabled
            rip: 0,
        }
    }
}

impl Default for ThreadContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Kernel Thread structure
///
/// This is modeled after Windows NT's KTHREAD structure.
#[repr(C)]
pub struct KThread {
    // Scheduling fields
    /// Current thread state
    pub state: ThreadState,
    /// Current priority (0-31, higher = more important)
    pub priority: i8,
    /// Base priority (restored after priority boost expires)
    pub base_priority: i8,
    /// Remaining quantum (time slices before preemption)
    pub quantum: i8,
    /// Priority decrement (for aging)
    pub priority_decrement: i8,
    /// Saturation (priority boost saturation)
    pub saturation: i8,

    // List entries for queue membership
    /// Entry in ready queue or wait list
    pub wait_list_entry: ListEntry,
    /// Entry in process's thread list
    pub thread_list_entry: ListEntry,

    // Stack
    /// Kernel stack pointer (current RSP when not running)
    pub kernel_stack: *mut u8,
    /// Base of kernel stack (highest address)
    pub stack_base: *mut u8,
    /// Limit of kernel stack (lowest address)
    pub stack_limit: *mut u8,

    // Context
    /// Saved register context for context switch
    pub context: ThreadContext,

    // Process
    /// Owning process
    pub process: *mut KProcess,

    // Thread routine
    /// Start routine (entry point)
    pub start_routine: Option<fn(*mut u8)>,
    /// Start context (argument to start routine)
    pub start_context: *mut u8,

    // Thread ID
    /// Unique thread identifier
    pub thread_id: u32,

    // APC support
    /// APC state (contains kernel and user APC queues)
    pub apc_state: KApcState,

    /// Special APC disable count
    /// When non-zero, normal kernel APCs cannot be delivered
    pub special_apc_disable: i16,

    /// APC disable count (kernel APCs disabled when non-zero)
    pub kernel_apc_disable: i16,

    /// Whether thread is in an alertable wait
    pub alertable: bool,

    /// Whether thread is currently processing APCs
    pub apc_queueable: bool,

    // Wait support
    /// Status returned from last wait operation
    pub wait_status: WaitStatus,

    /// Pointer to array of wait blocks for multi-object wait
    pub wait_block_list: *mut KWaitBlock,

    /// Type of wait (WaitAny or WaitAll)
    pub wait_type: WaitType,

    /// Number of objects being waited on
    pub wait_count: u8,
}

impl KThread {
    /// Create a new uninitialized thread
    pub const fn new() -> Self {
        Self {
            state: ThreadState::Initialized,
            priority: 8, // Default to normal priority
            base_priority: 8,
            quantum: constants::THREAD_QUANTUM,
            priority_decrement: 0,
            saturation: 0,
            wait_list_entry: ListEntry::new(),
            thread_list_entry: ListEntry::new(),
            kernel_stack: ptr::null_mut(),
            stack_base: ptr::null_mut(),
            stack_limit: ptr::null_mut(),
            context: ThreadContext::new(),
            process: ptr::null_mut(),
            start_routine: None,
            start_context: ptr::null_mut(),
            thread_id: 0,
            apc_state: KApcState::new(),
            special_apc_disable: 0,
            kernel_apc_disable: 0,
            alertable: false,
            apc_queueable: true,
            wait_status: WaitStatus::Object0,
            wait_block_list: ptr::null_mut(),
            wait_type: WaitType::WaitAny,
            wait_count: 0,
        }
    }

    /// Initialize a thread with a stack and entry point
    ///
    /// # Safety
    /// - `stack_base` must point to a valid stack region
    /// - `stack_size` must be the actual size of the stack
    pub unsafe fn init(
        &mut self,
        thread_id: u32,
        stack_base: *mut u8,
        stack_size: usize,
        start_routine: fn(*mut u8),
        start_context: *mut u8,
        priority: i8,
        process: *mut KProcess,
    ) {
        self.thread_id = thread_id;
        self.stack_base = stack_base;
        self.stack_limit = stack_base.sub(stack_size);
        self.start_routine = Some(start_routine);
        self.start_context = start_context;
        self.priority = priority;
        self.base_priority = priority;
        self.quantum = constants::THREAD_QUANTUM;
        self.process = process;
        self.state = ThreadState::Initialized;

        // Initialize APC state
        self.apc_state.init(process);
        self.special_apc_disable = 0;
        self.kernel_apc_disable = 0;
        self.alertable = false;
        self.apc_queueable = true;

        // Set up initial stack frame for first context switch
        // Stack grows downward, so we start from stack_base and go down
        let initial_sp = stack_base.sub(core::mem::size_of::<ThreadContext>());
        self.kernel_stack = initial_sp;

        // Set up context so first "return" from context switch enters start routine
        self.context.rip = thread_entry_trampoline as u64;
        self.context.rflags = 0x202; // Interrupts enabled
    }

    /// Check if this is a realtime priority thread
    #[inline]
    pub fn is_realtime(&self) -> bool {
        self.priority >= constants::LOW_REALTIME_PRIORITY
    }
}

impl Default for KThread {
    fn default() -> Self {
        Self::new()
    }
}

/// Trampoline function for new threads
///
/// This is the initial "return address" set up for new threads.
/// It calls the thread's start routine and then terminates the thread.
extern "C" fn thread_entry_trampoline() {
    // Get current thread from PRCB
    // For now, we'll implement this when we have the PRCB
    // The current thread pointer will be in a known location

    // TODO: Get current thread and call its start routine
    // let thread = get_current_thread();
    // if let Some(routine) = thread.start_routine {
    //     routine(thread.start_context);
    // }
    // terminate_current_thread();

    // Placeholder: just halt
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}

// Static thread pool (no heap allocator)
static mut THREAD_POOL: [KThread; constants::MAX_THREADS] = {
    const INIT: KThread = KThread::new();
    [INIT; constants::MAX_THREADS]
};

static mut THREAD_POOL_BITMAP: u32 = 0;

/// Allocate a thread from the static pool
///
/// # Safety
/// Must be called with interrupts disabled or proper synchronization
pub unsafe fn allocate_thread() -> Option<*mut KThread> {
    for i in 0..constants::MAX_THREADS {
        if THREAD_POOL_BITMAP & (1 << i) == 0 {
            THREAD_POOL_BITMAP |= 1 << i;
            let thread = &mut THREAD_POOL[i] as *mut KThread;
            (*thread) = KThread::new();
            return Some(thread);
        }
    }
    None
}

/// Free a thread back to the pool
///
/// # Safety
/// - Thread must have been allocated from this pool
/// - Thread must not be in any list or currently running
pub unsafe fn free_thread(thread: *mut KThread) {
    let index = (thread as usize - THREAD_POOL.as_ptr() as usize) / core::mem::size_of::<KThread>();
    if index < constants::MAX_THREADS {
        THREAD_POOL_BITMAP &= !(1 << index);
    }
}
