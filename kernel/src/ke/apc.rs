//! Asynchronous Procedure Calls (APC)
//!
//! APCs allow code to execute asynchronously in the context of a specific thread.
//! They are queued to a thread and delivered when certain conditions are met.
//!
//! # APC Types
//!
//! - **Kernel APC**: Executes at APC_LEVEL in kernel mode
//!   - Special kernel APCs: Higher priority, can interrupt normal kernel APCs
//!   - Normal kernel APCs: Execute when thread is not in critical region
//!
//! - **User APC**: Executes in user mode when thread returns from kernel
//!   in an alertable wait state
//!
//! # NT Compatibility
//! Equivalent to NT's KAPC / KeInitializeApc / KeInsertQueueApc

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use super::list::ListEntry;
use super::thread::KThread;

/// APC environment (which queue the APC is in)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApcEnvironment {
    /// Original environment when APC was created
    OriginalApcEnvironment = 0,
    /// Attached process environment
    AttachedApcEnvironment = 1,
    /// Current environment
    CurrentApcEnvironment = 2,
}

/// APC mode (kernel or user)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApcMode {
    /// Kernel mode APC
    KernelMode = 0,
    /// User mode APC
    UserMode = 1,
}

/// Kernel APC routine signature
///
/// Called at APC_LEVEL when the APC is delivered.
///
/// # Arguments
/// * `apc` - Pointer to the APC being delivered
/// * `normal_routine` - Address of normal routine (can be modified)
/// * `normal_context` - Context for normal routine (can be modified)
/// * `system_argument1` - First system argument (can be modified)
/// * `system_argument2` - Second system argument (can be modified)
pub type KernelRoutine = fn(
    apc: *mut KApc,
    normal_routine: *mut Option<NormalRoutine>,
    normal_context: *mut usize,
    system_argument1: *mut usize,
    system_argument2: *mut usize,
);

/// Normal APC routine signature
///
/// Called after kernel routine completes (for normal kernel APCs)
/// or in user mode (for user APCs).
///
/// # Arguments
/// * `normal_context` - Context passed when APC was queued
/// * `system_argument1` - First system argument
/// * `system_argument2` - Second system argument
pub type NormalRoutine = fn(
    normal_context: usize,
    system_argument1: usize,
    system_argument2: usize,
);

/// Rundown routine signature
///
/// Called if the thread terminates before the APC can be delivered.
///
/// # Arguments
/// * `apc` - Pointer to the APC being run down
pub type RundownRoutine = fn(apc: *mut KApc);

/// Kernel APC object
///
/// Equivalent to NT's KAPC structure
#[repr(C)]
pub struct KApc {
    /// Entry in the thread's APC queue
    apc_list_entry: UnsafeCell<ListEntry>,

    /// Target thread for this APC
    thread: UnsafeCell<*mut KThread>,

    /// Kernel routine (always called first at APC_LEVEL)
    kernel_routine: UnsafeCell<Option<KernelRoutine>>,

    /// Rundown routine (called if thread terminates)
    rundown_routine: UnsafeCell<Option<RundownRoutine>>,

    /// Normal routine (called after kernel routine)
    normal_routine: UnsafeCell<Option<NormalRoutine>>,

    /// Normal context passed to normal routine
    normal_context: UnsafeCell<usize>,

    /// System argument 1
    system_argument1: UnsafeCell<usize>,

    /// System argument 2
    system_argument2: UnsafeCell<usize>,

    /// APC state index (which queue)
    apc_state_index: UnsafeCell<ApcEnvironment>,

    /// APC mode (kernel or user)
    apc_mode: UnsafeCell<ApcMode>,

    /// Whether this APC is currently inserted in a queue
    inserted: AtomicBool,
}

// Safety: KApc is designed for multi-threaded access with proper synchronization
unsafe impl Sync for KApc {}
unsafe impl Send for KApc {}

impl KApc {
    /// Create a new uninitialized APC
    pub const fn new() -> Self {
        Self {
            apc_list_entry: UnsafeCell::new(ListEntry::new()),
            thread: UnsafeCell::new(core::ptr::null_mut()),
            kernel_routine: UnsafeCell::new(None),
            rundown_routine: UnsafeCell::new(None),
            normal_routine: UnsafeCell::new(None),
            normal_context: UnsafeCell::new(0),
            system_argument1: UnsafeCell::new(0),
            system_argument2: UnsafeCell::new(0),
            apc_state_index: UnsafeCell::new(ApcEnvironment::OriginalApcEnvironment),
            apc_mode: UnsafeCell::new(ApcMode::KernelMode),
            inserted: AtomicBool::new(false),
        }
    }

    /// Initialize a kernel APC
    ///
    /// Equivalent to KeInitializeApc for kernel mode APCs.
    ///
    /// # Arguments
    /// * `thread` - Target thread
    /// * `kernel_routine` - Routine called at APC_LEVEL
    /// * `rundown_routine` - Optional routine called on thread termination
    /// * `normal_routine` - Optional routine called after kernel routine
    /// * `apc_mode` - KernelMode or UserMode
    /// * `normal_context` - Context for normal routine
    ///
    /// # Safety
    /// Thread pointer must be valid for the lifetime of this APC
    pub unsafe fn init(
        &self,
        thread: *mut KThread,
        kernel_routine: KernelRoutine,
        rundown_routine: Option<RundownRoutine>,
        normal_routine: Option<NormalRoutine>,
        apc_mode: ApcMode,
        normal_context: usize,
    ) {
        *self.thread.get() = thread;
        *self.kernel_routine.get() = Some(kernel_routine);
        *self.rundown_routine.get() = rundown_routine;
        *self.normal_routine.get() = normal_routine;
        *self.apc_mode.get() = apc_mode;
        *self.normal_context.get() = normal_context;
        *self.apc_state_index.get() = ApcEnvironment::OriginalApcEnvironment;
        (*self.apc_list_entry.get()).init_head();
        self.inserted.store(false, Ordering::Release);
    }

    /// Initialize a special kernel APC
    ///
    /// Special kernel APCs have no normal routine and execute at higher priority.
    ///
    /// # Safety
    /// Thread pointer must be valid for the lifetime of this APC
    pub unsafe fn init_special(
        &self,
        thread: *mut KThread,
        kernel_routine: KernelRoutine,
        rundown_routine: Option<RundownRoutine>,
    ) {
        self.init(
            thread,
            kernel_routine,
            rundown_routine,
            None,
            ApcMode::KernelMode,
            0,
        );
    }

    /// Check if this APC is currently queued
    #[inline]
    pub fn is_inserted(&self) -> bool {
        self.inserted.load(Ordering::Acquire)
    }

    /// Get the target thread
    #[inline]
    pub fn thread(&self) -> *mut KThread {
        unsafe { *self.thread.get() }
    }

    /// Get the APC mode
    #[inline]
    pub fn apc_mode(&self) -> ApcMode {
        unsafe { *self.apc_mode.get() }
    }

    /// Check if this is a special kernel APC (no normal routine)
    #[inline]
    pub fn is_special(&self) -> bool {
        unsafe { (*self.normal_routine.get()).is_none() && *self.apc_mode.get() == ApcMode::KernelMode }
    }

    /// Insert this APC into its target thread's queue
    ///
    /// Equivalent to KeInsertQueueApc.
    ///
    /// # Arguments
    /// * `system_argument1` - First system argument
    /// * `system_argument2` - Second system argument
    ///
    /// # Returns
    /// true if successfully queued, false if already queued or thread is terminating
    ///
    /// # Safety
    /// Must be called with proper synchronization
    pub unsafe fn queue(&self, system_argument1: usize, system_argument2: usize) -> bool {
        // Check if already inserted
        if self.inserted.swap(true, Ordering::AcqRel) {
            return false;
        }

        *self.system_argument1.get() = system_argument1;
        *self.system_argument2.get() = system_argument2;

        let thread = *self.thread.get();
        if thread.is_null() {
            self.inserted.store(false, Ordering::Release);
            return false;
        }

        // Insert into appropriate queue based on APC type
        ki_insert_queue_apc(self, thread);

        true
    }

    /// Remove this APC from its thread's queue
    ///
    /// # Returns
    /// true if the APC was removed, false if it wasn't queued
    ///
    /// # Safety
    /// Must be called with proper synchronization
    pub unsafe fn remove(&self) -> bool {
        if !self.inserted.swap(false, Ordering::AcqRel) {
            return false;
        }

        let entry = &mut *self.apc_list_entry.get();
        entry.remove_entry();

        true
    }

    /// Deliver this APC (internal use)
    ///
    /// # Safety
    /// Must be called at appropriate IRQL with proper synchronization
    pub(crate) unsafe fn deliver(&self) {
        // Get routine parameters
        let mut normal_routine = *self.normal_routine.get();
        let mut normal_context = *self.normal_context.get();
        let mut system_argument1 = *self.system_argument1.get();
        let mut system_argument2 = *self.system_argument2.get();

        // Remove from queue
        self.remove();

        // Call kernel routine first (always)
        if let Some(kernel_routine) = *self.kernel_routine.get() {
            kernel_routine(
                self as *const _ as *mut KApc,
                &mut normal_routine,
                &mut normal_context,
                &mut system_argument1,
                &mut system_argument2,
            );
        }

        // Call normal routine if present and not cancelled by kernel routine
        if let Some(routine) = normal_routine {
            routine(normal_context, system_argument1, system_argument2);
        }
    }

    /// Run down this APC (called when thread terminates)
    ///
    /// # Safety
    /// Must be called during thread termination with proper synchronization
    pub(crate) unsafe fn rundown(&self) {
        self.remove();

        if let Some(rundown_routine) = *self.rundown_routine.get() {
            rundown_routine(self as *const _ as *mut KApc);
        }
    }
}

impl Default for KApc {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// APC State in Thread
// ============================================================================

/// APC state stored in each thread
///
/// Contains the APC queues and related flags.
#[repr(C)]
pub struct KApcState {
    /// List of kernel APCs pending delivery
    pub apc_list_head: [ListEntry; 2], // [KernelMode, UserMode]

    /// Process associated with this APC state
    pub process: *mut super::process::KProcess,

    /// Kernel APC in progress flag
    pub kernel_apc_in_progress: bool,

    /// Kernel APC pending flag
    pub kernel_apc_pending: bool,

    /// User APC pending flag
    pub user_apc_pending: bool,
}

impl KApcState {
    /// Create a new APC state
    pub const fn new() -> Self {
        Self {
            apc_list_head: [ListEntry::new(), ListEntry::new()],
            process: core::ptr::null_mut(),
            kernel_apc_in_progress: false,
            kernel_apc_pending: false,
            user_apc_pending: false,
        }
    }

    /// Initialize the APC state
    pub fn init(&mut self, process: *mut super::process::KProcess) {
        self.apc_list_head[0].init_head();
        self.apc_list_head[1].init_head();
        self.process = process;
        self.kernel_apc_in_progress = false;
        self.kernel_apc_pending = false;
        self.user_apc_pending = false;
    }

    /// Check if the kernel APC queue is empty
    #[inline]
    pub fn is_kernel_apc_queue_empty(&self) -> bool {
        self.apc_list_head[ApcMode::KernelMode as usize].is_empty()
    }

    /// Check if the user APC queue is empty
    #[inline]
    pub fn is_user_apc_queue_empty(&self) -> bool {
        self.apc_list_head[ApcMode::UserMode as usize].is_empty()
    }
}

impl Default for KApcState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// APC Queue Operations
// ============================================================================

use crate::containing_record;

/// Insert an APC into the thread's queue
///
/// # Safety
/// Must be called with thread lock held
unsafe fn ki_insert_queue_apc(apc: &KApc, thread: *mut KThread) {
    let apc_state = &mut (*thread).apc_state;
    let mode = apc.apc_mode() as usize;

    let entry = &mut *apc.apc_list_entry.get();
    let queue_head = &mut apc_state.apc_list_head[mode];

    // For special kernel APCs, insert at head for priority
    // For normal APCs, insert at tail (FIFO order)
    if apc.is_special() {
        queue_head.insert_head(entry);
    } else {
        queue_head.insert_tail(entry);
    }

    // Set pending flags
    if mode == ApcMode::KernelMode as usize {
        apc_state.kernel_apc_pending = true;
    } else {
        apc_state.user_apc_pending = true;
    }

    crate::serial_println!("[APC] Queued {} APC to thread {}",
        if mode == 0 { "kernel" } else { "user" },
        (*thread).thread_id);
}

/// Deliver pending kernel APCs to the current thread
///
/// Called when returning from interrupt or lowering IRQL.
/// Delivers all pending kernel APCs in order.
///
/// # Safety
/// Must be called at APC_LEVEL or below
pub unsafe fn ki_deliver_apc(mode: ApcMode) {
    let prcb = super::prcb::get_current_prcb_mut();
    let thread = prcb.current_thread;

    if thread.is_null() {
        return;
    }

    let apc_state = &mut (*thread).apc_state;

    // Deliver kernel APCs first
    if mode == ApcMode::KernelMode || apc_state.kernel_apc_pending {
        deliver_kernel_apcs(thread);
    }

    // Deliver user APCs if requested and pending
    if mode == ApcMode::UserMode && apc_state.user_apc_pending {
        deliver_user_apcs(thread);
    }
}

/// Deliver all pending kernel APCs
unsafe fn deliver_kernel_apcs(thread: *mut KThread) {
    let apc_state = &mut (*thread).apc_state;
    let queue = &mut apc_state.apc_list_head[ApcMode::KernelMode as usize];

    // Mark that we're delivering kernel APCs
    apc_state.kernel_apc_in_progress = true;

    while !queue.is_empty() {
        let entry = queue.flink;
        let apc = containing_record!(entry, KApc, apc_list_entry);

        // Check if this is a special APC or if we can deliver normal APCs
        // (Normal kernel APCs can only be delivered when not in critical region)
        if !(*apc).is_special() && (*thread).special_apc_disable != 0 {
            break;
        }

        crate::serial_println!("[APC] Delivering kernel APC to thread {}", (*thread).thread_id);
        (*apc).deliver();
    }

    // Update pending flag
    apc_state.kernel_apc_pending = !queue.is_empty();
    apc_state.kernel_apc_in_progress = false;
}

/// Deliver pending user APCs
unsafe fn deliver_user_apcs(thread: *mut KThread) {
    let apc_state = &mut (*thread).apc_state;
    let queue = &mut apc_state.apc_list_head[ApcMode::UserMode as usize];

    // Only deliver if thread is in alertable wait
    if !(*thread).alertable {
        return;
    }

    while !queue.is_empty() {
        let entry = queue.flink;
        let apc = containing_record!(entry, KApc, apc_list_entry);

        crate::serial_println!("[APC] Delivering user APC to thread {}", (*thread).thread_id);
        (*apc).deliver();
    }

    // Update pending flag
    apc_state.user_apc_pending = !queue.is_empty();
}

/// Run down all APCs for a terminating thread
///
/// # Safety
/// Must be called during thread termination
pub unsafe fn ki_rundown_apcs(thread: *mut KThread) {
    let apc_state = &mut (*thread).apc_state;

    // Run down kernel APCs
    while !apc_state.apc_list_head[ApcMode::KernelMode as usize].is_empty() {
        let entry = apc_state.apc_list_head[ApcMode::KernelMode as usize].flink;
        let apc = containing_record!(entry, KApc, apc_list_entry);
        (*apc).rundown();
    }

    // Run down user APCs
    while !apc_state.apc_list_head[ApcMode::UserMode as usize].is_empty() {
        let entry = apc_state.apc_list_head[ApcMode::UserMode as usize].flink;
        let apc = containing_record!(entry, KApc, apc_list_entry);
        (*apc).rundown();
    }

    apc_state.kernel_apc_pending = false;
    apc_state.user_apc_pending = false;
}

/// Check if current thread has pending APCs
pub fn ki_check_apc_pending() -> bool {
    unsafe {
        let prcb = super::prcb::get_current_prcb();
        let thread = prcb.current_thread;

        if thread.is_null() {
            return false;
        }

        let apc_state = &(*thread).apc_state;
        apc_state.kernel_apc_pending || apc_state.user_apc_pending
    }
}
