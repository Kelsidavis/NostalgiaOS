//! Cancel-Safe Queue (CSQ) API
//!
//! The Cancel-Safe Queue provides a framework for drivers to implement
//! IRP queuing with safe cancellation handling. It eliminates the complex
//! synchronization requirements typically needed for IRP cancellation.
//!
//! # Design
//!
//! The CSQ uses a set of driver-provided callbacks to:
//! - Insert IRPs into a queue
//! - Remove IRPs from the queue
//! - Peek at queued IRPs
//! - Acquire/release a lock
//! - Complete canceled IRPs
//!
//! The CSQ handles all the synchronization between IRP completion,
//! cancellation, and queue manipulation.
//!
//! # Usage
//!
//! ```ignore
//! // Initialize CSQ
//! let mut csq = IoCsq::new();
//! csq.init(insert_fn, remove_fn, peek_fn, lock_fn, unlock_fn, complete_fn);
//!
//! // Insert IRP
//! csq.insert_irp(irp, context);
//!
//! // Remove IRP
//! if let Some(irp) = csq.remove_irp(context) {
//!     // Process IRP
//! }
//! ```
//!
//! # NT Functions
//!
//! - `IoCsqInitialize` - Initialize a cancel-safe queue
//! - `IoCsqInitializeEx` - Initialize with extended features
//! - `IoCsqInsertIrp` - Insert IRP into queue
//! - `IoCsqInsertIrpEx` - Insert with context
//! - `IoCsqRemoveIrp` - Remove specific IRP
//! - `IoCsqRemoveNextIrp` - Remove next matching IRP

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

/// CSQ type identifier
pub const IO_TYPE_CSQ: u32 = 0x00000001;
pub const IO_TYPE_CSQ_EX: u32 = 0x00000002;
pub const IO_TYPE_CSQ_IRP_CONTEXT: u32 = 0x00000003;

/// IRP placeholder (simplified - real implementation would use actual IRP)
pub type Irp = usize;

/// IRQL level placeholder
pub type Irql = u8;

/// CSQ insert callback
pub type CsqInsertIrpFn = fn(csq: &mut IoCsq, irp: Irp);

/// CSQ insert callback with context (extended version)
pub type CsqInsertIrpExFn = fn(csq: &mut IoCsq, irp: Irp, context: usize) -> i32;

/// CSQ remove callback
pub type CsqRemoveIrpFn = fn(csq: &mut IoCsq, irp: Irp);

/// CSQ peek callback
pub type CsqPeekNextIrpFn = fn(csq: &mut IoCsq, irp: Option<Irp>, context: usize) -> Option<Irp>;

/// CSQ acquire lock callback
pub type CsqAcquireLockFn = fn(csq: &mut IoCsq) -> Irql;

/// CSQ release lock callback
pub type CsqReleaseLockFn = fn(csq: &mut IoCsq, irql: Irql);

/// CSQ complete canceled IRP callback
pub type CsqCompleteCanceledIrpFn = fn(csq: &mut IoCsq, irp: Irp);

/// Cancel-Safe Queue IRP Context
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoCsqIrpContext {
    /// Type identifier (IO_TYPE_CSQ_IRP_CONTEXT)
    pub context_type: u32,
    /// Associated IRP
    pub irp: Irp,
    /// Parent CSQ
    pub csq: *mut IoCsq,
}

impl Default for IoCsqIrpContext {
    fn default() -> Self {
        Self {
            context_type: IO_TYPE_CSQ_IRP_CONTEXT,
            irp: 0,
            csq: ptr::null_mut(),
        }
    }
}

/// Cancel-Safe Queue structure
#[repr(C)]
pub struct IoCsq {
    /// Type identifier
    pub csq_type: u32,
    /// Insert IRP callback
    insert_irp: Option<CsqInsertIrpFn>,
    /// Insert IRP extended callback
    insert_irp_ex: Option<CsqInsertIrpExFn>,
    /// Remove IRP callback
    remove_irp: Option<CsqRemoveIrpFn>,
    /// Peek next IRP callback
    peek_next_irp: Option<CsqPeekNextIrpFn>,
    /// Acquire lock callback
    acquire_lock: Option<CsqAcquireLockFn>,
    /// Release lock callback
    release_lock: Option<CsqReleaseLockFn>,
    /// Complete canceled IRP callback
    complete_canceled_irp: Option<CsqCompleteCanceledIrpFn>,
    /// Reserved pointer (used internally)
    pub reserve_pointer: usize,
}

impl Default for IoCsq {
    fn default() -> Self {
        Self::new()
    }
}

impl IoCsq {
    /// Create a new uninitialized CSQ
    pub const fn new() -> Self {
        Self {
            csq_type: IO_TYPE_CSQ,
            insert_irp: None,
            insert_irp_ex: None,
            remove_irp: None,
            peek_next_irp: None,
            acquire_lock: None,
            release_lock: None,
            complete_canceled_irp: None,
            reserve_pointer: 0,
        }
    }

    /// Initialize the cancel-safe queue (IoCsqInitialize)
    ///
    /// # Arguments
    /// * `insert_irp` - Callback to insert IRP into queue
    /// * `remove_irp` - Callback to remove IRP from queue
    /// * `peek_next_irp` - Callback to peek at next IRP
    /// * `acquire_lock` - Callback to acquire queue lock
    /// * `release_lock` - Callback to release queue lock
    /// * `complete_canceled_irp` - Callback to complete canceled IRP
    ///
    /// # Returns
    /// STATUS_SUCCESS (0) on success
    pub fn init(
        &mut self,
        insert_irp: CsqInsertIrpFn,
        remove_irp: CsqRemoveIrpFn,
        peek_next_irp: CsqPeekNextIrpFn,
        acquire_lock: CsqAcquireLockFn,
        release_lock: CsqReleaseLockFn,
        complete_canceled_irp: CsqCompleteCanceledIrpFn,
    ) -> i32 {
        self.csq_type = IO_TYPE_CSQ;
        self.insert_irp = Some(insert_irp);
        self.insert_irp_ex = None;
        self.remove_irp = Some(remove_irp);
        self.peek_next_irp = Some(peek_next_irp);
        self.acquire_lock = Some(acquire_lock);
        self.release_lock = Some(release_lock);
        self.complete_canceled_irp = Some(complete_canceled_irp);
        self.reserve_pointer = 0;

        CSQ_INIT_COUNT.fetch_add(1, Ordering::Relaxed);
        0 // STATUS_SUCCESS
    }

    /// Initialize the cancel-safe queue with extended features (IoCsqInitializeEx)
    ///
    /// The extended version uses a different insert callback that can return
    /// a status code and accepts a context parameter.
    pub fn init_ex(
        &mut self,
        insert_irp_ex: CsqInsertIrpExFn,
        remove_irp: CsqRemoveIrpFn,
        peek_next_irp: CsqPeekNextIrpFn,
        acquire_lock: CsqAcquireLockFn,
        release_lock: CsqReleaseLockFn,
        complete_canceled_irp: CsqCompleteCanceledIrpFn,
    ) -> i32 {
        self.csq_type = IO_TYPE_CSQ_EX;
        self.insert_irp = None;
        self.insert_irp_ex = Some(insert_irp_ex);
        self.remove_irp = Some(remove_irp);
        self.peek_next_irp = Some(peek_next_irp);
        self.acquire_lock = Some(acquire_lock);
        self.release_lock = Some(release_lock);
        self.complete_canceled_irp = Some(complete_canceled_irp);
        self.reserve_pointer = 0;

        CSQ_INIT_COUNT.fetch_add(1, Ordering::Relaxed);
        0 // STATUS_SUCCESS
    }

    /// Insert an IRP into the queue (IoCsqInsertIrp)
    ///
    /// The IRP will be associated with this CSQ for cancellation handling.
    ///
    /// # Arguments
    /// * `irp` - The IRP to insert
    /// * `context` - Optional context to associate with the IRP
    pub fn insert_irp(&mut self, irp: Irp, context: Option<&mut IoCsqIrpContext>) {
        // Set up context if provided
        if let Some(ctx) = context {
            ctx.context_type = IO_TYPE_CSQ_IRP_CONTEXT;
            ctx.irp = irp;
            ctx.csq = self;
        }

        // Acquire lock
        let irql = if let Some(acquire) = self.acquire_lock {
            acquire(self)
        } else {
            0
        };

        // Insert the IRP
        if let Some(insert) = self.insert_irp {
            insert(self, irp);
        }

        // Release lock
        if let Some(release) = self.release_lock {
            release(self, irql);
        }

        CSQ_INSERT_COUNT.fetch_add(1, Ordering::Relaxed);
    }

    /// Insert an IRP with extended features (IoCsqInsertIrpEx)
    ///
    /// # Arguments
    /// * `irp` - The IRP to insert
    /// * `context` - Optional context to associate with the IRP
    /// * `insert_context` - Context passed to insert callback
    ///
    /// # Returns
    /// Status from insert callback
    pub fn insert_irp_ex(
        &mut self,
        irp: Irp,
        context: Option<&mut IoCsqIrpContext>,
        insert_context: usize,
    ) -> i32 {
        // Set up context if provided
        if let Some(ctx) = context {
            ctx.context_type = IO_TYPE_CSQ_IRP_CONTEXT;
            ctx.irp = irp;
            ctx.csq = self;
        }

        // Acquire lock
        let irql = if let Some(acquire) = self.acquire_lock {
            acquire(self)
        } else {
            0
        };

        // Insert the IRP
        let status = if let Some(insert_ex) = self.insert_irp_ex {
            insert_ex(self, irp, insert_context)
        } else if let Some(insert) = self.insert_irp {
            insert(self, irp);
            0
        } else {
            -1073741823 // STATUS_UNSUCCESSFUL
        };

        // Release lock
        if let Some(release) = self.release_lock {
            release(self, irql);
        }

        if status == 0 {
            CSQ_INSERT_COUNT.fetch_add(1, Ordering::Relaxed);
        }

        status
    }

    /// Remove a specific IRP from the queue (IoCsqRemoveIrp)
    ///
    /// # Arguments
    /// * `context` - The context associated with the IRP to remove
    ///
    /// # Returns
    /// The removed IRP, or None if not found
    pub fn remove_irp(&mut self, context: &mut IoCsqIrpContext) -> Option<Irp> {
        // Acquire lock
        let irql = if let Some(acquire) = self.acquire_lock {
            acquire(self)
        } else {
            0
        };

        // Get the IRP from context
        let irp = context.irp;

        if irp == 0 {
            // IRP already removed (possibly canceled)
            if let Some(release) = self.release_lock {
                release(self, irql);
            }
            return None;
        }

        // Remove the IRP
        if let Some(remove) = self.remove_irp {
            remove(self, irp);
        }

        // Clear the context
        context.irp = 0;

        // Release lock
        if let Some(release) = self.release_lock {
            release(self, irql);
        }

        CSQ_REMOVE_COUNT.fetch_add(1, Ordering::Relaxed);
        Some(irp)
    }

    /// Remove the next matching IRP from the queue (IoCsqRemoveNextIrp)
    ///
    /// # Arguments
    /// * `peek_context` - Context for matching (driver-defined)
    ///
    /// # Returns
    /// The removed IRP, or None if no matching IRP found
    pub fn remove_next_irp(&mut self, peek_context: usize) -> Option<Irp> {
        // Acquire lock
        let irql = if let Some(acquire) = self.acquire_lock {
            acquire(self)
        } else {
            0
        };

        // Peek for the next IRP
        let irp = if let Some(peek) = self.peek_next_irp {
            peek(self, None, peek_context)
        } else {
            None
        };

        // Remove it if found
        if let Some(found_irp) = irp {
            if let Some(remove) = self.remove_irp {
                remove(self, found_irp);
            }
        }

        // Release lock
        if let Some(release) = self.release_lock {
            release(self, irql);
        }

        if irp.is_some() {
            CSQ_REMOVE_COUNT.fetch_add(1, Ordering::Relaxed);
        }

        irp
    }

    /// Complete a canceled IRP
    ///
    /// Called by the cancel routine to complete an IRP that was canceled.
    pub fn complete_canceled(&mut self, irp: Irp) {
        if let Some(complete) = self.complete_canceled_irp {
            complete(self, irp);
        }
        CSQ_CANCEL_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// Statistics
// ============================================================================

static CSQ_INIT_COUNT: AtomicU32 = AtomicU32::new(0);
static CSQ_INSERT_COUNT: AtomicU32 = AtomicU32::new(0);
static CSQ_REMOVE_COUNT: AtomicU32 = AtomicU32::new(0);
static CSQ_CANCEL_COUNT: AtomicU32 = AtomicU32::new(0);

/// CSQ statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct CsqStats {
    /// Number of CSQs initialized
    pub init_count: u32,
    /// Number of IRPs inserted
    pub insert_count: u32,
    /// Number of IRPs removed
    pub remove_count: u32,
    /// Number of IRPs canceled
    pub cancel_count: u32,
}

/// Get CSQ statistics
pub fn get_csq_stats() -> CsqStats {
    CsqStats {
        init_count: CSQ_INIT_COUNT.load(Ordering::Relaxed),
        insert_count: CSQ_INSERT_COUNT.load(Ordering::Relaxed),
        remove_count: CSQ_REMOVE_COUNT.load(Ordering::Relaxed),
        cancel_count: CSQ_CANCEL_COUNT.load(Ordering::Relaxed),
    }
}

/// Reset CSQ statistics
pub fn reset_csq_stats() {
    CSQ_INIT_COUNT.store(0, Ordering::Relaxed);
    CSQ_INSERT_COUNT.store(0, Ordering::Relaxed);
    CSQ_REMOVE_COUNT.store(0, Ordering::Relaxed);
    CSQ_CANCEL_COUNT.store(0, Ordering::Relaxed);
}

// ============================================================================
// Standalone Functions (NT API compatibility)
// ============================================================================

/// Initialize a cancel-safe queue (IoCsqInitialize)
pub fn io_csq_initialize(
    csq: &mut IoCsq,
    insert_irp: CsqInsertIrpFn,
    remove_irp: CsqRemoveIrpFn,
    peek_next_irp: CsqPeekNextIrpFn,
    acquire_lock: CsqAcquireLockFn,
    release_lock: CsqReleaseLockFn,
    complete_canceled_irp: CsqCompleteCanceledIrpFn,
) -> i32 {
    csq.init(insert_irp, remove_irp, peek_next_irp, acquire_lock, release_lock, complete_canceled_irp)
}

/// Initialize a cancel-safe queue with extended features (IoCsqInitializeEx)
pub fn io_csq_initialize_ex(
    csq: &mut IoCsq,
    insert_irp_ex: CsqInsertIrpExFn,
    remove_irp: CsqRemoveIrpFn,
    peek_next_irp: CsqPeekNextIrpFn,
    acquire_lock: CsqAcquireLockFn,
    release_lock: CsqReleaseLockFn,
    complete_canceled_irp: CsqCompleteCanceledIrpFn,
) -> i32 {
    csq.init_ex(insert_irp_ex, remove_irp, peek_next_irp, acquire_lock, release_lock, complete_canceled_irp)
}

/// Insert an IRP into a cancel-safe queue (IoCsqInsertIrp)
pub fn io_csq_insert_irp(
    csq: &mut IoCsq,
    irp: Irp,
    context: Option<&mut IoCsqIrpContext>,
) {
    csq.insert_irp(irp, context);
}

/// Insert an IRP with extended features (IoCsqInsertIrpEx)
pub fn io_csq_insert_irp_ex(
    csq: &mut IoCsq,
    irp: Irp,
    context: Option<&mut IoCsqIrpContext>,
    insert_context: usize,
) -> i32 {
    csq.insert_irp_ex(irp, context, insert_context)
}

/// Remove a specific IRP from a cancel-safe queue (IoCsqRemoveIrp)
pub fn io_csq_remove_irp(
    csq: &mut IoCsq,
    context: &mut IoCsqIrpContext,
) -> Option<Irp> {
    csq.remove_irp(context)
}

/// Remove the next matching IRP (IoCsqRemoveNextIrp)
pub fn io_csq_remove_next_irp(
    csq: &mut IoCsq,
    peek_context: usize,
) -> Option<Irp> {
    csq.remove_next_irp(peek_context)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize CSQ support
pub fn init() {
    CSQ_INIT_COUNT.store(0, Ordering::Release);
    CSQ_INSERT_COUNT.store(0, Ordering::Release);
    CSQ_REMOVE_COUNT.store(0, Ordering::Release);
    CSQ_CANCEL_COUNT.store(0, Ordering::Release);

    crate::serial_println!("[IO] Cancel-Safe Queue support initialized");
}
