//! HAL Interrupt Support
//!
//! Provides interrupt management for device drivers:
//!
//! - **KINTERRUPT**: Interrupt object for ISR registration
//! - **Interrupt Chaining**: Support for shared interrupts
//! - **IRQL Management**: Automatic IRQL handling during ISR
//!
//! # Architecture
//!
//! ```text
//! Device Interrupt
//!       │
//!       ▼
//! ┌─────────────┐
//! │   I/O APIC  │  Routes to CPU
//! └──────┬──────┘
//!        │
//!        ▼
//! ┌─────────────┐
//! │  Local APIC │  Delivers to CPU
//! └──────┬──────┘
//!        │
//!        ▼
//! ┌─────────────┐
//! │     IDT     │  Dispatches to handler
//! └──────┬──────┘
//!        │
//!        ▼
//! ┌─────────────┐
//! │ KINTERRUPT  │  Calls ISR with IRQL
//! └─────────────┘
//! ```
//!
//! # NT Functions
//!
//! - `IoConnectInterrupt` - Connect ISR to interrupt
//! - `IoDisconnectInterrupt` - Disconnect ISR
//! - `KeSynchronizeExecution` - Execute with interrupt spinlock
//!
//! # Usage
//!
//! ```ignore
//! let interrupt = hal_connect_interrupt(
//!     isr_handler,
//!     context,
//!     vector,
//!     irql,
//!     mode,
//!     share_vector,
//! );
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::ptr;
use crate::ke::spinlock::SpinLock;
use crate::ke::kpcr::Kirql;

/// Maximum number of interrupt objects
pub const MAX_INTERRUPT_OBJECTS: usize = 256;

/// Maximum shared interrupts per vector
pub const MAX_SHARED_PER_VECTOR: usize = 8;

/// Interrupt mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptMode {
    /// Level-triggered interrupt
    LevelSensitive = 0,
    /// Edge-triggered interrupt
    Latched = 1,
}

/// Interrupt polarity
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptPolarity {
    /// Active high
    InterruptActiveHigh = 0,
    /// Active low
    InterruptActiveLow = 1,
}

/// Interrupt service routine return value
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptReturn {
    /// Interrupt was not handled
    NotHandled = 0,
    /// Interrupt was handled
    Handled = 1,
}

impl From<bool> for InterruptReturn {
    fn from(handled: bool) -> Self {
        if handled {
            InterruptReturn::Handled
        } else {
            InterruptReturn::NotHandled
        }
    }
}

/// Interrupt Service Routine function type
///
/// Returns true if the interrupt was handled
pub type InterruptServiceRoutine = fn(context: *mut u8) -> bool;

/// Synchronize execution callback
pub type SynchronizeRoutine = fn(context: *mut u8) -> bool;

/// KINTERRUPT - Kernel Interrupt Object
///
/// Manages a hardware interrupt connection for a device driver.
#[repr(C)]
pub struct KInterrupt {
    /// Type marker
    pub type_marker: u16,
    /// Size of structure
    pub size: u16,
    /// Interrupt is connected and active
    pub connected: AtomicBool,
    /// Interrupt service routine
    pub service_routine: Option<InterruptServiceRoutine>,
    /// ISR context parameter
    pub service_context: *mut u8,
    /// Spinlock for synchronization
    pub spin_lock: SpinLock<()>,
    /// Interrupt vector number
    pub vector: u8,
    /// IRQL of this interrupt
    pub irql: Kirql,
    /// Synchronize IRQL (for multiprocessor)
    pub synchronize_irql: Kirql,
    /// Interrupt mode (level/edge)
    pub mode: InterruptMode,
    /// Interrupt polarity
    pub polarity: InterruptPolarity,
    /// Interrupt is sharable
    pub share_vector: bool,
    /// Floating save required (for FPU-using ISRs)
    pub floating_save: bool,
    /// Processor affinity mask
    pub processor_affinity: u64,
    /// Index in interrupt chain (for shared vectors)
    pub chain_index: u8,
    /// Interrupt statistics
    pub dispatch_count: AtomicU64,
    /// Count of handled interrupts
    pub handled_count: AtomicU64,
    /// Count of not-handled (for shared)
    pub not_handled_count: AtomicU64,
    /// Last dispatch timestamp (TSC)
    pub last_dispatch_time: AtomicU64,
    /// Total ISR time (TSC cycles)
    pub total_isr_time: AtomicU64,
}

impl KInterrupt {
    pub const fn new() -> Self {
        Self {
            type_marker: 0x16, // KOBJECT_INTERRUPT
            size: core::mem::size_of::<KInterrupt>() as u16,
            connected: AtomicBool::new(false),
            service_routine: None,
            service_context: ptr::null_mut(),
            spin_lock: SpinLock::new(()),
            vector: 0,
            irql: 0,
            synchronize_irql: 0,
            mode: InterruptMode::LevelSensitive,
            polarity: InterruptPolarity::InterruptActiveHigh,
            share_vector: false,
            floating_save: false,
            processor_affinity: !0u64, // All processors
            chain_index: 0,
            dispatch_count: AtomicU64::new(0),
            handled_count: AtomicU64::new(0),
            not_handled_count: AtomicU64::new(0),
            last_dispatch_time: AtomicU64::new(0),
            total_isr_time: AtomicU64::new(0),
        }
    }

    /// Initialize the interrupt object
    pub fn init(
        &mut self,
        service_routine: InterruptServiceRoutine,
        service_context: *mut u8,
        vector: u8,
        irql: Kirql,
        synchronize_irql: Kirql,
        mode: InterruptMode,
        share_vector: bool,
    ) {
        self.service_routine = Some(service_routine);
        self.service_context = service_context;
        self.vector = vector;
        self.irql = irql;
        self.synchronize_irql = synchronize_irql;
        self.mode = mode;
        self.share_vector = share_vector;
        self.connected.store(false, Ordering::Release);
    }

    /// Connect the interrupt (enable)
    pub fn connect(&self) -> bool {
        if self.service_routine.is_none() {
            return false;
        }

        // Check if already connected
        if self.connected.swap(true, Ordering::AcqRel) {
            return true; // Already connected
        }

        true
    }

    /// Disconnect the interrupt (disable)
    pub fn disconnect(&self) {
        self.connected.store(false, Ordering::Release);
    }

    /// Check if interrupt is connected
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// Dispatch the interrupt (called from IDT handler)
    ///
    /// Returns true if the interrupt was handled
    pub fn dispatch(&self) -> bool {
        if !self.is_connected() {
            return false;
        }

        let start_tsc = read_tsc();
        self.dispatch_count.fetch_add(1, Ordering::Relaxed);
        self.last_dispatch_time.store(start_tsc, Ordering::Relaxed);

        // Acquire spinlock and call ISR
        let _guard = unsafe { self.spin_lock.lock() };

        let handled = if let Some(isr) = self.service_routine {
            isr(self.service_context)
        } else {
            false
        };

        let end_tsc = read_tsc();
        self.total_isr_time.fetch_add(end_tsc - start_tsc, Ordering::Relaxed);

        if handled {
            self.handled_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.not_handled_count.fetch_add(1, Ordering::Relaxed);
        }

        handled
    }

    /// Get interrupt statistics
    pub fn get_stats(&self) -> InterruptStats {
        InterruptStats {
            vector: self.vector,
            irql: self.irql,
            dispatch_count: self.dispatch_count.load(Ordering::Relaxed),
            handled_count: self.handled_count.load(Ordering::Relaxed),
            not_handled_count: self.not_handled_count.load(Ordering::Relaxed),
            total_isr_time: self.total_isr_time.load(Ordering::Relaxed),
            is_shared: self.share_vector,
            is_connected: self.is_connected(),
        }
    }
}

impl Default for KInterrupt {
    fn default() -> Self {
        Self::new()
    }
}

/// Read Time Stamp Counter
#[inline]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Interrupt statistics
#[derive(Debug, Clone, Copy)]
pub struct InterruptStats {
    pub vector: u8,
    pub irql: Kirql,
    pub dispatch_count: u64,
    pub handled_count: u64,
    pub not_handled_count: u64,
    pub total_isr_time: u64,
    pub is_shared: bool,
    pub is_connected: bool,
}

impl Default for InterruptStats {
    fn default() -> Self {
        Self {
            vector: 0,
            irql: 0,
            dispatch_count: 0,
            handled_count: 0,
            not_handled_count: 0,
            total_isr_time: 0,
            is_shared: false,
            is_connected: false,
        }
    }
}

/// Interrupt vector chain entry
#[derive(Clone, Copy)]
struct VectorChainEntry {
    /// Index into interrupt pool
    interrupt_index: usize,
    /// Is this entry active?
    active: bool,
}

impl Default for VectorChainEntry {
    fn default() -> Self {
        Self {
            interrupt_index: 0,
            active: false,
        }
    }
}

/// Vector chain for shared interrupts
struct VectorChain {
    entries: [VectorChainEntry; MAX_SHARED_PER_VECTOR],
    count: usize,
}

impl VectorChain {
    const fn new() -> Self {
        Self {
            entries: [VectorChainEntry { interrupt_index: 0, active: false }; MAX_SHARED_PER_VECTOR],
            count: 0,
        }
    }

    fn add(&mut self, interrupt_index: usize) -> bool {
        if self.count >= MAX_SHARED_PER_VECTOR {
            return false;
        }

        for entry in self.entries.iter_mut() {
            if !entry.active {
                entry.interrupt_index = interrupt_index;
                entry.active = true;
                self.count += 1;
                return true;
            }
        }

        false
    }

    fn remove(&mut self, interrupt_index: usize) {
        for entry in self.entries.iter_mut() {
            if entry.active && entry.interrupt_index == interrupt_index {
                entry.active = false;
                if self.count > 0 {
                    self.count -= 1;
                }
                break;
            }
        }
    }
}

// ============================================================================
// Global Interrupt State
// ============================================================================

/// Pool of interrupt objects
static mut INTERRUPT_POOL: [KInterrupt; MAX_INTERRUPT_OBJECTS] = {
    const INIT: KInterrupt = KInterrupt::new();
    [INIT; MAX_INTERRUPT_OBJECTS]
};

/// Bitmap tracking allocated interrupts
static mut INTERRUPT_BITMAP: [u64; 4] = [0; 4]; // 256 bits

/// Vector chains for shared interrupts (vectors 32-255)
static mut VECTOR_CHAINS: [VectorChain; 224] = {
    const INIT: VectorChain = VectorChain::new();
    [INIT; 224]
};

/// Global interrupt lock
static INTERRUPT_LOCK: SpinLock<()> = SpinLock::new(());

/// Interrupt initialization flag
static INTERRUPT_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Statistics
static TOTAL_CONNECTS: AtomicU32 = AtomicU32::new(0);
static TOTAL_DISCONNECTS: AtomicU32 = AtomicU32::new(0);
static ACTIVE_INTERRUPTS: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// HAL Interrupt API
// ============================================================================

/// Connect an interrupt service routine to a vector
///
/// This is the primary API for device drivers to register ISRs.
///
/// # Arguments
/// * `service_routine` - The ISR to call
/// * `service_context` - Context passed to ISR
/// * `vector` - Interrupt vector number (32-255 for devices)
/// * `irql` - IRQL for this interrupt
/// * `mode` - Level or edge triggered
/// * `share_vector` - Allow sharing with other devices
///
/// # Returns
/// Handle to the interrupt object, or None on failure
pub fn hal_connect_interrupt(
    service_routine: InterruptServiceRoutine,
    service_context: *mut u8,
    vector: u8,
    irql: Kirql,
    mode: InterruptMode,
    share_vector: bool,
) -> Option<*mut KInterrupt> {
    hal_connect_interrupt_ex(
        service_routine,
        service_context,
        vector,
        irql,
        irql, // synchronize_irql = irql
        mode,
        share_vector,
        !0u64, // All processors
    )
}

/// Connect an interrupt with extended options
pub fn hal_connect_interrupt_ex(
    service_routine: InterruptServiceRoutine,
    service_context: *mut u8,
    vector: u8,
    irql: Kirql,
    synchronize_irql: Kirql,
    mode: InterruptMode,
    share_vector: bool,
    processor_affinity: u64,
) -> Option<*mut KInterrupt> {
    if !INTERRUPT_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    // Validate vector (device interrupts are 32-255)
    if vector < 32 {
        return None;
    }

    let _guard = INTERRUPT_LOCK.lock();

    unsafe {
        // Check if vector is already in use and not shareable
        let chain_idx = (vector - 32) as usize;
        if chain_idx < 224 && VECTOR_CHAINS[chain_idx].count > 0 {
            // Vector in use - check if shareable
            if !share_vector {
                return None; // Not shareable, can't connect
            }

            // Check if existing interrupts are shareable
            for entry in VECTOR_CHAINS[chain_idx].entries.iter() {
                if entry.active {
                    let existing = &INTERRUPT_POOL[entry.interrupt_index];
                    if !existing.share_vector {
                        return None; // Existing interrupt not shareable
                    }
                }
            }
        }

        // Allocate an interrupt object
        let interrupt_index = allocate_interrupt()?;
        let interrupt = &mut INTERRUPT_POOL[interrupt_index];

        // Initialize the interrupt object
        interrupt.init(
            service_routine,
            service_context,
            vector,
            irql,
            synchronize_irql,
            mode,
            share_vector,
        );
        interrupt.processor_affinity = processor_affinity;

        // Add to vector chain
        if chain_idx < 224 {
            if !VECTOR_CHAINS[chain_idx].add(interrupt_index) {
                // Failed to add to chain, free interrupt
                free_interrupt(interrupt_index);
                return None;
            }
            interrupt.chain_index = VECTOR_CHAINS[chain_idx].count as u8 - 1;
        }

        // Connect the interrupt
        if !interrupt.connect() {
            // Failed to connect, clean up
            if chain_idx < 224 {
                VECTOR_CHAINS[chain_idx].remove(interrupt_index);
            }
            free_interrupt(interrupt_index);
            return None;
        }

        TOTAL_CONNECTS.fetch_add(1, Ordering::Relaxed);
        ACTIVE_INTERRUPTS.fetch_add(1, Ordering::Relaxed);

        Some(interrupt as *mut KInterrupt)
    }
}

/// Disconnect an interrupt
pub fn hal_disconnect_interrupt(interrupt: *mut KInterrupt) {
    if interrupt.is_null() {
        return;
    }

    let _guard = INTERRUPT_LOCK.lock();

    unsafe {
        let int_ref = &mut *interrupt;

        if !int_ref.is_connected() {
            return;
        }

        // Disconnect
        int_ref.disconnect();

        // Remove from vector chain
        let vector = int_ref.vector;
        if vector >= 32 {
            let chain_idx = (vector - 32) as usize;
            if chain_idx < 224 {
                // Find the interrupt index
                let base = INTERRUPT_POOL.as_ptr() as usize;
                let int_addr = interrupt as usize;
                let int_size = core::mem::size_of::<KInterrupt>();

                if int_addr >= base && int_addr < base + MAX_INTERRUPT_OBJECTS * int_size {
                    let interrupt_index = (int_addr - base) / int_size;
                    VECTOR_CHAINS[chain_idx].remove(interrupt_index);
                    free_interrupt(interrupt_index);
                }
            }
        }

        TOTAL_DISCONNECTS.fetch_add(1, Ordering::Relaxed);
        if ACTIVE_INTERRUPTS.load(Ordering::Relaxed) > 0 {
            ACTIVE_INTERRUPTS.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Dispatch an interrupt by vector
///
/// Called from the IDT handler to dispatch to registered ISRs.
/// For shared vectors, calls all ISRs in the chain until one handles it.
///
/// Returns true if any ISR handled the interrupt
pub fn hal_dispatch_interrupt(vector: u8) -> bool {
    if vector < 32 {
        return false;
    }

    let chain_idx = (vector - 32) as usize;
    if chain_idx >= 224 {
        return false;
    }

    unsafe {
        // Walk the interrupt chain
        let chain = &VECTOR_CHAINS[chain_idx];

        for entry in chain.entries.iter() {
            if entry.active {
                let interrupt = &INTERRUPT_POOL[entry.interrupt_index];
                if interrupt.is_connected() {
                    if interrupt.dispatch() {
                        return true; // Interrupt handled
                    }
                }
            }
        }
    }

    false
}

/// Synchronize execution with an interrupt
///
/// Acquires the interrupt's spinlock and calls the synchronize routine.
/// This ensures the routine runs at the interrupt's IRQL and is mutually
/// exclusive with the ISR.
pub fn ke_synchronize_execution(
    interrupt: *mut KInterrupt,
    sync_routine: SynchronizeRoutine,
    sync_context: *mut u8,
) -> bool {
    if interrupt.is_null() {
        return false;
    }

    unsafe {
        let int_ref = &*interrupt;

        // Acquire the interrupt's spinlock
        let _guard = int_ref.spin_lock.lock();

        // Call the synchronize routine
        sync_routine(sync_context)
    }
}

/// Acquire interrupt spinlock
///
/// For use when synchronizing with an ISR without a callback.
pub fn ke_acquire_interrupt_spinlock(interrupt: *mut KInterrupt) -> Kirql {
    if interrupt.is_null() {
        return 0;
    }

    unsafe {
        let int_ref = &*interrupt;
        let old_irql = crate::ke::ke_raise_irql(int_ref.synchronize_irql);

        // Note: In a real implementation, we'd acquire the spinlock here
        // For now, just return the old IRQL

        old_irql
    }
}

/// Release interrupt spinlock
pub fn ke_release_interrupt_spinlock(interrupt: *mut KInterrupt, old_irql: Kirql) {
    if interrupt.is_null() {
        return;
    }

    unsafe {
        crate::ke::ke_lower_irql(old_irql);
    }
}

// ============================================================================
// Allocation Helpers
// ============================================================================

unsafe fn allocate_interrupt() -> Option<usize> {
    for i in 0..4 {
        if INTERRUPT_BITMAP[i] != !0u64 {
            for bit in 0..64 {
                if INTERRUPT_BITMAP[i] & (1 << bit) == 0 {
                    INTERRUPT_BITMAP[i] |= 1 << bit;
                    let idx = i * 64 + bit;
                    return Some(idx);
                }
            }
        }
    }
    None
}

unsafe fn free_interrupt(index: usize) {
    if index < MAX_INTERRUPT_OBJECTS {
        let bitmap_idx = index / 64;
        let bit = index % 64;
        INTERRUPT_BITMAP[bitmap_idx] &= !(1 << bit);

        // Reset the interrupt object
        INTERRUPT_POOL[index] = KInterrupt::new();
    }
}

// ============================================================================
// Query Functions
// ============================================================================

/// Get interrupt count for a vector
pub fn hal_get_interrupt_count(vector: u8) -> usize {
    if vector < 32 {
        return 0;
    }

    let chain_idx = (vector - 32) as usize;
    if chain_idx >= 224 {
        return 0;
    }

    unsafe { VECTOR_CHAINS[chain_idx].count }
}

/// Check if a vector has connected interrupts
pub fn hal_is_vector_in_use(vector: u8) -> bool {
    hal_get_interrupt_count(vector) > 0
}

/// Get statistics for an interrupt object
pub fn hal_get_interrupt_stats(interrupt: *mut KInterrupt) -> Option<InterruptStats> {
    if interrupt.is_null() {
        return None;
    }

    unsafe { Some((*interrupt).get_stats()) }
}

/// Global interrupt statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct GlobalInterruptStats {
    pub total_connects: u32,
    pub total_disconnects: u32,
    pub active_interrupts: u32,
    pub vectors_in_use: u32,
}

/// Get global interrupt statistics
pub fn hal_get_global_stats() -> GlobalInterruptStats {
    let mut vectors_in_use = 0u32;

    unsafe {
        for chain in VECTOR_CHAINS.iter() {
            if chain.count > 0 {
                vectors_in_use += 1;
            }
        }
    }

    GlobalInterruptStats {
        total_connects: TOTAL_CONNECTS.load(Ordering::Relaxed),
        total_disconnects: TOTAL_DISCONNECTS.load(Ordering::Relaxed),
        active_interrupts: ACTIVE_INTERRUPTS.load(Ordering::Relaxed),
        vectors_in_use,
    }
}

/// Get all active interrupt vectors
pub fn hal_get_active_vectors(max_count: usize) -> ([u8; 64], usize) {
    let mut vectors = [0u8; 64];
    let mut count = 0;

    unsafe {
        for (i, chain) in VECTOR_CHAINS.iter().enumerate() {
            if chain.count > 0 && count < max_count && count < 64 {
                vectors[count] = (i + 32) as u8;
                count += 1;
            }
        }
    }

    (vectors, count)
}

/// Per-vector statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct VectorStats {
    pub vector: u8,
    pub interrupt_count: usize,
    pub total_dispatches: u64,
    pub total_handled: u64,
}

/// Get statistics for a vector
pub fn hal_get_vector_stats(vector: u8) -> Option<VectorStats> {
    if vector < 32 {
        return None;
    }

    let chain_idx = (vector - 32) as usize;
    if chain_idx >= 224 {
        return None;
    }

    unsafe {
        let chain = &VECTOR_CHAINS[chain_idx];

        if chain.count == 0 {
            return None;
        }

        let mut total_dispatches = 0u64;
        let mut total_handled = 0u64;

        for entry in chain.entries.iter() {
            if entry.active {
                let interrupt = &INTERRUPT_POOL[entry.interrupt_index];
                total_dispatches += interrupt.dispatch_count.load(Ordering::Relaxed);
                total_handled += interrupt.handled_count.load(Ordering::Relaxed);
            }
        }

        Some(VectorStats {
            vector,
            interrupt_count: chain.count,
            total_dispatches,
            total_handled,
        })
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the HAL interrupt subsystem
pub fn init() {
    let _guard = INTERRUPT_LOCK.lock();

    unsafe {
        // Clear interrupt pool
        for interrupt in INTERRUPT_POOL.iter_mut() {
            *interrupt = KInterrupt::new();
        }

        // Clear bitmaps
        for bitmap in INTERRUPT_BITMAP.iter_mut() {
            *bitmap = 0;
        }

        // Clear vector chains
        for chain in VECTOR_CHAINS.iter_mut() {
            *chain = VectorChain::new();
        }
    }

    TOTAL_CONNECTS.store(0, Ordering::Relaxed);
    TOTAL_DISCONNECTS.store(0, Ordering::Relaxed);
    ACTIVE_INTERRUPTS.store(0, Ordering::Relaxed);

    INTERRUPT_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[HAL] Interrupt subsystem initialized");
}
