//! TLB Shootdown Implementation
//!
//! In an SMP system, when one CPU modifies a page table entry, other CPUs
//! may have stale TLB entries. TLB shootdown is the process of invalidating
//! TLB entries across all CPUs to maintain memory coherency.
//!
//! # Protocol
//!
//! 1. Caller creates a TlbShootdownRequest
//! 2. Invalidates local TLB
//! 3. Sends TLB_SHOOTDOWN IPI to all other CPUs
//! 4. Spins until all CPUs acknowledge
//!
//! # Safety
//!
//! TLB shootdown is critical for correctness:
//! - Security: Prevents access to freed memory
//! - Correctness: Prevents reading stale data
//! - Stability: Prevents crashes from accessing unmapped pages

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use crate::ke::prcb;
use crate::hal::apic;

/// IPI vector for TLB shootdown
pub use crate::arch::x86_64::idt::vector::TLB_SHOOTDOWN as TLB_SHOOTDOWN_VECTOR;

/// Maximum number of CPUs that can participate in TLB shootdown
const MAX_SHOOTDOWN_CPUS: usize = 64;

/// Type of TLB invalidation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlbInvalidationType {
    /// Invalidate a single page
    SinglePage,
    /// Invalidate a range of pages
    Range,
    /// Flush entire TLB
    Full,
}

/// TLB Shootdown Request
///
/// This structure is shared between CPUs during a TLB shootdown operation.
/// The initiating CPU fills in the request details, and target CPUs
/// acknowledge completion by incrementing the ack_count.
#[repr(C)]
pub struct TlbShootdownRequest {
    /// Type of invalidation
    pub invalidation_type: TlbInvalidationType,
    /// Virtual address to invalidate (for SinglePage)
    pub address: u64,
    /// End address (for Range)
    pub end_address: u64,
    /// Bitmap of CPUs that need to perform shootdown
    pub cpu_mask: u64,
    /// Number of CPUs that have acknowledged
    pub ack_count: AtomicU32,
    /// Active flag (set while shootdown is in progress)
    pub active: AtomicBool,
}

impl TlbShootdownRequest {
    /// Create a new empty shootdown request
    pub const fn new() -> Self {
        Self {
            invalidation_type: TlbInvalidationType::Full,
            address: 0,
            end_address: 0,
            cpu_mask: 0,
            ack_count: AtomicU32::new(0),
            active: AtomicBool::new(false),
        }
    }

    /// Reset the request for reuse
    pub fn reset(&mut self) {
        self.invalidation_type = TlbInvalidationType::Full;
        self.address = 0;
        self.end_address = 0;
        self.cpu_mask = 0;
        self.ack_count.store(0, Ordering::Release);
        self.active.store(false, Ordering::Release);
    }

    /// Get the number of target CPUs
    pub fn target_count(&self) -> u32 {
        self.cpu_mask.count_ones()
    }
}

/// Global shootdown request (protected by spinlock)
static SHOOTDOWN_REQUEST: SpinLock<TlbShootdownRequest> =
    SpinLock::new(TlbShootdownRequest::new());

/// Per-CPU pending shootdown flag (set by IPI, cleared by handler)
static PENDING_SHOOTDOWN: [AtomicBool; MAX_SHOOTDOWN_CPUS] =
    [const { AtomicBool::new(false) }; MAX_SHOOTDOWN_CPUS];

/// Statistics
static SHOOTDOWN_COUNT: AtomicU64 = AtomicU64::new(0);
static SHOOTDOWN_PAGES: AtomicU64 = AtomicU64::new(0);

/// Invalidate a single page across all CPUs
///
/// This function sends an IPI to all other CPUs to invalidate their
/// TLB entries for the specified virtual address.
///
/// # Safety
/// Must be called with interrupts enabled (will spin waiting for acks)
pub fn tlb_shootdown_single_page(virt_addr: u64) {
    // Get current CPU count
    let cpu_count = prcb::get_active_cpu_count();
    if cpu_count <= 1 {
        // Single CPU - just invalidate locally
        super::pte::mm_invalidate_page_local(virt_addr);
        return;
    }

    // Get current CPU ID
    let current_cpu = unsafe { crate::arch::x86_64::percpu::get_cpu_id() };

    // Calculate CPU mask (all CPUs except current)
    let mut cpu_mask = 0u64;
    for i in 0..cpu_count {
        if i != current_cpu {
            cpu_mask |= 1u64 << i;
        }
    }

    if cpu_mask == 0 {
        // No other CPUs to notify
        super::pte::mm_invalidate_page_local(virt_addr);
        return;
    }

    // Acquire shootdown lock
    let mut request = SHOOTDOWN_REQUEST.lock();

    // Set up shootdown request
    request.invalidation_type = TlbInvalidationType::SinglePage;
    request.address = virt_addr;
    request.end_address = virt_addr;
    request.cpu_mask = cpu_mask;
    request.ack_count.store(0, Ordering::Release);
    request.active.store(true, Ordering::Release);

    // Invalidate local TLB first
    super::pte::mm_invalidate_page_local(virt_addr);

    // Send IPI to all other CPUs
    let target_count = cpu_mask.count_ones();
    apic::broadcast_ipi(TLB_SHOOTDOWN_VECTOR);

    // Wait for all CPUs to acknowledge (with timeout)
    let timeout_ticks = 10000; // ~10ms at typical timer frequency
    let mut ticks = 0;

    while request.ack_count.load(Ordering::Acquire) < target_count {
        core::hint::spin_loop();
        ticks += 1;

        if ticks >= timeout_ticks {
            // Timeout - this is a critical error
            crate::serial_println!(
                "[TLB] SHOOTDOWN TIMEOUT: expected {} acks, got {}",
                target_count,
                request.ack_count.load(Ordering::Acquire)
            );
            break;
        }
    }

    // Mark shootdown complete
    request.active.store(false, Ordering::Release);

    // Update statistics
    SHOOTDOWN_COUNT.fetch_add(1, Ordering::Relaxed);
    SHOOTDOWN_PAGES.fetch_add(1, Ordering::Relaxed);

    // Lock is automatically released when 'request' goes out of scope
}

/// Invalidate a range of pages across all CPUs
///
/// # Safety
/// Must be called with interrupts enabled
pub fn tlb_shootdown_range(start_addr: u64, end_addr: u64) {
    // Get current CPU count
    let cpu_count = prcb::get_active_cpu_count();
    if cpu_count <= 1 {
        // Single CPU - just invalidate locally
        let mut addr = start_addr;
        while addr < end_addr {
            super::pte::mm_invalidate_page_local(addr);
            addr += super::PAGE_SIZE as u64;
        }
        return;
    }

    // Calculate page count
    let page_count = ((end_addr - start_addr) / super::PAGE_SIZE as u64) + 1;

    // If range is large, use full TLB flush instead
    if page_count > 256 {
        tlb_shootdown_all();
        return;
    }

    // Get current CPU ID
    let current_cpu = unsafe { crate::arch::x86_64::percpu::get_cpu_id() };

    // Calculate CPU mask (all CPUs except current)
    let mut cpu_mask = 0u64;
    for i in 0..cpu_count {
        if i != current_cpu {
            cpu_mask |= 1u64 << i;
        }
    }

    if cpu_mask == 0 {
        // No other CPUs to notify
        let mut addr = start_addr;
        while addr < end_addr {
            super::pte::mm_invalidate_page_local(addr);
            addr += super::PAGE_SIZE as u64;
        }
        return;
    }

    // Acquire shootdown lock
    let mut request = SHOOTDOWN_REQUEST.lock();

    // Set up shootdown request
    request.invalidation_type = TlbInvalidationType::Range;
    request.address = start_addr;
    request.end_address = end_addr;
    request.cpu_mask = cpu_mask;
    request.ack_count.store(0, Ordering::Release);
    request.active.store(true, Ordering::Release);

    // Invalidate local TLB first
    let mut addr = start_addr;
    while addr < end_addr {
        super::pte::mm_invalidate_page_local(addr);
        addr += super::PAGE_SIZE as u64;
    }

    // Send IPI to all other CPUs
    let target_count = cpu_mask.count_ones();
    apic::broadcast_ipi(TLB_SHOOTDOWN_VECTOR);

    // Wait for all CPUs to acknowledge (with timeout)
    let timeout_ticks = 10000;
    let mut ticks = 0;

    while request.ack_count.load(Ordering::Acquire) < target_count {
        core::hint::spin_loop();
        ticks += 1;

        if ticks >= timeout_ticks {
            crate::serial_println!(
                "[TLB] RANGE SHOOTDOWN TIMEOUT: expected {} acks, got {}",
                target_count,
                request.ack_count.load(Ordering::Acquire)
            );
            break;
        }
    }

    // Mark shootdown complete
    request.active.store(false, Ordering::Release);

    // Update statistics
    SHOOTDOWN_COUNT.fetch_add(1, Ordering::Relaxed);
    SHOOTDOWN_PAGES.fetch_add(page_count, Ordering::Relaxed);
}

/// Flush entire TLB across all CPUs
///
/// # Safety
/// Must be called with interrupts enabled
pub fn tlb_shootdown_all() {
    // Get current CPU count
    let cpu_count = prcb::get_active_cpu_count();
    if cpu_count <= 1 {
        // Single CPU - just flush locally
        super::pte::mm_flush_tlb_local();
        return;
    }

    // Get current CPU ID
    let current_cpu = unsafe { crate::arch::x86_64::percpu::get_cpu_id() };

    // Calculate CPU mask (all CPUs except current)
    let mut cpu_mask = 0u64;
    for i in 0..cpu_count {
        if i != current_cpu {
            cpu_mask |= 1u64 << i;
        }
    }

    if cpu_mask == 0 {
        // No other CPUs to notify
        super::pte::mm_flush_tlb_local();
        return;
    }

    // Acquire shootdown lock
    let mut request = SHOOTDOWN_REQUEST.lock();

    // Set up shootdown request
    request.invalidation_type = TlbInvalidationType::Full;
    request.address = 0;
    request.end_address = 0;
    request.cpu_mask = cpu_mask;
    request.ack_count.store(0, Ordering::Release);
    request.active.store(true, Ordering::Release);

    // Flush local TLB first
    super::pte::mm_flush_tlb_local();

    // Send IPI to all other CPUs
    let target_count = cpu_mask.count_ones();
    apic::broadcast_ipi(TLB_SHOOTDOWN_VECTOR);

    // Wait for all CPUs to acknowledge (with timeout)
    let timeout_ticks = 10000;
    let mut ticks = 0;

    while request.ack_count.load(Ordering::Acquire) < target_count {
        core::hint::spin_loop();
        ticks += 1;

        if ticks >= timeout_ticks {
            crate::serial_println!(
                "[TLB] FULL SHOOTDOWN TIMEOUT: expected {} acks, got {}",
                target_count,
                request.ack_count.load(Ordering::Acquire)
            );
            break;
        }
    }

    // Mark shootdown complete
    request.active.store(false, Ordering::Release);

    // Update statistics
    SHOOTDOWN_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// TLB shootdown IPI handler
///
/// This is called when a CPU receives a TLB_SHOOTDOWN_VECTOR IPI.
/// It reads the shootdown request and invalidates the appropriate TLB entries.
///
/// # Safety
/// Called from interrupt context (IRQL = HIGH_LEVEL)
pub unsafe fn tlb_shootdown_handler() {
    // Get current CPU ID
    let cpu_id = crate::arch::x86_64::percpu::get_cpu_id();

    // Check if we're a target of the shootdown
    let request = SHOOTDOWN_REQUEST.lock();

    let cpu_bit = 1u64 << cpu_id;
    if (request.cpu_mask & cpu_bit) == 0 {
        // Not a target, ignore (spurious IPI?)
        drop(request);
        apic::eoi();
        return;
    }

    // Perform the requested invalidation
    match request.invalidation_type {
        TlbInvalidationType::SinglePage => {
            super::pte::mm_invalidate_page_local(request.address);
        }
        TlbInvalidationType::Range => {
            let mut addr = request.address;
            while addr < request.end_address {
                super::pte::mm_invalidate_page_local(addr);
                addr += super::PAGE_SIZE as u64;
            }
        }
        TlbInvalidationType::Full => {
            super::pte::mm_flush_tlb_local();
        }
    }

    // Acknowledge completion
    request.ack_count.fetch_add(1, Ordering::Release);

    // Drop lock before EOI
    drop(request);

    // Send EOI to APIC
    apic::eoi();
}

/// Get TLB shootdown statistics
pub fn get_shootdown_stats() -> (u64, u64) {
    (
        SHOOTDOWN_COUNT.load(Ordering::Relaxed),
        SHOOTDOWN_PAGES.load(Ordering::Relaxed),
    )
}

/// Initialize TLB shootdown subsystem
pub fn init() {
    crate::serial_println!("[MM] TLB shootdown initialized");
}
