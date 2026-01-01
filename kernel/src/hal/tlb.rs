//! TLB (Translation Lookaside Buffer) Management
//!
//! Provides TLB control operations:
//!
//! - **Flush**: Invalidate TLB entries
//! - **Shootdown**: Cross-processor TLB flush
//! - **PCID**: Process Context ID support
//! - **INVLPG**: Single page invalidation
//!
//! # TLB Types
//!
//! - ITLB: Instruction TLB
//! - DTLB: Data TLB
//! - STLB: Shared/Unified TLB (L2)
//!
//! # Flush Methods
//!
//! - INVLPG: Invalidate single page
//! - MOV CR3: Flush entire TLB (except global)
//! - INVPCID: Invalidate by PCID
//!
//! # PCID
//!
//! Process Context IDs (0-4095) allow TLB entries
//! to be tagged, reducing flush overhead on context switch.
//!
//! # NT Functions
//!
//! - `KeFlushSingleTb` - Flush single page
//! - `KeFlushEntireTb` - Flush entire TLB
//!
//! # Usage
//!
//! ```ignore
//! // Flush single page
//! tlb_flush_page(virtual_addr);
//!
//! // Flush all TLB
//! tlb_flush_all();
//!
//! // IPI-based shootdown
//! tlb_shootdown_all();
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;

// ============================================================================
// Constants
// ============================================================================

/// Maximum PCID value (12 bits)
pub const MAX_PCID: u16 = 4095;

/// Global page bit in PTE
pub const PTE_GLOBAL: u64 = 1 << 8;

// ============================================================================
// INVPCID Types
// ============================================================================

/// INVPCID type values
pub mod invpcid_type {
    /// Invalidate single address for PCID
    pub const INDIVIDUAL_ADDRESS: u64 = 0;
    /// Invalidate all entries for PCID
    pub const SINGLE_CONTEXT: u64 = 1;
    /// Invalidate all entries except global
    pub const ALL_CONTEXTS: u64 = 2;
    /// Invalidate all entries including global
    pub const ALL_CONTEXTS_GLOBAL: u64 = 3;
}

// ============================================================================
// Types
// ============================================================================

/// TLB flush scope
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlbFlushScope {
    #[default]
    Local = 0,
    AllProcessors = 1,
    TargetProcessors = 2,
}

/// INVPCID descriptor
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, Default)]
pub struct InvpcidDescriptor {
    /// PCID value
    pub pcid: u64,
    /// Linear address
    pub address: u64,
}

// ============================================================================
// Global State
// ============================================================================

static TLB_LOCK: SpinLock<()> = SpinLock::new(());
static TLB_INITIALIZED: AtomicBool = AtomicBool::new(false);

static INVPCID_SUPPORTED: AtomicBool = AtomicBool::new(false);
static PCID_SUPPORTED: AtomicBool = AtomicBool::new(false);
static GLOBAL_PAGES_SUPPORTED: AtomicBool = AtomicBool::new(false);

static CURRENT_PCID: AtomicU32 = AtomicU32::new(0);

static LOCAL_FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);
static GLOBAL_FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);
static PAGE_FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);
static SHOOTDOWN_COUNT: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Feature Detection
// ============================================================================

/// Detect TLB capabilities
fn detect_tlb_features() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Check CPUID.01H for PGE (global pages)
        let (_, _, _, edx): (u32, u32, u32, u32);
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("eax") _,
            out("ecx") _,
            out("edx") edx,
            options(preserves_flags)
        );

        // PGE (bit 13)
        GLOBAL_PAGES_SUPPORTED.store((edx & (1 << 13)) != 0, Ordering::Relaxed);

        // Check CPUID.07H for INVPCID
        let ebx7: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 7",
            "xor ecx, ecx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx7,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(preserves_flags)
        );

        // INVPCID (bit 10)
        INVPCID_SUPPORTED.store((ebx7 & (1 << 10)) != 0, Ordering::Relaxed);

        // PCID support is in CR4.PCIDE which requires checking CPUID.01H:ECX[17]
        let (_, _, ecx, _): (u32, u32, u32, u32);
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("eax") _,
            out("ecx") ecx,
            out("edx") _,
            options(preserves_flags)
        );

        PCID_SUPPORTED.store((ecx & (1 << 17)) != 0, Ordering::Relaxed);
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize TLB management
pub fn init() {
    detect_tlb_features();

    TLB_INITIALIZED.store(true, Ordering::Release);

    let invpcid = INVPCID_SUPPORTED.load(Ordering::Relaxed);
    let pcid = PCID_SUPPORTED.load(Ordering::Relaxed);
    let global = GLOBAL_PAGES_SUPPORTED.load(Ordering::Relaxed);

    crate::serial_println!(
        "[TLB] Initialized: INVPCID={}, PCID={}, Global={}",
        invpcid, pcid, global
    );
}

// ============================================================================
// Local TLB Flush
// ============================================================================

/// Flush single TLB entry
#[inline]
pub fn tlb_flush_page(address: u64) {
    PAGE_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) address,
            options(nostack, preserves_flags)
        );
    }
}

/// Flush TLB for range of pages
pub fn tlb_flush_range(start: u64, size: usize) {
    const PAGE_SIZE: u64 = 4096;

    let end = start + size as u64;
    let mut addr = start & !(PAGE_SIZE - 1);

    while addr < end {
        tlb_flush_page(addr);
        addr += PAGE_SIZE;
    }
}

/// Flush entire TLB (except global pages)
#[inline]
pub fn tlb_flush_all() {
    LOCAL_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Read and write back CR3 to flush TLB
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack));
    }
}

/// Flush entire TLB including global pages
#[inline]
pub fn tlb_flush_all_global() {
    GLOBAL_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        if GLOBAL_PAGES_SUPPORTED.load(Ordering::Relaxed) {
            // Toggle CR4.PGE to flush global entries
            let cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack));

            // Disable PGE
            core::arch::asm!("mov cr4, {}", in(reg) cr4 & !(1u64 << 7), options(nostack));

            // Re-enable PGE
            core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack));
        } else {
            // Just reload CR3
            tlb_flush_all();
        }
    }
}

// ============================================================================
// INVPCID Operations
// ============================================================================

/// Execute INVPCID instruction
#[inline]
unsafe fn invpcid(inv_type: u64, descriptor: &InvpcidDescriptor) {
    #[cfg(target_arch = "x86_64")]
    {
        core::arch::asm!(
            "invpcid {0}, [{1}]",
            in(reg) inv_type,
            in(reg) descriptor as *const InvpcidDescriptor,
            options(nostack)
        );
    }
}

/// Flush single address for PCID
pub fn tlb_flush_pcid_address(pcid: u16, address: u64) {
    if !INVPCID_SUPPORTED.load(Ordering::Relaxed) {
        tlb_flush_page(address);
        return;
    }

    let descriptor = InvpcidDescriptor {
        pcid: pcid as u64,
        address,
    };

    unsafe {
        invpcid(invpcid_type::INDIVIDUAL_ADDRESS, &descriptor);
    }

    PAGE_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Flush all entries for specific PCID
pub fn tlb_flush_pcid(pcid: u16) {
    if !INVPCID_SUPPORTED.load(Ordering::Relaxed) {
        tlb_flush_all();
        return;
    }

    let descriptor = InvpcidDescriptor {
        pcid: pcid as u64,
        address: 0,
    };

    unsafe {
        invpcid(invpcid_type::SINGLE_CONTEXT, &descriptor);
    }

    LOCAL_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Flush all contexts except global
pub fn tlb_flush_all_contexts() {
    if !INVPCID_SUPPORTED.load(Ordering::Relaxed) {
        tlb_flush_all();
        return;
    }

    let descriptor = InvpcidDescriptor::default();

    unsafe {
        invpcid(invpcid_type::ALL_CONTEXTS, &descriptor);
    }

    LOCAL_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Flush all contexts including global
pub fn tlb_flush_all_contexts_global() {
    if !INVPCID_SUPPORTED.load(Ordering::Relaxed) {
        tlb_flush_all_global();
        return;
    }

    let descriptor = InvpcidDescriptor::default();

    unsafe {
        invpcid(invpcid_type::ALL_CONTEXTS_GLOBAL, &descriptor);
    }

    GLOBAL_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// TLB Shootdown (IPI-based)
// ============================================================================

/// Perform TLB shootdown on all processors
pub fn tlb_shootdown_all() {
    SHOOTDOWN_COUNT.fetch_add(1, Ordering::Relaxed);

    // Flush local TLB first
    tlb_flush_all();

    // Send IPI to other processors
    super::mp::mp_flush_tlb_all();
}

/// Perform TLB shootdown for specific page
pub fn tlb_shootdown_page(address: u64) {
    SHOOTDOWN_COUNT.fetch_add(1, Ordering::Relaxed);

    // Flush local TLB
    tlb_flush_page(address);

    // Send IPI to other processors with flush request
    super::mp::mp_flush_tlb_all();
}

/// Perform TLB shootdown for range
pub fn tlb_shootdown_range(start: u64, size: usize) {
    SHOOTDOWN_COUNT.fetch_add(1, Ordering::Relaxed);

    // Flush local TLB
    tlb_flush_range(start, size);

    // Send IPI to other processors
    super::mp::mp_flush_tlb_all();
}

// ============================================================================
// PCID Management
// ============================================================================

/// Get current PCID
pub fn tlb_get_current_pcid() -> u16 {
    CURRENT_PCID.load(Ordering::Relaxed) as u16
}

/// Set current PCID
pub fn tlb_set_current_pcid(pcid: u16) {
    if pcid > MAX_PCID {
        return;
    }

    CURRENT_PCID.store(pcid as u32, Ordering::Relaxed);
}

/// Check if PCID is supported
pub fn tlb_is_pcid_supported() -> bool {
    PCID_SUPPORTED.load(Ordering::Relaxed)
}

/// Check if INVPCID is supported
pub fn tlb_is_invpcid_supported() -> bool {
    INVPCID_SUPPORTED.load(Ordering::Relaxed)
}

/// Check if global pages are supported
pub fn tlb_is_global_supported() -> bool {
    GLOBAL_PAGES_SUPPORTED.load(Ordering::Relaxed)
}

// ============================================================================
// Query Functions
// ============================================================================

/// Check if TLB management is initialized
pub fn tlb_is_initialized() -> bool {
    TLB_INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// Statistics
// ============================================================================

/// TLB statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct TlbStats {
    pub initialized: bool,
    pub invpcid_supported: bool,
    pub pcid_supported: bool,
    pub global_supported: bool,
    pub current_pcid: u16,
    pub local_flush_count: u64,
    pub global_flush_count: u64,
    pub page_flush_count: u64,
    pub shootdown_count: u64,
}

/// Get TLB statistics
pub fn tlb_get_stats() -> TlbStats {
    TlbStats {
        initialized: TLB_INITIALIZED.load(Ordering::Relaxed),
        invpcid_supported: INVPCID_SUPPORTED.load(Ordering::Relaxed),
        pcid_supported: PCID_SUPPORTED.load(Ordering::Relaxed),
        global_supported: GLOBAL_PAGES_SUPPORTED.load(Ordering::Relaxed),
        current_pcid: CURRENT_PCID.load(Ordering::Relaxed) as u16,
        local_flush_count: LOCAL_FLUSH_COUNT.load(Ordering::Relaxed),
        global_flush_count: GLOBAL_FLUSH_COUNT.load(Ordering::Relaxed),
        page_flush_count: PAGE_FLUSH_COUNT.load(Ordering::Relaxed),
        shootdown_count: SHOOTDOWN_COUNT.load(Ordering::Relaxed),
    }
}

// ============================================================================
// NT Compatibility
// ============================================================================

/// KeFlushSingleTb equivalent
pub fn ke_flush_single_tb(address: u64, all_processors: bool) {
    if all_processors {
        tlb_shootdown_page(address);
    } else {
        tlb_flush_page(address);
    }
}

/// KeFlushEntireTb equivalent
pub fn ke_flush_entire_tb(all_processors: bool, include_global: bool) {
    if all_processors {
        tlb_shootdown_all();
    } else if include_global {
        tlb_flush_all_global();
    } else {
        tlb_flush_all();
    }
}
