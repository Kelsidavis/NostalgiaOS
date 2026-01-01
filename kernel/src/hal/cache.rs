//! CPU Cache Management
//!
//! Provides cache control operations:
//!
//! - **Flush**: Write back and invalidate cache
//! - **Writeback**: Write dirty lines to memory
//! - **Invalidate**: Discard cache contents
//! - **Prefetch**: Hint data into cache
//!
//! # Cache Levels
//!
//! Modern x86_64 processors have:
//! - L1 Data Cache (per-core, 32-64KB)
//! - L1 Instruction Cache (per-core, 32-64KB)
//! - L2 Cache (per-core, 256KB-1MB)
//! - L3 Cache (shared, 4-64MB)
//!
//! # Cache Line Size
//!
//! Standard cache line size is 64 bytes on modern processors.
//!
//! # NT Functions
//!
//! - `KeFlushWriteBuffer` - Memory barrier
//! - `KeSweepIcache` - Flush instruction cache
//! - `KeSweepDcache` - Flush data cache
//!
//! # Usage
//!
//! ```ignore
//! // Flush specific address range
//! cache_flush_range(addr, size);
//!
//! // Full cache flush
//! cache_flush_all();
//!
//! // Memory barrier
//! cache_memory_barrier();
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::spinlock::SpinLock;

// ============================================================================
// Constants
// ============================================================================

/// Default cache line size (bytes)
pub const DEFAULT_CACHE_LINE_SIZE: usize = 64;

/// Maximum cache levels
pub const MAX_CACHE_LEVELS: usize = 4;

/// Cache type bits from CPUID
const CACHE_TYPE_NULL: u32 = 0;
const CACHE_TYPE_DATA: u32 = 1;
const CACHE_TYPE_INSTRUCTION: u32 = 2;
const CACHE_TYPE_UNIFIED: u32 = 3;

// ============================================================================
// Types
// ============================================================================

/// Cache type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheType {
    #[default]
    Unknown = 0,
    Data = 1,
    Instruction = 2,
    Unified = 3,
}

/// Cache level information
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheInfo {
    /// Cache type
    pub cache_type: CacheType,
    /// Cache level (1, 2, 3, etc.)
    pub level: u8,
    /// Line size in bytes
    pub line_size: u16,
    /// Number of ways (associativity)
    pub ways: u16,
    /// Number of sets
    pub sets: u32,
    /// Total size in bytes
    pub size: u32,
    /// Self-initializing
    pub self_init: bool,
    /// Fully associative
    pub fully_assoc: bool,
    /// Shared between cores
    pub shared: bool,
    /// Number of threads sharing this cache
    pub sharing_threads: u16,
}

/// Cache flush mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushMode {
    /// Writeback only (leave data in cache)
    Writeback = 0,
    /// Invalidate only (discard without writing)
    Invalidate = 1,
    /// Writeback and invalidate
    WritebackInvalidate = 2,
}

/// Prefetch hint
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefetchHint {
    /// Non-temporal (streaming data)
    NonTemporal = 0,
    /// Temporal level 0 (all cache levels)
    T0 = 1,
    /// Temporal level 1 (L1 only)
    T1 = 2,
    /// Temporal level 2 (L2 only)
    T2 = 3,
}

// ============================================================================
// Global State
// ============================================================================

static CACHE_LOCK: SpinLock<()> = SpinLock::new(());
static CACHE_INITIALIZED: AtomicBool = AtomicBool::new(false);

static CACHE_LINE_SIZE: AtomicU32 = AtomicU32::new(DEFAULT_CACHE_LINE_SIZE as u32);
static CLFLUSH_SUPPORTED: AtomicBool = AtomicBool::new(false);
static CLFLUSHOPT_SUPPORTED: AtomicBool = AtomicBool::new(false);
static CLWB_SUPPORTED: AtomicBool = AtomicBool::new(false);
static PREFETCH_SUPPORTED: AtomicBool = AtomicBool::new(false);

static FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);
static LINES_FLUSHED: AtomicU64 = AtomicU64::new(0);
static PREFETCH_COUNT: AtomicU64 = AtomicU64::new(0);

static mut CACHE_INFO: [CacheInfo; MAX_CACHE_LEVELS] = [CacheInfo {
    cache_type: CacheType::Unknown,
    level: 0,
    line_size: 0,
    ways: 0,
    sets: 0,
    size: 0,
    self_init: false,
    fully_assoc: false,
    shared: false,
    sharing_threads: 0,
}; MAX_CACHE_LEVELS];

static CACHE_LEVEL_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Detection
// ============================================================================

/// Detect cache capabilities
fn detect_cache_features() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Check CPUID.01H for basic features
        let (_, ebx, ecx, edx): (u32, u32, u32, u32);
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx,
            out("eax") _,
            out("ecx") ecx,
            out("edx") edx,
            options(preserves_flags)
        );

        // CLFLUSH supported (EDX bit 19)
        CLFLUSH_SUPPORTED.store((edx & (1 << 19)) != 0, Ordering::Relaxed);

        // Cache line size from EBX bits 8-15
        let line_size = ((ebx >> 8) & 0xFF) * 8;
        if line_size > 0 {
            CACHE_LINE_SIZE.store(line_size, Ordering::Relaxed);
        }

        // Prefetch supported (SSE bit in EDX)
        PREFETCH_SUPPORTED.store((edx & (1 << 25)) != 0, Ordering::Relaxed);

        // Check CPUID.07H for extended features
        let ecx7: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 7",
            "xor ecx, ecx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ecx7,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(preserves_flags)
        );

        // CLFLUSHOPT supported (EBX bit 23)
        CLFLUSHOPT_SUPPORTED.store((ecx7 & (1 << 23)) != 0, Ordering::Relaxed);

        // CLWB supported (EBX bit 24)
        CLWB_SUPPORTED.store((ecx7 & (1 << 24)) != 0, Ordering::Relaxed);
    }
}

/// Detect cache topology using CPUID
fn detect_cache_topology() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut cache_count = 0u32;

        // Use CPUID.04H to enumerate caches
        for subleaf in 0..MAX_CACHE_LEVELS {
            let (eax, ebx, ecx, _edx): (u32, u32, u32, u32);
            core::arch::asm!(
                "push rbx",
                "mov eax, 4",
                "mov ecx, {0:e}",
                "cpuid",
                "mov {1:e}, ebx",
                "pop rbx",
                in(reg) subleaf,
                out(reg) ebx,
                out("eax") eax,
                out("ecx") ecx,
                out("edx") _edx,
                options(preserves_flags)
            );

            let cache_type = eax & 0x1F;
            if cache_type == CACHE_TYPE_NULL {
                break;
            }

            let level = ((eax >> 5) & 0x7) as u8;
            let self_init = (eax & (1 << 8)) != 0;
            let fully_assoc = (eax & (1 << 9)) != 0;

            let line_size = ((ebx & 0xFFF) + 1) as u16;
            let partitions = (((ebx >> 12) & 0x3FF) + 1) as u16;
            let ways = (((ebx >> 22) & 0x3FF) + 1) as u16;
            let sets = ecx + 1;

            let size = (line_size as u32) * (partitions as u32) * (ways as u32) * sets;

            let sharing_threads = (((eax >> 14) & 0xFFF) + 1) as u16;

            CACHE_INFO[subleaf] = CacheInfo {
                cache_type: match cache_type {
                    CACHE_TYPE_DATA => CacheType::Data,
                    CACHE_TYPE_INSTRUCTION => CacheType::Instruction,
                    CACHE_TYPE_UNIFIED => CacheType::Unified,
                    _ => CacheType::Unknown,
                },
                level,
                line_size,
                ways,
                sets,
                size,
                self_init,
                fully_assoc,
                shared: sharing_threads > 1,
                sharing_threads,
            };

            cache_count += 1;
        }

        CACHE_LEVEL_COUNT.store(cache_count, Ordering::Relaxed);
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize cache management
pub fn init() {
    let _guard = CACHE_LOCK.lock();

    detect_cache_features();
    detect_cache_topology();

    CACHE_INITIALIZED.store(true, Ordering::Release);

    let line_size = CACHE_LINE_SIZE.load(Ordering::Relaxed);
    let clflush = CLFLUSH_SUPPORTED.load(Ordering::Relaxed);
    let clflushopt = CLFLUSHOPT_SUPPORTED.load(Ordering::Relaxed);
    let clwb = CLWB_SUPPORTED.load(Ordering::Relaxed);

    crate::serial_println!(
        "[Cache] Initialized: line={}, clflush={}, clflushopt={}, clwb={}",
        line_size, clflush, clflushopt, clwb
    );
}

// ============================================================================
// Cache Flush Operations
// ============================================================================

/// Flush a single cache line
#[inline]
pub fn cache_flush_line(addr: u64) {
    LINES_FLUSHED.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    {
        if CLFLUSHOPT_SUPPORTED.load(Ordering::Relaxed) {
            unsafe {
                core::arch::asm!(
                    "clflushopt [{}]",
                    in(reg) addr,
                    options(nostack)
                );
            }
        } else if CLFLUSH_SUPPORTED.load(Ordering::Relaxed) {
            unsafe {
                core::arch::asm!(
                    "clflush [{}]",
                    in(reg) addr,
                    options(nostack)
                );
            }
        }
    }
}

/// Writeback a single cache line (keep in cache)
#[inline]
pub fn cache_writeback_line(addr: u64) {
    LINES_FLUSHED.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    {
        if CLWB_SUPPORTED.load(Ordering::Relaxed) {
            unsafe {
                core::arch::asm!(
                    "clwb [{}]",
                    in(reg) addr,
                    options(nostack)
                );
            }
        } else {
            // Fall back to flush
            cache_flush_line(addr);
        }
    }
}

/// Flush a range of addresses
pub fn cache_flush_range(start: u64, size: usize) {
    let line_size = CACHE_LINE_SIZE.load(Ordering::Relaxed) as u64;
    if line_size == 0 {
        return;
    }

    let end = start + size as u64;
    let mut addr = start & !(line_size - 1);

    FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);

    while addr < end {
        cache_flush_line(addr);
        addr += line_size;
    }

    // Memory fence
    cache_memory_fence();
}

/// Writeback a range of addresses
pub fn cache_writeback_range(start: u64, size: usize) {
    let line_size = CACHE_LINE_SIZE.load(Ordering::Relaxed) as u64;
    if line_size == 0 {
        return;
    }

    let end = start + size as u64;
    let mut addr = start & !(line_size - 1);

    FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);

    while addr < end {
        cache_writeback_line(addr);
        addr += line_size;
    }

    cache_memory_fence();
}

/// Flush entire cache (expensive!)
pub fn cache_flush_all() {
    FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("wbinvd", options(nostack));
    }
}

// ============================================================================
// Memory Barriers
// ============================================================================

/// Memory fence (all prior stores complete before continuing)
#[inline]
pub fn cache_memory_fence() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}

/// Store fence (all prior stores visible before continuing)
#[inline]
pub fn cache_store_fence() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("sfence", options(nostack, preserves_flags));
    }
}

/// Load fence (all prior loads complete before continuing)
#[inline]
pub fn cache_load_fence() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("lfence", options(nostack, preserves_flags));
    }
}

/// Compiler memory barrier only
#[inline]
pub fn cache_compiler_barrier() {
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

// ============================================================================
// Prefetch Operations
// ============================================================================

/// Prefetch data into cache
#[inline]
pub fn cache_prefetch(addr: u64, hint: PrefetchHint) {
    if !PREFETCH_SUPPORTED.load(Ordering::Relaxed) {
        return;
    }

    PREFETCH_COUNT.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        match hint {
            PrefetchHint::NonTemporal => {
                core::arch::asm!(
                    "prefetchnta [{}]",
                    in(reg) addr,
                    options(nostack)
                );
            }
            PrefetchHint::T0 => {
                core::arch::asm!(
                    "prefetcht0 [{}]",
                    in(reg) addr,
                    options(nostack)
                );
            }
            PrefetchHint::T1 => {
                core::arch::asm!(
                    "prefetcht1 [{}]",
                    in(reg) addr,
                    options(nostack)
                );
            }
            PrefetchHint::T2 => {
                core::arch::asm!(
                    "prefetcht2 [{}]",
                    in(reg) addr,
                    options(nostack)
                );
            }
        }
    }
}

/// Prefetch for write
#[inline]
pub fn cache_prefetch_write(addr: u64) {
    if !PREFETCH_SUPPORTED.load(Ordering::Relaxed) {
        return;
    }

    PREFETCH_COUNT.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "prefetchw [{}]",
            in(reg) addr,
            options(nostack)
        );
    }
}

// ============================================================================
// Query Functions
// ============================================================================

/// Get cache line size
pub fn cache_get_line_size() -> usize {
    CACHE_LINE_SIZE.load(Ordering::Relaxed) as usize
}

/// Get cache information for a level
pub fn cache_get_info(level: u8) -> Option<CacheInfo> {
    if level == 0 || level as usize > CACHE_LEVEL_COUNT.load(Ordering::Relaxed) as usize {
        return None;
    }

    unsafe {
        for info in CACHE_INFO.iter() {
            if info.level == level && info.cache_type != CacheType::Unknown {
                return Some(*info);
            }
        }
    }

    None
}

/// Get all cache information
pub fn cache_get_all_info() -> ([CacheInfo; MAX_CACHE_LEVELS], usize) {
    let count = CACHE_LEVEL_COUNT.load(Ordering::Relaxed) as usize;
    unsafe { (CACHE_INFO, count) }
}

/// Check if CLFLUSH is supported
pub fn cache_is_clflush_supported() -> bool {
    CLFLUSH_SUPPORTED.load(Ordering::Relaxed)
}

/// Check if CLFLUSHOPT is supported
pub fn cache_is_clflushopt_supported() -> bool {
    CLFLUSHOPT_SUPPORTED.load(Ordering::Relaxed)
}

/// Check if CLWB is supported
pub fn cache_is_clwb_supported() -> bool {
    CLWB_SUPPORTED.load(Ordering::Relaxed)
}

/// Check if cache management is initialized
pub fn cache_is_initialized() -> bool {
    CACHE_INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// Statistics
// ============================================================================

/// Cache statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheStats {
    pub initialized: bool,
    pub line_size: u32,
    pub levels: u32,
    pub clflush_supported: bool,
    pub clflushopt_supported: bool,
    pub clwb_supported: bool,
    pub prefetch_supported: bool,
    pub flush_count: u64,
    pub lines_flushed: u64,
    pub prefetch_count: u64,
}

/// Get cache statistics
pub fn cache_get_stats() -> CacheStats {
    CacheStats {
        initialized: CACHE_INITIALIZED.load(Ordering::Relaxed),
        line_size: CACHE_LINE_SIZE.load(Ordering::Relaxed),
        levels: CACHE_LEVEL_COUNT.load(Ordering::Relaxed),
        clflush_supported: CLFLUSH_SUPPORTED.load(Ordering::Relaxed),
        clflushopt_supported: CLFLUSHOPT_SUPPORTED.load(Ordering::Relaxed),
        clwb_supported: CLWB_SUPPORTED.load(Ordering::Relaxed),
        prefetch_supported: PREFETCH_SUPPORTED.load(Ordering::Relaxed),
        flush_count: FLUSH_COUNT.load(Ordering::Relaxed),
        lines_flushed: LINES_FLUSHED.load(Ordering::Relaxed),
        prefetch_count: PREFETCH_COUNT.load(Ordering::Relaxed),
    }
}

// ============================================================================
// NT Compatibility
// ============================================================================

/// KeFlushWriteBuffer equivalent
#[inline]
pub fn ke_flush_write_buffer() {
    cache_store_fence();
}

/// KeSweepDcache equivalent
pub fn ke_sweep_dcache() {
    cache_flush_all();
}

/// KeSweepIcache equivalent
pub fn ke_sweep_icache() {
    // x86_64 doesn't need explicit I-cache flush
    // Just memory barrier
    cache_memory_fence();
}

/// KeFlushIoBuffers equivalent
pub fn ke_flush_io_buffers(_read: bool) {
    cache_memory_fence();
}
