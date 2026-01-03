//! Process Quota Management
//!
//! Provides quota tracking and enforcement for process resources including:
//! - Paged pool memory
//! - Non-paged pool memory
//! - Page file usage
//! - Working set limits
//!
//! # Quota Blocks
//!
//! Each process has a quota block that tracks resource usage against limits.
//! Multiple processes can share a quota block (inherited from parent).
//!
//! # NT Functions
//!
//! - `PsChargePoolQuota` - Charge pool memory to process quota
//! - `PsReturnPoolQuota` - Return pool memory to process quota
//! - `PsChargeProcessPageFileQuota` - Charge page file usage
//! - `PsReturnProcessPageFileQuota` - Return page file usage
//! - `PsChargeProcessNonPagedPoolQuota` - Charge non-paged pool
//! - `PsChargeProcessPagedPoolQuota` - Charge paged pool

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;

/// Maximum number of quota blocks
pub const MAX_QUOTA_BLOCKS: usize = 256;

/// Default quota limits (generous for development)
pub const DEFAULT_PAGED_POOL_LIMIT: u64 = 64 * 1024 * 1024;      // 64 MB
pub const DEFAULT_NONPAGED_POOL_LIMIT: u64 = 32 * 1024 * 1024;   // 32 MB
pub const DEFAULT_PAGEFILE_LIMIT: u64 = 256 * 1024 * 1024;       // 256 MB
pub const DEFAULT_WORKING_SET_LIMIT: u64 = 128 * 1024 * 1024;    // 128 MB

/// Quota type for charging/returning
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PoolType {
    /// Non-paged pool
    NonPagedPool = 0,
    /// Paged pool
    PagedPool = 1,
    /// Non-paged pool with must-succeed semantics
    NonPagedPoolMustSucceed = 2,
    /// Non-paged pool cache-aligned
    NonPagedPoolCacheAligned = 4,
    /// Paged pool cache-aligned
    PagedPoolCacheAligned = 5,
}

impl PoolType {
    /// Check if this is a paged pool type
    pub fn is_paged(&self) -> bool {
        matches!(self, PoolType::PagedPool | PoolType::PagedPoolCacheAligned)
    }

    /// Check if this is a non-paged pool type
    pub fn is_non_paged(&self) -> bool {
        !self.is_paged()
    }
}

/// Quota usage tracking for a single resource
#[derive(Debug)]
pub struct QuotaUsage {
    /// Current usage
    pub usage: AtomicU64,
    /// Peak usage (high water mark)
    pub peak: AtomicU64,
    /// Limit (0 = unlimited)
    pub limit: AtomicU64,
}

impl QuotaUsage {
    pub const fn new() -> Self {
        Self {
            usage: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            limit: AtomicU64::new(0),
        }
    }

    pub fn init(&self, limit: u64) {
        self.usage.store(0, Ordering::Relaxed);
        self.peak.store(0, Ordering::Relaxed);
        self.limit.store(limit, Ordering::Relaxed);
    }

    /// Try to charge amount against quota
    ///
    /// Returns Ok(new_usage) if successful, Err(current_usage) if would exceed limit
    pub fn charge(&self, amount: u64) -> Result<u64, u64> {
        loop {
            let current = self.usage.load(Ordering::Acquire);
            let new_usage = current.saturating_add(amount);
            let limit = self.limit.load(Ordering::Relaxed);

            // Check limit (0 = unlimited)
            if limit > 0 && new_usage > limit {
                return Err(current);
            }

            // Try to update
            if self.usage.compare_exchange_weak(
                current,
                new_usage,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                // Update peak if needed
                loop {
                    let peak = self.peak.load(Ordering::Relaxed);
                    if new_usage <= peak {
                        break;
                    }
                    if self.peak.compare_exchange_weak(
                        peak,
                        new_usage,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ).is_ok() {
                        break;
                    }
                }
                return Ok(new_usage);
            }
            core::hint::spin_loop();
        }
    }

    /// Return amount to quota
    pub fn return_quota(&self, amount: u64) {
        self.usage.fetch_sub(amount, Ordering::Release);
    }

    /// Get current usage
    pub fn get_usage(&self) -> u64 {
        self.usage.load(Ordering::Relaxed)
    }

    /// Get peak usage
    pub fn get_peak(&self) -> u64 {
        self.peak.load(Ordering::Relaxed)
    }

    /// Get limit
    pub fn get_limit(&self) -> u64 {
        self.limit.load(Ordering::Relaxed)
    }

    /// Set new limit
    pub fn set_limit(&self, limit: u64) {
        self.limit.store(limit, Ordering::Relaxed);
    }
}

impl Default for QuotaUsage {
    fn default() -> Self {
        Self::new()
    }
}

/// Process Quota Block
///
/// Tracks resource usage limits for a process or group of processes.
/// Equivalent to NT's EPROCESS_QUOTA_BLOCK.
#[repr(C)]
pub struct QuotaBlock {
    /// Reference count
    pub reference_count: AtomicU32,
    /// Paged pool quota
    pub paged_pool: QuotaUsage,
    /// Non-paged pool quota
    pub non_paged_pool: QuotaUsage,
    /// Page file quota
    pub page_file: QuotaUsage,
    /// Working set quota
    pub working_set: QuotaUsage,
    /// Process count using this block
    pub process_count: AtomicU32,
    /// Block is in use
    pub in_use: AtomicBool,
    /// Block ID
    pub id: u32,
}

impl QuotaBlock {
    pub const fn new(id: u32) -> Self {
        Self {
            reference_count: AtomicU32::new(0),
            paged_pool: QuotaUsage::new(),
            non_paged_pool: QuotaUsage::new(),
            page_file: QuotaUsage::new(),
            working_set: QuotaUsage::new(),
            process_count: AtomicU32::new(0),
            in_use: AtomicBool::new(false),
            id,
        }
    }

    /// Initialize with default limits
    pub fn init_default(&self) {
        self.reference_count.store(1, Ordering::Relaxed);
        self.paged_pool.init(DEFAULT_PAGED_POOL_LIMIT);
        self.non_paged_pool.init(DEFAULT_NONPAGED_POOL_LIMIT);
        self.page_file.init(DEFAULT_PAGEFILE_LIMIT);
        self.working_set.init(DEFAULT_WORKING_SET_LIMIT);
        self.process_count.store(1, Ordering::Relaxed);
        self.in_use.store(true, Ordering::Release);
    }

    /// Initialize with custom limits
    pub fn init_with_limits(
        &self,
        paged_limit: u64,
        non_paged_limit: u64,
        pagefile_limit: u64,
        working_set_limit: u64,
    ) {
        self.reference_count.store(1, Ordering::Relaxed);
        self.paged_pool.init(paged_limit);
        self.non_paged_pool.init(non_paged_limit);
        self.page_file.init(pagefile_limit);
        self.working_set.init(working_set_limit);
        self.process_count.store(1, Ordering::Relaxed);
        self.in_use.store(true, Ordering::Release);
    }

    /// Add a reference
    pub fn add_ref(&self) -> u32 {
        self.reference_count.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Release a reference
    pub fn release(&self) -> u32 {
        let old = self.reference_count.fetch_sub(1, Ordering::AcqRel);
        if old == 1 {
            // Last reference - mark as free
            self.in_use.store(false, Ordering::Release);
        }
        old - 1
    }

    /// Charge pool quota
    pub fn charge_pool_quota(&self, pool_type: PoolType, amount: u64) -> Result<(), i32> {
        let quota = if pool_type.is_paged() {
            &self.paged_pool
        } else {
            &self.non_paged_pool
        };

        match quota.charge(amount) {
            Ok(_) => Ok(()),
            Err(_) => Err(-1073741801), // STATUS_QUOTA_EXCEEDED
        }
    }

    /// Return pool quota
    pub fn return_pool_quota(&self, pool_type: PoolType, amount: u64) {
        let quota = if pool_type.is_paged() {
            &self.paged_pool
        } else {
            &self.non_paged_pool
        };
        quota.return_quota(amount);
    }

    /// Charge page file quota
    pub fn charge_pagefile_quota(&self, amount: u64) -> Result<(), i32> {
        match self.page_file.charge(amount) {
            Ok(_) => Ok(()),
            Err(_) => Err(-1073741801), // STATUS_QUOTA_EXCEEDED
        }
    }

    /// Return page file quota
    pub fn return_pagefile_quota(&self, amount: u64) {
        self.page_file.return_quota(amount);
    }

    /// Charge working set quota
    pub fn charge_working_set_quota(&self, amount: u64) -> Result<(), i32> {
        match self.working_set.charge(amount) {
            Ok(_) => Ok(()),
            Err(_) => Err(-1073741801), // STATUS_QUOTA_EXCEEDED
        }
    }

    /// Return working set quota
    pub fn return_working_set_quota(&self, amount: u64) {
        self.working_set.return_quota(amount);
    }
}

impl Default for QuotaBlock {
    fn default() -> Self {
        Self::new(0)
    }
}

// Safety: QuotaBlock uses atomic operations for thread safety
unsafe impl Sync for QuotaBlock {}
unsafe impl Send for QuotaBlock {}

// ============================================================================
// Global Quota Block Pool
// ============================================================================

/// Global pool of quota blocks
static mut QUOTA_BLOCKS: [QuotaBlock; MAX_QUOTA_BLOCKS] = {
    const INIT: QuotaBlock = QuotaBlock::new(0);
    let mut blocks = [INIT; MAX_QUOTA_BLOCKS];
    let mut i = 0;
    while i < MAX_QUOTA_BLOCKS {
        blocks[i] = QuotaBlock::new(i as u32);
        i += 1;
    }
    blocks
};

static QUOTA_LOCK: SpinLock<()> = SpinLock::new(());
static QUOTA_INITIALIZED: AtomicBool = AtomicBool::new(false);

// Statistics
static QUOTA_BLOCKS_ALLOCATED: AtomicU32 = AtomicU32::new(0);
static QUOTA_EXCEEDED_COUNT: AtomicU64 = AtomicU64::new(0);

/// Initialize quota management subsystem
pub fn init() {
    let _guard = QUOTA_LOCK.lock();

    unsafe {
        for (i, block) in QUOTA_BLOCKS.iter_mut().enumerate() {
            *block = QuotaBlock::new(i as u32);
        }
    }

    QUOTA_BLOCKS_ALLOCATED.store(0, Ordering::Relaxed);
    QUOTA_EXCEEDED_COUNT.store(0, Ordering::Relaxed);
    QUOTA_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[PS] Quota management initialized");
}

/// Allocate a new quota block
pub fn allocate_quota_block() -> Option<&'static QuotaBlock> {
    if !QUOTA_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let _guard = QUOTA_LOCK.lock();

    unsafe {
        for block in QUOTA_BLOCKS.iter() {
            if !block.in_use.load(Ordering::Acquire) {
                block.init_default();
                QUOTA_BLOCKS_ALLOCATED.fetch_add(1, Ordering::Relaxed);
                return Some(block);
            }
        }
    }

    None
}

/// Allocate quota block with custom limits
pub fn allocate_quota_block_with_limits(
    paged_limit: u64,
    non_paged_limit: u64,
    pagefile_limit: u64,
    working_set_limit: u64,
) -> Option<&'static QuotaBlock> {
    if !QUOTA_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let _guard = QUOTA_LOCK.lock();

    unsafe {
        for block in QUOTA_BLOCKS.iter() {
            if !block.in_use.load(Ordering::Acquire) {
                block.init_with_limits(paged_limit, non_paged_limit, pagefile_limit, working_set_limit);
                QUOTA_BLOCKS_ALLOCATED.fetch_add(1, Ordering::Relaxed);
                return Some(block);
            }
        }
    }

    None
}

/// Get quota block by ID
pub fn get_quota_block(id: u32) -> Option<&'static QuotaBlock> {
    if id as usize >= MAX_QUOTA_BLOCKS {
        return None;
    }

    unsafe {
        let block = &QUOTA_BLOCKS[id as usize];
        if block.in_use.load(Ordering::Acquire) {
            Some(block)
        } else {
            None
        }
    }
}

/// Release a quota block reference
pub fn release_quota_block(block: &QuotaBlock) {
    if block.release() == 0 {
        QUOTA_BLOCKS_ALLOCATED.fetch_sub(1, Ordering::Relaxed);
    }
}

// ============================================================================
// NT API Compatible Functions
// ============================================================================

/// Charge pool quota to a process (PsChargePoolQuota)
///
/// # Arguments
/// * `process` - Process pointer (unused in current implementation)
/// * `pool_type` - Type of pool being charged
/// * `amount` - Amount to charge
///
/// Returns Ok(()) on success, Err(NTSTATUS) on failure
pub fn ps_charge_pool_quota(
    _process: usize,
    pool_type: PoolType,
    amount: u64,
) -> Result<(), i32> {
    // In a full implementation, this would get the process's quota block
    // For now, use the system default
    if let Some(block) = get_quota_block(0) {
        let result = block.charge_pool_quota(pool_type, amount);
        if result.is_err() {
            QUOTA_EXCEEDED_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        result
    } else {
        // No quota tracking - allow
        Ok(())
    }
}

/// Return pool quota from a process (PsReturnPoolQuota)
pub fn ps_return_pool_quota(
    _process: usize,
    pool_type: PoolType,
    amount: u64,
) {
    if let Some(block) = get_quota_block(0) {
        block.return_pool_quota(pool_type, amount);
    }
}

/// Charge non-paged pool quota (PsChargeProcessNonPagedPoolQuota)
pub fn ps_charge_process_non_paged_pool_quota(
    process: usize,
    amount: u64,
) -> Result<(), i32> {
    ps_charge_pool_quota(process, PoolType::NonPagedPool, amount)
}

/// Return non-paged pool quota (PsReturnProcessNonPagedPoolQuota)
pub fn ps_return_process_non_paged_pool_quota(process: usize, amount: u64) {
    ps_return_pool_quota(process, PoolType::NonPagedPool, amount);
}

/// Charge paged pool quota (PsChargeProcessPagedPoolQuota)
pub fn ps_charge_process_paged_pool_quota(
    process: usize,
    amount: u64,
) -> Result<(), i32> {
    ps_charge_pool_quota(process, PoolType::PagedPool, amount)
}

/// Return paged pool quota (PsReturnProcessPagedPoolQuota)
pub fn ps_return_process_paged_pool_quota(process: usize, amount: u64) {
    ps_return_pool_quota(process, PoolType::PagedPool, amount);
}

/// Charge page file quota (PsChargeProcessPageFileQuota)
pub fn ps_charge_process_page_file_quota(
    _process: usize,
    amount: u64,
) -> Result<(), i32> {
    if let Some(block) = get_quota_block(0) {
        let result = block.charge_pagefile_quota(amount);
        if result.is_err() {
            QUOTA_EXCEEDED_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        result
    } else {
        Ok(())
    }
}

/// Return page file quota (PsReturnProcessPageFileQuota)
pub fn ps_return_process_page_file_quota(_process: usize, amount: u64) {
    if let Some(block) = get_quota_block(0) {
        block.return_pagefile_quota(amount);
    }
}

// ============================================================================
// Quota Information Structures
// ============================================================================

/// Quota limits structure for query/set
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct QuotaLimits {
    /// Paged pool limit
    pub paged_pool_limit: u64,
    /// Non-paged pool limit
    pub non_paged_pool_limit: u64,
    /// Minimum working set
    pub minimum_working_set_size: u64,
    /// Maximum working set
    pub maximum_working_set_size: u64,
    /// Page file limit
    pub page_file_limit: u64,
    /// Time limit (not implemented)
    pub time_limit: i64,
}

/// Extended quota limits (Vista+)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct QuotaLimitsEx {
    /// Base limits
    pub limits: QuotaLimits,
    /// Flags
    pub flags: u32,
    /// CPU rate limit (0-10000 = 0-100%)
    pub cpu_rate_limit: u32,
}

/// Query quota limits for a process
pub fn ps_query_quota_limits(_process: usize) -> QuotaLimits {
    if let Some(block) = get_quota_block(0) {
        QuotaLimits {
            paged_pool_limit: block.paged_pool.get_limit(),
            non_paged_pool_limit: block.non_paged_pool.get_limit(),
            minimum_working_set_size: 0, // Not tracked separately
            maximum_working_set_size: block.working_set.get_limit(),
            page_file_limit: block.page_file.get_limit(),
            time_limit: 0,
        }
    } else {
        QuotaLimits::default()
    }
}

/// Set quota limits for a process
pub fn ps_set_quota_limits(_process: usize, limits: &QuotaLimits) -> Result<(), i32> {
    if let Some(block) = get_quota_block(0) {
        block.paged_pool.set_limit(limits.paged_pool_limit);
        block.non_paged_pool.set_limit(limits.non_paged_pool_limit);
        block.page_file.set_limit(limits.page_file_limit);
        block.working_set.set_limit(limits.maximum_working_set_size);
        Ok(())
    } else {
        Err(-1073741823) // STATUS_UNSUCCESSFUL
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Quota statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct QuotaStats {
    /// Number of quota blocks allocated
    pub blocks_allocated: u32,
    /// Number of times quota was exceeded
    pub exceeded_count: u64,
    /// System-wide paged pool usage
    pub paged_pool_usage: u64,
    /// System-wide paged pool peak
    pub paged_pool_peak: u64,
    /// System-wide non-paged pool usage
    pub non_paged_pool_usage: u64,
    /// System-wide non-paged pool peak
    pub non_paged_pool_peak: u64,
    /// System-wide page file usage
    pub page_file_usage: u64,
    /// System-wide page file peak
    pub page_file_peak: u64,
}

/// Get quota statistics
pub fn get_quota_stats() -> QuotaStats {
    let mut stats = QuotaStats {
        blocks_allocated: QUOTA_BLOCKS_ALLOCATED.load(Ordering::Relaxed),
        exceeded_count: QUOTA_EXCEEDED_COUNT.load(Ordering::Relaxed),
        ..Default::default()
    };

    // Sum up usage across all blocks
    unsafe {
        for block in QUOTA_BLOCKS.iter() {
            if block.in_use.load(Ordering::Relaxed) {
                stats.paged_pool_usage += block.paged_pool.get_usage();
                stats.paged_pool_peak = stats.paged_pool_peak.max(block.paged_pool.get_peak());
                stats.non_paged_pool_usage += block.non_paged_pool.get_usage();
                stats.non_paged_pool_peak = stats.non_paged_pool_peak.max(block.non_paged_pool.get_peak());
                stats.page_file_usage += block.page_file.get_usage();
                stats.page_file_peak = stats.page_file_peak.max(block.page_file.get_peak());
            }
        }
    }

    stats
}

/// Quota block snapshot for inspection
#[derive(Debug, Clone, Copy)]
pub struct QuotaBlockSnapshot {
    /// Block ID
    pub id: u32,
    /// Reference count
    pub reference_count: u32,
    /// Process count
    pub process_count: u32,
    /// Paged pool usage
    pub paged_pool_usage: u64,
    /// Paged pool peak
    pub paged_pool_peak: u64,
    /// Paged pool limit
    pub paged_pool_limit: u64,
    /// Non-paged pool usage
    pub non_paged_pool_usage: u64,
    /// Non-paged pool peak
    pub non_paged_pool_peak: u64,
    /// Non-paged pool limit
    pub non_paged_pool_limit: u64,
    /// Page file usage
    pub page_file_usage: u64,
    /// Page file limit
    pub page_file_limit: u64,
}

/// Get quota block snapshots
pub fn get_quota_block_snapshots() -> [Option<QuotaBlockSnapshot>; MAX_QUOTA_BLOCKS] {
    let mut snapshots = [None; MAX_QUOTA_BLOCKS];

    unsafe {
        for (i, block) in QUOTA_BLOCKS.iter().enumerate() {
            if block.in_use.load(Ordering::Relaxed) {
                snapshots[i] = Some(QuotaBlockSnapshot {
                    id: block.id,
                    reference_count: block.reference_count.load(Ordering::Relaxed),
                    process_count: block.process_count.load(Ordering::Relaxed),
                    paged_pool_usage: block.paged_pool.get_usage(),
                    paged_pool_peak: block.paged_pool.get_peak(),
                    paged_pool_limit: block.paged_pool.get_limit(),
                    non_paged_pool_usage: block.non_paged_pool.get_usage(),
                    non_paged_pool_peak: block.non_paged_pool.get_peak(),
                    non_paged_pool_limit: block.non_paged_pool.get_limit(),
                    page_file_usage: block.page_file.get_usage(),
                    page_file_limit: block.page_file.get_limit(),
                });
            }
        }
    }

    snapshots
}

/// Get count of active quota blocks
pub fn get_quota_block_count() -> u32 {
    QUOTA_BLOCKS_ALLOCATED.load(Ordering::Relaxed)
}
