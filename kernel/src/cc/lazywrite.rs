//! Lazy Writer Implementation
//!
//! The lazy writer is responsible for writing dirty data back to disk in the background.
//! This module implements the NT-compatible lazy write mechanism including:
//!
//! - **Timer-based scanning**: Periodic scans for dirty data
//! - **Work queues**: Express and regular queues for work items
//! - **Dirty page throttling**: Rate-limits writes based on system activity
//! - **Deferred writes**: Queue writes when system is under memory pressure
//! - **Lazy close**: Deferred close of inactive cached files
//!
//! # Key Constants
//!
//! - `LAZY_WRITER_IDLE_DELAY`: Time between scans when idle (1 second)
//! - `LAZY_WRITER_MAX_AGE_TARGET`: Maximum age of dirty data (8 ticks = 8 seconds)
//! - `MAX_WRITE_BEHIND`: Maximum bytes to write per flush (64KB)

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering as AtomicOrdering};
use crate::ke::spinlock::SpinLock;

/// Lazy writer idle delay in 100ns units (1 second)
pub const LAZY_WRITER_IDLE_DELAY: u64 = 10_000_000;

/// First delay after going active (3 seconds)
pub const LAZY_WRITER_FIRST_DELAY: u64 = 30_000_000;

/// Collision delay (100ms)
pub const LAZY_WRITER_COLLISION_DELAY: u64 = 1_000_000;

/// Maximum age target for dirty data (8 ticks)
pub const LAZY_WRITER_MAX_AGE_TARGET: u32 = 8;

/// Maximum write behind size (64KB)
pub const MAX_WRITE_BEHIND: usize = 64 * 1024;

/// Write charge threshold for deferred writes
pub const WRITE_CHARGE_THRESHOLD: u32 = 64 * 1024;

/// Maximum work queue entries
pub const MAX_WORK_QUEUE_ENTRIES: usize = 64;

/// Maximum deferred write entries
pub const MAX_DEFERRED_WRITES: usize = 32;

// ============================================================================
// Work Queue Entry Types
// ============================================================================

/// Work queue function types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkFunction {
    /// Read ahead operation
    ReadAhead = 0,
    /// Write behind operation
    WriteBehind = 1,
    /// Event set operation (for synchronization)
    EventSet = 2,
    /// Lazy write scan
    LazyWriteScan = 3,
    /// Lazy close operation
    LazyClose = 4,
}

impl Default for WorkFunction {
    fn default() -> Self {
        WorkFunction::LazyWriteScan
    }
}

/// Work queue entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WorkQueueEntry {
    /// Function to perform
    pub function: WorkFunction,
    /// Is this entry in use?
    pub in_use: bool,
    /// Cache map index for read/write operations
    pub cache_map_index: usize,
    /// Shared cache map pointer
    pub shared_cache_map: *mut super::SharedCacheMap,
    /// Pages to write
    pub pages_to_write: u32,
    /// Event to signal (for EventSet)
    pub event_signaled: bool,
}

unsafe impl Send for WorkQueueEntry {}
unsafe impl Sync for WorkQueueEntry {}

impl Default for WorkQueueEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkQueueEntry {
    pub const fn new() -> Self {
        Self {
            function: WorkFunction::LazyWriteScan,
            in_use: false,
            cache_map_index: 0,
            shared_cache_map: core::ptr::null_mut(),
            pages_to_write: 0,
            event_signaled: false,
        }
    }

    /// Reset entry for reuse
    pub fn reset(&mut self) {
        self.function = WorkFunction::LazyWriteScan;
        self.in_use = false;
        self.cache_map_index = 0;
        self.shared_cache_map = core::ptr::null_mut();
        self.pages_to_write = 0;
        self.event_signaled = false;
    }
}

// ============================================================================
// Deferred Write Support
// ============================================================================

/// Deferred write entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DeferredWrite {
    /// Is this entry in use?
    pub in_use: bool,
    /// Cache map pointer
    pub shared_cache_map: *mut super::SharedCacheMap,
    /// File offset
    pub file_offset: u64,
    /// Bytes to write
    pub bytes_to_write: u32,
    /// Is this a retry?
    pub retrying: bool,
    /// Queue time
    pub queue_time: u64,
}

unsafe impl Send for DeferredWrite {}
unsafe impl Sync for DeferredWrite {}

impl Default for DeferredWrite {
    fn default() -> Self {
        Self::new()
    }
}

impl DeferredWrite {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            shared_cache_map: core::ptr::null_mut(),
            file_offset: 0,
            bytes_to_write: 0,
            retrying: false,
            queue_time: 0,
        }
    }
}

// ============================================================================
// Lazy Writer State
// ============================================================================

/// Global lazy writer control structure
#[repr(C)]
pub struct LazyWriter {
    /// Is the scan currently active?
    pub scan_active: AtomicBool,
    /// Other work pending (lazy close, etc.)
    pub other_work: AtomicBool,
    /// Scan pass count
    pub scan_pass: AtomicU32,
    /// Last scan time (system ticks)
    pub last_scan_time: AtomicU64,
    /// Next scan time
    pub next_scan_time: AtomicU64,
    /// Total dirty pages in the system
    pub total_dirty_pages: AtomicU32,
    /// Dirty page threshold
    pub dirty_page_threshold: AtomicU32,
    /// Dirty page target
    pub dirty_page_target: AtomicU32,
    /// Pages yet to write this scan
    pub pages_yet_to_write: AtomicU32,
    /// Pages written last time
    pub pages_written_last_time: AtomicU32,
    /// Dirty pages at last scan
    pub dirty_pages_last_scan: AtomicU32,
}

impl Default for LazyWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl LazyWriter {
    pub const fn new() -> Self {
        Self {
            scan_active: AtomicBool::new(false),
            other_work: AtomicBool::new(false),
            scan_pass: AtomicU32::new(0),
            last_scan_time: AtomicU64::new(0),
            next_scan_time: AtomicU64::new(0),
            total_dirty_pages: AtomicU32::new(0),
            dirty_page_threshold: AtomicU32::new(0),
            dirty_page_target: AtomicU32::new(0),
            pages_yet_to_write: AtomicU32::new(0),
            pages_written_last_time: AtomicU32::new(0),
            dirty_pages_last_scan: AtomicU32::new(0),
        }
    }

    /// Check if scan is active
    pub fn is_active(&self) -> bool {
        self.scan_active.load(AtomicOrdering::Acquire)
    }

    /// Set scan active state
    pub fn set_active(&self, active: bool) {
        self.scan_active.store(active, AtomicOrdering::Release);
    }

    /// Increment scan pass
    pub fn increment_pass(&self) -> u32 {
        self.scan_pass.fetch_add(1, AtomicOrdering::AcqRel)
    }

    /// Get current dirty pages
    pub fn dirty_pages(&self) -> u32 {
        self.total_dirty_pages.load(AtomicOrdering::Acquire)
    }

    /// Add dirty pages
    pub fn add_dirty_pages(&self, count: u32) {
        self.total_dirty_pages.fetch_add(count, AtomicOrdering::AcqRel);
    }

    /// Remove dirty pages
    pub fn remove_dirty_pages(&self, count: u32) {
        let current = self.total_dirty_pages.load(AtomicOrdering::Acquire);
        let new_val = current.saturating_sub(count);
        self.total_dirty_pages.store(new_val, AtomicOrdering::Release);
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global lazy writer instance
static LAZY_WRITER: LazyWriter = LazyWriter::new();

/// Express work queue (high priority)
static mut EXPRESS_WORK_QUEUE: [WorkQueueEntry; MAX_WORK_QUEUE_ENTRIES] = {
    const INIT: WorkQueueEntry = WorkQueueEntry::new();
    [INIT; MAX_WORK_QUEUE_ENTRIES]
};

/// Regular work queue
static mut REGULAR_WORK_QUEUE: [WorkQueueEntry; MAX_WORK_QUEUE_ENTRIES] = {
    const INIT: WorkQueueEntry = WorkQueueEntry::new();
    [INIT; MAX_WORK_QUEUE_ENTRIES]
};

/// Express queue head/tail indices
static EXPRESS_QUEUE_HEAD: AtomicU32 = AtomicU32::new(0);
static EXPRESS_QUEUE_TAIL: AtomicU32 = AtomicU32::new(0);

/// Regular queue head/tail indices
static REGULAR_QUEUE_HEAD: AtomicU32 = AtomicU32::new(0);
static REGULAR_QUEUE_TAIL: AtomicU32 = AtomicU32::new(0);

/// Deferred writes queue
static mut DEFERRED_WRITES: [DeferredWrite; MAX_DEFERRED_WRITES] = {
    const INIT: DeferredWrite = DeferredWrite::new();
    [INIT; MAX_DEFERRED_WRITES]
};

/// Deferred writes count
static DEFERRED_WRITE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Work queue lock
static WORK_QUEUE_LOCK: SpinLock<()> = SpinLock::new(());

/// Lazy writer statistics
static mut LAZY_WRITER_STATS: LazyWriterStats = LazyWriterStats::new();

/// Lazy writer statistics
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LazyWriterStats {
    /// Number of scans performed
    pub scans: u64,
    /// Total pages written
    pub pages_written: u64,
    /// Total write operations
    pub write_ios: u64,
    /// Hot spot detections
    pub hot_spots: u64,
    /// Data flushes
    pub data_flushes: u64,
    /// Deferred writes queued
    pub deferred_writes: u64,
    /// Deferred writes completed
    pub deferred_completed: u64,
    /// Lost delayed writes (errors)
    pub lost_delayed_writes: u64,
    /// Lazy closes performed
    pub lazy_closes: u64,
}

impl Default for LazyWriterStats {
    fn default() -> Self {
        Self::new()
    }
}

impl LazyWriterStats {
    pub const fn new() -> Self {
        Self {
            scans: 0,
            pages_written: 0,
            write_ios: 0,
            hot_spots: 0,
            data_flushes: 0,
            deferred_writes: 0,
            deferred_completed: 0,
            lost_delayed_writes: 0,
            lazy_closes: 0,
        }
    }
}

// ============================================================================
// Work Queue Management
// ============================================================================

/// Allocate a work queue entry from the pool
fn allocate_work_queue_entry() -> Option<usize> {
    let _guard = WORK_QUEUE_LOCK.lock();

    unsafe {
        // First try regular queue pool
        for i in 0..MAX_WORK_QUEUE_ENTRIES {
            if !REGULAR_WORK_QUEUE[i].in_use {
                REGULAR_WORK_QUEUE[i].in_use = true;
                return Some(i);
            }
        }
    }

    None
}

/// Free a work queue entry
fn free_work_queue_entry(index: usize) {
    let _guard = WORK_QUEUE_LOCK.lock();

    unsafe {
        if index < MAX_WORK_QUEUE_ENTRIES {
            REGULAR_WORK_QUEUE[index].reset();
        }
    }
}

/// Post a work item to a queue
pub fn post_work_queue(entry_index: usize, express: bool) {
    let _guard = WORK_QUEUE_LOCK.lock();

    if express {
        let tail = EXPRESS_QUEUE_TAIL.load(AtomicOrdering::Acquire);
        let new_tail = (tail + 1) % MAX_WORK_QUEUE_ENTRIES as u32;
        EXPRESS_QUEUE_TAIL.store(new_tail, AtomicOrdering::Release);
    } else {
        let tail = REGULAR_QUEUE_TAIL.load(AtomicOrdering::Acquire);
        let new_tail = (tail + 1) % MAX_WORK_QUEUE_ENTRIES as u32;
        REGULAR_QUEUE_TAIL.store(new_tail, AtomicOrdering::Release);
    }

    let _ = entry_index;
}

/// Read the next work item from the queue
pub fn read_work_queue() -> Option<usize> {
    let _guard = WORK_QUEUE_LOCK.lock();

    // First check express queue
    let express_head = EXPRESS_QUEUE_HEAD.load(AtomicOrdering::Acquire);
    let express_tail = EXPRESS_QUEUE_TAIL.load(AtomicOrdering::Acquire);

    if express_head != express_tail {
        let new_head = (express_head + 1) % MAX_WORK_QUEUE_ENTRIES as u32;
        EXPRESS_QUEUE_HEAD.store(new_head, AtomicOrdering::Release);
        return Some(express_head as usize);
    }

    // Then check regular queue
    let regular_head = REGULAR_QUEUE_HEAD.load(AtomicOrdering::Acquire);
    let regular_tail = REGULAR_QUEUE_TAIL.load(AtomicOrdering::Acquire);

    if regular_head != regular_tail {
        let new_head = (regular_head + 1) % MAX_WORK_QUEUE_ENTRIES as u32;
        REGULAR_QUEUE_HEAD.store(new_head, AtomicOrdering::Release);
        return Some(regular_head as usize);
    }

    None
}

// ============================================================================
// Lazy Writer Scan
// ============================================================================

/// Schedule the next lazy write scan
pub fn schedule_lazy_write_scan(fast_scan: bool) {
    if fast_scan {
        LAZY_WRITER.set_active(true);
        LAZY_WRITER.next_scan_time.store(0, AtomicOrdering::Release);
    } else if LAZY_WRITER.is_active() {
        // Schedule idle delay
        let current = LAZY_WRITER.last_scan_time.load(AtomicOrdering::Acquire);
        LAZY_WRITER.next_scan_time.store(current + LAZY_WRITER_IDLE_DELAY, AtomicOrdering::Release);
    } else {
        // Going from idle to active - use first delay
        LAZY_WRITER.set_active(true);
        let current = LAZY_WRITER.last_scan_time.load(AtomicOrdering::Acquire);
        LAZY_WRITER.next_scan_time.store(current + LAZY_WRITER_FIRST_DELAY, AtomicOrdering::Release);
    }
}

/// Perform lazy write scan
///
/// This is the main lazy writer routine that scans for dirty data
/// and queues write operations.
pub unsafe fn lazy_write_scan() {
    LAZY_WRITER_STATS.scans += 1;
    LAZY_WRITER.increment_pass();

    let total_dirty = LAZY_WRITER.dirty_pages();
    let other_work = LAZY_WRITER.other_work.load(AtomicOrdering::Acquire);

    // If no work to do, go inactive
    if total_dirty == 0 && !other_work {
        // Check for deferred writes
        if DEFERRED_WRITE_COUNT.load(AtomicOrdering::Acquire) == 0 {
            LAZY_WRITER.set_active(false);
            return;
        } else {
            // Process deferred writes
            post_deferred_writes();
            schedule_lazy_write_scan(false);
            return;
        }
    }

    LAZY_WRITER.other_work.store(false, AtomicOrdering::Release);

    // Calculate pages to write
    let mut pages_to_write = total_dirty;
    if pages_to_write > LAZY_WRITER_MAX_AGE_TARGET {
        pages_to_write /= LAZY_WRITER_MAX_AGE_TARGET;
    }

    // Estimate foreground rate
    let dirty_last_scan = LAZY_WRITER.dirty_pages_last_scan.load(AtomicOrdering::Acquire);
    let written_last_time = LAZY_WRITER.pages_written_last_time.load(AtomicOrdering::Acquire);

    let foreground_rate = if (total_dirty + written_last_time) > dirty_last_scan {
        (total_dirty + written_last_time) - dirty_last_scan
    } else {
        0
    };

    // Adjust for dirty page target
    let dirty_target = LAZY_WRITER.dirty_page_target.load(AtomicOrdering::Acquire);
    let estimated_next = total_dirty.saturating_sub(pages_to_write) + foreground_rate;

    if estimated_next > dirty_target && dirty_target > 0 {
        pages_to_write += estimated_next - dirty_target;
    }

    // Save state for next scan
    LAZY_WRITER.dirty_pages_last_scan.store(total_dirty, AtomicOrdering::Release);
    LAZY_WRITER.pages_yet_to_write.store(pages_to_write, AtomicOrdering::Release);
    LAZY_WRITER.pages_written_last_time.store(pages_to_write, AtomicOrdering::Release);

    // Scan cache maps for dirty data
    let _guard = super::CACHE_LOCK.lock();

    for i in 0..super::MAX_CACHED_FILES {
        if super::CACHE_MAP_BITMAP & (1 << i) != 0 {
            let map = &mut super::CACHE_MAP_POOL[i];

            if !map.valid {
                continue;
            }

            // Check for dirty VACBs
            let mut map_dirty_pages = 0u32;
            for vacb in map.vacbs.iter() {
                if vacb.is_dirty() {
                    map_dirty_pages += vacb.dirty_pages.count_ones();
                }
            }

            if map_dirty_pages > 0 && pages_to_write > 0 {
                // Queue write behind for this cache map
                if let Some(entry_idx) = allocate_work_queue_entry() {
                    REGULAR_WORK_QUEUE[entry_idx].function = WorkFunction::WriteBehind;
                    REGULAR_WORK_QUEUE[entry_idx].cache_map_index = i;
                    REGULAR_WORK_QUEUE[entry_idx].shared_cache_map = map as *mut super::SharedCacheMap;
                    REGULAR_WORK_QUEUE[entry_idx].pages_to_write = map_dirty_pages.min(pages_to_write);

                    post_work_queue(entry_idx, false);

                    pages_to_write = pages_to_write.saturating_sub(map_dirty_pages);

                    LAZY_WRITER_STATS.write_ios += 1;
                }
            }

            // Check for lazy close candidates (no dirty data, zero refs)
            if map_dirty_pages == 0 {
                let mut can_close = true;
                for vacb in map.vacbs.iter() {
                    if vacb.ref_count > 0 {
                        can_close = false;
                        break;
                    }
                }

                if can_close && !map.file_object.is_null() {
                    // Queue lazy close
                    if let Some(entry_idx) = allocate_work_queue_entry() {
                        REGULAR_WORK_QUEUE[entry_idx].function = WorkFunction::LazyClose;
                        REGULAR_WORK_QUEUE[entry_idx].cache_map_index = i;
                        REGULAR_WORK_QUEUE[entry_idx].shared_cache_map = map as *mut super::SharedCacheMap;

                        post_work_queue(entry_idx, false);
                        LAZY_WRITER_STATS.lazy_closes += 1;
                    }
                }
            }
        }
    }

    // Process any deferred writes
    if DEFERRED_WRITE_COUNT.load(AtomicOrdering::Acquire) > 0 {
        drop(_guard);
        post_deferred_writes();
    }

    // Schedule next scan
    schedule_lazy_write_scan(false);
}

/// Write behind for a cache map
pub unsafe fn write_behind(cache_map: *mut super::SharedCacheMap, pages_to_write: u32) -> bool {
    if cache_map.is_null() {
        return false;
    }

    let map = &mut *cache_map;
    let mut pages_written = 0u32;

    // Flush dirty VACBs
    for i in 0..super::MAX_VACBS_PER_FILE {
        if pages_written >= pages_to_write {
            break;
        }

        let vacb = &mut map.vacbs[i];
        if vacb.is_dirty() && vacb.ref_count == 0 {
            let dirty_count = vacb.dirty_pages.count_ones();

            // Simulate write to disk
            // In full implementation, would build IRP and send to file system
            vacb.clear_dirty();

            pages_written += dirty_count;
            LAZY_WRITER_STATS.pages_written += dirty_count as u64;
        }
    }

    // Update dirty page count
    LAZY_WRITER.remove_dirty_pages(pages_written);

    if pages_written > 0 {
        LAZY_WRITER_STATS.data_flushes += 1;
    }

    true
}

// ============================================================================
// Deferred Write Support
// ============================================================================

/// Queue a deferred write
pub fn queue_deferred_write(
    cache_map: *mut super::SharedCacheMap,
    file_offset: u64,
    bytes_to_write: u32,
    retrying: bool,
) -> bool {
    let _guard = WORK_QUEUE_LOCK.lock();

    unsafe {
        for i in 0..MAX_DEFERRED_WRITES {
            if !DEFERRED_WRITES[i].in_use {
                DEFERRED_WRITES[i].in_use = true;
                DEFERRED_WRITES[i].shared_cache_map = cache_map;
                DEFERRED_WRITES[i].file_offset = file_offset;
                DEFERRED_WRITES[i].bytes_to_write = bytes_to_write;
                DEFERRED_WRITES[i].retrying = retrying;
                DEFERRED_WRITES[i].queue_time = 0; // Would get from HAL

                DEFERRED_WRITE_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
                LAZY_WRITER_STATS.deferred_writes += 1;

                // Wake up lazy writer if not active
                if !LAZY_WRITER.is_active() {
                    schedule_lazy_write_scan(true);
                }

                return true;
            }
        }
    }

    false
}

/// Post deferred writes when resources are available
pub unsafe fn post_deferred_writes() {
    let _guard = WORK_QUEUE_LOCK.lock();

    for i in 0..MAX_DEFERRED_WRITES {
        if DEFERRED_WRITES[i].in_use {
            // Check if we can write now
            let can_write = cc_can_i_write_internal(
                DEFERRED_WRITES[i].shared_cache_map,
                DEFERRED_WRITES[i].bytes_to_write,
            );

            if can_write {
                // Process this deferred write
                if let Some(entry_idx) = allocate_work_queue_entry() {
                    REGULAR_WORK_QUEUE[entry_idx].function = WorkFunction::WriteBehind;
                    REGULAR_WORK_QUEUE[entry_idx].shared_cache_map = DEFERRED_WRITES[i].shared_cache_map;
                    REGULAR_WORK_QUEUE[entry_idx].pages_to_write =
                        (DEFERRED_WRITES[i].bytes_to_write + super::CACHE_PAGE_SIZE as u32 - 1)
                        / super::CACHE_PAGE_SIZE as u32;

                    post_work_queue(entry_idx, false);
                }

                // Clear deferred write entry
                DEFERRED_WRITES[i].in_use = false;
                DEFERRED_WRITE_COUNT.fetch_sub(1, AtomicOrdering::AcqRel);
                LAZY_WRITER_STATS.deferred_completed += 1;
            }
        }
    }
}

/// Check if a write can proceed (internal version without callback)
fn cc_can_i_write_internal(cache_map: *mut super::SharedCacheMap, bytes_to_write: u32) -> bool {
    // Check dirty page threshold
    let dirty_pages = LAZY_WRITER.dirty_pages();
    let threshold = LAZY_WRITER.dirty_page_threshold.load(AtomicOrdering::Acquire);

    if threshold > 0 && dirty_pages > threshold {
        return false;
    }

    // Check if system has enough memory
    // In full implementation, would check available pages

    // For now, allow small writes
    bytes_to_write <= WRITE_CHARGE_THRESHOLD || cache_map.is_null()
}

/// Check if a write can proceed
pub fn cc_can_i_write(
    cache_map: *mut super::SharedCacheMap,
    bytes_to_write: u32,
    wait: bool,
    retrying: bool,
) -> bool {
    let can_write = cc_can_i_write_internal(cache_map, bytes_to_write);

    if !can_write && wait {
        // Queue as deferred write
        queue_deferred_write(cache_map, 0, bytes_to_write, retrying);
        return false;
    }

    can_write
}

/// Defer a write with callback
pub fn cc_defer_write(
    cache_map: *mut super::SharedCacheMap,
    bytes_to_write: u32,
    retrying: bool,
) {
    queue_deferred_write(cache_map, 0, bytes_to_write, retrying);
}

// ============================================================================
// Lazy Writer Control
// ============================================================================

/// Wait for current lazy writer activity to complete
pub fn cc_wait_for_current_lazy_writer_activity() -> i32 {
    // In full implementation, would queue an EventSet work item
    // and wait for it to complete

    // For now, just trigger a fast scan and return
    schedule_lazy_write_scan(true);
    0 // STATUS_SUCCESS
}

/// Set dirty page threshold
pub fn set_dirty_page_threshold(threshold: u32) {
    LAZY_WRITER.dirty_page_threshold.store(threshold, AtomicOrdering::Release);
}

/// Set dirty page target
pub fn set_dirty_page_target(target: u32) {
    LAZY_WRITER.dirty_page_target.store(target, AtomicOrdering::Release);
}

/// Get lazy writer reference
pub fn get_lazy_writer() -> &'static LazyWriter {
    &LAZY_WRITER
}

/// Get lazy writer statistics
pub fn get_stats() -> LazyWriterStats {
    unsafe { LAZY_WRITER_STATS }
}

/// Get deferred write count
pub fn get_deferred_write_count() -> u32 {
    DEFERRED_WRITE_COUNT.load(AtomicOrdering::Acquire)
}

// ============================================================================
// Lazy Writer Tick (called from timer/scheduler)
// ============================================================================

/// Lazy writer tick - called periodically from scheduler
pub unsafe fn lazy_writer_tick() {
    // Check if scan is due
    let current_time = LAZY_WRITER.last_scan_time.load(AtomicOrdering::Acquire);
    let next_scan = LAZY_WRITER.next_scan_time.load(AtomicOrdering::Acquire);

    // Update time (simulated - would come from HAL)
    LAZY_WRITER.last_scan_time.store(current_time + 1, AtomicOrdering::Release);

    if LAZY_WRITER.is_active() && current_time >= next_scan {
        lazy_write_scan();
    } else if !LAZY_WRITER.is_active() {
        // Check if we need to wake up
        let dirty_pages = LAZY_WRITER.dirty_pages();
        let threshold = LAZY_WRITER.dirty_page_threshold.load(AtomicOrdering::Acquire);

        if dirty_pages > 0 || DEFERRED_WRITE_COUNT.load(AtomicOrdering::Acquire) > 0 {
            schedule_lazy_write_scan(false);
        } else if threshold > 0 && dirty_pages > threshold / 2 {
            // Wake up early if getting close to threshold
            schedule_lazy_write_scan(false);
        }
    }

    // Process work queue
    while let Some(entry_idx) = read_work_queue() {
        if entry_idx < MAX_WORK_QUEUE_ENTRIES {
            let entry = &REGULAR_WORK_QUEUE[entry_idx];

            match entry.function {
                WorkFunction::WriteBehind => {
                    write_behind(entry.shared_cache_map, entry.pages_to_write);
                }
                WorkFunction::LazyWriteScan => {
                    lazy_write_scan();
                }
                WorkFunction::LazyClose => {
                    // Would uninitialize the cache map
                    // For now, just mark as closed
                    LAZY_WRITER_STATS.lazy_closes += 1;
                }
                WorkFunction::EventSet => {
                    // Would signal event
                }
                WorkFunction::ReadAhead => {
                    // Would perform read ahead
                }
            }

            free_work_queue_entry(entry_idx);
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the lazy writer
pub fn init() {
    // Calculate dirty page threshold based on available memory
    // For now, use a fixed value
    let threshold = (super::MAX_CACHE_SIZE / super::CACHE_PAGE_SIZE) as u32;
    LAZY_WRITER.dirty_page_threshold.store(threshold, AtomicOrdering::Release);
    LAZY_WRITER.dirty_page_target.store(threshold / 2, AtomicOrdering::Release);

    unsafe {
        LAZY_WRITER_STATS = LazyWriterStats::new();

        // Initialize work queues
        for entry in EXPRESS_WORK_QUEUE.iter_mut() {
            *entry = WorkQueueEntry::new();
        }
        for entry in REGULAR_WORK_QUEUE.iter_mut() {
            *entry = WorkQueueEntry::new();
        }
        for entry in DEFERRED_WRITES.iter_mut() {
            *entry = DeferredWrite::new();
        }
    }

    EXPRESS_QUEUE_HEAD.store(0, AtomicOrdering::Release);
    EXPRESS_QUEUE_TAIL.store(0, AtomicOrdering::Release);
    REGULAR_QUEUE_HEAD.store(0, AtomicOrdering::Release);
    REGULAR_QUEUE_TAIL.store(0, AtomicOrdering::Release);
    DEFERRED_WRITE_COUNT.store(0, AtomicOrdering::Release);

    crate::serial_println!("[CC] Lazy writer initialized");
}
