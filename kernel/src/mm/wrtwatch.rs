//! Write Watch Support
//!
//! Write watch allows tracking which pages in a memory region have been
//! written to. This is useful for:
//! - Garbage collection (tracking modified pages)
//! - Live migration (tracking dirty pages)
//! - Memory debugging and profiling
//! - Checkpoint/restore functionality
//!
//! # Architecture
//!
//! Each write-watched VAD has an associated bitmap where each bit represents
//! a page. When a page is written to, the corresponding bit is set. The
//! NtGetWriteWatch syscall returns the list of written pages, and
//! NtResetWriteWatch clears the tracking bits.
//!
//! # Implementation
//!
//! Write watch works by:
//! 1. Allocating memory with MEM_WRITE_WATCH flag
//! 2. The MM tracks writes via PTE dirty bits
//! 3. When dirty bits are captured (page out, protection change), they
//!    are recorded in the write watch bitmap
//! 4. Applications query/reset the bitmap via syscalls
//!
//! # NT API
//!
//! - NtGetWriteWatch: Get list of written pages
//! - NtResetWriteWatch: Reset write watch bits for a range

use core::ptr;
use crate::ke::SpinLock;
use crate::mm::{PAGE_SIZE, vad_flags, allocation_type};

/// Write watch flag for NtGetWriteWatch - reset bits after query
pub const WRITE_WATCH_FLAG_RESET: u32 = 0x01;

/// Maximum number of write watch regions
pub const MAX_WRITE_WATCH_REGIONS: usize = 64;

/// Maximum pages per write watch region (supports up to 16GB regions)
pub const MAX_WRITE_WATCH_PAGES: usize = 4 * 1024 * 1024;

/// Bitmap storage for write watch (packed u64s)
const BITMAP_WORDS_PER_REGION: usize = MAX_WRITE_WATCH_PAGES / 64;

/// Write watch region descriptor
#[repr(C)]
pub struct WriteWatchRegion {
    /// VAD index this region belongs to
    pub vad_index: u32,
    /// Process ID
    pub process_id: u32,
    /// Starting virtual page number
    pub starting_vpn: u64,
    /// Ending virtual page number (inclusive)
    pub ending_vpn: u64,
    /// Number of pages tracked
    pub page_count: u64,
    /// Write watch bitmap (one bit per page)
    /// Stored externally due to size
    pub bitmap_index: usize,
    /// Is this region active?
    pub active: bool,
    /// Statistics: total writes captured
    pub total_writes_captured: u64,
    /// Statistics: total resets
    pub total_resets: u64,
}

impl WriteWatchRegion {
    pub const fn new() -> Self {
        Self {
            vad_index: u32::MAX,
            process_id: 0,
            starting_vpn: 0,
            ending_vpn: 0,
            page_count: 0,
            bitmap_index: usize::MAX,
            active: false,
            total_writes_captured: 0,
            total_resets: 0,
        }
    }

    /// Convert virtual address to bitmap index
    pub fn va_to_bitmap_index(&self, virt_addr: u64) -> Option<usize> {
        let vpn = virt_addr >> 12;
        if vpn >= self.starting_vpn && vpn <= self.ending_vpn {
            Some((vpn - self.starting_vpn) as usize)
        } else {
            None
        }
    }

    /// Get the page count in this region
    pub fn page_count(&self) -> usize {
        (self.ending_vpn - self.starting_vpn + 1) as usize
    }
}

impl Default for WriteWatchRegion {
    fn default() -> Self {
        Self::new()
    }
}

/// Write watch bitmap storage
/// We use a separate pool for bitmaps to avoid bloating the region struct
#[repr(C)]
pub struct WriteWatchBitmap {
    /// Bitmap words (64 pages per word)
    pub words: [u64; BITMAP_WORDS_PER_REGION],
    /// Is this bitmap allocated?
    pub allocated: bool,
}

impl WriteWatchBitmap {
    pub const fn new() -> Self {
        Self {
            words: [0; BITMAP_WORDS_PER_REGION],
            allocated: false,
        }
    }

    /// Set a bit (mark page as written)
    pub fn set_bit(&mut self, index: usize) {
        if index < MAX_WRITE_WATCH_PAGES {
            let word_idx = index / 64;
            let bit_idx = index % 64;
            self.words[word_idx] |= 1u64 << bit_idx;
        }
    }

    /// Clear a bit
    pub fn clear_bit(&mut self, index: usize) {
        if index < MAX_WRITE_WATCH_PAGES {
            let word_idx = index / 64;
            let bit_idx = index % 64;
            self.words[word_idx] &= !(1u64 << bit_idx);
        }
    }

    /// Check if a bit is set
    pub fn test_bit(&self, index: usize) -> bool {
        if index < MAX_WRITE_WATCH_PAGES {
            let word_idx = index / 64;
            let bit_idx = index % 64;
            (self.words[word_idx] & (1u64 << bit_idx)) != 0
        } else {
            false
        }
    }

    /// Clear a range of bits
    pub fn clear_range(&mut self, start: usize, count: usize) {
        let end = (start + count).min(MAX_WRITE_WATCH_PAGES);
        for i in start..end {
            self.clear_bit(i);
        }
    }

    /// Clear all bits
    pub fn clear_all(&mut self) {
        for word in self.words.iter_mut() {
            *word = 0;
        }
    }

    /// Count set bits in a range
    pub fn count_set_bits(&self, start: usize, count: usize) -> usize {
        let end = (start + count).min(MAX_WRITE_WATCH_PAGES);
        let mut total = 0;

        // Handle partial first word
        let first_word = start / 64;
        let last_word = (end - 1) / 64;

        if first_word == last_word {
            // All in one word
            let mask = ((1u64 << (end - start)) - 1) << (start % 64);
            return (self.words[first_word] & mask).count_ones() as usize;
        }

        // First partial word
        let first_bit = start % 64;
        if first_bit != 0 {
            let mask = !((1u64 << first_bit) - 1);
            total += (self.words[first_word] & mask).count_ones() as usize;
        } else {
            total += self.words[first_word].count_ones() as usize;
        }

        // Full words in the middle
        for word_idx in (first_word + 1)..last_word {
            total += self.words[word_idx].count_ones() as usize;
        }

        // Last partial word
        let last_bit = end % 64;
        if last_bit != 0 {
            let mask = (1u64 << last_bit) - 1;
            total += (self.words[last_word] & mask).count_ones() as usize;
        } else if last_word > first_word {
            total += self.words[last_word].count_ones() as usize;
        }

        total
    }

    /// Find the next set bit starting from index
    pub fn find_next_set_bit(&self, start: usize, max_pages: usize) -> Option<usize> {
        let end = max_pages.min(MAX_WRITE_WATCH_PAGES);
        let mut index = start;

        while index < end {
            let word_idx = index / 64;
            let bit_idx = index % 64;

            // Check remaining bits in current word
            let word = self.words[word_idx] >> bit_idx;
            if word != 0 {
                return Some(index + word.trailing_zeros() as usize);
            }

            // Move to next word
            index = (word_idx + 1) * 64;
        }

        None
    }
}

impl Default for WriteWatchBitmap {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Write watch region pool
static mut WRITE_WATCH_REGIONS: [WriteWatchRegion; MAX_WRITE_WATCH_REGIONS] = {
    const INIT: WriteWatchRegion = WriteWatchRegion::new();
    [INIT; MAX_WRITE_WATCH_REGIONS]
};

/// Write watch bitmap pool (separate due to size)
/// Using a smaller pool since bitmaps are large
const MAX_BITMAPS: usize = 16;
static mut WRITE_WATCH_BITMAPS: [WriteWatchBitmap; MAX_BITMAPS] = {
    const INIT: WriteWatchBitmap = WriteWatchBitmap::new();
    [INIT; MAX_BITMAPS]
};

/// Global lock for write watch operations
static WRITE_WATCH_LOCK: SpinLock<()> = SpinLock::new(());

/// Statistics
static mut WRITE_WATCH_STATS: WriteWatchStats = WriteWatchStats::new();

/// Write watch statistics
#[derive(Debug, Clone, Copy)]
pub struct WriteWatchStats {
    pub active_regions: u32,
    pub total_regions_created: u64,
    pub total_writes_captured: u64,
    pub total_queries: u64,
    pub total_resets: u64,
}

impl WriteWatchStats {
    pub const fn new() -> Self {
        Self {
            active_regions: 0,
            total_regions_created: 0,
            total_writes_captured: 0,
            total_queries: 0,
            total_resets: 0,
        }
    }
}

impl Default for WriteWatchStats {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Write Watch API
// ============================================================================

/// Create a write watch region for a VAD
///
/// Called when memory is allocated with MEM_WRITE_WATCH.
pub unsafe fn mi_create_write_watch_region(
    vad_index: u32,
    process_id: u32,
    starting_vpn: u64,
    ending_vpn: u64,
) -> Option<usize> {
    let _guard = WRITE_WATCH_LOCK.lock();

    let page_count = ending_vpn - starting_vpn + 1;
    if page_count > MAX_WRITE_WATCH_PAGES as u64 {
        return None;
    }

    // Find a free region slot
    let region_idx = WRITE_WATCH_REGIONS.iter()
        .position(|r| !r.active)?;

    // Find a free bitmap
    let bitmap_idx = WRITE_WATCH_BITMAPS.iter()
        .position(|b| !b.allocated)?;

    // Initialize the bitmap
    WRITE_WATCH_BITMAPS[bitmap_idx].allocated = true;
    WRITE_WATCH_BITMAPS[bitmap_idx].clear_all();

    // Initialize the region
    let region = &mut WRITE_WATCH_REGIONS[region_idx];
    region.vad_index = vad_index;
    region.process_id = process_id;
    region.starting_vpn = starting_vpn;
    region.ending_vpn = ending_vpn;
    region.page_count = page_count;
    region.bitmap_index = bitmap_idx;
    region.active = true;
    region.total_writes_captured = 0;
    region.total_resets = 0;

    WRITE_WATCH_STATS.active_regions += 1;
    WRITE_WATCH_STATS.total_regions_created += 1;

    Some(region_idx)
}

/// Destroy a write watch region
pub unsafe fn mi_destroy_write_watch_region(region_idx: usize) {
    let _guard = WRITE_WATCH_LOCK.lock();

    if region_idx >= MAX_WRITE_WATCH_REGIONS {
        return;
    }

    let region = &mut WRITE_WATCH_REGIONS[region_idx];
    if !region.active {
        return;
    }

    // Free the bitmap
    if region.bitmap_index < MAX_BITMAPS {
        WRITE_WATCH_BITMAPS[region.bitmap_index].allocated = false;
    }

    // Clear the region
    region.active = false;
    region.vad_index = u32::MAX;
    region.bitmap_index = usize::MAX;

    if WRITE_WATCH_STATS.active_regions > 0 {
        WRITE_WATCH_STATS.active_regions -= 1;
    }
}

/// Find write watch region by VAD
pub unsafe fn mi_find_write_watch_region(
    process_id: u32,
    virt_addr: u64,
) -> Option<usize> {
    let vpn = virt_addr >> 12;

    for (idx, region) in WRITE_WATCH_REGIONS.iter().enumerate() {
        if region.active &&
           region.process_id == process_id &&
           vpn >= region.starting_vpn &&
           vpn <= region.ending_vpn
        {
            return Some(idx);
        }
    }

    None
}

/// Capture a dirty bit to the write watch bitmap
///
/// Called when a page is made non-dirty (page-out, protection change, etc.)
/// and the dirty bit needs to be preserved in the write watch bitmap.
pub unsafe fn mi_capture_write_watch_dirty_bit(
    process_id: u32,
    virt_addr: u64,
) {
    let _guard = WRITE_WATCH_LOCK.lock();

    // Find the write watch region containing this address
    let region_idx = match mi_find_write_watch_region_unlocked(process_id, virt_addr) {
        Some(idx) => idx,
        None => return,
    };

    let region = &mut WRITE_WATCH_REGIONS[region_idx];
    let vpn = virt_addr >> 12;
    let bitmap_idx = (vpn - region.starting_vpn) as usize;

    if region.bitmap_index < MAX_BITMAPS {
        WRITE_WATCH_BITMAPS[region.bitmap_index].set_bit(bitmap_idx);
        region.total_writes_captured += 1;
        WRITE_WATCH_STATS.total_writes_captured += 1;
    }
}

/// Internal: Find region without taking lock
unsafe fn mi_find_write_watch_region_unlocked(
    process_id: u32,
    virt_addr: u64,
) -> Option<usize> {
    let vpn = virt_addr >> 12;

    for (idx, region) in WRITE_WATCH_REGIONS.iter().enumerate() {
        if region.active &&
           region.process_id == process_id &&
           vpn >= region.starting_vpn &&
           vpn <= region.ending_vpn
        {
            return Some(idx);
        }
    }

    None
}

/// Get write watch information for a range
///
/// Returns the addresses of pages that have been written to.
/// If WRITE_WATCH_FLAG_RESET is set, also resets the bits.
pub unsafe fn nt_get_write_watch(
    process_id: u32,
    flags: u32,
    base_address: u64,
    region_size: u64,
    user_address_array: *mut u64,
    entries_count: *mut u64,
    granularity: *mut u32,
) -> i32 {
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_INVALID_PARAMETER_1: i32 = -1073741811_i32; // 0xC000000D
    const STATUS_INVALID_PARAMETER_2: i32 = -1073741810_i32;

    if user_address_array.is_null() || entries_count.is_null() || granularity.is_null() {
        return STATUS_INVALID_PARAMETER_1;
    }

    // Validate flags
    if (flags & !WRITE_WATCH_FLAG_RESET) != 0 {
        return STATUS_INVALID_PARAMETER_2;
    }

    let _guard = WRITE_WATCH_LOCK.lock();

    // Find the write watch region
    let region_idx = match mi_find_write_watch_region_unlocked(process_id, base_address) {
        Some(idx) => idx,
        None => return STATUS_INVALID_PARAMETER_1,
    };

    let region = &mut WRITE_WATCH_REGIONS[region_idx];

    // Verify the entire range is within this region
    let end_address = base_address + region_size - 1;
    let start_vpn = base_address >> 12;
    let end_vpn = end_address >> 12;

    if start_vpn < region.starting_vpn || end_vpn > region.ending_vpn {
        return STATUS_INVALID_PARAMETER_1;
    }

    let max_entries = *entries_count as usize;
    let bitmap_idx = region.bitmap_index;

    if bitmap_idx >= MAX_BITMAPS {
        return STATUS_INVALID_PARAMETER_1;
    }

    let bitmap = &mut WRITE_WATCH_BITMAPS[bitmap_idx];
    let mut entries_written = 0usize;
    let mut current_bit = (start_vpn - region.starting_vpn) as usize;
    let end_bit = (end_vpn - region.starting_vpn) as usize;

    // Find all set bits in the range
    while entries_written < max_entries && current_bit <= end_bit {
        if bitmap.test_bit(current_bit) {
            // Record this address
            let page_addr = (region.starting_vpn + current_bit as u64) << 12;
            *user_address_array.add(entries_written) = page_addr;
            entries_written += 1;

            // Reset if requested
            if (flags & WRITE_WATCH_FLAG_RESET) != 0 {
                bitmap.clear_bit(current_bit);
            }
        }
        current_bit += 1;
    }

    *entries_count = entries_written as u64;
    *granularity = PAGE_SIZE as u32;

    WRITE_WATCH_STATS.total_queries += 1;

    if (flags & WRITE_WATCH_FLAG_RESET) != 0 {
        region.total_resets += 1;
        WRITE_WATCH_STATS.total_resets += 1;
    }

    STATUS_SUCCESS
}

/// Reset write watch information for a range
///
/// Clears the write watch bits for all pages in the specified range.
pub unsafe fn nt_reset_write_watch(
    process_id: u32,
    base_address: u64,
    region_size: u64,
) -> i32 {
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_INVALID_PARAMETER_1: i32 = -1073741811_i32;

    let _guard = WRITE_WATCH_LOCK.lock();

    // Find the write watch region
    let region_idx = match mi_find_write_watch_region_unlocked(process_id, base_address) {
        Some(idx) => idx,
        None => return STATUS_INVALID_PARAMETER_1,
    };

    let region = &mut WRITE_WATCH_REGIONS[region_idx];

    // Verify the entire range is within this region
    let end_address = base_address + region_size - 1;
    let start_vpn = base_address >> 12;
    let end_vpn = end_address >> 12;

    if start_vpn < region.starting_vpn || end_vpn > region.ending_vpn {
        return STATUS_INVALID_PARAMETER_1;
    }

    let bitmap_idx = region.bitmap_index;
    if bitmap_idx >= MAX_BITMAPS {
        return STATUS_INVALID_PARAMETER_1;
    }

    let bitmap = &mut WRITE_WATCH_BITMAPS[bitmap_idx];

    // Clear the range
    let start_bit = (start_vpn - region.starting_vpn) as usize;
    let bit_count = (end_vpn - start_vpn + 1) as usize;
    bitmap.clear_range(start_bit, bit_count);

    region.total_resets += 1;
    WRITE_WATCH_STATS.total_resets += 1;

    STATUS_SUCCESS
}

/// Check if an address is within a write watch region
pub unsafe fn mi_is_write_watch_address(process_id: u32, virt_addr: u64) -> bool {
    let _guard = WRITE_WATCH_LOCK.lock();
    mi_find_write_watch_region_unlocked(process_id, virt_addr).is_some()
}

/// Get write watch statistics
pub fn mi_get_write_watch_stats() -> WriteWatchStats {
    unsafe { WRITE_WATCH_STATS }
}

/// Get snapshot of active write watch regions
pub fn mi_get_write_watch_snapshots() -> ([WriteWatchSnapshot; 16], usize) {
    let mut snapshots = [WriteWatchSnapshot::empty(); 16];
    let mut count = 0;

    unsafe {
        let _guard = WRITE_WATCH_LOCK.lock();

        for (idx, region) in WRITE_WATCH_REGIONS.iter().enumerate() {
            if count >= 16 {
                break;
            }
            if region.active {
                let dirty_pages = if region.bitmap_index < MAX_BITMAPS {
                    WRITE_WATCH_BITMAPS[region.bitmap_index].count_set_bits(0, region.page_count as usize)
                } else {
                    0
                };

                snapshots[count] = WriteWatchSnapshot {
                    index: idx,
                    vad_index: region.vad_index,
                    process_id: region.process_id,
                    start_address: region.starting_vpn << 12,
                    end_address: ((region.ending_vpn + 1) << 12) - 1,
                    page_count: region.page_count,
                    dirty_pages: dirty_pages as u64,
                    total_writes: region.total_writes_captured,
                    total_resets: region.total_resets,
                };
                count += 1;
            }
        }
    }

    (snapshots, count)
}

/// Write watch region snapshot for diagnostics
#[derive(Debug, Clone, Copy)]
pub struct WriteWatchSnapshot {
    pub index: usize,
    pub vad_index: u32,
    pub process_id: u32,
    pub start_address: u64,
    pub end_address: u64,
    pub page_count: u64,
    pub dirty_pages: u64,
    pub total_writes: u64,
    pub total_resets: u64,
}

impl WriteWatchSnapshot {
    pub const fn empty() -> Self {
        Self {
            index: 0,
            vad_index: 0,
            process_id: 0,
            start_address: 0,
            end_address: 0,
            page_count: 0,
            dirty_pages: 0,
            total_writes: 0,
            total_resets: 0,
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize write watch subsystem
pub fn init() {
    unsafe {
        for region in WRITE_WATCH_REGIONS.iter_mut() {
            region.active = false;
            region.bitmap_index = usize::MAX;
        }

        for bitmap in WRITE_WATCH_BITMAPS.iter_mut() {
            bitmap.allocated = false;
        }

        WRITE_WATCH_STATS = WriteWatchStats::new();
    }

    crate::serial_println!("[MM] Write Watch subsystem initialized ({} regions, {} bitmaps)",
        MAX_WRITE_WATCH_REGIONS, MAX_BITMAPS);
}
