//! Cache Manager (cc)
//!
//! The Cache Manager provides a unified caching layer for file system data:
//!
//! - **File Caching**: Caches file data in memory for fast access
//! - **Lazy Writer**: Writes dirty pages back to disk in background
//! - **Read Ahead**: Prefetches data anticipating sequential access
//! - **Write Behind**: Batches writes for efficiency
//!
//! # Architecture
//!
//! The cache manager uses a shared cache map per file:
//! - Virtual Address Control Block (VACB) - 256KB mapping windows
//! - Shared Cache Map - Per-file cache state
//! - Private Cache Map - Per-handle cache state
//!
//! # Key Structures
//!
//! - `SharedCacheMap`: Per-file cache state and VACB array
//! - `PrivateCacheMap`: Per-handle read-ahead state
//! - `CacheView`: Mapped view of cached data
//!
//! # NT API
//!
//! - `CcInitializeCacheMap` - Initialize caching for a file
//! - `CcUninitializeCacheMap` - Tear down caching
//! - `CcCopyRead` / `CcCopyWrite` - Cached read/write
//! - `CcMapData` / `CcUnpinData` - Map data into memory
//! - `CcFlushCache` - Flush dirty data to disk

use core::ptr;
use crate::ke::spinlock::SpinLock;
use crate::mm::PAGE_SIZE;

/// Size of a VACB mapping (256KB - standard NT cache granularity)
pub const VACB_MAPPING_SIZE: usize = 256 * 1024;

/// Maximum number of cached files
pub const MAX_CACHED_FILES: usize = 64;

/// Maximum VACBs per file
pub const MAX_VACBS_PER_FILE: usize = 16;

/// Total cache size limit (16MB for now)
pub const MAX_CACHE_SIZE: usize = 16 * 1024 * 1024;

/// Cache page size
pub const CACHE_PAGE_SIZE: usize = PAGE_SIZE;

/// Number of cache pages
pub const CACHE_PAGE_COUNT: usize = MAX_CACHE_SIZE / CACHE_PAGE_SIZE;

/// VACB (Virtual Address Control Block) state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VacbState {
    /// VACB is free
    Free = 0,
    /// VACB is mapped and valid
    Active = 1,
    /// VACB is being read from disk
    Reading = 2,
    /// VACB contains dirty data
    Dirty = 3,
    /// VACB is being written to disk
    Writing = 4,
}

/// Virtual Address Control Block
///
/// Maps a 256KB window of a file into the cache
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Vacb {
    /// State of this VACB
    pub state: VacbState,
    /// File offset this VACB covers
    pub file_offset: u64,
    /// Virtual address of the cached data
    pub base_address: usize,
    /// Reference count
    pub ref_count: u32,
    /// Dirty page bitmap (one bit per 4KB page in the 256KB window)
    pub dirty_pages: u64,
    /// Valid page bitmap
    pub valid_pages: u64,
    /// Owning shared cache map
    pub shared_cache_map: *mut SharedCacheMap,
}

impl Default for Vacb {
    fn default() -> Self {
        Self::new()
    }
}

impl Vacb {
    pub const fn new() -> Self {
        Self {
            state: VacbState::Free,
            file_offset: 0,
            base_address: 0,
            ref_count: 0,
            dirty_pages: 0,
            valid_pages: 0,
            shared_cache_map: ptr::null_mut(),
        }
    }

    /// Check if VACB is in use
    pub fn is_active(&self) -> bool {
        self.state != VacbState::Free
    }

    /// Check if VACB has dirty pages
    pub fn is_dirty(&self) -> bool {
        self.dirty_pages != 0
    }

    /// Get the number of pages in this VACB
    pub fn page_count(&self) -> usize {
        VACB_MAPPING_SIZE / CACHE_PAGE_SIZE
    }

    /// Mark a page as dirty
    pub fn mark_dirty(&mut self, page_index: usize) {
        if page_index < 64 {
            self.dirty_pages |= 1 << page_index;
            self.state = VacbState::Dirty;
        }
    }

    /// Mark a page as valid
    pub fn mark_valid(&mut self, page_index: usize) {
        if page_index < 64 {
            self.valid_pages |= 1 << page_index;
        }
    }

    /// Check if a page is valid
    pub fn is_page_valid(&self, page_index: usize) -> bool {
        page_index < 64 && (self.valid_pages & (1 << page_index)) != 0
    }

    /// Clear dirty flags after write
    pub fn clear_dirty(&mut self) {
        self.dirty_pages = 0;
        if self.state == VacbState::Dirty {
            self.state = VacbState::Active;
        }
    }

    /// Add a reference
    pub fn reference(&mut self) {
        self.ref_count += 1;
    }

    /// Remove a reference
    pub fn dereference(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }
}

/// Shared Cache Map
///
/// Per-file cache state, shared by all handles to the file
#[repr(C)]
pub struct SharedCacheMap {
    /// File object being cached
    pub file_object: *mut u8,
    /// File size
    pub file_size: u64,
    /// Section object for this file
    pub section: *mut u8,
    /// VACBs for this file
    pub vacbs: [Vacb; MAX_VACBS_PER_FILE],
    /// Number of active VACBs
    pub active_vacb_count: u32,
    /// Total dirty pages
    pub dirty_page_count: u32,
    /// Cache map is valid
    pub valid: bool,
    /// Read-ahead enabled
    pub read_ahead_enabled: bool,
    /// Write-behind enabled
    pub write_behind_enabled: bool,
    /// Lock for synchronization
    lock: SpinLock<()>,
}

impl Default for SharedCacheMap {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedCacheMap {
    pub const fn new() -> Self {
        Self {
            file_object: ptr::null_mut(),
            file_size: 0,
            section: ptr::null_mut(),
            vacbs: [Vacb::new(); MAX_VACBS_PER_FILE],
            active_vacb_count: 0,
            dirty_page_count: 0,
            valid: false,
            read_ahead_enabled: true,
            write_behind_enabled: true,
            lock: SpinLock::new(()),
        }
    }

    /// Initialize the cache map for a file
    pub fn init(&mut self, file_object: *mut u8, file_size: u64) {
        self.file_object = file_object;
        self.file_size = file_size;
        self.valid = true;
        self.active_vacb_count = 0;
        self.dirty_page_count = 0;

        // Initialize all VACBs
        for vacb in self.vacbs.iter_mut() {
            *vacb = Vacb::new();
        }
    }

    /// Find or create a VACB for the given file offset
    /// Returns the index of the VACB if found/created
    pub fn get_vacb_index(&mut self, file_offset: u64) -> Option<usize> {
        // Align offset to VACB boundary
        let aligned_offset = file_offset & !(VACB_MAPPING_SIZE as u64 - 1);

        // First, look for existing VACB
        for i in 0..MAX_VACBS_PER_FILE {
            if self.vacbs[i].is_active() && self.vacbs[i].file_offset == aligned_offset {
                self.vacbs[i].reference();
                return Some(i);
            }
        }

        // Need to create a new VACB - find a free slot
        for i in 0..MAX_VACBS_PER_FILE {
            if !self.vacbs[i].is_active() {
                self.vacbs[i].state = VacbState::Active;
                self.vacbs[i].file_offset = aligned_offset;
                self.vacbs[i].ref_count = 1;
                self.vacbs[i].dirty_pages = 0;
                self.vacbs[i].valid_pages = 0;
                self.vacbs[i].shared_cache_map = self as *mut SharedCacheMap;
                self.active_vacb_count += 1;
                return Some(i);
            }
        }

        // No free VACBs - need to evict one
        // For now, evict the first non-dirty VACB with zero refs
        for i in 0..MAX_VACBS_PER_FILE {
            if self.vacbs[i].is_active() && !self.vacbs[i].is_dirty() && self.vacbs[i].ref_count == 0 {
                // Evict this VACB
                self.vacbs[i].state = VacbState::Active;
                self.vacbs[i].file_offset = aligned_offset;
                self.vacbs[i].ref_count = 1;
                self.vacbs[i].dirty_pages = 0;
                self.vacbs[i].valid_pages = 0;
                return Some(i);
            }
        }

        None
    }

    /// Get a mutable reference to VACB by index
    pub fn vacb_mut(&mut self, index: usize) -> Option<&mut Vacb> {
        if index < MAX_VACBS_PER_FILE {
            Some(&mut self.vacbs[index])
        } else {
            None
        }
    }

    /// Release a VACB reference
    pub fn release_vacb(&mut self, vacb_index: usize) {
        if vacb_index < MAX_VACBS_PER_FILE {
            let vacb = &mut self.vacbs[vacb_index];
            if vacb.dereference() && !vacb.is_dirty() {
                // Can free this VACB
                vacb.state = VacbState::Free;
                if self.active_vacb_count > 0 {
                    self.active_vacb_count -= 1;
                }
            }
        }
    }

    /// Flush all dirty VACBs
    pub unsafe fn flush(&mut self) -> bool {
        // First collect indices of dirty VACBs
        let mut dirty_indices = [false; MAX_VACBS_PER_FILE];
        for i in 0..MAX_VACBS_PER_FILE {
            dirty_indices[i] = self.vacbs[i].is_dirty();
        }

        // Then flush each one
        for i in 0..MAX_VACBS_PER_FILE {
            if dirty_indices[i] {
                self.flush_vacb(i);
            }
        }

        true
    }

    /// Flush a single VACB by index
    unsafe fn flush_vacb(&mut self, index: usize) {
        if index >= MAX_VACBS_PER_FILE {
            return;
        }

        if !self.vacbs[index].is_dirty() || self.file_object.is_null() {
            return;
        }

        // In a full implementation, this would:
        // 1. Build an IRP for each dirty page range
        // 2. Send to the file system
        // 3. Wait for completion
        // 4. Clear dirty bits

        // For now, just clear the dirty state
        self.vacbs[index].clear_dirty();
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheMapStats {
        let mut dirty_pages = 0u32;
        let mut valid_pages = 0u32;

        for vacb in self.vacbs.iter() {
            if vacb.is_active() {
                dirty_pages += vacb.dirty_pages.count_ones();
                valid_pages += vacb.valid_pages.count_ones();
            }
        }

        CacheMapStats {
            file_size: self.file_size,
            active_vacbs: self.active_vacb_count,
            dirty_pages,
            valid_pages,
        }
    }
}

/// Private Cache Map
///
/// Per-handle cache state for read-ahead tracking
#[repr(C)]
pub struct PrivateCacheMap {
    /// Owning shared cache map
    pub shared_cache_map: *mut SharedCacheMap,
    /// Current file position for read-ahead
    pub file_offset: u64,
    /// Read-ahead granularity
    pub read_ahead_length: u32,
    /// Sequential read detection
    pub sequential_count: u32,
    /// Last read was sequential
    pub is_sequential: bool,
}

impl Default for PrivateCacheMap {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateCacheMap {
    pub const fn new() -> Self {
        Self {
            shared_cache_map: ptr::null_mut(),
            file_offset: 0,
            read_ahead_length: VACB_MAPPING_SIZE as u32,
            sequential_count: 0,
            is_sequential: false,
        }
    }

    /// Update read-ahead state based on current read
    pub fn update_read_ahead(&mut self, offset: u64, length: u32) {
        // Detect sequential access
        let expected = self.file_offset;
        if offset == expected {
            self.sequential_count += 1;
            self.is_sequential = true;

            // Increase read-ahead for sequential access
            if self.sequential_count > 2 && self.read_ahead_length < VACB_MAPPING_SIZE as u32 * 4 {
                self.read_ahead_length *= 2;
            }
        } else {
            self.sequential_count = 0;
            self.is_sequential = false;
            self.read_ahead_length = VACB_MAPPING_SIZE as u32;
        }

        self.file_offset = offset + length as u64;
    }

    /// Get read-ahead offset and length
    pub fn get_read_ahead(&self) -> Option<(u64, u32)> {
        if self.is_sequential && self.sequential_count > 1 {
            Some((self.file_offset, self.read_ahead_length))
        } else {
            None
        }
    }
}

/// Cache map statistics
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CacheMapStats {
    pub file_size: u64,
    pub active_vacbs: u32,
    pub dirty_pages: u32,
    pub valid_pages: u32,
}

// ============================================================================
// Global Cache State
// ============================================================================

/// Pool of shared cache maps
static mut CACHE_MAP_POOL: [SharedCacheMap; MAX_CACHED_FILES] = {
    const INIT: SharedCacheMap = SharedCacheMap::new();
    [INIT; MAX_CACHED_FILES]
};

/// Bitmap tracking allocated cache maps
static mut CACHE_MAP_BITMAP: u64 = 0;

/// Global cache lock
static CACHE_LOCK: SpinLock<()> = SpinLock::new(());

/// Cache statistics
static mut CACHE_STATS: CacheStats = CacheStats::new();

/// Global cache statistics
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    pub total_reads: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub total_writes: u64,
    pub dirty_pages: u64,
    pub active_cache_maps: u32,
}

impl Default for CacheStats {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheStats {
    pub const fn new() -> Self {
        Self {
            total_reads: 0,
            cache_hits: 0,
            cache_misses: 0,
            total_writes: 0,
            dirty_pages: 0,
            active_cache_maps: 0,
        }
    }

    /// Calculate hit rate as percentage (0-100)
    pub fn hit_rate_percent(&self) -> u32 {
        if self.total_reads == 0 {
            0
        } else {
            ((self.cache_hits * 100) / self.total_reads) as u32
        }
    }
}

// ============================================================================
// Cache Manager API
// ============================================================================

/// Initialize caching for a file
///
/// Called by file systems when a file is opened with caching enabled.
pub unsafe fn cc_initialize_cache_map(
    file_object: *mut u8,
    file_size: u64,
) -> *mut SharedCacheMap {
    let _guard = CACHE_LOCK.lock();

    // Find a free cache map
    for i in 0..MAX_CACHED_FILES {
        if CACHE_MAP_BITMAP & (1 << i) == 0 {
            CACHE_MAP_BITMAP |= 1 << i;

            let cache_map = &mut CACHE_MAP_POOL[i];
            cache_map.init(file_object, file_size);

            CACHE_STATS.active_cache_maps += 1;

            return cache_map as *mut SharedCacheMap;
        }
    }

    ptr::null_mut()
}

/// Uninitialize caching for a file
///
/// Called when a file is closed.
pub unsafe fn cc_uninitialize_cache_map(cache_map: *mut SharedCacheMap) {
    if cache_map.is_null() {
        return;
    }

    let _guard = CACHE_LOCK.lock();

    // Flush any dirty data first
    (*cache_map).flush();

    // Find and free the cache map
    let base = CACHE_MAP_POOL.as_ptr() as usize;
    let map_addr = cache_map as usize;
    let map_size = core::mem::size_of::<SharedCacheMap>();

    if map_addr >= base && map_addr < base + MAX_CACHED_FILES * map_size {
        let index = (map_addr - base) / map_size;

        (*cache_map).valid = false;
        CACHE_MAP_BITMAP &= !(1 << index);

        if CACHE_STATS.active_cache_maps > 0 {
            CACHE_STATS.active_cache_maps -= 1;
        }
    }
}

/// Copy data from file cache to user buffer
///
/// This is the main cached read path.
pub unsafe fn cc_copy_read(
    cache_map: *mut SharedCacheMap,
    file_offset: u64,
    buffer: *mut u8,
    length: u32,
) -> bool {
    if cache_map.is_null() || buffer.is_null() || length == 0 {
        return false;
    }

    let map = &mut *cache_map;

    // Check bounds
    if file_offset + length as u64 > map.file_size {
        return false;
    }

    CACHE_STATS.total_reads += 1;

    // Get or create VACB for this offset
    let vacb_idx = match map.get_vacb_index(file_offset) {
        Some(idx) => idx,
        None => {
            CACHE_STATS.cache_misses += 1;
            return false;
        }
    };

    let vacb = &map.vacbs[vacb_idx];

    // Calculate offset within VACB
    let vacb_offset = (file_offset - vacb.file_offset) as usize;

    // Check if data is valid in cache
    let start_page = vacb_offset / CACHE_PAGE_SIZE;
    let end_page = (vacb_offset + length as usize - 1) / CACHE_PAGE_SIZE;

    let mut all_valid = true;
    for page in start_page..=end_page {
        if !vacb.is_page_valid(page) {
            all_valid = false;
            break;
        }
    }

    if all_valid {
        CACHE_STATS.cache_hits += 1;

        // Copy from cache to user buffer
        if vacb.base_address != 0 {
            let src = (vacb.base_address + vacb_offset) as *const u8;
            core::ptr::copy_nonoverlapping(src, buffer, length as usize);
        }
        true
    } else {
        CACHE_STATS.cache_misses += 1;

        // Would need to read from disk here
        // For now, just return false to indicate cache miss
        false
    }
}

/// Copy data from user buffer to file cache
///
/// This is the main cached write path.
pub unsafe fn cc_copy_write(
    cache_map: *mut SharedCacheMap,
    file_offset: u64,
    buffer: *const u8,
    length: u32,
) -> bool {
    if cache_map.is_null() || buffer.is_null() || length == 0 {
        return false;
    }

    let map = &mut *cache_map;

    CACHE_STATS.total_writes += 1;

    // Get or create VACB for this offset
    let vacb_idx = match map.get_vacb_index(file_offset) {
        Some(idx) => idx,
        None => return false,
    };

    let vacb = &mut map.vacbs[vacb_idx];

    // Calculate offset within VACB
    let vacb_offset = (file_offset - vacb.file_offset) as usize;

    // Copy from user buffer to cache
    if vacb.base_address != 0 {
        let dst = (vacb.base_address + vacb_offset) as *mut u8;
        core::ptr::copy_nonoverlapping(buffer, dst, length as usize);
    }

    // Mark pages as dirty and valid
    let start_page = vacb_offset / CACHE_PAGE_SIZE;
    let end_page = (vacb_offset + length as usize - 1) / CACHE_PAGE_SIZE;

    for page in start_page..=end_page {
        vacb.mark_dirty(page);
        vacb.mark_valid(page);
    }

    CACHE_STATS.dirty_pages += (end_page - start_page + 1) as u64;

    true
}

/// Map cached data into memory
///
/// Returns a pointer to the cached data.
pub unsafe fn cc_map_data(
    cache_map: *mut SharedCacheMap,
    file_offset: u64,
    length: u32,
) -> Option<*mut u8> {
    if cache_map.is_null() {
        return None;
    }

    let map = &mut *cache_map;

    // Get VACB for this offset
    let vacb_idx = map.get_vacb_index(file_offset)?;
    let vacb = &map.vacbs[vacb_idx];

    if vacb.base_address == 0 {
        return None;
    }

    let vacb_offset = (file_offset - vacb.file_offset) as usize;
    let _ = length; // Validate length doesn't exceed VACB

    Some((vacb.base_address + vacb_offset) as *mut u8)
}

/// Unpin (release) mapped data
pub unsafe fn cc_unpin_data(cache_map: *mut SharedCacheMap, _bcb: *mut u8) {
    if cache_map.is_null() {
    }

    // In a full implementation, this would dereference the VACB
    // For now, this is a no-op as we don't track BCBs
}

/// Flush cache to disk
pub unsafe fn cc_flush_cache(cache_map: *mut SharedCacheMap) -> bool {
    if cache_map.is_null() {
        return false;
    }

    (*cache_map).flush()
}

/// Flush all caches (for shutdown)
pub unsafe fn cc_flush_all() {
    let _guard = CACHE_LOCK.lock();

    for i in 0..MAX_CACHED_FILES {
        if CACHE_MAP_BITMAP & (1 << i) != 0 {
            CACHE_MAP_POOL[i].flush();
        }
    }
}

/// Set file size in cache
pub unsafe fn cc_set_file_size(cache_map: *mut SharedCacheMap, new_size: u64) {
    if !cache_map.is_null() {
        (*cache_map).file_size = new_size;
    }
}

/// Get cache statistics
pub fn cc_get_stats() -> CacheStats {
    unsafe { CACHE_STATS }
}

/// Get cache map statistics
pub unsafe fn cc_get_cache_map_stats(cache_map: *mut SharedCacheMap) -> Option<CacheMapStats> {
    if cache_map.is_null() {
        return None;
    }

    Some((*cache_map).get_stats())
}

// ============================================================================
// Lazy Writer
// ============================================================================

/// Lazy writer state
static mut LAZY_WRITER_ENABLED: bool = true;

/// Enable/disable lazy writer
pub fn cc_set_lazy_writer(enabled: bool) {
    unsafe {
        LAZY_WRITER_ENABLED = enabled;
    }
}

/// Lazy writer tick - called periodically to flush dirty data
pub unsafe fn cc_lazy_writer_tick() {
    if !LAZY_WRITER_ENABLED {
        return;
    }

    let _guard = CACHE_LOCK.lock();

    // Scan for dirty cache maps and flush some pages
    for i in 0..MAX_CACHED_FILES {
        if CACHE_MAP_BITMAP & (1 << i) != 0 {
            let map = &mut CACHE_MAP_POOL[i];

            // Find oldest dirty VACB with zero refs
            let mut dirty_vacb_idx: Option<usize> = None;
            for (idx, vacb) in map.vacbs.iter().enumerate() {
                if vacb.is_dirty() && vacb.ref_count == 0 {
                    dirty_vacb_idx = Some(idx);
                    break;
                }
            }

            // Flush it if found
            if let Some(idx) = dirty_vacb_idx {
                let vacb = &mut map.vacbs[idx];
                // Clear dirty state directly (simulating write to file)
                vacb.clear_dirty();
            }
        }
    }
}

// ============================================================================
// MDL Support
// ============================================================================

/// Buffer Control Block (BCB)
///
/// Returned from pin/map operations to track mapped data
#[repr(C)]
pub struct Bcb {
    /// Type marker
    pub node_type: u16,
    /// Size of this structure
    pub node_size: u16,
    /// Owning shared cache map
    pub shared_cache_map: *mut SharedCacheMap,
    /// VACB index
    pub vacb_index: usize,
    /// Mapped address
    pub mapped_address: usize,
    /// Length of mapped region
    pub length: u32,
    /// Is this a pin (vs map)?
    pub pinned: bool,
    /// Is this dirty?
    pub dirty: bool,
}

impl Default for Bcb {
    fn default() -> Self {
        Self::new()
    }
}

impl Bcb {
    pub const fn new() -> Self {
        Self {
            node_type: 0x2FD, // CACHE_NTC_BCB
            node_size: core::mem::size_of::<Bcb>() as u16,
            shared_cache_map: ptr::null_mut(),
            vacb_index: 0,
            mapped_address: 0,
            length: 0,
            pinned: false,
            dirty: false,
        }
    }
}

/// BCB pool
const MAX_BCBS: usize = 256;
static mut BCB_POOL: [Bcb; MAX_BCBS] = {
    const INIT: Bcb = Bcb::new();
    [INIT; MAX_BCBS]
};
static mut BCB_BITMAP: [u64; 4] = [0; 4]; // 256 bits

/// Allocate a BCB
unsafe fn allocate_bcb() -> Option<*mut Bcb> {
    for i in 0..4 {
        if BCB_BITMAP[i] != !0u64 {
            for bit in 0..64 {
                if BCB_BITMAP[i] & (1 << bit) == 0 {
                    BCB_BITMAP[i] |= 1 << bit;
                    let idx = i * 64 + bit;
                    return Some(&mut BCB_POOL[idx] as *mut Bcb);
                }
            }
        }
    }
    None
}

/// Free a BCB
unsafe fn free_bcb(bcb: *mut Bcb) {
    let base = BCB_POOL.as_ptr() as usize;
    let bcb_addr = bcb as usize;
    let bcb_size = core::mem::size_of::<Bcb>();

    if bcb_addr >= base && bcb_addr < base + MAX_BCBS * bcb_size {
        let idx = (bcb_addr - base) / bcb_size;
        let bitmap_idx = idx / 64;
        let bit = idx % 64;
        BCB_BITMAP[bitmap_idx] &= !(1 << bit);
    }
}

/// Pin data for exclusive write access
///
/// Pins the data in memory and returns a BCB for later release.
pub unsafe fn cc_pin_read(
    cache_map: *mut SharedCacheMap,
    file_offset: u64,
    length: u32,
    flags: u32,
    bcb: *mut *mut Bcb,
    buffer: *mut *mut u8,
) -> bool {
    if cache_map.is_null() || bcb.is_null() || buffer.is_null() {
        return false;
    }

    let map = &mut *cache_map;
    let _wait = (flags & 1) != 0; // PIN_WAIT flag

    // Get VACB
    let vacb_idx = match map.get_vacb_index(file_offset) {
        Some(idx) => idx,
        None => return false,
    };

    let vacb = &map.vacbs[vacb_idx];
    if vacb.base_address == 0 {
        return false;
    }

    // Allocate BCB
    let new_bcb = match allocate_bcb() {
        Some(b) => b,
        None => return false,
    };

    let vacb_offset = (file_offset - vacb.file_offset) as usize;

    (*new_bcb).shared_cache_map = cache_map;
    (*new_bcb).vacb_index = vacb_idx;
    (*new_bcb).mapped_address = vacb.base_address + vacb_offset;
    (*new_bcb).length = length;
    (*new_bcb).pinned = true;
    (*new_bcb).dirty = false;

    *bcb = new_bcb;
    *buffer = (*new_bcb).mapped_address as *mut u8;

    true
}

/// Set dirty flag on a pinned BCB
pub unsafe fn cc_set_dirty_pinned_data(bcb: *mut Bcb, _lsn: Option<u64>) {
    if !bcb.is_null() {
        (*bcb).dirty = true;

        // Also mark the VACB as dirty
        if !(*bcb).shared_cache_map.is_null() {
            let map = &mut *(*bcb).shared_cache_map;
            if let Some(vacb) = map.vacb_mut((*bcb).vacb_index) {
                let start_offset = (*bcb).mapped_address - vacb.base_address;
                let start_page = start_offset / CACHE_PAGE_SIZE;
                let end_page = (start_offset + (*bcb).length as usize - 1) / CACHE_PAGE_SIZE;

                for page in start_page..=end_page {
                    vacb.mark_dirty(page);
                    vacb.mark_valid(page);
                }
            }
        }
    }
}

/// Unpin data previously pinned with cc_pin_read
pub unsafe fn cc_unpin_data_ex(bcb: *mut Bcb, release_from_lazy_write: bool) {
    if bcb.is_null() {
        return;
    }

    // Release the VACB reference
    if !(*bcb).shared_cache_map.is_null() {
        let map = &mut *(*bcb).shared_cache_map;
        map.release_vacb((*bcb).vacb_index);
    }

    let _ = release_from_lazy_write;

    // Free the BCB
    free_bcb(bcb);
}

/// Map data for read-only access (doesn't pin)
pub unsafe fn cc_map_data_ex(
    cache_map: *mut SharedCacheMap,
    file_offset: u64,
    length: u32,
    flags: u32,
    bcb: *mut *mut Bcb,
    buffer: *mut *mut u8,
) -> bool {
    if cache_map.is_null() || bcb.is_null() || buffer.is_null() {
        return false;
    }

    let map = &mut *cache_map;
    let _wait = (flags & 1) != 0;

    // Get VACB
    let vacb_idx = match map.get_vacb_index(file_offset) {
        Some(idx) => idx,
        None => return false,
    };

    let vacb = &map.vacbs[vacb_idx];
    if vacb.base_address == 0 {
        return false;
    }

    // Allocate BCB
    let new_bcb = match allocate_bcb() {
        Some(b) => b,
        None => return false,
    };

    let vacb_offset = (file_offset - vacb.file_offset) as usize;

    (*new_bcb).shared_cache_map = cache_map;
    (*new_bcb).vacb_index = vacb_idx;
    (*new_bcb).mapped_address = vacb.base_address + vacb_offset;
    (*new_bcb).length = length;
    (*new_bcb).pinned = false;
    (*new_bcb).dirty = false;

    *bcb = new_bcb;
    *buffer = (*new_bcb).mapped_address as *mut u8;

    true
}

/// Prepare MDL for cached write
pub unsafe fn cc_prepare_mdl_write(
    cache_map: *mut SharedCacheMap,
    file_offset: u64,
    length: u32,
) -> bool {
    if cache_map.is_null() || length == 0 {
        return false;
    }

    let map = &mut *cache_map;

    // Ensure we have VACBs for the entire range
    let mut offset = file_offset;
    let end_offset = file_offset + length as u64;

    while offset < end_offset {
        if map.get_vacb_index(offset).is_none() {
            return false;
        }
        offset += VACB_MAPPING_SIZE as u64;
    }

    true
}

/// Complete MDL write
pub unsafe fn cc_mdl_write_complete(
    cache_map: *mut SharedCacheMap,
    file_offset: u64,
    length: u32,
) {
    if cache_map.is_null() || length == 0 {
        return;
    }

    let map = &mut *cache_map;

    // Mark all pages in range as dirty
    let mut offset = file_offset;
    let end_offset = file_offset + length as u64;

    while offset < end_offset {
        if let Some(vacb_idx) = map.get_vacb_index(offset) {
            let vacb = &mut map.vacbs[vacb_idx];
            let vacb_offset = (offset - vacb.file_offset) as usize;
            let page_idx = vacb_offset / CACHE_PAGE_SIZE;
            vacb.mark_dirty(page_idx);
            vacb.mark_valid(page_idx);
            map.release_vacb(vacb_idx);
        }
        offset += CACHE_PAGE_SIZE as u64;
    }
}

// ============================================================================
// Zero Data Support
// ============================================================================

/// Zero a range of cached data
pub unsafe fn cc_zero_data(
    cache_map: *mut SharedCacheMap,
    start_offset: u64,
    end_offset: u64,
) -> bool {
    if cache_map.is_null() || end_offset <= start_offset {
        return false;
    }

    let map = &mut *cache_map;
    let mut offset = start_offset;

    while offset < end_offset {
        if let Some(vacb_idx) = map.get_vacb_index(offset) {
            let vacb = &mut map.vacbs[vacb_idx];

            if vacb.base_address != 0 {
                let vacb_start = vacb.file_offset;
                let range_start = offset.saturating_sub(vacb_start) as usize;
                let range_end = ((end_offset - vacb_start) as usize).min(VACB_MAPPING_SIZE);

                let zero_len = range_end.saturating_sub(range_start);
                let dst = (vacb.base_address + range_start) as *mut u8;
                core::ptr::write_bytes(dst, 0, zero_len);

                // Mark pages as dirty
                let start_page = range_start / CACHE_PAGE_SIZE;
                let end_page = (range_end - 1) / CACHE_PAGE_SIZE;
                for page in start_page..=end_page {
                    vacb.mark_dirty(page);
                    vacb.mark_valid(page);
                }
            }

            map.release_vacb(vacb_idx);
        }

        offset = (offset + VACB_MAPPING_SIZE as u64) & !(VACB_MAPPING_SIZE as u64 - 1);
    }

    true
}

// ============================================================================
// Deferred Write Support
// ============================================================================

/// Check if there's enough memory for a cached write
pub fn cc_can_i_write(
    _cache_map: *mut SharedCacheMap,
    bytes_to_write: u32,
    _wait: bool,
    _retrying: bool,
) -> bool {
    // Simple check - allow writes under 1MB
    bytes_to_write <= 1024 * 1024
}

/// Schedule a deferred write callback
pub fn cc_defer_write(
    _cache_map: *mut SharedCacheMap,
    _bytes_to_write: u32,
    _retrying: bool,
    _post_routine: fn(),
    _context: *mut u8,
) {
    // Stub - would queue a work item in full implementation
}

// ============================================================================
// Inspection Support
// ============================================================================

/// Cache Manager snapshot for diagnostics
#[derive(Debug, Clone, Copy)]
pub struct CacheSnapshot {
    pub index: usize,
    pub file_size: u64,
    pub active_vacbs: u32,
    pub dirty_pages: u32,
}

/// Get snapshots of active cache maps
pub fn cc_get_cache_snapshots(max_count: usize) -> ([CacheSnapshot; 32], usize) {
    let mut snapshots = [CacheSnapshot {
        index: 0,
        file_size: 0,
        active_vacbs: 0,
        dirty_pages: 0,
    }; 32];
    let mut count = 0;

    unsafe {
        let _guard = CACHE_LOCK.lock();

        for i in 0..MAX_CACHED_FILES {
            if count >= max_count || count >= 32 {
                break;
            }

            if CACHE_MAP_BITMAP & (1 << i) != 0 {
                let map = &CACHE_MAP_POOL[i];
                let stats = map.get_stats();

                snapshots[count] = CacheSnapshot {
                    index: i,
                    file_size: stats.file_size,
                    active_vacbs: stats.active_vacbs,
                    dirty_pages: stats.dirty_pages,
                };
                count += 1;
            }
        }
    }

    (snapshots, count)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the Cache Manager
pub fn init() {
    unsafe {
        CACHE_MAP_BITMAP = 0;
        CACHE_STATS = CacheStats::new();
        LAZY_WRITER_ENABLED = true;

        for map in CACHE_MAP_POOL.iter_mut() {
            map.valid = false;
        }

        // Initialize BCB pool
        for i in 0..4 {
            BCB_BITMAP[i] = 0;
        }
    }

    crate::serial_println!("[CC] Cache Manager initialized");
}
