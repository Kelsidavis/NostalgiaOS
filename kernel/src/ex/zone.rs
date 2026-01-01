//! Zone Buffer Allocator (Executive)
//!
//! The zone package provides a fast and efficient memory allocator for
//! fixed-size 64-bit aligned blocks of storage. The primary consumer
//! of this module is Local Procedure Call (LPC).
//!
//! # Design
//!
//! A zone is a set of fixed-size blocks of storage. Storage is assigned
//! to a zone during initialization and when extended. The zone uses the
//! first portion of each segment for overhead (SegmentList), and carves
//! the remainder into fixed-size blocks added to a free list.
//!
//! While a block is on the free list, its first pointer-sized portion
//! is used for linking. When allocated, the entire block is available.
//!
//! # Thread Safety
//!
//! The zone package does NOT provide serialization. Callers must provide
//! their own synchronization (typically a spinlock or fast mutex).
//!
//! # NT Functions
//!
//! - `ExInitializeZone` - Initialize a zone header
//! - `ExExtendZone` - Add more storage to a zone
//! - `ExAllocateFromZone` - Allocate a block (macro/inline)
//! - `ExFreeToZone` - Free a block (macro/inline)
//! - `ExIsFullZone` - Check if zone is exhausted
//! - `ExInterlockedAllocateFromZone` - Thread-safe allocation
//! - `ExInterlockedFreeToZone` - Thread-safe deallocation

use core::ptr;

/// Single list entry for free list linkage
#[repr(C)]
pub struct SingleListEntry {
    pub next: *mut SingleListEntry,
}

impl Default for SingleListEntry {
    fn default() -> Self {
        Self { next: ptr::null_mut() }
    }
}

/// Zone segment header
///
/// Each segment in a zone starts with this header.
#[repr(C)]
pub struct ZoneSegmentHeader {
    /// Links segments together
    pub segment_list: SingleListEntry,
    /// Reserved for alignment (unused)
    pub reserved: *mut core::ffi::c_void,
}

impl Default for ZoneSegmentHeader {
    fn default() -> Self {
        Self {
            segment_list: SingleListEntry::default(),
            reserved: ptr::null_mut(),
        }
    }
}

/// Zone header structure (ZONE_HEADER)
///
/// Manages a zone of fixed-size blocks.
#[repr(C)]
pub struct ZoneHeader {
    /// Head of free block list
    pub free_list: SingleListEntry,
    /// Head of segment list
    pub segment_list: SingleListEntry,
    /// Size of each block in bytes
    pub block_size: u32,
    /// Total size of all segments
    pub total_segment_size: u32,
}

impl Default for ZoneHeader {
    fn default() -> Self {
        Self {
            free_list: SingleListEntry::default(),
            segment_list: SingleListEntry::default(),
            block_size: 0,
            total_segment_size: 0,
        }
    }
}

/// Size of zone segment header
pub const ZONE_SEGMENT_HEADER_SIZE: usize = core::mem::size_of::<ZoneSegmentHeader>();

// ============================================================================
// Zone Functions
// ============================================================================

/// Initialize a zone header (ExInitializeZone)
///
/// Initializes a zone with the given block size and initial segment.
///
/// # Arguments
/// * `zone` - Zone header to initialize
/// * `block_size` - Size of each allocatable block (must be 8-byte aligned)
/// * `initial_segment` - Initial storage segment (must be 8-byte aligned)
/// * `initial_segment_size` - Size of initial segment in bytes
///
/// # Returns
/// * `Ok(())` - Zone initialized successfully
/// * `Err(status)` - Invalid parameters (alignment or size)
///
/// # Safety
/// Caller must ensure segment memory is valid and properly aligned.
pub unsafe fn ex_initialize_zone(
    zone: &mut ZoneHeader,
    block_size: u32,
    initial_segment: *mut u8,
    initial_segment_size: u32,
) -> Result<(), i32> {
    // Validate alignment and size
    if (block_size & 7) != 0 ||
       (initial_segment as usize & 7) != 0 ||
       block_size > initial_segment_size
    {
        return Err(-1073741811); // STATUS_INVALID_PARAMETER
    }

    zone.block_size = block_size;
    zone.free_list.next = ptr::null_mut();

    // Set up segment list
    let seg_header = initial_segment as *mut ZoneSegmentHeader;
    (*seg_header).segment_list.next = ptr::null_mut();
    (*seg_header).reserved = ptr::null_mut();
    zone.segment_list.next = &mut (*seg_header).segment_list;

    // Carve up segment into blocks
    let mut p = initial_segment.add(ZONE_SEGMENT_HEADER_SIZE);
    let mut i = ZONE_SEGMENT_HEADER_SIZE as u32;

    while i <= initial_segment_size - block_size {
        let entry = p as *mut SingleListEntry;
        (*entry).next = zone.free_list.next;
        zone.free_list.next = entry;
        p = p.add(block_size as usize);
        i += block_size;
    }

    zone.total_segment_size = i;

    Ok(())
}

/// Extend a zone with another segment (ExExtendZone)
///
/// Adds more storage to an existing zone.
///
/// # Arguments
/// * `zone` - Zone header to extend
/// * `segment` - New storage segment (must be 8-byte aligned)
/// * `segment_size` - Size of new segment in bytes
///
/// # Returns
/// * `Ok(())` - Zone extended successfully
/// * `Err(status)` - Invalid parameters
///
/// # Safety
/// Caller must ensure segment memory is valid and properly aligned.
pub unsafe fn ex_extend_zone(
    zone: &mut ZoneHeader,
    segment: *mut u8,
    segment_size: u32,
) -> Result<(), i32> {
    // Validate alignment and size
    if (segment as usize & 7) != 0 ||
       (segment_size & 7) != 0 ||
       zone.block_size > segment_size
    {
        return Err(-1073741823); // STATUS_UNSUCCESSFUL
    }

    // Link new segment to segment list
    let seg_header = segment as *mut ZoneSegmentHeader;
    (*seg_header).segment_list.next = zone.segment_list.next;
    zone.segment_list.next = &mut (*seg_header).segment_list;

    // Carve up segment into blocks
    let mut p = segment.add(ZONE_SEGMENT_HEADER_SIZE);
    let mut i = ZONE_SEGMENT_HEADER_SIZE as u32;

    while i <= segment_size - zone.block_size {
        let entry = p as *mut SingleListEntry;
        (*entry).next = zone.free_list.next;
        zone.free_list.next = entry;
        p = p.add(zone.block_size as usize);
        i += zone.block_size;
    }

    zone.total_segment_size += i;

    Ok(())
}

/// Allocate a block from a zone (ExAllocateFromZone)
///
/// Allocates a fixed-size block from the zone's free list.
///
/// # Arguments
/// * `zone` - Zone to allocate from
///
/// # Returns
/// * `Some(ptr)` - Pointer to allocated block
/// * `None` - Zone is exhausted
///
/// # Safety
/// Caller must ensure exclusive access to the zone (no synchronization provided).
#[inline]
pub unsafe fn ex_allocate_from_zone(zone: &mut ZoneHeader) -> Option<*mut u8> {
    let entry = zone.free_list.next;
    if entry.is_null() {
        None
    } else {
        zone.free_list.next = (*entry).next;
        Some(entry as *mut u8)
    }
}

/// Free a block to a zone (ExFreeToZone)
///
/// Returns a block to the zone's free list.
///
/// # Arguments
/// * `zone` - Zone to free to
/// * `block` - Block to free (must have been allocated from this zone)
///
/// # Returns
/// * Previous head of free list (for interlocked operations)
///
/// # Safety
/// - Caller must ensure exclusive access to the zone
/// - Block must have been allocated from this zone
#[inline]
pub unsafe fn ex_free_to_zone(zone: &mut ZoneHeader, block: *mut u8) -> *mut SingleListEntry {
    let entry = block as *mut SingleListEntry;
    let old_head = zone.free_list.next;
    (*entry).next = old_head;
    zone.free_list.next = entry;
    old_head
}

/// Check if zone is full/exhausted (ExIsFullZone)
///
/// # Arguments
/// * `zone` - Zone to check
///
/// # Returns
/// * `true` - Zone has no free blocks
/// * `false` - Zone has free blocks available
#[inline]
pub fn ex_is_full_zone(zone: &ZoneHeader) -> bool {
    zone.free_list.next.is_null()
}

/// Check if zone is empty (ExIsEmptyZone equivalent)
///
/// Note: This checks if there are ANY free blocks, not if ALL blocks are free.
#[inline]
pub fn ex_is_zone_empty(zone: &ZoneHeader) -> bool {
    zone.free_list.next.is_null()
}

/// Get block size of a zone
#[inline]
pub fn ex_zone_block_size(zone: &ZoneHeader) -> u32 {
    zone.block_size
}

/// Get total segment size of a zone
#[inline]
pub fn ex_zone_total_size(zone: &ZoneHeader) -> u32 {
    zone.total_segment_size
}

// ============================================================================
// Interlocked Zone Operations (with spinlock)
// ============================================================================

use crate::ke::spinlock::SpinLock;

/// Zone with built-in lock for thread-safe operations
pub struct LockedZone {
    /// The zone header
    zone: ZoneHeader,
    /// Lock for synchronization
    lock: SpinLock<()>,
}

impl LockedZone {
    /// Create a new locked zone (uninitialized)
    pub const fn new() -> Self {
        Self {
            zone: ZoneHeader {
                free_list: SingleListEntry { next: ptr::null_mut() },
                segment_list: SingleListEntry { next: ptr::null_mut() },
                block_size: 0,
                total_segment_size: 0,
            },
            lock: SpinLock::new(()),
        }
    }

    /// Initialize the locked zone
    ///
    /// # Safety
    /// Same as ex_initialize_zone
    pub unsafe fn init(
        &mut self,
        block_size: u32,
        initial_segment: *mut u8,
        initial_segment_size: u32,
    ) -> Result<(), i32> {
        ex_initialize_zone(&mut self.zone, block_size, initial_segment, initial_segment_size)
    }

    /// Extend the zone
    ///
    /// # Safety
    /// Same as ex_extend_zone
    pub unsafe fn extend(&mut self, segment: *mut u8, segment_size: u32) -> Result<(), i32> {
        let _guard = self.lock.lock();
        ex_extend_zone(&mut self.zone, segment, segment_size)
    }

    /// Allocate a block (thread-safe)
    ///
    /// # Safety
    /// Caller must properly manage the returned pointer.
    pub unsafe fn allocate(&mut self) -> Option<*mut u8> {
        let _guard = self.lock.lock();
        ex_allocate_from_zone(&mut self.zone)
    }

    /// Free a block (thread-safe)
    ///
    /// # Safety
    /// Block must have been allocated from this zone.
    pub unsafe fn free(&mut self, block: *mut u8) {
        let _guard = self.lock.lock();
        ex_free_to_zone(&mut self.zone, block);
    }

    /// Check if zone is exhausted
    pub fn is_full(&self) -> bool {
        ex_is_full_zone(&self.zone)
    }

    /// Get block size
    pub fn block_size(&self) -> u32 {
        self.zone.block_size
    }

    /// Get total size
    pub fn total_size(&self) -> u32 {
        self.zone.total_segment_size
    }
}

impl Default for LockedZone {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Interlocked Versions (ExInterlockedAllocateFromZone / ExInterlockedFreeToZone)
// ============================================================================

/// Allocate from zone with spinlock (ExInterlockedAllocateFromZone)
///
/// # Safety
/// - Zone must be properly initialized
/// - Lock must protect this zone
pub unsafe fn ex_interlocked_allocate_from_zone(
    zone: &mut ZoneHeader,
    lock: &SpinLock<()>,
) -> Option<*mut u8> {
    let _guard = lock.lock();
    ex_allocate_from_zone(zone)
}

/// Free to zone with spinlock (ExInterlockedFreeToZone)
///
/// # Safety
/// - Zone must be properly initialized
/// - Block must have been allocated from this zone
/// - Lock must protect this zone
pub unsafe fn ex_interlocked_free_to_zone(
    zone: &mut ZoneHeader,
    block: *mut u8,
    lock: &SpinLock<()>,
) -> *mut SingleListEntry {
    let _guard = lock.lock();
    ex_free_to_zone(zone, block)
}

// ============================================================================
// Zone Statistics
// ============================================================================

/// Zone statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ZoneStats {
    /// Block size
    pub block_size: u32,
    /// Total segment size
    pub total_size: u32,
    /// Number of free blocks
    pub free_blocks: u32,
    /// Number of segments
    pub segment_count: u32,
}

/// Get zone statistics
///
/// # Safety
/// Zone must be properly initialized.
pub unsafe fn get_zone_stats(zone: &ZoneHeader) -> ZoneStats {
    let mut free_blocks = 0u32;
    let mut ptr = zone.free_list.next;
    while !ptr.is_null() {
        free_blocks += 1;
        ptr = (*ptr).next;
    }

    let mut segment_count = 0u32;
    let mut seg_ptr = zone.segment_list.next;
    while !seg_ptr.is_null() {
        segment_count += 1;
        seg_ptr = (*seg_ptr).next;
    }

    ZoneStats {
        block_size: zone.block_size,
        total_size: zone.total_segment_size,
        free_blocks,
        segment_count,
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize zone support (nothing to do - zones are self-contained)
pub fn init() {
    crate::serial_println!("[EX] Zone allocator support initialized");
}
