//! Pool Tag Tracking
//!
//! Tracks pool allocations by tag for debugging and leak detection.
//!
//! # Pool Tags
//!
//! Each pool allocation can have a 4-character tag that identifies
//! the allocator. This module tracks allocations per tag for:
//! - Memory leak detection
//! - Usage analysis
//! - Driver debugging
//!
//! # NT Functions
//!
//! - `ExAllocatePoolWithTag` - Allocate with tag (tracked here)
//! - `ExFreePoolWithTag` - Free with tag verification
//!
//! # Well-known Tags
//!
//! - `Irp ` - I/O Request Packets
//! - `Mdl ` - Memory Descriptor Lists
//! - `File` - File objects
//! - `Thre` - Thread structures
//! - `Proc` - Process structures

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;

/// Maximum number of unique tags to track
pub const MAX_POOL_TAGS: usize = 256;

/// Pool tag entry
#[derive(Debug)]
pub struct PoolTagEntry {
    /// The 4-byte pool tag
    pub tag: u32,
    /// Total allocations with this tag
    pub alloc_count: AtomicU64,
    /// Total frees with this tag
    pub free_count: AtomicU64,
    /// Current allocation count (alloc - free)
    pub current_count: AtomicU64,
    /// Total bytes allocated
    pub total_bytes: AtomicU64,
    /// Current bytes in use
    pub current_bytes: AtomicU64,
    /// Peak bytes in use
    pub peak_bytes: AtomicU64,
    /// Non-paged allocations
    pub non_paged_allocs: AtomicU64,
    /// Paged allocations
    pub paged_allocs: AtomicU64,
    /// Entry is in use
    pub in_use: AtomicBool,
}

impl PoolTagEntry {
    pub const fn new() -> Self {
        Self {
            tag: 0,
            alloc_count: AtomicU64::new(0),
            free_count: AtomicU64::new(0),
            current_count: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            current_bytes: AtomicU64::new(0),
            peak_bytes: AtomicU64::new(0),
            non_paged_allocs: AtomicU64::new(0),
            paged_allocs: AtomicU64::new(0),
            in_use: AtomicBool::new(false),
        }
    }

    pub fn init(&self, tag: u32) {
        // Note: We can't modify tag directly as it's not atomic
        // This is called under lock protection
        self.alloc_count.store(0, Ordering::Relaxed);
        self.free_count.store(0, Ordering::Relaxed);
        self.current_count.store(0, Ordering::Relaxed);
        self.total_bytes.store(0, Ordering::Relaxed);
        self.current_bytes.store(0, Ordering::Relaxed);
        self.peak_bytes.store(0, Ordering::Relaxed);
        self.non_paged_allocs.store(0, Ordering::Relaxed);
        self.paged_allocs.store(0, Ordering::Relaxed);
        self.in_use.store(true, Ordering::Release);
    }

    /// Record an allocation
    pub fn record_alloc(&self, size: usize, paged: bool) {
        self.alloc_count.fetch_add(1, Ordering::Relaxed);
        self.current_count.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(size as u64, Ordering::Relaxed);

        let new_current = self.current_bytes.fetch_add(size as u64, Ordering::Relaxed) + size as u64;

        // Update peak if needed
        loop {
            let peak = self.peak_bytes.load(Ordering::Relaxed);
            if new_current <= peak {
                break;
            }
            if self.peak_bytes.compare_exchange_weak(
                peak,
                new_current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ).is_ok() {
                break;
            }
        }

        if paged {
            self.paged_allocs.fetch_add(1, Ordering::Relaxed);
        } else {
            self.non_paged_allocs.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a free
    pub fn record_free(&self, size: usize) {
        self.free_count.fetch_add(1, Ordering::Relaxed);
        self.current_count.fetch_sub(1, Ordering::Relaxed);
        self.current_bytes.fetch_sub(size as u64, Ordering::Relaxed);
    }

    /// Get tag as a string (4 ASCII characters)
    pub fn tag_string(&self) -> [u8; 4] {
        let tag = self.tag;
        [
            (tag & 0xFF) as u8,
            ((tag >> 8) & 0xFF) as u8,
            ((tag >> 16) & 0xFF) as u8,
            ((tag >> 24) & 0xFF) as u8,
        ]
    }
}

impl Default for PoolTagEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Pool Tag Table
// ============================================================================

/// Pool tag table entry with mutable tag field
struct PoolTagTableEntry {
    tag: u32,
    entry: PoolTagEntry,
}

impl PoolTagTableEntry {
    const fn new() -> Self {
        Self {
            tag: 0,
            entry: PoolTagEntry::new(),
        }
    }
}

static mut POOL_TAG_TABLE: [PoolTagTableEntry; MAX_POOL_TAGS] = {
    const INIT: PoolTagTableEntry = PoolTagTableEntry::new();
    [INIT; MAX_POOL_TAGS]
};

static POOL_TAG_LOCK: SpinLock<()> = SpinLock::new(());
static POOL_TAG_INITIALIZED: AtomicBool = AtomicBool::new(false);
static POOL_TAG_COUNT: AtomicU32 = AtomicU32::new(0);

// Global statistics
static TOTAL_ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static TOTAL_FREE_COUNT: AtomicU64 = AtomicU64::new(0);
static TOTAL_BYTES_ALLOCATED: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Tag Lookup and Management
// ============================================================================

/// Convert a 4-character string to a pool tag
pub const fn make_pool_tag(a: u8, b: u8, c: u8, d: u8) -> u32 {
    (a as u32) | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
}

/// Convert a string slice to a pool tag
pub fn str_to_pool_tag(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let a = bytes.first().copied().unwrap_or(b' ');
    let b = bytes.get(1).copied().unwrap_or(b' ');
    let c = bytes.get(2).copied().unwrap_or(b' ');
    let d = bytes.get(3).copied().unwrap_or(b' ');
    make_pool_tag(a, b, c, d)
}

/// Find or create a tag entry
fn find_or_create_tag(tag: u32) -> Option<&'static PoolTagEntry> {
    let _guard = POOL_TAG_LOCK.lock();

    unsafe {
        // First, try to find existing entry
        for entry in POOL_TAG_TABLE.iter() {
            if entry.entry.in_use.load(Ordering::Acquire) && entry.tag == tag {
                return Some(&entry.entry);
            }
        }

        // Not found, create new entry
        for entry in POOL_TAG_TABLE.iter_mut() {
            if !entry.entry.in_use.load(Ordering::Acquire) {
                entry.tag = tag;
                entry.entry.init(tag);
                POOL_TAG_COUNT.fetch_add(1, Ordering::Relaxed);
                return Some(&entry.entry);
            }
        }
    }

    None // Table full
}

/// Look up a tag entry (doesn't create)
fn find_tag(tag: u32) -> Option<&'static PoolTagEntry> {
    unsafe {
        for entry in POOL_TAG_TABLE.iter() {
            if entry.entry.in_use.load(Ordering::Acquire) && entry.tag == tag {
                return Some(&entry.entry);
            }
        }
    }
    None
}

// ============================================================================
// Pool Allocation Tracking
// ============================================================================

/// Record a pool allocation with tag
pub fn record_pool_alloc(tag: u32, size: usize, paged: bool) {
    if !POOL_TAG_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    TOTAL_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    TOTAL_BYTES_ALLOCATED.fetch_add(size as u64, Ordering::Relaxed);

    if let Some(entry) = find_or_create_tag(tag) {
        entry.record_alloc(size, paged);
    }
}

/// Record a pool free with tag
pub fn record_pool_free(tag: u32, size: usize) {
    if !POOL_TAG_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    TOTAL_FREE_COUNT.fetch_add(1, Ordering::Relaxed);

    if let Some(entry) = find_tag(tag) {
        entry.record_free(size);
    }
}

/// Record allocation with string tag
pub fn record_pool_alloc_str(tag: &str, size: usize, paged: bool) {
    record_pool_alloc(str_to_pool_tag(tag), size, paged);
}

/// Record free with string tag
pub fn record_pool_free_str(tag: &str, size: usize) {
    record_pool_free(str_to_pool_tag(tag), size);
}

// ============================================================================
// Well-Known Pool Tags
// ============================================================================

/// Well-known pool tags
pub mod pool_tags {
    use super::make_pool_tag;

    /// IRP allocation
    pub const IRP: u32 = make_pool_tag(b'I', b'r', b'p', b' ');
    /// MDL allocation
    pub const MDL: u32 = make_pool_tag(b'M', b'd', b'l', b' ');
    /// File object
    pub const FILE: u32 = make_pool_tag(b'F', b'i', b'l', b'e');
    /// Thread structure
    pub const THREAD: u32 = make_pool_tag(b'T', b'h', b'r', b'e');
    /// Process structure
    pub const PROCESS: u32 = make_pool_tag(b'P', b'r', b'o', b'c');
    /// Event object
    pub const EVENT: u32 = make_pool_tag(b'E', b'v', b'n', b't');
    /// Semaphore
    pub const SEMAPHORE: u32 = make_pool_tag(b'S', b'e', b'm', b'a');
    /// Mutex
    pub const MUTEX: u32 = make_pool_tag(b'M', b'u', b't', b'x');
    /// Timer
    pub const TIMER: u32 = make_pool_tag(b'T', b'i', b'm', b'r');
    /// Registry key
    pub const REGKEY: u32 = make_pool_tag(b'C', b'm', b'K', b'b');
    /// Registry value
    pub const REGVAL: u32 = make_pool_tag(b'C', b'm', b'V', b'a');
    /// Object header
    pub const OBJECT: u32 = make_pool_tag(b'O', b'b', b'j', b'h');
    /// Handle table
    pub const HANDLE: u32 = make_pool_tag(b'H', b'n', b'd', b'l');
    /// Security token
    pub const TOKEN: u32 = make_pool_tag(b'T', b'o', b'k', b'e');
    /// ACL
    pub const ACL: u32 = make_pool_tag(b'A', b'c', b'l', b' ');
    /// SID
    pub const SID: u32 = make_pool_tag(b'S', b'i', b'd', b' ');
    /// Named pipe
    pub const PIPE: u32 = make_pool_tag(b'N', b'p', b'F', b's');
    /// Lookaside list
    pub const LOOKASIDE: u32 = make_pool_tag(b'L', b'o', b'o', b'k');
    /// Driver object
    pub const DRIVER: u32 = make_pool_tag(b'D', b'r', b'v', b'r');
    /// Device object
    pub const DEVICE: u32 = make_pool_tag(b'D', b'e', b'v', b'i');
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize pool tag tracking
pub fn init() {
    let _guard = POOL_TAG_LOCK.lock();

    unsafe {
        for entry in POOL_TAG_TABLE.iter_mut() {
            *entry = PoolTagTableEntry::new();
        }
    }

    POOL_TAG_COUNT.store(0, Ordering::Relaxed);
    TOTAL_ALLOC_COUNT.store(0, Ordering::Relaxed);
    TOTAL_FREE_COUNT.store(0, Ordering::Relaxed);
    TOTAL_BYTES_ALLOCATED.store(0, Ordering::Relaxed);

    POOL_TAG_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[EX] Pool tag tracking initialized");
}

// ============================================================================
// Statistics and Inspection
// ============================================================================

/// Pool tag statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct PoolTagStats {
    /// Number of unique tags tracked
    pub tag_count: u32,
    /// Total allocations
    pub total_allocs: u64,
    /// Total frees
    pub total_frees: u64,
    /// Total bytes allocated (lifetime)
    pub total_bytes: u64,
    /// Outstanding allocations
    pub outstanding_allocs: u64,
}

/// Get overall pool tag statistics
pub fn get_pool_tag_stats() -> PoolTagStats {
    let allocs = TOTAL_ALLOC_COUNT.load(Ordering::Relaxed);
    let frees = TOTAL_FREE_COUNT.load(Ordering::Relaxed);

    PoolTagStats {
        tag_count: POOL_TAG_COUNT.load(Ordering::Relaxed),
        total_allocs: allocs,
        total_frees: frees,
        total_bytes: TOTAL_BYTES_ALLOCATED.load(Ordering::Relaxed),
        outstanding_allocs: allocs.saturating_sub(frees),
    }
}

/// Individual tag snapshot
#[derive(Debug, Clone, Copy, Default)]
pub struct PoolTagSnapshot {
    /// Pool tag (4 bytes)
    pub tag: u32,
    /// Tag as ASCII characters
    pub tag_chars: [u8; 4],
    /// Total allocations
    pub alloc_count: u64,
    /// Total frees
    pub free_count: u64,
    /// Current allocations (alloc - free)
    pub current_count: u64,
    /// Total bytes allocated
    pub total_bytes: u64,
    /// Current bytes in use
    pub current_bytes: u64,
    /// Peak bytes
    pub peak_bytes: u64,
    /// Non-paged allocations
    pub non_paged_allocs: u64,
    /// Paged allocations
    pub paged_allocs: u64,
}

/// Get all pool tag snapshots
pub fn get_pool_tag_snapshots() -> [Option<PoolTagSnapshot>; MAX_POOL_TAGS] {
    let mut snapshots = [None; MAX_POOL_TAGS];

    unsafe {
        for (i, entry) in POOL_TAG_TABLE.iter().enumerate() {
            if entry.entry.in_use.load(Ordering::Relaxed) {
                let tag = entry.tag;
                snapshots[i] = Some(PoolTagSnapshot {
                    tag,
                    tag_chars: [
                        (tag & 0xFF) as u8,
                        ((tag >> 8) & 0xFF) as u8,
                        ((tag >> 16) & 0xFF) as u8,
                        ((tag >> 24) & 0xFF) as u8,
                    ],
                    alloc_count: entry.entry.alloc_count.load(Ordering::Relaxed),
                    free_count: entry.entry.free_count.load(Ordering::Relaxed),
                    current_count: entry.entry.current_count.load(Ordering::Relaxed),
                    total_bytes: entry.entry.total_bytes.load(Ordering::Relaxed),
                    current_bytes: entry.entry.current_bytes.load(Ordering::Relaxed),
                    peak_bytes: entry.entry.peak_bytes.load(Ordering::Relaxed),
                    non_paged_allocs: entry.entry.non_paged_allocs.load(Ordering::Relaxed),
                    paged_allocs: entry.entry.paged_allocs.load(Ordering::Relaxed),
                });
            }
        }
    }

    snapshots
}

/// Get snapshot for a specific tag
pub fn get_tag_snapshot(tag: u32) -> Option<PoolTagSnapshot> {
    unsafe {
        for entry in POOL_TAG_TABLE.iter() {
            if entry.entry.in_use.load(Ordering::Relaxed) && entry.tag == tag {
                return Some(PoolTagSnapshot {
                    tag,
                    tag_chars: [
                        (tag & 0xFF) as u8,
                        ((tag >> 8) & 0xFF) as u8,
                        ((tag >> 16) & 0xFF) as u8,
                        ((tag >> 24) & 0xFF) as u8,
                    ],
                    alloc_count: entry.entry.alloc_count.load(Ordering::Relaxed),
                    free_count: entry.entry.free_count.load(Ordering::Relaxed),
                    current_count: entry.entry.current_count.load(Ordering::Relaxed),
                    total_bytes: entry.entry.total_bytes.load(Ordering::Relaxed),
                    current_bytes: entry.entry.current_bytes.load(Ordering::Relaxed),
                    peak_bytes: entry.entry.peak_bytes.load(Ordering::Relaxed),
                    non_paged_allocs: entry.entry.non_paged_allocs.load(Ordering::Relaxed),
                    paged_allocs: entry.entry.paged_allocs.load(Ordering::Relaxed),
                });
            }
        }
    }
    None
}

/// Get count of tracked tags
pub fn get_tag_count() -> u32 {
    POOL_TAG_COUNT.load(Ordering::Relaxed)
}

/// Find tags with outstanding allocations (potential leaks)
pub fn find_leaking_tags() -> [Option<PoolTagSnapshot>; MAX_POOL_TAGS] {
    let mut leaks = [None; MAX_POOL_TAGS];
    let mut leak_index = 0;

    unsafe {
        for entry in POOL_TAG_TABLE.iter() {
            if entry.entry.in_use.load(Ordering::Relaxed) {
                let current = entry.entry.current_count.load(Ordering::Relaxed);
                if current > 0 && leak_index < MAX_POOL_TAGS {
                    let tag = entry.tag;
                    leaks[leak_index] = Some(PoolTagSnapshot {
                        tag,
                        tag_chars: [
                            (tag & 0xFF) as u8,
                            ((tag >> 8) & 0xFF) as u8,
                            ((tag >> 16) & 0xFF) as u8,
                            ((tag >> 24) & 0xFF) as u8,
                        ],
                        alloc_count: entry.entry.alloc_count.load(Ordering::Relaxed),
                        free_count: entry.entry.free_count.load(Ordering::Relaxed),
                        current_count: current,
                        total_bytes: entry.entry.total_bytes.load(Ordering::Relaxed),
                        current_bytes: entry.entry.current_bytes.load(Ordering::Relaxed),
                        peak_bytes: entry.entry.peak_bytes.load(Ordering::Relaxed),
                        non_paged_allocs: entry.entry.non_paged_allocs.load(Ordering::Relaxed),
                        paged_allocs: entry.entry.paged_allocs.load(Ordering::Relaxed),
                    });
                    leak_index += 1;
                }
            }
        }
    }

    leaks
}
