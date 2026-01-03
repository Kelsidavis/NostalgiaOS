//! RTL Range Lists
//!
//! Implements range list utilities for resource management:
//! - Range list for tracking I/O ports, memory regions
//! - Range merging and conflict detection
//! - Used by PnP resource arbiters
//!
//! Based on Windows Server 2003 base/ntos/rtl/range.c

use core::ptr;

/// Range list entry tag
pub const RTL_RANGE_LIST_ENTRY_TAG: u32 = 0x656C5452; // 'RlTe'
pub const RTL_RANGE_LIST_MISC_TAG: u32 = 0x6D6C5452; // 'RlMi'

/// Range flags
pub mod range_flags {
    /// Range is shared with other owners
    pub const RTL_RANGE_SHARED: u8 = 0x01;
    /// Range has a conflict
    pub const RTL_RANGE_CONFLICT: u8 = 0x02;
}

/// Add range flags
pub mod add_flags {
    /// Add range even if it conflicts
    pub const RTL_RANGE_LIST_ADD_IF_CONFLICT: u32 = 0x00000001;
    /// Mark range as shared
    pub const RTL_RANGE_LIST_ADD_SHARED: u32 = 0x00000002;
}

/// Is range available flags
pub mod available_flags {
    /// Shared ranges are considered available
    pub const RTL_RANGE_LIST_SHARED_OK: u32 = 0x00000001;
    /// NULL owner conflicts are OK
    pub const RTL_RANGE_LIST_NULL_CONFLICT_OK: u32 = 0x00000002;
}

/// Merge flags
pub mod merge_flags {
    /// Merge even if there are conflicts
    pub const RTL_RANGE_LIST_MERGE_IF_CONFLICT: u32 = 0x00000001;
}

/// Internal range entry flags
mod private_flags {
    pub const RTLP_RANGE_LIST_ENTRY_MERGED: u8 = 0x01;
}

/// List entry for doubly-linked list
#[repr(C)]
#[derive(Debug)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

impl ListEntry {
    pub const fn new() -> Self {
        Self {
            flink: ptr::null_mut(),
            blink: ptr::null_mut(),
        }
    }

    /// Initialize as empty list head
    pub fn init_head(&mut self) {
        self.flink = self;
        self.blink = self;
    }

    /// Check if list is empty
    pub fn is_empty(&self) -> bool {
        self.flink as *const _ == self as *const _
    }

    /// Insert entry after this one
    pub unsafe fn insert_after(&mut self, entry: *mut ListEntry) {
        (*entry).flink = self.flink;
        (*entry).blink = self;
        (*self.flink).blink = entry;
        self.flink = entry;
    }

    /// Insert entry before this one
    pub unsafe fn insert_before(&mut self, entry: *mut ListEntry) {
        (*entry).blink = self.blink;
        (*entry).flink = self;
        (*self.blink).flink = entry;
        self.blink = entry;
    }

    /// Remove this entry from its list
    pub unsafe fn remove(&mut self) {
        let flink = self.flink;
        let blink = self.blink;
        (*blink).flink = flink;
        (*flink).blink = blink;
    }

    /// Insert at tail of list
    pub unsafe fn insert_tail(head: *mut ListEntry, entry: *mut ListEntry) {
        (*entry).flink = head;
        (*entry).blink = (*head).blink;
        (*(*head).blink).flink = entry;
        (*head).blink = entry;
    }
}

/// Public range structure (what users see)
#[repr(C)]
#[derive(Debug)]
pub struct RtlRange {
    /// Start of range
    pub start: u64,
    /// End of range (inclusive)
    pub end: u64,
    /// User-defined data
    pub user_data: *mut u8,
    /// Owner cookie
    pub owner: *mut u8,
    /// Attributes
    pub attributes: u8,
    /// Flags (RTL_RANGE_SHARED, RTL_RANGE_CONFLICT)
    pub flags: u8,
    /// Reserved
    reserved: [u8; 6],
}

impl RtlRange {
    pub const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            user_data: ptr::null_mut(),
            owner: ptr::null_mut(),
            attributes: 0,
            flags: 0,
            reserved: [0; 6],
        }
    }
}

/// Allocated range data
#[repr(C)]
#[derive(Clone, Copy)]
struct AllocatedData {
    user_data: *mut u8,
    owner: *mut u8,
}

/// Merged range data (stores list head as raw pointers for union compatibility)
#[repr(C)]
#[derive(Clone, Copy)]
struct MergedData {
    /// List head flink pointer
    list_head_flink: *mut ListEntry,
    /// List head blink pointer
    list_head_blink: *mut ListEntry,
}

impl MergedData {
    /// Get address of the embedded list head
    fn list_head_ptr(&mut self) -> *mut ListEntry {
        &mut self.list_head_flink as *mut *mut ListEntry as *mut ListEntry
    }

    /// Initialize as empty list
    fn init(&mut self) {
        let head = self.list_head_ptr();
        self.list_head_flink = head;
        self.list_head_blink = head;
    }

    /// Check if list is empty
    fn is_empty(&self) -> bool {
        let head = &self.list_head_flink as *const *mut ListEntry as *const ListEntry;
        self.list_head_flink as *const ListEntry == head
    }
}

/// Internal range list entry
#[repr(C)]
pub struct RangeListEntry {
    /// Start of range
    start: u64,
    /// End of range (inclusive)
    end: u64,
    /// Allocated or merged union
    data: RangeEntryData,
    /// Attributes
    attributes: u8,
    /// Public flags
    public_flags: u8,
    /// Private flags
    private_flags: u8,
    /// Padding
    _padding: u8,
    /// List entry
    list_entry: ListEntry,
}

/// Union for allocated vs merged entry data
#[repr(C)]
union RangeEntryData {
    allocated: AllocatedData,
    merged: MergedData,
}

impl Clone for RangeEntryData {
    fn clone(&self) -> Self {
        // Default to allocated since we can't know which variant
        unsafe {
            RangeEntryData {
                allocated: self.allocated,
            }
        }
    }
}

impl RangeListEntry {
    pub fn is_merged(&self) -> bool {
        self.private_flags & private_flags::RTLP_RANGE_LIST_ENTRY_MERGED != 0
    }

    pub fn is_shared(&self) -> bool {
        self.public_flags & range_flags::RTL_RANGE_SHARED != 0
    }

    pub fn is_conflict(&self) -> bool {
        self.public_flags & range_flags::RTL_RANGE_CONFLICT != 0
    }

    /// Check if two ranges intersect
    pub fn intersects(&self, other: &RangeListEntry) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Check if two ranges intersect (by limits)
    pub fn intersects_limits(&self, start: u64, end: u64) -> bool {
        self.start <= end && start <= self.end
    }
}

/// Range list header
#[repr(C)]
pub struct RtlRangeList {
    /// List of ranges
    list_head: ListEntry,
    /// Flags
    flags: u32,
    /// Number of ranges
    count: u32,
    /// Modification stamp
    stamp: u32,
}

impl RtlRangeList {
    pub const fn new() -> Self {
        Self {
            list_head: ListEntry::new(),
            flags: 0,
            count: 0,
            stamp: 0,
        }
    }
}

/// Range list iterator
#[repr(C)]
pub struct RtlRangeListIterator {
    /// Current position
    pub current: *mut RangeListEntry,
    /// Main list head
    pub range_list_head: *mut ListEntry,
    /// Merged list head (if in merged range)
    pub merged_head: *mut ListEntry,
    /// Modification stamp for validation
    pub stamp: u32,
}

impl RtlRangeListIterator {
    pub const fn new() -> Self {
        Self {
            current: ptr::null_mut(),
            range_list_head: ptr::null_mut(),
            merged_head: ptr::null_mut(),
            stamp: 0,
        }
    }
}

/// Conflict callback function type
pub type RtlConflictRangeCallback =
    unsafe fn(context: *mut u8, range: *const RtlRange) -> bool;

// ============================================================================
// Range List Functions
// ============================================================================

/// Initialize a range list
pub fn rtl_initialize_range_list(range_list: &mut RtlRangeList) {
    range_list.list_head.init_head();
    range_list.flags = 0;
    range_list.count = 0;
    range_list.stamp = 0;
}

/// Add a range to the list
pub unsafe fn rtl_add_range(
    range_list: &mut RtlRangeList,
    start: u64,
    end: u64,
    attributes: u8,
    flags: u32,
    user_data: *mut u8,
    owner: *mut u8,
) -> i32 {
    // Validate parameters
    if end < start {
        return -1073741811; // STATUS_INVALID_PARAMETER
    }

    // Allocate new entry (in real kernel would use lookaside list)
    let entry = alloc_range_entry();
    if entry.is_null() {
        return -1073741801; // STATUS_INSUFFICIENT_RESOURCES
    }

    // Initialize entry
    (*entry).start = start;
    (*entry).end = end;
    (*entry).attributes = attributes;
    (*entry).public_flags = 0;
    (*entry).private_flags = 0;
    (*entry).data.allocated = AllocatedData { user_data, owner };

    if flags & add_flags::RTL_RANGE_LIST_ADD_SHARED != 0 {
        (*entry).public_flags |= range_flags::RTL_RANGE_SHARED;
    }

    let status = add_range_internal(&mut range_list.list_head, entry, flags);

    if status >= 0 {
        range_list.count += 1;
        range_list.stamp += 1;
    } else {
        free_range_entry(entry);
    }

    status
}

/// Internal add range implementation
unsafe fn add_range_internal(
    list_head: *mut ListEntry,
    entry: *mut RangeListEntry,
    flags: u32,
) -> i32 {
    let _start = (*entry).start;
    let end = (*entry).end;

    // Clear conflict flag
    (*entry).public_flags &= !range_flags::RTL_RANGE_CONFLICT;

    // Find insertion point
    let mut current = (*list_head).flink;

    while current != list_head {
        let current_entry = list_entry_to_range_entry(current);

        if end < (*current_entry).start {
            // Insert before current
            (*current).insert_before(&mut (*entry).list_entry);
            return 0;
        }

        if (*entry).intersects(&*current_entry) {
            return add_intersecting_ranges(list_head, current_entry, entry, flags);
        }

        current = (*current).flink;
    }

    // Add at end
    ListEntry::insert_tail(list_head, &mut (*entry).list_entry);
    0
}

/// Handle intersecting range insertion
unsafe fn add_intersecting_ranges(
    list_head: *mut ListEntry,
    first: *mut RangeListEntry,
    entry: *mut RangeListEntry,
    flags: u32,
) -> i32 {
    let entry_shared = (*entry).is_shared();

    // Check for conflicts if we care
    if flags & add_flags::RTL_RANGE_LIST_ADD_IF_CONFLICT == 0 {
        let mut current = first;
        while &(*current).list_entry as *const _ != list_head {
            if (*entry).end < (*current).start {
                break;
            }

            if (*current).is_merged() {
                // Check merged ranges
                let merged_head = (*current).data.merged.list_head_ptr();
                let mut merged_current = (*merged_head).flink;

                while merged_current != merged_head {
                    let merged_entry = list_entry_to_range_entry(merged_current);
                    if (*entry).intersects(&*merged_entry)
                        && !(entry_shared && (*merged_entry).is_shared())
                    {
                        return -1073741793; // STATUS_RANGE_LIST_CONFLICT
                    }
                    merged_current = (*merged_current).flink;
                }
            } else if !(entry_shared && (*current).is_shared()) {
                return -1073741793; // STATUS_RANGE_LIST_CONFLICT
            }

            current = list_entry_to_range_entry((*current).list_entry.flink);
        }
    }

    // Convert first to merged if needed
    if !(*first).is_merged() {
        let status = convert_to_merged(first);
        if status < 0 {
            return status;
        }
    }

    // Add intersecting ranges to merged
    let mut current = list_entry_to_range_entry((*first).list_entry.flink);

    while &(*current).list_entry as *const _ != list_head {
        if (*entry).end < (*current).start {
            break;
        }

        let next = list_entry_to_range_entry((*current).list_entry.flink);

        if (*current).is_merged() {
            // Move all merged entries to first
            let merged_head = (*current).data.merged.list_head_ptr();
            while !(*merged_head).is_empty() {
                let merged_entry = list_entry_to_range_entry((*merged_head).flink);
                (*merged_entry).list_entry.remove();
                add_to_merged(first, merged_entry, flags);
            }
            (*current).list_entry.remove();
            free_range_entry(current);
        } else {
            (*current).list_entry.remove();
            add_to_merged(first, current, flags);
        }

        current = next;
    }

    // Add the new entry
    add_to_merged(first, entry, flags);

    0
}

/// Convert a range entry to a merged entry
unsafe fn convert_to_merged(entry: *mut RangeListEntry) -> i32 {
    // Copy the entry
    let new_entry = alloc_range_entry();
    if new_entry.is_null() {
        return -1073741801; // STATUS_INSUFFICIENT_RESOURCES
    }

    (*new_entry).start = (*entry).start;
    (*new_entry).end = (*entry).end;
    (*new_entry).attributes = (*entry).attributes;
    (*new_entry).public_flags = (*entry).public_flags;
    (*new_entry).private_flags = 0;
    (*new_entry).data = (*entry).data.clone();

    // Convert to merged
    (*entry).data.merged.init();
    (*entry).private_flags = private_flags::RTLP_RANGE_LIST_ENTRY_MERGED;

    // Add copy to merged list
    ListEntry::insert_tail(
        (*entry).data.merged.list_head_ptr(),
        &mut (*new_entry).list_entry,
    );

    0
}

/// Add entry to a merged range
unsafe fn add_to_merged(
    merged: *mut RangeListEntry,
    entry: *mut RangeListEntry,
    flags: u32,
) -> i32 {
    let entry_shared = (*entry).is_shared();
    let merged_head = (*merged).data.merged.list_head_ptr();

    // Find insertion point and check conflicts
    let mut insert = ptr::null_mut::<ListEntry>();
    let mut current = (*merged_head).flink;

    while current != merged_head {
        let current_entry = list_entry_to_range_entry(current);

        // Check conflict
        if (*entry).intersects(&*current_entry)
            && !(entry_shared && (*current_entry).is_shared())
        {
            if flags & add_flags::RTL_RANGE_LIST_ADD_IF_CONFLICT != 0 {
                (*current_entry).public_flags |= range_flags::RTL_RANGE_CONFLICT;
                (*entry).public_flags |= range_flags::RTL_RANGE_CONFLICT;
            } else {
                return -1073741793; // STATUS_RANGE_LIST_CONFLICT
            }
        }

        // Track insertion point
        if insert.is_null() && (*current_entry).start > (*entry).start {
            insert = (*current).blink;
        }

        current = (*current).flink;
    }

    // Insert
    if insert.is_null() {
        ListEntry::insert_tail(merged_head, &mut (*entry).list_entry);
    } else {
        (*insert).insert_after(&mut (*entry).list_entry);
    }

    // Expand merged range if needed
    if (*entry).start < (*merged).start {
        (*merged).start = (*entry).start;
    }
    if (*entry).end > (*merged).end {
        (*merged).end = (*entry).end;
    }

    // Update shared flag
    if (*merged).is_shared() && !entry_shared {
        (*merged).public_flags &= !range_flags::RTL_RANGE_SHARED;
    }

    0
}

/// Delete a range from the list
pub unsafe fn rtl_delete_range(
    range_list: &mut RtlRangeList,
    start: u64,
    end: u64,
    owner: *mut u8,
) -> i32 {
    let list_head = &mut range_list.list_head as *mut ListEntry;
    let mut current = (*list_head).flink;

    while current != list_head {
        if end < (*list_entry_to_range_entry(current)).start {
            break;
        }

        let current_entry = list_entry_to_range_entry(current);

        if (*current_entry).is_merged() {
            // Search merged list
            if start >= (*current_entry).start && end <= (*current_entry).end {
                let merged_head = (*current_entry).data.merged.list_head_ptr();
                let mut merged_current = (*merged_head).flink;

                while merged_current != merged_head {
                    let merged_entry = list_entry_to_range_entry(merged_current);

                    if (*merged_entry).start == start
                        && (*merged_entry).end == end
                        && (*merged_entry).data.allocated.owner == owner
                    {
                        // Found it - delete
                        (*merged_current).remove();
                        free_range_entry(merged_entry);
                        range_list.count -= 1;
                        range_list.stamp += 1;
                        // TODO: Rebuild merged range if needed
                        return 0;
                    }

                    merged_current = (*merged_current).flink;
                }
            }
        } else if (*current_entry).start == start
            && (*current_entry).end == end
            && (*current_entry).data.allocated.owner == owner
        {
            // Found it - delete
            (*current).remove();
            free_range_entry(current_entry);
            range_list.count -= 1;
            range_list.stamp += 1;
            return 0;
        }

        current = (*current).flink;
    }

    -1073741772 // STATUS_RANGE_NOT_FOUND
}

/// Delete all ranges owned by a specific owner
pub unsafe fn rtl_delete_owners_ranges(
    range_list: &mut RtlRangeList,
    owner: *mut u8,
) -> i32 {
    loop {
        let list_head = &mut range_list.list_head as *mut ListEntry;
        let mut current = (*list_head).flink;
        let mut found = false;

        while current != list_head {
            let current_entry = list_entry_to_range_entry(current);
            let next = (*current).flink;

            if (*current_entry).is_merged() {
                let merged_head = (*current_entry).data.merged.list_head_ptr();
                let mut merged_current = (*merged_head).flink;

                while merged_current != merged_head {
                    let merged_entry = list_entry_to_range_entry(merged_current);
                    let merged_next = (*merged_current).flink;

                    if (*merged_entry).data.allocated.owner == owner {
                        (*merged_current).remove();
                        free_range_entry(merged_entry);
                        range_list.count -= 1;
                        range_list.stamp += 1;
                        found = true;
                        break;
                    }

                    merged_current = merged_next;
                }

                if found {
                    break;
                }
            } else if (*current_entry).data.allocated.owner == owner {
                (*current).remove();
                free_range_entry(current_entry);
                range_list.count -= 1;
                range_list.stamp += 1;
                found = true;
                break;
            }

            current = next;
        }

        if !found {
            break;
        }
    }

    0
}

/// Check if a range is available
pub unsafe fn rtl_is_range_available(
    range_list: &RtlRangeList,
    start: u64,
    end: u64,
    flags: u32,
    attribute_mask: u8,
    _context: *mut u8,
    _callback: Option<RtlConflictRangeCallback>,
) -> bool {
    let shared_ok = flags & available_flags::RTL_RANGE_LIST_SHARED_OK != 0;
    let null_ok = flags & available_flags::RTL_RANGE_LIST_NULL_CONFLICT_OK != 0;

    let list_head = &range_list.list_head as *const ListEntry;
    let mut current = (*list_head).flink;

    while current != list_head as *const _ as *mut _ {
        let entry = list_entry_to_range_entry(current);

        if end < (*entry).start {
            break;
        }

        if (*entry).is_merged() {
            let merged_head = (*entry).data.merged.list_head_ptr();
            let mut merged_current = (*merged_head).flink;

            while merged_current != merged_head {
                let merged_entry = list_entry_to_range_entry(merged_current);

                if (*merged_entry).intersects_limits(start, end) {
                    if !((shared_ok && (*merged_entry).is_shared())
                        || ((*merged_entry).attributes & attribute_mask != 0)
                        || (null_ok && (*merged_entry).data.allocated.owner.is_null()))
                    {
                        return false;
                    }
                }

                merged_current = (*merged_current).flink;
            }
        } else if (*entry).intersects_limits(start, end) {
            if !((shared_ok && (*entry).is_shared())
                || ((*entry).attributes & attribute_mask != 0)
                || (null_ok && (*entry).data.allocated.owner.is_null()))
            {
                return false;
            }
        }

        current = (*current).flink;
    }

    true
}

/// Find an available range
pub unsafe fn rtl_find_range(
    range_list: &RtlRangeList,
    minimum: u64,
    maximum: u64,
    length: u32,
    alignment: u32,
    flags: u32,
    attribute_mask: u8,
    context: *mut u8,
    callback: Option<RtlConflictRangeCallback>,
) -> Option<u64> {
    if length == 0 || alignment == 0 || minimum > maximum {
        return None;
    }

    if maximum - minimum < length as u64 - 1 {
        return None;
    }

    // Search from high to low
    let mut start = maximum - (length as u64 - 1);
    start -= start % alignment as u64;

    if start < minimum {
        return None;
    }

    while start >= minimum {
        let end = start + length as u64 - 1;

        if rtl_is_range_available(range_list, start, end, flags, attribute_mask, context, callback)
        {
            return Some(start);
        }

        // Move down
        if start < length as u64 + alignment as u64 {
            break;
        }
        start -= alignment as u64;
    }

    None
}

/// Get the first range
pub unsafe fn rtl_get_first_range(
    range_list: &RtlRangeList,
    iterator: &mut RtlRangeListIterator,
) -> *mut RtlRange {
    iterator.range_list_head = &range_list.list_head as *const _ as *mut _;
    iterator.stamp = range_list.stamp;
    iterator.merged_head = ptr::null_mut();

    if range_list.list_head.is_empty() {
        iterator.current = ptr::null_mut();
        return ptr::null_mut();
    }

    let first = list_entry_to_range_entry(range_list.list_head.flink);

    if (*first).is_merged() {
        iterator.merged_head = (*first).data.merged.list_head_ptr();
        iterator.current =
            list_entry_to_range_entry((*iterator.merged_head).flink);
    } else {
        iterator.current = first;
    }

    iterator.current as *mut RtlRange
}

/// Get the next range
pub unsafe fn rtl_get_next_range(
    iterator: &mut RtlRangeListIterator,
    move_forwards: bool,
) -> *mut RtlRange {
    if iterator.current.is_null() {
        return ptr::null_mut();
    }

    let entry = &mut (*iterator.current).list_entry;
    let next_list = if move_forwards {
        (*entry).flink
    } else {
        (*entry).blink
    };

    // In merged range?
    if !iterator.merged_head.is_null() {
        if next_list == iterator.merged_head {
            // End of merged range, go to next main entry
            let merged_entry = container_of_merged(iterator.merged_head);
            let main_next = if move_forwards {
                (*merged_entry).list_entry.flink
            } else {
                (*merged_entry).list_entry.blink
            };
            iterator.merged_head = ptr::null_mut();

            if main_next == iterator.range_list_head {
                iterator.current = ptr::null_mut();
                return ptr::null_mut();
            }

            let next_entry = list_entry_to_range_entry(main_next);
            if (*next_entry).is_merged() {
                iterator.merged_head = (*next_entry).data.merged.list_head_ptr();
                iterator.current = list_entry_to_range_entry(if move_forwards {
                    (*iterator.merged_head).flink
                } else {
                    (*iterator.merged_head).blink
                });
            } else {
                iterator.current = next_entry;
            }
        } else {
            iterator.current = list_entry_to_range_entry(next_list);
        }
    } else {
        if next_list == iterator.range_list_head {
            iterator.current = ptr::null_mut();
            return ptr::null_mut();
        }

        let next_entry = list_entry_to_range_entry(next_list);
        if (*next_entry).is_merged() {
            iterator.merged_head = (*next_entry).data.merged.list_head_ptr();
            iterator.current = list_entry_to_range_entry(if move_forwards {
                (*iterator.merged_head).flink
            } else {
                (*iterator.merged_head).blink
            });
        } else {
            iterator.current = next_entry;
        }
    }

    iterator.current as *mut RtlRange
}

/// Free all ranges in a list
pub unsafe fn rtl_free_range_list(range_list: &mut RtlRangeList) {
    let list_head = &mut range_list.list_head as *mut ListEntry;

    while !(*list_head).is_empty() {
        let entry = list_entry_to_range_entry((*list_head).flink);

        if (*entry).is_merged() {
            let merged_head = (*entry).data.merged.list_head_ptr();
            while !(*merged_head).is_empty() {
                let merged_entry = list_entry_to_range_entry((*merged_head).flink);
                (*merged_entry).list_entry.remove();
                free_range_entry(merged_entry);
            }
        }

        (*entry).list_entry.remove();
        free_range_entry(entry);
    }

    range_list.flags = 0;
    range_list.count = 0;
}

// ============================================================================
// Helper functions
// ============================================================================

/// Get range entry from list entry
unsafe fn list_entry_to_range_entry(list: *mut ListEntry) -> *mut RangeListEntry {
    let offset = core::mem::offset_of!(RangeListEntry, list_entry);
    (list as usize - offset) as *mut RangeListEntry
}

/// Get merged entry from merged list head
unsafe fn container_of_merged(merged_head: *mut ListEntry) -> *mut RangeListEntry {
    // The merged list head is at offset of data.merged.list_head
    let offset = core::mem::offset_of!(RangeListEntry, data);
    (merged_head as usize - offset) as *mut RangeListEntry
}

// Simple allocation functions (would use pool in real kernel)
use core::alloc::Layout;

extern "Rust" {
    fn __rust_alloc(size: usize, align: usize) -> *mut u8;
    fn __rust_dealloc(ptr: *mut u8, size: usize, align: usize);
}

fn alloc_range_entry() -> *mut RangeListEntry {
    unsafe {
        let layout = Layout::new::<RangeListEntry>();
        let ptr = __rust_alloc(layout.size(), layout.align());
        if ptr.is_null() {
            return ptr::null_mut();
        }
        let entry = ptr as *mut RangeListEntry;
        core::ptr::write_bytes(entry, 0, 1);
        (*entry).list_entry.init_head();
        entry
    }
}

fn free_range_entry(entry: *mut RangeListEntry) {
    unsafe {
        if !entry.is_null() {
            let layout = Layout::new::<RangeListEntry>();
            __rust_dealloc(entry as *mut u8, layout.size(), layout.align());
        }
    }
}

/// Initialize range list subsystem
pub fn rtl_range_init() {
    crate::serial_println!("[RTL] Range list subsystem initialized");
}
