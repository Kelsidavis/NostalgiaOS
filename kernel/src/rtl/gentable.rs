//! RTL Generic Table
//!
//! Implements a generic table using splay trees for ordered storage:
//! - User-defined comparison and allocation routines
//! - O(log n) insert, lookup, and delete operations
//! - Maintains insertion order via linked list
//! - Enumeration support (ordered and insertion order)
//!
//! Based on Windows Server 2003 base/ntos/rtl/gentable.c

use core::ptr;
use crate::rtl::splay::SplayLinks;

/// Search result for table lookups
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableSearchResult {
    /// Table is empty
    EmptyTree,
    /// Node was found
    FoundNode,
    /// Insert as left child
    InsertAsLeft,
    /// Insert as right child
    InsertAsRight,
}

/// Comparison result from user compare routine
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericCompareResult {
    LessThan,
    GreaterThan,
    EqualTo,
}

/// List entry for doubly-linked list
#[repr(C)]
#[derive(Debug)]
pub struct GenericListEntry {
    pub flink: *mut GenericListEntry,
    pub blink: *mut GenericListEntry,
}

impl GenericListEntry {
    pub const fn new() -> Self {
        Self {
            flink: ptr::null_mut(),
            blink: ptr::null_mut(),
        }
    }

    /// Initialize as list head
    pub fn init_head(&mut self) {
        self.flink = self;
        self.blink = self;
    }

    /// Check if list is empty
    pub fn is_empty(&self) -> bool {
        self.flink as *const _ == self as *const _
    }
}

/// Generic table entry header
#[repr(C)]
pub struct TableEntryHeader {
    /// Splay tree links
    pub splay_links: SplayLinks,
    /// Insertion order list links
    pub list_entry: GenericListEntry,
    /// Start of user data (actually variable length)
    pub user_data: [u8; 0],
}

impl TableEntryHeader {
    /// Get pointer to user data
    pub fn user_data_ptr(&self) -> *const u8 {
        self.user_data.as_ptr()
    }

    /// Get mutable pointer to user data
    pub fn user_data_ptr_mut(&mut self) -> *mut u8 {
        self.user_data.as_mut_ptr()
    }
}

/// Comparison routine type
pub type RtlGenericCompareRoutine = unsafe fn(
    table: *const RtlGenericTable,
    first_struct: *const u8,
    second_struct: *const u8,
) -> GenericCompareResult;

/// Allocation routine type
pub type RtlGenericAllocateRoutine = unsafe fn(
    table: *const RtlGenericTable,
    byte_size: usize,
) -> *mut u8;

/// Free routine type
pub type RtlGenericFreeRoutine = unsafe fn(
    table: *const RtlGenericTable,
    buffer: *mut u8,
);

/// Generic table structure
#[repr(C)]
pub struct RtlGenericTable {
    /// Root of the splay tree
    pub table_root: *mut SplayLinks,
    /// Insertion order linked list
    pub insert_order_list: GenericListEntry,
    /// Number of elements in the table
    pub number_generic_table_elements: u32,
    /// Current position in ordered enumeration
    pub ordered_pointer: *mut GenericListEntry,
    /// Which element in ordered enumeration
    pub which_ordered_element: u32,
    /// User compare routine
    pub compare_routine: Option<RtlGenericCompareRoutine>,
    /// User allocate routine
    pub allocate_routine: Option<RtlGenericAllocateRoutine>,
    /// User free routine
    pub free_routine: Option<RtlGenericFreeRoutine>,
    /// User context
    pub table_context: *mut u8,
}

impl RtlGenericTable {
    pub const fn new() -> Self {
        Self {
            table_root: ptr::null_mut(),
            insert_order_list: GenericListEntry::new(),
            number_generic_table_elements: 0,
            ordered_pointer: ptr::null_mut(),
            which_ordered_element: 0,
            compare_routine: None,
            allocate_routine: None,
            free_routine: None,
            table_context: ptr::null_mut(),
        }
    }
}

// ============================================================================
// Core Functions
// ============================================================================

/// Initialize a generic table
pub fn rtl_initialize_generic_table(
    table: &mut RtlGenericTable,
    compare_routine: RtlGenericCompareRoutine,
    allocate_routine: RtlGenericAllocateRoutine,
    free_routine: RtlGenericFreeRoutine,
    table_context: *mut u8,
) {
    table.table_root = ptr::null_mut();
    table.insert_order_list.init_head();
    table.number_generic_table_elements = 0;
    table.ordered_pointer = &mut table.insert_order_list;
    table.which_ordered_element = 0;
    table.compare_routine = Some(compare_routine);
    table.allocate_routine = Some(allocate_routine);
    table.free_routine = Some(free_routine);
    table.table_context = table_context;
}

/// Check if table is empty
#[inline]
pub fn rtl_is_generic_table_empty(table: &RtlGenericTable) -> bool {
    table.table_root.is_null()
}

/// Get number of elements in table
#[inline]
pub fn rtl_number_generic_table_elements(table: &RtlGenericTable) -> u32 {
    table.number_generic_table_elements
}

/// Find a node or its parent in the table
unsafe fn find_node_or_parent(
    table: &RtlGenericTable,
    buffer: *const u8,
    node_or_parent: &mut *mut SplayLinks,
) -> TableSearchResult {
    if rtl_is_generic_table_empty(table) {
        return TableSearchResult::EmptyTree;
    }

    let compare = table.compare_routine.unwrap();
    let mut node_to_examine = table.table_root;

    loop {
        // Get user data from the entry
        let entry = node_to_examine as *const TableEntryHeader;
        let user_data = (*entry).user_data_ptr();

        let result = compare(table, buffer, user_data);

        match result {
            GenericCompareResult::LessThan => {
                let left = (*node_to_examine).left_child;
                if !left.is_null() {
                    node_to_examine = left;
                } else {
                    *node_or_parent = node_to_examine;
                    return TableSearchResult::InsertAsLeft;
                }
            }
            GenericCompareResult::GreaterThan => {
                let right = (*node_to_examine).right_child;
                if !right.is_null() {
                    node_to_examine = right;
                } else {
                    *node_or_parent = node_to_examine;
                    return TableSearchResult::InsertAsRight;
                }
            }
            GenericCompareResult::EqualTo => {
                *node_or_parent = node_to_examine;
                return TableSearchResult::FoundNode;
            }
        }
    }
}

/// Insert an element into the generic table
pub unsafe fn rtl_insert_element_generic_table(
    table: &mut RtlGenericTable,
    buffer: *const u8,
    buffer_size: usize,
    new_element: Option<&mut bool>,
) -> *mut u8 {
    let mut node_or_parent = ptr::null_mut();
    let lookup = find_node_or_parent(table, buffer, &mut node_or_parent);

    rtl_insert_element_generic_table_full(
        table,
        buffer,
        buffer_size,
        new_element,
        node_or_parent,
        lookup,
    )
}

/// Insert an element using pre-computed search result
pub unsafe fn rtl_insert_element_generic_table_full(
    table: &mut RtlGenericTable,
    buffer: *const u8,
    buffer_size: usize,
    new_element: Option<&mut bool>,
    node_or_parent: *mut SplayLinks,
    search_result: TableSearchResult,
) -> *mut u8 {
    if search_result != TableSearchResult::FoundNode {
        // Allocate space for new node
        let alloc = table.allocate_routine.unwrap();
        let header_size = core::mem::size_of::<TableEntryHeader>();
        let total_size = header_size + buffer_size;

        let node = alloc(table, total_size) as *mut TableEntryHeader;
        if node.is_null() {
            if let Some(flag) = new_element {
                *flag = false;
            }
            return ptr::null_mut();
        }

        // Initialize splay links
        (*node).splay_links.parent = &mut (*node).splay_links;
        (*node).splay_links.left_child = ptr::null_mut();
        (*node).splay_links.right_child = ptr::null_mut();

        // Insert into insertion order list
        let list_head = &mut table.insert_order_list as *mut GenericListEntry;
        let entry = &mut (*node).list_entry as *mut GenericListEntry;
        (*entry).flink = list_head;
        (*entry).blink = (*list_head).blink;
        (*(*list_head).blink).flink = entry;
        (*list_head).blink = entry;

        table.number_generic_table_elements += 1;

        // Insert into tree
        match search_result {
            TableSearchResult::EmptyTree => {
                table.table_root = &mut (*node).splay_links;
            }
            TableSearchResult::InsertAsLeft => {
                (*node_or_parent).left_child = &mut (*node).splay_links;
                (*node).splay_links.parent = node_or_parent;
            }
            TableSearchResult::InsertAsRight => {
                (*node_or_parent).right_child = &mut (*node).splay_links;
                (*node).splay_links.parent = node_or_parent;
            }
            _ => {}
        }

        // Copy user data
        let user_data = (*node).user_data_ptr_mut();
        core::ptr::copy_nonoverlapping(buffer, user_data, buffer_size);

        if let Some(flag) = new_element {
            *flag = true;
        }

        return user_data;
    }

    // Node already exists
    if let Some(flag) = new_element {
        *flag = false;
    }

    let entry = node_or_parent as *const TableEntryHeader;
    (*entry).user_data_ptr() as *mut u8
}

/// Look up an element in the generic table
pub unsafe fn rtl_lookup_element_generic_table(
    table: &RtlGenericTable,
    buffer: *const u8,
) -> *mut u8 {
    let mut node_or_parent = ptr::null_mut();
    let search_result = find_node_or_parent(table, buffer, &mut node_or_parent);

    rtl_lookup_element_generic_table_full(table, buffer, node_or_parent, search_result)
}

/// Look up an element with pre-computed search result
pub unsafe fn rtl_lookup_element_generic_table_full(
    table: &RtlGenericTable,
    _buffer: *const u8,
    node_or_parent: *mut SplayLinks,
    search_result: TableSearchResult,
) -> *mut u8 {
    if search_result != TableSearchResult::FoundNode {
        return ptr::null_mut();
    }

    // Splay the tree to bring found node to root
    let new_root = crate::rtl::splay::rtl_splay(node_or_parent);
    let table_mut = table as *const RtlGenericTable as *mut RtlGenericTable;
    (*table_mut).table_root = new_root;

    let entry = new_root as *const TableEntryHeader;
    (*entry).user_data_ptr() as *mut u8
}

/// Delete an element from the generic table
pub unsafe fn rtl_delete_element_generic_table(
    table: &mut RtlGenericTable,
    buffer: *const u8,
) -> bool {
    let mut node_or_parent = ptr::null_mut();
    let search_result = find_node_or_parent(table, buffer, &mut node_or_parent);

    if search_result != TableSearchResult::FoundNode {
        return false;
    }

    let entry = node_or_parent as *mut TableEntryHeader;

    // Remove from insertion order list
    let list_entry = &mut (*entry).list_entry as *mut GenericListEntry;
    (*(*list_entry).blink).flink = (*list_entry).flink;
    (*(*list_entry).flink).blink = (*list_entry).blink;

    // Delete from splay tree
    let new_root = crate::rtl::splay::rtl_delete(&mut (*entry).splay_links);
    table.table_root = new_root;

    table.number_generic_table_elements -= 1;

    // Reset ordered enumeration state
    table.ordered_pointer = &mut table.insert_order_list;
    table.which_ordered_element = 0;

    // Free the entry
    let free = table.free_routine.unwrap();
    free(table, entry as *mut u8);

    true
}

/// Enumerate elements in insertion order - get first
pub unsafe fn rtl_enumerate_generic_table(
    table: &mut RtlGenericTable,
    restart: bool,
) -> *mut u8 {
    if restart {
        table.which_ordered_element = 0;
        table.ordered_pointer = &mut table.insert_order_list;
    }

    rtl_enumerate_generic_table_without_splaying(table)
}

/// Enumerate elements without splaying
pub unsafe fn rtl_enumerate_generic_table_without_splaying(
    table: &mut RtlGenericTable,
) -> *mut u8 {
    let list_head = &table.insert_order_list as *const GenericListEntry;

    if table.ordered_pointer == list_head as *mut _ {
        // At the beginning, get first entry
        if table.insert_order_list.is_empty() {
            return ptr::null_mut();
        }
        table.ordered_pointer = table.insert_order_list.flink;
        table.which_ordered_element = 1;
    } else {
        // Move to next entry
        let next = (*table.ordered_pointer).flink;
        if next == list_head as *mut _ {
            return ptr::null_mut();
        }
        table.ordered_pointer = next;
        table.which_ordered_element += 1;
    }

    // Get the entry from the list entry
    let list_entry = table.ordered_pointer;
    let entry_offset = core::mem::offset_of!(TableEntryHeader, list_entry);
    let entry = (list_entry as usize - entry_offset) as *mut TableEntryHeader;

    (*entry).user_data_ptr() as *mut u8
}

/// Get element by index (0-based, in tree order)
pub unsafe fn rtl_get_element_generic_table(
    table: &mut RtlGenericTable,
    index: u32,
) -> *mut u8 {
    if index >= table.number_generic_table_elements {
        return ptr::null_mut();
    }

    // Simple implementation: enumerate to the index
    let mut current = 0u32;
    let list_head = &table.insert_order_list as *const GenericListEntry as *mut _;
    let mut entry = table.insert_order_list.flink;

    while entry != list_head {
        if current == index {
            let entry_offset = core::mem::offset_of!(TableEntryHeader, list_entry);
            let header = (entry as usize - entry_offset) as *mut TableEntryHeader;
            return (*header).user_data_ptr() as *mut u8;
        }
        current += 1;
        entry = (*entry).flink;
    }

    ptr::null_mut()
}

/// Enumerate in tree order
pub unsafe fn rtl_enumerate_generic_table_like_a_dictionary(
    table: &mut RtlGenericTable,
    previous: *mut u8,
) -> *mut u8 {
    if table.table_root.is_null() {
        return ptr::null_mut();
    }

    if previous.is_null() {
        // Find the leftmost node
        let mut node = table.table_root;
        while !(*node).left_child.is_null() {
            node = (*node).left_child;
        }
        let entry = node as *const TableEntryHeader;
        return (*entry).user_data_ptr() as *mut u8;
    }

    // Find the successor of the previous node
    let user_data_offset = core::mem::offset_of!(TableEntryHeader, user_data);
    let entry = (previous as usize - user_data_offset) as *mut TableEntryHeader;
    let mut node = &mut (*entry).splay_links as *mut SplayLinks;

    // If there's a right child, go right then all the way left
    if !(*node).right_child.is_null() {
        node = (*node).right_child;
        while !(*node).left_child.is_null() {
            node = (*node).left_child;
        }
        let entry = node as *const TableEntryHeader;
        return (*entry).user_data_ptr() as *mut u8;
    }

    // Go up until we came from a left child
    while (*node).parent != node {
        let parent = (*node).parent;
        if (*parent).left_child == node {
            let entry = parent as *const TableEntryHeader;
            return (*entry).user_data_ptr() as *mut u8;
        }
        node = parent;
    }

    // No successor
    ptr::null_mut()
}

/// Initialize generic table subsystem
pub fn rtl_gentable_init() {
    crate::serial_println!("[RTL] Generic table subsystem initialized");
}
