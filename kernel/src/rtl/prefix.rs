//! RTL Unicode Prefix Table
//!
//! Implements prefix table utilities for efficient string prefix matching:
//! - Unicode prefix tables for namespace lookups
//! - ANSI prefix tables for compatibility
//! - Splay tree based implementation for fast lookups
//!
//! Based on Windows Server 2003 base/ntos/rtl/prefix.c

use core::ptr;
use core::cmp::Ordering;
use crate::rtl::splay::{SplayLinks, rtl_splay, rtl_delete};

/// Node type codes for prefix data structures
pub const RTL_NTC_PREFIX_TABLE: i16 = 0x0200;
pub const RTL_NTC_ROOT: i16 = 0x0201;
pub const RTL_NTC_INTERNAL: i16 = 0x0202;

/// Node type codes for Unicode prefix data structures
pub const RTL_NTC_UNICODE_PREFIX_TABLE: i16 = 0x0800;
pub const RTL_NTC_UNICODE_ROOT: i16 = 0x0801;
pub const RTL_NTC_UNICODE_INTERNAL: i16 = 0x0802;
pub const RTL_NTC_UNICODE_CASE_MATCH: i16 = 0x0803;

/// Comparison result for prefix matching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixComparison {
    /// Prefix is less than name
    LessThan,
    /// Prefix is a proper prefix of name
    IsPrefix,
    /// Prefix equals name
    Equal,
    /// Prefix is greater than name
    GreaterThan,
}

/// ANSI string for prefix table
#[repr(C)]
#[derive(Debug)]
pub struct PfxAnsiString {
    /// Length in bytes
    pub length: u16,
    /// Maximum length in bytes
    pub maximum_length: u16,
    /// Buffer pointer
    pub buffer: *const u8,
}

impl PfxAnsiString {
    pub const fn empty() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            buffer: ptr::null(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        if self.buffer.is_null() || self.length == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(self.buffer, self.length as usize) }
        }
    }
}

/// Unicode string for prefix table
#[repr(C)]
#[derive(Debug)]
pub struct PfxUnicodeString {
    /// Length in bytes (not characters)
    pub length: u16,
    /// Maximum length in bytes
    pub maximum_length: u16,
    /// Buffer pointer (UTF-16)
    pub buffer: *const u16,
}

impl PfxUnicodeString {
    pub const fn empty() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            buffer: ptr::null(),
        }
    }

    pub fn char_len(&self) -> usize {
        (self.length / 2) as usize
    }

    pub fn as_slice(&self) -> &[u16] {
        if self.buffer.is_null() || self.length == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(self.buffer, self.char_len()) }
        }
    }
}

/// ANSI Prefix table entry
#[repr(C)]
pub struct PrefixTableEntry {
    /// Node type code
    pub node_type_code: i16,
    /// Name length (number of path components)
    pub name_length: i16,
    /// Pointer to next prefix tree (or NULL)
    pub next_prefix_tree: *mut PrefixTableEntry,
    /// Splay tree links
    pub links: SplayLinks,
    /// The prefix string
    pub prefix: *const PfxAnsiString,
}

impl PrefixTableEntry {
    pub const fn new() -> Self {
        Self {
            node_type_code: 0,
            name_length: 0,
            next_prefix_tree: ptr::null_mut(),
            links: SplayLinks::new(),
            prefix: ptr::null(),
        }
    }

    /// Initialize splay links
    pub fn init_splay_links(&mut self) {
        self.links.parent = &mut self.links;
        self.links.left_child = ptr::null_mut();
        self.links.right_child = ptr::null_mut();
    }
}

/// ANSI Prefix table
#[repr(C)]
pub struct PrefixTable {
    /// Node type code
    pub node_type_code: i16,
    /// Name length (always 0 for table header)
    pub name_length: i16,
    /// Pointer to first prefix tree
    pub next_prefix_tree: *mut PrefixTableEntry,
}

impl PrefixTable {
    pub const fn new() -> Self {
        Self {
            node_type_code: RTL_NTC_PREFIX_TABLE,
            name_length: 0,
            next_prefix_tree: ptr::null_mut(),
        }
    }
}

/// Unicode prefix table entry
#[repr(C)]
pub struct UnicodePrefixTableEntry {
    /// Node type code
    pub node_type_code: i16,
    /// Name length (number of path components)
    pub name_length: i16,
    /// Pointer to next prefix tree (or NULL for non-root nodes)
    pub next_prefix_tree: *mut UnicodePrefixTableEntry,
    /// Case match list (circular)
    pub case_match: *mut UnicodePrefixTableEntry,
    /// Splay tree links
    pub links: SplayLinks,
    /// The prefix string
    pub prefix: *const PfxUnicodeString,
}

impl UnicodePrefixTableEntry {
    pub const fn new() -> Self {
        Self {
            node_type_code: 0,
            name_length: 0,
            next_prefix_tree: ptr::null_mut(),
            case_match: ptr::null_mut(),
            links: SplayLinks::new(),
            prefix: ptr::null(),
        }
    }

    /// Initialize splay links
    pub fn init_splay_links(&mut self) {
        self.links.parent = &mut self.links;
        self.links.left_child = ptr::null_mut();
        self.links.right_child = ptr::null_mut();
    }
}

/// Unicode prefix table
#[repr(C)]
pub struct UnicodePrefixTable {
    /// Node type code
    pub node_type_code: i16,
    /// Name length (always 0 for table header)
    pub name_length: i16,
    /// Pointer to first prefix tree
    pub next_prefix_tree: *mut UnicodePrefixTableEntry,
    /// Last entry returned by RtlNextUnicodePrefix
    pub last_next_entry: *mut UnicodePrefixTableEntry,
}

impl UnicodePrefixTable {
    pub const fn new() -> Self {
        Self {
            node_type_code: RTL_NTC_UNICODE_PREFIX_TABLE,
            name_length: 0,
            next_prefix_tree: ptr::null_mut(),
            last_next_entry: ptr::null_mut(),
        }
    }
}

/// Compute name length (number of backslash-separated components)
fn compute_name_length(name: &[u8]) -> i16 {
    if name.is_empty() {
        return 1;
    }
    let mut count = 1i16;
    for i in 0..name.len().saturating_sub(1) {
        if name[i] == b'\\' {
            count += 1;
        }
    }
    count
}

/// Compute Unicode name length (number of backslash-separated components)
fn compute_unicode_name_length(name: &[u16]) -> i16 {
    if name.is_empty() {
        return 1;
    }
    let mut count = 1i16;
    for i in 0..name.len().saturating_sub(1) {
        if name[i] == b'\\' as u16 {
            count += 1;
        }
    }
    count
}

/// Compare ANSI names case-sensitive
fn compare_names_case_sensitive(prefix: &[u8], name: &[u8]) -> PrefixComparison {
    let prefix_len = prefix.len();
    let name_len = name.len();

    // Special case: prefix is just "\" and name starts with "\"
    if prefix_len == 1 && prefix[0] == b'\\' && name_len > 1 && name[0] == b'\\' {
        return PrefixComparison::IsPrefix;
    }

    let min_len = prefix_len.min(name_len);

    // Compare up to minimum length
    for i in 0..min_len {
        let p = if prefix[i] == b'\\' { 0u8 } else { prefix[i] };
        let n = if name[i] == b'\\' { 0u8 } else { name[i] };

        if p < n {
            return PrefixComparison::LessThan;
        } else if p > n {
            return PrefixComparison::GreaterThan;
        }
    }

    // They match up to minimum length
    match prefix_len.cmp(&name_len) {
        Ordering::Less => {
            // Prefix is shorter - check if it's a proper prefix
            if name[prefix_len] == b'\\' {
                PrefixComparison::IsPrefix
            } else {
                PrefixComparison::LessThan
            }
        }
        Ordering::Greater => PrefixComparison::GreaterThan,
        Ordering::Equal => PrefixComparison::Equal,
    }
}

/// Upcase a Unicode character (simplified ASCII only)
fn unicode_upcase(c: u16) -> u16 {
    if c >= b'a' as u16 && c <= b'z' as u16 {
        c - 32
    } else {
        c
    }
}

/// Compare Unicode strings with optional case sensitivity
fn compare_unicode_strings(
    prefix: &[u16],
    name: &[u16],
    case_insensitive_index: usize,
) -> PrefixComparison {
    let prefix_len = prefix.len();
    let name_len = name.len();

    // Special case: prefix is just "\" and name starts with "\"
    if prefix_len == 1 && prefix[0] == b'\\' as u16 && name_len > 1 && name[0] == b'\\' as u16 {
        return PrefixComparison::IsPrefix;
    }

    let min_len = prefix_len.min(name_len);
    let case_insensitive_start = case_insensitive_index.min(min_len);

    // Case-sensitive comparison first
    for i in 0..case_insensitive_start {
        let p = prefix[i];
        let n = name[i];
        if p != n {
            // Handle backslash specially
            if p == b'\\' as u16 {
                return PrefixComparison::LessThan;
            }
            if n == b'\\' as u16 {
                return PrefixComparison::GreaterThan;
            }
            if p < n {
                return PrefixComparison::LessThan;
            } else {
                return PrefixComparison::GreaterThan;
            }
        }
    }

    // Case-insensitive comparison for the rest
    for i in case_insensitive_start..min_len {
        let mut p = prefix[i];
        let mut n = name[i];

        if p != n {
            p = unicode_upcase(p);
            n = unicode_upcase(n);

            if p != n {
                // Handle backslash specially
                if prefix[i] == b'\\' as u16 {
                    return PrefixComparison::LessThan;
                }
                if name[i] == b'\\' as u16 {
                    return PrefixComparison::GreaterThan;
                }
                if p < n {
                    return PrefixComparison::LessThan;
                } else {
                    return PrefixComparison::GreaterThan;
                }
            }
        }
    }

    // They match up to minimum length
    match prefix_len.cmp(&name_len) {
        Ordering::Less => {
            // Prefix is shorter - check if it's a proper prefix
            if name[prefix_len] == b'\\' as u16 {
                PrefixComparison::IsPrefix
            } else {
                PrefixComparison::LessThan
            }
        }
        Ordering::Greater => PrefixComparison::GreaterThan,
        Ordering::Equal => PrefixComparison::Equal,
    }
}

// ============================================================================
// ANSI Prefix Table Functions
// ============================================================================

/// Initialize a prefix table
pub fn pfx_initialize(prefix_table: &mut PrefixTable) {
    prefix_table.node_type_code = RTL_NTC_PREFIX_TABLE;
    prefix_table.name_length = 0;
    // Point to self to indicate empty (circular list)
    prefix_table.next_prefix_tree = prefix_table as *mut PrefixTable as *mut PrefixTableEntry;
}

/// Insert a prefix into the table
/// Returns true if inserted, false if already exists
pub unsafe fn pfx_insert_prefix(
    prefix_table: &mut PrefixTable,
    prefix: &PfxAnsiString,
    entry: &mut PrefixTableEntry,
) -> bool {
    let prefix_name_length = compute_name_length(prefix.as_slice());

    // Setup the entry
    entry.name_length = prefix_name_length;
    entry.prefix = prefix;
    entry.init_splay_links();

    // Find the tree for this name length
    let mut previous: *mut PrefixTableEntry = prefix_table as *mut PrefixTable as *mut _;
    let mut current = (*previous).next_prefix_tree;

    while !current.is_null()
        && current != prefix_table as *mut PrefixTable as *mut PrefixTableEntry
        && (*current).name_length > prefix_name_length
    {
        previous = current;
        current = (*current).next_prefix_tree;
    }

    // If no tree for this length exists, create one
    if current.is_null()
        || current == prefix_table as *mut PrefixTable as *mut PrefixTableEntry
        || (*current).name_length != prefix_name_length
    {
        // Insert new tree between previous and current
        (*previous).next_prefix_tree = entry;
        entry.next_prefix_tree = current;
        entry.node_type_code = RTL_NTC_ROOT;
        return true;
    }

    // Tree exists, search for position
    let mut node = current;
    loop {
        let node_prefix = if (*node).prefix.is_null() {
            &[]
        } else {
            (*(*node).prefix).as_slice()
        };
        let comparison = compare_names_case_sensitive(node_prefix, prefix.as_slice());

        match comparison {
            PrefixComparison::Equal => {
                // Already exists
                return false;
            }
            PrefixComparison::GreaterThan => {
                // Go left
                if (*node).links.left_child.is_null() {
                    entry.node_type_code = RTL_NTC_INTERNAL;
                    entry.next_prefix_tree = ptr::null_mut();

                    // Insert as left child
                    (*node).links.left_child = &mut entry.links;
                    entry.links.parent = &mut (*node).links;
                    break;
                }
                node = ((*node).links.left_child as usize - offset_of_links()) as *mut _;
            }
            _ => {
                // Go right
                if (*node).links.right_child.is_null() {
                    entry.node_type_code = RTL_NTC_INTERNAL;
                    entry.next_prefix_tree = ptr::null_mut();

                    // Insert as right child
                    (*node).links.right_child = &mut entry.links;
                    entry.links.parent = &mut (*node).links;
                    break;
                }
                node = ((*node).links.right_child as usize - offset_of_links()) as *mut _;
            }
        }
    }

    // Splay the tree
    let next_tree = (*current).next_prefix_tree;
    (*current).node_type_code = RTL_NTC_INTERNAL;
    (*current).next_prefix_tree = ptr::null_mut();

    let new_root_links = rtl_splay(&mut (*node).links);
    let new_root = (new_root_links as usize - offset_of_links()) as *mut PrefixTableEntry;

    (*new_root).node_type_code = RTL_NTC_ROOT;
    (*previous).next_prefix_tree = new_root;
    (*new_root).next_prefix_tree = next_tree;

    true
}

/// Find a prefix in the table
pub unsafe fn pfx_find_prefix(
    prefix_table: &mut PrefixTable,
    full_name: &PfxAnsiString,
) -> *mut PrefixTableEntry {
    let name_length = compute_name_length(full_name.as_slice());

    // Find the first tree that could contain a prefix
    let mut previous: *mut PrefixTableEntry = prefix_table as *mut PrefixTable as *mut _;
    let mut current = (*previous).next_prefix_tree;

    while !current.is_null()
        && current != prefix_table as *mut PrefixTable as *mut PrefixTableEntry
        && (*current).name_length > name_length
    {
        previous = current;
        current = (*current).next_prefix_tree;
    }

    // Search all trees with name_length <= our name_length
    while !current.is_null()
        && current != prefix_table as *mut PrefixTable as *mut PrefixTableEntry
        && (*current).name_length > 0
    {
        let mut links: *mut SplayLinks = &mut (*current).links;

        while !links.is_null() {
            let node = (links as usize - offset_of_links()) as *mut PrefixTableEntry;
            let node_prefix = if (*node).prefix.is_null() {
                &[]
            } else {
                (*(*node).prefix).as_slice()
            };
            let comparison = compare_names_case_sensitive(node_prefix, full_name.as_slice());

            match comparison {
                PrefixComparison::GreaterThan => {
                    links = (*links).left_child;
                }
                PrefixComparison::LessThan => {
                    links = (*links).right_child;
                }
                PrefixComparison::IsPrefix | PrefixComparison::Equal => {
                    // Found it - splay if internal
                    if (*node).node_type_code == RTL_NTC_INTERNAL {
                        let next_tree = (*current).next_prefix_tree;
                        (*current).node_type_code = RTL_NTC_INTERNAL;
                        (*current).next_prefix_tree = ptr::null_mut();

                        let new_root_links = rtl_splay(&mut (*node).links);
                        let new_root =
                            (new_root_links as usize - offset_of_links()) as *mut PrefixTableEntry;

                        (*new_root).node_type_code = RTL_NTC_ROOT;
                        (*previous).next_prefix_tree = new_root;
                        (*new_root).next_prefix_tree = next_tree;
                    }
                    return node;
                }
            }
        }

        // Move to next tree
        previous = current;
        current = (*current).next_prefix_tree;
    }

    ptr::null_mut()
}

/// Remove a prefix from the table
pub unsafe fn pfx_remove_prefix(
    _prefix_table: &mut PrefixTable,
    entry: &mut PrefixTableEntry,
) {
    match entry.node_type_code {
        RTL_NTC_INTERNAL | RTL_NTC_ROOT => {
            // Find the root
            let mut links: *mut SplayLinks = &mut entry.links;
            while (*links).parent != links {
                links = (*links).parent;
            }
            let root = (links as usize - offset_of_links()) as *mut PrefixTableEntry;

            // Delete the node
            let new_root_links = rtl_delete(&mut entry.links);

            if new_root_links.is_null() {
                // Tree is now empty - find previous tree and unlink
                let mut prev = (*root).next_prefix_tree;
                while !prev.is_null() && (*prev).next_prefix_tree != root {
                    prev = (*prev).next_prefix_tree;
                }
                if !prev.is_null() {
                    (*prev).next_prefix_tree = (*root).next_prefix_tree;
                }
            } else if new_root_links != links {
                // Root changed
                let new_root = (new_root_links as usize - offset_of_links()) as *mut PrefixTableEntry;

                // Find previous tree
                let mut prev = (*root).next_prefix_tree;
                while !prev.is_null() && (*prev).next_prefix_tree != root {
                    prev = (*prev).next_prefix_tree;
                }

                if !prev.is_null() {
                    (*new_root).node_type_code = RTL_NTC_ROOT;
                    (*prev).next_prefix_tree = new_root;
                    (*new_root).next_prefix_tree = (*root).next_prefix_tree;
                    (*root).node_type_code = RTL_NTC_INTERNAL;
                    (*root).next_prefix_tree = ptr::null_mut();
                }
            }
        }
        _ => {}
    }
}

// ============================================================================
// Unicode Prefix Table Functions
// ============================================================================

/// Initialize a Unicode prefix table
pub fn rtl_initialize_unicode_prefix(prefix_table: &mut UnicodePrefixTable) {
    prefix_table.node_type_code = RTL_NTC_UNICODE_PREFIX_TABLE;
    prefix_table.name_length = 0;
    prefix_table.next_prefix_tree =
        prefix_table as *mut UnicodePrefixTable as *mut UnicodePrefixTableEntry;
    prefix_table.last_next_entry = ptr::null_mut();
}

/// Insert a Unicode prefix into the table
/// Returns true if inserted, false if already exists
pub unsafe fn rtl_insert_unicode_prefix(
    prefix_table: &mut UnicodePrefixTable,
    prefix: &PfxUnicodeString,
    entry: &mut UnicodePrefixTableEntry,
) -> bool {
    let prefix_name_length = compute_unicode_name_length(prefix.as_slice());

    // Setup the entry
    entry.name_length = prefix_name_length;
    entry.prefix = prefix;
    entry.init_splay_links();

    // Find the tree for this name length
    let mut previous: *mut UnicodePrefixTableEntry =
        prefix_table as *mut UnicodePrefixTable as *mut _;
    let mut current = (*previous).next_prefix_tree;

    while !current.is_null()
        && current != prefix_table as *mut UnicodePrefixTable as *mut UnicodePrefixTableEntry
        && (*current).name_length > prefix_name_length
    {
        previous = current;
        current = (*current).next_prefix_tree;
    }

    // If no tree for this length exists, create one
    if current.is_null()
        || current == prefix_table as *mut UnicodePrefixTable as *mut UnicodePrefixTableEntry
        || (*current).name_length != prefix_name_length
    {
        // Insert new tree between previous and current
        (*previous).next_prefix_tree = entry;
        entry.next_prefix_tree = current;
        entry.node_type_code = RTL_NTC_UNICODE_ROOT;
        entry.case_match = entry; // Points to self
        return true;
    }

    // Tree exists, search for position
    let mut node = current;
    loop {
        let node_prefix = if (*node).prefix.is_null() {
            &[]
        } else {
            (*(*node).prefix).as_slice()
        };
        let comparison = compare_unicode_strings(node_prefix, prefix.as_slice(), 0);

        match comparison {
            PrefixComparison::Equal => {
                // Case-blind match - check for case-sensitive duplicates
                let mut next = node;
                loop {
                    let next_prefix = if (*next).prefix.is_null() {
                        &[]
                    } else {
                        (*(*next).prefix).as_slice()
                    };
                    if compare_unicode_strings(next_prefix, prefix.as_slice(), usize::MAX)
                        == PrefixComparison::Equal
                    {
                        // Exact match exists
                        return false;
                    }
                    next = (*next).case_match;
                    if next == node {
                        break;
                    }
                }

                // Add as case match
                entry.node_type_code = RTL_NTC_UNICODE_CASE_MATCH;
                entry.next_prefix_tree = ptr::null_mut();
                entry.case_match = (*node).case_match;
                (*node).case_match = entry;
                break;
            }
            PrefixComparison::GreaterThan => {
                // Go left
                if (*node).links.left_child.is_null() {
                    entry.node_type_code = RTL_NTC_UNICODE_INTERNAL;
                    entry.next_prefix_tree = ptr::null_mut();
                    entry.case_match = entry;

                    // Insert as left child
                    (*node).links.left_child = &mut entry.links;
                    entry.links.parent = &mut (*node).links;
                    break;
                }
                node =
                    ((*node).links.left_child as usize - offset_of_unicode_links()) as *mut _;
            }
            _ => {
                // Go right
                if (*node).links.right_child.is_null() {
                    entry.node_type_code = RTL_NTC_UNICODE_INTERNAL;
                    entry.next_prefix_tree = ptr::null_mut();
                    entry.case_match = entry;

                    // Insert as right child
                    (*node).links.right_child = &mut entry.links;
                    entry.links.parent = &mut (*node).links;
                    break;
                }
                node =
                    ((*node).links.right_child as usize - offset_of_unicode_links()) as *mut _;
            }
        }
    }

    // Splay the tree (only if not a case match node)
    if entry.node_type_code != RTL_NTC_UNICODE_CASE_MATCH {
        let next_tree = (*current).next_prefix_tree;
        (*current).node_type_code = RTL_NTC_UNICODE_INTERNAL;
        (*current).next_prefix_tree = ptr::null_mut();

        let new_root_links = rtl_splay(&mut (*node).links);
        let new_root =
            (new_root_links as usize - offset_of_unicode_links()) as *mut UnicodePrefixTableEntry;

        (*new_root).node_type_code = RTL_NTC_UNICODE_ROOT;
        (*previous).next_prefix_tree = new_root;
        (*new_root).next_prefix_tree = next_tree;
    }

    true
}

/// Find a Unicode prefix in the table
pub unsafe fn rtl_find_unicode_prefix(
    prefix_table: &mut UnicodePrefixTable,
    full_name: &PfxUnicodeString,
    case_insensitive_index: usize,
) -> *mut UnicodePrefixTableEntry {
    let name_length = compute_unicode_name_length(full_name.as_slice());

    // Find the first tree that could contain a prefix
    let mut previous: *mut UnicodePrefixTableEntry =
        prefix_table as *mut UnicodePrefixTable as *mut _;
    let mut current = (*previous).next_prefix_tree;

    while !current.is_null()
        && current != prefix_table as *mut UnicodePrefixTable as *mut UnicodePrefixTableEntry
        && (*current).name_length > name_length
    {
        previous = current;
        current = (*current).next_prefix_tree;
    }

    // Search all trees with name_length <= our name_length
    while !current.is_null()
        && current != prefix_table as *mut UnicodePrefixTable as *mut UnicodePrefixTableEntry
        && (*current).name_length > 0
    {
        let mut links: *mut SplayLinks = &mut (*current).links;

        while !links.is_null() {
            let node =
                (links as usize - offset_of_unicode_links()) as *mut UnicodePrefixTableEntry;
            let node_prefix = if (*node).prefix.is_null() {
                &[]
            } else {
                (*(*node).prefix).as_slice()
            };
            let comparison = compare_unicode_strings(node_prefix, full_name.as_slice(), 0);

            match comparison {
                PrefixComparison::GreaterThan => {
                    links = (*links).left_child;
                }
                PrefixComparison::LessThan => {
                    links = (*links).right_child;
                }
                PrefixComparison::IsPrefix | PrefixComparison::Equal => {
                    // Case-insensitive match
                    if case_insensitive_index == 0 {
                        // Return first match
                        if (*node).node_type_code == RTL_NTC_UNICODE_INTERNAL {
                            // Splay
                            let next_tree = (*current).next_prefix_tree;
                            (*current).node_type_code = RTL_NTC_UNICODE_INTERNAL;
                            (*current).next_prefix_tree = ptr::null_mut();

                            let new_root_links = rtl_splay(&mut (*node).links);
                            let new_root = (new_root_links as usize - offset_of_unicode_links())
                                as *mut UnicodePrefixTableEntry;

                            (*new_root).node_type_code = RTL_NTC_UNICODE_ROOT;
                            (*previous).next_prefix_tree = new_root;
                            (*new_root).next_prefix_tree = next_tree;
                        }
                        return node;
                    }

                    // Search case match list for exact match
                    let mut next = node;
                    loop {
                        let next_prefix = if (*next).prefix.is_null() {
                            &[]
                        } else {
                            (*(*next).prefix).as_slice()
                        };
                        let comp = compare_unicode_strings(
                            next_prefix,
                            full_name.as_slice(),
                            case_insensitive_index,
                        );
                        if comp == PrefixComparison::Equal || comp == PrefixComparison::IsPrefix {
                            return next;
                        }
                        next = (*next).case_match;
                        if next == node {
                            break;
                        }
                    }

                    // No exact match in case list, continue search
                    break;
                }
            }
        }

        // Move to next tree
        previous = current;
        current = (*current).next_prefix_tree;
    }

    ptr::null_mut()
}

/// Remove a Unicode prefix from the table
pub unsafe fn rtl_remove_unicode_prefix(
    prefix_table: &mut UnicodePrefixTable,
    entry: &mut UnicodePrefixTableEntry,
) {
    // Invalidate next entry cache
    prefix_table.last_next_entry = ptr::null_mut();

    match entry.node_type_code {
        RTL_NTC_UNICODE_CASE_MATCH => {
            // Just remove from case match list
            let mut prev = (*entry).case_match;
            while (*prev).case_match != entry {
                prev = (*prev).case_match;
            }
            (*prev).case_match = (*entry).case_match;
        }
        RTL_NTC_UNICODE_INTERNAL | RTL_NTC_UNICODE_ROOT => {
            // Check if there are case matches to promote
            let entry_ptr = entry as *mut UnicodePrefixTableEntry;
            if (*entry).case_match != entry_ptr {
                // Promote a case match
                let mut prev = (*entry).case_match;
                while (*prev).case_match != entry_ptr {
                    prev = (*prev).case_match;
                }
                (*prev).case_match = (*entry).case_match;

                // Copy tree info to promoted node
                (*prev).node_type_code = (*entry).node_type_code;
                (*prev).next_prefix_tree = (*entry).next_prefix_tree;
                // Copy links field by field
                (*prev).links.parent = (*entry).links.parent;
                (*prev).links.left_child = (*entry).links.left_child;
                (*prev).links.right_child = (*entry).links.right_child;

                // Fix parent pointer
                let entry_links_ptr = &mut (*entry).links as *mut SplayLinks;
                if (*entry).links.parent == entry_links_ptr {
                    (*prev).links.parent = &mut (*prev).links;

                    // Find previous tree and update
                    let mut prev_tree = (*entry).next_prefix_tree;
                    while !prev_tree.is_null() && (*prev_tree).next_prefix_tree != entry_ptr {
                        prev_tree = (*prev_tree).next_prefix_tree;
                    }
                    if !prev_tree.is_null() {
                        (*prev_tree).next_prefix_tree = prev;
                    }
                } else if (*(*entry).links.parent).left_child == entry_links_ptr {
                    (*(*entry).links.parent).left_child = &mut (*prev).links;
                } else {
                    (*(*entry).links.parent).right_child = &mut (*prev).links;
                }

                // Fix children's parent pointers
                if !(*prev).links.left_child.is_null() {
                    (*(*prev).links.left_child).parent = &mut (*prev).links;
                }
                if !(*prev).links.right_child.is_null() {
                    (*(*prev).links.right_child).parent = &mut (*prev).links;
                }
            } else {
                // No case matches - delete from tree
                // Find the root
                let mut links: *mut SplayLinks = &mut entry.links;
                while (*links).parent != links {
                    links = (*links).parent;
                }
                let root =
                    (links as usize - offset_of_unicode_links()) as *mut UnicodePrefixTableEntry;

                // Delete the node
                let new_root_links = rtl_delete(&mut entry.links);

                if new_root_links.is_null() {
                    // Tree is now empty - find previous tree and unlink
                    let mut prev = (*root).next_prefix_tree;
                    while !prev.is_null() && (*prev).next_prefix_tree != root {
                        prev = (*prev).next_prefix_tree;
                    }
                    if !prev.is_null() {
                        (*prev).next_prefix_tree = (*root).next_prefix_tree;
                    }
                } else if new_root_links != links {
                    // Root changed
                    let new_root = (new_root_links as usize - offset_of_unicode_links())
                        as *mut UnicodePrefixTableEntry;

                    // Find previous tree
                    let mut prev = (*root).next_prefix_tree;
                    while !prev.is_null() && (*prev).next_prefix_tree != root {
                        prev = (*prev).next_prefix_tree;
                    }

                    if !prev.is_null() {
                        (*new_root).node_type_code = RTL_NTC_UNICODE_ROOT;
                        (*prev).next_prefix_tree = new_root;
                        (*new_root).next_prefix_tree = (*root).next_prefix_tree;
                        (*root).node_type_code = RTL_NTC_UNICODE_INTERNAL;
                        (*root).next_prefix_tree = ptr::null_mut();
                    }
                }
            }
        }
        _ => {}
    }
}

/// Get the next prefix in iteration
pub unsafe fn rtl_next_unicode_prefix(
    prefix_table: &mut UnicodePrefixTable,
    restart: bool,
) -> *mut UnicodePrefixTableEntry {
    if restart || prefix_table.last_next_entry.is_null() {
        // Start from beginning
        let node = prefix_table.next_prefix_tree;
        if node == prefix_table as *mut UnicodePrefixTable as *mut UnicodePrefixTableEntry {
            return ptr::null_mut();
        }

        // Find leftmost in first tree
        let mut links: *mut SplayLinks = &mut (*node).links;
        while !(*links).left_child.is_null() {
            links = (*links).left_child;
        }

        let result =
            (links as usize - offset_of_unicode_links()) as *mut UnicodePrefixTableEntry;
        prefix_table.last_next_entry = result;
        return result;
    }

    let last = prefix_table.last_next_entry;

    // Check for case match continuation
    if (*(*last).case_match).node_type_code == RTL_NTC_UNICODE_CASE_MATCH {
        prefix_table.last_next_entry = (*last).case_match;
        return prefix_table.last_next_entry;
    }

    // Find successor in tree
    let node = (*last).case_match;
    let links = &mut (*node).links;

    // Try right child's leftmost
    if !(*links).right_child.is_null() {
        let mut next = (*links).right_child;
        while !(*next).left_child.is_null() {
            next = (*next).left_child;
        }
        let result =
            (next as usize - offset_of_unicode_links()) as *mut UnicodePrefixTableEntry;
        prefix_table.last_next_entry = result;
        return result;
    }

    // Go up until we came from a left child
    let mut current = links as *mut SplayLinks;
    while (*current).parent != current {
        let parent = (*current).parent;
        if (*parent).left_child == current {
            let result =
                (parent as usize - offset_of_unicode_links()) as *mut UnicodePrefixTableEntry;
            prefix_table.last_next_entry = result;
            return result;
        }
        current = parent;
    }

    // Reached root - go to next tree
    let root = (current as usize - offset_of_unicode_links()) as *mut UnicodePrefixTableEntry;
    let next_tree = (*root).next_prefix_tree;

    if next_tree.is_null()
        || (*next_tree).name_length <= 0
        || next_tree == prefix_table as *mut UnicodePrefixTable as *mut UnicodePrefixTableEntry
    {
        prefix_table.last_next_entry = ptr::null_mut();
        return ptr::null_mut();
    }

    // Find leftmost in next tree
    let mut next_links: *mut SplayLinks = &mut (*next_tree).links;
    while !(*next_links).left_child.is_null() {
        next_links = (*next_links).left_child;
    }

    let result =
        (next_links as usize - offset_of_unicode_links()) as *mut UnicodePrefixTableEntry;
    prefix_table.last_next_entry = result;
    result
}

// Helper functions for offset calculations
fn offset_of_links() -> usize {
    let entry = PrefixTableEntry::new();
    let base = &entry as *const _ as usize;
    let links = &entry.links as *const _ as usize;
    links - base
}

fn offset_of_unicode_links() -> usize {
    let entry = UnicodePrefixTableEntry::new();
    let base = &entry as *const _ as usize;
    let links = &entry.links as *const _ as usize;
    links - base
}

/// Initialize prefix table subsystem
pub fn rtl_prefix_init() {
    crate::serial_println!("[RTL] Unicode prefix table subsystem initialized");
}
