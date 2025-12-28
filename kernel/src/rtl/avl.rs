//! AVL Tree Implementation
//!
//! Self-balancing binary search trees used throughout NT:
//! - VAD (Virtual Address Descriptor) trees in address spaces
//! - Object directory lookup
//! - Registry key indexing
//!
//! # Properties
//!
//! - O(log n) insert, delete, lookup
//! - Heights of subtrees differ by at most 1
//! - Automatic rebalancing on insert/delete
//!
//! # NT-Style Design
//!
//! NT's RTL_AVL_TABLE uses intrusive nodes where the AVL links
//! are embedded in the data structure itself.

use core::ptr;
use core::cmp::Ordering;

/// Balance factor for AVL nodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
pub enum AvlBalance {
    /// Left subtree is taller
    LeftHeavy = -1,
    /// Subtrees are equal height
    Balanced = 0,
    /// Right subtree is taller
    RightHeavy = 1,
}

/// AVL tree node links
///
/// This is embedded in data structures that participate in AVL trees.
/// Equivalent to NT's RTL_BALANCED_LINKS
#[repr(C)]
pub struct AvlLinks {
    /// Parent node (null for root)
    pub parent: *mut AvlLinks,
    /// Left child (smaller keys)
    pub left: *mut AvlLinks,
    /// Right child (larger keys)
    pub right: *mut AvlLinks,
    /// Balance factor (-1, 0, +1)
    pub balance: i8,
    /// Reserved for alignment
    reserved: [u8; 3],
}

impl AvlLinks {
    /// Create new unlinked AVL links
    pub const fn new() -> Self {
        Self {
            parent: ptr::null_mut(),
            left: ptr::null_mut(),
            right: ptr::null_mut(),
            balance: 0,
            reserved: [0; 3],
        }
    }

    /// Initialize the links
    pub fn init(&mut self) {
        self.parent = ptr::null_mut();
        self.left = ptr::null_mut();
        self.right = ptr::null_mut();
        self.balance = 0;
    }

    /// Check if this node is the left child of its parent
    #[inline]
    pub fn is_left_child(&self) -> bool {
        if self.parent.is_null() {
            return false;
        }
        unsafe { core::ptr::eq((*self.parent).left, self) }
    }

    /// Check if this node is the right child of its parent
    #[inline]
    pub fn is_right_child(&self) -> bool {
        if self.parent.is_null() {
            return false;
        }
        unsafe { core::ptr::eq((*self.parent).right, self) }
    }

    /// Get the minimum node in subtree rooted at this node
    pub fn minimum(&self) -> *mut AvlLinks {
        let mut current = self as *const _ as *mut AvlLinks;
        unsafe {
            while !(*current).left.is_null() {
                current = (*current).left;
            }
        }
        current
    }

    /// Get the maximum node in subtree rooted at this node
    pub fn maximum(&self) -> *mut AvlLinks {
        let mut current = self as *const _ as *mut AvlLinks;
        unsafe {
            while !(*current).right.is_null() {
                current = (*current).right;
            }
        }
        current
    }

    /// Get the in-order successor
    pub fn successor(&self) -> *mut AvlLinks {
        // If right child exists, successor is minimum of right subtree
        if !self.right.is_null() {
            return unsafe { (*self.right).minimum() };
        }

        // Otherwise, go up until we find a node that is a left child
        let mut current = self as *const _ as *mut AvlLinks;
        let mut parent = self.parent;

        unsafe {
            while !parent.is_null() && current == (*parent).right {
                current = parent;
                parent = (*parent).parent;
            }
        }

        parent
    }

    /// Get the in-order predecessor
    pub fn predecessor(&self) -> *mut AvlLinks {
        // If left child exists, predecessor is maximum of left subtree
        if !self.left.is_null() {
            return unsafe { (*self.left).maximum() };
        }

        // Otherwise, go up until we find a node that is a right child
        let mut current = self as *const _ as *mut AvlLinks;
        let mut parent = self.parent;

        unsafe {
            while !parent.is_null() && current == (*parent).left {
                current = parent;
                parent = (*parent).parent;
            }
        }

        parent
    }
}

impl Default for AvlLinks {
    fn default() -> Self {
        Self::new()
    }
}

/// Comparison function type for AVL operations
pub type AvlCompare<T> = fn(&T, &T) -> Ordering;

/// AVL Tree structure
///
/// Equivalent to NT's RTL_AVL_TABLE
#[repr(C)]
pub struct AvlTable<T> {
    /// Root node of the tree
    root: *mut AvlLinks,
    /// Number of elements in the tree
    count: usize,
    /// Comparison function
    compare: AvlCompare<T>,
    /// Offset of AvlLinks within T
    links_offset: usize,
}

impl<T> AvlTable<T> {
    /// Create a new empty AVL table
    ///
    /// # Arguments
    /// * `compare` - Comparison function for ordering elements
    /// * `links_offset` - Byte offset of AvlLinks field within T
    pub const fn new(compare: AvlCompare<T>, links_offset: usize) -> Self {
        Self {
            root: ptr::null_mut(),
            count: 0,
            compare,
            links_offset,
        }
    }

    /// Check if the tree is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.root.is_null()
    }

    /// Get the number of elements
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get a reference to the element containing the given links
    unsafe fn element_from_links(&self, links: *mut AvlLinks) -> *mut T {
        (links as *mut u8).sub(self.links_offset) as *mut T
    }

    /// Get the links from an element
    unsafe fn links_from_element(&self, element: *mut T) -> *mut AvlLinks {
        (element as *mut u8).add(self.links_offset) as *mut AvlLinks
    }

    /// Insert an element into the tree
    ///
    /// Returns true if inserted, false if a duplicate exists
    pub fn insert(&mut self, element: *mut T) -> bool {
        if element.is_null() {
            return false;
        }

        let new_links = unsafe { self.links_from_element(element) };
        unsafe { (*new_links).init(); }

        if self.root.is_null() {
            // Tree is empty - this becomes the root
            self.root = new_links;
            self.count = 1;
            return true;
        }

        // Find insertion point
        let mut current = self.root;
        let mut parent = ptr::null_mut();
        let mut is_left = false;

        unsafe {
            while !current.is_null() {
                parent = current;
                let current_element = self.element_from_links(current);

                match (self.compare)(&*element, &*current_element) {
                    Ordering::Less => {
                        current = (*current).left;
                        is_left = true;
                    }
                    Ordering::Greater => {
                        current = (*current).right;
                        is_left = false;
                    }
                    Ordering::Equal => {
                        // Duplicate - don't insert
                        return false;
                    }
                }
            }

            // Insert the new node
            (*new_links).parent = parent;
            if is_left {
                (*parent).left = new_links;
            } else {
                (*parent).right = new_links;
            }
        }

        self.count += 1;

        // Rebalance the tree
        self.rebalance_after_insert(new_links);

        true
    }

    /// Find an element in the tree
    ///
    /// Returns a pointer to the matching element, or null if not found
    pub fn find(&self, key: &T) -> *mut T {
        let mut current = self.root;

        unsafe {
            while !current.is_null() {
                let current_element = self.element_from_links(current);

                match (self.compare)(key, &*current_element) {
                    Ordering::Less => {
                        current = (*current).left;
                    }
                    Ordering::Greater => {
                        current = (*current).right;
                    }
                    Ordering::Equal => {
                        return current_element;
                    }
                }
            }
        }

        ptr::null_mut()
    }

    /// Remove an element from the tree
    ///
    /// Returns true if removed, false if not found
    pub fn remove(&mut self, element: *mut T) -> bool {
        if element.is_null() {
            return false;
        }

        let links = unsafe { self.links_from_element(element) };

        // Verify this element is actually in the tree
        if links == self.root {
            // It's the root - that's fine
        } else {
            unsafe {
                if (*links).parent.is_null() {
                    // Not in any tree
                    return false;
                }
            }
        }

        self.remove_node(links);
        self.count -= 1;
        true
    }

    /// Internal: remove a node from the tree
    fn remove_node(&mut self, node: *mut AvlLinks) {
        unsafe {
            let left = (*node).left;
            let right = (*node).right;
            let parent = (*node).parent;

            if left.is_null() && right.is_null() {
                // Leaf node - just remove
                self.replace_child(parent, node, ptr::null_mut());
                if !parent.is_null() {
                    self.rebalance_after_delete(parent);
                }
            } else if left.is_null() {
                // Only right child
                (*right).parent = parent;
                self.replace_child(parent, node, right);
                if !parent.is_null() {
                    self.rebalance_after_delete(parent);
                }
            } else if right.is_null() {
                // Only left child
                (*left).parent = parent;
                self.replace_child(parent, node, left);
                if !parent.is_null() {
                    self.rebalance_after_delete(parent);
                }
            } else {
                // Both children - find successor
                let successor = (*right).minimum();
                let successor_parent = (*successor).parent;

                if successor != right {
                    // Successor is not immediate right child
                    if !(*successor).right.is_null() {
                        (*(*successor).right).parent = successor_parent;
                    }
                    (*successor_parent).left = (*successor).right;

                    (*successor).right = right;
                    (*right).parent = successor;
                }

                (*successor).left = left;
                (*left).parent = successor;
                (*successor).parent = parent;
                (*successor).balance = (*node).balance;

                self.replace_child(parent, node, successor);

                // Rebalance from where we removed the successor
                let rebalance_point = if successor_parent == node {
                    successor
                } else {
                    successor_parent
                };
                self.rebalance_after_delete(rebalance_point);
            }

            // Clear the removed node's links
            (*node).init();
        }
    }

    /// Replace a child pointer in the parent
    fn replace_child(&mut self, parent: *mut AvlLinks, old: *mut AvlLinks, new: *mut AvlLinks) {
        if parent.is_null() {
            self.root = new;
        } else {
            unsafe {
                if (*parent).left == old {
                    (*parent).left = new;
                } else {
                    (*parent).right = new;
                }
            }
        }
    }

    /// Rebalance after insertion
    fn rebalance_after_insert(&mut self, mut node: *mut AvlLinks) {
        unsafe {
            while !(*node).parent.is_null() {
                let parent = (*node).parent;

                if node == (*parent).left {
                    // Inserted in left subtree
                    match (*parent).balance {
                        1 => {
                            // Was right-heavy, now balanced
                            (*parent).balance = 0;
                            return;
                        }
                        0 => {
                            // Was balanced, now left-heavy
                            (*parent).balance = -1;
                            node = parent;
                        }
                        -1 => {
                            // Was left-heavy, need to rotate
                            if (*node).balance == -1 {
                                self.rotate_right(parent);
                            } else {
                                self.rotate_left_right(parent);
                            }
                            return;
                        }
                        _ => unreachable!(),
                    }
                } else {
                    // Inserted in right subtree
                    match (*parent).balance {
                        -1 => {
                            // Was left-heavy, now balanced
                            (*parent).balance = 0;
                            return;
                        }
                        0 => {
                            // Was balanced, now right-heavy
                            (*parent).balance = 1;
                            node = parent;
                        }
                        1 => {
                            // Was right-heavy, need to rotate
                            if (*node).balance == 1 {
                                self.rotate_left(parent);
                            } else {
                                self.rotate_right_left(parent);
                            }
                            return;
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
    }

    /// Rebalance after deletion
    fn rebalance_after_delete(&mut self, mut node: *mut AvlLinks) {
        unsafe {
            loop {
                let parent = (*node).parent;
                let is_left = if parent.is_null() {
                    false
                } else {
                    (*parent).left == node
                };

                let balance = (*node).balance;

                if balance == -2 {
                    // Left subtree too heavy
                    let left = (*node).left;
                    if (*left).balance <= 0 {
                        self.rotate_right(node);
                        if (*left).balance == 0 {
                            return;
                        }
                    } else {
                        self.rotate_left_right(node);
                    }
                } else if balance == 2 {
                    // Right subtree too heavy
                    let right = (*node).right;
                    if (*right).balance >= 0 {
                        self.rotate_left(node);
                        if (*right).balance == 0 {
                            return;
                        }
                    } else {
                        self.rotate_right_left(node);
                    }
                }

                if parent.is_null() {
                    return;
                }

                // Update parent's balance and continue up
                if is_left {
                    (*parent).balance += 1;
                    if (*parent).balance == 1 {
                        return;
                    }
                } else {
                    (*parent).balance -= 1;
                    if (*parent).balance == -1 {
                        return;
                    }
                }

                node = parent;
            }
        }
    }

    /// Single left rotation
    fn rotate_left(&mut self, node: *mut AvlLinks) {
        unsafe {
            let right = (*node).right;
            let parent = (*node).parent;

            (*node).right = (*right).left;
            if !(*right).left.is_null() {
                (*(*right).left).parent = node;
            }

            (*right).left = node;
            (*node).parent = right;
            (*right).parent = parent;

            self.replace_child(parent, node, right);

            // Update balance factors
            if (*right).balance == 0 {
                (*node).balance = 1;
                (*right).balance = -1;
            } else {
                (*node).balance = 0;
                (*right).balance = 0;
            }
        }
    }

    /// Single right rotation
    fn rotate_right(&mut self, node: *mut AvlLinks) {
        unsafe {
            let left = (*node).left;
            let parent = (*node).parent;

            (*node).left = (*left).right;
            if !(*left).right.is_null() {
                (*(*left).right).parent = node;
            }

            (*left).right = node;
            (*node).parent = left;
            (*left).parent = parent;

            self.replace_child(parent, node, left);

            // Update balance factors
            if (*left).balance == 0 {
                (*node).balance = -1;
                (*left).balance = 1;
            } else {
                (*node).balance = 0;
                (*left).balance = 0;
            }
        }
    }

    /// Left-right double rotation
    fn rotate_left_right(&mut self, node: *mut AvlLinks) {
        unsafe {
            let left = (*node).left;
            let left_right = (*left).right;
            let parent = (*node).parent;

            // Rotate left at left child
            (*left).right = (*left_right).left;
            if !(*left_right).left.is_null() {
                (*(*left_right).left).parent = left;
            }
            (*left_right).left = left;
            (*left).parent = left_right;

            // Rotate right at node
            (*node).left = (*left_right).right;
            if !(*left_right).right.is_null() {
                (*(*left_right).right).parent = node;
            }
            (*left_right).right = node;
            (*node).parent = left_right;

            (*left_right).parent = parent;
            self.replace_child(parent, node, left_right);

            // Update balance factors
            match (*left_right).balance {
                -1 => {
                    (*node).balance = 1;
                    (*left).balance = 0;
                }
                0 => {
                    (*node).balance = 0;
                    (*left).balance = 0;
                }
                1 => {
                    (*node).balance = 0;
                    (*left).balance = -1;
                }
                _ => {}
            }
            (*left_right).balance = 0;
        }
    }

    /// Right-left double rotation
    fn rotate_right_left(&mut self, node: *mut AvlLinks) {
        unsafe {
            let right = (*node).right;
            let right_left = (*right).left;
            let parent = (*node).parent;

            // Rotate right at right child
            (*right).left = (*right_left).right;
            if !(*right_left).right.is_null() {
                (*(*right_left).right).parent = right;
            }
            (*right_left).right = right;
            (*right).parent = right_left;

            // Rotate left at node
            (*node).right = (*right_left).left;
            if !(*right_left).left.is_null() {
                (*(*right_left).left).parent = node;
            }
            (*right_left).left = node;
            (*node).parent = right_left;

            (*right_left).parent = parent;
            self.replace_child(parent, node, right_left);

            // Update balance factors
            match (*right_left).balance {
                1 => {
                    (*node).balance = -1;
                    (*right).balance = 0;
                }
                0 => {
                    (*node).balance = 0;
                    (*right).balance = 0;
                }
                -1 => {
                    (*node).balance = 0;
                    (*right).balance = 1;
                }
                _ => {}
            }
            (*right_left).balance = 0;
        }
    }

    /// Get the first (minimum) element
    pub fn first(&self) -> *mut T {
        if self.root.is_null() {
            return ptr::null_mut();
        }

        unsafe {
            let min = (*self.root).minimum();
            self.element_from_links(min)
        }
    }

    /// Get the last (maximum) element
    pub fn last(&self) -> *mut T {
        if self.root.is_null() {
            return ptr::null_mut();
        }

        unsafe {
            let max = (*self.root).maximum();
            self.element_from_links(max)
        }
    }

    /// Get the next element after the given one
    pub fn next(&self, element: *mut T) -> *mut T {
        if element.is_null() {
            return ptr::null_mut();
        }

        unsafe {
            let links = self.links_from_element(element);
            let successor = (*links).successor();
            if successor.is_null() {
                ptr::null_mut()
            } else {
                self.element_from_links(successor)
            }
        }
    }

    /// Get the previous element before the given one
    pub fn prev(&self, element: *mut T) -> *mut T {
        if element.is_null() {
            return ptr::null_mut();
        }

        unsafe {
            let links = self.links_from_element(element);
            let predecessor = (*links).predecessor();
            if predecessor.is_null() {
                ptr::null_mut()
            } else {
                self.element_from_links(predecessor)
            }
        }
    }
}

// NT API compatibility type aliases
#[allow(non_camel_case_types)]
pub type RTL_BALANCED_LINKS = AvlLinks;
#[allow(non_camel_case_types)]
pub type PRTL_BALANCED_LINKS = *mut AvlLinks;

/// Macro to get the offset of a field within a struct
#[macro_export]
macro_rules! avl_offset_of {
    ($type:ty, $field:ident) => {{
        let uninit = core::mem::MaybeUninit::<$type>::uninit();
        let base_ptr = uninit.as_ptr();
        let field_ptr = unsafe { core::ptr::addr_of!((*base_ptr).$field) };
        (field_ptr as usize) - (base_ptr as usize)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestNode {
        key: i32,
        links: AvlLinks,
    }

    impl TestNode {
        fn new(key: i32) -> Self {
            Self {
                key,
                links: AvlLinks::new(),
            }
        }
    }

    fn compare_test_nodes(a: &TestNode, b: &TestNode) -> Ordering {
        a.key.cmp(&b.key)
    }

    #[test]
    fn test_basic_insert_find() {
        let offset = avl_offset_of!(TestNode, links);
        let mut tree: AvlTable<TestNode> = AvlTable::new(compare_test_nodes, offset);

        let mut node1 = TestNode::new(10);
        let mut node2 = TestNode::new(5);
        let mut node3 = TestNode::new(15);

        assert!(tree.insert(&mut node1));
        assert!(tree.insert(&mut node2));
        assert!(tree.insert(&mut node3));

        assert_eq!(tree.count(), 3);

        let found = tree.find(&TestNode::new(10));
        assert!(!found.is_null());
        unsafe { assert_eq!((*found).key, 10); }

        let not_found = tree.find(&TestNode::new(100));
        assert!(not_found.is_null());
    }

    #[test]
    fn test_iteration() {
        let offset = avl_offset_of!(TestNode, links);
        let mut tree: AvlTable<TestNode> = AvlTable::new(compare_test_nodes, offset);

        let mut nodes = [
            TestNode::new(5),
            TestNode::new(3),
            TestNode::new(7),
            TestNode::new(1),
            TestNode::new(9),
        ];

        for node in nodes.iter_mut() {
            tree.insert(node);
        }

        // Check in-order traversal
        let mut current = tree.first();
        let expected = [1, 3, 5, 7, 9];
        for &exp in expected.iter() {
            assert!(!current.is_null());
            unsafe { assert_eq!((*current).key, exp); }
            current = tree.next(current);
        }
        assert!(current.is_null());
    }
}
