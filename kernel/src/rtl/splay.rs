//! RTL Splay Trees
//!
//! Self-adjusting binary search trees that move frequently accessed
//! nodes to the root. Provides amortized O(log n) operations.
//!
//! Features:
//! - Splay operation to bring nodes to root
//! - Insert, delete, and lookup operations
//! - In-order traversal (successor/predecessor)
//! - No explicit balancing needed
//!
//! Based on Windows Server 2003 base/ntos/rtl/splay.c

use core::ptr;

/// Splay tree node links
#[repr(C)]
#[derive(Debug)]
pub struct SplayLinks {
    /// Parent node (self if root)
    pub parent: *mut SplayLinks,
    /// Left child
    pub left_child: *mut SplayLinks,
    /// Right child
    pub right_child: *mut SplayLinks,
}

impl SplayLinks {
    /// Create uninitialized splay links
    pub const fn new() -> Self {
        Self {
            parent: ptr::null_mut(),
            left_child: ptr::null_mut(),
            right_child: ptr::null_mut(),
        }
    }

    /// Initialize as a root node (parent points to self)
    pub fn init_root(&mut self) {
        self.parent = self as *mut SplayLinks;
        self.left_child = ptr::null_mut();
        self.right_child = ptr::null_mut();
    }

    /// Check if this is the root (parent points to self)
    #[inline]
    pub fn is_root(&self) -> bool {
        self.parent == self as *const SplayLinks as *mut SplayLinks
    }

    /// Check if this is a left child
    #[inline]
    pub fn is_left_child(&self) -> bool {
        unsafe {
            !self.parent.is_null() && (*self.parent).left_child == self as *const SplayLinks as *mut SplayLinks
        }
    }

    /// Check if this is a right child
    #[inline]
    pub fn is_right_child(&self) -> bool {
        unsafe {
            !self.parent.is_null() && (*self.parent).right_child == self as *const SplayLinks as *mut SplayLinks
        }
    }

    /// Get the parent node
    #[inline]
    pub fn parent(&self) -> *mut SplayLinks {
        self.parent
    }

    /// Get the left child
    #[inline]
    pub fn left_child(&self) -> *mut SplayLinks {
        self.left_child
    }

    /// Get the right child
    #[inline]
    pub fn right_child(&self) -> *mut SplayLinks {
        self.right_child
    }

    /// Insert as left child
    pub fn insert_as_left_child(&mut self, child: *mut SplayLinks) {
        self.left_child = child;
        if !child.is_null() {
            unsafe {
                (*child).parent = self as *mut SplayLinks;
            }
        }
    }

    /// Insert as right child
    pub fn insert_as_right_child(&mut self, child: *mut SplayLinks) {
        self.right_child = child;
        if !child.is_null() {
            unsafe {
                (*child).parent = self as *mut SplayLinks;
            }
        }
    }
}

impl Default for SplayLinks {
    fn default() -> Self {
        Self::new()
    }
}

/// Get pointer to parent's child pointer that points to this node
#[inline]
unsafe fn parents_child_pointer_address(links: *mut SplayLinks) -> *mut *mut SplayLinks {
    if (*links).is_left_child() {
        &mut (*(*links).parent).left_child
    } else {
        &mut (*(*links).parent).right_child
    }
}

/// Splay a node to the root of the tree
///
/// Returns the new root of the tree (which will be the input node)
pub fn rtl_splay(links: *mut SplayLinks) -> *mut SplayLinks {
    if links.is_null() {
        return links;
    }

    let mut l = links;

    unsafe {
        // Keep rotating until L is the root
        while !(*l).is_root() {
            let p = (*l).parent;
            let g = (*p).parent;

            if (*l).is_left_child() {
                if (*p).is_root() {
                    // Zig rotation (L is left child of root P)
                    //       P           L
                    //      / \         / \
                    //     L   c  ==>  a   P
                    //    / \             / \
                    //   a   b           b   c

                    // Connect P & b
                    (*p).left_child = (*l).right_child;
                    if !(*p).left_child.is_null() {
                        (*(*p).left_child).parent = p;
                    }

                    // Connect L & P
                    (*l).right_child = p;
                    (*p).parent = l;

                    // Make L the root
                    (*l).parent = l;
                } else if (*p).is_left_child() {
                    // Zig-zig rotation (L and P are both left children)
                    //         G           L
                    //        / \         / \
                    //       P   d  ==>  a   P
                    //      / \             / \
                    //     L   c           b   G
                    //    / \                 / \
                    //   a   b               c   d

                    // Connect P & b
                    (*p).left_child = (*l).right_child;
                    if !(*p).left_child.is_null() {
                        (*(*p).left_child).parent = p;
                    }

                    // Connect G & c
                    (*g).left_child = (*p).right_child;
                    if !(*g).left_child.is_null() {
                        (*(*g).left_child).parent = g;
                    }

                    // Connect L & Great GrandParent
                    if (*g).is_root() {
                        (*l).parent = l;
                    } else {
                        (*l).parent = (*g).parent;
                        *parents_child_pointer_address(g) = l;
                    }

                    // Connect L & P
                    (*l).right_child = p;
                    (*p).parent = l;

                    // Connect P & G
                    (*p).right_child = g;
                    (*g).parent = p;
                } else {
                    // Zig-zag rotation (L is left child, P is right child)
                    //       G                L
                    //      / \             /   \
                    //     a   P           G     P
                    //        / \         / \   / \
                    //       L   d  ==>  a   b c   d
                    //      / \
                    //     b   c

                    // Connect G & b
                    (*g).right_child = (*l).left_child;
                    if !(*g).right_child.is_null() {
                        (*(*g).right_child).parent = g;
                    }

                    // Connect P & c
                    (*p).left_child = (*l).right_child;
                    if !(*p).left_child.is_null() {
                        (*(*p).left_child).parent = p;
                    }

                    // Connect L & Great GrandParent
                    if (*g).is_root() {
                        (*l).parent = l;
                    } else {
                        (*l).parent = (*g).parent;
                        *parents_child_pointer_address(g) = l;
                    }

                    // Connect L & G
                    (*l).left_child = g;
                    (*g).parent = l;

                    // Connect L & P
                    (*l).right_child = p;
                    (*p).parent = l;
                }
            } else {
                // L is right child
                if (*p).is_root() {
                    // Zag rotation (L is right child of root P)
                    //     P               L
                    //    / \             / \
                    //   a   L           P   c
                    //      / \         / \
                    //     b   c  ==>  a   b

                    // Connect P & b
                    (*p).right_child = (*l).left_child;
                    if !(*p).right_child.is_null() {
                        (*(*p).right_child).parent = p;
                    }

                    // Connect P & L
                    (*l).left_child = p;
                    (*p).parent = l;

                    // Make L the root
                    (*l).parent = l;
                } else if (*p).is_right_child() {
                    // Zag-zag rotation (L and P are both right children)
                    //   G                   L
                    //  / \                 / \
                    // a   P               P   d
                    //    / \             / \
                    //   b   L           G   c
                    //      / \         / \
                    //     c   d  ==>  a   b

                    // Connect G & b
                    (*g).right_child = (*p).left_child;
                    if !(*g).right_child.is_null() {
                        (*(*g).right_child).parent = g;
                    }

                    // Connect P & c
                    (*p).right_child = (*l).left_child;
                    if !(*p).right_child.is_null() {
                        (*(*p).right_child).parent = p;
                    }

                    // Connect L & Great GrandParent
                    if (*g).is_root() {
                        (*l).parent = l;
                    } else {
                        (*l).parent = (*g).parent;
                        *parents_child_pointer_address(g) = l;
                    }

                    // Connect L & P
                    (*l).left_child = p;
                    (*p).parent = l;

                    // Connect P & G
                    (*p).left_child = g;
                    (*g).parent = p;
                } else {
                    // Zag-zig rotation (L is right child, P is left child)
                    //       G              L
                    //      / \           /   \
                    //     P   d         P     G
                    //    / \           / \   / \
                    //   a   L    ==>  a   b c   d
                    //      / \
                    //     b   c

                    // Connect P & b
                    (*p).right_child = (*l).left_child;
                    if !(*p).right_child.is_null() {
                        (*(*p).right_child).parent = p;
                    }

                    // Connect G & c
                    (*g).left_child = (*l).right_child;
                    if !(*g).left_child.is_null() {
                        (*(*g).left_child).parent = g;
                    }

                    // Connect L & Great GrandParent
                    if (*g).is_root() {
                        (*l).parent = l;
                    } else {
                        (*l).parent = (*g).parent;
                        *parents_child_pointer_address(g) = l;
                    }

                    // Connect L & P
                    (*l).left_child = p;
                    (*p).parent = l;

                    // Connect L & G
                    (*l).right_child = g;
                    (*g).parent = l;
                }
            }
        }

        l
    }
}

/// Swap two nodes in the tree
unsafe fn swap_splay_links(link1: *mut SplayLinks, link2: *mut SplayLinks) {
    // Swap parent pointers
    let temp_parent = (*link1).parent;
    (*link1).parent = (*link2).parent;
    (*link2).parent = temp_parent;

    // Swap left child pointers
    let temp_left = (*link1).left_child;
    (*link1).left_child = (*link2).left_child;
    (*link2).left_child = temp_left;

    // Swap right child pointers
    let temp_right = (*link1).right_child;
    (*link1).right_child = (*link2).right_child;
    (*link2).right_child = temp_right;

    // Fix parent references in children
    if !(*link1).left_child.is_null() {
        (*(*link1).left_child).parent = link1;
    }
    if !(*link1).right_child.is_null() {
        (*(*link1).right_child).parent = link1;
    }
    if !(*link2).left_child.is_null() {
        (*(*link2).left_child).parent = link2;
    }
    if !(*link2).right_child.is_null() {
        (*(*link2).right_child).parent = link2;
    }

    // Fix child references in parents
    if (*link1).is_root() {
        (*link1).parent = link1;
    } else {
        if (*(*link1).parent).left_child == link2 {
            (*(*link1).parent).left_child = link1;
        } else {
            (*(*link1).parent).right_child = link1;
        }
    }

    if (*link2).is_root() {
        (*link2).parent = link2;
    } else {
        if (*(*link2).parent).left_child == link1 {
            (*(*link2).parent).left_child = link2;
        } else {
            (*(*link2).parent).right_child = link2;
        }
    }
}

/// Delete a node from the tree and return the new root
///
/// Returns NULL if tree is now empty
pub fn rtl_delete(links: *mut SplayLinks) -> *mut SplayLinks {
    if links.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        // If node has two children, swap with predecessor
        if !(*links).left_child.is_null() && !(*links).right_child.is_null() {
            let predecessor = rtl_subtree_predecessor(links);
            swap_splay_links(predecessor, links);
        }

        // Now links has at most one child

        // If links has no children
        if (*links).left_child.is_null() && (*links).right_child.is_null() {
            if (*links).is_root() {
                return ptr::null_mut();
            }

            // Set parent's child pointer to NULL and splay parent
            let parent = (*links).parent;
            *parents_child_pointer_address(links) = ptr::null_mut();
            return rtl_splay(parent);
        }

        // Links has one child
        let child = if !(*links).left_child.is_null() {
            (*links).left_child
        } else {
            (*links).right_child
        };

        // If links is root, make child the new root
        if (*links).is_root() {
            (*child).parent = child;
            return child;
        }

        // Link parent and child, splay parent
        *parents_child_pointer_address(links) = child;
        (*child).parent = (*links).parent;
        rtl_splay((*child).parent)
    }
}

/// Delete a node without splaying
pub fn rtl_delete_no_splay(links: *mut SplayLinks, root: &mut *mut SplayLinks) {
    if links.is_null() {
        return;
    }

    unsafe {
        // If node has two children, swap with predecessor
        if !(*links).left_child.is_null() && !(*links).right_child.is_null() {
            let predecessor = rtl_subtree_predecessor(links);
            if (*links).is_root() {
                *root = predecessor;
            }
            swap_splay_links(predecessor, links);
        }

        // If links has no children
        if (*links).left_child.is_null() && (*links).right_child.is_null() {
            if (*links).is_root() {
                *root = ptr::null_mut();
                return;
            }
            *parents_child_pointer_address(links) = ptr::null_mut();
            return;
        }

        // Links has one child
        let child = if !(*links).left_child.is_null() {
            (*links).left_child
        } else {
            (*links).right_child
        };

        if (*links).is_root() {
            (*child).parent = child;
            *root = child;
            return;
        }

        *parents_child_pointer_address(links) = child;
        (*child).parent = (*links).parent;
    }
}

/// Find the in-order successor in the subtree rooted at links
pub fn rtl_subtree_successor(links: *mut SplayLinks) -> *mut SplayLinks {
    if links.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        // Successor is leftmost node in right subtree
        let mut ptr = (*links).right_child;
        if ptr.is_null() {
            return ptr::null_mut();
        }

        while !(*ptr).left_child.is_null() {
            ptr = (*ptr).left_child;
        }

        ptr
    }
}

/// Find the in-order predecessor in the subtree rooted at links
pub fn rtl_subtree_predecessor(links: *mut SplayLinks) -> *mut SplayLinks {
    if links.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        // Predecessor is rightmost node in left subtree
        let mut ptr = (*links).left_child;
        if ptr.is_null() {
            return ptr::null_mut();
        }

        while !(*ptr).right_child.is_null() {
            ptr = (*ptr).right_child;
        }

        ptr
    }
}

/// Find the real successor (not just in subtree)
pub fn rtl_real_successor(links: *mut SplayLinks) -> *mut SplayLinks {
    if links.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        // First try subtree successor
        let successor = rtl_subtree_successor(links);
        if !successor.is_null() {
            return successor;
        }

        // Otherwise go up until we find an ancestor we are the left child of
        let mut ptr = links;
        while !(*ptr).is_root() && (*ptr).is_right_child() {
            ptr = (*ptr).parent;
        }

        if (*ptr).is_root() {
            return ptr::null_mut();
        }

        (*ptr).parent
    }
}

/// Find the real predecessor (not just in subtree)
pub fn rtl_real_predecessor(links: *mut SplayLinks) -> *mut SplayLinks {
    if links.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        // First try subtree predecessor
        let predecessor = rtl_subtree_predecessor(links);
        if !predecessor.is_null() {
            return predecessor;
        }

        // Otherwise go up until we find an ancestor we are the right child of
        let mut ptr = links;
        while !(*ptr).is_root() && (*ptr).is_left_child() {
            ptr = (*ptr).parent;
        }

        if (*ptr).is_root() {
            return ptr::null_mut();
        }

        (*ptr).parent
    }
}

/// Find the minimum (leftmost) node in the tree
pub fn rtl_splay_min(root: *mut SplayLinks) -> *mut SplayLinks {
    if root.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let mut ptr = root;
        while !(*ptr).left_child.is_null() {
            ptr = (*ptr).left_child;
        }
        ptr
    }
}

/// Find the maximum (rightmost) node in the tree
pub fn rtl_splay_max(root: *mut SplayLinks) -> *mut SplayLinks {
    if root.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let mut ptr = root;
        while !(*ptr).right_child.is_null() {
            ptr = (*ptr).right_child;
        }
        ptr
    }
}

/// Count nodes in the tree
pub fn rtl_splay_count(root: *mut SplayLinks) -> usize {
    if root.is_null() {
        return 0;
    }

    unsafe {
        1 + rtl_splay_count((*root).left_child) + rtl_splay_count((*root).right_child)
    }
}

/// Get the depth of a node (distance from root)
pub fn rtl_splay_depth(links: *mut SplayLinks) -> usize {
    if links.is_null() {
        return 0;
    }

    let mut depth = 0;
    let mut ptr = links;

    unsafe {
        while !(*ptr).is_root() {
            depth += 1;
            ptr = (*ptr).parent;
        }
    }

    depth
}

/// Get the height of the tree (maximum depth)
pub fn rtl_splay_height(root: *mut SplayLinks) -> usize {
    if root.is_null() {
        return 0;
    }

    unsafe {
        let left_height = rtl_splay_height((*root).left_child);
        let right_height = rtl_splay_height((*root).right_child);
        1 + left_height.max(right_height)
    }
}

/// Initialize splay subsystem (nothing needed for splay trees)
pub fn rtl_splay_init() {
    crate::serial_println!("[RTL] Splay tree subsystem initialized");
}
