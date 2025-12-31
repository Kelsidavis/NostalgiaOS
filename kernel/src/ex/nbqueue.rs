//! Executive Non-Blocking Queue
//!
//! Provides a lock-free FIFO queue implementation using compare-and-swap
//! operations. This is useful for high-performance inter-thread communication
//! without requiring traditional locks.
//!
//! Features:
//! - Lock-free insert and remove operations
//! - Uses SLIST for node allocation
//! - ABA problem prevention using tagged pointers
//! - Suitable for multi-producer/multi-consumer scenarios
//!
//! Based on Windows Server 2003 base/ntos/ex/nbqueue.c

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

extern crate alloc;

/// Non-blocking queue pointer (x86_64 version)
/// Contains a 48-bit pointer and 16-bit counter to prevent ABA problem
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NbQueuePointer {
    data: u64,
}

impl NbQueuePointer {
    pub const fn new() -> Self {
        Self { data: 0 }
    }

    /// Pack a node pointer and counter into the queue pointer
    pub fn pack(node: *mut NbQueueNode, count: u16) -> Self {
        let node_bits = (node as u64) & 0x0000_FFFF_FFFF_FFFF;
        let count_bits = (count as u64) << 48;
        Self {
            data: node_bits | count_bits,
        }
    }

    /// Unpack the node pointer from the queue pointer
    pub fn node(&self) -> *mut NbQueueNode {
        // Sign-extend if needed (for kernel addresses)
        let addr = self.data & 0x0000_FFFF_FFFF_FFFF;
        if addr & 0x0000_8000_0000_0000 != 0 {
            // High bit set, sign extend
            (addr | 0xFFFF_0000_0000_0000) as *mut NbQueueNode
        } else {
            addr as *mut NbQueueNode
        }
    }

    /// Get the counter value
    pub fn count(&self) -> u16 {
        (self.data >> 48) as u16
    }

    /// Check if node is null
    pub fn is_null(&self) -> bool {
        self.node().is_null()
    }
}

/// Non-blocking queue node
#[repr(C)]
pub struct NbQueueNode {
    /// Next pointer (atomic tagged pointer)
    next: AtomicU64,
    /// Value stored in this node
    value: u64,
}

impl NbQueueNode {
    pub fn new(value: u64) -> Self {
        Self {
            next: AtomicU64::new(0),
            value,
        }
    }

    fn next_ptr(&self) -> NbQueuePointer {
        NbQueuePointer {
            data: self.next.load(Ordering::Acquire),
        }
    }
}

/// Non-blocking queue header
pub struct NbQueue {
    /// Head pointer (atomic)
    head: AtomicU64,
    /// Tail pointer (atomic)
    tail: AtomicU64,
    /// Free node list
    free_list: AtomicU64,
    /// Total nodes allocated
    total_nodes: AtomicUsize,
    /// Nodes currently in queue
    active_nodes: AtomicUsize,
    /// Insert operations
    inserts: AtomicU64,
    /// Remove operations
    removes: AtomicU64,
    /// CAS failures (contention metric)
    cas_failures: AtomicU64,
}

impl NbQueue {
    /// Create a new non-blocking queue with initial nodes
    pub fn new(initial_nodes: usize) -> Option<Self> {
        if initial_nodes == 0 {
            return None;
        }

        // Allocate the queue structure
        let queue = Self {
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            free_list: AtomicU64::new(0),
            total_nodes: AtomicUsize::new(initial_nodes),
            active_nodes: AtomicUsize::new(0),
            inserts: AtomicU64::new(0),
            removes: AtomicU64::new(0),
            cas_failures: AtomicU64::new(0),
        };

        // Create initial node pool
        for _ in 0..initial_nodes {
            let node = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(NbQueueNode::new(0)));
            queue.push_free_node(node);
        }

        // Allocate sentinel node for head/tail
        let sentinel = match queue.pop_free_node() {
            Some(node) => node,
            None => return None,
        };

        // Initialize head and tail to sentinel
        unsafe {
            (*sentinel).next.store(0, Ordering::Release);
            (*sentinel).value = 0;
        }

        let ptr = NbQueuePointer::pack(sentinel, 0);
        queue.head.store(ptr.data, Ordering::Release);
        queue.tail.store(ptr.data, Ordering::Release);

        Some(queue)
    }

    /// Push a node onto the free list
    fn push_free_node(&self, node: *mut NbQueueNode) {
        loop {
            let old = self.free_list.load(Ordering::Acquire);
            unsafe {
                (*node).next.store(old, Ordering::Release);
            }
            if self
                .free_list
                .compare_exchange_weak(old, node as u64, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Pop a node from the free list
    fn pop_free_node(&self) -> Option<*mut NbQueueNode> {
        loop {
            let old = self.free_list.load(Ordering::Acquire);
            if old == 0 {
                return None;
            }

            let node = old as *mut NbQueueNode;
            let next = unsafe { (*node).next.load(Ordering::Acquire) };

            if self
                .free_list
                .compare_exchange_weak(old, next, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                return Some(node);
            }
            self.cas_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Insert a value at the tail of the queue
    pub fn insert_tail(&self, value: u64) -> bool {
        // Allocate a node from the free list
        let node = match self.pop_free_node() {
            Some(n) => n,
            None => return false,
        };

        // Initialize the node
        unsafe {
            (*node).next.store(0, Ordering::Release);
            (*node).value = value;
        }

        // Insert at tail using Michael-Scott algorithm
        loop {
            let tail = NbQueuePointer {
                data: self.tail.load(Ordering::Acquire),
            };
            let tail_node = tail.node();

            let next = unsafe { (*tail_node).next_ptr() };

            // Re-read tail to check consistency
            if tail.data != self.tail.load(Ordering::Acquire) {
                self.cas_failures.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            if next.is_null() {
                // Tail is pointing to last node, try to insert
                let insert = NbQueuePointer::pack(node, next.count().wrapping_add(1));

                if unsafe {
                    (*tail_node)
                        .next
                        .compare_exchange_weak(
                            next.data,
                            insert.data,
                            Ordering::Release,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                } {
                    // Successfully inserted, try to swing tail forward
                    let new_tail = NbQueuePointer::pack(node, tail.count().wrapping_add(1));
                    let _ = self.tail.compare_exchange_weak(
                        tail.data,
                        new_tail.data,
                        Ordering::Release,
                        Ordering::Relaxed,
                    );
                    break;
                }
            } else {
                // Tail is falling behind, try to advance it
                let new_tail = NbQueuePointer::pack(next.node(), tail.count().wrapping_add(1));
                let _ = self.tail.compare_exchange_weak(
                    tail.data,
                    new_tail.data,
                    Ordering::Release,
                    Ordering::Relaxed,
                );
            }
            self.cas_failures.fetch_add(1, Ordering::Relaxed);
        }

        self.inserts.fetch_add(1, Ordering::Relaxed);
        self.active_nodes.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Remove a value from the head of the queue
    pub fn remove_head(&self) -> Option<u64> {
        loop {
            let head = NbQueuePointer {
                data: self.head.load(Ordering::Acquire),
            };
            let tail = NbQueuePointer {
                data: self.tail.load(Ordering::Acquire),
            };
            let head_node = head.node();
            let next = unsafe { (*head_node).next_ptr() };

            // Re-read head to check consistency
            if head.data != self.head.load(Ordering::Acquire) {
                self.cas_failures.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            if head.node() == tail.node() {
                // Queue might be empty or tail is falling behind
                if next.is_null() {
                    // Queue is empty
                    return None;
                }

                // Tail is falling behind, try to advance it
                let new_tail = NbQueuePointer::pack(next.node(), tail.count().wrapping_add(1));
                let _ = self.tail.compare_exchange_weak(
                    tail.data,
                    new_tail.data,
                    Ordering::Release,
                    Ordering::Relaxed,
                );
            } else {
                // Queue is not empty, try to remove from head
                let next_node = next.node();
                if next_node.is_null() {
                    continue;
                }

                // Read value before CAS
                let value = unsafe { (*next_node).value };

                let new_head = NbQueuePointer::pack(next_node, head.count().wrapping_add(1));

                if self
                    .head
                    .compare_exchange_weak(
                        head.data,
                        new_head.data,
                        Ordering::Release,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    // Successfully removed, return old head to free list
                    self.push_free_node(head_node);
                    self.removes.fetch_add(1, Ordering::Relaxed);
                    self.active_nodes.fetch_sub(1, Ordering::Relaxed);
                    return Some(value);
                }
            }
            self.cas_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        let head = NbQueuePointer {
            data: self.head.load(Ordering::Acquire),
        };
        let next = unsafe { (*head.node()).next_ptr() };
        next.is_null()
    }

    /// Get approximate queue length
    pub fn len(&self) -> usize {
        self.active_nodes.load(Ordering::Relaxed)
    }

    /// Get queue statistics
    pub fn statistics(&self) -> NbQueueStats {
        NbQueueStats {
            total_nodes: self.total_nodes.load(Ordering::Relaxed),
            active_nodes: self.active_nodes.load(Ordering::Relaxed),
            inserts: self.inserts.load(Ordering::Relaxed),
            removes: self.removes.load(Ordering::Relaxed),
            cas_failures: self.cas_failures.load(Ordering::Relaxed),
        }
    }
}

impl Drop for NbQueue {
    fn drop(&mut self) {
        // Free all nodes in the queue
        while let Some(value) = self.remove_head() {
            let _ = value; // Drop the value
        }

        // Free remaining nodes in free list
        while let Some(node) = self.pop_free_node() {
            unsafe {
                let _ = alloc::boxed::Box::from_raw(node);
            }
        }

        // Free sentinel node
        let head = NbQueuePointer {
            data: self.head.load(Ordering::Acquire),
        };
        if !head.node().is_null() {
            unsafe {
                let _ = alloc::boxed::Box::from_raw(head.node());
            }
        }
    }
}

/// Queue statistics
#[derive(Debug, Clone)]
pub struct NbQueueStats {
    /// Total nodes allocated to this queue
    pub total_nodes: usize,
    /// Nodes currently containing values
    pub active_nodes: usize,
    /// Total insert operations
    pub inserts: u64,
    /// Total remove operations
    pub removes: u64,
    /// CAS failures (contention metric)
    pub cas_failures: u64,
}

/// Global NBQueue subsystem state
static mut NBQUEUE_INITIALIZED: bool = false;
static TOTAL_QUEUES: AtomicUsize = AtomicUsize::new(0);
static TOTAL_INSERTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_REMOVES: AtomicU64 = AtomicU64::new(0);

/// Initialize the NBQueue subsystem
pub fn exp_nbqueue_init() {
    unsafe {
        NBQUEUE_INITIALIZED = true;
    }
    crate::serial_println!("[EX] Non-blocking queue subsystem initialized");
}

/// Create a new non-blocking queue
pub fn ex_initialize_nbqueue(initial_nodes: usize) -> Option<NbQueue> {
    let queue = NbQueue::new(initial_nodes)?;
    TOTAL_QUEUES.fetch_add(1, Ordering::Relaxed);
    Some(queue)
}

/// Insert a value into a non-blocking queue
pub fn ex_insert_tail_nbqueue(queue: &NbQueue, value: u64) -> bool {
    let result = queue.insert_tail(value);
    if result {
        TOTAL_INSERTS.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Remove a value from a non-blocking queue
pub fn ex_remove_head_nbqueue(queue: &NbQueue) -> Option<u64> {
    let result = queue.remove_head();
    if result.is_some() {
        TOTAL_REMOVES.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Get global NBQueue statistics
pub fn exp_nbqueue_get_stats() -> (usize, u64, u64) {
    (
        TOTAL_QUEUES.load(Ordering::Relaxed),
        TOTAL_INSERTS.load(Ordering::Relaxed),
        TOTAL_REMOVES.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let queue = NbQueue::new(16).expect("Failed to create queue");

        // Insert some values
        assert!(queue.insert_tail(1));
        assert!(queue.insert_tail(2));
        assert!(queue.insert_tail(3));

        // Remove values in FIFO order
        assert_eq!(queue.remove_head(), Some(1));
        assert_eq!(queue.remove_head(), Some(2));
        assert_eq!(queue.remove_head(), Some(3));
        assert_eq!(queue.remove_head(), None);
    }

    #[test]
    fn test_empty_queue() {
        let queue = NbQueue::new(16).expect("Failed to create queue");
        assert!(queue.is_empty());
        assert_eq!(queue.remove_head(), None);
    }
}
