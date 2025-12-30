//! VirtIO Virtqueue Implementation
//!
//! Virtqueues are the mechanism for bulk data transport in VirtIO.
//! Each queue consists of:
//! - Descriptor table: array of buffer descriptors
//! - Available ring: driver-to-device buffer notifications
//! - Used ring: device-to-driver buffer completions

use core::sync::atomic::{fence, Ordering};

/// Virtqueue descriptor flags
pub mod desc_flags {
    pub const NEXT: u16 = 1;      // Buffer continues via next field
    pub const WRITE: u16 = 2;     // Buffer is write-only (device writes)
    pub const INDIRECT: u16 = 4;  // Buffer contains indirect descriptors
}

/// Virtqueue descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtqDesc {
    /// Physical address of buffer
    pub addr: u64,
    /// Length of buffer
    pub len: u32,
    /// Descriptor flags
    pub flags: u16,
    /// Next descriptor index (if NEXT flag set)
    pub next: u16,
}

/// Available ring
#[repr(C)]
pub struct VirtqAvail {
    /// Flags (unused, set to 0)
    pub flags: u16,
    /// Index into ring[] for next available entry
    pub idx: u16,
    /// Ring of descriptor indices
    pub ring: [u16; 0], // Dynamically sized
}

/// Used ring element
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtqUsedElem {
    /// Index of descriptor chain head
    pub id: u32,
    /// Total bytes written to the buffer
    pub len: u32,
}

/// Used ring
#[repr(C)]
pub struct VirtqUsed {
    /// Flags (unused, set to 0)
    pub flags: u16,
    /// Index into ring[] for next used entry
    pub idx: u16,
    /// Ring of used elements
    pub ring: [VirtqUsedElem; 0], // Dynamically sized
}

/// Page size for legacy virtqueue allocation
pub const PAGE_SIZE: usize = 4096;

/// Calculate descriptor table size
pub fn desc_table_size(queue_size: u16) -> usize {
    (queue_size as usize) * core::mem::size_of::<VirtqDesc>()
}

/// Calculate available ring size
pub fn avail_ring_size(queue_size: u16) -> usize {
    6 + 2 * (queue_size as usize) // flags + idx + ring + used_event
}

/// Calculate used ring size
pub fn used_ring_size(queue_size: u16) -> usize {
    6 + 8 * (queue_size as usize) // flags + idx + ring + avail_event
}

/// Calculate total virtqueue size (page-aligned for legacy)
pub fn virtqueue_size_legacy(queue_size: u16) -> usize {
    // Descriptor table + available ring, page-aligned
    let part1 = desc_table_size(queue_size) + avail_ring_size(queue_size);
    let part1_aligned = (part1 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // Used ring
    let part2 = used_ring_size(queue_size);

    part1_aligned + part2
}

/// Virtqueue
pub struct Virtqueue {
    /// Queue size (number of descriptors)
    pub size: u16,
    /// Queue index
    pub index: u16,
    /// Base physical address of queue memory
    pub base_phys: u64,
    /// Base virtual address
    pub base_virt: *mut u8,
    /// Pointer to descriptor table
    pub desc: *mut VirtqDesc,
    /// Pointer to available ring
    pub avail: *mut VirtqAvail,
    /// Pointer to used ring
    pub used: *mut VirtqUsed,
    /// Next descriptor to allocate
    pub free_head: u16,
    /// Number of free descriptors
    pub num_free: u16,
    /// Last seen used index
    pub last_used_idx: u16,
}

impl Virtqueue {
    /// Create a new virtqueue
    pub unsafe fn new(
        index: u16,
        size: u16,
        base_phys: u64,
        base_virt: *mut u8,
    ) -> Self {
        let desc = base_virt as *mut VirtqDesc;
        let avail_offset = desc_table_size(size);
        let avail = base_virt.add(avail_offset) as *mut VirtqAvail;
        let used_offset = (avail_offset + avail_ring_size(size) + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let used = base_virt.add(used_offset) as *mut VirtqUsed;

        // Initialize descriptor chain
        for i in 0..(size as usize - 1) {
            (*desc.add(i)).next = (i + 1) as u16;
        }

        // Initialize available ring
        (*avail).flags = 0;
        (*avail).idx = 0;

        // Initialize used ring
        (*used).flags = 0;
        (*used).idx = 0;

        Self {
            size,
            index,
            base_phys,
            base_virt,
            desc,
            avail,
            used,
            free_head: 0,
            num_free: size,
            last_used_idx: 0,
        }
    }

    /// Allocate a descriptor
    fn alloc_desc(&mut self) -> Option<u16> {
        if self.num_free == 0 {
            return None;
        }

        let idx = self.free_head;
        unsafe {
            self.free_head = (*self.desc.add(idx as usize)).next;
        }
        self.num_free -= 1;
        Some(idx)
    }

    /// Free a descriptor
    fn free_desc(&mut self, idx: u16) {
        unsafe {
            (*self.desc.add(idx as usize)).next = self.free_head;
        }
        self.free_head = idx;
        self.num_free += 1;
    }

    /// Free a descriptor chain
    pub fn free_chain(&mut self, head: u16) {
        let mut idx = head;
        loop {
            let desc = unsafe { &*self.desc.add(idx as usize) };
            let next = desc.next;
            let has_next = (desc.flags & desc_flags::NEXT) != 0;
            self.free_desc(idx);
            if !has_next {
                break;
            }
            idx = next;
        }
    }

    /// Add a buffer chain to the available ring
    pub fn add_buf(&mut self, out_bufs: &[(u64, u32)], in_bufs: &[(u64, u32)]) -> Option<u16> {
        let total = out_bufs.len() + in_bufs.len();
        if total == 0 || total > self.num_free as usize {
            return None;
        }

        let head = self.alloc_desc()?;
        let mut prev = head;
        let mut is_first = true;

        // Add output buffers (device reads)
        for (addr, len) in out_bufs {
            let idx = if is_first {
                is_first = false;
                head
            } else {
                let idx = self.alloc_desc()?;
                unsafe {
                    (*self.desc.add(prev as usize)).flags |= desc_flags::NEXT;
                    (*self.desc.add(prev as usize)).next = idx;
                }
                idx
            };

            unsafe {
                let desc = &mut *self.desc.add(idx as usize);
                desc.addr = *addr;
                desc.len = *len;
                desc.flags = 0;
            }
            prev = idx;
        }

        // Add input buffers (device writes)
        for (addr, len) in in_bufs {
            let idx = if is_first {
                is_first = false;
                head
            } else {
                let idx = self.alloc_desc()?;
                unsafe {
                    (*self.desc.add(prev as usize)).flags |= desc_flags::NEXT;
                    (*self.desc.add(prev as usize)).next = idx;
                }
                idx
            };

            unsafe {
                let desc = &mut *self.desc.add(idx as usize);
                desc.addr = *addr;
                desc.len = *len;
                desc.flags = desc_flags::WRITE;
            }
            prev = idx;
        }

        // Add to available ring
        fence(Ordering::SeqCst);
        unsafe {
            let avail_idx = (*self.avail).idx;
            let ring_ptr = (self.avail as *mut u16).add(2); // Skip flags and idx
            *ring_ptr.add((avail_idx % self.size) as usize) = head;
            fence(Ordering::SeqCst);
            (*self.avail).idx = avail_idx.wrapping_add(1);
        }
        fence(Ordering::SeqCst);

        Some(head)
    }

    /// Check for completed buffers
    pub fn poll(&mut self) -> Option<(u16, u32)> {
        fence(Ordering::SeqCst);

        let used_idx = unsafe { (*self.used).idx };
        if self.last_used_idx == used_idx {
            return None;
        }

        // Get the used element
        let ring_ptr = unsafe { (self.used as *const u8).add(4) as *const VirtqUsedElem };
        let elem = unsafe { *ring_ptr.add((self.last_used_idx % self.size) as usize) };

        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        Some((elem.id as u16, elem.len))
    }

    /// Number of available descriptors
    pub fn available_descs(&self) -> u16 {
        self.num_free
    }
}
