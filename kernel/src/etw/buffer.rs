//! ETW Trace Buffer Management
//!
//! Manages buffers for collecting trace events before flushing to consumers.

use super::WnodeHeader;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

extern crate alloc;

/// Trace buffer header - matches Windows WMI_BUFFER_HEADER
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BufferHeader {
    /// Size of buffer in bytes
    pub buffer_size: u32,
    /// Saved offset for resuming after flush
    pub saved_offset: u32,
    /// Current offset in buffer
    pub current_offset: u32,
    /// Reference count
    pub reference_count: i32,
    /// Timestamp when buffer was allocated
    pub timestamp: i64,
    /// Sequence number
    pub sequence_number: u64,
    /// Client context (clock type, etc.)
    pub client_context: ClientContext,
    /// Buffer state flags
    pub state: BufferState,
    /// Offset to start of data
    pub offset: u32,
    /// Buffer type
    pub buffer_type: BufferType,
    /// Processor number that owns this buffer
    pub processor_number: u16,
    /// Reserved for alignment
    pub reserved: u16,
}

impl Default for BufferHeader {
    fn default() -> Self {
        Self {
            buffer_size: 0,
            saved_offset: 0,
            current_offset: core::mem::size_of::<BufferHeader>() as u32,
            reference_count: 1,
            timestamp: 0,
            sequence_number: 0,
            client_context: ClientContext::default(),
            state: BufferState::Free,
            offset: core::mem::size_of::<BufferHeader>() as u32,
            buffer_type: BufferType::Normal,
            processor_number: 0,
            reserved: 0,
        }
    }
}

/// Client context for timestamp interpretation
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientContext {
    /// Log file mode
    pub log_file_mode: u8,
    /// Reserved
    pub reserved1: u8,
    /// Reserved
    pub reserved2: u16,
}

/// Buffer state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BufferState {
    /// Buffer is free for use
    #[default]
    Free = 0,
    /// Buffer is being written
    InUse = 1,
    /// Buffer is full, ready for flush
    Full = 2,
    /// Buffer is being flushed
    Flushing = 3,
}

/// Buffer type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BufferType {
    /// Normal buffer
    #[default]
    Normal = 0,
    /// Flush marker buffer
    FlushMarker = 1,
    /// Rundown buffer
    Rundown = 2,
    /// Context swap buffer
    ContextSwap = 3,
}

/// Trace buffer for collecting events
pub struct TraceBuffer {
    /// Buffer ID
    id: u32,
    /// Buffer header
    header: BufferHeader,
    /// Buffer data
    data: Vec<u8>,
    /// Current write position
    write_pos: AtomicU32,
    /// Is buffer ready for flush
    needs_flush: AtomicBool,
    /// Sequence number for ordering
    sequence: AtomicU64,
}

/// Atomic u64 wrapper
struct AtomicU64(core::sync::atomic::AtomicU64);

impl AtomicU64 {
    const fn new(val: u64) -> Self {
        Self(core::sync::atomic::AtomicU64::new(val))
    }

    fn load(&self, order: Ordering) -> u64 {
        self.0.load(order)
    }

    fn fetch_add(&self, val: u64, order: Ordering) -> u64 {
        self.0.fetch_add(val, order)
    }
}

impl TraceBuffer {
    /// Create a new trace buffer
    pub fn new(id: u32, size: usize) -> Self {
        let header_size = core::mem::size_of::<BufferHeader>();
        let data_size = size.saturating_sub(header_size);

        let mut header = BufferHeader::default();
        header.buffer_size = size as u32;
        header.current_offset = header_size as u32;
        header.offset = header_size as u32;

        Self {
            id,
            header,
            data: vec![0u8; data_size],
            write_pos: AtomicU32::new(0),
            needs_flush: AtomicBool::new(false),
            sequence: AtomicU64::new(0),
        }
    }

    /// Get buffer ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get buffer size
    pub fn size(&self) -> usize {
        self.data.len() + core::mem::size_of::<BufferHeader>()
    }

    /// Get remaining space
    pub fn remaining(&self) -> usize {
        let pos = self.write_pos.load(Ordering::SeqCst) as usize;
        self.data.len().saturating_sub(pos)
    }

    /// Check if buffer has space for event
    pub fn has_space(&self, size: usize) -> bool {
        self.remaining() >= size
    }

    /// Try to write an event to the buffer
    pub fn try_write(&mut self, header: &WnodeHeader) -> bool {
        let event_size = header.buffer_size as usize;
        let pos = self.write_pos.load(Ordering::SeqCst) as usize;

        if pos + event_size > self.data.len() {
            return false;
        }

        // Write header
        let header_bytes = unsafe {
            core::slice::from_raw_parts(
                header as *const WnodeHeader as *const u8,
                core::mem::size_of::<WnodeHeader>(),
            )
        };

        let header_len = header_bytes.len().min(event_size);
        self.data[pos..pos + header_len].copy_from_slice(&header_bytes[..header_len]);

        // Update write position
        self.write_pos
            .store((pos + event_size) as u32, Ordering::SeqCst);
        self.sequence.fetch_add(1, Ordering::SeqCst);

        true
    }

    /// Write raw data to buffer
    pub fn write_raw(&mut self, data: &[u8]) -> bool {
        let pos = self.write_pos.load(Ordering::SeqCst) as usize;

        if pos + data.len() > self.data.len() {
            return false;
        }

        self.data[pos..pos + data.len()].copy_from_slice(data);
        self.write_pos
            .store((pos + data.len()) as u32, Ordering::SeqCst);

        true
    }

    /// Mark buffer for flush
    pub fn mark_for_flush(&mut self) {
        self.needs_flush.store(true, Ordering::SeqCst);
        self.header.state = BufferState::Full;
    }

    /// Check if buffer needs flush
    pub fn needs_flush(&self) -> bool {
        self.needs_flush.load(Ordering::SeqCst)
    }

    /// Flush buffer (reset for reuse)
    pub fn flush(&mut self) {
        self.header.state = BufferState::Flushing;

        // In a real implementation, this would write to a file or consumer
        // For now, we just reset the buffer

        self.reset();
    }

    /// Reset buffer for reuse
    pub fn reset(&mut self) {
        self.write_pos.store(0, Ordering::SeqCst);
        self.needs_flush.store(false, Ordering::SeqCst);
        self.header.state = BufferState::Free;
        self.header.current_offset = core::mem::size_of::<BufferHeader>() as u32;

        // Zero out data
        for byte in self.data.iter_mut() {
            *byte = 0;
        }
    }

    /// Get data slice
    pub fn data(&self) -> &[u8] {
        let pos = self.write_pos.load(Ordering::SeqCst) as usize;
        &self.data[..pos]
    }

    /// Get buffer state
    pub fn state(&self) -> BufferState {
        self.header.state
    }

    /// Get sequence number
    pub fn sequence(&self) -> u64 {
        self.sequence.load(Ordering::SeqCst)
    }

    /// Get header
    pub fn header(&self) -> &BufferHeader {
        &self.header
    }
}

impl core::fmt::Debug for TraceBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TraceBuffer")
            .field("id", &self.id)
            .field("size", &self.size())
            .field("used", &self.write_pos.load(Ordering::SeqCst))
            .field("state", &self.header.state)
            .field("sequence", &self.sequence.load(Ordering::SeqCst))
            .finish()
    }
}

/// Buffer pool for managing multiple trace buffers
pub struct BufferPool {
    /// Pool of buffers
    buffers: Vec<TraceBuffer>,
    /// Buffer size in bytes
    buffer_size: usize,
    /// Maximum number of buffers
    max_buffers: usize,
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new(initial_count: usize, buffer_size: usize, max_buffers: usize) -> Self {
        let mut buffers = Vec::with_capacity(initial_count);
        for i in 0..initial_count {
            buffers.push(TraceBuffer::new(i as u32, buffer_size));
        }

        Self {
            buffers,
            buffer_size,
            max_buffers,
        }
    }

    /// Get index of a free buffer, optionally allocating one
    pub fn get_free_buffer_index(&mut self) -> Option<usize> {
        // First try to find an existing free buffer
        for (i, buffer) in self.buffers.iter().enumerate() {
            if buffer.state() == BufferState::Free {
                return Some(i);
            }
        }

        // If no free buffer and we can allocate more, do so
        if self.buffers.len() < self.max_buffers {
            let id = self.buffers.len() as u32;
            let buffer_size = self.buffer_size;
            self.buffers.push(TraceBuffer::new(id, buffer_size));
            return Some(self.buffers.len() - 1);
        }

        None
    }

    /// Get mutable reference to buffer by index
    pub fn get_buffer_mut(&mut self, index: usize) -> Option<&mut TraceBuffer> {
        self.buffers.get_mut(index)
    }

    /// Flush all buffers marked for flush
    pub fn flush_pending(&mut self) {
        for buffer in self.buffers.iter_mut() {
            if buffer.needs_flush() {
                buffer.flush();
            }
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> BufferPoolStats {
        let mut stats = BufferPoolStats::default();
        stats.total_buffers = self.buffers.len() as u32;
        stats.buffer_size = self.buffer_size as u32;

        for buffer in self.buffers.iter() {
            match buffer.state() {
                BufferState::Free => stats.free_buffers += 1,
                BufferState::InUse => stats.in_use_buffers += 1,
                BufferState::Full => stats.full_buffers += 1,
                BufferState::Flushing => stats.flushing_buffers += 1,
            }
        }

        stats
    }
}

/// Buffer pool statistics
#[derive(Debug, Default, Clone)]
pub struct BufferPoolStats {
    /// Total number of buffers
    pub total_buffers: u32,
    /// Buffer size in bytes
    pub buffer_size: u32,
    /// Free buffers
    pub free_buffers: u32,
    /// In-use buffers
    pub in_use_buffers: u32,
    /// Full buffers waiting for flush
    pub full_buffers: u32,
    /// Buffers currently flushing
    pub flushing_buffers: u32,
}
