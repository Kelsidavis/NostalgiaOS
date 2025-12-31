//! Performance Hook Infrastructure
//!
//! Provides hook registration and callback mechanisms for performance
//! event logging. Hooks are invoked at key kernel events to log data
//! to performance trace buffers.
//!
//! Reference: Windows Server 2003 base/ntos/perf/perfp.h

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::ke::SpinLock;

/// Maximum number of registered hooks
pub const MAX_PERF_HOOKS: usize = 64;

/// Hook IDs for different event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PerfHookId {
    /// Process creation
    ProcessCreate = 0x0001,
    /// Process termination
    ProcessTerminate = 0x0002,
    /// Thread creation
    ThreadCreate = 0x0003,
    /// Thread termination
    ThreadTerminate = 0x0004,
    /// Context switch
    ContextSwitch = 0x0005,
    /// Image load (DLL/EXE)
    ImageLoad = 0x0006,
    /// Image unload
    ImageUnload = 0x0007,
    /// Disk read
    DiskRead = 0x0010,
    /// Disk write
    DiskWrite = 0x0011,
    /// File create/open
    FileCreate = 0x0020,
    /// File delete
    FileDelete = 0x0021,
    /// File read
    FileRead = 0x0022,
    /// File write
    FileWrite = 0x0023,
    /// Registry query
    RegistryQuery = 0x0030,
    /// Registry set value
    RegistrySetValue = 0x0031,
    /// Network send
    NetworkSend = 0x0040,
    /// Network receive
    NetworkReceive = 0x0041,
    /// Page fault
    PageFault = 0x0050,
    /// Hard fault
    HardFault = 0x0051,
    /// Pool allocation
    PoolAlloc = 0x0060,
    /// Pool free
    PoolFree = 0x0061,
    /// DPC start
    DpcStart = 0x0070,
    /// DPC end
    DpcEnd = 0x0071,
    /// Interrupt start
    InterruptStart = 0x0080,
    /// Interrupt end
    InterruptEnd = 0x0081,
    /// System call enter
    SyscallEnter = 0x0090,
    /// System call exit
    SyscallExit = 0x0091,
    /// Timer expiration
    TimerExpire = 0x00A0,
    /// Wait start
    WaitStart = 0x00B0,
    /// Wait end
    WaitEnd = 0x00B1,
    /// Profile sample
    ProfileSample = 0x00C0,
    /// Custom event
    Custom = 0xFFFF,
}

impl From<u16> for PerfHookId {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => PerfHookId::ProcessCreate,
            0x0002 => PerfHookId::ProcessTerminate,
            0x0003 => PerfHookId::ThreadCreate,
            0x0004 => PerfHookId::ThreadTerminate,
            0x0005 => PerfHookId::ContextSwitch,
            0x0006 => PerfHookId::ImageLoad,
            0x0007 => PerfHookId::ImageUnload,
            0x0010 => PerfHookId::DiskRead,
            0x0011 => PerfHookId::DiskWrite,
            0x0020 => PerfHookId::FileCreate,
            0x0021 => PerfHookId::FileDelete,
            0x0022 => PerfHookId::FileRead,
            0x0023 => PerfHookId::FileWrite,
            0x0030 => PerfHookId::RegistryQuery,
            0x0031 => PerfHookId::RegistrySetValue,
            0x0040 => PerfHookId::NetworkSend,
            0x0041 => PerfHookId::NetworkReceive,
            0x0050 => PerfHookId::PageFault,
            0x0051 => PerfHookId::HardFault,
            0x0060 => PerfHookId::PoolAlloc,
            0x0061 => PerfHookId::PoolFree,
            0x0070 => PerfHookId::DpcStart,
            0x0071 => PerfHookId::DpcEnd,
            0x0080 => PerfHookId::InterruptStart,
            0x0081 => PerfHookId::InterruptEnd,
            0x0090 => PerfHookId::SyscallEnter,
            0x0091 => PerfHookId::SyscallExit,
            0x00A0 => PerfHookId::TimerExpire,
            0x00B0 => PerfHookId::WaitStart,
            0x00B1 => PerfHookId::WaitEnd,
            0x00C0 => PerfHookId::ProfileSample,
            _ => PerfHookId::Custom,
        }
    }
}

/// Performance event record header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PerfEventHeader {
    /// Hook ID that generated this event
    pub hook_id: u16,
    /// Size of the full record (header + data)
    pub size: u16,
    /// Timestamp (tick count)
    pub timestamp: u64,
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// CPU number
    pub cpu: u8,
    /// Reserved for alignment
    pub reserved: [u8; 3],
}

impl PerfEventHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn new(hook_id: PerfHookId, data_size: usize) -> Self {
        Self {
            hook_id: hook_id as u16,
            size: (Self::SIZE + data_size) as u16,
            timestamp: crate::hal::apic::get_tick_count(),
            pid: crate::ke::ke_get_current_process_id(),
            tid: crate::ke::ke_get_current_thread_id(),
            cpu: crate::ke::ke_get_current_processor_number() as u8,
            reserved: [0; 3],
        }
    }
}

/// Hook callback function type
pub type PerfHookCallback = fn(hook_id: PerfHookId, data: *const u8, data_len: usize);

/// Registered hook entry
struct HookEntry {
    hook_id: PerfHookId,
    callback: PerfHookCallback,
    enabled: bool,
}

/// Hook registry
static HOOK_LOCK: SpinLock<()> = SpinLock::new(());
static mut HOOKS: [Option<HookEntry>; MAX_PERF_HOOKS] = {
    const NONE: Option<HookEntry> = None;
    [NONE; MAX_PERF_HOOKS]
};
static HOOK_COUNT: AtomicU32 = AtomicU32::new(0);

/// Ring buffer for event logging
pub const EVENT_BUFFER_SIZE: usize = 65536; // 64KB
static mut EVENT_BUFFER: [u8; EVENT_BUFFER_SIZE] = [0; EVENT_BUFFER_SIZE];
static EVENT_WRITE_POS: AtomicU64 = AtomicU64::new(0);
static EVENT_READ_POS: AtomicU64 = AtomicU64::new(0);
static EVENTS_LOGGED: AtomicU64 = AtomicU64::new(0);
static EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);
static BUFFER_ENABLED: AtomicBool = AtomicBool::new(false);

/// Initialize the hook subsystem
pub fn init() {
    crate::serial_println!("[PERF] Initializing hook subsystem");

    // Clear hook registry
    let _guard = HOOK_LOCK.lock();
    unsafe {
        for hook in HOOKS.iter_mut() {
            *hook = None;
        }
    }
    HOOK_COUNT.store(0, Ordering::Relaxed);

    // Clear event buffer
    EVENT_WRITE_POS.store(0, Ordering::Relaxed);
    EVENT_READ_POS.store(0, Ordering::Relaxed);
    EVENTS_LOGGED.store(0, Ordering::Relaxed);
    EVENTS_DROPPED.store(0, Ordering::Relaxed);

    crate::serial_println!("[PERF] Hook subsystem initialized ({} max hooks, {} byte buffer)",
        MAX_PERF_HOOKS, EVENT_BUFFER_SIZE);
}

/// Register a performance hook
pub fn register_hook(hook_id: PerfHookId, callback: PerfHookCallback) -> Option<u32> {
    let _guard = HOOK_LOCK.lock();

    // Find empty slot
    unsafe {
        for (i, slot) in HOOKS.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(HookEntry {
                    hook_id,
                    callback,
                    enabled: true,
                });
                HOOK_COUNT.fetch_add(1, Ordering::Relaxed);
                return Some(i as u32);
            }
        }
    }

    None // No free slots
}

/// Unregister a hook by handle
pub fn unregister_hook(handle: u32) -> bool {
    let _guard = HOOK_LOCK.lock();

    if (handle as usize) < MAX_PERF_HOOKS {
        unsafe {
            if HOOKS[handle as usize].is_some() {
                HOOKS[handle as usize] = None;
                HOOK_COUNT.fetch_sub(1, Ordering::Relaxed);
                return true;
            }
        }
    }

    false
}

/// Enable or disable a hook
pub fn set_hook_enabled(handle: u32, enabled: bool) -> bool {
    let _guard = HOOK_LOCK.lock();

    if (handle as usize) < MAX_PERF_HOOKS {
        unsafe {
            if let Some(ref mut hook) = HOOKS[handle as usize] {
                hook.enabled = enabled;
                return true;
            }
        }
    }

    false
}

/// Fire a hook (internal use - called from event logging points)
#[inline]
pub fn fire_hook(hook_id: PerfHookId, data: *const u8, data_len: usize) {
    // Quick check if any hooks registered
    if HOOK_COUNT.load(Ordering::Relaxed) == 0 {
        return;
    }

    // Note: We don't lock here for performance - we accept potential races
    // in hook iteration for low overhead in hot paths

    unsafe {
        for slot in HOOKS.iter() {
            if let Some(ref hook) = slot {
                if hook.enabled && hook.hook_id == hook_id {
                    (hook.callback)(hook_id, data, data_len);
                }
            }
        }
    }
}

/// Enable event buffer logging
pub fn enable_buffer() {
    BUFFER_ENABLED.store(true, Ordering::SeqCst);
}

/// Disable event buffer logging
pub fn disable_buffer() {
    BUFFER_ENABLED.store(false, Ordering::SeqCst);
}

/// Check if buffer is enabled
pub fn is_buffer_enabled() -> bool {
    BUFFER_ENABLED.load(Ordering::Relaxed)
}

/// Log an event to the ring buffer
pub fn log_event(hook_id: PerfHookId, data: &[u8]) {
    if !BUFFER_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    let header = PerfEventHeader::new(hook_id, data.len());
    let total_size = PerfEventHeader::SIZE + data.len();

    // Check if event fits
    if total_size > EVENT_BUFFER_SIZE / 4 {
        EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let _guard = HOOK_LOCK.lock();

    let write_pos = EVENT_WRITE_POS.load(Ordering::Acquire) as usize;
    let read_pos = EVENT_READ_POS.load(Ordering::Acquire) as usize;

    // Calculate available space (with wrap-around)
    let available = if write_pos >= read_pos {
        EVENT_BUFFER_SIZE - (write_pos - read_pos)
    } else {
        read_pos - write_pos
    };

    if available < total_size + 1 {
        EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }

    unsafe {
        // Write header
        let header_bytes = core::slice::from_raw_parts(
            &header as *const PerfEventHeader as *const u8,
            PerfEventHeader::SIZE,
        );

        for (i, &byte) in header_bytes.iter().enumerate() {
            let pos = (write_pos + i) % EVENT_BUFFER_SIZE;
            EVENT_BUFFER[pos] = byte;
        }

        // Write data
        for (i, &byte) in data.iter().enumerate() {
            let pos = (write_pos + PerfEventHeader::SIZE + i) % EVENT_BUFFER_SIZE;
            EVENT_BUFFER[pos] = byte;
        }
    }

    let new_write_pos = (write_pos + total_size) % EVENT_BUFFER_SIZE;
    EVENT_WRITE_POS.store(new_write_pos as u64, Ordering::Release);
    EVENTS_LOGGED.fetch_add(1, Ordering::Relaxed);

    // Fire hook callbacks
    fire_hook(hook_id, data.as_ptr(), data.len());
}

/// Read events from the buffer
pub fn read_events(max_count: usize) -> Vec<(PerfEventHeader, Vec<u8>)> {
    let _guard = HOOK_LOCK.lock();

    let mut result = Vec::new();
    let mut count = 0;

    while count < max_count {
        let read_pos = EVENT_READ_POS.load(Ordering::Acquire) as usize;
        let write_pos = EVENT_WRITE_POS.load(Ordering::Acquire) as usize;

        if read_pos == write_pos {
            break; // Buffer empty
        }

        // Read header
        let mut header_bytes = [0u8; PerfEventHeader::SIZE];
        unsafe {
            for i in 0..PerfEventHeader::SIZE {
                let pos = (read_pos + i) % EVENT_BUFFER_SIZE;
                header_bytes[i] = EVENT_BUFFER[pos];
            }
        }

        let header: PerfEventHeader = unsafe {
            core::ptr::read(header_bytes.as_ptr() as *const PerfEventHeader)
        };

        let data_len = header.size as usize - PerfEventHeader::SIZE;
        if data_len > EVENT_BUFFER_SIZE / 4 {
            // Corrupted record - reset buffer
            EVENT_READ_POS.store(write_pos as u64, Ordering::Release);
            break;
        }

        // Read data
        let mut data = Vec::with_capacity(data_len);
        unsafe {
            for i in 0..data_len {
                let pos = (read_pos + PerfEventHeader::SIZE + i) % EVENT_BUFFER_SIZE;
                data.push(EVENT_BUFFER[pos]);
            }
        }

        let new_read_pos = (read_pos + header.size as usize) % EVENT_BUFFER_SIZE;
        EVENT_READ_POS.store(new_read_pos as u64, Ordering::Release);

        result.push((header, data));
        count += 1;
    }

    result
}

/// Clear the event buffer
pub fn clear_buffer() {
    let _guard = HOOK_LOCK.lock();
    EVENT_WRITE_POS.store(0, Ordering::SeqCst);
    EVENT_READ_POS.store(0, Ordering::SeqCst);
}

/// Get hook statistics
#[derive(Debug, Clone, Copy)]
pub struct HookStats {
    pub hooks_registered: u32,
    pub events_logged: u64,
    pub events_dropped: u64,
    pub buffer_used: usize,
    pub buffer_enabled: bool,
}

pub fn get_stats() -> HookStats {
    let write_pos = EVENT_WRITE_POS.load(Ordering::Relaxed) as usize;
    let read_pos = EVENT_READ_POS.load(Ordering::Relaxed) as usize;

    let buffer_used = if write_pos >= read_pos {
        write_pos - read_pos
    } else {
        EVENT_BUFFER_SIZE - (read_pos - write_pos)
    };

    HookStats {
        hooks_registered: HOOK_COUNT.load(Ordering::Relaxed),
        events_logged: EVENTS_LOGGED.load(Ordering::Relaxed),
        events_dropped: EVENTS_DROPPED.load(Ordering::Relaxed),
        buffer_used,
        buffer_enabled: BUFFER_ENABLED.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Convenience functions for logging specific event types
// ============================================================================

/// Log a process create event
#[inline]
pub fn log_process_create(pid: u32, parent_pid: u32, image_name: &[u8]) {
    let mut data = Vec::with_capacity(8 + image_name.len());
    data.extend_from_slice(&pid.to_le_bytes());
    data.extend_from_slice(&parent_pid.to_le_bytes());
    data.extend_from_slice(image_name);
    log_event(PerfHookId::ProcessCreate, &data);
}

/// Log a thread create event
#[inline]
pub fn log_thread_create(tid: u32, pid: u32, start_addr: u64) {
    let mut data = [0u8; 16];
    data[0..4].copy_from_slice(&tid.to_le_bytes());
    data[4..8].copy_from_slice(&pid.to_le_bytes());
    data[8..16].copy_from_slice(&start_addr.to_le_bytes());
    log_event(PerfHookId::ThreadCreate, &data);
}

/// Log a context switch event
#[inline]
pub fn log_context_switch_event(old_tid: u32, new_tid: u32, old_priority: u8, new_priority: u8) {
    let mut data = [0u8; 10];
    data[0..4].copy_from_slice(&old_tid.to_le_bytes());
    data[4..8].copy_from_slice(&new_tid.to_le_bytes());
    data[8] = old_priority;
    data[9] = new_priority;
    log_event(PerfHookId::ContextSwitch, &data);
}

/// Log a disk I/O event
#[inline]
pub fn log_disk_io(is_write: bool, disk: u8, lba: u64, sectors: u32) {
    let mut data = [0u8; 16];
    data[0] = disk;
    data[1..9].copy_from_slice(&lba.to_le_bytes());
    data[9..13].copy_from_slice(&sectors.to_le_bytes());
    log_event(
        if is_write { PerfHookId::DiskWrite } else { PerfHookId::DiskRead },
        &data,
    );
}

/// Log a syscall event
#[inline]
pub fn log_syscall_event(syscall_num: u32, is_exit: bool, result: i64) {
    let mut data = [0u8; 12];
    data[0..4].copy_from_slice(&syscall_num.to_le_bytes());
    data[4..12].copy_from_slice(&result.to_le_bytes());
    log_event(
        if is_exit { PerfHookId::SyscallExit } else { PerfHookId::SyscallEnter },
        &data,
    );
}

/// Log a page fault event
#[inline]
pub fn log_page_fault(address: u64, is_write: bool, is_user: bool) {
    let mut data = [0u8; 10];
    data[0..8].copy_from_slice(&address.to_le_bytes());
    data[8] = if is_write { 1 } else { 0 };
    data[9] = if is_user { 1 } else { 0 };
    log_event(PerfHookId::PageFault, &data);
}

/// Log a pool allocation event
#[inline]
pub fn log_pool_alloc_event(tag: u32, size: usize, pool_type: u8) {
    let mut data = [0u8; 13];
    data[0..4].copy_from_slice(&tag.to_le_bytes());
    data[4..12].copy_from_slice(&(size as u64).to_le_bytes());
    data[12] = pool_type;
    log_event(PerfHookId::PoolAlloc, &data);
}

/// Log DPC start event
#[inline]
pub fn log_dpc_start(dpc_addr: u64) {
    log_event(PerfHookId::DpcStart, &dpc_addr.to_le_bytes());
}

/// Log DPC end event
#[inline]
pub fn log_dpc_end(dpc_addr: u64) {
    log_event(PerfHookId::DpcEnd, &dpc_addr.to_le_bytes());
}

/// Log interrupt start event
#[inline]
pub fn log_interrupt_start(vector: u8) {
    log_event(PerfHookId::InterruptStart, &[vector]);
}

/// Log interrupt end event
#[inline]
pub fn log_interrupt_end(vector: u8) {
    log_event(PerfHookId::InterruptEnd, &[vector]);
}
