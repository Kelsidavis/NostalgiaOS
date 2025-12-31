//! Breakpoint Management
//!
//! Provides breakpoint table management for the kernel debugger:
//! - Setting and clearing breakpoints
//! - Breakpoint table with address/content tracking
//! - Deferred breakpoint handling for paged memory
//!
//! Based on Windows Server 2003 base/ntos/kd64/kdbreak.c

use crate::ke::SpinLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

extern crate alloc;

/// Maximum breakpoints in table
pub const BREAKPOINT_TABLE_SIZE: usize = 32;

/// x86_64 breakpoint instruction (INT 3)
pub const KDP_BREAKPOINT_VALUE: u8 = 0xCC;

/// Breakpoint alignment requirement
pub const KDP_BREAKPOINT_ALIGN: usize = 0;

/// Breakpoint flags
pub mod breakpoint_flags {
    pub const KD_BREAKPOINT_IN_USE: u32 = 0x00000001;
    pub const KD_BREAKPOINT_NEEDS_WRITE: u32 = 0x00000002;
    pub const KD_BREAKPOINT_SUSPENDED: u32 = 0x00000004;
    pub const KD_BREAKPOINT_NEEDS_REPLACE: u32 = 0x00000008;
}

/// Breakpoint table entry
#[derive(Debug, Clone, Default)]
pub struct BreakpointEntry {
    /// Address where breakpoint is set
    pub address: usize,
    /// Original instruction content
    pub content: u8,
    /// Breakpoint flags
    pub flags: u32,
    /// Directory table base (for process-specific breakpoints)
    pub directory_table_base: u64,
}

impl BreakpointEntry {
    pub const fn new() -> Self {
        Self {
            address: 0,
            content: 0,
            flags: 0,
            directory_table_base: 0,
        }
    }

    /// Check if breakpoint is in use
    pub fn is_in_use(&self) -> bool {
        (self.flags & breakpoint_flags::KD_BREAKPOINT_IN_USE) != 0
    }

    /// Check if breakpoint is suspended
    pub fn is_suspended(&self) -> bool {
        (self.flags & breakpoint_flags::KD_BREAKPOINT_SUSPENDED) != 0
    }

    /// Check if breakpoint needs to be written
    pub fn needs_write(&self) -> bool {
        (self.flags & breakpoint_flags::KD_BREAKPOINT_NEEDS_WRITE) != 0
    }

    /// Check if breakpoint needs to be replaced
    pub fn needs_replace(&self) -> bool {
        (self.flags & breakpoint_flags::KD_BREAKPOINT_NEEDS_REPLACE) != 0
    }
}

/// Breakpoint manager state
#[derive(Debug)]
pub struct BreakpointState {
    /// Breakpoint table
    table: [BreakpointEntry; BREAKPOINT_TABLE_SIZE],
    /// Breakpoints suspended flag
    pub suspended: bool,
    /// Owe breakpoint flag (deferred writes pending)
    pub owe_breakpoint: bool,
}

impl BreakpointState {
    pub const fn new() -> Self {
        const EMPTY_BP: BreakpointEntry = BreakpointEntry::new();
        Self {
            table: [EMPTY_BP; BREAKPOINT_TABLE_SIZE],
            suspended: false,
            owe_breakpoint: false,
        }
    }
}

/// Global breakpoint state
static mut BREAKPOINT_STATE: Option<SpinLock<BreakpointState>> = None;

/// Statistics
static BREAKPOINTS_SET: AtomicU64 = AtomicU64::new(0);
static BREAKPOINTS_HIT: AtomicU64 = AtomicU64::new(0);
static BREAKPOINTS_CLEARED: AtomicU64 = AtomicU64::new(0);

fn get_bp_state() -> &'static SpinLock<BreakpointState> {
    unsafe {
        BREAKPOINT_STATE
            .as_ref()
            .expect("Breakpoint state not initialized")
    }
}

/// Initialize breakpoint subsystem
pub fn kd_breakpoint_init() {
    unsafe {
        BREAKPOINT_STATE = Some(SpinLock::new(BreakpointState::new()));
    }
    crate::serial_println!("[KD] Breakpoint subsystem initialized");
}

/// Add a breakpoint
///
/// Returns the handle (1-based index) or 0 on failure
pub fn kd_add_breakpoint(address: usize) -> u32 {
    if (address & KDP_BREAKPOINT_ALIGN) != 0 {
        return 0;
    }

    let state = get_bp_state();
    let mut guard = state.lock();

    // Check if already set at this address
    for (index, bp) in guard.table.iter().enumerate() {
        if bp.is_in_use() && bp.address == address {
            if bp.needs_replace() {
                // Was being cleared, now being re-set
                guard.table[index].flags &= !breakpoint_flags::KD_BREAKPOINT_NEEDS_REPLACE;
                return (index + 1) as u32;
            } else {
                // Already set
                crate::serial_println!("[KD] Breakpoint already set at {:#x}", address);
                return 0;
            }
        }
    }

    // Find free entry
    let free_index = guard.table.iter().position(|bp| bp.flags == 0);

    match free_index {
        Some(index) => {
            // Read original content (simulated - would read actual memory)
            let original_content = 0x90u8; // NOP placeholder

            guard.table[index] = BreakpointEntry {
                address,
                content: original_content,
                flags: breakpoint_flags::KD_BREAKPOINT_IN_USE,
                directory_table_base: 0,
            };

            // In real implementation, write breakpoint instruction to memory:
            // unsafe { *(address as *mut u8) = KDP_BREAKPOINT_VALUE; }

            BREAKPOINTS_SET.fetch_add(1, Ordering::Relaxed);

            crate::serial_println!("[KD] Breakpoint {} set at {:#x}", index + 1, address);

            (index + 1) as u32
        }
        None => {
            crate::serial_println!("[KD] Breakpoint table full");
            0
        }
    }
}

/// Delete a breakpoint by handle
pub fn kd_delete_breakpoint(handle: u32) -> bool {
    if handle == 0 || handle as usize > BREAKPOINT_TABLE_SIZE {
        return false;
    }

    let index = (handle - 1) as usize;

    let state = get_bp_state();
    let mut guard = state.lock();

    if guard.table[index].flags == 0 {
        return false;
    }

    // If suspended, just clear the entry
    if guard.table[index].is_suspended() && !guard.table[index].needs_replace() {
        guard.table[index] = BreakpointEntry::new();
        BREAKPOINTS_CLEARED.fetch_add(1, Ordering::Relaxed);
        return true;
    }

    // In real implementation, restore original content:
    // unsafe { *(guard.table[index].address as *mut u8) = guard.table[index].content; }

    guard.table[index] = BreakpointEntry::new();
    BREAKPOINTS_CLEARED.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!("[KD] Breakpoint {} deleted", handle);

    true
}

/// Delete all breakpoints in a range
pub fn kd_delete_breakpoint_range(lower: usize, upper: usize) -> bool {
    let state = get_bp_state();
    let mut guard = state.lock();

    let mut any_deleted = false;

    for index in 0..BREAKPOINT_TABLE_SIZE {
        if guard.table[index].is_in_use() {
            let addr = guard.table[index].address;
            if addr >= lower && addr <= upper {
                guard.table[index] = BreakpointEntry::new();
                BREAKPOINTS_CLEARED.fetch_add(1, Ordering::Relaxed);
                any_deleted = true;
            }
        }
    }

    any_deleted
}

/// Suspend a breakpoint
pub fn kd_suspend_breakpoint(handle: u32) {
    if handle == 0 || handle as usize > BREAKPOINT_TABLE_SIZE {
        return;
    }

    let index = (handle - 1) as usize;

    let state = get_bp_state();
    let mut guard = state.lock();

    if guard.table[index].is_in_use() && !guard.table[index].is_suspended() {
        guard.table[index].flags |= breakpoint_flags::KD_BREAKPOINT_SUSPENDED;

        // In real implementation, restore original content temporarily:
        // unsafe { *(guard.table[index].address as *mut u8) = guard.table[index].content; }
    }
}

/// Suspend all breakpoints
pub fn kd_suspend_all_breakpoints() {
    let state = get_bp_state();
    let mut guard = state.lock();

    guard.suspended = true;

    for handle in 1..=BREAKPOINT_TABLE_SIZE as u32 {
        let index = (handle - 1) as usize;
        if guard.table[index].is_in_use() && !guard.table[index].is_suspended() {
            guard.table[index].flags |= breakpoint_flags::KD_BREAKPOINT_SUSPENDED;
        }
    }

    crate::serial_println!("[KD] All breakpoints suspended");
}

/// Restore all breakpoints
pub fn kd_restore_all_breakpoints() {
    let state = get_bp_state();
    let mut guard = state.lock();

    guard.suspended = false;

    for index in 0..BREAKPOINT_TABLE_SIZE {
        if guard.table[index].is_in_use() && guard.table[index].is_suspended() {
            guard.table[index].flags &= !breakpoint_flags::KD_BREAKPOINT_SUSPENDED;

            // In real implementation, write breakpoint instruction:
            // unsafe { *(guard.table[index].address as *mut u8) = KDP_BREAKPOINT_VALUE; }
        }
    }

    crate::serial_println!("[KD] All breakpoints restored");
}

/// Delete all breakpoints
pub fn kd_delete_all_breakpoints() {
    let state = get_bp_state();
    let mut guard = state.lock();

    guard.suspended = false;

    for index in 0..BREAKPOINT_TABLE_SIZE {
        if guard.table[index].flags != 0 {
            guard.table[index] = BreakpointEntry::new();
            BREAKPOINTS_CLEARED.fetch_add(1, Ordering::Relaxed);
        }
    }

    crate::serial_println!("[KD] All breakpoints deleted");
}

/// Record a breakpoint hit
pub fn kd_record_breakpoint_hit(address: usize) -> Option<u32> {
    let state = get_bp_state();
    let guard = state.lock();

    for (index, bp) in guard.table.iter().enumerate() {
        if bp.is_in_use() && bp.address == address && !bp.is_suspended() {
            BREAKPOINTS_HIT.fetch_add(1, Ordering::Relaxed);
            return Some((index + 1) as u32);
        }
    }

    None
}

/// Get breakpoint by handle
pub fn kd_get_breakpoint(handle: u32) -> Option<(usize, u8, u32)> {
    if handle == 0 || handle as usize > BREAKPOINT_TABLE_SIZE {
        return None;
    }

    let index = (handle - 1) as usize;

    let state = get_bp_state();
    let guard = state.lock();

    if guard.table[index].is_in_use() {
        Some((
            guard.table[index].address,
            guard.table[index].content,
            guard.table[index].flags,
        ))
    } else {
        None
    }
}

/// List all active breakpoints
pub fn kd_list_breakpoints() -> Vec<(u32, usize, bool)> {
    let state = get_bp_state();
    let guard = state.lock();

    let mut result = Vec::new();

    for (index, bp) in guard.table.iter().enumerate() {
        if bp.is_in_use() {
            result.push((
                (index + 1) as u32,
                bp.address,
                bp.is_suspended(),
            ));
        }
    }

    result
}

/// Get breakpoint statistics
pub fn kd_breakpoint_get_stats() -> (u64, u64, u64) {
    (
        BREAKPOINTS_SET.load(Ordering::Relaxed),
        BREAKPOINTS_HIT.load(Ordering::Relaxed),
        BREAKPOINTS_CLEARED.load(Ordering::Relaxed),
    )
}

/// Set owed breakpoints (deferred writes for paged-out memory)
pub fn kd_set_owed_breakpoints() {
    let state = get_bp_state();
    let mut guard = state.lock();

    if !guard.owe_breakpoint {
        return;
    }

    guard.owe_breakpoint = false;

    for index in 0..BREAKPOINT_TABLE_SIZE {
        let bp = &mut guard.table[index];

        if bp.needs_write() || bp.needs_replace() {
            // Try to write/restore the breakpoint
            // In real implementation, check if page is now accessible
            // and write the breakpoint instruction or restore content

            // For now, assume success
            if bp.needs_write() {
                bp.flags &= !breakpoint_flags::KD_BREAKPOINT_NEEDS_WRITE;
                crate::serial_println!("[KD] Deferred breakpoint {} written", index + 1);
            } else if bp.needs_replace() {
                bp.flags = 0;
                crate::serial_println!("[KD] Deferred breakpoint {} replaced", index + 1);
            }
        }
    }
}
