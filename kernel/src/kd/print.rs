//! Debug Print Buffer
//!
//! Provides debug print buffer management:
//! - Circular buffer for debug output
//! - DbgPrint support
//! - Component-based filtering
//!
//! Based on Windows Server 2003 base/ntos/kd64/kdinit.c (print buffer functions)

use crate::ke::SpinLock;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

extern crate alloc;

/// Default print buffer size
pub const KDPRINT_DEFAULT_BUFFER_SIZE: usize = 0x8000; // 32KB

/// Maximum print buffer size (16MB)
pub const KDPRINT_MAX_BUFFER_SIZE: usize = 0x1000000;

/// Print level masks
pub mod print_level {
    /// Error level - always shown
    pub const DPFLTR_ERROR_LEVEL: u32 = 0;
    /// Warning level
    pub const DPFLTR_WARNING_LEVEL: u32 = 1;
    /// Trace level
    pub const DPFLTR_TRACE_LEVEL: u32 = 2;
    /// Info level
    pub const DPFLTR_INFO_LEVEL: u32 = 3;
    /// Mask for all levels
    pub const DPFLTR_MASK: u32 = 0x80000000;
}

/// Debug print entry
#[derive(Debug, Clone)]
pub struct PrintEntry {
    /// Timestamp
    pub timestamp: u64,
    /// Component ID
    pub component_id: u32,
    /// Level
    pub level: u32,
    /// Message
    pub message: String,
}

/// Print buffer state
#[derive(Debug)]
pub struct PrintBufferState {
    /// Circular buffer for messages
    buffer: VecDeque<PrintEntry>,
    /// Maximum buffer entries
    max_entries: usize,
    /// Current buffer size in bytes
    current_size: usize,
    /// Maximum buffer size in bytes
    max_size: usize,
    /// Rollover count
    pub rollover_count: u64,
    /// Buffer changes count
    pub buffer_changes: u64,
    /// Component filter masks (one per component)
    component_filters: [u32; 128],
    /// Default filter mask
    default_filter: u32,
}

impl PrintBufferState {
    pub const fn new() -> Self {
        Self {
            buffer: VecDeque::new(),
            max_entries: 1000,
            current_size: 0,
            max_size: KDPRINT_DEFAULT_BUFFER_SIZE,
            rollover_count: 0,
            buffer_changes: 0,
            component_filters: [1u32; 128], // Default: only errors
            default_filter: 1, // Errors only
        }
    }
}

/// Global print buffer state
static mut PRINT_BUFFER_STATE: Option<SpinLock<PrintBufferState>> = None;

/// Statistics
static MESSAGES_LOGGED: AtomicU64 = AtomicU64::new(0);
static MESSAGES_DROPPED: AtomicU64 = AtomicU64::new(0);
static MESSAGES_FILTERED: AtomicU64 = AtomicU64::new(0);

fn get_print_state() -> &'static SpinLock<PrintBufferState> {
    unsafe {
        PRINT_BUFFER_STATE
            .as_ref()
            .expect("Print buffer not initialized")
    }
}

/// Initialize print buffer subsystem
pub fn kd_print_init() {
    unsafe {
        PRINT_BUFFER_STATE = Some(SpinLock::new(PrintBufferState::new()));
    }
    crate::serial_println!("[KD] Print buffer initialized ({}KB)", KDPRINT_DEFAULT_BUFFER_SIZE / 1024);
}

/// Log a debug print message
pub fn kd_log_dbg_print(component_id: u32, level: u32, message: &str) {
    let state = get_print_state();
    let mut guard = state.lock();

    // Check filter
    let filter_index = (component_id as usize).min(127);
    let filter_mask = guard.component_filters[filter_index];

    // Level 0 (error) always passes, otherwise check mask
    if level > 0 {
        let level_bit = 1u32 << level;
        if (filter_mask & level_bit) == 0 {
            MESSAGES_FILTERED.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }

    let entry = PrintEntry {
        timestamp: unsafe { core::arch::x86_64::_rdtsc() },
        component_id,
        level,
        message: String::from(message),
    };

    let msg_size = message.len();

    // Check if we need to make room
    while guard.current_size + msg_size > guard.max_size && !guard.buffer.is_empty() {
        if let Some(old) = guard.buffer.pop_front() {
            guard.current_size = guard.current_size.saturating_sub(old.message.len());
            guard.rollover_count += 1;
        }
    }

    if guard.buffer.len() >= guard.max_entries {
        if let Some(old) = guard.buffer.pop_front() {
            guard.current_size = guard.current_size.saturating_sub(old.message.len());
            guard.rollover_count += 1;
        }
    }

    guard.current_size += msg_size;
    guard.buffer.push_back(entry);

    MESSAGES_LOGGED.fetch_add(1, Ordering::Relaxed);
}

/// Set print buffer size
pub fn kd_set_dbg_print_buffer_size(size: usize) -> Result<(), &'static str> {
    if size > KDPRINT_MAX_BUFFER_SIZE {
        return Err("Buffer size too large");
    }

    let state = get_print_state();
    let mut guard = state.lock();

    let new_size = if size == 0 {
        KDPRINT_DEFAULT_BUFFER_SIZE
    } else {
        size
    };

    guard.max_size = new_size;
    guard.buffer_changes += 1;

    // Trim buffer if needed
    while guard.current_size > new_size && !guard.buffer.is_empty() {
        if let Some(old) = guard.buffer.pop_front() {
            guard.current_size = guard.current_size.saturating_sub(old.message.len());
        }
    }

    crate::serial_println!("[KD] Print buffer resized to {} bytes", new_size);

    Ok(())
}

/// Set component filter mask
pub fn kd_set_component_filter(component_id: u32, mask: u32) {
    let state = get_print_state();
    let mut guard = state.lock();

    let filter_index = (component_id as usize).min(127);
    guard.component_filters[filter_index] = mask;

    crate::serial_println!(
        "[KD] Component {} filter set to {:#x}",
        component_id,
        mask
    );
}

/// Get component filter mask
pub fn kd_get_component_filter(component_id: u32) -> u32 {
    let state = get_print_state();
    let guard = state.lock();

    let filter_index = (component_id as usize).min(127);
    guard.component_filters[filter_index]
}

/// Set default filter mask
pub fn kd_set_default_filter(mask: u32) {
    let state = get_print_state();
    let mut guard = state.lock();

    guard.default_filter = mask;

    // Apply to all components
    for filter in &mut guard.component_filters {
        *filter = mask;
    }

    crate::serial_println!("[KD] Default filter set to {:#x}", mask);
}

/// Clear the print buffer
pub fn kd_clear_print_buffer() {
    let state = get_print_state();
    let mut guard = state.lock();

    guard.buffer.clear();
    guard.current_size = 0;
    guard.buffer_changes += 1;

    crate::serial_println!("[KD] Print buffer cleared");
}

/// Get print buffer contents
pub fn kd_get_print_buffer(max_entries: usize) -> Vec<PrintEntry> {
    let state = get_print_state();
    let guard = state.lock();

    let count = max_entries.min(guard.buffer.len());
    guard.buffer.iter().rev().take(count).cloned().collect()
}

/// Get print buffer size info
pub fn kd_get_print_buffer_info() -> (usize, usize, u64, u64) {
    let state = get_print_state();
    let guard = state.lock();

    (
        guard.current_size,
        guard.max_size,
        guard.rollover_count,
        guard.buffer_changes,
    )
}

/// Get print statistics
pub fn kd_print_get_stats() -> (u64, u64, u64) {
    (
        MESSAGES_LOGGED.load(Ordering::Relaxed),
        MESSAGES_DROPPED.load(Ordering::Relaxed),
        MESSAGES_FILTERED.load(Ordering::Relaxed),
    )
}

/// DbgPrint equivalent
pub fn dbg_print(message: &str) {
    kd_log_dbg_print(0, 0, message);
    // Also output to serial for immediate visibility
    crate::serial_println!("[DbgPrint] {}", message);
}

/// DbgPrintEx equivalent with component and level
pub fn dbg_print_ex(component_id: u32, level: u32, message: &str) {
    kd_log_dbg_print(component_id, level, message);

    // Output to serial if level passes
    if level == 0 {
        crate::serial_println!("[DbgPrint:{}:{}] {}", component_id, level, message);
    }
}

/// Format level name
pub fn level_name(level: u32) -> &'static str {
    match level {
        print_level::DPFLTR_ERROR_LEVEL => "ERROR",
        print_level::DPFLTR_WARNING_LEVEL => "WARN",
        print_level::DPFLTR_TRACE_LEVEL => "TRACE",
        print_level::DPFLTR_INFO_LEVEL => "INFO",
        _ => "UNKNOWN",
    }
}
