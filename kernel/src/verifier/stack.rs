//! Stack Verification
//!
//! Provides stack checking functionality for driver verification:
//! - Stack overflow detection
//! - Stack watermarking for usage tracking
//! - Kernel stack seeding for uninitialized variable detection
//!
//! Based on Windows Server 2003 base/ntos/verifier/vfstack.c

use super::{vf_is_option_enabled, vf_report_violation, VerifierBugcheck, VerifierOptions};
use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

extern crate alloc;

/// Stack watermark pattern (used to detect stack usage)
pub const STACK_WATERMARK_PATTERN: u64 = 0xBAADF00DBAADF00D;

/// Stack seed pattern (used to detect uninitialized variables)
pub const STACK_SEED_PATTERN: u8 = 0xCD;

/// Kernel stack size (typical)
pub const KERNEL_STACK_SIZE: usize = 0x6000; // 24KB

/// Danger zone threshold (bytes from end of stack before warning)
pub const STACK_DANGER_ZONE: usize = 0x1000; // 4KB

/// Stack tracking entry
#[derive(Debug, Clone)]
pub struct TrackedStack {
    /// Stack base address (high address)
    pub stack_base: usize,
    /// Stack limit address (low address)
    pub stack_limit: usize,
    /// Current stack pointer
    pub current_sp: usize,
    /// Maximum stack usage observed
    pub max_usage: usize,
    /// Thread associated with this stack
    pub thread_id: usize,
    /// Driver name
    pub driver_name: [u8; 32],
    /// Seeded flag
    pub is_seeded: bool,
    /// Watermarked flag
    pub is_watermarked: bool,
}

impl TrackedStack {
    /// Get current stack usage
    pub fn current_usage(&self) -> usize {
        if self.current_sp >= self.stack_limit && self.current_sp <= self.stack_base {
            self.stack_base.saturating_sub(self.current_sp)
        } else {
            0
        }
    }

    /// Get stack remaining
    pub fn remaining(&self) -> usize {
        if self.current_sp >= self.stack_limit && self.current_sp <= self.stack_base {
            self.current_sp.saturating_sub(self.stack_limit)
        } else {
            0
        }
    }

    /// Check if in danger zone
    pub fn in_danger_zone(&self) -> bool {
        self.remaining() < STACK_DANGER_ZONE
    }
}

/// Stack verifier state
#[derive(Debug)]
pub struct StackVerifierState {
    /// Tracked stacks by thread ID
    tracked_stacks: BTreeMap<usize, TrackedStack>,
    /// Total stacks tracked
    pub total_stacks: u64,
    /// Stack overflow warnings issued
    pub overflow_warnings: u64,
    /// Stacks in danger zone
    pub stacks_in_danger: u64,
}

impl StackVerifierState {
    pub const fn new() -> Self {
        Self {
            tracked_stacks: BTreeMap::new(),
            total_stacks: 0,
            overflow_warnings: 0,
            stacks_in_danger: 0,
        }
    }
}

/// Global stack verifier state
static mut STACK_VERIFIER_STATE: Option<SpinLock<StackVerifierState>> = None;

/// Total stack checks performed
static STACK_CHECKS: AtomicU64 = AtomicU64::new(0);

fn get_stack_state() -> &'static SpinLock<StackVerifierState> {
    unsafe {
        STACK_VERIFIER_STATE
            .as_ref()
            .expect("Stack verifier not initialized")
    }
}

/// Initialize Stack verification
pub fn vf_stack_init() {
    unsafe {
        STACK_VERIFIER_STATE = Some(SpinLock::new(StackVerifierState::new()));
    }
    crate::serial_println!("[VERIFIER] Stack verification initialized");
}

/// Register a kernel stack for tracking
pub fn vf_stack_register(
    thread_id: usize,
    stack_base: usize,
    stack_limit: usize,
    driver_name: &str,
) {
    if !vf_is_option_enabled(VerifierOptions::SEED_STACK) {
        return;
    }

    let state = get_stack_state();
    let mut guard = state.lock();

    let mut name_buf = [0u8; 32];
    let name_bytes = driver_name.as_bytes();
    let copy_len = core::cmp::min(name_bytes.len(), 31);
    name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let tracked = TrackedStack {
        stack_base,
        stack_limit,
        current_sp: stack_base,
        max_usage: 0,
        thread_id,
        driver_name: name_buf,
        is_seeded: false,
        is_watermarked: false,
    };

    guard.tracked_stacks.insert(thread_id, tracked);
    guard.total_stacks += 1;
}

/// Unregister a kernel stack
pub fn vf_stack_unregister(thread_id: usize) {
    let state = get_stack_state();
    let mut guard = state.lock();

    guard.tracked_stacks.remove(&thread_id);
}

/// Seed a stack with pattern to detect uninitialized variable usage
pub unsafe fn vf_stack_seed(stack_limit: usize, size: usize) {
    if !vf_is_option_enabled(VerifierOptions::SEED_STACK) {
        return;
    }

    // Fill stack with seed pattern
    let ptr = stack_limit as *mut u8;
    for i in 0..size {
        ptr.add(i).write_volatile(STACK_SEED_PATTERN);
    }
}

/// Watermark a stack with pattern to track usage
pub unsafe fn vf_stack_watermark(stack_limit: usize, size: usize) {
    // Fill with watermark pattern (64-bit aligned)
    let ptr = stack_limit as *mut u64;
    let count = size / 8;
    for i in 0..count {
        ptr.add(i).write_volatile(STACK_WATERMARK_PATTERN);
    }
}

/// Check stack watermark to determine usage
pub unsafe fn vf_stack_check_watermark(
    stack_limit: usize,
    stack_base: usize,
) -> usize {
    let ptr = stack_limit as *const u64;
    let count = (stack_base - stack_limit) / 8;

    // Find first non-watermark value (indicates stack usage)
    for i in 0..count {
        let val = ptr.add(i).read_volatile();
        if val != STACK_WATERMARK_PATTERN {
            // Stack usage starts here
            let usage_start = stack_limit + (i * 8);
            return stack_base.saturating_sub(usage_start);
        }
    }

    // No usage detected
    0
}

/// Update stack pointer for a thread
pub fn vf_stack_update_sp(thread_id: usize, current_sp: usize, driver_name: &str) {
    if !vf_is_option_enabled(VerifierOptions::SEED_STACK) {
        return;
    }

    STACK_CHECKS.fetch_add(1, Ordering::Relaxed);

    let state = get_stack_state();
    let mut guard = state.lock();

    // Extract info first to avoid multiple mutable borrows
    let stack_info = guard.tracked_stacks.get_mut(&thread_id).map(|stack| {
        stack.current_sp = current_sp;

        let usage = stack.current_usage();
        if usage > stack.max_usage {
            stack.max_usage = usage;
        }

        let in_danger = stack.in_danger_zone();
        let remaining = stack.remaining();
        let is_overflow = current_sp < stack.stack_limit;
        let stack_limit = stack.stack_limit;
        let stack_base = stack.stack_base;

        (in_danger, remaining, is_overflow, stack_limit, stack_base)
    });

    // Now update counters and report
    if let Some((in_danger, remaining, is_overflow, stack_limit, stack_base)) = stack_info {
        if in_danger {
            guard.stacks_in_danger += 1;
            crate::serial_println!(
                "[VERIFIER] Stack danger zone! Thread {} has only {} bytes remaining in {}",
                thread_id,
                remaining,
                driver_name
            );
        }

        if is_overflow {
            guard.overflow_warnings += 1;
            // Drop guard before calling external function
            drop(guard);
            vf_report_violation(
                VerifierBugcheck::DriverOverranStackBuffer,
                driver_name,
                thread_id,
                current_sp,
                stack_limit,
                stack_base,
            );
        }
    }
}

/// Get stack statistics for a thread
pub fn vf_stack_get_thread_stats(thread_id: usize) -> Option<(usize, usize, usize)> {
    let state = get_stack_state();
    let guard = state.lock();

    guard.tracked_stacks.get(&thread_id).map(|stack| {
        (stack.current_usage(), stack.max_usage, stack.remaining())
    })
}

/// Get overall stack verification statistics
pub fn vf_stack_get_stats() -> (u64, u64, u64, u64) {
    let state = get_stack_state();
    let guard = state.lock();

    (
        guard.total_stacks,
        STACK_CHECKS.load(Ordering::Relaxed),
        guard.overflow_warnings,
        guard.stacks_in_danger,
    )
}

/// Get all tracked stacks info
pub fn vf_stack_get_all() -> Vec<(usize, usize, usize, usize)> {
    let state = get_stack_state();
    let guard = state.lock();

    guard.tracked_stacks.values()
        .map(|s| (s.thread_id, s.current_usage(), s.max_usage, s.remaining()))
        .collect()
}

/// Check if a stack is being tracked
pub fn vf_stack_is_tracked(thread_id: usize) -> bool {
    let state = get_stack_state();
    let guard = state.lock();

    guard.tracked_stacks.contains_key(&thread_id)
}

/// Force a stack usage check on all tracked stacks
pub fn vf_stack_audit_all() -> usize {
    let state = get_stack_state();
    let guard = state.lock();

    let mut danger_count = 0;

    for stack in guard.tracked_stacks.values() {
        if stack.in_danger_zone() {
            danger_count += 1;
            crate::serial_println!(
                "[VERIFIER] Stack audit: Thread {} in danger zone ({} bytes remaining)",
                stack.thread_id,
                stack.remaining()
            );
        }
    }

    danger_count
}
