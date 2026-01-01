//! Device Idle Detection
//!
//! This module implements automatic device power state transitions based on
//! activity monitoring. Devices register for idle detection and are automatically
//! transitioned to low-power states when idle.
//!
//! # Design
//!
//! - Devices register with conservation and performance idle timeouts
//! - Activity is reported via device_busy() calls
//! - Periodic tick updates idle counters
//! - When timeout expires, device power state is changed
//!
//! # Idle Timeouts
//!
//! - Conservation timeout: Used when system is on battery power (aggressive saving)
//! - Performance timeout: Used when on AC power (less aggressive)
//!
//! # NT API
//!
//! - PoRegisterDeviceForIdleDetection
//! - PoUnregisterDeviceForIdleDetection
//! - PoSetDeviceBusy

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::{DevicePowerState, is_ac_power};

/// Maximum number of devices registered for idle detection
pub const MAX_IDLE_DEVICES: usize = 64;

/// Default conservation idle timeout (seconds)
pub const DEFAULT_CONSERVATION_IDLE: u32 = 30;

/// Default performance idle timeout (seconds)
pub const DEFAULT_PERFORMANCE_IDLE: u32 = 300;

/// Idle detection tick interval (100ns units, 1 second)
pub const IDLE_TICK_INTERVAL: u64 = 10_000_000;

/// Device idle detection entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IdleDeviceEntry {
    /// Device object pointer (0 = unused entry)
    pub device: usize,
    /// Handle assigned to this entry
    pub handle: u32,
    /// Current idle counter (seconds)
    pub idle_count: u32,
    /// Conservation idle timeout (seconds, for battery)
    pub conservation_timeout: u32,
    /// Performance idle timeout (seconds, for AC)
    pub performance_timeout: u32,
    /// Current power state
    pub power_state: DevicePowerState,
    /// Target idle power state
    pub idle_power_state: DevicePowerState,
    /// Is device currently idle?
    pub is_idle: bool,
    /// Is entry active?
    pub active: bool,
    /// Device can wake the system
    pub wake_capable: bool,
    /// Last activity timestamp
    pub last_activity: u64,
}

impl IdleDeviceEntry {
    pub const fn new() -> Self {
        Self {
            device: 0,
            handle: 0,
            idle_count: 0,
            conservation_timeout: DEFAULT_CONSERVATION_IDLE,
            performance_timeout: DEFAULT_PERFORMANCE_IDLE,
            power_state: DevicePowerState::D0,
            idle_power_state: DevicePowerState::D3,
            is_idle: false,
            active: false,
            wake_capable: false,
            last_activity: 0,
        }
    }

    /// Get the effective timeout based on power source
    pub fn effective_timeout(&self) -> u32 {
        if is_ac_power() {
            self.performance_timeout
        } else {
            self.conservation_timeout
        }
    }

    /// Reset idle counter (device became busy)
    pub fn reset_idle(&mut self) {
        self.idle_count = 0;
        self.is_idle = false;
        if self.power_state != DevicePowerState::D0 {
            // Request power up
            self.power_state = DevicePowerState::D0;
        }
    }

    /// Increment idle counter
    pub fn tick(&mut self) {
        if !self.is_idle && self.power_state == DevicePowerState::D0 {
            self.idle_count = self.idle_count.saturating_add(1);

            if self.idle_count >= self.effective_timeout() {
                self.is_idle = true;
                self.power_state = self.idle_power_state;
            }
        }
    }
}

impl Default for IdleDeviceEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Idle device pool
static mut IDLE_DEVICES: [IdleDeviceEntry; MAX_IDLE_DEVICES] = {
    const INIT: IdleDeviceEntry = IdleDeviceEntry::new();
    [INIT; MAX_IDLE_DEVICES]
};

/// Next handle to allocate
static NEXT_IDLE_HANDLE: AtomicU32 = AtomicU32::new(1);

/// Idle detection enabled
static IDLE_DETECTION_ENABLED: AtomicBool = AtomicBool::new(true);

/// Lock for idle device operations
static IDLE_LOCK: SpinLock<()> = SpinLock::new(());

/// Idle detection statistics
static mut IDLE_STATS: IdleStats = IdleStats::new();

/// Idle detection statistics
#[derive(Debug, Clone, Copy)]
pub struct IdleStats {
    /// Total devices registered
    pub registered_devices: u32,
    /// Current idle devices
    pub idle_devices: u32,
    /// Total idle transitions
    pub idle_transitions: u64,
    /// Total busy transitions
    pub busy_transitions: u64,
    /// Total power savings (estimated mWh)
    pub power_savings_mwh: u64,
    /// Total ticks processed
    pub ticks_processed: u64,
}

impl IdleStats {
    pub const fn new() -> Self {
        Self {
            registered_devices: 0,
            idle_devices: 0,
            idle_transitions: 0,
            busy_transitions: 0,
            power_savings_mwh: 0,
            ticks_processed: 0,
        }
    }
}

impl Default for IdleStats {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Idle Detection API
// ============================================================================

/// Register a device for idle detection
///
/// Returns a handle to be used with other idle detection APIs.
pub fn po_register_device_for_idle_detection(
    device: usize,
    conservation_timeout: u32,
    performance_timeout: u32,
    idle_power_state: DevicePowerState,
) -> Option<u32> {
    if device == 0 {
        return None;
    }

    let _guard = IDLE_LOCK.lock();

    unsafe {
        // Find a free slot
        for entry in IDLE_DEVICES.iter_mut() {
            if !entry.active {
                let handle = NEXT_IDLE_HANDLE.fetch_add(1, Ordering::SeqCst);

                entry.device = device;
                entry.handle = handle;
                entry.idle_count = 0;
                entry.conservation_timeout = if conservation_timeout > 0 {
                    conservation_timeout
                } else {
                    DEFAULT_CONSERVATION_IDLE
                };
                entry.performance_timeout = if performance_timeout > 0 {
                    performance_timeout
                } else {
                    DEFAULT_PERFORMANCE_IDLE
                };
                entry.power_state = DevicePowerState::D0;
                entry.idle_power_state = idle_power_state;
                entry.is_idle = false;
                entry.active = true;
                entry.wake_capable = false;
                entry.last_activity = 0;

                IDLE_STATS.registered_devices += 1;

                crate::serial_println!(
                    "[PO] Idle detection registered for device {:#x} (handle={}, cons={}s, perf={}s)",
                    device, handle, entry.conservation_timeout, entry.performance_timeout
                );

                return Some(handle);
            }
        }
    }

    None // No free slots
}

/// Unregister a device from idle detection
pub fn po_unregister_device_for_idle_detection(handle: u32) -> bool {
    let _guard = IDLE_LOCK.lock();

    unsafe {
        for entry in IDLE_DEVICES.iter_mut() {
            if entry.active && entry.handle == handle {
                let was_idle = entry.is_idle;
                entry.active = false;
                entry.device = 0;

                IDLE_STATS.registered_devices = IDLE_STATS.registered_devices.saturating_sub(1);
                if was_idle {
                    IDLE_STATS.idle_devices = IDLE_STATS.idle_devices.saturating_sub(1);
                }

                return true;
            }
        }
    }

    false
}

/// Report that a device is busy (reset idle timer)
///
/// This should be called whenever the device performs I/O or other activity.
pub fn po_set_device_busy(handle: u32) {
    let _guard = IDLE_LOCK.lock();

    unsafe {
        for entry in IDLE_DEVICES.iter_mut() {
            if entry.active && entry.handle == handle {
                let was_idle = entry.is_idle;
                entry.reset_idle();

                if was_idle {
                    IDLE_STATS.idle_devices = IDLE_STATS.idle_devices.saturating_sub(1);
                    IDLE_STATS.busy_transitions += 1;
                }

                return;
            }
        }
    }
}

/// Report that a device is busy by device pointer
pub fn po_set_device_busy_by_ptr(device: usize) {
    let _guard = IDLE_LOCK.lock();

    unsafe {
        for entry in IDLE_DEVICES.iter_mut() {
            if entry.active && entry.device == device {
                let was_idle = entry.is_idle;
                entry.reset_idle();

                if was_idle {
                    IDLE_STATS.idle_devices = IDLE_STATS.idle_devices.saturating_sub(1);
                    IDLE_STATS.busy_transitions += 1;
                }

                return;
            }
        }
    }
}

/// Check if a device is currently idle
pub fn po_is_device_idle(handle: u32) -> bool {
    let _guard = IDLE_LOCK.lock();

    unsafe {
        for entry in IDLE_DEVICES.iter() {
            if entry.active && entry.handle == handle {
                return entry.is_idle;
            }
        }
    }

    false
}

/// Get the current power state of an idle-managed device
pub fn po_get_idle_device_power_state(handle: u32) -> Option<DevicePowerState> {
    let _guard = IDLE_LOCK.lock();

    unsafe {
        for entry in IDLE_DEVICES.iter() {
            if entry.active && entry.handle == handle {
                return Some(entry.power_state);
            }
        }
    }

    None
}

/// Set device wake capability
pub fn po_set_device_wake_capable(handle: u32, wake_capable: bool) {
    let _guard = IDLE_LOCK.lock();

    unsafe {
        for entry in IDLE_DEVICES.iter_mut() {
            if entry.active && entry.handle == handle {
                entry.wake_capable = wake_capable;
                return;
            }
        }
    }
}

/// Enable or disable idle detection globally
pub fn po_enable_idle_detection(enable: bool) {
    IDLE_DETECTION_ENABLED.store(enable, Ordering::SeqCst);

    if !enable {
        // Wake up all idle devices
        let _guard = IDLE_LOCK.lock();

        unsafe {
            for entry in IDLE_DEVICES.iter_mut() {
                if entry.active && entry.is_idle {
                    entry.reset_idle();
                    IDLE_STATS.idle_devices = IDLE_STATS.idle_devices.saturating_sub(1);
                }
            }
        }
    }

    crate::serial_println!("[PO] Idle detection {}", if enable { "enabled" } else { "disabled" });
}

/// Check if idle detection is enabled
pub fn po_is_idle_detection_enabled() -> bool {
    IDLE_DETECTION_ENABLED.load(Ordering::SeqCst)
}

// ============================================================================
// Idle Tick Processing
// ============================================================================

/// Process idle detection tick
///
/// Called periodically (typically every second) to update idle counters
/// and transition devices to low-power states.
pub unsafe fn po_idle_tick() {
    if !IDLE_DETECTION_ENABLED.load(Ordering::SeqCst) {
        return;
    }

    let _guard = IDLE_LOCK.lock();

    IDLE_STATS.ticks_processed += 1;

    for entry in IDLE_DEVICES.iter_mut() {
        if !entry.active {
            continue;
        }

        let was_idle = entry.is_idle;
        entry.tick();

        if entry.is_idle && !was_idle {
            // Device just went idle
            IDLE_STATS.idle_devices += 1;
            IDLE_STATS.idle_transitions += 1;

            // Estimate power savings (rough estimate: 100mW per idle device per hour)
            // This is a placeholder - real systems would have device-specific data
            IDLE_STATS.power_savings_mwh += 1;

            crate::serial_println!(
                "[PO] Device {:#x} (handle={}) transitioned to idle (D{:?})",
                entry.device, entry.handle, entry.power_state as u8
            );
        }
    }
}

/// Force idle scan for all devices
pub unsafe fn po_force_idle_scan() {
    if !IDLE_DETECTION_ENABLED.load(Ordering::SeqCst) {
        return;
    }

    let _guard = IDLE_LOCK.lock();

    for entry in IDLE_DEVICES.iter_mut() {
        if entry.active && !entry.is_idle && entry.power_state == DevicePowerState::D0 {
            // Force immediate idle check with current timeout
            let timeout = entry.effective_timeout();
            if entry.idle_count >= timeout / 2 {
                // If at least half the timeout has passed, go idle
                entry.is_idle = true;
                entry.power_state = entry.idle_power_state;
                IDLE_STATS.idle_devices += 1;
                IDLE_STATS.idle_transitions += 1;
            }
        }
    }
}

// ============================================================================
// Statistics and Diagnostics
// ============================================================================

/// Get idle detection statistics
pub fn po_get_idle_stats() -> IdleStats {
    unsafe { IDLE_STATS }
}

/// Get snapshot of idle devices
pub fn po_get_idle_device_snapshots() -> ([IdleDeviceSnapshot; 32], usize) {
    let mut snapshots = [IdleDeviceSnapshot::empty(); 32];
    let mut count = 0;

    let _guard = IDLE_LOCK.lock();

    unsafe {
        for entry in IDLE_DEVICES.iter() {
            if count >= 32 {
                break;
            }
            if entry.active {
                snapshots[count] = IdleDeviceSnapshot {
                    device: entry.device,
                    handle: entry.handle,
                    idle_count: entry.idle_count,
                    effective_timeout: entry.effective_timeout(),
                    power_state: entry.power_state,
                    is_idle: entry.is_idle,
                    wake_capable: entry.wake_capable,
                };
                count += 1;
            }
        }
    }

    (snapshots, count)
}

/// Idle device snapshot for diagnostics
#[derive(Debug, Clone, Copy)]
pub struct IdleDeviceSnapshot {
    pub device: usize,
    pub handle: u32,
    pub idle_count: u32,
    pub effective_timeout: u32,
    pub power_state: DevicePowerState,
    pub is_idle: bool,
    pub wake_capable: bool,
}

impl IdleDeviceSnapshot {
    pub const fn empty() -> Self {
        Self {
            device: 0,
            handle: 0,
            idle_count: 0,
            effective_timeout: 0,
            power_state: DevicePowerState::D0,
            is_idle: false,
            wake_capable: false,
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize idle detection subsystem
pub fn init() {
    unsafe {
        for entry in IDLE_DEVICES.iter_mut() {
            *entry = IdleDeviceEntry::new();
        }
        IDLE_STATS = IdleStats::new();
    }

    IDLE_DETECTION_ENABLED.store(true, Ordering::SeqCst);
    NEXT_IDLE_HANDLE.store(1, Ordering::SeqCst);

    crate::serial_println!("[PO] Idle detection subsystem initialized ({} device slots)", MAX_IDLE_DEVICES);
}
