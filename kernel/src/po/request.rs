//! Power Request Support
//!
//! Provides power request management to prevent system sleep/display off.
//!
//! Applications and drivers can create power requests to indicate they need
//! the system to remain active. This is used for:
//! - Media playback (prevent display off)
//! - File transfers (prevent system sleep)
//! - Presentations (prevent screen saver)
//!
//! # NT Functions
//!
//! - `PoCreatePowerRequest` - Create a power request handle
//! - `PoSetPowerRequest` - Set a power request type active
//! - `PoClearPowerRequest` - Clear a power request type
//! - `PoDeletePowerRequest` - Delete a power request handle
//!
//! # Request Types
//!
//! - **SystemRequired**: Prevent system sleep
//! - **DisplayRequired**: Prevent display off
//! - **AwayModeRequired**: Keep system running in "away mode"
//! - **ExecutionRequired**: Keep process running (for UWP)

use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;

/// Maximum number of power requests
pub const MAX_POWER_REQUESTS: usize = 128;

/// Power request types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerRequestType {
    /// Prevent the system from going to sleep
    SystemRequired = 0,
    /// Prevent the display from turning off
    DisplayRequired = 1,
    /// Allow away mode (system appears off but running)
    AwayModeRequired = 2,
    /// Keep execution active (prevents app suspension)
    ExecutionRequired = 3,
}

impl PowerRequestType {
    /// Convert from u32
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::SystemRequired),
            1 => Some(Self::DisplayRequired),
            2 => Some(Self::AwayModeRequired),
            3 => Some(Self::ExecutionRequired),
            _ => None,
        }
    }
}

/// Power request reason context
#[derive(Debug, Clone)]
pub struct PowerRequestContext {
    /// Version (should be 0)
    pub version: u32,
    /// Flags
    pub flags: u32,
    /// Simple reason string (truncated if needed)
    pub reason: [u8; 64],
    /// Reason length
    pub reason_len: usize,
}

impl Default for PowerRequestContext {
    fn default() -> Self {
        Self {
            version: 0,
            flags: 0,
            reason: [0; 64],
            reason_len: 0,
        }
    }
}

impl PowerRequestContext {
    /// Create a new context with a reason string
    pub fn with_reason(reason: &str) -> Self {
        let mut ctx = Self::default();
        let bytes = reason.as_bytes();
        let len = bytes.len().min(63);
        ctx.reason[..len].copy_from_slice(&bytes[..len]);
        ctx.reason_len = len;
        ctx
    }

    /// Get reason as string slice
    pub fn reason_str(&self) -> &str {
        core::str::from_utf8(&self.reason[..self.reason_len]).unwrap_or("")
    }
}

/// Power request entry
#[derive(Debug)]
pub struct PowerRequest {
    /// Request is allocated
    pub allocated: AtomicBool,
    /// Request ID
    pub id: u32,
    /// Owner process (EPROCESS pointer)
    pub owner_process: usize,
    /// Active request types (bitmap)
    pub active_types: AtomicU32,
    /// Reason context
    pub context: PowerRequestContext,
    /// Reference count
    pub ref_count: AtomicU32,
}

impl PowerRequest {
    pub const fn new(id: u32) -> Self {
        Self {
            allocated: AtomicBool::new(false),
            id,
            owner_process: 0,
            active_types: AtomicU32::new(0),
            context: PowerRequestContext {
                version: 0,
                flags: 0,
                reason: [0; 64],
                reason_len: 0,
            },
            ref_count: AtomicU32::new(0),
        }
    }

    /// Check if a request type is active
    pub fn is_type_active(&self, request_type: PowerRequestType) -> bool {
        let mask = 1u32 << (request_type as u32);
        (self.active_types.load(Ordering::Acquire) & mask) != 0
    }

    /// Set a request type active
    pub fn set_type(&self, request_type: PowerRequestType) -> bool {
        let mask = 1u32 << (request_type as u32);
        let old = self.active_types.fetch_or(mask, Ordering::AcqRel);
        (old & mask) == 0 // Return true if newly set
    }

    /// Clear a request type
    pub fn clear_type(&self, request_type: PowerRequestType) -> bool {
        let mask = 1u32 << (request_type as u32);
        let old = self.active_types.fetch_and(!mask, Ordering::AcqRel);
        (old & mask) != 0 // Return true if was previously set
    }

    /// Get all active types as bitmap
    pub fn get_active_types(&self) -> u32 {
        self.active_types.load(Ordering::Acquire)
    }
}

// ============================================================================
// Global Power Request Table
// ============================================================================

static mut POWER_REQUESTS: [PowerRequest; MAX_POWER_REQUESTS] = {
    const INIT: PowerRequest = PowerRequest::new(0);
    let mut requests = [INIT; MAX_POWER_REQUESTS];
    let mut i = 0;
    while i < MAX_POWER_REQUESTS {
        requests[i] = PowerRequest::new(i as u32);
        i += 1;
    }
    requests
};

static POWER_REQUEST_LOCK: SpinLock<()> = SpinLock::new(());
static POWER_REQUEST_INITIALIZED: AtomicBool = AtomicBool::new(false);

// Active request counts per type
static SYSTEM_REQUIRED_COUNT: AtomicU32 = AtomicU32::new(0);
static DISPLAY_REQUIRED_COUNT: AtomicU32 = AtomicU32::new(0);
static AWAY_MODE_COUNT: AtomicU32 = AtomicU32::new(0);
static EXECUTION_REQUIRED_COUNT: AtomicU32 = AtomicU32::new(0);

// Statistics
static REQUESTS_CREATED: AtomicU32 = AtomicU32::new(0);
static REQUESTS_DELETED: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Power Request API
// ============================================================================

/// Create a power request (PoCreatePowerRequest)
///
/// # Arguments
/// * `context` - Optional reason context
/// * `owner_process` - Owner process pointer
///
/// # Returns
/// Request handle on success, None on failure
pub fn po_create_power_request(
    context: Option<&PowerRequestContext>,
    owner_process: usize,
) -> Option<u32> {
    if !POWER_REQUEST_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let _guard = POWER_REQUEST_LOCK.lock();

    unsafe {
        for request in POWER_REQUESTS.iter_mut() {
            if !request.allocated.load(Ordering::Acquire) {
                request.allocated.store(true, Ordering::Release);
                request.owner_process = owner_process;
                request.active_types.store(0, Ordering::Release);
                request.ref_count.store(1, Ordering::Release);

                if let Some(ctx) = context {
                    request.context = ctx.clone();
                } else {
                    request.context = PowerRequestContext::default();
                }

                REQUESTS_CREATED.fetch_add(1, Ordering::Relaxed);
                return Some(request.id);
            }
        }
    }

    None
}

/// Delete a power request (PoDeletePowerRequest)
///
/// # Arguments
/// * `handle` - Power request handle
pub fn po_delete_power_request(handle: u32) {
    if handle as usize >= MAX_POWER_REQUESTS {
        return;
    }

    let _guard = POWER_REQUEST_LOCK.lock();

    unsafe {
        let request = &mut POWER_REQUESTS[handle as usize];
        if request.allocated.load(Ordering::Acquire) {
            // Clear all active types and update counts
            let active = request.active_types.swap(0, Ordering::AcqRel);

            if active & (1 << PowerRequestType::SystemRequired as u32) != 0 {
                SYSTEM_REQUIRED_COUNT.fetch_sub(1, Ordering::Relaxed);
            }
            if active & (1 << PowerRequestType::DisplayRequired as u32) != 0 {
                DISPLAY_REQUIRED_COUNT.fetch_sub(1, Ordering::Relaxed);
            }
            if active & (1 << PowerRequestType::AwayModeRequired as u32) != 0 {
                AWAY_MODE_COUNT.fetch_sub(1, Ordering::Relaxed);
            }
            if active & (1 << PowerRequestType::ExecutionRequired as u32) != 0 {
                EXECUTION_REQUIRED_COUNT.fetch_sub(1, Ordering::Relaxed);
            }

            request.allocated.store(false, Ordering::Release);
            request.owner_process = 0;
            REQUESTS_DELETED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Set a power request type active (PoSetPowerRequest)
///
/// # Arguments
/// * `handle` - Power request handle
/// * `request_type` - Type of request to set
///
/// # Returns
/// Ok(()) on success, Err(NTSTATUS) on failure
pub fn po_set_power_request(
    handle: u32,
    request_type: PowerRequestType,
) -> Result<(), i32> {
    if handle as usize >= MAX_POWER_REQUESTS {
        return Err(-1073741811); // STATUS_INVALID_PARAMETER
    }

    let _guard = POWER_REQUEST_LOCK.lock();

    unsafe {
        let request = &POWER_REQUESTS[handle as usize];
        if !request.allocated.load(Ordering::Acquire) {
            return Err(-1073741816); // STATUS_INVALID_HANDLE
        }

        if request.set_type(request_type) {
            // Increment global count for this type
            match request_type {
                PowerRequestType::SystemRequired => {
                    SYSTEM_REQUIRED_COUNT.fetch_add(1, Ordering::Relaxed);
                }
                PowerRequestType::DisplayRequired => {
                    DISPLAY_REQUIRED_COUNT.fetch_add(1, Ordering::Relaxed);
                }
                PowerRequestType::AwayModeRequired => {
                    AWAY_MODE_COUNT.fetch_add(1, Ordering::Relaxed);
                }
                PowerRequestType::ExecutionRequired => {
                    EXECUTION_REQUIRED_COUNT.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        Ok(())
    }
}

/// Clear a power request type (PoClearPowerRequest)
///
/// # Arguments
/// * `handle` - Power request handle
/// * `request_type` - Type of request to clear
///
/// # Returns
/// Ok(()) on success, Err(NTSTATUS) on failure
pub fn po_clear_power_request(
    handle: u32,
    request_type: PowerRequestType,
) -> Result<(), i32> {
    if handle as usize >= MAX_POWER_REQUESTS {
        return Err(-1073741811); // STATUS_INVALID_PARAMETER
    }

    let _guard = POWER_REQUEST_LOCK.lock();

    unsafe {
        let request = &POWER_REQUESTS[handle as usize];
        if !request.allocated.load(Ordering::Acquire) {
            return Err(-1073741816); // STATUS_INVALID_HANDLE
        }

        if request.clear_type(request_type) {
            // Decrement global count for this type
            match request_type {
                PowerRequestType::SystemRequired => {
                    SYSTEM_REQUIRED_COUNT.fetch_sub(1, Ordering::Relaxed);
                }
                PowerRequestType::DisplayRequired => {
                    DISPLAY_REQUIRED_COUNT.fetch_sub(1, Ordering::Relaxed);
                }
                PowerRequestType::AwayModeRequired => {
                    AWAY_MODE_COUNT.fetch_sub(1, Ordering::Relaxed);
                }
                PowerRequestType::ExecutionRequired => {
                    EXECUTION_REQUIRED_COUNT.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Query Functions
// ============================================================================

/// Check if system sleep is blocked by any power request
pub fn is_system_sleep_blocked() -> bool {
    SYSTEM_REQUIRED_COUNT.load(Ordering::Relaxed) > 0
}

/// Check if display off is blocked by any power request
pub fn is_display_off_blocked() -> bool {
    DISPLAY_REQUIRED_COUNT.load(Ordering::Relaxed) > 0
}

/// Check if away mode is requested
pub fn is_away_mode_requested() -> bool {
    AWAY_MODE_COUNT.load(Ordering::Relaxed) > 0
}

/// Check if execution required is active
pub fn is_execution_required() -> bool {
    EXECUTION_REQUIRED_COUNT.load(Ordering::Relaxed) > 0
}

/// Get count of active requests for a type
pub fn get_request_count(request_type: PowerRequestType) -> u32 {
    match request_type {
        PowerRequestType::SystemRequired => SYSTEM_REQUIRED_COUNT.load(Ordering::Relaxed),
        PowerRequestType::DisplayRequired => DISPLAY_REQUIRED_COUNT.load(Ordering::Relaxed),
        PowerRequestType::AwayModeRequired => AWAY_MODE_COUNT.load(Ordering::Relaxed),
        PowerRequestType::ExecutionRequired => EXECUTION_REQUIRED_COUNT.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize power request support
pub fn init() {
    let _guard = POWER_REQUEST_LOCK.lock();

    unsafe {
        for (i, request) in POWER_REQUESTS.iter_mut().enumerate() {
            *request = PowerRequest::new(i as u32);
        }
    }

    SYSTEM_REQUIRED_COUNT.store(0, Ordering::Relaxed);
    DISPLAY_REQUIRED_COUNT.store(0, Ordering::Relaxed);
    AWAY_MODE_COUNT.store(0, Ordering::Relaxed);
    EXECUTION_REQUIRED_COUNT.store(0, Ordering::Relaxed);
    REQUESTS_CREATED.store(0, Ordering::Relaxed);
    REQUESTS_DELETED.store(0, Ordering::Relaxed);

    POWER_REQUEST_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[PO] Power request support initialized");
}

// ============================================================================
// Statistics and Inspection
// ============================================================================

/// Power request statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct PowerRequestStats {
    /// Total requests created
    pub requests_created: u32,
    /// Total requests deleted
    pub requests_deleted: u32,
    /// Current active requests
    pub active_requests: u32,
    /// System required count
    pub system_required_count: u32,
    /// Display required count
    pub display_required_count: u32,
    /// Away mode count
    pub away_mode_count: u32,
    /// Execution required count
    pub execution_required_count: u32,
}

/// Get power request statistics
pub fn get_power_request_stats() -> PowerRequestStats {
    let created = REQUESTS_CREATED.load(Ordering::Relaxed);
    let deleted = REQUESTS_DELETED.load(Ordering::Relaxed);

    PowerRequestStats {
        requests_created: created,
        requests_deleted: deleted,
        active_requests: created.saturating_sub(deleted),
        system_required_count: SYSTEM_REQUIRED_COUNT.load(Ordering::Relaxed),
        display_required_count: DISPLAY_REQUIRED_COUNT.load(Ordering::Relaxed),
        away_mode_count: AWAY_MODE_COUNT.load(Ordering::Relaxed),
        execution_required_count: EXECUTION_REQUIRED_COUNT.load(Ordering::Relaxed),
    }
}

/// Power request snapshot for inspection
#[derive(Debug, Clone)]
pub struct PowerRequestSnapshot {
    /// Request ID
    pub id: u32,
    /// Owner process
    pub owner_process: usize,
    /// Active types bitmap
    pub active_types: u32,
    /// Reason string
    pub reason: [u8; 64],
    /// Reason length
    pub reason_len: usize,
}

/// Get all active power request snapshots
pub fn get_power_request_snapshots() -> [Option<PowerRequestSnapshot>; MAX_POWER_REQUESTS] {
    let mut snapshots = core::array::from_fn(|_| None);

    let _guard = POWER_REQUEST_LOCK.lock();

    unsafe {
        for (i, request) in POWER_REQUESTS.iter().enumerate() {
            if request.allocated.load(Ordering::Relaxed) {
                snapshots[i] = Some(PowerRequestSnapshot {
                    id: request.id,
                    owner_process: request.owner_process,
                    active_types: request.active_types.load(Ordering::Relaxed),
                    reason: request.context.reason,
                    reason_len: request.context.reason_len,
                });
            }
        }
    }

    snapshots
}

/// Get count of allocated power requests
pub fn get_power_request_count() -> u32 {
    let created = REQUESTS_CREATED.load(Ordering::Relaxed);
    let deleted = REQUESTS_DELETED.load(Ordering::Relaxed);
    created.saturating_sub(deleted)
}
