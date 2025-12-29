//! Executive Callback Objects
//!
//! Callback objects allow kernel components to register functions that
//! are called when specific events occur. This provides a publish-subscribe
//! pattern for kernel notifications.
//!
//! # Common Use Cases
//! - Registry change notifications
//! - Power state change notifications
//! - Process/thread creation/destruction
//! - System shutdown notifications
//! - Bugcheck callbacks
//!
//! # Windows Equivalent
//! This implements NT's callback.c functionality.
//!
//! # Example
//! ```
//! // Create a callback object
//! let callback = ExCallbackObject::new("\\Callback\\MyCallback", true);
//!
//! // Register a callback function
//! let registration = callback.register(my_callback_fn, context);
//!
//! // When the event occurs, notify all registered callbacks
//! callback.notify(arg1, arg2);
//!
//! // Unregister when done
//! callback.unregister(registration);
//! ```

use crate::ke::list::ListEntry;
use crate::ke::spinlock::RawSpinLock;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

/// Maximum number of callback objects in the system
pub const MAX_CALLBACK_OBJECTS: usize = 64;

/// Maximum number of registrations per callback object
pub const MAX_REGISTRATIONS_PER_CALLBACK: usize = 32;

/// Callback function signature
///
/// # Arguments
/// * `context` - User-provided context from registration
/// * `argument1` - First argument passed to ExNotifyCallback
/// * `argument2` - Second argument passed to ExNotifyCallback
pub type CallbackFunction = fn(context: *mut u8, argument1: *mut u8, argument2: *mut u8);

/// Callback object structure
///
/// A callback object holds a list of registered callback functions
/// that are invoked when ExNotifyCallback is called.
#[repr(C)]
pub struct ExCallbackObject {
    /// Object signature for validation
    signature: u32,
    /// Spinlock protecting the registration list
    lock: RawSpinLock,
    /// List of registered callbacks
    registered_callbacks: UnsafeCell<ListEntry>,
    /// Whether multiple registrations are allowed
    allow_multiple: bool,
    /// Number of active registrations
    registration_count: AtomicU32,
    /// Object is being deleted
    deleting: AtomicBool,
    /// Name of the callback (for named callbacks)
    name: [u8; 64],
    /// Name length
    name_len: usize,
}

// Safety: ExCallbackObject is designed for multi-threaded access
unsafe impl Sync for ExCallbackObject {}
unsafe impl Send for ExCallbackObject {}

/// Signature value for valid callback objects
const CALLBACK_SIGNATURE: u32 = 0x43414C4C; // 'CALL'

impl ExCallbackObject {
    /// Create a new callback object
    pub const fn new() -> Self {
        Self {
            signature: CALLBACK_SIGNATURE,
            lock: RawSpinLock::new(),
            registered_callbacks: UnsafeCell::new(ListEntry::new()),
            allow_multiple: true,
            registration_count: AtomicU32::new(0),
            deleting: AtomicBool::new(false),
            name: [0; 64],
            name_len: 0,
        }
    }

    /// Initialize a callback object
    ///
    /// # Arguments
    /// * `allow_multiple` - Whether multiple callbacks can be registered
    pub fn init(&mut self, allow_multiple: bool) {
        self.signature = CALLBACK_SIGNATURE;
        self.allow_multiple = allow_multiple;
        self.registration_count.store(0, Ordering::SeqCst);
        self.deleting.store(false, Ordering::SeqCst);
        unsafe {
            (*self.registered_callbacks.get()).init_head();
        }
    }

    /// Initialize with a name
    pub fn init_named(&mut self, name: &[u8], allow_multiple: bool) {
        self.init(allow_multiple);
        let len = name.len().min(63);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Check if the object is valid
    pub fn is_valid(&self) -> bool {
        self.signature == CALLBACK_SIGNATURE
    }

    /// Get the number of registered callbacks
    pub fn registration_count(&self) -> u32 {
        self.registration_count.load(Ordering::SeqCst)
    }

    /// Register a callback function
    ///
    /// # Arguments
    /// * `function` - The callback function to register
    /// * `context` - User context passed to the callback
    ///
    /// # Returns
    /// A registration handle that must be used to unregister, or None if
    /// registration failed.
    ///
    /// # Safety
    /// The caller must ensure the context pointer remains valid until
    /// the callback is unregistered.
    pub unsafe fn register(
        &self,
        function: CallbackFunction,
        context: *mut u8,
    ) -> Option<*mut CallbackRegistration> {
        // Check if we're deleting
        if self.deleting.load(Ordering::SeqCst) {
            return None;
        }

        // Check if multiple registrations are allowed
        if !self.allow_multiple && self.registration_count.load(Ordering::SeqCst) > 0 {
            return None;
        }

        // Allocate a registration from the static pool
        let registration = allocate_registration()?;

        // Initialize the registration
        (*registration).link.init_head();
        (*registration).callback_object = self as *const _ as *mut ExCallbackObject;
        (*registration).callback_function = Some(function);
        (*registration).callback_context = context;
        (*registration).busy.store(0, Ordering::SeqCst);
        (*registration).unregister_waiting.store(false, Ordering::SeqCst);

        // Add to the list
        let irq = self.lock.acquire();
        let list = &mut *self.registered_callbacks.get();
        list.insert_tail(&mut (*registration).link);
        self.registration_count.fetch_add(1, Ordering::SeqCst);
        self.lock.release(irq);

        Some(registration)
    }

    /// Unregister a callback
    ///
    /// # Arguments
    /// * `registration` - The registration handle returned from register()
    ///
    /// # Safety
    /// The registration must have been obtained from this callback object.
    pub unsafe fn unregister(&self, registration: *mut CallbackRegistration) {
        if registration.is_null() {
            return;
        }

        // Mark that we want to unregister
        (*registration).unregister_waiting.store(true, Ordering::SeqCst);

        // Wait for any active invocations to complete
        while (*registration).busy.load(Ordering::SeqCst) > 0 {
            core::hint::spin_loop();
        }

        // Remove from list
        let irq = self.lock.acquire();
        (*registration).link.remove_entry();
        self.registration_count.fetch_sub(1, Ordering::SeqCst);
        self.lock.release(irq);

        // Free the registration
        free_registration(registration);
    }

    /// Notify all registered callbacks
    ///
    /// Invokes each registered callback function with the provided arguments.
    ///
    /// # Arguments
    /// * `argument1` - First argument to pass to callbacks
    /// * `argument2` - Second argument to pass to callbacks
    pub unsafe fn notify(&self, argument1: *mut u8, argument2: *mut u8) {
        if self.deleting.load(Ordering::SeqCst) {
            return;
        }

        // Walk the registration list
        let irq = self.lock.acquire();
        let list = &*self.registered_callbacks.get();

        if list.is_empty() {
            self.lock.release(irq);
            return;
        }

        // Get first entry
        let mut current = list.flink;

        while !ptr::eq(current, list as *const _ as *mut ListEntry) {
            let registration = crate::containing_record!(current, CallbackRegistration, link);

            // Skip if unregistering
            if (*registration).unregister_waiting.load(Ordering::SeqCst) {
                current = (*current).flink;
                continue;
            }

            // Mark as busy
            (*registration).busy.fetch_add(1, Ordering::SeqCst);

            // Get function and context before releasing lock
            let function = (*registration).callback_function;
            let context = (*registration).callback_context;
            let next = (*current).flink;

            // Release lock while calling back (don't restore interrupts yet)
            self.lock.release(false);

            // Call the callback (with interrupts still disabled)
            if let Some(f) = function {
                f(context, argument1, argument2);
            }

            // Mark as not busy
            (*registration).busy.fetch_sub(1, Ordering::SeqCst);

            // Re-acquire lock and continue
            let _ = self.lock.acquire();
            current = next;
        }

        // Final release - restore original interrupt state
        self.lock.release(irq);
    }

    /// Mark the callback object as being deleted
    ///
    /// After calling this, no new registrations can be made.
    pub fn begin_delete(&self) {
        self.deleting.store(true, Ordering::SeqCst);
    }
}

impl Default for ExCallbackObject {
    fn default() -> Self {
        Self::new()
    }
}

/// Callback registration structure
///
/// Represents a single registered callback function.
#[repr(C)]
pub struct CallbackRegistration {
    /// Link in the callback object's list
    pub link: ListEntry,
    /// Pointer back to the callback object
    pub callback_object: *mut ExCallbackObject,
    /// The registered callback function
    pub callback_function: Option<CallbackFunction>,
    /// User-provided context
    pub callback_context: *mut u8,
    /// Number of active invocations
    pub busy: AtomicU32,
    /// Whether unregister is waiting
    pub unregister_waiting: AtomicBool,
}

// Safety: Protected by callback object lock
unsafe impl Sync for CallbackRegistration {}
unsafe impl Send for CallbackRegistration {}

impl CallbackRegistration {
    /// Create a new empty registration
    pub const fn new() -> Self {
        Self {
            link: ListEntry::new(),
            callback_object: ptr::null_mut(),
            callback_function: None,
            callback_context: ptr::null_mut(),
            busy: AtomicU32::new(0),
            unregister_waiting: AtomicBool::new(false),
        }
    }
}

impl Default for CallbackRegistration {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Registration Pool
// ============================================================================

/// Static pool of callback registrations
static mut REGISTRATION_POOL: [CallbackRegistration; MAX_CALLBACK_OBJECTS * MAX_REGISTRATIONS_PER_CALLBACK] = {
    const INIT: CallbackRegistration = CallbackRegistration::new();
    [INIT; MAX_CALLBACK_OBJECTS * MAX_REGISTRATIONS_PER_CALLBACK]
};

/// Bitmap tracking which registrations are allocated
static mut REGISTRATION_BITMAP: [u64; 32] = [0; 32]; // 2048 bits

/// Lock for registration allocation
static REGISTRATION_LOCK: RawSpinLock = RawSpinLock::new();

/// Allocate a registration from the pool
unsafe fn allocate_registration() -> Option<*mut CallbackRegistration> {
    let irq = REGISTRATION_LOCK.acquire();

    for (word_idx, word) in REGISTRATION_BITMAP.iter_mut().enumerate() {
        if *word != u64::MAX {
            // Find first free bit
            for bit in 0..64 {
                if (*word & (1 << bit)) == 0 {
                    *word |= 1 << bit;
                    let index = word_idx * 64 + bit;
                    if index < REGISTRATION_POOL.len() {
                        REGISTRATION_LOCK.release(irq);
                        let reg = &mut REGISTRATION_POOL[index] as *mut CallbackRegistration;
                        // Initialize the registration
                        (*reg).link.init_head();
                        (*reg).callback_object = ptr::null_mut();
                        (*reg).callback_function = None;
                        (*reg).callback_context = ptr::null_mut();
                        (*reg).busy.store(0, Ordering::SeqCst);
                        (*reg).unregister_waiting.store(false, Ordering::SeqCst);
                        return Some(reg);
                    }
                }
            }
        }
    }

    REGISTRATION_LOCK.release(irq);
    None
}

/// Free a registration back to the pool
unsafe fn free_registration(registration: *mut CallbackRegistration) {
    let base = REGISTRATION_POOL.as_ptr() as usize;
    let addr = registration as usize;
    let index = (addr - base) / core::mem::size_of::<CallbackRegistration>();

    if index < REGISTRATION_POOL.len() {
        let irq = REGISTRATION_LOCK.acquire();
        let word_idx = index / 64;
        let bit = index % 64;
        REGISTRATION_BITMAP[word_idx] &= !(1 << bit);
        REGISTRATION_LOCK.release(irq);
    }
}

// ============================================================================
// Callback Object Pool
// ============================================================================

/// Static pool of callback objects
static mut CALLBACK_POOL: [ExCallbackObject; MAX_CALLBACK_OBJECTS] = {
    const INIT: ExCallbackObject = ExCallbackObject::new();
    [INIT; MAX_CALLBACK_OBJECTS]
};

/// Bitmap tracking which callback objects are allocated
static mut CALLBACK_BITMAP: u64 = 0;

/// Lock for callback allocation
static CALLBACK_LOCK: RawSpinLock = RawSpinLock::new();

/// Allocate a callback object from the pool
pub unsafe fn allocate_callback_object() -> Option<*mut ExCallbackObject> {
    let irq = CALLBACK_LOCK.acquire();

    for bit in 0..MAX_CALLBACK_OBJECTS {
        if (CALLBACK_BITMAP & (1 << bit)) == 0 {
            CALLBACK_BITMAP |= 1 << bit;
            CALLBACK_LOCK.release(irq);
            let cb = &mut CALLBACK_POOL[bit] as *mut ExCallbackObject;
            (*cb).init(true);
            return Some(cb);
        }
    }

    CALLBACK_LOCK.release(irq);
    None
}

/// Free a callback object back to the pool
pub unsafe fn free_callback_object(callback: *mut ExCallbackObject) {
    let base = CALLBACK_POOL.as_ptr() as usize;
    let addr = callback as usize;
    let index = (addr - base) / core::mem::size_of::<ExCallbackObject>();

    if index < MAX_CALLBACK_OBJECTS {
        (*callback).begin_delete();
        let irq = CALLBACK_LOCK.acquire();
        CALLBACK_BITMAP &= !(1 << index);
        CALLBACK_LOCK.release(irq);
    }
}

// ============================================================================
// Public API Functions (NT-compatible naming)
// ============================================================================

/// Create or open a callback object (ExCreateCallback)
///
/// # Arguments
/// * `name` - Optional name for the callback (for opening existing callbacks)
/// * `create` - If true, create if not exists
/// * `allow_multiple` - Whether multiple registrations are allowed
///
/// # Returns
/// Pointer to callback object, or None if creation/open failed.
pub unsafe fn ex_create_callback(
    name: Option<&[u8]>,
    create: bool,
    allow_multiple: bool,
) -> Option<*mut ExCallbackObject> {
    // If name is provided, try to find existing
    if let Some(name_bytes) = name {
        // Search for existing callback with this name
        for i in 0..MAX_CALLBACK_OBJECTS {
            if (CALLBACK_BITMAP & (1 << i)) != 0 {
                let cb = &CALLBACK_POOL[i];
                if cb.name_len == name_bytes.len() && cb.name[..cb.name_len] == *name_bytes {
                    return Some(&CALLBACK_POOL[i] as *const _ as *mut ExCallbackObject);
                }
            }
        }
    }

    // Not found, create if requested
    if create {
        let callback = allocate_callback_object()?;
        (*callback).allow_multiple = allow_multiple;
        if let Some(name_bytes) = name {
            let len = name_bytes.len().min(63);
            (&mut (*callback).name)[..len].copy_from_slice(&name_bytes[..len]);
            (*callback).name_len = len;
        }
        Some(callback)
    } else {
        None
    }
}

/// Register a callback function (ExRegisterCallback)
///
/// # Returns
/// Registration handle to use with ExUnregisterCallback.
pub unsafe fn ex_register_callback(
    callback: *mut ExCallbackObject,
    function: CallbackFunction,
    context: *mut u8,
) -> Option<*mut CallbackRegistration> {
    if callback.is_null() || !(*callback).is_valid() {
        return None;
    }
    (*callback).register(function, context)
}

/// Unregister a callback (ExUnregisterCallback)
pub unsafe fn ex_unregister_callback(registration: *mut CallbackRegistration) {
    if registration.is_null() {
        return;
    }
    let callback = (*registration).callback_object;
    if !callback.is_null() && (*callback).is_valid() {
        (*callback).unregister(registration);
    }
}

/// Notify all registered callbacks (ExNotifyCallback)
pub unsafe fn ex_notify_callback(
    callback: *mut ExCallbackObject,
    argument1: *mut u8,
    argument2: *mut u8,
) {
    if callback.is_null() || !(*callback).is_valid() {
        return;
    }
    (*callback).notify(argument1, argument2);
}

// ============================================================================
// Well-Known Callback Objects
// ============================================================================

/// System shutdown callback
static mut SHUTDOWN_CALLBACK: ExCallbackObject = ExCallbackObject::new();

/// Power state callback
static mut POWER_STATE_CALLBACK: ExCallbackObject = ExCallbackObject::new();

/// Process creation callback
static mut PROCESS_CALLBACK: ExCallbackObject = ExCallbackObject::new();

/// Thread creation callback
static mut THREAD_CALLBACK: ExCallbackObject = ExCallbackObject::new();

/// Image load callback
static mut IMAGE_LOAD_CALLBACK: ExCallbackObject = ExCallbackObject::new();

/// Get the system shutdown callback object
pub fn get_shutdown_callback() -> *mut ExCallbackObject {
    unsafe { &mut SHUTDOWN_CALLBACK as *mut ExCallbackObject }
}

/// Get the power state callback object
pub fn get_power_state_callback() -> *mut ExCallbackObject {
    unsafe { &mut POWER_STATE_CALLBACK as *mut ExCallbackObject }
}

/// Get the process creation callback object
pub fn get_process_callback() -> *mut ExCallbackObject {
    unsafe { &mut PROCESS_CALLBACK as *mut ExCallbackObject }
}

/// Get the thread creation callback object
pub fn get_thread_callback() -> *mut ExCallbackObject {
    unsafe { &mut THREAD_CALLBACK as *mut ExCallbackObject }
}

/// Get the image load callback object
pub fn get_image_load_callback() -> *mut ExCallbackObject {
    unsafe { &mut IMAGE_LOAD_CALLBACK as *mut ExCallbackObject }
}

/// Initialize the callback subsystem
pub fn init() {
    unsafe {
        // Initialize well-known callbacks
        SHUTDOWN_CALLBACK.init_named(b"\\Callback\\Shutdown", true);
        POWER_STATE_CALLBACK.init_named(b"\\Callback\\PowerState", true);
        PROCESS_CALLBACK.init_named(b"\\Callback\\ProcessCreate", true);
        THREAD_CALLBACK.init_named(b"\\Callback\\ThreadCreate", true);
        IMAGE_LOAD_CALLBACK.init_named(b"\\Callback\\ImageLoad", true);
    }

    crate::serial_println!("[CALLBACK] Callback subsystem initialized");
}

// ============================================================================
// Inspection Functions
// ============================================================================

/// Callback object statistics
#[derive(Debug, Clone, Copy)]
pub struct CallbackStats {
    /// Maximum callback objects
    pub max_callback_objects: usize,
    /// Allocated callback objects
    pub allocated_count: usize,
    /// Free callback objects
    pub free_count: usize,
    /// Total registrations across all callbacks
    pub total_registrations: u32,
}

/// Get callback object statistics
pub fn get_callback_stats() -> CallbackStats {
    unsafe {
        let bitmap = CALLBACK_BITMAP;
        let allocated = bitmap.count_ones() as usize;

        let mut total_regs: u32 = 0;
        for i in 0..MAX_CALLBACK_OBJECTS {
            if (bitmap & (1 << i)) != 0 {
                total_regs += CALLBACK_POOL[i].registration_count.load(Ordering::Relaxed);
            }
        }

        // Also count well-known callbacks
        total_regs += SHUTDOWN_CALLBACK.registration_count.load(Ordering::Relaxed);
        total_regs += POWER_STATE_CALLBACK.registration_count.load(Ordering::Relaxed);
        total_regs += PROCESS_CALLBACK.registration_count.load(Ordering::Relaxed);
        total_regs += THREAD_CALLBACK.registration_count.load(Ordering::Relaxed);
        total_regs += IMAGE_LOAD_CALLBACK.registration_count.load(Ordering::Relaxed);

        CallbackStats {
            max_callback_objects: MAX_CALLBACK_OBJECTS,
            allocated_count: allocated + 5, // +5 for well-known
            free_count: MAX_CALLBACK_OBJECTS - allocated,
            total_registrations: total_regs,
        }
    }
}

/// Callback object snapshot for inspection
#[derive(Clone, Copy)]
pub struct CallbackSnapshot {
    /// Index in pool (or 0xFF for well-known)
    pub index: u8,
    /// Name
    pub name: [u8; 64],
    /// Name length
    pub name_len: u8,
    /// Registration count
    pub registration_count: u32,
    /// Call count (not tracked, always 0)
    pub call_count: u32,
}

impl CallbackSnapshot {
    pub const fn empty() -> Self {
        Self {
            index: 0,
            name: [0u8; 64],
            name_len: 0,
            registration_count: 0,
            call_count: 0,
        }
    }
}

/// Get snapshots of allocated callback objects
pub fn get_callback_snapshots(max_count: usize) -> ([CallbackSnapshot; 16], usize) {
    let mut snapshots = [CallbackSnapshot::empty(); 16];
    let mut count = 0;

    let limit = max_count.min(16);

    unsafe {
        // Add well-known callbacks first
        let well_known: [(&ExCallbackObject, &str); 5] = [
            (&SHUTDOWN_CALLBACK, "\\Callback\\Shutdown"),
            (&POWER_STATE_CALLBACK, "\\Callback\\PowerState"),
            (&PROCESS_CALLBACK, "\\Callback\\ProcessCreate"),
            (&THREAD_CALLBACK, "\\Callback\\ThreadCreate"),
            (&IMAGE_LOAD_CALLBACK, "\\Callback\\ImageLoad"),
        ];

        for (cb, name) in well_known.iter() {
            if count >= limit {
                break;
            }
            let snap = &mut snapshots[count];
            snap.index = 0xFF;
            let name_bytes = name.as_bytes();
            let len = name_bytes.len().min(64);
            snap.name[..len].copy_from_slice(&name_bytes[..len]);
            snap.name_len = len as u8;
            snap.registration_count = cb.registration_count.load(Ordering::Relaxed);
            snap.call_count = 0;
            count += 1;
        }

        // Add pool callbacks
        let bitmap = CALLBACK_BITMAP;
        for i in 0..MAX_CALLBACK_OBJECTS {
            if count >= limit {
                break;
            }

            if (bitmap & (1 << i)) != 0 {
                let cb = &CALLBACK_POOL[i];
                let snap = &mut snapshots[count];
                snap.index = i as u8;
                let len = cb.name_len.min(64);
                snap.name[..len].copy_from_slice(&cb.name[..len]);
                snap.name_len = len as u8;
                snap.registration_count = cb.registration_count.load(Ordering::Relaxed);
                snap.call_count = 0;
                count += 1;
            }
        }
    }

    (snapshots, count)
}
