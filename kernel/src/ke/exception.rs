//! Exception Handling Support
//!
//! Implements NT-compatible exception handling structures and functions:
//! - CONTEXT structure for x86-64 (full CPU state)
//! - EXCEPTION_RECORD structure
//! - EXCEPTION_POINTERS structure for VEH
//! - Vectored Exception Handler (VEH) framework
//! - NtRaiseException / NtContinue support
//!
//! # NT Compatibility
//! This module provides the same structures used by NT's Structured Exception
//! Handling (SEH) mechanism, allowing user-mode exception handlers to work.
//!
//! # Vectored Exception Handling
//!
//! VEH provides a way to register exception handlers that are called before
//! the frame-based SEH dispatch. Handlers return:
//! - EXCEPTION_CONTINUE_EXECUTION (-1): Exception handled, resume execution
//! - EXCEPTION_CONTINUE_SEARCH (0): Pass to next handler/SEH chain

use core::ptr;
use spin::Mutex;

/// Context flags indicating which parts of CONTEXT are valid
#[allow(non_snake_case)]
pub mod ContextFlags {
    /// i386 context
    pub const CONTEXT_I386: u32 = 0x00010000;
    /// AMD64 context
    pub const CONTEXT_AMD64: u32 = 0x00100000;

    /// Control registers (RIP, RSP, RFLAGS, CS, SS)
    pub const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x0001;
    /// Integer registers (RAX-R15)
    pub const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x0002;
    /// Segment registers (DS, ES, FS, GS)
    pub const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x0004;
    /// Floating point state (x87 FPU)
    pub const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x0008;
    /// Debug registers (DR0-DR7)
    pub const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x0010;
    /// XMM registers (SSE)
    pub const CONTEXT_XSTATE: u32 = CONTEXT_AMD64 | 0x0040;

    /// Full context (all standard registers)
    pub const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
    /// All registers
    pub const CONTEXT_ALL: u32 = CONTEXT_FULL | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS;
}

/// Exception codes
#[allow(non_snake_case)]
pub mod ExceptionCode {
    /// Access violation
    pub const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC0000005;
    /// Array bounds exceeded
    pub const EXCEPTION_ARRAY_BOUNDS_EXCEEDED: u32 = 0xC000008C;
    /// Breakpoint
    pub const EXCEPTION_BREAKPOINT: u32 = 0x80000003;
    /// Data type misalignment
    pub const EXCEPTION_DATATYPE_MISALIGNMENT: u32 = 0x80000002;
    /// Floating point denormal operand
    pub const EXCEPTION_FLT_DENORMAL_OPERAND: u32 = 0xC000008D;
    /// Floating point divide by zero
    pub const EXCEPTION_FLT_DIVIDE_BY_ZERO: u32 = 0xC000008E;
    /// Floating point inexact result
    pub const EXCEPTION_FLT_INEXACT_RESULT: u32 = 0xC000008F;
    /// Floating point invalid operation
    pub const EXCEPTION_FLT_INVALID_OPERATION: u32 = 0xC0000090;
    /// Floating point overflow
    pub const EXCEPTION_FLT_OVERFLOW: u32 = 0xC0000091;
    /// Floating point stack check
    pub const EXCEPTION_FLT_STACK_CHECK: u32 = 0xC0000092;
    /// Floating point underflow
    pub const EXCEPTION_FLT_UNDERFLOW: u32 = 0xC0000093;
    /// Illegal instruction
    pub const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000001D;
    /// In-page error
    pub const EXCEPTION_IN_PAGE_ERROR: u32 = 0xC0000006;
    /// Integer divide by zero
    pub const EXCEPTION_INT_DIVIDE_BY_ZERO: u32 = 0xC0000094;
    /// Integer overflow
    pub const EXCEPTION_INT_OVERFLOW: u32 = 0xC0000095;
    /// Invalid disposition
    pub const EXCEPTION_INVALID_DISPOSITION: u32 = 0xC0000026;
    /// Noncontinuable exception
    pub const EXCEPTION_NONCONTINUABLE_EXCEPTION: u32 = 0xC0000025;
    /// Privileged instruction
    pub const EXCEPTION_PRIV_INSTRUCTION: u32 = 0xC0000096;
    /// Single step
    pub const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
    /// Stack overflow
    pub const EXCEPTION_STACK_OVERFLOW: u32 = 0xC00000FD;
}

/// Exception flags
#[allow(non_snake_case)]
pub mod ExceptionFlags {
    /// Exception is continuable
    pub const EXCEPTION_CONTINUABLE: u32 = 0;
    /// Exception is noncontinuable
    pub const EXCEPTION_NONCONTINUABLE: u32 = 0x01;
    /// Exception is being unwound
    pub const EXCEPTION_UNWINDING: u32 = 0x02;
    /// Exit unwind is in progress
    pub const EXCEPTION_EXIT_UNWIND: u32 = 0x04;
    /// Stack is invalid
    pub const EXCEPTION_STACK_INVALID: u32 = 0x08;
    /// Nested exception
    pub const EXCEPTION_NESTED_CALL: u32 = 0x10;
    /// Target unwind in progress
    pub const EXCEPTION_TARGET_UNWIND: u32 = 0x20;
    /// Collided unwind
    pub const EXCEPTION_COLLIDED_UNWIND: u32 = 0x40;
}

/// VEH handler return values
#[allow(non_snake_case)]
pub mod ExceptionDisposition {
    /// Handler processed the exception; continue execution
    pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    /// Handler didn't process; continue search
    pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
    /// Execute the exception handler (for SEH)
    pub const EXCEPTION_EXECUTE_HANDLER: i32 = 1;
}

/// Maximum number of exception parameters
pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

/// 128-bit XMM register
#[derive(Debug, Clone, Copy)]
#[repr(C, align(16))]
pub struct M128A {
    pub low: u64,
    pub high: i64,
}

impl M128A {
    pub const fn new() -> Self {
        Self { low: 0, high: 0 }
    }
}

impl Default for M128A {
    fn default() -> Self {
        Self::new()
    }
}

/// Legacy floating point save area (x87 FPU state)
#[derive(Debug, Clone, Copy)]
#[repr(C, align(16))]
pub struct LegacyFloatingSaveArea {
    pub control_word: u16,
    pub status_word: u16,
    pub tag_word: u8,
    pub reserved1: u8,
    pub error_opcode: u16,
    pub error_offset: u32,
    pub error_selector: u16,
    pub reserved2: u16,
    pub data_offset: u32,
    pub data_selector: u16,
    pub reserved3: u16,
    pub mx_csr: u32,
    pub mx_csr_mask: u32,
    pub float_registers: [M128A; 8],
    pub xmm_registers: [M128A; 16],
    pub reserved4: [u8; 96],
}

impl LegacyFloatingSaveArea {
    pub const fn new() -> Self {
        Self {
            control_word: 0x27F, // Default x87 control word
            status_word: 0,
            tag_word: 0,
            reserved1: 0,
            error_opcode: 0,
            error_offset: 0,
            error_selector: 0,
            reserved2: 0,
            data_offset: 0,
            data_selector: 0,
            reserved3: 0,
            mx_csr: 0x1F80, // Default MXCSR
            mx_csr_mask: 0xFFFF,
            float_registers: [M128A::new(); 8],
            xmm_registers: [M128A::new(); 16],
            reserved4: [0; 96],
        }
    }
}

impl Default for LegacyFloatingSaveArea {
    fn default() -> Self {
        Self::new()
    }
}

/// x86-64 CONTEXT structure
///
/// This is the NT CONTEXT structure for AMD64, containing the full CPU state.
/// Used for exception handling, debugging, and context manipulation.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(16))]
pub struct Context {
    // Register parameter home addresses
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,

    // Context flags
    pub context_flags: u32,
    pub mx_csr: u32,

    // Segment registers and processor flags
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub e_flags: u32,

    // Debug registers
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,

    // Integer registers
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // Program counter
    pub rip: u64,

    // Floating point state (union with XMM_SAVE_AREA32)
    pub float_save: LegacyFloatingSaveArea,

    // Vector registers
    pub vector_register: [M128A; 26],
    pub vector_control: u64,

    // Debug control
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
}

impl Context {
    pub const fn new() -> Self {
        Self {
            p1_home: 0,
            p2_home: 0,
            p3_home: 0,
            p4_home: 0,
            p5_home: 0,
            p6_home: 0,
            context_flags: ContextFlags::CONTEXT_FULL,
            mx_csr: 0x1F80,
            seg_cs: 0x33, // User code segment
            seg_ds: 0x2B, // User data segment
            seg_es: 0x2B,
            seg_fs: 0x53, // TEB segment
            seg_gs: 0x2B,
            seg_ss: 0x2B,
            e_flags: 0x202, // IF set
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            float_save: LegacyFloatingSaveArea::new(),
            vector_register: [M128A::new(); 26],
            vector_control: 0,
            debug_control: 0,
            last_branch_to_rip: 0,
            last_branch_from_rip: 0,
            last_exception_to_rip: 0,
            last_exception_from_rip: 0,
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Exception record describing an exception
///
/// This structure describes the nature of an exception, including the
/// exception code, address, and any additional parameters.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ExceptionRecord {
    /// Exception code (e.g., EXCEPTION_ACCESS_VIOLATION)
    pub exception_code: u32,
    /// Exception flags (continuable, unwinding, etc.)
    pub exception_flags: u32,
    /// Pointer to nested exception record
    pub exception_record: *mut ExceptionRecord,
    /// Address where exception occurred
    pub exception_address: *mut u8,
    /// Number of parameters
    pub number_parameters: u32,
    /// Reserved/padding for alignment
    pub reserved: u32,
    /// Exception-specific information
    pub exception_information: [u64; EXCEPTION_MAXIMUM_PARAMETERS],
}

impl ExceptionRecord {
    pub const fn new() -> Self {
        Self {
            exception_code: 0,
            exception_flags: 0,
            exception_record: ptr::null_mut(),
            exception_address: ptr::null_mut(),
            number_parameters: 0,
            reserved: 0,
            exception_information: [0; EXCEPTION_MAXIMUM_PARAMETERS],
        }
    }

    /// Create an access violation exception record
    pub fn access_violation(address: *mut u8, is_write: bool) -> Self {
        let mut record = Self::new();
        record.exception_code = ExceptionCode::EXCEPTION_ACCESS_VIOLATION;
        record.exception_flags = ExceptionFlags::EXCEPTION_CONTINUABLE;
        record.exception_address = address;
        record.number_parameters = 2;
        // Parameter 0: 0 = read, 1 = write, 8 = DEP violation
        record.exception_information[0] = if is_write { 1 } else { 0 };
        // Parameter 1: faulting address
        record.exception_information[1] = address as u64;
        record
    }

    /// Create a breakpoint exception record
    pub fn breakpoint(address: *mut u8) -> Self {
        let mut record = Self::new();
        record.exception_code = ExceptionCode::EXCEPTION_BREAKPOINT;
        record.exception_flags = ExceptionFlags::EXCEPTION_CONTINUABLE;
        record.exception_address = address;
        record.number_parameters = 1;
        record.exception_information[0] = 0; // Breakpoint index
        record
    }

    /// Create a divide by zero exception record
    pub fn divide_by_zero(address: *mut u8) -> Self {
        let mut record = Self::new();
        record.exception_code = ExceptionCode::EXCEPTION_INT_DIVIDE_BY_ZERO;
        record.exception_flags = ExceptionFlags::EXCEPTION_CONTINUABLE;
        record.exception_address = address;
        record.number_parameters = 0;
        record
    }

    /// Check if exception is continuable
    pub fn is_continuable(&self) -> bool {
        (self.exception_flags & ExceptionFlags::EXCEPTION_NONCONTINUABLE) == 0
    }
}

impl Default for ExceptionRecord {
    fn default() -> Self {
        Self::new()
    }
}

// Make ExceptionRecord safe to send between threads
unsafe impl Send for ExceptionRecord {}
unsafe impl Sync for ExceptionRecord {}

/// Exception pointers structure for VEH
///
/// This structure is passed to vectored exception handlers and contains
/// pointers to both the exception record and the thread context.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ExceptionPointers {
    /// Pointer to the exception record
    pub exception_record: *mut ExceptionRecord,
    /// Pointer to the thread context at the time of exception
    pub context_record: *mut Context,
}

impl ExceptionPointers {
    pub const fn new() -> Self {
        Self {
            exception_record: ptr::null_mut(),
            context_record: ptr::null_mut(),
        }
    }

    /// Create from references
    pub fn from_refs(record: &mut ExceptionRecord, context: &mut Context) -> Self {
        Self {
            exception_record: record as *mut ExceptionRecord,
            context_record: context as *mut Context,
        }
    }
}

impl Default for ExceptionPointers {
    fn default() -> Self {
        Self::new()
    }
}

// Make ExceptionPointers safe to send
unsafe impl Send for ExceptionPointers {}
unsafe impl Sync for ExceptionPointers {}

// =============================================================================
// Vectored Exception Handler (VEH) Framework
// =============================================================================

/// Maximum number of VEH handlers that can be registered
pub const MAX_VEH_HANDLERS: usize = 32;

/// Type for vectored exception handler function
///
/// The handler receives a pointer to EXCEPTION_POINTERS and returns:
/// - EXCEPTION_CONTINUE_EXECUTION (-1): Exception handled, resume
/// - EXCEPTION_CONTINUE_SEARCH (0): Pass to next handler
pub type VectoredExceptionHandler = fn(*mut ExceptionPointers) -> i32;

/// Entry in the vectored exception handler list
#[derive(Clone, Copy)]
struct VehEntry {
    /// The handler function (None if slot is free)
    handler: Option<VectoredExceptionHandler>,
    /// Unique identifier for this entry (used as handle)
    id: u64,
}

impl VehEntry {
    const fn empty() -> Self {
        Self {
            handler: None,
            id: 0,
        }
    }
}

/// VEH list state
struct VehList {
    /// Handler entries (ordered - first to call is at index 0)
    entries: [VehEntry; MAX_VEH_HANDLERS],
    /// Number of active handlers
    count: usize,
}

impl VehList {
    const fn new() -> Self {
        Self {
            entries: [VehEntry::empty(); MAX_VEH_HANDLERS],
            count: 0,
        }
    }
}

/// Global vectored exception handler list
static VEH_LIST: Mutex<VehList> = Mutex::new(VehList::new());

/// Next VEH entry ID
static VEH_NEXT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Add a vectored exception handler
///
/// # Arguments
/// * `first_handler` - If non-zero, add as first handler; otherwise add as last
/// * `handler` - The handler function to call on exceptions
///
/// # Returns
/// A handle that can be used to remove the handler, or 0 on failure
pub fn rtl_add_vectored_exception_handler(
    first_handler: u32,
    handler: VectoredExceptionHandler,
) -> u64 {
    let mut list = VEH_LIST.lock();

    // Check if we have room
    if list.count >= MAX_VEH_HANDLERS {
        return 0; // No room
    }

    let id = VEH_NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    let entry = VehEntry {
        handler: Some(handler),
        id,
    };

    let count = list.count;
    if first_handler != 0 {
        // Insert at the beginning - shift existing entries right
        for i in (1..=count).rev() {
            list.entries[i] = list.entries[i - 1];
        }
        list.entries[0] = entry;
    } else {
        // Insert at the end
        list.entries[count] = entry;
    }

    list.count += 1;
    id
}

/// Remove a vectored exception handler
///
/// # Arguments
/// * `handle` - The handle returned from rtl_add_vectored_exception_handler
///
/// # Returns
/// Non-zero if successful, zero if handler not found
pub fn rtl_remove_vectored_exception_handler(handle: u64) -> u32 {
    let mut list = VEH_LIST.lock();
    let count = list.count;

    // Find the entry with this handle
    for i in 0..count {
        if list.entries[i].id == handle {
            // Found it - shift remaining entries left
            for j in i..(count - 1) {
                list.entries[j] = list.entries[j + 1];
            }
            // Clear the last slot
            list.entries[count - 1] = VehEntry::empty();
            list.count -= 1;
            return 1; // TRUE
        }
    }

    0 // FALSE - not found
}

/// Call all vectored exception handlers
///
/// This is called before frame-based SEH dispatch to give VEH handlers
/// a chance to handle the exception.
///
/// # Arguments
/// * `exception_record` - The exception that occurred
/// * `context` - The thread context at the time of exception
///
/// # Returns
/// true if a handler returned EXCEPTION_CONTINUE_EXECUTION
/// false if all handlers returned EXCEPTION_CONTINUE_SEARCH
pub fn rtl_call_vectored_exception_handlers(
    exception_record: *mut ExceptionRecord,
    context: *mut Context,
) -> bool {
    let list = VEH_LIST.lock();

    if list.count == 0 {
        return false;
    }

    // Create exception pointers structure
    let mut exception_info = ExceptionPointers {
        exception_record,
        context_record: context,
    };

    // Call each handler in order
    for i in 0..list.count {
        if let Some(handler) = list.entries[i].handler {
            let result = handler(&mut exception_info);
            if result == ExceptionDisposition::EXCEPTION_CONTINUE_EXECUTION {
                return true;
            }
        }
    }

    false
}

/// Get the number of registered VEH handlers
pub fn rtl_get_vectored_handler_count() -> usize {
    VEH_LIST.lock().count
}

// =============================================================================
// Structured Exception Handling (SEH) Framework
// =============================================================================

/// Maximum number of SEH frames per thread
pub const MAX_SEH_FRAMES: usize = 64;

/// SEH handler function type
///
/// The handler receives exception record, establisher frame, context, and
/// dispatcher context. Returns an EXCEPTION_DISPOSITION value.
pub type SehExceptionHandler = fn(
    exception_record: *mut ExceptionRecord,
    establisher_frame: u64,
    context: *mut Context,
    dispatcher_context: *mut DispatcherContext,
) -> i32;

/// Dispatcher context for SEH handlers
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DispatcherContext {
    /// Control PC where exception occurred
    pub control_pc: u64,
    /// Image base of the module
    pub image_base: u64,
    /// Runtime function entry (for table-based unwinding)
    pub function_entry: u64,
    /// Establisher frame pointer
    pub establisher_frame: u64,
    /// Target instruction pointer for unwind
    pub target_ip: u64,
    /// Context record
    pub context_record: *mut Context,
    /// Language-specific handler
    pub language_handler: u64,
    /// Handler-specific data
    pub handler_data: u64,
}

impl DispatcherContext {
    pub const fn new() -> Self {
        Self {
            control_pc: 0,
            image_base: 0,
            function_entry: 0,
            establisher_frame: 0,
            target_ip: 0,
            context_record: ptr::null_mut(),
            language_handler: 0,
            handler_data: 0,
        }
    }
}

impl Default for DispatcherContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Exception registration record for x86-style SEH
///
/// This is the traditional linked-list based SEH used in 32-bit Windows.
/// For x64, we use this alongside table-based unwinding for compatibility.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExceptionRegistrationRecord {
    /// Pointer to next registration record in chain
    pub next: *mut ExceptionRegistrationRecord,
    /// Exception handler function
    pub handler: Option<SehExceptionHandler>,
    /// Establisher frame (stack frame pointer)
    pub frame_pointer: u64,
}

impl ExceptionRegistrationRecord {
    pub const fn new() -> Self {
        Self {
            next: ptr::null_mut(),
            handler: None,
            frame_pointer: 0,
        }
    }
}

// Safety: Registration records are accessed only from the owning thread
unsafe impl Send for ExceptionRegistrationRecord {}
unsafe impl Sync for ExceptionRegistrationRecord {}

/// Sentinel value for end of exception chain
pub const EXCEPTION_CHAIN_END: *mut ExceptionRegistrationRecord =
    usize::MAX as *mut ExceptionRegistrationRecord;

/// Per-thread SEH state
struct ThreadSehState {
    /// Head of exception registration chain
    exception_list: *mut ExceptionRegistrationRecord,
    /// Pool of SEH frames for this thread
    frames: [ExceptionRegistrationRecord; MAX_SEH_FRAMES],
    /// Number of frames in use
    frame_count: usize,
}

impl ThreadSehState {
    const fn new() -> Self {
        Self {
            exception_list: EXCEPTION_CHAIN_END,
            frames: [ExceptionRegistrationRecord::new(); MAX_SEH_FRAMES],
            frame_count: 0,
        }
    }
}

// Safety: ThreadSehState is accessed under a lock and raw pointers
// point to data within the same structure
unsafe impl Send for ThreadSehState {}
unsafe impl Sync for ThreadSehState {}

/// Global SEH state (in a real implementation, this would be per-thread via TLS)
static SEH_STATE: Mutex<ThreadSehState> = Mutex::new(ThreadSehState::new());

/// Push an exception handler onto the current thread's SEH chain
///
/// # Arguments
/// * `handler` - The exception handler function
/// * `frame_pointer` - The stack frame pointer for this handler
///
/// # Returns
/// Pointer to the registration record, or null on failure
pub fn rtl_push_exception_handler(
    handler: SehExceptionHandler,
    frame_pointer: u64,
) -> *mut ExceptionRegistrationRecord {
    let mut state = SEH_STATE.lock();

    if state.frame_count >= MAX_SEH_FRAMES {
        return ptr::null_mut();
    }

    let index = state.frame_count;
    state.frames[index] = ExceptionRegistrationRecord {
        next: state.exception_list,
        handler: Some(handler),
        frame_pointer,
    };

    // Get pointer to the frame we just set up
    let frame_ptr = &mut state.frames[index] as *mut ExceptionRegistrationRecord;

    // Link into chain
    state.exception_list = frame_ptr;
    state.frame_count += 1;

    frame_ptr
}

/// Pop an exception handler from the current thread's SEH chain
///
/// # Arguments
/// * `registration` - The registration record to remove (must be head of chain)
///
/// # Returns
/// true if successful, false if the record wasn't found at head
pub fn rtl_pop_exception_handler(
    registration: *mut ExceptionRegistrationRecord,
) -> bool {
    let mut state = SEH_STATE.lock();

    if state.exception_list != registration {
        return false;
    }

    if state.exception_list == EXCEPTION_CHAIN_END {
        return false;
    }

    unsafe {
        state.exception_list = (*registration).next;
    }

    if state.frame_count > 0 {
        state.frame_count -= 1;
    }

    true
}

/// Get the current exception handler chain head
pub fn rtl_get_exception_list() -> *mut ExceptionRegistrationRecord {
    SEH_STATE.lock().exception_list
}

/// Set the exception handler chain head (used during unwind)
pub fn rtl_set_exception_list(list: *mut ExceptionRegistrationRecord) {
    SEH_STATE.lock().exception_list = list;
}

/// Walk the SEH chain and dispatch exception to handlers
///
/// # Arguments
/// * `exception_record` - The exception that occurred
/// * `context` - Thread context at time of exception
///
/// # Returns
/// true if a handler handled the exception (EXCEPTION_CONTINUE_EXECUTION)
/// false if no handler handled it (should try second chance or terminate)
pub fn rtl_dispatch_exception_seh(
    exception_record: *mut ExceptionRecord,
    context: *mut Context,
) -> bool {
    let state = SEH_STATE.lock();
    let mut current = state.exception_list;
    let mut nested_frame: *mut ExceptionRegistrationRecord = ptr::null_mut();

    drop(state); // Release lock before calling handlers

    while current != EXCEPTION_CHAIN_END && !current.is_null() {
        unsafe {
            let registration = &*current;

            // Check if we have a handler
            if let Some(handler) = registration.handler {
                // Set up dispatcher context
                let mut dispatcher_context = DispatcherContext::new();
                dispatcher_context.establisher_frame = registration.frame_pointer;
                dispatcher_context.context_record = context;

                // Get exception flags
                let exception_flags = if !exception_record.is_null() {
                    (*exception_record).exception_flags
                } else {
                    0
                };

                // Check for nested exception
                if !nested_frame.is_null() && current == nested_frame {
                    // Clear nested flag
                    if !exception_record.is_null() {
                        (*exception_record).exception_flags &= !ExceptionFlags::EXCEPTION_NESTED_CALL;
                    }
                    nested_frame = ptr::null_mut();
                }

                // Call the handler
                let disposition = handler(
                    exception_record,
                    registration.frame_pointer,
                    context,
                    &mut dispatcher_context,
                );

                match disposition {
                    d if d == ExceptionDisposition::EXCEPTION_CONTINUE_EXECUTION => {
                        // Handler handled the exception
                        if exception_flags & ExceptionFlags::EXCEPTION_NONCONTINUABLE != 0 {
                            // Can't continue from non-continuable exception
                            crate::serial_println!(
                                "[SEH] Handler tried to continue non-continuable exception"
                            );
                            return false;
                        }
                        crate::serial_println!("[SEH] Handler handled exception, continuing");
                        return true;
                    }
                    d if d == ExceptionDisposition::EXCEPTION_CONTINUE_SEARCH => {
                        // Try next handler
                        crate::serial_println!(
                            "[SEH] Handler at frame {:#x} passed, trying next",
                            registration.frame_pointer
                        );
                    }
                    d if d == ExceptionDisposition::EXCEPTION_EXECUTE_HANDLER => {
                        // Execute this handler (for __except blocks)
                        // This would involve unwinding to this frame
                        crate::serial_println!(
                            "[SEH] Handler at frame {:#x} will execute",
                            registration.frame_pointer
                        );
                        // In a full implementation, we'd unwind to this frame
                        // For now, treat as handled
                        return true;
                    }
                    _ => {
                        // Nested exception or other disposition
                        crate::serial_println!(
                            "[SEH] Handler returned disposition {}",
                            disposition
                        );
                        // Mark as nested and continue
                        if !exception_record.is_null() {
                            (*exception_record).exception_flags |=
                                ExceptionFlags::EXCEPTION_NESTED_CALL;
                        }
                        nested_frame = current;
                    }
                }
            }

            // Move to next handler in chain
            current = registration.next;
        }
    }

    // No handler handled the exception
    crate::serial_println!("[SEH] No handler found in chain");
    false
}

/// Get the count of registered SEH frames
pub fn rtl_get_seh_frame_count() -> usize {
    SEH_STATE.lock().frame_count
}

// =============================================================================
// Unhandled Exception Filter
// =============================================================================

/// Unhandled exception filter function type
pub type UnhandledExceptionFilter = fn(*mut ExceptionPointers) -> i32;

/// Global unhandled exception filter
static UNHANDLED_FILTER: Mutex<Option<UnhandledExceptionFilter>> = Mutex::new(None);

/// Set the unhandled exception filter
///
/// # Returns
/// The previous filter, or None if there was none
pub fn rtl_set_unhandled_exception_filter(
    filter: Option<UnhandledExceptionFilter>,
) -> Option<UnhandledExceptionFilter> {
    let mut current = UNHANDLED_FILTER.lock();
    let previous = *current;
    *current = filter;
    previous
}

/// Call the unhandled exception filter if set
///
/// # Returns
/// EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, or EXCEPTION_EXECUTE_HANDLER
pub fn rtl_call_unhandled_exception_filter(
    exception_record: *mut ExceptionRecord,
    context: *mut Context,
) -> i32 {
    let filter = *UNHANDLED_FILTER.lock();

    if let Some(filter_fn) = filter {
        let mut pointers = ExceptionPointers {
            exception_record,
            context_record: context,
        };
        filter_fn(&mut pointers)
    } else {
        // No filter set, continue search (will lead to termination)
        ExceptionDisposition::EXCEPTION_CONTINUE_SEARCH
    }
}

// =============================================================================
// Exception Dispatch Functions
// =============================================================================

/// Raise an exception in the current thread
///
/// This is the kernel implementation of NtRaiseException.
///
/// The exception dispatch order is:
/// 1. Vectored Exception Handlers (VEH) - global, first chance only
/// 2. Structured Exception Handlers (SEH) - frame-based
/// 3. Unhandled exception filter
/// 4. Second chance (usually terminates process)
///
/// # Arguments
/// * `exception_record` - The exception to raise
/// * `context` - Thread context at the time of the exception
/// * `first_chance` - True if this is the first chance to handle
///
/// # Safety
/// Must be called from thread context with valid pointers
pub unsafe fn ke_raise_exception(
    exception_record: *const ExceptionRecord,
    context: *mut Context,
    first_chance: bool,
) -> i32 {
    if exception_record.is_null() || context.is_null() {
        return -1; // STATUS_INVALID_PARAMETER
    }

    let record = &*exception_record;

    // Check if the exception is non-continuable and we're trying to continue
    if !record.is_continuable() && !first_chance {
        return 0xC0000025u32 as i32; // STATUS_NONCONTINUABLE_EXCEPTION
    }

    // Log the exception for debugging
    crate::serial_println!(
        "Exception: code={:#x} addr={:p} first_chance={}",
        record.exception_code,
        record.exception_address,
        first_chance
    );

    // First chance exception handling
    if first_chance {
        // Step 1: Call Vectored Exception Handlers (VEH)
        // VEH handlers are called before frame-based SEH
        if rtl_call_vectored_exception_handlers(
            exception_record as *mut ExceptionRecord,
            context,
        ) {
            // A VEH handler returned EXCEPTION_CONTINUE_EXECUTION
            crate::serial_println!("VEH handler handled exception, continuing execution");
            return 0; // STATUS_SUCCESS
        }

        // Step 2: Dispatch to frame-based SEH chain
        if rtl_dispatch_exception_seh(
            exception_record as *mut ExceptionRecord,
            context,
        ) {
            // An SEH handler handled the exception
            crate::serial_println!("SEH handler handled exception, continuing execution");
            return 0; // STATUS_SUCCESS
        }

        // Step 3: Call unhandled exception filter
        let filter_result = rtl_call_unhandled_exception_filter(
            exception_record as *mut ExceptionRecord,
            context,
        );

        if filter_result == ExceptionDisposition::EXCEPTION_CONTINUE_EXECUTION {
            crate::serial_println!("Unhandled filter handled exception, continuing");
            return 0; // STATUS_SUCCESS
        } else if filter_result == ExceptionDisposition::EXCEPTION_EXECUTE_HANDLER {
            // Execute handler (typically terminates process gracefully)
            crate::serial_println!("Unhandled filter requested handler execution");
            // Fall through to second chance
        }
        // EXCEPTION_CONTINUE_SEARCH falls through to second chance
    }

    // If first chance handling fails, this becomes a second chance exception
    // which typically results in process termination
    if !first_chance {
        crate::serial_println!(
            "Second chance exception not handled - process would be terminated"
        );
        // In a real implementation, we would terminate the process here
        // For kernel-mode exceptions, we might bugcheck
    }

    0 // STATUS_SUCCESS (exception was handled or logged)
}

/// Continue execution from an exception
///
/// This is the kernel implementation of NtContinue.
/// It restores the thread context and continues execution.
///
/// # Arguments
/// * `context` - Thread context to restore
/// * `test_alert` - If true, check for pending alerts
///
/// # Safety
/// Must be called from thread context with valid context pointer
pub unsafe fn ke_continue(context: *const Context, test_alert: bool) -> i32 {
    if context.is_null() {
        return -1; // STATUS_INVALID_PARAMETER
    }

    let ctx = &*context;

    // Get current thread
    let prcb = super::prcb::get_current_prcb_mut();
    let thread = prcb.current_thread;

    if thread.is_null() {
        return -1;
    }

    // If test_alert is set and we're alertable, check for APCs
    if test_alert && (*thread).alertable
        && (*thread).apc_state.user_apc_pending {
            super::apc::ki_deliver_apc(super::apc::ApcMode::UserMode);
            return 0x101; // STATUS_ALERTED
        }

    // Restore the thread context
    // This would normally update the trap frame on the stack
    // For now, we update the thread's saved context
    (*thread).context.rbx = ctx.rbx;
    (*thread).context.rbp = ctx.rbp;
    (*thread).context.r12 = ctx.r12;
    (*thread).context.r13 = ctx.r13;
    (*thread).context.r14 = ctx.r14;
    (*thread).context.r15 = ctx.r15;
    (*thread).context.rflags = ctx.e_flags as u64;
    (*thread).context.rip = ctx.rip;

    0 // STATUS_SUCCESS
}

/// Get the current thread's context
///
/// # Arguments
/// * `context` - Buffer to receive the context
/// * `context_flags` - Which parts of the context to retrieve
///
/// # Safety
/// Must be called from thread context with valid buffer
pub unsafe fn ke_get_context(context: *mut Context, context_flags: u32) -> i32 {
    if context.is_null() {
        return -1;
    }

    let prcb = super::prcb::get_current_prcb_mut();
    let thread = prcb.current_thread;

    if thread.is_null() {
        return -1;
    }

    let ctx = &mut *context;
    ctx.context_flags = context_flags;

    // Fill in the requested context portions
    if (context_flags & ContextFlags::CONTEXT_INTEGER) != 0 {
        ctx.rbx = (*thread).context.rbx;
        ctx.rbp = (*thread).context.rbp;
        ctx.r12 = (*thread).context.r12;
        ctx.r13 = (*thread).context.r13;
        ctx.r14 = (*thread).context.r14;
        ctx.r15 = (*thread).context.r15;
        // Other integer registers would come from the trap frame
    }

    if (context_flags & ContextFlags::CONTEXT_CONTROL) != 0 {
        ctx.rip = (*thread).context.rip;
        ctx.e_flags = (*thread).context.rflags as u32;
        // RSP would come from kernel_stack or trap frame
        ctx.rsp = (*thread).kernel_stack as u64;
        ctx.seg_cs = 0x33; // User code segment
        ctx.seg_ss = 0x2B; // User stack segment
    }

    0 // STATUS_SUCCESS
}

/// Set the current thread's context
///
/// # Arguments
/// * `context` - Context to set
///
/// # Safety
/// Must be called from thread context with valid context
pub unsafe fn ke_set_context(context: *const Context) -> i32 {
    if context.is_null() {
        return -1;
    }

    let prcb = super::prcb::get_current_prcb_mut();
    let thread = prcb.current_thread;

    if thread.is_null() {
        return -1;
    }

    let ctx = &*context;
    let flags = ctx.context_flags;

    // Set the requested context portions
    if (flags & ContextFlags::CONTEXT_INTEGER) != 0 {
        (*thread).context.rbx = ctx.rbx;
        (*thread).context.rbp = ctx.rbp;
        (*thread).context.r12 = ctx.r12;
        (*thread).context.r13 = ctx.r13;
        (*thread).context.r14 = ctx.r14;
        (*thread).context.r15 = ctx.r15;
    }

    if (flags & ContextFlags::CONTEXT_CONTROL) != 0 {
        (*thread).context.rip = ctx.rip;
        (*thread).context.rflags = ctx.e_flags as u64;
    }

    0 // STATUS_SUCCESS
}
