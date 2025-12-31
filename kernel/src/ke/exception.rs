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
    const STATUS_INVALID_PARAMETER: i32 = 0xC000000Du32 as i32;

    if exception_record.is_null() || context.is_null() {
        return STATUS_INVALID_PARAMETER;
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
    const STATUS_INVALID_PARAMETER: i32 = 0xC000000Du32 as i32;
    const STATUS_NO_THREAD: i32 = 0xC000012Bu32 as i32;

    if context.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let ctx = &*context;

    // Get current thread
    let prcb = super::prcb::get_current_prcb_mut();
    let thread = prcb.current_thread;

    if thread.is_null() {
        return STATUS_NO_THREAD;
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
    const STATUS_INVALID_PARAMETER: i32 = 0xC000000Du32 as i32;
    const STATUS_NO_THREAD: i32 = 0xC000012Bu32 as i32;

    if context.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let prcb = super::prcb::get_current_prcb_mut();
    let thread = prcb.current_thread;

    if thread.is_null() {
        return STATUS_NO_THREAD;
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
    const STATUS_INVALID_PARAMETER: i32 = 0xC000000Du32 as i32;
    const STATUS_NO_THREAD: i32 = 0xC000012Bu32 as i32;

    if context.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let prcb = super::prcb::get_current_prcb_mut();
    let thread = prcb.current_thread;

    if thread.is_null() {
        return STATUS_NO_THREAD;
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

// =============================================================================
// Exception History Tracking
// =============================================================================

/// Maximum number of exceptions to track in history
pub const EXCEPTION_HISTORY_SIZE: usize = 64;

/// Exception history entry
#[derive(Clone, Copy)]
pub struct ExceptionHistoryEntry {
    /// Exception code
    pub code: u32,
    /// Exception address (RIP where exception occurred)
    pub address: u64,
    /// Additional info (e.g., fault address for access violation)
    pub info: u64,
    /// Stack pointer at time of exception
    pub rsp: u64,
    /// Timestamp (TSC value)
    pub timestamp: u64,
    /// Exception flags
    pub flags: u32,
    /// Was this handled?
    pub handled: bool,
    /// First chance or second chance
    pub first_chance: bool,
    /// Entry is valid
    pub valid: bool,
}

impl ExceptionHistoryEntry {
    pub const fn new() -> Self {
        Self {
            code: 0,
            address: 0,
            info: 0,
            rsp: 0,
            timestamp: 0,
            flags: 0,
            handled: false,
            first_chance: true,
            valid: false,
        }
    }
}

/// Exception history buffer
struct ExceptionHistory {
    /// Circular buffer of entries
    entries: [ExceptionHistoryEntry; EXCEPTION_HISTORY_SIZE],
    /// Index of next entry to write
    write_index: usize,
    /// Total exceptions recorded (may wrap)
    total_count: u64,
}

impl ExceptionHistory {
    const fn new() -> Self {
        Self {
            entries: [ExceptionHistoryEntry::new(); EXCEPTION_HISTORY_SIZE],
            write_index: 0,
            total_count: 0,
        }
    }
}

/// Global exception history
static EXCEPTION_HISTORY: Mutex<ExceptionHistory> = Mutex::new(ExceptionHistory::new());

/// Record an exception in the history
pub fn record_exception(
    code: u32,
    address: u64,
    info: u64,
    rsp: u64,
    flags: u32,
    first_chance: bool,
    handled: bool,
) {
    let timestamp = read_tsc();

    let mut history = EXCEPTION_HISTORY.lock();
    let index = history.write_index;

    history.entries[index] = ExceptionHistoryEntry {
        code,
        address,
        info,
        rsp,
        timestamp,
        flags,
        handled,
        first_chance,
        valid: true,
    };

    history.write_index = (index + 1) % EXCEPTION_HISTORY_SIZE;
    history.total_count += 1;
}

/// Read TSC (Time Stamp Counter)
#[inline]
fn read_tsc() -> u64 {
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
}

/// Get exception history entries
///
/// Returns entries from most recent to oldest
pub fn get_exception_history() -> ([ExceptionHistoryEntry; EXCEPTION_HISTORY_SIZE], usize, u64) {
    let history = EXCEPTION_HISTORY.lock();
    (history.entries, history.write_index, history.total_count)
}

/// Clear exception history
pub fn clear_exception_history() {
    let mut history = EXCEPTION_HISTORY.lock();
    history.entries = [ExceptionHistoryEntry::new(); EXCEPTION_HISTORY_SIZE];
    history.write_index = 0;
    history.total_count = 0;
}

/// Get exception code name
pub fn exception_code_name(code: u32) -> &'static str {
    match code {
        ExceptionCode::EXCEPTION_ACCESS_VIOLATION => "ACCESS_VIOLATION",
        ExceptionCode::EXCEPTION_ARRAY_BOUNDS_EXCEEDED => "ARRAY_BOUNDS",
        ExceptionCode::EXCEPTION_BREAKPOINT => "BREAKPOINT",
        ExceptionCode::EXCEPTION_DATATYPE_MISALIGNMENT => "MISALIGNMENT",
        ExceptionCode::EXCEPTION_FLT_DENORMAL_OPERAND => "FLT_DENORMAL",
        ExceptionCode::EXCEPTION_FLT_DIVIDE_BY_ZERO => "FLT_DIV_ZERO",
        ExceptionCode::EXCEPTION_FLT_INEXACT_RESULT => "FLT_INEXACT",
        ExceptionCode::EXCEPTION_FLT_INVALID_OPERATION => "FLT_INVALID",
        ExceptionCode::EXCEPTION_FLT_OVERFLOW => "FLT_OVERFLOW",
        ExceptionCode::EXCEPTION_FLT_STACK_CHECK => "FLT_STACK",
        ExceptionCode::EXCEPTION_FLT_UNDERFLOW => "FLT_UNDERFLOW",
        ExceptionCode::EXCEPTION_ILLEGAL_INSTRUCTION => "ILLEGAL_INSN",
        ExceptionCode::EXCEPTION_IN_PAGE_ERROR => "IN_PAGE_ERROR",
        ExceptionCode::EXCEPTION_INT_DIVIDE_BY_ZERO => "INT_DIV_ZERO",
        ExceptionCode::EXCEPTION_INT_OVERFLOW => "INT_OVERFLOW",
        ExceptionCode::EXCEPTION_INVALID_DISPOSITION => "INVALID_DISP",
        ExceptionCode::EXCEPTION_NONCONTINUABLE_EXCEPTION => "NONCONTINUABLE",
        ExceptionCode::EXCEPTION_PRIV_INSTRUCTION => "PRIV_INSN",
        ExceptionCode::EXCEPTION_SINGLE_STEP => "SINGLE_STEP",
        ExceptionCode::EXCEPTION_STACK_OVERFLOW => "STACK_OVERFLOW",
        // CPU exceptions (interrupt vectors)
        0x00 => "DIVIDE_ERROR",
        0x01 => "DEBUG",
        0x02 => "NMI",
        0x03 => "BREAKPOINT",
        0x04 => "OVERFLOW",
        0x05 => "BOUND_RANGE",
        0x06 => "INVALID_OPCODE",
        0x07 => "DEVICE_NOT_AVAIL",
        0x08 => "DOUBLE_FAULT",
        0x0A => "INVALID_TSS",
        0x0B => "SEGMENT_NOT_PRESENT",
        0x0C => "STACK_FAULT",
        0x0D => "GENERAL_PROTECTION",
        0x0E => "PAGE_FAULT",
        0x10 => "X87_FPU_ERROR",
        0x11 => "ALIGNMENT_CHECK",
        0x12 => "MACHINE_CHECK",
        0x13 => "SIMD_FP",
        0x14 => "VIRTUALIZATION",
        0x15 => "CONTROL_PROTECTION",
        _ => "UNKNOWN",
    }
}

// =============================================================================
// KiDispatchException - Main Exception Dispatch (NT 5.2 Compatible)
// =============================================================================

use crate::arch::x86_64::context::KTrapFrame;

/// Processor mode enumeration
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessorMode {
    /// Kernel mode (ring 0)
    KernelMode = 0,
    /// User mode (ring 3)
    UserMode = 1,
}

/// Exception dispatch statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ExceptionDispatchStats {
    /// Total exceptions dispatched
    pub total_dispatched: u64,
    /// Kernel-mode exceptions
    pub kernel_exceptions: u64,
    /// User-mode exceptions
    pub user_exceptions: u64,
    /// First chance exceptions
    pub first_chance: u64,
    /// Second chance exceptions
    pub second_chance: u64,
    /// Exceptions handled by VEH
    pub handled_by_veh: u64,
    /// Exceptions handled by SEH
    pub handled_by_seh: u64,
    /// Exceptions handled by debugger
    pub handled_by_debugger: u64,
    /// Unhandled exceptions (bugcheck/terminate)
    pub unhandled: u64,
}

/// Global exception dispatch statistics
static EXCEPTION_DISPATCH_STATS: Mutex<ExceptionDispatchStats> =
    Mutex::new(ExceptionDispatchStats {
        total_dispatched: 0,
        kernel_exceptions: 0,
        user_exceptions: 0,
        first_chance: 0,
        second_chance: 0,
        handled_by_veh: 0,
        handled_by_seh: 0,
        handled_by_debugger: 0,
        unhandled: 0,
    });

/// Get exception dispatch statistics
pub fn ke_get_exception_stats() -> ExceptionDispatchStats {
    *EXCEPTION_DISPATCH_STATS.lock()
}

/// Convert trap frame to CONTEXT structure
///
/// This function moves the selected contents of the specified trap frame
/// into the specified context frame according to the specified context flags.
///
/// # Arguments
/// * `trap_frame` - Pointer to the trap frame
/// * `context` - Pointer to the context frame to fill
///
/// # Safety
/// Both pointers must be valid
pub unsafe fn ke_context_from_kframes(
    trap_frame: *const KTrapFrame,
    context: *mut Context,
) {
    if trap_frame.is_null() || context.is_null() {
        return;
    }

    let tf = &*trap_frame;
    let ctx = &mut *context;

    // Always set full context flags
    ctx.context_flags = ContextFlags::CONTEXT_FULL | ContextFlags::CONTEXT_SEGMENTS;

    // Control registers (RIP, RSP, RFLAGS, CS, SS)
    ctx.rip = tf.rip;
    ctx.rsp = tf.rsp;
    ctx.e_flags = tf.rflags as u32;
    ctx.seg_cs = tf.cs as u16;
    ctx.seg_ss = tf.ss as u16;

    // Segment registers
    ctx.seg_ds = tf.seg_ds;
    ctx.seg_es = tf.seg_es;
    ctx.seg_fs = tf.seg_fs;
    ctx.seg_gs = tf.seg_gs;

    // Integer registers (volatile/caller-saved)
    ctx.rax = tf.rax;
    ctx.rcx = tf.rcx;
    ctx.rdx = tf.rdx;
    ctx.r8 = tf.r8;
    ctx.r9 = tf.r9;
    ctx.r10 = tf.r10;
    ctx.r11 = tf.r11;

    // Integer registers (non-volatile/callee-saved)
    ctx.rbx = tf.rbx;
    ctx.rbp = tf.rbp;
    ctx.rsi = tf.rsi;
    ctx.rdi = tf.rdi;
    ctx.r12 = tf.r12;
    ctx.r13 = tf.r13;
    ctx.r14 = tf.r14;
    ctx.r15 = tf.r15;
}

/// Convert CONTEXT structure back to trap frame
///
/// This function moves the selected contents of the specified context frame
/// back into the specified trap frame according to the context flags.
///
/// # Arguments
/// * `context` - Pointer to the context frame
/// * `trap_frame` - Pointer to the trap frame to fill
/// * `previous_mode` - Kernel or user mode
///
/// # Safety
/// Both pointers must be valid
pub unsafe fn ke_context_to_kframes(
    context: *const Context,
    trap_frame: *mut KTrapFrame,
    previous_mode: ProcessorMode,
) {
    if context.is_null() || trap_frame.is_null() {
        return;
    }

    let ctx = &*context;
    let tf = &mut *trap_frame;
    let flags = ctx.context_flags;

    // Control registers
    if (flags & ContextFlags::CONTEXT_CONTROL) != 0 {
        // Sanitize RFLAGS - user mode can't change certain flags
        let mut rflags = ctx.e_flags as u64;
        if previous_mode == ProcessorMode::UserMode {
            // Preserve system flags, allow user-modifiable flags
            const USER_FLAGS_MASK: u64 = 0x3C0CD5; // CF, PF, AF, ZF, SF, TF, DF, OF
            rflags = (tf.rflags & !USER_FLAGS_MASK) | (rflags & USER_FLAGS_MASK);
            // Always keep IF set for user mode
            rflags |= 0x200;
        }
        tf.rflags = rflags;
        tf.rip = ctx.rip;
        tf.rsp = ctx.rsp;
    }

    // Segment registers are fixed for user/kernel mode
    if previous_mode == ProcessorMode::UserMode {
        tf.cs = 0x33;  // User code segment | RPL 3
        tf.ss = 0x2B;  // User data segment | RPL 3
    } else {
        tf.cs = 0x08;  // Kernel code segment
        tf.ss = 0x10;  // Kernel data segment
    }

    // Integer registers
    if (flags & ContextFlags::CONTEXT_INTEGER) != 0 {
        tf.rax = ctx.rax;
        tf.rcx = ctx.rcx;
        tf.rdx = ctx.rdx;
        tf.r8 = ctx.r8;
        tf.r9 = ctx.r9;
        tf.r10 = ctx.r10;
        tf.r11 = ctx.r11;
        tf.rbx = ctx.rbx;
        tf.rbp = ctx.rbp;
        tf.rsi = ctx.rsi;
        tf.rdi = ctx.rdi;
        tf.r12 = ctx.r12;
        tf.r13 = ctx.r13;
        tf.r14 = ctx.r14;
        tf.r15 = ctx.r15;
    }
}

/// Main exception dispatch function (KiDispatchException equivalent)
///
/// This function is called to dispatch an exception to the proper mode and
/// to cause the exception dispatcher to be called.
///
/// For kernel mode:
/// - Give debugger first chance
/// - Call RtlDispatchException (VEH + SEH)
/// - Give debugger second chance
/// - Bugcheck if still unhandled
///
/// For user mode:
/// - Send to debug port (if present)
/// - Transfer exception info to user stack
/// - Redirect execution to user exception dispatcher
///
/// # Arguments
/// * `exception_record` - The exception that occurred
/// * `trap_frame` - The trap frame at time of exception
/// * `previous_mode` - Whether exception occurred in kernel or user mode
/// * `first_chance` - True if this is the first chance
///
/// # Safety
/// Must be called from interrupt/exception context with valid pointers
pub unsafe fn ki_dispatch_exception(
    exception_record: *mut ExceptionRecord,
    trap_frame: *mut KTrapFrame,
    previous_mode: ProcessorMode,
    first_chance: bool,
) {
    if exception_record.is_null() || trap_frame.is_null() {
        return;
    }

    // Update statistics
    {
        let mut stats = EXCEPTION_DISPATCH_STATS.lock();
        stats.total_dispatched += 1;
        if previous_mode == ProcessorMode::KernelMode {
            stats.kernel_exceptions += 1;
        } else {
            stats.user_exceptions += 1;
        }
        if first_chance {
            stats.first_chance += 1;
        } else {
            stats.second_chance += 1;
        }
    }

    // Build context from trap frame
    let mut context = Context::new();
    ke_context_from_kframes(trap_frame, &mut context);

    // If the exception is a breakpoint, convert to fault (decrement RIP)
    if (*exception_record).exception_code == ExceptionCode::EXCEPTION_BREAKPOINT {
        context.rip = context.rip.wrapping_sub(1);
    }

    // Record exception in history
    record_exception(
        (*exception_record).exception_code,
        (*exception_record).exception_address as u64,
        if (*exception_record).number_parameters > 0 {
            (*exception_record).exception_information[0]
        } else {
            0
        },
        context.rsp,
        (*exception_record).exception_flags,
        first_chance,
        false, // Will update if handled
    );

    let exception_code = (*exception_record).exception_code;
    let exception_addr = (*exception_record).exception_address as u64;

    match previous_mode {
        ProcessorMode::KernelMode => {
            // ================================================================
            // Kernel Mode Exception Dispatch
            // ================================================================

            if first_chance {
                // First chance: Try debugger, then VEH/SEH

                // Step 1: Give kernel debugger first chance
                // TODO: Call KiDebugRoutine if connected
                let debugger_handled = false;
                if debugger_handled {
                    EXCEPTION_DISPATCH_STATS.lock().handled_by_debugger += 1;
                    ke_context_to_kframes(&context, trap_frame, previous_mode);
                    return;
                }

                // Step 2: Call VEH handlers
                if rtl_call_vectored_exception_handlers(exception_record, &mut context) {
                    crate::serial_println!(
                        "[EXCEPTION] Kernel exception handled by VEH: code={:#x} addr={:#x}",
                        exception_code, exception_addr
                    );
                    EXCEPTION_DISPATCH_STATS.lock().handled_by_veh += 1;
                    ke_context_to_kframes(&context, trap_frame, previous_mode);
                    return;
                }

                // Step 3: Dispatch to SEH chain
                if rtl_dispatch_exception_seh(exception_record, &mut context) {
                    crate::serial_println!(
                        "[EXCEPTION] Kernel exception handled by SEH: code={:#x} addr={:#x}",
                        exception_code, exception_addr
                    );
                    EXCEPTION_DISPATCH_STATS.lock().handled_by_seh += 1;
                    ke_context_to_kframes(&context, trap_frame, previous_mode);
                    return;
                }
            }

            // Second chance or unhandled first chance
            // TODO: Give kernel debugger second chance

            // Exception not handled - this is a kernel bugcheck
            EXCEPTION_DISPATCH_STATS.lock().unhandled += 1;
            crate::serial_println!(
                "*** KERNEL EXCEPTION NOT HANDLED ***"
            );
            crate::serial_println!(
                "Exception: {} ({:#x}) at {:#x}",
                exception_code_name(exception_code),
                exception_code,
                exception_addr
            );
            crate::serial_println!(
                "RIP={:#x} RSP={:#x} RBP={:#x}",
                context.rip, context.rsp, context.rbp
            );
            crate::serial_println!(
                "RAX={:#x} RBX={:#x} RCX={:#x} RDX={:#x}",
                context.rax, context.rbx, context.rcx, context.rdx
            );

            // In a real implementation, we would bugcheck here
            // For now, we panic
            panic!(
                "KMODE_EXCEPTION_NOT_HANDLED: {} ({:#x}) at {:#x}",
                exception_code_name(exception_code),
                exception_code,
                exception_addr
            );
        }

        ProcessorMode::UserMode => {
            // ================================================================
            // User Mode Exception Dispatch
            // ================================================================

            if first_chance {
                // First chance user mode exception

                // Step 1: Check if process has a debugger attached
                // If so, send to debugger via debug port
                let process = crate::ps::get_current_process();
                if !process.is_null() && crate::dbgk::dbgk_is_process_being_debugged(process as usize) {
                    // Forward to debugger via DbgkForwardException
                    // If debugger handles it, return
                    // TODO: Implement DbgkForwardException
                    crate::serial_println!(
                        "[EXCEPTION] User exception forwarded to debugger: code={:#x}",
                        exception_code
                    );
                }

                // Step 2: Transfer exception to user mode
                // This involves:
                // 1. Allocating space on user stack for EXCEPTION_RECORD and CONTEXT
                // 2. Copying the structures to user stack
                // 3. Setting up trap frame to return to user exception dispatcher

                // For now, we use kernel-side dispatch as user-mode dispatcher
                // isn't set up yet. In a full implementation:
                // - Copy exception record to user stack
                // - Copy context to user stack
                // - Set RIP to KiUserExceptionDispatcher
                // - Return to let trap handler restore and IRETQ

                // Step 3: Call VEH handlers (kernel-side for now)
                if rtl_call_vectored_exception_handlers(exception_record, &mut context) {
                    crate::serial_println!(
                        "[EXCEPTION] User exception handled by VEH: code={:#x}",
                        exception_code
                    );
                    EXCEPTION_DISPATCH_STATS.lock().handled_by_veh += 1;
                    ke_context_to_kframes(&context, trap_frame, previous_mode);
                    return;
                }

                // Step 4: Dispatch to SEH chain
                if rtl_dispatch_exception_seh(exception_record, &mut context) {
                    crate::serial_println!(
                        "[EXCEPTION] User exception handled by SEH: code={:#x}",
                        exception_code
                    );
                    EXCEPTION_DISPATCH_STATS.lock().handled_by_seh += 1;
                    ke_context_to_kframes(&context, trap_frame, previous_mode);
                    return;
                }

                // Unhandled first chance - will become second chance via NtRaiseException
                crate::serial_println!(
                    "[EXCEPTION] User exception unhandled on first chance: {} ({:#x}) at {:#x}",
                    exception_code_name(exception_code),
                    exception_code,
                    exception_addr
                );
            }

            // Second chance or unhandled first chance
            // In a full implementation:
            // - Send to debugger port (second chance)
            // - Send to subsystem port
            // - Terminate the thread/process

            EXCEPTION_DISPATCH_STATS.lock().unhandled += 1;
            crate::serial_println!(
                "*** USER EXCEPTION NOT HANDLED (SECOND CHANCE) ***"
            );
            crate::serial_println!(
                "Exception: {} ({:#x}) at {:#x}",
                exception_code_name(exception_code),
                exception_code,
                exception_addr
            );
            crate::serial_println!("Thread would be terminated.");

            // For now, restore context and let it crash naturally
            // In a real implementation, we'd terminate the process
            ke_context_to_kframes(&context, trap_frame, previous_mode);
        }
    }
}

/// Dispatch exception from interrupt handler
///
/// Convenience wrapper that determines processor mode from trap frame.
///
/// # Safety
/// Must be called from interrupt context with valid pointers
pub unsafe fn ki_dispatch_exception_from_trap(
    exception_code: u32,
    exception_address: u64,
    trap_frame: *mut KTrapFrame,
    first_chance: bool,
    param0: u64,
    param1: u64,
) {
    if trap_frame.is_null() {
        return;
    }

    // Determine previous mode from CS in trap frame
    let tf = &*trap_frame;
    let previous_mode = if (tf.cs & 0x3) == 0 {
        ProcessorMode::KernelMode
    } else {
        ProcessorMode::UserMode
    };

    // Build exception record
    let mut exception_record = ExceptionRecord::new();
    exception_record.exception_code = exception_code;
    exception_record.exception_flags = 0;
    exception_record.exception_record = ptr::null_mut();
    exception_record.exception_address = exception_address as *mut u8;
    exception_record.number_parameters = 2;
    exception_record.exception_information[0] = param0;
    exception_record.exception_information[1] = param1;

    ki_dispatch_exception(
        &mut exception_record,
        trap_frame,
        previous_mode,
        first_chance,
    );
}
