//! Context switching implementation for x86_64
//!
//! Provides low-level context switch routines that save and restore
//! CPU register state between threads.
//!
//! The x86_64 ABI requires preserving: RBX, RBP, R12-R15
//! We also save/restore RFLAGS and RSP (via stack manipulation)
//!
//! # Trap Frame
//!
//! The KTRAP_FRAME structure captures the complete CPU state when
//! transitioning from user mode to kernel mode (interrupt/exception/syscall).
//! This is the NT-compatible trap frame layout for x86_64.

use core::arch::naked_asm;
use crate::ke::thread::KThread;

// ============================================================================
// Trap Frame (KTRAP_FRAME)
// ============================================================================

/// Trap Frame - captures complete CPU state for user/kernel transitions
///
/// This structure is laid out to match the hardware interrupt frame
/// and stores all registers needed to resume user-mode execution.
///
/// The structure is designed so the hardware-pushed values (SS, RSP, RFLAGS,
/// CS, RIP, and optionally error code) are at the end, and software-saved
/// registers are at the beginning.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KTrapFrame {
    // ---- Software-saved general-purpose registers ----
    /// Home space for parameters (shadow space)
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,

    /// Previous mode (0 = kernel, 1 = user)
    pub previous_mode: u8,
    /// Exception active flag
    pub exception_active: u8,
    /// Reserved/padding
    pub _reserved1: [u8; 6],

    // Volatile registers (caller-saved)
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,

    // Non-volatile registers (callee-saved) - saved on exception
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // Segment selectors
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,

    /// Exception/trap number
    pub trap_number: u32,

    /// Error code (pushed by some exceptions, 0 otherwise)
    pub error_code: u64,

    // ---- Hardware-pushed interrupt frame (IRETQ frame) ----
    /// Instruction pointer
    pub rip: u64,
    /// Code segment
    pub cs: u64,
    /// CPU flags
    pub rflags: u64,
    /// Stack pointer (user-mode RSP)
    pub rsp: u64,
    /// Stack segment
    pub ss: u64,
}

impl KTrapFrame {
    /// Create a new zeroed trap frame
    pub const fn new() -> Self {
        Self {
            p1_home: 0,
            p2_home: 0,
            p3_home: 0,
            p4_home: 0,
            p5_home: 0,
            previous_mode: 0,
            exception_active: 0,
            _reserved1: [0; 6],
            rax: 0,
            rcx: 0,
            rdx: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            seg_ds: 0,
            seg_es: 0,
            seg_fs: 0,
            seg_gs: 0,
            trap_number: 0,
            error_code: 0,
            rip: 0,
            cs: 0,
            rflags: 0,
            rsp: 0,
            ss: 0,
        }
    }

    /// Create a trap frame for entering user mode
    ///
    /// Sets up the frame to execute at the given entry point with the given stack.
    pub fn for_user_mode(entry_point: u64, user_stack: u64) -> Self {
        let mut frame = Self::new();

        // User mode segments with RPL 3
        frame.cs = 0x23;  // User code segment | RPL 3
        frame.ss = 0x1B;  // User data segment | RPL 3
        frame.seg_ds = 0x1B;
        frame.seg_es = 0x1B;

        // Entry point and stack
        frame.rip = entry_point;
        frame.rsp = user_stack;

        // RFLAGS with IF set (interrupts enabled)
        frame.rflags = 0x202;

        // Mark as user mode
        frame.previous_mode = 1;

        frame
    }

    /// Check if this frame is from user mode
    #[inline]
    pub fn is_user_mode(&self) -> bool {
        self.previous_mode != 0
    }

    /// Get the size of the trap frame
    #[inline]
    pub const fn size() -> usize {
        core::mem::size_of::<Self>()
    }
}

impl Default for KTrapFrame {
    fn default() -> Self {
        Self::new()
    }
}

/// Previous processor mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessorMode {
    /// Kernel mode (ring 0)
    Kernel = 0,
    /// User mode (ring 3)
    User = 1,
}

// ============================================================================
// Thread Context for User-Mode Threads
// ============================================================================

/// User-mode thread context
///
/// This is stored in the KTHREAD and contains the saved trap frame
/// for a user-mode thread when it's not currently running.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UserContext {
    /// The saved trap frame
    pub trap_frame: KTrapFrame,
    /// Kernel stack pointer (for switching to this thread)
    pub kernel_stack: u64,
    /// CR3 (page table) for this thread's process
    pub cr3: u64,
    /// Whether this context is valid
    pub valid: bool,
}

impl UserContext {
    /// Create a new invalid context
    pub const fn new() -> Self {
        Self {
            trap_frame: KTrapFrame::new(),
            kernel_stack: 0,
            cr3: 0,
            valid: false,
        }
    }

    /// Initialize for user-mode execution
    pub fn init_user(&mut self, entry_point: u64, user_stack: u64, cr3: u64) {
        self.trap_frame = KTrapFrame::for_user_mode(entry_point, user_stack);
        self.cr3 = cr3;
        self.valid = true;
    }
}

/// Offset of kernel_stack field in KThread structure
/// This must match the actual offset in the KThread struct!
/// Layout: state(1) + priority(1) + base_priority(1) + quantum(1) +
///         priority_decrement(1) + saturation(1) + padding(2) +
///         wait_list_entry(16) + thread_list_entry(16) = 40
const KTHREAD_KERNEL_STACK_OFFSET: usize = 40;

/// Swap context from old thread to new thread
///
/// Saves callee-saved registers of old thread and restores new thread's registers.
/// Returns when the old thread is resumed.
///
/// # Safety
/// - Both thread pointers must be valid
/// - New thread must have a valid kernel stack set up
/// - Must be called with interrupts disabled
#[unsafe(naked)]
pub unsafe extern "C" fn ki_swap_context(_old_thread: *mut KThread, _new_thread: *mut KThread) {
    naked_asm!(
        // Save callee-saved registers on old thread's stack
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "pushfq",

        // Save current stack pointer to old thread's kernel_stack
        // old_thread is in rdi, kernel_stack offset is KTHREAD_KERNEL_STACK_OFFSET
        "mov [rdi + {stack_offset}], rsp",

        // Load new thread's stack pointer
        // new_thread is in rsi
        "mov rsp, [rsi + {stack_offset}]",

        // Restore callee-saved registers from new thread's stack
        "popfq",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",

        // Return to new thread (rip is on stack from original call)
        "ret",
        stack_offset = const KTHREAD_KERNEL_STACK_OFFSET,
    )
}

/// Load context for initial thread entry (no old thread to save)
///
/// Used when starting the first thread or switching from no thread.
///
/// # Safety
/// - Thread pointer must be valid
/// - Thread must have a valid kernel stack with context set up
/// - Must be called with interrupts disabled
#[unsafe(naked)]
pub unsafe extern "C" fn ki_load_context(_new_thread: *mut KThread) {
    naked_asm!(
        // Load new thread's stack pointer
        // new_thread is in rdi
        "mov rsp, [rdi + {stack_offset}]",

        // Restore callee-saved registers from new thread's stack
        "popfq",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",

        // Return to thread entry point (rip on stack)
        "ret",
        stack_offset = const KTHREAD_KERNEL_STACK_OFFSET,
    )
}

/// Set up a thread's initial stack for first context switch
///
/// Prepares the stack so that ki_swap_context or ki_load_context
/// will properly start the thread at its entry point.
///
/// # Safety
/// - stack_top must point to the top (highest address) of a valid stack
/// - entry_point must be a valid function pointer
pub unsafe fn setup_initial_context(
    thread: *mut KThread,
    stack_top: *mut u8,
    entry_point: fn(),
) {
    // Stack layout (growing downward from stack_top):
    // [stack_top]
    //   - return address (entry_point)  <- 8 bytes
    //   - rbx                           <- 8 bytes
    //   - rbp                           <- 8 bytes
    //   - r12                           <- 8 bytes
    //   - r13                           <- 8 bytes
    //   - r14                           <- 8 bytes
    //   - r15                           <- 8 bytes
    //   - rflags                        <- 8 bytes
    // [kernel_stack points here]

    let mut sp = stack_top as usize;

    // Push return address (entry point)
    sp -= 8;
    *(sp as *mut u64) = entry_point as usize as u64;

    // Push callee-saved registers (all zero for new thread)
    sp -= 8;
    *(sp as *mut u64) = 0; // rbx

    sp -= 8;
    *(sp as *mut u64) = 0; // rbp

    sp -= 8;
    *(sp as *mut u64) = 0; // r12

    sp -= 8;
    *(sp as *mut u64) = 0; // r13

    sp -= 8;
    *(sp as *mut u64) = 0; // r14

    sp -= 8;
    *(sp as *mut u64) = 0; // r15

    // Push rflags (interrupts enabled)
    sp -= 8;
    *(sp as *mut u64) = 0x202; // IF flag set

    // Set thread's kernel_stack to point to the prepared context
    (*thread).kernel_stack = sp as *mut u8;
}

// ============================================================================
// User-Mode Context Switching
// ============================================================================

/// Set up a user-mode thread's initial kernel stack
///
/// Prepares the kernel stack with a trap frame so that when we
/// switch to this thread, we can IRETQ into user mode.
///
/// # Safety
/// - kernel_stack_top must point to the top of a valid kernel stack
/// - entry_point and user_stack must be valid user-mode addresses
pub unsafe fn setup_user_thread_context(
    thread: *mut KThread,
    kernel_stack_top: *mut u8,
    entry_point: u64,
    user_stack: u64,
) {
    // Create the trap frame for initial user-mode entry
    let trap_frame = KTrapFrame::for_user_mode(entry_point, user_stack);

    // Calculate where to place the trap frame on the kernel stack
    let frame_size = core::mem::size_of::<KTrapFrame>();
    let frame_ptr = kernel_stack_top.sub(frame_size) as *mut KTrapFrame;

    // Write the trap frame to the stack
    *frame_ptr = trap_frame;

    // Now set up the kernel context that will lead to the trap frame
    // When ki_swap_context loads this context, it will pop callee-saved
    // registers then "ret" to a trampoline that does IRETQ

    let mut sp = frame_ptr as usize;

    // Push the address of the IRETQ trampoline as the "return address"
    sp -= 8;
    *(sp as *mut u64) = ki_return_to_user as *const () as usize as u64;

    // Push callee-saved registers (all zero for new thread)
    sp -= 8;
    *(sp as *mut u64) = 0; // rbx
    sp -= 8;
    *(sp as *mut u64) = 0; // rbp
    sp -= 8;
    *(sp as *mut u64) = 0; // r12
    sp -= 8;
    *(sp as *mut u64) = 0; // r13
    sp -= 8;
    *(sp as *mut u64) = 0; // r14
    sp -= 8;
    *(sp as *mut u64) = 0; // r15

    // Push rflags (interrupts disabled - will be re-enabled by IRETQ)
    sp -= 8;
    *(sp as *mut u64) = 0x002; // No IF

    // Set thread's kernel_stack to point to the prepared context
    (*thread).kernel_stack = sp as *mut u8;
}

/// Trampoline to return to user mode via IRETQ
///
/// This is called when a user-mode thread is scheduled.
/// The trap frame is already set up on the stack above us.
#[unsafe(naked)]
pub unsafe extern "C" fn ki_return_to_user() {
    naked_asm!(
        // At this point, RSP points just below the trap frame
        // We need to restore all registers from the trap frame and IRETQ

        // Skip the parameter homes and previous_mode (48 bytes)
        "add rsp, 48",

        // Restore volatile registers
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop r11",

        // Restore non-volatile registers
        "pop rbx",
        "pop rbp",
        "pop rsi",
        "pop rdi",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",

        // Skip segment selectors and trap_number (12 bytes)
        "add rsp, 12",

        // Skip error code (8 bytes)
        "add rsp, 8",

        // Now RSP points to the IRETQ frame (RIP, CS, RFLAGS, RSP, SS)
        // Execute IRETQ to enter user mode
        "iretq",
    )
}

/// Save a trap frame from the current stack
///
/// Called when entering kernel mode from user mode.
/// Saves all registers to the trap frame structure.
///
/// # Safety
/// Must be called immediately after interrupt entry before registers are clobbered.
#[allow(dead_code)]
pub unsafe fn save_trap_frame(frame: *mut KTrapFrame) {
    core::arch::asm!(
        // Save all general-purpose registers
        "mov [{frame} + 48], rax",   // rax
        "mov [{frame} + 56], rcx",   // rcx
        "mov [{frame} + 64], rdx",   // rdx
        "mov [{frame} + 72], r8",    // r8
        "mov [{frame} + 80], r9",    // r9
        "mov [{frame} + 88], r10",   // r10
        "mov [{frame} + 96], r11",   // r11
        "mov [{frame} + 104], rbx",  // rbx
        "mov [{frame} + 112], rbp",  // rbp
        "mov [{frame} + 120], rsi",  // rsi
        "mov [{frame} + 128], rdi",  // rdi
        "mov [{frame} + 136], r12",  // r12
        "mov [{frame} + 144], r13",  // r13
        "mov [{frame} + 152], r14",  // r14
        "mov [{frame} + 160], r15",  // r15
        frame = in(reg) frame,
        options(nostack, preserves_flags),
    );

    // Save segment registers
    let mut ds: u16;
    let mut es: u16;
    core::arch::asm!(
        "mov {ds:x}, ds",
        "mov {es:x}, es",
        ds = out(reg) ds,
        es = out(reg) es,
        options(nostack, nomem, preserves_flags),
    );
    (*frame).seg_ds = ds;
    (*frame).seg_es = es;
}

/// Restore trap frame and return to user mode
///
/// Restores all registers from the trap frame and executes IRETQ.
/// Does not return.
///
/// # Safety
/// - frame must point to a valid trap frame
/// - The frame's CS, SS must have RPL 3 for user mode
#[allow(dead_code)]
pub unsafe fn restore_trap_frame(frame: *const KTrapFrame) -> ! {
    core::arch::asm!(
        // Load the trap frame pointer
        "mov rsp, {frame}",

        // Skip parameter homes (40 bytes)
        "add rsp, 40",

        // Skip previous_mode, exception_active, reserved (8 bytes)
        "add rsp, 8",

        // Restore volatile registers
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop r11",

        // Restore non-volatile registers
        "pop rbx",
        "pop rbp",
        "pop rsi",
        "pop rdi",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",

        // Skip segment selectors and trap_number (12 bytes)
        "add rsp, 12",

        // Skip error code (8 bytes)
        "add rsp, 8",

        // IRETQ frame is now at RSP
        "iretq",

        frame = in(reg) frame,
        options(noreturn),
    );
}

/// Switch from kernel thread context to user thread context
///
/// This is used when scheduling a user-mode thread that was preempted.
///
/// # Safety
/// - trap_frame must point to a valid saved user trap frame
/// - user_cr3 must be a valid user-mode page table
#[allow(dead_code)]
pub unsafe fn switch_to_user_context(trap_frame: *const KTrapFrame, user_cr3: u64) -> ! {
    // Switch to user page tables
    core::arch::asm!(
        "mov cr3, {cr3}",
        cr3 = in(reg) user_cr3,
        options(nostack),
    );

    // Restore trap frame and IRETQ
    restore_trap_frame(trap_frame)
}
