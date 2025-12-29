//! Kernel Bug Check Implementation (BSOD)
//!
//! This module implements the Windows NT KeBugCheck and KeBugCheckEx
//! functions which are called when the kernel detects an unrecoverable
//! error. When triggered, the system:
//!
//! 1. Disables interrupts and raises IRQL to HIGH_LEVEL
//! 2. Freezes all other processors (SMP systems)
//! 3. Displays a "Blue Screen of Death" with error information
//! 4. Optionally writes a crash dump
//! 5. Halts the system
//!
//! # Bug Check Codes
//!
//! Bug check codes (also called "STOP codes") are 32-bit values that
//! identify the type of error. Common codes include:
//! - IRQL_NOT_LESS_OR_EQUAL (0x0A): Invalid memory access at elevated IRQL
//! - KERNEL_MODE_EXCEPTION_NOT_HANDLED (0x8E): Unhandled exception
//! - PAGE_FAULT_IN_NONPAGED_AREA (0x50): Page fault in non-pageable memory
//!
//! # Windows Equivalent
//! This implements NT's bugcheck.c functionality.

use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

/// Bug check has been initiated (prevents recursive bugcheck)
static BUGCHECK_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Counter for nested bugcheck attempts
static BUGCHECK_COUNT: AtomicU32 = AtomicU32::new(0);

/// Bug check data - saved for debugging
pub static mut BUGCHECK_DATA: BugCheckData = BugCheckData::new();

/// Bug check information structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BugCheckData {
    /// The bug check code
    pub code: u32,
    /// First parameter
    pub parameter1: u64,
    /// Second parameter
    pub parameter2: u64,
    /// Third parameter
    pub parameter3: u64,
    /// Fourth parameter
    pub parameter4: u64,
}

impl BugCheckData {
    const fn new() -> Self {
        Self {
            code: 0,
            parameter1: 0,
            parameter2: 0,
            parameter3: 0,
            parameter4: 0,
        }
    }
}

// ============================================================================
// Bug Check Codes (STOP Codes)
// ============================================================================

pub mod codes {
    //! Bug check codes from Windows NT
    //!
    //! These are the "STOP codes" displayed on the Blue Screen.

    /// APC_INDEX_MISMATCH (0x01)
    /// APC disable count mismatch at system call return
    pub const APC_INDEX_MISMATCH: u32 = 0x00000001;

    /// DEVICE_QUEUE_NOT_BUSY (0x02)
    /// Device queue not busy when expected
    pub const DEVICE_QUEUE_NOT_BUSY: u32 = 0x00000002;

    /// INVALID_AFFINITY_SET (0x03)
    /// Invalid processor affinity set
    pub const INVALID_AFFINITY_SET: u32 = 0x00000003;

    /// INVALID_DATA_ACCESS_TRAP (0x04)
    /// Invalid data access trap
    pub const INVALID_DATA_ACCESS_TRAP: u32 = 0x00000004;

    /// INVALID_PROCESS_ATTACH_ATTEMPT (0x05)
    /// Invalid process attach attempt
    pub const INVALID_PROCESS_ATTACH_ATTEMPT: u32 = 0x00000005;

    /// INVALID_PROCESS_DETACH_ATTEMPT (0x06)
    /// Invalid process detach attempt
    pub const INVALID_PROCESS_DETACH_ATTEMPT: u32 = 0x00000006;

    /// INVALID_SOFTWARE_INTERRUPT (0x07)
    /// Invalid software interrupt
    pub const INVALID_SOFTWARE_INTERRUPT: u32 = 0x00000007;

    /// IRQL_NOT_DISPATCH_LEVEL (0x08)
    /// IRQL not at DISPATCH_LEVEL when expected
    pub const IRQL_NOT_DISPATCH_LEVEL: u32 = 0x00000008;

    /// IRQL_NOT_GREATER_OR_EQUAL (0x09)
    /// IRQL too low for operation
    pub const IRQL_NOT_GREATER_OR_EQUAL: u32 = 0x00000009;

    /// IRQL_NOT_LESS_OR_EQUAL (0x0A)
    /// Memory access at invalid IRQL
    /// Parameter1: Address referenced
    /// Parameter2: IRQL level
    /// Parameter3: Read (0) or Write (1)
    /// Parameter4: Address that referenced memory
    pub const IRQL_NOT_LESS_OR_EQUAL: u32 = 0x0000000A;

    /// NO_EXCEPTION_HANDLING_SUPPORT (0x0B)
    /// No exception handling support available
    pub const NO_EXCEPTION_HANDLING_SUPPORT: u32 = 0x0000000B;

    /// MAXIMUM_WAIT_OBJECTS_EXCEEDED (0x0C)
    /// Too many wait objects in multi-object wait
    pub const MAXIMUM_WAIT_OBJECTS_EXCEEDED: u32 = 0x0000000C;

    /// MUTEX_LEVEL_NUMBER_VIOLATION (0x0D)
    /// Mutex level ordering violation
    pub const MUTEX_LEVEL_NUMBER_VIOLATION: u32 = 0x0000000D;

    /// NO_USER_MODE_CONTEXT (0x0E)
    /// No user mode context available
    pub const NO_USER_MODE_CONTEXT: u32 = 0x0000000E;

    /// SPIN_LOCK_ALREADY_OWNED (0x0F)
    /// Attempt to acquire spinlock already owned
    pub const SPIN_LOCK_ALREADY_OWNED: u32 = 0x0000000F;

    /// SPIN_LOCK_NOT_OWNED (0x10)
    /// Attempt to release spinlock not owned
    pub const SPIN_LOCK_NOT_OWNED: u32 = 0x00000010;

    /// THREAD_NOT_MUTEX_OWNER (0x11)
    /// Thread releasing mutex it doesn't own
    pub const THREAD_NOT_MUTEX_OWNER: u32 = 0x00000011;

    /// TRAP_CAUSE_UNKNOWN (0x12)
    /// Unknown trap cause
    pub const TRAP_CAUSE_UNKNOWN: u32 = 0x00000012;

    /// KMODE_EXCEPTION_NOT_HANDLED (0x1E)
    /// Kernel mode exception not handled
    /// Parameter1: Exception code
    /// Parameter2: Exception address
    /// Parameter3: Parameter 0 of exception
    /// Parameter4: Parameter 1 of exception
    pub const KMODE_EXCEPTION_NOT_HANDLED: u32 = 0x0000001E;

    /// KERNEL_MODE_EXCEPTION_NOT_HANDLED (0x8E)
    /// Kernel mode exception not handled (different from 0x1E)
    pub const KERNEL_MODE_EXCEPTION_NOT_HANDLED: u32 = 0x0000008E;

    /// UNEXPECTED_KERNEL_MODE_TRAP (0x7F)
    /// Unexpected kernel mode trap
    /// Parameter1: Trap number
    pub const UNEXPECTED_KERNEL_MODE_TRAP: u32 = 0x0000007F;

    /// PAGE_FAULT_IN_NONPAGED_AREA (0x50)
    /// Page fault in non-pageable memory
    /// Parameter1: Faulting virtual address
    /// Parameter2: Read (0) or Write (1)
    /// Parameter3: Address that referenced memory
    /// Parameter4: Type (0=nonexec, 1=read, 2=write)
    pub const PAGE_FAULT_IN_NONPAGED_AREA: u32 = 0x00000050;

    /// NTFS_FILE_SYSTEM (0x24)
    /// NTFS file system error
    pub const NTFS_FILE_SYSTEM: u32 = 0x00000024;

    /// FAT_FILE_SYSTEM (0x23)
    /// FAT file system error
    pub const FAT_FILE_SYSTEM: u32 = 0x00000023;

    /// INACCESSIBLE_BOOT_DEVICE (0x7B)
    /// Boot device cannot be accessed
    pub const INACCESSIBLE_BOOT_DEVICE: u32 = 0x0000007B;

    /// DATA_BUS_ERROR (0x2E)
    /// Data bus parity error
    pub const DATA_BUS_ERROR: u32 = 0x0000002E;

    /// NO_MORE_SYSTEM_PTES (0x3F)
    /// System PTE exhaustion
    pub const NO_MORE_SYSTEM_PTES: u32 = 0x0000003F;

    /// DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1)
    /// Driver accessed pageable memory at elevated IRQL
    pub const DRIVER_IRQL_NOT_LESS_OR_EQUAL: u32 = 0x000000D1;

    /// DRIVER_CORRUPTED_EXPOOL (0xC5)
    /// Driver corrupted executive pool
    pub const DRIVER_CORRUPTED_EXPOOL: u32 = 0x000000C5;

    /// DRIVER_CORRUPTED_SYSPTES (0xDB)
    /// Driver corrupted system PTEs
    pub const DRIVER_CORRUPTED_SYSPTES: u32 = 0x000000DB;

    /// THREAD_STUCK_IN_DEVICE_DRIVER (0xEA)
    /// Thread stuck in device driver
    pub const THREAD_STUCK_IN_DEVICE_DRIVER: u32 = 0x000000EA;

    /// CRITICAL_PROCESS_DIED (0xEF)
    /// Critical process terminated
    pub const CRITICAL_PROCESS_DIED: u32 = 0x000000EF;

    /// MANUALLY_INITIATED_CRASH (0xE2)
    /// Crash initiated by user/debugger
    pub const MANUALLY_INITIATED_CRASH: u32 = 0x000000E2;

    /// KERNEL_SECURITY_CHECK_FAILURE (0x139)
    /// Kernel security check failure
    pub const KERNEL_SECURITY_CHECK_FAILURE: u32 = 0x00000139;

    /// INVALID_WORK_QUEUE_ITEM (0x96)
    /// Invalid work queue item
    pub const INVALID_WORK_QUEUE_ITEM: u32 = 0x00000096;

    /// SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (0x7E)
    /// System thread exception not handled
    pub const SYSTEM_THREAD_EXCEPTION_NOT_HANDLED: u32 = 0x0000007E;
}

// ============================================================================
// Bug Check Display
// ============================================================================

/// Display the Blue Screen of Death
fn display_bugcheck_screen(data: &BugCheckData) {
    // Clear screen and set blue background (if we have display support)
    // For now, output to serial console

    crate::serial_println!("");
    crate::serial_println!("===============================================================================");
    crate::serial_println!("                        *** STOP: 0x{:08X} ***", data.code);
    crate::serial_println!("===============================================================================");
    crate::serial_println!("");
    crate::serial_println!("A problem has been detected and Nostalgia OS has been shut down to prevent");
    crate::serial_println!("damage to your computer.");
    crate::serial_println!("");
    crate::serial_println!("{}",  bugcheck_code_name(data.code));
    crate::serial_println!("");
    crate::serial_println!("Technical information:");
    crate::serial_println!("");
    crate::serial_println!("*** STOP: 0x{:08X} (0x{:016X}, 0x{:016X}, 0x{:016X}, 0x{:016X})",
        data.code, data.parameter1, data.parameter2, data.parameter3, data.parameter4);
    crate::serial_println!("");

    // Additional information based on code
    display_code_specific_info(data);

    crate::serial_println!("");
    crate::serial_println!("===============================================================================");
    crate::serial_println!("                          System Halted");
    crate::serial_println!("===============================================================================");
}

/// Get the human-readable name for a bug check code
fn bugcheck_code_name(code: u32) -> &'static str {
    match code {
        codes::APC_INDEX_MISMATCH => "APC_INDEX_MISMATCH",
        codes::DEVICE_QUEUE_NOT_BUSY => "DEVICE_QUEUE_NOT_BUSY",
        codes::INVALID_AFFINITY_SET => "INVALID_AFFINITY_SET",
        codes::INVALID_DATA_ACCESS_TRAP => "INVALID_DATA_ACCESS_TRAP",
        codes::INVALID_PROCESS_ATTACH_ATTEMPT => "INVALID_PROCESS_ATTACH_ATTEMPT",
        codes::INVALID_PROCESS_DETACH_ATTEMPT => "INVALID_PROCESS_DETACH_ATTEMPT",
        codes::INVALID_SOFTWARE_INTERRUPT => "INVALID_SOFTWARE_INTERRUPT",
        codes::IRQL_NOT_DISPATCH_LEVEL => "IRQL_NOT_DISPATCH_LEVEL",
        codes::IRQL_NOT_GREATER_OR_EQUAL => "IRQL_NOT_GREATER_OR_EQUAL",
        codes::IRQL_NOT_LESS_OR_EQUAL => "IRQL_NOT_LESS_OR_EQUAL",
        codes::NO_EXCEPTION_HANDLING_SUPPORT => "NO_EXCEPTION_HANDLING_SUPPORT",
        codes::MAXIMUM_WAIT_OBJECTS_EXCEEDED => "MAXIMUM_WAIT_OBJECTS_EXCEEDED",
        codes::MUTEX_LEVEL_NUMBER_VIOLATION => "MUTEX_LEVEL_NUMBER_VIOLATION",
        codes::NO_USER_MODE_CONTEXT => "NO_USER_MODE_CONTEXT",
        codes::SPIN_LOCK_ALREADY_OWNED => "SPIN_LOCK_ALREADY_OWNED",
        codes::SPIN_LOCK_NOT_OWNED => "SPIN_LOCK_NOT_OWNED",
        codes::THREAD_NOT_MUTEX_OWNER => "THREAD_NOT_MUTEX_OWNER",
        codes::TRAP_CAUSE_UNKNOWN => "TRAP_CAUSE_UNKNOWN",
        codes::KMODE_EXCEPTION_NOT_HANDLED => "KMODE_EXCEPTION_NOT_HANDLED",
        codes::KERNEL_MODE_EXCEPTION_NOT_HANDLED => "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
        codes::UNEXPECTED_KERNEL_MODE_TRAP => "UNEXPECTED_KERNEL_MODE_TRAP",
        codes::PAGE_FAULT_IN_NONPAGED_AREA => "PAGE_FAULT_IN_NONPAGED_AREA",
        codes::NTFS_FILE_SYSTEM => "NTFS_FILE_SYSTEM",
        codes::FAT_FILE_SYSTEM => "FAT_FILE_SYSTEM",
        codes::INACCESSIBLE_BOOT_DEVICE => "INACCESSIBLE_BOOT_DEVICE",
        codes::DATA_BUS_ERROR => "DATA_BUS_ERROR",
        codes::NO_MORE_SYSTEM_PTES => "NO_MORE_SYSTEM_PTES",
        codes::DRIVER_IRQL_NOT_LESS_OR_EQUAL => "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        codes::DRIVER_CORRUPTED_EXPOOL => "DRIVER_CORRUPTED_EXPOOL",
        codes::DRIVER_CORRUPTED_SYSPTES => "DRIVER_CORRUPTED_SYSPTES",
        codes::THREAD_STUCK_IN_DEVICE_DRIVER => "THREAD_STUCK_IN_DEVICE_DRIVER",
        codes::CRITICAL_PROCESS_DIED => "CRITICAL_PROCESS_DIED",
        codes::MANUALLY_INITIATED_CRASH => "MANUALLY_INITIATED_CRASH",
        codes::KERNEL_SECURITY_CHECK_FAILURE => "KERNEL_SECURITY_CHECK_FAILURE",
        codes::INVALID_WORK_QUEUE_ITEM => "INVALID_WORK_QUEUE_ITEM",
        codes::SYSTEM_THREAD_EXCEPTION_NOT_HANDLED => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        _ => "UNKNOWN_BUGCHECK",
    }
}

/// Display code-specific diagnostic information
fn display_code_specific_info(data: &BugCheckData) {
    match data.code {
        codes::IRQL_NOT_LESS_OR_EQUAL | codes::DRIVER_IRQL_NOT_LESS_OR_EQUAL => {
            crate::serial_println!("  Faulting address: 0x{:016X}", data.parameter1);
            crate::serial_println!("  IRQL: {}", data.parameter2);
            crate::serial_println!("  Operation: {}", if data.parameter3 == 0 { "Read" } else { "Write" });
            crate::serial_println!("  Instruction at: 0x{:016X}", data.parameter4);
        }
        codes::PAGE_FAULT_IN_NONPAGED_AREA => {
            crate::serial_println!("  Faulting virtual address: 0x{:016X}", data.parameter1);
            crate::serial_println!("  Operation: {}", if data.parameter2 == 0 { "Read" } else { "Write" });
            crate::serial_println!("  Instruction at: 0x{:016X}", data.parameter3);
        }
        codes::KMODE_EXCEPTION_NOT_HANDLED | codes::KERNEL_MODE_EXCEPTION_NOT_HANDLED => {
            crate::serial_println!("  Exception code: 0x{:08X}", data.parameter1 as u32);
            crate::serial_println!("  Exception address: 0x{:016X}", data.parameter2);
        }
        codes::UNEXPECTED_KERNEL_MODE_TRAP => {
            let trap_name = match data.parameter1 {
                0 => "Divide by zero",
                1 => "Debug exception",
                2 => "NMI",
                3 => "Breakpoint",
                4 => "Overflow",
                5 => "Bounds check",
                6 => "Invalid opcode",
                7 => "Device not available",
                8 => "Double fault",
                10 => "Invalid TSS",
                11 => "Segment not present",
                12 => "Stack fault",
                13 => "General protection fault",
                14 => "Page fault",
                _ => "Unknown trap",
            };
            crate::serial_println!("  Trap: {} ({})", data.parameter1, trap_name);
        }
        _ => {}
    }
}

// ============================================================================
// Bug Check Functions
// ============================================================================

/// Crash the system with a bug check code
///
/// This is the main entry point for kernel crashes. It:
/// 1. Prevents interrupts and recursive bugchecks
/// 2. Displays the blue screen
/// 3. Halts the system
///
/// # Arguments
/// * `code` - The bug check code identifying the error
///
/// # Never Returns
/// This function halts the system and never returns.
pub fn ke_bugcheck(code: u32) -> ! {
    ke_bugcheck_ex(code, 0, 0, 0, 0)
}

/// Crash the system with a bug check code and parameters
///
/// Extended version of ke_bugcheck that allows passing diagnostic parameters.
///
/// # Arguments
/// * `code` - The bug check code identifying the error
/// * `p1` - First parameter (meaning depends on code)
/// * `p2` - Second parameter
/// * `p3` - Third parameter
/// * `p4` - Fourth parameter
///
/// # Never Returns
/// This function halts the system and never returns.
pub fn ke_bugcheck_ex(code: u32, p1: u64, p2: u64, p3: u64, p4: u64) -> ! {
    // Disable interrupts immediately
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }

    // Check for recursive bugcheck
    let count = BUGCHECK_COUNT.fetch_add(1, Ordering::SeqCst);
    if count > 0 {
        // Recursive bugcheck - just halt
        crate::serial_println!("!!! RECURSIVE BUGCHECK - HALTING !!!");
        halt_system();
    }

    // Mark bugcheck as active
    BUGCHECK_ACTIVE.store(true, Ordering::SeqCst);

    // Save bugcheck data
    unsafe {
        BUGCHECK_DATA = BugCheckData {
            code,
            parameter1: p1,
            parameter2: p2,
            parameter3: p3,
            parameter4: p4,
        };
    }

    // Display the blue screen
    display_bugcheck_screen(unsafe { &BUGCHECK_DATA });

    // TODO: Write crash dump

    // TODO: Call bugcheck callbacks

    // Halt the system
    halt_system()
}

/// Halt the system permanently
fn halt_system() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}

/// Check if a bugcheck is currently active
pub fn is_bugcheck_active() -> bool {
    BUGCHECK_ACTIVE.load(Ordering::SeqCst)
}

/// Get the current bugcheck data (if active)
pub fn get_bugcheck_data() -> Option<BugCheckData> {
    if is_bugcheck_active() {
        Some(unsafe { BUGCHECK_DATA })
    } else {
        None
    }
}

// ============================================================================
// Convenience Macros
// ============================================================================

/// Trigger a bugcheck with file and line information
#[macro_export]
macro_rules! bugcheck {
    ($code:expr) => {
        $crate::ke::bugcheck::ke_bugcheck($code)
    };
    ($code:expr, $p1:expr) => {
        $crate::ke::bugcheck::ke_bugcheck_ex($code, $p1 as u64, 0, 0, 0)
    };
    ($code:expr, $p1:expr, $p2:expr) => {
        $crate::ke::bugcheck::ke_bugcheck_ex($code, $p1 as u64, $p2 as u64, 0, 0)
    };
    ($code:expr, $p1:expr, $p2:expr, $p3:expr) => {
        $crate::ke::bugcheck::ke_bugcheck_ex($code, $p1 as u64, $p2 as u64, $p3 as u64, 0)
    };
    ($code:expr, $p1:expr, $p2:expr, $p3:expr, $p4:expr) => {
        $crate::ke::bugcheck::ke_bugcheck_ex($code, $p1 as u64, $p2 as u64, $p3 as u64, $p4 as u64)
    };
}
