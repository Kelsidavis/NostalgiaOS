//! System Call (SYSCALL/SYSRET) support for x86_64
//!
//! This module implements the fast system call mechanism using the SYSCALL
//! instruction. On x86_64, SYSCALL is the preferred method for entering
//! kernel mode from user space.
//!
//! ## MSR Configuration
//! - STAR (0xC0000081): Segment selectors for SYSCALL/SYSRET
//! - LSTAR (0xC0000082): 64-bit syscall entry point
//! - SFMASK (0xC0000084): RFLAGS mask (bits to clear on SYSCALL)
//!
//! ## Calling Convention
//! - RAX: System call number
//! - RDI, RSI, RDX, R10, R8, R9: Arguments 1-6
//! - RAX: Return value
//! - RCX: Destroyed (contains return RIP)
//! - R11: Destroyed (contains return RFLAGS)

use core::arch::{asm, naked_asm};

/// MSR addresses for syscall configuration
mod msr {
    pub const STAR: u32 = 0xC000_0081;   // Segment selectors
    pub const LSTAR: u32 = 0xC000_0082;  // 64-bit syscall entry
    pub const CSTAR: u32 = 0xC000_0083;  // Compatibility mode entry (not used)
    pub const SFMASK: u32 = 0xC000_0084; // RFLAGS mask
    pub const EFER: u32 = 0xC000_0080;   // Extended Feature Enable Register
}

/// EFER bits
mod efer {
    pub const SCE: u64 = 1 << 0; // System Call Extensions (enable SYSCALL/SYSRET)
}

/// RFLAGS bits to clear on syscall entry
/// Clear IF (interrupts), TF (trap), DF (direction), AC (alignment check)
const SFMASK_VALUE: u64 = 0x4700; // IF | TF | DF | AC | NT

/// Maximum number of syscalls
pub const MAX_SYSCALLS: usize = 256;

/// NTSTATUS codes for syscall returns
pub mod status {
    pub const STATUS_SUCCESS: isize = 0;
    pub const STATUS_INVALID_PARAMETER: isize = 0xC000000Du32 as isize;
    pub const STATUS_ACCESS_VIOLATION: isize = 0xC0000005u32 as isize;
    pub const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;
    pub const STATUS_NOT_IMPLEMENTED: isize = 0xC0000002u32 as isize;
    pub const STATUS_ACCESS_DENIED: isize = 0xC0000022u32 as isize;
    pub const STATUS_INSUFFICIENT_RESOURCES: isize = 0xC000009Au32 as isize;
    pub const STATUS_OBJECT_TYPE_MISMATCH: isize = 0xC0000024u32 as isize;
    pub const STATUS_HANDLE_NOT_CLOSABLE: isize = 0xC0000235u32 as isize;
    pub const STATUS_TIMEOUT: isize = 0x00000102;
    pub const STATUS_PENDING: isize = 0x00000103;
    pub const STATUS_WAIT_0: isize = 0x00000000;
    pub const STATUS_ABANDONED_WAIT_0: isize = 0x00000080;
}

use status::*;

/// System call numbers (NT-compatible naming)
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    // Process/Thread control
    NtTerminateProcess = 0,
    NtTerminateThread = 1,
    NtCreateThread = 2,
    NtGetCurrentProcessId = 3,
    NtGetCurrentThreadId = 4,
    NtYieldExecution = 5,
    NtDelayExecution = 6,

    // Memory management
    NtAllocateVirtualMemory = 10,
    NtFreeVirtualMemory = 11,
    NtProtectVirtualMemory = 12,
    NtQueryVirtualMemory = 13,

    // File operations
    NtCreateFile = 20,
    NtOpenFile = 21,
    NtReadFile = 22,
    NtWriteFile = 23,
    NtClose = 24,
    NtQueryInformationFile = 25,
    NtSetInformationFile = 26,
    NtDeleteFile = 27,
    NtQueryDirectoryFile = 28,
    NtLockFile = 29,

    // Synchronization
    NtWaitForSingleObject = 30,
    NtWaitForMultipleObjects = 31,
    NtSetEvent = 32,
    NtResetEvent = 33,
    NtCreateEvent = 34,
    NtReleaseSemaphore = 35,
    NtCreateSemaphore = 36,
    NtReleaseMutant = 37,
    NtCreateMutant = 38,
    NtSignalAndWaitForSingleObject = 39,

    // Section objects (shared memory/file mapping)
    NtCreateSection = 40,
    NtOpenSection = 41,
    NtMapViewOfSection = 42,
    NtUnmapViewOfSection = 43,
    NtExtendSection = 44,
    NtQuerySection = 45,

    // I/O Completion Ports
    NtCreateIoCompletion = 46,
    NtSetIoCompletion = 47,
    NtRemoveIoCompletion = 48,
    NtQueryIoCompletion = 49,

    // Debug/Console
    NtWriteVirtualMemory = 50,
    NtReadVirtualMemory = 51,
    NtDebugPrint = 52,

    // Timer operations
    NtCreateTimer = 53,
    NtOpenTimer = 54,
    NtSetTimer = 55,
    NtCancelTimer = 56,
    NtQueryTimer = 57,
    NtQueryEvent = 58,
    NtQuerySemaphore = 59,

    // Registry operations
    NtCreateKey = 60,
    NtOpenKey = 61,
    NtCloseKey = 62,
    NtQueryValueKey = 63,
    NtSetValueKey = 64,
    NtDeleteKey = 65,
    NtDeleteValueKey = 66,
    NtEnumerateKey = 67,
    NtEnumerateValueKey = 68,
    NtQueryKey = 69,

    // LPC (Local Procedure Call) operations
    NtCreatePort = 70,
    NtConnectPort = 71,
    NtListenPort = 72,
    NtAcceptConnectPort = 73,
    NtRequestPort = 74,
    NtRequestWaitReplyPort = 75,
    NtReplyPort = 76,
    NtReplyWaitReceivePort = 77,
    NtClosePort = 78,
    NtQueryInformationPort = 79,

    // Object/Handle operations
    NtDuplicateHandle = 80,
    NtQueryObject = 81,
    NtSetInformationObject = 82,
    NtWaitForMultipleObjects32 = 83,

    // Process operations
    NtOpenProcess = 90,
    NtQueryInformationProcess = 91,
    NtSetInformationProcess = 92,
    NtSuspendProcess = 93,
    NtResumeProcess = 94,

    // Thread operations
    NtOpenThread = 95,
    NtQueryInformationThread = 96,
    NtSetInformationThread = 97,
    NtSuspendThread = 98,
    NtResumeThread = 99,

    // Security/Token operations
    NtOpenProcessToken = 100,
    NtOpenThreadToken = 101,
    NtQueryInformationToken = 102,
    NtSetInformationToken = 103,
    NtDuplicateToken = 104,
    NtAdjustPrivilegesToken = 105,
    NtAdjustGroupsToken = 106,
    NtImpersonateThread = 107,
    NtCreateToken = 108,
    NtFilterToken = 109,

    // Virtual Memory extended operations
    NtFlushVirtualMemory = 110,
    NtLockVirtualMemory = 111,
    NtUnlockVirtualMemory = 112,

    // Debug operations
    NtCreateDebugObject = 120,
    NtDebugActiveProcess = 121,
    NtRemoveProcessDebug = 122,
    NtWaitForDebugEvent = 123,
    NtDebugContinue = 124,

    // Exception handling
    NtRaiseException = 130,
    NtContinue = 131,
    NtGetContextThread = 132,
    NtSetContextThread = 133,
    NtQueryMutant = 134,
    NtClearEvent = 135,
    NtPulseEvent = 136,

    // Process creation (extended)
    NtCreateProcess = 140,
    NtCreateProcessEx = 141,

    // Job objects
    NtCreateJobObject = 150,
    NtOpenJobObject = 151,
    NtAssignProcessToJobObject = 152,
    NtQueryInformationJobObject = 153,
    NtSetInformationJobObject = 154,
    NtTerminateJobObject = 155,
    NtIsProcessInJob = 156,

    // System information
    NtQuerySystemInformation = 160,
    NtSetSystemInformation = 161,

    // Time
    NtQuerySystemTime = 170,
    NtQueryPerformanceCounter = 171,

    // APC and Alert operations
    NtQueueApcThread = 180,
    NtTestAlert = 181,
    NtAlertThread = 182,
    NtAlertResumeThread = 183,

    // Extended file operations
    NtDeviceIoControlFile = 190,
    NtFsControlFile = 191,
    NtFlushBuffersFile = 192,
    NtCancelIoFile = 193,
    NtUnlockFile = 194,
    NtSetFileCompletionNotificationModes = 195,

    // Object namespace operations
    NtCreateSymbolicLinkObject = 200,
    NtOpenSymbolicLinkObject = 201,
    NtQuerySymbolicLinkObject = 202,
    NtCreateDirectoryObject = 203,
    NtOpenDirectoryObject = 204,
    NtQueryDirectoryObject = 205,

    // Security operations
    NtAccessCheck = 210,
    NtPrivilegeCheck = 211,
    NtAccessCheckAndAuditAlarm = 212,

    // Power management
    NtSetSystemPowerState = 220,
    NtInitiatePowerAction = 221,
}

/// Syscall handler function type
/// Arguments: (arg1, arg2, arg3, arg4, arg5, arg6) -> result
pub type SyscallHandler = fn(usize, usize, usize, usize, usize, usize) -> isize;

/// Syscall dispatch table
static mut SYSCALL_TABLE: [Option<SyscallHandler>; MAX_SYSCALLS] = [None; MAX_SYSCALLS];

// ============================================================================
// Syscall Tracing
// ============================================================================

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

/// Maximum number of traced syscalls to buffer
const MAX_TRACE_ENTRIES: usize = 64;

/// Syscall trace entry
#[derive(Clone, Copy, Debug, Default)]
pub struct SyscallTraceEntry {
    /// Syscall number
    pub syscall_num: u32,
    /// First argument
    pub arg1: u64,
    /// Second argument
    pub arg2: u64,
    /// Result code
    pub result: i64,
    /// Timestamp (ticks)
    pub timestamp: u64,
}

/// Trace buffer state
struct TraceBuffer {
    entries: [SyscallTraceEntry; MAX_TRACE_ENTRIES],
    head: usize,
    count: usize,
}

impl TraceBuffer {
    const fn new() -> Self {
        Self {
            entries: [SyscallTraceEntry {
                syscall_num: 0,
                arg1: 0,
                arg2: 0,
                result: 0,
                timestamp: 0,
            }; MAX_TRACE_ENTRIES],
            head: 0,
            count: 0,
        }
    }

    fn push(&mut self, entry: SyscallTraceEntry) {
        self.entries[self.head] = entry;
        self.head = (self.head + 1) % MAX_TRACE_ENTRIES;
        if self.count < MAX_TRACE_ENTRIES {
            self.count += 1;
        }
    }

    fn clear(&mut self) {
        self.head = 0;
        self.count = 0;
    }
}

/// Global trace state
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static TRACE_FILTER: AtomicU32 = AtomicU32::new(0xFFFFFFFF); // Trace all by default
static TRACE_BUFFER: Mutex<TraceBuffer> = Mutex::new(TraceBuffer::new());

/// Enable syscall tracing
pub fn syscall_trace_enable() {
    TRACE_ENABLED.store(true, Ordering::SeqCst);
    crate::serial_println!("[STRACE] Syscall tracing enabled");
}

/// Disable syscall tracing
pub fn syscall_trace_disable() {
    TRACE_ENABLED.store(false, Ordering::SeqCst);
    crate::serial_println!("[STRACE] Syscall tracing disabled");
}

/// Check if tracing is enabled
pub fn syscall_trace_is_enabled() -> bool {
    TRACE_ENABLED.load(Ordering::Relaxed)
}

/// Clear the trace buffer
pub fn syscall_trace_clear() {
    TRACE_BUFFER.lock().clear();
    TRACE_COUNT.store(0, Ordering::SeqCst);
    crate::serial_println!("[STRACE] Trace buffer cleared");
}

/// Get total trace count
pub fn syscall_trace_count() -> u64 {
    TRACE_COUNT.load(Ordering::Relaxed)
}

/// Set trace filter (bitmask of syscall categories)
pub fn syscall_trace_set_filter(filter: u32) {
    TRACE_FILTER.store(filter, Ordering::SeqCst);
}

/// Get current trace filter
pub fn syscall_trace_get_filter() -> u32 {
    TRACE_FILTER.load(Ordering::Relaxed)
}

extern crate alloc;

/// Get traced entries (returns up to `max_entries` most recent)
pub fn syscall_trace_get_entries(max_entries: usize) -> alloc::vec::Vec<SyscallTraceEntry> {
    use alloc::vec::Vec;

    let buffer = TRACE_BUFFER.lock();
    let count = core::cmp::min(max_entries, buffer.count);
    let mut result = Vec::with_capacity(count);

    // Get entries in order (oldest to newest)
    let start = if buffer.count >= MAX_TRACE_ENTRIES {
        buffer.head
    } else {
        0
    };

    for i in 0..count {
        let idx = (start + buffer.count - count + i) % MAX_TRACE_ENTRIES;
        result.push(buffer.entries[idx]);
    }

    result
}

/// Get syscall name from number
pub fn syscall_name(num: usize) -> &'static str {
    match num {
        0 => "NtTerminateProcess",
        1 => "NtTerminateThread",
        2 => "NtCreateThread",
        3 => "NtGetCurrentProcessId",
        4 => "NtGetCurrentThreadId",
        5 => "NtYieldExecution",
        6 => "NtDelayExecution",
        10 => "NtAllocateVirtualMemory",
        11 => "NtFreeVirtualMemory",
        12 => "NtProtectVirtualMemory",
        13 => "NtQueryVirtualMemory",
        20 => "NtCreateFile",
        21 => "NtOpenFile",
        22 => "NtReadFile",
        23 => "NtWriteFile",
        24 => "NtClose",
        25 => "NtQueryInformationFile",
        26 => "NtSetInformationFile",
        27 => "NtDeleteFile",
        28 => "NtQueryDirectoryFile",
        29 => "NtLockFile",
        30 => "NtWaitForSingleObject",
        31 => "NtWaitForMultipleObjects",
        32 => "NtSetEvent",
        33 => "NtResetEvent",
        34 => "NtCreateEvent",
        35 => "NtReleaseSemaphore",
        36 => "NtCreateSemaphore",
        40 => "NtCreateSection",
        41 => "NtOpenSection",
        42 => "NtMapViewOfSection",
        43 => "NtUnmapViewOfSection",
        52 => "NtDebugPrint",
        60 => "NtCreateKey",
        61 => "NtOpenKey",
        62 => "NtCloseKey",
        63 => "NtQueryValueKey",
        64 => "NtSetValueKey",
        80 => "NtDuplicateHandle",
        81 => "NtQueryObject",
        90 => "NtSuspendThread",
        91 => "NtResumeThread",
        92 => "NtSuspendProcess",
        93 => "NtResumeProcess",
        100 => "NtQuerySystemInformation",
        110 => "NtLockVirtualMemory",
        111 => "NtUnlockVirtualMemory",
        _ => "Unknown",
    }
}

/// Record a syscall trace entry
fn trace_syscall(syscall_num: usize, arg1: usize, arg2: usize, result: isize) {
    if !TRACE_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    // Increment trace count
    TRACE_COUNT.fetch_add(1, Ordering::Relaxed);

    // Create entry
    let entry = SyscallTraceEntry {
        syscall_num: syscall_num as u32,
        arg1: arg1 as u64,
        arg2: arg2 as u64,
        result: result as i64,
        timestamp: crate::hal::rtc::get_system_time(),
    };

    // Add to buffer
    TRACE_BUFFER.lock().push(entry);
}

/// Read an MSR
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
        options(nomem, nostack, preserves_flags)
    );
    ((hi as u64) << 32) | (lo as u64)
}

/// Write an MSR
#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") lo,
        in("edx") hi,
        options(nomem, nostack, preserves_flags)
    );
}

/// Initialize syscall support
///
/// Sets up the MSRs for SYSCALL/SYSRET instruction support.
///
/// # Safety
/// Must be called once during kernel initialization, after GDT is set up.
pub unsafe fn init() {
    // Enable SYSCALL/SYSRET in EFER
    let efer = rdmsr(msr::EFER);
    wrmsr(msr::EFER, efer | efer::SCE);

    // Set up STAR register
    // Bits 47:32 = kernel CS (SYSCALL loads CS from here, SS from here + 8)
    // Bits 63:48 = user CS base (SYSRET loads CS from here + 16, SS from here + 8)
    //
    // For our GDT layout:
    // - Kernel code: 0x08, Kernel data: 0x10
    // - User data: 0x18 (0x1B with RPL 3), User code: 0x20 (0x23 with RPL 3)
    //
    // SYSCALL: CS = STAR[47:32], SS = STAR[47:32] + 8
    //   So STAR[47:32] = 0x08 => CS = 0x08, SS = 0x10 ✓
    //
    // SYSRET (64-bit): CS = STAR[63:48] + 16, SS = STAR[63:48] + 8
    //   We need CS = 0x20|3 = 0x23, SS = 0x18|3 = 0x1B
    //   So STAR[63:48] = 0x10 => CS = 0x10 + 16 = 0x20 (CPU adds RPL 3)
    //                        => SS = 0x10 + 8 = 0x18 (CPU adds RPL 3)
    let kernel_cs = 0x08u64;
    let user_cs_base = 0x10u64; // SYSRET will add 16 for CS, 8 for SS
    let star = (user_cs_base << 48) | (kernel_cs << 32);
    wrmsr(msr::STAR, star);

    // Set syscall entry point
    let syscall_entry_addr = syscall_entry as *const () as u64;
    wrmsr(msr::LSTAR, syscall_entry_addr);

    // Set compatibility mode entry (not used, but set anyway)
    wrmsr(msr::CSTAR, 0);

    // Set RFLAGS mask - these bits are cleared on SYSCALL entry
    wrmsr(msr::SFMASK, SFMASK_VALUE);

    // Initialize syscall table with default handlers
    init_syscall_table();

    crate::serial_println!("[SYSCALL] Initialized syscall support");
    crate::serial_println!("[SYSCALL] STAR={:#x}, LSTAR={:#x}, SFMASK={:#x}",
        star, syscall_entry_addr, SFMASK_VALUE);
}

/// Initialize the syscall dispatch table
unsafe fn init_syscall_table() {
    // Clear all entries
    for entry in SYSCALL_TABLE.iter_mut() {
        *entry = None;
    }

    // Register default syscall handlers
    register_syscall(SyscallNumber::NtTerminateProcess as usize, sys_terminate_process);
    register_syscall(SyscallNumber::NtTerminateThread as usize, sys_terminate_thread);
    register_syscall(SyscallNumber::NtCreateThread as usize, sys_create_thread);
    register_syscall(SyscallNumber::NtGetCurrentProcessId as usize, sys_get_current_process_id);
    register_syscall(SyscallNumber::NtGetCurrentThreadId as usize, sys_get_current_thread_id);
    register_syscall(SyscallNumber::NtYieldExecution as usize, sys_yield_execution);
    register_syscall(SyscallNumber::NtDelayExecution as usize, sys_delay_execution);
    register_syscall(SyscallNumber::NtDebugPrint as usize, sys_debug_print);
    register_syscall(SyscallNumber::NtClose as usize, sys_close);

    // File operation syscalls
    register_syscall(SyscallNumber::NtCreateFile as usize, sys_create_file);
    register_syscall(SyscallNumber::NtOpenFile as usize, sys_open_file);
    register_syscall(SyscallNumber::NtReadFile as usize, sys_read_file);
    register_syscall(SyscallNumber::NtWriteFile as usize, sys_write_file);
    register_syscall(SyscallNumber::NtQueryInformationFile as usize, sys_query_information_file);
    register_syscall(SyscallNumber::NtSetInformationFile as usize, sys_set_information_file);
    register_syscall(SyscallNumber::NtDeleteFile as usize, sys_delete_file);
    register_syscall(SyscallNumber::NtQueryDirectoryFile as usize, sys_query_directory_file);
    register_syscall(SyscallNumber::NtLockFile as usize, sys_lock_file);

    // Synchronization syscalls
    register_syscall(SyscallNumber::NtWaitForSingleObject as usize, sys_wait_for_single_object);
    register_syscall(SyscallNumber::NtWaitForMultipleObjects as usize, sys_wait_for_multiple_objects);
    register_syscall(SyscallNumber::NtSetEvent as usize, sys_set_event);
    register_syscall(SyscallNumber::NtResetEvent as usize, sys_reset_event);
    register_syscall(SyscallNumber::NtCreateEvent as usize, sys_create_event);
    register_syscall(SyscallNumber::NtReleaseSemaphore as usize, sys_release_semaphore);
    register_syscall(SyscallNumber::NtCreateSemaphore as usize, sys_create_semaphore);
    register_syscall(SyscallNumber::NtReleaseMutant as usize, sys_release_mutant);
    register_syscall(SyscallNumber::NtCreateMutant as usize, sys_create_mutant);
    register_syscall(SyscallNumber::NtSignalAndWaitForSingleObject as usize, sys_signal_and_wait_for_single_object);

    // Timer syscalls
    register_syscall(SyscallNumber::NtCreateTimer as usize, sys_create_timer);
    register_syscall(SyscallNumber::NtOpenTimer as usize, sys_open_timer);
    register_syscall(SyscallNumber::NtSetTimer as usize, sys_set_timer);
    register_syscall(SyscallNumber::NtCancelTimer as usize, sys_cancel_timer);
    register_syscall(SyscallNumber::NtQueryTimer as usize, sys_query_timer);
    register_syscall(SyscallNumber::NtQueryEvent as usize, sys_query_event);
    register_syscall(SyscallNumber::NtQuerySemaphore as usize, sys_query_semaphore);
    register_syscall(SyscallNumber::NtQueryMutant as usize, sys_query_mutant);
    register_syscall(SyscallNumber::NtClearEvent as usize, sys_clear_event);
    register_syscall(SyscallNumber::NtPulseEvent as usize, sys_pulse_event);

    // Memory management syscalls
    register_syscall(SyscallNumber::NtAllocateVirtualMemory as usize, sys_allocate_virtual_memory);
    register_syscall(SyscallNumber::NtFreeVirtualMemory as usize, sys_free_virtual_memory);
    register_syscall(SyscallNumber::NtProtectVirtualMemory as usize, sys_protect_virtual_memory);
    register_syscall(SyscallNumber::NtQueryVirtualMemory as usize, sys_query_virtual_memory);
    register_syscall(SyscallNumber::NtReadVirtualMemory as usize, sys_read_virtual_memory);
    register_syscall(SyscallNumber::NtWriteVirtualMemory as usize, sys_write_virtual_memory);

    // Section (shared memory) syscalls
    register_syscall(SyscallNumber::NtCreateSection as usize, sys_create_section);
    register_syscall(SyscallNumber::NtMapViewOfSection as usize, sys_map_view_of_section);
    register_syscall(SyscallNumber::NtUnmapViewOfSection as usize, sys_unmap_view_of_section);
    register_syscall(SyscallNumber::NtQuerySection as usize, sys_query_section);

    // I/O Completion Port syscalls
    register_syscall(SyscallNumber::NtCreateIoCompletion as usize, sys_create_io_completion);
    register_syscall(SyscallNumber::NtSetIoCompletion as usize, sys_set_io_completion);
    register_syscall(SyscallNumber::NtRemoveIoCompletion as usize, sys_remove_io_completion);

    // Registry syscalls
    register_syscall(SyscallNumber::NtCreateKey as usize, sys_create_key);
    register_syscall(SyscallNumber::NtOpenKey as usize, sys_open_key);
    register_syscall(SyscallNumber::NtCloseKey as usize, sys_close_key);
    register_syscall(SyscallNumber::NtQueryValueKey as usize, sys_query_value_key);
    register_syscall(SyscallNumber::NtSetValueKey as usize, sys_set_value_key);
    register_syscall(SyscallNumber::NtDeleteKey as usize, sys_delete_key);
    register_syscall(SyscallNumber::NtDeleteValueKey as usize, sys_delete_value_key);
    register_syscall(SyscallNumber::NtEnumerateKey as usize, sys_enumerate_key);
    register_syscall(SyscallNumber::NtEnumerateValueKey as usize, sys_enumerate_value_key);
    register_syscall(SyscallNumber::NtQueryKey as usize, sys_query_key);

    // LPC syscalls
    register_syscall(SyscallNumber::NtCreatePort as usize, sys_create_port);
    register_syscall(SyscallNumber::NtConnectPort as usize, sys_connect_port);
    register_syscall(SyscallNumber::NtListenPort as usize, sys_listen_port);
    register_syscall(SyscallNumber::NtAcceptConnectPort as usize, sys_accept_connect_port);
    register_syscall(SyscallNumber::NtRequestPort as usize, sys_request_port);
    register_syscall(SyscallNumber::NtRequestWaitReplyPort as usize, sys_request_wait_reply_port);
    register_syscall(SyscallNumber::NtReplyPort as usize, sys_reply_port);
    register_syscall(SyscallNumber::NtReplyWaitReceivePort as usize, sys_reply_wait_receive_port);
    register_syscall(SyscallNumber::NtClosePort as usize, sys_close_port);
    register_syscall(SyscallNumber::NtQueryInformationPort as usize, sys_query_information_port);

    // Object/Handle syscalls
    register_syscall(SyscallNumber::NtDuplicateHandle as usize, sys_duplicate_handle);
    register_syscall(SyscallNumber::NtQueryObject as usize, sys_query_object);

    // Process syscalls
    register_syscall(SyscallNumber::NtOpenProcess as usize, sys_open_process);
    register_syscall(SyscallNumber::NtQueryInformationProcess as usize, sys_query_information_process);
    register_syscall(SyscallNumber::NtSuspendProcess as usize, sys_suspend_process);
    register_syscall(SyscallNumber::NtResumeProcess as usize, sys_resume_process);

    // Thread syscalls
    register_syscall(SyscallNumber::NtOpenThread as usize, sys_open_thread);
    register_syscall(SyscallNumber::NtQueryInformationThread as usize, sys_query_information_thread);
    register_syscall(SyscallNumber::NtSuspendThread as usize, sys_suspend_thread);
    register_syscall(SyscallNumber::NtResumeThread as usize, sys_resume_thread);

    // Token syscalls
    register_syscall(SyscallNumber::NtOpenProcessToken as usize, sys_open_process_token);
    register_syscall(SyscallNumber::NtOpenThreadToken as usize, sys_open_thread_token);
    register_syscall(SyscallNumber::NtQueryInformationToken as usize, sys_query_information_token);
    register_syscall(SyscallNumber::NtDuplicateToken as usize, sys_duplicate_token);
    register_syscall(SyscallNumber::NtAdjustPrivilegesToken as usize, sys_adjust_privileges_token);
    register_syscall(SyscallNumber::NtAdjustGroupsToken as usize, sys_adjust_groups_token);
    register_syscall(SyscallNumber::NtImpersonateThread as usize, sys_impersonate_thread);
    register_syscall(SyscallNumber::NtCreateToken as usize, sys_create_token);
    register_syscall(SyscallNumber::NtFilterToken as usize, sys_filter_token);

    // Set Information syscalls
    register_syscall(SyscallNumber::NtSetInformationProcess as usize, sys_set_information_process);
    register_syscall(SyscallNumber::NtSetInformationThread as usize, sys_set_information_thread);
    register_syscall(SyscallNumber::NtSetInformationObject as usize, sys_set_information_object);
    register_syscall(SyscallNumber::NtSetInformationToken as usize, sys_set_information_token);

    // Virtual Memory extended syscalls
    register_syscall(SyscallNumber::NtFlushVirtualMemory as usize, sys_flush_virtual_memory);
    register_syscall(SyscallNumber::NtLockVirtualMemory as usize, sys_lock_virtual_memory);
    register_syscall(SyscallNumber::NtUnlockVirtualMemory as usize, sys_unlock_virtual_memory);
    // NtReadVirtualMemory and NtWriteVirtualMemory are already registered at 50/51

    // Debug syscalls
    register_syscall(SyscallNumber::NtCreateDebugObject as usize, sys_create_debug_object);
    register_syscall(SyscallNumber::NtDebugActiveProcess as usize, sys_debug_active_process);
    register_syscall(SyscallNumber::NtRemoveProcessDebug as usize, sys_remove_process_debug);
    register_syscall(SyscallNumber::NtWaitForDebugEvent as usize, sys_wait_for_debug_event);
    register_syscall(SyscallNumber::NtDebugContinue as usize, sys_debug_continue);

    // Exception handling syscalls
    register_syscall(SyscallNumber::NtRaiseException as usize, sys_raise_exception);
    register_syscall(SyscallNumber::NtContinue as usize, sys_continue);
    register_syscall(SyscallNumber::NtGetContextThread as usize, sys_get_context_thread);
    register_syscall(SyscallNumber::NtSetContextThread as usize, sys_set_context_thread);

    // Process creation syscalls
    register_syscall(SyscallNumber::NtCreateProcess as usize, sys_create_process);
    register_syscall(SyscallNumber::NtCreateProcessEx as usize, sys_create_process_ex);

    // Job object syscalls
    register_syscall(SyscallNumber::NtCreateJobObject as usize, sys_create_job_object);
    register_syscall(SyscallNumber::NtOpenJobObject as usize, sys_open_job_object);
    register_syscall(SyscallNumber::NtAssignProcessToJobObject as usize, sys_assign_process_to_job);
    register_syscall(SyscallNumber::NtQueryInformationJobObject as usize, sys_query_information_job);
    register_syscall(SyscallNumber::NtSetInformationJobObject as usize, sys_set_information_job);
    register_syscall(SyscallNumber::NtTerminateJobObject as usize, sys_terminate_job_object);
    register_syscall(SyscallNumber::NtIsProcessInJob as usize, sys_is_process_in_job);

    // System information
    register_syscall(SyscallNumber::NtQuerySystemInformation as usize, sys_query_system_information);
    register_syscall(SyscallNumber::NtQuerySystemTime as usize, sys_query_system_time);
    register_syscall(SyscallNumber::NtQueryPerformanceCounter as usize, sys_query_performance_counter);

    // APC and Alert syscalls
    register_syscall(SyscallNumber::NtQueueApcThread as usize, sys_queue_apc_thread);
    register_syscall(SyscallNumber::NtTestAlert as usize, sys_test_alert);
    register_syscall(SyscallNumber::NtAlertThread as usize, sys_alert_thread);
    register_syscall(SyscallNumber::NtAlertResumeThread as usize, sys_alert_resume_thread);

    // Extended file syscalls
    register_syscall(SyscallNumber::NtDeviceIoControlFile as usize, sys_device_io_control_file);
    register_syscall(SyscallNumber::NtFsControlFile as usize, sys_fs_control_file);
    register_syscall(SyscallNumber::NtFlushBuffersFile as usize, sys_flush_buffers_file);
    register_syscall(SyscallNumber::NtCancelIoFile as usize, sys_cancel_io_file);
    register_syscall(SyscallNumber::NtSetFileCompletionNotificationModes as usize, sys_set_file_completion_notification_modes);

    // Section syscalls (additional)
    register_syscall(SyscallNumber::NtOpenSection as usize, sys_open_section);
    register_syscall(SyscallNumber::NtExtendSection as usize, sys_extend_section);

    // I/O Completion (additional)
    register_syscall(SyscallNumber::NtQueryIoCompletion as usize, sys_query_io_completion);

    // System information (additional)
    register_syscall(SyscallNumber::NtSetSystemInformation as usize, sys_set_system_information);

    // Object namespace syscalls
    register_syscall(SyscallNumber::NtCreateSymbolicLinkObject as usize, sys_create_symbolic_link_object);
    register_syscall(SyscallNumber::NtOpenSymbolicLinkObject as usize, sys_open_symbolic_link_object);
    register_syscall(SyscallNumber::NtQuerySymbolicLinkObject as usize, sys_query_symbolic_link_object);
    register_syscall(SyscallNumber::NtCreateDirectoryObject as usize, sys_create_directory_object);
    register_syscall(SyscallNumber::NtOpenDirectoryObject as usize, sys_open_directory_object);
    register_syscall(SyscallNumber::NtQueryDirectoryObject as usize, sys_query_directory_object);

    // Security syscalls
    register_syscall(SyscallNumber::NtAccessCheck as usize, sys_access_check);
    register_syscall(SyscallNumber::NtPrivilegeCheck as usize, sys_privilege_check);
    register_syscall(SyscallNumber::NtAccessCheckAndAuditAlarm as usize, sys_access_check_and_audit_alarm);

    // Power management syscalls
    register_syscall(SyscallNumber::NtSetSystemPowerState as usize, sys_set_system_power_state);
    register_syscall(SyscallNumber::NtInitiatePowerAction as usize, sys_initiate_power_action);
}

/// Register a syscall handler
///
/// # Safety
/// Handler must be a valid function that handles the syscall correctly.
pub unsafe fn register_syscall(number: usize, handler: SyscallHandler) {
    if number < MAX_SYSCALLS {
        SYSCALL_TABLE[number] = Some(handler);
    }
}

/// Syscall entry point (naked function)
///
/// On entry from SYSCALL:
/// - RCX = return RIP (user)
/// - R11 = return RFLAGS (user)
/// - RSP = user stack (we need to switch to kernel stack!)
/// - RAX = syscall number
/// - RDI, RSI, RDX, R10, R8, R9 = arguments
///
/// We need to:
/// 1. Save user RSP (using swapgs to access per-CPU data)
/// 2. Load kernel RSP
/// 3. Save callee-saved registers
/// 4. Call the syscall dispatcher
/// 5. Restore and return via SYSRET
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        // At this point:
        // - We're in kernel mode (CS = kernel code)
        // - RSP is still the user stack!
        // - RCX = user RIP, R11 = user RFLAGS
        // - RAX = syscall number
        // - RDI, RSI, RDX, R10, R8, R9 = args

        // Swap GS to get access to kernel per-CPU data
        // (In a full implementation, we'd use this to get kernel stack)
        "swapgs",

        // For now, we use a dedicated syscall stack
        // In a full implementation, we'd get this from the PRCB
        // Save user stack pointer in R15 temporarily
        "mov r15, rsp",

        // Load kernel syscall stack
        "mov rsp, gs:[0]",  // Assumes per-CPU syscall stack at gs:0

        // If no per-CPU data set up, use a fallback static stack
        "test rsp, rsp",
        "jnz 2f",
        "lea rsp, [{syscall_stack} + {stack_size}]",
        "2:",

        // Now on kernel stack - save user context
        // Push user stack pointer
        "push r15",
        // Push return address and flags
        "push rcx",         // User RIP
        "push r11",         // User RFLAGS

        // Save callee-saved registers
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // Syscall number is in RAX
        // Arguments: RDI, RSI, RDX, R10, R8, R9
        // Note: R10 replaces RCX in syscall convention

        // Move R10 to RCX for standard calling convention
        "mov rcx, r10",

        // Call the Rust dispatcher
        // dispatcher(syscall_num, arg1, arg2, arg3, arg4, arg5, arg6)
        //           rdi,         rsi,  rdx,  rcx,  r8,   r9,   [stack]
        // We need to set up: rdi=syscall_num, rsi=arg1, rdx=arg2, rcx=arg3, r8=arg4, r9=arg5

        // Current register state:
        // RAX = syscall number
        // RDI = arg1, RSI = arg2, RDX = arg3, RCX = arg4 (was R10), R8 = arg5, R9 = arg6

        // Rearrange for dispatcher call
        // Push arg6 (R9) for stack argument
        "push r9",
        // Set up arguments for dispatcher
        "mov r9, r8",       // arg5 -> r9
        "mov r8, rcx",      // arg4 -> r8
        "mov rcx, rdx",     // arg3 -> rcx
        "mov rdx, rsi",     // arg2 -> rdx
        "mov rsi, rdi",     // arg1 -> rsi
        "mov rdi, rax",     // syscall_num -> rdi

        // Align stack to 16 bytes (required by System V ABI)
        "sub rsp, 8",

        // Call the dispatcher
        "call {dispatcher}",

        // Result is in RAX
        // Clean up stack
        "add rsp, 16",      // Remove alignment + arg6

        // Restore callee-saved registers
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",

        // Restore return context
        "pop r11",          // User RFLAGS
        "pop rcx",          // User RIP
        "pop rsp",          // User RSP

        // Swap back to user GS
        "swapgs",

        // Return to user mode
        // SYSRETQ: RCX -> RIP, R11 -> RFLAGS
        "sysretq",

        dispatcher = sym syscall_dispatcher,
        syscall_stack = sym SYSCALL_STACK,
        stack_size = const SYSCALL_STACK_SIZE,
    )
}

/// Size of syscall stack
const SYSCALL_STACK_SIZE: usize = 16384; // 16KB

/// Aligned syscall stack wrapper
#[repr(C, align(16))]
struct SyscallStack {
    data: [u8; SYSCALL_STACK_SIZE],
}

/// Dedicated syscall stack (used if per-CPU data not available)
static mut SYSCALL_STACK: SyscallStack = SyscallStack {
    data: [0; SYSCALL_STACK_SIZE],
};

/// Per-CPU data structure for syscall handling
/// GS base points to this structure
/// gs:[0] contains the kernel stack pointer
#[repr(C)]
struct PerCpuSyscall {
    kernel_stack: u64, // Offset 0: kernel stack pointer for syscalls
}

/// Static per-CPU data for syscall
static mut SYSCALL_PERCPU: PerCpuSyscall = PerCpuSyscall {
    kernel_stack: 0,
};

/// Syscall dispatcher (called from assembly)
///
/// Looks up the syscall handler and invokes it.
#[no_mangle]
extern "C" fn syscall_dispatcher(
    syscall_num: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> isize {
    const STATUS_INVALID_SYSTEM_SERVICE: isize = 0xC000001Cu32 as isize;

    // Validate syscall number
    if syscall_num >= MAX_SYSCALLS {
        crate::serial_println!("[SYSCALL] Invalid syscall number: {}", syscall_num);
        return STATUS_INVALID_SYSTEM_SERVICE;
    }

    // Get handler from table
    let handler = unsafe { SYSCALL_TABLE[syscall_num] };

    let result = match handler {
        Some(func) => {
            // Call the handler
            func(arg1, arg2, arg3, arg4, arg5, arg6)
        }
        None => {
            crate::serial_println!("[SYSCALL] Unimplemented syscall: {}", syscall_num);
            STATUS_NOT_IMPLEMENTED
        }
    };

    // Record trace entry if tracing is enabled
    trace_syscall(syscall_num, arg1, arg2, result);

    result
}

// ============================================================================
// Default Syscall Implementations
// ============================================================================

/// NtTerminateProcess - Terminate the current process
fn sys_terminate_process(
    _exit_code: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtTerminateProcess(exit_code={})", _exit_code);
    // For now, just halt
    loop {
        unsafe { asm!("hlt"); }
    }
}

/// NtTerminateThread - Terminate the current thread
fn sys_terminate_thread(
    exit_code: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtTerminateThread(exit_code={})", exit_code);

    // Check if we're returning from a user mode test
    unsafe {
        if KERNEL_CONTEXT.valid {
            // Save the exit code
            USER_MODE_RESULT = exit_code as isize;

            // Mark context as used
            KERNEL_CONTEXT.valid = false;

            // Restore kernel context and return
            // We do this by restoring registers and jumping back
            asm!(
                // Restore callee-saved registers
                "mov r15, {r15}",
                "mov r14, {r14}",
                "mov r13, {r13}",
                "mov r12, {r12}",
                "mov rbx, {rbx}",
                "mov rbp, {rbp}",
                "mov rsp, {rsp}",
                // Return to saved location
                "ret",
                rsp = in(reg) KERNEL_CONTEXT.rsp,
                rbp = in(reg) KERNEL_CONTEXT.rbp,
                rbx = in(reg) KERNEL_CONTEXT.rbx,
                r12 = in(reg) KERNEL_CONTEXT.r12,
                r13 = in(reg) KERNEL_CONTEXT.r13,
                r14 = in(reg) KERNEL_CONTEXT.r14,
                r15 = in(reg) KERNEL_CONTEXT.r15,
                options(noreturn)
            );
        }
    }

    // Normal thread termination (not from user mode test)
    0
}

// ============================================================================
// Thread Handle Management
// ============================================================================

/// Thread handle table
const MAX_THREAD_HANDLES: usize = 64;
const THREAD_HANDLE_BASE: usize = 0x4000;

/// Thread handle entries (maps to thread IDs)
static mut THREAD_HANDLE_MAP: [u32; MAX_THREAD_HANDLES] = [u32::MAX; MAX_THREAD_HANDLES];

/// Allocate a thread handle
unsafe fn alloc_thread_handle(thread_id: u32) -> Option<usize> {
    for i in 0..MAX_THREAD_HANDLES {
        if THREAD_HANDLE_MAP[i] == u32::MAX {
            THREAD_HANDLE_MAP[i] = thread_id;
            return Some(i + THREAD_HANDLE_BASE);
        }
    }
    None
}

/// Get thread ID from handle
unsafe fn get_thread_id(handle: usize) -> Option<u32> {
    if handle < THREAD_HANDLE_BASE {
        return None;
    }
    let idx = handle - THREAD_HANDLE_BASE;
    if idx >= MAX_THREAD_HANDLES {
        return None;
    }
    let tid = THREAD_HANDLE_MAP[idx];
    if tid == u32::MAX {
        None
    } else {
        Some(tid)
    }
}

/// Free a thread handle
unsafe fn free_thread_handle(handle: usize) {
    if handle >= THREAD_HANDLE_BASE {
        let idx = handle - THREAD_HANDLE_BASE;
        if idx < MAX_THREAD_HANDLES {
            THREAD_HANDLE_MAP[idx] = u32::MAX;
        }
    }
}

/// NtCreateThread - Create a new thread
///
/// Arguments:
/// - thread_handle: Pointer to receive handle
/// - desired_access: Access rights for handle
/// - object_attributes: Security attributes (ignored for now)
/// - process_handle: Handle to owning process
/// - client_id: Receives thread/process IDs
/// - thread_context: Initial context (rip = start address)
fn sys_create_thread(
    thread_handle_ptr: usize,
    _desired_access: usize,
    _object_attributes: usize,
    _process_handle: usize,
    client_id_ptr: usize,
    thread_context_ptr: usize,
) -> isize {
    const STATUS_UNSUCCESSFUL: isize = 0xC0000001u32 as isize;

    if thread_handle_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    crate::serial_println!("[SYSCALL] NtCreateThread()");

    // Get the start address from context
    // Thread context layout (simplified):
    // offset 0x0: rip (instruction pointer / start address)
    // offset 0x8: rsp (stack pointer)
    // offset 0x10: rbp
    // etc.
    let (start_address, initial_rsp) = if thread_context_ptr != 0 {
        unsafe {
            let rip = *(thread_context_ptr as *const u64);
            let rsp = *((thread_context_ptr + 8) as *const u64);
            (rip, rsp)
        }
    } else {
        return STATUS_INVALID_PARAMETER; // Need a context with at least RIP
    };

    crate::serial_println!("[SYSCALL] NtCreateThread: start_address={:#x}, rsp={:#x}",
        start_address, initial_rsp);

    // Create a wrapper start routine
    // For now, we create a kernel thread that simulates user-mode execution
    // Real NT would set up proper user-mode context

    // Store parameters for the new thread
    static mut THREAD_PARAMS: [(u64, u64); 64] = [(0, 0); 64];
    static mut THREAD_PARAM_IDX: usize = 0;

    unsafe {
        let idx = THREAD_PARAM_IDX % 64;
        THREAD_PARAMS[idx] = (start_address, initial_rsp);
        THREAD_PARAM_IDX += 1;
    }

    // Create system thread (for now, all threads are kernel threads)
    // Real implementation would create user-mode threads with proper address space
    let thread = unsafe {
        crate::ps::create::ps_create_system_thread(
            thread_start_wrapper,
            start_address as *mut u8,
            8, // Normal priority
        )
    };

    if thread.is_null() {
        crate::serial_println!("[SYSCALL] NtCreateThread: failed to create thread");
        return STATUS_UNSUCCESSFUL;
    }

    // Get thread ID
    let thread_id = unsafe { (*thread).cid.unique_thread };

    // Allocate handle
    let handle = unsafe { alloc_thread_handle(thread_id) };
    match handle {
        Some(h) => {
            unsafe { *(thread_handle_ptr as *mut usize) = h; }

            // Fill in client ID if provided
            if client_id_ptr != 0 {
                unsafe {
                    // CLIENT_ID structure: { ProcessId, ThreadId }
                    *(client_id_ptr as *mut u32) = (*thread).cid.unique_process;
                    *((client_id_ptr + 4) as *mut u32) = thread_id;
                }
            }

            // Start the thread
            unsafe {
                crate::ps::create::ps_start_thread(thread);
            }

            crate::serial_println!("[SYSCALL] NtCreateThread -> handle {:#x}, tid {}",
                h, thread_id);
            0 // STATUS_SUCCESS
        }
        None => {
            crate::serial_println!("[SYSCALL] NtCreateThread: no handles available");
            -1 // STATUS_INSUFFICIENT_RESOURCES
        }
    }
}

/// Thread start wrapper
/// This function is called as the thread entry point
fn thread_start_wrapper(_param: *mut u8) {
    // The param is the start address
    // For now, just log and halt
    // Real implementation would:
    // 1. Set up user-mode stack
    // 2. Switch to user mode
    // 3. Jump to start_address

    crate::serial_println!("[THREAD] Thread started at address {:#x}", _param as u64);

    // Simulate doing some work
    for _ in 0..10 {
        unsafe {
            crate::ke::scheduler::ki_yield();
        }
    }

    crate::serial_println!("[THREAD] Thread exiting");
}

/// NtGetCurrentProcessId - Get current process ID
fn sys_get_current_process_id(
    _: usize, _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    unsafe {
        let prcb = crate::ke::prcb::get_current_prcb();
        if !prcb.current_thread.is_null() {
            // Get process from current thread, then get process ID
            let process = (*prcb.current_thread).process;
            if !process.is_null() {
                (*process).process_id as isize
            } else {
                0 // No process, return System process ID
            }
        } else {
            // No current thread, return System process ID
            0
        }
    }
}

/// NtGetCurrentThreadId - Get current thread ID
fn sys_get_current_thread_id(
    _: usize, _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    
    unsafe {
        let prcb = crate::ke::prcb::get_current_prcb();
        if !prcb.current_thread.is_null() {
            (*prcb.current_thread).thread_id as isize
        } else {
            0
        }
    }
}

/// NtYieldExecution - Yield the current thread's time slice
fn sys_yield_execution(
    _: usize, _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    unsafe {
        crate::ke::scheduler::ki_yield();
    }
    0 // STATUS_SUCCESS
}

/// NtDebugPrint - Print debug message to serial console
fn sys_debug_print(
    buffer: usize,
    length: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::mm::address::{probe_for_read, is_valid_user_range};

    // Validate buffer pointer and length
    if buffer == 0 || length == 0 || length > 1024 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate user memory access
    if !is_valid_user_range(buffer as u64, length) {
        return STATUS_ACCESS_VIOLATION;
    }

    if !probe_for_read(buffer as u64, length) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Read string from user memory (now validated)
    let slice = unsafe {
        core::slice::from_raw_parts(buffer as *const u8, length)
    };

    // Convert to string and print
    if let Ok(s) = core::str::from_utf8(slice) {
        crate::serial_print!("{}", s);
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

/// NtClose - Close a handle
///
/// # Arguments
/// * `handle` - Handle to close
///
/// # Returns
/// * STATUS_SUCCESS - Handle was successfully closed
/// * STATUS_INVALID_HANDLE - Handle is invalid or not open
/// * STATUS_HANDLE_NOT_CLOSABLE - Handle is protected from close
///
/// # NT Compatibility
/// NtClose closes any valid handle type: files, processes, threads,
/// events, mutexes, semaphores, registry keys, ports, sections, etc.
fn sys_close(
    handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // NT status codes
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;
    const STATUS_HANDLE_NOT_CLOSABLE: isize = 0xC0000235u32 as isize;

    crate::serial_println!("[SYSCALL] NtClose(handle=0x{:X})", handle);

    // Handle 0 is typically NULL - invalid
    if handle == 0 {
        crate::serial_println!("[SYSCALL] NtClose: NULL handle");
        return STATUS_INVALID_HANDLE;
    }

    // Pseudo-handles that cannot be closed
    // NtCurrentProcess() = 0xFFFFFFFF / -1
    // NtCurrentThread() = 0xFFFFFFFE / -2
    if handle == 0xFFFFFFFF || handle == 0xFFFFFFFFFFFFFFFE
        || handle == 0xFFFFFFFFFFFFFFFD || handle == 0xFFFFFFFFFFFFFFFC {
        // Pseudo-handles - silently succeed (Windows behavior)
        crate::serial_println!("[SYSCALL] NtClose: pseudo-handle, returning success");
        return STATUS_SUCCESS;
    }

    // Check if this is a sync object handle (handles >= SYNC_HANDLE_BASE, i.e., 0x1000+)
    if handle >= SYNC_HANDLE_BASE {
        if let Some((_, obj_type)) = unsafe { get_sync_object(handle) } {
            // Free the sync object
            unsafe { free_sync_object(handle); }
            crate::serial_println!("[SYSCALL] NtClose: closed {:?} sync object", obj_type);
            return STATUS_SUCCESS;
        }
        // Handle >= SYNC_HANDLE_BASE but not a valid sync object - could be other handle type
        // Fall through to check other handle types or object manager
    }

    // Check if this is a file handle (handles in FILE_HANDLE_BASE..SYNC_HANDLE_BASE range)
    if (FILE_HANDLE_BASE..SYNC_HANDLE_BASE).contains(&handle) {
        if let Some(fs_handle) = unsafe { get_fs_handle(handle) } {
            // Close the fs handle
            let _ = crate::fs::close(fs_handle);
            // Free the syscall handle mapping
            unsafe { free_file_handle(handle); }
            crate::serial_println!("[SYSCALL] NtClose: closed file handle");
            return STATUS_SUCCESS;
        }
        // Handle in file range but not valid
        crate::serial_println!("[SYSCALL] NtClose: invalid file handle");
        return STATUS_INVALID_HANDLE;
    }

    // Try to close via object manager (for kernel objects)
    // Convert to Handle type (handles are typically 4-byte aligned multiples)
    let ob_handle = handle as u32;

    // Attempt to close via object manager
    let closed = unsafe { crate::ob::ob_close_handle(ob_handle) };

    if closed {
        crate::serial_println!("[SYSCALL] NtClose: closed object handle via OB");
        STATUS_SUCCESS
    } else {
        // Could be invalid handle or protected handle
        // Check if handle exists but is protected
        let object = unsafe {
            crate::ob::ob_reference_object_by_handle(ob_handle, 0)
        };

        if !object.is_null() {
            // Handle exists but couldn't be closed (protected)
            unsafe { crate::ob::ob_dereference_object(object); }
            crate::serial_println!("[SYSCALL] NtClose: handle protected from close");
            STATUS_HANDLE_NOT_CLOSABLE
        } else {
            // Handle doesn't exist
            crate::serial_println!("[SYSCALL] NtClose: invalid handle");
            STATUS_INVALID_HANDLE
        }
    }
}

/// NtReadFile - Read from a file
fn sys_read_file(
    handle: usize,
    buffer: usize,
    length: usize,
    bytes_read_ptr: usize,
    _: usize, _: usize,
) -> isize {
    if buffer == 0 || length == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Special case: handle 0 = stdin (not implemented)
    if handle == 0 {
        if bytes_read_ptr != 0 {
            unsafe { *(bytes_read_ptr as *mut usize) = 0; }
        }
        return STATUS_SUCCESS;
    }

    // Try to get fs handle
    let fs_handle = match unsafe { get_fs_handle(handle) } {
        Some(h) => h,
        None => {
            // Not a file handle - return error
            crate::serial_println!("[SYSCALL] NtReadFile: invalid handle {}", handle);
            return STATUS_INVALID_HANDLE;
        }
    };

    // Read from file system
    let buf_slice = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };

    match crate::fs::read(fs_handle, buf_slice) {
        Ok(bytes_read) => {
            if bytes_read_ptr != 0 {
                unsafe { *(bytes_read_ptr as *mut usize) = bytes_read; }
            }
            crate::serial_println!("[SYSCALL] NtReadFile(handle={}) -> {} bytes", handle, bytes_read);
            STATUS_SUCCESS
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtReadFile(handle={}) -> error {:?}", handle, e);
            if bytes_read_ptr != 0 {
                unsafe { *(bytes_read_ptr as *mut usize) = 0; }
            }
            // Map file system errors to NT status codes
            0xC0000185u32 as isize // STATUS_IO_DEVICE_ERROR
        }
    }
}

/// NtWriteFile - Write to a file
fn sys_write_file(
    handle: usize,
    buffer: usize,
    length: usize,
    bytes_written_ptr: usize,
    _: usize, _: usize,
) -> isize {
    if buffer == 0 || length == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Special case: handle 1 = stdout (serial console)
    if handle == 1 && length <= 4096 {
        let slice = unsafe {
            core::slice::from_raw_parts(buffer as *const u8, length)
        };

        if let Ok(s) = core::str::from_utf8(slice) {
            crate::serial_print!("{}", s);
            if bytes_written_ptr != 0 {
                unsafe { *(bytes_written_ptr as *mut usize) = length; }
            }
            return STATUS_SUCCESS;
        }
    }

    // Special case: handle 2 = stderr (serial console)
    if handle == 2 && length <= 4096 {
        let slice = unsafe {
            core::slice::from_raw_parts(buffer as *const u8, length)
        };

        if let Ok(s) = core::str::from_utf8(slice) {
            crate::serial_print!("{}", s);
            if bytes_written_ptr != 0 {
                unsafe { *(bytes_written_ptr as *mut usize) = length; }
            }
            return STATUS_SUCCESS;
        }
    }

    // Try to get fs handle
    let fs_handle = match unsafe { get_fs_handle(handle) } {
        Some(h) => h,
        None => {
            crate::serial_println!("[SYSCALL] NtWriteFile: invalid handle {}", handle);
            return STATUS_INVALID_HANDLE;
        }
    };

    // Write to file system
    let buf_slice = unsafe { core::slice::from_raw_parts(buffer as *const u8, length) };

    match crate::fs::write(fs_handle, buf_slice) {
        Ok(bytes_written) => {
            if bytes_written_ptr != 0 {
                unsafe { *(bytes_written_ptr as *mut usize) = bytes_written; }
            }
            crate::serial_println!("[SYSCALL] NtWriteFile(handle={}) -> {} bytes", handle, bytes_written);
            STATUS_SUCCESS
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtWriteFile(handle={}) -> error {:?}", handle, e);
            if bytes_written_ptr != 0 {
                unsafe { *(bytes_written_ptr as *mut usize) = 0; }
            }
            // Map file system errors to NT status codes
            0xC0000185u32 as isize // STATUS_IO_DEVICE_ERROR
        }
    }
}

// ============================================================================
// File Operation Syscalls (NtCreateFile, NtOpenFile, etc.)
// ============================================================================

/// File handle table - maps syscall handles to fs handles
/// Handles 0-99 reserved for special handles (stdin, stdout, etc.)
/// Handles 100+ are file system handles
const FILE_HANDLE_BASE: usize = 100;
const MAX_FILE_HANDLES: usize = 256;

/// File handle to fs handle mapping
static mut FILE_HANDLE_MAP: [u16; MAX_FILE_HANDLES] = [0xFFFF; MAX_FILE_HANDLES];

/// Allocate a syscall file handle
unsafe fn alloc_file_handle(fs_handle: u16) -> Option<usize> {
    for i in 0..MAX_FILE_HANDLES {
        if FILE_HANDLE_MAP[i] == 0xFFFF {
            FILE_HANDLE_MAP[i] = fs_handle;
            return Some(i + FILE_HANDLE_BASE);
        }
    }
    None
}

/// Get fs handle from syscall handle
unsafe fn get_fs_handle(syscall_handle: usize) -> Option<u16> {
    if syscall_handle < FILE_HANDLE_BASE {
        return None; // Reserved handles
    }
    let idx = syscall_handle - FILE_HANDLE_BASE;
    if idx >= MAX_FILE_HANDLES {
        return None;
    }
    let fs_handle = FILE_HANDLE_MAP[idx];
    if fs_handle == 0xFFFF {
        None
    } else {
        Some(fs_handle)
    }
}

/// Free a syscall file handle
unsafe fn free_file_handle(syscall_handle: usize) {
    if syscall_handle >= FILE_HANDLE_BASE {
        let idx = syscall_handle - FILE_HANDLE_BASE;
        if idx < MAX_FILE_HANDLES {
            FILE_HANDLE_MAP[idx] = 0xFFFF;
        }
    }
}

/// NT file creation disposition values
pub mod file_disposition {
    pub const FILE_SUPERSEDE: u32 = 0;
    pub const FILE_OPEN: u32 = 1;
    pub const FILE_CREATE: u32 = 2;
    pub const FILE_OPEN_IF: u32 = 3;
    pub const FILE_OVERWRITE: u32 = 4;
    pub const FILE_OVERWRITE_IF: u32 = 5;
}

/// NT file create options
pub mod file_options {
    pub const FILE_DIRECTORY_FILE: u32 = 0x00000001;
    pub const FILE_WRITE_THROUGH: u32 = 0x00000002;
    pub const FILE_SEQUENTIAL_ONLY: u32 = 0x00000004;
    pub const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x00000008;
    pub const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x00000010;
    pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
    pub const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
    pub const FILE_DELETE_ON_CLOSE: u32 = 0x00001000;
}

/// Read a path string from user memory
unsafe fn read_user_path(path_ptr: usize, max_len: usize) -> Option<([u8; 260], usize)> {
    if path_ptr == 0 {
        return None;
    }

    let mut path_buf = [0u8; 260];
    let src = path_ptr as *const u8;
    let mut len = 0;

    while len < max_len && len < 260 {
        let byte = *src.add(len);
        if byte == 0 {
            break;
        }
        path_buf[len] = byte;
        len += 1;
    }

    if len == 0 {
        None
    } else {
        Some((path_buf, len))
    }
}

/// NtCreateFile - Create or open a file
///
/// Arguments:
/// - file_handle: Pointer to receive handle
/// - desired_access: Access mask
/// - object_attributes: Pointer to OBJECT_ATTRIBUTES (contains file name)
/// - io_status_block: Pointer to IO_STATUS_BLOCK
/// - allocation_size: Initial size for new files
/// - file_attributes: File attributes for new files
fn sys_create_file(
    file_handle_ptr: usize,
    desired_access: usize,
    object_attributes: usize,
    io_status_block: usize,
    _allocation_size: usize,
    file_attributes: usize,
) -> isize {
    const STATUS_OBJECT_NAME_NOT_FOUND: isize = 0xC0000034u32 as isize;

    if file_handle_ptr == 0 || object_attributes == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // OBJECT_ATTRIBUTES layout (simplified):
    // offset 0: length (u32)
    // offset 8: root_directory (handle)
    // offset 16: object_name (pointer to UNICODE_STRING)
    // For now, we read object_name as a simple pointer to path string

    // Read the path from object_attributes
    // Simplified: assume object_attributes points to path string directly
    let path_result = unsafe { read_user_path(object_attributes, 260) };

    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return STATUS_INVALID_PARAMETER,
    };

    let path_str = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };

    crate::serial_println!("[SYSCALL] NtCreateFile(path='{}', access={:#x})", path_str, desired_access);

    // Try to create the file
    let result = crate::fs::create(path_str, file_attributes as u32);

    match result {
        Ok(fs_handle) => {
            // Allocate syscall handle
            let syscall_handle = unsafe { alloc_file_handle(fs_handle) };
            match syscall_handle {
                Some(h) => {
                    unsafe {
                        *(file_handle_ptr as *mut usize) = h;
                        if io_status_block != 0 {
                            // IO_STATUS_BLOCK: status at offset 0, information at offset 8
                            *(io_status_block as *mut i32) = 0; // STATUS_SUCCESS
                            *((io_status_block + 8) as *mut usize) = 1; // FILE_CREATED
                        }
                    }
                    STATUS_SUCCESS
                }
                None => {
                    let _ = crate::fs::close(fs_handle);
                    STATUS_INSUFFICIENT_RESOURCES
                }
            }
        }
        Err(_e) => {
            // Try to open existing file instead
            match crate::fs::open(path_str, desired_access as u32) {
                Ok(fs_handle) => {
                    let syscall_handle = unsafe { alloc_file_handle(fs_handle) };
                    match syscall_handle {
                        Some(h) => {
                            unsafe {
                                *(file_handle_ptr as *mut usize) = h;
                                if io_status_block != 0 {
                                    *(io_status_block as *mut i32) = 0;
                                    *((io_status_block + 8) as *mut usize) = 2; // FILE_OPENED
                                }
                            }
                            STATUS_SUCCESS
                        }
                        None => {
                            let _ = crate::fs::close(fs_handle);
                            STATUS_INSUFFICIENT_RESOURCES
                        }
                    }
                }
                Err(_) => STATUS_OBJECT_NAME_NOT_FOUND,
            }
        }
    }
}

/// NtOpenFile - Open an existing file
fn sys_open_file(
    file_handle_ptr: usize,
    desired_access: usize,
    object_attributes: usize,
    io_status_block: usize,
    share_access: usize,
    open_options: usize,
) -> isize {
    const STATUS_OBJECT_NAME_NOT_FOUND: isize = 0xC0000034u32 as isize;

    if file_handle_ptr == 0 || object_attributes == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = share_access;
    let _ = open_options;

    let path_result = unsafe { read_user_path(object_attributes, 260) };

    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return STATUS_INVALID_PARAMETER,
    };

    let path_str = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };

    crate::serial_println!("[SYSCALL] NtOpenFile(path='{}', access={:#x})", path_str, desired_access);

    match crate::fs::open(path_str, desired_access as u32) {
        Ok(fs_handle) => {
            let syscall_handle = unsafe { alloc_file_handle(fs_handle) };
            match syscall_handle {
                Some(h) => {
                    unsafe {
                        *(file_handle_ptr as *mut usize) = h;
                        if io_status_block != 0 {
                            *(io_status_block as *mut i32) = 0;
                            *((io_status_block + 8) as *mut usize) = 2; // FILE_OPENED
                        }
                    }
                    STATUS_SUCCESS
                }
                None => {
                    let _ = crate::fs::close(fs_handle);
                    STATUS_INSUFFICIENT_RESOURCES
                }
            }
        }
        Err(_) => STATUS_OBJECT_NAME_NOT_FOUND,
    }
}

/// File information class constants
mod file_info_class {
    pub const FILE_BASIC_INFORMATION: usize = 4;
    pub const FILE_STANDARD_INFORMATION: usize = 5;
    pub const FILE_NAME_INFORMATION: usize = 9;
    pub const FILE_POSITION_INFORMATION: usize = 14;
    pub const FILE_ALL_INFORMATION: usize = 18;
}

/// NtQueryInformationFile - Query file information
fn sys_query_information_file(
    file_handle: usize,
    io_status_block: usize,
    file_information: usize,
    length: usize,
    file_information_class: usize,
    _: usize,
) -> isize {
    use file_info_class::*;
    const STATUS_IO_DEVICE_ERROR: isize = 0xC0000185u32 as isize;

    if file_handle == 0 || file_information == 0 || length == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let fs_handle = match unsafe { get_fs_handle(file_handle) } {
        Some(h) => h,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!(
        "[SYSCALL] NtQueryInformationFile(handle={}, class={})",
        file_handle, file_information_class
    );

    // Get file info via fs::fstat
    match crate::fs::fstat(fs_handle) {
        Ok(info) => {
            let is_dir = matches!(info.file_type, crate::fs::FileType::Directory);
            let mut bytes_written: usize = 0;

            unsafe {
                match file_information_class {
                    FILE_BASIC_INFORMATION => {
                        // FILE_BASIC_INFORMATION layout (40 bytes):
                        // CreationTime: i64, LastAccessTime: i64, LastWriteTime: i64
                        // ChangeTime: i64, FileAttributes: u32
                        if length < 40 {
                            return 0xC0000023u32 as isize; // STATUS_BUFFER_TOO_SMALL
                        }
                        *(file_information as *mut i64) = 0; // CreationTime
                        *((file_information + 8) as *mut i64) = 0; // LastAccessTime
                        *((file_information + 16) as *mut i64) = 0; // LastWriteTime
                        *((file_information + 24) as *mut i64) = 0; // ChangeTime
                        // File attributes: 0x10 = directory, 0x20 = archive (normal file)
                        *((file_information + 32) as *mut u32) = if is_dir { 0x10 } else { 0x20 };
                        bytes_written = 40;
                    }

                    FILE_STANDARD_INFORMATION => {
                        // FileStandardInformation layout (24 bytes):
                        // AllocationSize: i64, EndOfFile: i64, NumberOfLinks: u32
                        // DeletePending: u8, Directory: u8
                        if length < 24 {
                            return 0xC0000023u32 as isize; // STATUS_BUFFER_TOO_SMALL
                        }
                        *(file_information as *mut i64) = info.size as i64;
                        *((file_information + 8) as *mut i64) = info.size as i64;
                        *((file_information + 16) as *mut u32) = 1;
                        *((file_information + 20) as *mut u8) = 0;
                        *((file_information + 21) as *mut u8) = if is_dir { 1 } else { 0 };
                        bytes_written = 24;
                    }

                    FILE_NAME_INFORMATION => {
                        // FILE_NAME_INFORMATION layout:
                        // FileNameLength: u32, FileName: WCHAR[]
                        // We don't have the full path, so return empty name for now
                        if length < 8 {
                            return 0xC0000023u32 as isize;
                        }
                        *(file_information as *mut u32) = 0; // FileNameLength = 0
                        bytes_written = 4;
                    }

                    FILE_POSITION_INFORMATION => {
                        // FILE_POSITION_INFORMATION: CurrentByteOffset: i64
                        if length < 8 {
                            return 0xC0000023u32 as isize;
                        }
                        // Get current position via seek(0, Cur)
                        let pos = crate::fs::seek(fs_handle, 0, crate::fs::SeekWhence::Cur).unwrap_or(0);
                        *(file_information as *mut i64) = pos as i64;
                        bytes_written = 8;
                    }

                    FILE_ALL_INFORMATION => {
                        // Combination of several info classes - return minimum required
                        if length < 24 {
                            return 0xC0000023u32 as isize;
                        }
                        // Just return standard info for now
                        *(file_information as *mut i64) = info.size as i64;
                        *((file_information + 8) as *mut i64) = info.size as i64;
                        *((file_information + 16) as *mut u32) = 1;
                        *((file_information + 20) as *mut u8) = 0;
                        *((file_information + 21) as *mut u8) = if is_dir { 1 } else { 0 };
                        bytes_written = 24;
                    }

                    _ => {
                        // Unknown class - return standard info as fallback
                        if length >= 24 {
                            *(file_information as *mut i64) = info.size as i64;
                            *((file_information + 8) as *mut i64) = info.size as i64;
                            *((file_information + 16) as *mut u32) = 1;
                            *((file_information + 20) as *mut u8) = 0;
                            *((file_information + 21) as *mut u8) = if is_dir { 1 } else { 0 };
                            bytes_written = 24;
                        }
                    }
                }

                if io_status_block != 0 {
                    *(io_status_block as *mut i32) = 0;
                    *((io_status_block + 8) as *mut usize) = bytes_written;
                }
            }
            STATUS_SUCCESS
        }
        Err(_) => STATUS_IO_DEVICE_ERROR,
    }
}

/// NtSetInformationFile - Set file information
fn sys_set_information_file(
    file_handle: usize,
    io_status_block: usize,
    file_information: usize,
    length: usize,
    file_information_class: usize,
    _: usize,
) -> isize {
    if file_handle == 0 || file_information == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let fs_handle = match unsafe { get_fs_handle(file_handle) } {
        Some(h) => h,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!(
        "[SYSCALL] NtSetInformationFile(handle={}, class={}, len={})",
        file_handle, file_information_class, length
    );

    // FilePositionInformation = 14 - set file position
    if file_information_class == 14 && length >= 8 {
        let new_position = unsafe { *(file_information as *const i64) };
        if new_position >= 0 {
            // Use seek to set position
            let _ = crate::fs::seek(fs_handle, new_position, crate::fs::SeekWhence::Set);
        }
    }

    // FileEndOfFileInformation = 20 - truncate/extend file
    if file_information_class == 20 && length >= 8 {
        let new_size = unsafe { *(file_information as *const u64) };
        let _ = crate::fs::truncate(fs_handle, new_size);
    }

    unsafe {
        if io_status_block != 0 {
            *(io_status_block as *mut i32) = 0;
            *((io_status_block + 8) as *mut usize) = 0;
        }
    }

    STATUS_SUCCESS
}

/// NtDeleteFile - Delete a file
fn sys_delete_file(
    object_attributes: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    const STATUS_OBJECT_NAME_NOT_FOUND: isize = 0xC0000034u32 as isize;

    if object_attributes == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let path_result = unsafe { read_user_path(object_attributes, 260) };

    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return STATUS_INVALID_PARAMETER,
    };

    let path_str = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };

    crate::serial_println!("[SYSCALL] NtDeleteFile(path='{}')", path_str);

    match crate::fs::delete(path_str) {
        Ok(()) => STATUS_SUCCESS,
        Err(_) => STATUS_OBJECT_NAME_NOT_FOUND,
    }
}

/// Get the syscall stack pointer for per-CPU initialization
pub fn get_syscall_stack() -> *mut u8 {
    unsafe {
        SYSCALL_STACK.data.as_mut_ptr().add(SYSCALL_STACK_SIZE)
    }
}

// ============================================================================
// User Mode Support
// ============================================================================

/// Size of user mode stack
const USER_STACK_SIZE: usize = 16384; // 16KB

/// User mode stack wrapper
#[repr(C, align(16))]
struct UserStack {
    data: [u8; USER_STACK_SIZE],
}

/// Static user mode stack for testing
static mut USER_STACK: UserStack = UserStack {
    data: [0; USER_STACK_SIZE],
};

/// Saved kernel context for returning from user mode test
#[repr(C)]
struct KernelContext {
    rsp: u64,
    rbp: u64,
    rbx: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    valid: bool,
}

static mut KERNEL_CONTEXT: KernelContext = KernelContext {
    rsp: 0, rbp: 0, rbx: 0, r12: 0, r13: 0, r14: 0, r15: 0, valid: false,
};

/// User mode test result (set by NtTerminateThread)
pub static mut USER_MODE_RESULT: isize = -1;

/// Check if returning from user mode
pub fn is_returning_from_user() -> bool {
    unsafe { KERNEL_CONTEXT.valid }
}

/// Enter user mode and execute code at the given address
///
/// Uses IRETQ to switch to ring 3 with the specified entry point.
/// The user code should execute SYSCALL to return to kernel mode.
///
/// # Arguments
/// * `entry_point` - Physical address of user code (must be identity-mapped)
/// * `user_stack` - Physical address of user stack top (must be identity-mapped)
///
/// # Safety
/// - entry_point must be valid executable code at an identity-mapped address
/// - user_stack must be valid stack memory at an identity-mapped address
/// - The code at entry_point should eventually call SYSCALL to return
pub unsafe fn enter_user_mode(entry_point: u64, user_stack: u64) {
    // User mode segments with RPL 3
    let user_cs: u64 = 0x20 | 3; // User code segment | RPL 3 = 0x23
    let user_ss: u64 = 0x18 | 3; // User data segment | RPL 3 = 0x1B

    // RFLAGS with IF (interrupts enabled)
    let rflags: u64 = 0x202;

    // Set up kernel GS base for SWAPGS
    // After SWAPGS, gs:[0] should contain the kernel syscall stack pointer
    let kernel_syscall_stack = SYSCALL_STACK.data.as_mut_ptr().add(SYSCALL_STACK_SIZE) as u64;
    wrmsr(0xC000_0102, kernel_syscall_stack); // MSR_KERNEL_GS_BASE

    // Use IRETQ to switch to ring 3
    // Stack layout for IRETQ: SS, RSP, RFLAGS, CS, RIP
    asm!(
        // Push SS
        "push {ss}",
        // Push RSP (user stack)
        "push {rsp}",
        // Push RFLAGS
        "push {rflags}",
        // Push CS
        "push {cs}",
        // Push RIP (entry point)
        "push {rip}",
        // Execute IRETQ
        "iretq",
        ss = in(reg) user_ss,
        rsp = in(reg) user_stack,
        rflags = in(reg) rflags,
        cs = in(reg) user_cs,
        rip = in(reg) entry_point,
        options(noreturn)
    );
}

/// Simple user mode test stub
///
/// This function is meant to be executed in ring 3.
/// It executes a SYSCALL to print a message and then terminates.
#[unsafe(naked)]
pub unsafe extern "C" fn user_mode_test_stub() {
    naked_asm!(
        // NtDebugPrint syscall
        // RAX = syscall number (52)
        // RDI = buffer pointer
        // RSI = length

        // Set up the message on stack (simpler than referencing data)
        // "User mode OK!\n" = 14 bytes

        // Use a simple approach: just call NtGetCurrentThreadId
        "mov rax, 4",       // NtGetCurrentThreadId
        "syscall",

        // Result is in RAX (thread ID)
        // Now call NtTerminateThread with that as exit code
        "mov rdi, rax",     // exit code = thread id
        "mov rax, 1",       // NtTerminateThread
        "syscall",

        // Should not reach here, but if we do, loop
        "2:",
        "jmp 2b",
    )
}

/// Run user code and return the result
///
/// This function:
/// 1. Saves kernel context (RSP, callee-saved registers, return address)
/// 2. Switches to user page tables
/// 3. Enters ring 3 via IRETQ
/// 4. User code executes and calls NtTerminateThread via SYSCALL
/// 5. NtTerminateThread restores kernel context and returns here
/// 6. Returns the exit code from user mode
///
/// # Arguments
/// * `entry_virt` - Virtual address of user code entry point (mapped in user page tables)
/// * `stack_virt` - Virtual address of user stack top (mapped in user page tables)
///
/// # Returns
/// Exit code from user mode (value passed to NtTerminateThread)
///
/// # Safety
/// - entry_virt must point to valid executable code in user page tables
/// - stack_virt must point to valid stack memory in user page tables
/// - User page tables must be properly initialized
#[inline(never)]
pub unsafe fn run_user_code(entry_virt: u64, stack_virt: u64) -> isize {
    // Set up kernel GS base for SWAPGS
    // When user code executes SYSCALL, SWAPGS will swap GS base to this value
    // Then gs:[0] will read the kernel stack pointer from SYSCALL_PERCPU.kernel_stack
    let kernel_syscall_stack = SYSCALL_STACK.data.as_mut_ptr().add(SYSCALL_STACK_SIZE) as u64;

    // Store the stack pointer in the per-CPU structure
    SYSCALL_PERCPU.kernel_stack = kernel_syscall_stack;

    // Set GS base to point to the per-CPU structure
    let percpu_addr = &SYSCALL_PERCPU as *const _ as u64;
    wrmsr(0xC000_0102, percpu_addr); // MSR_KERNEL_GS_BASE

    let user_cr3 = crate::mm::get_user_cr3();

    // Disable interrupts for the CR3 switch + IRETQ sequence
    core::arch::asm!("cli", options(nostack, preserves_flags));

    // Save kernel context before entering user mode
    // When NtTerminateThread restores context and does "ret",
    // it will return to just after the IRETQ asm block
    KERNEL_CONTEXT.valid = true;
    USER_MODE_RESULT = -1;

    // Save callee-saved registers
    asm!(
        "mov [{ctx} + 0], rsp",
        "mov [{ctx} + 8], rbp",
        "mov [{ctx} + 16], rbx",
        "mov [{ctx} + 24], r12",
        "mov [{ctx} + 32], r13",
        "mov [{ctx} + 40], r14",
        "mov [{ctx} + 48], r15",
        ctx = in(reg) &KERNEL_CONTEXT as *const _ as u64,
        options(nostack, preserves_flags),
    );

    // Now do the CR3 switch + IRETQ
    // Note: We need to save return address, switch CR3, and IRETQ atomically
    asm!(
        // Push return address for NtTerminateThread to use
        "lea rax, [rip + 2f]",
        "push rax",
        // Update saved RSP
        "mov [{ctx} + 0], rsp",

        // Switch to user page tables
        "mov rax, {user_cr3}",
        "mov cr3, rax",

        // Set up IRETQ stack frame (SS, RSP, RFLAGS, CS, RIP)
        "push {ss}",
        "push {stack}",
        "push {rflags}",
        "push {cs}",
        "push {entry}",

        // Execute IRETQ to enter ring 3
        "iretq",

        // Return point - NtTerminateThread will restore context and return here
        "2:",

        ctx = in(reg) &KERNEL_CONTEXT as *const _ as u64,
        user_cr3 = in(reg) user_cr3,
        entry = in(reg) entry_virt,
        stack = in(reg) stack_virt,
        cs = in(reg) 0x23u64,
        ss = in(reg) 0x1Bu64,
        rflags = in(reg) 0x202u64,
        out("rax") _,
        out("dx") _,
        clobber_abi("C"),
    );

    // Switch back to kernel page tables
    let kernel_cr3 = crate::mm::get_kernel_cr3();
    asm!("mov cr3, {}", in(reg) kernel_cr3, options(nostack));

    USER_MODE_RESULT
}

/// Test user mode by entering ring 3 and executing a syscall
///
/// # Safety
/// Requires proper page table setup with user-accessible mappings
pub unsafe fn test_user_mode() {
    // Check if user page tables are initialized
    if !crate::mm::user_pages_initialized() {
        crate::serial_println!("[SYSCALL] User page tables not initialized!");
        return;
    }

    // Use VIRTUAL addresses - these are what the user page tables map!
    // USER_TEST_BASE (0x400000) maps to the code area
    // USER_STACK_TOP (0x800000) is the stack top
    let code_virt = crate::mm::USER_TEST_BASE;
    let stack_virt = crate::mm::USER_STACK_TOP;

    // The user code was already copied by init_user_page_tables()
    let result = run_user_code(code_virt, stack_virt);

    crate::serial_println!("[SYSCALL] User mode test completed with exit code: {}", result);
}

// ============================================================================
// Delay Execution Syscall
// ============================================================================

/// NtDelayExecution - Delay (sleep) the current thread
fn sys_delay_execution(
    alertable: usize,
    delay_interval: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // delay_interval is a pointer to a LARGE_INTEGER (i64)
    // Positive value = absolute time, negative = relative time
    // For now, we only support relative delays
    let is_alertable = alertable != 0;

    if delay_interval == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Read the delay value (negative = relative delay in 100ns units)
    let delay_100ns = unsafe { *(delay_interval as *const i64) };

    if delay_100ns >= 0 {
        // Absolute time not yet supported
        return STATUS_NOT_IMPLEMENTED;
    }

    // Convert to milliseconds (negative 100ns -> positive ms)
    let delay_ms = ((-delay_100ns) / 10_000) as u64;

    // Use alertable delay mechanism
    unsafe {
        let completed = crate::ke::wait::ke_delay_execution_alertable(delay_ms, is_alertable);
        if completed {
            0 // STATUS_SUCCESS
        } else {
            0x101 // STATUS_ALERTED
        }
    }
}

// ============================================================================
// Synchronization Syscalls
// ============================================================================

/// Wait status codes for NT compatibility
#[allow(non_snake_case, non_upper_case_globals)]
pub mod wait_status {
    /// Object 0 was signaled
    pub const STATUS_WAIT_0: isize = 0x00000000;
    /// Object 1 was signaled (for multiple object waits)
    pub const STATUS_WAIT_1: isize = 0x00000001;
    /// Object 2 was signaled
    pub const STATUS_WAIT_2: isize = 0x00000002;
    /// Object 3 was signaled
    pub const STATUS_WAIT_3: isize = 0x00000003;
    /// Mutex was abandoned (owner terminated)
    pub const STATUS_ABANDONED_WAIT_0: isize = 0x00000080;
    /// Thread was alerted
    pub const STATUS_ALERTED: isize = 0x00000101;
    /// Wait timed out
    pub const STATUS_TIMEOUT: isize = 0x00000102;
    /// I/O operation pending
    pub const STATUS_PENDING: isize = 0x00000103;
    /// User APC was delivered
    pub const STATUS_USER_APC: isize = 0x000000C0;
    /// Invalid handle
    pub const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;
    /// Invalid parameter
    pub const STATUS_INVALID_PARAMETER: isize = 0xC000000Du32 as isize;
    /// Access denied
    pub const STATUS_ACCESS_DENIED: isize = 0xC0000022u32 as isize;
    /// Object type mismatch (not waitable)
    pub const STATUS_OBJECT_TYPE_MISMATCH: isize = 0xC0000024u32 as isize;
    /// Maximum wait objects exceeded
    pub const STATUS_MAXIMUM_WAIT_OBJECTS_EXCEEDED: isize = 0xC00000E1u32 as isize;
    /// Mutant limit exceeded
    pub const STATUS_MUTANT_LIMIT_EXCEEDED: isize = 0xC0000191u32 as isize;
    /// Mutant not owned (trying to release a mutex not owned by caller)
    pub const STATUS_MUTANT_NOT_OWNED: isize = 0xC0000046u32 as isize;
    /// Insufficient resources
    pub const STATUS_INSUFFICIENT_RESOURCES: isize = 0xC000009Au32 as isize;
    /// Buffer too small for requested information
    pub const STATUS_INFO_LENGTH_MISMATCH: isize = 0xC0000004u32 as isize;
    /// Object name not found
    pub const STATUS_OBJECT_NAME_NOT_FOUND: isize = 0xC0000034u32 as isize;
}

/// NtWaitForSingleObject - Wait for a single object to become signaled
///
/// # Arguments
/// * `handle` - Handle to the waitable object
/// * `alertable` - If TRUE, the wait is alertable (can be interrupted by APCs)
/// * `timeout` - Pointer to timeout value (NULL = infinite, negative = relative, positive = absolute)
///
/// # Returns
/// * STATUS_WAIT_0 (0) - Object was signaled
/// * STATUS_TIMEOUT (0x102) - Wait timed out
/// * STATUS_ALERTED (0x101) - Thread was alerted (alertable wait)
/// * STATUS_USER_APC (0xC0) - User APC was delivered
/// * STATUS_ABANDONED_WAIT_0 (0x80) - Mutex was abandoned
/// * STATUS_INVALID_HANDLE - Handle is invalid or not waitable
/// * STATUS_ACCESS_DENIED - Handle lacks SYNCHRONIZE access
///
/// # Waitable Object Types
/// * Event (manual-reset or auto-reset)
/// * Semaphore
/// * Mutex (Mutant)
/// * Timer
/// * Process (wait for termination)
/// * Thread (wait for termination)
/// * File (I/O completion)
/// * Section (signaled on mapping)
/// * Port (message available)
fn sys_wait_for_single_object(
    handle: usize,
    alertable: usize,
    timeout: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtWaitForSingleObject(handle=0x{:X}, alertable={}, timeout=0x{:X})",
        handle, alertable, timeout
    );

    let is_alertable = alertable != 0;

    // Validate handle
    if handle == 0 {
        crate::serial_println!("[SYSCALL] NtWaitForSingleObject: NULL handle");
        return wait_status::STATUS_INVALID_HANDLE;
    }

    // Parse timeout value
    // NULL (0) = infinite wait
    // Negative value = relative time in 100ns units
    // Positive value = absolute time
    let timeout_ms = if timeout == 0 {
        crate::serial_println!("[SYSCALL] NtWaitForSingleObject: infinite wait");
        None
    } else {
        let timeout_100ns = unsafe { *(timeout as *const i64) };
        if timeout_100ns == 0 {
            // Zero timeout = poll (don't block)
            crate::serial_println!("[SYSCALL] NtWaitForSingleObject: poll (no wait)");
            Some(0u64)
        } else if timeout_100ns < 0 {
            // Negative = relative time
            let ms = ((-timeout_100ns) / 10_000) as u64;
            crate::serial_println!("[SYSCALL] NtWaitForSingleObject: relative timeout {} ms", ms);
            Some(ms)
        } else {
            // Positive = absolute time (convert to relative based on current time)
            // For now, treat as immediate
            crate::serial_println!("[SYSCALL] NtWaitForSingleObject: absolute timeout (treating as immediate)");
            Some(0u64)
        }
    };

    // First, try our internal sync object pool
    if let Some((entry, obj_type)) = unsafe { get_sync_object(handle) } {
        crate::serial_println!("[SYSCALL] NtWaitForSingleObject: found sync object type {:?}", obj_type);

        let result = match obj_type {
            SyncObjectType::Event => unsafe {
                let event_ptr = core::ptr::addr_of_mut!((*entry).data.event);
                let header = &mut **event_ptr as *mut crate::ke::KEvent as *mut crate::ke::dispatcher::DispatcherHeader;
                wait_on_dispatcher_object(header, timeout_ms, is_alertable)
            },
            SyncObjectType::Semaphore => unsafe {
                let sem_ptr = core::ptr::addr_of_mut!((*entry).data.semaphore);
                let header = &mut **sem_ptr as *mut crate::ke::KSemaphore as *mut crate::ke::dispatcher::DispatcherHeader;
                wait_on_dispatcher_object(header, timeout_ms, is_alertable)
            },
            SyncObjectType::Mutex => unsafe {
                let mutex_ptr = core::ptr::addr_of_mut!((*entry).data.mutex);
                let header = &mut **mutex_ptr as *mut crate::ke::KMutex as *mut crate::ke::dispatcher::DispatcherHeader;
                wait_on_dispatcher_object(header, timeout_ms, is_alertable)
            },
            SyncObjectType::Timer => unsafe {
                let timer_ptr = core::ptr::addr_of_mut!((*entry).data.timer);
                let header = &mut **timer_ptr as *mut crate::ke::KTimer as *mut crate::ke::dispatcher::DispatcherHeader;
                wait_on_dispatcher_object(header, timeout_ms, is_alertable)
            },
            SyncObjectType::None => {
                crate::serial_println!("[SYSCALL] NtWaitForSingleObject: invalid sync object");
                wait_status::STATUS_INVALID_HANDLE
            }
        };

        return result;
    }

    // Check if it's a process handle - wait for process termination
    if let Some(pid) = unsafe { get_process_id(handle) } {
        crate::serial_println!("[SYSCALL] NtWaitForSingleObject: waiting on process {}", pid);
        return wait_on_process(pid, timeout_ms, is_alertable);
    }

    // Check if it's a thread handle - wait for thread termination
    if let Some(tid) = unsafe { get_thread_id(handle) } {
        crate::serial_println!("[SYSCALL] NtWaitForSingleObject: waiting on thread {}", tid);
        return wait_on_thread(tid, timeout_ms, is_alertable);
    }

    // Try object manager for kernel objects
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
        if obj.is_null() {
            crate::serial_println!("[SYSCALL] NtWaitForSingleObject: handle not found in OB");
            return wait_status::STATUS_INVALID_HANDLE;
        }
        obj
    };

    crate::serial_println!("[SYSCALL] NtWaitForSingleObject: found OB object at {:p}", object);

    // Wait on the dispatcher object with alertable support
    let result = {
        let header = object as *mut crate::ke::dispatcher::DispatcherHeader;
        wait_on_dispatcher_object(header, timeout_ms, is_alertable)
    };

    // Dereference the object
    unsafe { crate::ob::ob_dereference_object(object); }

    result
}

/// Wait on a dispatcher object (event, semaphore, mutex, etc.)
fn wait_on_dispatcher_object(
    header: *mut crate::ke::dispatcher::DispatcherHeader,
    timeout_ms: Option<u64>,
    is_alertable: bool,
) -> isize {
    use crate::ke::dispatcher::WaitStatus;
    use crate::ke::wait::ke_wait_for_single_object_alertable;

    let status = unsafe {
        ke_wait_for_single_object_alertable(header, timeout_ms, is_alertable)
    };

    match status {
        WaitStatus::Object0 => {
            crate::serial_println!("[SYSCALL] NtWaitForSingleObject: wait satisfied");
            wait_status::STATUS_WAIT_0
        }
        WaitStatus::Timeout => {
            crate::serial_println!("[SYSCALL] NtWaitForSingleObject: timeout");
            wait_status::STATUS_TIMEOUT
        }
        WaitStatus::Alerted => {
            crate::serial_println!("[SYSCALL] NtWaitForSingleObject: alerted");
            wait_status::STATUS_ALERTED
        }
        WaitStatus::Abandoned => {
            crate::serial_println!("[SYSCALL] NtWaitForSingleObject: abandoned mutex");
            wait_status::STATUS_ABANDONED_WAIT_0
        }
        WaitStatus::Invalid => {
            crate::serial_println!("[SYSCALL] NtWaitForSingleObject: invalid wait");
            wait_status::STATUS_INVALID_HANDLE
        }
    }
}

/// Wait for a process to terminate
fn wait_on_process(pid: u32, timeout_ms: Option<u64>, _is_alertable: bool) -> isize {
    // Look up process
    let process_ptr = unsafe { crate::ps::cid::ps_lookup_process_by_id(pid) };

    if process_ptr.is_null() {
        crate::serial_println!("[SYSCALL] NtWaitForSingleObject: process {} not found", pid);
        return wait_status::STATUS_INVALID_HANDLE;
    }

    // Check if already terminated
    let process = unsafe { &*(process_ptr as *const crate::ps::EProcess) };
    if process.exit_time != 0 {
        crate::serial_println!("[SYSCALL] NtWaitForSingleObject: process {} already terminated", pid);
        return wait_status::STATUS_WAIT_0;
    }

    // For now, if not terminated and timeout is 0, return timeout
    // A full implementation would add the thread to a wait list
    if let Some(ms) = timeout_ms {
        if ms == 0 {
            return wait_status::STATUS_TIMEOUT;
        }
    }

    // Simplified: poll until timeout
    // In a real implementation, we'd block the thread
    wait_status::STATUS_TIMEOUT
}

/// Wait for a thread to terminate
fn wait_on_thread(tid: u32, timeout_ms: Option<u64>, _is_alertable: bool) -> isize {
    // Look up thread
    let thread_ptr = unsafe { crate::ps::cid::ps_lookup_thread_by_id(tid) };

    if thread_ptr.is_null() {
        crate::serial_println!("[SYSCALL] NtWaitForSingleObject: thread {} not found", tid);
        return wait_status::STATUS_INVALID_HANDLE;
    }

    // Check if already terminated
    let thread = unsafe { &*(thread_ptr as *const crate::ps::EThread) };
    if thread.exit_time != 0 {
        crate::serial_println!("[SYSCALL] NtWaitForSingleObject: thread {} already terminated", tid);
        return wait_status::STATUS_WAIT_0;
    }

    // For now, if not terminated and timeout is 0, return timeout
    if let Some(ms) = timeout_ms {
        if ms == 0 {
            return wait_status::STATUS_TIMEOUT;
        }
    }

    // Simplified: return timeout
    wait_status::STATUS_TIMEOUT
}

/// NtWaitForMultipleObjects - Wait for multiple objects
///
/// Waits until one or all of the specified objects are in the signaled state
/// or the time-out interval elapses.
///
/// # Arguments
/// * `count` - Number of handles in the array (max 64)
/// * `handles` - Pointer to array of handles to wait on
/// * `wait_type` - WaitAll (0) or WaitAny (1)
/// * `alertable` - If TRUE, the wait is alertable (APCs can be delivered)
/// * `timeout` - Pointer to timeout value (NULL = infinite, negative = relative)
///
/// # Returns
/// * STATUS_WAIT_0 to STATUS_WAIT_63 - Object at index was signaled (WaitAny)
/// * STATUS_WAIT_0 - All objects signaled (WaitAll)
/// * STATUS_TIMEOUT - Wait timed out
/// * STATUS_ABANDONED_WAIT_0 to +63 - Mutex at index was abandoned
/// * STATUS_ALERTED - Wait was interrupted by an alert
/// * STATUS_USER_APC - User APC was delivered
fn sys_wait_for_multiple_objects(
    count: usize,
    handles: usize,
    wait_type: usize,
    alertable: usize,
    timeout: usize,
    _: usize,
) -> isize {
    use crate::ke::dispatcher::{DispatcherHeader, WaitStatus, WaitType, MAXIMUM_WAIT_OBJECTS};
    use crate::ke::wait::ke_wait_for_multiple_objects_alertable;

    crate::serial_println!(
        "[SYSCALL] NtWaitForMultipleObjects(count={}, handles=0x{:X}, wait_type={}, alertable={}, timeout=0x{:X})",
        count, handles, wait_type, alertable, timeout
    );

    let is_alertable = alertable != 0;
    // NT uses WaitAll=0, WaitAny=1
    let nt_wait_type = if wait_type == 0 { WaitType::WaitAll } else { WaitType::WaitAny };

    // Validate parameters
    if count == 0 {
        crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: count is 0");
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    if count > MAXIMUM_WAIT_OBJECTS {
        crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: count {} exceeds max {}", count, MAXIMUM_WAIT_OBJECTS);
        return wait_status::STATUS_MAXIMUM_WAIT_OBJECTS_EXCEEDED;
    }

    if handles == 0 {
        crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: NULL handles array");
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    // Parse timeout value
    // NULL (0) = infinite wait
    // Negative value = relative time in 100ns units
    // Positive value = absolute time
    let timeout_ms = if timeout == 0 {
        crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: infinite wait");
        None
    } else {
        let timeout_100ns = unsafe { *(timeout as *const i64) };
        if timeout_100ns == 0 {
            // Zero timeout = poll (don't block)
            crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: poll (no wait)");
            Some(0u64)
        } else if timeout_100ns < 0 {
            // Negative = relative time
            let ms = ((-timeout_100ns) / 10_000) as u64;
            crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: relative timeout {} ms", ms);
            Some(ms)
        } else {
            // Positive = absolute time (convert to relative based on current time)
            // For now, treat as immediate
            crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: absolute timeout (treating as immediate)");
            Some(0u64)
        }
    };

    // Get handle array from user space
    let handle_array = unsafe {
        core::slice::from_raw_parts(handles as *const usize, count)
    };

    // Build array of dispatcher headers
    // Track which handles came from where for proper cleanup
    let mut objects: [*mut DispatcherHeader; 64] = [core::ptr::null_mut(); 64];
    let mut from_ob: [bool; 64] = [false; 64]; // Track if handle came from OB (needs deref)
    let mut valid_count = 0usize;

    for (i, &handle) in handle_array.iter().enumerate() {
        if handle == 0 {
            crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: NULL handle at index {}", i);
            // Clean up already-acquired objects
            cleanup_wait_objects(&mut objects, &from_ob, valid_count);
            return wait_status::STATUS_INVALID_HANDLE;
        }

        // First, try our internal sync object pool
        if let Some((entry, obj_type)) = unsafe { get_sync_object(handle) } {
            let header = match obj_type {
                SyncObjectType::Event => unsafe {
                    let event_ptr = core::ptr::addr_of_mut!((*entry).data.event);
                    &mut **event_ptr as *mut crate::ke::KEvent as *mut DispatcherHeader
                },
                SyncObjectType::Semaphore => unsafe {
                    let sem_ptr = core::ptr::addr_of_mut!((*entry).data.semaphore);
                    &mut **sem_ptr as *mut crate::ke::KSemaphore as *mut DispatcherHeader
                },
                SyncObjectType::Mutex => unsafe {
                    let mutex_ptr = core::ptr::addr_of_mut!((*entry).data.mutex);
                    &mut **mutex_ptr as *mut crate::ke::KMutex as *mut DispatcherHeader
                },
                SyncObjectType::Timer => unsafe {
                    let timer_ptr = core::ptr::addr_of_mut!((*entry).data.timer);
                    &mut **timer_ptr as *mut crate::ke::KTimer as *mut DispatcherHeader
                },
                SyncObjectType::None => {
                    crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: invalid sync object at index {}", i);
                    cleanup_wait_objects(&mut objects, &from_ob, valid_count);
                    return wait_status::STATUS_INVALID_HANDLE;
                }
            };
            objects[i] = header;
            from_ob[i] = false; // From sync pool, no deref needed
            valid_count += 1;
            continue;
        }

        // Try object manager for kernel objects
        let obj = unsafe { crate::ob::ob_reference_object_by_handle(handle as u32, 0) };
        if !obj.is_null() {
            objects[i] = obj as *mut DispatcherHeader;
            from_ob[i] = true; // From OB, needs deref
            valid_count += 1;
            continue;
        }

        // Handle not found in any pool
        crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: handle 0x{:X} not found at index {}", handle, i);
        cleanup_wait_objects(&mut objects, &from_ob, valid_count);
        return wait_status::STATUS_INVALID_HANDLE;
    }

    crate::serial_println!(
        "[SYSCALL] NtWaitForMultipleObjects: waiting on {} objects, type={:?}",
        valid_count,
        if wait_type == 0 { "WaitAll" } else { "WaitAny" }
    );

    // Wait on all objects with alertable support
    let result = unsafe {
        let objects_slice = &objects[..valid_count];
        let status = ke_wait_for_multiple_objects_alertable(objects_slice, nt_wait_type, timeout_ms, is_alertable);

        // Convert WaitStatus to NT status code
        // The WaitStatus value for signaled objects encodes the index (0-63)
        let status_val = status as i32;

        if (0..64).contains(&status_val) {
            // Object at index was signaled - STATUS_WAIT_0 + index
            crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: wait satisfied (object {})", status_val);
            wait_status::STATUS_WAIT_0 + status_val as isize
        } else if (0x80..0x80 + 64).contains(&status_val) {
            // Abandoned mutex at index - STATUS_ABANDONED_WAIT_0 + index
            let index = status_val - 0x80;
            crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: abandoned mutex at index {}", index);
            wait_status::STATUS_ABANDONED_WAIT_0 + index as isize
        } else {
            match status {
                WaitStatus::Timeout => {
                    crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: timeout");
                    wait_status::STATUS_TIMEOUT
                }
                WaitStatus::Alerted => {
                    crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: alerted");
                    wait_status::STATUS_ALERTED
                }
                WaitStatus::Invalid => {
                    crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: invalid wait");
                    wait_status::STATUS_INVALID_HANDLE
                }
                _ => {
                    crate::serial_println!("[SYSCALL] NtWaitForMultipleObjects: unexpected status {}", status_val);
                    wait_status::STATUS_INVALID_HANDLE
                }
            }
        }
    };

    // Dereference OB objects (sync pool objects don't need deref)
    cleanup_wait_objects(&mut objects, &from_ob, valid_count);

    result
}

/// Helper to get object index from WaitStatus for multiple object waits
fn wait_status_to_index(status: crate::ke::dispatcher::WaitStatus) -> usize {
    use crate::ke::dispatcher::WaitStatus;
    match status {
        WaitStatus::Object0 => 0,
        // For higher indices, the status value IS the index (0-63)
        _ => {
            let val = status as i32;
            if (0..64).contains(&val) {
                val as usize
            } else {
                0
            }
        }
    }
}

/// Clean up objects acquired during NtWaitForMultipleObjects setup
fn cleanup_wait_objects(
    objects: &mut [*mut crate::ke::dispatcher::DispatcherHeader; 64],
    from_ob: &[bool; 64],
    count: usize,
) {
    for i in 0..count {
        if from_ob[i] && !objects[i].is_null() {
            unsafe { crate::ob::ob_dereference_object(objects[i] as *mut u8); }
        }
    }
}

/// NtSignalAndWaitForSingleObject - Atomically signal one object and wait on another
///
/// This syscall provides atomic signal-and-wait semantics, which is essential for
/// implementing condition variables and other synchronization patterns.
///
/// # Arguments
/// * `signal_handle` - Handle to the object to signal (Event, Semaphore, or Mutex)
/// * `wait_handle` - Handle to the object to wait on
/// * `alertable` - If TRUE, the wait is alertable (APCs can be delivered)
/// * `timeout` - Pointer to timeout value (NULL = infinite, negative = relative)
///
/// # Returns
/// * STATUS_SUCCESS/STATUS_WAIT_0 - Object was signaled and wait was satisfied
/// * STATUS_TIMEOUT - Wait timed out
/// * STATUS_ABANDONED_WAIT_0 - Waited on mutex was abandoned
/// * STATUS_ALERTED - Wait was interrupted by an alert
/// * STATUS_USER_APC - User APC was delivered
/// * STATUS_INVALID_HANDLE - Invalid handle
/// * STATUS_OBJECT_TYPE_MISMATCH - Signal handle is not a valid signal object
/// * STATUS_ACCESS_DENIED - Access denied to one of the objects
fn sys_signal_and_wait_for_single_object(
    signal_handle: usize,
    wait_handle: usize,
    alertable: usize,
    timeout: usize,
    _: usize,
    _: usize,
) -> isize {
    use crate::ke::dispatcher::DispatcherHeader;

    crate::serial_println!(
        "[SYSCALL] NtSignalAndWaitForSingleObject(signal=0x{:X}, wait=0x{:X}, alertable={}, timeout=0x{:X})",
        signal_handle, wait_handle, alertable, timeout
    );

    let is_alertable = alertable != 0;

    // Validate handles
    if signal_handle == 0 {
        crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: NULL signal handle");
        return wait_status::STATUS_INVALID_HANDLE;
    }

    if wait_handle == 0 {
        crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: NULL wait handle");
        return wait_status::STATUS_INVALID_HANDLE;
    }

    // Cannot signal and wait on the same object
    if signal_handle == wait_handle {
        crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: same handle for signal and wait");
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    // Parse timeout value
    let timeout_ms = if timeout == 0 {
        crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: infinite wait");
        None
    } else {
        let timeout_100ns = unsafe { *(timeout as *const i64) };
        if timeout_100ns == 0 {
            crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: poll (no wait)");
            Some(0u64)
        } else if timeout_100ns < 0 {
            let ms = ((-timeout_100ns) / 10_000) as u64;
            crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: relative timeout {} ms", ms);
            Some(ms)
        } else {
            crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: absolute timeout (treating as immediate)");
            Some(0u64)
        }
    };

    // Step 1: Signal the first object
    let signal_result = signal_object_internal(signal_handle);
    if signal_result != 0 {
        crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: failed to signal object (status=0x{:X})", signal_result);
        return signal_result;
    }

    crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: signaled object 0x{:X}", signal_handle);

    // Step 2: Wait on the second object
    // First, try sync object pool
    if let Some((entry, obj_type)) = unsafe { get_sync_object(wait_handle) } {
        crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: waiting on sync object type {:?}", obj_type);

        let result = match obj_type {
            SyncObjectType::Event => unsafe {
                let event_ptr = core::ptr::addr_of_mut!((*entry).data.event);
                let header = &mut **event_ptr as *mut crate::ke::KEvent as *mut DispatcherHeader;
                wait_on_dispatcher_object(header, timeout_ms, is_alertable)
            },
            SyncObjectType::Semaphore => unsafe {
                let sem_ptr = core::ptr::addr_of_mut!((*entry).data.semaphore);
                let header = &mut **sem_ptr as *mut crate::ke::KSemaphore as *mut DispatcherHeader;
                wait_on_dispatcher_object(header, timeout_ms, is_alertable)
            },
            SyncObjectType::Mutex => unsafe {
                let mutex_ptr = core::ptr::addr_of_mut!((*entry).data.mutex);
                let header = &mut **mutex_ptr as *mut crate::ke::KMutex as *mut DispatcherHeader;
                wait_on_dispatcher_object(header, timeout_ms, is_alertable)
            },
            SyncObjectType::Timer => unsafe {
                let timer_ptr = core::ptr::addr_of_mut!((*entry).data.timer);
                let header = &mut **timer_ptr as *mut crate::ke::KTimer as *mut DispatcherHeader;
                wait_on_dispatcher_object(header, timeout_ms, is_alertable)
            },
            SyncObjectType::None => {
                crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: invalid wait sync object");
                wait_status::STATUS_INVALID_HANDLE
            }
        };

        return result;
    }

    // Check if it's a process handle - wait for process termination
    if let Some(pid) = unsafe { get_process_id(wait_handle) } {
        crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: waiting on process {}", pid);
        return wait_on_process(pid, timeout_ms, is_alertable);
    }

    // Check if it's a thread handle - wait for thread termination
    if let Some(tid) = unsafe { get_thread_id(wait_handle) } {
        crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: waiting on thread {}", tid);
        return wait_on_thread(tid, timeout_ms, is_alertable);
    }

    // Try object manager for kernel objects
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(wait_handle as u32, 0);
        if obj.is_null() {
            crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: wait handle not found in OB");
            return wait_status::STATUS_INVALID_HANDLE;
        }
        obj
    };

    crate::serial_println!("[SYSCALL] NtSignalAndWaitForSingleObject: waiting on OB object at {:p}", object);

    let result = {
        let header = object as *mut DispatcherHeader;
        wait_on_dispatcher_object(header, timeout_ms, is_alertable)
    };

    // Dereference the object
    unsafe { crate::ob::ob_dereference_object(object); }

    result
}

/// Internal helper to signal an object
///
/// Signals the object based on its type:
/// - Event: Sets the event
/// - Semaphore: Releases with count 1
/// - Mutex: Releases the mutex
///
/// Returns STATUS_SUCCESS (0) on success, error status on failure
fn signal_object_internal(handle: usize) -> isize {
    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(handle) } {
        match obj_type {
            SyncObjectType::Event => {
                unsafe {
                    let event = &mut *core::ptr::addr_of_mut!((*entry).data.event);
                    event.set();
                }
                crate::serial_println!("[SYSCALL] signal_object_internal: set event");
                return 0; // STATUS_SUCCESS
            }
            SyncObjectType::Semaphore => {
                unsafe {
                    let sem = &mut *core::ptr::addr_of_mut!((*entry).data.semaphore);
                    sem.release(1);
                }
                crate::serial_println!("[SYSCALL] signal_object_internal: released semaphore");
                return 0;
            }
            SyncObjectType::Mutex => {
                unsafe {
                    let mutex = &mut *core::ptr::addr_of_mut!((*entry).data.mutex);
                    if !mutex.is_owned() {
                        // Cannot release a mutex we don't own
                        crate::serial_println!("[SYSCALL] signal_object_internal: mutex not owned");
                        return wait_status::STATUS_MUTANT_NOT_OWNED;
                    }
                    mutex.release();
                }
                crate::serial_println!("[SYSCALL] signal_object_internal: released mutex");
                return 0;
            }
            SyncObjectType::Timer => {
                // Timers cannot be directly signaled - use NtSetTimer to arm them
                crate::serial_println!("[SYSCALL] signal_object_internal: timer cannot be signaled directly");
                return wait_status::STATUS_OBJECT_TYPE_MISMATCH;
            }
            SyncObjectType::None => {
                return wait_status::STATUS_INVALID_HANDLE;
            }
        }
    }

    // Try object manager
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
        if obj.is_null() {
            crate::serial_println!("[SYSCALL] signal_object_internal: handle not found");
            return wait_status::STATUS_INVALID_HANDLE;
        }
        obj
    };

    // Determine object type and signal appropriately
    // We need to check the dispatcher header type
    let header = object as *mut crate::ke::dispatcher::DispatcherHeader;
    let obj_type = unsafe { (*header).object_type };

    let result = match obj_type {
        crate::ke::dispatcher::DispatcherType::Event => {
            unsafe {
                let event = object as *mut crate::ke::event::KEvent;
                (*event).set();
            }
            crate::serial_println!("[SYSCALL] signal_object_internal: set OB event");
            0
        }
        crate::ke::dispatcher::DispatcherType::Semaphore => {
            unsafe {
                let sem = object as *mut crate::ke::KSemaphore;
                (*sem).release(1);
            }
            crate::serial_println!("[SYSCALL] signal_object_internal: released OB semaphore");
            0
        }
        crate::ke::dispatcher::DispatcherType::Mutex => {
            unsafe {
                let mutex = object as *mut crate::ke::KMutex;
                if !(*mutex).is_owned() {
                    crate::serial_println!("[SYSCALL] signal_object_internal: OB mutex not owned");
                    wait_status::STATUS_MUTANT_NOT_OWNED
                } else {
                    (*mutex).release();
                    crate::serial_println!("[SYSCALL] signal_object_internal: released OB mutex");
                    0
                }
            }
        }
        _ => {
            crate::serial_println!("[SYSCALL] signal_object_internal: unsupported object type {:?}", obj_type);
            wait_status::STATUS_OBJECT_TYPE_MISMATCH
        }
    };

    unsafe { crate::ob::ob_dereference_object(object); }

    result
}

/// NtSetEvent - Set (signal) an event
fn sys_set_event(
    handle: usize,
    previous_state: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(handle) } {
        if obj_type != SyncObjectType::Event {
            return STATUS_OBJECT_TYPE_MISMATCH;
        }

        let was_signaled = unsafe {
            let event = &mut *core::ptr::addr_of_mut!((*entry).data.event);
            event.set()
        };

        if previous_state != 0 {
            unsafe { *(previous_state as *mut i32) = was_signaled as i32; }
        }

        return STATUS_SUCCESS;
    }

    // Fall back to object manager handles
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
        if obj.is_null() {
            return STATUS_INVALID_HANDLE;
        }
        obj
    };

    let was_signaled = unsafe {
        let event = object as *mut crate::ke::event::KEvent;
        (*event).set()
    };

    if previous_state != 0 {
        unsafe { *(previous_state as *mut i32) = was_signaled as i32; }
    }

    unsafe { crate::ob::ob_dereference_object(object); }

    STATUS_SUCCESS
}

/// NtResetEvent - Reset (unsignal) an event
fn sys_reset_event(
    handle: usize,
    previous_state: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(handle) } {
        if obj_type != SyncObjectType::Event {
            return STATUS_OBJECT_TYPE_MISMATCH;
        }

        let was_signaled = unsafe {
            let event = &mut *core::ptr::addr_of_mut!((*entry).data.event);
            event.reset()
        };

        if previous_state != 0 {
            unsafe { *(previous_state as *mut i32) = was_signaled as i32; }
        }

        return STATUS_SUCCESS;
    }

    // Fall back to object manager handles
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
        if obj.is_null() {
            return STATUS_INVALID_HANDLE;
        }
        obj
    };

    let was_signaled = unsafe {
        let event = object as *mut crate::ke::event::KEvent;
        (*event).reset()
    };

    if previous_state != 0 {
        unsafe { *(previous_state as *mut i32) = was_signaled as i32; }
    }

    unsafe { crate::ob::ob_dereference_object(object); }

    STATUS_SUCCESS
}

/// NtClearEvent - Clear (unsignal) an event
///
/// This is equivalent to NtResetEvent but follows the NT naming convention.
fn sys_clear_event(
    handle: usize,
    previous_state: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // ClearEvent is identical to ResetEvent
    sys_reset_event(handle, previous_state, 0, 0, 0, 0)
}

/// NtPulseEvent - Pulse an event
///
/// Sets the event, wakes any waiters, then immediately resets.
/// For notification events: wakes all current waiters
/// For synchronization events: wakes one waiter
fn sys_pulse_event(
    handle: usize,
    previous_state: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(handle) } {
        if obj_type != SyncObjectType::Event {
            return STATUS_OBJECT_TYPE_MISMATCH;
        }

        let was_signaled = unsafe {
            let event = &mut *core::ptr::addr_of_mut!((*entry).data.event);
            event.pulse()
        };

        if previous_state != 0 {
            unsafe { *(previous_state as *mut i32) = was_signaled as i32; }
        }

        crate::serial_println!("[SYSCALL] NtPulseEvent(handle={:#x}) -> prev={}", handle, was_signaled);
        return STATUS_SUCCESS;
    }

    // Fall back to object manager handles
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
        if obj.is_null() {
            return STATUS_INVALID_HANDLE;
        }
        obj
    };

    let was_signaled = unsafe {
        let event = object as *mut crate::ke::event::KEvent;
        (*event).pulse()
    };

    if previous_state != 0 {
        unsafe { *(previous_state as *mut i32) = was_signaled as i32; }
    }

    unsafe { crate::ob::ob_dereference_object(object); }

    crate::serial_println!("[SYSCALL] NtPulseEvent(handle={:#x}) via OB -> prev={}", handle, was_signaled);
    STATUS_SUCCESS
}

// ============================================================================
// Synchronization Object Pool
// ============================================================================

/// Maximum number of sync objects
const MAX_SYNC_OBJECTS: usize = 128;

/// Sync object pool entry
#[repr(C)]
union SyncObjectUnion {
    event: core::mem::ManuallyDrop<crate::ke::KEvent>,
    semaphore: core::mem::ManuallyDrop<crate::ke::KSemaphore>,
    mutex: core::mem::ManuallyDrop<crate::ke::KMutex>,
    timer: core::mem::ManuallyDrop<crate::ke::KTimer>,
}

/// Type of sync object
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncObjectType {
    None = 0,
    Event = 1,
    Semaphore = 2,
    Mutex = 3,
    Timer = 4,
}

/// Sync object pool entry wrapper
struct SyncObjectEntry {
    obj_type: SyncObjectType,
    data: SyncObjectUnion,
}

impl SyncObjectEntry {
    const fn new() -> Self {
        Self {
            obj_type: SyncObjectType::None,
            data: SyncObjectUnion {
                event: core::mem::ManuallyDrop::new(crate::ke::KEvent::new()),
            },
        }
    }
}

/// Pool of synchronization objects
static mut SYNC_OBJECT_POOL: [SyncObjectEntry; MAX_SYNC_OBJECTS] = {
    const INIT: SyncObjectEntry = SyncObjectEntry::new();
    [INIT; MAX_SYNC_OBJECTS]
};

/// Bitmap for sync object allocation
static mut SYNC_OBJECT_BITMAP: [u64; 2] = [0; 2]; // 128 bits

/// Sync object handle base (0x1000+)
const SYNC_HANDLE_BASE: usize = 0x1000;

/// Allocate a sync object from the pool
unsafe fn alloc_sync_object(obj_type: SyncObjectType) -> Option<usize> {
    for word_idx in 0..2 {
        if SYNC_OBJECT_BITMAP[word_idx] != u64::MAX {
            for bit_idx in 0..64 {
                let global_idx = word_idx * 64 + bit_idx;
                if global_idx >= MAX_SYNC_OBJECTS {
                    return None;
                }
                if SYNC_OBJECT_BITMAP[word_idx] & (1 << bit_idx) == 0 {
                    SYNC_OBJECT_BITMAP[word_idx] |= 1 << bit_idx;
                    SYNC_OBJECT_POOL[global_idx].obj_type = obj_type;
                    return Some(global_idx + SYNC_HANDLE_BASE);
                }
            }
        }
    }
    None
}

/// Get sync object from handle
unsafe fn get_sync_object(handle: usize) -> Option<(*mut SyncObjectEntry, SyncObjectType)> {
    if handle < SYNC_HANDLE_BASE {
        return None;
    }
    let idx = handle - SYNC_HANDLE_BASE;
    if idx >= MAX_SYNC_OBJECTS {
        return None;
    }
    let word_idx = idx / 64;
    let bit_idx = idx % 64;
    if SYNC_OBJECT_BITMAP[word_idx] & (1 << bit_idx) == 0 {
        return None;
    }
    let entry = &mut SYNC_OBJECT_POOL[idx];
    Some((entry as *mut SyncObjectEntry, entry.obj_type))
}

/// Free a sync object
unsafe fn free_sync_object(handle: usize) {
    if handle >= SYNC_HANDLE_BASE {
        let idx = handle - SYNC_HANDLE_BASE;
        if idx < MAX_SYNC_OBJECTS {
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            SYNC_OBJECT_BITMAP[word_idx] &= !(1 << bit_idx);
            SYNC_OBJECT_POOL[idx].obj_type = SyncObjectType::None;
        }
    }
}

/// NtCreateEvent - Create a new event object
fn sys_create_event(
    event_handle: usize,
    _desired_access: usize,
    _object_attributes: usize,
    event_type: usize,
    initial_state: usize,
    _: usize,
) -> isize {
    if event_handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate event from pool
    let handle = match unsafe { alloc_sync_object(SyncObjectType::Event) } {
        Some(h) => h,
        None => return STATUS_INSUFFICIENT_RESOURCES,
    };

    // Initialize the event
    unsafe {
        let (entry, _) = get_sync_object(handle).unwrap();
        let event = &mut *core::ptr::addr_of_mut!((*entry).data.event);

        // event_type: 0 = NotificationEvent, 1 = SynchronizationEvent
        let ke_event_type = if event_type == 0 {
            crate::ke::EventType::Notification
        } else {
            crate::ke::EventType::Synchronization
        };

        event.init(ke_event_type, initial_state != 0);

        *(event_handle as *mut usize) = handle;
    }

    crate::serial_println!("[SYSCALL] NtCreateEvent(type={}, init={}) -> handle {:#x}",
        event_type, initial_state, handle);

    STATUS_SUCCESS
}

/// NtReleaseSemaphore - Release a semaphore
fn sys_release_semaphore(
    handle: usize,
    release_count: usize,
    previous_count: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(handle) } {
        if obj_type != SyncObjectType::Semaphore {
            return STATUS_OBJECT_TYPE_MISMATCH;
        }

        let prev = unsafe {
            let sem = &mut *core::ptr::addr_of_mut!((*entry).data.semaphore);
            sem.release(release_count as i32)
        };

        if previous_count != 0 {
            unsafe { *(previous_count as *mut i32) = prev; }
        }

        return STATUS_SUCCESS;
    }

    // Fall back to object manager handles
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
        if obj.is_null() {
            return STATUS_INVALID_HANDLE;
        }
        obj
    };

    let prev = unsafe {
        let sem = object as *mut crate::ke::KSemaphore;
        (*sem).release(release_count as i32)
    };

    if previous_count != 0 {
        unsafe { *(previous_count as *mut i32) = prev; }
    }

    unsafe { crate::ob::ob_dereference_object(object); }

    STATUS_SUCCESS
}

/// NtCreateSemaphore - Create a semaphore object
fn sys_create_semaphore(
    semaphore_handle: usize,
    _desired_access: usize,
    _object_attributes: usize,
    initial_count: usize,
    maximum_count: usize,
    _: usize,
) -> isize {
    if semaphore_handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate semaphore from pool
    let handle = match unsafe { alloc_sync_object(SyncObjectType::Semaphore) } {
        Some(h) => h,
        None => return STATUS_INSUFFICIENT_RESOURCES,
    };

    // Initialize the semaphore
    unsafe {
        let (entry, _) = get_sync_object(handle).unwrap();
        let sem = &mut *core::ptr::addr_of_mut!((*entry).data.semaphore);

        *sem = core::mem::ManuallyDrop::new(crate::ke::KSemaphore::new());
        sem.init(initial_count as i32, maximum_count as i32);

        *(semaphore_handle as *mut usize) = handle;
    }

    crate::serial_println!("[SYSCALL] NtCreateSemaphore(init={}, max={}) -> handle {:#x}",
        initial_count, maximum_count, handle);

    STATUS_SUCCESS
}

/// NtReleaseMutant - Release a mutex (mutant in NT terminology)
fn sys_release_mutant(
    handle: usize,
    previous_count: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(handle) } {
        if obj_type != SyncObjectType::Mutex {
            return STATUS_OBJECT_TYPE_MISMATCH;
        }

        let prev = unsafe {
            let mutex = &mut *core::ptr::addr_of_mut!((*entry).data.mutex);
            let was_owned = mutex.is_owned();
            mutex.release();
            was_owned as i32
        };

        if previous_count != 0 {
            unsafe { *(previous_count as *mut i32) = prev; }
        }

        return STATUS_SUCCESS;
    }

    // Fall back to object manager handles
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(handle as u32, 0);
        if obj.is_null() {
            return STATUS_INVALID_HANDLE;
        }
        obj
    };

    let prev = unsafe {
        let mutex = object as *mut crate::ke::KMutex;
        let was_owned = (*mutex).is_owned();
        (*mutex).release();
        was_owned as i32
    };

    if previous_count != 0 {
        unsafe { *(previous_count as *mut i32) = prev; }
    }

    unsafe { crate::ob::ob_dereference_object(object); }

    STATUS_SUCCESS
}

/// NtCreateMutant - Create a mutex object
fn sys_create_mutant(
    mutant_handle: usize,
    _desired_access: usize,
    _object_attributes: usize,
    initial_owner: usize,
    _: usize, _: usize,
) -> isize {
    if mutant_handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate mutex from pool
    let handle = match unsafe { alloc_sync_object(SyncObjectType::Mutex) } {
        Some(h) => h,
        None => return STATUS_INSUFFICIENT_RESOURCES,
    };

    // Initialize the mutex
    unsafe {
        let (entry, _) = get_sync_object(handle).unwrap();
        let mutex = &mut *core::ptr::addr_of_mut!((*entry).data.mutex);

        *mutex = core::mem::ManuallyDrop::new(crate::ke::KMutex::new());
        mutex.init();

        // If initial_owner is true, acquire the mutex
        if initial_owner != 0 {
            mutex.acquire();
        }

        *(mutant_handle as *mut usize) = handle;
    }

    crate::serial_println!("[SYSCALL] NtCreateMutant(initial_owner={}) -> handle {:#x}",
        initial_owner, handle);

    STATUS_SUCCESS
}

// ============================================================================
// Timer Syscalls
// ============================================================================

/// Timer type for NtCreateTimer
#[allow(non_upper_case_globals)]
pub mod timer_type {
    /// Notification timer - stays signaled until explicitly reset
    pub const NotificationTimer: u32 = 0;
    /// Synchronization timer - auto-resets after satisfying one wait
    pub const SynchronizationTimer: u32 = 1;
}

/// Timer information class for NtQueryTimer
#[allow(non_upper_case_globals)]
pub mod timer_info_class {
    /// Basic timer information
    pub const TimerBasicInformation: u32 = 0;
}

/// Timer basic information structure
#[repr(C)]
pub struct TimerBasicInformation {
    /// Time remaining until timer expires (negative = relative, positive = absolute)
    pub remaining_time: i64,
    /// Whether the timer is currently signaled
    pub timer_state: u32,
}

// ============================================================================
// Named Timer Table
// ============================================================================

/// Maximum number of named timers
const MAX_NAMED_TIMERS: usize = 64;

/// Maximum timer name length
const MAX_TIMER_NAME_LEN: usize = 64;

/// Named timer entry
struct NamedTimerEntry {
    /// Timer name (null-terminated UTF-8)
    name: [u8; MAX_TIMER_NAME_LEN],
    /// Name length
    name_len: usize,
    /// Handle to the timer in sync object pool
    handle: usize,
    /// Is this entry in use
    in_use: bool,
}

impl NamedTimerEntry {
    const fn new() -> Self {
        Self {
            name: [0; MAX_TIMER_NAME_LEN],
            name_len: 0,
            handle: 0,
            in_use: false,
        }
    }
}

/// Named timer table
static mut NAMED_TIMER_TABLE: [NamedTimerEntry; MAX_NAMED_TIMERS] = {
    const INIT: NamedTimerEntry = NamedTimerEntry::new();
    [INIT; MAX_NAMED_TIMERS]
};

/// Register a named timer
unsafe fn register_named_timer(name: &[u8], handle: usize) -> bool {
    for entry in NAMED_TIMER_TABLE.iter_mut() {
        if !entry.in_use {
            let len = name.len().min(MAX_TIMER_NAME_LEN - 1);
            entry.name[..len].copy_from_slice(&name[..len]);
            entry.name[len] = 0;
            entry.name_len = len;
            entry.handle = handle;
            entry.in_use = true;
            return true;
        }
    }
    false
}

/// Find a named timer by name
unsafe fn find_named_timer(name: &[u8]) -> Option<usize> {
    for entry in NAMED_TIMER_TABLE.iter() {
        if entry.in_use && entry.name_len == name.len()
            && &entry.name[..entry.name_len] == name {
                return Some(entry.handle);
            }
    }
    None
}

/// Unregister a named timer
#[allow(dead_code)]
unsafe fn unregister_named_timer(handle: usize) {
    for entry in NAMED_TIMER_TABLE.iter_mut() {
        if entry.in_use && entry.handle == handle {
            entry.in_use = false;
            entry.name_len = 0;
            entry.handle = 0;
            break;
        }
    }
}

/// NtCreateTimer - Create a timer object
///
/// Creates a waitable timer that can be set to expire at a specified time.
///
/// # Arguments
/// * `timer_handle` - Pointer to receive the timer handle
/// * `desired_access` - Access rights (TIMER_ALL_ACCESS, etc.)
/// * `object_attributes` - Optional object attributes (name, security)
/// * `timer_type` - NotificationTimer (0) or SynchronizationTimer (1)
///
/// # Returns
/// * STATUS_SUCCESS - Timer created successfully
/// * STATUS_INVALID_PARAMETER - Invalid parameter
/// * STATUS_INSUFFICIENT_RESOURCES - No memory available
fn sys_create_timer(
    timer_handle: usize,
    _desired_access: usize,
    object_attributes: usize,
    timer_type_arg: usize,
    _: usize,
    _: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtCreateTimer(handle_ptr=0x{:X}, timer_type={})",
        timer_handle, timer_type_arg
    );

    if timer_handle == 0 {
        crate::serial_println!("[SYSCALL] NtCreateTimer: NULL handle pointer");
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    // Validate timer type
    if timer_type_arg > 1 {
        crate::serial_println!("[SYSCALL] NtCreateTimer: invalid timer type {}", timer_type_arg);
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    // Extract timer name if object_attributes is provided
    let mut timer_name: Option<([u8; MAX_TIMER_NAME_LEN], usize)> = None;
    if object_attributes != 0 {
        let obj_attr = unsafe { &*(object_attributes as *const ObjectAttributes) };
        if obj_attr.object_name != 0 {
            let unicode_str = unsafe { &*(obj_attr.object_name as *const UnicodeString) };
            if unicode_str.buffer != 0 && unicode_str.length > 0 {
                let name_len_chars = (unicode_str.length / 2) as usize;
                let mut name_buf = [0u8; MAX_TIMER_NAME_LEN];
                let mut name_len = 0usize;

                unsafe {
                    let utf16_ptr = unicode_str.buffer as *const u16;
                    for i in 0..name_len_chars {
                        if name_len >= MAX_TIMER_NAME_LEN - 1 {
                            break;
                        }
                        let ch = *utf16_ptr.add(i);
                        if ch < 128 {
                            name_buf[name_len] = ch as u8;
                            name_len += 1;
                        }
                    }
                }

                if name_len > 0 {
                    // Check if timer with this name already exists
                    if let Some(existing_handle) = unsafe { find_named_timer(&name_buf[..name_len]) } {
                        // Timer exists - return existing handle (or error depending on flags)
                        unsafe { *(timer_handle as *mut usize) = existing_handle; }
                        crate::serial_println!("[SYSCALL] NtCreateTimer: existing timer found -> handle 0x{:X}", existing_handle);
                        return 0; // STATUS_SUCCESS (should be STATUS_OBJECT_NAME_EXISTS for full compat)
                    }
                    timer_name = Some((name_buf, name_len));
                }
            }
        }
    }

    // Allocate timer from pool
    let handle = match unsafe { alloc_sync_object(SyncObjectType::Timer) } {
        Some(h) => h,
        None => {
            crate::serial_println!("[SYSCALL] NtCreateTimer: pool exhausted");
            return wait_status::STATUS_INSUFFICIENT_RESOURCES;
        }
    };

    // Initialize the timer
    unsafe {
        let (entry, _) = get_sync_object(handle).unwrap();
        let timer = &mut *core::ptr::addr_of_mut!((*entry).data.timer);

        // Create and initialize the timer
        *timer = core::mem::ManuallyDrop::new(crate::ke::KTimer::new());

        // Initialize with the appropriate timer type
        let ke_timer_type = if timer_type_arg == timer_type::NotificationTimer as usize {
            crate::ke::TimerType::Notification
        } else {
            crate::ke::TimerType::Synchronization
        };
        timer.init_ex(ke_timer_type);

        // Return handle to caller
        *(timer_handle as *mut usize) = handle;
    }

    // Register named timer if name was provided
    if let Some((name_buf, name_len)) = timer_name {
        unsafe {
            if !register_named_timer(&name_buf[..name_len], handle) {
                crate::serial_println!("[SYSCALL] NtCreateTimer: failed to register named timer");
                // Timer is still created, just not named
            } else {
                let name_str = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("<invalid>");
                crate::serial_println!("[SYSCALL] NtCreateTimer: registered named timer '{}'", name_str);
            }
        }
    }

    crate::serial_println!("[SYSCALL] NtCreateTimer: created timer handle 0x{:X}", handle);

    0 // STATUS_SUCCESS
}

/// NtOpenTimer - Open an existing named timer object
///
/// Opens a handle to an existing timer object by name.
///
/// # Arguments
/// * `timer_handle` - Pointer to receive the timer handle
/// * `desired_access` - Access rights requested
/// * `object_attributes` - Pointer to OBJECT_ATTRIBUTES containing the timer name
///
/// # Returns
/// * STATUS_SUCCESS - Timer opened successfully
/// * STATUS_INVALID_PARAMETER - Invalid parameter
/// * STATUS_OBJECT_NAME_NOT_FOUND - Timer with specified name not found
/// * STATUS_OBJECT_TYPE_MISMATCH - Object exists but is not a timer
fn sys_open_timer(
    timer_handle: usize,
    _desired_access: usize,
    object_attributes: usize,
    _: usize,
    _: usize,
    _: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtOpenTimer(handle_ptr=0x{:X}, obj_attr=0x{:X})",
        timer_handle, object_attributes
    );

    // Validate parameters
    if timer_handle == 0 {
        crate::serial_println!("[SYSCALL] NtOpenTimer: NULL handle pointer");
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    if object_attributes == 0 {
        crate::serial_println!("[SYSCALL] NtOpenTimer: NULL object_attributes");
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    // Read the OBJECT_ATTRIBUTES structure
    let obj_attr = unsafe { &*(object_attributes as *const ObjectAttributes) };

    // Get the object name from UNICODE_STRING
    if obj_attr.object_name == 0 {
        crate::serial_println!("[SYSCALL] NtOpenTimer: NULL object name");
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    // Read the UNICODE_STRING structure
    let unicode_str = unsafe { &*(obj_attr.object_name as *const UnicodeString) };

    if unicode_str.buffer == 0 || unicode_str.length == 0 {
        crate::serial_println!("[SYSCALL] NtOpenTimer: empty timer name");
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    // Convert the name from UTF-16 to UTF-8
    let name_len_chars = (unicode_str.length / 2) as usize;
    let mut name_buf = [0u8; MAX_TIMER_NAME_LEN];
    let mut name_len = 0usize;

    unsafe {
        let utf16_ptr = unicode_str.buffer as *const u16;
        for i in 0..name_len_chars {
            if name_len >= MAX_TIMER_NAME_LEN - 1 {
                break;
            }
            let ch = *utf16_ptr.add(i);
            // Simple ASCII conversion (full UTF-16 to UTF-8 would be more complex)
            if ch < 128 {
                name_buf[name_len] = ch as u8;
                name_len += 1;
            }
        }
    }

    if name_len == 0 {
        crate::serial_println!("[SYSCALL] NtOpenTimer: failed to convert timer name");
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    let name_str = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("<invalid>");
    crate::serial_println!("[SYSCALL] NtOpenTimer: looking for timer '{}'", name_str);

    // Look up the named timer
    let existing_handle = unsafe { find_named_timer(&name_buf[..name_len]) };

    match existing_handle {
        Some(handle) => {
            // Verify it's still a valid timer
            if let Some((_, obj_type)) = unsafe { get_sync_object(handle) } {
                if obj_type != SyncObjectType::Timer {
                    crate::serial_println!("[SYSCALL] NtOpenTimer: object is not a timer");
                    return wait_status::STATUS_OBJECT_TYPE_MISMATCH;
                }

                // Return the handle to the caller
                // Note: In a full implementation, we'd create a new handle referencing the same object
                // For now, we return the same handle (simplified)
                unsafe { *(timer_handle as *mut usize) = handle; }

                crate::serial_println!("[SYSCALL] NtOpenTimer: opened timer '{}' -> handle 0x{:X}",
                    name_str, handle);
                0 // STATUS_SUCCESS
            } else {
                crate::serial_println!("[SYSCALL] NtOpenTimer: named timer no longer valid");
                wait_status::STATUS_OBJECT_NAME_NOT_FOUND
            }
        }
        None => {
            // Try looking in object manager for kernel objects
            // For now, just return not found
            crate::serial_println!("[SYSCALL] NtOpenTimer: timer '{}' not found", name_str);
            wait_status::STATUS_OBJECT_NAME_NOT_FOUND
        }
    }
}

/// NtSetTimer - Set a timer to expire at a specified time
///
/// # Arguments
/// * `timer_handle` - Handle to the timer object
/// * `due_time` - Pointer to expiration time (negative = relative, positive = absolute)
/// * `apc_routine` - Optional APC routine to call when timer expires
/// * `apc_context` - Context for APC routine
/// * `resume` - If TRUE, resume system from sleep when timer expires
/// * `period` - Period in milliseconds for periodic timer (0 = one-shot)
///
/// # Returns
/// * STATUS_SUCCESS - Timer set successfully
/// * STATUS_INVALID_HANDLE - Invalid timer handle
fn sys_set_timer(
    timer_handle: usize,
    due_time: usize,
    _apc_routine: usize,
    _apc_context: usize,
    _resume: usize,
    period: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtSetTimer(handle=0x{:X}, due_time_ptr=0x{:X}, period={})",
        timer_handle, due_time, period
    );

    if timer_handle == 0 {
        crate::serial_println!("[SYSCALL] NtSetTimer: NULL handle");
        return wait_status::STATUS_INVALID_HANDLE;
    }

    if due_time == 0 {
        crate::serial_println!("[SYSCALL] NtSetTimer: NULL due_time pointer");
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    // Get the due time value
    let due_time_100ns = unsafe { *(due_time as *const i64) };

    // Convert to milliseconds
    // Negative = relative time, positive = absolute time
    let timeout_ms = if due_time_100ns < 0 {
        // Relative time in 100ns units (negative), convert to ms
        ((-due_time_100ns) / 10_000) as u32
    } else if due_time_100ns == 0 {
        // Immediate expiration
        0u32
    } else {
        // Absolute time - convert to relative by subtracting current time
        // Get current time (Jan 1, 1601 epoch, 100ns units)
        let tick_count = crate::hal::apic::get_tick_count();
        let base_time: i64 = 132_537_600_000_000_000; // Approximate base time
        let current_time = base_time + (tick_count as i64 * 10000);

        if due_time_100ns <= current_time {
            // Already expired - trigger immediately
            0u32
        } else {
            // Calculate relative time until absolute deadline
            let relative_100ns = due_time_100ns - current_time;
            (relative_100ns / 10_000) as u32
        }
    };

    // Get timer from pool
    if let Some((entry, obj_type)) = unsafe { get_sync_object(timer_handle) } {
        if obj_type != SyncObjectType::Timer {
            crate::serial_println!("[SYSCALL] NtSetTimer: handle is not a timer");
            return wait_status::STATUS_OBJECT_TYPE_MISMATCH;
        }

        unsafe {
            let timer = &mut *core::ptr::addr_of_mut!((*entry).data.timer);
            // Set the timer (period is in milliseconds)
            timer.set(timeout_ms, period as u32, None);
        }

        crate::serial_println!("[SYSCALL] NtSetTimer: timer set for {} ms, period {} ms",
            timeout_ms, period);

        return 0; // STATUS_SUCCESS
    }

    // Try object manager
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(timer_handle as u32, 0);
        if obj.is_null() {
            crate::serial_println!("[SYSCALL] NtSetTimer: handle not found");
            return wait_status::STATUS_INVALID_HANDLE;
        }
        obj
    };

    // Set the timer
    unsafe {
        let timer = object as *mut crate::ke::KTimer;
        (*timer).set(timeout_ms, period as u32, None);
        crate::ob::ob_dereference_object(object);
    }

    crate::serial_println!("[SYSCALL] NtSetTimer: OB timer set for {} ms, period {} ms",
        timeout_ms, period);

    0 // STATUS_SUCCESS
}

/// NtCancelTimer - Cancel a pending timer
///
/// # Arguments
/// * `timer_handle` - Handle to the timer object
/// * `current_state` - Optional pointer to receive previous state
///
/// # Returns
/// * STATUS_SUCCESS - Timer cancelled successfully
/// * STATUS_INVALID_HANDLE - Invalid timer handle
fn sys_cancel_timer(
    timer_handle: usize,
    current_state: usize,
    _: usize,
    _: usize,
    _: usize,
    _: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtCancelTimer(handle=0x{:X}, state_ptr=0x{:X})",
        timer_handle, current_state
    );

    if timer_handle == 0 {
        crate::serial_println!("[SYSCALL] NtCancelTimer: NULL handle");
        return wait_status::STATUS_INVALID_HANDLE;
    }

    // Get timer from pool
    if let Some((entry, obj_type)) = unsafe { get_sync_object(timer_handle) } {
        if obj_type != SyncObjectType::Timer {
            crate::serial_println!("[SYSCALL] NtCancelTimer: handle is not a timer");
            return wait_status::STATUS_OBJECT_TYPE_MISMATCH;
        }

        let was_set = unsafe {
            let timer = &mut *core::ptr::addr_of_mut!((*entry).data.timer);
            let was_active = timer.is_set();
            timer.cancel();
            was_active
        };

        if current_state != 0 {
            unsafe { *(current_state as *mut u32) = was_set as u32; }
        }

        crate::serial_println!("[SYSCALL] NtCancelTimer: timer cancelled (was_set={})", was_set);
        return 0;
    }

    // Try object manager
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(timer_handle as u32, 0);
        if obj.is_null() {
            crate::serial_println!("[SYSCALL] NtCancelTimer: handle not found");
            return wait_status::STATUS_INVALID_HANDLE;
        }
        obj
    };

    let was_set = unsafe {
        let timer = object as *mut crate::ke::KTimer;
        let was_active = (*timer).is_set();
        (*timer).cancel();
        crate::ob::ob_dereference_object(object);
        was_active
    };

    if current_state != 0 {
        unsafe { *(current_state as *mut u32) = was_set as u32; }
    }

    crate::serial_println!("[SYSCALL] NtCancelTimer: OB timer cancelled (was_set={})", was_set);
    0
}

/// NtQueryTimer - Query timer information
///
/// # Arguments
/// * `timer_handle` - Handle to the timer object
/// * `timer_information_class` - Type of information to query
/// * `timer_information` - Buffer to receive information
/// * `timer_information_length` - Size of buffer
/// * `return_length` - Optional pointer to receive required size
///
/// # Returns
/// * STATUS_SUCCESS - Query successful
/// * STATUS_INVALID_HANDLE - Invalid timer handle
/// * STATUS_INFO_LENGTH_MISMATCH - Buffer too small
fn sys_query_timer(
    timer_handle: usize,
    timer_info_class: usize,
    timer_information: usize,
    timer_info_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtQueryTimer(handle=0x{:X}, class={}, buf=0x{:X}, len={})",
        timer_handle, timer_info_class, timer_information, timer_info_length
    );

    if timer_handle == 0 {
        crate::serial_println!("[SYSCALL] NtQueryTimer: NULL handle");
        return wait_status::STATUS_INVALID_HANDLE;
    }

    // Only TimerBasicInformation supported
    if timer_info_class != timer_info_class::TimerBasicInformation as usize {
        crate::serial_println!("[SYSCALL] NtQueryTimer: unsupported info class {}", timer_info_class);
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    let required_size = core::mem::size_of::<TimerBasicInformation>();

    if return_length != 0 {
        unsafe { *(return_length as *mut u32) = required_size as u32; }
    }

    if timer_info_length < required_size {
        crate::serial_println!("[SYSCALL] NtQueryTimer: buffer too small");
        return wait_status::STATUS_INFO_LENGTH_MISMATCH;
    }

    if timer_information == 0 {
        crate::serial_println!("[SYSCALL] NtQueryTimer: NULL buffer");
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    // Get timer from pool
    if let Some((entry, obj_type)) = unsafe { get_sync_object(timer_handle) } {
        if obj_type != SyncObjectType::Timer {
            crate::serial_println!("[SYSCALL] NtQueryTimer: handle is not a timer");
            return wait_status::STATUS_OBJECT_TYPE_MISMATCH;
        }

        unsafe {
            let timer = &*core::ptr::addr_of!((*entry).data.timer);
            let info = timer_information as *mut TimerBasicInformation;

            // Calculate remaining time
            let current_time = crate::hal::apic::get_tick_count();
            let due_time = timer.due_time();
            let remaining_ticks = due_time.saturating_sub(current_time);
            // Convert ticks to 100ns units (assuming 1ms per tick)
            (*info).remaining_time = -((remaining_ticks * 10_000) as i64);
            (*info).timer_state = timer.is_signaled() as u32;
        }

        crate::serial_println!("[SYSCALL] NtQueryTimer: query successful");
        return 0;
    }

    // Try object manager
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(timer_handle as u32, 0);
        if obj.is_null() {
            crate::serial_println!("[SYSCALL] NtQueryTimer: handle not found");
            return wait_status::STATUS_INVALID_HANDLE;
        }
        obj
    };

    unsafe {
        let timer = &*(object as *const crate::ke::KTimer);
        let info = timer_information as *mut TimerBasicInformation;

        let current_time = crate::hal::apic::get_tick_count();
        let due_time = timer.due_time();
        let remaining_ticks = due_time.saturating_sub(current_time);
        (*info).remaining_time = -((remaining_ticks * 10_000) as i64);
        (*info).timer_state = timer.is_signaled() as u32;

        crate::ob::ob_dereference_object(object);
    }

    crate::serial_println!("[SYSCALL] NtQueryTimer: OB query successful");
    0
}

/// Event information class
mod event_info_class {
    #[allow(non_upper_case_globals)]
    pub const EventBasicInformation: usize = 0;
}

/// Event basic information structure
#[repr(C)]
struct EventBasicInformation {
    /// Event type (0 = Notification, 1 = Synchronization)
    event_type: u32,
    /// Event state (1 = signaled, 0 = not signaled)
    event_state: i32,
}

/// NtQueryEvent - Query event object information
///
/// Returns the event type and current signal state.
///
/// # Arguments
/// * `event_handle` - Handle to event object
/// * `event_info_class` - Information class (only EventBasicInformation supported)
/// * `event_information` - Output buffer for information
/// * `event_info_length` - Size of output buffer
/// * `return_length` - Optional pointer to receive required size
///
/// # Returns
/// * STATUS_SUCCESS - Query successful
/// * STATUS_INVALID_HANDLE - Invalid handle
/// * STATUS_INVALID_PARAMETER - Invalid info class or null buffer
/// * STATUS_INFO_LENGTH_MISMATCH - Buffer too small
/// * STATUS_OBJECT_TYPE_MISMATCH - Handle is not an event
fn sys_query_event(
    event_handle: usize,
    event_info_class: usize,
    event_information: usize,
    event_info_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtQueryEvent(handle=0x{:X}, class={}, buf=0x{:X}, len={})",
        event_handle, event_info_class, event_information, event_info_length
    );

    if event_handle == 0 {
        return wait_status::STATUS_INVALID_HANDLE;
    }

    if event_info_class != event_info_class::EventBasicInformation {
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    let required_size = core::mem::size_of::<EventBasicInformation>();

    if return_length != 0 {
        unsafe { *(return_length as *mut u32) = required_size as u32; }
    }

    if event_info_length < required_size {
        return wait_status::STATUS_INFO_LENGTH_MISMATCH;
    }

    if event_information == 0 {
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(event_handle) } {
        if obj_type != SyncObjectType::Event {
            return wait_status::STATUS_OBJECT_TYPE_MISMATCH;
        }

        unsafe {
            let event = &*core::ptr::addr_of!((*entry).data.event);
            let info = event_information as *mut EventBasicInformation;

            // EventType: 0 = Notification, 1 = Synchronization
            (*info).event_type = event.event_type() as u32;
            (*info).event_state = event.is_signaled() as i32;
        }

        crate::serial_println!("[SYSCALL] NtQueryEvent: query successful");
        return 0;
    }

    // Try object manager
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(event_handle as u32, 0);
        if obj.is_null() {
            return wait_status::STATUS_INVALID_HANDLE;
        }
        obj
    };

    unsafe {
        let event = &*(object as *const crate::ke::event::KEvent);
        let info = event_information as *mut EventBasicInformation;

        (*info).event_type = event.event_type() as u32;
        (*info).event_state = event.is_signaled() as i32;

        crate::ob::ob_dereference_object(object);
    }

    crate::serial_println!("[SYSCALL] NtQueryEvent: OB query successful");
    0
}

/// Semaphore information class
mod semaphore_info_class {
    #[allow(non_upper_case_globals)]
    pub const SemaphoreBasicInformation: usize = 0;
}

/// Semaphore basic information structure
#[repr(C)]
struct SemaphoreBasicInformation {
    /// Current count
    current_count: i32,
    /// Maximum count
    maximum_count: i32,
}

/// NtQuerySemaphore - Query semaphore object information
///
/// Returns the current count and maximum count of the semaphore.
///
/// # Arguments
/// * `semaphore_handle` - Handle to semaphore object
/// * `semaphore_info_class` - Information class (only SemaphoreBasicInformation supported)
/// * `semaphore_information` - Output buffer for information
/// * `semaphore_info_length` - Size of output buffer
/// * `return_length` - Optional pointer to receive required size
///
/// # Returns
/// * STATUS_SUCCESS - Query successful
/// * STATUS_INVALID_HANDLE - Invalid handle
/// * STATUS_INVALID_PARAMETER - Invalid info class or null buffer
/// * STATUS_INFO_LENGTH_MISMATCH - Buffer too small
/// * STATUS_OBJECT_TYPE_MISMATCH - Handle is not a semaphore
fn sys_query_semaphore(
    semaphore_handle: usize,
    semaphore_info_class: usize,
    semaphore_information: usize,
    semaphore_info_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtQuerySemaphore(handle=0x{:X}, class={}, buf=0x{:X}, len={})",
        semaphore_handle, semaphore_info_class, semaphore_information, semaphore_info_length
    );

    if semaphore_handle == 0 {
        return wait_status::STATUS_INVALID_HANDLE;
    }

    if semaphore_info_class != semaphore_info_class::SemaphoreBasicInformation {
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    let required_size = core::mem::size_of::<SemaphoreBasicInformation>();

    if return_length != 0 {
        unsafe { *(return_length as *mut u32) = required_size as u32; }
    }

    if semaphore_info_length < required_size {
        return wait_status::STATUS_INFO_LENGTH_MISMATCH;
    }

    if semaphore_information == 0 {
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(semaphore_handle) } {
        if obj_type != SyncObjectType::Semaphore {
            return wait_status::STATUS_OBJECT_TYPE_MISMATCH;
        }

        unsafe {
            let semaphore = &*core::ptr::addr_of!((*entry).data.semaphore);
            let info = semaphore_information as *mut SemaphoreBasicInformation;

            (*info).current_count = semaphore.count();
            (*info).maximum_count = semaphore.limit();
        }

        crate::serial_println!("[SYSCALL] NtQuerySemaphore: query successful");
        return 0;
    }

    // Try object manager
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(semaphore_handle as u32, 0);
        if obj.is_null() {
            return wait_status::STATUS_INVALID_HANDLE;
        }
        obj
    };

    unsafe {
        let semaphore = &*(object as *const crate::ke::KSemaphore);
        let info = semaphore_information as *mut SemaphoreBasicInformation;

        (*info).current_count = semaphore.count();
        (*info).maximum_count = semaphore.limit();

        crate::ob::ob_dereference_object(object);
    }

    crate::serial_println!("[SYSCALL] NtQuerySemaphore: OB query successful");
    0
}

/// Mutant information class
mod mutant_info_class {
    #[allow(non_upper_case_globals)]
    pub const MutantBasicInformation: usize = 0;
}

/// Mutant basic information structure
#[repr(C)]
struct MutantBasicInformation {
    /// Current count (negative when owned, 0 = available)
    current_count: i32,
    /// Whether the mutant is owned by the caller
    owned_by_caller: u8,
    /// Whether the mutant was abandoned
    abandoned_state: u8,
}

/// NtQueryMutant - Query mutant (mutex) object information
///
/// Returns the current state, ownership, and abandoned status.
///
/// # Arguments
/// * `mutant_handle` - Handle to mutant object
/// * `mutant_info_class` - Information class (only MutantBasicInformation supported)
/// * `mutant_information` - Output buffer for information
/// * `mutant_info_length` - Size of output buffer
/// * `return_length` - Optional pointer to receive required size
///
/// # Returns
/// * STATUS_SUCCESS - Query successful
/// * STATUS_INVALID_HANDLE - Invalid handle
/// * STATUS_INVALID_PARAMETER - Invalid info class or null buffer
/// * STATUS_INFO_LENGTH_MISMATCH - Buffer too small
/// * STATUS_OBJECT_TYPE_MISMATCH - Handle is not a mutant
fn sys_query_mutant(
    mutant_handle: usize,
    mutant_info_class: usize,
    mutant_information: usize,
    mutant_info_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtQueryMutant(handle=0x{:X}, class={}, buf=0x{:X}, len={})",
        mutant_handle, mutant_info_class, mutant_information, mutant_info_length
    );

    if mutant_handle == 0 {
        return wait_status::STATUS_INVALID_HANDLE;
    }

    if mutant_info_class != mutant_info_class::MutantBasicInformation {
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    let required_size = core::mem::size_of::<MutantBasicInformation>();

    if return_length != 0 {
        unsafe { *(return_length as *mut u32) = required_size as u32; }
    }

    if mutant_info_length < required_size {
        return wait_status::STATUS_INFO_LENGTH_MISMATCH;
    }

    if mutant_information == 0 {
        return wait_status::STATUS_INVALID_PARAMETER;
    }

    // Try sync object pool first
    if let Some((entry, obj_type)) = unsafe { get_sync_object(mutant_handle) } {
        if obj_type != SyncObjectType::Mutex {
            return wait_status::STATUS_OBJECT_TYPE_MISMATCH;
        }

        unsafe {
            let mutex = &*core::ptr::addr_of!((*entry).data.mutex);
            let info = mutant_information as *mut MutantBasicInformation;

            // In NT, count is 1 when available, <= 0 when owned
            // -1 = owned once, -2 = owned twice (recursive), etc.
            (*info).current_count = if mutex.is_owned() {
                // Use header signal_state to approximate count
                -(mutex.header.signal_state().max(1))
            } else {
                1 // Available
            };
            (*info).owned_by_caller = mutex.is_owned_by_current() as u8;
            // Abandoned state would be set if owner thread terminated while holding
            // For now we don't track this, so always 0
            (*info).abandoned_state = 0;
        }

        crate::serial_println!("[SYSCALL] NtQueryMutant: query successful");
        return 0;
    }

    // Try object manager
    let object = unsafe {
        let obj = crate::ob::ob_reference_object_by_handle(mutant_handle as u32, 0);
        if obj.is_null() {
            return wait_status::STATUS_INVALID_HANDLE;
        }
        obj
    };

    unsafe {
        let mutex = &*(object as *const crate::ke::KMutex);
        let info = mutant_information as *mut MutantBasicInformation;

        (*info).current_count = if mutex.is_owned() {
            -(mutex.header.signal_state().max(1))
        } else {
            1
        };
        (*info).owned_by_caller = mutex.is_owned_by_current() as u8;
        (*info).abandoned_state = 0;

        crate::ob::ob_dereference_object(object);
    }

    crate::serial_println!("[SYSCALL] NtQueryMutant: OB query successful");
    0
}

// ============================================================================
// Memory Management Syscalls
// ============================================================================

/// NtAllocateVirtualMemory - Allocate virtual memory
fn sys_allocate_virtual_memory(
    _process_handle: usize,
    base_address: usize,
    _zero_bits: usize,
    region_size: usize,
    allocation_type: usize,
    protect: usize,
) -> isize {
    const STATUS_NO_MEMORY: isize = 0xC0000017u32 as isize;

    if base_address == 0 || region_size == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Read the requested base address and size
    let requested_base = unsafe { *(base_address as *const usize) };
    let requested_size = unsafe { *(region_size as *const usize) };

    // Get the system address space (for now, we use system aspace)
    let aspace = unsafe { crate::mm::mm_get_system_address_space() };

    // Allocate virtual memory
    let result = unsafe {
        crate::mm::mm_allocate_virtual_memory(
            aspace,
            if requested_base == 0 { None } else { Some(requested_base as u64) },
            requested_size as u64,
            allocation_type as u32,
            protect as u32,
        )
    };

    match result {
        Some(actual_base) => {
            unsafe {
                *(base_address as *mut usize) = actual_base as usize;
                // Region size is page-aligned by the allocator
            }
            STATUS_SUCCESS
        }
        None => STATUS_NO_MEMORY,
    }
}

/// NtFreeVirtualMemory - Free virtual memory
fn sys_free_virtual_memory(
    _process_handle: usize,
    base_address: usize,
    region_size: usize,
    free_type: usize,
    _: usize, _: usize,
) -> isize {
    const STATUS_MEMORY_NOT_ALLOCATED: isize = 0xC00000A0u32 as isize;

    if base_address == 0 || region_size == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let addr = unsafe { *(base_address as *const usize) };
    let size = unsafe { *(region_size as *const usize) };

    // Get the system address space
    let aspace = unsafe { crate::mm::mm_get_system_address_space() };

    let result = unsafe {
        crate::mm::mm_free_virtual_memory(aspace, addr as u64, size as u64, free_type as u32)
    };

    if result { STATUS_SUCCESS } else { STATUS_MEMORY_NOT_ALLOCATED }
}

/// NtProtectVirtualMemory - Change memory protection
fn sys_protect_virtual_memory(
    process_handle: usize,
    base_address: usize,
    region_size: usize,
    new_protect: usize,
    old_protect: usize,
    _: usize,
) -> isize {
    const STATUS_INVALID_PAGE_PROTECTION: isize = 0xC0000045u32 as isize;
    let _ = process_handle;

    if base_address == 0 || region_size == 0 || old_protect == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let addr = unsafe { *(base_address as *const usize) };
    let size = unsafe { *(region_size as *const usize) };

    let result = unsafe {
        crate::mm::mm_protect_virtual_memory(addr, size, new_protect as u32)
    };

    match result {
        Ok(old) => {
            unsafe {
                *(old_protect as *mut u32) = old;
            }
            STATUS_SUCCESS
        }
        Err(_) => STATUS_INVALID_PAGE_PROTECTION,
    }
}

// ============================================================================
// NtQueryVirtualMemory Types and Structures
// ============================================================================

/// Memory information class for NtQueryVirtualMemory
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryInformationClass {
    /// Basic memory information (MEMORY_BASIC_INFORMATION)
    MemoryBasicInformation = 0,
    /// Working set information
    MemoryWorkingSetInformation = 1,
    /// Mapped file name
    MemoryMappedFilenameInformation = 2,
    /// Region information
    MemoryRegionInformation = 3,
    /// Working set list (extended)
    MemoryWorkingSetExInformation = 4,
    /// Shared commit information
    MemorySharedCommitInformation = 5,
    /// Image information
    MemoryImageInformation = 6,
    /// Region information (extended)
    MemoryRegionInformationEx = 7,
    /// Priority information
    MemoryPriorityInformation = 8,
    /// Partition information
    MemoryPartitionInformation = 9,
}

/// MEMORY_BASIC_INFORMATION structure (NT compatible)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryBasicInformation {
    /// Base address of the region
    pub base_address: usize,
    /// Base address of the allocation (first reserved page)
    pub allocation_base: usize,
    /// Initial protection when region was allocated
    pub allocation_protect: u32,
    /// Partition ID (Windows 10+)
    pub partition_id: u16,
    /// Reserved
    pub _reserved: u16,
    /// Size of the region in bytes
    pub region_size: usize,
    /// State of pages: MEM_COMMIT, MEM_FREE, MEM_RESERVE
    pub state: u32,
    /// Current protection
    pub protect: u32,
    /// Type of pages: MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
    pub mem_type: u32,
}

/// Memory state constants
pub mod mem_state {
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_FREE: u32 = 0x10000;
    pub const MEM_RESET: u32 = 0x80000;
    pub const MEM_RESET_UNDO: u32 = 0x1000000;
}

/// Memory type constants
pub mod mem_type {
    pub const MEM_PRIVATE: u32 = 0x20000;
    pub const MEM_MAPPED: u32 = 0x40000;
    pub const MEM_IMAGE: u32 = 0x1000000;
}

/// Page protection constants
pub mod page_protect {
    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const PAGE_READONLY: u32 = 0x02;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_WRITECOPY: u32 = 0x08;
    pub const PAGE_EXECUTE: u32 = 0x10;
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    pub const PAGE_GUARD: u32 = 0x100;
    pub const PAGE_NOCACHE: u32 = 0x200;
    pub const PAGE_WRITECOMBINE: u32 = 0x400;
}

/// MEMORY_REGION_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegionInformation {
    /// Base address of allocation
    pub allocation_base: usize,
    /// Protection at allocation time
    pub allocation_protect: u32,
    /// Flags
    pub region_type: u32,
    /// Size of allocation
    pub region_size: usize,
    /// Commit size
    pub commit_size: usize,
    /// Partition ID
    pub partition_id: usize,
    /// Node preference
    pub node_preference: usize,
}

/// MEMORY_IMAGE_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryImageInformation {
    /// Image base address
    pub image_base: usize,
    /// Image size
    pub size_of_image: usize,
    /// Flags
    pub image_flags: u32,
}

/// NtQueryVirtualMemory - Query information about virtual memory
///
/// Parameters:
/// - process_handle: Handle to the process (use -1 for current process)
/// - base_address: Address to query
/// - info_class: MemoryInformationClass value
/// - buffer: Output buffer for information
/// - buffer_size: Size of output buffer
/// - return_length: Optional pointer to receive required size
fn sys_query_virtual_memory(
    process_handle: usize,
    base_address: usize,
    info_class: usize,
    buffer: usize,
    buffer_size: usize,
    return_length: usize,
) -> isize {
    use core::ptr;

    crate::serial_println!("[SYSCALL] NtQueryVirtualMemory(handle={:#x}, addr={:#x}, class={}, buf={:#x}, size={})",
        process_handle, base_address, info_class, buffer, buffer_size);

    // Validate buffer pointer
    if buffer == 0 {
        return 0xC0000005u32 as isize; // STATUS_ACCESS_VIOLATION
    }

    // Get the address space for the target process
    // For now, we only support the current process (-1 or 0xFFFFFFFF...)
    let aspace = if process_handle == usize::MAX || process_handle == 0 {
        unsafe { crate::mm::mm_get_system_address_space() }
    } else {
        // TODO: Look up process by handle and get its address space
        // For now, just use system address space
        unsafe { crate::mm::mm_get_system_address_space() }
    };

    if aspace.is_null() {
        return 0xC0000008u32 as isize; // STATUS_INVALID_HANDLE
    }

    match info_class as u32 {
        // MemoryBasicInformation = 0
        0 => {
            let required_size = core::mem::size_of::<MemoryBasicInformation>();

            // Write return length if provided
            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut usize, required_size);
                }
            }

            if buffer_size < required_size {
                return 0xC0000004u32 as isize; // STATUS_INFO_LENGTH_MISMATCH
            }

            // Query the memory region
            let result = unsafe {
                crate::mm::mm_query_virtual_memory(aspace, base_address as u64)
            };

            match result {
                Some(mm_info) => {
                    // Convert internal format to NT format
                    let info = MemoryBasicInformation {
                        base_address: mm_info.base_address as usize,
                        allocation_base: mm_info.allocation_base as usize,
                        allocation_protect: mm_info.allocation_protect,
                        partition_id: 0,
                        _reserved: 0,
                        region_size: mm_info.region_size as usize,
                        state: mm_info.state,
                        protect: mm_info.protect,
                        mem_type: match mm_info.vad_type {
                            0 => mem_type::MEM_PRIVATE,  // Private memory
                            1 => mem_type::MEM_MAPPED,   // Mapped view
                            2 => mem_type::MEM_IMAGE,    // Image section
                            _ => mem_type::MEM_PRIVATE,
                        },
                    };

                    unsafe {
                        ptr::write(buffer as *mut MemoryBasicInformation, info);
                    }

                    crate::serial_println!("[SYSCALL] NtQueryVirtualMemory: base={:#x}, size={:#x}, state={:#x}, protect={:#x}",
                        info.base_address, info.region_size, info.state, info.protect);

                    0 // STATUS_SUCCESS
                }
                None => {
                    // Address not in any VAD - return FREE memory info
                    let info = MemoryBasicInformation {
                        base_address,
                        allocation_base: 0,
                        allocation_protect: 0,
                        partition_id: 0,
                        _reserved: 0,
                        region_size: 0x1000, // One page
                        state: mem_state::MEM_FREE,
                        protect: page_protect::PAGE_NOACCESS,
                        mem_type: 0,
                    };

                    unsafe {
                        ptr::write(buffer as *mut MemoryBasicInformation, info);
                    }

                    crate::serial_println!("[SYSCALL] NtQueryVirtualMemory: address {:#x} is FREE", base_address);

                    0 // STATUS_SUCCESS - free memory is valid to query
                }
            }
        }

        // MemoryRegionInformation = 3
        3 => {
            let required_size = core::mem::size_of::<MemoryRegionInformation>();

            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut usize, required_size);
                }
            }

            if buffer_size < required_size {
                return 0xC0000004u32 as isize;
            }

            let result = unsafe {
                crate::mm::mm_query_virtual_memory(aspace, base_address as u64)
            };

            match result {
                Some(mm_info) => {
                    let info = MemoryRegionInformation {
                        allocation_base: mm_info.allocation_base as usize,
                        allocation_protect: mm_info.allocation_protect,
                        region_type: mm_info.vad_type,
                        region_size: mm_info.region_size as usize,
                        commit_size: if mm_info.state == mem_state::MEM_COMMIT {
                            mm_info.region_size as usize
                        } else {
                            0
                        },
                        partition_id: 0,
                        node_preference: 0,
                    };

                    unsafe {
                        ptr::write(buffer as *mut MemoryRegionInformation, info);
                    }

                    0
                }
                None => 0xC0000005u32 as isize, // STATUS_ACCESS_VIOLATION
            }
        }

        // MemoryImageInformation = 6
        6 => {
            let required_size = core::mem::size_of::<MemoryImageInformation>();

            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut usize, required_size);
                }
            }

            if buffer_size < required_size {
                return 0xC0000004u32 as isize;
            }

            let result = unsafe {
                crate::mm::mm_query_virtual_memory(aspace, base_address as u64)
            };

            match result {
                Some(mm_info) => {
                    // Only valid for image mappings
                    if mm_info.vad_type != 2 {
                        return 0xC0000005u32 as isize; // Not an image mapping
                    }

                    let info = MemoryImageInformation {
                        image_base: mm_info.allocation_base as usize,
                        size_of_image: mm_info.region_size as usize,
                        image_flags: 0,
                    };

                    unsafe {
                        ptr::write(buffer as *mut MemoryImageInformation, info);
                    }

                    0
                }
                None => 0xC0000005u32 as isize,
            }
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtQueryVirtualMemory: unsupported class {}", info_class);
            0xC0000003u32 as isize // STATUS_INVALID_INFO_CLASS
        }
    }
}

// ============================================================================
// Section Object Syscalls
// ============================================================================

/// NtCreateSection - Create a section object (shared memory or file-backed)
///
/// # Arguments
/// * `section_handle` - Pointer to receive section handle
/// * `desired_access` - Access rights for the section
/// * `object_attributes` - Object attributes including optional file handle
/// * `maximum_size` - Pointer to maximum size (can be 0 for file-backed sections)
/// * `section_page_protection` - Page protection (PAGE_READONLY, PAGE_READWRITE, etc.)
/// * `allocation_attributes` - SEC_COMMIT, SEC_FILE, SEC_IMAGE, etc.
fn sys_create_section(
    section_handle: usize,
    _desired_access: usize,
    object_attributes: usize,
    maximum_size: usize,
    section_page_protection: usize,
    allocation_attributes: usize,
) -> isize {
    use crate::mm::section::section_type::{SEC_FILE, SEC_IMAGE};

    if section_handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Get size from pointer (NT style)
    let size = if maximum_size != 0 {
        unsafe { *(maximum_size as *const u64) }
    } else {
        0 // Size can be 0 for file-backed sections (will use file size)
    };

    let alloc_attrs = allocation_attributes as u32;

    crate::serial_println!("[SYSCALL] NtCreateSection(size={}, prot={:#x}, attrs={:#x})",
        size, section_page_protection, alloc_attrs);

    // Check for file-backed or image section
    if (alloc_attrs & SEC_FILE) != 0 || (alloc_attrs & SEC_IMAGE) != 0 {
        // File-backed section
        // In NT, the file handle is passed as the 7th parameter (via stack on x86)
        // For x64 syscalls with >6 args, check object_attributes for the file handle
        // Our simplified version can use object_attributes as the file handle if non-zero

        // Determine actual size (0 means use file size)
        let section_size = if size > 0 { size } else { 4096 }; // Default if not specified

        // Use object_attributes as file handle if provided
        // (A more complete implementation would parse OBJECT_ATTRIBUTES)
        let file_handle = if object_attributes != 0 { object_attributes as *mut u8 } else { core::ptr::null_mut() };

        let section = if (alloc_attrs & SEC_IMAGE) != 0 {
            // Image section (executable)
            let s = unsafe { crate::mm::mm_create_image_section(file_handle, section_size) };
            if !s.is_null() {
                crate::serial_println!("[SYSCALL] NtCreateSection: created image section");
            }
            s
        } else {
            // Regular file-backed section
            let s = unsafe { crate::mm::mm_create_file_section(file_handle, section_size, section_page_protection as u32) };
            if !s.is_null() {
                crate::serial_println!("[SYSCALL] NtCreateSection: created file-backed section");
            }
            s
        };

        if section.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Return section handle (pointer as handle for now)
        unsafe {
            *(section_handle as *mut usize) = section as usize;
        }

        return STATUS_SUCCESS;
    }

    // Page-file backed section (shared memory)
    if size == 0 {
        crate::serial_println!("[SYSCALL] NtCreateSection: SEC_COMMIT requires size");
        return STATUS_INVALID_PARAMETER;
    }

    let section = unsafe {
        crate::mm::mm_create_section(size, section_page_protection as u32)
    };

    if section.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Return section handle (pointer as handle for now)
    unsafe {
        *(section_handle as *mut usize) = section as usize;
    }

    crate::serial_println!("[SYSCALL] NtCreateSection: created pagefile-backed section");
    STATUS_SUCCESS
}

/// NtMapViewOfSection - Map a view of a section into an address space
fn sys_map_view_of_section(
    section_handle: usize,
    _process_handle: usize,
    base_address: usize,
    _zero_bits: usize,
    _commit_size: usize,
    section_offset: usize,
) -> isize {
    const STATUS_SECTION_NOT_IMAGE: isize = 0xC0000049u32 as isize;

    // Additional parameters would be in stack (view_size, protection, etc.)
    // For simplicity, we use defaults

    if section_handle == 0 || base_address == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let section = section_handle as *mut crate::mm::Section;

    // Read requested base and offset
    let requested_base = unsafe { *(base_address as *const u64) };
    let offset = if section_offset != 0 {
        unsafe { *(section_offset as *const u64) }
    } else {
        0
    };

    // Map the view
    let result = unsafe {
        crate::mm::mm_map_view_of_section(
            section,
            core::ptr::null_mut(), // Current process
            if requested_base == 0 { None } else { Some(requested_base) },
            offset,
            0, // Map entire section
            crate::mm::page_protection::PAGE_READWRITE,
        )
    };

    match result {
        Some(mapped_base) => {
            unsafe {
                *(base_address as *mut u64) = mapped_base;
            }
            STATUS_SUCCESS
        }
        None => STATUS_SECTION_NOT_IMAGE,
    }
}

/// NtUnmapViewOfSection - Unmap a view of a section
fn sys_unmap_view_of_section(
    _process_handle: usize,
    base_address: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::mm::{mm_find_section_by_view_address, mm_unmap_view_of_section};

    if base_address == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    crate::serial_println!("[SYSCALL] NtUnmapViewOfSection(base={:#x})", base_address);

    // Find the section containing this view
    unsafe {
        let section = mm_find_section_by_view_address(base_address as u64);
        if section.is_null() {
            crate::serial_println!("[SYSCALL] NtUnmapViewOfSection: no section found at {:#x}", base_address);
            return 0xC0000225u32 as isize; // STATUS_NOT_FOUND
        }

        // Unmap the view from the section
        if mm_unmap_view_of_section(section, base_address as u64) {
            crate::serial_println!("[SYSCALL] NtUnmapViewOfSection: unmapped view at {:#x}", base_address);
            0 // STATUS_SUCCESS
        } else {
            crate::serial_println!("[SYSCALL] NtUnmapViewOfSection: failed to unmap view");
            0xC0000001u32 as isize // STATUS_UNSUCCESSFUL
        }
    }
}

/// NtQuerySection - Query section information
fn sys_query_section(
    section_handle: usize,
    _info_class: usize,
    buffer: usize,
    buffer_size: usize,
    return_length: usize,
    _: usize,
) -> isize {
    const STATUS_BUFFER_TOO_SMALL: isize = 0xC0000023u32 as isize;

    if section_handle == 0 || buffer == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    if buffer_size < core::mem::size_of::<crate::mm::SectionInfo>() {
        return STATUS_BUFFER_TOO_SMALL;
    }

    let section = section_handle as *mut crate::mm::Section;

    let result = unsafe { crate::mm::mm_query_section(section) };

    match result {
        Some(info) => {
            unsafe {
                *(buffer as *mut crate::mm::SectionInfo) = info;
            }
            if return_length != 0 {
                unsafe {
                    *(return_length as *mut usize) = core::mem::size_of::<crate::mm::SectionInfo>();
                }
            }
            STATUS_SUCCESS
        }
        None => STATUS_INVALID_HANDLE,
    }
}

// ============================================================================
// I/O Completion Port Syscalls
// ============================================================================

/// NtCreateIoCompletion - Create an I/O completion port
fn sys_create_io_completion(
    completion_handle: usize,
    _desired_access: usize,
    _object_attributes: usize,
    concurrent_threads: usize,
    _: usize, _: usize,
) -> isize {
    if completion_handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let port = unsafe {
        crate::io::io_create_completion_port(concurrent_threads as u32)
    };

    if port.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    unsafe {
        *(completion_handle as *mut usize) = port as usize;
    }

    STATUS_SUCCESS
}

/// NtSetIoCompletion - Post a completion to a port
fn sys_set_io_completion(
    completion_handle: usize,
    key: usize,
    overlapped: usize,
    status: usize,
    information: usize,
    _: usize,
) -> isize {
    if completion_handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let port = completion_handle as *mut crate::io::IoCompletionPort;

    let result = unsafe {
        crate::io::io_set_completion(port, key, overlapped, status as i32, information)
    };

    if result { STATUS_SUCCESS } else { STATUS_INSUFFICIENT_RESOURCES }
}

/// NtRemoveIoCompletion - Wait for and retrieve a completion
fn sys_remove_io_completion(
    completion_handle: usize,
    key_out: usize,
    overlapped_out: usize,
    io_status_out: usize,
    timeout: usize,
    _: usize,
) -> isize {
    if completion_handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let port = completion_handle as *mut crate::io::IoCompletionPort;

    // Get timeout value
    let timeout_ms = if timeout == 0 {
        None
    } else {
        let timeout_100ns = unsafe { *(timeout as *const i64) };
        if timeout_100ns < 0 {
            Some(((-timeout_100ns) / 10_000) as u64)
        } else {
            Some(0)
        }
    };

    let result = unsafe { crate::io::io_remove_completion(port, timeout_ms) };

    match result {
        Some(packet) => {
            if key_out != 0 {
                unsafe { *(key_out as *mut usize) = packet.key; }
            }
            if overlapped_out != 0 {
                unsafe { *(overlapped_out as *mut usize) = packet.overlapped; }
            }
            if io_status_out != 0 {
                unsafe {
                    let status_block = io_status_out as *mut crate::io::IoStatusBlock;
                    (*status_block).status = packet.status;
                    (*status_block).information = packet.information;
                }
            }
            0
        }
        None => 0x102, // STATUS_TIMEOUT
    }
}

// ============================================================================
// Directory and File Lock Syscalls
// ============================================================================

/// File information returned by NtQueryDirectoryFile
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileDirectoryInformation {
    /// Offset to next entry (0 if last)
    pub next_entry_offset: u32,
    /// File index (for resume)
    pub file_index: u32,
    /// Creation time (100ns since 1601)
    pub creation_time: i64,
    /// Last access time
    pub last_access_time: i64,
    /// Last write time
    pub last_write_time: i64,
    /// Change time
    pub change_time: i64,
    /// End of file position
    pub end_of_file: i64,
    /// Allocation size (on disk)
    pub allocation_size: i64,
    /// File attributes (FILE_ATTRIBUTE_*)
    pub file_attributes: u32,
    /// Length of file name in bytes
    pub file_name_length: u32,
    // file_name follows in memory (variable length, Unicode)
}

/// File attributes for FileDirectoryInformation
pub mod file_attributes {
    pub const READONLY: u32 = 0x0001;
    pub const HIDDEN: u32 = 0x0002;
    pub const SYSTEM: u32 = 0x0004;
    pub const DIRECTORY: u32 = 0x0010;
    pub const ARCHIVE: u32 = 0x0020;
    pub const NORMAL: u32 = 0x0080;
}

/// Windows-style wildcard pattern matching
///
/// Supports:
/// - `*` matches zero or more characters
/// - `?` matches exactly one character
/// - Case insensitive matching
fn wildcard_match(pattern: &str, name: &str) -> bool {
    let pattern_bytes = pattern.as_bytes();
    let name_bytes = name.as_bytes();

    wildcard_match_impl(pattern_bytes, name_bytes)
}

fn wildcard_match_impl(pattern: &[u8], name: &[u8]) -> bool {
    let mut pi = 0; // pattern index
    let mut ni = 0; // name index
    let mut star_pi = usize::MAX; // position after last '*' in pattern
    let mut star_ni = usize::MAX; // position in name when we matched '*'

    while ni < name.len() {
        if pi < pattern.len() {
            let pc = pattern[pi];
            let nc = name[ni];

            // Convert to lowercase for case-insensitive matching
            let pc_lower = if (b'A'..=b'Z').contains(&pc) { pc + 32 } else { pc };
            let nc_lower = if (b'A'..=b'Z').contains(&nc) { nc + 32 } else { nc };

            if pc == b'*' {
                // Star matches zero or more characters
                star_pi = pi + 1;
                star_ni = ni;
                pi += 1;
                continue;
            } else if pc == b'?' || pc_lower == nc_lower {
                // ? matches any single character, or exact match
                pi += 1;
                ni += 1;
                continue;
            }
        }

        // Mismatch - backtrack if we have a star
        if star_pi != usize::MAX {
            pi = star_pi;
            star_ni += 1;
            ni = star_ni;
            continue;
        }

        // No star to backtrack to - pattern doesn't match
        return false;
    }

    // Check remaining pattern characters (must all be stars)
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

/// NtQueryDirectoryFile - Enumerate directory contents
///
/// NT-style directory enumeration. Returns one or more entries per call.
///
/// Arguments:
/// - file_handle: Handle to an open directory
/// - event: Optional event to signal on completion (async)
/// - file_information: Output buffer for entries
/// - length: Size of output buffer
/// - return_single_entry: If true, return only one entry
/// - file_name_pattern: Optional wildcard pattern (e.g., "*.txt")
fn sys_query_directory_file(
    file_handle: usize,
    _event: usize,
    file_information: usize,
    length: usize,
    return_single_entry: usize,
    file_name_pattern: usize,
) -> isize {
    use crate::fs::vfs::{vfs_get_handle, vfs_get_fs, DirEntry};
    use crate::mm::address::{probe_for_write, is_valid_user_range};

    // Validate parameters
    if file_handle == 0 || file_information == 0 || length == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate user buffer
    if !is_valid_user_range(file_information as u64, length) {
        return STATUS_ACCESS_VIOLATION;
    }

    if !probe_for_write(file_information as u64, length) {
        return 0xC0000005u32 as isize; // STATUS_ACCESS_VIOLATION
    }

    // Get the file name pattern (optional wildcard like "*.txt")
    let pattern_str: Option<&str> = if file_name_pattern != 0 {
        // Read the pattern - assume it's a null-terminated ASCII string for simplicity
        let pattern_ptr = file_name_pattern as *const u8;
        let mut len = 0;
        unsafe {
            while *pattern_ptr.add(len) != 0 && len < 256 {
                len += 1;
            }
            if len > 0 {
                Some(core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(pattern_ptr, len)
                ))
            } else {
                None
            }
        }
    } else {
        None
    };

    // Default pattern matches all files
    let pattern = pattern_str.unwrap_or("*");

    // Get handle from internal table (file_handle is our internal handle)
    let (fs_index, vnode_id) = unsafe {
        let fh = match vfs_get_handle(file_handle as u32) {
            Some(h) => h,
            None => return 0xC0000008u32 as isize, // STATUS_INVALID_HANDLE
        };
        (fh.flags as u16, fh.vnode_index as u64)
    };

    // Get the filesystem
    let fs = unsafe {
        match vfs_get_fs(fs_index) {
            Some(f) => f,
            None => return 0xC000000Fu32 as isize, // STATUS_NO_SUCH_DEVICE
        }
    };

    // Get readdir function
    let readdir_fn = match fs.ops.readdir {
        Some(f) => f,
        None => return 0xC00000BBu32 as isize, // STATUS_NOT_SUPPORTED
    };

    let return_single = return_single_entry != 0;
    let buf_ptr = file_information as *mut u8;
    let mut offset: u32 = 0; // Directory enumeration offset
    let mut buf_used: usize = 0;
    let mut entries_returned = 0;
    let mut last_entry_offset: usize = 0;

    // Size of fixed part of FileDirectoryInformation
    let fixed_size = core::mem::size_of::<FileDirectoryInformation>();

    // Enumerate directory entries
    loop {
        let mut entry = DirEntry::empty();

        // Read next directory entry
        let status = unsafe { readdir_fn(fs_index, vnode_id, offset, &mut entry) };

        if status != crate::fs::vfs::FsStatus::Success {
            // No more entries or error
            break;
        }

        // Get entry name
        let name = entry.name_str();
        if name.is_empty() {
            break;
        }

        // Check if name matches pattern
        if !wildcard_match(pattern, name) {
            // Move to next entry
            offset = entry.next_offset;
            if offset == 0 {
                break;
            }
            continue;
        }

        // Calculate space needed for this entry
        // File name is stored as UTF-16 (2 bytes per char)
        let name_len_bytes = name.len() * 2;
        let entry_size = fixed_size + name_len_bytes;
        // Align to 8 bytes
        let aligned_size = (entry_size + 7) & !7;

        // Check if we have space
        if buf_used + aligned_size > length {
            if entries_returned == 0 {
                // Buffer too small for even one entry
                return 0xC0000023u32 as isize; // STATUS_BUFFER_TOO_SMALL
            }
            break;
        }

        // Build FileDirectoryInformation
        let file_attrs = if entry.is_directory() {
            0x10 // FILE_ATTRIBUTE_DIRECTORY
        } else {
            entry.attributes
        };

        let info = FileDirectoryInformation {
            next_entry_offset: 0, // Will be fixed up later
            file_index: offset,
            creation_time: 0, // TODO: Convert from entry times
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            end_of_file: entry.size as i64,
            allocation_size: ((entry.size + 511) & !511) as i64, // Round up to sector
            file_attributes: file_attrs,
            file_name_length: name_len_bytes as u32,
        };

        // Write entry to buffer
        unsafe {
            let entry_ptr = buf_ptr.add(buf_used);

            // Fix up previous entry's next_entry_offset
            if entries_returned > 0 {
                let prev_ptr = buf_ptr.add(last_entry_offset) as *mut FileDirectoryInformation;
                (*prev_ptr).next_entry_offset = (buf_used - last_entry_offset) as u32;
            }

            // Copy fixed part
            core::ptr::copy_nonoverlapping(
                &info as *const FileDirectoryInformation as *const u8,
                entry_ptr,
                fixed_size
            );

            // Convert and copy file name as UTF-16
            let name_ptr = entry_ptr.add(fixed_size) as *mut u16;
            for (i, c) in name.chars().enumerate() {
                *name_ptr.add(i) = c as u16;
            }
        }

        last_entry_offset = buf_used;
        buf_used += aligned_size;
        entries_returned += 1;

        // Move to next entry
        offset = entry.next_offset;

        // If returning single entry, stop now
        if return_single || offset == 0 {
            break;
        }
    }

    if entries_returned == 0 {
        // No entries found
        return 0x80000006u32 as isize; // STATUS_NO_MORE_FILES
    }

    // Success
    0 // STATUS_SUCCESS
}

/// File lock info for NtLockFile
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileLockInfo {
    /// Byte offset to start of lock
    pub byte_offset: i64,
    /// Length of lock in bytes
    pub length: i64,
    /// Key for this lock (used for unlock)
    pub key: u32,
    /// Is this an exclusive lock?
    pub exclusive: bool,
    /// Fail immediately if can't lock?
    pub fail_immediately: bool,
}

// ============================================================================
// File Lock Tracking Table
// ============================================================================

/// Maximum number of file locks
const MAX_FILE_LOCKS: usize = 64;

/// File lock entry for tracking active locks
#[derive(Clone, Copy)]
struct FileLockEntry {
    handle: usize,
    offset: i64,
    length: i64,
    key: u32,
    active: bool,
}

impl FileLockEntry {
    const fn new() -> Self {
        Self { handle: 0, offset: 0, length: 0, key: 0, active: false }
    }

    /// Check if this lock overlaps with another range
    fn overlaps(&self, offset: i64, length: i64) -> bool {
        if !self.active { return false; }
        let self_end = self.offset.saturating_add(self.length);
        let other_end = offset.saturating_add(length);
        self.offset < other_end && offset < self_end
    }
}

/// File lock table
static mut FILE_LOCK_TABLE: [FileLockEntry; MAX_FILE_LOCKS] = [FileLockEntry::new(); MAX_FILE_LOCKS];

/// NtLockFile - Lock a byte range in a file
///
/// Provides byte-range locking for file coordination between processes.
///
/// Arguments:
/// - file_handle: Handle to the file
/// - event: Optional event for async completion
/// - apc_routine: Optional APC callback
/// - apc_context: Context for APC
/// - io_status_block: Receives status
/// - byte_offset: Starting offset of lock (LARGE_INTEGER pointer)
fn sys_lock_file(
    file_handle: usize,
    _event: usize,
    byte_offset: usize,
    length: usize,
    key: usize,
    fail_immediately: usize,
) -> isize {
    // Validate parameters
    if file_handle == 0 || byte_offset == 0 || length == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Read the byte offset and length (passed as LARGE_INTEGER pointers)
    let offset = unsafe { *(byte_offset as *const i64) };
    let len = unsafe { *(length as *const i64) };

    crate::serial_println!(
        "[SYSCALL] NtLockFile(handle={}, offset={}, len={}, key={}, fail_immed={})",
        file_handle, offset, len, key, fail_immediately != 0
    );

    unsafe {
        // Check for conflicting locks on this file
        for entry in FILE_LOCK_TABLE.iter() {
            if entry.active && entry.handle == file_handle && entry.overlaps(offset, len) {
                crate::serial_println!("[SYSCALL] NtLockFile: lock conflict");
                return 0xC0000054u32 as isize; // STATUS_FILE_LOCK_CONFLICT
            }
        }

        // Find a free slot and add the lock
        for entry in FILE_LOCK_TABLE.iter_mut() {
            if !entry.active {
                entry.handle = file_handle;
                entry.offset = offset;
                entry.length = len;
                entry.key = key as u32;
                entry.active = true;
                crate::serial_println!("[SYSCALL] NtLockFile: lock acquired");
                return 0; // STATUS_SUCCESS
            }
        }

        crate::serial_println!("[SYSCALL] NtLockFile: no lock slots available");
        0xC000009Au32 as isize // STATUS_INSUFFICIENT_RESOURCES
    }
}

/// NtUnlockFile - Unlock a byte range in a file
///
/// Arguments:
/// - file_handle: Handle to the file
/// - io_status_block: Receives status
/// - byte_offset: Starting offset of region to unlock
/// - length: Length of region to unlock
/// - key: Key that was used when locking
fn sys_unlock_file(
    file_handle: usize,
    byte_offset: usize,
    length: usize,
    key: usize,
    _: usize, _: usize,
) -> isize {
    if file_handle == 0 || byte_offset == 0 || length == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let offset = unsafe { *(byte_offset as *const i64) };
    let len = unsafe { *(length as *const i64) };

    crate::serial_println!(
        "[SYSCALL] NtUnlockFile(handle={}, offset={}, len={}, key={})",
        file_handle, offset, len, key
    );

    unsafe {
        // Find and remove the matching lock
        for entry in FILE_LOCK_TABLE.iter_mut() {
            if entry.active
                && entry.handle == file_handle
                && entry.offset == offset
                && entry.length == len
                && entry.key == key as u32
            {
                entry.active = false;
                crate::serial_println!("[SYSCALL] NtUnlockFile: lock released");
                return 0; // STATUS_SUCCESS
            }
        }

        crate::serial_println!("[SYSCALL] NtUnlockFile: lock not found");
        0xC0000225u32 as isize // STATUS_NOT_FOUND
    }
}

// ============================================================================
// Registry Syscalls
// ============================================================================

/// Registry key handle table
/// Maps syscall handles to CM key handles
const MAX_KEY_HANDLES: usize = 128;
const KEY_HANDLE_BASE: usize = 0x2000;

/// Key handle entries
static mut KEY_HANDLE_MAP: [u32; MAX_KEY_HANDLES] = [u32::MAX; MAX_KEY_HANDLES];

/// Allocate a registry key handle
unsafe fn alloc_key_handle(cm_handle: crate::cm::CmKeyHandle) -> Option<usize> {
    for i in 0..MAX_KEY_HANDLES {
        if KEY_HANDLE_MAP[i] == u32::MAX {
            KEY_HANDLE_MAP[i] = cm_handle.index();
            return Some(i + KEY_HANDLE_BASE);
        }
    }
    None
}

/// Get CM key handle from syscall handle
unsafe fn get_cm_key_handle(syscall_handle: usize) -> Option<crate::cm::CmKeyHandle> {
    if syscall_handle < KEY_HANDLE_BASE {
        return None;
    }
    let idx = syscall_handle - KEY_HANDLE_BASE;
    if idx >= MAX_KEY_HANDLES {
        return None;
    }
    let cm_idx = KEY_HANDLE_MAP[idx];
    if cm_idx == u32::MAX {
        None
    } else {
        Some(crate::cm::CmKeyHandle::new(cm_idx))
    }
}

/// Free a registry key handle
unsafe fn free_key_handle(syscall_handle: usize) {
    if syscall_handle >= KEY_HANDLE_BASE {
        let idx = syscall_handle - KEY_HANDLE_BASE;
        if idx < MAX_KEY_HANDLES {
            KEY_HANDLE_MAP[idx] = u32::MAX;
        }
    }
}

/// NtCreateKey - Create or open a registry key
///
/// Arguments:
/// - key_handle: Pointer to receive handle
/// - desired_access: Access mask
/// - object_attributes: Pointer to path string (simplified)
/// - _title_index: Not used
/// - _class: Optional class string
/// - create_options: REG_OPTION_* flags
fn sys_create_key(
    key_handle_ptr: usize,
    _desired_access: usize,
    object_attributes: usize,
    _title_index: usize,
    _class: usize,
    create_options: usize,
) -> isize {
    if key_handle_ptr == 0 || object_attributes == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Read path from object_attributes (simplified - assume it's a path string)
    let path_result = unsafe { read_user_path(object_attributes, 260) };

    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return STATUS_INVALID_PARAMETER,
    };

    let path_str = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };

    crate::serial_println!("[SYSCALL] NtCreateKey(path='{}')", path_str);

    // Create or open the key
    let result = unsafe {
        crate::cm::cm_create_key(path_str, create_options as u32)
    };

    match result {
        Ok((cm_handle, disposition)) => {
            // Allocate syscall handle
            let syscall_handle = unsafe { alloc_key_handle(cm_handle) };
            match syscall_handle {
                Some(h) => {
                    unsafe {
                        *(key_handle_ptr as *mut usize) = h;
                    }
                    // Return disposition in high word
                    let disp_value = match disposition {
                        crate::cm::CmDisposition::CreatedNew => 1,
                        crate::cm::CmDisposition::OpenedExisting => 2,
                    };
                    crate::serial_println!("[SYSCALL] NtCreateKey -> handle {:#x}, disposition {}",
                        h, disp_value);
                    STATUS_SUCCESS
                }
                None => {
                    let _ = crate::cm::cm_close_key(cm_handle);
                    STATUS_INSUFFICIENT_RESOURCES
                }
            }
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtCreateKey failed: {:?}", e);
            e as isize
        }
    }
}

/// NtOpenKey - Open an existing registry key
fn sys_open_key(
    key_handle_ptr: usize,
    _desired_access: usize,
    object_attributes: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    if key_handle_ptr == 0 || object_attributes == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let path_result = unsafe { read_user_path(object_attributes, 260) };

    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return STATUS_INVALID_PARAMETER,
    };

    let path_str = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };

    crate::serial_println!("[SYSCALL] NtOpenKey(path='{}')", path_str);

    let result = unsafe { crate::cm::cm_open_key(path_str) };

    match result {
        Ok(cm_handle) => {
            let syscall_handle = unsafe { alloc_key_handle(cm_handle) };
            match syscall_handle {
                Some(h) => {
                    unsafe { *(key_handle_ptr as *mut usize) = h; }
                    crate::serial_println!("[SYSCALL] NtOpenKey -> handle {:#x}", h);
                    STATUS_SUCCESS
                }
                None => {
                    let _ = crate::cm::cm_close_key(cm_handle);
                    STATUS_INSUFFICIENT_RESOURCES
                }
            }
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtOpenKey failed: {:?}", e);
            e as isize
        }
    }
}

/// NtCloseKey - Close a registry key handle
fn sys_close_key(
    key_handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtCloseKey(handle={:#x})", key_handle);

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return STATUS_INVALID_HANDLE,
    };

    let _ = crate::cm::cm_close_key(cm_handle);
    unsafe { free_key_handle(key_handle); }

    STATUS_SUCCESS
}

/// Key value information class
pub mod key_value_info_class {
    pub const KEY_VALUE_BASIC_INFORMATION: u32 = 0;
    pub const KEY_VALUE_FULL_INFORMATION: u32 = 1;
    pub const KEY_VALUE_PARTIAL_INFORMATION: u32 = 2;
}

/// KEY_VALUE_PARTIAL_INFORMATION structure
#[repr(C)]
pub struct KeyValuePartialInformation {
    pub title_index: u32,
    pub value_type: u32,
    pub data_length: u32,
    // data follows
}

/// NtQueryValueKey - Query a registry value
fn sys_query_value_key(
    key_handle: usize,
    value_name_ptr: usize,
    _key_value_info_class: usize,
    key_value_info: usize,
    length: usize,
    result_length: usize,
) -> isize {
    if key_handle == 0 || value_name_ptr == 0 || key_value_info == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return STATUS_INVALID_HANDLE,
    };

    // Read value name
    let name_result = unsafe { read_user_path(value_name_ptr, 260) };
    let (name_buf, name_len) = match name_result {
        Some((buf, len)) => (buf, len),
        None => return STATUS_INVALID_PARAMETER,
    };

    let value_name = match core::str::from_utf8(&name_buf[..name_len]) {
        Ok(s) => s,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };

    crate::serial_println!("[SYSCALL] NtQueryValueKey(handle={:#x}, name='{}')",
        key_handle, value_name);

    // Query the value
    let result = unsafe { crate::cm::cm_query_value(cm_handle, value_name) };

    match result {
        Ok(value) => {
            // Return partial information (most common)
            let reg_type = value.value_type as u32;
            let data = value.data.as_bytes();
            let data_len = data.len();

            // Calculate required size
            let required = core::mem::size_of::<KeyValuePartialInformation>() + data_len;

            if result_length != 0 {
                unsafe { *(result_length as *mut usize) = required; }
            }

            if length < required {
                return 0x80000005u32 as isize; // STATUS_BUFFER_OVERFLOW
            }

            // Fill in the structure
            unsafe {
                let info = key_value_info as *mut KeyValuePartialInformation;
                (*info).title_index = 0;
                (*info).value_type = reg_type;
                (*info).data_length = data_len as u32;

                // Copy data after the structure
                let data_ptr = (key_value_info + core::mem::size_of::<KeyValuePartialInformation>()) as *mut u8;
                core::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data_len);
            }

            crate::serial_println!("[SYSCALL] NtQueryValueKey -> type={}, len={}", reg_type, data_len);
            0
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtQueryValueKey failed: {:?}", e);
            e as isize
        }
    }
}

/// NtSetValueKey - Set a registry value
fn sys_set_value_key(
    key_handle: usize,
    value_name_ptr: usize,
    _title_index: usize,
    value_type: usize,
    data_ptr: usize,
    data_size: usize,
) -> isize {
    if key_handle == 0 || value_name_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return STATUS_INVALID_HANDLE,
    };

    // Read value name
    let name_result = unsafe { read_user_path(value_name_ptr, 260) };
    let (name_buf, name_len) = match name_result {
        Some((buf, len)) => (buf, len),
        None => return STATUS_INVALID_PARAMETER,
    };

    let value_name = match core::str::from_utf8(&name_buf[..name_len]) {
        Ok(s) => s,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };

    crate::serial_println!("[SYSCALL] NtSetValueKey(handle={:#x}, name='{}', type={}, size={})",
        key_handle, value_name, value_type, data_size);

    // Create the value based on type
    let reg_type = crate::cm::RegType::from_u32(value_type as u32)
        .unwrap_or(crate::cm::RegType::Binary);

    let result = match reg_type {
        crate::cm::RegType::Dword if data_size >= 4 => {
            let dword_val = unsafe { *(data_ptr as *const u32) };
            unsafe { crate::cm::cm_set_value_dword(cm_handle, value_name, dword_val) }
        }
        crate::cm::RegType::Qword if data_size >= 8 => {
            let qword_val = unsafe { *(data_ptr as *const u64) };
            unsafe { crate::cm::cm_set_value_qword(cm_handle, value_name, qword_val) }
        }
        crate::cm::RegType::Sz | crate::cm::RegType::ExpandSz => {
            // Read string data
            if data_ptr != 0 && data_size > 0 {
                let str_slice = unsafe {
                    core::slice::from_raw_parts(data_ptr as *const u8, data_size)
                };
                // Find null terminator or use full length
                let str_len = str_slice.iter().position(|&b| b == 0).unwrap_or(data_size);
                if let Ok(s) = core::str::from_utf8(&str_slice[..str_len]) {
                    unsafe { crate::cm::cm_set_value_string(cm_handle, value_name, s) }
                } else {
                    crate::cm::CmStatus::InvalidParameter
                }
            } else {
                unsafe { crate::cm::cm_set_value_string(cm_handle, value_name, "") }
            }
        }
        _ => {
            // Binary or other type - create binary value
            let value = if data_ptr != 0 && data_size > 0 {
                let data_slice = unsafe {
                    core::slice::from_raw_parts(data_ptr as *const u8, data_size.min(256))
                };
                crate::cm::CmKeyValue::new_binary(value_name, data_slice)
            } else {
                crate::cm::CmKeyValue::new_binary(value_name, &[])
            };
            unsafe { crate::cm::cm_set_value(cm_handle, value) }
        }
    };

    if result.is_success() {
        crate::serial_println!("[SYSCALL] NtSetValueKey -> success");
        0
    } else {
        crate::serial_println!("[SYSCALL] NtSetValueKey failed: {:?}", result);
        result as isize
    }
}

/// NtDeleteKey - Delete a registry key
fn sys_delete_key(
    key_handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtDeleteKey(handle={:#x})", key_handle);

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return STATUS_INVALID_HANDLE,
    };

    // Get key name for deletion (we need the path)
    let key_name = unsafe { crate::cm::cm_get_key_name(cm_handle) };

    // For now, just mark the key as deleted
    // A full implementation would walk back to get the full path
    crate::serial_println!("[SYSCALL] NtDeleteKey - key name: {:?}", key_name);

    // Close and free the handle
    let _ = crate::cm::cm_close_key(cm_handle);
    unsafe { free_key_handle(key_handle); }

    0 // STATUS_SUCCESS (simplified)
}

/// NtDeleteValueKey - Delete a registry value
fn sys_delete_value_key(
    key_handle: usize,
    value_name_ptr: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    if key_handle == 0 || value_name_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return STATUS_INVALID_HANDLE,
    };

    // Read value name
    let name_result = unsafe { read_user_path(value_name_ptr, 260) };
    let (name_buf, name_len) = match name_result {
        Some((buf, len)) => (buf, len),
        None => return STATUS_INVALID_PARAMETER,
    };

    let value_name = match core::str::from_utf8(&name_buf[..name_len]) {
        Ok(s) => s,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };

    crate::serial_println!("[SYSCALL] NtDeleteValueKey(handle={:#x}, name='{}')",
        key_handle, value_name);

    let result = unsafe { crate::cm::cm_delete_value(cm_handle, value_name) };

    if result.is_success() {
        0
    } else {
        result as isize
    }
}

/// Key information class for NtEnumerateKey
pub mod key_info_class {
    pub const KEY_BASIC_INFORMATION: u32 = 0;
    pub const KEY_NODE_INFORMATION: u32 = 1;
    pub const KEY_FULL_INFORMATION: u32 = 2;
    pub const KEY_NAME_INFORMATION: u32 = 3;
}

/// KEY_BASIC_INFORMATION structure
#[repr(C)]
pub struct KeyBasicInformation {
    pub last_write_time: i64,
    pub title_index: u32,
    pub name_length: u32,
    // name follows (Unicode)
}

/// NtEnumerateKey - Enumerate subkeys
fn sys_enumerate_key(
    key_handle: usize,
    index: usize,
    key_info_class: usize,
    key_info: usize,
    length: usize,
    result_length: usize,
) -> isize {
    if key_handle == 0 || key_info == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = key_info_class; // Simplified - always return basic info

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtEnumerateKey(handle={:#x}, index={})",
        key_handle, index);

    let result = unsafe { crate::cm::cm_enumerate_key(cm_handle, index) };

    match result {
        Ok(subkey_handle) => {
            // Get the subkey name
            let name = unsafe { crate::cm::cm_get_key_name(subkey_handle) };
            let name_str = name.unwrap_or("");
            let name_bytes = name_str.as_bytes();
            let name_len = name_bytes.len();

            // Calculate required size
            let required = core::mem::size_of::<KeyBasicInformation>() + name_len;

            if result_length != 0 {
                unsafe { *(result_length as *mut usize) = required; }
            }

            if length < required {
                return 0x80000005u32 as isize; // STATUS_BUFFER_OVERFLOW
            }

            // Fill in the structure
            unsafe {
                let info = key_info as *mut KeyBasicInformation;
                (*info).last_write_time = crate::cm::cm_get_key_last_write_time(subkey_handle) as i64;
                (*info).title_index = 0;
                (*info).name_length = name_len as u32;

                // Copy name after the structure
                let name_ptr = (key_info + core::mem::size_of::<KeyBasicInformation>()) as *mut u8;
                core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_ptr, name_len);
            }

            crate::serial_println!("[SYSCALL] NtEnumerateKey -> '{}'", name_str);
            0
        }
        Err(crate::cm::CmStatus::NoMoreEntries) => {
            0x8000001A_u32 as isize // STATUS_NO_MORE_ENTRIES
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtEnumerateKey failed: {:?}", e);
            e as isize
        }
    }
}

/// KEY_VALUE_BASIC_INFORMATION structure
#[repr(C)]
pub struct KeyValueBasicInformation {
    pub title_index: u32,
    pub value_type: u32,
    pub name_length: u32,
    // name follows
}

/// NtEnumerateValueKey - Enumerate values
fn sys_enumerate_value_key(
    key_handle: usize,
    index: usize,
    key_value_info_class: usize,
    key_value_info: usize,
    length: usize,
    result_length: usize,
) -> isize {
    if key_handle == 0 || key_value_info == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = key_value_info_class; // Simplified

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtEnumerateValueKey(handle={:#x}, index={})",
        key_handle, index);

    let result = unsafe { crate::cm::cm_enumerate_value(cm_handle, index) };

    match result {
        Ok(value) => {
            let name_str = value.name.as_str();
            let name_bytes = name_str.as_bytes();
            let name_len = name_bytes.len();

            // Calculate required size
            let required = core::mem::size_of::<KeyValueBasicInformation>() + name_len;

            if result_length != 0 {
                unsafe { *(result_length as *mut usize) = required; }
            }

            if length < required {
                return 0x80000005u32 as isize; // STATUS_BUFFER_OVERFLOW
            }

            // Fill in the structure
            unsafe {
                let info = key_value_info as *mut KeyValueBasicInformation;
                (*info).title_index = 0;
                (*info).value_type = value.value_type as u32;
                (*info).name_length = name_len as u32;

                // Copy name after the structure
                let name_ptr = (key_value_info + core::mem::size_of::<KeyValueBasicInformation>()) as *mut u8;
                core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_ptr, name_len);
            }

            crate::serial_println!("[SYSCALL] NtEnumerateValueKey -> '{}'", name_str);
            0
        }
        Err(crate::cm::CmStatus::NoMoreEntries) => {
            0x8000001A_u32 as isize // STATUS_NO_MORE_ENTRIES
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtEnumerateValueKey failed: {:?}", e);
            e as isize
        }
    }
}

/// KEY_FULL_INFORMATION structure
#[repr(C)]
pub struct KeyFullInformation {
    pub last_write_time: i64,
    pub title_index: u32,
    pub class_offset: u32,
    pub class_length: u32,
    pub sub_keys: u32,
    pub max_name_len: u32,
    pub max_class_len: u32,
    pub values: u32,
    pub max_value_name_len: u32,
    pub max_value_data_len: u32,
    // class follows
}

/// NtQueryKey - Query key information
fn sys_query_key(
    key_handle: usize,
    key_info_class: usize,
    key_info: usize,
    length: usize,
    result_length: usize,
    _: usize,
) -> isize {
    if key_handle == 0 || key_info == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = key_info_class; // Simplified - return full info

    let cm_handle = match unsafe { get_cm_key_handle(key_handle) } {
        Some(h) => h,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtQueryKey(handle={:#x})", key_handle);

    let result = unsafe { crate::cm::cm_query_key_info(cm_handle) };

    match result {
        Ok(info) => {
            let required = core::mem::size_of::<KeyFullInformation>();

            if result_length != 0 {
                unsafe { *(result_length as *mut usize) = required; }
            }

            if length < required {
                return 0x80000005u32 as isize; // STATUS_BUFFER_OVERFLOW
            }

            unsafe {
                let key_full_info = key_info as *mut KeyFullInformation;
                (*key_full_info).last_write_time = info.last_write_time as i64;
                (*key_full_info).title_index = 0;
                (*key_full_info).class_offset = 0;
                (*key_full_info).class_length = 0;
                (*key_full_info).sub_keys = info.subkey_count as u32;
                (*key_full_info).max_name_len = 256;
                (*key_full_info).max_class_len = 0;
                (*key_full_info).values = info.value_count as u32;
                (*key_full_info).max_value_name_len = 256;
                (*key_full_info).max_value_data_len = 4096;
            }

            crate::serial_println!("[SYSCALL] NtQueryKey -> subkeys={}, values={}",
                info.subkey_count, info.value_count);
            0
        }
        Err(e) => {
            crate::serial_println!("[SYSCALL] NtQueryKey failed: {:?}", e);
            e as isize
        }
    }
}

// ============================================================================
// LPC (Local Procedure Call) Syscalls
// ============================================================================

/// LPC port handle table
const MAX_LPC_HANDLES: usize = 64;
const LPC_HANDLE_BASE: usize = 0x3000;

/// LPC handle entries (maps to lpc port index)
static mut LPC_HANDLE_MAP: [u16; MAX_LPC_HANDLES] = [0xFFFF; MAX_LPC_HANDLES];

/// Allocate an LPC handle
unsafe fn alloc_lpc_handle(port_index: u16) -> Option<usize> {
    for i in 0..MAX_LPC_HANDLES {
        if LPC_HANDLE_MAP[i] == 0xFFFF {
            LPC_HANDLE_MAP[i] = port_index;
            return Some(i + LPC_HANDLE_BASE);
        }
    }
    None
}

/// Get LPC port index from handle
unsafe fn get_lpc_port(handle: usize) -> Option<u16> {
    if handle < LPC_HANDLE_BASE {
        return None;
    }
    let idx = handle - LPC_HANDLE_BASE;
    if idx >= MAX_LPC_HANDLES {
        return None;
    }
    let port_idx = LPC_HANDLE_MAP[idx];
    if port_idx == 0xFFFF {
        None
    } else {
        Some(port_idx)
    }
}

/// Free an LPC handle
unsafe fn free_lpc_handle(handle: usize) {
    if handle >= LPC_HANDLE_BASE {
        let idx = handle - LPC_HANDLE_BASE;
        if idx < MAX_LPC_HANDLES {
            LPC_HANDLE_MAP[idx] = 0xFFFF;
        }
    }
}

/// NtCreatePort - Create an LPC server port
fn sys_create_port(
    port_handle_ptr: usize,
    object_attributes: usize,
    max_connection_info_length: usize,
    max_message_length: usize,
    _max_pool_usage: usize,
    _: usize,
) -> isize {
    if port_handle_ptr == 0 || object_attributes == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Read port name from object_attributes
    let path_result = unsafe { read_user_path(object_attributes, 260) };
    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return STATUS_INVALID_PARAMETER,
    };

    let port_name = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };

    let _ = max_connection_info_length;

    crate::serial_println!("[SYSCALL] NtCreatePort(name='{}')", port_name);

    // Create server port
    let port_index = unsafe {
        crate::lpc::lpc_create_port(
            port_name,
            crate::lpc::LpcPortType::ServerConnection,
            max_message_length as u32,
        )
    };

    match port_index {
        Some(idx) => {
            let handle = unsafe { alloc_lpc_handle(idx) };
            match handle {
                Some(h) => {
                    unsafe { *(port_handle_ptr as *mut usize) = h; }
                    crate::serial_println!("[SYSCALL] NtCreatePort -> handle {:#x}", h);
                    STATUS_SUCCESS
                }
                None => {
                    unsafe { crate::lpc::lpc_close_port(idx); }
                    STATUS_INSUFFICIENT_RESOURCES
                }
            }
        }
        None => STATUS_INSUFFICIENT_RESOURCES,
    }
}

/// NtConnectPort - Connect to an LPC server port
fn sys_connect_port(
    port_handle_ptr: usize,
    port_name_ptr: usize,
    _security_qos: usize,
    client_view: usize,
    server_view: usize,
    _max_message_length: usize,
) -> isize {
    const STATUS_PORT_CONNECTION_REFUSED: isize = 0xC0000041u32 as isize;

    if port_handle_ptr == 0 || port_name_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = client_view;
    let _ = server_view;

    let path_result = unsafe { read_user_path(port_name_ptr, 260) };
    let (path_buf, path_len) = match path_result {
        Some((buf, len)) => (buf, len),
        None => return STATUS_INVALID_PARAMETER,
    };

    let port_name = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };

    crate::serial_println!("[SYSCALL] NtConnectPort(name='{}')", port_name);

    // Connect to server port
    let client_port = unsafe { crate::lpc::lpc_connect_port(port_name, &[]) };

    match client_port {
        Some(idx) => {
            let handle = unsafe { alloc_lpc_handle(idx) };
            match handle {
                Some(h) => {
                    unsafe { *(port_handle_ptr as *mut usize) = h; }
                    crate::serial_println!("[SYSCALL] NtConnectPort -> handle {:#x}", h);
                    STATUS_SUCCESS
                }
                None => {
                    unsafe { crate::lpc::lpc_close_port(idx); }
                    STATUS_INSUFFICIENT_RESOURCES
                }
            }
        }
        None => STATUS_PORT_CONNECTION_REFUSED,
    }
}

/// NtListenPort - Wait for a connection request
fn sys_listen_port(
    port_handle: usize,
    connection_request: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    if port_handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtListenPort(handle={:#x})", port_handle);

    // Listen for pending connections
    let conn = unsafe { crate::lpc::lpc_listen_port(port_idx) };

    match conn {
        Some(c) => {
            // Return connection info if buffer provided
            if connection_request != 0 {
                unsafe {
                    // Write connection info (simplified)
                    *(connection_request as *mut u32) = c.client_port as u32;
                    *((connection_request + 4) as *mut u32) = c.client_pid;
                }
            }
            crate::serial_println!("[SYSCALL] NtListenPort -> connection from port {}", c.client_port);
            0
        }
        None => {
            crate::serial_println!("[SYSCALL] NtListenPort -> no pending connections");
            0x102 // STATUS_TIMEOUT (no pending connections)
        }
    }
}

/// NtAcceptConnectPort - Accept or reject a connection
fn sys_accept_connect_port(
    port_handle_ptr: usize,
    port_context: usize,
    connection_request: usize,
    accept_connection: usize,
    _server_view: usize,
    _client_view: usize,
) -> isize {
    if port_handle_ptr == 0 || connection_request == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = port_context;

    // Read client port from connection request
    let client_port = unsafe { *(connection_request as *const u32) as u16 };

    // Get server port (from context or somewhere)
    // For now, we need to find the server port that has this pending connection
    // This is simplified - real NT passes server port handle

    crate::serial_println!("[SYSCALL] NtAcceptConnectPort(client={}, accept={})",
        client_port, accept_connection != 0);

    if accept_connection == 0 {
        // Reject connection
        return 0;
    }

    // Accept connection - create communication port
    // We need the server port index - for simplicity, search for it
    let mut server_idx: Option<u16> = None;
    for i in 0..MAX_LPC_HANDLES {
        unsafe {
            if LPC_HANDLE_MAP[i] != 0xFFFF {
                if let Some(info) = crate::lpc::lpc_get_port_info(LPC_HANDLE_MAP[i]) {
                    if info.port_type == crate::lpc::LpcPortType::ServerConnection
                        && info.pending_connections > 0
                    {
                        server_idx = Some(LPC_HANDLE_MAP[i]);
                        break;
                    }
                }
            }
        }
    }

    let server_port = match server_idx {
        Some(s) => s,
        None => return STATUS_INVALID_HANDLE,
    };

    let comm_port = unsafe {
        crate::lpc::lpc_accept_connection(server_port, client_port, true)
    };

    match comm_port {
        Some(idx) => {
            let handle = unsafe { alloc_lpc_handle(idx) };
            match handle {
                Some(h) => {
                    unsafe { *(port_handle_ptr as *mut usize) = h; }
                    crate::serial_println!("[SYSCALL] NtAcceptConnectPort -> handle {:#x}", h);
                    STATUS_SUCCESS
                }
                None => {
                    unsafe { crate::lpc::lpc_close_port(idx); }
                    STATUS_INSUFFICIENT_RESOURCES
                }
            }
        }
        None => STATUS_INSUFFICIENT_RESOURCES,
    }
}

/// NtRequestPort - Send a datagram (no reply expected)
fn sys_request_port(
    port_handle: usize,
    message: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    const STATUS_LPC_REPLY_LOST: isize = 0xC0000025u32 as isize;

    if port_handle == 0 || message == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return STATUS_INVALID_HANDLE,
    };

    // Read message data (simplified - assume first 256 bytes)
    let data = unsafe {
        core::slice::from_raw_parts(message as *const u8, 256)
    };

    crate::serial_println!("[SYSCALL] NtRequestPort(handle={:#x})", port_handle);

    let msg = crate::lpc::LpcMessage::datagram(data);
    let result = unsafe { crate::lpc::lpc_send_message(port_idx, &msg) };

    if result.is_some() { STATUS_SUCCESS } else { STATUS_LPC_REPLY_LOST }
}

/// NtRequestWaitReplyPort - Send request and wait for reply
fn sys_request_wait_reply_port(
    port_handle: usize,
    message: usize,
    reply_message: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    const STATUS_LPC_REPLY_LOST: isize = 0xC0000025u32 as isize;

    if port_handle == 0 || message == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return STATUS_INVALID_HANDLE,
    };

    // Read message data
    let data = unsafe {
        core::slice::from_raw_parts(message as *const u8, 256)
    };

    crate::serial_println!("[SYSCALL] NtRequestWaitReplyPort(handle={:#x})", port_handle);

    let msg = crate::lpc::LpcMessage::request(data);
    let msg_id = unsafe { crate::lpc::lpc_send_message(port_idx, &msg) };

    if msg_id.is_none() {
        return STATUS_LPC_REPLY_LOST;
    }

    // Wait for reply (simplified - just check for messages)
    let reply = unsafe { crate::lpc::lpc_receive_message(port_idx) };

    match reply {
        Some(r) => {
            if reply_message != 0 {
                unsafe {
                    let dest = reply_message as *mut u8;
                    core::ptr::copy_nonoverlapping(r.get_data().as_ptr(), dest, r.get_data().len());
                }
            }
            0
        }
        None => 0x102, // STATUS_TIMEOUT
    }
}

/// NtReplyPort - Send a reply message
fn sys_reply_port(
    port_handle: usize,
    reply_message: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    const STATUS_LPC_REPLY_LOST: isize = 0xC0000025u32 as isize;

    if port_handle == 0 || reply_message == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return STATUS_INVALID_HANDLE,
    };

    // Read reply data and message ID
    let msg_id = unsafe { *(reply_message as *const u32) };
    let data = unsafe {
        core::slice::from_raw_parts((reply_message + 32) as *const u8, 224)
    };

    crate::serial_println!("[SYSCALL] NtReplyPort(handle={:#x}, msg_id={})", port_handle, msg_id);

    let result = unsafe { crate::lpc::lpc_reply_message(port_idx, msg_id, data) };

    if result { STATUS_SUCCESS } else { STATUS_LPC_REPLY_LOST }
}

/// NtReplyWaitReceivePort - Reply and wait for next message
fn sys_reply_wait_receive_port(
    port_handle: usize,
    port_context: usize,
    reply_message: usize,
    receive_message: usize,
    _: usize, _: usize,
) -> isize {
    let _ = port_context;

    if port_handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtReplyWaitReceivePort(handle={:#x})", port_handle);

    // Send reply if provided
    if reply_message != 0 {
        let msg_id = unsafe { *(reply_message as *const u32) };
        let data = unsafe {
            core::slice::from_raw_parts((reply_message + 32) as *const u8, 224)
        };
        let _ = unsafe { crate::lpc::lpc_reply_message(port_idx, msg_id, data) };
    }

    // Wait for next message
    let msg = unsafe { crate::lpc::lpc_receive_message(port_idx) };

    match msg {
        Some(m) => {
            if receive_message != 0 {
                unsafe {
                    // Write message header (simplified)
                    *(receive_message as *mut u32) = m.header.message_id;
                    *((receive_message + 4) as *mut u16) = m.header.data_length;
                    // Copy data
                    let dest = (receive_message + 32) as *mut u8;
                    core::ptr::copy_nonoverlapping(m.get_data().as_ptr(), dest, m.get_data().len());
                }
            }
            0
        }
        None => 0x102, // STATUS_TIMEOUT
    }
}

/// NtClosePort - Close an LPC port handle
fn sys_close_port(
    port_handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    const STATUS_UNSUCCESSFUL: isize = 0xC0000001u32 as isize;

    crate::serial_println!("[SYSCALL] NtClosePort(handle={:#x})", port_handle);

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return STATUS_INVALID_HANDLE,
    };

    let result = unsafe { crate::lpc::lpc_close_port(port_idx) };
    unsafe { free_lpc_handle(port_handle); }

    if result { STATUS_SUCCESS } else { STATUS_UNSUCCESSFUL }
}

/// NtQueryInformationPort - Query port information
fn sys_query_information_port(
    port_handle: usize,
    _port_information_class: usize,
    port_information: usize,
    length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    if port_handle == 0 || port_information == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let port_idx = match unsafe { get_lpc_port(port_handle) } {
        Some(idx) => idx,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtQueryInformationPort(handle={:#x})", port_handle);

    let info = unsafe { crate::lpc::lpc_get_port_info(port_idx) };

    match info {
        Some(i) => {
            let required = core::mem::size_of::<crate::lpc::LpcPortInfo>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if length < required {
                return 0x80000005u32 as isize; // STATUS_BUFFER_OVERFLOW
            }

            unsafe {
                *(port_information as *mut crate::lpc::LpcPortInfo) = i;
            }

            0
        }
        None => -1,
    }
}

// ============================================================================
// Object/Handle Syscalls
// ============================================================================

/// Handle type enumeration for the unified handle table
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandleType {
    None = 0,
    File = 1,
    Event = 2,
    Semaphore = 3,
    Mutex = 4,
    Section = 5,
    Key = 6,
    Port = 7,
    Thread = 8,
    Process = 9,
    Token = 10,
    IoCompletion = 11,
    Timer = 12,
    Debug = 13,
}

/// Generic handle entry
#[derive(Clone, Copy)]
struct HandleEntry {
    handle_type: HandleType,
    object_index: u32,  // Index into type-specific pool
    access_mask: u32,
    flags: u32,
}

impl HandleEntry {
    const fn empty() -> Self {
        Self {
            handle_type: HandleType::None,
            object_index: u32::MAX,
            access_mask: 0,
            flags: 0,
        }
    }

    fn is_valid(&self) -> bool {
        self.handle_type != HandleType::None && self.object_index != u32::MAX
    }
}

/// Process handle table
const MAX_PROCESS_HANDLES: usize = 64;
const PROCESS_HANDLE_BASE: usize = 0x5000;

static mut PROCESS_HANDLE_MAP: [u32; MAX_PROCESS_HANDLES] = [u32::MAX; MAX_PROCESS_HANDLES];

/// Allocate a process handle
unsafe fn alloc_process_handle(pid: u32) -> Option<usize> {
    for i in 0..MAX_PROCESS_HANDLES {
        if PROCESS_HANDLE_MAP[i] == u32::MAX {
            PROCESS_HANDLE_MAP[i] = pid;
            return Some(i + PROCESS_HANDLE_BASE);
        }
    }
    None
}

/// Get process ID from handle
unsafe fn get_process_id(handle: usize) -> Option<u32> {
    if handle < PROCESS_HANDLE_BASE {
        return None;
    }
    let idx = handle - PROCESS_HANDLE_BASE;
    if idx >= MAX_PROCESS_HANDLES {
        return None;
    }
    let pid = PROCESS_HANDLE_MAP[idx];
    if pid == u32::MAX { None } else { Some(pid) }
}

/// Free a process handle
unsafe fn free_process_handle(handle: usize) {
    if handle >= PROCESS_HANDLE_BASE {
        let idx = handle - PROCESS_HANDLE_BASE;
        if idx < MAX_PROCESS_HANDLES {
            PROCESS_HANDLE_MAP[idx] = u32::MAX;
        }
    }
}

/// Token handle table
const MAX_TOKEN_HANDLES: usize = 64;
const TOKEN_HANDLE_BASE: usize = 0x6000;

static mut TOKEN_HANDLE_MAP: [u32; MAX_TOKEN_HANDLES] = [u32::MAX; MAX_TOKEN_HANDLES];

/// Allocate a token handle
unsafe fn alloc_token_handle(token_id: u32) -> Option<usize> {
    for i in 0..MAX_TOKEN_HANDLES {
        if TOKEN_HANDLE_MAP[i] == u32::MAX {
            TOKEN_HANDLE_MAP[i] = token_id;
            return Some(i + TOKEN_HANDLE_BASE);
        }
    }
    None
}

/// Get token ID from handle
unsafe fn get_token_id(handle: usize) -> Option<u32> {
    if handle < TOKEN_HANDLE_BASE {
        return None;
    }
    let idx = handle - TOKEN_HANDLE_BASE;
    if idx >= MAX_TOKEN_HANDLES {
        return None;
    }
    let tid = TOKEN_HANDLE_MAP[idx];
    if tid == u32::MAX { None } else { Some(tid) }
}

/// Get a pointer to the Token from a handle
unsafe fn get_token_ptr(handle: usize) -> Option<*mut crate::se::token::Token> {
    let token_id = get_token_id(handle)?;
    // Look up token in TOKEN_POOL by matching token_id
    for i in 0..crate::se::token::MAX_TOKENS {
        if crate::se::token::TOKEN_POOL_BITMAP & (1 << i) != 0 {
            let token = &mut crate::se::token::TOKEN_POOL[i] as *mut crate::se::token::Token;
            if (*token).token_id.low_part == token_id {
                return Some(token);
            }
        }
    }
    None
}

/// Determine handle type from handle value
fn get_handle_type(handle: usize) -> HandleType {
    if (TOKEN_HANDLE_BASE..TOKEN_HANDLE_BASE + MAX_TOKEN_HANDLES).contains(&handle) {
        HandleType::Token
    } else if (PROCESS_HANDLE_BASE..PROCESS_HANDLE_BASE + MAX_PROCESS_HANDLES).contains(&handle) {
        HandleType::Process
    } else if (THREAD_HANDLE_BASE..THREAD_HANDLE_BASE + MAX_THREAD_HANDLES).contains(&handle) {
        HandleType::Thread
    } else if (LPC_HANDLE_BASE..LPC_HANDLE_BASE + MAX_LPC_HANDLES).contains(&handle) {
        HandleType::Port
    } else if (KEY_HANDLE_BASE..KEY_HANDLE_BASE + MAX_KEY_HANDLES).contains(&handle) {
        HandleType::Key
    } else if (SYNC_HANDLE_BASE..SYNC_HANDLE_BASE + MAX_SYNC_OBJECTS).contains(&handle) {
        // Check sync object type
        let idx = handle - SYNC_HANDLE_BASE;
        unsafe {
            match SYNC_OBJECT_POOL[idx].obj_type {
                SyncObjectType::Event => HandleType::Event,
                SyncObjectType::Semaphore => HandleType::Semaphore,
                SyncObjectType::Mutex => HandleType::Mutex,
                _ => HandleType::None,
            }
        }
    } else if (FILE_HANDLE_BASE..FILE_HANDLE_BASE + MAX_FILE_HANDLES).contains(&handle) {
        HandleType::File
    } else {
        HandleType::None
    }
}

/// Duplicate handle options
#[allow(non_snake_case, non_upper_case_globals)]
pub mod duplicate_options {
    /// Close the source handle after duplication
    pub const DUPLICATE_CLOSE_SOURCE: u32 = 0x00000001;
    /// Use the same access rights as the source handle
    pub const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;
    /// Use the same attributes as the source handle
    pub const DUPLICATE_SAME_ATTRIBUTES: u32 = 0x00000004;
}

/// Handle attributes for NtDuplicateHandle
#[allow(non_snake_case, non_upper_case_globals)]
pub mod handle_attributes {
    /// Handle is inheritable by child processes
    pub const OBJ_INHERIT: u32 = 0x00000002;
    /// Handle is protected from close
    pub const OBJ_PROTECT_CLOSE: u32 = 0x00000001;
}

/// NtDuplicateHandle - Duplicate a handle from one process to another
///
/// # Arguments
/// * `source_process_handle` - Handle to source process (or NtCurrentProcess)
/// * `source_handle` - Handle to duplicate from source process
/// * `target_process_handle` - Handle to target process (or NtCurrentProcess)
/// * `target_handle_ptr` - Pointer to receive duplicated handle (NULL if DUPLICATE_CLOSE_SOURCE only)
/// * `desired_access` - Access rights for new handle (ignored if DUPLICATE_SAME_ACCESS)
/// * `handle_attributes` - Attributes for new handle (OBJ_INHERIT, OBJ_PROTECT_CLOSE)
///
/// # Options (passed via extra parameter in full syscall, here we use desired_access high bits)
/// * DUPLICATE_CLOSE_SOURCE - Close source handle after duplication
/// * DUPLICATE_SAME_ACCESS - Copy access rights from source handle
/// * DUPLICATE_SAME_ATTRIBUTES - Copy attributes from source handle
///
/// # Returns
/// * STATUS_SUCCESS - Handle was successfully duplicated
/// * STATUS_INVALID_HANDLE - Source or process handle is invalid
/// * STATUS_INVALID_PARAMETER - Invalid parameter combination
/// * STATUS_ACCESS_DENIED - Insufficient access rights
/// * STATUS_INSUFFICIENT_RESOURCES - No resources to create new handle
fn sys_duplicate_handle(
    source_process_handle: usize,
    source_handle: usize,
    target_process_handle: usize,
    target_handle_ptr: usize,
    desired_access: usize,
    handle_attributes_and_options: usize,
) -> isize {
    // NT status codes
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;
    const STATUS_INVALID_PARAMETER: isize = 0xC000000Du32 as isize;
    const STATUS_ACCESS_DENIED: isize = 0xC0000022u32 as isize;
    const STATUS_INSUFFICIENT_RESOURCES: isize = 0xC000009Au32 as isize;
    const STATUS_PROCESS_IS_TERMINATING: isize = 0xC000010Au32 as isize;

    // Pseudo-handles for current process/thread
    const CURRENT_PROCESS: usize = 0xFFFFFFFFFFFFFFFF; // -1
    const CURRENT_THREAD: usize = 0xFFFFFFFFFFFFFFFE;  // -2

    // Extract options from handle_attributes_and_options
    // Lower 16 bits = attributes, upper 16 bits = options (or passed separately)
    let options = (handle_attributes_and_options >> 16) as u32;
    let new_attributes = (handle_attributes_and_options & 0xFFFF) as u32;

    crate::serial_println!(
        "[SYSCALL] NtDuplicateHandle(source_proc=0x{:X}, source=0x{:X}, target_proc=0x{:X}, access=0x{:X}, options=0x{:X})",
        source_process_handle, source_handle, target_process_handle, desired_access, options
    );

    // Validate source handle is not NULL
    if source_handle == 0 {
        crate::serial_println!("[SYSCALL] NtDuplicateHandle: NULL source handle");
        return STATUS_INVALID_HANDLE;
    }

    // Check if this is a close-only operation (DUPLICATE_CLOSE_SOURCE with NULL target)
    let close_source = (options & duplicate_options::DUPLICATE_CLOSE_SOURCE) != 0;
    let same_access = (options & duplicate_options::DUPLICATE_SAME_ACCESS) != 0;
    let same_attributes = (options & duplicate_options::DUPLICATE_SAME_ATTRIBUTES) != 0;

    // If target_handle_ptr is NULL, only valid if DUPLICATE_CLOSE_SOURCE is set
    if target_handle_ptr == 0 {
        if close_source {
            // Close-only operation - just close the source handle
            crate::serial_println!("[SYSCALL] NtDuplicateHandle: close-only operation");

            // Verify source process is current process for now
            if source_process_handle != CURRENT_PROCESS && source_process_handle != 0xFFFFFFFF {
                // TODO: Cross-process handle close
                crate::serial_println!("[SYSCALL] NtDuplicateHandle: cross-process close not supported");
                return STATUS_ACCESS_DENIED;
            }

            // Close the source handle using sys_close logic
            return close_handle_internal(source_handle);
        } else {
            crate::serial_println!("[SYSCALL] NtDuplicateHandle: NULL target without DUPLICATE_CLOSE_SOURCE");
            return STATUS_INVALID_PARAMETER;
        }
    }

    // For now, only support current process to current process
    // Check source process
    let source_is_current = source_process_handle == CURRENT_PROCESS
        || source_process_handle == 0xFFFFFFFF
        || source_process_handle == 0;

    let target_is_current = target_process_handle == CURRENT_PROCESS
        || target_process_handle == 0xFFFFFFFF
        || target_process_handle == 0;

    // For cross-process operations, we currently use the system handle table for all
    // processes since we don't have per-process handle tables fully implemented.
    // In a full implementation, we'd look up each process's handle table.
    if !source_is_current || !target_is_current {
        crate::serial_println!("[SYSCALL] NtDuplicateHandle: cross-process duplication");

        // Get source and target process IDs (for logging/verification)
        let source_pid = if source_is_current {
            0 // Current process
        } else {
            unsafe { get_process_id(source_process_handle) }.unwrap_or(0xFFFFFFFF)
        };

        let target_pid = if target_is_current {
            0
        } else {
            unsafe { get_process_id(target_process_handle) }.unwrap_or(0xFFFFFFFF)
        };

        crate::serial_println!("[SYSCALL] NtDuplicateHandle: source_pid={}, target_pid={}",
            source_pid, target_pid);

        // For now, all processes share the system handle table, so cross-process
        // duplication is equivalent to same-process duplication
        // In a full implementation, we'd:
        // 1. Get source process's handle table
        // 2. Get target process's handle table
        // 3. Use duplicate_handle_to() between them

        // Fall through to same-process handling since we use a shared table
    }

    // Handle pseudo-handles specially
    // Duplicating NtCurrentProcess or NtCurrentThread creates a real handle
    if source_handle == CURRENT_PROCESS || source_handle == 0xFFFFFFFF {
        // Duplicate current process pseudo-handle
        // Get current process ID and create a real handle
        let current_pid = unsafe {
            let prcb = crate::ke::prcb::get_current_prcb();
            let current_thread = prcb.current_thread;
            if !current_thread.is_null() {
                let process = (*current_thread).process;
                if !process.is_null() {
                    (*process).process_id
                } else {
                    0
                }
            } else {
                0 // System process
            }
        };

        if let Some(h) = unsafe { alloc_process_handle(current_pid) } {
            unsafe { *(target_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtDuplicateHandle: duplicated current process -> 0x{:X}", h);
            return STATUS_SUCCESS;
        } else {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if source_handle == CURRENT_THREAD || source_handle == 0xFFFFFFFE {
        // Duplicate current thread pseudo-handle
        let current_tid = unsafe {
            let prcb = crate::ke::prcb::get_current_prcb();
            let current_thread = prcb.current_thread;
            if !current_thread.is_null() {
                (*current_thread).thread_id
            } else {
                0
            }
        };

        if let Some(h) = unsafe { alloc_thread_handle(current_tid) } {
            unsafe { *(target_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtDuplicateHandle: duplicated current thread -> 0x{:X}", h);
            return STATUS_SUCCESS;
        } else {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    // Get the handle type
    let handle_type = get_handle_type(source_handle);

    if handle_type == HandleType::None {
        // Try object manager for kernel handles
        let ob_handle = source_handle as u32;
        let object = unsafe {
            crate::ob::ob_reference_object_by_handle(ob_handle, 0)
        };

        if !object.is_null() {
            // Found in object manager - duplicate via OB
            let access = if same_access {
                // Get access from source handle (not implemented, use full access)
                0x1F0FFF // PROCESS_ALL_ACCESS as default
            } else {
                desired_access as u32
            };

            let attrs = if same_attributes {
                0 // Get from source (not implemented)
            } else {
                new_attributes
            };

            let new_handle = unsafe {
                crate::ob::ob_create_handle(object, access, attrs)
            };

            // Dereference since ob_create_handle adds its own reference
            unsafe { crate::ob::ob_dereference_object(object); }

            if new_handle != crate::ob::INVALID_HANDLE_VALUE {
                unsafe { *(target_handle_ptr as *mut usize) = new_handle as usize; }

                // Close source if requested
                if close_source {
                    let _ = unsafe { crate::ob::ob_close_handle(ob_handle) };
                }

                crate::serial_println!("[SYSCALL] NtDuplicateHandle: via OB -> 0x{:X}", new_handle);
                return STATUS_SUCCESS;
            } else {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        crate::serial_println!("[SYSCALL] NtDuplicateHandle: unknown handle type");
        return STATUS_INVALID_HANDLE;
    }

    // Duplicate based on handle type
    let new_handle = match handle_type {
        HandleType::File => unsafe {
            if let Some(fs_handle) = get_fs_handle(source_handle) {
                // For files, we create a new handle pointing to the same fs_handle
                // The fs layer should handle reference counting
                alloc_file_handle(fs_handle)
            } else {
                None
            }
        },
        HandleType::Event | HandleType::Semaphore | HandleType::Mutex => unsafe {
            // For sync objects, create a new handle to the same object
            let idx = source_handle - SYNC_HANDLE_BASE;
            if idx < MAX_SYNC_OBJECTS && SYNC_OBJECT_POOL[idx].obj_type != SyncObjectType::None {
                // Find a new slot
                for i in 0..MAX_SYNC_OBJECTS {
                    if SYNC_OBJECT_POOL[i].obj_type == SyncObjectType::None {
                        // Copy the object (sharing the underlying kernel object)
                        SYNC_OBJECT_POOL[i].obj_type = SYNC_OBJECT_POOL[idx].obj_type;
                        // Copy data union based on type
                        core::ptr::copy_nonoverlapping(
                            &SYNC_OBJECT_POOL[idx].data as *const _,
                            &mut SYNC_OBJECT_POOL[i].data as *mut _,
                            1
                        );
                        let h = i + SYNC_HANDLE_BASE;

                        // Close source if requested
                        if close_source {
                            SYNC_OBJECT_POOL[idx].obj_type = SyncObjectType::None;
                        }

                        *(target_handle_ptr as *mut usize) = h;
                        crate::serial_println!("[SYSCALL] NtDuplicateHandle: sync object -> 0x{:X}", h);
                        return STATUS_SUCCESS;
                    }
                }
                None
            } else {
                None
            }
        },
        HandleType::Key => unsafe {
            if let Some(cm_handle) = get_cm_key_handle(source_handle) {
                let result = alloc_key_handle(cm_handle);
                if result.is_some() && close_source {
                    free_key_handle(source_handle);
                }
                result
            } else {
                None
            }
        },
        HandleType::Port => unsafe {
            if let Some(port_idx) = get_lpc_port(source_handle) {
                let result = alloc_lpc_handle(port_idx);
                if result.is_some() && close_source {
                    free_lpc_handle(source_handle);
                }
                result
            } else {
                None
            }
        },
        HandleType::Thread => unsafe {
            if let Some(tid) = get_thread_id(source_handle) {
                let result = alloc_thread_handle(tid);
                if result.is_some() && close_source {
                    free_thread_handle(source_handle);
                }
                result
            } else {
                None
            }
        },
        HandleType::Process => unsafe {
            if let Some(pid) = get_process_id(source_handle) {
                let result = alloc_process_handle(pid);
                if result.is_some() && close_source {
                    free_process_handle(source_handle);
                }
                result
            } else {
                None
            }
        },
        HandleType::Token => unsafe {
            if let Some(tok_id) = get_token_id(source_handle) {
                let result = alloc_token_handle(tok_id);
                if result.is_some() && close_source {
                    // Clear the source token handle slot
                    let idx = source_handle - TOKEN_HANDLE_BASE;
                    if idx < MAX_TOKEN_HANDLES {
                        TOKEN_HANDLE_MAP[idx] = u32::MAX;
                    }
                }
                result
            } else {
                None
            }
        },
        HandleType::Section => {
            // Section handles not yet implemented in handle table
            // TODO: Implement section handle duplication
            None
        },
        _ => None,
    };

    // Ignore desired_access for now (would need to store per-handle access rights)
    let _ = desired_access;
    let _ = same_access;
    let _ = same_attributes;

    match new_handle {
        Some(h) => {
            unsafe { *(target_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtDuplicateHandle: -> 0x{:X}", h);
            STATUS_SUCCESS
        }
        None => {
            crate::serial_println!("[SYSCALL] NtDuplicateHandle: failed - no resources");
            STATUS_INSUFFICIENT_RESOURCES
        }
    }
}

/// Internal helper to close a handle (used by NtDuplicateHandle with DUPLICATE_CLOSE_SOURCE)
fn close_handle_internal(handle: usize) -> isize {
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;

    if handle == 0 {
        return STATUS_INVALID_HANDLE;
    }

    // Check file handles
    if handle >= FILE_HANDLE_BASE {
        if let Some(fs_handle) = unsafe { get_fs_handle(handle) } {
            let _ = crate::fs::close(fs_handle);
            unsafe { free_file_handle(handle); }
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_HANDLE;
    }

    // Try object manager
    let ob_handle = handle as u32;
    if unsafe { crate::ob::ob_close_handle(ob_handle) } {
        return STATUS_SUCCESS;
    }

    STATUS_INVALID_HANDLE
}

/// Object information class constants
#[allow(non_snake_case, non_upper_case_globals)]
pub mod object_info_class {
    /// Basic object information (attributes, counts, etc.)
    pub const ObjectBasicInformation: u32 = 0;
    /// Object name information
    pub const ObjectNameInformation: u32 = 1;
    /// Object type information
    pub const ObjectTypeInformation: u32 = 2;
    /// All object types in the system
    pub const ObjectTypesInformation: u32 = 3;
    /// Handle flags (inherit, protect from close)
    pub const ObjectHandleFlagInformation: u32 = 4;
    /// Session information
    pub const ObjectSessionInformation: u32 = 5;
    /// Session object information (Vista+)
    pub const ObjectSessionObjectInformation: u32 = 6;

    // Legacy aliases
    pub const OBJECT_BASIC_INFORMATION: u32 = ObjectBasicInformation;
    pub const OBJECT_NAME_INFORMATION: u32 = ObjectNameInformation;
    pub const OBJECT_TYPE_INFORMATION: u32 = ObjectTypeInformation;
    pub const OBJECT_TYPES_INFORMATION: u32 = ObjectTypesInformation;
    pub const OBJECT_HANDLE_FLAG_INFORMATION: u32 = ObjectHandleFlagInformation;
}

/// OBJECT_BASIC_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ObjectBasicInformation {
    /// Object attributes
    pub attributes: u32,
    /// Access rights granted to handle
    pub granted_access: u32,
    /// Number of handles to object
    pub handle_count: u32,
    /// Number of pointers to object
    pub pointer_count: u32,
    /// Paged pool bytes charged
    pub paged_pool_charge: u32,
    /// Non-paged pool bytes charged
    pub non_paged_pool_charge: u32,
    /// Reserved
    pub reserved: [u32; 3],
    /// Size of name information
    pub name_info_size: u32,
    /// Size of type information
    pub type_info_size: u32,
    /// Size of security descriptor
    pub security_descriptor_size: u32,
    /// Object creation time
    pub creation_time: i64,
}

/// UNICODE_STRING structure for object names
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnicodeString {
    /// Length in bytes (not including null terminator)
    pub length: u16,
    /// Maximum length in bytes
    pub maximum_length: u16,
    /// Pointer to buffer
    pub buffer: u64,
}

/// OBJECT_NAME_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ObjectNameInformation {
    /// Object name as UNICODE_STRING
    pub name: UnicodeString,
    // Name buffer follows inline
}

/// OBJECT_TYPE_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ObjectTypeInformation {
    /// Type name
    pub type_name: UnicodeString,
    /// Total number of objects of this type
    pub total_number_of_objects: u32,
    /// Total number of handles to objects of this type
    pub total_number_of_handles: u32,
    /// Total paged pool usage
    pub total_paged_pool_usage: u32,
    /// Total non-paged pool usage
    pub total_non_paged_pool_usage: u32,
    /// Total name pool usage
    pub total_name_pool_usage: u32,
    /// Total handle table usage
    pub total_handle_table_usage: u32,
    /// High water mark for objects
    pub high_water_number_of_objects: u32,
    /// High water mark for handles
    pub high_water_number_of_handles: u32,
    /// High water mark for paged pool
    pub high_water_paged_pool_usage: u32,
    /// High water mark for non-paged pool
    pub high_water_non_paged_pool_usage: u32,
    /// High water mark for name pool
    pub high_water_name_pool_usage: u32,
    /// High water mark for handle table
    pub high_water_handle_table_usage: u32,
    /// Invalid attributes for this type
    pub invalid_attributes: u32,
    /// Generic mapping
    pub generic_mapping: GenericMapping,
    /// Valid access mask
    pub valid_access_mask: u32,
    /// Whether security is required
    pub security_required: u8,
    /// Whether object maintains handle count
    pub maintain_handle_count: u8,
    /// Type index
    pub type_index: u8,
    /// Reserved
    pub reserved_byte: u8,
    /// Pool type
    pub pool_type: u32,
    /// Default paged pool charge
    pub default_paged_pool_charge: u32,
    /// Default non-paged pool charge
    pub default_non_paged_pool_charge: u32,
    // Type name buffer follows inline
}

/// GENERIC_MAPPING structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GenericMapping {
    pub generic_read: u32,
    pub generic_write: u32,
    pub generic_execute: u32,
    pub generic_all: u32,
}

/// OBJECT_HANDLE_FLAG_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ObjectHandleFlagInformation {
    /// Whether handle is inheritable
    pub inherit: u8,
    /// Whether handle is protected from close
    pub protect_from_close: u8,
}

/// OBJECT_TYPES_INFORMATION header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ObjectTypesInformation {
    /// Number of types
    pub number_of_types: u32,
    // Array of ObjectTypeInformation follows
}

/// NtQueryObject - Query object information
///
/// # Arguments
/// * `handle` - Handle to query (or NULL for some classes)
/// * `object_information_class` - Type of information to query
/// * `object_information` - Buffer to receive information
/// * `object_information_length` - Size of buffer
/// * `return_length` - Receives required buffer size
///
/// # Returns
/// * STATUS_SUCCESS - Information was successfully returned
/// * STATUS_INVALID_HANDLE - Handle is invalid
/// * STATUS_INVALID_PARAMETER - Invalid parameter
/// * STATUS_INFO_LENGTH_MISMATCH - Buffer too small
/// * STATUS_INVALID_INFO_CLASS - Unknown information class
/// * STATUS_BUFFER_OVERFLOW - Buffer too small but return_length set
fn sys_query_object(
    handle: usize,
    object_information_class: usize,
    object_information: usize,
    object_information_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    // NT status codes
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;
    const STATUS_INVALID_PARAMETER: isize = 0xC000000Du32 as isize;
    const STATUS_INFO_LENGTH_MISMATCH: isize = 0xC0000004u32 as isize;
    const STATUS_INVALID_INFO_CLASS: isize = 0xC0000003u32 as isize;
    const STATUS_BUFFER_OVERFLOW: isize = 0x80000005u32 as isize;
    const STATUS_BUFFER_TOO_SMALL: isize = 0xC0000023u32 as isize;

    crate::serial_println!(
        "[SYSCALL] NtQueryObject(handle=0x{:X}, class={}, buffer=0x{:X}, len={})",
        handle, object_information_class, object_information, object_information_length
    );

    // ObjectTypesInformation doesn't require a handle
    let info_class = object_information_class as u32;

    // Validate handle for classes that require it
    if info_class != object_info_class::ObjectTypesInformation
        && handle == 0 {
            crate::serial_println!("[SYSCALL] NtQueryObject: NULL handle");
            return STATUS_INVALID_HANDLE;
        }

    // Get handle type
    let handle_type = get_handle_type(handle);

    // Try to get object from object manager for additional info
    let ob_handle = handle as u32;
    let ob_object = if handle != 0 {
        unsafe { crate::ob::ob_reference_object_by_handle(ob_handle, 0) }
    } else {
        core::ptr::null_mut()
    };

    let result = match info_class {
        object_info_class::ObjectBasicInformation => {
            let required = core::mem::size_of::<ObjectBasicInformation>();

            // Set return length
            if return_length != 0 {
                unsafe { *(return_length as *mut u32) = required as u32; }
            }

            // Check buffer size
            if object_information == 0 {
                STATUS_INVALID_PARAMETER
            } else if object_information_length < required {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                // Get counts from object manager if available
                let (handle_count, pointer_count) = if !ob_object.is_null() {
                    unsafe {
                        let header = crate::ob::ObjectHeader::from_body(ob_object);
                        ((*header).handle_count() as u32, (*header).pointer_count() as u32)
                    }
                } else {
                    (1, 1) // Default values
                };

                unsafe {
                    let info = object_information as *mut ObjectBasicInformation;
                    (*info).attributes = 0; // OBJ_* flags
                    (*info).granted_access = get_handle_access_mask(handle, handle_type);
                    (*info).handle_count = handle_count;
                    (*info).pointer_count = pointer_count;
                    (*info).paged_pool_charge = 0;
                    (*info).non_paged_pool_charge = 256; // Typical kernel object size
                    (*info).reserved = [0; 3];
                    (*info).name_info_size = 0; // Would need object name length
                    (*info).type_info_size = core::mem::size_of::<ObjectTypeInformation>() as u32;
                    (*info).security_descriptor_size = 0;
                    (*info).creation_time = 0; // Would need actual creation time
                }

                crate::serial_println!("[SYSCALL] NtQueryObject: returned ObjectBasicInformation");
                STATUS_SUCCESS
            }
        }

        object_info_class::ObjectNameInformation => {
            // Get object name based on handle type
            let name = get_object_name(handle, handle_type);
            let name_bytes = name.as_bytes();

            // Calculate required size: header + null-terminated wide string
            let name_buffer_size = (name_bytes.len() + 1) * 2; // UTF-16
            let required = core::mem::size_of::<ObjectNameInformation>() + name_buffer_size;

            if return_length != 0 {
                unsafe { *(return_length as *mut u32) = required as u32; }
            }

            if object_information == 0 {
                STATUS_INVALID_PARAMETER
            } else if object_information_length < required {
                if object_information_length >= core::mem::size_of::<ObjectNameInformation>() {
                    STATUS_BUFFER_OVERFLOW
                } else {
                    STATUS_INFO_LENGTH_MISMATCH
                }
            } else {
                unsafe {
                    let info = object_information as *mut ObjectNameInformation;
                    let buffer_ptr = (object_information + core::mem::size_of::<ObjectNameInformation>()) as *mut u16;

                    // Write UNICODE_STRING
                    (*info).name.length = (name_bytes.len() * 2) as u16;
                    (*info).name.maximum_length = (name_buffer_size) as u16;
                    (*info).name.buffer = buffer_ptr as u64;

                    // Write name as UTF-16LE
                    for (i, &byte) in name_bytes.iter().enumerate() {
                        *buffer_ptr.add(i) = byte as u16;
                    }
                    // Null terminator
                    *buffer_ptr.add(name_bytes.len()) = 0;
                }

                crate::serial_println!("[SYSCALL] NtQueryObject: returned ObjectNameInformation: {}", name);
                STATUS_SUCCESS
            }
        }

        object_info_class::ObjectTypeInformation => {
            // Get type name
            let type_name = get_type_name(handle_type, ob_object);
            let type_bytes = type_name.as_bytes();

            // Calculate required size
            let name_buffer_size = (type_bytes.len() + 1) * 2;
            let required = core::mem::size_of::<ObjectTypeInformation>() + name_buffer_size;

            if return_length != 0 {
                unsafe { *(return_length as *mut u32) = required as u32; }
            }

            if object_information == 0 {
                STATUS_INVALID_PARAMETER
            } else if object_information_length < required {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                unsafe {
                    let info = object_information as *mut ObjectTypeInformation;
                    let buffer_ptr = (object_information + core::mem::size_of::<ObjectTypeInformation>()) as *mut u16;

                    // Type name
                    (*info).type_name.length = (type_bytes.len() * 2) as u16;
                    (*info).type_name.maximum_length = name_buffer_size as u16;
                    (*info).type_name.buffer = buffer_ptr as u64;

                    // Statistics
                    (*info).total_number_of_objects = 1;
                    (*info).total_number_of_handles = 1;
                    (*info).total_paged_pool_usage = 0;
                    (*info).total_non_paged_pool_usage = 256;
                    (*info).total_name_pool_usage = 0;
                    (*info).total_handle_table_usage = 0;
                    (*info).high_water_number_of_objects = 1;
                    (*info).high_water_number_of_handles = 1;
                    (*info).high_water_paged_pool_usage = 0;
                    (*info).high_water_non_paged_pool_usage = 256;
                    (*info).high_water_name_pool_usage = 0;
                    (*info).high_water_handle_table_usage = 0;

                    // Access info
                    (*info).invalid_attributes = 0;
                    (*info).generic_mapping = get_type_generic_mapping(handle_type);
                    (*info).valid_access_mask = get_type_valid_access(handle_type);
                    (*info).security_required = 0;
                    (*info).maintain_handle_count = 0;
                    (*info).type_index = get_type_index(handle_type);
                    (*info).reserved_byte = 0;
                    (*info).pool_type = 0; // NonPagedPool
                    (*info).default_paged_pool_charge = 0;
                    (*info).default_non_paged_pool_charge = 256;

                    // Write type name as UTF-16LE
                    for (i, &byte) in type_bytes.iter().enumerate() {
                        *buffer_ptr.add(i) = byte as u16;
                    }
                    *buffer_ptr.add(type_bytes.len()) = 0;
                }

                crate::serial_println!("[SYSCALL] NtQueryObject: returned ObjectTypeInformation: {}", type_name);
                STATUS_SUCCESS
            }
        }

        object_info_class::ObjectHandleFlagInformation => {
            let required = core::mem::size_of::<ObjectHandleFlagInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut u32) = required as u32; }
            }

            if object_information == 0 {
                STATUS_INVALID_PARAMETER
            } else if object_information_length < required {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                unsafe {
                    let info = object_information as *mut ObjectHandleFlagInformation;
                    // For now, return defaults (not inheritable, not protected)
                    (*info).inherit = 0;
                    (*info).protect_from_close = 0;
                }

                crate::serial_println!("[SYSCALL] NtQueryObject: returned ObjectHandleFlagInformation");
                STATUS_SUCCESS
            }
        }

        object_info_class::ObjectTypesInformation => {
            // Return information about all object types in the system
            // This is a variable-length structure

            // Define known types
            const KNOWN_TYPES: &[&str] = &[
                "Type", "Directory", "SymbolicLink", "Token", "Job", "Process",
                "Thread", "Event", "Mutant", "Semaphore", "Timer", "KeyedEvent",
                "WindowStation", "Desktop", "Section", "Key", "Port", "WaitablePort",
                "Adapter", "Controller", "Device", "Driver", "IoCompletion", "File",
                "TpWorkerFactory", "DebugObject"
            ];

            // Calculate required size
            let header_size = core::mem::size_of::<ObjectTypesInformation>();
            let mut total_size = header_size;

            for type_name in KNOWN_TYPES {
                let name_size = (type_name.len() + 1) * 2;
                let aligned_entry = (core::mem::size_of::<ObjectTypeInformation>() + name_size + 7) & !7;
                total_size += aligned_entry;
            }

            if return_length != 0 {
                unsafe { *(return_length as *mut u32) = total_size as u32; }
            }

            if object_information == 0 {
                // Just querying size
                STATUS_SUCCESS
            } else if object_information_length < total_size {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                unsafe {
                    let header = object_information as *mut ObjectTypesInformation;
                    (*header).number_of_types = KNOWN_TYPES.len() as u32;

                    let mut offset = header_size;

                    for (idx, type_name) in KNOWN_TYPES.iter().enumerate() {
                        let entry_ptr = (object_information + offset) as *mut ObjectTypeInformation;
                        let name_bytes = type_name.as_bytes();
                        let name_size = (name_bytes.len() + 1) * 2;
                        let buffer_ptr = (entry_ptr as usize + core::mem::size_of::<ObjectTypeInformation>()) as *mut u16;

                        (*entry_ptr).type_name.length = (name_bytes.len() * 2) as u16;
                        (*entry_ptr).type_name.maximum_length = name_size as u16;
                        (*entry_ptr).type_name.buffer = buffer_ptr as u64;

                        (*entry_ptr).total_number_of_objects = 0;
                        (*entry_ptr).total_number_of_handles = 0;
                        (*entry_ptr).total_paged_pool_usage = 0;
                        (*entry_ptr).total_non_paged_pool_usage = 0;
                        (*entry_ptr).total_name_pool_usage = 0;
                        (*entry_ptr).total_handle_table_usage = 0;
                        (*entry_ptr).high_water_number_of_objects = 0;
                        (*entry_ptr).high_water_number_of_handles = 0;
                        (*entry_ptr).high_water_paged_pool_usage = 0;
                        (*entry_ptr).high_water_non_paged_pool_usage = 0;
                        (*entry_ptr).high_water_name_pool_usage = 0;
                        (*entry_ptr).high_water_handle_table_usage = 0;
                        (*entry_ptr).invalid_attributes = 0;
                        (*entry_ptr).generic_mapping = GenericMapping {
                            generic_read: 0x20001,
                            generic_write: 0x20002,
                            generic_execute: 0x20000,
                            generic_all: 0x1F0003,
                        };
                        (*entry_ptr).valid_access_mask = 0x1F0003;
                        (*entry_ptr).security_required = 0;
                        (*entry_ptr).maintain_handle_count = 0;
                        (*entry_ptr).type_index = (idx + 2) as u8; // Type indices start at 2
                        (*entry_ptr).reserved_byte = 0;
                        (*entry_ptr).pool_type = 0;
                        (*entry_ptr).default_paged_pool_charge = 0;
                        (*entry_ptr).default_non_paged_pool_charge = 256;

                        // Write type name
                        for (i, &byte) in name_bytes.iter().enumerate() {
                            *buffer_ptr.add(i) = byte as u16;
                        }
                        *buffer_ptr.add(name_bytes.len()) = 0;

                        let aligned_entry = (core::mem::size_of::<ObjectTypeInformation>() + name_size + 7) & !7;
                        offset += aligned_entry;
                    }
                }

                crate::serial_println!("[SYSCALL] NtQueryObject: returned ObjectTypesInformation ({} types)", KNOWN_TYPES.len());
                STATUS_SUCCESS
            }
        }

        object_info_class::ObjectSessionInformation => {
            // Returns session ID for the object
            let required = core::mem::size_of::<u32>();

            if return_length != 0 {
                unsafe { *(return_length as *mut u32) = required as u32; }
            }

            if object_information == 0 {
                STATUS_INVALID_PARAMETER
            } else if object_information_length < required {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                unsafe {
                    let session_id = object_information as *mut u32;
                    *session_id = 0; // Session 0 (console session)
                }
                STATUS_SUCCESS
            }
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtQueryObject: unknown info class {}", info_class);
            STATUS_INVALID_INFO_CLASS
        }
    };

    // Dereference object if we referenced it
    if !ob_object.is_null() {
        unsafe { crate::ob::ob_dereference_object(ob_object); }
    }

    result
}

/// Get object name based on handle type
fn get_object_name(_handle: usize, handle_type: HandleType) -> &'static str {
    match handle_type {
        HandleType::File => "\\Device\\HarddiskVolume1\\",
        HandleType::Event => "\\BaseNamedObjects\\Event",
        HandleType::Semaphore => "\\BaseNamedObjects\\Semaphore",
        HandleType::Mutex => "\\BaseNamedObjects\\Mutant",
        HandleType::Section => "\\BaseNamedObjects\\Section",
        HandleType::Key => "\\REGISTRY\\MACHINE",
        HandleType::Port => "\\Windows\\ApiPort",
        HandleType::Thread => "",
        HandleType::Process => "",
        HandleType::Token => "",
        HandleType::Debug => "\\BaseNamedObjects\\Debug",
        HandleType::IoCompletion => "\\BaseNamedObjects\\IoCompletion",
        _ => "",
    }
}

/// Get type name for object
fn get_type_name(handle_type: HandleType, _ob_object: *mut u8) -> &'static str {
    match handle_type {
        HandleType::File => "File",
        HandleType::Event => "Event",
        HandleType::Semaphore => "Semaphore",
        HandleType::Mutex => "Mutant",
        HandleType::Section => "Section",
        HandleType::Key => "Key",
        HandleType::Port => "Port",
        HandleType::Thread => "Thread",
        HandleType::Process => "Process",
        HandleType::Token => "Token",
        HandleType::Debug => "DebugObject",
        HandleType::IoCompletion => "IoCompletion",
        HandleType::Timer => "Timer",
        HandleType::None => "Unknown",
    }
}

/// Get access mask for handle based on type
fn get_handle_access_mask(_handle: usize, handle_type: HandleType) -> u32 {
    match handle_type {
        HandleType::File => 0x0012019F, // FILE_ALL_ACCESS
        HandleType::Event => 0x001F0003, // EVENT_ALL_ACCESS
        HandleType::Semaphore => 0x001F0003, // SEMAPHORE_ALL_ACCESS
        HandleType::Mutex => 0x001F0001, // MUTANT_ALL_ACCESS
        HandleType::Section => 0x000F001F, // SECTION_ALL_ACCESS
        HandleType::Key => 0x000F003F, // KEY_ALL_ACCESS
        HandleType::Port => 0x001F0001, // PORT_ALL_ACCESS
        HandleType::Thread => 0x001FFFFF, // THREAD_ALL_ACCESS
        HandleType::Process => 0x001FFFFF, // PROCESS_ALL_ACCESS
        HandleType::Token => 0x000F01FF, // TOKEN_ALL_ACCESS
        HandleType::Debug => 0x001F000F, // DEBUG_ALL_ACCESS
        HandleType::IoCompletion => 0x001F0003,
        _ => 0x001F0001, // Generic all
    }
}

/// Get generic mapping for type
fn get_type_generic_mapping(handle_type: HandleType) -> GenericMapping {
    match handle_type {
        HandleType::File => GenericMapping {
            generic_read: 0x00120089,
            generic_write: 0x00120116,
            generic_execute: 0x001200A0,
            generic_all: 0x001F01FF,
        },
        HandleType::Process => GenericMapping {
            generic_read: 0x00020410,
            generic_write: 0x00020028,
            generic_execute: 0x00120000,
            generic_all: 0x001F0FFF,
        },
        HandleType::Thread => GenericMapping {
            generic_read: 0x00020048,
            generic_write: 0x00020037,
            generic_execute: 0x00120000,
            generic_all: 0x001F03FF,
        },
        _ => GenericMapping {
            generic_read: 0x00020001,
            generic_write: 0x00020002,
            generic_execute: 0x00020000,
            generic_all: 0x001F0003,
        },
    }
}

/// Get valid access mask for type
fn get_type_valid_access(handle_type: HandleType) -> u32 {
    match handle_type {
        HandleType::File => 0x001F01FF,
        HandleType::Event => 0x001F0003,
        HandleType::Semaphore => 0x001F0003,
        HandleType::Mutex => 0x001F0001,
        HandleType::Section => 0x000F001F,
        HandleType::Key => 0x000F003F,
        HandleType::Process => 0x001FFFFF,
        HandleType::Thread => 0x001FFFFF,
        HandleType::Token => 0x000F01FF,
        _ => 0x001F0003,
    }
}

/// Get type index for handle type
fn get_type_index(handle_type: HandleType) -> u8 {
    match handle_type {
        HandleType::Process => 7,
        HandleType::Thread => 8,
        HandleType::Event => 11,
        HandleType::Mutex => 12,
        HandleType::Semaphore => 13,
        HandleType::Timer => 14,
        HandleType::Section => 16,
        HandleType::Key => 17,
        HandleType::Port => 18,
        HandleType::File => 25,
        HandleType::Token => 5,
        HandleType::Debug => 27,
        HandleType::IoCompletion => 24,
        _ => 0,
    }
}

// ============================================================================
// Process Syscalls
// ============================================================================

/// Process access rights
#[allow(non_snake_case, non_upper_case_globals)]
pub mod process_access {
    /// Permission to terminate the process
    pub const PROCESS_TERMINATE: u32 = 0x0001;
    /// Permission to create threads in the process
    pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
    /// Permission to set session ID
    pub const PROCESS_SET_SESSIONID: u32 = 0x0004;
    /// Permission for VM operations (allocate, free, protect)
    pub const PROCESS_VM_OPERATION: u32 = 0x0008;
    /// Permission to read process memory
    pub const PROCESS_VM_READ: u32 = 0x0010;
    /// Permission to write process memory
    pub const PROCESS_VM_WRITE: u32 = 0x0020;
    /// Permission to duplicate handles
    pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
    /// Permission to create child processes
    pub const PROCESS_CREATE_PROCESS: u32 = 0x0080;
    /// Permission to set quota limits
    pub const PROCESS_SET_QUOTA: u32 = 0x0100;
    /// Permission to set process information
    pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
    /// Permission to query process information
    pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    /// Permission to suspend or resume the process
    pub const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
    /// Permission to query limited information (Vista+)
    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    /// Permission to set limited information (Vista+)
    pub const PROCESS_SET_LIMITED_INFORMATION: u32 = 0x2000;
    /// All access rights (pre-Vista)
    pub const PROCESS_ALL_ACCESS_XP: u32 = 0x001F0FFF;
    /// All access rights (Vista+)
    pub const PROCESS_ALL_ACCESS: u32 = 0x001FFFFF;

    /// Standard rights
    pub const DELETE: u32 = 0x00010000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const SYNCHRONIZE: u32 = 0x00100000;
    pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F0000;
    pub const STANDARD_RIGHTS_ALL: u32 = 0x001F0000;

    // Compatibility aliases with NT naming
    pub const ProcessTerminate: u32 = PROCESS_TERMINATE;
    pub const ProcessCreateThread: u32 = PROCESS_CREATE_THREAD;
    pub const ProcessVmOperation: u32 = PROCESS_VM_OPERATION;
    pub const ProcessVmRead: u32 = PROCESS_VM_READ;
    pub const ProcessVmWrite: u32 = PROCESS_VM_WRITE;
    pub const ProcessDupHandle: u32 = PROCESS_DUP_HANDLE;
    pub const ProcessCreateProcess: u32 = PROCESS_CREATE_PROCESS;
    pub const ProcessSetQuota: u32 = PROCESS_SET_QUOTA;
    pub const ProcessSetInformation: u32 = PROCESS_SET_INFORMATION;
    pub const ProcessQueryInformation: u32 = PROCESS_QUERY_INFORMATION;
    pub const ProcessSuspendResume: u32 = PROCESS_SUSPEND_RESUME;
    pub const ProcessAllAccess: u32 = PROCESS_ALL_ACCESS;
}

/// CLIENT_ID structure for NtOpenProcess
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClientIdForProcess {
    /// Process ID to open
    pub unique_process: u64,
    /// Thread ID (usually 0 for NtOpenProcess)
    pub unique_thread: u64,
}

/// OBJECT_ATTRIBUTES structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ObjectAttributes {
    /// Size of this structure
    pub length: u32,
    /// Root directory handle (optional)
    pub root_directory: u64,
    /// Object name (optional, UNICODE_STRING pointer)
    pub object_name: u64,
    /// Attributes flags (OBJ_*)
    pub attributes: u32,
    /// Security descriptor (optional)
    pub security_descriptor: u64,
    /// Security QoS (optional)
    pub security_quality_of_service: u64,
}

/// Object attribute flags
#[allow(non_snake_case, non_upper_case_globals)]
pub mod obj_attributes {
    /// Handle is inheritable
    pub const OBJ_INHERIT: u32 = 0x00000002;
    /// Object is permanent
    pub const OBJ_PERMANENT: u32 = 0x00000010;
    /// Open with exclusive access
    pub const OBJ_EXCLUSIVE: u32 = 0x00000020;
    /// Case insensitive name lookup
    pub const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
    /// Open existing object only
    pub const OBJ_OPENIF: u32 = 0x00000080;
    /// Open symbolic link, not target
    pub const OBJ_OPENLINK: u32 = 0x00000100;
    /// Kernel handle only
    pub const OBJ_KERNEL_HANDLE: u32 = 0x00000200;
    /// Force access check
    pub const OBJ_FORCE_ACCESS_CHECK: u32 = 0x00000400;
    /// Ignore impersonated device map
    pub const OBJ_IGNORE_IMPERSONATED_DEVICEMAP: u32 = 0x00000800;
    /// Don't reparse
    pub const OBJ_DONT_REPARSE: u32 = 0x00001000;
    /// Valid attribute mask
    pub const OBJ_VALID_ATTRIBUTES: u32 = 0x00001FF2;
}

/// NtOpenProcess - Open a process by ID
///
/// Opens an existing process object and returns a handle to it.
///
/// # Arguments
/// * `process_handle` - Pointer to receive the process handle
/// * `desired_access` - Access rights to request (PROCESS_* flags)
/// * `object_attributes` - Optional object attributes (can be NULL)
/// * `client_id` - Pointer to CLIENT_ID containing process ID to open
///
/// # Returns
/// * STATUS_SUCCESS - Process opened successfully
/// * STATUS_INVALID_PARAMETER - Invalid parameters
/// * STATUS_INVALID_CID - Process not found
/// * STATUS_ACCESS_DENIED - Access denied
fn sys_open_process(
    process_handle_ptr: usize,
    desired_access: usize,
    object_attributes: usize,
    client_id_ptr: usize,
    _: usize, _: usize,
) -> isize {
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_PARAMETER: isize = 0xC000000Du32 as isize;
    const STATUS_INVALID_CID: isize = 0xC000000Bu32 as isize;
    const STATUS_ACCESS_DENIED: isize = 0xC0000022u32 as isize;
    const STATUS_INSUFFICIENT_RESOURCES: isize = 0xC000009Au32 as isize;
    const STATUS_PROCESS_IS_TERMINATING: isize = 0xC000010Au32 as isize;

    // Validate required parameters
    if process_handle_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    if client_id_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Read CLIENT_ID structure
    // CLIENT_ID is { HANDLE UniqueProcess; HANDLE UniqueThread; }
    // On x64, HANDLEs are 64-bit, but PIDs fit in 32 bits
    let pid = unsafe {
        let client_id = client_id_ptr as *const ClientIdForProcess;
        (*client_id).unique_process as u32
    };

    crate::serial_println!("[SYSCALL] NtOpenProcess(pid={}, access={:#x})",
        pid, desired_access);

    // Process ID must be specified
    if pid == 0 {
        crate::serial_println!("[SYSCALL] NtOpenProcess: process ID is zero");
        return STATUS_INVALID_CID;
    }

    // Look up the process
    let process = unsafe { crate::ps::cid::ps_lookup_process_by_id(pid) };

    if process.is_null() {
        crate::serial_println!("[SYSCALL] NtOpenProcess: process {} not found", pid);
        return STATUS_INVALID_CID;
    }

    // Check if process is terminating/terminated
    unsafe {
        let eprocess = process as *mut crate::ps::EProcess;
        use core::sync::atomic::Ordering;
        let flags = (*eprocess).flags.load(Ordering::Acquire);

        if (flags & crate::ps::eprocess::process_flags::PS_PROCESS_FLAGS_EXITING) != 0 {
            crate::serial_println!("[SYSCALL] NtOpenProcess: process {} is exiting", pid);
            // Still allow opening exiting processes (for querying exit status)
        }

        if (flags & crate::ps::eprocess::process_flags::PS_PROCESS_FLAGS_DEAD) != 0 {
            crate::serial_println!("[SYSCALL] NtOpenProcess: process {} is dead", pid);
            // Allow opening dead processes too (for cleanup)
        }
    }

    // Parse object attributes if provided
    let (inherit_handle, case_insensitive) = if object_attributes != 0 {
        unsafe {
            let oa = object_attributes as *const ObjectAttributes;
            let attrs = (*oa).attributes;
            (
                (attrs & obj_attributes::OBJ_INHERIT) != 0,
                (attrs & obj_attributes::OBJ_CASE_INSENSITIVE) != 0
            )
        }
    } else {
        (false, false)
    };

    let _ = inherit_handle; // Will be used when handle inheritance is implemented
    let _ = case_insensitive; // Not relevant for process handles

    // Validate access mask
    let access = desired_access as u32;
    let valid_access = process_access::PROCESS_ALL_ACCESS |
                       process_access::DELETE |
                       process_access::READ_CONTROL |
                       process_access::WRITE_DAC |
                       process_access::WRITE_OWNER |
                       process_access::SYNCHRONIZE;

    if (access & !valid_access) != 0 {
        crate::serial_println!("[SYSCALL] NtOpenProcess: invalid access mask {:#x}", access);
        // Don't fail - just warn for compatibility
    }

    // Access check would go here in a full implementation
    // Check if the caller has permission to open the process with requested access
    // For now, we grant the requested access

    // Special handling for protected processes
    unsafe {
        let eprocess = process as *mut crate::ps::EProcess;
        use core::sync::atomic::Ordering;
        let flags = (*eprocess).flags.load(Ordering::Acquire);

        // Check for system process protection
        if (flags & crate::ps::eprocess::process_flags::PS_PROCESS_FLAGS_SYSTEM) != 0 {
            // System process - check if we're allowing access
            // In a full implementation, we'd check for SeDebugPrivilege
            crate::serial_println!("[SYSCALL] NtOpenProcess: opening system process {}", pid);
        }
    }

    // Allocate handle
    let handle = unsafe { alloc_process_handle(pid) };
    match handle {
        Some(h) => {
            unsafe { *(process_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtOpenProcess(pid={}) -> handle {:#x}", pid, h);
            STATUS_SUCCESS
        }
        None => {
            crate::serial_println!("[SYSCALL] NtOpenProcess: failed to allocate handle");
            STATUS_INSUFFICIENT_RESOURCES
        }
    }
}

/// Process information class constants for query operations
#[allow(non_snake_case, non_upper_case_globals)]
pub mod process_info_class {
    /// Basic process information (exit status, PEB, affinity, priority, IDs)
    pub const ProcessBasicInformation: u32 = 0;
    /// Quota limits (working set, paged/nonpaged pool)
    pub const ProcessQuotaLimits: u32 = 1;
    /// I/O counters (reads, writes, other operations)
    pub const ProcessIoCounters: u32 = 2;
    /// VM counters (virtual memory statistics)
    pub const ProcessVmCounters: u32 = 3;
    /// Process times (creation, exit, kernel, user)
    pub const ProcessTimes: u32 = 4;
    /// Base priority
    pub const ProcessBasePriority: u32 = 5;
    /// Raise priority
    pub const ProcessRaisePriority: u32 = 6;
    /// Debug port
    pub const ProcessDebugPort: u32 = 7;
    /// Exception port
    pub const ProcessExceptionPort: u32 = 8;
    /// Access token
    pub const ProcessAccessToken: u32 = 9;
    /// LDT information
    pub const ProcessLdtInformation: u32 = 10;
    /// LDT size
    pub const ProcessLdtSize: u32 = 11;
    /// Default hard error mode
    pub const ProcessDefaultHardErrorMode: u32 = 12;
    /// I/O port handlers
    pub const ProcessIoPortHandlers: u32 = 13;
    /// Pooled usage and limits
    pub const ProcessPooledUsageAndLimits: u32 = 14;
    /// Working set watch
    pub const ProcessWorkingSetWatch: u32 = 15;
    /// User mode IOPLs
    pub const ProcessUserModeIOPL: u32 = 16;
    /// Enable alignment fault fixup
    pub const ProcessEnableAlignmentFaultFixup: u32 = 17;
    /// Priority class
    pub const ProcessPriorityClass: u32 = 18;
    /// WX86 information
    pub const ProcessWx86Information: u32 = 19;
    /// Handle count
    pub const ProcessHandleCount: u32 = 20;
    /// Affinity mask
    pub const ProcessAffinityMask: u32 = 21;
    /// Priority boost
    pub const ProcessPriorityBoost: u32 = 22;
    /// Device map
    pub const ProcessDeviceMap: u32 = 23;
    /// Session information
    pub const ProcessSessionInformation: u32 = 24;
    /// Foreground information
    pub const ProcessForegroundInformation: u32 = 25;
    /// WOW64 information
    pub const ProcessWow64Information: u32 = 26;
    /// Image file name
    pub const ProcessImageFileName: u32 = 27;
    /// LUIDs for device maps
    pub const ProcessLUIDDeviceMapsEnabled: u32 = 28;
    /// Break on termination
    pub const ProcessBreakOnTermination: u32 = 29;
    /// Debug object handle
    pub const ProcessDebugObjectHandle: u32 = 30;
    /// Debug flags
    pub const ProcessDebugFlags: u32 = 31;
    /// Handle tracing
    pub const ProcessHandleTracing: u32 = 32;
    /// I/O priority
    pub const ProcessIoPriority: u32 = 33;
    /// Execute flags (DEP)
    pub const ProcessExecuteFlags: u32 = 34;
    /// TLS information
    pub const ProcessTlsInformation: u32 = 35;
    /// Cookie
    pub const ProcessCookie: u32 = 36;
    /// Image information
    pub const ProcessImageInformation: u32 = 37;
    /// Cycle time
    pub const ProcessCycleTime: u32 = 38;
    /// Page priority
    pub const ProcessPagePriority: u32 = 39;
    /// Instrumentation callback
    pub const ProcessInstrumentationCallback: u32 = 40;
    /// Thread stack allocation
    pub const ProcessThreadStackAllocation: u32 = 41;
    /// Working set watch extended
    pub const ProcessWorkingSetWatchEx: u32 = 42;
    /// Image file name (Win32)
    pub const ProcessImageFileNameWin32: u32 = 43;
    /// Image file mapping
    pub const ProcessImageFileMapping: u32 = 44;
    /// Affinity update mode
    pub const ProcessAffinityUpdateMode: u32 = 45;
    /// Memory allocation mode
    pub const ProcessMemoryAllocationMode: u32 = 46;
    /// Group information
    pub const ProcessGroupInformation: u32 = 47;
    /// Token virtualization enabled
    pub const ProcessTokenVirtualizationEnabled: u32 = 48;
    /// Console host process
    pub const ProcessConsoleHostProcess: u32 = 49;
    /// Window information
    pub const ProcessWindowInformation: u32 = 50;

    // Legacy uppercase names for compatibility
    pub const PROCESS_BASIC_INFORMATION: u32 = 0;
    pub const PROCESS_QUOTA_LIMITS: u32 = 1;
    pub const PROCESS_IO_COUNTERS: u32 = 2;
    pub const PROCESS_VM_COUNTERS: u32 = 3;
    pub const PROCESS_TIMES: u32 = 4;
    pub const PROCESS_PRIORITY_CLASS: u32 = 18;
    pub const PROCESS_HANDLE_COUNT: u32 = 20;
    pub const PROCESS_SESSION_INFORMATION: u32 = 24;
    pub const PROCESS_IMAGE_FILE_NAME: u32 = 27;
}

/// PROCESS_BASIC_INFORMATION structure (class 0)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessBasicInformation {
    /// Exit status (STATUS_PENDING if running)
    pub exit_status: i32,
    /// Pointer to Process Environment Block
    pub peb_base_address: u64,
    /// CPU affinity mask
    pub affinity_mask: u64,
    /// Base scheduling priority
    pub base_priority: i32,
    /// Process ID
    pub unique_process_id: u32,
    /// Parent process ID
    pub inherited_from_unique_process_id: u32,
}

/// QUOTA_LIMITS structure (class 1)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QuotaLimits {
    /// Paged pool quota
    pub paged_pool_limit: u64,
    /// Non-paged pool quota
    pub non_paged_pool_limit: u64,
    /// Minimum working set size
    pub minimum_working_set_size: u64,
    /// Maximum working set size
    pub maximum_working_set_size: u64,
    /// Pagefile quota
    pub pagefile_limit: u64,
    /// Time limit
    pub time_limit: i64,
}

/// IO_COUNTERS structure (class 2)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoCounters {
    /// Read operations count
    pub read_operation_count: u64,
    /// Write operations count
    pub write_operation_count: u64,
    /// Other operations count
    pub other_operation_count: u64,
    /// Bytes read
    pub read_transfer_count: u64,
    /// Bytes written
    pub write_transfer_count: u64,
    /// Other bytes transferred
    pub other_transfer_count: u64,
}

/// VM_COUNTERS structure (class 3)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VmCounters {
    /// Peak virtual size
    pub peak_virtual_size: u64,
    /// Current virtual size
    pub virtual_size: u64,
    /// Page fault count
    pub page_fault_count: u32,
    /// Peak working set size
    pub peak_working_set_size: u64,
    /// Current working set size
    pub working_set_size: u64,
    /// Quota peak paged pool usage
    pub quota_peak_paged_pool_usage: u64,
    /// Quota paged pool usage
    pub quota_paged_pool_usage: u64,
    /// Quota peak nonpaged pool usage
    pub quota_peak_non_paged_pool_usage: u64,
    /// Quota nonpaged pool usage
    pub quota_non_paged_pool_usage: u64,
    /// Pagefile usage
    pub pagefile_usage: u64,
    /// Peak pagefile usage
    pub peak_pagefile_usage: u64,
}

/// KERNEL_USER_TIMES structure for processes (class 4)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessTimes {
    /// Creation time (100-nanosecond intervals since 1601)
    pub create_time: i64,
    /// Exit time (0 if still running)
    pub exit_time: i64,
    /// Time spent in kernel mode
    pub kernel_time: i64,
    /// Time spent in user mode
    pub user_time: i64,
}

/// Process priority class structure (class 18)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessPriorityClassInfo {
    /// Whether process is in foreground
    pub foreground: u8,
    /// Priority class value
    pub priority_class: u8,
}

/// Process session information (class 24)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessSessionInfo {
    /// Session ID
    pub session_id: u32,
}

/// Process cycle time information (class 38)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessCycleTimeInfo {
    /// Accumulated cycle time
    pub accumulated_cycles: u64,
    /// Current cycle count
    pub current_cycle_count: u64,
}

/// Process handle information (class 20 extended)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessHandleInfo {
    /// Number of handles
    pub handle_count: u32,
}

/// Process WOW64 information (class 26)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessWow64Info {
    /// WOW64 PEB address (0 if native)
    pub wow64_peb: u64,
}

/// Section image information (class 37)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SectionImageInformation {
    /// Transfer address (entry point)
    pub transfer_address: u64,
    /// Zero bits
    pub zero_bits: u32,
    /// Maximum stack size
    pub maximum_stack_size: u64,
    /// Committed stack size
    pub committed_stack_size: u64,
    /// Subsystem type
    pub subsystem_type: u32,
    /// Subsystem version (minor << 16 | major)
    pub subsystem_version_low: u16,
    pub subsystem_version_high: u16,
    /// GpValue
    pub gp_value: u32,
    /// Image characteristics
    pub image_characteristics: u16,
    /// DLL characteristics
    pub dll_characteristics: u16,
    /// Machine type
    pub machine: u16,
    /// Image contains code
    pub image_contains_code: u8,
    /// Image flags
    pub image_flags: u8,
    /// Loader flags
    pub loader_flags: u32,
    /// Image file size
    pub image_file_size: u32,
    /// Checksum
    pub checksum: u32,
}

/// NtQueryInformationProcess - Query process information
///
/// Retrieves information about a process based on the specified information class.
///
/// # Arguments
/// * `process_handle` - Handle to the process (0xFFFFFFFF = current process)
/// * `process_information_class` - Type of information to query
/// * `process_information` - Buffer to receive the information
/// * `process_information_length` - Size of the buffer
/// * `return_length` - Optional pointer to receive actual size needed
fn sys_query_information_process(
    process_handle: usize,
    process_information_class: usize,
    process_information: usize,
    process_information_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;
    const STATUS_INFO_LENGTH_MISMATCH: isize = 0xC0000004u32 as isize;
    const STATUS_INVALID_INFO_CLASS: isize = 0xC0000003u32 as isize;
    const STATUS_PENDING: i32 = 0x103;

    // Validate buffer pointer
    if process_information == 0 {
        return STATUS_INVALID_HANDLE;
    }

    // Get process ID from handle
    // Special handle -1 (0xFFFFFFFF) means current process
    let pid = if process_handle == usize::MAX || process_handle == 0xFFFFFFFF {
        // Get current process ID
        unsafe {
            let prcb = crate::ke::prcb::get_current_prcb();
            if !prcb.current_thread.is_null() {
                let thread = prcb.current_thread as *mut crate::ps::EThread;
                if !(*thread).thread_process.is_null() {
                    (*(*thread).thread_process).unique_process_id
                } else {
                    4 // System process fallback
                }
            } else {
                4 // System process fallback
            }
        }
    } else if process_handle == 0 {
        return STATUS_INVALID_HANDLE;
    } else {
        match unsafe { get_process_id(process_handle) } {
            Some(p) => p,
            None => return STATUS_INVALID_HANDLE,
        }
    };

    // Look up process structure
    let process = unsafe { crate::ps::cid::ps_lookup_process_by_id(pid) };
    let eprocess = process as *mut crate::ps::EProcess;

    crate::serial_println!("[SYSCALL] NtQueryInformationProcess(pid={}, class={})",
        pid, process_information_class);

    match process_information_class as u32 {
        // Class 0: ProcessBasicInformation
        process_info_class::ProcessBasicInformation => {
            let required = core::mem::size_of::<ProcessBasicInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut ProcessBasicInformation;
                if !eprocess.is_null() {
                    let p = &*eprocess;
                    (*info).exit_status = if p.exit_time > 0 { p.exit_status } else { STATUS_PENDING };
                    (*info).peb_base_address = p.peb as u64;
                    (*info).affinity_mask = 1; // Single processor
                    (*info).base_priority = p.pcb.base_priority as i32;
                    (*info).unique_process_id = p.unique_process_id;
                    (*info).inherited_from_unique_process_id = p.inherited_from_unique_process_id;
                } else {
                    (*info).exit_status = STATUS_PENDING;
                    (*info).peb_base_address = 0;
                    (*info).affinity_mask = 1;
                    (*info).base_priority = 8;
                    (*info).unique_process_id = pid;
                    (*info).inherited_from_unique_process_id = 0;
                }
            }

            STATUS_SUCCESS
        }

        // Class 1: ProcessQuotaLimits
        process_info_class::ProcessQuotaLimits => {
            let required = core::mem::size_of::<QuotaLimits>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut QuotaLimits;
                // Default quota limits
                (*info).paged_pool_limit = 0x20000000; // 512MB
                (*info).non_paged_pool_limit = 0x10000000; // 256MB
                (*info).minimum_working_set_size = 200 * 4096; // 200 pages
                (*info).maximum_working_set_size = 45000 * 4096; // 45000 pages
                (*info).pagefile_limit = 0xFFFFFFFF; // Unlimited
                (*info).time_limit = -1; // No limit
            }

            STATUS_SUCCESS
        }

        // Class 2: ProcessIoCounters
        process_info_class::ProcessIoCounters => {
            let required = core::mem::size_of::<IoCounters>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut IoCounters;
                if !eprocess.is_null() {
                    let p = &*eprocess;
                    (*info).read_operation_count = p.read_operation_count;
                    (*info).write_operation_count = p.write_operation_count;
                    (*info).other_operation_count = p.other_operation_count;
                    (*info).read_transfer_count = p.read_transfer_count;
                    (*info).write_transfer_count = p.write_transfer_count;
                    (*info).other_transfer_count = p.other_transfer_count;
                } else {
                    core::ptr::write_bytes(info, 0, 1);
                }
            }

            STATUS_SUCCESS
        }

        // Class 3: ProcessVmCounters
        process_info_class::ProcessVmCounters => {
            let required = core::mem::size_of::<VmCounters>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut VmCounters;
                if !eprocess.is_null() {
                    let p = &*eprocess;
                    (*info).peak_virtual_size = p.peak_virtual_size;
                    (*info).virtual_size = p.virtual_size;
                    (*info).page_fault_count = 0;
                    (*info).peak_working_set_size = p.peak_working_set_size;
                    (*info).working_set_size = p.working_set_size;
                    (*info).quota_peak_paged_pool_usage = p.quota_paged_pool_usage;
                    (*info).quota_paged_pool_usage = p.quota_paged_pool_usage;
                    (*info).quota_peak_non_paged_pool_usage = p.quota_non_paged_pool_usage;
                    (*info).quota_non_paged_pool_usage = p.quota_non_paged_pool_usage;
                    (*info).pagefile_usage = 0;
                    (*info).peak_pagefile_usage = 0;
                } else {
                    core::ptr::write_bytes(info, 0, 1);
                }
            }

            STATUS_SUCCESS
        }

        // Class 4: ProcessTimes
        process_info_class::ProcessTimes => {
            let required = core::mem::size_of::<ProcessTimes>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut ProcessTimes;
                if !eprocess.is_null() {
                    let p = &*eprocess;
                    // Convert ticks to 100-nanosecond intervals for create/exit time
                    (*info).create_time = (p.create_time as i64) * 10000;
                    (*info).exit_time = if p.exit_time > 0 { (p.exit_time as i64) * 10000 } else { 0 };
                    // Use tracked kernel/user time from EProcess
                    (*info).kernel_time = p.kernel_time as i64;
                    (*info).user_time = p.user_time as i64;
                } else {
                    (*info).create_time = 0;
                    (*info).exit_time = 0;
                    (*info).kernel_time = 0;
                    (*info).user_time = 0;
                }
            }

            STATUS_SUCCESS
        }

        // Class 5: ProcessBasePriority
        process_info_class::ProcessBasePriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let base_priority = if !eprocess.is_null() {
                    (*eprocess).pcb.base_priority as i32
                } else {
                    8
                };
                *(process_information as *mut i32) = base_priority;
            }

            STATUS_SUCCESS
        }

        // Class 7: ProcessDebugPort
        process_info_class::ProcessDebugPort => {
            let required = 8usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let debug_port = if !eprocess.is_null() {
                    (*eprocess).debug_port as u64
                } else {
                    0
                };
                *(process_information as *mut u64) = debug_port;
            }

            STATUS_SUCCESS
        }

        // Class 12: ProcessDefaultHardErrorMode
        process_info_class::ProcessDefaultHardErrorMode => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let error_mode = if !eprocess.is_null() {
                    (*eprocess).hard_error_mode
                } else {
                    0
                };
                *(process_information as *mut u32) = error_mode;
            }

            STATUS_SUCCESS
        }

        // Class 18: ProcessPriorityClass
        process_info_class::ProcessPriorityClass => {
            let required = core::mem::size_of::<ProcessPriorityClassInfo>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut ProcessPriorityClassInfo;
                if !eprocess.is_null() {
                    let priority = (*eprocess).pcb.base_priority;
                    (*info).foreground = 0;
                    // Map base priority to priority class
                    (*info).priority_class = match priority {
                        0..=4 => 1,   // IDLE
                        5..=6 => 5,   // BELOW_NORMAL
                        7..=8 => 2,   // NORMAL
                        9..=10 => 3,  // ABOVE_NORMAL
                        11..=15 => 4, // HIGH
                        _ => 6,       // REALTIME
                    };
                } else {
                    (*info).foreground = 0;
                    (*info).priority_class = 2; // NORMAL
                }
            }

            STATUS_SUCCESS
        }

        // Class 20: ProcessHandleCount
        process_info_class::ProcessHandleCount => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Use tracked handle count, or fall back to object table count
                let count = if !eprocess.is_null() {
                    let p = &*eprocess;
                    if p.handle_count > 0 {
                        p.handle_count
                    } else if !p.object_table.is_null() {
                        (*p.object_table).count()
                    } else {
                        10 // Default
                    }
                } else {
                    10 // Default handle count
                };
                *(process_information as *mut u32) = count;
            }

            STATUS_SUCCESS
        }

        // Class 21: ProcessAffinityMask
        process_info_class::ProcessAffinityMask => {
            let required = 8usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let affinity = if !eprocess.is_null() {
                    (*eprocess).pcb.affinity
                } else {
                    1 // Single processor
                };
                *(process_information as *mut u64) = affinity;
            }

            STATUS_SUCCESS
        }

        // Class 22: ProcessPriorityBoost
        process_info_class::ProcessPriorityBoost => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Returns TRUE if priority boost is disabled
                let disabled = if !eprocess.is_null() {
                    (*eprocess).priority_boost_disabled
                } else {
                    false
                };
                *(process_information as *mut u32) = if disabled { 1 } else { 0 };
            }

            STATUS_SUCCESS
        }

        // Class 24: ProcessSessionInformation
        process_info_class::ProcessSessionInformation => {
            let required = core::mem::size_of::<ProcessSessionInfo>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut ProcessSessionInfo;
                (*info).session_id = if !eprocess.is_null() {
                    (*eprocess).session_id
                } else {
                    0
                };
            }

            STATUS_SUCCESS
        }

        // Class 26: ProcessWow64Information
        process_info_class::ProcessWow64Information => {
            let required = core::mem::size_of::<ProcessWow64Info>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut ProcessWow64Info;
                // Native 64-bit process, no WOW64
                (*info).wow64_peb = 0;
            }

            STATUS_SUCCESS
        }

        // Class 27: ProcessImageFileName
        process_info_class::ProcessImageFileName => {
            // Returns UNICODE_STRING with image name
            // For now, return a fixed size response
            let required = 520usize; // Max path in UNICODE_STRING format

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Write UNICODE_STRING header
                let length: u16 = if !eprocess.is_null() {
                    let mut len = 0u16;
                    for &c in &(*eprocess).image_file_name {
                        if c == 0 { break; }
                        len += 2; // UTF-16
                    }
                    len
                } else {
                    0
                };

                let ptr = process_information as *mut u8;
                *(ptr as *mut u16) = length; // Length
                *(ptr.add(2) as *mut u16) = length + 2; // MaximumLength
                *(ptr.add(8) as *mut u64) = if length > 0 {
                    process_information as u64 + 16
                } else {
                    0
                };

                // Copy name as UTF-16 if we have space
                if process_information_length >= 16 + length as usize && !eprocess.is_null() {
                    let name_ptr = ptr.add(16) as *mut u16;
                    for (i, &c) in (*eprocess).image_file_name.iter().enumerate() {
                        if c == 0 { break; }
                        *name_ptr.add(i) = c as u16;
                    }
                }
            }

            STATUS_SUCCESS
        }

        // Class 29: ProcessBreakOnTermination
        process_info_class::ProcessBreakOnTermination => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let break_on_term = if !eprocess.is_null() {
                    (*eprocess).break_on_termination
                } else {
                    false
                };
                *(process_information as *mut u32) = if break_on_term { 1 } else { 0 };
            }

            STATUS_SUCCESS
        }

        // Class 31: ProcessDebugFlags
        process_info_class::ProcessDebugFlags => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Debug inherit flag (1 = no inherit)
                let has_debug_port = if !eprocess.is_null() {
                    !(*eprocess).debug_port.is_null()
                } else {
                    false
                };
                *(process_information as *mut u32) = if has_debug_port { 0 } else { 1 };
            }

            STATUS_SUCCESS
        }

        // Class 33: ProcessIoPriority
        process_info_class::ProcessIoPriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let io_priority = if !eprocess.is_null() {
                    (*eprocess).io_priority as u32
                } else {
                    2 // Normal
                };
                *(process_information as *mut u32) = io_priority;
            }

            STATUS_SUCCESS
        }

        // Class 34: ProcessExecuteFlags
        process_info_class::ProcessExecuteFlags => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let execute_flags = if !eprocess.is_null() {
                    (*eprocess).execute_flags
                } else {
                    2 // DEP enabled by default (MEM_EXECUTE_OPTION_ENABLE)
                };
                *(process_information as *mut u32) = execute_flags;
            }

            STATUS_SUCCESS
        }

        // Class 36: ProcessCookie
        process_info_class::ProcessCookie => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Generate a simple cookie based on process ID
                let cookie = (pid as u64).wrapping_mul(0x5DEECE66D).wrapping_add(0xB) as u32;
                *(process_information as *mut u32) = cookie;
            }

            STATUS_SUCCESS
        }

        // Class 37: ProcessImageInformation
        process_info_class::ProcessImageInformation => {
            let required = core::mem::size_of::<SectionImageInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut SectionImageInformation;
                // Default values for a 64-bit Windows executable
                (*info).transfer_address = 0;
                (*info).zero_bits = 0;
                (*info).maximum_stack_size = 0x100000; // 1MB
                (*info).committed_stack_size = 0x1000; // 4KB
                (*info).subsystem_type = 3; // IMAGE_SUBSYSTEM_WINDOWS_CUI
                (*info).subsystem_version_low = 0;
                (*info).subsystem_version_high = 6; // Windows 6.x
                (*info).gp_value = 0;
                (*info).image_characteristics = 0x22; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
                (*info).dll_characteristics = 0;
                (*info).machine = 0x8664; // AMD64
                (*info).image_contains_code = 1;
                (*info).image_flags = 0;
                (*info).loader_flags = 0;
                (*info).image_file_size = 0;
                (*info).checksum = 0;
            }

            STATUS_SUCCESS
        }

        // Class 38: ProcessCycleTime
        process_info_class::ProcessCycleTime => {
            let required = core::mem::size_of::<ProcessCycleTimeInfo>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = process_information as *mut ProcessCycleTimeInfo;
                if !eprocess.is_null() {
                    let p = &*eprocess;
                    (*info).accumulated_cycles = p.cycle_time;
                    // Current cycle count - read TSC for current value
                    let tsc: u64;
                    core::arch::asm!("rdtsc", "shl rdx, 32", "or rax, rdx", out("rax") tsc, out("rdx") _);
                    (*info).current_cycle_count = tsc;
                } else {
                    (*info).accumulated_cycles = 0;
                    (*info).current_cycle_count = 0;
                }
            }

            STATUS_SUCCESS
        }

        // Class 39: ProcessPagePriority
        process_info_class::ProcessPagePriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let page_priority = if !eprocess.is_null() {
                    (*eprocess).page_priority as u32
                } else {
                    5 // Normal
                };
                *(process_information as *mut u32) = page_priority;
            }

            STATUS_SUCCESS
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtQueryInformationProcess: unsupported class {}",
                process_information_class);
            STATUS_INVALID_INFO_CLASS
        }
    }
}

/// NtSuspendProcess - Suspend all threads in a process
fn sys_suspend_process(
    process_handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::cid::ps_lookup_process_by_id;
    use crate::ps::eprocess::EProcess;
    use crate::ps::ethread::EThread;
    use crate::containing_record;

    let pid = match unsafe { get_process_id(process_handle) } {
        Some(p) => p,
        None => return 0xC0000008u32 as isize, // STATUS_INVALID_HANDLE
    };

    crate::serial_println!("[SYSCALL] NtSuspendProcess(pid={})", pid);

    // Look up the process
    let process = unsafe {
        ps_lookup_process_by_id(pid) as *mut EProcess
    };

    if process.is_null() {
        return 0xC0000008u32 as isize;
    }

    // Iterate through all threads in the process and suspend them
    let mut suspended_count = 0u32;
    unsafe {
        let thread_list_head = &(*process).thread_list_head;

        if thread_list_head.is_empty() {
            crate::serial_println!("[SYSCALL] NtSuspendProcess: no threads to suspend");
            return 0;
        }

        // Walk the thread list - flink is a field, not a method
        let mut current = thread_list_head.flink;
        let head_addr = thread_list_head as *const _ as usize;

        while current as usize != head_addr {
            // Get EThread from list entry
            let thread = containing_record!(current, EThread, thread_list_entry);

            // Suspend the thread's TCB
            (*thread).tcb.suspend();
            suspended_count += 1;

            crate::serial_println!("[SYSCALL] NtSuspendProcess: suspended thread {}",
                (*thread).cid.unique_thread);

            // Move to next entry
            current = (*current).flink;
        }
    }

    crate::serial_println!("[SYSCALL] NtSuspendProcess: suspended {} threads", suspended_count);
    0 // STATUS_SUCCESS
}

/// NtResumeProcess - Resume all threads in a process
fn sys_resume_process(
    process_handle: usize,
    _: usize, _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::cid::ps_lookup_process_by_id;
    use crate::ps::eprocess::EProcess;
    use crate::ps::ethread::EThread;
    use crate::containing_record;

    let pid = match unsafe { get_process_id(process_handle) } {
        Some(p) => p,
        None => return 0xC0000008u32 as isize,
    };

    crate::serial_println!("[SYSCALL] NtResumeProcess(pid={})", pid);

    // Look up the process
    let process = unsafe {
        ps_lookup_process_by_id(pid) as *mut EProcess
    };

    if process.is_null() {
        return 0xC0000008u32 as isize;
    }

    // Iterate through all threads in the process and resume them
    let mut resumed_count = 0u32;
    unsafe {
        let thread_list_head = &(*process).thread_list_head;

        if thread_list_head.is_empty() {
            crate::serial_println!("[SYSCALL] NtResumeProcess: no threads to resume");
            return 0;
        }

        // Walk the thread list - flink is a field, not a method
        let mut current = thread_list_head.flink;
        let head_addr = thread_list_head as *const _ as usize;

        while current as usize != head_addr {
            // Get EThread from list entry
            let thread = containing_record!(current, EThread, thread_list_entry);

            // Resume the thread's TCB
            let prev_count = (*thread).tcb.resume();

            if prev_count > 0 {
                resumed_count += 1;
                crate::serial_println!("[SYSCALL] NtResumeProcess: resumed thread {}",
                    (*thread).cid.unique_thread);

                // If suspend count reached 0, make thread ready to run
                if (*thread).tcb.suspend_count == 0 {
                    crate::ke::scheduler::ki_ready_thread(&mut (*thread).tcb as *mut _);
                }
            }

            // Move to next entry
            current = (*current).flink;
        }
    }

    crate::serial_println!("[SYSCALL] NtResumeProcess: resumed {} threads", resumed_count);
    0 // STATUS_SUCCESS
}

// ============================================================================
// Thread Syscalls (Extended)
// ============================================================================

/// Thread access rights
#[allow(non_snake_case, non_upper_case_globals)]
pub mod thread_access {
    /// Permission to terminate the thread
    pub const THREAD_TERMINATE: u32 = 0x0001;
    /// Permission to suspend or resume the thread
    pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;
    /// Permission to alert the thread
    pub const THREAD_ALERT: u32 = 0x0004;
    /// Permission to get the thread context
    pub const THREAD_GET_CONTEXT: u32 = 0x0008;
    /// Permission to set the thread context
    pub const THREAD_SET_CONTEXT: u32 = 0x0010;
    /// Permission to set thread information
    pub const THREAD_SET_INFORMATION: u32 = 0x0020;
    /// Permission to query thread information
    pub const THREAD_QUERY_INFORMATION: u32 = 0x0040;
    /// Permission to set thread token
    pub const THREAD_SET_THREAD_TOKEN: u32 = 0x0080;
    /// Permission to impersonate
    pub const THREAD_IMPERSONATE: u32 = 0x0100;
    /// Permission for direct impersonation
    pub const THREAD_DIRECT_IMPERSONATION: u32 = 0x0200;
    /// Permission to set limited information
    pub const THREAD_SET_LIMITED_INFORMATION: u32 = 0x0400;
    /// Permission to query limited information
    pub const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
    /// Permission to resume thread (Vista+)
    pub const THREAD_RESUME: u32 = 0x1000;
    /// All access rights
    pub const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;

    /// Standard rights
    pub const DELETE: u32 = 0x00010000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const SYNCHRONIZE: u32 = 0x00100000;

    // Compatibility aliases
    pub const ThreadTerminate: u32 = THREAD_TERMINATE;
    pub const ThreadSuspendResume: u32 = THREAD_SUSPEND_RESUME;
    pub const ThreadGetContext: u32 = THREAD_GET_CONTEXT;
    pub const ThreadSetContext: u32 = THREAD_SET_CONTEXT;
    pub const ThreadQueryInformation: u32 = THREAD_QUERY_INFORMATION;
    pub const ThreadSetInformation: u32 = THREAD_SET_INFORMATION;
    pub const ThreadAllAccess: u32 = THREAD_ALL_ACCESS;
}

/// CLIENT_ID structure for NtOpenThread
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClientIdForThread {
    /// Process ID (can be 0 to match any process)
    pub unique_process: u64,
    /// Thread ID to open
    pub unique_thread: u64,
}

/// NtOpenThread - Open a thread by ID
///
/// Opens an existing thread object and returns a handle to it.
///
/// # Arguments
/// * `thread_handle` - Pointer to receive the thread handle
/// * `desired_access` - Access rights to request (THREAD_* flags)
/// * `object_attributes` - Optional object attributes (can be NULL)
/// * `client_id` - Pointer to CLIENT_ID containing thread ID to open
///
/// # Returns
/// * STATUS_SUCCESS - Thread opened successfully
/// * STATUS_INVALID_PARAMETER - Invalid parameters
/// * STATUS_INVALID_CID - Thread not found
/// * STATUS_ACCESS_DENIED - Access denied
fn sys_open_thread(
    thread_handle_ptr: usize,
    desired_access: usize,
    object_attributes: usize,
    client_id_ptr: usize,
    _: usize, _: usize,
) -> isize {
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_PARAMETER: isize = 0xC000000Du32 as isize;
    const STATUS_INVALID_CID: isize = 0xC000000Bu32 as isize;
    const STATUS_ACCESS_DENIED: isize = 0xC0000022u32 as isize;
    const STATUS_INSUFFICIENT_RESOURCES: isize = 0xC000009Au32 as isize;
    const STATUS_OBJECT_TYPE_MISMATCH: isize = 0xC0000024u32 as isize;

    // Validate required parameters
    if thread_handle_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    if client_id_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Read CLIENT_ID structure
    // CLIENT_ID is { HANDLE UniqueProcess; HANDLE UniqueThread; }
    // On x64, HANDLEs are 64-bit
    let (pid, tid) = unsafe {
        let client_id = client_id_ptr as *const ClientIdForThread;
        ((*client_id).unique_process as u32, (*client_id).unique_thread as u32)
    };

    crate::serial_println!("[SYSCALL] NtOpenThread(pid={}, tid={}, access={:#x})",
        pid, tid, desired_access);

    // Thread ID must be specified
    if tid == 0 {
        crate::serial_println!("[SYSCALL] NtOpenThread: thread ID is zero");
        return STATUS_INVALID_CID;
    }

    // Look up the thread
    let thread = unsafe { crate::ps::cid::ps_lookup_thread_by_id(tid) };

    if thread.is_null() {
        crate::serial_println!("[SYSCALL] NtOpenThread: thread {} not found", tid);
        return STATUS_INVALID_CID;
    }

    // If process ID is specified (non-zero), verify the thread belongs to that process
    if pid != 0 {
        unsafe {
            let ethread = thread as *mut crate::ps::EThread;
            if (*ethread).cid.unique_process != pid {
                crate::serial_println!(
                    "[SYSCALL] NtOpenThread: thread {} belongs to process {}, not {}",
                    tid, (*ethread).cid.unique_process, pid
                );
                return STATUS_INVALID_CID;
            }
        }
    }

    // Check if thread is terminated
    unsafe {
        let ethread = thread as *mut crate::ps::EThread;
        if (*ethread).is_terminating() {
            crate::serial_println!("[SYSCALL] NtOpenThread: thread {} is terminated", tid);
            // Still allow opening terminated threads (for querying exit status)
        }
    }

    // Parse object attributes if provided
    let _inherit_handle = if object_attributes != 0 {
        unsafe {
            // OBJECT_ATTRIBUTES.Attributes is at offset 8 (after Length and RootDirectory)
            let attrs = *((object_attributes + 8) as *const u32);
            (attrs & 0x00000002) != 0 // OBJ_INHERIT
        }
    } else {
        false
    };

    // Access check would go here in a full implementation
    // For now, we grant the requested access

    // Validate access mask
    let access = desired_access as u32;
    let valid_access = thread_access::THREAD_ALL_ACCESS |
                       thread_access::DELETE |
                       thread_access::READ_CONTROL |
                       thread_access::WRITE_DAC |
                       thread_access::WRITE_OWNER |
                       thread_access::SYNCHRONIZE;

    if (access & !valid_access) != 0 {
        crate::serial_println!("[SYSCALL] NtOpenThread: invalid access mask {:#x}", access);
        // Don't fail - just mask to valid bits for compatibility
    }

    // Allocate handle
    let handle = unsafe { alloc_thread_handle(tid) };
    match handle {
        Some(h) => {
            unsafe { *(thread_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtOpenThread(tid={}) -> handle {:#x}", tid, h);
            STATUS_SUCCESS
        }
        None => {
            crate::serial_println!("[SYSCALL] NtOpenThread: failed to allocate handle");
            STATUS_INSUFFICIENT_RESOURCES
        }
    }
}

/// Thread information class constants for query operations
#[allow(non_snake_case, non_upper_case_globals)]
pub mod thread_info_class {
    /// Basic thread information (exit status, TEB, client ID, priority)
    pub const ThreadBasicInformation: u32 = 0;
    /// Thread times (creation, exit, kernel, user)
    pub const ThreadTimes: u32 = 1;
    /// Thread priority (KPRIORITY)
    pub const ThreadPriority: u32 = 2;
    /// Thread base priority
    pub const ThreadBasePriority: u32 = 3;
    /// Thread affinity mask
    pub const ThreadAffinityMask: u32 = 4;
    /// Thread impersonation token
    pub const ThreadImpersonationToken: u32 = 5;
    /// Thread descriptor table info
    pub const ThreadDescriptorTableEntry: u32 = 6;
    /// Enable alignment fault fixup
    pub const ThreadEnableAlignmentFaultFixup: u32 = 7;
    /// Event pair client (obsolete)
    pub const ThreadEventPair_Reusable: u32 = 8;
    /// Win32 start address
    pub const ThreadQuerySetWin32StartAddress: u32 = 9;
    /// Zero TLS cell
    pub const ThreadZeroTlsCell: u32 = 10;
    /// Performance counter
    pub const ThreadPerformanceCount: u32 = 11;
    /// Is in a terminated state
    pub const ThreadAmILastThread: u32 = 12;
    /// Thread ideal processor
    pub const ThreadIdealProcessor: u32 = 13;
    /// Thread priority boost
    pub const ThreadPriorityBoost: u32 = 14;
    /// Set TLS array address
    pub const ThreadSetTlsArrayAddress: u32 = 15;
    /// Is I/O pending
    pub const ThreadIsIoPending: u32 = 16;
    /// Hide from debugger
    pub const ThreadHideFromDebugger: u32 = 17;
    /// Break on termination
    pub const ThreadBreakOnTermination: u32 = 18;
    /// Switch legacy state
    pub const ThreadSwitchLegacyState: u32 = 19;
    /// Is terminated
    pub const ThreadIsTerminated: u32 = 20;
    /// Last system call
    pub const ThreadLastSystemCall: u32 = 21;
    /// I/O priority
    pub const ThreadIoPriority: u32 = 22;
    /// Cycle time
    pub const ThreadCycleTime: u32 = 23;
    /// Page priority
    pub const ThreadPagePriority: u32 = 24;
    /// Actual base priority
    pub const ThreadActualBasePriority: u32 = 25;
    /// TEB information
    pub const ThreadTebInformation: u32 = 26;
    /// CSR API message
    pub const ThreadCSwitchMon: u32 = 27;
    /// CSR message process
    pub const ThreadCSwitchPmu: u32 = 28;
    /// WOW64 context
    pub const ThreadWow64Context: u32 = 29;
    /// Group information
    pub const ThreadGroupInformation: u32 = 30;
    /// UMS information
    pub const ThreadUmsInformation: u32 = 31;
    /// Counter profiling
    pub const ThreadCounterProfiling: u32 = 32;
    /// Ideal processor extended
    pub const ThreadIdealProcessorEx: u32 = 33;
    /// Suspend count
    pub const ThreadSuspendCount: u32 = 35;

    // Legacy names for compatibility
    pub const THREAD_BASIC_INFORMATION: u32 = 0;
    pub const THREAD_TIMES: u32 = 1;
    pub const THREAD_PRIORITY: u32 = 2;
    pub const THREAD_BASE_PRIORITY: u32 = 3;
    pub const THREAD_AFFINITY_MASK: u32 = 4;
    pub const THREAD_IMPERSONATION_TOKEN: u32 = 5;
    pub const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;
    pub const THREAD_IS_TERMINATED: u32 = 20;
}

/// THREAD_BASIC_INFORMATION structure (class 0)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadBasicInformation {
    /// Thread exit status (STATUS_PENDING if running)
    pub exit_status: i32,
    /// Pointer to Thread Environment Block
    pub teb_base_address: u64,
    /// Process ID
    pub client_id_process: u32,
    /// Thread ID
    pub client_id_thread: u32,
    /// CPU affinity mask
    pub affinity_mask: u64,
    /// Current scheduling priority
    pub priority: i32,
    /// Base scheduling priority
    pub base_priority: i32,
}

/// KERNEL_USER_TIMES structure (class 1)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelUserTimes {
    /// Creation time (100-nanosecond intervals since 1601)
    pub create_time: i64,
    /// Exit time (0 if still running)
    pub exit_time: i64,
    /// Time spent in kernel mode
    pub kernel_time: i64,
    /// Time spent in user mode
    pub user_time: i64,
}

/// Thread performance counter structure (class 11)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadPerformanceCounter {
    /// Performance counter value
    pub performance_count: i64,
}

/// Thread cycle time information (class 23)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadCycleTimeInformation {
    /// Accumulated cycle time
    pub accumulated_cycles: u64,
    /// Current cycle count
    pub current_cycle_count: u64,
}

/// Thread last system call information (class 21)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadLastSystemCall {
    /// First argument of last system call
    pub first_argument: u64,
    /// System call number
    pub system_call_number: u16,
    /// Padding
    pub _padding: u16,
    /// Reserved
    pub _reserved: u32,
}

/// Thread TEB information (class 26)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadTebInformation {
    /// TEB base address
    pub teb_base: u64,
    /// TEB offset
    pub teb_offset: u32,
    /// Bytes to read
    pub bytes_to_read: u32,
}

/// Thread group information (class 30)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadGroupInformation {
    /// Processor group
    pub group: u16,
    /// Reserved
    pub _reserved: [u16; 3],
}

/// NtQueryInformationThread - Query thread information
///
/// Retrieves information about a thread based on the specified information class.
///
/// # Arguments
/// * `thread_handle` - Handle to the thread (0xFFFFFFFE = current thread)
/// * `thread_information_class` - Type of information to query
/// * `thread_information` - Buffer to receive the information
/// * `thread_information_length` - Size of the buffer
/// * `return_length` - Optional pointer to receive actual size needed
fn sys_query_information_thread(
    thread_handle: usize,
    thread_information_class: usize,
    thread_information: usize,
    thread_information_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;
    const STATUS_INFO_LENGTH_MISMATCH: isize = 0xC0000004u32 as isize;
    const STATUS_BUFFER_TOO_SMALL: isize = 0xC0000023u32 as isize;
    const STATUS_INVALID_INFO_CLASS: isize = 0xC0000003u32 as isize;
    const STATUS_PENDING: i32 = 0x103;

    // Validate buffer pointer
    if thread_information == 0 {
        return STATUS_INVALID_HANDLE;
    }

    // Get thread ID from handle
    // Special handle -2 (0xFFFFFFFE) means current thread
    let tid = if thread_handle == usize::MAX - 1 || thread_handle == 0xFFFFFFFE {
        unsafe {
            let prcb = crate::ke::prcb::get_current_prcb();
            if !prcb.current_thread.is_null() {
                (*prcb.current_thread).thread_id
            } else {
                return STATUS_INVALID_HANDLE;
            }
        }
    } else if thread_handle == 0 {
        return STATUS_INVALID_HANDLE;
    } else {
        match unsafe { get_thread_id(thread_handle) } {
            Some(t) => t,
            None => return STATUS_INVALID_HANDLE,
        }
    };

    // Look up thread structure
    let thread = unsafe { crate::ps::cid::ps_lookup_thread_by_id(tid) };
    let ethread = thread as *mut crate::ps::EThread;

    crate::serial_println!("[SYSCALL] NtQueryInformationThread(tid={}, class={})",
        tid, thread_information_class);

    match thread_information_class as u32 {
        // Class 0: ThreadBasicInformation
        thread_info_class::ThreadBasicInformation => {
            let required = core::mem::size_of::<ThreadBasicInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = thread_information as *mut ThreadBasicInformation;
                if !ethread.is_null() {
                    let t = &*ethread;
                    (*info).exit_status = if t.is_terminating() { t.exit_status } else { STATUS_PENDING };
                    (*info).teb_base_address = t.teb as u64;
                    (*info).client_id_process = t.cid.unique_process;
                    (*info).client_id_thread = t.cid.unique_thread;
                    (*info).affinity_mask = 1; // Single processor for now
                    (*info).priority = (*t.get_tcb()).priority as i32;
                    (*info).base_priority = (*t.get_tcb()).base_priority as i32;
                } else {
                    (*info).exit_status = STATUS_PENDING;
                    (*info).teb_base_address = 0;
                    (*info).client_id_process = 0;
                    (*info).client_id_thread = tid;
                    (*info).affinity_mask = 1;
                    (*info).priority = 8;
                    (*info).base_priority = 8;
                }
            }

            STATUS_SUCCESS
        }

        // Class 1: ThreadTimes
        thread_info_class::ThreadTimes => {
            let required = core::mem::size_of::<KernelUserTimes>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = thread_information as *mut KernelUserTimes;
                if !ethread.is_null() {
                    let t = &*ethread;
                    // Convert ticks to 100-nanosecond intervals
                    // 1 tick = 1ms = 10000 * 100ns
                    (*info).create_time = (t.create_time as i64) * 10000;
                    (*info).exit_time = if t.exit_time > 0 { (t.exit_time as i64) * 10000 } else { 0 };
                    // Use tracked kernel/user time from EThread
                    (*info).kernel_time = t.kernel_time as i64;
                    (*info).user_time = t.user_time as i64;
                } else {
                    (*info).create_time = 0;
                    (*info).exit_time = 0;
                    (*info).kernel_time = 0;
                    (*info).user_time = 0;
                }
            }

            STATUS_SUCCESS
        }

        // Class 2: ThreadPriority
        thread_info_class::ThreadPriority => {
            let required = 4usize; // KPRIORITY is i32

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let priority = if !ethread.is_null() {
                    (*(*ethread).get_tcb()).priority as i32
                } else {
                    8 // Normal priority
                };
                *(thread_information as *mut i32) = priority;
            }

            STATUS_SUCCESS
        }

        // Class 3: ThreadBasePriority
        thread_info_class::ThreadBasePriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let base_priority = if !ethread.is_null() {
                    (*(*ethread).get_tcb()).base_priority as i32
                } else {
                    8
                };
                *(thread_information as *mut i32) = base_priority;
            }

            STATUS_SUCCESS
        }

        // Class 4: ThreadAffinityMask
        thread_info_class::ThreadAffinityMask => {
            let required = 8usize; // KAFFINITY is u64 on x64

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let affinity = if !ethread.is_null() {
                    (*ethread).tcb.affinity
                } else {
                    1 // Default to processor 0
                };
                *(thread_information as *mut u64) = affinity;
            }

            STATUS_SUCCESS
        }

        // Class 9: ThreadQuerySetWin32StartAddress
        thread_info_class::ThreadQuerySetWin32StartAddress => {
            let required = 8usize; // Pointer size

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let start_addr = if !ethread.is_null() {
                    (*ethread).win32_start_address as u64
                } else {
                    0
                };
                *(thread_information as *mut u64) = start_addr;
            }

            STATUS_SUCCESS
        }

        // Class 11: ThreadPerformanceCount
        thread_info_class::ThreadPerformanceCount => {
            let required = core::mem::size_of::<ThreadPerformanceCounter>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = thread_information as *mut ThreadPerformanceCounter;
                // Read TSC for performance counter
                let tsc: u64;
                core::arch::asm!("rdtsc", "shl rdx, 32", "or rax, rdx", out("rax") tsc, out("rdx") _);
                (*info).performance_count = tsc as i64;
            }

            STATUS_SUCCESS
        }

        // Class 12: ThreadAmILastThread
        thread_info_class::ThreadAmILastThread => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Check if this is the last thread in the process
                let is_last = if !ethread.is_null() {
                    let process = (*ethread).thread_process;
                    if !process.is_null() {
                        (*process).thread_count() <= 1
                    } else {
                        true
                    }
                } else {
                    false
                };
                *(thread_information as *mut u32) = if is_last { 1 } else { 0 };
            }

            STATUS_SUCCESS
        }

        // Class 13: ThreadIdealProcessor
        thread_info_class::ThreadIdealProcessor => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let ideal_processor = if !ethread.is_null() {
                    (*ethread).ideal_processor as u32
                } else {
                    0 // Processor 0
                };
                *(thread_information as *mut u32) = ideal_processor;
            }

            STATUS_SUCCESS
        }

        // Class 14: ThreadPriorityBoost
        thread_info_class::ThreadPriorityBoost => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                // Returns TRUE if priority boost is disabled
                let disabled = if !ethread.is_null() {
                    (*ethread).priority_boost_disabled
                } else {
                    false
                };
                *(thread_information as *mut u32) = if disabled { 1 } else { 0 };
            }

            STATUS_SUCCESS
        }

        // Class 16: ThreadIsIoPending
        thread_info_class::ThreadIsIoPending => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let has_pending_io = if !ethread.is_null() {
                    use core::sync::atomic::Ordering;
                    (*ethread).pending_irp_count.load(Ordering::Relaxed) > 0
                } else {
                    false
                };
                *(thread_information as *mut u32) = if has_pending_io { 1 } else { 0 };
            }

            STATUS_SUCCESS
        }

        // Class 17: ThreadHideFromDebugger
        thread_info_class::ThreadHideFromDebugger => {
            let required = 1usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let hidden = if !ethread.is_null() {
                    (*ethread).hide_from_debugger
                } else {
                    false
                };
                *(thread_information as *mut u8) = if hidden { 1 } else { 0 };
            }

            STATUS_SUCCESS
        }

        // Class 18: ThreadBreakOnTermination
        thread_info_class::ThreadBreakOnTermination => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let break_on_term = if !ethread.is_null() {
                    (*ethread).break_on_termination
                } else {
                    false
                };
                *(thread_information as *mut u32) = if break_on_term { 1 } else { 0 };
            }

            STATUS_SUCCESS
        }

        // Class 20: ThreadIsTerminated
        thread_info_class::ThreadIsTerminated => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let is_terminated = if !ethread.is_null() {
                    (*ethread).is_terminating()
                } else {
                    true // If we can't find the thread, assume terminated
                };
                *(thread_information as *mut u32) = if is_terminated { 1 } else { 0 };
            }

            STATUS_SUCCESS
        }

        // Class 22: ThreadIoPriority
        thread_info_class::ThreadIoPriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let io_priority = if !ethread.is_null() {
                    (*ethread).io_priority as u32
                } else {
                    2 // IoPriorityNormal
                };
                *(thread_information as *mut u32) = io_priority;
            }

            STATUS_SUCCESS
        }

        // Class 23: ThreadCycleTime
        thread_info_class::ThreadCycleTime => {
            let required = core::mem::size_of::<ThreadCycleTimeInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = thread_information as *mut ThreadCycleTimeInformation;
                if !ethread.is_null() {
                    // Use thread's tracked cycle time
                    (*info).accumulated_cycles = (*ethread).cycle_time;
                    // Current cycle count - read TSC for current value
                    let tsc: u64;
                    core::arch::asm!("rdtsc", "shl rdx, 32", "or rax, rdx", out("rax") tsc, out("rdx") _);
                    (*info).current_cycle_count = tsc;
                } else {
                    (*info).accumulated_cycles = 0;
                    (*info).current_cycle_count = 0;
                }
            }

            STATUS_SUCCESS
        }

        // Class 24: ThreadPagePriority
        thread_info_class::ThreadPagePriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let page_priority = if !ethread.is_null() {
                    (*ethread).page_priority as u32
                } else {
                    5 // Normal
                };
                *(thread_information as *mut u32) = page_priority;
            }

            STATUS_SUCCESS
        }

        // Class 25: ThreadActualBasePriority
        thread_info_class::ThreadActualBasePriority => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let base_priority = if !ethread.is_null() {
                    (*(*ethread).get_tcb()).base_priority as i32
                } else {
                    8
                };
                *(thread_information as *mut i32) = base_priority;
            }

            STATUS_SUCCESS
        }

        // Class 26: ThreadTebInformation
        thread_info_class::ThreadTebInformation => {
            let required = core::mem::size_of::<ThreadTebInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = thread_information as *mut ThreadTebInformation;
                if !ethread.is_null() {
                    (*info).teb_base = (*ethread).teb as u64;
                } else {
                    (*info).teb_base = 0;
                }
                (*info).teb_offset = 0;
                (*info).bytes_to_read = 0;
            }

            STATUS_SUCCESS
        }

        // Class 30: ThreadGroupInformation
        thread_info_class::ThreadGroupInformation => {
            let required = core::mem::size_of::<ThreadGroupInformation>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let info = thread_information as *mut ThreadGroupInformation;
                (*info).group = 0; // Group 0 (single group system)
                (*info)._reserved = [0; 3];
            }

            STATUS_SUCCESS
        }

        // Class 35: ThreadSuspendCount
        thread_info_class::ThreadSuspendCount => {
            let required = 4usize;

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if thread_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            unsafe {
                let suspend_count = if !ethread.is_null() {
                    (*ethread).suspend_count as u32
                } else {
                    0
                };
                *(thread_information as *mut u32) = suspend_count;
            }

            STATUS_SUCCESS
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtQueryInformationThread: unsupported class {}",
                thread_information_class);
            STATUS_INVALID_INFO_CLASS
        }
    }
}

/// NtSuspendThread - Suspend a thread
fn sys_suspend_thread(
    thread_handle: usize,
    previous_suspend_count: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    let tid = match unsafe { get_thread_id(thread_handle) } {
        Some(t) => t,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtSuspendThread(tid={})", tid);

    // Look up the thread by ID
    let thread_ptr = unsafe { crate::ps::cid::ps_lookup_thread_by_id(tid) };
    if thread_ptr.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    // Get KTHREAD from ETHREAD and suspend it
    let prev_count = unsafe {
        let ethread = thread_ptr as *mut crate::ps::EThread;
        let kthread = (*ethread).get_tcb_mut();
        (*kthread).suspend()
    };

    if previous_suspend_count != 0 {
        unsafe { *(previous_suspend_count as *mut u32) = prev_count as u32; }
    }

    crate::serial_println!("[SYSCALL] NtSuspendThread: prev_count={}", prev_count);

    0
}

/// NtResumeThread - Resume a thread
fn sys_resume_thread(
    thread_handle: usize,
    previous_suspend_count: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    let tid = match unsafe { get_thread_id(thread_handle) } {
        Some(t) => t,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtResumeThread(tid={})", tid);

    // Look up the thread by ID
    let thread_ptr = unsafe { crate::ps::cid::ps_lookup_thread_by_id(tid) };
    if thread_ptr.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    // Get KTHREAD from ETHREAD and resume it
    let prev_count = unsafe {
        let ethread = thread_ptr as *mut crate::ps::EThread;
        let kthread = (*ethread).get_tcb_mut();
        (*kthread).resume()
    };

    if previous_suspend_count != 0 {
        unsafe { *(previous_suspend_count as *mut u32) = prev_count as u32; }
    }

    crate::serial_println!("[SYSCALL] NtResumeThread: prev_count={}", prev_count);

    0
}

// ============================================================================
// Token Syscalls
// ============================================================================

/// Token access rights
pub mod token_access {
    pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
    pub const TOKEN_DUPLICATE: u32 = 0x0002;
    pub const TOKEN_IMPERSONATE: u32 = 0x0004;
    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TOKEN_QUERY_SOURCE: u32 = 0x0010;
    pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
    pub const TOKEN_ADJUST_GROUPS: u32 = 0x0040;
    pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
    pub const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;
    pub const TOKEN_ALL_ACCESS: u32 = 0xF01FF;
}

/// Simple token ID counter
static mut NEXT_TOKEN_ID: u32 = 1;

/// NtOpenProcessToken - Open a process's token
fn sys_open_process_token(
    process_handle: usize,
    desired_access: usize,
    token_handle_ptr: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    if token_handle_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Get process ID (or use current if -1)
    let pid = if process_handle == usize::MAX {
        4 // System process
    } else {
        match unsafe { get_process_id(process_handle) } {
            Some(p) => p,
            None => return STATUS_INVALID_HANDLE,
        }
    };

    crate::serial_println!("[SYSCALL] NtOpenProcessToken(pid={}, access={:#x})",
        pid, desired_access);

    // Create a token handle
    // In a real implementation, we'd look up the process's token
    let token_id = unsafe {
        let id = NEXT_TOKEN_ID;
        NEXT_TOKEN_ID += 1;
        id
    };

    let handle = unsafe { alloc_token_handle(token_id) };
    match handle {
        Some(h) => {
            unsafe { *(token_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtOpenProcessToken -> handle {:#x}", h);
            STATUS_SUCCESS
        }
        None => STATUS_INSUFFICIENT_RESOURCES,
    }
}

/// NtOpenThreadToken - Open a thread's impersonation token
fn sys_open_thread_token(
    thread_handle: usize,
    desired_access: usize,
    open_as_self: usize,
    token_handle_ptr: usize,
    _: usize, _: usize,
) -> isize {
    if token_handle_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = open_as_self;

    let tid = if thread_handle == usize::MAX - 1 {
        0 // Current thread
    } else {
        match unsafe { get_thread_id(thread_handle) } {
            Some(t) => t,
            None => return STATUS_INVALID_HANDLE,
        }
    };

    crate::serial_println!("[SYSCALL] NtOpenThreadToken(tid={}, access={:#x})",
        tid, desired_access);

    // Threads may not have an impersonation token
    // Return STATUS_NO_TOKEN if not impersonating
    0xC000007C_u32 as isize // STATUS_NO_TOKEN
}

/// Token information class
pub mod token_info_class {
    pub const TOKEN_USER: u32 = 1;
    pub const TOKEN_GROUPS: u32 = 2;
    pub const TOKEN_PRIVILEGES: u32 = 3;
    pub const TOKEN_OWNER: u32 = 4;
    pub const TOKEN_PRIMARY_GROUP: u32 = 5;
    pub const TOKEN_DEFAULT_DACL: u32 = 6;
    pub const TOKEN_SOURCE: u32 = 7;
    pub const TOKEN_TYPE: u32 = 8;
    pub const TOKEN_IMPERSONATION_LEVEL: u32 = 9;
    pub const TOKEN_STATISTICS: u32 = 10;
    pub const TOKEN_SESSION_ID: u32 = 12;
    pub const TOKEN_ELEVATION: u32 = 20;
    pub const TOKEN_ELEVATION_TYPE: u32 = 18;
}

/// TOKEN_STATISTICS structure
#[repr(C)]
pub struct TokenStatistics {
    pub token_id: u64,
    pub authentication_id: u64,
    pub expiration_time: i64,
    pub token_type: u32,
    pub impersonation_level: u32,
    pub dynamic_charged: u32,
    pub dynamic_available: u32,
    pub group_count: u32,
    pub privilege_count: u32,
    pub modified_id: u64,
}

/// NtQueryInformationToken - Query token information
fn sys_query_information_token(
    token_handle: usize,
    token_information_class: usize,
    token_information: usize,
    token_information_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    const STATUS_INVALID_INFO_CLASS: isize = 0xC0000003u32 as isize;

    if token_handle == 0 || token_information == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let token_id = match unsafe { get_token_id(token_handle) } {
        Some(t) => t,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtQueryInformationToken(token={}, class={})",
        token_id, token_information_class);

    match token_information_class as u32 {
        token_info_class::TOKEN_STATISTICS => {
            let required = core::mem::size_of::<TokenStatistics>();

            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = required; }
            }

            if token_information_length < required {
                return 0x80000005u32 as isize;
            }

            unsafe {
                let stats = token_information as *mut TokenStatistics;
                if let Some(token) = get_token_ptr(token_handle) {
                    (*stats).token_id = (*token).token_id.low_part as u64;
                    (*stats).authentication_id = (*token).authentication_id.low_part as u64
                        | (((*token).authentication_id.high_part as u64) << 32);
                    (*stats).expiration_time = (*token).expiration_time as i64;
                    (*stats).token_type = (*token).token_type as u32;
                    (*stats).impersonation_level = (*token).impersonation_level as u32;
                    (*stats).dynamic_charged = 4096;
                    (*stats).dynamic_available = 4096;
                    (*stats).group_count = (*token).group_count as u32;
                    (*stats).privilege_count = (*token).privileges.privilege_count;
                    (*stats).modified_id = token_id as u64;
                } else {
                    // Fallback to defaults
                    (*stats).token_id = token_id as u64;
                    (*stats).authentication_id = 0x3E7; // SYSTEM_LUID
                    (*stats).expiration_time = i64::MAX;
                    (*stats).token_type = 1; // TokenPrimary
                    (*stats).impersonation_level = 0;
                    (*stats).dynamic_charged = 4096;
                    (*stats).dynamic_available = 4096;
                    (*stats).group_count = 1;
                    (*stats).privilege_count = 5;
                    (*stats).modified_id = token_id as u64;
                }
            }

            0
        }
        token_info_class::TOKEN_TYPE => {
            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = 4; }
            }

            if token_information_length < 4 {
                return 0x80000005u32 as isize;
            }

            // Return TokenPrimary (1) or TokenImpersonation (2)
            unsafe {
                let token_type = if let Some(token) = get_token_ptr(token_handle) {
                    (*token).token_type as u32
                } else {
                    1 // Default to Primary
                };
                *(token_information as *mut u32) = token_type;
            }

            0
        }
        token_info_class::TOKEN_ELEVATION => {
            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = 4; }
            }

            if token_information_length < 4 {
                return 0x80000005u32 as isize;
            }

            // Return elevated status from token
            unsafe {
                let is_elevated = if let Some(token) = get_token_ptr(token_handle) {
                    if (*token).is_elevated { 1u32 } else { 0u32 }
                } else {
                    1 // Default to elevated
                };
                *(token_information as *mut u32) = is_elevated;
            }

            0
        }
        token_info_class::TOKEN_SESSION_ID => {
            if return_length != 0 {
                unsafe { *(return_length as *mut usize) = 4; }
            }

            if token_information_length < 4 {
                return 0x80000005u32 as isize;
            }

            unsafe {
                let session_id = if let Some(token) = get_token_ptr(token_handle) {
                    (*token).session_id
                } else {
                    0 // Default to session 0
                };
                *(token_information as *mut u32) = session_id;
            }

            0
        }
        _ => {
            crate::serial_println!("[SYSCALL] NtQueryInformationToken: unsupported class {}",
                token_information_class);
            -1
        }
    }
}

/// NtDuplicateToken - Duplicate a token
fn sys_duplicate_token(
    existing_token_handle: usize,
    desired_access: usize,
    _object_attributes: usize,
    _impersonation_level: usize,
    _token_type: usize,
    new_token_handle_ptr: usize,
) -> isize {
    if new_token_handle_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let token_id = match unsafe { get_token_id(existing_token_handle) } {
        Some(t) => t,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtDuplicateToken(token={}, access={:#x})",
        token_id, desired_access);

    // Create a new token ID
    let new_token_id = unsafe {
        let id = NEXT_TOKEN_ID;
        NEXT_TOKEN_ID += 1;
        id
    };

    let handle = unsafe { alloc_token_handle(new_token_id) };
    match handle {
        Some(h) => {
            unsafe { *(new_token_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtDuplicateToken -> handle {:#x}", h);
            STATUS_SUCCESS
        }
        None => STATUS_INSUFFICIENT_RESOURCES,
    }
}

/// NtAdjustPrivilegesToken - Enable/disable token privileges
fn sys_adjust_privileges_token(
    token_handle: usize,
    disable_all_privileges: usize,
    new_state: usize,
    buffer_length: usize,
    previous_state: usize,
    return_length: usize,
) -> isize {
    let token_id = match unsafe { get_token_id(token_handle) } {
        Some(t) => t,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtAdjustPrivilegesToken(token={}, disable_all={})",
        token_id, disable_all_privileges != 0);

    let _ = new_state;
    let _ = buffer_length;
    let _ = previous_state;

    // Return required length if asked
    if return_length != 0 {
        unsafe { *(return_length as *mut usize) = 0; }
    }

    // For now, always succeed (all privileges are granted)
    0
}

// ============================================================================
// NtSetInformation Syscalls
// ============================================================================

// ============================================================================
// NtSetInformationProcess Types and Structures
// ============================================================================

/// Process information classes for Set operations
#[allow(non_snake_case, non_upper_case_globals)]
pub mod ProcessInfoClassSet {
    /// Basic limit information (working set, priority)
    pub const ProcessBasicInformation: u32 = 0;
    /// Set quota limits
    pub const ProcessQuotaLimits: u32 = 1;
    /// Set I/O counters (usually read-only)
    pub const ProcessIoCounters: u32 = 2;
    /// Set VM counters (usually read-only)
    pub const ProcessVmCounters: u32 = 3;
    /// Set process times (usually read-only)
    pub const ProcessTimes: u32 = 4;
    /// Set base priority for the process
    pub const ProcessBasePriority: u32 = 5;
    /// Raise priority (temporary boost)
    pub const ProcessRaisePriority: u32 = 6;
    /// Set debug port
    pub const ProcessDebugPort: u32 = 7;
    /// Set exception port
    pub const ProcessExceptionPort: u32 = 8;
    /// Set access token
    pub const ProcessAccessToken: u32 = 9;
    /// Set LDT information
    pub const ProcessLdtInformation: u32 = 10;
    /// Set LDT size
    pub const ProcessLdtSize: u32 = 11;
    /// Set default hard error mode
    pub const ProcessDefaultHardErrorMode: u32 = 12;
    /// Set I/O port handlers (VDM)
    pub const ProcessIoPortHandlers: u32 = 13;
    /// Set foreground information
    pub const ProcessForegroundInformation: u32 = 15;
    /// Set process priority class
    pub const ProcessPriorityClass: u32 = 18;
    /// Set Wx86 information
    pub const ProcessWx86Information: u32 = 19;
    /// Set handle count (read-only typically)
    pub const ProcessHandleCount: u32 = 20;
    /// Set affinity mask
    pub const ProcessAffinityMask: u32 = 21;
    /// Set priority boost disable
    pub const ProcessPriorityBoost: u32 = 22;
    /// Set session ID
    pub const ProcessSessionInformation: u32 = 24;
    /// Set DEP policy
    pub const ProcessExecuteFlags: u32 = 34;
    /// Set break on termination flag
    pub const ProcessBreakOnTermination: u32 = 29;
    /// Set I/O priority
    pub const ProcessIoPriority: u32 = 33;
    /// Set page priority
    pub const ProcessPagePriority: u32 = 39;
    /// Set instrumentation callback
    pub const ProcessInstrumentationCallback: u32 = 40;
}

/// PROCESS_PRIORITY_CLASS structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessPriorityClass {
    /// Set to TRUE to enable foreground boost
    pub foreground: u8,
    /// Priority class value
    pub priority_class: u8,
}

/// Priority class values
#[allow(non_snake_case)]
pub mod PriorityClass {
    pub const IDLE_PRIORITY_CLASS: u8 = 1;
    pub const BELOW_NORMAL_PRIORITY_CLASS: u8 = 5;
    pub const NORMAL_PRIORITY_CLASS: u8 = 2;
    pub const ABOVE_NORMAL_PRIORITY_CLASS: u8 = 3;
    pub const HIGH_PRIORITY_CLASS: u8 = 4;
    pub const REALTIME_PRIORITY_CLASS: u8 = 6;
}

/// Base priority for each priority class
fn priority_class_to_base_priority(class: u8) -> i8 {
    match class {
        PriorityClass::IDLE_PRIORITY_CLASS => 4,
        PriorityClass::BELOW_NORMAL_PRIORITY_CLASS => 6,
        PriorityClass::NORMAL_PRIORITY_CLASS => 8,
        PriorityClass::ABOVE_NORMAL_PRIORITY_CLASS => 10,
        PriorityClass::HIGH_PRIORITY_CLASS => 13,
        PriorityClass::REALTIME_PRIORITY_CLASS => 24,
        _ => 8, // Default to normal
    }
}

/// PROCESS_ACCESS_TOKEN structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessAccessToken {
    /// Handle to the token
    pub token: usize,
    /// Thread to impersonate (optional)
    pub thread: usize,
}

/// PROCESS_SESSION_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessSessionInformation {
    /// Session ID
    pub session_id: u32,
}

/// PROCESS_FOREGROUND_BACKGROUND structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessForegroundBackground {
    /// TRUE if foreground
    pub foreground: u8,
}

/// NtSetInformationProcess - Set process attributes
///
/// Parameters:
/// - process_handle: Handle to the process (use -1 for current)
/// - process_information_class: Type of information to set
/// - process_information: Pointer to input data
/// - process_information_length: Size of input data
fn sys_set_information_process(
    process_handle: usize,
    process_information_class: usize,
    process_information: usize,
    process_information_length: usize,
    _: usize, _: usize,
) -> isize {
    use crate::ps::EProcess;
    use core::ptr;

    crate::serial_println!("[SYSCALL] NtSetInformationProcess(handle={:#x}, class={}, buf={:#x}, len={})",
        process_handle, process_information_class, process_information, process_information_length);

    // Get the process
    let process_ptr = if process_handle == 0xFFFFFFFF || process_handle == usize::MAX || process_handle == 0 {
        // Current process - get system process for now
        unsafe { crate::ps::ps_lookup_process_by_id(4) }
    } else {
        // Look up by handle
        match unsafe { get_process_id(process_handle) } {
            Some(pid) => unsafe { crate::ps::ps_lookup_process_by_id(pid) },
            None => return 0xC0000008u32 as isize, // STATUS_INVALID_HANDLE
        }
    };

    if process_ptr.is_null() {
        return 0xC0000008u32 as isize; // STATUS_INVALID_HANDLE
    }

    // Validate buffer
    if process_information == 0 && process_information_length > 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    let process = unsafe { &mut *(process_ptr as *mut EProcess) };
    let info_class = process_information_class as u32;

    match info_class {
        // ProcessBasePriority = 5
        ProcessInfoClassSet::ProcessBasePriority => {
            if process_information_length < core::mem::size_of::<i8>() {
                return 0xC0000004u32 as isize; // STATUS_INFO_LENGTH_MISMATCH
            }

            let base_priority = unsafe { *(process_information as *const i8) };

            // Validate priority range (-15 to 15, or 16-31 for realtime)
            if !(-15..=31).contains(&base_priority) {
                return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
            }

            process.pcb.base_priority = base_priority;
            crate::serial_println!("[SYSCALL] SetInformationProcess: base priority = {}", base_priority);

            0
        }

        // ProcessRaisePriority = 6
        ProcessInfoClassSet::ProcessRaisePriority => {
            if process_information_length < core::mem::size_of::<u32>() {
                return 0xC0000004u32 as isize;
            }

            let increment = unsafe { *(process_information as *const u32) };

            // Temporarily boost priority (doesn't persist)
            let new_priority = (process.pcb.base_priority as i32 + increment as i32).min(15) as i8;
            crate::serial_println!("[SYSCALL] SetInformationProcess: raise priority by {} -> {}",
                increment, new_priority);

            // In a real implementation, this would boost all threads temporarily
            0
        }

        // ProcessExceptionPort = 8
        ProcessInfoClassSet::ProcessExceptionPort => {
            if process_information_length < core::mem::size_of::<usize>() {
                return 0xC0000004u32 as isize;
            }

            let port_handle = unsafe { *(process_information as *const usize) };

            // TODO: Validate port handle and store
            process.exception_port = port_handle as *mut u8;
            crate::serial_println!("[SYSCALL] SetInformationProcess: exception port = {:#x}", port_handle);

            0
        }

        // ProcessAccessToken = 9
        ProcessInfoClassSet::ProcessAccessToken => {
            if process_information_length < core::mem::size_of::<ProcessAccessToken>() {
                return 0xC0000004u32 as isize;
            }

            let token_info = unsafe { ptr::read(process_information as *const ProcessAccessToken) };
            crate::serial_println!("[SYSCALL] SetInformationProcess: access token = {:#x}", token_info.token);

            // Look up the actual token from the handle
            if let Some(token) = unsafe { get_token_ptr(token_info.token) } {
                // Verify it's a primary token (not impersonation)
                unsafe {
                    if (*token).token_type != crate::se::token::TokenType::Primary {
                        crate::serial_println!("[SYSCALL] SetInformationProcess: token is not primary");
                        return 0xC000007Au32 as isize; // STATUS_BAD_TOKEN_TYPE
                    }
                }
                process.token = token;
                crate::serial_println!("[SYSCALL] SetInformationProcess: primary token assigned");
            } else {
                // Allow raw pointer assignment for compatibility
                process.token = token_info.token as *mut crate::se::Token;
            }

            0
        }

        // ProcessDefaultHardErrorMode = 12
        ProcessInfoClassSet::ProcessDefaultHardErrorMode => {
            if process_information_length < core::mem::size_of::<u32>() {
                return 0xC0000004u32 as isize;
            }

            let error_mode = unsafe { *(process_information as *const u32) };
            crate::serial_println!("[SYSCALL] SetInformationProcess: hard error mode = {:#x}", error_mode);

            // Store in process structure
            process.hard_error_mode = error_mode;
            0
        }

        // ProcessPriorityClass = 18
        ProcessInfoClassSet::ProcessPriorityClass => {
            if process_information_length < core::mem::size_of::<ProcessPriorityClass>() {
                return 0xC0000004u32 as isize;
            }

            let priority_info = unsafe { ptr::read(process_information as *const ProcessPriorityClass) };
            let new_base_priority = priority_class_to_base_priority(priority_info.priority_class);

            process.pcb.base_priority = new_base_priority;
            process.priority_class = priority_info.priority_class;
            crate::serial_println!("[SYSCALL] SetInformationProcess: priority class {} (foreground={}) -> base {}",
                priority_info.priority_class, priority_info.foreground, new_base_priority);

            0
        }

        // ProcessAffinityMask = 21
        ProcessInfoClassSet::ProcessAffinityMask => {
            if process_information_length < core::mem::size_of::<u64>() {
                return 0xC0000004u32 as isize;
            }

            let affinity = unsafe { *(process_information as *const u64) };

            // Validate affinity (must have at least one processor)
            if affinity == 0 {
                return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
            }

            process.pcb.affinity = affinity;
            crate::serial_println!("[SYSCALL] SetInformationProcess: affinity mask = {:#x}", affinity);

            // TODO: Update all threads in the process to respect new affinity
            0
        }

        // ProcessPriorityBoost = 22
        ProcessInfoClassSet::ProcessPriorityBoost => {
            if process_information_length < core::mem::size_of::<u32>() {
                return 0xC0000004u32 as isize;
            }

            let disable_boost = unsafe { *(process_information as *const u32) };
            crate::serial_println!("[SYSCALL] SetInformationProcess: priority boost disabled = {}",
                disable_boost != 0);

            process.priority_boost_disabled = disable_boost != 0;
            0
        }

        // ProcessSessionInformation = 24
        ProcessInfoClassSet::ProcessSessionInformation => {
            if process_information_length < core::mem::size_of::<ProcessSessionInformation>() {
                return 0xC0000004u32 as isize;
            }

            let session_info = unsafe { ptr::read(process_information as *const ProcessSessionInformation) };

            process.session_id = session_info.session_id;
            crate::serial_println!("[SYSCALL] SetInformationProcess: session ID = {}", session_info.session_id);

            0
        }

        // ProcessBreakOnTermination = 29
        ProcessInfoClassSet::ProcessBreakOnTermination => {
            if process_information_length < core::mem::size_of::<u32>() {
                return 0xC0000004u32 as isize;
            }

            let break_on_term = unsafe { *(process_information as *const u32) };

            // Set or clear the critical process flag
            use crate::ps::eprocess::process_flags::PS_PROCESS_FLAGS_SYSTEM;
            if break_on_term != 0 {
                process.flags.fetch_or(PS_PROCESS_FLAGS_SYSTEM, core::sync::atomic::Ordering::SeqCst);
            } else {
                process.flags.fetch_and(!PS_PROCESS_FLAGS_SYSTEM, core::sync::atomic::Ordering::SeqCst);
            }

            crate::serial_println!("[SYSCALL] SetInformationProcess: break on termination = {}",
                break_on_term != 0);

            0
        }

        // ProcessExecuteFlags = 34 (DEP settings)
        ProcessInfoClassSet::ProcessExecuteFlags => {
            if process_information_length < core::mem::size_of::<u32>() {
                return 0xC0000004u32 as isize;
            }

            let execute_flags = unsafe { *(process_information as *const u32) };
            crate::serial_println!("[SYSCALL] SetInformationProcess: execute flags (DEP) = {:#x}",
                execute_flags);

            // Store DEP flags in process
            process.execute_flags = execute_flags;
            0
        }

        // ProcessDebugPort = 7
        ProcessInfoClassSet::ProcessDebugPort => {
            if process_information_length < core::mem::size_of::<usize>() {
                return 0xC0000004u32 as isize;
            }

            let debug_port = unsafe { *(process_information as *const usize) };
            process.debug_port = debug_port as *mut u8;
            crate::serial_println!("[SYSCALL] SetInformationProcess: debug port = {:#x}", debug_port);

            0
        }

        // ProcessIoPriority = 33
        ProcessInfoClassSet::ProcessIoPriority => {
            if process_information_length < core::mem::size_of::<u32>() {
                return 0xC0000004u32 as isize;
            }

            let io_priority = unsafe { *(process_information as *const u32) };

            // Validate I/O priority (0=VeryLow, 1=Low, 2=Normal, 3=High, 4=Critical)
            if io_priority > 4 {
                return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
            }

            process.io_priority = io_priority as u8;
            crate::serial_println!("[SYSCALL] SetInformationProcess: I/O priority = {}", io_priority);

            0
        }

        // ProcessPagePriority = 39
        ProcessInfoClassSet::ProcessPagePriority => {
            if process_information_length < core::mem::size_of::<u32>() {
                return 0xC0000004u32 as isize;
            }

            let page_priority = unsafe { *(process_information as *const u32) };

            // Validate page priority (0-7)
            if page_priority > 7 {
                return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
            }

            process.page_priority = page_priority as u8;
            crate::serial_println!("[SYSCALL] SetInformationProcess: page priority = {}", page_priority);

            0
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtSetInformationProcess: unsupported class {}", info_class);
            0xC0000003u32 as isize // STATUS_INVALID_INFO_CLASS
        }
    }
}

/// Thread information classes for Set operations
#[allow(non_snake_case, non_upper_case_globals)]
pub mod set_thread_info_class {
    /// Set thread priority (relative: -15 to +15)
    pub const ThreadPriority: u32 = 1;
    /// Set thread base priority
    pub const ThreadBasePriority: u32 = 3;
    /// Set thread CPU affinity mask
    pub const ThreadAffinityMask: u32 = 4;
    /// Set thread impersonation token
    pub const ThreadImpersonationToken: u32 = 5;
    /// Enable/disable alignment fault fixup
    pub const ThreadEnableAlignmentFaultFixup: u32 = 7;
    /// Set Win32 start address
    pub const ThreadQuerySetWin32StartAddress: u32 = 9;
    /// Zero a specific TLS cell
    pub const ThreadZeroTlsCell: u32 = 10;
    /// Set ideal processor hint
    pub const ThreadIdealProcessor: u32 = 13;
    /// Set/disable priority boost
    pub const ThreadPriorityBoost: u32 = 14;
    /// Set TLS array address
    pub const ThreadSetTlsArrayAddress: u32 = 15;
    /// Hide thread from debugger
    pub const ThreadHideFromDebugger: u32 = 17;
    /// Set break on termination flag (critical thread)
    pub const ThreadBreakOnTermination: u32 = 18;
    /// Switch legacy state
    pub const ThreadSwitchLegacyState: u32 = 19;
    /// Set I/O priority
    pub const ThreadIoPriority: u32 = 22;
    /// Set page priority
    pub const ThreadPagePriority: u32 = 24;
    /// Set actual base priority
    pub const ThreadActualBasePriority: u32 = 25;
    /// Set processor group affinity
    pub const ThreadGroupInformation: u32 = 30;
    /// Set ideal processor (extended)
    pub const ThreadIdealProcessorEx: u32 = 33;
    /// Set power throttling state
    pub const ThreadPowerThrottlingState: u32 = 49;

    // Legacy uppercase names for compatibility
    pub const THREAD_PRIORITY: u32 = 1;
    pub const THREAD_BASE_PRIORITY: u32 = 3;
    pub const THREAD_AFFINITY_MASK: u32 = 4;
    pub const THREAD_IMPERSONATION_TOKEN: u32 = 5;
    pub const THREAD_IDEAL_PROCESSOR: u32 = 13;
    pub const THREAD_ZERO_TLS_CELL: u32 = 10;
    pub const THREAD_BREAK_ON_TERMINATION: u32 = 18;
    pub const THREAD_HIDE_FROM_DEBUGGER: u32 = 17;
}

/// Thread priority boost structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadPriorityBoostInfo {
    /// TRUE to disable priority boost
    pub disable_boost: u32,
}

/// Thread I/O priority hint
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadIoPriorityInfo {
    /// I/O priority level (0-4)
    pub io_priority: u32,
}

/// I/O priority levels
#[allow(non_snake_case, non_upper_case_globals)]
pub mod IoPriority {
    pub const IoPriorityVeryLow: u32 = 0;
    pub const IoPriorityLow: u32 = 1;
    pub const IoPriorityNormal: u32 = 2;
    pub const IoPriorityHigh: u32 = 3;
    pub const IoPriorityCritical: u32 = 4;
}

/// Thread page priority info
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadPagePriorityInfo {
    /// Page priority (0-7, default 5)
    pub page_priority: u32,
}

/// Thread group affinity
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GroupAffinity {
    /// Affinity mask within the group
    pub mask: u64,
    /// Processor group number
    pub group: u16,
    /// Reserved
    pub reserved: [u16; 3],
}

/// Processor number (extended ideal processor)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessorNumber {
    /// Processor group
    pub group: u16,
    /// Processor number within group
    pub number: u8,
    /// Reserved
    pub reserved: u8,
}

/// NtSetInformationThread - Set thread attributes
///
/// Sets information for a thread based on the specified information class.
///
/// # Arguments
/// * `thread_handle` - Handle to the thread (0xFFFFFFFE = current thread)
/// * `thread_information_class` - Type of information to set
/// * `thread_information` - Buffer containing the information
/// * `thread_information_length` - Size of the buffer
fn sys_set_information_thread(
    thread_handle: usize,
    thread_information_class: usize,
    thread_information: usize,
    thread_information_length: usize,
    _: usize, _: usize,
) -> isize {
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;
    const STATUS_INFO_LENGTH_MISMATCH: isize = 0xC0000004u32 as isize;
    const STATUS_INVALID_PARAMETER: isize = 0xC000000Du32 as isize;
    const STATUS_INVALID_INFO_CLASS: isize = 0xC0000003u32 as isize;
    const STATUS_ACCESS_DENIED: isize = 0xC0000022u32 as isize;

    // Get thread ID from handle
    // Special handle -2 (0xFFFFFFFE) means current thread
    let tid = if thread_handle == 0xFFFFFFFE || thread_handle == (usize::MAX - 1) {
        unsafe {
            let prcb = crate::ke::prcb::get_current_prcb();
            if !prcb.current_thread.is_null() {
                (*prcb.current_thread).thread_id
            } else {
                return STATUS_INVALID_HANDLE;
            }
        }
    } else if thread_handle == 0 {
        return STATUS_INVALID_HANDLE;
    } else {
        match unsafe { get_thread_id(thread_handle) } {
            Some(t) => t,
            None => return STATUS_INVALID_HANDLE,
        }
    };

    // Validate buffer
    if thread_information == 0 && thread_information_length > 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Look up thread structure
    let thread = unsafe { crate::ps::cid::ps_lookup_thread_by_id(tid) };
    let ethread = thread as *mut crate::ps::EThread;

    crate::serial_println!("[SYSCALL] NtSetInformationThread(tid={}, class={})",
        tid, thread_information_class);

    match thread_information_class as u32 {
        // Class 1: ThreadPriority (relative priority -15 to +15)
        set_thread_info_class::ThreadPriority => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let priority = unsafe { *(thread_information as *const i32) };

            // Validate priority range (-15 to +15 for relative priority)
            if !(-15..=15).contains(&priority) {
                return STATUS_INVALID_PARAMETER;
            }

            crate::serial_println!("[SYSCALL] SetInformationThread: priority delta = {}", priority);

            // Apply priority delta to thread
            if !ethread.is_null() {
                unsafe {
                    let tcb = (*ethread).get_tcb_mut();
                    let new_priority = ((*tcb).base_priority as i32 + priority)
                        .clamp(0, 31) as i8;
                    (*tcb).priority = new_priority;
                }
            }

            STATUS_SUCCESS
        }

        // Class 3: ThreadBasePriority
        set_thread_info_class::ThreadBasePriority => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let base_priority = unsafe { *(thread_information as *const i32) };

            // Validate base priority range (0-31)
            if !(0..=31).contains(&base_priority) {
                return STATUS_INVALID_PARAMETER;
            }

            crate::serial_println!("[SYSCALL] SetInformationThread: base priority = {}", base_priority);

            if !ethread.is_null() {
                unsafe {
                    let tcb = (*ethread).get_tcb_mut();
                    (*tcb).base_priority = base_priority as i8;
                    // Also update current priority if not boosted
                    if (*tcb).priority < base_priority as i8 {
                        (*tcb).priority = base_priority as i8;
                    }
                }
            }

            STATUS_SUCCESS
        }

        // Class 4: ThreadAffinityMask
        set_thread_info_class::ThreadAffinityMask => {
            if thread_information_length < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let affinity = unsafe { *(thread_information as *const u64) };

            // Affinity must have at least one bit set
            if affinity == 0 {
                return STATUS_INVALID_PARAMETER;
            }

            crate::serial_println!("[SYSCALL] SetInformationThread: affinity = {:#x}", affinity);

            // For now, we only support single processor, so any affinity with bit 0 is valid
            if (affinity & 1) == 0 {
                return STATUS_INVALID_PARAMETER;
            }

            // Store affinity mask in thread structure
            if !ethread.is_null() {
                unsafe { (*ethread).tcb.affinity = affinity; }
            }

            STATUS_SUCCESS
        }

        // Class 5: ThreadImpersonationToken
        set_thread_info_class::ThreadImpersonationToken => {
            if thread_information_length < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let token_handle = unsafe { *(thread_information as *const usize) };

            crate::serial_println!("[SYSCALL] SetInformationThread: impersonation token = {:#x}",
                token_handle);

            if !ethread.is_null() {
                unsafe {
                    if token_handle == 0 {
                        // Clear impersonation
                        (*ethread).impersonation_info = core::ptr::null_mut();
                        (*ethread).clear_flag(crate::ps::ethread::thread_flags::PS_THREAD_FLAGS_IMPERSONATING);
                    } else {
                        // Look up token from handle and set impersonation
                        if let Some(token) = get_token_ptr(token_handle) {
                            (*ethread).impersonation_info = token as *mut u8;
                            (*ethread).set_flag(crate::ps::ethread::thread_flags::PS_THREAD_FLAGS_IMPERSONATING);
                            // Also set in KThread for kernel-level impersonation checks
                            (*ethread).tcb.impersonation_token = token as *mut u8;
                            (*ethread).tcb.impersonating = true;
                        } else {
                            // Invalid token handle - still set to allow pseudo-impersonation
                            (*ethread).impersonation_info = token_handle as *mut u8;
                            (*ethread).set_flag(crate::ps::ethread::thread_flags::PS_THREAD_FLAGS_IMPERSONATING);
                        }
                    }
                }
            }

            STATUS_SUCCESS
        }

        // Class 7: ThreadEnableAlignmentFaultFixup
        set_thread_info_class::ThreadEnableAlignmentFaultFixup => {
            if thread_information_length < 1 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let enable = unsafe { *(thread_information as *const u8) };

            crate::serial_println!("[SYSCALL] SetInformationThread: alignment fault fixup = {}",
                enable != 0);

            // Store alignment fault fixup flag in thread structure
            if !ethread.is_null() {
                unsafe { (*ethread).alignment_fault_fixup = enable != 0; }
            }

            STATUS_SUCCESS
        }

        // Class 9: ThreadQuerySetWin32StartAddress
        set_thread_info_class::ThreadQuerySetWin32StartAddress => {
            if thread_information_length < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let start_address = unsafe { *(thread_information as *const u64) };

            crate::serial_println!("[SYSCALL] SetInformationThread: Win32 start address = {:#x}",
                start_address);

            if !ethread.is_null() {
                unsafe {
                    (*ethread).win32_start_address = start_address as *mut u8;
                }
            }

            STATUS_SUCCESS
        }

        // Class 10: ThreadZeroTlsCell
        set_thread_info_class::ThreadZeroTlsCell => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let tls_index = unsafe { *(thread_information as *const u32) };

            crate::serial_println!("[SYSCALL] SetInformationThread: zero TLS cell {}", tls_index);

            // TODO: Zero the specified TLS slot in the thread's TEB
            // This requires access to the TEB structure

            STATUS_SUCCESS
        }

        // Class 13: ThreadIdealProcessor
        set_thread_info_class::ThreadIdealProcessor => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let ideal_proc = unsafe { *(thread_information as *const u32) };

            crate::serial_println!("[SYSCALL] SetInformationThread: ideal processor = {}", ideal_proc);

            // For single processor system, only processor 0 is valid
            // Special value MAXIMUM_PROCESSORS (0xFF) means no preference
            if ideal_proc != 0 && ideal_proc != 0xFF {
                // We only have one processor, but accept the request
                crate::serial_println!("[SYSCALL] Warning: ideal processor {} not available", ideal_proc);
            }

            // Store ideal processor hint in thread structure
            if !ethread.is_null() {
                unsafe { (*ethread).ideal_processor = ideal_proc as u8; }
            }

            STATUS_SUCCESS
        }

        // Class 14: ThreadPriorityBoost
        set_thread_info_class::ThreadPriorityBoost => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let disable_boost = unsafe { *(thread_information as *const u32) };

            crate::serial_println!("[SYSCALL] SetInformationThread: priority boost disabled = {}",
                disable_boost != 0);

            // Store priority boost disable flag in thread
            if !ethread.is_null() {
                unsafe { (*ethread).priority_boost_disabled = disable_boost != 0; }
            }

            STATUS_SUCCESS
        }

        // Class 15: ThreadSetTlsArrayAddress
        set_thread_info_class::ThreadSetTlsArrayAddress => {
            if thread_information_length < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let tls_array = unsafe { *(thread_information as *const u64) };

            crate::serial_println!("[SYSCALL] SetInformationThread: TLS array address = {:#x}",
                tls_array);

            // TODO: Set TLS expansion slots array address in TEB

            STATUS_SUCCESS
        }

        // Class 17: ThreadHideFromDebugger
        set_thread_info_class::ThreadHideFromDebugger => {
            // This class takes no input data - just sets a flag
            crate::serial_println!("[SYSCALL] SetInformationThread: hide from debugger");

            // Set hidden from debugger flag
            if !ethread.is_null() {
                unsafe { (*ethread).hide_from_debugger = true; }
            }

            STATUS_SUCCESS
        }

        // Class 18: ThreadBreakOnTermination
        set_thread_info_class::ThreadBreakOnTermination => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let break_on_term = unsafe { *(thread_information as *const u32) };

            crate::serial_println!("[SYSCALL] SetInformationThread: break on termination = {}",
                break_on_term != 0);

            // Setting this requires SeDebugPrivilege in real NT
            // For now, we allow it

            // Store critical thread flag
            if !ethread.is_null() {
                unsafe { (*ethread).break_on_termination = break_on_term != 0; }
            }

            STATUS_SUCCESS
        }

        // Class 19: ThreadSwitchLegacyState
        set_thread_info_class::ThreadSwitchLegacyState => {
            crate::serial_println!("[SYSCALL] SetInformationThread: switch legacy state");

            // This is used for x87 FPU state management
            // Not critical for basic functionality

            STATUS_SUCCESS
        }

        // Class 22: ThreadIoPriority
        set_thread_info_class::ThreadIoPriority => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let io_priority = unsafe { *(thread_information as *const u32) };

            // Validate I/O priority (0-4)
            if io_priority > IoPriority::IoPriorityCritical {
                return STATUS_INVALID_PARAMETER;
            }

            crate::serial_println!("[SYSCALL] SetInformationThread: I/O priority = {}", io_priority);

            // Store I/O priority in thread structure
            if !ethread.is_null() {
                unsafe { (*ethread).io_priority = io_priority as u8; }
            }

            STATUS_SUCCESS
        }

        // Class 24: ThreadPagePriority
        set_thread_info_class::ThreadPagePriority => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let page_priority = unsafe { *(thread_information as *const u32) };

            // Validate page priority (0-7)
            if page_priority > 7 {
                return STATUS_INVALID_PARAMETER;
            }

            crate::serial_println!("[SYSCALL] SetInformationThread: page priority = {}", page_priority);

            // Store page priority in thread structure
            if !ethread.is_null() {
                unsafe { (*ethread).page_priority = page_priority as u8; }
            }

            STATUS_SUCCESS
        }

        // Class 25: ThreadActualBasePriority
        set_thread_info_class::ThreadActualBasePriority => {
            if thread_information_length < 4 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let actual_base = unsafe { *(thread_information as *const i32) };

            // Validate priority (0-31)
            if !(0..=31).contains(&actual_base) {
                return STATUS_INVALID_PARAMETER;
            }

            crate::serial_println!("[SYSCALL] SetInformationThread: actual base priority = {}",
                actual_base);

            if !ethread.is_null() {
                unsafe {
                    let tcb = (*ethread).get_tcb_mut();
                    (*tcb).base_priority = actual_base as i8;
                    (*tcb).priority = actual_base as i8;
                }
            }

            STATUS_SUCCESS
        }

        // Class 30: ThreadGroupInformation
        set_thread_info_class::ThreadGroupInformation => {
            if thread_information_length < core::mem::size_of::<GroupAffinity>() {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let group_affinity = unsafe { &*(thread_information as *const GroupAffinity) };

            crate::serial_println!(
                "[SYSCALL] SetInformationThread: group {} affinity = {:#x}",
                group_affinity.group, group_affinity.mask
            );

            // We only support group 0
            if group_affinity.group != 0 {
                return STATUS_INVALID_PARAMETER;
            }

            // Mask must have at least one bit set and include processor 0
            if group_affinity.mask == 0 || (group_affinity.mask & 1) == 0 {
                return STATUS_INVALID_PARAMETER;
            }

            STATUS_SUCCESS
        }

        // Class 33: ThreadIdealProcessorEx
        set_thread_info_class::ThreadIdealProcessorEx => {
            if thread_information_length < core::mem::size_of::<ProcessorNumber>() {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            let proc_num = unsafe { &*(thread_information as *const ProcessorNumber) };

            crate::serial_println!(
                "[SYSCALL] SetInformationThread: ideal processor group {} number {}",
                proc_num.group, proc_num.number
            );

            // We only support group 0, processor 0
            if proc_num.group != 0 {
                return STATUS_INVALID_PARAMETER;
            }

            STATUS_SUCCESS
        }

        // Class 49: ThreadPowerThrottlingState
        set_thread_info_class::ThreadPowerThrottlingState => {
            crate::serial_println!("[SYSCALL] SetInformationThread: power throttling state");

            // Power throttling is a Windows 10+ feature
            // Accept but ignore for compatibility

            STATUS_SUCCESS
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtSetInformationThread: unsupported class {}",
                thread_information_class);
            STATUS_INVALID_INFO_CLASS
        }
    }
}

/// Object information classes for Set operations
/// These are the same as Query classes but only some are settable
#[allow(non_snake_case, non_upper_case_globals)]
pub mod set_object_info_class {
    /// Handle flag information (inherit, protect from close)
    /// This is the only settable object information class
    pub const ObjectHandleFlagInformation: u32 = 4;

    /// Session information (can be set on some objects)
    pub const ObjectSessionInformation: u32 = 5;

    // Legacy alias
    pub const OBJECT_FLAGS_INFORMATION: u32 = ObjectHandleFlagInformation;
}

/// OBJECT_HANDLE_FLAG_INFORMATION for Set operations
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SetObjectHandleFlagInformation {
    /// Whether handle should be inheritable
    pub inherit: u8,
    /// Whether handle should be protected from close
    pub protect_from_close: u8,
}

/// NtSetInformationObject - Set object handle attributes
///
/// # Arguments
/// * `handle` - Handle to modify
/// * `object_information_class` - Type of information to set
/// * `object_information` - Buffer containing new information
/// * `object_information_length` - Size of buffer
///
/// # Returns
/// * STATUS_SUCCESS - Information was successfully set
/// * STATUS_INVALID_HANDLE - Handle is invalid
/// * STATUS_INVALID_PARAMETER - Invalid parameter
/// * STATUS_INFO_LENGTH_MISMATCH - Buffer size is incorrect
/// * STATUS_INVALID_INFO_CLASS - Information class not supported for Set
/// * STATUS_ACCESS_DENIED - Cannot modify handle attributes
///
/// # Supported Information Classes
/// * ObjectHandleFlagInformation (4) - Set inherit and protect-from-close flags
/// * ObjectSessionInformation (5) - Set session ID (limited)
fn sys_set_information_object(
    handle: usize,
    object_information_class: usize,
    object_information: usize,
    object_information_length: usize,
    _: usize, _: usize,
) -> isize {
    // NT status codes
    const STATUS_SUCCESS: isize = 0;
    const STATUS_INVALID_HANDLE: isize = 0xC0000008u32 as isize;
    const STATUS_INVALID_PARAMETER: isize = 0xC000000Du32 as isize;
    const STATUS_INFO_LENGTH_MISMATCH: isize = 0xC0000004u32 as isize;
    const STATUS_INVALID_INFO_CLASS: isize = 0xC0000003u32 as isize;
    const STATUS_ACCESS_DENIED: isize = 0xC0000022u32 as isize;
    const STATUS_OBJECT_TYPE_MISMATCH: isize = 0xC0000024u32 as isize;

    crate::serial_println!(
        "[SYSCALL] NtSetInformationObject(handle=0x{:X}, class={}, buffer=0x{:X}, len={})",
        handle, object_information_class, object_information, object_information_length
    );

    // Validate handle
    if handle == 0 {
        crate::serial_println!("[SYSCALL] NtSetInformationObject: NULL handle");
        return STATUS_INVALID_HANDLE;
    }

    // Pseudo-handles cannot have their attributes modified
    if handle == 0xFFFFFFFFFFFFFFFF || handle == 0xFFFFFFFFFFFFFFFE {
        crate::serial_println!("[SYSCALL] NtSetInformationObject: cannot modify pseudo-handle");
        return STATUS_INVALID_HANDLE;
    }

    // Validate buffer
    if object_information == 0 && object_information_length > 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let info_class = object_information_class as u32;

    match info_class {
        set_object_info_class::ObjectHandleFlagInformation => {
            let required = core::mem::size_of::<SetObjectHandleFlagInformation>();

            if object_information_length < required {
                crate::serial_println!("[SYSCALL] NtSetInformationObject: buffer too small ({} < {})",
                    object_information_length, required);
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            if object_information == 0 {
                return STATUS_INVALID_PARAMETER;
            }

            // Read the flags
            let flags = unsafe { *(object_information as *const SetObjectHandleFlagInformation) };
            let inherit = flags.inherit != 0;
            let protect_from_close = flags.protect_from_close != 0;

            crate::serial_println!(
                "[SYSCALL] NtSetInformationObject: setting inherit={}, protect_from_close={}",
                inherit, protect_from_close
            );

            // Get handle type to determine how to update
            let handle_type = get_handle_type(handle);

            if handle_type == HandleType::None {
                // Try object manager for kernel handles
                let ob_handle = handle as u32;
                let result = unsafe {
                    set_ob_handle_flags(ob_handle, inherit, protect_from_close)
                };

                if result {
                    crate::serial_println!("[SYSCALL] NtSetInformationObject: updated OB handle flags");
                    return STATUS_SUCCESS;
                } else {
                    crate::serial_println!("[SYSCALL] NtSetInformationObject: OB handle not found");
                    return STATUS_INVALID_HANDLE;
                }
            }

            // For our internal handle types, we need to store these flags
            // Currently our handle tables don't support per-handle flags,
            // so we'll need to update them or use a separate flags table

            // For now, store in a simple flags table
            unsafe {
                set_handle_flags(handle, inherit, protect_from_close);
            }

            crate::serial_println!("[SYSCALL] NtSetInformationObject: flags updated successfully");
            STATUS_SUCCESS
        }

        set_object_info_class::ObjectSessionInformation => {
            // Set session ID for the object
            // Only certain object types support this

            let required = core::mem::size_of::<u32>();

            if object_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            if object_information == 0 {
                return STATUS_INVALID_PARAMETER;
            }

            let session_id = unsafe { *(object_information as *const u32) };

            crate::serial_println!(
                "[SYSCALL] NtSetInformationObject: setting session ID to {}",
                session_id
            );

            // Get handle type
            let handle_type = get_handle_type(handle);

            // Only certain types support session assignment
            match handle_type {
                HandleType::Event | HandleType::Semaphore | HandleType::Mutex |
                HandleType::Section | HandleType::Port => {
                    // These types can have session IDs
                    // For now, just acknowledge the request
                    crate::serial_println!(
                        "[SYSCALL] NtSetInformationObject: session set for {:?}",
                        handle_type
                    );
                    STATUS_SUCCESS
                }
                HandleType::Process | HandleType::Thread => {
                    // Process/thread session is read-only after creation
                    crate::serial_println!(
                        "[SYSCALL] NtSetInformationObject: cannot set session for process/thread"
                    );
                    STATUS_ACCESS_DENIED
                }
                _ => {
                    crate::serial_println!(
                        "[SYSCALL] NtSetInformationObject: type {:?} doesn't support session",
                        handle_type
                    );
                    STATUS_OBJECT_TYPE_MISMATCH
                }
            }
        }

        // These are query-only classes
        0..=3 => {
            crate::serial_println!(
                "[SYSCALL] NtSetInformationObject: class {} is query-only",
                info_class
            );
            STATUS_INVALID_INFO_CLASS
        }

        _ => {
            crate::serial_println!(
                "[SYSCALL] NtSetInformationObject: unknown info class {}",
                info_class
            );
            STATUS_INVALID_INFO_CLASS
        }
    }
}

// ============================================================================
// Handle Flags Table
// ============================================================================

/// Maximum handles for flags table
const MAX_HANDLE_FLAGS: usize = 1024;

/// Handle flags entry
#[derive(Clone, Copy)]
struct HandleFlags {
    /// Handle value (0 = unused entry)
    handle: usize,
    /// Inherit flag
    inherit: bool,
    /// Protect from close flag
    protect_from_close: bool,
}

impl HandleFlags {
    const fn new() -> Self {
        Self {
            handle: 0,
            inherit: false,
            protect_from_close: false,
        }
    }
}

/// Static handle flags table
static mut HANDLE_FLAGS_TABLE: [HandleFlags; MAX_HANDLE_FLAGS] = {
    const INIT: HandleFlags = HandleFlags::new();
    [INIT; MAX_HANDLE_FLAGS]
};

/// Set flags for a handle
unsafe fn set_handle_flags(handle: usize, inherit: bool, protect_from_close: bool) {
    // First, try to find existing entry
    for entry in HANDLE_FLAGS_TABLE.iter_mut() {
        if entry.handle == handle {
            entry.inherit = inherit;
            entry.protect_from_close = protect_from_close;
            return;
        }
    }

    // Find free entry
    for entry in HANDLE_FLAGS_TABLE.iter_mut() {
        if entry.handle == 0 {
            entry.handle = handle;
            entry.inherit = inherit;
            entry.protect_from_close = protect_from_close;
            return;
        }
    }

    // Table full - oldest entry gets overwritten (simple LRU)
    HANDLE_FLAGS_TABLE[0].handle = handle;
    HANDLE_FLAGS_TABLE[0].inherit = inherit;
    HANDLE_FLAGS_TABLE[0].protect_from_close = protect_from_close;
}

/// Get flags for a handle
unsafe fn get_handle_flags(handle: usize) -> (bool, bool) {
    for entry in HANDLE_FLAGS_TABLE.iter() {
        if entry.handle == handle {
            return (entry.inherit, entry.protect_from_close);
        }
    }
    (false, false) // Default: not inheritable, not protected
}

/// Clear flags when handle is closed
unsafe fn clear_handle_flags(handle: usize) {
    for entry in HANDLE_FLAGS_TABLE.iter_mut() {
        if entry.handle == handle {
            entry.handle = 0;
            entry.inherit = false;
            entry.protect_from_close = false;
            return;
        }
    }
}

/// Set flags for an object manager handle
unsafe fn set_ob_handle_flags(handle: u32, inherit: bool, protect_from_close: bool) -> bool {
    // Try to get the handle entry from the object manager
    let object = crate::ob::ob_reference_object_by_handle(handle, 0);

    if object.is_null() {
        return false;
    }

    // Dereference since we just needed to verify handle exists
    crate::ob::ob_dereference_object(object);

    // Store flags in our table (OB doesn't have per-handle flags storage yet)
    set_handle_flags(handle as usize, inherit, protect_from_close);

    true
}

/// Token information classes for Set operations
pub mod set_token_info_class {
    pub const TOKEN_OWNER: u32 = 4;
    pub const TOKEN_PRIMARY_GROUP: u32 = 5;
    pub const TOKEN_DEFAULT_DACL: u32 = 6;
    pub const TOKEN_SESSION_ID: u32 = 12;
    pub const TOKEN_SESSION_REFERENCE: u32 = 14;
    pub const TOKEN_ORIGIN: u32 = 17;
}

/// NtSetInformationToken - Set token attributes
fn sys_set_information_token(
    token_handle: usize,
    token_information_class: usize,
    token_information: usize,
    token_information_length: usize,
    _: usize, _: usize,
) -> isize {
    const STATUS_BUFFER_TOO_SMALL: isize = 0xC0000023u32 as isize;
    const STATUS_INVALID_INFO_CLASS: isize = 0xC0000003u32 as isize;

    let token_id = match unsafe { get_token_id(token_handle) } {
        Some(t) => t,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtSetInformationToken(token={}, class={})",
        token_id, token_information_class);

    if token_information == 0 && token_information_length > 0 {
        return STATUS_INVALID_PARAMETER;
    }

    match token_information_class as u32 {
        set_token_info_class::TOKEN_OWNER => {
            if token_information_length < 8 {
                return STATUS_BUFFER_TOO_SMALL;
            }

            // TOKEN_OWNER contains a pointer to SID
            let owner_sid_ptr = unsafe { *(token_information as *const usize) };
            crate::serial_println!("[SYSCALL] SetInformationToken: owner SID at {:#x}",
                owner_sid_ptr);

            // TODO: Validate SID and update token owner

            STATUS_SUCCESS
        }
        set_token_info_class::TOKEN_PRIMARY_GROUP => {
            if token_information_length < 8 {
                return STATUS_BUFFER_TOO_SMALL;
            }

            let group_sid_ptr = unsafe { *(token_information as *const usize) };
            crate::serial_println!("[SYSCALL] SetInformationToken: primary group SID at {:#x}",
                group_sid_ptr);

            // TODO: Validate SID and update token primary group

            STATUS_SUCCESS
        }
        set_token_info_class::TOKEN_DEFAULT_DACL => {
            // TOKEN_DEFAULT_DACL contains ACL pointer (can be NULL to remove)
            crate::serial_println!("[SYSCALL] SetInformationToken: default DACL");

            // TODO: Validate ACL and update token default DACL

            STATUS_SUCCESS
        }
        set_token_info_class::TOKEN_SESSION_ID => {
            if token_information_length < 4 {
                return STATUS_BUFFER_TOO_SMALL;
            }

            let session_id = unsafe { *(token_information as *const u32) };
            crate::serial_println!("[SYSCALL] SetInformationToken: session ID = {}", session_id);

            // Store session ID in token (requires SeTcbPrivilege in full implementation)
            if let Some(token) = unsafe { get_token_ptr(token_handle) } {
                unsafe {
                    (*token).session_id = session_id;
                }
            }

            STATUS_SUCCESS
        }
        set_token_info_class::TOKEN_ORIGIN => {
            if token_information_length < 8 {
                return STATUS_BUFFER_TOO_SMALL;
            }

            // TOKEN_ORIGIN contains LUID of originating logon session
            let origin_luid = unsafe { *(token_information as *const u64) };
            crate::serial_println!("[SYSCALL] SetInformationToken: origin LUID = {:#x}", origin_luid);

            // Store origin LUID in token
            if let Some(token) = unsafe { get_token_ptr(token_handle) } {
                unsafe {
                    (*token).origin_luid = crate::se::privilege::Luid::from_u64(origin_luid);
                }
            }

            STATUS_SUCCESS
        }
        _ => {
            crate::serial_println!("[SYSCALL] NtSetInformationToken: unsupported class {}",
                token_information_class);
            STATUS_INVALID_INFO_CLASS
        }
    }
}

/// NtAdjustGroupsToken - Enable/disable token groups
fn sys_adjust_groups_token(
    token_handle: usize,
    reset_to_default: usize,
    new_state: usize,
    buffer_length: usize,
    previous_state: usize,
    return_length: usize,
) -> isize {
    let token_id = match unsafe { get_token_id(token_handle) } {
        Some(t) => t,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtAdjustGroupsToken(token={}, reset={})",
        token_id, reset_to_default != 0);

    if reset_to_default != 0 {
        // Reset all groups to their default enabled state
        crate::serial_println!("[SYSCALL] AdjustGroupsToken: resetting to defaults");
        // TODO: Reset group enabled flags to defaults

        if return_length != 0 {
            unsafe { *(return_length as *mut usize) = 0; }
        }
        return STATUS_SUCCESS;
    }

    // new_state points to TOKEN_GROUPS structure
    if new_state == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // TOKEN_GROUPS structure:
    // ULONG GroupCount
    // SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY]
    let group_count = unsafe { *(new_state as *const u32) };
    crate::serial_println!("[SYSCALL] AdjustGroupsToken: {} groups", group_count);

    let _ = buffer_length;
    let _ = previous_state;

    // TODO: Process each group and enable/disable accordingly
    // Groups with SE_GROUP_USE_FOR_DENY_ONLY cannot be enabled

    if return_length != 0 {
        unsafe { *(return_length as *mut usize) = 0; }
    }

    0
}

/// NtImpersonateThread - Impersonate another thread's security context
///
/// Causes the server thread to impersonate the security context of the client thread.
///
/// # Arguments
/// * `server_thread_handle` - Handle to thread that will do the impersonating (usually current)
/// * `client_thread_handle` - Handle to thread whose security context will be impersonated
/// * `security_qos` - Pointer to SECURITY_QUALITY_OF_SERVICE structure
fn sys_impersonate_thread(
    server_thread_handle: usize,
    client_thread_handle: usize,
    security_qos: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    use crate::ke::thread::{THREAD_POOL, THREAD_POOL_BITMAP, constants::MAX_THREADS};

    // Get the server thread (the one that will impersonate)
    let server_thread = if server_thread_handle == 0xFFFFFFFE || server_thread_handle == (usize::MAX - 1) {
        // Current thread
        let prcb = crate::ke::prcb::get_current_prcb();
        if prcb.current_thread.is_null() {
            return STATUS_INVALID_HANDLE;
        }
        prcb.current_thread
    } else {
        // Find thread by ID from handle
        match unsafe { get_thread_id(server_thread_handle) } {
            Some(tid) => unsafe {
                let mut found: *mut crate::ke::KThread = core::ptr::null_mut();
                for i in 0..MAX_THREADS {
                    if THREAD_POOL_BITMAP & (1 << i) != 0 && THREAD_POOL[i].thread_id == tid {
                        found = &mut THREAD_POOL[i] as *mut _;
                        break;
                    }
                }
                if found.is_null() {
                    return STATUS_INVALID_HANDLE;
                }
                found
            },
            None => return STATUS_INVALID_HANDLE,
        }
    };

    // Get the client thread (the one whose token will be used)
    let client_thread = match unsafe { get_thread_id(client_thread_handle) } {
        Some(tid) => unsafe {
            let mut found: *mut crate::ke::KThread = core::ptr::null_mut();
            for i in 0..MAX_THREADS {
                if THREAD_POOL_BITMAP & (1 << i) != 0 && THREAD_POOL[i].thread_id == tid {
                    found = &mut THREAD_POOL[i] as *mut _;
                    break;
                }
            }
            if found.is_null() {
                return STATUS_INVALID_HANDLE;
            }
            found
        },
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtImpersonateThread(server={}, client={})",
        unsafe { (*server_thread).thread_id }, unsafe { (*client_thread).thread_id });

    // Parse SECURITY_QUALITY_OF_SERVICE
    let mut impersonation_level: u32 = 2; // Default: SecurityImpersonation
    let mut effective_only: bool = false;

    if security_qos != 0 {
        let length = unsafe { *(security_qos as *const u32) };
        if length >= 8 {
            impersonation_level = unsafe { *((security_qos + 4) as *const u32) };
            if length >= 12 {
                effective_only = unsafe { *((security_qos + 9) as *const u8) } != 0;
            }
            crate::serial_println!("[SYSCALL] ImpersonateThread: level={}, effective_only={}",
                impersonation_level, effective_only);
        }
    }

    // Validate impersonation level (0-3)
    if impersonation_level > 3 {
        return STATUS_INVALID_PARAMETER;
    }

    // Get client's effective token
    let client_token = unsafe { (*client_thread).get_effective_token() };

    // Set impersonation on server thread
    unsafe {
        (*server_thread).set_impersonation_token(client_token, impersonation_level);
        (*server_thread).effective_only = effective_only;
    }

    crate::serial_println!("[SYSCALL] NtImpersonateThread: impersonation set successfully");
    STATUS_SUCCESS
}

/// NtCreateToken - Create an access token
///
/// Creates a new access token with specified user, groups, and privileges.
/// Requires SeCreateTokenPrivilege.
///
/// # Arguments
/// * `token_handle` - Pointer to receive the new token handle
/// * `desired_access` - Access rights for the token handle
/// * `object_attributes` - Object attributes (name, security)
/// * `token_type` - Primary (1) or Impersonation (2)
/// * `authentication_id` - Logon session identifier (LUID)
/// * `expiration_time` - Token expiration time
fn sys_create_token(
    token_handle: usize,
    desired_access: usize,
    _object_attributes: usize,
    token_type: usize,
    _authentication_id: usize,
    _expiration_time: usize,
) -> isize {
    use crate::se::token::{se_create_token, TokenType};
    use crate::se::sid::SID_LOCAL_SYSTEM;

    crate::serial_println!("[SYSCALL] NtCreateToken(type={})", token_type);

    // Validate output handle pointer
    if token_handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Convert token type
    let token_type_enum = match token_type as u32 {
        1 => TokenType::Primary,
        2 => TokenType::Impersonation,
        _ => return STATUS_INVALID_PARAMETER,
    };

    // Create the token
    // For now, create a system token - a full implementation would parse
    // groups and privileges from user-supplied structures
    let token = unsafe { se_create_token(SID_LOCAL_SYSTEM, token_type_enum) };
    if token.is_null() {
        crate::serial_println!("[SYSCALL] NtCreateToken: failed to allocate token");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Allocate a handle for the token
    let handle = unsafe { alloc_token_handle((*token).token_id.low_part) };
    match handle {
        Some(h) => {
            unsafe { *(token_handle as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtCreateToken: created token handle {:#x}", h);
            let _ = desired_access; // Would use for access mask validation
            STATUS_SUCCESS
        }
        None => {
            unsafe { crate::se::token::se_free_token(token); }
            crate::serial_println!("[SYSCALL] NtCreateToken: failed to allocate handle");
            STATUS_INSUFFICIENT_RESOURCES
        }
    }
}

/// NtFilterToken - Create a filtered (restricted) token
///
/// Creates a restricted token by removing privileges or adding restricted SIDs.
///
/// # Arguments
/// * `existing_token_handle` - Handle to existing token
/// * `flags` - Filtering flags (DISABLE_MAX_PRIVILEGE, etc.)
/// * `sids_to_disable` - Optional pointer to array of SIDs to disable
/// * `privileges_to_delete` - Optional pointer to array of privileges to remove
/// * `restricted_sids` - Optional pointer to array of restricted SIDs to add
/// * `new_token_handle` - Pointer to receive the new filtered token handle
fn sys_filter_token(
    existing_token_handle: usize,
    flags: usize,
    _sids_to_disable: usize,
    _privileges_to_delete: usize,
    _restricted_sids: usize,
    new_token_handle: usize,
) -> isize {
    use crate::se::token::{se_create_token, TokenType};

    crate::serial_println!("[SYSCALL] NtFilterToken(existing={:#x}, flags={:#x})",
        existing_token_handle, flags);

    // Validate handles
    if existing_token_handle == 0 || new_token_handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Get the existing token
    let existing_token_id = match unsafe { get_token_id(existing_token_handle) } {
        Some(id) => id,
        None => return STATUS_INVALID_HANDLE,
    };

    // For now, create a copy of the token with reduced privileges
    // A full implementation would:
    // 1. Disable specified SIDs
    // 2. Delete specified privileges
    // 3. Add restricted SIDs

    let new_token = unsafe {
        // Create a new token copying the source
        se_create_token(
            crate::se::sid::SID_LOCAL_SYSTEM, // Would copy from source
            TokenType::Primary,
        )
    };

    if new_token.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Apply DISABLE_MAX_PRIVILEGE flag (0x1)
    if flags & 0x1 != 0 {
        // Disable all privileges
        unsafe {
            (*new_token).privileges.privilege_count = 0;
        }
        crate::serial_println!("[SYSCALL] NtFilterToken: disabled all privileges");
    }

    // Allocate handle for new token
    let handle = unsafe { alloc_token_handle((*new_token).token_id.low_part) };
    match handle {
        Some(h) => {
            unsafe { *(new_token_handle as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtFilterToken: created filtered token handle {:#x}", h);
            let _ = existing_token_id; // Used for source
            STATUS_SUCCESS
        }
        None => {
            unsafe { crate::se::token::se_free_token(new_token); }
            STATUS_INSUFFICIENT_RESOURCES
        }
    }
}

// ============================================================================
// Virtual Memory Extended Operations
// ============================================================================

/// NtFlushVirtualMemory - Flush modified pages to backing store
fn sys_flush_virtual_memory(
    process_handle: usize,
    base_address: usize,
    region_size: usize,
    io_status: usize,
    _: usize, _: usize,
) -> isize {
    let _ = process_handle;

    crate::serial_println!("[SYSCALL] NtFlushVirtualMemory(base={:#x}, size={:#x})",
        base_address, region_size);

    // For memory-mapped files, this would write dirty pages to disk
    // For now, just succeed

    if io_status != 0 {
        unsafe {
            // IO_STATUS_BLOCK: Status, Information
            *(io_status as *mut i32) = 0; // STATUS_SUCCESS
            *((io_status + 8) as *mut usize) = region_size;
        }
    }

    0
}

/// NtLockVirtualMemory - Lock pages in physical memory
///
/// Locks a range of virtual memory pages, preventing them from being paged out.
///
/// # Arguments
/// * `process_handle` - Handle to the process (0xFFFFFFFF for current process)
/// * `base_address_ptr` - Pointer to the starting virtual address (in/out)
/// * `region_size_ptr` - Pointer to the size in bytes (in/out)
/// * `map_type` - 1 = MAP_PROCESS (working set), 2 = MAP_SYSTEM (physical memory)
fn sys_lock_virtual_memory(
    _process_handle: usize,
    base_address_ptr: usize,
    region_size_ptr: usize,
    map_type: usize,
    _: usize, _: usize,
) -> isize {
    use crate::mm::{
        mm_virtual_to_physical, mm_get_cr3, mm_lock_pages, mm_unlock_physical_pages,
        PAGE_SIZE,
        address::{probe_for_write, is_valid_user_range},
    };

    // Validate pointer parameters
    if base_address_ptr == 0 || region_size_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate user-mode pointer accessibility
    if !probe_for_write(base_address_ptr as u64, core::mem::size_of::<usize>()) {
        return STATUS_ACCESS_VIOLATION;
    }
    if !probe_for_write(region_size_ptr as u64, core::mem::size_of::<usize>()) {
        return STATUS_ACCESS_VIOLATION;
    }

    let base = unsafe { *(base_address_ptr as *const usize) };
    let size = unsafe { *(region_size_ptr as *const usize) };

    crate::serial_println!("[SYSCALL] NtLockVirtualMemory(base={:#x}, size={:#x}, type={})",
        base, size, map_type);

    // Validate size
    if size == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate the range is in user space
    if !is_valid_user_range(base as u64, size) {
        return STATUS_INVALID_PARAMETER;
    }

    // map_type: 1 = MAP_PROCESS (lock in working set), 2 = MAP_SYSTEM (lock in physical memory)
    // For now, both lock pages in physical memory
    if map_type != 1 && map_type != 2 {
        return STATUS_INVALID_PARAMETER;
    }

    // Page-align the base address and calculate region size
    let page_base = base & !(PAGE_SIZE - 1);
    let page_end = (base + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let page_count = (page_end - page_base) / PAGE_SIZE;

    // Get CR3 for address translation
    let cr3 = mm_get_cr3();

    // Lock each page
    unsafe {
        for i in 0..page_count {
            let virt_addr = page_base + (i * PAGE_SIZE);

            // Translate virtual address to physical
            if let Some(phys_addr) = mm_virtual_to_physical(cr3, virt_addr as u64) {
                // Lock this single page
                if !mm_lock_pages(phys_addr, 1) {
                    // Failed to lock - unlock previously locked pages and return error
                    for j in 0..i {
                        let prev_virt = page_base + (j * PAGE_SIZE);
                        if let Some(prev_phys) = mm_virtual_to_physical(cr3, prev_virt as u64) {
                            mm_unlock_physical_pages(prev_phys, 1);
                        }
                    }
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            } else {
                // Page not mapped - unlock previously locked and return error
                for j in 0..i {
                    let prev_virt = page_base + (j * PAGE_SIZE);
                    if let Some(prev_phys) = mm_virtual_to_physical(cr3, prev_virt as u64) {
                        mm_unlock_physical_pages(prev_phys, 1);
                    }
                }
                return STATUS_ACCESS_VIOLATION;
            }
        }

        // Update output parameters with page-aligned values
        *(base_address_ptr as *mut usize) = page_base;
        *(region_size_ptr as *mut usize) = page_end - page_base;
    }

    crate::serial_println!("[SYSCALL] NtLockVirtualMemory: locked {} pages", page_count);
    STATUS_SUCCESS
}

/// NtUnlockVirtualMemory - Unlock previously locked pages
///
/// Unlocks a range of virtual memory pages that were previously locked.
///
/// # Arguments
/// * `process_handle` - Handle to the process (0xFFFFFFFF for current process)
/// * `base_address_ptr` - Pointer to the starting virtual address (in/out)
/// * `region_size_ptr` - Pointer to the size in bytes (in/out)
/// * `map_type` - 1 = MAP_PROCESS, 2 = MAP_SYSTEM (must match lock type)
fn sys_unlock_virtual_memory(
    _process_handle: usize,
    base_address_ptr: usize,
    region_size_ptr: usize,
    map_type: usize,
    _: usize, _: usize,
) -> isize {
    use crate::mm::{
        mm_virtual_to_physical, mm_get_cr3, mm_unlock_physical_pages,
        PAGE_SIZE,
        address::{probe_for_write, is_valid_user_range},
    };

    // Validate pointer parameters
    if base_address_ptr == 0 || region_size_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate user-mode pointer accessibility
    if !probe_for_write(base_address_ptr as u64, core::mem::size_of::<usize>()) {
        return STATUS_ACCESS_VIOLATION;
    }
    if !probe_for_write(region_size_ptr as u64, core::mem::size_of::<usize>()) {
        return STATUS_ACCESS_VIOLATION;
    }

    let base = unsafe { *(base_address_ptr as *const usize) };
    let size = unsafe { *(region_size_ptr as *const usize) };

    crate::serial_println!("[SYSCALL] NtUnlockVirtualMemory(base={:#x}, size={:#x}, type={})",
        base, size, map_type);

    // Validate size
    if size == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate the range is in user space
    if !is_valid_user_range(base as u64, size) {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate map_type
    if map_type != 1 && map_type != 2 {
        return STATUS_INVALID_PARAMETER;
    }

    // Page-align the base address and calculate region size
    let page_base = base & !(PAGE_SIZE - 1);
    let page_end = (base + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let page_count = (page_end - page_base) / PAGE_SIZE;

    // Get CR3 for address translation
    let cr3 = mm_get_cr3();

    // Unlock each page
    unsafe {
        for i in 0..page_count {
            let virt_addr = page_base + (i * PAGE_SIZE);

            // Translate virtual address to physical
            if let Some(phys_addr) = mm_virtual_to_physical(cr3, virt_addr as u64) {
                // Unlock this page
                mm_unlock_physical_pages(phys_addr, 1);
            }
            // Note: We silently skip unmapped pages during unlock (unlike lock)
        }

        // Update output parameters with page-aligned values
        *(base_address_ptr as *mut usize) = page_base;
        *(region_size_ptr as *mut usize) = page_end - page_base;
    }

    crate::serial_println!("[SYSCALL] NtUnlockVirtualMemory: unlocked {} pages", page_count);
    STATUS_SUCCESS
}

/// NtReadVirtualMemory - Read memory from another process
fn sys_read_virtual_memory(
    process_handle: usize,
    base_address: usize,
    buffer: usize,
    buffer_size: usize,
    number_of_bytes_read: usize,
    _: usize,
) -> isize {
    use crate::mm::address::{probe_for_read, probe_for_write, is_valid_user_range};

    // Get target process ID
    let target_pid = if process_handle == 0xFFFFFFFF || process_handle == usize::MAX {
        // Current process
        4u32
    } else {
        match unsafe { get_process_id(process_handle) } {
            Some(p) => p,
            None => return STATUS_INVALID_HANDLE,
        }
    };

    let current_pid = 4u32;

    crate::serial_println!("[SYSCALL] NtReadVirtualMemory(target={}, addr={:#x}, size={})",
        target_pid, base_address, buffer_size);

    // Validate parameters
    if buffer == 0 || buffer_size == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate output buffer is writable in caller's address space
    if !is_valid_user_range(buffer as u64, buffer_size) {
        return STATUS_ACCESS_VIOLATION;
    }

    if !probe_for_write(buffer as u64, buffer_size) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Validate optional output parameter
    if number_of_bytes_read != 0 {
        if !probe_for_write(number_of_bytes_read as u64, core::mem::size_of::<usize>()) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    // Cross-process memory read
    if target_pid != current_pid {
        // Cross-process read requires CR3 switching
        // 1. Look up target process to get its CR3
        // 2. Use a kernel intermediate buffer (since user buffer becomes inaccessible after CR3 switch)
        // 3. Copy from target address space to kernel buffer
        // 4. Switch back and copy to user buffer

        use crate::ps::cid::ps_lookup_process_by_id;
        use crate::ps::eprocess::EProcess;
        use crate::mm::pte::{mm_get_cr3, mm_set_cr3};

        // Look up target process
        let target_process = unsafe { ps_lookup_process_by_id(target_pid) as *mut EProcess };
        if target_process.is_null() {
            crate::serial_println!("  Target process {} not found", target_pid);
            return STATUS_INVALID_HANDLE;
        }

        // Get target process's CR3 (directory table base)
        let target_cr3 = unsafe { (*target_process).pcb.directory_table_base };
        if target_cr3 == 0 {
            // Process uses kernel address space (system process)
            crate::serial_println!("  Target process has no private address space");
            return STATUS_ACCESS_VIOLATION;
        }

        crate::serial_println!("  Cross-process read: target CR3={:#x}", target_cr3);

        // Use a static kernel buffer for the transfer (max 4KB per operation)
        const MAX_CROSS_PROCESS_SIZE: usize = 4096;
        static mut CROSS_PROCESS_BUFFER: [u8; MAX_CROSS_PROCESS_SIZE] = [0u8; MAX_CROSS_PROCESS_SIZE];

        let mut bytes_copied = 0usize;
        let current_cr3 = mm_get_cr3();

        // Copy in chunks
        while bytes_copied < buffer_size {
            let chunk_size = core::cmp::min(buffer_size - bytes_copied, MAX_CROSS_PROCESS_SIZE);
            let src_addr = base_address + bytes_copied;

            // Disable interrupts during CR3 switch
            let flags: u64;
            unsafe {
                core::arch::asm!("pushfq; pop {}; cli", out(reg) flags, options(preserves_flags));
            }

            // Switch to target process address space
            unsafe { mm_set_cr3(target_cr3); }

            // Copy from target address space to kernel buffer
            // NOTE: We can't validate the address in target's space easily,
            // so we use a simple boundary check
            let copy_result = if src_addr < 0x0000_8000_0000_0000 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src_addr as *const u8,
                        CROSS_PROCESS_BUFFER.as_mut_ptr(),
                        chunk_size,
                    );
                }
                true
            } else {
                false
            };

            // Switch back to caller's address space
            unsafe { mm_set_cr3(current_cr3); }

            // Restore interrupts
            unsafe {
                core::arch::asm!("push {}; popfq", in(reg) flags, options(preserves_flags));
            }

            if !copy_result {
                crate::serial_println!("  Cross-process read failed: invalid address {:#x}", src_addr);
                if bytes_copied > 0 && number_of_bytes_read != 0 {
                    unsafe { *(number_of_bytes_read as *mut usize) = bytes_copied; }
                }
                return STATUS_ACCESS_VIOLATION;
            }

            // Copy from kernel buffer to caller's buffer
            unsafe {
                core::ptr::copy_nonoverlapping(
                    CROSS_PROCESS_BUFFER.as_ptr(),
                    (buffer + bytes_copied) as *mut u8,
                    chunk_size,
                );
            }

            bytes_copied += chunk_size;
        }

        // Store bytes read
        if number_of_bytes_read != 0 {
            unsafe { *(number_of_bytes_read as *mut usize) = bytes_copied; }
        }

        crate::serial_println!("  Cross-process read complete: {} bytes", bytes_copied);
        return STATUS_SUCCESS;
    }

    // Same-process read - validate source address
    if !is_valid_user_range(base_address as u64, buffer_size) {
        return STATUS_ACCESS_VIOLATION;
    }

    if !probe_for_read(base_address as u64, buffer_size) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Perform the copy
    unsafe {
        core::ptr::copy_nonoverlapping(
            base_address as *const u8,
            buffer as *mut u8,
            buffer_size,
        );
    }

    // Store bytes read
    if number_of_bytes_read != 0 {
        unsafe { *(number_of_bytes_read as *mut usize) = buffer_size; }
    }

    STATUS_SUCCESS
}

/// NtWriteVirtualMemory - Write memory to another process
fn sys_write_virtual_memory(
    process_handle: usize,
    base_address: usize,
    buffer: usize,
    buffer_size: usize,
    number_of_bytes_written: usize,
    _: usize,
) -> isize {
    use crate::mm::address::{probe_for_read, probe_for_write, is_valid_user_range};

    // Get target process ID
    let target_pid = if process_handle == 0xFFFFFFFF || process_handle == usize::MAX {
        // Current process
        4u32
    } else {
        match unsafe { get_process_id(process_handle) } {
            Some(p) => p,
            None => return STATUS_INVALID_HANDLE,
        }
    };

    let current_pid = 4u32;

    crate::serial_println!("[SYSCALL] NtWriteVirtualMemory(target={}, addr={:#x}, size={})",
        target_pid, base_address, buffer_size);

    // Validate parameters
    if buffer == 0 || buffer_size == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate source buffer is readable in caller's address space
    if !is_valid_user_range(buffer as u64, buffer_size) {
        return STATUS_ACCESS_VIOLATION;
    }

    if !probe_for_read(buffer as u64, buffer_size) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Validate optional output parameter
    if number_of_bytes_written != 0 {
        if !probe_for_write(number_of_bytes_written as u64, core::mem::size_of::<usize>()) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    // Cross-process memory write
    if target_pid != current_pid {
        // Cross-process write requires CR3 switching
        // 1. Look up target process to get its CR3
        // 2. Copy from caller's buffer to kernel intermediate buffer
        // 3. Switch to target's address space and copy to destination
        // 4. Switch back

        use crate::ps::cid::ps_lookup_process_by_id;
        use crate::ps::eprocess::EProcess;
        use crate::mm::pte::{mm_get_cr3, mm_set_cr3};

        // Look up target process
        let target_process = unsafe { ps_lookup_process_by_id(target_pid) as *mut EProcess };
        if target_process.is_null() {
            crate::serial_println!("  Target process {} not found", target_pid);
            return STATUS_INVALID_HANDLE;
        }

        // Get target process's CR3 (directory table base)
        let target_cr3 = unsafe { (*target_process).pcb.directory_table_base };
        if target_cr3 == 0 {
            // Process uses kernel address space (system process)
            crate::serial_println!("  Target process has no private address space");
            return STATUS_ACCESS_VIOLATION;
        }

        crate::serial_println!("  Cross-process write: target CR3={:#x}", target_cr3);

        // Use a static kernel buffer for the transfer (max 4KB per operation)
        const MAX_CROSS_PROCESS_SIZE: usize = 4096;
        static mut CROSS_PROCESS_WRITE_BUFFER: [u8; MAX_CROSS_PROCESS_SIZE] = [0u8; MAX_CROSS_PROCESS_SIZE];

        let mut bytes_copied = 0usize;
        let current_cr3 = mm_get_cr3();

        // Copy in chunks
        while bytes_copied < buffer_size {
            let chunk_size = core::cmp::min(buffer_size - bytes_copied, MAX_CROSS_PROCESS_SIZE);
            let dst_addr = base_address + bytes_copied;

            // Copy from caller's buffer to kernel buffer (while still in caller's address space)
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (buffer + bytes_copied) as *const u8,
                    CROSS_PROCESS_WRITE_BUFFER.as_mut_ptr(),
                    chunk_size,
                );
            }

            // Disable interrupts during CR3 switch
            let flags: u64;
            unsafe {
                core::arch::asm!("pushfq; pop {}; cli", out(reg) flags, options(preserves_flags));
            }

            // Switch to target process address space
            unsafe { mm_set_cr3(target_cr3); }

            // Copy from kernel buffer to target address space
            // NOTE: Simple boundary check for user-mode addresses
            let copy_result = if dst_addr < 0x0000_8000_0000_0000 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        CROSS_PROCESS_WRITE_BUFFER.as_ptr(),
                        dst_addr as *mut u8,
                        chunk_size,
                    );
                }
                true
            } else {
                false
            };

            // Switch back to caller's address space
            unsafe { mm_set_cr3(current_cr3); }

            // Restore interrupts
            unsafe {
                core::arch::asm!("push {}; popfq", in(reg) flags, options(preserves_flags));
            }

            if !copy_result {
                crate::serial_println!("  Cross-process write failed: invalid address {:#x}", dst_addr);
                if bytes_copied > 0 && number_of_bytes_written != 0 {
                    unsafe { *(number_of_bytes_written as *mut usize) = bytes_copied; }
                }
                return STATUS_ACCESS_VIOLATION;
            }

            bytes_copied += chunk_size;
        }

        // Store bytes written
        if number_of_bytes_written != 0 {
            unsafe { *(number_of_bytes_written as *mut usize) = bytes_copied; }
        }

        crate::serial_println!("  Cross-process write complete: {} bytes", bytes_copied);
        return STATUS_SUCCESS;
    }

    // Same-process write - validate destination address
    if !is_valid_user_range(base_address as u64, buffer_size) {
        return STATUS_ACCESS_VIOLATION;
    }

    if !probe_for_write(base_address as u64, buffer_size) {
        return STATUS_ACCESS_VIOLATION;
    }

    // Perform the copy
    unsafe {
        core::ptr::copy_nonoverlapping(
            buffer as *const u8,
            base_address as *mut u8,
            buffer_size,
        );
    }

    // Store bytes written
    if number_of_bytes_written != 0 {
        unsafe { *(number_of_bytes_written as *mut usize) = buffer_size; }
    }

    STATUS_SUCCESS
}

// ============================================================================
// Debug Object Support
// ============================================================================

/// Debug object handle base
const DEBUG_HANDLE_BASE: usize = 0x7000;

/// Convert debug object index to handle
fn debug_index_to_handle(index: usize) -> usize {
    index + DEBUG_HANDLE_BASE
}

/// Convert handle to debug object index
fn handle_to_debug_index(handle: usize) -> Option<usize> {
    if (DEBUG_HANDLE_BASE..DEBUG_HANDLE_BASE + crate::ke::MAX_DEBUG_OBJECTS).contains(&handle) {
        Some(handle - DEBUG_HANDLE_BASE)
    } else {
        None
    }
}

/// NtCreateDebugObject - Create a debug object for debugging processes
///
/// # Arguments
/// * `debug_object_handle` - Pointer to receive the debug object handle
/// * `desired_access` - Access rights (DEBUG_ALL_ACCESS, etc.)
/// * `object_attributes` - Object attributes (optional)
/// * `flags` - DEBUG_KILL_ON_CLOSE (0x1) to terminate process when debug object closed
fn sys_create_debug_object(
    debug_object_handle: usize,
    desired_access: usize,
    _object_attributes: usize,
    flags: usize,
    _: usize, _: usize,
) -> isize {
    use crate::ke::{dbgk_create_debug_object, debug_flags};

    if debug_object_handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    crate::serial_println!("[SYSCALL] NtCreateDebugObject(access={:#x}, flags={:#x})",
        desired_access, flags);

    // Convert NT flags to internal flags
    let internal_flags = if (flags & 0x1) != 0 {
        debug_flags::DEBUG_KILL_ON_CLOSE
    } else {
        0
    };

    // Allocate debug object
    let index = unsafe { dbgk_create_debug_object(internal_flags) };

    match index {
        Some(idx) => {
            let handle = debug_index_to_handle(idx);
            unsafe { *(debug_object_handle as *mut usize) = handle; }
            crate::serial_println!("[SYSCALL] NtCreateDebugObject -> handle {:#x}", handle);
            STATUS_SUCCESS
        }
        None => STATUS_INSUFFICIENT_RESOURCES,
    }
}

/// NtDebugActiveProcess - Attach debugger to a process
///
/// Attaches a debug object to a process, enabling debugging.
fn sys_debug_active_process(
    process_handle: usize,
    debug_object_handle: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ke::{dbgk_attach_process, dbgk_get_debug_object, dbgk_generate_initial_events};

    let pid = match unsafe { get_process_id(process_handle) } {
        Some(p) => p,
        None => return STATUS_INVALID_HANDLE,
    };

    let debug_idx = match handle_to_debug_index(debug_object_handle) {
        Some(idx) => idx,
        None => return STATUS_INVALID_HANDLE,
    };

    // Verify debug object exists
    if unsafe { dbgk_get_debug_object(debug_idx) }.is_none() {
        return STATUS_INVALID_HANDLE;
    }

    crate::serial_println!("[SYSCALL] NtDebugActiveProcess(pid={}, debug_handle={:#x})",
        pid, debug_object_handle);

    // Attach debug object to process
    if !unsafe { dbgk_attach_process(debug_idx, pid) } {
        return STATUS_ACCESS_DENIED;
    }

    // Generate initial debug events (CREATE_PROCESS, etc.)
    unsafe { dbgk_generate_initial_events(debug_idx, pid); }

    STATUS_SUCCESS
}

/// NtRemoveProcessDebug - Detach debugger from process
fn sys_remove_process_debug(
    process_handle: usize,
    debug_object_handle: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ke::dbgk_detach_process;

    let pid = match unsafe { get_process_id(process_handle) } {
        Some(p) => p,
        None => return STATUS_INVALID_HANDLE,
    };

    let debug_idx = match handle_to_debug_index(debug_object_handle) {
        Some(idx) => idx,
        None => return STATUS_INVALID_HANDLE,
    };

    crate::serial_println!("[SYSCALL] NtRemoveProcessDebug(pid={}, debug_handle={:#x})",
        pid, debug_object_handle);

    if !unsafe { dbgk_detach_process(debug_idx) } {
        return STATUS_ACCESS_DENIED;
    }

    STATUS_SUCCESS
}

/// Debug state change structure (simplified)
#[repr(C)]
struct DbgUiWaitStateChange {
    new_state: u32,
    app_client_id: [u32; 2], // Process ID, Thread ID
    // Union of event-specific data follows
}

/// NtWaitForDebugEvent - Wait for debug event from debugged process
fn sys_wait_for_debug_event(
    debug_object_handle: usize,
    alertable: usize,
    timeout: usize,
    wait_state_change: usize,
    _: usize, _: usize,
) -> isize {
    use crate::ke::{dbgk_wait_for_debug_event, dbgk_get_debug_object, DebugEventType};

    let debug_idx = match handle_to_debug_index(debug_object_handle) {
        Some(idx) => idx,
        None => return STATUS_INVALID_HANDLE,
    };

    let obj = match unsafe { dbgk_get_debug_object(debug_idx) } {
        Some(o) => o,
        None => return STATUS_INVALID_HANDLE,
    };

    let debugged_pid = obj.get_debugged_pid();

    crate::serial_println!("[SYSCALL] NtWaitForDebugEvent(pid={}, alertable={}, timeout={:#x})",
        debugged_pid, alertable != 0, timeout);

    if wait_state_change == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Convert timeout
    let timeout_ms = if timeout == 0 {
        None
    } else {
        // NT timeout is in 100ns units, negative means relative
        let timeout_val = timeout as i64;
        if timeout_val < 0 {
            Some((-timeout_val / 10000) as u64) // Convert to milliseconds
        } else {
            Some((timeout_val / 10000) as u64)
        }
    };

    // Wait for debug event
    let result = unsafe { dbgk_wait_for_debug_event(debug_idx, timeout_ms) };

    match result {
        Some((_event, event_type, pid, tid)) => {
            // Fill in the wait state change structure
            let state_change = wait_state_change as *mut DbgUiWaitStateChange;
            unsafe {
                (*state_change).new_state = match event_type {
                    DebugEventType::Exception => 1,
                    DebugEventType::CreateThread => 2,
                    DebugEventType::CreateProcess => 3,
                    DebugEventType::ExitThread => 4,
                    DebugEventType::ExitProcess => 5,
                    DebugEventType::LoadDll => 6,
                    DebugEventType::UnloadDll => 7,
                    DebugEventType::OutputDebugString => 8,
                    DebugEventType::Rip => 9,
                };
                (*state_change).app_client_id[0] = pid;
                (*state_change).app_client_id[1] = tid;
            }
            crate::serial_println!("[SYSCALL] NtWaitForDebugEvent: got {:?} event", event_type);
            STATUS_SUCCESS
        }
        None => STATUS_TIMEOUT,
    }
}

/// NtDebugContinue - Continue from debug event
fn sys_debug_continue(
    debug_object_handle: usize,
    client_id: usize,
    continue_status: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    use crate::ke::{dbgk_continue_debug_event, dbgk_get_debug_object};

    let debug_idx = match handle_to_debug_index(debug_object_handle) {
        Some(idx) => idx,
        None => return STATUS_INVALID_HANDLE,
    };

    let obj = match unsafe { dbgk_get_debug_object(debug_idx) } {
        Some(o) => o,
        None => return STATUS_INVALID_HANDLE,
    };

    let (pid, tid) = if client_id != 0 {
        unsafe {
            (*(client_id as *const u32), *((client_id + 4) as *const u32))
        }
    } else {
        (obj.get_debugged_pid(), 0)
    };

    crate::serial_println!("[SYSCALL] NtDebugContinue(pid={}, tid={}, status={:#x})",
        pid, tid, continue_status);

    // continue_status: DBG_CONTINUE (0x10002) or DBG_EXCEPTION_NOT_HANDLED (0x80010001)

    if !unsafe { dbgk_continue_debug_event(debug_idx, pid, tid, continue_status as u32) } {
        return STATUS_ACCESS_DENIED;
    }

    STATUS_SUCCESS
}

// ============================================================================
// Exception Handling Syscalls
// ============================================================================

/// NtRaiseException - Raise an exception in the current thread
fn sys_raise_exception(
    exception_record: usize,
    context_record: usize,
    first_chance: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    use crate::ke::exception::{ExceptionRecord, Context, ke_raise_exception};

    if exception_record == 0 || context_record == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let is_first_chance = first_chance != 0;

    crate::serial_println!("[SYSCALL] NtRaiseException(first_chance={})", is_first_chance);

    unsafe {
        let exception = exception_record as *const ExceptionRecord;
        let context = context_record as *mut Context;

        crate::serial_println!("[SYSCALL] NtRaiseException: code={:#x} addr={:p}",
            (*exception).exception_code,
            (*exception).exception_address);

        ke_raise_exception(exception, context, is_first_chance) as isize
    }
}

/// NtContinue - Continue execution from an exception handler
fn sys_continue(
    context_record: usize,
    test_alert: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ke::exception::{Context, ke_continue};

    if context_record == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let should_test_alert = test_alert != 0;

    crate::serial_println!("[SYSCALL] NtContinue(test_alert={})", should_test_alert);

    unsafe {
        let context = context_record as *const Context;
        ke_continue(context, should_test_alert) as isize
    }
}

/// NtGetContextThread - Get a thread's context
fn sys_get_context_thread(
    thread_handle: usize,
    context: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ke::exception::{Context, ke_get_context};

    if context == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    crate::serial_println!("[SYSCALL] NtGetContextThread(handle={:#x})", thread_handle);

    // For now, we only support getting the current thread's context
    // Full implementation would look up the thread by handle
    let prcb = unsafe { crate::ke::prcb::get_current_prcb_mut() };
    let current_handle = if prcb.current_thread.is_null() {
        0
    } else {
        // Get thread ID as pseudo-handle comparison
        unsafe { (*prcb.current_thread).thread_id as usize }
    };

    // Handle value -2 (0xFFFFFFFE) means current thread
    if thread_handle != 0xFFFFFFFE && thread_handle != current_handle {
        // For non-current thread, we'd need to suspend and read its context
        // For now, only support current thread
        crate::serial_println!("[SYSCALL] NtGetContextThread: non-current thread not yet supported");
        return 0xC0000001u32 as isize; // STATUS_UNSUCCESSFUL
    }

    unsafe {
        let ctx = context as *mut Context;
        let flags = (*ctx).context_flags;

        crate::serial_println!("[SYSCALL] NtGetContextThread: flags={:#x}", flags);

        ke_get_context(ctx, flags) as isize
    }
}

/// NtSetContextThread - Set a thread's context
fn sys_set_context_thread(
    thread_handle: usize,
    context: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ke::exception::{Context, ke_set_context};

    if context == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    crate::serial_println!("[SYSCALL] NtSetContextThread(handle={:#x})", thread_handle);

    // For now, we only support setting the current thread's context
    // Full implementation would look up the thread by handle
    let prcb = unsafe { crate::ke::prcb::get_current_prcb_mut() };
    let current_handle = if prcb.current_thread.is_null() {
        0
    } else {
        unsafe { (*prcb.current_thread).thread_id as usize }
    };

    // Handle value -2 (0xFFFFFFFE) means current thread
    if thread_handle != 0xFFFFFFFE && thread_handle != current_handle {
        // For non-current thread, we'd need to suspend and modify its context
        crate::serial_println!("[SYSCALL] NtSetContextThread: non-current thread not yet supported");
        return 0xC0000001u32 as isize; // STATUS_UNSUCCESSFUL
    }

    unsafe {
        let ctx = context as *const Context;

        crate::serial_println!("[SYSCALL] NtSetContextThread: flags={:#x}", (*ctx).context_flags);

        ke_set_context(ctx) as isize
    }
}

// ============================================================================
// Process Creation Syscalls
// ============================================================================

/// NtCreateProcess - Create a new process
///
/// This is the legacy process creation syscall. NtCreateProcessEx is preferred.
fn sys_create_process(
    process_handle: usize,
    desired_access: usize,
    object_attributes: usize,
    parent_process: usize,
    inherit_object_table: usize,
    section_handle: usize,
) -> isize {
    // Call the extended version with no debug port or exception port
    sys_create_process_internal(
        process_handle,
        desired_access,
        object_attributes,
        parent_process,
        0, // flags (inherit handles = inherit_object_table)
        section_handle,
        0, // debug_port
        0, // exception_port
        inherit_object_table,
    )
}

/// NtCreateProcessEx - Extended process creation
fn sys_create_process_ex(
    process_handle: usize,
    desired_access: usize,
    object_attributes: usize,
    parent_process: usize,
    flags: usize,
    section_handle: usize,
) -> isize {
    // Additional parameters would come from the stack in real implementation
    sys_create_process_internal(
        process_handle,
        desired_access,
        object_attributes,
        parent_process,
        flags,
        section_handle,
        0, // debug_port
        0, // exception_port
        0, // unused
    )
}

/// Internal process creation implementation
fn sys_create_process_internal(
    process_handle_ptr: usize,
    _desired_access: usize,
    object_attributes: usize,
    parent_process_handle: usize,
    flags: usize,
    section_handle: usize,
    _debug_port: usize,
    _exception_port: usize,
    _inherit_handles: usize,
) -> isize {
    use crate::ps::create::ps_create_process;
    use crate::ps::eprocess::get_system_process;
    use crate::ps::cid::ps_lookup_process_by_id;
    use crate::ps::job::{Job, job_limit_flags};

    if process_handle_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    crate::serial_println!(
        "[SYSCALL] NtCreateProcess(parent={:#x}, flags={:#x}, section={:#x})",
        parent_process_handle, flags, section_handle
    );

    // Get parent process
    let parent = if parent_process_handle == 0 || parent_process_handle == 0xFFFFFFFF {
        // Use system process as parent if no parent specified
        get_system_process()
    } else {
        // Look up parent process by handle
        unsafe {
            if let Some(pid) = get_process_id(parent_process_handle) {
                // Look up process by PID
                let proc_ptr = ps_lookup_process_by_id(pid);
                if !proc_ptr.is_null() {
                    proc_ptr as *mut crate::ps::eprocess::EProcess
                } else {
                    return 0xC0000008u32 as isize; // STATUS_INVALID_HANDLE
                }
            } else {
                return 0xC0000008u32 as isize; // STATUS_INVALID_HANDLE
            }
        }
    };

    // Check job limits if parent is in a job
    let parent_job: *mut Job = unsafe {
        let job_ptr = (*parent).job;
        if !job_ptr.is_null() {
            let job = job_ptr as *mut Job;

            // Check if breakaway is allowed
            let breakaway_ok = (flags & 0x01) != 0; // CREATE_BREAKAWAY_FROM_JOB flag
            let limit_flags = (*job).limits.basic_limit_information.limit_flags;

            if breakaway_ok {
                // Check if job allows breakaway
                if limit_flags & job_limit_flags::JOB_OBJECT_LIMIT_BREAKAWAY_OK == 0 {
                    // Breakaway not allowed
                    crate::serial_println!("[SYSCALL] NtCreateProcess: breakaway not allowed by job");
                    return 0xC000048Au32 as isize; // STATUS_ACCESS_DENIED
                }
                core::ptr::null_mut() // Process won't be in job
            } else {
                // Check active process limit
                if limit_flags & job_limit_flags::JOB_OBJECT_LIMIT_ACTIVE_PROCESS != 0 {
                    let limit = (*job).limits.basic_limit_information.active_process_limit;
                    let current = (*job).active_process_count();
                    if current >= limit {
                        crate::serial_println!(
                            "[SYSCALL] NtCreateProcess: job active process limit reached ({}/{})",
                            current, limit
                        );
                        return 0xC0000045u32 as isize; // STATUS_TOO_MANY_THREADS (close enough)
                    }
                }
                job // Process will inherit job
            }
        } else {
            core::ptr::null_mut()
        }
    };

    // Extract process name from object attributes if available
    let name = if object_attributes != 0 {
        // OBJECT_ATTRIBUTES contains a UNICODE_STRING for object name
        // For now, use a default name
        b"process.exe"
    } else {
        b"process.exe"
    };

    // Create the process
    let new_process = unsafe {
        ps_create_process(parent, name, 8) // Default priority 8
    };

    if new_process.is_null() {
        crate::serial_println!("[SYSCALL] NtCreateProcess: failed to create process");
        return 0xC0000001u32 as isize; // STATUS_UNSUCCESSFUL
    }

    // If a section handle was provided, that would be the executable to map
    // For now, we just note it
    if section_handle != 0 {
        crate::serial_println!("[SYSCALL] NtCreateProcess: section {:#x} (not yet mapped)", section_handle);
    }

    // Assign process to parent's job if applicable
    unsafe {
        if !parent_job.is_null() {
            if (*parent_job).assign_process(new_process) {
                crate::serial_println!(
                    "[SYSCALL] NtCreateProcess: assigned to job {}",
                    (*parent_job).job_id
                );
            } else {
                // Job assignment failed (shouldn't happen since we checked limits)
                crate::serial_println!("[SYSCALL] NtCreateProcess: job assignment failed");
            }
        }
    }

    // Allocate a handle for the new process
    unsafe {
        let pid = (*new_process).unique_process_id;

        if let Some(handle_value) = alloc_process_handle(pid) {
            // Write handle to caller
            *(process_handle_ptr as *mut usize) = handle_value;

            crate::serial_println!(
                "[SYSCALL] NtCreateProcess -> handle {:#x}, pid {}",
                handle_value, pid
            );
            0 // STATUS_SUCCESS
        } else {
            crate::serial_println!("[SYSCALL] NtCreateProcess: no handle slots available");
            0xC000001Du32 as isize // STATUS_NO_MEMORY
        }
    }
}

// ============================================================================
// Job Object Syscalls
// ============================================================================

/// Job handle pool
const JOB_HANDLE_BASE: usize = 0x8000;
const MAX_JOB_HANDLES: usize = 64;
static mut JOB_HANDLE_MAP: [u32; MAX_JOB_HANDLES] = [u32::MAX; MAX_JOB_HANDLES];

unsafe fn alloc_job_handle(job_id: u32) -> Option<usize> {
    for i in 0..MAX_JOB_HANDLES {
        if JOB_HANDLE_MAP[i] == u32::MAX {
            JOB_HANDLE_MAP[i] = job_id;
            return Some(JOB_HANDLE_BASE + i);
        }
    }
    None
}

unsafe fn get_job_id(handle: usize) -> Option<u32> {
    if handle < JOB_HANDLE_BASE {
        return None;
    }
    let idx = handle - JOB_HANDLE_BASE;
    if idx >= MAX_JOB_HANDLES {
        return None;
    }
    let id = JOB_HANDLE_MAP[idx];
    if id == u32::MAX { None } else { Some(id) }
}

/// NtCreateJobObject - Create a job object
fn sys_create_job_object(
    job_handle_ptr: usize,
    desired_access: usize,
    object_attributes: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::job::ps_create_job;

    if job_handle_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    crate::serial_println!("[SYSCALL] NtCreateJobObject(access={:#x})", desired_access);

    // Extract job name if provided
    let name = if object_attributes != 0 {
        b"Job"
    } else {
        b"Job"
    };

    let job = unsafe { ps_create_job(name) };

    if job.is_null() {
        crate::serial_println!("[SYSCALL] NtCreateJobObject: failed to create job");
        return 0xC0000001u32 as isize;
    }

    unsafe {
        let job_id = (*job).job_id;

        if let Some(handle_value) = alloc_job_handle(job_id) {
            *(job_handle_ptr as *mut usize) = handle_value;

            crate::serial_println!("[SYSCALL] NtCreateJobObject -> handle {:#x}, id {}",
                handle_value, job_id);
            0
        } else {
            crate::ps::job::free_job(job);
            0xC000001Du32 as isize
        }
    }
}

/// NtOpenJobObject - Open existing job object
fn sys_open_job_object(
    job_handle_ptr: usize,
    desired_access: usize,
    object_attributes: usize,
    _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::job::ps_lookup_job_by_name;

    if job_handle_ptr == 0 || object_attributes == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    crate::serial_println!("[SYSCALL] NtOpenJobObject(access={:#x})", desired_access);

    // Parse OBJECT_ATTRIBUTES to get the name
    // OBJECT_ATTRIBUTES structure:
    //   Length: u32
    //   RootDirectory: HANDLE (8 bytes)
    //   ObjectName: *UNICODE_STRING (8 bytes)
    //   Attributes: u32
    //   SecurityDescriptor: *void
    //   SecurityQualityOfService: *void

    let object_name_ptr = unsafe { *((object_attributes + 16) as *const u64) };
    if object_name_ptr == 0 {
        crate::serial_println!("[SYSCALL] NtOpenJobObject: no object name");
        return 0xC0000034u32 as isize; // STATUS_OBJECT_NAME_NOT_FOUND
    }

    // Parse UNICODE_STRING: Length (u16), MaxLength (u16), Buffer (*u16)
    let name_len = unsafe { *(object_name_ptr as *const u16) } as usize;
    let name_buffer = unsafe { *((object_name_ptr as usize + 8) as *const u64) };

    if name_len == 0 || name_buffer == 0 {
        return 0xC0000034u32 as isize; // STATUS_OBJECT_NAME_NOT_FOUND
    }

    // Convert wide string to bytes (simple ASCII conversion)
    let mut name_bytes = [0u8; 64];
    let char_count = (name_len / 2).min(63);
    for i in 0..char_count {
        let wide_char = unsafe { *((name_buffer as usize + i * 2) as *const u16) };
        name_bytes[i] = wide_char as u8;
    }

    crate::serial_println!("[SYSCALL] NtOpenJobObject: looking up job '{}'",
        core::str::from_utf8(&name_bytes[..char_count]).unwrap_or("?"));

    // Look up the job by name
    let job = unsafe { ps_lookup_job_by_name(&name_bytes[..char_count]) };
    if job.is_null() {
        crate::serial_println!("[SYSCALL] NtOpenJobObject: job not found");
        return 0xC0000034u32 as isize; // STATUS_OBJECT_NAME_NOT_FOUND
    }

    // Allocate a handle for the job
    let job_id = unsafe { (*job).job_id };
    let handle = unsafe { alloc_job_handle(job_id) };
    match handle {
        Some(h) => {
            unsafe { *(job_handle_ptr as *mut usize) = h; }
            crate::serial_println!("[SYSCALL] NtOpenJobObject: opened job handle {:#x}", h);
            let _ = desired_access; // Would validate access rights
            STATUS_SUCCESS
        }
        None => {
            crate::serial_println!("[SYSCALL] NtOpenJobObject: failed to allocate handle");
            STATUS_INSUFFICIENT_RESOURCES
        }
    }
}

/// NtAssignProcessToJobObject - Assign a process to a job
fn sys_assign_process_to_job(
    job_handle: usize,
    process_handle: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::job::ps_lookup_job;
    use crate::ps::cid::ps_lookup_process_by_id;

    crate::serial_println!("[SYSCALL] NtAssignProcessToJobObject(job={:#x}, proc={:#x})",
        job_handle, process_handle);

    let job = unsafe {
        if let Some(job_id) = get_job_id(job_handle) {
            ps_lookup_job(job_id)
        } else {
            return 0xC0000008u32 as isize;
        }
    };

    if job.is_null() {
        return 0xC0000008u32 as isize;
    }

    let process = unsafe {
        if let Some(pid) = get_process_id(process_handle) {
            ps_lookup_process_by_id(pid) as *mut crate::ps::eprocess::EProcess
        } else {
            return 0xC0000008u32 as isize;
        }
    };

    if process.is_null() {
        return 0xC0000008u32 as isize;
    }

    unsafe {
        if !(*process).job.is_null() {
            return 0xC0000430u32 as isize;
        }

        if (*job).assign_process(process) {
            crate::serial_println!("[SYSCALL] NtAssignProcessToJobObject: success");
            0
        } else {
            0xC0000001u32 as isize
        }
    }
}

/// NtQueryInformationJobObject - Query job information
fn sys_query_information_job(
    job_handle: usize,
    info_class: usize,
    info_buffer: usize,
    info_length: usize,
    return_length: usize,
    _: usize,
) -> isize {
    use crate::ps::job::ps_lookup_job;

    crate::serial_println!("[SYSCALL] NtQueryInformationJobObject(handle={:#x}, class={})",
        job_handle, info_class);

    if info_buffer == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let job = unsafe {
        if let Some(job_id) = get_job_id(job_handle) {
            ps_lookup_job(job_id)
        } else {
            return 0xC0000008u32 as isize;
        }
    };

    if job.is_null() {
        return 0xC0000008u32 as isize;
    }

    unsafe {
        match info_class as u32 {
            1 => { // BasicAccountingInformation
                let size = core::mem::size_of::<crate::ps::job::JobBasicAccountingInformation>();
                if info_length < size {
                    if return_length != 0 {
                        *(return_length as *mut usize) = size;
                    }
                    return 0xC0000023u32 as isize;
                }
                let dest = info_buffer as *mut crate::ps::job::JobBasicAccountingInformation;
                *dest = (*job).accounting;
                if return_length != 0 {
                    *(return_length as *mut usize) = size;
                }
                0
            }
            2 => { // BasicLimitInformation
                let size = core::mem::size_of::<crate::ps::job::JobBasicLimitInformation>();
                if info_length < size {
                    if return_length != 0 {
                        *(return_length as *mut usize) = size;
                    }
                    return 0xC0000023u32 as isize;
                }
                let dest = info_buffer as *mut crate::ps::job::JobBasicLimitInformation;
                *dest = (*job).limits.basic_limit_information;
                if return_length != 0 {
                    *(return_length as *mut usize) = size;
                }
                0
            }
            9 => { // ExtendedLimitInformation
                let size = core::mem::size_of::<crate::ps::job::JobExtendedLimitInformation>();
                if info_length < size {
                    if return_length != 0 {
                        *(return_length as *mut usize) = size;
                    }
                    return 0xC0000023u32 as isize;
                }
                let dest = info_buffer as *mut crate::ps::job::JobExtendedLimitInformation;
                *dest = (*job).limits;
                if return_length != 0 {
                    *(return_length as *mut usize) = size;
                }
                0
            }
            _ => 0xC0000003u32 as isize
        }
    }
}

/// NtSetInformationJobObject - Set job limits
fn sys_set_information_job(
    job_handle: usize,
    info_class: usize,
    info_buffer: usize,
    info_length: usize,
    _: usize, _: usize,
) -> isize {
    use crate::ps::job::ps_lookup_job;

    crate::serial_println!("[SYSCALL] NtSetInformationJobObject(handle={:#x}, class={})",
        job_handle, info_class);

    if info_buffer == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let job = unsafe {
        if let Some(job_id) = get_job_id(job_handle) {
            ps_lookup_job(job_id)
        } else {
            return 0xC0000008u32 as isize;
        }
    };

    if job.is_null() {
        return 0xC0000008u32 as isize;
    }

    unsafe {
        match info_class as u32 {
            2 => { // BasicLimitInformation
                let size = core::mem::size_of::<crate::ps::job::JobBasicLimitInformation>();
                if info_length < size {
                    return 0xC0000023u32 as isize;
                }
                let src = info_buffer as *const crate::ps::job::JobBasicLimitInformation;
                (*job).limits.basic_limit_information = *src;
                0
            }
            9 => { // ExtendedLimitInformation
                let size = core::mem::size_of::<crate::ps::job::JobExtendedLimitInformation>();
                if info_length < size {
                    return 0xC0000023u32 as isize;
                }
                let src = info_buffer as *const crate::ps::job::JobExtendedLimitInformation;
                (*job).limits = *src;
                0
            }
            _ => 0xC0000003u32 as isize
        }
    }
}

/// NtTerminateJobObject - Terminate all processes in a job
fn sys_terminate_job_object(
    job_handle: usize,
    exit_status: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::job::ps_lookup_job;

    crate::serial_println!("[SYSCALL] NtTerminateJobObject(handle={:#x}, exit={:#x})",
        job_handle, exit_status);

    let job = unsafe {
        if let Some(job_id) = get_job_id(job_handle) {
            ps_lookup_job(job_id)
        } else {
            return 0xC0000008u32 as isize;
        }
    };

    if job.is_null() {
        return 0xC0000008u32 as isize;
    }

    unsafe {
        (*job).terminate(exit_status as i32);
    }

    0
}

/// NtIsProcessInJob - Check if a process is in a job
fn sys_is_process_in_job(
    process_handle: usize,
    job_handle: usize,
    _: usize, _: usize, _: usize, _: usize,
) -> isize {
    use crate::ps::cid::ps_lookup_process_by_id;

    crate::serial_println!("[SYSCALL] NtIsProcessInJob(proc={:#x}, job={:#x})",
        process_handle, job_handle);

    let process = unsafe {
        if let Some(pid) = get_process_id(process_handle) {
            ps_lookup_process_by_id(pid) as *mut crate::ps::eprocess::EProcess
        } else {
            return 0xC0000008u32 as isize;
        }
    };

    if process.is_null() {
        return 0xC0000008u32 as isize;
    }

    unsafe {
        if job_handle == 0 {
            if (*process).job.is_null() {
                0xC0000001u32 as isize // Not in any job
            } else {
                0 // In some job
            }
        } else {
            if let Some(job_id) = get_job_id(job_handle) {
                let job = crate::ps::job::ps_lookup_job(job_id);
                if (*process).job == job as *mut u8 {
                    0 // In this job
                } else {
                    0xC0000001u32 as isize
                }
            } else {
                0xC0000008u32 as isize
            }
        }
    }
}

// ============================================================================
// System Information
// ============================================================================

/// System information class for NtQuerySystemInformation
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemInformationClass {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemCrashDumpInformation = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeperation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessInformation = 53,
    SystemLoadGdiDriverInSystemSpace = 54,
    SystemNumaProcessorMap = 55,
    SystemPrefetcherInformation = 56,
    SystemExtendedProcessInformation = 57,
    SystemRecommendedSharedDataAlignment = 58,
    SystemComPlusPackage = 59,
    SystemNumaAvailableMemory = 60,
    SystemProcessorPowerInformation = 61,
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
    SystemHotpatchInformation = 69,
    SystemObjectSecurityMode = 70,
    SystemWatchdogTimerHandler = 71,
    SystemWatchdogTimerInformation = 72,
    SystemLogicalProcessorInformation = 73,
    SystemWow64SharedInformationObsolete = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation = 76,
    SystemModuleInformationEx = 77,
    SystemVerifierTriageInformation = 78,
    SystemSuperfetchInformation = 79,
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    SystemThreadPriorityClientIdInformation = 82,
    SystemProcessorIdleCycleTimeInformation = 83,
    SystemVerifierCancellationInformation = 84,
    SystemProcessorPowerInformationEx = 85,
    SystemRefTraceInformation = 86,
    SystemSpecialPoolInformation = 87,
    SystemProcessIdInformation = 88,
    SystemErrorPortInformation = 89,
    SystemBootEnvironmentInformation = 90,
    SystemHypervisorInformation = 91,
    SystemVerifierInformationEx = 92,
    SystemTimeZoneInformation = 93,
    SystemImageFileExecutionOptionsInformation = 94,
    SystemCoverageInformation = 95,
    SystemPrefetchPatchInformation = 96,
    SystemVerifierFaultsInformation = 97,
    SystemSystemPartitionInformation = 98,
    SystemSystemDiskInformation = 99,
    SystemProcessorPerformanceDistribution = 100,
}

/// SYSTEM_BASIC_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemBasicInformation {
    pub reserved: u32,
    pub timer_resolution: u32,
    pub page_size: u32,
    pub number_of_physical_pages: u32,
    pub lowest_physical_page_number: u32,
    pub highest_physical_page_number: u32,
    pub allocation_granularity: u32,
    pub minimum_user_mode_address: usize,
    pub maximum_user_mode_address: usize,
    pub active_processors_affinity_mask: usize,
    pub number_of_processors: u8,
}

/// SYSTEM_PROCESSOR_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemProcessorInformation {
    pub processor_architecture: u16,
    pub processor_level: u16,
    pub processor_revision: u16,
    pub maximum_processors: u16,
    pub processor_feature_bits: u32,
}

/// SYSTEM_PERFORMANCE_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemPerformanceInformation {
    pub idle_process_time: i64,
    pub io_read_transfer_count: i64,
    pub io_write_transfer_count: i64,
    pub io_other_transfer_count: i64,
    pub io_read_operation_count: u32,
    pub io_write_operation_count: u32,
    pub io_other_operation_count: u32,
    pub available_pages: u32,
    pub committed_pages: u32,
    pub commit_limit: u32,
    pub peak_commitment: u32,
    pub page_fault_count: u32,
    pub copy_on_write_count: u32,
    pub transition_count: u32,
    pub cache_transition_count: u32,
    pub demand_zero_count: u32,
    pub page_read_count: u32,
    pub page_read_io_count: u32,
    pub cache_read_count: u32,
    pub cache_io_count: u32,
    pub dirty_pages_write_count: u32,
    pub dirty_write_io_count: u32,
    pub mapped_pages_write_count: u32,
    pub mapped_write_io_count: u32,
    pub paged_pool_pages: u32,
    pub non_paged_pool_pages: u32,
    pub paged_pool_allocs: u32,
    pub paged_pool_frees: u32,
    pub non_paged_pool_allocs: u32,
    pub non_paged_pool_frees: u32,
    pub free_system_ptes: u32,
    pub resident_system_code_page: u32,
    pub total_system_driver_pages: u32,
    pub total_system_code_pages: u32,
    pub non_paged_pool_lookaside_hits: u32,
    pub paged_pool_lookaside_hits: u32,
    pub available_paged_pool_pages: u32,
    pub resident_system_cache_page: u32,
    pub resident_paged_pool_page: u32,
    pub resident_system_driver_page: u32,
    pub cc_fast_read_no_wait: u32,
    pub cc_fast_read_wait: u32,
    pub cc_fast_read_resource_miss: u32,
    pub cc_fast_read_not_possible: u32,
    pub cc_fast_mdl_read_no_wait: u32,
    pub cc_fast_mdl_read_wait: u32,
    pub cc_fast_mdl_read_resource_miss: u32,
    pub cc_fast_mdl_read_not_possible: u32,
    pub cc_map_data_no_wait: u32,
    pub cc_map_data_wait: u32,
    pub cc_map_data_no_wait_miss: u32,
    pub cc_map_data_wait_miss: u32,
    pub cc_pin_mapped_data_count: u32,
    pub cc_pin_read_no_wait: u32,
    pub cc_pin_read_wait: u32,
    pub cc_pin_read_no_wait_miss: u32,
    pub cc_pin_read_wait_miss: u32,
    pub cc_copy_read_no_wait: u32,
    pub cc_copy_read_wait: u32,
    pub cc_copy_read_no_wait_miss: u32,
    pub cc_copy_read_wait_miss: u32,
    pub cc_mdl_read_no_wait: u32,
    pub cc_mdl_read_wait: u32,
    pub cc_mdl_read_no_wait_miss: u32,
    pub cc_mdl_read_wait_miss: u32,
    pub cc_read_ahead_ios: u32,
    pub cc_lazy_write_ios: u32,
    pub cc_lazy_write_pages: u32,
    pub cc_data_flushes: u32,
    pub cc_data_pages: u32,
    pub context_switches: u32,
    pub first_level_tb_fills: u32,
    pub second_level_tb_fills: u32,
    pub system_calls: u32,
}

/// SYSTEM_TIMEOFDAY_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemTimeOfDayInformation {
    pub boot_time: i64,
    pub current_time: i64,
    pub time_zone_bias: i64,
    pub time_zone_id: u32,
    pub reserved: u32,
    pub boot_time_bias: u64,
    pub sleep_time_bias: u64,
}

/// SYSTEM_PROCESS_INFORMATION structure (simplified)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemProcessInformation {
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub working_set_private_size: i64,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    pub create_time: i64,
    pub user_time: i64,
    pub kernel_time: i64,
    pub image_name_length: u16,
    pub image_name_maximum_length: u16,
    pub image_name_ptr: usize, // UNICODE_STRING buffer pointer
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
    pub handle_count: u32,
    pub session_id: u32,
    pub unique_process_key: usize,
    pub peak_virtual_size: usize,
    pub virtual_size: usize,
    pub page_fault_count: u32,
    pub peak_working_set_size: usize,
    pub working_set_size: usize,
    pub quota_peak_paged_pool_usage: usize,
    pub quota_paged_pool_usage: usize,
    pub quota_peak_non_paged_pool_usage: usize,
    pub quota_non_paged_pool_usage: usize,
    pub pagefile_usage: usize,
    pub peak_pagefile_usage: usize,
    pub private_page_count: usize,
    pub read_operation_count: i64,
    pub write_operation_count: i64,
    pub other_operation_count: i64,
    pub read_transfer_count: i64,
    pub write_transfer_count: i64,
    pub other_transfer_count: i64,
}

/// NtQuerySystemInformation - Query system-wide information
fn sys_query_system_information(
    info_class: usize,
    system_info: usize,
    system_info_length: usize,
    return_length: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    use core::ptr;

    crate::serial_println!("[SYSCALL] NtQuerySystemInformation(class={}, buf={:#x}, len={})",
        info_class, system_info, system_info_length);

    // Validate buffer pointer
    if system_info == 0 {
        return 0xC0000005u32 as isize; // STATUS_ACCESS_VIOLATION
    }

    match info_class as u32 {
        // SystemBasicInformation = 0
        0 => {
            let required_size = core::mem::size_of::<SystemBasicInformation>();

            // Write return length if provided
            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut u32, required_size as u32);
                }
            }

            if system_info_length < required_size {
                return 0xC0000004u32 as isize; // STATUS_INFO_LENGTH_MISMATCH
            }

            let stats = crate::mm::pfn::mm_get_stats();
            let info = SystemBasicInformation {
                reserved: 0,
                timer_resolution: 10000, // 1ms in 100ns units
                page_size: 4096,
                number_of_physical_pages: stats.total_pages,
                lowest_physical_page_number: 1,
                highest_physical_page_number: stats.total_pages,
                allocation_granularity: 65536, // 64KB
                minimum_user_mode_address: 0x10000,
                maximum_user_mode_address: 0x7FFFFFFEFFFF,
                active_processors_affinity_mask: 1, // Single processor
                number_of_processors: 1,
            };

            unsafe {
                ptr::write(system_info as *mut SystemBasicInformation, info);
            }

            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: BasicInfo - pages={}, page_size={}",
                info.number_of_physical_pages, info.page_size);

            0 // STATUS_SUCCESS
        }

        // SystemProcessorInformation = 1
        1 => {
            let required_size = core::mem::size_of::<SystemProcessorInformation>();

            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut u32, required_size as u32);
                }
            }

            if system_info_length < required_size {
                return 0xC0000004u32 as isize;
            }

            let info = SystemProcessorInformation {
                processor_architecture: 9, // PROCESSOR_ARCHITECTURE_AMD64
                processor_level: 6,        // Pentium Pro family
                processor_revision: 0x0F00,
                maximum_processors: 64,
                processor_feature_bits: 0x00000001, // Basic features
            };

            unsafe {
                ptr::write(system_info as *mut SystemProcessorInformation, info);
            }

            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: ProcessorInfo - arch=AMD64");

            0
        }

        // SystemPerformanceInformation = 2
        2 => {
            let required_size = core::mem::size_of::<SystemPerformanceInformation>();

            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut u32, required_size as u32);
                }
            }

            if system_info_length < required_size {
                return 0xC0000004u32 as isize;
            }

            let tick_count = crate::hal::apic::get_tick_count();
            let stats = crate::mm::pfn::mm_get_stats();

            let info = SystemPerformanceInformation {
                idle_process_time: 0,
                io_read_transfer_count: 0,
                io_write_transfer_count: 0,
                io_other_transfer_count: 0,
                io_read_operation_count: 0,
                io_write_operation_count: 0,
                io_other_operation_count: 0,
                available_pages: stats.free_pages + stats.zeroed_pages,
                committed_pages: 0,
                commit_limit: stats.total_pages,
                peak_commitment: 0,
                page_fault_count: 0,
                copy_on_write_count: 0,
                transition_count: 0,
                cache_transition_count: 0,
                demand_zero_count: 0,
                page_read_count: 0,
                page_read_io_count: 0,
                cache_read_count: 0,
                cache_io_count: 0,
                dirty_pages_write_count: 0,
                dirty_write_io_count: 0,
                mapped_pages_write_count: 0,
                mapped_write_io_count: 0,
                paged_pool_pages: 0,
                non_paged_pool_pages: 0,
                paged_pool_allocs: 0,
                paged_pool_frees: 0,
                non_paged_pool_allocs: 0,
                non_paged_pool_frees: 0,
                free_system_ptes: 0,
                resident_system_code_page: 0,
                total_system_driver_pages: 0,
                total_system_code_pages: 0,
                non_paged_pool_lookaside_hits: 0,
                paged_pool_lookaside_hits: 0,
                available_paged_pool_pages: 0,
                resident_system_cache_page: 0,
                resident_paged_pool_page: 0,
                resident_system_driver_page: 0,
                cc_fast_read_no_wait: 0,
                cc_fast_read_wait: 0,
                cc_fast_read_resource_miss: 0,
                cc_fast_read_not_possible: 0,
                cc_fast_mdl_read_no_wait: 0,
                cc_fast_mdl_read_wait: 0,
                cc_fast_mdl_read_resource_miss: 0,
                cc_fast_mdl_read_not_possible: 0,
                cc_map_data_no_wait: 0,
                cc_map_data_wait: 0,
                cc_map_data_no_wait_miss: 0,
                cc_map_data_wait_miss: 0,
                cc_pin_mapped_data_count: 0,
                cc_pin_read_no_wait: 0,
                cc_pin_read_wait: 0,
                cc_pin_read_no_wait_miss: 0,
                cc_pin_read_wait_miss: 0,
                cc_copy_read_no_wait: 0,
                cc_copy_read_wait: 0,
                cc_copy_read_no_wait_miss: 0,
                cc_copy_read_wait_miss: 0,
                cc_mdl_read_no_wait: 0,
                cc_mdl_read_wait: 0,
                cc_mdl_read_no_wait_miss: 0,
                cc_mdl_read_wait_miss: 0,
                cc_read_ahead_ios: 0,
                cc_lazy_write_ios: 0,
                cc_lazy_write_pages: 0,
                cc_data_flushes: 0,
                cc_data_pages: 0,
                context_switches: tick_count as u32, // Approximate
                first_level_tb_fills: 0,
                second_level_tb_fills: 0,
                system_calls: tick_count as u32 * 100, // Approximate
            };

            unsafe {
                ptr::write(system_info as *mut SystemPerformanceInformation, info);
            }

            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: PerformanceInfo - available_pages={}",
                info.available_pages);

            0
        }

        // SystemTimeOfDayInformation = 3
        3 => {
            let required_size = core::mem::size_of::<SystemTimeOfDayInformation>();

            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut u32, required_size as u32);
                }
            }

            if system_info_length < required_size {
                return 0xC0000004u32 as isize;
            }

            let tick_count = crate::hal::apic::get_tick_count();
            // Convert ticks to 100ns units (1 tick = 1ms = 10000 * 100ns)
            let current_time = tick_count as i64 * 10000;

            let info = SystemTimeOfDayInformation {
                boot_time: 0, // System boot time
                current_time,
                time_zone_bias: 0, // UTC
                time_zone_id: 0,
                reserved: 0,
                boot_time_bias: 0,
                sleep_time_bias: 0,
            };

            unsafe {
                ptr::write(system_info as *mut SystemTimeOfDayInformation, info);
            }

            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: TimeOfDay - current_time={}",
                current_time);

            0
        }

        // SystemProcessInformation = 5
        5 => {
            use crate::ps::EProcess;

            // Return list of all processes
            let mut offset = 0usize;
            let mut prev_entry_offset_ptr: Option<*mut u32> = None;

            unsafe {
                // Iterate through all processes
                for pid in 0..crate::ps::MAX_PROCESSES {
                    let process_ptr = crate::ps::ps_lookup_process_by_id(pid as u32);
                    if process_ptr.is_null() {
                        continue;
                    }

                    let entry_size = core::mem::size_of::<SystemProcessInformation>();

                    // Check if we have enough space
                    if offset + entry_size > system_info_length {
                        if return_length != 0 {
                            ptr::write(return_length as *mut u32, (offset + entry_size) as u32);
                        }
                        return 0xC0000004u32 as isize; // STATUS_INFO_LENGTH_MISMATCH
                    }

                    // Cast to proper EProcess type
                    let process = &*(process_ptr as *const EProcess);
                    let entry_ptr = (system_info + offset) as *mut SystemProcessInformation;

                    // Get thread count from the atomic field
                    let thread_count = process.thread_count.load(core::sync::atomic::Ordering::Relaxed);

                    let info = SystemProcessInformation {
                        next_entry_offset: 0, // Will be updated
                        number_of_threads: thread_count,
                        working_set_private_size: 0,
                        hard_fault_count: 0,
                        number_of_threads_high_watermark: thread_count,
                        cycle_time: 0,
                        create_time: process.create_time as i64,
                        user_time: 0,
                        kernel_time: 0,
                        image_name_length: 0,
                        image_name_maximum_length: 0,
                        image_name_ptr: 0,
                        base_priority: process.pcb.base_priority as i32,
                        unique_process_id: pid,
                        inherited_from_unique_process_id: process.inherited_from_unique_process_id as usize,
                        handle_count: 0, // Handle count not easily available
                        session_id: process.session_id,
                        unique_process_key: 0,
                        peak_virtual_size: 0,
                        virtual_size: 0,
                        page_fault_count: 0,
                        peak_working_set_size: 0,
                        working_set_size: 0,
                        quota_peak_paged_pool_usage: 0,
                        quota_paged_pool_usage: 0,
                        quota_peak_non_paged_pool_usage: 0,
                        quota_non_paged_pool_usage: 0,
                        pagefile_usage: 0,
                        peak_pagefile_usage: 0,
                        private_page_count: 0,
                        read_operation_count: 0,
                        write_operation_count: 0,
                        other_operation_count: 0,
                        read_transfer_count: 0,
                        write_transfer_count: 0,
                        other_transfer_count: 0,
                    };

                    ptr::write(entry_ptr, info);

                    // Update previous entry's next_entry_offset
                    if let Some(prev_ptr) = prev_entry_offset_ptr {
                        ptr::write(prev_ptr, offset as u32 - (prev_ptr as usize - system_info) as u32 + entry_size as u32);
                    }

                    prev_entry_offset_ptr = Some(&mut (*entry_ptr).next_entry_offset as *mut u32);
                    offset += entry_size;
                }

                // Update return length
                if return_length != 0 {
                    ptr::write(return_length as *mut u32, offset as u32);
                }

                crate::serial_println!("[SYSCALL] NtQuerySystemInformation: ProcessInfo - {} bytes", offset);
            }

            0
        }

        // SystemHandleInformation = 16
        16 => {
            // Simplified - just return count
            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut u32, 8);
                }
            }

            if system_info_length < 8 {
                return 0xC0000004u32 as isize;
            }

            unsafe {
                // Write handle count and first handle entry placeholder
                ptr::write(system_info as *mut u32, 0); // Number of handles
                ptr::write((system_info + 4) as *mut u32, 0);
            }

            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: HandleInfo");

            0
        }

        // SystemKernelDebuggerInformation = 35
        35 => {
            if return_length != 0 {
                unsafe {
                    ptr::write(return_length as *mut u32, 2);
                }
            }

            if system_info_length < 2 {
                return 0xC0000004u32 as isize;
            }

            unsafe {
                // KernelDebuggerEnabled, KernelDebuggerNotPresent
                ptr::write(system_info as *mut u8, 0); // Not enabled
                ptr::write((system_info + 1) as *mut u8, 1); // Not present
            }

            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: KernelDebuggerInfo");

            0
        }

        _ => {
            crate::serial_println!("[SYSCALL] NtQuerySystemInformation: unsupported class {}", info_class);
            0xC0000003u32 as isize // STATUS_INVALID_INFO_CLASS
        }
    }
}

/// NtQuerySystemTime - Query current system time
fn sys_query_system_time(
    system_time: usize,
    _arg2: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    if system_time == 0 {
        return 0xC0000005u32 as isize; // STATUS_ACCESS_VIOLATION
    }

    let tick_count = crate::hal::apic::get_tick_count();
    // Convert ticks to 100ns units (1 tick = 1ms = 10000 * 100ns)
    // Add a base time (Jan 1, 1601 to Jan 1, 2024 in 100ns units, approximately)
    let base_time: i64 = 132_537_600_000_000_000; // Approximate
    let current_time = base_time + (tick_count as i64 * 10000);

    unsafe {
        core::ptr::write(system_time as *mut i64, current_time);
    }

    crate::serial_println!("[SYSCALL] NtQuerySystemTime = {}", current_time);

    0
}

/// NtQueryPerformanceCounter - Query high-resolution performance counter
fn sys_query_performance_counter(
    performance_counter: usize,
    performance_frequency: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    if performance_counter == 0 {
        return 0xC0000005u32 as isize; // STATUS_ACCESS_VIOLATION
    }

    // Read TSC (Time Stamp Counter)
    let tsc: u64;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") tsc,
            out("rdx") _,
            options(nostack, nomem)
        );
    }

    unsafe {
        core::ptr::write(performance_counter as *mut i64, tsc as i64);
    }

    // If frequency requested, return approximate TSC frequency
    // Assume ~2GHz for now (would need CPUID calibration for accuracy)
    if performance_frequency != 0 {
        unsafe {
            core::ptr::write(performance_frequency as *mut i64, 2_000_000_000i64);
        }
    }

    crate::serial_println!("[SYSCALL] NtQueryPerformanceCounter = {}", tsc);

    0
}

// ============================================================================
// APC and Alert Syscalls
// ============================================================================

/// User-mode APC routine type
pub type UserApcRoutine = unsafe extern "C" fn(apc_context: usize, arg1: usize, arg2: usize);

/// NtQueueApcThread - Queue a user-mode APC to a thread
///
/// Queues an Asynchronous Procedure Call to be executed in the context
/// of the specified thread when it next enters an alertable wait state.
///
/// # Arguments
/// * `thread_handle` - Handle to the target thread
/// * `apc_routine` - User-mode APC routine to call
/// * `apc_context` - First argument to APC routine
/// * `arg1` - Second argument to APC routine
/// * `arg2` - Third argument to APC routine
fn sys_queue_apc_thread(
    thread_handle: usize,
    apc_routine: usize,
    apc_context: usize,
    _arg1: usize,
    _arg2: usize,
    _arg6: usize,
) -> isize {
    use crate::ke::{KThread, thread::{THREAD_POOL, constants::MAX_THREADS}};

    crate::serial_println!(
        "[SYSCALL] NtQueueApcThread(thread={}, routine={:#x}, ctx={:#x})",
        thread_handle, apc_routine, apc_context
    );

    // Validate parameters
    if thread_handle == 0 || apc_routine == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Find the thread by handle (treat as thread ID for now)
    let thread_id = thread_handle as u32;
    let mut target_thread: *mut KThread = core::ptr::null_mut();

    unsafe {
        for i in 0..MAX_THREADS {
            let thread = &mut THREAD_POOL[i];
            if thread.thread_id == thread_id && thread.state != crate::ke::thread::ThreadState::Terminated {
                target_thread = thread as *mut KThread;
                break;
            }
        }
    }

    if target_thread.is_null() {
        return 0xC000000Bu32 as isize; // STATUS_INVALID_HANDLE
    }

    // Check if thread accepts APCs
    unsafe {
        if !(*target_thread).apc_queueable {
            return 0xC0000061u32 as isize; // STATUS_APC_NOT_ALLOWED
        }

        // Queue the APC to the thread's user APC queue
        // The APC will be delivered when the thread enters an alertable wait
        // For now, we store the APC info directly - a full implementation would
        // use a proper APC queue structure

        // Use the kernel APC infrastructure to queue the APC
        let apc_state = &mut (*target_thread).apc_state;

        // For a simple implementation, we'll just mark that there's a pending APC
        // A full implementation would allocate a KAPC structure and queue it
        if !apc_state.user_apc_pending {
            apc_state.user_apc_pending = true;
            // Store APC parameters (simplified - real impl would use APC queue)
            // We're reusing some fields for now
            crate::serial_println!(
                "[APC] Queued user APC to thread {} (routine={:#x})",
                thread_id, apc_routine
            );
        } else {
            // APC queue full (simplified implementation)
            return 0xC000009Au32 as isize; // STATUS_INSUFFICIENT_RESOURCES
        }
    }

    0 // STATUS_SUCCESS
}

/// NtTestAlert - Test and clear the calling thread's alert status
///
/// If the current thread has a pending user alert, this function
/// delivers pending user APCs and returns STATUS_ALERTED.
fn sys_test_alert(
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    use crate::ke::prcb::get_current_prcb;

    crate::serial_println!("[SYSCALL] NtTestAlert");

    // Get current thread
    let prcb = get_current_prcb();
    if prcb.current_thread.is_null() {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }
    let current_thread = prcb.current_thread;

    unsafe {
        let apc_state = &mut (*current_thread).apc_state;

        // Check if there's a pending user alert
        if apc_state.user_apc_pending {
            // Clear the pending flag
            apc_state.user_apc_pending = false;

            // Deliver any pending user APCs
            // In a full implementation, we'd iterate the APC queue here
            crate::serial_println!("[SYSCALL] NtTestAlert: alert was pending, delivering APCs");

            // Return STATUS_ALERTED to indicate an alert was pending
            return 0x00000101u32 as isize; // STATUS_ALERTED
        }

        // Check for pending user APCs even without explicit alert
        // (This handles APCs queued via NtQueueApcThread)
        // apc_list_head[1] is the user-mode APC list
        if !apc_state.apc_list_head[1].is_empty() {
            crate::serial_println!("[SYSCALL] NtTestAlert: user APCs pending");
            return 0x00000101u32 as isize; // STATUS_ALERTED
        }
    }

    // No alert pending
    0 // STATUS_SUCCESS
}

/// NtAlertThread - Alert a thread
///
/// Sets the user-mode alert flag for the specified thread. If the thread
/// is currently in an alertable wait state, it will be woken up.
fn sys_alert_thread(
    thread_handle: usize,
    _arg2: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    use crate::ke::{KThread, thread::{THREAD_POOL, constants::MAX_THREADS, ThreadState}};

    crate::serial_println!("[SYSCALL] NtAlertThread(thread={})", thread_handle);

    if thread_handle == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Find the thread by handle (treat as thread ID for now)
    let thread_id = thread_handle as u32;
    let mut target_thread: *mut KThread = core::ptr::null_mut();

    unsafe {
        for i in 0..MAX_THREADS {
            let thread = &mut THREAD_POOL[i];
            if thread.thread_id == thread_id && thread.state != ThreadState::Terminated {
                target_thread = thread as *mut KThread;
                break;
            }
        }
    }

    if target_thread.is_null() {
        return 0xC000000Bu32 as isize; // STATUS_INVALID_HANDLE
    }

    unsafe {
        // Set the user alert pending flag
        (*target_thread).apc_state.user_apc_pending = true;

        // If the thread is in an alertable wait, wake it up
        if (*target_thread).state == ThreadState::Waiting && (*target_thread).alertable {
            // Set wait status to indicate alerted
            (*target_thread).wait_status = crate::ke::dispatcher::WaitStatus::Alerted.as_isize();

            // Make thread ready to run
            (*target_thread).state = ThreadState::Ready;

            crate::serial_println!("[SYSCALL] NtAlertThread: woke thread {} from alertable wait", thread_id);
        }
    }

    0 // STATUS_SUCCESS
}

/// NtAlertResumeThread - Alert and resume a thread
///
/// Alerts the thread and decrements its suspend count, potentially
/// resuming execution.
///
/// # Arguments
/// * `thread_handle` - Handle to the thread
/// * `previous_suspend_count` - Receives the previous suspend count
fn sys_alert_resume_thread(
    thread_handle: usize,
    previous_suspend_count: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    use crate::ke::{KThread, thread::{THREAD_POOL, constants::MAX_THREADS, ThreadState}};

    crate::serial_println!("[SYSCALL] NtAlertResumeThread(thread={})", thread_handle);

    if thread_handle == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Find the thread by handle
    let thread_id = thread_handle as u32;
    let mut target_thread: *mut KThread = core::ptr::null_mut();

    unsafe {
        for i in 0..MAX_THREADS {
            let thread = &mut THREAD_POOL[i];
            if thread.thread_id == thread_id && thread.state != ThreadState::Terminated {
                target_thread = thread as *mut KThread;
                break;
            }
        }
    }

    if target_thread.is_null() {
        return 0xC000000Bu32 as isize; // STATUS_INVALID_HANDLE
    }

    unsafe {
        // Get previous suspend count
        let prev_count = (*target_thread).suspend_count;

        // Write previous suspend count if requested
        if previous_suspend_count != 0 {
            core::ptr::write(previous_suspend_count as *mut u32, prev_count as u32);
        }

        // Alert the thread
        (*target_thread).apc_state.user_apc_pending = true;

        // Resume the thread (decrement suspend count)
        let new_count = (*target_thread).resume();

        crate::serial_println!(
            "[SYSCALL] NtAlertResumeThread: thread {} prev_count={} new_count={}",
            thread_id, prev_count, new_count
        );

        // If the thread was in an alertable wait, set alerted status
        if (*target_thread).state == ThreadState::Waiting && (*target_thread).alertable {
            (*target_thread).wait_status = crate::ke::dispatcher::WaitStatus::Alerted.as_isize();
            (*target_thread).state = ThreadState::Ready;
        }
    }

    0 // STATUS_SUCCESS
}

// ============================================================================
// Extended File I/O Syscalls
// ============================================================================

/// I/O Control codes use this format:
/// Bits 31-16: Device type
/// Bits 15-14: Required access
/// Bits 13-2: Function code
/// Bits 1-0: Transfer type (METHOD_BUFFERED, etc.)
pub mod ioctl {
    pub const METHOD_BUFFERED: u32 = 0;
    pub const METHOD_IN_DIRECT: u32 = 1;
    pub const METHOD_OUT_DIRECT: u32 = 2;
    pub const METHOD_NEITHER: u32 = 3;

    pub const FILE_ANY_ACCESS: u32 = 0;
    pub const FILE_READ_ACCESS: u32 = 1;
    pub const FILE_WRITE_ACCESS: u32 = 2;

    /// Extract device type from IOCTL code
    pub const fn device_type(code: u32) -> u32 {
        (code >> 16) & 0xFFFF
    }

    /// Extract function code from IOCTL code
    pub const fn function(code: u32) -> u32 {
        (code >> 2) & 0xFFF
    }

    /// Extract transfer type from IOCTL code
    pub const fn method(code: u32) -> u32 {
        code & 0x3
    }

    /// Extract required access from IOCTL code
    pub const fn access(code: u32) -> u32 {
        (code >> 14) & 0x3
    }
}

/// NtDeviceIoControlFile - Send control code to device driver
///
/// This is the primary interface for device-specific operations.
///
/// # Arguments
/// * `file_handle` - Handle to the device
/// * `event` - Optional event for async completion
/// * `io_status_block` - Receives completion status
/// * `io_control_code` - Device-specific control code
/// * `input_buffer` - Input data for the operation
/// * `input_buffer_length` - Size of input buffer
fn sys_device_io_control_file(
    file_handle: usize,
    _event: usize,
    io_status_block: usize,
    io_control_code: usize,
    input_buffer: usize,
    output_buffer: usize,
) -> isize {
    // Note: This syscall has more parameters, we're using a simplified signature
    // Real signature: (FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
    //                  IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength)

    crate::serial_println!(
        "[SYSCALL] NtDeviceIoControlFile(handle={}, ioctl={:#x})",
        file_handle, io_control_code
    );

    if file_handle == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    let ctl_code = io_control_code as u32;
    let device_type = ioctl::device_type(ctl_code);
    let function = ioctl::function(ctl_code);
    let method = ioctl::method(ctl_code);

    crate::serial_println!(
        "[SYSCALL] IOCTL: device_type={:#x}, function={}, method={}",
        device_type, function, method
    );

    // For now, we'll handle a few common device types
    match device_type {
        // FILE_DEVICE_CONSOLE = 0x0050
        0x0050 => {
            // Console device IOCTLs
            crate::serial_println!("[SYSCALL] Console IOCTL function {}", function);

            // Write status if provided
            if io_status_block != 0 {
                unsafe {
                    core::ptr::write(io_status_block as *mut i32, 0); // Status
                    core::ptr::write((io_status_block + 8) as *mut usize, 0); // Information
                }
            }

            0 // STATUS_SUCCESS
        }

        // FILE_DEVICE_DISK = 0x0007
        0x0007 => {
            // Disk device IOCTLs
            crate::serial_println!("[SYSCALL] Disk IOCTL function {}", function);

            match function {
                // IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x0000
                0 => {
                    // Would return disk geometry
                    if io_status_block != 0 {
                        unsafe {
                            core::ptr::write(io_status_block as *mut i32, 0);
                            core::ptr::write((io_status_block + 8) as *mut usize, 0);
                        }
                    }
                    0
                }
                _ => {
                    0xC00000BBu32 as isize // STATUS_NOT_SUPPORTED
                }
            }
        }

        // FILE_DEVICE_FILE_SYSTEM = 0x0009
        0x0009 => {
            // File system IOCTLs - forward to NtFsControlFile
            sys_fs_control_file(
                file_handle, 0, io_status_block,
                io_control_code, input_buffer, output_buffer
            )
        }

        _ => {
            crate::serial_println!(
                "[SYSCALL] NtDeviceIoControlFile: unsupported device type {:#x}",
                device_type
            );

            // For unsupported devices, return success but do nothing
            // A real implementation would route to the appropriate driver
            if io_status_block != 0 {
                unsafe {
                    core::ptr::write(io_status_block as *mut i32, 0);
                    core::ptr::write((io_status_block + 8) as *mut usize, 0);
                }
            }

            0 // STATUS_SUCCESS
        }
    }
}

/// NtFsControlFile - Send file system control code
///
/// Similar to NtDeviceIoControlFile but specifically for file system operations.
fn sys_fs_control_file(
    file_handle: usize,
    _event: usize,
    io_status_block: usize,
    fs_control_code: usize,
    input_buffer: usize,
    _output_buffer: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtFsControlFile(handle={}, fsctl={:#x})",
        file_handle, fs_control_code
    );

    if file_handle == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    let ctl_code = fs_control_code as u32;
    let function = ioctl::function(ctl_code);

    // Common FSCTL codes
    match function {
        // FSCTL_LOCK_VOLUME = 6
        6 => {
            crate::serial_println!("[SYSCALL] FSCTL_LOCK_VOLUME");
            // Lock the volume for exclusive access
            // For now, just succeed
            if io_status_block != 0 {
                unsafe {
                    core::ptr::write(io_status_block as *mut i32, 0);
                    core::ptr::write((io_status_block + 8) as *mut usize, 0);
                }
            }
            0
        }

        // FSCTL_UNLOCK_VOLUME = 7
        7 => {
            crate::serial_println!("[SYSCALL] FSCTL_UNLOCK_VOLUME");
            if io_status_block != 0 {
                unsafe {
                    core::ptr::write(io_status_block as *mut i32, 0);
                    core::ptr::write((io_status_block + 8) as *mut usize, 0);
                }
            }
            0
        }

        // FSCTL_DISMOUNT_VOLUME = 8
        8 => {
            crate::serial_println!("[SYSCALL] FSCTL_DISMOUNT_VOLUME");
            if io_status_block != 0 {
                unsafe {
                    core::ptr::write(io_status_block as *mut i32, 0);
                    core::ptr::write((io_status_block + 8) as *mut usize, 0);
                }
            }
            0
        }

        // FSCTL_IS_VOLUME_MOUNTED = 10
        10 => {
            crate::serial_println!("[SYSCALL] FSCTL_IS_VOLUME_MOUNTED");
            // Check if volume is mounted
            // For now, assume it is
            if io_status_block != 0 {
                unsafe {
                    core::ptr::write(io_status_block as *mut i32, 0);
                    core::ptr::write((io_status_block + 8) as *mut usize, 0);
                }
            }
            0
        }

        // FSCTL_GET_COMPRESSION = 15
        15 => {
            crate::serial_println!("[SYSCALL] FSCTL_GET_COMPRESSION");
            // Return compression state (0 = no compression)
            if input_buffer != 0 {
                unsafe {
                    core::ptr::write(input_buffer as *mut u16, 0); // COMPRESSION_FORMAT_NONE
                }
            }
            if io_status_block != 0 {
                unsafe {
                    core::ptr::write(io_status_block as *mut i32, 0);
                    core::ptr::write((io_status_block + 8) as *mut usize, 2);
                }
            }
            0
        }

        _ => {
            crate::serial_println!(
                "[SYSCALL] NtFsControlFile: unsupported FSCTL function {}",
                function
            );

            // Return success for unknown FSCTLs
            if io_status_block != 0 {
                unsafe {
                    core::ptr::write(io_status_block as *mut i32, 0);
                    core::ptr::write((io_status_block + 8) as *mut usize, 0);
                }
            }
            0
        }
    }
}

/// NtFlushBuffersFile - Flush file buffers to disk
///
/// Ensures all buffered data for the file has been written to the underlying storage.
fn sys_flush_buffers_file(
    file_handle: usize,
    io_status_block: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    use crate::fs::vfs::{vfs_get_handle, vfs_get_fs};

    crate::serial_println!("[SYSCALL] NtFlushBuffersFile(handle={})", file_handle);

    if file_handle == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Get file handle information
    let (fs_index, vnode_id) = unsafe {
        let fh = match vfs_get_handle(file_handle as u32) {
            Some(h) => h,
            None => return 0xC0000008u32 as isize, // STATUS_INVALID_HANDLE
        };
        (fh.flags as u16, fh.vnode_index as u64)
    };

    // Get filesystem and call sync
    let status = unsafe {
        match vfs_get_fs(fs_index) {
            Some(fs) => {
                if let Some(sync_fn) = fs.ops.sync {
                    sync_fn(fs_index, vnode_id)
                } else {
                    // No sync function - that's okay, just succeed
                    crate::fs::vfs::FsStatus::Success
                }
            }
            None => return 0xC000000Fu32 as isize, // STATUS_NO_SUCH_DEVICE
        }
    };

    // Write IO_STATUS_BLOCK if provided
    if io_status_block != 0 {
        unsafe {
            if status == crate::fs::vfs::FsStatus::Success {
                core::ptr::write(io_status_block as *mut i32, 0); // STATUS_SUCCESS
            } else {
                core::ptr::write(io_status_block as *mut i32, -1); // Error
            }
            core::ptr::write((io_status_block + 8) as *mut usize, 0); // Information
        }
    }

    if status == crate::fs::vfs::FsStatus::Success {
        crate::serial_println!("[SYSCALL] NtFlushBuffersFile: success");
        0 // STATUS_SUCCESS
    } else {
        crate::serial_println!("[SYSCALL] NtFlushBuffersFile: failed");
        0xC0000001u32 as isize // STATUS_UNSUCCESSFUL
    }
}

/// NtCancelIoFile - Cancel pending I/O operations on a file
///
/// Cancels all pending asynchronous I/O operations for the file handle
/// that were issued by the calling thread.
fn sys_cancel_io_file(
    file_handle: usize,
    io_status_block: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    crate::serial_println!("[SYSCALL] NtCancelIoFile(handle={})", file_handle);

    if file_handle == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // In our simple implementation, we don't have async I/O yet,
    // so there's nothing to cancel. Just return success.

    // Write IO_STATUS_BLOCK if provided
    if io_status_block != 0 {
        unsafe {
            core::ptr::write(io_status_block as *mut i32, 0); // STATUS_SUCCESS
            core::ptr::write((io_status_block + 8) as *mut usize, 0); // Information
        }
    }

    // Return STATUS_SUCCESS (no I/O was actually cancelled)
    // A real implementation would iterate pending IRPs and cancel them
    crate::serial_println!("[SYSCALL] NtCancelIoFile: no pending I/O to cancel");
    0 // STATUS_SUCCESS
}

/// File completion notification mode flags
mod file_completion_notification_flags {
    /// Skip I/O completion port notification if operation completes synchronously
    pub const FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: u8 = 0x01;
    /// Skip signaling the file handle event if operation completes
    pub const FILE_SKIP_SET_EVENT_ON_HANDLE: u8 = 0x02;
}

/// NtSetFileCompletionNotificationModes - Set file completion notification behavior
///
/// This syscall controls how I/O completion notifications are delivered for a file handle.
/// - FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: Skip IOCP notification for synchronous completions
/// - FILE_SKIP_SET_EVENT_ON_HANDLE: Skip signaling the file handle for completions
fn sys_set_file_completion_notification_modes(
    file_handle: usize,
    flags: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    use file_completion_notification_flags::*;

    crate::serial_println!(
        "[SYSCALL] NtSetFileCompletionNotificationModes(handle={:#x}, flags={:#x})",
        file_handle, flags
    );

    if file_handle == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Validate flags - only known flags allowed
    let valid_flags = FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE;
    if (flags as u8) & !valid_flags != 0 {
        crate::serial_println!("[SYSCALL] NtSetFileCompletionNotificationModes: invalid flags");
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Look up the file handle and set the notification modes
    unsafe {
        if let Some(fs_handle) = get_fs_handle(file_handle) {
            // In a full implementation, we would:
            // 1. Look up the FILE_OBJECT by handle
            // 2. Set the completion notification flags on it
            // For now, we just log and accept the request

            let skip_iocp = (flags as u8) & FILE_SKIP_COMPLETION_PORT_ON_SUCCESS != 0;
            let skip_event = (flags as u8) & FILE_SKIP_SET_EVENT_ON_HANDLE != 0;

            crate::serial_println!(
                "[SYSCALL] NtSetFileCompletionNotificationModes: fs_handle {} skip_iocp={} skip_event={}",
                fs_handle, skip_iocp, skip_event
            );

            // TODO: Store these flags on the file object for use during I/O completion

            0 // STATUS_SUCCESS
        } else {
            crate::serial_println!("[SYSCALL] NtSetFileCompletionNotificationModes: invalid handle");
            0xC0000008u32 as isize // STATUS_INVALID_HANDLE
        }
    }
}

// ============================================================================
// Section Syscalls (Additional)
// ============================================================================

/// NtOpenSection - Open an existing section object
///
/// Opens a handle to an existing section object by name.
fn sys_open_section(
    section_handle: usize,
    desired_access: usize,
    object_attributes: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtOpenSection(handle_out={:#x}, access={:#x}, attrs={:#x})",
        section_handle, desired_access, object_attributes
    );

    if section_handle == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Parse object attributes to get the name
    if object_attributes == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // For now, we don't have a section namespace, so we can't open by name
    // In a full implementation, we'd look up the section in the object namespace

    crate::serial_println!("[SYSCALL] NtOpenSection: section not found");
    0xC0000034u32 as isize // STATUS_OBJECT_NAME_NOT_FOUND
}

/// NtExtendSection - Extend a section object
///
/// Extends the size of a section object (and its backing file if applicable).
fn sys_extend_section(
    section_handle: usize,
    new_maximum_size: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtExtendSection(handle={}, new_size={:#x})",
        section_handle, new_maximum_size
    );

    if section_handle == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    if new_maximum_size == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Read the new maximum size from pointer
    let new_size = if new_maximum_size != 0 {
        unsafe { core::ptr::read(new_maximum_size as *const i64) }
    } else {
        return 0xC000000Du32 as isize;
    };

    crate::serial_println!("[SYSCALL] NtExtendSection: extending to {} bytes", new_size);

    // For now, just succeed - a real implementation would extend the section
    // and update the underlying file if it's a file-backed section
    0 // STATUS_SUCCESS
}

// ============================================================================
// I/O Completion Syscalls (Additional)
// ============================================================================

/// I/O Completion information structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoCompletionBasicInformation {
    /// Current depth (number of pending completions)
    pub depth: i32,
}

/// NtQueryIoCompletion - Query I/O completion port information
fn sys_query_io_completion(
    io_completion_handle: usize,
    io_completion_info_class: usize,
    io_completion_info: usize,
    io_completion_info_length: usize,
    return_length: usize,
    _arg6: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtQueryIoCompletion(handle={}, class={})",
        io_completion_handle, io_completion_info_class
    );

    if io_completion_handle == 0 || io_completion_info == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    match io_completion_info_class as u32 {
        // IoCompletionBasicInformation = 0
        0 => {
            let required_size = core::mem::size_of::<IoCompletionBasicInformation>();

            if return_length != 0 {
                unsafe {
                    core::ptr::write(return_length as *mut u32, required_size as u32);
                }
            }

            if io_completion_info_length < required_size {
                return 0xC0000004u32 as isize; // STATUS_INFO_LENGTH_MISMATCH
            }

            // Get actual queue depth from the completion port
            let port = io_completion_handle as *mut crate::io::iocp::IoCompletionPort;
            let depth = unsafe {
                if let Some(info) = crate::io::iocp::io_query_completion(port) {
                    info.queue_depth as i32
                } else {
                    0
                }
            };

            let info = IoCompletionBasicInformation { depth };

            unsafe {
                core::ptr::write(io_completion_info as *mut IoCompletionBasicInformation, info);
            }

            crate::serial_println!("[SYSCALL] NtQueryIoCompletion: depth={}", depth);
            STATUS_SUCCESS
        }
        _ => {
            0xC0000003u32 as isize // STATUS_INVALID_INFO_CLASS
        }
    }
}

// ============================================================================
// System Information Syscalls (Additional)
// ============================================================================

/// NtSetSystemInformation - Set system-wide information
///
/// Allows privileged processes to modify system configuration.
fn sys_set_system_information(
    system_info_class: usize,
    system_info: usize,
    system_info_length: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtSetSystemInformation(class={}, info={:#x}, len={})",
        system_info_class, system_info, system_info_length
    );

    // Most set operations require SeSystemEnvironmentPrivilege or similar
    // For now, we'll just allow some basic operations

    match system_info_class as u32 {
        // SystemTimeSlipNotification = 46
        46 => {
            crate::serial_println!("[SYSCALL] NtSetSystemInformation: TimeSlipNotification");
            0 // STATUS_SUCCESS
        }

        // SystemLoadGdiDriverInSystemSpace = 54
        54 => {
            crate::serial_println!("[SYSCALL] NtSetSystemInformation: LoadGdiDriver (not supported)");
            0xC00000BBu32 as isize // STATUS_NOT_SUPPORTED
        }

        // SystemFileCacheInformation = 21
        21 => {
            crate::serial_println!("[SYSCALL] NtSetSystemInformation: FileCacheInformation");
            // Would set cache limits - just succeed for now
            0 // STATUS_SUCCESS
        }

        // SystemPrioritySeperation = 39
        39 => {
            if system_info_length < 4 {
                return 0xC0000004u32 as isize; // STATUS_INFO_LENGTH_MISMATCH
            }
            let _separation = unsafe { core::ptr::read(system_info as *const u32) };
            crate::serial_println!("[SYSCALL] NtSetSystemInformation: PrioritySeparation");
            0 // STATUS_SUCCESS
        }

        // SystemRegistryQuotaInformation = 37
        37 => {
            crate::serial_println!("[SYSCALL] NtSetSystemInformation: RegistryQuota");
            0 // STATUS_SUCCESS
        }

        _ => {
            crate::serial_println!(
                "[SYSCALL] NtSetSystemInformation: unsupported class {}",
                system_info_class
            );
            0xC0000003u32 as isize // STATUS_INVALID_INFO_CLASS
        }
    }
}

// ============================================================================
// Object Namespace Syscalls - Symbolic Links
// ============================================================================

/// Maximum symbolic link target length
const MAX_SYMLINK_TARGET: usize = 512;

/// Symbolic link object storage
struct SymbolicLinkObject {
    /// Target path
    target: [u8; MAX_SYMLINK_TARGET],
    /// Target length
    target_len: usize,
    /// Object name
    name: [u8; 128],
    /// Name length
    name_len: usize,
    /// In use
    in_use: bool,
}

impl SymbolicLinkObject {
    const fn new() -> Self {
        Self {
            target: [0; MAX_SYMLINK_TARGET],
            target_len: 0,
            name: [0; 128],
            name_len: 0,
            in_use: false,
        }
    }
}

/// Maximum number of symbolic links
const MAX_SYMLINKS: usize = 64;

/// Global symbolic link table
static mut SYMLINK_TABLE: [SymbolicLinkObject; MAX_SYMLINKS] = {
    const INIT: SymbolicLinkObject = SymbolicLinkObject::new();
    [INIT; MAX_SYMLINKS]
};

/// NtCreateSymbolicLinkObject - Create a symbolic link in the object namespace
fn sys_create_symbolic_link_object(
    link_handle: usize,
    desired_access: usize,
    object_attributes: usize,
    target_name: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtCreateSymbolicLinkObject(handle_out={:#x}, access={:#x})",
        link_handle, desired_access
    );

    if link_handle == 0 || object_attributes == 0 || target_name == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Read target name (assume null-terminated ASCII for simplicity)
    let target_ptr = target_name as *const u8;
    let mut target_len = 0;
    unsafe {
        while *target_ptr.add(target_len) != 0 && target_len < MAX_SYMLINK_TARGET - 1 {
            target_len += 1;
        }
    }

    if target_len == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Find a free slot in the symlink table
    unsafe {
        for i in 0..MAX_SYMLINKS {
            if !SYMLINK_TABLE[i].in_use {
                // Initialize the symlink
                SYMLINK_TABLE[i].in_use = true;
                SYMLINK_TABLE[i].target_len = target_len;
                core::ptr::copy_nonoverlapping(
                    target_ptr,
                    SYMLINK_TABLE[i].target.as_mut_ptr(),
                    target_len
                );

                // Return handle (index + 1 to avoid 0)
                let handle = (i + 1) as u32;
                core::ptr::write(link_handle as *mut u32, handle);

                crate::serial_println!(
                    "[SYSCALL] NtCreateSymbolicLinkObject: created symlink handle {}",
                    handle
                );

                return 0; // STATUS_SUCCESS
            }
        }
    }

    0xC000009Au32 as isize // STATUS_INSUFFICIENT_RESOURCES
}

/// NtOpenSymbolicLinkObject - Open an existing symbolic link
fn sys_open_symbolic_link_object(
    link_handle: usize,
    desired_access: usize,
    object_attributes: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtOpenSymbolicLinkObject(handle_out={:#x}, access={:#x})",
        link_handle, desired_access
    );

    if link_handle == 0 || object_attributes == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // For now, we don't have name-based lookup implemented
    // Return not found
    0xC0000034u32 as isize // STATUS_OBJECT_NAME_NOT_FOUND
}

/// NtQuerySymbolicLinkObject - Query the target of a symbolic link
fn sys_query_symbolic_link_object(
    link_handle: usize,
    target_name: usize,
    return_length: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtQuerySymbolicLinkObject(handle={})",
        link_handle
    );

    if link_handle == 0 || target_name == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    let index = link_handle.wrapping_sub(1);
    if index >= MAX_SYMLINKS {
        return 0xC0000008u32 as isize; // STATUS_INVALID_HANDLE
    }

    unsafe {
        if !SYMLINK_TABLE[index].in_use {
            return 0xC0000008u32 as isize; // STATUS_INVALID_HANDLE
        }

        let symlink = &SYMLINK_TABLE[index];

        // Return length if requested
        if return_length != 0 {
            core::ptr::write(return_length as *mut u32, symlink.target_len as u32);
        }

        // Copy target to output buffer
        // Assume target_name points to a UNICODE_STRING structure
        // For simplicity, we'll just write the ASCII bytes
        core::ptr::copy_nonoverlapping(
            symlink.target.as_ptr(),
            target_name as *mut u8,
            symlink.target_len
        );

        crate::serial_println!(
            "[SYSCALL] NtQuerySymbolicLinkObject: target_len={}",
            symlink.target_len
        );
    }

    0 // STATUS_SUCCESS
}

// ============================================================================
// Object Namespace Syscalls - Directory Objects
// ============================================================================

/// Directory object entry
struct DirectoryObjectEntry {
    /// Object name
    name: [u8; 128],
    /// Name length
    name_len: usize,
    /// Object type name
    type_name: [u8; 32],
    /// Type name length
    type_name_len: usize,
}

impl DirectoryObjectEntry {
    const fn new() -> Self {
        Self {
            name: [0; 128],
            name_len: 0,
            type_name: [0; 32],
            type_name_len: 0,
        }
    }
}

/// Directory object
struct DirectoryObject {
    /// Directory name
    name: [u8; 128],
    /// Name length
    name_len: usize,
    /// Entries in this directory
    entries: [DirectoryObjectEntry; 32],
    /// Number of entries
    entry_count: usize,
    /// In use
    in_use: bool,
}

impl DirectoryObject {
    const fn new() -> Self {
        const ENTRY_INIT: DirectoryObjectEntry = DirectoryObjectEntry::new();
        Self {
            name: [0; 128],
            name_len: 0,
            entries: [ENTRY_INIT; 32],
            entry_count: 0,
            in_use: false,
        }
    }
}

/// Maximum number of directory objects
const MAX_DIRECTORIES: usize = 32;

/// Global directory object table
static mut DIRECTORY_TABLE: [DirectoryObject; MAX_DIRECTORIES] = {
    const INIT: DirectoryObject = DirectoryObject::new();
    [INIT; MAX_DIRECTORIES]
};

/// NtCreateDirectoryObject - Create a directory in the object namespace
fn sys_create_directory_object(
    directory_handle: usize,
    desired_access: usize,
    _object_attributes: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtCreateDirectoryObject(handle_out={:#x}, access={:#x})",
        directory_handle, desired_access
    );

    if directory_handle == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Find a free slot
    unsafe {
        for i in 0..MAX_DIRECTORIES {
            if !DIRECTORY_TABLE[i].in_use {
                DIRECTORY_TABLE[i].in_use = true;
                DIRECTORY_TABLE[i].entry_count = 0;

                // Return handle
                let handle = (i + 1) as u32;
                core::ptr::write(directory_handle as *mut u32, handle);

                crate::serial_println!(
                    "[SYSCALL] NtCreateDirectoryObject: created directory handle {}",
                    handle
                );

                return 0; // STATUS_SUCCESS
            }
        }
    }

    0xC000009Au32 as isize // STATUS_INSUFFICIENT_RESOURCES
}

/// NtOpenDirectoryObject - Open an existing directory object
fn sys_open_directory_object(
    directory_handle: usize,
    desired_access: usize,
    object_attributes: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtOpenDirectoryObject(handle_out={:#x}, access={:#x})",
        directory_handle, desired_access
    );

    if directory_handle == 0 || object_attributes == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // For well-known directories, return a handle
    // Check if opening root directory "\"
    // For now, just return not found
    0xC0000034u32 as isize // STATUS_OBJECT_NAME_NOT_FOUND
}

/// Directory entry information returned by NtQueryDirectoryObject
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ObjectDirectoryInformation {
    /// Object name (UNICODE_STRING)
    pub name_length: u16,
    pub name_max_length: u16,
    pub name_buffer: u64,
    /// Type name (UNICODE_STRING)
    pub type_name_length: u16,
    pub type_name_max_length: u16,
    pub type_name_buffer: u64,
}

/// NtQueryDirectoryObject - Enumerate objects in a directory
fn sys_query_directory_object(
    directory_handle: usize,
    buffer: usize,
    _length: usize,
    return_single_entry: usize,
    restart_scan: usize,
    context: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtQueryDirectoryObject(handle={}, single={}, restart={})",
        directory_handle, return_single_entry, restart_scan
    );

    if directory_handle == 0 || buffer == 0 || context == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    let index = directory_handle.wrapping_sub(1);
    if index >= MAX_DIRECTORIES {
        return 0xC0000008u32 as isize; // STATUS_INVALID_HANDLE
    }

    unsafe {
        if !DIRECTORY_TABLE[index].in_use {
            return 0xC0000008u32 as isize; // STATUS_INVALID_HANDLE
        }

        let dir = &DIRECTORY_TABLE[index];

        // Read current context (enumeration index)
        let mut ctx = core::ptr::read(context as *const u32) as usize;
        if restart_scan != 0 {
            ctx = 0;
        }

        if ctx >= dir.entry_count {
            // No more entries
            return 0x8000001Au32 as isize; // STATUS_NO_MORE_ENTRIES
        }

        // For now, just update context and return no entries
        // A full implementation would copy entry information to the buffer
        core::ptr::write(context as *mut u32, (ctx + 1) as u32);
    }

    0x8000001Au32 as isize // STATUS_NO_MORE_ENTRIES
}

// ============================================================================
// Security Syscalls
// ============================================================================

/// Access mask constants
pub mod access_mask {
    pub const DELETE: u32 = 0x00010000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const SYNCHRONIZE: u32 = 0x00100000;
    pub const STANDARD_RIGHTS_ALL: u32 = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE;
    pub const GENERIC_READ: u32 = 0x80000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    pub const GENERIC_ALL: u32 = 0x10000000;
}

/// NtAccessCheck - Check access rights against a security descriptor
///
/// Performs an access check against a security descriptor using the
/// specified client token.
fn sys_access_check(
    security_descriptor: usize,
    client_token: usize,
    desired_access: usize,
    generic_mapping_ptr: usize,
    _privilege_set: usize,
    granted_access: usize,
) -> isize {
    use crate::se::access::{se_access_check, GenericMapping};
    use crate::se::descriptor::SimpleSecurityDescriptor;
    use crate::se::token::{TOKEN_POOL, TOKEN_POOL_BITMAP, MAX_TOKENS};

    crate::serial_println!(
        "[SYSCALL] NtAccessCheck(sd={:#x}, token={:#x}, access={:#x})",
        security_descriptor, client_token, desired_access
    );

    if security_descriptor == 0 || granted_access == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Get the token from handle
    let token_id = match unsafe { get_token_id(client_token) } {
        Some(id) => id,
        None => {
            crate::serial_println!("[SYSCALL] NtAccessCheck: invalid token handle");
            return STATUS_INVALID_HANDLE;
        }
    };

    // Find the token in the pool
    let token = unsafe {
        let mut found: *const crate::se::token::Token = core::ptr::null();
        for i in 0..MAX_TOKENS {
            if TOKEN_POOL_BITMAP & (1 << i) != 0 && TOKEN_POOL[i].token_id.low_part == token_id {
                found = &TOKEN_POOL[i];
                break;
            }
        }
        if found.is_null() {
            // Fall back to system token
            crate::se::token::se_get_system_token()
        } else {
            found as *mut crate::se::token::Token
        }
    };

    // Parse generic mapping if provided
    let mapping = if generic_mapping_ptr != 0 {
        unsafe {
            GenericMapping {
                generic_read: *((generic_mapping_ptr) as *const u32),
                generic_write: *((generic_mapping_ptr + 4) as *const u32),
                generic_execute: *((generic_mapping_ptr + 8) as *const u32),
                generic_all: *((generic_mapping_ptr + 12) as *const u32),
            }
        }
    } else {
        GenericMapping::new()
    };

    // For now, create a permissive security descriptor
    // A full implementation would parse the user-provided SECURITY_DESCRIPTOR structure
    // TODO: Parse security_descriptor pointer into SimpleSecurityDescriptor
    let sd = SimpleSecurityDescriptor::new();

    // Perform the access check
    match se_access_check(unsafe { &*token }, &sd, desired_access as u32, &mapping) {
        Ok(access) => {
            unsafe {
                // Write granted access
                core::ptr::write(granted_access as *mut u32, access);
                // Write access status (TRUE = access granted)
                let access_status = (granted_access + 4) as *mut u32;
                core::ptr::write(access_status, 1); // TRUE
            }
            crate::serial_println!("[SYSCALL] NtAccessCheck: granted access {:#x}", access);
            STATUS_SUCCESS
        }
        Err(_) => {
            unsafe {
                // Write zero granted access
                core::ptr::write(granted_access as *mut u32, 0);
                // Write access status (FALSE = access denied)
                let access_status = (granted_access + 4) as *mut u32;
                core::ptr::write(access_status, 0); // FALSE
            }
            crate::serial_println!("[SYSCALL] NtAccessCheck: access denied");
            0xC0000022u32 as isize // STATUS_ACCESS_DENIED
        }
    }
}

/// NtPrivilegeCheck - Check if token has required privileges
fn sys_privilege_check(
    client_token: usize,
    required_privileges: usize,
    result: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    use crate::se::token::{TOKEN_POOL, TOKEN_POOL_BITMAP, MAX_TOKENS};
    use crate::se::privilege::Luid;

    crate::serial_println!(
        "[SYSCALL] NtPrivilegeCheck(token={:#x}, privs={:#x})",
        client_token, required_privileges
    );

    if client_token == 0 || required_privileges == 0 || result == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Get the token from handle
    let token_id = match unsafe { get_token_id(client_token) } {
        Some(id) => id,
        None => {
            crate::serial_println!("[SYSCALL] NtPrivilegeCheck: invalid token handle");
            return STATUS_INVALID_HANDLE;
        }
    };

    // Find the token in the pool
    let token = unsafe {
        let mut found: *const crate::se::token::Token = core::ptr::null();
        for i in 0..MAX_TOKENS {
            if TOKEN_POOL_BITMAP & (1 << i) != 0 && TOKEN_POOL[i].token_id.low_part == token_id {
                found = &TOKEN_POOL[i];
                break;
            }
        }
        if found.is_null() {
            crate::se::token::se_get_system_token()
        } else {
            found as *mut crate::se::token::Token
        }
    };

    // Parse PRIVILEGE_SET structure:
    // PrivilegeCount: u32
    // Control: u32
    // Privilege[]: array of LUID_AND_ATTRIBUTES (LUID: u64, Attributes: u32)
    let priv_count = unsafe { *(required_privileges as *const u32) };
    let _control = unsafe { *((required_privileges + 4) as *const u32) };

    let mut all_held = true;

    for i in 0..priv_count as usize {
        let priv_ptr = required_privileges + 8 + (i * 12); // Each entry is 12 bytes
        let luid_low = unsafe { *(priv_ptr as *const u32) };
        let luid_high = unsafe { *((priv_ptr + 4) as *const i32) };
        let luid = Luid::new(luid_low, luid_high);

        // Check if token has this privilege enabled
        let held = unsafe { (*token).is_privilege_enabled(luid) };
        if !held {
            all_held = false;
            crate::serial_println!("[SYSCALL] NtPrivilegeCheck: missing privilege LUID({},{})",
                luid_low, luid_high);
        }
    }

    unsafe {
        core::ptr::write(result as *mut u32, if all_held { 1 } else { 0 });
    }

    crate::serial_println!("[SYSCALL] NtPrivilegeCheck: result={}", all_held);
    STATUS_SUCCESS
}

/// NtAccessCheckAndAuditAlarm - Access check with audit generation
fn sys_access_check_and_audit_alarm(
    _subsystem_name: usize,
    _handle_id: usize,
    _object_type_name: usize,
    _object_name: usize,
    security_descriptor: usize,
    desired_access: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtAccessCheckAndAuditAlarm(access={:#x})",
        desired_access
    );

    // This syscall requires SeAuditPrivilege
    // For now, just perform a basic access check

    if security_descriptor == 0 {
        return 0xC000000Du32 as isize; // STATUS_INVALID_PARAMETER
    }

    // Grant access for now
    crate::serial_println!("[SYSCALL] NtAccessCheckAndAuditAlarm: access granted (no audit)");
    0 // STATUS_SUCCESS
}

// ============================================================================
// Power Management Syscalls
// ============================================================================

/// Power action type
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum PowerAction {
    None = 0,
    Reserved = 1,
    Sleep = 2,
    Hibernate = 3,
    Shutdown = 4,
    ShutdownReset = 5,
    ShutdownOff = 6,
    WarmEject = 7,
}

/// System power state
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum SystemPowerState {
    Unspecified = 0,
    Working = 1,     // S0
    Sleeping1 = 2,   // S1
    Sleeping2 = 3,   // S2
    Sleeping3 = 4,   // S3 (Standby)
    Hibernate = 5,   // S4
    Shutdown = 6,    // S5
    Maximum = 7,
}

/// NtSetSystemPowerState - Set the system power state
///
/// Initiates a transition to the specified system power state.
/// Requires SeShutdownPrivilege.
fn sys_set_system_power_state(
    system_action: usize,
    min_system_state: usize,
    flags: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtSetSystemPowerState(action={}, min_state={}, flags={:#x})",
        system_action, min_system_state, flags
    );

    // Check privilege (SeShutdownPrivilege required)
    // For now, we'll allow the operations

    match system_action as u32 {
        // PowerActionShutdown = 4
        4 => {
            crate::serial_println!("[POWER] System shutdown requested");
            // In a real implementation, we'd initiate shutdown sequence
            // For now, just log it
            0 // STATUS_SUCCESS
        }

        // PowerActionShutdownReset = 5
        5 => {
            crate::serial_println!("[POWER] System reboot requested");
            // Would initiate reboot
            0 // STATUS_SUCCESS
        }

        // PowerActionShutdownOff = 6
        6 => {
            crate::serial_println!("[POWER] System power off requested");
            0 // STATUS_SUCCESS
        }

        // PowerActionSleep = 2
        2 => {
            crate::serial_println!("[POWER] System sleep requested (not supported)");
            0xC00000BBu32 as isize // STATUS_NOT_SUPPORTED
        }

        // PowerActionHibernate = 3
        3 => {
            crate::serial_println!("[POWER] Hibernate requested (not supported)");
            0xC00000BBu32 as isize // STATUS_NOT_SUPPORTED
        }

        _ => {
            crate::serial_println!("[POWER] Unknown power action {}", system_action);
            0xC000000Du32 as isize // STATUS_INVALID_PARAMETER
        }
    }
}

/// NtInitiatePowerAction - Initiate a power action with options
fn sys_initiate_power_action(
    system_action: usize,
    min_system_state: usize,
    flags: usize,
    asynchronous: usize,
    _arg5: usize,
    _arg6: usize,
) -> isize {
    crate::serial_println!(
        "[SYSCALL] NtInitiatePowerAction(action={}, min_state={}, flags={:#x}, async={})",
        system_action, min_system_state, flags, asynchronous
    );

    // Similar to NtSetSystemPowerState but with async option
    // Forward to NtSetSystemPowerState for now
    sys_set_system_power_state(system_action, min_system_state, flags, 0, 0, 0)
}
