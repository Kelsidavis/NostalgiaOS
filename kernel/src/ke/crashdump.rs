//! Crash Dump Support
//!
//! This module implements crash dump (memory dump) functionality for
//! capturing system state during a bugcheck for post-mortem analysis.
//!
//! # Dump Types
//!
//! - **Minidump**: Small dump containing key system state (~256KB-2MB)
//! - **Kernel dump**: Memory used by the kernel
//! - **Complete dump**: Full physical memory dump
//!
//! # Minidump Contents
//!
//! A minidump contains:
//! - Dump header with system information
//! - Bug check code and parameters
//! - CPU context (registers) for the faulting thread
//! - Kernel stack of the faulting thread
//! - List of loaded modules
//! - Basic memory information
//!
//! # File Format
//!
//! Windows dump files use a specific format:
//! - Signature: "PAGE" (0x45474150)
//! - Valid dump: "DU64" (0x34365544) for x64
//! - Header with system state
//! - Memory regions

use core::ptr;
use crate::arch::x86_64::context::KTrapFrame;

/// Dump file signature (ASCII "PAGE")
pub const DUMP_SIGNATURE: u32 = 0x4547_4150;

/// Valid dump signature for x64 (ASCII "DU64")
pub const DUMP_VALID_DUMP64: u32 = 0x3436_5544;

/// Valid dump signature for x86 (ASCII "DUMP")
pub const DUMP_VALID_DUMP: u32 = 0x504D_5544;

/// Dump type constants
pub mod dump_type {
    /// Full memory dump
    pub const DUMP_TYPE_FULL: u32 = 1;
    /// Kernel memory dump
    pub const DUMP_TYPE_KERNEL: u32 = 2;
    /// Mini dump (triage dump)
    pub const DUMP_TYPE_MINI: u32 = 3;
    /// Automatic (system decides)
    pub const DUMP_TYPE_AUTO: u32 = 4;
}

/// Dump header (matches Windows DUMP_HEADER64)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DumpHeader64 {
    /// Signature: "PAGE" (0x45474150)
    pub signature: u32,
    /// Valid dump indicator: "DU64" for valid x64 dump
    pub valid_dump: u32,
    /// Major version (e.g., 15 for Windows 10)
    pub major_version: u32,
    /// Minor version (build number)
    pub minor_version: u32,
    /// Directory table base (CR3)
    pub directory_table_base: u64,
    /// PFN database virtual address
    pub pfn_database: u64,
    /// Loaded module list
    pub ps_loaded_module_list: u64,
    /// Active process head
    pub ps_active_process_head: u64,
    /// Machine type (IMAGE_FILE_MACHINE_AMD64 = 0x8664)
    pub machine_image_type: u32,
    /// Number of processors
    pub number_of_processors: u32,
    /// Bug check code
    pub bug_check_code: u32,
    /// Padding
    pub _pad1: u32,
    /// Bug check parameter 1
    pub bug_check_parameter1: u64,
    /// Bug check parameter 2
    pub bug_check_parameter2: u64,
    /// Bug check parameter 3
    pub bug_check_parameter3: u64,
    /// Bug check parameter 4
    pub bug_check_parameter4: u64,
    /// Reserved (version string in some versions)
    pub version_user: [u8; 32],
    /// KdDebuggerDataBlock pointer
    pub kd_debugger_data_block: u64,
    /// Physical memory block
    pub physical_memory_block: PhysicalMemoryDescriptor,
    /// Context record for the thread that crashed
    pub context_record: [u8; 1232], // CONTEXT structure
    /// Exception record
    pub exception_record: [u8; 152], // EXCEPTION_RECORD64
    /// Dump type
    pub dump_type: u32,
    /// Padding
    pub _pad2: u32,
    /// Required dump space
    pub required_dump_space: u64,
    /// System time
    pub system_time: u64,
    /// Comment (can be used for crash reason)
    pub comment: [u8; 128],
    /// System uptime
    pub system_uptime: u64,
    /// Mini dump fields offset
    pub mini_dump_fields: u32,
    /// Secondary data state
    pub secondary_data_state: u32,
    /// Product type
    pub product_type: u32,
    /// Suite mask
    pub suite_mask: u32,
    /// Writer status
    pub writer_status: u32,
    /// Unused
    pub unused: u8,
    /// KdSecondaryVersion
    pub kd_secondary_version: u8,
    /// Reserved
    pub reserved: [u8; 2],
    /// Reserved
    pub _reserved: [u8; 4016],
}

impl DumpHeader64 {
    pub const fn new() -> Self {
        Self {
            signature: 0,
            valid_dump: 0,
            major_version: 0,
            minor_version: 0,
            directory_table_base: 0,
            pfn_database: 0,
            ps_loaded_module_list: 0,
            ps_active_process_head: 0,
            machine_image_type: 0,
            number_of_processors: 0,
            bug_check_code: 0,
            _pad1: 0,
            bug_check_parameter1: 0,
            bug_check_parameter2: 0,
            bug_check_parameter3: 0,
            bug_check_parameter4: 0,
            version_user: [0; 32],
            kd_debugger_data_block: 0,
            physical_memory_block: PhysicalMemoryDescriptor::new(),
            context_record: [0; 1232],
            exception_record: [0; 152],
            dump_type: 0,
            _pad2: 0,
            required_dump_space: 0,
            system_time: 0,
            comment: [0; 128],
            system_uptime: 0,
            mini_dump_fields: 0,
            secondary_data_state: 0,
            product_type: 0,
            suite_mask: 0,
            writer_status: 0,
            unused: 0,
            kd_secondary_version: 0,
            reserved: [0; 2],
            _reserved: [0; 4016],
        }
    }
}

/// Physical memory descriptor
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PhysicalMemoryDescriptor {
    /// Number of runs
    pub number_of_runs: u32,
    /// Padding
    pub _pad: u32,
    /// Number of pages
    pub number_of_pages: u64,
    /// Memory runs (up to 86 runs fit in header)
    pub runs: [PhysicalMemoryRun; 86],
}

impl PhysicalMemoryDescriptor {
    pub const fn new() -> Self {
        Self {
            number_of_runs: 0,
            _pad: 0,
            number_of_pages: 0,
            runs: [PhysicalMemoryRun::new(); 86],
        }
    }
}

/// Physical memory run descriptor
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PhysicalMemoryRun {
    /// Base page
    pub base_page: u64,
    /// Page count
    pub page_count: u64,
}

impl PhysicalMemoryRun {
    pub const fn new() -> Self {
        Self {
            base_page: 0,
            page_count: 0,
        }
    }
}

/// Minidump header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MinidumpHeader {
    /// Signature: "MDMP" (0x504D444D)
    pub signature: u32,
    /// Version
    pub version: u32,
    /// Number of streams
    pub number_of_streams: u32,
    /// Stream directory RVA (offset from file start)
    pub stream_directory_rva: u32,
    /// Checksum
    pub checksum: u32,
    /// Timestamp
    pub time_date_stamp: u32,
    /// Flags
    pub flags: u64,
}

impl MinidumpHeader {
    pub const fn new() -> Self {
        Self {
            signature: 0x504D_444D, // "MDMP"
            version: 0xA793, // Standard minidump version
            number_of_streams: 0,
            stream_directory_rva: 0,
            checksum: 0,
            time_date_stamp: 0,
            flags: 0,
        }
    }
}

/// Minidump stream types
pub mod stream_type {
    pub const UNUSED_STREAM: u32 = 0;
    pub const RESERVED_STREAM_0: u32 = 1;
    pub const RESERVED_STREAM_1: u32 = 2;
    pub const THREAD_LIST_STREAM: u32 = 3;
    pub const MODULE_LIST_STREAM: u32 = 4;
    pub const MEMORY_LIST_STREAM: u32 = 5;
    pub const EXCEPTION_STREAM: u32 = 6;
    pub const SYSTEM_INFO_STREAM: u32 = 7;
    pub const THREAD_EX_LIST_STREAM: u32 = 8;
    pub const MEMORY64_LIST_STREAM: u32 = 9;
    pub const COMMENT_STREAM_A: u32 = 10;
    pub const COMMENT_STREAM_W: u32 = 11;
    pub const HANDLE_DATA_STREAM: u32 = 12;
    pub const FUNCTION_TABLE_STREAM: u32 = 13;
    pub const UNLOADED_MODULE_LIST_STREAM: u32 = 14;
    pub const MISC_INFO_STREAM: u32 = 15;
    pub const MEMORY_INFO_LIST_STREAM: u32 = 16;
    pub const THREAD_INFO_LIST_STREAM: u32 = 17;
    pub const HANDLE_OPERATION_LIST_STREAM: u32 = 18;
    pub const LAST_RESERVED_STREAM: u32 = 0xFFFF;
}

/// Minidump stream directory entry
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MinidumpDirectory {
    /// Stream type
    pub stream_type: u32,
    /// Data size
    pub data_size: u32,
    /// RVA (offset in file)
    pub rva: u32,
}

impl MinidumpDirectory {
    pub const fn new() -> Self {
        Self {
            stream_type: 0,
            data_size: 0,
            rva: 0,
        }
    }
}

// ============================================================================
// Crash Dump State
// ============================================================================

/// Maximum dump buffer size (2MB)
pub const MAX_DUMP_BUFFER_SIZE: usize = 2 * 1024 * 1024;

/// Crash dump configuration
#[derive(Debug, Clone, Copy)]
pub struct CrashDumpConfig {
    /// Dump type to create
    pub dump_type: u32,
    /// Overwrite existing dump file
    pub overwrite: bool,
    /// Auto-reboot after dump
    pub auto_reboot: bool,
    /// Send alert on crash
    pub send_alert: bool,
    /// Write debug info
    pub write_debug_info: bool,
    /// Dump enabled
    pub enabled: bool,
}

impl Default for CrashDumpConfig {
    fn default() -> Self {
        Self {
            dump_type: dump_type::DUMP_TYPE_MINI,
            overwrite: true,
            auto_reboot: false,
            send_alert: false,
            write_debug_info: true,
            enabled: true,
        }
    }
}

/// Static dump configuration
static mut DUMP_CONFIG: CrashDumpConfig = CrashDumpConfig {
    dump_type: dump_type::DUMP_TYPE_MINI,
    overwrite: true,
    auto_reboot: false,
    send_alert: false,
    write_debug_info: true,
    enabled: true,
};

/// Crash dump buffer (static allocation for safety during crash)
static mut DUMP_BUFFER: [u8; 4096] = [0u8; 4096];

/// Last crash dump info
#[derive(Debug, Clone, Copy)]
pub struct CrashDumpInfo {
    /// Dump was written successfully
    pub success: bool,
    /// Dump size in bytes
    pub size: usize,
    /// Bug check code
    pub bug_check_code: u32,
    /// Timestamp
    pub timestamp: u64,
}

impl Default for CrashDumpInfo {
    fn default() -> Self {
        Self {
            success: false,
            size: 0,
            bug_check_code: 0,
            timestamp: 0,
        }
    }
}

static mut LAST_DUMP_INFO: CrashDumpInfo = CrashDumpInfo {
    success: false,
    size: 0,
    bug_check_code: 0,
    timestamp: 0,
};

// ============================================================================
// Crash Dump API
// ============================================================================

/// Get crash dump configuration
pub fn get_config() -> CrashDumpConfig {
    unsafe { DUMP_CONFIG }
}

/// Set crash dump configuration
pub fn set_config(config: CrashDumpConfig) {
    unsafe {
        DUMP_CONFIG = config;
    }
}

/// Check if crash dump is enabled
pub fn is_enabled() -> bool {
    unsafe { DUMP_CONFIG.enabled }
}

/// Enable or disable crash dump
pub fn set_enabled(enabled: bool) {
    unsafe {
        DUMP_CONFIG.enabled = enabled;
    }
}

/// Get last crash dump info
pub fn get_last_dump_info() -> CrashDumpInfo {
    unsafe { LAST_DUMP_INFO }
}

/// Write a crash dump header to buffer
///
/// This creates a minimal dump header that can be written to storage.
pub unsafe fn write_dump_header(
    bug_check_code: u32,
    param1: u64,
    param2: u64,
    param3: u64,
    param4: u64,
    context: Option<&KTrapFrame>,
) -> usize {
    let header = &mut *(DUMP_BUFFER.as_mut_ptr() as *mut DumpHeader64);

    // Clear header
    ptr::write_bytes(header, 0, 1);

    // Set signature
    header.signature = DUMP_SIGNATURE;
    header.valid_dump = DUMP_VALID_DUMP64;

    // Version info
    header.major_version = 5; // NT 5.2
    header.minor_version = 3790; // Windows Server 2003

    // Machine type
    header.machine_image_type = 0x8664; // AMD64

    // CPU count
    header.number_of_processors = 1; // TODO: Get from KPCR

    // Bug check info
    header.bug_check_code = bug_check_code;
    header.bug_check_parameter1 = param1;
    header.bug_check_parameter2 = param2;
    header.bug_check_parameter3 = param3;
    header.bug_check_parameter4 = param4;

    // Dump type
    header.dump_type = DUMP_CONFIG.dump_type;

    // System time
    header.system_time = crate::rtl::rtl_get_system_time() as u64;

    // Copy context if available
    if let Some(ctx) = context {
        // Copy relevant context fields
        // The context_record field is 1232 bytes which should fit our context
        let ctx_bytes = core::slice::from_raw_parts(
            ctx as *const KTrapFrame as *const u8,
            core::mem::size_of::<KTrapFrame>().min(1232),
        );
        header.context_record[..ctx_bytes.len()].copy_from_slice(ctx_bytes);
    }

    // Write version string
    let version = b"NostalgOS 0.1.0";
    header.version_user[..version.len().min(31)].copy_from_slice(&version[..version.len().min(31)]);

    // Physical memory info (minimal)
    header.physical_memory_block.number_of_runs = 1;
    header.physical_memory_block.number_of_pages = 0x10000; // 256MB placeholder
    header.physical_memory_block.runs[0].base_page = 0;
    header.physical_memory_block.runs[0].page_count = 0x10000;

    // Required dump space
    header.required_dump_space = 0x100000; // 1MB minimum

    core::mem::size_of::<DumpHeader64>()
}

/// Write crash dump to storage
///
/// This is called during bugcheck to write the dump to disk.
/// Note: In a full implementation, this would use the crash dump driver
/// chain to write directly to disk without the normal I/O stack.
pub unsafe fn write_crash_dump(
    bug_check_code: u32,
    param1: u64,
    param2: u64,
    param3: u64,
    param4: u64,
) -> bool {
    if !DUMP_CONFIG.enabled {
        return false;
    }

    crate::serial_println!("[CRASHDUMP] Writing crash dump...");
    crate::serial_println!("[CRASHDUMP] Bug check: {:#010x}", bug_check_code);
    crate::serial_println!("[CRASHDUMP] Parameters: {:#x}, {:#x}, {:#x}, {:#x}",
        param1, param2, param3, param4);

    // Write the dump header
    let header_size = write_dump_header(bug_check_code, param1, param2, param3, param4, None);

    crate::serial_println!("[CRASHDUMP] Header size: {} bytes", header_size);

    // In a full implementation, we would:
    // 1. Locate the crash dump driver (usually a disk driver marked for crash dump)
    // 2. Write the header
    // 3. Write physical memory pages
    // 4. Write additional metadata

    // For now, we just output to serial for debugging
    crate::serial_println!("[CRASHDUMP] Dump header written to serial (storage not implemented)");

    // Update last dump info
    LAST_DUMP_INFO = CrashDumpInfo {
        success: true,
        size: header_size,
        bug_check_code,
        timestamp: crate::rtl::rtl_get_system_time() as u64,
    };

    true
}

/// Get dump buffer pointer (for direct writing)
pub fn get_dump_buffer() -> &'static [u8] {
    unsafe { &DUMP_BUFFER }
}

/// Get dump buffer size
pub fn get_dump_buffer_size() -> usize {
    unsafe { DUMP_BUFFER.len() }
}

// ============================================================================
// Crash Dump Statistics
// ============================================================================

/// Crash dump statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct CrashDumpStats {
    /// Total dumps attempted
    pub dumps_attempted: u32,
    /// Successful dumps
    pub dumps_succeeded: u32,
    /// Failed dumps
    pub dumps_failed: u32,
    /// Last dump size
    pub last_dump_size: usize,
    /// Last dump timestamp
    pub last_dump_time: u64,
}

static mut DUMP_STATS: CrashDumpStats = CrashDumpStats {
    dumps_attempted: 0,
    dumps_succeeded: 0,
    dumps_failed: 0,
    last_dump_size: 0,
    last_dump_time: 0,
};

/// Get crash dump statistics
pub fn get_stats() -> CrashDumpStats {
    unsafe { DUMP_STATS }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize crash dump subsystem
pub fn init() {
    unsafe {
        DUMP_CONFIG = CrashDumpConfig::default();
        LAST_DUMP_INFO = CrashDumpInfo::default();
        DUMP_STATS = CrashDumpStats::default();
    }

    crate::serial_println!("[KE] Crash dump subsystem initialized (type: mini)");
}
