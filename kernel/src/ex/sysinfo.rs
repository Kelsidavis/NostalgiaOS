//! System Information Query and Set
//!
//! Implements NtQuerySystemInformation and NtSetSystemInformation.
//! These are the primary APIs for querying system configuration and statistics.
//!
//! Based on Windows Server 2003 base/ntos/ex/sysinfo.c

use crate::etw::NtStatus;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::Ordering;

extern crate alloc;

/// System Information Classes
///
/// These values match Windows NT 5.2 SYSTEM_INFORMATION_CLASS enum.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemInformationClass {
    /// Basic system information (CPU count, memory size, etc.)
    SystemBasicInformation = 0,
    /// Processor architecture information (obsolete)
    SystemProcessorInformation = 1,
    /// System performance counters
    SystemPerformanceInformation = 2,
    /// Time of day information
    SystemTimeOfDayInformation = 3,
    /// Path information (not implemented)
    SystemPathInformation = 4,
    /// Process and thread information
    SystemProcessInformation = 5,
    /// System call count information
    SystemCallCountInformation = 6,
    /// Device count information
    SystemDeviceInformation = 7,
    /// Per-processor performance information
    SystemProcessorPerformanceInformation = 8,
    /// System flags (NtGlobalFlag)
    SystemFlagsInformation = 9,
    /// Call time information
    SystemCallTimeInformation = 10,
    /// Loaded modules information
    SystemModuleInformation = 11,
    /// Lock information
    SystemLocksInformation = 12,
    /// Stack trace information
    SystemStackTraceInformation = 13,
    /// Paged pool information
    SystemPagedPoolInformation = 14,
    /// Non-paged pool information
    SystemNonPagedPoolInformation = 15,
    /// Handle information
    SystemHandleInformation = 16,
    /// Object information
    SystemObjectInformation = 17,
    /// Page file information
    SystemPageFileInformation = 18,
    /// VDM instruction emulation info
    SystemVdmInstemulInformation = 19,
    /// VDM BOP information
    SystemVdmBopInformation = 20,
    /// File cache information
    SystemFileCacheInformation = 21,
    /// Pool tag information
    SystemPoolTagInformation = 22,
    /// Interrupt information
    SystemInterruptInformation = 23,
    /// DPC behavior information
    SystemDpcBehaviorInformation = 24,
    /// Full memory information
    SystemFullMemoryInformation = 25,
    /// Load GDI driver information
    SystemLoadGdiDriverInformation = 26,
    /// Unload GDI driver information
    SystemUnloadGdiDriverInformation = 27,
    /// Time adjustment information
    SystemTimeAdjustmentInformation = 28,
    /// Summary memory information
    SystemSummaryMemoryInformation = 29,
    /// Mirror memory information
    SystemMirrorMemoryInformation = 30,
    /// Performance trace information
    SystemPerformanceTraceInformation = 31,
    /// Obsolete
    SystemObsolete0 = 32,
    /// Exception information
    SystemExceptionInformation = 33,
    /// Crash dump state information
    SystemCrashDumpStateInformation = 34,
    /// Kernel debugger information
    SystemKernelDebuggerInformation = 35,
    /// Context switch information
    SystemContextSwitchInformation = 36,
    /// Registry quota information
    SystemRegistryQuotaInformation = 37,
    /// Extend service table
    SystemExtendServiceTableInformation = 38,
    /// Priority separation
    SystemPrioritySeperation = 39,
    /// Verifier add driver
    SystemVerifierAddDriverInformation = 40,
    /// Verifier remove driver
    SystemVerifierRemoveDriverInformation = 41,
    /// Processor idle information
    SystemProcessorIdleInformation = 42,
    /// Legacy driver information
    SystemLegacyDriverInformation = 43,
    /// Current time zone information
    SystemCurrentTimeZoneInformation = 44,
    /// Lookaside information
    SystemLookasideInformation = 45,
    /// Time slip notification
    SystemTimeSlipNotification = 46,
    /// Session create
    SystemSessionCreate = 47,
    /// Session detach
    SystemSessionDetach = 48,
    /// Session information
    SystemSessionInformation = 49,
    /// Range start information
    SystemRangeStartInformation = 50,
    /// Verifier information
    SystemVerifierInformation = 51,
    /// Verifier thunk extend
    SystemVerifierThunkExtend = 52,
    /// Session process information
    SystemSessionProcessInformation = 53,
    /// Load GDI driver in system space
    SystemLoadGdiDriverInSystemSpace = 54,
    /// NUMA processor map
    SystemNumaProcessorMap = 55,
    /// Prefetcher information
    SystemPrefetcherInformation = 56,
    /// Extended process information
    SystemExtendedProcessInformation = 57,
    /// Recommended shared data alignment
    SystemRecommendedSharedDataAlignment = 58,
    /// COM+ package
    SystemComPlusPackage = 59,
    /// NUMA available memory
    SystemNumaAvailableMemory = 60,
    /// Processor power information
    SystemProcessorPowerInformation = 61,
    /// Emulation basic information
    SystemEmulationBasicInformation = 62,
    /// Emulation processor information
    SystemEmulationProcessorInformation = 63,
    /// Extended handle information
    SystemExtendedHandleInformation = 64,
    /// Lost delayed write information
    SystemLostDelayedWriteInformation = 65,
    /// Big pool information
    SystemBigPoolInformation = 66,
    /// Session pool tag information
    SystemSessionPoolTagInformation = 67,
    /// Session mapped view information
    SystemSessionMappedViewInformation = 68,
    /// Hotpatch information
    SystemHotpatchInformation = 69,
    /// Object security mode
    SystemObjectSecurityMode = 70,
    /// Watchdog timer handler
    SystemWatchdogTimerHandler = 71,
    /// Watchdog timer information
    SystemWatchdogTimerInformation = 72,
    /// Logical processor information
    SystemLogicalProcessorInformation = 73,
}

impl SystemInformationClass {
    /// Convert from u32 to SystemInformationClass
    pub fn from_u32(value: u32) -> Option<Self> {
        if value <= 73 {
            Some(unsafe { core::mem::transmute(value) })
        } else {
            None
        }
    }
}

/// Basic system information structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemBasicInformation {
    /// Reserved (always 0)
    pub reserved: u32,
    /// Timer resolution in 100ns units
    pub timer_resolution: u32,
    /// Page size in bytes
    pub page_size: u32,
    /// Number of physical pages
    pub number_of_physical_pages: usize,
    /// Lowest physical page number
    pub lowest_physical_page_number: usize,
    /// Highest physical page number
    pub highest_physical_page_number: usize,
    /// Allocation granularity
    pub allocation_granularity: u32,
    /// Minimum user mode address
    pub minimum_user_mode_address: usize,
    /// Maximum user mode address
    pub maximum_user_mode_address: usize,
    /// Active processors affinity mask
    pub active_processors_affinity_mask: usize,
    /// Number of processors
    pub number_of_processors: u8,
}

/// Processor information structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProcessorInformation {
    /// Processor architecture
    pub processor_architecture: u16,
    /// Processor level
    pub processor_level: u16,
    /// Processor revision
    pub processor_revision: u16,
    /// Reserved
    pub reserved: u16,
    /// Processor feature bits
    pub processor_feature_bits: u32,
}

/// Processor architecture constants
pub mod processor_architecture {
    pub const INTEL: u16 = 0;
    pub const MIPS: u16 = 1;
    pub const ALPHA: u16 = 2;
    pub const PPC: u16 = 3;
    pub const SHX: u16 = 4;
    pub const ARM: u16 = 5;
    pub const IA64: u16 = 6;
    pub const ALPHA64: u16 = 7;
    pub const AMD64: u16 = 9;
}

/// Time of day information structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTimeOfDayInformation {
    /// Boot time (100ns since 1601)
    pub boot_time: i64,
    /// Current time (100ns since 1601)
    pub current_time: i64,
    /// Time zone bias
    pub time_zone_bias: i64,
    /// Time zone ID
    pub time_zone_id: u32,
    /// Reserved
    pub reserved: u32,
    /// Boot time bias
    pub boot_time_bias: u64,
    /// Sleep time bias
    pub sleep_time_bias: u64,
}

/// Performance information structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemPerformanceInformation {
    /// Idle process time
    pub idle_process_time: i64,
    /// I/O read transfer count
    pub io_read_transfer_count: i64,
    /// I/O write transfer count
    pub io_write_transfer_count: i64,
    /// I/O other transfer count
    pub io_other_transfer_count: i64,
    /// I/O read operation count
    pub io_read_operation_count: u32,
    /// I/O write operation count
    pub io_write_operation_count: u32,
    /// I/O other operation count
    pub io_other_operation_count: u32,
    /// Available pages
    pub available_pages: u32,
    /// Committed pages
    pub committed_pages: usize,
    /// Commit limit
    pub commit_limit: usize,
    /// Peak commitment
    pub peak_commitment: usize,
    /// Page fault count
    pub page_fault_count: u32,
    /// Copy on write count
    pub copy_on_write_count: u32,
    /// Transition count
    pub transition_count: u32,
    /// Cache transition count
    pub cache_transition_count: u32,
    /// Demand zero count
    pub demand_zero_count: u32,
    /// Page read count
    pub page_read_count: u32,
    /// Page read I/O count
    pub page_read_io_count: u32,
    /// Cache read count
    pub cache_read_count: u32,
    /// Cache I/O count
    pub cache_io_count: u32,
    /// Dirty pages write count
    pub dirty_pages_write_count: u32,
    /// Dirty write I/O count
    pub dirty_write_io_count: u32,
    /// Mapped pages write count
    pub mapped_pages_write_count: u32,
    /// Mapped write I/O count
    pub mapped_write_io_count: u32,
    /// Paged pool pages
    pub paged_pool_pages: u32,
    /// Non-paged pool pages
    pub non_paged_pool_pages: u32,
    /// Paged pool allocs
    pub paged_pool_allocs: u32,
    /// Paged pool frees
    pub paged_pool_frees: u32,
    /// Non-paged pool allocs
    pub non_paged_pool_allocs: u32,
    /// Non-paged pool frees
    pub non_paged_pool_frees: u32,
    /// Free system PTEs
    pub free_system_ptes: u32,
    /// Resident system code page
    pub resident_system_code_page: u32,
    /// Total system driver pages
    pub total_system_driver_pages: u32,
    /// Total system code pages
    pub total_system_code_pages: u32,
    /// Non-paged pool lookaside hits
    pub non_paged_pool_lookaside_hits: u32,
    /// Paged pool lookaside hits
    pub paged_pool_lookaside_hits: u32,
    /// Available paged pool pages
    pub available_paged_pool_pages: u32,
    /// Resident system cache page
    pub resident_system_cache_page: u32,
    /// Resident paged pool page
    pub resident_paged_pool_page: u32,
    /// Resident system driver page
    pub resident_system_driver_page: u32,
    /// Cache manager fast read no wait
    pub cc_fast_read_no_wait: u32,
    /// Cache manager fast read wait
    pub cc_fast_read_wait: u32,
    /// Cache manager fast read resource miss
    pub cc_fast_read_resource_miss: u32,
    /// Cache manager fast read not possible
    pub cc_fast_read_not_possible: u32,
    /// Cache manager fast MDL read no wait
    pub cc_fast_mdl_read_no_wait: u32,
    /// Cache manager fast MDL read wait
    pub cc_fast_mdl_read_wait: u32,
    /// Cache manager fast MDL read resource miss
    pub cc_fast_mdl_read_resource_miss: u32,
    /// Cache manager fast MDL read not possible
    pub cc_fast_mdl_read_not_possible: u32,
    /// Cache manager map data no wait
    pub cc_map_data_no_wait: u32,
    /// Cache manager map data wait
    pub cc_map_data_wait: u32,
    /// Cache manager map data no wait miss
    pub cc_map_data_no_wait_miss: u32,
    /// Cache manager map data wait miss
    pub cc_map_data_wait_miss: u32,
    /// Cache manager pin mapped data count
    pub cc_pin_mapped_data_count: u32,
    /// Cache manager pin read no wait
    pub cc_pin_read_no_wait: u32,
    /// Cache manager pin read wait
    pub cc_pin_read_wait: u32,
    /// Cache manager pin read no wait miss
    pub cc_pin_read_no_wait_miss: u32,
    /// Cache manager pin read wait miss
    pub cc_pin_read_wait_miss: u32,
    /// Cache manager copy read no wait
    pub cc_copy_read_no_wait: u32,
    /// Cache manager copy read wait
    pub cc_copy_read_wait: u32,
    /// Cache manager copy read no wait miss
    pub cc_copy_read_no_wait_miss: u32,
    /// Cache manager copy read wait miss
    pub cc_copy_read_wait_miss: u32,
    /// Cache manager MDL read no wait
    pub cc_mdl_read_no_wait: u32,
    /// Cache manager MDL read wait
    pub cc_mdl_read_wait: u32,
    /// Cache manager MDL read no wait miss
    pub cc_mdl_read_no_wait_miss: u32,
    /// Cache manager MDL read wait miss
    pub cc_mdl_read_wait_miss: u32,
    /// Cache manager read ahead I/Os
    pub cc_read_ahead_ios: u32,
    /// Cache manager lazy write I/Os
    pub cc_lazy_write_ios: u32,
    /// Cache manager lazy write pages
    pub cc_lazy_write_pages: u32,
    /// Cache manager data flushes
    pub cc_data_flushes: u32,
    /// Cache manager data pages
    pub cc_data_pages: u32,
    /// Context switches
    pub context_switches: u32,
    /// First level TB fills
    pub first_level_tb_fills: u32,
    /// Second level TB fills
    pub second_level_tb_fills: u32,
    /// System calls
    pub system_calls: u32,
}

/// Device information structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDeviceInformation {
    /// Number of disks
    pub number_of_disks: u32,
    /// Number of floppies
    pub number_of_floppies: u32,
    /// Number of CD-ROMs
    pub number_of_cd_roms: u32,
    /// Number of tapes
    pub number_of_tapes: u32,
    /// Number of serial ports
    pub number_of_serial_ports: u32,
    /// Number of parallel ports
    pub number_of_parallel_ports: u32,
}

/// Per-processor performance information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProcessorPerformanceInformation {
    /// Idle time
    pub idle_time: i64,
    /// Kernel time
    pub kernel_time: i64,
    /// User time
    pub user_time: i64,
    /// DPC time
    pub dpc_time: i64,
    /// Interrupt time
    pub interrupt_time: i64,
    /// Interrupt count
    pub interrupt_count: u32,
}

/// Exception information structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemExceptionInformation {
    /// Alignment fixup count
    pub alignment_fixup_count: u32,
    /// Exception dispatch count
    pub exception_dispatch_count: u32,
    /// Floating emulation count
    pub floating_emulation_count: u32,
    /// Byte/word emulation count
    pub byte_word_emulation_count: u32,
}

/// Kernel debugger information structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemKernelDebuggerInformation {
    /// Kernel debugger enabled
    pub kernel_debugger_enabled: bool,
    /// Kernel debugger not present
    pub kernel_debugger_not_present: bool,
}

/// Registry quota information structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRegistryQuotaInformation {
    /// Registry quota allowed
    pub registry_quota_allowed: u32,
    /// Registry quota used
    pub registry_quota_used: u32,
    /// Paged pool size
    pub paged_pool_size: usize,
}

/// Page file information structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SystemPageFileInformation {
    /// Next entry offset
    pub next_entry_offset: u32,
    /// Total size in pages
    pub total_size: u32,
    /// Total in use pages
    pub total_in_use: u32,
    /// Peak usage in pages
    pub peak_usage: u32,
    /// Page file name
    pub page_file_name: [u16; 260],
}

impl Default for SystemPageFileInformation {
    fn default() -> Self {
        Self {
            next_entry_offset: 0,
            total_size: 0,
            total_in_use: 0,
            peak_usage: 0,
            page_file_name: [0u16; 260],
        }
    }
}

/// Handle table entry information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemHandleTableEntryInfo {
    /// Unique process ID
    pub unique_process_id: u16,
    /// Creator back trace index
    pub creator_back_trace_index: u16,
    /// Object type index
    pub object_type_index: u8,
    /// Handle attributes
    pub handle_attributes: u8,
    /// Handle value
    pub handle_value: u16,
    /// Object pointer
    pub object: usize,
    /// Granted access
    pub granted_access: u32,
}

/// Handle information structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SystemHandleInformation {
    /// Number of handles
    pub number_of_handles: u32,
    /// Handle entries (variable length)
    pub handles: Vec<SystemHandleTableEntryInfo>,
}

impl Default for SystemHandleInformation {
    fn default() -> Self {
        Self {
            number_of_handles: 0,
            handles: Vec::new(),
        }
    }
}

/// Context switch information
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemContextSwitchInformation {
    /// Context switches
    pub context_switches: u32,
    /// Find any count
    pub find_any: u32,
    /// Find last count
    pub find_last: u32,
    /// Find ideal count
    pub find_ideal: u32,
    /// Idle any count
    pub idle_any: u32,
    /// Idle current count
    pub idle_current: u32,
    /// Idle last count
    pub idle_last: u32,
    /// Idle ideal count
    pub idle_ideal: u32,
    /// Preempt any count
    pub preempt_any: u32,
    /// Preempt current count
    pub preempt_current: u32,
    /// Preempt last count
    pub preempt_last: u32,
    /// Switch to idle count
    pub switch_to_idle: u32,
}

/// Interrupt information structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemInterruptInformation {
    /// Context switches
    pub context_switches: u32,
    /// DPC count
    pub dpc_count: u32,
    /// DPC rate
    pub dpc_rate: u32,
    /// Time increment
    pub time_increment: u32,
    /// DPC bypass count
    pub dpc_bypass_count: u32,
    /// APC bypass count
    pub apc_bypass_count: u32,
}

/// Processor idle information structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProcessorIdleInformation {
    /// Idle time
    pub idle_time: u64,
    /// C1 time
    pub c1_time: u64,
    /// C2 time
    pub c2_time: u64,
    /// C3 time
    pub c3_time: u64,
    /// C1 transitions
    pub c1_transitions: u32,
    /// C2 transitions
    pub c2_transitions: u32,
    /// C3 transitions
    pub c3_transitions: u32,
    /// Padding
    pub padding: u32,
}

/// Logical processor relationship
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogicalProcessorRelationship {
    /// Processor core
    #[default]
    RelationProcessorCore = 0,
    /// NUMA node
    RelationNumaNode = 1,
}

/// Logical processor information structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemLogicalProcessorInformation {
    /// Processor mask
    pub processor_mask: usize,
    /// Relationship type
    pub relationship: LogicalProcessorRelationship,
    /// Flags for processor core
    pub flags: u8,
    /// Reserved
    pub reserved: [u8; 7],
    /// NUMA node or reserved
    pub node_or_reserved: u64,
}

/// Query system information
///
/// This is the main entry point for querying system information.
pub fn nt_query_system_information(
    system_information_class: SystemInformationClass,
    system_information: &mut [u8],
) -> Result<usize, NtStatus> {
    match system_information_class {
        SystemInformationClass::SystemBasicInformation => {
            query_basic_information(system_information)
        }
        SystemInformationClass::SystemProcessorInformation => {
            query_processor_information(system_information)
        }
        SystemInformationClass::SystemTimeOfDayInformation => {
            query_time_of_day_information(system_information)
        }
        SystemInformationClass::SystemPerformanceInformation => {
            query_performance_information(system_information)
        }
        SystemInformationClass::SystemDeviceInformation => {
            query_device_information(system_information)
        }
        SystemInformationClass::SystemProcessorPerformanceInformation => {
            query_processor_performance_information(system_information)
        }
        SystemInformationClass::SystemExceptionInformation => {
            query_exception_information(system_information)
        }
        SystemInformationClass::SystemKernelDebuggerInformation => {
            query_kernel_debugger_information(system_information)
        }
        SystemInformationClass::SystemContextSwitchInformation => {
            query_context_switch_information(system_information)
        }
        SystemInformationClass::SystemInterruptInformation => {
            query_interrupt_information(system_information)
        }
        SystemInformationClass::SystemRegistryQuotaInformation => {
            query_registry_quota_information(system_information)
        }
        _ => Err(NtStatus::InvalidInfoClass),
    }
}

fn query_basic_information(buffer: &mut [u8]) -> Result<usize, NtStatus> {
    let required_size = size_of::<SystemBasicInformation>();
    if buffer.len() < required_size {
        return Err(NtStatus::InfoLengthMismatch);
    }

    let info = SystemBasicInformation {
        reserved: 0,
        timer_resolution: 156250, // 15.625ms in 100ns units
        page_size: 4096,
        number_of_physical_pages: get_total_physical_pages(),
        lowest_physical_page_number: 1,
        highest_physical_page_number: get_highest_physical_page(),
        allocation_granularity: 65536, // 64KB
        minimum_user_mode_address: 0x10000,
        maximum_user_mode_address: 0x7FFFFFFEFFFF, // x86_64 user space
        active_processors_affinity_mask: get_active_processor_mask(),
        number_of_processors: get_number_of_processors(),
    };

    // Copy to buffer
    let info_bytes = unsafe {
        core::slice::from_raw_parts(&info as *const _ as *const u8, required_size)
    };
    buffer[..required_size].copy_from_slice(info_bytes);

    Ok(required_size)
}

fn query_processor_information(buffer: &mut [u8]) -> Result<usize, NtStatus> {
    let required_size = size_of::<SystemProcessorInformation>();
    if buffer.len() < required_size {
        return Err(NtStatus::InfoLengthMismatch);
    }

    let info = SystemProcessorInformation {
        processor_architecture: processor_architecture::AMD64,
        processor_level: get_processor_level(),
        processor_revision: get_processor_revision(),
        reserved: 0,
        processor_feature_bits: get_processor_features(),
    };

    let info_bytes = unsafe {
        core::slice::from_raw_parts(&info as *const _ as *const u8, required_size)
    };
    buffer[..required_size].copy_from_slice(info_bytes);

    Ok(required_size)
}

fn query_time_of_day_information(buffer: &mut [u8]) -> Result<usize, NtStatus> {
    let required_size = size_of::<SystemTimeOfDayInformation>();
    if buffer.len() < required_size {
        return Err(NtStatus::InfoLengthMismatch);
    }

    let current_time = crate::hal::rtc::get_system_time() as i64;

    let info = SystemTimeOfDayInformation {
        boot_time: get_boot_time(),
        current_time,
        time_zone_bias: 0, // UTC
        time_zone_id: 0,   // Unknown
        reserved: 0,
        boot_time_bias: 0,
        sleep_time_bias: 0,
    };

    let info_bytes = unsafe {
        core::slice::from_raw_parts(&info as *const _ as *const u8, required_size)
    };
    buffer[..required_size].copy_from_slice(info_bytes);

    Ok(required_size)
}

fn query_performance_information(buffer: &mut [u8]) -> Result<usize, NtStatus> {
    let required_size = size_of::<SystemPerformanceInformation>();
    if buffer.len() < required_size {
        return Err(NtStatus::InfoLengthMismatch);
    }

    let info = SystemPerformanceInformation {
        idle_process_time: 0,
        io_read_transfer_count: 0,
        io_write_transfer_count: 0,
        io_other_transfer_count: 0,
        io_read_operation_count: 0,
        io_write_operation_count: 0,
        io_other_operation_count: 0,
        available_pages: get_available_pages(),
        committed_pages: 0,
        commit_limit: get_commit_limit(),
        peak_commitment: 0,
        page_fault_count: get_page_fault_count(),
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
        context_switches: get_context_switch_count(),
        first_level_tb_fills: 0,
        second_level_tb_fills: 0,
        system_calls: get_system_call_count(),
    };

    let info_bytes = unsafe {
        core::slice::from_raw_parts(&info as *const _ as *const u8, required_size)
    };
    buffer[..required_size].copy_from_slice(info_bytes);

    Ok(required_size)
}

fn query_device_information(buffer: &mut [u8]) -> Result<usize, NtStatus> {
    let required_size = size_of::<SystemDeviceInformation>();
    if buffer.len() < required_size {
        return Err(NtStatus::InfoLengthMismatch);
    }

    let info = SystemDeviceInformation {
        number_of_disks: 0,
        number_of_floppies: 0,
        number_of_cd_roms: 0,
        number_of_tapes: 0,
        number_of_serial_ports: 0,
        number_of_parallel_ports: 0,
    };

    let info_bytes = unsafe {
        core::slice::from_raw_parts(&info as *const _ as *const u8, required_size)
    };
    buffer[..required_size].copy_from_slice(info_bytes);

    Ok(required_size)
}

fn query_processor_performance_information(buffer: &mut [u8]) -> Result<usize, NtStatus> {
    let num_processors = get_number_of_processors() as usize;
    let required_size = size_of::<SystemProcessorPerformanceInformation>() * num_processors;

    if buffer.len() < required_size {
        return Err(NtStatus::InfoLengthMismatch);
    }

    // Fill in performance info for each processor
    let info_size = size_of::<SystemProcessorPerformanceInformation>();
    for i in 0..num_processors {
        let info = SystemProcessorPerformanceInformation {
            idle_time: 0,
            kernel_time: 0,
            user_time: 0,
            dpc_time: 0,
            interrupt_time: 0,
            interrupt_count: 0,
        };

        let offset = i * info_size;
        let info_bytes = unsafe {
            core::slice::from_raw_parts(&info as *const _ as *const u8, info_size)
        };
        buffer[offset..offset + info_size].copy_from_slice(info_bytes);
    }

    Ok(required_size)
}

fn query_exception_information(buffer: &mut [u8]) -> Result<usize, NtStatus> {
    let required_size = size_of::<SystemExceptionInformation>();
    if buffer.len() < required_size {
        return Err(NtStatus::InfoLengthMismatch);
    }

    let info = SystemExceptionInformation {
        alignment_fixup_count: 0,
        exception_dispatch_count: 0,
        floating_emulation_count: 0,
        byte_word_emulation_count: 0,
    };

    let info_bytes = unsafe {
        core::slice::from_raw_parts(&info as *const _ as *const u8, required_size)
    };
    buffer[..required_size].copy_from_slice(info_bytes);

    Ok(required_size)
}

fn query_kernel_debugger_information(buffer: &mut [u8]) -> Result<usize, NtStatus> {
    let required_size = size_of::<SystemKernelDebuggerInformation>();
    if buffer.len() < required_size {
        return Err(NtStatus::InfoLengthMismatch);
    }

    let info = SystemKernelDebuggerInformation {
        kernel_debugger_enabled: false,
        kernel_debugger_not_present: true,
    };

    let info_bytes = unsafe {
        core::slice::from_raw_parts(&info as *const _ as *const u8, required_size)
    };
    buffer[..required_size].copy_from_slice(info_bytes);

    Ok(required_size)
}

fn query_context_switch_information(buffer: &mut [u8]) -> Result<usize, NtStatus> {
    let required_size = size_of::<SystemContextSwitchInformation>();
    if buffer.len() < required_size {
        return Err(NtStatus::InfoLengthMismatch);
    }

    let info = SystemContextSwitchInformation {
        context_switches: get_context_switch_count(),
        find_any: 0,
        find_last: 0,
        find_ideal: 0,
        idle_any: 0,
        idle_current: 0,
        idle_last: 0,
        idle_ideal: 0,
        preempt_any: 0,
        preempt_current: 0,
        preempt_last: 0,
        switch_to_idle: 0,
    };

    let info_bytes = unsafe {
        core::slice::from_raw_parts(&info as *const _ as *const u8, required_size)
    };
    buffer[..required_size].copy_from_slice(info_bytes);

    Ok(required_size)
}

fn query_interrupt_information(buffer: &mut [u8]) -> Result<usize, NtStatus> {
    let num_processors = get_number_of_processors() as usize;
    let required_size = size_of::<SystemInterruptInformation>() * num_processors;

    if buffer.len() < required_size {
        return Err(NtStatus::InfoLengthMismatch);
    }

    let info_size = size_of::<SystemInterruptInformation>();
    for i in 0..num_processors {
        let info = SystemInterruptInformation {
            context_switches: 0,
            dpc_count: 0,
            dpc_rate: 0,
            time_increment: 156250, // 15.625ms in 100ns units
            dpc_bypass_count: 0,
            apc_bypass_count: 0,
        };

        let offset = i * info_size;
        let info_bytes = unsafe {
            core::slice::from_raw_parts(&info as *const _ as *const u8, info_size)
        };
        buffer[offset..offset + info_size].copy_from_slice(info_bytes);
    }

    Ok(required_size)
}

fn query_registry_quota_information(buffer: &mut [u8]) -> Result<usize, NtStatus> {
    let required_size = size_of::<SystemRegistryQuotaInformation>();
    if buffer.len() < required_size {
        return Err(NtStatus::InfoLengthMismatch);
    }

    let info = SystemRegistryQuotaInformation {
        registry_quota_allowed: 32 * 1024 * 1024, // 32 MB default
        registry_quota_used: 0,
        paged_pool_size: 0,
    };

    let info_bytes = unsafe {
        core::slice::from_raw_parts(&info as *const _ as *const u8, required_size)
    };
    buffer[..required_size].copy_from_slice(info_bytes);

    Ok(required_size)
}

// Helper functions to get system information

fn get_total_physical_pages() -> usize {
    // Get from memory manager
    // For now return a placeholder
    262144 // 1GB with 4KB pages
}

fn get_highest_physical_page() -> usize {
    // Get from memory manager
    262144
}

fn get_active_processor_mask() -> usize {
    // For now, assume single processor
    1
}

fn get_number_of_processors() -> u8 {
    // For now, assume single processor
    1
}

fn get_processor_level() -> u16 {
    // Family 6 for modern Intel/AMD
    6
}

fn get_processor_revision() -> u16 {
    // Model/Stepping
    0x0000
}

fn get_processor_features() -> u32 {
    // Feature bits from CPUID
    0
}

fn get_boot_time() -> i64 {
    // Boot time in 100ns since 1601
    0
}

fn get_available_pages() -> u32 {
    // Get from memory manager
    0
}

fn get_commit_limit() -> usize {
    // Get from memory manager
    0
}

fn get_page_fault_count() -> u32 {
    0
}

fn get_context_switch_count() -> u32 {
    0
}

fn get_system_call_count() -> u32 {
    0
}
