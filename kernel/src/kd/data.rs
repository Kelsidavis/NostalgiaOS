//! Debugger Data Blocks
//!
//! Provides debugger data block management:
//! - KDDEBUGGER_DATA64 structure
//! - Data block registration/deregistration
//! - Kernel data pointers for debugger extensions
//!
//! Based on Windows Server 2003 base/ntos/kd64/kddata.c

use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

extern crate alloc;

/// Debugger data block tag
pub const KDBG_TAG: u32 = 0x4742444B; // 'KDBG'

/// Debug data header
#[derive(Debug, Clone)]
pub struct DebugDataHeader {
    /// Owner tag (4 bytes)
    pub owner_tag: u32,
    /// Size of the data block including header
    pub size: u32,
}

impl DebugDataHeader {
    pub const fn new() -> Self {
        Self {
            owner_tag: 0,
            size: 0,
        }
    }
}

/// Registered data block
#[derive(Debug, Clone)]
pub struct RegisteredDataBlock {
    /// Header
    pub header: DebugDataHeader,
    /// Block address (for tracking)
    pub address: usize,
    /// Name/description
    pub name: String,
}

/// KDDEBUGGER_DATA64 - Kernel debugger data block
#[derive(Debug, Clone)]
pub struct KdDebuggerData {
    /// Header
    pub header: DebugDataHeader,
    /// Kernel base address
    pub kern_base: u64,
    /// Breakpoint with status instruction
    pub breakpoint_with_status: u64,
    /// Saved context
    pub saved_context: u64,

    // Thread offsets
    /// Offset of CallbackStack in KTHREAD
    pub th_callback_stack: u16,
    /// Offset of NextCallback in KCALLOUT_FRAME
    pub next_callback: u16,
    /// Frame pointer offset
    pub frame_pointer: u16,
    /// PAE enabled flag
    pub pae_enabled: u16,

    // Kernel routines
    /// KiCallUserMode
    pub ki_call_user_mode: u64,
    /// KeUserCallbackDispatcher
    pub ke_user_callback_dispatcher: u64,

    // Loaded modules
    /// PsLoadedModuleList
    pub ps_loaded_module_list: u64,
    /// PsActiveProcessHead
    pub ps_active_process_head: u64,
    /// PspCidTable
    pub psp_cid_table: u64,

    // Executive resources
    /// ExpSystemResourcesList
    pub exp_system_resources_list: u64,
    /// ExpPagedPoolDescriptor
    pub exp_paged_pool_descriptor: u64,
    /// ExpNumberOfPagedPools
    pub exp_number_of_paged_pools: u64,

    // Timing
    /// KeTimeIncrement
    pub ke_time_increment: u64,
    /// KeBugCheckCallbackListHead
    pub ke_bugcheck_callback_list_head: u64,
    /// KiBugCheckData
    pub ki_bugcheck_data: u64,

    // I/O
    /// IopErrorLogListHead
    pub iop_error_log_list_head: u64,

    // Object Manager
    /// ObpRootDirectoryObject
    pub obp_root_directory_object: u64,
    /// ObpTypeObjectType
    pub obp_type_object_type: u64,

    // Memory Manager - Cache
    /// MmSystemCacheStart
    pub mm_system_cache_start: u64,
    /// MmSystemCacheEnd
    pub mm_system_cache_end: u64,
    /// MmSystemCacheWs
    pub mm_system_cache_ws: u64,

    // Memory Manager - PFN
    /// MmPfnDatabase
    pub mm_pfn_database: u64,
    /// MmSystemPtesStart
    pub mm_system_ptes_start: u64,
    /// MmSystemPtesEnd
    pub mm_system_ptes_end: u64,
    /// MmSubsectionBase
    pub mm_subsection_base: u64,
    /// MmNumberOfPagingFiles
    pub mm_number_of_paging_files: u64,

    // Memory Manager - Physical
    /// MmLowestPhysicalPage
    pub mm_lowest_physical_page: u64,
    /// MmHighestPhysicalPage
    pub mm_highest_physical_page: u64,
    /// MmNumberOfPhysicalPages
    pub mm_number_of_physical_pages: u64,

    // Memory Manager - NonPaged Pool
    /// MmMaximumNonPagedPoolInBytes
    pub mm_maximum_non_paged_pool_in_bytes: u64,
    /// MmNonPagedSystemStart
    pub mm_non_paged_system_start: u64,
    /// MmNonPagedPoolStart
    pub mm_non_paged_pool_start: u64,
    /// MmNonPagedPoolEnd
    pub mm_non_paged_pool_end: u64,

    // Memory Manager - Paged Pool
    /// MmPagedPoolStart
    pub mm_paged_pool_start: u64,
    /// MmPagedPoolEnd
    pub mm_paged_pool_end: u64,
    /// MmPagedPoolInfo
    pub mm_paged_pool_info: u64,
    /// Page size
    pub page_size: u64,
    /// MmSizeOfPagedPoolInBytes
    pub mm_size_of_paged_pool_in_bytes: u64,

    // Memory Manager - Commit
    /// MmTotalCommitLimit
    pub mm_total_commit_limit: u64,
    /// MmTotalCommittedPages
    pub mm_total_committed_pages: u64,
    /// MmSharedCommit
    pub mm_shared_commit: u64,
    /// MmDriverCommit
    pub mm_driver_commit: u64,
    /// MmProcessCommit
    pub mm_process_commit: u64,
    /// MmPagedPoolCommit
    pub mm_paged_pool_commit: u64,

    // Memory Manager - Page Lists
    /// MmZeroedPageListHead
    pub mm_zeroed_page_list_head: u64,
    /// MmFreePageListHead
    pub mm_free_page_list_head: u64,
    /// MmStandbyPageListHead
    pub mm_standby_page_list_head: u64,
    /// MmModifiedPageListHead
    pub mm_modified_page_list_head: u64,
    /// MmModifiedNoWritePageListHead
    pub mm_modified_no_write_page_list_head: u64,
    /// MmAvailablePages
    pub mm_available_pages: u64,
    /// MmResidentAvailablePages
    pub mm_resident_available_pages: u64,

    // Pool tracking
    /// PoolTrackTable
    pub pool_track_table: u64,
    /// NonPagedPoolDescriptor
    pub non_paged_pool_descriptor: u64,

    // User address space
    /// MmHighestUserAddress
    pub mm_highest_user_address: u64,
    /// MmSystemRangeStart
    pub mm_system_range_start: u64,
    /// MmUserProbeAddress
    pub mm_user_probe_address: u64,

    // Print buffer
    /// KdPrintCircularBufferStart
    pub kd_print_circular_buffer: u64,
    /// KdPrintCircularBufferEnd
    pub kd_print_circular_buffer_end: u64,
    /// KdPrintWritePointer
    pub kd_print_write_pointer: u64,
    /// KdPrintRolloverCount
    pub kd_print_rollover_count: u64,

    // Loaded images
    /// MmLoadedUserImageList
    pub mm_loaded_user_image_list: u64,

    // Processor block
    /// KiProcessorBlock
    pub ki_processor_block: u64,

    // Unloaded drivers
    /// MmUnloadedDrivers
    pub mm_unloaded_drivers: u64,
    /// MmLastUnloadedDriver
    pub mm_last_unloaded_driver: u64,
}

impl KdDebuggerData {
    pub const fn new() -> Self {
        Self {
            header: DebugDataHeader::new(),
            kern_base: 0,
            breakpoint_with_status: 0,
            saved_context: 0,
            th_callback_stack: 0,
            next_callback: 0,
            frame_pointer: 0,
            pae_enabled: 0,
            ki_call_user_mode: 0,
            ke_user_callback_dispatcher: 0,
            ps_loaded_module_list: 0,
            ps_active_process_head: 0,
            psp_cid_table: 0,
            exp_system_resources_list: 0,
            exp_paged_pool_descriptor: 0,
            exp_number_of_paged_pools: 0,
            ke_time_increment: 0,
            ke_bugcheck_callback_list_head: 0,
            ki_bugcheck_data: 0,
            iop_error_log_list_head: 0,
            obp_root_directory_object: 0,
            obp_type_object_type: 0,
            mm_system_cache_start: 0,
            mm_system_cache_end: 0,
            mm_system_cache_ws: 0,
            mm_pfn_database: 0,
            mm_system_ptes_start: 0,
            mm_system_ptes_end: 0,
            mm_subsection_base: 0,
            mm_number_of_paging_files: 0,
            mm_lowest_physical_page: 0,
            mm_highest_physical_page: 0,
            mm_number_of_physical_pages: 0,
            mm_maximum_non_paged_pool_in_bytes: 0,
            mm_non_paged_system_start: 0,
            mm_non_paged_pool_start: 0,
            mm_non_paged_pool_end: 0,
            mm_paged_pool_start: 0,
            mm_paged_pool_end: 0,
            mm_paged_pool_info: 0,
            page_size: 0x1000, // 4KB
            mm_size_of_paged_pool_in_bytes: 0,
            mm_total_commit_limit: 0,
            mm_total_committed_pages: 0,
            mm_shared_commit: 0,
            mm_driver_commit: 0,
            mm_process_commit: 0,
            mm_paged_pool_commit: 0,
            mm_zeroed_page_list_head: 0,
            mm_free_page_list_head: 0,
            mm_standby_page_list_head: 0,
            mm_modified_page_list_head: 0,
            mm_modified_no_write_page_list_head: 0,
            mm_available_pages: 0,
            mm_resident_available_pages: 0,
            pool_track_table: 0,
            non_paged_pool_descriptor: 0,
            mm_highest_user_address: 0x7FFFFFFEFFFF,
            mm_system_range_start: 0xFFFF800000000000,
            mm_user_probe_address: 0x7FFFFFFEFFFF,
            kd_print_circular_buffer: 0,
            kd_print_circular_buffer_end: 0,
            kd_print_write_pointer: 0,
            kd_print_rollover_count: 0,
            mm_loaded_user_image_list: 0,
            ki_processor_block: 0,
            mm_unloaded_drivers: 0,
            mm_last_unloaded_driver: 0,
        }
    }
}

/// Data block registry state
#[derive(Debug)]
pub struct DataBlockState {
    /// Main debugger data block
    pub debugger_data: KdDebuggerData,
    /// Registered data blocks by tag
    registered_blocks: BTreeMap<u32, RegisteredDataBlock>,
}

impl DataBlockState {
    pub const fn new() -> Self {
        Self {
            debugger_data: KdDebuggerData::new(),
            registered_blocks: BTreeMap::new(),
        }
    }
}

/// Global data block state
static mut DATA_BLOCK_STATE: Option<SpinLock<DataBlockState>> = None;

/// Statistics
static BLOCKS_REGISTERED: AtomicU64 = AtomicU64::new(0);
static BLOCKS_DEREGISTERED: AtomicU64 = AtomicU64::new(0);

fn get_data_state() -> &'static SpinLock<DataBlockState> {
    unsafe {
        DATA_BLOCK_STATE
            .as_ref()
            .expect("Data block state not initialized")
    }
}

/// Initialize data block subsystem
pub fn kd_data_init() {
    unsafe {
        DATA_BLOCK_STATE = Some(SpinLock::new(DataBlockState::new()));
    }

    // Register the main debugger data block
    let state = get_data_state();
    let mut guard = state.lock();

    guard.debugger_data.header.owner_tag = KDBG_TAG;
    guard.debugger_data.header.size = core::mem::size_of::<KdDebuggerData>() as u32;

    crate::serial_println!("[KD] Debugger data blocks initialized");
}

/// Register a debugger data block
pub fn kd_register_debugger_data_block(
    tag: u32,
    address: usize,
    size: u32,
    name: &str,
) -> bool {
    let state = get_data_state();
    let mut guard = state.lock();

    // Check if already registered
    if guard.registered_blocks.contains_key(&tag) {
        crate::serial_println!("[KD] Data block with tag {:#x} already registered", tag);
        return false;
    }

    let block = RegisteredDataBlock {
        header: DebugDataHeader {
            owner_tag: tag,
            size,
        },
        address,
        name: String::from(name),
    };

    guard.registered_blocks.insert(tag, block);
    BLOCKS_REGISTERED.fetch_add(1, Ordering::Relaxed);

    crate::serial_println!(
        "[KD] Registered data block '{}' (tag={:#x}, size={})",
        name,
        tag,
        size
    );

    true
}

/// Deregister a debugger data block
pub fn kd_deregister_debugger_data_block(tag: u32) -> bool {
    let state = get_data_state();
    let mut guard = state.lock();

    if tag == KDBG_TAG {
        crate::serial_println!("[KD] Cannot deregister main debugger data block");
        return false;
    }

    if guard.registered_blocks.remove(&tag).is_some() {
        BLOCKS_DEREGISTERED.fetch_add(1, Ordering::Relaxed);
        crate::serial_println!("[KD] Deregistered data block (tag={:#x})", tag);
        true
    } else {
        false
    }
}

/// Get debugger data block
pub fn kd_get_debugger_data() -> KdDebuggerData {
    let state = get_data_state();
    let guard = state.lock();
    guard.debugger_data.clone()
}

/// Update debugger data block field
pub fn kd_update_debugger_data<F>(updater: F)
where
    F: FnOnce(&mut KdDebuggerData),
{
    let state = get_data_state();
    let mut guard = state.lock();
    updater(&mut guard.debugger_data);
}

/// Get registered data block by tag
pub fn kd_get_data_block(tag: u32) -> Option<RegisteredDataBlock> {
    let state = get_data_state();
    let guard = state.lock();
    guard.registered_blocks.get(&tag).cloned()
}

/// List all registered data blocks
pub fn kd_list_data_blocks() -> Vec<(u32, String, u32)> {
    let state = get_data_state();
    let guard = state.lock();

    let mut result = Vec::new();

    // Add main debugger data block
    result.push((
        KDBG_TAG,
        String::from("KDDEBUGGER_DATA64"),
        guard.debugger_data.header.size,
    ));

    // Add registered blocks
    for (tag, block) in &guard.registered_blocks {
        result.push((*tag, block.name.clone(), block.header.size));
    }

    result
}

/// Get data block statistics
pub fn kd_data_get_stats() -> (u64, u64, usize) {
    let state = get_data_state();
    let guard = state.lock();

    (
        BLOCKS_REGISTERED.load(Ordering::Relaxed),
        BLOCKS_DEREGISTERED.load(Ordering::Relaxed),
        guard.registered_blocks.len() + 1, // +1 for main block
    )
}

/// Update kernel base address
pub fn kd_set_kern_base(base: u64) {
    kd_update_debugger_data(|data| {
        data.kern_base = base;
    });
}

/// Update PsLoadedModuleList address
pub fn kd_set_loaded_module_list(addr: u64) {
    kd_update_debugger_data(|data| {
        data.ps_loaded_module_list = addr;
    });
}

/// Update PsActiveProcessHead address
pub fn kd_set_active_process_head(addr: u64) {
    kd_update_debugger_data(|data| {
        data.ps_active_process_head = addr;
    });
}

/// Update memory manager data
pub fn kd_set_mm_data(
    pfn_database: u64,
    available_pages: u64,
    physical_pages: u64,
) {
    kd_update_debugger_data(|data| {
        data.mm_pfn_database = pfn_database;
        data.mm_available_pages = available_pages;
        data.mm_number_of_physical_pages = physical_pages;
    });
}
