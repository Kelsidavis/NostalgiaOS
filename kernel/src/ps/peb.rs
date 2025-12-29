//! Process Environment Block (PEB)
//!
//! The PEB is a user-mode structure that contains process-wide information.
//! It is located in user-mode address space and is accessible to user-mode code.
//!
//! # Structure Layout
//!
//! The PEB contains:
//! - Image base address
//! - Loader data (loaded modules list)
//! - Process parameters (command line, environment)
//! - Heap information
//! - TLS (Thread Local Storage) data
//! - API set map
//!
//! # Important Notes
//!
//! - The PEB is allocated in user-mode address space
//! - Its address is stored in the TEB (fs:[0x30] on x86, gs:[0x60] on x64)
//! - The PEB address is also stored in EPROCESS.peb
//!
//! # References
//!
//! Windows Server 2003 DDK: ntpsapi.h

use core::ptr;

/// PEB address in 64-bit mode (accessible via GS segment)
pub const PEB_ADDRESS_64: u64 = 0x7FFE0000;

/// TEB address offset from GS base in 64-bit mode
pub const TEB_SELF_OFFSET_64: usize = 0x30;

/// PEB pointer offset in TEB for 64-bit
pub const TEB_PEB_OFFSET_64: usize = 0x60;

/// Maximum length of current directory path
pub const RTL_MAX_DRIVE_LETTERS: usize = 32;

// ============================================================================
// RTL_USER_PROCESS_PARAMETERS
// ============================================================================

/// Process parameters passed from parent to child
#[repr(C)]
pub struct RtlUserProcessParameters {
    /// Maximum length of this structure
    pub maximum_length: u32,
    /// Current length of this structure
    pub length: u32,
    /// Flags
    pub flags: u32,
    /// Debug flags
    pub debug_flags: u32,
    /// Handle to console
    pub console_handle: u64,
    /// Console flags
    pub console_flags: u32,
    /// Padding
    _padding1: u32,
    /// Standard input handle
    pub standard_input: u64,
    /// Standard output handle
    pub standard_output: u64,
    /// Standard error handle
    pub standard_error: u64,
    /// Current directory path
    pub current_directory: RtlCurrentDirectory,
    /// DLL search path
    pub dll_path: UnicodeString,
    /// Image path and name
    pub image_path_name: UnicodeString,
    /// Command line
    pub command_line: UnicodeString,
    /// Environment block pointer
    pub environment: *mut u16,
    /// Starting X position for window
    pub starting_x: u32,
    /// Starting Y position for window
    pub starting_y: u32,
    /// Window width
    pub count_x: u32,
    /// Window height
    pub count_y: u32,
    /// Console character width (for console apps)
    pub count_chars_x: u32,
    /// Console character height (for console apps)
    pub count_chars_y: u32,
    /// Console fill attribute
    pub fill_attribute: u32,
    /// Window flags
    pub window_flags: u32,
    /// Show window flags
    pub show_window_flags: u32,
    /// Reserved
    _reserved: u32,
    /// Window title
    pub window_title: UnicodeString,
    /// Desktop name
    pub desktop_info: UnicodeString,
    /// Shell info
    pub shell_info: UnicodeString,
    /// Runtime data
    pub runtime_data: UnicodeString,
    /// Current directories
    pub current_directories: [RtlDriveLetterCurDir; RTL_MAX_DRIVE_LETTERS],
    /// Environment size
    pub environment_size: u64,
    /// Environment version
    pub environment_version: u64,
    /// Package dependency data
    pub package_dependency_data: *mut u8,
    /// Process group ID
    pub process_group_id: u32,
    /// Loader threads
    pub loader_threads: u32,
}

impl RtlUserProcessParameters {
    pub const fn new() -> Self {
        Self {
            maximum_length: 0,
            length: 0,
            flags: 0,
            debug_flags: 0,
            console_handle: 0,
            console_flags: 0,
            _padding1: 0,
            standard_input: 0,
            standard_output: 0,
            standard_error: 0,
            current_directory: RtlCurrentDirectory::new(),
            dll_path: UnicodeString::new(),
            image_path_name: UnicodeString::new(),
            command_line: UnicodeString::new(),
            environment: ptr::null_mut(),
            starting_x: 0,
            starting_y: 0,
            count_x: 0,
            count_y: 0,
            count_chars_x: 0,
            count_chars_y: 0,
            fill_attribute: 0,
            window_flags: 0,
            show_window_flags: 0,
            _reserved: 0,
            window_title: UnicodeString::new(),
            desktop_info: UnicodeString::new(),
            shell_info: UnicodeString::new(),
            runtime_data: UnicodeString::new(),
            current_directories: [RtlDriveLetterCurDir::new(); RTL_MAX_DRIVE_LETTERS],
            environment_size: 0,
            environment_version: 0,
            package_dependency_data: ptr::null_mut(),
            process_group_id: 0,
            loader_threads: 0,
        }
    }
}

impl Default for RtlUserProcessParameters {
    fn default() -> Self {
        Self::new()
    }
}

/// Unicode string structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    /// Length in bytes (not including null terminator)
    pub length: u16,
    /// Maximum length in bytes
    pub maximum_length: u16,
    /// Padding for alignment
    _padding: u32,
    /// Pointer to buffer
    pub buffer: *mut u16,
}

impl UnicodeString {
    pub const fn new() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            _padding: 0,
            buffer: ptr::null_mut(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0 || self.buffer.is_null()
    }
}

impl Default for UnicodeString {
    fn default() -> Self {
        Self::new()
    }
}

/// Current directory information
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtlCurrentDirectory {
    /// Path to current directory
    pub dos_path: UnicodeString,
    /// Handle to current directory
    pub handle: u64,
}

impl RtlCurrentDirectory {
    pub const fn new() -> Self {
        Self {
            dos_path: UnicodeString::new(),
            handle: 0,
        }
    }
}

impl Default for RtlCurrentDirectory {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-drive current directory
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtlDriveLetterCurDir {
    /// Flags
    pub flags: u16,
    /// Length
    pub length: u16,
    /// Timestamp
    pub time_stamp: u32,
    /// Path
    pub dos_path: UnicodeString,
}

impl RtlDriveLetterCurDir {
    pub const fn new() -> Self {
        Self {
            flags: 0,
            length: 0,
            time_stamp: 0,
            dos_path: UnicodeString::new(),
        }
    }
}

impl Default for RtlDriveLetterCurDir {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PEB_LDR_DATA - Loader Data
// ============================================================================

/// Loader data containing lists of loaded modules
#[repr(C)]
pub struct PebLdrData {
    /// Length of this structure
    pub length: u32,
    /// Initialization status
    pub initialized: u32,
    /// SS handle
    pub ss_handle: *mut u8,
    /// Load order list (LIST_ENTRY)
    pub in_load_order_module_list: ListEntry64,
    /// Memory order list (LIST_ENTRY)
    pub in_memory_order_module_list: ListEntry64,
    /// Init order list (LIST_ENTRY)
    pub in_initialization_order_module_list: ListEntry64,
    /// Entry in progress
    pub entry_in_progress: *mut u8,
    /// Shutdown in progress
    pub shutdown_in_progress: u32,
    /// Shutdown thread ID
    pub shutdown_thread_id: u64,
}

impl PebLdrData {
    pub const fn new() -> Self {
        Self {
            length: core::mem::size_of::<PebLdrData>() as u32,
            initialized: 0,
            ss_handle: ptr::null_mut(),
            in_load_order_module_list: ListEntry64::empty(),
            in_memory_order_module_list: ListEntry64::empty(),
            in_initialization_order_module_list: ListEntry64::empty(),
            entry_in_progress: ptr::null_mut(),
            shutdown_in_progress: 0,
            shutdown_thread_id: 0,
        }
    }
}

impl Default for PebLdrData {
    fn default() -> Self {
        Self::new()
    }
}

/// 64-bit list entry for user mode
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListEntry64 {
    pub flink: u64,
    pub blink: u64,
}

impl ListEntry64 {
    pub const fn empty() -> Self {
        Self { flink: 0, blink: 0 }
    }

    /// Initialize list head (points to itself)
    pub fn init_head(&mut self) {
        let self_addr = self as *mut Self as u64;
        self.flink = self_addr;
        self.blink = self_addr;
    }
}

impl Default for ListEntry64 {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// LDR_DATA_TABLE_ENTRY - Module Entry
// ============================================================================

/// Loader data table entry for a loaded module
#[repr(C)]
pub struct LdrDataTableEntry {
    /// Link in load order list
    pub in_load_order_links: ListEntry64,
    /// Link in memory order list
    pub in_memory_order_links: ListEntry64,
    /// Link in init order list
    pub in_initialization_order_links: ListEntry64,
    /// Base address of module
    pub dll_base: *mut u8,
    /// Entry point address
    pub entry_point: *mut u8,
    /// Size of image
    pub size_of_image: u32,
    /// Padding
    _padding: u32,
    /// Full DLL name
    pub full_dll_name: UnicodeString,
    /// Base DLL name
    pub base_dll_name: UnicodeString,
    /// Flags
    pub flags: u32,
    /// Load count
    pub load_count: u16,
    /// TLS index
    pub tls_index: u16,
    /// Hash links
    pub hash_links: ListEntry64,
    /// Time date stamp
    pub time_date_stamp: u32,
    /// Activation context
    pub entry_point_activation_context: *mut u8,
    /// Lock
    pub lock: *mut u8,
    /// DDA node
    pub ddag_node: *mut u8,
    /// Node module link
    pub node_module_link: ListEntry64,
    /// Load context
    pub load_context: *mut u8,
    /// Parent DLL base
    pub parent_dll_base: *mut u8,
    /// Switch back context
    pub switch_back_context: *mut u8,
}

impl LdrDataTableEntry {
    pub const fn new() -> Self {
        Self {
            in_load_order_links: ListEntry64::empty(),
            in_memory_order_links: ListEntry64::empty(),
            in_initialization_order_links: ListEntry64::empty(),
            dll_base: ptr::null_mut(),
            entry_point: ptr::null_mut(),
            size_of_image: 0,
            _padding: 0,
            full_dll_name: UnicodeString::new(),
            base_dll_name: UnicodeString::new(),
            flags: 0,
            load_count: 0,
            tls_index: 0,
            hash_links: ListEntry64::empty(),
            time_date_stamp: 0,
            entry_point_activation_context: ptr::null_mut(),
            lock: ptr::null_mut(),
            ddag_node: ptr::null_mut(),
            node_module_link: ListEntry64::empty(),
            load_context: ptr::null_mut(),
            parent_dll_base: ptr::null_mut(),
            switch_back_context: ptr::null_mut(),
        }
    }
}

impl Default for LdrDataTableEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PEB - Process Environment Block
// ============================================================================

/// PEB flags
pub mod peb_flags {
    /// Process is being debugged
    pub const BEING_DEBUGGED: u8 = 0x02;
    /// Image uses large pages
    pub const IMAGE_USES_LARGE_PAGES: u8 = 0x01;
}

/// Process Environment Block (64-bit)
///
/// This is the main structure that user-mode code uses to access
/// process-wide information. It is located in user-mode address space.
#[repr(C)]
pub struct Peb {
    /// Inherited address space flag
    pub inherited_address_space: u8,
    /// Read image file exec options
    pub read_image_file_exec_options: u8,
    /// Being debugged flag
    pub being_debugged: u8,
    /// Bit field flags
    pub bit_field: u8,
    /// Padding
    _padding1: u32,
    /// Mutant (for compatibility)
    pub mutant: u64,
    /// Image base address
    pub image_base_address: *mut u8,
    /// Pointer to loader data
    pub ldr: *mut PebLdrData,
    /// Pointer to process parameters
    pub process_parameters: *mut RtlUserProcessParameters,
    /// Sub-system data
    pub sub_system_data: *mut u8,
    /// Process heap
    pub process_heap: *mut u8,
    /// Fast PEB lock
    pub fast_peb_lock: *mut u8,
    /// ATL thunk list pointer
    pub atl_thunk_s_list_ptr: *mut u8,
    /// IFE/O key
    pub ifeo_key: *mut u8,
    /// Cross-process flags
    pub cross_process_flags: u32,
    /// Padding
    _padding2: u32,
    /// Kernel callback table / User shared info pointer
    pub kernel_callback_table: *mut u8,
    /// System reserved
    pub system_reserved: u32,
    /// ATL thunk list (32-bit)
    pub atl_thunk_s_list_ptr32: u32,
    /// API set map
    pub api_set_map: *mut u8,
    /// TLS expansion counter
    pub tls_expansion_counter: u32,
    /// Padding
    _padding3: u32,
    /// TLS bitmap
    pub tls_bitmap: *mut u8,
    /// TLS bitmap bits
    pub tls_bitmap_bits: [u32; 2],
    /// Read-only shared memory base
    pub read_only_shared_memory_base: *mut u8,
    /// Shared data (Vista+)
    pub shared_data: *mut u8,
    /// Read-only static server data
    pub read_only_static_server_data: *mut *mut u8,
    /// ANSI code page data
    pub ansi_code_page_data: *mut u8,
    /// OEM code page data
    pub oem_code_page_data: *mut u8,
    /// Unicode case table data
    pub unicode_case_table_data: *mut u8,
    /// Number of processors
    pub number_of_processors: u32,
    /// NT global flag
    pub nt_global_flag: u32,
    /// Critical section timeout
    pub critical_section_timeout: i64,
    /// Heap segment reserve
    pub heap_segment_reserve: u64,
    /// Heap segment commit
    pub heap_segment_commit: u64,
    /// Heap de-commit total free threshold
    pub heap_de_commit_total_free_threshold: u64,
    /// Heap de-commit free block threshold
    pub heap_de_commit_free_block_threshold: u64,
    /// Number of heaps
    pub number_of_heaps: u32,
    /// Maximum number of heaps
    pub maximum_number_of_heaps: u32,
    /// Process heaps pointer
    pub process_heaps: *mut *mut u8,
    /// GDI shared handle table
    pub gdi_shared_handle_table: *mut u8,
    /// Process starter helper
    pub process_starter_helper: *mut u8,
    /// GDI DC attribute list
    pub gdi_dc_attribute_list: u32,
    /// Padding
    _padding4: u32,
    /// Loader lock
    pub loader_lock: *mut u8,
    /// OS major version
    pub os_major_version: u32,
    /// OS minor version
    pub os_minor_version: u32,
    /// OS build number
    pub os_build_number: u16,
    /// OS CSD version
    pub os_csd_version: u16,
    /// OS platform ID
    pub os_platform_id: u32,
    /// Image subsystem
    pub image_subsystem: u32,
    /// Image subsystem major version
    pub image_subsystem_major_version: u32,
    /// Image subsystem minor version
    pub image_subsystem_minor_version: u32,
    /// Padding
    _padding5: u32,
    /// Active process affinity mask
    pub active_process_affinity_mask: u64,
    /// GDI handle buffer (Windows 2000)
    pub gdi_handle_buffer: [u32; 60],
    /// Post-process init routine
    pub post_process_init_routine: *mut u8,
    /// TLS expansion bitmap
    pub tls_expansion_bitmap: *mut u8,
    /// TLS expansion bitmap bits
    pub tls_expansion_bitmap_bits: [u32; 32],
    /// Session ID
    pub session_id: u32,
    /// Padding
    _padding6: u32,
    /// Application compatibility flags
    pub app_compat_flags: u64,
    /// Application compatibility flags user
    pub app_compat_flags_user: u64,
    /// Shim data
    pub shim_data: *mut u8,
    /// Application compatibility info
    pub app_compat_info: *mut u8,
    /// CSD version
    pub csd_version: UnicodeString,
    /// Activation context data
    pub activation_context_data: *mut u8,
    /// Process assembly storage map
    pub process_assembly_storage_map: *mut u8,
    /// System default activation context data
    pub system_default_activation_context_data: *mut u8,
    /// System assembly storage map
    pub system_assembly_storage_map: *mut u8,
    /// Minimum stack commit
    pub minimum_stack_commit: u64,
    /// Fiber local storage pointer
    pub fls_callback: *mut *mut u8,
    /// FLS list head
    pub fls_list_head: ListEntry64,
    /// FLS bitmap
    pub fls_bitmap: *mut u8,
    /// FLS bitmap bits
    pub fls_bitmap_bits: [u32; 4],
    /// FLS high index
    pub fls_high_index: u32,
    /// WER registration data
    pub wer_registration_data: *mut u8,
    /// WER ship assert pointer
    pub wer_ship_assert_ptr: *mut u8,
}

impl Peb {
    /// Create a new empty PEB
    pub const fn new() -> Self {
        Self {
            inherited_address_space: 0,
            read_image_file_exec_options: 0,
            being_debugged: 0,
            bit_field: 0,
            _padding1: 0,
            mutant: u64::MAX, // -1
            image_base_address: ptr::null_mut(),
            ldr: ptr::null_mut(),
            process_parameters: ptr::null_mut(),
            sub_system_data: ptr::null_mut(),
            process_heap: ptr::null_mut(),
            fast_peb_lock: ptr::null_mut(),
            atl_thunk_s_list_ptr: ptr::null_mut(),
            ifeo_key: ptr::null_mut(),
            cross_process_flags: 0,
            _padding2: 0,
            kernel_callback_table: ptr::null_mut(),
            system_reserved: 0,
            atl_thunk_s_list_ptr32: 0,
            api_set_map: ptr::null_mut(),
            tls_expansion_counter: 0,
            _padding3: 0,
            tls_bitmap: ptr::null_mut(),
            tls_bitmap_bits: [0; 2],
            read_only_shared_memory_base: ptr::null_mut(),
            shared_data: ptr::null_mut(),
            read_only_static_server_data: ptr::null_mut(),
            ansi_code_page_data: ptr::null_mut(),
            oem_code_page_data: ptr::null_mut(),
            unicode_case_table_data: ptr::null_mut(),
            number_of_processors: 1,
            nt_global_flag: 0,
            critical_section_timeout: 0,
            heap_segment_reserve: 0,
            heap_segment_commit: 0,
            heap_de_commit_total_free_threshold: 0,
            heap_de_commit_free_block_threshold: 0,
            number_of_heaps: 0,
            maximum_number_of_heaps: 0,
            process_heaps: ptr::null_mut(),
            gdi_shared_handle_table: ptr::null_mut(),
            process_starter_helper: ptr::null_mut(),
            gdi_dc_attribute_list: 0,
            _padding4: 0,
            loader_lock: ptr::null_mut(),
            os_major_version: 5,      // Windows Server 2003
            os_minor_version: 2,
            os_build_number: 3790,
            os_csd_version: 0,
            os_platform_id: 2,        // VER_PLATFORM_WIN32_NT
            image_subsystem: 0,
            image_subsystem_major_version: 0,
            image_subsystem_minor_version: 0,
            _padding5: 0,
            active_process_affinity_mask: 1,
            gdi_handle_buffer: [0; 60],
            post_process_init_routine: ptr::null_mut(),
            tls_expansion_bitmap: ptr::null_mut(),
            tls_expansion_bitmap_bits: [0; 32],
            session_id: 0,
            _padding6: 0,
            app_compat_flags: 0,
            app_compat_flags_user: 0,
            shim_data: ptr::null_mut(),
            app_compat_info: ptr::null_mut(),
            csd_version: UnicodeString::new(),
            activation_context_data: ptr::null_mut(),
            process_assembly_storage_map: ptr::null_mut(),
            system_default_activation_context_data: ptr::null_mut(),
            system_assembly_storage_map: ptr::null_mut(),
            minimum_stack_commit: 0,
            fls_callback: ptr::null_mut(),
            fls_list_head: ListEntry64::empty(),
            fls_bitmap: ptr::null_mut(),
            fls_bitmap_bits: [0; 4],
            fls_high_index: 0,
            wer_registration_data: ptr::null_mut(),
            wer_ship_assert_ptr: ptr::null_mut(),
        }
    }

    /// Check if process is being debugged
    pub fn is_debugged(&self) -> bool {
        self.being_debugged != 0
    }

    /// Set debug state
    pub fn set_debugged(&mut self, debugged: bool) {
        self.being_debugged = if debugged { 1 } else { 0 };
    }

    /// Get the image base
    pub fn image_base(&self) -> u64 {
        self.image_base_address as u64
    }
}

impl Default for Peb {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PEB Initialization
// ============================================================================

/// Static PEB pool for processes
/// In a full implementation, PEBs would be allocated in user-mode address space
static mut PEB_POOL: [Peb; crate::ps::MAX_PROCESSES] = {
    const INIT: Peb = Peb::new();
    [INIT; crate::ps::MAX_PROCESSES]
};

/// PEB pool bitmap
static mut PEB_POOL_BITMAP: u64 = 0;

/// PEB pool lock
static PEB_POOL_LOCK: crate::ke::SpinLock<()> = crate::ke::SpinLock::new(());

/// Allocate a PEB from the pool
///
/// # Safety
/// Must be called with proper synchronization
pub unsafe fn allocate_peb() -> Option<*mut Peb> {
    let _guard = PEB_POOL_LOCK.lock();

    for i in 0..crate::ps::MAX_PROCESSES {
        if PEB_POOL_BITMAP & (1 << i) == 0 {
            PEB_POOL_BITMAP |= 1 << i;
            let peb = &mut PEB_POOL[i] as *mut Peb;
            // Initialize to default
            *peb = Peb::new();
            return Some(peb);
        }
    }
    None
}

/// Free a PEB back to the pool
///
/// # Safety
/// PEB must have been allocated from this pool
pub unsafe fn free_peb(peb: *mut Peb) {
    let _guard = PEB_POOL_LOCK.lock();

    let base = PEB_POOL.as_ptr() as usize;
    let offset = peb as usize - base;
    let index = offset / core::mem::size_of::<Peb>();
    if index < crate::ps::MAX_PROCESSES {
        PEB_POOL_BITMAP &= !(1 << index);
    }
}

// ============================================================================
// PEB_LDR_DATA Pool
// ============================================================================

/// Static pool of PEB_LDR_DATA structures (one per process)
static mut LDR_DATA_POOL: [PebLdrData; crate::ps::MAX_PROCESSES] = {
    const INIT: PebLdrData = PebLdrData::new();
    [INIT; crate::ps::MAX_PROCESSES]
};

/// LDR data pool bitmap
static mut LDR_DATA_POOL_BITMAP: u64 = 0;

/// LDR data pool lock
static LDR_DATA_POOL_LOCK: crate::ke::SpinLock<()> = crate::ke::SpinLock::new(());

/// Allocate a PEB_LDR_DATA from the pool
///
/// # Safety
/// Must be called with proper synchronization
pub unsafe fn allocate_peb_ldr_data() -> Option<*mut PebLdrData> {
    let _guard = LDR_DATA_POOL_LOCK.lock();

    for bit_idx in 0..crate::ps::MAX_PROCESSES {
        if LDR_DATA_POOL_BITMAP & (1 << bit_idx) == 0 {
            LDR_DATA_POOL_BITMAP |= 1 << bit_idx;
            let ldr = &mut LDR_DATA_POOL[bit_idx] as *mut PebLdrData;
            // Initialize to default
            *ldr = PebLdrData::new();
            return Some(ldr);
        }
    }
    None
}

/// Free a PEB_LDR_DATA back to the pool
///
/// # Safety
/// LDR data must have been allocated from this pool
pub unsafe fn free_peb_ldr_data(ldr: *mut PebLdrData) {
    let _guard = LDR_DATA_POOL_LOCK.lock();

    let base = LDR_DATA_POOL.as_ptr() as usize;
    let offset = ldr as usize - base;
    let index = offset / core::mem::size_of::<PebLdrData>();
    if index < crate::ps::MAX_PROCESSES {
        LDR_DATA_POOL_BITMAP &= !(1 << index);
    }
}

/// Initialize a PEB for a new process
///
/// # Arguments
/// * `peb` - Pointer to PEB structure to initialize
/// * `image_base` - Base address of loaded executable
/// * `image_size` - Size of loaded executable
/// * `entry_point` - Entry point address
/// * `subsystem` - PE subsystem (GUI, CUI, etc.)
///
/// # Safety
/// peb must be a valid pointer to a PEB structure
///
/// Note: image_size and entry_point are logged but not stored in PEB.
/// They should be stored in the LDR_DATA_TABLE_ENTRY for the main executable.
pub unsafe fn init_peb(
    peb: *mut Peb,
    image_base: u64,
    image_size: u32,
    entry_point: u64,
    subsystem: u16,
) {
    let peb = &mut *peb;

    // Set image information
    peb.image_base_address = image_base as *mut u8;
    peb.image_subsystem = subsystem as u32;

    // OS version: Windows Server 2003 (5.2.3790)
    peb.os_major_version = 5;
    peb.os_minor_version = 2;
    peb.os_build_number = 3790;
    peb.os_platform_id = 2; // VER_PLATFORM_WIN32_NT

    // Initialize number of processors
    peb.number_of_processors = 1; // TODO: Get actual count

    // Set process affinity mask
    peb.active_process_affinity_mask = 1;

    // Initialize mutant to -1 (invalid handle)
    peb.mutant = u64::MAX;

    crate::serial_println!("[PEB] Initialized PEB at {:p}", peb);
    crate::serial_println!("[PEB]   Image base:   {:#x}", image_base);
    crate::serial_println!("[PEB]   Image size:   {:#x}", image_size);
    crate::serial_println!("[PEB]   Entry point:  {:#x}", entry_point);
    crate::serial_println!("[PEB]   Subsystem:    {}", subsystem);
}

/// Initialize PEB loader data (PEB_LDR_DATA)
///
/// This sets up the module lists that track loaded DLLs.
///
/// # Safety
/// peb must have been initialized with init_peb
pub unsafe fn init_peb_ldr_data(peb: *mut Peb, ldr: *mut PebLdrData) {
    let peb = &mut *peb;
    let ldr = &mut *ldr;

    // Initialize loader data
    ldr.length = core::mem::size_of::<PebLdrData>() as u32;
    ldr.initialized = 1;

    // Initialize module lists as empty (pointing to themselves)
    ldr.in_load_order_module_list.init_head();
    ldr.in_memory_order_module_list.init_head();
    ldr.in_initialization_order_module_list.init_head();

    // Link to PEB
    peb.ldr = ldr;

    crate::serial_println!("[PEB] Initialized loader data at {:p}", ldr);
}

// ============================================================================
// LDR_DATA_TABLE_ENTRY Pool and Initialization
// ============================================================================

/// Maximum number of loaded modules per process
pub const MAX_LDR_ENTRIES: usize = 64;

/// Static pool of LDR_DATA_TABLE_ENTRY structures
static mut LDR_ENTRY_POOL: [LdrDataTableEntry; MAX_LDR_ENTRIES] = {
    const INIT: LdrDataTableEntry = LdrDataTableEntry::new();
    [INIT; MAX_LDR_ENTRIES]
};

/// LDR entry pool bitmap
static mut LDR_ENTRY_POOL_BITMAP: u64 = 0;

/// LDR entry pool lock
static LDR_ENTRY_POOL_LOCK: crate::ke::SpinLock<()> = crate::ke::SpinLock::new(());

/// Allocate a LDR_DATA_TABLE_ENTRY from the pool
///
/// # Safety
/// Must be called with proper synchronization
pub unsafe fn allocate_ldr_entry() -> Option<*mut LdrDataTableEntry> {
    let _guard = LDR_ENTRY_POOL_LOCK.lock();

    for bit_idx in 0..MAX_LDR_ENTRIES {
        if LDR_ENTRY_POOL_BITMAP & (1 << bit_idx) == 0 {
            LDR_ENTRY_POOL_BITMAP |= 1 << bit_idx;
            let entry = &mut LDR_ENTRY_POOL[bit_idx] as *mut LdrDataTableEntry;
            // Initialize to default
            *entry = LdrDataTableEntry::new();
            return Some(entry);
        }
    }
    None
}

/// Free a LDR_DATA_TABLE_ENTRY back to the pool
///
/// # Safety
/// Entry must have been allocated from this pool
pub unsafe fn free_ldr_entry(entry: *mut LdrDataTableEntry) {
    let _guard = LDR_ENTRY_POOL_LOCK.lock();

    let base = LDR_ENTRY_POOL.as_ptr() as usize;
    let offset = entry as usize - base;
    let index = offset / core::mem::size_of::<LdrDataTableEntry>();
    if index < MAX_LDR_ENTRIES {
        LDR_ENTRY_POOL_BITMAP &= !(1 << index);
    }
}

/// LDR entry flags
pub mod ldr_flags {
    /// Entry is statically linked (not dynamically loaded)
    pub const LDRP_STATIC_LINK: u32 = 0x00000002;
    /// Entry is the image (main executable)
    pub const LDRP_IMAGE_DLL: u32 = 0x00000004;
    /// Entry point has been called
    pub const LDRP_ENTRY_PROCESSED: u32 = 0x00004000;
    /// Entry is being processed
    pub const LDRP_PROCESS_ATTACH_CALLED: u32 = 0x00080000;
    /// DLL can be relocated
    pub const LDRP_REDIRECTED: u32 = 0x10000000;
}

/// Initialize a LDR_DATA_TABLE_ENTRY for a loaded module
///
/// # Arguments
/// * `entry` - Pointer to entry to initialize
/// * `dll_base` - Base address of the loaded module
/// * `entry_point` - Entry point address
/// * `size_of_image` - Size of the module image
/// * `name` - Module name (base name only)
/// * `is_exe` - True if this is the main executable
///
/// # Safety
/// entry must be a valid allocated LdrDataTableEntry
pub unsafe fn init_ldr_entry(
    entry: *mut LdrDataTableEntry,
    dll_base: u64,
    entry_point: u64,
    size_of_image: u32,
    name: &[u8],
    is_exe: bool,
) {
    let entry = &mut *entry;

    // Set module addresses
    entry.dll_base = dll_base as *mut u8;
    entry.entry_point = entry_point as *mut u8;
    entry.size_of_image = size_of_image;

    // Set initial load count
    entry.load_count = if is_exe { u16::MAX } else { 1 }; // -1 for exe (pinned)

    // Set flags
    entry.flags = ldr_flags::LDRP_STATIC_LINK;
    if !is_exe {
        entry.flags |= ldr_flags::LDRP_IMAGE_DLL;
    }

    // Initialize links (will be updated when added to list)
    entry.in_load_order_links.init_head();
    entry.in_memory_order_links.init_head();
    entry.in_initialization_order_links.init_head();
    entry.hash_links.init_head();
    entry.node_module_link.init_head();

    // Set the base name
    // In a full implementation, we'd allocate unicode string buffers
    // For now, just log what we're initializing
    crate::serial_println!("[LDR] Initialized entry for '{}'",
        core::str::from_utf8_unchecked(name));
    crate::serial_println!("[LDR]   Base:        {:#x}", dll_base);
    crate::serial_println!("[LDR]   Entry:       {:#x}", entry_point);
    crate::serial_println!("[LDR]   Size:        {:#x}", size_of_image);
    crate::serial_println!("[LDR]   Flags:       {:#x}", entry.flags);
}

/// Add a LDR entry to the PEB_LDR_DATA module lists
///
/// # Safety
/// - ldr must be a valid initialized PEB_LDR_DATA
/// - entry must be a valid initialized LdrDataTableEntry
pub unsafe fn add_ldr_entry_to_lists(ldr: *mut PebLdrData, entry: *mut LdrDataTableEntry) {
    let ldr = &mut *ldr;
    let entry = &mut *entry;

    // Add to load order list (at tail)
    insert_tail_list64(
        &mut ldr.in_load_order_module_list,
        &mut entry.in_load_order_links,
    );

    // Add to memory order list (at tail)
    // Memory order list uses a different offset into LdrDataTableEntry
    insert_tail_list64(
        &mut ldr.in_memory_order_module_list,
        &mut entry.in_memory_order_links,
    );

    // Add to init order list (at tail)
    insert_tail_list64(
        &mut ldr.in_initialization_order_module_list,
        &mut entry.in_initialization_order_links,
    );
}

/// Insert entry at tail of a doubly-linked list
unsafe fn insert_tail_list64(head: &mut ListEntry64, entry: &mut ListEntry64) {
    let head_addr = head as *mut ListEntry64 as u64;
    let entry_addr = entry as *mut ListEntry64 as u64;

    // Get current tail
    let tail_addr = head.blink;

    // Entry's forward points to head, backward points to old tail
    entry.flink = head_addr;
    entry.blink = tail_addr;

    // Old tail's forward now points to new entry
    if tail_addr != 0 {
        let tail = tail_addr as *mut ListEntry64;
        (*tail).flink = entry_addr;
    }

    // Head's backward points to new entry (new tail)
    head.blink = entry_addr;

    // If list was empty, head's forward also points to entry
    if head.flink == head_addr {
        head.flink = entry_addr;
    }
}

/// Create and add a LDR entry for a loaded module
///
/// Convenience function that allocates an entry, initializes it,
/// and adds it to the loader lists.
///
/// # Returns
/// Pointer to the new entry, or null on failure
///
/// # Safety
/// ldr must be a valid initialized PEB_LDR_DATA
pub unsafe fn create_ldr_entry_for_module(
    ldr: *mut PebLdrData,
    dll_base: u64,
    entry_point: u64,
    size_of_image: u32,
    name: &[u8],
    is_exe: bool,
) -> *mut LdrDataTableEntry {
    // Allocate entry
    let entry = match allocate_ldr_entry() {
        Some(e) => e,
        None => {
            crate::serial_println!("[LDR] Failed to allocate LDR entry");
            return core::ptr::null_mut();
        }
    };

    // Initialize entry
    init_ldr_entry(entry, dll_base, entry_point, size_of_image, name, is_exe);

    // Add to lists
    add_ldr_entry_to_lists(ldr, entry);

    entry
}
