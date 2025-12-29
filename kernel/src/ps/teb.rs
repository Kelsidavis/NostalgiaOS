//! Thread Environment Block (TEB)
//!
//! The TEB is a user-mode structure that contains thread-specific information.
//! It is located in user-mode address space and is accessible via the GS segment
//! register on x64 (FS on x86).
//!
//! # Structure Layout
//!
//! The TEB contains:
//! - Exception handling chain (x86)
//! - Stack limits
//! - TLS (Thread Local Storage) slots
//! - PEB pointer
//! - Last error value
//! - Current locale
//!
//! # Accessing the TEB
//!
//! On x64:
//! - GS:[0x30] = TEB self pointer
//! - GS:[0x60] = PEB pointer
//! - GS:[0x68] = Last error
//!
//! On x86:
//! - FS:[0x18] = TEB self pointer
//! - FS:[0x30] = PEB pointer
//! - FS:[0x34] = Last error
//!
//! # References
//!
//! Windows Server 2003 DDK: ntpsapi.h

use core::ptr;
use super::peb::{Peb, UnicodeString, ListEntry64};

/// Number of TLS slots
pub const TLS_MINIMUM_AVAILABLE: usize = 64;

/// Number of expansion TLS slots
pub const TLS_EXPANSION_SLOTS: usize = 1024;

/// TEB GS offset for self pointer (x64)
pub const TEB_SELF_OFFSET: usize = 0x30;

/// TEB GS offset for PEB pointer (x64)
pub const TEB_PEB_OFFSET: usize = 0x60;

/// TEB GS offset for last error (x64)
pub const TEB_LAST_ERROR_OFFSET: usize = 0x68;

/// TEB GS offset for thread ID (x64)
pub const TEB_THREAD_ID_OFFSET: usize = 0x48;

/// TEB GS offset for process ID (x64)
pub const TEB_PROCESS_ID_OFFSET: usize = 0x40;

// ============================================================================
// NT_TIB - NT Thread Information Block
// ============================================================================

/// NT Thread Information Block (base of TEB)
///
/// This is the first part of the TEB and contains critical thread
/// information that is accessed frequently.
#[repr(C)]
pub struct NtTib {
    /// Exception list (x86 SEH chain) / Reserved (x64)
    pub exception_list: *mut u8,
    /// Stack base (high address)
    pub stack_base: *mut u8,
    /// Stack limit (low address)
    pub stack_limit: *mut u8,
    /// Sub-system TIB
    pub sub_system_tib: *mut u8,
    /// Fiber data / Version
    pub fiber_data: *mut u8,
    /// Arbitrary user pointer
    pub arbitrary_user_pointer: *mut u8,
    /// Self pointer (for accessing TEB)
    pub self_ptr: *mut NtTib,
}

impl NtTib {
    pub const fn new() -> Self {
        Self {
            exception_list: ptr::null_mut(),
            stack_base: ptr::null_mut(),
            stack_limit: ptr::null_mut(),
            sub_system_tib: ptr::null_mut(),
            fiber_data: ptr::null_mut(),
            arbitrary_user_pointer: ptr::null_mut(),
            self_ptr: ptr::null_mut(),
        }
    }

    /// Initialize the self pointer
    pub fn init_self(&mut self) {
        self.self_ptr = self as *mut NtTib;
    }

    /// Set stack bounds
    pub fn set_stack(&mut self, base: *mut u8, limit: *mut u8) {
        self.stack_base = base;
        self.stack_limit = limit;
    }

    /// Get available stack space
    pub fn stack_space(&self) -> usize {
        if self.stack_base.is_null() || self.stack_limit.is_null() {
            return 0;
        }
        (self.stack_base as usize).saturating_sub(self.stack_limit as usize)
    }
}

impl Default for NtTib {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CLIENT_ID
// ============================================================================

/// Client ID (process and thread IDs)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ClientId {
    /// Process ID
    pub unique_process: u64,
    /// Thread ID
    pub unique_thread: u64,
}

impl ClientId {
    pub const fn new() -> Self {
        Self {
            unique_process: 0,
            unique_thread: 0,
        }
    }

    pub fn from_ids(pid: u64, tid: u64) -> Self {
        Self {
            unique_process: pid,
            unique_thread: tid,
        }
    }
}

// ============================================================================
// GDI_TEB_BATCH
// ============================================================================

/// GDI batch for this thread
#[repr(C)]
pub struct GdiTebBatch {
    /// Offset
    pub offset: u32,
    /// HDC
    pub hdc: u64,
    /// Buffer
    pub buffer: [u32; 310],
}

impl GdiTebBatch {
    pub const fn new() -> Self {
        Self {
            offset: 0,
            hdc: 0,
            buffer: [0; 310],
        }
    }
}

impl Default for GdiTebBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TEB - Thread Environment Block
// ============================================================================

/// Thread Environment Block (64-bit)
///
/// This is the main structure that user-mode code uses to access
/// thread-specific information. It is located in user-mode address space.
#[repr(C)]
pub struct Teb {
    /// NT Thread Information Block
    pub nt_tib: NtTib,
    /// Environment pointer
    pub environment_pointer: *mut u8,
    /// Client ID (process and thread IDs)
    pub client_id: ClientId,
    /// Active RPC handle
    pub active_rpc_handle: *mut u8,
    /// Thread local storage pointer
    pub thread_local_storage_pointer: *mut *mut u8,
    /// Pointer to PEB
    pub process_environment_block: *mut Peb,
    /// Last error value
    pub last_error_value: u32,
    /// Count of owned critical sections
    pub count_of_owned_critical_sections: u32,
    /// CSR client thread
    pub csr_client_thread: *mut u8,
    /// Win32 thread info
    pub win32_thread_info: *mut u8,
    /// User32 reserved
    pub user32_reserved: [u32; 26],
    /// UserReserved
    pub user_reserved: [u32; 5],
    /// WOW32 reserved
    pub wow_32_reserved: *mut u8,
    /// Current locale
    pub current_locale: u32,
    /// FP software status register
    pub fp_software_status_register: u32,
    /// Reserved block
    pub reserved_for_debugger_instrumentation: [*mut u8; 16],
    /// System reserved 1
    pub system_reserved1: [*mut u8; 30],
    /// Placeholder compatibility mode
    pub placeholder_compatibility_mode: u8,
    /// Placeholder reserved
    pub placeholder_reserved: [u8; 11],
    /// Proxy DLL handle
    pub proxy_dll_handle: u32,
    /// Exception code
    pub exception_code: u32,
    /// Padding
    _padding1: u32,
    /// Activation context stack pointer
    pub activation_context_stack_pointer: *mut u8,
    /// Instrumentation callback SP
    pub instrumentation_callback_sp: u64,
    /// Instrumentation callback previous PC
    pub instrumentation_callback_previous_pc: u64,
    /// Instrumentation callback previous SP
    pub instrumentation_callback_previous_sp: u64,
    /// TX FS context
    pub tx_fs_context: u32,
    /// Instrumentation callback disabled
    pub instrumentation_callback_disabled: u8,
    /// Padding
    _padding2: [u8; 3],
    /// GDI batch
    pub gdi_teb_batch: GdiTebBatch,
    /// Real client ID
    pub real_client_id: ClientId,
    /// GDI cached process handle
    pub gdi_cached_process_handle: *mut u8,
    /// GDI client PID
    pub gdi_client_pid: u32,
    /// GDI client TID
    pub gdi_client_tid: u32,
    /// GDI thread locale info
    pub gdi_thread_locale_info: *mut u8,
    /// Win32 client info
    pub win32_client_info: [u64; 62],
    /// GL dispatch table
    pub gl_dispatch_table: [*mut u8; 233],
    /// GL reserved 1
    pub gl_reserved1: [u64; 29],
    /// GL reserved 2
    pub gl_reserved2: *mut u8,
    /// GL section info
    pub gl_section_info: *mut u8,
    /// GL section
    pub gl_section: *mut u8,
    /// GL table
    pub gl_table: *mut u8,
    /// GL current RC
    pub gl_current_rc: *mut u8,
    /// GL context
    pub gl_context: *mut u8,
    /// Last status value
    pub last_status_value: u32,
    /// Padding
    _padding3: u32,
    /// Static unicode string
    pub static_unicode_string: UnicodeString,
    /// Static unicode buffer
    pub static_unicode_buffer: [u16; 261],
    /// Padding
    _padding4: u16,
    /// Deallocation stack
    pub deallocation_stack: *mut u8,
    /// TLS slots
    pub tls_slots: [*mut u8; TLS_MINIMUM_AVAILABLE],
    /// TLS links
    pub tls_links: ListEntry64,
    /// VDM
    pub vdm: *mut u8,
    /// Reserved for NtRpc
    pub reserved_for_ntrpc: *mut u8,
    /// DbgSsReserved
    pub dbg_ss_reserved: [*mut u8; 2],
    /// Hard error mode
    pub hard_error_mode: u32,
    /// Padding
    _padding5: u32,
    /// Instrumentation
    pub instrumentation: [*mut u8; 11],
    /// Activity ID
    pub activity_id: [u8; 16],
    /// SubProcessTag
    pub sub_process_tag: *mut u8,
    /// Perflib data
    pub perflib_data: *mut u8,
    /// ETW trace data
    pub etw_trace_data: *mut u8,
    /// Win sock data
    pub win_sock_data: *mut u8,
    /// GDI batch count
    pub gdi_batch_count: u32,
    /// Current ideal processor/affinity
    pub current_ideal_processor: u32,
    /// Guaranteed stack bytes
    pub guaranteed_stack_bytes: u32,
    /// Padding
    _padding6: u32,
    /// Reserved for Perf
    pub reserved_for_perf: *mut u8,
    /// Reserved for OLE
    pub reserved_for_ole: *mut u8,
    /// Wait status pointer
    pub wait_status_pointer: u32,
    /// Saved priority state
    pub saved_priority_state: *mut u8,
    /// Reserved for code coverage
    pub reserved_for_code_coverage: u64,
    /// Thread pool data
    pub thread_pool_data: *mut u8,
    /// TLS expansion slots
    pub tls_expansion_slots: *mut *mut u8,
    /// Deallocation bstore
    pub deallocation_bstore: *mut u8,
    /// Bstore limit
    pub bstore_limit: *mut u8,
    /// Mui generation
    pub mui_generation: u32,
    /// Is impersonating
    pub is_impersonating: u32,
    /// Nls cache
    pub nls_cache: *mut u8,
    /// Shim data
    pub shim_data: *mut u8,
    /// Heap virtual affinity
    pub heap_virtual_affinity: u16,
    /// Low frag heap data slot
    pub low_frag_heap_data_slot: u16,
    /// Padding
    _padding7: u32,
    /// Current transaction handle
    pub current_transaction_handle: *mut u8,
    /// Active frame
    pub active_frame: *mut u8,
    /// FLS data
    pub fls_data: *mut u8,
    /// Preferred languages
    pub preferred_languages: *mut u8,
    /// User pref languages
    pub user_pref_languages: *mut u8,
    /// Merged pref languages
    pub merged_pref_languages: *mut u8,
    /// Mui impersonation
    pub mui_impersonation: u32,
    /// Cross-TEB flags
    pub cross_teb_flags: u16,
    /// Same TEB flags
    pub same_teb_flags: u16,
    /// Txn scope enter callback
    pub txn_scope_enter_callback: *mut u8,
    /// Txn scope exit callback
    pub txn_scope_exit_callback: *mut u8,
    /// Txn scope context
    pub txn_scope_context: *mut u8,
    /// Lock count
    pub lock_count: u32,
    /// Wow TEB offset
    pub wow_teb_offset: i32,
    /// Resource return value
    pub resource_return_value: *mut u8,
    /// Reserved for Wdf
    pub reserved_for_wdf: *mut u8,
    /// Reserved for CRT
    pub reserved_for_crt: u64,
    /// Effective container ID
    pub effective_container_id: [u8; 16],
}

impl Teb {
    /// Create a new empty TEB
    pub const fn new() -> Self {
        Self {
            nt_tib: NtTib::new(),
            environment_pointer: ptr::null_mut(),
            client_id: ClientId::new(),
            active_rpc_handle: ptr::null_mut(),
            thread_local_storage_pointer: ptr::null_mut(),
            process_environment_block: ptr::null_mut(),
            last_error_value: 0,
            count_of_owned_critical_sections: 0,
            csr_client_thread: ptr::null_mut(),
            win32_thread_info: ptr::null_mut(),
            user32_reserved: [0; 26],
            user_reserved: [0; 5],
            wow_32_reserved: ptr::null_mut(),
            current_locale: 0x0409, // en-US
            fp_software_status_register: 0,
            reserved_for_debugger_instrumentation: [ptr::null_mut(); 16],
            system_reserved1: [ptr::null_mut(); 30],
            placeholder_compatibility_mode: 0,
            placeholder_reserved: [0; 11],
            proxy_dll_handle: 0,
            exception_code: 0,
            _padding1: 0,
            activation_context_stack_pointer: ptr::null_mut(),
            instrumentation_callback_sp: 0,
            instrumentation_callback_previous_pc: 0,
            instrumentation_callback_previous_sp: 0,
            tx_fs_context: 0xFFFE, // TXF_MINIVERSION_DEFAULT_VIEW
            instrumentation_callback_disabled: 0,
            _padding2: [0; 3],
            gdi_teb_batch: GdiTebBatch::new(),
            real_client_id: ClientId::new(),
            gdi_cached_process_handle: ptr::null_mut(),
            gdi_client_pid: 0,
            gdi_client_tid: 0,
            gdi_thread_locale_info: ptr::null_mut(),
            win32_client_info: [0; 62],
            gl_dispatch_table: [ptr::null_mut(); 233],
            gl_reserved1: [0; 29],
            gl_reserved2: ptr::null_mut(),
            gl_section_info: ptr::null_mut(),
            gl_section: ptr::null_mut(),
            gl_table: ptr::null_mut(),
            gl_current_rc: ptr::null_mut(),
            gl_context: ptr::null_mut(),
            last_status_value: 0,
            _padding3: 0,
            static_unicode_string: UnicodeString::new(),
            static_unicode_buffer: [0; 261],
            _padding4: 0,
            deallocation_stack: ptr::null_mut(),
            tls_slots: [ptr::null_mut(); TLS_MINIMUM_AVAILABLE],
            tls_links: ListEntry64::empty(),
            vdm: ptr::null_mut(),
            reserved_for_ntrpc: ptr::null_mut(),
            dbg_ss_reserved: [ptr::null_mut(); 2],
            hard_error_mode: 0,
            _padding5: 0,
            instrumentation: [ptr::null_mut(); 11],
            activity_id: [0; 16],
            sub_process_tag: ptr::null_mut(),
            perflib_data: ptr::null_mut(),
            etw_trace_data: ptr::null_mut(),
            win_sock_data: ptr::null_mut(),
            gdi_batch_count: 0,
            current_ideal_processor: 0,
            guaranteed_stack_bytes: 0,
            _padding6: 0,
            reserved_for_perf: ptr::null_mut(),
            reserved_for_ole: ptr::null_mut(),
            wait_status_pointer: 0,
            saved_priority_state: ptr::null_mut(),
            reserved_for_code_coverage: 0,
            thread_pool_data: ptr::null_mut(),
            tls_expansion_slots: ptr::null_mut(),
            deallocation_bstore: ptr::null_mut(),
            bstore_limit: ptr::null_mut(),
            mui_generation: 0,
            is_impersonating: 0,
            nls_cache: ptr::null_mut(),
            shim_data: ptr::null_mut(),
            heap_virtual_affinity: 0,
            low_frag_heap_data_slot: 0,
            _padding7: 0,
            current_transaction_handle: ptr::null_mut(),
            active_frame: ptr::null_mut(),
            fls_data: ptr::null_mut(),
            preferred_languages: ptr::null_mut(),
            user_pref_languages: ptr::null_mut(),
            merged_pref_languages: ptr::null_mut(),
            mui_impersonation: 0,
            cross_teb_flags: 0,
            same_teb_flags: 0,
            txn_scope_enter_callback: ptr::null_mut(),
            txn_scope_exit_callback: ptr::null_mut(),
            txn_scope_context: ptr::null_mut(),
            lock_count: 0,
            wow_teb_offset: 0,
            resource_return_value: ptr::null_mut(),
            reserved_for_wdf: ptr::null_mut(),
            reserved_for_crt: 0,
            effective_container_id: [0; 16],
        }
    }

    /// Initialize the TEB for a thread
    pub fn init(&mut self, peb: *mut Peb, pid: u64, tid: u64) {
        self.nt_tib.init_self();
        self.process_environment_block = peb;
        self.client_id = ClientId::from_ids(pid, tid);
        self.real_client_id = self.client_id;
        self.gdi_client_pid = pid as u32;
        self.gdi_client_tid = tid as u32;
    }

    /// Set stack information
    pub fn set_stack(&mut self, base: *mut u8, limit: *mut u8, deallocation: *mut u8) {
        self.nt_tib.set_stack(base, limit);
        self.deallocation_stack = deallocation;
    }

    /// Get the last error value
    pub fn get_last_error(&self) -> u32 {
        self.last_error_value
    }

    /// Set the last error value
    pub fn set_last_error(&mut self, error: u32) {
        self.last_error_value = error;
    }

    /// Get the last status value
    pub fn get_last_status(&self) -> u32 {
        self.last_status_value
    }

    /// Set the last status value
    pub fn set_last_status(&mut self, status: u32) {
        self.last_status_value = status;
    }

    /// Get process ID
    pub fn process_id(&self) -> u64 {
        self.client_id.unique_process
    }

    /// Get thread ID
    pub fn thread_id(&self) -> u64 {
        self.client_id.unique_thread
    }

    /// Get a TLS slot value
    pub fn get_tls_value(&self, index: usize) -> Option<*mut u8> {
        if index < TLS_MINIMUM_AVAILABLE {
            Some(self.tls_slots[index])
        } else if index < TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS {
            if self.tls_expansion_slots.is_null() {
                Some(ptr::null_mut())
            } else {
                unsafe {
                    let expansion_index = index - TLS_MINIMUM_AVAILABLE;
                    Some(*self.tls_expansion_slots.add(expansion_index))
                }
            }
        } else {
            None
        }
    }

    /// Set a TLS slot value
    pub fn set_tls_value(&mut self, index: usize, value: *mut u8) -> bool {
        if index < TLS_MINIMUM_AVAILABLE {
            self.tls_slots[index] = value;
            true
        } else if index < TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS {
            if self.tls_expansion_slots.is_null() {
                false
            } else {
                unsafe {
                    let expansion_index = index - TLS_MINIMUM_AVAILABLE;
                    *self.tls_expansion_slots.add(expansion_index) = value;
                }
                true
            }
        } else {
            false
        }
    }

    /// Get pointer to PEB
    pub fn get_peb(&self) -> *mut Peb {
        self.process_environment_block
    }

    /// Get stack base
    pub fn stack_base(&self) -> *mut u8 {
        self.nt_tib.stack_base
    }

    /// Get stack limit
    pub fn stack_limit(&self) -> *mut u8 {
        self.nt_tib.stack_limit
    }
}

impl Default for Teb {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get the current TEB from the GS segment (x64)
///
/// # Safety
/// This function reads from the GS segment which must be properly set up.
#[inline]
pub unsafe fn get_current_teb() -> *mut Teb {
    let teb: *mut Teb;
    core::arch::asm!(
        "mov {}, gs:[0x30]",
        out(reg) teb,
        options(nostack, preserves_flags)
    );
    teb
}

/// Get the current PEB from the GS segment (x64)
///
/// # Safety
/// This function reads from the GS segment which must be properly set up.
#[inline]
pub unsafe fn get_current_peb() -> *mut Peb {
    let peb: *mut Peb;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags)
    );
    peb
}

/// Get the last error value from the current TEB
///
/// # Safety
/// This function reads from the GS segment which must be properly set up.
#[inline]
pub unsafe fn get_last_error() -> u32 {
    let error: u32;
    core::arch::asm!(
        "mov {:e}, gs:[0x68]",
        out(reg) error,
        options(nostack, preserves_flags)
    );
    error
}

/// Set the last error value in the current TEB
///
/// # Safety
/// This function writes to the GS segment which must be properly set up.
#[inline]
pub unsafe fn set_last_error(error: u32) {
    core::arch::asm!(
        "mov gs:[0x68], {:e}",
        in(reg) error,
        options(nostack, preserves_flags)
    );
}
