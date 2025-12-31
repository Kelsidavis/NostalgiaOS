//! Kernel Debugger (KD) Subsystem
//!
//! The Kernel Debugger provides debugging infrastructure for the kernel:
//! - Breakpoint management
//! - Debug print buffer
//! - Debugger data blocks for extensions
//! - Debug trap handling
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Kernel Debugger (KD)                     │
//! ├─────────────┬─────────────┬─────────────┬─────────────────┤
//! │ Breakpoints │ Print Buffer│ Data Blocks │   Debug Trap    │
//! ├─────────────┼─────────────┼─────────────┼─────────────────┤
//! │    Table    │  Circular   │   Version   │    Int 3 / Int 1│
//! │  Set/Clear  │   Buffer    │  Debugger   │    Handler      │
//! └─────────────┴─────────────┴─────────────┴─────────────────┘
//! ```
//!
//! Based on Windows Server 2003 base/ntos/kd64/

pub mod breakpoint;
pub mod data;
pub mod print;

pub use breakpoint::*;
pub use data::*;
pub use print::*;

use crate::ke::SpinLock;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

extern crate alloc;

/// Debugger initialized flag
static KD_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Debugger enabled flag
static KD_ENABLED: AtomicBool = AtomicBool::new(false);

/// Debugger not present flag (for user-mode checks)
static KD_DEBUGGER_NOT_PRESENT: AtomicBool = AtomicBool::new(true);

/// Debug port locked flag
static KD_PORT_LOCKED: AtomicBool = AtomicBool::new(false);

/// Pitch debugger flag (refuse to enable)
static KD_PITCH_DEBUGGER: AtomicBool = AtomicBool::new(true);

/// Control-C pressed flag
static KD_CONTROL_C_PRESSED: AtomicBool = AtomicBool::new(false);

/// Count of times debugger was entered
static KD_ENTERED_DEBUGGER: AtomicU64 = AtomicU64::new(0);

/// Protocol version
pub const DBGKD_64BIT_PROTOCOL_VERSION2: u16 = 6;

/// Max state change value
pub const DBGKD_MAXIMUM_STATE_CHANGE: u32 = 0x00000003;
pub const DBGKD_MINIMUM_STATE_CHANGE: u32 = 0x00000001;

/// Max manipulate value
pub const DBGKD_MAXIMUM_MANIPULATE: u32 = 0x00000039;
pub const DBGKD_MINIMUM_MANIPULATE: u32 = 0x00000031;

/// Machine type for x86_64
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// Version flags
pub mod version_flags {
    pub const DBGKD_VERS_FLAG_MP: u16 = 0x0001;
    pub const DBGKD_VERS_FLAG_DATA: u16 = 0x0002;
    pub const DBGKD_VERS_FLAG_PTR64: u16 = 0x0004;
    pub const DBGKD_VERS_FLAG_NOMM: u16 = 0x0008;
    pub const DBGKD_VERS_FLAG_HSS: u16 = 0x0010;
    pub const DBGKD_VERS_FLAG_PARTITIONS: u16 = 0x0020;
}

/// Debug filter component IDs
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugPrintComponent {
    System = 0,
    Smss = 1,
    Setup = 2,
    Ntfs = 3,
    Fstub = 4,
    Crashdump = 5,
    Cdaudio = 6,
    Cdrom = 7,
    Classpnp = 8,
    Disk = 9,
    Redbook = 10,
    Storprop = 11,
    Scsiport = 12,
    Scsiminiport = 13,
    Config = 14,
    I8042prt = 15,
    Sermouse = 16,
    Lsermous = 17,
    Kbdhid = 18,
    Mouhid = 19,
    Kbdclass = 20,
    Mouclass = 21,
    Twotrack = 22,
    Wmilib = 23,
    Acpi = 24,
    Amli = 25,
    Halia64 = 26,
    Video = 27,
    Svchost = 28,
    Videoprt = 29,
    Tcpip = 30,
    Dmsynth = 31,
    Ntospnp = 32,
    Fastfat = 33,
    Samss = 34,
    Pnpmgr = 35,
    Netapi = 36,
    Scserver = 37,
    Scclient = 38,
    Serial = 39,
    Serenum = 40,
    Uhcd = 41,
    Rpcproxy = 42,
    Autochk = 43,
    Dcomss = 44,
    Unimodem = 45,
    Sis = 46,
    Fltmgr = 47,
    Wmicore = 48,
    Burneng = 49,
    Imapi = 50,
    Default = 101,
}

/// Kernel debugger global state
pub struct KdState {
    /// Version block
    version: SpinLock<KdVersionBlock>,
    /// Break after symbol load flag
    break_after_symbol_load: AtomicBool,
    /// Auto enable on event
    auto_enable_on_event: AtomicBool,
    /// Ignore user mode exceptions
    ignore_um_exceptions: AtomicBool,
}

impl KdState {
    pub const fn new() -> Self {
        Self {
            version: SpinLock::new(KdVersionBlock::new()),
            break_after_symbol_load: AtomicBool::new(false),
            auto_enable_on_event: AtomicBool::new(false),
            ignore_um_exceptions: AtomicBool::new(false),
        }
    }
}

static mut KD_STATE: Option<KdState> = None;

fn get_kd_state() -> &'static KdState {
    unsafe { KD_STATE.as_ref().expect("KD not initialized") }
}

/// Initialize the Kernel Debugger subsystem
pub fn kd_init_system(phase: u32, debug_enabled: bool) -> bool {
    if phase == 0 {
        // Phase 0: Early initialization
        if KD_INITIALIZED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return true; // Already initialized
        }

        unsafe {
            KD_STATE = Some(KdState::new());
        }

        // Initialize sub-components
        kd_breakpoint_init();
        kd_print_init();
        kd_data_init();

        let state = get_kd_state();

        // Set version info
        {
            let mut version = state.version.lock();
            version.major_version = 5;
            version.minor_version = 2; // NT 5.2 = Windows Server 2003
            version.protocol_version = DBGKD_64BIT_PROTOCOL_VERSION2;
            version.machine_type = IMAGE_FILE_MACHINE_AMD64;
            version.max_state_change = (DBGKD_MAXIMUM_STATE_CHANGE - DBGKD_MINIMUM_STATE_CHANGE) as u8;
            version.max_manipulate = (DBGKD_MAXIMUM_MANIPULATE - DBGKD_MINIMUM_MANIPULATE) as u8;
            version.flags = version_flags::DBGKD_VERS_FLAG_PTR64 | version_flags::DBGKD_VERS_FLAG_DATA;
        }

        if debug_enabled {
            KD_PITCH_DEBUGGER.store(false, Ordering::SeqCst);
            KD_ENABLED.store(true, Ordering::SeqCst);
            KD_DEBUGGER_NOT_PRESENT.store(false, Ordering::SeqCst);

            crate::serial_println!("[KD] Kernel debugger enabled");
        } else {
            crate::serial_println!("[KD] Kernel debugger disabled (boot option)");
        }

        crate::serial_println!("[KD] Kernel debugger initialized (phase 0)");
    } else if phase == 1 {
        // Phase 1: Post-memory initialization
        crate::serial_println!("[KD] Kernel debugger initialized (phase 1)");
    }

    true
}

/// Check if kernel debugger is enabled
#[inline]
pub fn kd_debugger_enabled() -> bool {
    KD_ENABLED.load(Ordering::Relaxed)
}

/// Check if debugger is not present
#[inline]
pub fn kd_debugger_not_present() -> bool {
    KD_DEBUGGER_NOT_PRESENT.load(Ordering::Relaxed)
}

/// Enable the kernel debugger
pub fn kd_enable_debugger() -> bool {
    if KD_PITCH_DEBUGGER.load(Ordering::SeqCst) {
        return false;
    }

    if !KD_INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }

    KD_ENABLED.store(true, Ordering::SeqCst);
    KD_DEBUGGER_NOT_PRESENT.store(false, Ordering::SeqCst);

    crate::serial_println!("[KD] Debugger enabled");
    true
}

/// Disable the kernel debugger
pub fn kd_disable_debugger() -> bool {
    if !KD_INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }

    KD_ENABLED.store(false, Ordering::SeqCst);
    KD_DEBUGGER_NOT_PRESENT.store(true, Ordering::SeqCst);

    crate::serial_println!("[KD] Debugger disabled");
    true
}

/// Enter the debugger (debug trap)
pub fn kd_enter_debugger() -> bool {
    if !kd_debugger_enabled() {
        return false;
    }

    KD_ENTERED_DEBUGGER.fetch_add(1, Ordering::Relaxed);
    KD_PORT_LOCKED.store(true, Ordering::SeqCst);

    // In a real implementation, this would freeze other processors
    // and wait for debugger commands

    true
}

/// Exit the debugger
pub fn kd_exit_debugger(resume: bool) {
    KD_PORT_LOCKED.store(false, Ordering::SeqCst);

    if resume {
        // Resume execution
    }
}

/// Poll for break-in from debugger
pub fn kd_poll_break_in() -> bool {
    if !kd_debugger_enabled() {
        return false;
    }

    // Check if Ctrl+C was pressed
    KD_CONTROL_C_PRESSED.load(Ordering::Relaxed)
}

/// Set Control-C pressed flag
pub fn kd_set_control_c_pressed(pressed: bool) {
    KD_CONTROL_C_PRESSED.store(pressed, Ordering::SeqCst);
}

/// Get debugger entry count
pub fn kd_get_entered_count() -> u64 {
    KD_ENTERED_DEBUGGER.load(Ordering::Relaxed)
}

/// Get version block
pub fn kd_get_version() -> KdVersionBlock {
    if !KD_INITIALIZED.load(Ordering::SeqCst) {
        return KdVersionBlock::new();
    }

    let state = get_kd_state();
    state.version.lock().clone()
}

/// Debugger stub (when debugger is disabled)
pub fn kd_stub() {
    // Do nothing - debugger is disabled
}

/// Debug trap handler
pub fn kd_trap(
    trap_frame: usize,
    exception_record: usize,
    is_first_chance: bool,
) -> bool {
    if !kd_debugger_enabled() {
        return false;
    }

    // Log the trap
    crate::serial_println!(
        "[KD] Debug trap: frame={:#x}, exception={:#x}, first_chance={}",
        trap_frame,
        exception_record,
        is_first_chance
    );

    // Enter debugger
    if kd_enter_debugger() {
        // In a real implementation, we'd communicate with the debugger here
        // For now, just exit
        kd_exit_debugger(true);
        return true;
    }

    false
}

/// Get KD statistics
pub fn kd_get_stats() -> (u64, u64, u64, u64) {
    let bp_stats = kd_breakpoint_get_stats();
    let print_stats = kd_print_get_stats();

    (
        KD_ENTERED_DEBUGGER.load(Ordering::Relaxed),
        bp_stats.0, // breakpoints_set
        bp_stats.1, // breakpoints_hit
        print_stats.0, // messages_logged
    )
}

/// Version block structure
#[derive(Debug, Clone)]
pub struct KdVersionBlock {
    /// Major version number
    pub major_version: u16,
    /// Minor version number (build number)
    pub minor_version: u16,
    /// Protocol version
    pub protocol_version: u16,
    /// Flags
    pub flags: u16,
    /// Machine type
    pub machine_type: u16,
    /// Max packet type
    pub max_packet_type: u8,
    /// Max state change
    pub max_state_change: u8,
    /// Max manipulate
    pub max_manipulate: u8,
    /// Simulation flag
    pub simulation: u8,
    /// Kernel base
    pub kern_base: u64,
    /// PsLoadedModuleList
    pub ps_loaded_module_list: u64,
    /// Debugger data list
    pub debugger_data_list: u64,
}

impl KdVersionBlock {
    pub const fn new() -> Self {
        Self {
            major_version: 0,
            minor_version: 0,
            protocol_version: DBGKD_64BIT_PROTOCOL_VERSION2,
            flags: 0,
            machine_type: IMAGE_FILE_MACHINE_AMD64,
            max_packet_type: 12,
            max_state_change: 0,
            max_manipulate: 0,
            simulation: 0,
            kern_base: 0,
            ps_loaded_module_list: 0,
            debugger_data_list: 0,
        }
    }
}
