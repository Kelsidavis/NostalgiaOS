//! Accelerator Table Subsystem
//!
//! Implementation of Windows NT-style keyboard accelerator tables.
//! Provides keyboard shortcuts that translate to WM_COMMAND messages.
//!
//! # Components
//!
//! - **Accelerator entries**: ACCEL with fVirt, key, cmd
//! - **Accelerator tables**: CreateAcceleratorTable, DestroyAcceleratorTable
//! - **Translation**: TranslateAccelerator
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/mnaccel.c`

use super::super::{HWND, UserHandle};
use super::message::{self, MSG};
use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum accelerators per table
const MAX_ACCELERATORS: usize = 64;

/// Maximum accelerator tables
const MAX_ACCEL_TABLES: usize = 32;

// ============================================================================
// Accelerator Flags (fVirt field)
// ============================================================================

/// Virtual key (otherwise it's a character code)
pub const FVIRTKEY: u8 = 0x01;

/// Do not invert menu item
pub const FNOINVERT: u8 = 0x02;

/// Shift key must be pressed
pub const FSHIFT: u8 = 0x04;

/// Control key must be pressed
pub const FCONTROL: u8 = 0x08;

/// Alt key must be pressed
pub const FALT: u8 = 0x10;

/// Last key in accelerator table (internal use)
const FLASTKEY: u8 = 0x80;

// ============================================================================
// ACCEL Structure
// ============================================================================

/// Accelerator entry
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Accel {
    /// Flags (FVIRTKEY, FSHIFT, FCONTROL, FALT, FNOINVERT)
    pub f_virt: u8,
    /// Key code (virtual key if FVIRTKEY, character otherwise)
    pub key: u16,
    /// Command ID (sent as wParam of WM_COMMAND)
    pub cmd: u16,
}

impl Accel {
    /// Create a new accelerator entry
    pub const fn new(f_virt: u8, key: u16, cmd: u16) -> Self {
        Self { f_virt, key, cmd }
    }

    /// Create a virtual key accelerator
    pub const fn virt_key(key: u16, cmd: u16) -> Self {
        Self { f_virt: FVIRTKEY, key, cmd }
    }

    /// Create a Ctrl+Key accelerator
    pub const fn ctrl_key(key: u16, cmd: u16) -> Self {
        Self { f_virt: FVIRTKEY | FCONTROL, key, cmd }
    }

    /// Create a Alt+Key accelerator
    pub const fn alt_key(key: u16, cmd: u16) -> Self {
        Self { f_virt: FVIRTKEY | FALT, key, cmd }
    }

    /// Create a Shift+Key accelerator
    pub const fn shift_key(key: u16, cmd: u16) -> Self {
        Self { f_virt: FVIRTKEY | FSHIFT, key, cmd }
    }

    /// Create a Ctrl+Shift+Key accelerator
    pub const fn ctrl_shift_key(key: u16, cmd: u16) -> Self {
        Self { f_virt: FVIRTKEY | FCONTROL | FSHIFT, key, cmd }
    }
}

// ============================================================================
// HACCEL Handle
// ============================================================================

/// Handle to accelerator table
pub type HACCEL = UserHandle;

// ============================================================================
// Accelerator Table
// ============================================================================

/// Accelerator table structure
#[derive(Clone)]
struct AccelTable {
    /// Table entries
    entries: [Accel; MAX_ACCELERATORS],
    /// Number of entries
    count: usize,
    /// Is this slot in use?
    in_use: bool,
}

impl AccelTable {
    const fn empty() -> Self {
        Self {
            entries: [Accel { f_virt: 0, key: 0, cmd: 0 }; MAX_ACCELERATORS],
            count: 0,
            in_use: false,
        }
    }
}

/// Accelerator table storage
static ACCEL_TABLES: SpinLock<[AccelTable; MAX_ACCEL_TABLES]> = SpinLock::new([
    AccelTable::empty(), AccelTable::empty(), AccelTable::empty(), AccelTable::empty(),
    AccelTable::empty(), AccelTable::empty(), AccelTable::empty(), AccelTable::empty(),
    AccelTable::empty(), AccelTable::empty(), AccelTable::empty(), AccelTable::empty(),
    AccelTable::empty(), AccelTable::empty(), AccelTable::empty(), AccelTable::empty(),
    AccelTable::empty(), AccelTable::empty(), AccelTable::empty(), AccelTable::empty(),
    AccelTable::empty(), AccelTable::empty(), AccelTable::empty(), AccelTable::empty(),
    AccelTable::empty(), AccelTable::empty(), AccelTable::empty(), AccelTable::empty(),
    AccelTable::empty(), AccelTable::empty(), AccelTable::empty(), AccelTable::empty(),
]);

static ACCEL_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize accelerator subsystem
pub fn init() {
    if ACCEL_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[USER/Accelerator] Accelerator subsystem initialized");
    ACCEL_INITIALIZED.store(true, Ordering::Release);
}

// ============================================================================
// Accelerator Table Management
// ============================================================================

/// Create an accelerator table
///
/// # Arguments
/// * `accels` - Slice of accelerator entries
///
/// # Returns
/// Handle to the accelerator table, or NULL on failure
pub fn create_accelerator_table(accels: &[Accel]) -> HACCEL {
    if accels.is_empty() || accels.len() > MAX_ACCELERATORS {
        return HACCEL::NULL;
    }

    let mut tables = ACCEL_TABLES.lock();

    // Find empty slot
    for (index, table) in tables.iter_mut().enumerate() {
        if !table.in_use {
            // Copy accelerators
            let count = accels.len();
            table.entries[..count].copy_from_slice(accels);

            // Mark last entry
            if count > 0 {
                table.entries[count - 1].f_virt |= FLASTKEY;
            }

            table.count = count;
            table.in_use = true;

            // Create handle (index + 1 to avoid 0)
            let handle = HACCEL::from_raw((index as u32 + 1) | 0x00030000);

            crate::serial_println!("[USER/Accelerator] Created table {:x} with {} entries",
                handle.raw(), count);

            return handle;
        }
    }

    HACCEL::NULL
}

/// Destroy an accelerator table
///
/// # Arguments
/// * `haccel` - Handle to accelerator table
///
/// # Returns
/// true on success
pub fn destroy_accelerator_table(haccel: HACCEL) -> bool {
    if haccel == HACCEL::NULL {
        return false;
    }

    let index = ((haccel.raw() & 0xFFFF) - 1) as usize;
    if index >= MAX_ACCEL_TABLES {
        return false;
    }

    let mut tables = ACCEL_TABLES.lock();

    if !tables[index].in_use {
        return false;
    }

    tables[index].in_use = false;
    tables[index].count = 0;

    crate::serial_println!("[USER/Accelerator] Destroyed table {:x}", haccel.raw());

    true
}

/// Copy accelerator table entries
///
/// # Arguments
/// * `haccel` - Handle to accelerator table
/// * `buffer` - Buffer to copy entries into
///
/// # Returns
/// Number of entries copied, or 0 on failure
pub fn copy_accelerator_table(haccel: HACCEL, buffer: &mut [Accel]) -> usize {
    if haccel == HACCEL::NULL {
        return 0;
    }

    let index = ((haccel.raw() & 0xFFFF) - 1) as usize;
    if index >= MAX_ACCEL_TABLES {
        return 0;
    }

    let tables = ACCEL_TABLES.lock();

    if !tables[index].in_use {
        return 0;
    }

    let count = tables[index].count.min(buffer.len());
    buffer[..count].copy_from_slice(&tables[index].entries[..count]);

    // Clear the FLASTKEY flag from copied data (it's internal)
    for accel in buffer[..count].iter_mut() {
        accel.f_virt &= !FLASTKEY;
    }

    count
}

/// Get number of entries in accelerator table
pub fn get_accelerator_count(haccel: HACCEL) -> usize {
    if haccel == HACCEL::NULL {
        return 0;
    }

    let index = ((haccel.raw() & 0xFFFF) - 1) as usize;
    if index >= MAX_ACCEL_TABLES {
        return 0;
    }

    let tables = ACCEL_TABLES.lock();

    if !tables[index].in_use {
        return 0;
    }

    tables[index].count
}

// ============================================================================
// Keyboard State (for modifier key checking)
// ============================================================================

/// Current keyboard modifier state
static KEYBOARD_MODIFIERS: AtomicU32 = AtomicU32::new(0);

const MOD_SHIFT: u32 = 0x01;
const MOD_CONTROL: u32 = 0x02;
const MOD_ALT: u32 = 0x04;

/// Update keyboard modifier state
pub fn update_modifiers(shift: bool, control: bool, alt: bool) {
    let mut mods = 0u32;
    if shift { mods |= MOD_SHIFT; }
    if control { mods |= MOD_CONTROL; }
    if alt { mods |= MOD_ALT; }
    KEYBOARD_MODIFIERS.store(mods, Ordering::Release);
}

/// Get current keyboard modifier state
fn get_modifiers() -> (bool, bool, bool) {
    let mods = KEYBOARD_MODIFIERS.load(Ordering::Acquire);
    (
        mods & MOD_SHIFT != 0,
        mods & MOD_CONTROL != 0,
        mods & MOD_ALT != 0,
    )
}

// ============================================================================
// Translate Accelerator
// ============================================================================

/// Translate a keyboard message using an accelerator table
///
/// # Arguments
/// * `hwnd` - Window handle
/// * `haccel` - Accelerator table handle
/// * `msg` - Message to translate
///
/// # Returns
/// true if message was translated and WM_COMMAND was sent
pub fn translate_accelerator(hwnd: HWND, haccel: HACCEL, msg: &MSG) -> bool {
    if hwnd == HWND::NULL || haccel == HACCEL::NULL {
        return false;
    }

    // Only process keyboard messages
    let is_key_down = msg.message == message::WM_KEYDOWN ||
                      msg.message == message::WM_SYSKEYDOWN;
    let is_char = msg.message == message::WM_CHAR ||
                  msg.message == message::WM_SYSCHAR;

    if !is_key_down && !is_char {
        return false;
    }

    let index = ((haccel.raw() & 0xFFFF) - 1) as usize;
    if index >= MAX_ACCEL_TABLES {
        return false;
    }

    let tables = ACCEL_TABLES.lock();

    if !tables[index].in_use {
        return false;
    }

    let (shift_down, ctrl_down, alt_down) = get_modifiers();

    // Search for matching accelerator
    for i in 0..tables[index].count {
        let accel = &tables[index].entries[i];
        let is_virt_key = (accel.f_virt & FVIRTKEY) != 0;

        // Check if key type matches
        if is_virt_key != is_key_down {
            continue;
        }

        // Check if key matches
        if accel.key as u32 != msg.wparam as u32 {
            continue;
        }

        // Check modifier keys for virtual key accelerators
        if is_virt_key {
            let need_shift = (accel.f_virt & FSHIFT) != 0;
            let need_ctrl = (accel.f_virt & FCONTROL) != 0;
            let need_alt = (accel.f_virt & FALT) != 0;

            if shift_down != need_shift || ctrl_down != need_ctrl {
                continue;
            }

            if alt_down != need_alt {
                continue;
            }
        }

        // Found a match - send WM_COMMAND
        let cmd = accel.cmd as u32;
        let wparam = (cmd & 0xFFFF) | (1 << 16); // High word = 1 for accelerator

        // Drop the lock before sending message
        drop(tables);

        // Send WM_COMMAND to the window
        super::message::post_message(hwnd, message::WM_COMMAND, wparam as usize, 0);

        crate::serial_println!("[USER/Accelerator] Translated key {:x} -> command {}",
            msg.wparam, cmd);

        return true;
    }

    false
}

// ============================================================================
// Standard Accelerator Keys (Virtual Key Codes)
// ============================================================================

/// Standard virtual key codes for accelerators
pub mod vk {
    pub const VK_BACK: u16 = 0x08;
    pub const VK_TAB: u16 = 0x09;
    pub const VK_RETURN: u16 = 0x0D;
    pub const VK_ESCAPE: u16 = 0x1B;
    pub const VK_SPACE: u16 = 0x20;
    pub const VK_PRIOR: u16 = 0x21;  // Page Up
    pub const VK_NEXT: u16 = 0x22;   // Page Down
    pub const VK_END: u16 = 0x23;
    pub const VK_HOME: u16 = 0x24;
    pub const VK_LEFT: u16 = 0x25;
    pub const VK_UP: u16 = 0x26;
    pub const VK_RIGHT: u16 = 0x27;
    pub const VK_DOWN: u16 = 0x28;
    pub const VK_INSERT: u16 = 0x2D;
    pub const VK_DELETE: u16 = 0x2E;
    pub const VK_HELP: u16 = 0x2F;

    // 0-9
    pub const VK_0: u16 = 0x30;
    pub const VK_1: u16 = 0x31;
    pub const VK_2: u16 = 0x32;
    pub const VK_3: u16 = 0x33;
    pub const VK_4: u16 = 0x34;
    pub const VK_5: u16 = 0x35;
    pub const VK_6: u16 = 0x36;
    pub const VK_7: u16 = 0x37;
    pub const VK_8: u16 = 0x38;
    pub const VK_9: u16 = 0x39;

    // A-Z
    pub const VK_A: u16 = 0x41;
    pub const VK_B: u16 = 0x42;
    pub const VK_C: u16 = 0x43;
    pub const VK_D: u16 = 0x44;
    pub const VK_E: u16 = 0x45;
    pub const VK_F: u16 = 0x46;
    pub const VK_G: u16 = 0x47;
    pub const VK_H: u16 = 0x48;
    pub const VK_I: u16 = 0x49;
    pub const VK_J: u16 = 0x4A;
    pub const VK_K: u16 = 0x4B;
    pub const VK_L: u16 = 0x4C;
    pub const VK_M: u16 = 0x4D;
    pub const VK_N: u16 = 0x4E;
    pub const VK_O: u16 = 0x4F;
    pub const VK_P: u16 = 0x50;
    pub const VK_Q: u16 = 0x51;
    pub const VK_R: u16 = 0x52;
    pub const VK_S: u16 = 0x53;
    pub const VK_T: u16 = 0x54;
    pub const VK_U: u16 = 0x55;
    pub const VK_V: u16 = 0x56;
    pub const VK_W: u16 = 0x57;
    pub const VK_X: u16 = 0x58;
    pub const VK_Y: u16 = 0x59;
    pub const VK_Z: u16 = 0x5A;

    // Function keys
    pub const VK_F1: u16 = 0x70;
    pub const VK_F2: u16 = 0x71;
    pub const VK_F3: u16 = 0x72;
    pub const VK_F4: u16 = 0x73;
    pub const VK_F5: u16 = 0x74;
    pub const VK_F6: u16 = 0x75;
    pub const VK_F7: u16 = 0x76;
    pub const VK_F8: u16 = 0x77;
    pub const VK_F9: u16 = 0x78;
    pub const VK_F10: u16 = 0x79;
    pub const VK_F11: u16 = 0x7A;
    pub const VK_F12: u16 = 0x7B;
}

// ============================================================================
// Standard Command IDs
// ============================================================================

/// Standard Edit menu command IDs
pub mod cmd {
    pub const ID_EDIT_UNDO: u16 = 0xE12B;
    pub const ID_EDIT_REDO: u16 = 0xE12C;
    pub const ID_EDIT_CUT: u16 = 0xE123;
    pub const ID_EDIT_COPY: u16 = 0xE122;
    pub const ID_EDIT_PASTE: u16 = 0xE125;
    pub const ID_EDIT_DELETE: u16 = 0xE120;
    pub const ID_EDIT_SELECT_ALL: u16 = 0xE12A;
    pub const ID_EDIT_FIND: u16 = 0xE124;
    pub const ID_EDIT_REPLACE: u16 = 0xE126;

    pub const ID_FILE_NEW: u16 = 0xE100;
    pub const ID_FILE_OPEN: u16 = 0xE101;
    pub const ID_FILE_SAVE: u16 = 0xE103;
    pub const ID_FILE_SAVE_AS: u16 = 0xE104;
    pub const ID_FILE_PRINT: u16 = 0xE107;
    pub const ID_FILE_CLOSE: u16 = 0xE10C;
    pub const ID_FILE_EXIT: u16 = 0xE141;

    pub const ID_HELP_ABOUT: u16 = 0xE140;
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a standard Edit menu accelerator table
pub fn create_standard_edit_accels() -> HACCEL {
    use vk::*;
    use cmd::*;

    let accels = [
        Accel::ctrl_key(VK_Z, ID_EDIT_UNDO),      // Ctrl+Z = Undo
        Accel::ctrl_key(VK_Y, ID_EDIT_REDO),      // Ctrl+Y = Redo
        Accel::ctrl_key(VK_X, ID_EDIT_CUT),       // Ctrl+X = Cut
        Accel::ctrl_key(VK_C, ID_EDIT_COPY),      // Ctrl+C = Copy
        Accel::ctrl_key(VK_V, ID_EDIT_PASTE),     // Ctrl+V = Paste
        Accel::virt_key(VK_DELETE, ID_EDIT_DELETE), // Delete = Delete
        Accel::ctrl_key(VK_A, ID_EDIT_SELECT_ALL),  // Ctrl+A = Select All
        Accel::ctrl_key(VK_F, ID_EDIT_FIND),      // Ctrl+F = Find
        Accel::ctrl_key(VK_H, ID_EDIT_REPLACE),   // Ctrl+H = Replace
    ];

    create_accelerator_table(&accels)
}

/// Create a standard File menu accelerator table
pub fn create_standard_file_accels() -> HACCEL {
    use vk::*;
    use cmd::*;

    let accels = [
        Accel::ctrl_key(VK_N, ID_FILE_NEW),       // Ctrl+N = New
        Accel::ctrl_key(VK_O, ID_FILE_OPEN),      // Ctrl+O = Open
        Accel::ctrl_key(VK_S, ID_FILE_SAVE),      // Ctrl+S = Save
        Accel::ctrl_shift_key(VK_S, ID_FILE_SAVE_AS), // Ctrl+Shift+S = Save As
        Accel::ctrl_key(VK_P, ID_FILE_PRINT),     // Ctrl+P = Print
        Accel::ctrl_key(VK_W, ID_FILE_CLOSE),     // Ctrl+W = Close
        Accel::alt_key(VK_F4, ID_FILE_EXIT),      // Alt+F4 = Exit
    ];

    create_accelerator_table(&accels)
}

// ============================================================================
// Statistics
// ============================================================================

/// Accelerator statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceleratorStats {
    pub table_count: usize,
    pub total_entries: usize,
}

/// Get accelerator statistics
pub fn get_stats() -> AcceleratorStats {
    let tables = ACCEL_TABLES.lock();

    let mut table_count = 0;
    let mut total_entries = 0;

    for table in tables.iter() {
        if table.in_use {
            table_count += 1;
            total_entries += table.count;
        }
    }

    AcceleratorStats {
        table_count,
        total_entries,
    }
}
