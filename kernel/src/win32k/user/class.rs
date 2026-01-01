//! Window Class Registration
//!
//! Window classes define the behavior and appearance of windows.
//! Each window is an instance of a class.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/class.c`

use crate::ke::spinlock::SpinLock;
use super::MAX_CLASSES;

// ============================================================================
// Constants
// ============================================================================

/// Maximum class name length
pub const MAX_CLASS_NAME: usize = 64;

// ============================================================================
// Class Styles
// ============================================================================

bitflags::bitflags! {
    /// Class styles (CS_*)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ClassStyle: u32 {
        /// Redraw if width changes
        const HREDRAW = 0x0002;
        /// Redraw if height changes
        const VREDRAW = 0x0001;
        /// Send double-click messages
        const DBLCLKS = 0x0008;
        /// Own device context
        const OWNDC = 0x0020;
        /// Class device context
        const CLASSDC = 0x0040;
        /// Parent device context
        const PARENTDC = 0x0080;
        /// No close button
        const NOCLOSE = 0x0200;
        /// Save bits under window
        const SAVEBITS = 0x0800;
        /// Byte-align client area
        const BYTEALIGNCLIENT = 0x1000;
        /// Byte-align window
        const BYTEALIGNWINDOW = 0x2000;
        /// Global class
        const GLOBALCLASS = 0x4000;
        /// Drop shadow
        const DROPSHADOW = 0x00020000;
    }
}

// ============================================================================
// Window Class Structure
// ============================================================================

/// Registered window class
#[derive(Debug, Clone)]
pub struct WindowClass {
    /// Class style
    pub style: ClassStyle,

    /// Class name
    pub name: [u8; MAX_CLASS_NAME],

    /// Name length
    pub name_len: usize,

    /// Background brush handle
    pub background: u32,

    /// Cursor handle
    pub cursor: u32,

    /// Icon handle
    pub icon: u32,

    /// Small icon handle
    pub icon_sm: u32,

    /// Menu name/ID
    pub menu: u32,

    /// Extra class bytes
    pub class_extra: i32,

    /// Extra window bytes
    pub window_extra: i32,

    /// Is system class
    pub system: bool,

    /// Atom (unique class ID)
    pub atom: u16,

    /// Valid flag
    pub valid: bool,
}

impl Default for WindowClass {
    fn default() -> Self {
        Self {
            style: ClassStyle::empty(),
            name: [0; MAX_CLASS_NAME],
            name_len: 0,
            background: 0,
            cursor: 0,
            icon: 0,
            icon_sm: 0,
            menu: 0,
            class_extra: 0,
            window_extra: 0,
            system: false,
            atom: 0,
            valid: false,
        }
    }
}

impl WindowClass {
    /// Get class name as string
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

// ============================================================================
// Class Table
// ============================================================================

struct ClassEntry {
    class: Option<WindowClass>,
}

impl Default for ClassEntry {
    fn default() -> Self {
        Self { class: None }
    }
}

static CLASS_TABLE: SpinLock<ClassTable> = SpinLock::new(ClassTable::new());

struct ClassTable {
    entries: [ClassEntry; MAX_CLASSES],
    next_atom: u16,
}

impl ClassTable {
    const fn new() -> Self {
        const EMPTY: ClassEntry = ClassEntry { class: None };
        Self {
            entries: [EMPTY; MAX_CLASSES],
            next_atom: 0xC000, // User atoms start at 0xC000
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize class manager
pub fn init() {
    crate::serial_println!("[USER/Class] Class manager initialized");
}

// ============================================================================
// Class Operations
// ============================================================================

/// Allocate a class slot
fn allocate_class_slot() -> Option<usize> {
    let table = CLASS_TABLE.lock();

    for i in 0..MAX_CLASSES {
        if table.entries[i].class.is_none() {
            return Some(i);
        }
    }

    None
}

/// Register a window class
pub fn register_class(
    name: &str,
    style: ClassStyle,
    background: u32,
    cursor: u32,
    icon: u32,
) -> u16 {
    // Check if class already exists
    if find_class(name).is_some() {
        return 0;
    }

    let slot = match allocate_class_slot() {
        Some(s) => s,
        None => return 0,
    };

    let mut class = WindowClass::default();
    class.style = style;
    class.background = background;
    class.cursor = cursor;
    class.icon = icon;
    class.system = false;
    class.valid = true;

    // Copy name
    class.name_len = name.len().min(MAX_CLASS_NAME - 1);
    for (i, &b) in name.as_bytes().iter().take(class.name_len).enumerate() {
        class.name[i] = b;
    }

    let atom = {
        let mut table = CLASS_TABLE.lock();
        let atom = table.next_atom;
        table.next_atom += 1;
        class.atom = atom;
        table.entries[slot].class = Some(class);
        atom
    };

    super::inc_class_count();

    atom
}

/// Register a system window class
pub fn register_system_class(name: &str, style: u32) -> u16 {
    let slot = match allocate_class_slot() {
        Some(s) => s,
        None => return 0,
    };

    let mut class = WindowClass::default();
    class.style = ClassStyle::from_bits_truncate(style);
    class.system = true;
    class.valid = true;

    // Copy name
    class.name_len = name.len().min(MAX_CLASS_NAME - 1);
    for (i, &b) in name.as_bytes().iter().take(class.name_len).enumerate() {
        class.name[i] = b;
    }

    let atom = {
        let mut table = CLASS_TABLE.lock();
        let atom = table.next_atom;
        table.next_atom += 1;
        class.atom = atom;
        table.entries[slot].class = Some(class);
        atom
    };

    super::inc_class_count();

    atom
}

/// Unregister a window class
pub fn unregister_class(name: &str) -> bool {
    let mut table = CLASS_TABLE.lock();

    for entry in table.entries.iter_mut() {
        if let Some(ref class) = entry.class {
            if class.name_str() == name && !class.system {
                entry.class = None;
                super::dec_class_count();
                return true;
            }
        }
    }

    false
}

/// Find a class by name
pub fn find_class(name: &str) -> Option<WindowClass> {
    let table = CLASS_TABLE.lock();

    for entry in table.entries.iter() {
        if let Some(ref class) = entry.class {
            if class.name_str() == name {
                return Some(class.clone());
            }
        }
    }

    None
}

/// Find a class by atom
pub fn find_class_by_atom(atom: u16) -> Option<WindowClass> {
    let table = CLASS_TABLE.lock();

    for entry in table.entries.iter() {
        if let Some(ref class) = entry.class {
            if class.atom == atom {
                return Some(class.clone());
            }
        }
    }

    None
}

/// Get class info
pub fn get_class_info(name: &str) -> Option<WindowClass> {
    find_class(name)
}
