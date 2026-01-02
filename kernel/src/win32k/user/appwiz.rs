//! Add/Remove Programs Control Panel
//!
//! Kernel-mode application management following Windows NT patterns.
//! Provides installed programs list, uninstall, Windows components, and defaults.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `shell/cpls/appwiz/` - Add/Remove Programs control panel

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};

// ============================================================================
// Constants
// ============================================================================

/// Maximum installed programs
const MAX_PROGRAMS: usize = 256;

/// Maximum Windows components
const MAX_COMPONENTS: usize = 64;

/// Maximum program name length
const MAX_NAME: usize = 256;

/// Maximum publisher length
const MAX_PUBLISHER: usize = 128;

/// Maximum version length
const MAX_VERSION: usize = 64;

/// Maximum install location length
const MAX_LOCATION: usize = 260;

/// Maximum uninstall command length
const MAX_UNINSTALL: usize = 512;

/// Program flags
pub mod program_flags {
    /// Can be uninstalled
    pub const CAN_UNINSTALL: u32 = 0x0001;
    /// Can be modified/changed
    pub const CAN_MODIFY: u32 = 0x0002;
    /// Can be repaired
    pub const CAN_REPAIR: u32 = 0x0004;
    /// Is Windows update
    pub const IS_UPDATE: u32 = 0x0008;
    /// Is system component
    pub const IS_SYSTEM: u32 = 0x0010;
    /// Is hidden
    pub const IS_HIDDEN: u32 = 0x0020;
    /// No modify/remove
    pub const NO_MODIFY: u32 = 0x0040;
    /// No remove
    pub const NO_REMOVE: u32 = 0x0080;
}

/// Component states
pub mod component_state {
    /// Not installed
    pub const NOT_INSTALLED: u32 = 0;
    /// Partially installed
    pub const PARTIAL: u32 = 1;
    /// Fully installed
    pub const INSTALLED: u32 = 2;
}

/// View modes
pub mod view_mode {
    /// Currently installed programs
    pub const INSTALLED: u32 = 0;
    /// Add new programs
    pub const ADD_NEW: u32 = 1;
    /// Add/Remove Windows Components
    pub const COMPONENTS: u32 = 2;
    /// Set program access and defaults
    pub const DEFAULTS: u32 = 3;
}

// ============================================================================
// Types
// ============================================================================

/// Installed program information
#[derive(Clone, Copy)]
pub struct ProgramInfo {
    /// Program name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: u16,
    /// Publisher
    pub publisher: [u8; MAX_PUBLISHER],
    /// Publisher length
    pub publisher_len: u8,
    /// Version
    pub version: [u8; MAX_VERSION],
    /// Version length
    pub version_len: u8,
    /// Install location
    pub location: [u8; MAX_LOCATION],
    /// Location length
    pub location_len: u16,
    /// Uninstall command
    pub uninstall_cmd: [u8; MAX_UNINSTALL],
    /// Uninstall command length
    pub uninstall_len: u16,
    /// Install date (YYYYMMDD)
    pub install_date: u32,
    /// Estimated size in KB
    pub size_kb: u32,
    /// Frequency of use (0-3)
    pub frequency: u8,
    /// Last used date (YYYYMMDD)
    pub last_used: u32,
    /// Flags (program_flags)
    pub flags: u32,
    /// Support URL
    pub support_url: [u8; MAX_LOCATION],
    /// Support URL length
    pub support_url_len: u16,
}

impl ProgramInfo {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            publisher: [0; MAX_PUBLISHER],
            publisher_len: 0,
            version: [0; MAX_VERSION],
            version_len: 0,
            location: [0; MAX_LOCATION],
            location_len: 0,
            uninstall_cmd: [0; MAX_UNINSTALL],
            uninstall_len: 0,
            install_date: 0,
            size_kb: 0,
            frequency: 0,
            last_used: 0,
            flags: program_flags::CAN_UNINSTALL,
            support_url: [0; MAX_LOCATION],
            support_url_len: 0,
        }
    }
}

/// Windows component information
#[derive(Clone, Copy)]
pub struct ComponentInfo {
    /// Component name
    pub name: [u8; MAX_NAME],
    /// Name length
    pub name_len: u16,
    /// Description
    pub description: [u8; MAX_NAME],
    /// Description length
    pub desc_len: u16,
    /// Size in KB
    pub size_kb: u32,
    /// State (component_state)
    pub state: u32,
    /// Is required (cannot be removed)
    pub required: bool,
    /// Has subcomponents
    pub has_children: bool,
    /// Parent component index (-1 for root)
    pub parent: i16,
}

impl ComponentInfo {
    pub const fn new() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            description: [0; MAX_NAME],
            desc_len: 0,
            size_kb: 0,
            state: component_state::NOT_INSTALLED,
            required: false,
            has_children: false,
            parent: -1,
        }
    }
}

/// Program defaults category
#[derive(Clone, Copy)]
pub struct DefaultsCategory {
    /// Category name (e.g., "Web browser")
    pub name: [u8; 64],
    /// Name length
    pub name_len: u8,
    /// Current default program name
    pub current: [u8; MAX_NAME],
    /// Current length
    pub current_len: u16,
    /// Number of available programs
    pub count: u8,
}

impl DefaultsCategory {
    pub const fn new() -> Self {
        Self {
            name: [0; 64],
            name_len: 0,
            current: [0; MAX_NAME],
            current_len: 0,
            count: 0,
        }
    }
}

/// Add/Remove Programs dialog state
struct AppWizDialog {
    /// Parent window
    parent: HWND,
    /// Current view mode
    view_mode: u32,
    /// Selected program index
    selected: i32,
    /// Sort by (0=name, 1=size, 2=frequency, 3=date)
    sort_by: u32,
    /// Show updates
    show_updates: bool,
}

impl AppWizDialog {
    const fn new() -> Self {
        Self {
            parent: UserHandle::NULL,
            view_mode: view_mode::INSTALLED,
            selected: -1,
            sort_by: 0,
            show_updates: false,
        }
    }
}

// ============================================================================
// Static State
// ============================================================================

/// Module initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Installed programs
static PROGRAMS: SpinLock<[ProgramInfo; MAX_PROGRAMS]> =
    SpinLock::new([const { ProgramInfo::new() }; MAX_PROGRAMS]);

/// Program count
static PROGRAM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Windows components
static COMPONENTS: SpinLock<[ComponentInfo; MAX_COMPONENTS]> =
    SpinLock::new([const { ComponentInfo::new() }; MAX_COMPONENTS]);

/// Component count
static COMPONENT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Dialog state
static DIALOG: SpinLock<AppWizDialog> = SpinLock::new(AppWizDialog::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Add/Remove Programs
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Initialize sample installed programs
    init_sample_programs();

    // Initialize Windows components
    init_windows_components();

    crate::serial_println!("[APPWIZ] Add/Remove Programs initialized");
}

/// Initialize sample installed programs
fn init_sample_programs() {
    let mut programs = PROGRAMS.lock();
    let mut count = 0;

    let samples: &[(&[u8], &[u8], &[u8], u32)] = &[
        (b"Microsoft Office 2003", b"Microsoft Corporation", b"11.0", 500000),
        (b"Windows Media Player 10", b"Microsoft Corporation", b"10.0", 25000),
        (b"Internet Explorer 6", b"Microsoft Corporation", b"6.0.2900", 10000),
        (b".NET Framework 2.0", b"Microsoft Corporation", b"2.0.50727", 180000),
        (b"Visual C++ 2005 Redistributable", b"Microsoft Corporation", b"8.0", 5000),
        (b"DirectX 9.0c", b"Microsoft Corporation", b"9.0c", 95000),
        (b"Adobe Acrobat Reader", b"Adobe Systems", b"7.0", 45000),
        (b"Java Runtime Environment", b"Sun Microsystems", b"1.6.0", 120000),
        (b"WinZip", b"WinZip Computing", b"10.0", 8000),
        (b"Windows Installer 3.1", b"Microsoft Corporation", b"3.1", 2500),
    ];

    for (name, publisher, version, size) in samples.iter() {
        if count >= MAX_PROGRAMS {
            break;
        }

        let prog = &mut programs[count];

        let nlen = name.len().min(MAX_NAME);
        prog.name[..nlen].copy_from_slice(&name[..nlen]);
        prog.name_len = nlen as u16;

        let plen = publisher.len().min(MAX_PUBLISHER);
        prog.publisher[..plen].copy_from_slice(&publisher[..plen]);
        prog.publisher_len = plen as u8;

        let vlen = version.len().min(MAX_VERSION);
        prog.version[..vlen].copy_from_slice(&version[..vlen]);
        prog.version_len = vlen as u8;

        prog.size_kb = *size;
        prog.install_date = 20030101; // Sample date
        prog.flags = program_flags::CAN_UNINSTALL | program_flags::CAN_MODIFY;

        count += 1;
    }

    PROGRAM_COUNT.store(count as u32, Ordering::Release);
}

/// Initialize Windows components
fn init_windows_components() {
    let mut components = COMPONENTS.lock();
    let mut count = 0;

    let win_components: &[(&[u8], &[u8], u32, u32, bool)] = &[
        (b"Accessories and Utilities", b"Includes Windows Accessories and Utilities", 12000, component_state::INSTALLED, false),
        (b"Fax Services", b"Enables sending and receiving faxes", 3500, component_state::NOT_INSTALLED, false),
        (b"Indexing Service", b"Indexes documents for fast searching", 0, component_state::INSTALLED, false),
        (b"Internet Explorer", b"Web browser", 10000, component_state::INSTALLED, true),
        (b"Internet Information Services (IIS)", b"Web and FTP services", 15000, component_state::NOT_INSTALLED, false),
        (b"Management and Monitoring Tools", b"Network monitoring and management", 2000, component_state::NOT_INSTALLED, false),
        (b"Message Queuing", b"Message queuing services", 5000, component_state::NOT_INSTALLED, false),
        (b"Networking Services", b"DNS, DHCP, and other network services", 1500, component_state::PARTIAL, false),
        (b"Other Network File and Print Services", b"Print services for Unix", 0, component_state::NOT_INSTALLED, false),
        (b"Remote Installation Services", b"Remote OS installation", 2000, component_state::NOT_INSTALLED, false),
        (b"Remote Storage", b"Automatic file migration", 3500, component_state::NOT_INSTALLED, false),
        (b"Terminal Server", b"Remote desktop services", 8000, component_state::NOT_INSTALLED, false),
        (b"Terminal Server Licensing", b"Terminal Server license management", 500, component_state::NOT_INSTALLED, false),
        (b"Update Root Certificates", b"Automatic root certificate updates", 100, component_state::INSTALLED, false),
        (b"Windows Media Services", b"Streaming media services", 12000, component_state::NOT_INSTALLED, false),
    ];

    for (name, desc, size, state, required) in win_components.iter() {
        if count >= MAX_COMPONENTS {
            break;
        }

        let comp = &mut components[count];

        let nlen = name.len().min(MAX_NAME);
        comp.name[..nlen].copy_from_slice(&name[..nlen]);
        comp.name_len = nlen as u16;

        let dlen = desc.len().min(MAX_NAME);
        comp.description[..dlen].copy_from_slice(&desc[..dlen]);
        comp.desc_len = dlen as u16;

        comp.size_kb = *size;
        comp.state = *state;
        comp.required = *required;
        comp.parent = -1;

        count += 1;
    }

    COMPONENT_COUNT.store(count as u32, Ordering::Release);
}

// ============================================================================
// Program Management
// ============================================================================

/// Get number of installed programs
pub fn get_program_count() -> u32 {
    PROGRAM_COUNT.load(Ordering::Acquire)
}

/// Get program info by index
pub fn get_program(index: usize, info: &mut ProgramInfo) -> bool {
    let programs = PROGRAMS.lock();
    let count = PROGRAM_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    *info = programs[index];
    true
}

/// Find program by name
pub fn find_program(name: &[u8]) -> Option<usize> {
    let programs = PROGRAMS.lock();
    let count = PROGRAM_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = programs[i].name_len as usize;
        if &programs[i].name[..len] == name {
            return Some(i);
        }
    }
    None
}

/// Register a new program
pub fn register_program(info: &ProgramInfo) -> bool {
    let mut programs = PROGRAMS.lock();
    let count = PROGRAM_COUNT.load(Ordering::Acquire) as usize;

    if count >= MAX_PROGRAMS {
        return false;
    }

    programs[count] = *info;
    PROGRAM_COUNT.store((count + 1) as u32, Ordering::Release);

    true
}

/// Unregister a program
pub fn unregister_program(name: &[u8]) -> bool {
    let mut programs = PROGRAMS.lock();
    let count = PROGRAM_COUNT.load(Ordering::Acquire) as usize;

    let mut found_index = None;
    for i in 0..count {
        let len = programs[i].name_len as usize;
        if &programs[i].name[..len] == name {
            found_index = Some(i);
            break;
        }
    }

    if let Some(index) = found_index {
        for i in index..(count - 1) {
            programs[i] = programs[i + 1];
        }
        programs[count - 1] = ProgramInfo::new();
        PROGRAM_COUNT.store((count - 1) as u32, Ordering::Release);
        return true;
    }

    false
}

/// Get total size of installed programs
pub fn get_total_size() -> u64 {
    let programs = PROGRAMS.lock();
    let count = PROGRAM_COUNT.load(Ordering::Acquire) as usize;

    let mut total: u64 = 0;
    for i in 0..count {
        total += programs[i].size_kb as u64;
    }
    total
}

// ============================================================================
// Windows Components
// ============================================================================

/// Get number of Windows components
pub fn get_component_count() -> u32 {
    COMPONENT_COUNT.load(Ordering::Acquire)
}

/// Get component info by index
pub fn get_component(index: usize, info: &mut ComponentInfo) -> bool {
    let components = COMPONENTS.lock();
    let count = COMPONENT_COUNT.load(Ordering::Acquire) as usize;

    if index >= count {
        return false;
    }

    *info = components[index];
    true
}

/// Set component state
pub fn set_component_state(name: &[u8], state: u32) -> bool {
    let mut components = COMPONENTS.lock();
    let count = COMPONENT_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = components[i].name_len as usize;
        if &components[i].name[..len] == name {
            if components[i].required && state == component_state::NOT_INSTALLED {
                return false; // Cannot remove required components
            }
            components[i].state = state;
            return true;
        }
    }
    false
}

/// Get space required for pending component changes
pub fn get_space_required() -> i64 {
    let components = COMPONENTS.lock();
    let count = COMPONENT_COUNT.load(Ordering::Acquire) as usize;

    let mut delta: i64 = 0;
    for i in 0..count {
        // Would compare current vs pending state
        let _ = components[i].size_kb;
    }
    delta
}

// ============================================================================
// Uninstall Operations
// ============================================================================

/// Start program uninstall
pub fn start_uninstall(name: &[u8]) -> bool {
    let programs = PROGRAMS.lock();
    let count = PROGRAM_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = programs[i].name_len as usize;
        if &programs[i].name[..len] == name {
            if programs[i].flags & program_flags::CAN_UNINSTALL == 0 {
                return false;
            }
            // Would launch uninstall command
            // let cmd_len = programs[i].uninstall_len as usize;
            // let cmd = &programs[i].uninstall_cmd[..cmd_len];
            return true;
        }
    }
    false
}

/// Start program modify
pub fn start_modify(name: &[u8]) -> bool {
    let programs = PROGRAMS.lock();
    let count = PROGRAM_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = programs[i].name_len as usize;
        if &programs[i].name[..len] == name {
            if programs[i].flags & program_flags::CAN_MODIFY == 0 {
                return false;
            }
            // Would launch modify command
            return true;
        }
    }
    false
}

/// Start program repair
pub fn start_repair(name: &[u8]) -> bool {
    let programs = PROGRAMS.lock();
    let count = PROGRAM_COUNT.load(Ordering::Acquire) as usize;

    for i in 0..count {
        let len = programs[i].name_len as usize;
        if &programs[i].name[..len] == name {
            if programs[i].flags & program_flags::CAN_REPAIR == 0 {
                return false;
            }
            // Would launch repair command
            return true;
        }
    }
    false
}

// ============================================================================
// Dialog API
// ============================================================================

/// Show Add/Remove Programs
pub fn show_add_remove_programs(parent: HWND) -> bool {
    let mut dialog = DIALOG.lock();

    dialog.parent = parent;
    dialog.view_mode = view_mode::INSTALLED;
    dialog.selected = -1;
    dialog.sort_by = 0;
    dialog.show_updates = false;

    // Would show control panel with:
    // - Left sidebar: Change/Remove, Add New, Windows Components, Defaults
    // - Program list with size, frequency, date
    // - Change/Remove/Repair buttons

    true
}

/// Show Windows Components wizard
pub fn show_components_wizard(parent: HWND) -> bool {
    let _ = parent;
    // Would show Windows Components Wizard
    true
}

/// Show program defaults dialog
pub fn show_program_defaults(parent: HWND) -> bool {
    let _ = parent;
    // Would show Set Program Access and Defaults
    true
}

/// Refresh installed programs list
pub fn refresh_programs() {
    // Would re-enumerate from registry:
    // HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall
    // HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall
}
