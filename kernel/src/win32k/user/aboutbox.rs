//! About Box Dialog
//!
//! Provides the standard About dialog following the Windows shell32
//! ShellAbout pattern.
//!
//! # References
//!
//! - Windows Server 2003 shell32 about box
//! - ShellAbout API

use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum text length
pub const MAX_TEXT: usize = 256;

/// About box flags
pub mod about_flags {
    /// Show logo image
    pub const SHOW_LOGO: u32 = 0x00000001;
    /// Show system info button
    pub const SHOW_SYSINFO: u32 = 0x00000002;
    /// Show license text
    pub const SHOW_LICENSE: u32 = 0x00000004;
    /// Show credits button
    pub const SHOW_CREDITS: u32 = 0x00000008;
    /// Modal dialog
    pub const MODAL: u32 = 0x00000010;
    /// Center on parent
    pub const CENTER_PARENT: u32 = 0x00000020;
}

// ============================================================================
// Structures
// ============================================================================

/// About box info
#[derive(Clone, Copy)]
pub struct AboutBoxInfo {
    /// Owner window
    pub hwnd_owner: HWND,
    /// Flags
    pub flags: u32,
    /// Application name length
    pub app_name_len: u8,
    /// Application name
    pub app_name: [u8; 64],
    /// Version string length
    pub version_len: u8,
    /// Version string
    pub version: [u8; 32],
    /// Copyright length
    pub copyright_len: u8,
    /// Copyright text
    pub copyright: [u8; 128],
    /// Description length
    pub description_len: u8,
    /// Description text
    pub description: [u8; 256],
    /// License text length
    pub license_len: u16,
    /// License text (first 512 bytes)
    pub license: [u8; 512],
    /// Credits text length
    pub credits_len: u16,
    /// Credits text
    pub credits: [u8; 512],
    /// Logo resource ID
    pub logo_id: u32,
    /// Icon resource ID
    pub icon_id: u32,
}

impl AboutBoxInfo {
    pub const fn new() -> Self {
        Self {
            hwnd_owner: UserHandle::NULL,
            flags: about_flags::SHOW_LOGO | about_flags::CENTER_PARENT,
            app_name_len: 0,
            app_name: [0; 64],
            version_len: 0,
            version: [0; 32],
            copyright_len: 0,
            copyright: [0; 128],
            description_len: 0,
            description: [0; 256],
            license_len: 0,
            license: [0; 512],
            credits_len: 0,
            credits: [0; 512],
            logo_id: 0,
            icon_id: 0,
        }
    }

    /// Set application name
    pub fn set_app_name(&mut self, name: &[u8]) {
        self.app_name_len = name.len().min(64) as u8;
        self.app_name[..self.app_name_len as usize].copy_from_slice(&name[..self.app_name_len as usize]);
    }

    /// Set version string
    pub fn set_version(&mut self, version: &[u8]) {
        self.version_len = version.len().min(32) as u8;
        self.version[..self.version_len as usize].copy_from_slice(&version[..self.version_len as usize]);
    }

    /// Set copyright text
    pub fn set_copyright(&mut self, copyright: &[u8]) {
        self.copyright_len = copyright.len().min(128) as u8;
        self.copyright[..self.copyright_len as usize].copy_from_slice(&copyright[..self.copyright_len as usize]);
    }

    /// Set description
    pub fn set_description(&mut self, desc: &[u8]) {
        self.description_len = desc.len().min(256) as u8;
        self.description[..self.description_len as usize].copy_from_slice(&desc[..self.description_len as usize]);
    }
}

/// About dialog state
#[derive(Clone, Copy)]
pub struct AboutDialogState {
    /// Dialog is active
    pub active: bool,
    /// Dialog handle
    pub hwnd: HWND,
    /// About info
    pub info: AboutBoxInfo,
}

impl AboutDialogState {
    const fn new() -> Self {
        Self {
            active: false,
            hwnd: UserHandle::NULL,
            info: AboutBoxInfo::new(),
        }
    }
}

/// System info for about box
#[derive(Debug, Clone, Copy)]
pub struct SystemInfo {
    /// OS name length
    pub os_name_len: u8,
    /// OS name
    pub os_name: [u8; 64],
    /// OS version length
    pub os_version_len: u8,
    /// OS version
    pub os_version: [u8; 32],
    /// Processor name length
    pub processor_len: u8,
    /// Processor name
    pub processor: [u8; 64],
    /// RAM in MB
    pub ram_mb: u32,
    /// Disk space in MB
    pub disk_mb: u32,
}

impl SystemInfo {
    const fn new() -> Self {
        Self {
            os_name_len: 0,
            os_name: [0; 64],
            os_version_len: 0,
            os_version: [0; 32],
            processor_len: 0,
            processor: [0; 64],
            ram_mb: 0,
            disk_mb: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static ABOUT_INITIALIZED: AtomicBool = AtomicBool::new(false);
static ABOUT_LOCK: SpinLock<()> = SpinLock::new(());

static CURRENT_STATE: SpinLock<AboutDialogState> = SpinLock::new(AboutDialogState::new());
static SYSTEM_INFO: SpinLock<SystemInfo> = SpinLock::new(SystemInfo::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize about box subsystem
pub fn init() {
    let _guard = ABOUT_LOCK.lock();

    if ABOUT_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[ABOUTBOX] Initializing about box...");

    // Initialize system info
    init_system_info();

    ABOUT_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[ABOUTBOX] About box initialized");
}

/// Initialize system info
fn init_system_info() {
    let mut info = SYSTEM_INFO.lock();

    // Set OS name
    let os_name = b"NostalgiaOS";
    let os_name_len = os_name.len();
    info.os_name_len = os_name_len as u8;
    info.os_name[..os_name_len].copy_from_slice(os_name);

    // Set OS version
    let os_version = b"5.2.3790";
    let os_version_len = os_version.len();
    info.os_version_len = os_version_len as u8;
    info.os_version[..os_version_len].copy_from_slice(os_version);

    // Set processor
    let processor = b"x86-64 Compatible";
    let processor_len = processor.len();
    info.processor_len = processor_len as u8;
    info.processor[..processor_len].copy_from_slice(processor);

    // Default RAM and disk (would be detected at runtime)
    info.ram_mb = 512;
    info.disk_mb = 10240;
}

// ============================================================================
// About Box API
// ============================================================================

/// Show shell about dialog
pub fn shell_about(hwnd_owner: HWND, app_name: &[u8], other_stuff: &[u8], icon: u32) -> bool {
    if !ABOUT_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut info = AboutBoxInfo::new();
    info.hwnd_owner = hwnd_owner;
    info.set_app_name(app_name);
    info.set_description(other_stuff);
    info.icon_id = icon;
    info.flags = about_flags::SHOW_LOGO | about_flags::CENTER_PARENT | about_flags::MODAL;

    show_about_box(&info)
}

/// Show about box with full info
pub fn show_about_box(info: &AboutBoxInfo) -> bool {
    if !ABOUT_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut state = CURRENT_STATE.lock();

    if state.active {
        return false;
    }

    state.info = *info;

    // Create dialog
    let hwnd = create_about_dialog(info);

    if hwnd == UserHandle::NULL {
        return false;
    }

    state.active = true;
    state.hwnd = hwnd;

    drop(state);

    // Run dialog
    let result = run_about_dialog(hwnd);

    // Clean up
    let mut state = CURRENT_STATE.lock();
    state.active = false;
    state.hwnd = UserHandle::NULL;

    result
}

/// Close about dialog
pub fn close_about_dialog() {
    let mut state = CURRENT_STATE.lock();

    if state.active {
        if state.hwnd != UserHandle::NULL {
            super::window::destroy_window(state.hwnd);
        }

        state.active = false;
        state.hwnd = UserHandle::NULL;
    }
}

/// Get system info
pub fn get_system_info() -> SystemInfo {
    *SYSTEM_INFO.lock()
}

/// Set system info (for updating RAM/disk at runtime)
pub fn update_system_info(ram_mb: u32, disk_mb: u32) {
    let mut info = SYSTEM_INFO.lock();
    info.ram_mb = ram_mb;
    info.disk_mb = disk_mb;
}

// ============================================================================
// Windows About Box
// ============================================================================

/// Show Windows-style about box
pub fn show_windows_about(hwnd_owner: HWND) -> bool {
    let mut info = AboutBoxInfo::new();
    info.hwnd_owner = hwnd_owner;
    info.set_app_name(b"NostalgiaOS");
    info.set_version(b"Version 5.2 (Build 3790)");
    info.set_copyright(b"Copyright (C) 2024 NostalgiaOS Project");
    info.set_description(b"NostalgiaOS is a recreation of Windows Server 2003 (NT 5.2) targeting x86_64 bare metal.");
    info.flags = about_flags::SHOW_LOGO | about_flags::SHOW_SYSINFO | about_flags::CENTER_PARENT;

    show_about_box(&info)
}

/// Format system info as text
pub fn format_system_info(buffer: &mut [u8]) -> usize {
    let info = SYSTEM_INFO.lock();
    let mut pos = 0;

    // OS name and version
    let os_label = b"Operating System: ";
    if pos + os_label.len() <= buffer.len() {
        buffer[pos..pos + os_label.len()].copy_from_slice(os_label);
        pos += os_label.len();
    }

    let os_name_len = info.os_name_len as usize;
    if pos + os_name_len <= buffer.len() {
        buffer[pos..pos + os_name_len].copy_from_slice(&info.os_name[..os_name_len]);
        pos += os_name_len;
    }

    if pos + 1 <= buffer.len() {
        buffer[pos] = b' ';
        pos += 1;
    }

    let os_ver_len = info.os_version_len as usize;
    if pos + os_ver_len <= buffer.len() {
        buffer[pos..pos + os_ver_len].copy_from_slice(&info.os_version[..os_ver_len]);
        pos += os_ver_len;
    }

    // Newline
    if pos + 1 <= buffer.len() {
        buffer[pos] = b'\n';
        pos += 1;
    }

    // Processor
    let proc_label = b"Processor: ";
    if pos + proc_label.len() <= buffer.len() {
        buffer[pos..pos + proc_label.len()].copy_from_slice(proc_label);
        pos += proc_label.len();
    }

    let proc_len = info.processor_len as usize;
    if pos + proc_len <= buffer.len() {
        buffer[pos..pos + proc_len].copy_from_slice(&info.processor[..proc_len]);
        pos += proc_len;
    }

    // Newline
    if pos + 1 <= buffer.len() {
        buffer[pos] = b'\n';
        pos += 1;
    }

    // RAM
    let ram_label = b"Physical Memory: ";
    if pos + ram_label.len() <= buffer.len() {
        buffer[pos..pos + ram_label.len()].copy_from_slice(ram_label);
        pos += ram_label.len();
    }

    pos += format_number(info.ram_mb as u64, &mut buffer[pos..]);

    let mb_suffix = b" MB";
    if pos + mb_suffix.len() <= buffer.len() {
        buffer[pos..pos + mb_suffix.len()].copy_from_slice(mb_suffix);
        pos += mb_suffix.len();
    }

    pos
}

/// Format number into buffer
fn format_number(mut n: u64, buffer: &mut [u8]) -> usize {
    if n == 0 {
        if !buffer.is_empty() {
            buffer[0] = b'0';
            return 1;
        }
        return 0;
    }

    let mut temp = [0u8; 20];
    let mut len = 0;

    while n > 0 && len < 20 {
        temp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }

    // Reverse
    let copy_len = len.min(buffer.len());
    for i in 0..copy_len {
        buffer[i] = temp[len - 1 - i];
    }

    copy_len
}

// ============================================================================
// Dialog Creation
// ============================================================================

/// Create about dialog window
fn create_about_dialog(_info: &AboutBoxInfo) -> HWND {
    // Would create about dialog window
    UserHandle::NULL
}

/// Run about dialog modal loop
fn run_about_dialog(_hwnd: HWND) -> bool {
    // Would run modal dialog loop
    true
}

// ============================================================================
// Dialog Procedure
// ============================================================================

/// About dialog window procedure
pub fn about_dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    _lparam: isize,
) -> isize {
    match msg {
        super::message::WM_COMMAND => {
            handle_about_command(hwnd, wparam as u32)
        }
        super::message::WM_CLOSE => {
            close_about_dialog();
            0
        }
        _ => 0,
    }
}

/// Handle about dialog commands
fn handle_about_command(hwnd: HWND, command: u32) -> isize {
    let id = command as u16;

    match id {
        1 | 2 => {
            // OK or Cancel button
            let state = CURRENT_STATE.lock();
            if state.active && state.hwnd == hwnd {
                drop(state);
                close_about_dialog();
            }
            0
        }
        100 => {
            // System Info button
            show_system_info_dialog();
            0
        }
        101 => {
            // Credits button
            show_credits_dialog();
            0
        }
        _ => 0,
    }
}

/// Show system info dialog
fn show_system_info_dialog() {
    // Would show system info dialog
}

/// Show credits dialog
fn show_credits_dialog() {
    let state = CURRENT_STATE.lock();

    if !state.active {
        return;
    }

    // Would show scrolling credits dialog
    let _ = state.info.credits_len;
}

// ============================================================================
// Simple API
// ============================================================================

/// Show simple about box
pub fn show_simple_about(
    app_name: &[u8],
    version: &[u8],
    copyright: &[u8],
) -> bool {
    let mut info = AboutBoxInfo::new();
    info.set_app_name(app_name);
    info.set_version(version);
    info.set_copyright(copyright);
    info.flags = about_flags::CENTER_PARENT;

    show_about_box(&info)
}

/// Show about with description
pub fn show_about_with_description(
    app_name: &[u8],
    version: &[u8],
    copyright: &[u8],
    description: &[u8],
) -> bool {
    let mut info = AboutBoxInfo::new();
    info.set_app_name(app_name);
    info.set_version(version);
    info.set_copyright(copyright);
    info.set_description(description);
    info.flags = about_flags::SHOW_LOGO | about_flags::CENTER_PARENT;

    show_about_box(&info)
}
