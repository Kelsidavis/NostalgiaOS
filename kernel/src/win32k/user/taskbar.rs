//! Taskbar Integration
//!
//! Provides taskbar button and jump list support following the
//! Windows shell32 ITaskbarList patterns.
//!
//! # References
//!
//! - Windows Server 2003 shell32 taskbar APIs
//! - ITaskbarList, ITaskbarList2, ITaskbarList3 interfaces

use core::sync::atomic::{AtomicBool, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle};

// ============================================================================
// Constants
// ============================================================================

/// Maximum jump list items
pub const MAX_JUMP_LIST_ITEMS: usize = 16;

/// Maximum recent documents
pub const MAX_RECENT_DOCS: usize = 16;

/// Taskbar progress state flags (TBPF_*)
pub mod tbpf_flags {
    /// No progress
    pub const NOPROGRESS: u32 = 0x00000000;
    /// Indeterminate (marquee)
    pub const INDETERMINATE: u32 = 0x00000001;
    /// Normal progress
    pub const NORMAL: u32 = 0x00000002;
    /// Error state (red)
    pub const ERROR: u32 = 0x00000004;
    /// Paused state (yellow)
    pub const PAUSED: u32 = 0x00000008;
}

/// Thumbnail button flags (THBF_*)
pub mod thbf_flags {
    /// Button enabled
    pub const ENABLED: u32 = 0x00000000;
    /// Button disabled
    pub const DISABLED: u32 = 0x00000001;
    /// Dismiss on click
    pub const DISMISSONCLICK: u32 = 0x00000002;
    /// No background
    pub const NOBACKGROUND: u32 = 0x00000004;
    /// Hidden
    pub const HIDDEN: u32 = 0x00000008;
    /// Non-interactive
    pub const NONINTERACTIVE: u32 = 0x00000010;
}

/// Taskbar button state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TaskbarButtonState {
    #[default]
    Normal = 0,
    Flashing = 1,
    Active = 2,
    Highlighted = 3,
}

// ============================================================================
// Structures
// ============================================================================

/// Taskbar button entry
#[derive(Debug, Clone, Copy)]
pub struct TaskbarButton {
    /// Entry is valid
    pub valid: bool,
    /// Window handle
    pub hwnd: HWND,
    /// Button visible on taskbar
    pub visible: bool,
    /// Button state
    pub state: TaskbarButtonState,
    /// Progress state
    pub progress_state: u32,
    /// Progress value (0-10000)
    pub progress_value: u32,
    /// Has overlay icon
    pub has_overlay: bool,
    /// Overlay icon ID
    pub overlay_icon: u32,
    /// Flash count remaining
    pub flash_count: u8,
}

impl TaskbarButton {
    const fn new() -> Self {
        Self {
            valid: false,
            hwnd: UserHandle::NULL,
            visible: true,
            state: TaskbarButtonState::Normal,
            progress_state: tbpf_flags::NOPROGRESS,
            progress_value: 0,
            has_overlay: false,
            overlay_icon: 0,
            flash_count: 0,
        }
    }
}

/// Thumbnail toolbar button
#[derive(Debug, Clone, Copy)]
pub struct ThumbButton {
    /// Button is valid
    pub valid: bool,
    /// Button ID
    pub id: u32,
    /// Icon ID
    pub icon: u32,
    /// Tooltip length
    pub tooltip_len: u8,
    /// Tooltip text
    pub tooltip: [u8; 64],
    /// Flags
    pub flags: u32,
}

impl ThumbButton {
    const fn new() -> Self {
        Self {
            valid: false,
            id: 0,
            icon: 0,
            tooltip_len: 0,
            tooltip: [0; 64],
            flags: thbf_flags::ENABLED,
        }
    }
}

/// Jump list item
#[derive(Debug, Clone, Copy)]
pub struct JumpListItem {
    /// Item is valid
    pub valid: bool,
    /// Item type (0=task, 1=document, 2=separator)
    pub item_type: u8,
    /// Title length
    pub title_len: u8,
    /// Title
    pub title: [u8; 64],
    /// Path length
    pub path_len: u8,
    /// Path/command
    pub path: [u8; 128],
    /// Arguments length
    pub args_len: u8,
    /// Arguments
    pub args: [u8; 64],
    /// Icon index
    pub icon_index: i32,
}

impl JumpListItem {
    const fn new() -> Self {
        Self {
            valid: false,
            item_type: 0,
            title_len: 0,
            title: [0; 64],
            path_len: 0,
            path: [0; 128],
            args_len: 0,
            args: [0; 64],
            icon_index: 0,
        }
    }
}

/// Recent document entry
#[derive(Debug, Clone, Copy)]
pub struct RecentDoc {
    /// Entry is valid
    pub valid: bool,
    /// Path length
    pub path_len: u8,
    /// Document path
    pub path: [u8; 260],
    /// Last access time
    pub last_access: u64,
}

impl RecentDoc {
    const fn new() -> Self {
        Self {
            valid: false,
            path_len: 0,
            path: [0; 260],
            last_access: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

static TASKBAR_INITIALIZED: AtomicBool = AtomicBool::new(false);
static TASKBAR_LOCK: SpinLock<()> = SpinLock::new(());

const MAX_BUTTONS: usize = 64;
static TASKBAR_BUTTONS: SpinLock<[TaskbarButton; MAX_BUTTONS]> =
    SpinLock::new([const { TaskbarButton::new() }; MAX_BUTTONS]);

// Thumbnail toolbar (per window, max 7 buttons)
const MAX_THUMB_BUTTONS: usize = 7;
static THUMB_BUTTONS: SpinLock<[ThumbButton; MAX_THUMB_BUTTONS]> =
    SpinLock::new([const { ThumbButton::new() }; MAX_THUMB_BUTTONS]);

// Jump list
static JUMP_LIST: SpinLock<[JumpListItem; MAX_JUMP_LIST_ITEMS]> =
    SpinLock::new([const { JumpListItem::new() }; MAX_JUMP_LIST_ITEMS]);

// Recent documents
static RECENT_DOCS: SpinLock<[RecentDoc; MAX_RECENT_DOCS]> =
    SpinLock::new([const { RecentDoc::new() }; MAX_RECENT_DOCS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize taskbar subsystem
pub fn init() {
    let _guard = TASKBAR_LOCK.lock();

    if TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[TASKBAR] Initializing taskbar...");

    TASKBAR_INITIALIZED.store(true, Ordering::Release);
    crate::serial_println!("[TASKBAR] Taskbar initialized");
}

// ============================================================================
// Taskbar Button API (ITaskbarList)
// ============================================================================

/// Add a window to the taskbar
pub fn add_tab(hwnd: HWND) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut buttons = TASKBAR_BUTTONS.lock();

    // Check if already exists
    for button in buttons.iter() {
        if button.valid && button.hwnd == hwnd {
            return true; // Already added
        }
    }

    // Find free slot
    for button in buttons.iter_mut() {
        if !button.valid {
            button.valid = true;
            button.hwnd = hwnd;
            button.visible = true;
            button.state = TaskbarButtonState::Normal;
            button.progress_state = tbpf_flags::NOPROGRESS;
            button.progress_value = 0;
            button.has_overlay = false;
            button.flash_count = 0;
            return true;
        }
    }

    false
}

/// Remove a window from the taskbar
pub fn delete_tab(hwnd: HWND) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut buttons = TASKBAR_BUTTONS.lock();

    for button in buttons.iter_mut() {
        if button.valid && button.hwnd == hwnd {
            button.valid = false;
            button.hwnd = UserHandle::NULL;
            return true;
        }
    }

    false
}

/// Activate a taskbar tab
pub fn activate_tab(hwnd: HWND) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut buttons = TASKBAR_BUTTONS.lock();

    // Deactivate all, activate target
    for button in buttons.iter_mut() {
        if button.valid {
            if button.hwnd == hwnd {
                button.state = TaskbarButtonState::Active;
            } else if button.state == TaskbarButtonState::Active {
                button.state = TaskbarButtonState::Normal;
            }
        }
    }

    true
}

/// Set taskbar tab active/inactive
pub fn set_active_alt(hwnd: HWND) -> bool {
    activate_tab(hwnd)
}

// ============================================================================
// Taskbar Progress API (ITaskbarList3)
// ============================================================================

/// Set progress state
pub fn set_progress_state(hwnd: HWND, state: u32) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut buttons = TASKBAR_BUTTONS.lock();

    for button in buttons.iter_mut() {
        if button.valid && button.hwnd == hwnd {
            button.progress_state = state;
            return true;
        }
    }

    false
}

/// Set progress value (completed/total)
pub fn set_progress_value(hwnd: HWND, completed: u64, total: u64) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut buttons = TASKBAR_BUTTONS.lock();

    for button in buttons.iter_mut() {
        if button.valid && button.hwnd == hwnd {
            if total > 0 {
                button.progress_value = ((completed * 10000) / total).min(10000) as u32;
            } else {
                button.progress_value = 0;
            }
            return true;
        }
    }

    false
}

/// Set overlay icon
pub fn set_overlay_icon(hwnd: HWND, icon: u32, _description: &[u8]) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut buttons = TASKBAR_BUTTONS.lock();

    for button in buttons.iter_mut() {
        if button.valid && button.hwnd == hwnd {
            if icon != 0 {
                button.has_overlay = true;
                button.overlay_icon = icon;
            } else {
                button.has_overlay = false;
                button.overlay_icon = 0;
            }
            return true;
        }
    }

    false
}

// ============================================================================
// Thumbnail Toolbar API
// ============================================================================

/// Add thumbnail toolbar buttons
pub fn thumb_bar_add_buttons(hwnd: HWND, buttons: &[ThumbButton]) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let _ = hwnd; // Would associate with window

    let mut thumb = THUMB_BUTTONS.lock();
    let count = buttons.len().min(MAX_THUMB_BUTTONS);

    for (i, btn) in buttons.iter().take(count).enumerate() {
        thumb[i] = *btn;
        thumb[i].valid = true;
    }

    true
}

/// Update thumbnail toolbar button
pub fn thumb_bar_update_button(hwnd: HWND, button_id: u32, flags: u32) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let _ = hwnd;

    let mut thumb = THUMB_BUTTONS.lock();

    for btn in thumb.iter_mut() {
        if btn.valid && btn.id == button_id {
            btn.flags = flags;
            return true;
        }
    }

    false
}

/// Set thumbnail clip region
pub fn set_thumbnail_clip(hwnd: HWND, clip: Option<&super::super::Rect>) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let _ = (hwnd, clip);
    // Would set clip region for thumbnail preview
    true
}

/// Set thumbnail tooltip
pub fn set_thumbnail_tooltip(hwnd: HWND, tooltip: &[u8]) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let _ = (hwnd, tooltip);
    // Would set tooltip for thumbnail
    true
}

// ============================================================================
// Jump List API
// ============================================================================

/// Begin jump list update
pub fn begin_list() -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    // Clear current list
    let mut list = JUMP_LIST.lock();
    for item in list.iter_mut() {
        item.valid = false;
    }

    true
}

/// Add task to jump list
pub fn add_task(title: &[u8], path: &[u8], args: &[u8], icon_index: i32) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut list = JUMP_LIST.lock();

    for item in list.iter_mut() {
        if !item.valid {
            item.valid = true;
            item.item_type = 0; // Task

            item.title_len = title.len().min(64) as u8;
            item.title[..item.title_len as usize].copy_from_slice(&title[..item.title_len as usize]);

            item.path_len = path.len().min(128) as u8;
            item.path[..item.path_len as usize].copy_from_slice(&path[..item.path_len as usize]);

            item.args_len = args.len().min(64) as u8;
            item.args[..item.args_len as usize].copy_from_slice(&args[..item.args_len as usize]);

            item.icon_index = icon_index;
            return true;
        }
    }

    false
}

/// Add separator to jump list
pub fn add_separator() -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut list = JUMP_LIST.lock();

    for item in list.iter_mut() {
        if !item.valid {
            item.valid = true;
            item.item_type = 2; // Separator
            return true;
        }
    }

    false
}

/// Commit jump list changes
pub fn commit_list() -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    // Would apply changes to shell
    true
}

/// Get jump list items
pub fn get_jump_list() -> ([JumpListItem; MAX_JUMP_LIST_ITEMS], usize) {
    let list = JUMP_LIST.lock();
    let count = list.iter().filter(|i| i.valid).count();
    (*list, count)
}

// ============================================================================
// Recent Documents API
// ============================================================================

/// Add document to recent list
pub fn add_to_recent(path: &[u8]) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut docs = RECENT_DOCS.lock();
    let current_time = get_current_time();

    // Check if already exists
    for doc in docs.iter_mut() {
        if doc.valid && doc.path[..doc.path_len as usize] == *path {
            doc.last_access = current_time;
            return true;
        }
    }

    // Find oldest or empty slot
    let mut target = 0;
    let mut oldest_time = u64::MAX;

    for (i, doc) in docs.iter().enumerate() {
        if !doc.valid {
            target = i;
            break;
        }
        if doc.last_access < oldest_time {
            oldest_time = doc.last_access;
            target = i;
        }
    }

    // Add new entry
    let doc = &mut docs[target];
    doc.valid = true;
    doc.path_len = path.len().min(260) as u8;
    doc.path[..doc.path_len as usize].copy_from_slice(&path[..doc.path_len as usize]);
    doc.last_access = current_time;

    true
}

/// Clear recent documents
pub fn clear_recent() {
    let mut docs = RECENT_DOCS.lock();
    for doc in docs.iter_mut() {
        doc.valid = false;
    }
}

/// Get recent documents
pub fn get_recent_docs() -> ([RecentDoc; MAX_RECENT_DOCS], usize) {
    let docs = RECENT_DOCS.lock();
    let count = docs.iter().filter(|d| d.valid).count();
    (*docs, count)
}

// ============================================================================
// Flash Window API
// ============================================================================

/// Flash taskbar button
pub fn flash_window(hwnd: HWND, count: u8) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut buttons = TASKBAR_BUTTONS.lock();

    for button in buttons.iter_mut() {
        if button.valid && button.hwnd == hwnd {
            button.state = TaskbarButtonState::Flashing;
            button.flash_count = count;
            return true;
        }
    }

    false
}

/// Stop flashing taskbar button
pub fn stop_flash(hwnd: HWND) -> bool {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }

    let mut buttons = TASKBAR_BUTTONS.lock();

    for button in buttons.iter_mut() {
        if button.valid && button.hwnd == hwnd && button.state == TaskbarButtonState::Flashing {
            button.state = TaskbarButtonState::Normal;
            button.flash_count = 0;
            return true;
        }
    }

    false
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get current time
fn get_current_time() -> u64 {
    0
}

/// Get taskbar button info
pub fn get_button_info(hwnd: HWND) -> Option<TaskbarButton> {
    if !TASKBAR_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }

    let buttons = TASKBAR_BUTTONS.lock();

    for button in buttons.iter() {
        if button.valid && button.hwnd == hwnd {
            return Some(*button);
        }
    }

    None
}

/// Get active taskbar buttons
pub fn get_active_buttons() -> ([TaskbarButton; MAX_BUTTONS], usize) {
    let buttons = TASKBAR_BUTTONS.lock();
    let count = buttons.iter().filter(|b| b.valid).count();
    (*buttons, count)
}
