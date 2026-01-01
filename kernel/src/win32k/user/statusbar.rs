//! StatusBar Control - Windows Common Controls
//!
//! Implements the StatusBar control following the Windows Common Controls architecture.
//! Status bars display status information at the bottom of application windows.
//!
//! # Features
//!
//! - Multiple parts/panes for different information
//! - Size grip for window resizing
//! - Owner-draw support
//! - Simple mode (single text display)
//! - Icon display per part
//!
//! # Window Class
//!
//! The status bar control uses the "msctls_statusbar32" class name.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/commctrl.h` - StatusBar definitions

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Rect};

// ============================================================================
// StatusBar Styles (SBARS_*)
// ============================================================================

/// Display a size grip at the right end
pub const SBARS_SIZEGRIP: u32 = 0x0100;
/// Enable tooltips for parts
pub const SBARS_TOOLTIPS: u32 = 0x0800;

// ============================================================================
// StatusBar Text Styles (SBT_*)
// ============================================================================

/// Owner draws the text
pub const SBT_OWNERDRAW: u32 = 0x1000;
/// No borders around the part
pub const SBT_NOBORDERS: u32 = 0x0100;
/// Part appears raised (popout)
pub const SBT_POPOUT: u32 = 0x0200;
/// Text displays right-to-left
pub const SBT_RTLREADING: u32 = 0x0400;
/// Don't parse tab characters
pub const SBT_NOTABPARSING: u32 = 0x0800;
/// Enable tooltips for this part
pub const SBT_TOOLTIPS: u32 = 0x0800;

// ============================================================================
// StatusBar Messages (SB_*)
// ============================================================================

/// WM_USER base for statusbar messages
const WM_USER: u32 = 0x0400;

/// Set text for a part (ANSI)
pub const SB_SETTEXTA: u32 = WM_USER + 1;
/// Get text from a part (ANSI)
pub const SB_GETTEXTA: u32 = WM_USER + 2;
/// Get text length (ANSI)
pub const SB_GETTEXTLENGTHA: u32 = WM_USER + 3;
/// Set the number of parts
pub const SB_SETPARTS: u32 = WM_USER + 4;
/// Get the number of parts
pub const SB_GETPARTS: u32 = WM_USER + 6;
/// Get border widths
pub const SB_GETBORDERS: u32 = WM_USER + 7;
/// Set minimum height
pub const SB_SETMINHEIGHT: u32 = WM_USER + 8;
/// Enable simple mode
pub const SB_SIMPLE: u32 = WM_USER + 9;
/// Get rectangle of a part
pub const SB_GETRECT: u32 = WM_USER + 10;
/// Set text for a part (Unicode)
pub const SB_SETTEXTW: u32 = WM_USER + 11;
/// Get text length (Unicode)
pub const SB_GETTEXTLENGTHW: u32 = WM_USER + 12;
/// Get text from a part (Unicode)
pub const SB_GETTEXTW: u32 = WM_USER + 13;
/// Check if in simple mode
pub const SB_ISSIMPLE: u32 = WM_USER + 14;
/// Set icon for a part
pub const SB_SETICON: u32 = WM_USER + 15;
/// Set tooltip text (ANSI)
pub const SB_SETTIPTEXTA: u32 = WM_USER + 16;
/// Set tooltip text (Unicode)
pub const SB_SETTIPTEXTW: u32 = WM_USER + 17;
/// Get tooltip text (ANSI)
pub const SB_GETTIPTEXTA: u32 = WM_USER + 18;
/// Get tooltip text (Unicode)
pub const SB_GETTIPTEXTW: u32 = WM_USER + 19;
/// Get icon for a part
pub const SB_GETICON: u32 = WM_USER + 20;

// Common control messages used by statusbar
/// Set background color
pub const SB_SETBKCOLOR: u32 = 0x2001; // CCM_SETBKCOLOR

// ============================================================================
// StatusBar Notifications (SBN_*)
// ============================================================================

/// First statusbar notification
pub const SBN_FIRST: i32 = -880;
/// Simple mode changed
pub const SBN_SIMPLEMODECHANGE: i32 = SBN_FIRST - 0;

// ============================================================================
// Special Part ID
// ============================================================================

/// Simple mode part ID
pub const SB_SIMPLEID: u8 = 0xFF;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum statusbar controls
const MAX_STATUSBARS: usize = 64;

/// Maximum parts per statusbar
const MAX_PARTS: usize = 256;

/// Maximum text length per part
const MAX_PART_TEXT: usize = 256;

/// Default height
const DEFAULT_HEIGHT: i32 = 22;

/// Default border width
const DEFAULT_BORDER_WIDTH: i32 = 2;

/// Size grip width
const SIZEGRIP_WIDTH: i32 = 16;

// ============================================================================
// Structures
// ============================================================================

/// StatusBar part
#[derive(Clone, Copy)]
struct StatusBarPart {
    /// Part in use
    in_use: bool,
    /// Right edge of part (-1 for extend to end)
    right_edge: i32,
    /// Drawing style (SBT_*)
    style: u32,
    /// Part text
    text: [u8; MAX_PART_TEXT],
    /// Text length
    text_len: usize,
    /// Icon handle (0 for none)
    icon: u32,
    /// Tooltip text
    tooltip: [u8; MAX_PART_TEXT],
    /// Tooltip length
    tooltip_len: usize,
}

impl StatusBarPart {
    const fn new() -> Self {
        Self {
            in_use: false,
            right_edge: 0,
            style: 0,
            text: [0; MAX_PART_TEXT],
            text_len: 0,
            icon: 0,
            tooltip: [0; MAX_PART_TEXT],
            tooltip_len: 0,
        }
    }
}

/// StatusBar control state
#[derive(Clone, Copy)]
struct StatusBarControl {
    /// Control in use
    in_use: bool,
    /// Window handle
    hwnd: HWND,
    /// Style flags
    style: u32,
    /// Number of parts
    part_count: usize,
    /// Parts array
    parts: [StatusBarPart; MAX_PARTS],
    /// Simple mode enabled
    simple_mode: bool,
    /// Simple mode text
    simple_text: [u8; MAX_PART_TEXT],
    /// Simple text length
    simple_text_len: usize,
    /// Minimum height
    min_height: i32,
    /// Background color (CLR_DEFAULT = 0xFFFFFFFF)
    background_color: u32,
    /// Horizontal border width
    border_h: i32,
    /// Vertical border width
    border_v: i32,
    /// Width between parts
    border_between: i32,
}

impl StatusBarControl {
    const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle(0),
            style: 0,
            part_count: 0,
            parts: [const { StatusBarPart::new() }; MAX_PARTS],
            simple_mode: false,
            simple_text: [0; MAX_PART_TEXT],
            simple_text_len: 0,
            min_height: DEFAULT_HEIGHT,
            background_color: 0xFFFFFFFF, // CLR_DEFAULT
            border_h: DEFAULT_BORDER_WIDTH,
            border_v: DEFAULT_BORDER_WIDTH,
            border_between: DEFAULT_BORDER_WIDTH,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// StatusBar subsystem initialized
static STATUSBAR_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// StatusBar lock
static STATUSBAR_LOCK: SpinLock<()> = SpinLock::new(());

/// All statusbar controls
static STATUSBARS: SpinLock<[StatusBarControl; MAX_STATUSBARS]> =
    SpinLock::new([const { StatusBarControl::new() }; MAX_STATUSBARS]);

/// StatusBar count
static STATUSBAR_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize statusbar subsystem
pub fn init() {
    let _guard = STATUSBAR_LOCK.lock();

    if STATUSBAR_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[STATUSBAR] Initializing StatusBar Control...");

    STATUSBAR_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[STATUSBAR] StatusBar Control initialized");
}

// ============================================================================
// StatusBar Creation and Deletion
// ============================================================================

/// Create a statusbar control
pub fn create_statusbar(hwnd: HWND, style: u32) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut statusbars = STATUSBARS.lock();

    // Check if already exists
    for sb in statusbars.iter() {
        if sb.in_use && sb.hwnd == hwnd {
            return false;
        }
    }

    // Find free slot
    for sb in statusbars.iter_mut() {
        if !sb.in_use {
            sb.in_use = true;
            sb.hwnd = hwnd;
            sb.style = style;
            sb.part_count = 0;
            sb.simple_mode = false;
            sb.simple_text_len = 0;
            sb.min_height = DEFAULT_HEIGHT;
            sb.background_color = 0xFFFFFFFF;
            sb.border_h = DEFAULT_BORDER_WIDTH;
            sb.border_v = DEFAULT_BORDER_WIDTH;
            sb.border_between = DEFAULT_BORDER_WIDTH;

            STATUSBAR_COUNT.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }

    false
}

/// Destroy a statusbar control
pub fn destroy_statusbar(hwnd: HWND) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut statusbars = STATUSBARS.lock();

    for sb in statusbars.iter_mut() {
        if sb.in_use && sb.hwnd == hwnd {
            sb.in_use = false;
            STATUSBAR_COUNT.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }

    false
}

// ============================================================================
// Part Management
// ============================================================================

/// Set the number of parts and their positions
///
/// # Arguments
/// * `hwnd` - StatusBar window handle
/// * `edges` - Array of right edge positions (-1 for last part extends to end)
///
/// # Returns
/// true if successful
pub fn set_parts(hwnd: HWND, edges: &[i32]) -> bool {
    if hwnd.0 == 0 || edges.is_empty() {
        return false;
    }

    let mut statusbars = STATUSBARS.lock();

    for sb in statusbars.iter_mut() {
        if sb.in_use && sb.hwnd == hwnd {
            let count = edges.len().min(MAX_PARTS);

            for i in 0..count {
                sb.parts[i].in_use = true;
                sb.parts[i].right_edge = edges[i];
                // Preserve existing text if any
            }

            // Clear unused parts
            for i in count..sb.part_count {
                sb.parts[i].in_use = false;
            }

            sb.part_count = count;
            return true;
        }
    }

    false
}

/// Get the number of parts
pub fn get_parts(hwnd: HWND, edges: Option<&mut [i32]>) -> usize {
    if hwnd.0 == 0 {
        return 0;
    }

    let statusbars = STATUSBARS.lock();

    for sb in statusbars.iter() {
        if sb.in_use && sb.hwnd == hwnd {
            if let Some(edge_buf) = edges {
                let count = edge_buf.len().min(sb.part_count);
                for i in 0..count {
                    edge_buf[i] = sb.parts[i].right_edge;
                }
            }
            return sb.part_count;
        }
    }

    0
}

/// Set text for a part
pub fn set_text(hwnd: HWND, part: usize, text: &str, style: u32) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut statusbars = STATUSBARS.lock();

    for sb in statusbars.iter_mut() {
        if sb.in_use && sb.hwnd == hwnd {
            // Handle simple mode
            if part == SB_SIMPLEID as usize || sb.simple_mode {
                let bytes = text.as_bytes();
                let len = bytes.len().min(MAX_PART_TEXT);
                for i in 0..len {
                    sb.simple_text[i] = bytes[i];
                }
                sb.simple_text_len = len;
                return true;
            }

            if part >= sb.part_count {
                return false;
            }

            let bytes = text.as_bytes();
            let len = bytes.len().min(MAX_PART_TEXT);
            for i in 0..len {
                sb.parts[part].text[i] = bytes[i];
            }
            sb.parts[part].text_len = len;
            sb.parts[part].style = style;

            return true;
        }
    }

    false
}

/// Get text from a part
pub fn get_text(hwnd: HWND, part: usize, buffer: &mut [u8]) -> usize {
    if hwnd.0 == 0 || buffer.is_empty() {
        return 0;
    }

    let statusbars = STATUSBARS.lock();

    for sb in statusbars.iter() {
        if sb.in_use && sb.hwnd == hwnd {
            // Handle simple mode
            if part == SB_SIMPLEID as usize || sb.simple_mode {
                let copy_len = buffer.len().min(sb.simple_text_len);
                for i in 0..copy_len {
                    buffer[i] = sb.simple_text[i];
                }
                if copy_len < buffer.len() {
                    buffer[copy_len] = 0;
                }
                return copy_len;
            }

            if part >= sb.part_count {
                buffer[0] = 0;
                return 0;
            }

            let copy_len = buffer.len().min(sb.parts[part].text_len);
            for i in 0..copy_len {
                buffer[i] = sb.parts[part].text[i];
            }
            if copy_len < buffer.len() {
                buffer[copy_len] = 0;
            }

            return copy_len;
        }
    }

    buffer[0] = 0;
    0
}

/// Get text length for a part
pub fn get_text_length(hwnd: HWND, part: usize) -> usize {
    if hwnd.0 == 0 {
        return 0;
    }

    let statusbars = STATUSBARS.lock();

    for sb in statusbars.iter() {
        if sb.in_use && sb.hwnd == hwnd {
            if part == SB_SIMPLEID as usize || sb.simple_mode {
                return sb.simple_text_len;
            }

            if part >= sb.part_count {
                return 0;
            }

            return sb.parts[part].text_len;
        }
    }

    0
}

/// Get rectangle of a part
pub fn get_rect(hwnd: HWND, part: usize) -> Option<Rect> {
    if hwnd.0 == 0 {
        return None;
    }

    let statusbars = STATUSBARS.lock();

    for sb in statusbars.iter() {
        if sb.in_use && sb.hwnd == hwnd {
            if part >= sb.part_count {
                return None;
            }

            // Calculate part rectangle
            let left = if part == 0 {
                sb.border_h
            } else {
                sb.parts[part - 1].right_edge + sb.border_between
            };

            let right = if sb.parts[part].right_edge < 0 {
                // Extends to end (would need window width, use placeholder)
                1000
            } else {
                sb.parts[part].right_edge
            };

            return Some(Rect {
                left,
                top: sb.border_v,
                right,
                bottom: sb.min_height - sb.border_v,
            });
        }
    }

    None
}

// ============================================================================
// Simple Mode
// ============================================================================

/// Enable or disable simple mode
pub fn set_simple(hwnd: HWND, simple: bool) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut statusbars = STATUSBARS.lock();

    for sb in statusbars.iter_mut() {
        if sb.in_use && sb.hwnd == hwnd {
            sb.simple_mode = simple;
            return true;
        }
    }

    false
}

/// Check if in simple mode
pub fn is_simple(hwnd: HWND) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let statusbars = STATUSBARS.lock();

    for sb in statusbars.iter() {
        if sb.in_use && sb.hwnd == hwnd {
            return sb.simple_mode;
        }
    }

    false
}

// ============================================================================
// Icon Support
// ============================================================================

/// Set icon for a part
pub fn set_icon(hwnd: HWND, part: usize, icon: u32) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut statusbars = STATUSBARS.lock();

    for sb in statusbars.iter_mut() {
        if sb.in_use && sb.hwnd == hwnd {
            if part >= sb.part_count {
                return false;
            }

            sb.parts[part].icon = icon;
            return true;
        }
    }

    false
}

/// Get icon for a part
pub fn get_icon(hwnd: HWND, part: usize) -> u32 {
    if hwnd.0 == 0 {
        return 0;
    }

    let statusbars = STATUSBARS.lock();

    for sb in statusbars.iter() {
        if sb.in_use && sb.hwnd == hwnd {
            if part >= sb.part_count {
                return 0;
            }

            return sb.parts[part].icon;
        }
    }

    0
}

// ============================================================================
// Tooltip Support
// ============================================================================

/// Set tooltip text for a part
pub fn set_tip_text(hwnd: HWND, part: usize, text: &str) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut statusbars = STATUSBARS.lock();

    for sb in statusbars.iter_mut() {
        if sb.in_use && sb.hwnd == hwnd {
            if part >= sb.part_count {
                return false;
            }

            let bytes = text.as_bytes();
            let len = bytes.len().min(MAX_PART_TEXT);
            for i in 0..len {
                sb.parts[part].tooltip[i] = bytes[i];
            }
            sb.parts[part].tooltip_len = len;

            return true;
        }
    }

    false
}

/// Get tooltip text for a part
pub fn get_tip_text(hwnd: HWND, part: usize, buffer: &mut [u8]) -> usize {
    if hwnd.0 == 0 || buffer.is_empty() {
        return 0;
    }

    let statusbars = STATUSBARS.lock();

    for sb in statusbars.iter() {
        if sb.in_use && sb.hwnd == hwnd {
            if part >= sb.part_count {
                buffer[0] = 0;
                return 0;
            }

            let copy_len = buffer.len().min(sb.parts[part].tooltip_len);
            for i in 0..copy_len {
                buffer[i] = sb.parts[part].tooltip[i];
            }
            if copy_len < buffer.len() {
                buffer[copy_len] = 0;
            }

            return copy_len;
        }
    }

    buffer[0] = 0;
    0
}

// ============================================================================
// Appearance
// ============================================================================

/// Set minimum height
pub fn set_min_height(hwnd: HWND, height: i32) -> bool {
    if hwnd.0 == 0 {
        return false;
    }

    let mut statusbars = STATUSBARS.lock();

    for sb in statusbars.iter_mut() {
        if sb.in_use && sb.hwnd == hwnd {
            sb.min_height = height.max(1);
            return true;
        }
    }

    false
}

/// Set background color
pub fn set_bk_color(hwnd: HWND, color: u32) -> u32 {
    if hwnd.0 == 0 {
        return 0xFFFFFFFF;
    }

    let mut statusbars = STATUSBARS.lock();

    for sb in statusbars.iter_mut() {
        if sb.in_use && sb.hwnd == hwnd {
            let old = sb.background_color;
            sb.background_color = color;
            return old;
        }
    }

    0xFFFFFFFF
}

/// Get border widths
pub fn get_borders(hwnd: HWND) -> Option<(i32, i32, i32)> {
    if hwnd.0 == 0 {
        return None;
    }

    let statusbars = STATUSBARS.lock();

    for sb in statusbars.iter() {
        if sb.in_use && sb.hwnd == hwnd {
            return Some((sb.border_h, sb.border_v, sb.border_between));
        }
    }

    None
}

// ============================================================================
// Message Handler
// ============================================================================

/// Process statusbar message
///
/// # Returns
/// (handled, result)
pub fn process_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> (bool, isize) {
    match msg {
        SB_SETPARTS => {
            // wparam = number of parts
            // lparam = pointer to array of right edges
            // For now, just return success
            (true, 1)
        }
        SB_GETPARTS => {
            (true, get_parts(hwnd, None) as isize)
        }
        SB_SETTEXTA | SB_SETTEXTW => {
            let part = (wparam & 0xFF) as usize;
            let style = (wparam >> 8) as u32;
            // In a real implementation, lparam would be a pointer to the text
            let _ = (part, style, lparam);
            (true, 1)
        }
        SB_GETTEXTA | SB_GETTEXTW => {
            let part = wparam;
            let _ = (part, lparam);
            (true, 0)
        }
        SB_GETTEXTLENGTHA | SB_GETTEXTLENGTHW => {
            let len = get_text_length(hwnd, wparam);
            (true, len as isize)
        }
        SB_SIMPLE => {
            (true, set_simple(hwnd, wparam != 0) as isize)
        }
        SB_ISSIMPLE => {
            (true, is_simple(hwnd) as isize)
        }
        SB_SETMINHEIGHT => {
            (true, set_min_height(hwnd, wparam as i32) as isize)
        }
        SB_SETBKCOLOR => {
            (true, set_bk_color(hwnd, lparam as u32) as isize)
        }
        SB_GETBORDERS => {
            // lparam points to array of 3 ints
            if let Some((h, v, b)) = get_borders(hwnd) {
                // Would write to lparam array
                let _ = (h, v, b);
                (true, 1)
            } else {
                (true, 0)
            }
        }
        SB_GETRECT => {
            if get_rect(hwnd, wparam).is_some() {
                // Would write rect to lparam
                (true, 1)
            } else {
                (true, 0)
            }
        }
        SB_SETICON => {
            let part = wparam;
            let icon = lparam as u32;
            (true, set_icon(hwnd, part, icon) as isize)
        }
        SB_GETICON => {
            (true, get_icon(hwnd, wparam) as isize)
        }
        _ => (false, 0),
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Get number of statusbar controls
pub fn get_statusbar_count() -> u32 {
    STATUSBAR_COUNT.load(Ordering::Relaxed)
}
