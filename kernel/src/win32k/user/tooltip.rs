//! Tooltip Control Implementation
//!
//! Implements the Windows Tooltip control for displaying popup hints.
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `public/sdk/inc/commctrl.h` - Control styles and messages

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{HWND, Rect, Point};

// ============================================================================
// Tooltip Class
// ============================================================================

/// Tooltip window class name
pub const TOOLTIP_CLASS: &str = "tooltips_class32";

// ============================================================================
// Tooltip Styles (TTS_*)
// ============================================================================

/// Always show tip (even when window is inactive)
pub const TTS_ALWAYSTIP: u32 = 0x01;

/// Don't strip ampersands
pub const TTS_NOPREFIX: u32 = 0x02;

/// No animation
pub const TTS_NOANIMATE: u32 = 0x10;

/// No fade effect
pub const TTS_NOFADE: u32 = 0x20;

/// Balloon style tooltip
pub const TTS_BALLOON: u32 = 0x40;

/// Show close button
pub const TTS_CLOSE: u32 = 0x80;

// ============================================================================
// Tool Flags (TTF_*)
// ============================================================================

/// uId is an HWND
pub const TTF_IDISHWND: u32 = 0x0001;

/// Center tip below tool
pub const TTF_CENTERTIP: u32 = 0x0002;

/// RTL reading order
pub const TTF_RTLREADING: u32 = 0x0004;

/// Subclass to get mouse messages
pub const TTF_SUBCLASS: u32 = 0x0010;

/// Track mouse position
pub const TTF_TRACK: u32 = 0x0020;

/// Position is absolute
pub const TTF_ABSOLUTE: u32 = 0x0080;

/// Transparent tooltip
pub const TTF_TRANSPARENT: u32 = 0x0100;

/// Parse links in text
pub const TTF_PARSELINKS: u32 = 0x1000;

/// Set item on callback
pub const TTF_DI_SETITEM: u32 = 0x8000;

// ============================================================================
// Delay Time Types (TTDT_*)
// ============================================================================

/// Automatic delay times
pub const TTDT_AUTOMATIC: u32 = 0;

/// Reshow delay
pub const TTDT_RESHOW: u32 = 1;

/// Auto-popup delay
pub const TTDT_AUTOPOP: u32 = 2;

/// Initial delay
pub const TTDT_INITIAL: u32 = 3;

// ============================================================================
// Tooltip Messages (TTM_*)
// ============================================================================

/// WM_USER base
const WM_USER: u32 = 0x0400;

/// Activate/deactivate tooltip
pub const TTM_ACTIVATE: u32 = WM_USER + 1;

/// Set delay time
pub const TTM_SETDELAYTIME: u32 = WM_USER + 3;

/// Add a tool (ANSI)
pub const TTM_ADDTOOLA: u32 = WM_USER + 4;

/// Add a tool (Unicode)
pub const TTM_ADDTOOLW: u32 = WM_USER + 50;

/// Delete a tool (ANSI)
pub const TTM_DELTOOLA: u32 = WM_USER + 5;

/// Delete a tool (Unicode)
pub const TTM_DELTOOLW: u32 = WM_USER + 51;

/// Set new tool rectangle (ANSI)
pub const TTM_NEWTOOLRECTA: u32 = WM_USER + 6;

/// Set new tool rectangle (Unicode)
pub const TTM_NEWTOOLRECTW: u32 = WM_USER + 52;

/// Relay mouse event
pub const TTM_RELAYEVENT: u32 = WM_USER + 7;

/// Get tool info (ANSI)
pub const TTM_GETTOOLINFOA: u32 = WM_USER + 8;

/// Get tool info (Unicode)
pub const TTM_GETTOOLINFOW: u32 = WM_USER + 53;

/// Set tool info (ANSI)
pub const TTM_SETTOOLINFOA: u32 = WM_USER + 9;

/// Set tool info (Unicode)
pub const TTM_SETTOOLINFOW: u32 = WM_USER + 54;

/// Hit test (ANSI)
pub const TTM_HITTESTA: u32 = WM_USER + 10;

/// Hit test (Unicode)
pub const TTM_HITTESTW: u32 = WM_USER + 55;

/// Get text (ANSI)
pub const TTM_GETTEXTA: u32 = WM_USER + 11;

/// Get text (Unicode)
pub const TTM_GETTEXTW: u32 = WM_USER + 56;

/// Update tip text (ANSI)
pub const TTM_UPDATETIPTEXTA: u32 = WM_USER + 12;

/// Update tip text (Unicode)
pub const TTM_UPDATETIPTEXTW: u32 = WM_USER + 57;

/// Get tool count
pub const TTM_GETTOOLCOUNT: u32 = WM_USER + 13;

/// Enumerate tools (ANSI)
pub const TTM_ENUMTOOLSA: u32 = WM_USER + 14;

/// Enumerate tools (Unicode)
pub const TTM_ENUMTOOLSW: u32 = WM_USER + 58;

/// Get current tool (ANSI)
pub const TTM_GETCURRENTTOOLA: u32 = WM_USER + 15;

/// Get current tool (Unicode)
pub const TTM_GETCURRENTTOOLW: u32 = WM_USER + 59;

/// Get window from point
pub const TTM_WINDOWFROMPOINT: u32 = WM_USER + 16;

/// Activate tracking
pub const TTM_TRACKACTIVATE: u32 = WM_USER + 17;

/// Set track position
pub const TTM_TRACKPOSITION: u32 = WM_USER + 18;

/// Set tip background color
pub const TTM_SETTIPBKCOLOR: u32 = WM_USER + 19;

/// Set tip text color
pub const TTM_SETTIPTEXTCOLOR: u32 = WM_USER + 20;

/// Get delay time
pub const TTM_GETDELAYTIME: u32 = WM_USER + 21;

/// Get tip background color
pub const TTM_GETTIPBKCOLOR: u32 = WM_USER + 22;

/// Get tip text color
pub const TTM_GETTIPTEXTCOLOR: u32 = WM_USER + 23;

/// Set maximum tip width
pub const TTM_SETMAXTIPWIDTH: u32 = WM_USER + 24;

/// Get maximum tip width
pub const TTM_GETMAXTIPWIDTH: u32 = WM_USER + 25;

/// Set margin
pub const TTM_SETMARGIN: u32 = WM_USER + 26;

/// Get margin
pub const TTM_GETMARGIN: u32 = WM_USER + 27;

/// Hide the tooltip
pub const TTM_POP: u32 = WM_USER + 28;

/// Update tooltip
pub const TTM_UPDATE: u32 = WM_USER + 29;

/// Get bubble size
pub const TTM_GETBUBBLESIZE: u32 = WM_USER + 30;

/// Adjust rectangle
pub const TTM_ADJUSTRECT: u32 = WM_USER + 31;

/// Set title (ANSI)
pub const TTM_SETTITLEA: u32 = WM_USER + 32;

/// Set title (Unicode)
pub const TTM_SETTITLEW: u32 = WM_USER + 33;

/// Show tooltip
pub const TTM_POPUP: u32 = WM_USER + 34;

/// Get title
pub const TTM_GETTITLE: u32 = WM_USER + 35;

// ============================================================================
// Tooltip Notifications (TTN_*)
// ============================================================================

/// TTN notification base
const TTN_FIRST: u32 = 0xFFFFFDF8; // -520

/// Get display info (ANSI)
pub const TTN_GETDISPINFOA: u32 = TTN_FIRST - 0;

/// Get display info (Unicode)
pub const TTN_GETDISPINFOW: u32 = TTN_FIRST - 10;

/// Tooltip is about to show
pub const TTN_SHOW: u32 = TTN_FIRST - 1;

/// Tooltip is about to hide
pub const TTN_POP: u32 = TTN_FIRST - 2;

/// Link clicked
pub const TTN_LINKCLICK: u32 = TTN_FIRST - 3;

// ============================================================================
// Tool Structure
// ============================================================================

/// Maximum text length per tool
const MAX_TIP_TEXT: usize = 256;

/// Maximum tools per tooltip control
const MAX_TOOLS: usize = 64;

/// Tool info
#[derive(Debug, Clone)]
pub struct ToolInfo {
    /// Tool is in use
    pub in_use: bool,
    /// Flags
    pub flags: u32,
    /// Owner window
    pub hwnd: HWND,
    /// Tool ID
    pub id: usize,
    /// Tool rectangle (if not TTF_IDISHWND)
    pub rect: Rect,
    /// Tooltip text
    pub text: [u8; MAX_TIP_TEXT],
    /// Text length
    pub text_len: usize,
    /// Application data
    pub lparam: isize,
}

impl ToolInfo {
    const fn new() -> Self {
        Self {
            in_use: false,
            flags: 0,
            hwnd: HWND::NULL,
            id: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            text: [0u8; MAX_TIP_TEXT],
            text_len: 0,
            lparam: 0,
        }
    }

    fn reset(&mut self) {
        self.in_use = false;
        self.flags = 0;
        self.hwnd = HWND::NULL;
        self.id = 0;
        self.rect = Rect { left: 0, top: 0, right: 0, bottom: 0 };
        self.text = [0u8; MAX_TIP_TEXT];
        self.text_len = 0;
        self.lparam = 0;
    }

    fn set_text(&mut self, text: &[u8]) {
        let len = text.len().min(MAX_TIP_TEXT - 1);
        self.text[..len].copy_from_slice(&text[..len]);
        self.text[len] = 0;
        self.text_len = len;
    }
}

// ============================================================================
// Tooltip Control State
// ============================================================================

/// Maximum number of tooltip controls
const MAX_TOOLTIPS: usize = 32;

/// Tooltip control state
pub struct TooltipControl {
    /// Control is in use
    in_use: bool,
    /// Associated window handle
    hwnd: HWND,
    /// Control styles
    style: u32,
    /// Is active
    active: bool,
    /// Tools
    tools: [ToolInfo; MAX_TOOLS],
    /// Tool count
    tool_count: usize,
    /// Current tool index (-1 = none)
    current_tool: i32,
    /// Background color
    bk_color: u32,
    /// Text color
    text_color: u32,
    /// Maximum tip width
    max_tip_width: i32,
    /// Margin
    margin: Rect,
    /// Initial delay (ms)
    delay_initial: u32,
    /// Autopop delay (ms)
    delay_autopop: u32,
    /// Reshow delay (ms)
    delay_reshow: u32,
    /// Title text
    title: [u8; 64],
    /// Title length
    title_len: usize,
    /// Title icon
    title_icon: u32,
    /// Track position
    track_pos: Point,
    /// Tracking active
    tracking: bool,
}

impl TooltipControl {
    const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: HWND::NULL,
            style: 0,
            active: true,
            tools: [const { ToolInfo::new() }; MAX_TOOLS],
            tool_count: 0,
            current_tool: -1,
            bk_color: 0xFFFFE1, // Light yellow (INFO_BACKGROUND)
            text_color: 0x000000,
            max_tip_width: -1,
            margin: Rect { left: 2, top: 2, right: 2, bottom: 2 },
            delay_initial: 500,
            delay_autopop: 5000,
            delay_reshow: 100,
            title: [0u8; 64],
            title_len: 0,
            title_icon: 0,
            track_pos: Point { x: 0, y: 0 },
            tracking: false,
        }
    }

    fn reset(&mut self) {
        self.in_use = false;
        self.hwnd = HWND::NULL;
        self.style = 0;
        self.active = true;
        for tool in &mut self.tools {
            tool.reset();
        }
        self.tool_count = 0;
        self.current_tool = -1;
        self.bk_color = 0xFFFFE1;
        self.text_color = 0x000000;
        self.max_tip_width = -1;
        self.margin = Rect { left: 2, top: 2, right: 2, bottom: 2 };
        self.delay_initial = 500;
        self.delay_autopop = 5000;
        self.delay_reshow = 100;
        self.title = [0u8; 64];
        self.title_len = 0;
        self.title_icon = 0;
        self.track_pos = Point { x: 0, y: 0 };
        self.tracking = false;
    }
}

// ============================================================================
// Global State
// ============================================================================

static TOOLTIP_INITIALIZED: AtomicBool = AtomicBool::new(false);
static TOOLTIP_COUNT: AtomicU32 = AtomicU32::new(0);
static TOOLTIPS: SpinLock<[TooltipControl; MAX_TOOLTIPS]> =
    SpinLock::new([const { TooltipControl::new() }; MAX_TOOLTIPS]);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize tooltip control subsystem
pub fn init() {
    if TOOLTIP_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[TOOLTIP] Initializing Tooltip control...");

    TOOLTIP_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[TOOLTIP] Tooltip control initialized");
}

// ============================================================================
// Tooltip Creation/Destruction
// ============================================================================

/// Create a tooltip control
pub fn create_tooltip(hwnd: HWND, style: u32) -> Option<usize> {
    let mut tips = TOOLTIPS.lock();

    for (index, tip) in tips.iter_mut().enumerate() {
        if !tip.in_use {
            tip.in_use = true;
            tip.hwnd = hwnd;
            tip.style = style;
            tip.active = true;
            tip.tool_count = 0;
            tip.current_tool = -1;

            TOOLTIP_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(index);
        }
    }

    None
}

/// Destroy a tooltip control
pub fn destroy_tooltip(index: usize) -> bool {
    if index >= MAX_TOOLTIPS {
        return false;
    }

    let mut tips = TOOLTIPS.lock();
    if tips[index].in_use {
        tips[index].reset();
        TOOLTIP_COUNT.fetch_sub(1, Ordering::Relaxed);
        return true;
    }

    false
}

/// Find tooltip by window handle
pub fn find_tooltip(hwnd: HWND) -> Option<usize> {
    let tips = TOOLTIPS.lock();
    for (index, tip) in tips.iter().enumerate() {
        if tip.in_use && tip.hwnd == hwnd {
            return Some(index);
        }
    }
    None
}

// ============================================================================
// Tool Management
// ============================================================================

/// Add a tool
pub fn add_tool(index: usize, hwnd: HWND, id: usize, rect: Rect, text: &[u8], flags: u32) -> bool {
    if index >= MAX_TOOLTIPS {
        return false;
    }

    let mut tips = TOOLTIPS.lock();
    if !tips[index].in_use || tips[index].tool_count >= MAX_TOOLS {
        return false;
    }

    // Find free slot
    for tool in &mut tips[index].tools {
        if !tool.in_use {
            tool.in_use = true;
            tool.hwnd = hwnd;
            tool.id = id;
            tool.rect = rect;
            tool.flags = flags;
            tool.set_text(text);
            tips[index].tool_count += 1;
            return true;
        }
    }

    false
}

/// Delete a tool
pub fn del_tool(index: usize, hwnd: HWND, id: usize) -> bool {
    if index >= MAX_TOOLTIPS {
        return false;
    }

    let mut tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return false;
    }

    for tool in &mut tips[index].tools {
        if tool.in_use && tool.hwnd == hwnd && tool.id == id {
            tool.reset();
            tips[index].tool_count = tips[index].tool_count.saturating_sub(1);
            return true;
        }
    }

    false
}

/// Get tool count
pub fn get_tool_count(index: usize) -> i32 {
    if index >= MAX_TOOLTIPS {
        return 0;
    }

    let tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return 0;
    }

    tips[index].tool_count as i32
}

/// Update tool rect
pub fn new_tool_rect(index: usize, hwnd: HWND, id: usize, rect: Rect) -> bool {
    if index >= MAX_TOOLTIPS {
        return false;
    }

    let mut tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return false;
    }

    for tool in &mut tips[index].tools {
        if tool.in_use && tool.hwnd == hwnd && tool.id == id {
            tool.rect = rect;
            return true;
        }
    }

    false
}

/// Update tip text
pub fn update_tip_text(index: usize, hwnd: HWND, id: usize, text: &[u8]) -> bool {
    if index >= MAX_TOOLTIPS {
        return false;
    }

    let mut tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return false;
    }

    for tool in &mut tips[index].tools {
        if tool.in_use && tool.hwnd == hwnd && tool.id == id {
            tool.set_text(text);
            return true;
        }
    }

    false
}

/// Find tool by point
pub fn find_tool_by_point(index: usize, hwnd: HWND, pt: Point) -> Option<usize> {
    if index >= MAX_TOOLTIPS {
        return None;
    }

    let tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return None;
    }

    for (i, tool) in tips[index].tools.iter().enumerate() {
        if !tool.in_use || tool.hwnd != hwnd {
            continue;
        }

        if (tool.flags & TTF_IDISHWND) != 0 {
            // Tool is entire window - would need to check window bounds
            return Some(i);
        } else if pt.x >= tool.rect.left && pt.x < tool.rect.right &&
                  pt.y >= tool.rect.top && pt.y < tool.rect.bottom {
            return Some(i);
        }
    }

    None
}

// ============================================================================
// Activation
// ============================================================================

/// Activate or deactivate tooltip
pub fn activate(index: usize, active: bool) {
    if index >= MAX_TOOLTIPS {
        return;
    }

    let mut tips = TOOLTIPS.lock();
    if tips[index].in_use {
        tips[index].active = active;
        if !active {
            tips[index].current_tool = -1;
        }
    }
}

/// Check if active
pub fn is_active(index: usize) -> bool {
    if index >= MAX_TOOLTIPS {
        return false;
    }

    let tips = TOOLTIPS.lock();
    tips[index].in_use && tips[index].active
}

/// Pop (hide) the tooltip
pub fn pop(index: usize) {
    if index >= MAX_TOOLTIPS {
        return;
    }

    let mut tips = TOOLTIPS.lock();
    if tips[index].in_use {
        tips[index].current_tool = -1;
    }
}

// ============================================================================
// Colors
// ============================================================================

/// Get tip background color
pub fn get_tip_bk_color(index: usize) -> u32 {
    if index >= MAX_TOOLTIPS {
        return 0xFFFFE1;
    }

    let tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return 0xFFFFE1;
    }

    tips[index].bk_color
}

/// Set tip background color
pub fn set_tip_bk_color(index: usize, color: u32) {
    if index >= MAX_TOOLTIPS {
        return;
    }

    let mut tips = TOOLTIPS.lock();
    if tips[index].in_use {
        tips[index].bk_color = color;
    }
}

/// Get tip text color
pub fn get_tip_text_color(index: usize) -> u32 {
    if index >= MAX_TOOLTIPS {
        return 0x000000;
    }

    let tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return 0x000000;
    }

    tips[index].text_color
}

/// Set tip text color
pub fn set_tip_text_color(index: usize, color: u32) {
    if index >= MAX_TOOLTIPS {
        return;
    }

    let mut tips = TOOLTIPS.lock();
    if tips[index].in_use {
        tips[index].text_color = color;
    }
}

// ============================================================================
// Delay Times
// ============================================================================

/// Get delay time
pub fn get_delay_time(index: usize, delay_type: u32) -> u32 {
    if index >= MAX_TOOLTIPS {
        return 0;
    }

    let tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return 0;
    }

    match delay_type {
        TTDT_INITIAL => tips[index].delay_initial,
        TTDT_AUTOPOP => tips[index].delay_autopop,
        TTDT_RESHOW => tips[index].delay_reshow,
        _ => tips[index].delay_initial,
    }
}

/// Set delay time
pub fn set_delay_time(index: usize, delay_type: u32, time: u32) {
    if index >= MAX_TOOLTIPS {
        return;
    }

    let mut tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return;
    }

    match delay_type {
        TTDT_AUTOMATIC => {
            // Set all delays based on initial
            tips[index].delay_initial = time;
            tips[index].delay_autopop = time * 10;
            tips[index].delay_reshow = time / 5;
        }
        TTDT_INITIAL => tips[index].delay_initial = time,
        TTDT_AUTOPOP => tips[index].delay_autopop = time,
        TTDT_RESHOW => tips[index].delay_reshow = time,
        _ => {}
    }
}

// ============================================================================
// Max Tip Width
// ============================================================================

/// Get max tip width
pub fn get_max_tip_width(index: usize) -> i32 {
    if index >= MAX_TOOLTIPS {
        return -1;
    }

    let tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return -1;
    }

    tips[index].max_tip_width
}

/// Set max tip width
pub fn set_max_tip_width(index: usize, width: i32) -> i32 {
    if index >= MAX_TOOLTIPS {
        return -1;
    }

    let mut tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return -1;
    }

    let old = tips[index].max_tip_width;
    tips[index].max_tip_width = width;
    old
}

// ============================================================================
// Margin
// ============================================================================

/// Get margin
pub fn get_margin(index: usize) -> Rect {
    if index >= MAX_TOOLTIPS {
        return Rect { left: 0, top: 0, right: 0, bottom: 0 };
    }

    let tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return Rect { left: 0, top: 0, right: 0, bottom: 0 };
    }

    tips[index].margin
}

/// Set margin
pub fn set_margin(index: usize, margin: Rect) {
    if index >= MAX_TOOLTIPS {
        return;
    }

    let mut tips = TOOLTIPS.lock();
    if tips[index].in_use {
        tips[index].margin = margin;
    }
}

// ============================================================================
// Tracking
// ============================================================================

/// Activate tracking
pub fn track_activate(index: usize, activate: bool, hwnd: HWND, id: usize) {
    if index >= MAX_TOOLTIPS {
        return;
    }

    let mut tips = TOOLTIPS.lock();
    if !tips[index].in_use {
        return;
    }

    tips[index].tracking = activate;

    if activate {
        // Find the tool
        for (i, tool) in tips[index].tools.iter().enumerate() {
            if tool.in_use && tool.hwnd == hwnd && tool.id == id {
                tips[index].current_tool = i as i32;
                break;
            }
        }
    } else {
        tips[index].current_tool = -1;
    }
}

/// Set track position
pub fn track_position(index: usize, x: i32, y: i32) {
    if index >= MAX_TOOLTIPS {
        return;
    }

    let mut tips = TOOLTIPS.lock();
    if tips[index].in_use {
        tips[index].track_pos = Point { x, y };
    }
}

// ============================================================================
// Message Processing
// ============================================================================

/// Process tooltip message
pub fn process_message(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> Option<isize> {
    let index = find_tooltip(hwnd)?;

    match msg {
        TTM_ACTIVATE => {
            activate(index, wparam != 0);
            Some(0)
        }
        TTM_GETTOOLCOUNT => {
            Some(get_tool_count(index) as isize)
        }
        TTM_SETDELAYTIME => {
            set_delay_time(index, wparam as u32, lparam as u32);
            Some(0)
        }
        TTM_GETDELAYTIME => {
            Some(get_delay_time(index, wparam as u32) as isize)
        }
        TTM_SETTIPBKCOLOR => {
            set_tip_bk_color(index, lparam as u32);
            Some(0)
        }
        TTM_GETTIPBKCOLOR => {
            Some(get_tip_bk_color(index) as isize)
        }
        TTM_SETTIPTEXTCOLOR => {
            set_tip_text_color(index, lparam as u32);
            Some(0)
        }
        TTM_GETTIPTEXTCOLOR => {
            Some(get_tip_text_color(index) as isize)
        }
        TTM_SETMAXTIPWIDTH => {
            Some(set_max_tip_width(index, lparam as i32) as isize)
        }
        TTM_GETMAXTIPWIDTH => {
            Some(get_max_tip_width(index) as isize)
        }
        TTM_SETMARGIN => {
            if lparam != 0 {
                unsafe {
                    let rect = *(lparam as *const Rect);
                    set_margin(index, rect);
                }
            }
            Some(0)
        }
        TTM_GETMARGIN => {
            if lparam != 0 {
                unsafe {
                    let rect = &mut *(lparam as *mut Rect);
                    *rect = get_margin(index);
                }
            }
            Some(0)
        }
        TTM_POP => {
            pop(index);
            Some(0)
        }
        TTM_TRACKPOSITION => {
            let x = (lparam as u32 & 0xFFFF) as i16 as i32;
            let y = ((lparam as u32 >> 16) & 0xFFFF) as i16 as i32;
            track_position(index, x, y);
            Some(0)
        }
        _ => None,
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Tooltip statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct TooltipStats {
    pub initialized: bool,
    pub count: u32,
}

/// Get tooltip statistics
pub fn get_stats() -> TooltipStats {
    TooltipStats {
        initialized: TOOLTIP_INITIALIZED.load(Ordering::Relaxed),
        count: TOOLTIP_COUNT.load(Ordering::Relaxed),
    }
}
