//! Message Queue and Dispatch
//!
//! Windows uses a message-based event system. Each window has a message
//! queue, and messages are dispatched to window procedures.
//!
//! # Message Types
//!
//! - **Posted**: Queued asynchronously (PostMessage)
//! - **Sent**: Synchronous, waits for response (SendMessage)
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/sendmsg.c`
//! - `windows/core/ntuser/inc/messages.h`

use crate::ke::spinlock::SpinLock;
use super::super::HWND;
use super::MAX_QUEUE_SIZE;

// ============================================================================
// Window Messages
// ============================================================================

/// Window message constants
pub const WM_NULL: u32 = 0x0000;
pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_MOVE: u32 = 0x0003;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_ACTIVATE: u32 = 0x0006;
pub const WM_SETFOCUS: u32 = 0x0007;
pub const WM_KILLFOCUS: u32 = 0x0008;
pub const WM_ENABLE: u32 = 0x000A;
pub const WM_SETREDRAW: u32 = 0x000B;
pub const WM_SETTEXT: u32 = 0x000C;
pub const WM_GETTEXT: u32 = 0x000D;
pub const WM_GETTEXTLENGTH: u32 = 0x000E;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_QUERYENDSESSION: u32 = 0x0011;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_QUERYOPEN: u32 = 0x0013;
pub const WM_ERASEBKGND: u32 = 0x0014;
pub const WM_SYSCOLORCHANGE: u32 = 0x0015;
pub const WM_ENDSESSION: u32 = 0x0016;
pub const WM_SHOWWINDOW: u32 = 0x0018;
pub const WM_SETTINGCHANGE: u32 = 0x001A;

// Non-client messages
pub const WM_NCPAINT: u32 = 0x0085;
pub const WM_NCACTIVATE: u32 = 0x0086;
pub const WM_NCCALCSIZE: u32 = 0x0083;
pub const WM_NCHITTEST: u32 = 0x0084;
pub const WM_NCLBUTTONDOWN: u32 = 0x00A1;
pub const WM_NCLBUTTONUP: u32 = 0x00A2;
pub const WM_NCMOUSEMOVE: u32 = 0x00A0;

// Keyboard messages
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_DEADCHAR: u32 = 0x0103;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;
pub const WM_SYSCHAR: u32 = 0x0106;

// Mouse messages
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;
pub const WM_LBUTTONDBLCLK: u32 = 0x0203;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_RBUTTONUP: u32 = 0x0205;
pub const WM_RBUTTONDBLCLK: u32 = 0x0206;
pub const WM_MBUTTONDOWN: u32 = 0x0207;
pub const WM_MBUTTONUP: u32 = 0x0208;
pub const WM_MBUTTONDBLCLK: u32 = 0x0209;
pub const WM_MOUSEWHEEL: u32 = 0x020A;

// Timer
pub const WM_TIMER: u32 = 0x0113;

// Command/Control messages
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_SYSCOMMAND: u32 = 0x0112;

// Dialog messages
pub const WM_INITDIALOG: u32 = 0x0110;

// Menu messages
pub const WM_INITMENU: u32 = 0x0116;
pub const WM_INITMENUPOPUP: u32 = 0x0117;
pub const WM_MENUSELECT: u32 = 0x011F;
pub const WM_MENUCHAR: u32 = 0x0120;
pub const WM_ENTERIDLE: u32 = 0x0121;
pub const WM_MENURBUTTONUP: u32 = 0x0122;
pub const WM_MENUDRAG: u32 = 0x0123;
pub const WM_MENUGETOBJECT: u32 = 0x0124;
pub const WM_UNINITMENUPOPUP: u32 = 0x0125;
pub const WM_MENUCOMMAND: u32 = 0x0126;

// User-defined messages
pub const WM_USER: u32 = 0x0400;
pub const WM_APP: u32 = 0x8000;

// ============================================================================
// Hit Test Results
// ============================================================================

/// Hit test result values for WM_NCHITTEST
pub mod hittest {
    pub const HTERROR: isize = -2;
    pub const HTTRANSPARENT: isize = -1;
    pub const HTNOWHERE: isize = 0;
    pub const HTCLIENT: isize = 1;
    pub const HTCAPTION: isize = 2;
    pub const HTSYSMENU: isize = 3;
    pub const HTGROWBOX: isize = 4;
    pub const HTSIZE: isize = 4;
    pub const HTMENU: isize = 5;
    pub const HTHSCROLL: isize = 6;
    pub const HTVSCROLL: isize = 7;
    pub const HTMINBUTTON: isize = 8;
    pub const HTMAXBUTTON: isize = 9;
    pub const HTLEFT: isize = 10;
    pub const HTRIGHT: isize = 11;
    pub const HTTOP: isize = 12;
    pub const HTTOPLEFT: isize = 13;
    pub const HTTOPRIGHT: isize = 14;
    pub const HTBOTTOM: isize = 15;
    pub const HTBOTTOMLEFT: isize = 16;
    pub const HTBOTTOMRIGHT: isize = 17;
    pub const HTBORDER: isize = 18;
    pub const HTCLOSE: isize = 20;
    pub const HTHELP: isize = 21;
}

// ============================================================================
// System Commands
// ============================================================================

/// System command values for WM_SYSCOMMAND
pub mod syscmd {
    pub const SC_SIZE: usize = 0xF000;
    pub const SC_MOVE: usize = 0xF010;
    pub const SC_MINIMIZE: usize = 0xF020;
    pub const SC_MAXIMIZE: usize = 0xF030;
    pub const SC_NEXTWINDOW: usize = 0xF040;
    pub const SC_PREVWINDOW: usize = 0xF050;
    pub const SC_CLOSE: usize = 0xF060;
    pub const SC_VSCROLL: usize = 0xF070;
    pub const SC_HSCROLL: usize = 0xF080;
    pub const SC_MOUSEMENU: usize = 0xF090;
    pub const SC_KEYMENU: usize = 0xF100;
    pub const SC_RESTORE: usize = 0xF120;
    pub const SC_TASKLIST: usize = 0xF130;
    pub const SC_SCREENSAVE: usize = 0xF140;
}

// ============================================================================
// Message Structure
// ============================================================================

/// Window message (MSG structure)
#[derive(Debug, Clone, Copy)]
pub struct Message {
    /// Target window
    pub hwnd: HWND,

    /// Message type
    pub message: u32,

    /// First parameter (unsigned)
    pub wparam: usize,

    /// Second parameter (signed)
    pub lparam: isize,

    /// Time message was posted
    pub time: u32,

    /// Cursor position when message was posted
    pub pt_x: i32,
    pub pt_y: i32,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            hwnd: HWND::NULL,
            message: WM_NULL,
            wparam: 0,
            lparam: 0,
            time: 0,
            pt_x: 0,
            pt_y: 0,
        }
    }
}

impl Message {
    pub fn new(hwnd: HWND, message: u32, wparam: usize, lparam: isize) -> Self {
        Self {
            hwnd,
            message,
            wparam,
            lparam,
            time: 0, // TODO: get current time
            pt_x: 0,
            pt_y: 0,
        }
    }
}

/// Type alias for Windows API compatibility
pub type MSG = Message;

// ============================================================================
// Message Queue
// ============================================================================

/// Message queue for a thread
#[derive(Debug)]
struct MessageQueue {
    messages: [Message; MAX_QUEUE_SIZE],
    head: usize,
    tail: usize,
    count: usize,
}

impl MessageQueue {
    const fn new() -> Self {
        Self {
            messages: [Message {
                hwnd: HWND::NULL,
                message: 0,
                wparam: 0,
                lparam: 0,
                time: 0,
                pt_x: 0,
                pt_y: 0,
            }; MAX_QUEUE_SIZE],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn is_full(&self) -> bool {
        self.count >= MAX_QUEUE_SIZE
    }

    fn enqueue(&mut self, msg: Message) -> bool {
        if self.is_full() {
            return false;
        }

        self.messages[self.tail] = msg;
        self.tail = (self.tail + 1) % MAX_QUEUE_SIZE;
        self.count += 1;
        true
    }

    fn dequeue(&mut self) -> Option<Message> {
        if self.is_empty() {
            return None;
        }

        let msg = self.messages[self.head];
        self.head = (self.head + 1) % MAX_QUEUE_SIZE;
        self.count -= 1;
        Some(msg)
    }

    fn peek(&self) -> Option<Message> {
        if self.is_empty() {
            None
        } else {
            Some(self.messages[self.head])
        }
    }

    fn peek_for_window(&self, hwnd: HWND) -> Option<Message> {
        if self.is_empty() {
            return None;
        }

        // If hwnd is NULL, return any message
        if !hwnd.is_valid() {
            return self.peek();
        }

        // Search for message matching hwnd
        let mut idx = self.head;
        for _ in 0..self.count {
            if self.messages[idx].hwnd == hwnd {
                return Some(self.messages[idx]);
            }
            idx = (idx + 1) % MAX_QUEUE_SIZE;
        }

        None
    }

    fn dequeue_for_window(&mut self, hwnd: HWND) -> Option<Message> {
        if self.is_empty() {
            return None;
        }

        // If hwnd is NULL, return first message
        if !hwnd.is_valid() {
            return self.dequeue();
        }

        // Search for message matching hwnd
        let mut idx = self.head;
        for i in 0..self.count {
            if self.messages[idx].hwnd == hwnd {
                // Remove this message by shifting
                let msg = self.messages[idx];

                // Shift messages to fill gap
                let mut j = idx;
                for _ in i..self.count - 1 {
                    let next = (j + 1) % MAX_QUEUE_SIZE;
                    self.messages[j] = self.messages[next];
                    j = next;
                }

                self.tail = if self.tail == 0 { MAX_QUEUE_SIZE - 1 } else { self.tail - 1 };
                self.count -= 1;
                return Some(msg);
            }
            idx = (idx + 1) % MAX_QUEUE_SIZE;
        }

        None
    }
}

// Global message queue (simplified - should be per-thread)
static MESSAGE_QUEUE: SpinLock<MessageQueue> = SpinLock::new(MessageQueue::new());

// ============================================================================
// Initialization
// ============================================================================

/// Initialize message system
pub fn init() {
    crate::serial_println!("[USER/Message] Message system initialized");
}

// ============================================================================
// Message Operations
// ============================================================================

/// Post a message to a window's queue
pub fn post_message(hwnd: HWND, message: u32, wparam: usize, lparam: isize) -> bool {
    let msg = Message::new(hwnd, message, wparam, lparam);

    let mut queue = MESSAGE_QUEUE.lock();
    let result = queue.enqueue(msg);

    if result {
        super::inc_message_count();
    }

    result
}

/// Send a message synchronously (returns result)
pub fn send_message(hwnd: HWND, message: u32, wparam: usize, lparam: isize) -> isize {
    // For synchronous messages, call window procedure directly
    let msg = Message::new(hwnd, message, wparam, lparam);
    call_window_proc(hwnd, &msg)
}

/// Get a message from the queue (blocking)
pub fn get_message(hwnd: HWND) -> Option<Message> {
    // In a real implementation, this would block the thread
    // For now, just poll the queue
    let mut queue = MESSAGE_QUEUE.lock();
    queue.dequeue_for_window(hwnd)
}

/// Peek at a message (non-blocking)
pub fn peek_message(hwnd: HWND, remove: bool) -> Option<Message> {
    let mut queue = MESSAGE_QUEUE.lock();

    if remove {
        queue.dequeue_for_window(hwnd)
    } else {
        queue.peek_for_window(hwnd)
    }
}

/// Dispatch a message to window procedure
pub fn dispatch_message(msg: &Message) -> isize {
    call_window_proc(msg.hwnd, msg)
}

/// Translate virtual key messages to character messages
pub fn translate_message(msg: &Message) -> bool {
    match msg.message {
        WM_KEYDOWN | WM_SYSKEYDOWN => {
            // TODO: translate virtual key to character
            // For now, just post WM_CHAR for printable keys
            let vk = msg.wparam as u8;
            if (0x20..=0x7E).contains(&vk) {
                post_message(msg.hwnd, WM_CHAR, vk as usize, msg.lparam);
                return true;
            }
            false
        }
        _ => false,
    }
}

/// Call window procedure
fn call_window_proc(hwnd: HWND, msg: &Message) -> isize {
    // Get window and call default procedure
    // In a real implementation, each window class has its own procedure

    match msg.message {
        WM_CREATE => {
            // Window created
            0
        }
        WM_DESTROY => {
            // Window destroyed
            0
        }
        WM_PAINT => {
            // Handle paint - mark window as not needing paint
            super::window::with_window_mut(hwnd, |wnd| {
                wnd.needs_paint = false;
                wnd.invalid_rect = None;
            });
            0
        }
        WM_ERASEBKGND => {
            // Erase background with window background color
            1
        }
        WM_CLOSE => {
            // Default: destroy window
            super::window::destroy_window(hwnd);
            0
        }
        WM_NCHITTEST => {
            // Non-client hit test
            let x = (msg.lparam & 0xFFFF) as i16 as i32;
            let y = ((msg.lparam >> 16) & 0xFFFF) as i16 as i32;
            nc_hit_test(hwnd, x, y)
        }
        WM_NCLBUTTONDOWN => {
            // Non-client left button down - handle caption button clicks
            let hit_test = msg.wparam as isize;
            handle_nc_button_down(hwnd, hit_test)
        }
        WM_SYSCOMMAND => {
            // System command - handle minimize, maximize, close, etc.
            handle_sys_command(hwnd, msg.wparam, msg.lparam)
        }
        WM_SETTEXT => {
            // Set window text
            0
        }
        WM_GETTEXT => {
            // Get window text
            0
        }
        WM_SHOWWINDOW => {
            // Window shown/hidden
            0
        }
        _ => {
            // Unknown message, return 0
            0
        }
    }
}

/// Post quit message
pub fn post_quit_message(exit_code: i32) {
    post_message(HWND::NULL, WM_QUIT, exit_code as usize, 0);
}

/// Check if there are messages in the queue
pub fn has_messages(hwnd: HWND) -> bool {
    let queue = MESSAGE_QUEUE.lock();
    queue.peek_for_window(hwnd).is_some()
}

// ============================================================================
// Non-Client Hit Testing
// ============================================================================

/// Perform non-client hit test
fn nc_hit_test(hwnd: HWND, x: i32, y: i32) -> isize {
    let wnd = match super::window::get_window(hwnd) {
        Some(w) => w,
        None => return hittest::HTNOWHERE,
    };

    // Check if point is in window at all
    if x < wnd.rect.left || x >= wnd.rect.right ||
       y < wnd.rect.top || y >= wnd.rect.bottom {
        return hittest::HTNOWHERE;
    }

    let metrics = wnd.get_frame_metrics();
    let border = metrics.border_width;
    let caption_height = metrics.caption_height;

    // Relative coordinates within window
    let rel_x = x - wnd.rect.left;
    let rel_y = y - wnd.rect.top;
    let width = wnd.rect.width();
    let height = wnd.rect.height();

    // Check resize borders for resizable windows
    if wnd.style.contains(super::WindowStyle::THICKFRAME) {
        // Corner detection (larger hit area)
        let corner_size = border + 4;

        // Bottom-right corner
        if rel_x >= width - corner_size && rel_y >= height - corner_size {
            return hittest::HTBOTTOMRIGHT;
        }
        // Bottom-left corner
        if rel_x < corner_size && rel_y >= height - corner_size {
            return hittest::HTBOTTOMLEFT;
        }
        // Top-right corner
        if rel_x >= width - corner_size && rel_y < corner_size {
            return hittest::HTTOPRIGHT;
        }
        // Top-left corner
        if rel_x < corner_size && rel_y < corner_size {
            return hittest::HTTOPLEFT;
        }

        // Edges
        if rel_y < border {
            return hittest::HTTOP;
        }
        if rel_y >= height - border {
            return hittest::HTBOTTOM;
        }
        if rel_x < border {
            return hittest::HTLEFT;
        }
        if rel_x >= width - border {
            return hittest::HTRIGHT;
        }
    }

    // Check caption area
    if wnd.has_caption() && rel_y >= border && rel_y < border + caption_height {
        // Caption buttons are on the right side
        let button_width = 16;
        let button_margin = 2;
        let mut button_right = width - border - button_margin;

        // Close button (rightmost)
        if metrics.has_sys_menu {
            if rel_x >= button_right - button_width && rel_x < button_right {
                return hittest::HTCLOSE;
            }
            button_right -= button_width + 2;
        }

        // Maximize button
        if metrics.has_max_box {
            if rel_x >= button_right - button_width && rel_x < button_right {
                return hittest::HTMAXBUTTON;
            }
            button_right -= button_width;
        }

        // Minimize button
        if metrics.has_min_box {
            if rel_x >= button_right - button_width && rel_x < button_right {
                return hittest::HTMINBUTTON;
            }
        }

        // System menu icon area (leftmost)
        if metrics.has_sys_menu && rel_x >= border && rel_x < border + 16 {
            return hittest::HTSYSMENU;
        }

        // Rest of caption is for moving
        return hittest::HTCAPTION;
    }

    // Check border area
    if wnd.has_border() {
        if rel_y < border || rel_y >= height - border ||
           rel_x < border || rel_x >= width - border {
            return hittest::HTBORDER;
        }
    }

    // Must be client area
    hittest::HTCLIENT
}

// ============================================================================
// Non-Client Button Handling
// ============================================================================

/// Handle non-client left button down
fn handle_nc_button_down(hwnd: HWND, hit_test: isize) -> isize {
    match hit_test {
        hittest::HTCLOSE => {
            // Close button clicked - send WM_SYSCOMMAND SC_CLOSE
            send_message(hwnd, WM_SYSCOMMAND, syscmd::SC_CLOSE, 0);
            0
        }
        hittest::HTMINBUTTON => {
            // Minimize button clicked
            send_message(hwnd, WM_SYSCOMMAND, syscmd::SC_MINIMIZE, 0);
            0
        }
        hittest::HTMAXBUTTON => {
            // Maximize button clicked
            // Check if already maximized -> restore, else maximize
            if let Some(wnd) = super::window::get_window(hwnd) {
                if wnd.maximized {
                    send_message(hwnd, WM_SYSCOMMAND, syscmd::SC_RESTORE, 0);
                } else {
                    send_message(hwnd, WM_SYSCOMMAND, syscmd::SC_MAXIMIZE, 0);
                }
            }
            0
        }
        hittest::HTCAPTION => {
            // Caption clicked - initiate window move
            // TODO: Implement window dragging
            crate::serial_println!("[USER/Msg] Caption click - would start window drag");
            0
        }
        _ => 0,
    }
}

/// Handle system commands (WM_SYSCOMMAND)
fn handle_sys_command(hwnd: HWND, wparam: usize, _lparam: isize) -> isize {
    let cmd = wparam & 0xFFF0; // Mask out lower bits (contain mouse position info)

    match cmd {
        syscmd::SC_CLOSE => {
            // Close the window
            crate::serial_println!("[USER/Msg] SC_CLOSE: closing window {:#x}", hwnd.raw());
            send_message(hwnd, WM_CLOSE, 0, 0);
            0
        }
        syscmd::SC_MINIMIZE => {
            // Minimize the window
            crate::serial_println!("[USER/Msg] SC_MINIMIZE: minimizing window {:#x}", hwnd.raw());
            super::window::show_window(hwnd, super::ShowCommand::Minimize);
            // Repaint desktop and other windows
            super::paint::repaint_all();
            0
        }
        syscmd::SC_MAXIMIZE => {
            // Maximize the window
            crate::serial_println!("[USER/Msg] SC_MAXIMIZE: maximizing window {:#x}", hwnd.raw());
            if super::window::get_window(hwnd).is_some() {
                // Get screen dimensions for maximize
                let (width, height) = super::super::gdi::surface::get_primary_dimensions();
                // Leave room for taskbar
                let taskbar_height = 28;
                super::window::set_window_pos(
                    hwnd,
                    0, 0,
                    width as i32,
                    height as i32 - taskbar_height,
                    0
                );
                super::window::with_window_mut(hwnd, |w| {
                    w.maximized = true;
                    w.minimized = false;
                });
                super::paint::draw_window_frame(hwnd);
            }
            0
        }
        syscmd::SC_RESTORE => {
            // Restore the window from minimized or maximized state
            crate::serial_println!("[USER/Msg] SC_RESTORE: restoring window {:#x}", hwnd.raw());
            super::window::show_window(hwnd, super::ShowCommand::Restore);
            // TODO: Restore to saved size/position before maximize
            super::window::with_window_mut(hwnd, |w| {
                w.maximized = false;
                w.minimized = false;
            });
            super::paint::repaint_all();
            0
        }
        syscmd::SC_MOVE => {
            // Enter move mode
            crate::serial_println!("[USER/Msg] SC_MOVE: move mode for window {:#x}", hwnd.raw());
            0
        }
        syscmd::SC_SIZE => {
            // Enter size mode
            crate::serial_println!("[USER/Msg] SC_SIZE: size mode for window {:#x}", hwnd.raw());
            0
        }
        _ => {
            crate::serial_println!("[USER/Msg] Unhandled syscommand: {:#x}", cmd);
            0
        }
    }
}
