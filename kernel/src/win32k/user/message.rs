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
            1 // HTCLIENT
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
