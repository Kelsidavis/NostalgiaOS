//! CSR Console Management
//!
//! Manages console windows for console applications. Each console
//! has input and output buffers, and can be shared between processes.

extern crate alloc;

use crate::ke::spinlock::SpinLock;
use crate::ob::handle::Handle;
use alloc::vec::Vec;
use alloc::vec;
use alloc::string::String;
use alloc::collections::BTreeMap;

// ============================================================================
// Console Constants
// ============================================================================

/// Console input mode flags
pub const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
pub const ENABLE_LINE_INPUT: u32 = 0x0002;
pub const ENABLE_ECHO_INPUT: u32 = 0x0004;
pub const ENABLE_WINDOW_INPUT: u32 = 0x0008;
pub const ENABLE_MOUSE_INPUT: u32 = 0x0010;
pub const ENABLE_INSERT_MODE: u32 = 0x0020;
pub const ENABLE_QUICK_EDIT_MODE: u32 = 0x0040;
pub const ENABLE_EXTENDED_FLAGS: u32 = 0x0080;
pub const ENABLE_AUTO_POSITION: u32 = 0x0100;

/// Console output mode flags
pub const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
pub const ENABLE_WRAP_AT_EOL_OUTPUT: u32 = 0x0002;
pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
pub const DISABLE_NEWLINE_AUTO_RETURN: u32 = 0x0008;
pub const ENABLE_LVB_GRID_WORLDWIDE: u32 = 0x0010;

/// Console colors
pub const FOREGROUND_BLUE: u16 = 0x0001;
pub const FOREGROUND_GREEN: u16 = 0x0002;
pub const FOREGROUND_RED: u16 = 0x0004;
pub const FOREGROUND_INTENSITY: u16 = 0x0008;
pub const BACKGROUND_BLUE: u16 = 0x0010;
pub const BACKGROUND_GREEN: u16 = 0x0020;
pub const BACKGROUND_RED: u16 = 0x0040;
pub const BACKGROUND_INTENSITY: u16 = 0x0080;

/// Default console attributes (white on black)
pub const DEFAULT_ATTRIBUTES: u16 = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

/// Console buffer sizes
pub const DEFAULT_SCREEN_WIDTH: u16 = 80;
pub const DEFAULT_SCREEN_HEIGHT: u16 = 25;
pub const DEFAULT_BUFFER_HEIGHT: u16 = 300;
pub const MAX_INPUT_BUFFER_SIZE: usize = 4096;

// ============================================================================
// Console Structures
// ============================================================================

/// Console character cell
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CharInfo {
    /// Unicode character
    pub character: u16,
    /// Attributes (colors)
    pub attributes: u16,
}

impl CharInfo {
    pub fn new(ch: char, attr: u16) -> Self {
        Self {
            character: ch as u16,
            attributes: attr,
        }
    }

    pub fn blank() -> Self {
        Self {
            character: ' ' as u16,
            attributes: DEFAULT_ATTRIBUTES,
        }
    }
}

/// Console screen buffer info
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ConsoleScreenBufferInfo {
    /// Buffer size
    pub size_x: u16,
    pub size_y: u16,
    /// Cursor position
    pub cursor_x: u16,
    pub cursor_y: u16,
    /// Current attributes
    pub attributes: u16,
    /// Window rectangle
    pub window_left: u16,
    pub window_top: u16,
    pub window_right: u16,
    pub window_bottom: u16,
    /// Maximum window size
    pub max_window_x: u16,
    pub max_window_y: u16,
}

impl Default for ConsoleScreenBufferInfo {
    fn default() -> Self {
        Self {
            size_x: DEFAULT_SCREEN_WIDTH,
            size_y: DEFAULT_BUFFER_HEIGHT,
            cursor_x: 0,
            cursor_y: 0,
            attributes: DEFAULT_ATTRIBUTES,
            window_left: 0,
            window_top: 0,
            window_right: DEFAULT_SCREEN_WIDTH - 1,
            window_bottom: DEFAULT_SCREEN_HEIGHT - 1,
            max_window_x: DEFAULT_SCREEN_WIDTH,
            max_window_y: DEFAULT_SCREEN_HEIGHT,
        }
    }
}

/// Console cursor info
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ConsoleCursorInfo {
    /// Cursor size (1-100)
    pub size: u32,
    /// Cursor visible
    pub visible: bool,
}

impl Default for ConsoleCursorInfo {
    fn default() -> Self {
        Self {
            size: 25,
            visible: true,
        }
    }
}

/// Console input record types
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEventType {
    Key = 1,
    Mouse = 2,
    WindowBufferSize = 4,
    Menu = 8,
    Focus = 16,
}

/// Console input record
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct InputRecord {
    /// Event type
    pub event_type: InputEventType,
    /// Key event data
    pub key_down: bool,
    pub repeat_count: u16,
    pub virtual_key_code: u16,
    pub virtual_scan_code: u16,
    pub character: u16,
    pub control_key_state: u32,
}

impl Default for InputRecord {
    fn default() -> Self {
        Self {
            event_type: InputEventType::Key,
            key_down: false,
            repeat_count: 0,
            virtual_key_code: 0,
            virtual_scan_code: 0,
            character: 0,
            control_key_state: 0,
        }
    }
}

/// CSR Console
#[derive(Debug)]
pub struct CsrConsole {
    /// Console ID
    pub console_id: u32,
    /// Session ID
    pub session_id: u32,
    /// Title
    pub title: String,
    /// Screen buffer
    pub screen_buffer: Vec<CharInfo>,
    /// Screen buffer info
    pub buffer_info: ConsoleScreenBufferInfo,
    /// Cursor info
    pub cursor_info: ConsoleCursorInfo,
    /// Input buffer
    pub input_buffer: Vec<InputRecord>,
    /// Input mode
    pub input_mode: u32,
    /// Output mode
    pub output_mode: u32,
    /// Owning processes
    pub processes: Vec<u32>,
    /// Control-C handler installed
    pub ctrl_c_handler: bool,
}

impl CsrConsole {
    /// Create a new console
    pub fn new(console_id: u32, session_id: u32) -> Self {
        let buffer_size = (DEFAULT_SCREEN_WIDTH as usize) * (DEFAULT_BUFFER_HEIGHT as usize);

        Self {
            console_id,
            session_id,
            title: String::from("Command Prompt"),
            screen_buffer: vec![CharInfo::blank(); buffer_size],
            buffer_info: ConsoleScreenBufferInfo::default(),
            cursor_info: ConsoleCursorInfo::default(),
            input_buffer: Vec::with_capacity(MAX_INPUT_BUFFER_SIZE),
            input_mode: ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT,
            output_mode: ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT,
            processes: Vec::new(),
            ctrl_c_handler: false,
        }
    }

    /// Write a character at current cursor position
    pub fn write_char(&mut self, ch: char) {
        match ch {
            '\n' => {
                self.buffer_info.cursor_x = 0;
                self.buffer_info.cursor_y += 1;
                self.scroll_if_needed();
            }
            '\r' => {
                self.buffer_info.cursor_x = 0;
            }
            '\x08' => { // Backspace
                if self.buffer_info.cursor_x > 0 {
                    self.buffer_info.cursor_x -= 1;
                }
            }
            '\t' => {
                // Tab to next 8-column boundary
                let spaces = 8 - (self.buffer_info.cursor_x % 8);
                for _ in 0..spaces {
                    self.write_char(' ');
                }
            }
            _ => {
                let idx = self.cursor_index();
                if idx < self.screen_buffer.len() {
                    self.screen_buffer[idx] = CharInfo::new(ch, self.buffer_info.attributes);
                    self.buffer_info.cursor_x += 1;

                    // Wrap at end of line
                    if self.buffer_info.cursor_x >= self.buffer_info.size_x {
                        self.buffer_info.cursor_x = 0;
                        self.buffer_info.cursor_y += 1;
                        self.scroll_if_needed();
                    }
                }
            }
        }
    }

    /// Write a string
    pub fn write_string(&mut self, s: &str) {
        for ch in s.chars() {
            self.write_char(ch);
        }
    }

    /// Get cursor index in buffer
    fn cursor_index(&self) -> usize {
        (self.buffer_info.cursor_y as usize) * (self.buffer_info.size_x as usize)
            + (self.buffer_info.cursor_x as usize)
    }

    /// Scroll buffer if cursor past end
    fn scroll_if_needed(&mut self) {
        while self.buffer_info.cursor_y >= self.buffer_info.size_y {
            // Scroll up one line
            let line_size = self.buffer_info.size_x as usize;
            let buffer_size = self.screen_buffer.len();

            // Move all lines up
            for i in 0..(buffer_size - line_size) {
                self.screen_buffer[i] = self.screen_buffer[i + line_size];
            }

            // Clear last line
            for i in (buffer_size - line_size)..buffer_size {
                self.screen_buffer[i] = CharInfo::blank();
            }

            self.buffer_info.cursor_y -= 1;
        }
    }

    /// Set cursor position
    pub fn set_cursor(&mut self, x: u16, y: u16) {
        if x < self.buffer_info.size_x && y < self.buffer_info.size_y {
            self.buffer_info.cursor_x = x;
            self.buffer_info.cursor_y = y;
        }
    }

    /// Clear the screen
    pub fn clear(&mut self) {
        for cell in self.screen_buffer.iter_mut() {
            *cell = CharInfo::blank();
        }
        self.buffer_info.cursor_x = 0;
        self.buffer_info.cursor_y = 0;
    }

    /// Add input event
    pub fn add_input(&mut self, record: InputRecord) {
        if self.input_buffer.len() < MAX_INPUT_BUFFER_SIZE {
            self.input_buffer.push(record);
        }
    }

    /// Read input event
    pub fn read_input(&mut self) -> Option<InputRecord> {
        if !self.input_buffer.is_empty() {
            Some(self.input_buffer.remove(0))
        } else {
            None
        }
    }

    /// Peek input event
    pub fn peek_input(&self) -> Option<&InputRecord> {
        self.input_buffer.first()
    }

    /// Get input buffer count
    pub fn input_count(&self) -> usize {
        self.input_buffer.len()
    }
}

// ============================================================================
// Console Table
// ============================================================================

static CONSOLE_TABLE: SpinLock<BTreeMap<u32, CsrConsole>> = SpinLock::new(BTreeMap::new());
static NEXT_CONSOLE_ID: SpinLock<u32> = SpinLock::new(1);

// ============================================================================
// Console Functions
// ============================================================================

/// Initialize console management
pub fn init() {
    crate::serial_println!("[CSR] Console management initialized");
}

/// Create a new console
pub fn create_console(session_id: u32) -> Option<u32> {
    let mut next_id = NEXT_CONSOLE_ID.lock();
    let console_id = *next_id;
    *next_id += 1;
    drop(next_id);

    let console = CsrConsole::new(console_id, session_id);

    let mut table = CONSOLE_TABLE.lock();
    table.insert(console_id, console);

    crate::serial_println!("[CSR] Created console {}", console_id);
    Some(console_id)
}

/// Destroy a console
pub fn destroy_console(console_id: u32) -> bool {
    let mut table = CONSOLE_TABLE.lock();
    table.remove(&console_id).is_some()
}

/// Attach process to console
pub fn attach_console(console_id: u32, process_id: u32) -> bool {
    let mut table = CONSOLE_TABLE.lock();
    if let Some(console) = table.get_mut(&console_id) {
        if !console.processes.contains(&process_id) {
            console.processes.push(process_id);
        }
        true
    } else {
        false
    }
}

/// Detach process from console
pub fn detach_console(console_id: u32, process_id: u32) -> bool {
    let mut table = CONSOLE_TABLE.lock();
    if let Some(console) = table.get_mut(&console_id) {
        console.processes.retain(|&p| p != process_id);
        true
    } else {
        false
    }
}

/// Write to console output
pub fn write_console(console_id: u32, text: &str) -> usize {
    let mut table = CONSOLE_TABLE.lock();
    if let Some(console) = table.get_mut(&console_id) {
        let len = text.len();
        console.write_string(text);
        len
    } else {
        0
    }
}

/// Read from console input
pub fn read_console(console_id: u32, buffer: &mut [u8]) -> usize {
    let mut table = CONSOLE_TABLE.lock();
    if let Some(console) = table.get_mut(&console_id) {
        let mut count = 0;
        while count < buffer.len() {
            if let Some(record) = console.read_input() {
                if record.event_type == InputEventType::Key && record.key_down {
                    let ch = record.character as u8;
                    if ch != 0 {
                        buffer[count] = ch;
                        count += 1;
                    }
                }
            } else {
                break;
            }
        }
        count
    } else {
        0
    }
}

/// Set console title
pub fn set_console_title(console_id: u32, title: &str) -> bool {
    let mut table = CONSOLE_TABLE.lock();
    if let Some(console) = table.get_mut(&console_id) {
        console.title = String::from(title);
        true
    } else {
        false
    }
}

/// Get console title
pub fn get_console_title(console_id: u32) -> Option<String> {
    let table = CONSOLE_TABLE.lock();
    table.get(&console_id).map(|c| c.title.clone())
}

/// Get screen buffer info
pub fn get_screen_buffer_info(console_id: u32) -> Option<ConsoleScreenBufferInfo> {
    let table = CONSOLE_TABLE.lock();
    table.get(&console_id).map(|c| c.buffer_info)
}

/// Set cursor position
pub fn set_cursor_position(console_id: u32, x: u16, y: u16) -> bool {
    let mut table = CONSOLE_TABLE.lock();
    if let Some(console) = table.get_mut(&console_id) {
        console.set_cursor(x, y);
        true
    } else {
        false
    }
}

/// Set text attributes
pub fn set_text_attribute(console_id: u32, attributes: u16) -> bool {
    let mut table = CONSOLE_TABLE.lock();
    if let Some(console) = table.get_mut(&console_id) {
        console.buffer_info.attributes = attributes;
        true
    } else {
        false
    }
}

/// Clear console screen
pub fn clear_console(console_id: u32) -> bool {
    let mut table = CONSOLE_TABLE.lock();
    if let Some(console) = table.get_mut(&console_id) {
        console.clear();
        true
    } else {
        false
    }
}

/// Set console mode (input or output)
pub fn set_console_mode(console_id: u32, mode: u32, is_input: bool) -> bool {
    let mut table = CONSOLE_TABLE.lock();
    if let Some(console) = table.get_mut(&console_id) {
        if is_input {
            console.input_mode = mode;
        } else {
            console.output_mode = mode;
        }
        true
    } else {
        false
    }
}

/// Get console mode
pub fn get_console_mode(console_id: u32, is_input: bool) -> Option<u32> {
    let table = CONSOLE_TABLE.lock();
    table.get(&console_id).map(|c| {
        if is_input { c.input_mode } else { c.output_mode }
    })
}
