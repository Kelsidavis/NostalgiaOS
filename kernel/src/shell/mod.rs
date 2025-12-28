//! Simple Command Shell
//!
//! A basic interactive shell for Nostalgia OS that provides:
//! - Command line editing with backspace
//! - Command history with up/down arrow navigation
//! - Built-in commands (help, echo, clear, ver, etc.)
//! - File system commands (ls, cd, cat, mkdir, rmdir, rm, type)
//! - System information commands (mem, time)

use crate::hal::keyboard;
use crate::serial_println;

mod commands;

/// Maximum command line length
const MAX_CMD_LEN: usize = 256;

/// Maximum number of arguments
const MAX_ARGS: usize = 16;

/// Maximum number of commands in history
const HISTORY_SIZE: usize = 32;

/// Current working directory
static mut CURRENT_DIR: [u8; 64] = [0u8; 64];
static mut CURRENT_DIR_LEN: usize = 0;

/// Command history entry
#[derive(Clone, Copy)]
struct HistoryEntry {
    /// Command text
    data: [u8; MAX_CMD_LEN],
    /// Length of command
    len: usize,
}

impl HistoryEntry {
    const fn new() -> Self {
        Self {
            data: [0u8; MAX_CMD_LEN],
            len: 0,
        }
    }
}

/// Shell state
pub struct Shell {
    /// Command line buffer
    cmd_buf: [u8; MAX_CMD_LEN],
    /// Current position in command buffer
    cmd_pos: usize,
    /// Is the shell running?
    running: bool,
    /// Command history (circular buffer)
    history: [HistoryEntry; HISTORY_SIZE],
    /// Index of next entry to write (also count when < HISTORY_SIZE)
    history_write: usize,
    /// Total commands added to history
    history_count: usize,
    /// Current position when navigating history (-1 = current line)
    history_nav: isize,
    /// Saved current line when navigating history
    saved_line: [u8; MAX_CMD_LEN],
    /// Saved current line length
    saved_len: usize,
}

impl Shell {
    /// Create a new shell instance
    pub const fn new() -> Self {
        const EMPTY_ENTRY: HistoryEntry = HistoryEntry::new();
        Self {
            cmd_buf: [0u8; MAX_CMD_LEN],
            cmd_pos: 0,
            running: true,
            history: [EMPTY_ENTRY; HISTORY_SIZE],
            history_write: 0,
            history_count: 0,
            history_nav: -1,
            saved_line: [0u8; MAX_CMD_LEN],
            saved_len: 0,
        }
    }

    /// Initialize the shell
    pub fn init(&mut self) {
        // Set default directory to C:\
        unsafe {
            CURRENT_DIR[0] = b'C';
            CURRENT_DIR[1] = b':';
            CURRENT_DIR[2] = b'\\';
            CURRENT_DIR_LEN = 3;
        }

        self.print_banner();
        self.print_prompt();
    }

    /// Print the welcome banner
    fn print_banner(&self) {
        serial_println!("");
        serial_println!("========================================");
        serial_println!("  Nostalgia OS Shell v0.1.0");
        serial_println!("========================================");
        serial_println!("Type 'help' for available commands.");
        serial_println!("");
    }

    /// Print the command prompt
    fn print_prompt(&self) {
        let dir = get_current_dir();
        crate::serial_print!("{}> ", dir);
    }

    /// Run the shell main loop
    pub fn run(&mut self) {
        while self.running {
            let c = keyboard::read_char();
            self.process_char(c);
        }
    }

    /// Process a single character input
    fn process_char(&mut self, c: u8) {
        match c {
            // Enter - execute command
            b'\r' | b'\n' => {
                serial_println!("");
                if self.cmd_pos > 0 {
                    // Add to history before executing
                    self.add_to_history();
                    self.execute_command();
                }
                // Reset state
                self.cmd_pos = 0;
                self.cmd_buf = [0u8; MAX_CMD_LEN];
                self.history_nav = -1;
                if self.running {
                    self.print_prompt();
                }
            }

            // Backspace
            0x7F | 0x08 => {
                if self.cmd_pos > 0 {
                    self.cmd_pos -= 1;
                    self.cmd_buf[self.cmd_pos] = 0;
                    // Erase character on screen: backspace, space, backspace
                    crate::serial_print!("\x08 \x08");
                }
            }

            // Escape sequences (arrow keys, etc.)
            0x1B => {
                self.handle_escape_sequence();
            }

            // Tab - could be used for completion later
            b'\t' => {
                // Ignore for now
            }

            // Regular printable characters
            0x20..=0x7E => {
                if self.cmd_pos < MAX_CMD_LEN - 1 {
                    self.cmd_buf[self.cmd_pos] = c;
                    self.cmd_pos += 1;
                    crate::serial_print!("{}", c as char);
                }
            }

            // Ctrl+C - cancel current line
            0x03 => {
                serial_println!("^C");
                self.cmd_pos = 0;
                self.cmd_buf = [0u8; MAX_CMD_LEN];
                self.history_nav = -1;
                self.print_prompt();
            }

            // Ctrl+D - exit shell
            0x04 => {
                serial_println!("");
                serial_println!("Exiting shell...");
                self.running = false;
            }

            _ => {
                // Ignore other control characters
            }
        }
    }

    /// Handle escape sequences (arrow keys, etc.)
    fn handle_escape_sequence(&mut self) {
        // Read the next character (should be '[' for CSI sequences)
        if let Some(c1) = keyboard::try_read_char() {
            if c1 == b'[' {
                // CSI sequence - read the command character
                if let Some(c2) = keyboard::try_read_char() {
                    match c2 {
                        b'A' => self.history_up(),   // Up arrow
                        b'B' => self.history_down(), // Down arrow
                        b'C' => {}                   // Right arrow (TODO)
                        b'D' => {}                   // Left arrow (TODO)
                        b'H' => {}                   // Home (TODO)
                        b'F' => {}                   // End (TODO)
                        _ => {}
                    }
                }
            }
        }
    }

    /// Add current command to history
    fn add_to_history(&mut self) {
        if self.cmd_pos == 0 {
            return;
        }

        // Don't add duplicate of last command
        if self.history_count > 0 {
            let last_idx = if self.history_write == 0 {
                HISTORY_SIZE - 1
            } else {
                self.history_write - 1
            };
            let last = &self.history[last_idx];
            if last.len == self.cmd_pos {
                let mut same = true;
                for i in 0..self.cmd_pos {
                    if last.data[i] != self.cmd_buf[i] {
                        same = false;
                        break;
                    }
                }
                if same {
                    return;
                }
            }
        }

        // Add to history
        let entry = &mut self.history[self.history_write];
        entry.data[..self.cmd_pos].copy_from_slice(&self.cmd_buf[..self.cmd_pos]);
        entry.len = self.cmd_pos;

        self.history_write = (self.history_write + 1) % HISTORY_SIZE;
        if self.history_count < HISTORY_SIZE {
            self.history_count += 1;
        }
    }

    /// Navigate up in history (older commands)
    fn history_up(&mut self) {
        if self.history_count == 0 {
            return;
        }

        // Save current line if we're just starting to navigate
        if self.history_nav < 0 {
            self.saved_line[..self.cmd_pos].copy_from_slice(&self.cmd_buf[..self.cmd_pos]);
            self.saved_len = self.cmd_pos;
            self.history_nav = 0;
        } else if (self.history_nav as usize) < self.history_count - 1 {
            self.history_nav += 1;
        } else {
            // Already at oldest entry
            return;
        }

        self.load_history_entry();
    }

    /// Navigate down in history (newer commands)
    fn history_down(&mut self) {
        if self.history_nav < 0 {
            // Not navigating history
            return;
        }

        if self.history_nav > 0 {
            self.history_nav -= 1;
            self.load_history_entry();
        } else {
            // Return to saved line
            self.history_nav = -1;
            self.clear_line();
            self.cmd_buf[..self.saved_len].copy_from_slice(&self.saved_line[..self.saved_len]);
            self.cmd_pos = self.saved_len;
            self.redisplay_line();
        }
    }

    /// Load a history entry into the command buffer
    fn load_history_entry(&mut self) {
        // Calculate actual index in circular buffer
        // history_nav = 0 means most recent, 1 means second most recent, etc.
        let offset = self.history_nav as usize;

        // Most recent entry is at (history_write - 1), older entries go backwards
        let idx = if self.history_write > offset {
            self.history_write - 1 - offset
        } else {
            HISTORY_SIZE - 1 - (offset - self.history_write)
        };

        let entry = &self.history[idx];

        // Clear current line and display history entry
        self.clear_line();
        self.cmd_buf[..entry.len].copy_from_slice(&entry.data[..entry.len]);
        self.cmd_pos = entry.len;
        self.redisplay_line();
    }

    /// Clear the current line on screen
    fn clear_line(&self) {
        // Move cursor back to start of input and clear to end of line
        for _ in 0..self.cmd_pos {
            crate::serial_print!("\x08");
        }
        for _ in 0..self.cmd_pos {
            crate::serial_print!(" ");
        }
        for _ in 0..self.cmd_pos {
            crate::serial_print!("\x08");
        }
    }

    /// Redisplay the current command buffer
    fn redisplay_line(&self) {
        for i in 0..self.cmd_pos {
            crate::serial_print!("{}", self.cmd_buf[i] as char);
        }
    }

    /// Print command history
    fn print_history(&self) {
        if self.history_count == 0 {
            serial_println!("No commands in history.");
            return;
        }

        serial_println!("");
        let count = self.history_count.min(HISTORY_SIZE);

        for i in 0..count {
            // Calculate index from oldest to newest
            let idx = if self.history_count <= HISTORY_SIZE {
                i
            } else {
                (self.history_write + i) % HISTORY_SIZE
            };

            let entry = &self.history[idx];
            if entry.len > 0 {
                let cmd = core::str::from_utf8(&entry.data[..entry.len]).unwrap_or("<invalid>");
                serial_println!("  {:>3}  {}", i + 1, cmd);
            }
        }
        serial_println!("");
    }

    /// Execute the current command
    fn execute_command(&mut self) {
        // Get command string
        let cmd_str = match core::str::from_utf8(&self.cmd_buf[..self.cmd_pos]) {
            Ok(s) => s.trim(),
            Err(_) => {
                serial_println!("Invalid UTF-8 in command");
                return;
            }
        };

        if cmd_str.is_empty() {
            return;
        }

        // Parse command into arguments
        let mut args: [&str; MAX_ARGS] = [""; MAX_ARGS];
        let mut argc = 0;

        for arg in cmd_str.split_whitespace() {
            if argc < MAX_ARGS {
                args[argc] = arg;
                argc += 1;
            }
        }

        if argc == 0 {
            return;
        }

        // Execute command (case-insensitive)
        let cmd = args[0];

        if eq_ignore_case(cmd, "help") || cmd == "?" {
            commands::cmd_help(&args[1..argc]);
        } else if eq_ignore_case(cmd, "ver") || eq_ignore_case(cmd, "version") {
            commands::cmd_version();
        } else if eq_ignore_case(cmd, "echo") {
            commands::cmd_echo(&args[1..argc]);
        } else if eq_ignore_case(cmd, "clear") || eq_ignore_case(cmd, "cls") {
            commands::cmd_clear();
        } else if eq_ignore_case(cmd, "exit") || eq_ignore_case(cmd, "quit") {
            serial_println!("Goodbye!");
            self.running = false;
        // File system commands
        } else if eq_ignore_case(cmd, "dir") || eq_ignore_case(cmd, "ls") {
            commands::cmd_ls(&args[1..argc]);
        } else if eq_ignore_case(cmd, "cd") {
            commands::cmd_cd(&args[1..argc]);
        } else if eq_ignore_case(cmd, "pwd") {
            commands::cmd_pwd();
        } else if eq_ignore_case(cmd, "cat") || eq_ignore_case(cmd, "type") {
            commands::cmd_cat(&args[1..argc]);
        } else if eq_ignore_case(cmd, "mkdir") || eq_ignore_case(cmd, "md") {
            commands::cmd_mkdir(&args[1..argc]);
        } else if eq_ignore_case(cmd, "rmdir") || eq_ignore_case(cmd, "rd") {
            commands::cmd_rmdir(&args[1..argc]);
        } else if eq_ignore_case(cmd, "del") || eq_ignore_case(cmd, "rm") || eq_ignore_case(cmd, "erase") {
            commands::cmd_del(&args[1..argc]);
        } else if eq_ignore_case(cmd, "copy") || eq_ignore_case(cmd, "cp") {
            commands::cmd_copy(&args[1..argc]);
        } else if eq_ignore_case(cmd, "ren") || eq_ignore_case(cmd, "rename") || eq_ignore_case(cmd, "mv") {
            commands::cmd_rename(&args[1..argc]);
        } else if eq_ignore_case(cmd, "touch") {
            commands::cmd_touch(&args[1..argc]);
        // System commands
        } else if eq_ignore_case(cmd, "mem") || eq_ignore_case(cmd, "memory") {
            commands::cmd_mem();
        } else if eq_ignore_case(cmd, "time") {
            commands::cmd_time();
        } else if eq_ignore_case(cmd, "ps") || eq_ignore_case(cmd, "tasks") {
            commands::cmd_ps();
        } else if eq_ignore_case(cmd, "history") {
            self.print_history();
        } else if eq_ignore_case(cmd, "reboot") {
            commands::cmd_reboot();
        } else {
            serial_println!("'{}' is not recognized as a command.", args[0]);
            serial_println!("Type 'help' for available commands.");
        }
    }
}

/// Case-insensitive string comparison
fn eq_ignore_case(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (ca, cb) in a.bytes().zip(b.bytes()) {
        let ca_lower = if ca >= b'A' && ca <= b'Z' { ca + 32 } else { ca };
        let cb_lower = if cb >= b'A' && cb <= b'Z' { cb + 32 } else { cb };
        if ca_lower != cb_lower {
            return false;
        }
    }
    true
}

/// Get the current working directory as a string
pub fn get_current_dir() -> &'static str {
    unsafe {
        core::str::from_utf8_unchecked(&CURRENT_DIR[..CURRENT_DIR_LEN])
    }
}

/// Set the current working directory
pub fn set_current_dir(path: &str) {
    unsafe {
        let bytes = path.as_bytes();
        let len = bytes.len().min(CURRENT_DIR.len());
        CURRENT_DIR[..len].copy_from_slice(&bytes[..len]);
        CURRENT_DIR_LEN = len;
    }
}

/// Global shell instance
static mut SHELL: Shell = Shell::new();

/// Initialize and run the shell
pub fn run() {
    unsafe {
        SHELL.init();
        SHELL.run();
    }
}

/// Initialize the shell (for thread startup)
pub fn init() {
    serial_println!("[SHELL] Shell subsystem initialized");
}
