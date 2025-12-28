//! Simple Command Shell
//!
//! A basic interactive shell for Nostalgia OS that provides:
//! - Command line editing with backspace
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

/// Current working directory
static mut CURRENT_DIR: [u8; 64] = [0u8; 64];
static mut CURRENT_DIR_LEN: usize = 0;

/// Shell state
pub struct Shell {
    /// Command line buffer
    cmd_buf: [u8; MAX_CMD_LEN],
    /// Current position in command buffer
    cmd_pos: usize,
    /// Is the shell running?
    running: bool,
}

impl Shell {
    /// Create a new shell instance
    pub const fn new() -> Self {
        Self {
            cmd_buf: [0u8; MAX_CMD_LEN],
            cmd_pos: 0,
            running: true,
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
                    self.execute_command();
                }
                self.cmd_pos = 0;
                self.cmd_buf = [0u8; MAX_CMD_LEN];
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
                // Read the escape sequence but ignore it for now
                let _ = keyboard::try_read_char();
                let _ = keyboard::try_read_char();
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
