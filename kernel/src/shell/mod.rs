//! Simple Command Shell
//!
//! A basic interactive shell for Nostalgia OS that provides:
//! - Command line editing with backspace and cursor movement
//! - Left/right arrow keys for cursor navigation
//! - Home/End keys to jump to start/end of line
//! - Command history with up/down arrow navigation
//! - Tab completion for commands
//! - Output redirection with > and >>
//! - Built-in commands (help, echo, clear, ver, etc.)
//! - File system commands (ls, cd, cat, mkdir, rmdir, rm, type)
//! - System information commands (mem, time)

use crate::hal::keyboard;
use crate::serial_println;
use crate::fs;
use core::ptr::addr_of_mut;

mod commands;

/// Output redirection state
static mut REDIRECT_ACTIVE: bool = false;
static mut REDIRECT_APPEND: bool = false;
static mut REDIRECT_BUFFER: [u8; 8192] = [0u8; 8192];
static mut REDIRECT_LEN: usize = 0;
static mut REDIRECT_PATH: [u8; 128] = [0u8; 128];
static mut REDIRECT_PATH_LEN: usize = 0;

/// Write to redirect buffer or serial
pub fn shell_write(s: &str) {
    unsafe {
        let active = core::ptr::read_volatile(addr_of_mut!(REDIRECT_ACTIVE));
        if active {
            let buf = &mut *addr_of_mut!(REDIRECT_BUFFER);
            let len = &mut *addr_of_mut!(REDIRECT_LEN);
            for &b in s.as_bytes() {
                if *len < buf.len() {
                    buf[*len] = b;
                    *len += 1;
                }
            }
        } else {
            crate::serial_print!("{}", s);
        }
    }
}

/// Write line to redirect buffer or serial
pub fn shell_writeln(s: &str) {
    shell_write(s);
    shell_write("\r\n");
}

/// Start output redirection
fn start_redirect(path: &str, append: bool) {
    unsafe {
        core::ptr::write_volatile(addr_of_mut!(REDIRECT_ACTIVE), true);
        core::ptr::write_volatile(addr_of_mut!(REDIRECT_APPEND), append);
        core::ptr::write_volatile(addr_of_mut!(REDIRECT_LEN), 0);

        let rpath = &mut *addr_of_mut!(REDIRECT_PATH);
        let path_bytes = path.as_bytes();
        let len = path_bytes.len().min(rpath.len() - 1);
        rpath[..len].copy_from_slice(&path_bytes[..len]);
        core::ptr::write_volatile(addr_of_mut!(REDIRECT_PATH_LEN), len);
    }
}

/// End output redirection and write to file
fn end_redirect() -> Result<(), &'static str> {
    unsafe {
        let active = core::ptr::read_volatile(addr_of_mut!(REDIRECT_ACTIVE));
        if !active {
            return Ok(());
        }

        core::ptr::write_volatile(addr_of_mut!(REDIRECT_ACTIVE), false);

        let rpath = &*addr_of_mut!(REDIRECT_PATH);
        let rpath_len = core::ptr::read_volatile(addr_of_mut!(REDIRECT_PATH_LEN));
        let path = core::str::from_utf8(&rpath[..rpath_len])
            .map_err(|_| "Invalid path")?;

        let resolved = commands::resolve_path(path);

        let append_mode = core::ptr::read_volatile(addr_of_mut!(REDIRECT_APPEND));
        let buf = &mut *addr_of_mut!(REDIRECT_BUFFER);
        let redirect_len = &mut *addr_of_mut!(REDIRECT_LEN);

        if append_mode {
            // Append mode - read existing content first
            let mut existing: [u8; 8192] = [0u8; 8192];
            let existing_len = match fs::open(resolved, 0) {
                Ok(handle) => {
                    let len = fs::read(handle, &mut existing).unwrap_or(0);
                    let _ = fs::close(handle);
                    len
                }
                Err(fs::FsStatus::NotFound) => 0,
                Err(_) => 0,
            };

            // Combine existing + new
            let total_len = existing_len + *redirect_len;
            if total_len <= 8192 {
                // Shift buffer to make room for existing content
                for i in (0..*redirect_len).rev() {
                    if existing_len + i < 8192 {
                        buf[existing_len + i] = buf[i];
                    }
                }
                buf[..existing_len].copy_from_slice(&existing[..existing_len]);
                *redirect_len = total_len;
            }
        }

        // Create/overwrite file and write content
        match fs::create(resolved, 0) {
            Ok(handle) => {
                let result = fs::write(handle, &buf[..*redirect_len]);
                let _ = fs::close(handle);
                match result {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        crate::serial_println!("Error writing to file: {:?}", e);
                        Err("Write failed")
                    }
                }
            }
            Err(e) => {
                crate::serial_println!("Error creating file: {:?}", e);
                Err("Create failed")
            }
        }
    }
}

/// Maximum command line length
const MAX_CMD_LEN: usize = 256;

/// Maximum number of arguments
const MAX_ARGS: usize = 16;

/// Maximum number of commands in history
const HISTORY_SIZE: usize = 32;

/// List of available commands for tab completion
const COMMANDS: &[&str] = &[
    "cat", "cd", "clear", "cls", "copy", "cp",
    "del", "dir", "dump", "echo", "erase", "exit",
    "help", "history",
    "ldr", "ls",
    "md", "mem", "memory", "mkdir", "mv",
    "net",
    "pe", "ps", "pwd",
    "quit",
    "rd", "reboot", "ren", "rename", "resume", "rm", "rmdir",
    "sc", "services", "suspend",
    "tasks", "time", "touch", "type",
    "usertest",
    "ver", "version",
];

/// Current working directory
static mut CURRENT_DIR: [u8; 64] = [0u8; 64];
static mut CURRENT_DIR_LEN: usize = 0;

/// Get raw pointer to CURRENT_DIR
#[inline]
fn current_dir_ptr() -> *mut [u8; 64] {
    addr_of_mut!(CURRENT_DIR)
}

/// Get raw pointer to CURRENT_DIR_LEN
#[inline]
fn current_dir_len_ptr() -> *mut usize {
    addr_of_mut!(CURRENT_DIR_LEN)
}

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
    /// Length of command in buffer
    cmd_len: usize,
    /// Cursor position within the command (0 to cmd_len)
    cursor_pos: usize,
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
            cmd_len: 0,
            cursor_pos: 0,
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
            let dir = &mut *current_dir_ptr();
            dir[0] = b'C';
            dir[1] = b':';
            dir[2] = b'\\';
            *current_dir_len_ptr() = 3;
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
                if self.cmd_len > 0 {
                    // Add to history before executing
                    self.add_to_history();
                    self.execute_command();
                }
                // Reset state
                self.cmd_len = 0;
                self.cursor_pos = 0;
                self.cmd_buf = [0u8; MAX_CMD_LEN];
                self.history_nav = -1;
                if self.running {
                    self.print_prompt();
                }
            }

            // Backspace - delete character before cursor
            0x7F | 0x08 => {
                if self.cursor_pos > 0 {
                    // Shift everything after cursor left by one
                    for i in self.cursor_pos..self.cmd_len {
                        self.cmd_buf[i - 1] = self.cmd_buf[i];
                    }
                    self.cmd_len -= 1;
                    self.cursor_pos -= 1;
                    self.cmd_buf[self.cmd_len] = 0;

                    // Move cursor back, redraw rest of line, clear last char
                    crate::serial_print!("\x08");
                    for i in self.cursor_pos..self.cmd_len {
                        crate::serial_print!("{}", self.cmd_buf[i] as char);
                    }
                    crate::serial_print!(" ");
                    // Move cursor back to correct position
                    let chars_to_move_back = self.cmd_len - self.cursor_pos + 1;
                    for _ in 0..chars_to_move_back {
                        crate::serial_print!("\x08");
                    }
                }
            }

            // Delete key (Ctrl+D when line is non-empty, or DEL)
            0x04 if self.cmd_len > 0 => {
                self.delete_at_cursor();
            }

            // Ctrl+D on empty line - exit shell
            0x04 => {
                serial_println!("");
                serial_println!("Exiting shell...");
                self.running = false;
            }

            // Escape sequences (arrow keys, etc.)
            0x1B => {
                self.handle_escape_sequence();
            }

            // Tab - command completion
            b'\t' => {
                self.tab_complete();
            }

            // Regular printable characters
            0x20..=0x7E => {
                if self.cmd_len < MAX_CMD_LEN - 1 {
                    // Insert at cursor position
                    if self.cursor_pos < self.cmd_len {
                        // Shift characters right to make room
                        for i in (self.cursor_pos..self.cmd_len).rev() {
                            self.cmd_buf[i + 1] = self.cmd_buf[i];
                        }
                    }
                    self.cmd_buf[self.cursor_pos] = c;
                    self.cmd_len += 1;
                    self.cursor_pos += 1;

                    // Print the inserted char and rest of line
                    for i in (self.cursor_pos - 1)..self.cmd_len {
                        crate::serial_print!("{}", self.cmd_buf[i] as char);
                    }
                    // Move cursor back to correct position
                    let chars_to_move_back = self.cmd_len - self.cursor_pos;
                    for _ in 0..chars_to_move_back {
                        crate::serial_print!("\x08");
                    }
                }
            }

            // Ctrl+A - move to beginning of line
            0x01 => {
                self.cursor_home();
            }

            // Ctrl+E - move to end of line
            0x05 => {
                self.cursor_end();
            }

            // Ctrl+C - cancel current line
            0x03 => {
                serial_println!("^C");
                self.cmd_len = 0;
                self.cursor_pos = 0;
                self.cmd_buf = [0u8; MAX_CMD_LEN];
                self.history_nav = -1;
                self.print_prompt();
            }

            // Ctrl+U - clear line before cursor
            0x15 => {
                if self.cursor_pos > 0 {
                    // Move cursor to start
                    for _ in 0..self.cursor_pos {
                        crate::serial_print!("\x08");
                    }
                    // Shift remaining text to start
                    let remaining = self.cmd_len - self.cursor_pos;
                    for i in 0..remaining {
                        self.cmd_buf[i] = self.cmd_buf[self.cursor_pos + i];
                        crate::serial_print!("{}", self.cmd_buf[i] as char);
                    }
                    // Clear rest of line
                    for _ in 0..(self.cursor_pos) {
                        crate::serial_print!(" ");
                    }
                    // Move cursor back
                    for _ in 0..self.cursor_pos {
                        crate::serial_print!("\x08");
                    }
                    self.cmd_len = remaining;
                    self.cursor_pos = 0;
                }
            }

            // Ctrl+K - clear line after cursor
            0x0B => {
                if self.cursor_pos < self.cmd_len {
                    // Clear from cursor to end
                    for _ in self.cursor_pos..self.cmd_len {
                        crate::serial_print!(" ");
                    }
                    for _ in self.cursor_pos..self.cmd_len {
                        crate::serial_print!("\x08");
                    }
                    self.cmd_len = self.cursor_pos;
                }
            }

            _ => {
                // Ignore other control characters
            }
        }
    }

    /// Delete character at cursor position
    fn delete_at_cursor(&mut self) {
        if self.cursor_pos < self.cmd_len {
            // Shift everything after cursor left by one
            for i in self.cursor_pos..(self.cmd_len - 1) {
                self.cmd_buf[i] = self.cmd_buf[i + 1];
            }
            self.cmd_len -= 1;
            self.cmd_buf[self.cmd_len] = 0;

            // Redraw rest of line and clear last char
            for i in self.cursor_pos..self.cmd_len {
                crate::serial_print!("{}", self.cmd_buf[i] as char);
            }
            crate::serial_print!(" ");
            // Move cursor back to correct position
            let chars_to_move_back = self.cmd_len - self.cursor_pos + 1;
            for _ in 0..chars_to_move_back {
                crate::serial_print!("\x08");
            }
        }
    }

    /// Move cursor to beginning of line
    fn cursor_home(&mut self) {
        while self.cursor_pos > 0 {
            crate::serial_print!("\x08");
            self.cursor_pos -= 1;
        }
    }

    /// Move cursor to end of line
    fn cursor_end(&mut self) {
        while self.cursor_pos < self.cmd_len {
            crate::serial_print!("{}", self.cmd_buf[self.cursor_pos] as char);
            self.cursor_pos += 1;
        }
    }

    /// Move cursor left one character
    fn cursor_left(&mut self) {
        if self.cursor_pos > 0 {
            crate::serial_print!("\x08");
            self.cursor_pos -= 1;
        }
    }

    /// Move cursor right one character
    fn cursor_right(&mut self) {
        if self.cursor_pos < self.cmd_len {
            crate::serial_print!("{}", self.cmd_buf[self.cursor_pos] as char);
            self.cursor_pos += 1;
        }
    }

    /// Handle tab completion for commands and filenames
    fn tab_complete(&mut self) {
        // Find the last space to determine if we're completing command or filename
        let mut last_space: Option<usize> = None;
        for i in 0..self.cmd_len {
            if self.cmd_buf[i] == b' ' {
                last_space = Some(i);
            }
        }

        match last_space {
            None => self.complete_command(),
            Some(space_pos) => self.complete_filename(space_pos + 1),
        }
    }

    /// Complete command name (first word)
    fn complete_command(&mut self) {
        let prefix_len = self.cmd_len;
        if prefix_len == 0 {
            // Show all commands if nothing typed
            serial_println!("");
            let mut col = 0;
            for cmd in COMMANDS.iter() {
                crate::serial_print!("{:<12}", cmd);
                col += 1;
                if col >= 6 {
                    serial_println!("");
                    col = 0;
                }
            }
            if col > 0 {
                serial_println!("");
            }
            self.print_prompt();
            return;
        }

        // Find matching commands
        let mut matches: [&str; 16] = [""; 16];
        let mut match_count = 0;

        for &cmd in COMMANDS.iter() {
            if cmd.len() >= prefix_len && starts_with_ignore_case(cmd, &self.cmd_buf[..prefix_len])
                && match_count < 16 {
                    matches[match_count] = cmd;
                    match_count += 1;
                }
        }

        if match_count == 0 {
        } else if match_count == 1 {
            // Exactly one match - complete it
            let completion = matches[0];
            self.clear_line();
            let comp_bytes = completion.as_bytes();
            self.cmd_buf[..comp_bytes.len()].copy_from_slice(comp_bytes);
            self.cmd_len = comp_bytes.len();

            // Add a space after the command
            if self.cmd_len < MAX_CMD_LEN - 1 {
                self.cmd_buf[self.cmd_len] = b' ';
                self.cmd_len += 1;
            }
            self.cursor_pos = self.cmd_len;
            self.redisplay_line();
        } else {
            // Multiple matches - find common prefix and show options
            let common_len = find_common_prefix(&matches[..match_count]);

            if common_len > prefix_len {
                let first_match = matches[0].as_bytes();
                self.clear_line();
                self.cmd_buf[..common_len].copy_from_slice(&first_match[..common_len]);
                self.cmd_len = common_len;
                self.cursor_pos = self.cmd_len;
                self.redisplay_line();
            } else {
                serial_println!("");
                let mut col = 0;
                for i in 0..match_count {
                    crate::serial_print!("{:<12}", matches[i]);
                    col += 1;
                    if col >= 6 {
                        serial_println!("");
                        col = 0;
                    }
                }
                if col > 0 {
                    serial_println!("");
                }
                self.print_prompt();
                self.redisplay_line();
            }
        }
    }

    /// Complete filename (after command)
    fn complete_filename(&mut self, word_start: usize) {
        // Get the current word being typed
        let word_len = self.cmd_len - word_start;

        // Extract the word into a buffer
        let mut word_buf: [u8; 128] = [0u8; 128];
        let word_len = word_len.min(127);
        word_buf[..word_len].copy_from_slice(&self.cmd_buf[word_start..word_start + word_len]);

        // Find the last path separator to split directory and filename prefix
        let mut last_sep: Option<usize> = None;
        for i in 0..word_len {
            if word_buf[i] == b'\\' || word_buf[i] == b'/' {
                last_sep = Some(i);
            }
        }

        // Determine directory to search and filename prefix
        let (dir_path, prefix_start, prefix_len) = match last_sep {
            Some(sep_pos) => {
                // Has path separator - directory is before it, prefix after
                let mut dir_buf: [u8; 128] = [0u8; 128];

                // Build full directory path
                if word_buf[0] == b'\\' || word_buf[0] == b'/' ||
                   (word_len >= 2 && word_buf[1] == b':') {
                    // Absolute path
                    dir_buf[..sep_pos + 1].copy_from_slice(&word_buf[..sep_pos + 1]);
                } else {
                    // Relative path - prepend current directory
                    let cur_dir = get_current_dir();
                    let cur_bytes = cur_dir.as_bytes();
                    let mut pos = cur_bytes.len();
                    dir_buf[..pos].copy_from_slice(cur_bytes);
                    if pos > 0 && dir_buf[pos - 1] != b'\\' {
                        dir_buf[pos] = b'\\';
                        pos += 1;
                    }
                    dir_buf[pos..pos + sep_pos + 1].copy_from_slice(&word_buf[..sep_pos + 1]);
                }

                (dir_buf, word_start + sep_pos + 1, word_len - sep_pos - 1)
            }
            None => {
                // No path separator - use current directory
                let cur_dir = get_current_dir();
                let cur_bytes = cur_dir.as_bytes();
                let mut dir_buf: [u8; 128] = [0u8; 128];
                dir_buf[..cur_bytes.len()].copy_from_slice(cur_bytes);
                (dir_buf, word_start, word_len)
            }
        };

        // Get prefix to match
        let prefix = &self.cmd_buf[prefix_start..prefix_start + prefix_len];

        // Convert dir_path to string for fs::readdir
        let dir_str = {
            let mut len = 0;
            while len < dir_path.len() && dir_path[len] != 0 {
                len += 1;
            }
            core::str::from_utf8(&dir_path[..len]).unwrap_or("")
        };

        // Collect matching files
        const MAX_FILE_MATCHES: usize = 16;
        let mut file_matches: [[u8; 64]; MAX_FILE_MATCHES] = [[0u8; 64]; MAX_FILE_MATCHES];
        let mut file_lens: [usize; MAX_FILE_MATCHES] = [0; MAX_FILE_MATCHES];
        let mut is_dir: [bool; MAX_FILE_MATCHES] = [false; MAX_FILE_MATCHES];
        let mut match_count = 0;

        let mut offset = 0u32;
        loop {
            match fs::readdir(dir_str, offset) {
                Ok(entry) => {
                    let name = entry.name_str();
                    let name_bytes = name.as_bytes();

                    // Skip . and ..
                    if name == "." || name == ".." {
                        offset = entry.next_offset;
                        continue;
                    }

                    // Check if name starts with prefix (case-insensitive)
                    if (prefix_len == 0 || starts_with_ignore_case(name, prefix))
                        && match_count < MAX_FILE_MATCHES && name_bytes.len() < 64 {
                            file_matches[match_count][..name_bytes.len()].copy_from_slice(name_bytes);
                            file_lens[match_count] = name_bytes.len();
                            is_dir[match_count] = entry.file_type == fs::FileType::Directory;
                            match_count += 1;
                        }

                    offset = entry.next_offset;
                    if offset == 0 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        if match_count == 0 {
        } else if match_count == 1 {
            // Single match - complete it
            let name_len = file_lens[0];
            let is_directory = is_dir[0];

            // Calculate new command length
            let new_len = prefix_start + name_len + if is_directory { 1 } else { 1 };
            if new_len >= MAX_CMD_LEN {
                return;
            }

            // Replace prefix with full filename
            self.cmd_buf[prefix_start..prefix_start + name_len].copy_from_slice(&file_matches[0][..name_len]);
            self.cmd_len = prefix_start + name_len;

            // Add trailing backslash for directories or space for files
            if is_directory {
                self.cmd_buf[self.cmd_len] = b'\\';
            } else {
                self.cmd_buf[self.cmd_len] = b' ';
            }
            self.cmd_len += 1;

            self.cursor_pos = self.cmd_len;
            self.clear_line();
            self.redisplay_line();
        } else {
            // Multiple matches - find common prefix
            let common_len = find_common_prefix_bytes(&file_matches, &file_lens, match_count);

            if common_len > prefix_len {
                // Complete common prefix
                let new_len = prefix_start + common_len;
                if new_len < MAX_CMD_LEN {
                    self.cmd_buf[prefix_start..prefix_start + common_len]
                        .copy_from_slice(&file_matches[0][..common_len]);
                    self.cmd_len = new_len;
                    self.cursor_pos = self.cmd_len;
                    self.clear_line();
                    self.redisplay_line();
                }
            } else {
                // Show all matches
                serial_println!("");
                let mut col = 0;
                for i in 0..match_count {
                    let name = core::str::from_utf8(&file_matches[i][..file_lens[i]]).unwrap_or("?");
                    if is_dir[i] {
                        crate::serial_print!("{:<12}/", name);
                    } else {
                        crate::serial_print!("{:<13}", name);
                    }
                    col += 1;
                    if col >= 5 {
                        serial_println!("");
                        col = 0;
                    }
                }
                if col > 0 {
                    serial_println!("");
                }
                self.print_prompt();
                self.redisplay_line();
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
                        b'C' => self.cursor_right(), // Right arrow
                        b'D' => self.cursor_left(),  // Left arrow
                        b'H' => self.cursor_home(),  // Home
                        b'F' => self.cursor_end(),   // End
                        b'3' => {
                            // Delete key: ESC [ 3 ~
                            if let Some(c3) = keyboard::try_read_char() {
                                if c3 == b'~' {
                                    self.delete_at_cursor();
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Add current command to history
    fn add_to_history(&mut self) {
        if self.cmd_len == 0 {
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
            if last.len == self.cmd_len {
                let mut same = true;
                for i in 0..self.cmd_len {
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
        entry.data[..self.cmd_len].copy_from_slice(&self.cmd_buf[..self.cmd_len]);
        entry.len = self.cmd_len;

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
            self.saved_line[..self.cmd_len].copy_from_slice(&self.cmd_buf[..self.cmd_len]);
            self.saved_len = self.cmd_len;
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
            self.cmd_len = self.saved_len;
            self.cursor_pos = self.cmd_len;
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

        // Copy entry data before borrowing self mutably
        let entry_len = self.history[idx].len;
        let mut entry_data = [0u8; MAX_CMD_LEN];
        entry_data[..entry_len].copy_from_slice(&self.history[idx].data[..entry_len]);

        // Clear current line and display history entry
        self.clear_line();
        self.cmd_buf[..entry_len].copy_from_slice(&entry_data[..entry_len]);
        self.cmd_len = entry_len;
        self.cursor_pos = self.cmd_len;
        self.redisplay_line();
    }

    /// Clear the current line on screen
    fn clear_line(&mut self) {
        // Move cursor back to start of input
        for _ in 0..self.cursor_pos {
            crate::serial_print!("\x08");
        }
        // Clear the entire line
        for _ in 0..self.cmd_len {
            crate::serial_print!(" ");
        }
        // Move back to start
        for _ in 0..self.cmd_len {
            crate::serial_print!("\x08");
        }
        self.cursor_pos = 0;
    }

    /// Redisplay the current command buffer
    fn redisplay_line(&self) {
        for i in 0..self.cmd_len {
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
        let cmd_str = match core::str::from_utf8(&self.cmd_buf[..self.cmd_len]) {
            Ok(s) => s.trim(),
            Err(_) => {
                serial_println!("Invalid UTF-8 in command");
                return;
            }
        };

        if cmd_str.is_empty() {
            return;
        }

        // Check for output redirection (>> or >)
        let (cmd_part, redirect_file, append_mode) = parse_redirect(cmd_str);

        // Parse command into arguments
        let mut args: [&str; MAX_ARGS] = [""; MAX_ARGS];
        let mut argc = 0;

        for arg in cmd_part.split_whitespace() {
            if argc < MAX_ARGS {
                args[argc] = arg;
                argc += 1;
            }
        }

        if argc == 0 {
            return;
        }

        // Set up redirection if needed
        if let Some(file) = redirect_file {
            start_redirect(file, append_mode);
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
        } else if eq_ignore_case(cmd, "suspend") {
            commands::cmd_suspend(&args[1..argc]);
        } else if eq_ignore_case(cmd, "resume") {
            commands::cmd_resume(&args[1..argc]);
        // Hardware info commands
        } else if eq_ignore_case(cmd, "cpuinfo") || eq_ignore_case(cmd, "sysinfo") {
            commands::cmd_cpuinfo();
        } else if eq_ignore_case(cmd, "power") {
            commands::cmd_power(&args[1..argc]);
        } else if eq_ignore_case(cmd, "shutdown") {
            commands::cmd_shutdown();
        } else if eq_ignore_case(cmd, "veh") {
            commands::cmd_veh(&args[1..argc]);
        } else if eq_ignore_case(cmd, "seh") {
            commands::cmd_seh(&args[1..argc]);
        // Service commands
        } else if eq_ignore_case(cmd, "services") {
            commands::cmd_services(&args[1..argc]);
        } else if eq_ignore_case(cmd, "sc") {
            commands::cmd_sc(&args[1..argc]);
        } else if eq_ignore_case(cmd, "net") {
            commands::cmd_net(&args[1..argc]);
        // PE loader commands
        } else if eq_ignore_case(cmd, "pe") {
            commands::cmd_pe(&args[1..argc]);
        } else if eq_ignore_case(cmd, "dump") {
            commands::cmd_dump(&args[1..argc]);
        } else if eq_ignore_case(cmd, "ldr") {
            commands::cmd_ldr(&args[1..argc]);
        // RTL (Runtime Library)
        } else if eq_ignore_case(cmd, "rtl") {
            commands::cmd_rtl(&args[1..argc]);
        // Object Manager
        } else if eq_ignore_case(cmd, "ob") {
            commands::cmd_ob(&args[1..argc]);
        // Executive
        } else if eq_ignore_case(cmd, "ex") {
            commands::cmd_ex(&args[1..argc]);
        // Security
        } else if eq_ignore_case(cmd, "se") {
            commands::cmd_se(&args[1..argc]);
        // Kernel Executive
        } else if eq_ignore_case(cmd, "ke") {
            commands::cmd_ke(&args[1..argc]);
        // Memory Manager
        } else if eq_ignore_case(cmd, "mm") {
            commands::cmd_mm(&args[1..argc]);
        // I/O Manager
        } else if eq_ignore_case(cmd, "io") {
            commands::cmd_io(&args[1..argc]);
        // Hardware Abstraction Layer
        } else if eq_ignore_case(cmd, "hal") {
            commands::cmd_hal(&args[1..argc]);
        // User-mode test
        } else if eq_ignore_case(cmd, "usertest") {
            commands::cmd_usertest(&args[1..argc]);
        } else {
            serial_println!("'{}' is not recognized as a command.", args[0]);
            serial_println!("Type 'help' for available commands.");
        }

        // End redirection and write to file
        if redirect_file.is_some() {
            let _ = end_redirect();
        }
    }
}

/// Parse command string for output redirection
/// Returns: (command_part, optional_redirect_file, is_append_mode)
fn parse_redirect(cmd: &str) -> (&str, Option<&str>, bool) {
    // Look for >> first (append), then > (overwrite)
    if let Some(pos) = cmd.find(">>") {
        let cmd_part = cmd[..pos].trim();
        let file_part = cmd[pos + 2..].trim();
        if !file_part.is_empty() {
            return (cmd_part, Some(file_part), true);
        }
    } else if let Some(pos) = cmd.find('>') {
        let cmd_part = cmd[..pos].trim();
        let file_part = cmd[pos + 1..].trim();
        if !file_part.is_empty() {
            return (cmd_part, Some(file_part), false);
        }
    }
    (cmd, None, false)
}

/// Case-insensitive string comparison
fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.as_bytes().eq_ignore_ascii_case(b.as_bytes())
}

/// Check if string starts with prefix (case-insensitive)
fn starts_with_ignore_case(s: &str, prefix: &[u8]) -> bool {
    let s_bytes = s.as_bytes();
    if s_bytes.len() < prefix.len() {
        return false;
    }
    s_bytes[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Find common prefix length among matching commands
fn find_common_prefix(matches: &[&str]) -> usize {
    if matches.is_empty() {
        return 0;
    }
    if matches.len() == 1 {
        return matches[0].len();
    }

    let first = matches[0].as_bytes();
    let mut common_len = first.len();

    for &m in &matches[1..] {
        let m_bytes = m.as_bytes();
        let mut i = 0;
        while i < common_len && i < m_bytes.len() {
            if first[i].to_ascii_lowercase() != m_bytes[i].to_ascii_lowercase() {
                break;
            }
            i += 1;
        }
        common_len = common_len.min(i);
    }

    common_len
}

/// Find common prefix length among matching filenames (byte arrays)
fn find_common_prefix_bytes(matches: &[[u8; 64]; 16], lens: &[usize; 16], count: usize) -> usize {
    if count == 0 {
        return 0;
    }
    if count == 1 {
        return lens[0];
    }

    let first = &matches[0];
    let mut common_len = lens[0];

    for i in 1..count {
        let m = &matches[i];
        let m_len = lens[i];
        let mut j = 0;
        while j < common_len && j < m_len {
            if first[j].to_ascii_lowercase() != m[j].to_ascii_lowercase() {
                break;
            }
            j += 1;
        }
        common_len = common_len.min(j);
    }

    common_len
}

/// Get the current working directory as a string
pub fn get_current_dir() -> &'static str {
    unsafe {
        let dir = &*current_dir_ptr();
        let len = *current_dir_len_ptr();
        core::str::from_utf8_unchecked(&dir[..len])
    }
}

/// Set the current working directory
pub fn set_current_dir(path: &str) {
    unsafe {
        let dir = &mut *current_dir_ptr();
        let bytes = path.as_bytes();
        let len = bytes.len().min(dir.len());
        dir[..len].copy_from_slice(&bytes[..len]);
        *current_dir_len_ptr() = len;
    }
}

/// Global shell instance
static mut SHELL: Shell = Shell::new();

/// Initialize and run the shell
pub fn run() {
    unsafe {
        let shell = &mut *addr_of_mut!(SHELL);
        shell.init();
        shell.run();
    }
}

/// Initialize the shell (for thread startup)
pub fn init() {
    serial_println!("[SHELL] Shell subsystem initialized");
}
