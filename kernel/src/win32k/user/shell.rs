//! Command Shell Implementation
//!
//! Implements CMD.EXE-style command interpreter with real file system access.

use crate::ke::SpinLock;
use super::super::{HWND, Rect, ColorRef};
use super::super::gdi::{dc, surface};
use super::window;
use crate::io::{vfs_read_directory, vfs_create_directory, vfs_create_file, VfsEntry};

// ============================================================================
// Constants
// ============================================================================

/// Console width in characters
pub const COLS: usize = 80;
/// Console height in characters
pub const ROWS: usize = 25;
/// Character width in pixels
const CHAR_W: i32 = 8;
/// Character height in pixels
const CHAR_H: i32 = 14;
/// Max command length
const MAX_CMD: usize = 256;
/// Max path length
const MAX_PATH: usize = 128;
/// Max shells
const MAX_SHELLS: usize = 4;

// ============================================================================
// Shell State
// ============================================================================

/// Shell instance
pub struct Shell {
    /// Text buffer [row][col]
    buf: [[u8; COLS]; ROWS],
    /// Cursor position
    cx: usize,
    cy: usize,
    /// Current directory
    cwd: [u8; MAX_PATH],
    cwd_len: usize,
    /// Command line buffer
    cmd: [u8; MAX_CMD],
    cmd_len: usize,
    /// Window handle
    hwnd: HWND,
    /// Active flag
    active: bool,
}

impl Shell {
    const fn new() -> Self {
        Self {
            buf: [[b' '; COLS]; ROWS],
            cx: 0,
            cy: 0,
            cwd: [0; MAX_PATH],
            cwd_len: 0,
            cmd: [0; MAX_CMD],
            cmd_len: 0,
            hwnd: HWND::NULL,
            active: false,
        }
    }

    fn init(&mut self, hwnd: HWND) {
        self.hwnd = hwnd;
        self.active = true;
        self.cx = 0;
        self.cy = 0;
        self.cmd_len = 0;

        // Set default directory
        let cwd = b"C:\\";
        self.cwd_len = cwd.len();
        self.cwd[..self.cwd_len].copy_from_slice(cwd);

        // Clear buffer
        for row in 0..ROWS {
            for col in 0..COLS {
                self.buf[row][col] = b' ';
            }
        }

        // Print banner
        self.puts("Microsoft(R) Windows DOS\r\n");
        self.puts("(C) Copyright 1985-2003 Microsoft Corp.\r\n\r\n");
        self.prompt();
    }

    fn cwd_str(&self) -> &str {
        core::str::from_utf8(&self.cwd[..self.cwd_len]).unwrap_or("C:\\")
    }

    fn prompt(&mut self) {
        // Copy cwd to avoid borrow conflict
        let mut cwd_buf = [0u8; MAX_PATH];
        let cwd_len = self.cwd_len;
        cwd_buf[..cwd_len].copy_from_slice(&self.cwd[..cwd_len]);
        let cwd = core::str::from_utf8(&cwd_buf[..cwd_len]).unwrap_or("C:\\");
        self.puts(cwd);
        self.putc(b'>');
    }

    fn puts(&mut self, s: &str) {
        for b in s.bytes() {
            self.putc(b);
        }
    }

    fn putc(&mut self, c: u8) {
        match c {
            b'\r' => self.cx = 0,
            b'\n' => {
                self.cx = 0;
                self.cy += 1;
                if self.cy >= ROWS {
                    self.scroll();
                    self.cy = ROWS - 1;
                }
            }
            b'\x08' => {
                if self.cx > 0 {
                    self.cx -= 1;
                    self.buf[self.cy][self.cx] = b' ';
                }
            }
            _ => {
                if self.cx < COLS {
                    self.buf[self.cy][self.cx] = c;
                    self.cx += 1;
                }
                if self.cx >= COLS {
                    self.cx = 0;
                    self.cy += 1;
                    if self.cy >= ROWS {
                        self.scroll();
                        self.cy = ROWS - 1;
                    }
                }
            }
        }
    }

    fn scroll(&mut self) {
        for y in 0..(ROWS - 1) {
            self.buf[y] = self.buf[y + 1];
        }
        for x in 0..COLS {
            self.buf[ROWS - 1][x] = b' ';
        }
    }

    /// Handle keyboard input
    pub fn key(&mut self, scan: u8, ch: char) {
        match scan {
            0x1C => {
                // Enter
                self.puts("\r\n");
                if self.cmd_len > 0 {
                    self.exec();
                }
                self.cmd_len = 0;
                self.prompt();
            }
            0x0E => {
                // Backspace
                if self.cmd_len > 0 {
                    self.cmd_len -= 1;
                    self.putc(b'\x08');
                    self.putc(b' ');
                    self.putc(b'\x08');
                }
            }
            _ => {
                if ch.is_ascii() && ch >= ' ' && self.cmd_len < MAX_CMD - 1 {
                    let b = ch as u8;
                    self.cmd[self.cmd_len] = b;
                    self.cmd_len += 1;
                    self.putc(b);
                }
            }
        }
    }

    fn exec(&mut self) {
        // Copy command to local buffer to avoid borrow issues
        let mut cmd_buf = [0u8; MAX_CMD];
        let cmd_len = self.cmd_len;
        cmd_buf[..cmd_len].copy_from_slice(&self.cmd[..cmd_len]);

        let cmd_str = core::str::from_utf8(&cmd_buf[..cmd_len]).unwrap_or("");
        let cmd_str = cmd_str.trim();

        if cmd_str.is_empty() {
            return;
        }

        // Split command and args
        let (cmd, args) = match cmd_str.find(' ') {
            Some(i) => (&cmd_str[..i], cmd_str[i + 1..].trim()),
            None => (cmd_str, ""),
        };

        // Copy cmd and args to owned strings to avoid lifetime issues
        let mut cmd_lower = [0u8; 32];
        let cmd_lower_len = cmd.len().min(31);
        for (i, b) in cmd.bytes().take(cmd_lower_len).enumerate() {
            cmd_lower[i] = b.to_ascii_lowercase();
        }
        let cmd_lower_str = core::str::from_utf8(&cmd_lower[..cmd_lower_len]).unwrap_or("");

        match cmd_lower_str {
            "dir" => self.cmd_dir(args),
            "cd" | "chdir" => self.cmd_cd(args),
            "cls" => self.cmd_cls(),
            "type" => self.cmd_type(args),
            "echo" => self.cmd_echo(args),
            "ver" => self.cmd_ver(),
            "help" | "?" => self.cmd_help(),
            "exit" => self.cmd_exit(),
            "date" => self.cmd_date(),
            "time" => self.cmd_time(),
            "mkdir" | "md" => self.cmd_mkdir(args),
            "vol" => self.cmd_vol(),
            "copy" => self.cmd_copy(args),
            "del" | "erase" => self.cmd_del(args),
            "ren" | "rename" => self.cmd_ren(args),
            "path" => self.cmd_path(args),
            "set" => self.cmd_set(args),
            _ => {
                self.puts("'");
                self.puts(cmd);
                self.puts("' is not recognized as an internal or external command,\r\n");
                self.puts("operable program or batch file.\r\n");
            }
        }
    }

    fn cmd_dir(&mut self, args: &str) {
        // Get path (use CWD if not specified) - copy to avoid borrow issues
        let mut path_buf = [0u8; MAX_PATH];
        let path_len = if args.is_empty() {
            let cwd = self.cwd_str();
            let len = cwd.len().min(MAX_PATH);
            path_buf[..len].copy_from_slice(&cwd.as_bytes()[..len]);
            len
        } else {
            let len = args.len().min(MAX_PATH);
            path_buf[..len].copy_from_slice(&args.as_bytes()[..len]);
            len
        };
        let path = core::str::from_utf8(&path_buf[..path_len]).unwrap_or("");

        // Convert to VFS format
        let vfs_path = path.replace('\\', "/");

        self.puts(" Volume in drive C has no label.\r\n");
        self.puts(" Volume Serial Number is 1234-5678\r\n\r\n");
        self.puts(" Directory of ");
        self.puts(path);
        self.puts("\r\n\r\n");

        let mut entries = [VfsEntry::empty(); 32];
        let count = vfs_read_directory(&vfs_path, &mut entries);

        let mut files = 0u32;
        let mut dirs = 0u32;
        let mut bytes = 0u64;

        for i in 0..count {
            let e = &entries[i];
            let name = core::str::from_utf8(&e.name[..e.name_len]).unwrap_or("");

            self.puts("01/01/2024  12:00 ");

            if e.is_directory {
                self.puts("    <DIR>          ");
                dirs += 1;
            } else {
                // Right-align file size
                self.put_size(e.size);
                self.putc(b' ');
                files += 1;
                bytes += e.size;
            }

            self.puts(name);
            self.puts("\r\n");
        }

        // Summary
        self.puts("               ");
        self.put_num(files);
        self.puts(" File(s)  ");
        self.put_num(bytes as u32);
        self.puts(" bytes\r\n");
        self.puts("               ");
        self.put_num(dirs);
        self.puts(" Dir(s)\r\n");
    }

    fn cmd_cd(&mut self, args: &str) {
        if args.is_empty() {
            // Copy cwd to avoid borrow conflict
            let mut cwd_buf = [0u8; MAX_PATH];
            let cwd_len = self.cwd_len;
            cwd_buf[..cwd_len].copy_from_slice(&self.cwd[..cwd_len]);
            let cwd = core::str::from_utf8(&cwd_buf[..cwd_len]).unwrap_or("C:\\");
            self.puts(cwd);
            self.puts("\r\n");
            return;
        }

        let new_path = if args.starts_with('\\') || args.starts_with('/') ||
                          (args.len() >= 2 && args.as_bytes()[1] == b':') {
            args.to_string()
        } else if args == ".." {
            let cwd = self.cwd_str();
            if let Some(pos) = cwd.rfind(|c| c == '\\' || c == '/') {
                if pos > 2 {
                    cwd[..pos].to_string()
                } else {
                    cwd[..3].to_string()
                }
            } else {
                cwd.to_string()
            }
        } else {
            let cwd = self.cwd_str();
            let mut p = cwd.to_string();
            if !p.ends_with('\\') && !p.ends_with('/') {
                p.push('\\');
            }
            p.push_str(args);
            p
        };

        // Update CWD
        let bytes = new_path.as_bytes();
        let len = bytes.len().min(MAX_PATH - 1);
        self.cwd[..len].copy_from_slice(&bytes[..len]);
        self.cwd_len = len;
    }

    fn cmd_cls(&mut self) {
        for y in 0..ROWS {
            for x in 0..COLS {
                self.buf[y][x] = b' ';
            }
        }
        self.cx = 0;
        self.cy = 0;
    }

    fn cmd_type(&mut self, args: &str) {
        if args.is_empty() {
            self.puts("The syntax of the command is incorrect.\r\n");
            return;
        }
        self.puts("[File contents would be shown here]\r\n");
    }

    fn cmd_echo(&mut self, args: &str) {
        if args.is_empty() || args.eq_ignore_ascii_case("on") || args.eq_ignore_ascii_case("off") {
            self.puts("ECHO is on.\r\n");
        } else {
            self.puts(args);
            self.puts("\r\n");
        }
    }

    fn cmd_ver(&mut self) {
        self.puts("\r\nMicrosoft Windows [Version 5.2.3790]\r\n");
    }

    fn cmd_help(&mut self) {
        self.puts("CD       Change directory\r\n");
        self.puts("CLS      Clear screen\r\n");
        self.puts("COPY     Copy files\r\n");
        self.puts("DATE     Display date\r\n");
        self.puts("DEL      Delete files\r\n");
        self.puts("DIR      List directory\r\n");
        self.puts("ECHO     Display message\r\n");
        self.puts("EXIT     Exit shell\r\n");
        self.puts("HELP     Show this help\r\n");
        self.puts("MD       Create directory\r\n");
        self.puts("PATH     Display/set path\r\n");
        self.puts("REN      Rename file\r\n");
        self.puts("SET      Display/set variables\r\n");
        self.puts("TIME     Display time\r\n");
        self.puts("TYPE     Display file contents\r\n");
        self.puts("VER      Display version\r\n");
        self.puts("VOL      Display volume label\r\n");
    }

    fn cmd_exit(&mut self) {
        if self.hwnd.is_valid() {
            window::destroy_window(self.hwnd);
        }
        self.active = false;
    }

    fn cmd_date(&mut self) {
        let dt = crate::hal::rtc::get_datetime();
        self.puts("The current date is: ");
        // Day of week (simplified - not calculated)
        self.puts("    ");
        // MM/DD/YYYY format
        if dt.month < 10 { self.putc(b'0'); }
        self.put_num(dt.month as u32);
        self.putc(b'/');
        if dt.day < 10 { self.putc(b'0'); }
        self.put_num(dt.day as u32);
        self.putc(b'/');
        self.put_num(dt.year as u32);
        self.puts("\r\n");
    }

    fn cmd_time(&mut self) {
        let dt = crate::hal::rtc::get_datetime();
        self.puts("The current time is: ");
        if dt.hour < 10 { self.putc(b'0'); }
        self.put_num(dt.hour as u32);
        self.putc(b':');
        if dt.minute < 10 { self.putc(b'0'); }
        self.put_num(dt.minute as u32);
        self.putc(b':');
        if dt.second < 10 { self.putc(b'0'); }
        self.put_num(dt.second as u32);
        self.puts("\r\n");
    }

    fn cmd_mkdir(&mut self, args: &str) {
        if args.is_empty() {
            self.puts("The syntax of the command is incorrect.\r\n");
            return;
        }

        let full = if args.starts_with('\\') || args.starts_with('/') ||
                      (args.len() >= 2 && args.as_bytes()[1] == b':') {
            args.to_string()
        } else {
            let cwd = self.cwd_str();
            let mut p = cwd.to_string();
            if !p.ends_with('\\') && !p.ends_with('/') {
                p.push('/');
            }
            p.push_str(args);
            p
        };

        let vfs = full.replace('\\', "/");
        crate::serial_println!("[SHELL] mkdir: vfs path = '{}'", vfs);
        if let Some(pos) = vfs.rfind('/') {
            let parent = &vfs[..pos];
            let name = &vfs[pos + 1..];
            crate::serial_println!("[SHELL] mkdir: parent='{}' name='{}'", parent, name);
            if vfs_create_directory(parent, name) {
                // Success - no output
                crate::serial_println!("[SHELL] mkdir: success");
            } else {
                self.puts("A subdirectory or file ");
                self.puts(args);
                self.puts(" already exists.\r\n");
                crate::serial_println!("[SHELL] mkdir: failed");
            }
        } else {
            crate::serial_println!("[SHELL] mkdir: no slash found in path");
            self.puts("The syntax of the command is incorrect.\r\n");
        }
    }

    fn cmd_vol(&mut self) {
        self.puts(" Volume in drive C has no label.\r\n");
        self.puts(" Volume Serial Number is 1234-5678\r\n");
    }

    fn cmd_copy(&mut self, args: &str) {
        if args.is_empty() {
            self.puts("The syntax of the command is incorrect.\r\n");
            return;
        }
        self.puts("        0 file(s) copied.\r\n");
    }

    fn cmd_del(&mut self, args: &str) {
        if args.is_empty() {
            self.puts("The syntax of the command is incorrect.\r\n");
            return;
        }
        self.puts("Could Not Find ");
        self.puts(args);
        self.puts("\r\n");
    }

    fn cmd_ren(&mut self, args: &str) {
        if args.is_empty() {
            self.puts("The syntax of the command is incorrect.\r\n");
            return;
        }
        self.puts("The syntax of the command is incorrect.\r\n");
    }

    fn cmd_path(&mut self, _args: &str) {
        self.puts("PATH=C:\\Windows;C:\\Windows\\System32\r\n");
    }

    fn cmd_set(&mut self, args: &str) {
        if args.is_empty() {
            self.puts("COMSPEC=C:\\Windows\\System32\\cmd.exe\r\n");
            self.puts("PATH=C:\\Windows;C:\\Windows\\System32\r\n");
            self.puts("PROMPT=$P$G\r\n");
            self.puts("SystemRoot=C:\\Windows\r\n");
        }
    }

    fn put_num(&mut self, n: u32) {
        if n == 0 {
            self.putc(b'0');
            return;
        }
        let mut buf = [0u8; 12];
        let mut pos = 11;
        let mut num = n;
        while num > 0 && pos > 0 {
            pos -= 1;
            buf[pos] = b'0' + (num % 10) as u8;
            num /= 10;
        }
        for i in pos..12 {
            self.putc(buf[i]);
        }
    }

    fn put_size(&mut self, size: u64) {
        // Right-align in 14 chars
        let mut buf = [b' '; 14];
        let mut pos = 13;
        let mut num = size;
        if num == 0 {
            buf[pos] = b'0';
        } else {
            while num > 0 && pos > 0 {
                buf[pos] = b'0' + (num % 10) as u8;
                num /= 10;
                if pos > 0 {
                    pos -= 1;
                }
            }
        }
        for b in buf {
            self.putc(b);
        }
    }
}

extern crate alloc;
use alloc::string::{String, ToString};

// ============================================================================
// Shell Pool
// ============================================================================

static SHELLS: SpinLock<[Shell; MAX_SHELLS]> = SpinLock::new([
    Shell::new(), Shell::new(), Shell::new(), Shell::new()
]);

/// Create a new shell window
pub fn create_shell() -> HWND {
    use super::WindowStyle;

    let hwnd = window::create_window(
        "ConsoleWindowClass",
        "Command Prompt",
        WindowStyle::OVERLAPPEDWINDOW | WindowStyle::VISIBLE,
        super::WindowStyleEx::empty(),
        100, 80,
        COLS as i32 * CHAR_W + 16,
        ROWS as i32 * CHAR_H + 40,
        super::super::HWND::NULL,
        0,
    );

    if hwnd.is_valid() {
        let mut shells = SHELLS.lock();
        for shell in shells.iter_mut() {
            if !shell.active {
                shell.init(hwnd);
                break;
            }
        }

        super::explorer::taskband::add_task(hwnd);
        window::set_foreground_window(hwnd);
        super::input::set_active_window(hwnd);

        // Paint immediately - repaint_all draws the frame, paint_shell draws content
        drop(shells);
        super::paint::repaint_all();
    }

    hwnd
}

/// Handle keyboard input for shell
pub fn shell_key(hwnd: HWND, scan: u8, ch: char) {
    let mut shells = SHELLS.lock();
    for shell in shells.iter_mut() {
        if shell.active && shell.hwnd == hwnd {
            shell.key(scan, ch);
            break;
        }
    }
    drop(shells);
    paint_shell(hwnd);
}

/// Check if window is a shell
pub fn is_shell(hwnd: HWND) -> bool {
    if let Some(wnd) = window::get_window(hwnd) {
        wnd.class_name_str() == "ConsoleWindowClass"
    } else {
        false
    }
}

/// Paint shell window
pub fn paint_shell(hwnd: HWND) {
    let wnd = match window::get_window(hwnd) {
        Some(w) => w,
        None => return,
    };

    let hdc = match dc::create_display_dc() {
        Ok(h) => h,
        Err(_) => return,
    };

    let sh = dc::get_dc_surface(hdc);
    let surf = match surface::get_surface(sh) {
        Some(s) => s,
        None => {
            dc::delete_dc(hdc);
            return;
        }
    };

    let m = wnd.get_frame_metrics();
    let bw = m.border_width;
    let ch = if wnd.has_caption() { m.caption_height } else { 0 };
    let x0 = wnd.rect.left + bw;
    let y0 = wnd.rect.top + bw + ch;

    // Black background
    let bg = Rect::new(x0, y0, x0 + COLS as i32 * CHAR_W, y0 + ROWS as i32 * CHAR_H);
    surf.fill_rect(&bg, ColorRef::BLACK);

    let shells = SHELLS.lock();
    for shell in shells.iter() {
        if shell.active && shell.hwnd == hwnd {
            // Draw text
            for row in 0..ROWS {
                for col in 0..COLS {
                    let c = shell.buf[row][col];
                    if c != b' ' {
                        let px = x0 + col as i32 * CHAR_W;
                        let py = y0 + row as i32 * CHAR_H;
                        draw_char(&surf, px, py, c, ColorRef::rgb(192, 192, 192));
                    }
                }
            }

            // Draw cursor
            let cx = x0 + shell.cx as i32 * CHAR_W;
            let cy = y0 + shell.cy as i32 * CHAR_H;
            let cr = Rect::new(cx, cy, cx + CHAR_W, cy + CHAR_H);
            surf.fill_rect(&cr, ColorRef::rgb(192, 192, 192));

            break;
        }
    }

    dc::delete_dc(hdc);
}

/// Draw a character using bitmap font
fn draw_char(surf: &surface::Surface, x: i32, y: i32, ch: u8, color: ColorRef) {
    let glyph = get_glyph(ch);
    for row in 0..14 {
        let bits = glyph[row];
        for col in 0..8 {
            if (bits >> (7 - col)) & 1 != 0 {
                surf.set_pixel(x + col, y + row as i32, color);
            }
        }
    }
}

/// Get font glyph (8x14 VGA font)
fn get_glyph(ch: u8) -> [u8; 14] {
    match ch {
        b'A' => [0x00, 0x18, 0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'B' => [0x00, 0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'C' => [0x00, 0x3C, 0x66, 0x60, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'D' => [0x00, 0x78, 0x6C, 0x66, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'E' => [0x00, 0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'F' => [0x00, 0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'G' => [0x00, 0x3C, 0x66, 0x60, 0x60, 0x6E, 0x66, 0x66, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'H' => [0x00, 0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'I' => [0x00, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'J' => [0x00, 0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x6C, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'K' => [0x00, 0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'L' => [0x00, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'M' => [0x00, 0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'N' => [0x00, 0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'O' => [0x00, 0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'P' => [0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'Q' => [0x00, 0x3C, 0x66, 0x66, 0x66, 0x66, 0x6E, 0x3C, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'R' => [0x00, 0x7C, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'S' => [0x00, 0x3C, 0x66, 0x60, 0x3C, 0x06, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'T' => [0x00, 0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'U' => [0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'V' => [0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x3C, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'W' => [0x00, 0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'X' => [0x00, 0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'Y' => [0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'Z' => [0x00, 0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x60, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'a'..=b'z' => get_glyph(ch - 32),
        b'0' => [0x00, 0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'1' => [0x00, 0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'2' => [0x00, 0x3C, 0x66, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'3' => [0x00, 0x3C, 0x66, 0x06, 0x1C, 0x06, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'4' => [0x00, 0x0C, 0x1C, 0x3C, 0x6C, 0x7E, 0x0C, 0x0C, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'5' => [0x00, 0x7E, 0x60, 0x7C, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'6' => [0x00, 0x3C, 0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'7' => [0x00, 0x7E, 0x06, 0x0C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'8' => [0x00, 0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'9' => [0x00, 0x3C, 0x66, 0x66, 0x3E, 0x06, 0x06, 0x06, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00],
        b':' => [0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        b',' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00],
        b'-' => [0x00, 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'_' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00],
        b'/' => [0x00, 0x02, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'\\' => [0x00, 0x40, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'>' => [0x00, 0x60, 0x30, 0x18, 0x0C, 0x18, 0x30, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'<' => [0x00, 0x06, 0x0C, 0x18, 0x30, 0x18, 0x0C, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'(' => [0x00, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b')' => [0x00, 0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'[' => [0x00, 0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b']' => [0x00, 0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b' ' => [0x00; 14],
        b'=' => [0x00, 0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'$' => [0x00, 0x18, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'?' => [0x00, 0x3C, 0x66, 0x06, 0x0C, 0x18, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'!' => [0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'\'' => [0x00, 0x18, 0x18, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'"' => [0x00, 0x66, 0x66, 0x22, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        _ => [0x00; 14],
    }
}
