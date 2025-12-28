//! Shell Commands
//!
//! Implementation of all built-in shell commands.

use crate::fs;
use super::{get_current_dir, set_current_dir, shell_write, shell_writeln};
use core::fmt::Write;
use core::ptr::addr_of_mut;

/// Buffer for formatted output
static mut FMT_BUF: [u8; 512] = [0u8; 512];

/// Formatted print to shell (supports redirection)
macro_rules! out {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        unsafe {
            let buf = &mut *addr_of_mut!(FMT_BUF);
            let mut pos = 0usize;
            {
                let mut writer = FmtWriter { buf, pos: &mut pos };
                let _ = write!(writer, $($arg)*);
            }
            let buf = &*addr_of_mut!(FMT_BUF);
            let s = core::str::from_utf8_unchecked(&buf[..pos]);
            shell_write(s);
        }
    }};
}

/// Formatted println to shell (supports redirection)
macro_rules! outln {
    () => { shell_writeln(""); };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        unsafe {
            let buf = &mut *addr_of_mut!(FMT_BUF);
            let mut pos = 0usize;
            {
                let mut writer = FmtWriter { buf, pos: &mut pos };
                let _ = write!(writer, $($arg)*);
            }
            let buf = &*addr_of_mut!(FMT_BUF);
            let s = core::str::from_utf8_unchecked(&buf[..pos]);
            shell_writeln(s);
        }
    }};
}

/// Helper for formatted writing
struct FmtWriter<'a> {
    buf: &'a mut [u8; 512],
    pos: &'a mut usize,
}

impl<'a> Write for FmtWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if *self.pos < self.buf.len() {
                self.buf[*self.pos] = b;
                *self.pos += 1;
            }
        }
        Ok(())
    }
}

/// Display help information
pub fn cmd_help(args: &[&str]) {
    if args.is_empty() {
        outln!("Nostalgia OS Shell Commands:");
        outln!("");
        outln!("  General:");
        outln!("    help [cmd]     Show help (or help for specific command)");
        outln!("    ver            Show version information");
        outln!("    echo [text]    Display text");
        outln!("    cls, clear     Clear the screen");
        outln!("    exit           Exit the shell");
        outln!("");
        outln!("  File System:");
        outln!("    dir, ls [pat]  List directory (supports *, ? wildcards)");
        outln!("    cd [path]      Change directory");
        outln!("    pwd            Print working directory");
        outln!("    type, cat      Display file contents");
        outln!("    mkdir [name]   Create directory");
        outln!("    rmdir [name]   Remove directory");
        outln!("    del, rm [file] Delete file");
        outln!("    copy [s] [d]   Copy file");
        outln!("    ren [old] [new] Rename file");
        outln!("    touch [file]   Create empty file");
        outln!("");
        outln!("  System:");
        outln!("    mem            Show memory usage");
        outln!("    time           Show system time");
        outln!("    ps, tasks      Show running threads");
        outln!("    history        Show command history");
        outln!("    reboot         Restart the system");
        outln!("");
        outln!("  Use UP/DOWN arrows to navigate command history.");
    } else {
        let topic = args[0];
        if eq_ignore_case(topic, "dir") || eq_ignore_case(topic, "ls") {
            outln!("DIR [path] [pattern]");
            outln!("  Lists files and directories.");
            outln!("  If no path given, lists current directory.");
            outln!("");
            outln!("  Wildcards:");
            outln!("    *      Matches any characters");
            outln!("    ?      Matches single character");
            outln!("");
            outln!("  Examples:");
            outln!("    DIR *.TXT      List all .TXT files");
            outln!("    DIR TEST*.*    List files starting with TEST");
            outln!("    DIR C:\\*.EXE   List .EXE files in C:\\");
        } else if eq_ignore_case(topic, "cd") {
            outln!("CD [path]");
            outln!("  Changes the current directory.");
            outln!("  CD ..    Go to parent directory");
            outln!("  CD \\     Go to root directory");
        } else if eq_ignore_case(topic, "type") || eq_ignore_case(topic, "cat") {
            outln!("TYPE <filename>");
            outln!("  Displays the contents of a text file.");
        } else if eq_ignore_case(topic, "copy") || eq_ignore_case(topic, "cp") {
            outln!("COPY <source> <dest>");
            outln!("  Copies a file to a new location.");
        } else {
            outln!("No help available for '{}'", args[0]);
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

/// Check if a filename matches a wildcard pattern (case-insensitive)
/// Supports:
///   * - matches any sequence of characters (including empty)
///   ? - matches exactly one character
fn wildcard_match(pattern: &str, name: &str) -> bool {
    let pat = pattern.as_bytes();
    let txt = name.as_bytes();
    wildcard_match_bytes(pat, txt)
}

/// Recursive wildcard matching on byte slices
fn wildcard_match_bytes(pattern: &[u8], text: &[u8]) -> bool {
    let mut p = 0;
    let mut t = 0;
    let mut star_p: Option<usize> = None;
    let mut star_t: Option<usize> = None;

    while t < text.len() {
        if p < pattern.len() {
            let pc = pattern[p];
            let tc = text[t];

            if pc == b'*' {
                // Star: remember position and try to match zero chars first
                star_p = Some(p);
                star_t = Some(t);
                p += 1;
                continue;
            } else if pc == b'?' {
                // Question mark: match any single character
                p += 1;
                t += 1;
                continue;
            } else {
                // Regular character: case-insensitive compare
                let pc_lower = if pc >= b'A' && pc <= b'Z' { pc + 32 } else { pc };
                let tc_lower = if tc >= b'A' && tc <= b'Z' { tc + 32 } else { tc };
                if pc_lower == tc_lower {
                    p += 1;
                    t += 1;
                    continue;
                }
            }
        }

        // No match at current position - try to use a previous star
        if let (Some(sp), Some(st)) = (star_p, star_t) {
            // Backtrack: advance star_t and retry
            p = sp + 1;
            star_t = Some(st + 1);
            t = st + 1;
        } else {
            // No star to backtrack to - no match
            return false;
        }
    }

    // Consume any trailing stars in pattern
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }

    p == pattern.len()
}

/// Check if a string contains wildcard characters
fn has_wildcards(s: &str) -> bool {
    for c in s.bytes() {
        if c == b'*' || c == b'?' {
            return true;
        }
    }
    false
}

/// Secondary path buffer for building paths
static mut PATH_BUFFER2: [u8; 256] = [0u8; 256];

/// Build a path by combining directory and filename
fn build_path(dir: &str, filename: &str) -> &'static str {
    unsafe {
        let buf = &mut *addr_of_mut!(PATH_BUFFER2);
        let mut len = 0usize;

        // Copy directory
        for &b in dir.as_bytes() {
            if len < buf.len() - 1 {
                buf[len] = b;
                len += 1;
            }
        }

        // Add separator if needed
        if len > 0 && buf[len - 1] != b'\\' {
            if len < buf.len() - 1 {
                buf[len] = b'\\';
                len += 1;
            }
        }

        // Copy filename
        for &b in filename.as_bytes() {
            if len < buf.len() - 1 {
                buf[len] = b;
                len += 1;
            }
        }

        core::str::from_utf8_unchecked(&buf[..len])
    }
}

/// Display version information
pub fn cmd_version() {
    outln!("");
    outln!("Nostalgia OS [Version 0.1.0]");
    outln!("An NT-style kernel written in Rust");
    outln!("");
    outln!("Kernel build info:");
    outln!("  Architecture: x86_64");
    outln!("  Compiler: rustc (nightly)");
    outln!("");
}

/// Echo text to the console
pub fn cmd_echo(args: &[&str]) {
    if args.is_empty() {
        outln!("");
    } else {
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                out!(" ");
            }
            out!("{}", arg);
        }
        outln!("");
    }
}

/// Clear the screen
pub fn cmd_clear() {
    // ANSI escape sequence to clear screen and move cursor home
    out!("\x1B[2J\x1B[H");
}

/// List directory contents with optional wildcard pattern
pub fn cmd_ls(args: &[&str]) {
    let arg = if args.is_empty() {
        ""
    } else {
        args[0]
    };

    // Parse path and pattern
    // If arg contains wildcards, split into directory and pattern
    let (dir_path, pattern): (&str, Option<&str>) = if arg.is_empty() {
        (get_current_dir(), None)
    } else if has_wildcards(arg) {
        // Find last path separator to split directory from pattern
        let bytes = arg.as_bytes();
        let mut last_sep = None;
        for i in 0..bytes.len() {
            if bytes[i] == b'\\' || bytes[i] == b'/' {
                last_sep = Some(i);
            }
        }
        match last_sep {
            Some(pos) => {
                // Pattern has directory component
                let dir_part = &arg[..pos + 1];
                let pat_part = &arg[pos + 1..];
                (dir_part, Some(pat_part))
            }
            None => {
                // Pattern only, use current directory
                (get_current_dir(), Some(arg))
            }
        }
    } else {
        // No wildcards - treat as directory path
        (arg, None)
    };

    // Resolve the directory path
    let full_path = resolve_path(dir_path);

    outln!("");
    if let Some(pat) = pattern {
        outln!(" Directory of {}  ({})", full_path, pat);
    } else {
        outln!(" Directory of {}", full_path);
    }
    outln!("");

    let mut offset = 0u32;
    let mut file_count = 0u32;
    let mut dir_count = 0u32;
    let mut total_size = 0u64;
    let mut shown_count = 0u32;

    loop {
        match fs::readdir(&full_path, offset) {
            Ok(entry) => {
                let name = entry.name_str();

                // Skip . and .. entries
                if name == "." || name == ".." {
                    offset = entry.next_offset;
                    continue;
                }

                // Apply wildcard filter if present
                let matches = match pattern {
                    Some(pat) => wildcard_match(pat, name),
                    None => true,
                };

                if matches {
                    shown_count += 1;
                    let type_str = match entry.file_type {
                        fs::FileType::Directory => {
                            dir_count += 1;
                            "<DIR>     "
                        }
                        fs::FileType::Regular => {
                            file_count += 1;
                            total_size += entry.size;
                            "          "
                        }
                        _ => "          ",
                    };

                    // Format: type  size  name
                    if entry.file_type == fs::FileType::Directory {
                        outln!("{}           {}", type_str, name);
                    } else {
                        outln!("{}{:>10}  {}", type_str, entry.size, name);
                    }
                }

                offset = entry.next_offset;
            }
            Err(fs::FsStatus::NoMoreEntries) => break,
            Err(e) => {
                outln!("Error reading directory: {:?}", e);
                return;
            }
        }
    }

    if shown_count == 0 && pattern.is_some() {
        outln!("File Not Found");
    }

    outln!("");
    outln!("     {:>4} File(s)    {:>10} bytes", file_count, total_size);
    outln!("     {:>4} Dir(s)", dir_count);
    outln!("");
}

/// Change directory
pub fn cmd_cd(args: &[&str]) {
    if args.is_empty() {
        // Just print current directory
        outln!("{}", get_current_dir());
        return;
    }

    let path = args[0];

    // Handle special cases
    if path == "\\" || path == "/" {
        // Go to root of current drive
        let current = get_current_dir();
        if current.len() >= 2 {
            let mut new_path = [0u8; 4];
            new_path[0] = current.as_bytes()[0]; // Drive letter
            new_path[1] = b':';
            new_path[2] = b'\\';
            if let Ok(s) = core::str::from_utf8(&new_path[..3]) {
                set_current_dir(s);
            }
        }
        return;
    }

    if path == ".." {
        // Go to parent directory
        let current = get_current_dir();
        if current.len() > 3 {
            // Find last backslash
            if let Some(pos) = current[..current.len()-1].rfind('\\') {
                if pos >= 2 {
                    set_current_dir(&current[..pos+1]);
                } else {
                    // At root
                    set_current_dir(&current[..3]);
                }
            }
        }
        return;
    }

    // Resolve full path
    let full_path = resolve_path(path);

    // Verify it's a valid directory by trying to read it
    match fs::readdir(&full_path, 0) {
        Ok(_) => {
            // Valid directory
            let mut path_buf = [0u8; 64];
            let bytes = full_path.as_bytes();
            let len = bytes.len().min(64);
            path_buf[..len].copy_from_slice(&bytes[..len]);

            // Ensure path ends with backslash
            if len < 64 && !full_path.ends_with('\\') {
                path_buf[len] = b'\\';
                if let Ok(s) = core::str::from_utf8(&path_buf[..len+1]) {
                    set_current_dir(s);
                }
            } else {
                set_current_dir(&full_path);
            }
        }
        Err(fs::FsStatus::NotFound) => {
            outln!("The system cannot find the path specified.");
        }
        Err(fs::FsStatus::NotDirectory) => {
            outln!("The directory name is invalid.");
        }
        Err(e) => {
            outln!("Error: {:?}", e);
        }
    }
}

/// Print working directory
pub fn cmd_pwd() {
    outln!("{}", get_current_dir());
}

/// Display file contents
pub fn cmd_cat(args: &[&str]) {
    if args.is_empty() {
        outln!("Usage: type <filename>");
        return;
    }

    let full_path = resolve_path(args[0]);

    match fs::open(&full_path, 0) {
        Ok(handle) => {
            let mut buf = [0u8; 512];
            loop {
                match fs::read(handle, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        // Print as text, replacing non-printable chars
                        for &byte in &buf[..n] {
                            if byte == b'\n' {
                                outln!("");
                            } else if byte == b'\r' {
                                // Skip carriage return
                            } else if byte >= 0x20 && byte < 0x7F {
                                out!("{}", byte as char);
                            } else if byte == b'\t' {
                                out!("    ");
                            }
                        }
                    }
                    Err(fs::FsStatus::EndOfFile) => break,
                    Err(e) => {
                        outln!("");
                        outln!("Error reading file: {:?}", e);
                        break;
                    }
                }
            }
            outln!("");
            let _ = fs::close(handle);
        }
        Err(fs::FsStatus::NotFound) => {
            outln!("The system cannot find the file specified.");
        }
        Err(e) => {
            outln!("Error opening file: {:?}", e);
        }
    }
}

/// Create a directory
pub fn cmd_mkdir(args: &[&str]) {
    if args.is_empty() {
        outln!("Usage: mkdir <dirname>");
        return;
    }

    let full_path = resolve_path(args[0]);

    match fs::mkdir(&full_path) {
        Ok(()) => {
            // Success - no output
        }
        Err(fs::FsStatus::AlreadyExists) => {
            outln!("A subdirectory or file {} already exists.", args[0]);
        }
        Err(e) => {
            outln!("Error creating directory: {:?}", e);
        }
    }
}

/// Remove a directory
pub fn cmd_rmdir(args: &[&str]) {
    if args.is_empty() {
        outln!("Usage: rmdir <dirname>");
        return;
    }

    let full_path = resolve_path(args[0]);

    match fs::rmdir(&full_path) {
        Ok(()) => {
            // Success - no output
        }
        Err(fs::FsStatus::NotFound) => {
            outln!("The system cannot find the path specified.");
        }
        Err(fs::FsStatus::DirectoryNotEmpty) => {
            outln!("The directory is not empty.");
        }
        Err(e) => {
            outln!("Error removing directory: {:?}", e);
        }
    }
}

/// Delete a file
pub fn cmd_del(args: &[&str]) {
    if args.is_empty() {
        outln!("Usage: del <filename>");
        outln!("  Wildcards * and ? are supported.");
        return;
    }

    let arg = args[0];

    // Check for wildcards
    if has_wildcards(arg) {
        // Split into directory and pattern
        let bytes = arg.as_bytes();
        let mut last_sep = None;
        for i in 0..bytes.len() {
            if bytes[i] == b'\\' || bytes[i] == b'/' {
                last_sep = Some(i);
            }
        }

        let (dir_path, pattern) = match last_sep {
            Some(pos) => (&arg[..pos + 1], &arg[pos + 1..]),
            None => (get_current_dir(), arg),
        };

        let full_dir = resolve_path(dir_path);
        let mut deleted_count = 0u32;
        let mut error_count = 0u32;

        // Collect matching files first (to avoid modifying while iterating)
        let mut files_to_delete: [[u8; 64]; 32] = [[0u8; 64]; 32];
        let mut file_lens: [usize; 32] = [0; 32];
        let mut file_count = 0usize;

        let mut offset = 0u32;
        loop {
            match fs::readdir(&full_dir, offset) {
                Ok(entry) => {
                    let name = entry.name_str();

                    // Skip directories and special entries
                    if name == "." || name == ".." {
                        offset = entry.next_offset;
                        continue;
                    }

                    // Only delete files, not directories
                    if entry.file_type == fs::FileType::Regular {
                        if wildcard_match(pattern, name) {
                            if file_count < 32 {
                                let name_bytes = name.as_bytes();
                                let len = name_bytes.len().min(63);
                                files_to_delete[file_count][..len].copy_from_slice(&name_bytes[..len]);
                                file_lens[file_count] = len;
                                file_count += 1;
                            }
                        }
                    }

                    offset = entry.next_offset;
                }
                Err(_) => break,
            }
        }

        if file_count == 0 {
            outln!("Could not find the file specified.");
            return;
        }

        // Now delete the collected files
        for i in 0..file_count {
            let name = core::str::from_utf8(&files_to_delete[i][..file_lens[i]]).unwrap_or("");

            // Build full path for this file
            let file_path = build_path(&full_dir, name);

            match fs::delete(&file_path) {
                Ok(()) => {
                    deleted_count += 1;
                }
                Err(e) => {
                    outln!("Error deleting {}: {:?}", name, e);
                    error_count += 1;
                }
            }
        }

        if deleted_count > 0 || error_count > 0 {
            outln!("{} file(s) deleted.", deleted_count);
        }
    } else {
        // No wildcards - single file delete
        let full_path = resolve_path(arg);

        match fs::delete(&full_path) {
            Ok(()) => {
                // Success - no output (DOS behavior)
            }
            Err(fs::FsStatus::NotFound) => {
                outln!("Could not find the file specified.");
            }
            Err(e) => {
                outln!("Error deleting file: {:?}", e);
            }
        }
    }
}

/// Copy a file
pub fn cmd_copy(args: &[&str]) {
    if args.len() < 2 {
        outln!("Usage: copy <source> <dest>");
        outln!("  Wildcards * and ? are supported in source.");
        return;
    }

    let src_arg = args[0];
    let dst_arg = args[1];

    // Check for wildcards in source
    if has_wildcards(src_arg) {
        // Split source into directory and pattern
        let bytes = src_arg.as_bytes();
        let mut last_sep = None;
        for i in 0..bytes.len() {
            if bytes[i] == b'\\' || bytes[i] == b'/' {
                last_sep = Some(i);
            }
        }

        let (src_dir, pattern) = match last_sep {
            Some(pos) => (&src_arg[..pos + 1], &src_arg[pos + 1..]),
            None => (get_current_dir(), src_arg),
        };

        let full_src_dir = resolve_path(src_dir);
        let dst_path = resolve_path(dst_arg);

        // Collect matching files
        let mut files_to_copy: [[u8; 64]; 32] = [[0u8; 64]; 32];
        let mut file_lens: [usize; 32] = [0; 32];
        let mut file_count = 0usize;

        let mut offset = 0u32;
        loop {
            match fs::readdir(&full_src_dir, offset) {
                Ok(entry) => {
                    let name = entry.name_str();

                    if name == "." || name == ".." {
                        offset = entry.next_offset;
                        continue;
                    }

                    // Only copy files, not directories
                    if entry.file_type == fs::FileType::Regular {
                        if wildcard_match(pattern, name) {
                            if file_count < 32 {
                                let name_bytes = name.as_bytes();
                                let len = name_bytes.len().min(63);
                                files_to_copy[file_count][..len].copy_from_slice(&name_bytes[..len]);
                                file_lens[file_count] = len;
                                file_count += 1;
                            }
                        }
                    }

                    offset = entry.next_offset;
                }
                Err(_) => break,
            }
        }

        if file_count == 0 {
            outln!("The system cannot find the file specified.");
            return;
        }

        // Check if destination is a directory
        let dst_is_dir = match fs::stat(&dst_path) {
            Ok(info) => info.file_type == fs::FileType::Directory,
            Err(_) => dst_arg.ends_with('\\') || dst_arg.ends_with('/'),
        };

        let mut copied_count = 0u32;
        let mut total_bytes = 0u64;

        for i in 0..file_count {
            let name = core::str::from_utf8(&files_to_copy[i][..file_lens[i]]).unwrap_or("");
            let src_file = build_path(&full_src_dir, name);

            // Determine destination path
            let dst_file = if dst_is_dir {
                build_path(&dst_path, name)
            } else if file_count == 1 {
                // Single file to non-directory destination
                &dst_path
            } else {
                outln!("Cannot copy multiple files to a single file.");
                return;
            };

            // Need to copy src_file to a buffer since build_path uses static buffer
            let mut src_buf: [u8; 256] = [0u8; 256];
            let src_len = src_file.len().min(255);
            src_buf[..src_len].copy_from_slice(src_file.as_bytes());
            let src_str = core::str::from_utf8(&src_buf[..src_len]).unwrap_or("");

            match fs::copy(src_str, dst_file) {
                Ok(bytes) => {
                    copied_count += 1;
                    total_bytes += bytes as u64;
                }
                Err(e) => {
                    outln!("Error copying {}: {:?}", name, e);
                }
            }
        }

        outln!("        {} file(s) copied ({} bytes).", copied_count, total_bytes);
    } else {
        // No wildcards - single file copy
        let src_path = resolve_path(src_arg);
        let dst_path = resolve_path(dst_arg);

        match fs::copy(&src_path, &dst_path) {
            Ok(bytes) => {
                outln!("        1 file(s) copied ({} bytes).", bytes);
            }
            Err(fs::FsStatus::NotFound) => {
                outln!("The system cannot find the file specified.");
            }
            Err(e) => {
                outln!("Error copying file: {:?}", e);
            }
        }
    }
}

/// Rename a file or directory
pub fn cmd_rename(args: &[&str]) {
    if args.len() < 2 {
        outln!("Usage: ren <oldname> <newname>");
        return;
    }

    let old_path = resolve_path(args[0]);
    let new_path = resolve_path(args[1]);

    match fs::rename(&old_path, &new_path) {
        Ok(()) => {
            // Success - no output
        }
        Err(fs::FsStatus::NotFound) => {
            outln!("The system cannot find the file specified.");
        }
        Err(e) => {
            outln!("Error renaming: {:?}", e);
        }
    }
}

/// Create an empty file
pub fn cmd_touch(args: &[&str]) {
    if args.is_empty() {
        outln!("Usage: touch <filename>");
        return;
    }

    let full_path = resolve_path(args[0]);

    // Try to create the file
    match fs::create(&full_path, 0) {
        Ok(handle) => {
            let _ = fs::close(handle);
        }
        Err(fs::FsStatus::AlreadyExists) => {
            // File exists - that's OK for touch
        }
        Err(e) => {
            outln!("Error creating file: {:?}", e);
        }
    }
}

/// Show memory usage
pub fn cmd_mem() {
    outln!("");
    outln!("Memory Status:");
    outln!("");

    // Get memory stats from MM
    let stats = crate::mm::mm_get_stats();

    outln!("  Physical Memory:");
    outln!("    Total:     {} KB ({} pages)", stats.total_pages * 4, stats.total_pages);
    outln!("    Free:      {} KB ({} pages)", stats.free_pages * 4, stats.free_pages);
    outln!("    Zeroed:    {} KB ({} pages)", stats.zeroed_pages * 4, stats.zeroed_pages);
    outln!("    Active:    {} KB ({} pages)", stats.active_pages * 4, stats.active_pages);
    outln!("");
    outln!("  Memory Totals:");
    outln!("    Total:     {} bytes", stats.total_bytes());
    outln!("    Free:      {} bytes", stats.free_bytes());
    outln!("    Used:      {} bytes", stats.used_bytes());
    outln!("");
}

/// Show system time (tick count)
pub fn cmd_time() {
    let ticks = crate::hal::apic::get_tick_count();
    let seconds = ticks / 1000;
    let ms = ticks % 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;

    outln!("System uptime: {}:{:02}:{:02}.{:03}",
        hours,
        minutes % 60,
        seconds % 60,
        ms
    );
    outln!("Total ticks: {}", ticks);
}

/// Show running threads
pub fn cmd_ps() {
    outln!("");
    outln!("  TID  State      Priority  Name");
    outln!("  ---  -----      --------  ----");

    // Get thread list from scheduler
    unsafe {
        crate::ke::scheduler::list_threads();
    }
    outln!("");
}

/// Reboot the system
pub fn cmd_reboot() {
    outln!("Rebooting...");

    // Use keyboard controller reset
    unsafe {
        // Wait for keyboard controller
        while (crate::arch::io::inb(0x64) & 0x02) != 0 {}
        // Send reset command
        crate::arch::io::outb(0x64, 0xFE);
    }

    // If that didn't work, triple fault
    loop {
        crate::arch::halt();
    }
}

/// Test suspend/resume syscalls
pub fn cmd_suspend(args: &[&str]) {
    if args.is_empty() {
        outln!("Usage: suspend <thread|process> <id>");
        outln!("       suspend test");
        outln!("");
        outln!("Examples:");
        outln!("  suspend test           - Test suspend/resume on current process");
        outln!("  suspend thread 5       - Suspend thread with TID 5");
        outln!("  suspend process 4      - Suspend all threads in process PID 4");
        return;
    }

    extern "C" {
        fn syscall_dispatcher(
            num: usize, a1: usize, a2: usize, a3: usize,
            a4: usize, a5: usize, a6: usize,
        ) -> isize;
    }

    // Syscall numbers
    const NT_SUSPEND_PROCESS: usize = 93;
    const NT_RESUME_PROCESS: usize = 94;
    const NT_SUSPEND_THREAD: usize = 98;
    const NT_RESUME_THREAD: usize = 99;
    const NT_GET_CURRENT_PROCESS_ID: usize = 3;

    if eq_ignore_case(args[0], "test") {
        outln!("Testing suspend/resume syscalls...");
        outln!("");

        // Get current process ID
        let pid = unsafe { syscall_dispatcher(NT_GET_CURRENT_PROCESS_ID, 0, 0, 0, 0, 0, 0) };
        outln!("Current process ID: {}", pid);

        // We need a process handle - use the pseudo-handle for current process
        // In NT, -1 (0xFFFFFFFF) is NtCurrentProcess()
        let current_process_handle = 0x5000usize; // First process handle slot

        outln!("");
        outln!("Calling NtSuspendProcess on current process...");
        outln!("(This will suspend all threads including shell - expect no more output)");
        outln!("Note: In a real scenario, another thread would resume us.");
        outln!("");

        // For testing, we'll just call the syscall and see the debug output
        // We can't actually suspend ourselves without another thread to resume
        // So let's test on a different process or just show the syscall works

        // Instead, let's just verify the syscall dispatches correctly
        // by checking return values
        outln!("Testing NtSuspendThread on invalid handle...");
        let result = unsafe { syscall_dispatcher(NT_SUSPEND_THREAD, 0xFFFF, 0, 0, 0, 0, 0) };
        outln!("  Result: {:#x} (expected error for invalid handle)", result as u32);

        outln!("");
        outln!("Testing NtResumeThread on invalid handle...");
        let result = unsafe { syscall_dispatcher(NT_RESUME_THREAD, 0xFFFF, 0, 0, 0, 0, 0) };
        outln!("  Result: {:#x} (expected error for invalid handle)", result as u32);

        outln!("");
        outln!("Testing NtSuspendProcess on invalid handle...");
        let result = unsafe { syscall_dispatcher(NT_SUSPEND_PROCESS, 0xFFFF, 0, 0, 0, 0, 0) };
        outln!("  Result: {:#x} (expected error for invalid handle)", result as u32);

        outln!("");
        outln!("Testing NtResumeProcess on invalid handle...");
        let result = unsafe { syscall_dispatcher(NT_RESUME_PROCESS, 0xFFFF, 0, 0, 0, 0, 0) };
        outln!("  Result: {:#x} (expected error for invalid handle)", result as u32);

        outln!("");
        outln!("Suspend/resume syscall tests complete!");
        outln!("Check serial output for [SYSCALL] messages.");

    } else if eq_ignore_case(args[0], "thread") {
        if args.len() < 2 {
            outln!("Usage: suspend thread <tid>");
            return;
        }
        let tid: usize = match parse_number(args[1]) {
            Some(n) => n,
            None => {
                outln!("Invalid thread ID: {}", args[1]);
                return;
            }
        };
        // Thread handle = 0x1000 + tid (sync object handle base)
        let handle = 0x1000 + tid;
        outln!("Suspending thread {} (handle {:#x})...", tid, handle);
        let result = unsafe { syscall_dispatcher(NT_SUSPEND_THREAD, handle, 0, 0, 0, 0, 0) };
        if result >= 0 {
            outln!("Thread suspended. Previous suspend count: {}", result);
        } else {
            outln!("Failed to suspend thread: {:#x}", result as u32);
        }

    } else if eq_ignore_case(args[0], "process") {
        if args.len() < 2 {
            outln!("Usage: suspend process <pid>");
            return;
        }
        let pid: usize = match parse_number(args[1]) {
            Some(n) => n,
            None => {
                outln!("Invalid process ID: {}", args[1]);
                return;
            }
        };
        // Process handle = 0x5000 + pid
        let handle = 0x5000 + pid;
        outln!("Suspending process {} (handle {:#x})...", pid, handle);
        let result = unsafe { syscall_dispatcher(NT_SUSPEND_PROCESS, handle, 0, 0, 0, 0, 0) };
        if result == 0 {
            outln!("Process suspended successfully.");
        } else {
            outln!("Failed to suspend process: {:#x}", result as u32);
        }

    } else {
        outln!("Unknown subcommand: {}", args[0]);
        outln!("Use 'suspend' without arguments for help.");
    }
}

/// Parse a number from a string (decimal or hex with 0x prefix)
fn parse_number(s: &str) -> Option<usize> {
    if s.starts_with("0x") || s.starts_with("0X") {
        usize::from_str_radix(&s[2..], 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Resume suspended threads/processes
pub fn cmd_resume(args: &[&str]) {
    if args.is_empty() {
        outln!("Usage: resume <thread|process> <id>");
        outln!("");
        outln!("Examples:");
        outln!("  resume thread 5       - Resume thread with TID 5");
        outln!("  resume process 4      - Resume all threads in process PID 4");
        return;
    }

    extern "C" {
        fn syscall_dispatcher(
            num: usize, a1: usize, a2: usize, a3: usize,
            a4: usize, a5: usize, a6: usize,
        ) -> isize;
    }

    // Syscall numbers
    const NT_RESUME_PROCESS: usize = 94;
    const NT_RESUME_THREAD: usize = 99;

    if eq_ignore_case(args[0], "thread") {
        if args.len() < 2 {
            outln!("Usage: resume thread <tid>");
            return;
        }
        let tid: usize = match parse_number(args[1]) {
            Some(n) => n,
            None => {
                outln!("Invalid thread ID: {}", args[1]);
                return;
            }
        };
        // Thread handle = 0x1000 + tid (sync object handle base)
        let handle = 0x1000 + tid;
        outln!("Resuming thread {} (handle {:#x})...", tid, handle);
        let result = unsafe { syscall_dispatcher(NT_RESUME_THREAD, handle, 0, 0, 0, 0, 0) };
        if result >= 0 {
            outln!("Thread resumed. Previous suspend count: {}", result);
        } else {
            outln!("Failed to resume thread: {:#x}", result as u32);
        }

    } else if eq_ignore_case(args[0], "process") {
        if args.len() < 2 {
            outln!("Usage: resume process <pid>");
            return;
        }
        let pid: usize = match parse_number(args[1]) {
            Some(n) => n,
            None => {
                outln!("Invalid process ID: {}", args[1]);
                return;
            }
        };
        // Process handle = 0x5000 + pid
        let handle = 0x5000 + pid;
        outln!("Resuming process {} (handle {:#x})...", pid, handle);
        let result = unsafe { syscall_dispatcher(NT_RESUME_PROCESS, handle, 0, 0, 0, 0, 0) };
        if result == 0 {
            outln!("Process resumed successfully.");
        } else {
            outln!("Failed to resume process: {:#x}", result as u32);
        }

    } else {
        outln!("Unknown subcommand: {}", args[0]);
        outln!("Use 'resume' without arguments for help.");
    }
}

/// Path buffer for resolved paths
static mut PATH_BUFFER: [u8; 128] = [0u8; 128];

/// Resolve a path relative to current directory
/// Returns a static string reference (not thread-safe, but OK for single shell)
pub fn resolve_path(path: &str) -> &'static str {
    unsafe {
        let buf = &mut *addr_of_mut!(PATH_BUFFER);
        let mut path_len = 0usize;

        // Helper to append to path buffer
        let mut append = |s: &str, buf: &mut [u8; 128], len: &mut usize| {
            for &b in s.as_bytes() {
                if *len < buf.len() {
                    // Convert forward slash to backslash
                    buf[*len] = if b == b'/' { b'\\' } else { b };
                    *len += 1;
                }
            }
        };

        // If path starts with drive letter, it's absolute
        if path.len() >= 2 && path.as_bytes()[1] == b':' {
            append(path, buf, &mut path_len);
            return core::str::from_utf8_unchecked(&buf[..path_len]);
        }

        // If path starts with backslash, it's relative to drive root
        if path.starts_with('\\') || path.starts_with('/') {
            let current = get_current_dir();
            if current.len() >= 2 {
                // Add drive letter
                buf[0] = current.as_bytes()[0];
                buf[1] = b':';
                path_len = 2;
                append(path, buf, &mut path_len);
                return core::str::from_utf8_unchecked(&buf[..path_len]);
            }
        }

        // Relative path - append to current directory
        let current = get_current_dir();
        append(current, buf, &mut path_len);

        // Ensure current dir ends with backslash
        if path_len > 0 && buf[path_len - 1] != b'\\' {
            if path_len < buf.len() {
                buf[path_len] = b'\\';
                path_len += 1;
            }
        }

        append(path, buf, &mut path_len);
        core::str::from_utf8_unchecked(&buf[..path_len])
    }
}
