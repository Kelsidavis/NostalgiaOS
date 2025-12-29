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
        outln!("  Hardware/Power:");
        outln!("    cpuinfo        Show CPU and ACPI information");
        outln!("    power          Show power management status");
        outln!("    shutdown       Shut down the system");
        outln!("");
        outln!("  Services:");
        outln!("    services       List/manage services");
        outln!("    sc <cmd>       Service control (Windows sc.exe)");
        outln!("    net start/stop Service management (Windows net.exe)");
        outln!("");
        outln!("  Debugging:");
        outln!("    veh            Vectored Exception Handler info/test");
        outln!("    seh            Structured Exception Handler info/test");
        outln!("");
        outln!("  Kernel Subsystems:");
        outln!("    ob <cmd>       Object Manager (types, dir, handles)");
        outln!("    rtl <cmd>      Runtime Library (time, random, crc32)");
        outln!("    ldr <cmd>      Loader (info, modules, dll)");
        outln!("    pe <file>      Parse PE/DLL file headers");
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
    a.as_bytes().eq_ignore_ascii_case(b.as_bytes())
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
                if pc.to_ascii_lowercase() == tc.to_ascii_lowercase() {
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
        if len > 0 && buf[len - 1] != b'\\'
            && len < buf.len() - 1 {
                buf[len] = b'\\';
                len += 1;
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
        match fs::readdir(full_path, offset) {
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
    match fs::readdir(full_path, 0) {
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
                set_current_dir(full_path);
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

    match fs::open(full_path, 0) {
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
                            } else if (0x20..0x7F).contains(&byte) {
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

    match fs::mkdir(full_path) {
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

    match fs::rmdir(full_path) {
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
            match fs::readdir(full_dir, offset) {
                Ok(entry) => {
                    let name = entry.name_str();

                    // Skip directories and special entries
                    if name == "." || name == ".." {
                        offset = entry.next_offset;
                        continue;
                    }

                    // Only delete files, not directories
                    if entry.file_type == fs::FileType::Regular
                        && wildcard_match(pattern, name)
                            && file_count < 32 {
                                let name_bytes = name.as_bytes();
                                let len = name_bytes.len().min(63);
                                files_to_delete[file_count][..len].copy_from_slice(&name_bytes[..len]);
                                file_lens[file_count] = len;
                                file_count += 1;
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
            let file_path = build_path(full_dir, name);

            match fs::delete(file_path) {
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

        match fs::delete(full_path) {
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
            match fs::readdir(full_src_dir, offset) {
                Ok(entry) => {
                    let name = entry.name_str();

                    if name == "." || name == ".." {
                        offset = entry.next_offset;
                        continue;
                    }

                    // Only copy files, not directories
                    if entry.file_type == fs::FileType::Regular
                        && wildcard_match(pattern, name)
                            && file_count < 32 {
                                let name_bytes = name.as_bytes();
                                let len = name_bytes.len().min(63);
                                files_to_copy[file_count][..len].copy_from_slice(&name_bytes[..len]);
                                file_lens[file_count] = len;
                                file_count += 1;
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
        let dst_is_dir = match fs::stat(dst_path) {
            Ok(info) => info.file_type == fs::FileType::Directory,
            Err(_) => dst_arg.ends_with('\\') || dst_arg.ends_with('/'),
        };

        let mut copied_count = 0u32;
        let mut total_bytes = 0u64;

        for i in 0..file_count {
            let name = core::str::from_utf8(&files_to_copy[i][..file_lens[i]]).unwrap_or("");
            let src_file = build_path(full_src_dir, name);

            // Determine destination path
            let dst_file = if dst_is_dir {
                build_path(dst_path, name)
            } else if file_count == 1 {
                // Single file to non-directory destination
                dst_path
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
                    total_bytes += bytes;
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

        match fs::copy(src_path, dst_path) {
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

    match fs::rename(old_path, new_path) {
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
    match fs::create(full_path, 0) {
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
    // Get current date/time from RTC
    let dt = crate::hal::rtc::get_datetime();
    let day_names = ["", "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let day_name = if dt.day_of_week >= 1 && dt.day_of_week <= 7 {
        day_names[dt.day_of_week as usize]
    } else {
        "???"
    };

    outln!("Current time: {} {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        day_name,
        dt.year, dt.month, dt.day,
        dt.hour, dt.minute, dt.second
    );

    // Get uptime from tick counter
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
        let _current_process_handle = 0x5000usize; // First process handle slot

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
        let append = |s: &str, buf: &mut [u8; 128], len: &mut usize| {
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
        if path_len > 0 && buf[path_len - 1] != b'\\'
            && path_len < buf.len() {
                buf[path_len] = b'\\';
                path_len += 1;
            }

        append(path, buf, &mut path_len);
        core::str::from_utf8_unchecked(&buf[..path_len])
    }
}

/// Display CPU and system information (ACPI data)
pub fn cmd_cpuinfo() {
    outln!("System Information:");
    outln!("");

    // ACPI information
    if crate::hal::acpi::is_initialized() {
        outln!("ACPI:");
        outln!("  Revision: {}", if crate::hal::acpi::get_revision() >= 2 { "2.0+" } else { "1.0" });
        outln!("  Processor Count: {}", crate::hal::acpi::get_processor_count());
        outln!("  I/O APIC Count: {}", crate::hal::acpi::get_io_apic_count());
        outln!("  Local APIC Address: {:#x}", crate::hal::acpi::get_local_apic_address());
        outln!("  Legacy PIC Present: {}", crate::hal::acpi::has_legacy_pics());
        outln!("");

        // Show processor information
        outln!("Processors:");
        for i in 0..crate::hal::acpi::get_processor_count() {
            if let Some(cpu) = crate::hal::acpi::get_processor(i) {
                outln!("  CPU {}: APIC ID={}, ACPI ID={}, Enabled={}, BSP={}",
                    i, cpu.apic_id, cpu.acpi_id, cpu.enabled, cpu.is_bsp);
            }
        }
        outln!("");

        // Show I/O APIC information
        outln!("I/O APICs:");
        for i in 0..crate::hal::acpi::get_io_apic_count() {
            if let Some(ioapic) = crate::hal::acpi::get_io_apic(i) {
                outln!("  I/O APIC {}: ID={}, Address={:#x}, GSI Base={}",
                    i, ioapic.id, ioapic.address, ioapic.gsi_base);
            }
        }
    } else {
        outln!("ACPI: Not available");
    }

    outln!("");

    // Local APIC information
    let apic = crate::hal::apic::get();
    outln!("Local APIC:");
    outln!("  ID: {}", apic.id());
    outln!("  Base Address: {:#x}", apic.base_address());
    outln!("  Version: {:#x}", apic.version());
}

/// Power management command
pub fn cmd_power(args: &[&str]) {
    if args.is_empty() {
        // Show power status
        outln!("Power Management Status:");
        outln!("");

        // Power manager state
        if crate::po::is_initialized() {
            let state = crate::po::get_system_power_state();
            outln!("  System Power State: {:?}", state);
            outln!("  AC Power: {}", crate::po::is_ac_power());
            outln!("  Battery Power: {}", crate::po::is_battery_power());
            outln!("  Action in Progress: {}", crate::po::is_action_in_progress());
            outln!("  Processor Throttle: {}%", crate::po::get_processor_throttle());
            outln!("");

            // Capabilities
            let caps = crate::po::get_capabilities();
            outln!("  Power Capabilities:");
            outln!("    Power Button: {}", caps.power_button_present);
            outln!("    Sleep Button: {}", caps.sleep_button_present);
            outln!("    S1 (Standby): {}", caps.system_s1);
            outln!("    S3 (Sleep): {}", caps.system_s3);
            outln!("    S4 (Hibernate): {}", caps.system_s4);
            outln!("    S5 (Soft Off): {}", caps.system_s5);
        } else {
            outln!("  Power manager not initialized");
        }

        outln!("");
        outln!("Usage:");
        outln!("  power              - Show power status");
        outln!("  power throttle N   - Set CPU throttle to N%");
    } else if eq_ignore_case(args[0], "throttle") {
        if args.len() < 2 {
            outln!("Usage: power throttle <0-100>");
            return;
        }
        if let Some(level) = parse_number(args[1]) {
            let level = level.min(100) as u8;
            crate::po::set_processor_throttle(level);
            outln!("Processor throttle set to {}%", level);
        } else {
            outln!("Invalid throttle value");
        }
    } else {
        outln!("Unknown power command: {}", args[0]);
    }
}

/// Shutdown the system
pub fn cmd_shutdown() {
    outln!("Initiating system shutdown...");
    match crate::po::shutdown() {
        Ok(()) => {
            outln!("Shutdown in progress...");
            // Halt all processing
            loop {
                crate::arch::halt();
            }
        }
        Err(e) => {
            outln!("Shutdown failed: error {}", e);
        }
    }
}

/// VEH (Vectored Exception Handler) information and testing
///
/// Usage: veh [add|remove|list|test]
pub fn cmd_veh(args: &[&str]) {
    use crate::ke::{
        rtl_add_vectored_exception_handler,
        rtl_remove_vectored_exception_handler,
        rtl_get_vectored_handler_count,
        MAX_VEH_HANDLERS,
    };

    if args.is_empty() {
        // Show VEH status
        outln!("Vectored Exception Handler (VEH) Status");
        outln!("========================================");
        outln!("Registered handlers: {}/{}", rtl_get_vectored_handler_count(), MAX_VEH_HANDLERS);
        outln!();
        outln!("Commands:");
        outln!("  veh add     - Add a test VEH handler");
        outln!("  veh remove  - Remove all test handlers");
        outln!("  veh list    - List handler info");
        outln!("  veh test    - Test exception dispatch");
        return;
    }

    match args[0] {
        "add" => {
            // Add a test VEH handler
            let handle = rtl_add_vectored_exception_handler(0, test_veh_handler);
            if handle != 0 {
                outln!("Added VEH handler with handle: {:#x}", handle);
                outln!("Total handlers: {}", rtl_get_vectored_handler_count());
            } else {
                outln!("Failed to add VEH handler (list full?)");
            }
        }
        "addfirst" => {
            // Add as first handler
            let handle = rtl_add_vectored_exception_handler(1, test_veh_handler_first);
            if handle != 0 {
                outln!("Added FIRST VEH handler with handle: {:#x}", handle);
                outln!("Total handlers: {}", rtl_get_vectored_handler_count());
            } else {
                outln!("Failed to add VEH handler (list full?)");
            }
        }
        "remove" => {
            if args.len() > 1 {
                // Remove specific handler by handle
                if let Some(handle) = parse_number(args[1]) {
                    let handle = handle as u64;
                    if rtl_remove_vectored_exception_handler(handle) != 0 {
                        outln!("Removed VEH handler {:#x}", handle);
                    } else {
                        outln!("Handler {:#x} not found", handle);
                    }
                } else {
                    outln!("Invalid handle: {}", args[1]);
                }
            } else {
                outln!("Usage: veh remove <handle>");
            }
        }
        "list" => {
            outln!("VEH Handler List");
            outln!("================");
            outln!("Registered handlers: {}/{}", rtl_get_vectored_handler_count(), MAX_VEH_HANDLERS);
            outln!();
            outln!("VEH dispatch order:");
            outln!("  1. Vectored Exception Handlers (first chance)");
            outln!("  2. Structured Exception Handlers (SEH)");
            outln!("  3. Unhandled Exception Filter");
            outln!("  4. Second Chance (process termination)");
        }
        "test" => {
            outln!("Testing VEH exception dispatch...");
            outln!("Active handlers: {}", rtl_get_vectored_handler_count());
            outln!();

            // Create a test exception
            use crate::ke::{ExceptionRecord, Context, ke_raise_exception};

            let record = ExceptionRecord::breakpoint(0x1234 as *mut u8);
            let mut context = Context::new();

            outln!("Raising test breakpoint exception...");
            let result = unsafe {
                ke_raise_exception(&record, &mut context, true)
            };
            outln!("ke_raise_exception returned: {}", result);

            outln!();
            outln!("VEH test complete.");
        }
        _ => {
            outln!("Unknown VEH command: {}", args[0]);
            outln!("Use: veh add, veh remove <handle>, veh list, veh test");
        }
    }
}

/// Test VEH handler - logs exceptions but continues search
fn test_veh_handler(exception_info: *mut crate::ke::ExceptionPointers) -> i32 {
    use crate::ke::ExceptionDisposition;

    unsafe {
        if !exception_info.is_null() {
            let info = &*exception_info;
            if !info.exception_record.is_null() {
                let record = &*info.exception_record;
                crate::serial_println!(
                    "[VEH-TEST] Exception code={:#x} addr={:p}",
                    record.exception_code,
                    record.exception_address
                );
            }
        }
    }

    // Continue search - let other handlers process
    ExceptionDisposition::EXCEPTION_CONTINUE_SEARCH
}

/// Test VEH handler that marks itself as first and continues execution
fn test_veh_handler_first(exception_info: *mut crate::ke::ExceptionPointers) -> i32 {
    use crate::ke::ExceptionDisposition;

    unsafe {
        if !exception_info.is_null() {
            let info = &*exception_info;
            if !info.exception_record.is_null() {
                let record = &*info.exception_record;
                crate::serial_println!(
                    "[VEH-FIRST] Handling exception code={:#x} - CONTINUE_EXECUTION",
                    record.exception_code
                );
            }
        }
    }

    // Handle the exception - stop search and continue execution
    ExceptionDisposition::EXCEPTION_CONTINUE_EXECUTION
}

/// SEH (Structured Exception Handler) information and testing
///
/// Usage: seh [add|remove|list|test]
pub fn cmd_seh(args: &[&str]) {
    use crate::ke::{
        rtl_push_exception_handler,
        rtl_get_seh_frame_count, MAX_SEH_FRAMES,
    };

    if args.is_empty() {
        // Show SEH status
        outln!("Structured Exception Handler (SEH) Status");
        outln!("==========================================");
        outln!("Registered frames: {}/{}", rtl_get_seh_frame_count(), MAX_SEH_FRAMES);
        outln!();
        outln!("Commands:");
        outln!("  seh add     - Add a test SEH handler");
        outln!("  seh list    - List SEH chain info");
        outln!("  seh test    - Test exception dispatch through SEH");
        return;
    }

    match args[0] {
        "add" => {
            // Add a test SEH handler
            let frame = rtl_push_exception_handler(test_seh_handler, 0x1000);
            if !frame.is_null() {
                outln!("Added SEH handler at frame {:p}", frame);
                outln!("Total frames: {}", rtl_get_seh_frame_count());
            } else {
                outln!("Failed to add SEH handler (list full?)");
            }
        }
        "list" => {
            outln!("SEH Handler Chain");
            outln!("=================");
            outln!("Registered frames: {}/{}", rtl_get_seh_frame_count(), MAX_SEH_FRAMES);
            outln!();
            outln!("Exception dispatch order:");
            outln!("  1. Vectored Exception Handlers (VEH)");
            outln!("  2. Structured Exception Handlers (SEH) <- This chain");
            outln!("  3. Unhandled Exception Filter");
            outln!("  4. Second Chance (termination)");
        }
        "test" => {
            outln!("Testing SEH exception dispatch...");
            outln!("SEH frames: {}", rtl_get_seh_frame_count());
            outln!("VEH handlers: {}", crate::ke::rtl_get_vectored_handler_count());
            outln!();

            // Create a test exception
            use crate::ke::{ExceptionRecord, Context, ke_raise_exception};

            let record = ExceptionRecord::breakpoint(0x5678 as *mut u8);
            let mut context = Context::new();

            outln!("Raising test breakpoint exception...");
            let result = unsafe {
                ke_raise_exception(&record, &mut context, true)
            };
            outln!("ke_raise_exception returned: {}", result);

            outln!();
            outln!("SEH test complete.");
        }
        _ => {
            outln!("Unknown SEH command: {}", args[0]);
            outln!("Use: seh add, seh list, seh test");
        }
    }
}

/// Test SEH handler - logs and continues search
fn test_seh_handler(
    exception_record: *mut crate::ke::ExceptionRecord,
    establisher_frame: u64,
    _context: *mut crate::ke::Context,
    _dispatcher_context: *mut crate::ke::DispatcherContext,
) -> i32 {
    use crate::ke::ExceptionDisposition;

    unsafe {
        if !exception_record.is_null() {
            let record = &*exception_record;
            crate::serial_println!(
                "[SEH-TEST] Exception code={:#x} frame={:#x}",
                record.exception_code,
                establisher_frame
            );
        }
    }

    // Continue search - let other handlers try
    ExceptionDisposition::EXCEPTION_CONTINUE_SEARCH
}

// ============================================================================
// Service Control Manager Commands
// ============================================================================

/// List services command
pub fn cmd_services(args: &[&str]) {
    use crate::svc::{self, ServiceState, service_type};

    if args.is_empty() {
        // List all services
        outln!("");
        outln!("  SERVICE NAME                  TYPE            STATE           START TYPE");
        outln!("  ============                  ====            =====           ==========");

        svc::enumerate_services(|svc| {
            let name = svc.name_str();
            let type_str = if (svc.service_type & service_type::KERNEL_DRIVER) != 0 {
                "Kernel"
            } else if (svc.service_type & service_type::FILE_SYSTEM_DRIVER) != 0 {
                "FileSystem"
            } else if (svc.service_type & service_type::WIN32) != 0 {
                "Win32"
            } else {
                "Unknown"
            };

            let state_str = match svc.state() {
                ServiceState::Stopped => "Stopped",
                ServiceState::StartPending => "Starting",
                ServiceState::StopPending => "Stopping",
                ServiceState::Running => "Running",
                ServiceState::ContinuePending => "Continuing",
                ServiceState::PausePending => "Pausing",
                ServiceState::Paused => "Paused",
            };

            let start_str = match svc.start_type {
                svc::ServiceStartType::BootStart => "Boot",
                svc::ServiceStartType::SystemStart => "System",
                svc::ServiceStartType::AutoStart => "Auto",
                svc::ServiceStartType::DemandStart => "Demand",
                svc::ServiceStartType::Disabled => "Disabled",
            };

            outln!("  {:<28} {:<15} {:<15} {}", name, type_str, state_str, start_str);
            true
        });

        outln!("");
        let total = svc::service_count();
        let running = svc::get_services_by_state(ServiceState::Running);
        outln!("  {} services ({} running)", total, running);
        outln!("");
    } else {
        match args[0] {
            "start" => {
                if args.len() < 2 {
                    outln!("Usage: services start <service_name>");
                    return;
                }
                let result = svc::scm_start_service(args[1]);
                if result == 0 {
                    outln!("Service '{}' started successfully.", args[1]);
                } else {
                    outln!("Failed to start service '{}' (error: {:#x})", args[1], result);
                }
            }
            "stop" => {
                if args.len() < 2 {
                    outln!("Usage: services stop <service_name>");
                    return;
                }
                let result = svc::scm_stop_service(args[1]);
                if result == 0 {
                    outln!("Service '{}' stopped successfully.", args[1]);
                } else {
                    outln!("Failed to stop service '{}' (error: {:#x})", args[1], result);
                }
            }
            "query" | "status" => {
                if args.len() < 2 {
                    outln!("Usage: services query <service_name>");
                    return;
                }
                match svc::scm_query_service_status(args[1]) {
                    Some(status) => {
                        outln!("");
                        outln!("Service: {}", args[1]);
                        outln!("  Type:      {:#x}", status.service_type);
                        outln!("  State:     {}", match status.current_state {
                            1 => "Stopped",
                            2 => "Start Pending",
                            3 => "Stop Pending",
                            4 => "Running",
                            5 => "Continue Pending",
                            6 => "Pause Pending",
                            7 => "Paused",
                            _ => "Unknown",
                        });
                        outln!("  Controls:  {:#x}", status.controls_accepted);
                        outln!("");
                    }
                    None => {
                        outln!("Service '{}' not found.", args[1]);
                    }
                }
            }
            "help" | "/?" => {
                outln!("Usage: services [command] [service_name]");
                outln!("");
                outln!("Commands:");
                outln!("  (none)           List all services");
                outln!("  start <name>     Start a service");
                outln!("  stop <name>      Stop a service");
                outln!("  query <name>     Query service status");
                outln!("  help             Show this help");
            }
            _ => {
                outln!("Unknown services command: {}", args[0]);
                outln!("Use 'services help' for usage.");
            }
        }
    }
}

/// SC (Service Control) command - Windows sc.exe compatibility
pub fn cmd_sc(args: &[&str]) {
    use crate::svc;

    if args.is_empty() {
        outln!("Usage: sc <command> [service_name] [options]");
        outln!("");
        outln!("Commands:");
        outln!("  query [service]     Query service status");
        outln!("  queryex [service]   Query extended service status");
        outln!("  start <service>     Start a service");
        outln!("  stop <service>      Stop a service");
        outln!("  pause <service>     Pause a service");
        outln!("  continue <service>  Continue a paused service");
        outln!("  config <service>    Change service configuration");
        outln!("  create <service>    Create a new service");
        outln!("  delete <service>    Delete a service");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "query") || eq_ignore_case(cmd, "queryex") {
        if args.len() < 2 {
            // Query all services
            cmd_services(&[]);
        } else {
            cmd_services(&["query", args[1]]);
        }
    } else if eq_ignore_case(cmd, "start") {
        if args.len() < 2 {
            outln!("Usage: sc start <service_name>");
            return;
        }
        let result = svc::scm_start_service(args[1]);
        if result == 0 {
            outln!("SERVICE_NAME: {}", args[1]);
            outln!("        STATE: 4  RUNNING");
        } else {
            outln!("StartService FAILED {:#x}", result);
        }
    } else if eq_ignore_case(cmd, "stop") {
        if args.len() < 2 {
            outln!("Usage: sc stop <service_name>");
            return;
        }
        let result = svc::scm_stop_service(args[1]);
        if result == 0 {
            outln!("SERVICE_NAME: {}", args[1]);
            outln!("        STATE: 1  STOPPED");
        } else {
            outln!("ControlService FAILED {:#x}", result);
        }
    } else if eq_ignore_case(cmd, "pause") {
        if args.len() < 2 {
            outln!("Usage: sc pause <service_name>");
            return;
        }
        let result = svc::scm_control_service(args[1], svc::ServiceControl::Pause);
        if result == 0 {
            outln!("SERVICE_NAME: {}", args[1]);
            outln!("        STATE: 7  PAUSED");
        } else {
            outln!("ControlService FAILED {:#x}", result);
        }
    } else if eq_ignore_case(cmd, "continue") {
        if args.len() < 2 {
            outln!("Usage: sc continue <service_name>");
            return;
        }
        let result = svc::scm_control_service(args[1], svc::ServiceControl::Continue);
        if result == 0 {
            outln!("SERVICE_NAME: {}", args[1]);
            outln!("        STATE: 4  RUNNING");
        } else {
            outln!("ControlService FAILED {:#x}", result);
        }
    } else if eq_ignore_case(cmd, "config") {
        if args.len() < 3 {
            outln!("Usage: sc config <service_name> start=<type>");
            outln!("  Types: boot, system, auto, demand, disabled");
            return;
        }
        // Parse start= option
        for i in 2..args.len() {
            if args[i].starts_with("start=") {
                let start_type = &args[i][6..];
                let svc_start = match start_type {
                    "boot" => Some(svc::ServiceStartType::BootStart),
                    "system" => Some(svc::ServiceStartType::SystemStart),
                    "auto" => Some(svc::ServiceStartType::AutoStart),
                    "demand" => Some(svc::ServiceStartType::DemandStart),
                    "disabled" => Some(svc::ServiceStartType::Disabled),
                    _ => None,
                };

                if let Some(st) = svc_start {
                    let result = svc::scm_change_service_config(
                        args[1],
                        None,
                        Some(st),
                        None,
                        None,
                        None,
                    );
                    if result == 0 {
                        outln!("[SC] ChangeServiceConfig SUCCESS");
                    } else {
                        outln!("ChangeServiceConfig FAILED {:#x}", result);
                    }
                } else {
                    outln!("Invalid start type: {}", start_type);
                }
                return;
            }
        }
        outln!("No configuration options specified.");
    } else if eq_ignore_case(cmd, "create") {
        if args.len() < 3 {
            outln!("Usage: sc create <service_name> binPath=<path> [start=<type>] [type=<type>]");
            return;
        }
        // Parse options
        let mut bin_path: Option<&str> = None;
        let mut start_type = svc::ServiceStartType::DemandStart;
        let mut svc_type = svc::service_type::WIN32_OWN_PROCESS;

        for i in 2..args.len() {
            if args[i].starts_with("binPath=") || args[i].starts_with("binpath=") {
                bin_path = Some(&args[i][8..]);
            } else if args[i].starts_with("start=") {
                start_type = match &args[i][6..] {
                    "boot" => svc::ServiceStartType::BootStart,
                    "system" => svc::ServiceStartType::SystemStart,
                    "auto" => svc::ServiceStartType::AutoStart,
                    "demand" => svc::ServiceStartType::DemandStart,
                    "disabled" => svc::ServiceStartType::Disabled,
                    _ => svc::ServiceStartType::DemandStart,
                };
            } else if args[i].starts_with("type=") {
                svc_type = match &args[i][5..] {
                    "kernel" => svc::service_type::KERNEL_DRIVER,
                    "filesys" => svc::service_type::FILE_SYSTEM_DRIVER,
                    "own" => svc::service_type::WIN32_OWN_PROCESS,
                    "share" => svc::service_type::WIN32_SHARE_PROCESS,
                    _ => svc::service_type::WIN32_OWN_PROCESS,
                };
            }
        }

        if bin_path.is_none() {
            outln!("binPath= is required");
            return;
        }

        match svc::create_service(
            args[1],
            args[1], // display name = service name
            svc_type,
            start_type,
            svc::ServiceErrorControl::Normal,
            bin_path.unwrap(),
        ) {
            Some(_) => outln!("[SC] CreateService SUCCESS"),
            None => outln!("CreateService FAILED"),
        }
    } else if eq_ignore_case(cmd, "delete") {
        if args.len() < 2 {
            outln!("Usage: sc delete <service_name>");
            return;
        }
        if svc::delete_service(args[1]) {
            outln!("[SC] DeleteService SUCCESS");
        } else {
            outln!("DeleteService FAILED");
        }
    } else {
        outln!("Unknown sc command: {}", cmd);
    }
}

/// NET command - partial Windows net.exe compatibility
pub fn cmd_net(args: &[&str]) {
    use crate::svc;

    if args.is_empty() {
        outln!("Usage: net <command> [options]");
        outln!("");
        outln!("Commands:");
        outln!("  start [service]   Start a service (or list running)");
        outln!("  stop <service>    Stop a service");
        outln!("  pause <service>   Pause a service");
        outln!("  continue <service> Continue a paused service");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "start") {
        if args.len() < 2 {
            // List running services
            outln!("These Windows services are started:");
            outln!("");
            svc::enumerate_services(|svc| {
                if svc.state() == svc::ServiceState::Running {
                    outln!("   {}", svc.display_name_str());
                }
                true
            });
            outln!("");
            outln!("The command completed successfully.");
        } else {
            let result = svc::scm_start_service(args[1]);
            if result == 0 {
                outln!("The {} service was started successfully.", args[1]);
            } else {
                outln!("The {} service could not be started.", args[1]);
            }
        }
    } else if eq_ignore_case(cmd, "stop") {
        if args.len() < 2 {
            outln!("Usage: net stop <service_name>");
            return;
        }
        let result = svc::scm_stop_service(args[1]);
        if result == 0 {
            outln!("The {} service was stopped successfully.", args[1]);
        } else {
            outln!("The {} service could not be stopped.", args[1]);
        }
    } else if eq_ignore_case(cmd, "pause") {
        if args.len() < 2 {
            outln!("Usage: net pause <service_name>");
            return;
        }
        let result = svc::scm_control_service(args[1], svc::ServiceControl::Pause);
        if result == 0 {
            outln!("The {} service was paused successfully.", args[1]);
        } else {
            outln!("The {} service could not be paused.", args[1]);
        }
    } else if eq_ignore_case(cmd, "continue") {
        if args.len() < 2 {
            outln!("Usage: net continue <service_name>");
            return;
        }
        let result = svc::scm_control_service(args[1], svc::ServiceControl::Continue);
        if result == 0 {
            outln!("The {} service was continued successfully.", args[1]);
        } else {
            outln!("The {} service could not be continued.", args[1]);
        }
    } else {
        outln!("NET: unrecognized command '{}'", cmd);
    }
}

/// PE command - analyze PE (Portable Executable) files
pub fn cmd_pe(args: &[&str]) {
    if args.is_empty() {
        outln!("PE - Portable Executable Analyzer");
        outln!("");
        outln!("Usage: pe <command> [options]");
        outln!("");
        outln!("Commands:");
        outln!("  info <address>     Show PE info at memory address");
        outln!("  headers <address>  Show PE headers");
        outln!("  sections <address> List sections");
        outln!("  imports <address>  List imports");
        outln!("  exports <address>  List exports");
        outln!("  kernel             Analyze kernel image");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "kernel") {
        // Analyze the kernel image itself
        // The kernel is loaded by the bootloader, we can find it via a known symbol
        outln!("Kernel PE Analysis:");
        outln!("  Note: Kernel image analysis requires valid PE at load address");
        outln!("  Use 'pe info <address>' with kernel base address");
    } else if eq_ignore_case(cmd, "info") || eq_ignore_case(cmd, "headers") {
        if args.len() < 2 {
            outln!("Usage: pe {} <address>", cmd);
            return;
        }
        let addr = parse_hex_address(args[1]);
        if addr == 0 {
            outln!("Invalid address: {}", args[1]);
            return;
        }
        show_pe_info(addr, eq_ignore_case(cmd, "headers"));
    } else if eq_ignore_case(cmd, "sections") {
        if args.len() < 2 {
            outln!("Usage: pe sections <address>");
            return;
        }
        let addr = parse_hex_address(args[1]);
        if addr == 0 {
            outln!("Invalid address: {}", args[1]);
            return;
        }
        show_pe_sections(addr);
    } else if eq_ignore_case(cmd, "imports") {
        if args.len() < 2 {
            outln!("Usage: pe imports <address>");
            return;
        }
        let addr = parse_hex_address(args[1]);
        if addr == 0 {
            outln!("Invalid address: {}", args[1]);
            return;
        }
        show_pe_imports(addr);
    } else if eq_ignore_case(cmd, "exports") {
        if args.len() < 2 {
            outln!("Usage: pe exports <address>");
            return;
        }
        let addr = parse_hex_address(args[1]);
        if addr == 0 {
            outln!("Invalid address: {}", args[1]);
            return;
        }
        show_pe_exports(addr);
    } else {
        outln!("Unknown pe command: {}", cmd);
    }
}

/// Parse a hex address from string
fn parse_hex_address(s: &str) -> u64 {
    let s = s.trim();
    let s = if s.starts_with("0x") || s.starts_with("0X") {
        &s[2..]
    } else {
        s
    };

    let mut result: u64 = 0;
    for c in s.chars() {
        let digit = match c {
            '0'..='9' => c as u64 - '0' as u64,
            'a'..='f' => c as u64 - 'a' as u64 + 10,
            'A'..='F' => c as u64 - 'A' as u64 + 10,
            '_' => continue, // Allow underscores as separators
            _ => return 0,
        };
        result = result.checked_mul(16).unwrap_or(0);
        result = result.checked_add(digit).unwrap_or(0);
    }
    result
}

/// Show PE information
fn show_pe_info(addr: u64, verbose: bool) {
    use crate::ldr;

    outln!("PE Analysis at {:#x}", addr);
    outln!("");

    unsafe {
        let base = addr as *const u8;

        // Check DOS header
        let dos_header = &*(base as *const ldr::ImageDosHeader);
        if !dos_header.is_valid() {
            outln!("Error: Invalid DOS header (no MZ signature)");
            return;
        }

        // Copy packed fields to avoid unaligned access
        let e_magic = dos_header.e_magic;
        let e_lfanew = dos_header.e_lfanew;

        outln!("DOS Header:");
        outln!("  Magic:        MZ ({:#06x})", e_magic);
        outln!("  PE Offset:    {:#x}", e_lfanew);

        // Parse PE info
        match ldr::parse_pe(base) {
            Ok(info) => {
                outln!("");
                outln!("PE Information:");
                outln!("  Type:         {}", if info.is_64bit { "PE32+ (64-bit)" } else { "PE32 (32-bit)" });
                outln!("  Machine:      {}", machine_name(info.machine));
                outln!("  Image Base:   {:#x}", info.image_base);
                outln!("  Image Size:   {:#x} ({} KB)", info.size_of_image, info.size_of_image / 1024);
                outln!("  Entry Point:  {:#x}", info.entry_point_rva);
                outln!("  Sections:     {}", info.number_of_sections);
                outln!("  Subsystem:    {}", subsystem_name(info.subsystem));
                outln!("  DLL:          {}", if info.is_dll { "Yes" } else { "No" });
                outln!("  Relocatable:  {}", if info.has_relocations { "Yes" } else { "No" });

                if verbose {
                    outln!("");
                    outln!("Additional Info:");
                    outln!("  Section Align:  {:#x}", info.section_alignment);
                    outln!("  File Align:     {:#x}", info.file_alignment);
                    outln!("  Header Size:    {:#x}", info.size_of_headers);
                    outln!("  Stack Reserve:  {:#x}", info.stack_reserve);
                    outln!("  Stack Commit:   {:#x}", info.stack_commit);
                    outln!("  Heap Reserve:   {:#x}", info.heap_reserve);
                    outln!("  Heap Commit:    {:#x}", info.heap_commit);
                    outln!("  DLL Chars:      {:#06x}", info.dll_characteristics);
                }
            }
            Err(e) => {
                outln!("Error parsing PE: {:?}", e);
            }
        }
    }
}

/// Show PE sections
fn show_pe_sections(addr: u64) {
    use crate::ldr;

    outln!("PE Sections at {:#x}", addr);
    outln!("");

    unsafe {
        let base = addr as *const u8;

        match ldr::get_section_headers(base) {
            Some(sections) => {
                outln!("{:<8} {:>10} {:>10} {:>10} {:>10} {:>8}",
                    "Name", "VirtAddr", "VirtSize", "RawAddr", "RawSize", "Flags");
                outln!("------------------------------------------------------------------");

                for section in sections {
                    let name = section.name_str();
                    // Copy packed struct fields to avoid unaligned access
                    let vaddr = section.virtual_address;
                    let vsize = section.virtual_size;
                    let raddr = section.pointer_to_raw_data;
                    let rsize = section.size_of_raw_data;
                    let flags = format_section_flags(section.characteristics);

                    outln!("{:<8} {:#10x} {:#10x} {:#10x} {:#10x} {}",
                        name, vaddr, vsize, raddr, rsize, flags);
                }
            }
            None => {
                outln!("Error: Could not read section headers");
            }
        }
    }
}

/// Format section flags as string
fn format_section_flags(flags: u32) -> &'static str {
    use crate::ldr::section_characteristics::*;

    let r = (flags & IMAGE_SCN_MEM_READ) != 0;
    let w = (flags & IMAGE_SCN_MEM_WRITE) != 0;
    let x = (flags & IMAGE_SCN_MEM_EXECUTE) != 0;

    match (r, w, x) {
        (true, false, false) => "R--",
        (true, true, false) => "RW-",
        (true, false, true) => "R-X",
        (true, true, true) => "RWX",
        (false, false, true) => "--X",
        (false, true, false) => "-W-",
        (false, true, true) => "-WX",
        _ => "---",
    }
}

/// Show PE imports
fn show_pe_imports(addr: u64) {
    use crate::ldr;

    outln!("PE Imports at {:#x}", addr);
    outln!("");

    unsafe {
        let base = addr as *const u8;

        // Get import directory
        match ldr::get_data_directory(base, ldr::directory_entry::IMAGE_DIRECTORY_ENTRY_IMPORT) {
            Some(dir) if dir.is_present() => {
                // Copy packed struct fields
                let dir_rva = dir.virtual_address;
                let dir_size = dir.size;
                outln!("Import Directory RVA: {:#x}, Size: {:#x}", dir_rva, dir_size);
                outln!("");

                // Parse import descriptors
                let import_base = base.add(dir_rva as usize);
                let mut offset = 0usize;
                let mut dll_count = 0;

                loop {
                    let desc = &*(import_base.add(offset) as *const ldr::ImageImportDescriptor);
                    if desc.is_null() {
                        break;
                    }

                    // Get DLL name
                    let name_ptr = base.add(desc.name as usize);
                    let name = cstr_to_str_safe(name_ptr, 128);

                    outln!("  {}", name);
                    dll_count += 1;

                    offset += core::mem::size_of::<ldr::ImageImportDescriptor>();
                    if offset > dir_size as usize {
                        break;
                    }
                }

                outln!("");
                outln!("Total: {} DLLs", dll_count);
            }
            _ => {
                outln!("No import directory found");
            }
        }
    }
}

/// Show PE exports
fn show_pe_exports(addr: u64) {
    use crate::ldr;

    outln!("PE Exports at {:#x}", addr);
    outln!("");

    unsafe {
        let base = addr as *const u8;

        // Get export directory
        match ldr::get_data_directory(base, ldr::directory_entry::IMAGE_DIRECTORY_ENTRY_EXPORT) {
            Some(dir) if dir.is_present() => {
                // Copy packed struct field
                let dir_rva = dir.virtual_address;
                let exports = &*(base.add(dir_rva as usize) as *const ldr::ImageExportDirectory);

                // Copy packed struct fields to avoid unaligned access
                let exp_name = exports.name;
                let exp_base = exports.base;
                let exp_num_funcs = exports.number_of_functions;
                let exp_num_names = exports.number_of_names;
                let exp_addr_names = exports.address_of_names;

                // Get DLL name
                let name_ptr = base.add(exp_name as usize);
                let dll_name = cstr_to_str_safe(name_ptr, 128);

                outln!("DLL Name:     {}", dll_name);
                outln!("Base Ordinal: {}", exp_base);
                outln!("Functions:    {}", exp_num_funcs);
                outln!("Names:        {}", exp_num_names);
                outln!("");

                // List first 20 exports
                let name_table = base.add(exp_addr_names as usize) as *const u32;
                let max_show = (exp_num_names as usize).min(20);

                outln!("Exports (first {}):", max_show);
                for i in 0..max_show {
                    let name_rva = *name_table.add(i);
                    let func_name = cstr_to_str_safe(base.add(name_rva as usize), 64);
                    outln!("  {}", func_name);
                }

                if exp_num_names > 20 {
                    outln!("  ... and {} more", exp_num_names - 20);
                }
            }
            _ => {
                outln!("No export directory found");
            }
        }
    }
}

/// Safe C string to str conversion
unsafe fn cstr_to_str_safe(ptr: *const u8, max_len: usize) -> &'static str {
    if ptr.is_null() {
        return "";
    }

    let mut len = 0;
    while len < max_len && *ptr.add(len) != 0 {
        len += 1;
    }

    core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len))
}

/// Get machine type name
fn machine_name(machine: u16) -> &'static str {
    use crate::ldr::machine_type::*;

    match machine {
        IMAGE_FILE_MACHINE_AMD64 => "AMD64 (x64)",
        IMAGE_FILE_MACHINE_I386 => "Intel 386 (x86)",
        IMAGE_FILE_MACHINE_ARM => "ARM",
        IMAGE_FILE_MACHINE_ARM64 => "ARM64",
        IMAGE_FILE_MACHINE_IA64 => "Intel Itanium",
        _ => "Unknown",
    }
}

/// Get subsystem name
fn subsystem_name(subsystem: u16) -> &'static str {
    use crate::ldr::subsystem::*;

    match subsystem {
        IMAGE_SUBSYSTEM_NATIVE => "Native",
        IMAGE_SUBSYSTEM_WINDOWS_GUI => "Windows GUI",
        IMAGE_SUBSYSTEM_WINDOWS_CUI => "Windows Console",
        IMAGE_SUBSYSTEM_POSIX_CUI => "POSIX Console",
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI => "Windows CE",
        IMAGE_SUBSYSTEM_EFI_APPLICATION => "EFI Application",
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER => "EFI Boot Driver",
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER => "EFI Runtime Driver",
        _ => "Unknown",
    }
}

/// Memory dump command
pub fn cmd_dump(args: &[&str]) {
    if args.is_empty() {
        outln!("Usage: dump <address> [length]");
        outln!("");
        outln!("Dump memory in hex format");
        outln!("  address  Memory address (hex, e.g., 0x1000)");
        outln!("  length   Bytes to dump (default: 256, max: 4096)");
        return;
    }

    let addr = parse_hex_address(args[0]);
    if addr == 0 && args[0] != "0" && args[0] != "0x0" {
        outln!("Invalid address: {}", args[0]);
        return;
    }

    let len = if args.len() > 1 {
        parse_hex_address(args[1]).min(4096) as usize
    } else {
        256
    };

    outln!("Memory dump at {:#x} ({} bytes):", addr, len);
    outln!("");

    unsafe {
        let ptr = addr as *const u8;
        let mut offset = 0usize;

        while offset < len {
            // Print address
            out!("{:016x}  ", addr + offset as u64);

            // Print hex bytes
            for i in 0..16 {
                if offset + i < len {
                    out!("{:02x} ", *ptr.add(offset + i));
                } else {
                    out!("   ");
                }
                if i == 7 {
                    out!(" ");
                }
            }

            out!(" |");

            // Print ASCII
            for i in 0..16 {
                if offset + i < len {
                    let b = *ptr.add(offset + i);
                    if b >= 0x20 && b < 0x7f {
                        out!("{}", b as char);
                    } else {
                        out!(".");
                    }
                }
            }

            outln!("|");
            offset += 16;
        }
    }
}

// ============================================================================
// Loader (LDR) Command
// ============================================================================

/// Loader command - show loader information and load executables
pub fn cmd_ldr(args: &[&str]) {
    use crate::ldr;

    if args.is_empty() {
        outln!("Loader (LDR) Commands");
        outln!("");
        outln!("Usage: ldr <command> [args]");
        outln!("");
        outln!("Commands:");
        outln!("  info               Show loader status");
        outln!("  modules [pid]      List loaded modules for process");
        outln!("  load <addr>        Load PE executable at address");
        outln!("  dll <pid> <addr>   Load DLL into process");
        outln!("  parse <addr>       Parse PE at address (don't load)");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "info") {
        outln!("Loader Information:");
        outln!("");
        outln!("  Subsystem:    Active");
        outln!("  DLL Pool:     {}/{} slots used", ldr::get_loaded_dll_count(), ldr::MAX_DLLS);
        outln!("  Max DLL Size: {} KB", ldr::MAX_DLL_SIZE / 1024);
        outln!("");
        outln!("  Features:");
        outln!("    - PE32/PE32+ parsing");
        outln!("    - Section copying");
        outln!("    - Base relocations");
        outln!("    - Import resolution");
        outln!("    - Export lookup");
        outln!("    - LDR module tracking");
        outln!("    - DLL loading");
    } else if eq_ignore_case(cmd, "modules") {
        // Get process - use PID from args or default to system process
        let process: *mut crate::ps::EProcess = if args.len() > 1 {
            let pid = args[1].parse::<u32>().unwrap_or(0);
            unsafe { crate::ps::ps_lookup_process_by_id(pid) as *mut crate::ps::EProcess }
        } else {
            unsafe { crate::ps::get_system_process() }
        };

        if process.is_null() {
            outln!("Process not found");
            return;
        }

        unsafe {
            let pid = (*process).unique_process_id;
            outln!("Modules for Process {} ({}):", pid,
                core::str::from_utf8_unchecked((*process).image_name()));
            outln!("");

            let peb = (*process).peb;
            if peb.is_null() {
                outln!("  (No PEB - kernel process)");
                return;
            }

            let ldr_data = (*peb).ldr;
            if ldr_data.is_null() {
                outln!("  (No LDR data)");
                return;
            }

            outln!("{:<16} {:<10} {:<12} Name", "Base", "Size", "Entry");
            outln!("------------------------------------------------------------");

            // Walk the InLoadOrderModuleList
            let list_head = &(*ldr_data).in_load_order_module_list as *const crate::ps::ListEntry64;
            let mut current = (*list_head).flink as *const crate::ps::ListEntry64;
            let mut count = 0;

            while current != list_head && count < 32 {
                let entry = current as *const crate::ps::LdrDataTableEntry;

                let base = (*entry).dll_base as u64;
                let size = (*entry).size_of_image;
                let entry_point = (*entry).entry_point as u64;

                // Get module name - need buffer outside of conditionals for lifetime
                let mut name_buf_local = [0u8; 32];
                let base_name = &(*entry).base_dll_name;
                let name_len = if base_name.length > 0 && !base_name.buffer.is_null() {
                    let name_buf = base_name.buffer as *const u16;
                    let len = ((base_name.length / 2) as usize).min(31);
                    for i in 0..len {
                        name_buf_local[i] = (*name_buf.add(i)) as u8;
                    }
                    len
                } else {
                    let unknown = b"<unknown>";
                    name_buf_local[..unknown.len()].copy_from_slice(unknown);
                    unknown.len()
                };
                let name = core::str::from_utf8(&name_buf_local[..name_len]).unwrap_or("?");

                outln!("{:#016x} {:#010x} {:#012x} {}", base, size, entry_point, name);

                current = (*current).flink as *const crate::ps::ListEntry64;
                count += 1;
            }

            if count == 0 {
                outln!("  (No modules loaded)");
            } else {
                outln!("");
                outln!("Total: {} module(s)", count);
            }
        }
    } else if eq_ignore_case(cmd, "dll") {
        if args.len() < 3 {
            outln!("Usage: ldr dll <pid> <address> [name]");
            outln!("");
            outln!("Loads a DLL from the given memory address into the specified process.");
            return;
        }

        let pid = args[1].parse::<u32>().unwrap_or(0);
        let addr = parse_hex_address(args[2]);
        let name = if args.len() > 3 { args[3].as_bytes() } else { b"loaded.dll" };

        if addr == 0 {
            outln!("Invalid address: {}", args[2]);
            return;
        }

        let process = unsafe {
            crate::ps::ps_lookup_process_by_id(pid) as *mut crate::ps::EProcess
        };
        if process.is_null() {
            outln!("Process {} not found", pid);
            return;
        }

        outln!("Loading DLL from {:#x} into process {}...", addr, pid);
        outln!("");

        unsafe {
            let base = addr as *const u8;
            match ldr::parse_pe(base) {
                Ok(info) => {
                    if !info.is_dll {
                        outln!("Error: Not a DLL (is_dll=false)");
                        return;
                    }

                    outln!("DLL validated:");
                    outln!("  Type:    {}", if info.is_64bit { "PE32+" } else { "PE32" });
                    outln!("  Size:    {:#x}", info.size_of_image);
                    outln!("  Entry:   {:#x}", info.entry_point_rva);
                    outln!("");

                    match ldr::load_dll(process, base, info.size_of_image as usize, name) {
                        Ok(loaded) => {
                            outln!("DLL loaded successfully!");
                            outln!("  Base:    {:#x}", loaded.base);
                            outln!("  Size:    {:#x}", loaded.size);
                            outln!("  Entry:   {:#x}", loaded.entry_point);
                        }
                        Err(e) => {
                            outln!("Load failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    outln!("Invalid PE: {:?}", e);
                }
            }
        }
    } else if eq_ignore_case(cmd, "load") {
        if args.len() < 2 {
            outln!("Usage: ldr load <address>");
            outln!("");
            outln!("Loads a PE executable from the given memory address.");
            outln!("Address should point to a valid PE file (e.g., from RAM disk).");
            return;
        }

        let addr = parse_hex_address(args[1]);
        if addr == 0 {
            outln!("Invalid address: {}", args[1]);
            return;
        }

        outln!("Loading PE from {:#x}...", addr);
        outln!("");

        unsafe {
            // First validate it's a PE
            let base = addr as *const u8;
            match ldr::parse_pe(base) {
                Ok(info) => {
                    outln!("PE validated:");
                    outln!("  Type:    {}", if info.is_64bit { "PE32+" } else { "PE32" });
                    outln!("  Size:    {:#x}", info.size_of_image);
                    outln!("  Entry:   {:#x}", info.entry_point_rva);
                    outln!("");

                    // Try to load it
                    match ldr::load_executable(base, info.size_of_image as usize, b"loaded.exe") {
                        Ok(result) => {
                            outln!("Loaded successfully!");
                            outln!("  Process: PID {}", (*result.process).process_id());
                            outln!("  Thread:  TID {}", (*result.thread).thread_id());
                            outln!("  Base:    {:#x}", result.image.base);
                            outln!("  Entry:   {:#x}", result.image.entry_point);
                            outln!("");
                            outln!("Use 'ps start {}' to start the thread.", (*result.thread).thread_id());
                        }
                        Err(e) => {
                            outln!("Load failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    outln!("Invalid PE: {:?}", e);
                }
            }
        }
    } else if eq_ignore_case(cmd, "parse") {
        if args.len() < 2 {
            outln!("Usage: ldr parse <address>");
            return;
        }

        let addr = parse_hex_address(args[1]);
        if addr == 0 {
            outln!("Invalid address: {}", args[1]);
            return;
        }

        // Redirect to pe info command
        outln!("Parsing PE at {:#x}...", addr);
        outln!("");
        show_pe_info(addr, true);
    } else {
        outln!("Unknown ldr command: {}", cmd);
    }
}

// ============================================================================
// User-Mode Test Command
// ============================================================================

/// Test user-mode execution
pub fn cmd_usertest(args: &[&str]) {
    outln!("User-Mode Test");
    outln!("");

    if args.is_empty() {
        outln!("Usage: usertest <command>");
        outln!("");
        outln!("Commands:");
        outln!("  run      Run user-mode test (IRETQ to ring 3)");
        outln!("  info     Show user-mode page table info");
        outln!("  process  Test process creation with PEB/TEB");
        outln!("  teb      Show TEB structure info");
        outln!("  peb      Show PEB structure info");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "run") {
        outln!("Testing user-mode execution...");
        outln!("This will:");
        outln!("  1. Switch to user page tables");
        outln!("  2. IRETQ to ring 3 test code");
        outln!("  3. Test code calls SYSCALL to return");
        outln!("");

        unsafe {
            if !crate::mm::user_pages_initialized() {
                outln!("Error: User page tables not initialized!");
                outln!("Run 'mm init' first to set up user-mode mappings.");
                return;
            }

            outln!("Entering user mode...");
            crate::arch::x86_64::syscall::test_user_mode();
            outln!("User mode test completed.");
        }
    } else if eq_ignore_case(cmd, "info") {
        outln!("User-Mode Page Table Info:");
        outln!("");
        unsafe {
            if crate::mm::user_pages_initialized() {
                let cr3 = crate::mm::get_user_cr3();
                outln!("  User CR3:     {:#x}", cr3);
                outln!("  Test Base:    {:#x}", crate::mm::USER_TEST_BASE);
                outln!("  Stack Top:    {:#x}", crate::mm::USER_STACK_TOP);
                outln!("  Status:       Initialized");
            } else {
                outln!("  Status:       Not initialized");
                outln!("");
                outln!("Use 'mm init' to initialize user-mode page tables.");
            }
        }
    } else if eq_ignore_case(cmd, "process") {
        cmd_usertest_process();
    } else if eq_ignore_case(cmd, "teb") {
        cmd_usertest_teb();
    } else if eq_ignore_case(cmd, "peb") {
        cmd_usertest_peb();
    } else {
        outln!("Unknown usertest command: {}", cmd);
    }
}

/// Test process creation with PEB/TEB
fn cmd_usertest_process() {
    outln!("Testing User Process Creation with PEB/TEB");
    outln!("");

    unsafe {
        use crate::ps;

        // Get system process as parent
        let parent = ps::get_system_process();
        outln!("Parent process: {:p} (PID {})", parent, (*parent).unique_process_id);

        // Create a test user process
        // Use dummy addresses since we're just testing structure creation
        let entry_point = 0x401000u64;  // Typical PE entry point
        let user_stack = 0x7FFE0000u64; // High user stack address
        let image_base = 0x400000u64;   // Standard image base
        let image_size = 0x10000u32;    // 64KB image
        let subsystem = 3u16;           // IMAGE_SUBSYSTEM_WINDOWS_CUI

        outln!("Creating user process...");
        outln!("  Entry point:  {:#x}", entry_point);
        outln!("  User stack:   {:#x}", user_stack);
        outln!("  Image base:   {:#x}", image_base);
        outln!("  Image size:   {:#x}", image_size);
        outln!("  Subsystem:    {} (CUI)", subsystem);
        outln!("");

        let (process, thread) = ps::ps_create_user_process_ex(
            parent,
            b"test.exe",
            entry_point,
            user_stack,
            0, // CR3 - using kernel page tables
            image_base,
            image_size,
            subsystem,
        );

        if process.is_null() {
            outln!("Error: Failed to create process!");
            return;
        }

        outln!("Process created successfully!");
        outln!("  EPROCESS:     {:p}", process);
        outln!("  PID:          {}", (*process).unique_process_id);
        outln!("  Name:         {:?}", core::str::from_utf8_unchecked((*process).image_name()));
        outln!("  PEB:          {:p}", (*process).peb);
        outln!("");

        if !(*process).peb.is_null() {
            let peb = &*(*process).peb;
            outln!("PEB Contents:");
            outln!("  Image base:   {:#x}", peb.image_base_address as u64);
            outln!("  OS Version:   {}.{}.{}", peb.os_major_version, peb.os_minor_version, peb.os_build_number);
            outln!("  Subsystem:    {}", peb.image_subsystem);
            outln!("");
        }

        if thread.is_null() {
            outln!("Warning: Thread creation failed!");
        } else {
            outln!("Thread created successfully!");
            outln!("  ETHREAD:      {:p}", thread);
            outln!("  TID:          {}", (*thread).thread_id());
            outln!("  TEB:          {:p}", (*thread).teb);
            outln!("");

            if !(*thread).teb.is_null() {
                let teb = &*(*thread).teb;
                outln!("TEB Contents:");
                outln!("  Stack base:   {:p}", teb.nt_tib.stack_base);
                outln!("  Stack limit:  {:p}", teb.nt_tib.stack_limit);
                outln!("  PEB pointer:  {:p}", teb.process_environment_block);
                outln!("  PID:          {}", teb.client_id.unique_process);
                outln!("  TID:          {}", teb.client_id.unique_thread);
            }
        }

        outln!("");
        outln!("Per-CPU syscall data:");
        let percpu = crate::arch::x86_64::get_percpu_syscall_data();
        outln!("  Address:      {:#x}", percpu);
        outln!("  (gs:[0] after SWAPGS will read kernel stack from here)");
    }
}

/// Show TEB structure info
fn cmd_usertest_teb() {
    outln!("TEB (Thread Environment Block) Structure");
    outln!("");
    outln!("Size: {} bytes ({:#x})", core::mem::size_of::<crate::ps::Teb>(),
           core::mem::size_of::<crate::ps::Teb>());
    outln!("");
    outln!("Key fields (x64 offsets):");
    outln!("  gs:[0x00]  NT_TIB.ExceptionList");
    outln!("  gs:[0x08]  NT_TIB.StackBase");
    outln!("  gs:[0x10]  NT_TIB.StackLimit");
    outln!("  gs:[0x30]  NT_TIB.Self (TEB pointer)");
    outln!("  gs:[0x60]  ProcessEnvironmentBlock (PEB)");
    outln!("  gs:[0x68]  LastErrorValue");
    outln!("  gs:[0x48]  ClientId.UniqueProcess");
    outln!("  gs:[0x50]  ClientId.UniqueThread");
    outln!("");
    outln!("TLS slots: {} minimum + {} expansion",
           crate::ps::TLS_MINIMUM_AVAILABLE,
           crate::ps::TLS_EXPANSION_SLOTS);
}

/// Show PEB structure info
fn cmd_usertest_peb() {
    outln!("PEB (Process Environment Block) Structure");
    outln!("");
    outln!("Size: {} bytes ({:#x})", core::mem::size_of::<crate::ps::Peb>(),
           core::mem::size_of::<crate::ps::Peb>());
    outln!("");
    outln!("Key fields:");
    outln!("  +0x000  InheritedAddressSpace");
    outln!("  +0x002  BeingDebugged");
    outln!("  +0x010  ImageBaseAddress");
    outln!("  +0x018  Ldr (PEB_LDR_DATA)");
    outln!("  +0x020  ProcessParameters");
    outln!("  +0x118  OSMajorVersion");
    outln!("  +0x11C  OSMinorVersion");
    outln!("  +0x120  OSBuildNumber");
    outln!("  +0x128  ImageSubsystem");
    outln!("");
    outln!("Windows Server 2003 version: 5.2.3790");
}

// ============================================================================
// RTL (Runtime Library) Command
// ============================================================================

/// Runtime Library test command
pub fn cmd_rtl(args: &[&str]) {
    use crate::rtl;

    if args.is_empty() {
        outln!("RTL (Runtime Library) Commands");
        outln!("");
        outln!("Usage: rtl <command> [args]");
        outln!("");
        outln!("Commands:");
        outln!("  info               Show RTL module info");
        outln!("  time               Show current time");
        outln!("  random [count]     Generate random numbers");
        outln!("  crc32 <addr> <len> Calculate CRC32 of memory");
        outln!("  image <addr>       Show PE image info using RTL functions");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "info") {
        outln!("RTL (Runtime Library) Information");
        outln!("");
        outln!("Available modules:");
        outln!("  avl       - AVL tree implementation");
        outln!("  bitmap    - Bit manipulation (RtlBitmap)");
        outln!("  checksum  - CRC32, checksums");
        outln!("  image     - PE image helpers (RtlImageNtHeader, etc.)");
        outln!("  memory    - Memory functions (RtlCopyMemory, etc.)");
        outln!("  random    - Random number generation");
        outln!("  string    - Unicode/ANSI string handling");
        outln!("  time      - Time conversion (RtlTimeToTimeFields)");
        outln!("");
        outln!("Constants:");
        outln!("  TICKS_PER_SECOND:     {}", rtl::TICKS_PER_SECOND);
        outln!("  TICKS_PER_DAY:        {}", rtl::TICKS_PER_DAY);
        outln!("  TICKS_1601_TO_1970:   {}", rtl::TICKS_1601_TO_1970);
    } else if eq_ignore_case(cmd, "time") {
        // Get current system time
        let nt_time = rtl::rtl_get_system_time();

        let mut tf = rtl::TimeFields::new();
        unsafe {
            rtl::rtl_time_to_time_fields(nt_time, &mut tf);
        }

        outln!("System Time:");
        outln!("");
        outln!("  NT Time:    {}", nt_time);
        outln!("  Unix Time:  {}", rtl::nt_time_to_unix_time(nt_time));
        outln!("  Date/Time:  {}", tf);
        outln!("");
        outln!("  Year:       {}", tf.year);
        outln!("  Month:      {}", tf.month);
        outln!("  Day:        {}", tf.day);
        outln!("  Hour:       {}", tf.hour);
        outln!("  Minute:     {}", tf.minute);
        outln!("  Second:     {}", tf.second);
        outln!("  Weekday:    {} (0=Sun)", tf.weekday);
    } else if eq_ignore_case(cmd, "random") {
        let count = if args.len() > 1 {
            args[1].parse::<usize>().unwrap_or(5)
        } else {
            5
        };

        outln!("Random Numbers (count={}):", count);
        outln!("");

        for i in 0..count.min(20) {
            let r = rtl::kernel_random();
            outln!("  [{}] {:#010x} ({})", i, r, r);
        }

        if count > 20 {
            outln!("  ... (showing first 20 of {})", count);
        }
    } else if eq_ignore_case(cmd, "crc32") {
        if args.len() < 3 {
            outln!("Usage: rtl crc32 <address> <length>");
            return;
        }

        let addr = parse_hex_address(args[1]);
        let len = args[2].parse::<usize>().unwrap_or(0);

        if addr == 0 || len == 0 {
            outln!("Invalid address or length");
            return;
        }

        unsafe {
            let ptr = addr as *const u8;
            let data = core::slice::from_raw_parts(ptr, len);
            let crc = rtl::rtl_compute_crc32(0, data);
            outln!("CRC32 of {:#x} ({} bytes): {:#010x}", addr, len, crc);
        }
    } else if eq_ignore_case(cmd, "image") {
        if args.len() < 2 {
            outln!("Usage: rtl image <address>");
            return;
        }

        let addr = parse_hex_address(args[1]);
        if addr == 0 {
            outln!("Invalid address");
            return;
        }

        unsafe {
            let base = addr as *const u8;

            // Get NT header
            let nt_header = rtl::rtl_image_nt_header(base);
            if nt_header.is_null() {
                outln!("Invalid PE image at {:#x}", addr);
                return;
            }

            outln!("PE Image at {:#x}:", addr);
            outln!("");
            outln!("  NT Header:    {:p}", nt_header);
            outln!("  Entry Point:  {:#x}", rtl::rtl_image_entry_point(base));
            outln!("  Image Size:   {:#x}", rtl::rtl_image_size(base));
            outln!("  Is DLL:       {}", rtl::rtl_image_is_dll(base));
            outln!("  Subsystem:    {}", rtl::rtl_image_subsystem(base));

            // Check data directories
            let mut export_size: u32 = 0;
            let export_dir = rtl::rtl_image_export_directory(base, &mut export_size);
            outln!("");
            outln!("Data Directories:");
            outln!("  Export:      {:p} (size={:#x})", export_dir, export_size);

            let mut import_size: u32 = 0;
            let import_dir = rtl::rtl_image_import_directory(base, &mut import_size);
            outln!("  Import:      {:p} (size={:#x})", import_dir, import_size);

            let mut reloc_size: u32 = 0;
            let reloc_dir = rtl::rtl_image_relocation_directory(base, &mut reloc_size);
            outln!("  Relocation:  {:p} (size={:#x})", reloc_dir, reloc_size);
        }
    } else {
        outln!("Unknown rtl command: {}", cmd);
    }
}

// ============================================================================
// Object Manager (OB) Command
// ============================================================================

/// Object Manager test command
pub fn cmd_ob(args: &[&str]) {
    use crate::ob;

    if args.is_empty() {
        outln!("Object Manager (OB) Commands");
        outln!("");
        outln!("Usage: ob <command> [args]");
        outln!("");
        outln!("Commands:");
        outln!("  info               Show OB statistics");
        outln!("  types              List registered object types");
        outln!("  dir [path]         List directory contents");
        outln!("  handles            Show system handle table");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "info") {
        outln!("Object Manager Information");
        outln!("");
        outln!("Constants:");
        outln!("  MAX_OBJECT_TYPES:      {}", ob::MAX_OBJECT_TYPES);
        outln!("  MAX_DIRECTORY_ENTRIES: {}", ob::MAX_DIRECTORY_ENTRIES);
        outln!("  MAX_HANDLES:           {}", ob::MAX_HANDLES);
        outln!("  OB_MAX_NAME_LENGTH:    {}", ob::OB_MAX_NAME_LENGTH);
        outln!("");
        outln!("Well-known type indices:");
        outln!("  TYPE_TYPE:       {}", ob::type_index::TYPE_TYPE);
        outln!("  TYPE_DIRECTORY:  {}", ob::type_index::TYPE_DIRECTORY);
        outln!("  TYPE_PROCESS:    {}", ob::type_index::TYPE_PROCESS);
        outln!("  TYPE_THREAD:     {}", ob::type_index::TYPE_THREAD);
        outln!("  TYPE_EVENT:      {}", ob::type_index::TYPE_EVENT);
        outln!("  TYPE_FILE:       {}", ob::type_index::TYPE_FILE);
        outln!("  TYPE_SECTION:    {}", ob::type_index::TYPE_SECTION);
    } else if eq_ignore_case(cmd, "types") {
        outln!("Registered Object Types:");
        outln!("");
        outln!("{:<5} {:<20} {:<10}", "Idx", "Name", "Objects");
        outln!("---------------------------------------------");

        for i in 1..ob::MAX_OBJECT_TYPES {
            if let Some(obj_type) = ob::get_object_type(i as u8) {
                // Check if type is initialized (has a name)
                let name_bytes = obj_type.name_slice();
                if !name_bytes.is_empty() {
                    let name = core::str::from_utf8(name_bytes).unwrap_or("?");
                    outln!("{:<5} {:<20} {:<10}",
                           i,
                           name,
                           obj_type.get_object_count());
                }
            }
        }
    } else if eq_ignore_case(cmd, "dir") {
        let path = if args.len() > 1 { args[1] } else { "\\" };

        outln!("Directory: {}", path);
        outln!("");

        unsafe {
            // Get the appropriate directory
            let dir = if path == "\\" || path == "/" {
                ob::get_root_directory()
            } else if path == "\\ObjectTypes" || path == "/ObjectTypes" {
                ob::get_object_types_directory()
            } else if path == "\\Device" || path == "/Device" {
                ob::get_device_directory()
            } else if path == "\\BaseNamedObjects" || path == "/BaseNamedObjects" {
                ob::get_base_named_objects()
            } else {
                outln!("Unknown directory: {}", path);
                outln!("Known directories: \\, \\ObjectTypes, \\Device, \\BaseNamedObjects");
                return;
            };

            if dir.is_null() {
                outln!("  (Directory not found)");
                return;
            }

            outln!("{:<20} {:<18} {:<10}", "Name", "Object", "Type");
            outln!("----------------------------------------------------");

            let mut count = 0;
            for obj_ptr in (*dir).iter() {
                // Get object header to retrieve name and type
                let header = ob::ObjectHeader::from_body(obj_ptr);

                // Get name if available
                let mut name_buf = [0u8; 32];
                let name = if let Some(n) = (*header).get_name() {
                    let len = n.len().min(name_buf.len());
                    name_buf[..len].copy_from_slice(&n[..len]);
                    core::str::from_utf8(&name_buf[..len]).unwrap_or("?")
                } else {
                    "<unnamed>"
                };

                // Get type name
                let type_name = if let Some(t) = (*header).get_type() {
                    let name_bytes = t.name_slice();
                    core::str::from_utf8(name_bytes).unwrap_or("?")
                } else {
                    "?"
                };

                outln!("{:<20} {:p} {:<10}", name, obj_ptr, type_name);
                count += 1;
            }

            if count == 0 {
                outln!("  (Empty directory)");
            } else {
                outln!("");
                outln!("Total: {} entries", count);
            }
        }
    } else if eq_ignore_case(cmd, "handles") {
        outln!("System Handle Table");
        outln!("");

        unsafe {
            let table = ob::get_system_handle_table();

            if table.is_null() {
                outln!("  (Handle table not found)");
                return;
            }

            outln!("{:<10} {:<10} {:p}", "Handle", "Access", "Object");
            outln!("------------------------------------------");

            let mut count = 0;
            for i in 0..ob::MAX_HANDLES {
                // get_entry takes Handle (u32), not index
                let handle = (i as u32) * ob::HANDLE_INCREMENT;
                if let Some(entry) = (*table).get_entry(handle) {
                    outln!("{:#010x} {:#010x} {:p}",
                           handle,
                           entry.access_mask,
                           entry.object);
                    count += 1;

                    if count >= 20 {
                        outln!("  ... (showing first 20 handles)");
                        break;
                    }
                }
            }

            if count == 0 {
                outln!("  (No handles)");
            } else {
                outln!("");
                outln!("Total shown: {} handles", count);
            }
        }
    } else {
        outln!("Unknown ob command: {}", cmd);
    }
}
