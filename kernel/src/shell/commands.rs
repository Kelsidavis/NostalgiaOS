//! Shell Commands
//!
//! Implementation of all built-in shell commands.

use crate::serial_println;
use crate::fs;
use super::{get_current_dir, set_current_dir};

/// Display help information
pub fn cmd_help(args: &[&str]) {
    if args.is_empty() {
        serial_println!("Nostalgia OS Shell Commands:");
        serial_println!("");
        serial_println!("  General:");
        serial_println!("    help [cmd]     Show help (or help for specific command)");
        serial_println!("    ver            Show version information");
        serial_println!("    echo [text]    Display text");
        serial_println!("    cls, clear     Clear the screen");
        serial_println!("    exit           Exit the shell");
        serial_println!("");
        serial_println!("  File System:");
        serial_println!("    dir, ls [pat]  List directory (supports *, ? wildcards)");
        serial_println!("    cd [path]      Change directory");
        serial_println!("    pwd            Print working directory");
        serial_println!("    type, cat      Display file contents");
        serial_println!("    mkdir [name]   Create directory");
        serial_println!("    rmdir [name]   Remove directory");
        serial_println!("    del, rm [file] Delete file");
        serial_println!("    copy [s] [d]   Copy file");
        serial_println!("    ren [old] [new] Rename file");
        serial_println!("    touch [file]   Create empty file");
        serial_println!("");
        serial_println!("  System:");
        serial_println!("    mem            Show memory usage");
        serial_println!("    time           Show system time");
        serial_println!("    ps, tasks      Show running threads");
        serial_println!("    history        Show command history");
        serial_println!("    reboot         Restart the system");
        serial_println!("");
        serial_println!("  Use UP/DOWN arrows to navigate command history.");
    } else {
        let topic = args[0];
        if eq_ignore_case(topic, "dir") || eq_ignore_case(topic, "ls") {
            serial_println!("DIR [path] [pattern]");
            serial_println!("  Lists files and directories.");
            serial_println!("  If no path given, lists current directory.");
            serial_println!("");
            serial_println!("  Wildcards:");
            serial_println!("    *      Matches any characters");
            serial_println!("    ?      Matches single character");
            serial_println!("");
            serial_println!("  Examples:");
            serial_println!("    DIR *.TXT      List all .TXT files");
            serial_println!("    DIR TEST*.*    List files starting with TEST");
            serial_println!("    DIR C:\\*.EXE   List .EXE files in C:\\");
        } else if eq_ignore_case(topic, "cd") {
            serial_println!("CD [path]");
            serial_println!("  Changes the current directory.");
            serial_println!("  CD ..    Go to parent directory");
            serial_println!("  CD \\     Go to root directory");
        } else if eq_ignore_case(topic, "type") || eq_ignore_case(topic, "cat") {
            serial_println!("TYPE <filename>");
            serial_println!("  Displays the contents of a text file.");
        } else if eq_ignore_case(topic, "copy") || eq_ignore_case(topic, "cp") {
            serial_println!("COPY <source> <dest>");
            serial_println!("  Copies a file to a new location.");
        } else {
            serial_println!("No help available for '{}'", args[0]);
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
static mut PATH_LEN2: usize = 0;

/// Build a path by combining directory and filename
fn build_path(dir: &str, filename: &str) -> &'static str {
    unsafe {
        PATH_LEN2 = 0;

        // Copy directory
        for &b in dir.as_bytes() {
            if PATH_LEN2 < PATH_BUFFER2.len() - 1 {
                PATH_BUFFER2[PATH_LEN2] = b;
                PATH_LEN2 += 1;
            }
        }

        // Add separator if needed
        if PATH_LEN2 > 0 && PATH_BUFFER2[PATH_LEN2 - 1] != b'\\' {
            if PATH_LEN2 < PATH_BUFFER2.len() - 1 {
                PATH_BUFFER2[PATH_LEN2] = b'\\';
                PATH_LEN2 += 1;
            }
        }

        // Copy filename
        for &b in filename.as_bytes() {
            if PATH_LEN2 < PATH_BUFFER2.len() - 1 {
                PATH_BUFFER2[PATH_LEN2] = b;
                PATH_LEN2 += 1;
            }
        }

        core::str::from_utf8_unchecked(&PATH_BUFFER2[..PATH_LEN2])
    }
}

/// Display version information
pub fn cmd_version() {
    serial_println!("");
    serial_println!("Nostalgia OS [Version 0.1.0]");
    serial_println!("An NT-style kernel written in Rust");
    serial_println!("");
    serial_println!("Kernel build info:");
    serial_println!("  Architecture: x86_64");
    serial_println!("  Compiler: rustc (nightly)");
    serial_println!("");
}

/// Echo text to the console
pub fn cmd_echo(args: &[&str]) {
    if args.is_empty() {
        serial_println!("");
    } else {
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                crate::serial_print!(" ");
            }
            crate::serial_print!("{}", arg);
        }
        serial_println!("");
    }
}

/// Clear the screen
pub fn cmd_clear() {
    // ANSI escape sequence to clear screen and move cursor home
    crate::serial_print!("\x1B[2J\x1B[H");
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

    serial_println!("");
    if let Some(pat) = pattern {
        serial_println!(" Directory of {}  ({})", full_path, pat);
    } else {
        serial_println!(" Directory of {}", full_path);
    }
    serial_println!("");

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
                        serial_println!("{}           {}", type_str, name);
                    } else {
                        serial_println!("{}{:>10}  {}", type_str, entry.size, name);
                    }
                }

                offset = entry.next_offset;
            }
            Err(fs::FsStatus::NoMoreEntries) => break,
            Err(e) => {
                serial_println!("Error reading directory: {:?}", e);
                return;
            }
        }
    }

    if shown_count == 0 && pattern.is_some() {
        serial_println!("File Not Found");
    }

    serial_println!("");
    serial_println!("     {:>4} File(s)    {:>10} bytes", file_count, total_size);
    serial_println!("     {:>4} Dir(s)", dir_count);
    serial_println!("");
}

/// Change directory
pub fn cmd_cd(args: &[&str]) {
    if args.is_empty() {
        // Just print current directory
        serial_println!("{}", get_current_dir());
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
            serial_println!("The system cannot find the path specified.");
        }
        Err(fs::FsStatus::NotDirectory) => {
            serial_println!("The directory name is invalid.");
        }
        Err(e) => {
            serial_println!("Error: {:?}", e);
        }
    }
}

/// Print working directory
pub fn cmd_pwd() {
    serial_println!("{}", get_current_dir());
}

/// Display file contents
pub fn cmd_cat(args: &[&str]) {
    if args.is_empty() {
        serial_println!("Usage: type <filename>");
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
                                serial_println!("");
                            } else if byte == b'\r' {
                                // Skip carriage return
                            } else if byte >= 0x20 && byte < 0x7F {
                                crate::serial_print!("{}", byte as char);
                            } else if byte == b'\t' {
                                crate::serial_print!("    ");
                            }
                        }
                    }
                    Err(fs::FsStatus::EndOfFile) => break,
                    Err(e) => {
                        serial_println!("");
                        serial_println!("Error reading file: {:?}", e);
                        break;
                    }
                }
            }
            serial_println!("");
            let _ = fs::close(handle);
        }
        Err(fs::FsStatus::NotFound) => {
            serial_println!("The system cannot find the file specified.");
        }
        Err(e) => {
            serial_println!("Error opening file: {:?}", e);
        }
    }
}

/// Create a directory
pub fn cmd_mkdir(args: &[&str]) {
    if args.is_empty() {
        serial_println!("Usage: mkdir <dirname>");
        return;
    }

    let full_path = resolve_path(args[0]);

    match fs::mkdir(&full_path) {
        Ok(()) => {
            // Success - no output
        }
        Err(fs::FsStatus::AlreadyExists) => {
            serial_println!("A subdirectory or file {} already exists.", args[0]);
        }
        Err(e) => {
            serial_println!("Error creating directory: {:?}", e);
        }
    }
}

/// Remove a directory
pub fn cmd_rmdir(args: &[&str]) {
    if args.is_empty() {
        serial_println!("Usage: rmdir <dirname>");
        return;
    }

    let full_path = resolve_path(args[0]);

    match fs::rmdir(&full_path) {
        Ok(()) => {
            // Success - no output
        }
        Err(fs::FsStatus::NotFound) => {
            serial_println!("The system cannot find the path specified.");
        }
        Err(fs::FsStatus::DirectoryNotEmpty) => {
            serial_println!("The directory is not empty.");
        }
        Err(e) => {
            serial_println!("Error removing directory: {:?}", e);
        }
    }
}

/// Delete a file
pub fn cmd_del(args: &[&str]) {
    if args.is_empty() {
        serial_println!("Usage: del <filename>");
        serial_println!("  Wildcards * and ? are supported.");
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
            serial_println!("Could not find the file specified.");
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
                    serial_println!("Error deleting {}: {:?}", name, e);
                    error_count += 1;
                }
            }
        }

        if deleted_count > 0 || error_count > 0 {
            serial_println!("{} file(s) deleted.", deleted_count);
        }
    } else {
        // No wildcards - single file delete
        let full_path = resolve_path(arg);

        match fs::delete(&full_path) {
            Ok(()) => {
                // Success - no output (DOS behavior)
            }
            Err(fs::FsStatus::NotFound) => {
                serial_println!("Could not find the file specified.");
            }
            Err(e) => {
                serial_println!("Error deleting file: {:?}", e);
            }
        }
    }
}

/// Copy a file
pub fn cmd_copy(args: &[&str]) {
    if args.len() < 2 {
        serial_println!("Usage: copy <source> <dest>");
        serial_println!("  Wildcards * and ? are supported in source.");
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
            serial_println!("The system cannot find the file specified.");
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
                serial_println!("Cannot copy multiple files to a single file.");
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
                    serial_println!("Error copying {}: {:?}", name, e);
                }
            }
        }

        serial_println!("        {} file(s) copied ({} bytes).", copied_count, total_bytes);
    } else {
        // No wildcards - single file copy
        let src_path = resolve_path(src_arg);
        let dst_path = resolve_path(dst_arg);

        match fs::copy(&src_path, &dst_path) {
            Ok(bytes) => {
                serial_println!("        1 file(s) copied ({} bytes).", bytes);
            }
            Err(fs::FsStatus::NotFound) => {
                serial_println!("The system cannot find the file specified.");
            }
            Err(e) => {
                serial_println!("Error copying file: {:?}", e);
            }
        }
    }
}

/// Rename a file or directory
pub fn cmd_rename(args: &[&str]) {
    if args.len() < 2 {
        serial_println!("Usage: ren <oldname> <newname>");
        return;
    }

    let old_path = resolve_path(args[0]);
    let new_path = resolve_path(args[1]);

    match fs::rename(&old_path, &new_path) {
        Ok(()) => {
            // Success - no output
        }
        Err(fs::FsStatus::NotFound) => {
            serial_println!("The system cannot find the file specified.");
        }
        Err(e) => {
            serial_println!("Error renaming: {:?}", e);
        }
    }
}

/// Create an empty file
pub fn cmd_touch(args: &[&str]) {
    if args.is_empty() {
        serial_println!("Usage: touch <filename>");
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
            serial_println!("Error creating file: {:?}", e);
        }
    }
}

/// Show memory usage
pub fn cmd_mem() {
    serial_println!("");
    serial_println!("Memory Status:");
    serial_println!("");

    // Get memory stats from MM
    let stats = crate::mm::mm_get_stats();

    serial_println!("  Physical Memory:");
    serial_println!("    Total:     {} KB ({} pages)", stats.total_pages * 4, stats.total_pages);
    serial_println!("    Free:      {} KB ({} pages)", stats.free_pages * 4, stats.free_pages);
    serial_println!("    Zeroed:    {} KB ({} pages)", stats.zeroed_pages * 4, stats.zeroed_pages);
    serial_println!("    Active:    {} KB ({} pages)", stats.active_pages * 4, stats.active_pages);
    serial_println!("");
    serial_println!("  Memory Totals:");
    serial_println!("    Total:     {} bytes", stats.total_bytes());
    serial_println!("    Free:      {} bytes", stats.free_bytes());
    serial_println!("    Used:      {} bytes", stats.used_bytes());
    serial_println!("");
}

/// Show system time (tick count)
pub fn cmd_time() {
    let ticks = crate::hal::apic::get_tick_count();
    let seconds = ticks / 1000;
    let ms = ticks % 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;

    serial_println!("System uptime: {}:{:02}:{:02}.{:03}",
        hours,
        minutes % 60,
        seconds % 60,
        ms
    );
    serial_println!("Total ticks: {}", ticks);
}

/// Show running threads
pub fn cmd_ps() {
    serial_println!("");
    serial_println!("  TID  State      Priority  Name");
    serial_println!("  ---  -----      --------  ----");

    // Get thread list from scheduler
    unsafe {
        crate::ke::scheduler::list_threads();
    }
    serial_println!("");
}

/// Reboot the system
pub fn cmd_reboot() {
    serial_println!("Rebooting...");

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

/// Path buffer for resolved paths
static mut PATH_BUFFER: [u8; 128] = [0u8; 128];
static mut PATH_LEN: usize = 0;

/// Resolve a path relative to current directory
/// Returns a static string reference (not thread-safe, but OK for single shell)
fn resolve_path(path: &str) -> &'static str {
    unsafe {
        PATH_LEN = 0;

        // Helper to append to path buffer
        let mut append = |s: &str| {
            for &b in s.as_bytes() {
                if PATH_LEN < PATH_BUFFER.len() {
                    // Convert forward slash to backslash
                    PATH_BUFFER[PATH_LEN] = if b == b'/' { b'\\' } else { b };
                    PATH_LEN += 1;
                }
            }
        };

        // If path starts with drive letter, it's absolute
        if path.len() >= 2 && path.as_bytes()[1] == b':' {
            append(path);
            return core::str::from_utf8_unchecked(&PATH_BUFFER[..PATH_LEN]);
        }

        // If path starts with backslash, it's relative to drive root
        if path.starts_with('\\') || path.starts_with('/') {
            let current = get_current_dir();
            if current.len() >= 2 {
                // Add drive letter
                PATH_BUFFER[0] = current.as_bytes()[0];
                PATH_BUFFER[1] = b':';
                PATH_LEN = 2;
                append(path);
                return core::str::from_utf8_unchecked(&PATH_BUFFER[..PATH_LEN]);
            }
        }

        // Relative path - append to current directory
        let current = get_current_dir();
        append(current);

        // Ensure current dir ends with backslash
        if PATH_LEN > 0 && PATH_BUFFER[PATH_LEN - 1] != b'\\' {
            if PATH_LEN < PATH_BUFFER.len() {
                PATH_BUFFER[PATH_LEN] = b'\\';
                PATH_LEN += 1;
            }
        }

        append(path);
        core::str::from_utf8_unchecked(&PATH_BUFFER[..PATH_LEN])
    }
}
