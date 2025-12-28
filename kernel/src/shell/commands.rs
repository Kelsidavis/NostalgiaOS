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
        serial_println!("    dir, ls [path] List directory contents");
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
        serial_println!("    reboot         Restart the system");
    } else {
        let topic = args[0];
        if eq_ignore_case(topic, "dir") || eq_ignore_case(topic, "ls") {
            serial_println!("DIR [path]");
            serial_println!("  Lists files and directories.");
            serial_println!("  If no path given, lists current directory.");
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

/// List directory contents
pub fn cmd_ls(args: &[&str]) {
    let path = if args.is_empty() {
        get_current_dir()
    } else {
        args[0]
    };

    // Resolve path
    let full_path = resolve_path(path);

    serial_println!("");
    serial_println!(" Directory of {}", full_path);
    serial_println!("");

    let mut offset = 0u32;
    let mut file_count = 0u32;
    let mut dir_count = 0u32;
    let mut total_size = 0u64;

    loop {
        match fs::readdir(&full_path, offset) {
            Ok(entry) => {
                let name = entry.name_str();

                // Skip . and .. entries
                if name == "." || name == ".." {
                    offset = entry.next_offset;
                    continue;
                }

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

                offset = entry.next_offset;
            }
            Err(fs::FsStatus::NoMoreEntries) => break,
            Err(e) => {
                serial_println!("Error reading directory: {:?}", e);
                return;
            }
        }
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
        return;
    }

    let full_path = resolve_path(args[0]);

    match fs::delete(&full_path) {
        Ok(()) => {
            // Success - no output
        }
        Err(fs::FsStatus::NotFound) => {
            serial_println!("Could not find the file specified.");
        }
        Err(e) => {
            serial_println!("Error deleting file: {:?}", e);
        }
    }
}

/// Copy a file
pub fn cmd_copy(args: &[&str]) {
    if args.len() < 2 {
        serial_println!("Usage: copy <source> <dest>");
        return;
    }

    let src_path = resolve_path(args[0]);
    let dst_path = resolve_path(args[1]);

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
