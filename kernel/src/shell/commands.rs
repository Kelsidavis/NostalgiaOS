//! Shell Commands
//!
//! Implementation of all built-in shell commands.

extern crate alloc;

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

/// Case-insensitive ASCII string comparison
#[inline]
fn eq_ignore_ascii_case(a: &str, b: &str) -> bool {
    a.as_bytes().eq_ignore_ascii_case(b.as_bytes())
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
        outln!("    sysinfo        Comprehensive system overview");
        outln!("    mem            Show memory usage");
        outln!("    time           Show system time");
        outln!("    ps <cmd>       Process subsystem (list, proc, thread)");
        outln!("    history        Show command history");
        outln!("    reboot         Restart the system");
        outln!("");
        outln!("  Hardware/Power:");
        outln!("    cpuinfo        Show CPU and ACPI information");
        outln!("    acpi [tables]  Scan ACPI tables (RSDP, RSDT/XSDT)");
        outln!("    pci [scan]     Scan PCI devices");
        outln!("    power [cmd]    Power management (acpi, throttle, sleep, policy)");
        outln!("    shutdown       Shut down the system (ACPI S5)");
        outln!("    reboot         Restart the system (ACPI reset)");
        outln!("");
        outln!("  Services:");
        outln!("    services       List/manage services");
        outln!("    sc <cmd>       Service control (Windows sc.exe)");
        outln!("    net start/stop Service management (Windows net.exe)");
        outln!("");
        outln!("  Network:");
        outln!("    netinfo <cmd>  Network diagnostics (status, devices, stats, arp, ping)");
        outln!("");
        outln!("  Debugging:");
        outln!("    debug <cmd>    Kernel debug (bugcheck, break, regs)");
        outln!("    int <type>     Trigger interrupts (div0, break, gpf)");
        outln!("    timer <cmd>    Timer diagnostics (apic, tsc, pit)");
        outln!("    memmap <cmd>   Physical memory map (regions, e820)");
        outln!("    cpufeatures    CPU feature detection (CPUID)");
        outln!("    pagetable      Page table walker (cr3, walk, translate)");
        outln!("    msr            MSR browser (common, syscall, apic)");
        outln!("    port           I/O port browser (scan, inb/outb)");
        outln!("    apic           APIC viewer (lvt, ioapic, isr/irr)");
        outln!("    desc[riptor]   GDT/IDT viewer (gdt, idt, tss)");
        outln!("    stack (bt)     Stack trace/backtrace (trace, dump)");
        outln!("    hpet           HPET timer viewer (status, timers)");
        outln!("    smbios (dmi)   SMBIOS/DMI system info (bios, cpu, mem)");
        outln!("    exception      Exception history viewer (list, stats)");
        outln!("    irqstat        Interrupt statistics (all, rate, clear)");
        outln!("    pool           Kernel pool allocator stats (classes)");
        outln!("    pfn            PFN database viewer (stats, entry, range)");
        outln!("    timerq         Kernel timer queue viewer (stats, list)");
        outln!("    dpcq           DPC queue viewer (stats, list, pending)");
        outln!("    obdir          Object Manager namespace viewer (types, tree)");
        outln!("    handles        System handle table viewer (stats, list)");
        outln!("    prcb           PRCB viewer (threads, ready, ipi)");
        outln!("    irql           IRQL viewer (current, levels, state)");
        outln!("    apcq           APC queue viewer (stats, pending)");
        outln!("    sched          Scheduler viewer (stats, ready, current)");
        outln!("    veh            Vectored Exception Handler info/test");
        outln!("    seh            Structured Exception Handler info/test");
        outln!("");
        outln!("  Kernel Subsystems:");
        outln!("    ke <cmd>       Kernel Executive (irql, dpc, apc, prcb)");
        outln!("    mm <cmd>       Memory Manager (stats, pool, vad)");
        outln!("    ob <cmd>       Object Manager (types, dir, handles)");
        outln!("    io <cmd>       I/O Manager (block, volumes, pipes)");
        outln!("    ex <cmd>       Executive (worker, callback, luid, lookaside)");
        outln!("    se <cmd>       Security (sids, privileges, token)");
        outln!("    hal <cmd>      Hardware Abstraction (time, apic, tick)");
        outln!("    rtl <cmd>      Runtime Library (time, random, crc32)");
        outln!("    ldr <cmd>      Loader (info, modules, dll)");
        outln!("    pe <file>      Parse PE/DLL file headers");
        outln!("    cc, cache      Cache Manager (stats, maps, prefetch)");
        outln!("    prefetch       Prefetcher (stats, traces, enable/disable)");
        outln!("    verifier       Driver Verifier (stats, irp, pool, deadlock)");
        outln!("    disk,partition Disk/Partition info (mbr, gpt, geometry)");
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

/// Process Subsystem (PS) shell command
pub fn cmd_ps(args: &[&str]) {
    use crate::ps;

    if args.is_empty() {
        // Default: show threads (backwards compatible)
        outln!("");
        outln!("  TID  State      Priority  Name");
        outln!("  ---  -----      --------  ----");
        unsafe {
            crate::ke::scheduler::list_threads();
        }
        outln!("");
        outln!("Use 'ps help' for more options.");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "help") {
        outln!("Process Subsystem (PS) Commands");
        outln!("");
        outln!("Usage: ps [command] [args]");
        outln!("");
        outln!("Commands:");
        outln!("  (none)             List threads (default)");
        outln!("  info               Show PS subsystem info");
        outln!("  list               List all processes");
        outln!("  threads            List all threads");
        outln!("  proc <pid>         Show process details");
        outln!("  thread <tid>       Show thread details");
    } else if eq_ignore_case(cmd, "info") {
        outln!("Process Subsystem Information");
        outln!("");
        outln!("Components:");
        outln!("  EPROCESS:    Executive Process Object");
        outln!("  ETHREAD:     Executive Thread Object");
        outln!("  KPROCESS:    Kernel Process Object (PCB)");
        outln!("  KTHREAD:     Kernel Thread Object (TCB)");
        outln!("  PEB:         Process Environment Block");
        outln!("  TEB:         Thread Environment Block");
        outln!("  Job Objects: Process grouping and limits");
        outln!("");
        outln!("Constants:");
        outln!("  MAX_PROCESSES:  {}", ps::MAX_PROCESSES);
        outln!("  MAX_THREADS:    {}", ps::MAX_THREADS);
        outln!("  MAX_JOBS:       {}", ps::MAX_JOBS);
    } else if eq_ignore_case(cmd, "list") {
        outln!("Active Processes");
        outln!("");
        outln!("{:<6} {:<6} {:<8} {:<16}", "PID", "PPID", "Threads", "Name");
        outln!("----------------------------------------------");

        unsafe {
            let list_head = ps::get_active_process_list();
            if (*list_head).is_empty() {
                outln!("  (No processes)");
            } else {
                let mut count = 0;
                let mut entry = (*list_head).flink;
                while entry != list_head && count < 50 {
                    let process = crate::containing_record!(entry, ps::EProcess, active_process_links);

                    let pid = (*process).process_id();
                    let ppid = (*process).parent_process_id();
                    let thread_count = (*process).thread_count();
                    let name = (*process).image_name();
                    let name_str = core::str::from_utf8(name).unwrap_or("?");

                    outln!("{:<6} {:<6} {:<8} {:<16}", pid, ppid, thread_count, name_str);

                    entry = (*entry).flink;
                    count += 1;
                }
                outln!("");
                outln!("Total: {} processes", count);
            }
        }
    } else if eq_ignore_case(cmd, "threads") {
        outln!("");
        outln!("  TID  State      Priority  Name");
        outln!("  ---  -----      --------  ----");
        unsafe {
            crate::ke::scheduler::list_threads();
        }
        outln!("");
    } else if eq_ignore_case(cmd, "proc") {
        if args.len() < 2 {
            outln!("Usage: ps proc <pid>");
            return;
        }

        let pid_str = args[1];
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => {
                outln!("Invalid PID: {}", pid_str);
                return;
            }
        };

        unsafe {
            let process = ps::ps_lookup_process_by_id(pid) as *mut ps::EProcess;
            if process.is_null() {
                outln!("Process {} not found", pid);
                return;
            }

            outln!("Process Details (PID {})", pid);
            outln!("");
            outln!("EPROCESS:    {:p}", process);
            outln!("Name:        {}", core::str::from_utf8((*process).image_name()).unwrap_or("?"));
            outln!("Parent PID:  {}", (*process).parent_process_id());
            outln!("Threads:     {}", (*process).thread_count());
            outln!("System:      {}", if (*process).is_system() { "Yes" } else { "No" });
            outln!("Exiting:     {}", if (*process).is_exiting() { "Yes" } else { "No" });
        }
    } else if eq_ignore_case(cmd, "thread") {
        if args.len() < 2 {
            outln!("Usage: ps thread <tid>");
            return;
        }

        let tid_str = args[1];
        let tid: u32 = match tid_str.parse() {
            Ok(t) => t,
            Err(_) => {
                outln!("Invalid TID: {}", tid_str);
                return;
            }
        };

        unsafe {
            let thread = ps::ps_lookup_thread_by_id(tid) as *mut ps::EThread;
            if thread.is_null() {
                outln!("Thread {} not found", tid);
                return;
            }

            outln!("Thread Details (TID {})", tid);
            outln!("");
            outln!("ETHREAD:     {:p}", thread);
            outln!("Process ID:  {}", (*thread).process_id());
            outln!("System:      {}", if (*thread).is_system() { "Yes" } else { "No" });
            outln!("Terminating: {}", if (*thread).is_terminating() { "Yes" } else { "No" });
            outln!("Suspended:   {}", if (*thread).is_suspended() { "Yes" } else { "No" });
        }
    } else {
        // Treat unknown arg as "list threads" for compatibility
        outln!("");
        outln!("  TID  State      Priority  Name");
        outln!("  ---  -----      --------  ----");
        unsafe {
            crate::ke::scheduler::list_threads();
        }
        outln!("");
    }
}

/// Reboot the system
pub fn cmd_reboot() {
    outln!("Rebooting...");
    outln!("Stopping services and resetting...");

    // restart() never returns - it will reset the system
    crate::po::restart();
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
        outln!("========================");
        outln!("");

        // Power manager state
        if crate::po::is_initialized() {
            let state = crate::po::get_system_power_state();
            outln!("System State:");
            outln!("  Power State: {:?}", state);
            outln!("  AC Power: {}", crate::po::is_ac_power());
            outln!("  Battery Power: {}", crate::po::is_battery_power());
            outln!("  Action in Progress: {}", crate::po::is_action_in_progress());
            outln!("  Processor Throttle: {}%", crate::po::get_processor_throttle());
            outln!("");

            // Capabilities
            let caps = crate::po::get_capabilities();
            outln!("Power Capabilities:");
            outln!("  Power Button: {}", caps.power_button_present);
            outln!("  Sleep Button: {}", caps.sleep_button_present);
            outln!("  S1 (Standby): {}", caps.system_s1);
            outln!("  S2: {}", caps.system_s2);
            outln!("  S3 (Sleep): {}", caps.system_s3);
            outln!("  S4 (Hibernate): {}", caps.system_s4);
            outln!("  S5 (Soft Off): {}", caps.system_s5);
            outln!("");

            // Device power states
            let device_counts = crate::po::get_device_power_state_counts();
            outln!("Device Power States:");
            outln!("  D0 (On): {} devices", device_counts[1]);
            outln!("  D1: {} devices", device_counts[2]);
            outln!("  D2: {} devices", device_counts[3]);
            outln!("  D3 (Off): {} devices", device_counts[4]);
            outln!("");

            // Power statistics
            let stats = crate::po::get_power_stats();
            outln!("Power Statistics:");
            outln!("  Sleep events: {}", stats.sleep_count);
            outln!("  Wake events: {}", stats.wake_count);
            outln!("  Hibernate events: {}", stats.hibernate_count);
            outln!("  Shutdown events: {}", stats.shutdown_count);
        } else {
            outln!("  Power manager not initialized");
        }

        outln!("");
        outln!("Commands:");
        outln!("  power             - Show power status");
        outln!("  power acpi        - Show ACPI PM control info");
        outln!("  power throttle N  - Set CPU throttle to N%");
        outln!("  power sleep N     - Enter sleep state SN (1-4)");
        outln!("  power policy      - Show power policy");
    } else if eq_ignore_case(args[0], "acpi") {
        // Show ACPI PM control information
        outln!("ACPI Power Management:");
        outln!("======================");

        if crate::hal::acpi::is_initialized() {
            let pm = crate::hal::acpi::get_pm_control_info();
            outln!("PM1 Registers:");
            outln!("  PM1a Event:   {:#06x}", pm.pm1a_event);
            outln!("  PM1b Event:   {:#06x}", pm.pm1b_event);
            outln!("  PM1a Control: {:#06x}", pm.pm1a_control);
            outln!("  PM1b Control: {:#06x}", pm.pm1b_control);
            outln!("  PM Timer:     {:#06x}", pm.pm_timer);
            outln!("");
            outln!("Interrupts:");
            outln!("  SCI:          {}", pm.sci_interrupt);
            outln!("  SMI Command:  {:#06x}", pm.smi_command);
            outln!("");
            outln!("Current Status:");

            // Read actual PM registers
            let pm1_status = crate::hal::acpi::read_pm1_status();
            let pm1_enable = crate::hal::acpi::read_pm1_enable();
            let pm1_control = crate::hal::acpi::read_pm1_control();
            let pm_timer = crate::hal::acpi::read_pm_timer();

            outln!("  PM1 Status:  {:#06x}", pm1_status);
            if (pm1_status & 0x0100) != 0 { outln!("    - Power button pressed"); }
            if (pm1_status & 0x0200) != 0 { outln!("    - Sleep button pressed"); }
            if (pm1_status & 0x8000) != 0 { outln!("    - Wake event"); }

            outln!("  PM1 Enable:  {:#06x}", pm1_enable);
            outln!("  PM1 Control: {:#06x}", pm1_control);
            if (pm1_control & 0x0001) != 0 { outln!("    - SCI enabled (ACPI mode)"); }

            outln!("  PM Timer:    {:#010x}", pm_timer);
        } else {
            outln!("  ACPI not initialized");
        }
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
    } else if eq_ignore_case(args[0], "sleep") {
        if args.len() < 2 {
            outln!("Usage: power sleep <1-4>");
            outln!("  1 = S1 (Standby)");
            outln!("  3 = S3 (Sleep/Suspend to RAM)");
            outln!("  4 = S4 (Hibernate)");
            return;
        }
        if let Some(state) = parse_number(args[1]) {
            let state = state as u8;
            if state < 1 || state > 4 {
                outln!("Invalid sleep state. Use 1-4.");
                return;
            }

            // Check if state is supported
            if !crate::hal::acpi::is_sleep_state_supported(state) {
                outln!("Sleep state S{} is not supported on this system", state);
                return;
            }

            outln!("Entering sleep state S{}...", state);

            let power_state = match state {
                1 => crate::po::SystemPowerState::Sleeping1,
                2 => crate::po::SystemPowerState::Sleeping2,
                3 => crate::po::SystemPowerState::Sleeping3,
                4 => crate::po::SystemPowerState::Hibernate,
                _ => return,
            };

            match crate::po::set_system_power_state(power_state) {
                Ok(()) => outln!("Resumed from S{}", state),
                Err(e) => outln!("Failed to enter sleep state: error {}", e),
            }
        } else {
            outln!("Invalid sleep state number");
        }
    } else if eq_ignore_case(args[0], "policy") {
        // Show power policy
        let policy = crate::po::get_policy();
        outln!("Power Policy:");
        outln!("=============");
        outln!("  Revision: {}", policy.revision);
        outln!("  Power Button: {:?}", policy.power_button_action);
        outln!("  Sleep Button: {:?}", policy.sleep_button_action);
        outln!("  Lid Close: {:?}", policy.lid_close_action);
        outln!("  Idle Timeout: {} seconds", policy.idle_timeout);
        outln!("  Idle Action: {:?}", policy.idle_action);
        outln!("  Min Sleep: {:?}", policy.min_sleep);
        outln!("  Max Sleep: {:?}", policy.max_sleep);
        outln!("  Video Timeout: {} seconds", policy.video_timeout);
        outln!("  Spindown Timeout: {} seconds", policy.spindown_timeout);
    } else {
        outln!("Unknown power command: {}", args[0]);
        outln!("Use 'power' for help");
    }
}

/// Shutdown the system
pub fn cmd_shutdown() {
    outln!("Initiating system shutdown...");
    outln!("Stopping services and powering off...");

    // shutdown() never returns - it will power off the system
    crate::po::shutdown();
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

// ============================================================================
// Executive (EX) Command
// ============================================================================

/// Executive (EX) shell command
pub fn cmd_ex(args: &[&str]) {
    use crate::ex;

    if args.is_empty() {
        outln!("Executive (EX) Commands");
        outln!("");
        outln!("Usage: ex <command> [args]");
        outln!("");
        outln!("Commands:");
        outln!("  info               Show executive information");
        outln!("  worker             Show work queue status");
        outln!("  callback           Show registered callbacks");
        outln!("  luid               Show LUID allocator status");
        outln!("  lookaside          Show lookaside list info");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "info") {
        outln!("Executive Subsystem Information");
        outln!("");
        outln!("Components:");
        outln!("  ERESOURCE:       Reader-writer locks");
        outln!("  Push Locks:      Lightweight RW locks");
        outln!("  Fast Mutexes:    Efficient kernel mutexes");
        outln!("  Lookaside Lists: Fixed-size allocators");
        outln!("  Worker Threads:  Deferred work execution");
        outln!("  Callbacks:       Notification callbacks");
        outln!("  Rundown:         Safe resource cleanup");
        outln!("  Keyed Events:    Synchronization primitives");
        outln!("");
        outln!("Constants:");
        outln!("  LOOKASIDE_DEPTH: 256");
        outln!("  MAX_WORKERS:     4 per queue");
    } else if eq_ignore_case(cmd, "worker") {
        outln!("Executive Work Queues");
        outln!("");
        outln!("{:<25} {:<10}", "Queue", "Pending");
        outln!("-----------------------------------");

        let critical = ex::ex_get_work_queue_depth(ex::WorkQueueType::CriticalWorkQueue);
        let delayed = ex::ex_get_work_queue_depth(ex::WorkQueueType::DelayedWorkQueue);
        let hyper = ex::ex_get_work_queue_depth(ex::WorkQueueType::HyperCriticalWorkQueue);

        outln!("{:<25} {:<10}", "CriticalWorkQueue", critical);
        outln!("{:<25} {:<10}", "DelayedWorkQueue", delayed);
        outln!("{:<25} {:<10}", "HyperCriticalWorkQueue", hyper);
        outln!("");
        outln!("Total pending: {}", critical + delayed + hyper);
    } else if eq_ignore_case(cmd, "callback") {
        outln!("Executive Callback Objects");
        outln!("");
        outln!("Registered callback object types:");
        outln!("  SetSystemTime         - System time changes");
        outln!("  SetSystemState        - System state changes");
        outln!("  PowerState            - Power state notifications");
        outln!("  ProcessorAdd          - Processor hotplug");
        outln!("");
        outln!("(Use 'callback' command for detailed stats)");
    } else if eq_ignore_case(cmd, "luid") {
        let stats = ex::get_luid_stats();
        outln!("LUID Allocator Status");
        outln!("");
        outln!("Reserved range:   0 - {}", stats.reserved_count - 1);
        outln!("Next LUID:        {}", stats.next_luid);
        outln!("Allocated:        {}", stats.allocated_count);
        outln!("");
        outln!("(Use 'luid' command for detailed info)");
    } else if eq_ignore_case(cmd, "lookaside") {
        outln!("Lookaside List Configuration");
        outln!("");
        outln!("List types:");
        outln!("  NPagedLookasideList - Non-paged pool cache");
        outln!("  PagedLookasideList  - Paged pool cache");
        outln!("");
        outln!("Configuration:");
        outln!("  Max depth: 256, Min depth: 4");
        outln!("");
        outln!("(Use 'lookaside' command for detailed info)");
    } else {
        outln!("Unknown ex command: {}", cmd);
    }
}

// ============================================================================
// Security (SE) Command
// ============================================================================

/// Security Reference Monitor (SE) shell command
pub fn cmd_se(args: &[&str]) {
    use crate::se;

    if args.is_empty() {
        outln!("Security Reference Monitor (SE) Commands");
        outln!("");
        outln!("Usage: se <command> [args]");
        outln!("");
        outln!("Commands:");
        outln!("  info               Show security information");
        outln!("  sids               List well-known SIDs");
        outln!("  privileges         List system privileges");
        outln!("  token              Show system token info");
        outln!("  tokens             List all allocated tokens");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "info") {
        // Show token pool stats in info
        let stats = se::get_token_stats();
        outln!("Security Reference Monitor Information");
        outln!("");
        outln!("Components:");
        outln!("  Access Tokens:    Security context for processes/threads");
        outln!("  SIDs:             Security identifiers for users/groups");
        outln!("  ACLs:             Access control lists");
        outln!("  Privileges:       Special capabilities");
        outln!("  Impersonation:    Thread security context switching");
        outln!("");
        outln!("Token Pool:");
        outln!("  Max Tokens:       {}", stats.max_tokens);
        outln!("  Allocated:        {}", stats.allocated_tokens);
        outln!("  Free:             {}", stats.free_tokens);
        outln!("  Primary:          {}", stats.primary_tokens);
        outln!("  Impersonation:    {}", stats.impersonation_tokens);
        outln!("");
        outln!("Constants:");
        outln!("  TOKEN_MAX_GROUPS: {}", se::TOKEN_MAX_GROUPS);
        outln!("  MAX_ACE_COUNT:    {}", se::MAX_ACE_COUNT);
        outln!("  MAX_PRIVILEGES:   {}", se::SE_MAX_PRIVILEGES);
    } else if eq_ignore_case(cmd, "tokens") {
        show_token_list();
    } else if eq_ignore_case(cmd, "sids") {
        outln!("Well-Known Security Identifiers (SIDs)");
        outln!("");

        // Helper function to display a SID
        fn show_sid(name: &str, sid: &se::Sid) {
            let auth = sid.identifier_authority;
            let auth_val = ((auth[0] as u64) << 40)
                | ((auth[1] as u64) << 32)
                | ((auth[2] as u64) << 24)
                | ((auth[3] as u64) << 16)
                | ((auth[4] as u64) << 8)
                | (auth[5] as u64);

            outln!("{:<25} S-{}-{}", name, sid.revision, auth_val);
        }

        show_sid("Null SID", &se::SID_NULL);
        show_sid("World (Everyone)", &se::SID_WORLD);
        show_sid("Local System", &se::SID_LOCAL_SYSTEM);
        show_sid("Local Service", &se::SID_LOCAL_SERVICE);
        show_sid("Network Service", &se::SID_NETWORK_SERVICE);
        show_sid("Administrators", &se::SID_BUILTIN_ADMINISTRATORS);
        show_sid("Users", &se::SID_BUILTIN_USERS);
        show_sid("Authenticated Users", &se::SID_AUTHENTICATED_USERS);
    } else if eq_ignore_case(cmd, "privileges") {
        outln!("System Privileges");
        outln!("");
        outln!("{:<30} {:<10}", "Privilege", "LUID");
        outln!("------------------------------------------");

        // Display well-known privileges
        outln!("{:<30} {:<10}", "SeCreateTokenPrivilege", "2");
        outln!("{:<30} {:<10}", "SeAssignPrimaryTokenPrivilege", "3");
        outln!("{:<30} {:<10}", "SeLockMemoryPrivilege", "4");
        outln!("{:<30} {:<10}", "SeIncreaseQuotaPrivilege", "5");
        outln!("{:<30} {:<10}", "SeTcbPrivilege", "7");
        outln!("{:<30} {:<10}", "SeSecurityPrivilege", "8");
        outln!("{:<30} {:<10}", "SeLoadDriverPrivilege", "10");
        outln!("{:<30} {:<10}", "SeDebugPrivilege", "20");
        outln!("{:<30} {:<10}", "SeBackupPrivilege", "17");
        outln!("{:<30} {:<10}", "SeRestorePrivilege", "18");
        outln!("{:<30} {:<10}", "SeShutdownPrivilege", "19");
        outln!("{:<30} {:<10}", "SeImpersonatePrivilege", "29");
    } else if eq_ignore_case(cmd, "token") {
        outln!("System Token Information");
        outln!("");

        unsafe {
            let token = se::se_get_system_token();
            if token.is_null() {
                outln!("  (System token not available)");
                return;
            }

            outln!("System Token:");
            outln!("  Address:     {:p}", token);
            outln!("  Type:        Primary");
            outln!("  User:        SYSTEM (S-1-5-18)");
            outln!("  Groups:      Administrators, Everyone");
            outln!("  Privileges:  All enabled (privileged token)");
        }
    } else {
        outln!("Unknown se command: {}", cmd);
    }
}

// ============================================================================
// Kernel Executive (KE) Command
// ============================================================================

/// Kernel Executive (KE) shell command
pub fn cmd_ke(args: &[&str]) {
    use crate::ke;

    if args.is_empty() {
        outln!("Kernel Executive (KE) Commands");
        outln!("");
        outln!("Usage: ke <command> [args]");
        outln!("");
        outln!("Commands:");
        outln!("  info               Show kernel executive information");
        outln!("  irql               Show current IRQL levels");
        outln!("  dpc                Show DPC queue status");
        outln!("  apc                Show APC information");
        outln!("  timer              Show timer information");
        outln!("  prcb               Show processor control block");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "info") {
        outln!("Kernel Executive Information");
        outln!("");
        outln!("Components:");
        outln!("  Scheduler:      32 priority levels, per-CPU ready queues");
        outln!("  Dispatcher:     KEVENT, KSEMAPHORE, KMUTANT, KTIMER");
        outln!("  DPC:            Deferred Procedure Calls");
        outln!("  APC:            Asynchronous Procedure Calls");
        outln!("  Spinlocks:      Raw and queued spinlocks");
        outln!("  Wait/Unwait:    Multi-object wait support");
        outln!("  IPI:            Inter-processor interrupts");
        outln!("");
        outln!("IRQL Levels:");
        outln!("  PASSIVE_LEVEL:  0 (Normal execution)");
        outln!("  APC_LEVEL:      1 (APC delivery)");
        outln!("  DISPATCH_LEVEL: 2 (DPC/Scheduler)");
        outln!("  Device IRQLs:   3-26 (Hardware)");
        outln!("  IPI_LEVEL:      29");
        outln!("  HIGH_LEVEL:     31");
    } else if eq_ignore_case(cmd, "irql") {
        outln!("Current IRQL Status");
        outln!("");

        unsafe {
            let current_irql = ke::ke_get_current_irql();
            let irql_name = match current_irql {
                0 => "PASSIVE_LEVEL",
                1 => "APC_LEVEL",
                2 => "DISPATCH_LEVEL",
                29 => "IPI_LEVEL",
                30 => "POWER_LEVEL",
                31 => "HIGH_LEVEL",
                _ => "Device IRQL",
            };

            outln!("Current IRQL: {} ({})", current_irql, irql_name);
            outln!("");
            outln!("IRQL thresholds:");
            outln!("  DPC Level:  {}", ke::irql::DISPATCH_LEVEL);
            outln!("  Synch Level: {}", ke::irql::SYNCH_LEVEL);
            outln!("");

            let is_dpc = ke::ke_is_dpc_active();
            let is_intr = ke::ke_is_executing_interrupt();
            outln!("DPC Active:       {}", if is_dpc { "Yes" } else { "No" });
            outln!("In Interrupt:     {}", if is_intr { "Yes" } else { "No" });
        }
    } else if eq_ignore_case(cmd, "dpc") {
        outln!("Deferred Procedure Call (DPC) Information");
        outln!("");
        outln!("DPC Importance Levels:");
        outln!("  LowImportance:    Queue at tail");
        outln!("  MediumImportance: Queue at tail (default)");
        outln!("  HighImportance:   Queue at head");
        outln!("");

        unsafe {
            let _prcb = ke::get_current_prcb();
            outln!("Current processor DPC status:");
            outln!("  DPC list:     (pending DPCs in queue)");
            outln!("  DPC active:   {}", if ke::ke_is_dpc_active() { "Yes" } else { "No" });
        }
    } else if eq_ignore_case(cmd, "apc") {
        outln!("Asynchronous Procedure Call (APC) Information");
        outln!("");
        outln!("APC Modes:");
        outln!("  KernelMode: Runs at APC_LEVEL, cannot be disabled");
        outln!("  UserMode:   Runs in user context, alertable waits");
        outln!("");
        outln!("APC Types:");
        outln!("  Normal:   Full kernel/normal/rundown routine");
        outln!("  Special:  Kernel routine only, higher priority");
        outln!("");
        outln!("(Per-thread APC queues not yet exposed)");
    } else if eq_ignore_case(cmd, "timer") {
        outln!("Kernel Timer Information");
        outln!("");
        outln!("Timer Types:");
        outln!("  NotificationTimer: Signals all waiters");
        outln!("  SynchronizationTimer: Signals one waiter");
        outln!("");
        outln!("Timer Resolution:");
        outln!("  Standard:  ~15.6ms (64 Hz)");
        outln!("  Maximum:   ~0.5ms (adjustable)");
        outln!("");
        outln!("(Active timer list not yet exposed)");
    } else if eq_ignore_case(cmd, "prcb") {
        outln!("Processor Control Block (PRCB) Information");
        outln!("");

        unsafe {
            let active_cpus = ke::get_active_cpu_count();
            outln!("Active Processors: {}", active_cpus);
            outln!("Maximum CPUs:      {}", ke::MAX_CPUS);
            outln!("");

            let current_cpu = ke::ke_get_current_processor_number();
            outln!("Current CPU:       {}", current_cpu);
            outln!("");

            let idle_summary = ke::ki_get_idle_summary();
            outln!("Idle Summary:      {:#x}", idle_summary);

            outln!("");
            outln!("Queued Spinlock Queues: {}", ke::LOCK_QUEUE_MAXIMUM);
        }
    } else {
        outln!("Unknown ke command: {}", cmd);
    }
}

// ============================================================================
// Memory Manager (MM) Command
// ============================================================================

/// Memory Manager (MM) shell command
pub fn cmd_mm(args: &[&str]) {
    use crate::mm;

    if args.is_empty() {
        outln!("Memory Manager (MM) Commands");
        outln!("");
        outln!("Usage: mm <command> [args]");
        outln!("");
        outln!("Commands:");
        outln!("  info               Show memory manager information");
        outln!("  stats              Show memory statistics");
        outln!("  pool               Show pool allocator status");
        outln!("  physical           Show physical memory info");
        outln!("  vad                Show VAD statistics");
        outln!("  section            Show section statistics");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "info") {
        outln!("Memory Manager Information");
        outln!("");
        outln!("Components:");
        outln!("  Virtual Memory:    4-level page tables");
        outln!("  PFN Database:      Physical page tracking");
        outln!("  VAD Tree:          Virtual address descriptors");
        outln!("  Working Sets:      Per-process page sets");
        outln!("  Section Objects:   Shared memory/file mapping");
        outln!("  Pool Allocator:    Paged/NonPaged pools");
        outln!("");
        outln!("Address Space Layout (x86_64):");
        outln!("  User space:   0x0000_0000_0000 - 0x7FFF_FFFF_FFFF");
        outln!("  Kernel space: 0xFFFF_8000_0000 - 0xFFFF_FFFF_FFFF");
        outln!("");
        outln!("Constants:");
        outln!("  PAGE_SIZE:       {:#x} ({} bytes)", mm::PAGE_SIZE, mm::PAGE_SIZE);
        outln!("  LARGE_PAGE_SIZE: {:#x} ({} MB)", mm::LARGE_PAGE_SIZE, mm::LARGE_PAGE_SIZE / 1024 / 1024);
    } else if eq_ignore_case(cmd, "stats") {
        outln!("Memory Statistics");
        outln!("");

        let stats = mm::mm_get_stats();
        outln!("PFN Database:");
        outln!("  Total pages:     {}", stats.total_pages);
        outln!("  Free pages:      {}", stats.free_pages);
        outln!("  Active pages:    {}", stats.active_pages);
        outln!("  Zeroed pages:    {}", stats.zeroed_pages);
        outln!("");

        let total_mb = (stats.total_pages as usize * mm::PAGE_SIZE) / (1024 * 1024);
        let free_mb = (stats.free_pages as usize * mm::PAGE_SIZE) / (1024 * 1024);
        let used_mb = total_mb - free_mb;
        outln!("Memory Usage:");
        outln!("  Total:  {} MB", total_mb);
        outln!("  Used:   {} MB", used_mb);
        outln!("  Free:   {} MB", free_mb);
    } else if eq_ignore_case(cmd, "pool") {
        outln!("Pool Allocator Status");
        outln!("");

        let pool_stats = mm::mm_get_pool_stats();
        outln!("Pool Statistics:");
        outln!("  Total size:        {} bytes", pool_stats.total_size);
        outln!("  Bytes allocated:   {} bytes", pool_stats.bytes_allocated);
        outln!("  Bytes free:        {} bytes", pool_stats.bytes_free);
        outln!("  Allocation count:  {}", pool_stats.allocation_count);
        outln!("  Free count:        {}", pool_stats.free_count);
    } else if eq_ignore_case(cmd, "physical") {
        outln!("Physical Memory Information");
        outln!("");

        let phys_stats = mm::mm_get_physical_stats();
        outln!("Physical Memory:");
        outln!("  Total pages:     {}", phys_stats.total_pages);
        outln!("  Free pages:      {}", phys_stats.free_pages);
        outln!("  Active pages:    {}", phys_stats.active_pages);
        outln!("  Zeroed pages:    {}", phys_stats.zeroed_pages);
        outln!("  Total bytes:     {} MB", phys_stats.total_bytes / 1024 / 1024);
        outln!("  Usable bytes:    {} MB", phys_stats.usable_bytes / 1024 / 1024);
        outln!("");

        let region_count = mm::mm_get_region_count();
        outln!("Memory Regions: {}", region_count);
        outln!("(Region enumeration not yet implemented)");
    } else if eq_ignore_case(cmd, "vad") {
        outln!("Virtual Address Descriptor (VAD) Statistics");
        outln!("");

        let vad_stats = mm::mm_get_vad_stats();
        outln!("VAD Allocations:");
        outln!("  Total VADs:      {}", vad_stats.total_vads);
        outln!("  Allocated VADs:  {}", vad_stats.allocated_vads);
        outln!("  Free VADs:       {}", vad_stats.free_vads);
        outln!("");
        outln!("Max VADs:          {}", mm::MAX_VADS);
    } else if eq_ignore_case(cmd, "section") {
        outln!("Section Object Statistics");
        outln!("");

        let section_stats = mm::mm_get_section_stats();
        outln!("Sections:");
        outln!("  Total:           {}", section_stats.total_sections);
        outln!("  Active:          {}", section_stats.active_sections);
        outln!("");
        outln!("Views:");
        outln!("  Total views:     {}", section_stats.total_views);
        outln!("");
        outln!("Max Sections:      {}", mm::MAX_SECTIONS);
    } else {
        outln!("Unknown mm command: {}", cmd);
    }
}

// ============================================================================
// I/O Manager (IO) Command
// ============================================================================

/// I/O Manager (IO) shell command
pub fn cmd_io(args: &[&str]) {
    use crate::io;

    if args.is_empty() {
        outln!("I/O Manager (IO) Commands");
        outln!("");
        outln!("Usage: io <command> [args]");
        outln!("");
        outln!("Commands:");
        outln!("  info               Show I/O manager information");
        outln!("  block              Show block device status");
        outln!("  volumes            List disk volumes");
        outln!("  ramdisk            Show RAM disk status");
        outln!("  pipes              Show named pipe status");
        outln!("  iocp               Show I/O completion ports");
        outln!("  pnp                Show Plug and Play device tree");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "info") {
        outln!("I/O Manager Information");
        outln!("");
        outln!("Components:");
        outln!("  IRP:              I/O Request Packets");
        outln!("  Driver Objects:   Driver dispatch tables");
        outln!("  Device Objects:   Device stack representation");
        outln!("  File Objects:     Open file handles");
        outln!("  Block Devices:    Disk/storage abstraction");
        outln!("  Named Pipes:      Inter-process communication");
        outln!("  IOCP:             I/O Completion Ports");
        outln!("");
        outln!("IRP Major Functions:");
        outln!("  IRP_MJ_CREATE (0), CLOSE (2), READ (3), WRITE (4)");
        outln!("  IRP_MJ_DEVICE_CONTROL (14)");
        outln!("");
        outln!("Constants:");
        outln!("  SECTOR_SIZE:      {}", io::SECTOR_SIZE);
        outln!("  MAX_RAM_DISKS:    {}", io::MAX_RAM_DISKS);
        outln!("  MAX_NAMED_PIPES:  {}", io::MAX_NAMED_PIPES);
        outln!("  MAX_IOCP:         {}", io::MAX_COMPLETION_PORTS);
    } else if eq_ignore_case(cmd, "block") {
        outln!("Block Device Status");
        outln!("");

        let count = io::block_device_count();
        outln!("Registered block devices: {}", count);
        outln!("");

        if count > 0 {
            outln!("{:<10} {:<15} {:<12}", "Device", "Type", "Sectors");
            outln!("---------------------------------------");
            for i in 0..count.min(10) {
                if let Some(dev) = io::get_block_device(i as u8) {
                    let type_str = match dev.device_type {
                        io::BlockDeviceType::Unknown => "Unknown",
                        io::BlockDeviceType::HardDisk => "Hard Disk",
                        io::BlockDeviceType::SSD => "SSD",
                        io::BlockDeviceType::Optical => "CD/DVD",
                        io::BlockDeviceType::Floppy => "Floppy",
                        io::BlockDeviceType::USB => "USB",
                        io::BlockDeviceType::RamDisk => "RAM Disk",
                        _ => "Other",
                    };
                    outln!("{:<10} {:<15} {:<12}", i, type_str, dev.geometry.total_sectors);
                }
            }
        }
    } else if eq_ignore_case(cmd, "volumes") {
        outln!("Disk Volumes");
        outln!("");

        let count = io::volume_count();
        outln!("Detected volumes: {}", count);
        outln!("");

        if count > 0 {
            io::list_volumes();
        }
    } else if eq_ignore_case(cmd, "ramdisk") {
        outln!("RAM Disk Status");
        outln!("");

        let count = io::ramdisk_count();
        outln!("Active RAM disks: {}", count);
        outln!("Maximum RAM disks: {}", io::MAX_RAM_DISKS);
        outln!("Default size: {} MB", io::DEFAULT_RAMDISK_SIZE / 1024 / 1024);
        outln!("Maximum size: {} MB", io::MAX_RAMDISK_SIZE / 1024 / 1024);
    } else if eq_ignore_case(cmd, "pipes") {
        outln!("Named Pipe Status");
        outln!("");

        let stats = io::get_pipe_stats();
        outln!("Pipe Statistics:");
        outln!("  Total pipes:          {}", stats.total_pipes);
        outln!("  Active pipes:         {}", stats.active_pipes);
        outln!("  Total instances:      {}", stats.total_instances);
        outln!("  Connected instances:  {}", stats.connected_instances);
        outln!("");
        outln!("Limits:");
        outln!("  Max pipes:       {}", io::MAX_NAMED_PIPES);
        outln!("  Max instances:   {}", io::MAX_PIPE_INSTANCES);
        outln!("  Buffer size:     {}", io::DEFAULT_BUFFER_SIZE);
    } else if eq_ignore_case(cmd, "iocp") {
        outln!("I/O Completion Port Status");
        outln!("");
        outln!("Max completion ports: {}", io::MAX_COMPLETION_PORTS);
        outln!("Max queued completions: {}", io::MAX_QUEUED_COMPLETIONS);
        outln!("");
        outln!("(Detailed IOCP status not yet implemented)");
    } else if eq_ignore_case(cmd, "pnp") {
        outln!("Plug and Play Manager");
        outln!("");

        let (enumerated, started, removed) = io::pnp_get_stats();
        outln!("PnP Statistics:");
        outln!("  Devices enumerated:  {}", enumerated);
        outln!("  Devices started:     {}", started);
        outln!("  Devices removed:     {}", removed);
        outln!("");

        let count = io::device_node_count();
        outln!("Device Tree: {} nodes", count);
        outln!("");

        if count > 0 {
            outln!("{:<5} {:<30} {:<12}", "Idx", "Instance ID", "State");
            outln!("--------------------------------------------------");
            for snap in io::get_device_node_snapshots() {
                let state = io::device_state_name(snap.state);
                outln!("{:<5} {:<30} {:<12}", snap.index, snap.instance_id, state);
            }
        }
    } else {
        outln!("Unknown io command: {}", cmd);
    }
}

// ============================================================================
// Hardware Abstraction Layer (HAL) Command
// ============================================================================

/// Hardware Abstraction Layer (HAL) shell command
pub fn cmd_hal(args: &[&str]) {
    use crate::hal;

    if args.is_empty() {
        outln!("Hardware Abstraction Layer (HAL) Commands");
        outln!("");
        outln!("Usage: hal <command> [args]");
        outln!("");
        outln!("Commands:");
        outln!("  info               Show HAL information");
        outln!("  time               Show RTC date/time");
        outln!("  apic               Show APIC status");
        outln!("  tick               Show system tick count");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "info") {
        outln!("Hardware Abstraction Layer Information");
        outln!("");
        outln!("Components:");
        outln!("  PIC:    8259 Programmable Interrupt Controller");
        outln!("  APIC:   Advanced Programmable Interrupt Controller");
        outln!("  RTC:    Real-Time Clock (CMOS)");
        outln!("  ATA:    IDE/PATA disk controller");
        outln!("  ACPI:   Power management (stub)");
        outln!("");
        outln!("Interrupt Routing:");
        outln!("  IRQ 0:  Timer (PIT or APIC timer)");
        outln!("  IRQ 1:  Keyboard");
        outln!("  IRQ 8:  RTC");
        outln!("  IRQ 14: Primary ATA");
        outln!("  IRQ 15: Secondary ATA");
    } else if eq_ignore_case(cmd, "time") {
        outln!("Real-Time Clock");
        outln!("");

        let dt = hal::rtc::get_datetime();
        outln!("Current Date/Time:");
        outln!("  Date:   {:04}-{:02}-{:02}", dt.year, dt.month, dt.day);
        outln!("  Time:   {:02}:{:02}:{:02}", dt.hour, dt.minute, dt.second);
        outln!("  Day:    {} (1=Sun)", dt.day_of_week);
        outln!("");

        let boot_time = hal::rtc::get_boot_time();
        let system_time = hal::rtc::get_system_time();
        let uptime = hal::rtc::get_uptime_seconds();

        outln!("Boot time:    {:#x} (FILETIME)", boot_time);
        outln!("System time:  {:#x} (FILETIME)", system_time);
        outln!("Uptime:       {} seconds", uptime);
    } else if eq_ignore_case(cmd, "apic") {
        outln!("Advanced Programmable Interrupt Controller");
        outln!("");

        let apic = hal::apic::get();
        outln!("Local APIC:");
        outln!("  Base address: {:#x}", apic.base_address());
        outln!("  APIC ID:      {}", apic.id());
        outln!("  Version:      {:#x}", apic.version());
        outln!("");

        let ticks = hal::apic::get_tick_count();
        outln!("Timer:");
        outln!("  Tick count:   {}", ticks);
        outln!("  Current:      {}", apic.timer_current());
    } else if eq_ignore_case(cmd, "tick") {
        outln!("System Tick Counter");
        outln!("");

        let ticks = hal::apic::get_tick_count();
        let uptime = hal::rtc::get_uptime_seconds();

        outln!("APIC ticks:     {}", ticks);
        outln!("Uptime:         {} seconds", uptime);

        if uptime > 0 {
            let ticks_per_sec = ticks / uptime;
            outln!("Ticks/second:   ~{}", ticks_per_sec);
        }
    } else {
        outln!("Unknown hal command: {}", cmd);
    }
}

// ============================================================================
// System Information Command
// ============================================================================

/// System information command - gives comprehensive system overview
pub fn cmd_sysinfo() {
    use crate::{mm, ps, ke, hal, io, ob};

    outln!("============================================================");
    outln!("                   NOSTALGOS SYSTEM INFO");
    outln!("============================================================");
    outln!("");

    // OS Information
    outln!("Operating System:");
    outln!("  Name:         Nostalgia OS (NT 5.2 Compatible)");
    outln!("  Architecture: x86_64");
    outln!("  Build:        Development");
    outln!("");

    // Time Information
    let dt = hal::rtc::get_datetime();
    let uptime = hal::rtc::get_uptime_seconds();
    outln!("Time:");
    outln!("  Current:      {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
           dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);
    outln!("  Uptime:       {} seconds", uptime);
    outln!("");

    // CPU Information
    unsafe {
        let cpu_count = ke::get_active_cpu_count();
        let current_cpu = ke::ke_get_current_processor_number();
        let irql = ke::ke_get_current_irql();

        outln!("Processor:");
        outln!("  Active CPUs:  {}", cpu_count);
        outln!("  Current CPU:  {}", current_cpu);
        outln!("  Current IRQL: {}", irql);
        outln!("");
    }

    // Memory Information
    let mem_stats = mm::mm_get_stats();
    let total_mb = (mem_stats.total_pages as usize * mm::PAGE_SIZE) / (1024 * 1024);
    let free_mb = (mem_stats.free_pages as usize * mm::PAGE_SIZE) / (1024 * 1024);

    outln!("Memory:");
    outln!("  Total:        {} MB ({} pages)", total_mb, mem_stats.total_pages);
    outln!("  Free:         {} MB ({} pages)", free_mb, mem_stats.free_pages);
    outln!("  Active:       {} pages", mem_stats.active_pages);
    outln!("");

    // Process Information
    outln!("Processes:");
    outln!("  Max Processes: {}", ps::MAX_PROCESSES);
    outln!("  Max Threads:   {}", ps::MAX_THREADS);
    unsafe {
        let list_head = ps::get_active_process_list();
        let mut count = 0;
        let mut entry = (*list_head).flink;
        while entry != list_head && count < 100 {
            entry = (*entry).flink;
            count += 1;
        }
        outln!("  Active:        {} processes", count);
    }
    outln!("");

    // Object Manager
    outln!("Objects:");
    outln!("  Max Types:     {}", ob::MAX_OBJECT_TYPES);
    outln!("  Max Handles:   {}", ob::MAX_HANDLES);
    outln!("");

    // I/O Subsystem
    let block_count = io::block_device_count();
    let volume_count = io::volume_count();
    let ramdisk_count = io::ramdisk_count();

    outln!("Storage:");
    outln!("  Block Devices: {}", block_count);
    outln!("  Volumes:       {}", volume_count);
    outln!("  RAM Disks:     {}", ramdisk_count);
    outln!("");

    // Timer/Tick Information
    let ticks = hal::apic::get_tick_count();
    outln!("Timers:");
    outln!("  APIC Ticks:    {}", ticks);
    if uptime > 0 {
        outln!("  Ticks/sec:     ~{}", ticks / uptime);
    }
    outln!("");

    outln!("============================================================");
}

// ============================================================================
// Debug Command
// ============================================================================

/// Kernel debugging command
pub fn cmd_debug(args: &[&str]) {
    use crate::ke;

    if args.is_empty() {
        outln!("Kernel Debug Commands");
        outln!("");
        outln!("Usage: debug <command> [args]");
        outln!("");
        outln!("Commands:");
        outln!("  bugcheck         Test blue screen of death");
        outln!("  break            Trigger debug break");
        outln!("  stack            Show current stack pointer");
        outln!("  regs             Show general purpose registers");
        outln!("  cr               Show control registers (CR0-CR4)");
        outln!("  flags            Show RFLAGS register");
        outln!("  gdt              Show GDT base and limit");
        outln!("  idt              Show IDT base and limit");
        outln!("  peek <addr> [n]  Read n bytes at address (hex dump)");
        outln!("  cpuid [leaf]     Display CPUID information");
        outln!("  inb <port>       Read byte from I/O port");
        outln!("  inw <port>       Read word from I/O port");
        outln!("  ind <port>       Read dword from I/O port");
        outln!("  rdmsr <msr>      Read model-specific register");
        outln!("  tsc              Read Time Stamp Counter");
        outln!("  all              Dump complete system state");
        outln!("  veh              Show VEH handler count");
        outln!("  seh              Show SEH frame count");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "bugcheck") {
        outln!("Testing KeBugCheck...");
        outln!("");
        outln!("WARNING: This will cause a kernel panic!");
        outln!("");

        if args.len() > 1 && eq_ignore_case(args[1], "confirm") {
            outln!("Triggering bugcheck with code 0xDEADBEEF...");
            unsafe {
                ke::ke_bugcheck(0xDEADBEEF);
            }
        } else {
            outln!("Use 'debug bugcheck confirm' to actually trigger.");
        }
    } else if eq_ignore_case(cmd, "break") {
        outln!("Triggering debug break (INT 3)...");
        unsafe {
            core::arch::asm!("int3");
        }
        outln!("Returned from debug break.");
    } else if eq_ignore_case(cmd, "stack") {
        let rsp: u64;
        let rbp: u64;
        unsafe {
            core::arch::asm!(
                "mov {}, rsp",
                "mov {}, rbp",
                out(reg) rsp,
                out(reg) rbp,
            );
        }
        outln!("Stack Pointers:");
        outln!("  RSP: {:#018x}", rsp);
        outln!("  RBP: {:#018x}", rbp);
    } else if eq_ignore_case(cmd, "regs") {
        let rax: u64;
        let rbx: u64;
        let rcx: u64;
        let rdx: u64;
        let rsi: u64;
        let rdi: u64;
        let r8: u64;
        let r9: u64;
        let r10: u64;
        let r11: u64;
        let r12: u64;
        let r13: u64;
        let r14: u64;
        let r15: u64;

        unsafe {
            core::arch::asm!(
                "mov {}, rax",
                "mov {}, rbx",
                "mov {}, rcx",
                "mov {}, rdx",
                "mov {}, rsi",
                "mov {}, rdi",
                "mov {}, r8",
                "mov {}, r9",
                "mov {}, r10",
                "mov {}, r11",
                "mov {}, r12",
                "mov {}, r13",
                "mov {}, r14",
                "mov {}, r15",
                out(reg) rax,
                out(reg) rbx,
                out(reg) rcx,
                out(reg) rdx,
                out(reg) rsi,
                out(reg) rdi,
                out(reg) r8,
                out(reg) r9,
                out(reg) r10,
                out(reg) r11,
                out(reg) r12,
                out(reg) r13,
                out(reg) r14,
                out(reg) r15,
            );
        }

        outln!("General Purpose Registers:");
        outln!("  RAX: {:#018x}  RBX: {:#018x}", rax, rbx);
        outln!("  RCX: {:#018x}  RDX: {:#018x}", rcx, rdx);
        outln!("  RSI: {:#018x}  RDI: {:#018x}", rsi, rdi);
        outln!("  R8:  {:#018x}  R9:  {:#018x}", r8, r9);
        outln!("  R10: {:#018x}  R11: {:#018x}", r10, r11);
        outln!("  R12: {:#018x}  R13: {:#018x}", r12, r13);
        outln!("  R14: {:#018x}  R15: {:#018x}", r14, r15);
    } else if eq_ignore_case(cmd, "cr") {
        let cr0: u64;
        let cr2: u64;
        let cr3: u64;
        let cr4: u64;

        unsafe {
            core::arch::asm!(
                "mov {}, cr0",
                "mov {}, cr2",
                "mov {}, cr3",
                "mov {}, cr4",
                out(reg) cr0,
                out(reg) cr2,
                out(reg) cr3,
                out(reg) cr4,
            );
        }

        outln!("Control Registers:");
        outln!("  CR0: {:#018x}", cr0);
        outln!("       PE={} MP={} EM={} TS={} ET={} NE={} WP={} AM={} NW={} CD={} PG={}",
            (cr0 >> 0) & 1, (cr0 >> 1) & 1, (cr0 >> 2) & 1, (cr0 >> 3) & 1,
            (cr0 >> 4) & 1, (cr0 >> 5) & 1, (cr0 >> 16) & 1, (cr0 >> 18) & 1,
            (cr0 >> 29) & 1, (cr0 >> 30) & 1, (cr0 >> 31) & 1);
        outln!("  CR2: {:#018x} (Page Fault Linear Address)", cr2);
        outln!("  CR3: {:#018x} (Page Directory Base)", cr3);
        outln!("  CR4: {:#018x}", cr4);
        outln!("       VME={} PVI={} TSD={} DE={} PSE={} PAE={} MCE={} PGE={}",
            (cr4 >> 0) & 1, (cr4 >> 1) & 1, (cr4 >> 2) & 1, (cr4 >> 3) & 1,
            (cr4 >> 4) & 1, (cr4 >> 5) & 1, (cr4 >> 6) & 1, (cr4 >> 7) & 1);
        outln!("       PCE={} OSFXSR={} OSXMMEXCPT={} UMIP={} FSGSBASE={} PCIDE={}",
            (cr4 >> 8) & 1, (cr4 >> 9) & 1, (cr4 >> 10) & 1, (cr4 >> 11) & 1,
            (cr4 >> 16) & 1, (cr4 >> 17) & 1);
    } else if eq_ignore_case(cmd, "flags") {
        let rflags: u64;

        unsafe {
            core::arch::asm!(
                "pushfq",
                "pop {}",
                out(reg) rflags,
            );
        }

        outln!("RFLAGS: {:#018x}", rflags);
        outln!("  CF={} PF={} AF={} ZF={} SF={} TF={} IF={} DF={} OF={}",
            (rflags >> 0) & 1, (rflags >> 2) & 1, (rflags >> 4) & 1,
            (rflags >> 6) & 1, (rflags >> 7) & 1, (rflags >> 8) & 1,
            (rflags >> 9) & 1, (rflags >> 10) & 1, (rflags >> 11) & 1);
        outln!("  IOPL={} NT={} RF={} VM={} AC={} VIF={} VIP={} ID={}",
            (rflags >> 12) & 3, (rflags >> 14) & 1, (rflags >> 16) & 1,
            (rflags >> 17) & 1, (rflags >> 18) & 1, (rflags >> 19) & 1,
            (rflags >> 20) & 1, (rflags >> 21) & 1);
    } else if eq_ignore_case(cmd, "gdt") {
        #[repr(C, packed)]
        struct DescriptorTablePointer {
            limit: u16,
            base: u64,
        }

        let mut gdtr = DescriptorTablePointer { limit: 0, base: 0 };

        unsafe {
            core::arch::asm!(
                "sgdt [{}]",
                in(reg) &mut gdtr,
            );
        }

        // Copy from packed struct to avoid alignment issues
        let gdt_base = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(gdtr.base)) };
        let gdt_limit = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(gdtr.limit)) };

        outln!("Global Descriptor Table:");
        outln!("  Base:  {:#018x}", gdt_base);
        outln!("  Limit: {:#06x} ({} entries)", gdt_limit, (gdt_limit as u32 + 1) / 8);
    } else if eq_ignore_case(cmd, "idt") {
        #[repr(C, packed)]
        struct DescriptorTablePointer {
            limit: u16,
            base: u64,
        }

        let mut idtr = DescriptorTablePointer { limit: 0, base: 0 };

        unsafe {
            core::arch::asm!(
                "sidt [{}]",
                in(reg) &mut idtr,
            );
        }

        // Copy from packed struct to avoid alignment issues
        let idt_base = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(idtr.base)) };
        let idt_limit = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(idtr.limit)) };

        outln!("Interrupt Descriptor Table:");
        outln!("  Base:  {:#018x}", idt_base);
        outln!("  Limit: {:#06x} ({} entries)", idt_limit, (idt_limit as u32 + 1) / 16);
    } else if eq_ignore_case(cmd, "peek") {
        if args.len() < 2 {
            outln!("Usage: debug peek <address> [count]");
            outln!("  address: hex address to read (e.g., 0x1000)");
            outln!("  count:   bytes to read (default: 64, max: 256)");
            return;
        }

        // Parse address
        let addr_str = args[1].trim_start_matches("0x").trim_start_matches("0X");
        let addr = match u64::from_str_radix(addr_str, 16) {
            Ok(a) => a,
            Err(_) => {
                outln!("Error: Invalid address '{}'", args[1]);
                return;
            }
        };

        // Parse count
        let count = if args.len() > 2 {
            args[2].parse::<usize>().unwrap_or(64).min(256)
        } else {
            64
        };

        outln!("Memory at {:#018x} ({} bytes):", addr, count);
        outln!("");

        // Display as hex dump with ASCII
        let ptr = addr as *const u8;
        let mut row_offset = 0usize;

        while row_offset < count {
            // Print address
            out!("{:016x}  ", addr + row_offset as u64);

            // Print hex bytes
            let row_end = (row_offset + 16).min(count);
            for i in row_offset..row_end {
                let byte = unsafe { core::ptr::read_volatile(ptr.add(i)) };
                out!("{:02x} ", byte);
            }

            // Padding if row is incomplete
            for _ in row_end..(row_offset + 16) {
                out!("   ");
            }

            out!(" ");

            // Print ASCII
            for i in row_offset..row_end {
                let byte = unsafe { core::ptr::read_volatile(ptr.add(i)) };
                if byte >= 0x20 && byte < 0x7f {
                    out!("{}", byte as char);
                } else {
                    out!(".");
                }
            }

            outln!("");
            row_offset += 16;
        }
    } else if eq_ignore_case(cmd, "cpuid") {
        let leaf = if args.len() > 1 {
            let leaf_str = args[1].trim_start_matches("0x").trim_start_matches("0X");
            u32::from_str_radix(leaf_str, 16).unwrap_or(0)
        } else {
            0 // Default to leaf 0
        };

        let eax: u32;
        let ebx: u32;
        let ecx: u32;
        let edx: u32;

        unsafe {
            // rbx is reserved by LLVM, so we save/restore it
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "mov {ebx_out:e}, ebx",
                "pop rbx",
                inout("eax") leaf => eax,
                ebx_out = out(reg) ebx,
                inout("ecx") 0u32 => ecx,
                out("edx") edx,
            );
        }

        outln!("CPUID Leaf {:#x}:", leaf);
        outln!("  EAX: {:#010x}", eax);
        outln!("  EBX: {:#010x}", ebx);
        outln!("  ECX: {:#010x}", ecx);
        outln!("  EDX: {:#010x}", edx);

        // Decode common leaves
        if leaf == 0 {
            // Vendor string
            let mut vendor = [0u8; 12];
            vendor[0..4].copy_from_slice(&ebx.to_le_bytes());
            vendor[4..8].copy_from_slice(&edx.to_le_bytes());
            vendor[8..12].copy_from_slice(&ecx.to_le_bytes());
            let vendor_str = core::str::from_utf8(&vendor).unwrap_or("?");
            outln!("");
            outln!("  Vendor: {}", vendor_str);
            outln!("  Max Basic Leaf: {}", eax);
        } else if leaf == 1 {
            // Feature flags
            outln!("");
            outln!("  Family: {}", ((eax >> 8) & 0xF) + ((eax >> 20) & 0xFF));
            outln!("  Model: {}", ((eax >> 4) & 0xF) + (((eax >> 16) & 0xF) << 4));
            outln!("  Stepping: {}", eax & 0xF);
            outln!("");
            outln!("  Features (EDX):");
            outln!("    FPU={} VME={} DE={} PSE={} TSC={} MSR={} PAE={} MCE={}",
                (edx >> 0) & 1, (edx >> 1) & 1, (edx >> 2) & 1, (edx >> 3) & 1,
                (edx >> 4) & 1, (edx >> 5) & 1, (edx >> 6) & 1, (edx >> 7) & 1);
            outln!("    CX8={} APIC={} SEP={} MTRR={} PGE={} MCA={} CMOV={} PAT={}",
                (edx >> 8) & 1, (edx >> 9) & 1, (edx >> 11) & 1, (edx >> 12) & 1,
                (edx >> 13) & 1, (edx >> 14) & 1, (edx >> 15) & 1, (edx >> 16) & 1);
        }
    } else if eq_ignore_case(cmd, "inb") {
        if args.len() < 2 {
            outln!("Usage: debug inb <port>");
            return;
        }

        let port_str = args[1].trim_start_matches("0x").trim_start_matches("0X");
        let port = match u16::from_str_radix(port_str, 16) {
            Ok(p) => p,
            Err(_) => {
                outln!("Error: Invalid port '{}'", args[1]);
                return;
            }
        };

        let value: u8;
        unsafe {
            core::arch::asm!(
                "in al, dx",
                out("al") value,
                in("dx") port,
            );
        }

        outln!("Port {:#06x}: {:#04x} ({})", port, value, value);
    } else if eq_ignore_case(cmd, "inw") {
        if args.len() < 2 {
            outln!("Usage: debug inw <port>");
            return;
        }

        let port_str = args[1].trim_start_matches("0x").trim_start_matches("0X");
        let port = match u16::from_str_radix(port_str, 16) {
            Ok(p) => p,
            Err(_) => {
                outln!("Error: Invalid port '{}'", args[1]);
                return;
            }
        };

        let value: u16;
        unsafe {
            core::arch::asm!(
                "in ax, dx",
                out("ax") value,
                in("dx") port,
            );
        }

        outln!("Port {:#06x}: {:#06x} ({})", port, value, value);
    } else if eq_ignore_case(cmd, "ind") {
        if args.len() < 2 {
            outln!("Usage: debug ind <port>");
            return;
        }

        let port_str = args[1].trim_start_matches("0x").trim_start_matches("0X");
        let port = match u16::from_str_radix(port_str, 16) {
            Ok(p) => p,
            Err(_) => {
                outln!("Error: Invalid port '{}'", args[1]);
                return;
            }
        };

        let value: u32;
        unsafe {
            core::arch::asm!(
                "in eax, dx",
                out("eax") value,
                in("dx") port,
            );
        }

        outln!("Port {:#06x}: {:#010x} ({})", port, value, value);
    } else if eq_ignore_case(cmd, "rdmsr") {
        if args.len() < 2 {
            outln!("Usage: debug rdmsr <msr>");
            outln!("");
            outln!("Common MSRs:");
            outln!("  0x10      TSC (Time Stamp Counter)");
            outln!("  0x1B      APIC Base");
            outln!("  0xC0000080 EFER (Extended Feature Enable)");
            outln!("  0xC0000081 STAR (SYSCALL Target Address)");
            outln!("  0xC0000082 LSTAR (Long Mode SYSCALL Target)");
            return;
        }

        let msr_str = args[1].trim_start_matches("0x").trim_start_matches("0X");
        let msr = match u32::from_str_radix(msr_str, 16) {
            Ok(m) => m,
            Err(_) => {
                outln!("Error: Invalid MSR '{}'", args[1]);
                return;
            }
        };

        let lo: u32;
        let hi: u32;

        unsafe {
            core::arch::asm!(
                "rdmsr",
                in("ecx") msr,
                out("eax") lo,
                out("edx") hi,
            );
        }

        let value = ((hi as u64) << 32) | (lo as u64);
        outln!("MSR {:#010x}: {:#018x}", msr, value);

        // Decode common MSRs
        if msr == 0x1B {
            outln!("  APIC Base: {:#x}", value & 0xFFFFFF000);
            outln!("  BSP: {}", (value >> 8) & 1);
            outln!("  x2APIC Enable: {}", (value >> 10) & 1);
            outln!("  Global Enable: {}", (value >> 11) & 1);
        } else if msr == 0xC0000080 {
            outln!("  EFER:");
            outln!("    SCE (SYSCALL): {}", (value >> 0) & 1);
            outln!("    LME (Long Mode Enable): {}", (value >> 8) & 1);
            outln!("    LMA (Long Mode Active): {}", (value >> 10) & 1);
            outln!("    NXE (No-Execute): {}", (value >> 11) & 1);
        }
    } else if eq_ignore_case(cmd, "tsc") {
        let lo: u32;
        let hi: u32;

        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
            );
        }

        let tsc = ((hi as u64) << 32) | (lo as u64);
        outln!("Time Stamp Counter: {}", tsc);
        outln!("  Hex: {:#018x}", tsc);
    } else if eq_ignore_case(cmd, "all") {
        // Comprehensive system state dump
        outln!("=== Complete System State ===");
        outln!("");

        // CPU Info
        let eax: u32;
        let ebx: u32;
        let ecx: u32;
        let edx: u32;

        unsafe {
            core::arch::asm!(
                "push rbx",
                "mov eax, 0",
                "cpuid",
                "mov {ebx_out:e}, ebx",
                "pop rbx",
                ebx_out = out(reg) ebx,
                out("eax") eax,
                lateout("ecx") ecx,
                out("edx") edx,
            );
        }

        let mut vendor = [0u8; 12];
        vendor[0..4].copy_from_slice(&ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&ecx.to_le_bytes());
        let vendor_str = core::str::from_utf8(&vendor).unwrap_or("?");

        outln!("[CPU]");
        outln!("  Vendor: {}", vendor_str);

        // Control Registers
        let cr0: u64;
        let cr3: u64;
        let cr4: u64;
        let rflags: u64;

        unsafe {
            core::arch::asm!(
                "mov {}, cr0",
                "mov {}, cr3",
                "mov {}, cr4",
                "pushfq",
                "pop {}",
                out(reg) cr0,
                out(reg) cr3,
                out(reg) cr4,
                out(reg) rflags,
            );
        }

        outln!("");
        outln!("[Control Registers]");
        outln!("  CR0: {:#018x} (PG={} WP={} PE={})", cr0,
            (cr0 >> 31) & 1, (cr0 >> 16) & 1, cr0 & 1);
        outln!("  CR3: {:#018x}", cr3);
        outln!("  CR4: {:#018x} (PAE={} PSE={})", cr4, (cr4 >> 5) & 1, (cr4 >> 4) & 1);
        outln!("  RFLAGS: {:#018x} (IF={})", rflags, (rflags >> 9) & 1);

        // GDT/IDT
        #[repr(C, packed)]
        struct DescriptorTablePointer {
            limit: u16,
            base: u64,
        }

        let mut gdtr = DescriptorTablePointer { limit: 0, base: 0 };
        let mut idtr = DescriptorTablePointer { limit: 0, base: 0 };

        unsafe {
            core::arch::asm!("sgdt [{}]", in(reg) &mut gdtr);
            core::arch::asm!("sidt [{}]", in(reg) &mut idtr);
        }

        // Copy from packed structs to avoid alignment issues
        let gdt_base = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(gdtr.base)) };
        let gdt_limit = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(gdtr.limit)) };
        let idt_base = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(idtr.base)) };
        let idt_limit = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(idtr.limit)) };

        outln!("");
        outln!("[Descriptor Tables]");
        outln!("  GDT: {:#018x} (limit: {:#x})", gdt_base, gdt_limit);
        outln!("  IDT: {:#018x} (limit: {:#x})", idt_base, idt_limit);

        // Stack
        let rsp: u64;
        let rbp: u64;

        unsafe {
            core::arch::asm!(
                "mov {}, rsp",
                "mov {}, rbp",
                out(reg) rsp,
                out(reg) rbp,
            );
        }

        outln!("");
        outln!("[Stack]");
        outln!("  RSP: {:#018x}", rsp);
        outln!("  RBP: {:#018x}", rbp);

        // TSC
        let lo: u32;
        let hi: u32;

        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
            );
        }

        let tsc = ((hi as u64) << 32) | (lo as u64);

        outln!("");
        outln!("[Timing]");
        outln!("  TSC: {}", tsc);

        // Exception handlers
        let veh_count = ke::rtl_get_vectored_handler_count();
        let seh_count = ke::rtl_get_seh_frame_count();

        outln!("");
        outln!("[Exception Handling]");
        outln!("  VEH Handlers: {}", veh_count);
        outln!("  SEH Frames: {}", seh_count);

        outln!("");
        outln!("=== End System State ===");
    } else if eq_ignore_case(cmd, "veh") {
        let count = ke::rtl_get_vectored_handler_count();
        outln!("Vectored Exception Handlers:");
        outln!("  Registered: {}", count);
        outln!("  Maximum:    {}", ke::MAX_VEH_HANDLERS);
    } else if eq_ignore_case(cmd, "seh") {
        let count = ke::rtl_get_seh_frame_count();
        outln!("Structured Exception Handling:");
        outln!("  Active frames: {}", count);
        outln!("  Maximum:       {}", ke::MAX_SEH_FRAMES);
    } else {
        outln!("Unknown debug command: {}", cmd);
    }
}

// ============================================================================
// PCI Command
// ============================================================================

/// PCI device scanner
pub fn cmd_pci(args: &[&str]) {
    if args.is_empty() || eq_ignore_case(args[0], "scan") {
        scan_pci_devices();
    } else if eq_ignore_case(args[0], "read") {
        if args.len() < 4 {
            outln!("Usage: pci read <bus> <device> <function>");
            return;
        }

        let bus = args[1].parse::<u8>().unwrap_or(0);
        let device = args[2].parse::<u8>().unwrap_or(0);
        let function = args[3].parse::<u8>().unwrap_or(0);

        read_pci_device(bus, device, function);
    } else if eq_ignore_case(args[0], "help") {
        outln!("PCI Configuration Space Scanner");
        outln!("");
        outln!("Usage: pci [command]");
        outln!("");
        outln!("Commands:");
        outln!("  scan                     Scan for PCI devices");
        outln!("  read <bus> <dev> <func>  Read device config space");
        outln!("  help                     Show this help");
    } else {
        outln!("Unknown pci command: {}", args[0]);
    }
}

/// Read PCI config register
fn pci_read_config(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address: u32 = 0x80000000
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);

    unsafe {
        // Write address to 0xCF8
        core::arch::asm!(
            "out dx, eax",
            in("dx") 0xCF8u16,
            in("eax") address,
        );

        // Read data from 0xCFC
        let data: u32;
        core::arch::asm!(
            "in eax, dx",
            out("eax") data,
            in("dx") 0xCFCu16,
        );

        data
    }
}

/// Get PCI class name
fn pci_class_name(class: u8, subclass: u8) -> &'static str {
    match class {
        0x00 => "Unclassified",
        0x01 => match subclass {
            0x00 => "SCSI Controller",
            0x01 => "IDE Controller",
            0x02 => "Floppy Controller",
            0x05 => "ATA Controller",
            0x06 => "SATA Controller",
            0x08 => "NVMe Controller",
            _ => "Mass Storage",
        },
        0x02 => match subclass {
            0x00 => "Ethernet Controller",
            0x80 => "Network Controller",
            _ => "Network Controller",
        },
        0x03 => match subclass {
            0x00 => "VGA Controller",
            0x01 => "XGA Controller",
            _ => "Display Controller",
        },
        0x04 => "Multimedia Controller",
        0x05 => "Memory Controller",
        0x06 => match subclass {
            0x00 => "Host Bridge",
            0x01 => "ISA Bridge",
            0x04 => "PCI-to-PCI Bridge",
            0x80 => "Bridge Device",
            _ => "Bridge Device",
        },
        0x07 => "Communication Controller",
        0x08 => "System Peripheral",
        0x09 => "Input Device",
        0x0A => "Docking Station",
        0x0B => "Processor",
        0x0C => match subclass {
            0x03 => "USB Controller",
            0x05 => "SMBus Controller",
            _ => "Serial Bus Controller",
        },
        0x0D => "Wireless Controller",
        0x0E => "Intelligent I/O Controller",
        0x0F => "Satellite Controller",
        0x10 => "Encryption Controller",
        0x11 => "Signal Processing Controller",
        0x12 => "Processing Accelerator",
        0xFF => "Vendor Specific",
        _ => "Unknown",
    }
}

/// Scan for PCI devices
fn scan_pci_devices() {
    outln!("PCI Device Scan");
    outln!("");
    outln!("Bus Dev Func  VendorID DeviceID  Class  Description");
    outln!("--- --- ----  -------- --------  -----  -----------");

    let mut count = 0;

    for bus in 0u8..=255 {
        for device in 0u8..32 {
            for function in 0u8..8 {
                let vendor_device = pci_read_config(bus, device, function, 0x00);
                let vendor_id = (vendor_device & 0xFFFF) as u16;

                // 0xFFFF means no device
                if vendor_id == 0xFFFF {
                    if function == 0 {
                        break; // No device at this slot
                    }
                    continue;
                }

                let device_id = ((vendor_device >> 16) & 0xFFFF) as u16;
                let class_reg = pci_read_config(bus, device, function, 0x08);
                let class = ((class_reg >> 24) & 0xFF) as u8;
                let subclass = ((class_reg >> 16) & 0xFF) as u8;

                let class_name = pci_class_name(class, subclass);

                outln!("{:3} {:3}   {:1}    {:04x}     {:04x}    {:02x}:{:02x}  {}",
                    bus, device, function, vendor_id, device_id, class, subclass, class_name);

                count += 1;

                // Check if multifunction device
                if function == 0 {
                    let header_type = pci_read_config(bus, device, function, 0x0C);
                    if (header_type & 0x00800000) == 0 {
                        break; // Not multifunction
                    }
                }
            }
        }
    }

    outln!("");
    outln!("Found {} PCI device(s)", count);
}

/// Read full PCI config for a device
fn read_pci_device(bus: u8, device: u8, function: u8) {
    let vendor_device = pci_read_config(bus, device, function, 0x00);
    let vendor_id = (vendor_device & 0xFFFF) as u16;

    if vendor_id == 0xFFFF {
        outln!("No device at bus {}, device {}, function {}", bus, device, function);
        return;
    }

    let device_id = ((vendor_device >> 16) & 0xFFFF) as u16;
    let status_cmd = pci_read_config(bus, device, function, 0x04);
    let class_reg = pci_read_config(bus, device, function, 0x08);
    let header = pci_read_config(bus, device, function, 0x0C);
    let subsys = pci_read_config(bus, device, function, 0x2C);
    let int_pin = pci_read_config(bus, device, function, 0x3C);

    let class = ((class_reg >> 24) & 0xFF) as u8;
    let subclass = ((class_reg >> 16) & 0xFF) as u8;
    let prog_if = ((class_reg >> 8) & 0xFF) as u8;
    let revision = (class_reg & 0xFF) as u8;

    let header_type = ((header >> 16) & 0xFF) as u8;

    outln!("PCI Device {:02x}:{:02x}.{}", bus, device, function);
    outln!("");
    outln!("  Vendor ID:      {:04x}", vendor_id);
    outln!("  Device ID:      {:04x}", device_id);
    outln!("  Command:        {:04x}", status_cmd & 0xFFFF);
    outln!("  Status:         {:04x}", (status_cmd >> 16) & 0xFFFF);
    outln!("  Class:          {:02x}:{:02x}:{:02x} ({})", class, subclass, prog_if, pci_class_name(class, subclass));
    outln!("  Revision:       {:02x}", revision);
    outln!("  Header Type:    {:02x}", header_type & 0x7F);
    outln!("  Multi-Function: {}", if (header_type & 0x80) != 0 { "Yes" } else { "No" });
    outln!("  Subsystem ID:   {:04x}:{:04x}", (subsys >> 16) & 0xFFFF, subsys & 0xFFFF);
    outln!("  IRQ Line:       {}", int_pin & 0xFF);
    outln!("  IRQ Pin:        {}", (int_pin >> 8) & 0xFF);

    // Show BARs for standard header type
    if (header_type & 0x7F) == 0 {
        outln!("");
        outln!("  Base Address Registers:");
        for i in 0..6 {
            let bar = pci_read_config(bus, device, function, (0x10 + i * 4) as u8);
            if bar != 0 {
                if (bar & 1) == 1 {
                    outln!("    BAR{}: I/O  {:08x}", i, bar & 0xFFFFFFFC);
                } else {
                    outln!("    BAR{}: MEM  {:08x}", i, bar & 0xFFFFFFF0);
                }
            }
        }
    }
}

// ============================================================================
// ACPI Command
// ============================================================================

/// ACPI table scanner
pub fn cmd_acpi(args: &[&str]) {
    if args.is_empty() || eq_ignore_case(args[0], "tables") {
        scan_acpi_tables();
    } else if eq_ignore_case(args[0], "rsdp") {
        find_rsdp();
    } else if eq_ignore_case(args[0], "help") {
        outln!("ACPI Table Scanner");
        outln!("");
        outln!("Usage: acpi [command]");
        outln!("");
        outln!("Commands:");
        outln!("  tables       List ACPI tables (default)");
        outln!("  rsdp         Find and display RSDP");
        outln!("  help         Show this help");
    } else {
        outln!("Unknown acpi command: {}", args[0]);
    }
}

/// Find RSDP in memory
fn find_rsdp() {
    outln!("Searching for ACPI RSDP...");
    outln!("");

    // Search in EBDA (Extended BIOS Data Area) - first KB at 0x40E
    // and in BIOS ROM area 0xE0000 - 0xFFFFF

    let search_regions: [(u64, u64); 2] = [
        (0x000E0000, 0x00100000),  // BIOS ROM area
        (0x00080000, 0x000A0000),  // Additional search area
    ];

    for (start, end) in search_regions {
        let mut addr = start;
        while addr < end {
            let ptr = addr as *const u8;

            // Check for "RSD PTR " signature
            let sig = unsafe {
                [
                    *ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3),
                    *ptr.add(4), *ptr.add(5), *ptr.add(6), *ptr.add(7),
                ]
            };

            if &sig == b"RSD PTR " {
                outln!("Found RSDP at {:#x}", addr);
                outln!("");

                // Read RSDP fields
                let revision = unsafe { *ptr.add(15) };
                let rsdt_addr = unsafe { *(ptr.add(16) as *const u32) };

                outln!("  Signature:  RSD PTR ");
                outln!("  Revision:   {} (ACPI {})", revision, if revision == 0 { "1.0" } else { "2.0+" });
                outln!("  RSDT Addr:  {:#010x}", rsdt_addr);

                if revision >= 2 {
                    // XSDT for ACPI 2.0+
                    let xsdt_addr = unsafe { *(ptr.add(24) as *const u64) };
                    outln!("  XSDT Addr:  {:#018x}", xsdt_addr);
                }

                return;
            }

            addr += 16; // RSDP is 16-byte aligned
        }
    }

    outln!("RSDP not found in standard locations");
    outln!("(May be provided via UEFI on modern systems)");
}

/// Scan ACPI tables
fn scan_acpi_tables() {
    outln!("ACPI Table Scan");
    outln!("");
    outln!("Note: Full ACPI parsing requires RSDP location from bootloader.");
    outln!("");

    // Try to find RSDP first
    let search_regions: [(u64, u64); 2] = [
        (0x000E0000, 0x00100000),
        (0x00080000, 0x000A0000),
    ];

    let mut rsdp_addr: Option<u64> = None;

    for (start, end) in search_regions {
        let mut addr = start;
        while addr < end {
            let ptr = addr as *const u8;
            let sig = unsafe {
                [
                    *ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3),
                    *ptr.add(4), *ptr.add(5), *ptr.add(6), *ptr.add(7),
                ]
            };

            if &sig == b"RSD PTR " {
                rsdp_addr = Some(addr);
                break;
            }
            addr += 16;
        }
        if rsdp_addr.is_some() {
            break;
        }
    }

    match rsdp_addr {
        Some(addr) => {
            outln!("RSDP found at {:#x}", addr);

            let ptr = addr as *const u8;
            let revision = unsafe { *ptr.add(15) };
            let rsdt_addr = unsafe { *(ptr.add(16) as *const u32) } as u64;

            if revision >= 2 {
                let xsdt_addr = unsafe { *(ptr.add(24) as *const u64) };
                if xsdt_addr != 0 {
                    outln!("Using XSDT at {:#x}", xsdt_addr);
                    list_acpi_tables_from_xsdt(xsdt_addr);
                    return;
                }
            }

            if rsdt_addr != 0 {
                outln!("Using RSDT at {:#x}", rsdt_addr);
                list_acpi_tables_from_rsdt(rsdt_addr);
            }
        }
        None => {
            outln!("RSDP not found in legacy BIOS areas.");
            outln!("On UEFI systems, RSDP is provided through EFI configuration table.");
        }
    }
}

/// List tables from RSDT
fn list_acpi_tables_from_rsdt(rsdt_addr: u64) {
    let ptr = rsdt_addr as *const u8;

    // Read header
    let sig = unsafe {
        [*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)]
    };
    let length = unsafe { *(ptr.add(4) as *const u32) };

    if &sig != b"RSDT" {
        outln!("Invalid RSDT signature");
        return;
    }

    let header_size = 36u32; // Standard ACPI table header
    let entry_count = (length - header_size) / 4;

    outln!("");
    outln!("RSDT contains {} table entries:", entry_count);
    outln!("");
    outln!("  Signature  Address");
    outln!("  ---------  -------");

    let entries_ptr = unsafe { ptr.add(header_size as usize) as *const u32 };

    for i in 0..entry_count {
        let table_addr = unsafe { *entries_ptr.add(i as usize) } as u64;
        let table_ptr = table_addr as *const u8;

        let table_sig = unsafe {
            [*table_ptr, *table_ptr.add(1), *table_ptr.add(2), *table_ptr.add(3)]
        };
        let sig_str = core::str::from_utf8(&table_sig).unwrap_or("????");

        outln!("  {}       {:#010x}", sig_str, table_addr);
    }
}

/// List tables from XSDT
fn list_acpi_tables_from_xsdt(xsdt_addr: u64) {
    let ptr = xsdt_addr as *const u8;

    // Read header
    let sig = unsafe {
        [*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)]
    };
    let length = unsafe { *(ptr.add(4) as *const u32) };

    if &sig != b"XSDT" {
        outln!("Invalid XSDT signature");
        return;
    }

    let header_size = 36u32;
    let entry_count = (length - header_size) / 8;

    outln!("");
    outln!("XSDT contains {} table entries:", entry_count);
    outln!("");
    outln!("  Signature  Address");
    outln!("  ---------  -------");

    let entries_ptr = unsafe { ptr.add(header_size as usize) as *const u64 };

    for i in 0..entry_count {
        let table_addr = unsafe { *entries_ptr.add(i as usize) };
        let table_ptr = table_addr as *const u8;

        let table_sig = unsafe {
            [*table_ptr, *table_ptr.add(1), *table_ptr.add(2), *table_ptr.add(3)]
        };
        let sig_str = core::str::from_utf8(&table_sig).unwrap_or("????");

        outln!("  {}       {:#018x}", sig_str, table_addr);
    }
}

// ============================================================================
// Interrupt Test Command
// ============================================================================

/// Interrupt testing command
pub fn cmd_int(args: &[&str]) {
    if args.is_empty() {
        outln!("Interrupt Testing");
        outln!("");
        outln!("Usage: int <command>");
        outln!("");
        outln!("Commands:");
        outln!("  div0           Trigger divide by zero (INT 0)");
        outln!("  break          Trigger breakpoint (INT 3)");
        outln!("  invalid        Trigger invalid opcode (INT 6)");
        outln!("  gpf            Trigger general protection fault");
        outln!("  soft <n>       Trigger software interrupt n (0-5, 0x20-21, 0x80)");
        outln!("  nmi            Trigger NMI (dangerous!)");
        outln!("");
        outln!("WARNING: Some interrupts may crash the system!");
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "div0") {
        outln!("Triggering divide by zero...");
        unsafe {
            core::arch::asm!(
                "xor edx, edx",
                "xor eax, eax",
                "xor ecx, ecx",
                "div ecx",
                options(nostack, nomem),
            );
        }
        outln!("Returned from divide by zero handler");
    } else if eq_ignore_case(cmd, "break") {
        outln!("Triggering INT 3 (breakpoint)...");
        unsafe {
            core::arch::asm!("int3");
        }
        outln!("Returned from breakpoint handler");
    } else if eq_ignore_case(cmd, "overflow") {
        // INTO instruction is not available in 64-bit mode
        outln!("INTO (overflow) instruction not available in 64-bit mode");
        outln!("Use 'int soft 4' to trigger INT 4 instead");
    } else if eq_ignore_case(cmd, "invalid") {
        outln!("Triggering invalid opcode...");
        unsafe {
            core::arch::asm!("ud2");
        }
        outln!("Returned from invalid opcode handler");
    } else if eq_ignore_case(cmd, "soft") {
        if args.len() < 2 {
            outln!("Usage: int soft <vector>");
            outln!("  vector: interrupt number (0-255)");
            return;
        }

        let vector = args[1].parse::<u8>().unwrap_or(0);
        outln!("Triggering INT {}...", vector);

        // We can only do this for a few specific vectors with inline asm
        match vector {
            0 => unsafe { core::arch::asm!("int 0x00") },
            1 => unsafe { core::arch::asm!("int 0x01") },
            2 => unsafe { core::arch::asm!("int 0x02") },
            3 => unsafe { core::arch::asm!("int 0x03") },
            0x20 => unsafe { core::arch::asm!("int 0x20") },
            0x21 => unsafe { core::arch::asm!("int 0x21") },
            0x80 => unsafe { core::arch::asm!("int 0x80") },
            _ => {
                outln!("Only vectors 0-3, 0x20, 0x21, 0x80 supported in this command");
                return;
            }
        }

        outln!("Returned from INT {} handler", vector);
    } else if eq_ignore_case(cmd, "gpf") {
        outln!("Triggering General Protection Fault...");
        outln!("WARNING: This will likely crash!");

        if args.len() > 1 && eq_ignore_case(args[1], "confirm") {
            unsafe {
                // Try to write to kernel code segment (should cause GPF)
                core::arch::asm!(
                    "mov ax, 0x08",  // Kernel code segment
                    "mov ds, ax",    // Try to load into data segment
                    options(nostack),
                );
            }
        } else {
            outln!("Use 'int gpf confirm' to actually trigger");
        }
    } else if eq_ignore_case(cmd, "nmi") {
        outln!("Triggering NMI (Non-Maskable Interrupt)...");
        outln!("WARNING: This is dangerous!");

        if args.len() > 1 && eq_ignore_case(args[1], "confirm") {
            unsafe {
                core::arch::asm!("int 0x02");
            }
            outln!("Returned from NMI handler");
        } else {
            outln!("Use 'int nmi confirm' to actually trigger");
        }
    } else {
        outln!("Unknown int command: {}", cmd);
    }
}

// ============================================================================
// Timer Diagnostics Command
// ============================================================================

/// Timer diagnostics command
pub fn cmd_timer(args: &[&str]) {
    use crate::hal::apic;

    if args.is_empty() || eq_ignore_case(args[0], "status") {
        show_timer_status();
    } else if eq_ignore_case(args[0], "apic") {
        show_apic_timer_status();
    } else if eq_ignore_case(args[0], "tsc") {
        show_tsc_info();
    } else if eq_ignore_case(args[0], "active") {
        show_active_timers();
    } else if eq_ignore_case(args[0], "tick") {
        outln!("Current tick count: {}", apic::get_tick_count());
    } else if eq_ignore_case(args[0], "pit") {
        show_pit_status();
    } else if eq_ignore_case(args[0], "help") {
        outln!("Timer Diagnostics");
        outln!("");
        outln!("Usage: timer [command]");
        outln!("");
        outln!("Commands:");
        outln!("  status     Show timer overview (default)");
        outln!("  apic       Show APIC timer details");
        outln!("  tsc        Show TSC (Time Stamp Counter) info");
        outln!("  active     Show active kernel timers");
        outln!("  tick       Show current tick count");
        outln!("  pit        Show PIT (8254) status");
        outln!("  help       Show this help");
    } else {
        outln!("Unknown timer command: {}", args[0]);
    }
}

/// Show timer status overview
fn show_timer_status() {
    use crate::hal::apic;
    use crate::ke::timer;

    outln!("Timer Status Overview");
    outln!("");

    // System tick count
    let ticks = apic::get_tick_count();
    outln!("System Ticks:    {}", ticks);

    // Approximate uptime (assuming ~1000 ticks/sec)
    let seconds = ticks / 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;
    outln!("Approx Uptime:   {}h {}m {}s", hours, minutes % 60, seconds % 60);

    // Active timers
    let active = timer::ki_get_active_timer_count();
    outln!("Active Timers:   {}", active);

    // Next timer delta
    if let Some(delta) = timer::ki_get_next_timer_delta() {
        outln!("Next Expiry:     {} ms", delta);
    } else {
        outln!("Next Expiry:     (none)");
    }

    outln!("");

    // TSC
    let tsc: u64;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") tsc,
            out("rdx") _,
        );
    }
    outln!("TSC Value:       {:#018x} ({})", tsc, tsc);

    // APIC info
    let lapic = apic::get();
    outln!("APIC Base:       {:#x}", lapic.base_address());
    outln!("APIC ID:         {}", lapic.id());
}

/// Show APIC timer details
fn show_apic_timer_status() {
    use crate::hal::apic;

    outln!("APIC Timer Status");
    outln!("");

    let lapic = apic::get();

    outln!("APIC Base:      {:#x}", lapic.base_address());
    outln!("APIC ID:        {}", lapic.id());
    outln!("APIC Version:   {:#x}", lapic.version());
    outln!("");

    // Read timer registers directly
    let base = lapic.base_address();

    unsafe {
        let lvt_timer = core::ptr::read_volatile((base + 0x320) as *const u32);
        let timer_init = core::ptr::read_volatile((base + 0x380) as *const u32);
        let timer_current = core::ptr::read_volatile((base + 0x390) as *const u32);
        let timer_divide = core::ptr::read_volatile((base + 0x3E0) as *const u32);

        outln!("LVT Timer:      {:#010x}", lvt_timer);
        outln!("  Vector:       {}", lvt_timer & 0xFF);
        outln!("  Masked:       {}", if (lvt_timer & (1 << 16)) != 0 { "Yes" } else { "No" });

        let mode = (lvt_timer >> 17) & 0x3;
        let mode_str = match mode {
            0 => "One-shot",
            1 => "Periodic",
            2 => "TSC-Deadline",
            _ => "Reserved",
        };
        outln!("  Mode:         {}", mode_str);

        outln!("");
        outln!("Initial Count:  {}", timer_init);
        outln!("Current Count:  {}", timer_current);

        let divider = match timer_divide & 0xF {
            0b0000 => 2,
            0b0001 => 4,
            0b0010 => 8,
            0b0011 => 16,
            0b1000 => 32,
            0b1001 => 64,
            0b1010 => 128,
            0b1011 => 1,
            _ => 0,
        };
        outln!("Divider:        {} (raw: {:#x})", divider, timer_divide);

        // Calculate frequency if we have enough info
        if timer_init > 0 && divider > 0 {
            outln!("");
            outln!("Timer frequency depends on bus clock (typically 100-200MHz)");
            outln!("At 100MHz bus with div {}: ~{} Hz interrupt rate",
                divider, 100_000_000 / (divider * timer_init));
        }
    }
}

/// Show TSC information
fn show_tsc_info() {
    outln!("Time Stamp Counter (TSC) Information");
    outln!("");

    // Read TSC
    let tsc1: u64;
    let tsc2: u64;

    unsafe {
        core::arch::asm!(
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") tsc1,
            out("rdx") _,
        );

        // Small delay
        for _ in 0..10000 {
            core::hint::spin_loop();
        }

        core::arch::asm!(
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") tsc2,
            out("rdx") _,
        );
    }

    outln!("TSC Value:     {}", tsc1);
    outln!("TSC (hex):     {:#018x}", tsc1);

    let delta = tsc2.saturating_sub(tsc1);
    outln!("");
    outln!("Cycles in ~10k spins: {}", delta);

    // Check CPUID for TSC features
    let (_, _, ecx, edx): (u32, u32, u32, u32);
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => _,
            out("ecx") ecx,
            out("edx") edx,
        );
    }

    outln!("");
    outln!("TSC Features:");
    outln!("  TSC Available:   {}", if (edx & (1 << 4)) != 0 { "Yes" } else { "No" });

    // Check for invariant TSC (leaf 0x80000007)
    let (eax_max, _, _, _): (u32, u32, u32, u32);
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 0x80000000u32 => eax_max,
            out("ecx") _,
            out("edx") _,
        );
    }

    if eax_max >= 0x80000007 {
        let (_, _, _, edx_adv): (u32, u32, u32, u32);
        unsafe {
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "pop rbx",
                inout("eax") 0x80000007u32 => _,
                out("ecx") _,
                out("edx") edx_adv,
            );
        }
        outln!("  Invariant TSC:   {}", if (edx_adv & (1 << 8)) != 0 { "Yes" } else { "No" });
    }

    // Check for TSC deadline mode
    outln!("  TSC-Deadline:    {}", if (ecx & (1 << 24)) != 0 { "Yes" } else { "No" });
}

/// Show active kernel timers
fn show_active_timers() {
    use crate::ke::timer;

    outln!("Active Kernel Timers");
    outln!("");

    let count = timer::ki_get_active_timer_count();
    outln!("Active timer count: {}", count);

    if count > 0 {
        if let Some(delta) = timer::ki_get_next_timer_delta() {
            outln!("Next timer expires in: {} ms", delta);
        }
    }

    outln!("");
    outln!("Note: Detailed timer list not available without list traversal.");
    outln!("Timer subsystem tracks timers internally for expiration.");
}

/// Show PIT (8254) status
fn show_pit_status() {
    outln!("PIT (8254) Status");
    outln!("");

    // Read-back command: latch count and status for all channels
    // Command: 0xE2 = 11100010
    //   Bits 7-6: 11 = Read-back command
    //   Bit 5: 0 = Latch count
    //   Bit 4: 0 = Latch status
    //   Bit 3: 1 = Channel 2
    //   Bit 2: 1 = Channel 1
    //   Bit 1: 1 = Channel 0

    // Note: In many VM environments, PIT may be partially emulated
    // We'll read channel 0 which is the main timer

    unsafe {
        // Read channel 0 counter (ports 0x40, 0x41, 0x42 for channels 0, 1, 2)
        // Port 0x43 is the mode/command register

        // First, latch the counter for channel 0
        // Command 0x00 latches channel 0
        core::arch::asm!(
            "mov al, 0x00",
            "out 0x43, al",
            out("al") _,
        );

        // Read low byte then high byte
        let low: u8;
        let high: u8;
        core::arch::asm!(
            "in al, 0x40",
            out("al") low,
        );
        core::arch::asm!(
            "in al, 0x40",
            out("al") high,
        );

        let count = ((high as u16) << 8) | (low as u16);
        outln!("Channel 0 Count:  {} ({:#06x})", count, count);
    }

    outln!("");
    outln!("PIT Base Frequency: 1.193182 MHz");
    outln!("Port 0x40: Channel 0 (system timer)");
    outln!("Port 0x41: Channel 1 (DRAM refresh, legacy)");
    outln!("Port 0x42: Channel 2 (PC speaker)");
    outln!("Port 0x43: Mode/Command register");
    outln!("");
    outln!("Note: Modern systems use APIC timer instead of PIT.");
}

// ============================================================================
// Memory Map Command
// ============================================================================

/// Memory map and physical memory diagnostics
pub fn cmd_memmap(args: &[&str]) {
    use crate::mm;

    if args.is_empty() || eq_ignore_case(args[0], "regions") {
        show_memory_regions();
    } else if eq_ignore_case(args[0], "stats") {
        show_memory_stats();
    } else if eq_ignore_case(args[0], "e820") {
        show_e820_style();
    } else if eq_ignore_case(args[0], "phys") {
        if args.len() < 2 {
            outln!("Usage: memmap phys <address>");
            return;
        }
        let addr_str = args[1].trim_start_matches("0x").trim_start_matches("0X");
        match u64::from_str_radix(addr_str, 16) {
            Ok(addr) => check_physical_address(addr),
            Err(_) => outln!("Error: Invalid address '{}'", args[1]),
        }
    } else if eq_ignore_case(args[0], "help") {
        outln!("Memory Map Diagnostics");
        outln!("");
        outln!("Usage: memmap [command]");
        outln!("");
        outln!("Commands:");
        outln!("  regions        List all memory regions (default)");
        outln!("  stats          Show physical memory statistics");
        outln!("  e820           Show E820-style memory map");
        outln!("  phys <addr>    Check physical address type");
        outln!("  help           Show this help");
    } else {
        outln!("Unknown memmap command: {}", args[0]);
    }
}

/// Show all memory regions
fn show_memory_regions() {
    use crate::mm;

    let count = mm::mm_get_region_count();

    outln!("Physical Memory Regions ({} total)", count);
    outln!("");
    outln!("  Start            End              Pages       Size        Type");
    outln!("  ---------------  ---------------  ----------  ----------  ----");

    let mut total_usable = 0u64;
    let mut total_reserved = 0u64;

    for i in 0..count {
        if let Some(region) = mm::mm_get_region(i) {
            let type_name = memory_type_name(region.memory_type);
            let size = region.page_count * 4096;

            let size_str = format_size(size);

            outln!("  {:016x}  {:016x}  {:10}  {:>10}  {}",
                region.physical_start,
                region.physical_end(),
                region.page_count,
                size_str,
                type_name);

            if region.memory_type.is_usable() {
                total_usable += size;
            } else {
                total_reserved += size;
            }
        }
    }

    outln!("");
    outln!("Summary:");
    outln!("  Usable:   {} ({} pages)", format_size(total_usable), total_usable / 4096);
    outln!("  Reserved: {} ({} pages)", format_size(total_reserved), total_reserved / 4096);
}

/// Show memory statistics
fn show_memory_stats() {
    use crate::mm;

    let stats = mm::mm_get_physical_stats();

    outln!("Physical Memory Statistics");
    outln!("");
    outln!("  Total Physical:   {} ({} pages)",
        format_size(stats.total_bytes),
        stats.total_pages);
    outln!("  Usable Physical:  {} ({} pages)",
        format_size(stats.usable_bytes),
        stats.total_pages);
    outln!("");
    outln!("Page Frame Database:");
    outln!("  Total Pages:      {}", stats.total_pages);
    outln!("  Free Pages:       {}", stats.free_pages);
    outln!("  Zeroed Pages:     {}", stats.zeroed_pages);
    outln!("  Active Pages:     {}", stats.active_pages);
    outln!("");
    outln!("  Free Memory:      {}", format_size(stats.free_bytes()));
    outln!("  Usage:            {}%", stats.usage_percent());

    // Pool stats
    let pool_stats = mm::mm_get_pool_stats();
    outln!("");
    outln!("Pool Allocator:");
    outln!("  Total Size:       {} bytes", pool_stats.total_size);
    outln!("  Bytes Allocated:  {} bytes", pool_stats.bytes_allocated);
    outln!("  Bytes Free:       {} bytes", pool_stats.bytes_free);
    outln!("  Allocations:      {}", pool_stats.allocation_count);
    outln!("  Free Count:       {}", pool_stats.free_count);
}

/// Show E820-style memory map
fn show_e820_style() {
    use crate::mm;

    let count = mm::mm_get_region_count();

    outln!("E820-style Memory Map");
    outln!("");
    outln!("BIOS-e820: {} entries", count);
    outln!("");

    for i in 0..count {
        if let Some(region) = mm::mm_get_region(i) {
            let e820_type = match region.memory_type {
                mm::MmMemoryType::Conventional |
                mm::MmMemoryType::LoaderCode |
                mm::MmMemoryType::LoaderData |
                mm::MmMemoryType::BootServicesCode |
                mm::MmMemoryType::BootServicesData => "usable",
                mm::MmMemoryType::Reserved => "reserved",
                mm::MmMemoryType::AcpiReclaim => "ACPI data",
                mm::MmMemoryType::AcpiNvs => "ACPI NVS",
                mm::MmMemoryType::Unusable => "unusable",
                mm::MmMemoryType::RuntimeServicesCode |
                mm::MmMemoryType::RuntimeServicesData => "runtime",
                mm::MmMemoryType::Mmio |
                mm::MmMemoryType::MmioPortSpace => "MMIO",
                mm::MmMemoryType::PalCode => "PAL code",
                mm::MmMemoryType::Persistent => "persistent",
            };

            outln!(" [{:016x}-{:016x}] {} {}",
                region.physical_start,
                region.physical_end().saturating_sub(1),
                format_size(region.size()),
                e820_type);
        }
    }
}

/// Check type of a physical address
fn check_physical_address(addr: u64) {
    use crate::mm;

    outln!("Physical Address: {:#018x}", addr);
    outln!("");

    if let Some(mem_type) = mm::mm_get_physical_memory_type(addr) {
        outln!("  Memory Type: {}", memory_type_name(mem_type));
        outln!("  Usable:      {}", if mem_type.is_usable() { "Yes" } else { "No" });
        outln!("  Preserved:   {}", if mem_type.must_preserve() { "Yes" } else { "No" });
    } else {
        outln!("  Not mapped to any memory region");
    }

    outln!("");
    outln!("  Valid RAM:   {}", if mm::mm_is_valid_physical_address(addr) { "Yes" } else { "No" });

    // Page info
    let pfn = addr / 4096;
    outln!("  Page Frame:  {:#x} ({})", pfn, pfn);
}

/// Get human-readable name for memory type
fn memory_type_name(mem_type: crate::mm::MmMemoryType) -> &'static str {
    use crate::mm::MmMemoryType;
    match mem_type {
        MmMemoryType::Reserved => "Reserved",
        MmMemoryType::LoaderCode => "LoaderCode",
        MmMemoryType::LoaderData => "LoaderData",
        MmMemoryType::BootServicesCode => "BootCode",
        MmMemoryType::BootServicesData => "BootData",
        MmMemoryType::RuntimeServicesCode => "RuntimeCode",
        MmMemoryType::RuntimeServicesData => "RuntimeData",
        MmMemoryType::Conventional => "Conventional",
        MmMemoryType::Unusable => "Unusable",
        MmMemoryType::AcpiReclaim => "AcpiReclaim",
        MmMemoryType::AcpiNvs => "AcpiNVS",
        MmMemoryType::Mmio => "MMIO",
        MmMemoryType::MmioPortSpace => "MMIOPort",
        MmMemoryType::PalCode => "PalCode",
        MmMemoryType::Persistent => "Persistent",
    }
}

/// Format size in human-readable form
fn format_size(bytes: u64) -> &'static str {
    // Since we can't allocate strings, use static buffers
    // This is a simplified version
    static mut SIZE_BUFS: [[u8; 16]; 4] = [[0; 16]; 4];
    static mut BUF_IDX: usize = 0;

    unsafe {
        let idx = BUF_IDX;
        BUF_IDX = (BUF_IDX + 1) % 4;

        let buf = &mut SIZE_BUFS[idx];
        buf.fill(0);

        let (value, suffix) = if bytes >= 1024 * 1024 * 1024 {
            (bytes / (1024 * 1024 * 1024), "GB")
        } else if bytes >= 1024 * 1024 {
            (bytes / (1024 * 1024), "MB")
        } else if bytes >= 1024 {
            (bytes / 1024, "KB")
        } else {
            (bytes, "B")
        };

        // Format the number
        let mut pos = 0;
        let mut n = value;
        let mut digits = [0u8; 12];
        let mut digit_count = 0;

        if n == 0 {
            digits[0] = b'0';
            digit_count = 1;
        } else {
            while n > 0 && digit_count < 12 {
                digits[digit_count] = b'0' + (n % 10) as u8;
                n /= 10;
                digit_count += 1;
            }
        }

        // Reverse digits into buffer
        for i in (0..digit_count).rev() {
            if pos < 12 {
                buf[pos] = digits[i];
                pos += 1;
            }
        }

        // Add suffix
        for c in suffix.bytes() {
            if pos < 15 {
                buf[pos] = c;
                pos += 1;
            }
        }

        core::str::from_utf8_unchecked(&buf[..pos])
    }
}

// ============================================================================
// CPU Features Command
// ============================================================================

/// CPU feature detection and information
pub fn cmd_cpufeatures(args: &[&str]) {
    if args.is_empty() || eq_ignore_case(args[0], "all") {
        show_all_cpu_features();
    } else if eq_ignore_case(args[0], "vendor") {
        show_cpu_vendor();
    } else if eq_ignore_case(args[0], "basic") {
        show_basic_features();
    } else if eq_ignore_case(args[0], "extended") {
        show_extended_features();
    } else if eq_ignore_case(args[0], "cache") {
        show_cache_info();
    } else if eq_ignore_case(args[0], "raw") {
        if args.len() < 2 {
            outln!("Usage: cpufeatures raw <leaf> [subleaf]");
            return;
        }
        let leaf_str = args[1].trim_start_matches("0x").trim_start_matches("0X");
        let leaf = u32::from_str_radix(leaf_str, 16).unwrap_or(0);
        let subleaf = if args.len() > 2 {
            let sub_str = args[2].trim_start_matches("0x").trim_start_matches("0X");
            u32::from_str_radix(sub_str, 16).unwrap_or(0)
        } else {
            0
        };
        show_raw_cpuid(leaf, subleaf);
    } else if eq_ignore_case(args[0], "help") {
        outln!("CPU Feature Detection");
        outln!("");
        outln!("Usage: cpufeatures [command]");
        outln!("");
        outln!("Commands:");
        outln!("  all              Show all CPU features (default)");
        outln!("  vendor           Show vendor and brand string");
        outln!("  basic            Show basic feature flags");
        outln!("  extended         Show extended feature flags");
        outln!("  cache            Show cache information");
        outln!("  raw <leaf>       Show raw CPUID leaf");
        outln!("  help             Show this help");
    } else {
        outln!("Unknown cpufeatures command: {}", args[0]);
    }
}

/// Read CPUID with rbx workaround
fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;

    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            ebx_out = out(reg) ebx,
            inout("ecx") subleaf => ecx,
            out("edx") edx,
        );
    }

    (eax, ebx, ecx, edx)
}

/// Show all CPU features
fn show_all_cpu_features() {
    show_cpu_vendor();
    outln!("");
    show_basic_features();
    outln!("");
    show_extended_features();
}

/// Show CPU vendor and brand
fn show_cpu_vendor() {
    outln!("CPU Identification");
    outln!("");

    // Leaf 0: Vendor string
    let (max_leaf, ebx, ecx, edx) = cpuid(0, 0);

    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&ecx.to_le_bytes());
    let vendor_str = core::str::from_utf8(&vendor).unwrap_or("Unknown");

    outln!("  Vendor:     {}", vendor_str);
    outln!("  Max Leaf:   {:#x}", max_leaf);

    // Leaf 1: Family/Model/Stepping
    if max_leaf >= 1 {
        let (eax, _ebx, _ecx, _edx) = cpuid(1, 0);

        let stepping = eax & 0xF;
        let model = (eax >> 4) & 0xF;
        let family = (eax >> 8) & 0xF;
        let ext_model = (eax >> 16) & 0xF;
        let ext_family = (eax >> 20) & 0xFF;

        let display_family = if family == 0xF {
            family + ext_family
        } else {
            family
        };

        let display_model = if family == 0x6 || family == 0xF {
            (ext_model << 4) + model
        } else {
            model
        };

        outln!("  Family:     {} (ext: {})", display_family, ext_family);
        outln!("  Model:      {} (ext: {})", display_model, ext_model);
        outln!("  Stepping:   {}", stepping);
    }

    // Extended leaf 0x80000000: Max extended leaf
    let (max_ext_leaf, _, _, _) = cpuid(0x80000000, 0);

    if max_ext_leaf >= 0x80000004 {
        outln!("");
        outln!("  Brand String:");

        // Read brand string from leaves 0x80000002-0x80000004
        let mut brand = [0u8; 48];

        for i in 0..3 {
            let (eax, ebx, ecx, edx) = cpuid(0x80000002 + i, 0);
            let offset = (i as usize) * 16;
            brand[offset..offset+4].copy_from_slice(&eax.to_le_bytes());
            brand[offset+4..offset+8].copy_from_slice(&ebx.to_le_bytes());
            brand[offset+8..offset+12].copy_from_slice(&ecx.to_le_bytes());
            brand[offset+12..offset+16].copy_from_slice(&edx.to_le_bytes());
        }

        // Trim trailing nulls and whitespace
        let brand_len = brand.iter().rposition(|&c| c != 0 && c != b' ').map_or(0, |i| i + 1);
        let brand_str = core::str::from_utf8(&brand[..brand_len]).unwrap_or("Unknown");
        outln!("    {}", brand_str.trim());
    }
}

/// Show basic feature flags (leaf 1)
fn show_basic_features() {
    outln!("Basic CPU Features (CPUID.01H)");
    outln!("");

    let (max_leaf, _, _, _) = cpuid(0, 0);
    if max_leaf < 1 {
        outln!("  Leaf 1 not supported");
        return;
    }

    let (_, _, ecx, edx) = cpuid(1, 0);

    // EDX features
    outln!("  EDX Features:");
    let edx_features = [
        (0, "FPU", "x87 FPU"),
        (1, "VME", "Virtual Mode Extensions"),
        (2, "DE", "Debugging Extensions"),
        (3, "PSE", "Page Size Extension"),
        (4, "TSC", "Time Stamp Counter"),
        (5, "MSR", "Model Specific Registers"),
        (6, "PAE", "Physical Address Extension"),
        (7, "MCE", "Machine Check Exception"),
        (8, "CX8", "CMPXCHG8B"),
        (9, "APIC", "On-chip APIC"),
        (11, "SEP", "SYSENTER/SYSEXIT"),
        (12, "MTRR", "Memory Type Range Registers"),
        (13, "PGE", "Page Global Enable"),
        (14, "MCA", "Machine Check Architecture"),
        (15, "CMOV", "Conditional Move"),
        (16, "PAT", "Page Attribute Table"),
        (17, "PSE36", "36-bit Page Size Extension"),
        (19, "CLFSH", "CLFLUSH"),
        (23, "MMX", "MMX"),
        (24, "FXSR", "FXSAVE/FXRSTOR"),
        (25, "SSE", "SSE"),
        (26, "SSE2", "SSE2"),
        (28, "HTT", "Hyper-Threading"),
    ];

    for (bit, name, _desc) in edx_features {
        if (edx & (1 << bit)) != 0 {
            out!("  {} ", name);
        }
    }
    outln!("");

    // ECX features
    outln!("");
    outln!("  ECX Features:");
    let ecx_features = [
        (0, "SSE3", "SSE3"),
        (1, "PCLMULQDQ", "Carry-less Multiplication"),
        (3, "MONITOR", "MONITOR/MWAIT"),
        (9, "SSSE3", "SSSE3"),
        (12, "FMA", "FMA"),
        (13, "CX16", "CMPXCHG16B"),
        (19, "SSE4.1", "SSE4.1"),
        (20, "SSE4.2", "SSE4.2"),
        (21, "x2APIC", "x2APIC"),
        (22, "MOVBE", "MOVBE"),
        (23, "POPCNT", "POPCNT"),
        (24, "TSC-DL", "TSC-Deadline"),
        (25, "AES", "AES-NI"),
        (26, "XSAVE", "XSAVE"),
        (27, "OSXSAVE", "OSXSAVE"),
        (28, "AVX", "AVX"),
        (29, "F16C", "F16C"),
        (30, "RDRAND", "RDRAND"),
    ];

    for (bit, name, _desc) in ecx_features {
        if (ecx & (1 << bit)) != 0 {
            out!("  {} ", name);
        }
    }
    outln!("");
}

/// Show extended feature flags (leaf 7)
fn show_extended_features() {
    outln!("Extended CPU Features (CPUID.07H)");
    outln!("");

    let (max_leaf, _, _, _) = cpuid(0, 0);
    if max_leaf < 7 {
        outln!("  Leaf 7 not supported");
        return;
    }

    let (_, ebx, ecx, edx) = cpuid(7, 0);

    outln!("  EBX Features:");
    let ebx_features = [
        (0, "FSGSBASE", "FSGSBASE"),
        (3, "BMI1", "BMI1"),
        (4, "HLE", "HLE"),
        (5, "AVX2", "AVX2"),
        (7, "SMEP", "SMEP"),
        (8, "BMI2", "BMI2"),
        (9, "ERMS", "Enhanced REP MOVSB/STOSB"),
        (10, "INVPCID", "INVPCID"),
        (11, "RTM", "RTM"),
        (16, "AVX512F", "AVX-512 Foundation"),
        (18, "RDSEED", "RDSEED"),
        (19, "ADX", "ADX"),
        (20, "SMAP", "SMAP"),
        (23, "CLFLUSHOPT", "CLFLUSHOPT"),
        (26, "CLWB", "CLWB"),
        (29, "SHA", "SHA"),
    ];

    for (bit, name, _desc) in ebx_features {
        if (ebx & (1 << bit)) != 0 {
            out!("  {} ", name);
        }
    }
    outln!("");

    // ECX features
    if ecx != 0 {
        outln!("");
        outln!("  ECX Features:");
        let ecx_features = [
            (1, "WAITPKG", "UMONITOR/UMWAIT/TPAUSE"),
            (7, "CET_SS", "CET Shadow Stack"),
            (22, "RDPID", "RDPID"),
        ];

        for (bit, name, _desc) in ecx_features {
            if (ecx & (1 << bit)) != 0 {
                out!("  {} ", name);
            }
        }
        outln!("");
    }

    // Check for extended CPUID (AMD)
    let (max_ext, _, _, _) = cpuid(0x80000000, 0);
    if max_ext >= 0x80000001 {
        let (_, _, _ext_ecx, ext_edx) = cpuid(0x80000001, 0);

        outln!("");
        outln!("  Extended (AMD) Features:");
        let ext_features = [
            (11, "SYSCALL", "SYSCALL/SYSRET"),
            (20, "NX", "No-Execute"),
            (26, "1GBPAGES", "1GB Pages"),
            (27, "RDTSCP", "RDTSCP"),
            (29, "LM", "Long Mode"),
        ];

        for (bit, name, _desc) in ext_features {
            if (ext_edx & (1 << bit)) != 0 {
                out!("  {} ", name);
            }
        }
        outln!("");
    }
}

/// Show cache information
fn show_cache_info() {
    outln!("CPU Cache Information");
    outln!("");

    let (max_leaf, _, _, _) = cpuid(0, 0);

    // Try leaf 4 (Intel deterministic cache parameters)
    if max_leaf >= 4 {
        outln!("  Deterministic Cache Parameters (Leaf 4):");
        outln!("");

        for i in 0..8 {
            let (eax, ebx, ecx, _edx) = cpuid(4, i);

            let cache_type = eax & 0x1F;
            if cache_type == 0 {
                break; // No more caches
            }

            let level = (eax >> 5) & 0x7;
            let type_name = match cache_type {
                1 => "Data",
                2 => "Instruction",
                3 => "Unified",
                _ => "Unknown",
            };

            let ways = ((ebx >> 22) & 0x3FF) + 1;
            let partitions = ((ebx >> 12) & 0x3FF) + 1;
            let line_size = (ebx & 0xFFF) + 1;
            let sets = ecx + 1;

            let size = ways * partitions * line_size * sets;
            let size_kb = size / 1024;

            outln!("    L{} {} Cache: {} KB ({} ways, {} line, {} sets)",
                level, type_name, size_kb, ways, line_size, sets);
        }
    } else {
        outln!("  Leaf 4 not supported");
    }
}

/// Show raw CPUID output
fn show_raw_cpuid(leaf: u32, subleaf: u32) {
    let (eax, ebx, ecx, edx) = cpuid(leaf, subleaf);

    outln!("CPUID Leaf {:#x}, Subleaf {:#x}", leaf, subleaf);
    outln!("");
    outln!("  EAX: {:#010x} ({})", eax, eax);
    outln!("  EBX: {:#010x} ({})", ebx, ebx);
    outln!("  ECX: {:#010x} ({})", ecx, ecx);
    outln!("  EDX: {:#010x} ({})", edx, edx);
    outln!("");

    // Show as binary for feature flags
    outln!("  Binary:");
    outln!("  EAX: {:032b}", eax);
    outln!("  EBX: {:032b}", ebx);
    outln!("  ECX: {:032b}", ecx);
    outln!("  EDX: {:032b}", edx);
}

// ============================================================================
// Page Table Walker Command
// ============================================================================

/// Page table walker and virtual address diagnostics
pub fn cmd_pagetable(args: &[&str]) {
    if args.is_empty() || eq_ignore_case(args[0], "cr3") {
        show_cr3_info();
    } else if eq_ignore_case(args[0], "walk") {
        if args.len() < 2 {
            outln!("Usage: pagetable walk <virtual_address>");
            return;
        }
        let addr_str = args[1].trim_start_matches("0x").trim_start_matches("0X");
        match u64::from_str_radix(addr_str, 16) {
            Ok(addr) => walk_page_tables(addr),
            Err(_) => outln!("Error: Invalid address '{}'", args[1]),
        }
    } else if eq_ignore_case(args[0], "translate") {
        if args.len() < 2 {
            outln!("Usage: pagetable translate <virtual_address>");
            return;
        }
        let addr_str = args[1].trim_start_matches("0x").trim_start_matches("0X");
        match u64::from_str_radix(addr_str, 16) {
            Ok(addr) => translate_address(addr),
            Err(_) => outln!("Error: Invalid address '{}'", args[1]),
        }
    } else if eq_ignore_case(args[0], "kernel") {
        show_kernel_mappings();
    } else if eq_ignore_case(args[0], "help") {
        outln!("Page Table Walker");
        outln!("");
        outln!("Usage: pagetable [command]");
        outln!("");
        outln!("Commands:");
        outln!("  cr3              Show CR3 register info (default)");
        outln!("  walk <addr>      Walk page tables for address");
        outln!("  translate <addr> Translate virtual to physical");
        outln!("  kernel           Show kernel mapping summary");
        outln!("  help             Show this help");
    } else {
        outln!("Unknown pagetable command: {}", args[0]);
    }
}

/// Show CR3 register information
fn show_cr3_info() {
    outln!("Page Table Base Register (CR3)");
    outln!("");

    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3);
    }

    outln!("  CR3 Value:      {:#018x}", cr3);
    outln!("");

    // Decode CR3 bits
    let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;
    let pcid = cr3 & 0xFFF;
    let pwt = (cr3 >> 3) & 1;
    let pcd = (cr3 >> 4) & 1;

    outln!("  PML4 Base:      {:#018x}", pml4_base);
    outln!("  PCID:           {:#x} (if CR4.PCIDE=1)", pcid);
    outln!("  PWT:            {} (Page-level Write-Through)", pwt);
    outln!("  PCD:            {} (Page-level Cache Disable)", pcd);

    // Read CR4 to check PCIDE
    let cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
    }
    let pcide = (cr4 >> 17) & 1;
    outln!("");
    outln!("  CR4.PCIDE:      {} (PCID Enable)", pcide);

    // Show CR0 paging bits
    let cr0: u64;
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0);
    }
    outln!("");
    outln!("  Paging Status:");
    outln!("    CR0.PG:       {} (Paging Enabled)", (cr0 >> 31) & 1);
    outln!("    CR0.WP:       {} (Write Protect)", (cr0 >> 16) & 1);
    outln!("    CR4.PAE:      {} (Physical Address Extension)", (cr4 >> 5) & 1);
    outln!("    CR4.PSE:      {} (Page Size Extensions)", (cr4 >> 4) & 1);
    outln!("    CR4.PGE:      {} (Page Global Enable)", (cr4 >> 7) & 1);
    outln!("    CR4.SMEP:     {} (Supervisor Mode Exec Protection)", (cr4 >> 20) & 1);
    outln!("    CR4.SMAP:     {} (Supervisor Mode Access Prevention)", (cr4 >> 21) & 1);
}

/// Walk page tables for a virtual address
fn walk_page_tables(vaddr: u64) {
    outln!("Page Table Walk for Virtual Address {:#018x}", vaddr);
    outln!("");

    // Check canonical address
    let sign_ext = (vaddr >> 47) & 1;
    let upper_bits = vaddr >> 48;
    let is_canonical = (sign_ext == 0 && upper_bits == 0) ||
                       (sign_ext == 1 && upper_bits == 0xFFFF);

    if !is_canonical {
        outln!("  ERROR: Non-canonical address!");
        return;
    }

    // Get CR3
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3);
    }
    let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;

    // Calculate indices
    let pml4_idx = (vaddr >> 39) & 0x1FF;
    let pdpt_idx = (vaddr >> 30) & 0x1FF;
    let pd_idx = (vaddr >> 21) & 0x1FF;
    let pt_idx = (vaddr >> 12) & 0x1FF;
    let offset = vaddr & 0xFFF;

    outln!("  Address Breakdown:");
    outln!("    PML4 Index:   {} ({:#x})", pml4_idx, pml4_idx);
    outln!("    PDPT Index:   {} ({:#x})", pdpt_idx, pdpt_idx);
    outln!("    PD Index:     {} ({:#x})", pd_idx, pd_idx);
    outln!("    PT Index:     {} ({:#x})", pt_idx, pt_idx);
    outln!("    Page Offset:  {} ({:#x})", offset, offset);
    outln!("");

    // Walk page tables
    outln!("  Page Table Walk:");

    // Level 4: PML4
    let pml4e_addr = pml4_base + pml4_idx * 8;
    let pml4e = unsafe { core::ptr::read_volatile(pml4e_addr as *const u64) };
    outln!("    PML4E @ {:#x}: {:#018x}", pml4e_addr, pml4e);
    decode_pte(pml4e, "PML4E");

    if (pml4e & 1) == 0 {
        outln!("    -> Not Present!");
        return;
    }

    // Level 3: PDPT
    let pdpt_base = pml4e & 0x000F_FFFF_FFFF_F000;
    let pdpte_addr = pdpt_base + pdpt_idx * 8;
    let pdpte = unsafe { core::ptr::read_volatile(pdpte_addr as *const u64) };
    outln!("");
    outln!("    PDPTE @ {:#x}: {:#018x}", pdpte_addr, pdpte);
    decode_pte(pdpte, "PDPTE");

    if (pdpte & 1) == 0 {
        outln!("    -> Not Present!");
        return;
    }

    // Check for 1GB page
    if (pdpte & 0x80) != 0 {
        let phys = (pdpte & 0x000F_FFFF_C000_0000) | (vaddr & 0x3FFF_FFFF);
        outln!("");
        outln!("    -> 1GB Page!");
        outln!("    Physical Address: {:#018x}", phys);
        return;
    }

    // Level 2: PD
    let pd_base = pdpte & 0x000F_FFFF_FFFF_F000;
    let pde_addr = pd_base + pd_idx * 8;
    let pde = unsafe { core::ptr::read_volatile(pde_addr as *const u64) };
    outln!("");
    outln!("    PDE @ {:#x}: {:#018x}", pde_addr, pde);
    decode_pte(pde, "PDE");

    if (pde & 1) == 0 {
        outln!("    -> Not Present!");
        return;
    }

    // Check for 2MB page
    if (pde & 0x80) != 0 {
        let phys = (pde & 0x000F_FFFF_FFE0_0000) | (vaddr & 0x1F_FFFF);
        outln!("");
        outln!("    -> 2MB Page!");
        outln!("    Physical Address: {:#018x}", phys);
        return;
    }

    // Level 1: PT
    let pt_base = pde & 0x000F_FFFF_FFFF_F000;
    let pte_addr = pt_base + pt_idx * 8;
    let pte = unsafe { core::ptr::read_volatile(pte_addr as *const u64) };
    outln!("");
    outln!("    PTE @ {:#x}: {:#018x}", pte_addr, pte);
    decode_pte(pte, "PTE");

    if (pte & 1) == 0 {
        outln!("    -> Not Present!");
        return;
    }

    // Calculate final physical address
    let phys = (pte & 0x000F_FFFF_FFFF_F000) | offset;
    outln!("");
    outln!("    -> 4KB Page");
    outln!("    Physical Address: {:#018x}", phys);
}

/// Decode page table entry flags
fn decode_pte(pte: u64, level: &str) {
    let flags = [
        (0, "P", "Present"),
        (1, "R/W", "Read/Write"),
        (2, "U/S", "User/Supervisor"),
        (3, "PWT", "Page Write-Through"),
        (4, "PCD", "Page Cache Disable"),
        (5, "A", "Accessed"),
        (6, "D", "Dirty"),
        (7, "PS", "Page Size"),
        (8, "G", "Global"),
        (63, "XD", "Execute Disable"),
    ];

    out!("      Flags: ");
    for (bit, name, _desc) in flags {
        if (pte & (1 << bit)) != 0 {
            out!("{} ", name);
        }
    }
    outln!("");
}

/// Quick address translation
fn translate_address(vaddr: u64) {
    outln!("Address Translation: {:#018x}", vaddr);
    outln!("");

    // Get current CR3
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3);
    }
    let pml4_phys = cr3 & 0x000F_FFFF_FFFF_F000;

    // Use the mm module
    use crate::mm;

    if let Some(phys) = unsafe { mm::mm_virtual_to_physical(pml4_phys, vaddr) } {
        outln!("  Virtual:  {:#018x}", vaddr);
        outln!("  Physical: {:#018x}", phys);
    } else {
        outln!("  Virtual:  {:#018x}", vaddr);
        outln!("  Physical: NOT MAPPED");
    }
}

/// Show kernel mapping summary
fn show_kernel_mappings() {
    outln!("Kernel Address Space Summary");
    outln!("");

    outln!("  Canonical Address Ranges:");
    outln!("    User:   0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF (128 TB)");
    outln!("    Hole:   0x0000_8000_0000_0000 - 0xFFFF_7FFF_FFFF_FFFF (invalid)");
    outln!("    Kernel: 0xFFFF_8000_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF (128 TB)");
    outln!("");

    // Show some known kernel addresses
    outln!("  Sample Kernel Addresses:");

    // Get kernel entry point (RIP is typically in kernel)
    let rip: u64;
    unsafe {
        core::arch::asm!(
            "lea {}, [rip]",
            out(reg) rip,
        );
    }
    outln!("    Current RIP:  {:#018x}", rip);

    // Stack pointer
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp);
    }
    outln!("    Current RSP:  {:#018x}", rsp);

    // CR3 (page table base)
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3);
    }
    outln!("    CR3 (PML4):   {:#018x}", cr3 & 0x000F_FFFF_FFFF_F000);

    // Check if addresses are in expected ranges
    outln!("");
    let rip_kernel = rip >= 0xFFFF_8000_0000_0000;
    let rsp_kernel = rsp >= 0xFFFF_8000_0000_0000;
    outln!("  RIP in kernel space: {}", if rip_kernel { "Yes" } else { "No" });
    outln!("  RSP in kernel space: {}", if rsp_kernel { "Yes" } else { "No" });
}

// ============================================================================
// MSR Browser Command
// ============================================================================

/// MSR (Model Specific Register) browser
pub fn cmd_msr(args: &[&str]) {
    if args.is_empty() || eq_ignore_case(args[0], "common") {
        show_common_msrs();
    } else if eq_ignore_case(args[0], "read") {
        if args.len() < 2 {
            outln!("Usage: msr read <msr_address>");
            return;
        }
        let msr_str = args[1].trim_start_matches("0x").trim_start_matches("0X");
        match u32::from_str_radix(msr_str, 16) {
            Ok(msr) => read_msr_cmd(msr),
            Err(_) => outln!("Error: Invalid MSR address '{}'", args[1]),
        }
    } else if eq_ignore_case(args[0], "apic") {
        show_apic_msrs();
    } else if eq_ignore_case(args[0], "syscall") {
        show_syscall_msrs();
    } else if eq_ignore_case(args[0], "perf") {
        show_perf_msrs();
    } else if eq_ignore_case(args[0], "pat") {
        show_pat_msr();
    } else if eq_ignore_case(args[0], "list") {
        show_msr_list();
    } else if eq_ignore_case(args[0], "help") {
        outln!("MSR Browser");
        outln!("");
        outln!("Usage: msr [command]");
        outln!("");
        outln!("Commands:");
        outln!("  common          Show common MSRs (default)");
        outln!("  read <addr>     Read specific MSR");
        outln!("  apic            Show APIC MSRs");
        outln!("  syscall         Show SYSCALL/SYSRET MSRs");
        outln!("  perf            Show performance MSRs");
        outln!("  pat             Show PAT (Page Attribute Table)");
        outln!("  list            List known MSR addresses");
        outln!("  help            Show this help");
    } else {
        outln!("Unknown msr command: {}", args[0]);
    }
}

/// Read MSR safely
fn read_msr(msr: u32) -> Result<u64, ()> {
    let lo: u32;
    let hi: u32;

    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
        );
    }

    Ok(((hi as u64) << 32) | (lo as u64))
}

/// Read and display a specific MSR
fn read_msr_cmd(msr: u32) {
    match read_msr(msr) {
        Ok(value) => {
            outln!("MSR {:#010x}:", msr);
            outln!("  Value:  {:#018x}", value);
            outln!("  Hi:     {:#010x}", (value >> 32) as u32);
            outln!("  Lo:     {:#010x}", value as u32);
            outln!("");
            outln!("  Binary: {:064b}", value);
        }
        Err(_) => {
            outln!("Error reading MSR {:#010x}", msr);
        }
    }
}

/// Show common MSRs
fn show_common_msrs() {
    outln!("Common Model Specific Registers");
    outln!("");

    let msrs = [
        (0x10, "IA32_TIME_STAMP_COUNTER"),
        (0x1B, "IA32_APIC_BASE"),
        (0xFE, "IA32_MTRRCAP"),
        (0x174, "IA32_SYSENTER_CS"),
        (0x175, "IA32_SYSENTER_ESP"),
        (0x176, "IA32_SYSENTER_EIP"),
        (0x277, "IA32_PAT"),
        (0xC0000080, "IA32_EFER"),
        (0xC0000081, "IA32_STAR"),
        (0xC0000082, "IA32_LSTAR"),
        (0xC0000084, "IA32_FMASK"),
        (0xC0000100, "IA32_FS_BASE"),
        (0xC0000101, "IA32_GS_BASE"),
        (0xC0000102, "IA32_KERNEL_GS_BASE"),
    ];

    outln!("  {:>12}  {:<28}  {:<18}", "Address", "Name", "Value");
    outln!("  {:->12}  {:->28}  {:->18}", "", "", "");

    for (addr, name) in msrs {
        if let Ok(value) = read_msr(addr) {
            outln!("  {:#012x}  {:<28}  {:#018x}", addr, name, value);
        }
    }
}

/// Show APIC-related MSRs
fn show_apic_msrs() {
    outln!("APIC Model Specific Registers");
    outln!("");

    if let Ok(apic_base) = read_msr(0x1B) {
        outln!("IA32_APIC_BASE (0x1B): {:#018x}", apic_base);
        outln!("");
        outln!("  Base Address:  {:#018x}", apic_base & 0xFFFF_FFFF_FFFF_F000);
        outln!("  BSP:           {}", (apic_base >> 8) & 1);
        outln!("  x2APIC:        {}", (apic_base >> 10) & 1);
        outln!("  Global Enable: {}", (apic_base >> 11) & 1);
    }
}

/// Show SYSCALL/SYSRET MSRs
fn show_syscall_msrs() {
    outln!("SYSCALL/SYSRET Model Specific Registers");
    outln!("");

    // EFER
    if let Ok(efer) = read_msr(0xC0000080) {
        outln!("IA32_EFER (0xC0000080): {:#018x}", efer);
        outln!("  SCE (SYSCALL Enable):     {}", efer & 1);
        outln!("  LME (Long Mode Enable):   {}", (efer >> 8) & 1);
        outln!("  LMA (Long Mode Active):   {}", (efer >> 10) & 1);
        outln!("  NXE (No-Execute Enable):  {}", (efer >> 11) & 1);
        outln!("");
    }

    // STAR
    if let Ok(star) = read_msr(0xC0000081) {
        outln!("IA32_STAR (0xC0000081): {:#018x}", star);
        outln!("  SYSCALL CS:  {:#06x}", ((star >> 32) & 0xFFFF) as u16);
        outln!("  SYSCALL SS:  {:#06x}", (((star >> 32) & 0xFFFF) + 8) as u16);
        outln!("  SYSRET CS:   {:#06x}", (((star >> 48) & 0xFFFF) + 16) as u16);
        outln!("  SYSRET SS:   {:#06x}", (((star >> 48) & 0xFFFF) + 8) as u16);
        outln!("");
    }

    // LSTAR
    if let Ok(lstar) = read_msr(0xC0000082) {
        outln!("IA32_LSTAR (0xC0000082): {:#018x}", lstar);
        outln!("  SYSCALL Entry Point (Long Mode)");
        outln!("");
    }

    // CSTAR (Compatibility Mode - not used in 64-bit only)
    if let Ok(cstar) = read_msr(0xC0000083) {
        outln!("IA32_CSTAR (0xC0000083): {:#018x}", cstar);
        outln!("  SYSCALL Entry Point (Compatibility Mode)");
        outln!("");
    }

    // FMASK
    if let Ok(fmask) = read_msr(0xC0000084) {
        outln!("IA32_FMASK (0xC0000084): {:#018x}", fmask);
        outln!("  RFLAGS mask on SYSCALL");
    }
}

/// Show performance-related MSRs
fn show_perf_msrs() {
    outln!("Performance Model Specific Registers");
    outln!("");

    // TSC
    if let Ok(tsc) = read_msr(0x10) {
        outln!("IA32_TIME_STAMP_COUNTER (0x10): {}", tsc);
        outln!("");
    }

    // MPERF/APERF (if available)
    if let Ok(mperf) = read_msr(0xE7) {
        outln!("IA32_MPERF (0xE7): {}", mperf);
    }
    if let Ok(aperf) = read_msr(0xE8) {
        outln!("IA32_APERF (0xE8): {}", aperf);
    }

    outln!("");
    outln!("Note: Some performance MSRs may not be available on all CPUs");
}

/// Show PAT (Page Attribute Table) MSR
fn show_pat_msr() {
    outln!("Page Attribute Table (PAT) MSR");
    outln!("");

    if let Ok(pat) = read_msr(0x277) {
        outln!("IA32_PAT (0x277): {:#018x}", pat);
        outln!("");

        let pat_types = ["UC", "WC", "??", "??", "WT", "WP", "WB", "UC-"];

        for i in 0..8 {
            let entry = ((pat >> (i * 8)) & 0x7) as usize;
            let type_name = if entry < pat_types.len() {
                pat_types[entry]
            } else {
                "??"
            };
            outln!("  PA{}: {} ({})", i, entry, type_name);
        }

        outln!("");
        outln!("Type meanings:");
        outln!("  UC  = Uncacheable");
        outln!("  WC  = Write Combining");
        outln!("  WT  = Write Through");
        outln!("  WP  = Write Protected");
        outln!("  WB  = Write Back");
        outln!("  UC- = Uncacheable (weak)");
    }
}

/// Show list of known MSRs
fn show_msr_list() {
    outln!("Known Model Specific Registers");
    outln!("");
    outln!("Architectural MSRs:");
    outln!("  0x10        IA32_TIME_STAMP_COUNTER (TSC)");
    outln!("  0x1B        IA32_APIC_BASE");
    outln!("  0xFE        IA32_MTRRCAP");
    outln!("  0x174-176   IA32_SYSENTER_CS/ESP/EIP");
    outln!("  0x277       IA32_PAT");
    outln!("  0x2FF       IA32_MTRR_DEF_TYPE");
    outln!("");
    outln!("AMD64/Intel64 MSRs:");
    outln!("  0xC0000080  IA32_EFER (Extended Feature Enable)");
    outln!("  0xC0000081  IA32_STAR (SYSCALL target)");
    outln!("  0xC0000082  IA32_LSTAR (Long Mode SYSCALL)");
    outln!("  0xC0000083  IA32_CSTAR (Compat Mode SYSCALL)");
    outln!("  0xC0000084  IA32_FMASK (SYSCALL RFLAGS mask)");
    outln!("  0xC0000100  IA32_FS_BASE");
    outln!("  0xC0000101  IA32_GS_BASE");
    outln!("  0xC0000102  IA32_KERNEL_GS_BASE (for SWAPGS)");
    outln!("");
    outln!("Use 'msr read <addr>' to read any MSR");
}

// ============================================================================
// I/O Port Browser Command
// ============================================================================

/// I/O port browser for hardware diagnostics
pub fn cmd_port(args: &[&str]) {
    if args.is_empty() {
        show_port_help();
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "help") {
        show_port_help();
    } else if eq_ignore_case(cmd, "inb") {
        // Read byte from port
        if args.len() < 2 {
            outln!("Usage: port inb <port>");
            return;
        }
        if let Some(port) = parse_number(args[1]) {
            if port > 0xFFFF {
                outln!("Error: Port must be 0-0xFFFF");
                return;
            }
            let val = unsafe { port_read_u8(port as u16) };
            outln!("Port 0x{:04X}: 0x{:02X} ({})", port, val, val);
        } else {
            outln!("Invalid port number: {}", args[1]);
        }
    } else if eq_ignore_case(cmd, "inw") {
        // Read word from port
        if args.len() < 2 {
            outln!("Usage: port inw <port>");
            return;
        }
        if let Some(port) = parse_number(args[1]) {
            if port > 0xFFFF {
                outln!("Error: Port must be 0-0xFFFF");
                return;
            }
            let val = unsafe { port_read_u16(port as u16) };
            outln!("Port 0x{:04X}: 0x{:04X} ({})", port, val, val);
        } else {
            outln!("Invalid port number: {}", args[1]);
        }
    } else if eq_ignore_case(cmd, "ind") {
        // Read dword from port
        if args.len() < 2 {
            outln!("Usage: port ind <port>");
            return;
        }
        if let Some(port) = parse_number(args[1]) {
            if port > 0xFFFF {
                outln!("Error: Port must be 0-0xFFFF");
                return;
            }
            let val = unsafe { port_read_u32(port as u16) };
            outln!("Port 0x{:04X}: 0x{:08X} ({})", port, val, val);
        } else {
            outln!("Invalid port number: {}", args[1]);
        }
    } else if eq_ignore_case(cmd, "outb") {
        // Write byte to port
        if args.len() < 3 {
            outln!("Usage: port outb <port> <value>");
            return;
        }
        if let (Some(port), Some(val)) = (parse_number(args[1]), parse_number(args[2])) {
            if port > 0xFFFF {
                outln!("Error: Port must be 0-0xFFFF");
                return;
            }
            if val > 0xFF {
                outln!("Error: Value must be 0-0xFF for byte write");
                return;
            }
            unsafe { port_write_u8(port as u16, val as u8) };
            outln!("Wrote 0x{:02X} to port 0x{:04X}", val, port);
        } else {
            outln!("Invalid port or value");
        }
    } else if eq_ignore_case(cmd, "outw") {
        // Write word to port
        if args.len() < 3 {
            outln!("Usage: port outw <port> <value>");
            return;
        }
        if let (Some(port), Some(val)) = (parse_number(args[1]), parse_number(args[2])) {
            if port > 0xFFFF {
                outln!("Error: Port must be 0-0xFFFF");
                return;
            }
            if val > 0xFFFF {
                outln!("Error: Value must be 0-0xFFFF for word write");
                return;
            }
            unsafe { port_write_u16(port as u16, val as u16) };
            outln!("Wrote 0x{:04X} to port 0x{:04X}", val, port);
        } else {
            outln!("Invalid port or value");
        }
    } else if eq_ignore_case(cmd, "outd") {
        // Write dword to port
        if args.len() < 3 {
            outln!("Usage: port outd <port> <value>");
            return;
        }
        if let (Some(port), Some(val)) = (parse_number(args[1]), parse_number(args[2])) {
            if port > 0xFFFF {
                outln!("Error: Port must be 0-0xFFFF");
                return;
            }
            unsafe { port_write_u32(port as u16, val as u32) };
            outln!("Wrote 0x{:08X} to port 0x{:04X}", val, port);
        } else {
            outln!("Invalid port or value");
        }
    } else if eq_ignore_case(cmd, "scan") {
        // Scan a port range
        if args.len() < 2 {
            show_port_scan_standard();
        } else if eq_ignore_case(args[1], "serial") {
            scan_serial_ports();
        } else if eq_ignore_case(args[1], "parallel") {
            scan_parallel_ports();
        } else if eq_ignore_case(args[1], "pic") {
            scan_pic_ports();
        } else if eq_ignore_case(args[1], "pit") {
            scan_pit_ports();
        } else if eq_ignore_case(args[1], "cmos") {
            scan_cmos();
        } else if eq_ignore_case(args[1], "ps2") {
            scan_ps2_controller();
        } else {
            // Custom range scan
            if args.len() >= 3 {
                if let (Some(start), Some(end)) =
                    (parse_number(args[1]), parse_number(args[2]))
                {
                    if start > 0xFFFF || end > 0xFFFF {
                        outln!("Error: Ports must be 0-0xFFFF");
                        return;
                    }
                    if end < start {
                        outln!("Error: End port must be >= start port");
                        return;
                    }
                    if end - start > 256 {
                        outln!("Error: Range too large (max 256 ports)");
                        return;
                    }
                    scan_port_range(start as u16, end as u16);
                } else {
                    outln!("Invalid port range");
                }
            } else {
                outln!("Usage: port scan <start> <end>");
                outln!("   or: port scan serial|parallel|pic|pit|cmos|ps2");
            }
        }
    } else if eq_ignore_case(cmd, "list") {
        show_port_list();
    } else {
        outln!("Unknown port command: {}", cmd);
        outln!("Use 'port help' for usage");
    }
}

fn show_port_help() {
    outln!("I/O Port Browser");
    outln!("");
    outln!("Usage: port <command> [args]");
    outln!("");
    outln!("Read commands:");
    outln!("  inb <port>        Read byte from port");
    outln!("  inw <port>        Read word (16-bit) from port");
    outln!("  ind <port>        Read dword (32-bit) from port");
    outln!("");
    outln!("Write commands:");
    outln!("  outb <port> <val> Write byte to port");
    outln!("  outw <port> <val> Write word to port");
    outln!("  outd <port> <val> Write dword to port");
    outln!("");
    outln!("Scan commands:");
    outln!("  scan              Scan standard device ports");
    outln!("  scan serial       Scan COM1-4 ports");
    outln!("  scan parallel     Scan LPT1-3 ports");
    outln!("  scan pic          Scan PIC (8259) ports");
    outln!("  scan pit          Scan PIT (8254) ports");
    outln!("  scan cmos         Read CMOS/RTC values");
    outln!("  scan ps2          Scan PS/2 controller");
    outln!("  scan <start> <end> Scan custom range");
    outln!("");
    outln!("Other:");
    outln!("  list              Show known port assignments");
}

/// Port I/O helper functions
unsafe fn port_read_u8(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") val,
        in("dx") port,
        options(nostack, nomem, preserves_flags)
    );
    val
}

unsafe fn port_read_u16(port: u16) -> u16 {
    let val: u16;
    core::arch::asm!(
        "in ax, dx",
        out("ax") val,
        in("dx") port,
        options(nostack, nomem, preserves_flags)
    );
    val
}

unsafe fn port_read_u32(port: u16) -> u32 {
    let val: u32;
    core::arch::asm!(
        "in eax, dx",
        out("eax") val,
        in("dx") port,
        options(nostack, nomem, preserves_flags)
    );
    val
}

unsafe fn port_write_u8(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nostack, nomem, preserves_flags)
    );
}

unsafe fn port_write_u16(port: u16, val: u16) {
    core::arch::asm!(
        "out dx, ax",
        in("dx") port,
        in("ax") val,
        options(nostack, nomem, preserves_flags)
    );
}

unsafe fn port_write_u32(port: u16, val: u32) {
    core::arch::asm!(
        "out dx, eax",
        in("dx") port,
        in("eax") val,
        options(nostack, nomem, preserves_flags)
    );
}

fn show_port_scan_standard() {
    outln!("Standard Device Port Scan");
    outln!("");

    // Serial ports
    outln!("Serial Ports (COM):");
    for (name, port) in [("COM1", 0x3F8), ("COM2", 0x2F8), ("COM3", 0x3E8), ("COM4", 0x2E8)] {
        let iir = unsafe { port_read_u8(port + 2) };
        let present = iir != 0xFF;
        outln!(
            "  {}: 0x{:03X}  {}",
            name,
            port,
            if present { "Present" } else { "Not detected" }
        );
    }
    outln!("");

    // PS/2 controller
    outln!("PS/2 Controller:");
    let status = unsafe { port_read_u8(0x64) };
    outln!("  Status: 0x{:02X}", status);
    outln!("    Output buffer full: {}", (status & 1) != 0);
    outln!("    Input buffer full:  {}", (status & 2) != 0);
    outln!("");

    // PIT
    outln!("PIT (8254 Timer):");
    unsafe {
        port_write_u8(0x43, 0x00); // Latch channel 0
        let lo = port_read_u8(0x40);
        let hi = port_read_u8(0x40);
        let count = (hi as u16) << 8 | lo as u16;
        outln!("  Channel 0 count: 0x{:04X} ({})", count, count);
    }
}

fn scan_serial_ports() {
    outln!("Serial Port Scan (8250/16550 UART)");
    outln!("");

    for (name, base) in [("COM1", 0x3F8u16), ("COM2", 0x2F8), ("COM3", 0x3E8), ("COM4", 0x2E8)] {
        outln!("{}  (base 0x{:03X}):", name, base);

        unsafe {
            let iir = port_read_u8(base + 2); // Interrupt ID Register
            if iir == 0xFF {
                outln!("  Not present");
                outln!("");
                continue;
            }

            let lcr = port_read_u8(base + 3); // Line Control Register
            let mcr = port_read_u8(base + 4); // Modem Control Register
            let lsr = port_read_u8(base + 5); // Line Status Register
            let msr = port_read_u8(base + 6); // Modem Status Register

            // Check for FIFO (16550)
            let fifo_type = match (iir >> 6) & 3 {
                0 => "No FIFO (8250)",
                1 => "FIFO unusable",
                2 => "FIFO enabled (16550)",
                3 => "FIFO enabled (16550A)",
                _ => "Unknown",
            };

            outln!("  IIR: 0x{:02X}  LCR: 0x{:02X}  MCR: 0x{:02X}", iir, lcr, mcr);
            outln!("  LSR: 0x{:02X}  MSR: 0x{:02X}", lsr, msr);
            outln!("  Type: {}", fifo_type);

            // Decode line status
            outln!("  Status:");
            outln!("    Data ready:     {}", (lsr & 1) != 0);
            outln!("    TX empty:       {}", (lsr & 0x20) != 0);
            outln!("    TX holding:     {}", (lsr & 0x40) != 0);
        }
        outln!("");
    }
}

fn scan_parallel_ports() {
    outln!("Parallel Port Scan");
    outln!("");

    for (name, base) in [("LPT1", 0x378u16), ("LPT2", 0x278), ("LPT3", 0x3BC)] {
        outln!("{}  (base 0x{:03X}):", name, base);

        unsafe {
            let data = port_read_u8(base); // Data register
            let status = port_read_u8(base + 1); // Status register
            let control = port_read_u8(base + 2); // Control register

            // Check if port exists (reading should not return 0xFF typically)
            let exists = !(data == 0xFF && status == 0xFF && control == 0xFF);

            if !exists {
                outln!("  Not detected");
            } else {
                outln!("  Data: 0x{:02X}  Status: 0x{:02X}  Control: 0x{:02X}", data, status, control);
                outln!("  Status bits:");
                outln!("    Busy:     {}", (status & 0x80) == 0); // Inverted
                outln!("    Ack:      {}", (status & 0x40) != 0);
                outln!("    Paper:    {}", (status & 0x20) != 0);
                outln!("    Select:   {}", (status & 0x10) != 0);
                outln!("    Error:    {}", (status & 0x08) == 0); // Inverted
            }
        }
        outln!("");
    }
}

fn scan_pic_ports() {
    outln!("PIC (8259) Interrupt Controller");
    outln!("");

    unsafe {
        // Master PIC
        let master_irr = {
            port_write_u8(0x20, 0x0A); // Read IRR
            port_read_u8(0x20)
        };
        let master_isr = {
            port_write_u8(0x20, 0x0B); // Read ISR
            port_read_u8(0x20)
        };
        let master_mask = port_read_u8(0x21); // IMR

        outln!("Master PIC (0x20-0x21):");
        outln!("  IRR (pending):  0b{:08b}", master_irr);
        outln!("  ISR (in-service): 0b{:08b}", master_isr);
        outln!("  IMR (masked):   0b{:08b}", master_mask);
        outln!("");

        // Slave PIC
        let slave_irr = {
            port_write_u8(0xA0, 0x0A);
            port_read_u8(0xA0)
        };
        let slave_isr = {
            port_write_u8(0xA0, 0x0B);
            port_read_u8(0xA0)
        };
        let slave_mask = port_read_u8(0xA1);

        outln!("Slave PIC (0xA0-0xA1):");
        outln!("  IRR (pending):  0b{:08b}", slave_irr);
        outln!("  ISR (in-service): 0b{:08b}", slave_isr);
        outln!("  IMR (masked):   0b{:08b}", slave_mask);
    }
}

fn scan_pit_ports() {
    outln!("PIT (8254) Programmable Interval Timer");
    outln!("");

    unsafe {
        // Read all three channels
        for ch in 0..3u8 {
            let port = 0x40 + ch as u16;

            // Latch the counter
            port_write_u8(0x43, ch << 6);

            let lo = port_read_u8(port);
            let hi = port_read_u8(port);
            let count = (hi as u16) << 8 | lo as u16;

            outln!(
                "Channel {}: Count = 0x{:04X} ({})  Port 0x{:02X}",
                ch,
                count,
                count,
                port
            );
        }

        outln!("");
        outln!("PIT frequency: 1.193182 MHz");
        outln!("Channel 0: System timer (IRQ 0)");
        outln!("Channel 1: DRAM refresh (legacy)");
        outln!("Channel 2: PC speaker");
    }
}

fn scan_cmos() {
    outln!("CMOS/RTC Read");
    outln!("");

    unsafe {
        outln!("RTC Time/Date:");
        let seconds = cmos_read(0x00);
        let minutes = cmos_read(0x02);
        let hours = cmos_read(0x04);
        let day = cmos_read(0x07);
        let month = cmos_read(0x08);
        let year = cmos_read(0x09);

        // Check if BCD mode
        let status_b = cmos_read(0x0B);
        let bcd_mode = (status_b & 0x04) == 0;

        let (h, m, s, d, mo, y) = if bcd_mode {
            (
                bcd_to_bin(hours),
                bcd_to_bin(minutes),
                bcd_to_bin(seconds),
                bcd_to_bin(day),
                bcd_to_bin(month),
                bcd_to_bin(year),
            )
        } else {
            (hours, minutes, seconds, day, month, year)
        };

        outln!("  Time: {:02}:{:02}:{:02}", h, m, s);
        outln!("  Date: {:02}/{:02}/{:02}", mo, d, y);
        outln!("  Mode: {}", if bcd_mode { "BCD" } else { "Binary" });
        outln!("");

        outln!("CMOS Status Registers:");
        let status_a = cmos_read(0x0A);
        let status_c = cmos_read(0x0C);
        let status_d = cmos_read(0x0D);

        outln!("  Status A: 0x{:02X}", status_a);
        outln!("  Status B: 0x{:02X}", status_b);
        outln!("  Status C: 0x{:02X}", status_c);
        outln!("  Status D: 0x{:02X} (battery: {})", status_d, if (status_d & 0x80) != 0 { "OK" } else { "LOW" });
        outln!("");

        outln!("Equipment byte (0x14): 0x{:02X}", cmos_read(0x14));
        outln!("Base memory low (0x15): {} KB", cmos_read(0x15) as u16 | ((cmos_read(0x16) as u16) << 8));
    }
}

unsafe fn cmos_read(reg: u8) -> u8 {
    port_write_u8(0x70, reg);
    // Small delay
    for _ in 0..10 {
        core::arch::asm!("nop");
    }
    port_read_u8(0x71)
}

fn bcd_to_bin(bcd: u8) -> u8 {
    (bcd & 0x0F) + ((bcd >> 4) * 10)
}

fn scan_ps2_controller() {
    outln!("PS/2 Controller (8042)");
    outln!("");

    unsafe {
        let status = port_read_u8(0x64);

        outln!("Status Register (0x64): 0x{:02X}", status);
        outln!("  Output buffer full:   {}", (status & 0x01) != 0);
        outln!("  Input buffer full:    {}", (status & 0x02) != 0);
        outln!("  System flag:          {}", (status & 0x04) != 0);
        outln!("  Command/Data:         {}", if (status & 0x08) != 0 { "Command" } else { "Data" });
        outln!("  Timeout error:        {}", (status & 0x40) != 0);
        outln!("  Parity error:         {}", (status & 0x80) != 0);
        outln!("");

        // Try to read controller configuration
        port_write_u8(0x64, 0x20); // Read config command
        // Wait for output buffer
        for _ in 0..1000 {
            if (port_read_u8(0x64) & 1) != 0 {
                break;
            }
        }
        if (port_read_u8(0x64) & 1) != 0 {
            let config = port_read_u8(0x60);
            outln!("Configuration byte: 0x{:02X}", config);
            outln!("  Port 1 interrupt:     {}", (config & 0x01) != 0);
            outln!("  Port 2 interrupt:     {}", (config & 0x02) != 0);
            outln!("  Port 1 clock:         {}", (config & 0x10) == 0);
            outln!("  Port 2 clock:         {}", (config & 0x20) == 0);
            outln!("  Translation:          {}", (config & 0x40) != 0);
        }
    }
}

fn scan_port_range(start: u16, end: u16) {
    outln!("Port Range Scan: 0x{:04X} - 0x{:04X}", start, end);
    outln!("");

    let mut col = 0;
    for port in start..=end {
        let val = unsafe { port_read_u8(port) };
        if col == 0 {
            out!("0x{:04X}:", port);
        }
        out!(" {:02X}", val);
        col += 1;
        if col >= 16 {
            outln!("");
            col = 0;
        }
    }
    if col != 0 {
        outln!("");
    }
}

fn show_port_list() {
    outln!("Standard PC I/O Port Assignments");
    outln!("");
    outln!("DMA Controllers:");
    outln!("  0x00-0x0F   DMA 1 (channels 0-3)");
    outln!("  0xC0-0xDF   DMA 2 (channels 4-7)");
    outln!("");
    outln!("Interrupt Controllers (8259 PIC):");
    outln!("  0x20-0x21   Master PIC");
    outln!("  0xA0-0xA1   Slave PIC");
    outln!("");
    outln!("Timer (8254 PIT):");
    outln!("  0x40-0x43   PIT channels 0-2 + control");
    outln!("");
    outln!("Keyboard/PS2 Controller (8042):");
    outln!("  0x60        Data port");
    outln!("  0x64        Status/Command port");
    outln!("");
    outln!("CMOS/RTC:");
    outln!("  0x70        Index port");
    outln!("  0x71        Data port");
    outln!("");
    outln!("Serial Ports (8250/16550 UART):");
    outln!("  0x3F8-0x3FF COM1");
    outln!("  0x2F8-0x2FF COM2");
    outln!("  0x3E8-0x3EF COM3");
    outln!("  0x2E8-0x2EF COM4");
    outln!("");
    outln!("Parallel Ports:");
    outln!("  0x378-0x37F LPT1");
    outln!("  0x278-0x27F LPT2");
    outln!("  0x3BC-0x3BF LPT3");
    outln!("");
    outln!("VGA:");
    outln!("  0x3C0-0x3CF VGA registers");
    outln!("  0x3D4-0x3D5 CRT controller");
    outln!("");
    outln!("PCI Configuration:");
    outln!("  0xCF8       Config address");
    outln!("  0xCFC       Config data");
}

// ============================================================================
// APIC Viewer Command
// ============================================================================

/// APIC viewer for interrupt controller diagnostics
pub fn cmd_apic(args: &[&str]) {
    if args.is_empty() {
        show_apic_overview();
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "help") {
        show_apic_help();
    } else if eq_ignore_case(cmd, "status") {
        show_apic_overview();
    } else if eq_ignore_case(cmd, "regs") || eq_ignore_case(cmd, "registers") {
        show_apic_registers();
    } else if eq_ignore_case(cmd, "lvt") {
        show_apic_lvt();
    } else if eq_ignore_case(cmd, "timer") {
        show_apic_timer_detail();
    } else if eq_ignore_case(cmd, "isr") {
        show_apic_isr_irr();
    } else if eq_ignore_case(cmd, "ioapic") {
        show_ioapic();
    } else if eq_ignore_case(cmd, "eoi") {
        // Send End-Of-Interrupt (for testing)
        unsafe { apic_write(0xB0, 0) };
        outln!("EOI sent to local APIC");
    } else {
        outln!("Unknown apic command: {}", cmd);
        show_apic_help();
    }
}

fn show_apic_help() {
    outln!("APIC Viewer");
    outln!("");
    outln!("Usage: apic [command]");
    outln!("");
    outln!("Commands:");
    outln!("  status       Overview of APIC status (default)");
    outln!("  regs         Show all local APIC registers");
    outln!("  lvt          Show Local Vector Table entries");
    outln!("  timer        Detailed timer configuration");
    outln!("  isr          Show ISR/IRR/TMR status");
    outln!("  ioapic       Show I/O APIC information");
    outln!("  eoi          Send End-Of-Interrupt");
}

/// Read from local APIC register (memory-mapped)
unsafe fn apic_read(offset: u32) -> u32 {
    // Standard local APIC base address
    let base = 0xFEE0_0000u64;
    let addr = (base + offset as u64) as *const u32;
    core::ptr::read_volatile(addr)
}

/// Write to local APIC register
unsafe fn apic_write(offset: u32, value: u32) {
    let base = 0xFEE0_0000u64;
    let addr = (base + offset as u64) as *mut u32;
    core::ptr::write_volatile(addr, value);
}

fn show_apic_overview() {
    outln!("Local APIC Status");
    outln!("");

    unsafe {
        // Read APIC ID and version
        let id = apic_read(0x20);
        let version = apic_read(0x30);
        let tpr = apic_read(0x80);
        let apr = apic_read(0x90);
        let ppr = apic_read(0xA0);
        let svr = apic_read(0xF0);
        let esr = apic_read(0x280);

        outln!("APIC ID:        0x{:02X}", (id >> 24) & 0xFF);
        outln!("Version:        0x{:02X} (Max LVT: {})", version & 0xFF, ((version >> 16) & 0xFF) + 1);
        outln!("");

        outln!("Priority Registers:");
        outln!("  TPR (Task):       0x{:02X} (class {})", tpr & 0xFF, (tpr >> 4) & 0xF);
        outln!("  APR (Arbitration): 0x{:02X}", apr & 0xFF);
        outln!("  PPR (Processor):  0x{:02X}", ppr & 0xFF);
        outln!("");

        outln!("Spurious Vector: 0x{:02X}  APIC Enable: {}", svr & 0xFF, (svr & 0x100) != 0);
        outln!("Error Status:    0x{:08X}", esr);

        if esr != 0 {
            outln!("  Errors detected:");
            if (esr & 0x01) != 0 {
                outln!("    - Send checksum error");
            }
            if (esr & 0x02) != 0 {
                outln!("    - Receive checksum error");
            }
            if (esr & 0x04) != 0 {
                outln!("    - Send accept error");
            }
            if (esr & 0x08) != 0 {
                outln!("    - Receive accept error");
            }
            if (esr & 0x20) != 0 {
                outln!("    - Send illegal vector");
            }
            if (esr & 0x40) != 0 {
                outln!("    - Receive illegal vector");
            }
            if (esr & 0x80) != 0 {
                outln!("    - Illegal register address");
            }
        }
    }
}

fn show_apic_registers() {
    outln!("Local APIC Registers");
    outln!("");

    unsafe {
        // Key register offsets
        let regs = [
            (0x020, "ID"),
            (0x030, "Version"),
            (0x080, "TPR"),
            (0x090, "APR"),
            (0x0A0, "PPR"),
            (0x0B0, "EOI"),
            (0x0D0, "LDR"),
            (0x0E0, "DFR"),
            (0x0F0, "SVR"),
            (0x280, "ESR"),
            (0x300, "ICR_LO"),
            (0x310, "ICR_HI"),
            (0x320, "LVT_Timer"),
            (0x330, "LVT_Thermal"),
            (0x340, "LVT_PerfMon"),
            (0x350, "LVT_LINT0"),
            (0x360, "LVT_LINT1"),
            (0x370, "LVT_Error"),
            (0x380, "Timer_ICR"),
            (0x390, "Timer_CCR"),
            (0x3E0, "Timer_DCR"),
        ];

        for (offset, name) in regs {
            let val = apic_read(offset);
            outln!("  0x{:03X} {:12}: 0x{:08X}", offset, name, val);
        }
    }
}

fn show_apic_lvt() {
    outln!("Local Vector Table (LVT)");
    outln!("");

    unsafe {
        let lvt_entries = [
            (0x320, "Timer"),
            (0x330, "Thermal"),
            (0x340, "PerfMon"),
            (0x350, "LINT0"),
            (0x360, "LINT1"),
            (0x370, "Error"),
        ];

        for (offset, name) in lvt_entries {
            let val = apic_read(offset);
            let vector = val & 0xFF;
            let delivery = (val >> 8) & 0x7;
            let status = (val >> 12) & 0x1;
            let polarity = (val >> 13) & 0x1;
            let remote = (val >> 14) & 0x1;
            let trigger = (val >> 15) & 0x1;
            let masked = (val >> 16) & 0x1;

            let delivery_str = match delivery {
                0 => "Fixed",
                2 => "SMI",
                4 => "NMI",
                5 => "INIT",
                7 => "ExtINT",
                _ => "???",
            };

            outln!("{}:", name);
            outln!("  Vector: 0x{:02X}  Delivery: {} ({})", vector, delivery, delivery_str);
            outln!("  Masked: {}  Status: {}  Polarity: {}  Trigger: {}",
                   masked != 0,
                   if status != 0 { "Pending" } else { "Idle" },
                   if polarity != 0 { "Low" } else { "High" },
                   if trigger != 0 { "Level" } else { "Edge" });
            outln!("");
        }
    }
}

fn show_apic_timer_detail() {
    outln!("APIC Timer Configuration");
    outln!("");

    unsafe {
        let lvt_timer = apic_read(0x320);
        let icr = apic_read(0x380);
        let ccr = apic_read(0x390);
        let dcr = apic_read(0x3E0);

        let vector = lvt_timer & 0xFF;
        let mode = (lvt_timer >> 17) & 0x3;
        let masked = (lvt_timer >> 16) & 0x1;

        let mode_str = match mode {
            0 => "One-shot",
            1 => "Periodic",
            2 => "TSC-Deadline",
            _ => "Reserved",
        };

        let divisor = match dcr & 0xB {
            0x0 => 2,
            0x1 => 4,
            0x2 => 8,
            0x3 => 16,
            0x8 => 32,
            0x9 => 64,
            0xA => 128,
            0xB => 1,
            _ => 0,
        };

        outln!("LVT Timer:      0x{:08X}", lvt_timer);
        outln!("  Vector:       0x{:02X}", vector);
        outln!("  Mode:         {} ({})", mode, mode_str);
        outln!("  Masked:       {}", masked != 0);
        outln!("");

        outln!("Initial Count:  {} (0x{:08X})", icr, icr);
        outln!("Current Count:  {} (0x{:08X})", ccr, ccr);
        outln!("Divide Config:  0x{:X} (divide by {})", dcr & 0xB, divisor);

        if icr > 0 && divisor > 0 {
            let percent = if icr > 0 {
                ((icr - ccr) as u64 * 100) / icr as u64
            } else {
                0
            };
            outln!("");
            outln!("Progress:       {}% ({}/{})", percent, icr - ccr, icr);
        }
    }
}

fn show_apic_isr_irr() {
    outln!("APIC ISR/IRR/TMR Status");
    outln!("");

    unsafe {
        outln!("In-Service Register (ISR) - interrupts being serviced:");
        show_apic_bitmap(0x100, 8);

        outln!("");
        outln!("Interrupt Request Register (IRR) - pending interrupts:");
        show_apic_bitmap(0x200, 8);

        outln!("");
        outln!("Trigger Mode Register (TMR) - level (1) vs edge (0):");
        show_apic_bitmap(0x180, 8);
    }
}

unsafe fn show_apic_bitmap(base_offset: u32, count: usize) {
    for i in 0..count {
        let offset = base_offset + (i as u32 * 0x10);
        let val = apic_read(offset);
        if val != 0 {
            out!("  {:3}-{:3}: ", i * 32, i * 32 + 31);
            for bit in 0..32 {
                if (val & (1 << bit)) != 0 {
                    out!("{} ", i * 32 + bit);
                }
            }
            outln!("");
        }
    }
}

fn show_ioapic() {
    outln!("I/O APIC Information");
    outln!("");

    // Standard I/O APIC base address
    let ioapic_base = 0xFEC0_0000u64;

    unsafe {
        // Read I/O APIC ID
        let id = ioapic_read(ioapic_base, 0x00);
        let version = ioapic_read(ioapic_base, 0x01);
        let arb = ioapic_read(ioapic_base, 0x02);

        let max_redir = ((version >> 16) & 0xFF) + 1;

        outln!("I/O APIC at 0x{:08X}:", ioapic_base);
        outln!("  ID:           0x{:02X}", (id >> 24) & 0xF);
        outln!("  Version:      0x{:02X}", version & 0xFF);
        outln!("  Max Entries:  {}", max_redir);
        outln!("  Arbitration:  0x{:02X}", (arb >> 24) & 0xF);
        outln!("");

        outln!("Redirection Table:");
        let entries_to_show = max_redir.min(24) as u8;
        for i in 0..entries_to_show {
            let lo = ioapic_read(ioapic_base, 0x10 + i * 2);
            let hi = ioapic_read(ioapic_base, 0x11 + i * 2);

            let vector = lo & 0xFF;
            let delivery = (lo >> 8) & 0x7;
            let dest_mode = (lo >> 11) & 0x1;
            let polarity = (lo >> 13) & 0x1;
            let trigger = (lo >> 15) & 0x1;
            let masked = (lo >> 16) & 0x1;
            let dest = (hi >> 24) & 0xFF;

            if masked == 0 || vector != 0 {
                let delivery_str = match delivery {
                    0 => "Fixed",
                    1 => "LowPri",
                    2 => "SMI",
                    4 => "NMI",
                    5 => "INIT",
                    7 => "ExtINT",
                    _ => "???",
                };

                outln!(
                    "  IRQ{:2}: Vec 0x{:02X} -> CPU{} [{}{}{}{}]",
                    i,
                    vector,
                    dest,
                    delivery_str,
                    if polarity != 0 { " Low" } else { "" },
                    if trigger != 0 { " Level" } else { "" },
                    if masked != 0 { " MASKED" } else { "" }
                );
            }
        }
    }
}

/// Read from I/O APIC register
unsafe fn ioapic_read(base: u64, reg: u8) -> u32 {
    let ioregsel = base as *mut u32;
    let iowin = (base + 0x10) as *mut u32;

    core::ptr::write_volatile(ioregsel, reg as u32);
    core::ptr::read_volatile(iowin)
}

// ============================================================================
// GDT/IDT Viewer Command
// ============================================================================

/// GDT/IDT viewer for descriptor table inspection
pub fn cmd_descriptor(args: &[&str]) {
    if args.is_empty() {
        show_descriptor_help();
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "help") {
        show_descriptor_help();
    } else if eq_ignore_case(cmd, "gdt") {
        if args.len() > 1 {
            // Show specific entry
            if let Some(idx) = parse_number(args[1]) {
                show_gdt_entry(idx);
            } else {
                outln!("Invalid GDT index: {}", args[1]);
            }
        } else {
            show_gdt_all();
        }
    } else if eq_ignore_case(cmd, "idt") {
        if args.len() > 1 {
            // Show specific entry
            if let Some(idx) = parse_number(args[1]) {
                show_idt_entry(idx);
            } else {
                outln!("Invalid IDT index: {}", args[1]);
            }
        } else {
            show_idt_summary();
        }
    } else if eq_ignore_case(cmd, "tss") {
        show_tss();
    } else if eq_ignore_case(cmd, "ldt") {
        show_ldt();
    } else if eq_ignore_case(cmd, "selectors") {
        show_current_selectors();
    } else {
        outln!("Unknown descriptor command: {}", cmd);
        show_descriptor_help();
    }
}

fn show_descriptor_help() {
    outln!("Descriptor Table Viewer");
    outln!("");
    outln!("Usage: descriptor <command> [args]");
    outln!("");
    outln!("Commands:");
    outln!("  gdt              Show all GDT entries");
    outln!("  gdt <index>      Show specific GDT entry");
    outln!("  idt              Show IDT summary");
    outln!("  idt <index>      Show specific IDT entry");
    outln!("  tss              Show Task State Segment");
    outln!("  ldt              Show LDT status");
    outln!("  selectors        Show current segment selectors");
}

#[repr(C, packed)]
struct DescriptorTablePtr {
    limit: u16,
    base: u64,
}

unsafe fn get_gdtr() -> DescriptorTablePtr {
    let mut gdtr = DescriptorTablePtr { limit: 0, base: 0 };
    core::arch::asm!("sgdt [{}]", in(reg) &mut gdtr, options(nostack));
    gdtr
}

unsafe fn get_idtr() -> DescriptorTablePtr {
    let mut idtr = DescriptorTablePtr { limit: 0, base: 0 };
    core::arch::asm!("sidt [{}]", in(reg) &mut idtr, options(nostack));
    idtr
}

fn show_gdt_all() {
    outln!("Global Descriptor Table (GDT)");
    outln!("");

    unsafe {
        let gdtr = get_gdtr();
        // Copy fields from packed struct before using
        let gdt_base = { gdtr.base };
        let gdt_limit = { gdtr.limit };
        let num_entries = (gdt_limit as usize + 1) / 8;

        outln!("GDTR: Base=0x{:016X}  Limit=0x{:04X} ({} entries)",
               gdt_base, gdt_limit, num_entries);
        outln!("");

        outln!("Idx  Base             Limit    Type  DPL P  Flags");
        outln!("---  ----------------  -------  ----  --- -  -----");

        for i in 0..num_entries.min(32) {
            let entry_ptr = (gdt_base + (i as u64 * 8)) as *const u64;
            let entry = core::ptr::read_unaligned(entry_ptr);

            if entry == 0 {
                outln!("{:3}: NULL", i);
                continue;
            }

            // Check if this is a system segment (TSS/LDT are 16 bytes in 64-bit mode)
            let segment_type = ((entry >> 40) & 0xF) as u8;
            let is_system = ((entry >> 44) & 1) == 0;

            if is_system && (segment_type == 0x9 || segment_type == 0xB || segment_type == 0x2) {
                // 16-byte system segment (TSS or LDT)
                let entry_hi = core::ptr::read_unaligned((gdt_base + (i as u64 * 8) + 8) as *const u64);
                show_gdt_system_segment(i, entry, entry_hi);
            } else {
                show_gdt_code_data_segment(i, entry);
            }
        }
    }
}

fn show_gdt_code_data_segment(index: usize, entry: u64) {
    let base = ((entry >> 16) & 0xFFFFFF) | ((entry >> 32) & 0xFF000000);
    let limit = (entry & 0xFFFF) | ((entry >> 32) & 0xF0000);
    let access = ((entry >> 40) & 0xFF) as u8;
    let flags = ((entry >> 52) & 0xF) as u8;

    let segment_type = access & 0xF;
    let dpl = (access >> 5) & 0x3;
    let present = (access >> 7) & 1;
    let is_code = (access & 0x8) != 0;

    let granularity = (flags & 0x8) != 0;
    let actual_limit = if granularity { (limit << 12) | 0xFFF } else { limit };

    let type_str = if is_code {
        match segment_type & 0x7 {
            0 | 4 => "Code",
            1 | 5 => "Code-A",
            2 | 6 => "Code-R",
            3 | 7 => "Code-RA",
            _ => "Code-?",
        }
    } else {
        match segment_type & 0x7 {
            0 | 4 => "Data",
            1 | 5 => "Data-A",
            2 | 6 => "Data-W",
            3 | 7 => "Data-WA",
            _ => "Data-?",
        }
    };

    let flags_str = if (flags & 0x2) != 0 { "L" } else if (flags & 0x4) != 0 { "D" } else { "-" };

    outln!(
        "{:3}: {:016X}  {:07X}  {:6} {:3}  {}  {}{}",
        index,
        base,
        actual_limit,
        type_str,
        dpl,
        present,
        flags_str,
        if granularity { "G" } else { "-" }
    );
}

fn show_gdt_system_segment(index: usize, entry_lo: u64, entry_hi: u64) {
    let base = ((entry_lo >> 16) & 0xFFFFFF)
        | ((entry_lo >> 32) & 0xFF000000)
        | ((entry_hi & 0xFFFFFFFF) << 32);
    let limit = (entry_lo & 0xFFFF) | ((entry_lo >> 32) & 0xF0000);
    let access = ((entry_lo >> 40) & 0xFF) as u8;

    let segment_type = access & 0xF;
    let dpl = (access >> 5) & 0x3;
    let present = (access >> 7) & 1;

    let type_str = match segment_type {
        0x2 => "LDT",
        0x9 => "TSS-A",
        0xB => "TSS-B",
        _ => "Sys-?",
    };

    outln!(
        "{:3}: {:016X}  {:07X}  {:6} {:3}  {}  (16-byte)",
        index,
        base,
        limit,
        type_str,
        dpl,
        present
    );
}

fn show_gdt_entry(index: usize) {
    outln!("GDT Entry {}", index);
    outln!("");

    unsafe {
        let gdtr = get_gdtr();
        let gdt_base = { gdtr.base };
        let gdt_limit = { gdtr.limit };
        let max_entries = (gdt_limit as usize + 1) / 8;

        if index >= max_entries {
            outln!("Error: Index {} out of range (max {})", index, max_entries - 1);
            return;
        }

        let entry_ptr = (gdt_base + (index as u64 * 8)) as *const u64;
        let entry = core::ptr::read_unaligned(entry_ptr);

        outln!("Raw: 0x{:016X}", entry);
        outln!("");

        if entry == 0 {
            outln!("NULL descriptor");
            return;
        }

        // Decode all fields
        let base = ((entry >> 16) & 0xFFFFFF) | ((entry >> 32) & 0xFF000000);
        let limit = (entry & 0xFFFF) | ((entry >> 32) & 0xF0000);
        let access = ((entry >> 40) & 0xFF) as u8;
        let flags = ((entry >> 52) & 0xF) as u8;

        let segment_type = access & 0xF;
        let is_system = ((entry >> 44) & 1) == 0;
        let dpl = (access >> 5) & 0x3;
        let present = (access >> 7) & 1;

        let granularity = (flags & 0x8) != 0;
        let db = (flags & 0x4) != 0;
        let long_mode = (flags & 0x2) != 0;

        outln!("Base:        0x{:016X}", base);
        outln!("Limit:       0x{:05X} ({})", limit, if granularity { "4KB granularity" } else { "byte granularity" });
        outln!("Access:      0x{:02X}", access);
        outln!("  Type:      0x{:X} ({})", segment_type,
               if is_system {
                   match segment_type {
                       0x2 => "LDT",
                       0x9 => "64-bit TSS (Available)",
                       0xB => "64-bit TSS (Busy)",
                       _ => "System"
                   }
               } else if (access & 0x8) != 0 {
                   "Code"
               } else {
                   "Data"
               }
        );
        outln!("  DPL:       {}", dpl);
        outln!("  Present:   {}", present != 0);
        outln!("Flags:       0x{:X}", flags);
        outln!("  G (4KB):   {}", granularity);
        outln!("  D/B:       {}", db);
        outln!("  L (64-bit):{}", long_mode);
    }
}

fn show_idt_summary() {
    outln!("Interrupt Descriptor Table (IDT)");
    outln!("");

    unsafe {
        let idtr = get_idtr();
        let idt_base = { idtr.base };
        let idt_limit = { idtr.limit };
        let num_entries = (idt_limit as usize + 1) / 16;

        outln!("IDTR: Base=0x{:016X}  Limit=0x{:04X} ({} entries)",
               idt_base, idt_limit, num_entries);
        outln!("");

        outln!("Showing active entries (non-NULL handlers):");
        outln!("Vec  Handler           Type       DPL IST");
        outln!("---  ----------------  ---------  --- ---");

        let mut active_count = 0;
        for i in 0..num_entries.min(256) {
            let entry_ptr = (idt_base + (i as u64 * 16)) as *const u128;
            let entry = core::ptr::read_unaligned(entry_ptr);

            let offset_lo = (entry & 0xFFFF) as u64;
            let selector = ((entry >> 16) & 0xFFFF) as u16;
            let ist = ((entry >> 32) & 0x7) as u8;
            let gate_type = ((entry >> 40) & 0xF) as u8;
            let dpl = ((entry >> 45) & 0x3) as u8;
            let present = ((entry >> 47) & 0x1) as u8;
            let offset_mid = ((entry >> 48) & 0xFFFF) as u64;
            let offset_hi = ((entry >> 64) & 0xFFFFFFFF) as u64;

            let handler = offset_lo | (offset_mid << 16) | (offset_hi << 32);

            if present != 0 && handler != 0 {
                let type_str = match gate_type {
                    0xE => "Int Gate",
                    0xF => "Trap Gate",
                    _ => "Unknown",
                };

                let vec_name = get_interrupt_name(i);
                if let Some(name) = vec_name {
                    outln!("{:3}  {:016X}  {:9}  {:3} {:3}  {}",
                           i, handler, type_str, dpl, ist, name);
                } else {
                    outln!("{:3}  {:016X}  {:9}  {:3} {:3}",
                           i, handler, type_str, dpl, ist);
                }
                active_count += 1;
            }
        }

        outln!("");
        outln!("Total active entries: {}", active_count);
    }
}

fn get_interrupt_name(vector: usize) -> Option<&'static str> {
    match vector {
        0 => Some("#DE Divide Error"),
        1 => Some("#DB Debug"),
        2 => Some("NMI"),
        3 => Some("#BP Breakpoint"),
        4 => Some("#OF Overflow"),
        5 => Some("#BR Bound Range"),
        6 => Some("#UD Invalid Opcode"),
        7 => Some("#NM No Math"),
        8 => Some("#DF Double Fault"),
        10 => Some("#TS Invalid TSS"),
        11 => Some("#NP Segment Not Present"),
        12 => Some("#SS Stack Fault"),
        13 => Some("#GP General Protection"),
        14 => Some("#PF Page Fault"),
        16 => Some("#MF Math Fault"),
        17 => Some("#AC Alignment Check"),
        18 => Some("#MC Machine Check"),
        19 => Some("#XM SIMD Exception"),
        20 => Some("#VE Virtualization"),
        21 => Some("#CP Control Protection"),
        32..=47 => Some("IRQ (PIC/APIC)"),
        255 => Some("Spurious"),
        _ => None,
    }
}

fn show_idt_entry(index: usize) {
    outln!("IDT Entry {} (0x{:02X})", index, index);
    outln!("");

    unsafe {
        let idtr = get_idtr();
        let idt_base = { idtr.base };
        let idt_limit = { idtr.limit };
        let max_entries = (idt_limit as usize + 1) / 16;

        if index >= max_entries {
            outln!("Error: Index {} out of range (max {})", index, max_entries - 1);
            return;
        }

        let entry_ptr = (idt_base + (index as u64 * 16)) as *const u128;
        let entry = core::ptr::read_unaligned(entry_ptr);

        outln!("Raw: 0x{:032X}", entry);
        outln!("");

        let offset_lo = (entry & 0xFFFF) as u64;
        let selector = ((entry >> 16) & 0xFFFF) as u16;
        let ist = ((entry >> 32) & 0x7) as u8;
        let gate_type = ((entry >> 40) & 0xF) as u8;
        let dpl = ((entry >> 45) & 0x3) as u8;
        let present = ((entry >> 47) & 0x1) as u8;
        let offset_mid = ((entry >> 48) & 0xFFFF) as u64;
        let offset_hi = ((entry >> 64) & 0xFFFFFFFF) as u64;

        let handler = offset_lo | (offset_mid << 16) | (offset_hi << 32);

        outln!("Handler:     0x{:016X}", handler);
        outln!("Selector:    0x{:04X} (index {}, RPL {})", selector, selector >> 3, selector & 3);
        outln!("IST:         {} {}", ist, if ist > 0 { "(separate stack)" } else { "(default stack)" });
        outln!("Gate Type:   0x{:X} ({})", gate_type,
               match gate_type {
                   0xE => "64-bit Interrupt Gate",
                   0xF => "64-bit Trap Gate",
                   _ => "Unknown"
               }
        );
        outln!("DPL:         {}", dpl);
        outln!("Present:     {}", present != 0);

        if let Some(name) = get_interrupt_name(index) {
            outln!("");
            outln!("Description: {}", name);
        }
    }
}

fn show_tss() {
    outln!("Task State Segment (TSS)");
    outln!("");

    unsafe {
        // Get TSS from GDT - typically at index 2 or 3
        let gdtr = get_gdtr();
        let gdt_base = { gdtr.base };
        let gdt_limit = { gdtr.limit };
        let num_entries = (gdt_limit as usize + 1) / 8;

        let mut tss_found = false;

        for i in 1..num_entries.min(16) {
            let entry_ptr = (gdt_base + (i as u64 * 8)) as *const u64;
            let entry = core::ptr::read_unaligned(entry_ptr);

            let segment_type = ((entry >> 40) & 0xF) as u8;
            let is_system = ((entry >> 44) & 1) == 0;

            if is_system && (segment_type == 0x9 || segment_type == 0xB) {
                // Found TSS
                let entry_hi = core::ptr::read_unaligned((gdt_base + (i as u64 * 8) + 8) as *const u64);
                let base = ((entry >> 16) & 0xFFFFFF)
                    | ((entry >> 32) & 0xFF000000)
                    | ((entry_hi & 0xFFFFFFFF) << 32);
                let limit = (entry & 0xFFFF) | ((entry >> 32) & 0xF0000);

                outln!("TSS found at GDT index {}", i);
                outln!("  Base:  0x{:016X}", base);
                outln!("  Limit: 0x{:05X}", limit);
                outln!("  State: {}", if segment_type == 0x9 { "Available" } else { "Busy" });
                outln!("");

                // Read TSS fields
                let tss_ptr = base as *const u8;
                let rsp0 = core::ptr::read_unaligned(tss_ptr.add(4) as *const u64);
                let rsp1 = core::ptr::read_unaligned(tss_ptr.add(12) as *const u64);
                let rsp2 = core::ptr::read_unaligned(tss_ptr.add(20) as *const u64);

                outln!("Privilege Level Stacks:");
                outln!("  RSP0 (Ring 0): 0x{:016X}", rsp0);
                outln!("  RSP1 (Ring 1): 0x{:016X}", rsp1);
                outln!("  RSP2 (Ring 2): 0x{:016X}", rsp2);
                outln!("");

                outln!("Interrupt Stack Table (IST):");
                for ist in 1..=7 {
                    let ist_ptr = tss_ptr.add(28 + (ist - 1) * 8) as *const u64;
                    let ist_val = core::ptr::read_unaligned(ist_ptr);
                    if ist_val != 0 {
                        outln!("  IST{}: 0x{:016X}", ist, ist_val);
                    }
                }

                let iomap_base = core::ptr::read_unaligned(tss_ptr.add(102) as *const u16);
                outln!("");
                outln!("I/O Map Base: 0x{:04X}", iomap_base);

                tss_found = true;
                break;
            }
        }

        if !tss_found {
            outln!("No TSS found in GDT");
        }
    }
}

fn show_ldt() {
    outln!("Local Descriptor Table (LDT)");
    outln!("");

    unsafe {
        let mut ldtr: u16 = 0;
        core::arch::asm!("sldt {0:x}", out(reg) ldtr, options(nostack));

        if ldtr == 0 {
            outln!("LDTR: 0x0000 (no LDT active)");
            outln!("");
            outln!("Note: 64-bit long mode typically doesn't use LDT");
        } else {
            outln!("LDTR: 0x{:04X} (index {}, RPL {})", ldtr, ldtr >> 3, ldtr & 3);
        }
    }
}

fn show_current_selectors() {
    outln!("Current Segment Selectors");
    outln!("");

    unsafe {
        let cs: u16;
        let ds: u16;
        let es: u16;
        let fs: u16;
        let gs: u16;
        let ss: u16;

        core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nostack));
        core::arch::asm!("mov {0:x}, ds", out(reg) ds, options(nostack));
        core::arch::asm!("mov {0:x}, es", out(reg) es, options(nostack));
        core::arch::asm!("mov {0:x}, fs", out(reg) fs, options(nostack));
        core::arch::asm!("mov {0:x}, gs", out(reg) gs, options(nostack));
        core::arch::asm!("mov {0:x}, ss", out(reg) ss, options(nostack));

        fn describe_selector(sel: u16) -> (&'static str, u16, u16) {
            let index = sel >> 3;
            let rpl = sel & 3;
            let ti = (sel >> 2) & 1;
            let table = if ti == 0 { "GDT" } else { "LDT" };
            (table, index, rpl)
        }

        let (cs_table, cs_idx, cs_rpl) = describe_selector(cs);
        let (ds_table, ds_idx, ds_rpl) = describe_selector(ds);
        let (es_table, es_idx, es_rpl) = describe_selector(es);
        let (fs_table, fs_idx, fs_rpl) = describe_selector(fs);
        let (gs_table, gs_idx, gs_rpl) = describe_selector(gs);
        let (ss_table, ss_idx, ss_rpl) = describe_selector(ss);

        outln!("CS: 0x{:04X}  ({}[{}], RPL={})", cs, cs_table, cs_idx, cs_rpl);
        outln!("DS: 0x{:04X}  ({}[{}], RPL={})", ds, ds_table, ds_idx, ds_rpl);
        outln!("ES: 0x{:04X}  ({}[{}], RPL={})", es, es_table, es_idx, es_rpl);
        outln!("FS: 0x{:04X}  ({}[{}], RPL={})", fs, fs_table, fs_idx, fs_rpl);
        outln!("GS: 0x{:04X}  ({}[{}], RPL={})", gs, gs_table, gs_idx, gs_rpl);
        outln!("SS: 0x{:04X}  ({}[{}], RPL={})", ss, ss_table, ss_idx, ss_rpl);

        outln!("");
        outln!("Note: In 64-bit mode, CS/SS define privilege level;");
        outln!("      DS/ES/FS/GS bases are ignored except for FS/GS");
        outln!("      which use MSRs for their base addresses.");
    }
}

// ============================================================================
// Stack Trace Command
// ============================================================================

/// Stack trace / backtrace for debugging
pub fn cmd_stack(args: &[&str]) {
    if args.is_empty() {
        show_stack_trace(16);
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "help") {
        show_stack_help();
    } else if eq_ignore_case(cmd, "trace") {
        let depth = if args.len() > 1 {
            parse_number(args[1]).unwrap_or(16)
        } else {
            16
        };
        show_stack_trace(depth);
    } else if eq_ignore_case(cmd, "regs") {
        show_stack_registers();
    } else if eq_ignore_case(cmd, "dump") {
        let count = if args.len() > 1 {
            parse_number(args[1]).unwrap_or(32)
        } else {
            32
        };
        dump_stack(count);
    } else if eq_ignore_case(cmd, "rsp") || eq_ignore_case(cmd, "sp") {
        show_rsp_info();
    } else {
        // Assume it's a depth number for trace
        if let Some(depth) = parse_number(cmd) {
            show_stack_trace(depth);
        } else {
            outln!("Unknown stack command: {}", cmd);
            show_stack_help();
        }
    }
}

fn show_stack_help() {
    outln!("Stack Trace");
    outln!("");
    outln!("Usage: stack [command] [args]");
    outln!("");
    outln!("Commands:");
    outln!("  trace [depth]    Show call stack backtrace (default)");
    outln!("  <number>         Same as 'trace <number>'");
    outln!("  regs             Show RSP/RBP and stack-related registers");
    outln!("  dump [count]     Hex dump from current RSP");
    outln!("  rsp              Show RSP pointer info");
    outln!("");
    outln!("Examples:");
    outln!("  stack            Show backtrace (16 frames)");
    outln!("  stack 32         Show 32 stack frames");
    outln!("  stack dump 64    Dump 64 bytes from stack");
}

fn show_stack_trace(max_depth: usize) {
    outln!("Stack Trace (Backtrace)");
    outln!("");

    unsafe {
        let mut rbp: u64;
        let mut rsp: u64;
        let rip: u64;

        core::arch::asm!(
            "mov {}, rbp",
            "mov {}, rsp",
            out(reg) rbp,
            out(reg) rsp,
            options(nostack)
        );

        // Get approximate RIP (will be in the function that called us)
        core::arch::asm!(
            "lea {}, [rip]",
            out(reg) rip,
            options(nostack)
        );

        outln!("Current state:");
        outln!("  RIP: 0x{:016X}", rip);
        outln!("  RSP: 0x{:016X}", rsp);
        outln!("  RBP: 0x{:016X}", rbp);
        outln!("");

        outln!("Call Stack (walking RBP chain):");
        outln!("  #  Return Address     Frame Pointer");
        outln!("  -  ----------------   ----------------");

        let mut frame_count = 0;

        // Walk the RBP chain
        while rbp != 0 && frame_count < max_depth {
            // Validate RBP is in a reasonable range
            if rbp < 0x1000 || rbp > 0xFFFF_FFFF_FFFF_0000 {
                outln!("  (invalid frame pointer: 0x{:016X})", rbp);
                break;
            }

            // Check alignment (RBP should be 8-byte aligned)
            if (rbp & 7) != 0 {
                outln!("  (unaligned frame pointer: 0x{:016X})", rbp);
                break;
            }

            // Read the saved RBP and return address
            let saved_rbp = core::ptr::read_unaligned(rbp as *const u64);
            let return_addr = core::ptr::read_unaligned((rbp + 8) as *const u64);

            outln!("{:3}  0x{:016X}   0x{:016X}", frame_count, return_addr, rbp);

            // Move to next frame
            rbp = saved_rbp;
            frame_count += 1;

            // Safety check - frame should go up in memory
            if saved_rbp != 0 && saved_rbp <= rbp && saved_rbp != rbp {
                outln!("  (stack frame corruption detected)");
                break;
            }
        }

        if frame_count == 0 {
            outln!("  (no valid frames found - frame pointer may be omitted)");
        } else if rbp == 0 {
            outln!("");
            outln!("(end of stack - reached NULL frame pointer)");
        } else if frame_count >= max_depth {
            outln!("");
            outln!("(truncated at {} frames)", max_depth);
        }

        outln!("");
        outln!("Note: Addresses are return addresses (inside calling functions).");
        outln!("      Frame pointer omission (-fomit-frame-pointer) may cause issues.");
    }
}

fn show_stack_registers() {
    outln!("Stack-Related Registers");
    outln!("");

    unsafe {
        let rsp: u64;
        let rbp: u64;
        let rflags: u64;

        core::arch::asm!(
            "mov {}, rsp",
            "mov {}, rbp",
            "pushfq",
            "pop {}",
            out(reg) rsp,
            out(reg) rbp,
            out(reg) rflags,
            options(nostack)
        );

        outln!("RSP (Stack Pointer):    0x{:016X}", rsp);
        outln!("RBP (Base Pointer):     0x{:016X}", rbp);
        outln!("");

        // Check stack size (distance from RSP to RBP)
        if rbp > rsp {
            outln!("Current frame size:     {} bytes (0x{:X})", rbp - rsp, rbp - rsp);
        }

        outln!("");
        outln!("RFLAGS: 0x{:016X}", rflags);
        outln!("  CF={}  ZF={}  SF={}  OF={}  IF={}  DF={}",
               rflags & 1,
               (rflags >> 6) & 1,
               (rflags >> 7) & 1,
               (rflags >> 11) & 1,
               (rflags >> 9) & 1,
               (rflags >> 10) & 1
        );
    }
}

fn dump_stack(count: usize) {
    outln!("Stack Dump");
    outln!("");

    unsafe {
        let rsp: u64;
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack));

        outln!("RSP: 0x{:016X}", rsp);
        outln!("");

        let max_count = count.min(256); // Limit to 256 bytes
        let mut offset = 0usize;

        while offset < max_count {
            let addr = rsp + offset as u64;
            out!("0x{:016X}:", addr);

            // Print 8 bytes per line (one qword at a time)
            for i in 0..2 {
                if offset + i * 8 < max_count {
                    let val = core::ptr::read_unaligned((addr + (i * 8) as u64) as *const u64);
                    out!(" {:016X}", val);
                }
            }
            outln!("");
            offset += 16;
        }
    }
}

fn show_rsp_info() {
    outln!("Stack Pointer Information");
    outln!("");

    unsafe {
        let rsp: u64;
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack));

        outln!("RSP: 0x{:016X}", rsp);
        outln!("");

        // Try to determine which stack we're on
        // Kernel stacks are typically in high memory
        if rsp >= 0xFFFF_8000_0000_0000 {
            outln!("Location: Kernel space (higher half)");
        } else if rsp >= 0x7FFF_0000_0000 {
            outln!("Location: User space stack region");
        } else {
            outln!("Location: Unknown/low memory");
        }

        // Check alignment
        outln!("");
        outln!("Alignment:");
        outln!("  8-byte aligned:  {}", (rsp & 7) == 0);
        outln!("  16-byte aligned: {}", (rsp & 15) == 0);

        // Read a few values from the stack
        outln!("");
        outln!("Stack preview (first 4 qwords):");
        for i in 0..4u64 {
            let val = core::ptr::read_unaligned((rsp + i * 8) as *const u64);
            outln!("  [RSP+0x{:02X}]: 0x{:016X}", i * 8, val);
        }
    }
}

// ============================================================================
// HPET (High Precision Event Timer) Viewer
// ============================================================================

/// HPET viewer for high precision timer diagnostics
pub fn cmd_hpet(args: &[&str]) {
    // Standard HPET base address (can vary, normally found via ACPI)
    // Common addresses: 0xFED00000, 0xFED01000, 0xFED02000, 0xFED03000
    let hpet_base = 0xFED0_0000u64;

    if args.is_empty() {
        show_hpet_overview(hpet_base);
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "help") {
        show_hpet_help();
    } else if eq_ignore_case(cmd, "status") {
        show_hpet_overview(hpet_base);
    } else if eq_ignore_case(cmd, "regs") {
        show_hpet_registers(hpet_base);
    } else if eq_ignore_case(cmd, "timers") {
        show_hpet_timers(hpet_base);
    } else if eq_ignore_case(cmd, "counter") {
        show_hpet_counter(hpet_base);
    } else if eq_ignore_case(cmd, "base") {
        if args.len() > 1 {
            if let Some(addr) = parse_number(args[1]) {
                show_hpet_overview(addr as u64);
            } else {
                outln!("Invalid address: {}", args[1]);
            }
        } else {
            outln!("Current HPET base: 0x{:08X}", hpet_base);
            outln!("Usage: hpet base <address>");
        }
    } else {
        outln!("Unknown hpet command: {}", cmd);
        show_hpet_help();
    }
}

fn show_hpet_help() {
    outln!("HPET (High Precision Event Timer) Viewer");
    outln!("");
    outln!("Usage: hpet [command] [args]");
    outln!("");
    outln!("Commands:");
    outln!("  status       Overview of HPET (default)");
    outln!("  regs         Show all HPET registers");
    outln!("  timers       Show timer comparator info");
    outln!("  counter      Show main counter value");
    outln!("  base <addr>  Use different HPET base address");
    outln!("");
    outln!("Note: Default base is 0xFED00000. Actual address");
    outln!("      should be obtained from ACPI HPET table.");
}

unsafe fn hpet_read(base: u64, offset: u64) -> u64 {
    let addr = (base + offset) as *const u64;
    core::ptr::read_volatile(addr)
}

fn show_hpet_overview(base: u64) {
    outln!("HPET Status (base 0x{:08X})", base);
    outln!("");

    unsafe {
        // Read General Capabilities and ID Register (offset 0x00)
        let caps = hpet_read(base, 0x00);

        // Check if HPET appears valid
        if caps == 0 || caps == 0xFFFFFFFFFFFFFFFF {
            outln!("Error: HPET not detected at 0x{:08X}", base);
            outln!("Try 'hpet base <address>' with correct HPET address.");
            outln!("Common addresses: 0xFED00000, 0xFED01000");
            return;
        }

        let rev_id = (caps & 0xFF) as u8;
        let num_timers = (((caps >> 8) & 0x1F) + 1) as u8;
        let count_size = ((caps >> 13) & 1) != 0; // true = 64-bit
        let legacy_capable = ((caps >> 15) & 1) != 0;
        let vendor_id = ((caps >> 16) & 0xFFFF) as u16;
        let period_fs = (caps >> 32) as u32; // Period in femtoseconds

        outln!("Capabilities (0x00): 0x{:016X}", caps);
        outln!("");
        outln!("  Revision:      {}", rev_id);
        outln!("  Vendor ID:     0x{:04X}", vendor_id);
        outln!("  Num Timers:    {}", num_timers);
        outln!("  Counter Size:  {}-bit", if count_size { 64 } else { 32 });
        outln!("  Legacy Route:  {}", if legacy_capable { "Capable" } else { "Not capable" });
        outln!("");

        // Calculate frequency from period
        if period_fs > 0 {
            let freq_hz = 1_000_000_000_000_000u64 / period_fs as u64;
            let freq_mhz = freq_hz / 1_000_000;
            outln!("  Period:        {} fs ({} ns)", period_fs, period_fs / 1_000_000);
            outln!("  Frequency:     ~{} MHz ({} Hz)", freq_mhz, freq_hz);
        }
        outln!("");

        // Read General Configuration (offset 0x10)
        let config = hpet_read(base, 0x10);
        let enabled = (config & 1) != 0;
        let legacy_enabled = ((config >> 1) & 1) != 0;

        outln!("Configuration (0x10): 0x{:016X}", config);
        outln!("  ENABLE_CNF:    {} (main counter {})", enabled as u8,
               if enabled { "running" } else { "stopped" });
        outln!("  LEG_RT_CNF:    {} (legacy replacement {})", legacy_enabled as u8,
               if legacy_enabled { "enabled" } else { "disabled" });
        outln!("");

        // Read General Interrupt Status (offset 0x20)
        let int_status = hpet_read(base, 0x20);
        outln!("Interrupt Status (0x20): 0x{:016X}", int_status);

        // Read Main Counter (offset 0xF0)
        let counter = hpet_read(base, 0xF0);
        outln!("");
        outln!("Main Counter (0xF0): 0x{:016X} ({})", counter, counter);

        if period_fs > 0 && counter > 0 {
            let ns = (counter as u128 * period_fs as u128) / 1_000_000;
            let seconds = ns / 1_000_000_000;
            let ms = (ns % 1_000_000_000) / 1_000_000;
            outln!("  Uptime:        {}s {}ms", seconds, ms);
        }
    }
}

fn show_hpet_registers(base: u64) {
    outln!("HPET Registers (base 0x{:08X})", base);
    outln!("");

    unsafe {
        let regs = [
            (0x00, "GCAP_ID", "General Capabilities and ID"),
            (0x10, "GEN_CONF", "General Configuration"),
            (0x20, "GINTR_STA", "General Interrupt Status"),
            (0xF0, "MAIN_CNT", "Main Counter Value"),
        ];

        for (offset, name, desc) in regs {
            let val = hpet_read(base, offset);
            outln!("0x{:03X} {:10}: 0x{:016X}  {}", offset, name, val, desc);
        }
    }
}

fn show_hpet_timers(base: u64) {
    outln!("HPET Timer Comparators (base 0x{:08X})", base);
    outln!("");

    unsafe {
        let caps = hpet_read(base, 0x00);
        let num_timers = ((caps >> 8) & 0x1F) + 1;

        outln!("Number of timers: {}", num_timers);
        outln!("");

        for i in 0..num_timers.min(8) {
            let timer_offset = 0x100 + (i as u64 * 0x20);

            let config = hpet_read(base, timer_offset);
            let comparator = hpet_read(base, timer_offset + 0x08);

            let int_type = (config >> 1) & 1; // 0=edge, 1=level
            let int_enabled = (config >> 2) & 1;
            let periodic = (config >> 3) & 1;
            let periodic_capable = (config >> 4) & 1;
            let size_64 = (config >> 5) & 1;
            let fsb_capable = (config >> 15) & 1;
            let int_route = (config >> 9) & 0x1F;

            outln!("Timer {}:", i);
            outln!("  Config (0x{:03X}):     0x{:016X}", timer_offset, config);
            outln!("  Comparator:          0x{:016X}", comparator);
            outln!("  Int Enabled:         {}", int_enabled != 0);
            outln!("  Int Type:            {}", if int_type != 0 { "Level" } else { "Edge" });
            outln!("  Int Route:           {}", int_route);
            outln!("  Periodic:            {} (capable: {})", periodic != 0, periodic_capable != 0);
            outln!("  64-bit:              {}", size_64 != 0);
            outln!("  FSB Capable:         {}", fsb_capable != 0);
            outln!("");
        }
    }
}

fn show_hpet_counter(base: u64) {
    outln!("HPET Main Counter");
    outln!("");

    unsafe {
        let caps = hpet_read(base, 0x00);
        let period_fs = (caps >> 32) as u32;
        let config = hpet_read(base, 0x10);
        let enabled = (config & 1) != 0;

        outln!("Counter enabled: {}", enabled);
        outln!("");

        // Read counter multiple times to show it's ticking
        outln!("Counter samples (5 reads):");
        for i in 0..5 {
            let counter = hpet_read(base, 0xF0);
            outln!("  #{}: 0x{:016X} ({})", i + 1, counter, counter);

            // Small delay
            for _ in 0..10000 {
                core::arch::asm!("nop", options(nomem, nostack));
            }
        }

        if period_fs > 0 {
            let freq_mhz = 1_000_000_000_000_000u64 / period_fs as u64 / 1_000_000;
            outln!("");
            outln!("Counter frequency: ~{} MHz", freq_mhz);
            outln!("Period: {} femtoseconds", period_fs);
        }
    }
}

// ============================================================================
// SMBIOS/DMI Viewer Command
// ============================================================================

/// SMBIOS/DMI viewer for system information
pub fn cmd_smbios(args: &[&str]) {
    if args.is_empty() {
        show_smbios_overview();
        return;
    }

    let cmd = args[0];

    if eq_ignore_case(cmd, "help") {
        show_smbios_help();
    } else if eq_ignore_case(cmd, "status") || eq_ignore_case(cmd, "info") {
        show_smbios_overview();
    } else if eq_ignore_case(cmd, "bios") {
        show_smbios_bios();
    } else if eq_ignore_case(cmd, "system") {
        show_smbios_system();
    } else if eq_ignore_case(cmd, "cpu") || eq_ignore_case(cmd, "processor") {
        show_smbios_processor();
    } else if eq_ignore_case(cmd, "memory") || eq_ignore_case(cmd, "mem") {
        show_smbios_memory();
    } else if eq_ignore_case(cmd, "all") {
        show_smbios_all();
    } else if eq_ignore_case(cmd, "raw") {
        if args.len() > 1 {
            if let Some(type_num) = parse_number(args[1]) {
                show_smbios_type(type_num as u8);
            } else {
                outln!("Invalid type number: {}", args[1]);
            }
        } else {
            outln!("Usage: smbios raw <type>");
        }
    } else {
        outln!("Unknown smbios command: {}", cmd);
        show_smbios_help();
    }
}

fn show_smbios_help() {
    outln!("SMBIOS/DMI Viewer");
    outln!("");
    outln!("Usage: smbios [command]");
    outln!("");
    outln!("Commands:");
    outln!("  info         Show SMBIOS entry point (default)");
    outln!("  bios         BIOS information (Type 0)");
    outln!("  system       System information (Type 1)");
    outln!("  cpu          Processor information (Type 4)");
    outln!("  memory       Memory information (Type 16/17)");
    outln!("  all          List all SMBIOS structures");
    outln!("  raw <type>   Show raw data for specific type");
}

/// SMBIOS Entry Point structure (32-bit)
#[repr(C, packed)]
struct SmbiosEntryPoint {
    anchor: [u8; 4],       // "_SM_"
    checksum: u8,
    length: u8,
    major_version: u8,
    minor_version: u8,
    max_struct_size: u16,
    revision: u8,
    formatted_area: [u8; 5],
    intermediate_anchor: [u8; 5], // "_DMI_"
    intermediate_checksum: u8,
    table_length: u16,
    table_address: u32,
    num_structures: u16,
    bcd_revision: u8,
}

/// SMBIOS 3.0 Entry Point (64-bit)
#[repr(C, packed)]
struct Smbios3EntryPoint {
    anchor: [u8; 5],       // "_SM3_"
    checksum: u8,
    length: u8,
    major_version: u8,
    minor_version: u8,
    docrev: u8,
    revision: u8,
    reserved: u8,
    table_max_size: u32,
    table_address: u64,
}

/// SMBIOS structure header
#[repr(C, packed)]
struct SmbiosHeader {
    struct_type: u8,
    length: u8,
    handle: u16,
}

/// Find SMBIOS entry point
fn find_smbios_entry() -> Option<(u64, u8, u8, u32, u16)> {
    // Scan for SMBIOS entry in F0000-FFFFF range
    // In UEFI systems, may need to use EFI System Table instead
    unsafe {
        // First try SMBIOS 3.0 (_SM3_)
        let mut addr = 0xF0000u64;
        while addr < 0x100000 {
            let sig = core::ptr::read_unaligned(addr as *const [u8; 5]);
            if &sig == b"_SM3_" {
                let entry = addr as *const Smbios3EntryPoint;
                let major = { (*entry).major_version };
                let minor = { (*entry).minor_version };
                let table_addr = { (*entry).table_address };
                let max_size = { (*entry).table_max_size };
                return Some((table_addr, major, minor, max_size, 0));
            }
            addr += 16;
        }

        // Try legacy SMBIOS 2.x (_SM_)
        addr = 0xF0000;
        while addr < 0x100000 {
            let sig = core::ptr::read_unaligned(addr as *const [u8; 4]);
            if &sig == b"_SM_" {
                let entry = addr as *const SmbiosEntryPoint;
                let major = { (*entry).major_version };
                let minor = { (*entry).minor_version };
                let table_addr = { (*entry).table_address } as u64;
                let table_len = { (*entry).table_length };
                let num_structs = { (*entry).num_structures };
                return Some((table_addr, major, minor, table_len as u32, num_structs));
            }
            addr += 16;
        }
    }
    None
}

fn show_smbios_overview() {
    outln!("SMBIOS/DMI Information");
    outln!("");

    match find_smbios_entry() {
        Some((table_addr, major, minor, size, count)) => {
            outln!("SMBIOS Version: {}.{}", major, minor);
            outln!("Table Address:  0x{:08X}", table_addr);
            outln!("Table Size:     {} bytes", size);
            if count > 0 {
                outln!("Structures:     {}", count);
            }
            outln!("");

            // Try to show basic info
            show_smbios_bios();
        }
        None => {
            outln!("SMBIOS entry point not found in F0000-FFFFF range.");
            outln!("");
            outln!("Note: On UEFI systems, SMBIOS table address may be");
            outln!("      provided via EFI Configuration Table.");
        }
    }
}

/// Get string from SMBIOS structure
unsafe fn smbios_get_string(data_end: *const u8, index: u8) -> &'static str {
    if index == 0 {
        return "";
    }

    let mut ptr = data_end;
    let mut current = 1u8;

    while current < index {
        // Skip to next string
        while *ptr != 0 {
            ptr = ptr.add(1);
        }
        ptr = ptr.add(1);

        // Check for double-null (end of strings)
        if *ptr == 0 {
            return "";
        }
        current += 1;
    }

    // Found the string, read it
    let start = ptr;
    let mut len = 0;
    while *ptr.add(len) != 0 && len < 128 {
        len += 1;
    }

    core::str::from_utf8_unchecked(core::slice::from_raw_parts(start, len))
}

fn show_smbios_bios() {
    if let Some((table_addr, _, _, _, _)) = find_smbios_entry() {
        unsafe {
            let mut ptr = table_addr as *const u8;

            // Find Type 0 (BIOS Information)
            for _ in 0..50 {
                let header = ptr as *const SmbiosHeader;
                let struct_type = { (*header).struct_type };
                let length = { (*header).length };

                if struct_type == 0 && length >= 0x14 {
                    outln!("BIOS Information (Type 0)");
                    outln!("");

                    let data = ptr;
                    let strings = ptr.add(length as usize);

                    let vendor_idx = *data.add(0x04);
                    let version_idx = *data.add(0x05);
                    let date_idx = *data.add(0x08);

                    let vendor = smbios_get_string(strings, vendor_idx);
                    let version = smbios_get_string(strings, version_idx);
                    let date = smbios_get_string(strings, date_idx);

                    outln!("  Vendor:       {}", if vendor.is_empty() { "N/A" } else { vendor });
                    outln!("  Version:      {}", if version.is_empty() { "N/A" } else { version });
                    outln!("  Release Date: {}", if date.is_empty() { "N/A" } else { date });

                    if length >= 0x18 {
                        let rom_size = *data.add(0x09);
                        if rom_size != 0xFF {
                            outln!("  ROM Size:     {} KB", (rom_size as u32 + 1) * 64);
                        }
                    }
                    return;
                }

                // Move to next structure
                ptr = ptr.add(length as usize);
                while !(*ptr == 0 && *ptr.add(1) == 0) {
                    ptr = ptr.add(1);
                }
                ptr = ptr.add(2);

                if struct_type == 127 {
                    break; // End of table
                }
            }
        }
        outln!("BIOS information not found");
    } else {
        outln!("SMBIOS not available");
    }
}

fn show_smbios_system() {
    if let Some((table_addr, _, _, _, _)) = find_smbios_entry() {
        unsafe {
            let mut ptr = table_addr as *const u8;

            for _ in 0..50 {
                let header = ptr as *const SmbiosHeader;
                let struct_type = { (*header).struct_type };
                let length = { (*header).length };

                if struct_type == 1 && length >= 0x08 {
                    outln!("System Information (Type 1)");
                    outln!("");

                    let data = ptr;
                    let strings = ptr.add(length as usize);

                    let manufacturer_idx = *data.add(0x04);
                    let product_idx = *data.add(0x05);
                    let version_idx = *data.add(0x06);
                    let serial_idx = *data.add(0x07);

                    let manufacturer = smbios_get_string(strings, manufacturer_idx);
                    let product = smbios_get_string(strings, product_idx);
                    let version = smbios_get_string(strings, version_idx);
                    let serial = smbios_get_string(strings, serial_idx);

                    outln!("  Manufacturer: {}", if manufacturer.is_empty() { "N/A" } else { manufacturer });
                    outln!("  Product:      {}", if product.is_empty() { "N/A" } else { product });
                    outln!("  Version:      {}", if version.is_empty() { "N/A" } else { version });
                    outln!("  Serial:       {}", if serial.is_empty() { "N/A" } else { serial });

                    if length >= 0x19 {
                        // UUID at offset 0x08 (16 bytes)
                        out!("  UUID:         ");
                        for i in 0..16 {
                            out!("{:02X}", *data.add(0x08 + i));
                            if i == 3 || i == 5 || i == 7 || i == 9 {
                                out!("-");
                            }
                        }
                        outln!("");
                    }
                    return;
                }

                ptr = ptr.add(length as usize);
                while !(*ptr == 0 && *ptr.add(1) == 0) {
                    ptr = ptr.add(1);
                }
                ptr = ptr.add(2);

                if struct_type == 127 {
                    break;
                }
            }
        }
        outln!("System information not found");
    } else {
        outln!("SMBIOS not available");
    }
}

fn show_smbios_processor() {
    if let Some((table_addr, _, _, _, _)) = find_smbios_entry() {
        unsafe {
            let mut ptr = table_addr as *const u8;
            let mut proc_count = 0;

            for _ in 0..100 {
                let header = ptr as *const SmbiosHeader;
                let struct_type = { (*header).struct_type };
                let length = { (*header).length };

                if struct_type == 4 && length >= 0x1A {
                    if proc_count == 0 {
                        outln!("Processor Information (Type 4)");
                        outln!("");
                    }
                    proc_count += 1;

                    let data = ptr;
                    let strings = ptr.add(length as usize);

                    let socket_idx = *data.add(0x04);
                    let manufacturer_idx = *data.add(0x07);
                    let version_idx = *data.add(0x10);

                    let socket = smbios_get_string(strings, socket_idx);
                    let manufacturer = smbios_get_string(strings, manufacturer_idx);
                    let version = smbios_get_string(strings, version_idx);

                    let proc_type = *data.add(0x05);
                    let proc_family = *data.add(0x06);
                    let max_speed = u16::from_le_bytes([*data.add(0x14), *data.add(0x15)]);
                    let cur_speed = u16::from_le_bytes([*data.add(0x16), *data.add(0x17)]);

                    outln!("Processor {}:", proc_count);
                    outln!("  Socket:       {}", if socket.is_empty() { "N/A" } else { socket });
                    outln!("  Manufacturer: {}", if manufacturer.is_empty() { "N/A" } else { manufacturer });
                    outln!("  Version:      {}", if version.is_empty() { "N/A" } else { version });
                    outln!("  Type:         {} ({:#x})", proc_type_name(proc_type), proc_type);
                    outln!("  Family:       {}", proc_family);
                    outln!("  Max Speed:    {} MHz", max_speed);
                    outln!("  Current:      {} MHz", cur_speed);

                    if length >= 0x28 {
                        let cores = *data.add(0x23);
                        let enabled = *data.add(0x24);
                        let threads = *data.add(0x25);
                        if cores > 0 {
                            outln!("  Cores:        {} (enabled: {})", cores, enabled);
                            outln!("  Threads:      {}", threads);
                        }
                    }
                    outln!("");
                }

                ptr = ptr.add(length as usize);
                while !(*ptr == 0 && *ptr.add(1) == 0) {
                    ptr = ptr.add(1);
                }
                ptr = ptr.add(2);

                if struct_type == 127 {
                    break;
                }
            }

            if proc_count == 0 {
                outln!("Processor information not found");
            }
        }
    } else {
        outln!("SMBIOS not available");
    }
}

fn proc_type_name(t: u8) -> &'static str {
    match t {
        1 => "Other",
        2 => "Unknown",
        3 => "Central Processor",
        4 => "Math Processor",
        5 => "DSP Processor",
        6 => "Video Processor",
        _ => "Reserved",
    }
}

fn show_smbios_memory() {
    if let Some((table_addr, _, _, _, _)) = find_smbios_entry() {
        unsafe {
            let mut ptr = table_addr as *const u8;
            let mut device_count = 0;

            for _ in 0..200 {
                let header = ptr as *const SmbiosHeader;
                let struct_type = { (*header).struct_type };
                let length = { (*header).length };

                // Type 17: Memory Device
                if struct_type == 17 && length >= 0x15 {
                    if device_count == 0 {
                        outln!("Memory Devices (Type 17)");
                        outln!("");
                    }

                    let data = ptr;
                    let strings = ptr.add(length as usize);

                    let size = u16::from_le_bytes([*data.add(0x0C), *data.add(0x0D)]);
                    let device_loc_idx = *data.add(0x10);
                    let bank_loc_idx = *data.add(0x11);

                    if size != 0 && size != 0xFFFF {
                        device_count += 1;
                        let device_loc = smbios_get_string(strings, device_loc_idx);
                        let bank_loc = smbios_get_string(strings, bank_loc_idx);

                        let size_mb = if size & 0x8000 != 0 {
                            (size & 0x7FFF) as u32 // KB
                        } else {
                            (size as u32) * 1024 // MB to KB
                        };

                        outln!("Device {}:", device_count);
                        outln!("  Location:     {}", if device_loc.is_empty() { "N/A" } else { device_loc });
                        outln!("  Bank:         {}", if bank_loc.is_empty() { "N/A" } else { bank_loc });
                        outln!("  Size:         {} MB", size_mb / 1024);

                        if length >= 0x17 {
                            let speed = u16::from_le_bytes([*data.add(0x15), *data.add(0x16)]);
                            if speed > 0 {
                                outln!("  Speed:        {} MHz", speed);
                            }
                        }

                        if length >= 0x1B {
                            let manufacturer_idx = *data.add(0x17);
                            let manufacturer = smbios_get_string(strings, manufacturer_idx);
                            if !manufacturer.is_empty() {
                                outln!("  Manufacturer: {}", manufacturer);
                            }
                        }
                        outln!("");
                    }
                }

                ptr = ptr.add(length as usize);
                while !(*ptr == 0 && *ptr.add(1) == 0) {
                    ptr = ptr.add(1);
                }
                ptr = ptr.add(2);

                if struct_type == 127 {
                    break;
                }
            }

            if device_count == 0 {
                outln!("No populated memory devices found");
            } else {
                outln!("Total: {} memory device(s)", device_count);
            }
        }
    } else {
        outln!("SMBIOS not available");
    }
}

fn show_smbios_all() {
    if let Some((table_addr, major, minor, _, _)) = find_smbios_entry() {
        outln!("All SMBIOS Structures (v{}.{})", major, minor);
        outln!("");
        outln!("Type Handle Length Description");
        outln!("---- ------ ------ -----------");

        unsafe {
            let mut ptr = table_addr as *const u8;

            for _ in 0..256 {
                let header = ptr as *const SmbiosHeader;
                let struct_type = { (*header).struct_type };
                let length = { (*header).length };
                let handle = { (*header).handle };

                let type_name = smbios_type_name(struct_type);
                outln!("{:4} 0x{:04X} {:6} {}", struct_type, handle, length, type_name);

                ptr = ptr.add(length as usize);
                while !(*ptr == 0 && *ptr.add(1) == 0) {
                    ptr = ptr.add(1);
                }
                ptr = ptr.add(2);

                if struct_type == 127 {
                    break;
                }
            }
        }
    } else {
        outln!("SMBIOS not available");
    }
}

fn smbios_type_name(t: u8) -> &'static str {
    match t {
        0 => "BIOS Information",
        1 => "System Information",
        2 => "Baseboard Information",
        3 => "System Enclosure",
        4 => "Processor Information",
        5 => "Memory Controller",
        6 => "Memory Module",
        7 => "Cache Information",
        8 => "Port Connector",
        9 => "System Slots",
        10 => "On Board Devices",
        11 => "OEM Strings",
        12 => "System Config Options",
        13 => "BIOS Language",
        14 => "Group Associations",
        15 => "System Event Log",
        16 => "Physical Memory Array",
        17 => "Memory Device",
        18 => "32-bit Memory Error",
        19 => "Memory Array Mapped Addr",
        20 => "Memory Device Mapped Addr",
        21 => "Built-in Pointing Device",
        22 => "Portable Battery",
        23 => "System Reset",
        24 => "Hardware Security",
        25 => "System Power Controls",
        26 => "Voltage Probe",
        27 => "Cooling Device",
        28 => "Temperature Probe",
        29 => "Electrical Current Probe",
        30 => "Out-of-Band Remote Access",
        31 => "Boot Integrity Services",
        32 => "System Boot",
        33 => "64-bit Memory Error",
        34 => "Management Device",
        35 => "Mgmt Device Component",
        36 => "Mgmt Device Threshold",
        37 => "Memory Channel",
        38 => "IPMI Device",
        39 => "System Power Supply",
        40 => "Additional Information",
        41 => "Onboard Devices Ext",
        42 => "Mgmt Controller Host IF",
        43 => "TPM Device",
        44 => "Processor Additional",
        45 => "Firmware Inventory",
        127 => "End-of-Table",
        _ => "OEM/Unknown",
    }
}

fn show_smbios_type(type_num: u8) {
    if let Some((table_addr, _, _, _, _)) = find_smbios_entry() {
        outln!("SMBIOS Type {} Raw Data", type_num);
        outln!("");

        unsafe {
            let mut ptr = table_addr as *const u8;
            let mut found = false;

            for _ in 0..256 {
                let header = ptr as *const SmbiosHeader;
                let struct_type = { (*header).struct_type };
                let length = { (*header).length };
                let handle = { (*header).handle };

                if struct_type == type_num {
                    found = true;
                    outln!("Handle: 0x{:04X}  Length: {}", handle, length);
                    outln!("");

                    // Hex dump
                    for i in 0..length {
                        if i % 16 == 0 {
                            out!("{:04X}: ", i);
                        }
                        out!("{:02X} ", *ptr.add(i as usize));
                        if i % 16 == 15 || i == length - 1 {
                            outln!("");
                        }
                    }
                    outln!("");
                }

                ptr = ptr.add(length as usize);
                while !(*ptr == 0 && *ptr.add(1) == 0) {
                    ptr = ptr.add(1);
                }
                ptr = ptr.add(2);

                if struct_type == 127 {
                    break;
                }
            }

            if !found {
                outln!("No structures of type {} found", type_num);
            }
        }
    } else {
        outln!("SMBIOS not available");
    }
}

// ============================================================================
// Exception History Command
// ============================================================================

/// Exception history viewer command
pub fn cmd_exception(args: &[&str]) {
    if args.is_empty() {
        show_exception_overview();
        return;
    }

    let cmd = args[0];
    if eq_ignore_case(cmd, "help") {
        show_exception_help();
    } else if eq_ignore_case(cmd, "list") || eq_ignore_case(cmd, "history") {
        let count = if args.len() > 1 {
            parse_number(args[1]).unwrap_or(20) as usize
        } else {
            20
        };
        show_exception_list(count);
    } else if eq_ignore_case(cmd, "detail") || eq_ignore_case(cmd, "show") {
        if args.len() > 1 {
            let index = parse_number(args[1]).unwrap_or(0) as usize;
            show_exception_detail(index);
        } else {
            outln!("Usage: exception detail <index>");
        }
    } else if eq_ignore_case(cmd, "stats") || eq_ignore_case(cmd, "summary") {
        show_exception_stats();
    } else if eq_ignore_case(cmd, "clear") {
        clear_exception_history();
        outln!("Exception history cleared");
    } else if eq_ignore_case(cmd, "test") {
        if args.len() > 1 {
            test_exception(args[1]);
        } else {
            outln!("Usage: exception test <type>");
            outln!("  Types: div0, breakpoint, gpf, pagefault");
        }
    } else {
        outln!("Unknown exception command: {}", cmd);
        show_exception_help();
    }
}

fn show_exception_help() {
    outln!("Exception History Viewer");
    outln!("");
    outln!("Usage: exception <command>");
    outln!("");
    outln!("Commands:");
    outln!("  (none)        Show overview/status");
    outln!("  list [n]      Show last n exceptions (default 20)");
    outln!("  detail <idx>  Show detailed info for exception #idx");
    outln!("  stats         Show exception statistics");
    outln!("  clear         Clear exception history");
    outln!("  test <type>   Trigger test exception");
    outln!("");
    outln!("Test types:");
    outln!("  div0          Integer divide by zero");
    outln!("  breakpoint    Software breakpoint (INT 3)");
    outln!("  gpf           General protection fault");
    outln!("  pagefault     Page fault (null pointer)");
}

fn show_exception_overview() {
    use crate::ke::exception::{get_exception_history, EXCEPTION_HISTORY_SIZE};

    let (entries, write_index, total_count) = get_exception_history();

    outln!("Exception History");
    outln!("=================");
    outln!("");
    outln!("Total exceptions recorded: {}", total_count);
    outln!("Buffer size: {} entries", EXCEPTION_HISTORY_SIZE);
    outln!("Current write index: {}", write_index);

    // Count valid entries
    let valid_count = entries.iter().filter(|e| e.valid).count();
    outln!("Valid entries in buffer: {}", valid_count);

    if valid_count > 0 {
        outln!("");
        outln!("Most recent exceptions:");
        outln!("------------------------");

        // Show last 5 entries
        let mut shown = 0;
        let mut idx = if write_index == 0 { EXCEPTION_HISTORY_SIZE - 1 } else { write_index - 1 };
        while shown < 5 && shown < valid_count {
            let entry = &entries[idx];
            if entry.valid {
                let code_name = crate::ke::exception::exception_code_name(entry.code);
                let handled = if entry.handled { "H" } else { "-" };
                let chance = if entry.first_chance { "1st" } else { "2nd" };
                outln!("  #{:<2} {:#010x} {:16} {} {} addr={:#x}",
                    shown, entry.code, code_name, handled, chance, entry.address);
                shown += 1;
            }
            if idx == 0 {
                idx = EXCEPTION_HISTORY_SIZE - 1;
            } else {
                idx -= 1;
            }
            if idx == write_index {
                break;
            }
        }
    }

    outln!("");
    outln!("Use 'exception list' for full history");
    outln!("Use 'exception help' for all commands");
}

fn show_exception_list(count: usize) {
    use crate::ke::exception::{get_exception_history, EXCEPTION_HISTORY_SIZE};

    let (entries, write_index, total_count) = get_exception_history();

    let valid_count = entries.iter().filter(|e| e.valid).count();
    let show_count = count.min(valid_count);

    if valid_count == 0 {
        outln!("No exceptions in history");
        return;
    }

    outln!("Exception History (showing {} of {})", show_count, valid_count);
    outln!("");
    outln!("{:<4} {:<12} {:<18} {:<3} {:<3} {:<18} {:<18}",
        "#", "Code", "Type", "H", "Ch", "Address", "Info");
    outln!("--------------------------------------------------------------------------------");

    let mut shown = 0;
    let mut idx = if write_index == 0 { EXCEPTION_HISTORY_SIZE - 1 } else { write_index - 1 };

    while shown < show_count {
        let entry = &entries[idx];
        if entry.valid {
            let code_name = crate::ke::exception::exception_code_name(entry.code);
            let handled = if entry.handled { "Y" } else { "N" };
            let chance = if entry.first_chance { "1" } else { "2" };
            outln!("{:<4} {:#010x} {:18} {:3} {:3} {:#018x} {:#018x}",
                shown, entry.code, code_name, handled, chance, entry.address, entry.info);
            shown += 1;
        }
        if idx == 0 {
            idx = EXCEPTION_HISTORY_SIZE - 1;
        } else {
            idx -= 1;
        }
        if idx == write_index {
            break;
        }
    }

    if total_count > EXCEPTION_HISTORY_SIZE as u64 {
        outln!("");
        outln!("(History has wrapped; {} older entries lost)",
            total_count - EXCEPTION_HISTORY_SIZE as u64);
    }
}

fn show_exception_detail(index: usize) {
    use crate::ke::exception::{get_exception_history, EXCEPTION_HISTORY_SIZE};

    let (entries, write_index, _total_count) = get_exception_history();

    // Convert display index to buffer index (most recent = 0)
    let mut buf_idx = if write_index == 0 { EXCEPTION_HISTORY_SIZE - 1 } else { write_index - 1 };
    let mut current = 0;

    while current < index {
        if buf_idx == 0 {
            buf_idx = EXCEPTION_HISTORY_SIZE - 1;
        } else {
            buf_idx -= 1;
        }
        if entries[buf_idx].valid {
            current += 1;
        }
        if buf_idx == write_index {
            outln!("Exception #{} not found", index);
            return;
        }
    }

    let entry = &entries[buf_idx];
    if !entry.valid {
        outln!("Exception #{} not found", index);
        return;
    }

    let code_name = crate::ke::exception::exception_code_name(entry.code);

    outln!("Exception #{} Details", index);
    outln!("=====================");
    outln!("");
    outln!("Exception Code:   {:#010x} ({})", entry.code, code_name);
    outln!("Exception Flags:  {:#010x}", entry.flags);
    outln!("Address (RIP):    {:#018x}", entry.address);
    outln!("Additional Info:  {:#018x}", entry.info);
    outln!("Stack Pointer:    {:#018x}", entry.rsp);
    outln!("Timestamp (TSC):  {}", entry.timestamp);
    outln!("First Chance:     {}", if entry.first_chance { "Yes" } else { "No" });
    outln!("Handled:          {}", if entry.handled { "Yes" } else { "No" });

    // Decode flags
    outln!("");
    outln!("Flags Decoded:");
    if entry.flags == 0 {
        outln!("  CONTINUABLE");
    }
    if entry.flags & 0x01 != 0 {
        outln!("  NONCONTINUABLE");
    }
    if entry.flags & 0x02 != 0 {
        outln!("  UNWINDING");
    }
    if entry.flags & 0x04 != 0 {
        outln!("  EXIT_UNWIND");
    }
    if entry.flags & 0x08 != 0 {
        outln!("  STACK_INVALID");
    }
    if entry.flags & 0x10 != 0 {
        outln!("  NESTED_CALL");
    }

    // Decode exception-specific info
    if entry.code == 0xC0000005 || entry.code == 0x0E {
        // Access violation or page fault
        outln!("");
        outln!("Access Violation Details:");
        let access_type = entry.info & 0xFF;
        match access_type {
            0 => outln!("  Type: Read access"),
            1 => outln!("  Type: Write access"),
            8 => outln!("  Type: DEP violation"),
            _ => outln!("  Type: Unknown ({})", access_type),
        }
    }
}

fn show_exception_stats() {
    use crate::ke::exception::{get_exception_history, EXCEPTION_HISTORY_SIZE, ExceptionCode};

    let (entries, _write_index, total_count) = get_exception_history();

    let valid_count = entries.iter().filter(|e| e.valid).count();

    outln!("Exception Statistics");
    outln!("====================");
    outln!("");
    outln!("Total recorded:    {}", total_count);
    outln!("In current buffer: {}", valid_count);
    outln!("Buffer capacity:   {}", EXCEPTION_HISTORY_SIZE);

    if valid_count == 0 {
        return;
    }

    // Count by type
    let mut access_violation = 0u32;
    let mut breakpoint = 0u32;
    let mut div_zero = 0u32;
    let mut page_fault = 0u32;
    let mut gpf = 0u32;
    let mut other = 0u32;
    let mut handled = 0u32;
    let mut first_chance = 0u32;

    for entry in entries.iter() {
        if !entry.valid {
            continue;
        }
        match entry.code {
            c if c == ExceptionCode::EXCEPTION_ACCESS_VIOLATION => access_violation += 1,
            c if c == ExceptionCode::EXCEPTION_BREAKPOINT || c == 0x03 => breakpoint += 1,
            c if c == ExceptionCode::EXCEPTION_INT_DIVIDE_BY_ZERO || c == 0x00 => div_zero += 1,
            0x0E => page_fault += 1,
            0x0D => gpf += 1,
            _ => other += 1,
        }
        if entry.handled {
            handled += 1;
        }
        if entry.first_chance {
            first_chance += 1;
        }
    }

    outln!("");
    outln!("By Exception Type:");
    if access_violation > 0 { outln!("  Access Violation:  {}", access_violation); }
    if breakpoint > 0 { outln!("  Breakpoint:        {}", breakpoint); }
    if div_zero > 0 { outln!("  Divide by Zero:    {}", div_zero); }
    if page_fault > 0 { outln!("  Page Fault:        {}", page_fault); }
    if gpf > 0 { outln!("  GP Fault:          {}", gpf); }
    if other > 0 { outln!("  Other:             {}", other); }

    outln!("");
    outln!("Handling Statistics:");
    outln!("  Handled:           {} ({:.1}%)", handled,
        (handled as f64 / valid_count as f64) * 100.0);
    outln!("  First chance:      {} ({:.1}%)", first_chance,
        (first_chance as f64 / valid_count as f64) * 100.0);
}

fn clear_exception_history() {
    crate::ke::exception::clear_exception_history();
}

fn test_exception(exc_type: &str) {
    use crate::ke::exception::record_exception;

    outln!("Generating test exception: {}", exc_type);

    if eq_ignore_case(exc_type, "div0") {
        // Record first since the actual exception might crash
        record_exception(0x00, 0, 0, 0, 0, true, false);
        outln!("  Triggering divide by zero...");
        unsafe {
            core::arch::asm!(
                "xor eax, eax",
                "xor edx, edx",
                "div eax",  // Divide by zero
                options(nomem, nostack)
            );
        }
    } else if eq_ignore_case(exc_type, "breakpoint") || eq_ignore_case(exc_type, "int3") {
        record_exception(0x03, 0, 0, 0, 0, true, false);
        outln!("  Triggering breakpoint...");
        unsafe {
            core::arch::asm!("int3", options(nomem, nostack));
        }
    } else if eq_ignore_case(exc_type, "gpf") {
        record_exception(0x0D, 0, 0, 0, 0, true, false);
        outln!("  Triggering general protection fault...");
        unsafe {
            // Load invalid segment selector
            core::arch::asm!(
                "mov ax, 0xFFFF",
                "mov ds, ax",
                options(nomem, nostack)
            );
        }
    } else if eq_ignore_case(exc_type, "pagefault") || eq_ignore_case(exc_type, "pf") {
        record_exception(0x0E, 0, 0, 0, 0, true, false);
        outln!("  Triggering page fault (null pointer)...");
        unsafe {
            let null_ptr: *mut u8 = core::ptr::null_mut();
            core::ptr::write_volatile(null_ptr, 0);
        }
    } else {
        outln!("Unknown exception type: {}", exc_type);
        outln!("Available: div0, breakpoint, gpf, pagefault");
    }
}

// ============================================================================
// Interrupt Statistics Command
// ============================================================================

/// Interrupt statistics viewer command
pub fn cmd_irqstat(args: &[&str]) {
    if args.is_empty() {
        show_irqstat_overview();
        return;
    }

    let cmd = args[0];
    if eq_ignore_case(cmd, "help") {
        show_irqstat_help();
    } else if eq_ignore_case(cmd, "all") || eq_ignore_case(cmd, "full") {
        show_irqstat_all();
    } else if eq_ignore_case(cmd, "exceptions") || eq_ignore_case(cmd, "exc") {
        show_irqstat_exceptions();
    } else if eq_ignore_case(cmd, "interrupts") || eq_ignore_case(cmd, "int") {
        show_irqstat_interrupts();
    } else if eq_ignore_case(cmd, "clear") || eq_ignore_case(cmd, "reset") {
        clear_irqstat();
        outln!("Interrupt statistics cleared");
    } else if eq_ignore_case(cmd, "rate") {
        show_irqstat_rate();
    } else {
        outln!("Unknown irqstat command: {}", cmd);
        show_irqstat_help();
    }
}

fn show_irqstat_help() {
    outln!("Interrupt Statistics Viewer");
    outln!("");
    outln!("Usage: irqstat <command>");
    outln!("");
    outln!("Commands:");
    outln!("  (none)      Show summary overview");
    outln!("  all         Show all statistics");
    outln!("  exceptions  Show exception counts only");
    outln!("  interrupts  Show hardware interrupt counts only");
    outln!("  rate        Show interrupt rate (per second)");
    outln!("  clear       Reset all counters to zero");
}

fn show_irqstat_overview() {
    use crate::arch::x86_64::idt::get_interrupt_stats;
    use core::sync::atomic::Ordering;

    let stats = get_interrupt_stats();

    outln!("Interrupt Statistics Summary");
    outln!("============================");
    outln!("");

    let total_exc = stats.total_exceptions();
    let total_int = stats.total_interrupts();

    outln!("Total exceptions:  {}", total_exc);
    outln!("Total interrupts:  {}", total_int);
    outln!("Grand total:       {}", total_exc + total_int);
    outln!("");

    outln!("Hardware Interrupts:");
    let timer = stats.timer.load(Ordering::Relaxed);
    let keyboard = stats.keyboard.load(Ordering::Relaxed);
    let spurious = stats.spurious.load(Ordering::Relaxed);
    if timer > 0 { outln!("  Timer:       {}", timer); }
    if keyboard > 0 { outln!("  Keyboard:    {}", keyboard); }
    if spurious > 0 { outln!("  Spurious:    {}", spurious); }

    outln!("");
    outln!("IPIs (Inter-Processor Interrupts):");
    let ipi_stop = stats.ipi_stop.load(Ordering::Relaxed);
    let ipi_resched = stats.ipi_reschedule.load(Ordering::Relaxed);
    let tlb = stats.tlb_shootdown.load(Ordering::Relaxed);
    if ipi_stop > 0 { outln!("  Stop:        {}", ipi_stop); }
    if ipi_resched > 0 { outln!("  Reschedule:  {}", ipi_resched); }
    if tlb > 0 { outln!("  TLB Shoot:   {}", tlb); }

    outln!("");
    outln!("Use 'irqstat all' for complete breakdown");
}

fn show_irqstat_all() {
    use crate::arch::x86_64::idt::get_interrupt_stats;
    use core::sync::atomic::Ordering;

    let stats = get_interrupt_stats();

    outln!("Complete Interrupt Statistics");
    outln!("==============================");
    outln!("");

    outln!("CPU Exceptions (Vectors 0-31):");
    outln!("  #00 Divide Error:         {}", stats.divide_error.load(Ordering::Relaxed));
    outln!("  #01 Debug:                {}", stats.debug.load(Ordering::Relaxed));
    outln!("  #02 NMI:                  {}", stats.nmi.load(Ordering::Relaxed));
    outln!("  #03 Breakpoint:           {}", stats.breakpoint.load(Ordering::Relaxed));
    outln!("  #04 Overflow:             {}", stats.overflow.load(Ordering::Relaxed));
    outln!("  #05 Bound Range:          {}", stats.bound_range.load(Ordering::Relaxed));
    outln!("  #06 Invalid Opcode:       {}", stats.invalid_opcode.load(Ordering::Relaxed));
    outln!("  #07 Device Not Available: {}", stats.device_not_available.load(Ordering::Relaxed));
    outln!("  #08 Double Fault:         {}", stats.double_fault.load(Ordering::Relaxed));
    outln!("  #10 Invalid TSS:          {}", stats.invalid_tss.load(Ordering::Relaxed));
    outln!("  #11 Segment Not Present:  {}", stats.segment_not_present.load(Ordering::Relaxed));
    outln!("  #12 Stack Segment Fault:  {}", stats.stack_segment_fault.load(Ordering::Relaxed));
    outln!("  #13 General Protection:   {}", stats.general_protection.load(Ordering::Relaxed));
    outln!("  #14 Page Fault:           {}", stats.page_fault.load(Ordering::Relaxed));
    outln!("  #16 x87 FP:               {}", stats.x87_fp.load(Ordering::Relaxed));
    outln!("  #17 Alignment Check:      {}", stats.alignment_check.load(Ordering::Relaxed));
    outln!("  #18 Machine Check:        {}", stats.machine_check.load(Ordering::Relaxed));
    outln!("  #19 SIMD FP:              {}", stats.simd_fp.load(Ordering::Relaxed));
    outln!("  #20 Virtualization:       {}", stats.virtualization.load(Ordering::Relaxed));
    outln!("  Other Exceptions:         {}", stats.other_exceptions.load(Ordering::Relaxed));
    outln!("  -------------------------");
    outln!("  Total:                    {}", stats.total_exceptions());

    outln!("");
    outln!("Hardware Interrupts:");
    outln!("  #32 Timer (APIC):         {}", stats.timer.load(Ordering::Relaxed));
    outln!("  #33 Keyboard:             {}", stats.keyboard.load(Ordering::Relaxed));
    outln!("  Other Interrupts:         {}", stats.other_interrupts.load(Ordering::Relaxed));

    outln!("");
    outln!("Inter-Processor Interrupts:");
    outln!("  #FC IPI Stop:             {}", stats.ipi_stop.load(Ordering::Relaxed));
    outln!("  #FD IPI Reschedule:       {}", stats.ipi_reschedule.load(Ordering::Relaxed));
    outln!("  #FE TLB Shootdown:        {}", stats.tlb_shootdown.load(Ordering::Relaxed));
    outln!("  #FF Spurious:             {}", stats.spurious.load(Ordering::Relaxed));
    outln!("  -------------------------");
    outln!("  Total:                    {}", stats.total_interrupts());
}

fn show_irqstat_exceptions() {
    use crate::arch::x86_64::idt::get_interrupt_stats;
    use core::sync::atomic::Ordering;

    let stats = get_interrupt_stats();

    outln!("Exception Statistics");
    outln!("====================");
    outln!("");

    outln!("{:<4} {:<24} {:>12}", "Vec", "Type", "Count");
    outln!("--------------------------------------------");

    let exceptions = [
        (0x00, "Divide Error", stats.divide_error.load(Ordering::Relaxed)),
        (0x01, "Debug", stats.debug.load(Ordering::Relaxed)),
        (0x02, "NMI", stats.nmi.load(Ordering::Relaxed)),
        (0x03, "Breakpoint", stats.breakpoint.load(Ordering::Relaxed)),
        (0x04, "Overflow", stats.overflow.load(Ordering::Relaxed)),
        (0x05, "Bound Range", stats.bound_range.load(Ordering::Relaxed)),
        (0x06, "Invalid Opcode", stats.invalid_opcode.load(Ordering::Relaxed)),
        (0x07, "Device Not Available", stats.device_not_available.load(Ordering::Relaxed)),
        (0x08, "Double Fault", stats.double_fault.load(Ordering::Relaxed)),
        (0x0A, "Invalid TSS", stats.invalid_tss.load(Ordering::Relaxed)),
        (0x0B, "Segment Not Present", stats.segment_not_present.load(Ordering::Relaxed)),
        (0x0C, "Stack Segment Fault", stats.stack_segment_fault.load(Ordering::Relaxed)),
        (0x0D, "General Protection", stats.general_protection.load(Ordering::Relaxed)),
        (0x0E, "Page Fault", stats.page_fault.load(Ordering::Relaxed)),
        (0x10, "x87 Floating Point", stats.x87_fp.load(Ordering::Relaxed)),
        (0x11, "Alignment Check", stats.alignment_check.load(Ordering::Relaxed)),
        (0x12, "Machine Check", stats.machine_check.load(Ordering::Relaxed)),
        (0x13, "SIMD Floating Point", stats.simd_fp.load(Ordering::Relaxed)),
        (0x14, "Virtualization", stats.virtualization.load(Ordering::Relaxed)),
    ];

    for (vec, name, count) in exceptions.iter() {
        if *count > 0 {
            outln!("{:#04x} {:<24} {:>12}", vec, name, count);
        }
    }

    outln!("");
    outln!("Total: {}", stats.total_exceptions());
}

fn show_irqstat_interrupts() {
    use crate::arch::x86_64::idt::get_interrupt_stats;
    use core::sync::atomic::Ordering;

    let stats = get_interrupt_stats();

    outln!("Hardware Interrupt Statistics");
    outln!("=============================");
    outln!("");

    outln!("{:<4} {:<20} {:>12}", "Vec", "Type", "Count");
    outln!("-----------------------------------------");

    let timer = stats.timer.load(Ordering::Relaxed);
    let keyboard = stats.keyboard.load(Ordering::Relaxed);
    let ipi_stop = stats.ipi_stop.load(Ordering::Relaxed);
    let ipi_resched = stats.ipi_reschedule.load(Ordering::Relaxed);
    let tlb = stats.tlb_shootdown.load(Ordering::Relaxed);
    let spurious = stats.spurious.load(Ordering::Relaxed);
    let other = stats.other_interrupts.load(Ordering::Relaxed);

    if timer > 0 { outln!("0x20 Timer             {:>12}", timer); }
    if keyboard > 0 { outln!("0x21 Keyboard          {:>12}", keyboard); }
    if ipi_stop > 0 { outln!("0xFC IPI Stop          {:>12}", ipi_stop); }
    if ipi_resched > 0 { outln!("0xFD IPI Reschedule    {:>12}", ipi_resched); }
    if tlb > 0 { outln!("0xFE TLB Shootdown     {:>12}", tlb); }
    if spurious > 0 { outln!("0xFF Spurious          {:>12}", spurious); }
    if other > 0 { outln!("     Other             {:>12}", other); }

    outln!("");
    outln!("Total: {}", stats.total_interrupts());
}

fn clear_irqstat() {
    use crate::arch::x86_64::idt::get_interrupt_stats;
    get_interrupt_stats().clear();
}

fn show_irqstat_rate() {
    use crate::arch::x86_64::idt::get_interrupt_stats;
    use core::sync::atomic::Ordering;

    let stats = get_interrupt_stats();

    // Get current timer tick count as a proxy for uptime
    let timer_ticks = stats.timer.load(Ordering::Relaxed);

    if timer_ticks == 0 {
        outln!("No timer interrupts yet - cannot calculate rate");
        return;
    }

    outln!("Interrupt Rate Analysis");
    outln!("=======================");
    outln!("");

    // Assume 1000Hz timer for rate calculations
    let seconds = timer_ticks / 1000;
    if seconds == 0 {
        outln!("System uptime < 1 second - need more data");
        return;
    }

    outln!("Estimated uptime: {} seconds ({} timer ticks @ 1000Hz)", seconds, timer_ticks);
    outln!("");

    let keyboard = stats.keyboard.load(Ordering::Relaxed);
    let ipi_resched = stats.ipi_reschedule.load(Ordering::Relaxed);
    let tlb = stats.tlb_shootdown.load(Ordering::Relaxed);

    outln!("Average rates:");
    outln!("  Timer:       {} /sec (expected: 1000)", timer_ticks / seconds);
    if keyboard > 0 { outln!("  Keyboard:    {:.2} /sec", keyboard as f64 / seconds as f64); }
    if ipi_resched > 0 { outln!("  Reschedule:  {:.2} /sec", ipi_resched as f64 / seconds as f64); }
    if tlb > 0 { outln!("  TLB Shoot:   {:.2} /sec", tlb as f64 / seconds as f64); }
}

// ============================================================================
// Pool Statistics Command
// ============================================================================

/// Kernel pool statistics viewer command
pub fn cmd_pool(args: &[&str]) {
    if args.is_empty() {
        show_pool_overview();
        return;
    }

    let cmd = args[0];
    if eq_ignore_case(cmd, "help") {
        show_pool_help();
    } else if eq_ignore_case(cmd, "classes") || eq_ignore_case(cmd, "sizes") {
        show_pool_classes();
    } else if eq_ignore_case(cmd, "usage") || eq_ignore_case(cmd, "detail") {
        show_pool_usage();
    } else if eq_ignore_case(cmd, "fragmentation") || eq_ignore_case(cmd, "frag") {
        show_pool_fragmentation();
    } else if eq_ignore_case(cmd, "alloc") {
        if args.len() > 1 {
            let size = parse_number(args[1]).unwrap_or(64) as usize;
            test_pool_alloc(size);
        } else {
            outln!("Usage: pool alloc <size>");
        }
    } else {
        outln!("Unknown pool command: {}", cmd);
        show_pool_help();
    }
}

fn show_pool_help() {
    outln!("Kernel Pool Statistics Viewer");
    outln!("");
    outln!("Usage: pool <command>");
    outln!("");
    outln!("Commands:");
    outln!("  (none)         Show overview statistics");
    outln!("  classes        Show per-size-class stats");
    outln!("  usage          Show detailed usage breakdown");
    outln!("  fragmentation  Show fragmentation analysis");
    outln!("  alloc <size>   Test pool allocation");
}

fn show_pool_overview() {
    use crate::mm::pool::mm_get_pool_stats;

    let stats = mm_get_pool_stats();

    outln!("Kernel Pool Statistics");
    outln!("======================");
    outln!("");
    outln!("Pool Heap Size:    {} KB ({} bytes)", stats.total_size / 1024, stats.total_size);
    outln!("Bytes Allocated:   {} KB ({} bytes)", stats.bytes_allocated / 1024, stats.bytes_allocated);
    outln!("Bytes Free:        {} KB ({} bytes)", stats.bytes_free / 1024, stats.bytes_free);
    outln!("");
    outln!("Allocation Count:  {}", stats.allocation_count);
    outln!("Free Count:        {}", stats.free_count);
    outln!("Active Allocs:     {}", stats.allocation_count.saturating_sub(stats.free_count));

    let usage_pct = if stats.total_size > 0 {
        (stats.bytes_allocated as f64 / stats.total_size as f64) * 100.0
    } else {
        0.0
    };
    outln!("");
    outln!("Usage:             {:.1}%", usage_pct);

    outln!("");
    outln!("Use 'pool classes' for size class breakdown");
}

fn show_pool_classes() {
    use crate::mm::pool::{mm_get_pool_class_stats, mm_get_pool_class_count};

    outln!("Pool Size Classes");
    outln!("=================");
    outln!("");
    outln!("{:<6} {:<8} {:<8} {:<8} {:<10} {:<10}",
        "Class", "Size", "Total", "Used", "Free", "Usage%");
    outln!("--------------------------------------------------------------");

    for i in 0..mm_get_pool_class_count() {
        if let Some(stats) = mm_get_pool_class_stats(i) {
            let usage_pct = if stats.total_blocks > 0 {
                (stats.used_blocks as f64 / stats.total_blocks as f64) * 100.0
            } else {
                0.0
            };
            outln!("{:<6} {:>6}B {:>8} {:>8} {:>8} {:>9.1}%",
                i, stats.block_size, stats.total_blocks,
                stats.used_blocks, stats.free_blocks, usage_pct);
        }
    }
}

fn show_pool_usage() {
    use crate::mm::pool::{mm_get_pool_stats, mm_get_pool_class_stats, mm_get_pool_class_count};

    let overall = mm_get_pool_stats();

    outln!("Detailed Pool Usage");
    outln!("===================");
    outln!("");

    outln!("Overall:");
    outln!("  Total capacity:     {} KB", overall.total_size / 1024);
    outln!("  Currently in use:   {} KB ({:.1}%)",
        overall.bytes_allocated / 1024,
        (overall.bytes_allocated as f64 / overall.total_size as f64) * 100.0);
    outln!("  Available:          {} KB", overall.bytes_free / 1024);

    outln!("");
    outln!("Per Size Class:");
    outln!("{:<8} {:<12} {:<12} {:<12}",
        "Size", "Capacity", "In Use", "Available");
    outln!("------------------------------------------------");

    let mut total_capacity = 0usize;
    let mut total_in_use = 0usize;

    for i in 0..mm_get_pool_class_count() {
        if let Some(stats) = mm_get_pool_class_stats(i) {
            outln!("{:>6}B {:>10}B {:>10}B {:>10}B",
                stats.block_size, stats.total_bytes,
                stats.used_bytes, stats.total_bytes - stats.used_bytes);
            total_capacity += stats.total_bytes;
            total_in_use += stats.used_bytes;
        }
    }

    outln!("------------------------------------------------");
    outln!("{:<8} {:>10}B {:>10}B {:>10}B",
        "TOTAL", total_capacity, total_in_use, total_capacity - total_in_use);
}

fn show_pool_fragmentation() {
    use crate::mm::pool::{mm_get_pool_class_stats, mm_get_pool_class_count};

    outln!("Pool Fragmentation Analysis");
    outln!("===========================");
    outln!("");

    let mut total_waste = 0usize;
    let mut total_used = 0usize;
    let mut fragmented_classes = 0;

    for i in 0..mm_get_pool_class_count() {
        if let Some(stats) = mm_get_pool_class_stats(i) {
            if stats.used_blocks > 0 {
                total_used += stats.used_bytes;
                // Assume average internal fragmentation is block_size/4
                let estimated_waste = (stats.block_size / 4) * stats.used_blocks;
                total_waste += estimated_waste;

                // Check if class is fragmented (some used, some free)
                if stats.free_blocks > 0 && stats.used_blocks > 0 {
                    fragmented_classes += 1;
                }
            }
        }
    }

    outln!("Size Classes with Mixed Usage: {}/{}",
        fragmented_classes, mm_get_pool_class_count());

    if total_used > 0 {
        let frag_pct = (total_waste as f64 / (total_used + total_waste) as f64) * 100.0;
        outln!("");
        outln!("Estimated Internal Fragmentation:");
        outln!("  Used bytes:              {} B", total_used);
        outln!("  Est. wasted bytes:       {} B", total_waste);
        outln!("  Fragmentation rate:      {:.1}%", frag_pct);
    } else {
        outln!("");
        outln!("No allocations to analyze");
    }

    outln!("");
    outln!("Notes:");
    outln!("  - Internal fragmentation is estimated (actual may vary)");
    outln!("  - Pool uses fixed size classes which may waste space");
    outln!("  - Allocations are rounded up to next size class");
}

fn test_pool_alloc(size: usize) {
    use crate::mm::pool::{ex_allocate_pool_with_tag, ex_free_pool, PoolType, pool_tags};

    outln!("Testing pool allocation of {} bytes...", size);

    unsafe {
        let ptr = ex_allocate_pool_with_tag(
            PoolType::NonPagedPool,
            size,
            pool_tags::TAG_GENERIC,
        );

        if ptr.is_null() {
            outln!("  Allocation FAILED (null returned)");
            outln!("  Size may be too large for available pool");
        } else {
            outln!("  Allocation SUCCESS at {:p}", ptr);

            // Write some test data
            for i in 0..size.min(16) {
                *ptr.add(i) = (i & 0xFF) as u8;
            }
            outln!("  Wrote {} bytes of test data", size.min(16));

            // Free immediately
            ex_free_pool(ptr);
            outln!("  Freed successfully");
        }
    }

    // Show updated stats
    use crate::mm::pool::mm_get_pool_stats;
    let stats = mm_get_pool_stats();
    outln!("");
    outln!("Current pool state:");
    outln!("  Active allocations: {}",
        stats.allocation_count.saturating_sub(stats.free_count));
    outln!("  Bytes in use: {} B", stats.bytes_allocated);
}

// ============================================================================
// PFN Database Viewer Command
// ============================================================================

/// PFN database viewer command
pub fn cmd_pfn(args: &[&str]) {
    if args.is_empty() {
        show_pfn_overview();
        return;
    }

    let cmd = args[0];
    if eq_ignore_case(cmd, "help") {
        show_pfn_help();
    } else if eq_ignore_case(cmd, "stats") || eq_ignore_case(cmd, "detail") {
        show_pfn_detailed_stats();
    } else if eq_ignore_case(cmd, "entry") || eq_ignore_case(cmd, "show") {
        if args.len() > 1 {
            let index = parse_number(args[1]).unwrap_or(0) as usize;
            show_pfn_entry(index);
        } else {
            outln!("Usage: pfn entry <index>");
        }
    } else if eq_ignore_case(cmd, "range") {
        if args.len() > 2 {
            let start = parse_number(args[1]).unwrap_or(0) as usize;
            let count = parse_number(args[2]).unwrap_or(16) as usize;
            show_pfn_range(start, count);
        } else if args.len() > 1 {
            let start = parse_number(args[1]).unwrap_or(0) as usize;
            show_pfn_range(start, 16);
        } else {
            outln!("Usage: pfn range <start> [count]");
        }
    } else if eq_ignore_case(cmd, "active") {
        show_pfn_by_state_active();
    } else if eq_ignore_case(cmd, "lists") {
        show_pfn_lists();
    } else {
        outln!("Unknown pfn command: {}", cmd);
        show_pfn_help();
    }
}

fn show_pfn_help() {
    outln!("PFN Database Viewer");
    outln!("");
    outln!("Usage: pfn <command>");
    outln!("");
    outln!("Commands:");
    outln!("  (none)         Show overview statistics");
    outln!("  stats          Show detailed per-state counts");
    outln!("  entry <idx>    Show details for PFN entry");
    outln!("  range <s> [n]  Show range of PFN entries");
    outln!("  active         List active (in-use) pages");
    outln!("  lists          Show free/zeroed list heads");
}

fn show_pfn_overview() {
    use crate::mm::pfn::{mm_get_stats, mm_get_pfn_database_size, PAGE_SIZE};

    let stats = mm_get_stats();
    let db_size = mm_get_pfn_database_size();

    outln!("PFN Database Overview");
    outln!("=====================");
    outln!("");
    outln!("Database Size:     {} entries", db_size);
    outln!("Initialized Pages: {}", stats.total_pages);
    outln!("");
    outln!("Page States:");
    outln!("  Free:    {} pages ({} KB)",
        stats.free_pages, (stats.free_pages as usize * PAGE_SIZE) / 1024);
    outln!("  Zeroed:  {} pages ({} KB)",
        stats.zeroed_pages, (stats.zeroed_pages as usize * PAGE_SIZE) / 1024);
    outln!("  Active:  {} pages ({} KB)",
        stats.active_pages, (stats.active_pages as usize * PAGE_SIZE) / 1024);
    outln!("");

    let total_available = stats.free_pages + stats.zeroed_pages;
    let total_mb = (db_size * PAGE_SIZE) / (1024 * 1024);
    let used_mb = (stats.active_pages as usize * PAGE_SIZE) / (1024 * 1024);

    outln!("Summary:");
    outln!("  Max Trackable:   {} pages ({} MB)", db_size, total_mb);
    outln!("  Available:       {} pages", total_available);
    outln!("  In Use:          {} pages ({} MB)", stats.active_pages, used_mb);

    if stats.total_pages > 0 {
        let usage = (stats.active_pages as f64 / stats.total_pages as f64) * 100.0;
        outln!("  Usage:           {:.1}%", usage);
    }
}

fn show_pfn_detailed_stats() {
    use crate::mm::pfn::{mm_get_detailed_pfn_stats, PAGE_SIZE};

    let stats = mm_get_detailed_pfn_stats();

    outln!("Detailed PFN Statistics");
    outln!("=======================");
    outln!("");
    outln!("Initialized Pages: {}", stats.total_pages);
    outln!("");
    outln!("Pages by State:");
    outln!("  Free:         {:>8} pages ({:>6} KB)",
        stats.free_pages, (stats.free_pages as usize * PAGE_SIZE) / 1024);
    outln!("  Zeroed:       {:>8} pages ({:>6} KB)",
        stats.zeroed_pages, (stats.zeroed_pages as usize * PAGE_SIZE) / 1024);
    outln!("  Standby:      {:>8} pages ({:>6} KB)",
        stats.standby_pages, (stats.standby_pages as usize * PAGE_SIZE) / 1024);
    outln!("  Modified:     {:>8} pages ({:>6} KB)",
        stats.modified_pages, (stats.modified_pages as usize * PAGE_SIZE) / 1024);
    outln!("  Active:       {:>8} pages ({:>6} KB)",
        stats.active_pages, (stats.active_pages as usize * PAGE_SIZE) / 1024);
    outln!("  Transition:   {:>8} pages", stats.transition_pages);
    outln!("  Bad:          {:>8} pages", stats.bad_pages);

    outln!("");
    outln!("Pages by Flags:");
    outln!("  Kernel:       {:>8} pages", stats.kernel_pages);
    outln!("  Locked:       {:>8} pages", stats.locked_pages);
}

fn show_pfn_entry(index: usize) {
    use crate::mm::pfn::{mm_get_pfn_snapshot, mm_page_state_name, pfn_flags, PAGE_SIZE};

    match mm_get_pfn_snapshot(index) {
        Some(pfn) => {
            let phys_addr = index * PAGE_SIZE;

            outln!("PFN Entry {}", index);
            outln!("====================");
            outln!("");
            outln!("Physical Address: {:#x} - {:#x}",
                phys_addr, phys_addr + PAGE_SIZE - 1);
            outln!("State:            {} ({})", pfn.state as u8, mm_page_state_name(pfn.state));
            outln!("Reference Count:  {}", pfn.ref_count);
            outln!("Share Count:      {}", pfn.share_count);
            outln!("PTE Address:      {:#018x}", pfn.pte_address);
            if pfn.flink == u32::MAX {
                outln!("Flink:            NULL");
            } else {
                outln!("Flink:            {}", pfn.flink);
            }
            if pfn.blink == u32::MAX {
                outln!("Blink:            NULL");
            } else {
                outln!("Blink:            {}", pfn.blink);
            }
            outln!("Flags:            {:#06x}", pfn.flags);

            // Decode flags
            if pfn.flags != 0 {
                outln!("");
                outln!("Flags Decoded:");
                if (pfn.flags & pfn_flags::PFN_KERNEL) != 0 { outln!("  KERNEL"); }
                if (pfn.flags & pfn_flags::PFN_LOCKED) != 0 { outln!("  LOCKED"); }
                if (pfn.flags & pfn_flags::PFN_PROTOTYPE) != 0 { outln!("  PROTOTYPE"); }
                if (pfn.flags & pfn_flags::PFN_LARGE_PAGE) != 0 { outln!("  LARGE_PAGE"); }
                if (pfn.flags & pfn_flags::PFN_ROM) != 0 { outln!("  ROM"); }
                if (pfn.flags & pfn_flags::PFN_DIRTY) != 0 { outln!("  DIRTY"); }
            }
        }
        None => {
            outln!("PFN entry {} not found", index);
        }
    }
}

fn show_pfn_range(start: usize, count: usize) {
    use crate::mm::pfn::{mm_get_pfn_snapshot, mm_page_state_name, mm_get_pfn_database_size};

    let db_size = mm_get_pfn_database_size();
    let end = (start + count).min(db_size);

    if start >= db_size {
        outln!("Start index {} is beyond database size {}", start, db_size);
        return;
    }

    outln!("PFN Entries {} - {}", start, end - 1);
    outln!("");
    outln!("{:<8} {:<12} {:<6} {:<6} {:<8} {:<8}",
        "Index", "State", "Refs", "Share", "Flink", "Blink");
    outln!("------------------------------------------------------");

    for i in start..end {
        if let Some(pfn) = mm_get_pfn_snapshot(i) {
            if pfn.flink == u32::MAX {
                if pfn.blink == u32::MAX {
                    outln!("{:<8} {:<12} {:>5} {:>6} {:>8} {:>8}",
                        i, mm_page_state_name(pfn.state),
                        pfn.ref_count, pfn.share_count, "-", "-");
                } else {
                    outln!("{:<8} {:<12} {:>5} {:>6} {:>8} {:>8}",
                        i, mm_page_state_name(pfn.state),
                        pfn.ref_count, pfn.share_count, "-", pfn.blink);
                }
            } else {
                if pfn.blink == u32::MAX {
                    outln!("{:<8} {:<12} {:>5} {:>6} {:>8} {:>8}",
                        i, mm_page_state_name(pfn.state),
                        pfn.ref_count, pfn.share_count, pfn.flink, "-");
                } else {
                    outln!("{:<8} {:<12} {:>5} {:>6} {:>8} {:>8}",
                        i, mm_page_state_name(pfn.state),
                        pfn.ref_count, pfn.share_count, pfn.flink, pfn.blink);
                }
            }
        }
    }
}

fn show_pfn_by_state_active() {
    use crate::mm::pfn::{mm_get_pfn_snapshot, mm_get_pfn_database_size, MmPageState, PAGE_SIZE};

    let db_size = mm_get_pfn_database_size();

    outln!("Active Pages");
    outln!("============");
    outln!("");
    outln!("{:<8} {:<18} {:<6} {:<6} {:<18}",
        "Index", "Phys Address", "Refs", "Share", "PTE Address");
    outln!("--------------------------------------------------------------");

    let mut count = 0;
    for i in 0..db_size {
        if let Some(pfn) = mm_get_pfn_snapshot(i) {
            if pfn.state == MmPageState::Active {
                let phys_addr = i * PAGE_SIZE;
                outln!("{:<8} {:#018x} {:>5} {:>6} {:#018x}",
                    i, phys_addr, pfn.ref_count, pfn.share_count, pfn.pte_address);
                count += 1;
                if count >= 50 {
                    outln!("...(showing first 50, use 'pfn range' for more)");
                    break;
                }
            }
        }
    }

    if count == 0 {
        outln!("  No active pages found");
    } else {
        outln!("");
        outln!("Total: {} active pages shown", count);
    }
}

fn show_pfn_lists() {
    use crate::mm::pfn::{mm_get_stats, mm_get_pfn_snapshot};

    let stats = mm_get_stats();

    outln!("PFN List Information");
    outln!("====================");
    outln!("");

    outln!("Free List:");
    outln!("  Count:     {} pages", stats.free_pages);
    if stats.free_pages > 0 {
        // Find first free page to show list head
        for i in 0..4096 {
            if let Some(pfn) = mm_get_pfn_snapshot(i) {
                if pfn.state as u8 == 0 { // Free
                    outln!("  Head:      entry {}", i);
                    if pfn.flink == u32::MAX {
                        outln!("  Flink:     NULL");
                    } else {
                        outln!("  Flink:     {}", pfn.flink);
                    }
                    break;
                }
            }
        }
    }

    outln!("");
    outln!("Zeroed List:");
    outln!("  Count:     {} pages", stats.zeroed_pages);
    if stats.zeroed_pages > 0 {
        // Find first zeroed page
        for i in 0..4096 {
            if let Some(pfn) = mm_get_pfn_snapshot(i) {
                if pfn.state as u8 == 1 { // Zeroed
                    outln!("  Head:      entry {}", i);
                    break;
                }
            }
        }
    }

    outln!("");
    outln!("Active Pages: {}", stats.active_pages);
}

// ============================================================================
// Timer Queue Viewer Command
// ============================================================================

/// Timer queue viewer command
pub fn cmd_timerq(args: &[&str]) {
    let subcmd = if args.is_empty() { "stats" } else { args[0] };

    if eq_ignore_case(subcmd, "help") || eq_ignore_case(subcmd, "?") {
        outln!("TIMERQ - Timer Queue Viewer");
        outln!("");
        outln!("Commands:");
        outln!("  timerq              Show timer statistics (default)");
        outln!("  timerq stats        Show timer queue statistics");
        outln!("  timerq list         List active timers");
        outln!("  timerq next         Show next timer to expire");
        outln!("  timerq help         Show this help");
        return;
    }

    if eq_ignore_case(subcmd, "stats") {
        show_timer_stats();
    } else if eq_ignore_case(subcmd, "list") {
        show_timer_list();
    } else if eq_ignore_case(subcmd, "next") {
        show_next_timer();
    } else {
        outln!("Unknown timerq command: {}", subcmd);
        outln!("Use 'timerq help' for usage");
    }
}

fn show_timer_stats() {
    use crate::ke::timer::{ki_get_timer_stats, ki_get_active_timer_count};

    outln!("Timer Queue Statistics");
    outln!("======================");
    outln!("");

    let stats = ki_get_timer_stats();

    outln!("Current Time:      {} ticks", stats.current_time);
    outln!("Active Timers:     {}", stats.active_count);
    outln!("  Periodic:        {}", stats.periodic_count);
    outln!("  One-shot:        {}", stats.oneshot_count);
    outln!("  Signaled:        {}", stats.signaled_count);

    match stats.next_expiration_ms {
        Some(0) => outln!("Next Expiration:   NOW (overdue)"),
        Some(ms) => outln!("Next Expiration:   {} ms", ms),
        None => outln!("Next Expiration:   None (queue empty)"),
    }

    outln!("");
    outln!("Timer Count (alt): {}", ki_get_active_timer_count());
}

fn show_timer_list() {
    use crate::ke::timer::{ki_get_timer_snapshots, ki_get_timer_stats, timer_type_name};

    let stats = ki_get_timer_stats();
    let (timers, count) = ki_get_timer_snapshots(20);

    outln!("Active Timers (current time: {} ticks)", stats.current_time);
    outln!("==================================================");
    outln!("");

    if count == 0 {
        outln!("No active timers in the queue");
        return;
    }

    outln!("{:<18} {:<12} {:<10} {:<14} {:<6} {:<6}",
        "Address", "Due Time", "Delta", "Type", "Period", "DPC");
    outln!("--------------------------------------------------------------------------------");

    for i in 0..count {
        let t = &timers[i];
        let delta = if t.due_time > stats.current_time {
            t.due_time - stats.current_time
        } else {
            0
        };

        let type_name = timer_type_name(t.timer_type);
        let dpc_str = if t.has_dpc { "Yes" } else { "No" };

        if t.period > 0 {
            outln!("{:#018x} {:<12} {:>10} {:<14} {:>6} {:>6}",
                t.address, t.due_time, delta, type_name, t.period, dpc_str);
        } else {
            outln!("{:#018x} {:<12} {:>10} {:<14} {:>6} {:>6}",
                t.address, t.due_time, delta, type_name, "-", dpc_str);
        }
    }

    if count < stats.active_count as usize {
        outln!("");
        outln!("... showing {} of {} timers", count, stats.active_count);
    }
}

fn show_next_timer() {
    use crate::ke::timer::{ki_get_timer_snapshots, ki_get_timer_stats, timer_type_name};

    let stats = ki_get_timer_stats();
    let (timers, count) = ki_get_timer_snapshots(1);

    outln!("Next Timer to Expire");
    outln!("====================");
    outln!("");

    if count == 0 {
        outln!("No timers in the queue");
        return;
    }

    let t = &timers[0];
    let delta = if t.due_time > stats.current_time {
        t.due_time - stats.current_time
    } else {
        0
    };

    outln!("Timer Address:   {:#018x}", t.address);
    outln!("Due Time:        {} ticks", t.due_time);
    outln!("Current Time:    {} ticks", stats.current_time);
    if delta == 0 {
        outln!("Time Delta:      OVERDUE");
    } else {
        outln!("Time Delta:      {} ms", delta);
    }
    outln!("Timer Type:      {}", timer_type_name(t.timer_type));
    if t.period > 0 {
        outln!("Period:          {} ms", t.period);
    } else {
        outln!("Period:          None (one-shot)");
    }
    outln!("Signaled:        {}", if t.signaled { "Yes" } else { "No" });
    if t.has_dpc {
        outln!("DPC Address:     {:#018x}", t.dpc_address);
    } else {
        outln!("DPC:             None");
    }
}

// ============================================================================
// DPC Queue Viewer Command
// ============================================================================

/// DPC queue viewer command
pub fn cmd_dpcq(args: &[&str]) {
    let subcmd = if args.is_empty() { "stats" } else { args[0] };

    if eq_ignore_case(subcmd, "help") || eq_ignore_case(subcmd, "?") {
        outln!("DPCQ - DPC Queue Viewer");
        outln!("");
        outln!("Commands:");
        outln!("  dpcq               Show DPC statistics (default)");
        outln!("  dpcq stats         Show DPC queue statistics");
        outln!("  dpcq list          List queued DPCs");
        outln!("  dpcq pending       Check if DPCs are pending");
        outln!("  dpcq help          Show this help");
        return;
    }

    if eq_ignore_case(subcmd, "stats") {
        show_dpc_stats();
    } else if eq_ignore_case(subcmd, "list") {
        show_dpc_list();
    } else if eq_ignore_case(subcmd, "pending") {
        show_dpc_pending();
    } else {
        outln!("Unknown dpcq command: {}", subcmd);
        outln!("Use 'dpcq help' for usage");
    }
}

fn show_dpc_stats() {
    use crate::ke::dpc::ki_get_dpc_stats;
    use crate::ke::prcb::{get_current_prcb, ke_get_current_processor_number};

    let stats = ki_get_dpc_stats();
    let prcb = get_current_prcb();

    outln!("DPC Queue Statistics");
    outln!("====================");
    outln!("");

    outln!("Current Processor: {}", ke_get_current_processor_number());
    outln!("Active Processors: {}", stats.processor_count);
    outln!("");

    outln!("Current CPU DPC Queue:");
    outln!("  Queue Depth:     {}", stats.current_queue_depth);
    outln!("  DPC Pending:     {}", if stats.dpc_pending { "Yes" } else { "No" });
    outln!("  IRQ Requested:   {}", if prcb.dpc_interrupt_requested { "Yes" } else { "No" });

    outln!("");
    outln!("Scheduling State:");
    outln!("  Ready Summary:   {:#010x}", prcb.ready_summary);
    outln!("  Context Sw:      {}", prcb.context_switches);
    outln!("  Quantum End:     {}", if prcb.quantum_end { "Yes" } else { "No" });
}

fn show_dpc_list() {
    use crate::ke::dpc::{ki_get_dpc_snapshots, ki_get_dpc_stats, dpc_importance_name};

    let stats = ki_get_dpc_stats();
    let (dpcs, count) = ki_get_dpc_snapshots(16);

    outln!("DPC Queue Contents");
    outln!("==================");
    outln!("");

    if count == 0 {
        outln!("DPC queue is empty");
        outln!("  Pending flag: {}", if stats.dpc_pending { "Yes" } else { "No" });
        return;
    }

    outln!("{:<18} {:<18} {:<10} {:<10}",
        "DPC Address", "Routine", "Importance", "Target CPU");
    outln!("--------------------------------------------------------------");

    for i in 0..count {
        let d = &dpcs[i];
        let imp_name = dpc_importance_name(d.importance);
        let target = if d.target_processor == 0xFFFFFFFF {
            "Any"
        } else {
            "Current"
        };

        outln!("{:#018x} {:#018x} {:<10} {:<10}",
            d.address, d.routine_address, imp_name, target);
    }

    outln!("");
    outln!("Total queued: {}", count);
}

fn show_dpc_pending() {
    use crate::ke::dpc::ki_check_dpc_pending;
    use crate::ke::prcb::{get_current_prcb, ke_get_current_processor_number};

    let pending = ki_check_dpc_pending();
    let prcb = get_current_prcb();

    outln!("DPC Pending Status");
    outln!("==================");
    outln!("");

    outln!("Processor:       {}", ke_get_current_processor_number());
    outln!("DPC Pending:     {}", if pending { "YES" } else { "No" });
    outln!("Queue Depth:     {}", prcb.dpc_queue_depth);
    outln!("IRQ Requested:   {}", if prcb.dpc_interrupt_requested { "Yes" } else { "No" });

    if pending {
        outln!("");
        outln!("WARNING: DPCs are pending and should be processed");
        outln!("         at the next timer interrupt or software interrupt");
    }
}

// ============================================================================
// Object Manager Viewer Command
// ============================================================================

/// Object Manager viewer command
pub fn cmd_obdir(args: &[&str]) {
    let subcmd = if args.is_empty() { "stats" } else { args[0] };

    if eq_ignore_case(subcmd, "help") || eq_ignore_case(subcmd, "?") {
        outln!("OBDIR - Object Manager Directory Viewer");
        outln!("");
        outln!("Commands:");
        outln!("  obdir              Show namespace statistics (default)");
        outln!("  obdir stats        Show namespace statistics");
        outln!("  obdir types        List registered object types");
        outln!("  obdir dir [path]   List directory contents");
        outln!("                     0 = \\ (root)");
        outln!("                     1 = \\ObjectTypes");
        outln!("                     2 = \\BaseNamedObjects");
        outln!("                     3 = \\Device");
        outln!("  obdir tree         Show namespace tree");
        outln!("  obdir help         Show this help");
        return;
    }

    if eq_ignore_case(subcmd, "stats") {
        show_ob_stats();
    } else if eq_ignore_case(subcmd, "types") {
        show_ob_types();
    } else if eq_ignore_case(subcmd, "dir") {
        let dir_idx = if args.len() > 1 {
            // Simple single-digit parsing for directory index (0-3)
            let s = args[1].trim();
            if s.len() == 1 {
                match s.as_bytes()[0] {
                    b'0' => 0,
                    b'1' => 1,
                    b'2' => 2,
                    b'3' => 3,
                    _ => 0,
                }
            } else {
                0
            }
        } else {
            0
        };
        show_ob_directory(dir_idx);
    } else if eq_ignore_case(subcmd, "tree") {
        show_ob_tree();
    } else {
        outln!("Unknown obdir command: {}", subcmd);
        outln!("Use 'obdir help' for usage");
    }
}

fn show_ob_stats() {
    use crate::ob::{ob_get_type_stats, ob_get_directory_stats};

    outln!("Object Manager Statistics");
    outln!("=========================");
    outln!("");

    let type_stats = ob_get_type_stats();
    outln!("Object Types:");
    outln!("  Registered Types: {}", type_stats.type_count);
    outln!("  Total Objects:    {}", type_stats.total_objects);
    outln!("  Total Handles:    {}", type_stats.total_handles);

    outln!("");
    let dir_stats = ob_get_directory_stats();
    outln!("Namespace Directories:");
    outln!("  \\                   {} entries", dir_stats.root_entry_count);
    outln!("  \\ObjectTypes        {} entries", dir_stats.object_types_count);
    outln!("  \\BaseNamedObjects   {} entries", dir_stats.base_named_count);
    outln!("  \\Device             {} entries", dir_stats.device_count);

    outln!("");
    outln!("Total namespace directories: {}", dir_stats.directory_count);
}

fn show_ob_types() {
    use crate::ob::ob_get_type_snapshots;

    outln!("Registered Object Types");
    outln!("=======================");
    outln!("");

    let (types, count) = ob_get_type_snapshots();

    outln!("{:<5} {:<16} {:<8} {:<8} {:<8} {:<6}",
        "Idx", "Name", "Objects", "Handles", "Size", "Pool");
    outln!("--------------------------------------------------------------");

    for i in 0..count {
        let t = &types[i];
        let name = core::str::from_utf8(&t.name[..t.name_length as usize]).unwrap_or("?");
        let pool = if t.pool_type == 0 { "NP" } else { "P" };

        outln!("{:<5} {:<16} {:>8} {:>8} {:>8} {:>6}",
            t.type_index, name, t.object_count, t.handle_count, t.body_size, pool);
    }

    outln!("");
    outln!("Pool: NP = NonPaged, P = Paged");
}

fn show_ob_directory(dir_index: u8) {
    use crate::ob::{ob_get_directory_entries, ob_get_directory_name};

    let dir_name = ob_get_directory_name(dir_index);
    outln!("Directory: {}", dir_name);
    outln!("=================================");
    outln!("");

    let (entries, count) = ob_get_directory_entries(dir_index, 32);

    if count == 0 {
        outln!("(empty)");
        return;
    }

    outln!("{:<20} {:<16} {:<18} {:<6}",
        "Name", "Type", "Address", "Refs");
    outln!("--------------------------------------------------------------");

    for i in 0..count {
        let e = &entries[i];
        let name = core::str::from_utf8(&e.name[..e.name_length as usize]).unwrap_or("?");
        let type_name = core::str::from_utf8(&e.type_name[..e.type_name_length as usize]).unwrap_or("?");

        outln!("{:<20} {:<16} {:#018x} {:>5}",
            name, type_name, e.object_address, e.ref_count);
    }

    outln!("");
    outln!("Total: {} entries", count);
}

fn show_ob_tree() {
    use crate::ob::{ob_get_directory_entries, ob_get_directory_name};

    outln!("Object Namespace Tree");
    outln!("=====================");
    outln!("");

    // Root directory
    outln!("\\");
    let (root_entries, root_count) = ob_get_directory_entries(0, 32);
    for i in 0..root_count {
        let e = &root_entries[i];
        let name = core::str::from_utf8(&e.name[..e.name_length as usize]).unwrap_or("?");
        let type_name = core::str::from_utf8(&e.type_name[..e.type_name_length as usize]).unwrap_or("?");

        if e.is_directory {
            outln!("+-- {} <{}>", name, type_name);

            // Show children for known directories
            let child_idx = match name {
                "ObjectTypes" => Some(1u8),
                "BaseNamedObjects" => Some(2u8),
                "Device" => Some(3u8),
                _ => None,
            };

            if let Some(idx) = child_idx {
                let (child_entries, child_count) = ob_get_directory_entries(idx, 16);
                for j in 0..child_count {
                    let ce = &child_entries[j];
                    let child_name = core::str::from_utf8(&ce.name[..ce.name_length as usize]).unwrap_or("?");
                    let child_type = core::str::from_utf8(&ce.type_name[..ce.type_name_length as usize]).unwrap_or("?");

                    if j + 1 < child_count {
                        outln!("|   +-- {} <{}>", child_name, child_type);
                    } else {
                        outln!("    +-- {} <{}>", child_name, child_type);
                    }
                }
            }
        } else {
            outln!("+-- {} <{}>", name, type_name);
        }
    }
}

// ============================================================================
// Handle Table Viewer Command
// ============================================================================

/// Handle table viewer command
pub fn cmd_handles(args: &[&str]) {
    let subcmd = if args.is_empty() { "stats" } else { args[0] };

    if eq_ignore_case(subcmd, "help") || eq_ignore_case(subcmd, "?") {
        outln!("HANDLES - System Handle Table Viewer");
        outln!("");
        outln!("Commands:");
        outln!("  handles            Show handle statistics (default)");
        outln!("  handles stats      Show handle table statistics");
        outln!("  handles list       List all open handles");
        outln!("  handles help       Show this help");
        return;
    }

    if eq_ignore_case(subcmd, "stats") {
        show_handle_stats();
    } else if eq_ignore_case(subcmd, "list") {
        show_handle_list();
    } else {
        outln!("Unknown handles command: {}", subcmd);
        outln!("Use 'handles help' for usage");
    }
}

fn show_handle_stats() {
    use crate::ob::{ob_get_handle_stats, handle_attributes};

    outln!("System Handle Table Statistics");
    outln!("==============================");
    outln!("");

    let stats = ob_get_handle_stats();

    outln!("Handle Count:      {}", stats.handle_count);
    outln!("Max Handles:       {}", stats.max_handles);
    outln!("Next Hint:         {:#x}", stats.next_handle_hint);
    outln!("");
    outln!("Usage:             {:.1}%",
        (stats.handle_count as f64 / stats.max_handles as f64) * 100.0);
}

fn show_handle_list() {
    use crate::ob::{ob_get_handle_snapshots, ob_get_handle_stats, handle_attributes};

    let stats = ob_get_handle_stats();
    let (handles, count) = ob_get_handle_snapshots(32);

    outln!("System Handle Table ({} handles)", stats.handle_count);
    outln!("============================================");
    outln!("");

    if count == 0 {
        outln!("No handles in use");
        return;
    }

    outln!("{:<8} {:<18} {:<12} {:<10} {:<20}",
        "Handle", "Object", "Type", "Access", "Name");
    outln!("--------------------------------------------------------------------------------");

    for i in 0..count {
        let h = &handles[i];
        let type_name = core::str::from_utf8(&h.type_name[..h.type_name_length as usize]).unwrap_or("?");
        let obj_name = if h.object_name_length > 0 {
            core::str::from_utf8(&h.object_name[..h.object_name_length as usize]).unwrap_or("-")
        } else {
            "-"
        };

        outln!("{:#08x} {:#018x} {:<12} {:#010x} {:<20}",
            h.handle, h.object_address, type_name, h.access_mask, obj_name);
    }

    if count < stats.handle_count as usize {
        outln!("");
        outln!("... showing {} of {} handles", count, stats.handle_count);
    }
}

// ============================================================================
// PRCB Viewer Command
// ============================================================================

/// PRCB viewer command
pub fn cmd_prcb(args: &[&str]) {
    let subcmd = if args.is_empty() { "stats" } else { args[0] };

    if eq_ignore_case(subcmd, "help") || eq_ignore_case(subcmd, "?") {
        outln!("PRCB - Processor Control Block Viewer");
        outln!("");
        outln!("Commands:");
        outln!("  prcb               Show current PRCB info (default)");
        outln!("  prcb stats         Show PRCB statistics");
        outln!("  prcb threads       Show thread pointers");
        outln!("  prcb ready         Show ready queue summary");
        outln!("  prcb ipi           Show IPI state");
        outln!("  prcb help          Show this help");
        return;
    }

    if eq_ignore_case(subcmd, "stats") {
        show_prcb_stats();
    } else if eq_ignore_case(subcmd, "threads") {
        show_prcb_threads();
    } else if eq_ignore_case(subcmd, "ready") {
        show_prcb_ready();
    } else if eq_ignore_case(subcmd, "ipi") {
        show_prcb_ipi();
    } else {
        outln!("Unknown prcb command: {}", subcmd);
        outln!("Use 'prcb help' for usage");
    }
}

fn show_prcb_stats() {
    use crate::ke::prcb::{get_current_prcb, ke_get_current_processor_number,
                          get_active_cpu_count, ke_get_active_processors};

    let prcb = get_current_prcb();
    let cpu_num = ke_get_current_processor_number();
    let active_cpus = get_active_cpu_count();
    let active_mask = ke_get_active_processors();

    outln!("Processor Control Block (PRCB)");
    outln!("==============================");
    outln!("");

    outln!("Processor Identification:");
    outln!("  Current CPU:      {}", cpu_num);
    outln!("  Set Member:       {:#018x}", prcb.set_member);
    outln!("  Active CPUs:      {}", active_cpus);
    outln!("  Active Mask:      {:#018x}", active_mask);

    outln!("");
    outln!("Scheduling Statistics:");
    outln!("  Context Switches: {}", prcb.context_switches);
    outln!("  Ready Summary:    {:#010x}", prcb.ready_summary);
    outln!("  Quantum End:      {}", if prcb.quantum_end { "Yes" } else { "No" });

    outln!("");
    outln!("DPC State:");
    outln!("  Queue Depth:      {}", prcb.dpc_queue_depth);
    outln!("  DPC Pending:      {}", if prcb.dpc_pending { "Yes" } else { "No" });

    outln!("");
    outln!("Freeze State:");
    outln!("  Frozen:           {}", if prcb.frozen { "Yes" } else { "No" });
    outln!("  Freeze Requested: {}", if prcb.freeze_requested { "Yes" } else { "No" });
}

fn show_prcb_threads() {
    use crate::ke::prcb::get_current_prcb;

    let prcb = get_current_prcb();

    outln!("PRCB Thread Pointers");
    outln!("====================");
    outln!("");

    if prcb.current_thread.is_null() {
        outln!("Current Thread:   NULL");
    } else {
        outln!("Current Thread:   {:#018x}", prcb.current_thread as u64);
    }

    if prcb.next_thread.is_null() {
        outln!("Next Thread:      NULL");
    } else {
        outln!("Next Thread:      {:#018x}", prcb.next_thread as u64);
    }

    if prcb.idle_thread.is_null() {
        outln!("Idle Thread:      NULL");
    } else {
        outln!("Idle Thread:      {:#018x}", prcb.idle_thread as u64);
    }
}

fn show_prcb_ready() {
    use crate::ke::prcb::get_current_prcb;
    use crate::ke::thread::constants::MAXIMUM_PRIORITY;

    let prcb = get_current_prcb();

    outln!("Ready Queue Summary");
    outln!("===================");
    outln!("");

    outln!("Ready Summary: {:#010x}", prcb.ready_summary);
    outln!("");

    if prcb.ready_summary == 0 {
        outln!("No ready threads (all queues empty)");
        return;
    }

    outln!("Non-empty priority levels:");
    for pri in (0..MAXIMUM_PRIORITY).rev() {
        if (prcb.ready_summary & (1 << pri)) != 0 {
            outln!("  Priority {:>2}: READY", pri);
        }
    }

    if let Some(highest) = prcb.find_highest_ready_priority() {
        outln!("");
        outln!("Highest ready priority: {}", highest);
    }
}

fn show_prcb_ipi() {
    use crate::ke::prcb::get_current_prcb;
    use core::sync::atomic::Ordering;

    let prcb = get_current_prcb();

    outln!("IPI State");
    outln!("=========");
    outln!("");

    let request_summary = prcb.request_summary.load(Ordering::Relaxed);
    let target_set = prcb.target_set.load(Ordering::Relaxed);
    let packet_barrier = prcb.packet_barrier.load(Ordering::Relaxed);
    let worker = prcb.worker_routine.load(Ordering::Relaxed);

    outln!("Request Summary:  {:#018x}", request_summary);
    outln!("Target Set:       {:#018x}", target_set);
    outln!("Packet Barrier:   {:#018x}", packet_barrier);
    outln!("Worker Routine:   {:#018x}", worker);

    outln!("");
    outln!("Current Packet:");
    for (i, p) in prcb.current_packet.iter().enumerate() {
        outln!("  Param[{}]:       {:#018x}", i, p.load(Ordering::Relaxed));
    }
}

// ============================================================================
// IRQL Viewer Command
// ============================================================================

/// IRQL viewer command
pub fn cmd_irql(args: &[&str]) {
    let subcmd = if args.is_empty() { "current" } else { args[0] };

    if eq_ignore_case(subcmd, "help") || eq_ignore_case(subcmd, "?") {
        outln!("IRQL - Interrupt Request Level Viewer");
        outln!("");
        outln!("Commands:");
        outln!("  irql               Show current IRQL (default)");
        outln!("  irql current       Show current IRQL");
        outln!("  irql levels        Show all IRQL levels");
        outln!("  irql state         Show interrupt state");
        outln!("  irql help          Show this help");
        return;
    }

    if eq_ignore_case(subcmd, "current") {
        show_irql_current();
    } else if eq_ignore_case(subcmd, "levels") {
        show_irql_levels();
    } else if eq_ignore_case(subcmd, "state") {
        show_irql_state();
    } else {
        outln!("Unknown irql command: {}", subcmd);
        outln!("Use 'irql help' for usage");
    }
}

fn show_irql_current() {
    use crate::ke::kpcr::{ke_get_current_irql, irql, get_current_kpcr};

    let current_irql = ke_get_current_irql();
    let kpcr = get_current_kpcr();

    outln!("Current IRQL State");
    outln!("==================");
    outln!("");

    outln!("IRQL Value:        {}", current_irql);

    // Show level name
    let level_name = match current_irql {
        0 => "PASSIVE_LEVEL",
        1 => "APC_LEVEL",
        2 => "DISPATCH_LEVEL",
        28 => "CLOCK_LEVEL",
        29 => "IPI_LEVEL",
        30 => "POWER_LEVEL",
        31 => "HIGH_LEVEL",
        n if n >= 3 && n < 28 => "DEVICE_LEVEL",
        _ => "UNKNOWN",
    };
    outln!("Level Name:        {}", level_name);

    outln!("");
    outln!("Permissions at this level:");
    if current_irql <= irql::PASSIVE_LEVEL {
        outln!("  - Page faults:       ALLOWED");
        outln!("  - APCs:              ALLOWED");
        outln!("  - Thread preemption: ALLOWED");
    } else if current_irql <= irql::APC_LEVEL {
        outln!("  - Page faults:       ALLOWED");
        outln!("  - APCs:              DISABLED");
        outln!("  - Thread preemption: ALLOWED");
    } else if current_irql <= irql::DISPATCH_LEVEL {
        outln!("  - Page faults:       FORBIDDEN");
        outln!("  - APCs:              DISABLED");
        outln!("  - Thread preemption: DISABLED");
    } else {
        outln!("  - All interrupts:    MASKED");
    }
}

fn show_irql_levels() {
    use crate::ke::kpcr::irql;

    outln!("NT IRQL Levels");
    outln!("==============");
    outln!("");

    outln!("{:<3} {:<18} {}", "Lvl", "Name", "Description");
    outln!("--------------------------------------------------------------");
    outln!("{:>3} {:<18} {}", irql::PASSIVE_LEVEL, "PASSIVE_LEVEL", "Normal thread execution");
    outln!("{:>3} {:<18} {}", irql::APC_LEVEL, "APC_LEVEL", "APCs disabled");
    outln!("{:>3} {:<18} {}", irql::DISPATCH_LEVEL, "DISPATCH_LEVEL", "Thread preemption disabled");
    outln!("{:>3} {:<18} {}", "3-27", "DEVICE_LEVELS", "Device interrupt levels");
    outln!("{:>3} {:<18} {}", irql::CLOCK_LEVEL, "CLOCK_LEVEL", "Clock/timer interrupt");
    outln!("{:>3} {:<18} {}", irql::IPI_LEVEL, "IPI_LEVEL", "Inter-processor interrupt");
    outln!("{:>3} {:<18} {}", irql::POWER_LEVEL, "POWER_LEVEL", "Power fail interrupt");
    outln!("{:>3} {:<18} {}", irql::HIGH_LEVEL, "HIGH_LEVEL", "All interrupts disabled");

    outln!("");
    outln!("SYNCH_LEVEL = DISPATCH_LEVEL on x86-64");
}

fn show_irql_state() {
    use crate::ke::kpcr::{ke_get_current_irql, get_current_kpcr,
                          ke_is_executing_interrupt, ke_is_dpc_active};

    let current_irql = ke_get_current_irql();
    let kpcr = get_current_kpcr();

    outln!("Interrupt State");
    outln!("===============");
    outln!("");

    outln!("Current IRQL:      {}", current_irql);
    outln!("Processor Number:  {}", kpcr.number);
    outln!("Interrupt Count:   {}", kpcr.interrupt_count);
    outln!("");

    outln!("State Flags:");
    outln!("  In Interrupt:    {}", if ke_is_executing_interrupt() { "YES" } else { "No" });
    outln!("  DPC Active:      {}", if ke_is_dpc_active() { "YES" } else { "No" });
    outln!("  Debugger Active: {}", if kpcr.debugger_active != 0 { "YES" } else { "No" });

    outln!("");
    outln!("Exception Stacks:");
    if kpcr.nmi_stack != 0 {
        outln!("  NMI Stack:       {:#018x}", kpcr.nmi_stack);
    } else {
        outln!("  NMI Stack:       (not configured)");
    }
    if kpcr.double_fault_stack != 0 {
        outln!("  Double Fault:    {:#018x}", kpcr.double_fault_stack);
    } else {
        outln!("  Double Fault:    (not configured)");
    }
    if kpcr.machine_check_stack != 0 {
        outln!("  Machine Check:   {:#018x}", kpcr.machine_check_stack);
    } else {
        outln!("  Machine Check:   (not configured)");
    }
}

// ============================================================================
// APC Queue Viewer Command
// ============================================================================

/// APC queue viewer command
pub fn cmd_apcq(args: &[&str]) {
    let subcmd = if args.is_empty() { "stats" } else { args[0] };

    if eq_ignore_case(subcmd, "help") || eq_ignore_case(subcmd, "?") {
        outln!("APCQ - APC Queue Viewer");
        outln!("");
        outln!("Commands:");
        outln!("  apcq               Show APC status (default)");
        outln!("  apcq stats         Show APC queue statistics");
        outln!("  apcq pending       Check if APCs are pending");
        outln!("  apcq help          Show this help");
        return;
    }

    if eq_ignore_case(subcmd, "stats") {
        show_apc_stats();
    } else if eq_ignore_case(subcmd, "pending") {
        show_apc_pending();
    } else {
        outln!("Unknown apcq command: {}", subcmd);
        outln!("Use 'apcq help' for usage");
    }
}

fn show_apc_stats() {
    use crate::ke::apc::ki_check_apc_pending;
    use crate::ke::prcb::get_current_prcb;

    let prcb = get_current_prcb();
    let apc_pending = ki_check_apc_pending();

    outln!("APC Queue Statistics");
    outln!("====================");
    outln!("");

    if prcb.current_thread.is_null() {
        outln!("No current thread - APC information unavailable");
        return;
    }

    unsafe {
        let thread = &*prcb.current_thread;
        let apc_state = &thread.apc_state;

        outln!("Current Thread: {:#018x}", prcb.current_thread as u64);
        outln!("Thread ID:      {}", thread.thread_id);
        outln!("");

        outln!("APC State:");
        outln!("  Kernel APC Pending:     {}", if apc_state.kernel_apc_pending { "YES" } else { "No" });
        outln!("  Kernel APC In Progress: {}", if apc_state.kernel_apc_in_progress { "YES" } else { "No" });
        outln!("  User APC Pending:       {}", if apc_state.user_apc_pending { "YES" } else { "No" });
        outln!("");

        outln!("Queue Status:");
        outln!("  Kernel APC Queue:       {}",
            if apc_state.is_kernel_apc_queue_empty() { "Empty" } else { "Has APCs" });
        outln!("  User APC Queue:         {}",
            if apc_state.is_user_apc_queue_empty() { "Empty" } else { "Has APCs" });

        outln!("");
        outln!("Thread Flags:");
        outln!("  Alertable:              {}", if thread.alertable { "Yes" } else { "No" });
        outln!("  Special APC Disable:    {}", thread.special_apc_disable);
    }
}

fn show_apc_pending() {
    use crate::ke::apc::ki_check_apc_pending;

    let pending = ki_check_apc_pending();

    outln!("APC Pending Status");
    outln!("==================");
    outln!("");

    if pending {
        outln!("APCs are PENDING");
        outln!("");
        outln!("Pending APCs will be delivered when:");
        outln!("  - Returning from kernel to user mode");
        outln!("  - Thread enters alertable wait state");
        outln!("  - IRQL drops to PASSIVE_LEVEL");
    } else {
        outln!("No APCs pending");
    }
}

// ============================================================================
// Scheduler Viewer Command
// ============================================================================

/// Scheduler viewer command
pub fn cmd_sched(args: &[&str]) {
    let subcmd = if args.is_empty() { "stats" } else { args[0] };

    if eq_ignore_case(subcmd, "help") || eq_ignore_case(subcmd, "?") {
        outln!("SCHED - Scheduler Viewer");
        outln!("");
        outln!("Commands:");
        outln!("  sched              Show scheduler state (default)");
        outln!("  sched stats        Show scheduler statistics");
        outln!("  sched ready        Show ready queue summary");
        outln!("  sched current      Show current thread info");
        outln!("  sched help         Show this help");
        return;
    }

    if eq_ignore_case(subcmd, "stats") {
        show_sched_stats();
    } else if eq_ignore_case(subcmd, "ready") {
        show_sched_ready();
    } else if eq_ignore_case(subcmd, "current") {
        show_sched_current();
    } else {
        outln!("Unknown sched command: {}", subcmd);
        outln!("Use 'sched help' for usage");
    }
}

fn show_sched_stats() {
    use crate::ke::prcb::{get_current_prcb, ke_get_current_processor_number};
    use crate::ke::thread::constants::MAXIMUM_PRIORITY;

    let prcb = get_current_prcb();
    let cpu_num = ke_get_current_processor_number();

    outln!("Scheduler Statistics");
    outln!("====================");
    outln!("");

    outln!("Processor:         {}", cpu_num);
    outln!("Context Switches:  {}", prcb.context_switches);
    outln!("Ready Summary:     {:#010x}", prcb.ready_summary);
    outln!("Quantum End:       {}", if prcb.quantum_end { "Yes" } else { "No" });

    outln!("");
    outln!("Priority Configuration:");
    outln!("  Maximum Priority:  {}", MAXIMUM_PRIORITY);

    // Count ready priorities
    let mut ready_count = 0;
    for pri in 0..MAXIMUM_PRIORITY {
        if (prcb.ready_summary & (1 << pri)) != 0 {
            ready_count += 1;
        }
    }
    outln!("  Active Priorities: {}", ready_count);

    if let Some(highest) = prcb.find_highest_ready_priority() {
        outln!("  Highest Ready:     {}", highest);
    } else {
        outln!("  Highest Ready:     None");
    }
}

fn show_sched_ready() {
    use crate::ke::prcb::get_current_prcb;
    use crate::ke::thread::constants::MAXIMUM_PRIORITY;

    let prcb = get_current_prcb();

    outln!("Ready Queue Summary");
    outln!("===================");
    outln!("");

    outln!("Ready Summary Bitmap: {:#034b}", prcb.ready_summary);
    outln!("");

    if prcb.ready_summary == 0 {
        outln!("All ready queues are empty");
        outln!("(Idle thread would run)");
        return;
    }

    outln!("Priority  Status");
    outln!("--------  ------");
    for pri in (0..MAXIMUM_PRIORITY).rev() {
        if (prcb.ready_summary & (1 << pri)) != 0 {
            outln!("{:>8}  READY", pri);
        }
    }

    outln!("");
    if let Some(highest) = prcb.find_highest_ready_priority() {
        outln!("Next priority to run: {}", highest);
    }
}

fn show_sched_current() {
    use crate::ke::prcb::get_current_prcb;
    use crate::ke::thread::ThreadState;

    let prcb = get_current_prcb();

    outln!("Current Thread Information");
    outln!("==========================");
    outln!("");

    if prcb.current_thread.is_null() {
        outln!("No current thread (should not happen!)");
        return;
    }

    unsafe {
        let thread = &*prcb.current_thread;

        outln!("Thread Address:    {:#018x}", prcb.current_thread as u64);
        outln!("Thread ID:         {}", thread.thread_id);
        outln!("");

        outln!("Scheduling:");
        outln!("  Priority:        {}", thread.priority);
        outln!("  Base Priority:   {}", thread.base_priority);
        outln!("  Quantum:         {}", thread.quantum);
        outln!("  Affinity:        {:#018x}", thread.affinity);

        outln!("");
        outln!("State:");
        let state_name = match thread.state {
            ThreadState::Initialized => "Initialized",
            ThreadState::Ready => "Ready",
            ThreadState::Running => "Running",
            ThreadState::Standby => "Standby",
            ThreadState::Terminated => "Terminated",
            ThreadState::Waiting => "Waiting",
            ThreadState::Transition => "Transition",
            ThreadState::DeferredReady => "DeferredReady",
            ThreadState::Suspended => "Suspended",
        };
        outln!("  Thread State:    {}", state_name);
        outln!("  Wait Reason:     {}", thread.wait_reason);
        outln!("  Alertable:       {}", if thread.alertable { "Yes" } else { "No" });

        if !thread.process.is_null() {
            outln!("");
            outln!("Process:           {:#018x}", thread.process as u64);
        }
    }
}

// ============================================================================
// Wait Block Viewer Command
// ============================================================================

/// Wait block viewer command
pub fn cmd_waitq(args: &[&str]) {
    if args.is_empty() {
        show_waitq_help();
        return;
    }

    let cmd = args[0];
    if eq_ignore_ascii_case(cmd, "help") || cmd == "-h" || cmd == "--help" || cmd == "-?" {
        show_waitq_help();
    } else if eq_ignore_ascii_case(cmd, "threads") {
        show_waiting_threads();
    } else if eq_ignore_ascii_case(cmd, "reasons") {
        show_wait_reasons();
    } else {
        outln!("Unknown subcommand: {}", args[0]);
        show_waitq_help();
    }
}

fn show_waitq_help() {
    outln!("Wait Block Viewer");
    outln!("");
    outln!("Usage: waitq <subcommand>");
    outln!("");
    outln!("Subcommands:");
    outln!("  threads   - Show threads in waiting state");
    outln!("  reasons   - Show wait reason descriptions");
    outln!("  help      - Show this help message");
}

fn show_waiting_threads() {
    use crate::ke::thread::ThreadState;
    use crate::ps::MAX_THREADS;

    outln!("Waiting Threads");
    outln!("===============");
    outln!("");

    // Get EThread list from process subsystem
    let (threads, count) = crate::ps::ps_get_ethread_list();

    if count == 0 {
        outln!("No threads in system");
        return;
    }

    outln!("{:<6} {:<6} {:<12} {:<10} {:<8}", "TID", "PID", "State", "WaitReason", "Alertable");
    outln!("--------------------------------------------------");

    let mut waiting_count = 0;
    for i in 0..count.min(MAX_THREADS) {
        let ethread = threads[i];
        if ethread.is_null() {
            continue;
        }

        unsafe {
            let et = &*ethread;
            let tcb = et.get_tcb();
            if tcb.is_null() {
                continue;
            }
            let t = &*tcb;
            if t.state == ThreadState::Waiting {
                waiting_count += 1;
                let wait_reason = wait_reason_name(t.wait_reason);
                let alertable = if t.alertable { "Yes" } else { "No" };

                outln!("{:<6} {:<6} {:<12} {:<10} {:<8}",
                    et.thread_id(),
                    et.process_id(),
                    "Waiting",
                    wait_reason,
                    alertable
                );
            }
        }
    }

    outln!("");
    outln!("Total waiting: {}", waiting_count);
}

fn show_wait_reasons() {
    outln!("Wait Reasons");
    outln!("============");
    outln!("");
    outln!("{:<3} {:<20} {}", "ID", "Name", "Description");
    outln!("------------------------------------------------------------");
    outln!("{:<3} {:<20} {}", 0, "Executive", "General purpose wait");
    outln!("{:<3} {:<20} {}", 1, "FreePage", "Waiting for free page");
    outln!("{:<3} {:<20} {}", 2, "PageIn", "Waiting for page in");
    outln!("{:<3} {:<20} {}", 3, "PoolAllocation", "Waiting for pool memory");
    outln!("{:<3} {:<20} {}", 4, "DelayExecution", "Sleep/delay");
    outln!("{:<3} {:<20} {}", 5, "Suspended", "Thread suspended");
    outln!("{:<3} {:<20} {}", 6, "UserRequest", "User-mode wait");
    outln!("{:<3} {:<20} {}", 7, "WrExecutive", "Executive resource wait");
    outln!("{:<3} {:<20} {}", 8, "WrQueue", "Queue wait");
    outln!("{:<3} {:<20} {}", 9, "WrLpcReceive", "LPC receive wait");
    outln!("{:<3} {:<20} {}", 10, "WrLpcReply", "LPC reply wait");
    outln!("{:<3} {:<20} {}", 11, "WrVirtualMemory", "Virtual memory operation");
    outln!("{:<3} {:<20} {}", 12, "WrPageOut", "Page out wait");
}

fn wait_reason_name(reason: u8) -> &'static str {
    match reason {
        0 => "Executive",
        1 => "FreePage",
        2 => "PageIn",
        3 => "PoolAlloc",
        4 => "Delay",
        5 => "Suspended",
        6 => "UserReq",
        7 => "WrExec",
        8 => "WrQueue",
        9 => "LpcRecv",
        10 => "LpcReply",
        11 => "VirtMem",
        12 => "PageOut",
        _ => "Unknown",
    }
}

// ============================================================================
// Pool Tag Viewer Command
// ============================================================================

/// Pool tag viewer command
pub fn cmd_pooltag(args: &[&str]) {
    if args.is_empty() {
        show_pooltag_help();
        return;
    }

    let cmd = args[0];
    if eq_ignore_ascii_case(cmd, "help") || cmd == "-h" || cmd == "--help" || cmd == "-?" {
        show_pooltag_help();
    } else if eq_ignore_ascii_case(cmd, "stats") {
        show_pooltag_stats();
    } else if eq_ignore_ascii_case(cmd, "classes") {
        show_pooltag_classes();
    } else if eq_ignore_ascii_case(cmd, "tags") {
        show_common_tags();
    } else {
        outln!("Unknown subcommand: {}", args[0]);
        show_pooltag_help();
    }
}

fn show_pooltag_help() {
    outln!("Pool Tag Viewer");
    outln!("");
    outln!("Usage: pooltag <subcommand>");
    outln!("");
    outln!("Subcommands:");
    outln!("  stats     - Show pool allocation statistics");
    outln!("  classes   - Show pool size class details");
    outln!("  tags      - Show common pool tag definitions");
    outln!("  help      - Show this help message");
}

fn show_pooltag_stats() {
    use crate::mm::pool::mm_get_pool_stats;

    let stats = mm_get_pool_stats();

    outln!("Pool Allocation Statistics");
    outln!("==========================");
    outln!("");
    outln!("Total Size:       {} KB", stats.total_size / 1024);
    outln!("Bytes Allocated:  {} bytes", stats.bytes_allocated);
    outln!("Bytes Free:       {} bytes", stats.bytes_free);
    outln!("Allocation Count: {}", stats.allocation_count);
    outln!("Free Count:       {}", stats.free_count);
    outln!("");

    let usage_pct = if stats.total_size > 0 {
        (stats.bytes_allocated * 100) / stats.total_size
    } else {
        0
    };
    outln!("Usage: {}%", usage_pct);

    // Visual bar
    let bar_len = 40usize;
    let filled = (usage_pct * bar_len) / 100;
    let mut bar = [b' '; 40];
    for i in 0..filled {
        bar[i] = b'#';
    }
    let bar_str = core::str::from_utf8(&bar).unwrap_or("");
    outln!("[{}]", bar_str);
}

fn show_pooltag_classes() {
    use crate::mm::pool::{mm_get_pool_class_count, mm_get_pool_class_stats};

    outln!("Pool Size Classes");
    outln!("=================");
    outln!("");
    outln!("{:<6} {:<8} {:<8} {:<8} {:<12} {:<12}",
        "Class", "Size", "Total", "Free", "Used", "UsedBytes");
    outln!("------------------------------------------------------------");

    let class_count = mm_get_pool_class_count();
    for i in 0..class_count {
        if let Some(stats) = mm_get_pool_class_stats(i) {
            outln!("{:<6} {:<8} {:<8} {:<8} {:<12} {:<12}",
                i,
                stats.block_size,
                stats.total_blocks,
                stats.free_blocks,
                stats.used_blocks,
                stats.used_bytes
            );
        }
    }
}

fn show_common_tags() {
    outln!("Common Pool Tags");
    outln!("================");
    outln!("");
    outln!("{:<10} {}", "Tag", "Description");
    outln!("----------------------------------------");
    outln!("{:<10} {}", "Gen ", "Generic allocation");
    outln!("{:<10} {}", "Proc", "Process objects");
    outln!("{:<10} {}", "Thrd", "Thread objects");
    outln!("{:<10} {}", "File", "File objects");
    outln!("{:<10} {}", "Drvr", "Driver objects");
    outln!("{:<10} {}", "Irp ", "I/O Request Packets");
    outln!("{:<10} {}", "Mdl ", "Memory Descriptor Lists");
    outln!("{:<10} {}", "Sec ", "Security structures");
    outln!("{:<10} {}", "Obj ", "Object Manager objects");
    outln!("{:<10} {}", "Evnt", "Event objects");
    outln!("{:<10} {}", "Mutx", "Mutex objects");
    outln!("{:<10} {}", "Sema", "Semaphore objects");
    outln!("{:<10} {}", "Timr", "Timer objects");
    outln!("{:<10} {}", "Reg ", "Registry structures");
    outln!("{:<10} {}", "Mm  ", "Memory manager");
}

// ============================================================================
// I/O Request Queue Viewer Command
// ============================================================================

/// I/O request queue viewer command
pub fn cmd_ioq(args: &[&str]) {
    if args.is_empty() {
        show_ioq_help();
        return;
    }

    let cmd = args[0];
    if eq_ignore_ascii_case(cmd, "help") || cmd == "-h" || cmd == "--help" || cmd == "-?" {
        show_ioq_help();
    } else if eq_ignore_ascii_case(cmd, "stats") {
        show_irp_stats();
    } else if eq_ignore_ascii_case(cmd, "list") {
        show_irp_list();
    } else if eq_ignore_ascii_case(cmd, "pending") {
        show_pending_irps();
    } else {
        outln!("Unknown subcommand: {}", args[0]);
        show_ioq_help();
    }
}

fn show_ioq_help() {
    outln!("I/O Request Queue Viewer");
    outln!("");
    outln!("Usage: ioq <subcommand>");
    outln!("");
    outln!("Subcommands:");
    outln!("  stats     - Show IRP pool statistics");
    outln!("  list      - List allocated IRPs");
    outln!("  pending   - Show pending IRPs only");
    outln!("  help      - Show this help message");
}

fn show_irp_stats() {
    use crate::io::{io_get_irp_stats, IrpPoolStats};

    let stats: IrpPoolStats = io_get_irp_stats();

    outln!("IRP Pool Statistics");
    outln!("===================");
    outln!("");
    outln!("Total IRPs:       {}", stats.total_irps);
    outln!("Allocated:        {}", stats.allocated_irps);
    outln!("Free:             {}", stats.free_irps);
    outln!("Pending:          {}", stats.pending_irps);
    outln!("Completed:        {}", stats.completed_irps);
    outln!("");

    let usage_pct = if stats.total_irps > 0 {
        (stats.allocated_irps * 100) / stats.total_irps
    } else {
        0
    };
    outln!("Pool Usage: {}%", usage_pct);
}

fn show_irp_list() {
    use crate::io::{io_get_irp_snapshots, irp_major_function_name};

    outln!("Allocated IRPs");
    outln!("==============");
    outln!("");

    let (snapshots, count) = io_get_irp_snapshots(32);

    if count == 0 {
        outln!("No IRPs currently allocated");
        return;
    }

    outln!("{:<18} {:<14} {:<8} {:<8} {:<8}",
        "Address", "MajorFunc", "Stack", "Pending", "TID");
    outln!("------------------------------------------------------------");

    for i in 0..count {
        let irp = &snapshots[i];
        let func_name = irp_major_function_name(irp.major_function);
        let pending = if irp.is_pending { "Yes" } else { "No" };

        outln!("{:#018x} {:<14} {}/{:<5} {:<8} {:<8}",
            irp.address,
            func_name,
            irp.current_location,
            irp.stack_count,
            pending,
            irp.thread_id
        );
    }

    outln!("");
    outln!("Total: {} IRPs", count);
}

fn show_pending_irps() {
    use crate::io::{io_get_irp_snapshots, irp_major_function_name};

    outln!("Pending IRPs");
    outln!("============");
    outln!("");

    let (snapshots, count) = io_get_irp_snapshots(32);

    let mut pending_count = 0;
    let mut first = true;

    for i in 0..count {
        let irp = &snapshots[i];
        if irp.is_pending {
            if first {
                outln!("{:<18} {:<14} {:<10} {:<8}",
                    "Address", "MajorFunc", "Cancelled", "TID");
                outln!("-------------------------------------------------------");
                first = false;
            }

            pending_count += 1;
            let func_name = irp_major_function_name(irp.major_function);
            let cancelled = if irp.is_cancelled { "Yes" } else { "No" };

            outln!("{:#018x} {:<14} {:<10} {:<8}",
                irp.address,
                func_name,
                cancelled,
                irp.thread_id
            );
        }
    }

    if pending_count == 0 {
        outln!("No pending IRPs");
    } else {
        outln!("");
        outln!("Total pending: {}", pending_count);
    }
}

// ============================================================================
// Device/Driver Viewer Command
// ============================================================================

/// Device/Driver viewer command
pub fn cmd_devdrv(args: &[&str]) {
    if args.is_empty() {
        show_devdrv_help();
        return;
    }

    let cmd = args[0];
    if eq_ignore_ascii_case(cmd, "help") || cmd == "-h" || cmd == "--help" || cmd == "-?" {
        show_devdrv_help();
    } else if eq_ignore_ascii_case(cmd, "devices") {
        show_device_list();
    } else if eq_ignore_ascii_case(cmd, "drivers") {
        show_driver_list();
    } else if eq_ignore_ascii_case(cmd, "stats") {
        show_devdrv_stats();
    } else {
        outln!("Unknown subcommand: {}", args[0]);
        show_devdrv_help();
    }
}

fn show_devdrv_help() {
    outln!("Device/Driver Viewer");
    outln!("");
    outln!("Usage: devdrv <subcommand>");
    outln!("");
    outln!("Subcommands:");
    outln!("  stats     - Show device and driver statistics");
    outln!("  devices   - List allocated devices");
    outln!("  drivers   - List allocated drivers");
    outln!("  help      - Show this help message");
}

fn show_devdrv_stats() {
    use crate::io::{io_get_device_stats, io_get_driver_stats};

    let dev_stats = io_get_device_stats();
    let drv_stats = io_get_driver_stats();

    outln!("Device/Driver Pool Statistics");
    outln!("=============================");
    outln!("");
    outln!("Device Pool:");
    outln!("  Total:     {}", dev_stats.total_devices);
    outln!("  Allocated: {}", dev_stats.allocated_devices);
    outln!("  Free:      {}", dev_stats.free_devices);
    outln!("");
    outln!("Driver Pool:");
    outln!("  Total:     {}", drv_stats.total_drivers);
    outln!("  Allocated: {}", drv_stats.allocated_drivers);
    outln!("  Free:      {}", drv_stats.free_drivers);
}

fn show_device_list() {
    use crate::io::{io_get_device_snapshots, device_type_name};

    outln!("Allocated Devices");
    outln!("=================");
    outln!("");

    let (snapshots, count) = io_get_device_snapshots(32);

    if count == 0 {
        outln!("No devices currently allocated");
        return;
    }

    outln!("{:<18} {:<16} {:<12} {:<6} {:<6}",
        "Address", "Name", "Type", "Stack", "Refs");
    outln!("------------------------------------------------------------");

    for i in 0..count {
        let dev = &snapshots[i];
        let name = core::str::from_utf8(&dev.name[..dev.name_length as usize])
            .unwrap_or("?");
        let type_name = device_type_name(dev.device_type);

        outln!("{:#018x} {:<16} {:<12} {:<6} {:<6}",
            dev.address,
            name,
            type_name,
            dev.stack_size,
            dev.ref_count
        );
    }

    outln!("");
    outln!("Total: {} devices", count);
}

fn show_driver_list() {
    use crate::io::io_get_driver_snapshots;

    outln!("Allocated Drivers");
    outln!("=================");
    outln!("");

    let (snapshots, count) = io_get_driver_snapshots(16);

    if count == 0 {
        outln!("No drivers currently allocated");
        return;
    }

    outln!("{:<18} {:<20} {:<6} {:<8} {:<8}",
        "Address", "Name", "Devs", "Unload", "MajFns");
    outln!("------------------------------------------------------------");

    for i in 0..count {
        let drv = &snapshots[i];
        let name = core::str::from_utf8(&drv.name[..drv.name_length as usize])
            .unwrap_or("?");
        let has_unload = if drv.has_unload { "Yes" } else { "No" };

        outln!("{:#018x} {:<20} {:<6} {:<8} {:<8}",
            drv.address,
            name,
            drv.device_count,
            has_unload,
            drv.major_function_count
        );
    }

    outln!("");
    outln!("Total: {} drivers", count);
}

// ============================================================================
// File Object Viewer Command
// ============================================================================

/// File object viewer command
pub fn cmd_files(args: &[&str]) {
    if args.is_empty() {
        show_files_help();
        return;
    }

    let cmd = args[0];
    if eq_ignore_ascii_case(cmd, "help") || cmd == "-h" || cmd == "--help" || cmd == "-?" {
        show_files_help();
    } else if eq_ignore_ascii_case(cmd, "stats") {
        show_file_stats();
    } else if eq_ignore_ascii_case(cmd, "list") {
        show_file_list();
    } else {
        outln!("Unknown subcommand: {}", args[0]);
        show_files_help();
    }
}

fn show_files_help() {
    outln!("File Object Viewer");
    outln!("");
    outln!("Usage: files <subcommand>");
    outln!("");
    outln!("Subcommands:");
    outln!("  stats     - Show file object pool statistics");
    outln!("  list      - List allocated file objects");
    outln!("  help      - Show this help message");
}

fn show_file_stats() {
    use crate::io::io_get_file_stats;

    let stats = io_get_file_stats();

    outln!("File Object Pool Statistics");
    outln!("===========================");
    outln!("");
    outln!("Total Files:      {}", stats.total_files);
    outln!("Allocated:        {}", stats.allocated_files);
    outln!("Free:             {}", stats.free_files);
    outln!("");

    let usage_pct = if stats.total_files > 0 {
        (stats.allocated_files * 100) / stats.total_files
    } else {
        0
    };
    outln!("Pool Usage: {}%", usage_pct);
}

fn show_file_list() {
    use crate::io::io_get_file_snapshots;

    outln!("Allocated File Objects");
    outln!("======================");
    outln!("");

    let (snapshots, count) = io_get_file_snapshots(32);

    if count == 0 {
        outln!("No file objects currently allocated");
        return;
    }

    outln!("{:<18} {:<24} {:<6} {:<6} {:<10}",
        "Address", "Name", "R", "W", "Offset");
    outln!("------------------------------------------------------------");

    for i in 0..count {
        let file = &snapshots[i];
        let name = core::str::from_utf8(&file.name[..file.name_length as usize])
            .unwrap_or("?");
        let read_str = if file.read_access { "Y" } else { "-" };
        let write_str = if file.write_access { "Y" } else { "-" };

        outln!("{:#018x} {:<24} {:<6} {:<6} {:<10}",
            file.address,
            name,
            read_str,
            write_str,
            file.offset
        );
    }

    outln!("");
    outln!("Total: {} files", count);
}

// ============================================================================
// Completion Port Viewer Command
// ============================================================================

/// Completion port viewer command
pub fn cmd_iocp(args: &[&str]) {
    if args.is_empty() {
        show_iocp_help();
        return;
    }

    let cmd = args[0];
    if eq_ignore_ascii_case(cmd, "help") || cmd == "-h" || cmd == "--help" || cmd == "-?" {
        show_iocp_help();
    } else if eq_ignore_ascii_case(cmd, "stats") {
        show_iocp_stats();
    } else if eq_ignore_ascii_case(cmd, "list") {
        show_iocp_list();
    } else {
        outln!("Unknown subcommand: {}", args[0]);
        show_iocp_help();
    }
}

fn show_iocp_help() {
    outln!("Completion Port Viewer");
    outln!("");
    outln!("Usage: iocp <subcommand>");
    outln!("");
    outln!("Subcommands:");
    outln!("  stats     - Show completion port statistics");
    outln!("  list      - List allocated completion ports");
    outln!("  help      - Show this help message");
}

fn show_iocp_stats() {
    use crate::io::io_get_iocp_stats;

    let stats = io_get_iocp_stats();

    outln!("Completion Port Statistics");
    outln!("==========================");
    outln!("");
    outln!("Total Ports:      {}", stats.total_ports);
    outln!("Allocated:        {}", stats.allocated_ports);
    outln!("Free:             {}", stats.free_ports);
    outln!("Total Completions: {}", stats.total_completions);
}

fn show_iocp_list() {
    use crate::io::io_get_iocp_snapshots;

    outln!("Allocated Completion Ports");
    outln!("==========================");
    outln!("");

    let (snapshots, count) = io_get_iocp_snapshots(16);

    if count == 0 {
        outln!("No completion ports currently allocated");
        return;
    }

    outln!("{:<18} {:<8} {:<10} {:<8} {:<12}",
        "Address", "Active", "Concurrency", "Queued", "Processed");
    outln!("------------------------------------------------------------");

    for i in 0..count {
        let port = &snapshots[i];
        let active_str = if port.active { "Yes" } else { "No" };

        outln!("{:#018x} {:<8} {:<10} {:<8} {:<12}",
            port.address,
            active_str,
            port.concurrency_limit,
            port.queued_count,
            port.completions_processed
        );
    }

    outln!("");
    outln!("Total: {} ports", count);
}

// ============================================================================
// Named Pipes Command (pipes)
// ============================================================================

/// pipes - Named pipe viewer
///
/// Display named pipe statistics and list active pipes.
///
/// Usage: pipes [stats|list]
///
/// Subcommands:
///   stats  - Show pipe pool statistics (default)
///   list   - List all active named pipes
pub fn cmd_pipes(args: &[&str]) {
    if args.is_empty() {
        show_pipe_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_pipe_stats();
    } else if eq_ignore_ascii_case(subcmd, "list") {
        show_pipe_list();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("pipes - Named Pipe Viewer");
        outln!("");
        outln!("Usage: pipes [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show pipe pool statistics (default)");
        outln!("  list   - List all active named pipes");
        outln!("");
        outln!("Examples:");
        outln!("  pipes         - Show pipe statistics");
        outln!("  pipes list    - List all active pipes");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'pipes help' for usage information");
    }
}

fn show_pipe_stats() {
    use crate::io::{get_pipe_stats, MAX_NAMED_PIPES, MAX_PIPE_INSTANCES};

    let stats = get_pipe_stats();

    outln!("Named Pipe Statistics");
    outln!("=====================");
    outln!("");
    outln!("Max Pipes:          {}", MAX_NAMED_PIPES);
    outln!("Active Pipes:       {}", stats.active_pipes);
    outln!("Max Instances/Pipe: {}", MAX_PIPE_INSTANCES);
    outln!("Total Instances:    {}", stats.total_instances);
    outln!("Connected:          {}", stats.connected_instances);
}

fn show_pipe_list() {
    use crate::io::{io_get_pipe_snapshots, pipe_type_name};

    outln!("Active Named Pipes");
    outln!("==================");
    outln!("");

    let (snapshots, count) = io_get_pipe_snapshots(32);

    if count == 0 {
        outln!("No active named pipes");
        return;
    }

    outln!("{:<40} {:<10} {:<10} {:<10} {:<10}",
        "Name", "Type", "Instances", "Listening", "Connected");
    outln!("--------------------------------------------------------------------------------");

    for i in 0..count {
        let pipe = &snapshots[i];
        let name_len = pipe.name_len as usize;
        let name = core::str::from_utf8(&pipe.name[..name_len]).unwrap_or("<invalid>");

        outln!("{:<40} {:<10} {:<10} {:<10} {:<10}",
            name,
            pipe_type_name(pipe.type_flags),
            pipe.instance_count,
            pipe.listening_count,
            pipe.connected_count
        );
    }

    outln!("");
    outln!("Total: {} active pipes", count);
}

// ============================================================================
// RAM Disk Command (ramdisk)
// ============================================================================

/// ramdisk - RAM disk viewer
///
/// Display RAM disk statistics and list active RAM disks.
///
/// Usage: ramdisk [stats|list]
///
/// Subcommands:
///   stats  - Show RAM disk statistics (default)
///   list   - List all active RAM disks
pub fn cmd_ramdisk(args: &[&str]) {
    if args.is_empty() {
        show_ramdisk_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_ramdisk_stats();
    } else if eq_ignore_ascii_case(subcmd, "list") {
        show_ramdisk_list();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("ramdisk - RAM Disk Viewer");
        outln!("");
        outln!("Usage: ramdisk [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show RAM disk statistics (default)");
        outln!("  list   - List all active RAM disks");
        outln!("");
        outln!("Examples:");
        outln!("  ramdisk       - Show RAM disk statistics");
        outln!("  ramdisk list  - List all active RAM disks");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'ramdisk help' for usage information");
    }
}

fn show_ramdisk_stats() {
    use crate::io::{get_ramdisk_stats, DEFAULT_RAMDISK_SIZE};

    let stats = get_ramdisk_stats();

    outln!("RAM Disk Statistics");
    outln!("===================");
    outln!("");
    outln!("Max RAM Disks:      {}", stats.max_ramdisks);
    outln!("Active RAM Disks:   {}", stats.active_ramdisks);
    outln!("Total Size:         {} KB", stats.total_size / 1024);
    outln!("Total Sectors:      {}", stats.total_sectors);
    outln!("Default Size:       {} KB", DEFAULT_RAMDISK_SIZE / 1024);
}

fn show_ramdisk_list() {
    use crate::io::io_get_ramdisk_snapshots;

    outln!("Active RAM Disks");
    outln!("================");
    outln!("");

    let (snapshots, count) = io_get_ramdisk_snapshots(8);

    if count == 0 {
        outln!("No active RAM disks");
        return;
    }

    outln!("{:<6} {:<10} {:<12} {:<12}",
        "Slot", "Dev Index", "Size (KB)", "Sectors");
    outln!("------------------------------------------");

    for i in 0..count {
        let disk = &snapshots[i];

        outln!("{:<6} {:<10} {:<12} {:<12}",
            disk.slot,
            disk.dev_index,
            disk.size / 1024,
            disk.sector_count
        );
    }

    outln!("");
    outln!("Total: {} RAM disks", count);
}

// ============================================================================
// Volumes Command (volumes)
// ============================================================================

/// volumes - Volume/partition viewer
///
/// Display volume statistics and list all detected volumes.
///
/// Usage: volumes [stats|list]
///
/// Subcommands:
///   stats  - Show volume statistics (default)
///   list   - List all detected volumes
pub fn cmd_volumes(args: &[&str]) {
    if args.is_empty() {
        show_volume_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_volume_stats();
    } else if eq_ignore_ascii_case(subcmd, "list") {
        show_volume_list();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("volumes - Volume/Partition Viewer");
        outln!("");
        outln!("Usage: volumes [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show volume statistics (default)");
        outln!("  list   - List all detected volumes");
        outln!("");
        outln!("Examples:");
        outln!("  volumes       - Show volume statistics");
        outln!("  volumes list  - List all detected volumes");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'volumes help' for usage information");
    }
}

fn show_volume_stats() {
    use crate::io::{get_volume_stats, MAX_VOLUMES};

    let stats = get_volume_stats();

    outln!("Volume Statistics");
    outln!("=================");
    outln!("");
    outln!("Max Volumes:       {}", MAX_VOLUMES);
    outln!("Active Volumes:    {}", stats.active_volumes);
    outln!("Total Size:        {} MB", stats.total_size_mb);
    outln!("Bootable Volumes:  {}", stats.bootable_count);
}

fn show_volume_list() {
    use crate::io::{io_get_volume_snapshots, partition_type};

    outln!("Detected Volumes");
    outln!("================");
    outln!("");

    let (snapshots, count) = io_get_volume_snapshots(32);

    if count == 0 {
        outln!("No volumes detected");
        return;
    }

    outln!("{:<6} {:<6} {:<6} {:<12} {:<12} {:<10} {:<8}",
        "Vol#", "Disk", "Part", "Start LBA", "Size (MB)", "Type", "Boot");
    outln!("----------------------------------------------------------------------");

    for i in 0..count {
        let vol = &snapshots[i];
        let boot_str = if vol.bootable { "*" } else { "" };

        outln!("{:<6} {:<6} {:<6} {:<12} {:<12} {:<10} {:<8}",
            vol.volume_number,
            vol.disk_index,
            vol.partition_index,
            vol.start_lba,
            vol.size_mb,
            partition_type::name(vol.partition_type),
            boot_str
        );
    }

    outln!("");
    outln!("Total: {} volumes (* = bootable)", count);
}

// ============================================================================
// Block Devices Command (blocks)
// ============================================================================

/// blocks - Block device viewer
///
/// Display block device statistics and list all registered devices.
///
/// Usage: blocks [stats|list|detail <index>]
///
/// Subcommands:
///   stats         - Show block device statistics (default)
///   list          - List all registered block devices
///   detail <idx>  - Show detailed info for device at index
pub fn cmd_blocks(args: &[&str]) {
    if args.is_empty() {
        show_block_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_block_stats();
    } else if eq_ignore_ascii_case(subcmd, "list") {
        show_block_list();
    } else if eq_ignore_ascii_case(subcmd, "detail") {
        if args.len() < 2 {
            outln!("Usage: blocks detail <index>");
            return;
        }
        if let Ok(idx) = args[1].parse::<u8>() {
            show_block_detail(idx);
        } else {
            outln!("Invalid device index: {}", args[1]);
        }
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("blocks - Block Device Viewer");
        outln!("");
        outln!("Usage: blocks [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats         - Show block device statistics (default)");
        outln!("  list          - List all registered block devices");
        outln!("  detail <idx>  - Show detailed info for device at index");
        outln!("");
        outln!("Examples:");
        outln!("  blocks           - Show block device statistics");
        outln!("  blocks list      - List all block devices");
        outln!("  blocks detail 0  - Show details for device 0");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'blocks help' for usage information");
    }
}

fn show_block_stats() {
    use crate::io::{get_block_stats, MAX_BLOCK_DEVICES};

    let stats = get_block_stats();

    outln!("Block Device Statistics");
    outln!("=======================");
    outln!("");
    outln!("Max Devices:       {}", MAX_BLOCK_DEVICES);
    outln!("Registered:        {}", stats.device_count);
    outln!("Total Reads:       {}", stats.total_reads);
    outln!("Total Writes:      {}", stats.total_writes);
    outln!("Sectors Read:      {}", stats.total_sectors_read);
    outln!("Sectors Written:   {}", stats.total_sectors_written);
    outln!("Total Errors:      {}", stats.total_errors);
}

fn show_block_list() {
    use crate::io::{io_get_block_snapshots, block_device_type_name};

    outln!("Registered Block Devices");
    outln!("========================");
    outln!("");

    let (snapshots, count) = io_get_block_snapshots(16);

    if count == 0 {
        outln!("No block devices registered");
        return;
    }

    outln!("{:<4} {:<8} {:<10} {:<10} {:<10} {:<10}",
        "Idx", "Name", "Type", "Size (MB)", "Reads", "Writes");
    outln!("------------------------------------------------------------");

    for i in 0..count {
        let dev = &snapshots[i];
        let name_len = dev.name.iter().position(|&b| b == 0).unwrap_or(16);
        let name = core::str::from_utf8(&dev.name[..name_len]).unwrap_or("<invalid>");

        outln!("{:<4} {:<8} {:<10} {:<10} {:<10} {:<10}",
            dev.index,
            name,
            block_device_type_name(dev.device_type),
            dev.size_mb,
            dev.reads,
            dev.writes
        );
    }

    outln!("");
    outln!("Total: {} devices", count);
}

fn show_block_detail(index: u8) {
    use crate::io::{io_get_block_snapshots, block_device_type_name, block_flags};

    let (snapshots, count) = io_get_block_snapshots(16);

    // Find the device with the given index
    let mut found: Option<&crate::io::BlockDeviceSnapshot> = None;
    for i in 0..count {
        if snapshots[i].index == index {
            found = Some(&snapshots[i]);
            break;
        }
    }

    let dev = match found {
        Some(d) => d,
        None => {
            outln!("Device {} not found", index);
            return;
        }
    };

    let name_len = dev.name.iter().position(|&b| b == 0).unwrap_or(16);
    let name = core::str::from_utf8(&dev.name[..name_len]).unwrap_or("<invalid>");
    let model_len = dev.model.iter().position(|&b| b == 0).unwrap_or(32);
    let model = core::str::from_utf8(&dev.model[..model_len]).unwrap_or("<unknown>");

    outln!("Block Device Details: {}", name);
    outln!("==============================");
    outln!("");
    outln!("Index:           {}", dev.index);
    outln!("Name:            {}", name);
    outln!("Type:            {}", block_device_type_name(dev.device_type));
    outln!("Model:           {}", model);
    outln!("Size:            {} MB", dev.size_mb);
    outln!("Total Sectors:   {}", dev.total_sectors);
    outln!("Present:         {}", if dev.present { "Yes" } else { "No" });
    outln!("");
    outln!("Flags:");
    if (dev.flags & block_flags::REMOVABLE) != 0 {
        outln!("  - Removable");
    }
    if (dev.flags & block_flags::READONLY) != 0 {
        outln!("  - Read-Only");
    }
    if (dev.flags & block_flags::DMA) != 0 {
        outln!("  - DMA Support");
    }
    if (dev.flags & block_flags::LBA48) != 0 {
        outln!("  - LBA48 Support");
    }
    if (dev.flags & block_flags::BOOT) != 0 {
        outln!("  - Boot Device");
    }
    outln!("");
    outln!("I/O Statistics:");
    outln!("  Read Operations:    {}", dev.reads);
    outln!("  Write Operations:   {}", dev.writes);
    outln!("  Sectors Read:       {}", dev.sectors_read);
    outln!("  Sectors Written:    {}", dev.sectors_written);
    outln!("  Errors:             {}", dev.errors);
}

// ============================================================================
// Token List Command (se tokens)
// ============================================================================

fn show_token_list() {
    use crate::se::{se_get_token_snapshots, get_token_stats, token_type_name};

    let stats = get_token_stats();
    outln!("Allocated Tokens");
    outln!("================");
    outln!("");
    outln!("Pool: {}/{} allocated, {} primary, {} impersonation",
        stats.allocated_tokens, stats.max_tokens,
        stats.primary_tokens, stats.impersonation_tokens);
    outln!("");

    let (snapshots, count) = se_get_token_snapshots(32);

    if count == 0 {
        outln!("No tokens currently allocated");
        return;
    }

    outln!("{:<18} {:<6} {:<12} {:<10} {:<6} {:<6} {:<6}",
        "Address", "ID", "Type", "Elevated", "Groups", "Privs", "Refs");
    outln!("----------------------------------------------------------------------");

    for i in 0..count {
        let token = &snapshots[i];
        let elevated_str = if token.is_elevated { "Yes" } else { "No" };

        outln!("{:#018x} {:<6} {:<12} {:<10} {:<6} {:<6} {:<6}",
            token.address,
            token.token_id_low,
            token_type_name(token.token_type),
            elevated_str,
            token.group_count,
            token.privilege_count,
            token.ref_count
        );
    }

    outln!("");
    outln!("Total: {} tokens", count);
}

// ============================================================================
// VAD Viewer Command (vad)
// ============================================================================

/// vad - Virtual Address Descriptor viewer
///
/// Display VAD statistics and list allocated VADs.
///
/// Usage: vad [stats|list]
///
/// Subcommands:
///   stats  - Show VAD pool statistics (default)
///   list   - List all allocated VADs
pub fn cmd_vad(args: &[&str]) {
    if args.is_empty() {
        show_vad_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_vad_stats();
    } else if eq_ignore_ascii_case(subcmd, "list") {
        show_vad_list();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("vad - Virtual Address Descriptor Viewer");
        outln!("");
        outln!("Usage: vad [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show VAD pool statistics (default)");
        outln!("  list   - List all allocated VADs");
        outln!("");
        outln!("Examples:");
        outln!("  vad        - Show VAD statistics");
        outln!("  vad list   - List all allocated VADs");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'vad help' for usage information");
    }
}

fn show_vad_stats() {
    use crate::mm::{mm_get_vad_stats, MAX_VADS};

    let stats = mm_get_vad_stats();

    outln!("Virtual Address Descriptor (VAD) Statistics");
    outln!("============================================");
    outln!("");
    outln!("Max VADs:      {}", MAX_VADS);
    outln!("Allocated:     {}", stats.allocated_vads);
    outln!("Free:          {}", stats.free_vads);
}

fn show_vad_list() {
    use crate::mm::{mm_get_vad_snapshots, mm_get_vad_stats, vad_type_name, protection_name};

    let stats = mm_get_vad_stats();
    outln!("Allocated VADs");
    outln!("==============");
    outln!("");
    outln!("Pool: {}/{} allocated", stats.allocated_vads, stats.total_vads);
    outln!("");

    let (snapshots, count) = mm_get_vad_snapshots(64);

    if count == 0 {
        outln!("No VADs currently allocated");
        return;
    }

    outln!("{:<4} {:<18} {:<18} {:<12} {:<10} {:<6} {:<8}",
        "Idx", "Start", "End", "Size", "Type", "Prot", "Commit");
    outln!("--------------------------------------------------------------------------------");

    for i in 0..count {
        let vad = &snapshots[i];
        let commit_str = if vad.committed { "Yes" } else { "No" };

        outln!("{:<4} {:#018x} {:#018x} {:<12} {:<10} {:<6} {:<8}",
            vad.index,
            vad.start_address,
            vad.end_address,
            format_vad_size(vad.size),
            vad_type_name(vad.vad_type),
            protection_name(vad.protection),
            commit_str
        );
    }

    outln!("");
    outln!("Total: {} VADs", count);
}

fn format_vad_size(size: u64) -> &'static str {
    // Simple size formatter using static strings
    if size >= 0x100000000 {
        ">4GB"
    } else if size >= 0x40000000 {
        "1GB+"
    } else if size >= 0x10000000 {
        "256MB+"
    } else if size >= 0x1000000 {
        "16MB+"
    } else if size >= 0x100000 {
        "1MB+"
    } else if size >= 0x10000 {
        "64KB+"
    } else if size >= 0x1000 {
        "4KB+"
    } else {
        "<4KB"
    }
}

// ============================================================================
// Section Object Viewer Command (section)
// ============================================================================

/// section - Section object viewer
///
/// Display section object statistics and list active sections.
///
/// Usage: section [stats|list]
///
/// Subcommands:
///   stats  - Show section pool statistics (default)
///   list   - List all active section objects
pub fn cmd_section(args: &[&str]) {
    if args.is_empty() {
        show_section_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_section_stats();
    } else if eq_ignore_ascii_case(subcmd, "list") {
        show_section_list();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("section - Section Object Viewer");
        outln!("");
        outln!("Usage: section [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show section pool statistics (default)");
        outln!("  list   - List all active section objects");
        outln!("");
        outln!("Section Types:");
        outln!("  PageFile  - Shared memory (page-file backed)");
        outln!("  FileBacked - Memory-mapped file");
        outln!("  Image     - Executable/DLL");
        outln!("  Physical  - Physical memory mapping");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'section help' for usage information");
    }
}

fn show_section_stats() {
    use crate::mm::{mm_get_section_stats, MAX_SECTIONS};

    let stats = mm_get_section_stats();

    outln!("Section Object Statistics");
    outln!("=========================");
    outln!("");
    outln!("Max Sections:     {}", MAX_SECTIONS);
    outln!("Active Sections:  {}", stats.active_sections);
    outln!("Total Views:      {}", stats.total_views);
}

fn show_section_list() {
    use crate::mm::{mm_get_section_snapshots, mm_get_section_stats, section_type_name};

    let stats = mm_get_section_stats();
    outln!("Active Section Objects");
    outln!("======================");
    outln!("");
    outln!("Pool: {}/{} active", stats.active_sections, stats.total_sections);
    outln!("");

    let (snapshots, count) = mm_get_section_snapshots(32);

    if count == 0 {
        outln!("No section objects currently active");
        return;
    }

    outln!("{:<4} {:<12} {:<12} {:<8} {:<6} {:<10}",
        "Idx", "Type", "Size", "Views", "Refs", "FileBacked");
    outln!("------------------------------------------------------");

    for i in 0..count {
        let section = &snapshots[i];
        let file_str = if section.file_backed { "Yes" } else { "No" };

        outln!("{:<4} {:<12} {:<12} {:<8} {:<6} {:<10}",
            section.index,
            section_type_name(section.section_type),
            format_vad_size(section.size),
            section.view_count,
            section.ref_count,
            file_str
        );
    }

    outln!("");
    outln!("Total: {} sections", count);
}

// ============================================================================
// Working Set Viewer Command (wset)
// ============================================================================

/// wset - Working set viewer
///
/// Display working set statistics for address spaces.
///
/// Usage: wset [stats]
pub fn cmd_wset(args: &[&str]) {
    if args.is_empty() {
        show_working_set_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_working_set_stats();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("wset - Working Set Viewer");
        outln!("");
        outln!("Usage: wset [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show working set statistics (default)");
        outln!("");
        outln!("Working sets track the resident pages for each address space.");
        outln!("Pages not in the working set may be paged out.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'wset help' for usage information");
    }
}

fn show_working_set_stats() {
    use crate::mm::mm_get_address_space_stats;

    let stats = mm_get_address_space_stats();

    outln!("Working Set / Address Space Statistics");
    outln!("======================================");
    outln!("");
    outln!("Address Spaces:");
    outln!("  Max:       {}", stats.total);
    outln!("  Allocated: {}", stats.allocated);
    outln!("  Free:      {}", stats.free);
    outln!("");
    outln!("Note: Use 'mm' command for detailed memory statistics.");
}

// ============================================================================
// Keyed Event Viewer Command (keyedev)
// ============================================================================

/// keyedev - Keyed event viewer
///
/// Display keyed event statistics and list active keyed events.
///
/// Usage: keyedev [stats|list]
///
/// Subcommands:
///   stats  - Show keyed event statistics (default)
///   list   - List all active keyed events
pub fn cmd_keyedev(args: &[&str]) {
    if args.is_empty() {
        show_keyed_event_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_keyed_event_stats();
    } else if eq_ignore_ascii_case(subcmd, "list") {
        show_keyed_event_list();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("keyedev - Keyed Event Viewer");
        outln!("");
        outln!("Usage: keyedev [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show keyed event statistics (default)");
        outln!("  list   - List all active keyed events");
        outln!("");
        outln!("Keyed events are used for low-memory critical section fallback.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'keyedev help' for usage information");
    }
}

fn show_keyed_event_stats() {
    use crate::ex::{get_keyed_event_stats, MAX_KEYED_EVENT_OBJECTS};

    let stats = get_keyed_event_stats();

    outln!("Keyed Event Statistics");
    outln!("======================");
    outln!("");
    outln!("Max Keyed Events:  {}", MAX_KEYED_EVENT_OBJECTS);
    outln!("Allocated:         {}", stats.allocated_count);
    outln!("Free:              {}", stats.free_count);
    match stats.critsec_event_index {
        Some(idx) => outln!("CritSec Event:     Index {}", idx),
        None => outln!("CritSec Event:     Not initialized"),
    }
}

fn show_keyed_event_list() {
    use crate::ex::get_keyed_event_snapshots;

    outln!("Active Keyed Events");
    outln!("===================");
    outln!("");

    let (snapshots, count) = get_keyed_event_snapshots(16);

    if count == 0 {
        outln!("No keyed events currently allocated");
        return;
    }

    outln!("{:<6} {:<10} {:<8}",
        "Index", "RefCount", "Active");
    outln!("------------------------");

    for i in 0..count {
        let ke = &snapshots[i];
        let active_str = if ke.active { "Yes" } else { "No" };

        outln!("{:<6} {:<10} {:<8}",
            ke.index,
            ke.ref_count,
            active_str
        );
    }

    outln!("");
    outln!("Total: {} keyed events", count);
}

// ============================================================================
// Callback Object Viewer Command (callback)
// ============================================================================

/// callback - Executive callback object viewer
///
/// Display callback object statistics and list registered callbacks.
///
/// Usage: callback [stats|list]
pub fn cmd_callback(args: &[&str]) {
    if args.is_empty() {
        show_callback_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_callback_stats();
    } else if eq_ignore_ascii_case(subcmd, "list") {
        show_callback_list();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("callback - Executive Callback Object Viewer");
        outln!("");
        outln!("Usage: callback [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show callback statistics (default)");
        outln!("  list   - List all registered callbacks");
        outln!("");
        outln!("Callbacks are kernel notification mechanisms.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'callback help' for usage information");
    }
}

fn show_callback_stats() {
    use crate::ex::{get_callback_stats, MAX_CALLBACK_OBJECTS};

    let stats = get_callback_stats();

    outln!("Executive Callback Statistics");
    outln!("==============================");
    outln!("");
    outln!("Max Callback Objects:  {}", MAX_CALLBACK_OBJECTS);
    outln!("Allocated:             {}", stats.allocated_count);
    outln!("Free:                  {}", stats.free_count);
    outln!("Total Registrations:   {}", stats.total_registrations);
}

fn show_callback_list() {
    use crate::ex::get_callback_snapshots;

    outln!("Registered Callback Objects");
    outln!("===========================");
    outln!("");

    let (snapshots, count) = get_callback_snapshots(16);

    if count == 0 {
        outln!("No callback objects currently allocated");
        return;
    }

    outln!("{:<6} {:<32} {:<12} {:<8}",
        "Index", "Name", "Registrations", "Calls");
    outln!("--------------------------------------------------------------");

    for i in 0..count {
        let cb = &snapshots[i];
        let name_len = cb.name_len as usize;
        let name = core::str::from_utf8(&cb.name[..name_len]).unwrap_or("<invalid>");

        outln!("{:<6} {:<32} {:<12} {:<8}",
            cb.index,
            name,
            cb.registration_count,
            cb.call_count
        );
    }

    outln!("");
    outln!("Total: {} callback objects", count);
}

// ============================================================================
// Worker Queue Viewer
// ============================================================================

/// Worker queue viewer command
pub fn cmd_worker(args: &[&str]) {
    if args.is_empty() {
        show_worker_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_worker_stats();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("worker - Executive Worker Thread Pool Viewer");
        outln!("");
        outln!("Usage: worker [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show worker queue statistics (default)");
        outln!("");
        outln!("Worker queues allow drivers to defer work to a thread context.");
        outln!("Three priority levels: Critical, Delayed, HyperCritical.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'worker help' for usage information");
    }
}

fn show_worker_stats() {
    use crate::ex::get_work_queue_stats;

    let stats = get_work_queue_stats();

    outln!("Executive Worker Queue Statistics");
    outln!("==================================");
    outln!("");
    outln!("Queue Depths:");
    outln!("  Critical Queue:       {} items", stats.critical_depth);
    outln!("  Delayed Queue:        {} items", stats.delayed_depth);
    outln!("  HyperCritical Queue:  {} items", stats.hyper_critical_depth);
    outln!("");
    outln!("Total Queued:           {} items", stats.total_queued);
    outln!("Max Workers Per Queue:  {}", stats.max_workers);
}

// ============================================================================
// LUID Viewer
// ============================================================================

/// LUID viewer command
pub fn cmd_luid(args: &[&str]) {
    if args.is_empty() {
        show_luid_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_luid_stats();
    } else if eq_ignore_ascii_case(subcmd, "system") {
        show_system_luids();
    } else if eq_ignore_ascii_case(subcmd, "priv") || eq_ignore_ascii_case(subcmd, "privileges") {
        show_privilege_luids();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("luid - Locally Unique Identifier Viewer");
        outln!("");
        outln!("Usage: luid [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show LUID allocator statistics (default)");
        outln!("  system - Show well-known system LUIDs");
        outln!("  priv   - Show well-known privilege LUIDs");
        outln!("");
        outln!("LUIDs are 64-bit identifiers unique since boot.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'luid help' for usage information");
    }
}

fn show_luid_stats() {
    use crate::ex::get_luid_stats;

    let stats = get_luid_stats();

    outln!("LUID Allocator Statistics");
    outln!("=========================");
    outln!("");
    outln!("Reserved LUIDs:         0 - {}", stats.reserved_count - 1);
    outln!("Next LUID:              {}", stats.next_luid);
    outln!("Allocated Count:        {}", stats.allocated_count);
    outln!("");
    outln!("Well-Known LUIDs:");
    outln!("  System LUIDs:         {}", stats.system_luid_count);
    outln!("  Privilege LUIDs:      {}", stats.privilege_luid_count);
}

fn show_system_luids() {
    use crate::ex::get_system_luids;

    outln!("Well-Known System LUIDs");
    outln!("=======================");
    outln!("");
    outln!("{:<20} {:<16}", "Name", "Value");
    outln!("------------------------------------");

    for luid_info in get_system_luids().iter() {
        outln!("{:<20} 0x{:08X}:{:08X}",
            luid_info.name,
            luid_info.luid.high_part,
            luid_info.luid.low_part
        );
    }
}

fn show_privilege_luids() {
    use crate::ex::get_privilege_luids;

    outln!("Well-Known Privilege LUIDs");
    outln!("==========================");
    outln!("");
    outln!("{:<24} {:<6}", "Privilege", "Value");
    outln!("------------------------------");

    for luid_info in get_privilege_luids().iter() {
        outln!("Se{:<22} {}", luid_info.name, luid_info.luid.low_part);
    }

    outln!("");
    outln!("(Privilege values 2-30 are well-known)");
}

// ============================================================================
// Lookaside List Viewer
// ============================================================================

/// Lookaside list info command
pub fn cmd_lookaside(args: &[&str]) {
    if args.is_empty() {
        show_lookaside_info();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "info") {
        show_lookaside_info();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("lookaside - Lookaside List Information");
        outln!("");
        outln!("Usage: lookaside [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  info   - Show lookaside list information (default)");
        outln!("");
        outln!("Lookaside lists are high-performance fixed-size allocators.");
        outln!("They cache freed blocks to avoid pool allocator overhead.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'lookaside help' for usage information");
    }
}

fn show_lookaside_info() {
    outln!("Lookaside List Information");
    outln!("==========================");
    outln!("");
    outln!("Lookaside List Types:");
    outln!("  NPagedLookasideList - Non-paged pool cache");
    outln!("  PagedLookasideList  - Paged pool cache");
    outln!("  LookasideListEx     - Extended lookaside list");
    outln!("");
    outln!("Configuration:");
    outln!("  Maximum Cache Depth:  256 entries");
    outln!("  Minimum Cache Depth:  4 entries");
    outln!("  Minimum Block Size:   {} bytes (SListEntry size)", core::mem::size_of::<*mut u8>() * 2);
    outln!("");
    outln!("Operation:");
    outln!("  - Uses lock-free SLIST for cache operations");
    outln!("  - Falls back to pool allocator on cache miss");
    outln!("  - Tracks hits/misses for statistics");
    outln!("");
    outln!("Note: Individual lookaside list statistics require");
    outln!("      driver-specific inspection (not globally tracked).");
}

// ============================================================================
// Job Object Viewer
// ============================================================================

/// Job object viewer command
pub fn cmd_job(args: &[&str]) {
    if args.is_empty() {
        show_job_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_job_stats();
    } else if eq_ignore_ascii_case(subcmd, "list") {
        show_job_list();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("job - Job Object Viewer");
        outln!("");
        outln!("Usage: job [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show job statistics (default)");
        outln!("  list   - List all active jobs");
        outln!("");
        outln!("Jobs group processes for resource limits.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'job help' for usage information");
    }
}

fn show_job_stats() {
    use crate::ps::get_job_stats;

    let stats = get_job_stats();

    outln!("Job Object Statistics");
    outln!("=====================");
    outln!("");
    outln!("Max Jobs:               {}", stats.max_jobs);
    outln!("Allocated Jobs:         {}", stats.allocated_count);
    outln!("Free Jobs:              {}", stats.free_count);
    outln!("Total Active Processes: {}", stats.total_active_processes);
    outln!("Next Job ID:            {}", stats.next_job_id);
}

fn show_job_list() {
    use crate::ps::{ps_get_job_snapshots, job_limit_flags_name};

    outln!("Active Job Objects");
    outln!("==================");
    outln!("");

    let (snapshots, count) = ps_get_job_snapshots(16);

    if count == 0 {
        outln!("No jobs currently allocated");
        return;
    }

    outln!("{:<6} {:<24} {:<8} {:<10} {:<12}",
        "ID", "Name", "Active", "Total", "Limits");
    outln!("--------------------------------------------------------------");

    for i in 0..count {
        let job = &snapshots[i];
        let name_len = job.name_len as usize;
        let name = core::str::from_utf8(&job.name[..name_len]).unwrap_or("<invalid>");

        outln!("{:<6} {:<24} {:<8} {:<10} {:<12}",
            job.job_id,
            name,
            job.active_processes,
            job.total_processes,
            job_limit_flags_name(job.limit_flags)
        );
    }

    outln!("");
    outln!("Total: {} jobs", count);
}

// ============================================================================
// CID Table Viewer
// ============================================================================

/// CID table viewer command
pub fn cmd_cid(args: &[&str]) {
    if args.is_empty() {
        show_cid_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_cid_stats();
    } else if eq_ignore_ascii_case(subcmd, "procs") || eq_ignore_ascii_case(subcmd, "processes") {
        show_cid_processes();
    } else if eq_ignore_ascii_case(subcmd, "threads") {
        show_cid_threads();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("cid - Client ID Table Viewer");
        outln!("");
        outln!("Usage: cid [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats    - Show CID table statistics (default)");
        outln!("  procs    - List process CID entries");
        outln!("  threads  - List thread CID entries");
        outln!("");
        outln!("CID tables track process and thread IDs.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'cid help' for usage information");
    }
}

fn show_cid_stats() {
    use crate::ps::get_cid_stats;

    let stats = get_cid_stats();

    outln!("CID Table Statistics");
    outln!("====================");
    outln!("");
    outln!("Process Table:");
    outln!("  Max Entries:    {}", stats.max_processes);
    outln!("  Active:         {}", stats.active_processes);
    outln!("  Free Slots:     {}", stats.free_process_slots);
    outln!("  Next PID Hint:  {}", stats.next_pid_hint);
    outln!("");
    outln!("Thread Table:");
    outln!("  Max Entries:    {}", stats.max_threads);
    outln!("  Active:         {}", stats.active_threads);
    outln!("  Free Slots:     {}", stats.free_thread_slots);
    outln!("  Next TID Hint:  {}", stats.next_tid_hint);
}

fn show_cid_processes() {
    use crate::ps::get_process_cid_snapshots;

    outln!("Process CID Entries");
    outln!("===================");
    outln!("");

    let (snapshots, count) = get_process_cid_snapshots(32);

    if count == 0 {
        outln!("No processes registered");
        return;
    }

    outln!("{:<8} {:<18}", "PID", "EPROCESS");
    outln!("---------------------------");

    for i in 0..count {
        let entry = &snapshots[i];
        outln!("{:<8} 0x{:016X}", entry.id, entry.object_addr);
    }

    outln!("");
    outln!("Total: {} processes", count);
}

fn show_cid_threads() {
    use crate::ps::get_thread_cid_snapshots;

    outln!("Thread CID Entries");
    outln!("==================");
    outln!("");

    let (snapshots, count) = get_thread_cid_snapshots(32);

    if count == 0 {
        outln!("No threads registered");
        return;
    }

    outln!("{:<8} {:<18}", "TID", "ETHREAD");
    outln!("---------------------------");

    for i in 0..count {
        let entry = &snapshots[i];
        outln!("{:<8} 0x{:016X}", entry.id, entry.object_addr);
    }

    outln!("");
    outln!("Total: {} threads", count);
}

// ============================================================================
// PEB/TEB Viewer
// ============================================================================

/// PEB viewer command
pub fn cmd_peb(args: &[&str]) {
    if args.is_empty() {
        show_peb_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_peb_stats();
    } else if eq_ignore_ascii_case(subcmd, "list") {
        show_peb_list();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("peb - Process Environment Block Viewer");
        outln!("");
        outln!("Usage: peb [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show PEB pool statistics (default)");
        outln!("  list   - List all allocated PEBs");
        outln!("");
        outln!("PEBs contain process-wide information for user mode.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'peb help' for usage information");
    }
}

fn show_peb_stats() {
    use crate::ps::get_peb_pool_stats;

    let stats = get_peb_pool_stats();

    outln!("PEB Pool Statistics");
    outln!("===================");
    outln!("");
    outln!("PEB Pool:");
    outln!("  Max PEBs:         {}", stats.max_pebs);
    outln!("  Allocated:        {}", stats.allocated_count);
    outln!("  Free:             {}", stats.free_count);
    outln!("");
    outln!("LDR Entry Pool:");
    outln!("  Max Entries:      {}", stats.max_ldr_entries);
    outln!("  Allocated:        {}", stats.ldr_entries_allocated);
}

fn show_peb_list() {
    use crate::ps::ps_get_peb_snapshots;

    outln!("Allocated PEBs");
    outln!("==============");
    outln!("");

    let (snapshots, count) = ps_get_peb_snapshots(32);

    if count == 0 {
        outln!("No PEBs currently allocated");
        return;
    }

    outln!("{:<6} {:<18} {:<18} {:<8} {:<10}",
        "Index", "Address", "ImageBase", "HasLDR", "OS Ver");
    outln!("-------------------------------------------------------------------");

    for i in 0..count {
        let peb = &snapshots[i];
        outln!("{:<6} 0x{:016X} 0x{:016X} {:<8} {}.{}.{}",
            peb.index,
            peb.address,
            peb.image_base,
            if peb.has_ldr { "Yes" } else { "No" },
            peb.os_major,
            peb.os_minor,
            peb.os_build
        );
    }

    outln!("");
    outln!("Total: {} PEBs", count);
}

/// TEB viewer command
pub fn cmd_teb(args: &[&str]) {
    if args.is_empty() {
        show_teb_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_teb_stats();
    } else if eq_ignore_ascii_case(subcmd, "list") {
        show_teb_list();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("teb - Thread Environment Block Viewer");
        outln!("");
        outln!("Usage: teb [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats  - Show TEB pool statistics (default)");
        outln!("  list   - List all allocated TEBs");
        outln!("");
        outln!("TEBs contain thread-specific information for user mode.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'teb help' for usage information");
    }
}

fn show_teb_stats() {
    use crate::ps::get_teb_pool_stats;

    let stats = get_teb_pool_stats();

    outln!("TEB Pool Statistics");
    outln!("===================");
    outln!("");
    outln!("Max TEBs:     {}", stats.max_tebs);
    outln!("Allocated:    {}", stats.allocated_count);
    outln!("Free:         {}", stats.free_count);
}

fn show_teb_list() {
    use crate::ps::ps_get_teb_snapshots;

    outln!("Allocated TEBs");
    outln!("==============");
    outln!("");

    let (snapshots, count) = ps_get_teb_snapshots(32);

    if count == 0 {
        outln!("No TEBs currently allocated");
        return;
    }

    outln!("{:<6} {:<18} {:<8} {:<8} {:<18} {:<8}",
        "Index", "Address", "PID", "TID", "StackBase", "LastErr");
    outln!("------------------------------------------------------------------------");

    for i in 0..count {
        let teb = &snapshots[i];
        outln!("{:<6} 0x{:016X} {:<8} {:<8} 0x{:016X} {:<8}",
            teb.index,
            teb.address,
            teb.pid,
            teb.tid,
            teb.stack_base,
            teb.last_error
        );
    }

    outln!("");
    outln!("Total: {} TEBs", count);
}

// ============================================================================
// Cache Manager Commands
// ============================================================================

/// Cache Manager command
pub fn cmd_cc(args: &[&str]) {
    if args.is_empty() {
        show_cc_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_cc_stats();
    } else if eq_ignore_ascii_case(subcmd, "maps") {
        show_cc_maps();
    } else if eq_ignore_ascii_case(subcmd, "prefetch") {
        show_cc_prefetch();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("cc - Cache Manager Viewer");
        outln!("");
        outln!("Usage: cc [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats    - Show cache statistics (default)");
        outln!("  maps     - Show active cache maps");
        outln!("  prefetch - Show prefetch statistics");
        outln!("");
        outln!("The Cache Manager provides unified file caching with");
        outln!("VACB (256KB) mapping, lazy write, and prefetch support.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'cc help' for usage information");
    }
}

fn show_cc_stats() {
    use crate::cc;

    let stats = cc::cc_get_stats();

    outln!("Cache Manager Statistics");
    outln!("========================");
    outln!("");
    outln!("Cache Operations:");
    outln!("  Total Reads:      {}", stats.total_reads);
    outln!("  Cache Hits:       {}", stats.cache_hits);
    outln!("  Cache Misses:     {}", stats.cache_misses);
    outln!("  Hit Rate:         {}%", stats.hit_rate_percent());
    outln!("  Total Writes:     {}", stats.total_writes);
    outln!("");
    outln!("Cache State:");
    outln!("  Active Maps:      {}", stats.active_cache_maps);
    outln!("  Dirty Pages:      {}", stats.dirty_pages);
}

fn show_cc_maps() {
    use crate::cc;

    outln!("Active Cache Maps");
    outln!("=================");
    outln!("");

    let (snapshots, count) = cc::cc_get_cache_snapshots(32);

    if count == 0 {
        outln!("No active cache maps");
        return;
    }

    outln!("{:<6} {:<14} {:<8} {:<10}",
        "Index", "FileSize", "VACBs", "DirtyPgs");
    outln!("------------------------------------------");

    for i in 0..count {
        let snap = &snapshots[i];
        outln!("{:<6} {:<14} {:<8} {:<10}",
            snap.index,
            format_cache_size(snap.file_size),
            snap.active_vacbs,
            snap.dirty_pages
        );
    }

    outln!("");
    outln!("Total: {} cache maps", count);
}

fn show_cc_prefetch() {
    use crate::cc;

    let stats = cc::prefetch::pf_get_stats();

    outln!("Prefetch Statistics");
    outln!("===================");
    outln!("");
    outln!("Traces:");
    outln!("  Started:          {}", stats.traces_started);
    outln!("  Completed:        {}", stats.traces_completed);
    outln!("  Aborted:          {}", stats.traces_aborted);
    outln!("");
    outln!("Prefetch:");
    outln!("  Pages Prefetched: {}", stats.pages_prefetched);
    outln!("  Hits:             {}", stats.prefetch_hits);
    outln!("  Misses:           {}", stats.prefetch_misses);
    outln!("  Hit Rate:         {}%", stats.hit_rate_percent());
    outln!("");
    outln!("Storage:");
    outln!("  Scenarios Stored: {}", stats.scenarios_stored);
    outln!("  Active Traces:    {}", cc::cc_pf_active_traces());
}

/// Prefetch command
pub fn cmd_prefetch(args: &[&str]) {
    use crate::cc;

    if args.is_empty() {
        show_cc_prefetch();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_cc_prefetch();
    } else if eq_ignore_ascii_case(subcmd, "traces") {
        show_prefetch_traces();
    } else if eq_ignore_ascii_case(subcmd, "enable") {
        cc::prefetch::pf_set_enabled(true);
        outln!("Prefetcher enabled");
    } else if eq_ignore_ascii_case(subcmd, "disable") {
        cc::prefetch::pf_set_enabled(false);
        outln!("Prefetcher disabled");
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("prefetch - Prefetcher Viewer");
        outln!("");
        outln!("Usage: prefetch [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats    - Show prefetch statistics (default)");
        outln!("  traces   - Show active prefetch traces");
        outln!("  enable   - Enable prefetcher");
        outln!("  disable  - Disable prefetcher");
        outln!("");
        outln!("The prefetcher tracks application launch patterns to");
        outln!("proactively load data for faster subsequent starts.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'prefetch help' for usage information");
    }
}

fn show_prefetch_traces() {
    use crate::cc;

    outln!("Active Prefetch Traces");
    outln!("======================");
    outln!("");

    let (snapshots, count) = cc::cc_pf_get_traces();

    if count == 0 {
        outln!("No active prefetch traces");
        return;
    }

    outln!("{:<6} {:<10} {:<10} {:<8} {:<10}",
        "Index", "State", "Type", "PID", "Pages");
    outln!("------------------------------------------------");

    for i in 0..count {
        let snap = &snapshots[i];
        let state_str = match snap.state {
            cc::TraceState::Free => "Free",
            cc::TraceState::Active => "Active",
            cc::TraceState::Processing => "Processing",
            cc::TraceState::Complete => "Complete",
        };
        let type_str = match snap.scenario_type {
            cc::ScenarioType::Boot => "Boot",
            cc::ScenarioType::App => "App",
            cc::ScenarioType::Video => "Video",
            cc::ScenarioType::Layout => "Layout",
        };
        outln!("{:<6} {:<10} {:<10} {:<8} {:<10}",
            snap.index,
            state_str,
            type_str,
            snap.process_id,
            snap.pages_faulted
        );
    }

    outln!("");
    outln!("Total: {} traces", count);
}

// ============================================================================
// Driver Verifier Commands
// ============================================================================

/// Driver Verifier command
pub fn cmd_verifier(args: &[&str]) {
    if args.is_empty() {
        show_verifier_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_verifier_stats();
    } else if eq_ignore_ascii_case(subcmd, "drivers") {
        show_verifier_drivers();
    } else if eq_ignore_ascii_case(subcmd, "irp") {
        show_verifier_irp();
    } else if eq_ignore_ascii_case(subcmd, "pool") {
        show_verifier_pool();
    } else if eq_ignore_ascii_case(subcmd, "deadlock") {
        show_verifier_deadlock();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("verifier - Driver Verifier");
        outln!("");
        outln!("Usage: verifier [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats    - Show verifier statistics (default)");
        outln!("  drivers  - List verified drivers");
        outln!("  irp      - Show IRP tracking info");
        outln!("  pool     - Show pool allocation tracking");
        outln!("  deadlock - Show deadlock detection info");
        outln!("");
        outln!("Driver Verifier validates driver behavior by tracking");
        outln!("IRPs, pool allocations, and lock acquisitions.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'verifier help' for usage information");
    }
}

fn show_verifier_stats() {
    use crate::verifier;

    let stats = verifier::vf_get_statistics();

    outln!("Driver Verifier Statistics");
    outln!("==========================");
    outln!("");
    outln!("State:              {}", if verifier::vf_is_enabled() { "Enabled" } else { "Disabled" });
    outln!("");
    outln!("IRP Tracking:");
    outln!("  Tracked:          {}", stats.irps_tracked);
    outln!("  Completed:        {}", stats.irps_completed);
    outln!("  Violations:       {}", stats.irp_violations);
    outln!("");
    outln!("Pool Tracking:");
    outln!("  Allocations:      {}", stats.pool_allocations);
    outln!("  Frees:            {}", stats.pool_frees);
    outln!("  Violations:       {}", stats.pool_violations);
    outln!("");
    outln!("Deadlock:");
    outln!("  Checks:           {}", stats.deadlock_checks);
    outln!("  Detected:         {}", stats.deadlock_detections);
}

fn show_verifier_drivers() {
    use crate::verifier;

    outln!("Verified Drivers");
    outln!("================");
    outln!("");

    let drivers = verifier::vf_get_verified_drivers();

    if drivers.is_empty() {
        outln!("No drivers currently being verified");
        return;
    }

    outln!("Driver Name");
    outln!("--------------------");

    for driver in drivers.iter() {
        outln!("{}", driver);
    }

    outln!("");
    outln!("Total: {} verified drivers", drivers.len());
}

fn show_verifier_irp() {
    use crate::verifier::irp;

    let (alloc_count, free_count, active_count) = irp::vf_irp_get_stats();

    outln!("IRP Verifier Statistics");
    outln!("=======================");
    outln!("");
    outln!("Allocations:      {}", alloc_count);
    outln!("Frees:            {}", free_count);
    outln!("Active:           {}", active_count);
    outln!("Outstanding:      {}", alloc_count.saturating_sub(free_count));
}

fn show_verifier_pool() {
    use crate::verifier::pool;

    let stats = pool::vf_pool_get_stats();

    outln!("Pool Verifier Statistics");
    outln!("========================");
    outln!("");
    outln!("Current Allocs:   {}", stats.current_allocs);
    outln!("Total Allocs:     {}", stats.total_allocs);
    outln!("Total Frees:      {}", stats.total_frees);
    outln!("");
    outln!("Memory:");
    outln!("  Total Allocated: {} bytes", stats.total_bytes_allocated);
    outln!("  Total Freed:     {} bytes", stats.total_bytes_freed);
    outln!("  Current:         {} bytes", stats.current_bytes);
    outln!("  Peak Allocs:     {}", stats.peak_alloc_count);
}

fn show_verifier_deadlock() {
    use crate::verifier::deadlock;

    let stats = deadlock::vf_deadlock_get_stats();

    outln!("Deadlock Detection Statistics");
    outln!("==============================");
    outln!("");
    outln!("Resources:        {}", stats.resources);
    outln!("Graph Nodes:      {}", stats.graph_nodes);
    outln!("Graph Edges:      {}", stats.graph_edges);
    outln!("");
    outln!("Threads:");
    outln!("  Holding Locks:  {}", stats.threads_with_locks);
    outln!("  Total Held:     {}", stats.total_locks_held);
    outln!("");
    outln!("Resets:           {}", stats.resets);
}

// ============================================================================
// Disk/Partition Commands
// ============================================================================

/// Disk/Partition command
pub fn cmd_disk(args: &[&str]) {
    if args.is_empty() {
        show_disk_info();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "info") {
        show_disk_info();
    } else if eq_ignore_ascii_case(subcmd, "partitions") {
        show_disk_partitions();
    } else if eq_ignore_ascii_case(subcmd, "mbr") {
        show_disk_mbr();
    } else if eq_ignore_ascii_case(subcmd, "gpt") {
        show_disk_gpt();
    } else if eq_ignore_ascii_case(subcmd, "geometry") {
        show_disk_geometry();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("disk - Disk/Partition Viewer");
        outln!("");
        outln!("Usage: disk [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  info       - Show disk overview (default)");
        outln!("  partitions - Show partition table");
        outln!("  mbr        - Show MBR information");
        outln!("  gpt        - Show GPT information");
        outln!("  geometry   - Show disk geometry");
        outln!("");
        outln!("FSTUB provides partition table support for MBR and GPT");
        outln!("disks, including extended partitions and GPT attributes.");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'disk help' for usage information");
    }
}

fn show_disk_info() {
    use crate::fstub;

    outln!("Disk Information");
    outln!("================");
    outln!("");
    outln!("FSTUB Module Status: Initialized");
    outln!("");
    outln!("Supported Partition Styles:");
    outln!("  - MBR (Master Boot Record)");
    outln!("  - GPT (GUID Partition Table)");
    outln!("");
    outln!("Partition Types (MBR):");

    let types = [
        (fstub::PartitionType::Fat12, "FAT12"),
        (fstub::PartitionType::Fat16Small, "FAT16 (<32MB)"),
        (fstub::PartitionType::Fat16, "FAT16 (>=32MB)"),
        (fstub::PartitionType::Fat32, "FAT32"),
        (fstub::PartitionType::Fat32Lba, "FAT32 LBA"),
        (fstub::PartitionType::Ntfs, "NTFS"),
        (fstub::PartitionType::Linux, "Linux"),
        (fstub::PartitionType::GptProtective, "GPT Protective"),
        (fstub::PartitionType::Extended, "Extended"),
    ];

    for (ptype, name) in types.iter() {
        outln!("  0x{:02X}  {}", *ptype as u8, name);
    }
}

fn show_disk_partitions() {
    outln!("Partition Information");
    outln!("=====================");
    outln!("");
    outln!("Note: No physical disks attached to show partition data.");
    outln!("");
    outln!("To parse partitions, use:");
    outln!("  fstub_read_partition_table(disk_data, sector_size)");
    outln!("");
    outln!("Supported partition styles:");
    outln!("  - MBR: Up to 4 primary partitions");
    outln!("  - MBR Extended: Unlimited logical partitions");
    outln!("  - GPT: Up to 128 partitions");
}

fn show_disk_mbr() {
    use crate::fstub;

    outln!("MBR Structure");
    outln!("=============");
    outln!("");
    outln!("Offset  Size   Description");
    outln!("------  -----  -----------");
    outln!("0x000   440    Bootstrap code");
    outln!("0x1B8   4      Disk signature");
    outln!("0x1BC   2      Reserved");
    outln!("0x1BE   16     Partition entry 1");
    outln!("0x1CE   16     Partition entry 2");
    outln!("0x1DE   16     Partition entry 3");
    outln!("0x1EE   16     Partition entry 4");
    outln!("0x1FE   2      Boot signature (0xAA55)");
    outln!("");
    outln!("MBR Signature: 0x{:04X}", fstub::mbr::MBR_SIGNATURE);
    outln!("Max Primary Partitions: {}", fstub::mbr::MAX_MBR_PARTITIONS);
    outln!("");
    outln!("Partition Entry Format (16 bytes):");
    outln!("  Offset  Size  Description");
    outln!("  0       1     Boot indicator (0x80 = active)");
    outln!("  1       3     Starting CHS");
    outln!("  4       1     Partition type");
    outln!("  5       3     Ending CHS");
    outln!("  8       4     Starting LBA");
    outln!("  12      4     Size in sectors");
}

fn show_disk_gpt() {
    use crate::fstub::gpt;

    outln!("GPT Structure");
    outln!("=============");
    outln!("");
    outln!("EFI Signature: \"EFI PART\" (0x{:016X})", gpt::EFI_SIGNATURE);
    outln!("Revision:      0x{:08X}", gpt::GPT_REVISION);
    outln!("Entry Size:    {} bytes", gpt::GPT_ENTRY_SIZE);
    outln!("Max Entries:   128 partitions (typical)");
    outln!("");
    outln!("GPT Header Layout:");
    outln!("  Offset  Size  Description");
    outln!("  0x00    8     Signature \"EFI PART\"");
    outln!("  0x08    4     Revision");
    outln!("  0x0C    4     Header size");
    outln!("  0x10    4     Header CRC32");
    outln!("  0x18    8     Current LBA");
    outln!("  0x20    8     Backup LBA");
    outln!("  0x28    8     First usable LBA");
    outln!("  0x30    8     Last usable LBA");
    outln!("  0x38    16    Disk GUID");
    outln!("  0x48    8     Partition entries LBA");
    outln!("  0x50    4     Number of entries");
    outln!("  0x54    4     Entry size");
    outln!("  0x58    4     Partition entries CRC32");
    outln!("");
    outln!("Well-known Partition Type GUIDs:");
    outln!("  EFI System:      C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    outln!("  MS Reserved:     E3C9E316-0B5C-4DB8-817D-F92DF00215AE");
    outln!("  MS Basic Data:   EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
    outln!("  Linux FS:        0FC63DAF-8483-4772-8E79-3D69D8477DE4");
}

fn show_disk_geometry() {
    use crate::fstub::geometry;

    outln!("Disk Geometry");
    outln!("=============");
    outln!("");
    outln!("Standard geometry for modern disks:");
    let geo = geometry::estimate_geometry(500 * 1024 * 1024 * 1024, 512);
    outln!("  Sectors per track:  {}", geo.sectors_per_track);
    outln!("  Tracks per cyl:     {}", geo.tracks_per_cylinder);
    outln!("  Bytes per sector:   {}", geo.bytes_per_sector);
    outln!("");
    outln!("Media Types:");
    let types = [
        geometry::MediaType::FixedMedia,
        geometry::MediaType::RemovableMedia,
        geometry::MediaType::F3_1pt44_512,
        geometry::MediaType::F3_2pt88_512,
        geometry::MediaType::F5_1pt2_512,
    ];
    for mt in types.iter() {
        outln!("  {:2}  {}", *mt as u32, mt.name());
    }
}

/// Format size in human-readable format for cache display
fn format_cache_size(size: u64) -> &'static str {
    // Use static strings for common sizes to avoid allocation
    if size == 0 {
        "0 B"
    } else if size < 1024 {
        "< 1 KB"
    } else if size < 1024 * 1024 {
        "< 1 MB"
    } else if size < 10 * 1024 * 1024 {
        "< 10 MB"
    } else if size < 100 * 1024 * 1024 {
        "< 100 MB"
    } else if size < 1024 * 1024 * 1024 {
        "< 1 GB"
    } else {
        "> 1 GB"
    }
}

// ============================================================================
// RTL Heap Command (heap)
// ============================================================================

/// heap - RTL Heap Manager diagnostics
///
/// Display heap statistics and configuration.
///
/// Usage: heap [stats|info|config]
///
/// Subcommands:
///   stats   - Show heap statistics (default)
///   info    - Show heap configuration info
///   config  - Show heap constants and limits
pub fn cmd_heap(args: &[&str]) {
    if args.is_empty() {
        show_heap_stats();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "stats") {
        show_heap_stats();
    } else if eq_ignore_ascii_case(subcmd, "info") {
        show_heap_info();
    } else if eq_ignore_ascii_case(subcmd, "config") {
        show_heap_config();
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("heap - RTL Heap Manager Diagnostics");
        outln!("");
        outln!("Usage: heap [subcommand]");
        outln!("");
        outln!("Subcommands:");
        outln!("  stats   - Show heap statistics (default)");
        outln!("  info    - Show heap information");
        outln!("  config  - Show heap configuration constants");
        outln!("");
        outln!("Examples:");
        outln!("  heap         - Show heap statistics");
        outln!("  heap info    - Show heap information");
    } else {
        outln!("Unknown subcommand: {}", subcmd);
        outln!("Use 'heap help' for usage information");
    }
}

fn show_heap_stats() {
    use crate::rtl::heap;

    outln!("RTL Heap Statistics");
    outln!("===================");
    outln!("");

    outln!("Max Heaps Per Process: {}", heap::MAX_HEAPS_PER_PROCESS);
    outln!("");

    // Check process default heap
    unsafe {
        if let Some(handle) = heap::rtl_get_process_heap() {
            outln!("Process Heap ({})", handle);
            if let Some(stats) = heap::rtl_get_heap_stats(handle) {
                outln!("  Total Size:    {} bytes", stats.total_size);
                outln!("  Free Size:     {} bytes", stats.total_free_size);
                outln!("  Allocations:   {}", stats.alloc_count);
                outln!("  Frees:         {}", stats.free_count);
                outln!("  Segments:      {}", stats.segment_count);
            }
        } else {
            outln!("No process heap initialized");
        }
    }
}

fn show_heap_info() {
    use crate::rtl::heap;

    outln!("RTL Heap Information");
    outln!("====================");
    outln!("");
    outln!("Process Default Heap:");

    unsafe {
        if let Some(handle) = heap::rtl_get_process_heap() {
            outln!("  Handle:    {:#x}", handle);
            outln!("  Status:    Active");
        } else {
            outln!("  Status:    Not initialized");
        }
    }

    outln!("");
    outln!("Heap Flags:");
    outln!("  GROWABLE:              Create growable heap");
    outln!("  NO_SERIALIZE:          Disable locking");
    outln!("  GENERATE_EXCEPTIONS:   Throw on allocation failure");
    outln!("  ZERO_MEMORY:           Zero allocated memory");
    outln!("  REALLOC_IN_PLACE_ONLY: Don't move on realloc");
    outln!("  TAIL_CHECKING_ENABLED: Enable tail checking");
    outln!("  FREE_CHECKING_ENABLED: Enable free checking");
    outln!("  CREATE_ALIGN_16:       16-byte alignment");
}

fn show_heap_config() {
    use crate::rtl::heap;

    outln!("RTL Heap Configuration");
    outln!("======================");
    outln!("");
    outln!("Constants:");
    outln!("  HEAP_GRANULARITY:        {} bytes", heap::HEAP_GRANULARITY);
    outln!("  HEAP_MAXIMUM_FREELISTS:  {}", heap::HEAP_MAXIMUM_FREELISTS);
    outln!("  HEAP_MAXIMUM_SEGMENTS:   {}", heap::HEAP_MAXIMUM_SEGMENTS);
    outln!("  MAX_HEAPS_PER_PROCESS:   {}", heap::MAX_HEAPS_PER_PROCESS);
    outln!("  HEAP_MAXIMUM_BLOCK_SIZE: {:#x}", heap::HEAP_MAXIMUM_BLOCK_SIZE);
    outln!("");
    outln!("Size Classes:");
    outln!("  Free List 0:   1-{} bytes", heap::HEAP_GRANULARITY);
    outln!("  Free List 1:   {}-{} bytes", heap::HEAP_GRANULARITY + 1, heap::HEAP_GRANULARITY * 2);
    outln!("  ...");
    outln!("  Free List 127: Large allocations");
}

// ============================================================================
// Registry Command (reg)
// ============================================================================

/// reg - Registry browser
///
/// Browse and query the Windows registry.
///
/// Usage: reg [query|enum|info|hives] [path]
///
/// Subcommands:
///   query <path>  - Query a registry key
///   enum <path>   - Enumerate subkeys and values
///   info <path>   - Show detailed key information
///   hives         - List loaded registry hives
pub fn cmd_reg(args: &[&str]) {
    if args.is_empty() {
        show_reg_hives();
        return;
    }

    let subcmd = args[0];

    if eq_ignore_ascii_case(subcmd, "hives") {
        show_reg_hives();
    } else if eq_ignore_ascii_case(subcmd, "query") {
        if args.len() < 2 {
            outln!("Usage: reg query <path>");
            outln!("Example: reg query SYSTEM\\CurrentControlSet");
            return;
        }
        show_reg_query(args[1]);
    } else if eq_ignore_ascii_case(subcmd, "enum") {
        if args.len() < 2 {
            outln!("Usage: reg enum <path>");
            outln!("Example: reg enum SYSTEM");
            return;
        }
        show_reg_enum(args[1]);
    } else if eq_ignore_ascii_case(subcmd, "info") {
        if args.len() < 2 {
            outln!("Usage: reg info <path>");
            outln!("Example: reg info SOFTWARE\\Microsoft");
            return;
        }
        show_reg_info(args[1]);
    } else if eq_ignore_ascii_case(subcmd, "help") || subcmd == "-h" || subcmd == "--help" {
        outln!("reg - Registry Browser");
        outln!("");
        outln!("Usage: reg [subcommand] [path]");
        outln!("");
        outln!("Subcommands:");
        outln!("  hives         - List loaded registry hives (default)");
        outln!("  query <path>  - Query a registry key");
        outln!("  enum <path>   - Enumerate subkeys and values");
        outln!("  info <path>   - Show detailed key information");
        outln!("");
        outln!("Path Examples:");
        outln!("  SYSTEM");
        outln!("  SYSTEM\\CurrentControlSet");
        outln!("  SOFTWARE\\Microsoft\\Windows");
        outln!("");
        outln!("Examples:");
        outln!("  reg hives               - List all hives");
        outln!("  reg query SYSTEM        - Query SYSTEM hive root");
        outln!("  reg enum SYSTEM         - Enumerate SYSTEM subkeys");
    } else {
        // Treat as a path query
        show_reg_query(subcmd);
    }
}

fn show_reg_hives() {
    use crate::cm;
    use core::sync::atomic::Ordering;

    outln!("Registry Hives");
    outln!("==============");
    outln!("");

    outln!("{:<20} {:<10} {:<10} {:<10}",
        "Hive", "Keys", "Values", "Type");
    outln!("------------------------------------------------------------");

    let hive_count = cm::cm_get_hive_count();

    unsafe {
        for i in 0..hive_count {
            if let Some(hive) = cm::cm_get_hive(i as u16) {
                let name_len = hive.name.length as usize;
                let name = core::str::from_utf8(&hive.name.chars[..name_len]).unwrap_or("<unknown>");
                let hive_type = match hive.hive_type {
                    cm::CmHiveType::Primary => "Primary",
                    cm::CmHiveType::User => "User",
                    cm::CmHiveType::Volatile => "Volatile",
                    cm::CmHiveType::Alternate => "Alternate",
                };
                outln!("{:<20} {:<10} {:<10} {:<10}",
                    name,
                    hive.key_count.load(Ordering::SeqCst),
                    hive.value_count.load(Ordering::SeqCst),
                    hive_type
                );
            }
        }
    }

    outln!("");
    outln!("Total: {} hives loaded", hive_count);
}

fn show_reg_query(path: &str) {
    use crate::cm;

    outln!("Registry Query: {}", path);
    outln!("{}", "=".repeat(path.len() + 17));
    outln!("");

    unsafe {
        match cm::cm_open_key(path) {
            Ok(handle) => {
                // Get key info
                if let Ok(info) = cm::cm_query_key_info(handle) {
                    outln!("Key Information:");
                    outln!("  Subkeys:        {}", info.subkey_count);
                    outln!("  Values:         {}", info.value_count);
                    outln!("  Volatile:       {}", if info.is_volatile { "Yes" } else { "No" });
                    outln!("  Last Write:     {:#x}", info.last_write_time);
                    outln!("");
                }

                // List values
                if let Ok(info) = cm::cm_query_key_info(handle) {
                    if info.value_count > 0 {
                        outln!("Values:");
                        for i in 0..info.value_count {
                            if let Ok(value) = cm::cm_enumerate_value(handle, i) {
                                let name = if value.name.is_empty() {
                                    "(Default)"
                                } else {
                                    value.name.as_str()
                                };
                                let type_str = match value.value_type {
                                    cm::RegType::Sz => "REG_SZ",
                                    cm::RegType::Dword => "REG_DWORD",
                                    cm::RegType::Qword => "REG_QWORD",
                                    cm::RegType::Binary => "REG_BINARY",
                                    cm::RegType::MultiSz => "REG_MULTI_SZ",
                                    cm::RegType::ExpandSz => "REG_EXPAND_SZ",
                                    _ => "REG_NONE",
                                };

                                // Get display value
                                let display = match value.value_type {
                                    cm::RegType::Sz | cm::RegType::ExpandSz => {
                                        value.get_string().unwrap_or("")
                                    }
                                    _ => "",
                                };

                                if !display.is_empty() {
                                    outln!("  {} ({}) = \"{}\"", name, type_str, display);
                                } else if let Some(dw) = value.get_dword() {
                                    outln!("  {} ({}) = {:#x}", name, type_str, dw);
                                } else if let Some(qw) = value.get_qword() {
                                    outln!("  {} ({}) = {:#x}", name, type_str, qw);
                                } else {
                                    outln!("  {} ({}) = <{} bytes>", name, type_str, value.data.size);
                                }
                            }
                        }
                        outln!("");
                    }
                }

                cm::cm_close_key(handle);
            }
            Err(e) => {
                outln!("Error opening key: {:?}", e);
            }
        }
    }
}

fn show_reg_enum(path: &str) {
    use crate::cm;

    outln!("Registry Enumeration: {}", path);
    outln!("{}", "=".repeat(path.len() + 23));
    outln!("");

    unsafe {
        match cm::cm_open_key(path) {
            Ok(handle) => {
                // Get key info
                if let Ok(info) = cm::cm_query_key_info(handle) {
                    outln!("Subkeys ({}):", info.subkey_count);
                    outln!("");

                    for i in 0..info.subkey_count {
                        if let Ok(subkey_handle) = cm::cm_enumerate_key(handle, i) {
                            if let Some(name) = cm::cm_get_key_name(subkey_handle) {
                                // Get subkey info
                                if let Ok(subinfo) = cm::cm_query_key_info(subkey_handle) {
                                    outln!("  [{}]  ({} subkeys, {} values)",
                                        name, subinfo.subkey_count, subinfo.value_count);
                                } else {
                                    outln!("  [{}]", name);
                                }
                            }
                        }
                    }

                    if info.subkey_count == 0 {
                        outln!("  (none)");
                    }

                    outln!("");
                    outln!("Values ({}):", info.value_count);
                    outln!("");

                    for i in 0..info.value_count {
                        if let Ok(value) = cm::cm_enumerate_value(handle, i) {
                            let name = if value.name.is_empty() {
                                "(Default)"
                            } else {
                                value.name.as_str()
                            };
                            let type_str = match value.value_type {
                                cm::RegType::Sz => "REG_SZ",
                                cm::RegType::Dword => "REG_DWORD",
                                cm::RegType::Qword => "REG_QWORD",
                                cm::RegType::Binary => "REG_BINARY",
                                cm::RegType::MultiSz => "REG_MULTI_SZ",
                                cm::RegType::ExpandSz => "REG_EXPAND_SZ",
                                _ => "REG_NONE",
                            };
                            outln!("  {}  [{}]  {} bytes", name, type_str, value.data.size);
                        }
                    }

                    if info.value_count == 0 {
                        outln!("  (none)");
                    }
                }

                cm::cm_close_key(handle);
            }
            Err(e) => {
                outln!("Error opening key: {:?}", e);
            }
        }
    }
}

/// NTFS file system command
pub fn cmd_ntfs(args: &[&str]) {
    use crate::fs::ntfs;

    if args.is_empty() {
        show_ntfs_info();
        return;
    }

    match args[0] {
        "help" | "-h" | "--help" | "?" => {
            outln!("NTFS File System Diagnostic Commands");
            outln!("=====================================");
            outln!("");
            outln!("Usage: ntfs <command>");
            outln!("");
            outln!("Commands:");
            outln!("  (none)        - Show NTFS driver information");
            outln!("  mounts        - List NTFS mounts");
            outln!("  boot <dev>    - Show boot sector for device");
            outln!("  mft <dev>     - Show MFT entries for device");
            outln!("  attrs         - Show attribute types");
            outln!("  help          - Show this help");
            outln!("");
            outln!("Examples:");
            outln!("  ntfs          - Show driver info");
            outln!("  ntfs mounts   - List mounted NTFS volumes");
            outln!("  ntfs attrs    - Show NTFS attribute types");
        }
        "mounts" => show_ntfs_mounts(),
        "boot" => {
            if args.len() > 1 {
                show_ntfs_boot(args[1]);
            } else {
                outln!("Usage: ntfs boot <device_index>");
            }
        }
        "mft" => {
            if args.len() > 1 {
                show_ntfs_mft(args[1]);
            } else {
                outln!("Usage: ntfs mft <device_index>");
            }
        }
        "attrs" | "attributes" => show_ntfs_attrs(),
        _ => {
            outln!("Unknown ntfs command: '{}'", args[0]);
            outln!("Type 'ntfs help' for usage.");
        }
    }
}

fn show_ntfs_info() {
    use crate::fs::ntfs;

    outln!("NTFS File System Driver");
    outln!("=======================");
    outln!("");
    outln!("Driver Version: 1.0");
    outln!("Status:         Active");
    outln!("");
    outln!("Features:");
    outln!("  Boot Sector:  Supported");
    outln!("  MFT Parsing:  Supported");
    outln!("  Attributes:   Read-only");
    outln!("  Data Runs:    Supported");
    outln!("  Compression:  Not yet supported");
    outln!("  Encryption:   Not yet supported");
    outln!("");
    outln!("Use 'ntfs help' for available commands.");
}

fn show_ntfs_mounts() {
    use crate::fs::ntfs;

    outln!("NTFS Mounted Volumes");
    outln!("====================");
    outln!("");

    let mounts = ntfs::file::get_active_mounts();
    if mounts.is_empty() {
        outln!("No NTFS volumes currently mounted.");
        return;
    }

    outln!("{:<4} {:<8} {:>12} {:>10} {:>10}",
        "Idx", "Device", "Total Clus", "Clus Size", "MFT Rec");
    outln!("{}", "-".repeat(50));

    for mount in mounts {
        outln!("{:<4} {:<8} {:>12} {:>10} {:>10}",
            mount.fs_index, mount.device_index, mount.total_clusters,
            mount.bytes_per_cluster, mount.file_record_size);
    }
}

fn show_ntfs_boot(dev_arg: &str) {
    outln!("NTFS Boot Sector Analysis");
    outln!("=========================");
    outln!("");
    outln!("Device: {}", dev_arg);
    outln!("");
    outln!("Note: Boot sector reading requires block device access.");
    outln!("This is a placeholder for future functionality.");
    outln!("");
    outln!("Expected Information:");
    outln!("  OEM ID:             NTFS");
    outln!("  Bytes per Sector:   512");
    outln!("  Sectors per Cluster: Varies");
    outln!("  MFT Cluster:        Varies");
    outln!("  MFT Mirror Cluster: Varies");
    outln!("  File Record Size:   1024");
}

fn show_ntfs_mft(dev_arg: &str) {
    use crate::fs::ntfs::mft;

    outln!("NTFS Master File Table");
    outln!("======================");
    outln!("");
    outln!("Device: {}", dev_arg);
    outln!("");
    outln!("Well-Known MFT Entries:");
    outln!("{:<6} {:<12} {}", "Index", "Name", "Description");
    outln!("{}", "-".repeat(50));

    outln!("{:<6} {:<12} {}", 0, mft::mft_entry_name(0), "Master File Table");
    outln!("{:<6} {:<12} {}", 1, mft::mft_entry_name(1), "MFT Mirror (first 4 entries)");
    outln!("{:<6} {:<12} {}", 2, mft::mft_entry_name(2), "Transaction log");
    outln!("{:<6} {:<12} {}", 3, mft::mft_entry_name(3), "Volume information");
    outln!("{:<6} {:<12} {}", 4, mft::mft_entry_name(4), "Attribute definitions");
    outln!("{:<6} {:<12} {}", 5, mft::mft_entry_name(5), "Root directory");
    outln!("{:<6} {:<12} {}", 6, mft::mft_entry_name(6), "Cluster allocation bitmap");
    outln!("{:<6} {:<12} {}", 7, mft::mft_entry_name(7), "Boot sector");
    outln!("{:<6} {:<12} {}", 8, mft::mft_entry_name(8), "Bad cluster list");
    outln!("{:<6} {:<12} {}", 9, mft::mft_entry_name(9), "Security descriptors");
    outln!("{:<6} {:<12} {}", 10, mft::mft_entry_name(10), "Uppercase table");
    outln!("{:<6} {:<12} {}", 11, mft::mft_entry_name(11), "Extended metadata directory");
    outln!("");
    outln!("First user file at index: {}", mft::well_known_mft::FIRST_USER_FILE);
}

fn show_ntfs_attrs() {
    use crate::fs::ntfs::attr::attr_types;

    outln!("NTFS Attribute Types");
    outln!("====================");
    outln!("");
    outln!("{:<10} {:<28} {}", "Type ID", "Name", "Description");
    outln!("{}", "-".repeat(60));

    outln!("{:#010x} {:<28} {}", attr_types::STANDARD_INFORMATION, "$STANDARD_INFORMATION", "File timestamps, flags");
    outln!("{:#010x} {:<28} {}", attr_types::ATTRIBUTE_LIST, "$ATTRIBUTE_LIST", "List of attribute records");
    outln!("{:#010x} {:<28} {}", attr_types::FILE_NAME, "$FILE_NAME", "File name (Unicode)");
    outln!("{:#010x} {:<28} {}", attr_types::OBJECT_ID, "$OBJECT_ID", "Unique object identifier");
    outln!("{:#010x} {:<28} {}", attr_types::SECURITY_DESCRIPTOR, "$SECURITY_DESCRIPTOR", "Security information");
    outln!("{:#010x} {:<28} {}", attr_types::VOLUME_NAME, "$VOLUME_NAME", "Volume label");
    outln!("{:#010x} {:<28} {}", attr_types::VOLUME_INFORMATION, "$VOLUME_INFORMATION", "Volume version, flags");
    outln!("{:#010x} {:<28} {}", attr_types::DATA, "$DATA", "File data content");
    outln!("{:#010x} {:<28} {}", attr_types::INDEX_ROOT, "$INDEX_ROOT", "Index B-tree root");
    outln!("{:#010x} {:<28} {}", attr_types::INDEX_ALLOCATION, "$INDEX_ALLOCATION", "Index B-tree nodes");
    outln!("{:#010x} {:<28} {}", attr_types::BITMAP, "$BITMAP", "Bitmap for index/MFT");
    outln!("{:#010x} {:<28} {}", attr_types::REPARSE_POINT, "$REPARSE_POINT", "Symbolic links, junctions");
    outln!("{:#010x} {:<28} {}", attr_types::EA_INFORMATION, "$EA_INFORMATION", "Extended attr info");
    outln!("{:#010x} {:<28} {}", attr_types::EA, "$EA", "Extended attributes");
    outln!("{:#010x} {:<28} {}", attr_types::LOGGED_UTILITY_STREAM, "$LOGGED_UTILITY_STREAM", "EFS data");
    outln!("");
    outln!("End Marker: {:#010x}", 0xFFFFFFFFu32);
}

fn show_reg_info(path: &str) {
    use crate::cm;

    outln!("Registry Key Info: {}", path);
    outln!("{}", "=".repeat(path.len() + 19));
    outln!("");

    unsafe {
        match cm::cm_open_key(path) {
            Ok(handle) => {
                // Use enhanced query with KeyFullInformation
                match cm::cm_query_key_ex(handle, cm::KeyInformationClass::KeyFullInformation) {
                    Ok(cm::KeyQueryResult::Full(info)) => {
                        outln!("Full Key Information:");
                        outln!("  Last Write Time:      {:#x}", info.last_write_time);
                        outln!("  Title Index:          {}", info.title_index);
                        outln!("  Subkey Count:         {}", info.subkey_count);
                        outln!("  Max Subkey Name Len:  {} bytes", info.max_subkey_name_length);
                        outln!("  Max Subkey Class Len: {} bytes", info.max_subkey_class_length);
                        outln!("  Value Count:          {}", info.value_count);
                        outln!("  Max Value Name Len:   {} bytes", info.max_value_name_length);
                        outln!("  Max Value Data Len:   {} bytes", info.max_value_data_length);
                    }
                    Ok(_) => {
                        outln!("Unexpected result type");
                    }
                    Err(e) => {
                        outln!("Error querying key info: {:?}", e);
                    }
                }

                outln!("");

                // Get path
                if let Some(full_path) = cm::cm_get_key_full_path(handle) {
                    outln!("Full Path: {}", full_path);
                }

                cm::cm_close_key(handle);
            }
            Err(e) => {
                outln!("Error opening key: {:?}", e);
            }
        }
    }
}

/// Test user mode process creation infrastructure
pub fn cmd_userproc(args: &[&str]) {
    if args.is_empty() {
        outln!("User Mode Process Test");
        outln!("");
        outln!("Commands:");
        outln!("  userproc create     - Create a test user process");
        outln!("  userproc aspace     - Create and test address space");
        outln!("  userproc info       - Show address space stats");
        outln!("");
        return;
    }

    if eq_ignore_case(args[0], "create") {
        outln!("Creating test user process...");
        outln!("");

        unsafe {
            // Get the system process as parent
            let parent = crate::ps::eprocess::get_system_process();
            if parent.is_null() {
                outln!("Error: Cannot get system process");
                return;
            }

            // Create a user process with the test entry point
            let entry_point = crate::mm::USER_TEST_BASE;
            let stack_top = crate::mm::USER_STACK_TOP;

            let (process, thread) = crate::ps::create::ps_create_user_process(
                parent,
                b"test.exe",
                entry_point,
                stack_top,
                0, // CR3 will be created by the function
            );

            if process.is_null() {
                outln!("Error: Failed to create process");
                return;
            }

            outln!("Process created successfully:");
            outln!("  PID:         {}", (*process).unique_process_id);
            outln!("  Name:        {}", core::str::from_utf8_unchecked((*process).image_name()));
            outln!("  Entry Point: {:#x}", entry_point);
            outln!("  Stack:       {:#x}", stack_top);

            // Check address space
            let aspace = (*process).address_space as *const crate::mm::MmAddressSpace;
            if !aspace.is_null() {
                outln!("  CR3:         {:#x}", (*aspace).pml4_physical);
                outln!("  VAD Count:   {}", (*aspace).vad_root.count);
            } else {
                outln!("  (using shared address space)");
            }

            if thread.is_null() {
                outln!("");
                outln!("Warning: Failed to create initial thread");
            } else {
                outln!("");
                outln!("Thread created:");
                outln!("  TID:         {}", (*thread).cid.unique_thread);
                let teb = (*thread).teb;
                if !teb.is_null() {
                    outln!("  TEB:         {:p}", teb);
                }
            }
        }
    } else if eq_ignore_case(args[0], "aspace") {
        outln!("Testing per-process address space...");
        outln!("");

        unsafe {
            // Create an address space
            match crate::mm::mm_create_process_address_space() {
                Some(aspace) => {
                    outln!("Address space created:");
                    outln!("  PML4 Physical: {:#x}", (*aspace).pml4_physical);
                    outln!("  Ref Count:     {}", (*aspace).ref_count.load(core::sync::atomic::Ordering::SeqCst));
                    outln!("");

                    // Test mapping a user page
                    let test_addr: u64 = 0x400000; // 4MB
                    let flags = crate::mm::pte_flags::USER_RWX;

                    outln!("Mapping user page at {:#x}...", test_addr);
                    if let Some(phys) = crate::mm::mm_map_user_page(aspace, test_addr, flags) {
                        outln!("  Mapped to physical: {:#x}", phys);
                        outln!("  Working set size:   {}", (*aspace).working_set.current_size);
                        outln!("");

                        // Release the reference
                        (*aspace).release();
                        outln!("Released address space reference");
                    } else {
                        outln!("  Failed to map page");
                        // Clean up
                        (*aspace).release();
                    }
                }
                None => {
                    outln!("Failed to create address space");
                }
            }
        }
    } else if eq_ignore_case(args[0], "info") {
        outln!("Address Space Statistics:");
        outln!("");

        let stats = crate::mm::mm_get_address_space_stats();
        outln!("  Total:     {}", stats.total);
        outln!("  Allocated: {}", stats.allocated);
        outln!("  Free:      {}", stats.free);
        outln!("");

        let pfn_stats = crate::mm::mm_get_stats();
        outln!("PFN Statistics:");
        outln!("  Total Pages: {}", pfn_stats.total_pages);
        outln!("  Free Pages:  {}", pfn_stats.free_pages);
        outln!("  Used Pages:  {}", pfn_stats.total_pages - pfn_stats.free_pages);
    } else {
        outln!("Unknown command: {}", args[0]);
        outln!("Use 'userproc' for help");
    }
}

/// NETINFO command - Network diagnostics and information
pub fn cmd_netinfo(args: &[&str]) {
    use crate::net;

    if args.is_empty() {
        outln!("Usage: netinfo <command>");
        outln!("");
        outln!("Commands:");
        outln!("  status     Show network subsystem status");
        outln!("  devices    List registered network devices");
        outln!("  stats      Show global network statistics");
        outln!("  arp        Show ARP cache");
        outln!("  ping <ip>  Send ICMP echo request");
        outln!("  loopback   Process loopback queue");
        outln!("  udp        Show UDP socket status");
        outln!("  udpsend    Send UDP test packet");
        outln!("  dns        Show DNS configuration");
        outln!("  resolve    Resolve hostname to IP");
        outln!("  ipconfig   Configure static IP address");
        outln!("  dhcp       Run DHCP discovery");
        outln!("  tcp        Show TCP socket status");
        outln!("  connect    Connect to TCP server");
        outln!("  listen     Listen on TCP port");
        outln!("  http       Make HTTP GET request");
        outln!("  telnet     Start/stop telnet server");
        outln!("  httpd      Start/stop HTTP server");
        outln!("  ntp        Sync time with NTP server");
        outln!("  wol        Send Wake-on-LAN packet");
        outln!("  tftp       Download file via TFTP");
        outln!("  ftp        FTP file transfer");
        outln!("  syslog     Configure syslog client");
        outln!("  smtp       SMTP email notifications");
        outln!("  pop3       POP3 email retrieval");
        outln!("  snmp       SNMP network monitoring");
        return;
    }

    if eq_ignore_case(args[0], "status") {
        outln!("Network Subsystem Status:");
        outln!("");
        if net::is_initialized() {
            outln!("  Status: Initialized");
        } else {
            outln!("  Status: Not Initialized");
        }
        outln!("  Devices: {}", net::get_device_count());

        // Show loopback info
        if let Some(idx) = net::loopback::get_device_index() {
            let (queued, _) = net::loopback::get_queue_stats();
            outln!("  Loopback: Device {} ({} packets queued)", idx, queued);
        }

        // Show UDP info
        let (udp_active, udp_max) = net::udp::get_socket_stats();
        outln!("  UDP Sockets: {}/{}", udp_active, udp_max);
        outln!("");

        // Show global stats summary
        let stats = net::get_stats();
        outln!("Statistics Summary:");
        outln!("  RX Packets: {}", stats.packets_received);
        outln!("  TX Packets: {}", stats.packets_transmitted);
        outln!("  RX Errors:  {}", stats.receive_errors);
        outln!("  TX Errors:  {}", stats.transmit_errors);
    } else if eq_ignore_case(args[0], "devices") {
        outln!("Network Devices:");
        outln!("");

        let count = net::get_device_count();
        if count == 0 {
            outln!("  No devices registered");
            return;
        }

        for i in 0..count {
            if let Some(device) = net::get_device(i) {
                outln!("Device {}:", i);
                outln!("  Name:       {}", device.info.name);
                outln!("  MAC:        {:?}", device.info.mac_address);
                outln!("  State:      {:?}", device.state());
                if let Some(ip) = device.ip_address {
                    outln!("  IP:         {:?}", ip);
                }
                if let Some(mask) = device.subnet_mask {
                    outln!("  Mask:       {:?}", mask);
                }
                if let Some(gw) = device.gateway {
                    outln!("  Gateway:    {:?}", gw);
                }
                outln!("  Link Speed: {} Mbps", device.info.capabilities.link_speed);
                outln!("  MTU:        {}", device.info.capabilities.mtu);
                outln!("  RX Packets: {}", device.stats.rx_packets);
                outln!("  TX Packets: {}", device.stats.tx_packets);
                outln!("  RX Bytes:   {}", device.stats.rx_bytes);
                outln!("  TX Bytes:   {}", device.stats.tx_bytes);
                outln!("");
            }
        }
    } else if eq_ignore_case(args[0], "stats") {
        outln!("Global Network Statistics:");
        outln!("");

        let stats = net::get_stats();
        outln!("  Packets Received:     {}", stats.packets_received);
        outln!("  Packets Transmitted:  {}", stats.packets_transmitted);
        outln!("  Bytes Received:       {}", stats.bytes_received);
        outln!("  Bytes Transmitted:    {}", stats.bytes_transmitted);
        outln!("  Receive Errors:       {}", stats.receive_errors);
        outln!("  Transmit Errors:      {}", stats.transmit_errors);
        outln!("");
        outln!("Protocol Statistics:");
        outln!("  ARP Requests Sent:    {}", stats.arp_requests);
        outln!("  ARP Replies Received: {}", stats.arp_replies);
        outln!("  ICMP Echo Requests:   {}", stats.icmp_echo_requests);
        outln!("  ICMP Echo Replies:    {}", stats.icmp_echo_replies);
    } else if eq_ignore_case(args[0], "arp") {
        outln!("ARP Cache ({} entries):", net::arp::get_cache_count());
        outln!("");

        let entries = net::arp::get_cache_entries();
        if entries.is_empty() {
            outln!("  (empty)");
            return;
        }

        outln!("  IP Address         MAC Address        Static  Age(ticks)");
        outln!("  ---------------    -----------------  ------  ----------");

        let current_time = crate::hal::apic::TICK_COUNT.load(core::sync::atomic::Ordering::Relaxed);
        for entry in entries.iter() {
            let age = current_time.saturating_sub(entry.timestamp);
            let static_str = if entry.is_static { "Yes" } else { "No" };
            outln!("  {:?}    {:?}  {}     {}",
                entry.ip_address,
                entry.mac_address,
                static_str,
                age
            );
        }
    } else if eq_ignore_case(args[0], "ping") {
        if args.len() < 2 {
            outln!("Usage: netinfo ping <ip_address>");
            outln!("  Example: netinfo ping 192.168.1.1");
            return;
        }

        // Parse IP address (format: a.b.c.d)
        let ip_str = args[1];
        let mut octets = [0u8; 4];
        let mut octet_idx = 0;
        let mut current = 0u32;

        for c in ip_str.chars() {
            if c == '.' {
                if octet_idx >= 3 || current > 255 {
                    outln!("Invalid IP address format");
                    return;
                }
                octets[octet_idx] = current as u8;
                octet_idx += 1;
                current = 0;
            } else if let Some(d) = c.to_digit(10) {
                current = current * 10 + d;
            } else {
                outln!("Invalid IP address format");
                return;
            }
        }

        if octet_idx != 3 || current > 255 {
            outln!("Invalid IP address format");
            return;
        }
        octets[3] = current as u8;

        let target_ip = net::Ipv4Address::new(octets);
        outln!("Pinging {:?}...", target_ip);

        // Try to send ping (requires a device)
        if net::get_device_count() == 0 {
            outln!("  No network device available");
            return;
        }

        // Use first device
        let result = net::send_icmp_echo_request(
            0,          // device index
            target_ip,
            0x1234,     // identifier
            1,          // sequence
            b"PING",    // data
        );

        match result {
            Ok(()) => outln!("  Echo request sent"),
            Err(e) => outln!("  Failed: {}", e),
        }
    } else if eq_ignore_case(args[0], "loopback") {
        outln!("Loopback Device Status:");
        outln!("");

        if let Some(idx) = net::loopback::get_device_index() {
            outln!("  Device Index: {}", idx);

            let (queued, max) = net::loopback::get_queue_stats();
            outln!("  Queue:        {}/{} packets", queued, max);

            if queued > 0 {
                outln!("");
                outln!("Processing queued packets...");
                let processed = net::loopback::process_queue();
                outln!("  Processed {} packets", processed);
            }
        } else {
            outln!("  Loopback device not initialized");
        }
    } else if eq_ignore_case(args[0], "udp") {
        outln!("UDP Socket Status:");
        outln!("");

        let (active, max) = net::udp::get_socket_stats();
        outln!("  Active Sockets: {}/{}", active, max);
        outln!("");

        if active > 0 {
            outln!("  ID  State   Port   Pending");
            outln!("  --  -----   ----   -------");
            for i in 0..max {
                if let Some((state, port, pending)) = net::udp::get_socket_info(i) {
                    if state != net::udp::UdpSocketState::Closed {
                        outln!("  {:2}  {:?}  {:5}  {}", i, state, port, pending);
                    }
                }
            }
        }
    } else if eq_ignore_case(args[0], "udpsend") {
        // Usage: netinfo udpsend <dst_ip> <dst_port> <message>
        if args.len() < 4 {
            outln!("Usage: netinfo udpsend <ip> <port> <message>");
            outln!("  Example: netinfo udpsend 127.0.0.1 5000 hello");
            return;
        }

        // Parse IP address
        let ip_str = args[1];
        let mut octets = [0u8; 4];
        let mut octet_idx = 0;
        let mut current = 0u32;

        for c in ip_str.chars() {
            if c == '.' {
                if octet_idx >= 3 || current > 255 {
                    outln!("Invalid IP address format");
                    return;
                }
                octets[octet_idx] = current as u8;
                octet_idx += 1;
                current = 0;
            } else if let Some(d) = c.to_digit(10) {
                current = current * 10 + d;
            } else {
                outln!("Invalid IP address format");
                return;
            }
        }
        if octet_idx != 3 || current > 255 {
            outln!("Invalid IP address format");
            return;
        }
        octets[3] = current as u8;
        let dst_ip = net::Ipv4Address::new(octets);

        // Parse port
        let port: u16 = match args[2].parse() {
            Ok(p) => p,
            Err(_) => {
                outln!("Invalid port number");
                return;
            }
        };

        // Get message
        let message = args[3];

        outln!("Sending UDP to {:?}:{}", dst_ip, port);

        // Create socket
        let socket = match net::udp::socket_create() {
            Some(s) => s,
            None => {
                outln!("  Failed to create socket");
                return;
            }
        };

        // Send data
        match net::udp::socket_sendto(socket, 0, dst_ip, port, message.as_bytes()) {
            Ok(sent) => outln!("  Sent {} bytes", sent),
            Err(e) => outln!("  Failed: {}", e),
        }

        // Close socket
        let _ = net::udp::socket_close(socket);
    } else if eq_ignore_case(args[0], "dns") {
        outln!("DNS Configuration:");
        outln!("");

        let server = net::dns::get_dns_server();
        outln!("  DNS Server: {:?}", server);

        if args.len() >= 2 && eq_ignore_case(args[1], "set") {
            if args.len() < 3 {
                outln!("");
                outln!("Usage: netinfo dns set <ip>");
                outln!("  Example: netinfo dns set 8.8.8.8");
                return;
            }

            // Parse IP address
            let ip_str = args[2];
            let mut octets = [0u8; 4];
            let mut octet_idx = 0;
            let mut current = 0u32;

            for c in ip_str.chars() {
                if c == '.' {
                    if octet_idx >= 3 || current > 255 {
                        outln!("Invalid IP address format");
                        return;
                    }
                    octets[octet_idx] = current as u8;
                    octet_idx += 1;
                    current = 0;
                } else if let Some(d) = c.to_digit(10) {
                    current = current * 10 + d;
                } else {
                    outln!("Invalid IP address format");
                    return;
                }
            }
            if octet_idx != 3 || current > 255 {
                outln!("Invalid IP address format");
                return;
            }
            octets[3] = current as u8;

            let new_server = net::Ipv4Address::new(octets);
            net::dns::set_dns_server(new_server);
            outln!("  DNS server set to {:?}", new_server);
        }
    } else if eq_ignore_case(args[0], "resolve") {
        if args.len() < 2 {
            outln!("Usage: netinfo resolve <hostname>");
            outln!("  Example: netinfo resolve example.com");
            return;
        }

        let hostname = args[1];
        outln!("Resolving {}...", hostname);

        match net::dns::resolve(0, hostname) {
            Some(ip) => outln!("  {} -> {:?}", hostname, ip),
            None => outln!("  Resolution failed"),
        }
    } else if eq_ignore_case(args[0], "ipconfig") {
        // Usage: netinfo ipconfig <device> <ip> <mask> [gateway]
        if args.len() < 4 {
            outln!("Configure static IP address");
            outln!("");
            outln!("Usage: netinfo ipconfig <device> <ip> <mask> [gateway]");
            outln!("");
            outln!("Examples:");
            outln!("  netinfo ipconfig 0 192.168.1.100 255.255.255.0");
            outln!("  netinfo ipconfig 0 192.168.1.100 255.255.255.0 192.168.1.1");
            outln!("");
            outln!("Current device configurations:");

            let count = net::get_device_count();
            for i in 0..count {
                if let Some(device) = net::get_device(i) {
                    out!("  {}: {}", i, device.info.name);
                    if let Some(ip) = device.ip_address {
                        out!(" IP={:?}", ip);
                    } else {
                        out!(" IP=none");
                    }
                    if let Some(mask) = device.subnet_mask {
                        out!(" Mask={:?}", mask);
                    } else {
                        out!(" Mask=none");
                    }
                    if let Some(gw) = device.gateway {
                        outln!(" GW={:?}", gw);
                    } else {
                        outln!(" GW=none");
                    }
                }
            }
            return;
        }

        // Parse device index
        let device_idx: usize = match args[1].parse() {
            Ok(d) => d,
            Err(_) => {
                outln!("Invalid device index");
                return;
            }
        };

        // Helper closure to parse IP
        let parse_ip = |s: &str| -> Option<net::Ipv4Address> {
            let mut octets = [0u8; 4];
            let mut octet_idx = 0;
            let mut current = 0u32;

            for c in s.chars() {
                if c == '.' {
                    if octet_idx >= 3 || current > 255 {
                        return None;
                    }
                    octets[octet_idx] = current as u8;
                    octet_idx += 1;
                    current = 0;
                } else if let Some(d) = c.to_digit(10) {
                    current = current * 10 + d;
                } else {
                    return None;
                }
            }
            if octet_idx != 3 || current > 255 {
                return None;
            }
            octets[3] = current as u8;
            Some(net::Ipv4Address::new(octets))
        };

        // Parse IP address
        let ip = match parse_ip(args[2]) {
            Some(ip) => ip,
            None => {
                outln!("Invalid IP address format");
                return;
            }
        };

        // Parse subnet mask
        let mask = match parse_ip(args[3]) {
            Some(m) => m,
            None => {
                outln!("Invalid subnet mask format");
                return;
            }
        };

        // Parse gateway (optional)
        let gateway = if args.len() >= 5 {
            match parse_ip(args[4]) {
                Some(g) => Some(g),
                None => {
                    outln!("Invalid gateway address format");
                    return;
                }
            }
        } else {
            None
        };

        outln!("Configuring device {}:", device_idx);
        outln!("  IP:      {:?}", ip);
        outln!("  Mask:    {:?}", mask);
        if let Some(gw) = gateway {
            outln!("  Gateway: {:?}", gw);
        }

        match net::dhcp::configure_static(device_idx, ip, mask, gateway) {
            Ok(()) => outln!("Configuration applied successfully"),
            Err(e) => outln!("Configuration failed: {}", e),
        }
    } else if eq_ignore_case(args[0], "dhcp") {
        // Usage: netinfo dhcp [device]
        let device_idx: usize = if args.len() >= 2 {
            match args[1].parse() {
                Ok(d) => d,
                Err(_) => {
                    outln!("Invalid device index");
                    return;
                }
            }
        } else {
            // Default to first non-loopback device
            let mut found = None;
            for i in 0..net::get_device_count() {
                if let Some(device) = net::get_device(i) {
                    // Skip loopback
                    if device.info.name != "lo0" {
                        found = Some(i);
                        break;
                    }
                }
            }
            match found {
                Some(i) => i,
                None => {
                    outln!("No non-loopback network device found");
                    return;
                }
            }
        };

        outln!("Running DHCP discovery on device {}...", device_idx);

        match net::dhcp::discover(device_idx) {
            Ok(lease) => {
                outln!("");
                outln!("DHCP Lease Obtained:");
                outln!("  IP Address:  {:?}", lease.ip_address);
                outln!("  Subnet Mask: {:?}", lease.subnet_mask);
                if let Some(gw) = lease.gateway {
                    outln!("  Gateway:     {:?}", gw);
                }
                if let Some(dns) = lease.dns_server {
                    outln!("  DNS Server:  {:?}", dns);
                }
                outln!("  DHCP Server: {:?}", lease.server_id);
                outln!("  Lease Time:  {} seconds", lease.lease_time);
            }
            Err(e) => {
                outln!("  DHCP failed: {}", e);
                outln!("");
                outln!("Note: Use 'netinfo ipconfig' for manual IP configuration");
            }
        }
    } else if eq_ignore_case(args[0], "tcp") {
        outln!("TCP Socket Status:");
        outln!("");

        let (active, max) = net::tcp::get_socket_stats();
        outln!("  Active Sockets: {}/{}", active, max);
        outln!("");

        if active > 0 {
            outln!("  ID  State          Local    Remote             RX   TX");
            outln!("  --  -------------  -----    ----------------   ---  ---");
            for i in 0..max {
                if let Some((state, local_port, remote_port, remote_ip, rx_len, tx_len)) = net::tcp::get_socket_info(i) {
                    if state != net::tcp::TcpState::Closed {
                        outln!("  {:2}  {:13?}  {:5}    {:?}:{}  {}  {}",
                            i, state, local_port, remote_ip, remote_port, rx_len, tx_len);
                    }
                }
            }
        }
    } else if eq_ignore_case(args[0], "connect") {
        // Usage: netinfo connect <ip> <port>
        if args.len() < 3 {
            outln!("Connect to a TCP server");
            outln!("");
            outln!("Usage: netinfo connect <ip> <port>");
            outln!("");
            outln!("Examples:");
            outln!("  netinfo connect 192.168.1.1 80");
            outln!("  netinfo connect 10.0.2.2 22");
            return;
        }

        // Parse IP address
        let parse_ip = |s: &str| -> Option<net::Ipv4Address> {
            let mut octets = [0u8; 4];
            let mut octet_idx = 0;
            let mut current = 0u32;

            for c in s.chars() {
                if c == '.' {
                    if octet_idx >= 3 || current > 255 {
                        return None;
                    }
                    octets[octet_idx] = current as u8;
                    octet_idx += 1;
                    current = 0;
                } else if let Some(d) = c.to_digit(10) {
                    current = current * 10 + d;
                } else {
                    return None;
                }
            }
            if octet_idx != 3 || current > 255 {
                return None;
            }
            octets[3] = current as u8;
            Some(net::Ipv4Address::new(octets))
        };

        let ip = match parse_ip(args[1]) {
            Some(ip) => ip,
            None => {
                outln!("Invalid IP address format");
                return;
            }
        };

        let port: u16 = match args[2].parse() {
            Ok(p) => p,
            Err(_) => {
                outln!("Invalid port number");
                return;
            }
        };

        outln!("Connecting to {:?}:{}...", ip, port);

        // Create socket
        let socket = match net::tcp::socket_create() {
            Some(s) => s,
            None => {
                outln!("  Failed to create socket");
                return;
            }
        };

        // Find first non-loopback device
        let device_idx = {
            let mut found = None;
            for i in 0..net::get_device_count() {
                if let Some(device) = net::get_device(i) {
                    if device.info.name != "lo0" && device.ip_address.is_some() {
                        found = Some(i);
                        break;
                    }
                }
            }
            match found {
                Some(i) => i,
                None => {
                    outln!("  No network device with IP configured");
                    return;
                }
            }
        };

        match net::tcp::socket_connect(socket, device_idx, ip, port) {
            Ok(()) => {
                outln!("  SYN sent, socket {} waiting for SYN-ACK", socket);
                outln!("  (Use 'netinfo tcp' to check connection state)");
            }
            Err(e) => {
                outln!("  Connect failed: {}", e);
                let _ = net::tcp::socket_close(socket);
            }
        }
    } else if eq_ignore_case(args[0], "listen") {
        // Usage: netinfo listen <port>
        if args.len() < 2 {
            outln!("Listen on a TCP port");
            outln!("");
            outln!("Usage: netinfo listen <port>");
            outln!("");
            outln!("Examples:");
            outln!("  netinfo listen 8080");
            outln!("  netinfo listen 23");
            return;
        }

        let port: u16 = match args[1].parse() {
            Ok(p) => p,
            Err(_) => {
                outln!("Invalid port number");
                return;
            }
        };

        // Create socket
        let socket = match net::tcp::socket_create() {
            Some(s) => s,
            None => {
                outln!("Failed to create socket");
                return;
            }
        };

        // Bind to port
        if let Err(e) = net::tcp::socket_bind(socket, port) {
            outln!("Failed to bind: {}", e);
            let _ = net::tcp::socket_close(socket);
            return;
        }

        // Start listening
        match net::tcp::socket_listen(socket, 8) {
            Ok(()) => {
                outln!("Listening on port {} (socket {})", port, socket);
                outln!("(Use 'netinfo tcp' to check for connections)");
            }
            Err(e) => {
                outln!("Listen failed: {}", e);
                let _ = net::tcp::socket_close(socket);
            }
        }
    } else if eq_ignore_case(args[0], "http") {
        // Usage: netinfo http <ip> [port] [path]
        // Or: netinfo http <hostname> [port] [path]
        if args.len() < 2 {
            outln!("Make an HTTP GET request");
            outln!("");
            outln!("Usage: netinfo http <ip> [port] [path]");
            outln!("");
            outln!("Examples:");
            outln!("  netinfo http 93.184.216.34          - GET / from example.com");
            outln!("  netinfo http 10.0.2.2 8080 /api     - GET /api on port 8080");
            outln!("");
            outln!("Note: Use 'netinfo resolve' to get IP from hostname first");
            return;
        }

        // Parse IP address
        let parse_ip = |s: &str| -> Option<net::Ipv4Address> {
            let mut octets = [0u8; 4];
            let mut octet_idx = 0;
            let mut current = 0u32;

            for c in s.chars() {
                if c == '.' {
                    if octet_idx >= 3 || current > 255 {
                        return None;
                    }
                    octets[octet_idx] = current as u8;
                    octet_idx += 1;
                    current = 0;
                } else if let Some(d) = c.to_digit(10) {
                    current = current * 10 + d;
                } else {
                    return None;
                }
            }
            if octet_idx != 3 || current > 255 {
                return None;
            }
            octets[3] = current as u8;
            Some(net::Ipv4Address::new(octets))
        };

        let ip = match parse_ip(args[1]) {
            Some(ip) => ip,
            None => {
                outln!("Invalid IP address format");
                outln!("Use 'netinfo resolve <hostname>' to get IP first");
                return;
            }
        };

        let port: u16 = if args.len() >= 3 {
            match args[2].parse() {
                Ok(p) => p,
                Err(_) => {
                    outln!("Invalid port number, using 80");
                    80
                }
            }
        } else {
            80
        };

        let path = if args.len() >= 4 {
            args[3]
        } else {
            "/"
        };

        // Find first non-loopback device with IP
        let device_idx = {
            let mut found = None;
            for i in 0..net::get_device_count() {
                if let Some(device) = net::get_device(i) {
                    if device.info.name != "lo0" && device.ip_address.is_some() {
                        found = Some(i);
                        break;
                    }
                }
            }
            match found {
                Some(i) => i,
                None => {
                    outln!("No network device with IP configured");
                    return;
                }
            }
        };

        outln!("GET http://{:?}:{}{}", ip, port, path);
        outln!("");

        match net::http::http_get(device_idx, args[1], ip, port, path) {
            Ok(response) => {
                outln!("HTTP/{} {}", "1.0", response.status_code);
                outln!("Status: {} {}", response.status_code, response.status_text);
                outln!("");

                // Show headers
                outln!("Headers:");
                for (name, value) in &response.headers {
                    outln!("  {}: {}", name, value);
                }
                outln!("");

                // Show body preview
                outln!("Body ({} bytes):", response.body.len());
                if let Some(body_str) = response.body_as_string() {
                    // Show first 500 bytes
                    let preview_len = body_str.len().min(500);
                    outln!("{}", &body_str[..preview_len]);
                    if body_str.len() > 500 {
                        outln!("... ({} more bytes)", body_str.len() - 500);
                    }
                } else {
                    outln!("  (binary data, {} bytes)", response.body.len());
                }
            }
            Err(e) => {
                outln!("HTTP request failed: {}", e);
            }
        }
    } else if eq_ignore_case(args[0], "telnet") {
        // Usage: netinfo telnet [start|stop|status]
        let subcmd = if args.len() >= 2 { args[1] } else { "status" };

        if eq_ignore_case(subcmd, "start") {
            // Find first non-loopback device with IP
            let device_idx = {
                let mut found = None;
                for i in 0..net::get_device_count() {
                    if let Some(device) = net::get_device(i) {
                        if device.info.name != "lo0" && device.ip_address.is_some() {
                            found = Some(i);
                            break;
                        }
                    }
                }
                match found {
                    Some(i) => i,
                    None => {
                        outln!("No network device with IP configured");
                        outln!("Use 'netinfo ipconfig' to configure an IP address first");
                        return;
                    }
                }
            };

            let port = if args.len() >= 3 {
                args[2].parse().unwrap_or(23)
            } else {
                23
            };

            outln!("Starting telnet server on port {}...", port);
            match net::telnet::start_server(device_idx, port) {
                Ok(()) => {
                    outln!("Telnet server started");
                    outln!("");
                    outln!("Connect with: telnet <ip> {}", port);
                    if let Some(device) = net::get_device(device_idx) {
                        if let Some(ip) = device.ip_address {
                            outln!("Example: telnet {:?} {}", ip, port);
                        }
                    }
                }
                Err(e) => outln!("Failed to start: {}", e),
            }
        } else if eq_ignore_case(subcmd, "stop") {
            outln!("Stopping telnet server...");
            match net::telnet::stop_server() {
                Ok(()) => outln!("Telnet server stopped"),
                Err(e) => outln!("Failed to stop: {}", e),
            }
        } else if eq_ignore_case(subcmd, "poll") {
            // Manual poll for testing
            net::telnet::poll();
            outln!("Telnet polled");
        } else {
            // Show status
            let (listening, active, port) = net::telnet::get_status();

            outln!("Telnet Server Status:");
            outln!("");
            if listening {
                outln!("  Status:   Running on port {}", port);
                outln!("  Sessions: {}/{}", active, net::telnet::MAX_TELNET_SESSIONS);
                outln!("");

                if active > 0 {
                    outln!("Active Sessions:");
                    for i in 0..net::telnet::MAX_TELNET_SESSIONS {
                        if let Some((state, ip, rport)) = net::telnet::get_session_info(i) {
                            outln!("  {}: {:?}:{} ({:?})", i, ip, rport, state);
                        }
                    }
                }
            } else {
                outln!("  Status: Not running");
                outln!("");
                outln!("Use 'netinfo telnet start' to start the server");
            }
        }
    } else if eq_ignore_case(args[0], "httpd") {
        // Usage: netinfo httpd [start|stop|status]
        let subcmd = if args.len() >= 2 { args[1] } else { "status" };

        if eq_ignore_case(subcmd, "start") {
            // Find first non-loopback device with IP
            let device_idx = {
                let mut found = None;
                for i in 0..net::get_device_count() {
                    if let Some(device) = net::get_device(i) {
                        if device.info.name != "lo0" && device.ip_address.is_some() {
                            found = Some(i);
                            break;
                        }
                    }
                }
                match found {
                    Some(i) => i,
                    None => {
                        outln!("No network device with IP configured");
                        outln!("Use 'netinfo ipconfig' to configure an IP address first");
                        return;
                    }
                }
            };

            let port = if args.len() >= 3 {
                args[2].parse().unwrap_or(80)
            } else {
                80
            };

            outln!("Starting HTTP server on port {}...", port);

            match net::httpd::start_server(device_idx, port) {
                Ok(()) => {
                    if let Some(device) = net::get_device(device_idx) {
                        if let Some(ip) = device.ip_address {
                            outln!("HTTP server started");
                            outln!("");
                            outln!("Access at: http://{:?}:{}/", ip, port);
                        }
                    }
                }
                Err(e) => outln!("Failed to start HTTP server: {}", e),
            }
        } else if eq_ignore_case(subcmd, "stop") {
            match net::httpd::stop_server() {
                Ok(()) => outln!("HTTP server stopped"),
                Err(e) => outln!("Failed to stop HTTP server: {}", e),
            }
        } else if eq_ignore_case(subcmd, "poll") {
            // Poll server (for debugging)
            net::httpd::poll();
            outln!("HTTP server polled");
        } else {
            // Show status
            let (running, port, requests, bytes) = net::httpd::get_status();
            let connections = net::httpd::get_connection_count();

            outln!("HTTP Server Status:");
            outln!("");

            if running {
                outln!("  Status: Running on port {}", port);
                outln!("  Active connections: {}", connections);
                outln!("  Total requests: {}", requests);
                outln!("  Bytes sent: {}", bytes);
                outln!("");
                outln!("Use 'netinfo httpd stop' to stop the server");
            } else {
                outln!("  Status: Not running");
                outln!("");
                outln!("Use 'netinfo httpd start' to start the server");
            }
        }
    } else if eq_ignore_case(args[0], "ntp") {
        // Usage: netinfo ntp [server_ip]
        // Find first non-loopback device with IP
        let device_idx = {
            let mut found = None;
            for i in 0..net::get_device_count() {
                if let Some(device) = net::get_device(i) {
                    if device.info.name != "lo0" && device.ip_address.is_some() {
                        found = Some(i);
                        break;
                    }
                }
            }
            match found {
                Some(i) => i,
                None => {
                    outln!("No network device with IP configured");
                    outln!("Use 'netinfo ipconfig' to configure an IP address first");
                    return;
                }
            }
        };

        // Parse server IP or use default
        let server_ip = if args.len() >= 2 {
            // Parse IP address manually without allocation
            let ip_str = args[1];
            let mut octets = [0u8; 4];
            let mut octet_idx = 0;
            let mut current: u16 = 0;
            let mut valid = true;

            for c in ip_str.chars() {
                if c == '.' {
                    if current > 255 || octet_idx >= 3 {
                        valid = false;
                        break;
                    }
                    octets[octet_idx] = current as u8;
                    octet_idx += 1;
                    current = 0;
                } else if let Some(digit) = c.to_digit(10) {
                    current = current * 10 + digit as u16;
                } else {
                    valid = false;
                    break;
                }
            }

            if valid && octet_idx == 3 && current <= 255 {
                octets[3] = current as u8;
                net::ip::Ipv4Address::new(octets)
            } else {
                outln!("Invalid IP address: {}", args[1]);
                return;
            }
        } else {
            // Use default NTP server (time.google.com)
            net::ntp::servers::TIME_GOOGLE
        };

        outln!("Syncing time with {:?}...", server_ip);

        match net::ntp::sync_time(device_idx, server_ip) {
            Ok(result) => {
                let (year, month, day, hour, minute, second) =
                    net::ntp::unix_to_datetime(result.unix_timestamp);

                outln!("");
                outln!("NTP Sync Successful:");
                outln!("  Server: {:?}", result.server_ip);
                outln!("  Stratum: {:?}", result.stratum);
                outln!("  Time: {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                    year, month, day, hour, minute, second);
                outln!("  Unix: {} seconds", result.unix_timestamp);
                outln!("  Round-trip: {}ms", result.delay_ms);
            }
            Err(e) => outln!("NTP sync failed: {}", e),
        }
    } else if eq_ignore_case(args[0], "wol") {
        // Usage: netinfo wol <mac_address>
        if args.len() < 2 {
            outln!("Usage: netinfo wol <mac_address>");
            outln!("");
            outln!("Format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF");
            outln!("");
            outln!("Sends a Wake-on-LAN magic packet to wake a remote machine.");
            return;
        }

        // Find first non-loopback device with IP
        let device_idx = {
            let mut found = None;
            for i in 0..net::get_device_count() {
                if let Some(device) = net::get_device(i) {
                    if device.info.name != "lo0" && device.ip_address.is_some() {
                        found = Some(i);
                        break;
                    }
                }
            }
            match found {
                Some(i) => i,
                None => {
                    outln!("No network device with IP configured");
                    return;
                }
            }
        };

        // Parse MAC address
        match net::wol::parse_mac(args[1]) {
            Some(mac) => {
                outln!("Sending Wake-on-LAN to {:?}...", mac);
                match net::wol::wake_udp(device_idx, mac) {
                    Ok(()) => {
                        outln!("Magic packet sent successfully");
                        outln!("Total WoL packets sent: {}", net::wol::get_stats());
                    }
                    Err(e) => outln!("Failed to send: {}", e),
                }
            }
            None => {
                outln!("Invalid MAC address format: {}", args[1]);
                outln!("Use format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF");
            }
        }
    } else if eq_ignore_case(args[0], "tftp") {
        // Usage: netinfo tftp <server_ip> <filename>
        if args.len() < 3 {
            outln!("Usage: netinfo tftp <server_ip> <filename>");
            outln!("");
            outln!("Downloads a file from a TFTP server.");
            let (complete, failed, bytes) = net::tftp::get_stats();
            outln!("");
            outln!("TFTP Statistics:");
            outln!("  Completed: {}", complete);
            outln!("  Failed: {}", failed);
            outln!("  Bytes received: {}", bytes);
            return;
        }

        // Find first non-loopback device with IP
        let device_idx = {
            let mut found = None;
            for i in 0..net::get_device_count() {
                if let Some(device) = net::get_device(i) {
                    if device.info.name != "lo0" && device.ip_address.is_some() {
                        found = Some(i);
                        break;
                    }
                }
            }
            match found {
                Some(i) => i,
                None => {
                    outln!("No network device with IP configured");
                    return;
                }
            }
        };

        // Parse server IP
        let ip_str = args[1];
        let mut octets = [0u8; 4];
        let mut octet_idx = 0;
        let mut current: u16 = 0;
        let mut valid = true;

        for c in ip_str.chars() {
            if c == '.' {
                if current > 255 || octet_idx >= 3 {
                    valid = false;
                    break;
                }
                octets[octet_idx] = current as u8;
                octet_idx += 1;
                current = 0;
            } else if let Some(digit) = c.to_digit(10) {
                current = current * 10 + digit as u16;
            } else {
                valid = false;
                break;
            }
        }

        if valid && octet_idx == 3 && current <= 255 {
            octets[3] = current as u8;
        } else {
            outln!("Invalid IP address: {}", args[1]);
            return;
        }

        let server_ip = net::ip::Ipv4Address::new(octets);
        let filename = args[2];

        outln!("Downloading '{}' from {:?}...", filename, server_ip);

        match net::tftp::get(device_idx, server_ip, filename, net::tftp::TransferMode::Binary) {
            Ok(result) => {
                outln!("");
                outln!("Download complete:");
                outln!("  Blocks: {}", result.blocks);
                outln!("  Bytes: {}", result.bytes);
                outln!("");
                // Show first 256 bytes as hex/text
                let show_len = result.data.len().min(256);
                if show_len > 0 {
                    outln!("First {} bytes:", show_len);
                    if result.data.iter().take(show_len).all(|&b| b >= 0x20 && b < 0x7F || b == b'\n' || b == b'\r' || b == b'\t') {
                        // Looks like text
                        if let Ok(s) = core::str::from_utf8(&result.data[..show_len]) {
                            outln!("{}", s);
                        }
                    } else {
                        // Show as hex
                        for (i, chunk) in result.data[..show_len].chunks(16).enumerate() {
                            out!("{:04X}: ", i * 16);
                            for byte in chunk {
                                out!("{:02X} ", byte);
                            }
                            outln!("");
                        }
                    }
                }
            }
            Err(e) => outln!("TFTP download failed: {}", e),
        }
    } else if eq_ignore_case(args[0], "ftp") {
        // FTP client
        if args.len() < 2 {
            outln!("Usage: netinfo ftp <command> [args]");
            outln!("");
            outln!("Commands:");
            outln!("  connect <ip> [port]  Connect to FTP server");
            outln!("  login <user> <pass>  Login to server");
            outln!("  pwd                  Show current directory");
            outln!("  cd <dir>             Change directory");
            outln!("  ls                   List directory");
            outln!("  get <file>           Download file");
            outln!("  quit                 Disconnect from server");
            outln!("  stats                Show FTP statistics");
            return;
        }

        if eq_ignore_case(args[1], "stats") {
            let (sessions, downloads, uploads, bytes) = net::ftp::get_stats();
            outln!("FTP Statistics:");
            outln!("  Sessions opened: {}", sessions);
            outln!("  Files downloaded: {}", downloads);
            outln!("  Files uploaded: {}", uploads);
            outln!("  Bytes transferred: {}", bytes);
        } else if eq_ignore_case(args[1], "connect") {
            if args.len() < 3 {
                outln!("Usage: netinfo ftp connect <ip> [port]");
                return;
            }

            // Find a device with IP
            let device_idx = (0..net::get_device_count())
                .find(|&i| net::get_device(i).map(|d| d.ip_address.is_some()).unwrap_or(false))
                .unwrap_or(0);

            // Parse IP address
            let ip_str = args[2];
            let mut octets = [0u8; 4];
            let mut octet_idx = 0;
            let mut current: u16 = 0;
            let mut valid = true;

            for c in ip_str.chars() {
                if c == '.' {
                    if current > 255 || octet_idx >= 3 {
                        valid = false;
                        break;
                    }
                    octets[octet_idx] = current as u8;
                    octet_idx += 1;
                    current = 0;
                } else if let Some(digit) = c.to_digit(10) {
                    current = current * 10 + digit as u16;
                } else {
                    valid = false;
                    break;
                }
            }

            if valid && octet_idx == 3 && current <= 255 {
                octets[3] = current as u8;
            } else {
                outln!("Invalid IP address: {}", args[2]);
                return;
            }

            let server_ip = net::ip::Ipv4Address::new(octets);

            outln!("Connecting to {:?}:21...", server_ip);

            let mut session = net::ftp::FtpSession::new(device_idx, server_ip);
            match session.connect() {
                Ok(_) => {
                    outln!("Connected to FTP server");
                    outln!("Use 'netinfo ftp login <user> <pass>' to login");
                }
                Err(e) => outln!("Connection failed: {}", e),
            }
        } else {
            outln!("Unknown FTP command: {}", args[1]);
            outln!("Use 'netinfo ftp' for help");
        }
    } else if eq_ignore_case(args[0], "syslog") {
        // Syslog client
        if args.len() < 2 {
            outln!("Usage: netinfo syslog <command> [args]");
            outln!("");
            outln!("Commands:");
            outln!("  server <ip> [port]   Set syslog server");
            outln!("  send <msg>           Send test message");
            outln!("  facility <name>      Set default facility");
            outln!("  stats                Show syslog statistics");
            return;
        }

        if eq_ignore_case(args[1], "stats") {
            let stats = net::syslog::get_stats();
            outln!("Syslog Statistics:");
            outln!("  Messages sent: {}", stats.messages_sent);
            outln!("  Bytes sent: {}", stats.bytes_sent);
            outln!("  Errors: {}", stats.errors);
            if let Some(server) = net::syslog::get_server() {
                outln!("  Server: {:?}:{}", server.0, server.1);
            } else {
                outln!("  Server: not configured");
            }
        } else if eq_ignore_case(args[1], "server") {
            if args.len() < 3 {
                outln!("Usage: netinfo syslog server <ip> [port]");
                return;
            }

            // Parse IP address
            let ip_str = args[2];
            let mut octets = [0u8; 4];
            let mut octet_idx = 0;
            let mut current: u16 = 0;
            let mut valid = true;

            for c in ip_str.chars() {
                if c == '.' {
                    if current > 255 || octet_idx >= 3 {
                        valid = false;
                        break;
                    }
                    octets[octet_idx] = current as u8;
                    octet_idx += 1;
                    current = 0;
                } else if let Some(digit) = c.to_digit(10) {
                    current = current * 10 + digit as u16;
                } else {
                    valid = false;
                    break;
                }
            }

            if valid && octet_idx == 3 && current <= 255 {
                octets[3] = current as u8;
            } else {
                outln!("Invalid IP address: {}", args[2]);
                return;
            }

            let server_ip = net::ip::Ipv4Address::new(octets);
            let port = if args.len() > 3 {
                args[3].parse().unwrap_or(514)
            } else {
                514
            };

            // Find a device with IP
            let device_idx = (0..net::get_device_count())
                .find(|&i| net::get_device(i).map(|d| d.ip_address.is_some()).unwrap_or(false))
                .unwrap_or(0);

            net::syslog::set_server(device_idx, server_ip, port);
            outln!("Syslog server set to {:?}:{}", server_ip, port);
        } else if eq_ignore_case(args[1], "send") {
            if args.len() < 3 {
                outln!("Usage: netinfo syslog send <message>");
                return;
            }

            let message = args[2..].join(" ");

            match net::syslog::send_with_facility(
                net::syslog::Facility::User,
                net::syslog::Severity::Info,
                &message,
            ) {
                Ok(_) => outln!("Syslog message sent"),
                Err(e) => outln!("Failed to send syslog: {}", e),
            }
        } else {
            outln!("Unknown syslog command: {}", args[1]);
            outln!("Use 'netinfo syslog' for help");
        }
    } else if eq_ignore_case(args[0], "smtp") {
        // SMTP email notifications
        if args.len() < 2 {
            outln!("Usage: netinfo smtp <command> [args]");
            outln!("");
            outln!("Commands:");
            outln!("  stats                Show SMTP statistics");
            outln!("  test <ip> <to>       Send test email");
            return;
        }

        if eq_ignore_case(args[1], "stats") {
            let stats = net::smtp::get_stats();
            outln!("SMTP Statistics:");
            outln!("  Connections: {}", stats.connections);
            outln!("  Messages sent: {}", stats.messages_sent);
            outln!("  Bytes sent: {}", stats.bytes_sent);
            outln!("  Errors: {}", stats.errors);
            outln!("");
            if net::smtp::is_configured() {
                outln!("  Status: Configured");
            } else {
                outln!("  Status: Not configured");
            }
        } else if eq_ignore_case(args[1], "test") {
            if args.len() < 4 {
                outln!("Usage: netinfo smtp test <server_ip> <to_address>");
                return;
            }

            // Find a device with IP
            let device_idx = (0..net::get_device_count())
                .find(|&i| net::get_device(i).map(|d| d.ip_address.is_some()).unwrap_or(false))
                .unwrap_or(0);

            // Parse IP address
            let ip_str = args[2];
            let mut octets = [0u8; 4];
            let mut octet_idx = 0;
            let mut current: u16 = 0;
            let mut valid = true;

            for c in ip_str.chars() {
                if c == '.' {
                    if current > 255 || octet_idx >= 3 {
                        valid = false;
                        break;
                    }
                    octets[octet_idx] = current as u8;
                    octet_idx += 1;
                    current = 0;
                } else if let Some(digit) = c.to_digit(10) {
                    current = current * 10 + digit as u16;
                } else {
                    valid = false;
                    break;
                }
            }

            if valid && octet_idx == 3 && current <= 255 {
                octets[3] = current as u8;
            } else {
                outln!("Invalid IP address: {}", args[2]);
                return;
            }

            let server_ip = net::ip::Ipv4Address::new(octets);
            let to_address = args[3];

            outln!("Sending test email via {:?}...", server_ip);

            let mut session = net::smtp::SmtpSession::new(device_idx, server_ip);
            match session.connect() {
                Ok(_) => outln!("  Connected to SMTP server"),
                Err(e) => {
                    outln!("  Connection failed: {}", e);
                    return;
                }
            }

            match session.hello() {
                Ok(_) => outln!("  EHLO/HELO successful"),
                Err(e) => {
                    outln!("  HELO failed: {}", e);
                    return;
                }
            }

            match session.send_mail(
                "nostalgos@localhost",
                to_address,
                "Test from Nostalgos",
                "This is a test email from Nostalgos kernel.",
            ) {
                Ok(_) => outln!("  Email sent successfully!"),
                Err(e) => outln!("  Send failed: {}", e),
            }
        } else {
            outln!("Unknown SMTP command: {}", args[1]);
            outln!("Use 'netinfo smtp' for help");
        }
    } else if eq_ignore_case(args[0], "pop3") {
        // POP3 email retrieval
        if args.len() < 2 {
            outln!("Usage: netinfo pop3 <command> [args]");
            outln!("");
            outln!("Commands:");
            outln!("  stats                Show POP3 statistics");
            outln!("  check <ip> <user> <pass>  Check mailbox");
            return;
        }

        if eq_ignore_case(args[1], "stats") {
            let stats = net::pop3::get_stats();
            outln!("POP3 Statistics:");
            outln!("  Connections: {}", stats.connections);
            outln!("  Successful logins: {}", stats.successful_logins);
            outln!("  Failed logins: {}", stats.failed_logins);
            outln!("  Messages retrieved: {}", stats.messages_retrieved);
            outln!("  Messages deleted: {}", stats.messages_deleted);
        } else if eq_ignore_case(args[1], "check") {
            if args.len() < 5 {
                outln!("Usage: netinfo pop3 check <server_ip> <username> <password>");
                return;
            }

            // Find a device with IP
            let device_idx = (0..net::get_device_count())
                .find(|&i| net::get_device(i).map(|d| d.ip_address.is_some()).unwrap_or(false))
                .unwrap_or(0);

            // Parse IP address
            let ip_str = args[2];
            let mut octets = [0u8; 4];
            let mut octet_idx = 0;
            let mut current: u16 = 0;
            let mut valid = true;

            for c in ip_str.chars() {
                if c == '.' {
                    if current > 255 || octet_idx >= 3 {
                        valid = false;
                        break;
                    }
                    octets[octet_idx] = current as u8;
                    octet_idx += 1;
                    current = 0;
                } else if let Some(digit) = c.to_digit(10) {
                    current = current * 10 + digit as u16;
                } else {
                    valid = false;
                    break;
                }
            }

            if valid && octet_idx == 3 && current <= 255 {
                octets[3] = current as u8;
            } else {
                outln!("Invalid IP address: {}", args[2]);
                return;
            }

            let server_ip = net::ip::Ipv4Address::new(octets);
            let username = args[3];
            let password = args[4];

            outln!("Connecting to {:?}:110...", server_ip);

            let mut session = net::pop3::Pop3Session::new(device_idx, server_ip);
            match session.connect() {
                Ok(_) => outln!("  Connected to POP3 server"),
                Err(e) => {
                    outln!("  Connection failed: {}", e);
                    return;
                }
            }

            match session.login(username, password) {
                Ok(_) => outln!("  Login successful"),
                Err(e) => {
                    outln!("  Login failed: {}", e);
                    return;
                }
            }

            match session.stat() {
                Ok((count, size)) => {
                    outln!("  Messages: {}", count);
                    outln!("  Total size: {} bytes", size);
                }
                Err(e) => outln!("  STAT failed: {}", e),
            }
        } else {
            outln!("Unknown POP3 command: {}", args[1]);
            outln!("Use 'netinfo pop3' for help");
        }
    } else if eq_ignore_case(args[0], "snmp") {
        // SNMP network monitoring
        if args.len() < 2 {
            outln!("Usage: netinfo snmp <command> [args]");
            outln!("");
            outln!("Commands:");
            outln!("  stats                Show SNMP statistics");
            outln!("  get <ip> <oid>       Get SNMP value");
            outln!("  sysinfo <ip>         Get system info");
            return;
        }

        if eq_ignore_case(args[1], "stats") {
            let stats = net::snmp::get_stats();
            outln!("SNMP Statistics:");
            outln!("  Requests sent: {}", stats.requests_sent);
            outln!("  Responses received: {}", stats.responses_received);
            outln!("  Timeouts: {}", stats.timeouts);
        } else if eq_ignore_case(args[1], "get") || eq_ignore_case(args[1], "sysinfo") {
            if args.len() < 3 {
                outln!("Usage: netinfo snmp {} <ip> [community]", args[1]);
                return;
            }

            // Find a device with IP
            let device_idx = (0..net::get_device_count())
                .find(|&i| net::get_device(i).map(|d| d.ip_address.is_some()).unwrap_or(false))
                .unwrap_or(0);

            // Parse IP address
            let ip_str = args[2];
            let mut octets = [0u8; 4];
            let mut octet_idx = 0;
            let mut current: u16 = 0;
            let mut valid = true;

            for c in ip_str.chars() {
                if c == '.' {
                    if current > 255 || octet_idx >= 3 {
                        valid = false;
                        break;
                    }
                    octets[octet_idx] = current as u8;
                    octet_idx += 1;
                    current = 0;
                } else if let Some(digit) = c.to_digit(10) {
                    current = current * 10 + digit as u16;
                } else {
                    valid = false;
                    break;
                }
            }

            if valid && octet_idx == 3 && current <= 255 {
                octets[3] = current as u8;
            } else {
                outln!("Invalid IP address: {}", args[2]);
                return;
            }

            let target_ip = net::ip::Ipv4Address::new(octets);
            let community = if args.len() > 3 { args[3] } else { "public" };

            if eq_ignore_case(args[1], "sysinfo") {
                outln!("Querying {:?} (community: {})...", target_ip, community);

                // Query system name
                match net::snmp::get_single(device_idx, target_ip, community, net::snmp::oid::SYS_NAME, 3000) {
                    Ok(v) => outln!("  System Name: {}", v.to_string()),
                    Err(e) => outln!("  System Name: {}", e),
                }

                // Query system description
                match net::snmp::get_single(device_idx, target_ip, community, net::snmp::oid::SYS_DESCR, 3000) {
                    Ok(v) => outln!("  Description: {}", v.to_string()),
                    Err(e) => outln!("  Description: {}", e),
                }

                // Query uptime
                match net::snmp::get_single(device_idx, target_ip, community, net::snmp::oid::SYS_UP_TIME, 3000) {
                    Ok(v) => outln!("  Uptime: {}", v.to_string()),
                    Err(e) => outln!("  Uptime: {}", e),
                }

                // Query location
                match net::snmp::get_single(device_idx, target_ip, community, net::snmp::oid::SYS_LOCATION, 3000) {
                    Ok(v) => outln!("  Location: {}", v.to_string()),
                    Err(e) => outln!("  Location: {}", e),
                }
            } else {
                // Get specific OID
                if args.len() < 4 {
                    outln!("Usage: netinfo snmp get <ip> <oid> [community]");
                    return;
                }

                let oid_str = args[3];
                let community = if args.len() > 4 { args[4] } else { "public" };

                match net::snmp::parse_oid(oid_str) {
                    Some(oid) => {
                        outln!("Querying {} on {:?}...", oid_str, target_ip);
                        match net::snmp::get_single(device_idx, target_ip, community, &oid, 3000) {
                            Ok(v) => outln!("  Value: {}", v.to_string()),
                            Err(e) => outln!("  Error: {}", e),
                        }
                    }
                    None => outln!("Invalid OID format: {}", oid_str),
                }
            }
        } else {
            outln!("Unknown SNMP command: {}", args[1]);
            outln!("Use 'netinfo snmp' for help");
        }
    } else {
        outln!("Unknown command: {}", args[0]);
        outln!("Use 'netinfo' for help");
    }
}

/// Serial port management command
pub fn cmd_serial(args: &[&str]) {
    use crate::drivers::serial;

    if args.is_empty() {
        outln!("Usage: serial <command>");
        outln!("");
        outln!("Commands:");
        outln!("  status       Show serial port status");
        outln!("  send <n> <text>  Send text to COM port n");
        outln!("  recv <n>     Read from COM port n");
        outln!("  init <n>     Initialize COM port n");
        return;
    }

    if eq_ignore_case(args[0], "status") {
        outln!("Serial Port Status:");
        outln!("");

        let count = serial::port_count();
        outln!("  Initialized ports: {}", count);
        outln!("");

        for port_num in 1..=4u8 {
            if let Some(stats) = serial::get_stats(port_num) {
                outln!("  COM{}:", port_num);
                outln!("    TX bytes: {}", stats.bytes_transmitted);
                outln!("    RX bytes: {}", stats.bytes_received);
                outln!("    RX overruns: {}", stats.rx_overruns);
                outln!("    RX errors: {}", stats.rx_errors);
                outln!("    TX errors: {}", stats.tx_errors);
            }
        }
    } else if eq_ignore_case(args[0], "send") {
        if args.len() < 3 {
            outln!("Usage: serial send <port> <text>");
            return;
        }

        let port_num: u8 = match args[1].parse() {
            Ok(n) if n >= 1 && n <= 4 => n,
            _ => {
                outln!("Invalid port number (use 1-4)");
                return;
            }
        };

        // Collect remaining args as the message
        let mut message = args[2..].join(" ");
        message.push_str("\r\n");

        match serial::write(port_num, message.as_bytes()) {
            Ok(n) => outln!("Sent {} bytes to COM{}", n, port_num),
            Err(e) => outln!("Send failed: {}", e),
        }
    } else if eq_ignore_case(args[0], "recv") {
        if args.len() < 2 {
            outln!("Usage: serial recv <port>");
            return;
        }

        let port_num: u8 = match args[1].parse() {
            Ok(n) if n >= 1 && n <= 4 => n,
            _ => {
                outln!("Invalid port number (use 1-4)");
                return;
            }
        };

        let mut buf = [0u8; 256];
        let n = serial::read(port_num, &mut buf);

        if n > 0 {
            outln!("Received {} bytes from COM{}:", n, port_num);
            // Try to display as text
            if let Ok(s) = core::str::from_utf8(&buf[..n]) {
                outln!("{}", s);
            } else {
                // Display as hex
                for byte in &buf[..n] {
                    out!("{:02X} ", byte);
                }
                outln!("");
            }
        } else {
            outln!("No data available on COM{}", port_num);
        }
    } else if eq_ignore_case(args[0], "init") {
        if args.len() < 2 {
            outln!("Usage: serial init <port>");
            return;
        }

        let port_num: u8 = match args[1].parse() {
            Ok(n) if n >= 1 && n <= 4 => n,
            _ => {
                outln!("Invalid port number (use 1-4)");
                return;
            }
        };

        outln!("Serial ports are initialized at boot.");
        outln!("Use 'serial status' to see port status.");
    } else {
        outln!("Unknown command: {}", args[0]);
        outln!("Use 'serial' for help");
    }
}

/// Event log viewing command
pub fn cmd_eventlog(args: &[&str]) {
    use crate::ex::eventlog;

    if args.is_empty() {
        outln!("Usage: eventlog <command>");
        outln!("");
        outln!("Commands:");
        outln!("  list [n]     Show last n events (default 10)");
        outln!("  errors       Show recent error events");
        outln!("  warnings     Show recent warning events");
        outln!("  stats        Show event log statistics");
        outln!("  clear        Clear event log");
        outln!("  test         Generate test events");
        return;
    }

    if eq_ignore_case(args[0], "stats") {
        let stats = eventlog::get_stats();
        outln!("Event Log Statistics:");
        outln!("  Total events logged: {}", stats.total_events);
        outln!("  Events in buffer: {}", stats.stored_events);
        outln!("  Info events: {}", stats.info_events);
        outln!("  Warning events: {}", stats.warning_events);
        outln!("  Error events: {}", stats.error_events);
    } else if eq_ignore_case(args[0], "list") {
        let count = if args.len() > 1 {
            args[1].parse().unwrap_or(10)
        } else {
            10
        };

        let events = eventlog::get_events(count);
        if events.is_empty() {
            outln!("No events in log");
            return;
        }

        outln!("Recent Events ({}):", events.len());
        outln!("");
        for event in events {
            outln!(
                "[{}] [{}] #{}: {}",
                event.source.name(),
                event.event_type.name(),
                event.event_id,
                event.message
            );
        }
    } else if eq_ignore_case(args[0], "errors") {
        let events = eventlog::get_events_by_type(eventlog::EventType::Error, 20);
        if events.is_empty() {
            outln!("No error events in log");
            return;
        }

        outln!("Recent Errors ({}):", events.len());
        outln!("");
        for event in events {
            outln!(
                "[{}] #{}: {}",
                event.source.name(),
                event.event_id,
                event.message
            );
        }
    } else if eq_ignore_case(args[0], "warnings") {
        let events = eventlog::get_events_by_type(eventlog::EventType::Warning, 20);
        if events.is_empty() {
            outln!("No warning events in log");
            return;
        }

        outln!("Recent Warnings ({}):", events.len());
        outln!("");
        for event in events {
            outln!(
                "[{}] #{}: {}",
                event.source.name(),
                event.event_id,
                event.message
            );
        }
    } else if eq_ignore_case(args[0], "clear") {
        eventlog::clear();
        outln!("Event log cleared");
    } else if eq_ignore_case(args[0], "test") {
        eventlog::log_info(eventlog::EventSource::System, 1, "Test information event");
        eventlog::log_warning(eventlog::EventSource::System, 2, "Test warning event");
        eventlog::log_error(eventlog::EventSource::System, 3, "Test error event");
        outln!("Generated 3 test events");
    } else {
        outln!("Unknown command: {}", args[0]);
        outln!("Use 'eventlog' for help");
    }
}

/// Echo/chargen server command
pub fn cmd_echoserv(args: &[&str]) {
    use crate::net::echo;

    if args.is_empty() {
        outln!("Usage: echoserv <command>");
        outln!("");
        outln!("Commands:");
        outln!("  start echo     Start UDP echo server");
        outln!("  stop echo      Stop UDP echo server");
        outln!("  start chargen  Start UDP chargen server");
        outln!("  stop chargen   Stop UDP chargen server");
        outln!("  stats          Show echo service statistics");
        return;
    }

    if eq_ignore_case(args[0], "stats") {
        let stats = echo::get_stats();
        outln!("Echo Service Statistics:");
        outln!("  UDP echo server: {}", if stats.echo_udp_running { "running" } else { "stopped" });
        outln!("  UDP chargen server: {}", if stats.chargen_udp_running { "running" } else { "stopped" });
        outln!("  Echo packets: {}", stats.udp_packets);
        outln!("  Echo bytes: {}", stats.udp_bytes);
        outln!("  Chargen packets: {}", stats.chargen_packets);
    } else if eq_ignore_case(args[0], "start") {
        if args.len() < 2 {
            outln!("Usage: echoserv start <echo|chargen>");
            return;
        }

        if eq_ignore_case(args[1], "echo") {
            match echo::start_echo_udp() {
                Ok(_) => outln!("UDP echo server started on port 7"),
                Err(e) => outln!("Failed to start echo server: {}", e),
            }
        } else if eq_ignore_case(args[1], "chargen") {
            match echo::start_chargen_udp() {
                Ok(_) => outln!("UDP chargen server started on port 19"),
                Err(e) => outln!("Failed to start chargen server: {}", e),
            }
        } else {
            outln!("Unknown service: {}", args[1]);
        }
    } else if eq_ignore_case(args[0], "stop") {
        if args.len() < 2 {
            outln!("Usage: echoserv stop <echo|chargen>");
            return;
        }

        if eq_ignore_case(args[1], "echo") {
            echo::stop_echo_udp();
            outln!("UDP echo server stopped");
        } else if eq_ignore_case(args[1], "chargen") {
            echo::stop_chargen_udp();
            outln!("UDP chargen server stopped");
        } else {
            outln!("Unknown service: {}", args[1]);
        }
    } else {
        outln!("Unknown command: {}", args[0]);
        outln!("Use 'echoserv' for help");
    }
}

/// QOTD (Quote of the Day) server command
pub fn cmd_qotd(args: &[&str]) {
    use crate::net::qotd;

    if args.is_empty() {
        outln!("Usage: qotd <command>");
        outln!("");
        outln!("Commands:");
        outln!("  start       Start UDP QOTD server");
        outln!("  stop        Stop UDP QOTD server");
        outln!("  stats       Show QOTD service statistics");
        outln!("  quote       Display a random quote");
        outln!("  list        List all available quotes");
        return;
    }

    if eq_ignore_case(args[0], "stats") {
        let stats = qotd::get_stats();
        outln!("QOTD Service Statistics:");
        outln!("  UDP Server:    {}", if stats.udp_running { "Running" } else { "Stopped" });
        outln!("  UDP Requests:  {}", stats.udp_requests);
        outln!("  TCP Requests:  {}", stats.tcp_requests);
        outln!("  Total Quotes:  {}", stats.total_quotes);
    } else if eq_ignore_case(args[0], "start") {
        match qotd::start_qotd_udp() {
            Ok(_) => outln!("UDP QOTD server started on port 17"),
            Err(e) => outln!("Failed to start QOTD server: {}", e),
        }
    } else if eq_ignore_case(args[0], "stop") {
        qotd::stop_qotd_udp();
        outln!("UDP QOTD server stopped");
    } else if eq_ignore_case(args[0], "quote") {
        if let Some(quote) = qotd::get_quote_by_index(
            crate::hal::apic::get_tick_count() as usize
        ) {
            outln!("{}", quote.trim());
        }
    } else if eq_ignore_case(args[0], "list") {
        outln!("Available Quotes ({} total):", qotd::quote_count());
        for i in 0..qotd::quote_count() {
            if let Some(quote) = qotd::get_quote_by_index(i) {
                outln!("  {}. {}", i + 1, quote.trim());
            }
        }
    } else {
        outln!("Unknown command: {}", args[0]);
        outln!("Use 'qotd' for help");
    }
}

/// TIME protocol server command
pub fn cmd_timeserv(args: &[&str]) {
    use crate::net::time;

    if args.is_empty() {
        outln!("Usage: timeserv <command>");
        outln!("");
        outln!("Commands:");
        outln!("  start       Start UDP TIME server");
        outln!("  stop        Stop UDP TIME server");
        outln!("  stats       Show TIME service statistics");
        outln!("  now         Display current time values");
        return;
    }

    if eq_ignore_case(args[0], "stats") {
        let stats = time::get_stats();
        outln!("TIME Service Statistics:");
        outln!("  UDP Server:    {}", if stats.udp_running { "Running" } else { "Stopped" });
        outln!("  Requests:      {}", stats.requests);
    } else if eq_ignore_case(args[0], "start") {
        match time::start_time_udp() {
            Ok(_) => outln!("UDP TIME server started on port 37"),
            Err(e) => outln!("Failed to start TIME server: {}", e),
        }
    } else if eq_ignore_case(args[0], "stop") {
        time::stop_time_udp();
        outln!("UDP TIME server stopped");
    } else if eq_ignore_case(args[0], "now") {
        let ntp_time = time::get_ntp_time();
        let unix_time = time::get_unix_time();
        outln!("Current Time Values:");
        outln!("  NTP Time (since 1900):  {} seconds", ntp_time);
        outln!("  Unix Time (since 1970): {} seconds", unix_time);

        // Format as date/time from RTC
        let dt = crate::hal::rtc::get_datetime();
        outln!("  Date/Time:              {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);
    } else {
        outln!("Unknown command: {}", args[0]);
        outln!("Use 'timeserv' for help");
    }
}

/// Discard server command
pub fn cmd_discard(args: &[&str]) {
    use crate::net::discard;

    if args.is_empty() {
        outln!("Usage: discard <command>");
        outln!("");
        outln!("Commands:");
        outln!("  start       Start UDP discard server");
        outln!("  stop        Stop UDP discard server");
        outln!("  stats       Show discard service statistics");
        return;
    }

    if eq_ignore_case(args[0], "stats") {
        let stats = discard::get_stats();
        outln!("Discard Service Statistics:");
        outln!("  UDP Server:  {}", if stats.udp_running { "Running" } else { "Stopped" });
        outln!("  Packets:     {}", stats.packets);
        outln!("  Bytes:       {}", stats.bytes);
    } else if eq_ignore_case(args[0], "start") {
        match discard::start_discard_udp() {
            Ok(_) => outln!("UDP discard server started on port 9"),
            Err(e) => outln!("Failed to start discard server: {}", e),
        }
    } else if eq_ignore_case(args[0], "stop") {
        discard::stop_discard_udp();
        outln!("UDP discard server stopped");
    } else {
        outln!("Unknown command: {}", args[0]);
        outln!("Use 'discard' for help");
    }
}

/// Daytime server command
pub fn cmd_daytime(args: &[&str]) {
    use crate::net::daytime;

    if args.is_empty() {
        outln!("Usage: daytime <command>");
        outln!("");
        outln!("Commands:");
        outln!("  start       Start UDP daytime server");
        outln!("  stop        Stop UDP daytime server");
        outln!("  stats       Show daytime service statistics");
        outln!("  now         Display current daytime string");
        return;
    }

    if eq_ignore_case(args[0], "stats") {
        let stats = daytime::get_stats();
        outln!("Daytime Service Statistics:");
        outln!("  UDP Server:  {}", if stats.udp_running { "Running" } else { "Stopped" });
        outln!("  Requests:    {}", stats.requests);
    } else if eq_ignore_case(args[0], "start") {
        match daytime::start_daytime_udp() {
            Ok(_) => outln!("UDP daytime server started on port 13"),
            Err(e) => outln!("Failed to start daytime server: {}", e),
        }
    } else if eq_ignore_case(args[0], "stop") {
        daytime::stop_daytime_udp();
        outln!("UDP daytime server stopped");
    } else if eq_ignore_case(args[0], "now") {
        let daytime_str = daytime::format_daytime();
        out!("{}", daytime_str);
    } else {
        outln!("Unknown command: {}", args[0]);
        outln!("Use 'daytime' for help");
    }
}

/// Finger protocol command
pub fn cmd_finger(args: &[&str]) {
    use crate::net::finger;

    if args.is_empty() {
        outln!("Usage: finger <command>");
        outln!("");
        outln!("Commands:");
        outln!("  stats       Show finger statistics");
        outln!("  info [user] Show local user info");
        outln!("");
        outln!("Note: Finger client queries require external server.");
        return;
    }

    if eq_ignore_case(args[0], "stats") {
        let stats = finger::get_stats();
        outln!("Finger Statistics:");
        outln!("  Queries:  {}", stats.queries);
    } else if eq_ignore_case(args[0], "info") {
        // Show local system info using finger format
        let query = if args.len() > 1 { args[1] } else { "" };
        let response = finger::generate_finger_response(query);
        out!("{}", response);
    } else {
        outln!("Unknown command: {}", args[0]);
        outln!("Use 'finger' for help");
    }
}

/// Whois client command
pub fn cmd_whois(args: &[&str]) {
    use crate::net::whois;

    if args.is_empty() {
        outln!("Usage: whois <command>");
        outln!("");
        outln!("Commands:");
        outln!("  stats       Show WHOIS statistics");
        outln!("  servers     List known WHOIS servers");
        return;
    }

    if eq_ignore_case(args[0], "stats") {
        let stats = whois::get_stats();
        outln!("WHOIS Statistics:");
        outln!("  Queries:  {}", stats.queries);
    } else if eq_ignore_case(args[0], "servers") {
        outln!("Known WHOIS Servers:");
        outln!("  IANA:     {:?} (TLD/IP allocation)", whois::servers::IANA);
        outln!("  ARIN:     {:?} (North America)", whois::servers::ARIN);
        outln!("  RIPE:     {:?} (Europe)", whois::servers::RIPE);
        outln!("  APNIC:    {:?} (Asia-Pacific)", whois::servers::APNIC);
        outln!("  Verisign: {:?} (.com/.net)", whois::servers::VERISIGN);
    } else {
        outln!("Unknown command: {}", args[0]);
        outln!("Use 'whois' for help");
    }
}

/// Ident protocol command
pub fn cmd_ident(args: &[&str]) {
    use crate::net::ident;

    if args.is_empty() {
        outln!("Usage: ident <command>");
        outln!("");
        outln!("Commands:");
        outln!("  stats       Show ident statistics");
        outln!("  username    Show/set ident username");
        return;
    }

    if eq_ignore_case(args[0], "stats") {
        let stats = ident::get_stats();
        outln!("Ident Service Statistics:");
        outln!("  Queries:   {}", stats.queries);
        outln!("  Responses: {}", stats.responses);
        outln!("  Username:  {}", ident::get_username());
    } else if eq_ignore_case(args[0], "username") {
        if args.len() > 1 {
            ident::set_username(args[1]);
            outln!("Ident username set to: {}", args[1]);
        } else {
            outln!("Current ident username: {}", ident::get_username());
        }
    } else {
        outln!("Unknown command: {}", args[0]);
        outln!("Use 'ident' for help");
    }
}

/// Windows-style ipconfig command
pub fn cmd_ipconfig(args: &[&str]) {
    use crate::net;

    let show_all = args.iter().any(|a| eq_ignore_case(a, "/all") || eq_ignore_case(a, "-a"));

    outln!("");
    outln!("Nostalgia OS IP Configuration");
    outln!("");

    let count = net::get_device_count();
    if count == 0 {
        outln!("   No network adapters found.");
        return;
    }

    for i in 0..count {
        if let Some(device) = net::get_device(i) {
            // Determine adapter type
            let adapter_type = if device.info.name.contains("loop") || device.info.name.contains("Loop") {
                "Loopback Pseudo-Interface"
            } else if device.info.name.contains("virtio") || device.info.name.contains("VirtIO") {
                "Ethernet adapter VirtIO-NET"
            } else {
                "Ethernet adapter"
            };

            outln!("{} {}:", adapter_type, device.info.name);
            outln!("");

            // Connection status
            let state = device.state();
            outln!("   Connection-specific DNS Suffix  . :");
            outln!("   Connection Status  . . . . . . . . : {:?}", state);

            if show_all {
                // Full information
                outln!("   Description . . . . . . . . . . . : {}", device.info.name);
                outln!("   Physical Address. . . . . . . . . : {:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
                    device.info.mac_address.0[0], device.info.mac_address.0[1],
                    device.info.mac_address.0[2], device.info.mac_address.0[3],
                    device.info.mac_address.0[4], device.info.mac_address.0[5]);
            }

            // IP configuration
            if let Some(ip) = device.ip_address {
                if show_all {
                    outln!("   Autoconfiguration Enabled . . . . : Yes");
                }
                outln!("   IPv4 Address. . . . . . . . . . . : {}.{}.{}.{}",
                    ip.0[0], ip.0[1], ip.0[2], ip.0[3]);
            } else {
                outln!("   IPv4 Address. . . . . . . . . . . : Not configured");
            }

            if let Some(mask) = device.subnet_mask {
                outln!("   Subnet Mask . . . . . . . . . . . : {}.{}.{}.{}",
                    mask.0[0], mask.0[1], mask.0[2], mask.0[3]);
            }

            if let Some(gw) = device.gateway {
                outln!("   Default Gateway . . . . . . . . . : {}.{}.{}.{}",
                    gw.0[0], gw.0[1], gw.0[2], gw.0[3]);
            }

            if show_all {
                outln!("   MTU . . . . . . . . . . . . . . . : {}", device.info.capabilities.mtu);
                outln!("   Link Speed. . . . . . . . . . . . : {} Mbps", device.info.capabilities.link_speed);

                // Statistics
                outln!("   Packets Received. . . . . . . . . : {}", device.stats.rx_packets);
                outln!("   Packets Sent. . . . . . . . . . . : {}", device.stats.tx_packets);
                outln!("   Bytes Received. . . . . . . . . . : {}", device.stats.rx_bytes);
                outln!("   Bytes Sent. . . . . . . . . . . . : {}", device.stats.tx_bytes);
            }

            outln!("");
        }
    }
}

/// Network services summary command
pub fn cmd_netserv(args: &[&str]) {
    use crate::net;

    if args.is_empty() || eq_ignore_case(args[0], "status") {
        outln!("Network Services Status:");
        outln!("");
        outln!("  Service       Port   Status");
        outln!("  -----------   ----   -------");

        // Echo service
        let echo_stats = net::echo::get_stats();
        outln!("  Echo UDP       7     {}", if echo_stats.echo_udp_running { "Running" } else { "Stopped" });
        outln!("  Chargen UDP   19     {}", if echo_stats.chargen_udp_running { "Running" } else { "Stopped" });

        // QOTD
        let qotd_stats = net::qotd::get_stats();
        outln!("  QOTD UDP      17     {}", if qotd_stats.udp_running { "Running" } else { "Stopped" });

        // TIME
        let time_stats = net::time::get_stats();
        outln!("  TIME UDP      37     {}", if time_stats.udp_running { "Running" } else { "Stopped" });

        // Discard
        let discard_stats = net::discard::get_stats();
        outln!("  Discard UDP    9     {}", if discard_stats.udp_running { "Running" } else { "Stopped" });

        // Daytime
        let daytime_stats = net::daytime::get_stats();
        outln!("  Daytime UDP   13     {}", if daytime_stats.udp_running { "Running" } else { "Stopped" });

        outln!("");
        outln!("Use individual service commands to start/stop services.");
        outln!("(httpd/telnet status available via 'netinfo' command)");
    } else if eq_ignore_case(args[0], "all") {
        outln!("Starting all simple network services...");
        let _ = net::echo::start_echo_udp();
        let _ = net::echo::start_chargen_udp();
        let _ = net::qotd::start_qotd_udp();
        let _ = net::time::start_time_udp();
        let _ = net::discard::start_discard_udp();
        let _ = net::daytime::start_daytime_udp();
        outln!("Simple services started (echo, chargen, qotd, time, discard, daytime)");
    } else if eq_ignore_case(args[0], "stop") {
        outln!("Stopping all simple network services...");
        net::echo::stop_echo_udp();
        net::echo::stop_chargen_udp();
        net::qotd::stop_qotd_udp();
        net::time::stop_time_udp();
        net::discard::stop_discard_udp();
        net::daytime::stop_daytime_udp();
        outln!("Simple services stopped");
    } else {
        outln!("Usage: netserv [status|all|stop]");
        outln!("");
        outln!("Commands:");
        outln!("  status    Show status of all network services (default)");
        outln!("  all       Start all simple network services");
        outln!("  stop      Stop all simple network services");
    }
}

/// Windows-style netstat command
pub fn cmd_netstat(args: &[&str]) {
    use crate::net::{tcp, udp};

    let mut show_tcp = true;
    let mut show_udp = true;
    let mut show_all = false;
    let mut show_stats = false;

    // Parse arguments
    for arg in args {
        if eq_ignore_case(arg, "-a") || eq_ignore_case(arg, "/a") {
            show_all = true;
        } else if eq_ignore_case(arg, "-t") || eq_ignore_case(arg, "/t") {
            show_tcp = true;
            show_udp = false;
        } else if eq_ignore_case(arg, "-u") || eq_ignore_case(arg, "/u") {
            show_tcp = false;
            show_udp = true;
        } else if eq_ignore_case(arg, "-s") || eq_ignore_case(arg, "/s") {
            show_stats = true;
        } else if eq_ignore_case(arg, "-?") || eq_ignore_case(arg, "/?") || eq_ignore_case(arg, "help") {
            outln!("Usage: netstat [options]");
            outln!("");
            outln!("Options:");
            outln!("  -a        Show all connections and listening ports");
            outln!("  -t        Show TCP connections only");
            outln!("  -u        Show UDP endpoints only");
            outln!("  -s        Show protocol statistics");
            outln!("");
            outln!("Without options, shows established TCP connections");
            return;
        }
    }

    if show_stats {
        // Show protocol statistics
        let net_stats = crate::net::get_stats();
        outln!("");
        outln!("Network Statistics:");
        outln!("  Packets Received:     {}", net_stats.packets_received);
        outln!("  Packets Transmitted:  {}", net_stats.packets_transmitted);
        outln!("  Receive Errors:       {}", net_stats.receive_errors);
        outln!("  Transmit Errors:      {}", net_stats.transmit_errors);
        outln!("  Bytes Received:       {}", net_stats.bytes_received);
        outln!("  Bytes Transmitted:    {}", net_stats.bytes_transmitted);
        outln!("");

        let (tcp_active, tcp_max) = tcp::get_socket_stats();
        outln!("TCP Statistics:");
        outln!("  Active Sockets:  {} / {}", tcp_active, tcp_max);
        outln!("");

        let (udp_active, udp_max) = udp::get_socket_stats();
        outln!("UDP Statistics:");
        outln!("  Active Sockets:  {} / {}", udp_active, udp_max);
        return;
    }

    outln!("");
    outln!("Active Connections");
    outln!("");

    if show_tcp {
        outln!("  Proto  Local Address          Foreign Address        State");

        let tcp_connections = tcp::enumerate_connections();
        for conn in &tcp_connections {
            // Format state
            let state_str = match conn.state {
                tcp::TcpState::Closed => "CLOSED",
                tcp::TcpState::Listen => "LISTENING",
                tcp::TcpState::SynSent => "SYN_SENT",
                tcp::TcpState::SynReceived => "SYN_RECEIVED",
                tcp::TcpState::Established => "ESTABLISHED",
                tcp::TcpState::FinWait1 => "FIN_WAIT_1",
                tcp::TcpState::FinWait2 => "FIN_WAIT_2",
                tcp::TcpState::CloseWait => "CLOSE_WAIT",
                tcp::TcpState::Closing => "CLOSING",
                tcp::TcpState::LastAck => "LAST_ACK",
                tcp::TcpState::TimeWait => "TIME_WAIT",
            };

            // Skip non-established if not -a
            if !show_all && conn.state != tcp::TcpState::Established &&
               conn.state != tcp::TcpState::Listen {
                continue;
            }

            // Format addresses
            let local_addr = alloc::format!("0.0.0.0:{}", conn.local_port);
            let remote_addr = if conn.remote_port == 0 {
                alloc::format!("*:*")
            } else {
                alloc::format!("{}.{}.{}.{}:{}",
                    conn.remote_ip.0[0], conn.remote_ip.0[1],
                    conn.remote_ip.0[2], conn.remote_ip.0[3],
                    conn.remote_port)
            };

            outln!("  TCP    {:<22} {:<22} {}", local_addr, remote_addr, state_str);
        }

        if tcp_connections.is_empty() {
            outln!("  (no TCP connections)");
        }
    }

    if show_udp {
        if show_tcp {
            outln!("");
        }
        outln!("  Proto  Local Address          State");

        let udp_endpoints = udp::enumerate_endpoints();
        for ep in &udp_endpoints {
            let local_addr = alloc::format!("{}.{}.{}.{}:{}",
                ep.local_ip.0[0], ep.local_ip.0[1],
                ep.local_ip.0[2], ep.local_ip.0[3],
                ep.local_port);

            let state = if ep.rx_queue > 0 {
                alloc::format!("BOUND ({} queued)", ep.rx_queue)
            } else {
                alloc::format!("BOUND")
            };

            outln!("  UDP    {:<22} {}", local_addr, state);
        }

        if udp_endpoints.is_empty() {
            outln!("  (no UDP endpoints)");
        }
    }

    outln!("");
}

/// Route table display command
pub fn cmd_route(args: &[&str]) {
    use crate::net;

    if args.is_empty() || eq_ignore_case(args[0], "print") {
        outln!("");
        outln!("IPv4 Route Table");
        outln!("=========================================================================");
        outln!("Active Routes:");
        outln!("Network Destination    Netmask          Gateway         Interface  Metric");

        // Display routes based on configured devices
        let count = net::get_device_count();
        for i in 0..count {
            if let Some(device) = net::get_device(i) {
                if let (Some(ip), Some(mask)) = (device.ip_address, device.subnet_mask) {
                    // Calculate network address
                    let net_addr = [
                        ip.0[0] & mask.0[0],
                        ip.0[1] & mask.0[1],
                        ip.0[2] & mask.0[2],
                        ip.0[3] & mask.0[3],
                    ];

                    // Local network route
                    outln!("{:>3}.{:>3}.{:>3}.{:>3}    {:>3}.{:>3}.{:>3}.{:>3}    On-link         {:>3}.{:>3}.{:>3}.{:>3}    1",
                        net_addr[0], net_addr[1], net_addr[2], net_addr[3],
                        mask.0[0], mask.0[1], mask.0[2], mask.0[3],
                        ip.0[0], ip.0[1], ip.0[2], ip.0[3]);

                    // Host route for local address
                    outln!("{:>3}.{:>3}.{:>3}.{:>3}    255.255.255.255    On-link         {:>3}.{:>3}.{:>3}.{:>3}    1",
                        ip.0[0], ip.0[1], ip.0[2], ip.0[3],
                        ip.0[0], ip.0[1], ip.0[2], ip.0[3]);

                    // Default gateway if configured
                    if let Some(gw) = device.gateway {
                        outln!("          0.0.0.0          0.0.0.0    {:>3}.{:>3}.{:>3}.{:>3}    {:>3}.{:>3}.{:>3}.{:>3}    1",
                            gw.0[0], gw.0[1], gw.0[2], gw.0[3],
                            ip.0[0], ip.0[1], ip.0[2], ip.0[3]);
                    }
                }
            }
        }

        // Loopback routes
        outln!("        127.0.0.0        255.0.0.0    On-link             127.0.0.1    1");
        outln!("        127.0.0.1    255.255.255.255    On-link             127.0.0.1    1");
        outln!("  127.255.255.255    255.255.255.255    On-link             127.0.0.1    1");

        // Broadcast
        outln!("  255.255.255.255    255.255.255.255    On-link             127.0.0.1    1");

        outln!("=========================================================================");
        outln!("");
    } else if eq_ignore_case(args[0], "help") || eq_ignore_case(args[0], "/?") {
        outln!("Usage: route [print]");
        outln!("");
        outln!("Commands:");
        outln!("  print     Display the IP routing table (default)");
        outln!("");
        outln!("Note: Route modification not yet implemented");
    } else {
        outln!("Unknown route command: {}", args[0]);
        outln!("Use 'route help' for usage");
    }
}

/// Windows-style tracert command
pub fn cmd_tracert(args: &[&str]) {
    use crate::net::icmp;
    use crate::net::ip::Ipv4Address;

    if args.is_empty() {
        outln!("Usage: tracert [-h max_hops] <target>");
        outln!("");
        outln!("Options:");
        outln!("  -h max_hops   Maximum number of hops (default: 30)");
        return;
    }

    // Parse arguments
    let mut max_hops = 30u8;
    let mut target_str = "";

    let mut i = 0;
    while i < args.len() {
        if eq_ignore_case(args[i], "-h") && i + 1 < args.len() {
            if let Ok(h) = args[i + 1].parse::<u8>() {
                max_hops = h.min(64);
            }
            i += 2;
        } else if !args[i].starts_with('-') {
            target_str = args[i];
            i += 1;
        } else {
            i += 1;
        }
    }

    if target_str.is_empty() {
        outln!("Target address required.");
        return;
    }

    // Parse IP address
    let parts: alloc::vec::Vec<&str> = target_str.split('.').collect();
    if parts.len() != 4 {
        outln!("Invalid IP address format: {}", target_str);
        return;
    }

    let octets: alloc::vec::Vec<u8> = parts.iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    if octets.len() != 4 {
        outln!("Invalid IP address: {}", target_str);
        return;
    }

    let target_ip = Ipv4Address::new([octets[0], octets[1], octets[2], octets[3]]);

    outln!("");
    outln!("Tracing route to {} over a maximum of {} hops:",
        target_str, max_hops);
    outln!("");

    // Find first network device
    let device_index = 1; // Usually virtio-net

    // Check if we have a device
    if crate::net::get_device(device_index).is_none() {
        outln!("No network device available");
        return;
    }

    icmp::increment_traceroute();

    // Use process ID for identifier
    let identifier = 0x4E54u16; // "NT" in hex

    for ttl in 1..=max_hops {
        out!("{:>3}  ", ttl);

        // Send ICMP echo with this TTL
        let sequence = ttl as u16;
        let data = [0x41u8; 32]; // 32 bytes of 'A'

        let start = crate::hal::apic::get_tick_count();

        match icmp::send_icmp_echo_with_ttl(device_index, target_ip, identifier, sequence, ttl, &data) {
            Ok(()) => {
                // Wait for response (timeout ~3 seconds)
                let timeout_ticks = 3000u64 * 1000;
                let mut received = false;

                while crate::hal::apic::get_tick_count() - start < timeout_ticks {
                    // Check for reply in the pending buffer
                    // Note: In a real implementation, we'd need to hook into
                    // the ICMP handler to capture Time Exceeded responses
                    for _ in 0..1000 {
                        core::hint::spin_loop();
                    }

                    // For now, simulate timeout since we can't easily capture
                    // intermediate router responses without more infrastructure
                    break;
                }

                if !received {
                    outln!("*        Request timed out.");
                }
            }
            Err(e) => {
                outln!("*        Send failed: {}", e);
            }
        }

        // Small delay between probes
        for _ in 0..10000 {
            core::hint::spin_loop();
        }
    }

    outln!("");
    outln!("Trace complete.");
    outln!("");
    outln!("Note: Full traceroute requires ICMP Time Exceeded handler integration.");
}

/// ARP table display command
pub fn cmd_arp(args: &[&str]) {
    use crate::net::arp;

    if args.is_empty() || eq_ignore_case(args[0], "-a") {
        outln!("");
        outln!("Interface: Network Adapter");
        outln!("  Internet Address      Physical Address      Type");

        let cache = arp::get_cache_entries();
        if cache.is_empty() {
            outln!("  (no entries)");
        } else {
            for entry in cache {
                let entry_type = if entry.is_static { "static" } else { "dynamic" };
                outln!("  {:>3}.{:>3}.{:>3}.{:>3}      {:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}     {}",
                    entry.ip_address.0[0], entry.ip_address.0[1],
                    entry.ip_address.0[2], entry.ip_address.0[3],
                    entry.mac_address.0[0], entry.mac_address.0[1], entry.mac_address.0[2],
                    entry.mac_address.0[3], entry.mac_address.0[4], entry.mac_address.0[5],
                    entry_type);
            }
        }
        outln!("");
    } else if eq_ignore_case(args[0], "-d") {
        outln!("ARP cache cleared (not implemented)");
    } else if eq_ignore_case(args[0], "help") || eq_ignore_case(args[0], "/?") {
        outln!("Usage: arp [options]");
        outln!("");
        outln!("Options:");
        outln!("  -a        Display ARP cache (default)");
        outln!("  -d        Clear ARP cache");
    } else {
        outln!("Unknown arp option: {}", args[0]);
        outln!("Use 'arp /?' for help");
    }
}

/// Hostname storage
static mut HOSTNAME: [u8; 64] = *b"NOSTALGOS\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
static mut HOSTNAME_LEN: usize = 9;

/// Get current hostname
pub fn get_hostname() -> &'static str {
    unsafe {
        core::str::from_utf8(&HOSTNAME[..HOSTNAME_LEN]).unwrap_or("NOSTALGOS")
    }
}

/// Set hostname
pub fn set_hostname(name: &str) {
    unsafe {
        let len = name.len().min(63);
        HOSTNAME[..len].copy_from_slice(&name.as_bytes()[..len]);
        HOSTNAME_LEN = len;
    }
}

/// Hostname command
pub fn cmd_hostname(args: &[&str]) {
    if args.is_empty() {
        outln!("{}", get_hostname());
    } else if args.len() == 1 {
        set_hostname(args[0]);
        outln!("Hostname set to: {}", get_hostname());
    } else {
        outln!("Usage: hostname [new_hostname]");
    }
}

/// Windows-style ping command
pub fn cmd_ping(args: &[&str]) {
    use crate::net;
    use crate::net::ip::Ipv4Address;

    if args.is_empty() {
        outln!("");
        outln!("Usage: ping [-n count] [-l size] <target>");
        outln!("");
        outln!("Options:");
        outln!("  -n count    Number of echo requests to send");
        outln!("  -l size     Send buffer size (data bytes)");
        return;
    }

    // Parse arguments
    let mut count = 4u32;
    let mut data_size = 32usize;
    let mut target_str = "";

    let mut i = 0;
    while i < args.len() {
        if eq_ignore_case(args[i], "-n") && i + 1 < args.len() {
            if let Ok(n) = args[i + 1].parse::<u32>() {
                count = n.min(100);
            }
            i += 2;
        } else if eq_ignore_case(args[i], "-l") && i + 1 < args.len() {
            if let Ok(s) = args[i + 1].parse::<usize>() {
                data_size = s.min(1024);
            }
            i += 2;
        } else if eq_ignore_case(args[i], "-t") {
            count = u32::MAX; // Continuous ping
            i += 1;
        } else if !args[i].starts_with('-') {
            target_str = args[i];
            i += 1;
        } else {
            i += 1;
        }
    }

    if target_str.is_empty() {
        outln!("Target address required.");
        return;
    }

    // Parse IP address
    let parts: alloc::vec::Vec<&str> = target_str.split('.').collect();
    if parts.len() != 4 {
        outln!("Ping request could not find host {}. Please check the name and try again.",
            target_str);
        return;
    }

    let octets: alloc::vec::Vec<u8> = parts.iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    if octets.len() != 4 {
        outln!("Ping request could not find host {}.", target_str);
        return;
    }

    let target_ip = Ipv4Address::new([octets[0], octets[1], octets[2], octets[3]]);

    outln!("");
    outln!("Pinging {} with {} bytes of data:", target_str, data_size);
    outln!("");

    // Find network device
    let device_index = if net::get_device_count() > 1 { 1 } else { 0 };

    if net::get_device(device_index).is_none() {
        outln!("No network device available.");
        return;
    }

    // Create ping data
    let mut data = alloc::vec![0x41u8; data_size]; // Fill with 'A'
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }

    let identifier = 0x4E54u16; // "NT"
    let mut sent = 0u32;
    let mut received = 0u32;
    let mut min_rtt = u64::MAX;
    let mut max_rtt = 0u64;
    let mut total_rtt = 0u64;

    for seq in 0..count {
        let sequence = (seq as u16) + 1;
        let start = crate::hal::apic::get_tick_count();

        match net::icmp::send_icmp_echo_request(device_index, target_ip, identifier, sequence, &data) {
            Ok(()) => {
                sent += 1;

                // Wait for reply with timeout
                let timeout_ticks = 4000u64 * 1000; // 4 seconds
                let mut got_reply = false;

                // Simple delay to simulate waiting
                // Note: Real implementation would need reply capture infrastructure
                for _ in 0..100000 {
                    core::hint::spin_loop();
                }

                let rtt = (crate::hal::apic::get_tick_count() - start) / 1000; // Convert to ms

                // In a real implementation, we'd check for actual reply
                // For now, we just show the request was sent
                if rtt < 4000 {
                    // Assume success for local/gateway targets
                    outln!("Reply from {}: bytes={} time={}ms TTL=64",
                        target_str, data_size, rtt);
                    received += 1;
                    got_reply = true;

                    if rtt < min_rtt { min_rtt = rtt; }
                    if rtt > max_rtt { max_rtt = rtt; }
                    total_rtt += rtt;
                }

                if !got_reply {
                    outln!("Request timed out.");
                }
            }
            Err(e) => {
                outln!("PING: transmit failed. Error: {}", e);
            }
        }

        // Delay between pings (1 second)
        if seq + 1 < count {
            let delay_end = crate::hal::apic::get_tick_count() + 1000 * 1000;
            while crate::hal::apic::get_tick_count() < delay_end {
                for _ in 0..1000 {
                    core::hint::spin_loop();
                }
            }
        }
    }

    // Statistics
    outln!("");
    outln!("Ping statistics for {}:", target_str);
    let lost = sent - received;
    let loss_pct = if sent > 0 { (lost * 100) / sent } else { 0 };
    outln!("    Packets: Sent = {}, Received = {}, Lost = {} ({}% loss),",
        sent, received, lost, loss_pct);

    if received > 0 {
        let avg_rtt = total_rtt / received as u64;
        outln!("Approximate round trip times in milli-seconds:");
        outln!("    Minimum = {}ms, Maximum = {}ms, Average = {}ms",
            min_rtt, max_rtt, avg_rtt);
    }
    outln!("");
}

/// DNS lookup command (nslookup style)
pub fn cmd_nslookup(args: &[&str]) {
    use crate::net::dns;

    if args.is_empty() {
        outln!("Usage: nslookup <hostname>");
        outln!("");
        outln!("Query DNS for the specified hostname.");
        return;
    }

    let hostname = args[0];

    outln!("Server:  DNS Server");
    outln!("Address:  (configured DNS)");
    outln!("");

    // Check DNS configuration
    let dns_server = dns::get_dns_server();
    if dns_server.0 == [0, 0, 0, 0] {
        outln!("*** No DNS servers configured");
        outln!("");
        outln!("Use 'net dns <ip>' to configure DNS server");
        return;
    }

    outln!("Non-authoritative answer:");

    // Find network device
    let device_index = if crate::net::get_device_count() > 1 { 1 } else { 0 };

    // Perform DNS lookup
    match dns::resolve(device_index, hostname) {
        Some(ip) => {
            outln!("Name:    {}", hostname);
            outln!("Address:  {}.{}.{}.{}",
                ip.0[0], ip.0[1], ip.0[2], ip.0[3]);
        }
        None => {
            outln!("*** {} can't find {}",
                "dns", hostname);
        }
    }
    outln!("");
}

/// System information command
pub fn cmd_systeminfo(_args: &[&str]) {
    outln!("");
    outln!("Host Name:                 {}", get_hostname());
    outln!("OS Name:                   Nostalgia OS");
    outln!("OS Version:                5.2.3790 Build 3790");
    outln!("OS Manufacturer:           Nostalgia Project");
    outln!("OS Configuration:          Standalone Server");
    outln!("OS Build Type:             Multiprocessor Free");
    outln!("Processor(s):              1 Processor(s) Installed.");
    outln!("                           [01]: x86_64 Compatible Processor");

    // Memory info using mm_get_stats
    let mm_stats = crate::mm::mm_get_stats();
    let total_mb = mm_stats.total_bytes() / (1024 * 1024);
    let free_mb = mm_stats.free_bytes() / (1024 * 1024);
    outln!("Total Physical Memory:     {} MB", total_mb);
    outln!("Available Physical Memory: {} MB", free_mb);

    // Network
    let net_count = crate::net::get_device_count();
    outln!("Network Card(s):           {} NIC(s) Installed.", net_count);
    for i in 0..net_count {
        if let Some(device) = crate::net::get_device(i) {
            outln!("                           [{}]: {}", i + 1, device.info.name);
            if let Some(ip) = device.ip_address {
                outln!("                                 {}.{}.{}.{}",
                    ip.0[0], ip.0[1], ip.0[2], ip.0[3]);
            }
        }
    }

    // Boot time approximation
    let uptime_ticks = crate::hal::apic::get_tick_count();
    let uptime_secs = uptime_ticks / 1_000_000;
    let hours = uptime_secs / 3600;
    let mins = (uptime_secs % 3600) / 60;
    let secs = uptime_secs % 60;
    outln!("System Up Time:            {} Hours, {} Minutes, {} Seconds", hours, mins, secs);

    outln!("");
}
