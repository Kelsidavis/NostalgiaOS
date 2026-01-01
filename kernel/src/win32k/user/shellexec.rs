//! Shell Execute Helpers
//!
//! Windows shell execute functions.
//! Based on Windows Server 2003 shellapi.h.
//!
//! # Features
//!
//! - ShellExecute/ShellExecuteEx
//! - File associations
//! - Verb handling (open, edit, print, etc.)
//!
//! # References
//!
//! - `public/sdk/inc/shellapi.h` - ShellExecute

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND};
use super::strhelp;

// ============================================================================
// ShellExecute Return Values
// ============================================================================

/// Success (instance handle)
pub const SE_ERR_SUCCESS: usize = 32;

/// Out of memory
pub const SE_ERR_OOM: usize = 8;

/// File not found
pub const SE_ERR_FNF: usize = 2;

/// Path not found
pub const SE_ERR_PNF: usize = 3;

/// Access denied
pub const SE_ERR_ACCESSDENIED: usize = 5;

/// No association
pub const SE_ERR_NOASSOC: usize = 31;

/// Share error
pub const SE_ERR_SHARE: usize = 26;

/// DDE busy
pub const SE_ERR_DDEBUSY: usize = 30;

/// DDE fail
pub const SE_ERR_DDEFAIL: usize = 29;

/// DDE timeout
pub const SE_ERR_DDETIMEOUT: usize = 28;

/// DLL not found
pub const SE_ERR_DLLNOTFOUND: usize = 32;

// ============================================================================
// ShellExecuteEx Flags (SEE_MASK_*)
// ============================================================================

/// Use class name
pub const SEE_MASK_CLASSNAME: u32 = 0x00000001;

/// Use class key
pub const SEE_MASK_CLASSKEY: u32 = 0x00000003;

/// Use ID list
pub const SEE_MASK_IDLIST: u32 = 0x00000004;

/// Use invokeidlist
pub const SEE_MASK_INVOKEIDLIST: u32 = 0x0000000C;

/// Use icon
pub const SEE_MASK_ICON: u32 = 0x00000010;

/// Use hotkey
pub const SEE_MASK_HOTKEY: u32 = 0x00000020;

/// No close process
pub const SEE_MASK_NOCLOSEPROCESS: u32 = 0x00000040;

/// Connect network drive
pub const SEE_MASK_CONNECTNETDRV: u32 = 0x00000080;

/// No async
pub const SEE_MASK_NOASYNC: u32 = 0x00000100;

/// Flag DDEWAIT
pub const SEE_MASK_FLAG_DDEWAIT: u32 = SEE_MASK_NOASYNC;

/// Do environment subst
pub const SEE_MASK_DOENVSUBST: u32 = 0x00000200;

/// No UI
pub const SEE_MASK_FLAG_NO_UI: u32 = 0x00000400;

/// Unicode
pub const SEE_MASK_UNICODE: u32 = 0x00004000;

/// No console
pub const SEE_MASK_NO_CONSOLE: u32 = 0x00008000;

/// Async OK
pub const SEE_MASK_ASYNCOK: u32 = 0x00100000;

/// No zone check
pub const SEE_MASK_NOZONECHECKS: u32 = 0x00800000;

/// No query class store
pub const SEE_MASK_NOQUERYCLASSSTORE: u32 = 0x01000000;

/// Wait for input idle
pub const SEE_MASK_WAITFORINPUTIDLE: u32 = 0x02000000;

/// Flag log usage
pub const SEE_MASK_FLAG_LOG_USAGE: u32 = 0x04000000;

// ============================================================================
// Standard Verbs
// ============================================================================

/// Open verb
pub const VERB_OPEN: &[u8] = b"open";

/// Edit verb
pub const VERB_EDIT: &[u8] = b"edit";

/// Print verb
pub const VERB_PRINT: &[u8] = b"print";

/// Explore verb
pub const VERB_EXPLORE: &[u8] = b"explore";

/// Find verb
pub const VERB_FIND: &[u8] = b"find";

/// Properties verb
pub const VERB_PROPERTIES: &[u8] = b"properties";

/// Run as verb
pub const VERB_RUNAS: &[u8] = b"runas";

// ============================================================================
// SHELLEXECUTEINFO Structure
// ============================================================================

/// Maximum file path
pub const MAX_PATH: usize = 260;

/// Shell execute info
#[derive(Clone)]
pub struct ShellExecuteInfo {
    /// Structure size
    pub cb_size: u32,
    /// Flags
    pub mask: u32,
    /// Parent window
    pub hwnd: HWND,
    /// Verb (open, edit, etc.)
    pub verb: [u8; 32],
    /// File to execute
    pub file: [u8; MAX_PATH],
    /// Parameters
    pub parameters: [u8; MAX_PATH],
    /// Directory
    pub directory: [u8; MAX_PATH],
    /// Show command
    pub show: i32,
    /// Result (instance handle or error)
    pub inst_app: usize,
    /// ID list
    pub id_list: usize,
    /// Class name
    pub class_name: [u8; 64],
    /// Class key
    pub class_key: usize,
    /// Hotkey
    pub hotkey: u32,
    /// Icon/Monitor
    pub icon: usize,
    /// Process handle
    pub process: usize,
}

impl ShellExecuteInfo {
    /// Create default info
    pub const fn new() -> Self {
        Self {
            cb_size: 0,
            mask: 0,
            hwnd: UserHandle::NULL,
            verb: [0; 32],
            file: [0; MAX_PATH],
            parameters: [0; MAX_PATH],
            directory: [0; MAX_PATH],
            show: 1, // SW_SHOWNORMAL
            inst_app: 0,
            id_list: 0,
            class_name: [0; 64],
            class_key: 0,
            hotkey: 0,
            icon: 0,
            process: 0,
        }
    }
}

// ============================================================================
// File Association Storage
// ============================================================================

/// Maximum file associations
pub const MAX_ASSOCIATIONS: usize = 64;

/// File association entry
#[derive(Clone)]
pub struct FileAssociation {
    /// Is this slot in use
    pub in_use: bool,
    /// Extension (e.g., ".txt")
    pub extension: [u8; 16],
    /// Program path
    pub program: [u8; MAX_PATH],
    /// Default verb
    pub default_verb: [u8; 32],
    /// Description
    pub description: [u8; 64],
    /// Content type
    pub content_type: [u8; 64],
}

impl FileAssociation {
    pub const fn new() -> Self {
        Self {
            in_use: false,
            extension: [0; 16],
            program: [0; MAX_PATH],
            default_verb: [0; 32],
            description: [0; 64],
            content_type: [0; 64],
        }
    }
}

static ASSOCIATIONS: SpinLock<[FileAssociation; MAX_ASSOCIATIONS]> =
    SpinLock::new([const { FileAssociation::new() }; MAX_ASSOCIATIONS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize shell execute
pub fn init() {
    // Register some default associations
    register_default_associations();
    crate::serial_println!("[USER] Shell execute helpers initialized");
}

/// Register default file associations
fn register_default_associations() {
    let defaults: &[(&[u8], &[u8], &[u8], &[u8])] = &[
        (b".txt", b"notepad.exe", b"open", b"Text Document"),
        (b".exe", b"", b"open", b"Application"),
        (b".bat", b"cmd.exe", b"open", b"Batch File"),
        (b".cmd", b"cmd.exe", b"open", b"Command Script"),
        (b".htm", b"iexplore.exe", b"open", b"HTML Document"),
        (b".html", b"iexplore.exe", b"open", b"HTML Document"),
        (b".doc", b"winword.exe", b"open", b"Word Document"),
        (b".pdf", b"acrobat.exe", b"open", b"PDF Document"),
        (b".jpg", b"mspaint.exe", b"open", b"JPEG Image"),
        (b".png", b"mspaint.exe", b"open", b"PNG Image"),
        (b".bmp", b"mspaint.exe", b"open", b"Bitmap Image"),
    ];

    for &(ext, prog, verb, desc) in defaults.iter() {
        let _ = register_association(ext, prog, verb, desc);
    }
}

/// Register file association
pub fn register_association(
    extension: &[u8],
    program: &[u8],
    default_verb: &[u8],
    description: &[u8],
) -> bool {
    let mut assocs = ASSOCIATIONS.lock();

    // Check if already exists
    for assoc in assocs.iter_mut() {
        if assoc.in_use && strhelp::str_cmp_i(&assoc.extension, extension) == 0 {
            // Update existing
            let prog_len = strhelp::str_len(program).min(MAX_PATH - 1);
            assoc.program[..prog_len].copy_from_slice(&program[..prog_len]);
            assoc.program[prog_len] = 0;
            return true;
        }
    }

    // Add new
    for assoc in assocs.iter_mut() {
        if !assoc.in_use {
            assoc.in_use = true;

            let ext_len = strhelp::str_len(extension).min(15);
            assoc.extension[..ext_len].copy_from_slice(&extension[..ext_len]);
            assoc.extension[ext_len] = 0;

            let prog_len = strhelp::str_len(program).min(MAX_PATH - 1);
            assoc.program[..prog_len].copy_from_slice(&program[..prog_len]);
            assoc.program[prog_len] = 0;

            let verb_len = strhelp::str_len(default_verb).min(31);
            assoc.default_verb[..verb_len].copy_from_slice(&default_verb[..verb_len]);
            assoc.default_verb[verb_len] = 0;

            let desc_len = strhelp::str_len(description).min(63);
            assoc.description[..desc_len].copy_from_slice(&description[..desc_len]);
            assoc.description[desc_len] = 0;

            return true;
        }
    }

    false
}

/// Find association for extension
pub fn find_association(extension: &[u8]) -> Option<usize> {
    let assocs = ASSOCIATIONS.lock();

    for (i, assoc) in assocs.iter().enumerate() {
        if assoc.in_use && strhelp::str_cmp_i(&assoc.extension, extension) == 0 {
            return Some(i);
        }
    }

    None
}

/// Get program for extension
pub fn get_associated_program(extension: &[u8], buffer: &mut [u8]) -> bool {
    let assocs = ASSOCIATIONS.lock();

    for assoc in assocs.iter() {
        if assoc.in_use && strhelp::str_cmp_i(&assoc.extension, extension) == 0 {
            let len = strhelp::str_len(&assoc.program).min(buffer.len() - 1);
            buffer[..len].copy_from_slice(&assoc.program[..len]);
            buffer[len] = 0;
            return true;
        }
    }

    false
}

/// Shell execute (simple version)
pub fn shell_execute(
    hwnd: HWND,
    verb: &[u8],
    file: &[u8],
    parameters: &[u8],
    directory: &[u8],
    show_cmd: i32,
) -> usize {
    let _ = (hwnd, show_cmd);

    // Get file extension
    let ext_pos = strhelp::path_find_extension(file);

    // Check for URL
    let scheme_len = strhelp::url_get_scheme_length(file);
    if scheme_len > 0 {
        // URL handling would go here
        return SE_ERR_NOASSOC;
    }

    // Find association
    if let Some(ext) = ext_pos {
        let extension = &file[ext..];

        // Check if it's an executable
        if strhelp::str_cmp_ni(extension, b".exe", 4) == 0
            || strhelp::str_cmp_ni(extension, b".com", 4) == 0
        {
            // Direct execution
            let _ = (parameters, directory);
            return SE_ERR_SUCCESS + 1;
        }

        // Look up association
        if find_association(extension).is_some() {
            // Would launch associated program here
            let _ = verb;
            return SE_ERR_SUCCESS + 1;
        }
    }

    SE_ERR_NOASSOC
}

/// Shell execute extended
pub fn shell_execute_ex(info: &mut ShellExecuteInfo) -> bool {
    // Use verb if specified, otherwise "open"
    let verb = if info.verb[0] != 0 {
        &info.verb[..]
    } else {
        VERB_OPEN
    };

    let result = shell_execute(
        info.hwnd,
        verb,
        &info.file,
        &info.parameters,
        &info.directory,
        info.show,
    );

    info.inst_app = result;

    // Set process handle if requested
    if (info.mask & SEE_MASK_NOCLOSEPROCESS) != 0 {
        info.process = 0; // Would be actual process handle
    }

    result > 32
}

/// Find executable for document
pub fn find_executable(file: &[u8], directory: &[u8], result: &mut [u8]) -> usize {
    let _ = directory;

    // Get extension
    let ext_pos = match strhelp::path_find_extension(file) {
        Some(p) => p,
        None => return SE_ERR_NOASSOC,
    };

    let extension = &file[ext_pos..];

    // Check if it's already an executable
    if strhelp::str_cmp_ni(extension, b".exe", 4) == 0
        || strhelp::str_cmp_ni(extension, b".com", 4) == 0
    {
        let len = strhelp::str_len(file).min(result.len() - 1);
        result[..len].copy_from_slice(&file[..len]);
        result[len] = 0;
        return SE_ERR_SUCCESS + 1;
    }

    // Look up association
    if get_associated_program(extension, result) {
        SE_ERR_SUCCESS + 1
    } else {
        SE_ERR_NOASSOC
    }
}

/// Get file description
pub fn get_file_description(extension: &[u8], buffer: &mut [u8]) -> bool {
    let assocs = ASSOCIATIONS.lock();

    for assoc in assocs.iter() {
        if assoc.in_use && strhelp::str_cmp_i(&assoc.extension, extension) == 0 {
            let len = strhelp::str_len(&assoc.description).min(buffer.len() - 1);
            buffer[..len].copy_from_slice(&assoc.description[..len]);
            buffer[len] = 0;
            return true;
        }
    }

    false
}

/// Open with default program
pub fn shell_open(file: &[u8]) -> usize {
    shell_execute(
        UserHandle::NULL,
        VERB_OPEN,
        file,
        b"",
        b"",
        1, // SW_SHOWNORMAL
    )
}

/// Print with default program
pub fn shell_print(file: &[u8]) -> usize {
    shell_execute(
        UserHandle::NULL,
        VERB_PRINT,
        file,
        b"",
        b"",
        0, // SW_HIDE
    )
}

/// Explore folder
pub fn shell_explore(path: &[u8]) -> usize {
    shell_execute(
        UserHandle::NULL,
        VERB_EXPLORE,
        path,
        b"",
        b"",
        1, // SW_SHOWNORMAL
    )
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> ShellExecStats {
    let assocs = ASSOCIATIONS.lock();

    let mut count = 0;
    for assoc in assocs.iter() {
        if assoc.in_use {
            count += 1;
        }
    }

    ShellExecStats {
        max_associations: MAX_ASSOCIATIONS,
        registered_associations: count,
    }
}

/// Shell execute statistics
#[derive(Debug, Clone, Copy)]
pub struct ShellExecStats {
    pub max_associations: usize,
    pub registered_associations: usize,
}
