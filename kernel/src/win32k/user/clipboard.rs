//! Clipboard Subsystem
//!
//! Implementation of Windows NT-style clipboard for data transfer.
//! Provides system-wide clipboard with format support.
//!
//! # Components
//!
//! - **Clipboard access**: OpenClipboard, CloseClipboard
//! - **Data management**: SetClipboardData, GetClipboardData
//! - **Format handling**: Standard and custom formats
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/clip.c`
//! - `windows/core/ntuser/kernel/clipdata.c`

use super::super::{HWND, UserHandle};
use crate::ke::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum clipboard data size
const MAX_CLIPBOARD_DATA: usize = 65536;

/// Maximum number of clipboard formats
const MAX_CLIPBOARD_FORMATS: usize = 16;

// ============================================================================
// Standard Clipboard Formats (CF_*)
// ============================================================================

/// Clipboard format types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClipboardFormat {
    /// No format
    #[default]
    None = 0,
    /// Text format (null-terminated)
    Text = 1,
    /// Bitmap format
    Bitmap = 2,
    /// Metafile picture format
    MetafilePict = 3,
    /// SYLK (symbolic link)
    Sylk = 4,
    /// DIF (data interchange format)
    Dif = 5,
    /// TIFF image
    Tiff = 6,
    /// OEM text
    OemText = 7,
    /// Device-independent bitmap
    Dib = 8,
    /// Palette handle
    Palette = 9,
    /// Pen data
    PenData = 10,
    /// RIFF audio
    Riff = 11,
    /// Wave audio
    Wave = 12,
    /// Unicode text
    UnicodeText = 13,
    /// Enhanced metafile
    EnhMetafile = 14,
    /// HDROP (file list)
    HDrop = 15,
    /// Locale identifier
    Locale = 16,
    /// DIB V5 bitmap
    DibV5 = 17,
    /// Owner display
    OwnerDisplay = 0x0080,
    /// Display text
    DspText = 0x0081,
    /// Display bitmap
    DspBitmap = 0x0082,
    /// Display metafile
    DspMetafilePict = 0x0083,
    /// Display enhanced metafile
    DspEnhMetafile = 0x008E,
    /// First private format
    PrivateFirst = 0x0200,
    /// Last private format
    PrivateLast = 0x02FF,
    /// First GDI object format
    GdiObjFirst = 0x0300,
    /// Last GDI object format
    GdiObjLast = 0x03FF,
}

impl ClipboardFormat {
    /// Get format from u32
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Text,
            2 => Self::Bitmap,
            3 => Self::MetafilePict,
            7 => Self::OemText,
            8 => Self::Dib,
            13 => Self::UnicodeText,
            14 => Self::EnhMetafile,
            _ => Self::None,
        }
    }
}

// ============================================================================
// Clipboard Data Entry
// ============================================================================

/// Clipboard data entry
#[derive(Clone)]
struct ClipboardEntry {
    /// Data format
    format: ClipboardFormat,
    /// Data buffer
    data: [u8; MAX_CLIPBOARD_DATA],
    /// Data length
    len: usize,
    /// Is this entry in use?
    in_use: bool,
}

impl ClipboardEntry {
    const fn empty() -> Self {
        Self {
            format: ClipboardFormat::None,
            data: [0; MAX_CLIPBOARD_DATA],
            len: 0,
            in_use: false,
        }
    }
}

// ============================================================================
// Clipboard State
// ============================================================================

/// Clipboard state
struct ClipboardState {
    /// Is clipboard open?
    is_open: bool,
    /// Owner window
    owner: HWND,
    /// Clipboard sequence number (increments on change)
    sequence: u32,
    /// Clipboard data entries
    entries: [ClipboardEntry; MAX_CLIPBOARD_FORMATS],
    /// Number of formats
    format_count: usize,
}

impl ClipboardState {
    const fn new() -> Self {
        Self {
            is_open: false,
            owner: UserHandle::NULL,
            sequence: 0,
            entries: [
                ClipboardEntry::empty(), ClipboardEntry::empty(),
                ClipboardEntry::empty(), ClipboardEntry::empty(),
                ClipboardEntry::empty(), ClipboardEntry::empty(),
                ClipboardEntry::empty(), ClipboardEntry::empty(),
                ClipboardEntry::empty(), ClipboardEntry::empty(),
                ClipboardEntry::empty(), ClipboardEntry::empty(),
                ClipboardEntry::empty(), ClipboardEntry::empty(),
                ClipboardEntry::empty(), ClipboardEntry::empty(),
            ],
            format_count: 0,
        }
    }
}

static CLIPBOARD: SpinLock<ClipboardState> = SpinLock::new(ClipboardState::new());
static CLIPBOARD_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Initialization
// ============================================================================

/// Initialize clipboard subsystem
pub fn init() {
    if CLIPBOARD_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[USER/Clipboard] Clipboard subsystem initialized");
    CLIPBOARD_INITIALIZED.store(true, Ordering::Release);
}

// ============================================================================
// Clipboard Access
// ============================================================================

/// Open the clipboard for access
///
/// # Arguments
/// * `hwnd` - Window to associate with clipboard operations
///
/// # Returns
/// true if clipboard was opened, false if already open by another window
pub fn open_clipboard(hwnd: HWND) -> bool {
    let mut state = CLIPBOARD.lock();

    if state.is_open {
        return false;
    }

    state.is_open = true;
    state.owner = hwnd;

    crate::serial_println!("[USER/Clipboard] Opened by {:x}", hwnd.raw());
    true
}

/// Close the clipboard
pub fn close_clipboard() -> bool {
    let mut state = CLIPBOARD.lock();

    if !state.is_open {
        return false;
    }

    state.is_open = false;

    crate::serial_println!("[USER/Clipboard] Closed");
    true
}

/// Get the clipboard owner window
pub fn get_clipboard_owner() -> HWND {
    let state = CLIPBOARD.lock();
    state.owner
}

/// Check if a format is available on the clipboard
pub fn is_clipboard_format_available(format: ClipboardFormat) -> bool {
    let state = CLIPBOARD.lock();

    for entry in state.entries.iter() {
        if entry.in_use && entry.format == format {
            return true;
        }
    }

    false
}

// ============================================================================
// Clipboard Data Management
// ============================================================================

/// Empty the clipboard
///
/// # Returns
/// true on success, false if clipboard is not open
pub fn empty_clipboard() -> bool {
    let mut state = CLIPBOARD.lock();

    if !state.is_open {
        return false;
    }

    // Clear all entries
    for entry in state.entries.iter_mut() {
        entry.in_use = false;
        entry.len = 0;
    }
    state.format_count = 0;
    state.sequence += 1;

    crate::serial_println!("[USER/Clipboard] Emptied");
    true
}

/// Set clipboard data
///
/// # Arguments
/// * `format` - Data format
/// * `data` - Data bytes
///
/// # Returns
/// true on success
pub fn set_clipboard_data(format: ClipboardFormat, data: &[u8]) -> bool {
    let mut state = CLIPBOARD.lock();

    if !state.is_open {
        return false;
    }

    // Check if format already exists
    for entry in state.entries.iter_mut() {
        if entry.in_use && entry.format == format {
            // Replace existing data
            let len = data.len().min(MAX_CLIPBOARD_DATA);
            entry.data[..len].copy_from_slice(&data[..len]);
            entry.len = len;
            state.sequence += 1;
            return true;
        }
    }

    // Find empty slot
    for entry in state.entries.iter_mut() {
        if !entry.in_use {
            entry.format = format;
            let len = data.len().min(MAX_CLIPBOARD_DATA);
            entry.data[..len].copy_from_slice(&data[..len]);
            entry.len = len;
            entry.in_use = true;
            state.format_count += 1;
            state.sequence += 1;

            crate::serial_println!("[USER/Clipboard] Set {:?} data ({} bytes)", format, len);
            return true;
        }
    }

    false
}

/// Get clipboard data
///
/// # Arguments
/// * `format` - Data format to retrieve
/// * `buffer` - Buffer to copy data into
///
/// # Returns
/// Number of bytes copied, or 0 if format not found
pub fn get_clipboard_data(format: ClipboardFormat, buffer: &mut [u8]) -> usize {
    let state = CLIPBOARD.lock();

    for entry in state.entries.iter() {
        if entry.in_use && entry.format == format {
            let len = entry.len.min(buffer.len());
            buffer[..len].copy_from_slice(&entry.data[..len]);
            return len;
        }
    }

    0
}

/// Get clipboard data size
///
/// # Arguments
/// * `format` - Data format
///
/// # Returns
/// Size of data in bytes, or 0 if format not found
pub fn get_clipboard_data_size(format: ClipboardFormat) -> usize {
    let state = CLIPBOARD.lock();

    for entry in state.entries.iter() {
        if entry.in_use && entry.format == format {
            return entry.len;
        }
    }

    0
}

// ============================================================================
// Text Clipboard Helpers
// ============================================================================

/// Set clipboard text (CF_TEXT)
pub fn set_clipboard_text(text: &str) -> bool {
    // Text must be null-terminated
    let bytes = text.as_bytes();
    let mut data = [0u8; MAX_CLIPBOARD_DATA];
    let len = bytes.len().min(MAX_CLIPBOARD_DATA - 1);
    data[..len].copy_from_slice(&bytes[..len]);
    // Null terminator is already 0

    set_clipboard_data(ClipboardFormat::Text, &data[..len + 1])
}

/// Get clipboard text (CF_TEXT)
pub fn get_clipboard_text(buffer: &mut [u8]) -> usize {
    let len = get_clipboard_data(ClipboardFormat::Text, buffer);

    // Remove null terminator from length
    if len > 0 && buffer[len - 1] == 0 {
        len - 1
    } else {
        len
    }
}

/// Get clipboard text as string slice
pub fn get_clipboard_text_str<'a>(buffer: &'a mut [u8]) -> &'a str {
    let len = get_clipboard_text(buffer);
    core::str::from_utf8(&buffer[..len]).unwrap_or("")
}

// ============================================================================
// Format Enumeration
// ============================================================================

/// Count available clipboard formats
pub fn count_clipboard_formats() -> u32 {
    let state = CLIPBOARD.lock();
    state.format_count as u32
}

/// Enumerate clipboard formats
///
/// # Arguments
/// * `format` - Previous format (0 to start enumeration)
///
/// # Returns
/// Next format, or None if no more formats
pub fn enum_clipboard_formats(format: ClipboardFormat) -> Option<ClipboardFormat> {
    let state = CLIPBOARD.lock();

    let mut found_current = format == ClipboardFormat::None;

    for entry in state.entries.iter() {
        if entry.in_use {
            if found_current {
                return Some(entry.format);
            }
            if entry.format == format {
                found_current = true;
            }
        }
    }

    None
}

/// Get priority clipboard format from a list
pub fn get_priority_clipboard_format(formats: &[ClipboardFormat]) -> Option<ClipboardFormat> {
    let state = CLIPBOARD.lock();

    for &format in formats {
        for entry in state.entries.iter() {
            if entry.in_use && entry.format == format {
                return Some(format);
            }
        }
    }

    None
}

// ============================================================================
// Clipboard Sequence
// ============================================================================

/// Get clipboard sequence number
///
/// This number changes each time the clipboard contents change
pub fn get_clipboard_sequence_number() -> u32 {
    let state = CLIPBOARD.lock();
    state.sequence
}

// ============================================================================
// Custom Format Registration
// ============================================================================

/// Next custom format ID
static NEXT_CUSTOM_FORMAT: AtomicU32 = AtomicU32::new(0xC000);

/// Registered format name
struct RegisteredFormat {
    name: [u8; 64],
    name_len: usize,
    format_id: u32,
    in_use: bool,
}

impl RegisteredFormat {
    const fn empty() -> Self {
        Self {
            name: [0; 64],
            name_len: 0,
            format_id: 0,
            in_use: false,
        }
    }
}

/// Registered formats table
static REGISTERED_FORMATS: SpinLock<[RegisteredFormat; 64]> = SpinLock::new([
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
    RegisteredFormat::empty(), RegisteredFormat::empty(),
]);

/// Register a custom clipboard format
///
/// # Arguments
/// * `format_name` - Name of the format
///
/// # Returns
/// Format ID (can be used with SetClipboardData/GetClipboardData)
pub fn register_clipboard_format(format_name: &str) -> u32 {
    let mut formats = REGISTERED_FORMATS.lock();

    // Check if already registered
    let name_bytes = format_name.as_bytes();
    for fmt in formats.iter() {
        if fmt.in_use && fmt.name_len == name_bytes.len() {
            if &fmt.name[..fmt.name_len] == name_bytes {
                return fmt.format_id;
            }
        }
    }

    // Register new format
    for fmt in formats.iter_mut() {
        if !fmt.in_use {
            let len = name_bytes.len().min(63);
            fmt.name[..len].copy_from_slice(&name_bytes[..len]);
            fmt.name_len = len;
            fmt.format_id = NEXT_CUSTOM_FORMAT.fetch_add(1, Ordering::Relaxed);
            fmt.in_use = true;

            crate::serial_println!("[USER/Clipboard] Registered format '{}' as 0x{:X}",
                format_name, fmt.format_id);
            return fmt.format_id;
        }
    }

    0 // Failed
}

/// Get clipboard format name
pub fn get_clipboard_format_name(format: u32, buffer: &mut [u8]) -> usize {
    // Check standard formats
    if format < 0xC000 {
        let name = match format {
            1 => "CF_TEXT",
            2 => "CF_BITMAP",
            7 => "CF_OEMTEXT",
            8 => "CF_DIB",
            13 => "CF_UNICODETEXT",
            14 => "CF_ENHMETAFILE",
            _ => return 0,
        };
        let len = name.len().min(buffer.len());
        buffer[..len].copy_from_slice(&name.as_bytes()[..len]);
        return len;
    }

    // Check registered formats
    let formats = REGISTERED_FORMATS.lock();
    for fmt in formats.iter() {
        if fmt.in_use && fmt.format_id == format {
            let len = fmt.name_len.min(buffer.len());
            buffer[..len].copy_from_slice(&fmt.name[..len]);
            return len;
        }
    }

    0
}

// ============================================================================
// Statistics
// ============================================================================

/// Clipboard statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct ClipboardStats {
    pub is_open: bool,
    pub format_count: usize,
    pub sequence: u32,
}

/// Get clipboard statistics
pub fn get_stats() -> ClipboardStats {
    let state = CLIPBOARD.lock();
    ClipboardStats {
        is_open: state.is_open,
        format_count: state.format_count,
        sequence: state.sequence,
    }
}
