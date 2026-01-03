//! Palette Management - Windows Color Palette Support
//!
//! Implements color palette management following the Windows NT GDI architecture.
//! Palettes are used for color mapping on 8-bit (256 color) displays and for
//! color animation.
//!
//! # Palette Architecture
//!
//! Windows uses logical palettes that map to the system (hardware) palette:
//! - LOGPALETTE: Logical palette with PALETTEENTRY array
//! - CreatePalette: Creates logical palette from LOGPALETTE
//! - SelectPalette: Selects palette into DC
//! - RealizePalette: Maps logical palette to system palette
//!
//! # Color Matching
//!
//! When drawing with palettes:
//! - Foreground application gets exact colors in system palette
//! - Background applications get closest matches
//! - PC_RESERVED entries reserved for animation
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntuser/kernel/palette.c` - Palette handling
//! - `windows/core/ntgdi/gre/palette.cxx` - GRE palette implementation

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;
use super::super::{GdiHandle, ColorRef, HPALETTE, HDC};

// ============================================================================
// Palette Entry Flags (PC_*)
// ============================================================================

/// Palette index used for animation
pub const PC_RESERVED: u8 = 0x01;
/// Palette index is explicit to device
pub const PC_EXPLICIT: u8 = 0x02;
/// Do not match color to system palette
pub const PC_NOCOLLAPSE: u8 = 0x04;

// ============================================================================
// System Palette Indices
// ============================================================================

/// Index for black in system palette
pub const SYSPAL_BLACK: u8 = 0;
/// Index for white in system palette
pub const SYSPAL_WHITE: u8 = 255;
/// First usable palette index (after system colors)
pub const SYSPAL_FIRST_FREE: u8 = 10;
/// Last usable palette index (before system colors)
pub const SYSPAL_LAST_FREE: u8 = 245;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum palettes that can be created
const MAX_PALETTES: usize = 256;

/// Maximum entries per palette
const MAX_PALETTE_ENTRIES: usize = 256;

/// System palette size
const SYSTEM_PALETTE_SIZE: usize = 256;

/// Default palette version
const PALETTE_VERSION: u16 = 0x0300;

// ============================================================================
// Structures
// ============================================================================

/// Palette entry (PALETTEENTRY)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PaletteEntry {
    /// Red component (0-255)
    pub red: u8,
    /// Green component (0-255)
    pub green: u8,
    /// Blue component (0-255)
    pub blue: u8,
    /// Flags (PC_RESERVED, PC_EXPLICIT, PC_NOCOLLAPSE)
    pub flags: u8,
}

impl PaletteEntry {
    /// Create a new palette entry
    pub const fn new(red: u8, green: u8, blue: u8) -> Self {
        Self {
            red,
            green,
            blue,
            flags: 0,
        }
    }

    /// Create palette entry with flags
    pub const fn with_flags(red: u8, green: u8, blue: u8, flags: u8) -> Self {
        Self { red, green, blue, flags }
    }

    /// Create from ColorRef
    pub const fn from_colorref(color: ColorRef) -> Self {
        Self {
            red: color.red(),
            green: color.green(),
            blue: color.blue(),
            flags: 0,
        }
    }

    /// Convert to ColorRef
    pub const fn to_colorref(&self) -> ColorRef {
        ColorRef::rgb(self.red, self.green, self.blue)
    }
}

/// Logical palette header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LogPalette {
    /// Palette version (should be 0x0300)
    pub version: u16,
    /// Number of entries
    pub num_entries: u16,
}

impl LogPalette {
    /// Create a new logical palette header
    pub const fn new(num_entries: u16) -> Self {
        Self {
            version: PALETTE_VERSION,
            num_entries,
        }
    }
}

/// Internal palette object
#[derive(Clone, Copy)]
struct Palette {
    /// Palette in use
    in_use: bool,
    /// Palette handle
    handle: HPALETTE,
    /// Number of entries
    num_entries: u16,
    /// Palette entries
    entries: [PaletteEntry; MAX_PALETTE_ENTRIES],
    /// Reference count
    ref_count: u32,
    /// Currently selected into a DC
    selected: bool,
    /// DC this palette is selected into
    selected_dc: HDC,
    /// Is this a stock palette
    is_stock: bool,
}

impl Palette {
    const fn new() -> Self {
        Self {
            in_use: false,
            handle: GdiHandle(0),
            num_entries: 0,
            entries: [PaletteEntry::new(0, 0, 0); MAX_PALETTE_ENTRIES],
            ref_count: 0,
            selected: false,
            selected_dc: GdiHandle(0),
            is_stock: false,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Palette subsystem initialized
static PALETTE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Palette subsystem lock
static PALETTE_LOCK: SpinLock<()> = SpinLock::new(());

/// All palettes
static PALETTES: SpinLock<[Palette; MAX_PALETTES]> =
    SpinLock::new([const { Palette::new() }; MAX_PALETTES]);

/// System palette (hardware palette on 8-bit displays)
static SYSTEM_PALETTE: SpinLock<[PaletteEntry; SYSTEM_PALETTE_SIZE]> =
    SpinLock::new([const { PaletteEntry::new(0, 0, 0) }; SYSTEM_PALETTE_SIZE]);

/// Next palette handle
static NEXT_PALETTE_HANDLE: AtomicU32 = AtomicU32::new(1);

/// Palette allocation count
static PALETTE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Stock default palette handle
static DEFAULT_PALETTE: SpinLock<HPALETTE> = SpinLock::new(GdiHandle(0));

// ============================================================================
// Default System Palette (20 static colors)
// ============================================================================

/// Standard 20-color system palette
static DEFAULT_ENTRIES: [PaletteEntry; 20] = [
    // First 10 colors (Windows standard)
    PaletteEntry::new(0x00, 0x00, 0x00), // 0: Black
    PaletteEntry::new(0x80, 0x00, 0x00), // 1: Dark Red
    PaletteEntry::new(0x00, 0x80, 0x00), // 2: Dark Green
    PaletteEntry::new(0x80, 0x80, 0x00), // 3: Dark Yellow
    PaletteEntry::new(0x00, 0x00, 0x80), // 4: Dark Blue
    PaletteEntry::new(0x80, 0x00, 0x80), // 5: Dark Magenta
    PaletteEntry::new(0x00, 0x80, 0x80), // 6: Dark Cyan
    PaletteEntry::new(0xC0, 0xC0, 0xC0), // 7: Light Gray
    PaletteEntry::new(0xC0, 0xDC, 0xC0), // 8: Money Green
    PaletteEntry::new(0xA6, 0xCA, 0xF0), // 9: Sky Blue
    // Last 10 colors (Windows standard)
    PaletteEntry::new(0xFF, 0xFB, 0xF0), // 246: Cream
    PaletteEntry::new(0xA0, 0xA0, 0xA4), // 247: Medium Gray
    PaletteEntry::new(0x80, 0x80, 0x80), // 248: Dark Gray
    PaletteEntry::new(0xFF, 0x00, 0x00), // 249: Red
    PaletteEntry::new(0x00, 0xFF, 0x00), // 250: Green
    PaletteEntry::new(0xFF, 0xFF, 0x00), // 251: Yellow
    PaletteEntry::new(0x00, 0x00, 0xFF), // 252: Blue
    PaletteEntry::new(0xFF, 0x00, 0xFF), // 253: Magenta
    PaletteEntry::new(0x00, 0xFF, 0xFF), // 254: Cyan
    PaletteEntry::new(0xFF, 0xFF, 0xFF), // 255: White
];

// ============================================================================
// Initialization
// ============================================================================

/// Initialize palette subsystem
pub fn init() {
    let _guard = PALETTE_LOCK.lock();

    if PALETTE_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[PALETTE] Initializing Palette Manager...");

    // Initialize system palette with default colors
    init_system_palette();

    // Create default stock palette
    create_default_palette();

    PALETTE_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[PALETTE] Palette Manager initialized");
}

/// Initialize system palette with Windows default colors
fn init_system_palette() {
    let mut sys_pal = SYSTEM_PALETTE.lock();

    // Copy first 10 static colors
    for i in 0..10 {
        sys_pal[i] = DEFAULT_ENTRIES[i];
    }

    // Initialize middle colors to grayscale gradient
    for i in 10..246 {
        let gray = ((i - 10) * 255 / 235) as u8;
        sys_pal[i] = PaletteEntry::new(gray, gray, gray);
    }

    // Copy last 10 static colors
    for i in 0..10 {
        sys_pal[246 + i] = DEFAULT_ENTRIES[10 + i];
    }
}

/// Create the default stock palette
fn create_default_palette() {
    let mut palettes = PALETTES.lock();
    let mut default_pal = DEFAULT_PALETTE.lock();

    // Find free slot
    for (i, pal) in palettes.iter_mut().enumerate() {
        if !pal.in_use {
            let handle = GdiHandle(0x8000 | (i as u32)); // Stock object flag

            pal.in_use = true;
            pal.handle = handle;
            pal.num_entries = 20;
            pal.ref_count = 1; // Permanent
            pal.is_stock = true;

            // Copy default entries
            for j in 0..10 {
                pal.entries[j] = DEFAULT_ENTRIES[j];
            }
            for j in 0..10 {
                pal.entries[246 + j] = DEFAULT_ENTRIES[10 + j];
            }

            *default_pal = handle;
            break;
        }
    }
}

// ============================================================================
// Palette Creation and Deletion
// ============================================================================

/// Create a palette from a logical palette structure
///
/// # Arguments
/// * `log_palette` - Logical palette header
/// * `entries` - Palette entries array
///
/// # Returns
/// Handle to created palette or NULL on failure
pub fn create_palette(log_palette: &LogPalette, entries: &[PaletteEntry]) -> HPALETTE {
    if log_palette.version != PALETTE_VERSION {
        return GdiHandle(0);
    }

    let num_entries = (log_palette.num_entries as usize).min(MAX_PALETTE_ENTRIES).min(entries.len());
    if num_entries == 0 {
        return GdiHandle(0);
    }

    let mut palettes = PALETTES.lock();

    // Find free slot
    for (_i, pal) in palettes.iter_mut().enumerate() {
        if !pal.in_use {
            let handle_value = NEXT_PALETTE_HANDLE.fetch_add(1, Ordering::Relaxed);
            let handle = GdiHandle(handle_value);

            pal.in_use = true;
            pal.handle = handle;
            pal.num_entries = num_entries as u16;
            pal.ref_count = 1;
            pal.is_stock = false;

            // Copy entries
            for (j, entry) in entries.iter().take(num_entries).enumerate() {
                pal.entries[j] = *entry;
            }

            PALETTE_COUNT.fetch_add(1, Ordering::Relaxed);
            return handle;
        }
    }

    GdiHandle(0)
}

/// Create a halftone palette for the specified DC
///
/// Creates a 256-color palette optimized for halftone dithering.
///
/// # Arguments
/// * `hdc` - Device context handle
///
/// # Returns
/// Handle to halftone palette or NULL on failure
pub fn create_halftone_palette(_hdc: HDC) -> HPALETTE {
    let mut entries = [PaletteEntry::new(0, 0, 0); 256];

    // Create 6x6x6 color cube (216 colors)
    let mut idx = 0;
    for r in 0..6 {
        for g in 0..6 {
            for b in 0..6 {
                entries[idx] = PaletteEntry::new(
                    (r * 51) as u8,
                    (g * 51) as u8,
                    (b * 51) as u8,
                );
                idx += 1;
            }
        }
    }

    // Add grayscale ramp (40 colors)
    for i in 0..40 {
        let gray = ((i * 255) / 39) as u8;
        entries[216 + i] = PaletteEntry::new(gray, gray, gray);
    }

    let log_pal = LogPalette::new(256);
    create_palette(&log_pal, &entries)
}

/// Delete a palette
///
/// # Arguments
/// * `hpal` - Handle to palette to delete
///
/// # Returns
/// true if deleted successfully
pub fn delete_palette(hpal: HPALETTE) -> bool {
    if hpal.0 == 0 {
        return false;
    }

    let mut palettes = PALETTES.lock();

    for pal in palettes.iter_mut() {
        if pal.in_use && pal.handle == hpal {
            // Can't delete stock objects
            if pal.is_stock {
                return false;
            }

            // Can't delete if selected into DC
            if pal.selected {
                return false;
            }

            pal.in_use = false;
            PALETTE_COUNT.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }

    false
}

// ============================================================================
// Palette Selection and Realization
// ============================================================================

/// Select a palette into a device context
///
/// # Arguments
/// * `hdc` - Device context handle
/// * `hpal` - Palette handle
/// * `force_background` - Force palette to background
///
/// # Returns
/// Previous palette handle or NULL
pub fn select_palette(hdc: HDC, hpal: HPALETTE, _force_background: bool) -> HPALETTE {
    if hdc.0 == 0 || hpal.0 == 0 {
        return GdiHandle(0);
    }

    let mut palettes = PALETTES.lock();

    let mut old_palette = GdiHandle(0);
    let mut new_palette_found = false;

    // Find and deselect old palette
    for pal in palettes.iter_mut() {
        if pal.in_use && pal.selected && pal.selected_dc == hdc {
            old_palette = pal.handle;
            pal.selected = false;
            pal.selected_dc = GdiHandle(0);
            break;
        }
    }

    // Select new palette
    for pal in palettes.iter_mut() {
        if pal.in_use && pal.handle == hpal {
            pal.selected = true;
            pal.selected_dc = hdc;
            new_palette_found = true;
            break;
        }
    }

    if new_palette_found {
        old_palette
    } else {
        GdiHandle(0)
    }
}

/// Realize a palette to the device
///
/// Maps the logical palette to the physical device palette.
///
/// # Arguments
/// * `hdc` - Device context handle
///
/// # Returns
/// Number of entries mapped
pub fn realize_palette(hdc: HDC) -> u32 {
    if hdc.0 == 0 {
        return 0;
    }

    let palettes = PALETTES.lock();

    // Find palette selected into this DC
    for pal in palettes.iter() {
        if pal.in_use && pal.selected && pal.selected_dc == hdc {
            // In a real implementation, this would update the system palette
            // For now, return the number of entries
            return pal.num_entries as u32;
        }
    }

    0
}

// ============================================================================
// Palette Entry Access
// ============================================================================

/// Get palette entries
///
/// # Arguments
/// * `hpal` - Palette handle
/// * `start` - Starting index
/// * `entries` - Output buffer for entries
///
/// # Returns
/// Number of entries copied
pub fn get_palette_entries(hpal: HPALETTE, start: u32, entries: &mut [PaletteEntry]) -> u32 {
    if hpal.0 == 0 || entries.is_empty() {
        return 0;
    }

    let palettes = PALETTES.lock();

    for pal in palettes.iter() {
        if pal.in_use && pal.handle == hpal {
            let start_idx = start as usize;
            if start_idx >= pal.num_entries as usize {
                return 0;
            }

            let available = pal.num_entries as usize - start_idx;
            let count = entries.len().min(available);

            for i in 0..count {
                entries[i] = pal.entries[start_idx + i];
            }

            return count as u32;
        }
    }

    0
}

/// Set palette entries
///
/// # Arguments
/// * `hpal` - Palette handle
/// * `start` - Starting index
/// * `entries` - Entries to set
///
/// # Returns
/// Number of entries set
pub fn set_palette_entries(hpal: HPALETTE, start: u32, entries: &[PaletteEntry]) -> u32 {
    if hpal.0 == 0 || entries.is_empty() {
        return 0;
    }

    let mut palettes = PALETTES.lock();

    for pal in palettes.iter_mut() {
        if pal.in_use && pal.handle == hpal {
            // Can't modify stock palettes
            if pal.is_stock {
                return 0;
            }

            let start_idx = start as usize;
            if start_idx >= pal.num_entries as usize {
                return 0;
            }

            let available = pal.num_entries as usize - start_idx;
            let count = entries.len().min(available);

            for i in 0..count {
                pal.entries[start_idx + i] = entries[i];
            }

            return count as u32;
        }
    }

    0
}

/// Resize a palette
///
/// # Arguments
/// * `hpal` - Palette handle
/// * `num_entries` - New number of entries
///
/// # Returns
/// true if successful
pub fn resize_palette(hpal: HPALETTE, num_entries: u32) -> bool {
    if hpal.0 == 0 || num_entries > MAX_PALETTE_ENTRIES as u32 {
        return false;
    }

    let mut palettes = PALETTES.lock();

    for pal in palettes.iter_mut() {
        if pal.in_use && pal.handle == hpal {
            // Can't resize stock palettes
            if pal.is_stock {
                return false;
            }

            pal.num_entries = num_entries as u16;
            return true;
        }
    }

    false
}

// ============================================================================
// System Palette Access
// ============================================================================

/// Get system palette entries
///
/// # Arguments
/// * `hdc` - Device context handle
/// * `start` - Starting index
/// * `entries` - Output buffer
///
/// # Returns
/// Number of entries copied
pub fn get_system_palette_entries(_hdc: HDC, start: u32, entries: &mut [PaletteEntry]) -> u32 {
    if entries.is_empty() {
        return 0;
    }

    let sys_pal = SYSTEM_PALETTE.lock();

    let start_idx = start as usize;
    if start_idx >= SYSTEM_PALETTE_SIZE {
        return 0;
    }

    let available = SYSTEM_PALETTE_SIZE - start_idx;
    let count = entries.len().min(available);

    for i in 0..count {
        entries[i] = sys_pal[start_idx + i];
    }

    count as u32
}

/// Get system palette use mode
///
/// # Arguments
/// * `hdc` - Device context handle
///
/// # Returns
/// SYSPAL_STATIC (1), SYSPAL_NOSTATIC (2), or SYSPAL_ERROR (0)
pub fn get_system_palette_use(_hdc: HDC) -> u32 {
    // Return SYSPAL_STATIC - system colors always present
    1
}

/// Set system palette use mode
///
/// # Arguments
/// * `hdc` - Device context handle
/// * `use_mode` - SYSPAL_STATIC or SYSPAL_NOSTATIC
///
/// # Returns
/// Previous mode or SYSPAL_ERROR
pub fn set_system_palette_use(_hdc: HDC, _use_mode: u32) -> u32 {
    // Always return static mode
    1
}

// ============================================================================
// Color Matching
// ============================================================================

/// Get the nearest palette index for a color
///
/// # Arguments
/// * `hpal` - Palette handle
/// * `color` - Color to match
///
/// # Returns
/// Nearest palette index or CLR_INVALID on error
pub fn get_nearest_palette_index(hpal: HPALETTE, color: ColorRef) -> u32 {
    if hpal.0 == 0 {
        return 0xFFFFFFFF; // CLR_INVALID
    }

    let palettes = PALETTES.lock();

    for pal in palettes.iter() {
        if pal.in_use && pal.handle == hpal {
            let target_r = color.red() as i32;
            let target_g = color.green() as i32;
            let target_b = color.blue() as i32;

            let mut best_index = 0u32;
            let mut best_distance = i32::MAX;

            for i in 0..pal.num_entries as usize {
                let entry = &pal.entries[i];
                let dr = target_r - entry.red as i32;
                let dg = target_g - entry.green as i32;
                let db = target_b - entry.blue as i32;

                // Use squared distance (no sqrt needed for comparison)
                let distance = dr * dr + dg * dg + db * db;

                if distance < best_distance {
                    best_distance = distance;
                    best_index = i as u32;

                    // Exact match
                    if distance == 0 {
                        break;
                    }
                }
            }

            return best_index;
        }
    }

    0xFFFFFFFF // CLR_INVALID
}

/// Get the nearest color in the system palette
///
/// # Arguments
/// * `hdc` - Device context handle
/// * `color` - Color to match
///
/// # Returns
/// Nearest color or original color
pub fn get_nearest_color(_hdc: HDC, color: ColorRef) -> ColorRef {
    let sys_pal = SYSTEM_PALETTE.lock();

    let target_r = color.red() as i32;
    let target_g = color.green() as i32;
    let target_b = color.blue() as i32;

    let mut best_color = color;
    let mut best_distance = i32::MAX;

    for entry in sys_pal.iter() {
        let dr = target_r - entry.red as i32;
        let dg = target_g - entry.green as i32;
        let db = target_b - entry.blue as i32;

        let distance = dr * dr + dg * dg + db * db;

        if distance < best_distance {
            best_distance = distance;
            best_color = entry.to_colorref();

            if distance == 0 {
                break;
            }
        }
    }

    best_color
}

// ============================================================================
// Animation Support
// ============================================================================

/// Animate palette entries
///
/// Changes palette entries without requiring realization.
/// Used for color cycling effects.
///
/// # Arguments
/// * `hpal` - Palette handle
/// * `start` - Starting index
/// * `entries` - New entries
///
/// # Returns
/// true if successful
pub fn animate_palette(hpal: HPALETTE, start: u32, entries: &[PaletteEntry]) -> bool {
    if hpal.0 == 0 || entries.is_empty() {
        return false;
    }

    let mut palettes = PALETTES.lock();

    for pal in palettes.iter_mut() {
        if pal.in_use && pal.handle == hpal {
            let start_idx = start as usize;
            if start_idx >= pal.num_entries as usize {
                return false;
            }

            let available = pal.num_entries as usize - start_idx;
            let count = entries.len().min(available);

            // Only animate entries marked as PC_RESERVED
            for i in 0..count {
                if (pal.entries[start_idx + i].flags & PC_RESERVED) != 0 {
                    pal.entries[start_idx + i] = entries[i];
                    // Preserve the reserved flag
                    pal.entries[start_idx + i].flags |= PC_RESERVED;
                }
            }

            return true;
        }
    }

    false
}

// ============================================================================
// Stock Palette Access
// ============================================================================

/// Get the default stock palette
pub fn get_stock_palette() -> HPALETTE {
    *DEFAULT_PALETTE.lock()
}

// ============================================================================
// Statistics
// ============================================================================

/// Get number of allocated palettes
pub fn get_palette_count() -> u32 {
    PALETTE_COUNT.load(Ordering::Relaxed)
}
