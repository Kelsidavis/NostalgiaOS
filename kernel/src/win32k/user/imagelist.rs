//! ImageList Implementation
//!
//! Windows ImageList for storing and managing collections of images.
//! Based on Windows Server 2003 commctrl.h.
//!
//! # Features
//!
//! - Store multiple same-size images
//! - Mask support for transparency
//! - Overlay images
//! - Drag image support
//! - Background color
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - ImageList_* functions, ILC_* flags

use crate::ke::spinlock::SpinLock;
use super::super::{Point, Rect, ColorRef};

// ============================================================================
// ImageList Creation Flags (ILC_*)
// ============================================================================

/// Use a mask
pub const ILC_MASK: u32 = 0x00000001;

/// Device-dependent color (default)
pub const ILC_COLOR: u32 = 0x00000000;

/// Use DDB format
pub const ILC_COLORDDB: u32 = 0x000000FE;

/// 4-bit color
pub const ILC_COLOR4: u32 = 0x00000004;

/// 8-bit color
pub const ILC_COLOR8: u32 = 0x00000008;

/// 16-bit color
pub const ILC_COLOR16: u32 = 0x00000010;

/// 24-bit color
pub const ILC_COLOR24: u32 = 0x00000018;

/// 32-bit color
pub const ILC_COLOR32: u32 = 0x00000020;

/// Mirror images
pub const ILC_MIRROR: u32 = 0x00002000;

/// Mirror each item
pub const ILC_PERITEMMIRROR: u32 = 0x00008000;

// ============================================================================
// ImageList Draw Flags (ILD_*)
// ============================================================================

/// Normal draw
pub const ILD_NORMAL: u32 = 0x00000000;

/// Transparent background
pub const ILD_TRANSPARENT: u32 = 0x00000001;

/// Draw mask only
pub const ILD_MASK: u32 = 0x00000010;

/// Draw image only (no mask)
pub const ILD_IMAGE: u32 = 0x00000020;

/// Use ROP
pub const ILD_ROP: u32 = 0x00000040;

/// 25% blend
pub const ILD_BLEND25: u32 = 0x00000002;

/// 50% blend
pub const ILD_BLEND50: u32 = 0x00000004;

/// Overlay mask
pub const ILD_OVERLAYMASK: u32 = 0x00000F00;

/// Preserve alpha channel
pub const ILD_PRESERVEALPHA: u32 = 0x00001000;

/// Scale image
pub const ILD_SCALE: u32 = 0x00002000;

/// DPI scaling
pub const ILD_DPISCALE: u32 = 0x00004000;

/// Selected (blend 50%)
pub const ILD_SELECTED: u32 = ILD_BLEND50;

/// Focus (blend 25%)
pub const ILD_FOCUS: u32 = ILD_BLEND25;

/// Blend (50%)
pub const ILD_BLEND: u32 = ILD_BLEND50;

// ============================================================================
// Copy Flags (ILCF_*)
// ============================================================================

/// Move image
pub const ILCF_MOVE: u32 = 0x00000000;

/// Swap images
pub const ILCF_SWAP: u32 = 0x00000001;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of image lists
pub const MAX_IMAGE_LISTS: usize = 64;

/// Maximum images per list
pub const MAX_IMAGES_PER_LIST: usize = 256;

/// Maximum overlay images
pub const MAX_OVERLAYS: usize = 15;

/// Handle type for image lists
pub type HIMAGELIST = usize;

/// Null image list handle
pub const NULL_HIMAGELIST: HIMAGELIST = 0;

// ============================================================================
// Image Info Structure
// ============================================================================

/// Information about a single image
#[derive(Clone, Copy)]
pub struct ImageInfo {
    /// Image is in use
    pub in_use: bool,
    /// Bitmap handle (or index for internal storage)
    pub hbm_image: usize,
    /// Mask bitmap handle
    pub hbm_mask: usize,
    /// Unused space on left of image
    pub unused1: Rect,
    /// Unused space on right of image
    pub unused2: Rect,
}

impl ImageInfo {
    /// Create empty image info
    pub const fn new() -> Self {
        Self {
            in_use: false,
            hbm_image: 0,
            hbm_mask: 0,
            unused1: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            unused2: Rect { left: 0, top: 0, right: 0, bottom: 0 },
        }
    }
}

// ============================================================================
// Image Data (simplified pixel storage)
// ============================================================================

/// Simplified image data storage
#[derive(Clone)]
pub struct ImageData {
    /// Width in pixels
    pub width: i32,
    /// Height in pixels
    pub height: i32,
    /// Pixel data (RGBA)
    pub pixels: [u32; 64 * 64], // Support up to 64x64 images
    /// Mask data
    pub mask: [u8; 64 * 64 / 8],
    /// Has mask
    pub has_mask: bool,
}

impl ImageData {
    /// Create empty image data
    pub const fn new() -> Self {
        Self {
            width: 0,
            height: 0,
            pixels: [0u32; 64 * 64],
            mask: [0u8; 64 * 64 / 8],
            has_mask: false,
        }
    }

    /// Get pixel at position
    pub fn get_pixel(&self, x: i32, y: i32) -> u32 {
        if x >= 0 && x < self.width && y >= 0 && y < self.height {
            let idx = (y * self.width + x) as usize;
            if idx < self.pixels.len() {
                return self.pixels[idx];
            }
        }
        0
    }

    /// Set pixel at position
    pub fn set_pixel(&mut self, x: i32, y: i32, color: u32) {
        if x >= 0 && x < self.width && y >= 0 && y < self.height {
            let idx = (y * self.width + x) as usize;
            if idx < self.pixels.len() {
                self.pixels[idx] = color;
            }
        }
    }

    /// Check if pixel is masked (transparent)
    pub fn is_masked(&self, x: i32, y: i32) -> bool {
        if !self.has_mask {
            return false;
        }
        if x >= 0 && x < self.width && y >= 0 && y < self.height {
            let bit_idx = (y * self.width + x) as usize;
            let byte_idx = bit_idx / 8;
            let bit_offset = bit_idx % 8;
            if byte_idx < self.mask.len() {
                return (self.mask[byte_idx] & (1 << bit_offset)) != 0;
            }
        }
        false
    }
}

// ============================================================================
// ImageList Structure
// ============================================================================

/// Image list state
#[derive(Clone)]
pub struct ImageList {
    /// Is this slot in use
    pub in_use: bool,
    /// Image width
    pub cx: i32,
    /// Image height
    pub cy: i32,
    /// Creation flags
    pub flags: u32,
    /// Current image count
    pub count: usize,
    /// Growth amount
    pub grow: usize,
    /// Background color
    pub bk_color: ColorRef,
    /// Image data
    pub images: [ImageData; MAX_IMAGES_PER_LIST],
    /// Overlay mappings (overlay index -> image index)
    pub overlays: [i32; MAX_OVERLAYS],
    /// Drag state
    pub drag_index: i32,
    pub drag_hotspot: Point,
    pub drag_cursor: Point,
    pub dragging: bool,
}

impl ImageList {
    /// Create a new empty image list
    pub const fn new() -> Self {
        Self {
            in_use: false,
            cx: 0,
            cy: 0,
            flags: 0,
            count: 0,
            grow: 4,
            bk_color: ColorRef(0xFFFFFFFF), // CLR_NONE equivalent
            images: [const { ImageData::new() }; MAX_IMAGES_PER_LIST],
            overlays: [-1i32; MAX_OVERLAYS],
            drag_index: -1,
            drag_hotspot: Point { x: 0, y: 0 },
            drag_cursor: Point { x: 0, y: 0 },
            dragging: false,
        }
    }

    /// Reset image list
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Initialize image list
    pub fn init(&mut self, cx: i32, cy: i32, flags: u32, initial: usize, grow: usize) {
        self.cx = cx;
        self.cy = cy;
        self.flags = flags;
        self.count = 0;
        self.grow = if grow > 0 { grow } else { 4 };

        // Pre-initialize images with size
        for img in self.images.iter_mut() {
            img.width = cx;
            img.height = cy;
            img.has_mask = (flags & ILC_MASK) != 0;
        }

        let _ = initial; // Used for pre-allocation in real implementation
    }

    /// Add an image
    pub fn add(&mut self) -> i32 {
        if self.count >= MAX_IMAGES_PER_LIST {
            return -1;
        }

        let index = self.count;
        self.images[index].width = self.cx;
        self.images[index].height = self.cy;
        self.images[index].has_mask = (self.flags & ILC_MASK) != 0;
        self.count += 1;

        index as i32
    }

    /// Remove an image
    pub fn remove(&mut self, index: i32) -> bool {
        if index < 0 {
            // Remove all
            for img in self.images.iter_mut() {
                *img = ImageData::new();
            }
            self.count = 0;
            return true;
        }

        let idx = index as usize;
        if idx >= self.count {
            return false;
        }

        // Shift images down
        for i in idx..self.count - 1 {
            self.images[i] = self.images[i + 1].clone();
        }
        self.images[self.count - 1] = ImageData::new();
        self.count -= 1;

        true
    }

    /// Replace an image
    pub fn replace(&mut self, index: i32) -> bool {
        let idx = index as usize;
        if idx >= self.count {
            return false;
        }

        // In a real implementation, we'd copy bitmap data here
        self.images[idx].width = self.cx;
        self.images[idx].height = self.cy;
        true
    }

    /// Set background color
    pub fn set_bk_color(&mut self, color: ColorRef) -> ColorRef {
        let old = self.bk_color;
        self.bk_color = color;
        old
    }

    /// Get background color
    pub fn get_bk_color(&self) -> ColorRef {
        self.bk_color
    }

    /// Set overlay image
    pub fn set_overlay_image(&mut self, image: i32, overlay: i32) -> bool {
        if overlay < 1 || overlay > MAX_OVERLAYS as i32 {
            return false;
        }
        if image < 0 || image as usize >= self.count {
            return false;
        }

        self.overlays[(overlay - 1) as usize] = image;
        true
    }

    /// Get image count
    pub fn get_image_count(&self) -> usize {
        self.count
    }

    /// Set image count
    pub fn set_image_count(&mut self, count: usize) -> bool {
        if count > MAX_IMAGES_PER_LIST {
            return false;
        }

        if count > self.count {
            // Add empty images
            for i in self.count..count {
                self.images[i].width = self.cx;
                self.images[i].height = self.cy;
                self.images[i].has_mask = (self.flags & ILC_MASK) != 0;
            }
        }

        self.count = count;
        true
    }

    /// Get icon size
    pub fn get_icon_size(&self) -> (i32, i32) {
        (self.cx, self.cy)
    }

    /// Set icon size
    pub fn set_icon_size(&mut self, cx: i32, cy: i32) -> bool {
        if cx <= 0 || cy <= 0 || cx > 64 || cy > 64 {
            return false;
        }

        self.cx = cx;
        self.cy = cy;

        // Resize all images
        for img in self.images[..self.count].iter_mut() {
            img.width = cx;
            img.height = cy;
        }

        true
    }

    /// Copy/swap images
    pub fn copy(&mut self, dst: i32, src: i32, flags: u32) -> bool {
        let dst_idx = dst as usize;
        let src_idx = src as usize;

        if dst_idx >= self.count || src_idx >= self.count {
            return false;
        }

        if flags & ILCF_SWAP != 0 {
            // Swap
            let temp = self.images[dst_idx].clone();
            self.images[dst_idx] = self.images[src_idx].clone();
            self.images[src_idx] = temp;
        } else {
            // Copy
            self.images[dst_idx] = self.images[src_idx].clone();
        }

        true
    }

    /// Begin drag operation
    pub fn begin_drag(&mut self, index: i32, hotspot_x: i32, hotspot_y: i32) -> bool {
        if index < 0 || index as usize >= self.count {
            return false;
        }

        self.drag_index = index;
        self.drag_hotspot.x = hotspot_x;
        self.drag_hotspot.y = hotspot_y;
        self.dragging = true;
        true
    }

    /// End drag operation
    pub fn end_drag(&mut self) {
        self.dragging = false;
        self.drag_index = -1;
    }

    /// Move drag image
    pub fn drag_move(&mut self, x: i32, y: i32) -> bool {
        if !self.dragging {
            return false;
        }

        self.drag_cursor.x = x;
        self.drag_cursor.y = y;
        true
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global image list storage
static IMAGE_LISTS: SpinLock<[ImageList; MAX_IMAGE_LISTS]> =
    SpinLock::new([const { ImageList::new() }; MAX_IMAGE_LISTS]);

/// Current drag image list
static DRAG_IMAGELIST: SpinLock<Option<usize>> = SpinLock::new(None);

// ============================================================================
// Public API
// ============================================================================

/// Initialize ImageList subsystem
pub fn init() {
    crate::serial_println!("[USER] ImageList initialized");
}

/// Create an image list
pub fn create(cx: i32, cy: i32, flags: u32, initial: usize, grow: usize) -> HIMAGELIST {
    let mut lists = IMAGE_LISTS.lock();

    for (i, list) in lists.iter_mut().enumerate() {
        if !list.in_use {
            list.reset();
            list.in_use = true;
            list.init(cx, cy, flags, initial, grow);
            return i + 1; // Handle is index + 1 (0 is null)
        }
    }

    NULL_HIMAGELIST
}

/// Destroy an image list
pub fn destroy(himl: HIMAGELIST) -> bool {
    if himl == NULL_HIMAGELIST {
        return false;
    }

    let mut lists = IMAGE_LISTS.lock();
    let index = himl - 1;

    if index >= MAX_IMAGE_LISTS {
        return false;
    }

    if lists[index].in_use {
        lists[index].reset();
        true
    } else {
        false
    }
}

/// Get image count
pub fn get_image_count(himl: HIMAGELIST) -> i32 {
    if himl == NULL_HIMAGELIST {
        return 0;
    }

    let lists = IMAGE_LISTS.lock();
    let index = himl - 1;

    if index >= MAX_IMAGE_LISTS || !lists[index].in_use {
        return 0;
    }

    lists[index].count as i32
}

/// Set image count
pub fn set_image_count(himl: HIMAGELIST, count: usize) -> bool {
    if himl == NULL_HIMAGELIST {
        return false;
    }

    let mut lists = IMAGE_LISTS.lock();
    let index = himl - 1;

    if index >= MAX_IMAGE_LISTS || !lists[index].in_use {
        return false;
    }

    lists[index].set_image_count(count)
}

/// Add an image (returns index or -1)
pub fn add(himl: HIMAGELIST) -> i32 {
    if himl == NULL_HIMAGELIST {
        return -1;
    }

    let mut lists = IMAGE_LISTS.lock();
    let index = himl - 1;

    if index >= MAX_IMAGE_LISTS || !lists[index].in_use {
        return -1;
    }

    lists[index].add()
}

/// Remove an image (or all if index is -1)
pub fn remove(himl: HIMAGELIST, index: i32) -> bool {
    if himl == NULL_HIMAGELIST {
        return false;
    }

    let mut lists = IMAGE_LISTS.lock();
    let list_idx = himl - 1;

    if list_idx >= MAX_IMAGE_LISTS || !lists[list_idx].in_use {
        return false;
    }

    lists[list_idx].remove(index)
}

/// Replace an image
pub fn replace(himl: HIMAGELIST, index: i32) -> bool {
    if himl == NULL_HIMAGELIST {
        return false;
    }

    let mut lists = IMAGE_LISTS.lock();
    let list_idx = himl - 1;

    if list_idx >= MAX_IMAGE_LISTS || !lists[list_idx].in_use {
        return false;
    }

    lists[list_idx].replace(index)
}

/// Set background color
pub fn set_bk_color(himl: HIMAGELIST, color: ColorRef) -> ColorRef {
    if himl == NULL_HIMAGELIST {
        return ColorRef(0xFFFFFFFF);
    }

    let mut lists = IMAGE_LISTS.lock();
    let index = himl - 1;

    if index >= MAX_IMAGE_LISTS || !lists[index].in_use {
        return ColorRef(0xFFFFFFFF);
    }

    lists[index].set_bk_color(color)
}

/// Get background color
pub fn get_bk_color(himl: HIMAGELIST) -> ColorRef {
    if himl == NULL_HIMAGELIST {
        return ColorRef(0xFFFFFFFF);
    }

    let lists = IMAGE_LISTS.lock();
    let index = himl - 1;

    if index >= MAX_IMAGE_LISTS || !lists[index].in_use {
        return ColorRef(0xFFFFFFFF);
    }

    lists[index].bk_color
}

/// Set overlay image
pub fn set_overlay_image(himl: HIMAGELIST, image: i32, overlay: i32) -> bool {
    if himl == NULL_HIMAGELIST {
        return false;
    }

    let mut lists = IMAGE_LISTS.lock();
    let index = himl - 1;

    if index >= MAX_IMAGE_LISTS || !lists[index].in_use {
        return false;
    }

    lists[index].set_overlay_image(image, overlay)
}

/// Get icon size
pub fn get_icon_size(himl: HIMAGELIST) -> Option<(i32, i32)> {
    if himl == NULL_HIMAGELIST {
        return None;
    }

    let lists = IMAGE_LISTS.lock();
    let index = himl - 1;

    if index >= MAX_IMAGE_LISTS || !lists[index].in_use {
        return None;
    }

    Some(lists[index].get_icon_size())
}

/// Set icon size
pub fn set_icon_size(himl: HIMAGELIST, cx: i32, cy: i32) -> bool {
    if himl == NULL_HIMAGELIST {
        return false;
    }

    let mut lists = IMAGE_LISTS.lock();
    let index = himl - 1;

    if index >= MAX_IMAGE_LISTS || !lists[index].in_use {
        return false;
    }

    lists[index].set_icon_size(cx, cy)
}

/// Copy images
pub fn copy(himl_dst: HIMAGELIST, dst: i32, himl_src: HIMAGELIST, src: i32, flags: u32) -> bool {
    if himl_dst == NULL_HIMAGELIST || himl_src == NULL_HIMAGELIST {
        return false;
    }

    // Only support same-list copy for now
    if himl_dst != himl_src {
        return false;
    }

    let mut lists = IMAGE_LISTS.lock();
    let index = himl_dst - 1;

    if index >= MAX_IMAGE_LISTS || !lists[index].in_use {
        return false;
    }

    lists[index].copy(dst, src, flags)
}

/// Begin drag operation
pub fn begin_drag(himl: HIMAGELIST, index: i32, hotspot_x: i32, hotspot_y: i32) -> bool {
    if himl == NULL_HIMAGELIST {
        return false;
    }

    let mut lists = IMAGE_LISTS.lock();
    let list_idx = himl - 1;

    if list_idx >= MAX_IMAGE_LISTS || !lists[list_idx].in_use {
        return false;
    }

    if lists[list_idx].begin_drag(index, hotspot_x, hotspot_y) {
        *DRAG_IMAGELIST.lock() = Some(list_idx);
        true
    } else {
        false
    }
}

/// End drag operation
pub fn end_drag() {
    let drag_idx = DRAG_IMAGELIST.lock().take();

    if let Some(idx) = drag_idx {
        let mut lists = IMAGE_LISTS.lock();
        if idx < MAX_IMAGE_LISTS && lists[idx].in_use {
            lists[idx].end_drag();
        }
    }
}

/// Move drag image
pub fn drag_move(x: i32, y: i32) -> bool {
    let drag_idx = *DRAG_IMAGELIST.lock();

    if let Some(idx) = drag_idx {
        let mut lists = IMAGE_LISTS.lock();
        if idx < MAX_IMAGE_LISTS && lists[idx].in_use {
            return lists[idx].drag_move(x, y);
        }
    }

    false
}

/// Duplicate an image list
pub fn duplicate(himl: HIMAGELIST) -> HIMAGELIST {
    if himl == NULL_HIMAGELIST {
        return NULL_HIMAGELIST;
    }

    let lists = IMAGE_LISTS.lock();
    let src_idx = himl - 1;

    if src_idx >= MAX_IMAGE_LISTS || !lists[src_idx].in_use {
        return NULL_HIMAGELIST;
    }

    let cx = lists[src_idx].cx;
    let cy = lists[src_idx].cy;
    let flags = lists[src_idx].flags;
    let count = lists[src_idx].count;

    drop(lists);

    // Create new list
    let new_himl = create(cx, cy, flags, count, 4);
    if new_himl == NULL_HIMAGELIST {
        return NULL_HIMAGELIST;
    }

    // Copy contents
    let mut lists = IMAGE_LISTS.lock();
    let src_idx = himl - 1;
    let dst_idx = new_himl - 1;

    lists[dst_idx].count = count;
    for i in 0..count {
        lists[dst_idx].images[i] = lists[src_idx].images[i].clone();
    }
    lists[dst_idx].overlays = lists[src_idx].overlays;
    lists[dst_idx].bk_color = lists[src_idx].bk_color;

    new_himl
}

/// Get statistics
pub fn get_stats() -> ImageListStats {
    let lists = IMAGE_LISTS.lock();

    let mut active_count = 0;
    let mut total_images = 0;

    for list in lists.iter() {
        if list.in_use {
            active_count += 1;
            total_images += list.count;
        }
    }

    ImageListStats {
        max_lists: MAX_IMAGE_LISTS,
        active_lists: active_count,
        total_images,
    }
}

/// ImageList statistics
#[derive(Debug, Clone, Copy)]
pub struct ImageListStats {
    pub max_lists: usize,
    pub active_lists: usize,
    pub total_images: usize,
}
