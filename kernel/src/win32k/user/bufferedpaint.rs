//! Buffered Paint Implementation
//!
//! Windows buffered painting for flicker-free drawing.
//! Based on Windows Vista+ UxTheme buffered paint API.
//!
//! # Features
//!
//! - Double-buffered painting
//! - Alpha channel support
//! - Animation support
//! - Automatic buffer management
//!
//! # References
//!
//! - `public/sdk/inc/uxtheme.h` - BufferedPaint functions

use crate::ke::spinlock::SpinLock;
use super::super::{UserHandle, HWND, Rect, GdiHandle};

// ============================================================================
// Buffered Paint Flags (BPBF_*)
// ============================================================================

/// Compatible bitmap
pub const BPBF_COMPATIBLEBITMAP: u32 = 0;

/// DIB section
pub const BPBF_DIB: u32 = 1;

/// Top-down DIB
pub const BPBF_TOPDOWNDIB: u32 = 2;

/// Top-down monochrome DIB
pub const BPBF_TOPDOWNMONODIB: u32 = 3;

// ============================================================================
// Buffered Paint Parameters Flags (BPPF_*)
// ============================================================================

/// Erase background
pub const BPPF_ERASE: u32 = 0x0001;

/// No clip
pub const BPPF_NOCLIP: u32 = 0x0002;

/// Non-client area
pub const BPPF_NONCLIENT: u32 = 0x0004;

// ============================================================================
// Animation Styles (BPAS_*)
// ============================================================================

/// No animation
pub const BPAS_NONE: u32 = 0;

/// Linear animation
pub const BPAS_LINEAR: u32 = 1;

/// Cubic animation
pub const BPAS_CUBIC: u32 = 2;

/// Sine animation
pub const BPAS_SINE: u32 = 3;

// ============================================================================
// Constants
// ============================================================================

/// Maximum buffered paint handles
pub const MAX_BUFFERED_PAINTS: usize = 64;

/// Maximum animation buffers
pub const MAX_ANIMATION_BUFFERS: usize = 32;

/// Default animation duration (ms)
pub const DEFAULT_ANIMATION_DURATION: u32 = 250;

// ============================================================================
// Buffered Paint Parameters
// ============================================================================

/// Buffered paint parameters
#[derive(Clone, Copy)]
pub struct BufferedPaintParams {
    /// Size of structure
    pub cb_size: u32,
    /// Flags
    pub flags: u32,
    /// Exclude rectangle
    pub rc_exclude: Rect,
    /// Alpha
    pub alpha: u8,
}

impl BufferedPaintParams {
    /// Create default parameters
    pub const fn new() -> Self {
        Self {
            cb_size: 0,
            flags: 0,
            rc_exclude: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            alpha: 255,
        }
    }
}

// ============================================================================
// Animation Parameters
// ============================================================================

/// Animation parameters
#[derive(Clone, Copy)]
pub struct AnimationParams {
    /// Size of structure
    pub cb_size: u32,
    /// Animation style
    pub style: u32,
    /// Duration in milliseconds
    pub duration: u32,
}

impl AnimationParams {
    /// Create default parameters
    pub const fn new() -> Self {
        Self {
            cb_size: 0,
            style: BPAS_LINEAR,
            duration: DEFAULT_ANIMATION_DURATION,
        }
    }
}

// ============================================================================
// Buffered Paint State
// ============================================================================

/// Buffered paint state
#[derive(Clone)]
pub struct BufferedPaint {
    /// Is this slot in use
    pub in_use: bool,
    /// Target window
    pub hwnd: HWND,
    /// Target DC
    pub hdc_target: GdiHandle,
    /// Buffer DC
    pub hdc_buffer: GdiHandle,
    /// Buffer bitmap
    pub hbm_buffer: GdiHandle,
    /// Target rectangle
    pub rc_target: Rect,
    /// Buffer format
    pub format: u32,
    /// Parameters
    pub params: BufferedPaintParams,
    /// Has alpha
    pub has_alpha: bool,
    /// Buffer bits (for DIB)
    pub bits: usize,
    /// Row stride
    pub row_stride: i32,
}

impl BufferedPaint {
    /// Create empty buffered paint
    pub const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle::NULL,
            hdc_target: GdiHandle::NULL,
            hdc_buffer: GdiHandle::NULL,
            hbm_buffer: GdiHandle::NULL,
            rc_target: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            format: BPBF_COMPATIBLEBITMAP,
            params: BufferedPaintParams::new(),
            has_alpha: false,
            bits: 0,
            row_stride: 0,
        }
    }

    /// Reset state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Get buffer width
    pub fn width(&self) -> i32 {
        self.rc_target.right - self.rc_target.left
    }

    /// Get buffer height
    pub fn height(&self) -> i32 {
        self.rc_target.bottom - self.rc_target.top
    }

    /// Clear buffer with color
    pub fn clear(&mut self, color: u32) {
        // In a real implementation, this would fill the buffer
        let _ = color;
    }

    /// Make opaque (set alpha to 255)
    pub fn make_opaque(&mut self, rect: Option<&Rect>) {
        self.has_alpha = false;
        let _ = rect;
    }

    /// Set alpha
    pub fn set_alpha(&mut self, alpha: u8, rect: Option<&Rect>) {
        self.params.alpha = alpha;
        let _ = rect;
    }
}

// ============================================================================
// Animation Buffer
// ============================================================================

/// Animation buffer for transitions
#[derive(Clone)]
pub struct AnimationBuffer {
    /// Is this slot in use
    pub in_use: bool,
    /// Target window
    pub hwnd: HWND,
    /// Target rectangle
    pub rc_target: Rect,
    /// From state buffer
    pub hdc_from: GdiHandle,
    /// To state buffer
    pub hdc_to: GdiHandle,
    /// Animation parameters
    pub params: AnimationParams,
    /// Start time
    pub start_time: u64,
    /// Is animating
    pub animating: bool,
    /// Current progress (0.0 - 1.0 as fixed point)
    pub progress: u32, // 0-1000 representing 0.0-1.0
}

impl AnimationBuffer {
    /// Create empty animation buffer
    pub const fn new() -> Self {
        Self {
            in_use: false,
            hwnd: UserHandle::NULL,
            rc_target: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            hdc_from: GdiHandle::NULL,
            hdc_to: GdiHandle::NULL,
            params: AnimationParams::new(),
            start_time: 0,
            animating: false,
            progress: 0,
        }
    }

    /// Reset state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Update animation progress
    pub fn update(&mut self, current_time: u64) -> bool {
        if !self.animating {
            return false;
        }

        let elapsed = current_time.saturating_sub(self.start_time);
        let duration = self.params.duration as u64;

        if elapsed >= duration {
            self.progress = 1000;
            self.animating = false;
            return false;
        }

        // Calculate progress based on style
        let linear_progress = ((elapsed * 1000) / duration) as u32;

        self.progress = match self.params.style {
            BPAS_LINEAR => linear_progress,
            BPAS_CUBIC => {
                // Cubic ease-in-out using integer math
                // t is 0-1000, so we work in fixed point
                let t = linear_progress as i64;
                if t < 500 {
                    // 4 * t^3 / 1000^2 (scaled properly)
                    ((4 * t * t * t) / 1_000_000) as u32
                } else {
                    // 1 - ((2-2t)^3)/2 in fixed point
                    let s = 2000 - 2 * t;
                    (1000 - (s * s * s) / 2_000_000) as u32
                }
            }
            BPAS_SINE => {
                // Sine ease-in-out (parabolic approximation)
                let t = linear_progress as i32;
                // Simple approximation: t * (2000 - t) / 1000
                ((t * (2000 - t)) / 1000) as u32
            }
            _ => linear_progress,
        };

        true
    }

    /// Get alpha blend value (0-255)
    pub fn get_alpha(&self) -> u8 {
        ((self.progress * 255) / 1000) as u8
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global buffered paint storage
static BUFFERED_PAINTS: SpinLock<[BufferedPaint; MAX_BUFFERED_PAINTS]> =
    SpinLock::new([const { BufferedPaint::new() }; MAX_BUFFERED_PAINTS]);

/// Global animation buffer storage
static ANIMATION_BUFFERS: SpinLock<[AnimationBuffer; MAX_ANIMATION_BUFFERS]> =
    SpinLock::new([const { AnimationBuffer::new() }; MAX_ANIMATION_BUFFERS]);

/// Buffered paint initialized
static INITIALIZED: SpinLock<bool> = SpinLock::new(false);

/// Handle type
pub type HPAINTBUFFER = usize;
pub type HANIMATIONBUFFER = usize;

/// Null handle
pub const NULL_HPAINTBUFFER: HPAINTBUFFER = 0;
pub const NULL_HANIMATIONBUFFER: HANIMATIONBUFFER = 0;

// ============================================================================
// Public API
// ============================================================================

/// Initialize BufferedPaint subsystem
pub fn init() {
    crate::serial_println!("[USER] BufferedPaint initialized");
}

/// Initialize buffered paint for thread
pub fn buffered_paint_init() -> bool {
    let mut init = INITIALIZED.lock();
    *init = true;
    true
}

/// Uninitialize buffered paint for thread
pub fn buffered_paint_uninit() -> bool {
    let mut init = INITIALIZED.lock();
    *init = false;
    true
}

/// Begin buffered paint
pub fn begin_buffered_paint(
    hdc_target: GdiHandle,
    rc_target: &Rect,
    format: u32,
    params: Option<&BufferedPaintParams>,
) -> (HPAINTBUFFER, GdiHandle) {
    let mut paints = BUFFERED_PAINTS.lock();

    for (i, paint) in paints.iter_mut().enumerate() {
        if !paint.in_use {
            paint.reset();
            paint.in_use = true;
            paint.hdc_target = hdc_target;
            paint.rc_target = *rc_target;
            paint.format = format;

            if let Some(p) = params {
                paint.params = *p;
            }

            paint.has_alpha = format == BPBF_DIB || format == BPBF_TOPDOWNDIB;

            // In a real implementation, create the buffer DC and bitmap here
            // For now, return the target DC as the buffer DC
            paint.hdc_buffer = hdc_target;

            return (i + 1, paint.hdc_buffer);
        }
    }

    (NULL_HPAINTBUFFER, GdiHandle::NULL)
}

/// End buffered paint
pub fn end_buffered_paint(hpb: HPAINTBUFFER, update_target: bool) -> bool {
    if hpb == NULL_HPAINTBUFFER {
        return false;
    }

    let mut paints = BUFFERED_PAINTS.lock();
    let idx = hpb - 1;

    if idx >= MAX_BUFFERED_PAINTS {
        return false;
    }

    if !paints[idx].in_use {
        return false;
    }

    if update_target {
        // In a real implementation, BitBlt from buffer to target
    }

    paints[idx].reset();
    true
}

/// Get buffered paint target rect
pub fn get_buffered_paint_target_rect(hpb: HPAINTBUFFER) -> Option<Rect> {
    if hpb == NULL_HPAINTBUFFER {
        return None;
    }

    let paints = BUFFERED_PAINTS.lock();
    let idx = hpb - 1;

    if idx >= MAX_BUFFERED_PAINTS || !paints[idx].in_use {
        return None;
    }

    Some(paints[idx].rc_target)
}

/// Get buffered paint target DC
pub fn get_buffered_paint_target_dc(hpb: HPAINTBUFFER) -> GdiHandle {
    if hpb == NULL_HPAINTBUFFER {
        return GdiHandle::NULL;
    }

    let paints = BUFFERED_PAINTS.lock();
    let idx = hpb - 1;

    if idx >= MAX_BUFFERED_PAINTS || !paints[idx].in_use {
        return GdiHandle::NULL;
    }

    paints[idx].hdc_target
}

/// Get buffered paint DC
pub fn get_buffered_paint_dc(hpb: HPAINTBUFFER) -> GdiHandle {
    if hpb == NULL_HPAINTBUFFER {
        return GdiHandle::NULL;
    }

    let paints = BUFFERED_PAINTS.lock();
    let idx = hpb - 1;

    if idx >= MAX_BUFFERED_PAINTS || !paints[idx].in_use {
        return GdiHandle::NULL;
    }

    paints[idx].hdc_buffer
}

/// Get buffered paint bits
pub fn get_buffered_paint_bits(hpb: HPAINTBUFFER) -> (usize, i32) {
    if hpb == NULL_HPAINTBUFFER {
        return (0, 0);
    }

    let paints = BUFFERED_PAINTS.lock();
    let idx = hpb - 1;

    if idx >= MAX_BUFFERED_PAINTS || !paints[idx].in_use {
        return (0, 0);
    }

    (paints[idx].bits, paints[idx].row_stride)
}

/// Clear buffered paint
pub fn buffered_paint_clear(hpb: HPAINTBUFFER, rect: Option<&Rect>) -> bool {
    if hpb == NULL_HPAINTBUFFER {
        return false;
    }

    let mut paints = BUFFERED_PAINTS.lock();
    let idx = hpb - 1;

    if idx >= MAX_BUFFERED_PAINTS || !paints[idx].in_use {
        return false;
    }

    paints[idx].clear(0);
    let _ = rect;
    true
}

/// Set buffered paint alpha
pub fn buffered_paint_set_alpha(hpb: HPAINTBUFFER, rect: Option<&Rect>, alpha: u8) -> bool {
    if hpb == NULL_HPAINTBUFFER {
        return false;
    }

    let mut paints = BUFFERED_PAINTS.lock();
    let idx = hpb - 1;

    if idx >= MAX_BUFFERED_PAINTS || !paints[idx].in_use {
        return false;
    }

    paints[idx].set_alpha(alpha, rect);
    true
}

/// Make buffered paint opaque
pub fn buffered_paint_make_opaque(hpb: HPAINTBUFFER, rect: Option<&Rect>) -> bool {
    buffered_paint_set_alpha(hpb, rect, 255)
}

/// Begin buffered animation
pub fn begin_buffered_animation(
    hwnd: HWND,
    hdc_target: GdiHandle,
    rc_target: &Rect,
    format: u32,
    params: Option<&AnimationParams>,
) -> (HANIMATIONBUFFER, GdiHandle, GdiHandle) {
    let mut anims = ANIMATION_BUFFERS.lock();

    for (i, anim) in anims.iter_mut().enumerate() {
        if !anim.in_use {
            anim.reset();
            anim.in_use = true;
            anim.hwnd = hwnd;
            anim.rc_target = *rc_target;

            if let Some(p) = params {
                anim.params = *p;
            }

            anim.animating = true;
            anim.start_time = 0; // Would use actual time
            anim.progress = 0;

            let _ = format;

            // In a real implementation, create from/to DCs
            anim.hdc_from = hdc_target;
            anim.hdc_to = hdc_target;

            return (i + 1, anim.hdc_from, anim.hdc_to);
        }
    }

    (NULL_HANIMATIONBUFFER, GdiHandle::NULL, GdiHandle::NULL)
}

/// End buffered animation
pub fn end_buffered_animation(hab: HANIMATIONBUFFER, update_target: bool) -> bool {
    if hab == NULL_HANIMATIONBUFFER {
        return false;
    }

    let mut anims = ANIMATION_BUFFERS.lock();
    let idx = hab - 1;

    if idx >= MAX_ANIMATION_BUFFERS {
        return false;
    }

    if !anims[idx].in_use {
        return false;
    }

    let _ = update_target;
    anims[idx].reset();
    true
}

/// Check if buffered animation is running
pub fn buffered_animation_running(hwnd: HWND) -> bool {
    let anims = ANIMATION_BUFFERS.lock();

    for anim in anims.iter() {
        if anim.in_use && anim.hwnd == hwnd && anim.animating {
            return true;
        }
    }

    false
}

/// Get statistics
pub fn get_stats() -> BufferedPaintStats {
    let paints = BUFFERED_PAINTS.lock();
    let anims = ANIMATION_BUFFERS.lock();

    let mut paint_count = 0;
    let mut anim_count = 0;

    for paint in paints.iter() {
        if paint.in_use {
            paint_count += 1;
        }
    }

    for anim in anims.iter() {
        if anim.in_use {
            anim_count += 1;
        }
    }

    BufferedPaintStats {
        max_paint_buffers: MAX_BUFFERED_PAINTS,
        active_paint_buffers: paint_count,
        max_animation_buffers: MAX_ANIMATION_BUFFERS,
        active_animation_buffers: anim_count,
    }
}

/// BufferedPaint statistics
#[derive(Debug, Clone, Copy)]
pub struct BufferedPaintStats {
    pub max_paint_buffers: usize,
    pub active_paint_buffers: usize,
    pub max_animation_buffers: usize,
    pub active_animation_buffers: usize,
}
