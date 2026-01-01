//! Animate Control Implementation
//!
//! Windows Animation control for displaying AVI clips.
//! Based on Windows Server 2003 commctrl.h and SysAnimate32.
//!
//! # Features
//!
//! - AVI animation playback (simplified frame-based)
//! - Looping and repeat control
//! - Centered and transparent display
//! - Start/stop notifications
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - ACM_* messages, ACS_* styles

use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Rect};

// ============================================================================
// Animate Control Styles (ACS_*)
// ============================================================================

/// Center the animation in the control
pub const ACS_CENTER: u32 = 0x0001;

/// Draw using transparent background
pub const ACS_TRANSPARENT: u32 = 0x0002;

/// Start playing when opened
pub const ACS_AUTOPLAY: u32 = 0x0004;

/// Use timer instead of separate thread
pub const ACS_TIMER: u32 = 0x0008;

// ============================================================================
// Animate Control Messages
// ============================================================================

/// WM_USER base for Animate messages
pub const WM_USER: u32 = 0x0400;

/// Open an animation resource (ANSI)
/// wParam: HINSTANCE (or 0 for file)
/// lParam: pointer to resource name or file path
/// Returns: TRUE if successful
pub const ACM_OPENA: u32 = WM_USER + 100;

/// Play the animation
/// wParam: number of times to play (0 = infinite)
/// lParam: LOWORD = start frame, HIWORD = end frame (-1 = all)
/// Returns: TRUE if successful
pub const ACM_PLAY: u32 = WM_USER + 101;

/// Stop the animation
/// Returns: TRUE if successful
pub const ACM_STOP: u32 = WM_USER + 102;

/// Open an animation resource (Unicode)
/// wParam: HINSTANCE (or 0 for file)
/// lParam: pointer to resource name or file path
/// Returns: TRUE if successful
pub const ACM_OPENW: u32 = WM_USER + 103;

/// Alias for ACM_OPENA
pub const ACM_OPEN: u32 = ACM_OPENA;

// ============================================================================
// Animate Control Notifications (ACN_*)
// ============================================================================

/// Sent when animation starts playing
pub const ACN_START: u32 = 1;

/// Sent when animation stops playing
pub const ACN_STOP: u32 = 2;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of Animate controls
pub const MAX_ANIMATE_CONTROLS: usize = 32;

/// Maximum number of frames per animation
pub const MAX_ANIMATION_FRAMES: usize = 256;

/// Animate control class name
pub const ANIMATE_CLASS: &str = "SysAnimate32";

// ============================================================================
// Animation Frame Structure
// ============================================================================

/// A single animation frame
#[derive(Clone, Copy)]
pub struct AnimationFrame {
    /// Frame duration in milliseconds
    pub duration_ms: u32,
    /// Frame index in source data
    pub source_index: u32,
    /// Is this frame valid
    pub valid: bool,
}

impl AnimationFrame {
    /// Create a new empty frame
    pub const fn new() -> Self {
        Self {
            duration_ms: 100,
            source_index: 0,
            valid: false,
        }
    }
}

// ============================================================================
// Animation State
// ============================================================================

/// Animation playback state
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PlaybackState {
    /// Not playing
    Stopped,
    /// Currently playing
    Playing,
    /// Paused (can resume)
    Paused,
}

impl Default for PlaybackState {
    fn default() -> Self {
        Self::Stopped
    }
}

// ============================================================================
// Animate Control Structure
// ============================================================================

/// Animate control state
#[derive(Clone)]
pub struct AnimateControl {
    /// Control handle
    pub hwnd: HWND,
    /// Is this slot in use
    pub in_use: bool,
    /// Control style flags
    pub style: u32,
    /// Display rectangle
    pub rect: Rect,
    /// Animation is loaded
    pub loaded: bool,
    /// Playback state
    pub state: PlaybackState,
    /// Total number of frames
    pub frame_count: usize,
    /// Current frame index
    pub current_frame: usize,
    /// Start frame for playback
    pub start_frame: usize,
    /// End frame for playback
    pub end_frame: usize,
    /// Repeat count (0 = infinite)
    pub repeat_count: u32,
    /// Current repeat iteration
    pub current_repeat: u32,
    /// Frame data
    pub frames: [AnimationFrame; MAX_ANIMATION_FRAMES],
    /// Last tick when frame was advanced
    pub last_tick: u64,
    /// Resource name (simplified storage)
    pub resource_name: [u8; 64],
    pub resource_name_len: usize,
}

impl AnimateControl {
    /// Create a new Animate control
    pub const fn new() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            in_use: false,
            style: 0,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            loaded: false,
            state: PlaybackState::Stopped,
            frame_count: 0,
            current_frame: 0,
            start_frame: 0,
            end_frame: 0,
            repeat_count: 0,
            current_repeat: 0,
            frames: [const { AnimationFrame::new() }; MAX_ANIMATION_FRAMES],
            last_tick: 0,
            resource_name: [0u8; 64],
            resource_name_len: 0,
        }
    }

    /// Reset control to default state
    pub fn reset(&mut self) {
        self.hwnd = UserHandle::NULL;
        self.in_use = false;
        self.style = 0;
        self.rect = Rect { left: 0, top: 0, right: 0, bottom: 0 };
        self.loaded = false;
        self.state = PlaybackState::Stopped;
        self.frame_count = 0;
        self.current_frame = 0;
        self.start_frame = 0;
        self.end_frame = 0;
        self.repeat_count = 0;
        self.current_repeat = 0;
        for frame in self.frames.iter_mut() {
            *frame = AnimationFrame::new();
        }
        self.last_tick = 0;
        self.resource_name = [0u8; 64];
        self.resource_name_len = 0;
    }

    /// Open an animation resource
    pub fn open(&mut self, _hinst: usize, name: &[u8]) -> bool {
        // Store resource name
        let len = core::cmp::min(name.len(), self.resource_name.len());
        self.resource_name[..len].copy_from_slice(&name[..len]);
        self.resource_name_len = len;

        // In a real implementation, we would parse the AVI file here
        // For now, create a placeholder animation with default frames
        self.frame_count = 4;
        for i in 0..self.frame_count {
            self.frames[i].valid = true;
            self.frames[i].source_index = i as u32;
            self.frames[i].duration_ms = 100;
        }

        self.loaded = true;
        self.current_frame = 0;
        self.start_frame = 0;
        self.end_frame = self.frame_count.saturating_sub(1);

        // Auto-play if style is set
        if self.style & ACS_AUTOPLAY != 0 {
            self.play(0, 0, self.frame_count.saturating_sub(1));
        }

        true
    }

    /// Close the current animation
    pub fn close(&mut self) {
        self.stop();
        self.loaded = false;
        self.frame_count = 0;
        for frame in self.frames.iter_mut() {
            frame.valid = false;
        }
        self.resource_name_len = 0;
    }

    /// Start playing the animation
    pub fn play(&mut self, repeat: u32, start: usize, end: usize) -> bool {
        if !self.loaded || self.frame_count == 0 {
            return false;
        }

        self.start_frame = core::cmp::min(start, self.frame_count.saturating_sub(1));
        self.end_frame = core::cmp::min(end, self.frame_count.saturating_sub(1));
        if self.end_frame < self.start_frame {
            self.end_frame = self.frame_count.saturating_sub(1);
        }

        self.repeat_count = repeat;
        self.current_repeat = 0;
        self.current_frame = self.start_frame;
        self.state = PlaybackState::Playing;
        self.last_tick = 0; // Will be set on first update

        true
    }

    /// Stop the animation
    pub fn stop(&mut self) -> bool {
        if self.state == PlaybackState::Stopped {
            return false;
        }

        self.state = PlaybackState::Stopped;
        self.current_frame = self.start_frame;
        true
    }

    /// Pause the animation
    pub fn pause(&mut self) -> bool {
        if self.state != PlaybackState::Playing {
            return false;
        }

        self.state = PlaybackState::Paused;
        true
    }

    /// Resume paused animation
    pub fn resume(&mut self) -> bool {
        if self.state != PlaybackState::Paused {
            return false;
        }

        self.state = PlaybackState::Playing;
        true
    }

    /// Advance to next frame based on elapsed time
    pub fn update(&mut self, current_tick: u64) -> bool {
        if self.state != PlaybackState::Playing {
            return false;
        }

        if self.last_tick == 0 {
            self.last_tick = current_tick;
            return false;
        }

        let frame = &self.frames[self.current_frame];
        let elapsed = current_tick.saturating_sub(self.last_tick);

        if elapsed >= frame.duration_ms as u64 {
            self.last_tick = current_tick;

            // Advance to next frame
            if self.current_frame >= self.end_frame {
                // End of sequence
                self.current_repeat += 1;
                if self.repeat_count != 0 && self.current_repeat >= self.repeat_count {
                    // Stop after repeat count reached
                    self.state = PlaybackState::Stopped;
                    return true;
                }
                // Loop back to start
                self.current_frame = self.start_frame;
            } else {
                self.current_frame += 1;
            }

            return true; // Frame changed
        }

        false
    }

    /// Get current frame index
    pub fn get_current_frame(&self) -> usize {
        self.current_frame
    }

    /// Check if animation is playing
    pub fn is_playing(&self) -> bool {
        self.state == PlaybackState::Playing
    }

    /// Seek to a specific frame
    pub fn seek(&mut self, frame: usize) -> bool {
        if !self.loaded {
            return false;
        }

        if frame < self.frame_count {
            self.current_frame = frame;
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global Animate control storage
static ANIMATE_CONTROLS: SpinLock<[AnimateControl; MAX_ANIMATE_CONTROLS]> =
    SpinLock::new([const { AnimateControl::new() }; MAX_ANIMATE_CONTROLS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize Animate control subsystem
pub fn init() {
    crate::serial_println!("[USER] Animate control initialized");
}

/// Create an Animate control
pub fn create_animate(hwnd: HWND, style: u32, rect: &Rect) -> Option<usize> {
    let mut controls = ANIMATE_CONTROLS.lock();

    for (i, control) in controls.iter_mut().enumerate() {
        if !control.in_use {
            control.reset();
            control.hwnd = hwnd;
            control.in_use = true;
            control.style = style;
            control.rect = *rect;
            return Some(i);
        }
    }

    None
}

/// Destroy an Animate control
pub fn destroy_animate(index: usize) -> bool {
    let mut controls = ANIMATE_CONTROLS.lock();

    if index >= MAX_ANIMATE_CONTROLS {
        return false;
    }

    if controls[index].in_use {
        controls[index].reset();
        true
    } else {
        false
    }
}

/// Open an animation
pub fn open(index: usize, hinst: usize, name: &[u8]) -> bool {
    let mut controls = ANIMATE_CONTROLS.lock();

    if index >= MAX_ANIMATE_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].open(hinst, name)
}

/// Close the current animation
pub fn close(index: usize) -> bool {
    let mut controls = ANIMATE_CONTROLS.lock();

    if index >= MAX_ANIMATE_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].close();
    true
}

/// Play the animation
pub fn play(index: usize, repeat: u32, start: usize, end: usize) -> bool {
    let mut controls = ANIMATE_CONTROLS.lock();

    if index >= MAX_ANIMATE_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].play(repeat, start, end)
}

/// Stop the animation
pub fn stop(index: usize) -> bool {
    let mut controls = ANIMATE_CONTROLS.lock();

    if index >= MAX_ANIMATE_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].stop()
}

/// Update animation (advance frames)
pub fn update(index: usize, current_tick: u64) -> bool {
    let mut controls = ANIMATE_CONTROLS.lock();

    if index >= MAX_ANIMATE_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].update(current_tick)
}

/// Get current frame
pub fn get_current_frame(index: usize) -> Option<usize> {
    let controls = ANIMATE_CONTROLS.lock();

    if index >= MAX_ANIMATE_CONTROLS || !controls[index].in_use {
        return None;
    }

    Some(controls[index].current_frame)
}

/// Check if playing
pub fn is_playing(index: usize) -> bool {
    let controls = ANIMATE_CONTROLS.lock();

    if index >= MAX_ANIMATE_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].is_playing()
}

/// Process Animate control message
pub fn process_message(index: usize, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        ACM_OPENA | ACM_OPENW => {
            // In a real implementation, lparam would point to the resource name
            // For now, we'll use a dummy name
            let name = b"animation";
            if open(index, wparam, name) { 1 } else { 0 }
        }
        ACM_PLAY => {
            let repeat = wparam as u32;
            let start = (lparam & 0xFFFF) as usize;
            let end = ((lparam >> 16) & 0xFFFF) as usize;
            let end = if end == 0xFFFF { usize::MAX } else { end };
            if play(index, repeat, start, end) { 1 } else { 0 }
        }
        ACM_STOP => {
            if stop(index) { 1 } else { 0 }
        }
        _ => 0,
    }
}

/// Get statistics
pub fn get_stats() -> AnimateStats {
    let controls = ANIMATE_CONTROLS.lock();

    let mut active_count = 0;
    let mut playing_count = 0;

    for control in controls.iter() {
        if control.in_use {
            active_count += 1;
            if control.is_playing() {
                playing_count += 1;
            }
        }
    }

    AnimateStats {
        max_controls: MAX_ANIMATE_CONTROLS,
        active_controls: active_count,
        playing_controls: playing_count,
    }
}

/// Animate statistics
#[derive(Debug, Clone, Copy)]
pub struct AnimateStats {
    pub max_controls: usize,
    pub active_controls: usize,
    pub playing_controls: usize,
}
