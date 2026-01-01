//! Win32k Subsystem
//!
//! Kernel-mode implementation of the Windows graphical subsystem.
//! This provides GDI (Graphics Device Interface) and USER (Window Manager)
//! functionality following the Windows NT architecture.
//!
//! # Architecture
//!
//! The Win32k subsystem consists of two major components:
//!
//! - **GDI (gdi/)**: Graphics rendering, device contexts, brushes, pens, regions
//! - **USER (user/)**: Window management, message queues, input handling
//!
//! # NT Functions
//!
//! GDI entry points (NtGdiXxx):
//! - `NtGdiCreateDC` - Create device context
//! - `NtGdiBitBlt` - Bit block transfer
//! - `NtGdiLineTo` - Draw line
//! - `NtGdiRectangle` - Draw rectangle
//!
//! USER entry points (NtUserXxx):
//! - `NtUserCreateWindowEx` - Create window
//! - `NtUserDestroyWindow` - Destroy window
//! - `NtUserGetMessage` - Get message from queue
//! - `NtUserDispatchMessage` - Dispatch message to window procedure
//!
//! # References
//!
//! Based on Windows Server 2003 win32k.sys implementation:
//! - `windows/core/ntgdi/` - GDI implementation
//! - `windows/core/ntuser/` - USER implementation

pub mod gdi;
pub mod user;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::ke::spinlock::SpinLock;

// ============================================================================
// Win32k Global State
// ============================================================================

/// Win32k initialization state
static WIN32K_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Global session count
static SESSION_COUNT: AtomicU32 = AtomicU32::new(0);

/// Win32k global lock
static WIN32K_LOCK: SpinLock<()> = SpinLock::new(());

// ============================================================================
// NT Status Codes
// ============================================================================

/// Win32k-specific status codes
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum W32Status {
    Success = 0,
    InvalidHandle = 0xC0000008,
    InvalidParameter = 0xC000000D,
    NoMemory = 0xC0000017,
    NotImplemented = 0xC0000002,
    AccessDenied = 0xC0000022,
    ObjectTypeMismatch = 0xC0000024,
    BufferTooSmall = 0xC0000023,
}

impl W32Status {
    pub fn is_success(self) -> bool {
        self == W32Status::Success
    }
}

// ============================================================================
// Object Types
// ============================================================================

/// GDI object types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdiObjectType {
    None = 0,
    DC = 1,           // Device Context
    Bitmap = 2,       // Bitmap/Surface
    Brush = 3,        // Brush
    Pen = 4,          // Pen
    Font = 5,         // Font
    Region = 6,       // Region
    Palette = 7,      // Palette
    Path = 8,         // Path
}

/// USER object types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserObjectType {
    None = 0,
    Window = 1,       // Window
    Menu = 2,         // Menu
    Cursor = 3,       // Cursor
    Icon = 4,         // Icon
    Hook = 5,         // Hook
    AccelTable = 6,   // Accelerator table
    Monitor = 7,      // Monitor
}

// ============================================================================
// Handle Types
// ============================================================================

/// GDI handle (HDC, HBITMAP, HBRUSH, etc.)
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GdiHandle(u32);

impl GdiHandle {
    pub const NULL: GdiHandle = GdiHandle(0);

    /// Create a new handle from index and type
    pub const fn new(index: u16, obj_type: GdiObjectType) -> Self {
        // Handle format: type (8 bits) | stock (1 bit) | reserved (7 bits) | index (16 bits)
        GdiHandle(((obj_type as u32) << 24) | (index as u32))
    }

    /// Get the object type from handle
    pub const fn object_type(self) -> GdiObjectType {
        match (self.0 >> 24) as u8 {
            1 => GdiObjectType::DC,
            2 => GdiObjectType::Bitmap,
            3 => GdiObjectType::Brush,
            4 => GdiObjectType::Pen,
            5 => GdiObjectType::Font,
            6 => GdiObjectType::Region,
            7 => GdiObjectType::Palette,
            8 => GdiObjectType::Path,
            _ => GdiObjectType::None,
        }
    }

    /// Get the index from handle
    pub const fn index(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }

    /// Check if handle is valid
    pub const fn is_valid(self) -> bool {
        self.0 != 0 && matches!(self.object_type(),
            GdiObjectType::DC | GdiObjectType::Bitmap | GdiObjectType::Brush |
            GdiObjectType::Pen | GdiObjectType::Font | GdiObjectType::Region |
            GdiObjectType::Palette | GdiObjectType::Path)
    }

    /// Get raw handle value
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// USER handle (HWND, HMENU, etc.)
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserHandle(u32);

impl UserHandle {
    pub const NULL: UserHandle = UserHandle(0);

    /// Create a new handle from index and type
    pub const fn new(index: u16, obj_type: UserObjectType) -> Self {
        UserHandle(((obj_type as u32) << 24) | (index as u32))
    }

    /// Get the object type from handle
    pub const fn object_type(self) -> UserObjectType {
        match (self.0 >> 24) as u8 {
            1 => UserObjectType::Window,
            2 => UserObjectType::Menu,
            3 => UserObjectType::Cursor,
            4 => UserObjectType::Icon,
            5 => UserObjectType::Hook,
            6 => UserObjectType::AccelTable,
            7 => UserObjectType::Monitor,
            _ => UserObjectType::None,
        }
    }

    /// Get the index from handle
    pub const fn index(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }

    /// Check if handle is valid
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }

    /// Get raw handle value
    pub const fn raw(self) -> u32 {
        self.0
    }
}

// Type aliases for clarity
pub type HDC = GdiHandle;
pub type HBITMAP = GdiHandle;
pub type HBRUSH = GdiHandle;
pub type HPEN = GdiHandle;
pub type HFONT = GdiHandle;
pub type HRGN = GdiHandle;
pub type HPALETTE = GdiHandle;

pub type HWND = UserHandle;
pub type HMENU = UserHandle;
pub type HCURSOR = UserHandle;
pub type HICON = UserHandle;

// ============================================================================
// Common Structures
// ============================================================================

/// Point structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    pub const fn new(x: i32, y: i32) -> Self {
        Point { x, y }
    }
}

/// Size structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Size {
    pub cx: i32,
    pub cy: i32,
}

impl Size {
    pub const fn new(cx: i32, cy: i32) -> Self {
        Size { cx, cy }
    }
}

/// Rectangle structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect {
    pub const fn new(left: i32, top: i32, right: i32, bottom: i32) -> Self {
        Rect { left, top, right, bottom }
    }

    pub const fn width(&self) -> i32 {
        self.right - self.left
    }

    pub const fn height(&self) -> i32 {
        self.bottom - self.top
    }

    pub const fn is_empty(&self) -> bool {
        self.left >= self.right || self.top >= self.bottom
    }

    pub fn contains_point(&self, pt: Point) -> bool {
        pt.x >= self.left && pt.x < self.right &&
        pt.y >= self.top && pt.y < self.bottom
    }

    pub fn intersects(&self, other: &Rect) -> bool {
        self.left < other.right && self.right > other.left &&
        self.top < other.bottom && self.bottom > other.top
    }

    pub fn intersect(&self, other: &Rect) -> Option<Rect> {
        let result = Rect {
            left: self.left.max(other.left),
            top: self.top.max(other.top),
            right: self.right.min(other.right),
            bottom: self.bottom.min(other.bottom),
        };

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    pub fn union(&self, other: &Rect) -> Rect {
        Rect {
            left: self.left.min(other.left),
            top: self.top.min(other.top),
            right: self.right.max(other.right),
            bottom: self.bottom.max(other.bottom),
        }
    }

    pub fn offset(&mut self, dx: i32, dy: i32) {
        self.left += dx;
        self.right += dx;
        self.top += dy;
        self.bottom += dy;
    }
}

/// RGB color
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ColorRef(pub u32);

impl ColorRef {
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        ColorRef((r as u32) | ((g as u32) << 8) | ((b as u32) << 16))
    }

    pub const fn red(self) -> u8 {
        (self.0 & 0xFF) as u8
    }

    pub const fn green(self) -> u8 {
        ((self.0 >> 8) & 0xFF) as u8
    }

    pub const fn blue(self) -> u8 {
        ((self.0 >> 16) & 0xFF) as u8
    }

    /// Convert to 32-bit BGRA format (for framebuffer)
    pub const fn to_bgra(self) -> u32 {
        (self.blue() as u32) |
        ((self.green() as u32) << 8) |
        ((self.red() as u32) << 16) |
        0xFF000000 // Alpha = 255
    }
}

// Standard colors
impl ColorRef {
    pub const BLACK: ColorRef = ColorRef::rgb(0, 0, 0);
    pub const WHITE: ColorRef = ColorRef::rgb(255, 255, 255);
    pub const RED: ColorRef = ColorRef::rgb(255, 0, 0);
    pub const GREEN: ColorRef = ColorRef::rgb(0, 255, 0);
    pub const BLUE: ColorRef = ColorRef::rgb(0, 0, 255);
    pub const YELLOW: ColorRef = ColorRef::rgb(255, 255, 0);
    pub const CYAN: ColorRef = ColorRef::rgb(0, 255, 255);
    pub const MAGENTA: ColorRef = ColorRef::rgb(255, 0, 255);
    pub const GRAY: ColorRef = ColorRef::rgb(128, 128, 128);
    pub const LIGHT_GRAY: ColorRef = ColorRef::rgb(192, 192, 192);
    pub const DARK_GRAY: ColorRef = ColorRef::rgb(64, 64, 64);

    // Windows classic colors
    pub const WINDOW_BG: ColorRef = ColorRef::rgb(212, 208, 200);      // Classic window background
    pub const WINDOW_FRAME: ColorRef = ColorRef::rgb(0, 0, 128);       // Dark blue title bar
    pub const ACTIVE_CAPTION: ColorRef = ColorRef::rgb(0, 84, 227);    // Active title bar (XP blue)
    pub const INACTIVE_CAPTION: ColorRef = ColorRef::rgb(122, 150, 223);
    pub const BUTTON_FACE: ColorRef = ColorRef::rgb(212, 208, 200);
    pub const BUTTON_SHADOW: ColorRef = ColorRef::rgb(128, 128, 128);
    pub const BUTTON_HIGHLIGHT: ColorRef = ColorRef::rgb(255, 255, 255);
    pub const DESKTOP: ColorRef = ColorRef::rgb(58, 110, 165);         // Classic desktop blue
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Win32k subsystem
pub fn init() {
    let _guard = WIN32K_LOCK.lock();

    if WIN32K_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    crate::serial_println!("[Win32k] Initializing graphical subsystem...");

    // Initialize GDI
    gdi::init();

    // Initialize USER
    user::init();

    WIN32K_INITIALIZED.store(true, Ordering::Release);

    crate::serial_println!("[Win32k] Graphical subsystem initialized");
}

/// Check if Win32k is initialized
pub fn is_initialized() -> bool {
    WIN32K_INITIALIZED.load(Ordering::Acquire)
}

/// Get Win32k statistics
pub fn get_stats() -> Win32kStats {
    Win32kStats {
        initialized: is_initialized(),
        session_count: SESSION_COUNT.load(Ordering::Relaxed),
        gdi_stats: gdi::get_stats(),
        user_stats: user::get_stats(),
    }
}

/// Win32k statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct Win32kStats {
    pub initialized: bool,
    pub session_count: u32,
    pub gdi_stats: gdi::GdiStats,
    pub user_stats: user::UserStats,
}
