//! GDI32.dll Stub Implementation
//!
//! Graphics Device Interface APIs - drawing, fonts, bitmaps, device contexts.
//! These wrap syscalls to Win32k GDI subsystem.

use core::ptr;

/// Syscall numbers for Win32k GDI services
mod syscall {
    // Device Context
    pub const NtGdiCreateCompatibleDC: u32 = 0x2000;
    pub const NtGdiDeleteDC: u32 = 0x2001;
    pub const NtGdiGetDeviceCaps: u32 = 0x2002;
    pub const NtGdiSaveDC: u32 = 0x2003;
    pub const NtGdiRestoreDC: u32 = 0x2004;
    pub const NtGdiSetBkMode: u32 = 0x2005;
    pub const NtGdiGetBkMode: u32 = 0x2006;
    pub const NtGdiSetBkColor: u32 = 0x2007;
    pub const NtGdiGetBkColor: u32 = 0x2008;
    pub const NtGdiSetTextColor: u32 = 0x2009;
    pub const NtGdiGetTextColor: u32 = 0x200A;
    pub const NtGdiSetMapMode: u32 = 0x200B;
    pub const NtGdiGetMapMode: u32 = 0x200C;

    // Objects
    pub const NtGdiSelectObject: u32 = 0x2010;
    pub const NtGdiGetObject: u32 = 0x2011;
    pub const NtGdiDeleteObject: u32 = 0x2012;
    pub const NtGdiGetStockObject: u32 = 0x2013;
    pub const NtGdiGetCurrentObject: u32 = 0x2014;

    // Pens
    pub const NtGdiCreatePen: u32 = 0x2020;
    pub const NtGdiExtCreatePen: u32 = 0x2021;

    // Brushes
    pub const NtGdiCreateSolidBrush: u32 = 0x2030;
    pub const NtGdiCreateHatchBrush: u32 = 0x2031;
    pub const NtGdiCreatePatternBrush: u32 = 0x2032;
    pub const NtGdiCreateDIBPatternBrush: u32 = 0x2033;

    // Bitmaps
    pub const NtGdiCreateBitmap: u32 = 0x2040;
    pub const NtGdiCreateCompatibleBitmap: u32 = 0x2041;
    pub const NtGdiCreateDIBSection: u32 = 0x2042;
    pub const NtGdiGetDIBits: u32 = 0x2043;
    pub const NtGdiSetDIBits: u32 = 0x2044;
    pub const NtGdiStretchDIBits: u32 = 0x2045;
    pub const NtGdiBitBlt: u32 = 0x2046;
    pub const NtGdiStretchBlt: u32 = 0x2047;
    pub const NtGdiPatBlt: u32 = 0x2048;
    pub const NtGdiMaskBlt: u32 = 0x2049;
    pub const NtGdiAlphaBlend: u32 = 0x204A;
    pub const NtGdiTransparentBlt: u32 = 0x204B;

    // Drawing
    pub const NtGdiMoveTo: u32 = 0x2050;
    pub const NtGdiLineTo: u32 = 0x2051;
    pub const NtGdiPolyline: u32 = 0x2052;
    pub const NtGdiPolylineTo: u32 = 0x2053;
    pub const NtGdiPolygon: u32 = 0x2054;
    pub const NtGdiPolyPolygon: u32 = 0x2055;
    pub const NtGdiRectangle: u32 = 0x2056;
    pub const NtGdiRoundRect: u32 = 0x2057;
    pub const NtGdiEllipse: u32 = 0x2058;
    pub const NtGdiArc: u32 = 0x2059;
    pub const NtGdiPie: u32 = 0x205A;
    pub const NtGdiChord: u32 = 0x205B;

    // Fill
    pub const NtGdiFillRect: u32 = 0x2060;
    pub const NtGdiFrameRect: u32 = 0x2061;
    pub const NtGdiInvertRect: u32 = 0x2062;
    pub const NtGdiSetPixel: u32 = 0x2063;
    pub const NtGdiGetPixel: u32 = 0x2064;
    pub const NtGdiFloodFill: u32 = 0x2065;
    pub const NtGdiExtFloodFill: u32 = 0x2066;

    // Regions
    pub const NtGdiCreateRectRgn: u32 = 0x2070;
    pub const NtGdiCreateEllipticRgn: u32 = 0x2071;
    pub const NtGdiCreatePolygonRgn: u32 = 0x2072;
    pub const NtGdiCombineRgn: u32 = 0x2073;
    pub const NtGdiSelectClipRgn: u32 = 0x2074;
    pub const NtGdiGetClipRgn: u32 = 0x2075;
    pub const NtGdiPtInRegion: u32 = 0x2076;
    pub const NtGdiRectInRegion: u32 = 0x2077;
    pub const NtGdiGetRgnBox: u32 = 0x2078;
    pub const NtGdiOffsetRgn: u32 = 0x2079;

    // Fonts
    pub const NtGdiCreateFontA: u32 = 0x2080;
    pub const NtGdiCreateFontW: u32 = 0x2081;
    pub const NtGdiCreateFontIndirectA: u32 = 0x2082;
    pub const NtGdiCreateFontIndirectW: u32 = 0x2083;
    pub const NtGdiGetTextMetrics: u32 = 0x2084;
    pub const NtGdiGetTextExtentPoint: u32 = 0x2085;
    pub const NtGdiGetCharWidth: u32 = 0x2086;
    pub const NtGdiGetTextFace: u32 = 0x2087;

    // Text Output
    pub const NtGdiTextOutA: u32 = 0x2090;
    pub const NtGdiTextOutW: u32 = 0x2091;
    pub const NtGdiExtTextOutA: u32 = 0x2092;
    pub const NtGdiExtTextOutW: u32 = 0x2093;
    pub const NtGdiDrawTextA: u32 = 0x2094;
    pub const NtGdiDrawTextW: u32 = 0x2095;
    pub const NtGdiSetTextAlign: u32 = 0x2096;
    pub const NtGdiGetTextAlign: u32 = 0x2097;

    // Paths
    pub const NtGdiBeginPath: u32 = 0x20A0;
    pub const NtGdiEndPath: u32 = 0x20A1;
    pub const NtGdiCloseFigure: u32 = 0x20A2;
    pub const NtGdiStrokePath: u32 = 0x20A3;
    pub const NtGdiFillPath: u32 = 0x20A4;
    pub const NtGdiStrokeAndFillPath: u32 = 0x20A5;
    pub const NtGdiFlattenPath: u32 = 0x20A6;
    pub const NtGdiWidenPath: u32 = 0x20A7;

    // Coordinate transforms
    pub const NtGdiSetViewportOrgEx: u32 = 0x20B0;
    pub const NtGdiGetViewportOrgEx: u32 = 0x20B1;
    pub const NtGdiSetWindowOrgEx: u32 = 0x20B2;
    pub const NtGdiGetWindowOrgEx: u32 = 0x20B3;
    pub const NtGdiSetViewportExtEx: u32 = 0x20B4;
    pub const NtGdiGetViewportExtEx: u32 = 0x20B5;
    pub const NtGdiSetWindowExtEx: u32 = 0x20B6;
    pub const NtGdiGetWindowExtEx: u32 = 0x20B7;
    pub const NtGdiDPtoLP: u32 = 0x20B8;
    pub const NtGdiLPtoDP: u32 = 0x20B9;

    // Metafiles
    pub const NtGdiCreateMetaFile: u32 = 0x20C0;
    pub const NtGdiCloseMetaFile: u32 = 0x20C1;
    pub const NtGdiPlayMetaFile: u32 = 0x20C2;
    pub const NtGdiCreateEnhMetaFile: u32 = 0x20C3;
    pub const NtGdiCloseEnhMetaFile: u32 = 0x20C4;
    pub const NtGdiPlayEnhMetaFile: u32 = 0x20C5;

    // Palettes
    pub const NtGdiCreatePalette: u32 = 0x20D0;
    pub const NtGdiSelectPalette: u32 = 0x20D1;
    pub const NtGdiRealizePalette: u32 = 0x20D2;
    pub const NtGdiGetNearestColor: u32 = 0x20D3;
    pub const NtGdiGetNearestPaletteIndex: u32 = 0x20D4;
}

/// Make a Win32k syscall
#[inline(always)]
unsafe fn win32k_syscall(num: u32, args: &[u64]) -> u64 {
    let result: u64;
    let syscall_num = num as u64 | 0x1000;

    match args.len() {
        0 => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        1 => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                in("rdi") args[0],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        2 => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                in("rdi") args[0],
                in("rsi") args[1],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        3 => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        4 => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                in("r10") args[3],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        5 => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                in("r10") args[3],
                in("r8") args[4],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        _ => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                in("r10") args[3],
                in("r8") args[4],
                in("r9") args[5],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
    }
    result
}

// Type definitions
pub type HDC = u64;
pub type HGDIOBJ = u64;
pub type HPEN = u64;
pub type HBRUSH = u64;
pub type HBITMAP = u64;
pub type HFONT = u64;
pub type HRGN = u64;
pub type HPALETTE = u64;
pub type HMETAFILE = u64;
pub type HENHMETAFILE = u64;
pub type COLORREF = u32;
pub type BOOL = i32;
pub type UINT = u32;
pub type LONG = i32;
pub type DWORD = u32;
pub type WORD = u16;
pub type BYTE = u8;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

// RGB macro equivalent
#[inline]
pub const fn RGB(r: u8, g: u8, b: u8) -> COLORREF {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

#[inline]
pub const fn GetRValue(c: COLORREF) -> u8 { c as u8 }
#[inline]
pub const fn GetGValue(c: COLORREF) -> u8 { (c >> 8) as u8 }
#[inline]
pub const fn GetBValue(c: COLORREF) -> u8 { (c >> 16) as u8 }

#[repr(C)]
pub struct POINT {
    pub x: LONG,
    pub y: LONG,
}

#[repr(C)]
pub struct SIZE {
    pub cx: LONG,
    pub cy: LONG,
}

#[repr(C)]
pub struct RECT {
    pub left: LONG,
    pub top: LONG,
    pub right: LONG,
    pub bottom: LONG,
}

#[repr(C)]
pub struct TEXTMETRICA {
    pub tmHeight: LONG,
    pub tmAscent: LONG,
    pub tmDescent: LONG,
    pub tmInternalLeading: LONG,
    pub tmExternalLeading: LONG,
    pub tmAveCharWidth: LONG,
    pub tmMaxCharWidth: LONG,
    pub tmWeight: LONG,
    pub tmOverhang: LONG,
    pub tmDigitizedAspectX: LONG,
    pub tmDigitizedAspectY: LONG,
    pub tmFirstChar: BYTE,
    pub tmLastChar: BYTE,
    pub tmDefaultChar: BYTE,
    pub tmBreakChar: BYTE,
    pub tmItalic: BYTE,
    pub tmUnderlined: BYTE,
    pub tmStruckOut: BYTE,
    pub tmPitchAndFamily: BYTE,
    pub tmCharSet: BYTE,
}

#[repr(C)]
pub struct LOGFONTA {
    pub lfHeight: LONG,
    pub lfWidth: LONG,
    pub lfEscapement: LONG,
    pub lfOrientation: LONG,
    pub lfWeight: LONG,
    pub lfItalic: BYTE,
    pub lfUnderline: BYTE,
    pub lfStrikeOut: BYTE,
    pub lfCharSet: BYTE,
    pub lfOutPrecision: BYTE,
    pub lfClipPrecision: BYTE,
    pub lfQuality: BYTE,
    pub lfPitchAndFamily: BYTE,
    pub lfFaceName: [u8; 32],
}

#[repr(C)]
pub struct LOGFONTW {
    pub lfHeight: LONG,
    pub lfWidth: LONG,
    pub lfEscapement: LONG,
    pub lfOrientation: LONG,
    pub lfWeight: LONG,
    pub lfItalic: BYTE,
    pub lfUnderline: BYTE,
    pub lfStrikeOut: BYTE,
    pub lfCharSet: BYTE,
    pub lfOutPrecision: BYTE,
    pub lfClipPrecision: BYTE,
    pub lfQuality: BYTE,
    pub lfPitchAndFamily: BYTE,
    pub lfFaceName: [u16; 32],
}

#[repr(C)]
pub struct BITMAP {
    pub bmType: LONG,
    pub bmWidth: LONG,
    pub bmHeight: LONG,
    pub bmWidthBytes: LONG,
    pub bmPlanes: WORD,
    pub bmBitsPixel: WORD,
    pub bmBits: *mut u8,
}

#[repr(C)]
pub struct BITMAPINFOHEADER {
    pub biSize: DWORD,
    pub biWidth: LONG,
    pub biHeight: LONG,
    pub biPlanes: WORD,
    pub biBitCount: WORD,
    pub biCompression: DWORD,
    pub biSizeImage: DWORD,
    pub biXPelsPerMeter: LONG,
    pub biYPelsPerMeter: LONG,
    pub biClrUsed: DWORD,
    pub biClrImportant: DWORD,
}

#[repr(C)]
pub struct RGBQUAD {
    pub rgbBlue: BYTE,
    pub rgbGreen: BYTE,
    pub rgbRed: BYTE,
    pub rgbReserved: BYTE,
}

#[repr(C)]
pub struct BITMAPINFO {
    pub bmiHeader: BITMAPINFOHEADER,
    pub bmiColors: [RGBQUAD; 1],
}

// Stock objects
pub const WHITE_BRUSH: i32 = 0;
pub const LTGRAY_BRUSH: i32 = 1;
pub const GRAY_BRUSH: i32 = 2;
pub const DKGRAY_BRUSH: i32 = 3;
pub const BLACK_BRUSH: i32 = 4;
pub const NULL_BRUSH: i32 = 5;
pub const HOLLOW_BRUSH: i32 = 5;
pub const WHITE_PEN: i32 = 6;
pub const BLACK_PEN: i32 = 7;
pub const NULL_PEN: i32 = 8;
pub const OEM_FIXED_FONT: i32 = 10;
pub const ANSI_FIXED_FONT: i32 = 11;
pub const ANSI_VAR_FONT: i32 = 12;
pub const SYSTEM_FONT: i32 = 13;
pub const DEVICE_DEFAULT_FONT: i32 = 14;
pub const DEFAULT_PALETTE: i32 = 15;
pub const SYSTEM_FIXED_FONT: i32 = 16;
pub const DEFAULT_GUI_FONT: i32 = 17;
pub const DC_BRUSH: i32 = 18;
pub const DC_PEN: i32 = 19;

// Pen styles
pub const PS_SOLID: i32 = 0;
pub const PS_DASH: i32 = 1;
pub const PS_DOT: i32 = 2;
pub const PS_DASHDOT: i32 = 3;
pub const PS_DASHDOTDOT: i32 = 4;
pub const PS_NULL: i32 = 5;
pub const PS_INSIDEFRAME: i32 = 6;

// Brush styles
pub const BS_SOLID: i32 = 0;
pub const BS_NULL: i32 = 1;
pub const BS_HOLLOW: i32 = 1;
pub const BS_HATCHED: i32 = 2;
pub const BS_PATTERN: i32 = 3;

// Hatch styles
pub const HS_HORIZONTAL: i32 = 0;
pub const HS_VERTICAL: i32 = 1;
pub const HS_FDIAGONAL: i32 = 2;
pub const HS_BDIAGONAL: i32 = 3;
pub const HS_CROSS: i32 = 4;
pub const HS_DIAGCROSS: i32 = 5;

// Background modes
pub const TRANSPARENT: i32 = 1;
pub const OPAQUE: i32 = 2;

// Map modes
pub const MM_TEXT: i32 = 1;
pub const MM_LOMETRIC: i32 = 2;
pub const MM_HIMETRIC: i32 = 3;
pub const MM_LOENGLISH: i32 = 4;
pub const MM_HIENGLISH: i32 = 5;
pub const MM_TWIPS: i32 = 6;
pub const MM_ISOTROPIC: i32 = 7;
pub const MM_ANISOTROPIC: i32 = 8;

// Text alignment
pub const TA_NOUPDATECP: UINT = 0;
pub const TA_UPDATECP: UINT = 1;
pub const TA_LEFT: UINT = 0;
pub const TA_RIGHT: UINT = 2;
pub const TA_CENTER: UINT = 6;
pub const TA_TOP: UINT = 0;
pub const TA_BOTTOM: UINT = 8;
pub const TA_BASELINE: UINT = 24;

// Raster operations
pub const SRCCOPY: DWORD = 0x00CC0020;
pub const SRCPAINT: DWORD = 0x00EE0086;
pub const SRCAND: DWORD = 0x008800C6;
pub const SRCINVERT: DWORD = 0x00660046;
pub const SRCERASE: DWORD = 0x00440328;
pub const NOTSRCCOPY: DWORD = 0x00330008;
pub const NOTSRCERASE: DWORD = 0x001100A6;
pub const MERGECOPY: DWORD = 0x00C000CA;
pub const MERGEPAINT: DWORD = 0x00BB0226;
pub const PATCOPY: DWORD = 0x00F00021;
pub const PATPAINT: DWORD = 0x00FB0A09;
pub const PATINVERT: DWORD = 0x005A0049;
pub const DSTINVERT: DWORD = 0x00550009;
pub const BLACKNESS: DWORD = 0x00000042;
pub const WHITENESS: DWORD = 0x00FF0062;

// Region combine modes
pub const RGN_AND: i32 = 1;
pub const RGN_OR: i32 = 2;
pub const RGN_XOR: i32 = 3;
pub const RGN_DIFF: i32 = 4;
pub const RGN_COPY: i32 = 5;

// Region return values
pub const ERROR: i32 = 0;
pub const NULLREGION: i32 = 1;
pub const SIMPLEREGION: i32 = 2;
pub const COMPLEXREGION: i32 = 3;

// Device capabilities
pub const HORZSIZE: i32 = 4;
pub const VERTSIZE: i32 = 6;
pub const HORZRES: i32 = 8;
pub const VERTRES: i32 = 10;
pub const BITSPIXEL: i32 = 12;
pub const PLANES: i32 = 14;
pub const NUMBRUSHES: i32 = 16;
pub const NUMPENS: i32 = 18;
pub const NUMFONTS: i32 = 22;
pub const NUMCOLORS: i32 = 24;
pub const LOGPIXELSX: i32 = 88;
pub const LOGPIXELSY: i32 = 90;

// Font weights
pub const FW_DONTCARE: i32 = 0;
pub const FW_THIN: i32 = 100;
pub const FW_EXTRALIGHT: i32 = 200;
pub const FW_LIGHT: i32 = 300;
pub const FW_NORMAL: i32 = 400;
pub const FW_MEDIUM: i32 = 500;
pub const FW_SEMIBOLD: i32 = 600;
pub const FW_BOLD: i32 = 700;
pub const FW_EXTRABOLD: i32 = 800;
pub const FW_HEAVY: i32 = 900;

// Character sets
pub const ANSI_CHARSET: u8 = 0;
pub const DEFAULT_CHARSET: u8 = 1;
pub const SYMBOL_CHARSET: u8 = 2;
pub const OEM_CHARSET: u8 = 255;

// DIB color usage
pub const DIB_RGB_COLORS: UINT = 0;
pub const DIB_PAL_COLORS: UINT = 1;

// ============================================================================
// Device Context Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn CreateCompatibleDC(hdc: HDC) -> HDC {
    win32k_syscall(syscall::NtGdiCreateCompatibleDC, &[hdc])
}

#[no_mangle]
pub unsafe extern "system" fn DeleteDC(hdc: HDC) -> BOOL {
    win32k_syscall(syscall::NtGdiDeleteDC, &[hdc]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetDeviceCaps(hdc: HDC, index: i32) -> i32 {
    win32k_syscall(syscall::NtGdiGetDeviceCaps, &[hdc, index as u64]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn SaveDC(hdc: HDC) -> i32 {
    win32k_syscall(syscall::NtGdiSaveDC, &[hdc]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn RestoreDC(hdc: HDC, saved_dc: i32) -> BOOL {
    win32k_syscall(syscall::NtGdiRestoreDC, &[hdc, saved_dc as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn SetBkMode(hdc: HDC, mode: i32) -> i32 {
    win32k_syscall(syscall::NtGdiSetBkMode, &[hdc, mode as u64]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn GetBkMode(hdc: HDC) -> i32 {
    win32k_syscall(syscall::NtGdiGetBkMode, &[hdc]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn SetBkColor(hdc: HDC, color: COLORREF) -> COLORREF {
    win32k_syscall(syscall::NtGdiSetBkColor, &[hdc, color as u64]) as COLORREF
}

#[no_mangle]
pub unsafe extern "system" fn GetBkColor(hdc: HDC) -> COLORREF {
    win32k_syscall(syscall::NtGdiGetBkColor, &[hdc]) as COLORREF
}

#[no_mangle]
pub unsafe extern "system" fn SetTextColor(hdc: HDC, color: COLORREF) -> COLORREF {
    win32k_syscall(syscall::NtGdiSetTextColor, &[hdc, color as u64]) as COLORREF
}

#[no_mangle]
pub unsafe extern "system" fn GetTextColor(hdc: HDC) -> COLORREF {
    win32k_syscall(syscall::NtGdiGetTextColor, &[hdc]) as COLORREF
}

#[no_mangle]
pub unsafe extern "system" fn SetMapMode(hdc: HDC, mode: i32) -> i32 {
    win32k_syscall(syscall::NtGdiSetMapMode, &[hdc, mode as u64]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn GetMapMode(hdc: HDC) -> i32 {
    win32k_syscall(syscall::NtGdiGetMapMode, &[hdc]) as i32
}

// ============================================================================
// Object Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn SelectObject(hdc: HDC, obj: HGDIOBJ) -> HGDIOBJ {
    win32k_syscall(syscall::NtGdiSelectObject, &[hdc, obj])
}

#[no_mangle]
pub unsafe extern "system" fn GetObjectA(obj: HGDIOBJ, size: i32, buf: *mut u8) -> i32 {
    win32k_syscall(syscall::NtGdiGetObject, &[obj, size as u64, buf as u64, 0]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn GetObjectW(obj: HGDIOBJ, size: i32, buf: *mut u8) -> i32 {
    win32k_syscall(syscall::NtGdiGetObject, &[obj, size as u64, buf as u64, 1]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn DeleteObject(obj: HGDIOBJ) -> BOOL {
    win32k_syscall(syscall::NtGdiDeleteObject, &[obj]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetStockObject(index: i32) -> HGDIOBJ {
    win32k_syscall(syscall::NtGdiGetStockObject, &[index as u64])
}

#[no_mangle]
pub unsafe extern "system" fn GetCurrentObject(hdc: HDC, obj_type: UINT) -> HGDIOBJ {
    win32k_syscall(syscall::NtGdiGetCurrentObject, &[hdc, obj_type as u64])
}

// ============================================================================
// Pen Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn CreatePen(style: i32, width: i32, color: COLORREF) -> HPEN {
    win32k_syscall(syscall::NtGdiCreatePen, &[style as u64, width as u64, color as u64])
}

// ============================================================================
// Brush Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn CreateSolidBrush(color: COLORREF) -> HBRUSH {
    win32k_syscall(syscall::NtGdiCreateSolidBrush, &[color as u64])
}

#[no_mangle]
pub unsafe extern "system" fn CreateHatchBrush(style: i32, color: COLORREF) -> HBRUSH {
    win32k_syscall(syscall::NtGdiCreateHatchBrush, &[style as u64, color as u64])
}

#[no_mangle]
pub unsafe extern "system" fn CreatePatternBrush(bitmap: HBITMAP) -> HBRUSH {
    win32k_syscall(syscall::NtGdiCreatePatternBrush, &[bitmap])
}

// ============================================================================
// Bitmap Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn CreateBitmap(width: i32, height: i32, planes: UINT, bpp: UINT, bits: *const u8) -> HBITMAP {
    win32k_syscall(syscall::NtGdiCreateBitmap, &[width as u64, height as u64, planes as u64, bpp as u64, bits as u64])
}

#[no_mangle]
pub unsafe extern "system" fn CreateCompatibleBitmap(hdc: HDC, width: i32, height: i32) -> HBITMAP {
    win32k_syscall(syscall::NtGdiCreateCompatibleBitmap, &[hdc, width as u64, height as u64])
}

#[no_mangle]
pub unsafe extern "system" fn CreateDIBSection(
    hdc: HDC,
    bmi: *const BITMAPINFO,
    usage: UINT,
    bits: *mut *mut u8,
    section: u64,
    offset: DWORD,
) -> HBITMAP {
    win32k_syscall(syscall::NtGdiCreateDIBSection, &[hdc, bmi as u64, usage as u64, bits as u64, section, offset as u64])
}

#[no_mangle]
pub unsafe extern "system" fn GetDIBits(
    hdc: HDC,
    bitmap: HBITMAP,
    start: UINT,
    lines: UINT,
    bits: *mut u8,
    bmi: *mut BITMAPINFO,
    usage: UINT,
) -> i32 {
    win32k_syscall(syscall::NtGdiGetDIBits, &[hdc, bitmap, start as u64, lines as u64, bits as u64, bmi as u64]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn SetDIBits(
    hdc: HDC,
    bitmap: HBITMAP,
    start: UINT,
    lines: UINT,
    bits: *const u8,
    bmi: *const BITMAPINFO,
    usage: UINT,
) -> i32 {
    win32k_syscall(syscall::NtGdiSetDIBits, &[hdc, bitmap, start as u64, lines as u64, bits as u64, bmi as u64]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn BitBlt(
    dest: HDC,
    x_dest: i32,
    y_dest: i32,
    width: i32,
    height: i32,
    src: HDC,
    x_src: i32,
    y_src: i32,
    rop: DWORD,
) -> BOOL {
    let params: [u64; 9] = [
        dest, x_dest as u64, y_dest as u64, width as u64, height as u64,
        src, x_src as u64, y_src as u64, rop as u64,
    ];
    win32k_syscall(syscall::NtGdiBitBlt, &[params.as_ptr() as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn StretchBlt(
    dest: HDC,
    x_dest: i32,
    y_dest: i32,
    w_dest: i32,
    h_dest: i32,
    src: HDC,
    x_src: i32,
    y_src: i32,
    w_src: i32,
    h_src: i32,
    rop: DWORD,
) -> BOOL {
    let params: [u64; 11] = [
        dest, x_dest as u64, y_dest as u64, w_dest as u64, h_dest as u64,
        src, x_src as u64, y_src as u64, w_src as u64, h_src as u64, rop as u64,
    ];
    win32k_syscall(syscall::NtGdiStretchBlt, &[params.as_ptr() as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn PatBlt(hdc: HDC, x: i32, y: i32, w: i32, h: i32, rop: DWORD) -> BOOL {
    win32k_syscall(syscall::NtGdiPatBlt, &[hdc, x as u64, y as u64, w as u64, h as u64, rop as u64]) as BOOL
}

// ============================================================================
// Drawing Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn MoveToEx(hdc: HDC, x: i32, y: i32, point: *mut POINT) -> BOOL {
    win32k_syscall(syscall::NtGdiMoveTo, &[hdc, x as u64, y as u64, point as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn LineTo(hdc: HDC, x: i32, y: i32) -> BOOL {
    win32k_syscall(syscall::NtGdiLineTo, &[hdc, x as u64, y as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn Polyline(hdc: HDC, points: *const POINT, count: i32) -> BOOL {
    win32k_syscall(syscall::NtGdiPolyline, &[hdc, points as u64, count as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn PolylineTo(hdc: HDC, points: *const POINT, count: DWORD) -> BOOL {
    win32k_syscall(syscall::NtGdiPolylineTo, &[hdc, points as u64, count as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn Polygon(hdc: HDC, points: *const POINT, count: i32) -> BOOL {
    win32k_syscall(syscall::NtGdiPolygon, &[hdc, points as u64, count as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn Rectangle(hdc: HDC, left: i32, top: i32, right: i32, bottom: i32) -> BOOL {
    win32k_syscall(syscall::NtGdiRectangle, &[hdc, left as u64, top as u64, right as u64, bottom as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn RoundRect(hdc: HDC, left: i32, top: i32, right: i32, bottom: i32, width: i32, height: i32) -> BOOL {
    let params: [u64; 7] = [hdc, left as u64, top as u64, right as u64, bottom as u64, width as u64, height as u64];
    win32k_syscall(syscall::NtGdiRoundRect, &params) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn Ellipse(hdc: HDC, left: i32, top: i32, right: i32, bottom: i32) -> BOOL {
    win32k_syscall(syscall::NtGdiEllipse, &[hdc, left as u64, top as u64, right as u64, bottom as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn Arc(
    hdc: HDC,
    left: i32, top: i32, right: i32, bottom: i32,
    x_start: i32, y_start: i32, x_end: i32, y_end: i32,
) -> BOOL {
    let params: [u64; 9] = [hdc, left as u64, top as u64, right as u64, bottom as u64, x_start as u64, y_start as u64, x_end as u64, y_end as u64];
    win32k_syscall(syscall::NtGdiArc, &[params.as_ptr() as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn Pie(
    hdc: HDC,
    left: i32, top: i32, right: i32, bottom: i32,
    x_start: i32, y_start: i32, x_end: i32, y_end: i32,
) -> BOOL {
    let params: [u64; 9] = [hdc, left as u64, top as u64, right as u64, bottom as u64, x_start as u64, y_start as u64, x_end as u64, y_end as u64];
    win32k_syscall(syscall::NtGdiPie, &[params.as_ptr() as u64]) as BOOL
}

// ============================================================================
// Fill Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn FillRect(hdc: HDC, rect: *const RECT, brush: HBRUSH) -> i32 {
    win32k_syscall(syscall::NtGdiFillRect, &[hdc, rect as u64, brush]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn FrameRect(hdc: HDC, rect: *const RECT, brush: HBRUSH) -> i32 {
    win32k_syscall(syscall::NtGdiFrameRect, &[hdc, rect as u64, brush]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn InvertRect(hdc: HDC, rect: *const RECT) -> BOOL {
    win32k_syscall(syscall::NtGdiInvertRect, &[hdc, rect as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn SetPixel(hdc: HDC, x: i32, y: i32, color: COLORREF) -> COLORREF {
    win32k_syscall(syscall::NtGdiSetPixel, &[hdc, x as u64, y as u64, color as u64]) as COLORREF
}

#[no_mangle]
pub unsafe extern "system" fn GetPixel(hdc: HDC, x: i32, y: i32) -> COLORREF {
    win32k_syscall(syscall::NtGdiGetPixel, &[hdc, x as u64, y as u64]) as COLORREF
}

#[no_mangle]
pub unsafe extern "system" fn FloodFill(hdc: HDC, x: i32, y: i32, color: COLORREF) -> BOOL {
    win32k_syscall(syscall::NtGdiFloodFill, &[hdc, x as u64, y as u64, color as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn ExtFloodFill(hdc: HDC, x: i32, y: i32, color: COLORREF, fill_type: UINT) -> BOOL {
    win32k_syscall(syscall::NtGdiExtFloodFill, &[hdc, x as u64, y as u64, color as u64, fill_type as u64]) as BOOL
}

// ============================================================================
// Region Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn CreateRectRgn(left: i32, top: i32, right: i32, bottom: i32) -> HRGN {
    win32k_syscall(syscall::NtGdiCreateRectRgn, &[left as u64, top as u64, right as u64, bottom as u64])
}

#[no_mangle]
pub unsafe extern "system" fn CreateRectRgnIndirect(rect: *const RECT) -> HRGN {
    let r = &*rect;
    win32k_syscall(syscall::NtGdiCreateRectRgn, &[r.left as u64, r.top as u64, r.right as u64, r.bottom as u64])
}

#[no_mangle]
pub unsafe extern "system" fn CreateEllipticRgn(left: i32, top: i32, right: i32, bottom: i32) -> HRGN {
    win32k_syscall(syscall::NtGdiCreateEllipticRgn, &[left as u64, top as u64, right as u64, bottom as u64])
}

#[no_mangle]
pub unsafe extern "system" fn CreatePolygonRgn(points: *const POINT, count: i32, fill_mode: i32) -> HRGN {
    win32k_syscall(syscall::NtGdiCreatePolygonRgn, &[points as u64, count as u64, fill_mode as u64])
}

#[no_mangle]
pub unsafe extern "system" fn CombineRgn(dest: HRGN, src1: HRGN, src2: HRGN, mode: i32) -> i32 {
    win32k_syscall(syscall::NtGdiCombineRgn, &[dest, src1, src2, mode as u64]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn SelectClipRgn(hdc: HDC, rgn: HRGN) -> i32 {
    win32k_syscall(syscall::NtGdiSelectClipRgn, &[hdc, rgn]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn GetClipRgn(hdc: HDC, rgn: HRGN) -> i32 {
    win32k_syscall(syscall::NtGdiGetClipRgn, &[hdc, rgn]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn PtInRegion(rgn: HRGN, x: i32, y: i32) -> BOOL {
    win32k_syscall(syscall::NtGdiPtInRegion, &[rgn, x as u64, y as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn RectInRegion(rgn: HRGN, rect: *const RECT) -> BOOL {
    win32k_syscall(syscall::NtGdiRectInRegion, &[rgn, rect as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetRgnBox(rgn: HRGN, rect: *mut RECT) -> i32 {
    win32k_syscall(syscall::NtGdiGetRgnBox, &[rgn, rect as u64]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn OffsetRgn(rgn: HRGN, x: i32, y: i32) -> i32 {
    win32k_syscall(syscall::NtGdiOffsetRgn, &[rgn, x as u64, y as u64]) as i32
}

// ============================================================================
// Font Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn CreateFontA(
    height: i32, width: i32, escapement: i32, orientation: i32, weight: i32,
    italic: DWORD, underline: DWORD, strike_out: DWORD, char_set: DWORD,
    out_prec: DWORD, clip_prec: DWORD, quality: DWORD, pitch_and_family: DWORD,
    face_name: *const u8,
) -> HFONT {
    let params: [u64; 14] = [
        height as u64, width as u64, escapement as u64, orientation as u64, weight as u64,
        italic as u64, underline as u64, strike_out as u64, char_set as u64,
        out_prec as u64, clip_prec as u64, quality as u64, pitch_and_family as u64,
        face_name as u64,
    ];
    win32k_syscall(syscall::NtGdiCreateFontA, &[params.as_ptr() as u64])
}

#[no_mangle]
pub unsafe extern "system" fn CreateFontW(
    height: i32, width: i32, escapement: i32, orientation: i32, weight: i32,
    italic: DWORD, underline: DWORD, strike_out: DWORD, char_set: DWORD,
    out_prec: DWORD, clip_prec: DWORD, quality: DWORD, pitch_and_family: DWORD,
    face_name: *const u16,
) -> HFONT {
    let params: [u64; 14] = [
        height as u64, width as u64, escapement as u64, orientation as u64, weight as u64,
        italic as u64, underline as u64, strike_out as u64, char_set as u64,
        out_prec as u64, clip_prec as u64, quality as u64, pitch_and_family as u64,
        face_name as u64,
    ];
    win32k_syscall(syscall::NtGdiCreateFontW, &[params.as_ptr() as u64])
}

#[no_mangle]
pub unsafe extern "system" fn CreateFontIndirectA(lf: *const LOGFONTA) -> HFONT {
    win32k_syscall(syscall::NtGdiCreateFontIndirectA, &[lf as u64])
}

#[no_mangle]
pub unsafe extern "system" fn CreateFontIndirectW(lf: *const LOGFONTW) -> HFONT {
    win32k_syscall(syscall::NtGdiCreateFontIndirectW, &[lf as u64])
}

#[no_mangle]
pub unsafe extern "system" fn GetTextMetricsA(hdc: HDC, tm: *mut TEXTMETRICA) -> BOOL {
    win32k_syscall(syscall::NtGdiGetTextMetrics, &[hdc, tm as u64, 0]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetTextExtentPoint32A(hdc: HDC, text: *const u8, len: i32, size: *mut SIZE) -> BOOL {
    win32k_syscall(syscall::NtGdiGetTextExtentPoint, &[hdc, text as u64, len as u64, size as u64, 0]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetTextExtentPoint32W(hdc: HDC, text: *const u16, len: i32, size: *mut SIZE) -> BOOL {
    win32k_syscall(syscall::NtGdiGetTextExtentPoint, &[hdc, text as u64, len as u64, size as u64, 1]) as BOOL
}

// ============================================================================
// Text Output Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn TextOutA(hdc: HDC, x: i32, y: i32, text: *const u8, len: i32) -> BOOL {
    win32k_syscall(syscall::NtGdiTextOutA, &[hdc, x as u64, y as u64, text as u64, len as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn TextOutW(hdc: HDC, x: i32, y: i32, text: *const u16, len: i32) -> BOOL {
    win32k_syscall(syscall::NtGdiTextOutW, &[hdc, x as u64, y as u64, text as u64, len as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn ExtTextOutA(
    hdc: HDC, x: i32, y: i32, options: UINT,
    rect: *const RECT, text: *const u8, len: UINT, dx: *const i32,
) -> BOOL {
    let params: [u64; 8] = [hdc, x as u64, y as u64, options as u64, rect as u64, text as u64, len as u64, dx as u64];
    win32k_syscall(syscall::NtGdiExtTextOutA, &[params.as_ptr() as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn ExtTextOutW(
    hdc: HDC, x: i32, y: i32, options: UINT,
    rect: *const RECT, text: *const u16, len: UINT, dx: *const i32,
) -> BOOL {
    let params: [u64; 8] = [hdc, x as u64, y as u64, options as u64, rect as u64, text as u64, len as u64, dx as u64];
    win32k_syscall(syscall::NtGdiExtTextOutW, &[params.as_ptr() as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn DrawTextA(hdc: HDC, text: *const u8, len: i32, rect: *mut RECT, format: UINT) -> i32 {
    win32k_syscall(syscall::NtGdiDrawTextA, &[hdc, text as u64, len as u64, rect as u64, format as u64]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn DrawTextW(hdc: HDC, text: *const u16, len: i32, rect: *mut RECT, format: UINT) -> i32 {
    win32k_syscall(syscall::NtGdiDrawTextW, &[hdc, text as u64, len as u64, rect as u64, format as u64]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn SetTextAlign(hdc: HDC, align: UINT) -> UINT {
    win32k_syscall(syscall::NtGdiSetTextAlign, &[hdc, align as u64]) as UINT
}

#[no_mangle]
pub unsafe extern "system" fn GetTextAlign(hdc: HDC) -> UINT {
    win32k_syscall(syscall::NtGdiGetTextAlign, &[hdc]) as UINT
}

// ============================================================================
// Path Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn BeginPath(hdc: HDC) -> BOOL {
    win32k_syscall(syscall::NtGdiBeginPath, &[hdc]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn EndPath(hdc: HDC) -> BOOL {
    win32k_syscall(syscall::NtGdiEndPath, &[hdc]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CloseFigure(hdc: HDC) -> BOOL {
    win32k_syscall(syscall::NtGdiCloseFigure, &[hdc]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn StrokePath(hdc: HDC) -> BOOL {
    win32k_syscall(syscall::NtGdiStrokePath, &[hdc]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn FillPath(hdc: HDC) -> BOOL {
    win32k_syscall(syscall::NtGdiFillPath, &[hdc]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn StrokeAndFillPath(hdc: HDC) -> BOOL {
    win32k_syscall(syscall::NtGdiStrokeAndFillPath, &[hdc]) as BOOL
}

// ============================================================================
// Coordinate Transform Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn SetViewportOrgEx(hdc: HDC, x: i32, y: i32, point: *mut POINT) -> BOOL {
    win32k_syscall(syscall::NtGdiSetViewportOrgEx, &[hdc, x as u64, y as u64, point as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetViewportOrgEx(hdc: HDC, point: *mut POINT) -> BOOL {
    win32k_syscall(syscall::NtGdiGetViewportOrgEx, &[hdc, point as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn SetWindowOrgEx(hdc: HDC, x: i32, y: i32, point: *mut POINT) -> BOOL {
    win32k_syscall(syscall::NtGdiSetWindowOrgEx, &[hdc, x as u64, y as u64, point as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetWindowOrgEx(hdc: HDC, point: *mut POINT) -> BOOL {
    win32k_syscall(syscall::NtGdiGetWindowOrgEx, &[hdc, point as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn DPtoLP(hdc: HDC, points: *mut POINT, count: i32) -> BOOL {
    win32k_syscall(syscall::NtGdiDPtoLP, &[hdc, points as u64, count as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn LPtoDP(hdc: HDC, points: *mut POINT, count: i32) -> BOOL {
    win32k_syscall(syscall::NtGdiLPtoDP, &[hdc, points as u64, count as u64]) as BOOL
}

// ============================================================================
// Palette Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn SelectPalette(hdc: HDC, palette: HPALETTE, force_bg: BOOL) -> HPALETTE {
    win32k_syscall(syscall::NtGdiSelectPalette, &[hdc, palette, force_bg as u64])
}

#[no_mangle]
pub unsafe extern "system" fn RealizePalette(hdc: HDC) -> UINT {
    win32k_syscall(syscall::NtGdiRealizePalette, &[hdc]) as UINT
}

#[no_mangle]
pub unsafe extern "system" fn GetNearestColor(hdc: HDC, color: COLORREF) -> COLORREF {
    win32k_syscall(syscall::NtGdiGetNearestColor, &[hdc, color as u64]) as COLORREF
}

// ============================================================================
// Module initialization
// ============================================================================

/// Initialize the gdi32 stub module
pub fn init() {
    crate::serial_println!("[GDI32] Initializing gdi32.dll stub...");
}

/// Get the address of an exported function
pub fn get_export(name: &str) -> Option<u64> {
    let addr: u64 = match name {
        // DC
        "CreateCompatibleDC" => CreateCompatibleDC as usize as u64,
        "DeleteDC" => DeleteDC as usize as u64,
        "GetDeviceCaps" => GetDeviceCaps as usize as u64,
        "SaveDC" => SaveDC as usize as u64,
        "RestoreDC" => RestoreDC as usize as u64,
        "SetBkMode" => SetBkMode as usize as u64,
        "GetBkMode" => GetBkMode as usize as u64,
        "SetBkColor" => SetBkColor as usize as u64,
        "GetBkColor" => GetBkColor as usize as u64,
        "SetTextColor" => SetTextColor as usize as u64,
        "GetTextColor" => GetTextColor as usize as u64,
        "SetMapMode" => SetMapMode as usize as u64,
        "GetMapMode" => GetMapMode as usize as u64,
        // Objects
        "SelectObject" => SelectObject as usize as u64,
        "GetObjectA" => GetObjectA as usize as u64,
        "GetObjectW" => GetObjectW as usize as u64,
        "DeleteObject" => DeleteObject as usize as u64,
        "GetStockObject" => GetStockObject as usize as u64,
        "GetCurrentObject" => GetCurrentObject as usize as u64,
        // Pens
        "CreatePen" => CreatePen as usize as u64,
        // Brushes
        "CreateSolidBrush" => CreateSolidBrush as usize as u64,
        "CreateHatchBrush" => CreateHatchBrush as usize as u64,
        "CreatePatternBrush" => CreatePatternBrush as usize as u64,
        // Bitmaps
        "CreateBitmap" => CreateBitmap as usize as u64,
        "CreateCompatibleBitmap" => CreateCompatibleBitmap as usize as u64,
        "CreateDIBSection" => CreateDIBSection as usize as u64,
        "GetDIBits" => GetDIBits as usize as u64,
        "SetDIBits" => SetDIBits as usize as u64,
        "BitBlt" => BitBlt as usize as u64,
        "StretchBlt" => StretchBlt as usize as u64,
        "PatBlt" => PatBlt as usize as u64,
        // Drawing
        "MoveToEx" => MoveToEx as usize as u64,
        "LineTo" => LineTo as usize as u64,
        "Polyline" => Polyline as usize as u64,
        "PolylineTo" => PolylineTo as usize as u64,
        "Polygon" => Polygon as usize as u64,
        "Rectangle" => Rectangle as usize as u64,
        "RoundRect" => RoundRect as usize as u64,
        "Ellipse" => Ellipse as usize as u64,
        "Arc" => Arc as usize as u64,
        "Pie" => Pie as usize as u64,
        // Fill
        "FillRect" => FillRect as usize as u64,
        "FrameRect" => FrameRect as usize as u64,
        "InvertRect" => InvertRect as usize as u64,
        "SetPixel" => SetPixel as usize as u64,
        "GetPixel" => GetPixel as usize as u64,
        "FloodFill" => FloodFill as usize as u64,
        "ExtFloodFill" => ExtFloodFill as usize as u64,
        // Regions
        "CreateRectRgn" => CreateRectRgn as usize as u64,
        "CreateRectRgnIndirect" => CreateRectRgnIndirect as usize as u64,
        "CreateEllipticRgn" => CreateEllipticRgn as usize as u64,
        "CreatePolygonRgn" => CreatePolygonRgn as usize as u64,
        "CombineRgn" => CombineRgn as usize as u64,
        "SelectClipRgn" => SelectClipRgn as usize as u64,
        "GetClipRgn" => GetClipRgn as usize as u64,
        "PtInRegion" => PtInRegion as usize as u64,
        "RectInRegion" => RectInRegion as usize as u64,
        "GetRgnBox" => GetRgnBox as usize as u64,
        "OffsetRgn" => OffsetRgn as usize as u64,
        // Fonts
        "CreateFontA" => CreateFontA as usize as u64,
        "CreateFontW" => CreateFontW as usize as u64,
        "CreateFontIndirectA" => CreateFontIndirectA as usize as u64,
        "CreateFontIndirectW" => CreateFontIndirectW as usize as u64,
        "GetTextMetricsA" => GetTextMetricsA as usize as u64,
        "GetTextExtentPoint32A" => GetTextExtentPoint32A as usize as u64,
        "GetTextExtentPoint32W" => GetTextExtentPoint32W as usize as u64,
        // Text
        "TextOutA" => TextOutA as usize as u64,
        "TextOutW" => TextOutW as usize as u64,
        "ExtTextOutA" => ExtTextOutA as usize as u64,
        "ExtTextOutW" => ExtTextOutW as usize as u64,
        "DrawTextA" => DrawTextA as usize as u64,
        "DrawTextW" => DrawTextW as usize as u64,
        "SetTextAlign" => SetTextAlign as usize as u64,
        "GetTextAlign" => GetTextAlign as usize as u64,
        // Paths
        "BeginPath" => BeginPath as usize as u64,
        "EndPath" => EndPath as usize as u64,
        "CloseFigure" => CloseFigure as usize as u64,
        "StrokePath" => StrokePath as usize as u64,
        "FillPath" => FillPath as usize as u64,
        "StrokeAndFillPath" => StrokeAndFillPath as usize as u64,
        // Coordinate transforms
        "SetViewportOrgEx" => SetViewportOrgEx as usize as u64,
        "GetViewportOrgEx" => GetViewportOrgEx as usize as u64,
        "SetWindowOrgEx" => SetWindowOrgEx as usize as u64,
        "GetWindowOrgEx" => GetWindowOrgEx as usize as u64,
        "DPtoLP" => DPtoLP as usize as u64,
        "LPtoDP" => LPtoDP as usize as u64,
        // Palette
        "SelectPalette" => SelectPalette as usize as u64,
        "RealizePalette" => RealizePalette as usize as u64,
        "GetNearestColor" => GetNearestColor as usize as u64,
        _ => return None,
    };
    Some(addr)
}
