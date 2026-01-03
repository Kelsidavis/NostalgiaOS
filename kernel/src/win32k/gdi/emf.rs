//! Enhanced Metafile (EMF) Support
//!
//! Enhanced Metafiles are a device-independent format for storing
//! GDI commands that can be played back on any device.
//!
//! # Structure
//!
//! An EMF consists of:
//! - Header: File information and bounds
//! - Records: GDI commands in order
//! - EOF record: End of file marker
//!
//! # Operations
//!
//! - **CreateEnhMetaFile**: Begin recording
//! - **CloseEnhMetaFile**: Stop recording, get metafile handle
//! - **PlayEnhMetaFile**: Play back recorded commands
//! - **GetEnhMetaFile**: Load from memory/file
//! - **DeleteEnhMetaFile**: Free metafile resources
//!
//! # References
//!
//! Based on Windows Server 2003:
//! - `windows/core/ntgdi/gre/metafile.cxx` - Metafile support

extern crate alloc;

use super::super::{GdiHandle, GdiObjectType, ColorRef, Point, Rect};
use super::dc;
use crate::ke::spinlock::SpinLock;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::BTreeMap;

// ============================================================================
// EMF Constants
// ============================================================================

/// EMF signature
pub const EMF_SIGNATURE: u32 = 0x464D4520; // " EMF"

/// EMF version
pub const EMF_VERSION: u32 = 0x00010000;

/// Maximum EMF record size
pub const MAX_RECORD_SIZE: usize = 0x100000; // 1 MB

// ============================================================================
// EMF Record Types
// ============================================================================

/// EMF record types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmfRecordType {
    /// Header record
    Header = 1,
    /// PolyBezier
    PolyBezier = 2,
    /// Polygon
    Polygon = 3,
    /// Polyline
    Polyline = 4,
    /// PolyBezierTo
    PolyBezierTo = 5,
    /// PolylineTo
    PolylineTo = 6,
    /// PolyPolyline
    PolyPolyline = 7,
    /// PolyPolygon
    PolyPolygon = 8,
    /// SetWindowExtEx
    SetWindowExtEx = 9,
    /// SetWindowOrgEx
    SetWindowOrgEx = 10,
    /// SetViewportExtEx
    SetViewportExtEx = 11,
    /// SetViewportOrgEx
    SetViewportOrgEx = 12,
    /// SetBrushOrgEx
    SetBrushOrgEx = 13,
    /// EOF
    Eof = 14,
    /// SetPixelV
    SetPixelV = 15,
    /// SetMapperFlags
    SetMapperFlags = 16,
    /// SetMapMode
    SetMapMode = 17,
    /// SetBkMode
    SetBkMode = 18,
    /// SetPolyfillMode
    SetPolyfillMode = 19,
    /// SetRop2
    SetRop2 = 20,
    /// SetStretchBltMode
    SetStretchBltMode = 21,
    /// SetTextAlign
    SetTextAlign = 22,
    /// SetColorAdjustment
    SetColorAdjustment = 23,
    /// SetTextColor
    SetTextColor = 24,
    /// SetBkColor
    SetBkColor = 25,
    /// OffsetClipRgn
    OffsetClipRgn = 26,
    /// MoveToEx
    MoveToEx = 27,
    /// SetMetaRgn
    SetMetaRgn = 28,
    /// ExcludeClipRect
    ExcludeClipRect = 29,
    /// IntersectClipRect
    IntersectClipRect = 30,
    /// ScaleViewportExtEx
    ScaleViewportExtEx = 31,
    /// ScaleWindowExtEx
    ScaleWindowExtEx = 32,
    /// SaveDC
    SaveDc = 33,
    /// RestoreDC
    RestoreDc = 34,
    /// SetWorldTransform
    SetWorldTransform = 35,
    /// ModifyWorldTransform
    ModifyWorldTransform = 36,
    /// SelectObject
    SelectObject = 37,
    /// CreatePen
    CreatePen = 38,
    /// CreateBrushIndirect
    CreateBrushIndirect = 39,
    /// DeleteObject
    DeleteObject = 40,
    /// AngleArc
    AngleArc = 41,
    /// Ellipse
    Ellipse = 42,
    /// Rectangle
    Rectangle = 43,
    /// RoundRect
    RoundRect = 44,
    /// Arc
    Arc = 45,
    /// Chord
    Chord = 46,
    /// Pie
    Pie = 47,
    /// SelectPalette
    SelectPalette = 48,
    /// CreatePalette
    CreatePalette = 49,
    /// SetPaletteEntries
    SetPaletteEntries = 50,
    /// ResizePalette
    ResizePalette = 51,
    /// RealizePalette
    RealizePalette = 52,
    /// ExtFloodFill
    ExtFloodFill = 53,
    /// LineTo
    LineTo = 54,
    /// ArcTo
    ArcTo = 55,
    /// PolyDraw
    PolyDraw = 56,
    /// SetArcDirection
    SetArcDirection = 57,
    /// SetMiterLimit
    SetMiterLimit = 58,
    /// BeginPath
    BeginPath = 59,
    /// EndPath
    EndPath = 60,
    /// CloseFigure
    CloseFigure = 61,
    /// FillPath
    FillPath = 62,
    /// StrokeAndFillPath
    StrokeAndFillPath = 63,
    /// StrokePath
    StrokePath = 64,
    /// FlattenPath
    FlattenPath = 65,
    /// WidenPath
    WidenPath = 66,
    /// SelectClipPath
    SelectClipPath = 67,
    /// AbortPath
    AbortPath = 68,
    /// GdiComment = 70
    GdiComment = 70,
    /// FillRgn
    FillRgn = 71,
    /// FrameRgn
    FrameRgn = 72,
    /// InvertRgn
    InvertRgn = 73,
    /// PaintRgn
    PaintRgn = 74,
    /// ExtSelectClipRgn
    ExtSelectClipRgn = 75,
    /// BitBlt
    BitBlt = 76,
    /// StretchBlt
    StretchBlt = 77,
    /// MaskBlt
    MaskBlt = 78,
    /// PlgBlt
    PlgBlt = 79,
    /// SetDIBitsToDevice
    SetDibitsToDevice = 80,
    /// StretchDIBits
    StretchDibits = 81,
    /// ExtCreateFontIndirectW
    ExtCreateFontIndirectW = 82,
    /// ExtTextOutA
    ExtTextOutA = 83,
    /// ExtTextOutW
    ExtTextOutW = 84,
    /// PolyBezier16
    PolyBezier16 = 85,
    /// Polygon16
    Polygon16 = 86,
    /// Polyline16
    Polyline16 = 87,
    /// PolyBezierTo16
    PolyBezierTo16 = 88,
    /// PolylineTo16
    PolylineTo16 = 89,
    /// PolyPolyline16
    PolyPolyline16 = 90,
    /// PolyPolygon16
    PolyPolygon16 = 91,
    /// PolyDraw16
    PolyDraw16 = 92,
    /// CreateMonoBrush
    CreateMonoBrush = 93,
    /// CreateDIBPatternBrushPt
    CreateDibPatternBrushPt = 94,
    /// ExtCreatePen
    ExtCreatePen = 95,
    /// PolyTextOutA
    PolyTextOutA = 96,
    /// PolyTextOutW
    PolyTextOutW = 97,
    /// SetICMMode
    SetIcmMode = 98,
    /// CreateColorSpace
    CreateColorSpace = 99,
    /// SetColorSpace
    SetColorSpace = 100,
    /// DeleteColorSpace
    DeleteColorSpace = 101,
    /// GlsRecord
    GlsRecord = 102,
    /// GlsBoundedRecord
    GlsBoundedRecord = 103,
    /// PixelFormat
    PixelFormat = 104,
    /// DrawEscape
    DrawEscape = 105,
    /// ExtEscape
    ExtEscape = 106,
    /// StartDoc
    StartDoc = 107,
    /// SmallTextOut
    SmallTextOut = 108,
    /// ForceUFIMapping
    ForceUfiMapping = 109,
    /// NamedEscape
    NamedEscape = 110,
    /// ColorCorrectPalette
    ColorCorrectPalette = 111,
    /// SetICMProfileA
    SetIcmProfileA = 112,
    /// SetICMProfileW
    SetIcmProfileW = 113,
    /// AlphaBlend
    AlphaBlend = 114,
    /// SetLayout
    SetLayout = 115,
    /// TransparentBlt
    TransparentBlt = 116,
    /// GradientFill
    GradientFill = 118,
    /// SetLinkedUFIs
    SetLinkedUfis = 119,
    /// SetTextJustification
    SetTextJustification = 120,
    /// ColorMatchToTargetW
    ColorMatchToTargetW = 121,
    /// CreateColorSpaceW
    CreateColorSpaceW = 122,
}

// ============================================================================
// EMF Structures
// ============================================================================

/// EMF header
#[derive(Debug, Clone)]
#[repr(C)]
pub struct EmfHeader {
    /// Record type (EMR_HEADER)
    pub record_type: u32,
    /// Record size
    pub record_size: u32,
    /// Bounds rectangle
    pub bounds_left: i32,
    pub bounds_top: i32,
    pub bounds_right: i32,
    pub bounds_bottom: i32,
    /// Frame rectangle (0.01mm units)
    pub frame_left: i32,
    pub frame_top: i32,
    pub frame_right: i32,
    pub frame_bottom: i32,
    /// Signature (EMF_SIGNATURE)
    pub signature: u32,
    /// Version
    pub version: u32,
    /// Total file size in bytes
    pub file_size: u32,
    /// Number of records
    pub record_count: u32,
    /// Number of handles
    pub handle_count: u16,
    /// Reserved
    pub reserved: u16,
    /// Description string length
    pub description_length: u32,
    /// Description string offset
    pub description_offset: u32,
    /// Number of palette entries
    pub palette_entries: u32,
    /// Reference device pixels
    pub device_width_pixels: i32,
    pub device_height_pixels: i32,
    /// Reference device millimeters
    pub device_width_mm: i32,
    pub device_height_mm: i32,
    /// Pixel format size (0 if none)
    pub pixel_format_size: u32,
    /// Pixel format offset
    pub pixel_format_offset: u32,
    /// OpenGL flag
    pub opengl_present: u32,
    /// Micrometers
    pub device_width_um: i32,
    pub device_height_um: i32,
}

impl Default for EmfHeader {
    fn default() -> Self {
        Self {
            record_type: EmfRecordType::Header as u32,
            record_size: core::mem::size_of::<Self>() as u32,
            bounds_left: 0,
            bounds_top: 0,
            bounds_right: 0,
            bounds_bottom: 0,
            frame_left: 0,
            frame_top: 0,
            frame_right: 0,
            frame_bottom: 0,
            signature: EMF_SIGNATURE,
            version: EMF_VERSION,
            file_size: 0,
            record_count: 1,
            handle_count: 0,
            reserved: 0,
            description_length: 0,
            description_offset: 0,
            palette_entries: 0,
            device_width_pixels: 1024,
            device_height_pixels: 768,
            device_width_mm: 320,
            device_height_mm: 240,
            pixel_format_size: 0,
            pixel_format_offset: 0,
            opengl_present: 0,
            device_width_um: 320000,
            device_height_um: 240000,
        }
    }
}

/// Generic EMF record
#[derive(Debug, Clone)]
#[repr(C)]
pub struct EmfRecord {
    /// Record type
    pub record_type: u32,
    /// Record size (including this header)
    pub record_size: u32,
    /// Record data
    pub data: Vec<u8>,
}

impl EmfRecord {
    /// Create a new record
    pub fn new(record_type: EmfRecordType) -> Self {
        Self {
            record_type: record_type as u32,
            record_size: 8, // Header only
            data: Vec::new(),
        }
    }

    /// Create a record with data
    pub fn with_data(record_type: EmfRecordType, data: Vec<u8>) -> Self {
        let size = 8 + data.len() as u32;
        // Align to DWORD boundary
        let aligned_size = (size + 3) & !3;
        Self {
            record_type: record_type as u32,
            record_size: aligned_size,
            data,
        }
    }
}

/// Enhanced Metafile
pub struct EnhMetaFile {
    /// Handle
    pub handle: GdiHandle,
    /// Header
    pub header: EmfHeader,
    /// Records
    pub records: Vec<EmfRecord>,
    /// Description
    pub description: String,
}

impl EnhMetaFile {
    /// Create a new empty metafile
    pub fn new(handle: GdiHandle) -> Self {
        Self {
            handle,
            header: EmfHeader::default(),
            records: Vec::new(),
            description: String::new(),
        }
    }

    /// Add a record
    pub fn add_record(&mut self, record: EmfRecord) {
        self.header.record_count += 1;
        self.header.file_size += record.record_size;
        self.records.push(record);
    }

    /// Update bounds rectangle
    pub fn update_bounds(&mut self, x: i32, y: i32) {
        if x < self.header.bounds_left {
            self.header.bounds_left = x;
        }
        if x > self.header.bounds_right {
            self.header.bounds_right = x;
        }
        if y < self.header.bounds_top {
            self.header.bounds_top = y;
        }
        if y > self.header.bounds_bottom {
            self.header.bounds_bottom = y;
        }
    }

    /// Get total size
    pub fn size(&self) -> usize {
        core::mem::size_of::<EmfHeader>()
            + self.records.iter().map(|r| r.record_size as usize).sum::<usize>()
            + 8 // EOF record
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.size());

        // Header (simplified - in real impl would use proper serialization)
        result.extend_from_slice(&self.header.record_type.to_le_bytes());
        result.extend_from_slice(&self.header.record_size.to_le_bytes());
        result.extend_from_slice(&self.header.bounds_left.to_le_bytes());
        result.extend_from_slice(&self.header.bounds_top.to_le_bytes());
        result.extend_from_slice(&self.header.bounds_right.to_le_bytes());
        result.extend_from_slice(&self.header.bounds_bottom.to_le_bytes());
        result.extend_from_slice(&self.header.signature.to_le_bytes());
        result.extend_from_slice(&self.header.version.to_le_bytes());
        // ... (other header fields)

        // Records
        for record in &self.records {
            result.extend_from_slice(&record.record_type.to_le_bytes());
            result.extend_from_slice(&record.record_size.to_le_bytes());
            result.extend_from_slice(&record.data);
            // Padding to DWORD boundary
            let padding = (4 - (record.data.len() % 4)) % 4;
            for _ in 0..padding {
                result.push(0);
            }
        }

        // EOF record
        result.extend_from_slice(&(EmfRecordType::Eof as u32).to_le_bytes());
        result.extend_from_slice(&20u32.to_le_bytes()); // Size
        result.extend_from_slice(&0u32.to_le_bytes()); // nPalEntries
        result.extend_from_slice(&0u32.to_le_bytes()); // offPalEntries
        result.extend_from_slice(&(self.size() as u32).to_le_bytes()); // nSizeLast

        result
    }
}

/// Metafile DC for recording
pub struct MetafileDc {
    /// DC handle
    pub dc_handle: GdiHandle,
    /// Metafile being recorded
    pub metafile: EnhMetaFile,
    /// Reference DC
    pub reference_dc: GdiHandle,
    /// Current pen handle index
    pub current_pen: u32,
    /// Current brush handle index
    pub current_brush: u32,
    /// Created object handles
    pub object_handles: Vec<u32>,
}

impl MetafileDc {
    /// Create a new metafile DC
    pub fn new(dc_handle: GdiHandle, mf_handle: GdiHandle, reference_dc: GdiHandle) -> Self {
        Self {
            dc_handle,
            metafile: EnhMetaFile::new(mf_handle),
            reference_dc,
            current_pen: 0,
            current_brush: 0,
            object_handles: Vec::new(),
        }
    }

    /// Record a MoveTo operation
    pub fn record_move_to(&mut self, x: i32, y: i32) {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&x.to_le_bytes());
        data.extend_from_slice(&y.to_le_bytes());

        let record = EmfRecord::with_data(EmfRecordType::MoveToEx, data);
        self.metafile.add_record(record);
        self.metafile.update_bounds(x, y);
    }

    /// Record a LineTo operation
    pub fn record_line_to(&mut self, x: i32, y: i32) {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&x.to_le_bytes());
        data.extend_from_slice(&y.to_le_bytes());

        let record = EmfRecord::with_data(EmfRecordType::LineTo, data);
        self.metafile.add_record(record);
        self.metafile.update_bounds(x, y);
    }

    /// Record a Rectangle operation
    pub fn record_rectangle(&mut self, left: i32, top: i32, right: i32, bottom: i32) {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&left.to_le_bytes());
        data.extend_from_slice(&top.to_le_bytes());
        data.extend_from_slice(&right.to_le_bytes());
        data.extend_from_slice(&bottom.to_le_bytes());

        let record = EmfRecord::with_data(EmfRecordType::Rectangle, data);
        self.metafile.add_record(record);
        self.metafile.update_bounds(left, top);
        self.metafile.update_bounds(right, bottom);
    }

    /// Record an Ellipse operation
    pub fn record_ellipse(&mut self, left: i32, top: i32, right: i32, bottom: i32) {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&left.to_le_bytes());
        data.extend_from_slice(&top.to_le_bytes());
        data.extend_from_slice(&right.to_le_bytes());
        data.extend_from_slice(&bottom.to_le_bytes());

        let record = EmfRecord::with_data(EmfRecordType::Ellipse, data);
        self.metafile.add_record(record);
        self.metafile.update_bounds(left, top);
        self.metafile.update_bounds(right, bottom);
    }

    /// Record SetTextColor
    pub fn record_set_text_color(&mut self, color: ColorRef) {
        let mut data = Vec::with_capacity(4);
        data.extend_from_slice(&color.0.to_le_bytes());

        let record = EmfRecord::with_data(EmfRecordType::SetTextColor, data);
        self.metafile.add_record(record);
    }

    /// Record SetBkColor
    pub fn record_set_bk_color(&mut self, color: ColorRef) {
        let mut data = Vec::with_capacity(4);
        data.extend_from_slice(&color.0.to_le_bytes());

        let record = EmfRecord::with_data(EmfRecordType::SetBkColor, data);
        self.metafile.add_record(record);
    }

    /// Record SaveDC
    pub fn record_save_dc(&mut self) {
        let record = EmfRecord::new(EmfRecordType::SaveDc);
        self.metafile.add_record(record);
    }

    /// Record RestoreDC
    pub fn record_restore_dc(&mut self, saved_dc: i32) {
        let mut data = Vec::with_capacity(4);
        data.extend_from_slice(&saved_dc.to_le_bytes());

        let record = EmfRecord::with_data(EmfRecordType::RestoreDc, data);
        self.metafile.add_record(record);
    }

    /// Record BeginPath
    pub fn record_begin_path(&mut self) {
        let record = EmfRecord::new(EmfRecordType::BeginPath);
        self.metafile.add_record(record);
    }

    /// Record EndPath
    pub fn record_end_path(&mut self) {
        let record = EmfRecord::new(EmfRecordType::EndPath);
        self.metafile.add_record(record);
    }

    /// Record StrokePath
    pub fn record_stroke_path(&mut self) {
        let record = EmfRecord::new(EmfRecordType::StrokePath);
        self.metafile.add_record(record);
    }

    /// Record FillPath
    pub fn record_fill_path(&mut self) {
        let record = EmfRecord::new(EmfRecordType::FillPath);
        self.metafile.add_record(record);
    }

    /// Record polygon
    pub fn record_polygon(&mut self, points: &[Point]) {
        let mut data = Vec::with_capacity(8 + points.len() * 8);

        // Bounds
        let (min_x, min_y, max_x, max_y) = calculate_bounds(points);
        data.extend_from_slice(&min_x.to_le_bytes());
        data.extend_from_slice(&min_y.to_le_bytes());
        data.extend_from_slice(&max_x.to_le_bytes());
        data.extend_from_slice(&max_y.to_le_bytes());

        // Point count
        data.extend_from_slice(&(points.len() as u32).to_le_bytes());

        // Points
        for p in points {
            data.extend_from_slice(&p.x.to_le_bytes());
            data.extend_from_slice(&p.y.to_le_bytes());
        }

        let record = EmfRecord::with_data(EmfRecordType::Polygon, data);
        self.metafile.add_record(record);

        self.metafile.update_bounds(min_x, min_y);
        self.metafile.update_bounds(max_x, max_y);
    }

    /// Record polyline
    pub fn record_polyline(&mut self, points: &[Point]) {
        let mut data = Vec::with_capacity(8 + points.len() * 8);

        // Bounds
        let (min_x, min_y, max_x, max_y) = calculate_bounds(points);
        data.extend_from_slice(&min_x.to_le_bytes());
        data.extend_from_slice(&min_y.to_le_bytes());
        data.extend_from_slice(&max_x.to_le_bytes());
        data.extend_from_slice(&max_y.to_le_bytes());

        // Point count
        data.extend_from_slice(&(points.len() as u32).to_le_bytes());

        // Points
        for p in points {
            data.extend_from_slice(&p.x.to_le_bytes());
            data.extend_from_slice(&p.y.to_le_bytes());
        }

        let record = EmfRecord::with_data(EmfRecordType::Polyline, data);
        self.metafile.add_record(record);

        self.metafile.update_bounds(min_x, min_y);
        self.metafile.update_bounds(max_x, max_y);
    }
}

/// Calculate bounding box of points
fn calculate_bounds(points: &[Point]) -> (i32, i32, i32, i32) {
    if points.is_empty() {
        return (0, 0, 0, 0);
    }

    let mut min_x = points[0].x;
    let mut min_y = points[0].y;
    let mut max_x = points[0].x;
    let mut max_y = points[0].y;

    for p in points.iter().skip(1) {
        if p.x < min_x { min_x = p.x; }
        if p.x > max_x { max_x = p.x; }
        if p.y < min_y { min_y = p.y; }
        if p.y > max_y { max_y = p.y; }
    }

    (min_x, min_y, max_x, max_y)
}

// ============================================================================
// EMF Table
// ============================================================================

static EMF_TABLE: SpinLock<BTreeMap<u32, EnhMetaFile>> = SpinLock::new(BTreeMap::new());
static MF_DC_TABLE: SpinLock<BTreeMap<u32, MetafileDc>> = SpinLock::new(BTreeMap::new());
static NEXT_EMF_HANDLE: SpinLock<u32> = SpinLock::new(0x5000);

// ============================================================================
// EMF API
// ============================================================================

/// Initialize EMF subsystem
pub fn init() {
    crate::serial_println!("[GDI] EMF subsystem initialized");
}

/// Create an enhanced metafile DC for recording
pub fn create_enh_metafile_dc(
    reference_dc: GdiHandle,
    _filename: Option<&str>,
    _rect: Option<&Rect>,
    _description: Option<&str>,
) -> GdiHandle {
    let mut next = NEXT_EMF_HANDLE.lock();
    let mf_handle_val = *next;
    *next += 1;
    drop(next);

    let dc_handle = GdiHandle::new(mf_handle_val as u16, GdiObjectType::DC);
    let mf_handle = GdiHandle::new(mf_handle_val as u16, GdiObjectType::Bitmap); // Using Bitmap type for metafile

    let mf_dc = MetafileDc::new(dc_handle, mf_handle, reference_dc);

    let mut table = MF_DC_TABLE.lock();
    table.insert(mf_handle_val, mf_dc);

    crate::serial_println!("[GDI] Created metafile DC {:?}", dc_handle);
    dc_handle
}

/// Close enhanced metafile and get the metafile handle
pub fn close_enh_metafile(hdc: GdiHandle) -> GdiHandle {
    let handle_val = hdc.index() as u32;

    let mut dc_table = MF_DC_TABLE.lock();
    if let Some(mf_dc) = dc_table.remove(&handle_val) {
        let mf_handle = mf_dc.metafile.handle;

        let mut emf_table = EMF_TABLE.lock();
        emf_table.insert(handle_val, mf_dc.metafile);

        crate::serial_println!("[GDI] Closed metafile, handle {:?}", mf_handle);
        mf_handle
    } else {
        GdiHandle::NULL
    }
}

/// Delete an enhanced metafile
pub fn delete_enh_metafile(hemf: GdiHandle) -> bool {
    let handle_val = hemf.index() as u32;
    let mut table = EMF_TABLE.lock();
    table.remove(&handle_val).is_some()
}

/// Get enhanced metafile header
pub fn get_enh_metafile_header(hemf: GdiHandle) -> Option<EmfHeader> {
    let handle_val = hemf.index() as u32;
    let table = EMF_TABLE.lock();
    table.get(&handle_val).map(|emf| emf.header.clone())
}

/// Get enhanced metafile bits (raw data)
pub fn get_enh_metafile_bits(hemf: GdiHandle) -> Option<Vec<u8>> {
    let handle_val = hemf.index() as u32;
    let table = EMF_TABLE.lock();
    table.get(&handle_val).map(|emf| emf.to_bytes())
}

/// Play enhanced metafile on a DC
pub fn play_enh_metafile(hdc: GdiHandle, hemf: GdiHandle, _rect: &Rect) -> bool {
    let handle_val = hemf.index() as u32;
    let table = EMF_TABLE.lock();

    if let Some(emf) = table.get(&handle_val) {
        crate::serial_println!("[GDI] Playing metafile with {} records", emf.records.len());

        // In a full implementation, we would iterate through records
        // and replay each GDI operation on the target DC
        for record in &emf.records {
            play_record(hdc, record);
        }

        true
    } else {
        false
    }
}

/// Play a single EMF record
fn play_record(hdc: GdiHandle, record: &EmfRecord) {
    match record.record_type {
        t if t == EmfRecordType::MoveToEx as u32 => {
            if record.data.len() >= 8 {
                let x = i32::from_le_bytes([record.data[0], record.data[1], record.data[2], record.data[3]]);
                let y = i32::from_le_bytes([record.data[4], record.data[5], record.data[6], record.data[7]]);
                super::move_to(hdc, x, y);
            }
        }
        t if t == EmfRecordType::LineTo as u32 => {
            if record.data.len() >= 8 {
                let x = i32::from_le_bytes([record.data[0], record.data[1], record.data[2], record.data[3]]);
                let y = i32::from_le_bytes([record.data[4], record.data[5], record.data[6], record.data[7]]);
                super::line_to(hdc, x, y);
            }
        }
        t if t == EmfRecordType::Rectangle as u32 => {
            if record.data.len() >= 16 {
                let left = i32::from_le_bytes([record.data[0], record.data[1], record.data[2], record.data[3]]);
                let top = i32::from_le_bytes([record.data[4], record.data[5], record.data[6], record.data[7]]);
                let right = i32::from_le_bytes([record.data[8], record.data[9], record.data[10], record.data[11]]);
                let bottom = i32::from_le_bytes([record.data[12], record.data[13], record.data[14], record.data[15]]);
                super::rectangle(hdc, left, top, right, bottom);
            }
        }
        t if t == EmfRecordType::Ellipse as u32 => {
            if record.data.len() >= 16 {
                let left = i32::from_le_bytes([record.data[0], record.data[1], record.data[2], record.data[3]]);
                let top = i32::from_le_bytes([record.data[4], record.data[5], record.data[6], record.data[7]]);
                let right = i32::from_le_bytes([record.data[8], record.data[9], record.data[10], record.data[11]]);
                let bottom = i32::from_le_bytes([record.data[12], record.data[13], record.data[14], record.data[15]]);
                super::ellipse(hdc, left, top, right, bottom);
            }
        }
        t if t == EmfRecordType::SetTextColor as u32 => {
            if record.data.len() >= 4 {
                let color = u32::from_le_bytes([record.data[0], record.data[1], record.data[2], record.data[3]]);
                dc::set_text_color(hdc, ColorRef(color));
            }
        }
        t if t == EmfRecordType::SetBkColor as u32 => {
            if record.data.len() >= 4 {
                let color = u32::from_le_bytes([record.data[0], record.data[1], record.data[2], record.data[3]]);
                dc::set_bk_color(hdc, ColorRef(color));
            }
        }
        t if t == EmfRecordType::SaveDc as u32 => {
            // TODO: Implement save_dc when DC state stack is available
            let _ = hdc;
        }
        t if t == EmfRecordType::RestoreDc as u32 => {
            // TODO: Implement restore_dc when DC state stack is available
            let _ = record;
        }
        _ => {
            // Unknown record type, skip
        }
    }
}

/// Check if a DC is a metafile DC
pub fn is_metafile_dc(hdc: GdiHandle) -> bool {
    let handle_val = hdc.index() as u32;
    let table = MF_DC_TABLE.lock();
    table.contains_key(&handle_val)
}

/// Record a GDI operation to metafile (if recording)
pub fn record_to_metafile<F>(hdc: GdiHandle, recorder: F)
where
    F: FnOnce(&mut MetafileDc),
{
    let handle_val = hdc.index() as u32;
    let mut table = MF_DC_TABLE.lock();
    if let Some(mf_dc) = table.get_mut(&handle_val) {
        recorder(mf_dc);
    }
}
