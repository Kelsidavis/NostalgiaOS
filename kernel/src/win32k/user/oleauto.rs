//! OLE Automation Helpers
//!
//! COM and OLE automation support structures and helpers.
//! Based on Windows Server 2003 oleauto.h and oaidl.h.
//!
//! # Features
//!
//! - VARIANT type
//! - SAFEARRAY support
//! - BSTR strings
//! - IDispatch helpers
//!
//! # References
//!
//! - `public/sdk/inc/oleauto.h` - OLE Automation
//! - `public/sdk/inc/oaidl.h` - OLE Automation IDL

use crate::ke::spinlock::SpinLock;

// ============================================================================
// VARTYPE Constants (VT_*)
// ============================================================================

/// Empty
pub const VT_EMPTY: u16 = 0;

/// Null
pub const VT_NULL: u16 = 1;

/// Short (i16)
pub const VT_I2: u16 = 2;

/// Long (i32)
pub const VT_I4: u16 = 3;

/// Float (f32)
pub const VT_R4: u16 = 4;

/// Double (f64)
pub const VT_R8: u16 = 5;

/// Currency
pub const VT_CY: u16 = 6;

/// Date
pub const VT_DATE: u16 = 7;

/// BSTR string
pub const VT_BSTR: u16 = 8;

/// IDispatch*
pub const VT_DISPATCH: u16 = 9;

/// Error
pub const VT_ERROR: u16 = 10;

/// Boolean
pub const VT_BOOL: u16 = 11;

/// VARIANT
pub const VT_VARIANT: u16 = 12;

/// IUnknown*
pub const VT_UNKNOWN: u16 = 13;

/// Decimal
pub const VT_DECIMAL: u16 = 14;

/// Char (i8)
pub const VT_I1: u16 = 16;

/// Unsigned char (u8)
pub const VT_UI1: u16 = 17;

/// Unsigned short (u16)
pub const VT_UI2: u16 = 18;

/// Unsigned long (u32)
pub const VT_UI4: u16 = 19;

/// 64-bit signed int
pub const VT_I8: u16 = 20;

/// 64-bit unsigned int
pub const VT_UI8: u16 = 21;

/// Integer
pub const VT_INT: u16 = 22;

/// Unsigned integer
pub const VT_UINT: u16 = 23;

/// Void
pub const VT_VOID: u16 = 24;

/// HRESULT
pub const VT_HRESULT: u16 = 25;

/// Pointer
pub const VT_PTR: u16 = 26;

/// Safe array
pub const VT_SAFEARRAY: u16 = 27;

/// C-style array
pub const VT_CARRAY: u16 = 28;

/// User-defined type
pub const VT_USERDEFINED: u16 = 29;

/// LPSTR
pub const VT_LPSTR: u16 = 30;

/// LPWSTR
pub const VT_LPWSTR: u16 = 31;

/// Record
pub const VT_RECORD: u16 = 36;

/// Signed pointer-sized int
pub const VT_INT_PTR: u16 = 37;

/// Unsigned pointer-sized int
pub const VT_UINT_PTR: u16 = 38;

/// File time
pub const VT_FILETIME: u16 = 64;

/// Blob
pub const VT_BLOB: u16 = 65;

/// Stream
pub const VT_STREAM: u16 = 66;

/// Storage
pub const VT_STORAGE: u16 = 67;

/// Streamed object
pub const VT_STREAMED_OBJECT: u16 = 68;

/// Stored object
pub const VT_STORED_OBJECT: u16 = 69;

/// Blob object
pub const VT_BLOB_OBJECT: u16 = 70;

/// Clipboard format
pub const VT_CF: u16 = 71;

/// CLSID
pub const VT_CLSID: u16 = 72;

/// Versioned stream
pub const VT_VERSIONED_STREAM: u16 = 73;

/// Type modifier: vector
pub const VT_VECTOR: u16 = 0x1000;

/// Type modifier: array
pub const VT_ARRAY: u16 = 0x2000;

/// Type modifier: byref
pub const VT_BYREF: u16 = 0x4000;

/// Type modifier: reserved
pub const VT_RESERVED: u16 = 0x8000;

// ============================================================================
// VARIANT Boolean Values
// ============================================================================

/// Variant TRUE
pub const VARIANT_TRUE: i16 = -1;

/// Variant FALSE
pub const VARIANT_FALSE: i16 = 0;

// ============================================================================
// DISPID Constants
// ============================================================================

/// Value property
pub const DISPID_VALUE: i32 = 0;

/// Unknown DISPID
pub const DISPID_UNKNOWN: i32 = -1;

/// Property put (assignment)
pub const DISPID_PROPERTYPUT: i32 = -3;

/// NewEnum
pub const DISPID_NEWENUM: i32 = -4;

/// Evaluate
pub const DISPID_EVALUATE: i32 = -5;

/// Constructor
pub const DISPID_CONSTRUCTOR: i32 = -6;

/// Destructor
pub const DISPID_DESTRUCTOR: i32 = -7;

/// Collect
pub const DISPID_COLLECT: i32 = -8;

// ============================================================================
// Invoke Flags (DISPATCH_*)
// ============================================================================

/// Method call
pub const DISPATCH_METHOD: u16 = 0x1;

/// Property get
pub const DISPATCH_PROPERTYGET: u16 = 0x2;

/// Property put
pub const DISPATCH_PROPERTYPUT: u16 = 0x4;

/// Property put reference
pub const DISPATCH_PROPERTYPUTREF: u16 = 0x8;

// ============================================================================
// Constants
// ============================================================================

/// Maximum BSTR length
pub const MAX_BSTR_LEN: usize = 4096;

/// Maximum BSTRs
pub const MAX_BSTRS: usize = 128;

/// Maximum variants
pub const MAX_VARIANTS: usize = 64;

/// Maximum safe arrays
pub const MAX_SAFEARRAYS: usize = 32;

// ============================================================================
// GUID/CLSID Structure
// ============================================================================

/// GUID structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// Create null GUID
    pub const fn null() -> Self {
        Self {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }

    /// Check if null
    pub fn is_null(&self) -> bool {
        self.data1 == 0 && self.data2 == 0 && self.data3 == 0 && self.data4 == [0; 8]
    }
}

/// IID_NULL
pub const IID_NULL: Guid = Guid::null();

/// IID_IUnknown
pub const IID_IUNKNOWN: Guid = Guid {
    data1: 0x00000000,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

/// IID_IDispatch
pub const IID_IDISPATCH: Guid = Guid {
    data1: 0x00020400,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

// ============================================================================
// BSTR (Basic String)
// ============================================================================

/// BSTR handle
pub type BSTR = usize;

/// Null BSTR
pub const NULL_BSTR: BSTR = 0;

/// BSTR storage entry
#[derive(Clone)]
pub struct BstrEntry {
    /// Is this slot in use
    pub in_use: bool,
    /// Handle value
    pub handle: BSTR,
    /// String length (in characters)
    pub len: u32,
    /// String data (wide chars stored as u16 pairs)
    pub data: [u8; MAX_BSTR_LEN],
}

impl BstrEntry {
    /// Create empty entry
    pub const fn new() -> Self {
        Self {
            in_use: false,
            handle: 0,
            len: 0,
            data: [0; MAX_BSTR_LEN],
        }
    }
}

// ============================================================================
// VARIANT Structure
// ============================================================================

/// VARIANT value union (simplified)
#[derive(Clone, Copy)]
pub union VariantValue {
    pub bool_val: i16,
    pub i1_val: i8,
    pub ui1_val: u8,
    pub i2_val: i16,
    pub ui2_val: u16,
    pub i4_val: i32,
    pub ui4_val: u32,
    pub i8_val: i64,
    pub ui8_val: u64,
    pub int_val: i32,
    pub uint_val: u32,
    pub ptr_val: usize,
    pub error_val: i32,
}

impl Default for VariantValue {
    fn default() -> Self {
        Self { ui8_val: 0 }
    }
}

/// VARIANT structure
#[derive(Clone, Copy)]
pub struct Variant {
    /// Type (VT_*)
    pub vt: u16,
    /// Reserved
    pub reserved1: u16,
    /// Reserved
    pub reserved2: u16,
    /// Reserved
    pub reserved3: u16,
    /// Value
    pub value: VariantValue,
}

impl Variant {
    /// Create empty variant
    pub const fn empty() -> Self {
        Self {
            vt: VT_EMPTY,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            value: VariantValue { ui8_val: 0 },
        }
    }

    /// Create null variant
    pub const fn null() -> Self {
        Self {
            vt: VT_NULL,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            value: VariantValue { ui8_val: 0 },
        }
    }

    /// Create bool variant
    pub fn from_bool(val: bool) -> Self {
        Self {
            vt: VT_BOOL,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            value: VariantValue {
                bool_val: if val { VARIANT_TRUE } else { VARIANT_FALSE },
            },
        }
    }

    /// Create i32 variant
    pub fn from_i4(val: i32) -> Self {
        Self {
            vt: VT_I4,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            value: VariantValue { i4_val: val },
        }
    }

    /// Create BSTR variant
    pub fn from_bstr(bstr: BSTR) -> Self {
        Self {
            vt: VT_BSTR,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            value: VariantValue { ptr_val: bstr },
        }
    }

    /// Get type
    pub fn get_type(&self) -> u16 {
        self.vt & 0x0FFF
    }

    /// Is empty or null
    pub fn is_empty_or_null(&self) -> bool {
        matches!(self.get_type(), VT_EMPTY | VT_NULL)
    }

    /// Get bool value
    pub fn as_bool(&self) -> Option<bool> {
        if self.get_type() == VT_BOOL {
            Some(unsafe { self.value.bool_val } != 0)
        } else {
            None
        }
    }

    /// Get i32 value
    pub fn as_i4(&self) -> Option<i32> {
        if self.get_type() == VT_I4 {
            Some(unsafe { self.value.i4_val })
        } else {
            None
        }
    }
}

impl Default for Variant {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// SAFEARRAY Structure
// ============================================================================

/// SAFEARRAY bound
#[derive(Clone, Copy, Default)]
pub struct SafeArrayBound {
    /// Number of elements
    pub elements: u32,
    /// Lower bound
    pub lbound: i32,
}

/// SAFEARRAY structure
#[derive(Clone)]
pub struct SafeArray {
    /// Is this slot in use
    pub in_use: bool,
    /// Handle value
    pub handle: usize,
    /// Number of dimensions
    pub dims: u16,
    /// Features/flags
    pub features: u16,
    /// Size of each element
    pub element_size: u32,
    /// Lock count
    pub locks: u32,
    /// Element type
    pub vt: u16,
    /// Bounds (up to 4 dimensions)
    pub bounds: [SafeArrayBound; 4],
    /// Data pointer (simulated)
    pub data: usize,
}

impl SafeArray {
    /// Create empty array
    pub const fn new() -> Self {
        Self {
            in_use: false,
            handle: 0,
            dims: 0,
            features: 0,
            element_size: 0,
            locks: 0,
            vt: VT_EMPTY,
            bounds: [SafeArrayBound {
                elements: 0,
                lbound: 0,
            }; 4],
            data: 0,
        }
    }

    /// Get total elements
    pub fn total_elements(&self) -> usize {
        let mut total = 1usize;
        for i in 0..self.dims as usize {
            total = total.saturating_mul(self.bounds[i].elements as usize);
        }
        total
    }
}

// ============================================================================
// EXCEPINFO Structure
// ============================================================================

/// Exception info
#[derive(Clone)]
pub struct ExcepInfo {
    /// Error code
    pub code: u16,
    /// Reserved
    pub reserved: u16,
    /// Source
    pub source: BSTR,
    /// Description
    pub description: BSTR,
    /// Help file
    pub help_file: BSTR,
    /// Help context
    pub help_context: u32,
    /// Reserved pointer
    pub reserved_ptr: usize,
    /// Deferred fill in
    pub deferred_fill_in: usize,
    /// SCODE
    pub scode: i32,
}

impl ExcepInfo {
    /// Create empty exception
    pub const fn new() -> Self {
        Self {
            code: 0,
            reserved: 0,
            source: NULL_BSTR,
            description: NULL_BSTR,
            help_file: NULL_BSTR,
            help_context: 0,
            reserved_ptr: 0,
            deferred_fill_in: 0,
            scode: 0,
        }
    }
}

impl Default for ExcepInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DISPPARAMS Structure
// ============================================================================

/// Dispatch parameters
#[derive(Clone)]
pub struct DispParams {
    /// Arguments
    pub args: [Variant; 16],
    /// Named argument DISPIDs
    pub named_args: [i32; 16],
    /// Number of arguments
    pub count_args: u32,
    /// Number of named arguments
    pub count_named: u32,
}

impl DispParams {
    /// Create empty params
    pub const fn new() -> Self {
        Self {
            args: [Variant::empty(); 16],
            named_args: [DISPID_UNKNOWN; 16],
            count_args: 0,
            count_named: 0,
        }
    }
}

impl Default for DispParams {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global BSTR storage
static BSTRS: SpinLock<[BstrEntry; MAX_BSTRS]> =
    SpinLock::new([const { BstrEntry::new() }; MAX_BSTRS]);

/// Global SafeArray storage
static SAFEARRAYS: SpinLock<[SafeArray; MAX_SAFEARRAYS]> =
    SpinLock::new([const { SafeArray::new() }; MAX_SAFEARRAYS]);

/// Next BSTR handle
static NEXT_BSTR: SpinLock<BSTR> = SpinLock::new(1);

/// Next SafeArray handle
static NEXT_SAFEARRAY: SpinLock<usize> = SpinLock::new(1);

// ============================================================================
// Public API
// ============================================================================

/// Initialize OLE automation
pub fn init() {
    crate::serial_println!("[USER] OLE automation helpers initialized");
}

/// Allocate BSTR from bytes (ANSI)
pub fn sys_alloc_string(src: &[u8]) -> BSTR {
    let mut bstrs = BSTRS.lock();
    let mut next = NEXT_BSTR.lock();

    for entry in bstrs.iter_mut() {
        if !entry.in_use {
            let handle = *next;
            *next += 1;

            entry.in_use = true;
            entry.handle = handle;

            // Copy string (convert to wide by zero-extending)
            let len = src.len().min(MAX_BSTR_LEN / 2 - 1);
            for (i, &b) in src[..len].iter().enumerate() {
                entry.data[i * 2] = b;
                entry.data[i * 2 + 1] = 0;
            }
            entry.len = len as u32;

            return handle;
        }
    }

    NULL_BSTR
}

/// Allocate BSTR with length
pub fn sys_alloc_string_len(src: Option<&[u8]>, len: u32) -> BSTR {
    let mut bstrs = BSTRS.lock();
    let mut next = NEXT_BSTR.lock();

    for entry in bstrs.iter_mut() {
        if !entry.in_use {
            let handle = *next;
            *next += 1;

            entry.in_use = true;
            entry.handle = handle;
            entry.len = len;

            // Copy source if provided
            if let Some(data) = src {
                let copy_len = (len as usize * 2).min(data.len()).min(MAX_BSTR_LEN);
                entry.data[..copy_len].copy_from_slice(&data[..copy_len]);
            }

            return handle;
        }
    }

    NULL_BSTR
}

/// Free BSTR
pub fn sys_free_string(bstr: BSTR) {
    if bstr == NULL_BSTR {
        return;
    }

    let mut bstrs = BSTRS.lock();

    for entry in bstrs.iter_mut() {
        if entry.in_use && entry.handle == bstr {
            *entry = BstrEntry::new();
            return;
        }
    }
}

/// Get BSTR length
pub fn sys_string_len(bstr: BSTR) -> u32 {
    if bstr == NULL_BSTR {
        return 0;
    }

    let bstrs = BSTRS.lock();

    for entry in bstrs.iter() {
        if entry.in_use && entry.handle == bstr {
            return entry.len;
        }
    }

    0
}

/// Get BSTR byte length
pub fn sys_string_byte_len(bstr: BSTR) -> u32 {
    sys_string_len(bstr) * 2
}

/// Reallocate BSTR
pub fn sys_realloc_string(old_bstr: &mut BSTR, src: &[u8]) -> bool {
    sys_free_string(*old_bstr);
    *old_bstr = sys_alloc_string(src);
    *old_bstr != NULL_BSTR
}

/// Reallocate BSTR with length
pub fn sys_realloc_string_len(old_bstr: &mut BSTR, src: Option<&[u8]>, len: u32) -> bool {
    sys_free_string(*old_bstr);
    *old_bstr = sys_alloc_string_len(src, len);
    *old_bstr != NULL_BSTR
}

// ============================================================================
// Variant Functions
// ============================================================================

/// Initialize variant
pub fn variant_init(var: &mut Variant) {
    *var = Variant::empty();
}

/// Clear variant
pub fn variant_clear(var: &mut Variant) -> i32 {
    // Free any allocated resources
    if var.get_type() == VT_BSTR {
        let bstr = unsafe { var.value.ptr_val };
        sys_free_string(bstr);
    }

    *var = Variant::empty();
    0 // S_OK
}

/// Copy variant
pub fn variant_copy(dest: &mut Variant, src: &Variant) -> i32 {
    // Clear destination first
    variant_clear(dest);

    // Copy source
    dest.vt = src.vt;
    dest.reserved1 = src.reserved1;
    dest.reserved2 = src.reserved2;
    dest.reserved3 = src.reserved3;
    dest.value = src.value;

    // For BSTR, we need to duplicate the string
    if src.get_type() == VT_BSTR {
        let src_bstr = unsafe { src.value.ptr_val };
        // Would need to duplicate the string
        dest.value = VariantValue { ptr_val: src_bstr };
    }

    0 // S_OK
}

/// Change variant type
pub fn variant_change_type(
    dest: &mut Variant,
    src: &Variant,
    flags: u16,
    target_vt: u16,
) -> i32 {
    let _ = flags;

    let src_type = src.get_type();

    if src_type == target_vt {
        return variant_copy(dest, src);
    }

    // Basic type conversions
    match (src_type, target_vt) {
        (VT_I4, VT_BOOL) => {
            let val = unsafe { src.value.i4_val };
            *dest = Variant::from_bool(val != 0);
            0
        }
        (VT_BOOL, VT_I4) => {
            let val = unsafe { src.value.bool_val };
            *dest = Variant::from_i4(if val != 0 { 1 } else { 0 });
            0
        }
        (VT_I2, VT_I4) => {
            let val = unsafe { src.value.i2_val };
            *dest = Variant::from_i4(val as i32);
            0
        }
        _ => {
            // Type conversion not supported
            -2147024809 // E_INVALIDARG
        }
    }
}

// ============================================================================
// SafeArray Functions
// ============================================================================

/// Create SafeArray
pub fn safe_array_create(vt: u16, dims: u32, bounds: &[SafeArrayBound]) -> usize {
    if dims == 0 || dims > 4 {
        return 0;
    }

    let mut arrays = SAFEARRAYS.lock();
    let mut next = NEXT_SAFEARRAY.lock();

    for arr in arrays.iter_mut() {
        if !arr.in_use {
            let handle = *next;
            *next += 1;

            arr.in_use = true;
            arr.handle = handle;
            arr.dims = dims as u16;
            arr.features = 0;
            arr.vt = vt;
            arr.locks = 0;

            // Calculate element size
            arr.element_size = match vt {
                VT_I1 | VT_UI1 => 1,
                VT_I2 | VT_UI2 | VT_BOOL => 2,
                VT_I4 | VT_UI4 | VT_R4 | VT_INT | VT_UINT | VT_ERROR => 4,
                VT_I8 | VT_UI8 | VT_R8 | VT_CY | VT_DATE => 8,
                VT_VARIANT => 16,
                VT_BSTR | VT_UNKNOWN | VT_DISPATCH => 8, // pointer size
                _ => 4,
            };

            // Copy bounds
            for (i, bound) in bounds.iter().take(dims as usize).enumerate() {
                arr.bounds[i] = *bound;
            }

            return handle;
        }
    }

    0
}

/// Create SafeArray vector (1D)
pub fn safe_array_create_vector(vt: u16, lbound: i32, count: u32) -> usize {
    let bounds = [SafeArrayBound {
        elements: count,
        lbound,
    }];
    safe_array_create(vt, 1, &bounds)
}

/// Destroy SafeArray
pub fn safe_array_destroy(handle: usize) -> i32 {
    if handle == 0 {
        return -2147024809; // E_INVALIDARG
    }

    let mut arrays = SAFEARRAYS.lock();

    for arr in arrays.iter_mut() {
        if arr.in_use && arr.handle == handle {
            if arr.locks > 0 {
                return -2147024863; // E_UNEXPECTED (locked)
            }
            *arr = SafeArray::new();
            return 0; // S_OK
        }
    }

    -2147024809 // E_INVALIDARG
}

/// Get SafeArray dimension
pub fn safe_array_get_dim(handle: usize) -> u32 {
    let arrays = SAFEARRAYS.lock();

    for arr in arrays.iter() {
        if arr.in_use && arr.handle == handle {
            return arr.dims as u32;
        }
    }

    0
}

/// Get SafeArray element size
pub fn safe_array_get_elem_size(handle: usize) -> u32 {
    let arrays = SAFEARRAYS.lock();

    for arr in arrays.iter() {
        if arr.in_use && arr.handle == handle {
            return arr.element_size;
        }
    }

    0
}

/// Get SafeArray lower bound
pub fn safe_array_get_lbound(handle: usize, dim: u32, lbound: &mut i32) -> i32 {
    let arrays = SAFEARRAYS.lock();

    for arr in arrays.iter() {
        if arr.in_use && arr.handle == handle {
            if dim == 0 || dim > arr.dims as u32 {
                return -2147024809; // E_INVALIDARG
            }
            *lbound = arr.bounds[dim as usize - 1].lbound;
            return 0; // S_OK
        }
    }

    -2147024809 // E_INVALIDARG
}

/// Get SafeArray upper bound
pub fn safe_array_get_ubound(handle: usize, dim: u32, ubound: &mut i32) -> i32 {
    let arrays = SAFEARRAYS.lock();

    for arr in arrays.iter() {
        if arr.in_use && arr.handle == handle {
            if dim == 0 || dim > arr.dims as u32 {
                return -2147024809;
            }
            let bound = &arr.bounds[dim as usize - 1];
            *ubound = bound.lbound + bound.elements as i32 - 1;
            return 0;
        }
    }

    -2147024809
}

/// Lock SafeArray
pub fn safe_array_lock(handle: usize) -> i32 {
    let mut arrays = SAFEARRAYS.lock();

    for arr in arrays.iter_mut() {
        if arr.in_use && arr.handle == handle {
            arr.locks += 1;
            return 0;
        }
    }

    -2147024809
}

/// Unlock SafeArray
pub fn safe_array_unlock(handle: usize) -> i32 {
    let mut arrays = SAFEARRAYS.lock();

    for arr in arrays.iter_mut() {
        if arr.in_use && arr.handle == handle {
            if arr.locks > 0 {
                arr.locks -= 1;
                return 0;
            }
            return -2147024863; // E_UNEXPECTED
        }
    }

    -2147024809
}

/// Access SafeArray data
pub fn safe_array_access_data(handle: usize, data: &mut usize) -> i32 {
    let mut arrays = SAFEARRAYS.lock();

    for arr in arrays.iter_mut() {
        if arr.in_use && arr.handle == handle {
            arr.locks += 1;
            *data = arr.data;
            return 0;
        }
    }

    -2147024809
}

/// Unaccess SafeArray data
pub fn safe_array_unaccess_data(handle: usize) -> i32 {
    safe_array_unlock(handle)
}

/// Get SafeArray VARTYPE
pub fn safe_array_get_vartype(handle: usize, vt: &mut u16) -> i32 {
    let arrays = SAFEARRAYS.lock();

    for arr in arrays.iter() {
        if arr.in_use && arr.handle == handle {
            *vt = arr.vt;
            return 0;
        }
    }

    -2147024809
}

// ============================================================================
// GUID Functions
// ============================================================================

/// Compare GUIDs
pub fn is_equal_guid(guid1: &Guid, guid2: &Guid) -> bool {
    guid1 == guid2
}

/// Is GUID null
pub fn is_equal_iid(iid1: &Guid, iid2: &Guid) -> bool {
    is_equal_guid(iid1, iid2)
}

/// Is GUID null
pub fn is_equal_clsid(clsid1: &Guid, clsid2: &Guid) -> bool {
    is_equal_guid(clsid1, clsid2)
}

/// String from GUID
pub fn string_from_guid(guid: &Guid, buffer: &mut [u8]) -> bool {
    if buffer.len() < 39 {
        return false;
    }

    // Format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    let hex_chars: &[u8; 16] = b"0123456789ABCDEF";

    buffer[0] = b'{';

    // data1 (8 hex chars)
    for i in 0..8 {
        let shift = (7 - i) * 4;
        let nibble = ((guid.data1 >> shift) & 0xF) as usize;
        buffer[1 + i] = hex_chars[nibble];
    }
    buffer[9] = b'-';

    // data2 (4 hex chars)
    for i in 0..4 {
        let shift = (3 - i) * 4;
        let nibble = ((guid.data2 >> shift) & 0xF) as usize;
        buffer[10 + i] = hex_chars[nibble];
    }
    buffer[14] = b'-';

    // data3 (4 hex chars)
    for i in 0..4 {
        let shift = (3 - i) * 4;
        let nibble = ((guid.data3 >> shift) & 0xF) as usize;
        buffer[15 + i] = hex_chars[nibble];
    }
    buffer[19] = b'-';

    // data4[0..2] (4 hex chars)
    for i in 0..2 {
        buffer[20 + i * 2] = hex_chars[(guid.data4[i] >> 4) as usize];
        buffer[20 + i * 2 + 1] = hex_chars[(guid.data4[i] & 0xF) as usize];
    }
    buffer[24] = b'-';

    // data4[2..8] (12 hex chars)
    for i in 2..8 {
        let base = 25 + (i - 2) * 2;
        buffer[base] = hex_chars[(guid.data4[i] >> 4) as usize];
        buffer[base + 1] = hex_chars[(guid.data4[i] & 0xF) as usize];
    }

    buffer[37] = b'}';
    buffer[38] = 0;

    true
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics
pub fn get_stats() -> OleAutoStats {
    let bstrs = BSTRS.lock();
    let arrays = SAFEARRAYS.lock();

    let mut bstr_count = 0;
    let mut array_count = 0;

    for entry in bstrs.iter() {
        if entry.in_use {
            bstr_count += 1;
        }
    }

    for arr in arrays.iter() {
        if arr.in_use {
            array_count += 1;
        }
    }

    OleAutoStats {
        max_bstrs: MAX_BSTRS,
        allocated_bstrs: bstr_count,
        max_safearrays: MAX_SAFEARRAYS,
        allocated_safearrays: array_count,
    }
}

/// OLE automation statistics
#[derive(Debug, Clone, Copy)]
pub struct OleAutoStats {
    pub max_bstrs: usize,
    pub allocated_bstrs: usize,
    pub max_safearrays: usize,
    pub allocated_safearrays: usize,
}
