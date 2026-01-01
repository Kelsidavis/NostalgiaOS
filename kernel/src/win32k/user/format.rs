//! Format String Helpers
//!
//! Windows-style format string functions (FormatMessage, wsprintf).
//! Based on Windows Server 2003 user32.h and kernel32.h.
//!
//! # Features
//!
//! - Printf-style formatting (wsprintf)
//! - FormatMessage-style formatting
//! - Number formatting with thousands separator
//! - Date/time formatting
//!
//! # References
//!
//! - `public/sdk/inc/winuser.h` - wsprintf
//! - `public/sdk/inc/winbase.h` - FormatMessage

use super::strhelp;

// ============================================================================
// Format Message Flags
// ============================================================================

/// Allocate buffer
pub const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x0100;

/// Ignore inserts
pub const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x0200;

/// From string
pub const FORMAT_MESSAGE_FROM_STRING: u32 = 0x0400;

/// From module
pub const FORMAT_MESSAGE_FROM_HMODULE: u32 = 0x0800;

/// From system
pub const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x1000;

/// Argument array
pub const FORMAT_MESSAGE_ARGUMENT_ARRAY: u32 = 0x2000;

/// Max width mask
pub const FORMAT_MESSAGE_MAX_WIDTH_MASK: u32 = 0x00FF;

// ============================================================================
// Number Format
// ============================================================================

/// Number format settings
#[derive(Clone, Copy)]
pub struct NumberFormat {
    /// Number of fractional digits
    pub num_digits: u32,
    /// Leading zero
    pub leading_zero: u32,
    /// Grouping
    pub grouping: u32,
    /// Decimal separator
    pub decimal_sep: [u8; 4],
    /// Thousands separator
    pub thousand_sep: [u8; 4],
    /// Negative order (0=(-1.1), 1=-1.1, 2=(1.1-), etc.)
    pub negative_order: u32,
}

impl NumberFormat {
    /// Default US format
    pub const fn default() -> Self {
        Self {
            num_digits: 2,
            leading_zero: 1,
            grouping: 3,
            decimal_sep: [b'.', 0, 0, 0],
            thousand_sep: [b',', 0, 0, 0],
            negative_order: 1,
        }
    }
}

/// Currency format settings
#[derive(Clone, Copy)]
pub struct CurrencyFormat {
    /// Number of fractional digits
    pub num_digits: u32,
    /// Leading zero
    pub leading_zero: u32,
    /// Grouping
    pub grouping: u32,
    /// Decimal separator
    pub decimal_sep: [u8; 4],
    /// Thousands separator
    pub thousand_sep: [u8; 4],
    /// Currency symbol
    pub currency_symbol: [u8; 8],
    /// Positive order (0=$1.1, 1=1.1$, 2=$ 1.1, 3=1.1 $)
    pub positive_order: u32,
    /// Negative order
    pub negative_order: u32,
}

impl CurrencyFormat {
    /// Default US format
    pub const fn default() -> Self {
        Self {
            num_digits: 2,
            leading_zero: 1,
            grouping: 3,
            decimal_sep: [b'.', 0, 0, 0],
            thousand_sep: [b',', 0, 0, 0],
            currency_symbol: [b'$', 0, 0, 0, 0, 0, 0, 0],
            positive_order: 0,
            negative_order: 0,
        }
    }
}

// ============================================================================
// Date/Time Format Constants
// ============================================================================

/// Date format flags
pub const DATE_SHORTDATE: u32 = 0x0001;
pub const DATE_LONGDATE: u32 = 0x0002;
pub const DATE_USE_ALT_CALENDAR: u32 = 0x0004;
pub const DATE_YEARMONTH: u32 = 0x0008;
pub const DATE_LTRREADING: u32 = 0x0010;
pub const DATE_RTLREADING: u32 = 0x0020;

/// Time format flags
pub const TIME_NOMINUTESORSECONDS: u32 = 0x0001;
pub const TIME_NOSECONDS: u32 = 0x0002;
pub const TIME_NOTIMEMARKER: u32 = 0x0004;
pub const TIME_FORCE24HOURFORMAT: u32 = 0x0008;

// ============================================================================
// Format Specifier Parsing
// ============================================================================

/// Format specifier
#[derive(Clone, Copy, Default)]
struct FormatSpec {
    /// Flags (-, +, 0, space, #)
    flags: u8,
    /// Minimum width
    width: usize,
    /// Precision
    precision: Option<usize>,
    /// Size modifier (h, l, ll)
    size: u8,
    /// Conversion type (d, i, u, x, X, s, c, etc.)
    conversion: u8,
}

const FLAG_MINUS: u8 = 0x01;  // Left-justify
const FLAG_PLUS: u8 = 0x02;   // Always show sign
const FLAG_SPACE: u8 = 0x04;  // Space for positive
const FLAG_HASH: u8 = 0x08;   // Alternative form
const FLAG_ZERO: u8 = 0x10;   // Zero-pad

// ============================================================================
// Printf-style Formatting
// ============================================================================

/// Printf-style format (simplified wsprintf)
/// Supports: %d, %i, %u, %x, %X, %s, %c, %%
pub fn wsprintf(dst: &mut [u8], format: &[u8], args: &[usize]) -> usize {
    if dst.is_empty() {
        return 0;
    }

    let fmt_len = strhelp::str_len(format);
    let mut dst_pos = 0;
    let mut fmt_pos = 0;
    let mut arg_idx = 0;

    while fmt_pos < fmt_len && dst_pos < dst.len() - 1 {
        if format[fmt_pos] == b'%' {
            fmt_pos += 1;
            if fmt_pos >= fmt_len {
                break;
            }

            // Handle %%
            if format[fmt_pos] == b'%' {
                dst[dst_pos] = b'%';
                dst_pos += 1;
                fmt_pos += 1;
                continue;
            }

            // Parse format specifier
            let spec = parse_format_spec(format, &mut fmt_pos, fmt_len);

            // Get argument
            let arg = if arg_idx < args.len() {
                args[arg_idx]
            } else {
                0
            };
            arg_idx += 1;

            // Format based on conversion type
            dst_pos += format_arg(&mut dst[dst_pos..], &spec, arg);
        } else {
            dst[dst_pos] = format[fmt_pos];
            dst_pos += 1;
            fmt_pos += 1;
        }
    }

    dst[dst_pos] = 0;
    dst_pos
}

/// Parse a format specifier
fn parse_format_spec(format: &[u8], pos: &mut usize, len: usize) -> FormatSpec {
    let mut spec = FormatSpec::default();

    // Parse flags
    while *pos < len {
        match format[*pos] {
            b'-' => spec.flags |= FLAG_MINUS,
            b'+' => spec.flags |= FLAG_PLUS,
            b' ' => spec.flags |= FLAG_SPACE,
            b'#' => spec.flags |= FLAG_HASH,
            b'0' => spec.flags |= FLAG_ZERO,
            _ => break,
        }
        *pos += 1;
    }

    // Parse width
    while *pos < len && strhelp::is_digit(format[*pos]) {
        spec.width = spec.width * 10 + (format[*pos] - b'0') as usize;
        *pos += 1;
    }

    // Parse precision
    if *pos < len && format[*pos] == b'.' {
        *pos += 1;
        let mut prec = 0;
        while *pos < len && strhelp::is_digit(format[*pos]) {
            prec = prec * 10 + (format[*pos] - b'0') as usize;
            *pos += 1;
        }
        spec.precision = Some(prec);
    }

    // Parse size modifier
    if *pos < len {
        match format[*pos] {
            b'h' => {
                spec.size = b'h';
                *pos += 1;
            }
            b'l' => {
                spec.size = b'l';
                *pos += 1;
                if *pos < len && format[*pos] == b'l' {
                    spec.size = b'L'; // ll
                    *pos += 1;
                }
            }
            b'I' => {
                spec.size = b'I';
                *pos += 1;
                // Skip 32 or 64 if present
                if *pos + 1 < len {
                    if format[*pos] == b'3' && format[*pos + 1] == b'2' {
                        *pos += 2;
                    } else if format[*pos] == b'6' && format[*pos + 1] == b'4' {
                        *pos += 2;
                    }
                }
            }
            _ => {}
        }
    }

    // Parse conversion type
    if *pos < len {
        spec.conversion = format[*pos];
        *pos += 1;
    }

    spec
}

/// Format a single argument
fn format_arg(dst: &mut [u8], spec: &FormatSpec, arg: usize) -> usize {
    match spec.conversion {
        b'd' | b'i' => format_signed(dst, spec, arg as isize),
        b'u' => format_unsigned(dst, spec, arg, 10, false),
        b'x' => format_unsigned(dst, spec, arg, 16, false),
        b'X' => format_unsigned(dst, spec, arg, 16, true),
        b'o' => format_unsigned(dst, spec, arg, 8, false),
        b's' => format_string(dst, spec, arg),
        b'c' => format_char(dst, arg as u8),
        b'p' => format_pointer(dst, arg),
        _ => 0,
    }
}

/// Format signed integer
fn format_signed(dst: &mut [u8], spec: &FormatSpec, value: isize) -> usize {
    let negative = value < 0;
    let abs_val = if negative { (-value) as usize } else { value as usize };

    // Format number without sign
    let mut temp = [0u8; 32];
    let mut len = format_unsigned(&mut temp, spec, abs_val, 10, false);

    // Calculate padding
    let sign_len = if negative || (spec.flags & (FLAG_PLUS | FLAG_SPACE)) != 0 { 1 } else { 0 };
    let total_len = len + sign_len;
    let pad_len = if spec.width > total_len { spec.width - total_len } else { 0 };

    let mut pos = 0;

    // Left-justify: add sign first, then number, then padding
    // Right-justify with zero: add sign, then zeros, then number
    // Right-justify with space: add spaces, then sign, then number

    if (spec.flags & FLAG_MINUS) != 0 {
        // Left-justify
        if negative {
            dst[pos] = b'-';
            pos += 1;
        } else if (spec.flags & FLAG_PLUS) != 0 {
            dst[pos] = b'+';
            pos += 1;
        } else if (spec.flags & FLAG_SPACE) != 0 {
            dst[pos] = b' ';
            pos += 1;
        }

        dst[pos..pos + len].copy_from_slice(&temp[..len]);
        pos += len;

        for _ in 0..pad_len {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = b' ';
            pos += 1;
        }
    } else if (spec.flags & FLAG_ZERO) != 0 {
        // Right-justify with zeros
        if negative {
            dst[pos] = b'-';
            pos += 1;
        } else if (spec.flags & FLAG_PLUS) != 0 {
            dst[pos] = b'+';
            pos += 1;
        } else if (spec.flags & FLAG_SPACE) != 0 {
            dst[pos] = b' ';
            pos += 1;
        }

        for _ in 0..pad_len {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = b'0';
            pos += 1;
        }

        dst[pos..pos + len].copy_from_slice(&temp[..len]);
        pos += len;
    } else {
        // Right-justify with spaces
        for _ in 0..pad_len {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = b' ';
            pos += 1;
        }

        if negative {
            dst[pos] = b'-';
            pos += 1;
        } else if (spec.flags & FLAG_PLUS) != 0 {
            dst[pos] = b'+';
            pos += 1;
        } else if (spec.flags & FLAG_SPACE) != 0 {
            dst[pos] = b' ';
            pos += 1;
        }

        dst[pos..pos + len].copy_from_slice(&temp[..len]);
        pos += len;
    }

    pos
}

/// Format unsigned integer
fn format_unsigned(dst: &mut [u8], spec: &FormatSpec, value: usize, base: usize, uppercase: bool) -> usize {
    if dst.is_empty() {
        return 0;
    }

    let digits: &[u8] = if uppercase {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };

    // Build number in reverse
    let mut temp = [0u8; 32];
    let mut len = 0;
    let mut v = value;

    if v == 0 {
        temp[0] = b'0';
        len = 1;
    } else {
        while v > 0 && len < 32 {
            temp[len] = digits[v % base];
            v /= base;
            len += 1;
        }
    }

    // Handle precision (minimum digits)
    let min_digits = spec.precision.unwrap_or(1);
    let extra_zeros = if min_digits > len { min_digits - len } else { 0 };

    // Handle prefix for alternative form
    let prefix_len = if (spec.flags & FLAG_HASH) != 0 && value != 0 {
        match base {
            8 => 1,  // 0
            16 => 2, // 0x or 0X
            _ => 0,
        }
    } else {
        0
    };

    let total_len = len + extra_zeros + prefix_len;
    let pad_len = if spec.width > total_len { spec.width - total_len } else { 0 };

    let mut pos = 0;

    // Handle padding and output
    if (spec.flags & FLAG_MINUS) != 0 {
        // Left-justify
        // Prefix
        if prefix_len == 2 {
            dst[pos] = b'0';
            dst[pos + 1] = if uppercase { b'X' } else { b'x' };
            pos += 2;
        } else if prefix_len == 1 {
            dst[pos] = b'0';
            pos += 1;
        }

        // Extra zeros
        for _ in 0..extra_zeros {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = b'0';
            pos += 1;
        }

        // Digits (in reverse)
        for i in (0..len).rev() {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = temp[i];
            pos += 1;
        }

        // Padding
        for _ in 0..pad_len {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = b' ';
            pos += 1;
        }
    } else if (spec.flags & FLAG_ZERO) != 0 && spec.precision.is_none() {
        // Right-justify with zeros
        // Prefix first
        if prefix_len == 2 {
            dst[pos] = b'0';
            dst[pos + 1] = if uppercase { b'X' } else { b'x' };
            pos += 2;
        } else if prefix_len == 1 {
            dst[pos] = b'0';
            pos += 1;
        }

        // Padding zeros
        for _ in 0..pad_len {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = b'0';
            pos += 1;
        }

        // Digits (in reverse)
        for i in (0..len).rev() {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = temp[i];
            pos += 1;
        }
    } else {
        // Right-justify with spaces
        for _ in 0..pad_len {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = b' ';
            pos += 1;
        }

        // Prefix
        if prefix_len == 2 {
            dst[pos] = b'0';
            dst[pos + 1] = if uppercase { b'X' } else { b'x' };
            pos += 2;
        } else if prefix_len == 1 {
            dst[pos] = b'0';
            pos += 1;
        }

        // Extra zeros
        for _ in 0..extra_zeros {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = b'0';
            pos += 1;
        }

        // Digits (in reverse)
        for i in (0..len).rev() {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = temp[i];
            pos += 1;
        }
    }

    pos
}

/// Format string
fn format_string(dst: &mut [u8], spec: &FormatSpec, ptr: usize) -> usize {
    if dst.is_empty() {
        return 0;
    }

    // In a real implementation, ptr would be a pointer to the string
    // For now, we'll just output "(string)" as a placeholder
    let placeholder = b"(string)";
    let str_len = if let Some(prec) = spec.precision {
        prec.min(placeholder.len())
    } else {
        placeholder.len()
    };

    let pad_len = if spec.width > str_len { spec.width - str_len } else { 0 };
    let mut pos = 0;

    if (spec.flags & FLAG_MINUS) != 0 {
        // Left-justify
        let copy_len = str_len.min(dst.len() - 1);
        dst[..copy_len].copy_from_slice(&placeholder[..copy_len]);
        pos = copy_len;

        for _ in 0..pad_len {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = b' ';
            pos += 1;
        }
    } else {
        // Right-justify
        for _ in 0..pad_len {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = b' ';
            pos += 1;
        }

        let copy_len = str_len.min(dst.len() - 1 - pos);
        dst[pos..pos + copy_len].copy_from_slice(&placeholder[..copy_len]);
        pos += copy_len;
    }

    let _ = ptr;
    pos
}

/// Format single character
fn format_char(dst: &mut [u8], c: u8) -> usize {
    if dst.is_empty() {
        return 0;
    }

    dst[0] = c;
    1
}

/// Format pointer
fn format_pointer(dst: &mut [u8], ptr: usize) -> usize {
    if dst.is_empty() {
        return 0;
    }

    // Format as 0xXXXXXXXX
    let mut pos = 0;

    if dst.len() > 2 {
        dst[0] = b'0';
        dst[1] = b'x';
        pos = 2;
    }

    let spec = FormatSpec {
        flags: FLAG_ZERO,
        width: 8, // Assuming 32-bit, use 16 for 64-bit
        precision: None,
        size: 0,
        conversion: b'X',
    };

    pos += format_unsigned(&mut dst[pos..], &spec, ptr, 16, true);
    pos
}

// ============================================================================
// Number Formatting
// ============================================================================

/// Format a number with grouping (e.g., 1,234,567)
pub fn format_number(dst: &mut [u8], value: i64, format: &NumberFormat) -> usize {
    if dst.is_empty() {
        return 0;
    }

    let negative = value < 0;
    let abs_val = if negative { (-value) as u64 } else { value as u64 };

    // Build integer part in reverse
    let mut int_part = [0u8; 32];
    let mut int_len = 0;
    let mut v = abs_val;

    if v == 0 {
        int_part[0] = b'0';
        int_len = 1;
    } else {
        let grouping = format.grouping as usize;
        let mut group_count = 0;

        while v > 0 {
            if grouping > 0 && group_count == grouping && int_len < 31 {
                // Add thousands separator
                int_part[int_len] = format.thousand_sep[0];
                int_len += 1;
                group_count = 0;
            }

            if int_len < 32 {
                int_part[int_len] = (v % 10) as u8 + b'0';
                int_len += 1;
                v /= 10;
                group_count += 1;
            } else {
                break;
            }
        }
    }

    // Build output
    let mut pos = 0;

    // Handle negative
    if negative {
        match format.negative_order {
            0 => {
                // (-1.1)
                if pos < dst.len() - 1 {
                    dst[pos] = b'(';
                    pos += 1;
                }
            }
            1 | _ => {
                // -1.1
                if pos < dst.len() - 1 {
                    dst[pos] = b'-';
                    pos += 1;
                }
            }
        }
    }

    // Copy integer part (reversed)
    for i in (0..int_len).rev() {
        if pos >= dst.len() - 1 { break; }
        dst[pos] = int_part[i];
        pos += 1;
    }

    // Add decimal part if num_digits > 0
    if format.num_digits > 0 {
        if pos < dst.len() - 1 {
            dst[pos] = format.decimal_sep[0];
            pos += 1;
        }

        for _ in 0..format.num_digits {
            if pos >= dst.len() - 1 { break; }
            dst[pos] = b'0';
            pos += 1;
        }
    }

    // Close parenthesis for negative
    if negative && format.negative_order == 0 {
        if pos < dst.len() - 1 {
            dst[pos] = b')';
            pos += 1;
        }
    }

    if pos < dst.len() {
        dst[pos] = 0;
    }

    pos
}

// ============================================================================
// FormatMessage Style Formatting
// ============================================================================

/// FormatMessage style formatting
/// Supports: %0 (null), %n (newline), %1-%99 (arguments)
pub fn format_message(dst: &mut [u8], format: &[u8], args: &[&[u8]]) -> usize {
    if dst.is_empty() {
        return 0;
    }

    let fmt_len = strhelp::str_len(format);
    let mut dst_pos = 0;
    let mut fmt_pos = 0;

    while fmt_pos < fmt_len && dst_pos < dst.len() - 1 {
        if format[fmt_pos] == b'%' {
            fmt_pos += 1;
            if fmt_pos >= fmt_len {
                break;
            }

            match format[fmt_pos] {
                b'0' => {
                    // %0 - null terminator (end of message)
                    break;
                }
                b'n' => {
                    // %n - newline
                    if dst_pos < dst.len() - 1 {
                        dst[dst_pos] = b'\n';
                        dst_pos += 1;
                    }
                    fmt_pos += 1;
                }
                b'%' => {
                    // %% - literal percent
                    if dst_pos < dst.len() - 1 {
                        dst[dst_pos] = b'%';
                        dst_pos += 1;
                    }
                    fmt_pos += 1;
                }
                b'1'..=b'9' => {
                    // %1 through %99 - argument substitution
                    let mut arg_num = (format[fmt_pos] - b'0') as usize;
                    fmt_pos += 1;

                    // Check for second digit
                    if fmt_pos < fmt_len && strhelp::is_digit(format[fmt_pos]) {
                        arg_num = arg_num * 10 + (format[fmt_pos] - b'0') as usize;
                        fmt_pos += 1;
                    }

                    // Insert argument (1-based index)
                    if arg_num > 0 && arg_num <= args.len() {
                        let arg = args[arg_num - 1];
                        let arg_len = strhelp::str_len(arg);
                        let copy_len = arg_len.min(dst.len() - 1 - dst_pos);
                        dst[dst_pos..dst_pos + copy_len].copy_from_slice(&arg[..copy_len]);
                        dst_pos += copy_len;
                    }
                }
                _ => {
                    // Unknown format, output literally
                    if dst_pos < dst.len() - 1 {
                        dst[dst_pos] = b'%';
                        dst_pos += 1;
                    }
                }
            }
        } else {
            dst[dst_pos] = format[fmt_pos];
            dst_pos += 1;
            fmt_pos += 1;
        }
    }

    dst[dst_pos] = 0;
    dst_pos
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize format helpers
pub fn init() {
    crate::serial_println!("[USER] Format helpers initialized");
}
