//! Data Formatting Utilities
//!
//! Format data for display and logging purposes.
//! Provides hex dumps, size formatting, and other utilities.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Format bytes as a human-readable size (KB, MB, GB, etc.)
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];

    if bytes == 0 {
        return String::from("0 B");
    }

    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        // Bytes - no decimal
        alloc::format!("{} {}", bytes, UNITS[unit_idx])
    } else if size >= 100.0 {
        // Large number - no decimal
        alloc::format!("{:.0} {}", size, UNITS[unit_idx])
    } else if size >= 10.0 {
        // Medium number - 1 decimal
        alloc::format!("{:.1} {}", size, UNITS[unit_idx])
    } else {
        // Small number - 2 decimals
        alloc::format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

/// Format bytes as a hex dump (classic format)
///
/// Output format:
/// ```text
/// 00000000  48 65 6C 6C 6F 2C 20 57  6F 72 6C 64 21 0A 00 00  |Hello, World!...|
/// ```
pub fn hex_dump(data: &[u8], offset: usize) -> String {
    let mut output = String::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        // Address
        output.push_str(&alloc::format!("{:08X}  ", offset + i * 16));

        // Hex bytes (first 8)
        for (j, &byte) in chunk.iter().take(8).enumerate() {
            output.push_str(&alloc::format!("{:02X} ", byte));
            if j == 7 {
                output.push(' ');
            }
        }

        // Hex bytes (next 8)
        for (j, &byte) in chunk.iter().skip(8).take(8).enumerate() {
            output.push_str(&alloc::format!("{:02X} ", byte));
            if j == 7 && chunk.len() > 8 {
                output.push(' ');
            }
        }

        // Pad if less than 16 bytes
        let padding = 16 - chunk.len();
        for _ in 0..padding {
            output.push_str("   ");
        }
        if chunk.len() <= 8 {
            output.push(' ');
        }

        // ASCII representation
        output.push_str(" |");
        for &byte in chunk {
            if byte >= 0x20 && byte < 0x7F {
                output.push(byte as char);
            } else {
                output.push('.');
            }
        }
        for _ in 0..padding {
            output.push(' ');
        }
        output.push_str("|\n");
    }

    output
}

/// Format bytes as a compact hex string
pub fn hex_string(data: &[u8]) -> String {
    let mut output = String::with_capacity(data.len() * 2);
    for &byte in data {
        output.push_str(&alloc::format!("{:02x}", byte));
    }
    output
}

/// Format bytes as a hex string with separator
pub fn hex_string_with_sep(data: &[u8], sep: char) -> String {
    let mut output = String::with_capacity(data.len() * 3);
    for (i, &byte) in data.iter().enumerate() {
        if i > 0 {
            output.push(sep);
        }
        output.push_str(&alloc::format!("{:02X}", byte));
    }
    output
}

/// Format a duration in seconds as human readable
pub fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        alloc::format!("{}s", seconds)
    } else if seconds < 3600 {
        let m = seconds / 60;
        let s = seconds % 60;
        if s == 0 {
            alloc::format!("{}m", m)
        } else {
            alloc::format!("{}m {}s", m, s)
        }
    } else if seconds < 86400 {
        let h = seconds / 3600;
        let m = (seconds % 3600) / 60;
        if m == 0 {
            alloc::format!("{}h", h)
        } else {
            alloc::format!("{}h {}m", h, m)
        }
    } else {
        let d = seconds / 86400;
        let h = (seconds % 86400) / 3600;
        if h == 0 {
            alloc::format!("{}d", d)
        } else {
            alloc::format!("{}d {}h", d, h)
        }
    }
}

/// Format a number with thousand separators
pub fn format_number(n: u64) -> String {
    let s = alloc::format!("{}", n);
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();

    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }

    result
}

/// Format bytes as rate (e.g., "1.5 MB/s")
pub fn format_rate(bytes_per_second: u64) -> String {
    let size = format_size(bytes_per_second);
    alloc::format!("{}/s", size)
}

/// Format a percentage
pub fn format_percent(value: u64, total: u64) -> String {
    if total == 0 {
        return String::from("0%");
    }
    let percent = (value * 100) / total;
    alloc::format!("{}%", percent)
}

/// Format a percentage with decimals
pub fn format_percent_precise(value: u64, total: u64) -> String {
    if total == 0 {
        return String::from("0.00%");
    }
    let percent = (value as f64 * 100.0) / total as f64;
    alloc::format!("{:.2}%", percent)
}

/// Truncate a string with ellipsis
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        String::from(s)
    } else if max_len <= 3 {
        String::from(&s[..max_len])
    } else {
        let mut result = String::from(&s[..max_len - 3]);
        result.push_str("...");
        result
    }
}

/// Pad a string on the left
pub fn pad_left(s: &str, width: usize, pad_char: char) -> String {
    if s.len() >= width {
        String::from(s)
    } else {
        let padding: String = core::iter::repeat(pad_char).take(width - s.len()).collect();
        alloc::format!("{}{}", padding, s)
    }
}

/// Pad a string on the right
pub fn pad_right(s: &str, width: usize, pad_char: char) -> String {
    if s.len() >= width {
        String::from(s)
    } else {
        let padding: String = core::iter::repeat(pad_char).take(width - s.len()).collect();
        alloc::format!("{}{}", s, padding)
    }
}

/// Center a string
pub fn center(s: &str, width: usize, pad_char: char) -> String {
    if s.len() >= width {
        String::from(s)
    } else {
        let total_padding = width - s.len();
        let left_padding = total_padding / 2;
        let right_padding = total_padding - left_padding;
        let left: String = core::iter::repeat(pad_char).take(left_padding).collect();
        let right: String = core::iter::repeat(pad_char).take(right_padding).collect();
        alloc::format!("{}{}{}", left, s, right)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(100), "100 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(1048576), "1.00 MB");
        assert_eq!(format_size(1073741824), "1.00 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(60), "1m");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(3660), "1h 1m");
        assert_eq!(format_duration(86400), "1d");
        assert_eq!(format_duration(90000), "1d 1h");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1000000), "1,000,000");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello...");
        assert_eq!(truncate("hi", 2), "hi");
    }
}
