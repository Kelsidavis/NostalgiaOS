//! Hexadecimal Encoding and Decoding
//!
//! Utilities for converting between binary data and hexadecimal strings.

extern crate alloc;

use alloc::vec::Vec;

/// Hexadecimal alphabet (lowercase)
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Hexadecimal alphabet (uppercase)
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Decode table for hex characters
const HEX_DECODE: [i8; 256] = {
    let mut table = [-1i8; 256];
    let mut i = 0u8;
    while i < 10 {
        table[(b'0' + i) as usize] = i as i8;
        i += 1;
    }
    let mut i = 0u8;
    while i < 6 {
        table[(b'a' + i) as usize] = (10 + i) as i8;
        table[(b'A' + i) as usize] = (10 + i) as i8;
        i += 1;
    }
    table
};

/// Calculate encoded length (2 hex chars per byte)
pub fn encoded_len(input_len: usize) -> usize {
    input_len * 2
}

/// Calculate decoded length
pub fn decoded_len(input_len: usize) -> usize {
    input_len / 2
}

/// Encode binary data to lowercase hexadecimal
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_with_alphabet(input, HEX_LOWER)
}

/// Encode binary data to uppercase hexadecimal
pub fn encode_upper(input: &[u8]) -> Vec<u8> {
    encode_with_alphabet(input, HEX_UPPER)
}

/// Encode with specific alphabet
fn encode_with_alphabet(input: &[u8], alphabet: &[u8; 16]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len() * 2);

    for &byte in input {
        output.push(alphabet[(byte >> 4) as usize]);
        output.push(alphabet[(byte & 0xF) as usize]);
    }

    output
}

/// Hex decoding error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Invalid character in input
    InvalidChar(u8),
    /// Odd number of characters
    OddLength,
}

/// Decode hexadecimal string to binary data
pub fn decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if input.len() % 2 != 0 {
        return Err(DecodeError::OddLength);
    }

    let mut output = Vec::with_capacity(input.len() / 2);

    for chunk in input.chunks(2) {
        let high = HEX_DECODE[chunk[0] as usize];
        let low = HEX_DECODE[chunk[1] as usize];

        if high < 0 {
            return Err(DecodeError::InvalidChar(chunk[0]));
        }
        if low < 0 {
            return Err(DecodeError::InvalidChar(chunk[1]));
        }

        output.push(((high as u8) << 4) | (low as u8));
    }

    Ok(output)
}

/// Encode to a fixed-size buffer
///
/// # Returns
/// Number of bytes written, or None if buffer too small
pub fn encode_to_slice(input: &[u8], output: &mut [u8]) -> Option<usize> {
    let needed = encoded_len(input.len());
    if output.len() < needed {
        return None;
    }

    for (i, &byte) in input.iter().enumerate() {
        output[i * 2] = HEX_LOWER[(byte >> 4) as usize];
        output[i * 2 + 1] = HEX_LOWER[(byte & 0xF) as usize];
    }

    Some(needed)
}

/// Encode to uppercase in a fixed-size buffer
pub fn encode_upper_to_slice(input: &[u8], output: &mut [u8]) -> Option<usize> {
    let needed = encoded_len(input.len());
    if output.len() < needed {
        return None;
    }

    for (i, &byte) in input.iter().enumerate() {
        output[i * 2] = HEX_UPPER[(byte >> 4) as usize];
        output[i * 2 + 1] = HEX_UPPER[(byte & 0xF) as usize];
    }

    Some(needed)
}

/// Decode from slice to a fixed-size buffer
///
/// # Returns
/// Number of bytes written, or None if buffer too small or invalid input
pub fn decode_to_slice(input: &[u8], output: &mut [u8]) -> Option<usize> {
    if input.len() % 2 != 0 {
        return None;
    }

    let needed = decoded_len(input.len());
    if output.len() < needed {
        return None;
    }

    for (i, chunk) in input.chunks(2).enumerate() {
        let high = HEX_DECODE[chunk[0] as usize];
        let low = HEX_DECODE[chunk[1] as usize];

        if high < 0 || low < 0 {
            return None;
        }

        output[i] = ((high as u8) << 4) | (low as u8);
    }

    Some(needed)
}

/// Format a single byte as two hex characters
#[inline]
pub fn byte_to_hex(byte: u8) -> [u8; 2] {
    [HEX_LOWER[(byte >> 4) as usize], HEX_LOWER[(byte & 0xF) as usize]]
}

/// Format a single byte as two uppercase hex characters
#[inline]
pub fn byte_to_hex_upper(byte: u8) -> [u8; 2] {
    [HEX_UPPER[(byte >> 4) as usize], HEX_UPPER[(byte & 0xF) as usize]]
}

/// Parse two hex characters to a byte
#[inline]
pub fn hex_to_byte(high: u8, low: u8) -> Option<u8> {
    let h = HEX_DECODE[high as usize];
    let l = HEX_DECODE[low as usize];

    if h < 0 || l < 0 {
        None
    } else {
        Some(((h as u8) << 4) | (l as u8))
    }
}

/// Check if a character is a valid hex digit
#[inline]
pub fn is_hex_digit(c: u8) -> bool {
    HEX_DECODE[c as usize] >= 0
}

/// Format bytes with a separator (e.g., "AA:BB:CC")
pub fn encode_with_separator(input: &[u8], separator: u8) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }

    let len = input.len() * 3 - 1; // 2 chars per byte + separators
    let mut output = Vec::with_capacity(len);

    for (i, &byte) in input.iter().enumerate() {
        if i > 0 {
            output.push(separator);
        }
        output.push(HEX_LOWER[(byte >> 4) as usize]);
        output.push(HEX_LOWER[(byte & 0xF) as usize]);
    }

    output
}

/// Decode bytes with separator removed
pub fn decode_with_separator(input: &[u8], separator: u8) -> Result<Vec<u8>, DecodeError> {
    // Filter out separators
    let filtered: Vec<u8> = input.iter()
        .filter(|&&c| c != separator)
        .copied()
        .collect();

    decode(&filtered)
}

// ============================================================================
// Convenience functions for common sizes
// ============================================================================

/// Encode u16 to hex string (4 chars)
pub fn u16_to_hex(value: u16) -> [u8; 4] {
    let bytes = value.to_be_bytes();
    [
        HEX_LOWER[(bytes[0] >> 4) as usize],
        HEX_LOWER[(bytes[0] & 0xF) as usize],
        HEX_LOWER[(bytes[1] >> 4) as usize],
        HEX_LOWER[(bytes[1] & 0xF) as usize],
    ]
}

/// Encode u32 to hex string (8 chars)
pub fn u32_to_hex(value: u32) -> [u8; 8] {
    let bytes = value.to_be_bytes();
    let mut output = [0u8; 8];
    for (i, &byte) in bytes.iter().enumerate() {
        output[i * 2] = HEX_LOWER[(byte >> 4) as usize];
        output[i * 2 + 1] = HEX_LOWER[(byte & 0xF) as usize];
    }
    output
}

/// Encode u64 to hex string (16 chars)
pub fn u64_to_hex(value: u64) -> [u8; 16] {
    let bytes = value.to_be_bytes();
    let mut output = [0u8; 16];
    for (i, &byte) in bytes.iter().enumerate() {
        output[i * 2] = HEX_LOWER[(byte >> 4) as usize];
        output[i * 2 + 1] = HEX_LOWER[(byte & 0xF) as usize];
    }
    output
}

/// Parse hex string to u16
pub fn hex_to_u16(input: &[u8]) -> Option<u16> {
    if input.len() != 4 {
        return None;
    }

    let mut result: u16 = 0;
    for &c in input {
        let digit = HEX_DECODE[c as usize];
        if digit < 0 {
            return None;
        }
        result = (result << 4) | (digit as u16);
    }
    Some(result)
}

/// Parse hex string to u32
pub fn hex_to_u32(input: &[u8]) -> Option<u32> {
    if input.len() != 8 {
        return None;
    }

    let mut result: u32 = 0;
    for &c in input {
        let digit = HEX_DECODE[c as usize];
        if digit < 0 {
            return None;
        }
        result = (result << 4) | (digit as u32);
    }
    Some(result)
}

/// Parse hex string to u64
pub fn hex_to_u64(input: &[u8]) -> Option<u64> {
    if input.len() != 16 {
        return None;
    }

    let mut result: u64 = 0;
    for &c in input {
        let digit = HEX_DECODE[c as usize];
        if digit < 0 {
            return None;
        }
        result = (result << 4) | (digit as u64);
    }
    Some(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_empty() {
        assert_eq!(encode(&[]), Vec::<u8>::new());
    }

    #[test]
    fn test_encode_simple() {
        assert_eq!(encode(&[0x00]), b"00".to_vec());
        assert_eq!(encode(&[0xff]), b"ff".to_vec());
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), b"deadbeef".to_vec());
    }

    #[test]
    fn test_encode_upper() {
        assert_eq!(encode_upper(&[0xde, 0xad]), b"DEAD".to_vec());
    }

    #[test]
    fn test_decode_simple() {
        assert_eq!(decode(b"00").unwrap(), vec![0x00]);
        assert_eq!(decode(b"ff").unwrap(), vec![0xff]);
        assert_eq!(decode(b"FF").unwrap(), vec![0xff]);
        assert_eq!(decode(b"deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_error() {
        assert_eq!(decode(b"0"), Err(DecodeError::OddLength));
        assert_eq!(decode(b"gg"), Err(DecodeError::InvalidChar(b'g')));
    }

    #[test]
    fn test_roundtrip() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_separator() {
        let data = [0xaa, 0xbb, 0xcc];
        let encoded = encode_with_separator(&data, b':');
        assert_eq!(encoded, b"aa:bb:cc".to_vec());

        let decoded = decode_with_separator(&encoded, b':').unwrap();
        assert_eq!(decoded, data);
    }
}
