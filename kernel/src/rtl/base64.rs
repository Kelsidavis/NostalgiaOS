//! Base64 Encoding and Decoding
//!
//! RFC 4648 - The Base16, Base32, and Base64 Data Encodings
//! Standard Base64 encoding/decoding for binary data transport.

extern crate alloc;

use alloc::vec::Vec;

/// Base64 alphabet (RFC 4648 Table 1)
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 URL-safe alphabet (RFC 4648 Table 2)
const BASE64_URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Padding character
const PAD: u8 = b'=';

/// Decode table for standard Base64
const DECODE_TABLE: [i8; 256] = {
    let mut table = [-1i8; 256];
    let mut i = 0usize;
    while i < 64 {
        table[BASE64_ALPHABET[i] as usize] = i as i8;
        i += 1;
    }
    table
};

/// Decode table for URL-safe Base64
const DECODE_TABLE_URL: [i8; 256] = {
    let mut table = [-1i8; 256];
    let mut i = 0usize;
    while i < 64 {
        table[BASE64_URL_ALPHABET[i] as usize] = i as i8;
        i += 1;
    }
    table
};

/// Calculate encoded length
pub fn encoded_len(input_len: usize) -> usize {
    ((input_len + 2) / 3) * 4
}

/// Calculate maximum decoded length (before removing padding)
pub fn decoded_len(input_len: usize) -> usize {
    (input_len / 4) * 3
}

/// Encode binary data to Base64 string
///
/// # Arguments
/// * `input` - Binary data to encode
///
/// # Returns
/// Base64-encoded bytes (ASCII string)
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_with_alphabet(input, BASE64_ALPHABET, true)
}

/// Encode binary data to Base64 string without padding
pub fn encode_no_pad(input: &[u8]) -> Vec<u8> {
    encode_with_alphabet(input, BASE64_ALPHABET, false)
}

/// Encode binary data to URL-safe Base64 string
pub fn encode_url(input: &[u8]) -> Vec<u8> {
    encode_with_alphabet(input, BASE64_URL_ALPHABET, true)
}

/// Encode binary data to URL-safe Base64 string without padding
pub fn encode_url_no_pad(input: &[u8]) -> Vec<u8> {
    encode_with_alphabet(input, BASE64_URL_ALPHABET, false)
}

/// Encode with a specific alphabet
fn encode_with_alphabet(input: &[u8], alphabet: &[u8; 64], pad: bool) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }

    let output_len = if pad {
        encoded_len(input.len())
    } else {
        // Without padding: (input_len * 4 + 2) / 3
        (input.len() * 4 + 2) / 3
    };

    let mut output = Vec::with_capacity(output_len);

    // Process complete 3-byte groups
    let mut i = 0;
    while i + 3 <= input.len() {
        let b0 = input[i] as u32;
        let b1 = input[i + 1] as u32;
        let b2 = input[i + 2] as u32;

        // Combine into 24-bit value
        let n = (b0 << 16) | (b1 << 8) | b2;

        // Extract 4 6-bit groups
        output.push(alphabet[((n >> 18) & 0x3F) as usize]);
        output.push(alphabet[((n >> 12) & 0x3F) as usize]);
        output.push(alphabet[((n >> 6) & 0x3F) as usize]);
        output.push(alphabet[(n & 0x3F) as usize]);

        i += 3;
    }

    // Handle remaining bytes
    let remaining = input.len() - i;
    if remaining == 1 {
        let b0 = input[i] as u32;
        let n = b0 << 16;

        output.push(alphabet[((n >> 18) & 0x3F) as usize]);
        output.push(alphabet[((n >> 12) & 0x3F) as usize]);
        if pad {
            output.push(PAD);
            output.push(PAD);
        }
    } else if remaining == 2 {
        let b0 = input[i] as u32;
        let b1 = input[i + 1] as u32;
        let n = (b0 << 16) | (b1 << 8);

        output.push(alphabet[((n >> 18) & 0x3F) as usize]);
        output.push(alphabet[((n >> 12) & 0x3F) as usize]);
        output.push(alphabet[((n >> 6) & 0x3F) as usize]);
        if pad {
            output.push(PAD);
        }
    }

    output
}

/// Base64 decoding error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Invalid character in input
    InvalidChar(u8),
    /// Invalid input length
    InvalidLength,
    /// Invalid padding
    InvalidPadding,
}

/// Decode Base64 string to binary data
///
/// # Arguments
/// * `input` - Base64-encoded bytes (ASCII string)
///
/// # Returns
/// Decoded binary data or error
pub fn decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode_with_table(input, &DECODE_TABLE)
}

/// Decode URL-safe Base64 string to binary data
pub fn decode_url(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode_with_table(input, &DECODE_TABLE_URL)
}

/// Decode with a specific decode table
fn decode_with_table(input: &[u8], table: &[i8; 256]) -> Result<Vec<u8>, DecodeError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    // Count padding
    let mut padding = 0;
    let mut end = input.len();
    while end > 0 && input[end - 1] == PAD {
        padding += 1;
        end -= 1;
    }

    if padding > 2 {
        return Err(DecodeError::InvalidPadding);
    }

    // Input without padding
    let input = &input[..end];

    // Check length (should be 4n or 4n-padding after removing padding)
    let total_len = input.len() + padding;
    if total_len % 4 != 0 {
        // Allow unpadded input
        if padding == 0 && input.len() % 4 != 0 {
            // Unpadded input is allowed
        } else {
            return Err(DecodeError::InvalidLength);
        }
    }

    // Calculate output length
    let output_len = (input.len() * 3) / 4;
    let mut output = Vec::with_capacity(output_len);

    // Process complete 4-character groups
    let mut i = 0;
    while i + 4 <= input.len() {
        let c0 = table[input[i] as usize];
        let c1 = table[input[i + 1] as usize];
        let c2 = table[input[i + 2] as usize];
        let c3 = table[input[i + 3] as usize];

        if c0 < 0 { return Err(DecodeError::InvalidChar(input[i])); }
        if c1 < 0 { return Err(DecodeError::InvalidChar(input[i + 1])); }
        if c2 < 0 { return Err(DecodeError::InvalidChar(input[i + 2])); }
        if c3 < 0 { return Err(DecodeError::InvalidChar(input[i + 3])); }

        let n = ((c0 as u32) << 18) | ((c1 as u32) << 12) |
                ((c2 as u32) << 6) | (c3 as u32);

        output.push(((n >> 16) & 0xFF) as u8);
        output.push(((n >> 8) & 0xFF) as u8);
        output.push((n & 0xFF) as u8);

        i += 4;
    }

    // Handle remaining characters (with or without padding)
    let remaining = input.len() - i;
    if remaining == 2 {
        let c0 = table[input[i] as usize];
        let c1 = table[input[i + 1] as usize];

        if c0 < 0 { return Err(DecodeError::InvalidChar(input[i])); }
        if c1 < 0 { return Err(DecodeError::InvalidChar(input[i + 1])); }

        let n = ((c0 as u32) << 18) | ((c1 as u32) << 12);
        output.push(((n >> 16) & 0xFF) as u8);
    } else if remaining == 3 {
        let c0 = table[input[i] as usize];
        let c1 = table[input[i + 1] as usize];
        let c2 = table[input[i + 2] as usize];

        if c0 < 0 { return Err(DecodeError::InvalidChar(input[i])); }
        if c1 < 0 { return Err(DecodeError::InvalidChar(input[i + 1])); }
        if c2 < 0 { return Err(DecodeError::InvalidChar(input[i + 2])); }

        let n = ((c0 as u32) << 18) | ((c1 as u32) << 12) | ((c2 as u32) << 6);
        output.push(((n >> 16) & 0xFF) as u8);
        output.push(((n >> 8) & 0xFF) as u8);
    } else if remaining == 1 {
        return Err(DecodeError::InvalidLength);
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

    let encoded = encode(input);
    output[..encoded.len()].copy_from_slice(&encoded);
    Some(encoded.len())
}

/// Decode from slice to a fixed-size buffer
///
/// # Returns
/// Number of bytes written, or None if buffer too small or invalid input
pub fn decode_to_slice(input: &[u8], output: &mut [u8]) -> Option<usize> {
    let decoded = decode(input).ok()?;
    if output.len() < decoded.len() {
        return None;
    }

    output[..decoded.len()].copy_from_slice(&decoded);
    Some(decoded.len())
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
        assert_eq!(encode(b"f"), b"Zg==".to_vec());
        assert_eq!(encode(b"fo"), b"Zm8=".to_vec());
        assert_eq!(encode(b"foo"), b"Zm9v".to_vec());
        assert_eq!(encode(b"foob"), b"Zm9vYg==".to_vec());
        assert_eq!(encode(b"fooba"), b"Zm9vYmE=".to_vec());
        assert_eq!(encode(b"foobar"), b"Zm9vYmFy".to_vec());
    }

    #[test]
    fn test_decode_simple() {
        assert_eq!(decode(b"Zg==").unwrap(), b"f".to_vec());
        assert_eq!(decode(b"Zm8=").unwrap(), b"fo".to_vec());
        assert_eq!(decode(b"Zm9v").unwrap(), b"foo".to_vec());
        assert_eq!(decode(b"Zm9vYmFy").unwrap(), b"foobar".to_vec());
    }

    #[test]
    fn test_roundtrip() {
        let data = b"Hello, World!";
        let encoded = encode(data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data.to_vec());
    }

    #[test]
    fn test_no_padding() {
        assert_eq!(encode_no_pad(b"f"), b"Zg".to_vec());
        assert_eq!(encode_no_pad(b"fo"), b"Zm8".to_vec());
        assert_eq!(encode_no_pad(b"foo"), b"Zm9v".to_vec());
    }

    #[test]
    fn test_decode_no_padding() {
        assert_eq!(decode(b"Zg").unwrap(), b"f".to_vec());
        assert_eq!(decode(b"Zm8").unwrap(), b"fo".to_vec());
    }

    #[test]
    fn test_url_safe() {
        // Standard Base64 uses + and /
        // URL-safe uses - and _
        let data = [0xfb, 0xef, 0xfe]; // Would produce +/
        let standard = encode(&data);
        let url_safe = encode_url(&data);
        assert!(standard.contains(&b'+') || standard.contains(&b'/'));
        assert!(!url_safe.contains(&b'+') && !url_safe.contains(&b'/'));
    }
}
