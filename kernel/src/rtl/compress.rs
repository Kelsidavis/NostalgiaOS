//! LZNT1 Compression Engine
//!
//! This module implements the LZNT1 compression algorithm used by Windows NT
//! for NTFS file compression and hibernation. LZNT1 is a variant of LZ77
//! that processes data in 4KB chunks.
//!
//! # Chunk Format
//!
//! Each compressed chunk consists of:
//! - 2-byte header (size, signature, compressed flag)
//! - Sequence of flag bytes followed by data elements
//!
//! # Copy Token Format
//!
//! The copy token uses a sliding format where the displacement/length
//! bit allocation changes based on position within the chunk:
//!
//! | Position | Length bits | Displacement bits | Max displacement |
//! |----------|------------|-------------------|------------------|
//! | 0-15     | 12         | 4                 | 16               |
//! | 16-31    | 11         | 5                 | 32               |
//! | 32-63    | 10         | 6                 | 64               |
//! | ...      | ...        | ...               | ...              |
//! | 2048+    | 4          | 12                | 4096             |

/// RTL Compression/Decompression status codes
///
/// These match the NTSTATUS codes used by the Windows NT RTL compression APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RtlStatus {
    /// Operation completed successfully
    Success = 0,
    /// Buffer contains all zeros (successful compression, special case)
    BufferAllZeros = 0x00000117,
    /// Invalid parameter was passed
    InvalidParameter = -0x3FFFFFF3_i32, // 0xC000000D
    /// The compression format is not supported
    UnsupportedCompression = -0x3FFFFD9C_i32, // 0xC0000264
    /// The compressed buffer is malformed
    BadCompressionBuffer = -0x3FFFFDBE_i32, // 0xC0000242
    /// Buffer is too small for the operation
    BufferTooSmall = -0x3FFFFFDD_i32, // 0xC0000023
    /// No more entries available
    NoMoreEntries = -0x7FFFFFE6_i32, // 0x8000001A
    /// Not supported
    NotSupported = -0x3FFFFF45_i32, // 0xC00000BB
}

/// Maximum uncompressed chunk size (4KB)
pub const MAX_UNCOMPRESSED_CHUNK_SIZE: usize = 4096;

/// Compression format constants
pub const COMPRESSION_FORMAT_NONE: u16 = 0;
pub const COMPRESSION_FORMAT_DEFAULT: u16 = 1;
pub const COMPRESSION_FORMAT_LZNT1: u16 = 2;

/// Compression engine constants
pub const COMPRESSION_ENGINE_STANDARD: u16 = 0x0000;
pub const COMPRESSION_ENGINE_MAXIMUM: u16 = 0x0100;
pub const COMPRESSION_ENGINE_HIBER: u16 = 0x0200;

/// Compressed chunk header
///
/// The header is a 16-bit value with:
/// - Bits 0-11: Compressed size minus 3
/// - Bits 12-14: Chunk signature (must be 3)
/// - Bit 15: Is chunk compressed flag
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CompressedChunkHeader {
    value: u16,
}

impl CompressedChunkHeader {
    /// Create a new chunk header
    #[inline]
    pub fn new(compressed_size: u16, is_compressed: bool) -> Self {
        debug_assert!(compressed_size >= 4 && compressed_size <= 4098);
        let size_field = (compressed_size - 3) & 0x0FFF;
        let signature = 3u16 << 12;
        let compressed_flag = if is_compressed { 1u16 << 15 } else { 0 };
        Self {
            value: size_field | signature | compressed_flag,
        }
    }

    /// Get the compressed chunk size
    #[inline]
    pub fn compressed_size(&self) -> u16 {
        (self.value & 0x0FFF) + 3
    }

    /// Get the chunk signature (should be 3)
    #[inline]
    pub fn signature(&self) -> u16 {
        (self.value >> 12) & 0x07
    }

    /// Check if the chunk is compressed
    #[inline]
    pub fn is_compressed(&self) -> bool {
        (self.value & 0x8000) != 0
    }

    /// Check if this is an end marker (zero header)
    #[inline]
    pub fn is_end(&self) -> bool {
        self.value == 0
    }

    /// Get raw value
    #[inline]
    pub fn raw(&self) -> u16 {
        self.value
    }

    /// Create from raw value
    #[inline]
    pub fn from_raw(value: u16) -> Self {
        Self { value }
    }
}

/// Copy token format indices
const FORMAT_4_12: usize = 0; // 12-bit length, 4-bit displacement
const FORMAT_5_11: usize = 1;
const FORMAT_6_10: usize = 2;
const FORMAT_7_9: usize = 3;
const FORMAT_8_8: usize = 4;
const FORMAT_9_7: usize = 5;
const FORMAT_10_6: usize = 6;
const FORMAT_11_5: usize = 7;
const FORMAT_12_4: usize = 8; // 4-bit length, 12-bit displacement

/// Maximum length for each format (length + 3)
const FORMAT_MAX_LENGTH: [usize; 9] = [4098, 2050, 1026, 514, 258, 130, 66, 34, 18];

/// Maximum displacement for each format
const FORMAT_MAX_DISPLACEMENT: [usize; 9] = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

/// Workspace size for standard compression (includes hash table)
pub const STANDARD_WORKSPACE_SIZE: usize = 4096 * 2 * core::mem::size_of::<usize>() + 32;

/// Workspace size for decompression fragment
pub const FRAGMENT_WORKSPACE_SIZE: usize = 4096;

/// Get the format index for a given position in the uncompressed buffer
#[inline]
fn get_format_for_position(position: usize) -> usize {
    for (i, &max_disp) in FORMAT_MAX_DISPLACEMENT.iter().enumerate() {
        if position < max_disp {
            return i;
        }
    }
    FORMAT_12_4
}

/// Extract length from copy token given the format
#[inline]
fn get_copy_length(format: usize, token: u16) -> usize {
    let length_bits = 12 - format;
    let length_mask = (1u16 << length_bits) - 1;
    ((token & length_mask) + 3) as usize
}

/// Extract displacement from copy token given the format
#[inline]
fn get_copy_displacement(format: usize, token: u16) -> usize {
    let length_bits = 12 - format;
    let displacement = (token >> length_bits) + 1;
    displacement as usize
}

/// Create a copy token from length and displacement
#[inline]
fn make_copy_token(format: usize, length: usize, displacement: usize) -> u16 {
    let length_bits = 12 - format;
    let length_field = ((length - 3) as u16) & ((1u16 << length_bits) - 1);
    let displacement_field = ((displacement - 1) as u16) << length_bits;
    length_field | displacement_field
}

/// Get compression workspace size
///
/// Returns the required workspace sizes for compression.
///
/// # Arguments
/// * `format_and_engine` - Compression format and engine flags
/// * `compress_buffer_size` - Receives workspace size for buffer compression
/// * `compress_fragment_size` - Receives workspace size for fragment decompression
pub fn rtl_get_compression_workspace_size(
    format_and_engine: u16,
    compress_buffer_size: &mut u32,
    compress_fragment_size: &mut u32,
) -> RtlStatus {
    let format = format_and_engine & 0x00FF;
    let engine = format_and_engine & 0xFF00;

    if format == COMPRESSION_FORMAT_NONE || format == COMPRESSION_FORMAT_DEFAULT {
        return RtlStatus::InvalidParameter;
    }

    if format != COMPRESSION_FORMAT_LZNT1 {
        return RtlStatus::UnsupportedCompression;
    }

    match engine {
        COMPRESSION_ENGINE_STANDARD | COMPRESSION_ENGINE_MAXIMUM => {
            *compress_buffer_size = STANDARD_WORKSPACE_SIZE as u32;
            *compress_fragment_size = FRAGMENT_WORKSPACE_SIZE as u32;
            RtlStatus::Success
        }
        COMPRESSION_ENGINE_HIBER => {
            *compress_buffer_size = 4096 * 4; // Index table
            *compress_fragment_size = FRAGMENT_WORKSPACE_SIZE as u32;
            RtlStatus::Success
        }
        _ => RtlStatus::NotSupported,
    }
}

/// Decompress a single LZNT1 chunk
///
/// # Arguments
/// * `uncompressed` - Output buffer for uncompressed data
/// * `compressed` - Input compressed chunk (excluding header)
///
/// # Returns
/// Number of bytes written to uncompressed buffer, or error
fn lznt1_decompress_chunk(
    uncompressed: &mut [u8],
    compressed: &[u8],
) -> Result<usize, RtlStatus> {
    if compressed.is_empty() {
        return Ok(0);
    }

    let mut output_pos = 0;
    let mut input_pos = 0;

    // Get first flag byte
    let mut flag_byte = compressed[input_pos];
    input_pos += 1;
    let mut flag_bit = 0;

    while output_pos < uncompressed.len() && input_pos < compressed.len() {
        // Determine the format based on current output position
        let format = get_format_for_position(output_pos);

        // Check the current flag bit
        if (flag_byte & (1 << flag_bit)) == 0 {
            // Literal byte
            uncompressed[output_pos] = compressed[input_pos];
            output_pos += 1;
            input_pos += 1;
        } else {
            // Copy token (2 bytes)
            if input_pos + 1 >= compressed.len() {
                return Err(RtlStatus::BadCompressionBuffer);
            }

            let token = u16::from_le_bytes([compressed[input_pos], compressed[input_pos + 1]]);
            input_pos += 2;

            let displacement = get_copy_displacement(format, token);
            let length = get_copy_length(format, token);

            // Validate displacement
            if displacement > output_pos {
                return Err(RtlStatus::BadCompressionBuffer);
            }

            // Adjust length to not overflow output buffer
            let copy_len = length.min(uncompressed.len() - output_pos);

            // Copy bytes (must handle overlapping copy for RLE-like patterns)
            for _ in 0..copy_len {
                uncompressed[output_pos] = uncompressed[output_pos - displacement];
                output_pos += 1;
            }
        }

        // Advance to next flag bit
        flag_bit = (flag_bit + 1) % 8;
        if flag_bit == 0 && input_pos < compressed.len() {
            flag_byte = compressed[input_pos];
            input_pos += 1;
        }
    }

    Ok(output_pos)
}

/// Decompress an LZNT1 compressed buffer
///
/// # Arguments
/// * `format` - Compression format (must be COMPRESSION_FORMAT_LZNT1)
/// * `uncompressed` - Output buffer for uncompressed data
/// * `compressed` - Input compressed buffer
/// * `final_size` - Receives the final uncompressed size
pub fn rtl_decompress_buffer(
    format: u16,
    uncompressed: &mut [u8],
    compressed: &[u8],
    final_size: &mut u32,
) -> RtlStatus {
    let format_val = format & 0x00FF;

    if format_val == COMPRESSION_FORMAT_NONE || format_val == COMPRESSION_FORMAT_DEFAULT {
        return RtlStatus::InvalidParameter;
    }

    if format_val != COMPRESSION_FORMAT_LZNT1 {
        return RtlStatus::UnsupportedCompression;
    }

    *final_size = 0;

    let mut compressed_pos = 0;
    let mut uncompressed_pos = 0;

    while compressed_pos + 2 <= compressed.len() && uncompressed_pos < uncompressed.len() {
        // Read chunk header
        let header = CompressedChunkHeader::from_raw(
            u16::from_le_bytes([compressed[compressed_pos], compressed[compressed_pos + 1]])
        );

        // Check for end marker
        if header.is_end() {
            break;
        }

        // Validate signature
        if header.signature() != 3 {
            return RtlStatus::BadCompressionBuffer;
        }

        let chunk_size = header.compressed_size() as usize;

        // Validate chunk fits in input
        if compressed_pos + chunk_size > compressed.len() {
            return RtlStatus::BadCompressionBuffer;
        }

        if header.is_compressed() {
            // Decompress the chunk
            let chunk_data = &compressed[compressed_pos + 2..compressed_pos + chunk_size];
            let output_slice = &mut uncompressed[uncompressed_pos..];
            let max_output = output_slice.len().min(MAX_UNCOMPRESSED_CHUNK_SIZE);

            match lznt1_decompress_chunk(&mut output_slice[..max_output], chunk_data) {
                Ok(decompressed_size) => {
                    uncompressed_pos += decompressed_size;
                }
                Err(status) => return status,
            }
        } else {
            // Uncompressed chunk - just copy
            let data_size = (chunk_size - 2).min(MAX_UNCOMPRESSED_CHUNK_SIZE);
            let copy_size = data_size.min(uncompressed.len() - uncompressed_pos);

            let src = &compressed[compressed_pos + 2..compressed_pos + 2 + copy_size];
            uncompressed[uncompressed_pos..uncompressed_pos + copy_size].copy_from_slice(src);
            uncompressed_pos += copy_size;
        }

        compressed_pos += chunk_size;
    }

    *final_size = uncompressed_pos as u32;
    RtlStatus::Success
}

/// Decompress a fragment from an LZNT1 compressed buffer
///
/// This function extracts a specific portion of the uncompressed data
/// without decompressing the entire buffer.
///
/// # Arguments
/// * `format` - Compression format
/// * `uncompressed` - Output buffer for the fragment
/// * `compressed` - Input compressed buffer
/// * `fragment_offset` - Offset within the uncompressed data
/// * `final_size` - Receives the size of the extracted fragment
/// * `workspace` - Temporary workspace buffer (at least FRAGMENT_WORKSPACE_SIZE)
pub fn rtl_decompress_fragment(
    format: u16,
    uncompressed: &mut [u8],
    compressed: &[u8],
    fragment_offset: u32,
    final_size: &mut u32,
    workspace: &mut [u8],
) -> RtlStatus {
    let format_val = format & 0x00FF;

    if format_val == COMPRESSION_FORMAT_NONE || format_val == COMPRESSION_FORMAT_DEFAULT {
        return RtlStatus::InvalidParameter;
    }

    if format_val != COMPRESSION_FORMAT_LZNT1 {
        return RtlStatus::UnsupportedCompression;
    }

    *final_size = 0;

    if workspace.len() < FRAGMENT_WORKSPACE_SIZE {
        return RtlStatus::BufferTooSmall;
    }

    let mut compressed_pos = 0;
    let mut fragment_offset = fragment_offset;
    let mut output_pos = 0;

    // Skip chunks until we reach the one containing our fragment
    while compressed_pos + 2 <= compressed.len() {
        let header = CompressedChunkHeader::from_raw(
            u16::from_le_bytes([compressed[compressed_pos], compressed[compressed_pos + 1]])
        );

        if header.is_end() {
            break;
        }

        if header.signature() != 3 {
            return RtlStatus::BadCompressionBuffer;
        }

        let chunk_size = header.compressed_size() as usize;

        if compressed_pos + chunk_size > compressed.len() {
            return RtlStatus::BadCompressionBuffer;
        }

        // Check if fragment starts in this chunk
        if fragment_offset >= MAX_UNCOMPRESSED_CHUNK_SIZE as u32 {
            fragment_offset -= MAX_UNCOMPRESSED_CHUNK_SIZE as u32;
            compressed_pos += chunk_size;
            continue;
        }

        // We're in the right chunk now - decompress and extract
        let chunk_data = &compressed[compressed_pos + 2..compressed_pos + chunk_size];

        if header.is_compressed() {
            // Decompress into workspace
            match lznt1_decompress_chunk(workspace, chunk_data) {
                Ok(decompressed_size) => {
                    let start = fragment_offset as usize;
                    if start < decompressed_size {
                        let copy_len = (decompressed_size - start).min(uncompressed.len() - output_pos);
                        uncompressed[output_pos..output_pos + copy_len]
                            .copy_from_slice(&workspace[start..start + copy_len]);
                        output_pos += copy_len;
                    }
                }
                Err(status) => return status,
            }
        } else {
            // Uncompressed chunk
            let start = fragment_offset as usize;
            let data_len = chunk_size - 2;
            if start < data_len {
                let copy_len = (data_len - start).min(uncompressed.len() - output_pos);
                let src_start = compressed_pos + 2 + start;
                uncompressed[output_pos..output_pos + copy_len]
                    .copy_from_slice(&compressed[src_start..src_start + copy_len]);
                output_pos += copy_len;
            }
        }

        // Reset fragment offset for subsequent chunks
        fragment_offset = 0;
        compressed_pos += chunk_size;

        // Check if we've filled the output buffer
        if output_pos >= uncompressed.len() {
            break;
        }
    }

    *final_size = output_pos as u32;
    RtlStatus::Success
}

/// Compress a single chunk using LZNT1
///
/// Returns the compressed chunk size, or 0 if compression failed/not beneficial
fn lznt1_compress_chunk(
    uncompressed: &[u8],
    compressed: &mut [u8],
    workspace: &mut [usize],
) -> Result<usize, RtlStatus> {
    let input_len = uncompressed.len().min(MAX_UNCOMPRESSED_CHUNK_SIZE);

    // Need space for header + at least some data
    if compressed.len() < 4 {
        return Err(RtlStatus::BufferTooSmall);
    }

    // Clear workspace (hash table)
    for entry in workspace.iter_mut().take(4096 * 2) {
        *entry = usize::MAX;
    }

    let mut output_pos = 2; // Skip header
    let mut input_pos = 0;
    let mut flag_pos = output_pos;
    output_pos += 1;
    let mut flag_byte: u8 = 0;
    let mut flag_bit = 0;
    let mut all_zeros = true;

    // Maximum output size before giving up (must save at least 1 byte)
    let max_output = compressed.len().min(input_len + 1);

    while input_pos < input_len {
        // Calculate format based on position
        let format = get_format_for_position(input_pos);
        let max_length = FORMAT_MAX_LENGTH[format].min(input_len - input_pos);
        let max_displacement = FORMAT_MAX_DISPLACEMENT[format].min(input_pos);

        // Try to find a match (need at least 3 bytes)
        let mut best_length = 0;
        let mut best_displacement = 0;

        if input_pos + 3 <= input_len && max_displacement > 0 {
            // Compute hash for current position
            let hash = ((uncompressed[input_pos] as usize) << 4
                ^ (uncompressed[input_pos + 1] as usize)
                ^ ((uncompressed[input_pos + 2] as usize) << 4))
                & 0xFFF;

            // Check hash table entries
            for slot in 0..2 {
                let entry = workspace[hash * 2 + slot];
                if entry < input_pos && input_pos - entry <= max_displacement {
                    // Check for match
                    let mut len = 0;
                    while len < max_length
                        && input_pos + len < input_len
                        && uncompressed[entry + len] == uncompressed[input_pos + len]
                    {
                        len += 1;
                    }
                    if len >= 3 && len > best_length {
                        best_length = len;
                        best_displacement = input_pos - entry;
                    }
                }
            }

            // Update hash table
            workspace[hash * 2 + 1] = workspace[hash * 2];
            workspace[hash * 2] = input_pos;
        }

        if best_length >= 3 {
            // Output copy token
            if output_pos + 2 > max_output {
                // Compression not beneficial
                return Ok(0);
            }

            flag_byte |= 1 << flag_bit;
            let token = make_copy_token(format, best_length, best_displacement);
            compressed[output_pos] = token as u8;
            compressed[output_pos + 1] = (token >> 8) as u8;
            output_pos += 2;
            input_pos += best_length;
        } else {
            // Output literal
            if output_pos >= max_output {
                return Ok(0);
            }

            let byte = uncompressed[input_pos];
            if byte != 0 {
                all_zeros = false;
            }
            compressed[output_pos] = byte;
            output_pos += 1;
            input_pos += 1;
        }

        // Update flag
        flag_bit += 1;
        if flag_bit == 8 {
            compressed[flag_pos] = flag_byte;
            flag_byte = 0;
            flag_bit = 0;
            if input_pos < input_len {
                flag_pos = output_pos;
                output_pos += 1;
            }
        }
    }

    // Write final flag byte
    if flag_bit > 0 {
        compressed[flag_pos] = flag_byte;
    }

    // Check if compression was beneficial
    if output_pos >= input_len {
        return Ok(0);
    }

    // Write header
    let header = CompressedChunkHeader::new(output_pos as u16, true);
    compressed[0] = header.raw() as u8;
    compressed[1] = (header.raw() >> 8) as u8;

    if all_zeros {
        // Special case: return negative to indicate all zeros
        Ok(output_pos | 0x8000_0000)
    } else {
        Ok(output_pos)
    }
}

/// Compress a buffer using LZNT1
///
/// # Arguments
/// * `format_and_engine` - Compression format and engine flags
/// * `uncompressed` - Input uncompressed data
/// * `compressed` - Output buffer for compressed data
/// * `chunk_size` - Uncompressed chunk size (should be 4096)
/// * `final_size` - Receives the final compressed size
/// * `workspace` - Workspace buffer (get size from rtl_get_compression_workspace_size)
pub fn rtl_compress_buffer(
    format_and_engine: u16,
    uncompressed: &[u8],
    compressed: &mut [u8],
    _chunk_size: u32,
    final_size: &mut u32,
    workspace: &mut [u8],
) -> RtlStatus {
    let format = format_and_engine & 0x00FF;
    let _engine = format_and_engine & 0xFF00;

    if format == COMPRESSION_FORMAT_NONE || format == COMPRESSION_FORMAT_DEFAULT {
        return RtlStatus::InvalidParameter;
    }

    if format != COMPRESSION_FORMAT_LZNT1 {
        return RtlStatus::UnsupportedCompression;
    }

    *final_size = 0;

    // Convert workspace to usize slice for hash table
    let workspace_usize = unsafe {
        core::slice::from_raw_parts_mut(
            workspace.as_mut_ptr() as *mut usize,
            workspace.len() / core::mem::size_of::<usize>(),
        )
    };

    let mut input_pos = 0;
    let mut output_pos = 0;
    let mut all_zeros = true;

    while input_pos < uncompressed.len() {
        let chunk_end = (input_pos + MAX_UNCOMPRESSED_CHUNK_SIZE).min(uncompressed.len());
        let chunk = &uncompressed[input_pos..chunk_end];

        // Need at least header + data space
        if output_pos + 2 >= compressed.len() {
            return RtlStatus::BufferTooSmall;
        }

        let output_slice = &mut compressed[output_pos..];

        match lznt1_compress_chunk(chunk, output_slice, workspace_usize) {
            Ok(size) if size == 0 || (size & 0x7FFF_FFFF) >= chunk.len() + 2 => {
                // Compression not beneficial - store uncompressed
                let total_size = chunk.len() + 2;
                if output_pos + total_size > compressed.len() {
                    return RtlStatus::BufferTooSmall;
                }

                let header = CompressedChunkHeader::new(total_size as u16, false);
                compressed[output_pos] = header.raw() as u8;
                compressed[output_pos + 1] = (header.raw() >> 8) as u8;
                compressed[output_pos + 2..output_pos + 2 + chunk.len()].copy_from_slice(chunk);
                output_pos += total_size;

                // Check for zeros
                for &b in chunk {
                    if b != 0 {
                        all_zeros = false;
                        break;
                    }
                }
            }
            Ok(size) => {
                let actual_size = size & 0x7FFF_FFFF;
                if size & 0x8000_0000 == 0 {
                    all_zeros = false;
                }
                output_pos += actual_size;
            }
            Err(status) => return status,
        }

        input_pos = chunk_end;
    }

    // Write terminator if space permits
    if output_pos + 2 <= compressed.len() {
        compressed[output_pos] = 0;
        compressed[output_pos + 1] = 0;
    }

    *final_size = output_pos as u32;

    if all_zeros {
        RtlStatus::BufferAllZeros
    } else {
        RtlStatus::Success
    }
}

/// Describe the current chunk in a compressed buffer
///
/// # Arguments
/// * `format` - Compression format
/// * `compressed` - Compressed buffer starting at current chunk
/// * `chunk_buffer` - Receives pointer to chunk data
/// * `chunk_size` - Receives chunk size (0 for end of buffer)
pub fn rtl_describe_chunk(
    format: u16,
    compressed: &[u8],
    chunk_offset: &mut usize,
    chunk_size: &mut usize,
) -> RtlStatus {
    let format_val = format & 0x00FF;

    if format_val == COMPRESSION_FORMAT_NONE || format_val == COMPRESSION_FORMAT_DEFAULT {
        return RtlStatus::InvalidParameter;
    }

    if format_val != COMPRESSION_FORMAT_LZNT1 {
        return RtlStatus::UnsupportedCompression;
    }

    *chunk_size = 0;

    if compressed.len() < 4 {
        return RtlStatus::NoMoreEntries;
    }

    let header = CompressedChunkHeader::from_raw(
        u16::from_le_bytes([compressed[0], compressed[1]])
    );

    if header.is_end() {
        return RtlStatus::NoMoreEntries;
    }

    if header.signature() != 3 {
        return RtlStatus::BadCompressionBuffer;
    }

    let size = header.compressed_size() as usize;

    if size > compressed.len() {
        return RtlStatus::BadCompressionBuffer;
    }

    if header.is_compressed() {
        *chunk_offset = 2;
        *chunk_size = size - 2;
    } else {
        // Uncompressed chunk must be exactly 4098 bytes
        if size != MAX_UNCOMPRESSED_CHUNK_SIZE + 2 {
            return RtlStatus::BadCompressionBuffer;
        }
        *chunk_offset = 2;
        *chunk_size = MAX_UNCOMPRESSED_CHUNK_SIZE;
    }

    RtlStatus::Success
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_header() {
        let header = CompressedChunkHeader::new(100, true);
        assert_eq!(header.compressed_size(), 100);
        assert_eq!(header.signature(), 3);
        assert!(header.is_compressed());

        let header2 = CompressedChunkHeader::new(4098, false);
        assert_eq!(header2.compressed_size(), 4098);
        assert!(!header2.is_compressed());
    }

    #[test]
    fn test_copy_token() {
        // Test format 4/12 at position 0
        let token = make_copy_token(FORMAT_4_12, 5, 3);
        assert_eq!(get_copy_length(FORMAT_4_12, token), 5);
        assert_eq!(get_copy_displacement(FORMAT_4_12, token), 3);

        // Test format 12/4 at position 2048+
        let token2 = make_copy_token(FORMAT_12_4, 10, 1000);
        assert_eq!(get_copy_length(FORMAT_12_4, token2), 10);
        assert_eq!(get_copy_displacement(FORMAT_12_4, token2), 1000);
    }

    #[test]
    fn test_format_selection() {
        assert_eq!(get_format_for_position(0), FORMAT_4_12);
        assert_eq!(get_format_for_position(15), FORMAT_4_12);
        assert_eq!(get_format_for_position(16), FORMAT_5_11);
        assert_eq!(get_format_for_position(2048), FORMAT_12_4);
        assert_eq!(get_format_for_position(4000), FORMAT_12_4);
    }
}
