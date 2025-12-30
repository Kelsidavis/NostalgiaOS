//! Cryptographic Hash Functions
//!
//! MD5 (RFC 1321) and SHA-1 (RFC 3174) implementations.
//! These match the Windows CryptoAPI hash functions.

/// MD5 hash output size in bytes
pub const MD5_DIGEST_SIZE: usize = 16;

/// SHA-1 hash output size in bytes
pub const SHA1_DIGEST_SIZE: usize = 20;

/// MD5 block size in bytes
const MD5_BLOCK_SIZE: usize = 64;

/// SHA-1 block size in bytes
const SHA1_BLOCK_SIZE: usize = 64;

/// MD5 hash context
#[derive(Clone)]
pub struct Md5Context {
    state: [u32; 4],
    count: u64,
    buffer: [u8; MD5_BLOCK_SIZE],
    buffer_len: usize,
}

impl Md5Context {
    /// Initial state values
    const INIT_STATE: [u32; 4] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
    ];

    /// Create a new MD5 context
    pub fn new() -> Self {
        Self {
            state: Self::INIT_STATE,
            count: 0,
            buffer: [0u8; MD5_BLOCK_SIZE],
            buffer_len: 0,
        }
    }

    /// Reset the context
    pub fn reset(&mut self) {
        self.state = Self::INIT_STATE;
        self.count = 0;
        self.buffer = [0u8; MD5_BLOCK_SIZE];
        self.buffer_len = 0;
    }

    /// Update hash with data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Process buffered data first
        if self.buffer_len > 0 {
            let space = MD5_BLOCK_SIZE - self.buffer_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset = to_copy;

            if self.buffer_len == MD5_BLOCK_SIZE {
                self.transform(&self.buffer.clone());
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while offset + MD5_BLOCK_SIZE <= data.len() {
            let block: [u8; MD5_BLOCK_SIZE] = data[offset..offset + MD5_BLOCK_SIZE]
                .try_into()
                .unwrap();
            self.transform(&block);
            offset += MD5_BLOCK_SIZE;
        }

        // Buffer remaining data
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }

        self.count += data.len() as u64;
    }

    /// Finalize and get digest
    pub fn finalize(&mut self) -> [u8; MD5_DIGEST_SIZE] {
        let bits = self.count * 8;

        // Padding
        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };

        let mut padding = [0u8; 72];
        padding[0] = 0x80;

        // Length in little-endian
        padding[pad_len..pad_len + 8].copy_from_slice(&bits.to_le_bytes());

        self.update(&padding[..pad_len + 8]);

        // Output digest
        let mut digest = [0u8; MD5_DIGEST_SIZE];
        for (i, &word) in self.state.iter().enumerate() {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }

        digest
    }

    /// MD5 round functions
    #[inline]
    fn f(x: u32, y: u32, z: u32) -> u32 { (x & y) | (!x & z) }
    #[inline]
    fn g(x: u32, y: u32, z: u32) -> u32 { (x & z) | (y & !z) }
    #[inline]
    fn h(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }
    #[inline]
    fn i(x: u32, y: u32, z: u32) -> u32 { y ^ (x | !z) }

    /// Transform a 64-byte block
    fn transform(&mut self, block: &[u8; MD5_BLOCK_SIZE]) {
        // Parse block into 16 32-bit words (little-endian)
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        // Round 1
        const S1: [u32; 4] = [7, 12, 17, 22];
        const K1: [u32; 16] = [
            0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
            0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
            0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
            0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
        ];
        for i in 0..16 {
            let f = Self::f(b, c, d);
            let temp = a.wrapping_add(f).wrapping_add(m[i]).wrapping_add(K1[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(temp.rotate_left(S1[i % 4]));
        }

        // Round 2
        const S2: [u32; 4] = [5, 9, 14, 20];
        const K2: [u32; 16] = [
            0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
            0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
            0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
            0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
        ];
        for i in 0..16 {
            let g = Self::g(b, c, d);
            let idx = (5 * i + 1) % 16;
            let temp = a.wrapping_add(g).wrapping_add(m[idx]).wrapping_add(K2[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(temp.rotate_left(S2[i % 4]));
        }

        // Round 3
        const S3: [u32; 4] = [4, 11, 16, 23];
        const K3: [u32; 16] = [
            0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
            0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
            0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
            0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
        ];
        for i in 0..16 {
            let h = Self::h(b, c, d);
            let idx = (3 * i + 5) % 16;
            let temp = a.wrapping_add(h).wrapping_add(m[idx]).wrapping_add(K3[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(temp.rotate_left(S3[i % 4]));
        }

        // Round 4
        const S4: [u32; 4] = [6, 10, 15, 21];
        const K4: [u32; 16] = [
            0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
            0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
            0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
            0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
        ];
        for i in 0..16 {
            let ii = Self::i(b, c, d);
            let idx = (7 * i) % 16;
            let temp = a.wrapping_add(ii).wrapping_add(m[idx]).wrapping_add(K4[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(temp.rotate_left(S4[i % 4]));
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

impl Default for Md5Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute MD5 hash of data
pub fn md5(data: &[u8]) -> [u8; MD5_DIGEST_SIZE] {
    let mut ctx = Md5Context::new();
    ctx.update(data);
    ctx.finalize()
}

/// SHA-1 hash context
#[derive(Clone)]
pub struct Sha1Context {
    state: [u32; 5],
    count: u64,
    buffer: [u8; SHA1_BLOCK_SIZE],
    buffer_len: usize,
}

impl Sha1Context {
    /// Initial state values
    const INIT_STATE: [u32; 5] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    ];

    /// Create a new SHA-1 context
    pub fn new() -> Self {
        Self {
            state: Self::INIT_STATE,
            count: 0,
            buffer: [0u8; SHA1_BLOCK_SIZE],
            buffer_len: 0,
        }
    }

    /// Reset the context
    pub fn reset(&mut self) {
        self.state = Self::INIT_STATE;
        self.count = 0;
        self.buffer = [0u8; SHA1_BLOCK_SIZE];
        self.buffer_len = 0;
    }

    /// Update hash with data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Process buffered data first
        if self.buffer_len > 0 {
            let space = SHA1_BLOCK_SIZE - self.buffer_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset = to_copy;

            if self.buffer_len == SHA1_BLOCK_SIZE {
                self.transform(&self.buffer.clone());
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while offset + SHA1_BLOCK_SIZE <= data.len() {
            let block: [u8; SHA1_BLOCK_SIZE] = data[offset..offset + SHA1_BLOCK_SIZE]
                .try_into()
                .unwrap();
            self.transform(&block);
            offset += SHA1_BLOCK_SIZE;
        }

        // Buffer remaining data
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }

        self.count += data.len() as u64;
    }

    /// Finalize and get digest
    pub fn finalize(&mut self) -> [u8; SHA1_DIGEST_SIZE] {
        let bits = self.count * 8;

        // Padding
        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };

        let mut padding = [0u8; 72];
        padding[0] = 0x80;

        // Length in big-endian
        padding[pad_len..pad_len + 8].copy_from_slice(&bits.to_be_bytes());

        self.update(&padding[..pad_len + 8]);

        // Output digest
        let mut digest = [0u8; SHA1_DIGEST_SIZE];
        for (i, &word) in self.state.iter().enumerate() {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }

        digest
    }

    /// Transform a 64-byte block
    fn transform(&mut self, block: &[u8; SHA1_BLOCK_SIZE]) {
        // Expand block into 80 32-bit words
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

impl Default for Sha1Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-1 hash of data
pub fn sha1(data: &[u8]) -> [u8; SHA1_DIGEST_SIZE] {
    let mut ctx = Sha1Context::new();
    ctx.update(data);
    ctx.finalize()
}

/// Format hash as hexadecimal string
pub fn hash_to_hex(hash: &[u8], buf: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let len = hash.len().min(buf.len() / 2);

    for (i, &byte) in hash[..len].iter().enumerate() {
        buf[i * 2] = HEX[(byte >> 4) as usize];
        buf[i * 2 + 1] = HEX[(byte & 0xF) as usize];
    }

    len * 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_empty() {
        let hash = md5(b"");
        assert_eq!(hash, [
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
            0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
        ]);
    }

    #[test]
    fn test_md5_abc() {
        let hash = md5(b"abc");
        assert_eq!(hash, [
            0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
            0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
        ]);
    }

    #[test]
    fn test_sha1_empty() {
        let hash = sha1(b"");
        assert_eq!(hash, [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
            0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ]);
    }

    #[test]
    fn test_sha1_abc() {
        let hash = sha1(b"abc");
        assert_eq!(hash, [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
            0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ]);
    }
}
