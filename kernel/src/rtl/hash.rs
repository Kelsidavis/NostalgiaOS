//! Cryptographic Hash Functions
//!
//! MD5 (RFC 1321), SHA-1 (RFC 3174), and SHA-256 (FIPS 180-4) implementations.
//! These match the Windows CryptoAPI hash functions.

/// MD5 hash output size in bytes
pub const MD5_DIGEST_SIZE: usize = 16;

/// SHA-1 hash output size in bytes
pub const SHA1_DIGEST_SIZE: usize = 20;

/// SHA-256 hash output size in bytes
pub const SHA256_DIGEST_SIZE: usize = 32;

/// MD5 block size in bytes
const MD5_BLOCK_SIZE: usize = 64;

/// SHA-1 block size in bytes
const SHA1_BLOCK_SIZE: usize = 64;

/// SHA-256 block size in bytes
const SHA256_BLOCK_SIZE: usize = 64;

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

/// SHA-256 hash context (FIPS 180-4)
#[derive(Clone)]
pub struct Sha256Context {
    state: [u32; 8],
    count: u64,
    buffer: [u8; SHA256_BLOCK_SIZE],
    buffer_len: usize,
}

impl Sha256Context {
    /// Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    const INIT_STATE: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    /// Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    /// Create a new SHA-256 context
    pub fn new() -> Self {
        Self {
            state: Self::INIT_STATE,
            count: 0,
            buffer: [0u8; SHA256_BLOCK_SIZE],
            buffer_len: 0,
        }
    }

    /// Reset the context
    pub fn reset(&mut self) {
        self.state = Self::INIT_STATE;
        self.count = 0;
        self.buffer = [0u8; SHA256_BLOCK_SIZE];
        self.buffer_len = 0;
    }

    /// Update hash with data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Process buffered data first
        if self.buffer_len > 0 {
            let space = SHA256_BLOCK_SIZE - self.buffer_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset = to_copy;

            if self.buffer_len == SHA256_BLOCK_SIZE {
                self.transform(&self.buffer.clone());
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while offset + SHA256_BLOCK_SIZE <= data.len() {
            let block: [u8; SHA256_BLOCK_SIZE] = data[offset..offset + SHA256_BLOCK_SIZE]
                .try_into()
                .unwrap();
            self.transform(&block);
            offset += SHA256_BLOCK_SIZE;
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
    pub fn finalize(&mut self) -> [u8; SHA256_DIGEST_SIZE] {
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

        // Output digest in big-endian
        let mut digest = [0u8; SHA256_DIGEST_SIZE];
        for (i, &word) in self.state.iter().enumerate() {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }

        digest
    }

    /// SHA-256 helper functions
    #[inline]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline]
    fn sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline]
    fn sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline]
    fn gamma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline]
    fn gamma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    /// Transform a 64-byte block
    fn transform(&mut self, block: &[u8; SHA256_BLOCK_SIZE]) {
        // Message schedule
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            w[i] = Self::gamma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(Self::gamma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let t1 = h
                .wrapping_add(Self::sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let t2 = Self::sigma0(a).wrapping_add(Self::maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Default for Sha256Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-256 hash of data
pub fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut ctx = Sha256Context::new();
    ctx.update(data);
    ctx.finalize()
}

// ============================================================================
// HMAC - Hash-based Message Authentication Code (RFC 2104)
// ============================================================================

/// HMAC block size (same for MD5, SHA-1, SHA-256)
const HMAC_BLOCK_SIZE: usize = 64;

/// HMAC inner pad byte
const HMAC_IPAD: u8 = 0x36;

/// HMAC outer pad byte
const HMAC_OPAD: u8 = 0x5c;

/// Compute HMAC-MD5
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; MD5_DIGEST_SIZE] {
    let mut k_ipad = [0u8; HMAC_BLOCK_SIZE];
    let mut k_opad = [0u8; HMAC_BLOCK_SIZE];

    // If key > block size, hash it first
    if key.len() > HMAC_BLOCK_SIZE {
        let hashed_key = md5(key);
        k_ipad[..MD5_DIGEST_SIZE].copy_from_slice(&hashed_key);
        k_opad[..MD5_DIGEST_SIZE].copy_from_slice(&hashed_key);
    } else {
        k_ipad[..key.len()].copy_from_slice(key);
        k_opad[..key.len()].copy_from_slice(key);
    }

    // XOR with pads
    for i in 0..HMAC_BLOCK_SIZE {
        k_ipad[i] ^= HMAC_IPAD;
        k_opad[i] ^= HMAC_OPAD;
    }

    // Inner hash: H(K ^ ipad || message)
    let mut inner_ctx = Md5Context::new();
    inner_ctx.update(&k_ipad);
    inner_ctx.update(data);
    let inner_hash = inner_ctx.finalize();

    // Outer hash: H(K ^ opad || inner_hash)
    let mut outer_ctx = Md5Context::new();
    outer_ctx.update(&k_opad);
    outer_ctx.update(&inner_hash);
    outer_ctx.finalize()
}

/// Compute HMAC-SHA1
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; SHA1_DIGEST_SIZE] {
    let mut k_ipad = [0u8; HMAC_BLOCK_SIZE];
    let mut k_opad = [0u8; HMAC_BLOCK_SIZE];

    // If key > block size, hash it first
    if key.len() > HMAC_BLOCK_SIZE {
        let hashed_key = sha1(key);
        k_ipad[..SHA1_DIGEST_SIZE].copy_from_slice(&hashed_key);
        k_opad[..SHA1_DIGEST_SIZE].copy_from_slice(&hashed_key);
    } else {
        k_ipad[..key.len()].copy_from_slice(key);
        k_opad[..key.len()].copy_from_slice(key);
    }

    // XOR with pads
    for i in 0..HMAC_BLOCK_SIZE {
        k_ipad[i] ^= HMAC_IPAD;
        k_opad[i] ^= HMAC_OPAD;
    }

    // Inner hash: H(K ^ ipad || message)
    let mut inner_ctx = Sha1Context::new();
    inner_ctx.update(&k_ipad);
    inner_ctx.update(data);
    let inner_hash = inner_ctx.finalize();

    // Outer hash: H(K ^ opad || inner_hash)
    let mut outer_ctx = Sha1Context::new();
    outer_ctx.update(&k_opad);
    outer_ctx.update(&inner_hash);
    outer_ctx.finalize()
}

/// Compute HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut k_ipad = [0u8; HMAC_BLOCK_SIZE];
    let mut k_opad = [0u8; HMAC_BLOCK_SIZE];

    // If key > block size, hash it first
    if key.len() > HMAC_BLOCK_SIZE {
        let hashed_key = sha256(key);
        k_ipad[..SHA256_DIGEST_SIZE].copy_from_slice(&hashed_key);
        k_opad[..SHA256_DIGEST_SIZE].copy_from_slice(&hashed_key);
    } else {
        k_ipad[..key.len()].copy_from_slice(key);
        k_opad[..key.len()].copy_from_slice(key);
    }

    // XOR with pads
    for i in 0..HMAC_BLOCK_SIZE {
        k_ipad[i] ^= HMAC_IPAD;
        k_opad[i] ^= HMAC_OPAD;
    }

    // Inner hash: H(K ^ ipad || message)
    let mut inner_ctx = Sha256Context::new();
    inner_ctx.update(&k_ipad);
    inner_ctx.update(data);
    let inner_hash = inner_ctx.finalize();

    // Outer hash: H(K ^ opad || inner_hash)
    let mut outer_ctx = Sha256Context::new();
    outer_ctx.update(&k_opad);
    outer_ctx.update(&inner_hash);
    outer_ctx.finalize()
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

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        assert_eq!(hash, [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ]);
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        assert_eq!(hash, [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ]);
    }

    #[test]
    fn test_hmac_md5() {
        // RFC 2104 test vector
        let key = [0x0bu8; 16];
        let data = b"Hi There";
        let hash = hmac_md5(&key, data);
        assert_eq!(hash, [
            0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
            0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d,
        ]);
    }

    #[test]
    fn test_hmac_sha1() {
        // RFC 2202 test vector
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let hash = hmac_sha1(&key, data);
        assert_eq!(hash, [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
            0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
            0xf1, 0x46, 0xbe, 0x00,
        ]);
    }

    #[test]
    fn test_hmac_sha256() {
        // RFC 4231 test vector
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let hash = hmac_sha256(&key, data);
        assert_eq!(hash, [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
        ]);
    }
}
