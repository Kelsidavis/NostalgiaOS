//! Random Number Generator (RTL)
//!
//! This module implements random number generation for the kernel.
//! Based on the Windows NT RtlRandom and RtlRandomEx algorithms.
//!
//! # Algorithms
//!
//! - `RtlUniform`: Simple D.H. Lehmer (1948) linear congruential generator
//! - `RtlRandom`: MacLaren-Marsaglia shuffle algorithm for better distribution
//! - `RtlRandomEx`: Bays-Durham shuffle (faster, better period)
//!
//! # Usage
//! ```
//! let mut seed: u32 = get_initial_seed();
//! let random_value = rtl_random(&mut seed);
//! ```
//!
//! # Thread Safety
//! The functions are thread-safe as long as different threads use different seeds.
//! For a global random source, use the RtlRandomState with proper locking.

use core::sync::atomic::{AtomicU32, Ordering};

/// Constants for Lehmer's algorithm
const MULTIPLIER: u32 = 0x80000000 - 19; // 2^31 - 19
const INCREMENT: u32 = 0x80000000 - 61;  // 2^31 - 61
const MODULUS: u32 = 0x80000000 - 1;     // 2^31 - 1

/// Size of the shuffle table
const SHUFFLE_TABLE_SIZE: usize = 128;

/// Shuffle table for RtlRandom (initialized with pseudo-random values)
static RANDOM_TABLE: [AtomicU32; SHUFFLE_TABLE_SIZE] = {
    // Initialize with values from the Lehmer generator starting with seed 1
    const fn init_table() -> [AtomicU32; SHUFFLE_TABLE_SIZE] {
        let mut table = [const { AtomicU32::new(0) }; SHUFFLE_TABLE_SIZE];
        let mut seed: u32 = 1;
        let mut i = 0;
        while i < SHUFFLE_TABLE_SIZE {
            // Lehmer step
            seed = ((MULTIPLIER as u64 * seed as u64 + INCREMENT as u64) % MODULUS as u64) as u32;
            table[i] = AtomicU32::new(seed);
            i += 1;
        }
        table
    }
    init_table()
};

/// Auxiliary variable for RtlRandomEx
static RANDOM_EX_Y: AtomicU32 = AtomicU32::new(0x12345678);

/// Shuffle table for RtlRandomEx
static RANDOM_EX_TABLE: [AtomicU32; SHUFFLE_TABLE_SIZE] = {
    const fn init_table() -> [AtomicU32; SHUFFLE_TABLE_SIZE] {
        let mut table = [const { AtomicU32::new(0) }; SHUFFLE_TABLE_SIZE];
        let mut seed: u32 = 0x87654321;
        let mut i = 0;
        while i < SHUFFLE_TABLE_SIZE {
            seed = ((MULTIPLIER as u64 * seed as u64 + INCREMENT as u64) % MODULUS as u64) as u32;
            table[i] = AtomicU32::new(seed);
            i += 1;
        }
        table
    }
    init_table()
};

/// Generate a uniform random number using Lehmer's algorithm
///
/// This is a simple linear congruential generator (LCG) based on
/// D.H. Lehmer's 1948 algorithm.
///
/// # Arguments
/// * `seed` - Pointer to the seed value (updated after call)
///
/// # Returns
/// A random number uniformly distributed over [0..MAXLONG]
#[inline]
pub fn rtl_uniform(seed: &mut u32) -> u32 {
    *seed = (((MULTIPLIER as u64) * (*seed as u64) + (INCREMENT as u64)) % (MODULUS as u64)) as u32;
    *seed
}

/// Generate a random number using the MacLaren-Marsaglia algorithm
///
/// This provides better randomness than RtlUniform by using a shuffle table.
/// Based on Algorithm B from Knuth's TAOCP Vol 2.
///
/// # Arguments
/// * `seed` - Pointer to the seed value (updated after call)
///
/// # Returns
/// A random number uniformly distributed over [0..MAXLONG]
pub fn rtl_random(seed: &mut u32) -> u32 {
    // Generate two uniform random numbers
    let x = rtl_uniform(seed);
    let y = rtl_uniform(seed);

    // Use y to select an index in the shuffle table
    let j = (y as usize) % SHUFFLE_TABLE_SIZE;

    // Get the value from the table
    let result = RANDOM_TABLE[j].load(Ordering::Relaxed);

    // Replace it with x
    RANDOM_TABLE[j].store(x, Ordering::Relaxed);

    result
}

/// Generate a random number using the Bays-Durham algorithm
///
/// This is faster than RtlRandom and has a better period.
/// Based on Algorithm B' from Knuth's TAOCP Vol 2.
///
/// # Arguments
/// * `seed` - Pointer to the seed value (updated after call)
///
/// # Returns
/// A random number uniformly distributed over [0..MAXLONG]
pub fn rtl_random_ex(seed: &mut u32) -> u32 {
    // Get index from auxiliary variable
    let y = RANDOM_EX_Y.load(Ordering::Relaxed);
    let j = (y as usize) % SHUFFLE_TABLE_SIZE;

    // Update auxiliary variable with table value
    let new_y = RANDOM_EX_TABLE[j].load(Ordering::Relaxed);
    RANDOM_EX_Y.store(new_y, Ordering::Relaxed);

    // Update table with new uniform value
    let new_val = rtl_uniform(seed);
    RANDOM_EX_TABLE[j].store(new_val, Ordering::Relaxed);

    new_val
}

/// Global random state for kernel use
pub struct RtlRandomState {
    seed: AtomicU32,
}

impl RtlRandomState {
    /// Create a new random state with the given initial seed
    pub const fn new(initial_seed: u32) -> Self {
        Self {
            seed: AtomicU32::new(initial_seed),
        }
    }

    /// Generate a random number (thread-safe)
    pub fn next(&self) -> u32 {
        // Atomically update the seed and return the value
        let mut current = self.seed.load(Ordering::Relaxed);
        loop {
            let next = (((MULTIPLIER as u64) * (current as u64) + (INCREMENT as u64))
                % (MODULUS as u64)) as u32;
            match self.seed.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(c) => current = c,
            }
        }
    }

    /// Generate a random number in range [0, max)
    pub fn next_bounded(&self, max: u32) -> u32 {
        if max == 0 {
            return 0;
        }
        self.next() % max
    }

    /// Seed the random state
    pub fn seed(&self, new_seed: u32) {
        self.seed.store(new_seed, Ordering::Relaxed);
    }
}

impl Default for RtlRandomState {
    fn default() -> Self {
        Self::new(1)
    }
}

/// Global kernel random state
/// Initialized with a seed based on boot time
static KERNEL_RANDOM: RtlRandomState = RtlRandomState::new(0x31415926);

/// Get a random number from the kernel's global random state
pub fn kernel_random() -> u32 {
    KERNEL_RANDOM.next()
}

/// Get a random number in range [0, max) from kernel random
pub fn kernel_random_bounded(max: u32) -> u32 {
    KERNEL_RANDOM.next_bounded(max)
}

/// Seed the kernel random state (call during init with boot time or similar)
pub fn kernel_random_seed(seed: u32) {
    KERNEL_RANDOM.seed(seed);
}

/// Generate a random byte array
pub fn rtl_random_bytes(buffer: &mut [u8], seed: &mut u32) {
    for chunk in buffer.chunks_mut(4) {
        let val = rtl_random(seed);
        let bytes = val.to_le_bytes();
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte = bytes[i];
        }
    }
}

/// Fill a buffer with random bytes from kernel random
pub fn kernel_random_bytes(buffer: &mut [u8]) {
    let mut seed = KERNEL_RANDOM.next();
    rtl_random_bytes(buffer, &mut seed);
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the random subsystem with entropy from system sources
pub fn init() {
    // Seed with something based on system state
    // In a real kernel, we'd use RDTSC, RTC, or hardware RNG
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        }
        let tsc = ((hi as u64) << 32) | (lo as u64);
        kernel_random_seed((tsc as u32) ^ 0xDEADBEEF);
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        // Fallback: use a fixed seed (not ideal but functional)
        kernel_random_seed(0x12345678);
    }

    crate::serial_println!("[RTL] Random number generator initialized");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniform_deterministic() {
        let mut seed1 = 12345u32;
        let mut seed2 = 12345u32;

        let a1 = rtl_uniform(&mut seed1);
        let a2 = rtl_uniform(&mut seed2);
        assert_eq!(a1, a2);
        assert_eq!(seed1, seed2);
    }

    #[test]
    fn test_uniform_changes_seed() {
        let mut seed = 12345u32;
        let original = seed;
        rtl_uniform(&mut seed);
        assert_ne!(seed, original);
    }

    #[test]
    fn test_random_state() {
        let state = RtlRandomState::new(12345);
        let a = state.next();
        let b = state.next();
        assert_ne!(a, b);
    }
}
