//! RTL Atom Table
//!
//! Atom tables provide efficient string interning for the kernel and window
//! manager. Each unique string is assigned a 16-bit "atom" identifier.
//!
//! # Atom Types
//!
//! - **Integer atoms**: 0x0001-0xBFFF are reserved for integer atoms (MAKEINTATOM)
//! - **String atoms**: 0xC000-0xFFFF are handles to interned strings
//!
//! # API
//!
//! - `RtlAddAtomToAtomTable` - Add a string, returns its atom
//! - `RtlLookupAtomInAtomTable` - Find atom for a string
//! - `RtlQueryAtomInAtomTable` - Get string for an atom
//! - `RtlDeleteAtomFromAtomTable` - Decrement reference count

use core::ptr;
use crate::ke::spinlock::SpinLock;

/// Minimum string atom value (0xC000)
pub const RTL_ATOM_MINIMUM_STRING_ATOM: u16 = 0xC000;

/// Maximum string atom value (0xFFFF)
pub const RTL_ATOM_MAXIMUM_STRING_ATOM: u16 = 0xFFFF;

/// Maximum integer atom value (0xBFFF)
pub const RTL_ATOM_MAXIMUM_INTEGER_ATOM: u16 = 0xBFFF;

/// Invalid atom value
pub const RTL_ATOM_INVALID: u16 = 0;

/// Maximum atom name length in characters
pub const RTL_ATOM_MAXIMUM_NAME_LENGTH: usize = 255;

/// Default number of hash buckets
pub const RTL_ATOM_TABLE_DEFAULT_BUCKETS: usize = 37;

/// Type alias for atom values
pub type RtlAtom = u16;

/// Atom table entry
#[repr(C)]
pub struct AtomTableEntry {
    /// Next entry in hash chain
    pub next: *mut AtomTableEntry,
    /// Reference count
    pub ref_count: u32,
    /// Flags (pinned, etc.)
    pub flags: u16,
    /// Length of name in characters
    pub name_length: u16,
    /// The atom value assigned to this entry
    pub atom: RtlAtom,
    /// Name buffer (variable length, stored inline)
    /// Actually stored as [u16; name_length] after this struct
    name_buffer: [u16; 0],
}

/// Atom table entry flags
pub mod atom_flags {
    /// Entry is pinned and cannot be deleted
    pub const PINNED: u16 = 0x0001;
}

impl AtomTableEntry {
    /// Get the name as a slice
    ///
    /// # Safety
    /// Caller must ensure the entry is valid and the name buffer is properly allocated
    pub unsafe fn name(&self) -> &[u16] {
        let ptr = (self as *const AtomTableEntry).add(1) as *const u16;
        core::slice::from_raw_parts(ptr, self.name_length as usize)
    }

    /// Check if this entry is pinned
    pub fn is_pinned(&self) -> bool {
        (self.flags & atom_flags::PINNED) != 0
    }
}

/// Atom table structure
#[repr(C)]
pub struct AtomTable {
    /// Lock for thread-safe access
    lock: SpinLock<()>,
    /// Number of hash buckets
    num_buckets: usize,
    /// Number of atoms in table
    num_atoms: u32,
    /// Next atom value to assign
    next_atom: RtlAtom,
    /// Hash buckets (array of entry pointers)
    buckets: [*mut AtomTableEntry; RTL_ATOM_TABLE_DEFAULT_BUCKETS],
}

impl AtomTable {
    /// Create a new atom table
    pub const fn new() -> Self {
        Self {
            lock: SpinLock::new(()),
            num_buckets: RTL_ATOM_TABLE_DEFAULT_BUCKETS,
            num_atoms: 0,
            next_atom: RTL_ATOM_MINIMUM_STRING_ATOM,
            buckets: [ptr::null_mut(); RTL_ATOM_TABLE_DEFAULT_BUCKETS],
        }
    }

    /// Hash a string to a bucket index
    fn hash_name(&self, name: &[u16]) -> usize {
        let mut hash: u32 = 0;
        for &ch in name {
            // Case-insensitive hash
            let ch = if ch >= b'a' as u16 && ch <= b'z' as u16 {
                ch - 32 // Convert to uppercase
            } else {
                ch
            };
            hash = hash.wrapping_mul(37).wrapping_add(ch as u32);
        }
        (hash as usize) % self.num_buckets
    }

    /// Compare two names case-insensitively
    fn names_equal(name1: &[u16], name2: &[u16]) -> bool {
        if name1.len() != name2.len() {
            return false;
        }
        for (&c1, &c2) in name1.iter().zip(name2.iter()) {
            let c1_upper = if c1 >= b'a' as u16 && c1 <= b'z' as u16 {
                c1 - 32
            } else {
                c1
            };
            let c2_upper = if c2 >= b'a' as u16 && c2 <= b'z' as u16 {
                c2 - 32
            } else {
                c2
            };
            if c1_upper != c2_upper {
                return false;
            }
        }
        true
    }

    /// Look up an entry by name
    ///
    /// Returns the entry and optionally the previous entry for deletion
    unsafe fn lookup_entry(
        &self,
        name: &[u16],
        bucket: usize,
    ) -> (*mut AtomTableEntry, *mut AtomTableEntry) {
        let mut prev: *mut AtomTableEntry = ptr::null_mut();
        let mut entry = self.buckets[bucket];

        while !entry.is_null() {
            if (*entry).name_length as usize == name.len()
                && Self::names_equal((*entry).name(), name)
            {
                return (entry, prev);
            }
            prev = entry;
            entry = (*entry).next;
        }

        (ptr::null_mut(), ptr::null_mut())
    }
}

// ============================================================================
// Global Atom Table
// ============================================================================

/// Global (system-wide) atom table
static mut GLOBAL_ATOM_TABLE: AtomTable = AtomTable::new();

/// Maximum entries in our static atom table pool
const MAX_ATOM_ENTRIES: usize = 256;

/// Static pool of atom entries
static mut ATOM_ENTRY_POOL: [AtomEntryBuffer; MAX_ATOM_ENTRIES] = [AtomEntryBuffer::new(); MAX_ATOM_ENTRIES];

/// Bitmap tracking allocated atom entries
static mut ATOM_ENTRY_BITMAP: [u64; 4] = [0; 4];

/// Buffer for atom entry with inline name storage
#[repr(C)]
#[derive(Clone, Copy)]
struct AtomEntryBuffer {
    entry: AtomTableEntryStatic,
}

impl AtomEntryBuffer {
    const fn new() -> Self {
        Self {
            entry: AtomTableEntryStatic::new(),
        }
    }
}

/// Static version of AtomTableEntry with inline name
#[repr(C)]
#[derive(Clone, Copy)]
struct AtomTableEntryStatic {
    next: *mut AtomTableEntry,
    ref_count: u32,
    flags: u16,
    name_length: u16,
    atom: RtlAtom,
    _pad: u16,
    name: [u16; RTL_ATOM_MAXIMUM_NAME_LENGTH + 1],
}

impl AtomTableEntryStatic {
    const fn new() -> Self {
        Self {
            next: ptr::null_mut(),
            ref_count: 0,
            flags: 0,
            name_length: 0,
            atom: RTL_ATOM_INVALID,
            _pad: 0,
            name: [0; RTL_ATOM_MAXIMUM_NAME_LENGTH + 1],
        }
    }
}

/// Allocate an atom entry
unsafe fn allocate_atom_entry() -> Option<*mut AtomTableEntryStatic> {
    for i in 0..4 {
        if ATOM_ENTRY_BITMAP[i] != !0u64 {
            for bit in 0..64 {
                if ATOM_ENTRY_BITMAP[i] & (1 << bit) == 0 {
                    ATOM_ENTRY_BITMAP[i] |= 1 << bit;
                    let idx = i * 64 + bit;
                    if idx < MAX_ATOM_ENTRIES {
                        return Some(&mut ATOM_ENTRY_POOL[idx].entry as *mut AtomTableEntryStatic);
                    }
                }
            }
        }
    }
    None
}

/// Free an atom entry
unsafe fn free_atom_entry(entry: *mut AtomTableEntryStatic) {
    let base = ATOM_ENTRY_POOL.as_ptr() as usize;
    let entry_addr = entry as usize;
    let entry_size = core::mem::size_of::<AtomEntryBuffer>();

    if entry_addr >= base && entry_addr < base + MAX_ATOM_ENTRIES * entry_size {
        let idx = (entry_addr - base) / entry_size;
        let bitmap_idx = idx / 64;
        let bit = idx % 64;
        ATOM_ENTRY_BITMAP[bitmap_idx] &= !(1 << bit);

        // Clear the entry
        (*entry).ref_count = 0;
        (*entry).flags = 0;
        (*entry).name_length = 0;
        (*entry).atom = RTL_ATOM_INVALID;
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Check if an atom is an integer atom (vs string atom)
#[inline]
pub fn rtl_is_integer_atom(atom: RtlAtom) -> bool {
    atom != 0 && atom <= RTL_ATOM_MAXIMUM_INTEGER_ATOM
}

/// Add an atom to the global atom table
///
/// If the string already exists, increments its reference count.
/// Returns the atom value.
pub fn rtl_add_atom_to_atom_table(name: &[u16]) -> Option<RtlAtom> {
    if name.is_empty() || name.len() > RTL_ATOM_MAXIMUM_NAME_LENGTH {
        return None;
    }

    // Check for integer atom (#1234 syntax)
    if name[0] == b'#' as u16 && name.len() > 1 {
        let mut value: u32 = 0;
        for &ch in &name[1..] {
            if ch < b'0' as u16 || ch > b'9' as u16 {
                break;
            }
            value = value * 10 + (ch - b'0' as u16) as u32;
        }
        if value > 0 && value <= RTL_ATOM_MAXIMUM_INTEGER_ATOM as u32 {
            return Some(value as RtlAtom);
        }
    }

    unsafe {
        let _guard = GLOBAL_ATOM_TABLE.lock.lock();

        let bucket = GLOBAL_ATOM_TABLE.hash_name(name);

        // Look for existing entry
        let (entry, _) = GLOBAL_ATOM_TABLE.lookup_entry(name, bucket);

        if !entry.is_null() {
            // Found - increment reference count
            (*entry).ref_count += 1;
            return Some((*entry).atom);
        }

        // Not found - create new entry
        if GLOBAL_ATOM_TABLE.next_atom > RTL_ATOM_MAXIMUM_STRING_ATOM {
            return None; // Table full
        }

        let new_entry = match allocate_atom_entry() {
            Some(e) => e,
            None => return None,
        };

        // Initialize the entry
        (*new_entry).ref_count = 1;
        (*new_entry).flags = 0;
        (*new_entry).name_length = name.len() as u16;
        (*new_entry).atom = GLOBAL_ATOM_TABLE.next_atom;

        // Copy the name
        for (i, &ch) in name.iter().enumerate() {
            (*new_entry).name[i] = ch;
        }

        // Insert into hash chain
        (*new_entry).next = GLOBAL_ATOM_TABLE.buckets[bucket] as *mut AtomTableEntry;
        GLOBAL_ATOM_TABLE.buckets[bucket] = new_entry as *mut AtomTableEntry;

        GLOBAL_ATOM_TABLE.next_atom += 1;
        GLOBAL_ATOM_TABLE.num_atoms += 1;

        Some((*new_entry).atom)
    }
}

/// Look up an atom in the global atom table
///
/// Returns the atom if found, None otherwise.
pub fn rtl_lookup_atom_in_atom_table(name: &[u16]) -> Option<RtlAtom> {
    if name.is_empty() || name.len() > RTL_ATOM_MAXIMUM_NAME_LENGTH {
        return None;
    }

    // Check for integer atom
    if name[0] == b'#' as u16 && name.len() > 1 {
        let mut value: u32 = 0;
        for &ch in &name[1..] {
            if ch < b'0' as u16 || ch > b'9' as u16 {
                break;
            }
            value = value * 10 + (ch - b'0' as u16) as u32;
        }
        if value > 0 && value <= RTL_ATOM_MAXIMUM_INTEGER_ATOM as u32 {
            return Some(value as RtlAtom);
        }
    }

    unsafe {
        let _guard = GLOBAL_ATOM_TABLE.lock.lock();

        let bucket = GLOBAL_ATOM_TABLE.hash_name(name);
        let (entry, _) = GLOBAL_ATOM_TABLE.lookup_entry(name, bucket);

        if !entry.is_null() {
            Some((*entry).atom)
        } else {
            None
        }
    }
}

/// Delete an atom from the global atom table
///
/// Decrements the reference count. Entry is removed when count reaches zero.
/// Pinned atoms cannot be deleted.
pub fn rtl_delete_atom_from_atom_table(atom: RtlAtom) -> bool {
    // Integer atoms cannot be deleted
    if rtl_is_integer_atom(atom) {
        return true;
    }

    if atom < RTL_ATOM_MINIMUM_STRING_ATOM {
        return false;
    }

    unsafe {
        let _guard = GLOBAL_ATOM_TABLE.lock.lock();

        // Search all buckets for this atom
        for bucket_idx in 0..GLOBAL_ATOM_TABLE.num_buckets {
            let mut prev: *mut AtomTableEntry = ptr::null_mut();
            let mut entry = GLOBAL_ATOM_TABLE.buckets[bucket_idx];

            while !entry.is_null() {
                if (*entry).atom == atom {
                    // Found it
                    if (*entry).is_pinned() {
                        return true; // Pinned atoms always succeed but don't delete
                    }

                    if (*entry).ref_count > 0 {
                        (*entry).ref_count -= 1;
                    }

                    if (*entry).ref_count == 0 {
                        // Remove from chain
                        if prev.is_null() {
                            GLOBAL_ATOM_TABLE.buckets[bucket_idx] = (*entry).next;
                        } else {
                            (*prev).next = (*entry).next;
                        }

                        GLOBAL_ATOM_TABLE.num_atoms -= 1;

                        // Free the entry
                        free_atom_entry(entry as *mut AtomTableEntryStatic);
                    }

                    return true;
                }

                prev = entry;
                entry = (*entry).next;
            }
        }
    }

    false
}

/// Pin an atom so it cannot be deleted
pub fn rtl_pin_atom_in_atom_table(atom: RtlAtom) -> bool {
    // Integer atoms are always valid
    if rtl_is_integer_atom(atom) {
        return true;
    }

    if atom < RTL_ATOM_MINIMUM_STRING_ATOM {
        return false;
    }

    unsafe {
        let _guard = GLOBAL_ATOM_TABLE.lock.lock();

        // Search for the atom
        for bucket_idx in 0..GLOBAL_ATOM_TABLE.num_buckets {
            let mut entry = GLOBAL_ATOM_TABLE.buckets[bucket_idx];

            while !entry.is_null() {
                if (*entry).atom == atom {
                    (*entry).flags |= atom_flags::PINNED;
                    return true;
                }
                entry = (*entry).next;
            }
        }
    }

    false
}

/// Query atom information
///
/// Returns the name length and optionally copies the name to the provided buffer.
pub fn rtl_query_atom_in_atom_table(
    atom: RtlAtom,
    name_buffer: Option<&mut [u16]>,
) -> Option<(u16, u32)> {
    // Handle integer atoms
    if rtl_is_integer_atom(atom) {
        // Format as "#N"
        let mut temp = [0u16; 8];
        let mut len = 0;
        temp[len] = b'#' as u16;
        len += 1;

        // Convert atom value to string
        let mut val = atom as u32;
        let mut digits = [0u16; 6];
        let mut digit_count = 0;

        if val == 0 {
            digits[0] = b'0' as u16;
            digit_count = 1;
        } else {
            while val > 0 {
                digits[digit_count] = (b'0' as u16) + (val % 10) as u16;
                val /= 10;
                digit_count += 1;
            }
        }

        // Reverse digits
        for i in 0..digit_count {
            temp[len] = digits[digit_count - 1 - i];
            len += 1;
        }

        if let Some(buffer) = name_buffer {
            let copy_len = len.min(buffer.len());
            buffer[..copy_len].copy_from_slice(&temp[..copy_len]);
        }

        return Some((len as u16, 0)); // Integer atoms have no ref count
    }

    if atom < RTL_ATOM_MINIMUM_STRING_ATOM {
        return None;
    }

    unsafe {
        let _guard = GLOBAL_ATOM_TABLE.lock.lock();

        // Search for the atom
        for bucket_idx in 0..GLOBAL_ATOM_TABLE.num_buckets {
            let mut entry = GLOBAL_ATOM_TABLE.buckets[bucket_idx];

            while !entry.is_null() {
                if (*entry).atom == atom {
                    let entry_static = entry as *const AtomTableEntryStatic;
                    let name_len = (*entry_static).name_length as usize;

                    if let Some(buffer) = name_buffer {
                        let copy_len = name_len.min(buffer.len());
                        let name_ptr = core::ptr::addr_of!((*entry_static).name);
                        let name_slice = core::slice::from_raw_parts(
                            (*name_ptr).as_ptr(),
                            copy_len
                        );
                        buffer[..copy_len].copy_from_slice(name_slice);
                    }

                    return Some(((*entry).name_length, (*entry).ref_count));
                }
                entry = (*entry).next;
            }
        }
    }

    None
}

// ============================================================================
// Atom Table Statistics
// ============================================================================

/// Atom table statistics
#[derive(Debug, Clone, Copy)]
pub struct AtomTableStats {
    /// Number of atoms in the table
    pub num_atoms: u32,
    /// Next atom value to be assigned
    pub next_atom: RtlAtom,
    /// Number of buckets
    pub num_buckets: usize,
    /// Maximum chain length
    pub max_chain_length: u32,
    /// Number of pinned atoms
    pub pinned_count: u32,
}

/// Get global atom table statistics
pub fn rtl_get_atom_table_stats() -> AtomTableStats {
    let mut max_chain = 0u32;
    let mut pinned = 0u32;

    unsafe {
        let _guard = GLOBAL_ATOM_TABLE.lock.lock();

        for bucket_idx in 0..GLOBAL_ATOM_TABLE.num_buckets {
            let mut chain_len = 0u32;
            let mut entry = GLOBAL_ATOM_TABLE.buckets[bucket_idx];

            while !entry.is_null() {
                chain_len += 1;
                if (*entry).is_pinned() {
                    pinned += 1;
                }
                entry = (*entry).next;
            }

            if chain_len > max_chain {
                max_chain = chain_len;
            }
        }

        AtomTableStats {
            num_atoms: GLOBAL_ATOM_TABLE.num_atoms,
            next_atom: GLOBAL_ATOM_TABLE.next_atom,
            num_buckets: GLOBAL_ATOM_TABLE.num_buckets,
            max_chain_length: max_chain,
            pinned_count: pinned,
        }
    }
}

/// Initialize the atom table subsystem
pub fn init() {
    unsafe {
        // Clear the bitmap
        for i in 0..4 {
            ATOM_ENTRY_BITMAP[i] = 0;
        }

        // Clear the hash buckets
        for bucket in GLOBAL_ATOM_TABLE.buckets.iter_mut() {
            *bucket = ptr::null_mut();
        }

        GLOBAL_ATOM_TABLE.num_atoms = 0;
        GLOBAL_ATOM_TABLE.next_atom = RTL_ATOM_MINIMUM_STRING_ATOM;
    }

    crate::serial_println!("[RTL] Atom table initialized");
}
