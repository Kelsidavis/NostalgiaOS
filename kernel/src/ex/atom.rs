//! Executive Atom Table
//!
//! Provides atom table support for efficient string handling:
//! - Global and per-process atom tables
//! - String-to-atom and atom-to-string mapping
//! - Reference counted atoms
//! - Integer atoms (0-0xBFFF)
//!
//! Based on Windows Server 2003 base/ntos/ex/exatom.c

use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

extern crate alloc;

/// Atom type (16-bit handle)
pub type RtlAtom = u16;

/// Maximum atom name length
pub const RTL_ATOM_MAXIMUM_NAME_LENGTH: usize = 255;

/// Invalid atom value
pub const RTL_ATOM_INVALID: RtlAtom = 0;

/// Maximum integer atom value
pub const RTL_ATOM_INTEGER_MAX: RtlAtom = 0xBFFF;

/// First string atom value
pub const RTL_ATOM_STRING_BASE: RtlAtom = 0xC000;

/// Maximum number of atoms per table
pub const RTL_ATOM_TABLE_MAX_SIZE: usize = 16384;

/// Atom entry
#[derive(Debug, Clone)]
pub struct AtomEntry {
    /// Atom value
    pub atom: RtlAtom,
    /// Atom name
    pub name: String,
    /// Reference count
    pub ref_count: u32,
    /// Is pinned (cannot be deleted)
    pub pinned: bool,
    /// Hash value
    pub hash: u32,
}

impl AtomEntry {
    pub fn new(atom: RtlAtom, name: String, hash: u32) -> Self {
        Self {
            atom,
            name,
            ref_count: 1,
            pinned: false,
            hash,
        }
    }
}

/// Atom table
#[derive(Debug)]
pub struct AtomTable {
    /// Table name (for debugging)
    name: String,
    /// Atoms by value
    atoms: BTreeMap<RtlAtom, AtomEntry>,
    /// Atoms by name (lowercase for case-insensitive lookup)
    by_name: BTreeMap<String, RtlAtom>,
    /// Next available atom
    next_atom: RtlAtom,
    /// Maximum atom value
    max_atom: RtlAtom,
}

impl AtomTable {
    pub fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            atoms: BTreeMap::new(),
            by_name: BTreeMap::new(),
            next_atom: RTL_ATOM_STRING_BASE,
            max_atom: u16::MAX,
        }
    }

    /// Simple string hash
    fn hash_string(s: &str) -> u32 {
        let mut hash: u32 = 0;
        for c in s.chars() {
            let lower = c.to_ascii_lowercase() as u32;
            hash = hash.wrapping_mul(31).wrapping_add(lower);
        }
        hash
    }

    /// Add an atom to the table
    pub fn add_atom(&mut self, name: &str) -> Result<RtlAtom, &'static str> {
        // Check for empty name
        if name.is_empty() {
            return Err("Empty atom name");
        }

        // Check for name length
        if name.len() > RTL_ATOM_MAXIMUM_NAME_LENGTH {
            return Err("Atom name too long");
        }

        // Check for integer atom (#number)
        if let Some(int_atom) = parse_integer_atom(name) {
            if int_atom <= RTL_ATOM_INTEGER_MAX {
                return Ok(int_atom);
            }
            return Err("Integer atom out of range");
        }

        // Check if already exists (case-insensitive)
        let lower_name = name.to_ascii_lowercase();
        if let Some(&existing) = self.by_name.get(&lower_name) {
            // Increment reference count
            if let Some(entry) = self.atoms.get_mut(&existing) {
                entry.ref_count = entry.ref_count.saturating_add(1);
            }
            return Ok(existing);
        }

        // Check table size limit
        if self.atoms.len() >= RTL_ATOM_TABLE_MAX_SIZE {
            return Err("Atom table full");
        }

        // Allocate new atom
        let atom = self.next_atom;
        if atom >= self.max_atom {
            return Err("No more atoms available");
        }
        self.next_atom = self.next_atom.saturating_add(1);

        // Create entry
        let hash = Self::hash_string(name);
        let entry = AtomEntry::new(atom, String::from(name), hash);

        self.atoms.insert(atom, entry);
        self.by_name.insert(lower_name, atom);

        Ok(atom)
    }

    /// Find an atom by name
    pub fn find_atom(&self, name: &str) -> Option<RtlAtom> {
        // Check for empty name
        if name.is_empty() {
            return None;
        }

        // Check for integer atom
        if let Some(int_atom) = parse_integer_atom(name) {
            if int_atom <= RTL_ATOM_INTEGER_MAX {
                return Some(int_atom);
            }
            return None;
        }

        // Case-insensitive lookup
        let lower_name = name.to_ascii_lowercase();
        self.by_name.get(&lower_name).copied()
    }

    /// Delete an atom (decrement reference count)
    pub fn delete_atom(&mut self, atom: RtlAtom) -> Result<(), &'static str> {
        // Integer atoms cannot be deleted
        if atom <= RTL_ATOM_INTEGER_MAX {
            return Ok(());
        }

        let entry = self.atoms.get_mut(&atom).ok_or("Atom not found")?;

        // Pinned atoms cannot be deleted
        if entry.pinned {
            return Err("Atom is pinned");
        }

        // Decrement reference count
        if entry.ref_count > 1 {
            entry.ref_count -= 1;
            return Ok(());
        }

        // Remove the atom
        let lower_name = entry.name.to_ascii_lowercase();
        self.by_name.remove(&lower_name);
        self.atoms.remove(&atom);

        Ok(())
    }

    /// Get atom name
    pub fn get_atom_name(&self, atom: RtlAtom) -> Option<String> {
        // Integer atoms return #number format
        if atom <= RTL_ATOM_INTEGER_MAX {
            return Some(alloc::format!("#{}", atom));
        }

        self.atoms.get(&atom).map(|e| e.name.clone())
    }

    /// Get atom info
    pub fn get_atom_info(&self, atom: RtlAtom) -> Option<(String, u32, bool)> {
        // Integer atoms
        if atom <= RTL_ATOM_INTEGER_MAX {
            return Some((alloc::format!("#{}", atom), 1, true));
        }

        self.atoms.get(&atom).map(|e| (e.name.clone(), e.ref_count, e.pinned))
    }

    /// Pin an atom (prevent deletion)
    pub fn pin_atom(&mut self, atom: RtlAtom) -> Result<(), &'static str> {
        if atom <= RTL_ATOM_INTEGER_MAX {
            return Ok(()); // Integer atoms are always "pinned"
        }

        let entry = self.atoms.get_mut(&atom).ok_or("Atom not found")?;
        entry.pinned = true;
        Ok(())
    }

    /// Unpin an atom
    pub fn unpin_atom(&mut self, atom: RtlAtom) -> Result<(), &'static str> {
        if atom <= RTL_ATOM_INTEGER_MAX {
            return Ok(());
        }

        let entry = self.atoms.get_mut(&atom).ok_or("Atom not found")?;
        entry.pinned = false;
        Ok(())
    }

    /// List all atoms
    pub fn list_atoms(&self) -> Vec<(RtlAtom, String, u32)> {
        self.atoms
            .values()
            .map(|e| (e.atom, e.name.clone(), e.ref_count))
            .collect()
    }

    /// Get table statistics
    pub fn get_stats(&self) -> (usize, RtlAtom, RtlAtom) {
        let count = self.atoms.len();
        let min = self.atoms.keys().copied().min().unwrap_or(0);
        let max = self.atoms.keys().copied().max().unwrap_or(0);
        (count, min, max)
    }
}

/// Parse integer atom from string (#number)
fn parse_integer_atom(name: &str) -> Option<RtlAtom> {
    if name.starts_with('#') {
        let num_str = &name[1..];
        if let Ok(value) = num_str.parse::<u16>() {
            return Some(value);
        }
    }
    None
}

/// Global atom table state
#[derive(Debug)]
pub struct AtomTableState {
    /// Global atom table
    global_table: AtomTable,
    /// Session atom tables by session ID
    session_tables: BTreeMap<u32, AtomTable>,
}

impl AtomTableState {
    pub const fn new() -> Self {
        Self {
            global_table: AtomTable {
                name: String::new(),
                atoms: BTreeMap::new(),
                by_name: BTreeMap::new(),
                next_atom: RTL_ATOM_STRING_BASE,
                max_atom: u16::MAX,
            },
            session_tables: BTreeMap::new(),
        }
    }
}

/// Global atom state
static mut ATOM_STATE: Option<SpinLock<AtomTableState>> = None;

/// Statistics
static ATOMS_ADDED: AtomicU64 = AtomicU64::new(0);
static ATOMS_FOUND: AtomicU64 = AtomicU64::new(0);
static ATOMS_DELETED: AtomicU64 = AtomicU64::new(0);

fn get_atom_state() -> &'static SpinLock<AtomTableState> {
    unsafe {
        ATOM_STATE
            .as_ref()
            .expect("Atom subsystem not initialized")
    }
}

/// Initialize atom subsystem
pub fn exp_atom_init() {
    let mut state = AtomTableState::new();
    state.global_table = AtomTable::new("Global");

    // Add some well-known atoms
    let _ = state.global_table.add_atom("UxSubclassInfo");
    let _ = state.global_table.add_atom("UxThemeClassName");
    let _ = state.global_table.add_atom("SysFnt00");
    let _ = state.global_table.add_atom("SysFnt01");

    unsafe {
        ATOM_STATE = Some(SpinLock::new(state));
    }

    crate::serial_println!("[EX] Atom table subsystem initialized");
}

/// Add atom to global table (NtAddAtom)
pub fn nt_add_atom(name: &str) -> Result<RtlAtom, &'static str> {
    let state = get_atom_state();
    let mut guard = state.lock();

    let result = guard.global_table.add_atom(name);
    if result.is_ok() {
        ATOMS_ADDED.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Find atom in global table (NtFindAtom)
pub fn nt_find_atom(name: &str) -> Option<RtlAtom> {
    let state = get_atom_state();
    let guard = state.lock();

    let result = guard.global_table.find_atom(name);
    if result.is_some() {
        ATOMS_FOUND.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Delete atom from global table (NtDeleteAtom)
pub fn nt_delete_atom(atom: RtlAtom) -> Result<(), &'static str> {
    let state = get_atom_state();
    let mut guard = state.lock();

    let result = guard.global_table.delete_atom(atom);
    if result.is_ok() {
        ATOMS_DELETED.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Get atom name (NtQueryInformationAtom)
pub fn nt_query_atom_name(atom: RtlAtom) -> Option<String> {
    let state = get_atom_state();
    let guard = state.lock();
    guard.global_table.get_atom_name(atom)
}

/// Get atom info (name, ref_count, pinned)
pub fn nt_query_atom_info(atom: RtlAtom) -> Option<(String, u32, bool)> {
    let state = get_atom_state();
    let guard = state.lock();
    guard.global_table.get_atom_info(atom)
}

/// List all global atoms
pub fn exp_list_atoms() -> Vec<(RtlAtom, String, u32)> {
    let state = get_atom_state();
    let guard = state.lock();
    guard.global_table.list_atoms()
}

/// Get atom statistics
pub fn exp_atom_get_stats() -> (u64, u64, u64, usize) {
    let state = get_atom_state();
    let guard = state.lock();
    let table_stats = guard.global_table.get_stats();

    (
        ATOMS_ADDED.load(Ordering::Relaxed),
        ATOMS_FOUND.load(Ordering::Relaxed),
        ATOMS_DELETED.load(Ordering::Relaxed),
        table_stats.0,
    )
}

/// Create session atom table
pub fn exp_create_session_atom_table(session_id: u32) -> Result<(), &'static str> {
    let state = get_atom_state();
    let mut guard = state.lock();

    if guard.session_tables.contains_key(&session_id) {
        return Err("Session atom table already exists");
    }

    let table = AtomTable::new(&alloc::format!("Session{}", session_id));
    guard.session_tables.insert(session_id, table);

    crate::serial_println!("[EX] Created session {} atom table", session_id);

    Ok(())
}

/// Destroy session atom table
pub fn exp_destroy_session_atom_table(session_id: u32) -> Result<(), &'static str> {
    let state = get_atom_state();
    let mut guard = state.lock();

    if guard.session_tables.remove(&session_id).is_none() {
        return Err("Session atom table not found");
    }

    crate::serial_println!("[EX] Destroyed session {} atom table", session_id);

    Ok(())
}

/// Add atom to session table
pub fn exp_add_session_atom(session_id: u32, name: &str) -> Result<RtlAtom, &'static str> {
    let state = get_atom_state();
    let mut guard = state.lock();

    let table = guard.session_tables.get_mut(&session_id)
        .ok_or("Session atom table not found")?;

    table.add_atom(name)
}

/// Find atom in session table
pub fn exp_find_session_atom(session_id: u32, name: &str) -> Option<RtlAtom> {
    let state = get_atom_state();
    let guard = state.lock();

    guard.session_tables.get(&session_id)?.find_atom(name)
}

/// List session tables
pub fn exp_list_session_tables() -> Vec<(u32, usize)> {
    let state = get_atom_state();
    let guard = state.lock();

    guard.session_tables
        .iter()
        .map(|(&id, table)| (id, table.atoms.len()))
        .collect()
}

// RTL-level functions that work with any atom table

/// Add atom to a specific table
pub fn rtl_add_atom_to_atom_table(table: &mut AtomTable, name: &str) -> Result<RtlAtom, &'static str> {
    table.add_atom(name)
}

/// Lookup atom in a specific table
pub fn rtl_lookup_atom_in_atom_table(table: &AtomTable, name: &str) -> Option<RtlAtom> {
    table.find_atom(name)
}

/// Delete atom from a specific table
pub fn rtl_delete_atom_from_atom_table(table: &mut AtomTable, atom: RtlAtom) -> Result<(), &'static str> {
    table.delete_atom(atom)
}

/// Get atom name from a specific table
pub fn rtl_query_atom_in_atom_table(table: &AtomTable, atom: RtlAtom) -> Option<String> {
    table.get_atom_name(atom)
}
