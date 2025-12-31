//! RTL Environment Variables
//!
//! Provides environment variable management for kernel-mode and boot configuration:
//! - Environment block creation and destruction
//! - Variable query, set, and expand operations
//! - System environment for boot parameters
//! - Per-process environment support
//!
//! Based on Windows Server 2003 base/ntos/rtl/environ.c

use crate::ke::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

extern crate alloc;

/// Maximum environment variable name length
pub const RTL_ENVIRONMENT_MAX_NAME: usize = 32767;

/// Maximum environment variable value length
pub const RTL_ENVIRONMENT_MAX_VALUE: usize = 32767;

/// Maximum total environment size
pub const RTL_ENVIRONMENT_MAX_SIZE: usize = 65536;

/// Maximum number of environment variables per block
pub const RTL_ENVIRONMENT_MAX_VARS: usize = 4096;

/// Environment variable entry
#[derive(Debug, Clone)]
pub struct EnvironmentVariable {
    /// Variable name
    pub name: String,
    /// Variable value
    pub value: String,
    /// Is read-only (cannot be modified)
    pub read_only: bool,
}

impl EnvironmentVariable {
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: String::from(name),
            value: String::from(value),
            read_only: false,
        }
    }

    pub fn new_readonly(name: &str, value: &str) -> Self {
        Self {
            name: String::from(name),
            value: String::from(value),
            read_only: true,
        }
    }
}

/// Environment block
#[derive(Debug)]
pub struct EnvironmentBlock {
    /// Variables by name (case-insensitive on Windows)
    variables: BTreeMap<String, EnvironmentVariable>,
    /// Total size of all variables
    total_size: usize,
    /// Is this block read-only
    read_only: bool,
}

impl EnvironmentBlock {
    pub fn new() -> Self {
        Self {
            variables: BTreeMap::new(),
            total_size: 0,
            read_only: false,
        }
    }

    /// Create a read-only environment block
    pub fn new_readonly() -> Self {
        Self {
            variables: BTreeMap::new(),
            total_size: 0,
            read_only: true,
        }
    }

    /// Get a variable by name (case-insensitive)
    pub fn get(&self, name: &str) -> Option<&str> {
        let key = name.to_ascii_uppercase();
        self.variables.get(&key).map(|v| v.value.as_str())
    }

    /// Set a variable
    pub fn set(&mut self, name: &str, value: &str) -> Result<(), &'static str> {
        if self.read_only {
            return Err("Environment block is read-only");
        }

        if name.is_empty() {
            return Err("Variable name cannot be empty");
        }

        if name.len() > RTL_ENVIRONMENT_MAX_NAME {
            return Err("Variable name too long");
        }

        if value.len() > RTL_ENVIRONMENT_MAX_VALUE {
            return Err("Variable value too long");
        }

        let key = name.to_ascii_uppercase();

        // Check if variable exists and is read-only
        if let Some(existing) = self.variables.get(&key) {
            if existing.read_only {
                return Err("Variable is read-only");
            }
            // Subtract old size
            self.total_size -= existing.name.len() + existing.value.len();
        }

        // Check total size limit
        let new_size = self.total_size + name.len() + value.len();
        if new_size > RTL_ENVIRONMENT_MAX_SIZE {
            return Err("Environment block too large");
        }

        // Check variable count
        if !self.variables.contains_key(&key) && self.variables.len() >= RTL_ENVIRONMENT_MAX_VARS {
            return Err("Too many environment variables");
        }

        self.total_size = new_size;
        self.variables.insert(key, EnvironmentVariable::new(name, value));

        Ok(())
    }

    /// Set a read-only variable (for system use)
    pub fn set_readonly(&mut self, name: &str, value: &str) -> Result<(), &'static str> {
        if name.is_empty() {
            return Err("Variable name cannot be empty");
        }

        let key = name.to_ascii_uppercase();

        // Check if already exists
        if self.variables.contains_key(&key) {
            return Err("Variable already exists");
        }

        let new_size = self.total_size + name.len() + value.len();
        if new_size > RTL_ENVIRONMENT_MAX_SIZE {
            return Err("Environment block too large");
        }

        self.total_size = new_size;
        self.variables.insert(key, EnvironmentVariable::new_readonly(name, value));

        Ok(())
    }

    /// Remove a variable
    pub fn remove(&mut self, name: &str) -> Result<(), &'static str> {
        if self.read_only {
            return Err("Environment block is read-only");
        }

        let key = name.to_ascii_uppercase();

        if let Some(existing) = self.variables.get(&key) {
            if existing.read_only {
                return Err("Variable is read-only");
            }
            self.total_size -= existing.name.len() + existing.value.len();
            self.variables.remove(&key);
            Ok(())
        } else {
            Err("Variable not found")
        }
    }

    /// List all variables
    pub fn list(&self) -> Vec<(String, String)> {
        self.variables
            .values()
            .map(|v| (v.name.clone(), v.value.clone()))
            .collect()
    }

    /// Get number of variables
    pub fn len(&self) -> usize {
        self.variables.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    /// Get total size
    pub fn size(&self) -> usize {
        self.total_size
    }

    /// Expand environment variables in a string
    /// Replaces %VAR% with the variable's value
    pub fn expand(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                // Look for closing %
                let mut var_name = String::new();
                let mut found_end = false;

                while let Some(&next) = chars.peek() {
                    if next == '%' {
                        chars.next();
                        found_end = true;
                        break;
                    }
                    var_name.push(chars.next().unwrap());
                }

                if found_end && !var_name.is_empty() {
                    // Try to expand the variable
                    if let Some(value) = self.get(&var_name) {
                        result.push_str(value);
                    } else {
                        // Variable not found, keep original
                        result.push('%');
                        result.push_str(&var_name);
                        result.push('%');
                    }
                } else if found_end {
                    // %% becomes %
                    result.push('%');
                } else {
                    // Unclosed %, just add it
                    result.push('%');
                    result.push_str(&var_name);
                }
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Clone the environment block
    pub fn clone_block(&self) -> Self {
        Self {
            variables: self.variables.clone(),
            total_size: self.total_size,
            read_only: false, // Clone is not read-only
        }
    }
}

impl Default for EnvironmentBlock {
    fn default() -> Self {
        Self::new()
    }
}

/// System environment state
struct EnvironmentState {
    /// System environment (boot parameters, kernel config)
    system_env: EnvironmentBlock,
    /// Process environments by ID
    process_envs: BTreeMap<u64, EnvironmentBlock>,
}

impl EnvironmentState {
    pub const fn new() -> Self {
        Self {
            system_env: EnvironmentBlock {
                variables: BTreeMap::new(),
                total_size: 0,
                read_only: false,
            },
            process_envs: BTreeMap::new(),
        }
    }
}

/// Global environment state
static mut ENVIRON_STATE: Option<SpinLock<EnvironmentState>> = None;

/// Statistics
static VARS_SET: AtomicU64 = AtomicU64::new(0);
static VARS_GET: AtomicU64 = AtomicU64::new(0);
static VARS_REMOVED: AtomicU64 = AtomicU64::new(0);
static VARS_EXPANDED: AtomicU64 = AtomicU64::new(0);

fn get_environ_state() -> &'static SpinLock<EnvironmentState> {
    unsafe {
        ENVIRON_STATE
            .as_ref()
            .expect("Environment subsystem not initialized")
    }
}

/// Initialize environment subsystem
pub fn rtl_environ_init() {
    let mut state = EnvironmentState::new();

    // Initialize system environment with some default values
    let _ = state.system_env.set_readonly("OSNAME", "NostalgiaOS");
    let _ = state.system_env.set_readonly("OSVERSION", "5.2");
    let _ = state.system_env.set_readonly("OSBUILD", "1");
    let _ = state.system_env.set_readonly("ARCH", "x86_64");
    let _ = state.system_env.set_readonly("COMPUTERNAME", "NOSTALGOS");
    let _ = state.system_env.set("SYSTEMROOT", "\\Windows");
    let _ = state.system_env.set("SYSTEMDRIVE", "C:");
    let _ = state.system_env.set("TEMP", "\\Windows\\Temp");
    let _ = state.system_env.set("TMP", "\\Windows\\Temp");
    let _ = state.system_env.set("PATH", "\\Windows\\System32;\\Windows");

    unsafe {
        ENVIRON_STATE = Some(SpinLock::new(state));
    }

    crate::serial_println!("[RTL] Environment subsystem initialized");
}

/// Create a new environment block
pub fn rtl_create_environment(clone_current: bool) -> Option<u64> {
    let state = get_environ_state();
    let mut guard = state.lock();

    // Generate a handle for the new environment
    static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);

    let env = if clone_current {
        guard.system_env.clone_block()
    } else {
        EnvironmentBlock::new()
    };

    guard.process_envs.insert(handle, env);
    Some(handle)
}

/// Destroy an environment block
pub fn rtl_destroy_environment(handle: u64) -> bool {
    let state = get_environ_state();
    let mut guard = state.lock();
    guard.process_envs.remove(&handle).is_some()
}

/// Query a system environment variable
pub fn rtl_query_environment_variable(name: &str) -> Option<String> {
    let state = get_environ_state();
    let guard = state.lock();
    VARS_GET.fetch_add(1, Ordering::Relaxed);
    guard.system_env.get(name).map(String::from)
}

/// Set a system environment variable
pub fn rtl_set_environment_variable(name: &str, value: &str) -> Result<(), &'static str> {
    let state = get_environ_state();
    let mut guard = state.lock();
    let result = guard.system_env.set(name, value);
    if result.is_ok() {
        VARS_SET.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Remove a system environment variable
pub fn rtl_remove_environment_variable(name: &str) -> Result<(), &'static str> {
    let state = get_environ_state();
    let mut guard = state.lock();
    let result = guard.system_env.remove(name);
    if result.is_ok() {
        VARS_REMOVED.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Expand environment variables in a string
pub fn rtl_expand_environment_strings(input: &str) -> String {
    let state = get_environ_state();
    let guard = state.lock();
    VARS_EXPANDED.fetch_add(1, Ordering::Relaxed);
    guard.system_env.expand(input)
}

/// List all system environment variables
pub fn rtl_list_environment_variables() -> Vec<(String, String)> {
    let state = get_environ_state();
    let guard = state.lock();
    guard.system_env.list()
}

/// Get environment statistics
pub fn rtl_environ_get_stats() -> EnvironStats {
    let state = get_environ_state();
    let guard = state.lock();

    EnvironStats {
        system_vars: guard.system_env.len(),
        system_size: guard.system_env.size(),
        process_envs: guard.process_envs.len(),
        total_get: VARS_GET.load(Ordering::Relaxed),
        total_set: VARS_SET.load(Ordering::Relaxed),
        total_removed: VARS_REMOVED.load(Ordering::Relaxed),
        total_expanded: VARS_EXPANDED.load(Ordering::Relaxed),
    }
}

/// Environment statistics
#[derive(Debug, Clone)]
pub struct EnvironStats {
    /// Number of system environment variables
    pub system_vars: usize,
    /// Total size of system environment
    pub system_size: usize,
    /// Number of process environments
    pub process_envs: usize,
    /// Total get operations
    pub total_get: u64,
    /// Total set operations
    pub total_set: u64,
    /// Total remove operations
    pub total_removed: u64,
    /// Total expand operations
    pub total_expanded: u64,
}

// Process-specific environment functions

/// Query a variable from a process environment
pub fn rtl_query_process_environment(handle: u64, name: &str) -> Option<String> {
    let state = get_environ_state();
    let guard = state.lock();

    // First check process env, then fall back to system
    if let Some(env) = guard.process_envs.get(&handle) {
        if let Some(value) = env.get(name) {
            VARS_GET.fetch_add(1, Ordering::Relaxed);
            return Some(String::from(value));
        }
    }

    // Fall back to system environment
    VARS_GET.fetch_add(1, Ordering::Relaxed);
    guard.system_env.get(name).map(String::from)
}

/// Set a variable in a process environment
pub fn rtl_set_process_environment(handle: u64, name: &str, value: &str) -> Result<(), &'static str> {
    let state = get_environ_state();
    let mut guard = state.lock();

    let env = guard.process_envs.get_mut(&handle)
        .ok_or("Process environment not found")?;

    let result = env.set(name, value);
    if result.is_ok() {
        VARS_SET.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Remove a variable from a process environment
pub fn rtl_remove_process_environment(handle: u64, name: &str) -> Result<(), &'static str> {
    let state = get_environ_state();
    let mut guard = state.lock();

    let env = guard.process_envs.get_mut(&handle)
        .ok_or("Process environment not found")?;

    let result = env.remove(name);
    if result.is_ok() {
        VARS_REMOVED.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// List all variables in a process environment
pub fn rtl_list_process_environment(handle: u64) -> Vec<(String, String)> {
    let state = get_environ_state();
    let guard = state.lock();

    guard.process_envs.get(&handle)
        .map(|env| env.list())
        .unwrap_or_default()
}

/// Expand variables using a process environment
pub fn rtl_expand_process_environment(handle: u64, input: &str) -> String {
    let state = get_environ_state();
    let guard = state.lock();
    VARS_EXPANDED.fetch_add(1, Ordering::Relaxed);

    if let Some(env) = guard.process_envs.get(&handle) {
        env.expand(input)
    } else {
        guard.system_env.expand(input)
    }
}

/// Get system boot parameters as environment variables
pub fn rtl_get_boot_environment() -> Vec<(String, String)> {
    let state = get_environ_state();
    let guard = state.lock();

    // Return only read-only (system) variables
    guard.system_env.variables
        .values()
        .filter(|v| v.read_only)
        .map(|v| (v.name.clone(), v.value.clone()))
        .collect()
}

/// Set a boot parameter (kernel use only)
pub fn rtl_set_boot_parameter(name: &str, value: &str) -> Result<(), &'static str> {
    let state = get_environ_state();
    let mut guard = state.lock();

    // Check if already exists as read-only
    let key = name.to_ascii_uppercase();
    if let Some(existing) = guard.system_env.variables.get(&key) {
        if existing.read_only {
            return Err("Boot parameter is read-only");
        }
    }

    guard.system_env.set(name, value)
}
