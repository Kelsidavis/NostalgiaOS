//! Architecture-specific code
//!
//! This module provides CPU and hardware abstractions for x86_64.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
