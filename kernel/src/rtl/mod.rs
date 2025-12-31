//! Runtime Library (rtl)
//!
//! Common data structures and utilities used throughout the kernel:
//!
//! - **Strings**: UNICODE_STRING, ANSI_STRING
//! - **Lists**: Doubly-linked list macros (LIST_ENTRY)
//! - **Bitmaps**: RTL_BITMAP for bit manipulation
//! - **AVL Trees**: Self-balancing binary trees (for VAD)
//! - **Splay Trees**: Self-adjusting binary trees
//! - **Heap**: User-mode heap management
//!
//! # UNICODE_STRING
//!
//! NT uses counted strings (not null-terminated):
//! ```ignore
//! struct UnicodeString {
//!     length: u16,         // Current length in bytes
//!     maximum_length: u16, // Buffer capacity in bytes
//!     buffer: *mut u16,    // UTF-16 data
//! }
//! ```
//!
//! # LIST_ENTRY
//!
//! Intrusive doubly-linked list:
//! ```ignore
//! struct ListEntry {
//!     flink: *mut ListEntry, // Forward link
//!     blink: *mut ListEntry, // Backward link
//! }
//! ```

pub mod atom;
pub mod avl;
pub mod base64;
pub mod bitmap;
pub mod checksum;
pub mod compress;
pub mod gen8dot3;
pub mod hash;
pub mod heap;
pub mod format;
pub mod hex;
pub mod image;
pub mod memory;
pub mod nls;
pub mod random;
pub mod string;
pub mod time;
pub mod uuid;
pub mod environ;
pub mod splay;
pub mod version;

// Re-exports for convenience
pub use atom::*;
pub use avl::*;
pub use base64::{encode as base64_encode, decode as base64_decode};
pub use bitmap::*;
pub use checksum::*;
pub use compress::*;
pub use format::{format_size, format_duration, format_number, hex_dump};
pub use gen8dot3::*;
pub use hash::*;
pub use heap::*;
pub use hex::{encode as hex_encode, decode as hex_decode};
pub use image::*;
pub use memory::*;
pub use random::*;
pub use string::*;
pub use time::*;
pub use uuid::{Uuid, create_uuid, create_sequential_uuid};
pub use environ::*;
pub use splay::*;
pub use version::*;
