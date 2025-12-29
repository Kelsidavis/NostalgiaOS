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

pub mod avl;
pub mod bitmap;
pub mod checksum;
pub mod image;
pub mod memory;
pub mod random;
pub mod string;
pub mod time;
// pub mod heap;   // TODO: User-mode heap
// pub mod splay;  // TODO: Splay trees

// Re-exports for convenience
pub use avl::*;
pub use bitmap::*;
pub use checksum::*;
pub use image::*;
pub use memory::*;
pub use random::*;
pub use string::*;
pub use time::*;
