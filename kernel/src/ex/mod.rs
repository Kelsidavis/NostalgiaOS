//! Executive (ex)
//!
//! The executive provides common services used by all kernel components:
//!
//! - **Pool Allocator**: Tag-based memory allocation (Paged/NonPaged)
//! - **Lookaside Lists**: Fast fixed-size allocation
//! - **ERESOURCE**: Reader-writer locks
//! - **Push Locks**: Lightweight reader-writer locks
//! - **Fast Mutexes**: Efficient kernel mutexes
//! - **Rundown Protection**: Safe resource cleanup
//! - **Worker Threads**: Deferred work execution
//!
//! # Pool Types
//!
//! - NonPagedPool: Always resident, usable at any IRQL
//! - PagedPool: Can be paged out, only at PASSIVE_LEVEL
//!
//! # Key Structures
//!
//! - `ERESOURCE`: Reader-writer lock
//! - `EX_PUSH_LOCK`: Lightweight RW lock
//! - `FAST_MUTEX`: Fast kernel mutex
//! - `LOOKASIDE_LIST_EX`: Per-CPU lookaside list

pub mod callback;
pub mod fast_mutex;
pub mod keyed_event;
pub mod lookaside;
pub mod luid;
pub mod pushlock;
pub mod resource;
pub mod rundown;
pub mod worker;
// pub mod pool;      // Uses mm::pool
// pub mod timer;     // Uses ke::timer

// Re-exports for convenience
pub use callback::*;
pub use fast_mutex::*;
pub use keyed_event::*;
pub use lookaside::*;
pub use luid::*;
pub use pushlock::*;
pub use resource::*;
pub use rundown::*;
pub use worker::*;
