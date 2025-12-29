//! File System Runtime Library (FSRTL)
//!
//! FSRTL provides common utilities for file system drivers:
//!
//! - **MCB (Mapping Control Block)**: Track VBN↔LBN extent mappings
//! - **File Locks**: Byte-range locking for exclusive/shared access
//! - **Name Utilities**: Unicode name comparison, wildcards, path parsing
//! - **FCB Header**: Common File Control Block header for cache integration
//! - **Fast I/O**: Predicates for determining fast I/O eligibility
//! - **Tunneling**: Short name preservation across delete/rename
//! - **Notifications**: Directory change notifications
//!
//! This implementation is NT 5.2 (Windows Server 2003) compatible.

pub mod mcb;
pub mod filelock;
pub mod name;
pub mod fcb;
pub mod notify;
pub mod tunnel;
pub mod oplock;

// Re-export key types
pub use mcb::{
    LargeMcb, BaseMcb,
    fsrtl_initialize_large_mcb, fsrtl_uninitialize_large_mcb,
    fsrtl_add_large_mcb_entry, fsrtl_remove_large_mcb_entry,
    fsrtl_lookup_large_mcb_entry, fsrtl_lookup_last_large_mcb_entry,
    fsrtl_get_next_large_mcb_entry, fsrtl_truncate_large_mcb,
    fsrtl_number_of_runs_in_large_mcb, fsrtl_split_large_mcb,
};

pub use filelock::{
    FileLock, FileLockInfo,
    fsrtl_initialize_file_lock, fsrtl_uninitialize_file_lock,
    fsrtl_process_file_lock, fsrtl_check_lock_for_read_access,
    fsrtl_check_lock_for_write_access, fsrtl_fast_lock,
    fsrtl_fast_unlock_single, fsrtl_fast_unlock_all,
    fsrtl_get_next_file_lock,
};

pub use name::{
    fsrtl_dissect_name, fsrtl_does_name_contain_wild_cards,
    fsrtl_are_names_equal, fsrtl_is_name_in_expression,
    fsrtl_is_fat_legal, fsrtl_is_ntfs_legal,
    FSRTL_FAT_LEGAL, FSRTL_NTFS_LEGAL, FSRTL_WILD_CHARACTER,
};

pub use fcb::{
    FsrtlCommonFcbHeader, FsrtlAdvancedFcbHeader,
    FastIoPossible, FsrtlFlags, FsrtlFlags2,
    fsrtl_copy_read, fsrtl_copy_write,
    fsrtl_get_file_size, fsrtl_set_file_size,
};

pub use notify::{
    NotifySync, NotifyChange,
    fsrtl_notify_initialize_sync, fsrtl_notify_uninitialize_sync,
    fsrtl_notify_change_directory, fsrtl_notify_full_report_change,
    fsrtl_notify_cleanup,
};

pub use tunnel::{
    TunnelCache, TunnelEntry,
    fsrtl_initialize_tunnel_cache, fsrtl_delete_tunnel_cache,
    fsrtl_add_to_tunnel_cache, fsrtl_find_in_tunnel_cache,
    fsrtl_delete_from_tunnel_cache, fsrtl_delete_key_from_tunnel_cache,
    fsrtl_set_tunnel_cache_timeout, fsrtl_get_tunnel_cache_size,
};

pub use oplock::{
    Oplock, OplockType, OplockBreakStatus, OplockBreakRequest,
    fsrtl_initialize_oplock, fsrtl_uninitialize_oplock,
    fsrtl_request_oplock, fsrtl_check_oplock,
    fsrtl_oplock_break_notify, fsrtl_oplock_break_acknowledge,
    fsrtl_oplock_release, fsrtl_get_oplock_type,
    fsrtl_oplock_is_fast_io_possible, fsrtl_current_batch_oplock,
};
