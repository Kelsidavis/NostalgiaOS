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
pub mod fastio;
pub mod stackovf;
pub mod unc;
pub mod fltmgr;

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
    // Types
    Oplock, OplockType, OplockBreakStatus, OplockBreakRequest,
    OplockWaitInfo, OplockStats, Level2OplockInfo,
    OplockWaitCompleteRoutine, OplockPrePostIrpRoutine,
    // Flag modules
    oplock_flags, fsctl_oplock, oplock_break_info, oplock_status,
    // Core functions
    fsrtl_initialize_oplock, fsrtl_uninitialize_oplock,
    fsrtl_request_oplock, fsrtl_check_oplock,
    fsrtl_oplock_break_notify, fsrtl_oplock_break_acknowledge,
    fsrtl_oplock_release, fsrtl_get_oplock_type,
    fsrtl_oplock_is_fast_io_possible, fsrtl_current_batch_oplock,
    // Extended functions
    fsrtl_oplock_fsctrl, fsrtl_check_oplock_ex, fsrtl_break_level2_oplocks,
    fsrtl_get_oplock_stats,
};

pub use fastio::{
    // Types
    FastIoDispatch, IoStatusBlock, FastIoStats,
    FileBasicInformation, FileStandardInformation, FileNetworkOpenInformation,
    FsRtlCommonFcbHeader,
    // Flags
    FSRTL_FLAG_FILE_MODIFIED, FSRTL_FLAG_FILE_LENGTH_CHANGED,
    FSRTL_FLAG_LIMIT_MODIFIED_PAGES, FSRTL_FLAG_ACQUIRE_MAIN_RSRC_EX,
    FSRTL_FLAG_ACQUIRE_MAIN_RSRC_SH, FSRTL_FLAG_USER_MAPPED_FILE,
    // Fast I/O functions
    fsrtl_copy_read as fastio_copy_read, fsrtl_copy_write as fastio_copy_write,
    fsrtl_mdl_read, fsrtl_mdl_read_complete,
    fsrtl_prepare_mdl_write, fsrtl_mdl_write_complete,
    fsrtl_acquire_file_exclusive, fsrtl_release_file,
    fsrtl_acquire_file_for_cc_flush, fsrtl_release_file_for_cc_flush,
    fsrtl_acquire_file_for_mod_write, fsrtl_release_file_for_mod_write,
    fsrtl_get_file_size as fastio_get_file_size,
    fsrtl_set_file_size as fastio_set_file_size,
    fsrtl_fast_io_check_if_possible,
    // Statistics
    get_fast_io_stats,
    fsrtl_increment_cc_fast_read_not_possible,
    fsrtl_increment_cc_fast_read_wait,
    fsrtl_increment_cc_fast_read_resource_miss,
};

pub use stackovf::{
    // Types
    StackOverflowRoutine, StackOverflowItem, StackOverflowStats,
    // Constants
    STACK_OVERFLOW_READ_THRESHHOLD,
    // Stack check functions
    io_get_remaining_stack_size, io_check_stack_overflow,
    fsrtl_is_stack_overflow_read_possible, get_stack_usage_percent,
    // Post functions
    fsrtl_post_stack_overflow, fsrtl_post_paging_file_stack_overflow,
    // Worker functions
    fsrtl_stack_overflow_worker, fsrtl_worker_thread_normal, fsrtl_worker_thread_paging,
    // Status checking
    fsrtl_is_ntstatus_expected,
    // Statistics
    get_stats as get_stack_overflow_stats, reset_stats as reset_stack_overflow_stats,
    // Init
    init as init_stack_overflow,
};

pub use unc::{
    // Types
    UncProvider, MupState, UncPath, UncProviderRegistrationEx, UncStats,
    // Flag modules
    provider_flags,
    // Constants
    MAX_UNC_PROVIDERS,
    // Registration
    fsrtl_register_unc_provider, fsrtl_deregister_unc_provider,
    fsrtl_register_unc_provider_ex,
    // DFS
    fsrtl_is_dfs_enabled, fsrtl_set_dfs_enabled,
    // Query
    get_provider_count, get_provider_info, find_provider_by_name,
    // Path parsing
    fsrtl_parse_unc_path, fsrtl_is_unc_path, fsrtl_is_dfs_path,
    // Statistics
    get_unc_stats,
    // Init
    init as init_unc,
};

pub use fltmgr::{
    // Types
    FltFilter, FltInstance, FltPort, FltRegistration, FltCallbackData,
    FltOperationCallback, FltOperation, FltIoParams,
    FltPreopCallbackStatus, FltPostopCallbackStatus,
    FltPreOperationCallback, FltPostOperationCallback,
    FltMgrStats, FltFilterSnapshot,
    // Constants
    MAX_MINIFILTERS, MAX_INSTANCES, MAX_CALLBACKS, PORT_BUFFER_SIZE,
    // Filter registration
    flt_register_filter, flt_unregister_filter, flt_start_filtering,
    // Instance management
    flt_attach_volume, flt_detach_volume,
    // Communication ports
    flt_create_communication_port, flt_close_communication_port, flt_send_message,
    // Callback invocation
    flt_invoke_pre_callbacks, flt_invoke_post_callbacks,
    // Statistics
    get_fltmgr_stats, get_filter_snapshots, list_filters,
    // Init
    init as init_fltmgr,
};
