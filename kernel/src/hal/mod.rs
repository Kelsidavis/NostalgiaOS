//! Hardware Abstraction Layer (hal)
//!
//! The HAL provides hardware abstraction for portability:
//!
//! - **Interrupts**: Interrupt routing and management
//! - **Timers**: Hardware timer access
//! - **ACPI**: Power management and hardware discovery
//! - **Platform**: Machine-specific initialization
//!
//! # IRQL Management
//!
//! The HAL provides IRQL primitives:
//! - `KeRaiseIrql`: Raise interrupt level
//! - `KeLowerIrql`: Lower interrupt level
//! - `KeGetCurrentIrql`: Query current level
//!
//! # Timer Support
//!
//! - PIT (8254) for legacy systems
//! - APIC timer for modern systems
//! - HPET for high-precision timing
//!
//! # APIC
//!
//! Modern systems use:
//! - Local APIC: Per-CPU interrupt controller
//! - I/O APIC: External interrupt routing

// Submodules
pub mod acpi;
pub mod apic;
pub mod ata;
pub mod interrupt;
pub mod keyboard;
pub mod mouse;
pub mod pci;
pub mod pic;
pub mod rtc;
pub mod timer;

// Re-export interrupt types
pub use interrupt::{
    KInterrupt, InterruptMode, InterruptPolarity, InterruptReturn,
    InterruptServiceRoutine, SynchronizeRoutine, InterruptStats,
    GlobalInterruptStats, VectorStats,
    MAX_INTERRUPT_OBJECTS, MAX_SHARED_PER_VECTOR,
    hal_connect_interrupt, hal_connect_interrupt_ex, hal_disconnect_interrupt,
    hal_dispatch_interrupt, ke_synchronize_execution,
    ke_acquire_interrupt_spinlock, ke_release_interrupt_spinlock,
    hal_get_interrupt_count, hal_is_vector_in_use, hal_get_interrupt_stats,
    hal_get_global_stats, hal_get_active_vectors, hal_get_vector_stats,
};

// Re-export timer types
pub use timer::{
    TimerSource, TimerCalibration, TimerStats,
    TIME_INCREMENT, NANOSECONDS_PER_SECOND, NANOSECONDS_PER_TIME_UNIT,
    NT_UNIX_EPOCH_DIFF,
    read_tsc, read_tsc_serialized, is_tsc_invariant,
    hal_query_performance_counter, hal_query_performance_frequency,
    hal_query_performance_counter_ex, ticks_to_nanoseconds, nanoseconds_to_ticks,
    hal_query_system_time, hal_query_local_time, hal_query_boot_time,
    hal_query_uptime, hal_query_uptime_seconds, hal_query_tick_count,
    hal_get_time_zone_bias, hal_set_time_zone_bias,
    ke_query_tick_count, ke_query_time_increment,
    hal_timer_interrupt, hal_set_timer_interval, hal_get_timer_interval,
    hal_enable_timer_interrupt, hal_disable_timer_interrupt,
    hal_is_timer_interrupt_enabled, hal_get_timer_interrupt_count,
    hal_calibrate_timers, hal_get_calibration, hal_is_calibrated,
    hal_stall_execution, hal_stall_execution_ns, hal_get_timer_stats,
    hal_is_timer_initialized,
};

// TODO: Future submodules
// pub mod platform;
