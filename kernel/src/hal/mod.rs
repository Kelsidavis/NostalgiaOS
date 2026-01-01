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
pub mod dma;
pub mod interrupt;
pub mod keyboard;
pub mod mouse;
pub mod pci;
pub mod pic;
pub mod ppm;
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

// Re-export DMA types
pub use dma::{
    DmaAdapter, DmaAdapterStats, DeviceDescription, InterfaceType,
    DmaWidth, DmaSpeed, DmaMode, DmaDirection,
    ScatterGatherElement, ScatterGatherList, GlobalDmaStats,
    MAX_DMA_ADAPTERS, MAX_SG_ELEMENTS, MAX_MAP_REGISTERS,
    DEVICE_DESCRIPTION_VERSION,
    hal_get_dma_adapter, hal_put_dma_adapter,
    hal_allocate_common_buffer, hal_free_common_buffer,
    hal_allocate_adapter_channel, hal_free_adapter_channel,
    hal_map_transfer, hal_flush_adapter_buffers, hal_read_dma_counter,
    hal_get_dma_stats, hal_get_adapter_stats, hal_is_dma_initialized,
};

// Re-export PPM types
pub use ppm::{
    CState, PState, TState, PowerPolicy,
    CStateInfo, PStateInfo, ProcessorPowerState, ProcessorPowerInfo, PpmStats,
    MAX_PROCESSORS, MAX_C_STATES, MAX_P_STATES,
    ppm_enter_idle_state, ppm_exit_idle_state, ppm_get_deepest_c_state,
    ppm_is_mwait_supported, ppm_set_performance_state, ppm_get_current_p_state,
    ppm_is_speedstep_supported, ppm_get_p_state_count,
    ppm_get_temperature, ppm_is_thermal_throttling, ppm_set_thermal_throttle_point,
    ppm_set_power_policy, ppm_get_power_policy,
    ppm_register_processor, ppm_unregister_processor,
    ppm_get_stats, ppm_get_processor_info, ppm_is_initialized,
};

// TODO: Future submodules
// pub mod platform;
