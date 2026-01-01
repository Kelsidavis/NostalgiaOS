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
pub mod bus;
pub mod cache;
pub mod cmos;
pub mod cpuid;
pub mod display;
pub mod dma;
pub mod interrupt;
pub mod keyboard;
pub mod mce;
pub mod mouse;
pub mod mp;
pub mod msreg;
pub mod pci;
pub mod pic;
pub mod port;
pub mod power;
pub mod ppm;
pub mod profile;
pub mod rtc;
pub mod timer;
pub mod tlb;

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

// Re-export bus types
pub use bus::{
    BusType, BusDataType, PciSlotNumber, BusAddress, AddressSpace,
    BusInfo, SlotInfo, ResourceDescriptor, ResourceType, BusStats,
    MAX_BUSES,
    hal_get_bus_data, hal_set_bus_data,
    hal_translate_bus_address, hal_get_interrupt_vector,
    hal_register_bus, hal_query_bus, hal_enumerate_buses,
    hal_scan_pci_bus, hal_get_bus_stats, hal_is_bus_initialized,
    pci_read_config_word, pci_read_config_dword,
};

// Re-export MCE types
pub use mce::{
    McaBankStatus, ErrorLogEntry, CpuMceState, ErrorSeverity, ErrorSource, MceStats,
    MAX_MCA_BANKS, MAX_MCE_CPUS, MAX_ERROR_LOG,
    mce_is_supported, mce_get_bank_count, mce_init_cpu, mce_poll_errors,
    mce_exception_handler, mce_get_error_log, mce_clear_error_log,
    mce_get_stats, mce_get_global_stats, mce_is_initialized,
};

// Re-export port types
pub use port::{
    Port, PortStats, ports,
    read_port_u8, read_port_u16, read_port_u32,
    write_port_u8, write_port_u16, write_port_u32,
    read_port_buffer_u8, read_port_buffer_u16, read_port_buffer_u32,
    write_port_buffer_u8, write_port_buffer_u16, write_port_buffer_u32,
    read_port_u8_delayed, write_port_u8_delayed, io_delay, io_delay_multiple,
    hal_read_port_uchar, hal_read_port_ushort, hal_read_port_ulong,
    hal_write_port_uchar, hal_write_port_ushort, hal_write_port_ulong,
    hal_read_port_buffer_uchar, hal_read_port_buffer_ushort, hal_read_port_buffer_ulong,
    hal_write_port_buffer_uchar, hal_write_port_buffer_ushort, hal_write_port_buffer_ulong,
    hal_get_port_stats, hal_reset_port_stats,
};

// Re-export CMOS types
pub use cmos::{
    RtcTime, CmosStatus, CmosStats, registers as cmos_registers,
    CMOS_SIZE, EXTENDED_CMOS_SIZE, NVRAM_START, NVRAM_END,
    cmos_read, cmos_write, cmos_read_buffer, cmos_write_buffer,
    cmos_read_rtc, cmos_write_rtc, cmos_get_status, cmos_battery_good,
    cmos_disable_nmi, cmos_enable_nmi, cmos_is_nmi_disabled,
    cmos_calculate_checksum, cmos_get_stored_checksum, cmos_verify_checksum, cmos_update_checksum,
    cmos_get_base_memory, cmos_get_extended_memory,
    hal_read_cmos_data, hal_write_cmos_data,
    cmos_get_stats, cmos_is_initialized,
};

// Re-export MP types
pub use mp::{
    ProcessorState, IpiType, IpiDestination, ProcessorInfo, CpuTopology, MpStats,
    IPI_VECTOR_TLB_FLUSH, IPI_VECTOR_RESCHEDULE, IPI_VECTOR_CALL_FUNCTION,
    mp_get_apic_id, mp_send_ipi, mp_send_ipi_fixed, mp_send_ipi_all,
    mp_send_nmi, mp_send_init, mp_send_sipi,
    mp_start_ap, mp_start_all_aps, mp_ap_ready,
    mp_register_processor, mp_set_apic_base,
    mp_get_processor_count, mp_get_active_processor_count, mp_get_bsp_apic_id,
    mp_is_bsp, mp_get_processor_info, mp_get_processor_by_apic_id, mp_get_topology,
    mp_flush_tlb_all, mp_request_reschedule,
    mp_get_stats, mp_is_initialized,
    ke_number_processors, ke_get_current_processor_number, hal_start_next_processor, hal_request_ipi,
};

// Re-export profile types
pub use profile::{
    ProfileSource, ProfileSample, StackSample, ProfileStats,
    MAX_PROFILE_SOURCES, MAX_PROFILE_SAMPLES, MAX_STACK_DEPTH, PROFILE_VECTOR,
    profile_is_pmc_supported, profile_start, profile_stop, profile_is_active,
    profile_record_sample, profile_record_sample_with_stack,
    profile_get_samples, profile_clear_samples,
    profile_set_stack_capture, profile_is_stack_capture_enabled, profile_capture_stack,
    profile_read_pmc, profile_read_fixed_counter,
    profile_get_instructions, profile_get_cycles, profile_get_ref_cycles,
    profile_get_stats, profile_is_initialized,
    hal_start_profile_interrupt, hal_stop_profile_interrupt, hal_set_profile_interval,
};

// Re-export display types
pub use display::{
    VgaColor, DisplayMode, DisplayInfo, CursorPos, DisplayStats,
    VGA_BUFFER_ADDR, VGA_WIDTH, VGA_HEIGHT, BSOD_ATTRIBUTE,
    display_write_char, display_write_string, display_write_hex,
    display_set_attribute, display_get_cursor, display_set_cursor, display_clear,
    display_bugcheck_screen, display_is_bugcheck_active,
    display_set_gop, display_get_info, display_get_mode, display_is_initialized,
    display_get_stats,
    hal_display_string, hal_query_display_parameters, inbv_display_string, inbv_set_text_color,
};

// Re-export power types
pub use power::{
    SleepState, GlobalState, WakeSource, ShutdownAction, SleepSupport,
    PowerStateInfo, AcpiFadt, SleepTypeValues, PowerStats,
    power_set_fadt, power_set_sleep_types,
    power_get_sleep_support, power_is_s3_supported, power_is_s4_supported, power_is_s5_supported,
    power_enter_sleep_state, power_exit_sleep_state, power_get_current_state,
    power_shutdown, power_enable_rtc_wake, power_disable_rtc_wake, power_get_last_wake_source,
    power_get_state_info, power_is_initialized, power_is_acpi_available, power_get_stats,
    hal_system_shutdown, hal_return_to_firmware, nt_set_system_power_state,
};

// Re-export cache types
pub use cache::{
    CacheType, CacheInfo, FlushMode, PrefetchHint, CacheStats,
    DEFAULT_CACHE_LINE_SIZE, MAX_CACHE_LEVELS,
    cache_flush_line, cache_writeback_line, cache_flush_range, cache_writeback_range, cache_flush_all,
    cache_memory_fence, cache_store_fence, cache_load_fence, cache_compiler_barrier,
    cache_prefetch, cache_prefetch_write,
    cache_get_line_size, cache_get_info, cache_get_all_info,
    cache_is_clflush_supported, cache_is_clflushopt_supported, cache_is_clwb_supported, cache_is_initialized,
    cache_get_stats,
    ke_flush_write_buffer, ke_sweep_dcache, ke_sweep_icache, ke_flush_io_buffers,
};

// Re-export CPUID types
pub use cpuid::{
    CpuVendor, CpuFeature, CpuModel, CpuCapabilities, CpuidStats,
    cpuid, cpuid_leaf,
    cpuid_has_feature, cpuid_has_features,
    cpuid_get_vendor, cpuid_get_vendor_string, cpuid_get_brand_string,
    cpuid_get_model, cpuid_get_capabilities, cpuid_is_virtual, cpuid_is_initialized,
    cpuid_get_stats, ex_is_processor_feature_present,
};

// Re-export MSR types
pub use msreg::{
    ia32, efer, apic_base, MsrStats,
    msr_read_raw, msr_write_raw, msr_read, msr_write,
    msr_read_bits, msr_set_bits, msr_clear_bits,
    msr_get_apic_base, msr_is_bsp, msr_is_x2apic_enabled,
    msr_get_efer, msr_is_long_mode, msr_is_nx_enabled,
    msr_get_syscall_handler, msr_set_syscall_handler,
    msr_get_fs_base, msr_set_fs_base, msr_get_gs_base, msr_set_gs_base,
    msr_get_kernel_gs_base, msr_set_kernel_gs_base, msr_swap_gs,
    msr_read_tsc, rdtsc, rdtscp,
    msr_is_initialized, msr_get_stats, msr_record_gp_fault,
    hal_read_msr, hal_write_msr,
};

// Re-export TLB types
pub use tlb::{
    TlbFlushScope, InvpcidDescriptor, TlbStats, MAX_PCID,
    tlb_flush_page, tlb_flush_range, tlb_flush_all, tlb_flush_all_global,
    tlb_flush_pcid_address, tlb_flush_pcid, tlb_flush_all_contexts, tlb_flush_all_contexts_global,
    tlb_shootdown_all, tlb_shootdown_page, tlb_shootdown_range,
    tlb_get_current_pcid, tlb_set_current_pcid,
    tlb_is_pcid_supported, tlb_is_invpcid_supported, tlb_is_global_supported, tlb_is_initialized,
    tlb_get_stats, ke_flush_single_tb, ke_flush_entire_tb,
};

// TODO: Future submodules
// pub mod platform;
