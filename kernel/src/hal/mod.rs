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

// TODO: Future submodules
// pub mod platform;
// pub mod timer;
