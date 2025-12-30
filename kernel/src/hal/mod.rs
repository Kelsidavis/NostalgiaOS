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
pub mod keyboard;
pub mod pci;
pub mod pic;
pub mod rtc;

// TODO: Future submodules
// pub mod interrupt;
// pub mod platform;
// pub mod timer;
