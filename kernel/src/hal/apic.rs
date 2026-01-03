//! Local APIC (Advanced Programmable Interrupt Controller)
//!
//! Provides timer and inter-processor interrupt functionality.
//! The Local APIC is memory-mapped at 0xFEE00000 (default) or
//! at the address specified in MSR 0x1B.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};

/// Default Local APIC base address
const APIC_DEFAULT_BASE: u64 = 0xFEE0_0000;

/// APIC Register offsets
mod reg {
    pub const ID: u32 = 0x020;              // Local APIC ID
    pub const VERSION: u32 = 0x030;         // Local APIC Version
    pub const TPR: u32 = 0x080;             // Task Priority Register
    pub const EOI: u32 = 0x0B0;             // End of Interrupt
    pub const SPURIOUS: u32 = 0x0F0;        // Spurious Interrupt Vector
    pub const ICR_LOW: u32 = 0x300;         // Interrupt Command (low)
    pub const ICR_HIGH: u32 = 0x310;        // Interrupt Command (high)
    pub const LVT_TIMER: u32 = 0x320;       // LVT Timer Register
    pub const LVT_THERMAL: u32 = 0x330;     // LVT Thermal Sensor
    pub const LVT_PERF: u32 = 0x340;        // LVT Performance Counter
    pub const LVT_LINT0: u32 = 0x350;       // LVT LINT0
    pub const LVT_LINT1: u32 = 0x360;       // LVT LINT1
    pub const LVT_ERROR: u32 = 0x370;       // LVT Error
    pub const TIMER_INIT: u32 = 0x380;      // Timer Initial Count
    pub const TIMER_CURRENT: u32 = 0x390;   // Timer Current Count
    pub const TIMER_DIVIDE: u32 = 0x3E0;    // Timer Divide Configuration
}

/// LVT Timer modes
mod timer_mode {
    pub const ONE_SHOT: u32 = 0b00 << 17;
    pub const PERIODIC: u32 = 0b01 << 17;
    pub const TSC_DEADLINE: u32 = 0b10 << 17;
}

/// Timer divider values (maps to actual divisor)
/// Value -> Divisor: 0->2, 1->4, 2->8, 3->16, 8->32, 9->64, 10->128, 11->1
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum TimerDivide {
    Div2 = 0b0000,
    Div4 = 0b0001,
    Div8 = 0b0010,
    Div16 = 0b0011,
    Div32 = 0b1000,
    Div64 = 0b1001,
    Div128 = 0b1010,
    Div1 = 0b1011,
}

/// System tick counter (incremented by timer interrupt)
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Local APIC instance
pub struct LocalApic {
    base_addr: u64,
}

/// Global APIC instance
static mut LOCAL_APIC: Option<LocalApic> = None;

impl LocalApic {
    /// Create a new Local APIC instance
    /// Reads the base address from MSR 0x1B
    pub fn new() -> Self {
        let base = unsafe {
            let lo: u32;
            let hi: u32;
            core::arch::asm!(
                "rdmsr",
                in("ecx") 0x1Bu32,
                out("eax") lo,
                out("edx") hi,
            );
            // Combine low and high parts, base address is bits 12-35
            let msr_value = ((hi as u64) << 32) | (lo as u64);
            msr_value & 0xFFFF_F000
        };

        // If MSR returns 0, use default
        let base_addr = if base == 0 { APIC_DEFAULT_BASE } else { base };

        Self { base_addr }
    }

    /// Read an APIC register
    #[inline]
    fn read(&self, offset: u32) -> u32 {
        unsafe {
            read_volatile((self.base_addr + offset as u64) as *const u32)
        }
    }

    /// Write to an APIC register
    #[inline]
    fn write(&self, offset: u32, value: u32) {
        unsafe {
            write_volatile((self.base_addr + offset as u64) as *mut u32, value);
        }
    }

    /// Initialize the Local APIC
    pub fn init(&self) {
        // Enable APIC via spurious interrupt vector register
        // Set bit 8 (APIC enable) and spurious vector to 0xFF
        self.write(reg::SPURIOUS, 0x1FF);

        // Clear task priority to accept all interrupts
        self.write(reg::TPR, 0);

        // Mask all LVT entries initially
        self.write(reg::LVT_TIMER, 1 << 16);    // Masked
        self.write(reg::LVT_THERMAL, 1 << 16);
        self.write(reg::LVT_PERF, 1 << 16);

        // Configure LINT0 for ExtINT to pass through PIC interrupts (Virtual Wire Mode)
        // This allows the 8259 PIC interrupts to reach the CPU via the APIC
        // Bits: 0-7 = vector (not used for ExtINT), 8-10 = delivery mode (111 = ExtINT),
        //       12 = delivery status, 13 = polarity, 14 = remote IRR, 15 = trigger mode,
        //       16 = mask (0 = unmasked)
        self.write(reg::LVT_LINT0, 0x700); // ExtINT mode, unmasked

        // LINT1 is typically used for NMI, mask it for now
        self.write(reg::LVT_LINT1, 1 << 16);
        self.write(reg::LVT_ERROR, 1 << 16);
    }

    /// Get the Local APIC ID
    pub fn id(&self) -> u8 {
        ((self.read(reg::ID) >> 24) & 0xFF) as u8
    }

    /// Get the APIC version
    pub fn version(&self) -> u32 {
        self.read(reg::VERSION)
    }

    /// Configure the timer in periodic mode
    ///
    /// # Arguments
    /// * `vector` - Interrupt vector number (32-255)
    /// * `divider` - Timer clock divider
    /// * `initial_count` - Initial counter value (determines frequency)
    pub fn set_timer_periodic(&self, vector: u8, divider: TimerDivide, initial_count: u32) {
        // Set divide configuration
        self.write(reg::TIMER_DIVIDE, divider as u32);

        // Set LVT timer: periodic mode, not masked, specified vector
        let lvt = timer_mode::PERIODIC | (vector as u32);
        self.write(reg::LVT_TIMER, lvt);

        // Set initial count (starts the timer)
        self.write(reg::TIMER_INIT, initial_count);
    }

    /// Configure the timer in one-shot mode
    pub fn set_timer_oneshot(&self, vector: u8, divider: TimerDivide, initial_count: u32) {
        self.write(reg::TIMER_DIVIDE, divider as u32);
        let lvt = timer_mode::ONE_SHOT | (vector as u32);
        self.write(reg::LVT_TIMER, lvt);
        self.write(reg::TIMER_INIT, initial_count);
    }

    /// Stop the timer
    pub fn stop_timer(&self) {
        // Mask the timer
        self.write(reg::LVT_TIMER, 1 << 16);
        self.write(reg::TIMER_INIT, 0);
    }

    /// Read current timer count
    pub fn timer_current(&self) -> u32 {
        self.read(reg::TIMER_CURRENT)
    }

    /// Send End of Interrupt
    #[inline]
    pub fn eoi(&self) {
        self.write(reg::EOI, 0);
    }

    /// Get the APIC base address
    pub fn base_address(&self) -> u64 {
        self.base_addr
    }
}

/// Initialize the global APIC instance
pub fn init() {
    // Reset tick count to 0 (important since .bss may not be zeroed by bootloader)
    TICK_COUNT.store(0, Ordering::Relaxed);

    let apic = LocalApic::new();
    apic.init();

    unsafe {
        LOCAL_APIC = Some(apic);
    }
}

/// Get a reference to the global APIC
pub fn get() -> &'static LocalApic {
    unsafe {
        LOCAL_APIC.as_ref().expect("APIC not initialized")
    }
}

/// Send End of Interrupt (convenience function)
#[inline]
pub fn eoi() {
    get().eoi();
}

/// Start the APIC timer with a target frequency
///
/// # Arguments
/// * `vector` - Interrupt vector (should be 32 for timer)
/// * `frequency_hz` - Target frequency in Hz (e.g., 1000 for 1kHz)
///
/// Note: The actual frequency depends on the bus clock and may not be exact.
/// For a 100MHz bus with divider 16, initial_count of 6250 gives ~1000Hz.
pub fn start_timer(vector: u8, frequency_hz: u32) {
    let apic = get();

    // Use divider of 16 for reasonable precision
    // Typical bus frequency is 100MHz-200MHz
    // For 100MHz / 16 = 6.25MHz base
    // 6.25MHz / 1000Hz = 6250 count for 1ms period

    // We'll use a reasonable default assuming ~100MHz bus
    // The actual frequency can be calibrated later using PIT or TSC
    let base_freq = 6_250_000u32; // Assumed 6.25MHz after divide by 16
    let initial_count = base_freq / frequency_hz;

    apic.set_timer_periodic(vector, TimerDivide::Div16, initial_count);
}

/// Get the current tick count
#[inline]
pub fn get_tick_count() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// Inter-Processor Interrupt (IPI) Support
// ============================================================================

/// IPI delivery modes
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum IpiDeliveryMode {
    /// Fixed - deliver interrupt to all processors in destination
    Fixed = 0b000,
    /// Lowest Priority - deliver to lowest-priority processor
    LowestPriority = 0b001,
    /// SMI - System Management Interrupt
    Smi = 0b010,
    /// NMI - Non-Maskable Interrupt
    Nmi = 0b100,
    /// INIT - Initialization (used for starting APs)
    Init = 0b101,
    /// Startup - Startup IPI (SIPI, used for starting APs)
    Startup = 0b110,
}

/// IPI destination shorthand
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum IpiDestination {
    /// No shorthand - use destination field
    NoShorthand = 0b00,
    /// Send to self only
    ToSelf = 0b01,
    /// Send to all including self
    AllIncludingSelf = 0b10,
    /// Send to all excluding self
    AllExcludingSelf = 0b11,
}

impl LocalApic {
    /// Send an Inter-Processor Interrupt
    ///
    /// # Arguments
    /// * `dest_apic_id` - Destination APIC ID (ignored for broadcast)
    /// * `vector` - Interrupt vector
    /// * `delivery_mode` - Delivery mode
    /// * `dest_shorthand` - Destination shorthand
    pub fn send_ipi(
        &self,
        dest_apic_id: u8,
        vector: u8,
        delivery_mode: IpiDeliveryMode,
        dest_shorthand: IpiDestination,
    ) {
        // Build ICR value
        // Bits: 0-7 vector, 8-10 delivery mode, 11 dest mode (0=physical),
        //       12 delivery status (read-only), 13 reserved,
        //       14 level (1=assert), 15 trigger mode (0=edge),
        //       16-17 reserved, 18-19 dest shorthand
        let icr_low: u32 = (vector as u32)
            | ((delivery_mode as u32) << 8)
            | (1 << 14) // Assert
            | ((dest_shorthand as u32) << 18);

        let icr_high: u32 = (dest_apic_id as u32) << 24;

        // Write ICR (high then low, as writing low triggers the IPI)
        self.write(reg::ICR_HIGH, icr_high);
        self.write(reg::ICR_LOW, icr_low);

        // Wait for delivery (poll delivery status bit)
        while (self.read(reg::ICR_LOW) & (1 << 12)) != 0 {
            core::hint::spin_loop();
        }
    }

    /// Send INIT IPI to a processor
    ///
    /// This is the first step in starting an Application Processor (AP).
    pub fn send_init_ipi(&self, dest_apic_id: u8) {
        // Send INIT with level assert
        // Bit 14: Level (1=Assert), Bit 15: Trigger (0=Edge)
        let icr_low: u32 = (IpiDeliveryMode::Init as u32) << 8
            | (1 << 14);  // Level: Assert (Trigger: Edge is default 0)

        let icr_high: u32 = (dest_apic_id as u32) << 24;

        self.write(reg::ICR_HIGH, icr_high);
        self.write(reg::ICR_LOW, icr_low);

        // Wait for delivery
        while (self.read(reg::ICR_LOW) & (1 << 12)) != 0 {
            core::hint::spin_loop();
        }
    }

    /// Send INIT IPI de-assert (level-triggered)
    pub fn send_init_ipi_deassert(&self) {
        // INIT de-assert is broadcast to all processors
        // Bit 14: Level (0=De-assert), Bit 15: Trigger (1=Level)
        let icr_low: u32 = (IpiDeliveryMode::Init as u32) << 8
            | (1 << 15)  // Trigger: Level (Level: De-assert is default 0)
            | (IpiDestination::AllIncludingSelf as u32) << 18;

        self.write(reg::ICR_LOW, icr_low);

        // Wait for delivery
        while (self.read(reg::ICR_LOW) & (1 << 12)) != 0 {
            core::hint::spin_loop();
        }
    }

    /// Send Startup IPI (SIPI) to a processor
    ///
    /// # Arguments
    /// * `dest_apic_id` - Target APIC ID
    /// * `vector` - Startup vector (physical address >> 12, must be < 0x100).
    ///   The AP will start executing at physical address vector * 0x1000
    pub fn send_startup_ipi(&self, dest_apic_id: u8, vector: u8) {
        let icr_low: u32 = (vector as u32)
            | ((IpiDeliveryMode::Startup as u32) << 8)
            | (1 << 14); // Assert

        let icr_high: u32 = (dest_apic_id as u32) << 24;

        self.write(reg::ICR_HIGH, icr_high);
        self.write(reg::ICR_LOW, icr_low);

        // Wait for delivery
        while (self.read(reg::ICR_LOW) & (1 << 12)) != 0 {
            core::hint::spin_loop();
        }
    }

    /// Send a fixed IPI to another processor
    pub fn send_fixed_ipi(&self, dest_apic_id: u8, vector: u8) {
        self.send_ipi(dest_apic_id, vector, IpiDeliveryMode::Fixed, IpiDestination::NoShorthand);
    }

    /// Send an NMI to another processor
    pub fn send_nmi(&self, dest_apic_id: u8) {
        self.send_ipi(dest_apic_id, 0, IpiDeliveryMode::Nmi, IpiDestination::NoShorthand);
    }

    /// Broadcast an IPI to all processors (excluding self)
    pub fn broadcast_ipi(&self, vector: u8) {
        self.send_ipi(0, vector, IpiDeliveryMode::Fixed, IpiDestination::AllExcludingSelf);
    }

    /// Broadcast an IPI to all processors (including self)
    pub fn broadcast_ipi_all(&self, vector: u8) {
        self.send_ipi(0, vector, IpiDeliveryMode::Fixed, IpiDestination::AllIncludingSelf);
    }
}

/// Send an IPI to a specific processor (convenience function)
pub fn send_ipi(dest_apic_id: u8, vector: u8) {
    get().send_fixed_ipi(dest_apic_id, vector);
}

/// Broadcast an IPI to all processors except self (convenience function)
pub fn broadcast_ipi(vector: u8) {
    get().broadcast_ipi(vector);
}

// ============================================================================
// I/O APIC Support
// ============================================================================

/// I/O APIC register select offset
const IOAPIC_REGSEL: u32 = 0x00;
/// I/O APIC data window offset
const IOAPIC_WINDOW: u32 = 0x10;

/// I/O APIC register indices
mod ioapic_reg {
    pub const ID: u32 = 0x00;
    pub const VERSION: u32 = 0x01;
    pub const ARBITRATION: u32 = 0x02;
    pub const REDIRECTION_TABLE_BASE: u32 = 0x10;
}

/// I/O APIC redirection entry
#[derive(Clone, Copy, Debug)]
pub struct IoApicRedirectionEntry {
    /// Interrupt vector
    pub vector: u8,
    /// Delivery mode (000 = fixed, 001 = lowest, 010 = SMI, 100 = NMI, 101 = INIT, 111 = ExtINT)
    pub delivery_mode: u8,
    /// Destination mode (0 = physical, 1 = logical)
    pub dest_mode: bool,
    /// Delivery status (read-only, 0 = idle, 1 = pending)
    pub delivery_status: bool,
    /// Pin polarity (0 = active high, 1 = active low)
    pub polarity: bool,
    /// Remote IRR (read-only for level-triggered)
    pub remote_irr: bool,
    /// Trigger mode (0 = edge, 1 = level)
    pub trigger_mode: bool,
    /// Mask (0 = enabled, 1 = masked)
    pub masked: bool,
    /// Destination (APIC ID or logical destination)
    pub destination: u8,
}

impl IoApicRedirectionEntry {
    /// Create a default (masked) entry
    pub fn masked() -> Self {
        Self {
            vector: 0,
            delivery_mode: 0,
            dest_mode: false,
            delivery_status: false,
            polarity: false,
            remote_irr: false,
            trigger_mode: false,
            masked: true,
            destination: 0,
        }
    }

    /// Create an entry for an ISA interrupt
    pub fn for_isa(vector: u8, dest_apic_id: u8) -> Self {
        Self {
            vector,
            delivery_mode: 0, // Fixed
            dest_mode: false, // Physical
            delivery_status: false,
            polarity: false,  // Active high (ISA default)
            remote_irr: false,
            trigger_mode: false, // Edge triggered (ISA default)
            masked: false,
            destination: dest_apic_id,
        }
    }

    /// Convert to raw 64-bit value
    pub fn to_raw(&self) -> u64 {
        let mut value: u64 = self.vector as u64;
        value |= (self.delivery_mode as u64 & 0x7) << 8;
        if self.dest_mode { value |= 1 << 11; }
        if self.polarity { value |= 1 << 13; }
        if self.trigger_mode { value |= 1 << 15; }
        if self.masked { value |= 1 << 16; }
        value |= (self.destination as u64) << 56;
        value
    }

    /// Create from raw 64-bit value
    pub fn from_raw(value: u64) -> Self {
        Self {
            vector: (value & 0xFF) as u8,
            delivery_mode: ((value >> 8) & 0x7) as u8,
            dest_mode: (value & (1 << 11)) != 0,
            delivery_status: (value & (1 << 12)) != 0,
            polarity: (value & (1 << 13)) != 0,
            remote_irr: (value & (1 << 14)) != 0,
            trigger_mode: (value & (1 << 15)) != 0,
            masked: (value & (1 << 16)) != 0,
            destination: ((value >> 56) & 0xFF) as u8,
        }
    }
}

/// I/O APIC interface
pub struct IoApic {
    base_addr: u64,
}

impl IoApic {
    /// Create a new I/O APIC instance
    pub fn new(base_addr: u64) -> Self {
        Self { base_addr }
    }

    /// Read an I/O APIC register
    fn read(&self, reg: u32) -> u32 {
        unsafe {
            // Write register select
            write_volatile((self.base_addr + IOAPIC_REGSEL as u64) as *mut u32, reg);
            // Read data
            read_volatile((self.base_addr + IOAPIC_WINDOW as u64) as *const u32)
        }
    }

    /// Write to an I/O APIC register
    fn write(&self, reg: u32, value: u32) {
        unsafe {
            // Write register select
            write_volatile((self.base_addr + IOAPIC_REGSEL as u64) as *mut u32, reg);
            // Write data
            write_volatile((self.base_addr + IOAPIC_WINDOW as u64) as *mut u32, value);
        }
    }

    /// Get the I/O APIC ID
    pub fn id(&self) -> u8 {
        ((self.read(ioapic_reg::ID) >> 24) & 0xF) as u8
    }

    /// Get the I/O APIC version and max redirection entries
    pub fn version(&self) -> (u8, u8) {
        let ver = self.read(ioapic_reg::VERSION);
        ((ver & 0xFF) as u8, ((ver >> 16) & 0xFF) as u8 + 1)
    }

    /// Read a redirection entry
    pub fn read_redirection(&self, irq: u8) -> IoApicRedirectionEntry {
        let reg_base = ioapic_reg::REDIRECTION_TABLE_BASE + (irq as u32 * 2);
        let low = self.read(reg_base) as u64;
        let high = self.read(reg_base + 1) as u64;
        IoApicRedirectionEntry::from_raw(low | (high << 32))
    }

    /// Write a redirection entry
    pub fn write_redirection(&self, irq: u8, entry: IoApicRedirectionEntry) {
        let reg_base = ioapic_reg::REDIRECTION_TABLE_BASE + (irq as u32 * 2);
        let raw = entry.to_raw();
        // Write high first (contains destination which doesn't trigger routing change)
        self.write(reg_base + 1, (raw >> 32) as u32);
        self.write(reg_base, raw as u32);
    }

    /// Mask (disable) an IRQ
    pub fn mask(&self, irq: u8) {
        let mut entry = self.read_redirection(irq);
        entry.masked = true;
        self.write_redirection(irq, entry);
    }

    /// Unmask (enable) an IRQ
    pub fn unmask(&self, irq: u8) {
        let mut entry = self.read_redirection(irq);
        entry.masked = false;
        self.write_redirection(irq, entry);
    }

    /// Initialize I/O APIC - mask all interrupts
    pub fn init(&self) {
        let (_, max_entries) = self.version();
        for i in 0..max_entries {
            self.write_redirection(i, IoApicRedirectionEntry::masked());
        }
    }
}

// ============================================================================
// MP Startup Support
// ============================================================================

/// IPI vectors for kernel use
pub mod ipi_vector {
    /// Reschedule IPI - triggers scheduler on target CPU
    pub const RESCHEDULE: u8 = 0xFD;
    /// TLB shootdown IPI - invalidate TLB on target CPU
    pub const TLB_SHOOTDOWN: u8 = 0xFE;
    /// Stop IPI - halt target CPU
    pub const STOP: u8 = 0xFF;
}

/// Start an Application Processor using INIT-SIPI-SIPI sequence
///
/// # Arguments
/// * `apic_id` - The APIC ID of the processor to start
/// * `startup_vector` - The physical page number where AP startup code resides
///   (physical address = startup_vector * 0x1000)
///
/// # Safety
/// The startup code must be properly set up at the specified address before
/// calling this function.
pub unsafe fn start_ap(apic_id: u8, startup_vector: u8) {
    let apic = get();

    // Send INIT IPI
    apic.send_init_ipi(apic_id);

    // Wait 10ms (INIT-SIPI delay as per Intel spec)
    // For now, use a simple delay loop
    for _ in 0..10_000 {
        core::hint::spin_loop();
    }

    // Send first SIPI
    apic.send_startup_ipi(apic_id, startup_vector);

    // Wait 200μs
    for _ in 0..1_000 {
        core::hint::spin_loop();
    }

    // Send second SIPI (some processors need this)
    apic.send_startup_ipi(apic_id, startup_vector);
}

/// Get the current processor's APIC ID
pub fn current_apic_id() -> u8 {
    get().id()
}

/// Start all Application Processors discovered by ACPI
///
/// This function:
/// 1. Sets up the AP trampoline code in low memory
/// 2. Sends INIT-SIPI-SIPI sequence to each AP
/// 3. Waits for APs to complete initialization
///
/// # Safety
/// Must be called after ACPI initialization and before enabling scheduling on APs
pub unsafe fn start_all_aps() {
    use crate::arch::x86_64::ap_trampoline;

    crate::serial_println!("[SMP] Starting Application Processors...");

    // Setup trampoline code in low memory
    // Note: setup_trampoline() already writes the entry point address to 0x8158
    // and the PML4 address to 0x8160, so we don't need to do that here
    ap_trampoline::setup_trampoline();

    // Get processor count from ACPI
    let processor_count = super::acpi::get_processor_count();
    crate::serial_println!("[SMP] ACPI reported {} total processors", processor_count);

    let mut ap_count = 0u32;

    // Start each AP (skip index 0, which is the BSP)
    for i in 1..processor_count {
        if let Some(proc_info) = super::acpi::get_processor(i) {
            if !proc_info.enabled {
                crate::serial_println!("[SMP] Skipping disabled processor {} (APIC ID {})",
                    i, proc_info.apic_id);
                continue;
            }

            crate::serial_println!("[SMP] Starting AP {} (APIC ID {})...",
                i, proc_info.apic_id);

            // Send INIT-SIPI-SIPI sequence
            // Startup vector = 0x08 (trampoline at 0x8000)
            start_ap(proc_info.apic_id, 0x08);

            ap_count += 1;

            // Wait a bit before starting next AP
            for _ in 0..50_000 {
                core::hint::spin_loop();
            }
        }
    }

    if ap_count > 0 {
        crate::serial_println!("[SMP] Waiting for {} APs to start (timeout 5s)...", ap_count);

        // Wait for APs to signal they've started (5 second timeout)
        if ap_trampoline::wait_for_aps(ap_count, 5000) {
            crate::serial_println!("[SMP] All {} APs started successfully!", ap_count);
        } else {
            crate::serial_println!("[SMP] WARNING: Timeout waiting for APs. {} started, {} expected",
                ap_trampoline::AP_STARTED_COUNT.load(core::sync::atomic::Ordering::Acquire),
                ap_count);
        }
    } else {
        crate::serial_println!("[SMP] No additional processors to start (single CPU system)");
    }
}
