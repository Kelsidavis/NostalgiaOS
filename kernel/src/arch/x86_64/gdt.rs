//! Global Descriptor Table (GDT)
//!
//! The GDT defines memory segments and privilege levels.
//! In long mode, segmentation is largely disabled, but we still need:
//!
//! - Null descriptor (required)
//! - Kernel code segment (CS for ring 0)
//! - Kernel data segment (DS/SS for ring 0)
//! - User code segment (CS for ring 3)
//! - User data segment (DS/SS for ring 3)
//! - TSS descriptor (for interrupt stack switching)

use spin::Lazy;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::registers::segmentation::SegmentSelector;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector as GdtSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// Size of interrupt stacks
const STACK_SIZE: usize = 4096 * 5; // 20 KB

/// Interrupt Stack Table index for double fault handler
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Interrupt Stack Table index for page fault handler
pub const PAGE_FAULT_IST_INDEX: u16 = 1;

/// Interrupt Stack Table index for general protection fault handler
pub const GPF_IST_INDEX: u16 = 2;

/// Task State Segment
///
/// Used primarily for:
/// - Interrupt stack table (IST) - separate stacks for critical exceptions
/// - RSP0 - stack pointer for privilege level 0 (kernel)
static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();

    // Set up RSP0 - kernel stack used when interrupt occurs in ring 3
    tss.privilege_stack_table[0] = {
        static mut RSP0_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
        let stack_start = VirtAddr::from_ptr(&raw const RSP0_STACK);
        stack_start + STACK_SIZE as u64 // Stack grows down
    };

    // Set up interrupt stack for double faults
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
        static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
        let stack_start = VirtAddr::from_ptr(&raw const STACK);
        stack_start + STACK_SIZE as u64 // Stack grows down
    };

    // Set up interrupt stack for page faults
    tss.interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] = {
        static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
        let stack_start = VirtAddr::from_ptr(&raw const STACK);
        stack_start + STACK_SIZE as u64
    };

    // Set up interrupt stack for general protection faults
    tss.interrupt_stack_table[GPF_IST_INDEX as usize] = {
        static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
        let stack_start = VirtAddr::from_ptr(&raw const STACK);
        stack_start + STACK_SIZE as u64
    };

    tss
});

/// GDT and segment selectors
struct Gdt {
    gdt: GlobalDescriptorTable,
    kernel_code_selector: GdtSelector,
    kernel_data_selector: GdtSelector,
    user_code_selector: GdtSelector,
    user_data_selector: GdtSelector,
    tss_selector: GdtSelector,
}

static GDT: Lazy<Gdt> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();

    // Add segments in the order expected by SYSCALL/SYSRET
    let kernel_code_selector = gdt.append(Descriptor::kernel_code_segment());
    let kernel_data_selector = gdt.append(Descriptor::kernel_data_segment());
    let user_data_selector = gdt.append(Descriptor::user_data_segment());
    let user_code_selector = gdt.append(Descriptor::user_code_segment());
    let tss_selector = gdt.append(Descriptor::tss_segment(&TSS));

    Gdt {
        gdt,
        kernel_code_selector,
        kernel_data_selector,
        user_code_selector,
        user_data_selector,
        tss_selector,
    }
});

/// Initialize the GDT
///
/// Loads the GDT and sets up segment registers and TSS.
pub fn init() {
    // Load the GDT
    GDT.gdt.load();

    // Reload segment registers
    unsafe {
        // Set CS to kernel code segment
        CS::set_reg(GDT.kernel_code_selector);

        // Set data segments to kernel data segment
        DS::set_reg(GDT.kernel_data_selector);
        ES::set_reg(GDT.kernel_data_selector);
        SS::set_reg(GDT.kernel_data_selector);

        // Load TSS
        load_tss(GDT.tss_selector);
    }
}

/// Get the kernel code segment selector
#[inline]
pub fn kernel_code_selector() -> SegmentSelector {
    SegmentSelector(GDT.kernel_code_selector.0)
}

/// Get the kernel data segment selector
#[inline]
pub fn kernel_data_selector() -> SegmentSelector {
    SegmentSelector(GDT.kernel_data_selector.0)
}

/// Get the user code segment selector
#[inline]
pub fn user_code_selector() -> SegmentSelector {
    SegmentSelector(GDT.user_code_selector.0)
}

/// Get the user data segment selector
#[inline]
pub fn user_data_selector() -> SegmentSelector {
    SegmentSelector(GDT.user_data_selector.0)
}
