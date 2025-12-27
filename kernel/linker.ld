/* Nostalgia OS Kernel Linker Script */

ENTRY(kernel_main)

/* Kernel is loaded at 16MB physical, mapped to higher half */
KERNEL_PHYS_BASE = 0x0000000001000000;
KERNEL_VIRT_BASE = 0xFFFFFFFF80000000;

SECTIONS
{
    /* Virtual address where kernel will be mapped */
    . = KERNEL_VIRT_BASE;

    /* Text section - code comes first */
    .text ALIGN(4K) : AT(KERNEL_PHYS_BASE)
    {
        *(.text.kernel_main)  /* Entry point first */
        *(.text .text.*)
    }

    /* Read-only data */
    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE)
    {
        *(.rodata .rodata.*)
    }

    /* Initialized data */
    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE)
    {
        *(.data .data.*)
    }

    /* Uninitialized data (BSS) */
    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* End of kernel */
    . = ALIGN(4K);
    __kernel_end = .;
    __kernel_size = . - KERNEL_VIRT_BASE;

    /* Discard unnecessary sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
