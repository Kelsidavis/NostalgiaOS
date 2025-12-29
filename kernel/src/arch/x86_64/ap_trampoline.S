# Application Processor Trampoline Code
#
# This code runs when an Application Processor (AP) starts up.
# It begins in 16-bit real mode and transitions to 64-bit long mode.
#
# Entry: CS:IP = 0x0000:0x8000 (real mode)
# Exit: Jumps to ap_main in 64-bit long mode

.code16
.section .ap_trampoline, "awx"
.global ap_trampoline_start
.global ap_trampoline_end

ap_trampoline_start:
    cli                      # Disable interrupts

    # Set up segments for real mode
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax

    # Load our GDT
    lgdt [ap_gdt_desc]

    # Enable protected mode (set CR0.PE = 1)
    mov eax, cr0
    or al, 1
    mov cr0, eax

    # Far jump to 32-bit protected mode
    # GDT entry 1 is 32-bit code segment
    ljmp $0x08, $ap_protected_mode

.code32
ap_protected_mode:
    # Set up 32-bit segments
    mov ax, 0x10             # GDT entry 2 = 32-bit data
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    # Enable PAE (Physical Address Extension)
    mov eax, cr4
    or eax, (1 << 5)         # CR4.PAE = 1
    mov cr4, eax

    # Load page tables (PML4)
    # We'll use the kernel's page tables
    mov eax, 0x1000          # Kernel PML4 physical address (from bootloader)
    mov cr3, eax

    # Enable long mode (set EFER.LME = 1)
    mov ecx, 0xC0000080      # EFER MSR
    rdmsr
    or eax, (1 << 8)         # EFER.LME = 1
    wrmsr

    # Enable paging (set CR0.PG = 1)
    # This activates long mode
    mov eax, cr0
    or eax, (1 << 31)        # CR0.PG = 1
    mov cr0, eax

    # Far jump to 64-bit long mode
    # GDT entry 3 is 64-bit code segment
    ljmp $0x18, $ap_long_mode

.code64
ap_long_mode:
    # Set up 64-bit segments
    mov ax, 0x20             # GDT entry 4 = 64-bit data
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    # Set up stack
    mov rsp, 0x9000          # Stack grows down from 0x9000

    # Jump to ap_main (Rust entry point)
    # The address is stored at known location
    mov rax, [ap_entry_point_addr]
    call rax

    # Should never reach here
1:
    hlt
    jmp 1b

# GDT for AP startup
.align 16
ap_gdt:
    # Entry 0: Null descriptor
    .quad 0

    # Entry 1: 32-bit code segment
    .word 0xFFFF             # Limit 0-15
    .word 0x0000             # Base 0-15
    .byte 0x00               # Base 16-23
    .byte 0x9A               # Access: Present, DPL=0, Code, Executable, Readable
    .byte 0xCF               # Flags: Granularity=4K, 32-bit
    .byte 0x00               # Base 24-31

    # Entry 2: 32-bit data segment
    .word 0xFFFF
    .word 0x0000
    .byte 0x00
    .byte 0x92               # Access: Present, DPL=0, Data, Writable
    .byte 0xCF
    .byte 0x00

    # Entry 3: 64-bit code segment
    .word 0x0000             # Limit (ignored in long mode)
    .word 0x0000             # Base (ignored in long mode)
    .byte 0x00
    .byte 0x9A               # Access: Present, DPL=0, Code, Executable, Readable
    .byte 0xAF               # Flags: Granularity=4K, Long mode (L=1)
    .byte 0x00

    # Entry 4: 64-bit data segment
    .word 0x0000
    .word 0x0000
    .byte 0x00
    .byte 0x92               # Access: Present, DPL=0, Data, Writable
    .byte 0x00               # Flags: No special flags for data in long mode
    .byte 0x00

ap_gdt_end:

# GDT descriptor
.align 16
ap_gdt_desc:
    .word ap_gdt_end - ap_gdt - 1    # Limit
    .long ap_gdt                      # Base (32-bit for real/protected mode)

# AP entry point address (filled in by Rust code)
.align 8
.global ap_entry_point_addr
ap_entry_point_addr:
    .quad 0

ap_trampoline_end:
