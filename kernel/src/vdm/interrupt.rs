//! VDM Interrupt Handling
//!
//! Manages software and hardware interrupt handling for DOS applications.
//! Provides INT instruction emulation and interrupt vector management.

extern crate alloc;

use super::{VdmFlags, V86Context, VDM_TABLE};
use crate::ke::spinlock::SpinLock;

// ============================================================================
// Interrupt Constants
// ============================================================================

/// Common DOS interrupt vectors
pub mod vectors {
    /// Divide error
    pub const INT_DIVIDE: u8 = 0x00;
    /// Single step
    pub const INT_DEBUG: u8 = 0x01;
    /// NMI
    pub const INT_NMI: u8 = 0x02;
    /// Breakpoint
    pub const INT_BREAKPOINT: u8 = 0x03;
    /// Overflow
    pub const INT_OVERFLOW: u8 = 0x04;
    /// Print screen
    pub const INT_PRINT_SCREEN: u8 = 0x05;
    /// Timer tick (IRQ0)
    pub const INT_TIMER: u8 = 0x08;
    /// Keyboard (IRQ1)
    pub const INT_KEYBOARD: u8 = 0x09;
    /// COM2/COM4 (IRQ3)
    pub const INT_COM2: u8 = 0x0B;
    /// COM1/COM3 (IRQ4)
    pub const INT_COM1: u8 = 0x0C;
    /// LPT2 (IRQ5)
    pub const INT_LPT2: u8 = 0x0D;
    /// Floppy (IRQ6)
    pub const INT_FLOPPY: u8 = 0x0E;
    /// LPT1 (IRQ7)
    pub const INT_LPT1: u8 = 0x0F;
    /// Video BIOS
    pub const INT_VIDEO: u8 = 0x10;
    /// Equipment check
    pub const INT_EQUIPMENT: u8 = 0x11;
    /// Memory size
    pub const INT_MEMORY: u8 = 0x12;
    /// Disk BIOS
    pub const INT_DISK: u8 = 0x13;
    /// Serial port BIOS
    pub const INT_SERIAL: u8 = 0x14;
    /// Cassette/system services
    pub const INT_SYSTEM: u8 = 0x15;
    /// Keyboard BIOS
    pub const INT_KEYBOARD_BIOS: u8 = 0x16;
    /// Printer BIOS
    pub const INT_PRINTER: u8 = 0x17;
    /// ROM BASIC
    pub const INT_BASIC: u8 = 0x18;
    /// Bootstrap loader
    pub const INT_BOOTSTRAP: u8 = 0x19;
    /// Time of day
    pub const INT_TIME: u8 = 0x1A;
    /// Ctrl-Break
    pub const INT_CTRL_BREAK: u8 = 0x1B;
    /// Timer tick (user)
    pub const INT_USER_TIMER: u8 = 0x1C;
    /// Video parameter table
    pub const INT_VIDEO_PARAMS: u8 = 0x1D;
    /// Disk parameter table
    pub const INT_DISK_PARAMS: u8 = 0x1E;
    /// Graphics characters
    pub const INT_GRAPHICS_CHARS: u8 = 0x1F;
    /// DOS function calls
    pub const INT_DOS: u8 = 0x21;
    /// DOS terminate
    pub const INT_TERMINATE: u8 = 0x20;
    /// DOS TSR
    pub const INT_TSR: u8 = 0x27;
    /// DOS idle
    pub const INT_IDLE: u8 = 0x28;
    /// DOS absolute disk read
    pub const INT_DISK_READ: u8 = 0x25;
    /// DOS absolute disk write
    pub const INT_DISK_WRITE: u8 = 0x26;
    /// Mouse
    pub const INT_MOUSE: u8 = 0x33;
    /// DPMI
    pub const INT_DPMI: u8 = 0x31;
    /// EMS
    pub const INT_EMS: u8 = 0x67;
    /// XMS
    pub const INT_XMS: u8 = 0x2F;
}

/// Interrupt handler result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptResult {
    /// Interrupt was handled
    Handled,
    /// Interrupt should be reflected to DOS
    Reflect,
    /// Interrupt caused VDM termination
    Terminate,
    /// Interrupt not recognized
    Unknown,
}

/// DOS function codes (INT 21h AH values)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DosFunction {
    /// Terminate program
    Terminate = 0x00,
    /// Read character with echo
    ReadCharEcho = 0x01,
    /// Write character
    WriteChar = 0x02,
    /// Read string
    ReadString = 0x0A,
    /// Check keyboard status
    CheckKeyboard = 0x0B,
    /// Reset disk
    ResetDisk = 0x0D,
    /// Set default drive
    SetDrive = 0x0E,
    /// Get default drive
    GetDrive = 0x19,
    /// Set DTA
    SetDta = 0x1A,
    /// Get date
    GetDate = 0x2A,
    /// Set date
    SetDate = 0x2B,
    /// Get time
    GetTime = 0x2C,
    /// Set time
    SetTime = 0x2D,
    /// Get DOS version
    GetVersion = 0x30,
    /// Terminate and stay resident
    Tsr = 0x31,
    /// Get interrupt vector
    GetVector = 0x35,
    /// Get free disk space
    GetDiskSpace = 0x36,
    /// Create directory
    Mkdir = 0x39,
    /// Remove directory
    Rmdir = 0x3A,
    /// Change directory
    Chdir = 0x3B,
    /// Create file
    Create = 0x3C,
    /// Open file
    Open = 0x3D,
    /// Close file
    Close = 0x3E,
    /// Read file
    Read = 0x3F,
    /// Write file
    Write = 0x40,
    /// Delete file
    Delete = 0x41,
    /// Seek file
    Seek = 0x42,
    /// Get/set file attributes
    FileAttrib = 0x43,
    /// Get current directory
    GetCwd = 0x47,
    /// Allocate memory
    Alloc = 0x48,
    /// Free memory
    Free = 0x49,
    /// Resize memory block
    Resize = 0x4A,
    /// Execute program
    Exec = 0x4B,
    /// Exit with return code
    Exit = 0x4C,
    /// Find first file
    FindFirst = 0x4E,
    /// Find next file
    FindNext = 0x4F,
    /// Get PSP
    GetPsp = 0x62,
}

// ============================================================================
// Interrupt State
// ============================================================================

/// Pending interrupt queue entry
#[derive(Debug, Clone)]
struct PendingInterrupt {
    /// VDM ID
    vdm_id: u32,
    /// Interrupt vector
    vector: u8,
    /// Hardware interrupt flag
    is_hardware: bool,
}

static PENDING_QUEUE: SpinLock<alloc::vec::Vec<PendingInterrupt>> =
    SpinLock::new(alloc::vec::Vec::new());

// ============================================================================
// Interrupt Functions
// ============================================================================

/// Initialize interrupt handling
pub fn init() {
    crate::serial_println!("[VDM] Interrupt handling initialized");
}

/// Queue an interrupt for a VDM
pub fn vdm_queue_interrupt(vdm_id: u32, vector: u8, is_hardware: bool) -> bool {
    let mut table = VDM_TABLE.lock();
    if let Some(state) = table.get_mut(&vdm_id) {
        state.queue_interrupt(vector);

        // Also add to global pending queue
        let mut queue = PENDING_QUEUE.lock();
        queue.push(PendingInterrupt {
            vdm_id,
            vector,
            is_hardware,
        });

        true
    } else {
        false
    }
}

/// Queue interrupt from user mode (used by NtVdmControl)
pub fn vdm_queue_interrupt_from_user(params_ptr: usize) -> i32 {
    if params_ptr == 0 {
        return -1;
    }

    // In real implementation, would read vdm_id and vector from params_ptr
    // For now, just acknowledge
    0
}

/// Handle a software interrupt (INT instruction)
pub fn vdm_handle_interrupt(vdm_id: u32, vector: u8, context: &mut V86Context) -> InterruptResult {
    match vector {
        vectors::INT_DOS => handle_dos_interrupt(vdm_id, context),
        vectors::INT_VIDEO => handle_video_interrupt(context),
        vectors::INT_KEYBOARD_BIOS => handle_keyboard_interrupt(context),
        vectors::INT_DISK => handle_disk_interrupt(context),
        vectors::INT_TIME => handle_time_interrupt(context),
        vectors::INT_SYSTEM => handle_system_interrupt(context),
        vectors::INT_TERMINATE | vectors::INT_TSR => {
            // Program termination
            InterruptResult::Terminate
        }
        vectors::INT_DPMI => handle_dpmi_interrupt(context),
        vectors::INT_MOUSE => handle_mouse_interrupt(context),
        _ => {
            // Unknown interrupt, reflect to DOS handler
            InterruptResult::Reflect
        }
    }
}

/// Handle DOS INT 21h
fn handle_dos_interrupt(vdm_id: u32, context: &mut V86Context) -> InterruptResult {
    let function = (context.eax >> 8) as u8;

    match function {
        0x00 | 0x4C => {
            // Terminate program
            crate::serial_println!("[VDM] DOS terminate, exit code {}", context.eax as u8);
            InterruptResult::Terminate
        }

        0x02 => {
            // Write character (DL)
            let ch = context.edx as u8 as char;
            crate::serial_print!("{}", ch);
            InterruptResult::Handled
        }

        0x09 => {
            // Write string (DS:DX points to $-terminated string)
            // In real implementation, would read from VDM memory
            InterruptResult::Handled
        }

        0x19 => {
            // Get current drive
            context.eax = (context.eax & 0xFFFFFF00) | 2; // C: drive
            InterruptResult::Handled
        }

        0x2A => {
            // Get date
            // CX = year, DH = month, DL = day, AL = day of week
            context.ecx = (context.ecx & 0xFFFF0000) | 2003; // Year 2003
            context.edx = (context.edx & 0xFFFF0000) | 0x0101; // Jan 1
            context.eax = (context.eax & 0xFFFFFF00) | 3; // Wednesday
            InterruptResult::Handled
        }

        0x2C => {
            // Get time
            // CH = hour, CL = minute, DH = second, DL = 1/100 sec
            context.ecx = (context.ecx & 0xFFFF0000) | 0x0C00; // 12:00
            context.edx = (context.edx & 0xFFFF0000) | 0x0000; // 00.00
            InterruptResult::Handled
        }

        0x30 => {
            // Get DOS version
            let table = VDM_TABLE.lock();
            let (major, minor) = if let Some(state) = table.get(&vdm_id) {
                state.dos_version
            } else {
                (5, 0)
            };
            context.eax = (context.eax & 0xFFFF0000) | (minor as u32) << 8 | major as u32;
            context.ebx = 0; // OEM serial number
            context.ecx = 0; // No user serial
            InterruptResult::Handled
        }

        0x35 => {
            // Get interrupt vector
            let int_num = context.eax as u8;
            let table = VDM_TABLE.lock();
            if let Some(state) = table.get(&vdm_id) {
                let (seg, off) = state.get_interrupt_vector(int_num);
                context.es = seg;
                context.ebx = (context.ebx & 0xFFFF0000) | off as u32;
            }
            InterruptResult::Handled
        }

        0x36 => {
            // Get free disk space
            // Returns: AX = sectors/cluster, BX = free clusters
            //          CX = bytes/sector, DX = total clusters
            context.eax = (context.eax & 0xFFFF0000) | 8; // 8 sectors/cluster
            context.ebx = (context.ebx & 0xFFFF0000) | 0x8000; // Free clusters
            context.ecx = (context.ecx & 0xFFFF0000) | 512; // 512 bytes/sector
            context.edx = (context.edx & 0xFFFF0000) | 0xFFFF; // Total clusters
            InterruptResult::Handled
        }

        0x48 => {
            // Allocate memory
            // BX = paragraphs requested
            // Returns: AX = segment, or error with BX = largest available
            let paragraphs = (context.ebx & 0xFFFF) as u16;
            // Simplified: pretend we have memory
            context.eax = (context.eax & 0xFFFF0000) | 0x1000; // Return segment 0x1000
            // Clear carry flag to indicate success
            context.eflags &= !0x01;
            InterruptResult::Handled
        }

        0x49 => {
            // Free memory
            // ES = segment to free
            // Clear carry flag to indicate success
            context.eflags &= !0x01;
            InterruptResult::Handled
        }

        0x62 => {
            // Get PSP
            let table = VDM_TABLE.lock();
            let psp = if let Some(state) = table.get(&vdm_id) {
                state.current_psp
            } else {
                0x100
            };
            context.ebx = (context.ebx & 0xFFFF0000) | psp as u32;
            InterruptResult::Handled
        }

        _ => {
            // Unhandled DOS function, reflect
            crate::serial_println!("[VDM] Unhandled DOS function: {:02X}h", function);
            InterruptResult::Reflect
        }
    }
}

/// Handle video BIOS INT 10h
fn handle_video_interrupt(context: &mut V86Context) -> InterruptResult {
    let function = (context.eax >> 8) as u8;

    match function {
        0x00 => {
            // Set video mode
            let mode = context.eax as u8;
            crate::serial_println!("[VDM] Set video mode: {:02X}h", mode);
            InterruptResult::Handled
        }

        0x02 => {
            // Set cursor position
            // BH = page, DH = row, DL = column
            InterruptResult::Handled
        }

        0x03 => {
            // Get cursor position
            // Returns: DH = row, DL = column, CH = start line, CL = end line
            context.edx = (context.edx & 0xFFFF0000) | 0x0000; // Row 0, Col 0
            context.ecx = (context.ecx & 0xFFFF0000) | 0x0607; // Normal cursor
            InterruptResult::Handled
        }

        0x0E => {
            // Teletype output
            let ch = context.eax as u8 as char;
            crate::serial_print!("{}", ch);
            InterruptResult::Handled
        }

        0x0F => {
            // Get video mode
            // Returns: AH = columns, AL = mode, BH = page
            context.eax = (context.eax & 0xFFFF0000) | 0x5003; // 80 cols, mode 3
            context.ebx = (context.ebx & 0xFFFF00FF); // Page 0
            InterruptResult::Handled
        }

        _ => InterruptResult::Reflect
    }
}

/// Handle keyboard BIOS INT 16h
fn handle_keyboard_interrupt(context: &mut V86Context) -> InterruptResult {
    let function = (context.eax >> 8) as u8;

    match function {
        0x00 | 0x10 => {
            // Read character (blocking)
            // Returns: AH = scan code, AL = ASCII
            // For now, return 'A'
            context.eax = (context.eax & 0xFFFF0000) | 0x1E41; // 'A'
            InterruptResult::Handled
        }

        0x01 | 0x11 => {
            // Check keyboard status
            // ZF = 1 if no key, AX = key if available
            context.eflags |= 0x40; // Set ZF (no key)
            InterruptResult::Handled
        }

        0x02 | 0x12 => {
            // Get shift key status
            context.eax = (context.eax & 0xFFFFFF00); // No shift keys
            InterruptResult::Handled
        }

        _ => InterruptResult::Reflect
    }
}

/// Handle disk BIOS INT 13h
fn handle_disk_interrupt(context: &mut V86Context) -> InterruptResult {
    let function = (context.eax >> 8) as u8;

    match function {
        0x00 => {
            // Reset disk
            context.eax = (context.eax & 0xFFFFFF00); // Success
            context.eflags &= !0x01; // Clear carry
            InterruptResult::Handled
        }

        0x02 => {
            // Read sectors
            // Returns sectors read in AL, CF=0 on success
            context.eflags &= !0x01; // Clear carry
            InterruptResult::Handled
        }

        0x08 => {
            // Get drive parameters
            // Returns: CH = low 8 bits of cylinders
            //          CL = sectors + high 2 bits of cylinders
            //          DH = heads - 1
            //          DL = number of drives
            context.ecx = (context.ecx & 0xFFFF0000) | 0x4F12; // 80 cyls, 18 sec
            context.edx = (context.edx & 0xFFFF0000) | 0x0102; // 2 heads, 2 drives
            context.eflags &= !0x01; // Clear carry
            InterruptResult::Handled
        }

        _ => InterruptResult::Reflect
    }
}

/// Handle time BIOS INT 1Ah
fn handle_time_interrupt(context: &mut V86Context) -> InterruptResult {
    let function = (context.eax >> 8) as u8;

    match function {
        0x00 => {
            // Get system time
            // Returns: CX:DX = tick count, AL = midnight flag
            context.ecx = 0;
            context.edx = 0;
            context.eax = (context.eax & 0xFFFFFF00); // No midnight
            InterruptResult::Handled
        }

        0x02 => {
            // Get RTC time
            // Returns: CH = hours (BCD), CL = minutes, DH = seconds
            context.ecx = (context.ecx & 0xFFFF0000) | 0x1200; // 12:00
            context.edx = (context.edx & 0xFFFF0000) | 0x0000; // 00 sec
            context.eflags &= !0x01; // Clear carry
            InterruptResult::Handled
        }

        0x04 => {
            // Get RTC date
            // Returns: CH = century, CL = year, DH = month, DL = day
            context.ecx = (context.ecx & 0xFFFF0000) | 0x2003; // 2003
            context.edx = (context.edx & 0xFFFF0000) | 0x0101; // Jan 1
            context.eflags &= !0x01; // Clear carry
            InterruptResult::Handled
        }

        _ => InterruptResult::Reflect
    }
}

/// Handle system services INT 15h
fn handle_system_interrupt(context: &mut V86Context) -> InterruptResult {
    let function = (context.eax >> 8) as u8;

    match function {
        0x87 => {
            // Move block (used for high memory access)
            context.eflags &= !0x01; // Success
            InterruptResult::Handled
        }

        0x88 => {
            // Get extended memory size
            context.eax = (context.eax & 0xFFFF0000) | 0x3C00; // 15 MB
            context.eflags &= !0x01;
            InterruptResult::Handled
        }

        0xC0 => {
            // Get system configuration
            context.eflags |= 0x01; // Not supported
            InterruptResult::Handled
        }

        _ => InterruptResult::Reflect
    }
}

/// Handle DPMI INT 31h
fn handle_dpmi_interrupt(context: &mut V86Context) -> InterruptResult {
    let function = context.eax as u16;

    match function {
        0x0000 => {
            // Allocate LDT descriptors
            context.eflags |= 0x01; // Error (not supported)
            InterruptResult::Handled
        }

        0x0400 => {
            // Get DPMI version
            context.eax = (context.eax & 0xFFFF0000) | 0x005A; // DPMI 0.9
            context.ebx = 0x0005; // Flags
            context.ecx = 0x04; // CPU type (486)
            context.edx = 0; // PIC base
            context.eflags &= !0x01;
            InterruptResult::Handled
        }

        _ => {
            context.eflags |= 0x01; // Error
            InterruptResult::Handled
        }
    }
}

/// Handle mouse INT 33h
fn handle_mouse_interrupt(context: &mut V86Context) -> InterruptResult {
    let function = context.eax as u16;

    match function {
        0x0000 => {
            // Reset mouse
            context.eax = 0xFFFF; // Mouse installed
            context.ebx = 3; // 3 buttons
            InterruptResult::Handled
        }

        0x0003 => {
            // Get mouse position
            context.ebx = 0; // No buttons pressed
            context.ecx = 320; // X position
            context.edx = 200; // Y position
            InterruptResult::Handled
        }

        _ => InterruptResult::Reflect
    }
}

/// Dispatch a hardware interrupt to VDM
pub fn dispatch_hardware_interrupt(vdm_id: u32, irq: u8) {
    // Convert IRQ to interrupt vector
    let vector = if irq < 8 {
        irq + 0x08 // IRQ 0-7 map to INT 08h-0Fh
    } else {
        irq - 8 + 0x70 // IRQ 8-15 map to INT 70h-77h
    };

    vdm_queue_interrupt(vdm_id, vector, true);
}
