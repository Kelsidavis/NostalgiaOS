//! Executive Buffer Probing
//!
//! Implements buffer validation for user-mode pointers:
//! - ProbeForRead: Verify buffer is readable
//! - ProbeForWrite: Verify buffer is writable
//! - Alignment checking
//! - Address range validation
//!
//! Based on Windows Server 2003 base/ntos/ex/probe.c

/// Maximum user-mode address
/// Values above this are kernel addresses
pub const MM_USER_PROBE_ADDRESS: usize = 0x7FFFFFFF0000;

/// Page size for probing
pub const PAGE_SIZE: usize = 4096;

/// Exception types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeException {
    /// Access violation - invalid address
    AccessViolation,
    /// Datatype misalignment - improper alignment
    DatatypeMisalignment,
}

/// Result of a probe operation
pub type ProbeResult = Result<(), ProbeException>;

/// Probe a user-mode buffer for read access
///
/// This function validates that the specified address range is:
/// 1. Properly aligned to the specified alignment
/// 2. Within the valid user-mode address range
/// 3. Does not wrap around (start + length > start)
///
/// # Arguments
///
/// * `address` - Pointer to the buffer to probe
/// * `length` - Length of the buffer in bytes
/// * `alignment` - Required alignment (1, 2, 4, 8, or 16)
///
/// # Returns
///
/// Ok(()) if the buffer is valid, Err(ProbeException) otherwise
pub fn probe_for_read(address: usize, length: usize, alignment: usize) -> ProbeResult {
    debug_assert!(
        alignment == 1 || alignment == 2 || alignment == 4 || alignment == 8 || alignment == 16,
        "Invalid alignment: {}",
        alignment
    );

    if length == 0 {
        return Ok(());
    }

    // Check alignment
    if (address & (alignment - 1)) != 0 {
        return Err(ProbeException::DatatypeMisalignment);
    }

    // Check for overflow and valid address range
    let end_address = address.checked_add(length).ok_or(ProbeException::AccessViolation)?;

    if end_address > MM_USER_PROBE_ADDRESS {
        return Err(ProbeException::AccessViolation);
    }

    Ok(())
}

/// Probe a user-mode buffer for write access
///
/// This function validates that the specified address range is:
/// 1. Properly aligned to the specified alignment
/// 2. Within the valid user-mode address range
/// 3. Does not wrap around (start + length > start)
/// 4. Actually writable (by touching each page)
///
/// # Arguments
///
/// * `address` - Pointer to the buffer to probe
/// * `length` - Length of the buffer in bytes
/// * `alignment` - Required alignment (1, 2, 4, 8, or 16)
///
/// # Returns
///
/// Ok(()) if the buffer is valid and writable, Err(ProbeException) otherwise
///
/// # Safety
///
/// This function reads from and writes to the specified address range.
/// The caller must ensure this is only called with valid user-mode addresses.
pub unsafe fn probe_for_write(address: usize, length: usize, alignment: usize) -> ProbeResult {
    debug_assert!(
        alignment == 1 || alignment == 2 || alignment == 4 || alignment == 8 || alignment == 16,
        "Invalid alignment: {}",
        alignment
    );

    if length == 0 {
        return Ok(());
    }

    // Check alignment
    if (address & (alignment - 1)) != 0 {
        return Err(ProbeException::DatatypeMisalignment);
    }

    // Check for overflow
    let end_address = match address.checked_add(length - 1) {
        Some(addr) => addr,
        None => return Err(ProbeException::AccessViolation),
    };

    // Check valid address range
    if address > end_address || end_address >= MM_USER_PROBE_ADDRESS {
        return Err(ProbeException::AccessViolation);
    }

    // Probe each page by reading and writing back the same value
    // This ensures the page is present and writable
    let mut current = address;
    let final_page = (end_address & !(PAGE_SIZE - 1)) + PAGE_SIZE;

    while current < final_page {
        // Read and write the same byte to ensure page is writable
        let ptr = current as *mut u8;
        let value = core::ptr::read_volatile(ptr);
        core::ptr::write_volatile(ptr, value);

        // Move to next page
        current = (current & !(PAGE_SIZE - 1)) + PAGE_SIZE;
    }

    Ok(())
}

/// Probe a structure for read access (typed version)
///
/// # Safety
///
/// The caller must ensure T is a valid type for the address.
pub fn probe_for_read_typed<T>(address: usize) -> ProbeResult {
    probe_for_read(address, core::mem::size_of::<T>(), core::mem::align_of::<T>())
}

/// Probe a structure for write access (typed version)
///
/// # Safety
///
/// The caller must ensure T is a valid type for the address.
pub unsafe fn probe_for_write_typed<T>(address: usize) -> ProbeResult {
    probe_for_write(address, core::mem::size_of::<T>(), core::mem::align_of::<T>())
}

/// Probe and copy from user buffer
///
/// # Safety
///
/// The caller must ensure the destination buffer is valid.
pub unsafe fn probe_and_read_buffer(
    user_buffer: usize,
    kernel_buffer: *mut u8,
    length: usize,
) -> ProbeResult {
    // Probe the user buffer for read
    probe_for_read(user_buffer, length, 1)?;

    // Copy the data
    core::ptr::copy_nonoverlapping(user_buffer as *const u8, kernel_buffer, length);

    Ok(())
}

/// Probe and copy to user buffer
///
/// # Safety
///
/// The caller must ensure the source buffer is valid.
pub unsafe fn probe_and_write_buffer(
    kernel_buffer: *const u8,
    user_buffer: usize,
    length: usize,
) -> ProbeResult {
    // Probe the user buffer for write
    probe_for_write(user_buffer, length, 1)?;

    // Copy the data
    core::ptr::copy_nonoverlapping(kernel_buffer, user_buffer as *mut u8, length);

    Ok(())
}

/// Check if an address is in user space
#[inline]
pub fn is_user_address(address: usize) -> bool {
    address < MM_USER_PROBE_ADDRESS
}

/// Check if an address is in kernel space
#[inline]
pub fn is_kernel_address(address: usize) -> bool {
    address >= MM_USER_PROBE_ADDRESS
}

/// Check if a buffer range is entirely in user space
#[inline]
pub fn is_user_range(address: usize, length: usize) -> bool {
    if length == 0 {
        return true;
    }

    match address.checked_add(length) {
        Some(end) => end <= MM_USER_PROBE_ADDRESS,
        None => false,
    }
}

/// Raise access violation exception
pub fn ex_raise_access_violation() -> ! {
    panic!("Access violation");
}

/// Raise datatype misalignment exception
pub fn ex_raise_datatype_misalignment() -> ! {
    panic!("Datatype misalignment");
}

/// Initialize probe subsystem
pub fn ex_probe_init() {
    crate::serial_println!("[EX] Probe subsystem initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_for_read_empty() {
        assert!(probe_for_read(0, 0, 1).is_ok());
    }

    #[test]
    fn test_probe_for_read_valid() {
        assert!(probe_for_read(0x1000, 0x100, 1).is_ok());
    }

    #[test]
    fn test_probe_for_read_kernel_address() {
        assert!(probe_for_read(MM_USER_PROBE_ADDRESS, 1, 1).is_err());
    }

    #[test]
    fn test_probe_for_read_misaligned() {
        assert!(probe_for_read(0x1001, 4, 4).is_err());
    }

    #[test]
    fn test_probe_for_read_overflow() {
        assert!(probe_for_read(usize::MAX - 10, 100, 1).is_err());
    }
}
