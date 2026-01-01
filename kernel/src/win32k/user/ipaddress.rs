//! IP Address Control Implementation
//!
//! Windows IP Address control for entering IPv4 addresses.
//! Based on Windows Server 2003 commctrl.h and SysIPAddress32.
//!
//! # Features
//!
//! - Four-field IPv4 address entry
//! - Per-field value range limits
//! - Automatic field navigation
//! - Blank/empty state detection
//!
//! # References
//!
//! - `public/sdk/inc/commctrl.h` - IPM_* messages

use crate::ke::spinlock::SpinLock;
use super::super::{HWND, UserHandle, Rect};

// ============================================================================
// IP Address Messages
// ============================================================================

/// WM_USER base
pub const WM_USER: u32 = 0x0400;

/// Clear the address (set all fields blank)
pub const IPM_CLEARADDRESS: u32 = WM_USER + 100;

/// Set the IP address
/// lParam: packed IP address (MAKEIPADDRESS format)
pub const IPM_SETADDRESS: u32 = WM_USER + 101;

/// Get the IP address
/// lParam: pointer to DWORD to receive address
/// Returns: number of non-blank fields
pub const IPM_GETADDRESS: u32 = WM_USER + 102;

/// Set the range for a field
/// wParam: field index (0-3)
/// lParam: packed range (MAKEIPRANGE format)
pub const IPM_SETRANGE: u32 = WM_USER + 103;

/// Set focus to a field
/// wParam: field index (0-3)
pub const IPM_SETFOCUS: u32 = WM_USER + 104;

/// Check if address is blank
/// Returns: TRUE if all fields are blank
pub const IPM_ISBLANK: u32 = WM_USER + 105;

// ============================================================================
// Notifications (IPN_*)
// ============================================================================

/// First IPN notification code
pub const IPN_FIRST: u32 = 0u32.wrapping_sub(860);

/// Field value changed notification
pub const IPN_FIELDCHANGED: u32 = IPN_FIRST.wrapping_sub(0);

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of IP Address controls
pub const MAX_IPADDRESS_CONTROLS: usize = 64;

/// IP Address class name
pub const IPADDRESS_CLASS: &str = "SysIPAddress32";

/// Number of fields in an IP address
pub const IP_FIELD_COUNT: usize = 4;

// ============================================================================
// Helper Functions for IP Address Packing
// ============================================================================

/// Pack 4 octets into an IP address value
/// Equivalent to Windows MAKEIPADDRESS macro
pub const fn make_ip_address(b1: u8, b2: u8, b3: u8, b4: u8) -> u32 {
    ((b1 as u32) << 24) | ((b2 as u32) << 16) | ((b3 as u32) << 8) | (b4 as u32)
}

/// Pack low and high bounds into a range value
/// Equivalent to Windows MAKEIPRANGE macro
pub const fn make_ip_range(low: u8, high: u8) -> u16 {
    ((high as u16) << 8) | (low as u16)
}

/// Extract first octet from packed IP address
pub const fn first_ip_address(addr: u32) -> u8 {
    ((addr >> 24) & 0xFF) as u8
}

/// Extract second octet from packed IP address
pub const fn second_ip_address(addr: u32) -> u8 {
    ((addr >> 16) & 0xFF) as u8
}

/// Extract third octet from packed IP address
pub const fn third_ip_address(addr: u32) -> u8 {
    ((addr >> 8) & 0xFF) as u8
}

/// Extract fourth octet from packed IP address
pub const fn fourth_ip_address(addr: u32) -> u8 {
    (addr & 0xFF) as u8
}

// ============================================================================
// IP Field Structure
// ============================================================================

/// A single field in an IP address
#[derive(Clone, Copy)]
pub struct IpField {
    /// Current value (0-255)
    pub value: u8,
    /// Is this field blank (not entered)
    pub blank: bool,
    /// Minimum allowed value
    pub min: u8,
    /// Maximum allowed value
    pub max: u8,
}

impl IpField {
    /// Create a new IP field with default range
    pub const fn new() -> Self {
        Self {
            value: 0,
            blank: true,
            min: 0,
            max: 255,
        }
    }

    /// Set value with range clamping
    pub fn set_value(&mut self, value: u8) {
        self.value = value.clamp(self.min, self.max);
        self.blank = false;
    }

    /// Set range
    pub fn set_range(&mut self, min: u8, max: u8) {
        self.min = min;
        self.max = max;
        // Clamp current value if needed
        if !self.blank {
            self.value = self.value.clamp(self.min, self.max);
        }
    }

    /// Clear field (make blank)
    pub fn clear(&mut self) {
        self.value = 0;
        self.blank = true;
    }
}

// ============================================================================
// IP Address Control Structure
// ============================================================================

/// IP Address control state
#[derive(Clone)]
pub struct IpAddressControl {
    /// Control handle
    pub hwnd: HWND,
    /// Is this slot in use
    pub in_use: bool,
    /// Display rectangle
    pub rect: Rect,
    /// The four IP address fields
    pub fields: [IpField; IP_FIELD_COUNT],
    /// Currently focused field (0-3, or 4 if none)
    pub focus_field: u8,
    /// Is control focused
    pub has_focus: bool,
    /// Text being typed in current field
    pub input_buffer: [u8; 4],
    pub input_len: usize,
}

impl IpAddressControl {
    /// Create a new IP Address control
    pub const fn new() -> Self {
        Self {
            hwnd: UserHandle::NULL,
            in_use: false,
            rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            fields: [const { IpField::new() }; IP_FIELD_COUNT],
            focus_field: 0,
            has_focus: false,
            input_buffer: [0; 4],
            input_len: 0,
        }
    }

    /// Reset control to default state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Clear all fields
    pub fn clear_address(&mut self) {
        for field in self.fields.iter_mut() {
            field.clear();
        }
        self.input_len = 0;
    }

    /// Set the IP address from a packed u32
    pub fn set_address(&mut self, addr: u32) {
        self.fields[0].set_value(first_ip_address(addr));
        self.fields[1].set_value(second_ip_address(addr));
        self.fields[2].set_value(third_ip_address(addr));
        self.fields[3].set_value(fourth_ip_address(addr));
    }

    /// Get the IP address as a packed u32
    /// Returns (non_blank_count, address)
    pub fn get_address(&self) -> (u8, u32) {
        let mut count = 0u8;
        for field in &self.fields {
            if !field.blank {
                count += 1;
            }
        }

        let addr = make_ip_address(
            if self.fields[0].blank { 0 } else { self.fields[0].value },
            if self.fields[1].blank { 0 } else { self.fields[1].value },
            if self.fields[2].blank { 0 } else { self.fields[2].value },
            if self.fields[3].blank { 0 } else { self.fields[3].value },
        );

        (count, addr)
    }

    /// Set range for a field
    pub fn set_range(&mut self, field: usize, low: u8, high: u8) -> bool {
        if field >= IP_FIELD_COUNT {
            return false;
        }

        self.fields[field].set_range(low, high);
        true
    }

    /// Set focus to a field
    pub fn set_field_focus(&mut self, field: usize) -> bool {
        if field >= IP_FIELD_COUNT {
            return false;
        }

        self.focus_field = field as u8;
        self.input_len = 0;
        self.has_focus = true;
        true
    }

    /// Check if all fields are blank
    pub fn is_blank(&self) -> bool {
        self.fields.iter().all(|f| f.blank)
    }

    /// Handle character input
    pub fn on_char(&mut self, c: u8) -> bool {
        // Only accept digits
        if c < b'0' || c > b'9' {
            // Period/dot advances to next field
            if c == b'.' {
                return self.advance_field();
            }
            return false;
        }

        // Add digit to input buffer
        if self.input_len < 3 {
            self.input_buffer[self.input_len] = c;
            self.input_len += 1;

            // Parse the current input
            let value = self.parse_input();
            let field = &mut self.fields[self.focus_field as usize];

            if value > field.max as u32 {
                // Value too large, commit and move to next field
                self.commit_input();
                self.advance_field();
                // Start the next field with this digit
                self.input_buffer[0] = c;
                self.input_len = 1;
            } else if self.input_len == 3 || value * 10 > field.max as u32 {
                // 3 digits entered or next digit would exceed max
                self.commit_input();
                self.advance_field();
            } else {
                // Update field value
                field.set_value(value as u8);
            }

            return true;
        }

        false
    }

    /// Parse the current input buffer as a number
    fn parse_input(&self) -> u32 {
        let mut value = 0u32;
        for i in 0..self.input_len {
            value = value * 10 + (self.input_buffer[i] - b'0') as u32;
        }
        value
    }

    /// Commit current input to field value
    fn commit_input(&mut self) {
        if self.input_len > 0 {
            let value = self.parse_input();
            let field = &mut self.fields[self.focus_field as usize];
            field.set_value(value.min(255) as u8);
        }
        self.input_len = 0;
    }

    /// Advance to next field
    fn advance_field(&mut self) -> bool {
        self.commit_input();
        if self.focus_field < 3 {
            self.focus_field += 1;
            true
        } else {
            false
        }
    }

    /// Go to previous field
    fn prev_field(&mut self) -> bool {
        self.commit_input();
        if self.focus_field > 0 {
            self.focus_field -= 1;
            true
        } else {
            false
        }
    }

    /// Handle key down
    pub fn on_key_down(&mut self, vk: u8) -> bool {
        match vk {
            0x25 => self.prev_field(),  // VK_LEFT
            0x27 => self.advance_field(), // VK_RIGHT
            0x08 => { // VK_BACK
                if self.input_len > 0 {
                    self.input_len -= 1;
                    if self.input_len == 0 {
                        self.fields[self.focus_field as usize].clear();
                    } else {
                        let value = self.parse_input();
                        self.fields[self.focus_field as usize].set_value(value as u8);
                    }
                    true
                } else if self.focus_field > 0 {
                    self.focus_field -= 1;
                    // Clear the previous field
                    self.fields[self.focus_field as usize].clear();
                    true
                } else {
                    false
                }
            }
            0x2E => { // VK_DELETE
                self.fields[self.focus_field as usize].clear();
                self.input_len = 0;
                true
            }
            0x24 => { // VK_HOME
                self.commit_input();
                self.focus_field = 0;
                true
            }
            0x23 => { // VK_END
                self.commit_input();
                self.focus_field = 3;
                true
            }
            _ => false,
        }
    }

    /// Get display text
    pub fn get_display_text(&self, buffer: &mut [u8]) -> usize {
        let mut pos = 0;

        for (i, field) in self.fields.iter().enumerate() {
            if i > 0 && pos < buffer.len() {
                buffer[pos] = b'.';
                pos += 1;
            }

            if field.blank {
                // Empty field
            } else {
                // Write value
                pos += write_num(field.value as u32, &mut buffer[pos..]);
            }
        }

        pos
    }
}

/// Write a number to buffer
fn write_num(n: u32, buffer: &mut [u8]) -> usize {
    if buffer.is_empty() {
        return 0;
    }

    if n == 0 {
        buffer[0] = b'0';
        return 1;
    }

    let mut temp = [0u8; 10];
    let mut tpos = 0;
    let mut val = n;

    while val > 0 && tpos < temp.len() {
        temp[tpos] = b'0' + (val % 10) as u8;
        val /= 10;
        tpos += 1;
    }

    let len = core::cmp::min(tpos, buffer.len());
    for i in 0..len {
        buffer[i] = temp[tpos - 1 - i];
    }
    len
}

// ============================================================================
// Global State
// ============================================================================

/// Global IP Address control storage
static IPADDRESS_CONTROLS: SpinLock<[IpAddressControl; MAX_IPADDRESS_CONTROLS]> =
    SpinLock::new([const { IpAddressControl::new() }; MAX_IPADDRESS_CONTROLS]);

// ============================================================================
// Public API
// ============================================================================

/// Initialize IP Address control subsystem
pub fn init() {
    crate::serial_println!("[USER] IPAddress control initialized");
}

/// Create an IP Address control
pub fn create_ipaddress(hwnd: HWND, rect: &Rect) -> Option<usize> {
    let mut controls = IPADDRESS_CONTROLS.lock();

    for (i, control) in controls.iter_mut().enumerate() {
        if !control.in_use {
            control.reset();
            control.hwnd = hwnd;
            control.in_use = true;
            control.rect = *rect;
            return Some(i);
        }
    }

    None
}

/// Destroy an IP Address control
pub fn destroy_ipaddress(index: usize) -> bool {
    let mut controls = IPADDRESS_CONTROLS.lock();

    if index >= MAX_IPADDRESS_CONTROLS {
        return false;
    }

    if controls[index].in_use {
        controls[index].reset();
        true
    } else {
        false
    }
}

/// Clear address
pub fn clear_address(index: usize) -> bool {
    let mut controls = IPADDRESS_CONTROLS.lock();

    if index >= MAX_IPADDRESS_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].clear_address();
    true
}

/// Set address
pub fn set_address(index: usize, addr: u32) -> bool {
    let mut controls = IPADDRESS_CONTROLS.lock();

    if index >= MAX_IPADDRESS_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].set_address(addr);
    true
}

/// Get address
pub fn get_address(index: usize) -> (u8, u32) {
    let controls = IPADDRESS_CONTROLS.lock();

    if index >= MAX_IPADDRESS_CONTROLS || !controls[index].in_use {
        return (0, 0);
    }

    controls[index].get_address()
}

/// Set range for a field
pub fn set_range(index: usize, field: usize, range: u16) -> bool {
    let mut controls = IPADDRESS_CONTROLS.lock();

    if index >= MAX_IPADDRESS_CONTROLS || !controls[index].in_use {
        return false;
    }

    let low = (range & 0xFF) as u8;
    let high = ((range >> 8) & 0xFF) as u8;
    controls[index].set_range(field, low, high)
}

/// Set focus to a field
pub fn set_field_focus(index: usize, field: usize) -> bool {
    let mut controls = IPADDRESS_CONTROLS.lock();

    if index >= MAX_IPADDRESS_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].set_field_focus(field)
}

/// Check if blank
pub fn is_blank(index: usize) -> bool {
    let controls = IPADDRESS_CONTROLS.lock();

    if index >= MAX_IPADDRESS_CONTROLS || !controls[index].in_use {
        return true;
    }

    controls[index].is_blank()
}

/// Handle character input
pub fn on_char(index: usize, c: u8) -> bool {
    let mut controls = IPADDRESS_CONTROLS.lock();

    if index >= MAX_IPADDRESS_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].on_char(c)
}

/// Handle key down
pub fn on_key_down(index: usize, vk: u8) -> bool {
    let mut controls = IPADDRESS_CONTROLS.lock();

    if index >= MAX_IPADDRESS_CONTROLS || !controls[index].in_use {
        return false;
    }

    controls[index].on_key_down(vk)
}

/// Get display text
pub fn get_display_text(index: usize, buffer: &mut [u8]) -> usize {
    let controls = IPADDRESS_CONTROLS.lock();

    if index >= MAX_IPADDRESS_CONTROLS || !controls[index].in_use {
        return 0;
    }

    controls[index].get_display_text(buffer)
}

/// Process IP Address control message
pub fn process_message(index: usize, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        IPM_CLEARADDRESS => {
            clear_address(index);
            0
        }
        IPM_SETADDRESS => {
            set_address(index, lparam as u32);
            0
        }
        IPM_GETADDRESS => {
            let (count, _addr) = get_address(index);
            // In real implementation, write addr to lparam pointer
            count as isize
        }
        IPM_SETRANGE => {
            set_range(index, wparam, lparam as u16);
            0
        }
        IPM_SETFOCUS => {
            set_field_focus(index, wparam);
            0
        }
        IPM_ISBLANK => {
            if is_blank(index) { 1 } else { 0 }
        }
        _ => 0,
    }
}

/// Get statistics
pub fn get_stats() -> IpAddressStats {
    let controls = IPADDRESS_CONTROLS.lock();

    let mut active_count = 0;
    for control in controls.iter() {
        if control.in_use {
            active_count += 1;
        }
    }

    IpAddressStats {
        max_controls: MAX_IPADDRESS_CONTROLS,
        active_controls: active_count,
    }
}

/// IP Address statistics
#[derive(Debug, Clone, Copy)]
pub struct IpAddressStats {
    pub max_controls: usize,
    pub active_controls: usize,
}
