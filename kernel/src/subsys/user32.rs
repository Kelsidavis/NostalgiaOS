//! User32.dll Stub Implementation
//!
//! User interface APIs - windows, messages, input, dialogs, menus.
//! These wrap syscalls to Win32k USER subsystem.

use core::ptr;

/// Syscall numbers for Win32k USER services
mod syscall {
    pub const NtUserCreateWindowEx: u32 = 0x1000;
    pub const NtUserDestroyWindow: u32 = 0x1001;
    pub const NtUserShowWindow: u32 = 0x1002;
    pub const NtUserMoveWindow: u32 = 0x1003;
    pub const NtUserSetWindowPos: u32 = 0x1004;
    pub const NtUserGetWindowRect: u32 = 0x1005;
    pub const NtUserGetClientRect: u32 = 0x1006;
    pub const NtUserSetWindowText: u32 = 0x1007;
    pub const NtUserGetWindowText: u32 = 0x1008;
    pub const NtUserGetWindowLong: u32 = 0x1009;
    pub const NtUserSetWindowLong: u32 = 0x100A;
    pub const NtUserGetMessage: u32 = 0x1010;
    pub const NtUserPeekMessage: u32 = 0x1011;
    pub const NtUserTranslateMessage: u32 = 0x1012;
    pub const NtUserDispatchMessage: u32 = 0x1013;
    pub const NtUserPostMessage: u32 = 0x1014;
    pub const NtUserSendMessage: u32 = 0x1015;
    pub const NtUserPostQuitMessage: u32 = 0x1016;
    pub const NtUserRegisterClass: u32 = 0x1020;
    pub const NtUserUnregisterClass: u32 = 0x1021;
    pub const NtUserGetClassInfo: u32 = 0x1022;
    pub const NtUserDefWindowProc: u32 = 0x1023;
    pub const NtUserBeginPaint: u32 = 0x1030;
    pub const NtUserEndPaint: u32 = 0x1031;
    pub const NtUserGetDC: u32 = 0x1032;
    pub const NtUserReleaseDC: u32 = 0x1033;
    pub const NtUserInvalidateRect: u32 = 0x1034;
    pub const NtUserUpdateWindow: u32 = 0x1035;
    pub const NtUserSetFocus: u32 = 0x1040;
    pub const NtUserGetFocus: u32 = 0x1041;
    pub const NtUserSetCapture: u32 = 0x1042;
    pub const NtUserReleaseCapture: u32 = 0x1043;
    pub const NtUserGetCapture: u32 = 0x1044;
    pub const NtUserSetActiveWindow: u32 = 0x1045;
    pub const NtUserGetActiveWindow: u32 = 0x1046;
    pub const NtUserSetForegroundWindow: u32 = 0x1047;
    pub const NtUserGetForegroundWindow: u32 = 0x1048;
    pub const NtUserGetKeyState: u32 = 0x1050;
    pub const NtUserGetAsyncKeyState: u32 = 0x1051;
    pub const NtUserGetKeyboardState: u32 = 0x1052;
    pub const NtUserSetKeyboardState: u32 = 0x1053;
    pub const NtUserMapVirtualKey: u32 = 0x1054;
    pub const NtUserGetCursorPos: u32 = 0x1060;
    pub const NtUserSetCursorPos: u32 = 0x1061;
    pub const NtUserShowCursor: u32 = 0x1062;
    pub const NtUserSetCursor: u32 = 0x1063;
    pub const NtUserLoadCursor: u32 = 0x1064;
    pub const NtUserCreateMenu: u32 = 0x1070;
    pub const NtUserDestroyMenu: u32 = 0x1071;
    pub const NtUserAppendMenu: u32 = 0x1072;
    pub const NtUserInsertMenu: u32 = 0x1073;
    pub const NtUserDeleteMenu: u32 = 0x1074;
    pub const NtUserSetMenu: u32 = 0x1075;
    pub const NtUserGetMenu: u32 = 0x1076;
    pub const NtUserTrackPopupMenu: u32 = 0x1077;
    pub const NtUserMessageBox: u32 = 0x1080;
    pub const NtUserDialogBox: u32 = 0x1081;
    pub const NtUserCreateDialog: u32 = 0x1082;
    pub const NtUserEndDialog: u32 = 0x1083;
    pub const NtUserGetDlgItem: u32 = 0x1084;
    pub const NtUserSetDlgItemText: u32 = 0x1085;
    pub const NtUserGetDlgItemText: u32 = 0x1086;
    pub const NtUserSetTimer: u32 = 0x1090;
    pub const NtUserKillTimer: u32 = 0x1091;
    pub const NtUserGetSystemMetrics: u32 = 0x10A0;
    pub const NtUserSystemParametersInfo: u32 = 0x10A1;
    pub const NtUserGetDesktopWindow: u32 = 0x10A2;
    pub const NtUserFindWindow: u32 = 0x10A3;
    pub const NtUserEnumWindows: u32 = 0x10A4;
    pub const NtUserEnumChildWindows: u32 = 0x10A5;
    pub const NtUserGetParent: u32 = 0x10A6;
    pub const NtUserSetParent: u32 = 0x10A7;
    pub const NtUserIsWindow: u32 = 0x10A8;
    pub const NtUserIsWindowVisible: u32 = 0x10A9;
    pub const NtUserIsWindowEnabled: u32 = 0x10AA;
    pub const NtUserEnableWindow: u32 = 0x10AB;
    pub const NtUserGetClientToScreen: u32 = 0x10B0;
    pub const NtUserGetScreenToClient: u32 = 0x10B1;
    pub const NtUserLoadIcon: u32 = 0x10C0;
    pub const NtUserLoadImage: u32 = 0x10C1;
    pub const NtUserCreateIcon: u32 = 0x10C2;
    pub const NtUserDestroyIcon: u32 = 0x10C3;
    pub const NtUserDrawIcon: u32 = 0x10C4;
    pub const NtUserSetClipboardData: u32 = 0x10D0;
    pub const NtUserGetClipboardData: u32 = 0x10D1;
    pub const NtUserOpenClipboard: u32 = 0x10D2;
    pub const NtUserCloseClipboard: u32 = 0x10D3;
    pub const NtUserEmptyClipboard: u32 = 0x10D4;
}

/// Make a Win32k syscall
#[inline(always)]
unsafe fn win32k_syscall(num: u32, args: &[u64]) -> u64 {
    let result: u64;
    let syscall_num = num as u64 | 0x1000; // Win32k syscalls have high bit set

    match args.len() {
        0 => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        1 => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                in("rdi") args[0],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        2 => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                in("rdi") args[0],
                in("rsi") args[1],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        3 => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        4 => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                in("r10") args[3],
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
        _ => {
            core::arch::asm!(
                "syscall",
                in("rax") syscall_num,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                in("r10") args[3],
                in("r8") args[4],
                in("r9") if args.len() > 5 { args[5] } else { 0 },
                lateout("rax") result,
                out("rcx") _,
                out("r11") _,
            );
        }
    }
    result
}

// Type definitions
pub type HWND = u64;
pub type HDC = u64;
pub type HMENU = u64;
pub type HICON = u64;
pub type HCURSOR = u64;
pub type HBRUSH = u64;
pub type HINSTANCE = u64;
pub type ATOM = u16;
pub type WPARAM = u64;
pub type LPARAM = i64;
pub type LRESULT = i64;
pub type WNDPROC = extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT;
pub type UINT = u32;
pub type BOOL = i32;
pub type DWORD = u32;
pub type WORD = u16;
pub type LONG = i32;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

#[repr(C)]
pub struct POINT {
    pub x: LONG,
    pub y: LONG,
}

#[repr(C)]
pub struct RECT {
    pub left: LONG,
    pub top: LONG,
    pub right: LONG,
    pub bottom: LONG,
}

#[repr(C)]
pub struct MSG {
    pub hwnd: HWND,
    pub message: UINT,
    pub wParam: WPARAM,
    pub lParam: LPARAM,
    pub time: DWORD,
    pub pt: POINT,
}

#[repr(C)]
pub struct WNDCLASSA {
    pub style: UINT,
    pub lpfnWndProc: WNDPROC,
    pub cbClsExtra: i32,
    pub cbWndExtra: i32,
    pub hInstance: HINSTANCE,
    pub hIcon: HICON,
    pub hCursor: HCURSOR,
    pub hbrBackground: HBRUSH,
    pub lpszMenuName: *const u8,
    pub lpszClassName: *const u8,
}

#[repr(C)]
pub struct WNDCLASSW {
    pub style: UINT,
    pub lpfnWndProc: WNDPROC,
    pub cbClsExtra: i32,
    pub cbWndExtra: i32,
    pub hInstance: HINSTANCE,
    pub hIcon: HICON,
    pub hCursor: HCURSOR,
    pub hbrBackground: HBRUSH,
    pub lpszMenuName: *const u16,
    pub lpszClassName: *const u16,
}

#[repr(C)]
pub struct PAINTSTRUCT {
    pub hdc: HDC,
    pub fErase: BOOL,
    pub rcPaint: RECT,
    pub fRestore: BOOL,
    pub fIncUpdate: BOOL,
    pub rgbReserved: [u8; 32],
}

// Window style constants
pub const WS_OVERLAPPED: DWORD = 0x00000000;
pub const WS_POPUP: DWORD = 0x80000000;
pub const WS_CHILD: DWORD = 0x40000000;
pub const WS_MINIMIZE: DWORD = 0x20000000;
pub const WS_VISIBLE: DWORD = 0x10000000;
pub const WS_DISABLED: DWORD = 0x08000000;
pub const WS_CLIPSIBLINGS: DWORD = 0x04000000;
pub const WS_CLIPCHILDREN: DWORD = 0x02000000;
pub const WS_MAXIMIZE: DWORD = 0x01000000;
pub const WS_CAPTION: DWORD = 0x00C00000;
pub const WS_BORDER: DWORD = 0x00800000;
pub const WS_DLGFRAME: DWORD = 0x00400000;
pub const WS_VSCROLL: DWORD = 0x00200000;
pub const WS_HSCROLL: DWORD = 0x00100000;
pub const WS_SYSMENU: DWORD = 0x00080000;
pub const WS_THICKFRAME: DWORD = 0x00040000;
pub const WS_MINIMIZEBOX: DWORD = 0x00020000;
pub const WS_MAXIMIZEBOX: DWORD = 0x00010000;
pub const WS_OVERLAPPEDWINDOW: DWORD = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;

// Extended window styles
pub const WS_EX_DLGMODALFRAME: DWORD = 0x00000001;
pub const WS_EX_TOPMOST: DWORD = 0x00000008;
pub const WS_EX_ACCEPTFILES: DWORD = 0x00000010;
pub const WS_EX_TRANSPARENT: DWORD = 0x00000020;
pub const WS_EX_TOOLWINDOW: DWORD = 0x00000080;
pub const WS_EX_WINDOWEDGE: DWORD = 0x00000100;
pub const WS_EX_CLIENTEDGE: DWORD = 0x00000200;
pub const WS_EX_APPWINDOW: DWORD = 0x00040000;

// ShowWindow commands
pub const SW_HIDE: i32 = 0;
pub const SW_SHOWNORMAL: i32 = 1;
pub const SW_SHOWMINIMIZED: i32 = 2;
pub const SW_SHOWMAXIMIZED: i32 = 3;
pub const SW_MAXIMIZE: i32 = 3;
pub const SW_SHOWNOACTIVATE: i32 = 4;
pub const SW_SHOW: i32 = 5;
pub const SW_MINIMIZE: i32 = 6;
pub const SW_SHOWMINNOACTIVE: i32 = 7;
pub const SW_SHOWNA: i32 = 8;
pub const SW_RESTORE: i32 = 9;
pub const SW_SHOWDEFAULT: i32 = 10;

// Window messages
pub const WM_NULL: UINT = 0x0000;
pub const WM_CREATE: UINT = 0x0001;
pub const WM_DESTROY: UINT = 0x0002;
pub const WM_MOVE: UINT = 0x0003;
pub const WM_SIZE: UINT = 0x0005;
pub const WM_ACTIVATE: UINT = 0x0006;
pub const WM_SETFOCUS: UINT = 0x0007;
pub const WM_KILLFOCUS: UINT = 0x0008;
pub const WM_ENABLE: UINT = 0x000A;
pub const WM_SETTEXT: UINT = 0x000C;
pub const WM_GETTEXT: UINT = 0x000D;
pub const WM_GETTEXTLENGTH: UINT = 0x000E;
pub const WM_PAINT: UINT = 0x000F;
pub const WM_CLOSE: UINT = 0x0010;
pub const WM_QUIT: UINT = 0x0012;
pub const WM_ERASEBKGND: UINT = 0x0014;
pub const WM_SHOWWINDOW: UINT = 0x0018;
pub const WM_SETCURSOR: UINT = 0x0020;
pub const WM_MOUSEACTIVATE: UINT = 0x0021;
pub const WM_GETMINMAXINFO: UINT = 0x0024;
pub const WM_WINDOWPOSCHANGING: UINT = 0x0046;
pub const WM_WINDOWPOSCHANGED: UINT = 0x0047;
pub const WM_NCCREATE: UINT = 0x0081;
pub const WM_NCDESTROY: UINT = 0x0082;
pub const WM_NCCALCSIZE: UINT = 0x0083;
pub const WM_NCHITTEST: UINT = 0x0084;
pub const WM_NCPAINT: UINT = 0x0085;
pub const WM_NCACTIVATE: UINT = 0x0086;
pub const WM_KEYDOWN: UINT = 0x0100;
pub const WM_KEYUP: UINT = 0x0101;
pub const WM_CHAR: UINT = 0x0102;
pub const WM_SYSKEYDOWN: UINT = 0x0104;
pub const WM_SYSKEYUP: UINT = 0x0105;
pub const WM_SYSCHAR: UINT = 0x0106;
pub const WM_COMMAND: UINT = 0x0111;
pub const WM_SYSCOMMAND: UINT = 0x0112;
pub const WM_TIMER: UINT = 0x0113;
pub const WM_HSCROLL: UINT = 0x0114;
pub const WM_VSCROLL: UINT = 0x0115;
pub const WM_MOUSEMOVE: UINT = 0x0200;
pub const WM_LBUTTONDOWN: UINT = 0x0201;
pub const WM_LBUTTONUP: UINT = 0x0202;
pub const WM_LBUTTONDBLCLK: UINT = 0x0203;
pub const WM_RBUTTONDOWN: UINT = 0x0204;
pub const WM_RBUTTONUP: UINT = 0x0205;
pub const WM_RBUTTONDBLCLK: UINT = 0x0206;
pub const WM_MBUTTONDOWN: UINT = 0x0207;
pub const WM_MBUTTONUP: UINT = 0x0208;
pub const WM_MBUTTONDBLCLK: UINT = 0x0209;
pub const WM_MOUSEWHEEL: UINT = 0x020A;
pub const WM_USER: UINT = 0x0400;

// MessageBox flags
pub const MB_OK: UINT = 0x00000000;
pub const MB_OKCANCEL: UINT = 0x00000001;
pub const MB_ABORTRETRYIGNORE: UINT = 0x00000002;
pub const MB_YESNOCANCEL: UINT = 0x00000003;
pub const MB_YESNO: UINT = 0x00000004;
pub const MB_RETRYCANCEL: UINT = 0x00000005;
pub const MB_ICONERROR: UINT = 0x00000010;
pub const MB_ICONQUESTION: UINT = 0x00000020;
pub const MB_ICONWARNING: UINT = 0x00000030;
pub const MB_ICONINFORMATION: UINT = 0x00000040;

// MessageBox return values
pub const IDOK: i32 = 1;
pub const IDCANCEL: i32 = 2;
pub const IDABORT: i32 = 3;
pub const IDRETRY: i32 = 4;
pub const IDIGNORE: i32 = 5;
pub const IDYES: i32 = 6;
pub const IDNO: i32 = 7;

// System metrics
pub const SM_CXSCREEN: i32 = 0;
pub const SM_CYSCREEN: i32 = 1;
pub const SM_CXVSCROLL: i32 = 2;
pub const SM_CYHSCROLL: i32 = 3;
pub const SM_CYCAPTION: i32 = 4;
pub const SM_CXBORDER: i32 = 5;
pub const SM_CYBORDER: i32 = 6;
pub const SM_CXICON: i32 = 11;
pub const SM_CYICON: i32 = 12;
pub const SM_CXCURSOR: i32 = 13;
pub const SM_CYCURSOR: i32 = 14;
pub const SM_CYMENU: i32 = 15;
pub const SM_CXFULLSCREEN: i32 = 16;
pub const SM_CYFULLSCREEN: i32 = 17;
pub const SM_MOUSEPRESENT: i32 = 19;
pub const SM_CXMIN: i32 = 28;
pub const SM_CYMIN: i32 = 29;
pub const SM_CXSIZE: i32 = 30;
pub const SM_CYSIZE: i32 = 31;
pub const SM_CXFRAME: i32 = 32;
pub const SM_CYFRAME: i32 = 33;
pub const SM_CXMINTRACK: i32 = 34;
pub const SM_CYMINTRACK: i32 = 35;
pub const SM_CXDOUBLECLK: i32 = 36;
pub const SM_CYDOUBLECLK: i32 = 37;
pub const SM_CXICONSPACING: i32 = 38;
pub const SM_CYICONSPACING: i32 = 39;

// Virtual key codes
pub const VK_LBUTTON: i32 = 0x01;
pub const VK_RBUTTON: i32 = 0x02;
pub const VK_CANCEL: i32 = 0x03;
pub const VK_MBUTTON: i32 = 0x04;
pub const VK_BACK: i32 = 0x08;
pub const VK_TAB: i32 = 0x09;
pub const VK_RETURN: i32 = 0x0D;
pub const VK_SHIFT: i32 = 0x10;
pub const VK_CONTROL: i32 = 0x11;
pub const VK_MENU: i32 = 0x12;
pub const VK_PAUSE: i32 = 0x13;
pub const VK_CAPITAL: i32 = 0x14;
pub const VK_ESCAPE: i32 = 0x1B;
pub const VK_SPACE: i32 = 0x20;
pub const VK_PRIOR: i32 = 0x21;
pub const VK_NEXT: i32 = 0x22;
pub const VK_END: i32 = 0x23;
pub const VK_HOME: i32 = 0x24;
pub const VK_LEFT: i32 = 0x25;
pub const VK_UP: i32 = 0x26;
pub const VK_RIGHT: i32 = 0x27;
pub const VK_DOWN: i32 = 0x28;
pub const VK_INSERT: i32 = 0x2D;
pub const VK_DELETE: i32 = 0x2E;
pub const VK_F1: i32 = 0x70;
pub const VK_F2: i32 = 0x71;
pub const VK_F3: i32 = 0x72;
pub const VK_F4: i32 = 0x73;
pub const VK_F5: i32 = 0x74;
pub const VK_F6: i32 = 0x75;
pub const VK_F7: i32 = 0x76;
pub const VK_F8: i32 = 0x77;
pub const VK_F9: i32 = 0x78;
pub const VK_F10: i32 = 0x79;
pub const VK_F11: i32 = 0x7A;
pub const VK_F12: i32 = 0x7B;

// NULL values
pub const NULL: u64 = 0;
pub const HWND_DESKTOP: HWND = 0;

// ============================================================================
// Window Class Registration
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn RegisterClassA(wc: *const WNDCLASSA) -> ATOM {
    if wc.is_null() {
        return 0;
    }
    win32k_syscall(syscall::NtUserRegisterClass, &[wc as u64, 0]) as ATOM
}

#[no_mangle]
pub unsafe extern "system" fn RegisterClassW(wc: *const WNDCLASSW) -> ATOM {
    if wc.is_null() {
        return 0;
    }
    win32k_syscall(syscall::NtUserRegisterClass, &[wc as u64, 1]) as ATOM
}

#[no_mangle]
pub unsafe extern "system" fn UnregisterClassA(class_name: *const u8, instance: HINSTANCE) -> BOOL {
    win32k_syscall(syscall::NtUserUnregisterClass, &[class_name as u64, instance, 0]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn UnregisterClassW(class_name: *const u16, instance: HINSTANCE) -> BOOL {
    win32k_syscall(syscall::NtUserUnregisterClass, &[class_name as u64, instance, 1]) as BOOL
}

// ============================================================================
// Window Creation/Destruction
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn CreateWindowExA(
    ex_style: DWORD,
    class_name: *const u8,
    window_name: *const u8,
    style: DWORD,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: HWND,
    menu: HMENU,
    instance: HINSTANCE,
    param: *mut u8,
) -> HWND {
    // Pack parameters for syscall
    let params: [u64; 12] = [
        ex_style as u64,
        class_name as u64,
        window_name as u64,
        style as u64,
        x as u64,
        y as u64,
        width as u64,
        height as u64,
        parent,
        menu,
        instance,
        param as u64,
    ];
    win32k_syscall(syscall::NtUserCreateWindowEx, &[params.as_ptr() as u64, 0])
}

#[no_mangle]
pub unsafe extern "system" fn CreateWindowExW(
    ex_style: DWORD,
    class_name: *const u16,
    window_name: *const u16,
    style: DWORD,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: HWND,
    menu: HMENU,
    instance: HINSTANCE,
    param: *mut u8,
) -> HWND {
    let params: [u64; 12] = [
        ex_style as u64,
        class_name as u64,
        window_name as u64,
        style as u64,
        x as u64,
        y as u64,
        width as u64,
        height as u64,
        parent,
        menu,
        instance,
        param as u64,
    ];
    win32k_syscall(syscall::NtUserCreateWindowEx, &[params.as_ptr() as u64, 1])
}

#[no_mangle]
pub unsafe extern "system" fn DestroyWindow(hwnd: HWND) -> BOOL {
    win32k_syscall(syscall::NtUserDestroyWindow, &[hwnd]) as BOOL
}

// ============================================================================
// Window Display
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn ShowWindow(hwnd: HWND, cmd_show: i32) -> BOOL {
    win32k_syscall(syscall::NtUserShowWindow, &[hwnd, cmd_show as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn MoveWindow(
    hwnd: HWND,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    repaint: BOOL,
) -> BOOL {
    win32k_syscall(syscall::NtUserMoveWindow, &[
        hwnd,
        x as u64,
        y as u64,
        width as u64,
        height as u64,
        repaint as u64,
    ]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn SetWindowPos(
    hwnd: HWND,
    hwnd_insert_after: HWND,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    flags: UINT,
) -> BOOL {
    win32k_syscall(syscall::NtUserSetWindowPos, &[
        hwnd,
        hwnd_insert_after,
        x as u64,
        y as u64,
        cx as u64,
        cy as u64,
        flags as u64,
    ]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetWindowRect(hwnd: HWND, rect: *mut RECT) -> BOOL {
    win32k_syscall(syscall::NtUserGetWindowRect, &[hwnd, rect as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetClientRect(hwnd: HWND, rect: *mut RECT) -> BOOL {
    win32k_syscall(syscall::NtUserGetClientRect, &[hwnd, rect as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn UpdateWindow(hwnd: HWND) -> BOOL {
    win32k_syscall(syscall::NtUserUpdateWindow, &[hwnd]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn InvalidateRect(hwnd: HWND, rect: *const RECT, erase: BOOL) -> BOOL {
    win32k_syscall(syscall::NtUserInvalidateRect, &[hwnd, rect as u64, erase as u64]) as BOOL
}

// ============================================================================
// Window Text
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn SetWindowTextA(hwnd: HWND, text: *const u8) -> BOOL {
    win32k_syscall(syscall::NtUserSetWindowText, &[hwnd, text as u64, 0]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn SetWindowTextW(hwnd: HWND, text: *const u16) -> BOOL {
    win32k_syscall(syscall::NtUserSetWindowText, &[hwnd, text as u64, 1]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetWindowTextA(hwnd: HWND, buffer: *mut u8, max_count: i32) -> i32 {
    win32k_syscall(syscall::NtUserGetWindowText, &[hwnd, buffer as u64, max_count as u64, 0]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn GetWindowTextW(hwnd: HWND, buffer: *mut u16, max_count: i32) -> i32 {
    win32k_syscall(syscall::NtUserGetWindowText, &[hwnd, buffer as u64, max_count as u64, 1]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn GetWindowTextLengthA(hwnd: HWND) -> i32 {
    win32k_syscall(syscall::NtUserGetWindowText, &[hwnd, 0, 0, 2]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn GetWindowTextLengthW(hwnd: HWND) -> i32 {
    win32k_syscall(syscall::NtUserGetWindowText, &[hwnd, 0, 0, 3]) as i32
}

// ============================================================================
// Window Properties
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn GetWindowLongA(hwnd: HWND, index: i32) -> LONG {
    win32k_syscall(syscall::NtUserGetWindowLong, &[hwnd, index as u64, 0]) as LONG
}

#[no_mangle]
pub unsafe extern "system" fn GetWindowLongW(hwnd: HWND, index: i32) -> LONG {
    win32k_syscall(syscall::NtUserGetWindowLong, &[hwnd, index as u64, 1]) as LONG
}

#[no_mangle]
pub unsafe extern "system" fn SetWindowLongA(hwnd: HWND, index: i32, new_long: LONG) -> LONG {
    win32k_syscall(syscall::NtUserSetWindowLong, &[hwnd, index as u64, new_long as u64, 0]) as LONG
}

#[no_mangle]
pub unsafe extern "system" fn SetWindowLongW(hwnd: HWND, index: i32, new_long: LONG) -> LONG {
    win32k_syscall(syscall::NtUserSetWindowLong, &[hwnd, index as u64, new_long as u64, 1]) as LONG
}

// ============================================================================
// Message Loop
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn GetMessageA(msg: *mut MSG, hwnd: HWND, msg_filter_min: UINT, msg_filter_max: UINT) -> BOOL {
    win32k_syscall(syscall::NtUserGetMessage, &[msg as u64, hwnd, msg_filter_min as u64, msg_filter_max as u64, 0]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetMessageW(msg: *mut MSG, hwnd: HWND, msg_filter_min: UINT, msg_filter_max: UINT) -> BOOL {
    win32k_syscall(syscall::NtUserGetMessage, &[msg as u64, hwnd, msg_filter_min as u64, msg_filter_max as u64, 1]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn PeekMessageA(msg: *mut MSG, hwnd: HWND, msg_filter_min: UINT, msg_filter_max: UINT, remove_msg: UINT) -> BOOL {
    win32k_syscall(syscall::NtUserPeekMessage, &[msg as u64, hwnd, msg_filter_min as u64, msg_filter_max as u64, remove_msg as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn PeekMessageW(msg: *mut MSG, hwnd: HWND, msg_filter_min: UINT, msg_filter_max: UINT, remove_msg: UINT) -> BOOL {
    win32k_syscall(syscall::NtUserPeekMessage, &[msg as u64, hwnd, msg_filter_min as u64, msg_filter_max as u64, remove_msg as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn TranslateMessage(msg: *const MSG) -> BOOL {
    win32k_syscall(syscall::NtUserTranslateMessage, &[msg as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn DispatchMessageA(msg: *const MSG) -> LRESULT {
    win32k_syscall(syscall::NtUserDispatchMessage, &[msg as u64, 0]) as LRESULT
}

#[no_mangle]
pub unsafe extern "system" fn DispatchMessageW(msg: *const MSG) -> LRESULT {
    win32k_syscall(syscall::NtUserDispatchMessage, &[msg as u64, 1]) as LRESULT
}

#[no_mangle]
pub unsafe extern "system" fn PostMessageA(hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM) -> BOOL {
    win32k_syscall(syscall::NtUserPostMessage, &[hwnd, msg as u64, wparam, lparam as u64, 0]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn PostMessageW(hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM) -> BOOL {
    win32k_syscall(syscall::NtUserPostMessage, &[hwnd, msg as u64, wparam, lparam as u64, 1]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn SendMessageA(hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    win32k_syscall(syscall::NtUserSendMessage, &[hwnd, msg as u64, wparam, lparam as u64, 0]) as LRESULT
}

#[no_mangle]
pub unsafe extern "system" fn SendMessageW(hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    win32k_syscall(syscall::NtUserSendMessage, &[hwnd, msg as u64, wparam, lparam as u64, 1]) as LRESULT
}

#[no_mangle]
pub unsafe extern "system" fn PostQuitMessage(exit_code: i32) {
    win32k_syscall(syscall::NtUserPostQuitMessage, &[exit_code as u64]);
}

#[no_mangle]
pub unsafe extern "system" fn DefWindowProcA(hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    win32k_syscall(syscall::NtUserDefWindowProc, &[hwnd, msg as u64, wparam, lparam as u64, 0]) as LRESULT
}

#[no_mangle]
pub unsafe extern "system" fn DefWindowProcW(hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    win32k_syscall(syscall::NtUserDefWindowProc, &[hwnd, msg as u64, wparam, lparam as u64, 1]) as LRESULT
}

// ============================================================================
// Painting
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn BeginPaint(hwnd: HWND, paint: *mut PAINTSTRUCT) -> HDC {
    win32k_syscall(syscall::NtUserBeginPaint, &[hwnd, paint as u64])
}

#[no_mangle]
pub unsafe extern "system" fn EndPaint(hwnd: HWND, paint: *const PAINTSTRUCT) -> BOOL {
    win32k_syscall(syscall::NtUserEndPaint, &[hwnd, paint as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetDC(hwnd: HWND) -> HDC {
    win32k_syscall(syscall::NtUserGetDC, &[hwnd])
}

#[no_mangle]
pub unsafe extern "system" fn ReleaseDC(hwnd: HWND, hdc: HDC) -> i32 {
    win32k_syscall(syscall::NtUserReleaseDC, &[hwnd, hdc]) as i32
}

// ============================================================================
// Focus and Activation
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn SetFocus(hwnd: HWND) -> HWND {
    win32k_syscall(syscall::NtUserSetFocus, &[hwnd])
}

#[no_mangle]
pub unsafe extern "system" fn GetFocus() -> HWND {
    win32k_syscall(syscall::NtUserGetFocus, &[])
}

#[no_mangle]
pub unsafe extern "system" fn SetActiveWindow(hwnd: HWND) -> HWND {
    win32k_syscall(syscall::NtUserSetActiveWindow, &[hwnd])
}

#[no_mangle]
pub unsafe extern "system" fn GetActiveWindow() -> HWND {
    win32k_syscall(syscall::NtUserGetActiveWindow, &[])
}

#[no_mangle]
pub unsafe extern "system" fn SetForegroundWindow(hwnd: HWND) -> BOOL {
    win32k_syscall(syscall::NtUserSetForegroundWindow, &[hwnd]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetForegroundWindow() -> HWND {
    win32k_syscall(syscall::NtUserGetForegroundWindow, &[])
}

// ============================================================================
// Mouse Capture
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn SetCapture(hwnd: HWND) -> HWND {
    win32k_syscall(syscall::NtUserSetCapture, &[hwnd])
}

#[no_mangle]
pub unsafe extern "system" fn ReleaseCapture() -> BOOL {
    win32k_syscall(syscall::NtUserReleaseCapture, &[]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetCapture() -> HWND {
    win32k_syscall(syscall::NtUserGetCapture, &[])
}

// ============================================================================
// Keyboard Input
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn GetKeyState(vkey: i32) -> i16 {
    win32k_syscall(syscall::NtUserGetKeyState, &[vkey as u64]) as i16
}

#[no_mangle]
pub unsafe extern "system" fn GetAsyncKeyState(vkey: i32) -> i16 {
    win32k_syscall(syscall::NtUserGetAsyncKeyState, &[vkey as u64]) as i16
}

#[no_mangle]
pub unsafe extern "system" fn GetKeyboardState(state: *mut u8) -> BOOL {
    win32k_syscall(syscall::NtUserGetKeyboardState, &[state as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn SetKeyboardState(state: *const u8) -> BOOL {
    win32k_syscall(syscall::NtUserSetKeyboardState, &[state as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn MapVirtualKeyA(code: UINT, map_type: UINT) -> UINT {
    win32k_syscall(syscall::NtUserMapVirtualKey, &[code as u64, map_type as u64, 0]) as UINT
}

#[no_mangle]
pub unsafe extern "system" fn MapVirtualKeyW(code: UINT, map_type: UINT) -> UINT {
    win32k_syscall(syscall::NtUserMapVirtualKey, &[code as u64, map_type as u64, 1]) as UINT
}

// ============================================================================
// Mouse/Cursor
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn GetCursorPos(point: *mut POINT) -> BOOL {
    win32k_syscall(syscall::NtUserGetCursorPos, &[point as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn SetCursorPos(x: i32, y: i32) -> BOOL {
    win32k_syscall(syscall::NtUserSetCursorPos, &[x as u64, y as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn ShowCursor(show: BOOL) -> i32 {
    win32k_syscall(syscall::NtUserShowCursor, &[show as u64]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn SetCursor(cursor: HCURSOR) -> HCURSOR {
    win32k_syscall(syscall::NtUserSetCursor, &[cursor])
}

#[no_mangle]
pub unsafe extern "system" fn LoadCursorA(instance: HINSTANCE, cursor_name: *const u8) -> HCURSOR {
    win32k_syscall(syscall::NtUserLoadCursor, &[instance, cursor_name as u64, 0])
}

#[no_mangle]
pub unsafe extern "system" fn LoadCursorW(instance: HINSTANCE, cursor_name: *const u16) -> HCURSOR {
    win32k_syscall(syscall::NtUserLoadCursor, &[instance, cursor_name as u64, 1])
}

// ============================================================================
// Menus
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn CreateMenu() -> HMENU {
    win32k_syscall(syscall::NtUserCreateMenu, &[])
}

#[no_mangle]
pub unsafe extern "system" fn CreatePopupMenu() -> HMENU {
    win32k_syscall(syscall::NtUserCreateMenu, &[1])
}

#[no_mangle]
pub unsafe extern "system" fn DestroyMenu(menu: HMENU) -> BOOL {
    win32k_syscall(syscall::NtUserDestroyMenu, &[menu]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn AppendMenuA(menu: HMENU, flags: UINT, id_new_item: u64, new_item: *const u8) -> BOOL {
    win32k_syscall(syscall::NtUserAppendMenu, &[menu, flags as u64, id_new_item, new_item as u64, 0]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn AppendMenuW(menu: HMENU, flags: UINT, id_new_item: u64, new_item: *const u16) -> BOOL {
    win32k_syscall(syscall::NtUserAppendMenu, &[menu, flags as u64, id_new_item, new_item as u64, 1]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn SetMenu(hwnd: HWND, menu: HMENU) -> BOOL {
    win32k_syscall(syscall::NtUserSetMenu, &[hwnd, menu]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetMenu(hwnd: HWND) -> HMENU {
    win32k_syscall(syscall::NtUserGetMenu, &[hwnd])
}

#[no_mangle]
pub unsafe extern "system" fn TrackPopupMenu(
    menu: HMENU,
    flags: UINT,
    x: i32,
    y: i32,
    reserved: i32,
    hwnd: HWND,
    rect: *const RECT,
) -> BOOL {
    win32k_syscall(syscall::NtUserTrackPopupMenu, &[menu, flags as u64, x as u64, y as u64, reserved as u64, hwnd, rect as u64]) as BOOL
}

// ============================================================================
// MessageBox
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn MessageBoxA(hwnd: HWND, text: *const u8, caption: *const u8, mb_type: UINT) -> i32 {
    win32k_syscall(syscall::NtUserMessageBox, &[hwnd, text as u64, caption as u64, mb_type as u64, 0]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn MessageBoxW(hwnd: HWND, text: *const u16, caption: *const u16, mb_type: UINT) -> i32 {
    win32k_syscall(syscall::NtUserMessageBox, &[hwnd, text as u64, caption as u64, mb_type as u64, 1]) as i32
}

// ============================================================================
// Dialogs
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn GetDlgItem(dlg: HWND, id: i32) -> HWND {
    win32k_syscall(syscall::NtUserGetDlgItem, &[dlg, id as u64])
}

#[no_mangle]
pub unsafe extern "system" fn SetDlgItemTextA(dlg: HWND, id: i32, text: *const u8) -> BOOL {
    win32k_syscall(syscall::NtUserSetDlgItemText, &[dlg, id as u64, text as u64, 0]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn SetDlgItemTextW(dlg: HWND, id: i32, text: *const u16) -> BOOL {
    win32k_syscall(syscall::NtUserSetDlgItemText, &[dlg, id as u64, text as u64, 1]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn GetDlgItemTextA(dlg: HWND, id: i32, text: *mut u8, max_count: i32) -> UINT {
    win32k_syscall(syscall::NtUserGetDlgItemText, &[dlg, id as u64, text as u64, max_count as u64, 0]) as UINT
}

#[no_mangle]
pub unsafe extern "system" fn GetDlgItemTextW(dlg: HWND, id: i32, text: *mut u16, max_count: i32) -> UINT {
    win32k_syscall(syscall::NtUserGetDlgItemText, &[dlg, id as u64, text as u64, max_count as u64, 1]) as UINT
}

#[no_mangle]
pub unsafe extern "system" fn EndDialog(dlg: HWND, result: i64) -> BOOL {
    win32k_syscall(syscall::NtUserEndDialog, &[dlg, result as u64]) as BOOL
}

// ============================================================================
// Timers
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn SetTimer(hwnd: HWND, id: u64, elapse: UINT, timer_func: u64) -> u64 {
    win32k_syscall(syscall::NtUserSetTimer, &[hwnd, id, elapse as u64, timer_func])
}

#[no_mangle]
pub unsafe extern "system" fn KillTimer(hwnd: HWND, id: u64) -> BOOL {
    win32k_syscall(syscall::NtUserKillTimer, &[hwnd, id]) as BOOL
}

// ============================================================================
// System Information
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn GetSystemMetrics(index: i32) -> i32 {
    win32k_syscall(syscall::NtUserGetSystemMetrics, &[index as u64]) as i32
}

#[no_mangle]
pub unsafe extern "system" fn GetDesktopWindow() -> HWND {
    win32k_syscall(syscall::NtUserGetDesktopWindow, &[])
}

// ============================================================================
// Window Enumeration and Search
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn FindWindowA(class_name: *const u8, window_name: *const u8) -> HWND {
    win32k_syscall(syscall::NtUserFindWindow, &[class_name as u64, window_name as u64, 0])
}

#[no_mangle]
pub unsafe extern "system" fn FindWindowW(class_name: *const u16, window_name: *const u16) -> HWND {
    win32k_syscall(syscall::NtUserFindWindow, &[class_name as u64, window_name as u64, 1])
}

#[no_mangle]
pub unsafe extern "system" fn GetParent(hwnd: HWND) -> HWND {
    win32k_syscall(syscall::NtUserGetParent, &[hwnd])
}

#[no_mangle]
pub unsafe extern "system" fn SetParent(hwnd_child: HWND, hwnd_new_parent: HWND) -> HWND {
    win32k_syscall(syscall::NtUserSetParent, &[hwnd_child, hwnd_new_parent])
}

#[no_mangle]
pub unsafe extern "system" fn IsWindow(hwnd: HWND) -> BOOL {
    win32k_syscall(syscall::NtUserIsWindow, &[hwnd]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn IsWindowVisible(hwnd: HWND) -> BOOL {
    win32k_syscall(syscall::NtUserIsWindowVisible, &[hwnd]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn IsWindowEnabled(hwnd: HWND) -> BOOL {
    win32k_syscall(syscall::NtUserIsWindowEnabled, &[hwnd]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn EnableWindow(hwnd: HWND, enable: BOOL) -> BOOL {
    win32k_syscall(syscall::NtUserEnableWindow, &[hwnd, enable as u64]) as BOOL
}

// ============================================================================
// Coordinate Transformation
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn ClientToScreen(hwnd: HWND, point: *mut POINT) -> BOOL {
    win32k_syscall(syscall::NtUserGetClientToScreen, &[hwnd, point as u64]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn ScreenToClient(hwnd: HWND, point: *mut POINT) -> BOOL {
    win32k_syscall(syscall::NtUserGetScreenToClient, &[hwnd, point as u64]) as BOOL
}

// ============================================================================
// Icons
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn LoadIconA(instance: HINSTANCE, icon_name: *const u8) -> HICON {
    win32k_syscall(syscall::NtUserLoadIcon, &[instance, icon_name as u64, 0])
}

#[no_mangle]
pub unsafe extern "system" fn LoadIconW(instance: HINSTANCE, icon_name: *const u16) -> HICON {
    win32k_syscall(syscall::NtUserLoadIcon, &[instance, icon_name as u64, 1])
}

#[no_mangle]
pub unsafe extern "system" fn DestroyIcon(icon: HICON) -> BOOL {
    win32k_syscall(syscall::NtUserDestroyIcon, &[icon]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn DrawIcon(hdc: HDC, x: i32, y: i32, icon: HICON) -> BOOL {
    win32k_syscall(syscall::NtUserDrawIcon, &[hdc, x as u64, y as u64, icon]) as BOOL
}

// ============================================================================
// Clipboard
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn OpenClipboard(hwnd: HWND) -> BOOL {
    win32k_syscall(syscall::NtUserOpenClipboard, &[hwnd]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn CloseClipboard() -> BOOL {
    win32k_syscall(syscall::NtUserCloseClipboard, &[]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn EmptyClipboard() -> BOOL {
    win32k_syscall(syscall::NtUserEmptyClipboard, &[]) as BOOL
}

#[no_mangle]
pub unsafe extern "system" fn SetClipboardData(format: UINT, data: u64) -> u64 {
    win32k_syscall(syscall::NtUserSetClipboardData, &[format as u64, data])
}

#[no_mangle]
pub unsafe extern "system" fn GetClipboardData(format: UINT) -> u64 {
    win32k_syscall(syscall::NtUserGetClipboardData, &[format as u64])
}

// ============================================================================
// Module initialization
// ============================================================================

/// Initialize the user32 stub module
pub fn init() {
    crate::serial_println!("[USER32] Initializing user32.dll stub...");
}

/// Get the address of an exported function
pub fn get_export(name: &str) -> Option<u64> {
    // Cast function pointers at runtime to avoid const eval issues
    let addr: u64 = match name {
        "RegisterClassA" => RegisterClassA as usize as u64,
        "RegisterClassW" => RegisterClassW as usize as u64,
        "UnregisterClassA" => UnregisterClassA as usize as u64,
        "UnregisterClassW" => UnregisterClassW as usize as u64,
        "CreateWindowExA" => CreateWindowExA as usize as u64,
        "CreateWindowExW" => CreateWindowExW as usize as u64,
        "DestroyWindow" => DestroyWindow as usize as u64,
        "ShowWindow" => ShowWindow as usize as u64,
        "MoveWindow" => MoveWindow as usize as u64,
        "SetWindowPos" => SetWindowPos as usize as u64,
        "GetWindowRect" => GetWindowRect as usize as u64,
        "GetClientRect" => GetClientRect as usize as u64,
        "UpdateWindow" => UpdateWindow as usize as u64,
        "InvalidateRect" => InvalidateRect as usize as u64,
        "SetWindowTextA" => SetWindowTextA as usize as u64,
        "SetWindowTextW" => SetWindowTextW as usize as u64,
        "GetWindowTextA" => GetWindowTextA as usize as u64,
        "GetWindowTextW" => GetWindowTextW as usize as u64,
        "GetWindowTextLengthA" => GetWindowTextLengthA as usize as u64,
        "GetWindowTextLengthW" => GetWindowTextLengthW as usize as u64,
        "GetWindowLongA" => GetWindowLongA as usize as u64,
        "GetWindowLongW" => GetWindowLongW as usize as u64,
        "SetWindowLongA" => SetWindowLongA as usize as u64,
        "SetWindowLongW" => SetWindowLongW as usize as u64,
        "GetMessageA" => GetMessageA as usize as u64,
        "GetMessageW" => GetMessageW as usize as u64,
        "PeekMessageA" => PeekMessageA as usize as u64,
        "PeekMessageW" => PeekMessageW as usize as u64,
        "TranslateMessage" => TranslateMessage as usize as u64,
        "DispatchMessageA" => DispatchMessageA as usize as u64,
        "DispatchMessageW" => DispatchMessageW as usize as u64,
        "PostMessageA" => PostMessageA as usize as u64,
        "PostMessageW" => PostMessageW as usize as u64,
        "SendMessageA" => SendMessageA as usize as u64,
        "SendMessageW" => SendMessageW as usize as u64,
        "PostQuitMessage" => PostQuitMessage as usize as u64,
        "DefWindowProcA" => DefWindowProcA as usize as u64,
        "DefWindowProcW" => DefWindowProcW as usize as u64,
        "BeginPaint" => BeginPaint as usize as u64,
        "EndPaint" => EndPaint as usize as u64,
        "GetDC" => GetDC as usize as u64,
        "ReleaseDC" => ReleaseDC as usize as u64,
        "SetFocus" => SetFocus as usize as u64,
        "GetFocus" => GetFocus as usize as u64,
        "SetActiveWindow" => SetActiveWindow as usize as u64,
        "GetActiveWindow" => GetActiveWindow as usize as u64,
        "SetForegroundWindow" => SetForegroundWindow as usize as u64,
        "GetForegroundWindow" => GetForegroundWindow as usize as u64,
        "SetCapture" => SetCapture as usize as u64,
        "ReleaseCapture" => ReleaseCapture as usize as u64,
        "GetCapture" => GetCapture as usize as u64,
        "GetKeyState" => GetKeyState as usize as u64,
        "GetAsyncKeyState" => GetAsyncKeyState as usize as u64,
        "GetKeyboardState" => GetKeyboardState as usize as u64,
        "SetKeyboardState" => SetKeyboardState as usize as u64,
        "MapVirtualKeyA" => MapVirtualKeyA as usize as u64,
        "MapVirtualKeyW" => MapVirtualKeyW as usize as u64,
        "GetCursorPos" => GetCursorPos as usize as u64,
        "SetCursorPos" => SetCursorPos as usize as u64,
        "ShowCursor" => ShowCursor as usize as u64,
        "SetCursor" => SetCursor as usize as u64,
        "LoadCursorA" => LoadCursorA as usize as u64,
        "LoadCursorW" => LoadCursorW as usize as u64,
        "CreateMenu" => CreateMenu as usize as u64,
        "CreatePopupMenu" => CreatePopupMenu as usize as u64,
        "DestroyMenu" => DestroyMenu as usize as u64,
        "AppendMenuA" => AppendMenuA as usize as u64,
        "AppendMenuW" => AppendMenuW as usize as u64,
        "SetMenu" => SetMenu as usize as u64,
        "GetMenu" => GetMenu as usize as u64,
        "TrackPopupMenu" => TrackPopupMenu as usize as u64,
        "MessageBoxA" => MessageBoxA as usize as u64,
        "MessageBoxW" => MessageBoxW as usize as u64,
        "GetDlgItem" => GetDlgItem as usize as u64,
        "SetDlgItemTextA" => SetDlgItemTextA as usize as u64,
        "SetDlgItemTextW" => SetDlgItemTextW as usize as u64,
        "GetDlgItemTextA" => GetDlgItemTextA as usize as u64,
        "GetDlgItemTextW" => GetDlgItemTextW as usize as u64,
        "EndDialog" => EndDialog as usize as u64,
        "SetTimer" => SetTimer as usize as u64,
        "KillTimer" => KillTimer as usize as u64,
        "GetSystemMetrics" => GetSystemMetrics as usize as u64,
        "GetDesktopWindow" => GetDesktopWindow as usize as u64,
        "FindWindowA" => FindWindowA as usize as u64,
        "FindWindowW" => FindWindowW as usize as u64,
        "GetParent" => GetParent as usize as u64,
        "SetParent" => SetParent as usize as u64,
        "IsWindow" => IsWindow as usize as u64,
        "IsWindowVisible" => IsWindowVisible as usize as u64,
        "IsWindowEnabled" => IsWindowEnabled as usize as u64,
        "EnableWindow" => EnableWindow as usize as u64,
        "ClientToScreen" => ClientToScreen as usize as u64,
        "ScreenToClient" => ScreenToClient as usize as u64,
        "LoadIconA" => LoadIconA as usize as u64,
        "LoadIconW" => LoadIconW as usize as u64,
        "DestroyIcon" => DestroyIcon as usize as u64,
        "DrawIcon" => DrawIcon as usize as u64,
        "OpenClipboard" => OpenClipboard as usize as u64,
        "CloseClipboard" => CloseClipboard as usize as u64,
        "EmptyClipboard" => EmptyClipboard as usize as u64,
        "SetClipboardData" => SetClipboardData as usize as u64,
        "GetClipboardData" => GetClipboardData as usize as u64,
        _ => return None,
    };
    Some(addr)
}
