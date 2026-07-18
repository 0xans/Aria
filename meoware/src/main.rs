#![cfg_attr(not(any(debug_assertions, feature = "verbose")), no_std)]

use meoware::core::ssn_table;

fn main() {
    unsafe {
        if !ssn_table::initialize_syscalls(core::ptr::null_mut()) {
            return;
        }
        
        /*
            TODO: A sandbox check
            if !sandbox::env_is_safe() {
                return
            } 
        */
        
        meoware::core::demo::demo();
    }
}
