#![cfg_attr(not(any(debug_assertions, feature = "verbose")), no_std)]

use meoware::core::ssn_table;

fn main() {
    unsafe {
        if !ssn_table::initialize_syscalls(core::ptr::null_mut()) {
            return;
        }

        meoware::core::demo::demo(9224);
    }
}
