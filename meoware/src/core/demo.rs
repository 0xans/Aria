use crate::debug;
use crate::core::ssn_table;
use crate::core::nt;
use crate::core::types::*;

pub unsafe fn demo(pid: u32) { unsafe {
    debug!("Just a Demo Function ^_^");

    let table = ssn_table::syscall_table();
    debug!("[*] NtOpenProcess ==---> 0x{:04X} Syscall Address: 0x{:p}",
        table.ssns.nt_open_process.ssn, table.ssns.nt_open_process.syscall_addr
    );

    debug!("[*] NtClose ==---> 0x{:04X} Syscall Address: 0x{:p}",
        table.ssns.nt_close.ssn, table.ssns.nt_close.syscall_addr
    );

    let mut hprocess: HANDLE = core::ptr::null_mut();
    let mut oa: ObjectAttributes = core::mem::zeroed();
    let mut cid = ClientID { 
        unique_process: pid as HANDLE,
        unique_thread: core::ptr::null_mut(),
    };

    initialize_object_attributes(
        &mut oa, 
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(), 
        core::ptr::null_mut(),
    );

    let status = nt::nt_open_process(&mut hprocess, 0x1F0FFF, &mut oa, &mut cid);
    if status != STATUS_SUCCESS {
        debug!("[-] NtOpenProcess returned 0x{:08X} -> Could not open target process", status as u32);
        return;
    }
    debug!("[+] Got the handle -> {:?}", hprocess);

    debug!("[>] Pause");
    std::io::stdin().read_line(&mut String::new()).unwrap();

    nt::nt_close(hprocess);
    debug!("Done..");
}}