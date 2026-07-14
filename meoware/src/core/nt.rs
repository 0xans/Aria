use crate::core::invoke;
use crate::core::ssn_table;
use crate::core::types::*;

pub unsafe fn nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
    client_id: *mut ClientID,
) -> NTSTATUS { unsafe {
    let table = ssn_table::syscall_table();
    let e = &table.ssns.nt_open_process;
    invoke::syscall4(
        e.ssn, 
        e.syscall_addr as usize, 
        process_handle as usize,
        desired_access as usize, 
        object_attributes as usize, 
        client_id as usize,
    )
}}

pub unsafe fn nt_close(handle: HANDLE) -> NTSTATUS { unsafe {
    let table = ssn_table::syscall_table();
    let e = &table.ssns.nt_close;
    invoke::syscall1(e.ssn, e.syscall_addr as usize, handle as usize)
}}
