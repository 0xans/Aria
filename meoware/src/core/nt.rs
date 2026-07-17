use crate::core::invoke;
use crate::core::ssn_table;
use crate::core::types::*;
use core::ffi::c_void;

pub unsafe fn nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
    client_id: *mut ClientID,
) -> NTSTATUS {
    unsafe {
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
    }
}

pub unsafe fn nt_close(handle: HANDLE) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_close;
        invoke::syscall1(e.ssn, e.syscall_addr as usize, handle as usize)
    }
}

pub unsafe fn nt_allocate_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_allocate_virtual_memory;
        invoke::syscall6(
            e.ssn,
            e.syscall_addr as usize,
            process_handle as usize,
            base_address as usize,
            zero_bits,
            region_size as usize,
            allocation_type as usize,
            protect as usize,
        )
    }
}

pub unsafe fn nt_write_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut c_void,
    buffer: *const c_void,
    buffer_size: usize,
    bytes_written: *mut usize,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_write_virtual_memory;
        invoke::syscall5(
            e.ssn,
            e.syscall_addr as usize,
            process_handle as usize,
            base_address as usize,
            buffer as usize,
            buffer_size,
            bytes_written as usize,
        )
    }
}

pub unsafe fn nt_protect_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_protect_virtual_memory;
        invoke::syscall5(
            e.ssn,
            e.syscall_addr as usize,
            process_handle as usize,
            base_address as usize,
            region_size as usize,
            new_protect as usize,
            old_protect as usize,
        )
    }
}

pub unsafe fn nt_create_thread_ex(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut c_void,
    process_handle: HANDLE,
    start_address: *mut c_void,
    parameter: *mut c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_commit: usize,
    stack_reserve: usize,
    bytes_buffer: *mut c_void,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_create_thread_ex;
        invoke::syscall11(
            e.ssn,
            e.syscall_addr as usize,
            thread_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            process_handle as usize,
            start_address as usize,
            parameter as usize,
            create_flags as usize,
            zero_bits,
            stack_commit,
            stack_reserve,
            bytes_buffer as usize,
        )
    }
}

pub unsafe fn nt_wait_for_single_object(
    handle: HANDLE,
    alertable: u8,
    timeout: *mut c_void,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_wait_for_single_object;
        invoke::syscall3(
            e.ssn,
            e.syscall_addr as usize,
            handle as usize,
            alertable as usize,
            timeout as usize,
        )
    }
}

pub unsafe fn nt_queue_apc_thread(
    thread_handle: HANDLE,
    apc_routine: *mut c_void,
    apc_argument1: *mut c_void,
    apc_argument2: *mut c_void,
    apc_argument3: *mut c_void,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_queue_apc_thread;
        invoke::syscall5(
            e.ssn,
            e.syscall_addr as usize,
            thread_handle as usize,
            apc_routine as usize,
            apc_argument1 as usize,
            apc_argument2 as usize,
            apc_argument3 as usize,
        )
    }
}

pub unsafe fn nt_resume_thread(
    thread_handle: HANDLE,
    previous_suspend_count: *mut u32,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_resume_thread;
        invoke::syscall2(
            e.ssn,
            e.syscall_addr as usize,
            thread_handle as usize,
            previous_suspend_count as usize,
        )
    }
}

pub unsafe fn nt_create_file(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
    io_status_block: *mut IoStatusBlock,
    allocation_size: *mut c_void,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: *mut c_void,
    ea_lenght: u32,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_create_file;
        invoke::syscall11(
            e.ssn,
            e.syscall_addr as usize,
            file_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            io_status_block as usize,
            allocation_size as usize,
            file_attributes as usize,
            share_access as usize,
            create_disposition as usize,
            create_options as usize,
            ea_buffer as usize,
            ea_lenght as usize,
        )
    }
}

pub unsafe fn nt_write_file(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: *mut IoStatusBlock,
    buffer: *const c_void,
    length: u32,
    byte_offset: *mut c_void,
    key: *mut c_void,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_write_file;
        invoke::syscall9(
            e.ssn,
            e.syscall_addr as usize,
            file_handle as usize,
            event as usize,
            apc_routine as usize,
            apc_context as usize,
            io_status_block as usize,
            buffer as usize,
            length as usize,
            byte_offset as usize,
            key as usize,
        )
    }
}

pub unsafe fn nt_read_file(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: *mut IoStatusBlock,
    buffer: *mut c_void,
    length: u32,
    byte_offset: *mut c_void,
    key: *mut c_void,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_read_file;
        invoke::syscall9(
            e.ssn,
            e.syscall_addr as usize,
            file_handle as usize,
            event as usize,
            apc_routine as usize,
            apc_context as usize,
            io_status_block as usize,
            buffer as usize,
            length as usize,
            byte_offset as usize,
            key as usize,
        )
    }
}

pub unsafe fn nt_set_information_file(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    file_information: *mut c_void,
    length: u32,
    file_information_class: u32,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_set_information_file;
        invoke::syscall5(
            e.ssn,
            e.syscall_addr as usize,
            file_handle as usize,
            io_status_block as usize,
            file_information as usize,
            length as usize,
            file_information_class as usize,
        )
    }
}

pub unsafe fn nt_create_section(
    section_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut c_void,
    maximum_size: *mut c_void,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: HANDLE,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_create_section;
        invoke::syscall7(
            e.ssn,
            e.syscall_addr as usize,
            section_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            maximum_size as usize,
            section_page_protection as usize,
            allocation_attributes as usize,
            file_handle as usize,
        )
    }
}

pub unsafe fn nt_create_process_ex(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut c_void,
    parent_process: HANDLE,
    flags: u32,
    section_handle: HANDLE,
    debug_port: HANDLE,
    exception_port: HANDLE,
    job_member_level: u32,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_create_process_ex;
        invoke::syscall9(
            e.ssn,
            e.syscall_addr as usize,
            process_handle as usize,
            desired_access as usize,
            object_attributes as usize,
            parent_process as usize,
            flags as usize,
            section_handle as usize,
            debug_port as usize,
            exception_port as usize,
            job_member_level as usize,
        )
    }
}

pub unsafe fn nt_query_information_process(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: *mut c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_query_information_process;
        invoke::syscall5(
            e.ssn,
            e.syscall_addr as usize,
            process_handle as usize,
            process_information_class as usize,
            process_information as usize,
            process_information_length as usize,
            return_length as usize,
        )
    }
}

pub unsafe fn nt_read_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut c_void,
    buffer: *mut c_void,
    buffer_size: usize,
    bytes_read: *mut usize,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_read_virtual_memory;
        invoke::syscall5(
            e.ssn,
            e.syscall_addr as usize,
            process_handle as usize,
            base_address as usize,
            buffer as usize,
            buffer_size,
            bytes_read as usize,
        )
    }
}

pub unsafe fn nt_query_system_information(
    system_information_class: u32,
    system_information: *mut c_void,
    system_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_query_system_information;
        invoke::syscall4(
            e.ssn,
            e.syscall_addr as usize,
            system_information_class as usize,
            system_information as usize,
            system_information_length as usize,
            return_length as usize,
        )
    }
}

pub unsafe fn nt_terminate_process(process_handle: HANDLE, exit_status: NTSTATUS) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_terminate_process;
        invoke::syscall2(
            e.ssn,
            e.syscall_addr as usize,
            process_handle as usize,
            exit_status as usize,
        )
    }
}

pub unsafe fn nt_duplicate_object(
    source_process: HANDLE,
    source_handle: HANDLE,
    target_process: HANDLE,
    target_handle: *mut HANDLE,
    desired_access: u32,
    attributes: u32,
    options: u32,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_duplicate_object;
        invoke::syscall7(
            e.ssn,
            e.syscall_addr as usize,
            source_process as usize,
            source_handle as usize,
            target_process as usize,
            target_handle as usize,
            desired_access as usize,
            attributes as usize,
            options as usize,
        )
    }
}

pub unsafe fn nt_set_io_completion(
    io_completion: HANDLE,
    key_context: *mut c_void,
    apc_context: *mut c_void,
    io_status: NTSTATUS,
    io_information: usize,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_set_io_completion;
        invoke::syscall5(
            e.ssn,
            e.syscall_addr as usize,
            io_completion as usize,
            key_context as usize,
            apc_context as usize,
            io_status as usize,
            io_information,
        )
    }
}

pub unsafe fn nt_query_information_worker_factory(
    worker_factory: HANDLE,
    info_class: u32,
    buffer: *mut c_void,
    buffer_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_query_information_worker_factory;
        invoke::syscall5(
            e.ssn,
            e.syscall_addr as usize,
            worker_factory as usize,
            info_class as usize,
            buffer as usize,
            buffer_length as usize,
            return_length as usize,
        )
    }
}

pub unsafe fn nt_map_view_of_section(
    section_handle: HANDLE,
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    commit_size: usize,
    section_offset: *mut i64,
    view_size: *mut usize,
    inherit_disposition: u32,
    allocation_type: u32,
    win32_protect: u32,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_map_view_of_section;
        invoke::syscall10(
            e.ssn,
            e.syscall_addr as usize,
            section_handle as usize,
            process_handle as usize,
            base_address as usize,
            zero_bits,
            commit_size,
            section_offset as usize,
            view_size as usize,
            inherit_disposition as usize,
            allocation_type as usize,
            win32_protect as usize,
        )
    }
}

pub unsafe fn nt_unmap_view_of_section(
    process_handle: HANDLE,
    base_address: *mut c_void,
) -> NTSTATUS {
    unsafe {
        let table = ssn_table::syscall_table();
        let e = &table.ssns.nt_unmap_view_of_section;
        invoke::syscall2(
            e.ssn,
            e.syscall_addr as usize,
            process_handle as usize,
            base_address as usize,
        )
    }
}
