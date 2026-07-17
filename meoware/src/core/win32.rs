use crate::core::types::*;
use crate::core::{invoke, ssn_table};
use core::ffi::c_void;

pub unsafe fn rtl_init_unicode_string(
    destinations_string: *mut UnicodeString,
    source_string: *const u16,
) { unsafe {
    let table = ssn_table::syscall_table();
    if table.win32.rtl_init_unicode_string.is_null() {
        return;
    }

    type FnRtlInitUnicodeString = unsafe extern "system" fn(*mut UnicodeString, *const u16);
    let func: FnRtlInitUnicodeString = core::mem::transmute(table.win32.rtl_init_unicode_string);
    func(destinations_string, source_string);
}}

pub unsafe fn rtl_get_version(prtl_osversioninfow: *mut OsVersionInfoExW) -> NTSTATUS { unsafe {
    let table = ssn_table::syscall_table();
    invoke::call1(table.win32.rtl_get_version, prtl_osversioninfow as usize)
}}

pub unsafe fn tp_alloc_work(
    work_return: *mut *mut c_void,
    callback: *mut c_void,
    context: *mut c_void,
    callback_environ: *mut c_void,
) -> NTSTATUS { unsafe {
    let table = ssn_table::syscall_table();
    if table.win32.tp_alloc_work.is_null() {
        return -1;
    }

    type FnTPAllockWork = unsafe extern "system" fn(
        *mut *mut c_void, // PTP_WORK*
        *mut c_void,      // PTP_WORK_CALLBACK
        *mut c_void,      // PVOID Context
        *mut c_void,      // PTP_CALLBACK_ENVIRON
    ) -> NTSTATUS;

    let func: FnTPAllockWork = core::mem::transmute(table.win32.tp_alloc_work);
    func(work_return, callback, context, callback_environ)
}}

pub unsafe fn tp_port_work(work: *mut c_void) { unsafe {
    let table = ssn_table::syscall_table();
    if table.win32.tp_post_work.is_null() {
        return;
    }
    type FnTpPostWork = unsafe extern "system" fn(*mut c_void);

    let func: FnTpPostWork = core::mem::transmute(table.win32.tp_post_work);
    func(work);
}}

pub unsafe fn tp_release_work(work: *mut c_void) { unsafe {
    let table = ssn_table::syscall_table();
    if table.win32.tp_release_work.is_null() {
        return;
    }
    type FnTpReleaseWork = unsafe extern "system" fn(*mut c_void);

    let func: FnTpReleaseWork = core::mem::transmute(table.win32.tp_release_work);
    func(work);
}}

pub unsafe fn create_process_w(
    application_name: *const u16,
    command_line: *mut u16,
    process_attributes: *mut c_void,
    thread_attributes: *mut c_void,
    inherit_handles: i32,
    creation_flag: u32,
    environment: *mut c_void,
    current_directory: *const u16,
    startup_info: *mut StartupInfoW,
    process_information: *mut ProcessInformation,
) -> i32 { unsafe {
    let table = ssn_table::syscall_table();
    if table.win32.create_process_w.is_null() {
        return 0;
    }

    type FnCreateProcessW = unsafe extern "system" fn(
        *const u16,              // lpApplicationName
        *mut u16,                // lpCommandLine
        *mut c_void,             // lpProcessAttributes
        *mut c_void,             // lpThreadAttributes
        i32,                     // bInheritHandles
        u32,                     // dwCreationFlags
        *mut c_void,             // lpEnvironment
        *const u16,              // lpCurrentDirectory
        *mut StartupInfoW,       // lpStartupInfo
        *mut ProcessInformation, // lpProcessInformation
    ) -> i32;

    let func: FnCreateProcessW = core::mem::transmute(table.win32.create_process_w);
    func(
        application_name,
        command_line,
        process_attributes,
        thread_attributes,
        inherit_handles,
        creation_flag,
        environment,
        current_directory,
        startup_info,
        process_information,
    )
}}

pub unsafe fn rtl_create_process_parameters_ex(
    process_parameters: *mut *mut c_void,
    image_path_name: *mut UnicodeString,
    dll_path: *mut UnicodeString,
    current_directory: *mut UnicodeString,
    command_line: *mut UnicodeString,
    environment: *mut c_void,
    window_title: *mut UnicodeString,
    desktop_info: *mut UnicodeString,
    shell_info: *mut UnicodeString,
    runtime_data: *mut UnicodeString,
    flags: u32,
) -> NTSTATUS { unsafe {
    let table = ssn_table::syscall_table();
    if table.win32.rtl_create_process_parameters_ex.is_null() {
        return -1;
    }

    type FnRtlCreateProcessParametersEx = unsafe extern "system" fn(
        *mut *mut c_void,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut c_void,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut UnicodeString,
        *mut UnicodeString,
        u32,
    ) -> NTSTATUS;

    let func: FnRtlCreateProcessParametersEx =
        core::mem::transmute(table.win32.rtl_create_process_parameters_ex);
    func(
        process_parameters,
        image_path_name,
        dll_path,
        current_directory,
        command_line,
        environment,
        window_title,
        desktop_info,
        shell_info,
        runtime_data,
        flags,
    )
}}

pub unsafe fn rtl_destroy_process_parameters(process_parameters: *mut c_void) { unsafe {
    let table = ssn_table::syscall_table();
    if table.win32.rtl_destroy_process_parameters.is_null() {
        return;
    }
    type FnRtlDestroyProcessParameters = unsafe extern "system" fn(*mut c_void) -> NTSTATUS;

    let func: FnRtlDestroyProcessParameters =
        core::mem::transmute(table.win32.rtl_destroy_process_parameters);
    func(process_parameters);
}}
