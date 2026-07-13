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
 * */
#[repr(C)]
pub struct SyscallSsns {
    pub(crate) nt_open_process: SyscallEntry,
}

/**
 * Struct to hold pointers to dynamically resolved Win32 and Rtl functions
 * */
#[repr(C)]
pub struct Win32Funcs {
    pub(crate) create_process_w: *mut c_void,
}

/**
 * Struct that contains handles to dynamically resolved modules
 * */
pub struct ModuleHandles {
    pub(crate) ntdll: HANDLE,
    pub(crate) kernel32: HANDLE,
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
    },
    win32: Win32Funcs {
        create_process_w: core::ptr::null_mut(),
    },
    modules: ModuleHandles {
        ntdll: core::ptr::null_mut(),
        kernel32: core::ptr::null_mut(),
    },
}));

pub unsafe fn initialize_syscalls(mut ntdll: *mut c_void) -> bool {
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

    // Resolve each syscall - both SSN and pre function syscall address
    resolve_ssn!(nt_open_process, hashes::NTOPENPROCESS_HASH);

    state.win32.create_process_w = resolver::ldr_function_by_hash(state.modules.kernel32, hashes::CREATEPROCESSW_HASH);

    state.ssns.nt_open_process.ssn != 0 && !state.ssns.nt_open_process.syscall_addr.is_null()
}

unsafe fn extract_syscall_info(
    function: *mut c_void,
    resolve_hooked: bool,
    mut ssn: Option<&mut u16>,
    syscall_address: Option<&mut *mut c_void>,
) -> bool {
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

unsafe fn find_hooked_syscall_ssn(function: *mut c_void, ssn: &mut u16) -> bool {
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
