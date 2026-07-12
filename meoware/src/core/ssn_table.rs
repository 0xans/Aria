use core::cell::UnsafeCell;
use crate::core::types::{HANDLE, SyscallEntry};
use core::ffi::c_void;

/** 
 * Struct to hold SSN + syscall addresses per funcion
 * */
#[repr(C)]
pub struct SyscallSsns {
    pub(crate) nt_open_process:SyscallEntry,
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
    pub(crate) kernel32: HANDLE
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

static NATIVE: SyscallCell = SyscallCell(
    UnsafeCell::new(
        SyscallInfo { 
            ssns: SyscallSsns { 
                nt_open_process: SyscallEntry::empty() 
            }, 
            win32: Win32Funcs { 
                create_process_w: core::ptr::null_mut() 
            }, 
            modules: ModuleHandles { 
                ntdll: core::ptr::null_mut(), 
                kernel32: core::ptr::null_mut(), 
            }
        }
    )
);

pub unsafe fn initialize_syscalls(mut ntdll: *mut c_void) -> bool {
    let state = &mut *NATIVE.0.get();

    if ntdll.is_null() {
        unimplemented!()
    }

    state.modules.ntdll = ntdll;

    true
}