pub type HANDLE = *mut core::ffi::c_void;


// Struct to hold SSN + syscall instruction address for a single NT function.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEntry {
    pub ssn: u16,
    pub syscall_addr: *mut core::ffi::c_void,
}

impl SyscallEntry {
    pub const fn empty() -> Self {
        Self {
            ssn: 0,
            syscall_addr: core::ptr::null_mut(),
        }
    }
}