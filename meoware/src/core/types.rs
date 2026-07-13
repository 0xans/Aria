pub type HANDLE = *mut core::ffi::c_void;

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub(crate) number_of_names: u32,
    pub address_of_functions: u32,     // RVA from base of image
    pub address_of_names: u32,         // RVA from base of image
    pub address_of_name_ordinals: u32, // RVA from base of image
}
