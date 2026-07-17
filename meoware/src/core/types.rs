pub type HANDLE = *mut core::ffi::c_void;

pub type NTSTATUS = i32;
pub const STATUS_SUCCESS: NTSTATUS = 0;

// PE Image Signature and Directory Constants
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

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

#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: HANDLE,
    pub object_name: *mut UnicodeString,
    pub attributes: u32,
    pub security_descriptor: *mut core::ffi::c_void,
    pub security_quality_of_service: *mut core::ffi::c_void,
}

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u16,
}

#[repr(C)]
pub struct ClientID {
    pub unique_process: HANDLE,
    pub unique_thread: HANDLE,
}

#[inline]
pub unsafe fn initialize_object_attributes(
    p: *mut ObjectAttributes,
    name: *mut UnicodeString,
    attr: u32,
    root: HANDLE,
    sec: *mut core::ffi::c_void,
) {
    unsafe {
        (*p).length = core::mem::size_of::<ObjectAttributes>() as u32;
        (*p).root_directory = root;
        (*p).object_name = name;
        (*p).attributes = attr;
        (*p).security_descriptor = sec;
        (*p).security_quality_of_service = core::ptr::null_mut();
    }
}

#[repr(C)]
pub struct IoStatusBlock {
    pub status: NTSTATUS,
    pub information: usize,
}

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
pub struct OsVersionInfoExW {
    pub os_version_info_size: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
    pub csd_version: [u16; 128],
    pub service_pack_major: u16,
    pub service_pack_minor: u16,
    pub suite_mask: u16,
    pub product_type: u8,
    pub reserved: u8,
}

#[repr(C)]
pub struct StartupInfoW {
    pub cb: u32,
    pub reserved: *mut u16,
    pub desktop: *mut u16,
    pub title: *mut u16,
    pub x: u32,
    pub y: u32,
    pub x_size: u32,
    pub y_size: u32,
    pub x_count_chars: u32,
    pub y_count_chars: u32,
    pub fill_attribute: u32,
    pub flags: u32,
    pub show_window: u16,
    pub cb_reserved_2: u16,
    pub lp_reserved_2: *mut u16,
    pub std_input: HANDLE,
    pub std_output: HANDLE,
    pub std_error: HANDLE,
}

#[repr(C)]
pub struct ProcessInformation {
    pub process: HANDLE,
    pub thread: HANDLE,
    pub process_id: u32,
    pub thread_id: u32,
}
