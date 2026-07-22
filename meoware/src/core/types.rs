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

/**
 * Debug register offsets in CONTEXT (x64):
 *  Dr0 = offset 0x048 (breakpoint 0 address)
 *  Dr1 = offset 0x050
 *  Dr2 = offset 0x058
 *  Dr3 = offset 0x060
 *  Dr6 = offset 0x068 (debug status)
 *  Dr7 = offset 0x070 (debug control) 
 * */
#[repr(C, align(16))]
pub struct Context64 {
    pub data: [u8; 1232], // Full context, we address fields by known offsets
}

impl Context64 {
    pub const fn zeroed() -> Self {
        Self { data: [0u8; 1232] }
    }

    pub fn set_flags(&mut self, flags: u32) {
        let bytes = flags.to_le_bytes();
        self.data[0x30..0x34].copy_from_slice(&bytes);
    }

    pub fn flags(&self) -> u32 {
        u32::from_le_bytes([self.data[0x30], self.data[0x31], self.data[0x32], self.data[0x33]])
    }

    // DR0 at offset 0x048
    pub fn set_dr0(&mut self, val: u64) {
        self.data[0x48..0x50].copy_from_slice(&val.to_le_bytes());
    }
    pub fn dr0(&self) -> u64 {
        u64::from_le_bytes(self.data[0x48..0x50].try_into().unwrap())
    }

    // DR7 at offset 0x070
    pub fn set_dr7(&mut self, val: u64) {
        self.data[0x70..0x78].copy_from_slice(&val.to_le_bytes());
    }
    pub fn dr7(&self) -> u64 {
        u64::from_le_bytes(self.data[0x70..0x78].try_into().unwrap())
    }   

    // RIP at offset 0x0F8
    pub fn set_rip(&mut self, val: u64) {
        self.data[0xF8..0x100].copy_from_slice(&val.to_le_bytes());
    }
    pub fn rip(&self) -> u64 {
        u64::from_le_bytes(self.data[0xF8..0x100].try_into().unwrap())
    }

    // RAX at offset 0x078
    pub fn set_rax(&mut self, val: u64) {
        self.data[0x78..0x80].copy_from_slice(&val.to_le_bytes());
    }

    // RSP at offset 0x098
    pub fn set_rsp(&mut self, val: u64) {
        self.data[0x098..0xA0].copy_from_slice(&val.to_le_bytes());
    }
    pub fn rsp(&self) -> u64 {
        u64::from_le_bytes(self.data[0x98..0xA0].try_into().unwrap())
    }
}

// Context flags for NtGetContextThread/NtSetContextThread
pub const CONTEXT_DEBUG_REGISTERS: u32 = 0x00100010; // CONTEXT_AMD64 | DEBUG_REGISTERS
pub const CONTEXT_ALL: u32 = 0x0010001F; // CONTEXT_AMD64


#[repr(C)]
pub struct ExceptionRecord {
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_record: *mut ExceptionRecord,
    pub exception_address: *mut core::ffi::c_void,
    pub number_parameters: u32,
    pub exception_information: [usize; 15], // EXCEPTION_MAXIMUM_PARAMETERS
}

#[repr(C)]
pub struct ExceptionPointers {
    pub exception_record: *mut ExceptionRecord,
    pub context_record: *mut Context64,
}

// Exception record for VEH
pub const STATUS_SINGLE_STEP: u32 = 0x80000004;

// VEH return codes
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
