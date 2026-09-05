use crate::debug;
use crate::core::types::*;
use crate::core::nt;

use core::ffi::c_void;
use core::ptr::null_mut;

/// ntdll.dll native NT path as UTF 16LE + null-terminated
/// \??\C:\Windows\System32\ntdll.dll
const NTDLL_PATH: &[u16] = &[
    0x005C, 0x003F, 0x003F, 0x005C, 0x0043, 0x003A, 0x005C, 0x0057,
    0x0069, 0x006E, 0x0064, 0x006F, 0x0077, 0x0073, 0x005C, 0x0053,
    0x0079, 0x0073, 0x0074, 0x0065, 0x006D, 0x0033, 0x0032, 0x005C,
    0x006E, 0x0074, 0x0064, 0x006C, 0x006C, 0x002E, 0x0064, 0x006C,
    0x006C, 0x0000,
];


unsafe fn get_ntdll_base() -> Option<usize> {
    let peb: usize;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb
    );
    let ldr = *((peb + 0x18) as *const usize);
    if ldr == 0 { return None }

    // InMemoryOrderModuleList
    let list_head = ldr + 0x20;
    let first = *(list_head as *const usize);
    if first == list_head { return None } 

    // Second entry = ntdll
    let second = *(first as *const usize);
    if second == list_head { return None } 

    // DllBase is at offset 0x20 from InMemoryOrderLinks entry
    let base = *((second + 0x20) as *const usize);
    if base == 0 { return None }

    // Verify MZ signature
    let dos = *(base as *const u16);
    if dos != 0x5A4D { return None }

    Some(base)
}

unsafe fn open_ntdll_file() -> Option<HANDLE> {
    // Build UNICODE_STRING for the NT path
    let path_bytes = (NTDLL_PATH.len() - 1) * 2; // exclude null terminator
    let unicode_string = UnicodeString {
        length: path_bytes as u16,
        maximum_length: (NTDLL_PATH.len() * 2) as u16,
        buffer: NTDLL_PATH.as_ptr(),
    };

    // Build OBJECT_ATTRIBUTES  
    let mut obj_attr = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: null_mut(),
        object_name: &unicode_string as *const UnicodeString as *mut UnicodeString,
        attributes: 0x00000040, // OBJ_CASE_INSENSITIVE
        security_descriptor: null_mut(),
        security_quality_of_service: null_mut(),
    };

    let mut file_handle: HANDLE = null_mut();
    let mut io_status = IoStatusBlock {
        status: 0,
        information: 0,
    };

    let status = nt::nt_create_file(
        &mut file_handle,
        0x80100000,     // GENERIC_READ | SYNCHRONIZE
        &mut obj_attr,
        &mut io_status,
        null_mut(),     // AllocationSize
        0x80,           // FILE_ATTRIBUTE_NORMAL
        0x00000001,     // FILE_SHARE_READ
        0x00000001,     // FILE_OPEN (open existing)
        0x00000060,     // FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
        null_mut(),     // EaBuffer
        0,              // EaLength
    );

    if status != STATUS_SUCCESS || file_handle.is_null() {
        debug!("[UNHOOK] NtCreateFile failed: 0x{:08X}", status);
        return None;
    }

    Some(file_handle)
}

/**
 * Find the .text section in a PE image and return (absolute_address, size) of the .text section 
 * */
unsafe fn find_text_section(base: usize) -> Option<(usize, usize)> {
    let e_lfanew = *((base + 0x3C) as *const u32) as usize;
    let nt_header = base + e_lfanew;

    // Verify PE signature "PE\0\0"
    let signature = *(nt_header as *const u32);
    if signature != 0x00004550 {
        return None
    }

    let num_section = *((nt_header + 6) as *const u16) as usize;
    let optional_size = *((nt_header + 20) as *const u16) as usize;
    let section_start = nt_header + 24 + optional_size;

    // Each IMAGE_SECTION_HEADER is 40 bytes
    for i in 0..num_section {
        let section = section_start + i * 40;
        let name = core::slice::from_raw_parts(section as *const u8, 5);

        // ".text"
        if name[0] == b'.' && name[1] == b't' && name[2] == b'e' && name[3] == b'x' && name[4] == b't' {
            let virtual_size = *((section + 8) as *const u32) as usize;  
            let virtual_addr = *((section + 12) as *const u32) as usize;
            return Some((base + virtual_addr, virtual_size))  
       }  
    }
    None
}

pub unsafe fn unhook_ntdll() -> Option<usize> {
    // Get the loaded ntdll base from PEB
    let loaded_base = get_ntdll_base()?;
    debug!("[UNHOOK] Loaded ntdll base: 0x{:X}", loaded_base);

    // Open ntdll.dll from disk
    let file_handle = open_ntdll_file()?;
    debug!("[UNHOOK] Opened ntdll.dll from disk");

    // Create a SEC_IMAGE section
    let mut section_handle: HANDLE = null_mut();
    let status = nt::nt_create_section(
        &mut section_handle,
        0x000F0005, // SECTION_MAP_READ | SECTION_QUERY | STANDARD_RIGHTS_REQUIRED
        null_mut(), // no ObjectAttributes
        null_mut(), // MaximumSize = file size
        0x02,       // PAGE_READONLY
        0x01000000, // SEC_IMAGE, map as PE image
        file_handle,
    );
    nt::nt_close(file_handle);

    if status != STATUS_SUCCESS || section_handle.is_null() {
        debug!("[UNHOOK] NtCreateSeection failed: 0x{:08X}", status);
        return None;
    }

    // Map the clean ntdll image into our process
    let mut clean_base: *mut c_void = null_mut();
    let mut view_size: usize = 0;
    let current_process: HANDLE = -1isize as HANDLE;

    let status = nt::nt_map_view_of_section(
        section_handle,
        current_process,
        &mut clean_base,
        0,          // ZeroBits
        0,          // CommitSize
        null_mut(), // SectionOffset
        &mut view_size,
        2,          // ViewUnmap
        0,          // AllocationType
        0x02,       // PAGE_READONLY    
    );
    nt::nt_close(section_handle);

    if status != STATUS_SUCCESS || clean_base.is_null() {
        debug!("[UNHOOK] NtMapViewOfSection failed: 0x{:08X}", status);
        return None;
    }
    debug!("[UNHOOK] Clean ntdll mapped at: {:p} size=0x{:X}", clean_base, view_size);

    // Find .txt section in both images
    let (loaded_text, text_size) = match find_text_section(loaded_base) {
        Some(t) => t,
        None => {
            debug!("[UNHOOK] Failed to find .text in clean ntdll");
            nt::nt_unmap_view_of_section(current_process, clean_base);
            return None;
        }
    };

    let (clean_text, clean_size) = match find_text_section(clean_base as usize) {
        Some(t) => t,
        None => {
            debug!("[UNHOOK] Failed to find .text in clean ntdll");
            nt::nt_unmap_view_of_section(current_process, clean_base);
            return None;
        }
    };

    let compare_size = text_size.min(clean_size);
    debug!("[UNHOOK] .text loaded=0x{:X} size=0x{:X}", loaded_text, compare_size);

    // TODO: Compare and count differences
    unimplemented!()
}