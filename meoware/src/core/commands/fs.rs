extern crate alloc;
use alloc::string::String;
use crate::core::{invoke, nt, ssn_table, types::*};

const FILE_DIRECTORY_FILE: u32 = 0x00000001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const FILE_OPEN: u32 = 1;
const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const SYNCHRONIZE: u32 = 0x00100000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;

fn to_nt_path(path: &str) -> Vec<u16> {
    let full_path = if path .len() >= 2 && path.as_bytes()[1] == b':' {
        // Absolute path, like C:\blah
        alloc::format!("\\??\\{}", path)
    } else if path.starts_with("\\??\\") || path.starts_with("\\Device\\") {
        // Already NT path
        String::from(path)
    } else {
        // Relative path, prepend CWD
        let cwd = unsafe { super::get_cwd() };
        if path == "." || path.is_empty() {
            alloc::format!("\\??\\{}", cwd)
        } else if path == ".." {
            // Go up one level
            let parent = if let Some(pos) = cwd.rfind('\\') {
                &cwd[..pos]
            } else {
                &cwd
            };
            alloc::format!("\\??\\{}", parent)
        } else {
            let sep = if cwd.ends_with('\\') { "" } else { "\\" };
            alloc::format!("\\??\\{}{}{}", cwd, sep, path)
        }
    };

    // Convert it to UTF16
    let mut result: Vec<u16> = full_path.encode_utf16().collect();
    result.push(0); // null terminator
    result
}

pub unsafe fn cmd_pwd() -> Result<String, String> {
    Ok(super::get_cwd())
}

pub unsafe fn cmd_cd(args: &[String]) -> Result<String, String> {
    if args.is_empty() {
        return Ok(super::get_cwd());
    }

    let target = &args[0];
    let nt_path = to_nt_path(target);
    let mut unicode_str = core::mem::zeroed::<UnicodeString>();
    let mut obj_attr = core::mem::zeroed::<ObjectAttributes>();
    build_boject_attributes(&nt_path, &mut unicode_str, &mut obj_attr);

    let mut handle: HANDLE = core::ptr::null_mut();
    let mut io_status = IoStatusBlock { status: 0, information: 0};

    let status = nt::nt_create_file(
        &mut handle,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &mut obj_attr,
        &mut io_status,
        core::ptr::null_mut(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        core::ptr::null_mut(),
        0,
    );

    if status != 0 {
        return Err(alloc::format!("Directory not found: {}", target))
    }

    // Close Handle
    let table = ssn_table::syscall_table();
    invoke::syscall1(table.ssns.nt_close.ssn, table.ssns.nt_close.syscall_addr as usize, handle as usize);

    // Extract the actual paht: strip "\??\" 
    let path_str: String = nt_path.iter()
    .take_while(|&&c| c != 0)
    .skip(4) // skip \??\
    .map(|&c| if c < 129 { c as u8 as char } else { '?' }).collect();

    // Remove trailing backslash if not root
    let clean = if path_str.len() > 3 && path_str.ends_with('\\') {
        String::from(&path_str[..&path_str.len()-1])
    } else {
        path_str
    };
    
    super::set_cwd(clean.clone());
    Ok(alloc::format!("Changeed directory to: {}", clean)) 
}

pub unsafe fn cmd_ls(args: &[String]) -> Result<String, String> {
    let target = if args.is_empty() { String::from(".") } else { args[0].clone() };
    let nt_path =to_nt_path(&target);
    let mut unicode_str = core::mem::zeroed::<UnicodeString>();
    let mut obj_attr = core::mem::zeroed::<ObjectAttributes>();

    build_boject_attributes(&nt_path, &mut unicode_str, &mut obj_attr);

    let mut handle: HANDLE = core::ptr::null_mut();
    let mut io_status = IoStatusBlock { status: 0, information: 0 };

    let status = nt::nt_create_file(
        &mut handle,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &mut obj_attr,
        &mut io_status,
        core::ptr::null_mut(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        core::ptr::null_mut(),
        0,
    );

    if status != 0 {
        return Err(alloc::format!("Cannot open directory: 0x{:08x}", status))
    }

    let table = ssn_table::syscall_table();
    let mut output = String::with_capacity(4096);
    output.push_str("  TYPE    SIZE          NAME\n");
    output.push_str("  ----    ---------     -----------\n");

    // Query directory entries
    let mut buf = [0u8; 8192];
    let mut first_query = true;

    loop {
        io_status = IoStatusBlock { status: 0, information: 0 };

        let status = invoke::syscall9(
            table.ssns.nt_query_directory_file.ssn,
            table.ssns.nt_query_directory_file.syscall_addr as usize,
            handle as usize,
            0, // Event
            0, // ApcRoutine
            0, // ApcContext
            &mut io_status as *mut _ as usize,
            buf.as_mut_ptr() as usize,
            buf.len(),
            3, // FileBothDirectoryInformation
            0, // ReturnSingleEntry = FALSE
        );

        if status != 0 {
            if first_query {
                invoke::syscall1(table.ssns.nt_close.ssn, table.ssns.nt_close.syscall_addr as usize, handle as usize);
                return Err(alloc::format!("NtQueryDirectoryFile failed: 0x{:08x}", status));
            }
        }
        first_query = false;

        let mut offset: usize = 0;
        loop {
            let entry = buf.as_ptr().add(offset);

            let next_offset = *(entry as *const u32);
            let file_size = *(entry.add(0x28) as *const i64);
            let attributes = *(entry.add(0x38) as *const u32);
            let name_len_bytes = *(entry.add(0x3C) as *const u32) as usize;
            let name_ptr = entry.add(0x5E) as *const u16;
            let name_chars = name_len_bytes / 2;

            let mut name = String::with_capacity(name_chars);
            for i in 0..name_chars {
                let c = *name_ptr.add(i);
                if c == 0 { break }
                name.push(if c < 128 { c as u8 as char } else { '?' });
            }

            if name != "." && name != ".." {
                let type_str = if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 { "DIR " } else { "FILE" };
                let size_str = if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    String::from("          -")
                } else {
                    format_size(file_size as u64)
                };
                output.push_str(&alloc::format!("  {}    {:>10}    {}\n", type_str, size_str, name));
            }

            if next_offset == 0 { break; }
            offset += next_offset as usize
        }
    }
}



unsafe fn build_boject_attributes(nt_path: &[u16], unicode_str: &mut UnicodeString, obj_attr: &mut ObjectAttributes) {
    let byte_len = (nt_path.len() - 1) * 2; // exclude null for length
    let max_len = nt_path.len() * 2;
    *unicode_str = UnicodeString { 
        length: byte_len as u16, maximum_length: max_len as u16, buffer: nt_path.as_ptr() 
    };
    *obj_attr = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: core::ptr::null_mut(),
        object_name: unicode_str as *mut UnicodeString,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        alloc::format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        alloc::format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        alloc::format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        alloc::format!("{:.1}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}