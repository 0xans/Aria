extern crate alloc;
use alloc::string::String;
use crate::core::types::*;

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

    unimplemented!()      
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
        attributes: 0x40,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };
}