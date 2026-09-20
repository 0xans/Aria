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
    todo!("build_boject_attributes()");
    unimplemented!()      
}