use crate::debug;

pub unsafe fn is_safe_environment() -> bool { unsafe {
    if is_debugger_presetnt() {
        debug!("[ANTI] Debugger detected (PEB.BeingDebugged)");
        false;
    }

    if check_nt_global_flag() {
        debug!("[ANTI] Debugger detected (NtGlobalFlag)");
        false;
    }

    if check_debug_port() {
        debug!("[ANTI] Debugger detected (ProcessDebugPort)");
        false;
    }

    true
}}

unsafe fn is_debugger_presetnt() -> bool { unsafe {
    let being_debugged: usize;
    core::arch::asm!(
        "mov {tmp}, gs:[0x60]",
        "movzx {out}, byte ptr [{tmp} + 0x02]", // PEB.BeingDebugged at offest 0x02 in x64
        tmp = out(reg) _,
        out = out(reg) being_debugged,
    );
    being_debugged != 0
}}
// TODO: is_debugger_presetnt for x86


unsafe fn check_nt_global_flag() -> bool { unsafe {
    let nt_global_flag: u32;
    core::arch::asm!(
        "mov {tmp}, gs:[0x60]",
        "mov {out:e}, dword ptr [{tmp} + 0xBC]", // PEB.NtGlobalFlag at offset 0xBC in x64
        tmp = out(reg) _,
        out = out(reg) nt_global_flag,
    );
    // Debugger set heap debug flags (0x70)
    (nt_global_flag & 0x70) != 0 
}}
// TODO: check_nt_global_flag for x86


// More robust than PEB.BeingDebugged
unsafe fn check_debug_port() -> bool { unsafe {
    let table = crate::core::ssn_table::syscall_table(); 
    let entry = &table.ssns.nt_query_information_process; 
    if entry.ssn == 0 { return false; }

    let mut debug_port: usize = 0;
    let mut return_length: u32 = 0;
    let status = crate::core::invoke::syscall5(
        entry.ssn,
        entry.syscall_addr as usize, 
        -1isize as usize,   // CurrentProcess
        7usize,             // ProcessDebugPort
        &mut debug_port as *mut _ as usize, 
        core::mem::size_of::<usize>() as usize, 
        &mut return_length as *mut _ as usize
    );

    // STATUS_SUCCESS and non zero port = debugger attached
    status == 0 && debug_port != 0
}}
