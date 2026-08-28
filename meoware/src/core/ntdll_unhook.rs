use crate::debug;

use core::ffi::c_void;

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

pub unsafe fn unhook_ntdll() -> Option<usize> {
    // Get the loaded ntdll base from PEB
    let loaded_base = get_ntdll_base()?;

    unimplemented!()
}