use crate::core::types::*;
use crate::core::win32;
use crate::debug;

pub unsafe fn demo() {
    unsafe {
        let mut os_info: OsVersionInfoExW = core::mem::zeroed();
        os_info.os_version_info_size = core::mem::size_of::<OsVersionInfoExW>() as u32;

        let status = win32::rtl_get_version(&mut os_info);
        if status == STATUS_SUCCESS {
            let product = match os_info.product_type {
                1 => "Workstation",
                2 => "Domain Controller",
                3 => "Server",
                _ => "Unknown",
            };
            debug!(
                "[+] OS Version: {}.{} (Build {}) - {}",
                os_info.major_version,
                os_info.minor_version,
                os_info.build_number,
                product
            );

            let friendly = match (os_info.major_version, os_info.build_number) {
                (10, b) if b >= 22000 => "Windows 11",
                (10, _) => "Windows 10",
                // if 6 and minor_version is 3 -> Win8.1 
                // if 6 and minor_version is 2 -> Win8
                // if 6 and minor_version is 1 -> Win7
                _ => "Unknown Windows",
            };
            debug!("[+] Detected: {} (Build {})", friendly, os_info.build_number);
        } else {
            debug!("[-] RtlGetVersion failed with 0x{:08X}", status as u32);
        }
    }
}
