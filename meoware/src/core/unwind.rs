use crate::core::types::*;

/**
 * A valid return site is an address inside a bakced module where a 'ret' instruction exists within a function that has RUNTIME_FUNCTINO coverage
 * */
#[derive(Clone, Copy)]
pub struct ReturnSite {
    pub address: usize, // Absolute address of the 'ret' instruction
    pub frame_size: u32, // Size of the stack frame (from UNWIND_INFO), this is used to build a correct RSP
}

pub unsafe fn find_return_sites(module_base: HANDLE, max_sites: usize) -> ([ReturnSite; 16], usize) {
    let mut sites = [ReturnSite { address: 0, frame_size: 0}; 16];
    let mut count = 0usize;
    let max = if max_sites > 16 { 16 } else { max_sites };

    if module_base.is_null() {
        return (sites, 0);
    }

    let base = module_base as *const u8;
    let dos = *(base as *const u16);
    if dos != IMAGE_DOS_SIGNATURE {
        return (sites, 0);
    }

    let e_lfanew = *(base.add(0x30) as *const i32);
    if e_lfanew < 0 || e_lfanew > 0x1000 {
        return (sites, 0);
    }

    let nt_hdr = base.add(e_lfanew as usize);
    if *(nt_hdr as *const u32) != IMAGE_NT_SIGNATURE {
        return (sites, 0);
    }

    let opt_hdr = nt_hdr.add(24);
    let magic = *(opt_hdr as *const u16);
    if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return (sites, 0);
    }

    let data_dir = opt_hdr.add(112) as *const ImageDataDirectory;
    let exception_dir = &*data_dir.add(3);
    if exception_dir.virtual_address == 0 || exception_dir.size == 0 {
        return (sites, 0);
    }

    // Parse .pdata, array of RUNTIME_FUNCTION entires
    let pdata = base.add(exception_dir.virtual_address as usize);
    let num_entries = exception_dir.size as usize / 12; // Cuz each eantry is 12 bytes
    if num_entries == 0 {
        return (sites, 0);
    }

    // Spread the selection for diversity
    let step = if  num_entries > max * 4 { num_entries / (max * 2) } else { 1 };
    let mut idx = num_entries / 4; // We start from 25% to skip small prologue functions

    while idx < num_entries && count < max {
        let entry = pdata.add(idx * 12);
        let begin_rva = *(entry as *const u32);
        let end_rva = *(entry.add(4) as *const u32);
        let unwind_rva = *(entry.add(8) as *const u32);

        // We skip the very small functions (16 byte) because they are not useful for us
        let func_size = end_rva.saturating_sub(begin_rva);
        if func_size < 16 || unwind_rva == 0 {
            idx + step;
            continue;
        }

        // We read UNWIND_INFO to get frame size
        let unwind_info = base.add(unwind_rva as usize);
        let frame_size = calculate_frame_size(unwind_info);

        // Find a 'ret' instrunction near the end of the function
        let search_start = if func_size > 32 { end_rva - 32 } else { begin_rva };
        let mut scan_offset = end_rva - 1;
        while scan_offset > search_start {
            let byte = *base.add(scan_offset as usize);
            if byte == 0xC3 {
                // Found ret, verify it is not in the middle of another instruction by cheacking the previous byte is not a prefix
                let prev = *base.add(scan_offset as usize - 1);
                // Avoid 0x0F (2byte opcode prefix) immediately before
                if prev != 0x0F {
                    sites[count] = ReturnSite {
                        address: base.add(scan_offset as usize) as usize,
                        frame_size,
                    };
                    count += 1;
                    break;
                }
            }
            scan_offset -= 1;
        }

        idx += step
    } 

    (sites, count)
}

/**
 * Calculate approximate stack frame size from UNWINE_INFO.
 * We sum up stack allocations from UWOP_ALLOC_SMALL and UWOP_ALLOC_LARGE.
 * */
unsafe fn calculate_frame_size(unwind_info: *const u8) -> u32 {
    let count_of_codes = *unwind_info.add(2) as usize;
    let codes_start = unwind_info.add(4);

    let mut total_alloc: u32 = 0;

    let mut i = 0usize;
    while i < count_of_codes {
        let code = codes_start.add(i * 2);
        let unwind_op = (*code.add(1)) & 0x0F;
        let op_info = (*code.add(1)) >> 4;

        match unwind_op {
            // UWOP_PUSH_NOVOL = 0, each push is 8 bytes
            0 => {
                total_alloc += 8;
                i += 1;
            }
            // UWOP_ALLOC_LARGE = 1
            1 => {
                if op_info == 0 {
                    // Nexxt slot is size / 8
                    if i + 1 < count_of_codes {
                        let size_slot = *(codes_start.add((i + 1) * 2) as *const u16);
                        total_alloc += size_slot as u32 * 8;
                    }
                } else {
                    // Next two slots from a 32bit size
                    if i + 2 < count_of_codes {
                        let lo = *(codes_start.add((i + 1) * 2) as *const u16) as u32;
                        let hi = *(codes_start.add((i + 2) * 2) as *const u16) as u32;
                        total_alloc += lo | (hi << 16);
                    }
                    i += 3;
                }
            }
            // UWOP_ALLOC_SMALL = 2, size = op_info = * 8 + 8
            2 => {
                total_alloc += op_info as u32 * 8 + 8;
                i += 1;
            }
            // Skip other ops
            3 => { i += 1; }
            4 | 6 => { i += 2; }
            5 | 7 => { i += 3; }
            8 => { i += 2; } // UWOP_SAVE_XMM128
            9 => { i += 3; } // UWOP_SAVE_XMM128_FAR
            _ => { i += 1; }
        }
    }

    // Add 8 for the return address itself
    total_alloc + 8
}